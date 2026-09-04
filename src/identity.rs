//! Governed external identity, shadow resolution, and portable database identity.
//!
//! `bindings` remains the compact live uniqueness index.  This module is the
//! only ordinary write path around it: normalization, authorization, record
//! creation, binding mutation, observations, provenance, and append-only audit
//! all share one `BEGIN IMMEDIATE` transaction.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{Connection, SqliteConnection};
use sqlx::{Row, Sqlite, Transaction};
use std::collections::HashSet;
use std::path::Path;
use std::str::FromStr;
use uuid::Uuid;

use crate::authorization::{self, Capability, Principal};
use crate::blob::{BlobMeta, BLOB_REF_FACET_KEY};
use crate::db::Db;
use crate::error::{Error, Result};
use crate::schema::UNFILED_RECORD_ID;
use crate::store::{append_in, now_iso, AppendSpec};

pub(crate) mod account;
pub(crate) mod binding_plan;
#[doc(hidden)]
pub mod hosted;
mod stdio;

pub use stdio::resolve_stdio_account_identity;

use binding_plan::{
    AddBindingPlan, CanonicalizeBindingPlan, ExistingBinding, ReconcileBindingFact,
    ReconcileBindingPlan, RemoveBindingPlan,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingClaim {
    pub system: String,
    pub identifier: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StubHints {
    pub record_type: Option<String>,
    pub kind: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationQuality {
    Reported,
    Fetched,
}

impl ObservationQuality {
    fn as_str(self) -> &'static str {
        match self {
            Self::Reported => "reported",
            Self::Fetched => "fetched",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaterializationPolicy {
    IdentityOnly,
    Snapshot,
}

impl MaterializationPolicy {
    fn as_str(self) -> &'static str {
        match self {
            Self::IdentityOnly => "identity_only",
            Self::Snapshot => "snapshot",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationFreshness {
    Unknown,
    Fresh,
    Stale,
}

impl ObservationFreshness {
    fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Fresh => "fresh",
            Self::Stale => "stale",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionState {
    None,
    Captured,
    Retained,
}

impl RetentionState {
    fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Captured => "captured",
            Self::Retained => "retained",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceAvailability {
    Unknown,
    Available,
    Unavailable,
}

impl SourceAvailability {
    fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Available => "available",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefreshOutcome {
    NotAttempted,
    Succeeded,
    Failed,
}

impl RefreshOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::NotAttempted => "not_attempted",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }
}

/// Source-qualified provenance for one append-only observation.
///
/// A retained snapshot names the prior observation whose immutable attachment
/// remains available. The service copies that observation's source revision
/// and digest, rejecting contradictory caller claims, so a failed refresh can
/// never relabel old bytes as a newly fetched source revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationProvenance {
    pub source_revision: Option<String>,
    pub source_digest: Option<String>,
    pub freshness: ObservationFreshness,
    pub retention_state: RetentionState,
    pub source_availability: SourceAvailability,
    pub refresh_outcome: RefreshOutcome,
    pub retained_from_observation_id: Option<String>,
}

impl Default for ObservationProvenance {
    fn default() -> Self {
        Self {
            source_revision: None,
            source_digest: None,
            freshness: ObservationFreshness::Unknown,
            retention_state: RetentionState::None,
            source_availability: SourceAvailability::Unknown,
            refresh_outcome: RefreshOutcome::NotAttempted,
            retained_from_observation_id: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MutationContext<'a> {
    pub actor: &'a str,
    pub reason: &'a str,
    pub run_key: Option<&'a str>,
    pub parent_key: Option<&'a str>,
    pub intent: Option<&'a str>,
    /// Reserved systems are available only to engine/hosting call sites.
    pub internal: bool,
    /// Set only by a gateway that actually performed/authorized the source read.
    pub source_read_authorized: bool,
}

impl MutationContext<'_> {
    fn validate(&self, tool: &str) -> Result<()> {
        if self.reason.trim().is_empty() {
            return Err(Error::engine(format!(
                "{tool}: 'reason' must contain non-whitespace reasoning"
            )));
        }
        Ok(())
    }

    fn principal(&self) -> Principal<'_> {
        Principal::bound(self.actor, true)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Resolution {
    pub record_id: String,
    pub created: bool,
    pub bindings_added: Vec<BindingClaim>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ObservationResult {
    pub observation_id: String,
    pub record_id: String,
    pub created: bool,
    pub provenance_attachment_id: Option<String>,
    pub provenance: ObservationProvenance,
}

/// Read-only projection of one governed binding mutation for the explicitly
/// gated executor plan runtime. The projection is computed from the same
/// normalized claims, system policy, authorization and live binding rows as
/// production execution, inside a transaction that is always rolled back.
#[cfg(feature = "mcp-executor-prototype")]
#[derive(Clone, Debug)]
pub(crate) struct BindingMutationPreparation {
    pub canonical_source_arguments: serde_json::Value,
    pub target_id: String,
    pub target: String,
    pub state_revision: String,
    pub target_state_digest: String,
    pub effect: serde_json::Value,
    pub effect_summary: String,
}

#[derive(Debug, Clone)]
struct SystemRule {
    system: String,
    compatible_type: Option<String>,
    compatible_kind: Option<String>,
    add_policy: String,
    remove_policy: String,
    canonicalize_policy: String,
    transfer_policy: String,
    reconciliation_rule: String,
    authoritative_provenance: bool,
    stub_allowed: bool,
}

#[derive(Debug, PartialEq, Eq)]
struct GovernedSystemDefinition {
    system: String,
    normalizer: String,
    compatible_type: Option<String>,
    compatible_kind: Option<String>,
    visibility: String,
    add_policy: String,
    remove_policy: String,
    canonicalize_policy: String,
    transfer_policy: String,
    reconciliation_rule: String,
    stub_allowed: i64,
    authoritative_provenance: i64,
    required_durable: i64,
}

#[derive(Debug, Clone, Copy)]
enum BindingOperation {
    Add,
    Remove,
    Canonicalize,
    Transfer,
}

fn enforce_operation_policy(
    rule: &SystemRule,
    operation: BindingOperation,
    internal: bool,
) -> Result<()> {
    let policy = match operation {
        BindingOperation::Add => &rule.add_policy,
        BindingOperation::Remove => &rule.remove_policy,
        BindingOperation::Canonicalize => &rule.canonicalize_policy,
        BindingOperation::Transfer => &rule.transfer_policy,
    };
    if policy == "internal" && !internal {
        return Err(Error::engine(format!(
            "forbidden binding-system operation: '{}' requires an internal writer",
            rule.system
        )));
    }
    if policy == "forbidden" {
        return Err(Error::engine(format!(
            "binding system '{}' forbids this operation",
            rule.system
        )));
    }
    if policy != "internal" && policy != "record_manage" {
        return Err(Error::engine(format!(
            "binding system '{}' has an unsupported operation policy",
            rule.system
        )));
    }
    Ok(())
}

pub(crate) fn mint_database_id() -> String {
    // UUIDv4 reserves six bits for its version/variant. Portable database
    // identities require all 128 bits to come from the operating system CSPRNG.
    let mut bytes = [0_u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    format!("ndb_{}", hex::encode(bytes))
}

pub fn is_database_id(value: &str) -> bool {
    value.len() == 36
        && value.starts_with("ndb_")
        && value[4..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn encode_native_record(origin_db_id: &str, origin_record_id: &str) -> Result<String> {
    if !is_database_id(origin_db_id) {
        return Err(Error::engine("invalid native-record database identity"));
    }
    if origin_record_id.is_empty() {
        return Err(Error::engine(
            "native-record origin record id must not be empty",
        ));
    }
    Ok(format!(
        "{origin_db_id}/{}",
        URL_SAFE_NO_PAD.encode(origin_record_id.as_bytes())
    ))
}

pub fn decode_native_record(value: &str) -> Result<(String, String)> {
    let (database, encoded) = value
        .split_once('/')
        .ok_or_else(|| Error::engine("malformed native-record identifier"))?;
    if !is_database_id(database) || encoded.is_empty() || encoded.contains('=') {
        return Err(Error::engine("malformed native-record identifier"));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| Error::engine("malformed native-record identifier"))?;
    let record = String::from_utf8(bytes)
        .map_err(|_| Error::engine("native-record id is not valid UTF-8"))?;
    if record.is_empty() || encode_native_record(database, &record)? != value {
        return Err(Error::engine("non-canonical native-record identifier"));
    }
    Ok((database.into(), record))
}

pub async fn database_id(db: &Db) -> Result<String> {
    sqlx::query_scalar("SELECT origin_db_id FROM database_identity WHERE singleton = 1")
        .fetch_optional(db.write_pool())
        .await?
        .ok_or_else(|| Error::engine("database identity singleton is missing"))
}

/// Stable workspace-local pseudonym for one portable account. The relation
/// exposes this value instead of account, person-record, or host identifiers.
#[doc(hidden)]
pub fn activity_member_ref(workspace_id: &str, account_id: &str) -> String {
    use sha2::{Digest, Sha256};

    let mut digest = Sha256::new();
    digest.update(b"native.workspace-activity-member.v1\0");
    digest.update(workspace_id.as_bytes());
    digest.update(b"\0");
    digest.update(account_id.as_bytes());
    format!("native:workspace-member:{}", hex::encode(digest.finalize()))
}

/// Mint identity for a fresh schema after the canonical root genesis exists.
pub async fn seed_database_identity(db: &Db) -> Result<String> {
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    if let Some(existing) = sqlx::query_scalar::<_, String>(
        "SELECT origin_db_id FROM database_identity WHERE singleton = 1",
    )
    .fetch_optional(&mut *tx)
    .await?
    {
        tx.rollback().await?;
        return Ok(existing);
    }
    let token = mint_database_id();
    insert_database_identity(
        &mut tx,
        &token,
        "engine:seed",
        "mint fresh database identity",
    )
    .await?;
    tx.commit().await?;
    Ok(token)
}

pub(crate) async fn insert_database_identity(
    tx: &mut Transaction<'static, Sqlite>,
    token: &str,
    actor: &str,
    reason: &str,
) -> Result<()> {
    if !is_database_id(token) {
        return Err(Error::engine("invalid database identity token"));
    }
    let now = now_iso();
    sqlx::query(
        "INSERT INTO database_identity (singleton, origin_db_id, created_at) VALUES (1, ?, ?)",
    )
    .bind(token)
    .bind(&now)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "INSERT INTO database_identity_audit
         (id, action, old_origin_db_id, new_origin_db_id, actor, reason, created_at)
         VALUES (?, 'mint', NULL, ?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(token)
    .bind(actor)
    .bind(reason)
    .bind(now)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub async fn state_violations(db: &Db) -> Result<Vec<String>> {
    let mut violations = Vec::new();
    let identities: Vec<String> =
        sqlx::query_scalar("SELECT origin_db_id FROM database_identity ORDER BY singleton")
            .fetch_all(db.write_pool())
            .await?;
    if identities.len() != 1 || !identities.first().is_some_and(|id| is_database_id(id)) {
        violations.push("database_identity must contain one canonical ndb token".into());
    }
    let systems = sqlx::query(
        "SELECT system,normalizer,compatible_type,compatible_kind,visibility,
                add_policy,remove_policy,canonicalize_policy,transfer_policy,reconciliation_rule,
                stub_allowed,authoritative_provenance,required_durable
           FROM binding_systems
          WHERE system IN ('native-principal','email','account','native-record')
          ORDER BY system",
    )
    .fetch_all(db.write_pool())
    .await?;
    let actual: Vec<_> = systems
        .into_iter()
        .map(|row| {
            Ok::<_, sqlx::Error>(GovernedSystemDefinition {
                system: row.try_get("system")?,
                normalizer: row.try_get("normalizer")?,
                compatible_type: row.try_get("compatible_type")?,
                compatible_kind: row.try_get("compatible_kind")?,
                visibility: row.try_get("visibility")?,
                add_policy: row.try_get("add_policy")?,
                remove_policy: row.try_get("remove_policy")?,
                canonicalize_policy: row.try_get("canonicalize_policy")?,
                transfer_policy: row.try_get("transfer_policy")?,
                reconciliation_rule: row.try_get("reconciliation_rule")?,
                stub_allowed: row.try_get("stub_allowed")?,
                authoritative_provenance: row.try_get("authoritative_provenance")?,
                required_durable: row.try_get("required_durable")?,
            })
        })
        .collect::<std::result::Result<_, _>>()?;
    let expected = vec![
        GovernedSystemDefinition {
            system: "account".into(),
            normalizer: "account-v1".into(),
            compatible_type: Some("Entity".into()),
            compatible_kind: Some("person".into()),
            visibility: "reserved".into(),
            add_policy: "internal".into(),
            remove_policy: "internal".into(),
            canonicalize_policy: "internal".into(),
            transfer_policy: "internal".into(),
            reconciliation_rule: "binding_only".into(),
            stub_allowed: 0,
            authoritative_provenance: 1,
            required_durable: 1,
        },
        GovernedSystemDefinition {
            system: "email".into(),
            normalizer: "email-v1".into(),
            compatible_type: Some("Entity".into()),
            compatible_kind: Some("person".into()),
            visibility: "reserved".into(),
            add_policy: "internal".into(),
            remove_policy: "internal".into(),
            canonicalize_policy: "internal".into(),
            transfer_policy: "internal".into(),
            reconciliation_rule: "binding_only".into(),
            stub_allowed: 0,
            authoritative_provenance: 1,
            required_durable: 0,
        },
        GovernedSystemDefinition {
            system: "native-principal".into(),
            normalizer: "native-principal-v1".into(),
            compatible_type: Some("Entity".into()),
            compatible_kind: Some("person".into()),
            visibility: "public".into(),
            add_policy: "record_manage".into(),
            remove_policy: "record_manage".into(),
            canonicalize_policy: "record_manage".into(),
            transfer_policy: "record_manage".into(),
            reconciliation_rule: "binding_only".into(),
            stub_allowed: 1,
            authoritative_provenance: 1,
            required_durable: 1,
        },
        GovernedSystemDefinition {
            system: "native-record".into(),
            normalizer: "native-record-v1".into(),
            compatible_type: None,
            compatible_kind: None,
            visibility: "public".into(),
            add_policy: "record_manage".into(),
            remove_policy: "record_manage".into(),
            canonicalize_policy: "record_manage".into(),
            transfer_policy: "record_manage".into(),
            reconciliation_rule: "binding_only".into(),
            stub_allowed: 1,
            authoritative_provenance: 1,
            required_durable: 1,
        },
    ];
    if actual != expected {
        violations
            .push("binding-system registry differs from the governed built-in definitions".into());
    }
    let identity_audit = sqlx::query(
        "SELECT action,old_origin_db_id,new_origin_db_id FROM database_identity_audit ORDER BY seq",
    )
    .fetch_all(db.write_pool())
    .await?;
    let mut previous: Option<String> = None;
    for (index, row) in identity_audit.iter().enumerate() {
        let action: String = row.try_get("action")?;
        let old: Option<String> = row.try_get("old_origin_db_id")?;
        let new: String = row.try_get("new_origin_db_id")?;
        if (index == 0 && (action != "mint" || old.is_some()))
            || (index > 0 && (action != "rekey" || old != previous))
            || !is_database_id(&new)
        {
            violations.push(
                "database identity audit is not one mint followed by a contiguous rekey chain"
                    .into(),
            );
            break;
        }
        previous = Some(new);
    }
    if previous.as_ref() != identities.first() {
        violations.push("database identity singleton does not match the audit tail".into());
    }
    let tails = sqlx::query(
        "SELECT a.system,a.identifier,a.new_record_id,a.new_canonical,b.record_id AS live_record_id,b.is_canonical AS live_canonical
           FROM binding_audit a
           JOIN (SELECT system,identifier,MAX(seq) seq FROM binding_audit GROUP BY system,identifier) tail
             ON tail.seq=a.seq
           LEFT JOIN bindings b ON b.system=a.system AND b.identifier=a.identifier",
    ).fetch_all(db.write_pool()).await?;
    for row in tails {
        let system: String = row.try_get("system")?;
        let identifier: String = row.try_get("identifier")?;
        let audited_record: Option<String> = row.try_get("new_record_id")?;
        let audited_canonical: Option<i64> = row.try_get("new_canonical")?;
        let live_record: Option<String> = row.try_get("live_record_id")?;
        let live_canonical: Option<i64> = row.try_get("live_canonical")?;
        if audited_record != live_record || audited_canonical != live_canonical {
            violations.push(format!(
                "binding audit tail does not explain {system}:{identifier}"
            ));
        }
    }
    let unaudited: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM bindings b WHERE NOT EXISTS(
           SELECT 1 FROM binding_audit a WHERE a.system=b.system AND a.identifier=b.identifier)",
    )
    .fetch_one(db.write_pool())
    .await?;
    if unaudited != 0 {
        violations.push(format!("{unaudited} live binding(s) have no audit history"));
    }
    let unreasoned_observations: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM external_observations WHERE length(trim(reason)) = 0",
    )
    .fetch_one(db.write_pool())
    .await?;
    if unreasoned_observations != 0 {
        violations.push(format!(
            "{unreasoned_observations} external observation(s) have no audit reason"
        ));
    }
    let invalid_retained: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)
           FROM external_observations current
           LEFT JOIN external_observations prior
             ON prior.id = current.retained_from_observation_id
          WHERE current.retention_state = 'retained'
            AND (prior.id IS NULL
              OR prior.record_id <> current.record_id
              OR prior.source_system <> current.source_system
              OR prior.source_identifier <> current.source_identifier
              OR prior.materialization_policy <> 'snapshot'
              OR prior.provenance_attachment_id IS NULL
              OR prior.provenance_attachment_id <> current.provenance_attachment_id
              OR prior.source_revision IS NOT current.source_revision
              OR prior.source_digest IS NOT current.source_digest)",
    )
    .fetch_one(db.write_pool())
    .await?;
    if invalid_retained != 0 {
        violations.push(format!(
            "{invalid_retained} retained external snapshot(s) contradict their prior artifact provenance"
        ));
    }
    Ok(violations)
}

/// Rekey an intentionally writable fork while it is offline.
///
/// The caller supplies a separately verified preimage snapshot. Under an
/// exclusive SQLite lock we prove that it carries the same portable identity
/// and authoritative log heads, then update only the singleton and append one
/// rekey audit row. The predecessor is provenance, never an active alias.
fn digest_text(digest: &mut Sha256, value: &str) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value.as_bytes());
}

fn digest_optional_text(digest: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            digest.update([1]);
            digest_text(digest, value);
        }
        None => digest.update([0]),
    }
}

async fn authoritative_log_digest(connection: &mut SqliteConnection) -> Result<[u8; 32]> {
    let mut digest = Sha256::new();
    digest.update(b"native-authoritative-logs-v1\0");
    for row in sqlx::query(
        "SELECT seq,id,record_id,type,payload,actor,run_key,parent_key,intent,created_at
           FROM content_events ORDER BY seq",
    )
    .fetch_all(&mut *connection)
    .await?
    {
        digest.update(b"content\0");
        digest.update(row.try_get::<i64, _>("seq")?.to_be_bytes());
        for field in ["id", "record_id", "type", "created_at"] {
            digest_text(&mut digest, &row.try_get::<String, _>(field)?);
        }
        for field in ["payload", "actor", "run_key", "parent_key", "intent"] {
            let value = row.try_get::<Option<String>, _>(field)?;
            digest_optional_text(&mut digest, value.as_deref());
        }
    }
    for row in sqlx::query(
        "SELECT seq,id,subject_id,type,payload,actor,created_at FROM meta_events ORDER BY seq",
    )
    .fetch_all(&mut *connection)
    .await?
    {
        digest.update(b"meta\0");
        digest.update(row.try_get::<i64, _>("seq")?.to_be_bytes());
        for field in ["id", "subject_id", "type", "created_at"] {
            digest_text(&mut digest, &row.try_get::<String, _>(field)?);
        }
        for field in ["payload", "actor"] {
            let value = row.try_get::<Option<String>, _>(field)?;
            digest_optional_text(&mut digest, value.as_deref());
        }
    }
    Ok(digest.finalize().into())
}

async fn schema_digest(connection: &mut SqliteConnection) -> Result<[u8; 32]> {
    let mut digest = Sha256::new();
    digest.update(b"native-sqlite-schema-v1\0");
    let rows = sqlx::query(
        "SELECT type,name,tbl_name,sql FROM sqlite_schema
          WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name",
    )
    .fetch_all(&mut *connection)
    .await?;
    for row in rows {
        for field in ["type", "name", "tbl_name"] {
            digest_text(&mut digest, &row.try_get::<String, _>(field)?);
        }
        let sql = row.try_get::<Option<String>, _>("sql")?;
        digest_optional_text(&mut digest, sql.as_deref());
    }
    Ok(digest.finalize().into())
}

async fn database_identity_digest(connection: &mut SqliteConnection) -> Result<[u8; 32]> {
    let mut digest = Sha256::new();
    digest.update(b"native-database-identity-state-v1\0");
    for row in sqlx::query(
        "SELECT singleton,origin_db_id,created_at FROM database_identity ORDER BY singleton",
    )
    .fetch_all(&mut *connection)
    .await?
    {
        digest.update(row.try_get::<i64, _>("singleton")?.to_be_bytes());
        digest_text(&mut digest, &row.try_get::<String, _>("origin_db_id")?);
        digest_text(&mut digest, &row.try_get::<String, _>("created_at")?);
    }
    for row in sqlx::query(
        "SELECT seq,id,action,old_origin_db_id,new_origin_db_id,actor,reason,
                run_key,parent_key,intent,created_at
           FROM database_identity_audit ORDER BY seq",
    )
    .fetch_all(&mut *connection)
    .await?
    {
        digest.update(row.try_get::<i64, _>("seq")?.to_be_bytes());
        for field in [
            "id",
            "action",
            "new_origin_db_id",
            "actor",
            "reason",
            "created_at",
        ] {
            digest_text(&mut digest, &row.try_get::<String, _>(field)?);
        }
        for field in ["old_origin_db_id", "run_key", "parent_key", "intent"] {
            let value = row.try_get::<Option<String>, _>(field)?;
            digest_optional_text(&mut digest, value.as_deref());
        }
    }
    Ok(digest.finalize().into())
}

pub async fn rekey_database_offline(
    path: &Path,
    verified_preimage_backup: &Path,
    expected_old_id: &str,
    actor: &str,
    reason: &str,
) -> Result<String> {
    if reason.trim().is_empty() {
        return Err(Error::engine("database rekey requires a nonblank reason"));
    }
    let path = std::fs::canonicalize(path)?;
    let verified_preimage_backup = std::fs::canonicalize(verified_preimage_backup)?;
    if path == verified_preimage_backup {
        return Err(Error::engine(
            "database rekey backup must be a distinct file",
        ));
    }
    let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))?
        .create_if_missing(false)
        .foreign_keys(true);
    let mut source = SqliteConnection::connect_with(&options).await?;
    sqlx::query("BEGIN EXCLUSIVE").execute(&mut source).await?;
    let operation: Result<String> = async {
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&mut source).await?;
        if version != crate::db::CURRENT_ENGINE_SCHEMA_VERSION {
            return Err(Error::engine(format!("database rekey requires current schema, found {version}")));
        }
        let old_id: String = sqlx::query_scalar(
            "SELECT origin_db_id FROM database_identity WHERE singleton=1",
        ).fetch_one(&mut source).await?;
        if old_id != expected_old_id || !is_database_id(&old_id) {
            return Err(Error::engine("database rekey confirmation does not match current identity"));
        }
        let source_check: String = sqlx::query_scalar("PRAGMA quick_check(1)")
            .fetch_one(&mut source).await?;
        let source_logs = authoritative_log_digest(&mut source).await?;
        let source_schema = schema_digest(&mut source).await?;
        let source_identity = database_identity_digest(&mut source).await?;
        let backup_options = SqliteConnectOptions::from_str(&format!(
            "sqlite:{}", verified_preimage_backup.display()
        ))?.create_if_missing(false).read_only(true).foreign_keys(true);
        let mut backup = SqliteConnection::connect_with(&backup_options).await?;
        let backup_check: String = sqlx::query_scalar("PRAGMA quick_check(1)")
            .fetch_one(&mut backup).await?;
        let backup_version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&mut backup).await?;
        let backup_id: String = sqlx::query_scalar(
            "SELECT origin_db_id FROM database_identity WHERE singleton=1",
        ).fetch_one(&mut backup).await?;
        let backup_logs = authoritative_log_digest(&mut backup).await?;
        let backup_schema = schema_digest(&mut backup).await?;
        let backup_identity = database_identity_digest(&mut backup).await?;
        backup.close().await?;
        if source_check != "ok"
            || backup_check != "ok"
            || backup_version != version
            || backup_id != old_id
            || backup_logs != source_logs
            || backup_schema != source_schema
            || backup_identity != source_identity
        {
            return Err(Error::engine(
                "database rekey requires a verified preimage backup with matching identity, schema, and complete authoritative logs",
            ));
        }
        let new_id = mint_database_id();
        let now = now_iso();
        sqlx::query("UPDATE database_identity SET origin_db_id=?, created_at=? WHERE singleton=1")
            .bind(&new_id).bind(&now).execute(&mut source).await?;
        sqlx::query(
            "INSERT INTO database_identity_audit
             (id,action,old_origin_db_id,new_origin_db_id,actor,reason,created_at)
             VALUES(?,'rekey',?,?,?,?,?)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&old_id)
        .bind(&new_id)
        .bind(actor)
        .bind(reason)
        .bind(now)
        .execute(&mut source)
        .await?;
        Ok(new_id)
    }.await;
    match operation {
        Ok(new_id) => {
            sqlx::query("COMMIT").execute(&mut source).await?;
            source.close().await?;
            Ok(new_id)
        }
        Err(error) => {
            let _ = sqlx::query("ROLLBACK").execute(&mut source).await;
            let _ = source.close().await;
            Err(error)
        }
    }
}

pub(crate) fn normalize_identifier(system: &str, raw: &str) -> Result<String> {
    let invalid = || Error::engine(format!("invalid identifier for binding system '{system}'"));
    match system {
        "native-principal" => {
            let Some((network_id, principal_id)) = raw.split_once('/') else {
                return Err(invalid());
            };
            let address = crate::federation::PrincipalAddress {
                network_id: network_id.to_owned(),
                principal_id: principal_id.to_owned(),
            };
            if !address.is_valid() {
                return Err(invalid());
            }
            Ok(raw.into())
        }
        "email" => {
            let value = raw.trim().to_ascii_lowercase();
            let (local, domain) = value.split_once('@').ok_or_else(invalid)?;
            if local.is_empty()
                || domain.is_empty()
                || domain.contains('@')
                || value.len() > 254
                || value.chars().any(char::is_whitespace)
            {
                return Err(invalid());
            }
            Ok(value)
        }
        "account" => {
            // Canonical local tokens use acct_<32 hex>; signed incoming and
            // legacy historical actors remain opaque non-canonical aliases.
            if raw.is_empty() || raw.len() > 256 || !raw.bytes().all(protocol_token_byte) {
                return Err(invalid());
            }
            Ok(raw.into())
        }
        "native-record" => {
            decode_native_record(raw)?;
            Ok(raw.into())
        }
        _ => Err(Error::engine(format!("unknown binding system '{system}'"))),
    }
}

fn protocol_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-')
}

async fn rule_in(
    tx: &mut Transaction<'static, Sqlite>,
    claim: &BindingClaim,
    internal: bool,
    operation: Option<BindingOperation>,
) -> Result<(BindingClaim, SystemRule)> {
    let row = sqlx::query(
        "SELECT compatible_type, compatible_kind, visibility,
                add_policy, remove_policy, canonicalize_policy, transfer_policy,
                reconciliation_rule, authoritative_provenance, stub_allowed
           FROM binding_systems WHERE system = ?",
    )
    .bind(&claim.system)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| Error::engine(format!("unknown binding system '{}'", claim.system)))?;
    let visibility: String = row.try_get("visibility")?;
    if visibility != "public" && !internal {
        return Err(Error::engine(format!(
            "forbidden binding-system operation: '{}' is {visibility}",
            claim.system
        )));
    }
    let normalized = BindingClaim {
        system: claim.system.clone(),
        identifier: normalize_identifier(&claim.system, &claim.identifier)?,
    };
    let rule = SystemRule {
        system: claim.system.clone(),
        compatible_type: row.try_get("compatible_type")?,
        compatible_kind: row.try_get("compatible_kind")?,
        add_policy: row.try_get("add_policy")?,
        remove_policy: row.try_get("remove_policy")?,
        canonicalize_policy: row.try_get("canonicalize_policy")?,
        transfer_policy: row.try_get("transfer_policy")?,
        reconciliation_rule: row.try_get("reconciliation_rule")?,
        authoritative_provenance: row.try_get::<i64, _>("authoritative_provenance")? != 0,
        stub_allowed: row.try_get::<i64, _>("stub_allowed")? != 0,
    };
    if let Some(operation) = operation {
        enforce_operation_policy(&rule, operation, internal)?;
    }
    Ok((normalized, rule))
}

async fn require_record_shape(
    tx: &mut Transaction<'static, Sqlite>,
    record_id: &str,
    rule: &SystemRule,
) -> Result<()> {
    let row = sqlx::query("SELECT type, kind, deleted_at FROM records WHERE id = ?")
        .bind(record_id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| Error::engine(format!("record '{record_id}' not found")))?;
    let record_type: String = row.try_get("type")?;
    let kind: Option<String> = row.try_get("kind")?;
    if row.try_get::<Option<String>, _>("deleted_at")?.is_some()
        || rule
            .compatible_type
            .as_deref()
            .is_some_and(|expected| expected != record_type)
        || rule
            .compatible_kind
            .as_deref()
            .is_some_and(|expected| Some(expected) != kind.as_deref())
    {
        return Err(Error::engine(format!(
            "incompatible record kind for binding system '{}' on record '{record_id}'",
            rule.system
        )));
    }
    Ok(())
}

async fn require_capability_in(
    tx: &mut Transaction<'static, Sqlite>,
    context: &MutationContext<'_>,
    record_id: &str,
    capability: Capability,
) -> Result<()> {
    if context.internal {
        return Ok(());
    }
    authorization::require_capability_on(tx, context.principal(), record_id, capability).await
}

async fn require_binding_visibility_in(
    tx: &mut Transaction<'static, Sqlite>,
    context: &MutationContext<'_>,
    record_id: &str,
) -> Result<()> {
    match require_capability_in(tx, context, record_id, Capability::View).await {
        Ok(()) => Ok(()),
        Err(error) if context.internal => Err(error),
        Err(_) => Err(Error::engine(
            "binding_not_visible: the external identity is not visible to this caller",
        )),
    }
}

#[allow(clippy::too_many_arguments)]
async fn append_binding_audit(
    tx: &mut Transaction<'static, Sqlite>,
    context: &MutationContext<'_>,
    action: &str,
    claim: &BindingClaim,
    old_record_id: Option<&str>,
    new_record_id: Option<&str>,
    old_canonical: Option<bool>,
    new_canonical: Option<bool>,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO binding_audit
         (id, action, system, identifier, old_record_id, new_record_id,
          old_canonical, new_canonical, actor, reason, run_key, parent_key, intent, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(action)
    .bind(&claim.system)
    .bind(&claim.identifier)
    .bind(old_record_id)
    .bind(new_record_id)
    .bind(old_canonical.map(i64::from))
    .bind(new_canonical.map(i64::from))
    .bind(context.actor)
    .bind(context.reason)
    .bind(context.run_key)
    .bind(context.parent_key)
    .bind(context.intent)
    .bind(now_iso())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn add_binding_in(
    tx: &mut Transaction<'static, Sqlite>,
    context: &MutationContext<'_>,
    record_id: &str,
    claim: &BindingClaim,
    canonical: bool,
) -> Result<bool> {
    let existing = sqlx::query(
        "SELECT record_id, is_canonical FROM bindings WHERE system = ? AND identifier = ?",
    )
    .bind(&claim.system)
    .bind(&claim.identifier)
    .fetch_optional(&mut **tx)
    .await?;
    if let Some(row) = existing {
        let owner: String = row.try_get("record_id")?;
        let was_canonical = row.try_get::<i64, _>("is_canonical")? != 0;
        if owner != record_id {
            require_binding_visibility_in(tx, context, &owner).await?;
            return Err(Error::engine(
                "binding collision: external identity already belongs to another visible record",
            ));
        }
        if canonical && !was_canonical {
            return canonicalize_in(tx, context, record_id, claim).await;
        }
        return Ok(false);
    }
    if canonical {
        let previous = sqlx::query(
            "SELECT identifier FROM bindings WHERE record_id = ? AND system = ? AND is_canonical = 1",
        )
        .bind(record_id)
        .bind(&claim.system)
        .fetch_optional(&mut **tx)
        .await?;
        if let Some(previous) = previous {
            let previous = BindingClaim {
                system: claim.system.clone(),
                identifier: previous.try_get("identifier")?,
            };
            sqlx::query(
                "UPDATE bindings SET is_canonical = 0 WHERE record_id = ? AND system = ? AND identifier = ?",
            )
            .bind(record_id)
            .bind(&previous.system)
            .bind(&previous.identifier)
            .execute(&mut **tx)
            .await?;
            append_binding_audit(
                tx,
                context,
                "canonicalize",
                &previous,
                Some(record_id),
                Some(record_id),
                Some(true),
                Some(false),
            )
            .await?;
        }
    }
    sqlx::query(
        "INSERT INTO bindings (record_id, system, identifier, is_canonical) VALUES (?, ?, ?, ?)",
    )
    .bind(record_id)
    .bind(&claim.system)
    .bind(&claim.identifier)
    .bind(i64::from(canonical))
    .execute(&mut **tx)
    .await?;
    append_binding_audit(
        tx,
        context,
        "add",
        claim,
        None,
        Some(record_id),
        None,
        Some(canonical),
    )
    .await?;
    Ok(true)
}

/// Engine/hosting entry point for reserved systems inside an existing identity
/// transaction.  Keeps account/email provisioning on the same governed writer
/// and audit contract without nesting a second writer transaction.
pub(crate) async fn add_binding_internal_in(
    tx: &mut Transaction<'static, Sqlite>,
    actor: &str,
    reason: &str,
    record_id: &str,
    system: &str,
    identifier: &str,
    canonical: bool,
) -> Result<bool> {
    let context = MutationContext {
        actor,
        reason,
        run_key: None,
        parent_key: None,
        intent: None,
        internal: true,
        source_read_authorized: false,
    };
    context.validate("internal binding writer")?;
    let (claim, rule) = rule_in(
        tx,
        &BindingClaim {
            system: system.into(),
            identifier: identifier.into(),
        },
        true,
        Some(BindingOperation::Add),
    )
    .await?;
    require_record_shape(tx, record_id, &rule).await?;
    add_binding_in(tx, &context, record_id, &claim, canonical).await
}

async fn canonicalize_in(
    tx: &mut Transaction<'static, Sqlite>,
    context: &MutationContext<'_>,
    record_id: &str,
    claim: &BindingClaim,
) -> Result<bool> {
    let target: Option<i64> = sqlx::query_scalar(
        "SELECT is_canonical FROM bindings WHERE record_id = ? AND system = ? AND identifier = ?",
    )
    .bind(record_id)
    .bind(&claim.system)
    .bind(&claim.identifier)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(target) = target else {
        return Err(Error::engine(
            "binding to canonicalize does not exist on record",
        ));
    };
    if target == 1 {
        return Ok(false);
    }
    if let Some(previous) = sqlx::query_scalar::<_, String>(
        "SELECT identifier FROM bindings WHERE record_id = ? AND system = ? AND is_canonical = 1",
    )
    .bind(record_id)
    .bind(&claim.system)
    .fetch_optional(&mut **tx)
    .await?
    {
        sqlx::query(
            "UPDATE bindings SET is_canonical = 0 WHERE record_id = ? AND system = ? AND identifier = ?",
        )
        .bind(record_id)
        .bind(&claim.system)
        .bind(&previous)
        .execute(&mut **tx)
        .await?;
        append_binding_audit(
            tx,
            context,
            "canonicalize",
            &BindingClaim {
                system: claim.system.clone(),
                identifier: previous,
            },
            Some(record_id),
            Some(record_id),
            Some(true),
            Some(false),
        )
        .await?;
    }
    sqlx::query(
        "UPDATE bindings SET is_canonical = 1 WHERE record_id = ? AND system = ? AND identifier = ?",
    )
    .bind(record_id)
    .bind(&claim.system)
    .bind(&claim.identifier)
    .execute(&mut **tx)
    .await?;
    append_binding_audit(
        tx,
        context,
        "canonicalize",
        claim,
        Some(record_id),
        Some(record_id),
        Some(false),
        Some(true),
    )
    .await?;
    Ok(true)
}

/// Transaction-borrowing identity resolution for sealed engine workflows.
///
/// Callers must already own the serialized write transaction. Keeping this
/// crate-private prevents transport and MCP surfaces from bypassing the
/// public self-committing service while allowing federation to make identity,
/// provenance, and Message projection one atomic change.
pub(crate) async fn resolve_external_in(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    context: &MutationContext<'_>,
    claims: &[BindingClaim],
    hints: &StubHints,
) -> Result<Resolution> {
    context.validate("resolve_external")?;
    if claims.is_empty() {
        return Err(Error::engine(
            "resolve_external requires at least one binding claim",
        ));
    }
    let mut normalized = Vec::with_capacity(claims.len());
    for claim in claims {
        normalized.push(rule_in(tx, claim, context.internal, None).await?);
    }
    let mut owners = Vec::new();
    let mut resolved = Vec::with_capacity(normalized.len());
    for (claim, rule) in normalized {
        let owner = sqlx::query_scalar::<_, String>(
            "SELECT record_id FROM bindings WHERE system = ? AND identifier = ?",
        )
        .bind(&claim.system)
        .bind(&claim.identifier)
        .fetch_optional(&mut **tx)
        .await?;
        if let Some(owner) = owner.as_ref() {
            if !owners.contains(owner) {
                owners.push(owner.clone());
            }
        }
        resolved.push((claim, rule, owner));
    }
    for owner in &owners {
        require_binding_visibility_in(tx, context, owner).await?;
    }
    if owners.len() > 1 {
        return Err(Error::engine(
            "reconciliation conflict: supplied bindings resolve to different visible records",
        ));
    }
    let missing = resolved.iter().any(|(_, _, owner)| owner.is_none());
    let (record_id, created) = if let Some(owner) = owners.first() {
        (owner.clone(), false)
    } else {
        let primary_rule = &resolved[0].1;
        if !primary_rule.stub_allowed {
            return Err(Error::engine(format!(
                "binding system '{}' cannot create an identity-only stub",
                primary_rule.system
            )));
        }
        require_capability_in(tx, context, UNFILED_RECORD_ID, Capability::Edit).await?;
        let record_type = primary_rule
            .compatible_type
            .clone()
            .or_else(|| hints.record_type.clone())
            .ok_or_else(|| {
                Error::engine("record_type hint is required to resolve this native-record miss")
            })?;
        let kind = primary_rule
            .compatible_kind
            .clone()
            .or_else(|| hints.kind.clone())
            .ok_or_else(|| {
                Error::engine("kind hint is required to resolve this native-record miss")
            })?;
        let record_id = Uuid::new_v4().to_string();
        let owner_id: Option<String> = sqlx::query_scalar(
            "SELECT record_id FROM bindings
              WHERE system = 'account' AND identifier = ? AND is_canonical = 1",
        )
        .bind(context.actor)
        .fetch_optional(&mut **tx)
        .await?;
        append_in(
            db,
            tx,
            AppendSpec {
                record_id: record_id.clone(),
                event_type: "record.created".into(),
                payload: json!({
                    "type": record_type,
                    "kind": kind,
                    "name": hints.name.clone().unwrap_or_else(|| format!("External {}", &record_id[..8])),
                    "home_id": UNFILED_RECORD_ID,
                    "owner_id": owner_id,
                    "persistence": "enduring"
                }),
                actor: Some(context.actor.into()),
            },
        )
        .await?;
        (record_id, true)
    };
    if missing {
        // Every binding add, including the bindings on a freshly created
        // shadow, crosses the same record-manage boundary. Pure hits remain
        // readable with view authority and perform no write.
        require_capability_in(tx, context, &record_id, Capability::Manage).await?;
    }
    let mut added = Vec::new();
    for (claim, rule, owner) in resolved {
        require_record_shape(tx, &record_id, &rule).await?;
        if owner.is_some() {
            // A resolution hit is observational: preserve the binding's
            // canonical flag and audit tail exactly as found.
            continue;
        }
        enforce_operation_policy(&rule, BindingOperation::Add, context.internal)?;
        if add_binding_in(tx, context, &record_id, &claim, true).await? {
            added.push(claim);
        }
    }
    Ok(Resolution {
        record_id,
        created,
        bindings_added: added,
    })
}

pub async fn resolve_external(
    db: &Db,
    context: &MutationContext<'_>,
    claims: &[BindingClaim],
    hints: &StubHints,
) -> Result<Resolution> {
    context.validate("resolve_external")?;
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let result = resolve_external_in(db, &mut tx, context, claims, hints).await?;
    if result.created || !result.bindings_added.is_empty() {
        tx.commit().await?;
    } else {
        tx.rollback().await?;
    }
    Ok(result)
}

pub async fn list_bindings(
    db: &Db,
    actor: &str,
    record_id: &str,
) -> Result<Vec<serde_json::Value>> {
    authorization::require_capability(
        db,
        Principal::bound(actor, true),
        record_id,
        Capability::View,
    )
    .await?;
    let rows = sqlx::query(
        "SELECT b.system, b.identifier, b.is_canonical, b.url, b.etag, b.last_seen_at
           FROM bindings b
           JOIN binding_systems s ON s.system = b.system
          WHERE b.record_id = ? AND s.visibility = 'public'
          ORDER BY b.system, b.is_canonical DESC, b.identifier",
    )
    .bind(record_id)
    .fetch_all(db.write_pool())
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(json!({
                "system": row.try_get::<String, _>("system")?,
                "identifier": row.try_get::<String, _>("identifier")?,
                "is_canonical": row.try_get::<i64, _>("is_canonical")? != 0,
                "url": row.try_get::<Option<String>, _>("url")?,
                "etag": row.try_get::<Option<String>, _>("etag")?,
                "last_seen_at": row.try_get::<Option<String>, _>("last_seen_at")?,
            }))
        })
        .collect()
}

/// Return a bounded, payload-free observation summary for a visible record.
/// Immutable attachment bytes and record content are deliberately not joined.
pub async fn list_observations(
    db: &Db,
    actor: &str,
    record_id: &str,
    limit: i64,
) -> Result<Vec<serde_json::Value>> {
    if !(1..=50).contains(&limit) {
        return Err(Error::engine(
            "list_observations: limit must be between 1 and 50",
        ));
    }
    authorization::require_capability(
        db,
        Principal::bound(actor, true),
        record_id,
        Capability::View,
    )
    .await?;
    let rows = sqlx::query(
        "SELECT o.id,o.source_system,o.source_identifier,o.quality,o.as_of,o.observed_at,
                o.materialization_policy,o.source_revision,o.source_digest,
                o.freshness,o.retention_state,o.source_availability,o.refresh_outcome,
                o.retained_from_observation_id,o.provenance_attachment_id
           FROM external_observations o
           JOIN binding_systems s ON s.system=o.source_system
          WHERE o.record_id=? AND s.visibility='public'
          ORDER BY o.observed_at DESC,o.id DESC LIMIT ?",
    )
    .bind(record_id)
    .bind(limit)
    .fetch_all(db.write_pool())
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(json!({
                "observation_id": row.try_get::<String, _>("id")?,
                "source": {
                    "system": row.try_get::<String, _>("source_system")?,
                    "identifier": row.try_get::<String, _>("source_identifier")?,
                },
                "quality": row.try_get::<String, _>("quality")?,
                "as_of": row.try_get::<Option<String>, _>("as_of")?,
                "observed_at": row.try_get::<String, _>("observed_at")?,
                "materialization_policy": row.try_get::<String, _>("materialization_policy")?,
                "provenance": {
                    "source_revision": row.try_get::<Option<String>, _>("source_revision")?,
                    "source_digest": row.try_get::<Option<String>, _>("source_digest")?,
                    "freshness": row.try_get::<String, _>("freshness")?,
                    "retention_state": row.try_get::<String, _>("retention_state")?,
                    "source_availability": row.try_get::<String, _>("source_availability")?,
                    "refresh_outcome": row.try_get::<String, _>("refresh_outcome")?,
                    "retained_from_observation_id": row.try_get::<Option<String>, _>("retained_from_observation_id")?,
                },
                "attachment_id": row.try_get::<Option<String>, _>("provenance_attachment_id")?,
            }))
        })
        .collect()
}

/// Resolve an exact public binding without creating or changing a shadow.
/// Invisible owners collapse to `None` so lookup cannot become an oracle.
pub async fn find_visible_binding_record(
    db: &Db,
    actor: &str,
    claim: &BindingClaim,
) -> Result<Option<String>> {
    let identifier = normalize_identifier(&claim.system, &claim.identifier)?;
    let record_id: Option<String> = sqlx::query_scalar(
        "SELECT b.record_id FROM bindings b
           JOIN binding_systems s ON s.system=b.system
          WHERE b.system=? AND b.identifier=? AND s.visibility='public'",
    )
    .bind(&claim.system)
    .bind(identifier)
    .fetch_optional(db.write_pool())
    .await?;
    let Some(record_id) = record_id else {
        return Ok(None);
    };
    match authorization::require_capability(
        db,
        Principal::bound(actor, true),
        &record_id,
        Capability::View,
    )
    .await
    {
        Ok(()) => Ok(Some(record_id)),
        Err(_) => Ok(None),
    }
}

pub async fn latest_snapshot_observation(
    db: &Db,
    actor: &str,
    record_id: &str,
    claim: &BindingClaim,
) -> Result<Option<String>> {
    authorization::require_capability(
        db,
        Principal::bound(actor, true),
        record_id,
        Capability::View,
    )
    .await?;
    let identifier = normalize_identifier(&claim.system, &claim.identifier)?;
    sqlx::query_scalar(
        "SELECT id FROM external_observations
          WHERE record_id=? AND source_system=? AND source_identifier=?
            AND materialization_policy='snapshot' AND provenance_attachment_id IS NOT NULL
          ORDER BY observed_at DESC,id DESC LIMIT 1",
    )
    .bind(record_id)
    .bind(&claim.system)
    .bind(identifier)
    .fetch_optional(db.write_pool())
    .await
    .map_err(Into::into)
}

async fn binding_record_name(
    tx: &mut Transaction<'static, Sqlite>,
    record_id: &str,
) -> Result<String> {
    sqlx::query_scalar("SELECT name FROM records WHERE id = ?")
        .bind(record_id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| Error::engine(format!("record '{record_id}' not found")))
}

#[cfg(feature = "mcp-executor-prototype")]
fn binding_preparation(
    mut canonical_source_arguments: serde_json::Value,
    state_revision: String,
    target_id: String,
    target: String,
    state: serde_json::Value,
    effect: serde_json::Value,
    effect_summary: String,
) -> Result<BindingMutationPreparation> {
    let target_state_digest = hex::encode(Sha256::digest(serde_jcs::to_vec(&state)?));
    canonical_source_arguments["if_binding_state_revision"] = json!(state_revision);
    Ok(BindingMutationPreparation {
        canonical_source_arguments,
        target_id,
        target,
        state_revision,
        target_state_digest,
        effect,
        effect_summary,
    })
}

/// Source-owned identity high-water used as an optimistic concurrency fence.
/// Every governed binding change appends `binding_audit` in the same
/// transaction. Binding-system policy and the relevant records' content heads
/// are included because they can change normalization, eligibility, labels, or
/// the approved target even without a binding mutation.
async fn binding_state_revision_in(
    tx: &mut Transaction<'static, Sqlite>,
    record_ids: &[&str],
) -> Result<String> {
    let audit_seq: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM binding_audit")
        .fetch_one(&mut **tx)
        .await?;
    let system_rows = sqlx::query(
        "SELECT system,normalizer,compatible_type,compatible_kind,visibility,
                add_policy,remove_policy,canonicalize_policy,transfer_policy,
                reconciliation_rule,stub_allowed,authoritative_provenance,required_durable
           FROM binding_systems ORDER BY system",
    )
    .fetch_all(&mut **tx)
    .await?;
    let systems = system_rows
        .into_iter()
        .map(|row| {
            Ok(json!({
                "system":row.try_get::<String,_>("system")?,
                "normalizer":row.try_get::<String,_>("normalizer")?,
                "compatible_type":row.try_get::<Option<String>,_>("compatible_type")?,
                "compatible_kind":row.try_get::<Option<String>,_>("compatible_kind")?,
                "visibility":row.try_get::<String,_>("visibility")?,
                "add_policy":row.try_get::<String,_>("add_policy")?,
                "remove_policy":row.try_get::<String,_>("remove_policy")?,
                "canonicalize_policy":row.try_get::<String,_>("canonicalize_policy")?,
                "transfer_policy":row.try_get::<String,_>("transfer_policy")?,
                "reconciliation_rule":row.try_get::<String,_>("reconciliation_rule")?,
                "stub_allowed":row.try_get::<i64,_>("stub_allowed")?,
                "authoritative_provenance":row.try_get::<i64,_>("authoritative_provenance")?,
                "required_durable":row.try_get::<i64,_>("required_durable")?,
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut record_ids = record_ids.to_vec();
    record_ids.sort_unstable();
    record_ids.dedup();
    let mut records = Vec::with_capacity(record_ids.len());
    for record_id in record_ids {
        let row = sqlx::query(
            "SELECT type,kind,name,deleted_at,
                    (SELECT MAX(seq) FROM content_events WHERE record_id=records.id) AS content_seq
               FROM records WHERE id=?",
        )
        .bind(record_id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| Error::engine(format!("record '{record_id}' not found")))?;
        records.push(json!({
            "id":record_id,
            "type":row.try_get::<String,_>("type")?,
            "kind":row.try_get::<Option<String>,_>("kind")?,
            "name":row.try_get::<String,_>("name")?,
            "deleted_at":row.try_get::<Option<String>,_>("deleted_at")?,
            "content_seq":row.try_get::<Option<i64>,_>("content_seq")?,
        }));
    }
    let state = json!({
        "schema":"native.binding-state-revision.v1",
        "binding_audit_seq":audit_seq,
        "binding_systems":systems,
        "records":records,
    });
    Ok(format!(
        "ibsv1:{}",
        hex::encode(Sha256::digest(serde_jcs::to_vec(&state)?))
    ))
}

async fn require_binding_state_revision_in(
    tx: &mut Transaction<'static, Sqlite>,
    record_ids: &[&str],
    expected: Option<&str>,
) -> Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };
    let current = binding_state_revision_in(tx, record_ids).await?;
    if current != expected {
        return Err(Error::engine(format!(
            "binding state revision conflict: expected {expected}, current {current}"
        )));
    }
    Ok(())
}

#[cfg_attr(not(feature = "mcp-executor-prototype"), allow(dead_code))]
struct PlannedBindingMutation<T> {
    plan: T,
    rule: SystemRule,
    target_name: Option<String>,
    state_revision: Option<String>,
}

async fn plan_add_binding_in(
    tx: &mut Transaction<'static, Sqlite>,
    context: &MutationContext<'_>,
    record_id: &str,
    claim: &BindingClaim,
    canonical: bool,
    expected_state_revision: Option<&str>,
    capture_preparation: bool,
) -> Result<PlannedBindingMutation<AddBindingPlan>> {
    context.validate("manage_bindings")?;
    require_capability_in(tx, context, record_id, Capability::Manage).await?;
    let (claim, rule) = rule_in(tx, claim, context.internal, Some(BindingOperation::Add)).await?;
    require_record_shape(tx, record_id, &rule).await?;
    // Preserve execution error precedence: the source-owned fence wins before
    // add-specific live binding interpretation.
    require_binding_state_revision_in(tx, &[record_id], expected_state_revision).await?;
    let target_name = if capture_preparation {
        Some(binding_record_name(tx, record_id).await?)
    } else {
        None
    };
    let existing_row =
        sqlx::query("SELECT record_id,is_canonical FROM bindings WHERE system=? AND identifier=?")
            .bind(&claim.system)
            .bind(&claim.identifier)
            .fetch_optional(&mut **tx)
            .await?;
    let existing = if let Some(row) = existing_row {
        let binding = ExistingBinding {
            record_id: row.try_get("record_id")?,
            canonical: row.try_get::<i64, _>("is_canonical")? != 0,
        };
        if binding.record_id != record_id {
            require_binding_visibility_in(tx, context, &binding.record_id).await?;
        }
        Some(binding)
    } else {
        None
    };
    binding_plan::validate_add_owner(record_id, existing.as_ref())
        .map_err(|error| Error::engine(error.to_string()))?;
    let was_canonical = existing.as_ref().is_some_and(|binding| binding.canonical);
    let previous_canonical = if canonical && !was_canonical {
        sqlx::query_scalar::<_, String>(
            "SELECT identifier FROM bindings WHERE record_id=? AND system=? AND is_canonical=1",
        )
        .bind(record_id)
        .bind(&claim.system)
        .fetch_optional(&mut **tx)
        .await?
    } else {
        None
    };
    let plan = binding_plan::plan_add(record_id, claim, canonical, existing, previous_canonical)
        .map_err(|error| Error::engine(error.to_string()))?;
    let state_revision = if capture_preparation {
        Some(binding_state_revision_in(tx, &[record_id]).await?)
    } else {
        None
    };
    Ok(PlannedBindingMutation {
        plan,
        rule,
        target_name,
        state_revision,
    })
}

async fn apply_add_binding_plan_in(
    tx: &mut Transaction<'static, Sqlite>,
    context: &MutationContext<'_>,
    plan: &AddBindingPlan,
) -> Result<()> {
    if !plan.changed {
        return Ok(());
    }
    if let Some(previous) = plan.previous_canonical.as_deref() {
        if previous != plan.claim.identifier.as_str() {
            sqlx::query(
                "UPDATE bindings SET is_canonical=0 WHERE record_id=? AND system=? AND identifier=?",
            )
            .bind(&plan.record_id)
            .bind(&plan.claim.system)
            .bind(previous)
            .execute(&mut **tx)
            .await?;
            let previous_claim = BindingClaim {
                system: plan.claim.system.clone(),
                identifier: previous.into(),
            };
            append_binding_audit(
                tx,
                context,
                "canonicalize",
                &previous_claim,
                Some(&plan.record_id),
                Some(&plan.record_id),
                Some(true),
                Some(false),
            )
            .await?;
        }
    }
    if plan.present {
        sqlx::query(
            "UPDATE bindings SET is_canonical=1 WHERE record_id=? AND system=? AND identifier=?",
        )
        .bind(&plan.record_id)
        .bind(&plan.claim.system)
        .bind(&plan.claim.identifier)
        .execute(&mut **tx)
        .await?;
        append_binding_audit(
            tx,
            context,
            "canonicalize",
            &plan.claim,
            Some(&plan.record_id),
            Some(&plan.record_id),
            Some(false),
            Some(true),
        )
        .await?;
    } else {
        sqlx::query(
            "INSERT INTO bindings (record_id,system,identifier,is_canonical) VALUES (?,?,?,?)",
        )
        .bind(&plan.record_id)
        .bind(&plan.claim.system)
        .bind(&plan.claim.identifier)
        .bind(i64::from(plan.requested_canonical))
        .execute(&mut **tx)
        .await?;
        append_binding_audit(
            tx,
            context,
            "add",
            &plan.claim,
            None,
            Some(&plan.record_id),
            None,
            Some(plan.requested_canonical),
        )
        .await?;
    }
    Ok(())
}

async fn plan_canonicalize_binding_in(
    tx: &mut Transaction<'static, Sqlite>,
    context: &MutationContext<'_>,
    record_id: &str,
    claim: &BindingClaim,
    expected_state_revision: Option<&str>,
    capture_preparation: bool,
) -> Result<PlannedBindingMutation<CanonicalizeBindingPlan>> {
    context.validate("manage_bindings")?;
    require_capability_in(tx, context, record_id, Capability::Manage).await?;
    let (claim, rule) = rule_in(
        tx,
        claim,
        context.internal,
        Some(BindingOperation::Canonicalize),
    )
    .await?;
    // Preserve execution error precedence before target/canonical facts.
    require_binding_state_revision_in(tx, &[record_id], expected_state_revision).await?;
    let target_name = if capture_preparation {
        Some(binding_record_name(tx, record_id).await?)
    } else {
        None
    };
    let target_canonical = sqlx::query_scalar::<_, i64>(
        "SELECT is_canonical FROM bindings WHERE record_id=? AND system=? AND identifier=?",
    )
    .bind(record_id)
    .bind(&claim.system)
    .bind(&claim.identifier)
    .fetch_optional(&mut **tx)
    .await?
    .map(|value| value != 0);
    let previous_canonical =
        match target_canonical {
            Some(true) => Some(claim.identifier.clone()),
            Some(false) => sqlx::query_scalar::<_, String>(
                "SELECT identifier FROM bindings WHERE record_id=? AND system=? AND is_canonical=1",
            )
            .bind(record_id)
            .bind(&claim.system)
            .fetch_optional(&mut **tx)
            .await?,
            None => None,
        };
    let plan =
        binding_plan::plan_canonicalize(record_id, claim, target_canonical, previous_canonical)
            .map_err(|error| Error::engine(error.to_string()))?;
    let state_revision = if capture_preparation {
        Some(binding_state_revision_in(tx, &[record_id]).await?)
    } else {
        None
    };
    Ok(PlannedBindingMutation {
        plan,
        rule,
        target_name,
        state_revision,
    })
}

async fn apply_canonicalize_binding_plan_in(
    tx: &mut Transaction<'static, Sqlite>,
    context: &MutationContext<'_>,
    plan: &CanonicalizeBindingPlan,
) -> Result<()> {
    if !plan.changed {
        return Ok(());
    }
    if let Some(previous) = plan.previous_canonical.as_deref() {
        if previous != plan.claim.identifier.as_str() {
            sqlx::query(
                "UPDATE bindings SET is_canonical=0 WHERE record_id=? AND system=? AND identifier=?",
            )
            .bind(&plan.record_id)
            .bind(&plan.claim.system)
            .bind(previous)
            .execute(&mut **tx)
            .await?;
            let previous_claim = BindingClaim {
                system: plan.claim.system.clone(),
                identifier: previous.into(),
            };
            append_binding_audit(
                tx,
                context,
                "canonicalize",
                &previous_claim,
                Some(&plan.record_id),
                Some(&plan.record_id),
                Some(true),
                Some(false),
            )
            .await?;
        }
    }
    sqlx::query(
        "UPDATE bindings SET is_canonical=1 WHERE record_id=? AND system=? AND identifier=?",
    )
    .bind(&plan.record_id)
    .bind(&plan.claim.system)
    .bind(&plan.claim.identifier)
    .execute(&mut **tx)
    .await?;
    append_binding_audit(
        tx,
        context,
        "canonicalize",
        &plan.claim,
        Some(&plan.record_id),
        Some(&plan.record_id),
        Some(false),
        Some(true),
    )
    .await
}

async fn plan_remove_binding_in(
    tx: &mut Transaction<'static, Sqlite>,
    context: &MutationContext<'_>,
    record_id: &str,
    claim: &BindingClaim,
    expected_state_revision: Option<&str>,
    capture_preparation: bool,
) -> Result<PlannedBindingMutation<RemoveBindingPlan>> {
    context.validate("manage_bindings")?;
    require_capability_in(tx, context, record_id, Capability::Manage).await?;
    let (claim, rule) =
        rule_in(tx, claim, context.internal, Some(BindingOperation::Remove)).await?;
    // Preserve execution error precedence before presence/durability facts.
    require_binding_state_revision_in(tx, &[record_id], expected_state_revision).await?;
    let target_name = if capture_preparation {
        Some(binding_record_name(tx, record_id).await?)
    } else {
        None
    };
    let target_canonical = sqlx::query_scalar::<_, i64>(
        "SELECT is_canonical FROM bindings WHERE record_id=? AND system=? AND identifier=?",
    )
    .bind(record_id)
    .bind(&claim.system)
    .bind(&claim.identifier)
    .fetch_optional(&mut **tx)
    .await?
    .map(|value| value != 0);
    let (required_durable, system_binding_count) = if target_canonical.is_some() {
        let required = sqlx::query_scalar::<_, i64>(
            "SELECT required_durable FROM binding_systems WHERE system=?",
        )
        .bind(&claim.system)
        .fetch_one(&mut **tx)
        .await?
            != 0;
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM bindings WHERE record_id=? AND system=?",
        )
        .bind(record_id)
        .bind(&claim.system)
        .fetch_one(&mut **tx)
        .await?;
        (required, count)
    } else {
        (false, 0)
    };
    let plan = binding_plan::plan_remove(
        record_id,
        claim,
        target_canonical,
        required_durable,
        system_binding_count,
    )
    .map_err(|error| Error::engine(error.to_string()))?;
    let state_revision = if capture_preparation {
        Some(binding_state_revision_in(tx, &[record_id]).await?)
    } else {
        None
    };
    Ok(PlannedBindingMutation {
        plan,
        rule,
        target_name,
        state_revision,
    })
}

async fn apply_remove_binding_plan_in(
    tx: &mut Transaction<'static, Sqlite>,
    context: &MutationContext<'_>,
    plan: &RemoveBindingPlan,
) -> Result<()> {
    if !plan.changed {
        return Ok(());
    }
    sqlx::query("DELETE FROM bindings WHERE record_id=? AND system=? AND identifier=?")
        .bind(&plan.record_id)
        .bind(&plan.claim.system)
        .bind(&plan.claim.identifier)
        .execute(&mut **tx)
        .await?;
    append_binding_audit(
        tx,
        context,
        "remove",
        &plan.claim,
        Some(&plan.record_id),
        None,
        plan.was_canonical,
        None,
    )
    .await
}

#[cfg_attr(not(feature = "mcp-executor-prototype"), allow(dead_code))]
struct PlannedReconcileMutation {
    plan: ReconcileBindingPlan,
    target_name: Option<String>,
    source_name: Option<String>,
    state_revision: Option<String>,
}

#[allow(clippy::too_many_arguments)]
async fn plan_reconcile_bindings_in(
    tx: &mut Transaction<'static, Sqlite>,
    context: &MutationContext<'_>,
    target_record_id: &str,
    expected_source_record_id: &str,
    claims: &[BindingClaim],
    expected_state_revision: Option<&str>,
    complete_transition: bool,
    capture_preparation: bool,
) -> Result<PlannedReconcileMutation> {
    if complete_transition {
        context.validate("manage_bindings")?;
    }
    if claims.is_empty() {
        return Err(Error::engine(
            "reconcile requires at least one selected binding",
        ));
    }
    if target_record_id == expected_source_record_id {
        return Err(Error::engine(
            "reconcile target and expected source records must be different",
        ));
    }
    require_capability_in(tx, context, target_record_id, Capability::Manage).await?;
    require_capability_in(tx, context, expected_source_record_id, Capability::Manage).await?;
    let (target_name, source_name) = if capture_preparation {
        (
            Some(binding_record_name(tx, target_record_id).await?),
            Some(binding_record_name(tx, expected_source_record_id).await?),
        )
    } else {
        (None, None)
    };
    let mut selected = Vec::with_capacity(claims.len());
    let mut seen = HashSet::new();
    for claim in claims {
        let (claim, rule) = rule_in(
            tx,
            claim,
            context.internal,
            Some(BindingOperation::Transfer),
        )
        .await?;
        if !seen.insert((claim.system.clone(), claim.identifier.clone())) {
            return Err(Error::engine(format!(
                "reconcile selected duplicate binding {}:{}",
                claim.system, claim.identifier
            )));
        }
        if rule.reconciliation_rule != "binding_only" {
            return Err(Error::engine(format!(
                "binding system '{}' does not permit binding-only reconciliation",
                rule.system
            )));
        }
        require_record_shape(tx, target_record_id, &rule).await?;
        let owner_record_id = sqlx::query_scalar::<_, String>(
            "SELECT record_id FROM bindings WHERE system=? AND identifier=?",
        )
        .bind(&claim.system)
        .bind(&claim.identifier)
        .fetch_optional(&mut **tx)
        .await?;
        if let Some(actual_owner) = owner_record_id.as_deref() {
            if actual_owner != expected_source_record_id {
                require_binding_visibility_in(tx, context, actual_owner).await?;
            }
        }
        let mut fact = ReconcileBindingFact {
            claim,
            owner_record_id,
            canonical: false,
            target_canonical_identifier: None,
            transfer_policy: rule.transfer_policy,
            reconciliation_rule: rule.reconciliation_rule,
        };
        binding_plan::validate_reconcile_owners(
            expected_source_record_id,
            std::slice::from_ref(&fact),
        )
        .map_err(|error| Error::engine(error.to_string()))?;
        if complete_transition && capture_preparation {
            fact.canonical = sqlx::query_scalar::<_, i64>(
                "SELECT is_canonical FROM bindings WHERE record_id=? AND system=? AND identifier=?",
            )
            .bind(expected_source_record_id)
            .bind(&fact.claim.system)
            .bind(&fact.claim.identifier)
            .fetch_one(&mut **tx)
            .await?
                != 0;
            fact.target_canonical_identifier = sqlx::query_scalar::<_, String>(
                "SELECT identifier FROM bindings WHERE record_id=? AND system=? AND is_canonical=1",
            )
            .bind(target_record_id)
            .bind(&fact.claim.system)
            .fetch_optional(&mut **tx)
            .await?;
            binding_plan::plan_reconcile(
                target_record_id,
                expected_source_record_id,
                vec![fact.clone()],
            )
            .map_err(|error| Error::engine(error.to_string()))?;
        }
        selected.push(fact);
    }
    binding_plan::validate_reconcile_owners(expected_source_record_id, &selected)
        .map_err(|error| Error::engine(error.to_string()))?;
    if !complete_transition {
        return Ok(PlannedReconcileMutation {
            plan: ReconcileBindingPlan {
                target_record_id: target_record_id.into(),
                source_record_id: expected_source_record_id.into(),
                bindings: selected,
            },
            target_name,
            source_name,
            state_revision: None,
        });
    }
    // Reconciliation historically verifies every selected owner before the
    // revision fence, then resolves canonical collisions after it.
    require_binding_state_revision_in(
        tx,
        &[target_record_id, expected_source_record_id],
        expected_state_revision,
    )
    .await?;
    if !capture_preparation {
        for binding in &mut selected {
            binding.canonical = sqlx::query_scalar::<_, i64>(
                "SELECT is_canonical FROM bindings WHERE record_id=? AND system=? AND identifier=?",
            )
            .bind(expected_source_record_id)
            .bind(&binding.claim.system)
            .bind(&binding.claim.identifier)
            .fetch_one(&mut **tx)
            .await?
                != 0;
            if binding.canonical {
                binding.target_canonical_identifier = sqlx::query_scalar::<_, String>(
                    "SELECT identifier FROM bindings WHERE record_id=? AND system=? AND is_canonical=1",
                )
                .bind(target_record_id)
                .bind(&binding.claim.system)
                .fetch_optional(&mut **tx)
                .await?;
            }
        }
    }
    let plan = binding_plan::plan_reconcile(target_record_id, expected_source_record_id, selected)
        .map_err(|error| Error::engine(error.to_string()))?;
    let state_revision = if capture_preparation {
        Some(binding_state_revision_in(tx, &[target_record_id, expected_source_record_id]).await?)
    } else {
        None
    };
    Ok(PlannedReconcileMutation {
        plan,
        target_name,
        source_name,
        state_revision,
    })
}

async fn apply_reconcile_binding_plan_in(
    tx: &mut Transaction<'static, Sqlite>,
    context: &MutationContext<'_>,
    plan: &ReconcileBindingPlan,
) -> Result<()> {
    for binding in &plan.bindings {
        sqlx::query(
            "UPDATE bindings SET record_id=? WHERE record_id=? AND system=? AND identifier=?",
        )
        .bind(&plan.target_record_id)
        .bind(&plan.source_record_id)
        .bind(&binding.claim.system)
        .bind(&binding.claim.identifier)
        .execute(&mut **tx)
        .await?;
        append_binding_audit(
            tx,
            context,
            "transfer",
            &binding.claim,
            Some(&plan.source_record_id),
            Some(&plan.target_record_id),
            Some(binding.canonical),
            Some(binding.canonical),
        )
        .await?;
    }
    Ok(())
}

/// Prepare an exact add/canonicalize-on-add effect without writing a binding
/// or audit row. Collision concealment and system policy are identical to the
/// production mutation path.
#[cfg(feature = "mcp-executor-prototype")]
pub(crate) async fn prepare_add_binding(
    db: &Db,
    context: &MutationContext<'_>,
    record_id: &str,
    claim: &BindingClaim,
    canonical: bool,
) -> Result<BindingMutationPreparation> {
    context.validate("manage_bindings")?;
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let planned =
        plan_add_binding_in(&mut tx, context, record_id, claim, canonical, None, true).await?;
    let plan = &planned.plan;
    let target_name = planned.target_name.as_deref().expect("preparation label");
    let state = json!({
        "operation":"add",
        "record_id":record_id,
        "binding":plan.claim,
        "present":plan.present,
        "canonical":plan.was_canonical,
        "previous_canonical_identifier":plan.previous_canonical,
        "system_policy":{"add":planned.rule.add_policy,"canonicalize":planned.rule.canonicalize_policy},
    });
    let effect = json!({
        "action":"add",
        "target":{"record_id":record_id,"name":target_name},
        "binding":plan.claim,
        "before":{
            "present":plan.present,
            "canonical":plan.was_canonical,
            "canonical_identifier":plan.previous_canonical,
        },
        "after":{"present":true,"canonical":canonical || plan.was_canonical},
        "changed":plan.changed,
    });
    let effect_summary = if plan.changed {
        format!(
            "add {}:{} to '{}' ({record_id}){}",
            plan.claim.system,
            plan.claim.identifier,
            target_name,
            if canonical { " as canonical" } else { "" }
        )
    } else {
        format!(
            "leave existing {}:{} on '{}' ({record_id}) unchanged",
            plan.claim.system, plan.claim.identifier, target_name
        )
    };
    let prepared = binding_preparation(
        json!({
            "action":"add",
            "record_id":record_id,
            "binding":plan.claim,
            "canonical":canonical,
            "reason":context.reason,
        }),
        planned.state_revision.expect("preparation revision"),
        record_id.to_string(),
        format!("{} ({record_id})", target_name),
        state,
        effect,
        effect_summary,
    )?;
    tx.rollback().await?;
    Ok(prepared)
}

/// Prepare an exact canonicalization effect without updating canonical flags.
#[cfg(feature = "mcp-executor-prototype")]
pub(crate) async fn prepare_canonicalize_binding(
    db: &Db,
    context: &MutationContext<'_>,
    record_id: &str,
    claim: &BindingClaim,
) -> Result<BindingMutationPreparation> {
    context.validate("manage_bindings")?;
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let planned =
        plan_canonicalize_binding_in(&mut tx, context, record_id, claim, None, true).await?;
    let plan = &planned.plan;
    let target_name = planned.target_name.as_deref().expect("preparation label");
    let state = json!({
        "operation":"canonicalize",
        "record_id":record_id,
        "binding":plan.claim,
        "target_canonical":plan.was_canonical,
        "previous_canonical_identifier":plan.previous_canonical,
        "system_policy":{"canonicalize":planned.rule.canonicalize_policy},
    });
    let effect = json!({
        "action":"canonicalize",
        "target":{"record_id":record_id,"name":target_name},
        "binding":plan.claim,
        "before":{"canonical":plan.was_canonical,"canonical_identifier":plan.previous_canonical},
        "after":{"canonical":true,"canonical_identifier":plan.claim.identifier},
        "changed":plan.changed,
    });
    let effect_summary = if plan.changed {
        format!(
            "make {}:{} canonical on '{}' ({record_id})",
            plan.claim.system, plan.claim.identifier, target_name
        )
    } else {
        format!(
            "leave already-canonical {}:{} on '{}' ({record_id}) unchanged",
            plan.claim.system, plan.claim.identifier, target_name
        )
    };
    let prepared = binding_preparation(
        json!({
            "action":"canonicalize",
            "record_id":record_id,
            "binding":plan.claim,
            "reason":context.reason,
        }),
        planned.state_revision.expect("preparation revision"),
        record_id.to_string(),
        format!("{} ({record_id})", target_name),
        state,
        effect,
        effect_summary,
    )?;
    tx.rollback().await?;
    Ok(prepared)
}

/// Prepare an exact removal effect, including the required-durable guard,
/// without deleting the binding or appending its audit row.
#[cfg(feature = "mcp-executor-prototype")]
pub(crate) async fn prepare_remove_binding(
    db: &Db,
    context: &MutationContext<'_>,
    record_id: &str,
    claim: &BindingClaim,
) -> Result<BindingMutationPreparation> {
    context.validate("manage_bindings")?;
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let planned = plan_remove_binding_in(&mut tx, context, record_id, claim, None, true).await?;
    let plan = &planned.plan;
    let target_name = planned.target_name.as_deref().expect("preparation label");
    let state = json!({
        "operation":"remove",
        "record_id":record_id,
        "binding":plan.claim,
        "present":plan.was_canonical.is_some(),
        "canonical":plan.was_canonical,
        "required_durable":plan.required_durable,
        "system_binding_count":plan.system_binding_count,
        "system_policy":{"remove":planned.rule.remove_policy},
    });
    let effect = json!({
        "action":"remove",
        "target":{"record_id":record_id,"name":target_name},
        "binding":plan.claim,
        "before":{"present":plan.was_canonical.is_some(),"canonical":plan.was_canonical},
        "after":{"present":false},
        "changed":plan.changed,
    });
    let effect_summary = if plan.changed {
        format!(
            "remove {}:{} from '{}' ({record_id})",
            plan.claim.system, plan.claim.identifier, target_name
        )
    } else {
        format!(
            "leave absent {}:{} on '{}' ({record_id}) unchanged",
            plan.claim.system, plan.claim.identifier, target_name
        )
    };
    let prepared = binding_preparation(
        json!({
            "action":"remove",
            "record_id":record_id,
            "binding":plan.claim,
            "reason":context.reason,
        }),
        planned.state_revision.expect("preparation revision"),
        record_id.to_string(),
        format!("{} ({record_id})", target_name),
        state,
        effect,
        effect_summary,
    )?;
    tx.rollback().await?;
    Ok(prepared)
}

/// Prepare exact binding-only transfers. Each normalized identity, its current
/// owner/canonical bit and any target canonical collision are resolved before
/// the effect is returned; no record merge or guessed reconciliation occurs.
#[cfg(feature = "mcp-executor-prototype")]
pub(crate) async fn prepare_reconcile_bindings(
    db: &Db,
    context: &MutationContext<'_>,
    target_record_id: &str,
    expected_source_record_id: &str,
    claims: &[BindingClaim],
) -> Result<BindingMutationPreparation> {
    context.validate("manage_bindings")?;
    if claims.is_empty() {
        return Err(Error::engine(
            "reconcile requires at least one selected binding",
        ));
    }
    if target_record_id == expected_source_record_id {
        return Err(Error::engine(
            "reconcile target and expected source records must be different",
        ));
    }
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let planned = plan_reconcile_bindings_in(
        &mut tx,
        context,
        target_record_id,
        expected_source_record_id,
        claims,
        None,
        true,
        true,
    )
    .await?;
    let target_name = planned.target_name.as_deref().expect("preparation label");
    let source_name = planned.source_name.as_deref().expect("preparation label");
    let selected = planned
        .plan
        .bindings
        .iter()
        .map(|binding| {
            json!({
                "binding":binding.claim,
                "from_record_id":expected_source_record_id,
                "to_record_id":target_record_id,
                "canonical":binding.canonical,
                "target_canonical_identifier":binding.target_canonical_identifier,
                "system_policy":{
                    "transfer":binding.transfer_policy,
                    "reconciliation_rule":binding.reconciliation_rule,
                },
            })
        })
        .collect::<Vec<_>>();
    let normalized_claims = planned
        .plan
        .bindings
        .iter()
        .map(|binding| binding.claim.clone())
        .collect::<Vec<_>>();
    let state = json!({
        "operation":"reconcile",
        "target_record_id":target_record_id,
        "source_record_id":expected_source_record_id,
        "selected":selected,
    });
    let effect = json!({
        "action":"reconcile",
        "target":{"record_id":target_record_id,"name":target_name},
        "source":{"record_id":expected_source_record_id,"name":source_name},
        "bindings":selected,
        "scope":"bindings_only",
        "changed":true,
    });
    let effect_summary = format!(
        "transfer {} selected binding{} from '{}' ({expected_source_record_id}) to '{}' ({target_record_id})",
        selected.len(),
        if selected.len() == 1 { "" } else { "s" },
        source_name,
        target_name,
    );
    let prepared = binding_preparation(
        json!({
            "action":"reconcile",
            "target_record_id":target_record_id,
            "expected_source_record_id":expected_source_record_id,
            "bindings":normalized_claims,
            "apply":true,
            "reason":context.reason,
        }),
        planned.state_revision.expect("preparation revision"),
        target_record_id.to_string(),
        format!(
            "{} ({target_record_id}) from {} ({expected_source_record_id})",
            target_name, source_name
        ),
        state,
        effect,
        effect_summary,
    )?;
    tx.rollback().await?;
    Ok(prepared)
}

pub async fn add_binding(
    db: &Db,
    context: &MutationContext<'_>,
    record_id: &str,
    claim: &BindingClaim,
    canonical: bool,
) -> Result<bool> {
    add_binding_if_revision(db, context, record_id, claim, canonical, None).await
}

pub(crate) async fn add_binding_if_revision(
    db: &Db,
    context: &MutationContext<'_>,
    record_id: &str,
    claim: &BindingClaim,
    canonical: bool,
    expected_state_revision: Option<&str>,
) -> Result<bool> {
    context.validate("manage_bindings")?;
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let planned = plan_add_binding_in(
        &mut tx,
        context,
        record_id,
        claim,
        canonical,
        expected_state_revision,
        false,
    )
    .await?;
    apply_add_binding_plan_in(&mut tx, context, &planned.plan).await?;
    if planned.plan.changed {
        tx.commit().await?
    } else {
        tx.rollback().await?
    }
    Ok(planned.plan.changed)
}

pub async fn canonicalize_binding(
    db: &Db,
    context: &MutationContext<'_>,
    record_id: &str,
    claim: &BindingClaim,
) -> Result<bool> {
    canonicalize_binding_if_revision(db, context, record_id, claim, None).await
}

pub(crate) async fn canonicalize_binding_if_revision(
    db: &Db,
    context: &MutationContext<'_>,
    record_id: &str,
    claim: &BindingClaim,
    expected_state_revision: Option<&str>,
) -> Result<bool> {
    context.validate("manage_bindings")?;
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let planned = plan_canonicalize_binding_in(
        &mut tx,
        context,
        record_id,
        claim,
        expected_state_revision,
        false,
    )
    .await?;
    apply_canonicalize_binding_plan_in(&mut tx, context, &planned.plan).await?;
    if planned.plan.changed {
        tx.commit().await?;
    } else {
        tx.rollback().await?;
    }
    Ok(planned.plan.changed)
}

pub async fn remove_binding(
    db: &Db,
    context: &MutationContext<'_>,
    record_id: &str,
    claim: &BindingClaim,
) -> Result<bool> {
    remove_binding_if_revision(db, context, record_id, claim, None).await
}

pub(crate) async fn remove_binding_if_revision(
    db: &Db,
    context: &MutationContext<'_>,
    record_id: &str,
    claim: &BindingClaim,
    expected_state_revision: Option<&str>,
) -> Result<bool> {
    context.validate("manage_bindings")?;
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let planned = plan_remove_binding_in(
        &mut tx,
        context,
        record_id,
        claim,
        expected_state_revision,
        false,
    )
    .await?;
    apply_remove_binding_plan_in(&mut tx, context, &planned.plan).await?;
    if planned.plan.changed {
        tx.commit().await?;
    } else {
        tx.rollback().await?;
    }
    Ok(planned.plan.changed)
}

pub async fn reconcile_bindings(
    db: &Db,
    context: &MutationContext<'_>,
    target_record_id: &str,
    expected_source_record_id: &str,
    claims: &[BindingClaim],
    apply: bool,
) -> Result<Vec<BindingClaim>> {
    reconcile_bindings_if_revision(
        db,
        context,
        target_record_id,
        expected_source_record_id,
        claims,
        apply,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn reconcile_bindings_if_revision(
    db: &Db,
    context: &MutationContext<'_>,
    target_record_id: &str,
    expected_source_record_id: &str,
    claims: &[BindingClaim],
    apply: bool,
    expected_state_revision: Option<&str>,
) -> Result<Vec<BindingClaim>> {
    if apply {
        context.validate("manage_bindings")?;
    }
    if claims.is_empty() {
        return Err(Error::engine(
            "reconcile requires at least one selected binding",
        ));
    }
    if target_record_id == expected_source_record_id {
        return Err(Error::engine(
            "reconcile target and expected source records must be different",
        ));
    }
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let planned = plan_reconcile_bindings_in(
        &mut tx,
        context,
        target_record_id,
        expected_source_record_id,
        claims,
        expected_state_revision,
        apply,
        false,
    )
    .await?;
    let normalized = planned
        .plan
        .bindings
        .iter()
        .map(|binding| binding.claim.clone())
        .collect::<Vec<_>>();
    if !apply {
        tx.rollback().await?;
        return Ok(normalized);
    }
    apply_reconcile_binding_plan_in(&mut tx, context, &planned.plan).await?;
    tx.commit().await?;
    Ok(normalized)
}

struct Snapshot<'a> {
    bytes: &'a [u8],
    mime: Option<&'a str>,
    filename: Option<&'a str>,
}

async fn insert_blob_in(
    tx: &mut Transaction<'static, Sqlite>,
    snapshot: &Snapshot<'_>,
) -> Result<BlobMeta> {
    let meta = BlobMeta {
        id: Uuid::new_v4().to_string(),
        mime: snapshot.mime.map(String::from),
        size_bytes: snapshot.bytes.len() as i64,
        sha256: hex::encode(Sha256::digest(snapshot.bytes)),
        original_filename: snapshot.filename.map(String::from),
        storage_tier: "inline".into(),
        created_at: now_iso(),
    };
    sqlx::query(
        "INSERT INTO blobs
         (id, bytes, mime, size_bytes, sha256, original_filename, storage_tier, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&meta.id)
    .bind(snapshot.bytes)
    .bind(&meta.mime)
    .bind(meta.size_bytes)
    .bind(&meta.sha256)
    .bind(&meta.original_filename)
    .bind(&meta.storage_tier)
    .bind(&meta.created_at)
    .execute(&mut **tx)
    .await?;
    Ok(meta)
}

#[allow(clippy::too_many_arguments)]
pub async fn observe_external(
    db: &Db,
    context: &MutationContext<'_>,
    claims: &[BindingClaim],
    hints: &StubHints,
    source: &BindingClaim,
    quality: ObservationQuality,
    policy: MaterializationPolicy,
    as_of: Option<&str>,
    provenance: &ObservationProvenance,
    display_name: Option<&str>,
    snapshot_bytes: Option<&[u8]>,
    snapshot_mime: Option<&str>,
    snapshot_filename: Option<&str>,
) -> Result<ObservationResult> {
    context.validate("observe_external")?;
    for (name, value) in [
        ("source_revision", provenance.source_revision.as_deref()),
        ("source_digest", provenance.source_digest.as_deref()),
    ] {
        if value.is_some_and(|value| value.trim().is_empty()) {
            return Err(Error::engine(format!(
                "observe_external: provenance.{name} must be nonblank when supplied"
            )));
        }
    }
    if (quality == ObservationQuality::Fetched || policy == MaterializationPolicy::Snapshot)
        && !context.source_read_authorized
    {
        return Err(Error::engine(
            "snapshot_authorization_failure: this caller has no verified source-read authority",
        ));
    }
    match (
        quality,
        policy,
        provenance.retention_state,
        snapshot_bytes,
        provenance.retained_from_observation_id.as_deref(),
    ) {
        (_, MaterializationPolicy::IdentityOnly, RetentionState::None, None, None) => {}
        (
            ObservationQuality::Fetched,
            MaterializationPolicy::Snapshot,
            RetentionState::Captured,
            Some(_),
            None,
        ) if provenance.source_revision.is_some()
            && provenance.freshness == ObservationFreshness::Fresh
            && provenance.source_availability == SourceAvailability::Available
            && provenance.refresh_outcome == RefreshOutcome::Succeeded => {}
        (
            ObservationQuality::Fetched,
            MaterializationPolicy::Snapshot,
            RetentionState::Retained,
            None,
            Some(_),
        ) if provenance.freshness == ObservationFreshness::Stale
            && provenance.refresh_outcome == RefreshOutcome::Failed => {}
        (_, MaterializationPolicy::IdentityOnly, _, Some(_), _) => {
            return Err(Error::engine(
                "identity_only observation must not include snapshot content",
            ))
        }
        (
            ObservationQuality::Reported,
            MaterializationPolicy::Snapshot,
            _,
            _,
            _,
        ) => {
            return Err(Error::engine(
                "reported observations cannot materialize readable snapshots",
            ))
        }
        _ => {
            return Err(Error::engine(
                "observe_external: inconsistent materialization provenance; captured snapshots require a fresh successful available revision and new bytes, retained snapshots require a failed stale refresh and retained_from_observation_id, and identity_only retains neither",
            ))
        }
    }
    if provenance.retention_state != RetentionState::Captured
        && (snapshot_mime.is_some() || snapshot_filename.is_some())
    {
        return Err(Error::engine(
            "observe_external: snapshot MIME and filename are valid only when capturing new bytes",
        ));
    }
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let resolution = resolve_external_in(db, &mut tx, context, claims, hints).await?;
    require_capability_in(&mut tx, context, &resolution.record_id, Capability::Manage).await?;
    let (source, source_rule) = rule_in(&mut tx, source, context.internal, None).await?;
    if !source_rule.authoritative_provenance {
        return Err(Error::engine(format!(
            "binding system '{}' is not authoritative observation provenance",
            source.system
        )));
    }
    require_record_shape(&mut tx, &resolution.record_id, &source_rule).await?;
    let is_source: i64 = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM bindings WHERE record_id = ? AND system = ? AND identifier = ?)",
    )
    .bind(&resolution.record_id)
    .bind(&source.system)
    .bind(&source.identifier)
    .fetch_one(&mut *tx)
    .await?;
    if is_source == 0 {
        return Err(Error::engine(
            "observation source must be one of the resolved record's exact bindings",
        ));
    }

    let mut effective_provenance = provenance.clone();
    let provenance_attachment_id = match provenance.retention_state {
        RetentionState::None => None,
        RetentionState::Captured => {
            let bytes = snapshot_bytes.expect("captured provenance validated with bytes");
            let meta = insert_blob_in(
                &mut tx,
                &Snapshot {
                    bytes,
                    mime: snapshot_mime,
                    filename: snapshot_filename,
                },
            )
            .await?;
            let attachment_id = Uuid::new_v4().to_string();
            // Attachments are records in the bearer's canonical folder, not
            // children of arbitrary entity/document records. The `part_of`
            // edge carries authorization from the resolved shadow; the
            // observation row below remains the exact provenance edge.
            let attachment_home: String =
                sqlx::query_scalar("SELECT home_id FROM records WHERE id = ?")
                    .bind(&resolution.record_id)
                    .fetch_one(&mut *tx)
                    .await?;
            append_in(
                db,
                &mut tx,
                AppendSpec {
                    record_id: attachment_id.clone(),
                    event_type: "record.created".into(),
                    payload: json!({
                        "type": "Document",
                        "kind": "attachment",
                        "name": snapshot_filename.unwrap_or("External snapshot"),
                        "home_id": attachment_home,
                        "persistence": "enduring"
                    }),
                    actor: Some(context.actor.into()),
                },
            )
            .await?;
            append_in(
                db,
                &mut tx,
                AppendSpec {
                    record_id: attachment_id.clone(),
                    event_type: "link.added".into(),
                    payload: json!({
                        "source_id": attachment_id.clone(),
                        "target_id": resolution.record_id,
                        "relationship": "part_of"
                    }),
                    actor: Some(context.actor.into()),
                },
            )
            .await?;
            append_in(
                db,
                &mut tx,
                AppendSpec {
                    record_id: attachment_id.clone(),
                    event_type: "facet.set".into(),
                    payload: json!({"key": BLOB_REF_FACET_KEY, "value": meta.id}),
                    actor: Some(context.actor.into()),
                },
            )
            .await?;
            Some(attachment_id)
        }
        RetentionState::Retained => {
            let retained_from = provenance
                .retained_from_observation_id
                .as_deref()
                .expect("retained provenance validated with source observation");
            let prior: Option<(Option<String>, Option<String>, String)> = sqlx::query_as(
                "SELECT source_revision, source_digest, provenance_attachment_id
                   FROM external_observations
                  WHERE id = ? AND record_id = ? AND source_system = ? AND source_identifier = ?
                    AND materialization_policy = 'snapshot' AND provenance_attachment_id IS NOT NULL",
            )
            .bind(retained_from)
            .bind(&resolution.record_id)
            .bind(&source.system)
            .bind(&source.identifier)
            .fetch_optional(&mut *tx)
            .await?;
            let Some((source_revision, source_digest, attachment_id)) = prior else {
                return Err(Error::engine(
                    "observe_external: retained_from_observation_id must name a prior snapshot for the same record and source binding",
                ));
            };
            if (provenance.source_revision.is_some()
                && provenance.source_revision != source_revision)
                || (provenance.source_digest.is_some() && provenance.source_digest != source_digest)
            {
                return Err(Error::engine(
                    "observe_external: retained snapshot provenance contradicts the prior artifact",
                ));
            }
            effective_provenance.source_revision = source_revision;
            effective_provenance.source_digest = source_digest;
            Some(attachment_id)
        }
    };
    let observation_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO external_observations
         (id, record_id, source_system, source_identifier, quality, as_of, observed_at,
          actor, reason, run_key, parent_key, intent, materialization_policy, display_name,
          source_revision, source_digest, freshness, retention_state, source_availability,
          refresh_outcome, retained_from_observation_id, provenance_attachment_id, derived_render_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
    )
    .bind(&observation_id)
    .bind(&resolution.record_id)
    .bind(&source.system)
    .bind(&source.identifier)
    .bind(quality.as_str())
    .bind(as_of)
    .bind(now_iso())
    .bind(context.actor)
    .bind(context.reason)
    .bind(context.run_key)
    .bind(context.parent_key)
    .bind(context.intent)
    .bind(policy.as_str())
    .bind(display_name)
    .bind(&effective_provenance.source_revision)
    .bind(&effective_provenance.source_digest)
    .bind(effective_provenance.freshness.as_str())
    .bind(effective_provenance.retention_state.as_str())
    .bind(effective_provenance.source_availability.as_str())
    .bind(effective_provenance.refresh_outcome.as_str())
    .bind(&effective_provenance.retained_from_observation_id)
    .bind(&provenance_attachment_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(ObservationResult {
        observation_id,
        record_id: resolution.record_id,
        created: resolution.created,
        provenance_attachment_id,
        provenance: effective_provenance,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_principal_bindings_use_the_wire_address_grammar() {
        for valid in [
            "native/A",
            "dns:example.com/p_01J.foo~9",
            "key:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/z9",
        ] {
            assert_eq!(
                normalize_identifier("native-principal", valid).unwrap(),
                valid
            );
        }
        for invalid in [
            "fixture/alice",
            "dns:Example.com/alice",
            "dns:example.com/_alice",
            "native/alice/other",
        ] {
            assert!(normalize_identifier("native-principal", invalid).is_err());
        }
    }

    #[test]
    fn native_record_codec_is_canonical_and_handles_slashes() {
        let db = "ndb_0123456789abcdef0123456789abcdef";
        let encoded = encode_native_record(db, "record/with/slashes").unwrap();
        assert_eq!(
            decode_native_record(&encoded).unwrap(),
            (db.into(), "record/with/slashes".into())
        );
        assert!(decode_native_record(&format!("{db}/cmVjb3Jk=")).is_err());
        assert!(decode_native_record(&format!("{db}/")).is_err());
    }

    #[test]
    fn minted_database_identity_is_exactly_sixteen_lowercase_hex_bytes() {
        let identity = mint_database_id();
        assert!(is_database_id(&identity));
        let bytes = hex::decode(&identity[4..]).unwrap();
        assert_eq!(bytes.len(), 16);
        assert_eq!(identity, identity.to_ascii_lowercase());
    }
}
