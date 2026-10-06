//! Engine-neutral authority act-head probe for standby delta refresh.
//!
//! This defines the closed authority contract and the one-statement,
//! handle-free read used by the hosted delta adapter and refresh controller.
//!
//! A whole-act delta is cut on act boundaries, so the authority's act head is
//! its primary no-op coordinate: equality of `head_act` proves no act-stamped
//! canonical write happened. That is necessary but not sufficient. The
//! `storage_portability_policy` singleton is canonical, compare-and-set
//! state with no act stamp, so
//! No-op comparison additionally requires the unwatermarked policy revision
//! and source pin to match. A policy-only
//! revision change with a stable act head is therefore not a no-op.
//!
//! Everything the probe needs is read by exactly one SQL statement inside a
//! consistent read transaction. That statement is a SQLite `json_object`
//! assembly of the closed contract: the JSON1 primitives are what let one
//! statement carry the scalar singletons, the ten mechanically generated
//! per-log maxima, the three non-sequenced max-act watermarks, the ten act
//! cutovers, the four governed binding seeds and the webhook pins together.
//! No export handle or snapshot is created.
//!
//! V2 is deliberately strict about the two webhook tables: non-empty state
//! refuses the delta path and falls back to whole-snapshot handling. This is
//! only safe because a native revision-5 authority has no webhook writers
//! today; the refusal is the fail-closed guard, not a permanent carriage
//! decision.

use std::collections::BTreeSet;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{Connection, SqliteConnection};

use crate::error::{Error, Result};

/// Closed contract identity for the authority act-head probe.
pub const AUTHORITY_ACT_HEAD_CONTRACT: &str = "native.standby-authority-act-head.v2";
/// The only contract version this core understands.
pub const AUTHORITY_ACT_HEAD_VERSION: u32 = 2;

/// The only canonical-interchange revision an authority may author for
/// exhaustively-carried canonical history. Kept mechanically tied to
/// [`crate::interchange::REVISION`] by
/// `required_native_revision_matches_interchange`, so a revision bump cannot
/// silently change what this contract accepts.
pub const REQUIRED_NATIVE_INTERCHANGE_REVISION: u64 = 5;

/// The closed authority act-head document. Every field is required and
/// unknown fields are refused, so a newer producer cannot smuggle a
/// coordinate past an older consumer.
///
/// This is the authoritative act-range evidence for one workspace database:
/// [`head_act`](Self::head_act) is the equivalence/freshness coordinate (the
/// act of the most recently committed write transaction, or 0), the cutovers
/// record the grouping-unknown boundary, and the policy pin plus watermarks
/// are the companions a head-only comparison would silently drop. Per-log
/// `seq` maxima are diagnostics (local fold positions), and the engine
/// schema is advisory provenance only.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityActHeadV1 {
    pub contract: String,
    pub version: u32,
    pub origin_database_id: String,
    /// The workspace act counter: the act of the most recently committed
    /// write transaction, or 0 when no act-stamped write has committed.
    pub head_act: i64,
    /// The canonical-interchange revision this authority authors.
    pub native_interchange_revision: u64,
    /// Advisory provenance only; engine identity never gates materialisation.
    pub source_engine_schema: i64,
    /// Diagnostics: `MAX(seq)` per sequenced canonical log, in
    /// [`crate::act::CANONICAL_EVENT_TABLES`] order.
    pub per_log_max_seq: Vec<LogMaxSeqV1>,
    /// Act watermarks of the non-sequenced act-stamped logs, in
    /// [`crate::act::NON_SEQUENCED_ACT_STAMPED_TABLES`] order.
    pub non_sequenced_max_acts: Vec<NonSequencedMaxActV1>,
    /// `None` is the compatible no-row state; `Some` carries the revision and
    /// the exact source pin the policy was computed against.
    pub storage_portability_policy: Option<StoragePortabilityPolicyHeadV1>,
    /// All ten act cutovers, ordered by domain.
    pub act_cutovers: Vec<ActCutoverV1>,
    /// The content-log causal cutover singleton.
    pub content_causal_cutover: ContentCausalCutoverV1,
    /// The four governed binding-system seeds, ordered by system.
    pub binding_systems: Vec<BindingSystemSeedV1>,
    /// `webhook_endpoints` row count; must be zero for the v2 delta path.
    pub webhook_endpoint_count: i64,
    /// `webhook_credentials` row count; must be zero for the v2 delta path.
    pub webhook_credential_count: i64,
}

/// Backwards-compatible alias: the head struct keeps its V1 name so the
/// standby cut core and tests need no rename churn; the wire contract is v2
/// via [`AUTHORITY_ACT_HEAD_CONTRACT`] and [`AUTHORITY_ACT_HEAD_VERSION`].
pub(crate) type AuthorityActHeadV2 = AuthorityActHeadV1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LogMaxSeqV1 {
    pub table: String,
    pub max_seq: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NonSequencedMaxActV1 {
    pub table: String,
    pub max_act: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoragePortabilityPolicyHeadV1 {
    pub policy_revision: i64,
    pub source_profile_id: String,
    pub source_profile_revision: i64,
    pub source_mode: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActCutoverV1 {
    pub domain: String,
    pub last_legacy_seq: i64,
    pub cutover_at: String,
    pub from_engine_schema: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContentCausalCutoverV1 {
    pub last_legacy_local_seq: i64,
    pub cutover_at: String,
    pub from_engine_schema: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BindingSystemSeedV1 {
    pub system: String,
    pub normalizer: String,
    pub compatible_type: Option<String>,
    pub compatible_kind: Option<String>,
    pub visibility: String,
    pub add_policy: String,
    pub remove_policy: String,
    pub canonicalize_policy: String,
    pub transfer_policy: String,
    pub reconciliation_rule: String,
    pub stub_allowed: i64,
    pub authoritative_provenance: i64,
    pub required_durable: i64,
}

impl StoragePortabilityPolicyHeadV1 {
    fn validate(&self) -> Result<()> {
        require(
            self.policy_revision > 0,
            "authority act-head portability policy revision is invalid",
        )?;
        require(
            !self.source_profile_id.trim().is_empty(),
            "authority act-head portability source profile id is empty",
        )?;
        require(
            self.source_profile_revision > 0,
            "authority act-head portability source profile revision is invalid",
        )?;
        require(
            matches!(self.source_mode.as_str(), "embedded" | "network" | "sync"),
            "authority act-head portability source mode is invalid",
        )
    }
}

impl ContentCausalCutoverV1 {
    fn validate(&self) -> Result<()> {
        require(
            self.last_legacy_local_seq >= 0,
            "authority act-head content causal cutover is negative",
        )?;
        require(
            !self.cutover_at.trim().is_empty(),
            "authority act-head content causal cutover timestamp is empty",
        )
    }
}

impl AuthorityActHeadV1 {
    /// Validate the closed contract. Every failure is a refusal of the delta
    /// path: a missing or duplicate coordinate, a non-native interchange
    /// revision, a binding registry that is not exactly the governed seeds,
    /// or any webhook state at all.
    pub fn validate(&self) -> Result<()> {
        self.validate_without_engine_schema()?;
        require(
            self.source_engine_schema > 0,
            "authority act-head source engine schema is invalid",
        )
    }

    /// Validate every closed-contract invariant that does not depend on the
    /// advisory source engine schema identity. The canonical delta document
    /// deliberately omits engine/DDL identity from its wire, so its evidence
    /// validates the same shared coordinate set through
    /// [`AuthorityActHeadCoordinates`] rather than fabricating a source engine
    /// schema it does not carry.
    pub(crate) fn validate_without_engine_schema(&self) -> Result<()> {
        self.coordinates().validate()
    }

    /// The shared closed-contract coordinates, without the advisory engine
    /// schema identity.
    pub(crate) fn coordinates(&self) -> AuthorityActHeadCoordinates<'_> {
        AuthorityActHeadCoordinates {
            contract: &self.contract,
            version: self.version,
            origin_database_id: &self.origin_database_id,
            head_act: self.head_act,
            native_interchange_revision: self.native_interchange_revision,
            per_log_max_seq: &self.per_log_max_seq,
            non_sequenced_max_acts: &self.non_sequenced_max_acts,
            storage_portability_policy: self.storage_portability_policy.as_ref(),
            act_cutovers: &self.act_cutovers,
            content_causal_cutover: &self.content_causal_cutover,
            binding_systems: &self.binding_systems,
            webhook_endpoint_count: self.webhook_endpoint_count,
            webhook_credential_count: self.webhook_credential_count,
        }
    }

    /// RFC 8785 canonical JSON bytes for the validated contract.
    #[cfg(test)]
    pub(crate) fn canonical_json(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_jcs::to_vec(self).map_err(Into::into)
    }

    /// True only when two valid heads prove a delta from `installed` to
    /// `self` carries nothing.
    ///
    /// This requires the act head *and* the unwatermarked
    /// policy/pin coordinates to match. Head equality alone is deliberately
    /// insufficient: the storage portability policy changes under a
    /// compare-and-set revision with no act allocation, and would otherwise be
    /// silently dropped.
    #[cfg(test)]
    pub(crate) fn is_noop_against(&self, installed: &Self) -> bool {
        self.validate().is_ok()
            && installed.validate().is_ok()
            && self.contract == installed.contract
            && self.version == installed.version
            && self.origin_database_id == installed.origin_database_id
            && self.native_interchange_revision == installed.native_interchange_revision
            && self.head_act == installed.head_act
            && self.per_log_max_seq == installed.per_log_max_seq
            && self.non_sequenced_max_acts == installed.non_sequenced_max_acts
            && self.storage_portability_policy == installed.storage_portability_policy
            && self.act_cutovers == installed.act_cutovers
            && self.content_causal_cutover == installed.content_causal_cutover
            && self.binding_systems == installed.binding_systems
            && self.webhook_endpoint_count == installed.webhook_endpoint_count
            && self.webhook_credential_count == installed.webhook_credential_count
    }
}

/// The closed-contract coordinates shared by an authority head observation and
/// the canonical delta wire evidence.
///
/// The only authority-head field deliberately absent is the advisory
/// `source_engine_schema`: engine/DDL identity never gates materialisation and
/// is not replicated on the delta wire. Validating a coordinate view lets the
/// wire evidence check exactly the shared invariants without constructing a
/// full [`AuthorityActHeadV1`] with a fabricated engine schema.
pub(crate) struct AuthorityActHeadCoordinates<'a> {
    pub(crate) contract: &'a str,
    pub(crate) version: u32,
    pub(crate) origin_database_id: &'a str,
    pub(crate) head_act: i64,
    pub(crate) native_interchange_revision: u64,
    pub(crate) per_log_max_seq: &'a [LogMaxSeqV1],
    pub(crate) non_sequenced_max_acts: &'a [NonSequencedMaxActV1],
    pub(crate) storage_portability_policy: Option<&'a StoragePortabilityPolicyHeadV1>,
    pub(crate) act_cutovers: &'a [ActCutoverV1],
    pub(crate) content_causal_cutover: &'a ContentCausalCutoverV1,
    pub(crate) binding_systems: &'a [BindingSystemSeedV1],
    pub(crate) webhook_endpoint_count: i64,
    pub(crate) webhook_credential_count: i64,
}

impl AuthorityActHeadCoordinates<'_> {
    /// The one closed-contract validator for both the observed head and the
    /// replicated wire evidence.
    pub(crate) fn validate(&self) -> Result<()> {
        require(
            self.contract == AUTHORITY_ACT_HEAD_CONTRACT,
            "unknown authority act-head contract",
        )?;
        require(
            self.version == AUTHORITY_ACT_HEAD_VERSION,
            "unknown authority act-head contract version",
        )?;
        require(
            crate::identity::is_database_id(self.origin_database_id),
            "authority act-head origin database id is invalid",
        )?;
        require(
            self.head_act >= 0,
            "authority act-head act counter is negative",
        )?;
        require(
            self.native_interchange_revision == REQUIRED_NATIVE_INTERCHANGE_REVISION,
            "authority act-head requires native canonical-interchange revision 5",
        )?;

        require(
            self.per_log_max_seq.len() == crate::act::CANONICAL_EVENT_TABLES.len(),
            "authority act-head per-log diagnostics are incomplete",
        )?;
        for (row, expected) in self
            .per_log_max_seq
            .iter()
            .zip(crate::act::CANONICAL_EVENT_TABLES)
        {
            require(
                row.table == expected,
                "authority act-head per-log diagnostics are out of order",
            )?;
            require(
                row.max_seq >= 0,
                "authority act-head per-log maximum is negative",
            )?;
        }

        require(
            self.non_sequenced_max_acts.len() == crate::act::NON_SEQUENCED_ACT_STAMPED_TABLES.len(),
            "authority act-head non-sequenced act watermarks are incomplete",
        )?;
        for (row, expected) in self
            .non_sequenced_max_acts
            .iter()
            .zip(crate::act::NON_SEQUENCED_ACT_STAMPED_TABLES)
        {
            require(
                row.table == expected,
                "authority act-head non-sequenced act watermarks are out of order",
            )?;
            require(
                row.max_act >= 0,
                "authority act-head non-sequenced act watermark is negative",
            )?;
        }

        if let Some(policy) = self.storage_portability_policy {
            policy.validate()?;
        }

        require(
            self.act_cutovers.len() == crate::act::CANONICAL_EVENT_TABLES.len(),
            "authority act-head act cutovers are incomplete",
        )?;
        let expected_cutover_domains = crate::act::CANONICAL_EVENT_TABLES
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter();
        let mut domains = BTreeSet::new();
        for (cutover, expected_domain) in self.act_cutovers.iter().zip(expected_cutover_domains) {
            require(
                cutover.domain == expected_domain,
                "authority act-head act cutovers are out of order or incomplete",
            )?;
            require(
                domains.insert(cutover.domain.as_str()),
                "authority act-head has a duplicate act cutover",
            )?;
            require(
                cutover.last_legacy_seq >= 0,
                "authority act-head act cutover is negative",
            )?;
            require(
                !cutover.cutover_at.trim().is_empty(),
                "authority act-head act cutover timestamp is empty",
            )?;
        }
        require(
            domains.len() == crate::act::CANONICAL_EVENT_TABLES.len(),
            "authority act-head is missing an act cutover",
        )?;

        self.content_causal_cutover.validate()?;

        require(
            self.binding_systems == expected_binding_system_seeds(),
            "authority act-head binding systems differ from the governed seeds",
        )?;

        require(
            self.webhook_endpoint_count == 0 && self.webhook_credential_count == 0,
            "authority act-head refuses non-empty webhook state",
        )?;
        Ok(())
    }
}

/// Read the authority act head inside a consistent read transaction. The
/// read-only pool is a different snapshot from the writer, so a probe is
/// always a point-in-time observation rather than a partial in-transaction
/// read.
pub(crate) async fn read_authority_act_head(db: &crate::Db) -> Result<AuthorityActHeadV1> {
    let mut tx = db.pool().begin().await?;
    let outcome = read_authority_act_head_on(&mut tx).await;
    let rollback = tx.rollback().await;
    match (outcome, rollback) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error.into()),
        (Ok(probe), Ok(())) => Ok(probe),
    }
}

/// Read the authoritative act-head evidence for one workspace database file,
/// read-only, without opening it as an engine [`crate::Db`].
///
/// This is Slice A of the freeze-receipt work: the file-path entry point a
/// release controller (or any external holder of managed fleet files) calls
/// to observe the act-range coordinate. It runs the exact same one-statement
/// probe and closed-contract validation as the `Db`-handle probe above —
/// same SQL, same parse, same [`AuthorityActHeadV1::validate`] — so there is
/// one coordinate definition, not two.
///
/// Read-only hardening mirrors the catalog inventory helper: the file is
/// opened `read_only` (never created), `PRAGMA query_only = ON` is set before
/// any read, and the probe runs inside `BEGIN DEFERRED` / `ROLLBACK`, so a
/// future accidental write added below fails at SQLite's execution boundary.
/// `immutable` is deliberately *not* set: live fleet files may carry a `-wal`
/// sidecar and an immutable open would silently read a stale snapshot.
/// SQLite may materialize an empty WAL during a read-only open. Callers that
/// also bind exact file bytes must probe before hashing those bytes.
///
/// Point-in-time only. Stability across two reads is the caller's
/// responsibility: observe under the deployment freeze (or any equivalent
/// writer exclusion) and re-probe to detect drift. This function chooses no
/// freeze-receipt policy.
///
/// Fail-closed (`Err`, never partial evidence) when the path is missing, the
/// file is not a database, any act-coordinate table or singleton is absent —
/// including pre-act schemas below engine 56, which have no `act_state`,
/// `act` columns or `act_cutover` rows — or any closed-contract invariant is
/// violated (binding seeds, webhook state, interchange revision, cutover
/// shape, policy pin).
pub async fn read_authority_act_head_from_path(path: &Path) -> Result<AuthorityActHeadV1> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(false)
        .read_only(true)
        .foreign_keys(true)
        .busy_timeout(std::time::Duration::from_secs(5));
    let mut connection = SqliteConnection::connect_with(&options).await?;
    let result = async {
        sqlx::query("PRAGMA query_only = ON")
            .execute(&mut connection)
            .await?;
        sqlx::query("BEGIN DEFERRED")
            .execute(&mut connection)
            .await?;
        let inner = read_authority_act_head_on(&mut connection).await;
        let rollback = sqlx::query("ROLLBACK").execute(&mut connection).await;
        match inner {
            Err(error) => {
                let _ = rollback;
                Err(error)
            }
            Ok(probe) => {
                rollback?;
                Ok(probe)
            }
        }
    }
    .await;
    connection.close().await?;
    result
}

/// The one-statement seam: run the probe on an already-open connection that
/// is inside a consistent read transaction. It executes exactly one SQL
/// statement, proven by `authority_read_is_one_statement_in_one_read_transaction`.
pub(crate) async fn read_authority_act_head_on(
    conn: &mut SqliteConnection,
) -> Result<AuthorityActHeadV1> {
    let sql = authority_act_head_sql();
    let raw: String = sqlx::query_scalar(&sql).fetch_one(&mut *conn).await?;
    let mut value: serde_json::Value = serde_json::from_str(&raw).map_err(|error| {
        Error::engine(format!(
            "authority act-head probe is not valid JSON: {error}"
        ))
    })?;
    require_present(&value, "origin_database_id", "database_identity")?;
    require_present(&value, "head_act", "act_state")?;
    require_present(&value, "source_engine_schema", "engine schema")?;
    require_present(&value, "source_history_revision", "source history")?;
    let source_history_revision = value
        .get("source_history_revision")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    require(
        source_history_revision == REQUIRED_NATIVE_INTERCHANGE_REVISION,
        "authority act-head source history is not exhaustively current",
    )?;
    value
        .as_object_mut()
        .expect("probe SQL always returns an object")
        .remove("source_history_revision");
    require_present(
        &value,
        "content_causal_cutover",
        "content_event_causal_cutover",
    )?;
    let probe: AuthorityActHeadV1 = serde_json::from_value(value).map_err(|error| {
        Error::engine(format!(
            "authority act-head probe contract is invalid: {error}"
        ))
    })?;
    probe.validate()?;
    Ok(probe)
}

/// The four governed binding systems, in the `ORDER BY system` order the
/// probe reads them. Tied to the engine seed by
/// `binding_seed_catalog_is_tied_to_the_engine_seed`.
pub(crate) fn expected_binding_system_seeds() -> Vec<BindingSystemSeedV1> {
    vec![
        BindingSystemSeedV1 {
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
        BindingSystemSeedV1 {
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
        BindingSystemSeedV1 {
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
        BindingSystemSeedV1 {
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
    ]
}

/// Build the single SQL statement that assembles the closed contract.
///
/// The per-log diagnostics are generated mechanically from
/// [`crate::act::CANONICAL_EVENT_TABLES`]; the non-sequenced watermarks are
/// generated mechanically from [`crate::act::NON_SEQUENCED_ACT_STAMPED_TABLES`]
/// in that order, so the vector is tied to the shared inventory rather than
/// a second copy.
fn authority_act_head_sql() -> String {
    let per_log_max_seq = crate::act::CANONICAL_EVENT_TABLES
        .iter()
        .map(|table| {
            format!(
                "json_object('table',{},'max_seq',COALESCE((SELECT MAX(seq) FROM {}),0))",
                sql_literal(table),
                table
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let non_sequenced_max_acts = crate::act::NON_SEQUENCED_ACT_STAMPED_TABLES
        .iter()
        .map(|table| {
            format!(
                "json_object('table',{},'max_act',COALESCE((SELECT MAX(act) FROM {}),0))",
                sql_literal(table),
                table
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "SELECT json_object(\
'contract',{contract},\
'version',{version},\
'origin_database_id',(SELECT origin_db_id FROM database_identity WHERE singleton=1),\
'head_act',(SELECT next_act FROM act_state WHERE singleton=1),\
'native_interchange_revision',{native_revision},\
'source_history_revision',(SELECT CASE application_id WHEN {history_marker} THEN {native_revision} ELSE 0 END FROM pragma_application_id),\
'source_engine_schema',(SELECT user_version FROM pragma_user_version),\
'per_log_max_seq',json_array({per_log_max_seq}),\
'non_sequenced_max_acts',json_array({non_sequenced_max_acts}),\
'storage_portability_policy',(SELECT json_object('policy_revision',policy_revision,'source_profile_id',source_profile_id,'source_profile_revision',source_profile_revision,'source_mode',source_mode) FROM storage_portability_policy WHERE singleton=1),\
'act_cutovers',(SELECT json_group_array(json_object('domain',domain,'last_legacy_seq',last_legacy_seq,'cutover_at',cutover_at,'from_engine_schema',from_engine_schema)) FROM (SELECT domain,last_legacy_seq,cutover_at,from_engine_schema FROM act_cutover ORDER BY domain)),\
'content_causal_cutover',(SELECT json_object('last_legacy_local_seq',last_legacy_local_seq,'cutover_at',cutover_at,'from_engine_schema',from_engine_schema) FROM content_event_causal_cutover WHERE singleton=1),\
'binding_systems',(SELECT json_group_array(json_object('system',system,'normalizer',normalizer,'compatible_type',compatible_type,'compatible_kind',compatible_kind,'visibility',visibility,'add_policy',add_policy,'remove_policy',remove_policy,'canonicalize_policy',canonicalize_policy,'transfer_policy',transfer_policy,'reconciliation_rule',reconciliation_rule,'stub_allowed',stub_allowed,'authoritative_provenance',authoritative_provenance,'required_durable',required_durable)) FROM (SELECT system,normalizer,compatible_type,compatible_kind,visibility,add_policy,remove_policy,canonicalize_policy,transfer_policy,reconciliation_rule,stub_allowed,authoritative_provenance,required_durable FROM binding_systems ORDER BY system)),\
'webhook_endpoint_count',(SELECT COUNT(*) FROM webhook_endpoints),\
'webhook_credential_count',(SELECT COUNT(*) FROM webhook_credentials)\
)",
        contract = sql_literal(AUTHORITY_ACT_HEAD_CONTRACT),
        version = AUTHORITY_ACT_HEAD_VERSION,
        native_revision = crate::interchange::REVISION,
        history_marker = crate::interchange::source_history_application_id(crate::interchange::REVISION),
        per_log_max_seq = per_log_max_seq,
        non_sequenced_max_acts = non_sequenced_max_acts,
    )
}

fn sql_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn require_present(value: &serde_json::Value, key: &str, singleton: &str) -> Result<()> {
    require(
        value.get(key).is_some_and(|field| !field.is_null()),
        &format!("authority act-head is missing its {singleton} singleton"),
    )
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(Error::engine(message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECORD_ID: &str = "1a7e4000-0000-4000-8000-000000000101";
    const LEGACY_ORIGIN: &str = "ndb_0123456789abcdef0123456789abcdef";

    async fn fresh_authority() -> crate::Db {
        crate::db::create_database(":memory:").await.unwrap()
    }

    /// A schema-complete authority that holds an origin but has never
    /// committed an act-stamped write. This is the honest shape of a
    /// pre-act database migrated forward: `database_identity` predates act
    /// stamping, so the act counter is still zero.
    async fn empty_authority() -> crate::Db {
        let db = crate::db::open_database(":memory:").await.unwrap();
        crate::db::apply_schema(&db).await.unwrap();
        sqlx::query(
            "INSERT INTO database_identity(singleton,origin_db_id,created_at) VALUES(1,?,?)",
        )
        .bind(LEGACY_ORIGIN)
        .bind("2026-01-01T00:00:00.000Z")
        .execute(db.write_pool())
        .await
        .unwrap();
        db
    }

    async fn max_seq(db: &crate::Db, table: &str) -> i64 {
        sqlx::query_scalar(&format!("SELECT COALESCE(MAX(seq),0) FROM {table}"))
            .fetch_one(db.pool())
            .await
            .unwrap()
    }

    async fn occur(
        conn: &mut SqliteConnection,
        table: &str,
        column: &str,
        value: &str,
    ) -> Vec<i64> {
        sqlx::query_scalar(&format!(
            "SELECT act FROM {table} WHERE {column} = ? AND act IS NOT NULL"
        ))
        .bind(value)
        .fetch_all(conn)
        .await
        .unwrap()
    }

    /// A schema-only authority reports the empty head and zero maxima. The
    /// seed pins (cutovers, binding seeds, webhooks) are all present and
    /// validated, so this is the "no act-stamped write yet" case rather than
    /// a partially-provisioned one.
    #[tokio::test]
    async fn empty_authority_reports_zero_head_and_zero_maxima() {
        let db = empty_authority().await;
        let probe = read_authority_act_head(&db).await.unwrap();
        assert_eq!(probe.head_act, 0);
        assert_eq!(
            probe
                .non_sequenced_max_acts
                .iter()
                .map(|row| (row.table.as_str(), row.max_act))
                .collect::<Vec<_>>(),
            crate::act::NON_SEQUENCED_ACT_STAMPED_TABLES
                .iter()
                .map(|table| (*table, 0))
                .collect::<Vec<_>>(),
        );
        assert!(probe.storage_portability_policy.is_none());
        assert!(probe.per_log_max_seq.iter().all(|row| row.max_seq == 0));
        assert_eq!(probe.act_cutovers.len(), 10);
        assert_eq!(probe.binding_systems, expected_binding_system_seeds());
        assert_eq!(probe.webhook_endpoint_count, 0);
        assert_eq!(probe.webhook_credential_count, 0);
        assert_eq!(
            probe.native_interchange_revision,
            REQUIRED_NATIVE_INTERCHANGE_REVISION
        );
        assert_eq!(
            probe.source_engine_schema,
            crate::CURRENT_ENGINE_SCHEMA_VERSION
        );
        assert_eq!(
            probe.content_causal_cutover.last_legacy_local_seq, 0,
            "a fresh cutover marks the whole log as act-clean"
        );
        db.close().await;
    }

    /// One transaction writing to five domains consumes one act, and the
    /// probe reports that act together with each log's true maximum. The
    /// maxima are compared against direct per-table `MAX(seq)` reads rather
    /// than hardcoded, so a mis-generated diagnostic fails here.
    #[tokio::test]
    async fn five_domain_act_reports_one_head_and_correct_maxima() {
        let db = fresh_authority().await;
        let before = read_authority_act_head(&db).await.unwrap();

        crate::store::append(
            &db,
            crate::store::AppendSpec {
                record_id: RECORD_ID.into(),
                event_type: "record.created".into(),
                payload: serde_json::json!({
                    "type": "Document",
                    "kind": "note",
                    "name": "authority probe fixture",
                }),
                actor: None,
            },
        )
        .await
        .unwrap();

        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut alloc = crate::act::ActAllocation::new();
        crate::store::append_in(
            &db,
            &mut tx,
            crate::store::AppendSpec {
                record_id: RECORD_ID.into(),
                event_type: "record.updated".into(),
                payload: serde_json::json!({"summary": "authority probe"}),
                actor: None,
            },
            &mut alloc,
        )
        .await
        .unwrap();
        crate::policy::append_replaced_in(
            &mut tx,
            RECORD_ID,
            vec![crate::policy::NormalizedPolicyEntry::new(
                "members".into(),
                crate::authorization::MEMBERS_SUBJECT_ID.into(),
                crate::authorization::Capability::Edit,
            )],
            "probe-fixture",
            "authority probe",
            &mut alloc,
        )
        .await
        .unwrap();
        crate::awareness::append_notification_candidate_in(
            &mut tx,
            "acct:probe-fixture",
            RECORD_ID,
            "human_obligation",
            "routine",
            None,
            "metadata_only",
            "portable_default",
            "probe-fixture-v1",
            "record.updated",
            "probe-fixture-source",
            &mut alloc,
        )
        .await
        .unwrap();
        crate::control::append_control_event_in(
            &mut tx,
            crate::control::NewControlEvent::authored(
                "probe-fixture-run-start",
                "probe-fixture-activity",
                "acct:probe-fixture",
                Some("scout-chair-a748b2".into()),
                "authority probe",
                crate::control::ControlEventPayload::AgentRunStarted(
                    crate::control::AgentRunStartedPayload {
                        activity_id: "probe-fixture-activity".into(),
                        account_id: "acct:probe-fixture".into(),
                        started_at: crate::store::now_iso(),
                        channel: None,
                        reported_mcp_client_name: None,
                        reported_mcp_client_version: None,
                        reported_model: None,
                    },
                ),
            )
            .unwrap(),
            &mut alloc,
        )
        .await
        .unwrap();
        crate::derivation::append_derivation_event_in(
            &mut tx,
            crate::derivation::NewDerivationEvent::authored(
                "probe-fixture-series",
                "probe-fixture",
                None,
                "authority probe",
                crate::derivation::DerivationEventPayload::SeriesCreated(
                    crate::derivation::DerivationSeriesCreated {
                        id: "probe-fixture-series".into(),
                        series_key: "probe-fixture-series".into(),
                        definition: serde_json::json!({"act": "test"}),
                    },
                ),
            )
            .unwrap(),
            &mut alloc,
        )
        .await
        .unwrap();
        db.commit_content(tx).await.unwrap();

        let after = read_authority_act_head(&db).await.unwrap();
        assert_eq!(
            after.head_act,
            before.head_act + 2,
            "the record append and the five-domain transaction each consume one act"
        );
        for row in &after.non_sequenced_max_acts {
            let expected: i64 =
                sqlx::query_scalar(&format!("SELECT COALESCE(MAX(act),0) FROM {}", row.table))
                    .fetch_one(db.pool())
                    .await
                    .unwrap();
            assert_eq!(
                row.max_act, expected,
                "non-sequenced maximum for {}",
                row.table
            );
        }

        for row in &after.per_log_max_seq {
            assert_eq!(
                row.max_seq,
                max_seq(&db, &row.table).await,
                "per-log maximum for {}",
                row.table
            );
        }

        // The five-domain transaction stamps one act across the five logs it
        // touched, and that act is the reported head.
        let mut conn = db.pool().acquire().await.unwrap();
        let mut observed = Vec::new();
        observed.extend(occur(&mut conn, "content_events", "record_id", RECORD_ID).await);
        observed.retain(|act| *act == after.head_act);
        assert_eq!(
            observed,
            vec![after.head_act],
            "the updated content event carries the head act"
        );
        for (table, column, value) in [
            ("policy_events", "record_id", RECORD_ID),
            ("notification_candidate_events", "message_id", RECORD_ID),
            (
                "control_events",
                "idempotency_key",
                "probe-fixture-run-start",
            ),
            (
                "derivation_events",
                "idempotency_key",
                "probe-fixture-series",
            ),
        ] {
            let acts = occur(&mut conn, table, column, value).await;
            assert_eq!(
                acts,
                vec![after.head_act],
                "the five-domain transaction stamps one act in {table}"
            );
        }
        drop(conn);
        db.close().await;
    }

    /// A policy change allocates no act. Head equality alone would call the
    /// second probe a no-op; the comparison must not, because the
    /// policy/pin coordinate moved.
    #[tokio::test]
    async fn policy_only_revision_change_is_not_a_noop() {
        let db = fresh_authority().await;
        let before = read_authority_act_head(&db).await.unwrap();
        assert!(before.storage_portability_policy.is_none());
        assert!(before.is_noop_against(&before));

        crate::storage_profile::update_portability_policy(
            &db,
            crate::storage_profile::PortabilityPolicyUpdate {
                if_policy_revision: 0,
                enforcement: crate::storage_profile::PortabilityEnforcement::Off,
                target_profiles: vec![],
                allow_conversions: vec![],
            },
        )
        .await
        .unwrap();

        let after = read_authority_act_head(&db).await.unwrap();
        assert_eq!(
            after.head_act, before.head_act,
            "a portability policy write allocates no act"
        );
        let pin = after
            .storage_portability_policy
            .as_ref()
            .expect("the policy is now present");
        assert_eq!(pin.policy_revision, 1);
        assert!(!after.is_noop_against(&before));
        assert!(!before.is_noop_against(&after));
        db.close().await;
    }

    /// The origin and act singletons are required: deleting either refuses
    /// the probe instead of inventing a zero head.
    #[tokio::test]
    async fn missing_origin_or_act_singleton_refuses() {
        let no_act = fresh_authority().await;
        sqlx::query("DELETE FROM act_state")
            .execute(no_act.write_pool())
            .await
            .unwrap();
        assert!(read_authority_act_head(&no_act).await.is_err());

        let no_origin = fresh_authority().await;
        sqlx::query("DELETE FROM database_identity")
            .execute(no_origin.write_pool())
            .await
            .unwrap();
        assert!(read_authority_act_head(&no_origin).await.is_err());

        no_act.close().await;
        no_origin.close().await;
    }

    /// A binding registry that is not exactly the governed four seeds
    /// refuses. The engine triggers are dropped only to make the tamper
    /// expressible in a test; production DML already fails closed.
    #[tokio::test]
    async fn tampered_binding_seed_refuses() {
        let db = fresh_authority().await;
        sqlx::query("DROP TRIGGER binding_systems_no_update")
            .execute(db.write_pool())
            .await
            .unwrap();
        sqlx::query("UPDATE binding_systems SET normalizer='tampered-v1' WHERE system='email'")
            .execute(db.write_pool())
            .await
            .unwrap();
        assert!(read_authority_act_head(&db).await.is_err());
        db.close().await;
    }

    /// V1 refuses the delta path whenever either webhook table is non-empty.
    #[tokio::test]
    async fn nonempty_webhook_state_refuses() {
        let db = fresh_authority().await;
        sqlx::query(
            "INSERT INTO webhook_endpoints(id,name,issuer_account_id,destination_id,profile,created_at)
             VALUES('wh-1','one','acct:test','destination','default','2026-01-01T00:00:00.000Z')",
        )
        .execute(db.write_pool())
        .await
        .unwrap();
        assert!(read_authority_act_head(&db).await.is_err());
        db.close().await;
    }

    /// Closed-field, inventory, pin and canonical-JSON validation. Each
    /// mutation targets one coordinate the contract must refuse.
    #[tokio::test]
    async fn contract_inventory_and_closed_fields_fail_closed() {
        let db = fresh_authority().await;
        let probe = read_authority_act_head(&db).await.unwrap();
        probe.validate().unwrap();

        let mut wrong_revision = probe.clone();
        wrong_revision.native_interchange_revision = 4;
        assert!(wrong_revision.validate().is_err());

        let mut wrong_version = probe.clone();
        wrong_version.version = 1;
        assert!(wrong_version.validate().is_err());

        let mut missing_log = probe.clone();
        missing_log.per_log_max_seq.pop();
        assert!(missing_log.validate().is_err());

        let mut missing_watermark = probe.clone();
        missing_watermark.non_sequenced_max_acts.pop();
        assert!(missing_watermark.validate().is_err());

        let mut reordered_watermarks = probe.clone();
        reordered_watermarks.non_sequenced_max_acts.swap(0, 1);
        assert!(reordered_watermarks.validate().is_err());
        assert!(!reordered_watermarks.is_noop_against(&reordered_watermarks));

        let mut negative_watermark = probe.clone();
        negative_watermark.non_sequenced_max_acts[0].max_act = -1;
        assert!(negative_watermark.validate().is_err());

        let mut missing_cutover = probe.clone();
        missing_cutover.act_cutovers.pop();
        assert!(missing_cutover.validate().is_err());

        let mut duplicate_cutover = probe.clone();
        duplicate_cutover.act_cutovers[1].domain = duplicate_cutover.act_cutovers[0].domain.clone();
        assert!(duplicate_cutover.validate().is_err());

        let mut reordered_cutovers = probe.clone();
        reordered_cutovers.act_cutovers.swap(0, 1);
        assert!(reordered_cutovers.validate().is_err());
        assert!(!reordered_cutovers.is_noop_against(&reordered_cutovers));

        let mut tampered_seed = probe.clone();
        tampered_seed.binding_systems[0].normalizer = "tampered-v1".into();
        assert!(tampered_seed.validate().is_err());

        let mut credential_only = probe.clone();
        credential_only.webhook_credential_count = 1;
        assert!(credential_only.validate().is_err());
        assert!(!credential_only.is_noop_against(&credential_only));

        let mut tampered_pin = probe.clone();
        tampered_pin.storage_portability_policy = Some(StoragePortabilityPolicyHeadV1 {
            policy_revision: 1,
            source_profile_id: "kite-local".into(),
            source_profile_revision: 0,
            source_mode: "embedded".into(),
        });
        assert!(tampered_pin.validate().is_err());

        // Unknown fields are refused by the closed contract.
        let mut value = serde_json::to_value(&probe).unwrap();
        value["future_coordinate"] = serde_json::json!(1);
        assert!(serde_json::from_value::<AuthorityActHeadV1>(value).is_err());

        // Canonical JSON is stable and round-trips the validated contract.
        let bytes = probe.canonical_json().unwrap();
        let reparsed: AuthorityActHeadV1 = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(reparsed, probe);
        assert_eq!(probe.canonical_json().unwrap(), bytes);

        db.close().await;
    }

    /// The one-statement proof: inside a consistent read transaction, the
    /// probe executes exactly one top-level SQL statement.
    #[tokio::test]
    async fn authority_read_is_one_statement_in_one_read_transaction() {
        use crate::query::test_sqlite::SqliteTrace;

        let db = fresh_authority().await;
        let mut tx = db.pool().begin().await.unwrap();
        let trace = SqliteTrace::install(&mut tx).await.unwrap();
        let probe = read_authority_act_head_on(&mut tx).await.unwrap();
        let work = trace.finish(&mut tx).await.unwrap();
        tx.rollback().await.unwrap();

        // `SqliteWork::statements` counts nested execution too. The one
        // nested substatement here is SQLite's own `-- PRAGMA user_version;`
        // for the `pragma_user_version` table-valued function; it is not a
        // second statement issued by the probe. Subtracting the marked
        // internal substatements therefore proves exactly one top-level
        // statement, which is the property this seam exists to pin.
        assert_eq!(
            work.statements - work.internal_statements,
            1,
            "the authority probe must be one top-level SQL statement"
        );
        probe.validate().unwrap();
        db.close().await;
    }

    /// The compiled catalog ties this contract's required revision and
    /// inventories to the shared constants rather than a second copy.
    #[test]
    fn required_native_revision_matches_interchange() {
        assert_eq!(
            REQUIRED_NATIVE_INTERCHANGE_REVISION,
            crate::interchange::REVISION
        );
        assert_eq!(crate::act::CANONICAL_EVENT_TABLES.len(), 10);
        assert_eq!(
            crate::act::NON_SEQUENCED_ACT_STAMPED_TABLES,
            [
                "awareness_command_intents",
                "external_observations",
                "provenance_attestation_validity_events"
            ]
        );
    }

    /// The expected seeds are the engine's own seeded rows, read back from a
    /// fresh database. This is what makes the constant a tie to the DDL seed
    /// rather than an independent copy.
    #[tokio::test]
    async fn binding_seed_catalog_is_tied_to_the_engine_seed() {
        let db = fresh_authority().await;
        let rows = sqlx::query(
            "SELECT system,normalizer,compatible_type,compatible_kind,visibility,
                    add_policy,remove_policy,canonicalize_policy,transfer_policy,
                    reconciliation_rule,stub_allowed,authoritative_provenance,required_durable
               FROM binding_systems ORDER BY system",
        )
        .fetch_all(db.write_pool())
        .await
        .unwrap();
        let actual = rows
            .into_iter()
            .map(|row| {
                use sqlx::Row as _;
                BindingSystemSeedV1 {
                    system: row.try_get("system").unwrap(),
                    normalizer: row.try_get("normalizer").unwrap(),
                    compatible_type: row.try_get("compatible_type").unwrap(),
                    compatible_kind: row.try_get("compatible_kind").unwrap(),
                    visibility: row.try_get("visibility").unwrap(),
                    add_policy: row.try_get("add_policy").unwrap(),
                    remove_policy: row.try_get("remove_policy").unwrap(),
                    canonicalize_policy: row.try_get("canonicalize_policy").unwrap(),
                    transfer_policy: row.try_get("transfer_policy").unwrap(),
                    reconciliation_rule: row.try_get("reconciliation_rule").unwrap(),
                    stub_allowed: row.try_get("stub_allowed").unwrap(),
                    authoritative_provenance: row.try_get("authoritative_provenance").unwrap(),
                    required_durable: row.try_get("required_durable").unwrap(),
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, expected_binding_system_seeds());
        db.close().await;
    }

    /// File-path probe fixtures: an on-disk engine database this test owns,
    /// closed before probing so the probe never contends with an open writer.
    async fn file_authority(dir: &tempfile::TempDir, name: &str) -> std::path::PathBuf {
        let path = dir.path().join(name);
        let db = crate::db::create_database(path.to_str().unwrap())
            .await
            .unwrap();
        crate::store::append(
            &db,
            crate::store::AppendSpec {
                record_id: RECORD_ID.into(),
                event_type: "record.created".into(),
                payload: serde_json::json!({
                    "type": "Document",
                    "kind": "note",
                    "name": "file probe fixture",
                }),
                actor: None,
            },
        )
        .await
        .unwrap();
        db.close().await;
        path
    }

    /// The hashed content the probe promises not to touch: the main file
    /// always, and the `-wal` sidecar's bytes when it carries any. An absent
    /// sidecar and a zero-length sidecar are the same empty-content state:
    /// SQLite teardown bookkeeping (shutdown-checkpoint TRUNCATE-then-unlink,
    /// delayed pool-drop closes) can materialize or remove an empty `-wal`
    /// without moving a single content byte, and every SQLite reader treats
    /// both identically. `-shm` is ephemeral reader state and `-journal`
    /// must never appear.
    fn hashed_fleet_bytes(path: &std::path::Path) -> (Vec<u8>, Option<Vec<u8>>) {
        let main = std::fs::read(path).unwrap();
        let mut wal_path = path.as_os_str().to_owned();
        wal_path.push("-wal");
        let wal = std::fs::read(std::path::Path::new(&wal_path))
            .ok()
            .filter(|bytes| !bytes.is_empty());
        (main, wal)
    }

    /// Content-free `-wal` churn normalizes away, but a sidecar carrying
    /// bytes always stays represented. Pins the normalization above without
    /// a database: absent and empty hash identically, non-empty exactly.
    #[test]
    fn wal_content_normalization_keeps_nonempty_sidecars() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("probe.db");
        std::fs::write(&path, b"main-bytes").unwrap();
        let mut wal_os = path.as_os_str().to_owned();
        wal_os.push("-wal");
        let wal_path = std::path::Path::new(&wal_os);
        assert_eq!(hashed_fleet_bytes(&path), (b"main-bytes".to_vec(), None));
        std::fs::write(wal_path, b"").unwrap();
        assert_eq!(hashed_fleet_bytes(&path), (b"main-bytes".to_vec(), None));
        std::fs::write(wal_path, b"wal-frame-bytes").unwrap();
        assert_eq!(
            hashed_fleet_bytes(&path),
            (b"main-bytes".to_vec(), Some(b"wal-frame-bytes".to_vec()))
        );
    }

    fn assert_no_journal(path: &std::path::Path) {
        let mut journal = path.as_os_str().to_owned();
        journal.push("-journal");
        assert!(
            std::fs::symlink_metadata(std::path::Path::new(&journal)).is_err(),
            "probe created a -journal sidecar for {}",
            path.display()
        );
    }

    /// The file-path probe observes the same closed contract as the
    /// `Db`-handle probe, is stable across reads, and writes nothing: every
    /// hashed byte is identical afterwards and no journal appears.
    #[tokio::test]
    async fn file_probe_matches_closed_contract_is_stable_and_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = file_authority(&dir, "authority.db").await;

        let before = hashed_fleet_bytes(&path);
        let first = read_authority_act_head_from_path(&path).await.unwrap();
        let second = read_authority_act_head_from_path(&path).await.unwrap();
        assert_eq!(first, second, "probe must be stable");
        assert_eq!(
            hashed_fleet_bytes(&path),
            before,
            "probe must write nothing"
        );
        assert_no_journal(&path);

        first.validate().unwrap();
        assert_eq!(first.contract, AUTHORITY_ACT_HEAD_CONTRACT);
        assert_eq!(first.version, AUTHORITY_ACT_HEAD_VERSION);
        assert!(crate::identity::is_database_id(&first.origin_database_id));
        assert!(first.head_act > 0, "the fixture committed one act");
        assert_eq!(
            first.native_interchange_revision,
            REQUIRED_NATIVE_INTERCHANGE_REVISION
        );
        assert_eq!(
            first.source_engine_schema,
            crate::CURRENT_ENGINE_SCHEMA_VERSION
        );
        assert_eq!(first.act_cutovers.len(), 10);
        assert_eq!(first.non_sequenced_max_acts.len(), 3);
        assert_eq!(first.binding_systems, expected_binding_system_seeds());
        assert_eq!(first.webhook_endpoint_count, 0);
        assert_eq!(first.webhook_credential_count, 0);
    }

    /// The probe observes committed truth: one more write transaction moves
    /// the head by exactly one act.
    #[tokio::test]
    async fn file_probe_observes_committed_advance() {
        let dir = tempfile::tempdir().unwrap();
        let path = file_authority(&dir, "authority.db").await;
        let before = read_authority_act_head_from_path(&path).await.unwrap();

        let db = crate::db::open_existing_database(path.to_str().unwrap())
            .await
            .unwrap();
        crate::store::append(
            &db,
            crate::store::AppendSpec {
                record_id: RECORD_ID.into(),
                event_type: "record.updated".into(),
                payload: serde_json::json!({"summary": "second act"}),
                actor: None,
            },
        )
        .await
        .unwrap();
        db.close().await;

        let after = read_authority_act_head_from_path(&path).await.unwrap();
        assert_eq!(after.head_act, before.head_act + 1);
        assert_eq!(after.origin_database_id, before.origin_database_id);
    }

    /// A missing path fails closed rather than probing nothing.
    #[tokio::test]
    async fn file_probe_fails_closed_on_missing_path() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            read_authority_act_head_from_path(&dir.path().join("absent.db"))
                .await
                .is_err()
        );
    }

    /// A non-database file fails closed rather than yielding partial evidence.
    #[tokio::test]
    async fn file_probe_fails_closed_on_non_database_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-a-database.db");
        std::fs::write(&path, b"this is not sqlite").unwrap();
        assert!(read_authority_act_head_from_path(&path).await.is_err());
    }

    /// A pre-act schema — sequenced logs without `act_state`, `act` columns
    /// or `act_cutover` rows — fails closed. This is the shape of every
    /// engine below schema 56, including a cancellable-retiring tenant the
    /// ready-only fleet migration never moved forward.
    #[tokio::test]
    async fn file_probe_fails_closed_on_pre_act_schema() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pre-act.db");
        let options = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true);
        let mut connection = SqliteConnection::connect_with(&options).await.unwrap();
        sqlx::query("CREATE TABLE content_events(seq INTEGER PRIMARY KEY)")
            .execute(&mut connection)
            .await
            .unwrap();
        sqlx::query("INSERT INTO content_events(seq) VALUES(1)")
            .execute(&mut connection)
            .await
            .unwrap();
        connection.close().await.unwrap();
        assert!(read_authority_act_head_from_path(&path).await.is_err());
    }

    /// A schema-complete database with a damaged coordinate — one act
    /// cutover row removed — fails closed rather than reporting a head
    /// without its grouping-unknown boundary.
    #[tokio::test]
    async fn file_probe_fails_closed_on_incomplete_cutover() {
        let dir = tempfile::tempdir().unwrap();
        let path = file_authority(&dir, "authority.db").await;
        read_authority_act_head_from_path(&path).await.unwrap();

        let options = SqliteConnectOptions::new().filename(&path);
        let mut connection = SqliteConnection::connect_with(&options).await.unwrap();
        sqlx::query("DELETE FROM act_cutover WHERE domain = 'content_events'")
            .execute(&mut connection)
            .await
            .unwrap();
        connection.close().await.unwrap();

        assert!(read_authority_act_head_from_path(&path).await.is_err());
    }
}
