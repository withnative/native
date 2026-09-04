//! Postgres engine adapter and production runtime boundary.
//!
//! The runtime owns typed/redacted connection configuration, deterministic
//! schema-per-logical-database isolation, least-privilege provisioning,
//! readiness, and the bounded record lifecycle currently proven by the shared
//! contract harness. Full Native domain parity remains a separate qualification
//! step; selecting this engine never implies support for unregistered handlers.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, SecondsFormat, Utc};
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions, PgSslMode};
use sqlx::{Acquire, Executor, Postgres, Row, Transaction};
use uuid::Uuid;

use crate::blob::{BlobMeta, BlobSlice};
use crate::domain_transaction::{
    AttachmentPhysicalPort, BindingAudit, BindingPhysicalPort, BindingRow, BindingSystemRule,
    ContentSemanticStatePort, FacetObservationPort, FacetWrite, ProjectionPlan, ProjectorIntent,
    RecordSemanticState,
};
use crate::events::{CausalEnvelopeV1, EventRow};
use crate::interchange::{validate_canonical_interchange, Cell, Section, ValidatedInterchange};
use crate::mcp::fetch::FetchConfig;
use crate::mcp::{Caller, EngineHandle, EngineKind, ToolRegistry};
use crate::portable_sql::{
    BindValue, ColumnSpec, DomainStatementExecutor, ExecutionControl, NormalizedRow,
    PostgresTransaction as PortableStatementTransaction, SqlResult, StatementTemplate,
};
use crate::schema::{
    spine_facet_column, DEFAULT_WORKSPACE_NAME, ROOT_RECORD_ID, SPINE_TYPES, UNFILED_RECORD_ID,
};
use crate::store::AppendSpec;
use crate::{Error, Result};

/// The Postgres `query_sql` executor: adapter-owned, implementing the
/// backend-neutral `crate::query::sql_contract`. Contracts never depend on
/// adapters; the executor lives with the backend it drives.
pub mod query_sql;

mod substrate;
pub use substrate::{
    PostgresAuthoritativeEvent, PostgresBlob, PostgresControlEvent, PostgresLogKind,
    PostgresMetaEvent, PostgresPolicyEvent,
};

const SCHEMA_VERSION: i32 = 6;
const DATABASE_PROVISION_LOCK: &str = "native-ce:postgres-database-provision:v1";
const SEEDED_RECORD_TIMESTAMP: &str = "1970-01-01T00:00:00Z";
const POSTGRES_DESCRIBE_SCHEMA_DDL_COUNT: usize = 54;
const POSTGRES_DESCRIBE_SCHEMA_DDL_FINGERPRINT: &str =
    "3ee20c39d45c4c8d7cf2738685f6b311164264d5ba3ae23d4955e0cfe3e74b6a";
const POSTGRES_V4_DDL_COUNT: usize = 49;
const POSTGRES_V4_DDL_FINGERPRINT: &str =
    "9a65675dd0d396a6437fe25d98051303b9a6128fc6686fbb28bdfaff0a5eb553";
const MAX_MULTI_UPDATE: usize = 100;
const MAX_MULTI_UPDATE_FAILURE_DETAILS: usize = 20;
const REQUIRED_RELATIONS: [&str; 35] = [
    "schema_migrations",
    "event_cursor",
    "content_events",
    "content_event_causal_frontier",
    "content_event_causal_cutover",
    "content_event_sources",
    "records",
    "facet_values",
    "bindings",
    "message_audience",
    "log_cursors",
    "meta_events",
    "policy_events",
    "control_events",
    "links",
    "blobs",
    "binding_systems",
    "binding_audit",
    "database_identity",
    "database_identity_audit",
    "record_policies",
    "policy_entries",
    "authorization_revision",
    "vocabularies",
    "vocabulary_values",
    "schema_config",
    "control_projections",
    "run_contexts",
    "request_interactions",
    "storage_portability_policy",
    "instruction_bindings",
    "onboarding_programmes",
    "onboarding_programme_sources",
    "notification_candidate_events",
    "notification_candidates",
];
pub const POSTGRES_RUNTIME_CONFIG_FORMAT: &str = "native.postgres-runtime.v1";

#[derive(Clone, Debug, Deserialize)]
struct PostgresCandidateReplayEvent {
    seq: i64,
    id: String,
    candidate_key: String,
    action: String,
    recipient_account_id: String,
    message_id: String,
    reason: String,
    priority: String,
    not_before: Option<String>,
    redaction_class: String,
    evaluator_kind: String,
    policy_version: String,
    source_event_type: String,
    source_event_id: String,
    payload: Value,
    created_at: String,
}

#[derive(Clone, Deserialize)]
#[serde(transparent)]
pub struct SecretString(String);

impl SecretString {
    fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[redacted]")
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PostgresTlsMode {
    Disable,
    Prefer,
    Require,
    VerifyCa,
    VerifyFull,
}

impl PostgresTlsMode {
    fn sqlx(self) -> PgSslMode {
        match self {
            Self::Disable => PgSslMode::Disable,
            Self::Prefer => PgSslMode::Prefer,
            Self::Require => PgSslMode::Require,
            Self::VerifyCa => PgSslMode::VerifyCa,
            Self::VerifyFull => PgSslMode::VerifyFull,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct PostgresPoolConfig {
    pub min_connections: u32,
    pub max_connections: u32,
    pub acquisition_timeout_ms: u64,
    pub idle_lifetime_ms: u64,
    pub max_lifetime_ms: u64,
}

impl Default for PostgresPoolConfig {
    fn default() -> Self {
        Self {
            min_connections: 1,
            max_connections: 12,
            acquisition_timeout_ms: 5_000,
            idle_lifetime_ms: 300_000,
            max_lifetime_ms: 1_800_000,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct PostgresTimeoutConfig {
    pub statement_timeout_ms: u64,
    pub lock_timeout_ms: u64,
}

impl Default for PostgresTimeoutConfig {
    fn default() -> Self {
        Self {
            statement_timeout_ms: 30_000,
            lock_timeout_ms: 5_000,
        }
    }
}

/// Exact runtime locator for one Native logical database. The schema name is
/// derived from `logical_database_id`; callers cannot point this handle at an
/// arbitrary operator-owned schema. Admin credentials and the ownership token
/// are optional as a pair: omit both to connect to an already-provisioned
/// target, or supply both for idempotent provision/drop operations.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostgresRuntimeConfig {
    pub format: String,
    pub logical_database_id: String,
    pub endpoint_url: SecretString,
    pub runtime_password: SecretString,
    pub tls_mode: PostgresTlsMode,
    #[serde(default = "default_application_name")]
    pub application_name: String,
    #[serde(default)]
    pub pool: PostgresPoolConfig,
    #[serde(default)]
    pub timeouts: PostgresTimeoutConfig,
    #[serde(default)]
    pub admin_url: Option<SecretString>,
    #[serde(default)]
    pub ownership_token: Option<SecretString>,
}

fn default_application_name() -> String {
    "native-ce".into()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PostgresRedactedConfig {
    pub format: String,
    pub logical_database_id: String,
    pub schema: String,
    pub runtime_role: String,
    pub endpoint_url: &'static str,
    pub runtime_password: &'static str,
    pub tls_mode: PostgresTlsMode,
    pub application_name: String,
    pub pool: PostgresPoolConfig,
    pub timeouts: PostgresTimeoutConfig,
    pub provisioning_enabled: bool,
    pub admin_url: Option<&'static str>,
    pub ownership_token: Option<&'static str>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PostgresSchemaCurrency {
    Current,
    Missing,
    Ahead,
    Behind,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PostgresHealthReport {
    pub live: bool,
    pub reachable: bool,
    pub ready: bool,
    pub write_ready: bool,
    pub least_privilege: bool,
    pub schema_currency: PostgresSchemaCurrency,
    pub expected_schema_version: i32,
    pub observed_schema_version: Option<i32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PostgresProvisionReport {
    pub logical_database_id: String,
    pub schema: String,
    pub runtime_role: String,
    pub schema_created: bool,
    pub role_created: bool,
    pub schema_version: i32,
}

#[derive(Clone, Debug)]
struct PostgresRuntimeMetadata {
    logical_database_id: String,
    runtime_role: String,
    redacted: PostgresRedactedConfig,
}

impl PostgresRuntimeConfig {
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let config: Self = serde_json::from_slice(bytes)
            .map_err(|error| Error::engine(format!("invalid Postgres runtime config: {error}")))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.format != POSTGRES_RUNTIME_CONFIG_FORMAT {
            return Err(Error::engine(format!(
                "unsupported Postgres runtime config format: {}",
                self.format
            )));
        }
        if self.logical_database_id.trim().is_empty()
            || self.logical_database_id.len() > 128
            || self.logical_database_id.chars().any(char::is_control)
        {
            return Err(Error::engine(
                "Postgres logical_database_id must be 1-128 non-control characters",
            ));
        }
        if self.endpoint_url.expose().trim().is_empty() || self.runtime_password.expose().is_empty()
        {
            return Err(Error::engine(
                "Postgres endpoint_url and runtime_password must be non-empty",
            ));
        }
        PgConnectOptions::from_str(self.endpoint_url.expose())
            .map_err(|_| Error::engine("Postgres endpoint_url is invalid"))?;
        if self.application_name.is_empty()
            || self.application_name.len() > 63
            || self.application_name.chars().any(char::is_control)
        {
            return Err(Error::engine(
                "Postgres application_name must be 1-63 non-control characters",
            ));
        }
        if self.pool.max_connections == 0
            || self.pool.min_connections > self.pool.max_connections
            || self.pool.acquisition_timeout_ms == 0
            || self.pool.idle_lifetime_ms == 0
            || self.pool.max_lifetime_ms == 0
            || self.timeouts.statement_timeout_ms == 0
            || self.timeouts.lock_timeout_ms == 0
            || self.timeouts.lock_timeout_ms > self.timeouts.statement_timeout_ms
        {
            return Err(Error::engine(
                "Postgres pool and timeout values must be non-zero, min_connections must not exceed max_connections, and lock_timeout_ms must not exceed statement_timeout_ms",
            ));
        }
        match (&self.admin_url, &self.ownership_token) {
            (None, None) => {}
            (Some(admin_url), Some(token)) => {
                PgConnectOptions::from_str(admin_url.expose())
                    .map_err(|_| Error::engine("Postgres admin_url is invalid"))?;
                if token.expose().len() < 16 {
                    return Err(Error::engine(
                        "Postgres ownership_token must contain at least 16 characters",
                    ));
                }
            }
            _ => {
                return Err(Error::engine(
                    "Postgres admin_url and ownership_token must be supplied together",
                ))
            }
        }
        quote_identifier(&self.schema_name())?;
        quote_identifier(&self.runtime_role())?;
        Ok(())
    }

    pub fn schema_name(&self) -> String {
        let digest = hex::encode(Sha256::digest(self.logical_database_id.as_bytes()));
        format!("native_{}", &digest[..32])
    }

    pub fn runtime_role(&self) -> String {
        let digest = hex::encode(Sha256::digest(self.logical_database_id.as_bytes()));
        format!("native_{}_runtime", &digest[..24])
    }

    pub fn query_role(&self) -> String {
        let digest = hex::encode(Sha256::digest(self.logical_database_id.as_bytes()));
        format!("native_{}_query", &digest[..24])
    }

    pub fn redacted(&self) -> PostgresRedactedConfig {
        PostgresRedactedConfig {
            format: self.format.clone(),
            logical_database_id: self.logical_database_id.clone(),
            schema: self.schema_name(),
            runtime_role: self.runtime_role(),
            endpoint_url: "[redacted]",
            runtime_password: "[redacted]",
            tls_mode: self.tls_mode,
            application_name: self.application_name.clone(),
            pool: self.pool.clone(),
            timeouts: self.timeouts.clone(),
            provisioning_enabled: self.admin_url.is_some(),
            admin_url: self.admin_url.as_ref().map(|_| "[redacted]"),
            ownership_token: self.ownership_token.as_ref().map(|_| "[redacted]"),
        }
    }

    fn marker(&self) -> Result<String> {
        let token = self
            .ownership_token
            .as_ref()
            .ok_or_else(|| Error::engine("Postgres provisioning credentials are not configured"))?;
        let logical = hex::encode(Sha256::digest(self.logical_database_id.as_bytes()));
        let ownership = hex::encode(Sha256::digest(token.expose().as_bytes()));
        Ok(format!(
            "native-ce:v1:{}:{}",
            &logical[..24],
            &ownership[..24]
        ))
    }

    fn runtime_connect_options(&self) -> Result<PgConnectOptions> {
        Ok(PgConnectOptions::from_str(self.endpoint_url.expose())
            .map_err(|_| Error::engine("Postgres endpoint_url is invalid"))?
            .username(&self.runtime_role())
            .password(self.runtime_password.expose())
            .ssl_mode(self.tls_mode.sqlx())
            .application_name(&self.application_name))
    }

    fn admin_connect_options(&self) -> Result<PgConnectOptions> {
        let admin_url = self
            .admin_url
            .as_ref()
            .ok_or_else(|| Error::engine("Postgres provisioning credentials are not configured"))?;
        Ok(PgConnectOptions::from_str(admin_url.expose())
            .map_err(|_| Error::engine("Postgres admin_url is invalid"))?
            .ssl_mode(self.tls_mode.sqlx())
            .application_name("native-ce-provisioner"))
    }

    async fn runtime_pool(&self) -> Result<PgPool> {
        self.validate()?;
        let statement_timeout_ms = self.timeouts.statement_timeout_ms;
        let lock_timeout_ms = self.timeouts.lock_timeout_ms;
        Ok(PgPoolOptions::new()
            .min_connections(self.pool.min_connections)
            .max_connections(self.pool.max_connections)
            .acquire_timeout(Duration::from_millis(self.pool.acquisition_timeout_ms))
            .idle_timeout(Duration::from_millis(self.pool.idle_lifetime_ms))
            .max_lifetime(Duration::from_millis(self.pool.max_lifetime_ms))
            .after_connect(move |connection, _metadata| {
                Box::pin(async move {
                    sqlx::query(&format!("SET statement_timeout = {statement_timeout_ms}"))
                        .execute(&mut *connection)
                        .await?;
                    sqlx::query(&format!("SET lock_timeout = {lock_timeout_ms}"))
                        .execute(&mut *connection)
                        .await?;
                    Ok(())
                })
            })
            .connect_with(self.runtime_connect_options()?)
            .await?)
    }

    async fn query_pool(&self) -> Result<PgPool> {
        self.validate()?;
        Ok(PgPoolOptions::new()
            .min_connections(0)
            .max_connections(self.pool.max_connections.min(4))
            .acquire_timeout(Duration::from_millis(self.pool.acquisition_timeout_ms))
            .idle_timeout(Duration::from_millis(self.pool.idle_lifetime_ms))
            .max_lifetime(Duration::from_millis(self.pool.max_lifetime_ms))
            .after_release(|connection, _metadata| {
                Box::pin(async move {
                    sqlx::query("DISCARD ALL").execute(connection).await?;
                    Ok(false)
                })
            })
            .connect_with(self.runtime_connect_options()?)
            .await?)
    }

    async fn admin_pool(&self) -> Result<PgPool> {
        Ok(PgPoolOptions::new()
            .min_connections(0)
            .max_connections(1)
            .acquire_timeout(Duration::from_millis(self.pool.acquisition_timeout_ms))
            .idle_timeout(Duration::from_millis(self.pool.idle_lifetime_ms))
            .max_lifetime(Duration::from_millis(self.pool.max_lifetime_ms))
            .connect_with(self.admin_connect_options()?)
            .await?)
    }

    async fn ensure_query_role_boundary(&self) -> Result<()> {
        self.validate()?;
        let query_role = self.query_role();
        let runtime_role = self.runtime_role();
        if self.admin_url.is_some() {
            let marker = self.marker()?;
            let schema = self.schema_name();
            let quoted_query_role = quote_identifier(&query_role)?;
            let quoted_runtime_role = quote_identifier(&runtime_role)?;
            let admin = self.admin_pool().await?;
            let mut connection = admin.acquire().await?;
            connection.close_on_drop();
            sqlx::query("SELECT pg_advisory_lock(hashtextextended($1, 0))")
                .bind(&self.logical_database_id)
                .execute(&mut *connection)
                .await?;
            let result = async {
                let mut tx = connection.begin().await?;
                let runtime_marker: Option<Option<String>> = sqlx::query_scalar(
                    "SELECT shobj_description(oid, 'pg_authid') FROM pg_roles WHERE rolname=$1",
                )
                .bind(&runtime_role)
                .fetch_optional(&mut *tx)
                .await?;
                if runtime_marker.flatten().as_deref() != Some(marker.as_str()) {
                    return Err(Error::engine(
                        "Postgres runtime role is absent or not owned by this logical database",
                    ));
                }
                let schema_owned: bool = sqlx::query_scalar(
                    "SELECT owner.rolname=$2 AND obj_description(namespace.oid, 'pg_namespace')=$3 FROM pg_namespace namespace JOIN pg_roles owner ON owner.oid=namespace.nspowner WHERE namespace.nspname=$1",
                )
                .bind(&schema)
                .bind(&runtime_role)
                .bind(&marker)
                .fetch_optional(&mut *tx)
                .await?
                .unwrap_or(false);
                if !schema_owned {
                    return Err(Error::engine(
                        "Postgres logical schema is absent or not owned by this logical database",
                    ));
                }
                let query_marker: Option<Option<String>> = sqlx::query_scalar(
                    "SELECT shobj_description(oid, 'pg_authid') FROM pg_roles WHERE rolname=$1",
                )
                .bind(&query_role)
                .fetch_optional(&mut *tx)
                .await?;
                if query_marker
                    .as_ref()
                    .is_some_and(|value| value.as_deref() != Some(marker.as_str()))
                {
                    return Err(Error::engine(
                        "Postgres query role exists but is not owned by this logical database",
                    ));
                }
                if query_marker.is_none() {
                    tx.execute(format!("CREATE ROLE {quoted_query_role}").as_str())
                        .await?;
                }
                tx.execute(
                    format!("ALTER ROLE {quoted_query_role} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS").as_str(),
                )
                .await?;
                tx.execute(
                    format!("COMMENT ON ROLE {quoted_query_role} IS '{marker}'").as_str(),
                )
                .await?;
                let unexpected_members: Vec<String> = sqlx::query_scalar(
                    "SELECT member.rolname FROM pg_auth_members membership JOIN pg_roles role ON role.oid=membership.roleid JOIN pg_roles member ON member.oid=membership.member WHERE role.rolname=$1 AND member.rolname<>$2",
                )
                .bind(&query_role)
                .bind(&runtime_role)
                .fetch_all(&mut *tx)
                .await?;
                for member in unexpected_members {
                    tx.execute(
                        format!(
                            "REVOKE {quoted_query_role} FROM {}",
                            quote_identifier(&member)?
                        )
                        .as_str(),
                    )
                    .await?;
                }
                let parent_roles: Vec<String> = sqlx::query_scalar(
                    "SELECT role.rolname FROM pg_auth_members membership JOIN pg_roles role ON role.oid=membership.roleid JOIN pg_roles member ON member.oid=membership.member WHERE member.rolname=$1",
                )
                .bind(&query_role)
                .fetch_all(&mut *tx)
                .await?;
                for parent in parent_roles {
                    tx.execute(
                        format!(
                            "REVOKE {} FROM {quoted_query_role}",
                            quote_identifier(&parent)?
                        )
                        .as_str(),
                    )
                    .await?;
                }
                tx.execute(
                    format!("GRANT {quoted_query_role} TO {quoted_runtime_role} WITH ADMIN FALSE, INHERIT FALSE, SET TRUE").as_str(),
                )
                .await?;
                tx.commit().await?;
                Result::<()>::Ok(())
            }
            .await;
            let unlock = sqlx::query("SELECT pg_advisory_unlock(hashtextextended($1, 0))")
                .bind(&self.logical_database_id)
                .execute(&mut *connection)
                .await;
            drop(connection);
            admin.close().await;
            result?;
            unlock?;
        }

        let verification = self.runtime_pool().await?;
        let exact: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM pg_roles role WHERE role.rolname=$1 AND NOT role.rolcanlogin AND NOT role.rolsuper AND NOT role.rolcreatedb AND NOT role.rolcreaterole AND NOT role.rolinherit AND NOT role.rolreplication AND NOT role.rolbypassrls) \
             AND EXISTS(SELECT 1 FROM pg_auth_members membership JOIN pg_roles role ON role.oid=membership.roleid JOIN pg_roles member ON member.oid=membership.member WHERE role.rolname=$1 AND member.rolname=current_user AND NOT membership.admin_option AND NOT membership.inherit_option AND membership.set_option) \
             AND NOT EXISTS(SELECT 1 FROM pg_auth_members membership JOIN pg_roles role ON role.oid=membership.roleid JOIN pg_roles member ON member.oid=membership.member WHERE role.rolname=$1 AND member.rolname<>current_user) \
             AND NOT EXISTS(SELECT 1 FROM pg_auth_members membership JOIN pg_roles member ON member.oid=membership.member WHERE member.rolname=$1)",
        )
        .bind(&query_role)
        .fetch_one(&verification)
        .await?;
        verification.close().await;
        if !exact {
            return Err(Error::engine(
                "Postgres query role boundary is absent or not least privilege",
            ));
        }
        Ok(())
    }

    /// Connect an already-provisioned logical database and fail closed unless
    /// the authenticated role, deterministic schema, and schema revision are
    /// all current.
    pub async fn connect(&self) -> Result<PostgresDb> {
        self.ensure_query_role_boundary().await?;
        let pool = self.runtime_pool().await?;
        let query_pool = self.query_pool().await?;
        let db = PostgresDb {
            pool,
            query_pool,
            query_role: self.query_role(),
            schema: self.schema_name(),
            schema_tag: None,
            runtime: Some(Arc::new(PostgresRuntimeMetadata {
                logical_database_id: self.logical_database_id.clone(),
                runtime_role: self.runtime_role(),
                redacted: self.redacted(),
            })),
            portability_policy_gate: Arc::new(tokio::sync::RwLock::new(())),
            realtime_hub: Arc::new(PostgresRealtimeHub::new()),
            #[cfg(feature = "postgres-tests")]
            intent_persist_checkpoint: Arc::new(PostgresIntentPersistCheckpoint::default()),
            #[cfg(test)]
            request_lifecycle_test_bypass: false,
        };
        let health = db.health().await?;
        if !health.ready || !health.write_ready {
            db.close().await;
            if let Some(version) = health
                .observed_schema_version
                .filter(|version| *version < SCHEMA_VERSION)
            {
                let recovery = if version == 4 {
                    "provision_and_connect exact v4-to-v5 migration or operator-controlled reprovisioning"
                } else {
                    "operator-controlled reprovisioning"
                };
                return Err(Error::engine(format!(
                    "Postgres logical database uses legacy schema v{version}; authoritative substrate v{SCHEMA_VERSION} requires {recovery}"
                )));
            }
            return Err(Error::engine(format!(
                "Postgres logical database is not ready: schema_currency={:?}",
                health.schema_currency
            )));
        }
        Ok(db)
    }

    /// Create or re-open the exact owned role/schema pair, migrate only a
    /// wholly empty owned schema, and return a runtime handle using the
    /// least-privilege role rather than the administrative connection.
    pub async fn provision_and_connect(&self) -> Result<(PostgresDb, PostgresProvisionReport)> {
        self.validate()?;
        let marker = self.marker()?;
        let schema = self.schema_name();
        let role = self.runtime_role();
        let query_role = self.query_role();
        let quoted_schema = quote_identifier(&schema)?;
        let quoted_role = quote_identifier(&role)?;
        let admin = self.admin_pool().await?;
        let mut admin_connection = admin.acquire().await?;
        // Session advisory locks survive transaction boundaries. If this
        // future is cancelled at any await after lock acquisition, dropping a
        // reusable pooled connection would strand that lock in the pool. Mark
        // it for physical close before acquiring the lock; the normal path
        // still performs the explicit unlock below.
        admin_connection.close_on_drop();
        // Role grants rewrite the shared database ACL tuple, even when two
        // provisions own unrelated logical schemas. PostgreSQL can otherwise
        // abort one concurrent GRANT CONNECT with `tuple concurrently
        // updated`. Serialize that database-global catalog mutation while
        // retaining the logical-database lock used to fence one substrate.
        sqlx::query("SELECT pg_advisory_lock(hashtextextended($1, 0))")
            .bind(DATABASE_PROVISION_LOCK)
            .execute(&mut *admin_connection)
            .await?;
        sqlx::query("SELECT pg_advisory_lock(hashtextextended($1, 0))")
            .bind(&self.logical_database_id)
            .execute(&mut *admin_connection)
            .await?;
        // This is deliberately a session lock, not a transaction lock. It
        // remains held while the runtime role performs DDL and readiness is
        // checked, so a concurrent first provision cannot observe the role and
        // schema in the gap before their relation set is complete.
        let result = async {
            let mut tx = admin_connection.begin().await?;

            let role_state = sqlx::query(
                "SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls, shobj_description(oid, 'pg_authid') AS marker FROM pg_roles WHERE rolname=$1",
            )
            .bind(&role)
            .fetch_optional(&mut *tx)
            .await?;
            let role_created = role_state.is_none();
            if let Some(row) = role_state {
                let existing_marker: Option<String> = row.try_get("marker")?;
                if existing_marker.as_deref() != Some(marker.as_str()) {
                    return Err(Error::engine(
                        "Postgres runtime role exists but is not owned by this logical database",
                    ));
                }
            }
            let query_role_marker: Option<Option<String>> = sqlx::query_scalar(
                "SELECT shobj_description(oid, 'pg_authid') FROM pg_roles WHERE rolname=$1",
            )
            .bind(&query_role)
            .fetch_optional(&mut *tx)
            .await?;
            if query_role_marker
                .as_ref()
                .is_some_and(|value| value.as_deref() != Some(marker.as_str()))
            {
                return Err(Error::engine(
                    "Postgres query role exists but is not owned by this logical database",
                ));
            }

            let schema_state = sqlx::query(
                "SELECT owner.rolname AS owner, obj_description(namespace.oid, 'pg_namespace') AS marker FROM pg_namespace namespace JOIN pg_roles owner ON owner.oid=namespace.nspowner WHERE namespace.nspname=$1",
            )
            .bind(&schema)
            .fetch_optional(&mut *tx)
            .await?;
            let schema_created = schema_state.is_none();
            if let Some(row) = schema_state {
                let owner: String = row.try_get("owner")?;
                let existing_marker: Option<String> = row.try_get("marker")?;
                if owner != role || existing_marker.as_deref() != Some(marker.as_str()) {
                    return Err(Error::engine(
                        "Postgres logical schema exists but is not owned by this logical database",
                    ));
                }
            }

            sqlx::query(
                "SELECT set_config('native_ce.runtime_role', $1, true), set_config('native_ce.runtime_password', $2, true), set_config('native_ce.ownership_marker', $3, true), set_config('native_ce.query_role', $4, true)",
            )
            .bind(&role)
            .bind(self.runtime_password.expose())
            .bind(&marker)
            .bind(&query_role)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "DO $native$ DECLARE role_name text := current_setting('native_ce.runtime_role'); role_password text := current_setting('native_ce.runtime_password'); marker text := current_setting('native_ce.ownership_marker'); BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=role_name) THEN EXECUTE format('CREATE ROLE %I LOGIN', role_name); END IF; EXECUTE format('ALTER ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD %L', role_name, role_password); EXECUTE format('COMMENT ON ROLE %I IS %L', role_name, marker); END $native$",
            )
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "DO $native$ DECLARE query_role text := current_setting('native_ce.query_role'); runtime_role text := current_setting('native_ce.runtime_role'); marker text := current_setting('native_ce.ownership_marker'); BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=query_role) THEN EXECUTE format('CREATE ROLE %I', query_role); END IF; EXECUTE format('ALTER ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS', query_role); EXECUTE format('COMMENT ON ROLE %I IS %L', query_role, marker); EXECUTE format('GRANT %I TO %I WITH ADMIN FALSE, INHERIT FALSE, SET TRUE', query_role, runtime_role); END $native$",
            )
            .execute(&mut *tx)
            .await?;
            if schema_created {
                tx.execute(format!("CREATE SCHEMA {quoted_schema} AUTHORIZATION {quoted_role}").as_str())
                    .await?;
            }
            sqlx::query("SELECT set_config('native_ce.logical_schema', $1, true)")
                .bind(&schema)
                .execute(&mut *tx)
                .await?;
            sqlx::query(
                "DO $native$ DECLARE schema_name text := current_setting('native_ce.logical_schema'); marker text := current_setting('native_ce.ownership_marker'); role_name text := current_setting('native_ce.runtime_role'); BEGIN EXECUTE format('ALTER SCHEMA %I OWNER TO %I', schema_name, role_name); EXECUTE format('COMMENT ON SCHEMA %I IS %L', schema_name, marker); EXECUTE format('REVOKE ALL ON SCHEMA %I FROM PUBLIC', schema_name); EXECUTE format('GRANT USAGE, CREATE ON SCHEMA %I TO %I', schema_name, role_name); EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), role_name); END $native$",
            )
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;

            let pool = self.runtime_pool().await?;
            let query_pool = self.query_pool().await?;
            let db = PostgresDb {
                pool,
                query_pool,
                query_role: self.query_role(),
                schema: schema.clone(),
                schema_tag: None,
                runtime: Some(Arc::new(PostgresRuntimeMetadata {
                    logical_database_id: self.logical_database_id.clone(),
                    runtime_role: role.clone(),
                    redacted: self.redacted(),
                })),
                portability_policy_gate: Arc::new(tokio::sync::RwLock::new(())),
                realtime_hub: Arc::new(PostgresRealtimeHub::new()),
                #[cfg(feature = "postgres-tests")]
                intent_persist_checkpoint: Arc::new(PostgresIntentPersistCheckpoint::default()),
                #[cfg(test)]
                request_lifecycle_test_bypass: false,
            };
            let relation = format!("{schema}.schema_migrations");
            let migration_exists: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
                .bind(&relation)
                .fetch_one(&db.pool)
                .await?;
            if !migration_exists {
                let objects: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM pg_class class JOIN pg_namespace namespace ON namespace.oid=class.relnamespace WHERE namespace.nspname=$1",
                )
                .bind(&schema)
                .fetch_one(&db.pool)
                .await?;
                if objects != 0 {
                    db.close().await;
                    return Err(Error::engine(
                        "Postgres owned schema is non-empty but has no Native migration ledger",
                    ));
                }
                db.migrate(true).await?;
            }
            let migrations = db.qualified_table("schema_migrations")?;
            let observed: Option<i32> =
                sqlx::query_scalar(&format!("SELECT MAX(version) FROM {migrations}"))
                    .fetch_one(&db.pool)
                    .await?;
            if observed == Some(4) {
                if let Err(error) = assert_postgres_v4_search_migration_source(&db).await {
                    db.close().await;
                    return Err(error);
                }
                db.migrate_v4_to_v5().await?;
            }
            let observed: Option<i32> =
                sqlx::query_scalar(&format!("SELECT MAX(version) FROM {migrations}"))
                    .fetch_one(&db.pool)
                    .await?;
            if observed == Some(5) {
                db.migrate_v5_to_v6().await?;
            }
            let health = db.health().await?;
            if !health.ready || !health.write_ready {
                db.close().await;
                if let Some(version) = health
                    .observed_schema_version
                    .filter(|version| *version < SCHEMA_VERSION)
                {
                    return Err(Error::engine(format!(
                        "Postgres logical database uses legacy schema v{version}; authoritative substrate v{SCHEMA_VERSION} requires operator-controlled reprovisioning"
                    )));
                }
                return Err(Error::engine(
                    "Postgres provisioned logical database failed readiness checks",
                ));
            }
            Ok((
                db,
                PostgresProvisionReport {
                    logical_database_id: self.logical_database_id.clone(),
                    schema,
                    runtime_role: role,
                    schema_created,
                    role_created,
                    schema_version: SCHEMA_VERSION,
                },
            ))
        }
        .await;
        let logical_unlock =
            sqlx::query_scalar::<_, bool>("SELECT pg_advisory_unlock(hashtextextended($1, 0))")
                .bind(&self.logical_database_id)
                .fetch_one(&mut *admin_connection)
                .await;
        let database_unlock =
            sqlx::query_scalar::<_, bool>("SELECT pg_advisory_unlock(hashtextextended($1, 0))")
                .bind(DATABASE_PROVISION_LOCK)
                .fetch_one(&mut *admin_connection)
                .await;
        drop(admin_connection);
        admin.close().await;
        match (result, logical_unlock, database_unlock) {
            (Err(error), _, _) => Err(error),
            (Ok(value), Ok(true), Ok(true)) => Ok(value),
            (Ok(_), Ok(false), _) => Err(Error::engine(
                "Postgres provisioning advisory lock was not held at release",
            )),
            (Ok(_), _, Ok(false)) => Err(Error::engine(
                "Postgres database provisioning advisory lock was not held at release",
            )),
            (Ok(_), Err(error), _) | (Ok(_), _, Err(error)) => Err(error.into()),
        }
    }

    /// Drop only a schema/role carrying this configuration's hashed ownership
    /// marker. Operator-owned or differently owned names fail closed. Calling
    /// cleanup again after a successful drop is a no-op.
    pub async fn drop_owned(&self) -> Result<()> {
        self.drop_owned_with_application_name(None).await
    }

    #[cfg(feature = "postgres-tests")]
    pub async fn contract_drop_owned_with_application_name_for_test(
        &self,
        application_name: &str,
    ) -> Result<()> {
        if application_name.is_empty()
            || application_name.len() > 63
            || application_name.chars().any(char::is_control)
        {
            return Err(Error::engine(
                "Postgres test cleanup application_name must be 1-63 non-control characters",
            ));
        }
        self.drop_owned_with_application_name(Some(application_name))
            .await
    }

    async fn drop_owned_with_application_name(
        &self,
        test_application_name: Option<&str>,
    ) -> Result<()> {
        self.validate()?;
        let marker = self.marker()?;
        let schema = self.schema_name();
        let role = self.runtime_role();
        let query_role = self.query_role();
        let quoted_schema = quote_identifier(&schema)?;
        let quoted_role = quote_identifier(&role)?;
        let quoted_query_role = quote_identifier(&query_role)?;
        let admin = self.admin_pool().await?;
        let result = async {
            let mut tx = admin.begin().await?;
            if let Some(application_name) = test_application_name {
                sqlx::query("SELECT set_config('application_name', $1, true)")
                    .bind(application_name)
                    .execute(&mut *tx)
                    .await?;
            }
            // REVOKE CONNECT rewrites the same database ACL tuple as the
            // provisioning GRANT. Take the database-global catalog lock
            // before the logical-database lock, matching provision_and_connect
            // so concurrent cleanup and provisioning cannot race or deadlock.
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind(DATABASE_PROVISION_LOCK)
                .execute(&mut *tx)
                .await?;
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                .bind(&self.logical_database_id)
                .execute(&mut *tx)
                .await?;
            let schema_state = sqlx::query(
                "SELECT owner.rolname AS owner, obj_description(namespace.oid, 'pg_namespace') AS marker FROM pg_namespace namespace JOIN pg_roles owner ON owner.oid=namespace.nspowner WHERE namespace.nspname=$1",
            )
            .bind(&schema)
            .fetch_optional(&mut *tx)
            .await?;
            if let Some(row) = &schema_state {
                let owner: String = row.try_get("owner")?;
                let existing_marker: Option<String> = row.try_get("marker")?;
                if owner != role || existing_marker.as_deref() != Some(marker.as_str()) {
                    return Err(Error::engine(
                        "refusing to drop a Postgres schema without the expected owner and ownership marker",
                    ));
                }
            }
            let role_marker: Option<Option<String>> = sqlx::query_scalar(
                "SELECT shobj_description(oid, 'pg_authid') FROM pg_roles WHERE rolname=$1",
            )
            .bind(&role)
            .fetch_optional(&mut *tx)
            .await?;
            if role_marker
                .as_ref()
                .is_some_and(|value| value.as_deref() != Some(marker.as_str()))
            {
                return Err(Error::engine(
                    "refusing to drop a Postgres role without the expected ownership marker",
                ));
            }
            let query_role_marker: Option<Option<String>> = sqlx::query_scalar(
                "SELECT shobj_description(oid, 'pg_authid') FROM pg_roles WHERE rolname=$1",
            )
            .bind(&query_role)
            .fetch_optional(&mut *tx)
            .await?;
            if query_role_marker
                .as_ref()
                .is_some_and(|value| value.as_deref() != Some(marker.as_str()))
            {
                return Err(Error::engine(
                    "refusing to drop a Postgres query role without the expected ownership marker",
                ));
            }
            if schema_state.is_some() {
                tx.execute(format!("DROP SCHEMA {quoted_schema} CASCADE").as_str())
                    .await?;
            }
            if query_role_marker.is_some() {
                tx.execute(format!("DROP OWNED BY {quoted_query_role}").as_str())
                    .await?;
                if role_marker.is_some() {
                    tx.execute(
                        format!("REVOKE {quoted_query_role} FROM {quoted_role}").as_str(),
                    )
                    .await?;
                }
                tx.execute(format!("DROP ROLE {quoted_query_role}").as_str())
                    .await?;
            }
            if role_marker.is_some() {
                let database: String = sqlx::query_scalar("SELECT current_database()")
                    .fetch_one(&mut *tx)
                    .await?;
                let quoted_database = quote_operator_identifier(&database)?;
                tx.execute(
                    format!("REVOKE CONNECT ON DATABASE {quoted_database} FROM {quoted_role}")
                        .as_str(),
                )
                .await?;
                tx.execute(format!("DROP ROLE {quoted_role}").as_str())
                    .await?;
            }
            tx.commit().await?;
            Ok(())
        }
        .await;
        admin.close().await;
        result
    }
}

#[derive(Clone, Debug)]
pub struct PostgresCluster {
    pool: PgPool,
    options: PgConnectOptions,
}

impl PostgresCluster {
    pub async fn connect(url: &str) -> Result<Self> {
        let options = PgConnectOptions::from_str(url)
            .map_err(|_| Error::engine("Postgres contract URL is invalid"))?;
        let pool = PgPoolOptions::new()
            .max_connections(12)
            .connect_with(options.clone())
            .await?;
        Ok(Self { pool, options })
    }

    pub async fn fresh_logical_database(&self) -> Result<PostgresDb> {
        self.fresh_database(true, None).await
    }

    async fn fresh_database(&self, seed_roots: bool, tag: Option<&str>) -> Result<PostgresDb> {
        let schema = match tag {
            Some(tag) => format!("native_contract_{tag}_{}", Uuid::new_v4().simple()),
            None => format!("native_contract_{}", Uuid::new_v4().simple()),
        };
        let quoted = quote_identifier(&schema)?;
        self.pool
            .execute(format!("CREATE SCHEMA {quoted}").as_str())
            .await?;
        let query_pool = PgPoolOptions::new()
            .min_connections(0)
            .max_connections(4)
            .after_release(|connection, _metadata| {
                Box::pin(async move {
                    sqlx::query("DISCARD ALL").execute(connection).await?;
                    Ok(false)
                })
            })
            .connect_with(self.options.clone())
            .await?;
        let query_role = query_role_for_schema(&schema)?;
        let db = PostgresDb {
            pool: self.pool.clone(),
            query_pool,
            query_role,
            schema,
            schema_tag: tag.map(str::to_owned),
            runtime: None,
            portability_policy_gate: Arc::new(tokio::sync::RwLock::new(())),
            realtime_hub: Arc::new(PostgresRealtimeHub::new()),
            #[cfg(feature = "postgres-tests")]
            intent_persist_checkpoint: Arc::new(PostgresIntentPersistCheckpoint::default()),
            #[cfg(test)]
            request_lifecycle_test_bypass: false,
        };
        if let Err(error) = db.migrate(seed_roots).await {
            return match db.drop_schema().await {
                Ok(()) => Err(error),
                Err(cleanup) => Err(Error::engine(format!(
                    "{error}; additionally failed to clean up Postgres staging schema {}: {cleanup}",
                    db.schema()
                ))),
            };
        }
        Ok(db)
    }

    /// Import one validated canonical document into a fresh, isolated schema.
    /// A failed import drops the staging schema before returning.
    pub async fn import_canonical_interchange(
        &self,
        bytes: &[u8],
    ) -> Result<(PostgresDb, PostgresImportReport)> {
        self.import_canonical_interchange_with_optional_tag(bytes, None)
            .await
    }

    /// Import seam with a short generated-schema tag for isolated integration
    /// cleanup assertions. Production callers should use the untagged method.
    #[doc(hidden)]
    pub async fn import_canonical_interchange_with_tag(
        &self,
        bytes: &[u8],
        tag: &str,
    ) -> Result<(PostgresDb, PostgresImportReport)> {
        validate_schema_tag(tag)?;
        self.import_canonical_interchange_with_optional_tag(bytes, Some(tag))
            .await
    }

    async fn import_canonical_interchange_with_optional_tag(
        &self,
        bytes: &[u8],
        tag: Option<&str>,
    ) -> Result<(PostgresDb, PostgresImportReport)> {
        let interchange = validate_canonical_interchange(bytes)?;
        validate_postgres_admission(&interchange)?;
        let db = self.fresh_database(false, tag).await?;
        match db.import_validated(&interchange).await {
            Ok(report) => Ok((db, report)),
            Err(error) => {
                match db.drop_schema().await {
                    Ok(()) => Err(error),
                    Err(cleanup) => Err(Error::engine(format!(
                        "{error}; additionally failed to clean up Postgres staging schema {}: {cleanup}",
                        db.schema()
                    ))),
                }
            }
        }
    }

    /// Generated logical schemas owned by the Postgres contract slice. This is
    /// an operator/test diagnostic and never exposes unrelated schemas.
    pub async fn logical_schemas(&self) -> Result<Vec<String>> {
        Ok(sqlx::query_scalar(
            "SELECT nspname FROM pg_namespace \
             WHERE left(nspname, 16) = 'native_contract_' \
                OR left(nspname, 14) = 'native_replay_' \
             ORDER BY nspname",
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// List only contract and replay schemas carrying one validated import-test
    /// tag.
    #[doc(hidden)]
    pub async fn logical_schemas_with_tag(&self, tag: &str) -> Result<Vec<String>> {
        validate_schema_tag(tag)?;
        let contract_prefix = format!("native_contract_{tag}_");
        let replay_prefix = format!("native_replay_{tag}_");
        Ok(sqlx::query_scalar(
            "SELECT nspname FROM pg_namespace \
             WHERE left(nspname, length($1)) = $1 \
                OR left(nspname, length($2)) = $2 \
             ORDER BY nspname",
        )
        .bind(contract_prefix)
        .bind(replay_prefix)
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn close(&self) {
        self.pool.close().await;
    }
}

/// One Native logical database, isolated in one Postgres schema for the spike.
#[derive(Clone, Debug)]
pub struct PostgresDb {
    pool: PgPool,
    query_pool: PgPool,
    query_role: String,
    schema: String,
    schema_tag: Option<String>,
    runtime: Option<Arc<PostgresRuntimeMetadata>>,
    portability_policy_gate: Arc<tokio::sync::RwLock<()>>,
    realtime_hub: Arc<PostgresRealtimeHub>,
    #[cfg(feature = "postgres-tests")]
    intent_persist_checkpoint: Arc<PostgresIntentPersistCheckpoint>,
    /// Only the unreachable lazy-handle registry unit may skip physical
    /// request effects; production and integration constructors set false.
    #[cfg(test)]
    request_lifecycle_test_bypass: bool,
}

#[cfg(feature = "postgres-tests")]
#[derive(Debug, Default)]
struct PostgresIntentPersistCheckpoint {
    armed: AtomicBool,
    entered: AtomicBool,
    entered_notify: tokio::sync::Notify,
}

#[cfg(feature = "postgres-tests")]
impl PostgresIntentPersistCheckpoint {
    fn arm(&self) {
        self.entered.store(false, Ordering::Release);
        self.armed.store(true, Ordering::Release);
    }

    async fn enter(&self) {
        if !self.armed.swap(false, Ordering::AcqRel) {
            return;
        }
        self.entered.store(true, Ordering::Release);
        self.entered_notify.notify_waiters();
        std::future::pending::<()>().await;
    }

    async fn wait_until_entered(&self) {
        loop {
            let notified = self.entered_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.entered.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
}

/// Database-scoped post-commit wake channel for the Postgres runtime. Durable
/// log cursors remain the recovery authority; this channel is latency only.
#[derive(Debug)]
pub struct PostgresRealtimeHub {
    generation: AtomicU64,
    sender: tokio::sync::broadcast::Sender<u64>,
}

impl PostgresRealtimeHub {
    fn new() -> Self {
        let (sender, _) = tokio::sync::broadcast::channel(crate::realtime::HUB_CAPACITY);
        Self {
            generation: AtomicU64::new(0),
            sender,
        }
    }

    fn wake(&self) {
        let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        let _ = self.sender.send(generation);
    }

    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<u64> {
        self.sender.subscribe()
    }
}

struct PostgresRequestRealtimeCompletion {
    committed: AtomicBool,
    hub: Arc<PostgresRealtimeHub>,
}

impl PostgresRequestRealtimeCompletion {
    fn finish(&self) {
        if self.committed.swap(false, Ordering::AcqRel) {
            self.hub.wake();
        }
    }
}

impl Drop for PostgresRequestRealtimeCompletion {
    fn drop(&mut self) {
        self.finish();
    }
}

tokio::task_local! {
    static POSTGRES_REQUEST_REALTIME_COMPLETION: Arc<PostgresRequestRealtimeCompletion>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UnmaterializedSection {
    pub name: String,
    pub row_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VerifiedProjectionCoverage {
    pub section: String,
    pub fields: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PostgresVerificationReport {
    pub source_profile_id: String,
    pub source_profile_revision: u64,
    pub verified_projection_coverage: Vec<VerifiedProjectionCoverage>,
    pub unmaterialized_sections: Vec<UnmaterializedSection>,
    pub emulated_fields: Vec<String>,
    pub event_count: u64,
    pub record_count: u64,
    pub facet_count: u64,
}

#[derive(Clone, Debug, Deserialize)]
struct PostgresBindingAuditEvent {
    seq: i64,
    id: String,
    action: String,
    system: String,
    identifier: String,
    old_record_id: Option<String>,
    new_record_id: Option<String>,
    old_canonical: Option<bool>,
    new_canonical: Option<bool>,
    actor: String,
    reason: String,
    run_key: Option<String>,
    parent_key: Option<String>,
    intent: Option<String>,
    created_at: DateTime<Utc>,
}

pub type PostgresImportReport = PostgresVerificationReport;

fn postgres_delete_parity_schema(schema: &str) -> Vec<String> {
    vec![
        format!("CREATE TABLE {schema}.instruction_bindings (id TEXT PRIMARY KEY,scope_kind TEXT NOT NULL CHECK(scope_kind IN ('database','account')),scope_id TEXT NOT NULL,source_record_id TEXT NOT NULL REFERENCES {schema}.records(id),position BIGINT NOT NULL,enabled BOOLEAN NOT NULL DEFAULT TRUE,created_by TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL,updated_at TIMESTAMPTZ NOT NULL,UNIQUE(scope_kind,scope_id,position),UNIQUE(scope_kind,scope_id,source_record_id))"),
        format!("CREATE INDEX instruction_bindings_source ON {schema}.instruction_bindings(source_record_id)"),
        format!("CREATE TABLE {schema}.onboarding_programmes (id TEXT PRIMARY KEY,trigger_key TEXT NOT NULL,generation BIGINT NOT NULL DEFAULT 1 CHECK(generation > 0),position BIGINT NOT NULL,enabled BOOLEAN NOT NULL DEFAULT TRUE,created_by TEXT NOT NULL,legacy_baseline_before TIMESTAMPTZ,created_at TIMESTAMPTZ NOT NULL,updated_at TIMESTAMPTZ NOT NULL)"),
        format!("CREATE TABLE {schema}.onboarding_programme_sources (programme_id TEXT NOT NULL REFERENCES {schema}.onboarding_programmes(id) ON DELETE CASCADE,source_record_id TEXT NOT NULL REFERENCES {schema}.records(id),source_role TEXT NOT NULL CHECK(source_role IN ('guidance','completion_criteria')),position BIGINT NOT NULL,PRIMARY KEY(programme_id,source_record_id),UNIQUE(programme_id,position))"),
        format!("CREATE TABLE {schema}.notification_candidate_events (seq BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,id TEXT NOT NULL UNIQUE,candidate_key TEXT NOT NULL,action TEXT NOT NULL CHECK(action IN ('proposed','suppressed','withdrawn')),recipient_account_id TEXT NOT NULL,message_id TEXT NOT NULL,reason TEXT NOT NULL CHECK(reason IN ('principal_mention','human_obligation','human_intervention','snooze_due','routine_arrival')),priority TEXT NOT NULL CHECK(priority IN ('routine','urgent')),not_before TIMESTAMPTZ,redaction_class TEXT NOT NULL CHECK(redaction_class IN ('metadata_only','minimal_context')),evaluator_kind TEXT NOT NULL CHECK(evaluator_kind IN ('portable_default','recipient_policy','intervention_policy')),policy_version TEXT NOT NULL,source_event_type TEXT NOT NULL,source_event_id TEXT NOT NULL,payload JSONB NOT NULL CHECK(jsonb_typeof(payload)='object'),created_at TIMESTAMPTZ NOT NULL)"),
        format!("CREATE INDEX notification_candidate_events_recipient ON {schema}.notification_candidate_events(recipient_account_id,seq)"),
        format!("CREATE TRIGGER notification_candidate_events_append_only BEFORE UPDATE OR DELETE ON {schema}.notification_candidate_events FOR EACH ROW EXECUTE FUNCTION {schema}.reject_authoritative_event_mutation()"),
        format!("CREATE TABLE {schema}.notification_candidates (candidate_id TEXT PRIMARY KEY REFERENCES {schema}.notification_candidate_events(id) ON DELETE RESTRICT,candidate_key TEXT NOT NULL UNIQUE,recipient_account_id TEXT NOT NULL,message_id TEXT NOT NULL,reason TEXT NOT NULL,priority TEXT NOT NULL,not_before TIMESTAMPTZ,redaction_class TEXT NOT NULL,evaluator_kind TEXT NOT NULL,policy_version TEXT NOT NULL,source_event_type TEXT NOT NULL,source_event_id TEXT NOT NULL,candidate_event_seq BIGINT NOT NULL UNIQUE,status TEXT NOT NULL CHECK(status IN ('effective','suppressed','withdrawn')),created_at TIMESTAMPTZ NOT NULL)"),
        format!("CREATE INDEX notification_candidates_recipient ON {schema}.notification_candidates(recipient_account_id,candidate_event_seq)"),
    ]
}

fn postgres_v5_schema(schema: &str) -> Vec<String> {
    vec![format!(
        "CREATE INDEX records_native_fts ON {schema}.records USING GIN \
         (to_tsvector('english',coalesce(name,'') || ' ' || coalesce(body,'')))"
    )]
}

fn postgres_v6_schema(schema: &str) -> Vec<String> {
    vec![
        format!(
            "ALTER TABLE {schema}.content_events \
             ADD COLUMN causal_envelope_version BIGINT NOT NULL DEFAULT 1 \
                 CHECK(causal_envelope_version=1),\
             ADD COLUMN causal_status TEXT NOT NULL DEFAULT 'legacy_unknown' \
                 CHECK(causal_status IN ('complete','import_incomplete','legacy_unknown'))"
        ),
        format!(
            "ALTER TABLE {schema}.content_events \
             ALTER COLUMN causal_envelope_version DROP DEFAULT,\
             ALTER COLUMN causal_status DROP DEFAULT"
        ),
        format!(
            "CREATE TABLE {schema}.content_event_causal_frontier (\
             event_id TEXT NOT NULL REFERENCES {schema}.content_events(id) ON DELETE CASCADE,\
             parent_event_id TEXT NOT NULL CHECK(btrim(parent_event_id) <> ''),\
             PRIMARY KEY(event_id,parent_event_id),CHECK(event_id<>parent_event_id))"
        ),
        format!(
            "CREATE INDEX content_event_causal_frontier_parent ON \
             {schema}.content_event_causal_frontier(parent_event_id,event_id)"
        ),
        format!(
            "CREATE TABLE {schema}.content_event_causal_cutover (\
             singleton SMALLINT PRIMARY KEY CHECK(singleton=1),\
             last_legacy_local_seq BIGINT NOT NULL CHECK(last_legacy_local_seq>=0),\
             cutover_at TIMESTAMPTZ NOT NULL,from_engine_schema INTEGER)"
        ),
        format!(
            "INSERT INTO {schema}.content_event_causal_cutover(\
             singleton,last_legacy_local_seq,cutover_at,from_engine_schema) \
             SELECT 1,COALESCE(MAX(seq),0),transaction_timestamp(),5 \
             FROM {schema}.content_events"
        ),
        format!(
            "CREATE TABLE {schema}.content_event_sources (\
             event_id TEXT PRIMARY KEY REFERENCES {schema}.content_events(id) ON DELETE CASCADE,\
             origin_database_id TEXT NOT NULL CHECK(btrim(origin_database_id) <> ''),\
             source_seq BIGINT NOT NULL CHECK(source_seq > 0),\
             source_record_id TEXT NOT NULL CHECK(btrim(source_record_id) <> ''),\
             source_principal TEXT NOT NULL CHECK(btrim(source_principal) <> ''),\
             source_fingerprint TEXT NOT NULL CHECK(length(source_fingerprint)=64))"
        ),
    ]
}

impl PostgresDb {
    #[cfg(feature = "postgres-tests")]
    #[doc(hidden)]
    pub async fn contract_rewind_schema_v5_to_v4_for_test(&self) -> Result<()> {
        let migrations = self.qualified_table("schema_migrations")?;
        let index = format!(
            "{}.{}",
            quote_identifier(&self.schema)?,
            quote_identifier("records_native_fts")?
        );
        let mut tx = self.pool.begin().await?;
        tx.execute(
            format!(
                "DROP TABLE {}.{}",
                quote_identifier(&self.schema)?,
                quote_identifier("content_event_causal_frontier")?
            )
            .as_str(),
        )
        .await?;
        tx.execute(
            format!(
                "DROP TABLE {}.{}",
                quote_identifier(&self.schema)?,
                quote_identifier("content_event_causal_cutover")?
            )
            .as_str(),
        )
        .await?;
        tx.execute(
            format!(
                "DROP TABLE {}.{}",
                quote_identifier(&self.schema)?,
                quote_identifier("content_event_sources")?
            )
            .as_str(),
        )
        .await?;
        tx.execute(
            format!(
                "ALTER TABLE {}.{} DROP COLUMN causal_envelope_version,DROP COLUMN causal_status",
                quote_identifier(&self.schema)?,
                quote_identifier("content_events")?
            )
            .as_str(),
        )
        .await?;
        tx.execute(format!("DROP INDEX {index}").as_str()).await?;
        sqlx::query(&format!("DELETE FROM {migrations} WHERE version IN (5,6)"))
            .execute(&mut *tx)
            .await?;
        sqlx::query(&format!(
            "INSERT INTO {migrations}(version) VALUES(4) ON CONFLICT DO NOTHING"
        ))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    #[cfg(feature = "postgres-tests")]
    #[doc(hidden)]
    /// Append one record the way an older build left it behind: a projected
    /// `record.created` carrying a caller-chosen, non-UUID id. Today's
    /// admission rule refuses such an id, but databases written before it
    /// still hold them, and boundary behaviour — prefix resolution in
    /// particular — must keep answering for them. The event is written to the
    /// authoritative log and folded by the production projector; only the id
    /// admission check is bypassed.
    pub async fn contract_create_historical_record_for_test(
        &self,
        record_id: &str,
        name: &str,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let created = json!({
            "type":"Document",
            "kind":"note",
            "name":name,
            "home_id":UNFILED_RECORD_ID,
            "persistence":"enduring"
        });
        let (_, created_at) = append_event(
            self,
            &mut tx,
            record_id,
            "record.created",
            &created,
            "engine:migration",
        )
        .await?;
        apply_projection(
            self,
            &mut tx,
            record_id,
            "record.created",
            &created,
            &created_at,
        )
        .await?;
        tx.commit().await?;
        self.complete_realtime_commit();
        Ok(())
    }

    pub async fn contract_create_attribution_record_for_test(&self, record_id: &str) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let created = json!({
            "type":"Annotation",
            "kind":"attribution",
            "name":"Contract attribution",
            "home_id":UNFILED_RECORD_ID,
            "persistence":"enduring",
            "reason":"Exercise portable attribution deletion refusal."
        });
        let (_, created_at) = append_event(
            self,
            &mut tx,
            record_id,
            "record.created",
            &created,
            "contract",
        )
        .await?;
        apply_projection(
            self,
            &mut tx,
            record_id,
            "record.created",
            &created,
            &created_at,
        )
        .await?;
        let linked = json!({
            "source_id":record_id,
            "target_id":ROOT_RECORD_ID,
            "relationship":"part_of",
            "reason":"Bind attribution authorization to its bearer."
        });
        let (_, linked_at) =
            append_event(self, &mut tx, record_id, "link.added", &linked, "contract").await?;
        apply_projection(self, &mut tx, record_id, "link.added", &linked, &linked_at).await?;
        tx.commit().await?;
        self.complete_realtime_commit();
        Ok(())
    }

    #[cfg(feature = "postgres-tests")]
    pub fn contract_arm_intent_persist_block(&self) {
        self.intent_persist_checkpoint.arm();
    }

    #[cfg(feature = "postgres-tests")]
    pub async fn contract_wait_for_intent_persist_block(&self) {
        self.intent_persist_checkpoint.wait_until_entered().await;
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub(crate) fn query_pool(&self) -> &PgPool {
        &self.query_pool
    }

    pub(crate) fn query_role(&self) -> &str {
        &self.query_role
    }

    #[doc(hidden)]
    pub fn query_role_name(&self) -> &str {
        &self.query_role
    }

    #[cfg(feature = "postgres-tests")]
    #[doc(hidden)]
    pub async fn qualification_query_backend_pid(&self) -> Result<i32> {
        let mut connection = self.query_pool.acquire().await?;
        Ok(sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *connection)
            .await?)
    }

    pub fn schema(&self) -> &str {
        &self.schema
    }

    pub fn logical_database_id(&self) -> Option<&str> {
        self.runtime
            .as_ref()
            .map(|runtime| runtime.logical_database_id.as_str())
    }

    pub fn redacted_config(&self) -> Option<&PostgresRedactedConfig> {
        self.runtime.as_ref().map(|runtime| &runtime.redacted)
    }

    pub fn liveness(&self) -> bool {
        !self.pool.is_closed()
    }

    pub async fn health(&self) -> Result<PostgresHealthReport> {
        let live = self.liveness();
        if !live {
            return Ok(PostgresHealthReport {
                live: false,
                reachable: false,
                ready: false,
                write_ready: false,
                least_privilege: false,
                schema_currency: PostgresSchemaCurrency::Missing,
                expected_schema_version: SCHEMA_VERSION,
                observed_schema_version: None,
            });
        }
        let mut connection = match self.pool.acquire().await {
            Ok(connection) => connection,
            Err(_) => {
                return Ok(PostgresHealthReport {
                    live: true,
                    reachable: false,
                    ready: false,
                    write_ready: false,
                    least_privilege: false,
                    schema_currency: PostgresSchemaCurrency::Missing,
                    expected_schema_version: SCHEMA_VERSION,
                    observed_schema_version: None,
                })
            }
        };
        let current_user: String = sqlx::query_scalar("SELECT current_user")
            .fetch_one(&mut *connection)
            .await?;
        let role_matches = self
            .runtime
            .as_ref()
            .is_none_or(|runtime| runtime.runtime_role == current_user);
        let schema_usage: bool =
            sqlx::query_scalar("SELECT has_schema_privilege(current_user, $1, 'USAGE')")
                .bind(&self.schema)
                .fetch_one(&mut *connection)
                .await?;
        let constrained_role: bool = sqlx::query_scalar(
            "SELECT rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolinherit AND NOT rolreplication AND NOT rolbypassrls FROM pg_roles WHERE rolname=current_user",
        )
        .fetch_optional(&mut *connection)
        .await?
        .unwrap_or(false);
        let can_create_database: bool = sqlx::query_scalar(
            "SELECT has_database_privilege(current_user, current_database(), 'CREATE')",
        )
        .fetch_one(&mut *connection)
        .await?;
        let external_schema_create: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pg_namespace WHERE nspname <> $1 AND nspname NOT LIKE 'pg_temp_%' AND nspname NOT LIKE 'pg_toast_temp_%' AND has_schema_privilege(current_user, nspname, 'CREATE')",
        )
        .bind(&self.schema)
        .fetch_one(&mut *connection)
        .await?;
        let query_role_boundary: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM pg_roles role WHERE role.rolname=$1 AND NOT role.rolcanlogin AND NOT role.rolsuper AND NOT role.rolcreatedb AND NOT role.rolcreaterole AND NOT role.rolinherit AND NOT role.rolreplication AND NOT role.rolbypassrls) \
             AND EXISTS(SELECT 1 FROM pg_auth_members membership JOIN pg_roles role ON role.oid=membership.roleid JOIN pg_roles member ON member.oid=membership.member WHERE role.rolname=$1 AND member.rolname=current_user AND NOT membership.admin_option AND NOT membership.inherit_option AND membership.set_option) \
             AND NOT EXISTS(SELECT 1 FROM pg_auth_members membership JOIN pg_roles role ON role.oid=membership.roleid JOIN pg_roles member ON member.oid=membership.member WHERE role.rolname=$1 AND member.rolname<>current_user) \
             AND NOT EXISTS(SELECT 1 FROM pg_auth_members membership JOIN pg_roles member ON member.oid=membership.member WHERE member.rolname=$1)",
        )
        .bind(&self.query_role)
        .fetch_one(&mut *connection)
        .await?;
        let least_privilege = constrained_role
            && !can_create_database
            && external_schema_create == 0
            && query_role_boundary;
        let required_relations = REQUIRED_RELATIONS
            .iter()
            .map(|relation| (*relation).to_string())
            .collect::<Vec<_>>();
        let relation_state = sqlx::query(
            "WITH required(name) AS (SELECT unnest($2::text[])) \
             SELECT COUNT(class.oid) = cardinality($2::text[]) AS complete, \
                    COALESCE(bool_and(owner.rolname=current_user), FALSE) AS owned, \
                    COALESCE(bool_and(\
                        has_table_privilege(current_user, class.oid, 'SELECT') AND \
                        has_table_privilege(current_user, class.oid, 'INSERT') AND \
                        has_table_privilege(current_user, class.oid, 'UPDATE') AND \
                        has_table_privilege(current_user, class.oid, 'DELETE')\
                    ), FALSE) AS dml \
             FROM required \
             LEFT JOIN pg_namespace namespace ON namespace.nspname=$1 \
             LEFT JOIN pg_class class ON class.relnamespace=namespace.oid \
                                      AND class.relname=required.name \
                                      AND class.relkind IN ('r', 'p') \
             LEFT JOIN pg_roles owner ON owner.oid=class.relowner",
        )
        .bind(&self.schema)
        .bind(&required_relations)
        .fetch_one(&mut *connection)
        .await?;
        let relation_set_complete: bool = relation_state.try_get("complete")?;
        let relation_set_owned: bool = relation_state.try_get("owned")?;
        let dml_ready: bool = relation_state.try_get("dml")?;
        let append_only_ready: bool = sqlx::query_scalar(
            "SELECT COUNT(*)=6 AND COALESCE(bool_and(\
                    trigger.tgtype=27 AND trigger.tgenabled<>'D' AND \
                    proc.proname='reject_authoritative_event_mutation' AND \
                    proc.prosrc LIKE '%authoritative event logs are append-only%' AND \
                    proc.prosrc LIKE '%55000%'\
                 ),FALSE) \
             FROM pg_trigger trigger \
             JOIN pg_class relation ON relation.oid=trigger.tgrelid \
             JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace \
             JOIN pg_proc proc ON proc.oid=trigger.tgfoid \
             JOIN pg_namespace proc_namespace ON proc_namespace.oid=proc.pronamespace \
             WHERE namespace.nspname=$1 AND proc_namespace.nspname=$1 \
               AND relation.relname=ANY($2::text[]) \
               AND trigger.tgname=relation.relname || '_append_only' \
               AND NOT trigger.tgisinternal",
        )
        .bind(&self.schema)
        .bind([
            "content_events",
            "meta_events",
            "policy_events",
            "control_events",
            "notification_candidate_events",
            "binding_audit",
        ])
        .fetch_one(&mut *connection)
        .await?;
        let search_index_ready: bool = sqlx::query_scalar(
            "SELECT EXISTS(\
                 SELECT 1 \
                 FROM pg_index index_state \
                 JOIN pg_class index_relation ON index_relation.oid=index_state.indexrelid \
                 JOIN pg_namespace index_namespace ON index_namespace.oid=index_relation.relnamespace \
                 JOIN pg_class records_relation ON records_relation.oid=index_state.indrelid \
                 JOIN pg_namespace records_namespace ON records_namespace.oid=records_relation.relnamespace \
                 JOIN pg_am access_method ON access_method.oid=index_relation.relam \
                 WHERE index_namespace.nspname=$1 \
                   AND records_namespace.nspname=$1 \
                   AND index_relation.relname='records_native_fts' \
                   AND records_relation.relname='records' \
                   AND access_method.amname='gin' \
                   AND index_state.indnkeyatts=1 \
                   AND index_state.indpred IS NULL \
                   AND index_state.indisvalid \
                   AND index_state.indisready \
                   AND pg_get_expr(index_state.indexprs,index_state.indrelid)=$2\
             )",
        )
        .bind(&self.schema)
        .bind("to_tsvector('english'::regconfig, ((COALESCE(name, ''::text) || ' '::text) || COALESCE(body, ''::text)))")
        .fetch_one(&mut *connection)
        .await?;
        let relation = format!("{}.schema_migrations", self.schema);
        let exists: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
            .bind(relation)
            .fetch_one(&mut *connection)
            .await?;
        let observed_schema_version = if exists {
            let migrations = self.qualified_table("schema_migrations")?;
            sqlx::query_scalar::<_, Option<i32>>(&format!("SELECT MAX(version) FROM {migrations}"))
                .fetch_one(&mut *connection)
                .await?
        } else {
            None
        };
        let schema_currency = match observed_schema_version {
            None => PostgresSchemaCurrency::Missing,
            Some(version) if version < SCHEMA_VERSION => PostgresSchemaCurrency::Behind,
            Some(version) if version > SCHEMA_VERSION => PostgresSchemaCurrency::Ahead,
            Some(_) => PostgresSchemaCurrency::Current,
        };
        let ready = role_matches
            && schema_usage
            && least_privilege
            && relation_set_complete
            && relation_set_owned
            && append_only_ready
            && search_index_ready
            && schema_currency == PostgresSchemaCurrency::Current;
        let write_probe_ready = if ready && dml_ready {
            let event_cursor = self.qualified_table("event_cursor")?;
            let mut probe = connection.begin().await?;
            let probe_result = sqlx::query(&format!(
                "UPDATE {event_cursor} SET last_seq=last_seq WHERE singleton=TRUE"
            ))
            .execute(&mut *probe)
            .await;
            let rollback_result = probe.rollback().await;
            probe_result.is_ok_and(|result| result.rows_affected() == 1) && rollback_result.is_ok()
        } else {
            false
        };
        Ok(PostgresHealthReport {
            live,
            reachable: true,
            ready,
            write_ready: ready && dml_ready && write_probe_ready,
            least_privilege,
            schema_currency,
            expected_schema_version: SCHEMA_VERSION,
            observed_schema_version,
        })
    }

    pub async fn close(&self) {
        self.query_pool.close().await;
        self.pool.close().await;
    }

    pub fn realtime_hub(&self) -> Arc<PostgresRealtimeHub> {
        Arc::clone(&self.realtime_hub)
    }

    pub(crate) fn complete_realtime_commit(&self) {
        if POSTGRES_REQUEST_REALTIME_COMPLETION
            .try_with(|completion| completion.committed.store(true, Ordering::Release))
            .is_err()
        {
            self.realtime_hub.wake();
        }
    }

    pub(crate) async fn with_request_realtime_completion<F>(&self, future: F) -> F::Output
    where
        F: std::future::Future,
    {
        let completion = Arc::new(PostgresRequestRealtimeCompletion {
            committed: AtomicBool::new(false),
            hub: Arc::clone(&self.realtime_hub),
        });
        let output = POSTGRES_REQUEST_REALTIME_COMPLETION
            .scope(Arc::clone(&completion), future)
            .await;
        completion.finish();
        output
    }

    pub fn qualified_table(&self, table: &str) -> Result<String> {
        if !matches!(
            table,
            "schema_migrations"
                | "event_cursor"
                | "content_events"
                | "content_event_causal_frontier"
                | "content_event_causal_cutover"
                | "content_event_sources"
                | "records"
                | "facet_values"
                | "bindings"
                | "message_audience"
                | "log_cursors"
                | "meta_events"
                | "policy_events"
                | "control_events"
                | "links"
                | "blobs"
                | "binding_systems"
                | "binding_audit"
                | "database_identity"
                | "database_identity_audit"
                | "record_policies"
                | "policy_entries"
                | "authorization_revision"
                | "vocabularies"
                | "vocabulary_values"
                | "schema_config"
                | "control_projections"
                | "run_contexts"
                | "request_interactions"
                | "storage_portability_policy"
                | "instruction_bindings"
                | "onboarding_programmes"
                | "onboarding_programme_sources"
                | "notification_candidate_events"
                | "notification_candidates"
                | "annotation_targets"
        ) {
            return Err(Error::engine("unknown Postgres substrate table"));
        }
        Ok(format!(
            "{}.{}",
            quote_identifier(&self.schema)?,
            quote_identifier(table)?
        ))
    }

    async fn migrate(&self, seed_roots: bool) -> Result<()> {
        if self.runtime.is_none() {
            self.ensure_contract_query_role().await?;
        }
        let schema = quote_identifier(&self.schema)?;
        let statements = [
            format!(
                "CREATE TABLE {schema}.schema_migrations (\
                 version INTEGER PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp())"
            ),
            format!(
                "CREATE TABLE {schema}.event_cursor (\
                 singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),\
                 last_seq BIGINT NOT NULL CHECK (last_seq >= 0))"
            ),
            format!(
                "CREATE TABLE {schema}.content_events (\
                 seq BIGINT PRIMARY KEY, id TEXT NOT NULL UNIQUE, record_id TEXT NOT NULL,\
                 type TEXT NOT NULL, payload JSONB NOT NULL, actor TEXT,run_key TEXT,parent_key TEXT,intent TEXT,\
                 created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),\
                 causal_envelope_version BIGINT NOT NULL CHECK(causal_envelope_version=1),\
                 causal_status TEXT NOT NULL CHECK(causal_status IN ('complete','import_incomplete','legacy_unknown')))"
            ),
            format!(
                "CREATE INDEX content_events_record_seq ON {schema}.content_events(record_id, seq)"
            ),
            format!(
                "CREATE TABLE {schema}.content_event_causal_frontier (\
                 event_id TEXT NOT NULL REFERENCES {schema}.content_events(id) ON DELETE CASCADE,\
                 parent_event_id TEXT NOT NULL CHECK(btrim(parent_event_id) <> ''),\
                 PRIMARY KEY(event_id,parent_event_id),CHECK(event_id<>parent_event_id))"
            ),
            format!(
                "CREATE INDEX content_event_causal_frontier_parent ON {schema}.content_event_causal_frontier(parent_event_id,event_id)"
            ),
            format!(
                "CREATE TABLE {schema}.content_event_causal_cutover (\
                 singleton SMALLINT PRIMARY KEY CHECK(singleton=1),\
                 last_legacy_local_seq BIGINT NOT NULL CHECK(last_legacy_local_seq>=0),\
                 cutover_at TIMESTAMPTZ NOT NULL,from_engine_schema INTEGER)"
            ),
            format!(
                "CREATE TABLE {schema}.content_event_sources (\
                 event_id TEXT PRIMARY KEY REFERENCES {schema}.content_events(id) ON DELETE CASCADE,\
                 origin_database_id TEXT NOT NULL CHECK(btrim(origin_database_id) <> ''),\
                 source_seq BIGINT NOT NULL CHECK(source_seq > 0),\
                 source_record_id TEXT NOT NULL CHECK(btrim(source_record_id) <> ''),\
                 source_principal TEXT NOT NULL CHECK(btrim(source_principal) <> ''),\
                 source_fingerprint TEXT NOT NULL CHECK(length(source_fingerprint)=64))"
            ),
            format!(
                "CREATE TABLE {schema}.records (\
                 id TEXT PRIMARY KEY, record_type TEXT NOT NULL CHECK(record_type IN ('Document','Program','WorkItem','Outcome','Entity','Collection','Resolution','Conversation','Message','Annotation')), kind TEXT NOT NULL CHECK (kind <> ''),\
                 name TEXT, body TEXT, home_id TEXT REFERENCES {schema}.records(id) ON DELETE SET NULL, summary TEXT, lifecycle TEXT, owner_id TEXT REFERENCES {schema}.records(id),\
                 policy_anchor_id TEXT REFERENCES {schema}.records(id),\
                 persistence TEXT NOT NULL DEFAULT 'enduring' CHECK(persistence IN ('enduring','occurrent')), maturity TEXT,\
                 archived BOOLEAN NOT NULL DEFAULT FALSE, deleted_at TIMESTAMPTZ,\
                 created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),\
                 updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp())"
            ),
            format!(
                "CREATE TABLE {schema}.facet_values (\
                 record_id TEXT NOT NULL REFERENCES {schema}.records(id) ON DELETE CASCADE,\
                 key TEXT NOT NULL, value JSONB NOT NULL, PRIMARY KEY(record_id, key))"
            ),
            format!(
                "CREATE TABLE {schema}.bindings (\
                 record_id TEXT NOT NULL REFERENCES {schema}.records(id) ON DELETE CASCADE,\
                 system TEXT NOT NULL, identifier TEXT NOT NULL, is_canonical BOOLEAN NOT NULL,\
                 url TEXT, etag TEXT, last_seen_at TIMESTAMPTZ,\
                 PRIMARY KEY(record_id, system, identifier), UNIQUE(system, identifier))"
            ),
            format!(
                "CREATE TABLE {schema}.message_audience (\
                 message_id TEXT NOT NULL REFERENCES {schema}.records(id) ON DELETE CASCADE,\
                 account_id TEXT NOT NULL, PRIMARY KEY(message_id, account_id))"
            ),
            format!(
                "CREATE UNIQUE INDEX bindings_one_canonical_per_system ON {schema}.bindings(record_id,system) WHERE is_canonical"
            ),
            format!(
                "CREATE TABLE {schema}.log_cursors (log_name TEXT PRIMARY KEY CHECK(log_name IN ('content','meta','policy','control')), last_seq BIGINT NOT NULL CHECK(last_seq >= 0))"
            ),
            format!(
                "CREATE TABLE {schema}.meta_events (seq BIGINT PRIMARY KEY,id TEXT NOT NULL UNIQUE,subject_id TEXT NOT NULL,type TEXT NOT NULL,payload JSONB,actor TEXT,created_at TIMESTAMPTZ NOT NULL)"
            ),
            format!("CREATE INDEX meta_events_subject_seq ON {schema}.meta_events(subject_id,seq)"),
            format!(
                "CREATE TABLE {schema}.policy_events (seq BIGINT PRIMARY KEY,id TEXT NOT NULL UNIQUE,record_id TEXT NOT NULL,type TEXT NOT NULL CHECK(type IN ('policy.replaced','policy.inheritance_restored')),payload JSONB,actor TEXT NOT NULL CHECK(btrim(actor) <> ''),reason TEXT NOT NULL CHECK(btrim(reason) <> ''),created_at TIMESTAMPTZ NOT NULL)"
            ),
            format!("CREATE INDEX policy_events_record_seq ON {schema}.policy_events(record_id,seq)"),
            format!(
                "CREATE TABLE {schema}.control_events (seq BIGINT PRIMARY KEY,id TEXT NOT NULL UNIQUE,idempotency_key TEXT NOT NULL UNIQUE CHECK(btrim(idempotency_key) <> ''),type TEXT NOT NULL CHECK(btrim(type) <> ''),schema_version BIGINT NOT NULL CHECK(schema_version > 0),aggregate_kind TEXT NOT NULL CHECK(btrim(aggregate_kind) <> ''),aggregate_id TEXT NOT NULL CHECK(btrim(aggregate_id) <> ''),actor TEXT NOT NULL CHECK(btrim(actor) <> ''),run_key TEXT,reason TEXT NOT NULL CHECK(btrim(reason) <> ''),payload JSONB NOT NULL CHECK(jsonb_typeof(payload)='object'),created_at TIMESTAMPTZ NOT NULL)"
            ),
            format!("CREATE INDEX control_events_aggregate_seq ON {schema}.control_events(aggregate_kind,aggregate_id,seq)"),
            format!(
                "CREATE FUNCTION {schema}.reject_authoritative_event_mutation() RETURNS trigger LANGUAGE plpgsql AS $native$ BEGIN RAISE EXCEPTION 'authoritative event logs are append-only' USING ERRCODE='55000'; END $native$"
            ),
            format!("CREATE TRIGGER content_events_append_only BEFORE UPDATE OR DELETE ON {schema}.content_events FOR EACH ROW EXECUTE FUNCTION {schema}.reject_authoritative_event_mutation()"),
            format!("CREATE TRIGGER meta_events_append_only BEFORE UPDATE OR DELETE ON {schema}.meta_events FOR EACH ROW EXECUTE FUNCTION {schema}.reject_authoritative_event_mutation()"),
            format!("CREATE TRIGGER policy_events_append_only BEFORE UPDATE OR DELETE ON {schema}.policy_events FOR EACH ROW EXECUTE FUNCTION {schema}.reject_authoritative_event_mutation()"),
            format!("CREATE TRIGGER control_events_append_only BEFORE UPDATE OR DELETE ON {schema}.control_events FOR EACH ROW EXECUTE FUNCTION {schema}.reject_authoritative_event_mutation()"),
            format!(
                "CREATE TABLE {schema}.links (id TEXT PRIMARY KEY,source_id TEXT NOT NULL REFERENCES {schema}.records(id) ON DELETE CASCADE,target_id TEXT NOT NULL REFERENCES {schema}.records(id) ON DELETE CASCADE,relationship TEXT NOT NULL,note TEXT,created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),UNIQUE(source_id,target_id,relationship))"
            ),
            format!(
                "CREATE TABLE {schema}.blobs (id TEXT PRIMARY KEY,bytes BYTEA,mime TEXT,size_bytes BIGINT NOT NULL CHECK(size_bytes >= 0),sha256 TEXT NOT NULL CHECK(sha256 ~ '^[0-9a-f]{{64}}$'),original_filename TEXT,storage_tier TEXT NOT NULL DEFAULT 'inline' CHECK(storage_tier IN ('inline','external')),external_ref TEXT,created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),CHECK((storage_tier='inline' AND bytes IS NOT NULL AND external_ref IS NULL) OR (storage_tier='external' AND bytes IS NULL AND external_ref IS NOT NULL)))"
            ),
            format!("CREATE INDEX blobs_sha ON {schema}.blobs(sha256)"),
            format!(
                "CREATE TABLE {schema}.binding_systems (system TEXT PRIMARY KEY,normalizer TEXT NOT NULL,compatible_type TEXT,compatible_kind TEXT,visibility TEXT NOT NULL CHECK(visibility IN ('public','internal','reserved')),add_policy TEXT NOT NULL CHECK(add_policy IN ('record_manage','internal','forbidden')),remove_policy TEXT NOT NULL CHECK(remove_policy IN ('record_manage','internal','forbidden')),canonicalize_policy TEXT NOT NULL CHECK(canonicalize_policy IN ('record_manage','internal','forbidden')),transfer_policy TEXT NOT NULL CHECK(transfer_policy IN ('record_manage','internal','forbidden')),reconciliation_rule TEXT NOT NULL CHECK(reconciliation_rule IN ('binding_only','none')),stub_allowed BOOLEAN NOT NULL,authoritative_provenance BOOLEAN NOT NULL,required_durable BOOLEAN NOT NULL)"
            ),
            format!(
                "CREATE TABLE {schema}.binding_audit (seq BIGINT PRIMARY KEY,id TEXT NOT NULL UNIQUE,action TEXT NOT NULL CHECK(action IN ('add','remove','canonicalize','transfer')),system TEXT NOT NULL REFERENCES {schema}.binding_systems(system),identifier TEXT NOT NULL CHECK(btrim(identifier) <> ''),old_record_id TEXT,new_record_id TEXT,old_canonical BOOLEAN,new_canonical BOOLEAN,actor TEXT NOT NULL CHECK(btrim(actor) <> ''),reason TEXT NOT NULL CHECK(btrim(reason) <> ''),run_key TEXT,parent_key TEXT,intent TEXT,created_at TIMESTAMPTZ NOT NULL,CHECK((action='add' AND old_record_id IS NULL AND new_record_id IS NOT NULL AND old_canonical IS NULL AND new_canonical IS NOT NULL) OR (action='remove' AND old_record_id IS NOT NULL AND new_record_id IS NULL AND old_canonical IS NOT NULL AND new_canonical IS NULL) OR (action='transfer' AND old_record_id IS NOT NULL AND new_record_id IS NOT NULL AND old_record_id<>new_record_id AND old_canonical=new_canonical) OR (action='canonicalize' AND old_record_id=new_record_id AND old_canonical<>new_canonical)))"
            ),
            format!("CREATE TRIGGER binding_audit_append_only BEFORE UPDATE OR DELETE ON {schema}.binding_audit FOR EACH ROW EXECUTE FUNCTION {schema}.reject_authoritative_event_mutation()"),
            format!(
                "CREATE TABLE {schema}.database_identity (singleton SMALLINT PRIMARY KEY CHECK(singleton=1),origin_db_id TEXT NOT NULL UNIQUE CHECK(origin_db_id ~ '^ndb_[0-9a-f]{{32}}$'),created_at TIMESTAMPTZ NOT NULL)"
            ),
            format!(
                "CREATE TABLE {schema}.database_identity_audit (seq BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,id TEXT NOT NULL UNIQUE,action TEXT NOT NULL CHECK(action IN ('mint','rekey')),old_origin_db_id TEXT,new_origin_db_id TEXT NOT NULL CHECK(new_origin_db_id ~ '^ndb_[0-9a-f]{{32}}$'),actor TEXT NOT NULL CHECK(btrim(actor) <> ''),reason TEXT NOT NULL CHECK(btrim(reason) <> ''),run_key TEXT,parent_key TEXT,intent TEXT,created_at TIMESTAMPTZ NOT NULL,CHECK((action='mint' AND old_origin_db_id IS NULL) OR (action='rekey' AND old_origin_db_id IS NOT NULL AND old_origin_db_id<>new_origin_db_id)))"
            ),
            format!(
                "CREATE TABLE {schema}.record_policies (record_id TEXT PRIMARY KEY REFERENCES {schema}.records(id) ON DELETE CASCADE,created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp())"
            ),
            format!(
                "CREATE TABLE {schema}.policy_entries (policy_anchor_id TEXT NOT NULL REFERENCES {schema}.record_policies(record_id) ON DELETE CASCADE,subject_kind TEXT NOT NULL CHECK(subject_kind IN ('members','account')),subject_id TEXT NOT NULL,effect TEXT NOT NULL DEFAULT 'allow' CHECK(effect='allow'),capability TEXT NOT NULL CHECK(capability IN ('view','edit','manage')),CHECK((subject_kind='members' AND subject_id='native:members' AND capability IN ('view','edit')) OR (subject_kind='account' AND length(subject_id)>0)),PRIMARY KEY(policy_anchor_id,subject_kind,subject_id,effect))"
            ),
            format!("CREATE INDEX policy_entries_subject ON {schema}.policy_entries(subject_kind,subject_id,policy_anchor_id,capability)"),
            format!("CREATE TABLE {schema}.authorization_revision (id SMALLINT PRIMARY KEY CHECK(id=1),epoch BIGINT NOT NULL)"),
            format!("CREATE TABLE {schema}.vocabularies (id TEXT PRIMARY KEY,name TEXT NOT NULL UNIQUE,created_at TIMESTAMPTZ NOT NULL)"),
            format!(
                "CREATE TABLE {schema}.vocabulary_values (id TEXT PRIMARY KEY,vocabulary_id TEXT NOT NULL REFERENCES {schema}.vocabularies(id) ON DELETE CASCADE,value TEXT NOT NULL,gloss TEXT,status TEXT NOT NULL DEFAULT 'active',ordinal DOUBLE PRECISION NOT NULL DEFAULT 0,terminality TEXT NOT NULL DEFAULT 'open' CHECK(terminality IN ('open','terminal_positive','terminal_negative')),metadata JSONB NOT NULL DEFAULT '{{}}'::jsonb,alias_of TEXT REFERENCES {schema}.vocabulary_values(id),UNIQUE(vocabulary_id,value))"
            ),
            format!(
                "CREATE TABLE {schema}.schema_config (id TEXT PRIMARY KEY,layer TEXT NOT NULL CHECK(layer IN ('pack','user')),name TEXT,data TEXT NOT NULL,applies_to_collection_id TEXT REFERENCES {schema}.records(id) ON DELETE CASCADE,version_lineage TEXT,created_at TIMESTAMPTZ NOT NULL)"
            ),
            format!(
                "CREATE TABLE {schema}.control_projections (aggregate_kind TEXT NOT NULL,aggregate_id TEXT NOT NULL,event_seq BIGINT NOT NULL UNIQUE,event_type TEXT NOT NULL,schema_version BIGINT NOT NULL,payload JSONB NOT NULL,updated_at TIMESTAMPTZ NOT NULL,PRIMARY KEY(aggregate_kind,aggregate_id))"
            ),
            format!(
                "CREATE TABLE {schema}.run_contexts (run_key TEXT PRIMARY KEY,intent TEXT,agent_key TEXT,created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),updated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp())"
            ),
            format!(
                "CREATE TABLE {schema}.request_interactions (seq BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,id TEXT NOT NULL UNIQUE,tool TEXT NOT NULL,actor TEXT NOT NULL,run_key TEXT,parent_key TEXT,arguments JSONB,outcome TEXT NOT NULL CHECK(outcome IN ('ok','error')),error_kind TEXT,run_context JSONB NOT NULL,started_at TIMESTAMPTZ NOT NULL,ended_at TIMESTAMPTZ NOT NULL)"
            ),
            format!(
                "CREATE TABLE {schema}.storage_portability_policy (singleton SMALLINT PRIMARY KEY CHECK(singleton=1),policy_revision BIGINT NOT NULL CHECK(policy_revision > 0),enforcement TEXT NOT NULL CHECK(enforcement IN ('off','strict')),source_profile_id TEXT NOT NULL,source_profile_revision BIGINT NOT NULL CHECK(source_profile_revision > 0),source_mode TEXT NOT NULL,targets JSONB NOT NULL,revision_floors JSONB NOT NULL,allow_conversions JSONB NOT NULL,catalog_sha256 TEXT NOT NULL CHECK(length(catalog_sha256)=64),updated_at TIMESTAMPTZ NOT NULL)"
            ),
        ];
        let mut tx = self.pool.begin().await?;
        for statement in statements {
            tx.execute(statement.as_str()).await?;
        }
        for statement in postgres_delete_parity_schema(&schema) {
            tx.execute(statement.as_str()).await?;
        }
        for statement in postgres_v5_schema(&schema) {
            tx.execute(statement.as_str()).await?;
        }
        sqlx::query(&format!(
            "INSERT INTO {schema}.event_cursor(singleton, last_seq) VALUES(TRUE, 0)"
        ))
        .execute(&mut *tx)
        .await?;
        sqlx::query(&format!(
            "INSERT INTO {schema}.log_cursors(log_name,last_seq) VALUES('content',0),('meta',0),('policy',0),('control',0)"
        ))
        .execute(&mut *tx)
        .await?;
        sqlx::query(&format!(
            "INSERT INTO {schema}.content_event_causal_cutover(singleton,last_legacy_local_seq,cutover_at,from_engine_schema) \
             VALUES(1,0,transaction_timestamp(),NULL)"
        ))
        .execute(&mut *tx)
        .await?;
        sqlx::query(&format!(
            "INSERT INTO {schema}.authorization_revision(id,epoch) VALUES(1,0)"
        ))
        .execute(&mut *tx)
        .await?;
        sqlx::query(&format!(
            "INSERT INTO {schema}.binding_systems(system,normalizer,compatible_type,compatible_kind,visibility,add_policy,remove_policy,canonicalize_policy,transfer_policy,reconciliation_rule,stub_allowed,authoritative_provenance,required_durable) VALUES ('native-principal','native-principal-v1','Entity','person','public','record_manage','record_manage','record_manage','record_manage','binding_only',TRUE,TRUE,TRUE),('email','email-v1','Entity','person','reserved','internal','internal','internal','internal','binding_only',FALSE,TRUE,FALSE),('account','account-v1','Entity','person','reserved','internal','internal','internal','internal','binding_only',FALSE,TRUE,TRUE),('native-record','native-record-v1',NULL,NULL,'public','record_manage','record_manage','record_manage','record_manage','binding_only',TRUE,TRUE,TRUE)"
        ))
        .execute(&mut *tx)
        .await?;
        if seed_roots {
            sqlx::query(&format!(
                "INSERT INTO {schema}.records \
                 (id, record_type, kind, name, home_id, policy_anchor_id, persistence, created_at, updated_at) VALUES \
                 ($1, 'Collection', 'folder', $4, NULL, $1, 'enduring', $3::timestamptz, $3::timestamptz),\
                 ($2, 'Collection', 'folder', 'Unfiled', $1, $1, 'enduring', $3::timestamptz, $3::timestamptz)"
            ))
            .bind(ROOT_RECORD_ID)
            .bind(UNFILED_RECORD_ID)
            .bind(SEEDED_RECORD_TIMESTAMP)
            // Postgres genesis has no account email in hand, so the workspace
            // takes the neutral default name.
            .bind(DEFAULT_WORKSPACE_NAME)
            .execute(&mut *tx)
            .await?;
            sqlx::query(&format!(
                "INSERT INTO {schema}.record_policies(record_id) VALUES($1)"
            ))
            .bind(ROOT_RECORD_ID)
            .execute(&mut *tx)
            .await?;
            sqlx::query(&format!(
                "INSERT INTO {schema}.policy_entries(policy_anchor_id,subject_kind,subject_id,effect,capability) VALUES($1,'members','native:members','allow','edit')"
            ))
            .bind(ROOT_RECORD_ID)
            .execute(&mut *tx)
            .await?;
            seed_governed_vocabularies(&mut tx, &schema).await?;
        }
        sqlx::query(&format!(
            "INSERT INTO {schema}.schema_migrations(version) VALUES($1)"
        ))
        .bind(SCHEMA_VERSION)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        self.complete_realtime_commit();
        Ok(())
    }

    async fn migrate_v4_to_v5(&self) -> Result<()> {
        let schema = quote_identifier(&self.schema)?;
        let migrations = self.qualified_table("schema_migrations")?;
        let mut tx = self.pool.begin().await?;
        let observed: Option<i32> = sqlx::query_scalar(&format!(
            "SELECT version FROM {migrations} ORDER BY version DESC LIMIT 1 FOR UPDATE"
        ))
        .fetch_optional(&mut *tx)
        .await?;
        if observed != Some(4) {
            return Err(Error::engine(
                "Postgres schema v4-to-v5 migration requires exact source version 4",
            ));
        }
        for statement in postgres_v5_schema(&schema) {
            tx.execute(statement.as_str()).await?;
        }
        sqlx::query(&format!("INSERT INTO {migrations}(version) VALUES(5)"))
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        self.complete_realtime_commit();
        Ok(())
    }

    async fn migrate_v5_to_v6(&self) -> Result<()> {
        let schema = quote_identifier(&self.schema)?;
        let migrations = self.qualified_table("schema_migrations")?;
        let mut tx = self.pool.begin().await?;
        let observed: Option<i32> = sqlx::query_scalar(&format!(
            "SELECT version FROM {migrations} ORDER BY version DESC LIMIT 1 FOR UPDATE"
        ))
        .fetch_optional(&mut *tx)
        .await?;
        if observed != Some(5) {
            return Err(Error::engine(
                "Postgres schema v5-to-v6 migration requires exact source version 5",
            ));
        }
        for statement in postgres_v6_schema(&schema) {
            tx.execute(statement.as_str()).await?;
        }
        sqlx::query(&format!("INSERT INTO {migrations}(version) VALUES(6)"))
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        self.complete_realtime_commit();
        Ok(())
    }

    pub async fn drop_schema(&self) -> Result<()> {
        self.query_pool.close().await;
        let schema = quote_identifier(&self.schema)?;
        // A sandbox session that just cancelled a statement-timeout canary may
        // still be rolling back its temp state; that rollback and the cascade
        // both take AccessExclusiveLocks, so a deadlock (40P01) here only means
        // "try again once the rollback finishes".
        let mut attempts = 0;
        loop {
            let result = self
                .pool
                .execute(format!("DROP SCHEMA IF EXISTS {schema} CASCADE").as_str())
                .await;
            match result {
                Ok(_) => break,
                Err(error) => {
                    let deadlock = error
                        .as_database_error()
                        .and_then(|db| db.code())
                        .is_some_and(|code| code == "40P01");
                    attempts += 1;
                    if !deadlock || attempts >= 5 {
                        return Err(error.into());
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(200 * attempts)).await;
                }
            }
        }
        let query_role = quote_identifier(&self.query_role)?;
        self.pool
            .execute(format!("DROP OWNED BY {query_role}").as_str())
            .await?;
        self.pool
            .execute(format!("DROP ROLE IF EXISTS {query_role}").as_str())
            .await?;
        Ok(())
    }

    async fn ensure_contract_query_role(&self) -> Result<()> {
        let mut connection = self.pool.acquire().await?;
        sqlx::query("SELECT set_config('native_ce.query_role', $1, false)")
            .bind(&self.query_role)
            .execute(&mut *connection)
            .await?;
        sqlx::query(
            "DO $native$ DECLARE query_role text := current_setting('native_ce.query_role'); member_role text := current_user; BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=query_role) THEN EXECUTE format('CREATE ROLE %I', query_role); END IF; EXECUTE format('ALTER ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS', query_role); EXECUTE format('GRANT %I TO %I WITH ADMIN FALSE, INHERIT FALSE, SET TRUE', query_role, member_role); END $native$",
        )
        .execute(&mut *connection)
        .await?;
        Ok(())
    }

    pub async fn provision_member(
        &self,
        person_id: &str,
        account_id: &str,
        principal_id: &str,
    ) -> Result<()> {
        for (label, value) in [
            ("person record id", person_id),
            ("account identifier", account_id),
            ("principal identifier", principal_id),
        ] {
            if value.trim().is_empty() || value != value.trim() {
                return Err(Error::engine(format!(
                    "Postgres member {label} must be nonblank and normalized"
                )));
            }
        }
        let bindings = self.qualified_table("bindings")?;
        let records = self.qualified_table("records")?;
        let systems = self.qualified_table("binding_systems")?;
        let audit = self.qualified_table("binding_audit")?;
        let revision = self.qualified_table("authorization_revision")?;
        let mut tx = self.pool.begin().await?;
        let record: (String, String) = sqlx::query_as(&format!(
            "SELECT record_type,kind FROM {records} WHERE id=$1 AND deleted_at IS NULL FOR UPDATE"
        ))
        .bind(person_id)
        .fetch_one(&mut *tx)
        .await?;
        let compatible: bool = sqlx::query_scalar(&format!(
            "SELECT COUNT(*)=2 FROM {systems} WHERE system IN ('account','native-principal') AND (compatible_type IS NULL OR compatible_type=$1) AND (compatible_kind IS NULL OR compatible_kind=$2)"
        ))
        .bind(&record.0)
        .bind(&record.1)
        .fetch_one(&mut *tx)
        .await?;
        if !compatible {
            return Err(Error::engine(
                "Postgres member bindings require a compatible Entity/person record",
            ));
        }
        sqlx::query(&format!(
            "INSERT INTO {bindings}(record_id, system, identifier, is_canonical) \
             VALUES($1, 'account', $2, TRUE), ($1, 'native-principal', $3, TRUE)"
        ))
        .bind(person_id)
        .bind(account_id)
        .bind(principal_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "SELECT pg_advisory_xact_lock(hashtextextended('native-ce:binding-audit-sequence', 0))",
        )
        .execute(&mut *tx)
        .await?;
        for (system, identifier) in [("account", account_id), ("native-principal", principal_id)] {
            sqlx::query(&format!(
                "INSERT INTO {audit}(seq,id,action,system,identifier,new_record_id,new_canonical,actor,reason,created_at) \
                 VALUES((SELECT COALESCE(MAX(seq),0)+1 FROM {audit}),$1,'add',$2,$3,$4,TRUE,'native:provisioner','Provision member identity bindings.',transaction_timestamp())"
            ))
            .bind(Uuid::new_v4().to_string())
            .bind(system)
            .bind(identifier)
            .bind(person_id)
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query(&format!("UPDATE {revision} SET epoch=epoch+1 WHERE id=1"))
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        self.complete_realtime_commit();
        Ok(())
    }

    async fn import_validated(
        &self,
        interchange: &ValidatedInterchange,
    ) -> Result<PostgresImportReport> {
        let events_section = required_section(interchange, "content_events")?;
        let frontier_section = required_section(interchange, "content_event_causal_frontier")?;
        let cutover_section = required_section(interchange, "content_event_causal_cutover")?;
        let sources_section = required_section(interchange, "content_event_sources")?;
        let mut tx = self.pool.begin().await?;
        let events = self.qualified_table("content_events")?;
        let frontier = self.qualified_table("content_event_causal_frontier")?;
        let cutover = self.qualified_table("content_event_causal_cutover")?;
        let sources = self.qualified_table("content_event_sources")?;
        let cursor = self.qualified_table("event_cursor")?;
        let log_cursors = self.qualified_table("log_cursors")?;

        let existing: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {events}"))
            .fetch_one(&mut *tx)
            .await?;
        if existing != 0 {
            return Err(Error::engine(
                "Postgres canonical import requires a clean logical database",
            ));
        }

        if cutover_section.rows.len() != 1 {
            return Err(Error::engine(
                "Postgres canonical import requires exactly one causal cutover row",
            ));
        }
        let cutover_row = &cutover_section.rows[0];
        let last_legacy_local_seq = integer(cutover_section, cutover_row, "last_legacy_local_seq")?;
        let source_sequences = sources_section
            .rows
            .iter()
            .map(|row| {
                Ok((
                    text(sources_section, row, "event_id")?.to_string(),
                    integer(sources_section, row, "source_seq")?,
                ))
            })
            .collect::<Result<HashMap<_, _>>>()?;
        let mut frontier_by_event: HashMap<String, Vec<String>> = HashMap::new();
        for row in &frontier_section.rows {
            frontier_by_event
                .entry(text(frontier_section, row, "event_id")?.to_string())
                .or_default()
                .push(text(frontier_section, row, "parent_event_id")?.to_string());
        }
        if causal_frontier_has_cycle(&frontier_by_event) {
            return Err(Error::engine(
                "Postgres canonical import received a cyclic causal frontier",
            ));
        }

        let mut last_seq = 0_i64;
        for row in &events_section.rows {
            let seq = integer(events_section, row, "seq")?;
            let id = text(events_section, row, "id")?;
            let record_id = text(events_section, row, "record_id")?;
            let event_type = text(events_section, row, "type")?;
            let payload_text =
                optional_text_cell(events_section, row, "payload")?.ok_or_else(|| {
                    Error::engine("Postgres canonical import requires event payloads")
                })?;
            let payload: Value = serde_json::from_str(payload_text).map_err(|error| {
                Error::engine(format!("invalid canonical content event payload: {error}"))
            })?;
            let actor = optional_text_cell(events_section, row, "actor")?;
            let created_at = text(events_section, row, "created_at")?;
            let run_key = optional_text_cell(events_section, row, "run_key")?;
            let parent_key = optional_text_cell(events_section, row, "parent_key")?;
            let intent = optional_text_cell(events_section, row, "intent")?;
            let causal_envelope_version = integer(events_section, row, "causal_envelope_version")?;
            let causal_status = text(events_section, row, "causal_status")?;
            if causal_envelope_version != 1
                || !matches!(
                    causal_status,
                    "complete" | "import_incomplete" | "legacy_unknown"
                )
            {
                return Err(Error::engine(
                    "Postgres canonical import received an unsupported causal envelope",
                ));
            }
            let parents = frontier_by_event.get(id).map(Vec::as_slice).unwrap_or(&[]);
            let source_seq = source_sequences.get(id).copied();
            if (causal_status == "legacy_unknown"
                && (seq > last_legacy_local_seq || !parents.is_empty()))
                || (seq <= last_legacy_local_seq && causal_status != "legacy_unknown")
                || (seq > last_legacy_local_seq
                    && source_seq.is_none()
                    && causal_status != "complete")
                || (causal_status == "import_incomplete" && source_seq.is_none())
                || (causal_status == "complete"
                    && parents.is_empty()
                    && !((source_seq.is_none() && seq == 1) || source_seq == Some(1)))
            {
                return Err(Error::engine(
                    "Postgres canonical import received incoherent causal state",
                ));
            }
            if !matches!(
                event_type,
                "record.created"
                    | "record.updated"
                    | "record.type_corrected.v1"
                    | "facet.set"
                    | "facet.unset"
            ) {
                return Err(Error::engine(format!(
                    "unsupported Postgres canonical event type {event_type}"
                )));
            }
            sqlx::query(&format!(
                "INSERT INTO {events}(seq,id,record_id,type,payload,actor,run_key,parent_key,intent,created_at,causal_envelope_version,causal_status) \
                 VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9,$10::timestamptz,$11,$12)"
            ))
            .bind(seq)
            .bind(id)
            .bind(record_id)
            .bind(event_type)
            .bind(payload_text)
            .bind(actor)
            .bind(run_key)
            .bind(parent_key)
            .bind(intent)
            .bind(created_at)
            .bind(causal_envelope_version)
            .bind(causal_status)
            .execute(&mut *tx)
            .await?;
            apply_projection(self, &mut tx, record_id, event_type, &payload, created_at).await?;
            last_seq = last_seq.max(seq);
        }
        for row in &frontier_section.rows {
            sqlx::query(&format!(
                "INSERT INTO {frontier}(event_id,parent_event_id) VALUES($1,$2)"
            ))
            .bind(text(frontier_section, row, "event_id")?)
            .bind(text(frontier_section, row, "parent_event_id")?)
            .execute(&mut *tx)
            .await?;
        }
        for row in &sources_section.rows {
            sqlx::query(&format!(
                "INSERT INTO {sources}(event_id,origin_database_id,source_seq,source_record_id,source_principal,source_fingerprint) \
                 VALUES($1,$2,$3,$4,$5,$6)"
            ))
            .bind(text(sources_section, row, "event_id")?)
            .bind(text(sources_section, row, "origin_database_id")?)
            .bind(integer(sources_section, row, "source_seq")?)
            .bind(text(sources_section, row, "source_record_id")?)
            .bind(text(sources_section, row, "source_principal")?)
            .bind(text(sources_section, row, "source_fingerprint")?)
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query(&format!("DELETE FROM {cutover}"))
            .execute(&mut *tx)
            .await?;
        sqlx::query(&format!(
            "INSERT INTO {cutover}(singleton,last_legacy_local_seq,cutover_at,from_engine_schema) \
             VALUES($1,$2,$3::timestamptz,$4)"
        ))
        .bind(integer(cutover_section, cutover_row, "singleton")?)
        .bind(integer(
            cutover_section,
            cutover_row,
            "last_legacy_local_seq",
        )?)
        .bind(text(cutover_section, cutover_row, "cutover_at")?)
        .bind(optional_integer_cell(
            cutover_section,
            cutover_row,
            "from_engine_schema",
        )?)
        .execute(&mut *tx)
        .await?;
        sqlx::query(&format!(
            "UPDATE {cursor} SET last_seq=$1 WHERE singleton=TRUE"
        ))
        .bind(last_seq)
        .execute(&mut *tx)
        .await?;
        sqlx::query(&format!(
            "UPDATE {log_cursors} SET last_seq=$1 WHERE log_name='content'"
        ))
        .bind(last_seq)
        .execute(&mut *tx)
        .await?;

        // The policy lands after the events it must govern, mirroring the
        // SQLite importer's ordering: a strict policy becomes real only once
        // the state it pins is materialized, and an unusable pin fails the
        // import rather than arriving as a live policy nobody can satisfy.
        self.import_portability_policy(&mut tx, interchange).await?;

        let report = self.verify_on(&mut tx, interchange).await?;
        tx.commit().await?;
        self.complete_realtime_commit();
        self.assert_replay_equivalent().await?;
        Ok(report)
    }

    async fn import_portability_policy(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        interchange: &ValidatedInterchange,
    ) -> Result<()> {
        let Some((section, row)) = canonical_portability_policy(interchange)? else {
            return Ok(());
        };
        let columns = canonical_policy_columns(section, row)?;
        // Decode and validate before the row can gate a request: an unusable
        // pin fails the import instead of arriving as a live strict policy.
        let decoded = crate::storage_profile::decode_policy_columns(columns.clone())?;
        crate::storage_profile::validate_persisted_policy(
            &decoded,
            &crate::storage_profile::active_profile_authority(),
        )?;
        let table = self.qualified_table("storage_portability_policy")?;
        sqlx::query(&format!(
            "INSERT INTO {table}(singleton,policy_revision,enforcement,source_profile_id,source_profile_revision,source_mode,targets,revision_floors,allow_conversions,catalog_sha256,updated_at) \
             VALUES(1,$1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8::jsonb,$9,$10::timestamptz)"
        ))
        .bind(columns.policy_revision)
        .bind(&columns.enforcement)
        .bind(&columns.source_profile_id)
        .bind(columns.source_profile_revision)
        .bind(&columns.source_mode)
        .bind(&columns.targets)
        .bind(&columns.revision_floors)
        .bind(&columns.allow_conversions)
        .bind(&columns.catalog_sha256)
        .bind(text(section, row, "updated_at")?)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    /// Revalidate canonical bytes and compare every field materialized by the
    /// bounded Postgres slice. Missing, extra, and changed rows fail closed.
    pub async fn verify_canonical_interchange(
        &self,
        bytes: &[u8],
    ) -> Result<PostgresVerificationReport> {
        let interchange = validate_canonical_interchange(bytes)?;
        validate_postgres_admission(&interchange)?;
        let mut tx = self.pool.begin().await?;
        let report = self.verify_on(&mut tx, &interchange).await?;
        tx.rollback().await?;
        Ok(report)
    }

    async fn verify_on(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        interchange: &ValidatedInterchange,
    ) -> Result<PostgresVerificationReport> {
        let expected = expected_postgres_state(interchange)?;
        let actual = self.postgres_import_state(tx).await?;
        if expected != actual {
            return Err(Error::engine(
                "Postgres canonical verification detected missing, extra, or changed state",
            ));
        }
        let (source_profile_id, source_profile_revision) = interchange.source_profile();
        let unmaterialized_sections = interchange
            .sections()
            .iter()
            .filter(|section| {
                !matches!(
                    section.name.as_str(),
                    "content_events"
                        | "content_event_causal_frontier"
                        | "content_event_causal_cutover"
                        | "records"
                        | "facet_values"
                        | "storage_portability_policy"
                ) && !section.rows.is_empty()
            })
            .map(|section| UnmaterializedSection {
                name: section.name.clone(),
                row_count: section.rows.len() as u64,
            })
            .collect();
        Ok(PostgresVerificationReport {
            source_profile_id: source_profile_id.into(),
            source_profile_revision,
            verified_projection_coverage: vec![
                VerifiedProjectionCoverage {
                    section: "content_events".into(),
                    fields: [
                        "seq",
                        "id",
                        "record_id",
                        "type",
                        "payload",
                        "actor",
                        "causal_envelope_version",
                        "causal_status",
                        "created_at",
                    ]
                    .into_iter()
                    .map(String::from)
                    .collect(),
                },
                VerifiedProjectionCoverage {
                    section: "content_event_causal_frontier".into(),
                    fields: vec!["event_id".into(), "parent_event_id".into()],
                },
                VerifiedProjectionCoverage {
                    section: "content_event_causal_cutover".into(),
                    fields: vec![
                        "singleton".into(),
                        "last_legacy_local_seq".into(),
                        "cutover_at".into(),
                        "from_engine_schema".into(),
                    ],
                },
                VerifiedProjectionCoverage {
                    section: "records".into(),
                    fields: [
                        "id",
                        "type",
                        "kind",
                        "name",
                        "body",
                        "home_id",
                        "summary",
                        "lifecycle",
                        "owner_id",
                        "persistence",
                        "maturity",
                        "archived_from_facet_presence",
                        "deleted_at_presence",
                    ]
                    .into_iter()
                    .map(String::from)
                    .collect(),
                },
                VerifiedProjectionCoverage {
                    section: "facet_values".into(),
                    fields: ["record_id", "key", "value"]
                        .into_iter()
                        .map(String::from)
                        .collect(),
                },
                VerifiedProjectionCoverage {
                    section: "derived:event_cursor".into(),
                    fields: vec!["last_seq".into()],
                },
                VerifiedProjectionCoverage {
                    section: "storage_portability_policy".into(),
                    fields: [
                        "policy_revision",
                        "enforcement",
                        "source_profile_id",
                        "source_profile_revision",
                        "source_mode",
                        "targets",
                        "revision_floors",
                        "allow_conversions",
                        "catalog_sha256",
                    ]
                    .into_iter()
                    .map(String::from)
                    .collect(),
                },
            ],
            unmaterialized_sections,
            emulated_fields: vec![
                "event_cursor.last_seq rebuilt from canonical event positions and verified".into(),
                "content_events.created_at normalized to UTC microseconds and verified".into(),
                "content_events payload JSON text normalized through jsonb".into(),
                "records policy_anchor_id/last_activity_at/timestamps not materialized".into(),
                "facet_values id/vocab_ref/created_at not materialized".into(),
                "storage_portability_policy targets/revision_floors/allow_conversions normalized through jsonb and verified as parsed JSON".into(),
                "storage_portability_policy.updated_at normalized to timestamptz and not verified".into(),
            ],
            event_count: expected["events"]
                .as_array()
                .map_or(0, |rows| rows.len() as u64),
            record_count: expected["records"]
                .as_array()
                .map_or(0, |rows| rows.len() as u64),
            facet_count: expected["facets"]
                .as_array()
                .map_or(0, |rows| rows.len() as u64),
        })
    }

    async fn postgres_import_state(&self, tx: &mut Transaction<'_, Postgres>) -> Result<Value> {
        let events = self.qualified_table("content_events")?;
        let frontier = self.qualified_table("content_event_causal_frontier")?;
        let cutover = self.qualified_table("content_event_causal_cutover")?;
        let cursor = self.qualified_table("event_cursor")?;
        let records = self.qualified_table("records")?;
        let facets = self.qualified_table("facet_values")?;
        let event_rows = sqlx::query(&format!(
            "SELECT seq,id,record_id,type,payload::text AS payload,actor,run_key,parent_key,intent,causal_envelope_version,causal_status,\
                    (EXTRACT(EPOCH FROM created_at) * 1000000)::bigint AS created_at_micros \
             FROM {events} ORDER BY seq"
        ))
        .fetch_all(&mut **tx)
        .await?;
        let mut logical_events = Vec::new();
        for row in event_rows {
            logical_events.push(json!({
                "seq": row.try_get::<i64, _>("seq")?,
                "id": row.try_get::<String, _>("id")?,
                "record_id": row.try_get::<String, _>("record_id")?,
                "type": row.try_get::<String, _>("type")?,
                "payload": serde_json::from_str::<Value>(&row.try_get::<String, _>("payload")?)?,
                "actor": row.try_get::<Option<String>, _>("actor")?,
                "run_key": row.try_get::<Option<String>, _>("run_key")?,
                "parent_key": row.try_get::<Option<String>, _>("parent_key")?,
                "intent": row.try_get::<Option<String>, _>("intent")?,
                "causal_envelope_version": row.try_get::<i64, _>("causal_envelope_version")?,
                "causal_status": row.try_get::<String, _>("causal_status")?,
                "created_at_micros": row.try_get::<i64, _>("created_at_micros")?,
            }));
        }
        let logical_frontier = sqlx::query(&format!(
            "SELECT event_id,parent_event_id FROM {frontier} ORDER BY event_id COLLATE \"C\",parent_event_id COLLATE \"C\""
        ))
        .fetch_all(&mut **tx)
        .await?
        .into_iter()
        .map(|row| {
            Ok(json!({
                "event_id":row.try_get::<String,_>("event_id")?,
                "parent_event_id":row.try_get::<String,_>("parent_event_id")?,
            }))
        })
        .collect::<Result<Vec<_>>>()?;
        let cutover_row = sqlx::query(&format!(
            "SELECT singleton,last_legacy_local_seq,(EXTRACT(EPOCH FROM cutover_at)*1000000)::bigint AS cutover_at_micros,from_engine_schema FROM {cutover}"
        ))
        .fetch_one(&mut **tx)
        .await?;
        let logical_cutover = json!({
            "singleton":i64::from(cutover_row.try_get::<i16,_>("singleton")?),
            "last_legacy_local_seq":cutover_row.try_get::<i64,_>("last_legacy_local_seq")?,
            "cutover_at_micros":cutover_row.try_get::<i64,_>("cutover_at_micros")?,
            "from_engine_schema":cutover_row.try_get::<Option<i32>,_>("from_engine_schema")?,
        });
        let cursor_last_seq: i64 = sqlx::query_scalar(&format!(
            "SELECT last_seq FROM {cursor} WHERE singleton=TRUE"
        ))
        .fetch_one(&mut **tx)
        .await?;
        let record_rows = sqlx::query(&format!(
            "SELECT id,record_type,kind,name,body,home_id,summary,lifecycle,owner_id,persistence,maturity,archived,deleted_at IS NOT NULL AS deleted \
             FROM {records} ORDER BY id COLLATE \"C\""
        ))
        .fetch_all(&mut **tx)
        .await?;
        let mut logical_records = Vec::new();
        for row in record_rows {
            logical_records.push(json!({
                "id": row.try_get::<String, _>("id")?,
                "type": row.try_get::<String, _>("record_type")?,
                "kind": row.try_get::<String, _>("kind")?,
                "name": row.try_get::<Option<String>, _>("name")?,
                "body": row.try_get::<Option<String>, _>("body")?,
                "home_id": row.try_get::<Option<String>, _>("home_id")?,
                "summary": row.try_get::<Option<String>, _>("summary")?,
                "lifecycle": row.try_get::<Option<String>, _>("lifecycle")?,
                "owner_id": row.try_get::<Option<String>, _>("owner_id")?,
                "persistence": row.try_get::<String, _>("persistence")?,
                "maturity": row.try_get::<Option<String>, _>("maturity")?,
                "archived": row.try_get::<bool, _>("archived")?,
                "deleted": row.try_get::<bool, _>("deleted")?,
            }));
        }
        let facet_rows = sqlx::query(&format!(
            "SELECT record_id,key,value::text AS value FROM {facets} ORDER BY record_id COLLATE \"C\",key COLLATE \"C\""
        ))
        .fetch_all(&mut **tx)
        .await?;
        let mut logical_facets = Vec::new();
        for row in facet_rows {
            logical_facets.push(json!({
                "record_id": row.try_get::<String, _>("record_id")?,
                "key": row.try_get::<String, _>("key")?,
                "value": serde_json::from_str::<Value>(&row.try_get::<String, _>("value")?)?,
            }));
        }
        let portability_policy = match self.load_portability_policy_columns(tx).await? {
            Some(columns) => policy_logical_projection(&columns)?,
            None => Value::Null,
        };
        Ok(json!({
            "cursor_last_seq": cursor_last_seq,
            "events": logical_events,
            "causal_frontier": logical_frontier,
            "causal_cutover": logical_cutover,
            "records": logical_records,
            "facets": logical_facets,
            "portability_policy": portability_policy
        }))
    }

    async fn load_portability_policy_columns(
        &self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<Option<crate::storage_profile::PortabilityPolicyColumns>> {
        let table = self.qualified_table("storage_portability_policy")?;
        sqlx::query(&format!(
            "SELECT {POLICY_COLUMN_PROJECTION} FROM {table} WHERE singleton=1"
        ))
        .fetch_optional(&mut **tx)
        .await?
        .as_ref()
        .map(policy_columns_from_row)
        .transpose()
    }

    pub async fn assert_replay_equivalent(&self) -> Result<()> {
        // Capture the complete authoritative input and its live projection in
        // one database snapshot. Rebuilding may take arbitrarily long, so the
        // read transaction is released once those immutable inputs are in
        // memory; concurrent commits belong wholly before or after the proof.
        let mut source_tx = self.repeatable_read_snapshot().await?;
        let live = self
            .authoritative_projection_snapshot_on(&mut source_tx)
            .await?;
        let captured_log = |kind: PostgresLogKind| -> Result<Vec<PostgresAuthoritativeEvent>> {
            serde_json::from_value(live["logs"][kind.as_str()].clone()).map_err(Into::into)
        };
        let content_events = captured_log(PostgresLogKind::Content)?;
        let meta_events = captured_log(PostgresLogKind::Meta)?;
        let policy_events = captured_log(PostgresLogKind::Policy)?;
        let control_events = captured_log(PostgresLogKind::Control)?;
        let candidate_events: Vec<PostgresCandidateReplayEvent> =
            serde_json::from_value(live["adjunct_logs"]["notification_candidate_events"].clone())?;
        let binding_audit: Vec<PostgresBindingAuditEvent> =
            serde_json::from_value(live["identity"]["binding_audit"].clone())?;
        let source_events = self.qualified_table("content_events")?;
        let source_frontier = self.qualified_table("content_event_causal_frontier")?;
        let source_cutover = self.qualified_table("content_event_causal_cutover")?;
        let content_causality: HashMap<String, (i64, String)> = sqlx::query(&format!(
            "SELECT id,causal_envelope_version,causal_status FROM {source_events}"
        ))
        .fetch_all(&mut *source_tx)
        .await?
        .into_iter()
        .map(|row| {
            Ok((
                row.try_get::<String, _>("id")?,
                (
                    row.try_get::<i64, _>("causal_envelope_version")?,
                    row.try_get::<String, _>("causal_status")?,
                ),
            ))
        })
        .collect::<Result<_>>()?;
        let content_frontier: Vec<(String, String)> = sqlx::query_as(&format!(
            "SELECT event_id,parent_event_id FROM {source_frontier} ORDER BY event_id,parent_event_id"
        ))
        .fetch_all(&mut *source_tx)
        .await?;
        let content_cutover: (i16, i64, DateTime<Utc>, Option<i32>) = sqlx::query_as(&format!(
            "SELECT singleton,last_legacy_local_seq,cutover_at,from_engine_schema FROM {source_cutover}"
        ))
        .fetch_one(&mut *source_tx)
        .await?;
        source_tx.commit().await?;

        let scratch = match self.schema_tag.as_deref() {
            Some(tag) => format!("native_replay_{tag}_{}", Uuid::new_v4().simple()),
            None => format!("native_replay_{}", Uuid::new_v4().simple()),
        };
        let quoted = quote_identifier(&scratch)?;
        self.pool
            .execute(format!("CREATE SCHEMA {quoted}").as_str())
            .await?;
        let query_role = query_role_for_schema(&scratch)?;
        let query_pool = PgPoolOptions::new()
            .min_connections(0)
            .max_connections(4)
            .after_release(|connection, _metadata| {
                Box::pin(async move {
                    sqlx::query("DISCARD ALL").execute(connection).await?;
                    Ok(false)
                })
            })
            .connect_with(self.pool.connect_options().as_ref().clone())
            .await?;
        let rebuilt = PostgresDb {
            pool: self.pool.clone(),
            query_pool,
            query_role,
            schema: scratch,
            schema_tag: self.schema_tag.clone(),
            runtime: None,
            portability_policy_gate: Arc::new(tokio::sync::RwLock::new(())),
            realtime_hub: Arc::new(PostgresRealtimeHub::new()),
            #[cfg(feature = "postgres-tests")]
            intent_persist_checkpoint: Arc::new(PostgresIntentPersistCheckpoint::default()),
            #[cfg(test)]
            request_lifecycle_test_bypass: false,
        };
        let result = async {
            let has_imported_roots = content_events.iter().any(|event| {
                event.subject_id == ROOT_RECORD_ID && event.event_type == "record.created"
            });
            rebuilt.migrate(!has_imported_roots).await?;
            let rebuilt_events = rebuilt.qualified_table("content_events")?;
            let rebuilt_frontier = rebuilt.qualified_table("content_event_causal_frontier")?;
            let rebuilt_cutover = rebuilt.qualified_table("content_event_causal_cutover")?;
            let rebuilt_cursor = rebuilt.qualified_table("event_cursor")?;
            let rebuilt_log_cursors = rebuilt.qualified_table("log_cursors")?;
            let mut tx = rebuilt.pool.begin().await?;
            let mut content_high_water = 0_i64;
            for event in content_events {
                let payload = event.payload.unwrap_or(Value::Null);
                let (causal_version, causal_status) = content_causality
                    .get(&event.id)
                    .ok_or_else(|| Error::engine("Postgres replay lost content causality"))?;
                sqlx::query(&format!(
                    "INSERT INTO {rebuilt_events}(seq,id,record_id,type,payload,actor,run_key,parent_key,intent,created_at,causal_envelope_version,causal_status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::timestamptz,$11,$12)"
                ))
                .bind(event.seq)
                .bind(event.id)
                .bind(&event.subject_id)
                .bind(&event.event_type)
                .bind(&payload)
                .bind(event.actor)
                .bind(event.run_key)
                .bind(event.parent_key)
                .bind(event.intent)
                .bind(&event.created_at)
                .bind(causal_version)
                .bind(causal_status)
                .execute(&mut *tx)
                .await?;
                apply_projection(
                    &rebuilt,
                    &mut tx,
                    &event.subject_id,
                    &event.event_type,
                    &payload,
                    &event.created_at,
                )
                .await?;
                content_high_water = event.seq;
            }
            for (event_id, parent_event_id) in content_frontier {
                sqlx::query(&format!(
                    "INSERT INTO {rebuilt_frontier}(event_id,parent_event_id) VALUES($1,$2)"
                ))
                .bind(event_id)
                .bind(parent_event_id)
                .execute(&mut *tx)
                .await?;
            }
            sqlx::query(&format!("DELETE FROM {rebuilt_cutover}"))
                .execute(&mut *tx)
                .await?;
            sqlx::query(&format!(
                "INSERT INTO {rebuilt_cutover}(singleton,last_legacy_local_seq,cutover_at,from_engine_schema) VALUES($1,$2,$3,$4)"
            ))
            .bind(content_cutover.0)
            .bind(content_cutover.1)
            .bind(content_cutover.2)
            .bind(content_cutover.3)
            .execute(&mut *tx)
            .await?;
            sqlx::query(&format!("UPDATE {rebuilt_cursor} SET last_seq=$1 WHERE singleton=TRUE"))
                .bind(content_high_water)
                .execute(&mut *tx)
                .await?;
            sqlx::query(&format!("UPDATE {rebuilt_log_cursors} SET last_seq=$1 WHERE log_name='content'"))
                .bind(content_high_water)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;

            for event in meta_events {
                rebuilt
                    .append_meta_event(PostgresMetaEvent {
                        id: event.id,
                        subject_id: event.subject_id,
                        event_type: event.event_type,
                        payload: event.payload.unwrap_or(Value::Null),
                        actor: event.actor,
                        created_at: event.created_at,
                    })
                    .await?;
            }
            for event in policy_events {
                rebuilt
                    .append_policy_event(PostgresPolicyEvent {
                        id: event.id,
                        record_id: event.subject_id,
                        event_type: event.event_type,
                        payload: event.payload,
                        actor: event.actor.unwrap_or_default(),
                        reason: event.reason.unwrap_or_default(),
                        created_at: event.created_at,
                    })
                    .await?;
            }
            for event in control_events {
                rebuilt
                    .append_control_event(PostgresControlEvent {
                        id: event.id,
                        idempotency_key: event.idempotency_key.unwrap_or_default(),
                        event_type: event.event_type,
                        schema_version: event.schema_version.unwrap_or_default(),
                        aggregate_kind: event.aggregate_kind.unwrap_or_default(),
                        aggregate_id: event.subject_id,
                        actor: event.actor.unwrap_or_default(),
                        run_key: event.run_key,
                        reason: event.reason.unwrap_or_default(),
                        payload: event.payload.unwrap_or(Value::Null),
                        created_at: event.created_at,
                    })
                    .await?;
            }

            rebuilt.replay_candidate_events(&candidate_events).await?;
            let rebuilt_bindings = rebuilt.qualified_table("bindings")?;
            let rebuilt_binding_audit = rebuilt.qualified_table("binding_audit")?;
            let mut tx = rebuilt.pool.begin().await?;
            for event in binding_audit {
                match event.action.as_str() {
                    "add" => {
                        sqlx::query(&format!(
                            "INSERT INTO {rebuilt_bindings}(record_id,system,identifier,is_canonical) VALUES($1,$2,$3,$4)"
                        ))
                        .bind(event.new_record_id.as_deref().ok_or_else(|| {
                            Error::engine("binding add audit is missing its new record")
                        })?)
                        .bind(&event.system)
                        .bind(&event.identifier)
                        .bind(event.new_canonical.ok_or_else(|| {
                            Error::engine("binding add audit is missing canonical state")
                        })?)
                        .execute(&mut *tx)
                        .await?;
                    }
                    "remove" => {
                        sqlx::query(&format!(
                            "DELETE FROM {rebuilt_bindings} WHERE record_id=$1 AND system=$2 AND identifier=$3"
                        ))
                        .bind(event.old_record_id.as_deref().ok_or_else(|| {
                            Error::engine("binding remove audit is missing its old record")
                        })?)
                        .bind(&event.system)
                        .bind(&event.identifier)
                        .execute(&mut *tx)
                        .await?;
                    }
                    "canonicalize" => {
                        sqlx::query(&format!(
                            "UPDATE {rebuilt_bindings} SET is_canonical=$1 WHERE record_id=$2 AND system=$3 AND identifier=$4"
                        ))
                        .bind(event.new_canonical.ok_or_else(|| {
                            Error::engine(
                                "binding canonicalize audit is missing its new canonical state",
                            )
                        })?)
                        .bind(event.new_record_id.as_deref().ok_or_else(|| {
                            Error::engine("binding canonicalize audit is missing its record")
                        })?)
                        .bind(&event.system)
                        .bind(&event.identifier)
                        .execute(&mut *tx)
                        .await?;
                    }
                    "transfer" => {
                        sqlx::query(&format!(
                            "UPDATE {rebuilt_bindings} SET record_id=$1 WHERE record_id=$2 AND system=$3 AND identifier=$4"
                        ))
                        .bind(event.new_record_id.as_deref().ok_or_else(|| {
                            Error::engine("binding transfer audit is missing its new record")
                        })?)
                        .bind(event.old_record_id.as_deref().ok_or_else(|| {
                            Error::engine("binding transfer audit is missing its old record")
                        })?)
                        .bind(&event.system)
                        .bind(&event.identifier)
                        .execute(&mut *tx)
                        .await?;
                    }
                    action => {
                        return Err(Error::engine(format!(
                            "binding replay encountered unknown audit action '{action}'"
                        )));
                    }
                }
                sqlx::query(&format!(
                    "INSERT INTO {rebuilt_binding_audit}(seq,id,action,system,identifier,old_record_id,new_record_id,old_canonical,new_canonical,actor,reason,run_key,parent_key,intent,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)"
                ))
                .bind(event.seq)
                .bind(event.id)
                .bind(event.action)
                .bind(event.system)
                .bind(event.identifier)
                .bind(event.old_record_id)
                .bind(event.new_record_id)
                .bind(event.old_canonical)
                .bind(event.new_canonical)
                .bind(event.actor)
                .bind(event.reason)
                .bind(event.run_key)
                .bind(event.parent_key)
                .bind(event.intent)
                .bind(event.created_at)
                .execute(&mut *tx)
                .await?;
            }
            tx.commit().await?;

            let replayed = rebuilt.authoritative_projection_snapshot().await?;
            if live != replayed {
                return Err(Error::engine(format!(
                    "authoritative replay diverged from logical logs/projections: live={live} replayed={replayed}"
                )));
            }
            Ok(())
        }
        .await;
        let cleanup = rebuilt.drop_schema().await;
        match (result, cleanup) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) => Err(error),
            (Ok(()), Err(cleanup)) => Err(cleanup),
            (Err(error), Err(cleanup)) => Err(Error::engine(format!(
                "{error}; additionally failed to clean up Postgres replay schema {}: {cleanup}",
                rebuilt.schema()
            ))),
        }
    }

    async fn replay_candidate_events(&self, events: &[PostgresCandidateReplayEvent]) -> Result<()> {
        let event_table = self.qualified_table("notification_candidate_events")?;
        let candidate_table = self.qualified_table("notification_candidates")?;
        let mut tx = self.pool.begin().await?;
        for event in events {
            sqlx::query(&format!(
                "INSERT INTO {event_table}(seq,id,candidate_key,action,recipient_account_id,message_id,reason,priority,not_before,redaction_class,evaluator_kind,policy_version,source_event_type,source_event_id,payload,created_at) OVERRIDING SYSTEM VALUE VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::timestamptz,$10,$11,$12,$13,$14,$15,$16::timestamptz)"
            ))
            .bind(event.seq)
            .bind(&event.id)
            .bind(&event.candidate_key)
            .bind(&event.action)
            .bind(&event.recipient_account_id)
            .bind(&event.message_id)
            .bind(&event.reason)
            .bind(&event.priority)
            .bind(&event.not_before)
            .bind(&event.redaction_class)
            .bind(&event.evaluator_kind)
            .bind(&event.policy_version)
            .bind(&event.source_event_type)
            .bind(&event.source_event_id)
            .bind(&event.payload)
            .bind(&event.created_at)
            .execute(&mut *tx)
            .await?;
            if event.action == "proposed" {
                sqlx::query(&format!(
                    "INSERT INTO {candidate_table}(candidate_id,candidate_key,recipient_account_id,message_id,reason,priority,not_before,redaction_class,evaluator_kind,policy_version,source_event_type,source_event_id,candidate_event_seq,status,created_at) VALUES($1,$2,$3,$4,$5,$6,$7::timestamptz,$8,$9,$10,$11,$12,$13,'effective',$14::timestamptz)"
                ))
                .bind(&event.id)
                .bind(&event.candidate_key)
                .bind(&event.recipient_account_id)
                .bind(&event.message_id)
                .bind(&event.reason)
                .bind(&event.priority)
                .bind(&event.not_before)
                .bind(&event.redaction_class)
                .bind(&event.evaluator_kind)
                .bind(&event.policy_version)
                .bind(&event.source_event_type)
                .bind(&event.source_event_id)
                .bind(event.seq)
                .bind(&event.created_at)
                .execute(&mut *tx)
                .await?;
            } else {
                let status = match event.action.as_str() {
                    "suppressed" => "suppressed",
                    "withdrawn" => "withdrawn",
                    action => {
                        return Err(Error::engine(format!(
                            "unknown notification candidate replay action: {action}"
                        )))
                    }
                };
                let updated = sqlx::query(&format!(
                    "UPDATE {candidate_table} SET status=$1,candidate_event_seq=$2 WHERE candidate_key=$3"
                ))
                .bind(status)
                .bind(event.seq)
                .bind(&event.candidate_key)
                .execute(&mut *tx)
                .await?;
                if updated.rows_affected() != 1 {
                    return Err(Error::engine(format!(
                        "notification candidate replay action {} has no prior proposal for {}",
                        event.action, event.candidate_key
                    )));
                }
            }
        }
        tx.commit().await?;
        self.complete_realtime_commit();
        Ok(())
    }

    async fn canonical_state_on(&self, tx: &mut Transaction<'_, Postgres>) -> Result<Value> {
        let records = self.qualified_table("records")?;
        let facets = self.qualified_table("facet_values")?;
        let audience = self.qualified_table("message_audience")?;
        let record_rows = sqlx::query(&format!(
            "SELECT id, record_type, kind, name, body, home_id, summary, lifecycle, owner_id, \
                    persistence, maturity, archived, deleted_at IS NOT NULL AS deleted, \
                    created_at, updated_at \
             FROM {records} ORDER BY id COLLATE \"C\""
        ))
        .fetch_all(&mut **tx)
        .await?;
        let mut logical_records = Vec::new();
        for row in record_rows {
            logical_records.push(json!({
                "id": row.try_get::<String, _>("id")?,
                "type": row.try_get::<String, _>("record_type")?,
                "kind": row.try_get::<String, _>("kind")?,
                "name": row.try_get::<Option<String>, _>("name")?,
                "body": row.try_get::<Option<String>, _>("body")?,
                "home_id": row.try_get::<Option<String>, _>("home_id")?,
                "summary": row.try_get::<Option<String>, _>("summary")?,
                "lifecycle": row.try_get::<Option<String>, _>("lifecycle")?,
                "owner_id": row.try_get::<Option<String>, _>("owner_id")?,
                "persistence": row.try_get::<String, _>("persistence")?,
                "maturity": row.try_get::<Option<String>, _>("maturity")?,
                "archived": row.try_get::<bool, _>("archived")?,
                "deleted": row.try_get::<bool, _>("deleted")?,
                "created_at": row.try_get::<DateTime<Utc>, _>("created_at")?
                    .to_rfc3339_opts(SecondsFormat::AutoSi, true),
                "updated_at": row.try_get::<DateTime<Utc>, _>("updated_at")?
                    .to_rfc3339_opts(SecondsFormat::AutoSi, true),
            }));
        }
        let facet_rows = sqlx::query(&format!(
            "SELECT record_id, key, value::text AS value FROM {facets} \
             ORDER BY record_id COLLATE \"C\", key COLLATE \"C\""
        ))
        .fetch_all(&mut **tx)
        .await?;
        let mut logical_facets = Vec::new();
        for row in facet_rows {
            let value: Value = serde_json::from_str(&row.try_get::<String, _>("value")?)?;
            logical_facets.push(json!({
                "record_id": row.try_get::<String, _>("record_id")?,
                "key": row.try_get::<String, _>("key")?,
                "value": value,
            }));
        }
        let audience_rows = sqlx::query(&format!(
            "SELECT message_id, account_id FROM {audience} \
             ORDER BY message_id COLLATE \"C\", account_id COLLATE \"C\""
        ))
        .fetch_all(&mut **tx)
        .await?;
        let logical_audience = audience_rows
            .into_iter()
            .map(|row| {
                Ok(json!({
                    "message_id": row.try_get::<String, _>("message_id")?,
                    "account_id": row.try_get::<String, _>("account_id")?,
                }))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(json!({
            "records": logical_records,
            "facets": logical_facets,
            "message_audience": logical_audience,
        }))
    }
}

fn validate_postgres_admission(interchange: &ValidatedInterchange) -> Result<()> {
    let events = required_section(interchange, "content_events")?;
    for (index, row) in events.rows.iter().enumerate() {
        let expected = index as i64 + 1;
        let actual = integer(events, row, "seq")?;
        if actual != expected {
            return Err(Error::engine(format!(
                "Postgres canonical import requires gapless content event positions in canonical order: expected seq {expected}, found {actual}"
            )));
        }
    }
    let records = required_section(interchange, "records")?;
    for row in &records.rows {
        let record_type = text(records, row, "type")?;
        let kind = optional_text_cell(records, row, "kind")?.unwrap_or("");
        if record_type == "Annotation" || (record_type == "Document" && kind == "attachment") {
            return Err(Error::engine(format!(
                "Postgres canonical import does not admit derived record {} ({record_type}/{kind}) without bearer authorization support",
                text(records, row, "id")?
            )));
        }
    }
    Ok(())
}

fn validate_schema_tag(tag: &str) -> Result<()> {
    if tag.is_empty()
        || tag.len() > 10
        || !tag
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(Error::engine("invalid Postgres import schema tag"));
    }
    Ok(())
}

/// The verified policy columns, projected as the shared decoder expects them.
/// `jsonb::text` is used because the decoder parses JSON text on every backend;
/// only the parsed values are ever compared, so key normalization is inert.
const POLICY_COLUMN_PROJECTION: &str = "policy_revision,enforcement,source_profile_id,source_profile_revision,source_mode,targets::text AS targets,revision_floors::text AS revision_floors,allow_conversions::text AS allow_conversions,catalog_sha256";

fn policy_columns_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<crate::storage_profile::PortabilityPolicyColumns> {
    Ok(crate::storage_profile::PortabilityPolicyColumns {
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

/// The canonical portability-policy singleton carried by a bundle.
///
/// The section is always present in a canonical document and is empty when the
/// source database never set a policy. More than one row is not a policy: the
/// physical table is a singleton on every backend.
fn canonical_portability_policy(
    interchange: &ValidatedInterchange,
) -> Result<Option<(&Section, &[Cell])>> {
    let section = required_section(interchange, "storage_portability_policy")?;
    match section.rows.len() {
        0 => Ok(None),
        1 => Ok(Some((section, section.rows[0].as_slice()))),
        count => Err(Error::engine(format!(
            "canonical storage portability policy must be a singleton row, found {count}"
        ))),
    }
}

/// The policy columns this adapter materializes, in the shared decoder's shape.
/// `updated_at` is deliberately absent: it is written but not verified, because
/// the canonical text is normalized into `timestamptz` on the way in.
fn canonical_policy_columns(
    section: &Section,
    row: &[Cell],
) -> Result<crate::storage_profile::PortabilityPolicyColumns> {
    Ok(crate::storage_profile::PortabilityPolicyColumns {
        policy_revision: integer(section, row, "policy_revision")?,
        enforcement: text(section, row, "enforcement")?.into(),
        source_profile_id: text(section, row, "source_profile_id")?.into(),
        source_profile_revision: integer(section, row, "source_profile_revision")?,
        source_mode: text(section, row, "source_mode")?.into(),
        targets: text(section, row, "targets")?.into(),
        revision_floors: text(section, row, "revision_floors")?.into(),
        allow_conversions: text(section, row, "allow_conversions")?.into(),
        catalog_sha256: text(section, row, "catalog_sha256")?.into(),
    })
}

fn policy_logical_projection(
    columns: &crate::storage_profile::PortabilityPolicyColumns,
) -> Result<Value> {
    Ok(json!({
        "policy_revision": columns.policy_revision,
        "enforcement": columns.enforcement,
        "source_profile_id": columns.source_profile_id,
        "source_profile_revision": columns.source_profile_revision,
        "source_mode": columns.source_mode,
        // Compared as parsed JSON so a jsonb round trip cannot look like drift.
        "targets": serde_json::from_str::<Value>(&columns.targets)?,
        "revision_floors": serde_json::from_str::<Value>(&columns.revision_floors)?,
        "allow_conversions": serde_json::from_str::<Value>(&columns.allow_conversions)?,
        "catalog_sha256": columns.catalog_sha256,
    }))
}

fn expected_portability_policy(interchange: &ValidatedInterchange) -> Result<Value> {
    let Some((section, row)) = canonical_portability_policy(interchange)? else {
        return Ok(Value::Null);
    };
    policy_logical_projection(&canonical_policy_columns(section, row)?)
}

fn causal_frontier_has_cycle(frontier: &HashMap<String, Vec<String>>) -> bool {
    fn visit(
        event_id: &str,
        frontier: &HashMap<String, Vec<String>>,
        visiting: &mut HashSet<String>,
        visited: &mut HashSet<String>,
    ) -> bool {
        if visited.contains(event_id) {
            return false;
        }
        if !visiting.insert(event_id.to_string()) {
            return true;
        }
        if frontier.get(event_id).is_some_and(|parents| {
            parents
                .iter()
                .any(|parent| visit(parent, frontier, visiting, visited))
        }) {
            return true;
        }
        visiting.remove(event_id);
        visited.insert(event_id.to_string());
        false
    }

    let mut visiting = HashSet::new();
    let mut visited = HashSet::new();
    frontier
        .keys()
        .any(|event_id| visit(event_id, frontier, &mut visiting, &mut visited))
}

fn required_section<'a>(interchange: &'a ValidatedInterchange, name: &str) -> Result<&'a Section> {
    interchange
        .section(name)
        .ok_or_else(|| Error::engine(format!("canonical interchange is missing section {name}")))
}

fn cell<'a>(section: &'a Section, row: &'a [Cell], column: &str) -> Result<&'a Cell> {
    let index = section
        .columns
        .iter()
        .position(|candidate| candidate.name == column)
        .ok_or_else(|| {
            Error::engine(format!(
                "canonical section {} is missing column {column}",
                section.name
            ))
        })?;
    row.get(index).ok_or_else(|| {
        Error::engine(format!(
            "canonical section {} contains a short row",
            section.name
        ))
    })
}

fn text<'a>(section: &'a Section, row: &'a [Cell], column: &str) -> Result<&'a str> {
    match cell(section, row, column)? {
        Cell::Text(value) => Ok(value),
        _ => Err(Error::engine(format!(
            "canonical section {} column {column} must be text",
            section.name
        ))),
    }
}

fn optional_text_cell<'a>(
    section: &'a Section,
    row: &'a [Cell],
    column: &str,
) -> Result<Option<&'a str>> {
    match cell(section, row, column)? {
        Cell::Null => Ok(None),
        Cell::Text(value) => Ok(Some(value)),
        _ => Err(Error::engine(format!(
            "canonical section {} column {column} must be text or null",
            section.name
        ))),
    }
}

fn integer(section: &Section, row: &[Cell], column: &str) -> Result<i64> {
    match cell(section, row, column)? {
        Cell::Integer(value) => Ok(*value),
        _ => Err(Error::engine(format!(
            "canonical section {} column {column} must be an integer",
            section.name
        ))),
    }
}

fn optional_integer_cell(section: &Section, row: &[Cell], column: &str) -> Result<Option<i64>> {
    match cell(section, row, column)? {
        Cell::Null => Ok(None),
        Cell::Integer(value) => Ok(Some(*value)),
        _ => Err(Error::engine(format!(
            "canonical section {} column {column} must be an integer or null",
            section.name
        ))),
    }
}

fn json_text_cell(section: &Section, row: &[Cell], column: &str) -> Result<Value> {
    match optional_text_cell(section, row, column)? {
        Some(value) => serde_json::from_str(value).map_err(|error| {
            Error::engine(format!(
                "canonical section {} column {column} contains invalid JSON: {error}",
                section.name
            ))
        }),
        None => Ok(Value::Null),
    }
}

fn timestamp_micros(section: &Section, row: &[Cell], column: &str) -> Result<i64> {
    let value = text(section, row, column)?;
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.timestamp_micros())
        .map_err(|error| {
            Error::engine(format!(
                "canonical section {} column {column} contains an invalid timestamp: {error}",
                section.name
            ))
        })
}

fn facet_value_cell(section: &Section, row: &[Cell]) -> Result<Value> {
    match cell(section, row, "value")? {
        Cell::Null => Ok(Value::Null),
        Cell::Text(value) => Ok(Value::String(value.clone())),
        _ => Err(Error::engine(format!(
            "canonical section {} column value must be text or null",
            section.name
        ))),
    }
}

fn expected_postgres_state(interchange: &ValidatedInterchange) -> Result<Value> {
    let events = required_section(interchange, "content_events")?;
    let frontier = required_section(interchange, "content_event_causal_frontier")?;
    let cutover = required_section(interchange, "content_event_causal_cutover")?;
    let records = required_section(interchange, "records")?;
    let facets = required_section(interchange, "facet_values")?;

    let mut logical_events = Vec::with_capacity(events.rows.len());
    for row in &events.rows {
        logical_events.push(json!({
            "seq": integer(events, row, "seq")?,
            "id": text(events, row, "id")?,
            "record_id": text(events, row, "record_id")?,
            "type": text(events, row, "type")?,
            "payload": json_text_cell(events, row, "payload")?,
            "actor": optional_text_cell(events, row, "actor")?,
            "run_key": optional_text_cell(events, row, "run_key")?,
            "parent_key": optional_text_cell(events, row, "parent_key")?,
            "intent": optional_text_cell(events, row, "intent")?,
            "causal_envelope_version": integer(events, row, "causal_envelope_version")?,
            "causal_status": text(events, row, "causal_status")?,
            "created_at_micros": timestamp_micros(events, row, "created_at")?,
        }));
    }
    let logical_frontier = frontier
        .rows
        .iter()
        .map(|row| {
            Ok(json!({
                "event_id":text(frontier,row,"event_id")?,
                "parent_event_id":text(frontier,row,"parent_event_id")?,
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    if cutover.rows.len() != 1 {
        return Err(Error::engine(
            "Postgres canonical verification requires exactly one causal cutover row",
        ));
    }
    let cutover_row = &cutover.rows[0];
    let logical_cutover = json!({
        "singleton":integer(cutover,cutover_row,"singleton")?,
        "last_legacy_local_seq":integer(cutover,cutover_row,"last_legacy_local_seq")?,
        "cutover_at_micros":timestamp_micros(cutover,cutover_row,"cutover_at")?,
        "from_engine_schema":optional_integer_cell(cutover,cutover_row,"from_engine_schema")?,
    });

    let mut archived = BTreeSet::new();
    let mut logical_facets = Vec::new();
    for row in &facets.rows {
        let record_id = text(facets, row, "record_id")?;
        let key = text(facets, row, "key")?;
        let value = facet_value_cell(facets, row)?;
        if key == "archived" {
            if value == Value::String("true".into()) {
                archived.insert(record_id.to_string());
            }
            continue;
        }
        logical_facets.push(json!({
            "record_id": record_id,
            "key": key,
            "value": value,
        }));
    }
    logical_facets.sort_by(|left, right| {
        (left["record_id"].as_str(), left["key"].as_str())
            .cmp(&(right["record_id"].as_str(), right["key"].as_str()))
    });

    let mut logical_records = Vec::with_capacity(records.rows.len());
    for row in &records.rows {
        let id = text(records, row, "id")?;
        let kind = optional_text_cell(records, row, "kind")?.ok_or_else(|| {
            Error::engine(format!(
                "Postgres canonical import requires a non-null kind for record {id}"
            ))
        })?;
        logical_records.push(json!({
            "id": id,
            "type": text(records, row, "type")?,
            "kind": kind,
            "name": optional_text_cell(records, row, "name")?,
            "body": optional_text_cell(records, row, "body")?,
            "home_id": optional_text_cell(records, row, "home_id")?,
            "summary": optional_text_cell(records, row, "summary")?,
            "lifecycle": optional_text_cell(records, row, "lifecycle")?,
            "owner_id": optional_text_cell(records, row, "owner_id")?,
            "persistence": text(records, row, "persistence")?,
            "maturity": optional_text_cell(records, row, "maturity")?,
            "archived": archived.contains(id),
            "deleted": optional_text_cell(records, row, "deleted_at")?.is_some(),
        }));
    }
    let cursor_last_seq = events
        .rows
        .iter()
        .map(|row| integer(events, row, "seq"))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .max()
        .unwrap_or(0);
    Ok(json!({
        "cursor_last_seq": cursor_last_seq,
        "events": logical_events,
        "causal_frontier":logical_frontier,
        "causal_cutover":logical_cutover,
        "records": logical_records,
        "facets": logical_facets,
        "portability_policy": expected_portability_policy(interchange)?
    }))
}

fn quote_identifier(identifier: &str) -> Result<String> {
    if identifier.is_empty()
        || !identifier
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(Error::engine("invalid generated Postgres identifier"));
    }
    Ok(format!("\"{identifier}\""))
}

fn query_role_for_schema(schema: &str) -> Result<String> {
    let candidate = format!("{schema}_query");
    let role = if candidate.len() <= 63 {
        candidate
    } else {
        let digest = hex::encode(Sha256::digest(schema.as_bytes()));
        format!("native_{}_query", &digest[..32])
    };
    quote_identifier(&role)?;
    Ok(role)
}

fn quote_operator_identifier(identifier: &str) -> Result<String> {
    if identifier.is_empty() || identifier.contains('\0') {
        return Err(Error::engine("invalid Postgres identifier"));
    }
    Ok(format!("\"{}\"", identifier.replace('"', "\"\"")))
}

fn normalize_postgres_contract_sql(sql: &str, schema: &str) -> String {
    sql.trim()
        .replace(&format!("\"{schema}\"."), "{{schema}}.")
        .replace(&format!("{schema}."), "{{schema}}.")
}

async fn postgres_complete_schema_contract(
    db: &PostgresDb,
    snapshot: &mut PostgresDomainTransaction<'_>,
    required_relations: &[&str],
) -> Result<(BTreeMap<String, Vec<Value>>, Vec<String>)> {
    let schema = &db.schema;
    let column_rows = sqlx::query(
        "SELECT relation.relname AS table_name,attribute.attname AS column_name, \
                pg_catalog.format_type(attribute.atttypid,attribute.atttypmod) AS physical_type, \
                attribute.attnotnull AS notnull,attribute.attnum AS ordinal_position, \
                pg_catalog.pg_get_expr(default_row.adbin,default_row.adrelid) AS default_expression, \
                attribute.attidentity::text AS identity_kind \
           FROM pg_catalog.pg_class relation \
           JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace \
           JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid=relation.oid \
           LEFT JOIN pg_catalog.pg_attrdef default_row ON default_row.adrelid=relation.oid AND default_row.adnum=attribute.attnum \
          WHERE namespace.nspname=$1 AND relation.relkind='r' \
            AND attribute.attnum>0 AND NOT attribute.attisdropped \
          ORDER BY relation.relname,attribute.attnum",
    )
    .bind(schema)
    .fetch_all(&mut **snapshot.admitted("describe postgres schema columns")?)
    .await?;
    let primary_keys = sqlx::query(
        "SELECT relation.relname AS table_name,attribute.attname AS column_name \
           FROM pg_catalog.pg_index index_row \
           JOIN pg_catalog.pg_class relation ON relation.oid=index_row.indrelid \
           JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace \
           JOIN pg_catalog.pg_attribute attribute ON attribute.attrelid=relation.oid AND attribute.attnum=ANY(index_row.indkey) \
          WHERE namespace.nspname=$1 AND index_row.indisprimary",
    )
    .bind(schema)
    .fetch_all(&mut **snapshot.admitted("describe postgres primary keys")?)
    .await?
    .into_iter()
    .map(|row| {
        Ok((
            row.try_get::<String, _>("table_name")?,
            row.try_get::<String, _>("column_name")?,
        ))
    })
    .collect::<Result<HashSet<_>>>()?;
    let allowlist = required_relations.iter().copied().collect::<HashSet<_>>();
    let mut response_columns: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    let mut ddl_columns: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for row in column_rows {
        let table: String = row.try_get("table_name")?;
        if !allowlist.contains(table.as_str()) {
            continue;
        }
        let name: String = row.try_get("column_name")?;
        let physical_type: String = row.try_get("physical_type")?;
        let notnull: bool = row.try_get("notnull")?;
        let default_expression: Option<String> = row.try_get("default_expression")?;
        let identity_kind: String = row.try_get("identity_kind")?;
        let pk = primary_keys.contains(&(table.clone(), name.clone()));
        response_columns
            .entry(table.clone())
            .or_default()
            .push(crate::schema::discovery::column(
                &table,
                name.clone(),
                physical_type.clone(),
                notnull,
                pk,
            ));
        let mut declaration = format!("{} {physical_type}", quote_identifier(&name)?);
        if identity_kind == "a" {
            declaration.push_str(" GENERATED ALWAYS AS IDENTITY");
        } else if identity_kind == "d" {
            declaration.push_str(" GENERATED BY DEFAULT AS IDENTITY");
        } else if let Some(default_expression) = default_expression {
            declaration.push_str(" DEFAULT ");
            declaration.push_str(&normalize_postgres_contract_sql(
                &default_expression,
                schema,
            ));
        }
        if notnull {
            declaration.push_str(" NOT NULL");
        }
        ddl_columns.entry(table).or_default().push(declaration);
    }
    for &table in required_relations {
        if !response_columns.contains_key(table) {
            return Err(Error::engine(format!(
                "describe_schema: required Postgres relation '{table}' is absent"
            )));
        }
    }

    let constraint_rows = sqlx::query(
        "SELECT relation.relname AS table_name,constraint_row.conname AS constraint_name, \
                pg_catalog.pg_get_constraintdef(constraint_row.oid,true) AS definition \
           FROM pg_catalog.pg_constraint constraint_row \
           JOIN pg_catalog.pg_class relation ON relation.oid=constraint_row.conrelid \
           JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace \
          WHERE namespace.nspname=$1 \
          ORDER BY relation.relname,constraint_row.contype,constraint_row.conname",
    )
    .bind(schema)
    .fetch_all(&mut **snapshot.admitted("describe postgres constraints")?)
    .await?;
    let mut ddl_constraints: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for row in constraint_rows {
        let table: String = row.try_get("table_name")?;
        if !allowlist.contains(table.as_str()) {
            continue;
        }
        let name: String = row.try_get("constraint_name")?;
        let definition: String = row.try_get("definition")?;
        ddl_constraints.entry(table).or_default().push(format!(
            "CONSTRAINT {} {}",
            quote_identifier(&name)?,
            normalize_postgres_contract_sql(&definition, schema)
        ));
    }

    let mut statements = Vec::new();
    for &table in required_relations {
        let mut declarations = ddl_columns.remove(table).expect("required columns checked");
        declarations.extend(ddl_constraints.remove(table).unwrap_or_default());
        statements.push(format!(
            "CREATE TABLE {{schema}}.{} ({})",
            quote_identifier(table)?,
            declarations.join(", ")
        ));
    }
    let index_rows = sqlx::query(
        "SELECT table_row.relname AS table_name,pg_catalog.pg_get_indexdef(index_row.indexrelid) AS definition \
           FROM pg_catalog.pg_index index_row \
           JOIN pg_catalog.pg_class table_row ON table_row.oid=index_row.indrelid \
           JOIN pg_catalog.pg_namespace namespace ON namespace.oid=table_row.relnamespace \
          WHERE namespace.nspname=$1 \
            AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint constraint_row WHERE constraint_row.conindid=index_row.indexrelid) \
          ORDER BY table_row.relname,index_row.indexrelid::regclass::text",
    )
    .bind(schema)
    .fetch_all(&mut **snapshot.admitted("describe postgres indexes")?)
    .await?;
    for row in index_rows {
        let table: String = row.try_get("table_name")?;
        if allowlist.contains(table.as_str()) {
            let definition: String = row.try_get("definition")?;
            statements.push(normalize_postgres_contract_sql(&definition, schema));
        }
    }
    let trigger_rows = sqlx::query(
        "SELECT relation.relname AS table_name,pg_catalog.pg_get_triggerdef(trigger_row.oid,true) AS definition \
           FROM pg_catalog.pg_trigger trigger_row \
           JOIN pg_catalog.pg_class relation ON relation.oid=trigger_row.tgrelid \
           JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace \
          WHERE namespace.nspname=$1 AND NOT trigger_row.tgisinternal \
          ORDER BY relation.relname,trigger_row.tgname",
    )
    .bind(schema)
    .fetch_all(&mut **snapshot.admitted("describe postgres triggers")?)
    .await?;
    for row in trigger_rows {
        let table: String = row.try_get("table_name")?;
        if allowlist.contains(table.as_str()) {
            let definition: String = row.try_get("definition")?;
            statements.push(normalize_postgres_contract_sql(&definition, schema));
        }
    }
    let function_definition: Option<String> = sqlx::query_scalar(
        "SELECT pg_catalog.pg_get_functiondef(procedure_row.oid) \
           FROM pg_catalog.pg_proc procedure_row \
           JOIN pg_catalog.pg_namespace namespace ON namespace.oid=procedure_row.pronamespace \
          WHERE namespace.nspname=$1 AND procedure_row.proname='reject_authoritative_event_mutation'",
    )
    .bind(schema)
    .fetch_optional(&mut **snapshot.admitted("describe postgres trigger function")?)
    .await?;
    if let Some(function_definition) = function_definition {
        statements.push(normalize_postgres_contract_sql(
            &function_definition,
            schema,
        ));
    }
    Ok((response_columns, statements))
}

async fn assert_postgres_v4_search_migration_source(db: &PostgresDb) -> Result<()> {
    let v4_relations = REQUIRED_RELATIONS
        .iter()
        .copied()
        .filter(|relation| {
            !matches!(
                *relation,
                "content_event_causal_frontier"
                    | "content_event_causal_cutover"
                    | "content_event_sources"
            )
        })
        .collect::<Vec<_>>();
    let mut snapshot = PostgresDomainTransaction::begin_snapshot(db).await?;
    let contract = postgres_complete_schema_contract(db, &mut snapshot, &v4_relations).await;
    let rollback = snapshot.rollback().await;
    rollback?;
    let (_, ddl) = contract.map_err(|_| {
        Error::engine("Postgres schema v4 search migration requires exact main-era v4 DDL")
    })?;
    let fingerprint = hex::encode(Sha256::digest(serde_json::to_vec(&ddl)?));
    if ddl.len() != POSTGRES_V4_DDL_COUNT || fingerprint != POSTGRES_V4_DDL_FINGERPRINT {
        return Err(Error::engine(
            "Postgres schema v4 search migration requires exact main-era v4 DDL",
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DescribeSchemaArguments {
    include_ddl: Option<bool>,
}

fn postgres_schema_table_visible(table: &str, caller: &Caller) -> bool {
    caller.is_host_owner()
        || !matches!(
            table,
            "schema_migrations"
                | "event_cursor"
                | "log_cursors"
                | "meta_events"
                | "policy_events"
                | "control_events"
                | "binding_systems"
                | "binding_audit"
                | "database_identity"
                | "database_identity_audit"
                | "record_policies"
                | "policy_entries"
                | "authorization_revision"
                | "control_projections"
                | "run_contexts"
                | "request_interactions"
                | "storage_portability_policy"
        )
}

async fn postgres_describe_schema(
    db: &PostgresDb,
    caller: &Caller,
    arguments: Value,
) -> Result<Value> {
    let args: DescribeSchemaArguments = parse("describe_schema", arguments)?;
    if args.include_ddl.unwrap_or(false) && !caller.is_host_owner() {
        return Err(Error::auth(
            "describe_schema: database owner host role required for physical DDL",
        ));
    }

    let mut snapshot = PostgresDomainTransaction::begin_snapshot(db).await?;
    let result = async {
        // Read governed logical state before consulting engine catalogs. Apart
        // from making the authority order explicit, this keeps cancellation
        // observable at the exact reviewed relation query rather than inside
        // an implementation-defined information_schema lock acquisition.
        let all_schema_rows = crate::query::cascade::schema_config_rows_with(&mut snapshot).await?;
        let mut visible_schema_rows = Vec::with_capacity(all_schema_rows.len());
        for row in all_schema_rows {
            let visible = match row.applies_to_collection_id.as_deref() {
                None => true,
                Some(bearer) => ordinary_bearer_visible_in(
                    snapshot.admitted("authorize postgres schema row")?,
                    db,
                    caller,
                    bearer,
                )
                .await?,
            };
            if visible {
                visible_schema_rows.push(row);
            }
        }
        let mut resolved = crate::query::cascade::resolve_from_rows(&visible_schema_rows).resolved;
        let mut kind_registry = Map::new();
        for record_type in crate::schema::SPINE_TYPES {
            let kinds = crate::meta::kind::list_active_with(&mut snapshot, record_type).await?;
            let tokens = kinds
                .iter()
                .map(|kind| Value::String(kind.token.clone()))
                .collect();
            resolved["shapes"][record_type]["kinds"] = Value::Array(tokens);
            kind_registry.insert(record_type.into(), serde_json::to_value(kinds)?);
        }

        let (by_table, complete_ddl) =
            postgres_complete_schema_contract(db, &mut snapshot, &REQUIRED_RELATIONS).await?;
        if !crate::schema::discovery::shared_logical_contract_holds(&by_table) {
            return Err(Error::engine(format!(
                "describe_schema: Postgres logical column contract is incomplete: {}",
                crate::schema::discovery::shared_logical_contract_mismatches(&by_table).join(", ")
            )));
        }
        let ddl_fingerprint = hex::encode(Sha256::digest(serde_json::to_vec(&complete_ddl)?));
        if complete_ddl.len() != POSTGRES_DESCRIBE_SCHEMA_DDL_COUNT
            || ddl_fingerprint != POSTGRES_DESCRIBE_SCHEMA_DDL_FINGERPRINT
        {
            return Err(Error::engine(format!(
                "describe_schema: installed Postgres DDL differs from the frozen allowlisted contract (count={}, fingerprint={ddl_fingerprint})",
                complete_ddl.len()
            )));
        }

        let tables = REQUIRED_RELATIONS
            .iter()
            .filter(|table| postgres_schema_table_visible(table, caller))
            .map(|table| {
                json!({
                    "name":table,
                    "role":crate::schema::discovery::table_role(table),
                    "columns":by_table.get(*table).expect("required relation checked"),
                })
            })
            .collect::<Vec<_>>();
        let migration_version: i32 = sqlx::query_scalar(&format!(
            "SELECT COALESCE(MAX(version),0) FROM {}",
            db.qualified_table("schema_migrations")?
        ))
        .fetch_one(&mut **snapshot.admitted("describe postgres migration version")?)
        .await?;
        let ddl_statements = args.include_ddl.unwrap_or(false).then_some(complete_ddl);
        let mut out = json!({
            "engine":{
                "name":crate::ENGINE_NAME,
                "version":crate::ENGINE_VERSION,
                "git_sha":crate::GIT_SHA,
                "schema_version":crate::CURRENT_ENGINE_SCHEMA_VERSION,
                "supported_schema_baseline":crate::SUPPORTED_ENGINE_SCHEMA_BASELINE,
                "user_version":migration_version,
                "ddl_fingerprint":ddl_fingerprint,
                "storage_profile":"postgres-server",
                "storage_profile_revision":5,
            },
            "model":crate::schema::discovery::AUTHORITY_MODEL,
            "physical_differences":{
                "catalog":"allowlisted logical schema only",
                "record_type_column":"record_type",
                "json":"jsonb",
                "timestamps":"timestamptz",
                "generated_schema_name_exposed":false,
            },
            "tables":tables,
            "resolved_schema_config":resolved,
            "kind_registry":kind_registry,
        });
        if let Some(ddl_statements) = ddl_statements {
            out["ddl_statements"] = serde_json::to_value(ddl_statements)?;
            out["ddl_schema_placeholder"] = json!("{schema}");
            out["ddl_representation"] = json!("complete normalized installed contract: allowlisted tables with columns, defaults, identity, keys, foreign keys and checks, plus non-constraint indexes, user triggers and their trigger function");
        }
        Ok(out)
    }
    .await;
    let cleanup = snapshot.rollback().await;
    match result {
        Ok(value) => {
            cleanup?;
            Ok(value)
        }
        Err(error) => {
            let _ = cleanup;
            Err(error)
        }
    }
}

pub fn register_postgres_tools(registry: &mut ToolRegistry) -> Result<()> {
    register_postgres_tools_with(registry, FetchConfig::default())
}

/// Register the Postgres handlers with an explicit guarded-fetch config for
/// contract tests. Production callers use [`register_postgres_tools`], which
/// retains the default SSRF policy.
pub fn register_postgres_tools_with(
    registry: &mut ToolRegistry,
    fetch_config: FetchConfig,
) -> Result<()> {
    match (registry.get("ping"), registry.get("engine_info")) {
        (None, None) => crate::mcp::register_builtin_tools(registry)?,
        (Some(_), Some(_)) => {}
        _ => {
            return Err(Error::engine(
                "Postgres registry has an incomplete built-in tool set",
            ))
        }
    }
    registry.register_engine_handler(
        "ping",
        EngineKind::Postgres,
        |_engine, _caller, arguments| async move {
            let object = arguments
                .as_object()
                .ok_or_else(|| Error::engine("invalid arguments: expected an object"))?;
            if !object.is_empty() {
                return Err(Error::engine("invalid arguments: expected no arguments"));
            }
            Ok(json!({"ok": true}))
        },
    )?;
    registry.register_engine_handler(
        "engine_info",
        EngineKind::Postgres,
        |engine, _caller, arguments| async move {
            let EngineHandle::Postgres(db) = engine else {
                unreachable!("registry selected a Postgres handler for SQLite")
            };
            postgres_engine_info(&db, arguments).await
        },
    )?;
    macro_rules! register {
        ($name:literal, $handler:ident) => {
            registry.register_engine_handler(
                $name,
                EngineKind::Postgres,
                |engine, caller, arguments| async move {
                    let EngineHandle::Postgres(db) = engine else {
                        unreachable!("registry selected a Postgres handler for SQLite")
                    };
                    stable_tool_result($name, $handler(&db, &caller, arguments).await)
                },
            )?;
        };
    }
    register!("create_record", create_record);
    register!("get_record", get_record);
    for operation in [
        "get_structure",
        "get_dashboard",
        "render_record",
        "query_record",
        "resolve_rollup",
        "search",
        "scan",
        "preview_record_shape",
        "resolve_facets",
        "suggest_facet_values",
    ] {
        registry.register_engine_handler(
            operation,
            EngineKind::Postgres,
            move |engine, caller, arguments| async move {
                let EngineHandle::Postgres(db) = engine else {
                    unreachable!("registry selected a Postgres handler for SQLite")
                };
                stable_tool_result(
                    operation,
                    run_portable_view(&db, &caller, arguments, operation).await,
                )
            },
        )?;
    }
    register!("manage_facet_observations", manage_facet_observations);
    register!("update_record", update_record);
    #[cfg(feature = "mcp-executor-prototype")]
    register!("correct_record_type", correct_record_type);
    register!("delete_record", delete_record);
    register!("archive_record", archive_record);
    register!("get_history", get_history);
    registry.register_engine_handler_for_selector_values(
        "manage_links",
        EngineKind::Postgres,
        "action",
        &["add", "list"],
        |engine, caller, arguments| async move {
            let EngineHandle::Postgres(db) = engine else {
                unreachable!("registry selected a Postgres handler for SQLite")
            };
            stable_tool_result("manage_links", manage_links(&db, &caller, arguments).await)
        },
    )?;
    register!("attach_text", attach_text);
    let fetch_config = Arc::new(fetch_config);
    registry.register_engine_handler(
        "attach_from_url",
        EngineKind::Postgres,
        move |engine, caller, arguments| {
            let fetch_config = Arc::clone(&fetch_config);
            async move {
                let EngineHandle::Postgres(db) = engine else {
                    unreachable!("registry selected a Postgres handler for SQLite")
                };
                stable_tool_result(
                    "attach_from_url",
                    attach_from_url(&db, &caller, arguments, (*fetch_config).clone()).await,
                )
            }
        },
    )?;
    register!("read_attachment", read_attachment);
    register!("manage_attachments", manage_attachments);
    register!("describe_schema", postgres_describe_schema);
    register!("resolve_external", postgres_resolve_external);
    registry.register_engine_handler_for_selector_values(
        "manage_bindings",
        EngineKind::Postgres,
        "action",
        &["list", "add", "remove", "canonicalize", "reconcile"],
        |engine, caller, arguments| async move {
            let EngineHandle::Postgres(db) = engine else {
                unreachable!()
            };
            stable_tool_result(
                "manage_bindings",
                postgres_manage_bindings(&db, &caller, arguments).await,
            )
        },
    )?;
    register!("query_sql", postgres_query_sql);
    registry.register_engine_handler(
        "set_intent",
        EngineKind::Postgres,
        |_engine, _caller, arguments| async move {
            crate::mcp::tools::intent::declare_without_activity_briefing(arguments)
        },
    )?;
    Ok(())
}

async fn postgres_resolve_external(
    db: &PostgresDb,
    caller: &Caller,
    arguments: Value,
) -> Result<Value> {
    let request = crate::domain_transaction::parse_resolve_external(arguments)?;
    let mut port = PostgresDomainTransaction::begin(db).await?;
    let result = crate::domain_transaction::resolve_external(
        &mut port,
        attachment_principal(caller),
        caller.actor(),
        caller.run_key(),
        caller.parent_key(),
        caller.intent(),
        request,
    )
    .await;
    match result {
        Ok(result) => {
            if result.created || !result.bindings_added.is_empty() {
                port.commit().await?;
            } else {
                port.rollback().await?;
            }
            Ok(json!({
                "status":if result.created{"created"}else{"resolved"},
                "record_id":result.record_id,
                "created":result.created,
                "bindings_added":result.bindings_added,
            }))
        }
        Err(error) => {
            let _ = port.rollback().await;
            Err(error)
        }
    }
}

async fn postgres_manage_bindings(
    db: &PostgresDb,
    caller: &Caller,
    arguments: Value,
) -> Result<Value> {
    let request = crate::domain_transaction::parse_manage_bindings(arguments)?;
    let mut port = PostgresDomainTransaction::begin(db).await?;
    let result = crate::domain_transaction::manage_bindings(
        &mut port,
        attachment_principal(caller),
        caller.actor(),
        caller.run_key(),
        caller.parent_key(),
        caller.intent(),
        request,
    )
    .await;
    match result {
        Ok(outcome) => {
            if outcome.changed {
                port.commit().await?;
            } else {
                port.rollback().await?;
            }
            Ok(outcome.response)
        }
        Err(error) => {
            let _ = port.rollback().await;
            Err(error)
        }
    }
}

/// Backwards-compatible name retained for the contract harness while the
/// runtime adapter is broader than the original bounded slice.
pub fn register_postgres_slice_tools(registry: &mut ToolRegistry) -> Result<()> {
    register_postgres_tools(registry)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PostgresEngineInfoArguments {
    #[serde(default)]
    target_profiles: Vec<crate::storage_profile::StorageTarget>,
    #[serde(default)]
    required_capabilities: Option<Vec<String>>,
}

async fn postgres_engine_info(db: &PostgresDb, arguments: Value) -> Result<Value> {
    if arguments
        .get("required_capabilities")
        .is_some_and(Value::is_null)
    {
        return Err(Error::engine(
            "invalid arguments: required_capabilities must be an array when present",
        ));
    }
    let arguments = serde_json::from_value::<PostgresEngineInfoArguments>(arguments)
        .map_err(|error| Error::engine(format!("invalid arguments: {error}")))?;
    if arguments.required_capabilities.is_some() && arguments.target_profiles.is_empty() {
        return Err(Error::engine(
            "required_capabilities requires at least one target profile",
        ));
    }
    let health = db.health().await?;
    let mut result = json!({
        "engine": crate::ENGINE_NAME,
        "engine_version": crate::ENGINE_VERSION,
        "git_sha": crate::GIT_SHA,
        "schema_version": health.observed_schema_version,
        "storage_profile": {
            "format": "native.storage-runtime.v1",
            "id": "postgres-server",
            "revision": 5,
            "mode": "network",
            "status": "spike",
            "topology": "schema-per-logical-database",
            "logical_database_id": db.logical_database_id(),
            "schema": db.schema(),
            "enforcement": "off"
        },
        "health": health,
        "configuration": db.redacted_config(),
        "query_sql": crate::query::sql_contract::capability(
            crate::query::sql_contract::QuerySqlProfile::PostgresServer
        )
    });
    if !arguments.target_profiles.is_empty() {
        result["portability_audit"] = crate::storage_profile::portability_audit(
            &arguments.target_profiles,
            arguments.required_capabilities.as_deref(),
        )?;
    }
    Ok(result)
}

async fn postgres_query_sql(db: &PostgresDb, caller: &Caller, arguments: Value) -> Result<Value> {
    let request = serde_json::from_value::<crate::query::sql_contract::QuerySqlRequest>(arguments)
        .map_err(|error| {
            crate::query::sql_contract::categorized_error(
                crate::query::sql_contract::QuerySqlErrorCategory::InvalidArguments,
                error.to_string(),
            )
        })?;
    let result =
        crate::postgres::query_sql::query_sql_request_owned(db.clone(), caller.into(), request)
            .await
            .map_err(crate::query::sql_contract::ensure_categorized)?;
    Ok(json!({
        "columns": result.columns,
        "rows": result.rows,
        "row_count": result.row_count,
        "truncated": result.truncated,
    }))
}

fn stable_tool_result(tool: &str, result: Result<Value>) -> Result<Value> {
    result.map_err(|error| match error {
        Error::Sqlx(sqlx::Error::Database(database)) => match database.code().as_deref() {
            Some("23505") => Error::engine(format!("{tool}: uniqueness conflict")),
            Some("23503" | "23514") => {
                Error::engine(format!("{tool}: storage constraint violated"))
            }
            Some("40001" | "40P01" | "55P03") => {
                Error::engine(format!("{tool}: storage transaction must be retried"))
            }
            Some("53300" | "57014") => {
                Error::engine(format!("{tool}: storage temporarily unavailable"))
            }
            _ => Error::engine(format!("{tool}: storage operation failed")),
        },
        Error::Sqlx(_) => Error::engine(format!("{tool}: storage operation failed")),
        Error::Json(_) => Error::engine(format!("{tool}: invalid arguments")),
        other => other,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateArgs {
    id: Option<String>,
    #[serde(rename = "type")]
    record_type: String,
    kind: String,
    name: Option<String>,
    body: Option<String>,
    home_id: Option<String>,
    summary: Option<String>,
    lifecycle: Option<String>,
    owner_id: Option<String>,
    persistence: Option<String>,
    maturity: Option<String>,
    facets: Option<Map<String, Value>>,
    links: Option<Vec<CreateLink>>,
    addressed_to: Option<Vec<String>>,
    reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateLink {
    target_id: String,
    relationship: String,
    note: Option<String>,
}

fn link_added_payload(
    source_id: &str,
    target_id: &str,
    relationship: &str,
    note: Option<String>,
) -> Value {
    let mut payload = json!({
        "source_id": source_id,
        "target_id": target_id,
        "relationship": relationship,
    });
    if let Some(note) = note {
        payload["note"] = json!(note);
    }
    payload
}

fn parse<T: for<'de> Deserialize<'de>>(tool: &str, arguments: Value) -> Result<T> {
    serde_json::from_value(arguments)
        .map_err(|error| Error::engine(format!("invalid arguments for {tool}: {error}")))
}

async fn create_record(db: &PostgresDb, caller: &Caller, arguments: Value) -> Result<Value> {
    let args: CreateArgs = parse("create_record", arguments)?;
    if args.reason.trim().is_empty() {
        return Err(Error::engine("create_record: 'reason' must not be blank"));
    }
    if args.kind.is_empty() {
        return Err(Error::engine("create_record: 'kind' must not be empty"));
    }
    if !matches!(
        args.record_type.as_str(),
        "Document"
            | "Program"
            | "WorkItem"
            | "Outcome"
            | "Entity"
            | "Collection"
            | "Resolution"
            | "Conversation"
            | "Message"
            | "Annotation"
    ) {
        return Err(Error::engine("create_record: unsupported record type"));
    }
    if args.record_type == "Annotation"
        || (args.record_type == "Document" && args.kind == "attachment")
    {
        return Err(Error::engine(
            "create_record: derived artifact authorization is not qualified for Postgres",
        ));
    }
    let persistence = args
        .persistence
        .clone()
        .unwrap_or_else(|| "enduring".into());
    if !matches!(persistence.as_str(), "enduring" | "occurrent") {
        return Err(Error::engine(
            "create_record: persistence must be enduring or occurrent",
        ));
    }
    crate::freshness::reject_reserved_semantic_unit_kind(&args.kind, "create_record")?;
    let id = crate::domain_transaction::record_id_for_create(args.id)?;
    let mut facets = args
        .facets
        .unwrap_or_default()
        .into_iter()
        .map(|(key, value)| {
            crate::mcp::tools::lifecycle::parse_facet_entry("create_record", &key, &value, false)?
                .ok_or_else(|| Error::engine("create_record: facet value must not be null"))
        })
        .collect::<Result<Vec<_>>>()?;
    let bindings = db.qualified_table("bindings")?;
    let mut transaction = PostgresDomainTransaction::begin(db).await?;
    let owner_id = if caller.is_trusted_local() {
        args.owner_id
    } else {
        let tx = transaction.admitted("authorize create_record owner")?;
        Some(
            sqlx::query_scalar::<_, String>(&format!(
                "SELECT record_id FROM {bindings} \
                 WHERE system='account' AND identifier=$1 AND is_canonical=TRUE"
            ))
            .bind(caller.credential())
            .fetch_optional(&mut **tx)
            .await?
            .ok_or_else(|| {
                Error::engine("create_record: caller has no portable account binding")
            })?,
        )
    };
    if args.record_type == "Message" && args.addressed_to.is_none() {
        return Err(Error::engine(
            "create_record: Message requires explicit addressed_to",
        ));
    }
    let resolution =
        crate::meta::kind::resolve_with(&mut transaction, &args.record_type, &args.kind).await?;
    let kind = resolution
        .canonical_kind_for_write()
        .unwrap_or(&args.kind)
        .to_string();
    if args.record_type == "Document" && kind == "attachment" {
        return Err(Error::engine(
            "create_record: derived artifact authorization is not qualified for Postgres",
        ));
    }
    let lifecycle = args.lifecycle.or_else(|| {
        (args.record_type == "WorkItem" && matches!(kind.as_str(), "task" | "epic"))
            .then(|| "open".into())
    });
    let schema_rows = crate::query::cascade::schema_config_rows_with(&mut transaction).await?;
    let mut governed = facets.clone();
    if let Some(lifecycle) = lifecycle.as_ref() {
        governed.push(FacetWrite {
            key: "lifecycle".into(),
            value: Value::String(lifecycle.clone()),
            vocab_ref: None,
        });
    }
    crate::domain_transaction::govern_facet_writes(
        &mut transaction,
        &schema_rows,
        "create_record",
        &args.record_type,
        Some(&kind),
        &mut governed,
    )
    .await?;
    for facet in &mut facets {
        facet.vocab_ref = governed
            .iter()
            .find(|checked| checked.key == facet.key)
            .and_then(|checked| checked.vocab_ref.clone());
    }
    let payload = json!({
        "type": args.record_type,
        "kind": kind,
        "name": args.name,
        "body": args.body,
        // Placement omission has one meaning on every backend: non-root
        // records are homed in Unfiled (`normalize_event_payload`).
        "home_id": args.home_id,
        "summary": args.summary,
        "lifecycle": lifecycle,
        "owner_id": owner_id,
        "persistence": persistence,
        "maturity": args.maturity,
        "reason": args.reason,
    });
    {
        let tx = transaction.admitted("append create_record")?;
        let (_, created_at) =
            append_event(db, tx, &id, "record.created", &payload, caller.actor()).await?;
        apply_projection(db, tx, &id, "record.created", &payload, &created_at).await?;
    }

    for facet in facets {
        let spec = crate::domain_transaction::facet_set_spec(&id, &facet, caller.actor());
        let tx = transaction.admitted("append governed create_record facet")?;
        let (_, created_at) =
            append_event(db, tx, &id, &spec.event_type, &spec.payload, caller.actor()).await?;
        apply_projection(db, tx, &id, &spec.event_type, &spec.payload, &created_at).await?;
    }
    let required_after = crate::domain_transaction::required_violations(
        &mut transaction,
        &schema_rows,
        &[id.as_str()],
    )
    .await?;
    crate::domain_transaction::assert_required_not_worsened(
        "create_record",
        &Default::default(),
        &required_after,
    )?;

    for link in args.links.unwrap_or_default() {
        if link.relationship.is_empty() {
            return Err(Error::engine(
                "create_record: link relationship must not be empty",
            ));
        }
        let target_exists: bool = {
            let records = db.qualified_table("records")?;
            sqlx::query_scalar(&format!(
                "SELECT EXISTS(SELECT 1 FROM {records} WHERE id=$1 AND deleted_at IS NULL)"
            ))
            .bind(&link.target_id)
            .fetch_one(&mut **transaction.admitted("validate create_record link")?)
            .await?
        };
        if !target_exists {
            return Err(Error::engine(format!(
                "create_record: link target {} does not exist",
                link.target_id
            )));
        }
        let payload = link_added_payload(&id, &link.target_id, &link.relationship, link.note);
        let tx = transaction.admitted("append create_record link")?;
        let (_, created_at) =
            append_event(db, tx, &id, "link.added", &payload, caller.actor()).await?;
        apply_projection(db, tx, &id, "link.added", &payload, &created_at).await?;
    }

    if args.record_type == "Message" {
        let owner = owner_id
            .ok_or_else(|| Error::engine("create_record: Message requires sender owner_id"))?;
        let mut accounts = Vec::new();
        for recipient in args.addressed_to.unwrap_or_default() {
            let account = sqlx::query_scalar::<_, String>(&format!(
                "SELECT identifier FROM {bindings} \
                 WHERE record_id=$1 AND system='account' AND is_canonical=TRUE"
            ))
            .bind(&recipient)
            .fetch_optional(&mut **transaction.admitted("resolve create_record audience")?)
            .await?
            .ok_or_else(|| {
                Error::engine(format!(
                    "create_record: addressed_to recipient {recipient} has no account binding"
                ))
            })?;
            accounts.push(account);
        }
        accounts.sort();
        accounts.dedup();
        let payload = json!({ "sender_id": owner, "accounts": accounts });
        let tx = transaction.admitted("append create_record audience")?;
        let (_, created_at) = append_event(
            db,
            tx,
            &id,
            "message.audience.declared",
            &payload,
            caller.actor(),
        )
        .await?;
        apply_projection(
            db,
            tx,
            &id,
            "message.audience.declared",
            &payload,
            &created_at,
        )
        .await?;
    }
    transaction.commit().await?;
    read_record(db, caller, &id).await?.ok_or_else(|| {
        Error::engine(format!(
            "create_record: record {id} not readable after write"
        ))
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GetArgs {
    ids: Vec<String>,
    include_interpretation: Option<bool>,
}

async fn get_record(db: &PostgresDb, caller: &Caller, arguments: Value) -> Result<Value> {
    let args: GetArgs = parse("get_record", arguments)?;
    if args.include_interpretation.unwrap_or(false) {
        return Err(crate::domain_transaction::unsupported_backend_operation(
            "postgres-server",
            "get_record interpretation projection",
        ));
    }
    // Every id, authorization decision, Message audience check, and facet
    // projection in one request must observe the same database instant.
    let mut snapshot = PostgresDomainTransaction::begin_snapshot(db).await?;
    let lifecycle_interpreter = crate::query::lifecycle::LifecycleInterpreter::load_visible_with(
        &mut snapshot,
        attachment_principal(caller),
    )
    .await?;
    let mut records = Vec::with_capacity(args.ids.len());
    for id in args.ids {
        match read_record_in(
            snapshot.admitted("get_record read")?,
            db,
            caller,
            &id,
            &lifecycle_interpreter,
        )
        .await?
        {
            Some(mut record) => {
                crate::mcp::tools::lifecycle::annotate_full_record_path_for_item(&mut record, &id)?;
                records.push(record);
            }
            None => records.push(json!({ "id": id, "status": "not_found" })),
        }
    }
    snapshot.rollback().await?;
    Ok(json!({ "records": records }))
}

async fn read_record(db: &PostgresDb, caller: &Caller, id: &str) -> Result<Option<Value>> {
    let mut snapshot = PostgresDomainTransaction::begin_snapshot(db).await?;
    let lifecycle_interpreter = crate::query::lifecycle::LifecycleInterpreter::load_visible_with(
        &mut snapshot,
        attachment_principal(caller),
    )
    .await?;
    let record = read_record_in(
        snapshot.admitted("read record")?,
        db,
        caller,
        id,
        &lifecycle_interpreter,
    )
    .await?;
    snapshot.rollback().await?;
    Ok(record)
}

/// Resolve an attachment to the ordinary record at the end of its authoritative
/// `part_of` chain. This deliberately does not call `read_record_in` for an
/// intermediate attachment: doing so would recurse through this helper. The
/// shape checks mirror the shared derived-bearer fold and fail closed for
/// malformed, cyclic, deleted, or over-deep chains.
async fn attachment_authorization_bearer_in(
    tx: &mut Transaction<'_, Postgres>,
    db: &PostgresDb,
    attachment_id: &str,
) -> Result<Option<String>> {
    let records = db.qualified_table("records")?;
    let links = db.qualified_table("links")?;
    let mut current = attachment_id.to_owned();
    let mut seen = HashSet::new();

    for _ in 0..=crate::authorization::MAX_DERIVED_BEARER_DEPTH {
        if !seen.insert(current.clone()) {
            return Ok(None);
        }
        let row = sqlx::query(&format!(
            "SELECT record_type, kind, deleted_at FROM {records} WHERE id=$1"
        ))
        .bind(&current)
        .fetch_optional(&mut **tx)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let record_type: String = row.try_get("record_type")?;
        let kind: String = row.try_get("kind")?;
        let deleted_at: Option<DateTime<Utc>> = row.try_get("deleted_at")?;
        if deleted_at.is_some() {
            return Ok(None);
        }
        if record_type == "Annotation" {
            return Ok(None);
        }
        if record_type != "Document" || kind != "attachment" {
            return Ok(Some(current));
        }

        let bearer_rows = sqlx::query(&format!(
            "SELECT target_id FROM {links} WHERE source_id=$1 AND relationship='part_of' ORDER BY target_id"
        ))
        .bind(&current)
        .fetch_all(&mut **tx)
        .await?;
        if bearer_rows.len() != 1 {
            return Ok(None);
        }
        current = bearer_rows[0].try_get("target_id")?;
    }
    Ok(None)
}

/// Apply the ordinary-record visibility rules to the terminal bearer without
/// calling `read_record_in`; that avoids an async recursion cycle when a
/// derived attachment is itself being read.
async fn ordinary_bearer_visible_in(
    tx: &mut Transaction<'_, Postgres>,
    db: &PostgresDb,
    caller: &Caller,
    bearer_id: &str,
) -> Result<bool> {
    let records = db.qualified_table("records")?;
    let row = sqlx::query(&format!(
        "SELECT record_type, kind, owner_id, policy_anchor_id, deleted_at FROM {records} WHERE id=$1"
    ))
    .bind(bearer_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(false);
    };
    let record_type: String = row.try_get("record_type")?;
    let kind: String = row.try_get("kind")?;
    let deleted_at: Option<DateTime<Utc>> = row.try_get("deleted_at")?;
    if deleted_at.is_some()
        || record_type == "Annotation"
        || (record_type == "Document" && kind == "attachment")
    {
        return Ok(false);
    }
    let Some(policy_anchor_id) = row.try_get::<Option<String>, _>("policy_anchor_id")? else {
        return Ok(false);
    };
    let policies = db.qualified_table("record_policies")?;
    let anchor_is_explicit: bool = sqlx::query_scalar(&format!(
        "SELECT EXISTS(SELECT 1 FROM {policies} WHERE record_id=$1)"
    ))
    .bind(&policy_anchor_id)
    .fetch_one(&mut **tx)
    .await?;
    if !anchor_is_explicit {
        return Ok(false);
    }
    if caller.is_trusted_local() {
        return Ok(true);
    }
    let bindings = db.qualified_table("bindings")?;
    let owner_id: Option<String> = row.try_get("owner_id")?;
    let owns: bool = sqlx::query_scalar(&format!(
        "SELECT EXISTS(SELECT 1 FROM {bindings} WHERE record_id=$1 AND system='account' AND identifier=$2 AND is_canonical=TRUE)"
    ))
    .bind(&owner_id)
    .bind(caller.credential())
    .fetch_one(&mut **tx)
    .await?;
    if !owns {
        let entries = db.qualified_table("policy_entries")?;
        let allowed: bool = sqlx::query_scalar(&format!(
            "SELECT EXISTS(SELECT 1 FROM {entries} WHERE policy_anchor_id=$1 AND effect='allow' AND capability IN ('view','edit','manage') AND ((subject_kind='account' AND subject_id=$2) OR (subject_kind='members' AND subject_id='native:members')))"
        ))
        .bind(&policy_anchor_id)
        .bind(caller.credential())
        .fetch_one(&mut **tx)
        .await?;
        if !allowed {
            return Ok(false);
        }
    }
    if record_type == "Message" {
        let audience = db.qualified_table("message_audience")?;
        let visible: bool = sqlx::query_scalar(&format!(
            "SELECT EXISTS(SELECT 1 FROM {bindings} b WHERE b.record_id=$1 AND b.system='account' AND b.identifier=$3 AND b.is_canonical=TRUE) OR EXISTS(SELECT 1 FROM {audience} a WHERE a.message_id=$2 AND a.account_id=$3)"
        ))
        .bind(owner_id)
        .bind(bearer_id)
        .bind(caller.credential())
        .fetch_one(&mut **tx)
        .await?;
        return Ok(visible);
    }
    Ok(true)
}

/// Attachments inherit authorization from the resolved `part_of` bearer, not
/// from the attachment row's projected home/policy anchor. Resolve the chain
/// first, then authorize only its ordinary terminal bearer.
async fn attachment_bearer_visible_in(
    tx: &mut Transaction<'_, Postgres>,
    db: &PostgresDb,
    caller: &Caller,
    attachment_id: &str,
) -> Result<bool> {
    let Some(bearer_id) = attachment_authorization_bearer_in(tx, db, attachment_id).await? else {
        return Ok(false);
    };
    ordinary_bearer_visible_in(tx, db, caller, &bearer_id).await
}

async fn read_record_in(
    tx: &mut Transaction<'_, Postgres>,
    db: &PostgresDb,
    caller: &Caller,
    id: &str,
    lifecycle_interpreter: &crate::query::lifecycle::LifecycleInterpreter,
) -> Result<Option<Value>> {
    let records = db.qualified_table("records")?;
    let bindings = db.qualified_table("bindings")?;
    let audience = db.qualified_table("message_audience")?;
    let row = sqlx::query(&format!(
        "SELECT id, record_type, kind, name, body, home_id, summary, lifecycle, owner_id,policy_anchor_id, \
                persistence, maturity, archived, created_at, updated_at, deleted_at::text AS deleted_at \
         FROM {records} WHERE id=$1"
    ))
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let record_type: String = row.try_get("record_type")?;
    let kind: String = row.try_get("kind")?;
    let is_attachment = record_type == "Document" && kind == "attachment";
    if is_attachment && !attachment_bearer_visible_in(tx, db, caller, id).await? {
        return Ok(None);
    }
    if !is_attachment {
        let policy_anchor_id: Option<String> = row.try_get("policy_anchor_id")?;
        let Some(policy_anchor_id) = policy_anchor_id else {
            if !caller.is_trusted_local() {
                return Ok(None);
            }
            return Err(Error::engine(format!(
                "record {id} has no effective policy anchor"
            )));
        };
        let policies = db.qualified_table("record_policies")?;
        let anchor_is_explicit: bool = sqlx::query_scalar(&format!(
            "SELECT EXISTS(SELECT 1 FROM {policies} WHERE record_id=$1)"
        ))
        .bind(&policy_anchor_id)
        .fetch_one(&mut **tx)
        .await?;
        if !anchor_is_explicit {
            if !caller.is_trusted_local() {
                return Ok(None);
            }
            return Err(Error::engine(format!(
                "record {id} has an invalid effective policy anchor"
            )));
        }
        if !caller.is_trusted_local() {
            let owner_id: Option<String> = row.try_get("owner_id")?;
            let owns: bool = sqlx::query_scalar(&format!(
                "SELECT EXISTS(SELECT 1 FROM {bindings} WHERE record_id=$1 AND system='account' AND identifier=$2 AND is_canonical=TRUE)"
            ))
            .bind(owner_id)
            .bind(caller.credential())
            .fetch_one(&mut **tx)
            .await?;
            if !owns {
                let entries = db.qualified_table("policy_entries")?;
                let allowed: bool = sqlx::query_scalar(&format!(
                        "SELECT EXISTS(SELECT 1 FROM {entries} WHERE policy_anchor_id=$1 AND effect='allow' AND capability IN ('view','edit','manage') AND ((subject_kind='account' AND subject_id=$2) OR (subject_kind='members' AND subject_id='native:members')))"
                ))
                .bind(&policy_anchor_id)
                .bind(caller.credential())
                .fetch_one(&mut **tx)
                .await?;
                if !allowed {
                    return Ok(None);
                }
            }
        }
    }
    // Attachment authorization is complete after the live bearer fold above.
    // Annotations remain outside this backend's derived-artifact contract.
    if record_type == "Annotation" {
        return Err(Error::engine(format!(
            "record {id} uses derived artifact authorization not qualified for Postgres"
        )));
    }
    if !caller.is_trusted_local() && record_type == "Message" {
        let visible: bool = sqlx::query_scalar(&format!(
            "SELECT EXISTS(\
                 SELECT 1 FROM {bindings} b \
                 WHERE b.record_id=$1 AND b.system='account' AND b.identifier=$3 AND b.is_canonical=TRUE\
             ) OR EXISTS(\
                 SELECT 1 FROM {audience} a WHERE a.message_id=$2 AND a.account_id=$3\
             )"
        ))
        .bind(row.try_get::<Option<String>, _>("owner_id")?)
        .bind(id)
        .bind(caller.credential())
        .fetch_one(&mut **tx)
        .await?;
        if !visible {
            return Ok(None);
        }
    }
    let facets = db.qualified_table("facet_values")?;
    let facet_rows = sqlx::query(&format!(
        "SELECT key, value::text AS value FROM {facets} \
         WHERE record_id=$1 ORDER BY key COLLATE \"C\""
    ))
    .bind(id)
    .fetch_all(&mut **tx)
    .await?;
    let mut logical_facets = Vec::new();
    for facet in facet_rows {
        let value: Value = serde_json::from_str(&facet.try_get::<String, _>("value")?)?;
        logical_facets.push(json!({
            "key": facet.try_get::<String, _>("key")?,
            "value": value,
        }));
    }
    let home_id: Option<String> = row.try_get("home_id")?;
    let lifecycle: Option<String> = row.try_get("lifecycle")?;
    let lifecycle_interpretation = lifecycle_interpreter.interpret(
        &record_type,
        Some(&kind),
        home_id.as_deref(),
        lifecycle.as_deref(),
    );
    let mut record = json!({
        "status": "found",
        "id": row.try_get::<String, _>("id")?,
        "type": record_type,
        "kind": kind,
        "name": row.try_get::<Option<String>, _>("name")?,
        "body": row.try_get::<Option<String>, _>("body")?,
        "home_id": home_id,
        "summary": row.try_get::<Option<String>, _>("summary")?,
        "lifecycle_interpretation": lifecycle_interpretation,
        "owner_id": row.try_get::<Option<String>, _>("owner_id")?,
        "persistence": row.try_get::<String, _>("persistence")?,
        "maturity": row.try_get::<Option<String>, _>("maturity")?,
        "archived": row.try_get::<bool, _>("archived")?,
        "created_at": row.try_get::<DateTime<Utc>, _>("created_at")?
            .to_rfc3339_opts(SecondsFormat::AutoSi, true),
        "updated_at": row.try_get::<DateTime<Utc>, _>("updated_at")?
            .to_rfc3339_opts(SecondsFormat::AutoSi, true),
        "deleted_at": row.try_get::<Option<String>, _>("deleted_at")?,
        "facets": logical_facets,
    });
    crate::mcp::tools::lifecycle::annotate_body_digest(&mut record);
    Ok(Some(record))
}

fn present<'de, D>(deserializer: D) -> std::result::Result<Option<Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Value::deserialize(deserializer).map(Some)
}

#[cfg(feature = "mcp-executor-prototype")]
async fn postgres_correction_snapshot(
    transaction: &mut PostgresDomainTransaction<'_>,
    caller: &Caller,
    args: &crate::mcp::tools::lifecycle::CorrectRecordTypeArgs,
    require_manage_capability: bool,
    lock_record: bool,
) -> Result<crate::record_type_correction::CorrectionPlan> {
    const TOOL: &str = "correct_record_type";
    let db = transaction.db;
    if args.reason.trim().is_empty() {
        return Err(Error::engine(
            "correct_record_type: 'reason' must not be blank",
        ));
    }
    if !SPINE_TYPES.contains(&args.target_type.as_str()) || args.target_kind.trim().is_empty() {
        return Err(Error::engine(
            "correct_record_type: target_type must be a closed spine type and target_kind must be non-empty",
        ));
    }
    let records = db.qualified_table("records")?;
    let events = db.qualified_table("content_events")?;
    let meta_events = db.qualified_table("meta_events")?;
    let links = db.qualified_table("links")?;
    let facets = db.qualified_table("facet_values")?;
    let bindings = db.qualified_table("bindings")?;
    let binding_audit = db.qualified_table("binding_audit")?;
    let binding_systems = db.qualified_table("binding_systems")?;
    let annotation_targets = db.qualified_table("annotation_targets")?;
    let annotation_targets_exist: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(&annotation_targets)
        .fetch_one(&mut **transaction.admitted("inspect correction annotation target projection")?)
        .await?;
    let annotation_targets = if annotation_targets_exist {
        annotation_targets
    } else {
        "(SELECT NULL::text AS annotation_id, NULL::text AS target_record_id WHERE FALSE) AS annotation_targets"
            .into()
    };
    let lock = if lock_record { " FOR UPDATE" } else { "" };
    let row = sqlx::query(&format!(
        "SELECT id,record_type,kind,COALESCE(name,'') AS name,body,updated_at,deleted_at,owner_id,home_id,lifecycle,persistence,maturity FROM {records} WHERE id=$1{lock}"
    ))
    .bind(&args.record_id)
    .fetch_optional(&mut **transaction.admitted("read record type correction target")?)
    .await?
    .ok_or_else(|| Error::engine(format!("{TOOL}: record {} does not exist", args.record_id)))?;
    if row
        .try_get::<Option<DateTime<Utc>>, _>("deleted_at")?
        .is_some()
    {
        return Err(Error::engine(format!(
            "{TOOL}: record {} does not exist",
            args.record_id
        )));
    }
    let owner_id: Option<String> = row.try_get("owner_id")?;
    if require_manage_capability {
        require_manage(
            transaction.admitted("authorize record type correction")?,
            db,
            caller,
            &args.record_id,
            owner_id.clone(),
        )
        .await?;
    } else {
        require_edit(
            transaction.admitted("authorize record type correction")?,
            db,
            caller,
            &args.record_id,
            owner_id.clone(),
        )
        .await?;
    }
    let current_type: String = row.try_get("record_type")?;
    let current_kind: String = row.try_get("kind")?;
    let name: String = row.try_get("name")?;
    let body: Option<String> = row.try_get("body")?;
    let updated_at = row
        .try_get::<DateTime<Utc>, _>("updated_at")?
        .to_rfc3339_opts(SecondsFormat::Millis, true);
    let previous_seq: i64 = sqlx::query_scalar(&format!(
        "SELECT COALESCE(MAX(seq),0) FROM {events} WHERE record_id=$1"
    ))
    .bind(&args.record_id)
    .fetch_one(&mut **transaction.admitted("read correction content revision")?)
    .await?;
    if args
        .if_content_seq
        .is_some_and(|expected| expected != previous_seq)
    {
        return Err(Error::engine(
            "correct_record_type: content revision conflict; prepare again",
        ));
    }

    let target_resolution =
        crate::meta::kind::resolve_with(transaction, &args.target_type, &args.target_kind).await?;
    let target_active = !target_resolution.quarantined;
    let canonical_target_kind = target_resolution
        .canonical_kind
        .clone()
        .unwrap_or_else(|| args.target_kind.clone());
    let current_resolution =
        crate::meta::kind::resolve_with(transaction, &current_type, &current_kind).await?;
    let mut matching_types = Vec::new();
    for record_type in SPINE_TYPES {
        if !crate::meta::kind::resolve_with(transaction, record_type, &current_kind)
            .await?
            .quarantined
        {
            matching_types.push(record_type);
        }
    }
    let unique_wrong_type_match = current_resolution.quarantined
        && matching_types.as_slice() == [args.target_type.as_str()]
        && target_active
        && canonical_target_kind == current_kind;

    let id_queries = [
        ("incoming_links", format!("SELECT source_id AS id FROM {links} WHERE target_id=$1 ORDER BY source_id LIMIT 20")),
        ("outgoing_links", format!("SELECT target_id AS id FROM {links} WHERE source_id=$1 ORDER BY target_id LIMIT 20")),
        ("children", format!("SELECT id FROM {records} WHERE home_id=$1 AND deleted_at IS NULL ORDER BY id LIMIT 20")),
        ("comments", format!("SELECT r.id FROM {links} l JOIN {records} r ON r.id=l.source_id WHERE l.target_id=$1 AND l.relationship='part_of' AND r.record_type='Annotation' AND r.kind='comment' AND r.deleted_at IS NULL ORDER BY r.id LIMIT 20")),
        ("citations", format!("SELECT r.id FROM {links} l JOIN {records} r ON r.id=l.source_id WHERE l.target_id=$1 AND l.relationship='part_of' AND r.record_type='Annotation' AND r.kind='citation' AND r.deleted_at IS NULL ORDER BY r.id LIMIT 20")),
        ("attachments", format!("SELECT r.id FROM {links} l JOIN {records} r ON r.id=l.source_id WHERE l.target_id=$1 AND l.relationship='part_of' AND r.record_type='Document' AND r.kind='attachment' AND r.deleted_at IS NULL ORDER BY r.id LIMIT 20")),
        ("targeted_annotations", format!("SELECT annotation_id AS id FROM {annotation_targets} WHERE target_record_id=$1 ORDER BY annotation_id LIMIT 20")),
        ("attributions", format!("SELECT r.id FROM {links} l JOIN {records} r ON r.id=l.source_id WHERE l.target_id=$1 AND l.relationship='part_of' AND r.record_type='Annotation' AND r.kind='attribution' AND r.deleted_at IS NULL ORDER BY r.id LIMIT 20")),
        ("bindings", format!("SELECT system || ':' || identifier || ':' || is_canonical::text AS id FROM {bindings} WHERE record_id=$1 ORDER BY system,identifier LIMIT 20")),
    ];
    let mut bounded_ids = BTreeMap::new();
    for (key, query) in &id_queries {
        let ids = sqlx::query_scalar::<_, String>(query)
            .bind(&args.record_id)
            .fetch_all(&mut **transaction.admitted("read correction dependent ids")?)
            .await?;
        bounded_ids.insert((*key).to_string(), ids);
    }
    bounded_ids.insert("relationships".into(), Vec::new());
    let count_queries = [
        ("incoming_links", format!("SELECT COUNT(*) FROM {links} WHERE target_id=$1")),
        ("outgoing_links", format!("SELECT COUNT(*) FROM {links} WHERE source_id=$1")),
        ("children", format!("SELECT COUNT(*) FROM {records} WHERE home_id=$1 AND deleted_at IS NULL")),
        ("comments", format!("SELECT COUNT(*) FROM {links} l JOIN {records} r ON r.id=l.source_id WHERE l.target_id=$1 AND l.relationship='part_of' AND r.record_type='Annotation' AND r.kind='comment' AND r.deleted_at IS NULL")),
        ("citations", format!("SELECT COUNT(*) FROM {links} l JOIN {records} r ON r.id=l.source_id WHERE l.target_id=$1 AND l.relationship='part_of' AND r.record_type='Annotation' AND r.kind='citation' AND r.deleted_at IS NULL")),
        ("attachments", format!("SELECT COUNT(*) FROM {links} l JOIN {records} r ON r.id=l.source_id WHERE l.target_id=$1 AND l.relationship='part_of' AND r.record_type='Document' AND r.kind='attachment' AND r.deleted_at IS NULL")),
        ("targeted_annotations", format!("SELECT COUNT(*) FROM {annotation_targets} WHERE target_record_id=$1")),
        ("attributions", format!("SELECT COUNT(*) FROM {links} l JOIN {records} r ON r.id=l.source_id WHERE l.target_id=$1 AND l.relationship='part_of' AND r.record_type='Annotation' AND r.kind='attribution' AND r.deleted_at IS NULL")),
        ("bindings", format!("SELECT COUNT(*) FROM {bindings} WHERE record_id=$1")),
    ];
    let mut counts = BTreeMap::new();
    for (key, query) in &count_queries {
        let count = sqlx::query_scalar::<_, i64>(query)
            .bind(&args.record_id)
            .fetch_one(&mut **transaction.admitted("read correction dependent counts")?)
            .await?;
        counts.insert((*key).to_string(), count);
    }
    counts.insert("relationships".into(), 0);
    counts.insert(
        "facets".into(),
        sqlx::query_scalar::<_, i64>(&format!("SELECT COUNT(*) FROM {facets} WHERE record_id=$1"))
            .bind(&args.record_id)
            .fetch_one(&mut **transaction.admitted("read correction facet count")?)
            .await?,
    );

    let mut relevant_ids = BTreeSet::from([args.record_id.clone()]);
    for (category, ids) in &bounded_ids {
        if !matches!(category.as_str(), "relationships" | "bindings") {
            relevant_ids.extend(ids.iter().cloned());
        }
    }
    let mut dependency_heads = BTreeMap::new();
    for id in &relevant_ids {
        let rows = sqlx::query(&format!(
            "SELECT seq FROM {events} WHERE record_id=$1 ORDER BY seq"
        ))
        .bind(id)
        .fetch_all(&mut **transaction.admitted("read correction provenance")?)
        .await?;
        dependency_heads.insert(
            id.clone(),
            rows.last()
                .map(|event| event.try_get::<i64, _>("seq"))
                .transpose()?
                .unwrap_or(0),
        );
    }
    // This adapter deliberately does not materialize portable
    // content_event_sources. Actor plus an asserted run key therefore cannot
    // prove that the history is local; fail closed to confirmed execution.
    let same_run_provenance = false;

    let mut blockers = Vec::new();
    let mut block = |blocker: crate::record_type_correction::Blocker| blockers.push(blocker);
    if crate::schema::ENGINE_PROVISIONED_RECORD_IDS.contains(&args.record_id.as_str()) {
        block(crate::record_type_correction::Blocker::EngineFilingRecord);
    }
    let runtime: Option<Value> = sqlx::query_scalar(&format!(
        "SELECT value FROM {facets} WHERE record_id=$1 AND key='runtime'"
    ))
    .bind(&args.record_id)
    .fetch_optional(&mut **transaction.admitted("read correction runtime facet")?)
    .await?;
    if args.target_type == "Program" {
        let expected = match canonical_target_kind.as_str() {
            "module" => Some("native.mdx.v2"),
            "recipe" => Some("native.recipe.v1"),
            _ => None,
        };
        if expected.is_none() || runtime.as_ref().and_then(Value::as_str) != expected {
            block(crate::record_type_correction::Blocker::ProgramRuntimeTargetShape);
        }
    }
    if args.target_type == "Message" {
        block(crate::record_type_correction::Blocker::MessageTargetShape);
    }
    if args.target_type == "Annotation"
        && matches!(
            canonical_target_kind.as_str(),
            "attribution" | "citation" | "comment"
        )
    {
        block(crate::record_type_correction::Blocker::GovernedAnnotationTargetShape);
    }
    if current_type == "Annotation" && current_kind == "attribution" {
        block(crate::record_type_correction::Blocker::GovernedAttribution);
    }
    let is_targeted: bool = sqlx::query_scalar(&format!(
        "SELECT EXISTS(SELECT 1 FROM {annotation_targets} WHERE annotation_id=$1)"
    ))
    .bind(&args.record_id)
    .fetch_one(&mut **transaction.admitted("read correction annotation target")?)
    .await?;
    if is_targeted {
        block(crate::record_type_correction::Blocker::TargetedAnnotation);
    }
    let has_audience: bool = sqlx::query_scalar(&format!(
        "SELECT EXISTS(SELECT 1 FROM {} WHERE message_id=$1)",
        db.qualified_table("message_audience")?
    ))
    .bind(&args.record_id)
    .fetch_one(&mut **transaction.admitted("read correction message state")?)
    .await?;
    if current_type == "Message" && has_audience {
        block(crate::record_type_correction::Blocker::MessageDeliveryState);
    }
    let incompatible_binding: bool = sqlx::query_scalar(&format!(
        "SELECT EXISTS(SELECT 1 FROM {bindings} b JOIN {binding_systems} s ON s.system=b.system WHERE b.record_id=$1 AND ((s.compatible_type IS NOT NULL AND s.compatible_type<>$2) OR (s.compatible_kind IS NOT NULL AND s.compatible_kind<>$3)))"
    ))
    .bind(&args.record_id)
    .bind(&args.target_type)
    .bind(&canonical_target_kind)
    .fetch_one(&mut **transaction.admitted("read correction bindings")?)
    .await?;
    if incompatible_binding {
        block(crate::record_type_correction::Blocker::IncompatibleIdentityBinding);
    }

    let schema_rows = crate::query::cascade::schema_config_rows_with(transaction).await?;
    let target_facets = crate::query::cascade::facets_for_record_context(
        &schema_rows,
        &args.target_type,
        Some(&canonical_target_kind),
        row.try_get::<Option<String>, _>("home_id")?.as_deref(),
    );
    let open_rows = sqlx::query(&format!(
        "SELECT key,value FROM {facets} WHERE record_id=$1 ORDER BY key"
    ))
    .bind(&args.record_id)
    .fetch_all(&mut **transaction.admitted("read correction facets")?)
    .await?;
    let present_open = open_rows
        .iter()
        .map(|facet| facet.try_get::<String, _>("key"))
        .collect::<std::result::Result<BTreeSet<_>, _>>()?;
    for (key, shape) in &target_facets {
        if shape.get("required") != Some(&Value::Bool(true)) {
            continue;
        }
        let present = match spine_facet_column(key) {
            Some("lifecycle") => row.try_get::<Option<String>, _>("lifecycle")?.is_some(),
            Some("owner_id") => owner_id.is_some(),
            Some("persistence") => row.try_get::<Option<String>, _>("persistence")?.is_some(),
            Some("maturity") => row.try_get::<Option<String>, _>("maturity")?.is_some(),
            Some(other) => {
                return Err(Error::engine(format!(
                    "correct_record_type: unsupported spine facet column '{other}'"
                )))
            }
            None => present_open.contains(key),
        };
        if !present {
            block(
                crate::record_type_correction::Blocker::RequiredFacetMissing { facet: key.clone() },
            );
        }
    }
    let mut preserved_facets = open_rows
        .into_iter()
        .map(|facet| {
            Ok(FacetWrite {
                key: facet.try_get("key")?,
                value: facet.try_get("value")?,
                vocab_ref: None,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if let Err(error) = crate::domain_transaction::govern_facet_writes(
        transaction,
        &schema_rows,
        TOOL,
        &args.target_type,
        Some(&canonical_target_kind),
        &mut preserved_facets,
    )
    .await
    {
        block(
            crate::record_type_correction::Blocker::IncompatibleFacetValue {
                detail: error.to_string(),
            },
        );
    }

    let (meta_seq, content_seq): (i64, i64) = sqlx::query_as(&format!(
        "SELECT COALESCE((SELECT MAX(seq) FROM {meta_events}),0),COALESCE((SELECT MAX(seq) FROM {events}),0)"
    ))
    .fetch_one(&mut **transaction.admitted("read correction schema revision")?)
    .await?;
    let schema_state_revision = format!("schema-state-v1:meta:{meta_seq}:content:{content_seq}");
    if args
        .if_schema_state_revision
        .as_deref()
        .is_some_and(|expected| expected != schema_state_revision)
    {
        return Err(Error::engine(
            "correct_record_type: schema state revision conflict; prepare again",
        ));
    }
    let binding_audit_head: i64 = sqlx::query_scalar(&format!(
        "SELECT COALESCE(MAX(seq),0) FROM {binding_audit} WHERE old_record_id=$1 OR new_record_id=$1"
    ))
    .bind(&args.record_id)
    .fetch_one(&mut **transaction.admitted("read correction binding audit head")?)
    .await?;
    // This adapter has no portable relationship-event log to fence on, so it
    // binds per-record content heads instead. That difference is deliberate
    // and stays with the adapter that can observe it.
    let plan = crate::record_type_correction::CorrectionPlan::new(
        crate::record_type_correction::CorrectionFacts {
            record_id: args.record_id.clone(),
            reason: args.reason.clone(),
            name,
            body_digest: crate::mcp::tools::lifecycle::body_digest(body.as_deref()),
            updated_at,
            previous_seq,
            schema_state_revision,
            current: crate::record_type_correction::Identity {
                record_type: current_type,
                kind: current_kind,
            },
            target: crate::record_type_correction::Identity {
                record_type: args.target_type.clone(),
                kind: canonical_target_kind,
            },
            target_active,
            unique_wrong_type_match,
            same_run_provenance,
            preserved_state_counts: counts,
            bounded_identifiers: bounded_ids,
            dependency_fences: BTreeMap::from([
                ("dependency_heads".to_string(), json!(dependency_heads)),
                ("binding_audit_head".to_string(), json!(binding_audit_head)),
            ]),
            blockers,
        },
    )?;
    if args
        .if_dependency_digest
        .as_deref()
        .is_some_and(|expected| expected != plan.dependency_digest())
    {
        return Err(Error::engine(
            "correct_record_type: dependent state changed; prepare again",
        ));
    }
    Ok(plan)
}

#[cfg(feature = "mcp-executor-prototype")]
pub(crate) async fn prepare_correct_record_type(
    db: &PostgresDb,
    caller: &Caller,
    arguments: Value,
) -> Result<crate::mcp::tools::lifecycle::CorrectRecordTypePreparation> {
    let args: crate::mcp::tools::lifecycle::CorrectRecordTypeArgs =
        parse("correct_record_type", arguments)?;
    if args.if_content_seq.is_some()
        || args.if_schema_state_revision.is_some()
        || args.if_dependency_digest.is_some()
        || args.plan_id.is_some()
        || args.effect_digest.is_some()
        || args.mode.is_some()
        || args.confirmation_required.is_some()
    {
        return Err(Error::engine(
            "correct_record_type: preparation does not accept executor-owned fields",
        ));
    }
    let mut transaction = PostgresDomainTransaction::begin_snapshot(db).await?;
    let plan = postgres_correction_snapshot(&mut transaction, caller, &args, false, false).await?;
    let prepared = plan.prepared()?;
    transaction.rollback().await?;
    Ok(prepared.into())
}

#[cfg(feature = "mcp-executor-prototype")]
async fn correct_record_type(db: &PostgresDb, caller: &Caller, arguments: Value) -> Result<Value> {
    let args: crate::mcp::tools::lifecycle::CorrectRecordTypeArgs =
        parse("correct_record_type", arguments)?;
    let execution = caller.write_plan_execution().ok_or_else(|| {
        Error::engine(
            "correct_record_type: execute only through a claimed records_write.correct_record_type plan",
        )
    })?;
    if execution.executor != "records_write"
        || execution.operation != "correct_record_type"
        || args.plan_id.as_deref() != Some(execution.plan_id.as_str())
        || args.effect_digest.as_deref() != Some(execution.effect_digest.as_str())
    {
        return Err(Error::engine(
            "correct_record_type: executor plan binding does not match the claimed plan",
        ));
    }
    let mode = args.mode.as_deref().ok_or_else(|| Error::engine("correct_record_type: execute only through records_write.correct_record_type preparation"))?;
    if mode == "ineligible" {
        return Err(Error::engine("correct_record_type: prepared effect is ineligible; create a new bearer when appropriate"));
    }
    let confirmation_required = args.confirmation_required.unwrap_or(false);
    if (mode == "confirmed") != confirmation_required || !matches!(mode, "autonomous" | "confirmed")
    {
        return Err(Error::engine(
            "correct_record_type: invalid prepared correction mode",
        ));
    }
    let plan_id = args
        .plan_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| Error::engine("correct_record_type: executor plan_id is required"))?;
    let effect_digest = args
        .effect_digest
        .as_deref()
        .filter(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
        .ok_or_else(|| Error::engine("correct_record_type: executor effect_digest is required"))?;
    let mut transaction = PostgresDomainTransaction::begin(db).await?;
    let plan =
        postgres_correction_snapshot(&mut transaction, caller, &args, confirmation_required, true)
            .await?;
    let classification = plan.classification();
    let expected_mode = plan.execution_mode();
    if mode != expected_mode {
        return Err(Error::engine(
            "correct_record_type: eligibility changed; prepare again",
        ));
    }
    let payload = json!({
        "from":classification.current,
        "to":classification.target,
        "mode":mode,
        "reason":args.reason,
        "plan_id":plan_id,
        "effect_digest":format!("sha256:{effect_digest}"),
        "schema_state_revision":plan.schema_state_revision(),
        "confirmation_required":confirmation_required,
    });
    let tx = transaction.admitted("append record type correction")?;
    let (event_seq, event_id, created_at) = append_event_with_id(
        db,
        tx,
        &args.record_id,
        "record.type_corrected.v1",
        &payload,
        caller.actor(),
    )
    .await?;
    apply_projection(
        db,
        tx,
        &args.record_id,
        "record.type_corrected.v1",
        &payload,
        &created_at,
    )
    .await?;
    transaction.commit().await?;
    Ok(
        json!({"record_id":args.record_id,"type":plan.classification().target.record_type,"kind":plan.classification().target.kind,"mode":mode,"event_id":event_id,"event_seq":event_seq,"previous_seq":plan.previous_seq(),"body_digest":plan.body_digest()}),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateArgs {
    id: String,
    reason: String,
    #[serde(default, deserialize_with = "present")]
    name: Option<Value>,
    #[serde(default, deserialize_with = "present")]
    body: Option<Value>,
    #[serde(default, deserialize_with = "present")]
    summary: Option<Value>,
    #[serde(default, deserialize_with = "present")]
    lifecycle: Option<Value>,
    if_body_digest: Option<String>,
    if_unmodified_since: Option<String>,
    facets: Option<Map<String, Value>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MultiUpdateArgs {
    ids: Vec<String>,
    reason: String,
    facets: Option<Map<String, Value>>,
    #[serde(default, deserialize_with = "present")]
    maturity: Option<Value>,
    home_id: Option<String>,
    if_facets: Option<Map<String, Value>>,
    #[serde(default, deserialize_with = "present")]
    if_maturity: Option<Value>,
    if_home_id: Option<String>,
}

#[derive(Clone)]
struct PreparedMultiUpdate {
    index: usize,
    id: String,
    fields: Map<String, Value>,
    facet_sets: Vec<FacetWrite>,
    facet_unsets: Vec<String>,
}

impl PreparedMultiUpdate {
    fn changed(&self) -> bool {
        !self.fields.is_empty() || !self.facet_sets.is_empty() || !self.facet_unsets.is_empty()
    }
}

#[derive(Serialize)]
struct MultiUpdateIssue {
    index: usize,
    id: String,
    classification: &'static str,
    message: String,
}

fn validate_multi_maturity(field: &str, value: &Option<Value>) -> Result<()> {
    if value
        .as_ref()
        .is_some_and(|value| !matches!(value, Value::String(_) | Value::Null))
    {
        return Err(Error::engine(format!(
            "update_record: '{field}' must be a string or null"
        )));
    }
    Ok(())
}

fn postgres_multi_update_rejection(
    requested: usize,
    unchanged: usize,
    issues: Vec<MultiUpdateIssue>,
) -> Error {
    let conflicted = issues
        .iter()
        .filter(|issue| issue.classification == "conflict")
        .count();
    let failed = issues.len() - conflicted;
    let omitted = issues
        .len()
        .saturating_sub(MAX_MULTI_UPDATE_FAILURE_DETAILS);
    let details = issues
        .into_iter()
        .take(MAX_MULTI_UPDATE_FAILURE_DETAILS)
        .collect::<Vec<_>>();
    let receipt = json!({
        "requested": requested,
        "changed": 0,
        "unchanged": unchanged,
        "conflicted": conflicted,
        "failed": failed,
        "details": details,
        "details_truncated": omitted > 0,
        "omitted_detail_count": omitted,
    });
    let message = format!(
        "update_record: multi-target preflight rejected the atomic request; nothing was written; receipt={receipt}"
    );
    if failed == 0 {
        Error::conflict(message)
    } else {
        Error::engine(message)
    }
}

async fn postgres_facet_state(
    transaction: &mut PostgresDomainTransaction<'_>,
    record_id: &str,
    key: &str,
) -> Result<Option<(String, Option<String>)>> {
    let facets = transaction.db.qualified_table("facet_values")?;
    let events = transaction.db.qualified_table("content_events")?;
    let row = sqlx::query(&format!(
        "SELECT facet.value::text AS value, \
                (SELECT event.payload->>'vocab_ref' FROM {events} event \
                  WHERE event.record_id=facet.record_id \
                    AND event.type='facet.set' \
                    AND event.payload->>'key'=facet.key \
                    AND NOT COALESCE((event.payload->>'observation_only')::boolean,FALSE) \
                  ORDER BY event.seq DESC LIMIT 1) AS vocab_ref \
           FROM {facets} facet WHERE facet.record_id=$1 AND facet.key=$2"
    ))
    .bind(record_id)
    .bind(key)
    .fetch_optional(&mut **transaction.admitted("read multi-update facet state")?)
    .await?;
    row.map(|row| Ok((row.try_get("value")?, row.try_get("vocab_ref")?)))
        .transpose()
}

fn postgres_stored_facet_value(facet: &FacetWrite) -> Result<(String, Option<String>)> {
    Ok((
        serde_json::to_string(&facet.stored_value())?,
        facet.vocab_ref.clone(),
    ))
}

async fn postgres_collection_message_origin(
    transaction: &mut PostgresDomainTransaction<'_>,
    record_id: &str,
) -> Result<Option<String>> {
    let events = transaction.db.qualified_table("content_events")?;
    Ok(sqlx::query_scalar(&format!(
        "SELECT payload->>'collection_id' FROM {events} \
          WHERE record_id=$1 AND type='message.origin.declared.v1' \
          ORDER BY seq DESC LIMIT 1"
    ))
    .bind(record_id)
    .fetch_optional(&mut **transaction.admitted("read Message collection origin")?)
    .await?
    .flatten())
}

async fn refresh_postgres_policy_anchor_subtree(
    transaction: &mut PostgresDomainTransaction<'_>,
    record_id: &str,
) -> Result<()> {
    let records = transaction.db.qualified_table("records")?;
    let policies = transaction.db.qualified_table("record_policies")?;
    let updated = sqlx::query(&format!(
        "WITH RECURSIVE descendants(id, anchor_id) AS (\
           SELECT r.id, CASE WHEN own.record_id IS NOT NULL THEN r.id ELSE parent.policy_anchor_id END \
             FROM {records} r \
             LEFT JOIN {policies} own ON own.record_id=r.id \
             LEFT JOIN {records} parent ON parent.id=r.home_id \
            WHERE r.id=$1 \
           UNION ALL \
           SELECT child.id, CASE WHEN own.record_id IS NOT NULL THEN child.id ELSE descendants.anchor_id END \
             FROM {records} child \
             JOIN descendants ON child.home_id=descendants.id \
             LEFT JOIN {policies} own ON own.record_id=child.id) \
         UPDATE {records} r SET policy_anchor_id=descendants.anchor_id \
           FROM descendants WHERE r.id=descendants.id"
    ))
    .bind(record_id)
    .execute(&mut **transaction.admitted("refresh multi-update policy anchors")?)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(Error::engine(format!("record '{record_id}' not found")));
    }
    let missing: i64 = sqlx::query_scalar(&format!(
        "WITH RECURSIVE subtree(id) AS (\
           SELECT $1::text UNION ALL \
           SELECT r.id FROM {records} r JOIN subtree s ON r.home_id=s.id) \
         SELECT COUNT(*) FROM {records} WHERE id IN (SELECT id FROM subtree) AND policy_anchor_id IS NULL"
    ))
    .bind(record_id)
    .fetch_one(&mut **transaction.admitted("validate multi-update policy anchors")?)
    .await?;
    if missing != 0 {
        return Err(Error::engine(format!(
            "policy inheritance from '{record_id}' does not terminate at an explicit boundary"
        )));
    }
    Ok(())
}

fn optional_text(tool: &str, field: &str, value: &Option<Value>) -> Result<(bool, Option<String>)> {
    match value {
        None => Ok((false, None)),
        Some(Value::Null) => Ok((true, None)),
        Some(Value::String(value)) => Ok((true, Some(value.clone()))),
        Some(_) => Err(Error::engine(format!(
            "{tool}: '{field}' must be a string or null"
        ))),
    }
}

async fn update_record_multi(db: &PostgresDb, caller: &Caller, arguments: Value) -> Result<Value> {
    let args: MultiUpdateArgs = parse("update_record", arguments)?;
    if args.reason.trim().is_empty() {
        return Err(Error::engine("update_record: 'reason' must not be blank"));
    }
    if args.ids.is_empty() {
        return Err(Error::engine(
            "update_record: 'ids' must contain at least one record id",
        ));
    }
    if args.ids.len() > MAX_MULTI_UPDATE {
        return Err(Error::engine(format!(
            "update_record: at most {MAX_MULTI_UPDATE} ids may be updated per call"
        )));
    }
    let mut positions = BTreeMap::new();
    for (index, id) in args.ids.iter().enumerate() {
        if !crate::mcp::record_ref::is_canonical_uuid_v4_or_v7(id) {
            return Err(Error::engine(format!(
                "update_record: ids[{index}] must be an exact canonical lowercase UUID of version 4 or 7"
            )));
        }
        if let Some(first) = positions.insert(id.as_str(), index) {
            return Err(Error::engine(format!(
                "update_record: ids[{index}] duplicates ids[{first}]; multi-target ids must be unique"
            )));
        }
    }
    validate_multi_maturity("maturity", &args.maturity)?;
    validate_multi_maturity("if_maturity", &args.if_maturity)?;

    let facet_inputs = args.facets.clone().unwrap_or_default();
    if facet_inputs.is_empty() && args.maturity.is_none() && args.home_id.is_none() {
        return Err(Error::engine(
            "update_record: multi-target mode requires at least one non-empty facets patch, maturity, or home_id",
        ));
    }
    let mut facet_sets = Vec::new();
    let mut facet_unsets = Vec::new();
    for (key, value) in &facet_inputs {
        match crate::mcp::tools::lifecycle::parse_facet_entry("update_record", key, value, true)? {
            Some(facet) => facet_sets.push(facet),
            None => facet_unsets.push(key.clone()),
        }
    }
    let expected_facet_inputs = args.if_facets.clone().unwrap_or_default();
    if args.if_facets.is_some() && expected_facet_inputs.is_empty() {
        return Err(Error::engine(
            "update_record: 'if_facets' must not be empty when supplied",
        ));
    }
    let mut expected_facet_sets = Vec::new();
    let mut expected_facet_absent = Vec::new();
    for (key, value) in &expected_facet_inputs {
        match crate::mcp::tools::lifecycle::parse_facet_entry("update_record", key, value, true)? {
            Some(facet) => expected_facet_sets.push(facet),
            None => expected_facet_absent.push(key.clone()),
        }
    }

    let records = db.qualified_table("records")?;
    let mut transaction = PostgresDomainTransaction::begin(db).await?;
    // Avoid deadlocks between callers naming the same cohort in different
    // orders, and serialize the final-graph containment preflight with peers.
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended('native-ce:update-record-multi', 0))",
    )
    .execute(&mut **transaction.admitted("serialize multi-update preflight")?)
    .await?;
    let _locked = sqlx::query_scalar::<_, String>(&format!(
        "SELECT id FROM {records} WHERE id=ANY($1) ORDER BY id FOR UPDATE"
    ))
    .bind(&args.ids)
    .fetch_all(&mut **transaction.admitted("lock multi-update cohort")?)
    .await?;

    if let Some(new_home) = args.home_id.as_deref() {
        let destination = sqlx::query(&format!(
            "SELECT owner_id,record_type,kind,persistence,archived,deleted_at FROM {records} WHERE id=$1 FOR UPDATE"
        ))
        .bind(new_home)
        .fetch_optional(&mut **transaction.admitted("lock multi-update destination")?)
        .await?;
        let Some(destination) = destination else {
            return Err(Error::engine(format!(
                "update_record: multi-target relocation home {new_home} is unavailable; nothing was written"
            )));
        };
        require_edit(
            transaction.admitted("authorize multi-update destination")?,
            db,
            caller,
            new_home,
            destination.try_get("owner_id")?,
        )
        .await
        .map_err(|_| {
            Error::engine(format!(
                "update_record: multi-target relocation home {new_home} is unavailable; nothing was written"
            ))
        })?;
        if destination.try_get::<String, _>("record_type")? != "Collection"
            || destination.try_get::<String, _>("kind")? != "folder"
            || destination.try_get::<String, _>("persistence")? != "enduring"
            || destination.try_get::<bool, _>("archived")?
            || destination
                .try_get::<Option<DateTime<Utc>>, _>("deleted_at")?
                .is_some()
        {
            return Err(Error::engine(format!(
                "update_record: home {new_home} must be a live, unarchived, enduring Collection kind:folder; nothing was written"
            )));
        }
    }

    // Assess all source authority against the same pre-request projection.
    // No event or derived anchor is changed until this entire pass completes.
    let mut authorized = vec![false; args.ids.len()];
    let mut issues = Vec::new();
    for (index, id) in args.ids.iter().enumerate() {
        let row = sqlx::query(&format!(
            "SELECT owner_id,home_id FROM {records} WHERE id=$1 AND deleted_at IS NULL"
        ))
        .bind(id)
        .fetch_optional(&mut **transaction.admitted("read multi-update authorization state")?)
        .await?;
        let Some(row) = row else {
            issues.push(MultiUpdateIssue {
                index,
                id: id.clone(),
                classification: "unavailable",
                message: "record is unavailable".into(),
            });
            continue;
        };
        let current_home: Option<String> = row.try_get("home_id")?;
        let relocates = args
            .home_id
            .as_deref()
            .is_some_and(|desired| current_home.as_deref() != Some(desired));
        let authorization = if relocates {
            require_manage(
                transaction.admitted("authorize multi-update relocation source")?,
                db,
                caller,
                id,
                row.try_get("owner_id")?,
            )
            .await
        } else {
            require_edit(
                transaction.admitted("authorize multi-update source")?,
                db,
                caller,
                id,
                row.try_get("owner_id")?,
            )
            .await
        };
        match authorization {
            Ok(()) => authorized[index] = true,
            Err(_) => issues.push(MultiUpdateIssue {
                index,
                id: id.clone(),
                classification: "unavailable",
                message: "record is unavailable".into(),
            }),
        }
    }

    let schema_rows = crate::query::cascade::schema_config_rows_with(&mut transaction).await?;
    let touches_message_expectation =
        facet_inputs.contains_key(crate::message_expectation::EXPECTATION_FACET_KEY);
    let mut prepared = Vec::with_capacity(args.ids.len());
    let mut unchanged = 0usize;
    for (index, id) in args.ids.iter().enumerate() {
        if !authorized[index] {
            continue;
        }
        let row = sqlx::query(&format!(
            "SELECT record_type,kind,maturity,home_id FROM {records} WHERE id=$1 AND deleted_at IS NULL"
        ))
        .bind(id)
        .fetch_optional(&mut **transaction.admitted("read multi-update target state")?)
        .await?;
        let Some(row) = row else {
            issues.push(MultiUpdateIssue {
                index,
                id: id.clone(),
                classification: "unavailable",
                message: "record is unavailable".into(),
            });
            continue;
        };
        let record_type: String = row.try_get("record_type")?;
        let kind: String = row.try_get("kind")?;
        let current_maturity: Option<String> = row.try_get("maturity")?;
        let current_home: Option<String> = row.try_get("home_id")?;
        if touches_message_expectation && record_type == "Message" {
            issues.push(MultiUpdateIssue {
                index,
                id: id.clone(),
                classification: "invalid",
                message: "Message expectation is immutable sender-authored content".into(),
            });
            continue;
        }

        let resolution =
            crate::meta::kind::resolve_with(&mut transaction, &record_type, &kind).await?;
        let effective_kind = resolution.canonical_kind_for_write().unwrap_or(&kind);
        let mut governed_sets = facet_sets.clone();
        if let Err(error) = crate::domain_transaction::govern_facet_writes(
            &mut transaction,
            &schema_rows,
            "update_record",
            &record_type,
            Some(effective_kind),
            &mut governed_sets,
        )
        .await
        {
            issues.push(MultiUpdateIssue {
                index,
                id: id.clone(),
                classification: "invalid",
                message: error.to_string(),
            });
            continue;
        }
        let mut governed_expected = expected_facet_sets.clone();
        if let Err(error) = crate::domain_transaction::govern_facet_writes(
            &mut transaction,
            &schema_rows,
            "update_record",
            &record_type,
            Some(effective_kind),
            &mut governed_expected,
        )
        .await
        {
            issues.push(MultiUpdateIssue {
                index,
                id: id.clone(),
                classification: "invalid",
                message: error.to_string(),
            });
            continue;
        }

        let mut conflict = None;
        for expected in &governed_expected {
            let current = postgres_facet_state(&mut transaction, id, &expected.key).await?;
            if current.as_ref() != Some(&postgres_stored_facet_value(expected)?) {
                conflict = Some(format!(
                    "facet '{}' no longer has the expected current value",
                    expected.key
                ));
                break;
            }
        }
        if conflict.is_none() {
            for key in &expected_facet_absent {
                if postgres_facet_state(&mut transaction, id, key)
                    .await?
                    .is_some()
                {
                    conflict = Some(format!("facet '{key}' is no longer absent"));
                    break;
                }
            }
        }
        if conflict.is_none() {
            if let Some(expected) = args.if_maturity.as_ref() {
                let matches = match expected {
                    Value::String(expected) => current_maturity.as_deref() == Some(expected),
                    Value::Null => current_maturity.is_none(),
                    _ => unreachable!("multi maturity shape was validated"),
                };
                if !matches {
                    conflict = Some("maturity no longer has the expected current value".into());
                }
            }
        }
        if conflict.is_none()
            && args
                .if_home_id
                .as_deref()
                .is_some_and(|expected| current_home.as_deref() != Some(expected))
        {
            conflict = Some("home_id no longer has the expected current value".into());
        }
        if let Some(message) = conflict {
            issues.push(MultiUpdateIssue {
                index,
                id: id.clone(),
                classification: "conflict",
                message,
            });
            continue;
        }

        if let Some(new_home) = args.home_id.as_deref() {
            if record_type == "Message"
                && postgres_collection_message_origin(&mut transaction, id)
                    .await?
                    .is_some_and(|collection_id| collection_id != new_home)
            {
                issues.push(MultiUpdateIssue {
                    index,
                    id: id.clone(),
                    classification: "invalid",
                    message:
                        "a Collection-origin Message must remain filed in its authored Collection"
                            .into(),
                });
                continue;
            }
        }

        let mut changed_sets = Vec::new();
        for facet in governed_sets {
            let current = postgres_facet_state(&mut transaction, id, &facet.key).await?;
            if current.as_ref() != Some(&postgres_stored_facet_value(&facet)?) {
                changed_sets.push(facet);
            }
        }
        let mut changed_unsets = Vec::new();
        for key in &facet_unsets {
            if postgres_facet_state(&mut transaction, id, key)
                .await?
                .is_some()
            {
                changed_unsets.push(key.clone());
            }
        }
        let mut fields = Map::new();
        if let Some(desired) = args.maturity.as_ref() {
            let changed = match desired {
                Value::String(desired) => current_maturity.as_deref() != Some(desired),
                Value::Null => current_maturity.is_some(),
                _ => unreachable!("multi maturity shape was validated"),
            };
            if changed {
                fields.insert("maturity".into(), desired.clone());
            }
        }
        if let Some(desired) = args.home_id.as_deref() {
            if current_home.as_deref() != Some(desired) {
                fields.insert("home_id".into(), json!(desired));
            }
        }
        let target = PreparedMultiUpdate {
            index,
            id: id.clone(),
            fields,
            facet_sets: changed_sets,
            facet_unsets: changed_unsets,
        };
        if !target.changed() {
            unchanged += 1;
        }
        prepared.push(target);
    }

    // Evaluate containment against the complete proposed graph. Every cohort
    // member's outgoing home edge changes simultaneously for this purpose.
    if issues.is_empty() {
        if let Some(new_home) = args.home_id.as_deref() {
            let cyclic: Vec<String> = sqlx::query_scalar(&format!(
            "WITH RECURSIVE walk(start_id,id,path,cycle) AS (\
               SELECT r.id,r.id,ARRAY[r.id],FALSE FROM {records} r WHERE r.id=ANY($1) \
               UNION ALL \
               SELECT w.start_id,parent.id,w.path||parent.id,parent.id=ANY(w.path) \
                 FROM walk w \
                 JOIN {records} current ON current.id=w.id \
                 JOIN {records} parent ON parent.id=(CASE WHEN current.id=ANY($1) THEN $2 ELSE current.home_id END) \
                WHERE NOT w.cycle) \
             SELECT DISTINCT start_id FROM walk WHERE cycle"
        ))
        .bind(&args.ids)
        .bind(new_home)
        .fetch_all(&mut **transaction.admitted("preflight multi-update final containment graph")?)
        .await?;
            let cyclic = cyclic.into_iter().collect::<HashSet<_>>();
            for (index, id) in args.ids.iter().enumerate() {
                if authorized[index] && cyclic.contains(id) {
                    issues.push(MultiUpdateIssue {
                        index,
                        id: id.clone(),
                        classification: "invalid",
                        message: format!(
                            "homing {id} in {new_home} would create a containment cycle"
                        ),
                    });
                }
            }
            issues.sort_by_key(|issue| issue.index);
        }
    }
    if !issues.is_empty() {
        return Err(postgres_multi_update_rejection(
            args.ids.len(),
            unchanged,
            issues,
        ));
    }

    let id_refs = args.ids.iter().map(String::as_str).collect::<Vec<_>>();
    let required_before =
        crate::domain_transaction::required_violations(&mut transaction, &schema_rows, &id_refs)
            .await?;
    let changed = prepared.iter().filter(|target| target.changed()).count();
    for mut target in prepared.iter().filter(|target| target.changed()).cloned() {
        let field_event = !target.fields.is_empty();
        if field_event {
            target
                .fields
                .insert("reason".into(), json!(args.reason.clone()));
            let payload = Value::Object(target.fields);
            let tx = transaction.admitted("append multi-update fields")?;
            let (_, created_at) = append_event(
                db,
                tx,
                &target.id,
                "record.updated",
                &payload,
                caller.actor(),
            )
            .await?;
            apply_projection(db, tx, &target.id, "record.updated", &payload, &created_at).await?;
        }
        let mut first_facet = true;
        for facet in target.facet_sets {
            let mut spec =
                crate::domain_transaction::facet_set_spec(&target.id, &facet, caller.actor());
            if !field_event && first_facet {
                spec.payload["reason"] = json!(args.reason.clone());
            }
            first_facet = false;
            let tx = transaction.admitted("append multi-update facet set")?;
            let (_, created_at) = append_event(
                db,
                tx,
                &target.id,
                &spec.event_type,
                &spec.payload,
                caller.actor(),
            )
            .await?;
            apply_projection(
                db,
                tx,
                &target.id,
                &spec.event_type,
                &spec.payload,
                &created_at,
            )
            .await?;
        }
        for key in target.facet_unsets {
            let mut payload = json!({"key": key});
            if !field_event && first_facet {
                payload["reason"] = json!(args.reason.clone());
            }
            first_facet = false;
            let tx = transaction.admitted("append multi-update facet unset")?;
            let (_, created_at) =
                append_event(db, tx, &target.id, "facet.unset", &payload, caller.actor()).await?;
            apply_projection(db, tx, &target.id, "facet.unset", &payload, &created_at).await?;
        }
    }
    for target in prepared
        .iter()
        .filter(|target| target.fields.contains_key("home_id"))
    {
        refresh_postgres_policy_anchor_subtree(&mut transaction, &target.id).await?;
    }
    let required_after =
        crate::domain_transaction::required_violations(&mut transaction, &schema_rows, &id_refs)
            .await?;
    crate::domain_transaction::assert_required_not_worsened(
        "update_record",
        &required_before,
        &required_after,
    )?;
    transaction.commit().await?;

    let results = prepared
        .into_iter()
        .map(|target| {
            json!({
                "index": target.index,
                "id": target.id,
                "status": if target.changed() { "changed" } else { "unchanged" },
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "requested": args.ids.len(),
        "changed": changed,
        "unchanged": args.ids.len() - changed,
        "results": results,
    }))
}

async fn update_record(db: &PostgresDb, caller: &Caller, arguments: Value) -> Result<Value> {
    if arguments.get("ids").is_some() {
        Box::pin(update_record_multi(db, caller, arguments)).await
    } else {
        Box::pin(update_record_singular(db, caller, arguments)).await
    }
}

async fn update_record_singular(
    db: &PostgresDb,
    caller: &Caller,
    arguments: Value,
) -> Result<Value> {
    let args: UpdateArgs = parse("update_record", arguments)?;
    if args.reason.trim().is_empty() {
        return Err(Error::engine("update_record: 'reason' must not be blank"));
    }
    crate::mcp::tools::require_workspace_rename_authority(
        "update_record",
        caller,
        &args.id,
        args.name.as_ref(),
    )?;
    let mut facets = args
        .facets
        .unwrap_or_default()
        .into_iter()
        .map(|(key, value)| {
            crate::mcp::tools::lifecycle::parse_facet_entry("update_record", &key, &value, true)
                .map(|facet| (key, facet))
        })
        .collect::<Result<Vec<_>>>()?;
    let records = db.qualified_table("records")?;
    let mut transaction = PostgresDomainTransaction::begin(db).await?;
    let row = sqlx::query(&format!(
        "SELECT body, name, owner_id, updated_at, record_type, kind, lifecycle FROM {records} WHERE id=$1 AND deleted_at IS NULL FOR UPDATE"
    ))
    .bind(&args.id)
    .fetch_optional(&mut **transaction.admitted("lock update_record")?)
    .await?
    .ok_or_else(|| Error::engine(format!("update_record: record {} does not exist", args.id)))?;
    require_edit(
        transaction.admitted("authorize update_record")?,
        db,
        caller,
        &args.id,
        row.try_get("owner_id")?,
    )
    .await?;
    let current_body: Option<String> = row.try_get("body")?;
    // The whole-body guard is evaluated under the same `FOR UPDATE` row lock
    // that the write uses, so a concurrent writer cannot establish non-empty
    // content between the check and the append. Postgres mints no display
    // reference, so the refusal identifies the record by title and id.
    let guard_target = || crate::mcp::tools::lifecycle::BodyGuardTarget {
        id: args.id.clone(),
        name: row.try_get::<Option<String>, _>("name").unwrap_or_default(),
        display_reference: None,
        body_digest: crate::mcp::tools::lifecycle::body_digest(current_body.as_deref()),
        updated_at: row
            .try_get::<DateTime<Utc>, _>("updated_at")
            .map(|value| value.to_rfc3339_opts(SecondsFormat::AutoSi, true))
            .unwrap_or_default(),
    };
    if let Some(expected_raw) = args.if_unmodified_since.as_deref() {
        let expected = DateTime::parse_from_rfc3339(expected_raw)
            .map_err(|_| {
                Error::engine("update_record: 'if_unmodified_since' must be an RFC3339 timestamp")
            })?
            .with_timezone(&Utc);
        let current: DateTime<Utc> = row.try_get("updated_at")?;
        if expected != current {
            return Err(crate::mcp::tools::lifecycle::stale_unmodified_since_error(
                "update_record",
                &guard_target(),
            ));
        }
    }
    if crate::mcp::tools::lifecycle::whole_body_write_needs_guard(
        args.body.is_some(),
        current_body.as_deref(),
        args.if_body_digest.as_deref(),
        args.if_unmodified_since.as_deref(),
    ) {
        return Err(crate::mcp::tools::lifecycle::unguarded_body_write_error(
            "update_record",
            &guard_target(),
        ));
    }
    if let Some(expected) = args.if_body_digest.as_deref() {
        let actual = crate::mcp::tools::lifecycle::body_digest(current_body.as_deref());
        if !expected.eq_ignore_ascii_case(&actual) {
            return Err(crate::mcp::tools::lifecycle::stale_body_digest_error(
                "update_record",
                &guard_target(),
            ));
        }
    }
    let (set_name, name) = optional_text("update_record", "name", &args.name)?;
    let (set_body, body) = optional_text("update_record", "body", &args.body)?;
    let (set_summary, summary) = optional_text("update_record", "summary", &args.summary)?;
    let (set_lifecycle, lifecycle) = optional_text("update_record", "lifecycle", &args.lifecycle)?;
    let record_type: String = row.try_get("record_type")?;
    let kind: String = row.try_get("kind")?;
    let resolution = crate::meta::kind::resolve_with(&mut transaction, &record_type, &kind).await?;
    let effective_kind = resolution.canonical_kind_for_write().unwrap_or(&kind);
    let schema_rows = crate::query::cascade::schema_config_rows_with(&mut transaction).await?;
    let required_before = crate::domain_transaction::required_violations(
        &mut transaction,
        &schema_rows,
        &[args.id.as_str()],
    )
    .await?;
    let mut governed = facets
        .iter()
        .filter_map(|(_, facet)| facet.clone())
        .collect::<Vec<_>>();
    if let Some(lifecycle) = lifecycle.as_ref() {
        governed.push(FacetWrite {
            key: "lifecycle".into(),
            value: Value::String(lifecycle.clone()),
            vocab_ref: None,
        });
    }
    crate::domain_transaction::govern_facet_writes(
        &mut transaction,
        &schema_rows,
        "update_record",
        &record_type,
        Some(effective_kind),
        &mut governed,
    )
    .await?;
    for (_, facet) in &mut facets {
        if let Some(facet) = facet {
            facet.vocab_ref = governed
                .iter()
                .find(|checked| checked.key == facet.key)
                .and_then(|checked| checked.vocab_ref.clone());
        }
    }
    let mut payload = Map::new();
    payload.insert("reason".into(), json!(args.reason));
    for (key, set, value) in [
        ("name", set_name, &name),
        ("body", set_body, &body),
        ("summary", set_summary, &summary),
        ("lifecycle", set_lifecycle, &lifecycle),
    ] {
        if set {
            payload.insert(key.into(), json!(value));
        }
    }
    let tx = transaction.admitted("append update_record")?;
    let (_, created_at) = append_event(
        db,
        tx,
        &args.id,
        "record.updated",
        &Value::Object(payload.clone()),
        caller.actor(),
    )
    .await?;
    apply_projection(
        db,
        tx,
        &args.id,
        "record.updated",
        &Value::Object(payload),
        &created_at,
    )
    .await?;
    for (key, facet) in facets {
        let spec = match facet {
            Some(facet) => {
                crate::domain_transaction::facet_set_spec(&args.id, &facet, caller.actor())
            }
            None => AppendSpec {
                record_id: args.id.clone(),
                event_type: "facet.unset".into(),
                payload: json!({"key":key}),
                actor: Some(caller.actor().into()),
            },
        };
        let tx = transaction.admitted("append governed update_record facet")?;
        let (_, created_at) = append_event(
            db,
            tx,
            &args.id,
            &spec.event_type,
            &spec.payload,
            caller.actor(),
        )
        .await?;
        apply_projection(
            db,
            tx,
            &args.id,
            &spec.event_type,
            &spec.payload,
            &created_at,
        )
        .await?;
    }
    let required_after = crate::domain_transaction::required_violations(
        &mut transaction,
        &schema_rows,
        &[args.id.as_str()],
    )
    .await?;
    crate::domain_transaction::assert_required_not_worsened(
        "update_record",
        &required_before,
        &required_after,
    )?;
    transaction.commit().await?;
    read_record(db, caller, &args.id).await?.ok_or_else(|| {
        Error::engine(format!(
            "update_record: record {} not readable after write",
            args.id
        ))
    })
}

async fn require_edit(
    tx: &mut Transaction<'_, Postgres>,
    db: &PostgresDb,
    caller: &Caller,
    record_id: &str,
    owner_id: Option<String>,
) -> Result<()> {
    let records = db.qualified_table("records")?;
    let policies = db.qualified_table("record_policies")?;
    let record_type: Option<String> = sqlx::query_scalar(&format!(
        "SELECT record.record_type FROM {records} record JOIN {policies} policy ON policy.record_id=record.policy_anchor_id WHERE record.id=$1 AND record.deleted_at IS NULL AND NOT(record.record_type='Annotation' OR (record.record_type='Document' AND record.kind='attachment'))"
    ))
    .bind(record_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(record_type) = record_type else {
        return Err(Error::engine(
            "record authorization shape is invalid or unsupported",
        ));
    };
    if caller.is_trusted_local() {
        return Ok(());
    }
    let bindings = db.qualified_table("bindings")?;
    let owns: bool = sqlx::query_scalar(&format!(
        "SELECT EXISTS(SELECT 1 FROM {bindings} \
         WHERE record_id=$1 AND system='account' AND identifier=$2 AND is_canonical=TRUE)"
    ))
    .bind(owner_id)
    .bind(caller.credential())
    .fetch_one(&mut **tx)
    .await?;
    if owns {
        Ok(())
    } else if record_type == "Message" {
        // Addressed recipients have view authority, never sender authority.
        // Treat a recipient mutation exactly like an absent record so the
        // audience projection cannot become an edit-capability escalation.
        Err(Error::engine("record does not exist"))
    } else {
        let entries = db.qualified_table("policy_entries")?;
        let allowed: bool = sqlx::query_scalar(&format!(
            "SELECT EXISTS(SELECT 1 FROM {records} record JOIN {entries} entry ON entry.policy_anchor_id=record.policy_anchor_id WHERE record.id=$1 AND entry.effect='allow' AND entry.capability IN ('edit','manage') AND ((entry.subject_kind='account' AND entry.subject_id=$2) OR (entry.subject_kind='members' AND entry.subject_id='native:members')))"
        ))
        .bind(record_id)
        .bind(caller.credential())
        .fetch_one(&mut **tx)
        .await?;
        if allowed {
            Ok(())
        } else {
            Err(Error::engine("record does not exist"))
        }
    }
}

async fn require_manage(
    tx: &mut Transaction<'_, Postgres>,
    db: &PostgresDb,
    caller: &Caller,
    record_id: &str,
    owner_id: Option<String>,
) -> Result<()> {
    if caller.is_trusted_local() {
        return Ok(());
    }
    let records = db.qualified_table("records")?;
    let policies = db.qualified_table("record_policies")?;
    let valid: bool = sqlx::query_scalar(&format!(
        "SELECT EXISTS(SELECT 1 FROM {records} record JOIN {policies} policy ON policy.record_id=record.policy_anchor_id WHERE record.id=$1 AND record.deleted_at IS NULL AND NOT(record.record_type='Annotation' OR (record.record_type='Document' AND record.kind='attachment')))"
    ))
    .bind(record_id)
    .fetch_one(&mut **tx)
    .await?;
    if !valid {
        return Err(Error::engine("record does not exist"));
    }
    let bindings = db.qualified_table("bindings")?;
    let owns: bool = sqlx::query_scalar(&format!(
        "SELECT EXISTS(SELECT 1 FROM {bindings} WHERE record_id=$1 AND system='account' AND identifier=$2 AND is_canonical=TRUE)"
    ))
    .bind(owner_id)
    .bind(caller.credential())
    .fetch_one(&mut **tx)
    .await?;
    if owns {
        return Ok(());
    }
    let entries = db.qualified_table("policy_entries")?;
    let allowed: bool = sqlx::query_scalar(&format!(
        "SELECT EXISTS(SELECT 1 FROM {records} record JOIN {entries} entry ON entry.policy_anchor_id=record.policy_anchor_id WHERE record.id=$1 AND entry.effect='allow' AND entry.capability='manage' AND entry.subject_kind='account' AND entry.subject_id=$2)"
    ))
    .bind(record_id)
    .bind(caller.credential())
    .fetch_one(&mut **tx)
    .await?;
    if allowed {
        Ok(())
    } else {
        Err(Error::engine("record does not exist"))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveArgs {
    id: String,
    archived: Option<bool>,
    reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeleteArgs {
    id: String,
    reason: String,
    #[serde(default)]
    if_content_seq: Option<i64>,
}

async fn delete_record(db: &PostgresDb, caller: &Caller, arguments: Value) -> Result<Value> {
    let args: DeleteArgs = parse("delete_record", arguments)?;
    let mut port = PostgresDomainTransaction::begin(db).await?;
    let result = crate::domain_transaction::delete_record(
        &mut port,
        attachment_principal(caller),
        &args.id,
        &args.reason,
        caller.actor(),
        args.if_content_seq,
    )
    .await?;
    port.commit().await?;
    Ok(result)
}

async fn archive_record(db: &PostgresDb, caller: &Caller, arguments: Value) -> Result<Value> {
    let args: ArchiveArgs = parse("archive_record", arguments)?;
    if args.reason.trim().is_empty() {
        return Err(Error::engine("archive_record: 'reason' must not be blank"));
    }
    let want = args.archived.unwrap_or(true);
    let records = db.qualified_table("records")?;
    let events = db.qualified_table("content_events")?;
    let mut tx = db.pool.begin().await?;
    let row = sqlx::query(&format!(
        "SELECT archived, owner_id FROM {records} WHERE id=$1 AND deleted_at IS NULL FOR UPDATE"
    ))
    .bind(&args.id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| Error::engine(format!("archive_record: record {} does not exist", args.id)))?;
    require_edit(&mut tx, db, caller, &args.id, row.try_get("owner_id")?).await?;
    let previous_seq: Option<i64> =
        sqlx::query_scalar(&format!("SELECT MAX(seq) FROM {events} WHERE record_id=$1"))
            .bind(&args.id)
            .fetch_one(&mut *tx)
            .await?;
    let current: bool = row.try_get("archived")?;
    if current == want {
        tx.rollback().await?;
        return Ok(json!({
            "id": args.id, "archived": want, "changed": false, "previous_seq": previous_seq
        }));
    }
    let event_type = if want { "facet.set" } else { "facet.unset" };
    let payload = json!({ "key": "archived", "value": if want { Value::String("true".into()) } else { Value::Null } });
    let (_, created_at) =
        append_event(db, &mut tx, &args.id, event_type, &payload, caller.actor()).await?;
    apply_projection(db, &mut tx, &args.id, event_type, &payload, &created_at).await?;
    tx.commit().await?;
    db.complete_realtime_commit();
    Ok(json!({
        "id": args.id, "archived": want, "changed": true, "previous_seq": previous_seq
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryArgs {
    record_id: Option<String>,
    #[serde(rename = "after_local_seq", alias = "after_seq")]
    after_seq: Option<i64>,
    limit: Option<i64>,
    #[serde(default)]
    detail: crate::mcp::tools::history::HistoryDetail,
}

async fn get_history(db: &PostgresDb, caller: &Caller, arguments: Value) -> Result<Value> {
    let args: HistoryArgs = parse("get_history", arguments)?;
    let Some(record_id) = args.record_id.as_deref() else {
        // Whole-log history requires event-by-event authorization and Message
        // payload redaction. Until that shared contract is qualified for this
        // backend, fail closed instead of returning an unfiltered event log.
        return Err(Error::engine(
            "get_history: Postgres requires record_id; whole-log history is not qualified",
        ));
    };
    // Authorization and event selection must observe one database instant.
    // REPEATABLE READ closes the revocation TOCTOU window between these two
    // adapter-owned statements without relying on the caller to coordinate a
    // snapshot or on a broader storage abstraction.
    let mut tx = db.pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await?;
    if !history_record_visible_in(&mut tx, db, caller, record_id).await? {
        tx.rollback().await?;
        return Err(Error::engine(format!(
            "get_history: record {record_id} does not exist"
        )));
    }
    let events = db.qualified_table("content_events")?;
    let causal_frontier = db.qualified_table("content_event_causal_frontier")?;
    let limit = args.limit.unwrap_or(100).clamp(1, 1000) as usize;
    let mut result = Vec::new();
    // Attribution follows visibility of the actor's person record, the same
    // question this reader already asks of the records it returns. Decided once
    // per distinct actor: a page holds many events but few actors.
    let mut disclosable: HashMap<String, bool> = HashMap::new();
    let mut scan_after = args.after_seq.unwrap_or(0);
    let mut exhausted = false;
    while result.len() <= limit && !exhausted {
        let rows = sqlx::query(&format!(
            "SELECT seq, id, record_id, type, payload::text AS payload, actor, run_key, parent_key, intent, created_at::text AS created_at, \
                    causal_envelope_version,causal_status,\
                    COALESCE((SELECT jsonb_agg(parent_event_id ORDER BY parent_event_id) FROM {causal_frontier} frontier WHERE frontier.event_id={events}.id),'[]'::jsonb)::text AS causal_frontier \
             FROM {events} WHERE seq > $1 AND record_id=$2 \
             ORDER BY seq LIMIT $3"
        ))
        .bind(scan_after)
        .bind(record_id)
        .bind(1001_i64)
        .fetch_all(&mut *tx)
        .await?;
        exhausted = rows.len() < 1001;
        for row in rows {
            scan_after = row.try_get::<i64, _>("seq")?;
            let event_type = row.try_get::<String, _>("type")?;
            if row.try_get::<i64, _>("causal_envelope_version")? != 1 {
                return Err(Error::engine("unsupported stored causal envelope version"));
            }
            let causal_status: String = row.try_get("causal_status")?;
            let causal_frontier: Value =
                serde_json::from_str(&row.try_get::<String, _>("causal_frontier")?)?;
            let mut payload: Value = serde_json::from_str(&row.try_get::<String, _>("payload")?)?;
            if !postgres_history_event_visible(&mut tx, db, caller, &event_type, &payload).await? {
                continue;
            }
            let mut actor: Option<String> = row.try_get("actor")?;
            let mut run_key: Option<String> = row.try_get("run_key")?;
            let mut parent_key: Option<String> = row.try_get("parent_key")?;
            let mut intent: Option<String> = row.try_get("intent")?;
            if !caller.is_trusted_local() {
                crate::domain_transaction::redact_history_payload_for_member(
                    &mut payload,
                    caller.credential(),
                );
                let disclose = match actor.as_deref() {
                    Some(actor) => {
                        if let Some(decided) = disclosable.get(actor) {
                            *decided
                        } else {
                            let decided = actor_disclosable_in(&mut tx, db, caller, actor).await?;
                            disclosable.insert(actor.to_string(), decided);
                            decided
                        }
                    }
                    None => false,
                };
                if !disclose {
                    actor = None;
                    run_key = None;
                    parent_key = None;
                    intent = None;
                }
            }
            result.push(crate::mcp::tools::history::shape_history_event(
                json!({
                    "local_seq": scan_after,
                    "id": row.try_get::<String, _>("id")?,
                    "record_id": row.try_get::<String, _>("record_id")?,
                    "type": event_type,
                    "payload": payload,
                    "actor": actor,
                    "run_key": run_key,
                    "parent_key": parent_key,
                    "intent": intent,
                    "created_at": row.try_get::<String, _>("created_at")?,
                    "causal_envelope": {
                        "version": "v1",
                        "status": causal_status,
                        "frontier": causal_frontier,
                    },
                }),
                args.detail,
            ));
            if result.len() > limit {
                break;
            }
        }
    }
    let has_more = result.len() > limit;
    if has_more {
        result.pop();
    }
    let next_after_seq = has_more
        .then(|| {
            result
                .last()
                .and_then(|event| event.get("local_seq"))
                .and_then(Value::as_i64)
        })
        .flatten();
    tx.commit().await?;
    Ok(json!({
        "local_database_id": db.logical_database_id(),
        "events": result,
        "next_after_local_seq": next_after_seq,
        "order": "oldest_first",
        "representation": crate::mcp::tools::history::history_representation(args.detail),
    }))
}

async fn postgres_history_event_visible(
    tx: &mut Transaction<'_, Postgres>,
    db: &PostgresDb,
    caller: &Caller,
    event_type: &str,
    payload: &Value,
) -> Result<bool> {
    if matches!(
        event_type,
        "reconciliation.recorded.v1" | "unit.superseded.v1" | "receipt.dependency_audited.v1"
    ) {
        return Ok(false);
    }
    if event_type != "occurrence.bound.v1" {
        return Ok(true);
    }
    let Ok(payload) =
        serde_json::from_value::<crate::events::OccurrenceBoundPayload>(payload.clone())
    else {
        return Ok(false);
    };
    history_record_visible_in(tx, db, caller, &payload.artefact_revision.subject_id).await
}

/// Whether an event's `actor` may be disclosed to `caller`.
///
/// A name is identity, and identity is disclosed on the same terms as any other
/// record: by visibility of the person the account is bound to, asked with the
/// same question this reader already asks of the records it returns. Being the
/// actor is the trivial case rather than the rule, and an actor bound to no
/// readable person stays hidden.
async fn actor_disclosable_in(
    tx: &mut Transaction<'_, Postgres>,
    db: &PostgresDb,
    caller: &Caller,
    actor: &str,
) -> Result<bool> {
    if actor == caller.credential() {
        return Ok(true);
    }
    let bindings = db.qualified_table("bindings")?;
    let person: Option<String> = sqlx::query_scalar(&format!(
        "SELECT record_id FROM {bindings} WHERE system='account' AND identifier=$1 LIMIT 1"
    ))
    .bind(actor)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(person) = person else {
        return Ok(false);
    };
    history_record_visible_in(tx, db, caller, &person).await
}

async fn history_record_visible_in(
    tx: &mut Transaction<'_, Postgres>,
    db: &PostgresDb,
    caller: &Caller,
    id: &str,
) -> Result<bool> {
    let records = db.qualified_table("records")?;
    let row = sqlx::query(&format!(
        "SELECT record_type, kind, owner_id, policy_anchor_id FROM {records} WHERE id=$1"
    ))
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(false);
    };
    let record_type: String = row.try_get("record_type")?;
    let kind: String = row.try_get("kind")?;
    let owner_id: Option<String> = row.try_get("owner_id")?;
    let bindings = db.qualified_table("bindings")?;
    let is_attachment = record_type == "Document" && kind == "attachment";
    if is_attachment && !attachment_bearer_visible_in(tx, db, caller, id).await? {
        return Ok(false);
    }
    if !is_attachment {
        let policy_anchor_id: Option<String> = row.try_get("policy_anchor_id")?;
        let Some(policy_anchor_id) = policy_anchor_id else {
            if !caller.is_trusted_local() {
                return Ok(false);
            }
            return Err(Error::engine(format!(
                "record {id} has no effective policy anchor"
            )));
        };
        let policies = db.qualified_table("record_policies")?;
        let anchor_is_explicit: bool = sqlx::query_scalar(&format!(
            "SELECT EXISTS(SELECT 1 FROM {policies} WHERE record_id=$1)"
        ))
        .bind(&policy_anchor_id)
        .fetch_one(&mut **tx)
        .await?;
        if !anchor_is_explicit {
            if !caller.is_trusted_local() {
                return Ok(false);
            }
            return Err(Error::engine(format!(
                "record {id} has an invalid effective policy anchor"
            )));
        }
        if !caller.is_trusted_local() {
            let owns: bool = sqlx::query_scalar(&format!(
                "SELECT EXISTS(SELECT 1 FROM {bindings} WHERE record_id=$1 AND system='account' AND identifier=$2 AND is_canonical=TRUE)"
            ))
            .bind(&owner_id)
            .bind(caller.credential())
            .fetch_one(&mut **tx)
            .await?;
            if !owns {
                let entries = db.qualified_table("policy_entries")?;
                let allowed: bool = sqlx::query_scalar(&format!(
                    "SELECT EXISTS(SELECT 1 FROM {entries} WHERE policy_anchor_id=$1 AND effect='allow' AND capability IN ('view','edit','manage') AND ((subject_kind='account' AND subject_id=$2) OR (subject_kind='members' AND subject_id='native:members')))"
                ))
                .bind(&policy_anchor_id)
                .bind(caller.credential())
                .fetch_one(&mut **tx)
                .await?;
                if !allowed {
                    return Ok(false);
                }
            }
        }
    }
    // Attachment authorization is complete after the live bearer fold above.
    // Annotations remain outside this backend's derived-artifact contract.
    if record_type == "Annotation" {
        return Err(Error::engine(format!(
            "record {id} uses derived artifact authorization not qualified for Postgres"
        )));
    }
    if !caller.is_trusted_local() && record_type == "Message" {
        let audience = db.qualified_table("message_audience")?;
        let visible: bool = sqlx::query_scalar(&format!(
            "SELECT EXISTS(SELECT 1 FROM {bindings} b WHERE b.record_id=$1 AND b.system='account' AND b.identifier=$3 AND b.is_canonical=TRUE) OR EXISTS(SELECT 1 FROM {audience} a WHERE a.message_id=$2 AND a.account_id=$3)"
        ))
        .bind(owner_id)
        .bind(id)
        .bind(caller.credential())
        .fetch_one(&mut **tx)
        .await?;
        if !visible {
            return Ok(false);
        }
    }
    Ok(true)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "action", rename_all = "snake_case")]
enum ManageLinksArgs {
    Add {
        source_id: String,
        target_id: String,
        relationship: String,
        note: Option<String>,
    },
    // The fields spell out the accepted wire shape for deny_unknown_fields even
    // though the action itself fails closed until removal is qualified.
    #[allow(dead_code)]
    Remove {
        source_id: String,
        target_id: String,
        relationship: String,
    },
    List {
        record_id: String,
    },
}

/// Bounded `manage_links` slice: event-sourced link addition and visible
/// listing. `remove` fails closed until link removal is qualified for this
/// backend; the SQLite reference remains the full-semantics oracle.
async fn manage_links(db: &PostgresDb, caller: &Caller, arguments: Value) -> Result<Value> {
    match parse("manage_links", arguments)? {
        ManageLinksArgs::Add {
            source_id,
            target_id,
            relationship,
            note,
        } => {
            if relationship.trim().is_empty() {
                return Err(Error::engine(
                    "manage_links: link relationship must contain non-whitespace text",
                ));
            }
            if read_record(db, caller, &target_id).await?.is_none() {
                return Err(Error::engine(format!(
                    "manage_links: record {target_id} does not exist"
                )));
            }
            let records = db.qualified_table("records")?;
            let mut tx = db.pool.begin().await?;
            let row = sqlx::query(&format!(
                "SELECT owner_id FROM {records} WHERE id=$1 AND deleted_at IS NULL FOR UPDATE"
            ))
            .bind(&source_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| {
                Error::engine(format!("manage_links: record {source_id} does not exist"))
            })?;
            require_edit(&mut tx, db, caller, &source_id, row.try_get("owner_id")?).await?;
            let payload = link_added_payload(&source_id, &target_id, &relationship, note);
            let (_, created_at) = append_event(
                db,
                &mut tx,
                &source_id,
                "link.added",
                &payload,
                caller.actor(),
            )
            .await?;
            apply_projection(db, &mut tx, &source_id, "link.added", &payload, &created_at).await?;
            tx.commit().await?;
            db.complete_realtime_commit();
            Ok(json!({
                "status": "added",
                "source_id": source_id,
                "target_id": target_id,
                "relationship": relationship,
            }))
        }
        ManageLinksArgs::Remove { .. } => Err(Error::engine(
            "manage_links: the remove action is not yet qualified for Postgres",
        )),
        ManageLinksArgs::List { record_id } => {
            if read_record(db, caller, &record_id).await?.is_none() {
                return Err(Error::engine(format!(
                    "manage_links: record {record_id} does not exist"
                )));
            }
            let links = db.qualified_table("links")?;
            let rows = sqlx::query(&format!(
                "SELECT id, source_id, target_id, relationship, note, created_at \
                 FROM {links} WHERE source_id=$1 OR target_id=$1 ORDER BY id COLLATE \"C\""
            ))
            .bind(&record_id)
            .fetch_all(&db.pool)
            .await?;
            let mut links_out = Vec::new();
            let mut links_in = Vec::new();
            for row in rows {
                let source_id: String = row.try_get("source_id")?;
                let target_id: String = row.try_get("target_id")?;
                let other = if source_id == record_id {
                    &target_id
                } else {
                    &source_id
                };
                if !caller.is_trusted_local() && read_record(db, caller, other).await?.is_none() {
                    continue;
                }
                let outbound = source_id == record_id;
                let value = json!({
                    "id": row.try_get::<String, _>("id")?,
                    "source_id": source_id,
                    "target_id": target_id,
                    "relationship": row.try_get::<String, _>("relationship")?,
                    "note": row.try_get::<Option<String>, _>("note")?,
                    "created_at": row.try_get::<DateTime<Utc>, _>("created_at")?
                        .to_rfc3339_opts(SecondsFormat::AutoSi, true),
                });
                if outbound {
                    links_out.push(value);
                } else {
                    links_in.push(value);
                }
            }
            Ok(json!({
                "record_id": record_id,
                "links_out": links_out,
                "links_in": links_in,
            }))
        }
    }
}

/// `to_char` expression rendering one physical timestamptz column in the
/// portable text spelling the shared domain statements read (UTC RFC3339
/// with milliseconds, matching `store::now_iso`).
fn portable_timestamp_text(column: &str) -> String {
    format!("to_char({column} AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"')")
}

/// Install per-transaction temporary views presenting this schema's physical
/// tables in the portable logical shapes the shared domain statements expect
/// (SQLite spellings: `records.type`, text timestamps, integer booleans, raw
/// facet text, and an empty `semantic_units` relation because this backend
/// projects no semantic Units). The views are read-only compatibility
/// projections scoped to the session; every write stays on the qualified
/// physical tables. `CREATE OR REPLACE` re-points a pooled connection's views
/// at the current logical schema before any reviewed statement runs.
async fn install_portable_relation_views(
    db: &PostgresDb,
    tx: &mut Transaction<'_, Postgres>,
) -> Result<()> {
    let records = db.qualified_table("records")?;
    let content_events = db.qualified_table("content_events")?;
    let meta_events = db.qualified_table("meta_events")?;
    let links = db.qualified_table("links")?;
    let facet_values = db.qualified_table("facet_values")?;
    let blobs = db.qualified_table("blobs")?;
    let bindings = db.qualified_table("bindings")?;
    let message_audience = db.qualified_table("message_audience")?;
    let record_policies = db.qualified_table("record_policies")?;
    let policy_entries = db.qualified_table("policy_entries")?;
    let vocabularies = db.qualified_table("vocabularies")?;
    let vocabulary_values = db.qualified_table("vocabulary_values")?;
    let schema_config = db.qualified_table("schema_config")?;
    let instruction_bindings = db.qualified_table("instruction_bindings")?;
    let onboarding_programmes = db.qualified_table("onboarding_programmes")?;
    let onboarding_programme_sources = db.qualified_table("onboarding_programme_sources")?;
    let notification_candidates = db.qualified_table("notification_candidates")?;
    let annotation_targets = db.qualified_table("annotation_targets")?;
    let annotation_targets_exist: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(&annotation_targets)
        .fetch_one(&mut **tx)
        .await?;
    let deleted_at = portable_timestamp_text("r.deleted_at");
    let record_created_at = portable_timestamp_text("r.created_at");
    let record_updated_at = portable_timestamp_text("r.updated_at");
    let last_activity_at = portable_timestamp_text("e.created_at");
    let created_at = portable_timestamp_text("created_at");
    let updated_at = portable_timestamp_text("updated_at");
    let annotation_targets_view = if annotation_targets_exist {
        format!(
            "CREATE OR REPLACE TEMPORARY VIEW annotation_targets AS \
             SELECT annotation_id,target_record_id,source_slot FROM {annotation_targets}"
        )
    } else {
        "CREATE OR REPLACE TEMPORARY VIEW annotation_targets AS \
         SELECT NULL::text AS annotation_id,NULL::text AS target_record_id,NULL::text AS source_slot WHERE FALSE"
            .to_string()
    };
    let statements = [
        format!(
            "CREATE OR REPLACE TEMPORARY VIEW meta_events AS \
             SELECT seq FROM {meta_events}"
        ),
        format!(
            "CREATE OR REPLACE TEMPORARY VIEW content_events AS \
             SELECT seq, record_id, actor, run_key, {created_at} AS created_at \
             FROM {content_events}"
        ),
        format!(
            "CREATE OR REPLACE TEMPORARY VIEW records AS \
             SELECT r.id, r.record_type AS type, r.kind, COALESCE(r.name,'') AS name, r.body, r.home_id, \
                    r.summary, r.lifecycle, r.owner_id, r.policy_anchor_id, r.persistence, r.maturity, \
                    COALESCE((SELECT {last_activity_at} FROM {content_events} e \
                               WHERE e.record_id=r.id \
                                 AND e.type NOT IN ('reconciliation.recorded.v1','unit.superseded.v1','receipt.dependency_audited.v1') \
                               ORDER BY e.seq DESC LIMIT 1), {record_created_at}) AS last_activity_at, \
                    {deleted_at} AS deleted_at, {record_created_at} AS created_at, \
                    {record_updated_at} AS updated_at \
             FROM {records} r"
        ),
        format!(
            "CREATE OR REPLACE TEMPORARY VIEW links AS \
             SELECT id, source_id, target_id, relationship, note, {created_at} AS created_at \
             FROM {links}"
        ),
        format!(
            "CREATE OR REPLACE TEMPORARY VIEW facet_values AS \
             SELECT record_id, key, \
                    CASE WHEN jsonb_typeof(value)='string' THEN value #>> '{{}}' \
                         ELSE value::text END AS value, \
                    CASE WHEN btrim(value #>> '{{}}', E' \\t\\n\\r') ~ '^-?(0|[1-9][0-9]*)(\\.[0-9]+)?([eE][+-]?[0-9]+)?$' THEN \
                         CASE WHEN pg_input_is_valid(btrim(value #>> '{{}}', E' \\t\\n\\r'), 'double precision') \
                              THEN btrim(value #>> '{{}}', E' \\t\\n\\r')::double precision \
                              WHEN pg_input_is_valid(btrim(value #>> '{{}}', E' \\t\\n\\r'), 'numeric') THEN \
                                   CASE WHEN abs(btrim(value #>> '{{}}', E' \\t\\n\\r')::numeric) < 1::numeric \
                                        THEN CASE WHEN left(btrim(value #>> '{{}}', E' \\t\\n\\r'),1)='-' \
                                                  THEN '-0'::double precision ELSE 0::double precision END \
                                        ELSE NULL::double precision END \
                              ELSE NULL::double precision END \
                         ELSE NULL::double precision END AS value_num, \
                    (SELECT event.payload->>'vocab_ref' FROM {content_events} event \
                      WHERE event.record_id=facet.record_id \
                        AND event.type='facet.set' \
                        AND event.payload->>'key'=facet.key \
                        AND NOT COALESCE((event.payload->>'observation_only')::boolean,FALSE) \
                      ORDER BY event.seq DESC LIMIT 1) AS vocab_ref \
             FROM {facet_values} facet \
             UNION ALL SELECT id AS record_id, 'archived' AS key, 'true' AS value, \
                              NULL::double precision AS value_num, \
                              NULL::text AS vocab_ref FROM {records} WHERE archived"
        ),
        format!(
            "CREATE OR REPLACE TEMPORARY VIEW facet_observations AS \
             WITH candidates AS (SELECT event.record_id,event.seq,event.type,event.payload,event.created_at, \
                    COALESCE(event.payload->>'as_of', {event_created_at}) AS as_of \
                    FROM {content_events} event \
                    WHERE event.type IN ('facet.set','facet.unset') \
                      AND event.payload->>'key' IS NOT NULL \
                      AND event.payload->>'key' NOT IN ('lifecycle','owner','persistence','maturity')), \
                  corrected AS (SELECT DISTINCT ON(record_id,payload->>'key',as_of) \
                    record_id,seq,type,payload,created_at,as_of FROM candidates \
                    ORDER BY record_id,payload->>'key',as_of,seq DESC) \
             SELECT 'fo:'||record_id||':'||(payload->>'key')||':'||as_of AS id,record_id, \
                    payload->>'key' AS key,CASE WHEN type='facet.set' THEN payload->>'value' ELSE NULL END AS value, \
                    CASE WHEN type='facet.set' THEN 'set' ELSE 'unset' END AS op, \
                    CASE WHEN type='facet.set' THEN payload->>'vocab_ref' ELSE NULL END AS vocab_ref, \
                    as_of,{observed_at} AS observed_at,seq AS event_seq FROM corrected",
            event_created_at = portable_timestamp_text("event.created_at"),
            observed_at = portable_timestamp_text("created_at"),
        ),
        format!(
            "CREATE OR REPLACE TEMPORARY VIEW blobs AS \
             SELECT id, mime, size_bytes, sha256, original_filename, storage_tier, \
                    {created_at} AS created_at \
             FROM {blobs}"
        ),
        format!(
            "CREATE OR REPLACE TEMPORARY VIEW bindings AS \
             SELECT record_id, system, identifier, \
                    CASE WHEN is_canonical THEN 1 ELSE 0 END AS is_canonical \
             FROM {bindings}"
        ),
        format!(
            "CREATE OR REPLACE TEMPORARY VIEW message_audiences AS \
             SELECT message_id, account_id AS principal_id FROM {message_audience}"
        ),
        format!(
            "CREATE OR REPLACE TEMPORARY VIEW record_policies AS \
             SELECT record_id FROM {record_policies}"
        ),
        format!(
            "CREATE OR REPLACE TEMPORARY VIEW policy_entries AS \
             SELECT policy_anchor_id, subject_kind, subject_id, effect, capability \
             FROM {policy_entries}"
        ),
        "CREATE OR REPLACE TEMPORARY VIEW semantic_units AS \
         SELECT NULL::text AS unit_id, NULL::text AS authority_bearer_record_id WHERE FALSE"
            .to_string(),
        format!(
            "CREATE OR REPLACE TEMPORARY VIEW vocabularies AS \
             SELECT id, name, {created_at} AS created_at FROM {vocabularies}"
        ),
        format!(
            "CREATE OR REPLACE TEMPORARY VIEW vocabulary_values AS \
             SELECT id, vocabulary_id, value, gloss, status, ordinal, terminality, \
                    metadata::text AS metadata, alias_of \
             FROM {vocabulary_values}"
        ),
        format!(
            "CREATE OR REPLACE TEMPORARY VIEW schema_config AS \
             SELECT id, layer, name, data, applies_to_collection_id, version_lineage, \
                    {created_at} AS created_at \
             FROM {schema_config}"
        ),
        annotation_targets_view,
        format!(
            "CREATE OR REPLACE TEMPORARY VIEW instruction_bindings AS \
             SELECT id,scope_kind,scope_id,source_record_id,position,enabled,created_by, \
                    {created_at} AS created_at,{updated_at} AS updated_at \
             FROM {instruction_bindings}"
        ),
        format!(
            "CREATE OR REPLACE TEMPORARY VIEW onboarding_programmes AS \
             SELECT id,trigger_key,generation,position,enabled,created_by,legacy_baseline_before, \
                    {created_at} AS created_at,{updated_at} AS updated_at \
             FROM {onboarding_programmes}"
        ),
        format!(
            "CREATE OR REPLACE TEMPORARY VIEW onboarding_programme_sources AS \
             SELECT programme_id,source_record_id,source_role,position \
             FROM {onboarding_programme_sources}"
        ),
        format!(
            "CREATE OR REPLACE TEMPORARY VIEW notification_candidates AS \
             SELECT candidate_id,candidate_key,recipient_account_id,message_id,reason,priority, \
                    {not_before} AS not_before,redaction_class,evaluator_kind,policy_version, \
                    source_event_type,source_event_id,candidate_event_seq,status,{created_at} AS created_at \
             FROM {notification_candidates}",
            not_before = portable_timestamp_text("not_before")
        ),
    ];
    for statement in statements {
        sqlx::query(&statement).execute(&mut **tx).await?;
    }
    Ok(())
}

/// One Postgres transaction admitted for the shared attachments domain fold.
///
/// Reviewed relational statements render into `pg_temp` and execute against
/// the portable views installed at construction; the physical port methods
/// write the qualified base tables and reuse this backend's canonical event
/// append/projection kernel. Acquisition, commit, rollback, and realtime
/// completion stay here, never in the shared fold.
struct PostgresDomainTransaction<'db> {
    db: &'db PostgresDb,
    executor: PortableStatementTransaction<'static>,
    control: ExecutionControl,
}

impl<'db> PostgresDomainTransaction<'db> {
    async fn begin(db: &'db PostgresDb) -> Result<Self> {
        let mut tx = db.pool.begin().await?;
        install_portable_relation_views(db, &mut tx).await?;
        let executor =
            PortableStatementTransaction::from_admitted(tx, "pg_temp").map_err(|error| {
                crate::domain_transaction::stable_storage_error(
                    "begin postgres domain transaction",
                    &error,
                )
            })?;
        Ok(Self {
            db,
            executor,
            control: ExecutionControl::default(),
        })
    }

    async fn begin_snapshot(db: &'db PostgresDb) -> Result<Self> {
        let mut tx = db.pool.begin().await?;
        // The portable executor installs transaction-local views before it can
        // issue its reviewed SELECT templates. Postgres classifies CREATE TEMP
        // VIEW as a write even though it cannot touch authoritative storage, so
        // a SQL-level READ ONLY flag would reject the admission substrate. The
        // snapshot is still mutation-free: its portable view/schema callers
        // issue only reviewed reads after admission.
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *tx)
            .await?;
        install_portable_relation_views(db, &mut tx).await?;
        let executor =
            PortableStatementTransaction::from_admitted(tx, "pg_temp").map_err(|error| {
                crate::domain_transaction::stable_storage_error(
                    "begin postgres domain snapshot",
                    &error,
                )
            })?;
        Ok(Self {
            db,
            executor,
            control: ExecutionControl::default(),
        })
    }

    async fn commit(self) -> Result<()> {
        let db = self.db;
        let tx = self.executor.into_admitted().map_err(|error| {
            crate::domain_transaction::stable_storage_error(
                "commit postgres domain transaction",
                &error,
            )
        })?;
        tx.commit().await?;
        db.complete_realtime_commit();
        Ok(())
    }

    async fn rollback(self) -> Result<()> {
        let transaction = self.executor.into_admitted().map_err(|error| {
            crate::domain_transaction::stable_storage_error(
                "roll back postgres domain snapshot",
                &error,
            )
        })?;
        transaction.rollback().await?;
        Ok(())
    }

    fn admitted(&mut self, operation: &'static str) -> Result<&mut Transaction<'static, Postgres>> {
        self.executor
            .admitted_mut()
            .map_err(|error| crate::domain_transaction::stable_storage_error(operation, &error))
    }
}

async fn run_portable_view(
    db: &PostgresDb,
    caller: &Caller,
    arguments: Value,
    operation: &'static str,
) -> Result<Value> {
    let mut snapshot = PostgresDomainTransaction::begin_snapshot(db).await?;
    let outcome = match operation {
        "get_structure" => {
            crate::domain_transaction::views_history::get_structure(
                &mut snapshot,
                caller,
                arguments,
            )
            .await
        }
        "get_dashboard" => {
            crate::domain_transaction::views_history::get_dashboard(
                &mut snapshot,
                caller,
                arguments,
            )
            .await
        }
        "render_record" => {
            crate::domain_transaction::views_history::render_record(
                &mut snapshot,
                caller,
                arguments,
            )
            .await
        }
        "query_record" => {
            crate::mcp::tools::querying::execute_portable_live_query_record(
                &mut snapshot,
                caller,
                arguments,
            )
            .await
        }
        "resolve_rollup" => {
            crate::mcp::tools::querying::execute_portable_live_rollup(
                &mut snapshot,
                caller,
                arguments,
            )
            .await
        }
        "search" => {
            crate::domain_transaction::search::execute(&mut snapshot, caller, arguments).await
        }
        "scan" => {
            crate::mcp::tools::querying::execute_portable_nonlexical_scan(
                &mut snapshot,
                caller,
                arguments,
            )
            .await
        }
        "preview_record_shape" => {
            crate::domain_transaction::execute_preview_record_shape(
                &mut snapshot,
                caller,
                arguments,
            )
            .await
        }
        "resolve_facets" => {
            crate::domain_transaction::execute_resolve_facets(&mut snapshot, caller, arguments)
                .await
        }
        "suggest_facet_values" => {
            crate::domain_transaction::execute_suggest_facet_values(
                &mut snapshot,
                caller,
                arguments,
            )
            .await
        }
        _ => unreachable!("registered portable view operation"),
    };
    let cleanup = snapshot.rollback().await;
    match outcome {
        Ok(value) => {
            cleanup?;
            Ok(value)
        }
        Err(error) => {
            let _ = cleanup;
            Err(error)
        }
    }
}

async fn manage_facet_observations(
    db: &PostgresDb,
    caller: &Caller,
    arguments: Value,
) -> Result<Value> {
    let action = arguments
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if action == "list" {
        let mut snapshot = PostgresDomainTransaction::begin_snapshot(db).await?;
        let control = snapshot.control.clone();
        let outcome = crate::domain_transaction::execute_manage_facet_observations(
            &mut snapshot,
            caller,
            arguments,
            &control,
        )
        .await;
        let cleanup = snapshot.rollback().await;
        return match outcome {
            Ok(value) => {
                cleanup?;
                Ok(value)
            }
            Err(error) => {
                let _ = cleanup;
                Err(error)
            }
        };
    }
    let mut transaction = PostgresDomainTransaction::begin(db).await?;
    let control = transaction.control.clone();
    let outcome = crate::domain_transaction::execute_manage_facet_observations(
        &mut transaction,
        caller,
        arguments,
        &control,
    )
    .await;
    match outcome {
        Ok(value) => {
            transaction.commit().await?;
            Ok(value)
        }
        Err(error) => {
            let _ = transaction.rollback().await;
            Err(error)
        }
    }
}

/// Resolve abbreviated record arguments in a short portable read snapshot.
/// The snapshot is closed before the selected tool handler opens its own
/// transaction, so argument admission cannot contend with or become part of a
/// later mutation.
pub(crate) async fn resolve_record_ids(
    db: &PostgresDb,
    caller: &Caller,
    tool: &str,
    arguments: Value,
    abbreviations: Vec<(String, String)>,
) -> Result<Value> {
    let mut snapshot = PostgresDomainTransaction::begin(db).await?;
    let resolved = crate::mcp::record_ref::resolve_record_ids_with(
        &mut snapshot,
        caller,
        tool,
        arguments,
        abbreviations,
    )
    .await;
    let cleanup = snapshot.rollback().await;
    match resolved {
        Ok(arguments) => {
            cleanup?;
            Ok(arguments)
        }
        Err(error) => {
            let _ = cleanup;
            Err(error)
        }
    }
}

impl DomainStatementExecutor for PostgresDomainTransaction<'_> {
    fn fetch_all<'a>(
        &'a mut self,
        statement: &'a StatementTemplate,
        bindings: &'a [BindValue],
        columns: &'a [ColumnSpec],
    ) -> BoxFuture<'a, SqlResult<Vec<NormalizedRow>>> {
        let control = self.control.clone();
        Box::pin(async move {
            self.executor
                .fetch_all(statement, bindings, columns, &control)
                .await
        })
    }
}

impl crate::domain_transaction::search::SearchPhysicalPort for PostgresDomainTransaction<'_> {
    fn native_lexical_candidates<'a>(
        &'a mut self,
        terms: &'a [String],
        eligible_ids: &'a HashSet<String>,
        cap: i64,
    ) -> BoxFuture<'a, Result<Vec<crate::domain_transaction::search::NativeSearchCandidate>>> {
        Box::pin(async move {
            if eligible_ids.is_empty() {
                return Ok(Vec::new());
            }
            let records = self.db.qualified_table("records")?;
            let query = terms.join(" ");
            let mut eligible_ids = eligible_ids.iter().cloned().collect::<Vec<_>>();
            eligible_ids.sort();
            let tx = self.admitted("search postgres native FTS")?;
            let rows = sqlx::query(&format!(
                "WITH native_matches AS MATERIALIZED (\
                     SELECT id,substr(coalesce(name,''),1,512) AS name,\
                            substr(body,1,4096) AS body \
                     FROM {records} \
                     WHERE to_tsvector('english',coalesce(name,'') || ' ' || coalesce(body,'')) \
                           @@ plainto_tsquery('english',$1)\
                 ) \
                 SELECT id,name,body FROM native_matches \
                 WHERE id = ANY($2::text[]) \
                 ORDER BY id COLLATE \"C\" LIMIT $3"
            ))
            .bind(query)
            .bind(eligible_ids)
            .bind(cap)
            .fetch_all(&mut **tx)
            .await
            .map_err(|_| Error::engine("search: postgres native FTS execution failed"))?;
            rows.into_iter()
                .map(|row| {
                    Ok(crate::domain_transaction::search::NativeSearchCandidate {
                        id: row.try_get("id")?,
                        name: row.try_get("name")?,
                        body: row.try_get("body")?,
                    })
                })
                .collect()
        })
    }
}

impl FacetObservationPort for PostgresDomainTransaction<'_> {
    fn lock_facet_revision<'a>(&'a mut self) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let cursors = self.db.qualified_table("log_cursors")?;
            let tx = self.admitted("lock facet content revision")?;
            let _: i64 = sqlx::query_scalar(&format!(
                "UPDATE {cursors} SET last_seq=last_seq WHERE log_name='content' RETURNING last_seq"
            ))
            .fetch_one(&mut **tx)
            .await?;
            Ok(())
        })
    }

    fn append_facet_observation<'a>(
        &'a mut self,
        spec: AppendSpec,
        _control: &'a ExecutionControl,
    ) -> BoxFuture<'a, Result<i64>> {
        Box::pin(async move {
            let payload = crate::domain_transaction::normalize_event_payload(
                &spec.record_id,
                &spec.event_type,
                spec.payload,
            );
            let actor = spec.actor.as_deref().ok_or_else(|| {
                Error::engine("postgres facet observation requires an attributed actor")
            })?;
            let db = self.db;
            let tx = self.admitted("append facet observation")?;
            let (seq, created_at) =
                append_event(db, tx, &spec.record_id, &spec.event_type, &payload, actor).await?;
            apply_projection(
                db,
                tx,
                &spec.record_id,
                &spec.event_type,
                &payload,
                &created_at,
            )
            .await?;
            Ok(seq)
        })
    }
}

impl AttachmentPhysicalPort for PostgresDomainTransaction<'_> {
    fn lock_content_log<'a>(&'a mut self) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let cursors = self.db.qualified_table("log_cursors")?;
            let tx = self.admitted("lock attachment content revision")?;
            let _: i64 = sqlx::query_scalar(&format!(
                "UPDATE {cursors} SET last_seq=last_seq WHERE log_name='content' RETURNING last_seq"
            ))
            .fetch_one(&mut **tx)
            .await?;
            Ok(())
        })
    }

    fn insert_blob<'a>(
        &'a mut self,
        bytes: &'a [u8],
        mime: Option<&'a str>,
        original_filename: Option<&'a str>,
    ) -> BoxFuture<'a, Result<BlobMeta>> {
        Box::pin(async move {
            let meta = crate::blob::new_blob_meta(bytes, mime, original_filename);
            let blobs = self.db.qualified_table("blobs")?;
            let tx = self.admitted("insert attachment blob")?;
            sqlx::query(&format!(
                "INSERT INTO {blobs}(id,bytes,mime,size_bytes,sha256,original_filename,storage_tier,created_at) \
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8::timestamptz)"
            ))
            .bind(&meta.id)
            .bind(bytes)
            .bind(&meta.mime)
            .bind(meta.size_bytes)
            .bind(&meta.sha256)
            .bind(&meta.original_filename)
            .bind(&meta.storage_tier)
            .bind(&meta.created_at)
            .execute(&mut **tx)
            .await?;
            Ok(meta)
        })
    }

    fn read_blob_range<'a>(
        &'a mut self,
        blob_id: &'a str,
        offset: u64,
        length: u64,
    ) -> BoxFuture<'a, Result<Option<BlobSlice>>> {
        Box::pin(async move {
            if offset > i64::MAX as u64 || length > i64::MAX as u64 {
                return Err(Error::engine(format!(
                    "blob range out of bounds: offset {offset}, length {length}"
                )));
            }
            let blobs = self.db.qualified_table("blobs")?;
            let tx = self.admitted("read attachment blob")?;
            let Some(row) = sqlx::query(&format!(
                "SELECT size_bytes, storage_tier, (bytes IS NULL) AS no_bytes FROM {blobs} WHERE id=$1"
            ))
            .bind(blob_id)
            .fetch_optional(&mut **tx)
            .await?
            else {
                return Ok(None);
            };
            let tier: String = row.try_get("storage_tier")?;
            if tier != "inline" {
                return Err(Error::engine(format!(
                    "blob {blob_id} is stored externally (storage_tier '{tier}') — external blobs are not readable in v1"
                )));
            }
            if row.try_get::<bool, _>("no_bytes")? {
                return Err(Error::engine(format!("blob {blob_id} has no inline bytes")));
            }
            let total_size = row.try_get::<i64, _>("size_bytes")?.max(0) as u64;
            let bytes = if offset >= total_size {
                Vec::new()
            } else {
                // Inline bytea is capped far below i32::MAX, so a start inside
                // the blob always fits Postgres's int4 substring arguments.
                let out_of_bounds = || {
                    Error::engine(format!(
                        "blob range out of bounds: offset {offset}, length {length}"
                    ))
                };
                let start = i32::try_from(offset + 1).map_err(|_| out_of_bounds())?;
                let count =
                    i32::try_from(length.min(total_size - offset)).map_err(|_| out_of_bounds())?;
                sqlx::query_scalar::<_, Vec<u8>>(&format!(
                    "SELECT substring(bytes FROM $2 FOR $3) FROM {blobs} WHERE id=$1"
                ))
                .bind(blob_id)
                .bind(start)
                .bind(count)
                .fetch_one(&mut **tx)
                .await?
            };
            Ok(Some(BlobSlice {
                eof: offset + bytes.len() as u64 >= total_size,
                bytes,
                offset,
                total_size,
            }))
        })
    }

    fn append_content<'a>(&'a mut self, spec: AppendSpec) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let payload = crate::domain_transaction::normalize_event_payload(
                &spec.record_id,
                &spec.event_type,
                spec.payload,
            );
            let actor = spec.actor.as_deref().ok_or_else(|| {
                Error::engine("postgres append_content requires an attributed actor")
            })?;
            let db = self.db;
            let tx = self.executor.admitted_mut().map_err(|error| {
                crate::domain_transaction::stable_storage_error("append content event", &error)
            })?;
            let (_, created_at) =
                append_event(db, tx, &spec.record_id, &spec.event_type, &payload, actor).await?;
            apply_projection(
                db,
                tx,
                &spec.record_id,
                &spec.event_type,
                &payload,
                &created_at,
            )
            .await?;
            Ok(())
        })
    }
}

impl crate::domain_transaction::RecordLifecyclePhysicalPort for PostgresDomainTransaction<'_> {
    fn lock_live_record<'a>(&'a mut self, record_id: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let records = self.db.qualified_table("records")?;
            let tx = self.admitted("lock delete target")?;
            sqlx::query(&format!("SELECT id FROM {records} WHERE id=$1 FOR UPDATE"))
                .bind(record_id)
                .fetch_optional(&mut **tx)
                .await?;
            Ok(())
        })
    }

    fn lock_content_log<'a>(&'a mut self) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let cursors = self.db.qualified_table("log_cursors")?;
            let tx = self.admitted("lock delete content revision")?;
            let _: i64 = sqlx::query_scalar(&format!(
                "UPDATE {cursors} SET last_seq=last_seq WHERE log_name='content' RETURNING last_seq"
            ))
            .fetch_one(&mut **tx)
            .await?;
            Ok(())
        })
    }

    fn append_content<'a>(&'a mut self, spec: AppendSpec) -> BoxFuture<'a, Result<String>> {
        Box::pin(async move {
            let payload = crate::domain_transaction::normalize_event_payload(
                &spec.record_id,
                &spec.event_type,
                spec.payload,
            );
            let actor = spec.actor.as_deref().ok_or_else(|| {
                Error::engine("postgres append_content requires an attributed actor")
            })?;
            let db = self.db;
            let tx = self.executor.admitted_mut().map_err(|error| {
                crate::domain_transaction::stable_storage_error("append content event", &error)
            })?;
            let (_, event_id, created_at) =
                append_event_with_id(db, tx, &spec.record_id, &spec.event_type, &payload, actor)
                    .await?;
            apply_projection(
                db,
                tx,
                &spec.record_id,
                &spec.event_type,
                &payload,
                &created_at,
            )
            .await?;
            Ok(event_id)
        })
    }
}

impl crate::awareness::CandidateWithdrawalPhysicalPort for PostgresDomainTransaction<'_> {
    fn append_candidate_withdrawal<'a>(
        &'a mut self,
        withdrawal_event_id: &'a str,
        candidate: &'a crate::awareness::CandidateWithdrawal,
        message_id: &'a str,
        source_event_type: &'a str,
        source_event_id: &'a str,
        created_at: &'a str,
    ) -> BoxFuture<'a, Result<i64>> {
        Box::pin(async move {
            let events = self.db.qualified_table("notification_candidate_events")?;
            let tx = self.admitted("append notification candidate withdrawal")?;
            Ok(sqlx::query_scalar(&format!(
                "INSERT INTO {events}(id,candidate_key,action,recipient_account_id,message_id,reason,priority,not_before,redaction_class,evaluator_kind,policy_version,source_event_type,source_event_id,payload,created_at) VALUES($1,$2,'withdrawn',$3,$4,$5,$6,$7::timestamptz,$8,$9,$10,$11,$12,$13::jsonb,$14::timestamptz) RETURNING seq"
            ))
            .bind(withdrawal_event_id)
            .bind(&candidate.candidate_key)
            .bind(&candidate.recipient_account_id)
            .bind(message_id)
            .bind(&candidate.reason)
            .bind(&candidate.priority)
            .bind(&candidate.not_before)
            .bind(&candidate.redaction_class)
            .bind(&candidate.evaluator_kind)
            .bind(&candidate.policy_version)
            .bind(source_event_type)
            .bind(source_event_id)
            .bind("{\"schema\":\"native.notification-candidate.v1\"}")
            .bind(created_at)
            .fetch_one(&mut **tx)
            .await?)
        })
    }

    fn project_candidate_withdrawal<'a>(
        &'a mut self,
        candidate_id: &'a str,
        event_seq: i64,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let candidates = self.db.qualified_table("notification_candidates")?;
            let tx = self.admitted("project notification candidate withdrawal")?;
            sqlx::query(&format!(
                "UPDATE {candidates} SET status='withdrawn',candidate_event_seq=$1 WHERE candidate_id=$2"
            ))
            .bind(event_seq)
            .bind(candidate_id)
            .execute(&mut **tx)
            .await?;
            Ok(())
        })
    }
}

impl BindingPhysicalPort for PostgresDomainTransaction<'_> {
    fn lock_bindings<'a>(
        &'a mut self,
        claims: &'a [crate::identity::BindingClaim],
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let mut keys = claims
                .iter()
                .map(|claim| {
                    format!(
                        "{}:{}/{}",
                        claim.system.len(),
                        claim.system,
                        claim.identifier
                    )
                })
                .collect::<Vec<_>>();
            keys.sort();
            keys.dedup();
            let tx = self.admitted("lock external bindings")?;
            for key in keys {
                sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
                    .bind(key)
                    .execute(&mut **tx)
                    .await?;
            }
            Ok(())
        })
    }

    fn system_rule<'a>(
        &'a mut self,
        system: &'a str,
    ) -> BoxFuture<'a, Result<Option<BindingSystemRule>>> {
        Box::pin(async move {
            let table = self.db.qualified_table("binding_systems")?;
            let row = sqlx::query(&format!(
                "SELECT compatible_type,compatible_kind,visibility,add_policy,remove_policy,canonicalize_policy,transfer_policy,reconciliation_rule,stub_allowed,required_durable FROM {table} WHERE system=$1"
            ))
            .bind(system)
            .fetch_optional(&mut **self.admitted("read binding system")?)
            .await?;
            row.map(|row| {
                Ok(BindingSystemRule {
                    system: system.into(),
                    compatible_type: row.try_get("compatible_type")?,
                    compatible_kind: row.try_get("compatible_kind")?,
                    visibility: row.try_get("visibility")?,
                    add_policy: row.try_get("add_policy")?,
                    remove_policy: row.try_get("remove_policy")?,
                    canonicalize_policy: row.try_get("canonicalize_policy")?,
                    transfer_policy: row.try_get("transfer_policy")?,
                    reconciliation_rule: row.try_get("reconciliation_rule")?,
                    stub_allowed: row.try_get("stub_allowed")?,
                    required_durable: row.try_get("required_durable")?,
                })
            })
            .transpose()
        })
    }

    fn binding<'a>(
        &'a mut self,
        system: &'a str,
        identifier: &'a str,
    ) -> BoxFuture<'a, Result<Option<BindingRow>>> {
        Box::pin(async move {
            let table = self.db.qualified_table("bindings")?;
            let row = sqlx::query(&format!("SELECT record_id,system,identifier,is_canonical,url,etag,last_seen_at FROM {table} WHERE system=$1 AND identifier=$2"))
                .bind(system).bind(identifier)
                .fetch_optional(&mut **self.admitted("read external binding")?).await?;
            row.map(postgres_binding_row).transpose()
        })
    }

    fn record_shape<'a>(
        &'a mut self,
        record_id: &'a str,
    ) -> BoxFuture<'a, Result<Option<(String, Option<String>, bool)>>> {
        Box::pin(async move {
            let table = self.db.qualified_table("records")?;
            let row = sqlx::query(&format!("SELECT record_type,kind,deleted_at IS NOT NULL AS deleted FROM {table} WHERE id=$1"))
                .bind(record_id).fetch_optional(&mut **self.admitted("read binding record shape")?).await?;
            row.map(|row| {
                Ok((
                    row.try_get("record_type")?,
                    row.try_get("kind")?,
                    row.try_get("deleted")?,
                ))
            })
            .transpose()
        })
    }

    fn canonical_binding<'a>(
        &'a mut self,
        record_id: &'a str,
        system: &'a str,
    ) -> BoxFuture<'a, Result<Option<String>>> {
        Box::pin(async move {
            let table = self.db.qualified_table("bindings")?;
            Ok(sqlx::query_scalar(&format!("SELECT identifier FROM {table} WHERE record_id=$1 AND system=$2 AND is_canonical=TRUE"))
                .bind(record_id).bind(system).fetch_optional(&mut **self.admitted("read canonical binding")?).await?)
        })
    }

    fn binding_count<'a>(
        &'a mut self,
        record_id: &'a str,
        system: &'a str,
    ) -> BoxFuture<'a, Result<i64>> {
        Box::pin(async move {
            let table = self.db.qualified_table("bindings")?;
            Ok(sqlx::query_scalar(&format!(
                "SELECT COUNT(*) FROM {table} WHERE record_id=$1 AND system=$2"
            ))
            .bind(record_id)
            .bind(system)
            .fetch_one(&mut **self.admitted("count bindings")?)
            .await?)
        })
    }

    fn account_owner<'a>(&'a mut self, actor: &'a str) -> BoxFuture<'a, Result<Option<String>>> {
        Box::pin(async move {
            let table = self.db.qualified_table("bindings")?;
            Ok(sqlx::query_scalar(&format!("SELECT record_id FROM {table} WHERE system='account' AND identifier=$1 AND is_canonical=TRUE"))
                .bind(actor).fetch_optional(&mut **self.admitted("resolve binding owner")?).await?)
        })
    }

    fn public_bindings<'a>(
        &'a mut self,
        record_id: &'a str,
    ) -> BoxFuture<'a, Result<Vec<BindingRow>>> {
        Box::pin(async move {
            let bindings = self.db.qualified_table("bindings")?;
            let systems = self.db.qualified_table("binding_systems")?;
            sqlx::query(&format!("SELECT b.record_id,b.system,b.identifier,b.is_canonical,b.url,b.etag,b.last_seen_at FROM {bindings} b JOIN {systems} s ON s.system=b.system WHERE b.record_id=$1 AND s.visibility='public' ORDER BY b.system,b.is_canonical DESC,b.identifier COLLATE \"C\""))
                .bind(record_id).fetch_all(&mut **self.admitted("list public bindings")?).await?
                .into_iter().map(postgres_binding_row).collect()
        })
    }

    fn set_canonical<'a>(
        &'a mut self,
        record_id: &'a str,
        system: &'a str,
        identifier: &'a str,
        canonical: bool,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let table = self.db.qualified_table("bindings")?;
            sqlx::query(&format!("UPDATE {table} SET is_canonical=$1 WHERE record_id=$2 AND system=$3 AND identifier=$4"))
                .bind(canonical).bind(record_id).bind(system).bind(identifier)
                .execute(&mut **self.admitted("update canonical binding")?).await?;
            Ok(())
        })
    }

    fn insert_binding<'a>(
        &'a mut self,
        record_id: &'a str,
        claim: &'a crate::identity::BindingClaim,
        canonical: bool,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let table = self.db.qualified_table("bindings")?;
            sqlx::query(&format!(
                "INSERT INTO {table}(record_id,system,identifier,is_canonical) VALUES($1,$2,$3,$4)"
            ))
            .bind(record_id)
            .bind(&claim.system)
            .bind(&claim.identifier)
            .bind(canonical)
            .execute(&mut **self.admitted("insert external binding")?)
            .await?;
            Ok(())
        })
    }

    fn delete_binding<'a>(
        &'a mut self,
        record_id: &'a str,
        claim: &'a crate::identity::BindingClaim,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let table = self.db.qualified_table("bindings")?;
            sqlx::query(&format!(
                "DELETE FROM {table} WHERE record_id=$1 AND system=$2 AND identifier=$3"
            ))
            .bind(record_id)
            .bind(&claim.system)
            .bind(&claim.identifier)
            .execute(&mut **self.admitted("delete external binding")?)
            .await?;
            Ok(())
        })
    }

    fn transfer_binding<'a>(
        &'a mut self,
        source_record_id: &'a str,
        target_record_id: &'a str,
        claim: &'a crate::identity::BindingClaim,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let table = self.db.qualified_table("bindings")?;
            sqlx::query(&format!("UPDATE {table} SET record_id=$1 WHERE record_id=$2 AND system=$3 AND identifier=$4"))
                .bind(target_record_id).bind(source_record_id).bind(&claim.system).bind(&claim.identifier)
                .execute(&mut **self.admitted("transfer external binding")?).await?;
            Ok(())
        })
    }

    fn append_binding_audit<'a>(
        &'a mut self,
        audit: BindingAudit<'a>,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let table = self.db.qualified_table("binding_audit")?;
            let tx = self.admitted("append binding audit")?;
            sqlx::query(
                "SELECT pg_advisory_xact_lock(hashtextextended('native-ce:binding-audit-sequence', 0))",
            )
            .execute(&mut **tx)
            .await?;
            sqlx::query(&format!("INSERT INTO {table}(seq,id,action,system,identifier,old_record_id,new_record_id,old_canonical,new_canonical,actor,reason,run_key,parent_key,intent,created_at) VALUES((SELECT COALESCE(MAX(seq),0)+1 FROM {table}),$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,transaction_timestamp())"))
                .bind(Uuid::new_v4().to_string()).bind(audit.action).bind(&audit.claim.system).bind(&audit.claim.identifier)
                .bind(audit.old_record_id).bind(audit.new_record_id).bind(audit.old_canonical).bind(audit.new_canonical)
                .bind(audit.actor).bind(audit.reason).bind(audit.run_key).bind(audit.parent_key).bind(audit.intent)
                .execute(&mut **tx).await?;
            Ok(())
        })
    }
}

fn postgres_binding_row(row: sqlx::postgres::PgRow) -> Result<BindingRow> {
    Ok(BindingRow {
        record_id: row.try_get("record_id")?,
        system: row.try_get("system")?,
        identifier: row.try_get("identifier")?,
        canonical: row.try_get("is_canonical")?,
        url: row.try_get("url")?,
        etag: row.try_get("etag")?,
        last_seen_at: row
            .try_get::<Option<DateTime<Utc>>, _>("last_seen_at")?
            .map(|value| value.to_rfc3339_opts(SecondsFormat::AutoSi, true)),
    })
}

/// Map one MCP caller onto the shared authorization principal exactly as the
/// Turso-local boundary does: only the unhosted trusted-local caller bypasses
/// policy; routed hosted callers are member-bound accounts.
fn attachment_principal(caller: &Caller) -> crate::authorization::Principal<'_> {
    if caller.is_trusted_local() && caller.hosting_database().is_none() {
        crate::authorization::Principal::trusted_local()
    } else {
        crate::authorization::Principal::bound(caller.credential(), true)
    }
}

fn attachment_facet_write(key: String, value: Value) -> Result<FacetWrite> {
    match value {
        Value::String(_) | Value::Number(_) | Value::Object(_) => Ok(FacetWrite {
            key,
            value,
            vocab_ref: None,
        }),
        _ => Err(Error::engine(
            "Postgres facets require string, number, or object values",
        )),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AttachTextArgs {
    record_id: String,
    text: String,
    filename: Option<String>,
    mime: Option<String>,
    name: Option<String>,
    lifecycle: Option<String>,
    owner_id: Option<String>,
    persistence: Option<String>,
    maturity: Option<String>,
    facets: Option<Map<String, Value>>,
}

/// `attach_text` slice: the shared attachments domain fold (blob bytes plus
/// event-sourced attachment record) inside one admitted transaction, at
/// behavioral parity with the Turso-local implementation.
async fn attach_text(db: &PostgresDb, caller: &Caller, arguments: Value) -> Result<Value> {
    const TOOL: &str = "attach_text";
    const MAX_BYTES: usize = crate::mcp::fetch::MAX_FETCH_BYTES as usize;
    let args: AttachTextArgs = parse(TOOL, arguments)?;
    if args.text.len() > MAX_BYTES {
        return Err(Error::engine(format!(
            "attach_text: text exceeds the {MAX_BYTES} byte cap"
        )));
    }
    let facets = args
        .facets
        .unwrap_or_default()
        .into_iter()
        .map(|(key, value)| attachment_facet_write(key, value))
        .collect::<Result<Vec<_>>>()?;
    let mime = args
        .mime
        .unwrap_or_else(|| "text/plain; charset=utf-8".into());
    let name = args
        .name
        .or_else(|| args.filename.clone())
        .unwrap_or_else(|| "attachment".into());
    let mut port = PostgresDomainTransaction::begin(db).await?;
    let result = crate::domain_transaction::create_attachment(
        &mut port,
        crate::domain_transaction::AttachmentCreate {
            tool: TOOL,
            bearer_id: &args.record_id,
            bytes: args.text.as_bytes(),
            mime: Some(&mime),
            filename: args.filename.as_deref(),
            name: &name,
            lifecycle: args.lifecycle.as_deref(),
            owner_id: args.owner_id.as_deref(),
            persistence: args.persistence.as_deref(),
            maturity: args.maturity.as_deref(),
            extra_facets: facets,
            actor: caller.actor(),
            credential: caller.credential(),
            principal: attachment_principal(caller),
            attachment_id: None,
            image_insert: None,
        },
    )
    .await?;
    port.commit().await?;
    Ok(result)
}

async fn preflight_attach_target(
    db: &PostgresDb,
    caller: &Caller,
    tool: &str,
    record_id: &str,
) -> Result<()> {
    let mut port = PostgresDomainTransaction::begin(db).await?;
    if !crate::authorization::allows_record_with(
        &mut port,
        attachment_principal(caller),
        record_id,
        crate::authorization::Capability::Edit,
    )
    .await?
    {
        return Err(Error::engine(format!(
            "{tool}: record {record_id} does not exist"
        )));
    }
    crate::domain_transaction::require_live_attachment_bearer(&mut port, tool, record_id).await
}

/// `attach_from_url` parses and authorizes before network I/O, then enters the
/// same transactional create fold as `attach_text`. The fold repeats the
/// bearer checks after the fetch.
async fn attach_from_url(
    db: &PostgresDb,
    caller: &Caller,
    arguments: Value,
    config: FetchConfig,
) -> Result<Value> {
    const TOOL: &str = "attach_from_url";
    let (request, config) =
        crate::mcp::tools::attachments::parse_attachment_from_url(TOOL, arguments, config)?;
    preflight_attach_target(db, caller, TOOL, &request.record_id).await?;
    let prepared =
        crate::mcp::tools::attachments::fetch_attachment_from_url(request, &config).await?;
    let crate::mcp::tools::attachments::PreparedAttachmentFromUrl {
        record_id,
        bytes,
        mime,
        filename,
        name,
        lifecycle,
        owner_id,
        persistence,
        maturity,
        facets,
        url,
        final_url,
        redirects,
    } = prepared;
    let mut port = PostgresDomainTransaction::begin(db).await?;
    let mut result = crate::domain_transaction::create_attachment(
        &mut port,
        crate::domain_transaction::AttachmentCreate {
            tool: TOOL,
            bearer_id: &record_id,
            bytes: &bytes,
            mime: Some(&mime),
            filename: filename.as_deref(),
            name: &name,
            lifecycle: lifecycle.as_deref(),
            owner_id: owner_id.as_deref(),
            persistence: persistence.as_deref(),
            maturity: maturity.as_deref(),
            extra_facets: facets,
            actor: caller.actor(),
            credential: caller.credential(),
            principal: attachment_principal(caller),
            attachment_id: None,
            image_insert: None,
        },
    )
    .await?;
    port.commit().await?;
    let object = result.as_object_mut().expect("create_attachment payload");
    object.insert("url".into(), json!(url));
    object.insert("final_url".into(), json!(final_url));
    object.insert("redirects".into(), json!(redirects));
    Ok(result)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadAttachmentArgs {
    attachment_id: String,
    offset: Option<u64>,
    length: Option<u64>,
}

/// `read_attachment` slice: ranged, visibility-gated blob reads with the
/// shared 64KiB default / 512KiB maximum window. The snapshot transaction is
/// dropped without commit.
async fn read_attachment(db: &PostgresDb, caller: &Caller, arguments: Value) -> Result<Value> {
    let args: ReadAttachmentArgs = parse("read_attachment", arguments)?;
    let mut port = PostgresDomainTransaction::begin(db).await?;
    crate::domain_transaction::read_attachment(
        &mut port,
        attachment_principal(caller),
        "read_attachment",
        &args.attachment_id,
        args.offset.unwrap_or(0),
        args.length.unwrap_or(64 * 1024),
        512 * 1024,
    )
    .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "action", rename_all = "snake_case")]
enum ManageAttachmentsArgs {
    List {
        record_id: String,
    },
    Inspect {
        attachment_id: String,
    },
    Detach {
        attachment_id: String,
        #[serde(default)]
        if_content_seq: Option<i64>,
    },
}

#[cfg(feature = "mcp-executor-prototype")]
pub(crate) async fn prepare_manage_attachments_detach(
    db: &PostgresDb,
    caller: &Caller,
    arguments: Value,
) -> Result<crate::domain_transaction::AttachmentDetachPreparation> {
    let ManageAttachmentsArgs::Detach {
        attachment_id,
        if_content_seq: None,
    } = parse("manage_attachments", arguments)?
    else {
        return Err(Error::engine(
            "manage_attachments: executor preparation only supports action detach without an internal revision",
        ));
    };
    let mut port = PostgresDomainTransaction::begin(db).await?;
    crate::domain_transaction::prepare_attachment_detach(
        &mut port,
        attachment_principal(caller),
        "manage_attachments",
        &attachment_id,
    )
    .await
}

/// `manage_attachments` slice: list/inspect snapshots and the event-sourced
/// detach tombstone, all through the shared attachments domain fold.
async fn manage_attachments(db: &PostgresDb, caller: &Caller, arguments: Value) -> Result<Value> {
    const TOOL: &str = "manage_attachments";
    match parse(TOOL, arguments)? {
        ManageAttachmentsArgs::List { record_id } => {
            let mut port = PostgresDomainTransaction::begin(db).await?;
            crate::domain_transaction::list_attachments(
                &mut port,
                attachment_principal(caller),
                TOOL,
                &record_id,
            )
            .await
        }
        ManageAttachmentsArgs::Inspect { attachment_id } => {
            let mut port = PostgresDomainTransaction::begin(db).await?;
            crate::domain_transaction::inspect_attachment(
                &mut port,
                attachment_principal(caller),
                TOOL,
                &attachment_id,
            )
            .await
        }
        ManageAttachmentsArgs::Detach {
            attachment_id,
            if_content_seq,
        } => {
            let mut port = PostgresDomainTransaction::begin(db).await?;
            let result = crate::domain_transaction::detach_attachment(
                &mut port,
                attachment_principal(caller),
                TOOL,
                &attachment_id,
                caller.actor(),
                if_content_seq,
            )
            .await?;
            port.commit().await?;
            Ok(result)
        }
    }
}

/// Seed the engine-shipped vocabularies (including every `kind:*` vocabulary)
/// as deterministic genesis projections, mirroring the Turso-local seed set.
/// Like the root records above, genesis state is engine-provisioned rather
/// than log-derived on this backend, so replay reseeds it identically.
async fn seed_governed_vocabularies(
    tx: &mut Transaction<'_, Postgres>,
    schema: &str,
) -> Result<()> {
    async fn seed_vocabulary(
        tx: &mut Transaction<'_, Postgres>,
        schema: &str,
        id: &str,
        name: &str,
    ) -> Result<()> {
        sqlx::query(&format!(
            "INSERT INTO {schema}.vocabularies(id,name,created_at) VALUES($1,$2,$3::timestamptz)"
        ))
        .bind(id)
        .bind(name)
        .bind(SEEDED_RECORD_TIMESTAMP)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    async fn seed_value(
        tx: &mut Transaction<'_, Postgres>,
        schema: &str,
        id: &str,
        vocabulary_id: &str,
        value: &str,
        progression: (f64, &str),
        metadata: &Value,
    ) -> Result<()> {
        let (ordinal, terminality) = progression;
        sqlx::query(&format!(
            "INSERT INTO {schema}.vocabulary_values(id,vocabulary_id,value,status,ordinal,terminality,metadata) \
             VALUES($1,$2,$3,'active',$4,$5,$6::jsonb)"
        ))
        .bind(id)
        .bind(vocabulary_id)
        .bind(value)
        .bind(ordinal)
        .bind(terminality)
        .bind(metadata.to_string())
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    for (name, values) in crate::meta::vocabulary::SEED_VOCABULARIES {
        let vocabulary_id = format!("voc:{name}");
        seed_vocabulary(tx, schema, &vocabulary_id, name).await?;
        for (value, ordinal, terminality) in values.seeded() {
            let value_id = format!("vv:{vocabulary_id}:{value}");
            seed_value(
                tx,
                schema,
                &value_id,
                &vocabulary_id,
                value,
                (ordinal, terminality.as_str()),
                &json!({}),
            )
            .await?;
        }
    }
    let manifest = crate::meta::kind::core_kind_manifest()?;
    for record_type in crate::schema::SPINE_TYPES {
        let vocabulary_id = crate::meta::kind::kind_vocabulary_id(record_type);
        let vocabulary_name = crate::meta::kind::kind_vocabulary_name(record_type);
        seed_vocabulary(tx, schema, &vocabulary_id, &vocabulary_name).await?;
        for kind in manifest
            .kinds
            .iter()
            .filter(|kind| kind.record_type == record_type)
        {
            seed_value(
                tx,
                schema,
                &kind.value_id,
                &vocabulary_id,
                &kind.token,
                (0.0, "open"),
                &serde_json::to_value(&kind.metadata)?,
            )
            .await?;
        }
    }
    sqlx::query(&format!(
        "INSERT INTO {schema}.schema_config(id,layer,name,data,created_at) \
         VALUES('pack:@native/recommended','pack','@native/recommended',$1,$2::timestamptz)"
    ))
    .bind(crate::meta::schema_config::recommended_pack_schema_config().to_string())
    .bind(SEEDED_RECORD_TIMESTAMP)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn append_event(
    db: &PostgresDb,
    tx: &mut Transaction<'_, Postgres>,
    record_id: &str,
    event_type: &str,
    payload: &Value,
    actor: &str,
) -> Result<(i64, String)> {
    let (seq, _, created_at) =
        append_event_with_id(db, tx, record_id, event_type, payload, actor).await?;
    Ok((seq, created_at))
}

async fn append_event_with_id(
    db: &PostgresDb,
    tx: &mut Transaction<'_, Postgres>,
    record_id: &str,
    event_type: &str,
    payload: &Value,
    actor: &str,
) -> Result<(i64, String, String)> {
    let cursor = db.qualified_table("event_cursor")?;
    let log_cursors = db.qualified_table("log_cursors")?;
    let events = db.qualified_table("content_events")?;
    let frontier = db.qualified_table("content_event_causal_frontier")?;
    // Advancing the one content cursor is the Postgres writer-serialization
    // fence. Read heads only after this row lock is held, so two local writers
    // cannot compute the same stale frontier.
    let seq: i64 = sqlx::query_scalar(&format!(
        "UPDATE {log_cursors} SET last_seq=last_seq+1 WHERE log_name='content' RETURNING last_seq"
    ))
    .fetch_one(&mut **tx)
    .await?;
    let heads: Vec<String> = sqlx::query_scalar(&format!(
        "SELECT event.id FROM {events} event \
          WHERE NOT EXISTS(SELECT 1 FROM {frontier} edge WHERE edge.parent_event_id=event.id) \
          ORDER BY event.id COLLATE \"C\""
    ))
    .fetch_all(&mut **tx)
    .await?;
    if heads.is_empty() {
        let event_count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {events}"))
            .fetch_one(&mut **tx)
            .await?;
        if event_count != 0 {
            return Err(Error::engine(
                "Postgres content event causal state has no heads for a nonempty log",
            ));
        }
    }
    sqlx::query(&format!(
        "UPDATE {cursor} SET last_seq=$1 WHERE singleton=TRUE"
    ))
    .bind(seq)
    .execute(&mut **tx)
    .await?;
    let annotations = crate::store::current_event_annotations();
    let event_id = Uuid::new_v4().to_string();
    let created_at: DateTime<Utc> = sqlx::query_scalar(&format!(
        "INSERT INTO {events}(seq,id,record_id,type,payload,actor,run_key,parent_key,intent,\
                              causal_envelope_version,causal_status) \
         VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9,1,'complete') RETURNING created_at"
    ))
    .bind(seq)
    .bind(&event_id)
    .bind(record_id)
    .bind(event_type)
    .bind(payload.to_string())
    .bind(actor)
    .bind(annotations.run_key)
    .bind(annotations.parent_key)
    .bind(annotations.intent)
    .fetch_one(&mut **tx)
    .await?;
    for parent_event_id in heads {
        sqlx::query(&format!(
            "INSERT INTO {frontier}(event_id,parent_event_id) VALUES($1,$2)"
        ))
        .bind(&event_id)
        .bind(parent_event_id)
        .execute(&mut **tx)
        .await?;
    }
    Ok((
        seq,
        event_id,
        created_at.to_rfc3339_opts(SecondsFormat::AutoSi, true),
    ))
}

async fn advance_record_updated_at(
    db: &PostgresDb,
    tx: &mut Transaction<'_, Postgres>,
    record_id: &str,
    event_created_at: &str,
) -> Result<()> {
    let records = db.qualified_table("records")?;
    sqlx::query(&format!(
        "UPDATE {records} \
         SET updated_at=GREATEST($2::timestamptz, updated_at + INTERVAL '1 microsecond') \
         WHERE id=$1"
    ))
    .bind(record_id)
    .bind(event_created_at)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

struct PostgresContentSemanticState<'db, 'tx, 'conn> {
    db: &'db PostgresDb,
    tx: &'tx mut Transaction<'conn, Postgres>,
}

impl ContentSemanticStatePort for PostgresContentSemanticState<'_, '_, '_> {
    fn record_state<'a>(
        &'a mut self,
        record_id: &'a str,
    ) -> BoxFuture<'a, Result<Option<RecordSemanticState>>> {
        Box::pin(async move {
            let records = self.db.qualified_table("records")?;
            let audience = self.db.qualified_table("message_audience")?;
            let row = sqlx::query(&format!(
                "SELECT r.record_type,r.kind,r.persistence,r.deleted_at,r.policy_anchor_id,r.archived, \
                        EXISTS(SELECT 1 FROM {audience} a WHERE a.message_id=r.id) AS has_audience \
                   FROM {records} r WHERE r.id=$1"
            ))
            .bind(record_id)
            .fetch_optional(&mut **self.tx)
            .await?;
            row.map(|row| {
                let record_type: String = row.try_get("record_type")?;
                let kind: Option<String> = row.try_get("kind")?;
                let has_audience: bool = row.try_get("has_audience")?;
                Ok(RecordSemanticState {
                    targeted: record_type == "Annotation"
                        && matches!(kind.as_deref(), Some("citation" | "comment")),
                    attributed: record_type == "Annotation"
                        && kind.as_deref() == Some("attribution"),
                    semantic_unit: false,
                    message_status: (record_type == "Message").then(|| {
                        if has_audience {
                            "shared".to_string()
                        } else {
                            "pending_local".to_string()
                        }
                    }),
                    record_type,
                    kind,
                    persistence: row.try_get("persistence")?,
                    deleted: row
                        .try_get::<Option<chrono::DateTime<Utc>>, _>("deleted_at")?
                        .is_some(),
                    policy_anchor_id: row.try_get("policy_anchor_id")?,
                    archived: row.try_get("archived")?,
                })
            })
            .transpose()
        })
    }

    fn home_would_cycle<'a>(
        &'a mut self,
        _record_id: &'a str,
        _home_id: &'a str,
    ) -> BoxFuture<'a, Result<bool>> {
        Box::pin(async {
            Err(Error::engine(
                "Postgres correction planner does not support containment planning",
            ))
        })
    }

    fn first_live_child<'a>(
        &'a mut self,
        _record_id: &'a str,
    ) -> BoxFuture<'a, Result<Option<String>>> {
        Box::pin(async {
            Err(Error::engine(
                "Postgres correction planner does not support child planning",
            ))
        })
    }

    fn link_identity<'a>(
        &'a mut self,
        _source_id: &'a str,
        _target_id: &'a str,
        _relationship: &'a str,
    ) -> BoxFuture<'a, Result<Option<String>>> {
        Box::pin(async {
            Err(Error::engine(
                "Postgres correction planner does not support link planning",
            ))
        })
    }
}

async fn apply_projection(
    db: &PostgresDb,
    tx: &mut Transaction<'_, Postgres>,
    record_id: &str,
    event_type: &str,
    payload: &Value,
    event_created_at: &str,
) -> Result<()> {
    let records = db.qualified_table("records")?;
    let facets = db.qualified_table("facet_values")?;
    let audience = db.qualified_table("message_audience")?;
    match event_type {
        "record.created" => {
            let home_id = if record_id == ROOT_RECORD_ID {
                None
            } else {
                Some(payload["home_id"].as_str().unwrap_or(UNFILED_RECORD_ID))
            };
            let policy_anchor_id = if record_id == ROOT_RECORD_ID {
                Some(ROOT_RECORD_ID.to_string())
            } else if let Some(home_id) = home_id {
                sqlx::query_scalar::<_, Option<String>>(&format!(
                    "SELECT policy_anchor_id FROM {records} WHERE id=$1"
                ))
                .bind(home_id)
                .fetch_optional(&mut **tx)
                .await?
                .flatten()
            } else {
                Some(ROOT_RECORD_ID.to_string())
            };
            sqlx::query(&format!(
                "INSERT INTO {records}(\
                id, record_type, kind, name, body, home_id, summary, lifecycle, owner_id, persistence, maturity,policy_anchor_id,created_at,updated_at\
                 ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::timestamptz,$13::timestamptz)"
            ))
            .bind(record_id)
            .bind(payload["type"].as_str())
            .bind(payload["kind"].as_str())
            // SQLite's records.name is NOT NULL DEFAULT ''. Its projector
            // therefore canonicalizes omitted/null names to the empty string.
            .bind(payload["name"].as_str().unwrap_or(""))
            .bind(payload["body"].as_str())
            .bind(home_id)
            .bind(payload["summary"].as_str())
            .bind(payload["lifecycle"].as_str())
            .bind(payload["owner_id"].as_str())
            .bind(payload["persistence"].as_str().unwrap_or("enduring"))
            .bind(payload["maturity"].as_str())
            .bind(policy_anchor_id)
            .bind(event_created_at)
            .execute(&mut **tx)
            .await?;
            if record_id == ROOT_RECORD_ID {
                let policies = db.qualified_table("record_policies")?;
                let entries = db.qualified_table("policy_entries")?;
                sqlx::query(&format!(
                    "INSERT INTO {policies}(record_id) VALUES($1) ON CONFLICT(record_id) DO NOTHING"
                ))
                .bind(ROOT_RECORD_ID)
                .execute(&mut **tx)
                .await?;
                sqlx::query(&format!(
                    "INSERT INTO {entries}(policy_anchor_id,subject_kind,subject_id,effect,capability) VALUES($1,'members','native:members','allow','edit') ON CONFLICT DO NOTHING"
                ))
                .bind(ROOT_RECORD_ID)
                .execute(&mut **tx)
                .await?;
            }
        }
        "record.updated" => {
            let fields = [
                "name",
                "body",
                "summary",
                "lifecycle",
                "home_id",
                "maturity",
            ];
            for field in fields {
                if payload.get(field).is_some() {
                    let column = quote_identifier(field)?;
                    sqlx::query(&format!("UPDATE {records} SET {column}=$2 WHERE id=$1"))
                        .bind(record_id)
                        .bind(payload[field].as_str())
                        .execute(&mut **tx)
                        .await?;
                }
            }
            advance_record_updated_at(db, tx, record_id, event_created_at).await?;
        }
        "record.type_corrected.v1" => {
            let event = EventRow {
                local_seq: -1,
                id: "postgres:record-type-correction".into(),
                record_id: record_id.into(),
                event_type: event_type.into(),
                payload: Some(serde_json::to_string(payload)?),
                actor: None,
                run_key: None,
                parent_key: None,
                intent: None,
                created_at: event_created_at.into(),
                causal_envelope: CausalEnvelopeV1::default(),
            };
            let intent = ProjectorIntent::from_event(&event)?;
            let plan = {
                let mut state = PostgresContentSemanticState { db, tx };
                crate::domain_transaction::plan_projection(&mut state, &event, &intent).await?
            };
            let ProjectionPlan::RecordTypeCorrected { record_type, kind } = plan else {
                return Err(Error::engine(
                    "Postgres correction planner returned an unexpected projection",
                ));
            };
            sqlx::query(&format!(
                "UPDATE {records} SET record_type=$2,kind=$3 WHERE id=$1"
            ))
            .bind(record_id)
            .bind(record_type)
            .bind(kind)
            .execute(&mut **tx)
            .await?;
            advance_record_updated_at(db, tx, record_id, event_created_at).await?;
        }
        "facet.set" if payload["key"] == "archived" => {
            sqlx::query(&format!("UPDATE {records} SET archived=TRUE WHERE id=$1"))
                .bind(record_id)
                .execute(&mut **tx)
                .await?;
            advance_record_updated_at(db, tx, record_id, event_created_at).await?;
        }
        "facet.unset" if payload["key"] == "archived" => {
            sqlx::query(&format!("UPDATE {records} SET archived=FALSE WHERE id=$1"))
                .bind(record_id)
                .execute(&mut **tx)
                .await?;
            advance_record_updated_at(db, tx, record_id, event_created_at).await?;
        }
        "facet.set" => {
            if !payload["observation_only"].as_bool().unwrap_or(false) {
                sqlx::query(&format!(
                    "INSERT INTO {facets}(record_id, key, value) VALUES($1,$2,$3::jsonb) \
                     ON CONFLICT(record_id, key) DO UPDATE SET value=EXCLUDED.value"
                ))
                .bind(record_id)
                .bind(payload["key"].as_str())
                .bind(payload["value"].to_string())
                .execute(&mut **tx)
                .await?;
            }
            advance_record_updated_at(db, tx, record_id, event_created_at).await?;
        }
        "facet.unset" => {
            if !payload["observation_only"].as_bool().unwrap_or(false) {
                sqlx::query(&format!(
                    "DELETE FROM {facets} WHERE record_id=$1 AND key=$2"
                ))
                .bind(record_id)
                .bind(payload["key"].as_str())
                .execute(&mut **tx)
                .await?;
            }
            advance_record_updated_at(db, tx, record_id, event_created_at).await?;
        }
        "link.added" => {
            let links = db.qualified_table("links")?;
            let source_id = payload["source_id"]
                .as_str()
                .ok_or_else(|| Error::engine("link.added payload requires source_id"))?;
            if source_id != record_id {
                return Err(Error::engine(
                    "link.added envelope mismatch: event record does not match payload source_id",
                ));
            }
            let target_id = payload["target_id"]
                .as_str()
                .ok_or_else(|| Error::engine("link.added payload requires target_id"))?;
            let relationship = payload["relationship"]
                .as_str()
                .filter(|relationship| !relationship.is_empty())
                .ok_or_else(|| {
                    Error::engine("link.added payload requires a non-empty relationship")
                })?;
            // The deterministic id mirrors the shared projector seam
            // (`domain_transaction::plan_link_added`), so replay rebuilds the
            // identical projection row without storing backend-local state.
            let link_id = match payload["id"].as_str() {
                Some(id) => id.to_string(),
                None => format!("lnk:{source_id}:{target_id}:{relationship}"),
            };
            sqlx::query(&format!(
                "INSERT INTO {links}(id, source_id, target_id, relationship, note, created_at) \
                 VALUES($1,$2,$3,$4,$5,$6::timestamptz)"
            ))
            .bind(link_id)
            .bind(source_id)
            .bind(target_id)
            .bind(relationship)
            .bind(payload["note"].as_str())
            .bind(event_created_at)
            .execute(&mut **tx)
            .await?;
            advance_record_updated_at(db, tx, record_id, event_created_at).await?;
        }
        "record.deleted" => {
            sqlx::query(&format!(
                "UPDATE {records} SET deleted_at=$2::timestamptz WHERE id=$1"
            ))
            .bind(record_id)
            .bind(event_created_at)
            .execute(&mut **tx)
            .await?;
            advance_record_updated_at(db, tx, record_id, event_created_at).await?;
        }
        "message.audience.declared" => {
            for account in payload["accounts"].as_array().into_iter().flatten() {
                sqlx::query(&format!(
                    "INSERT INTO {audience}(message_id, account_id) VALUES($1,$2)"
                ))
                .bind(record_id)
                .bind(account.as_str())
                .execute(&mut **tx)
                .await?;
            }
            advance_record_updated_at(db, tx, record_id, event_created_at).await?;
        }
        other => {
            return Err(Error::engine(format!(
                "unsupported Postgres replay event {other}"
            )))
        }
    }
    Ok(())
}

pub async fn migration_version(db: &PostgresDb) -> Result<i32> {
    let migrations = db.qualified_table("schema_migrations")?;
    Ok(
        sqlx::query_scalar(&format!("SELECT MAX(version) FROM {migrations}"))
            .fetch_one(&db.pool)
            .await?,
    )
}

pub async fn event_count(db: &PostgresDb, record_id: &str) -> Result<i64> {
    let events = db.qualified_table("content_events")?;
    Ok(
        sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {events} WHERE record_id=$1"))
            .bind(record_id)
            .fetch_one(&db.pool)
            .await?,
    )
}

pub async fn projection_exists(db: &PostgresDb, record_id: &str) -> Result<bool> {
    let records = db.qualified_table("records")?;
    Ok(sqlx::query_scalar(&format!(
        "SELECT EXISTS(SELECT 1 FROM {records} WHERE id=$1)"
    ))
    .bind(record_id)
    .fetch_one(&db.pool)
    .await?)
}

pub async fn event_sequences(db: &PostgresDb) -> Result<Vec<i64>> {
    let events = db.qualified_table("content_events")?;
    Ok(
        sqlx::query_scalar(&format!("SELECT seq FROM {events} ORDER BY seq"))
            .fetch_all(&db.pool)
            .await?,
    )
}

/// Rejects a projection either by name or by record id. The id arm matches the
/// dedicated `...-0099%` block reserved for the three projection-rollback
/// contract tests; it used to match `contract:reject-projection:%`, which the
/// v4/v7 record-id rule made unwritable. Records in that block exist only to
/// be rejected, so keep the block dedicated: widening it to a busier prefix
/// would reject unrelated fixtures and the tests would still pass.
pub async fn install_projection_failure_trigger(db: &PostgresDb) -> Result<()> {
    let schema = quote_identifier(db.schema())?;
    let records = db.qualified_table("records")?;
    db.pool
        .execute(
            format!(
                "CREATE OR REPLACE FUNCTION {schema}.reject_contract_projection() RETURNS trigger \
                 LANGUAGE plpgsql AS $$ BEGIN \
                   IF NEW.name = '__reject_projection__' \
                   OR NEW.id LIKE '9c150000-0000-4000-8000-0099%' \
                   THEN RAISE EXCEPTION 'projection rejected'; END IF; \
                   RETURN NEW; END $$"
            )
            .as_str(),
        )
        .await?;
    db.pool
        .execute(
            format!(
                "CREATE TRIGGER reject_contract_projection BEFORE INSERT OR UPDATE ON {records} \
                 FOR EACH ROW EXECUTE FUNCTION {schema}.reject_contract_projection()"
            )
            .as_str(),
        )
        .await?;
    Ok(())
}

pub async fn physical_tables(db: &PostgresDb) -> Result<Vec<String>> {
    Ok(sqlx::query_scalar(
        "SELECT table_name FROM information_schema.tables \
         WHERE table_schema=$1 ORDER BY table_name",
    )
    .bind(db.schema())
    .fetch_all(&db.pool)
    .await?)
}

pub async fn current_search_path(db: &PostgresDb) -> Result<String> {
    Ok(sqlx::query_scalar("SHOW search_path")
        .fetch_one(&db.pool)
        .await?)
}

#[cfg(test)]
mod runtime_config_tests {
    use super::*;

    fn base_config_value() -> Value {
        json!({
            "format": POSTGRES_RUNTIME_CONFIG_FORMAT,
            "logical_database_id": "workspace:alpha",
            "endpoint_url": "postgresql://database.internal/native",
            "runtime_password": "runtime-secret-value",
            "tls_mode": "verify-full",
            "application_name": "native-ce",
            "pool": PostgresPoolConfig::default(),
            "timeouts": PostgresTimeoutConfig::default()
        })
    }

    fn config_error(value: Value) -> String {
        PostgresRuntimeConfig::from_json(&serde_json::to_vec(&value).unwrap())
            .unwrap_err()
            .to_string()
    }

    fn codec_section() -> Section {
        Section {
            format: "native.interchange-section.v1".into(),
            revision: 1,
            name: "codec_fixture".into(),
            columns: ["text", "optional", "integer", "json", "timestamp", "value"]
                .into_iter()
                .map(|name| crate::interchange::Column {
                    name: name.into(),
                    declared_type: "TEXT".into(),
                })
                .collect(),
            primary_key: vec!["text".into()],
            rows: vec![vec![
                Cell::Text("alpha".into()),
                Cell::Null,
                Cell::Integer(7),
                Cell::Text(r#"{"ok":true}"#.into()),
                Cell::Text("2026-08-10T12:34:56Z".into()),
                Cell::Text("facet".into()),
            ]],
        }
    }

    fn config_json(extra: &str) -> Vec<u8> {
        format!(
            r#"{{
                "format":"native.postgres-runtime.v1",
                "logical_database_id":"workspace:alpha",
                "endpoint_url":"postgresql://database.internal/native",
                "runtime_password":"runtime-secret-value",
                "tls_mode":"verify-full"{extra}
            }}"#
        )
        .into_bytes()
    }

    #[test]
    fn runtime_config_derives_stable_names_and_redacts_every_secret() {
        let config = PostgresRuntimeConfig::from_json(&config_json(
            r#", "admin_url":"postgresql://admin:admin-secret@database.internal/native", "ownership_token":"ownership-token-value""#,
        ))
        .unwrap();
        assert_eq!(
            config.schema_name(),
            "native_43f0f26c4c191b5b1e2b31d08ffb2950"
        );
        assert_eq!(
            config.runtime_role(),
            "native_43f0f26c4c191b5b1e2b31d0_runtime"
        );
        let debug = format!("{config:?}");
        assert!(!debug.contains("runtime-secret-value"));
        assert!(!debug.contains("admin-secret"));
        assert!(!debug.contains("ownership-token-value"));
        let redacted = serde_json::to_string(&config.redacted()).unwrap();
        assert!(!redacted.contains("runtime-secret-value"));
        assert!(!redacted.contains("admin-secret"));
        assert!(!redacted.contains("ownership-token-value"));
        assert!(redacted.contains("[redacted]"));
    }

    #[test]
    fn postgres_feature_explicitly_selects_rustls_with_native_roots() {
        let manifest = include_str!("../Cargo.toml");
        assert!(
            manifest.contains("\"sqlx/tls-rustls-ring-native-roots\""),
            "the production Postgres feature must compile SQLx's rustls native-root backend"
        );
        // Keep an API-level compile assertion beside the feature assertion so
        // verified TLS modes and explicit PEM roots remain representable.
        let _options = PgConnectOptions::from_str("postgresql://database.internal/native")
            .unwrap()
            .ssl_mode(PgSslMode::VerifyFull)
            .ssl_root_cert_from_pem(Vec::new());
    }

    #[test]
    fn runtime_config_rejects_ambiguous_or_unbounded_settings() {
        let unpaired = PostgresRuntimeConfig::from_json(&config_json(
            r#", "admin_url":"postgresql://admin@database.internal/native""#,
        ))
        .unwrap_err()
        .to_string();
        assert!(unpaired.contains("must be supplied together"), "{unpaired}");

        let invalid_timeout = PostgresRuntimeConfig::from_json(
            br#"{
                "format":"native.postgres-runtime.v1",
                "logical_database_id":"workspace:alpha",
                "endpoint_url":"postgresql://database.internal/native",
                "runtime_password":"runtime-secret-value",
                "tls_mode":"require",
                "timeouts":{"statement_timeout_ms":1000,"lock_timeout_ms":1001}
            }"#,
        )
        .unwrap_err()
        .to_string();
        assert!(
            invalid_timeout.contains("lock_timeout_ms"),
            "{invalid_timeout}"
        );
    }

    #[test]
    fn runtime_config_rejects_each_security_boundary_and_builds_owned_options() {
        let mut cases = Vec::new();
        for (pointer, replacement, expected) in [
            (
                "/format",
                json!("native.postgres-runtime.v2"),
                "unsupported Postgres runtime config format",
            ),
            ("/logical_database_id", json!(""), "logical_database_id"),
            (
                "/logical_database_id",
                json!("x".repeat(129)),
                "logical_database_id",
            ),
            (
                "/logical_database_id",
                json!("workspace:\u{0}"),
                "logical_database_id",
            ),
            (
                "/endpoint_url",
                json!(""),
                "endpoint_url and runtime_password",
            ),
            (
                "/runtime_password",
                json!(""),
                "endpoint_url and runtime_password",
            ),
            ("/application_name", json!(""), "application_name"),
            (
                "/application_name",
                json!("x".repeat(64)),
                "application_name",
            ),
            (
                "/application_name",
                json!("native\u{0}"),
                "application_name",
            ),
            ("/pool/max_connections", json!(0), "pool and timeout values"),
            (
                "/pool/min_connections",
                json!(13),
                "pool and timeout values",
            ),
            (
                "/timeouts/statement_timeout_ms",
                json!(0),
                "pool and timeout values",
            ),
            (
                "/timeouts/lock_timeout_ms",
                json!(0),
                "pool and timeout values",
            ),
        ] {
            let mut value = base_config_value();
            if pointer.starts_with("/pool/") {
                value["pool"] = serde_json::to_value(PostgresPoolConfig::default()).unwrap();
            }
            if pointer.starts_with("/timeouts/") {
                value["timeouts"] = serde_json::to_value(PostgresTimeoutConfig::default()).unwrap();
            }
            *value.pointer_mut(pointer).unwrap() = replacement;
            cases.push((value, expected));
        }
        for (value, expected) in cases {
            let error = config_error(value);
            assert!(error.contains(expected), "{error}");
        }

        assert!(PostgresRuntimeConfig::from_json(b"{")
            .unwrap_err()
            .to_string()
            .contains("invalid Postgres runtime config"));

        let mut owned = base_config_value();
        owned["admin_url"] = json!("postgresql://admin@database.internal/native");
        owned["ownership_token"] = json!("short");
        assert!(config_error(owned.clone()).contains("at least 16 characters"));
        owned["ownership_token"] = json!("ownership-token-value");
        let config =
            PostgresRuntimeConfig::from_json(&serde_json::to_vec(&owned).unwrap()).unwrap();
        assert!(config.marker().unwrap().starts_with("native-ce:v1:"));
        config.runtime_connect_options().unwrap();
        config.admin_connect_options().unwrap();

        let unowned =
            PostgresRuntimeConfig::from_json(&serde_json::to_vec(&base_config_value()).unwrap())
                .unwrap();
        assert!(unowned
            .marker()
            .unwrap_err()
            .to_string()
            .contains("not configured"));
        assert!(unowned
            .admin_connect_options()
            .unwrap_err()
            .to_string()
            .contains("not configured"));

        for mode in [
            PostgresTlsMode::Disable,
            PostgresTlsMode::Prefer,
            PostgresTlsMode::Require,
            PostgresTlsMode::VerifyCa,
            PostgresTlsMode::VerifyFull,
        ] {
            let _ = mode.sqlx();
        }
    }

    #[test]
    fn canonical_cell_codecs_and_identifier_guards_fail_closed() {
        let section = codec_section();
        let row = &section.rows[0];
        assert_eq!(text(&section, row, "text").unwrap(), "alpha");
        assert_eq!(optional_text_cell(&section, row, "optional").unwrap(), None);
        assert_eq!(
            optional_text_cell(&section, row, "text").unwrap(),
            Some("alpha")
        );
        assert_eq!(integer(&section, row, "integer").unwrap(), 7);
        assert_eq!(
            json_text_cell(&section, row, "json").unwrap(),
            json!({"ok":true})
        );
        assert_eq!(
            json_text_cell(&section, row, "optional").unwrap(),
            Value::Null
        );
        assert!(timestamp_micros(&section, row, "timestamp").unwrap() > 0);
        assert_eq!(facet_value_cell(&section, row).unwrap(), json!("facet"));

        assert!(cell(&section, row, "missing")
            .unwrap_err()
            .to_string()
            .contains("missing column"));
        assert!(cell(&section, &row[..1], "integer")
            .unwrap_err()
            .to_string()
            .contains("short row"));
        assert!(text(&section, row, "integer")
            .unwrap_err()
            .to_string()
            .contains("must be text"));
        assert!(optional_text_cell(&section, row, "integer")
            .unwrap_err()
            .to_string()
            .contains("text or null"));
        assert!(integer(&section, row, "text")
            .unwrap_err()
            .to_string()
            .contains("integer"));

        let mut invalid = section.clone();
        invalid.rows[0][3] = Cell::Text("not-json".into());
        assert!(json_text_cell(&invalid, &invalid.rows[0], "json")
            .unwrap_err()
            .to_string()
            .contains("invalid JSON"));
        invalid.rows[0][4] = Cell::Text("not-a-time".into());
        assert!(timestamp_micros(&invalid, &invalid.rows[0], "timestamp")
            .unwrap_err()
            .to_string()
            .contains("invalid timestamp"));
        invalid.rows[0][5] = Cell::Integer(1);
        assert!(facet_value_cell(&invalid, &invalid.rows[0])
            .unwrap_err()
            .to_string()
            .contains("text or null"));
        invalid.rows[0][5] = Cell::Null;
        assert_eq!(
            facet_value_cell(&invalid, &invalid.rows[0]).unwrap(),
            Value::Null
        );

        assert_eq!(
            quote_identifier("native_schema").unwrap(),
            "\"native_schema\""
        );
        assert!(quote_identifier("Native-Schema").is_err());
        assert_eq!(
            quote_operator_identifier("operator\"db").unwrap(),
            "\"operator\"\"db\""
        );
        assert!(quote_operator_identifier("bad\0db").is_err());
        for tag in ["proof_123", "a"] {
            validate_schema_tag(tag).unwrap();
        }
        for tag in ["", "too_long_tag", "Upper", "bad-tag"] {
            assert!(validate_schema_tag(tag).is_err(), "{tag}");
        }
        for (kind, name, relation) in [
            (PostgresLogKind::Content, "content", "content_events"),
            (PostgresLogKind::Meta, "meta", "meta_events"),
            (PostgresLogKind::Policy, "policy", "policy_events"),
            (PostgresLogKind::Control, "control", "control_events"),
        ] {
            assert_eq!(kind.as_str(), name);
            assert_eq!(kind.relation(), relation);
        }
    }

    #[test]
    fn postgres_v6_causal_migration_is_required_and_non_defaulted() {
        let ddl = postgres_v6_schema("native_test").join("\n");
        assert!(ddl.contains("DEFAULT 1"));
        assert!(ddl.contains("DEFAULT 'legacy_unknown'"));
        assert!(ddl.contains("ALTER COLUMN causal_envelope_version DROP DEFAULT"));
        assert!(ddl.contains("ALTER COLUMN causal_status DROP DEFAULT"));
        assert!(ddl.contains("COALESCE(MAX(seq),0)"));
        assert!(!ddl.contains("INSERT INTO native_test.content_event_causal_frontier"));
    }

    #[cfg(feature = "postgres-tests")]
    #[tokio::test]
    async fn postgres_local_appends_advance_the_exact_causal_head() {
        let Some(url) = std::env::var_os("NATIVE_CE_POSTGRES_TEST_URL") else {
            return;
        };
        let cluster = PostgresCluster::connect(
            url.to_str()
                .expect("NATIVE_CE_POSTGRES_TEST_URL must be valid UTF-8"),
        )
        .await
        .unwrap();
        let db = cluster.fresh_logical_database().await.unwrap();
        let caller = Caller::local();
        let record_id = "17fec000-0000-4000-8000-000000000006";
        create_record(
            &db,
            &caller,
            json!({
                "id":record_id,
                "type":"Document",
                "kind":"note",
                "name":"Postgres causal head",
                "reason":"Exercise the v1 causal append contract."
            }),
        )
        .await
        .unwrap();
        update_record(
            &db,
            &caller,
            json!({
                "id":record_id,
                "summary":"second revision",
                "reason":"Advance the exact local causal head."
            }),
        )
        .await
        .unwrap();

        let events = db.qualified_table("content_events").unwrap();
        let frontier = db.qualified_table("content_event_causal_frontier").unwrap();
        let rows: Vec<(i64, String, i64, String)> = sqlx::query_as(&format!(
            "SELECT seq,id,causal_envelope_version,causal_status FROM {events} ORDER BY seq"
        ))
        .fetch_all(db.pool())
        .await
        .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(
            (rows[0].0, rows[0].2, rows[0].3.as_str()),
            (1, 1, "complete")
        );
        assert_eq!(
            (rows[1].0, rows[1].2, rows[1].3.as_str()),
            (2, 1, "complete")
        );
        let edges: Vec<(String, String)> = sqlx::query_as(&format!(
            "SELECT event_id,parent_event_id FROM {frontier} ORDER BY event_id,parent_event_id"
        ))
        .fetch_all(db.pool())
        .await
        .unwrap();
        assert_eq!(edges, vec![(rows[1].1.clone(), rows[0].1.clone())]);

        db.drop_schema().await.unwrap();
        cluster.close().await;
    }

    #[tokio::test]
    async fn closed_runtime_health_and_commit_wakes_are_deterministic() {
        let hub = Arc::new(PostgresRealtimeHub::new());
        let mut receiver = hub.subscribe();
        let completion = PostgresRequestRealtimeCompletion {
            committed: AtomicBool::new(true),
            hub: Arc::clone(&hub),
        };
        completion.finish();
        assert_eq!(receiver.recv().await.unwrap(), 1);
        completion.finish();
        assert!(receiver.try_recv().is_err());

        let options = PgConnectOptions::from_str("postgresql://localhost/native").unwrap();
        let db = PostgresDb {
            pool: PgPoolOptions::new().connect_lazy_with(options.clone()),
            query_pool: PgPoolOptions::new().connect_lazy_with(options),
            query_role: "native_closed_query".into(),
            schema: "native_closed".into(),
            schema_tag: None,
            runtime: None,
            portability_policy_gate: Arc::new(tokio::sync::RwLock::new(())),
            realtime_hub: hub,
            #[cfg(feature = "postgres-tests")]
            intent_persist_checkpoint: Arc::new(PostgresIntentPersistCheckpoint::default()),
            request_lifecycle_test_bypass: true,
        };
        assert!(db.liveness());
        assert_eq!(db.schema(), "native_closed");
        assert_eq!(db.logical_database_id(), None);
        assert_eq!(db.redacted_config(), None);
        db.close().await;
        let health = db.health().await.unwrap();
        assert!(!health.live);
        assert!(!health.reachable);
        assert_eq!(health.schema_currency, PostgresSchemaCurrency::Missing);
    }

    #[tokio::test]
    async fn registry_routes_the_postgres_handle_without_backend_fallback() {
        let options = PgConnectOptions::from_str("postgresql://localhost/native").unwrap();
        let db = PostgresDb {
            pool: PgPoolOptions::new().connect_lazy_with(options.clone()),
            query_pool: PgPoolOptions::new().connect_lazy_with(options),
            query_role: "native_43f0f26c4c191b5b1e2b31d08ffb2950_query".into(),
            schema: "native_43f0f26c4c191b5b1e2b31d08ffb2950".into(),
            schema_tag: None,
            runtime: None,
            portability_policy_gate: Arc::new(tokio::sync::RwLock::new(())),
            realtime_hub: Arc::new(PostgresRealtimeHub::new()),
            #[cfg(feature = "postgres-tests")]
            intent_persist_checkpoint: Arc::new(PostgresIntentPersistCheckpoint::default()),
            request_lifecycle_test_bypass: true,
        };
        let mut registry = ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut registry).unwrap();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        register_postgres_tools(&mut registry).unwrap();

        let ping = registry
            .call_engine(
                EngineHandle::Postgres(db.clone()),
                Caller::local(),
                "ping",
                json!({}),
            )
            .await
            .unwrap();
        assert_eq!(ping["ok"], true);
        let interpretation_error = registry
            .call_engine(
                EngineHandle::Postgres(db.clone()),
                Caller::local(),
                "get_record",
                json!({"ids":["record"],"include_interpretation":true}),
            )
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(
            interpretation_error,
            "postgres-server operation 'get_record interpretation projection' is unsupported by the qualified domain boundary"
        );
        let history_error = registry
            .call_engine(
                EngineHandle::Postgres(db.clone()),
                Caller::authenticated("acct:unrelated"),
                "get_history",
                json!({}),
            )
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(
            history_error,
            "get_history: Postgres requires record_id; whole-log history is not qualified"
        );
        let local_history_error = registry
            .call_engine(
                EngineHandle::Postgres(db.clone()),
                Caller::local(),
                "get_history",
                json!({}),
            )
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(
            local_history_error,
            "get_history: Postgres requires record_id; whole-log history is not qualified"
        );
        let error = registry
            .call_engine(
                EngineHandle::Postgres(db.clone()),
                Caller::local(),
                "query_sql",
                json!({}),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.starts_with("query_sql [invalid_arguments]: missing field `sql`"),
            "{error}"
        );
        db.close().await;
    }

    #[cfg(feature = "mcp-executor-prototype")]
    #[tokio::test]
    async fn postgres_record_type_correction_source_cannot_bypass_claimed_plan() {
        let options = PgConnectOptions::from_str("postgresql://localhost/native").unwrap();
        let db = PostgresDb {
            pool: PgPoolOptions::new().connect_lazy_with(options.clone()),
            query_pool: PgPoolOptions::new().connect_lazy_with(options),
            query_role: "native_closed_query".into(),
            schema: "native_closed".into(),
            schema_tag: None,
            runtime: None,
            portability_policy_gate: Arc::new(tokio::sync::RwLock::new(())),
            realtime_hub: Arc::new(PostgresRealtimeHub::new()),
            #[cfg(feature = "postgres-tests")]
            intent_persist_checkpoint: Arc::new(PostgresIntentPersistCheckpoint::default()),
            request_lifecycle_test_bypass: true,
        };
        let mut registry = ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        register_postgres_tools(&mut registry).unwrap();
        let bypass = registry
            .call_engine(
                EngineHandle::Postgres(db.clone()),
                Caller::local(),
                "correct_record_type",
                json!({
                    "record_id":"00000000-0000-4000-8000-000000000001",
                    "target_type":"Resolution",
                    "target_kind":"decision",
                    "reason":"Attempt direct source-tool execution.",
                    "if_content_seq":1,
                    "if_schema_state_revision":"schema-state-v1:meta:1:content:1",
                    "if_dependency_digest":"a".repeat(64),
                    "plan_id":"wpl1:forged",
                    "effect_digest":"b".repeat(64),
                    "mode":"confirmed",
                    "confirmation_required":true
                }),
            )
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(
            bypass,
            "correct_record_type: execute only through a claimed records_write.correct_record_type plan"
        );
        db.close().await;
    }

    #[cfg(all(feature = "mcp-executor-prototype", feature = "postgres-tests"))]
    #[tokio::test]
    async fn postgres_record_type_correction_is_prepared_claimed_and_stale_safe() {
        let Some(url) = std::env::var_os("NATIVE_CE_POSTGRES_TEST_URL") else {
            return;
        };
        let cluster = PostgresCluster::connect(
            url.to_str()
                .expect("NATIVE_CE_POSTGRES_TEST_URL must be valid UTF-8"),
        )
        .await
        .unwrap();
        let db = cluster.fresh_logical_database().await.unwrap();
        let caller = Caller::local();
        let record_id = "17fec000-0000-4000-8000-000000000002";
        create_record(
            &db,
            &caller,
            json!({
                "id": record_id,
                "type": "Document",
                "kind": "decision",
                "name": "Misfiled Postgres decision",
                "body": "The bearer body must remain unchanged.",
                "reason": "Install the governed correction contract fixture."
            }),
        )
        .await
        .unwrap();
        let request = json!({
            "record_id": record_id,
            "target_type": "Resolution",
            "target_kind": "decision",
            "reason": "Correct the registry-proven wrong spine type."
        });
        let events = db.qualified_table("content_events").unwrap();
        let before: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {events}"))
            .fetch_one(db.pool())
            .await
            .unwrap();
        let prepared = prepare_correct_record_type(&db, &caller, request.clone())
            .await
            .unwrap();
        let after: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {events}"))
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(after, before, "preparation must not publish an event");
        assert_eq!(prepared.effect["eligibility"], "confirmation_required");

        update_record(
            &db,
            &caller,
            json!({
                "id": record_id,
                "summary": "Concurrent edit",
                "reason": "Make the prepared correction stale."
            }),
        )
        .await
        .unwrap();
        let mut stale_arguments = prepared.canonical_source_arguments;
        stale_arguments["plan_id"] = json!("wpl1:postgres-stale");
        stale_arguments["effect_digest"] = json!("a".repeat(64));
        let stale_caller =
            caller
                .clone()
                .with_write_plan_execution(crate::mcp::registry::WritePlanExecution {
                    plan_id: "wpl1:postgres-stale".into(),
                    effect_digest: "a".repeat(64),
                    executor: "records_write".into(),
                    operation: "correct_record_type".into(),
                });
        let stale = correct_record_type(&db, &stale_caller, stale_arguments)
            .await
            .unwrap_err()
            .to_string();
        assert!(stale.contains("content revision conflict"), "{stale}");

        let fresh = prepare_correct_record_type(&db, &caller, request)
            .await
            .unwrap();
        let body_digest = fresh.effect["identity_and_body"]["body_digest_unchanged"]
            .as_str()
            .unwrap()
            .to_owned();
        let mut execute_arguments = fresh.canonical_source_arguments;
        execute_arguments["plan_id"] = json!("wpl1:postgres-fresh");
        execute_arguments["effect_digest"] = json!("b".repeat(64));
        let execution_caller =
            caller.with_write_plan_execution(crate::mcp::registry::WritePlanExecution {
                plan_id: "wpl1:postgres-fresh".into(),
                effect_digest: "b".repeat(64),
                executor: "records_write".into(),
                operation: "correct_record_type".into(),
            });
        let corrected = correct_record_type(&db, &execution_caller, execute_arguments)
            .await
            .unwrap();
        assert_eq!(corrected["record_id"], record_id);
        assert_eq!(corrected["type"], "Resolution");
        assert_eq!(corrected["kind"], "decision");
        assert_eq!(corrected["body_digest"], body_digest);

        let records = db.qualified_table("records").unwrap();
        let row: (String, String, Option<String>) = sqlx::query_as(&format!(
            "SELECT record_type,kind,body FROM {records} WHERE id=$1"
        ))
        .bind(record_id)
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(row.0, "Resolution");
        assert_eq!(row.1, "decision");
        assert_eq!(
            row.2.as_deref(),
            Some("The bearer body must remain unchanged.")
        );
        let corrections: i64 = sqlx::query_scalar(&format!(
            "SELECT COUNT(*) FROM {events} WHERE record_id=$1 AND type='record.type_corrected.v1'"
        ))
        .bind(record_id)
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(corrections, 1);
        db.assert_replay_equivalent().await.unwrap();

        db.drop_schema().await.unwrap();
        cluster.close().await;
    }
}
