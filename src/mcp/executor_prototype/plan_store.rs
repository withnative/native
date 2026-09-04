//! Durable lifecycle storage for executor write plans.
//!
//! The plan payload is deliberately opaque here. Operation-specific
//! preparation and revalidation stay in `write_operations`; this module owns
//! only signing keys and atomic lifecycle transitions. A separate, versioned
//! SQLite file avoids silently extending the user database schema and can be
//! shared by multiple local executor processes that open the same database.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use futures::future::BoxFuture;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::Sha256;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Row, SqlitePool};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};

const STORE_SCHEMA_VERSION: i64 = 1;
const KEY_ROTATION_INTERVAL_MS: i64 = 30 * 24 * 60 * 60 * 1_000;
const HOSTED_KEY_READINESS_TIMEOUT: Duration = Duration::from_secs(5);
const HOSTED_KEY_READINESS_DOMAIN: &str = "native.mcp-executor.hosted-key-readiness.v1";
const HOSTED_STORED_PLAN_FORMAT: &str = "native.hosted-write-plan-envelope.v1";
const HOSTED_RETAINED_KEY_DOMAIN: &str = "native.mcp-executor.retained-key.v1";
const DEPLOYMENT_KEYRING_MAX_BYTES: usize = 16 * 1024;
pub(super) const HOSTED_MAX_RETAINED_KEYS: usize = 16;
const DEPLOYMENT_KEY_BYTES: usize = 32;
pub(super) const EXPIRED_PLAN_RETENTION_MS: i64 = 7 * 24 * 60 * 60 * 1_000;
type HmacSha256 = Hmac<Sha256>;

const STORE_SCHEMA: &[&str] = &[
    r#"CREATE TABLE write_plan_keys (
         key_id         TEXT PRIMARY KEY,
         secret         BLOB NOT NULL CHECK (length(secret) = 32),
         status         TEXT NOT NULL CHECK (status IN ('active','retired')),
         created_at_ms  INTEGER NOT NULL,
         retired_at_ms  INTEGER
       )"#,
    r#"CREATE UNIQUE INDEX write_plan_keys_one_active
       ON write_plan_keys(status) WHERE status = 'active'"#,
    r#"CREATE TABLE write_plans (
         plan_id                TEXT PRIMARY KEY,
         payload                TEXT NOT NULL CHECK (json_valid(payload)),
         key_id                 TEXT NOT NULL REFERENCES write_plan_keys(key_id),
         state                  TEXT NOT NULL
                                CHECK (state IN ('prepared','executing','completed','expired','indeterminate')),
         expires_at_ms          INTEGER NOT NULL,
         attempt_id             TEXT,
         execution_owner        TEXT,
         started_at_ms          INTEGER,
         completed_at_ms        INTEGER,
         result                 TEXT CHECK (result IS NULL OR json_valid(result)),
         source_dispatch_count  INTEGER NOT NULL DEFAULT 0 CHECK (source_dispatch_count >= 0),
         terminal_reason        TEXT,
         created_at_ms          INTEGER NOT NULL,
         updated_at_ms          INTEGER NOT NULL,
         CHECK ((state = 'prepared' AND attempt_id IS NULL AND execution_owner IS NULL AND started_at_ms IS NULL)
             OR (state IN ('executing','indeterminate') AND attempt_id IS NOT NULL AND execution_owner IS NOT NULL AND started_at_ms IS NOT NULL)
             OR (state = 'completed' AND attempt_id IS NOT NULL AND execution_owner IS NOT NULL AND started_at_ms IS NOT NULL AND completed_at_ms IS NOT NULL AND result IS NOT NULL)
             OR state = 'expired')
       )"#,
    r#"CREATE INDEX write_plans_expiry ON write_plans(state, expires_at_ms)"#,
];

/// Hosted signing is operator-owned. Every instance serving one catalogue
/// must resolve the same active and retained key ids. There is intentionally
/// no catalogue, volume, or implicit local fallback.
pub trait HostedPlanKeyProvider: Send + Sync {
    fn active_key_id(&self) -> BoxFuture<'static, Result<String>>;
    fn seal(&self, key_id: String, payload: Value) -> BoxFuture<'static, Result<String>>;
    fn verify(
        &self,
        key_id: String,
        payload: Value,
        signature: String,
    ) -> BoxFuture<'static, Result<()>>;
}

/// Authoritative hosted catalogue storage for executor write-plan lifecycle
/// rows.
///
/// The executor owns the lifecycle SQL and its activity-epoch fences. Hosting
/// supplies only the catalogue pool capability, so the public executor does
/// not depend on the concrete held catalogue type.
/// Implementations must return the pool of an opened, schema-admitted hosted
/// catalogue; a user database or local plan sidecar is not a valid source.
#[doc(hidden)]
pub trait HostedPlanCatalogue: Send + Sync {
    fn executor_plan_pool(&self) -> &SqlitePool;
}

/// Strict deployment-secret keyring for the controlled hosted dogfood tier.
///
/// The provider is deliberately constructed from an already-loaded secret;
/// it never reads process environment itself and its debug representation
/// never exposes key ids or material. A managed remote KMS implementation of
/// [`HostedPlanKeyProvider`] remains the production-scale boundary.
pub struct DeploymentPlanKeyring {
    active_key_id: String,
    keys: BTreeMap<String, Zeroizing<[u8; DEPLOYMENT_KEY_BYTES]>>,
}

impl std::fmt::Debug for DeploymentPlanKeyring {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DeploymentPlanKeyring([redacted])")
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeploymentKeyringInput {
    active_key_id: String,
    keys: Vec<DeploymentKeyInput>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeploymentKeyInput {
    id: String,
    key: String,
}

impl DeploymentPlanKeyring {
    /// Parse the bounded JSON supplied by the hosting secret configuration.
    /// Validation errors intentionally identify only shape, never secret data.
    pub fn from_json(raw: &str) -> Result<Self> {
        if raw.len() > DEPLOYMENT_KEYRING_MAX_BYTES {
            return Err(Error::engine(
                "hosted write plan keyring exceeds the 16 KiB limit",
            ));
        }
        let mut input: DeploymentKeyringInput = serde_json::from_str(raw)
            .map_err(|_| Error::engine("hosted write plan keyring is invalid JSON or shape"))?;
        if input.keys.is_empty() || input.keys.len() > HOSTED_MAX_RETAINED_KEYS {
            return Err(Error::engine(
                "hosted write plan keyring must contain 1-16 keys",
            ));
        }
        validate_deployment_key_id(&input.active_key_id)?;
        let mut keys = BTreeMap::new();
        for mut entry in input.keys.drain(..) {
            validate_deployment_key_id(&entry.id)?;
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(entry.key.as_bytes())
                .map_err(|_| Error::engine("hosted write plan keyring contains an invalid key"));
            entry.key.zeroize();
            let mut decoded = decoded?;
            if decoded.len() != DEPLOYMENT_KEY_BYTES {
                decoded.zeroize();
                return Err(Error::engine(
                    "hosted write plan keyring keys must decode to exactly 32 bytes",
                ));
            }
            let mut secret = [0_u8; DEPLOYMENT_KEY_BYTES];
            secret.copy_from_slice(&decoded);
            decoded.zeroize();
            if keys.insert(entry.id, Zeroizing::new(secret)).is_some() {
                return Err(Error::engine(
                    "hosted write plan keyring contains a duplicate key id",
                ));
            }
        }
        if !keys.contains_key(&input.active_key_id) {
            return Err(Error::engine(
                "hosted write plan keyring active key id is not retained",
            ));
        }
        Ok(Self {
            active_key_id: input.active_key_id,
            keys,
        })
    }
}

fn validate_deployment_key_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 64
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(Error::engine(
            "hosted write plan key ids must be 1-64 safe ASCII characters",
        ));
    }
    Ok(())
}

impl HostedPlanKeyProvider for DeploymentPlanKeyring {
    fn active_key_id(&self) -> BoxFuture<'static, Result<String>> {
        let active_key_id = self.active_key_id.clone();
        Box::pin(async move { Ok(active_key_id) })
    }

    fn seal(&self, key_id: String, payload: Value) -> BoxFuture<'static, Result<String>> {
        let secret = (key_id == self.active_key_id)
            .then(|| self.keys.get(&key_id).map(|secret| **secret))
            .flatten();
        Box::pin(async move {
            let mut secret = secret.ok_or_else(|| {
                Error::engine("hosted write plan active signing key is unavailable")
            })?;
            let result = sign(&secret, &payload);
            secret.zeroize();
            result
        })
    }

    fn verify(
        &self,
        key_id: String,
        payload: Value,
        signature: String,
    ) -> BoxFuture<'static, Result<()>> {
        let secret = self.keys.get(&key_id).map(|secret| **secret);
        Box::pin(async move {
            let mut secret = secret.ok_or_else(|| {
                Error::engine("hosted write plan verification key is unavailable")
            })?;
            let result = verify_signature(&secret, &payload, &signature);
            secret.zeroize();
            result
        })
    }
}

pub(super) async fn validate_hosted_key_provider(
    keys: &Arc<dyn HostedPlanKeyProvider>,
) -> Result<()> {
    let keys = keys.clone();
    tokio::time::timeout(HOSTED_KEY_READINESS_TIMEOUT, async move {
        let active_key_id = keys.active_key_id().await?;
        if active_key_id.trim().is_empty() {
            return Err(Error::engine(
                "hosted write plan key provider returned an empty active key id",
            ));
        }
        // Fixed and non-secret by design: this proves the active provider path
        // can both sign and resolve that signature without persisting or
        // exposing any user or plan material.
        let challenge = json!({"domain":HOSTED_KEY_READINESS_DOMAIN});
        let signature = keys.seal(active_key_id.clone(), challenge.clone()).await?;
        keys.verify(active_key_id, challenge, signature).await
    })
    .await
    .map_err(|_| Error::engine("hosted write plan key provider readiness timed out"))?
}

#[derive(Clone)]
pub(super) struct PlanStore {
    backend: PlanStoreBackend,
    keys: Arc<dyn HostedPlanKeyProvider>,
    instance_id: String,
}

#[derive(Clone)]
enum PlanStoreBackend {
    Local(SqlitePool),
    Catalogue {
        catalog: Arc<dyn HostedPlanCatalogue>,
        db_id: String,
        activity_epoch: i64,
    },
}

impl std::fmt::Debug for PlanStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PlanStore")
            .field(
                "backend",
                &match &self.backend {
                    PlanStoreBackend::Local(_) => "local-sidecar",
                    PlanStoreBackend::Catalogue { .. } => "shared-catalogue",
                },
            )
            .field("instance_id", &self.instance_id)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct LocalPlanKeyProvider {
    pool: SqlitePool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum StoredState {
    Prepared,
    Executing {
        started_at_ms: i64,
        attempt_id: String,
    },
    Completed {
        result: Value,
        source_dispatch_count: u64,
    },
    Expired,
    Indeterminate {
        started_at_ms: i64,
        attempt_id: String,
    },
}

#[derive(Clone, Debug)]
pub(super) struct StoredPlan {
    pub payload: Value,
    pub key_id: String,
    /// Hosted catalogue CAS digest over the complete storage envelope. Local
    /// sidecars have no catalogue transaction and therefore leave this empty.
    pub catalogue_payload_sha256: Option<String>,
    pub state: StoredState,
    pub expires_at_ms: i64,
}

#[derive(Clone, Debug)]
pub(super) enum ClaimOutcome {
    Claimed {
        plan: StoredPlan,
        attempt_id: String,
    },
    Existing(StoredPlan),
    NotFound,
}

impl PlanStore {
    pub(super) async fn open_for_database(database_path: &Path) -> Result<Self> {
        let path = sidecar_path(database_path)?;
        prepare_sidecar_file(&path)?;
        let options = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(false)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5))
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full);
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(options)
            .await?;
        initialize_schema(&pool).await?;
        rotate_local_key_if_older_than(
            &pool,
            chrono::Utc::now().timestamp_millis(),
            KEY_ROTATION_INTERVAL_MS,
        )
        .await?;
        Ok(Self {
            backend: PlanStoreBackend::Local(pool.clone()),
            keys: Arc::new(LocalPlanKeyProvider { pool }),
            instance_id: Uuid::new_v4().to_string(),
        })
    }

    /// Open the shared catalogue lifecycle store for one authoritative hosted
    /// database. The caller must supply a genuinely shared key provider; this
    /// constructor has no path to the local sidecar or its local key table.
    #[cfg(test)]
    pub(super) async fn open_for_catalogue<C>(
        catalog: C,
        db_id: impl Into<String>,
        keys: Arc<dyn HostedPlanKeyProvider>,
    ) -> Result<Self>
    where
        C: HostedPlanCatalogue + 'static,
    {
        validate_hosted_key_provider(&keys).await?;
        Self::open_for_catalogue_with_ready_keys(catalog, db_id, keys).await
    }

    /// Open after an enclosing process/router startup boundary has already
    /// validated the shared provider. The store still consults that provider
    /// for every seal/verify operation; this only avoids a second ambiguous
    /// readiness probe while constructing a per-request hosted server.
    pub(super) async fn open_for_catalogue_with_ready_keys<C>(
        catalog: C,
        db_id: impl Into<String>,
        keys: Arc<dyn HostedPlanKeyProvider>,
    ) -> Result<Self>
    where
        C: HostedPlanCatalogue + 'static,
    {
        let db_id = db_id.into();
        let activity_epoch: i64 = sqlx::query_scalar(
            "SELECT activity_epoch FROM databases WHERE id = ? AND status = 'ready'",
        )
        .bind(&db_id)
        .fetch_optional(catalog.executor_plan_pool())
        .await?
        .ok_or_else(|| {
            Error::engine(
                "hosted write plan store requires an authoritative ready catalogue database",
            )
        })?;
        Ok(Self {
            backend: PlanStoreBackend::Catalogue {
                catalog: Arc::new(catalog),
                db_id,
                activity_epoch,
            },
            keys,
            instance_id: Uuid::new_v4().to_string(),
        })
    }

    pub(super) async fn active_key_id(&self) -> Result<String> {
        self.keys.active_key_id().await
    }

    pub(super) async fn seal(&self, key_id: &str, payload: &Value) -> Result<String> {
        self.keys.seal(key_id.to_owned(), payload.clone()).await
    }

    pub(super) async fn verify(
        &self,
        key_id: &str,
        payload: &Value,
        signature: &str,
    ) -> Result<()> {
        self.keys
            .verify(key_id.to_owned(), payload.clone(), signature.to_owned())
            .await
    }

    pub(super) async fn insert_prepared(
        &self,
        plan_id: &str,
        payload: &Value,
        key_id: &str,
        expires_at_ms: i64,
        now_ms: i64,
    ) -> Result<()> {
        match &self.backend {
            PlanStoreBackend::Local(pool) => {
                let payload_json = serde_json::to_string(payload)?;
                sqlx::query(
                    "INSERT INTO write_plans
                     (plan_id, payload, key_id, state, expires_at_ms, created_at_ms, updated_at_ms)
                     VALUES (?, ?, ?, 'prepared', ?, ?, ?)",
                )
                .bind(plan_id)
                .bind(payload_json)
                .bind(key_id)
                .bind(expires_at_ms)
                .bind(now_ms)
                .bind(now_ms)
                .execute(pool)
                .await?;
            }
            PlanStoreBackend::Catalogue {
                catalog,
                db_id,
                activity_epoch,
            } => {
                let stored = hosted_stored_plan_envelope(&self.keys, key_id, payload).await?;
                let payload_json = serde_json::to_string(&stored)?;
                let inserted = sqlx::query(
                    "INSERT INTO executor_write_plans
                     (plan_id, db_id, payload, payload_sha256, key_id, state,
                      expires_at_ms, created_at_ms, updated_at_ms, activity_epoch)
                     SELECT ?, databases.id, ?, ?, ?, 'prepared', ?, ?, ?, databases.activity_epoch
                     FROM databases
                     WHERE databases.id = ? AND databases.status = 'ready'
                       AND databases.activity_epoch = ?",
                )
                .bind(plan_id)
                .bind(payload_json)
                .bind(payload_sha256(&stored)?)
                .bind(key_id)
                .bind(expires_at_ms)
                .bind(now_ms)
                .bind(now_ms)
                .bind(db_id)
                .bind(activity_epoch)
                .execute(catalog.executor_plan_pool())
                .await?
                .rows_affected();
                if inserted != 1 {
                    return Err(Error::engine(
                        "hosted write plan database lifecycle changed before preparation",
                    ));
                }
            }
        }
        Ok(())
    }

    pub(super) async fn load(&self, plan_id: &str, now_ms: i64) -> Result<Option<StoredPlan>> {
        self.expire_prepared(plan_id, now_ms).await?;
        self.load_row(plan_id).await
    }

    pub(super) async fn claim(&self, plan_id: &str, now_ms: i64) -> Result<ClaimOutcome> {
        self.expire_prepared(plan_id, now_ms).await?;
        let attempt_id = Uuid::new_v4().to_string();
        let updated = match &self.backend {
            PlanStoreBackend::Local(pool) => sqlx::query(
                "UPDATE write_plans
                 SET state = 'executing', attempt_id = ?, execution_owner = ?,
                     started_at_ms = ?, updated_at_ms = ?, source_dispatch_count = 1
                 WHERE plan_id = ? AND state = 'prepared' AND expires_at_ms > ?",
            )
            .bind(&attempt_id)
            .bind(&self.instance_id)
            .bind(now_ms)
            .bind(now_ms)
            .bind(plan_id)
            .bind(now_ms)
            .execute(pool)
            .await?
            .rows_affected(),
            PlanStoreBackend::Catalogue {
                catalog,
                db_id,
                activity_epoch,
            } => sqlx::query(
                "UPDATE executor_write_plans
                 SET state = 'executing', attempt_id = ?, execution_owner = ?,
                     started_at_ms = ?, updated_at_ms = ?, source_dispatch_count = 1
                 WHERE plan_id = ? AND db_id = ? AND state = 'prepared' AND expires_at_ms > ?
                   AND activity_epoch = ?
                   AND EXISTS (
                     SELECT 1 FROM databases
                     WHERE databases.id = executor_write_plans.db_id
                       AND databases.status = 'ready'
                       AND databases.activity_epoch = executor_write_plans.activity_epoch
                       AND databases.activity_epoch = ?
                   )",
            )
            .bind(&attempt_id)
            .bind(&self.instance_id)
            .bind(now_ms)
            .bind(now_ms)
            .bind(plan_id)
            .bind(db_id)
            .bind(now_ms)
            .bind(activity_epoch)
            .bind(activity_epoch)
            .execute(catalog.executor_plan_pool())
            .await?
            .rows_affected(),
        };
        let Some(plan) = self.load_row(plan_id).await? else {
            return Ok(ClaimOutcome::NotFound);
        };
        if updated == 1 {
            return Ok(ClaimOutcome::Claimed { plan, attempt_id });
        }
        Ok(ClaimOutcome::Existing(plan))
    }

    pub(super) async fn complete(
        &self,
        plan_id: &str,
        attempt_id: &str,
        result: &Value,
        now_ms: i64,
    ) -> Result<()> {
        let result = serde_json::to_string(result)?;
        let updated = match &self.backend {
            PlanStoreBackend::Local(pool) => sqlx::query(
                "UPDATE write_plans
                 SET state = 'completed', result = ?, completed_at_ms = ?, updated_at_ms = ?
                 WHERE plan_id = ? AND attempt_id = ? AND state IN ('executing','indeterminate')",
            )
            .bind(result)
            .bind(now_ms)
            .bind(now_ms)
            .bind(plan_id)
            .bind(attempt_id)
            .execute(pool)
            .await?
            .rows_affected(),
            PlanStoreBackend::Catalogue { catalog, db_id, .. } => sqlx::query(
                "UPDATE executor_write_plans
                 SET state = 'completed', result = ?, completed_at_ms = ?, updated_at_ms = ?
                 WHERE plan_id = ? AND db_id = ? AND attempt_id = ?
                   AND state IN ('executing','indeterminate')",
            )
            .bind(result)
            .bind(now_ms)
            .bind(now_ms)
            .bind(plan_id)
            .bind(db_id)
            .bind(attempt_id)
            .execute(catalog.executor_plan_pool())
            .await?
            .rows_affected(),
        };
        if updated != 1 {
            return Err(Error::engine(
                "write plan completion lost its durable execution fence",
            ));
        }
        Ok(())
    }

    pub(super) async fn mark_indeterminate(
        &self,
        plan_id: &str,
        attempt_id: &str,
        reason: &str,
        now_ms: i64,
    ) -> Result<bool> {
        let updated = match &self.backend {
            PlanStoreBackend::Local(pool) => sqlx::query(
                "UPDATE write_plans
                 SET state = 'indeterminate', terminal_reason = ?, updated_at_ms = ?
                 WHERE plan_id = ? AND attempt_id = ? AND state = 'executing'",
            )
            .bind(reason)
            .bind(now_ms)
            .bind(plan_id)
            .bind(attempt_id)
            .execute(pool)
            .await?
            .rows_affected(),
            PlanStoreBackend::Catalogue { catalog, db_id, .. } => sqlx::query(
                "UPDATE executor_write_plans
                 SET state = 'indeterminate', terminal_reason = ?, updated_at_ms = ?
                 WHERE plan_id = ? AND db_id = ? AND attempt_id = ? AND state = 'executing'",
            )
            .bind(reason)
            .bind(now_ms)
            .bind(plan_id)
            .bind(db_id)
            .bind(attempt_id)
            .execute(catalog.executor_plan_pool())
            .await?
            .rows_affected(),
        };
        Ok(updated == 1)
    }

    /// Expire unused plans without deleting any lifecycle row. Completed and
    /// indeterminate rows are permanent safety tombstones in v1.
    pub(super) async fn expire_all(&self, now_ms: i64) -> Result<u64> {
        let affected = match &self.backend {
            PlanStoreBackend::Local(pool) => sqlx::query(
                "UPDATE write_plans SET state = 'expired', updated_at_ms = ?
                 WHERE state = 'prepared' AND expires_at_ms <= ?",
            )
            .bind(now_ms)
            .bind(now_ms)
            .execute(pool)
            .await?
            .rows_affected(),
            PlanStoreBackend::Catalogue {
                catalog,
                db_id,
                activity_epoch,
            } => sqlx::query(
                "UPDATE executor_write_plans SET state = 'expired', updated_at_ms = ?
                 WHERE db_id = ? AND state = 'prepared' AND expires_at_ms <= ?
                   AND activity_epoch = ?
                   AND EXISTS (
                     SELECT 1 FROM databases
                     WHERE databases.id = executor_write_plans.db_id
                       AND databases.status = 'ready'
                       AND databases.activity_epoch = executor_write_plans.activity_epoch
                       AND databases.activity_epoch = ?
                   )",
            )
            .bind(now_ms)
            .bind(db_id)
            .bind(now_ms)
            .bind(activity_epoch)
            .bind(activity_epoch)
            .execute(catalog.executor_plan_pool())
            .await?
            .rows_affected(),
        };
        Ok(affected)
    }

    /// Delete only plans that expired before any execution claim. Execution
    /// fences and completed replay rows are never eligible for cleanup.
    pub(super) async fn cleanup_expired(&self, now_ms: i64, retention_ms: i64) -> Result<u64> {
        let cutoff = now_ms.saturating_sub(retention_ms.max(0));
        let affected = match &self.backend {
            PlanStoreBackend::Local(pool) => sqlx::query(
                "DELETE FROM write_plans WHERE state = 'expired' AND updated_at_ms <= ?",
            )
            .bind(cutoff)
            .execute(pool)
            .await?
            .rows_affected(),
            PlanStoreBackend::Catalogue {
                catalog,
                db_id,
                activity_epoch,
            } => sqlx::query(
                "DELETE FROM executor_write_plans
                 WHERE db_id = ? AND state = 'expired' AND updated_at_ms <= ?
                   AND activity_epoch = ?
                   AND EXISTS (
                     SELECT 1 FROM databases
                     WHERE databases.id = executor_write_plans.db_id
                       AND databases.status = 'ready'
                       AND databases.activity_epoch = executor_write_plans.activity_epoch
                       AND databases.activity_epoch = ?
                   )",
            )
            .bind(db_id)
            .bind(cutoff)
            .bind(activity_epoch)
            .bind(activity_epoch)
            .execute(catalog.executor_plan_pool())
            .await?
            .rows_affected(),
        };
        Ok(affected)
    }

    #[cfg(test)]
    pub(super) async fn replace_payload(
        &self,
        plan_id: &str,
        payload: &Value,
        key_id: &str,
    ) -> Result<()> {
        match &self.backend {
            PlanStoreBackend::Local(pool) => {
                let payload_json = serde_json::to_string(payload)?;
                sqlx::query("UPDATE write_plans SET payload = ?, key_id = ? WHERE plan_id = ?")
                    .bind(payload_json)
                    .bind(key_id)
                    .bind(plan_id)
                    .execute(pool)
                    .await?;
            }
            PlanStoreBackend::Catalogue { catalog, db_id, .. } => {
                let stored = hosted_stored_plan_envelope(&self.keys, key_id, payload).await?;
                let payload_json = serde_json::to_string(&stored)?;
                sqlx::query(
                    "UPDATE executor_write_plans
                     SET payload = ?, payload_sha256 = ?, key_id = ?
                     WHERE plan_id = ? AND db_id = ?",
                )
                .bind(payload_json)
                .bind(payload_sha256(&stored)?)
                .bind(key_id)
                .bind(plan_id)
                .bind(db_id)
                .execute(catalog.executor_plan_pool())
                .await?;
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn local_pool(&self) -> &SqlitePool {
        match &self.backend {
            PlanStoreBackend::Local(pool) => pool,
            PlanStoreBackend::Catalogue { .. } => panic!("expected local plan store"),
        }
    }

    #[cfg(test)]
    async fn rotate_local_key_if_older_than(&self, now_ms: i64, max_age_ms: i64) -> Result<String> {
        rotate_local_key_if_older_than(self.local_pool(), now_ms, max_age_ms).await
    }

    async fn load_row(&self, plan_id: &str) -> Result<Option<StoredPlan>> {
        match &self.backend {
            PlanStoreBackend::Local(pool) => load_row(pool, "write_plans", plan_id, None).await,
            PlanStoreBackend::Catalogue { catalog, db_id, .. } => {
                load_row(
                    catalog.executor_plan_pool(),
                    "executor_write_plans",
                    plan_id,
                    Some(db_id),
                )
                .await
            }
        }
    }

    async fn expire_prepared(&self, plan_id: &str, now_ms: i64) -> Result<()> {
        match &self.backend {
            PlanStoreBackend::Local(pool) => {
                sqlx::query(
                    "UPDATE write_plans SET state = 'expired', updated_at_ms = ?
                     WHERE plan_id = ? AND state = 'prepared' AND expires_at_ms <= ?",
                )
                .bind(now_ms)
                .bind(plan_id)
                .bind(now_ms)
                .execute(pool)
                .await?;
            }
            PlanStoreBackend::Catalogue {
                catalog,
                db_id,
                activity_epoch,
            } => {
                sqlx::query(
                    "UPDATE executor_write_plans SET state = 'expired', updated_at_ms = ?
                     WHERE plan_id = ? AND db_id = ? AND state = 'prepared' AND expires_at_ms <= ?
                       AND activity_epoch = ?
                       AND EXISTS (
                         SELECT 1 FROM databases
                         WHERE databases.id = executor_write_plans.db_id
                           AND databases.status = 'ready'
                           AND databases.activity_epoch = executor_write_plans.activity_epoch
                           AND databases.activity_epoch = ?
                       )",
                )
                .bind(now_ms)
                .bind(plan_id)
                .bind(db_id)
                .bind(now_ms)
                .bind(activity_epoch)
                .bind(activity_epoch)
                .execute(catalog.executor_plan_pool())
                .await?;
            }
        }
        Ok(())
    }
}

/// Run bounded hosted lifecycle maintenance once at executor-router startup.
///
/// Hosted request servers are reconstructed for each authenticated request,
/// so maintenance in their constructor would make even frozen reads mutate
/// the catalogue. This process boundary replaces the union of the former
/// per-database passes while retaining their ready/current-epoch fence.
pub(super) async fn maintain_hosted_catalogue(
    catalog: &dyn HostedPlanCatalogue,
    now_ms: i64,
    retention_ms: i64,
) -> Result<(u64, u64)> {
    let expired = sqlx::query(
        "UPDATE executor_write_plans SET state = 'expired', updated_at_ms = ?
         WHERE state = 'prepared' AND expires_at_ms <= ?
           AND EXISTS (
             SELECT 1 FROM databases
             WHERE databases.id = executor_write_plans.db_id
               AND databases.status = 'ready'
               AND databases.activity_epoch = executor_write_plans.activity_epoch
           )",
    )
    .bind(now_ms)
    .bind(now_ms)
    .execute(catalog.executor_plan_pool())
    .await?
    .rows_affected();
    let cutoff = now_ms.saturating_sub(retention_ms.max(0));
    let cleaned = sqlx::query(
        "DELETE FROM executor_write_plans
         WHERE state = 'expired' AND updated_at_ms <= ?
           AND EXISTS (
             SELECT 1 FROM databases
             WHERE databases.id = executor_write_plans.db_id
               AND databases.status = 'ready'
               AND databases.activity_epoch = executor_write_plans.activity_epoch
           )",
    )
    .bind(cutoff)
    .execute(catalog.executor_plan_pool())
    .await?
    .rows_affected();
    Ok((expired, cleaned))
}

impl HostedPlanKeyProvider for LocalPlanKeyProvider {
    fn active_key_id(&self) -> BoxFuture<'static, Result<String>> {
        let pool = self.pool.clone();
        Box::pin(async move {
            sqlx::query_scalar("SELECT key_id FROM write_plan_keys WHERE status = 'active'")
                .fetch_optional(&pool)
                .await?
                .ok_or_else(|| Error::engine("write plan store has no active signing key"))
        })
    }

    fn seal(&self, key_id: String, payload: Value) -> BoxFuture<'static, Result<String>> {
        let pool = self.pool.clone();
        Box::pin(async move {
            let secret: Option<Vec<u8>> = sqlx::query_scalar(
                "SELECT secret FROM write_plan_keys
                 WHERE key_id = ? AND status IN ('active','retired')",
            )
            .bind(key_id)
            .fetch_optional(&pool)
            .await?;
            let secret =
                secret.ok_or_else(|| Error::engine("write plan signing key is unavailable"))?;
            sign(&secret, &payload)
        })
    }

    fn verify(
        &self,
        key_id: String,
        payload: Value,
        signature: String,
    ) -> BoxFuture<'static, Result<()>> {
        let pool = self.pool.clone();
        Box::pin(async move {
            let secret: Option<Vec<u8>> =
                sqlx::query_scalar("SELECT secret FROM write_plan_keys WHERE key_id = ?")
                    .bind(key_id)
                    .fetch_optional(&pool)
                    .await?;
            let secret =
                secret.ok_or_else(|| Error::engine("write plan signing key is unavailable"))?;
            verify_signature(&secret, &payload, &signature)
        })
    }
}

fn sidecar_path(database_path: &Path) -> Result<PathBuf> {
    let database_path = std::fs::canonicalize(database_path).map_err(|error| {
        Error::engine(format!(
            "database path cannot be canonicalized for durable write plans: {error}"
        ))
    })?;
    let file_name = database_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Error::engine("database path cannot identify a write plan store"))?;
    Ok(database_path.with_file_name(format!("{file_name}.write-plans.sqlite3")))
}

async fn rotate_local_key_if_older_than(
    pool: &SqlitePool,
    now_ms: i64,
    max_age_ms: i64,
) -> Result<String> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    let active =
        sqlx::query("SELECT key_id, created_at_ms FROM write_plan_keys WHERE status = 'active'")
            .fetch_one(&mut *tx)
            .await?;
    let active_key_id: String = active.try_get("key_id")?;
    let created_at_ms: i64 = active.try_get("created_at_ms")?;
    if now_ms.saturating_sub(created_at_ms) < max_age_ms {
        tx.commit().await?;
        return Ok(active_key_id);
    }
    let key_id = format!("wpk1:{}", Uuid::new_v4());
    let secret: [u8; 32] = rand::random();
    sqlx::query(
        "UPDATE write_plan_keys SET status = 'retired', retired_at_ms = ? WHERE status = 'active'",
    )
    .bind(now_ms)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO write_plan_keys (key_id, secret, status, created_at_ms)
         VALUES (?, ?, 'active', ?)",
    )
    .bind(&key_id)
    .bind(secret.as_slice())
    .bind(now_ms)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(key_id)
}

async fn initialize_schema(pool: &SqlitePool) -> Result<()> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    let version: i64 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(&mut *tx)
        .await?;
    match version {
        STORE_SCHEMA_VERSION => {
            tx.commit().await?;
            validate_schema(pool).await
        }
        0 => {
            let objects: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
            )
            .fetch_one(&mut *tx)
            .await?;
            if objects != 0 {
                tx.rollback().await?;
                return Err(Error::engine(
                    "refusing to initialize a non-empty unversioned write plan store",
                ));
            }
            for statement in STORE_SCHEMA {
                sqlx::query(statement).execute(&mut *tx).await?;
            }
            let key_id = format!("wpk1:{}", Uuid::new_v4());
            let secret: [u8; 32] = rand::random();
            sqlx::query(
                "INSERT INTO write_plan_keys (key_id, secret, status, created_at_ms)
                 VALUES (?, ?, 'active', ?)",
            )
            .bind(key_id)
            .bind(secret.as_slice())
            .bind(chrono::Utc::now().timestamp_millis())
            .execute(&mut *tx)
            .await?;
            sqlx::query(&format!("PRAGMA user_version = {STORE_SCHEMA_VERSION}"))
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            validate_schema(pool).await
        }
        other => {
            tx.rollback().await?;
            Err(Error::engine(format!(
                "unsupported write plan store schema {other}; expected {STORE_SCHEMA_VERSION}"
            )))
        }
    }
}

async fn validate_schema(pool: &SqlitePool) -> Result<()> {
    #[derive(Clone, Copy)]
    struct ExpectedColumn {
        name: &'static str,
        kind: &'static str,
        not_null: bool,
        default: Option<&'static str>,
        primary_key: i64,
    }
    struct ExpectedTable {
        name: &'static str,
        sql: &'static str,
        columns: &'static [ExpectedColumn],
    }
    const fn column(
        name: &'static str,
        kind: &'static str,
        not_null: bool,
        default: Option<&'static str>,
        primary_key: i64,
    ) -> ExpectedColumn {
        ExpectedColumn {
            name,
            kind,
            not_null,
            default,
            primary_key,
        }
    }
    const EXPECTED: &[ExpectedTable] = &[
        ExpectedTable {
            name: "write_plan_keys",
            sql: STORE_SCHEMA[0],
            columns: &[
                column("key_id", "TEXT", false, None, 1),
                column("secret", "BLOB", true, None, 0),
                column("status", "TEXT", true, None, 0),
                column("created_at_ms", "INTEGER", true, None, 0),
                column("retired_at_ms", "INTEGER", false, None, 0),
            ],
        },
        ExpectedTable {
            name: "write_plans",
            sql: STORE_SCHEMA[2],
            columns: &[
                column("plan_id", "TEXT", false, None, 1),
                column("payload", "TEXT", true, None, 0),
                column("key_id", "TEXT", true, None, 0),
                column("state", "TEXT", true, None, 0),
                column("expires_at_ms", "INTEGER", true, None, 0),
                column("attempt_id", "TEXT", false, None, 0),
                column("execution_owner", "TEXT", false, None, 0),
                column("started_at_ms", "INTEGER", false, None, 0),
                column("completed_at_ms", "INTEGER", false, None, 0),
                column("result", "TEXT", false, None, 0),
                column("source_dispatch_count", "INTEGER", true, Some("0"), 0),
                column("terminal_reason", "TEXT", false, None, 0),
                column("created_at_ms", "INTEGER", true, None, 0),
                column("updated_at_ms", "INTEGER", true, None, 0),
            ],
        },
    ];
    for table in EXPECTED {
        let found: Option<String> =
            sqlx::query_scalar("SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?")
                .bind(table.name)
                .fetch_optional(pool)
                .await?;
        let Some(found_sql) = found else {
            return Err(Error::engine(format!(
                "write plan store schema is incomplete: missing {}",
                table.name
            )));
        };
        if normalize_schema_sql(&found_sql) != normalize_schema_sql(table.sql) {
            return Err(Error::engine(format!(
                "write plan store schema is incompatible: unexpected {} definition",
                table.name
            )));
        }
        let columns = sqlx::query(
            "SELECT name, type, \"notnull\" AS not_null, dflt_value, pk
             FROM pragma_table_info(?) ORDER BY cid",
        )
        .bind(table.name)
        .fetch_all(pool)
        .await?;
        let column_shape = columns
            .iter()
            .map(|row| {
                Ok((
                    row.try_get::<String, _>("name")?,
                    row.try_get::<String, _>("type")?,
                    row.try_get::<i64, _>("not_null")? != 0,
                    row.try_get::<Option<String>, _>("dflt_value")?,
                    row.try_get::<i64, _>("pk")?,
                ))
            })
            .collect::<std::result::Result<Vec<_>, sqlx::Error>>()?;
        let expected_shape = table
            .columns
            .iter()
            .map(|column| {
                (
                    column.name.to_owned(),
                    column.kind.to_owned(),
                    column.not_null,
                    column.default.map(str::to_owned),
                    column.primary_key,
                )
            })
            .collect::<Vec<_>>();
        if column_shape != expected_shape {
            return Err(Error::engine(format!(
                "write plan store schema is incompatible: unexpected {} column shape",
                table.name
            )));
        }
    }
    for (index, expected_sql) in [
        ("write_plan_keys_one_active", STORE_SCHEMA[1]),
        ("write_plans_expiry", STORE_SCHEMA[3]),
    ] {
        let found: Option<String> =
            sqlx::query_scalar("SELECT sql FROM sqlite_schema WHERE type = 'index' AND name = ?")
                .bind(index)
                .fetch_optional(pool)
                .await?;
        let Some(found_sql) = found else {
            return Err(Error::engine(format!(
                "write plan store schema is incomplete: missing {index}"
            )));
        };
        if normalize_schema_sql(&found_sql) != normalize_schema_sql(expected_sql) {
            return Err(Error::engine(format!(
                "write plan store schema is incompatible: unexpected {index} definition"
            )));
        }
    }
    Ok(())
}

fn normalize_schema_sql(sql: &str) -> String {
    sql.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

async fn load_row(
    pool: &SqlitePool,
    table: &str,
    plan_id: &str,
    db_id: Option<&str>,
) -> Result<Option<StoredPlan>> {
    let query = format!(
        "SELECT payload, {}, key_id, state, expires_at_ms, attempt_id, started_at_ms, result,
                source_dispatch_count
         FROM {table} WHERE plan_id = ?{}",
        if db_id.is_some() {
            "payload_sha256"
        } else {
            "NULL AS payload_sha256"
        },
        if db_id.is_some() {
            " AND db_id = ?"
        } else {
            ""
        }
    );
    let query = sqlx::query(&query).bind(plan_id);
    let query = if let Some(db_id) = db_id {
        query.bind(db_id)
    } else {
        query
    };
    let Some(row) = query.fetch_optional(pool).await? else {
        return Ok(None);
    };
    let stored_payload: Value = serde_json::from_str(row.try_get::<&str, _>("payload")?)?;
    let catalogue_payload_sha256 = row.try_get::<Option<String>, _>("payload_sha256")?;
    if let Some(stored_digest) = &catalogue_payload_sha256 {
        let computed_digest = payload_sha256(&stored_payload)?;
        if stored_digest != &computed_digest {
            return Err(Error::engine(
                "hosted write plan payload digest does not match its catalogue fence",
            ));
        }
    }
    let key_id: String = row.try_get("key_id")?;
    let payload = if db_id.is_some() {
        hosted_plan_payload(&stored_payload, &key_id)?.clone()
    } else {
        stored_payload
    };
    let dispatch_count = u64::try_from(row.try_get::<i64, _>("source_dispatch_count")?)
        .map_err(|_| Error::engine("write plan source dispatch count is invalid"))?;
    let state = match row.try_get::<&str, _>("state")? {
        "prepared" => StoredState::Prepared,
        "executing" => StoredState::Executing {
            started_at_ms: required_i64(&row, "started_at_ms")?,
            attempt_id: required_text(&row, "attempt_id")?,
        },
        "completed" => StoredState::Completed {
            result: serde_json::from_str(required_text(&row, "result")?.as_str())?,
            source_dispatch_count: dispatch_count,
        },
        "expired" => StoredState::Expired,
        "indeterminate" => StoredState::Indeterminate {
            started_at_ms: required_i64(&row, "started_at_ms")?,
            attempt_id: required_text(&row, "attempt_id")?,
        },
        other => {
            return Err(Error::engine(format!(
                "write plan store contains unknown lifecycle state {other}"
            )))
        }
    };
    Ok(Some(StoredPlan {
        payload,
        key_id,
        catalogue_payload_sha256,
        state,
        expires_at_ms: row.try_get("expires_at_ms")?,
    }))
}

fn required_text(row: &sqlx::sqlite::SqliteRow, field: &str) -> Result<String> {
    row.try_get::<Option<String>, _>(field)?
        .ok_or_else(|| Error::engine(format!("write plan {field} is missing")))
}

fn required_i64(row: &sqlx::sqlite::SqliteRow, field: &str) -> Result<i64> {
    row.try_get::<Option<i64>, _>(field)?
        .ok_or_else(|| Error::engine(format!("write plan {field} is missing")))
}

fn sign(secret: &[u8], payload: &Value) -> Result<String> {
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|_| Error::engine("write plan signing key is malformed"))?;
    mac.update(&serde_jcs::to_vec(payload)?);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn verify_signature(secret: &[u8], payload: &Value, signature: &str) -> Result<()> {
    let expected =
        hex::decode(signature).map_err(|_| Error::engine("write plan integrity is malformed"))?;
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|_| Error::engine("write plan signing key is malformed"))?;
    mac.update(&serde_jcs::to_vec(payload)?);
    mac.verify_slice(&expected)
        .map_err(|_| Error::engine("write plan integrity check failed"))
}

fn payload_sha256(payload: &Value) -> Result<String> {
    use sha2::Digest as _;

    Ok(hex::encode(Sha256::digest(serde_jcs::to_vec(payload)?)))
}

fn hosted_retained_key_challenge(key_id: &str) -> Value {
    json!({
        "domain": HOSTED_RETAINED_KEY_DOMAIN,
        "format": HOSTED_STORED_PLAN_FORMAT,
        "key_id": key_id,
    })
}

async fn hosted_stored_plan_envelope(
    keys: &Arc<dyn HostedPlanKeyProvider>,
    key_id: &str,
    plan_payload: &Value,
) -> Result<Value> {
    let key_verifier = keys
        .seal(key_id.to_owned(), hosted_retained_key_challenge(key_id))
        .await?;
    Ok(json!({
        "format": HOSTED_STORED_PLAN_FORMAT,
        "key_id": key_id,
        "key_verifier": key_verifier,
        "plan_payload": plan_payload,
    }))
}

fn hosted_plan_payload<'a>(stored: &'a Value, expected_key_id: &str) -> Result<&'a Value> {
    if stored.get("format").and_then(Value::as_str) != Some(HOSTED_STORED_PLAN_FORMAT)
        || stored.get("key_id").and_then(Value::as_str) != Some(expected_key_id)
        || stored.get("key_verifier").and_then(Value::as_str).is_none()
    {
        return Err(Error::engine(
            "hosted write plan storage envelope is unsupported or invalid",
        ));
    }
    stored
        .get("plan_payload")
        .ok_or_else(|| Error::engine("hosted write plan storage envelope is incomplete"))
}

pub(super) async fn verify_hosted_retained_key(
    keys: &Arc<dyn HostedPlanKeyProvider>,
    expected_key_id: &str,
    stored_payload_json: &str,
    expected_payload_sha256: &str,
) -> Result<()> {
    let stored: Value = serde_json::from_str(stored_payload_json)
        .map_err(|_| Error::engine("hosted write plan storage envelope is invalid"))?;
    if payload_sha256(&stored)? != expected_payload_sha256 {
        return Err(Error::engine(
            "hosted write plan payload digest does not match its catalogue fence",
        ));
    }
    hosted_plan_payload(&stored, expected_key_id)?;
    let key_verifier = stored
        .get("key_verifier")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::engine("hosted write plan storage envelope is incomplete"))?;
    keys.verify(
        expected_key_id.to_owned(),
        hosted_retained_key_challenge(expected_key_id),
        key_verifier.to_owned(),
    )
    .await
}

#[cfg(unix)]
fn prepare_sidecar_file(path: &Path) -> Result<()> {
    use std::fs::OpenOptions;
    use std::io::ErrorKind;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
                return Err(Error::engine("refusing a symbolic-link write plan sidecar"));
            }
        }
        Err(error) => return Err(error.into()),
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn prepare_sidecar_file(path: &Path) -> Result<()> {
    use std::fs::OpenOptions;
    use std::io::ErrorKind;

    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::sync::RwLock;

    const TEST_HOSTED_DB_ID: &str = "executor-plan-test-db";
    const TEST_CATALOGUE_DDL: &[&str] = &[
        r#"CREATE TABLE databases (
          id             TEXT PRIMARY KEY,
          status         TEXT NOT NULL
                         CHECK (status IN ('ready','retiring')),
          activity_epoch INTEGER NOT NULL DEFAULT 0 CHECK (activity_epoch >= 0)
       )"#,
        r#"CREATE TABLE executor_write_plans (
          plan_id                TEXT PRIMARY KEY,
          db_id                  TEXT NOT NULL REFERENCES databases(id),
          payload                TEXT NOT NULL CHECK (json_valid(payload)),
          payload_sha256         TEXT NOT NULL CHECK (length(payload_sha256) = 64),
          key_id                 TEXT NOT NULL,
          state                  TEXT NOT NULL
                                 CHECK (state IN ('prepared','executing','completed','expired','indeterminate')),
          expires_at_ms          INTEGER NOT NULL,
          attempt_id             TEXT,
          execution_owner        TEXT,
          started_at_ms          INTEGER,
          completed_at_ms        INTEGER,
          result                 TEXT CHECK (result IS NULL OR json_valid(result)),
          source_dispatch_count  INTEGER NOT NULL DEFAULT 0 CHECK (source_dispatch_count >= 0),
          terminal_reason        TEXT,
          created_at_ms          INTEGER NOT NULL,
          updated_at_ms          INTEGER NOT NULL,
          activity_epoch         INTEGER NOT NULL DEFAULT 0 CHECK (activity_epoch >= 0),
          CHECK ((state = 'prepared' AND attempt_id IS NULL AND execution_owner IS NULL AND started_at_ms IS NULL)
              OR (state IN ('executing','indeterminate') AND attempt_id IS NOT NULL AND execution_owner IS NOT NULL AND started_at_ms IS NOT NULL)
              OR (state = 'completed' AND attempt_id IS NOT NULL AND execution_owner IS NOT NULL AND started_at_ms IS NOT NULL AND completed_at_ms IS NOT NULL AND result IS NOT NULL)
              OR state = 'expired')
       )"#,
        r#"CREATE INDEX idx_executor_write_plans_expiry
           ON executor_write_plans(db_id, state, expires_at_ms)"#,
    ];

    #[derive(Clone)]
    struct SharedTestKeys {
        active: Arc<RwLock<String>>,
        secrets: Arc<RwLock<BTreeMap<String, Vec<u8>>>>,
    }

    impl SharedTestKeys {
        fn new() -> Self {
            Self {
                active: Arc::new(RwLock::new("hosted-key-1".into())),
                secrets: Arc::new(RwLock::new(BTreeMap::from([(
                    "hosted-key-1".into(),
                    vec![7; 32],
                )]))),
            }
        }

        fn rotate(&self, key_id: &str, secret: Vec<u8>) {
            self.secrets
                .write()
                .unwrap()
                .insert(key_id.to_owned(), secret);
            *self.active.write().unwrap() = key_id.to_owned();
        }
    }

    impl HostedPlanKeyProvider for SharedTestKeys {
        fn active_key_id(&self) -> BoxFuture<'static, Result<String>> {
            let active = self.active.clone();
            Box::pin(async move {
                Ok(active
                    .read()
                    .map_err(|_| Error::engine("test key lock poisoned"))?
                    .clone())
            })
        }

        fn seal(&self, key_id: String, payload: Value) -> BoxFuture<'static, Result<String>> {
            let secrets = self.secrets.clone();
            Box::pin(async move {
                let secret = secrets
                    .read()
                    .map_err(|_| Error::engine("test key lock poisoned"))?
                    .get(&key_id)
                    .cloned()
                    .ok_or_else(|| Error::engine("test hosted key unavailable"))?;
                sign(&secret, &payload)
            })
        }

        fn verify(
            &self,
            key_id: String,
            payload: Value,
            signature: String,
        ) -> BoxFuture<'static, Result<()>> {
            let secrets = self.secrets.clone();
            Box::pin(async move {
                let secret = secrets
                    .read()
                    .map_err(|_| Error::engine("test key lock poisoned"))?
                    .get(&key_id)
                    .cloned()
                    .ok_or_else(|| Error::engine("test hosted key unavailable"))?;
                verify_signature(&secret, &payload, &signature)
            })
        }
    }

    #[derive(Clone)]
    struct TestHostedPlanCatalogue {
        pool: SqlitePool,
        path: PathBuf,
    }

    impl TestHostedPlanCatalogue {
        async fn create(directory: &tempfile::TempDir, db_id: &str) -> Self {
            let path = directory.path().join("catalog.sqlite3");
            let catalogue = Self::open(path, true).await;
            for statement in TEST_CATALOGUE_DDL {
                sqlx::query(statement)
                    .execute(&catalogue.pool)
                    .await
                    .unwrap();
            }
            sqlx::query(
                "INSERT INTO databases (id, status, activity_epoch) VALUES (?, 'ready', 0)",
            )
            .bind(db_id)
            .execute(&catalogue.pool)
            .await
            .unwrap();
            catalogue
        }

        async fn reopen(path: PathBuf) -> Self {
            Self::open(path, false).await
        }

        async fn open(path: PathBuf, create_if_missing: bool) -> Self {
            let options = SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(create_if_missing)
                .foreign_keys(true)
                .busy_timeout(Duration::from_secs(5))
                .journal_mode(SqliteJournalMode::Wal)
                .synchronous(SqliteSynchronous::Full);
            let pool = SqlitePoolOptions::new()
                .max_connections(4)
                .connect_with(options)
                .await
                .unwrap();
            Self { pool, path }
        }

        fn pool(&self) -> &SqlitePool {
            &self.pool
        }

        fn path(&self) -> PathBuf {
            self.path.clone()
        }

        async fn close(self) {
            self.pool.close().await;
        }
    }

    impl HostedPlanCatalogue for TestHostedPlanCatalogue {
        fn executor_plan_pool(&self) -> &SqlitePool {
            &self.pool
        }
    }

    fn engine_path(directory: &tempfile::TempDir) -> PathBuf {
        let path = directory.path().join("native.sqlite3");
        std::fs::File::create(&path).unwrap();
        path
    }

    fn deployment_keyring(active: &str, entries: &[(&str, u8)]) -> String {
        serde_json::to_string(&json!({
            "active_key_id": active,
            "keys": entries.iter().map(|(id, byte)| json!({
                "id": id,
                "key": STANDARD.encode([*byte; DEPLOYMENT_KEY_BYTES]),
            })).collect::<Vec<_>>()
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn deployment_keyring_seals_with_active_and_verifies_retained_keys() {
        let first = DeploymentPlanKeyring::from_json(&deployment_keyring(
            "key-2",
            &[("key-1", 1), ("key-2", 2)],
        ))
        .unwrap();
        assert_eq!(format!("{first:?}"), "DeploymentPlanKeyring([redacted])");
        assert_eq!(first.active_key_id().await.unwrap(), "key-2");
        let payload = json!({"plan":"prepared"});
        let signature = first.seal("key-2".into(), payload.clone()).await.unwrap();
        first
            .verify("key-2".into(), payload.clone(), signature)
            .await
            .unwrap();

        let previous =
            DeploymentPlanKeyring::from_json(&deployment_keyring("key-1", &[("key-1", 1)]))
                .unwrap();
        let old_signature = previous
            .seal("key-1".into(), payload.clone())
            .await
            .unwrap();
        first
            .verify("key-1".into(), payload.clone(), old_signature)
            .await
            .unwrap();
        assert!(first
            .seal("key-1".into(), payload)
            .await
            .unwrap_err()
            .to_string()
            .contains("active signing key"));
    }

    #[test]
    fn deployment_keyring_rejects_unsafe_or_ambiguous_configuration() {
        let invalid = [
            "{}".to_owned(),
            deployment_keyring("missing", &[("retained", 1)]),
            deployment_keyring("unsafe/id", &[("unsafe/id", 1)]),
            serde_json::to_string(&json!({
                "active_key_id":"key-1",
                "keys":[
                    {"id":"key-1","key":STANDARD.encode([1; DEPLOYMENT_KEY_BYTES])},
                    {"id":"key-1","key":STANDARD.encode([2; DEPLOYMENT_KEY_BYTES])}
                ]
            }))
            .unwrap(),
            serde_json::to_string(&json!({
                "active_key_id":"key-1",
                "keys":[{"id":"key-1","key":STANDARD.encode([1; DEPLOYMENT_KEY_BYTES - 1])}]
            }))
            .unwrap(),
        ];
        for raw in invalid {
            let error = DeploymentPlanKeyring::from_json(&raw).unwrap_err();
            assert!(!error.to_string().contains(&raw), "{error}");
        }

        let too_many = (0..=HOSTED_MAX_RETAINED_KEYS)
            .map(|index| (format!("key-{index}"), index as u8))
            .collect::<Vec<_>>();
        let raw = serde_json::to_string(&json!({
            "active_key_id":"key-0",
            "keys":too_many.iter().map(|(id, byte)| json!({
                "id":id,
                "key":STANDARD.encode([*byte; DEPLOYMENT_KEY_BYTES])
            })).collect::<Vec<_>>()
        }))
        .unwrap();
        assert!(DeploymentPlanKeyring::from_json(&raw).is_err());
        assert!(
            DeploymentPlanKeyring::from_json(&" ".repeat(DEPLOYMENT_KEYRING_MAX_BYTES + 1))
                .is_err()
        );
    }

    async fn insert(store: &PlanStore, plan_id: &str, expires_at_ms: i64) -> (String, Value) {
        let key_id = store.active_key_id().await.unwrap();
        let mut payload = json!({
            "id":plan_id,
            "signing_key_id":key_id,
            "integrity":""
        });
        let signature = store.seal(&key_id, &payload).await.unwrap();
        payload["integrity"] = json!(signature);
        store
            .insert_prepared(plan_id, &payload, &key_id, expires_at_ms, 10)
            .await
            .unwrap();
        (key_id, payload)
    }

    #[tokio::test]
    async fn hosted_catalogue_port_accepts_non_catalog_implementation() {
        let directory = tempfile::tempdir().unwrap();
        let catalogue = TestHostedPlanCatalogue::create(&directory, TEST_HOSTED_DB_ID).await;
        let keys: Arc<dyn HostedPlanKeyProvider> = Arc::new(SharedTestKeys::new());

        super::super::validate_hosted_plan_keys_for_catalogue(&keys, &catalogue)
            .await
            .unwrap();
        let store = PlanStore::open_for_catalogue(catalogue, TEST_HOSTED_DB_ID, keys)
            .await
            .unwrap();
        let (_, payload) = insert(&store, "catalogue-port-plan", 10_000).await;
        let stored = store
            .load("catalogue-port-plan", 20)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(stored.payload, payload);
        assert!(matches!(stored.state, StoredState::Prepared));
    }

    #[tokio::test]
    async fn hosted_startup_maintenance_expires_current_ready_plans() {
        let directory = tempfile::tempdir().unwrap();
        let catalogue = TestHostedPlanCatalogue::create(&directory, TEST_HOSTED_DB_ID).await;
        let keys: Arc<dyn HostedPlanKeyProvider> = Arc::new(SharedTestKeys::new());
        let store = PlanStore::open_for_catalogue(catalogue.clone(), TEST_HOSTED_DB_ID, keys)
            .await
            .unwrap();
        insert(&store, "startup-expiry", 10).await;

        assert_eq!(
            maintain_hosted_catalogue(&catalogue, 20, 100)
                .await
                .unwrap(),
            (1, 0)
        );
        assert!(matches!(
            store
                .load("startup-expiry", 20)
                .await
                .unwrap()
                .unwrap()
                .state,
            StoredState::Expired
        ));
    }

    #[tokio::test]
    async fn hosted_stale_store_cannot_prepare_or_claim_across_retire_and_cancel() {
        let directory = tempfile::tempdir().unwrap();
        let catalogue = TestHostedPlanCatalogue::create(&directory, TEST_HOSTED_DB_ID).await;
        let keys = Arc::new(SharedTestKeys::new());
        let stale =
            PlanStore::open_for_catalogue(catalogue.clone(), TEST_HOSTED_DB_ID, keys.clone())
                .await
                .unwrap();
        let (key_id, payload) = insert(&stale, "before-retirement", 10_000).await;
        insert(&stale, "expired-evidence", 15).await;
        insert(&stale, "due-after-retirement", 15).await;
        assert!(matches!(
            stale
                .load("expired-evidence", 20)
                .await
                .unwrap()
                .unwrap()
                .state,
            StoredState::Expired
        ));

        sqlx::query(
            "UPDATE databases
             SET status = 'retiring', activity_epoch = activity_epoch + 1
             WHERE id = ?",
        )
        .bind(TEST_HOSTED_DB_ID)
        .execute(catalogue.pool())
        .await
        .unwrap();
        let error = stale
            .insert_prepared("during-retirement", &payload, &key_id, 10_000, 20)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("lifecycle changed"), "{error}");
        assert!(matches!(
            stale.claim("before-retirement", 20).await.unwrap(),
            ClaimOutcome::Existing(StoredPlan {
                state: StoredState::Prepared,
                ..
            })
        ));
        assert!(matches!(
            stale
                .load("due-after-retirement", 20)
                .await
                .unwrap()
                .unwrap()
                .state,
            StoredState::Prepared
        ));
        assert_eq!(stale.expire_all(20).await.unwrap(), 0);
        assert_eq!(stale.cleanup_expired(30, 0).await.unwrap(), 0);
        assert!(matches!(
            stale
                .load("expired-evidence", 30)
                .await
                .unwrap()
                .unwrap()
                .state,
            StoredState::Expired
        ));

        sqlx::query(
            "UPDATE databases
             SET status = 'ready', activity_epoch = activity_epoch + 1
             WHERE id = ?",
        )
        .bind(TEST_HOSTED_DB_ID)
        .execute(catalogue.pool())
        .await
        .unwrap();
        assert!(stale
            .insert_prepared("after-cancel-stale", &payload, &key_id, 10_000, 30)
            .await
            .unwrap_err()
            .to_string()
            .contains("lifecycle changed"));
        assert!(matches!(
            stale.claim("before-retirement", 30).await.unwrap(),
            ClaimOutcome::Existing(StoredPlan {
                state: StoredState::Prepared,
                ..
            })
        ));
        assert_eq!(stale.expire_all(30).await.unwrap(), 0);
        assert_eq!(stale.cleanup_expired(30, 0).await.unwrap(), 0);

        let fresh = PlanStore::open_for_catalogue(catalogue.clone(), TEST_HOSTED_DB_ID, keys)
            .await
            .unwrap();
        insert(&fresh, "after-cancel-fresh", 10_000).await;
        assert!(matches!(
            fresh.claim("after-cancel-fresh", 40).await.unwrap(),
            ClaimOutcome::Claimed { .. }
        ));
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM executor_write_plans
                 WHERE plan_id IN ('during-retirement','after-cancel-stale')",
            )
            .fetch_one(catalogue.pool())
            .await
            .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn hosted_retained_key_probe_is_inner_format_independent_and_skips_corrupt_samples() {
        let directory = tempfile::tempdir().unwrap();
        let catalogue = TestHostedPlanCatalogue::create(&directory, TEST_HOSTED_DB_ID).await;
        let keys = Arc::new(SharedTestKeys::new());
        let store =
            PlanStore::open_for_catalogue(catalogue.clone(), TEST_HOSTED_DB_ID, keys.clone())
                .await
                .unwrap();
        insert(&store, "a-corrupt", 10_000).await;
        insert(&store, "b-future", 10_000).await;

        let corrupt_json: String = sqlx::query_scalar(
            "SELECT payload FROM executor_write_plans WHERE plan_id = 'a-corrupt'",
        )
        .fetch_one(catalogue.pool())
        .await
        .unwrap();
        let stored: Value = serde_json::from_str(&corrupt_json).unwrap();
        let corrupt = stored["plan_payload"].clone();
        sqlx::query(
            "UPDATE executor_write_plans SET payload = ?, payload_sha256 = ?
             WHERE plan_id = 'a-corrupt'",
        )
        .bind(serde_json::to_string(&corrupt).unwrap())
        .bind(payload_sha256(&corrupt).unwrap())
        .execute(catalogue.pool())
        .await
        .unwrap();
        assert!(store
            .load("a-corrupt", 20)
            .await
            .unwrap_err()
            .to_string()
            .contains("storage envelope is unsupported"));

        let future_json: String = sqlx::query_scalar(
            "SELECT payload FROM executor_write_plans WHERE plan_id = 'b-future'",
        )
        .fetch_one(catalogue.pool())
        .await
        .unwrap();
        let mut future: Value = serde_json::from_str(&future_json).unwrap();
        future["plan_payload"] = json!({
            "format":"native.write-plan.v99",
            "opaque_future_shape":[1, 2, 3]
        });
        sqlx::query(
            "UPDATE executor_write_plans SET payload = ?, payload_sha256 = ?
             WHERE plan_id = 'b-future'",
        )
        .bind(serde_json::to_string(&future).unwrap())
        .bind(payload_sha256(&future).unwrap())
        .execute(catalogue.pool())
        .await
        .unwrap();

        let provider: Arc<dyn HostedPlanKeyProvider> = keys;
        super::super::validate_hosted_plan_keys_for_catalogue(&provider, &catalogue)
            .await
            .unwrap();
        catalogue.close().await;
    }

    #[tokio::test]
    async fn hosted_retained_key_probe_rejects_missing_and_wrong_material() {
        let directory = tempfile::tempdir().unwrap();
        let catalogue = TestHostedPlanCatalogue::create(&directory, TEST_HOSTED_DB_ID).await;
        let original = Arc::new(SharedTestKeys::new());
        let store = PlanStore::open_for_catalogue(catalogue.clone(), TEST_HOSTED_DB_ID, original)
            .await
            .unwrap();
        insert(&store, "retained", 10_000).await;

        let wrong: Arc<dyn HostedPlanKeyProvider> = Arc::new(SharedTestKeys {
            active: Arc::new(RwLock::new("hosted-key-1".into())),
            secrets: Arc::new(RwLock::new(BTreeMap::from([(
                "hosted-key-1".into(),
                vec![9; 32],
            )]))),
        });
        assert!(
            super::super::validate_hosted_plan_keys_for_catalogue(&wrong, &catalogue)
                .await
                .unwrap_err()
                .to_string()
                .contains("unavailable or incorrect")
        );

        let missing: Arc<dyn HostedPlanKeyProvider> = Arc::new(SharedTestKeys {
            active: Arc::new(RwLock::new("hosted-key-2".into())),
            secrets: Arc::new(RwLock::new(BTreeMap::from([(
                "hosted-key-2".into(),
                vec![2; 32],
            )]))),
        });
        assert!(
            super::super::validate_hosted_plan_keys_for_catalogue(&missing, &catalogue)
                .await
                .unwrap_err()
                .to_string()
                .contains("unavailable or incorrect")
        );
        catalogue.close().await;
    }

    #[tokio::test]
    async fn hosted_retained_key_probe_rejects_unbounded_catalogue_key_sets() {
        let directory = tempfile::tempdir().unwrap();
        let catalogue = TestHostedPlanCatalogue::create(&directory, TEST_HOSTED_DB_ID).await;
        let keys = Arc::new(SharedTestKeys::new());
        let store =
            PlanStore::open_for_catalogue(catalogue.clone(), TEST_HOSTED_DB_ID, keys.clone())
                .await
                .unwrap();
        for index in 0..=HOSTED_MAX_RETAINED_KEYS {
            if index > 0 {
                keys.rotate(&format!("hosted-key-{}", index + 1), vec![index as u8; 32]);
            }
            insert(&store, &format!("plan-{index:02}"), 10_000).await;
        }

        let provider: Arc<dyn HostedPlanKeyProvider> = keys;
        let error = super::super::validate_hosted_plan_keys_for_catalogue(&provider, &catalogue)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("more retained keys"), "{error}");
        catalogue.close().await;
    }

    #[tokio::test]
    async fn catalogue_store_is_shared_across_instances_and_restart() {
        let directory = tempfile::tempdir().unwrap();
        let catalogue = TestHostedPlanCatalogue::create(&directory, TEST_HOSTED_DB_ID).await;
        let catalogue_path = catalogue.path();
        let keys = Arc::new(SharedTestKeys::new());
        let first =
            PlanStore::open_for_catalogue(catalogue.clone(), TEST_HOSTED_DB_ID, keys.clone())
                .await
                .unwrap();
        let second =
            PlanStore::open_for_catalogue(catalogue.clone(), TEST_HOSTED_DB_ID, keys.clone())
                .await
                .unwrap();
        insert(&first, "wpl1:hosted", 1_000).await;

        let (left, right) = tokio::join!(
            first.claim("wpl1:hosted", 20),
            second.claim("wpl1:hosted", 20)
        );
        let attempts = [left.unwrap(), right.unwrap()];
        let attempt_id = attempts
            .iter()
            .find_map(|outcome| match outcome {
                ClaimOutcome::Claimed { attempt_id, .. } => Some(attempt_id.clone()),
                _ => None,
            })
            .unwrap();
        assert_eq!(
            attempts
                .iter()
                .filter(|outcome| matches!(outcome, ClaimOutcome::Claimed { .. }))
                .count(),
            1
        );
        first
            .complete("wpl1:hosted", &attempt_id, &json!({"shared":true}), 30)
            .await
            .unwrap();

        catalogue.close().await;
        let restarted = TestHostedPlanCatalogue::reopen(catalogue_path).await;
        let store = PlanStore::open_for_catalogue(restarted.clone(), TEST_HOSTED_DB_ID, keys)
            .await
            .unwrap();
        assert_eq!(
            store
                .load("wpl1:hosted", 2_000)
                .await
                .unwrap()
                .unwrap()
                .state,
            StoredState::Completed {
                result: json!({"shared":true}),
                source_dispatch_count: 1,
            }
        );
        restarted.close().await;
    }

    #[tokio::test]
    async fn catalogue_store_uses_shared_rotation_and_retained_keys() {
        let directory = tempfile::tempdir().unwrap();
        let catalogue = TestHostedPlanCatalogue::create(&directory, TEST_HOSTED_DB_ID).await;
        let keys = Arc::new(SharedTestKeys::new());
        let first =
            PlanStore::open_for_catalogue(catalogue.clone(), TEST_HOSTED_DB_ID, keys.clone())
                .await
                .unwrap();
        let old_id = first.active_key_id().await.unwrap();
        let payload = json!({"plan":"old"});
        let signature = first.seal(&old_id, &payload).await.unwrap();
        insert(&first, "retained-across-rotation", 10_000).await;

        keys.rotate("hosted-key-2", vec![9; 32]);
        let second =
            PlanStore::open_for_catalogue(catalogue.clone(), TEST_HOSTED_DB_ID, keys.clone())
                .await
                .unwrap();
        assert_eq!(second.active_key_id().await.unwrap(), "hosted-key-2");
        second.verify(&old_id, &payload, &signature).await.unwrap();
        let provider: Arc<dyn HostedPlanKeyProvider> = keys;
        super::super::validate_hosted_plan_keys_for_catalogue(&provider, &catalogue)
            .await
            .unwrap();
        catalogue.close().await;
    }

    #[tokio::test]
    async fn two_instances_claim_once_and_replay_terminal_result_after_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = engine_path(&directory);
        let first = PlanStore::open_for_database(&path).await.unwrap();
        let second = PlanStore::open_for_database(&path).await.unwrap();
        insert(&first, "wpl1:shared", 1_000).await;

        let (left, right) = tokio::join!(
            first.claim("wpl1:shared", 20),
            second.claim("wpl1:shared", 20)
        );
        let outcomes = [left.unwrap(), right.unwrap()];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, ClaimOutcome::Claimed { .. }))
                .count(),
            1
        );
        let attempt_id = outcomes
            .iter()
            .find_map(|outcome| match outcome {
                ClaimOutcome::Claimed { attempt_id, .. } => Some(attempt_id.clone()),
                _ => None,
            })
            .unwrap();
        second
            .complete("wpl1:shared", &attempt_id, &json!({"ok":true}), 30)
            .await
            .unwrap();

        drop(first);
        drop(second);
        let restarted = PlanStore::open_for_database(&path).await.unwrap();
        let stored = restarted.load("wpl1:shared", 2_000).await.unwrap().unwrap();
        assert_eq!(
            stored.state,
            StoredState::Completed {
                result: json!({"ok":true}),
                source_dispatch_count: 1,
            }
        );
    }

    #[tokio::test]
    async fn executing_and_indeterminate_fences_survive_expiry() {
        let directory = tempfile::tempdir().unwrap();
        let store = PlanStore::open_for_database(&engine_path(&directory))
            .await
            .unwrap();
        insert(&store, "wpl1:uncertain", 100).await;
        let attempt_id = match store.claim("wpl1:uncertain", 20).await.unwrap() {
            ClaimOutcome::Claimed { attempt_id, plan } => {
                assert!(matches!(plan.state, StoredState::Executing { .. }));
                attempt_id
            }
            other => panic!("unexpected claim outcome: {other:?}"),
        };
        assert!(store
            .mark_indeterminate("wpl1:uncertain", &attempt_id, "cancelled", 30)
            .await
            .unwrap());
        assert_eq!(store.expire_all(1_000).await.unwrap(), 0);
        let stored = store.load("wpl1:uncertain", 1_000).await.unwrap().unwrap();
        match stored.state {
            StoredState::Indeterminate { started_at_ms, .. } => {
                assert_eq!(started_at_ms, 20);
            }
            other => panic!("unexpected state: {other:?}"),
        }
        let row = sqlx::query(
            "SELECT attempt_id, execution_owner, terminal_reason FROM write_plans WHERE plan_id = ?",
        )
        .bind("wpl1:uncertain")
        .fetch_one(store.local_pool())
        .await
        .unwrap();
        assert_eq!(row.get::<String, _>("attempt_id"), attempt_id);
        assert!(!row.get::<String, _>("execution_owner").is_empty());
        assert_eq!(row.get::<String, _>("terminal_reason"), "cancelled");

        insert(&store, "wpl1:unused", 40).await;
        assert_eq!(store.expire_all(50).await.unwrap(), 1);
        assert_eq!(store.cleanup_expired(60, 0).await.unwrap(), 1);
        assert!(store.load("wpl1:unused", 60).await.unwrap().is_none());
        assert!(store.load("wpl1:uncertain", 60).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn key_rotation_keeps_existing_plans_verifiable() {
        let directory = tempfile::tempdir().unwrap();
        let store = PlanStore::open_for_database(&engine_path(&directory))
            .await
            .unwrap();
        let (old_key, payload) = insert(&store, "wpl1:rotation", 1_000).await;
        let signature = payload["integrity"].as_str().unwrap();
        let unsigned = json!({
            "id":"wpl1:rotation",
            "signing_key_id":old_key,
            "integrity":""
        });
        store.verify(&old_key, &unsigned, signature).await.unwrap();
        let new_key = store
            .rotate_local_key_if_older_than(i64::MAX, 0)
            .await
            .unwrap();
        assert_ne!(old_key, new_key);
        store.verify(&old_key, &unsigned, signature).await.unwrap();
        assert_eq!(store.active_key_id().await.unwrap(), new_key);
    }

    #[tokio::test]
    async fn unknown_schema_version_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let path = engine_path(&directory);
        let store = PlanStore::open_for_database(&path).await.unwrap();
        sqlx::query("PRAGMA user_version = 99")
            .execute(store.local_pool())
            .await
            .unwrap();
        drop(store);
        let error = PlanStore::open_for_database(&path).await.unwrap_err();
        assert!(error
            .to_string()
            .contains("unsupported write plan store schema 99"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sidecar_is_restricted_to_the_service_account() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let engine = engine_path(&directory);
        let sidecar = sidecar_path(&engine).unwrap();
        prepare_sidecar_file(&sidecar).unwrap();
        let creation_mode = std::fs::metadata(&sidecar).unwrap().permissions().mode() & 0o777;
        assert_eq!(creation_mode, 0o600);
        let store = PlanStore::open_for_database(&engine).await.unwrap();
        drop(store);
        let mode = std::fs::metadata(sidecar).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symbolic_link_sidecar_is_rejected_without_touching_its_target() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let engine = engine_path(&directory);
        let target = directory.path().join("redirected");
        std::fs::write(&target, b"do not open").unwrap();
        symlink(&target, sidecar_path(&engine).unwrap()).unwrap();

        let error = PlanStore::open_for_database(&engine).await.unwrap_err();
        assert!(error.to_string().contains("symbolic-link"));
        assert_eq!(std::fs::read(target).unwrap(), b"do not open");
    }

    #[tokio::test]
    async fn versioned_store_with_weakened_definition_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let engine = engine_path(&directory);
        let sidecar = sidecar_path(&engine).unwrap();
        let options = SqliteConnectOptions::new()
            .filename(&sidecar)
            .create_if_missing(true);
        let pool = SqlitePool::connect_with(options).await.unwrap();
        for statement in STORE_SCHEMA {
            let statement =
                statement.replace("source_dispatch_count >= 0", "source_dispatch_count >= -1");
            sqlx::query(&statement).execute(&pool).await.unwrap();
        }
        sqlx::query(
            "INSERT INTO write_plan_keys (key_id, secret, status, created_at_ms)
             VALUES ('wpk1:test', zeroblob(32), 'active', 0)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("PRAGMA user_version = 1")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;

        let error = PlanStore::open_for_database(&engine).await.unwrap_err();
        assert!(error
            .to_string()
            .contains("unexpected write_plans definition"));
    }

    #[tokio::test]
    async fn corrupt_negative_dispatch_count_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let store = PlanStore::open_for_database(&engine_path(&directory))
            .await
            .unwrap();
        insert(&store, "wpl1:corrupt-count", 1_000).await;
        let mut connection = store.local_pool().acquire().await.unwrap();
        sqlx::query("PRAGMA ignore_check_constraints = ON")
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE write_plans SET source_dispatch_count = -1 WHERE plan_id = 'wpl1:corrupt-count'",
        )
        .execute(&mut *connection)
        .await
        .unwrap();
        drop(connection);

        let error = store.load("wpl1:corrupt-count", 20).await.unwrap_err();
        assert!(error.to_string().contains("dispatch count is invalid"));
    }

    #[tokio::test]
    async fn unversioned_nonempty_store_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let engine = engine_path(&directory);
        let sidecar = sidecar_path(&engine).unwrap();
        let options = SqliteConnectOptions::new()
            .filename(&sidecar)
            .create_if_missing(true);
        let pool = SqlitePool::connect_with(options).await.unwrap();
        sqlx::query("CREATE TABLE unrelated (id TEXT PRIMARY KEY)")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;

        let error = PlanStore::open_for_database(&engine).await.unwrap_err();
        assert!(error
            .to_string()
            .contains("non-empty unversioned write plan store"));
    }
}
