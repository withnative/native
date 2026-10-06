//! Server-side member copy generation registry (contract c323277 rev 7,
//! slice P2a; engine crate only).
//!
//! Scope of this increment: **no hosted catalog, no transport, no MCP tool.**
//! It owns the server-side state behind §1.3 (generation identity, retention
//! current-only per `scope_ref`), §1.4 F4 (the lazy ordinal), §1.5
//! (`scope_ref`), the workspace part of the §4.2 fence tuple (both
//! authorization counters plus the units-state digest), and §4.3 steps 3/5/6/7
//! for the reconnect answers `current`/`replace{…, scope_changed}`. `revoked`
//! and `locked` are the catalog's answers (§4.3 step 7) and are modelled as an
//! input here; the catalog's `activity_epoch` and credential footing are P2b.
//!
//! ## Where the registry state lives
//!
//! The registry keeps its rows in a **separate server-only SQLite store**
//! (`<store_dir>/registry.db`), not in the workspace database. Reasons:
//! - the workspace schema is frozen and exhaustively classified by
//!   [`crate::schema::member_classification`]; a new engine table would force
//!   a DDL/migration/conformance change, and any new table would need a
//!   member disposition. A separate store needs neither.
//! - the store is never read by [`crate::member_copy_producer`], so no
//!   registry row (counters, ordinal, generation identity) can ship in a
//!   member copy. The member file is built only from the workspace database.
//!
//! The workspace **fence part** is read from the workspace database in the
//! same read transaction as the slice (§4.3 step 3 "W"), via
//! [`crate::member_copy_producer::build_member_copy_in_tx`].
//!
//! **Single-writer assumption (R1).** `store_dir` must live on the volume
//! guarded by the hosting `HostingAuthorityLock` (the exclusive `flock` on
//! `<data_dir>/users`, `held/hosting/src/hosting/mod.rs`); P2b wires it. The
//! in-process [`tokio::sync::Mutex`] serialises publishes, and the store adds
//! `UNIQUE(scope_ref, ordinal)` plus a `BEGIN IMMEDIATE` read-decide-publish
//! with an in-transaction re-read, so a second writer fails loudly rather than
//! silently colliding.
//!
//! ## Inferences
//!
//! - `scope_ref` is `HMAC-SHA256(key, JCS([origin_database_id, user_id,
//!   account_token, membership_created_at, role, profile_major]))`. §1.5
//!   writes the inputs joined by `‖` without an encoding; a JCS array is the
//!   unambiguous canonicalisation, and the digest is lower-case hex.
//! - Retention is current-only per `scope_ref`: publishing a new generation
//!   supersedes the old one, whose row and file are removed only when no live
//!   lease pins them (and, for a rotated `scope_ref`, when its last lease
//!   ends). The durable, crash-resumable purge and cleanup barrier are the
//!   lifecycle workstream's (`src/member_copy_lifecycle.rs`); this increment
//!   does a best-effort removal only.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha256;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions, SqliteRow};
use sqlx::{Acquire, Connection, Row, Sqlite, SqlitePool, Transaction};

use crate::db::Db;
use crate::error::{Error, Result};
use crate::holding::HoldingDisclosureV2;
use crate::member_copy_producer::{build_member_copy_in_tx, MemberCopy, MemberCopyRequest};
use crate::query::sql::install_visible_records_in;
use crate::query::QueryPrincipal;
use crate::replica_generation::{ReplicaGenerationManifest, ReplicaOrdering};

type HmacSha256 = Hmac<Sha256>;

/// Catalog-supplied inputs to `scope_ref` (§1.5). All values arrive from the
/// catalog in P2b; here they are caller-supplied so the engine crate stays
/// catalog-free.
/// Not `Debug`: it carries `account_token` and must never be logged (R5).
#[derive(Clone, Eq, PartialEq)]
pub struct ScopeInputs {
    pub origin_database_id: String,
    pub user_id: String,
    pub account_token: String,
    pub membership_created_at: String,
    pub role: String,
    pub profile_major: u32,
    /// The portable account the catalog resolved for this request (the
    /// `query_sql` credential). Not an HMAC input: `account_token` is.
    pub member_account: String,
}

/// Injected HMAC key for `scope_ref` (§1.5). Constructed by the composition
/// root; never derived from caller input.
#[derive(Clone)]
pub struct ScopeRefKey([u8; 32]);

impl ScopeRefKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::engine("scope_ref key must be 32 bytes"))?;
        Ok(Self(key))
    }
}

impl ScopeInputs {
    /// §1.5: `scope_ref` rotates on re-add (`membership_created_at`), role
    /// change, identity re-binding (`account_token`) and a profile major
    /// bump.
    pub fn scope_ref(&self, key: &ScopeRefKey) -> String {
        let encoded = crate::canonical_json::canonical_json(&serde_json::json!([
            self.origin_database_id,
            self.user_id,
            self.account_token,
            self.membership_created_at,
            self.role,
            self.profile_major,
        ]));
        let mut mac = HmacSha256::new_from_slice(&key.0).expect("HMAC accepts any key length");
        mac.update(&encoded);
        hex::encode(mac.finalize().into_bytes())
    }
}

/// The catalog's verdict on the caller's credential (§4.3 step 7). P2b
/// computes it; P2a models it as an input so `request` can answer `revoked`
/// and `locked` without the catalog. Serialised only so the client-facing
/// `RequestAnswer` can echo it; it carries no counter-bearing field (R5).
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CredentialVerdict {
    Ready,
    /// §2.2/§4.3: `membership_ended | role_changed | session_revoked`. The
    /// device derives `account_changed` locally and never sends it.
    Revoked {
        cause: String,
    },
    /// §6.1: expired but not revoked. Only ever entered from the reconnect
    /// answer, never a local clock.
    Locked,
}

/// The reconnect answer (§4.3 step 7, workspace side). `Current` and
/// `Replace` are computed here; `Revoked`/`Locked` echo the catalog verdict.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RequestAnswer {
    Current {
        generation_id: String,
        scope_ref: String,
        ordinal: i64,
        content_digest: String,
        manifest: ReplicaGenerationManifest,
    },
    Replace {
        generation_id: String,
        scope_ref: String,
        scope_changed: bool,
        ordinal: i64,
        content_digest: String,
        manifest: ReplicaGenerationManifest,
    },
    Revoked {
        cause: String,
    },
    Locked,
}

/// The C1 person + account token the W transaction re-checks (§4.3 step 3:
/// "re-read the account binding for `account_token₁` in the same
/// transaction"). Server-internal; never serialised.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountBindingGuard {
    pub person_record_id: String,
    pub account_token: String,
}

/// The result of a tracked cut. `published` is true only when a **new**
/// generation row was created, so the caller can discard a C2-failed cut
/// without destroying a reused current generation other leases may pin.
#[derive(Clone, Debug)]
pub enum RequestCut {
    Produced {
        // Boxed: `RequestAnswer` is much larger than the `BindingChanged` arm.
        answer: Box<RequestAnswer>,
        published: bool,
    },
    /// The in-transaction binding guard found `account_token₁` no longer maps
    /// to the C1 person (a same-token person-swap). The cut is discarded.
    BindingChanged,
}

/// One published generation row. Route-free by design: the generation
/// identity excludes route, so aliases share the row and each mint binds
/// its own lease (see N1).
#[derive(Clone, Debug)]
struct PublishedGeneration {
    scope_ref: String,
    content_digest: String,
    ordinal: i64,
    generation_id: String,
    file_path: String,
    discarded: bool,
}

/// One download lease row (F3).
#[derive(Clone, Debug)]
struct LeaseRow {
    member_account: String,
    generation_id: String,
    authorization_revision: i64,
    authorization_grant_revision: i64,
    units_state_digest: String,
    eligibility_fingerprint: String,
    expires_at_ms: i64,
    revoked: bool,
}

/// The caller-binding of a download lease: the member account and the
/// `scope_ref` it was issued for, plus the trusted hosted route. `scope_ref`
/// is `HMAC(origin_database_id, user_id, account_token,
/// membership.created_at, role, profile_major)` — it binds origin + member
/// identity, **not** the hosted route (`§1.5`); the route-bound lease field
/// closes that gap (B3). Enforcement lives in
/// [`MemberCopyRegistry::lease_binding_for`]: only a full
/// account + scope + route match yields the binding, so a handle is opaque
/// AND unauthorized callers learn nothing from the lookup.
///
/// One bounded window of a pinned generation's file bytes (B3). The HTTP
/// transport reaches this only through the fence's exact-route + principal
/// gate; nothing here re-checks the caller.
#[derive(Clone, Debug)]
pub struct PinnedChunk {
    /// The requested `[start, start + bytes.len())` window (clamped to EOF).
    pub bytes: Vec<u8>,
    /// Total pinned file size, for `Content-Range` and 416 accounting.
    pub total_size: u64,
    /// SHA-256 of the whole pinned file (the manifest's pinned byte
    /// identity after the cached-byte fix), for `ETag`.
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseBinding {
    pub member_account: String,
    pub scope_ref: String,
    /// Trusted hosted route the handle was minted for. The transport must
    /// require it to equal the request route before lookup, check, revoke
    /// or byte serving (B3 exact-route binding).
    pub hosted_route_database_id: String,
}

/// A pinned download handle (F3). The caller streams `file_path`; the handle
/// keeps that exact generation alive until completion, TTL or restart.
#[derive(Clone, Debug)]
pub struct DownloadHandle {
    pub handle: String,
    pub generation_id: String,
    pub content_digest: String,
    pub expires_at_ms: i64,
    /// Server-internal only (F6): never serialised to a client. The transport
    /// increment (P2b) streams this path; tests read it via [`Self::file_path`].
    #[allow(dead_code)]
    file_path: String,
}

impl DownloadHandle {
    /// The server-side file to stream for this pinned generation. Not
    /// client-facing.
    #[allow(dead_code)] // Consumed by the P2b transport and the registry tests.
    pub(crate) fn file_path(&self) -> &str {
        &self.file_path
    }
}

/// The answer to `check_download` (F3/S2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DownloadDecision {
    /// Keep streaming the pinned generation.
    Continue,
    /// E(m) changed: the pinned generation is discarded and must not be
    /// served again; the client must request a fresh one.
    Restart,
    /// The lease ended (TTL or an explicit completion/revocation).
    Expired,
}

/// Registry construction inputs.
#[derive(Clone)]
pub struct RegistryConfig {
    pub store_dir: PathBuf,
    pub scope_ref_key: ScopeRefKey,
    pub lease_ttl: Duration,
    pub hosted_route_database_id: String,
    pub consumer: crate::standby_snapshot::StandbyConsumerIdentity,
}

/// Server-side generation registry. See the module docs for the store choice.
pub struct MemberCopyRegistry {
    pool: SqlitePool,
    key: ScopeRefKey,
    store_dir: PathBuf,
    lease_ttl: Duration,
    hosted_route_database_id: String,
    consumer: crate::standby_snapshot::StandbyConsumerIdentity,
    /// Serialises the read-decide-publish step so two concurrent requests for
    /// one scope cannot both allocate `ordinal + 1` (F3). Defense in depth:
    /// `decide_and_publish` also runs in one `BEGIN IMMEDIATE` transaction with
    /// a re-read, and the store carries `UNIQUE(scope_ref, ordinal)` (R1).
    publish_lock: tokio::sync::Mutex<()>,
    /// Test-only rendezvous before the publish lock, so a concurrency test can
    /// make both requests observe the same pre-change state (R2).
    #[cfg(test)]
    publish_barrier: Option<std::sync::Arc<tokio::sync::Barrier>>,
}

/// F1: the fence-side coverage for `(semantic_units, unit_id)`. Neither
/// authorization counter watches a `unit_id` update, but E(m) reads
/// `semantic_units.unit_id` (`_query_sql_visible_records`, `src/query/sql.rs`),
/// so [`MemberCopyRegistry`] folds every `semantic_units` row into the
/// workspace fence's `units_state_digest` and `check_download` re-evaluates
/// E(m) whenever it moves. `authorization_trigger_coverage` references this
/// constant so its safety net is not vacuous for that pair.
#[allow(dead_code)] // Referenced by `authorization_trigger_coverage`'s safety net.
pub(crate) const UNITS_STATE_FENCE_COVERS_UNIT_ID: bool = true;

/// N1: the registry store's on-disk schema version. Version 2 adds the B3
/// route-bound lease column (`hosted_route_database_id` on leases only).
/// Generation rows deliberately carry NO route: the generation identity
/// excludes route, so one cached generation is shared by every authorized
/// same-origin route/alias, and each mint binds its own lease to its own
/// request route. Binding the singleton generation row to the first route
/// would wrongly prevent minting a fresh handle on an authorized alias.
/// Compatibility policy (B3, fail-closed): a version-1 store is explicitly
/// refused at [`MemberCopyRegistry::open`] — its leases carry no trusted
/// route binding, and no honest backfill exists (the route is not
/// recoverable from v1 rows, and request-installed fields are untrusted),
/// so old rows must never serve the new HTTP transport. Removal + recreate
/// is the only path; this is safe because no production store exists
/// pre-release (the runtime only opens the registry when a scope-ref key
/// is configured, which is `None` in default deployments).
pub const MEMBER_COPY_REGISTRY_SCHEMA_VERSION: u32 = 2;

const REGISTRY_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS member_copy_registry_meta (
  singleton      INTEGER PRIMARY KEY CHECK (singleton = 1),
  schema_version INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS member_copy_generations (
  generation_id        TEXT PRIMARY KEY,
  scope_ref            TEXT NOT NULL,
  origin_database_id   TEXT NOT NULL,
  content_digest       TEXT NOT NULL,
  ordinal              INTEGER NOT NULL,
  file_path            TEXT NOT NULL,
  authorization_revision       INTEGER NOT NULL,
  authorization_grant_revision INTEGER NOT NULL,
  units_state_digest           TEXT NOT NULL,
  discarded            INTEGER NOT NULL DEFAULT 0,
  published_at         TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_member_copy_generations_scope_ordinal
  ON member_copy_generations(scope_ref, ordinal);
CREATE TABLE IF NOT EXISTS member_copy_current (
  scope_ref     TEXT PRIMARY KEY,
  generation_id TEXT NOT NULL,
  updated_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS member_copy_scopes (
  origin_database_id TEXT NOT NULL,
  user_id            TEXT NOT NULL,
  scope_ref          TEXT NOT NULL,
  updated_at         TEXT NOT NULL,
  PRIMARY KEY (origin_database_id, user_id)
);
CREATE TABLE IF NOT EXISTS member_copy_leases (
  handle                    TEXT PRIMARY KEY,
  member_account            TEXT NOT NULL,
  scope_ref                 TEXT NOT NULL,
  hosted_route_database_id  TEXT NOT NULL,
  generation_id             TEXT NOT NULL,
  content_digest            TEXT NOT NULL,
  authorization_revision    INTEGER NOT NULL,
  authorization_grant_revision INTEGER NOT NULL,
  units_state_digest        TEXT NOT NULL,
  eligibility_fingerprint   TEXT NOT NULL,
  expires_at_ms             INTEGER NOT NULL,
  revoked                   INTEGER NOT NULL DEFAULT 0
);
"#;

impl MemberCopyRegistry {
    pub async fn open(config: RegistryConfig) -> Result<Self> {
        std::fs::create_dir_all(&config.store_dir)?;
        let options = SqliteConnectOptions::new()
            .filename(config.store_dir.join("registry.db"))
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?;
        for statement in REGISTRY_DDL
            .split(';')
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            sqlx::query(statement).execute(&pool).await?;
        }
        // N1: version the store; refuse anything but the current version
        // rather than guessing at its shape. Version 1 is refused
        // explicitly (not migrated): its rows carry no trusted route
        // binding, so they must never serve the B3 HTTP transport.
        let existing: Option<i64> = sqlx::query_scalar(
            "SELECT schema_version FROM member_copy_registry_meta WHERE singleton = 1",
        )
        .fetch_optional(&pool)
        .await?;
        match existing {
            None => {
                sqlx::query(
                    "INSERT INTO member_copy_registry_meta (singleton, schema_version) VALUES (1, ?)",
                )
                .bind(MEMBER_COPY_REGISTRY_SCHEMA_VERSION as i64)
                .execute(&pool)
                .await?;
            }
            Some(version) if version == MEMBER_COPY_REGISTRY_SCHEMA_VERSION as i64 => {}
            Some(1) => {
                return Err(Error::engine(
                    "member copy registry store uses pre-B3 schema version 1 without \
                     route-bound leases; remove the store directory to recreate it",
                ));
            }
            Some(version) => {
                return Err(Error::engine(format!(
                    "member copy registry store has unsupported schema version {version} \
                     (expected {MEMBER_COPY_REGISTRY_SCHEMA_VERSION})"
                )));
            }
        }
        Ok(Self {
            pool,
            key: config.scope_ref_key,
            store_dir: config.store_dir,
            lease_ttl: config.lease_ttl,
            hosted_route_database_id: config.hosted_route_database_id,
            consumer: config.consumer,
            publish_lock: tokio::sync::Mutex::new(()),
            #[cfg(test)]
            publish_barrier: None,
        })
    }

    /// R2 test seam: rendezvous requests before the publish lock. Set it only
    /// around the concurrent requests under test.
    #[cfg(test)]
    pub(crate) fn set_publish_barrier(&mut self, barrier: std::sync::Arc<tokio::sync::Barrier>) {
        self.publish_barrier = Some(barrier);
    }

    /// The registry's own store path (tests and diagnostics).
    pub fn store_dir(&self) -> &Path {
        &self.store_dir
    }

    /// The `scope_ref` for a set of inputs under this registry's key (§1.5).
    pub fn scope_ref(&self, inputs: &ScopeInputs) -> String {
        inputs.scope_ref(&self.key)
    }
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Constant-time equality for `scope_ref`/`generation_id` comparisons (F7).
/// These are HMAC outputs or derived ids; the compared value is the caller's
/// own, but a constant-time compare costs nothing.
fn ct_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in a.bytes().zip(b.bytes()) {
        difference |= left ^ right;
    }
    difference == 0
}

/// Remove a file, tolerating absence. Any other error is surfaced (F5).
fn remove_file_if_present(path: &str) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn published_from_row(row: &SqliteRow) -> PublishedGeneration {
    PublishedGeneration {
        scope_ref: row.get("scope_ref"),
        content_digest: row.get("content_digest"),
        ordinal: row.get("ordinal"),
        generation_id: row.get("generation_id"),
        file_path: row.get("file_path"),
        discarded: row.get::<i64, _>("discarded") != 0,
    }
}

/// The current generation for `scope_ref`, read inside `tx` (R1 re-read).
async fn fetch_current_in(
    tx: &mut Transaction<'_, Sqlite>,
    scope_ref: &str,
) -> Result<Option<PublishedGeneration>> {
    let row = sqlx::query(
        "SELECT g.scope_ref, g.content_digest, g.ordinal, g.generation_id, \
                g.file_path, g.discarded \
         FROM member_copy_current AS c \
         JOIN member_copy_generations AS g ON g.generation_id = c.generation_id \
         WHERE c.scope_ref = ?",
    )
    .bind(scope_ref)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(row.as_ref().map(published_from_row))
}

async fn generation_by_id_in(
    tx: &mut Transaction<'_, Sqlite>,
    generation_id: &str,
) -> Result<Option<PublishedGeneration>> {
    let row = sqlx::query(
        "SELECT scope_ref, content_digest, ordinal, generation_id, file_path, \
                discarded \
         FROM member_copy_generations WHERE generation_id = ?",
    )
    .bind(generation_id)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(row.as_ref().map(published_from_row))
}

async fn is_current_in(tx: &mut Transaction<'_, Sqlite>, generation_id: &str) -> Result<bool> {
    let exists: i64 = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM member_copy_current WHERE generation_id = ?)",
    )
    .bind(generation_id)
    .fetch_one(&mut **tx)
    .await?;
    Ok(exists != 0)
}

async fn has_live_lease_in(tx: &mut Transaction<'_, Sqlite>, generation_id: &str) -> Result<bool> {
    let now = chrono::Utc::now().timestamp_millis();
    let exists: i64 = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM member_copy_leases \
         WHERE generation_id = ? AND revoked = 0 AND expires_at_ms >= ?)",
    )
    .bind(generation_id)
    .bind(now)
    .fetch_one(&mut **tx)
    .await?;
    Ok(exists != 0)
}

/// Remove a non-current, unleased generation's row and file (F2/R3).
async fn purge_generation_if_unleased_in(
    tx: &mut Transaction<'_, Sqlite>,
    generation_id: &str,
) -> Result<()> {
    if is_current_in(tx, generation_id).await? {
        return Ok(());
    }
    if has_live_lease_in(tx, generation_id).await? {
        return Ok(());
    }
    if let Some(row) = generation_by_id_in(tx, generation_id).await? {
        remove_file_if_present(&row.file_path)?;
    }
    sqlx::query("DELETE FROM member_copy_generations WHERE generation_id = ?")
        .bind(generation_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn purge_scope_generations_except_in(
    tx: &mut Transaction<'_, Sqlite>,
    scope_ref: &str,
    keep: &str,
) -> Result<()> {
    let generations: Vec<String> = sqlx::query_scalar(
        "SELECT generation_id FROM member_copy_generations \
         WHERE scope_ref = ? AND generation_id != ?",
    )
    .bind(scope_ref)
    .bind(keep)
    .fetch_all(&mut **tx)
    .await?;
    for generation_id in generations {
        purge_generation_if_unleased_in(tx, &generation_id).await?;
    }
    Ok(())
}

async fn purge_rotated_scope_in(
    tx: &mut Transaction<'_, Sqlite>,
    inputs: &ScopeInputs,
    new_scope: &str,
) -> Result<()> {
    let previous: Option<String> = sqlx::query_scalar(
        "SELECT scope_ref FROM member_copy_scopes \
         WHERE origin_database_id = ? AND user_id = ?",
    )
    .bind(&inputs.origin_database_id)
    .bind(&inputs.user_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(previous) = previous else {
        return Ok(());
    };
    if ct_eq(&previous, new_scope) {
        return Ok(());
    }
    let generations: Vec<String> =
        sqlx::query_scalar("SELECT generation_id FROM member_copy_generations WHERE scope_ref = ?")
            .bind(&previous)
            .fetch_all(&mut **tx)
            .await?;
    sqlx::query("UPDATE member_copy_generations SET discarded = 1 WHERE scope_ref = ?")
        .bind(&previous)
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM member_copy_current WHERE scope_ref = ?")
        .bind(&previous)
        .execute(&mut **tx)
        .await?;
    for generation_id in generations {
        purge_generation_if_unleased_in(tx, &generation_id).await?;
    }
    Ok(())
}

async fn insert_generation_in(
    tx: &mut Transaction<'_, Sqlite>,
    scope_ref: &str,
    manifest: &ReplicaGenerationManifest,
    ordinal: i64,
    generation_id: &str,
    file_path: &str,
    fence: &WorkspaceFence,
) -> Result<()> {
    // Plain INSERT: `UNIQUE(scope_ref, ordinal)` and the generation_id PK are
    // the cross-process backstop, so a collision fails loudly (R1).
    sqlx::query(
        "INSERT INTO member_copy_generations \
           (generation_id, scope_ref, origin_database_id, content_digest, ordinal, \
            file_path, authorization_revision, authorization_grant_revision, \
            units_state_digest, discarded, published_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)",
    )
    .bind(generation_id)
    .bind(scope_ref)
    .bind(&manifest.origin_database_id)
    .bind(&manifest.content_digest)
    .bind(ordinal)
    .bind(file_path)
    .bind(fence.authorization_revision)
    .bind(fence.authorization_grant_revision)
    .bind(&fence.units_state_digest)
    .bind(now_iso())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn set_current_in(
    tx: &mut Transaction<'_, Sqlite>,
    scope_ref: &str,
    generation_id: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO member_copy_current (scope_ref, generation_id, updated_at) \
         VALUES (?, ?, ?) \
         ON CONFLICT(scope_ref) DO UPDATE SET \
           generation_id=excluded.generation_id, updated_at=excluded.updated_at",
    )
    .bind(scope_ref)
    .bind(generation_id)
    .bind(now_iso())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn remember_scope_in(
    tx: &mut Transaction<'_, Sqlite>,
    inputs: &ScopeInputs,
    scope_ref: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO member_copy_scopes \
           (origin_database_id, user_id, scope_ref, updated_at) \
         VALUES (?, ?, ?, ?) \
         ON CONFLICT(origin_database_id, user_id) DO UPDATE SET \
           scope_ref=excluded.scope_ref, updated_at=excluded.updated_at",
    )
    .bind(&inputs.origin_database_id)
    .bind(&inputs.user_id)
    .bind(scope_ref)
    .bind(now_iso())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// The server-internal workspace fence part (§4.2): both authorization
/// counters plus the units-state digest that covers the `semantic_units`
/// `unit_id` gap (F1). Never serialised to a client.
#[derive(Clone, Debug)]
struct WorkspaceFence {
    authorization_revision: i64,
    authorization_grant_revision: i64,
    units_state_digest: String,
}

/// Read the workspace fence in the caller's transaction. The units digest
/// folds every `semantic_units` row, because E(m) reads `unit_id` and a
/// `unit_id` update moves neither counter (F1).
async fn workspace_fence(tx: &mut Transaction<'_, Sqlite>) -> Result<WorkspaceFence> {
    let broad: i64 =
        sqlx::query_scalar("SELECT epoch FROM main.authorization_revision WHERE id = 1")
            .fetch_one(&mut **tx)
            .await?;
    let grant: i64 =
        sqlx::query_scalar("SELECT epoch FROM main.authorization_grant_revision WHERE id = 1")
            .fetch_one(&mut **tx)
            .await?;
    let rows = sqlx::query(
        "SELECT unit_id, authority_bearer_record_id FROM main.semantic_units \
         ORDER BY unit_id, authority_bearer_record_id",
    )
    .fetch_all(&mut **tx)
    .await?;
    let mut units: Vec<[String; 2]> = Vec::with_capacity(rows.len());
    for row in rows {
        units.push([row.get("unit_id"), row.get("authority_bearer_record_id")]);
    }
    Ok(WorkspaceFence {
        authorization_revision: broad,
        authorization_grant_revision: grant,
        units_state_digest: crate::canonical_json::digest_json(&serde_json::json!([units])),
    })
}

/// §4.3 step 3: is the canonical account binding for `guard.account_token`
/// still the C1 person? Run inside the W transaction.
async fn account_binding_intact_in(
    tx: &mut Transaction<'_, Sqlite>,
    guard: &AccountBindingGuard,
) -> Result<bool> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT record_id FROM main.bindings \
         WHERE system = 'account' AND identifier = ? AND is_canonical = 1",
    )
    .bind(&guard.account_token)
    .fetch_all(&mut **tx)
    .await?;
    Ok(rows.len() == 1 && rows[0] == guard.person_record_id)
}

impl MemberCopyRegistry {
    /// §7.1 `member_copy.request` for the workspace side: build the slice in
    /// one read transaction with the fence, then answer `current` or
    /// `replace` with the lazily-assigned ordinal.
    pub async fn request(
        &self,
        db: &Db,
        inputs: &ScopeInputs,
        credential: CredentialVerdict,
        installed_generation_id: Option<&str>,
        installed_scope_ref: Option<&str>,
    ) -> Result<RequestAnswer> {
        let route = self.hosted_route_database_id.clone();
        self.request_for_route(
            db,
            inputs,
            credential,
            installed_generation_id,
            installed_scope_ref,
            &route,
        )
        .await
    }

    /// §7.1 with an explicit hosting route id. The hosted catalog uses the
    /// workspace's route `db_id` (the same value `standby_snapshot` binds), and
    /// one registry store serves every workspace.
    pub async fn request_for_route(
        &self,
        db: &Db,
        inputs: &ScopeInputs,
        credential: CredentialVerdict,
        installed_generation_id: Option<&str>,
        installed_scope_ref: Option<&str>,
        hosted_route_database_id: &str,
    ) -> Result<RequestAnswer> {
        let consumer = self.consumer.clone();
        match self
            .request_tracked(
                db,
                inputs,
                credential,
                installed_generation_id,
                installed_scope_ref,
                hosted_route_database_id,
                &consumer,
                None,
            )
            .await?
        {
            RequestCut::Produced { answer, .. } => Ok(*answer),
            RequestCut::BindingChanged => Err(Error::engine(
                "member copy: account binding changed during the cut",
            )),
        }
    }

    /// As [`Self::request_for_route`], but reports whether a **new**
    /// generation was published, honours an optional in-transaction binding
    /// guard (§4.3 step 3), and binds the caller's device consumer
    /// declaration into the manifest (fresh and reused answers alike). The
    /// hosted sandwich uses all three: it discards only a
    /// freshly-published cut on a C2 mismatch, it re-reads the C1 person's
    /// canonical account binding inside W, and B3 passes the device's
    /// declared consumer (never the registry's placeholder default).
    #[allow(clippy::too_many_arguments)]
    pub async fn request_tracked(
        &self,
        db: &Db,
        inputs: &ScopeInputs,
        credential: CredentialVerdict,
        installed_generation_id: Option<&str>,
        installed_scope_ref: Option<&str>,
        hosted_route_database_id: &str,
        consumer: &crate::standby_snapshot::StandbyConsumerIdentity,
        guard: Option<&AccountBindingGuard>,
    ) -> Result<RequestCut> {
        match credential {
            CredentialVerdict::Revoked { cause } => {
                return Ok(RequestCut::Produced {
                    answer: Box::new(RequestAnswer::Revoked { cause }),
                    published: false,
                });
            }
            CredentialVerdict::Locked => {
                return Ok(RequestCut::Produced {
                    answer: Box::new(RequestAnswer::Locked),
                    published: false,
                });
            }
            CredentialVerdict::Ready => {}
        }
        let scope_ref = inputs.scope_ref(&self.key);

        // §4.3 step 3 "W": one read transaction for the fence and the slice.
        let staging = self
            .store_dir
            .join(format!("staging-{}.db", uuid::Uuid::new_v4()));
        let mut connection = db.governed_pool().acquire().await?;
        let mut tx = connection.begin().await?;
        install_visible_records_in(
            &mut tx,
            QueryPrincipal::authenticated(inputs.member_account.clone(), true),
        )
        .await?;
        // §4.3 step 3: re-read the canonical account binding for
        // `account_token₁` in this same transaction, and require it still maps
        // to the C1 person (a same-token person-swap fails closed here).
        if let Some(guard) = guard {
            if !account_binding_intact_in(&mut tx, guard).await? {
                tx.rollback().await?;
                connection.close_on_drop();
                return Ok(RequestCut::BindingChanged);
            }
        }
        let built = async {
            let fence = workspace_fence(&mut tx).await?;
            let request = MemberCopyRequest {
                member_account: inputs.member_account.clone(),
                scope_ref: scope_ref.clone(),
                hosted_route_database_id: hosted_route_database_id.to_owned(),
                ordinal: 0,
                consumer: consumer.clone(),
                out_path: staging.clone(),
            };
            let copy = build_member_copy_in_tx(&mut tx, request).await?;
            Ok::<_, Error>((copy, fence))
        }
        .await;
        let rollback = tx.rollback().await;
        connection.close_on_drop();
        let (built, fence) = built?;
        rollback?;

        // R2 test seam: let both requests reach the publish step together.
        #[cfg(test)]
        if let Some(barrier) = &self.publish_barrier {
            barrier.wait().await;
        }

        // F3/R1: serialise decide-and-publish in-process (this mutex) and in
        // the store (`BEGIN IMMEDIATE` + `UNIQUE(scope_ref, ordinal)` + a
        // re-read inside the transaction).
        let _publish = self.publish_lock.lock().await;
        let (answer, published) = self
            .decide_and_publish(
                inputs,
                &scope_ref,
                built,
                installed_generation_id,
                installed_scope_ref,
                &staging,
                &fence,
            )
            .await?;
        Ok(RequestCut::Produced {
            answer: Box::new(answer),
            published,
        })
    }

    /// R1: the read-decide-publish step in one `BEGIN IMMEDIATE` transaction
    /// on the registry store, with the current row re-read inside it. The
    /// `UNIQUE(scope_ref, ordinal)` index is the cross-process backstop.
    #[allow(clippy::too_many_arguments)]
    async fn decide_and_publish(
        &self,
        inputs: &ScopeInputs,
        scope_ref: &str,
        built: MemberCopy,
        installed_generation_id: Option<&str>,
        installed_scope_ref: Option<&str>,
        staging: &Path,
        fence: &WorkspaceFence,
    ) -> Result<(RequestAnswer, bool)> {
        let scope_changed =
            installed_scope_ref.is_some_and(|installed| !ct_eq(installed, scope_ref));
        let mut connection = self.pool.acquire().await?;
        let mut tx = connection.begin_with("BEGIN IMMEDIATE").await?;

        // F4: a rotated scope_ref for the same (origin, user_id) purges the
        // superseded scope (subject to live leases) and is never resolved
        // again.
        purge_rotated_scope_in(&mut tx, inputs, scope_ref).await?;

        let latest = fetch_current_in(&mut tx, scope_ref).await?;
        let reuse = latest
            .as_ref()
            .filter(|row| !row.discarded && row.content_digest == built.content_digest);

        if let Some(row) = reuse {
            // Content unchanged: keep the published generation; the manifest
            // must describe the pinned file, not the freshly built staging
            // file (same content_digest can encode different physical bytes:
            // copy_table has no ORDER BY). Read the pinned bytes first so a
            // missing file fails closed before staging is discarded.
            let pinned_bytes = std::fs::read(&row.file_path).map_err(|error| {
                Error::engine(format!("member copy: pinned generation missing: {error}"))
            })?;
            let _ = std::fs::remove_file(staging);
            let mut manifest = built.manifest;
            manifest.bytes.size_bytes = pinned_bytes.len() as u64;
            manifest.bytes.sha256 = crate::standby_snapshot::sha256_bytes(&pinned_bytes);
            manifest.ordering = ReplicaOrdering::Scoped {
                ordinal: row.ordinal,
            };
            manifest.holding = HoldingDisclosureV2::member(scope_ref.to_owned(), row.ordinal);
            manifest.validate()?;
            let is_current = installed_generation_id
                .is_some_and(|generation| ct_eq(generation, &row.generation_id))
                && installed_scope_ref.is_some_and(|installed| ct_eq(installed, scope_ref));
            let generation_id = row.generation_id.clone();
            let ordinal = row.ordinal;
            let content_digest = row.content_digest.clone();
            let answer = if is_current {
                RequestAnswer::Current {
                    generation_id,
                    scope_ref: scope_ref.to_owned(),
                    ordinal,
                    content_digest,
                    manifest,
                }
            } else {
                RequestAnswer::Replace {
                    generation_id,
                    scope_ref: scope_ref.to_owned(),
                    scope_changed,
                    ordinal,
                    content_digest,
                    manifest,
                }
            };
            tx.commit().await?;
            return Ok((answer, false));
        }

        // §1.4 F4: a new ordinal exactly when the content digest changed.
        let ordinal = latest.as_ref().map(|row| row.ordinal + 1).unwrap_or(1);
        let mut manifest = built.manifest;
        manifest.ordering = ReplicaOrdering::Scoped { ordinal };
        manifest.holding = HoldingDisclosureV2::member(scope_ref.to_owned(), ordinal);
        manifest.validate()?;
        let generation_id = manifest.generation_id();
        let final_path = self.store_dir.join(format!("{generation_id}.db"));
        let final_path = final_path.to_string_lossy().into_owned();
        // N2: stage the row first, then rename. An INSERT failure (e.g. the
        // `UNIQUE(scope_ref, ordinal)` backstop) therefore leaves no final
        // generation file; a rename failure rolls the row back with the tx.
        insert_generation_in(
            &mut tx,
            scope_ref,
            &manifest,
            ordinal,
            &generation_id,
            &final_path,
            fence,
        )
        .await?;
        std::fs::rename(staging, &final_path)?;
        set_current_in(&mut tx, scope_ref, &generation_id).await?;
        remember_scope_in(&mut tx, inputs, scope_ref).await?;
        // F2: purge every superseded generation of this scope except the new
        // current one, keeping any still pinned by a live lease.
        purge_scope_generations_except_in(&mut tx, scope_ref, &generation_id).await?;
        tx.commit().await?;
        let content_digest = manifest.content_digest.clone();
        Ok((
            RequestAnswer::Replace {
                generation_id,
                scope_ref: scope_ref.to_owned(),
                scope_changed,
                ordinal,
                content_digest,
                manifest,
            },
            true,
        ))
    }

    /// Test-only read of the current generation for a scope.
    #[cfg(test)]
    async fn published_for(&self, scope_ref: &str) -> Result<Option<PublishedGeneration>> {
        let row = sqlx::query(
            "SELECT g.scope_ref, g.content_digest, g.ordinal, g.generation_id, \
                    g.file_path, g.discarded \
             FROM member_copy_current AS c \
             JOIN member_copy_generations AS g ON g.generation_id = c.generation_id \
             WHERE c.scope_ref = ?",
        )
        .bind(scope_ref)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.as_ref().map(published_from_row))
    }

    /// Remove a generation's row and file unless it is current or a live lease
    /// still pins it (F2/R3). A removal failure other than "not found" is an
    /// error.
    async fn purge_generation_if_unleased(&self, generation_id: &str) -> Result<()> {
        if self.is_current(generation_id).await? {
            return Ok(());
        }
        if self.has_live_lease(generation_id).await? {
            return Ok(());
        }
        if let Some(row) = self.generation_by_id(generation_id).await? {
            remove_file_if_present(&row.file_path)?;
        }
        sqlx::query("DELETE FROM member_copy_generations WHERE generation_id = ?")
            .bind(generation_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn is_current(&self, generation_id: &str) -> Result<bool> {
        let exists: i64 = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM member_copy_current WHERE generation_id = ?)",
        )
        .bind(generation_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(exists != 0)
    }

    async fn has_live_lease(&self, generation_id: &str) -> Result<bool> {
        let now = chrono::Utc::now().timestamp_millis();
        let exists: i64 = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM member_copy_leases \
             WHERE generation_id = ? AND revoked = 0 AND expires_at_ms >= ?)",
        )
        .bind(generation_id)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;
        Ok(exists != 0)
    }
}

impl MemberCopyRegistry {
    /// §4.3 step 5/6: pin the exact generation a download handle was issued
    /// for (F3). R4: the generation must be the caller's own current
    /// generation for `scope_ref` (matching scope, named by the current
    /// pointer) and not discarded, so a handle can only be issued for the
    /// caller's own current copy. B3: the generation row carries no route
    /// (its identity excludes route, so aliases share it); the requested
    /// route is persisted on the lease, and later reads enforce the
    /// exact-route binding at lookup before check/revoke/bytes.
    pub async fn begin_download(
        &self,
        db: &Db,
        member_account: &str,
        scope_ref: &str,
        generation_id: &str,
        hosted_route_database_id: &str,
    ) -> Result<DownloadHandle> {
        let row = self
            .generation_by_id(generation_id)
            .await?
            .ok_or_else(|| Error::engine("member copy: unknown generation"))?;
        if row.discarded
            || !ct_eq(&row.scope_ref, scope_ref)
            || !self.is_current(generation_id).await?
        {
            return Err(Error::engine(
                "member copy: generation is not the caller's current generation",
            ));
        }
        let fence = workspace_fence_now(db).await?;
        let fingerprint = eligibility_fingerprint(db, member_account).await?;
        let handle = uuid::Uuid::new_v4().to_string();
        let expires_at_ms =
            chrono::Utc::now().timestamp_millis() + self.lease_ttl.as_millis() as i64;
        sqlx::query(
            "INSERT INTO member_copy_leases \
               (handle, member_account, scope_ref, hosted_route_database_id, \
                generation_id, content_digest, \
                authorization_revision, authorization_grant_revision, \
                units_state_digest, eligibility_fingerprint, expires_at_ms, revoked) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
        )
        .bind(&handle)
        .bind(member_account)
        .bind(&row.scope_ref)
        .bind(hosted_route_database_id)
        .bind(generation_id)
        .bind(&row.content_digest)
        .bind(fence.authorization_revision)
        .bind(fence.authorization_grant_revision)
        .bind(&fence.units_state_digest)
        .bind(&fingerprint)
        .bind(expires_at_ms)
        .execute(&self.pool)
        .await?;
        Ok(DownloadHandle {
            handle,
            generation_id: generation_id.to_owned(),
            content_digest: row.content_digest,
            file_path: row.file_path,
            expires_at_ms,
        })
    }

    /// §4.3 step 6 (S2): restart only when E(m) changed. A moved workspace
    /// counter with an unchanged eligibility fingerprint is not a restart.
    pub async fn check_download(&self, db: &Db, handle: &str) -> Result<DownloadDecision> {
        let Some(lease) = self.lease(handle).await? else {
            return Ok(DownloadDecision::Expired);
        };
        if lease.revoked || chrono::Utc::now().timestamp_millis() > lease.expires_at_ms {
            self.end_lease_and_reclaim(handle, &lease.generation_id)
                .await?;
            return Ok(DownloadDecision::Expired);
        }
        // F5: a discarded (or missing) generation is authoritative.
        let discarded = self
            .generation_by_id(&lease.generation_id)
            .await?
            .map(|row| row.discarded)
            .unwrap_or(true);
        if discarded {
            self.end_lease_and_reclaim(handle, &lease.generation_id)
                .await?;
            return Ok(DownloadDecision::Restart);
        }
        // F1/R6: read the fence and the E(m) fingerprint in one transaction,
        // and re-evaluate E(m) when either counter OR the units-state digest
        // moved.
        let (fence, fingerprint) = fence_and_fingerprint(db, &lease.member_account).await?;
        let moved = fence.authorization_revision != lease.authorization_revision
            || fence.authorization_grant_revision != lease.authorization_grant_revision
            || !ct_eq(&fence.units_state_digest, &lease.units_state_digest);
        if !moved {
            return Ok(DownloadDecision::Continue);
        }
        if ct_eq(&fingerprint, &lease.eligibility_fingerprint) {
            // The workspace moved but E(m) did not: keep serving the pinned
            // generation and remember the new fence.
            sqlx::query(
                "UPDATE member_copy_leases SET authorization_revision = ?, \
                 authorization_grant_revision = ?, units_state_digest = ? WHERE handle = ?",
            )
            .bind(fence.authorization_revision)
            .bind(fence.authorization_grant_revision)
            .bind(&fence.units_state_digest)
            .bind(handle)
            .execute(&self.pool)
            .await?;
            return Ok(DownloadDecision::Continue);
        }
        // E(m) changed: the pinned generation is discarded and never served
        // again.
        self.discard_generation(&lease.generation_id).await?;
        self.end_lease_and_reclaim(handle, &lease.generation_id)
            .await?;
        Ok(DownloadDecision::Restart)
    }

    /// §4.3 step 7: discard a lease's pinned generation on a catalog
    /// revocation (member→guest, removal, session revocation). The generation
    /// is marked discarded, its file removed when unleased, and the lease
    /// deleted so it is never served again.
    pub async fn revoke(&self, handle: &str) -> Result<()> {
        let generation_id = self.lease(handle).await?.map(|lease| lease.generation_id);
        if let Some(generation_id) = generation_id.as_deref() {
            self.discard_generation(generation_id).await?;
        }
        sqlx::query("DELETE FROM member_copy_leases WHERE handle = ?")
            .bind(handle)
            .execute(&self.pool)
            .await?;
        if let Some(generation_id) = generation_id.as_deref() {
            self.purge_generation_if_unleased(generation_id).await?;
        }
        Ok(())
    }

    /// Delete a lease and reclaim its generation if it is no longer current
    /// and unleased (R3).
    async fn end_lease_and_reclaim(&self, handle: &str, generation_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM member_copy_leases WHERE handle = ?")
            .bind(handle)
            .execute(&self.pool)
            .await?;
        self.purge_generation_if_unleased(generation_id).await?;
        Ok(())
    }

    /// A completed download ends its lease and reclaims the generation (R3).
    pub async fn complete_download(&self, handle: &str) -> Result<()> {
        let generation_id = self.lease(handle).await?.map(|lease| lease.generation_id);
        sqlx::query("DELETE FROM member_copy_leases WHERE handle = ?")
            .bind(handle)
            .execute(&self.pool)
            .await?;
        if let Some(generation_id) = generation_id {
            self.purge_generation_if_unleased(&generation_id).await?;
        }
        Ok(())
    }

    /// Read one bounded window of the generation a lease pins. Fail-closed:
    /// an unknown handle, a discarded or missing generation, or a missing
    /// file is an error (the fence maps these to typed outcomes, never
    /// bytes). `start >= total_size` yields empty bytes so the caller can
    /// answer 416 with the true size.
    pub async fn read_pinned_bytes(
        &self,
        handle: &str,
        start: u64,
        len: usize,
    ) -> Result<PinnedChunk> {
        let Some(lease) = self.lease(handle).await? else {
            return Err(Error::engine("member copy: unknown download handle"));
        };
        let Some(row) = self.generation_by_id(&lease.generation_id).await? else {
            return Err(Error::engine("member copy: pinned generation missing"));
        };
        if row.discarded {
            return Err(Error::engine("member copy: pinned generation discarded"));
        }
        let all = std::fs::read(&row.file_path).map_err(|error| {
            Error::engine(format!("member copy: pinned generation missing: {error}"))
        })?;
        let total_size = all.len() as u64;
        let sha256 = crate::standby_snapshot::sha256_bytes(&all);
        let start_usize: usize = start
            .try_into()
            .map_err(|_| Error::engine("member copy: byte range start is not addressable"))?;
        let bytes = if start_usize >= all.len() {
            Vec::new()
        } else {
            let end = start_usize.saturating_add(len).min(all.len());
            all[start_usize..end].to_vec()
        };
        Ok(PinnedChunk {
            bytes,
            total_size,
            sha256,
        })
    }

    async fn generation_by_id(&self, generation_id: &str) -> Result<Option<PublishedGeneration>> {
        let row = sqlx::query(
            "SELECT scope_ref, content_digest, ordinal, generation_id, file_path, \
                    discarded \
             FROM member_copy_generations WHERE generation_id = ?",
        )
        .bind(generation_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|row| PublishedGeneration {
            scope_ref: row.get("scope_ref"),
            content_digest: row.get("content_digest"),
            ordinal: row.get("ordinal"),
            generation_id: row.get("generation_id"),
            file_path: row.get("file_path"),
            discarded: row.get::<i64, _>("discarded") != 0,
        }))
    }

    /// The caller-binding of a lease, constrained at lookup: `Some` only
    /// when the handle exists AND is bound to the given `member_account`,
    /// `scope_ref` and `hosted_route_database_id`. An unknown, foreign, or
    /// cross-route handle is `None` without exposing the stored binding, so
    /// the transport learns nothing about another principal's lease. This
    /// is the only lease-metadata lookup the transport uses before
    /// check/revoke/bytes; no raw accessor exists.
    pub async fn lease_binding_for(
        &self,
        handle: &str,
        member_account: &str,
        scope_ref: &str,
        hosted_route_database_id: &str,
    ) -> Result<Option<LeaseBinding>> {
        let row = sqlx::query(
            "SELECT member_account, scope_ref, hosted_route_database_id \
             FROM member_copy_leases WHERE handle = ?",
        )
        .bind(handle)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let binding = LeaseBinding {
            member_account: row.get("member_account"),
            scope_ref: row.get("scope_ref"),
            hosted_route_database_id: row.try_get("hosted_route_database_id").unwrap_or_default(),
        };
        if ct_eq(&binding.member_account, member_account)
            && ct_eq(&binding.scope_ref, scope_ref)
            && ct_eq(&binding.hosted_route_database_id, hosted_route_database_id)
        {
            Ok(Some(binding))
        } else {
            Ok(None)
        }
    }

    async fn lease(&self, handle: &str) -> Result<Option<LeaseRow>> {
        let row = sqlx::query(
            "SELECT member_account, generation_id, authorization_revision, \
                    authorization_grant_revision, units_state_digest, \
                    eligibility_fingerprint, expires_at_ms, revoked \
             FROM member_copy_leases WHERE handle = ?",
        )
        .bind(handle)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|row| LeaseRow {
            member_account: row.get("member_account"),
            generation_id: row.get("generation_id"),
            authorization_revision: row.get("authorization_revision"),
            authorization_grant_revision: row.get("authorization_grant_revision"),
            units_state_digest: row.get("units_state_digest"),
            eligibility_fingerprint: row.get("eligibility_fingerprint"),
            expires_at_ms: row.get("expires_at_ms"),
            revoked: row.get::<i64, _>("revoked") != 0,
        }))
    }

    /// Mark a generation discarded and remove its file, so it is never served
    /// again. The current pointer is left in place so the lazy ordinal keeps
    /// advancing (a discarded generation is never reused). Used by
    /// `check_download` on an E(m) change and by the hosted C/W/C sandwich to
    /// discard a cut when C2 sees a catalog change.
    pub async fn discard_generation(&self, generation_id: &str) -> Result<()> {
        if let Some(row) = self.generation_by_id(generation_id).await? {
            remove_file_if_present(&row.file_path)?;
        }
        sqlx::query("UPDATE member_copy_generations SET discarded = 1 WHERE generation_id = ?")
            .bind(generation_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

/// Read the workspace fence (both counters plus the units digest) in a fresh
/// read transaction.
async fn workspace_fence_now(db: &Db) -> Result<WorkspaceFence> {
    let mut connection = db.governed_pool().acquire().await?;
    let mut tx = connection.begin().await?;
    let fence = workspace_fence(&mut tx).await;
    let rollback = tx.rollback().await;
    connection.close_on_drop();
    let fence = fence?;
    rollback?;
    Ok(fence)
}

/// §4.3 step 6: a hash of the sorted E(m) id set plus the caller-bound
/// footing (the caller's own account binding, member context and instruction
/// bindings). Content edits and hidden-only changes do not move it.
async fn eligibility_fingerprint(db: &Db, account: &str) -> Result<String> {
    let mut connection = db.governed_pool().acquire().await?;
    let mut tx = connection.begin().await?;
    install_visible_records_in(
        &mut tx,
        QueryPrincipal::authenticated(account.to_owned(), true),
    )
    .await?;
    let computed = eligibility_fingerprint_in(&mut tx, account).await;
    let rollback = tx.rollback().await;
    connection.close_on_drop();
    let fingerprint = computed?;
    rollback?;
    Ok(fingerprint)
}

/// The fingerprint body, for a transaction that already installed the
/// visibility views.
async fn eligibility_fingerprint_in(
    tx: &mut Transaction<'_, Sqlite>,
    account: &str,
) -> Result<String> {
    let ids: BTreeSet<String> =
        sqlx::query_scalar("SELECT id FROM temp._query_sql_visible_records")
            .fetch_all(&mut **tx)
            .await?
            .into_iter()
            .collect();
    let mut footing: BTreeSet<String> = BTreeSet::new();
    let bindings = sqlx::query(
        "SELECT record_id, identifier FROM main.bindings \
         WHERE system = 'account' AND identifier = ? AND is_canonical = 1",
    )
    .bind(account)
    .fetch_all(&mut **tx)
    .await?;
    for row in bindings {
        let record_id: String = row.get("record_id");
        let identifier: String = row.get("identifier");
        footing.insert(format!("binding:{record_id}:{identifier}"));
    }
    let contexts = sqlx::query(
        "SELECT account_id, person_record_id, root_record_id FROM main.member_contexts \
         WHERE account_id = ?",
    )
    .bind(account)
    .fetch_all(&mut **tx)
    .await?;
    for row in contexts {
        let account_id: String = row.get("account_id");
        let person: String = row.get("person_record_id");
        let root: String = row.get("root_record_id");
        footing.insert(format!("context:{account_id}:{person}:{root}"));
    }
    let instructions = sqlx::query(
        "SELECT t.id, t.source_record_id FROM main.instruction_bindings AS t \
         WHERE EXISTS (SELECT 1 FROM temp._query_sql_visible_records AS v \
                       WHERE v.id = t.source_record_id) \
           AND ((t.scope_kind = 'account' AND t.scope_id = ?) \
                OR t.scope_kind = 'database')",
    )
    .bind(account)
    .fetch_all(&mut **tx)
    .await?;
    for row in instructions {
        let id: String = row.get("id");
        let source: String = row.get("source_record_id");
        footing.insert(format!("instruction:{id}:{source}"));
    }
    Ok(crate::canonical_json::digest_json(&serde_json::json!([
        ids, footing,
    ])))
}

/// F1/R6: read the workspace fence and the E(m) fingerprint in one read
/// transaction, so a lease check cannot straddle two snapshots.
async fn fence_and_fingerprint(db: &Db, account: &str) -> Result<(WorkspaceFence, String)> {
    let mut connection = db.governed_pool().acquire().await?;
    let mut tx = connection.begin().await?;
    install_visible_records_in(
        &mut tx,
        QueryPrincipal::authenticated(account.to_owned(), true),
    )
    .await?;
    let computed = async {
        let fence = workspace_fence(&mut tx).await?;
        let fingerprint = eligibility_fingerprint_in(&mut tx, account).await?;
        Ok::<_, Error>((fence, fingerprint))
    }
    .await;
    let rollback = tx.rollback().await;
    connection.close_on_drop();
    let result = computed?;
    rollback?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use rusqlite::Connection as RusqliteConnection;

    use super::*;
    use crate::authorization::{AllowEntry, Capability};
    use crate::db::create_database;
    use crate::member_offline_fixtures::{self as fixtures, assert_no_counter_fields};
    use crate::schema::ROOT_RECORD_ID;
    use crate::standby_snapshot::{StandbyConsumerPlatform, STANDBY_CONSUMER_CONTRACT};

    const PERSON_A: &str = "a1000000-0000-4000-8000-0000000000a1";
    const PERSON_B: &str = "a1000000-0000-4000-8000-0000000000b1";
    const VIS: &str = "a1000000-0000-4000-8000-000000000001";
    const HID: &str = "a1000000-0000-4000-8000-000000000002";
    const VIS2: &str = "a1000000-0000-4000-8000-000000000003";
    const HID2: &str = "a1000000-0000-4000-8000-000000000004";
    /// Hidden from A; the initial `unit_id` target for the units-state test.
    const OTHER: &str = "a1000000-0000-4000-8000-000000000005";
    /// A hidden collection used as a policy anchor for the anchor-move test.
    const HIDDEN_ANCHOR: &str = "a1000000-0000-4000-8000-000000000006";

    fn consumer() -> crate::standby_snapshot::StandbyConsumerIdentity {
        crate::standby_snapshot::StandbyConsumerIdentity {
            contract: STANDBY_CONSUMER_CONTRACT.to_owned(),
            version: 1,
            platform: StandbyConsumerPlatform::LinuxX8664,
            source_sha: "c".repeat(40),
            artifact_sha256: "d".repeat(64),
            engine_schema_version: crate::CURRENT_ENGINE_SCHEMA_VERSION,
            ddl_sha256: "e".repeat(64),
        }
    }

    async fn registry(dir: &Path) -> MemberCopyRegistry {
        MemberCopyRegistry::open(RegistryConfig {
            store_dir: dir.to_path_buf(),
            scope_ref_key: ScopeRefKey::new([7u8; 32]),
            lease_ttl: Duration::from_secs(3600),
            hosted_route_database_id: "route-test".to_owned(),
            consumer: consumer(),
        })
        .await
        .unwrap()
    }

    fn inputs(account: &str, created: &str) -> ScopeInputs {
        ScopeInputs {
            origin_database_id: format!("ndb_{}", "1".repeat(32)),
            user_id: format!("user-{account}"),
            account_token: account.to_owned(),
            membership_created_at: created.to_owned(),
            role: "member".to_owned(),
            profile_major: 1,
            member_account: account.to_owned(),
        }
    }

    async fn world() -> Db {
        let db = create_database(":memory:").await.unwrap();
        fixtures::create_member(&db, PERSON_A, fixtures::ACCT_A).await;
        fixtures::create_member(&db, PERSON_B, fixtures::ACCT_B).await;
        fixtures::grant(&db, PERSON_A, vec![AllowEntry::members(Capability::View)]).await;
        fixtures::grant(&db, PERSON_B, vec![AllowEntry::members(Capability::View)]).await;
        fixtures::mk_doc(&db, VIS, ROOT_RECORD_ID, Some("visible"), None).await;
        fixtures::grant(&db, VIS, vec![AllowEntry::members(Capability::View)]).await;
        fixtures::mk_doc(&db, HID, ROOT_RECORD_ID, Some("hidden"), None).await;
        fixtures::grant(
            &db,
            HID,
            vec![AllowEntry::account(fixtures::ACCT_B, Capability::View)],
        )
        .await;
        db
    }

    fn published(answer: &RequestAnswer) -> (&str, i64) {
        match answer {
            RequestAnswer::Replace {
                generation_id,
                ordinal,
                ..
            } => (generation_id, *ordinal),
            other => panic!("expected replace, got {other:?}"),
        }
    }

    fn record_ids(path: &str) -> BTreeSet<String> {
        let connection = RusqliteConnection::open(path).unwrap();
        let mut statement = connection.prepare("SELECT id FROM records").unwrap();
        statement
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap()
    }

    async fn counters(db: &Db) -> (i64, i64) {
        let broad: i64 =
            sqlx::query_scalar("SELECT epoch FROM authorization_revision WHERE id = 1")
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        let grant: i64 =
            sqlx::query_scalar("SELECT epoch FROM authorization_grant_revision WHERE id = 1")
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        (broad, grant)
    }

    #[tokio::test]
    async fn unchanged_world_is_current_with_same_generation() {
        let db = world().await;
        let dir = tempfile::tempdir().unwrap();
        let reg = registry(dir.path()).await;
        let inputs = inputs(fixtures::ACCT_A, "2026-01-01T00:00:00Z");
        let scope_ref = reg.scope_ref(&inputs);
        let first = reg
            .request(&db, &inputs, CredentialVerdict::Ready, None, None)
            .await
            .unwrap();
        let (gid, ordinal) = published(&first);
        assert_eq!(ordinal, 1);
        let second = reg
            .request(
                &db,
                &inputs,
                CredentialVerdict::Ready,
                Some(gid),
                Some(&scope_ref),
            )
            .await
            .unwrap();
        match second {
            RequestAnswer::Current {
                generation_id,
                ordinal,
                ..
            } => {
                assert_eq!(generation_id, gid);
                assert_eq!(ordinal, 1);
            }
            other => panic!("expected current, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn download_survives_edits_and_hidden_changes_but_restarts_on_e_change() {
        let db = world().await;
        let dir = tempfile::tempdir().unwrap();
        let reg = registry(dir.path()).await;
        let inputs = inputs(fixtures::ACCT_A, "2026-01-01T00:00:00Z");
        let scope_ref = reg.scope_ref(&inputs);
        let first = reg
            .request(&db, &inputs, CredentialVerdict::Ready, None, None)
            .await
            .unwrap();
        let (gid, _) = published(&first);
        let gid = gid.to_owned();
        let handle = reg
            .begin_download(&db, fixtures::ACCT_A, &scope_ref, &gid, "route-test")
            .await
            .unwrap();

        // A visible content edit: no restart.
        crate::store::update_record(&db, VIS, serde_json::json!({"body": "edited"}))
            .await
            .unwrap();
        assert_eq!(
            reg.check_download(&db, &handle.handle).await.unwrap(),
            DownloadDecision::Continue
        );

        // A hidden-only change moves the counters but not E(A): no restart.
        fixtures::mk_doc(&db, HID2, ROOT_RECORD_ID, Some("hidden2"), None).await;
        fixtures::grant(
            &db,
            HID2,
            vec![AllowEntry::account(fixtures::ACCT_B, Capability::View)],
        )
        .await;
        assert_eq!(
            reg.check_download(&db, &handle.handle).await.unwrap(),
            DownloadDecision::Continue
        );

        // Re-granting VIS to B only removes A's access: restart, then never
        // served again. (The true anchor-move case is
        // `moving_a_record_under_a_hidden_anchor_restarts_download`.)
        fixtures::grant(
            &db,
            VIS,
            vec![AllowEntry::account(fixtures::ACCT_B, Capability::View)],
        )
        .await;
        assert_eq!(
            reg.check_download(&db, &handle.handle).await.unwrap(),
            DownloadDecision::Restart
        );
        assert_eq!(
            reg.check_download(&db, &handle.handle).await.unwrap(),
            DownloadDecision::Expired
        );
        assert!(reg
            .begin_download(&db, fixtures::ACCT_A, &scope_ref, &gid, "route-test")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn granting_a_record_publishes_a_new_generation() {
        let db = world().await;
        let dir = tempfile::tempdir().unwrap();
        let reg = registry(dir.path()).await;
        let inputs = inputs(fixtures::ACCT_A, "2026-01-01T00:00:00Z");
        let scope_ref = reg.scope_ref(&inputs);
        let first = reg
            .request(&db, &inputs, CredentialVerdict::Ready, None, None)
            .await
            .unwrap();
        let (gid, ordinal) = published(&first);
        assert_eq!(ordinal, 1);
        let gid = gid.to_owned();

        fixtures::mk_doc(&db, VIS2, ROOT_RECORD_ID, Some("visible2"), None).await;
        fixtures::grant(&db, VIS2, vec![AllowEntry::members(Capability::View)]).await;
        let second = reg
            .request(
                &db,
                &inputs,
                CredentialVerdict::Ready,
                Some(&gid),
                Some(&scope_ref),
            )
            .await
            .unwrap();
        let (new_gid, ordinal) = match second {
            RequestAnswer::Replace {
                generation_id,
                ordinal,
                ..
            } => (generation_id, ordinal),
            other => panic!("expected replace, got {other:?}"),
        };
        assert_ne!(new_gid, gid);
        assert_eq!(ordinal, 2);
        let handle = reg
            .begin_download(&db, fixtures::ACCT_A, &scope_ref, &new_gid, "route-test")
            .await
            .unwrap();
        assert!(record_ids(handle.file_path()).contains(VIS2));
    }

    #[tokio::test]
    async fn ordinal_counts_only_content_changes() {
        let db = world().await;
        let dir = tempfile::tempdir().unwrap();
        let reg = registry(dir.path()).await;
        let inputs = inputs(fixtures::ACCT_A, "2026-01-01T00:00:00Z");
        let scope_ref = reg.scope_ref(&inputs);
        let first = reg
            .request(&db, &inputs, CredentialVerdict::Ready, None, None)
            .await
            .unwrap();
        let (gid, ordinal) = published(&first);
        assert_eq!(ordinal, 1);
        let gid = gid.to_owned();

        // Hidden-only changes never move the ordinal.
        crate::store::update_record(&db, HID, serde_json::json!({"body": "h1-edited"}))
            .await
            .unwrap();
        fixtures::mk_doc(&db, HID2, ROOT_RECORD_ID, Some("h2"), None).await;
        fixtures::grant(
            &db,
            HID2,
            vec![AllowEntry::account(fixtures::ACCT_B, Capability::View)],
        )
        .await;
        let answer = reg
            .request(
                &db,
                &inputs,
                CredentialVerdict::Ready,
                Some(&gid),
                Some(&scope_ref),
            )
            .await
            .unwrap();
        match answer {
            RequestAnswer::Current {
                generation_id,
                ordinal,
                ..
            } => {
                assert_eq!(generation_id, gid);
                assert_eq!(ordinal, 1, "hidden changes must not move the ordinal");
            }
            other => panic!("expected current after hidden changes, got {other:?}"),
        }

        // One visible change: exactly +1.
        fixtures::mk_doc(&db, VIS2, ROOT_RECORD_ID, Some("v2"), None).await;
        fixtures::grant(&db, VIS2, vec![AllowEntry::members(Capability::View)]).await;
        let answer = reg
            .request(
                &db,
                &inputs,
                CredentialVerdict::Ready,
                Some(&gid),
                Some(&scope_ref),
            )
            .await
            .unwrap();
        let (new_gid, ordinal) = published(&answer);
        assert_eq!(ordinal, 2);
        assert_ne!(new_gid, gid);
    }

    #[tokio::test]
    async fn rotated_scope_ref_is_never_current() {
        let db = world().await;
        let dir = tempfile::tempdir().unwrap();
        let reg = registry(dir.path()).await;
        let first_inputs = inputs(fixtures::ACCT_A, "2026-01-01T00:00:00Z");
        let first_scope = reg.scope_ref(&first_inputs);
        let first = reg
            .request(&db, &first_inputs, CredentialVerdict::Ready, None, None)
            .await
            .unwrap();
        let (gid, _) = published(&first);
        let gid = gid.to_owned();

        let rotated = inputs(fixtures::ACCT_A, "2026-02-01T00:00:00Z");
        let rotated_scope = reg.scope_ref(&rotated);
        assert_ne!(first_scope, rotated_scope);
        let answer = reg
            .request(
                &db,
                &rotated,
                CredentialVerdict::Ready,
                Some(&gid),
                Some(&first_scope),
            )
            .await
            .unwrap();
        match answer {
            RequestAnswer::Replace {
                scope_changed,
                generation_id,
                ..
            } => {
                assert!(scope_changed, "a superseded scope_ref must not be current");
                assert_ne!(generation_id, gid);
            }
            other => panic!("expected replace scope_changed, got {other:?}"),
        }
        let answer = reg
            .request(
                &db,
                &rotated,
                CredentialVerdict::Ready,
                Some(&gid),
                Some(&rotated_scope),
            )
            .await
            .unwrap();
        assert!(matches!(
            answer,
            RequestAnswer::Replace {
                scope_changed: false,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn answers_carry_no_counter_fields() {
        let db = world().await;
        let dir = tempfile::tempdir().unwrap();
        let reg = registry(dir.path()).await;
        let inputs = inputs(fixtures::ACCT_A, "2026-01-01T00:00:00Z");
        let scope_ref = reg.scope_ref(&inputs);
        let first = reg
            .request(&db, &inputs, CredentialVerdict::Ready, None, None)
            .await
            .unwrap();
        let (gid, _) = published(&first);
        let gid = gid.to_owned();
        let second = reg
            .request(
                &db,
                &inputs,
                CredentialVerdict::Ready,
                Some(&gid),
                Some(&scope_ref),
            )
            .await
            .unwrap();
        let revoked = reg
            .request(
                &db,
                &inputs,
                CredentialVerdict::Revoked {
                    cause: "session_revoked".into(),
                },
                Some(&gid),
                Some(&scope_ref),
            )
            .await
            .unwrap();
        let locked = reg
            .request(
                &db,
                &inputs,
                CredentialVerdict::Locked,
                Some(&gid),
                Some(&scope_ref),
            )
            .await
            .unwrap();
        for answer in [&first, &second, &revoked, &locked] {
            let value = serde_json::to_value(answer).unwrap();
            assert_no_counter_fields(&value, "registry answer");
        }
    }

    #[tokio::test]
    async fn revoked_and_locked_are_echoed_without_building() {
        let db = world().await;
        let dir = tempfile::tempdir().unwrap();
        let reg = registry(dir.path()).await;
        let inputs = inputs(fixtures::ACCT_A, "2026-01-01T00:00:00Z");
        let revoked = reg
            .request(
                &db,
                &inputs,
                CredentialVerdict::Revoked {
                    cause: "membership_ended".into(),
                },
                None,
                None,
            )
            .await
            .unwrap();
        assert!(matches!(revoked, RequestAnswer::Revoked { cause } if cause == "membership_ended"));
        let locked = reg
            .request(&db, &inputs, CredentialVerdict::Locked, None, None)
            .await
            .unwrap();
        assert!(matches!(locked, RequestAnswer::Locked));
    }

    /// F1: a `semantic_units.unit_id` update moves neither counter but does
    /// change E(m), so the units-state digest must drive a restart.
    #[tokio::test]
    async fn unit_id_change_that_narrows_e_m_restarts_download() {
        let db = world().await;
        fixtures::mk_doc(&db, OTHER, ROOT_RECORD_ID, Some("other"), None).await;
        fixtures::grant(
            &db,
            OTHER,
            vec![AllowEntry::account(fixtures::ACCT_B, Capability::View)],
        )
        .await;
        let (event_id, event_seq): (String, i64) = sqlx::query_as(
            "SELECT id, seq FROM content_events WHERE record_id = ? ORDER BY seq LIMIT 1",
        )
        .bind(OTHER)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO semantic_units \
               (unit_id, authority_bearer_record_id, creation_event_id, \
                creation_event_seq, created_at) \
             VALUES (?, ?, ?, ?, '2026-09-23T00:00:00.000Z')",
        )
        .bind(OTHER)
        .bind(PERSON_A)
        .bind(event_id)
        .bind(event_seq)
        .execute(db.write_pool())
        .await
        .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let reg = registry(dir.path()).await;
        let inputs = inputs(fixtures::ACCT_A, "2026-01-01T00:00:00Z");
        let scope_ref = reg.scope_ref(&inputs);
        let first = reg
            .request(&db, &inputs, CredentialVerdict::Ready, None, None)
            .await
            .unwrap();
        let (gid, _) = published(&first);
        let gid = gid.to_owned();
        let handle = reg
            .begin_download(&db, fixtures::ACCT_A, &scope_ref, &gid, "route-test")
            .await
            .unwrap();

        let before = counters(&db).await;
        // Re-point the unit at VIS: VIS becomes a Unit and leaves E(A), while
        // neither authorization counter moves.
        sqlx::query("UPDATE semantic_units SET unit_id = ? WHERE unit_id = ?")
            .bind(VIS)
            .bind(OTHER)
            .execute(db.write_pool())
            .await
            .unwrap();
        assert_eq!(before, counters(&db).await, "counters must not move");
        assert_eq!(
            reg.check_download(&db, &handle.handle).await.unwrap(),
            DownloadDecision::Restart
        );
    }

    /// F2: a live lease keeps the superseded generation's bytes across a
    /// publish; once the lease ends, the next publish removes them.
    #[tokio::test]
    async fn live_lease_keeps_superseded_generation_bytes() {
        let db = world().await;
        let dir = tempfile::tempdir().unwrap();
        let reg = registry(dir.path()).await;
        let inputs = inputs(fixtures::ACCT_A, "2026-01-01T00:00:00Z");
        let scope_ref = reg.scope_ref(&inputs);
        let first = reg
            .request(&db, &inputs, CredentialVerdict::Ready, None, None)
            .await
            .unwrap();
        let (gid1, _) = published(&first);
        let gid1 = gid1.to_owned();
        let handle1 = reg
            .begin_download(&db, fixtures::ACCT_A, &scope_ref, &gid1, "route-test")
            .await
            .unwrap();
        let path1 = handle1.file_path().to_owned();
        assert!(Path::new(&path1).exists());
        assert!(
            reg.has_live_lease(&gid1).await.unwrap(),
            "lease must be live"
        );

        // A visible body edit changes the digest but not E(A): device 2
        // publishes a new generation while device 1's lease is live.
        crate::store::update_record(&db, VIS, serde_json::json!({"body": "edited"}))
            .await
            .unwrap();
        let second = reg
            .request(
                &db,
                &inputs,
                CredentialVerdict::Ready,
                Some(&gid1),
                Some(&scope_ref),
            )
            .await
            .unwrap();
        let (gid2, ordinal2) = published(&second);
        let gid2 = gid2.to_owned();
        assert_ne!(gid2, gid1);
        assert_eq!(ordinal2, 2);
        assert!(
            Path::new(&path1).exists(),
            "a live lease must keep the superseded file"
        );
        // The pinned generation is still resolvable while its lease is live.
        assert!(reg.generation_by_id(&gid1).await.unwrap().is_some());
        assert_eq!(
            reg.check_download(&db, &handle1.handle).await.unwrap(),
            DownloadDecision::Continue
        );

        // Ending the lease lets the next publish purge it.
        reg.complete_download(&handle1.handle).await.unwrap();
        assert!(!reg.has_live_lease(&gid1).await.unwrap(), "lease must end");
        crate::store::update_record(&db, VIS, serde_json::json!({"body": "edited again"}))
            .await
            .unwrap();
        let third = reg
            .request(
                &db,
                &inputs,
                CredentialVerdict::Ready,
                Some(&gid2),
                Some(&scope_ref),
            )
            .await
            .unwrap();
        let (_, ordinal3) = published(&third);
        assert_eq!(ordinal3, 3);
        assert!(
            !Path::new(&path1).exists(),
            "an unleased superseded file must be removed"
        );
    }

    /// F3/R2: two concurrent requests for one scope allocate exactly one
    /// ordinal. The barrier makes both observe the pre-change state before
    /// either publishes, so the test would race without the mutex plus the
    /// store's `BEGIN IMMEDIATE`/`UNIQUE(scope_ref, ordinal)`.
    #[tokio::test]
    async fn concurrent_requests_allocate_one_ordinal() {
        let db = world().await;
        let dir = tempfile::tempdir().unwrap();
        let mut reg = registry(dir.path()).await;
        let inputs = inputs(fixtures::ACCT_A, "2026-01-01T00:00:00Z");
        let scope_ref = reg.scope_ref(&inputs);
        let first = reg
            .request(&db, &inputs, CredentialVerdict::Ready, None, None)
            .await
            .unwrap();
        let (gid1, _) = published(&first);
        let gid1 = gid1.to_owned();

        fixtures::mk_doc(&db, VIS2, ROOT_RECORD_ID, Some("v2"), None).await;
        fixtures::grant(&db, VIS2, vec![AllowEntry::members(Capability::View)]).await;
        reg.set_publish_barrier(std::sync::Arc::new(tokio::sync::Barrier::new(2)));
        let (left, right) = tokio::join!(
            reg.request(
                &db,
                &inputs,
                CredentialVerdict::Ready,
                Some(&gid1),
                Some(&scope_ref)
            ),
            reg.request(
                &db,
                &inputs,
                CredentialVerdict::Ready,
                Some(&gid1),
                Some(&scope_ref)
            ),
        );
        let left = left.unwrap();
        let right = right.unwrap();
        let (gid_a, ordinal_a) = published(&left);
        let (gid_b, ordinal_b) = published(&right);
        assert_eq!(ordinal_a, 2);
        assert_eq!(ordinal_b, 2);
        assert_eq!(gid_a, gid_b, "both requests must observe one generation");
        let rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM member_copy_generations WHERE scope_ref = ? AND ordinal = 2",
        )
        .bind(&scope_ref)
        .fetch_one(&reg.pool)
        .await
        .unwrap();
        assert_eq!(rows, 1, "exactly one generation may hold ordinal 2");
    }

    /// F4: a `scope_ref` rotation purges the superseded scope and never
    /// resolves it again.
    #[tokio::test]
    async fn rotation_purges_the_superseded_scope() {
        let db = world().await;
        let dir = tempfile::tempdir().unwrap();
        let reg = registry(dir.path()).await;
        let first_inputs = inputs(fixtures::ACCT_A, "2026-01-01T00:00:00Z");
        let first_scope = reg.scope_ref(&first_inputs);
        let first = reg
            .request(&db, &first_inputs, CredentialVerdict::Ready, None, None)
            .await
            .unwrap();
        let (gid1, _) = published(&first);
        let gid1 = gid1.to_owned();
        let handle = reg
            .begin_download(&db, fixtures::ACCT_A, &first_scope, &gid1, "route-test")
            .await
            .unwrap();
        let path1 = handle.file_path().to_owned();
        reg.complete_download(&handle.handle).await.unwrap();

        let rotated = inputs(fixtures::ACCT_A, "2026-02-01T00:00:00Z");
        let rotated_scope = reg.scope_ref(&rotated);
        let second = reg
            .request(
                &db,
                &rotated,
                CredentialVerdict::Ready,
                Some(&gid1),
                Some(&first_scope),
            )
            .await
            .unwrap();
        assert!(matches!(
            second,
            RequestAnswer::Replace {
                scope_changed: true,
                ..
            }
        ));
        assert!(
            !Path::new(&path1).exists(),
            "the superseded scope's file must be purged"
        );
        assert!(reg
            .begin_download(&db, fixtures::ACCT_A, &first_scope, &gid1, "route-test")
            .await
            .is_err());
        assert!(reg.published_for(&first_scope).await.unwrap().is_none());
        assert!(reg.published_for(&rotated_scope).await.unwrap().is_some());
    }

    /// F8: a real anchor move (re-point `policy_anchor_id` at a hidden
    /// collection) changes E(A) mid-download.
    #[tokio::test]
    async fn moving_a_record_under_a_hidden_anchor_restarts_download() {
        let db = world().await;
        fixtures::mk_collection(&db, HIDDEN_ANCHOR, ROOT_RECORD_ID).await;
        fixtures::grant(
            &db,
            HIDDEN_ANCHOR,
            vec![AllowEntry::account(fixtures::ACCT_B, Capability::View)],
        )
        .await;

        let dir = tempfile::tempdir().unwrap();
        let reg = registry(dir.path()).await;
        let inputs = inputs(fixtures::ACCT_A, "2026-01-01T00:00:00Z");
        let scope_ref = reg.scope_ref(&inputs);
        let first = reg
            .request(&db, &inputs, CredentialVerdict::Ready, None, None)
            .await
            .unwrap();
        let (gid, _) = published(&first);
        let gid = gid.to_owned();
        let handle = reg
            .begin_download(&db, fixtures::ACCT_A, &scope_ref, &gid, "route-test")
            .await
            .unwrap();

        sqlx::query("UPDATE records SET policy_anchor_id = ? WHERE id = ?")
            .bind(HIDDEN_ANCHOR)
            .bind(VIS)
            .execute(db.write_pool())
            .await
            .unwrap();
        assert_eq!(
            reg.check_download(&db, &handle.handle).await.unwrap(),
            DownloadDecision::Restart
        );
    }

    /// R3: a rotated-away generation pinned by a lease is reclaimed when the
    /// lease ends.
    #[tokio::test]
    async fn rotation_reclaims_the_file_when_the_last_lease_ends() {
        let db = world().await;
        let dir = tempfile::tempdir().unwrap();
        let reg = registry(dir.path()).await;
        let first_inputs = inputs(fixtures::ACCT_A, "2026-01-01T00:00:00Z");
        let first_scope = reg.scope_ref(&first_inputs);
        let first = reg
            .request(&db, &first_inputs, CredentialVerdict::Ready, None, None)
            .await
            .unwrap();
        let (gid1, _) = published(&first);
        let gid1 = gid1.to_owned();
        let handle = reg
            .begin_download(&db, fixtures::ACCT_A, &first_scope, &gid1, "route-test")
            .await
            .unwrap();
        let path1 = handle.file_path().to_owned();
        assert!(Path::new(&path1).exists());

        // Rotate: gid1 is discarded but its live lease keeps the file.
        let rotated = inputs(fixtures::ACCT_A, "2026-02-01T00:00:00Z");
        let rotated_scope = reg.scope_ref(&rotated);
        reg.request(
            &db,
            &rotated,
            CredentialVerdict::Ready,
            Some(&gid1),
            Some(&first_scope),
        )
        .await
        .unwrap();
        assert!(
            Path::new(&path1).exists(),
            "a live lease keeps the rotated file"
        );
        assert!(reg.generation_by_id(&gid1).await.unwrap().is_some());

        // Ending the lease reclaims the discarded generation.
        reg.complete_download(&handle.handle).await.unwrap();
        assert!(
            !Path::new(&path1).exists(),
            "the rotated file is reclaimed on lease end"
        );
        assert!(reg.generation_by_id(&gid1).await.unwrap().is_none());
        assert!(reg.published_for(&rotated_scope).await.unwrap().is_some());
    }

    /// R4: a handle can only be issued for the caller's own current
    /// generation; a foreign or stale id is refused.
    #[tokio::test]
    async fn begin_download_refuses_foreign_and_stale_generations() {
        let db = world().await;
        let dir = tempfile::tempdir().unwrap();
        let reg = registry(dir.path()).await;
        let inputs_a = inputs(fixtures::ACCT_A, "2026-01-01T00:00:00Z");
        let scope_a = reg.scope_ref(&inputs_a);
        let first = reg
            .request(&db, &inputs_a, CredentialVerdict::Ready, None, None)
            .await
            .unwrap();
        let (gid1, _) = published(&first);
        let gid1 = gid1.to_owned();

        // A different member's scope cannot pin A's generation.
        let inputs_b = inputs(fixtures::ACCT_B, "2026-01-01T00:00:00Z");
        let scope_b = reg.scope_ref(&inputs_b);
        assert!(reg
            .begin_download(&db, fixtures::ACCT_B, &scope_b, &gid1, "route-test")
            .await
            .is_err());

        // After a new generation is current, the old id is stale.
        fixtures::mk_doc(&db, VIS2, ROOT_RECORD_ID, Some("v2"), None).await;
        fixtures::grant(&db, VIS2, vec![AllowEntry::members(Capability::View)]).await;
        let second = reg
            .request(
                &db,
                &inputs_a,
                CredentialVerdict::Ready,
                Some(&gid1),
                Some(&scope_a),
            )
            .await
            .unwrap();
        let (gid2, _) = published(&second);
        assert_ne!(gid2, gid1);
        assert!(reg
            .begin_download(&db, fixtures::ACCT_A, &scope_a, &gid1, "route-test")
            .await
            .is_err());
        assert!(reg
            .begin_download(&db, fixtures::ACCT_A, &scope_a, gid2, "route-test")
            .await
            .is_ok());
    }

    /// R5/§2.6: the verdict is client-facing and must carry no counter field.
    #[test]
    fn credential_verdict_serialisation_has_no_counter_fields() {
        for verdict in [
            CredentialVerdict::Ready,
            CredentialVerdict::Locked,
            CredentialVerdict::Revoked {
                cause: "membership_ended".to_owned(),
            },
            CredentialVerdict::Revoked {
                cause: "role_changed".to_owned(),
            },
            CredentialVerdict::Revoked {
                cause: "session_revoked".to_owned(),
            },
        ] {
            let value = serde_json::to_value(&verdict).unwrap();
            assert_no_counter_fields(&value, "credential verdict");
        }
    }

    /// N1: an unknown on-disk store version is refused, not guessed at.
    #[tokio::test]
    async fn registry_refuses_unknown_store_schema_version() {
        let dir = tempfile::tempdir().unwrap();
        let reg = registry(dir.path()).await;
        sqlx::query("UPDATE member_copy_registry_meta SET schema_version = 999")
            .execute(&reg.pool)
            .await
            .unwrap();
        drop(reg);
        let reopened = MemberCopyRegistry::open(RegistryConfig {
            store_dir: dir.path().to_path_buf(),
            scope_ref_key: ScopeRefKey::new([7u8; 32]),
            lease_ttl: Duration::from_secs(3600),
            hosted_route_database_id: "route-test".to_owned(),
            consumer: consumer(),
        })
        .await;
        assert!(
            reopened.is_err(),
            "an unknown member copy registry schema version must be refused"
        );
    }

    /// N2: an INSERT failure after the generation id is chosen must not leave
    /// a final generation file (the rename happens only after the row stages).
    #[tokio::test]
    async fn insert_failure_leaves_no_generation_file() {
        let db = world().await;
        let dir = tempfile::tempdir().unwrap();
        let reg = registry(dir.path()).await;
        let inputs = inputs(fixtures::ACCT_A, "2026-01-01T00:00:00Z");
        let scope_ref = reg.scope_ref(&inputs);
        // A conflicting `(scope_ref, ordinal=1)` row with no current pointer
        // makes the first publish hit `UNIQUE(scope_ref, ordinal)`.
        sqlx::query(
            "INSERT INTO member_copy_generations \
               (generation_id, scope_ref, origin_database_id, content_digest, ordinal, \
                file_path, authorization_revision, authorization_grant_revision, \
                units_state_digest, discarded, published_at) \
             VALUES ('manual-conflict', ?, 'x', 'd', 1, 'x', 0, 0, 'u', 0, 't')",
        )
        .bind(&scope_ref)
        .execute(&reg.pool)
        .await
        .unwrap();
        let result = reg
            .request(&db, &inputs, CredentialVerdict::Ready, None, None)
            .await;
        assert!(
            result.is_err(),
            "the UNIQUE(scope_ref, ordinal) backstop must fail loudly"
        );
        let mut finals: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| {
                name.len() == 67
                    && name.ends_with(".db")
                    && name[..64].bytes().all(|b| b.is_ascii_hexdigit())
            })
            .collect();
        finals.sort();
        assert!(
            finals.is_empty(),
            "no final generation file may remain after an INSERT failure: {finals:?}"
        );
    }

    /// §4.3 step 3: the W binding guard fails closed when the canonical
    /// account binding no longer maps to the C1 person (a same-token swap).
    #[tokio::test]
    async fn binding_guard_rejects_a_person_swap() {
        let db = world().await;
        let dir = tempfile::tempdir().unwrap();
        let reg = registry(dir.path()).await;
        let inputs = inputs(fixtures::ACCT_A, "2026-01-01T00:00:00Z");
        // The C1 person matches the canonical ACCT_A binding: the cut proceeds.
        let intact = reg
            .request_tracked(
                &db,
                &inputs,
                CredentialVerdict::Ready,
                None,
                None,
                "route-test",
                &consumer(),
                Some(&AccountBindingGuard {
                    person_record_id: PERSON_A.to_owned(),
                    account_token: fixtures::ACCT_A.to_owned(),
                }),
            )
            .await
            .unwrap();
        assert!(matches!(intact, RequestCut::Produced { .. }), "{intact:?}");
        // Same account token, different person: fail closed.
        let swapped = reg
            .request_tracked(
                &db,
                &inputs,
                CredentialVerdict::Ready,
                None,
                None,
                "route-test",
                &consumer(),
                Some(&AccountBindingGuard {
                    person_record_id: PERSON_B.to_owned(),
                    account_token: fixtures::ACCT_A.to_owned(),
                }),
            )
            .await
            .unwrap();
        assert!(matches!(swapped, RequestCut::BindingChanged), "{swapped:?}");
    }

    /// Cached reuse must report the pinned file's byte identity, not fresh
    /// staging bytes. Same logical rows in different physical order share
    /// `content_digest` (ORDER BY PK) but encode different SQLite bytes
    /// (`copy_table` has no ORDER BY). Never mutates the published file.
    #[tokio::test]
    async fn reused_generation_reports_pinned_byte_identity() {
        let db = world().await;
        let dir = tempfile::tempdir().unwrap();
        let reg = registry(dir.path()).await;
        let inputs = inputs(fixtures::ACCT_A, "2026-01-01T00:00:00Z");
        let scope_ref = reg.scope_ref(&inputs);
        let first = reg
            .request(&db, &inputs, CredentialVerdict::Ready, None, None)
            .await
            .unwrap();
        let (gid, ordinal) = published(&first);
        assert_eq!(ordinal, 1);
        let gid = gid.to_owned();
        let first_digest = match &first {
            RequestAnswer::Replace { content_digest, .. } => content_digest.clone(),
            other => panic!("expected replace, got {other:?}"),
        };
        let handle = reg
            .begin_download(&db, fixtures::ACCT_A, &scope_ref, &gid, "route-test")
            .await
            .unwrap();
        let pinned = std::fs::read(handle.file_path()).unwrap();
        let pinned_sha = crate::standby_snapshot::sha256_bytes(&pinned);
        // Reorder physical SOURCE rows, preserving every logical value and
        // timestamp: move vocabularies rowids to reverse order. Digest sorts
        // by PK, so it cannot move; the staging insert order can.
        let ids: Vec<String> = sqlx::query_scalar("SELECT id FROM vocabularies ORDER BY rowid")
            .fetch_all(db.write_pool())
            .await
            .unwrap();
        assert!(ids.len() >= 2, "need 2+ vocabularies, got {ids:?}");
        for (i, id) in ids.iter().rev().enumerate() {
            sqlx::query("UPDATE vocabularies SET rowid = ? WHERE id = ?")
                .bind(1_000_000_i64 + i as i64)
                .bind(id)
                .execute(db.write_pool())
                .await
                .unwrap();
        }
        // Precondition: a fresh build sees the same digest but different bytes.
        let fresh_path = dir.path().join("fresh-probe.db");
        let fresh = crate::member_copy_producer::build_member_copy(
            &db,
            crate::member_copy_producer::MemberCopyRequest {
                member_account: fixtures::ACCT_A.to_owned(),
                scope_ref: scope_ref.clone(),
                hosted_route_database_id: "route-test".to_owned(),
                ordinal: 1,
                consumer: consumer(),
                out_path: fresh_path.clone(),
            },
        )
        .await
        .unwrap();
        assert_eq!(fresh.content_digest, first_digest);
        let fresh_bytes = std::fs::read(&fresh_path).unwrap();
        assert_ne!(
            crate::standby_snapshot::sha256_bytes(&fresh_bytes),
            pinned_sha,
            "fixture must flip physical bytes while digest stays put"
        );
        // The cached request reuses the generation but must name pinned bytes.
        let second = reg
            .request(
                &db,
                &inputs,
                CredentialVerdict::Ready,
                Some(&gid),
                Some(&scope_ref),
            )
            .await
            .unwrap();
        match second {
            RequestAnswer::Current {
                generation_id,
                ordinal,
                content_digest,
                manifest,
                ..
            } => {
                assert_eq!(generation_id, gid);
                assert_eq!(ordinal, 1);
                assert_eq!(content_digest, first_digest);
                assert_eq!(manifest.bytes.sha256, pinned_sha);
                assert_eq!(manifest.bytes.size_bytes, pinned.len() as u64);
                let conn = RusqliteConnection::open(handle.file_path()).unwrap();
                assert_eq!(
                    crate::member_digest::content_digest(&conn).unwrap(),
                    content_digest
                );
            }
            other => panic!("expected current reuse, got {other:?}"),
        }
    }

    /// B3: the request path's future must be `Send` for the multi-thread
    /// HTTP transport. The producer once held `&rusqlite::Connection`
    /// (`!Sync`) across a `sqlx` await, which made this future `!Send`;
    /// current-thread `#[tokio::test]` never required `Send`, so it went
    /// unnoticed until the axum handlers were compiled. This is a
    /// compile-time regression guard: it fails to build if that returns.
    #[tokio::test]
    async fn request_path_future_is_send() {
        let db = world().await;
        let dir = tempfile::tempdir().unwrap();
        let reg = registry(dir.path()).await;
        let inputs = inputs(fixtures::ACCT_A, "2026-01-01T00:00:00Z");
        fn assert_send<T: Send>(_: &T) {}
        let future = reg.request(&db, &inputs, CredentialVerdict::Ready, None, None);
        assert_send(&future);
        let _ = future.await.unwrap();
    }

    /// B3 compat policy: a pre-B3 version-1 store (no route-bound columns)
    /// is explicitly refused at open, so its unbound leases/generations can
    /// never serve the new HTTP transport. No backfill exists: the route is
    /// not recoverable from v1 rows and request-installed fields are
    /// untrusted.
    #[tokio::test]
    async fn pre_b3_v1_store_is_refused_at_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry.db");
        let conn = RusqliteConnection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE member_copy_registry_meta (singleton INTEGER PRIMARY KEY, schema_version INTEGER NOT NULL);
             INSERT INTO member_copy_registry_meta VALUES (1, 1);
             CREATE TABLE member_copy_generations (generation_id TEXT PRIMARY KEY, scope_ref TEXT NOT NULL,
               origin_database_id TEXT NOT NULL, content_digest TEXT NOT NULL, ordinal INTEGER NOT NULL,
               file_path TEXT NOT NULL, authorization_revision INTEGER NOT NULL,
               authorization_grant_revision INTEGER NOT NULL, units_state_digest TEXT NOT NULL,
               discarded INTEGER NOT NULL DEFAULT 0, published_at TEXT NOT NULL);
             INSERT INTO member_copy_generations VALUES ('g-old', 's-old', 'o-old', 'd-old', 1,
               '/nonexistent.db', 0, 0, 'u', 0, 't');
             CREATE TABLE member_copy_leases (handle TEXT PRIMARY KEY, member_account TEXT NOT NULL,
               scope_ref TEXT NOT NULL, generation_id TEXT NOT NULL, content_digest TEXT NOT NULL,
               authorization_revision INTEGER NOT NULL, authorization_grant_revision INTEGER NOT NULL,
               units_state_digest TEXT NOT NULL, eligibility_fingerprint TEXT NOT NULL,
               expires_at_ms INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
             INSERT INTO member_copy_leases VALUES ('h-old', 'acct-old', 's-old', 'g-old', 'd-old',
               0, 0, 'u', 'f', 9999999999999, 0);",
        )
        .unwrap();
        drop(conn);
        let reopened = MemberCopyRegistry::open(RegistryConfig {
            store_dir: dir.path().to_path_buf(),
            scope_ref_key: ScopeRefKey::new([7u8; 32]),
            lease_ttl: Duration::from_secs(3600),
            hosted_route_database_id: "route-test".to_owned(),
            consumer: consumer(),
        })
        .await;
        match reopened {
            Err(error) => assert!(
                error.to_string().contains("version 1"),
                "a pre-B3 v1 store must be refused for its version, got {error}"
            ),
            Ok(_) => panic!("a pre-B3 v1 store must be refused at open"),
        }
    }

    /// B3: the route is bound on the lease at mint and constrained at
    /// lookup. The bound lookup yields nothing for a wrong route or a
    /// foreign account — without exposing the stored binding.
    #[tokio::test]
    async fn route_binding_is_enforced_at_mint_and_lookup() {
        let db = world().await;
        let dir = tempfile::tempdir().unwrap();
        let reg = registry(dir.path()).await;
        let inputs = inputs(fixtures::ACCT_A, "2026-01-01T00:00:00Z");
        let scope_ref = reg.scope_ref(&inputs);
        let first = reg
            .request(&db, &inputs, CredentialVerdict::Ready, None, None)
            .await
            .unwrap();
        let (gid, _) = published(&first);
        let gid = gid.to_owned();
        let handle = reg
            .begin_download(&db, fixtures::ACCT_A, &scope_ref, &gid, "route-test")
            .await
            .unwrap();
        assert!(reg
            .lease_binding_for(&handle.handle, fixtures::ACCT_A, &scope_ref, "route-other")
            .await
            .unwrap()
            .is_none());
        assert!(reg
            .lease_binding_for(&handle.handle, fixtures::ACCT_B, &scope_ref, "route-test")
            .await
            .unwrap()
            .is_none());
        let binding = reg
            .lease_binding_for(&handle.handle, fixtures::ACCT_A, &scope_ref, "route-test")
            .await
            .unwrap()
            .expect("exact account/scope/route must yield the binding");
        assert_eq!(binding.hosted_route_database_id, "route-test");
    }

    /// B3 alias acceptance: generation identity excludes route, so a cached
    /// generation built through route A is reused by a fresh request
    /// through authorized route B (same origin ⇒ same scope). The A-bound
    /// handle must be denied on B, but a newly minted B-bound handle for
    /// the same generation must remain usable. Lease-only route binding
    /// (no route on the generation row) is what makes both true at once.
    #[tokio::test]
    async fn same_origin_alias_reuses_generation_with_per_route_handles() {
        let db = world().await;
        let dir = tempfile::tempdir().unwrap();
        let reg = registry(dir.path()).await;
        let inputs = inputs(fixtures::ACCT_A, "2026-01-01T00:00:00Z");
        let scope_ref = reg.scope_ref(&inputs);
        let first = reg
            .request_for_route(
                &db,
                &inputs,
                CredentialVerdict::Ready,
                None,
                None,
                "route-a",
            )
            .await
            .unwrap();
        let (gid_a, _) = published(&first);
        let gid_a = gid_a.to_owned();
        // Same origin and member through the alias route: identical scope,
        // so the cached generation is reused, not republished.
        let second = reg
            .request_for_route(
                &db,
                &inputs,
                CredentialVerdict::Ready,
                None,
                None,
                "route-b",
            )
            .await
            .unwrap();
        let (gid_b, _) = published(&second);
        assert_eq!(gid_b, gid_a, "alias route must reuse the cached generation");
        // The A-bound handle is denied on B without exposing its binding.
        let handle_a = reg
            .begin_download(&db, fixtures::ACCT_A, &scope_ref, &gid_a, "route-a")
            .await
            .unwrap();
        assert!(reg
            .lease_binding_for(&handle_a.handle, fixtures::ACCT_A, &scope_ref, "route-b")
            .await
            .unwrap()
            .is_none());
        // A fresh B-bound handle for the same generation mints and verifies.
        let handle_b = reg
            .begin_download(&db, fixtures::ACCT_A, &scope_ref, &gid_a, "route-b")
            .await
            .unwrap();
        let binding_b = reg
            .lease_binding_for(&handle_b.handle, fixtures::ACCT_A, &scope_ref, "route-b")
            .await
            .unwrap()
            .expect("fresh alias handle must verify on its own route");
        assert_eq!(binding_b.hosted_route_database_id, "route-b");
        // The A handle still verifies on A: no cross-route destruction.
        assert!(reg
            .lease_binding_for(&handle_a.handle, fixtures::ACCT_A, &scope_ref, "route-a")
            .await
            .unwrap()
            .is_some());
    }
}
