//! Forward-only, offline schema-evolution machinery.
//!
//! Historical product schemas are supported only from a deliberately selected
//! release baseline. The runner remains independently testable through
//! synthetic registries as well as the qualified production path.

use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use futures::future::{BoxFuture, FutureExt};
use serde::Serialize;
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{Connection, Row, SqliteConnection};

use crate::db::{probe_database, DatabaseVersionState, CURRENT_ENGINE_SCHEMA_VERSION};
use crate::error::{Error, Result};
#[cfg(test)]
use crate::mcp::{AuthoritativeDisposition, ToolKind};

pub trait EngineMigrationStep: std::fmt::Debug + Send + Sync {
    fn from(&self) -> i64;
    fn to(&self) -> i64;
    fn name(&self) -> &str;
    /// Stable evidence identity for this runtime transition. Production steps
    /// must keep this value stable once a supported capability path cites it.
    fn stable_id(&self) -> &str {
        self.name()
    }
    fn requires_foreign_keys_disabled(&self) -> bool {
        false
    }
    /// Whether the runner must `VACUUM` this file in autocommit *before*
    /// opening the step's ordinary `BEGIN IMMEDIATE` apply transaction.
    ///
    /// SQLite refuses `VACUUM` inside a transaction. The compacting 52→53,
    /// 54→55, and 63→64 edges return true. The runner then
    /// keeps every ordinary contract: fenced apply, version stamp inside
    /// `BEGIN IMMEDIATE`, and `ROLLBACK` if a later fence or apply fails so
    /// `user_version` cannot advance in autocommit. Failure or kill leaves
    /// the file at `from()`. Ordinary current boots take no pending
    /// steps and never vacuum.
    fn requires_pre_apply_compaction(&self) -> bool {
        false
    }
    /// Inspect the migration source before any mutation.
    ///
    /// The runner hands EVERY pending step the same physically read-only
    /// connection over the ORIGINAL preimage, before the backup is taken —
    /// never the intermediate shape this step's `apply` will actually see on
    /// a multi-hop path. A step whose `from()` is above the path's start must
    /// therefore treat a lower `PRAGMA user_version` as "not mine to judge"
    /// and return `Ok(())`, validating its frozen source shape only when the
    /// preimage header equals its own `from()` (the earliest pending step is
    /// the one whose source assertions bind the preimage). Intermediate
    /// shapes are unvalidatable here by construction; drift in a step's
    /// inline DDL is caught by exact post-migration shape verification.
    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>>;
    fn apply<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EngineMigrationCapabilityEdge {
    pub from: i64,
    pub to: i64,
    pub stable_id: String,
}

/// A convenient concrete SQL transition. Migrations that need Rust shape
/// checks or backfills implement [`EngineMigrationStep`] directly.
#[derive(Debug, Clone)]
pub struct EngineMigration {
    pub from: i64,
    pub to: i64,
    pub name: String,
    /// Statements that must all execute successfully before the pre-image is
    /// captured or any migration writes occur.
    pub preflight: Vec<String>,
    pub apply: Vec<String>,
}

impl EngineMigrationStep for EngineMigration {
    fn from(&self) -> i64 {
        self.from
    }
    fn to(&self) -> i64 {
        self.to
    }
    fn name(&self) -> &str {
        &self.name
    }
    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            for statement in &self.preflight {
                sqlx::query(statement).execute(&mut *connection).await?;
            }
            Ok(())
        }
        .boxed()
    }
    fn apply<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            for statement in &self.apply {
                sqlx::query(statement).execute(&mut *connection).await?;
            }
            Ok(())
        }
        .boxed()
    }
}

#[derive(Debug, Clone)]
pub struct EngineMigrationRegistry {
    pub current: i64,
    /// Deliberately selected release baseline. `None` refuses every
    /// non-current schema even if transition implementations exist in source.
    pub supported_baseline: Option<i64>,
    pub minimum_supported: i64,
    migrations: Vec<Arc<dyn EngineMigrationStep>>,
}

impl EngineMigrationRegistry {
    pub fn new(
        current: i64,
        minimum_supported: i64,
        mut migrations: Vec<Arc<dyn EngineMigrationStep>>,
    ) -> Result<Self> {
        if minimum_supported > current {
            return Err(Error::engine(
                "minimum supported schema exceeds current schema",
            ));
        }
        migrations.sort_by_key(|migration| migration.from());
        let mut expected = minimum_supported;
        for migration in &migrations {
            if migration.from() != expected || migration.to() != expected + 1 {
                return Err(Error::engine(format!(
                    "engine migration registry gap or non-forward edge at {} -> {} (expected {} -> {})",
                    migration.from(),
                    migration.to(),
                    expected,
                    expected + 1
                )));
            }
            expected = migration.to();
        }
        if expected != current {
            return Err(Error::engine(format!(
                "engine migration registry ends at {expected}, current is {current}"
            )));
        }
        Ok(Self {
            current,
            supported_baseline: Some(minimum_supported),
            minimum_supported,
            migrations,
        })
    }

    /// The runtime registry contains only deliberately supported release edges.
    ///
    /// The production registry spans the deliberately supported historical
    /// window. Synthetic registries still exercise runner mechanics
    /// independently of product compatibility policy.
    pub fn production() -> Self {
        let minimum =
            crate::db::SUPPORTED_ENGINE_SCHEMA_BASELINE.unwrap_or(CURRENT_ENGINE_SCHEMA_VERSION);
        Self::new(
            CURRENT_ENGINE_SCHEMA_VERSION,
            minimum,
            production_migrations(),
        )
        .expect("the production engine registry spans its declared baseline")
    }
}

/// The deliberately supported release edges, in ascending order.
///
/// One entry per engine schema step from
/// [`crate::db::SUPPORTED_ENGINE_SCHEMA_BASELINE`] to
/// [`CURRENT_ENGINE_SCHEMA_VERSION`]. `EngineMigrationRegistry::new` refuses a
/// gap or a non-forward edge, so this list and the declared baseline cannot
/// drift apart.
fn production_migrations() -> Vec<Arc<dyn EngineMigrationStep>> {
    vec![
        Arc::new(Engine39To40Migration),
        Arc::new(Engine40To41Migration),
        Arc::new(Engine41To42Migration),
        Arc::new(Engine42To43Migration),
        Arc::new(Engine43To44Migration),
        Arc::new(Engine44To45Migration),
        Arc::new(Engine45To46Migration),
        Arc::new(Engine46To47Migration),
        Arc::new(Engine47To48Migration),
        Arc::new(Engine48To49Migration),
        Arc::new(Engine49To50Migration),
        Arc::new(Engine50To51Migration),
        Arc::new(Engine51To52Migration),
        Arc::new(Engine52To53Migration),
        Arc::new(Engine53To54Migration),
        Arc::new(Engine54To55Migration),
        Arc::new(Engine55To56Migration),
        Arc::new(Engine56To57Migration),
        Arc::new(Engine57To58Migration),
        Arc::new(Engine58To59Migration),
        Arc::new(Engine59To60Migration),
        Arc::new(Engine60To61Migration),
        Arc::new(Engine61To62Migration),
        Arc::new(Engine62To63Migration),
        Arc::new(Engine63To64Migration),
        Arc::new(Engine64To65Migration),
    ]
}

const DOGFOOD_RICHARD_ID: &str = "298117e0-23e4-4d1e-83e7-f0be6d21e9d5";
const DOGFOOD_NEILL_ID: &str = "d3764e5a-91b4-4ba1-b4cf-0d434a3bb5dd";
const DOGFOOD_DIRECT_PRINCIPALS: [&str; 2] = [
    "native/pMN6hF03c4lbUYdDlRBvkKwp",
    "native/pcChlW7O9X0Up5UoO-t0uEgp",
];

#[derive(Clone, Copy, Debug)]
enum DogfoodMessageOrigin {
    Collection,
    Direct { addressed_to: &'static str },
}

#[derive(Clone, Copy, Debug)]
struct DogfoodMessageOriginRepair {
    message_id: &'static str,
    owner_id: &'static str,
    origin: DogfoodMessageOrigin,
}

/// The complete, human-reviewed pre-explicit-origin cohort in Native HQ.
///
/// This is deliberately an identity-bound repair manifest rather than a
/// general inference rule. A database that does not contain one of these
/// canonical Message ids is unchanged by the product-data part of engine 48.
const DOGFOOD_MESSAGE_ORIGIN_REPAIRS: [DogfoodMessageOriginRepair; 13] = [
    DogfoodMessageOriginRepair {
        message_id: "577c60d4-c7e1-4128-94dc-00e312012882",
        owner_id: DOGFOOD_RICHARD_ID,
        origin: DogfoodMessageOrigin::Direct {
            addressed_to: DOGFOOD_NEILL_ID,
        },
    },
    DogfoodMessageOriginRepair {
        message_id: "e4bbbaf0-9f3d-4124-9658-4233b50107ad",
        owner_id: DOGFOOD_NEILL_ID,
        origin: DogfoodMessageOrigin::Direct {
            addressed_to: DOGFOOD_RICHARD_ID,
        },
    },
    DogfoodMessageOriginRepair {
        message_id: "9c292784-a4ea-4aaa-8e2c-52c54774a9ed",
        owner_id: DOGFOOD_NEILL_ID,
        origin: DogfoodMessageOrigin::Direct {
            addressed_to: DOGFOOD_RICHARD_ID,
        },
    },
    DogfoodMessageOriginRepair {
        message_id: "d224339e-da65-4227-b596-eb8daf3a7f2f",
        owner_id: DOGFOOD_NEILL_ID,
        origin: DogfoodMessageOrigin::Direct {
            addressed_to: DOGFOOD_RICHARD_ID,
        },
    },
    DogfoodMessageOriginRepair {
        message_id: "1ddbb03f-eb26-4f7f-935f-0894deb4a715",
        owner_id: DOGFOOD_RICHARD_ID,
        origin: DogfoodMessageOrigin::Collection,
    },
    DogfoodMessageOriginRepair {
        message_id: "e47e15f6-24be-4921-bbde-a278bb1bee04",
        owner_id: DOGFOOD_NEILL_ID,
        origin: DogfoodMessageOrigin::Collection,
    },
    DogfoodMessageOriginRepair {
        message_id: "0acf1c5c-b87d-4555-b766-7fb4eb91544f",
        owner_id: DOGFOOD_NEILL_ID,
        origin: DogfoodMessageOrigin::Collection,
    },
    DogfoodMessageOriginRepair {
        message_id: "6e7a18fe-ae32-486a-931c-1e00ab00ad30",
        owner_id: DOGFOOD_RICHARD_ID,
        origin: DogfoodMessageOrigin::Collection,
    },
    DogfoodMessageOriginRepair {
        message_id: "a56328ac-b36c-4fbb-8437-a802621eb386",
        owner_id: DOGFOOD_RICHARD_ID,
        origin: DogfoodMessageOrigin::Collection,
    },
    DogfoodMessageOriginRepair {
        message_id: "cb953321-1277-4d04-825e-19a9835ad4f2",
        owner_id: DOGFOOD_RICHARD_ID,
        origin: DogfoodMessageOrigin::Collection,
    },
    DogfoodMessageOriginRepair {
        message_id: "e2231667-f02e-49a1-99f3-86db614e139a",
        owner_id: DOGFOOD_RICHARD_ID,
        origin: DogfoodMessageOrigin::Collection,
    },
    DogfoodMessageOriginRepair {
        message_id: "bb0b32ce-afa2-4474-b32c-96057ac02b39",
        owner_id: DOGFOOD_RICHARD_ID,
        origin: DogfoodMessageOrigin::Collection,
    },
    DogfoodMessageOriginRepair {
        message_id: "a0f6e667-3303-4040-850d-fa03b6735e8a",
        owner_id: DOGFOOD_RICHARD_ID,
        origin: DogfoodMessageOrigin::Collection,
    },
];

#[cfg(feature = "turso-local")]
pub(crate) fn dogfood_message_origin_repair_ids() -> impl Iterator<Item = &'static str> {
    DOGFOOD_MESSAGE_ORIGIN_REPAIRS
        .iter()
        .map(|repair| repair.message_id)
}

#[derive(Debug)]
struct Engine39To40Migration;

impl EngineMigrationStep for Engine39To40Migration {
    fn from(&self) -> i64 {
        39
    }

    fn to(&self) -> i64 {
        40
    }

    fn name(&self) -> &str {
        "engine-39-to-40-provenance-action-attestation-channel"
    }

    fn requires_foreign_keys_disabled(&self) -> bool {
        true
    }

    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move { crate::db::validate_supported_engine_migration_source(connection, 39).await }
            .boxed()
    }

    fn apply<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            // Server-observed ingress transport, added by engine schema 40. The
            // column is placed beside `executor_kind` in frozen v40 DDL. SQLite
            // can only append with ADD COLUMN, which would produce a different
            // physical contract and fail exact post-migration verification, so
            // rebuild this one table while the runner has foreign keys fenced.
            // `unknown` is the honest absence of a historical observation.
            for statement in [
                "PRAGMA legacy_alter_table=ON",
                "ALTER TABLE provenance_action_attestations RENAME TO provenance_action_attestations_v39",
                r#"CREATE TABLE provenance_action_attestations (
                     id                      TEXT PRIMARY KEY,
                     schema_version          INTEGER NOT NULL CHECK (schema_version IN (1,2)),
                     principal               TEXT NOT NULL CHECK (length(trim(principal)) > 0),
                     executor_kind           TEXT NOT NULL CHECK (executor_kind IN ('human','agent','authenticated_principal','local')),
                     channel                 TEXT NOT NULL DEFAULT 'unknown' CHECK (channel IN ('web','mcp','local','unknown')),
                     executor_ref            TEXT,
                     delegation_ref          TEXT,
                     interaction_receipt_id  TEXT REFERENCES provenance_interaction_receipts(id),
                     operation               TEXT NOT NULL CHECK (length(trim(operation)) > 0),
                     action_commitment       TEXT NOT NULL CHECK (json_valid(action_commitment)),
                     action_digest           TEXT NOT NULL CHECK (length(action_digest) = 64),
                     output_event_set_digest TEXT NOT NULL CHECK (length(output_event_set_digest) = 64),
                     issuer                  TEXT NOT NULL CHECK (length(trim(issuer)) > 0),
                     issuer_origin_database_id TEXT NOT NULL CHECK (
                       length(issuer_origin_database_id) = 36
                       AND substr(issuer_origin_database_id, 1, 4) = 'ndb_'
                       AND substr(issuer_origin_database_id, 5) NOT GLOB '*[^0-9a-f]*'
                     ),
                     issued_at               TEXT NOT NULL,
                     command_identity_digest TEXT CHECK (command_identity_digest IS NULL OR length(command_identity_digest) = 64),
                     intent_digest           TEXT CHECK (intent_digest IS NULL OR length(intent_digest) = 64)
                   )"#,
                r#"INSERT INTO provenance_action_attestations
                     (id,schema_version,principal,executor_kind,channel,executor_ref,
                      delegation_ref,interaction_receipt_id,operation,action_commitment,
                      action_digest,output_event_set_digest,issuer,issuer_origin_database_id,
                      issued_at,command_identity_digest,intent_digest)
                   SELECT id,schema_version,principal,executor_kind,'unknown',executor_ref,
                          delegation_ref,interaction_receipt_id,operation,action_commitment,
                          action_digest,output_event_set_digest,issuer,issuer_origin_database_id,
                          issued_at,command_identity_digest,intent_digest
                     FROM provenance_action_attestations_v39"#,
                "DROP TABLE provenance_action_attestations_v39",
                r#"CREATE INDEX idx_provenance_action_principal
                     ON provenance_action_attestations(principal, issued_at, id)"#,
                r#"CREATE INDEX idx_provenance_action_command
                     ON provenance_action_attestations(principal, operation, command_identity_digest)
                     WHERE command_identity_digest IS NOT NULL"#,
                r#"CREATE TRIGGER provenance_action_attestations_no_update
                     BEFORE UPDATE ON provenance_action_attestations
                     BEGIN SELECT RAISE(ABORT, 'provenance_action_attestations is append-only'); END"#,
                r#"CREATE TRIGGER provenance_action_attestations_no_delete
                     BEFORE DELETE ON provenance_action_attestations
                     BEGIN SELECT RAISE(ABORT, 'provenance_action_attestations is append-only'); END"#,
                "PRAGMA legacy_alter_table=OFF",
            ] {
                sqlx::query(statement).execute(&mut *connection).await?;
            }
            Ok(())
        }
        .boxed()
    }
}

/// The for-purpose promotion-drill migration (design record `5c4ca2cd`,
/// spec `02f09af5`): a deliberately trivial, genuinely real schema move, so
/// that the promotion pipeline's riskiest path — snapshot → preflight →
/// migrate → verify — is exercised by a migration whose semantics are as
/// close to zero-risk as a schema change can be. Purely additive: no
/// existing table, index, trigger, or row is touched.
#[derive(Debug)]
struct Engine40To41Migration;

impl EngineMigrationStep for Engine40To41Migration {
    fn from(&self) -> i64 {
        40
    }

    fn to(&self) -> i64 {
        41
    }

    fn name(&self) -> &str {
        "engine-40-to-41-promotion-drill-table"
    }

    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            // Every step's preflight inspects the ORIGINAL preimage (the
            // runner's all-steps-before-backup contract), so on a multi-hop
            // path this step legitimately sees a pre-40 header. Each earlier
            // edge validates its own source shape; this one asserts the
            // frozen 40 shape only when 40 is what it was handed.
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await?;
            if version == 40 {
                crate::db::validate_supported_engine_migration_source(connection, 40).await?;
            }
            Ok(())
        }
        .boxed()
    }

    fn apply<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            for statement in [
                // Identical text to the frozen v41 DDL: the post-migration
                // verifier compares exact physical shape, so the created
                // table must not drift from a fresh v41 database's.
                r#"CREATE TABLE engine_migration_drills (
     id            TEXT PRIMARY KEY,
     migrated_at   TEXT NOT NULL,
     from_version  INTEGER NOT NULL,
     to_version    INTEGER NOT NULL,
     note          TEXT NOT NULL
   )"#,
                r#"CREATE TRIGGER engine_migration_drills_no_update BEFORE UPDATE ON engine_migration_drills
       BEGIN SELECT RAISE(ABORT, 'engine_migration_drills is append-only'); END"#,
                r#"CREATE TRIGGER engine_migration_drills_no_delete BEFORE DELETE ON engine_migration_drills
       BEGIN SELECT RAISE(ABORT, 'engine_migration_drills is append-only'); END"#,
                r#"INSERT INTO engine_migration_drills (id, migrated_at, from_version, to_version, note)
       VALUES (lower(hex(randomblob(16))), strftime('%Y-%m-%dT%H:%M:%fZ','now'), 40, 41,
               'for-purpose pipeline drill migration')"#,
            ] {
                sqlx::query(statement).execute(&mut *connection).await?;
            }
            Ok(())
        }
        .boxed()
    }
}

/// The manual-promotion verification edge (requested by Neill, 25 Aug):
/// a change confined to the for-purpose drill table so a human can review a
/// schema-moving PR, merge it when CI is quiet, and verify the promotion by
/// hand — `engine_info` reports schema 42, and the drill table carries a row
/// recording this migration with `drill_stage = 'manual-promotion-test'`.
/// The new column is appended, so ADD COLUMN matches the frozen v42 DDL's
/// physical shape exactly (unlike a mid-table column, which would force the
/// 39→40-style table rebuild).
#[derive(Debug)]
struct Engine41To42Migration;

impl EngineMigrationStep for Engine41To42Migration {
    fn from(&self) -> i64 {
        41
    }

    fn to(&self) -> i64 {
        42
    }

    fn name(&self) -> &str {
        "engine-41-to-42-manual-promotion-verification"
    }

    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            // All-steps-before-backup: on a multi-hop path this step sees the
            // ORIGINAL preimage, so assert the frozen 41 shape only when 41
            // is what it was handed.
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await?;
            if version == 41 {
                crate::db::validate_supported_engine_migration_source(connection, 41).await?;
            }
            Ok(())
        }
        .boxed()
    }

    fn apply<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            for statement in [
                "ALTER TABLE engine_migration_drills ADD COLUMN drill_stage TEXT",
                r#"INSERT INTO engine_migration_drills (id, migrated_at, from_version, to_version, note, drill_stage)
       VALUES (lower(hex(randomblob(16))), strftime('%Y-%m-%dT%H:%M:%fZ','now'), 41, 42,
               'for-purpose pipeline drill migration', 'manual-promotion-test')"#,
            ] {
                sqlx::query(statement).execute(&mut *connection).await?;
            }
            Ok(())
        }
        .boxed()
    }
}

/// The destination-lane edge (engine 43): the awareness tier gains a fifth
/// lane and its projection.
///
/// Unlike the two drill edges before it this one is not additive. The lane's
/// subject is a Collection rather than a Message, so `awareness_events` needed
/// a `destination_id` column *beside* `message_id`, `message_id` relaxed to
/// nullable, and paired table CHECKs binding each subject column to its lane.
/// SQLite can only append with ADD COLUMN and cannot add a table constraint at
/// all, while the post-migration verifier compares exact physical shape, so
/// this rebuilds the one table with foreign keys fenced — the same shape as the
/// 39-to-40 edge.
///
/// Every retained row is a Message-lane event and is copied with a NULL
/// `destination_id`, which is the honest statement that it was never about a
/// destination. Nothing is folded, invented, or dropped: `member_destinations`
/// is created empty, so a member's rail starts as the tier's usual meaningful
/// default — nothing on it — rather than as a guess derived from message
/// history.
#[derive(Debug)]
struct Engine42To43Migration;

impl EngineMigrationStep for Engine42To43Migration {
    fn from(&self) -> i64 {
        42
    }

    fn to(&self) -> i64 {
        43
    }

    fn name(&self) -> &str {
        "engine-42-to-43-awareness-destination-lane"
    }

    fn requires_foreign_keys_disabled(&self) -> bool {
        true
    }

    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            // All-steps-before-backup: on a multi-hop path this step sees the
            // ORIGINAL preimage, so assert the frozen 42 shape only when 42 is
            // what it was handed.
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await?;
            if version == 42 {
                crate::db::validate_supported_engine_migration_source(connection, 42).await?;
            }
            Ok(())
        }
        .boxed()
    }

    fn apply<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            for statement in [
                "PRAGMA legacy_alter_table=ON",
                "ALTER TABLE awareness_events RENAME TO awareness_events_v42",
                // Structurally identical to the frozen v43 DDL. Comments and
                // whitespace are normalized out of the shape contract, so only
                // columns, their order, types and constraints have to match —
                // and those must match exactly.
                r#"CREATE TABLE awareness_events (
     seq                    INTEGER PRIMARY KEY AUTOINCREMENT,
     id                     TEXT NOT NULL UNIQUE,
     idempotency_key        TEXT NOT NULL,
     intent_sha256          TEXT NOT NULL CHECK (length(intent_sha256) = 64),
     schema_version         INTEGER NOT NULL DEFAULT 1 CHECK (schema_version = 1),
     subject_account_id     TEXT NOT NULL CHECK (length(trim(subject_account_id)) > 0),
     message_id             TEXT CHECK (message_id IS NULL OR length(trim(message_id)) > 0),
     destination_id         TEXT CHECK (destination_id IS NULL OR length(trim(destination_id)) > 0),
     lane                   TEXT NOT NULL CHECK (lane IN ('human','agent','preference','routing','destination')),
     action                 TEXT NOT NULL CHECK (length(trim(action)) > 0),
     authenticated_actor    TEXT NOT NULL CHECK (length(trim(authenticated_actor)) > 0),
     executor_kind          TEXT NOT NULL CHECK (executor_kind IN ('human_attested','agent','system')),
     executor_ref           TEXT,
     delegation_ref         TEXT,
     expected_version       INTEGER NOT NULL CHECK (expected_version >= 0),
     reason_code            TEXT NOT NULL CHECK (length(trim(reason_code)) > 0),
     interaction_nonce      TEXT,
     payload                TEXT NOT NULL CHECK (json_valid(payload)),
     created_at             TEXT NOT NULL,
     UNIQUE (subject_account_id, idempotency_key),
     UNIQUE (subject_account_id, message_id, interaction_nonce),
     UNIQUE (subject_account_id, destination_id, interaction_nonce),
     CHECK ((lane = 'destination') = (destination_id IS NOT NULL)),
     CHECK ((lane = 'destination') = (message_id IS NULL))
   )"#,
                // `seq` is copied rather than regenerated: every projection in
                // this tier stores it as `last_event_seq`, and the Inbox's
                // `newer_available` compares against its maximum.
                r#"INSERT INTO awareness_events
                     (seq,id,idempotency_key,intent_sha256,schema_version,subject_account_id,
                      message_id,destination_id,lane,action,authenticated_actor,executor_kind,
                      executor_ref,delegation_ref,expected_version,reason_code,interaction_nonce,
                      payload,created_at)
                   SELECT seq,id,idempotency_key,intent_sha256,schema_version,subject_account_id,
                          message_id,NULL,lane,action,authenticated_actor,executor_kind,
                          executor_ref,delegation_ref,expected_version,reason_code,interaction_nonce,
                          payload,created_at
                     FROM awareness_events_v42"#,
                "DROP TABLE awareness_events_v42",
                r#"CREATE INDEX idx_awareness_events_subject_seq
       ON awareness_events(subject_account_id, seq)"#,
                r#"CREATE INDEX idx_awareness_events_message
       ON awareness_events(message_id, subject_account_id, seq)"#,
                r#"CREATE INDEX idx_awareness_events_destination
       ON awareness_events(destination_id, subject_account_id, seq)"#,
                r#"CREATE TRIGGER awareness_events_no_update BEFORE UPDATE ON awareness_events
       BEGIN SELECT RAISE(ABORT, 'awareness_events is append-only'); END"#,
                r#"CREATE TRIGGER awareness_events_no_delete BEFORE DELETE ON awareness_events
       BEGIN SELECT RAISE(ABORT, 'awareness_events is append-only'); END"#,
                r#"CREATE TABLE member_destinations (
     subject_account_id TEXT NOT NULL,
     collection_id      TEXT NOT NULL,
     present            INTEGER NOT NULL CHECK (present IN (0,1)),
     joined_at          TEXT,
     joined_by          TEXT NOT NULL CHECK (joined_by IN ('explicit','send')),
     last_event_seq     INTEGER NOT NULL REFERENCES awareness_events(seq),
     version            INTEGER NOT NULL CHECK (version > 0),
     PRIMARY KEY (subject_account_id, collection_id)
   )"#,
                r#"CREATE INDEX idx_member_destinations_subject
       ON member_destinations(subject_account_id, present, collection_id)"#,
                "PRAGMA legacy_alter_table=OFF",
            ] {
                sqlx::query(statement).execute(&mut *connection).await?;
            }
            Ok(())
        }
        .boxed()
    }
}

/// The explicit Message communication-origin edge (engine 44).
///
/// Existing Messages are represented honestly as origin-unknown. In
/// particular this migration does not reinterpret addressing, placement,
/// visibility policy or membership as authored direct/channel context.
#[derive(Debug)]
struct Engine43To44Migration;

impl EngineMigrationStep for Engine43To44Migration {
    fn from(&self) -> i64 {
        43
    }

    fn to(&self) -> i64 {
        44
    }

    fn name(&self) -> &str {
        "engine-43-to-44-explicit-message-origin"
    }

    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await?;
            if version == 43 {
                crate::db::validate_supported_engine_migration_source(connection, 43).await?;
            }
            Ok(())
        }
        .boxed()
    }

    fn apply<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            for statement in [
                r#"CREATE TABLE message_origin_state (
     message_id            TEXT PRIMARY KEY REFERENCES records(id) ON DELETE CASCADE,
     status                TEXT NOT NULL CHECK (status IN ('declared','legacy_unknown')),
     origin_type           TEXT CHECK (origin_type IN ('collection','direct')),
     collection_id         TEXT CHECK (collection_id IS NULL OR length(trim(collection_id)) > 0),
     direct_set_digest     TEXT CHECK (direct_set_digest IS NULL OR length(direct_set_digest) = 64),
     participant_count     INTEGER,
     declaration_event_seq INTEGER,
     updated_at            TEXT NOT NULL,
     CHECK ((status = 'legacy_unknown'
             AND origin_type IS NULL AND collection_id IS NULL
             AND direct_set_digest IS NULL AND participant_count IS NULL
             AND declaration_event_seq IS NULL)
         OR (status = 'declared' AND declaration_event_seq IS NOT NULL
             AND ((origin_type = 'collection' AND collection_id IS NOT NULL
                   AND direct_set_digest IS NULL AND participant_count = 0)
               OR (origin_type = 'direct' AND collection_id IS NULL
                   AND direct_set_digest IS NOT NULL AND participant_count > 0))))
   )"#,
                r#"CREATE INDEX idx_message_origin_collection
       ON message_origin_state(origin_type, collection_id, message_id)"#,
                r#"CREATE INDEX idx_message_origin_direct
       ON message_origin_state(origin_type, direct_set_digest, participant_count, message_id)"#,
                r#"CREATE TABLE message_origin_principals (
     message_id    TEXT NOT NULL REFERENCES message_origin_state(message_id) ON DELETE CASCADE,
     principal_id  TEXT NOT NULL CHECK (length(trim(principal_id)) > 0),
     event_seq     INTEGER NOT NULL,
     created_at    TEXT NOT NULL,
     PRIMARY KEY (message_id, principal_id)
   )"#,
                r#"CREATE INDEX idx_message_origin_principals_principal
       ON message_origin_principals(principal_id, message_id)"#,
                r#"INSERT INTO message_origin_state
                     (message_id,status,origin_type,collection_id,direct_set_digest,
                      participant_count,declaration_event_seq,updated_at)
                   SELECT id,'legacy_unknown',NULL,NULL,NULL,NULL,NULL,created_at
                     FROM records WHERE type='Message'"#,
            ] {
                sqlx::query(statement).execute(&mut *connection).await?;
            }
            Ok(())
        }
        .boxed()
    }
}

/// Durable workspace-local identity and explicit lifecycle for intentful runs.
/// Existing engine-44 databases start empty: disposable request capture is not
/// authoritative enough to backfill a run start or principal association.
#[derive(Debug)]
struct Engine44To45Migration;

impl EngineMigrationStep for Engine44To45Migration {
    fn from(&self) -> i64 {
        44
    }

    fn to(&self) -> i64 {
        45
    }

    fn name(&self) -> &str {
        "engine-44-to-45-durable-agent-runs"
    }

    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await?;
            if version == 44 {
                crate::db::validate_supported_engine_migration_source(connection, 44).await?;
            }
            Ok(())
        }
        .boxed()
    }

    fn apply<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            for statement in [
                r#"CREATE TABLE agent_runs (
     activity_id        TEXT PRIMARY KEY,
     run_key            TEXT NOT NULL UNIQUE CHECK (length(trim(run_key)) > 0),
     account_id         TEXT NOT NULL CHECK (length(trim(account_id)) > 0),
     started_at         TEXT NOT NULL,
     ended_at           TEXT,
     start_event_id     TEXT NOT NULL UNIQUE REFERENCES control_events(id),
     start_event_seq    INTEGER NOT NULL UNIQUE REFERENCES control_events(seq),
     close_event_id     TEXT UNIQUE REFERENCES control_events(id),
     close_event_seq    INTEGER UNIQUE REFERENCES control_events(seq),
     CHECK ((ended_at IS NULL AND close_event_id IS NULL AND close_event_seq IS NULL)
         OR (ended_at IS NOT NULL AND close_event_id IS NOT NULL AND close_event_seq IS NOT NULL))
   )"#,
                r#"CREATE INDEX idx_agent_runs_account_started
       ON agent_runs(account_id, started_at, activity_id)"#,
            ] {
                sqlx::query(statement).execute(&mut *connection).await?;
            }
            Ok(())
        }
        .boxed()
    }
}

/// The exact engine-45-to-46 statements: the single authoritative source for
/// this schema edge.
///
/// Both the reference SQLite runner (`Engine45To46Migration::apply` below) and
/// the Turso-local runner (`crate::turso_local::migrate_existing_engine_schema`)
/// execute this same sequence. Each runner keeps its own connection API,
/// transaction and pragma handling, error mapping, and fault behavior; only the
/// backend-neutral schema and data statements are shared. Whitespace and
/// comments are normalized out of the shape contract, so this canonical
/// spelling governs both backends.
pub(crate) const ENGINE_45_TO_46_STATEMENTS: [&str; 14] = [
    "ALTER TABLE content_events RENAME TO content_events_v45",
    r#"CREATE TABLE content_events (
     seq                     INTEGER PRIMARY KEY AUTOINCREMENT,
     id                      TEXT NOT NULL UNIQUE,
     record_id               TEXT NOT NULL,
     type                    TEXT NOT NULL,
     payload                 TEXT,
     actor                   TEXT,
     run_key                 TEXT,
     parent_key              TEXT,
     intent                  TEXT,
     causal_envelope_version INTEGER NOT NULL CHECK (causal_envelope_version = 1),
     causal_status           TEXT NOT NULL CHECK (causal_status IN ('complete','import_incomplete','legacy_unknown')),
     created_at              TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
   )"#,
    r#"INSERT INTO content_events
                     (seq,id,record_id,type,payload,actor,run_key,parent_key,intent,
                      causal_envelope_version,causal_status,created_at)
                   SELECT seq,id,record_id,type,payload,actor,run_key,parent_key,intent,
                          1,'legacy_unknown',created_at
                     FROM content_events_v45"#,
    "DROP TABLE content_events_v45",
    r#"CREATE INDEX idx_content_events_record ON content_events(record_id, seq)"#,
    r#"CREATE INDEX idx_content_events_run ON content_events(run_key, seq)"#,
    // The v2 Message carrier adds causal metadata to the signed
    // source-event envelope. Widen the closed version check while
    // preserving every v1 provenance row byte-for-byte.
    "ALTER TABLE replicated_message_provenance RENAME TO replicated_message_provenance_v45",
    r#"CREATE TABLE replicated_message_provenance (
     source_event_id      TEXT PRIMARY KEY REFERENCES content_event_sources(event_id) ON DELETE CASCADE,
     content_version      TEXT NOT NULL CHECK (content_version IN ('native.message.v1','native.message.v2')),
     operation            TEXT NOT NULL CHECK (operation = 'message.created'),
     source_account_token TEXT NOT NULL CHECK (length(trim(source_account_token)) > 0),
     source_created_at    TEXT NOT NULL,
     canonical_payload    TEXT NOT NULL CHECK (json_valid(canonical_payload)),
     payload_digest       TEXT NOT NULL CHECK (length(payload_digest) = 64),
     envelope_id          TEXT,
     envelope_digest      TEXT,
     CHECK ((envelope_id IS NULL AND envelope_digest IS NULL)
         OR (envelope_id IS NOT NULL AND envelope_digest IS NOT NULL
             AND length(trim(envelope_id)) > 0 AND length(envelope_digest) = 64))
   )"#,
    r#"INSERT INTO replicated_message_provenance
                     (source_event_id,content_version,operation,source_account_token,
                      source_created_at,canonical_payload,payload_digest,envelope_id,envelope_digest)
                   SELECT source_event_id,content_version,operation,source_account_token,
                          source_created_at,canonical_payload,payload_digest,envelope_id,envelope_digest
                     FROM replicated_message_provenance_v45"#,
    "DROP TABLE replicated_message_provenance_v45",
    r#"CREATE TABLE content_event_causal_frontier (
     event_id        TEXT NOT NULL REFERENCES content_events(id) ON DELETE CASCADE,
     parent_event_id TEXT NOT NULL CHECK (length(trim(parent_event_id)) > 0),
     PRIMARY KEY (event_id, parent_event_id),
     CHECK (event_id <> parent_event_id)
   )"#,
    r#"CREATE INDEX idx_content_event_causal_frontier_parent
       ON content_event_causal_frontier(parent_event_id, event_id)"#,
    r#"CREATE TABLE content_event_causal_cutover (
     singleton             INTEGER PRIMARY KEY CHECK (singleton = 1),
     last_legacy_local_seq INTEGER NOT NULL CHECK (last_legacy_local_seq >= 0),
     cutover_at            TEXT NOT NULL,
     from_engine_schema    INTEGER
   )"#,
    r#"INSERT INTO content_event_causal_cutover
                     (singleton,last_legacy_local_seq,cutover_at,from_engine_schema)
                   SELECT 1,COALESCE(MAX(seq),0),strftime('%Y-%m-%dT%H:%M:%fZ','now'),45
                     FROM content_events"#,
];

/// The exact engine-46-to-47 statements: the single authoritative source for
/// this schema edge.
///
/// Both the reference SQLite runner (`Engine46To47Migration::apply` below) and
/// the Turso-local runner (`crate::turso_local::migrate_existing_engine_schema`)
/// execute this same sequence. Each runner keeps its own connection API,
/// transaction handling, error mapping, and fault behavior; only the statement
/// text is shared. No row or epoch value is changed by this edge.
pub(crate) const ENGINE_46_TO_47_STATEMENTS: [&str; 10] = [
    "DROP TRIGGER authorization_revision_records_update",
    r#"CREATE TRIGGER authorization_revision_records_update
       AFTER UPDATE OF owner_id, policy_anchor_id, deleted_at, type, kind ON records
       WHEN OLD.owner_id IS NOT NEW.owner_id
         OR OLD.policy_anchor_id IS NOT NEW.policy_anchor_id
         OR OLD.deleted_at IS NOT NEW.deleted_at
         OR OLD.type IS NOT NEW.type
         OR OLD.kind IS NOT NEW.kind
       BEGIN UPDATE authorization_revision SET epoch = epoch + 1 WHERE id = 1; END"#,
    "DROP TRIGGER authorization_revision_record_policies_update",
    r#"CREATE TRIGGER authorization_revision_record_policies_update AFTER UPDATE ON record_policies
       WHEN OLD.record_id IS NOT NEW.record_id
         OR OLD.created_at IS NOT NEW.created_at
       BEGIN UPDATE authorization_revision SET epoch = epoch + 1 WHERE id = 1; END"#,
    "DROP TRIGGER authorization_revision_policy_entries_update",
    r#"CREATE TRIGGER authorization_revision_policy_entries_update AFTER UPDATE ON policy_entries
       WHEN OLD.policy_anchor_id IS NOT NEW.policy_anchor_id
         OR OLD.subject_kind IS NOT NEW.subject_kind
         OR OLD.subject_id IS NOT NEW.subject_id
         OR OLD.effect IS NOT NEW.effect
         OR OLD.capability IS NOT NEW.capability
       BEGIN UPDATE authorization_revision SET epoch = epoch + 1 WHERE id = 1; END"#,
    "DROP TRIGGER authorization_revision_bindings_update",
    r#"CREATE TRIGGER authorization_revision_bindings_update AFTER UPDATE ON bindings
       WHEN (OLD.system = 'account' OR NEW.system = 'account')
        AND (OLD.record_id IS NOT NEW.record_id
          OR OLD.system IS NOT NEW.system
          OR OLD.identifier IS NOT NEW.identifier
          OR OLD.is_canonical IS NOT NEW.is_canonical
          OR OLD.url IS NOT NEW.url
          OR OLD.etag IS NOT NEW.etag
          OR OLD.last_seen_at IS NOT NEW.last_seen_at)
       BEGIN UPDATE authorization_revision SET epoch = epoch + 1 WHERE id = 1; END"#,
    "DROP TRIGGER authorization_revision_links_update",
    r#"CREATE TRIGGER authorization_revision_links_update AFTER UPDATE ON links
       WHEN (OLD.relationship = 'part_of' OR NEW.relationship = 'part_of')
        AND (OLD.id IS NOT NEW.id
          OR OLD.source_id IS NOT NEW.source_id
          OR OLD.target_id IS NOT NEW.target_id
          OR OLD.relationship IS NOT NEW.relationship
          OR OLD.note IS NOT NEW.note
          OR OLD.created_at IS NOT NEW.created_at)
       BEGIN UPDATE authorization_revision SET epoch = epoch + 1 WHERE id = 1; END"#,
];

/// Versioned causal envelopes for the authoritative content log.
///
/// Historical engine-45 events are classified honestly as `legacy_unknown`;
/// the migration neither infers ordering from their database-local `seq` nor
/// fabricates frontier edges. Required, non-defaulted envelope columns force
/// every post-cutover append through typed causal admission. Because SQLite
/// cannot add such columns without a default, the log is rebuilt while the
/// migration runner has foreign keys fenced. Original replay positions are
/// copied verbatim.
#[derive(Debug)]
struct Engine45To46Migration;

impl EngineMigrationStep for Engine45To46Migration {
    fn from(&self) -> i64 {
        45
    }

    fn to(&self) -> i64 {
        46
    }

    fn name(&self) -> &str {
        "engine-45-to-46-content-event-causal-frontiers"
    }

    fn requires_foreign_keys_disabled(&self) -> bool {
        true
    }

    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await?;
            if version == 45 {
                crate::db::validate_supported_engine_migration_source(connection, 45).await?;
            }
            Ok(())
        }
        .boxed()
    }

    fn apply<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            sqlx::query("PRAGMA legacy_alter_table=ON")
                .execute(&mut *connection)
                .await?;
            for statement in ENGINE_45_TO_46_STATEMENTS {
                sqlx::query(statement).execute(&mut *connection).await?;
            }
            sqlx::query("PRAGMA legacy_alter_table=OFF")
                .execute(&mut *connection)
                .await?;
            Ok(())
        }
        .boxed()
    }
}

/// Narrow every authorization-epoch UPDATE trigger to genuine value changes.
///
/// Engine 46 carries the intentionally broad trigger definitions. The frozen
/// DDL uses `IF NOT EXISTS`, so an explicit migration must replace the five
/// persisted definitions before exact current-shape validation can succeed.
/// No row or epoch value is changed by this edge.
#[derive(Debug)]
struct Engine46To47Migration;

impl EngineMigrationStep for Engine46To47Migration {
    fn from(&self) -> i64 {
        46
    }

    fn to(&self) -> i64 {
        47
    }

    fn name(&self) -> &str {
        "engine-46-to-47-value-changed-authorization-epoch"
    }

    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await?;
            if version == 46 {
                crate::db::validate_supported_engine_migration_source(connection, 46).await?;
            }
            Ok(())
        }
        .boxed()
    }

    fn apply<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            for statement in ENGINE_46_TO_47_STATEMENTS {
                sqlx::query(statement).execute(&mut *connection).await?;
            }
            Ok(())
        }
        .boxed()
    }
}

/// Apply the one reviewed Native HQ Message-origin repair manifest.
///
/// Engine 48 changes no physical tables. It appends ordinary canonical origin
/// events so the repaired projection remains rebuildable from the content log.
/// Every present manifest row is guarded by the exact owner, filing and
/// addressed-to evidence reviewed before release; unrelated databases are a
/// product-data no-op.
#[derive(Debug)]
struct Engine47To48Migration;

impl EngineMigrationStep for Engine47To48Migration {
    fn from(&self) -> i64 {
        47
    }

    fn to(&self) -> i64 {
        48
    }

    fn name(&self) -> &str {
        "engine-47-to-48-reviewed-dogfood-message-origins"
    }

    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await?;
            if version == 47 {
                crate::db::validate_supported_engine_migration_source(connection, 47).await?;
            }
            // Production preflights every pending edge against the original
            // read-only preimage. Message-origin projection tables exist from
            // engine 44 onward, so validate the repair manifest there even
            // when this edge will be reached through one or more earlier
            // transitions.
            if (44..=47).contains(&version) {
                for repair in DOGFOOD_MESSAGE_ORIGIN_REPAIRS {
                    planned_dogfood_message_origin_repair(connection, repair).await?;
                }
            }
            Ok(())
        }
        .boxed()
    }

    fn apply<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            for repair in DOGFOOD_MESSAGE_ORIGIN_REPAIRS {
                if let Some(origin) =
                    planned_dogfood_message_origin_repair(connection, repair).await?
                {
                    append_dogfood_message_origin_declaration(
                        connection,
                        repair.message_id,
                        origin,
                    )
                    .await?;
                }
            }
            Ok(())
        }
        .boxed()
    }
}

/// Native Canvas v1: the scene projection and batch ledger. Both tables are
/// folds of `canvas.batch.committed.v1` content events, so an existing
/// engine-48 database gains them empty and any canvas written afterwards is
/// rebuildable from its own content stream. DDL-additive, no data movement.
#[derive(Debug)]
struct Engine48To49Migration;

impl EngineMigrationStep for Engine48To49Migration {
    fn from(&self) -> i64 {
        48
    }

    fn to(&self) -> i64 {
        49
    }

    fn name(&self) -> &str {
        "engine-48-to-49-canvas-scene-projection"
    }

    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await?;
            if version == 48 {
                crate::db::validate_supported_engine_migration_source(connection, 48).await?;
            }
            Ok(())
        }
        .boxed()
    }

    fn apply<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            for statement in ENGINE_49_CANVAS_DDL {
                sqlx::query(statement).execute(&mut *connection).await?;
            }
            Ok(())
        }
        .boxed()
    }
}

/// The exact engine-49 canvas statements, shared with the DDL so the
/// post-migration shape verification compares identical text.
pub(crate) const ENGINE_49_CANVAS_DDL: [&str; 3] = [
    r#"CREATE TABLE canvas_objects (
     canvas_id     TEXT NOT NULL REFERENCES records(id),
     object_id     TEXT NOT NULL,
     kind          TEXT NOT NULL,
     x             REAL NOT NULL,
     y             REAL NOT NULL,
     w             REAL NOT NULL,
     h             REAL NOT NULL,
     z             TEXT NOT NULL,
     parent_id     TEXT,
     props         TEXT NOT NULL CHECK (json_valid(props)),
     deleted       INTEGER NOT NULL DEFAULT 0 CHECK (deleted IN (0,1)),
     geometry_seq  INTEGER NOT NULL CHECK (geometry_seq > 0),
     content_seq   INTEGER NOT NULL CHECK (content_seq > 0),
     created_seq   INTEGER NOT NULL CHECK (created_seq > 0),
     PRIMARY KEY (canvas_id, object_id)
   )"#,
    r#"CREATE INDEX canvas_objects_live ON canvas_objects(canvas_id, deleted, z)"#,
    r#"CREATE TABLE canvas_batches (
     canvas_id     TEXT NOT NULL REFERENCES records(id),
     batch_id      TEXT NOT NULL,
     actor         TEXT,
     event_id      TEXT NOT NULL UNIQUE REFERENCES content_events(id),
     event_seq     INTEGER NOT NULL UNIQUE CHECK (event_seq > 0),
     ops_sha256    TEXT NOT NULL CHECK (length(ops_sha256) = 64),
     origin_kind   TEXT NOT NULL,
     PRIMARY KEY (canvas_id, batch_id)
   )"#,
];

/// Inbound webhook storage and truthful delegated-service attribution. The
/// endpoint, credential and delivery tables are additive; the attestation
/// table is rebuilt because SQLite cannot widen CHECK constraints in place.
#[derive(Debug)]
struct Engine49To50Migration;

impl EngineMigrationStep for Engine49To50Migration {
    fn from(&self) -> i64 {
        49
    }

    fn to(&self) -> i64 {
        50
    }

    fn name(&self) -> &str {
        "engine-49-to-50-inbound-webhooks"
    }

    fn requires_foreign_keys_disabled(&self) -> bool {
        true
    }

    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            // Every pending edge preflights the original preimage before the
            // backup is taken. Earlier edges validate earlier source shapes.
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await?;
            if version == 49 {
                crate::db::validate_supported_engine_migration_source(connection, 49).await?;
            }
            Ok(())
        }
        .boxed()
    }

    fn apply<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            for statement in [
                "PRAGMA legacy_alter_table=ON",
                "ALTER TABLE provenance_action_attestations RENAME TO provenance_action_attestations_v49",
                crate::schema::ddl::PROVENANCE_ACTION_ATTESTATIONS_DDL,
                r#"INSERT INTO provenance_action_attestations
                     (id,schema_version,principal,executor_kind,channel,executor_ref,
                      delegation_ref,interaction_receipt_id,operation,action_commitment,
                      action_digest,output_event_set_digest,issuer,issuer_origin_database_id,
                      issued_at,command_identity_digest,intent_digest)
                   SELECT id,schema_version,principal,executor_kind,channel,executor_ref,
                          delegation_ref,interaction_receipt_id,operation,action_commitment,
                          action_digest,output_event_set_digest,issuer,issuer_origin_database_id,
                          issued_at,command_identity_digest,intent_digest
                     FROM provenance_action_attestations_v49"#,
                "DROP TABLE provenance_action_attestations_v49",
                r#"CREATE INDEX idx_provenance_action_principal
                     ON provenance_action_attestations(principal, issued_at, id)"#,
                r#"CREATE INDEX idx_provenance_action_command
                     ON provenance_action_attestations(principal, operation, command_identity_digest)
                     WHERE command_identity_digest IS NOT NULL"#,
                r#"CREATE TRIGGER provenance_action_attestations_no_update
                     BEFORE UPDATE ON provenance_action_attestations
                     BEGIN SELECT RAISE(ABORT, 'provenance_action_attestations is append-only'); END"#,
                r#"CREATE TRIGGER provenance_action_attestations_no_delete
                     BEFORE DELETE ON provenance_action_attestations
                     BEGIN SELECT RAISE(ABORT, 'provenance_action_attestations is append-only'); END"#,
                "PRAGMA legacy_alter_table=OFF",
            ] {
                sqlx::query(statement).execute(&mut *connection).await?;
            }
            for statement in crate::schema::ddl::ENGINE_50_WEBHOOK_DDL {
                sqlx::query(statement).execute(&mut *connection).await?;
            }
            Ok(())
        }
        .boxed()
    }
}

/// Read-log result annotations are additive, nullable operational evidence.
/// Existing raw call rows did not emit an annotation, so the migration must
/// retain them as NULL rather than attempting to infer a historical notice
/// from present-day overlap state.
#[derive(Debug)]
struct Engine50To51Migration;

impl EngineMigrationStep for Engine50To51Migration {
    fn from(&self) -> i64 {
        50
    }

    fn to(&self) -> i64 {
        51
    }

    fn name(&self) -> &str {
        "engine-50-to-51-read-log-result-annotations"
    }

    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await?;
            if version == 50 {
                crate::db::validate_supported_engine_migration_source(connection, 50).await?;
            }
            Ok(())
        }
        .boxed()
    }

    fn apply<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            // Appending is deliberate: it produces the exact same physical
            // table shape as fresh engine-51 DDL and leaves old calls NULL.
            sqlx::query(
                "ALTER TABLE read_log_calls ADD COLUMN result_annotation TEXT CHECK (result_annotation IS NULL OR json_valid(result_annotation))",
            )
            .execute(&mut *connection)
            .await?;
            sqlx::query(
                "CREATE INDEX idx_read_log_calls_overlap_annotation ON read_log_calls(actor, ended_at, seq) WHERE result_annotation IS NOT NULL",
            )
            .execute(&mut *connection)
            .await?;
            Ok(())
        }
        .boxed()
    }
}

/// Engine 52 rebuilds `read_log_touches` as a WITHOUT ROWID table, clustered
/// on its composite primary key. The rowid form stored the key twice (table
/// b-tree plus a `sqlite_autoindex` implementing the PK); the clustered form
/// eliminates the autoindex and aligns physical order with the canonical
/// interchange export's `ORDER BY <primary-key>`. No consumer references the
/// touches rowid and `last_insert_rowid()` reads `read_log_calls`, which this
/// edge does not touch. Every row — including `result_rank` — is copied.
/// Turso-local does not run this rebuild: turso_core 0.7.2 refuses CREATE
/// INDEX on WITHOUT ROWID, so it keeps the released rowid table.
pub(crate) const ENGINE_51_TO_52_STATEMENTS: [&str; 7] = [
    "PRAGMA legacy_alter_table=ON",
    "ALTER TABLE read_log_touches RENAME TO read_log_touches_v51",
    r#"CREATE TABLE read_log_touches (
     call_seq     INTEGER NOT NULL REFERENCES read_log_calls(seq) ON DELETE CASCADE,
     record_id    TEXT NOT NULL,
     interaction  TEXT NOT NULL CHECK (interaction IN ('surfaced','opened','mutated')),
     result_rank  INTEGER,
     PRIMARY KEY (call_seq, record_id, interaction)
   ) WITHOUT ROWID"#,
    // Sorted inserts build the clustered b-tree left-to-right at full page
    // fill instead of splitting pages at random PK positions; the logical
    // content is identical either way because the b-tree IS the primary key.
    r#"INSERT INTO read_log_touches
         (call_seq, record_id, interaction, result_rank)
       SELECT call_seq, record_id, interaction, result_rank
         FROM read_log_touches_v51
        ORDER BY call_seq, record_id, interaction"#,
    // The renamed table carries the old rowid-form index; dropping the table
    // drops that index and frees the name for the identical index on the
    // clustered table.
    "DROP TABLE read_log_touches_v51",
    r#"CREATE INDEX idx_read_log_touches_record ON read_log_touches(record_id, call_seq)"#,
    "PRAGMA legacy_alter_table=OFF",
];

#[derive(Debug)]
struct Engine51To52Migration;

impl EngineMigrationStep for Engine51To52Migration {
    fn from(&self) -> i64 {
        51
    }

    fn to(&self) -> i64 {
        52
    }

    fn name(&self) -> &str {
        "engine-51-to-52-read-log-touches-without-rowid"
    }

    fn requires_foreign_keys_disabled(&self) -> bool {
        // Same fence as the 39→40 and 49→50 table rebuilds: the copied table
        // REFERENCES `read_log_calls(seq)` and the rename must not rewrite
        // or enforce referencing clauses mid-rebuild.
        true
    }

    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await?;
            if version == 51 {
                crate::db::validate_supported_engine_migration_source(connection, 51).await?;
            }
            Ok(())
        }
        .boxed()
    }

    fn apply<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            // Shared SQLite rebuild statements. The runner checks
            // `pragma_foreign_key_check` before committing while foreign keys
            // are fenced off, so a source with dangling `call_seq` rows
            // refuses here rather than silently shipping them forward.
            // Turso-local does not apply this rebuild; it keeps the released
            // rowid table (turso_core 0.7.2 refuses CREATE INDEX on WITHOUT
            // ROWID).
            for statement in ENGINE_51_TO_52_STATEMENTS {
                sqlx::query(statement).execute(&mut *connection).await?;
            }
            Ok(())
        }
        .boxed()
    }
}

/// Engine 53 reclaims the pages the 51→52 rebuild freed. Copying rows into
/// the clustered b-tree inside one transaction leaves the displaced pages on
/// the freelist, so a migrated file keeps its previous allocated size — and
/// startup prefetch and staging volume checks read allocated bytes — until a
/// VACUUM. SQLite refuses VACUUM inside a transaction, so the runner runs
/// in-place VACUUM in autocommit via [`EngineMigrationStep::requires_pre_apply_compaction`]
/// *before* this step's ordinary `BEGIN IMMEDIATE` apply. `apply` itself is
/// a no-op: the version stamp stays inside that transaction so a lost fence
/// can `ROLLBACK` rather than leaving `user_version=53` in autocommit.
/// Failure or kill leaves the file stamped 52 (VACUUM's own journal/WAL
/// transaction recovers like any other write) so the edge simply runs again.
/// Ordinary serving never vacuums: current databases take no migration steps.
#[derive(Debug)]
struct Engine52To53Migration;

impl EngineMigrationStep for Engine52To53Migration {
    fn from(&self) -> i64 {
        52
    }

    fn to(&self) -> i64 {
        53
    }

    fn name(&self) -> &str {
        "engine-52-to-53-read-log-freelist-compaction"
    }

    fn requires_pre_apply_compaction(&self) -> bool {
        true
    }

    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await?;
            if version == 52 {
                crate::db::validate_supported_engine_migration_source(connection, 52).await?;
            }
            Ok(())
        }
        .boxed()
    }

    fn apply<'a>(&'a self, _connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move { Ok(()) }.boxed()
    }
}

/// Intern repeated historical record IDs without discarding any read-log row.
/// The dictionary is tenant-local and deliberately has no relation to current
/// records: arbitrary and dangling historical IDs retain their exact strings.
#[derive(Debug)]
struct Engine53To54Migration;

impl EngineMigrationStep for Engine53To54Migration {
    fn from(&self) -> i64 {
        53
    }
    fn to(&self) -> i64 {
        54
    }
    fn name(&self) -> &str {
        "engine-53-to-54-read-log-record-dictionary"
    }
    fn requires_foreign_keys_disabled(&self) -> bool {
        true
    }

    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await?;
            if version == 53 {
                crate::db::validate_supported_engine_migration_source(connection, 53).await?;
            }
            Ok(())
        }
        .boxed()
    }

    fn apply<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            sqlx::query("PRAGMA legacy_alter_table=ON").execute(&mut *connection).await?;
            let rebuilt: Result<()> = async {
                for statement in [
                    "ALTER TABLE read_log_touches RENAME TO read_log_touches_v53",
                    "CREATE TABLE read_log_record_ids (record_ref INTEGER PRIMARY KEY, record_id TEXT NOT NULL UNIQUE)",
                    // Ascending exact strings assign ascending references. Scanning
                    // the old clustered key below therefore inserts the new key
                    // in order without a second full-table sort by reference.
                    "INSERT INTO read_log_record_ids (record_id) SELECT DISTINCT record_id FROM read_log_touches_v53 ORDER BY record_id",
                    "CREATE TABLE read_log_touches (call_seq INTEGER NOT NULL REFERENCES read_log_calls(seq) ON DELETE CASCADE, record_ref INTEGER NOT NULL REFERENCES read_log_record_ids(record_ref), interaction TEXT NOT NULL CHECK (interaction IN ('surfaced','opened','mutated')), result_rank INTEGER, PRIMARY KEY (call_seq, record_ref, interaction)) WITHOUT ROWID",
                    "INSERT INTO read_log_touches (call_seq, record_ref, interaction, result_rank) SELECT t.call_seq, d.record_ref, t.interaction, t.result_rank FROM read_log_touches_v53 t JOIN read_log_record_ids d ON d.record_id=t.record_id ORDER BY t.call_seq, t.record_id, t.interaction",
                ] {
                    sqlx::query(statement).execute(&mut *connection).await?;
                }
                // Within the runner's fenced transaction, equal counts plus an
                // injective full-primary-key mapping prove equality in both
                // directions. BINARY UNIQUE dictionary strings preserve identity;
                // IS NOT compares nullable ranks without dropping NULL mismatches.
                // Indexed lookups avoid materializing two full EXCEPT results.
                let counts_match: i64 = sqlx::query_scalar(
                    "SELECT (SELECT COUNT(*) FROM read_log_touches_v53) = (SELECT COUNT(*) FROM read_log_touches)",
                ).fetch_one(&mut *connection).await?;
                let differs: i64 = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM read_log_touches_v53 o LEFT JOIN read_log_record_ids d ON d.record_id=o.record_id COLLATE BINARY LEFT JOIN read_log_touches n ON n.call_seq=o.call_seq AND n.record_ref=d.record_ref AND n.interaction=o.interaction WHERE n.call_seq IS NULL OR n.result_rank IS NOT o.result_rank)",
                ).fetch_one(&mut *connection).await?;
                if counts_match != 1 || differs != 0 {
                    return Err(Error::engine("read-log dictionary migration changed decoded touches"));
                }
                // The runner verifies foreign keys before committing this edge.
                // Dropping the renamed table frees its old secondary-index name.
                sqlx::query("DROP TABLE read_log_touches_v53").execute(&mut *connection).await?;
                sqlx::query("CREATE INDEX idx_read_log_touches_record ON read_log_touches(record_ref, call_seq)")
                    .execute(&mut *connection).await?;
                Ok(())
            }.await;
            let reset = sqlx::query("PRAGMA legacy_alter_table=OFF").execute(&mut *connection).await;
            rebuilt?;
            reset?;
            Ok(())
        }.boxed()
    }
}

/// Reclaim the old text-key pages after the transactional dictionary rebuild.
/// As with 52→53, an interrupted VACUUM leaves the prior version stamped and
/// retryable; the final version stamp remains in the runner's fenced transaction.
#[derive(Debug)]
struct Engine54To55Migration;

impl EngineMigrationStep for Engine54To55Migration {
    fn from(&self) -> i64 {
        54
    }
    fn to(&self) -> i64 {
        55
    }
    fn name(&self) -> &str {
        "engine-54-to-55-read-log-dictionary-compaction"
    }
    fn requires_pre_apply_compaction(&self) -> bool {
        true
    }

    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await?;
            if version == 54 {
                crate::db::validate_supported_engine_migration_source(connection, 54).await?;
            }
            Ok(())
        }
        .boxed()
    }

    fn apply<'a>(&'a self, _connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move { Ok(()) }.boxed()
    }
}

/// The exact engine-55-to-56 statements: the single authoritative source for
/// this schema edge.
///
/// Both the reference SQLite runner (`Engine55To56Migration::apply` below)
/// and the Turso-local runner
/// (`crate::turso_local::migrate_existing_engine_schema`) execute this same
/// sequence. Each runner keeps its own connection API, transaction and pragma
/// handling, error mapping, and fault behavior; only the backend-neutral
/// schema and data statements are shared.
///
/// Every `ALTER TABLE ... ADD COLUMN act` is metadata-only with a NULL
/// default, so existing rows are left unstamped (grouping unknown) and the
/// edge stays cheap on large files. The `act_cutover` seed records the
/// per-domain grouping-unknown frontier explicitly rather than fabricating
/// grouping for legacy rows.
pub(crate) const ENGINE_55_TO_56_STATEMENTS: [&str; 14] = [
    "ALTER TABLE content_events ADD COLUMN act INTEGER",
    "ALTER TABLE policy_events ADD COLUMN act INTEGER",
    "ALTER TABLE awareness_events ADD COLUMN act INTEGER",
    "ALTER TABLE notification_candidate_events ADD COLUMN act INTEGER",
    "ALTER TABLE binding_audit ADD COLUMN act INTEGER",
    "ALTER TABLE database_identity_audit ADD COLUMN act INTEGER",
    "ALTER TABLE meta_events ADD COLUMN act INTEGER",
    "ALTER TABLE control_events ADD COLUMN act INTEGER",
    "ALTER TABLE derivation_events ADD COLUMN act INTEGER",
    "ALTER TABLE relationship_events ADD COLUMN act INTEGER",
    r#"CREATE TABLE act_state (
     singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
     next_act  INTEGER NOT NULL CHECK (next_act >= 0)
    )"#,
    r#"INSERT INTO act_state (singleton, next_act) VALUES (1, 0)"#,
    r#"CREATE TABLE act_cutover (
     domain            TEXT PRIMARY KEY CHECK (domain IN ('content_events','policy_events','awareness_events','notification_candidate_events','binding_audit','database_identity_audit','meta_events','control_events','derivation_events','relationship_events')),
     last_legacy_seq   INTEGER NOT NULL CHECK (last_legacy_seq >= 0),
     cutover_at        TEXT NOT NULL,
     from_engine_schema INTEGER
    )"#,
    r#"INSERT INTO act_cutover (domain,last_legacy_seq,cutover_at,from_engine_schema)
       VALUES ('awareness_events',(SELECT COALESCE(MAX(seq),0) FROM awareness_events),strftime('%Y-%m-%dT%H:%M:%fZ','now'),55),
              ('binding_audit',(SELECT COALESCE(MAX(seq),0) FROM binding_audit),strftime('%Y-%m-%dT%H:%M:%fZ','now'),55),
              ('content_events',(SELECT COALESCE(MAX(seq),0) FROM content_events),strftime('%Y-%m-%dT%H:%M:%fZ','now'),55),
              ('control_events',(SELECT COALESCE(MAX(seq),0) FROM control_events),strftime('%Y-%m-%dT%H:%M:%fZ','now'),55),
              ('database_identity_audit',(SELECT COALESCE(MAX(seq),0) FROM database_identity_audit),strftime('%Y-%m-%dT%H:%M:%fZ','now'),55),
              ('derivation_events',(SELECT COALESCE(MAX(seq),0) FROM derivation_events),strftime('%Y-%m-%dT%H:%M:%fZ','now'),55),
              ('meta_events',(SELECT COALESCE(MAX(seq),0) FROM meta_events),strftime('%Y-%m-%dT%H:%M:%fZ','now'),55),
              ('notification_candidate_events',(SELECT COALESCE(MAX(seq),0) FROM notification_candidate_events),strftime('%Y-%m-%dT%H:%M:%fZ','now'),55),
              ('policy_events',(SELECT COALESCE(MAX(seq),0) FROM policy_events),strftime('%Y-%m-%dT%H:%M:%fZ','now'),55),
              ('relationship_events',(SELECT COALESCE(MAX(seq),0) FROM relationship_events),strftime('%Y-%m-%dT%H:%M:%fZ','now'),55)"#,
];

/// The exact engine-56-to-57 statements: the single authoritative source for
/// this schema edge.
///
/// The reference SQLite runner (`Engine56To57Migration::apply` below)
/// executes the frozen trigger text shared with fresh-schema DDL
/// (`crate::schema::ddl::CONTENT_EVENTS_APPEND_ONLY_TRIGGERS`), so migrated
/// databases are byte-identical to fresh ones. The Turso-local runner
/// deliberately does not execute this edge: its contract corpus requires
/// physical content-event mutation probes, so it advances the version stamp
/// without installing these triggers (see `migrate_existing_engine_schema`).
pub(crate) const ENGINE_56_TO_57_STATEMENTS: [&str; 2] =
    crate::schema::ddl::CONTENT_EVENTS_APPEND_ONLY_TRIGGERS;

/// Stamp every canonical event with a gapless per-workspace act number
/// (decision 4e152d5): nullable `act` columns on the ten sequenced logs plus
/// the `act_state` counter and the recorded `act_cutover`. Historical rows
/// keep NULL acts and stay grouping-unknown; the counter starts at zero so
/// the first post-cutover transaction allocates act 1.
#[derive(Debug)]
struct Engine55To56Migration;

impl EngineMigrationStep for Engine55To56Migration {
    fn from(&self) -> i64 {
        55
    }

    fn to(&self) -> i64 {
        56
    }

    fn name(&self) -> &str {
        "engine-55-to-56-act-number-stamping"
    }

    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await?;
            if version == 55 {
                crate::db::validate_supported_engine_migration_source(connection, 55).await?;
            }
            Ok(())
        }
        .boxed()
    }

    fn apply<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            for statement in ENGINE_55_TO_56_STATEMENTS {
                sqlx::query(statement).execute(&mut *connection).await?;
            }
            Ok(())
        }
        .boxed()
    }
}

/// The content-event append-only edge (engine 56 → 57).
///
/// SQLite `content_events` gains the same durable UPDATE/DELETE rejection
/// Postgres already enforces (`content_events_append_only`), spelled in this
/// repository's SQLite convention (`content_events_no_update` /
/// `content_events_no_delete`, `'content_events is append-only'`), matching
/// the existing `relationship_events`, `policy_events`, and
/// `provenance_action_attestations` triggers. Purely additive: no existing
/// table, index, or row is touched, and every production writer appends via
/// INSERT, so no legitimate rewrite path exists to preserve.
#[derive(Debug)]
struct Engine56To57Migration;

impl EngineMigrationStep for Engine56To57Migration {
    fn from(&self) -> i64 {
        56
    }

    fn to(&self) -> i64 {
        57
    }

    fn name(&self) -> &str {
        "engine-56-to-57-content-events-append-only"
    }

    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await?;
            if version == 56 {
                crate::db::validate_supported_engine_migration_source(connection, 56).await?;
            }
            Ok(())
        }
        .boxed()
    }

    fn apply<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            for statement in ENGINE_56_TO_57_STATEMENTS {
                sqlx::query(statement).execute(&mut *connection).await?;
            }
            Ok(())
        }
        .boxed()
    }
}

/// The exact engine-57-to-58 statements: the single authoritative source for
/// this schema edge.
///
/// Both the reference SQLite runner (`Engine57To58Migration::apply` below)
/// and the Turso-local runner
/// (`crate::turso_local::migrate_existing_engine_schema`) execute this same
/// sequence. Each runner keeps its own connection API, transaction and pragma
/// handling, error mapping, and fault behavior; only the backend-neutral
/// schema statements are shared.
///
/// Every `ALTER TABLE ... ADD COLUMN` is metadata-only with a NULL default,
/// so existing runs keep NULL reported identity (admitted before any client
/// could declare it) and the edge stays cheap on large files. The fresh-DDL
/// `agent_runs` definition carries the three columns last, so the appended
/// columns land in the identical physical position and migrated databases are
/// byte-identical to fresh ones under the shape contract.
pub(crate) const ENGINE_57_TO_58_STATEMENTS: [&str; 3] = [
    "ALTER TABLE agent_runs ADD COLUMN reported_mcp_client_name TEXT",
    "ALTER TABLE agent_runs ADD COLUMN reported_mcp_client_version TEXT",
    "ALTER TABLE agent_runs ADD COLUMN reported_model TEXT",
];

/// The reported-client-identity edge (engine 57 → 58).
///
/// Nullable column adds only: no row is rebuilt, no existing table, index, or
/// trigger is touched, and every production writer inserts with explicit
/// column lists, so no legitimate statement path needs preserving.
#[derive(Debug)]
struct Engine57To58Migration;

impl EngineMigrationStep for Engine57To58Migration {
    fn from(&self) -> i64 {
        57
    }

    fn to(&self) -> i64 {
        58
    }

    fn name(&self) -> &str {
        "engine-57-to-58-agent-run-client-identity"
    }

    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await?;
            if version == 57 {
                crate::db::validate_supported_engine_migration_source(connection, 57).await?;
            }
            Ok(())
        }
        .boxed()
    }

    fn apply<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            for statement in ENGINE_57_TO_58_STATEMENTS {
                sqlx::query(statement).execute(&mut *connection).await?;
            }
            Ok(())
        }
        .boxed()
    }
}

/// The exact engine-58-to-59 DDL: the single authoritative source for this
/// schema edge's structural change.
///
/// Both the reference SQLite runner (`Engine58To59Migration::apply` below)
/// and the Turso-local runner
/// (`crate::turso_local::migrate_existing_engine_schema`) execute this same
/// sequence. Each runner keeps its own connection API, transaction and pragma
/// handling, error mapping, and fault behavior; only the backend-neutral
/// schema statements are shared. The data backfill is a Rust loop over the
/// parser (see `backfill_record_mentions`), so it cannot be shared as SQL:
///
/// - SQLite applies DDL + backfill together, inside the runner's
///   `BEGIN IMMEDIATE` transaction.
/// - Turso-local applies DDL + its own `backfill_record_mentions` mirror
///   together, inside the same `BEGIN IMMEDIATE` transaction. Both backfills
///   share `record_body::BODY_CARRYING_EVENT_SQL` and the same scan/coercion
///   semantics, so a migrated database converges with the live fold and replay
///   on either backend.
///
/// The three statements must stay byte-identical to the corresponding
/// `crate::schema::DDL_STATEMENTS` entries; the 58→59 migration test asserts
/// that rather than assuming it.
pub(crate) const ENGINE_58_TO_59_STATEMENTS: [&str; 3] = [
    r#"CREATE TABLE record_mentions (
      source_id          TEXT NOT NULL REFERENCES records(id) ON DELETE CASCADE,
      occurrence_ix      INTEGER NOT NULL,
      source_event_seq   INTEGER NOT NULL REFERENCES content_events(seq),
      span_start         INTEGER NOT NULL CHECK (span_start >= 0),
      span_end           INTEGER NOT NULL CHECK (span_end > span_start),
      authored_reference TEXT NOT NULL CHECK (length(trim(authored_reference)) > 0),
      lookup_key         TEXT NOT NULL CHECK (length(trim(lookup_key)) > 0),
      form               TEXT NOT NULL CHECK (form IN ('url', 'wiki_hex', 'wiki_name', 'bare_hex')),
      parser_version     INTEGER NOT NULL CHECK (parser_version > 0),
      PRIMARY KEY (source_id, occurrence_ix)
    )"#,
    r#"CREATE INDEX idx_record_mentions_lookup
        ON record_mentions(lookup_key, source_id)"#,
    r#"CREATE INDEX idx_record_mentions_source
        ON record_mentions(source_id)"#,
];

/// The current-state body-mention projection edge (engine 58 → 59).
///
/// DDL-additive plus a backfill that converges with the live fold: the table
/// holds only occurrences from each live record's current body, stamped with
/// that body's provenance.
#[derive(Debug)]
struct Engine58To59Migration;

impl EngineMigrationStep for Engine58To59Migration {
    fn from(&self) -> i64 {
        58
    }

    fn to(&self) -> i64 {
        59
    }

    fn name(&self) -> &str {
        "engine-58-to-59-record-mentions-projection"
    }

    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await?;
            if version == 58 {
                crate::db::validate_supported_engine_migration_source(connection, 58).await?;
            }
            Ok(())
        }
        .boxed()
    }

    fn apply<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            for statement in ENGINE_58_TO_59_STATEMENTS {
                sqlx::query(statement).execute(&mut *connection).await?;
            }
            backfill_record_mentions(connection).await?;
            Ok(())
        }
        .boxed()
    }
}

/// Backfill `record_mentions` from live current bodies.
///
/// For each live (`deleted_at IS NULL`) record whose stored body is non-empty
/// text, scan the CURRENT body text and stamp every row with the latest
/// body-carrying event's sequence, not `MAX(seq)` overall: metadata-only
/// updates and deletions carry higher sequences but no body, and stamping
/// those would diverge from the live fold, which keeps the body's own event
/// sequence. The event set is exactly the projector's four body writers
/// (`crate::record_body::BODY_CARRYING_EVENT_SQL`) — `record.created`,
/// `record.updated`, `receipt.committed.v1` through `$.body`, and
/// `unit.revision.recorded.v1` through `$.content.content`. Tombstoned,
/// removed (null/empty body) and never-written sources yield no rows — the
/// same replacement semantics as the live fold, so backfill, live folding and
/// replay converge.
///
/// A live non-empty body with no body-carrying event (only possible when the
/// row was written outside the projector, never through an append) is left
/// without rows rather than stamped with an invented sequence; the next
/// body-carrying write folds it. Skipping also preserves rebuild equality
/// there, since a replay over the same log produces no rows either.
///
/// `typeof(body)='text'` excludes non-text storage classes the scanner cannot
/// read; a stored body is already the canonical text the projector coerced,
/// so the live fold scans the same bytes.
pub(crate) async fn backfill_record_mentions(connection: &mut SqliteConnection) -> Result<()> {
    let sources: Vec<(String, String)> = sqlx::query_as(
        "SELECT id, body FROM records
          WHERE deleted_at IS NULL AND typeof(body) = 'text' AND body <> ''
          ORDER BY id",
    )
    .fetch_all(&mut *connection)
    .await?;
    let provenance_sql = format!(
        "SELECT MAX(seq) FROM content_events
          WHERE record_id = ? AND ({})",
        crate::record_body::BODY_CARRYING_EVENT_SQL
    );
    for (source_id, body) in sources {
        let source_event_seq: Option<i64> = sqlx::query_scalar(&provenance_sql)
            .bind(&source_id)
            .fetch_one(&mut *connection)
            .await?;
        let Some(source_event_seq) = source_event_seq else {
            continue;
        };
        sqlx::query("DELETE FROM record_mentions WHERE source_id = ?")
            .bind(&source_id)
            .execute(&mut *connection)
            .await?;
        for (occurrence_ix, occurrence) in crate::mentions::scan_body(&body).iter().enumerate() {
            sqlx::query(
                "INSERT INTO record_mentions
                   (source_id, occurrence_ix, source_event_seq, span_start, span_end,
                    authored_reference, lookup_key, form, parser_version)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&source_id)
            .bind(occurrence_ix as i64)
            .bind(source_event_seq)
            .bind(occurrence.span_start as i64)
            .bind(occurrence.span_end as i64)
            .bind(&occurrence.authored_reference)
            .bind(&occurrence.lookup_key)
            .bind(occurrence.form.as_str())
            .bind(crate::mentions::MENTION_PARSER_VERSION)
            .execute(&mut *connection)
            .await?;
        }
    }
    Ok(())
}

/// Add workspace-act membership to provenance validity changes. Historical
/// rows remain NULL because their transaction grouping is unknown.
pub(crate) const ENGINE_59_TO_60_STATEMENTS: [&str; 2] = [
    "ALTER TABLE provenance_attestation_validity_events ADD COLUMN act INTEGER",
    "CREATE INDEX idx_provenance_validity_act ON provenance_attestation_validity_events(act) WHERE act IS NOT NULL",
];
#[derive(Debug)]
struct Engine59To60Migration;

impl EngineMigrationStep for Engine59To60Migration {
    fn from(&self) -> i64 {
        59
    }
    fn to(&self) -> i64 {
        60
    }
    fn name(&self) -> &str {
        "engine-59-to-60-provenance-validity-act-stamping"
    }

    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await?;
            if version == 59 {
                crate::db::validate_supported_engine_migration_source(connection, 59).await?;
            }
            Ok(())
        }
        .boxed()
    }

    fn apply<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            for statement in ENGINE_59_TO_60_STATEMENTS {
                sqlx::query(statement).execute(&mut *connection).await?;
            }
            Ok(())
        }
        .boxed()
    }
}

/// Add partial act-range indexes to the ten sequenced canonical logs and
/// freeze the unwatermarked binding-system registry.
pub(crate) const ENGINE_60_TO_61_STATEMENTS: [&str; 13] = [
    "CREATE INDEX idx_content_events_act ON content_events(act) WHERE act IS NOT NULL",
    "CREATE INDEX idx_policy_events_act ON policy_events(act) WHERE act IS NOT NULL",
    "CREATE INDEX idx_awareness_events_act ON awareness_events(act) WHERE act IS NOT NULL",
    "CREATE INDEX idx_notification_candidate_events_act ON notification_candidate_events(act) WHERE act IS NOT NULL",
    "CREATE INDEX idx_binding_audit_act ON binding_audit(act) WHERE act IS NOT NULL",
    "CREATE INDEX idx_database_identity_audit_act ON database_identity_audit(act) WHERE act IS NOT NULL",
    "CREATE INDEX idx_meta_events_act ON meta_events(act) WHERE act IS NOT NULL",
    "CREATE INDEX idx_control_events_act ON control_events(act) WHERE act IS NOT NULL",
    "CREATE INDEX idx_derivation_events_act ON derivation_events(act) WHERE act IS NOT NULL",
    "CREATE INDEX idx_relationship_events_act ON relationship_events(act) WHERE act IS NOT NULL",
    "CREATE TRIGGER binding_systems_no_insert BEFORE INSERT ON binding_systems BEGIN SELECT RAISE(ABORT, 'binding_systems is immutable'); END",
    "CREATE TRIGGER binding_systems_no_update BEFORE UPDATE ON binding_systems BEGIN SELECT RAISE(ABORT, 'binding_systems is immutable'); END",
    "CREATE TRIGGER binding_systems_no_delete BEFORE DELETE ON binding_systems BEGIN SELECT RAISE(ABORT, 'binding_systems is immutable'); END",
];

#[derive(Debug)]
struct Engine60To61Migration;

impl EngineMigrationStep for Engine60To61Migration {
    fn from(&self) -> i64 {
        60
    }
    fn to(&self) -> i64 {
        61
    }
    fn name(&self) -> &str {
        "engine-60-to-61-canonical-act-range-indexes"
    }

    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await?;
            if version == 60 {
                crate::db::validate_supported_engine_migration_source(connection, 60).await?;
            }
            Ok(())
        }
        .boxed()
    }

    fn apply<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            for statement in ENGINE_60_TO_61_STATEMENTS {
                sqlx::query(statement).execute(&mut *connection).await?;
            }
            Ok(())
        }
        .boxed()
    }
}

/// Stamp workspace acts on external observations and awareness command
/// intents. Historical rows remain NULL because their grouping is unknown.
pub(crate) const ENGINE_61_TO_62_STATEMENTS: [&str; 4] = [
    "ALTER TABLE external_observations ADD COLUMN act INTEGER",
    "CREATE INDEX idx_external_observations_act ON external_observations(act) WHERE act IS NOT NULL",
    "ALTER TABLE awareness_command_intents ADD COLUMN act INTEGER",
    "CREATE INDEX idx_awareness_command_intents_act ON awareness_command_intents(act) WHERE act IS NOT NULL",
];

#[derive(Debug)]
struct Engine61To62Migration;

impl EngineMigrationStep for Engine61To62Migration {
    fn from(&self) -> i64 {
        61
    }
    fn to(&self) -> i64 {
        62
    }
    fn name(&self) -> &str {
        "engine-61-to-62-observation-intent-act-stamping"
    }

    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await?;
            if version == 61 {
                crate::db::validate_supported_engine_migration_source(connection, 61).await?;
            }
            Ok(())
        }
        .boxed()
    }

    fn apply<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            for statement in ENGINE_61_TO_62_STATEMENTS {
                sqlx::query(statement).execute(&mut *connection).await?;
            }
            Ok(())
        }
        .boxed()
    }
}

/// The selective read-log cleanup edge (engine 62 → 63, task 8a6377f PR B).
///
/// Data-only: no schema object moves (62 and 63 share one structural shape),
/// so there is no `requires_foreign_keys_disabled` rebuild and no
/// `requires_pre_apply_compaction` VACUUM hop. Foreign keys stay enforced so
/// deleting a disposable call cascades to its touches, and any dangling
/// reference would fail the edge closed inside the runner's transaction.
///
/// The row predicate mirrors PR A's live-capture retention predicate
/// (`crate::mcp::interactions::should_retain_capture`, task 8a6377f PR A)
/// for the reviewed engine-59 corpus, with frozen tool sets below. The
/// equality test detects later drift from PR A without changing historical
/// replay; tools added after that freeze remain retained pending audit:
///
/// * run issuance (`bootstrap`, plus read/mixed-read calls carrying a
///   `"new"` / `"new:<agent>"` run-key selector) keeps its call row but
///   loses its attention touches, and its arguments shrink to the run-key
///   selector alone — the same row/touch split PR A writes for new traffic.
///   Rows whose `arguments` are not valid JSON are retained byte-identical
///   (never normalized, never deleted): malformed history fails closed;
/// * annotation-bearing rows, rows with `mutated` touches, successful
///   `set_intent` declarations, failed declaration attempts, every
///   `Mutation`-disposition call, and mixed-tool write/unknown/malformed
///   actions are kept with verbatim arguments, ordering, and touches
///   (fail-closed: unknown tool names are never disposable);
/// * only known-observational calls are deleted: `Read`-disposition tools
///   (other than issuance) and the read actions of mixed (`Actions`) tools
///   for these exact arguments.
/// * `result_count`, `result_bytes`, and per-touch `result_rank` keep their
///   historical values: PR A nulls them at write time for new rows, but the
///   cleanup preserves retained evidence verbatim rather than scrubbing it.
///
/// Dictionary entries (`read_log_record_ids`) survive only while referenced:
/// entries orphaned by the touch/call deletions — including pre-existing
/// orphans — are purged. Call `seq` values are never renumbered, so
/// intra-run ordering (`ORDER BY ended_at, seq`), `parent_key` chains, and
/// the `sqlite_sequence` high-water mark survive the edge.
#[derive(Debug)]
struct Engine62To63Migration;

impl EngineMigrationStep for Engine62To63Migration {
    fn from(&self) -> i64 {
        62
    }

    fn to(&self) -> i64 {
        63
    }

    fn name(&self) -> &str {
        "engine-62-to-63-read-log-selective-cleanup"
    }

    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await?;
            if version == 62 {
                crate::db::validate_supported_engine_migration_source(connection, 62).await?;
            }
            Ok(())
        }
        .boxed()
    }

    fn apply<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move { apply_read_log_selective_cleanup(connection).await }.boxed()
    }
}

/// Reclaim the pages released by 62→63 without changing any logical row or
/// schema object. VACUUM runs in autocommit before this hop's fenced, no-op
/// apply transaction. A kill or lost fence before the stamp leaves engine 63
/// retryable; current engine 64 opens do not vacuum.
#[derive(Debug)]
struct Engine63To64Migration;

impl EngineMigrationStep for Engine63To64Migration {
    fn from(&self) -> i64 {
        63
    }

    fn to(&self) -> i64 {
        64
    }

    fn name(&self) -> &str {
        "engine-63-to-64-read-log-freelist-compaction"
    }

    fn requires_pre_apply_compaction(&self) -> bool {
        true
    }

    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await?;
            if version == 63 {
                crate::db::validate_supported_engine_migration_source(connection, 63).await?;
            }
            Ok(())
        }
        .boxed()
    }

    fn apply<'a>(&'a self, _connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move { Ok(()) }.boxed()
    }
}

/// The exact engine-64-to-65 DDL: the single authoritative source for this
/// schema edge's structural change.
///
/// Both the reference SQLite runner (`Engine64To65Migration::apply` below)
/// and the Turso-local runner
/// (`crate::turso_local::migrate_existing_engine_schema`) execute this same
/// sequence. The edge is DDL-only: `alpha_tab_installs` is new install state
/// with no pre-existing rows to backfill, so a migrated database gains the
/// empty projection and converges with a fresh database trivially.
///
/// The two statements must stay byte-identical to the corresponding
/// `crate::schema::DDL_STATEMENTS` entries; the 64→65 migration test asserts
/// that rather than assuming it.
pub(crate) const ENGINE_64_TO_65_STATEMENTS: [&str; 2] = [
    r#"CREATE TABLE alpha_tab_installs (
     account_id                TEXT NOT NULL CHECK (length(trim(account_id)) > 0),
     package                   TEXT NOT NULL CHECK (length(trim(package)) > 0),
     version                   TEXT NOT NULL CHECK (length(trim(version)) > 0),
     digest                    TEXT NOT NULL CHECK (length(trim(digest)) > 0),
     artifact_id               TEXT NOT NULL REFERENCES records(id),
     consented_source_revision TEXT NOT NULL CHECK (length(trim(consented_source_revision)) > 0),
     declaration_digest        TEXT NOT NULL CHECK (length(declaration_digest) = 64),
     consented_declaration     TEXT NOT NULL CHECK (json_valid(consented_declaration) AND json_type(consented_declaration) = 'object'),
     adoption                  TEXT NOT NULL CHECK (adoption IN ('caller_asserted','shell_adopt.v1')),
     status                    TEXT NOT NULL CHECK (status IN ('installed','disabled','removed')),
     event_id                  TEXT NOT NULL UNIQUE REFERENCES control_events(id),
     event_seq                 INTEGER NOT NULL UNIQUE REFERENCES control_events(seq),
     updated_at                TEXT NOT NULL,
     PRIMARY KEY (account_id, package)
    )"#,
    r#"CREATE INDEX idx_alpha_tab_installs_artifact ON alpha_tab_installs(artifact_id)"#,
];

/// The personal alpha-tab install projection edge (engine 64 → 65).
#[derive(Debug)]
struct Engine64To65Migration;

impl EngineMigrationStep for Engine64To65Migration {
    fn from(&self) -> i64 {
        64
    }

    fn to(&self) -> i64 {
        65
    }

    fn name(&self) -> &str {
        "engine-64-to-65-alpha-tab-installs-projection"
    }

    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await?;
            if version == 64 {
                crate::db::validate_supported_engine_migration_source(connection, 64).await?;
            }
            Ok(())
        }
        .boxed()
    }

    fn apply<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            for statement in ENGINE_64_TO_65_STATEMENTS {
                sqlx::query(statement).execute(&mut *connection).await?;
            }
            Ok(())
        }
        .boxed()
    }
}

/// Frozen 62→63 deletion policy: the `Read`-disposition tools whose calls
/// are disposable unless kept by an earlier retention rule, minus
/// `bootstrap`, which is always issuance rather than exhaust.
///
/// Frozen, not derived: historical deletion must not change when a later
/// release adds tools or reclassifies them. Measured from the reviewed
/// engine-59 policy before the 62→63 edge was renumbered. The equality test
/// compares this snapshot to the current PR A capture disposition
/// with only explicitly named post-freeze tools excluded, so later drift
/// fails loudly instead of silently retargeting history.
const ENGINE_62_TO_63_PURE_READ_TOOLS: &[&str] = &[
    "describe_schema",
    "engine_info",
    "get_dashboard",
    "get_event_context",
    "get_history",
    "get_record",
    "get_reuse_context",
    "get_run_activity",
    "get_structure",
    "open_collection",
    "ping",
    "preview_record_shape",
    "query_record",
    "query_sql",
    "reach_read",
    "read_attachment",
    "read_attributions",
    "read_canvas",
    "read_guide",
    "render_artifact",
    "render_record",
    "render_record_version_diff",
    "render_suggestion_review",
    "resolve_citation",
    "resolve_facets",
    "resolve_many",
    "resolve_rollup",
    "scan",
    "search",
    "standby_status",
    "suggest_facet_values",
    "verify_artifact",
    "whats_changed",
    "workspace_read",
];

/// Frozen 62→63 deletion policy: `(tool, read-actions)` for every
/// mixed-disposition shipped tool in the reviewed engine-59 policy. A call on one of
/// these tools is disposable only when its exact `action` argument is one
/// of the listed read actions; missing, non-string, or unknown actions fail
/// closed (kept), exactly like PR A capture. Frozen for the same reason as
/// [`ENGINE_62_TO_63_PURE_READ_TOOLS`].
const ENGINE_62_TO_63_MIXED_READS: &[(&str, &[&str])] = &[
    ("manage_artifact_inputs", &["read"]),
    ("manage_artifact_module_grants", &["read"]),
    ("manage_attachments", &["inspect", "list"]),
    ("manage_bindings", &["list", "observations"]),
    ("manage_change_summaries", &["inspect"]),
    ("manage_facet_observations", &["list"]),
    ("manage_instructions", &["compare_seeded_default", "list"]),
    ("manage_interventions", &["get", "query"]),
    ("manage_links", &["list"]),
    ("manage_mdx_modules", &["impact", "inspect"]),
    (
        "manage_memberships",
        &["invitations_inspect", "invitations_list", "list"],
    ),
    (
        "manage_messages",
        &[
            "get_attention",
            "list_context",
            "list_conversation",
            "list_destinations",
            "list_inbox",
            "list_message_state",
            "list_my_conversations",
            "list_notification_candidates",
            "list_unclassified",
        ],
    ),
    (
        "manage_onboarding",
        &["list_programmes", "preview_generation"],
    ),
    ("manage_record_policy", &["inspect", "list"]),
    ("manage_relationships", &["find", "read", "why"]),
    ("manage_renderer_binding", &["read"]),
    ("manage_schema_config", &["read"]),
    ("manage_surface_bindings", &["get", "list"]),
    ("manage_vocabularies", &["list_values"]),
    ("query_change_summaries", &["drill", "get", "list"]),
    ("start_work", &["preview"]),
];

/// Frozen 62→63 policy: the `Mutation`-disposition tools in the reviewed
/// engine-59 policy, pinned for the dry-run report and equality test.
/// Mutation calls are always retained, so this list never appears in a
/// `DELETE`, but the report needs it to tell unknown tools apart from
/// known mutations. Frozen for the same reason as
/// [`ENGINE_62_TO_63_PURE_READ_TOOLS`].
const ENGINE_62_TO_63_MUTATION_TOOLS: &[&str] = &[
    "advance_artifact_port_pin",
    "archive_record",
    "attach_from_url",
    "attach_text",
    "batch_write",
    "claim_unowned_record",
    "close_run",
    "correct_record_type",
    "create_attribution",
    "create_exploration",
    "create_many",
    "create_record",
    "delete_record",
    "export_snapshot",
    "instantiate_artifact",
    "invoke_artifact_interaction",
    "manage_attributions",
    "manage_canvas",
    "manage_citations",
    "observe_external",
    "quickstart",
    "reach_connect",
    "resolve_external",
    "resolve_suggestions",
    "save_account",
    "set_intent",
    "update_record",
];

/// These read tools arrived after the reviewed deletion set was frozen.
/// PR A capture drops their new observational calls. Historical rows with
/// these names remain retained pending a separate consumer/corpus audit;
/// neither renumbering nor a current Read disposition silently widens DELETE.
const ENGINE_62_TO_63_POST_FREEZE_TOOLS: &[&str] = &[
    "get_workspace_snapshot",
    "authority_act_head",
    "authority_act_delta",
    "manage_alpha_tabs",
];

/// Shipped tools whose calls are disposable unless kept by an earlier
/// retention rule (issuance, annotation, mutated touch, `set_intent`): the
/// frozen [`ENGINE_62_TO_63_PURE_READ_TOOLS`] list.
fn read_log_disposable_pure_reads() -> Vec<&'static str> {
    ENGINE_62_TO_63_PURE_READ_TOOLS.to_vec()
}

/// `(tool, read-actions)` for every mixed-disposition shipped tool: the
/// frozen [`ENGINE_62_TO_63_MIXED_READS`] list.
fn read_log_mixed_reads() -> Vec<(&'static str, Vec<&'static str>)> {
    ENGINE_62_TO_63_MIXED_READS
        .iter()
        .map(|(tool, actions)| (*tool, actions.to_vec()))
        .collect()
}

/// Quote a shipped tool or action name as a SQL string literal. Names are
/// compile-time `[a-z_]` constants from `ToolKind`; the assertion keeps a
/// future rename honest rather than letting it become an injection.
fn read_log_name_literal(name: &str) -> String {
    debug_assert!(
        !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_'),
        "unexpected tool/action name in read-log predicate: {name}"
    );
    format!("'{name}'")
}

/// Total-args expression for every `json_*` call below. The bundled SQLite
/// build aborts the whole statement on malformed text (`malformed JSON`)
/// rather than returning `NULL`, and `WHERE`-conjunct evaluation order is
/// the planner's choice, so a bare `json_valid(...) AND ...` guard cannot
/// protect a later extract on its own. Reading through this `CASE`
/// substitutes `'{}'` for anything that does not parse, which folds every
/// malformed row to non-issuance / non-disposable — retained, fail-closed.
fn read_log_parseable_args_sql(args_expression: &str) -> String {
    format!("(CASE WHEN json_valid({args_expression}) THEN {args_expression} ELSE '{{}}' END)")
}

/// `json_extract(<args>,'$.run_key')` selects a fresh run (`"new"` or
/// `"new:<agent>"`), mirroring PR A's `is_read_issuance` selector check.
/// Two-valued by construction on top of parseable args: a missing or
/// non-text selector is `NULL`, which would otherwise poison the enclosing
/// `NOT` and spare every row, so each comparison is `COALESCE`d to false.
fn read_log_run_key_is_new_sql(args_expression: &str) -> String {
    let selector = format!("json_extract({args_expression},'$.run_key')");
    format!(
        "(COALESCE(({selector} = 'new'), 0) OR COALESCE((substr({selector}, 1, 4) = 'new:'), 0))"
    )
}

/// A mixed tool's read-action match for these exact arguments, two-valued
/// on top of parseable args: a missing, non-string, or unknown `action` is
/// `NULL` and must fail closed (kept), never match as disposable.
fn read_log_action_is_read_sql(args_expression: &str, actions: &[&str]) -> String {
    let reads: Vec<String> = actions
        .iter()
        .map(|action| read_log_name_literal(action))
        .collect();
    format!(
        "COALESCE((json_extract({args_expression},'$.action') IN ({})), 0)",
        reads.join(", ")
    )
}

/// Calls retained as run issuance: `bootstrap` rows plus read/mixed-read
/// calls carrying a fresh-run selector. `calls_ref` qualifies the
/// `read_log_calls` columns (table name or outer-query alias).
fn read_log_issuance_sql(calls_ref: &str) -> String {
    let args = read_log_parseable_args_sql(&format!("{calls_ref}.arguments"));
    let is_new = read_log_run_key_is_new_sql(&args);
    let pure: Vec<String> = read_log_disposable_pure_reads()
        .iter()
        .map(|tool| read_log_name_literal(tool))
        .collect();
    let mut alternatives = vec![format!("{calls_ref}.tool = 'bootstrap'")];
    alternatives.push(format!(
        "{calls_ref}.tool IN ({}) AND {is_new}",
        pure.join(", ")
    ));
    for (tool, actions) in read_log_mixed_reads() {
        alternatives.push(format!(
            "{calls_ref}.tool = {} AND {} AND {is_new}",
            read_log_name_literal(tool),
            read_log_action_is_read_sql(&args, &actions)
        ));
    }
    format!("({})", alternatives.join(" OR "))
}

/// Disposable calls: no annotation, no `mutated` touch, not issuance, and a
/// known-observational shape (pure read, or a mixed tool's read action for
/// these exact arguments). Everything else — `set_intent`, mutations, mixed
/// writes, unknown/malformed actions, unknown tool names — is kept.
/// Malformed `arguments` text fails closed as well: the disposable
/// predicate requires `json_valid`, so a non-parsing row is retained
/// byte-identical whatever its tool. All extracts additionally read through
/// the parseable-args substitution (without it the bundled SQLite build
/// aborts the statement on malformed text instead of returning `NULL`), and
/// the explicit `json_valid` gates on the rewriting statements guarantee
/// malformed bytes are never normalized.
fn read_log_disposable_sql(calls_ref: &str) -> String {
    let issuance = read_log_issuance_sql(calls_ref);
    let args = read_log_parseable_args_sql(&format!("{calls_ref}.arguments"));
    let pure: Vec<String> = read_log_disposable_pure_reads()
        .iter()
        .map(|tool| read_log_name_literal(tool))
        .collect();
    let mut observational = vec![format!("{calls_ref}.tool IN ({})", pure.join(", "))];
    for (tool, actions) in read_log_mixed_reads() {
        observational.push(format!(
            "{calls_ref}.tool = {} AND {}",
            read_log_name_literal(tool),
            read_log_action_is_read_sql(&args, &actions)
        ));
    }
    format!(
        "({calls_ref}.result_annotation IS NULL \
         AND NOT EXISTS (SELECT 1 FROM read_log_touches t \
                         WHERE t.call_seq = {calls_ref}.seq AND t.interaction = 'mutated') \
         AND NOT {issuance} \
         AND json_valid({calls_ref}.arguments) \
         AND ({}))",
        observational.join(" OR ")
    )
}

/// Aggregate-only 62→63 dry-run result. Categories overlap by design: for
/// example a malformed known read is both retained and invalid. A mixed
/// unmatched text action may be a valid write or an unknown future action;
/// the frozen read-action policy cannot distinguish those without guessing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReadLog62To63AttentionReport {
    pub total_calls: i64,
    pub disposable_calls: i64,
    pub retained_calls: i64,
    pub issuance_calls: i64,
    pub unknown_tool_calls: i64,
    pub mixed_missing_or_nontext_action_calls: i64,
    pub mixed_unmatched_text_action_calls: i64,
    pub null_arguments_calls: i64,
    pub malformed_arguments_calls: i64,
    pub total_touches: i64,
    pub removable_touches: i64,
    pub total_dictionary_entries: i64,
    pub projected_orphan_dictionary_entries: i64,
}

/// Read-only count query for a frozen engine-62 preimage. It uses the exact
/// DELETE and issuance predicates below, returns no tools, arguments, ids, or
/// per-call rows, and makes fail-closed attention visible before migration.
/// Run it on a disposable fixture/copy through a read-only connection; it is
/// not a production preflight and does not authorize migration or compaction.
pub async fn read_log_62_to_63_attention_report(
    connection: &mut SqliteConnection,
) -> Result<ReadLog62To63AttentionReport> {
    let version: i64 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(&mut *connection)
        .await?;
    if version != 62 {
        return Err(Error::engine(
            "read-log attention report requires engine 62",
        ));
    }
    let calls = "c";
    let disposable = read_log_disposable_sql(calls);
    let issuance = read_log_issuance_sql(calls);
    let known: Vec<String> = ENGINE_62_TO_63_PURE_READ_TOOLS
        .iter()
        .chain(ENGINE_62_TO_63_MUTATION_TOOLS.iter())
        .chain(ENGINE_62_TO_63_POST_FREEZE_TOOLS.iter())
        .chain(std::iter::once(&"bootstrap"))
        .map(|name| read_log_name_literal(name))
        .chain(
            ENGINE_62_TO_63_MIXED_READS
                .iter()
                .map(|(name, _)| read_log_name_literal(name)),
        )
        .collect();
    let mixed: Vec<String> = ENGINE_62_TO_63_MIXED_READS
        .iter()
        .map(|(name, _)| read_log_name_literal(name))
        .collect();
    let args = read_log_parseable_args_sql("c.arguments");
    let action_type = format!("json_type({args},'$.action')");
    let matched_read_actions = ENGINE_62_TO_63_MIXED_READS
        .iter()
        .map(|(tool, actions)| {
            format!(
                "(c.tool = {} AND {})",
                read_log_name_literal(tool),
                read_log_action_is_read_sql(&args, actions)
            )
        })
        .collect::<Vec<_>>()
        .join(" OR ");
    let row = sqlx::query(&format!(
        "SELECT COUNT(*) AS total_calls, \
          COALESCE(SUM(CASE WHEN {disposable} THEN 1 ELSE 0 END),0) AS disposable_calls, \
          COALESCE(SUM(CASE WHEN {issuance} THEN 1 ELSE 0 END),0) AS issuance_calls, \
          COALESCE(SUM(CASE WHEN c.tool IS NULL OR c.tool NOT IN ({}) THEN 1 ELSE 0 END),0) AS unknown_tool_calls, \
          COALESCE(SUM(CASE WHEN c.tool IN ({}) AND json_valid(c.arguments) AND COALESCE({action_type} != 'text',1) THEN 1 ELSE 0 END),0) AS mixed_missing_action_calls, \
          COALESCE(SUM(CASE WHEN c.tool IN ({}) AND json_valid(c.arguments) AND {action_type} = 'text' AND NOT ({matched_read_actions}) THEN 1 ELSE 0 END),0) AS mixed_unmatched_action_calls, \
          COALESCE(SUM(CASE WHEN c.arguments IS NULL THEN 1 ELSE 0 END),0) AS null_arguments_calls, \
          COALESCE(SUM(CASE WHEN c.arguments IS NOT NULL AND NOT json_valid(c.arguments) THEN 1 ELSE 0 END),0) AS malformed_arguments_calls \
         FROM read_log_calls c",
        known.join(", "), mixed.join(", "), mixed.join(", ")
    ))
    .fetch_one(&mut *connection)
    .await?;
    let total_calls: i64 = row.try_get("total_calls")?;
    let disposable_calls: i64 = row.try_get("disposable_calls")?;
    let total_touches: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM read_log_touches")
        .fetch_one(&mut *connection)
        .await?;
    let removable_touches: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM read_log_touches t JOIN read_log_calls c ON c.seq = t.call_seq \
         WHERE {disposable} OR ({issuance} AND (c.tool = 'bootstrap' OR json_valid(c.arguments)))"
    ))
    .fetch_one(&mut *connection)
    .await?;
    let total_dictionary_entries: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM read_log_record_ids")
            .fetch_one(&mut *connection)
            .await?;
    let projected_orphan_dictionary_entries: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM read_log_record_ids d WHERE NOT EXISTS \
         (SELECT 1 FROM read_log_touches t JOIN read_log_calls c ON c.seq = t.call_seq \
          WHERE t.record_ref = d.record_ref AND NOT ({disposable}) \
            AND NOT ({issuance} AND (c.tool = 'bootstrap' OR json_valid(c.arguments))))"
    ))
    .fetch_one(&mut *connection)
    .await?;
    Ok(ReadLog62To63AttentionReport {
        total_calls,
        disposable_calls,
        retained_calls: total_calls - disposable_calls,
        issuance_calls: row.try_get("issuance_calls")?,
        unknown_tool_calls: row.try_get("unknown_tool_calls")?,
        mixed_missing_or_nontext_action_calls: row.try_get("mixed_missing_action_calls")?,
        mixed_unmatched_text_action_calls: row.try_get("mixed_unmatched_action_calls")?,
        null_arguments_calls: row.try_get("null_arguments_calls")?,
        malformed_arguments_calls: row.try_get("malformed_arguments_calls")?,
        total_touches,
        removable_touches,
        total_dictionary_entries,
        projected_orphan_dictionary_entries,
    })
}

/// Run the four selective-cleanup statements in dependency order: issuance
/// touches, issuance argument minimization, disposable calls (whose touches
/// cascade under the runner's enforced foreign keys), then the orphan
/// dictionary purge. Idempotent: re-running over an already-cleaned file
/// deletes nothing and still succeeds.
async fn apply_read_log_selective_cleanup(connection: &mut SqliteConnection) -> Result<()> {
    let issuance = read_log_issuance_sql("read_log_calls");
    let disposable = read_log_disposable_sql("read_log_calls");
    // Attention-touch strip: `bootstrap` issuance needs no JSON and strips
    // regardless; every other issuance row matched through JSON extracts and
    // must still parse, otherwise its touches stay as fail-closed evidence
    // alongside the retained row.
    sqlx::query(&format!(
        "DELETE FROM read_log_touches WHERE call_seq IN \
         (SELECT seq FROM read_log_calls WHERE {issuance} \
          AND (read_log_calls.tool = 'bootstrap' \
               OR json_valid(read_log_calls.arguments)))"
    ))
    .execute(&mut *connection)
    .await?;
    // Issuance retains only the caller-supplied run-key selector, exactly as
    // PR A capture stores it: a text selector keeps `{"run_key": ...}`, while
    // a missing or non-text selector (e.g. historical `bootstrap` rows, which
    // carry run identity in the `run_key`/`parent_key` columns) keeps `{}`.
    // The `json_valid` gate keeps malformed historical bytes byte-identical
    // instead of normalizing them; the `CASE` reads through the parseable
    // substitution so the extract itself is total too.
    let update_args = read_log_parseable_args_sql("arguments");
    sqlx::query(&format!(
        "UPDATE read_log_calls \
         SET arguments = CASE \
           WHEN json_type({update_args},'$.run_key') = 'text' \
           THEN json_object('run_key', json_extract({update_args},'$.run_key')) \
           ELSE '{{}}' END \
         WHERE {issuance} AND json_valid(read_log_calls.arguments)"
    ))
    .execute(&mut *connection)
    .await?;
    sqlx::query(&format!("DELETE FROM read_log_calls WHERE {disposable}"))
        .execute(&mut *connection)
        .await?;
    sqlx::query(
        "DELETE FROM read_log_record_ids WHERE NOT EXISTS \
         (SELECT 1 FROM read_log_touches \
          WHERE read_log_touches.record_ref = read_log_record_ids.record_ref)",
    )
    .execute(&mut *connection)
    .await?;
    Ok(())
}

async fn planned_dogfood_message_origin_repair(
    connection: &mut SqliteConnection,
    repair: DogfoodMessageOriginRepair,
) -> Result<Option<crate::events::MessageOriginDeclaredPayload>> {
    let record = sqlx::query("SELECT type,owner_id,home_id,deleted_at FROM records WHERE id=?")
        .bind(repair.message_id)
        .fetch_optional(&mut *connection)
        .await?;
    let Some(record) = record else {
        return Ok(None);
    };
    let matches_record = record.try_get::<String, _>("type")? == "Message"
        && record.try_get::<Option<String>, _>("owner_id")?.as_deref() == Some(repair.owner_id)
        && record.try_get::<Option<String>, _>("home_id")?.as_deref()
            == Some(crate::schema::UNFILED_RECORD_ID)
        && record.try_get::<Option<String>, _>("deleted_at")?.is_none();
    if !matches_record {
        return Err(Error::engine(format!(
            "reviewed Message-origin evidence mismatch for {}: expected a live Message owned by {} and filed in {}",
            repair.message_id,
            repair.owner_id,
            crate::schema::UNFILED_RECORD_ID
        )));
    }

    let addressed_to: Vec<String> = sqlx::query_scalar(
        "SELECT target_id FROM links
          WHERE source_id=? AND relationship='addressed_to' ORDER BY target_id",
    )
    .bind(repair.message_id)
    .fetch_all(&mut *connection)
    .await?;
    let origin = match repair.origin {
        DogfoodMessageOrigin::Collection => {
            if !addressed_to.is_empty() {
                return Err(Error::engine(format!(
                    "reviewed Message-origin evidence mismatch for {}: expected no addressed_to links",
                    repair.message_id
                )));
            }
            let live_collection: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM records
                  WHERE id=? AND type='Collection' AND kind='folder' AND deleted_at IS NULL)",
            )
            .bind(crate::schema::UNFILED_RECORD_ID)
            .fetch_one(&mut *connection)
            .await?;
            if !live_collection {
                return Err(Error::engine(
                    "reviewed Message-origin evidence mismatch: native:unfiled is not a live Collection folder",
                ));
            }
            crate::events::MessageOriginDeclaredPayload::Collection {
                collection_id: crate::schema::UNFILED_RECORD_ID.into(),
            }
        }
        DogfoodMessageOrigin::Direct {
            addressed_to: expected,
        } => {
            if addressed_to.as_slice() != [expected] {
                return Err(Error::engine(format!(
                    "reviewed Message-origin evidence mismatch for {}: expected addressed_to {}",
                    repair.message_id, expected
                )));
            }
            for (person_id, expected_principal) in [
                (DOGFOOD_RICHARD_ID, DOGFOOD_DIRECT_PRINCIPALS[0]),
                (DOGFOOD_NEILL_ID, DOGFOOD_DIRECT_PRINCIPALS[1]),
            ] {
                let principal: Option<String> = sqlx::query_scalar(
                    "SELECT b.identifier FROM records r JOIN bindings b ON b.record_id=r.id
                      WHERE r.id=? AND r.type='Entity' AND r.kind='person'
                        AND r.deleted_at IS NULL AND b.system='native-principal'
                        AND b.is_canonical=1",
                )
                .bind(person_id)
                .fetch_optional(&mut *connection)
                .await?;
                if principal.as_deref() != Some(expected_principal) {
                    return Err(Error::engine(format!(
                        "reviewed Message-origin evidence mismatch for {}: Person {} has an unexpected canonical principal",
                        repair.message_id, person_id
                    )));
                }
            }
            crate::events::MessageOriginDeclaredPayload::Direct {
                principals: DOGFOOD_DIRECT_PRINCIPALS
                    .iter()
                    .map(|principal| (*principal).to_owned())
                    .collect(),
            }
        }
    };

    let state = sqlx::query(
        "SELECT status,origin_type,collection_id,direct_set_digest,participant_count
           FROM message_origin_state WHERE message_id=?",
    )
    .bind(repair.message_id)
    .fetch_optional(&mut *connection)
    .await?
    .ok_or_else(|| {
        Error::engine(format!(
            "reviewed Message-origin evidence mismatch for {}: origin state is absent",
            repair.message_id
        ))
    })?;
    match state.try_get::<String, _>("status")?.as_str() {
        "legacy_unknown" => Ok(Some(origin)),
        "declared" if projected_origin_matches(connection, repair.message_id, &state, &origin).await? => {
            Ok(None)
        }
        _ => Err(Error::engine(format!(
            "reviewed Message-origin evidence mismatch for {}: origin state is not the reviewed value",
            repair.message_id
        ))),
    }
}

async fn projected_origin_matches(
    connection: &mut SqliteConnection,
    message_id: &str,
    state: &sqlx::sqlite::SqliteRow,
    origin: &crate::events::MessageOriginDeclaredPayload,
) -> Result<bool> {
    Ok(match origin {
        crate::events::MessageOriginDeclaredPayload::Collection { collection_id } => {
            state
                .try_get::<Option<String>, _>("origin_type")?
                .as_deref()
                == Some("collection")
                && state
                    .try_get::<Option<String>, _>("collection_id")?
                    .as_deref()
                    == Some(collection_id)
                && state
                    .try_get::<Option<String>, _>("direct_set_digest")?
                    .is_none()
                && state.try_get::<Option<i64>, _>("participant_count")? == Some(0)
        }
        crate::events::MessageOriginDeclaredPayload::Direct { principals } => {
            let projected: Vec<String> = sqlx::query_scalar(
                "SELECT principal_id FROM message_origin_principals
                  WHERE message_id=? ORDER BY principal_id",
            )
            .bind(message_id)
            .fetch_all(&mut *connection)
            .await?;
            state
                .try_get::<Option<String>, _>("origin_type")?
                .as_deref()
                == Some("direct")
                && state
                    .try_get::<Option<String>, _>("collection_id")?
                    .is_none()
                && state
                    .try_get::<Option<String>, _>("direct_set_digest")?
                    .as_deref()
                    == Some(crate::events::direct_origin_set_digest(principals).as_str())
                && state.try_get::<Option<i64>, _>("participant_count")?
                    == Some(principals.len() as i64)
                && projected == *principals
        }
    })
}

async fn append_dogfood_message_origin_declaration(
    connection: &mut SqliteConnection,
    message_id: &str,
    origin: crate::events::MessageOriginDeclaredPayload,
) -> Result<()> {
    let event_id = uuid::Uuid::new_v4().to_string();
    let heads: Vec<String> = sqlx::query_scalar(
        "SELECT event.id FROM content_events event
              WHERE NOT EXISTS (
                    SELECT 1 FROM content_event_causal_frontier frontier
                     WHERE frontier.parent_event_id=event.id)
              ORDER BY event.id",
    )
    .fetch_all(&mut *connection)
    .await?;
    if heads.is_empty() {
        let event_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(&mut *connection)
            .await?;
        if event_count != 0 {
            return Err(Error::engine(
                "content event causal state has no heads for a nonempty log",
            ));
        }
    }
    let frontier = crate::events::CausalFrontierV1::new(heads)?;
    let causal_envelope = crate::events::CausalEnvelopeV1::complete(frontier);
    causal_envelope.validate_for_event(&event_id)?;
    let created_at = crate::store::now_iso();
    let payload = serde_json::to_string(&origin)?;
    let local_seq: i64 = sqlx::query_scalar(
        "INSERT INTO content_events
            (id,record_id,type,payload,actor,run_key,parent_key,intent,created_at,
             causal_envelope_version,causal_status)
         VALUES (?,?,'message.origin.declared.v1',?,?,'engine-47-to-48-message-origin-repair',NULL,
                 'Apply the reviewed Native HQ legacy Message-origin manifest.',?,1,'complete')
         RETURNING seq",
    )
    .bind(&event_id)
    .bind(message_id)
    .bind(&payload)
    .bind("engine:message-origin-dogfood-migration")
    .bind(&created_at)
    .fetch_one(&mut *connection)
    .await?;
    for parent_event_id in causal_envelope.frontier().as_slice() {
        sqlx::query(
            "INSERT INTO content_event_causal_frontier(event_id,parent_event_id) VALUES (?,?)",
        )
        .bind(&event_id)
        .bind(parent_event_id)
        .execute(&mut *connection)
        .await?;
    }
    crate::projector::project(
        connection,
        &crate::events::EventRow {
            local_seq,
            id: event_id,
            record_id: message_id.to_owned(),
            event_type: "message.origin.declared.v1".into(),
            payload: Some(payload),
            actor: Some("engine:message-origin-dogfood-migration".into()),
            run_key: Some("engine-47-to-48-message-origin-repair".into()),
            parent_key: None,
            intent: Some("Apply the reviewed Native HQ legacy Message-origin manifest.".into()),
            created_at,
            causal_envelope,
            act: None,
        },
    )
    .await
}

impl EngineMigrationRegistry {
    pub fn pending(&self, from: i64, to: i64) -> Result<Vec<Arc<dyn EngineMigrationStep>>> {
        if self.supported_baseline.is_none() && from != self.current {
            return Err(Error::engine(format!(
                "engine schema {from} is not supported: no historical engine schema baseline exists yet; reset or recreate this database at engine schema {}",
                self.current
            )));
        }
        if from < self.minimum_supported {
            return Err(Error::engine(format!(
                "engine schema {from} predates the supported baseline {}; reset or recreate this database at engine schema {}",
                self.minimum_supported, self.current
            )));
        }
        if to > self.current || to < from || from < self.minimum_supported {
            return Err(Error::engine(format!(
                "unsupported engine migration range {from} -> {to} (supported {} -> {})",
                self.minimum_supported, self.current
            )));
        }
        let pending: Vec<_> = self
            .migrations
            .iter()
            .filter(|migration| migration.from() >= from && migration.to() <= to)
            .cloned()
            .collect();
        let end = pending.last().map_or(from, |migration| migration.to());
        if end != to {
            return Err(Error::engine(format!(
                "no contiguous engine migration path from {from} to {to}"
            )));
        }
        Ok(pending)
    }

    /// Candidate evidence derives from the same production registry used by
    /// execution. An edge cannot be advertised under a parallel manifest.
    pub fn capability_edges(&self) -> Vec<EngineMigrationCapabilityEdge> {
        self.migrations
            .iter()
            .map(|migration| EngineMigrationCapabilityEdge {
                from: migration.from(),
                to: migration.to(),
                stable_id: migration.stable_id().to_string(),
            })
            .collect()
    }
}

/// Run the complete production migration path's concrete preflight checks on
/// one existing database without permitting any filesystem or SQLite writes.
///
/// This is the release-planning seam: a supported version header alone does
/// not prove that the corresponding historical schema is complete. Every
/// pending transition inspects the same original preimage, matching the
/// production runner's all-steps-before-backup contract.
pub async fn preflight_production_migration_read_only(path: &Path) -> Result<i64> {
    let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))?
        .create_if_missing(false)
        .read_only(true)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5));
    let mut connection = SqliteConnection::connect_with(&options).await?;
    let outcome: Result<i64> = async {
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&mut connection)
            .await?;
        let integrity: String = sqlx::query_scalar("PRAGMA quick_check(1)")
            .fetch_one(&mut connection)
            .await?;
        if integrity != "ok" {
            return Err(Error::engine("migration preflight quick_check failed"));
        }
        let registry = EngineMigrationRegistry::production();
        let pending = registry.pending(version, registry.current)?;
        for migration in pending {
            migration.preflight(&mut connection).await.map_err(|err| {
                Error::engine(format!(
                    "migration {} preflight failed: {err}",
                    migration.name()
                ))
            })?;
        }
        Ok(version)
    }
    .await;
    let _ = connection.close().await;
    outcome
}

pub type FenceFn = Arc<dyn Fn() -> BoxFuture<'static, Result<()>> + Send + Sync>;
/// Persists the attempt journal after a verified pre-image and before mutation.
///
/// Returning `Ok(())` asserts that the reservation is durably recorded—not
/// merely buffered or scheduled—and binds the exact `from`, `to`, pre-image
/// key, and digest supplied by the runner.
#[doc(hidden)]
pub type AttemptReservationFn =
    Arc<dyn Fn(i64, i64, PreimageBackup) -> BoxFuture<'static, Result<()>> + Send + Sync>;
type PostMigrationVerifier =
    Arc<dyn Fn(PathBuf) -> BoxFuture<'static, PostMigrationVerification> + Send + Sync>;

enum PostMigrationVerification {
    Passed,
    StructuralFailed(String),
    VerifyOpenFailed(String),
    ConformanceFailed(String),
}

#[derive(Debug, Clone, Serialize)]
pub struct PreimageBackup {
    pub key: String,
    pub digest: String,
}

/// Stores a verified migration pre-image outside the source being mutated.
///
/// The portable migration runner owns snapshot creation and integrity
/// verification. An implementation must not mutate `source`; it may return
/// success only after storage outside the source database's failure boundary
/// has durably read back the exact bytes and bound their digest to the returned
/// key.
pub trait MigrationPreimageStore: Send + Sync {
    /// Durably store and read back `source`, returning its stable lookup key
    /// and an exact-byte digest.
    fn store_verified_preimage(
        &self,
        run_id: &str,
        db_id: &str,
        source: &Path,
    ) -> BoxFuture<'static, Result<PreimageBackup>>;
}

#[derive(Debug, Clone, Serialize)]
pub struct DatabaseMigrationReport {
    pub path: PathBuf,
    pub from_version: Option<i64>,
    pub to_version: i64,
    pub outcome: String,
    pub backup: Option<PreimageBackup>,
    pub error_kind: Option<String>,
    pub error_message: Option<String>,
}

fn single_connection_options(path: &Path) -> Result<SqliteConnectOptions> {
    Ok(
        SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))?
            .create_if_missing(false)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5)),
    )
}

/// In-place VACUUM plus the checks that must pass before the compacting
/// edge is allowed to open its stamp transaction. Must not be called with
/// an open transaction on `connection`.
async fn compact_database_in_place(
    connection: &mut SqliteConnection,
    migration: &dyn EngineMigrationStep,
    db_id: &str,
) -> Result<()> {
    eprintln!(
        "migration-phase db_id={db_id:?} step={} phase=vacuum start",
        migration.name()
    );
    let vacuum_started = std::time::Instant::now();
    sqlx::query("VACUUM").execute(&mut *connection).await?;
    eprintln!(
        "migration-phase db_id={db_id:?} step={} phase=vacuum completed elapsed_ms={}",
        migration.name(),
        vacuum_started.elapsed().as_millis()
    );
    eprintln!(
        "migration-phase db_id={db_id:?} step={} phase=post-vacuum-checks start",
        migration.name()
    );
    let checks_started = std::time::Instant::now();
    let integrity: String = sqlx::query("PRAGMA integrity_check")
        .fetch_one(&mut *connection)
        .await?
        .get(0);
    if integrity != "ok" {
        return Err(Error::engine(format!(
            "{} left integrity_check '{integrity}'",
            migration.name()
        )));
    }
    let foreign_key_violations: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM pragma_foreign_key_check")
            .fetch_one(&mut *connection)
            .await?;
    if foreign_key_violations != 0 {
        return Err(Error::engine(format!(
            "{} left {foreign_key_violations} foreign-key violation(s)",
            migration.name()
        )));
    }
    if !crate::db::validate_engine_shape_on(connection, migration.to()).await? {
        return Err(Error::engine(format!(
            "{} left a shape that does not match schema {}",
            migration.name(),
            migration.to()
        )));
    }
    eprintln!(
        "migration-phase db_id={db_id:?} step={} phase=post-vacuum-checks completed elapsed_ms={}",
        migration.name(),
        checks_started.elapsed().as_millis()
    );
    Ok(())
}

async fn capture_preimage(
    connection: &mut SqliteConnection,
    path: &Path,
    db_id: &str,
    run_id: &str,
    backup: &dyn MigrationPreimageStore,
) -> Result<PreimageBackup> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let dir = tempfile::Builder::new()
        .prefix("native-ce-migration-preimage-")
        .tempdir_in(parent)?;
    let snapshot = dir.path().join("preimage.db");
    eprintln!("migration-phase db_id={db_id:?} phase=backup-vacuum-into start");
    let snapshot_started = std::time::Instant::now();
    sqlx::query("VACUUM INTO ?")
        .bind(snapshot.to_string_lossy().into_owned())
        .execute(&mut *connection)
        .await?;
    eprintln!(
        "migration-phase db_id={db_id:?} phase=backup-vacuum-into completed elapsed_ms={}",
        snapshot_started.elapsed().as_millis()
    );
    eprintln!("migration-phase db_id={db_id:?} phase=backup-integrity start");
    let integrity_started = std::time::Instant::now();
    let snapshot_options =
        SqliteConnectOptions::from_str(&format!("sqlite:{}", snapshot.display()))?
            .create_if_missing(false)
            .read_only(true)
            .foreign_keys(true);
    let mut snapshot_connection = SqliteConnection::connect_with(&snapshot_options).await?;
    let integrity: String = sqlx::query("PRAGMA integrity_check")
        .fetch_one(&mut snapshot_connection)
        .await?
        .get(0);
    if integrity != "ok" {
        return Err(Error::engine(format!(
            "pre-image integrity_check failed for {}: {integrity}",
            path.display()
        )));
    }
    snapshot_connection.close().await?;
    eprintln!(
        "migration-phase db_id={db_id:?} phase=backup-integrity completed elapsed_ms={}",
        integrity_started.elapsed().as_millis()
    );
    eprintln!("migration-phase db_id={db_id:?} phase=backup-store-verify start");
    let store_started = std::time::Instant::now();
    let stored = backup
        .store_verified_preimage(run_id, db_id, &snapshot)
        .await?;
    eprintln!(
        "migration-phase db_id={db_id:?} phase=backup-store-verify completed elapsed_ms={}",
        store_started.elapsed().as_millis()
    );
    Ok(stored)
}

pub async fn migrate_database(
    path: &Path,
    db_id: &str,
    run_id: &str,
    target: i64,
    registry: &EngineMigrationRegistry,
    backup_options: &dyn MigrationPreimageStore,
    fence: FenceFn,
) -> DatabaseMigrationReport {
    migrate_database_with_reservation(
        path,
        db_id,
        run_id,
        target,
        registry,
        backup_options,
        fence,
        None,
        None,
        #[cfg(test)]
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn migrate_database_with_reservation(
    path: &Path,
    db_id: &str,
    run_id: &str,
    target: i64,
    registry: &EngineMigrationRegistry,
    backup_options: &dyn MigrationPreimageStore,
    fence: FenceFn,
    reserve_attempt: Option<AttemptReservationFn>,
    verifier: Option<PostMigrationVerifier>,
    #[cfg(test)] probe_override: Option<DatabaseVersionState>,
) -> DatabaseMigrationReport {
    #[cfg(not(test))]
    let state = probe_database(path, registry.current).await;
    #[cfg(test)]
    let state = match probe_override {
        Some(state) => state,
        None => probe_database(path, registry.current).await,
    };
    let from = match state {
        DatabaseVersionState::Known(version) => version,
        DatabaseVersionState::Future(version) => {
            return failed(
                path,
                Some(version),
                target,
                "future",
                format!("future schema {version}"),
            );
        }
        other => return failed(path, None, target, "probe", other.to_string()),
    };
    if from == target {
        return DatabaseMigrationReport {
            path: path.to_path_buf(),
            from_version: Some(from),
            to_version: target,
            outcome: "current".into(),
            backup: None,
            error_kind: None,
            error_message: None,
        };
    }
    let pending = match registry.pending(from, target) {
        Ok(pending) => pending,
        Err(err) => return failed(path, Some(from), target, "unsupported", err.to_string()),
    };
    // Preflight on a physically read-only handle. Even a buggy concrete
    // preflight cannot mutate the file before every transition has passed.
    let read_only_options =
        match SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display())) {
            Ok(options) => options
                .create_if_missing(false)
                .read_only(true)
                .foreign_keys(true),
            Err(err) => return failed(path, Some(from), target, "open", err.to_string()),
        };
    let mut preflight_connection = match SqliteConnection::connect_with(&read_only_options).await {
        Ok(connection) => connection,
        Err(err) => return failed(path, Some(from), target, "open", err.to_string()),
    };
    for migration in &pending {
        if let Err(err) = migration.preflight(&mut preflight_connection).await {
            let _ = preflight_connection.close().await;
            return failed(
                path,
                Some(from),
                target,
                "preflight",
                format!("{}: {err}", migration.name()),
            );
        }
    }
    let _ = preflight_connection.close().await;

    let mut connection = match single_connection_options(path) {
        Ok(options) => match SqliteConnection::connect_with(&options).await {
            Ok(connection) => connection,
            Err(err) => return failed(path, Some(from), target, "open", err.to_string()),
        },
        Err(err) => return failed(path, Some(from), target, "open", err.to_string()),
    };

    if let Err(err) = fence().await {
        let _ = connection.close().await;
        return failed(path, Some(from), target, "fence", err.to_string());
    }
    let backup = match capture_preimage(&mut connection, path, db_id, run_id, backup_options).await
    {
        Ok(backup) => backup,
        Err(err) => {
            let _ = connection.close().await;
            return failed(path, Some(from), target, "backup", err.to_string());
        }
    };

    if let Some(reserve_attempt) = reserve_attempt {
        if let Err(err) = reserve_attempt(from, target, backup.clone()).await {
            let _ = connection.close().await;
            return failed_with_backup(
                path,
                from,
                target,
                "attempt-journal",
                err.to_string(),
                backup,
            );
        }
    }

    for migration in pending {
        // Revalidate immediately before every mutation. A runner whose lease
        // was taken over after backup cannot begin a write transaction.
        if let Err(err) = fence().await {
            let _ = connection.close().await;
            return failed_with_backup(path, from, target, "fence", err.to_string(), backup);
        }
        if migration.requires_pre_apply_compaction() {
            // In-place VACUUM cannot run inside BEGIN IMMEDIATE. Do it in
            // autocommit, still fenced and still before any version stamp;
            // then fall through to the ordinary transactional apply so a
            // lost fence can ROLLBACK the stamp. A second connection holding
            // a write-preventing lock fails this hop closed (stay on from()).
            if let Err(err) =
                compact_database_in_place(&mut connection, migration.as_ref(), db_id).await
            {
                let _ = connection.close().await;
                return failed_with_backup(
                    path,
                    from,
                    target,
                    "compact",
                    format!("{}: {err}", migration.name()),
                    backup,
                );
            }
            if let Err(err) = fence().await {
                let _ = connection.close().await;
                return failed_with_backup(path, from, target, "fence", err.to_string(), backup);
            }
        }
        eprintln!(
            "migration-phase db_id={db_id:?} step={} phase=apply start",
            migration.name()
        );
        let apply_started = std::time::Instant::now();
        let foreign_keys_disabled = migration.requires_foreign_keys_disabled();
        if foreign_keys_disabled {
            if let Err(err) = sqlx::query("PRAGMA foreign_keys=OFF")
                .execute(&mut connection)
                .await
            {
                let _ = connection.close().await;
                return failed_with_backup(
                    path,
                    from,
                    target,
                    "begin",
                    format!("{} could not disable foreign keys: {err}", migration.name()),
                    backup,
                );
            }
            match sqlx::query_scalar::<_, bool>("PRAGMA foreign_keys")
                .fetch_one(&mut connection)
                .await
            {
                Ok(false) => {}
                Ok(true) => {
                    let _ = connection.close().await;
                    return failed_with_backup(
                        path,
                        from,
                        target,
                        "begin",
                        format!(
                            "{} requires foreign keys disabled before BEGIN",
                            migration.name()
                        ),
                        backup,
                    );
                }
                Err(err) => {
                    let _ = connection.close().await;
                    return failed_with_backup(
                        path,
                        from,
                        target,
                        "begin",
                        format!(
                            "{} could not verify foreign-key mode: {err}",
                            migration.name()
                        ),
                        backup,
                    );
                }
            }
        }
        if let Err(err) = sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut connection)
            .await
        {
            let _ = connection.close().await;
            return failed_with_backup(path, from, target, "begin", err.to_string(), backup);
        }
        let step = async {
            migration.apply(&mut connection).await?;
            if foreign_keys_disabled {
                let violations = sqlx::query(
                    "SELECT \"table\", rowid, parent, fkid
                       FROM pragma_foreign_key_check LIMIT 20",
                )
                .fetch_all(&mut connection)
                .await?;
                if !violations.is_empty() {
                    let details = violations
                        .into_iter()
                        .map(|row| {
                            Ok(format!(
                                "{} row {:?} -> {} (fk {})",
                                row.try_get::<String, _>("table")?,
                                row.try_get::<Option<i64>, _>("rowid")?,
                                row.try_get::<String, _>("parent")?,
                                row.try_get::<i64, _>("fkid")?,
                            ))
                        })
                        .collect::<Result<Vec<_>>>()?;
                    return Err(Error::engine(format!(
                        "{} left at least {} foreign-key violation(s): {}",
                        migration.name(),
                        details.len(),
                        details.join(", ")
                    )));
                }
            }
            // A long-running step may outlive a lease even though it began
            // while fenced. Its writes are still inside this transaction, so
            // revalidate before version stamping and roll everything back if
            // the background heartbeat lost ownership meanwhile.
            fence().await?;
            sqlx::query(&format!("PRAGMA user_version = {}", migration.to()))
                .execute(&mut connection)
                .await?;
            fence().await?;
            Ok::<(), Error>(())
        }
        .await;
        if let Err(err) = step {
            let _ = sqlx::query("ROLLBACK").execute(&mut connection).await;
            let _ = connection.close().await;
            return failed_with_backup(
                path,
                from,
                target,
                "apply",
                format!("{}: {err}", migration.name()),
                backup,
            );
        }
        if let Err(err) = sqlx::query("COMMIT").execute(&mut connection).await {
            let _ = sqlx::query("ROLLBACK").execute(&mut connection).await;
            let _ = connection.close().await;
            return failed_with_backup(path, from, target, "commit", err.to_string(), backup);
        }
        if foreign_keys_disabled {
            let restored = async {
                sqlx::query("PRAGMA foreign_keys=ON")
                    .execute(&mut connection)
                    .await?;
                let enabled: bool = sqlx::query_scalar("PRAGMA foreign_keys")
                    .fetch_one(&mut connection)
                    .await?;
                if !enabled {
                    return Err(Error::engine(
                        "foreign keys remained disabled after migration",
                    ));
                }
                Ok::<(), Error>(())
            }
            .await;
            if let Err(err) = restored {
                let _ = connection.close().await;
                return failed_with_backup(
                    path,
                    from,
                    target,
                    "commit",
                    format!("{}: {err}", migration.name()),
                    backup,
                );
            }
        }
        eprintln!(
            "migration-phase db_id={db_id:?} step={} phase=apply completed elapsed_ms={}",
            migration.name(),
            apply_started.elapsed().as_millis()
        );
    }
    eprintln!("migration-phase db_id={db_id:?} phase=final-integrity start");
    let final_integrity_started = std::time::Instant::now();
    let integrity = sqlx::query("PRAGMA integrity_check")
        .fetch_one(&mut connection)
        .await
        .map(|row| row.get::<String, _>(0));
    if !matches!(integrity, Ok(ref value) if value == "ok") {
        let message = match integrity {
            Ok(value) => value,
            Err(err) => err.to_string(),
        };
        let _ = connection.close().await;
        return failed_with_backup(path, from, target, "integrity", message, backup);
    }
    eprintln!(
        "migration-phase db_id={db_id:?} phase=final-integrity completed elapsed_ms={}",
        final_integrity_started.elapsed().as_millis()
    );
    let _ = connection.close().await;
    if target == CURRENT_ENGINE_SCHEMA_VERSION {
        let verification = match verifier.clone() {
            Some(verifier) => verifier(path.to_path_buf()).await,
            None => verify_migrated_database(path.to_path_buf(), db_id).await,
        };
        match verification {
            PostMigrationVerification::Passed => {}
            PostMigrationVerification::StructuralFailed(message) => {
                return failed_with_backup(path, from, target, "verify-shape", message, backup);
            }
            PostMigrationVerification::VerifyOpenFailed(message) => {
                return failed_with_backup(path, from, target, "verify-open", message, backup);
            }
            PostMigrationVerification::ConformanceFailed(message) => {
                return failed_with_backup(path, from, target, "conformance", message, backup);
            }
        }
    }
    DatabaseMigrationReport {
        path: path.to_path_buf(),
        from_version: Some(from),
        to_version: target,
        outcome: "migrated".into(),
        backup: Some(backup),
        error_kind: None,
        error_message: None,
    }
}

/// Run one database migration with a durable attempt-reservation hook.
///
/// Hosted fleet orchestration uses this seam to record the verified pre-image
/// before the first mutation without moving catalog ownership into the
/// portable migration module.
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub async fn migrate_database_with_attempt_reservation(
    path: &Path,
    db_id: &str,
    run_id: &str,
    target: i64,
    registry: &EngineMigrationRegistry,
    backup_options: &dyn MigrationPreimageStore,
    fence: FenceFn,
    reserve_attempt: AttemptReservationFn,
) -> DatabaseMigrationReport {
    migrate_database_with_reservation(
        path,
        db_id,
        run_id,
        target,
        registry,
        backup_options,
        fence,
        Some(reserve_attempt),
        None,
        #[cfg(test)]
        None,
    )
    .await
}

async fn verify_migrated_database(path: PathBuf, db_id: &str) -> PostMigrationVerification {
    eprintln!("migration-verification db_id={db_id:?} check=shape phase=start");
    let shape_started = std::time::Instant::now();
    if let Err(err) = crate::db::validate_current_engine_shape_read_only(&path).await {
        return PostMigrationVerification::StructuralFailed(err.to_string());
    }
    eprintln!(
        "migration-verification db_id={db_id:?} check=shape phase=passed elapsed_ms={}",
        shape_started.elapsed().as_millis()
    );
    eprintln!("migration-verification db_id={db_id:?} check=open phase=start");
    let open_started = std::time::Instant::now();
    let db = match crate::db::open_existing_database_at(&path).await {
        Ok(db) => db,
        Err(err) => {
            return PostMigrationVerification::VerifyOpenFailed(err.to_string());
        }
    };
    eprintln!(
        "migration-verification db_id={db_id:?} check=open phase=passed elapsed_ms={}",
        open_started.elapsed().as_millis()
    );
    let conformance = crate::conformance::run_conformance_with_progress(&db, |name, elapsed| {
        if let Some(elapsed_ms) = elapsed {
            eprintln!(
                "migration-verification db_id={db_id:?} check={name} phase=completed elapsed_ms={elapsed_ms}"
            );
        } else {
            eprintln!("migration-verification db_id={db_id:?} check={name} phase=start");
        }
    })
    .await;
    db.close().await;
    if conformance.ok {
        PostMigrationVerification::Passed
    } else {
        PostMigrationVerification::ConformanceFailed(format!("{conformance:?}"))
    }
}

fn failed(
    path: &Path,
    from: Option<i64>,
    to: i64,
    kind: &str,
    message: String,
) -> DatabaseMigrationReport {
    DatabaseMigrationReport {
        path: path.to_path_buf(),
        from_version: from,
        to_version: to,
        outcome: "failed".into(),
        backup: None,
        error_kind: Some(kind.into()),
        error_message: Some(message),
    }
}

fn failed_with_backup(
    path: &Path,
    from: i64,
    to: i64,
    kind: &str,
    message: String,
    backup: PreimageBackup,
) -> DatabaseMigrationReport {
    let mut report = failed(path, Some(from), to, kind, message);
    report.backup = Some(backup);
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::{BackupSink, FsSink};
    use sha2::{Digest, Sha256};
    use sqlx::Row;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    #[derive(Clone)]
    struct TestPreimageStore {
        sink: Arc<dyn BackupSink>,
    }

    impl MigrationPreimageStore for TestPreimageStore {
        fn store_verified_preimage(
            &self,
            run_id: &str,
            db_id: &str,
            source: &Path,
        ) -> BoxFuture<'static, Result<PreimageBackup>> {
            let sink = self.sink.clone();
            let key = format!("_migrations/{run_id}/{db_id}.preimage.db");
            let source = source.to_path_buf();
            async move {
                let expected = tokio::fs::read(&source).await?;
                let digest = hex::encode(Sha256::digest(&expected));
                sink.put(key.clone(), source.clone()).await?;
                let readback = source.with_extension("readback.db");
                sink.get(key.clone(), readback.clone()).await?;
                let actual = tokio::fs::read(&readback).await?;
                let _ = tokio::fs::remove_file(&readback).await;
                if actual != expected {
                    return Err(Error::engine("test pre-image readback mismatch"));
                }
                Ok(PreimageBackup { key, digest })
            }
            .boxed()
        }
    }

    fn test_preimage_store(offbox: &Path, data_dir: &Path) -> TestPreimageStore {
        TestPreimageStore {
            sink: Arc::new(FsSink::outside(offbox, data_dir).unwrap()),
        }
    }

    async fn create_current_schema(path: &Path) {
        crate::create_database(&path.to_string_lossy())
            .await
            .unwrap()
            .close()
            .await;
    }

    fn synthetic_zero_to_current_registry() -> EngineMigrationRegistry {
        let migrations = (0..CURRENT_ENGINE_SCHEMA_VERSION)
            .map(|from| {
                Arc::new(EngineMigration {
                    from,
                    to: from + 1,
                    name: format!("synthetic-{from}-to-{}", from + 1),
                    preflight: vec![],
                    apply: vec![],
                }) as Arc<dyn EngineMigrationStep>
            })
            .collect();
        EngineMigrationRegistry::new(CURRENT_ENGINE_SCHEMA_VERSION, 0, migrations).unwrap()
    }

    fn header_version(path: &Path) -> i64 {
        rusqlite::Connection::open(path)
            .unwrap()
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap()
    }

    /// Apply remaining production `apply` bodies and stamp `user_version` on
    /// this already-open connection so later `open_existing_database_at` sees
    /// the current header.
    ///
    /// This is not the production runner: it does not `BEGIN IMMEDIATE` /
    /// `COMMIT` around each step, capture a preimage, or fence. Compaction
    /// still runs in autocommit when a step asks for it, and foreign keys
    /// are toggled around rebuilds. Tests that need the runner's transactional
    /// stamp/rollback contract use `migrate_database_with_reservation`.
    async fn apply_remaining_production_steps(connection: &mut SqliteConnection, from: i64) {
        let mut version = from;
        for step in EngineMigrationRegistry::production()
            .pending(from, CURRENT_ENGINE_SCHEMA_VERSION)
            .unwrap()
        {
            assert_eq!(step.from(), version);
            if step.requires_pre_apply_compaction() {
                compact_database_in_place(connection, step.as_ref(), "fixture")
                    .await
                    .unwrap();
            }
            let foreign_keys_disabled = step.requires_foreign_keys_disabled();
            if foreign_keys_disabled {
                sqlx::query("PRAGMA foreign_keys=OFF")
                    .execute(&mut *connection)
                    .await
                    .unwrap();
            }
            step.apply(connection).await.unwrap();
            if foreign_keys_disabled {
                sqlx::query("PRAGMA foreign_keys=ON")
                    .execute(&mut *connection)
                    .await
                    .unwrap();
            }
            sqlx::query(&format!("PRAGMA user_version = {}", step.to()))
                .execute(&mut *connection)
                .await
                .unwrap();
            version = step.to();
        }
        assert_eq!(version, CURRENT_ENGINE_SCHEMA_VERSION);
    }

    #[tokio::test]
    async fn real_post_migration_verifier_covers_pass_and_structural_failure() {
        let dir = tempfile::tempdir().unwrap();
        let passing = dir.path().join("passing.db");
        create_current_schema(&passing).await;
        assert!(matches!(
            verify_migrated_database(passing, "passing-fixture").await,
            PostMigrationVerification::Passed
        ));

        let nonconformant = dir.path().join("nonconformant.db");
        let db = crate::create_database(&nonconformant.to_string_lossy())
            .await
            .unwrap();
        sqlx::query("DROP TABLE jobs")
            .execute(db.write_pool())
            .await
            .unwrap();
        db.close().await;
        assert!(matches!(
            verify_migrated_database(nonconformant, "nonconformant-fixture").await,
            PostMigrationVerification::StructuralFailed(_)
        ));
    }

    #[tokio::test]
    async fn synthetic_current_target_runs_the_real_verifier() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("user.db");
        create_current_schema(&path).await;
        let offbox = tempfile::tempdir().unwrap();
        let backup = test_preimage_store(offbox.path(), dir.path());
        let report = migrate_database_with_reservation(
            &path,
            "passing-user",
            "passing-run",
            CURRENT_ENGINE_SCHEMA_VERSION,
            &synthetic_zero_to_current_registry(),
            &backup,
            Arc::new(|| async { Ok(()) }.boxed()),
            None,
            None,
            Some(DatabaseVersionState::Known(0)),
        )
        .await;

        assert_eq!(report.outcome, "migrated", "{report:?}");
        crate::open_existing_database_at(&path)
            .await
            .unwrap()
            .close()
            .await;
    }

    #[tokio::test]
    async fn failed_post_migration_verification_reports_a_restorable_preimage() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("user.db");
        create_current_schema(&path).await;
        let offbox = tempfile::tempdir().unwrap();
        let backup = test_preimage_store(offbox.path(), dir.path());
        let verifier: PostMigrationVerifier = Arc::new(|_| {
            async {
                PostMigrationVerification::ConformanceFailed(
                    "injected post-commit conformance refusal".into(),
                )
            }
            .boxed()
        });
        let report = migrate_database_with_reservation(
            &path,
            "conformance-user",
            "conformance-run",
            CURRENT_ENGINE_SCHEMA_VERSION,
            &synthetic_zero_to_current_registry(),
            &backup,
            Arc::new(|| async { Ok(()) }.boxed()),
            None,
            Some(verifier),
            Some(DatabaseVersionState::Known(0)),
        )
        .await;

        assert_eq!(report.outcome, "failed");
        assert_eq!(report.error_kind.as_deref(), Some("conformance"));
        let captured = report.backup.expect("verified preimage");
        let restored = dir.path().join("restored-preimage.db");
        backup
            .sink
            .get(captured.key, restored.clone())
            .await
            .unwrap();
        assert_eq!(header_version(&restored), CURRENT_ENGINE_SCHEMA_VERSION);
        crate::open_existing_database_at(&restored)
            .await
            .unwrap()
            .close()
            .await;
    }

    /// Undo engine 50's webhook storage and attestation vocabulary, leaving
    /// the released engine-49 shape.
    async fn revert_to_engine_49(connection: &mut SqliteConnection) {
        revert_to_engine_50(connection).await;
        let enforcing: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
            .fetch_one(&mut *connection)
            .await
            .unwrap();
        sqlx::query("PRAGMA foreign_keys=OFF")
            .execute(&mut *connection)
            .await
            .unwrap();
        for statement in [
            "DROP INDEX IF EXISTS webhook_deliveries_recent",
            "DROP INDEX IF EXISTS webhook_deliveries_accepted_external",
            "DROP TABLE IF EXISTS webhook_deliveries",
            "DROP INDEX IF EXISTS webhook_credentials_live",
            "DROP TABLE IF EXISTS webhook_credentials",
            "DROP TABLE IF EXISTS webhook_endpoints",
            "PRAGMA legacy_alter_table=ON",
            "ALTER TABLE provenance_action_attestations RENAME TO provenance_action_attestations_v50",
            r#"CREATE TABLE provenance_action_attestations (
     id                      TEXT PRIMARY KEY,
     schema_version          INTEGER NOT NULL CHECK (schema_version IN (1,2)),
     principal               TEXT NOT NULL CHECK (length(trim(principal)) > 0),
     executor_kind           TEXT NOT NULL CHECK (executor_kind IN ('human','agent','authenticated_principal','local')),
     -- Server-observed transport. A THIRD axis beside principal and executor
     -- kind: weaker than executor_kind and never a substitute for it. Rows
     -- written before a host declared a transport read as 'unknown', which is
     -- the honest absence of an observation, not a fourth transport.
     channel                 TEXT NOT NULL DEFAULT 'unknown' CHECK (channel IN ('web','mcp','local','unknown')),
     executor_ref            TEXT,
     delegation_ref          TEXT,
     interaction_receipt_id  TEXT REFERENCES provenance_interaction_receipts(id),
     operation               TEXT NOT NULL CHECK (length(trim(operation)) > 0),
     action_commitment       TEXT NOT NULL CHECK (json_valid(action_commitment)),
     action_digest           TEXT NOT NULL CHECK (length(action_digest) = 64),
     output_event_set_digest TEXT NOT NULL CHECK (length(output_event_set_digest) = 64),
     issuer                  TEXT NOT NULL CHECK (length(trim(issuer)) > 0),
     issuer_origin_database_id TEXT NOT NULL CHECK (
       length(issuer_origin_database_id) = 36
       AND substr(issuer_origin_database_id, 1, 4) = 'ndb_'
       AND substr(issuer_origin_database_id, 5) NOT GLOB '*[^0-9a-f]*'
     ),
     issued_at               TEXT NOT NULL,
     command_identity_digest TEXT CHECK (command_identity_digest IS NULL OR length(command_identity_digest) = 64),
     intent_digest           TEXT CHECK (intent_digest IS NULL OR length(intent_digest) = 64)
   )"#,
            r#"INSERT INTO provenance_action_attestations
                 (id,schema_version,principal,executor_kind,channel,executor_ref,
                  delegation_ref,interaction_receipt_id,operation,action_commitment,
                  action_digest,output_event_set_digest,issuer,issuer_origin_database_id,
                  issued_at,command_identity_digest,intent_digest)
               SELECT id,schema_version,principal,executor_kind,channel,executor_ref,
                      delegation_ref,interaction_receipt_id,operation,action_commitment,
                      action_digest,output_event_set_digest,issuer,issuer_origin_database_id,
                      issued_at,command_identity_digest,intent_digest
                 FROM provenance_action_attestations_v50"#,
            "DROP TABLE provenance_action_attestations_v50",
            r#"CREATE INDEX idx_provenance_action_principal
                 ON provenance_action_attestations(principal, issued_at, id)"#,
            r#"CREATE INDEX idx_provenance_action_command
                 ON provenance_action_attestations(principal, operation, command_identity_digest)
                 WHERE command_identity_digest IS NOT NULL"#,
            r#"CREATE TRIGGER provenance_action_attestations_no_update
                 BEFORE UPDATE ON provenance_action_attestations
                 BEGIN SELECT RAISE(ABORT, 'provenance_action_attestations is append-only'); END"#,
            r#"CREATE TRIGGER provenance_action_attestations_no_delete
                 BEFORE DELETE ON provenance_action_attestations
                 BEGIN SELECT RAISE(ABORT, 'provenance_action_attestations is append-only'); END"#,
            "PRAGMA legacy_alter_table=OFF",
        ] {
            sqlx::query(statement)
                .execute(&mut *connection)
                .await
                .unwrap();
        }
        if enforcing != 0 {
            sqlx::query("PRAGMA foreign_keys=ON")
                .execute(&mut *connection)
                .await
                .unwrap();
        }
    }

    /// Undo engine-56 act stamping, leaving the released engine-55 shape.
    /// `DROP COLUMN` rewrites the stored table text, so the reverted tables
    /// compare equal to fresh engine-55 DDL under the shape contract.
    async fn revert_to_engine_55(connection: &mut SqliteConnection) {
        // The engine-58 `agent_runs` columns land after this shape, so the
        // engine-55 preimage drops them first alongside the triggers below.
        revert_to_engine_57(connection).await;
        // The content-event append-only triggers land in engine 57, so the
        // engine-55 preimage drops them alongside the act columns below.
        sqlx::query("DROP TRIGGER content_events_no_update")
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query("DROP TRIGGER content_events_no_delete")
            .execute(&mut *connection)
            .await
            .unwrap();
        for table in [
            "content_events",
            "policy_events",
            "awareness_events",
            "notification_candidate_events",
            "binding_audit",
            "database_identity_audit",
            "meta_events",
            "control_events",
            "derivation_events",
            "relationship_events",
        ] {
            sqlx::query(&format!("ALTER TABLE {table} DROP COLUMN act"))
                .execute(&mut *connection)
                .await
                .unwrap();
        }
        sqlx::query("DROP TABLE act_cutover")
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query("DROP TABLE act_state")
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query("PRAGMA user_version=55")
            .execute(&mut *connection)
            .await
            .unwrap();
    }

    /// Reconstruct the released engine-56 shape: current DDL minus exactly
    /// the two content-event append-only triggers and the three engine-58
    /// `agent_runs` columns. Test fixtures retain their absence; this is not
    /// a rollback API.
    async fn revert_to_engine_56(connection: &mut SqliteConnection) {
        revert_to_engine_57(connection).await;
        sqlx::query("DROP TRIGGER content_events_no_update")
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query("DROP TRIGGER content_events_no_delete")
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query("PRAGMA user_version=56")
            .execute(&mut *connection)
            .await
            .unwrap();
    }

    /// Reconstruct main's released engine-59 shape by reversing the three
    /// act-delta edges. Test fixtures only; this is not a rollback API.
    async fn revert_to_engine_59(connection: &mut SqliteConnection) {
        revert_to_engine_64(connection).await;
        for statement in [
            "DROP INDEX idx_external_observations_act",
            "ALTER TABLE external_observations DROP COLUMN act",
            "DROP INDEX idx_awareness_command_intents_act",
            "ALTER TABLE awareness_command_intents DROP COLUMN act",
            "DROP INDEX idx_content_events_act",
            "DROP INDEX idx_policy_events_act",
            "DROP INDEX idx_awareness_events_act",
            "DROP INDEX idx_notification_candidate_events_act",
            "DROP INDEX idx_binding_audit_act",
            "DROP INDEX idx_database_identity_audit_act",
            "DROP INDEX idx_meta_events_act",
            "DROP INDEX idx_control_events_act",
            "DROP INDEX idx_derivation_events_act",
            "DROP INDEX idx_relationship_events_act",
            "DROP TRIGGER binding_systems_no_insert",
            "DROP TRIGGER binding_systems_no_update",
            "DROP TRIGGER binding_systems_no_delete",
            "DROP INDEX idx_provenance_validity_act",
            "ALTER TABLE provenance_attestation_validity_events DROP COLUMN act",
        ] {
            sqlx::query(statement)
                .execute(&mut *connection)
                .await
                .unwrap();
        }
        sqlx::query("PRAGMA user_version=59")
            .execute(&mut *connection)
            .await
            .unwrap();
    }

    /// Remove main's record-mentions edge from the engine-59 preimage.
    async fn revert_to_engine_58(connection: &mut SqliteConnection) {
        revert_to_engine_59(connection).await;
        sqlx::query("DROP TABLE record_mentions")
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query("PRAGMA user_version=58")
            .execute(&mut *connection)
            .await
            .unwrap();
    }

    /// Advance a focused historical-edge fixture to the current schema
    /// before ordinary reopen, starting at its verified source version.
    async fn advance_engine_58_to_current(connection: &mut SqliteConnection, start: i64) {
        for (from, to, name) in [
            (58, 59, "engine-58-to-59-record-mentions-projection"),
            (59, 60, "engine-59-to-60-provenance-validity-act-stamping"),
            (60, 61, "engine-60-to-61-canonical-act-range-indexes"),
            (61, 62, "engine-61-to-62-observation-intent-act-stamping"),
            (62, 63, "engine-62-to-63-read-log-selective-cleanup"),
            (63, 64, "engine-63-to-64-read-log-freelist-compaction"),
            (64, 65, "engine-64-to-65-alpha-tab-installs-projection"),
        ] {
            if from < start {
                continue;
            }
            let step = EngineMigrationRegistry::production()
                .pending(from, to)
                .unwrap()
                .pop()
                .unwrap();
            assert_eq!(step.name(), name);
            step.preflight(&mut *connection).await.unwrap();
            if step.requires_pre_apply_compaction() {
                compact_database_in_place(connection, step.as_ref(), "fixture")
                    .await
                    .unwrap();
            }
            step.apply(&mut *connection).await.unwrap();
            sqlx::query(&format!("PRAGMA user_version={to}"))
                .execute(&mut *connection)
                .await
                .unwrap();
            assert!(
                crate::db::validate_engine_shape_on_for_test(&mut *connection, to)
                    .await
                    .unwrap()
            );
        }
    }

    /// Reconstruct the released engine-57 shape: engine 58 minus exactly the
    /// three `agent_runs` reported-identity columns. `DROP COLUMN`
    /// rewrites the stored table text, so the reverted table compares equal
    /// to fresh engine-57 DDL under the shape contract. Test fixtures retain
    /// the columns' absence; this is not a rollback API.
    async fn revert_to_engine_57(connection: &mut SqliteConnection) {
        revert_to_engine_58(connection).await;
        for column in [
            "reported_mcp_client_name",
            "reported_mcp_client_version",
            "reported_model",
        ] {
            sqlx::query(&format!("ALTER TABLE agent_runs DROP COLUMN {column}"))
                .execute(&mut *connection)
                .await
                .unwrap();
        }
        sqlx::query("PRAGMA user_version=57")
            .execute(&mut *connection)
            .await
            .unwrap();
    }

    /// Reconstruct the released TEXT-key shape before dictionary interning.
    /// Test fixtures retain every decoded touch; this is not a rollback API.
    async fn revert_to_engine_53(connection: &mut SqliteConnection) {
        revert_to_engine_55(connection).await;
        let enforcing: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
            .fetch_one(&mut *connection)
            .await
            .unwrap();
        sqlx::query("PRAGMA foreign_keys=OFF")
            .execute(&mut *connection)
            .await
            .unwrap();
        for statement in [
            "PRAGMA legacy_alter_table=ON",
            "ALTER TABLE read_log_touches RENAME TO read_log_touches_v54",
            "CREATE TABLE read_log_touches (call_seq INTEGER NOT NULL REFERENCES read_log_calls(seq) ON DELETE CASCADE, record_id TEXT NOT NULL, interaction TEXT NOT NULL CHECK (interaction IN ('surfaced','opened','mutated')), result_rank INTEGER, PRIMARY KEY (call_seq, record_id, interaction)) WITHOUT ROWID",
            "INSERT INTO read_log_touches SELECT t.call_seq,d.record_id,t.interaction,t.result_rank FROM read_log_touches_v54 t JOIN read_log_record_ids d ON d.record_ref=t.record_ref ORDER BY t.call_seq,d.record_id,t.interaction",
            "DROP TABLE read_log_touches_v54",
            "DROP TABLE read_log_record_ids",
            "CREATE INDEX idx_read_log_touches_record ON read_log_touches(record_id, call_seq)",
            "PRAGMA legacy_alter_table=OFF",
            "PRAGMA user_version=53",
        ] {
            sqlx::query(statement).execute(&mut *connection).await.unwrap();
        }
        if enforcing != 0 {
            sqlx::query("PRAGMA foreign_keys=ON")
                .execute(&mut *connection)
                .await
                .unwrap();
        }
    }

    /// Undo engine 52's WITHOUT ROWID rebuild, leaving the released
    /// engine-51 rowid physical shape (autoindex-backed composite PK).
    async fn revert_to_engine_51(connection: &mut SqliteConnection) {
        revert_to_engine_53(connection).await;
        let enforcing: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
            .fetch_one(&mut *connection)
            .await
            .unwrap();
        sqlx::query("PRAGMA foreign_keys=OFF")
            .execute(&mut *connection)
            .await
            .unwrap();
        for statement in [
            "PRAGMA legacy_alter_table=ON",
            "ALTER TABLE read_log_touches RENAME TO read_log_touches_v52",
            r#"CREATE TABLE read_log_touches (
     call_seq     INTEGER NOT NULL REFERENCES read_log_calls(seq) ON DELETE CASCADE,
     record_id    TEXT NOT NULL,
     interaction  TEXT NOT NULL CHECK (interaction IN ('surfaced','opened','mutated')),
     result_rank  INTEGER,
     PRIMARY KEY (call_seq, record_id, interaction)
   )"#,
            r#"INSERT INTO read_log_touches
                 (call_seq, record_id, interaction, result_rank)
               SELECT call_seq, record_id, interaction, result_rank
                 FROM read_log_touches_v52
                ORDER BY call_seq, record_id, interaction"#,
            "DROP TABLE read_log_touches_v52",
            r#"CREATE INDEX idx_read_log_touches_record ON read_log_touches(record_id, call_seq)"#,
            "PRAGMA legacy_alter_table=OFF",
        ] {
            sqlx::query(statement)
                .execute(&mut *connection)
                .await
                .unwrap();
        }
        if enforcing != 0 {
            sqlx::query("PRAGMA foreign_keys=ON")
                .execute(&mut *connection)
                .await
                .unwrap();
        }
    }

    /// Undo engine 51's nullable read-log result annotation, leaving the
    /// released engine-50 physical shape.  It is intentionally a schema-only
    /// reversal for test reconstruction: historical annotations are not
    /// inferred or backfilled by the real forward migration.
    async fn revert_to_engine_50(connection: &mut SqliteConnection) {
        revert_to_engine_51(connection).await;
        let enforcing: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
            .fetch_one(&mut *connection)
            .await
            .unwrap();
        sqlx::query("PRAGMA foreign_keys=OFF")
            .execute(&mut *connection)
            .await
            .unwrap();
        for statement in [
            "DROP INDEX idx_read_log_calls_overlap_annotation",
            "PRAGMA legacy_alter_table=ON",
            "ALTER TABLE read_log_calls RENAME TO read_log_calls_v51",
            r#"CREATE TABLE read_log_calls (
     seq          INTEGER PRIMARY KEY AUTOINCREMENT,
     id           TEXT NOT NULL UNIQUE,
     tool         TEXT NOT NULL,
     run_key      TEXT,
     parent_key   TEXT,
     intent       TEXT,
     actor        TEXT,
     arguments    TEXT,
     outcome      TEXT NOT NULL CHECK (outcome IN ('ok','error')),
     error_kind   TEXT,
     result_count INTEGER,
     result_bytes INTEGER,
     started_at   TEXT NOT NULL,
     ended_at     TEXT NOT NULL
   )"#,
            r#"INSERT INTO read_log_calls
                 (seq,id,tool,run_key,parent_key,intent,actor,arguments,outcome,error_kind,
                  result_count,result_bytes,started_at,ended_at)
              SELECT seq,id,tool,run_key,parent_key,intent,actor,arguments,outcome,error_kind,
                     result_count,result_bytes,started_at,ended_at
                FROM read_log_calls_v51"#,
            "DROP TABLE read_log_calls_v51",
            "CREATE INDEX idx_read_log_calls_run ON read_log_calls(run_key, seq)",
            "CREATE INDEX idx_read_log_calls_started ON read_log_calls(started_at)",
            "PRAGMA legacy_alter_table=OFF",
        ] {
            sqlx::query(statement)
                .execute(&mut *connection)
                .await
                .unwrap();
        }
        if enforcing != 0 {
            sqlx::query("PRAGMA foreign_keys=ON")
                .execute(&mut *connection)
                .await
                .unwrap();
        }
    }

    /// Undo engine 49's canvas projection tables, leaving released engine 48
    /// (structurally identical to engine 47). Idempotent so a reconstruction
    /// chain may call it directly or through a later revert.
    async fn revert_to_engine_48(connection: &mut SqliteConnection) {
        revert_to_engine_49(connection).await;
        for statement in [
            "DROP INDEX IF EXISTS canvas_objects_live",
            "DROP TABLE IF EXISTS canvas_batches",
            "DROP TABLE IF EXISTS canvas_objects",
        ] {
            sqlx::query(statement)
                .execute(&mut *connection)
                .await
                .unwrap();
        }
    }

    /// Undo engine 47's authorization-epoch guards, leaving released engine 46.
    async fn revert_to_engine_46(connection: &mut SqliteConnection) {
        revert_to_engine_48(connection).await;
        for statement in [
            "DROP TRIGGER authorization_revision_records_update",
            r#"CREATE TRIGGER authorization_revision_records_update
       AFTER UPDATE OF owner_id, policy_anchor_id, deleted_at, type, kind ON records
       BEGIN UPDATE authorization_revision SET epoch = epoch + 1 WHERE id = 1; END"#,
            "DROP TRIGGER authorization_revision_record_policies_update",
            r#"CREATE TRIGGER authorization_revision_record_policies_update AFTER UPDATE ON record_policies
       BEGIN UPDATE authorization_revision SET epoch = epoch + 1 WHERE id = 1; END"#,
            "DROP TRIGGER authorization_revision_policy_entries_update",
            r#"CREATE TRIGGER authorization_revision_policy_entries_update AFTER UPDATE ON policy_entries
       BEGIN UPDATE authorization_revision SET epoch = epoch + 1 WHERE id = 1; END"#,
            "DROP TRIGGER authorization_revision_bindings_update",
            r#"CREATE TRIGGER authorization_revision_bindings_update AFTER UPDATE ON bindings
       WHEN OLD.system = 'account' OR NEW.system = 'account'
       BEGIN UPDATE authorization_revision SET epoch = epoch + 1 WHERE id = 1; END"#,
            "DROP TRIGGER authorization_revision_links_update",
            r#"CREATE TRIGGER authorization_revision_links_update AFTER UPDATE ON links
       WHEN OLD.relationship = 'part_of' OR NEW.relationship = 'part_of'
       BEGIN UPDATE authorization_revision SET epoch = epoch + 1 WHERE id = 1; END"#,
        ] {
            sqlx::query(statement)
                .execute(&mut *connection)
                .await
                .unwrap();
        }
    }

    /// Reconstruct the released engine-45 predecessor from a fresh engine-46
    /// database. This is test authority for the 45→46 edge and the common
    /// first step for every older predecessor reconstruction below it.
    async fn revert_to_engine_45(connection: &mut SqliteConnection) {
        revert_to_engine_46(connection).await;
        let enforcing: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
            .fetch_one(&mut *connection)
            .await
            .unwrap();
        sqlx::query("PRAGMA foreign_keys=OFF")
            .execute(&mut *connection)
            .await
            .unwrap();
        for statement in [
            "DROP TABLE content_event_causal_frontier",
            "DROP TABLE content_event_causal_cutover",
            "PRAGMA legacy_alter_table=ON",
            "ALTER TABLE content_events RENAME TO content_events_v46",
            r#"CREATE TABLE content_events (
     seq        INTEGER PRIMARY KEY AUTOINCREMENT,
     id         TEXT NOT NULL UNIQUE,
     record_id  TEXT NOT NULL,
     type       TEXT NOT NULL,
     payload    TEXT,
     actor      TEXT,
     run_key    TEXT,
     parent_key TEXT,
     intent     TEXT,
     created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
   )"#,
            r#"INSERT INTO content_events
                 (seq,id,record_id,type,payload,actor,run_key,parent_key,intent,created_at)
               SELECT seq,id,record_id,type,payload,actor,run_key,parent_key,intent,created_at
                 FROM content_events_v46"#,
            "DROP TABLE content_events_v46",
            r#"CREATE INDEX idx_content_events_record ON content_events(record_id, seq)"#,
            r#"CREATE INDEX idx_content_events_run ON content_events(run_key, seq)"#,
            "ALTER TABLE replicated_message_provenance RENAME TO replicated_message_provenance_v46",
            r#"CREATE TABLE replicated_message_provenance (
     source_event_id      TEXT PRIMARY KEY REFERENCES content_event_sources(event_id) ON DELETE CASCADE,
     content_version      TEXT NOT NULL CHECK (content_version = 'native.message.v1'),
     operation            TEXT NOT NULL CHECK (operation = 'message.created'),
     source_account_token TEXT NOT NULL CHECK (length(trim(source_account_token)) > 0),
     source_created_at    TEXT NOT NULL,
     canonical_payload    TEXT NOT NULL CHECK (json_valid(canonical_payload)),
     payload_digest       TEXT NOT NULL CHECK (length(payload_digest) = 64),
     envelope_id          TEXT,
     envelope_digest      TEXT,
     CHECK ((envelope_id IS NULL AND envelope_digest IS NULL)
         OR (envelope_id IS NOT NULL AND envelope_digest IS NOT NULL
             AND length(trim(envelope_id)) > 0 AND length(envelope_digest) = 64))
   )"#,
            r#"INSERT INTO replicated_message_provenance
                 (source_event_id,content_version,operation,source_account_token,
                  source_created_at,canonical_payload,payload_digest,envelope_id,envelope_digest)
               SELECT source_event_id,content_version,operation,source_account_token,
                      source_created_at,canonical_payload,payload_digest,envelope_id,envelope_digest
                 FROM replicated_message_provenance_v46"#,
            "DROP TABLE replicated_message_provenance_v46",
            "PRAGMA legacy_alter_table=OFF",
        ] {
            sqlx::query(statement)
                .execute(&mut *connection)
                .await
                .unwrap();
        }
        if enforcing == 1 {
            sqlx::query("PRAGMA foreign_keys=ON")
                .execute(&mut *connection)
                .await
                .unwrap();
        }
    }

    /// Undo engine 45's durable-run projection, leaving released engine 44.
    async fn revert_to_engine_44(connection: &mut SqliteConnection) {
        revert_to_engine_45(connection).await;
        sqlx::query("DROP TABLE agent_runs")
            .execute(&mut *connection)
            .await
            .unwrap();
    }

    /// Undo the engine-44 additive Message-origin projection, leaving the
    /// released engine-43 shape.
    async fn revert_to_engine_43(connection: &mut SqliteConnection) {
        revert_to_engine_44(connection).await;
        for statement in [
            "DROP TABLE message_origin_principals",
            "DROP TABLE message_origin_state",
        ] {
            sqlx::query(statement)
                .execute(&mut *connection)
                .await
                .unwrap();
        }
    }

    /// Undo the engine-43 change on a fresh current database, leaving the
    /// released engine-42 shape. Each edge's test reconstructs its own preimage
    /// by walking back from current, so every edge at or below 43 comes through
    /// here first.
    async fn revert_to_engine_42(connection: &mut SqliteConnection) {
        revert_to_engine_43(connection).await;
        // Rebuilding a table that other tables REFERENCE is only safe with
        // foreign keys fenced: SQLite ignores `legacy_alter_table` while they
        // are enforced and rewrites every referring clause to point at the
        // renamed table, which silently changes the shape being reconstructed.
        // This is the same fence the runner puts around the real edge.
        let enforcing: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
            .fetch_one(&mut *connection)
            .await
            .unwrap();
        sqlx::query("PRAGMA foreign_keys=OFF")
            .execute(&mut *connection)
            .await
            .unwrap();
        for statement in [
            "DROP TABLE member_destinations",
            "PRAGMA legacy_alter_table=ON",
            "ALTER TABLE awareness_events RENAME TO awareness_events_v43",
            r#"CREATE TABLE awareness_events (
     seq                    INTEGER PRIMARY KEY AUTOINCREMENT,
     id                     TEXT NOT NULL UNIQUE,
     idempotency_key        TEXT NOT NULL,
     intent_sha256          TEXT NOT NULL CHECK (length(intent_sha256) = 64),
     schema_version         INTEGER NOT NULL DEFAULT 1 CHECK (schema_version = 1),
     subject_account_id     TEXT NOT NULL CHECK (length(trim(subject_account_id)) > 0),
     message_id             TEXT NOT NULL CHECK (length(trim(message_id)) > 0),
     lane                   TEXT NOT NULL CHECK (lane IN ('human','agent','preference','routing')),
     action                 TEXT NOT NULL CHECK (length(trim(action)) > 0),
     authenticated_actor    TEXT NOT NULL CHECK (length(trim(authenticated_actor)) > 0),
     executor_kind          TEXT NOT NULL CHECK (executor_kind IN ('human_attested','agent','system')),
     executor_ref           TEXT,
     delegation_ref         TEXT,
     expected_version       INTEGER NOT NULL CHECK (expected_version >= 0),
     reason_code            TEXT NOT NULL CHECK (length(trim(reason_code)) > 0),
     interaction_nonce      TEXT,
     payload                TEXT NOT NULL CHECK (json_valid(payload)),
     created_at             TEXT NOT NULL,
     UNIQUE (subject_account_id, idempotency_key),
     UNIQUE (subject_account_id, message_id, interaction_nonce)
   )"#,
            "DROP TABLE awareness_events_v43",
            r#"CREATE INDEX idx_awareness_events_subject_seq
       ON awareness_events(subject_account_id, seq)"#,
            r#"CREATE INDEX idx_awareness_events_message
       ON awareness_events(message_id, subject_account_id, seq)"#,
            r#"CREATE TRIGGER awareness_events_no_update BEFORE UPDATE ON awareness_events
       BEGIN SELECT RAISE(ABORT, 'awareness_events is append-only'); END"#,
            r#"CREATE TRIGGER awareness_events_no_delete BEFORE DELETE ON awareness_events
       BEGIN SELECT RAISE(ABORT, 'awareness_events is append-only'); END"#,
            "PRAGMA legacy_alter_table=OFF",
        ] {
            sqlx::query(statement)
                .execute(&mut *connection)
                .await
                .unwrap();
        }
        if enforcing != 0 {
            sqlx::query("PRAGMA foreign_keys=ON")
                .execute(&mut *connection)
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn engine_40_to_41_drill_migration_moves_a_released_40_shape() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("drill.db");
        create_current_schema(&path).await;

        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();

        let registry = EngineMigrationRegistry::production();
        let pending = registry.pending(40, 41).unwrap();
        assert_eq!(pending.len(), 1);
        let step = &pending[0];
        assert_eq!(step.stable_id(), "engine-40-to-41-promotion-drill-table");

        // A current database merely restamped to 40 is not an admissible
        // 40 source: the header claims 40 but the shape is still 41's.
        sqlx::query("PRAGMA user_version = 40")
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(step.preflight(&mut conn).await.is_err());

        // Reconstruct the released engine-40 shape by walking current back:
        // undo 43's destination lane, then 42's appended drill column, then
        // 41's additive drill table. Preflight passing here is what proves
        // ENGINE_40_SHAPE_CONTRACT_SHA256 matches the released tree.
        revert_to_engine_42(&mut conn).await;
        sqlx::query("ALTER TABLE engine_migration_drills DROP COLUMN drill_stage")
            .execute(&mut conn)
            .await
            .unwrap();
        sqlx::query("DROP TABLE engine_migration_drills")
            .execute(&mut conn)
            .await
            .unwrap();
        step.preflight(&mut conn).await.unwrap();

        step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version = 41")
            .execute(&mut conn)
            .await
            .unwrap();
        crate::db::validate_supported_engine_migration_source(&mut conn, 41)
            .await
            .unwrap();

        let row = sqlx::query("SELECT from_version, to_version, note FROM engine_migration_drills")
            .fetch_one(&mut conn)
            .await
            .unwrap();
        assert_eq!(row.get::<i64, _>("from_version"), 40);
        assert_eq!(row.get::<i64, _>("to_version"), 41);
        assert_eq!(
            row.get::<String, _>("note"),
            "for-purpose pipeline drill migration"
        );
        conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn engine_41_to_42_migration_moves_a_released_41_shape() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manual-drill.db");
        create_current_schema(&path).await;

        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();

        let registry = EngineMigrationRegistry::production();
        let pending = registry.pending(41, 42).unwrap();
        assert_eq!(pending.len(), 1);
        let step = &pending[0];
        assert_eq!(
            step.stable_id(),
            "engine-41-to-42-manual-promotion-verification"
        );

        // A current database merely restamped to 41 is not an admissible
        // 41 source: the header claims 41 but the shape carries drill_stage.
        sqlx::query("PRAGMA user_version = 41")
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(step.preflight(&mut conn).await.is_err());

        // Reconstruct the released engine-41 shape by walking current back:
        // undo 43's destination lane, then 42's appended column. Preflight
        // passing here is what proves ENGINE_41_SHAPE_CONTRACT_SHA256 matches
        // the released tree.
        revert_to_engine_42(&mut conn).await;
        sqlx::query("ALTER TABLE engine_migration_drills DROP COLUMN drill_stage")
            .execute(&mut conn)
            .await
            .unwrap();
        step.preflight(&mut conn).await.unwrap();

        step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version = 42")
            .execute(&mut conn)
            .await
            .unwrap();
        crate::db::validate_supported_engine_migration_source(&mut conn, 42)
            .await
            .unwrap();

        let row = sqlx::query(
            "SELECT from_version, to_version, note, drill_stage FROM engine_migration_drills",
        )
        .fetch_one(&mut conn)
        .await
        .unwrap();
        assert_eq!(row.get::<i64, _>("from_version"), 41);
        assert_eq!(row.get::<i64, _>("to_version"), 42);
        assert_eq!(row.get::<String, _>("drill_stage"), "manual-promotion-test");
        conn.close().await.unwrap();
    }

    /// Reconstruct the released engine-42 shape from a fresh 43 database and
    /// prove the edge moves it. Preflight passing here is what proves
    /// ENGINE_42_SHAPE_CONTRACT_SHA256 matches the released tree, and the
    /// post-migration check proves a migrated 42 is exactly a fresh 43.
    #[tokio::test]
    async fn engine_42_to_43_migration_moves_a_released_42_shape() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("destination.db");
        create_current_schema(&path).await;

        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(false);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();

        let registry = EngineMigrationRegistry::production();
        let pending = registry.pending(42, 43).unwrap();
        assert_eq!(pending.len(), 1);
        let step = &pending[0];
        assert_eq!(
            step.stable_id(),
            "engine-42-to-43-awareness-destination-lane"
        );

        // A current database merely restamped to 42 is not an admissible 42
        // source: the header claims 42 but the shape carries the fifth lane.
        sqlx::query("PRAGMA user_version = 42")
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(step.preflight(&mut conn).await.is_err());

        revert_to_engine_42(&mut conn).await;
        sqlx::query(
            r#"INSERT INTO awareness_events
                 (seq,id,idempotency_key,intent_sha256,schema_version,subject_account_id,
                  message_id,lane,action,authenticated_actor,executor_kind,expected_version,
                  reason_code,payload,created_at)
               VALUES (41,'retained-event','retained-key',?,1,'acct:retained',
                       'message:retained','agent','agent.triaged','agent:test','agent',0,
                       'migration fixture',?, '2026-08-27T00:00:00.000Z')"#,
        )
        .bind("0".repeat(64))
        .bind(r#"{"state":"triaged","evidence":[{"record_id":"evidence:retained","role":"work"}]}"#)
        .execute(&mut conn)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO agent_message_dispositions
               (subject_account_id,message_id,state,reason_code,last_executor_ref,
                delegation_ref,last_event_seq,version)
             VALUES ('acct:retained','message:retained','triaged','migration fixture',
                     'agent:test',NULL,41,1)",
        )
        .execute(&mut conn)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO awareness_event_evidence
               (event_id,evidence_record_id,evidence_role)
             VALUES ('retained-event','evidence:retained','work')",
        )
        .execute(&mut conn)
        .await
        .unwrap();
        step.preflight(&mut conn).await.unwrap();
        step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version = 43")
            .execute(&mut conn)
            .await
            .unwrap();
        crate::db::validate_supported_engine_migration_source(&mut conn, 43)
            .await
            .unwrap();
        let retained: (i64, Option<String>, String) = sqlx::query_as(
            "SELECT seq,destination_id,payload FROM awareness_events WHERE id='retained-event'",
        )
        .fetch_one(&mut conn)
        .await
        .unwrap();
        assert_eq!(retained.0, 41);
        assert_eq!(retained.1, None);
        assert!(retained.2.contains("triaged"));
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT last_event_seq FROM agent_message_dispositions
                  WHERE subject_account_id='acct:retained' AND message_id='message:retained'",
            )
            .fetch_one(&mut conn)
            .await
            .unwrap(),
            41
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT evidence_record_id FROM awareness_event_evidence
                  WHERE event_id='retained-event'",
            )
            .fetch_one(&mut conn)
            .await
            .unwrap(),
            "evidence:retained"
        );
        let next_seq: i64 = sqlx::query_scalar(
            r#"INSERT INTO awareness_events
                 (id,idempotency_key,intent_sha256,schema_version,subject_account_id,
                  message_id,destination_id,lane,action,authenticated_actor,executor_kind,
                  expected_version,reason_code,payload,created_at)
               VALUES ('next-event','next-key',?,1,'acct:retained','message:next',NULL,
                       'preference','preference.flag_attention','agent:test','agent',0,
                       'migration fixture','{}','2026-08-27T00:00:01.000Z')
               RETURNING seq"#,
        )
        .bind("1".repeat(64))
        .fetch_one(&mut conn)
        .await
        .unwrap();
        assert_eq!(next_seq, 42, "copied sequence must advance AUTOINCREMENT");
        conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn engine_43_to_44_preserves_legacy_messages_as_origin_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("message-origin.db");
        create_current_schema(&path).await;
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        let registry = EngineMigrationRegistry::production();
        let step = registry.pending(43, 44).unwrap().pop().unwrap();

        sqlx::query("PRAGMA user_version = 43")
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(step.preflight(&mut conn).await.is_err());
        revert_to_engine_43(&mut conn).await;
        step.preflight(&mut conn).await.unwrap();
        sqlx::query(
            "INSERT INTO records
                (id,type,kind,name,home_id,policy_anchor_id,persistence,
                 created_at,updated_at,last_activity_at)
             VALUES ('43000000-0000-4000-8000-000000000044','Message','text','legacy',
                     'native:unfiled','native:root','enduring',?,?,?)",
        )
        .bind("2026-08-28T00:00:00.000Z")
        .bind("2026-08-28T01:00:00.000Z")
        .bind("2026-08-28T01:00:00.000Z")
        .execute(&mut conn)
        .await
        .unwrap();

        step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version = 44")
            .execute(&mut conn)
            .await
            .unwrap();
        crate::db::validate_supported_engine_migration_source(&mut conn, 44)
            .await
            .unwrap();
        let row: (String, Option<String>, String) = sqlx::query_as(
            "SELECT status,origin_type,updated_at FROM message_origin_state
              WHERE message_id='43000000-0000-4000-8000-000000000044'",
        )
        .fetch_one(&mut conn)
        .await
        .unwrap();
        assert_eq!(row.0, "legacy_unknown");
        assert_eq!(row.1, None);
        assert_eq!(row.2, "2026-08-28T00:00:00.000Z");
        conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn engine_44_to_45_adds_empty_durable_agent_runs_exactly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent-runs.db");
        create_current_schema(&path).await;
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        let step = EngineMigrationRegistry::production()
            .pending(44, 45)
            .unwrap()
            .pop()
            .unwrap();

        sqlx::query("PRAGMA user_version = 44")
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(step.preflight(&mut conn).await.is_err());
        revert_to_engine_44(&mut conn).await;
        let digest = crate::db::schema_shape_contract_sha256_for_test(&mut conn)
            .await
            .unwrap();
        assert_eq!(digest, crate::db::ENGINE_44_SHAPE_CONTRACT_SHA256);
        step.preflight(&mut conn).await.unwrap();

        step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version = 45")
            .execute(&mut conn)
            .await
            .unwrap();
        crate::db::validate_supported_engine_migration_source(&mut conn, 45)
            .await
            .unwrap();
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM agent_runs")
            .fetch_one(&mut conn)
            .await
            .unwrap();
        assert_eq!(count, 0, "transient engine-44 evidence is not backfilled");
        conn.close().await.unwrap();

        let runner_path = dir.path().join("agent-runs-runner.db");
        create_current_schema(&runner_path).await;
        let runner_options =
            SqliteConnectOptions::from_str(&format!("sqlite:{}", runner_path.display()))
                .unwrap()
                .foreign_keys(false);
        let mut runner_conn = SqliteConnection::connect_with(&runner_options)
            .await
            .unwrap();
        revert_to_engine_44(&mut runner_conn).await;
        sqlx::query("PRAGMA user_version = 44")
            .execute(&mut runner_conn)
            .await
            .unwrap();
        runner_conn.close().await.unwrap();
        let offbox = tempfile::tempdir().unwrap();
        let backup = test_preimage_store(offbox.path(), dir.path());
        let report = migrate_database_with_reservation(
            &runner_path,
            "agent-runs-user",
            "agent-runs-migration",
            CURRENT_ENGINE_SCHEMA_VERSION,
            &EngineMigrationRegistry::production(),
            &backup,
            Arc::new(|| async { Ok(()) }.boxed()),
            None,
            None,
            Some(DatabaseVersionState::Known(44)),
        )
        .await;
        assert_eq!(report.outcome, "migrated", "{report:?}");
        assert!(report.backup.is_some());
        crate::open_existing_database_at(&runner_path)
            .await
            .unwrap()
            .close()
            .await;
    }

    /// Parity/drift pin for the shared 45->46 and 46->47 statement sources.
    ///
    /// `ENGINE_45_TO_46_STATEMENTS` and `ENGINE_46_TO_47_STATEMENTS` are the
    /// single authoritative text for those edges: the reference SQLite steps
    /// (`Engine45To46Migration`, `Engine46To47Migration`) and the Turso-local
    /// runner (`crate::turso_local::migrate_existing_engine_schema`, behind
    /// `turso-local`) execute the same arrays through their own connection
    /// API, transactions, and error mapping. The Turso module is feature-gated
    /// out of this lane, so this test pins every byte and boundary in the
    /// shared statement sequences while the existing
    /// `engine_45_to_46_...` and `engine_46_to_47_...` tests prove the plan
    /// still migrates a released predecessor to its released successor shape.
    /// Any statement added, removed, reordered, or edited must deliberately
    /// update the corresponding digest.
    #[test]
    fn shared_45_to_47_statement_sources_have_parity() {
        fn sequence_digest(statements: &[&str]) -> String {
            let mut digest = Sha256::new();
            for statement in statements {
                digest.update((statement.len() as u64).to_be_bytes());
                digest.update(statement.as_bytes());
            }
            hex::encode(digest.finalize())
        }

        assert_eq!(ENGINE_45_TO_46_STATEMENTS.len(), 14);
        assert_eq!(ENGINE_46_TO_47_STATEMENTS.len(), 10);
        assert_eq!(
            sequence_digest(&ENGINE_45_TO_46_STATEMENTS),
            "0debf903e618e3aecae35acce358b27ab4681605087252e7271c522c9668f7aa"
        );
        assert_eq!(
            sequence_digest(&ENGINE_46_TO_47_STATEMENTS),
            "dfa830b218c2d0906f188658beec52156e394803fdd12f76d70a5299a0b375bb"
        );

        // Both edges stay bound to the production registry under stable ids.
        let registry = EngineMigrationRegistry::production();
        let edges = registry.capability_edges();
        for (from, to, stable_id) in [
            (45, 46, "engine-45-to-46-content-event-causal-frontiers"),
            (46, 47, "engine-46-to-47-value-changed-authorization-epoch"),
        ] {
            assert!(
                edges.iter().any(|edge| {
                    edge.from == from && edge.to == to && edge.stable_id == stable_id
                }),
                "production registry lost the {from}->{to} edge {stable_id}"
            );
        }
    }

    #[tokio::test]
    async fn engine_45_to_46_classifies_legacy_events_without_inventing_frontiers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("content-causality.db");
        create_current_schema(&path).await;
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(false);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        let step = EngineMigrationRegistry::production()
            .pending(45, 46)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(
            step.stable_id(),
            "engine-45-to-46-content-event-causal-frontiers"
        );

        // Restamping current shape does not manufacture an admissible
        // predecessor. Reconstruct and measure the immutable engine-45 shape.
        sqlx::query("PRAGMA user_version = 45")
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(step.preflight(&mut conn).await.is_err());
        revert_to_engine_45(&mut conn).await;
        let digest = crate::db::schema_shape_contract_sha256_for_test(&mut conn)
            .await
            .unwrap();
        assert_eq!(digest, crate::db::ENGINE_45_SHAPE_CONTRACT_SHA256);

        // Preserve a nontrivial replay position and a v1 source-provenance row
        // across both table rebuilds.
        sqlx::query(
            "INSERT INTO content_events
                (seq,id,record_id,type,payload,actor,run_key,parent_key,intent,created_at)
             VALUES (41,'45000000-0000-4000-8000-000000000046',
                     '45000000-0000-4000-8000-000000000045','record.created','{}',
                     'migration:test',NULL,NULL,NULL,'2026-09-01T00:00:00.000Z')",
        )
        .execute(&mut conn)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO content_event_sources
                (event_id,origin_database_id,source_seq,source_record_id,source_principal,source_fingerprint)
             VALUES ('45000000-0000-4000-8000-000000000046','ndb_source',7,
                     '45000000-0000-4000-8000-000000000045','native:principal',?)",
        )
        .bind("1".repeat(64))
        .execute(&mut conn)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO replicated_message_provenance
                (source_event_id,content_version,operation,source_account_token,
                 source_created_at,canonical_payload,payload_digest)
             VALUES ('45000000-0000-4000-8000-000000000046','native.message.v1',
                     'message.created','account:source','2026-09-01T00:00:00.000Z','{}',?)",
        )
        .bind("2".repeat(64))
        .execute(&mut conn)
        .await
        .unwrap();
        step.preflight(&mut conn).await.unwrap();

        step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version = 46")
            .execute(&mut conn)
            .await
            .unwrap();
        crate::db::validate_supported_engine_migration_source(&mut conn, 46)
            .await
            .unwrap();

        let migrated: (i64, i64, String) = sqlx::query_as(
            "SELECT seq,causal_envelope_version,causal_status
               FROM content_events
              WHERE id='45000000-0000-4000-8000-000000000046'",
        )
        .fetch_one(&mut conn)
        .await
        .unwrap();
        assert_eq!(migrated, (41, 1, "legacy_unknown".into()));
        let frontier_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM content_event_causal_frontier")
                .fetch_one(&mut conn)
                .await
                .unwrap();
        assert_eq!(frontier_count, 0, "migration must not infer ancestry");
        let cutover: (i64, i64, Option<i64>) = sqlx::query_as(
            "SELECT singleton,last_legacy_local_seq,from_engine_schema
               FROM content_event_causal_cutover",
        )
        .fetch_one(&mut conn)
        .await
        .unwrap();
        assert_eq!(cutover, (1, 41, Some(45)));
        let retained_version: String = sqlx::query_scalar(
            "SELECT content_version FROM replicated_message_provenance
              WHERE source_event_id='45000000-0000-4000-8000-000000000046'",
        )
        .fetch_one(&mut conn)
        .await
        .unwrap();
        assert_eq!(retained_version, "native.message.v1");
        let foreign_key_violations: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM pragma_foreign_key_check")
                .fetch_one(&mut conn)
                .await
                .unwrap();
        assert_eq!(foreign_key_violations, 0);

        let legacy_heads: Vec<String> =
            sqlx::query_scalar("SELECT id FROM content_events ORDER BY id")
                .fetch_all(&mut conn)
                .await
                .unwrap();
        let epoch_step = EngineMigrationRegistry::production()
            .pending(46, 47)
            .unwrap()
            .pop()
            .unwrap();
        epoch_step.preflight(&mut conn).await.unwrap();
        epoch_step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version = 47")
            .execute(&mut conn)
            .await
            .unwrap();
        let origin_step = EngineMigrationRegistry::production()
            .pending(47, 48)
            .unwrap()
            .pop()
            .unwrap();
        origin_step.preflight(&mut conn).await.unwrap();
        origin_step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version = 48")
            .execute(&mut conn)
            .await
            .unwrap();
        let canvas_step = EngineMigrationRegistry::production()
            .pending(48, 49)
            .unwrap()
            .pop()
            .unwrap();
        canvas_step.preflight(&mut conn).await.unwrap();
        canvas_step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version = 49")
            .execute(&mut conn)
            .await
            .unwrap();
        let successor = EngineMigrationRegistry::production()
            .pending(49, 50)
            .unwrap()
            .pop()
            .unwrap();
        successor.preflight(&mut conn).await.unwrap();
        successor.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version = 50")
            .execute(&mut conn)
            .await
            .unwrap();
        let annotation = EngineMigrationRegistry::production()
            .pending(50, 51)
            .unwrap()
            .pop()
            .unwrap();
        annotation.preflight(&mut conn).await.unwrap();
        annotation.apply(&mut conn).await.unwrap();
        apply_remaining_production_steps(&mut conn, 51).await;
        conn.close().await.unwrap();

        // The first ordinary post-cutover append consumes every legacy head;
        // it must not merely advance AUTOINCREMENT while leaving history
        // disconnected from the new causal graph.
        let db = crate::open_existing_database_at(&path).await.unwrap();
        let new_record_id = "46000000-0000-4000-8000-000000000045";
        crate::store::create_record(
            &db,
            serde_json::json!({
                "id": new_record_id,
                "type": "Document",
                "kind": "note",
                "name": "first post-cutover append"
            }),
        )
        .await
        .unwrap();
        let appended: (i64, String, String) = sqlx::query_as(
            "SELECT seq,id,causal_status FROM content_events
              WHERE record_id=? AND type='record.created'",
        )
        .bind(new_record_id)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(appended.0, 42);
        assert_eq!(appended.2, "complete");
        let appended_frontier: Vec<String> = sqlx::query_scalar(
            "SELECT parent_event_id FROM content_event_causal_frontier
              WHERE event_id=? ORDER BY parent_event_id",
        )
        .bind(appended.1)
        .fetch_all(db.write_pool())
        .await
        .unwrap();
        assert_eq!(appended_frontier, legacy_heads);
        db.close().await;
    }

    #[tokio::test]
    async fn engine_46_to_47_narrows_the_authorization_epoch_triggers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("epoch-guards.db");
        create_current_schema(&path).await;
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        revert_to_engine_46(&mut conn).await;
        sqlx::query("PRAGMA user_version = 46")
            .execute(&mut conn)
            .await
            .unwrap();
        let digest = crate::db::schema_shape_contract_sha256_for_test(&mut conn)
            .await
            .unwrap();
        assert_eq!(digest, crate::db::ENGINE_46_SHAPE_CONTRACT_SHA256);

        sqlx::query(
            "INSERT INTO records
                (id,type,kind,name,body,home_id,policy_anchor_id,persistence,
                 created_at,updated_at,last_activity_at)
             VALUES ('46000000-0000-4000-8000-000000000047','Document','note',
                     'epoch probe','first','native:unfiled','native:root','enduring',?,?,?)",
        )
        .bind("2026-09-02T00:00:00.000Z")
        .bind("2026-09-02T00:00:00.000Z")
        .bind("2026-09-02T00:00:00.000Z")
        .execute(&mut conn)
        .await
        .unwrap();
        let epoch_before: i64 = crate::freshness::authorization_revision_on(&mut conn)
            .await
            .unwrap();
        let body_only = "UPDATE records SET body='second', owner_id=owner_id, kind=kind WHERE id='46000000-0000-4000-8000-000000000047'";
        sqlx::query(body_only).execute(&mut conn).await.unwrap();
        assert_eq!(
            crate::freshness::authorization_revision_on(&mut conn)
                .await
                .unwrap(),
            epoch_before + 1,
            "engine 46 advanced its fence for a statement that merely named authorization columns"
        );

        let step = EngineMigrationRegistry::production()
            .pending(46, 47)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(
            step.stable_id(),
            "engine-46-to-47-value-changed-authorization-epoch"
        );
        step.preflight(&mut conn).await.unwrap();
        step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version = 47")
            .execute(&mut conn)
            .await
            .unwrap();
        let epoch_after = crate::freshness::authorization_revision_on(&mut conn)
            .await
            .unwrap();
        sqlx::query(body_only).execute(&mut conn).await.unwrap();
        assert_eq!(
            crate::freshness::authorization_revision_on(&mut conn)
                .await
                .unwrap(),
            epoch_after,
            "engine 47 must ignore value-preserving authorization-column mentions"
        );
        sqlx::query(
            "UPDATE records SET owner_id='native:root' WHERE id='46000000-0000-4000-8000-000000000047'",
        )
        .execute(&mut conn)
        .await
        .unwrap();
        assert_eq!(
            crate::freshness::authorization_revision_on(&mut conn)
                .await
                .unwrap(),
            epoch_after + 1,
            "a real authorization change must still move the fence"
        );
    }

    #[tokio::test]
    async fn engine_47_to_48_repairs_only_reviewed_message_origins_as_causal_events() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dogfood-message-origins.db");
        let db = crate::create_database(&path.to_string_lossy())
            .await
            .unwrap();
        for (id, principal) in [
            (DOGFOOD_RICHARD_ID, DOGFOOD_DIRECT_PRINCIPALS[0]),
            (DOGFOOD_NEILL_ID, DOGFOOD_DIRECT_PRINCIPALS[1]),
        ] {
            crate::store::create_record(
                &db,
                serde_json::json!({"id":id,"type":"Entity","kind":"person","name":id}),
            )
            .await
            .unwrap();
            crate::identity::add_binding(
                &db,
                &crate::identity::MutationContext {
                    actor: "engine:migration-test",
                    reason: "seed an audited canonical principal binding",
                    run_key: Some("engine-47-to-48-test-fixture"),
                    parent_key: None,
                    intent: Some("exercise the reviewed dogfood message-origin repair"),
                    is_member: true,
                    internal: true,
                    source_read_authorized: false,
                },
                id,
                &crate::identity::BindingClaim {
                    system: "native-principal".into(),
                    identifier: principal.into(),
                },
                true,
            )
            .await
            .unwrap();
        }
        let direct_id = DOGFOOD_MESSAGE_ORIGIN_REPAIRS[0].message_id;
        let collection_id = DOGFOOD_MESSAGE_ORIGIN_REPAIRS[4].message_id;
        for (id, owner) in [
            (direct_id, DOGFOOD_RICHARD_ID),
            (collection_id, DOGFOOD_RICHARD_ID),
        ] {
            crate::store::create_record(
                &db,
                serde_json::json!({
                    "id":id,"type":"Message","kind":"text","name":"legacy",
                    "body":"legacy","home_id":crate::schema::UNFILED_RECORD_ID,
                    "owner_id":owner
                }),
            )
            .await
            .unwrap();
        }
        crate::store::add_link(
            &db,
            crate::events::LinkAddedPayload {
                id: None,
                source_id: direct_id.into(),
                target_id: DOGFOOD_NEILL_ID.into(),
                relationship: "addressed_to".into(),
                note: None,
            },
        )
        .await
        .unwrap();
        assert!(
            crate::conformance::rebuild_and_diff(&db)
                .await
                .unwrap()
                .equal
        );
        db.close().await;

        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        revert_to_engine_48(&mut conn).await;
        sqlx::query("PRAGMA user_version=47")
            .execute(&mut conn)
            .await
            .unwrap();
        let digest = crate::db::schema_shape_contract_sha256_for_test(&mut conn)
            .await
            .unwrap();
        assert_eq!(digest, crate::db::ENGINE_47_SHAPE_CONTRACT_SHA256);
        let old_heads: Vec<String> = sqlx::query_scalar(
            "SELECT event.id FROM content_events event WHERE NOT EXISTS (
               SELECT 1 FROM content_event_causal_frontier frontier
                WHERE frontier.parent_event_id=event.id) ORDER BY event.id",
        )
        .fetch_all(&mut conn)
        .await
        .unwrap();
        let step = EngineMigrationRegistry::production()
            .pending(47, 48)
            .unwrap()
            .pop()
            .unwrap();
        step.preflight(&mut conn).await.unwrap();
        step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version=48")
            .execute(&mut conn)
            .await
            .unwrap();
        let canvas_step = EngineMigrationRegistry::production()
            .pending(48, 49)
            .unwrap()
            .pop()
            .unwrap();
        canvas_step.preflight(&mut conn).await.unwrap();
        canvas_step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version=49")
            .execute(&mut conn)
            .await
            .unwrap();
        let successor = EngineMigrationRegistry::production()
            .pending(49, 50)
            .unwrap()
            .pop()
            .unwrap();
        successor.preflight(&mut conn).await.unwrap();
        sqlx::query("PRAGMA foreign_keys=OFF")
            .execute(&mut conn)
            .await
            .unwrap();
        successor.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA foreign_keys=ON")
            .execute(&mut conn)
            .await
            .unwrap();
        sqlx::query("PRAGMA user_version=50")
            .execute(&mut conn)
            .await
            .unwrap();
        let annotation = EngineMigrationRegistry::production()
            .pending(50, 51)
            .unwrap()
            .pop()
            .unwrap();
        annotation.preflight(&mut conn).await.unwrap();
        annotation.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version=51")
            .execute(&mut conn)
            .await
            .unwrap();

        let direct: (String, String, i64) = sqlx::query_as(
            "SELECT status,origin_type,participant_count FROM message_origin_state
              WHERE message_id=?",
        )
        .bind(direct_id)
        .fetch_one(&mut conn)
        .await
        .unwrap();
        assert_eq!(direct, ("declared".into(), "direct".into(), 2));
        let principals: Vec<String> = sqlx::query_scalar(
            "SELECT principal_id FROM message_origin_principals
              WHERE message_id=? ORDER BY principal_id",
        )
        .bind(direct_id)
        .fetch_all(&mut conn)
        .await
        .unwrap();
        assert_eq!(principals, DOGFOOD_DIRECT_PRINCIPALS);
        let collection: (String, String, String) = sqlx::query_as(
            "SELECT status,origin_type,collection_id FROM message_origin_state
              WHERE message_id=?",
        )
        .bind(collection_id)
        .fetch_one(&mut conn)
        .await
        .unwrap();
        assert_eq!(
            collection,
            (
                "declared".into(),
                "collection".into(),
                crate::schema::UNFILED_RECORD_ID.into()
            )
        );
        let migrated_events: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT record_id,actor,causal_status FROM content_events
              WHERE type='message.origin.declared.v1' ORDER BY seq",
        )
        .fetch_all(&mut conn)
        .await
        .unwrap();
        assert_eq!(migrated_events.len(), 2);
        assert!(migrated_events.iter().all(|(_, actor, status)| actor
            == "engine:message-origin-dogfood-migration"
            && status == "complete"));
        let first_event_id: String = sqlx::query_scalar(
            "SELECT id FROM content_events WHERE type='message.origin.declared.v1'
              ORDER BY seq LIMIT 1",
        )
        .fetch_one(&mut conn)
        .await
        .unwrap();
        let first_frontier: Vec<String> = sqlx::query_scalar(
            "SELECT parent_event_id FROM content_event_causal_frontier
              WHERE event_id=? ORDER BY parent_event_id",
        )
        .bind(first_event_id)
        .fetch_all(&mut conn)
        .await
        .unwrap();
        assert_eq!(first_frontier, old_heads);
        apply_remaining_production_steps(&mut conn, 51).await;
        conn.close().await.unwrap();

        let db = crate::open_existing_database_at(&path).await.unwrap();
        assert!(
            crate::conformance::rebuild_and_diff(&db)
                .await
                .unwrap()
                .equal
        );
        db.close().await;
    }

    #[tokio::test]
    async fn engine_48_to_49_adds_the_canvas_projection_tables_and_keeps_replay_exact() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("canvas-scene-projection.db");
        let db = crate::create_database(&path.to_string_lossy())
            .await
            .unwrap();
        crate::store::create_record(
            &db,
            serde_json::json!({
                "type": "Document", "kind": "note", "name": "before canvas", "body": "x"
            }),
        )
        .await
        .unwrap();
        db.close().await;

        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        revert_to_engine_48(&mut conn).await;
        sqlx::query("PRAGMA user_version=48")
            .execute(&mut conn)
            .await
            .unwrap();
        let digest = crate::db::schema_shape_contract_sha256_for_test(&mut conn)
            .await
            .unwrap();
        assert_eq!(digest, crate::db::ENGINE_48_SHAPE_CONTRACT_SHA256);
        // Engine 48 moved no DDL, so its frozen structural shape is engine 47's.
        assert_eq!(
            crate::db::ENGINE_48_SHAPE_CONTRACT_SHA256,
            crate::db::ENGINE_47_SHAPE_CONTRACT_SHA256
        );
        for pending in EngineMigrationRegistry::production()
            .pending(48, CURRENT_ENGINE_SCHEMA_VERSION)
            .unwrap()
        {
            pending.preflight(&mut conn).await.unwrap();
        }
        let step = EngineMigrationRegistry::production()
            .pending(48, 49)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(step.name(), "engine-48-to-49-canvas-scene-projection");
        step.preflight(&mut conn).await.unwrap();
        step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version=49")
            .execute(&mut conn)
            .await
            .unwrap();
        for table in ["canvas_objects", "canvas_batches"] {
            let rows: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
                .fetch_one(&mut conn)
                .await
                .unwrap();
            assert_eq!(rows, 0, "{table} starts empty on a migrated file");
        }
        assert!(crate::db::validate_engine_shape_on_for_test(&mut conn, 49)
            .await
            .unwrap());
        let successor = EngineMigrationRegistry::production()
            .pending(49, 50)
            .unwrap()
            .pop()
            .unwrap();
        sqlx::query("PRAGMA foreign_keys=OFF")
            .execute(&mut conn)
            .await
            .unwrap();
        successor.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA foreign_keys=ON")
            .execute(&mut conn)
            .await
            .unwrap();
        sqlx::query("PRAGMA user_version=50")
            .execute(&mut conn)
            .await
            .unwrap();
        let annotation = EngineMigrationRegistry::production()
            .pending(50, 51)
            .unwrap()
            .pop()
            .unwrap();
        annotation.preflight(&mut conn).await.unwrap();
        annotation.apply(&mut conn).await.unwrap();
        apply_remaining_production_steps(&mut conn, 51).await;
        conn.close().await.unwrap();

        let db = crate::open_existing_database_at(&path).await.unwrap();
        assert!(
            crate::conformance::rebuild_and_diff(&db)
                .await
                .unwrap()
                .equal
        );
        db.close().await;
    }

    #[tokio::test]
    async fn engine_49_to_50_adds_webhook_storage_and_widens_attribution() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("inbound-webhooks.db");
        create_current_schema(&path).await;

        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        revert_to_engine_49(&mut conn).await;
        sqlx::query("PRAGMA user_version=49")
            .execute(&mut conn)
            .await
            .unwrap();
        let digest = crate::db::schema_shape_contract_sha256_for_test(&mut conn)
            .await
            .unwrap();
        assert_eq!(digest, crate::db::ENGINE_49_SHAPE_CONTRACT_SHA256);
        sqlx::query(
            r#"INSERT INTO provenance_action_attestations
                 (id,schema_version,principal,executor_kind,channel,operation,
                  action_commitment,action_digest,output_event_set_digest,
                  issuer,issuer_origin_database_id,issued_at)
               VALUES
                 ('attestation-before-webhooks',2,'acct:issuer','authenticated_principal','mcp',
                  'create_record','{}',?,?, 'native-ce',?, '2026-09-03T00:00:00Z')"#,
        )
        .bind("a".repeat(64))
        .bind("b".repeat(64))
        .bind("ndb_00000000000000000000000000000000")
        .execute(&mut conn)
        .await
        .unwrap();

        let step = EngineMigrationRegistry::production()
            .pending(49, 50)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(step.name(), "engine-49-to-50-inbound-webhooks");
        step.preflight(&mut conn).await.unwrap();
        sqlx::query("PRAGMA foreign_keys=OFF")
            .execute(&mut conn)
            .await
            .unwrap();
        step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA foreign_keys=ON")
            .execute(&mut conn)
            .await
            .unwrap();
        sqlx::query("PRAGMA user_version=50")
            .execute(&mut conn)
            .await
            .unwrap();

        for table in [
            "webhook_endpoints",
            "webhook_credentials",
            "webhook_deliveries",
        ] {
            let rows: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
                .fetch_one(&mut conn)
                .await
                .unwrap();
            assert_eq!(rows, 0, "{table} starts empty on a migrated file");
        }
        let preserved: (String, String, String) = sqlx::query_as(
            "SELECT principal, executor_kind, channel
               FROM provenance_action_attestations
              WHERE id='attestation-before-webhooks'",
        )
        .fetch_one(&mut conn)
        .await
        .unwrap();
        assert_eq!(
            preserved,
            (
                "acct:issuer".to_string(),
                "authenticated_principal".to_string(),
                "mcp".to_string()
            )
        );
        assert!(crate::db::validate_engine_shape_on_for_test(&mut conn, 50)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn engine_50_to_51_adds_nullable_read_log_result_annotations() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("read-log-result-annotations.db");
        create_current_schema(&path).await;

        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        revert_to_engine_50(&mut conn).await;
        sqlx::query("PRAGMA user_version=50")
            .execute(&mut conn)
            .await
            .unwrap();
        let digest = crate::db::schema_shape_contract_sha256_for_test(&mut conn)
            .await
            .unwrap();
        assert_eq!(digest, crate::db::ENGINE_50_SHAPE_CONTRACT_SHA256);
        sqlx::query(
            "INSERT INTO read_log_calls (id,tool,outcome,started_at,ended_at) VALUES ('pre-annotation-call','get_record','ok','2026-09-10T00:00:00.000Z','2026-09-10T00:00:00.000Z')",
        )
        .execute(&mut conn)
        .await
        .unwrap();

        let step = EngineMigrationRegistry::production()
            .pending(50, 51)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(step.name(), "engine-50-to-51-read-log-result-annotations");
        step.preflight(&mut conn).await.unwrap();
        step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version=51")
            .execute(&mut conn)
            .await
            .unwrap();

        let retained: Option<String> = sqlx::query_scalar(
            "SELECT result_annotation FROM read_log_calls WHERE id='pre-annotation-call'",
        )
        .fetch_one(&mut conn)
        .await
        .unwrap();
        assert_eq!(retained, None, "old calls are not inferred or backfilled");
        let index_sql: String = sqlx::query_scalar(
            "SELECT sql FROM sqlite_master WHERE type='index' AND name='idx_read_log_calls_overlap_annotation'",
        )
        .fetch_one(&mut conn)
        .await
        .unwrap();
        assert!(index_sql.contains("WHERE result_annotation IS NOT NULL"));
        assert!(crate::db::validate_engine_shape_on_for_test(&mut conn, 51)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn engine_46_to_48_preflight_rejects_reviewed_message_evidence_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dogfood-message-origin-mismatch.db");
        let db = crate::create_database(&path.to_string_lossy())
            .await
            .unwrap();
        crate::store::create_record(
            &db,
            serde_json::json!({
                "id": DOGFOOD_MESSAGE_ORIGIN_REPAIRS[0].message_id,
                "type": "Message",
                "kind": "text",
                "name": "wrong reviewed owner",
                "body": "legacy",
                "home_id": crate::schema::UNFILED_RECORD_ID,
                "owner_id": "native:root"
            }),
        )
        .await
        .unwrap();
        db.close().await;

        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        revert_to_engine_46(&mut conn).await;
        sqlx::query("PRAGMA user_version=46")
            .execute(&mut conn)
            .await
            .unwrap();
        conn.close().await.unwrap();

        let error = preflight_production_migration_read_only(&path)
            .await
            .unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("engine-47-to-48-reviewed-dogfood-message-origins"),
            "{message}"
        );
        assert!(
            message.contains("reviewed Message-origin evidence mismatch"),
            "{message}"
        );
    }

    #[tokio::test]
    async fn engine_47_to_48_append_refuses_nonempty_causal_log_without_heads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dogfood-message-origin-headless-log.db");
        let db = crate::create_database(&path.to_string_lossy())
            .await
            .unwrap();
        for suffix in ["one", "two"] {
            crate::store::create_record(
                &db,
                serde_json::json!({
                    "type": "Document",
                    "kind": "note",
                    "name": suffix,
                    "body": suffix
                }),
            )
            .await
            .unwrap();
        }
        db.close().await;
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        let event_ids: Vec<String> =
            sqlx::query_scalar("SELECT id FROM content_events ORDER BY seq LIMIT 2")
                .fetch_all(&mut conn)
                .await
                .unwrap();
        assert_eq!(event_ids.len(), 2);
        let heads: Vec<String> = sqlx::query_scalar(
            "SELECT event.id FROM content_events event WHERE NOT EXISTS (
               SELECT 1 FROM content_event_causal_frontier frontier
                WHERE frontier.parent_event_id=event.id) ORDER BY event.id",
        )
        .fetch_all(&mut conn)
        .await
        .unwrap();
        assert!(!heads.is_empty());
        for head in heads {
            let child = if event_ids[0] == head {
                &event_ids[1]
            } else {
                &event_ids[0]
            };
            sqlx::query(
                "INSERT INTO content_event_causal_frontier(event_id,parent_event_id) VALUES (?,?)",
            )
            .bind(child)
            .bind(head)
            .execute(&mut conn)
            .await
            .unwrap();
        }

        let error = append_dogfood_message_origin_declaration(
            &mut conn,
            DOGFOOD_MESSAGE_ORIGIN_REPAIRS[4].message_id,
            crate::events::MessageOriginDeclaredPayload::Collection {
                collection_id: crate::schema::UNFILED_RECORD_ID.into(),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "content event causal state has no heads for a nonempty log"
        );
    }

    fn always_fenced() -> FenceFn {
        Arc::new(|| async { Ok(()) }.boxed())
    }

    async fn checkpoint_file_bytes(connection: &mut SqliteConnection, path: &Path) -> u64 {
        let _ = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .execute(&mut *connection)
            .await;
        std::fs::metadata(path).unwrap().len()
    }

    /// Presence + length framing so NULL cannot alias `i64::MIN` / empty /
    /// embedded-NUL strings. Evidence-only: not a product digest.
    fn digest_opt_text(digest: &mut Sha256, value: Option<&str>) {
        match value {
            Some(value) => {
                digest.update([1]);
                digest.update((value.len() as u64).to_be_bytes());
                digest.update(value.as_bytes());
            }
            None => digest.update([0]),
        }
    }

    fn digest_opt_i64(digest: &mut Sha256, value: Option<i64>) {
        match value {
            Some(value) => {
                digest.update([1]);
                digest.update(value.to_be_bytes());
            }
            None => digest.update([0]),
        }
    }

    async fn read_log_logical_digest(connection: &mut SqliteConnection) -> String {
        let mut digest = Sha256::new();
        let calls = sqlx::query(
            "SELECT seq, id, tool, run_key, parent_key, intent, actor, arguments,
                    outcome, error_kind, result_count, result_bytes, started_at,
                    ended_at, result_annotation
               FROM read_log_calls ORDER BY seq",
        )
        .fetch_all(&mut *connection)
        .await
        .unwrap();
        for row in calls {
            let seq: i64 = row.get("seq");
            digest.update(seq.to_be_bytes());
            for column in [
                "id",
                "tool",
                "run_key",
                "parent_key",
                "intent",
                "actor",
                "arguments",
                "outcome",
                "error_kind",
                "started_at",
                "ended_at",
                "result_annotation",
            ] {
                let value: Option<String> = row.get(column);
                digest_opt_text(&mut digest, value.as_deref());
            }
            digest_opt_i64(&mut digest, row.get("result_count"));
            digest_opt_i64(&mut digest, row.get("result_bytes"));
        }
        digest.update([1]);
        let normalized: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pragma_table_info('read_log_touches') WHERE name='record_ref'",
        )
        .fetch_one(&mut *connection)
        .await
        .unwrap();
        let touch_sql = if normalized != 0 {
            "SELECT t.call_seq,d.record_id,t.interaction,t.result_rank
               FROM read_log_touches t JOIN read_log_record_ids d ON d.record_ref=t.record_ref
              ORDER BY t.call_seq,d.record_id,t.interaction"
        } else {
            "SELECT call_seq, record_id, interaction, result_rank
               FROM read_log_touches
              ORDER BY call_seq, record_id, interaction"
        };
        let touches = sqlx::query(touch_sql)
            .fetch_all(&mut *connection)
            .await
            .unwrap();
        for row in touches {
            let call_seq: i64 = row.get("call_seq");
            let record_id: String = row.get("record_id");
            let interaction: String = row.get("interaction");
            digest.update(call_seq.to_be_bytes());
            digest_opt_text(&mut digest, Some(&record_id));
            digest_opt_text(&mut digest, Some(&interaction));
            digest_opt_i64(&mut digest, row.get("result_rank"));
        }
        hex::encode(digest.finalize())
    }

    async fn insert_read_log_rows(connection: &mut SqliteConnection, count: i64) {
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *connection)
            .await
            .unwrap();
        for i in 1..=count {
            sqlx::query(
                "INSERT INTO read_log_calls (seq,id,tool,outcome,started_at,ended_at)
                 VALUES (?, ?, 'get_record', 'ok', '2026-09-12T00:00:00.000Z', '2026-09-12T00:00:00.000Z')",
            )
            .bind(i)
            .bind(format!("call-{i:04}"))
            .execute(&mut *connection)
            .await
            .unwrap();
            for (record_id, interaction, rank) in [
                (
                    format!("aaaaaaaa-aaaa-4aaa-8aaa-{i:012x}"),
                    "opened",
                    Some(i),
                ),
                (
                    format!("aaaaaaaa-aaaa-4aaa-8aaa-{i:012x}"),
                    "surfaced",
                    None,
                ),
                ("native:root".into(), "opened", None),
                ("café-record".into(), "mutated", Some(0)),
            ] {
                sqlx::query(
                    "INSERT INTO read_log_touches (call_seq, record_id, interaction, result_rank)
                     VALUES (?, ?, ?, ?)",
                )
                .bind(i)
                .bind(record_id)
                .bind(interaction)
                .bind(rank)
                .execute(&mut *connection)
                .await
                .unwrap();
            }
        }
        sqlx::query("COMMIT")
            .execute(&mut *connection)
            .await
            .unwrap();
    }

    async fn relocate_record_rowid(connection: &mut SqliteConnection, id: &str, rowid: i64) {
        sqlx::query("CREATE TEMP TABLE rec_move AS SELECT * FROM records WHERE id=?")
            .bind(id)
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query("DELETE FROM records WHERE id=?")
            .bind(id)
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO records (
                rowid, id, type, kind, name, body, home_id, lifecycle, owner_id,
                claimed_by_account, claimed_run_key, claimed_at, policy_anchor_id,
                persistence, maturity, summary, last_activity_at, created_at,
                updated_at, deleted_at
             )
             SELECT ?, id, type, kind, name, body, home_id, lifecycle, owner_id,
                    claimed_by_account, claimed_run_key, claimed_at, policy_anchor_id,
                    persistence, maturity, summary, last_activity_at, created_at,
                    updated_at, deleted_at
               FROM rec_move",
        )
        .bind(rowid)
        .execute(&mut *connection)
        .await
        .unwrap();
        sqlx::query("DROP TABLE rec_move")
            .execute(&mut *connection)
            .await
            .unwrap();
    }

    async fn fts_rank1_ok(connection: &mut SqliteConnection, table: &str) -> bool {
        sqlx::query(&format!(
            "INSERT INTO {table}({table}, rank) VALUES('integrity-check', 1)"
        ))
        .execute(&mut *connection)
        .await
        .is_ok()
    }

    async fn match_record_ids(
        connection: &mut SqliteConnection,
        sql: &str,
        query: &str,
    ) -> Vec<String> {
        sqlx::query_scalar(sql)
            .bind(query)
            .fetch_all(&mut *connection)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn engine_51_to_52_rebuilds_read_log_touches_without_rowid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("read-log-without-rowid.db");
        create_current_schema(&path).await;
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        revert_to_engine_51(&mut conn).await;
        sqlx::query("PRAGMA user_version=51")
            .execute(&mut conn)
            .await
            .unwrap();
        let digest = crate::db::schema_shape_contract_sha256_for_test(&mut conn)
            .await
            .unwrap();
        assert_eq!(digest, crate::db::ENGINE_51_SHAPE_CONTRACT_SHA256);

        sqlx::query(
            "INSERT INTO read_log_calls (id,tool,outcome,started_at,ended_at)
             VALUES ('call-a','get_record','ok','2026-09-12T00:00:00.000Z','2026-09-12T00:00:00.000Z')",
        )
        .execute(&mut conn)
        .await
        .unwrap();
        let seq: i64 = sqlx::query_scalar("SELECT seq FROM read_log_calls WHERE id='call-a'")
            .fetch_one(&mut conn)
            .await
            .unwrap();
        for (record_id, interaction, rank) in [
            ("native:root", "opened", None),
            ("native:root", "surfaced", Some(1_i64)),
            ("café-record", "mutated", Some(2)),
            ("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "opened", None),
        ] {
            sqlx::query(
                "INSERT INTO read_log_touches (call_seq, record_id, interaction, result_rank)
                 VALUES (?, ?, ?, ?)",
            )
            .bind(seq)
            .bind(record_id)
            .bind(interaction)
            .bind(rank)
            .execute(&mut conn)
            .await
            .unwrap();
        }
        let before = read_log_logical_digest(&mut conn).await;

        let step = EngineMigrationRegistry::production()
            .pending(51, 52)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(
            step.name(),
            "engine-51-to-52-read-log-touches-without-rowid"
        );
        assert!(step.requires_foreign_keys_disabled());
        assert!(!step.requires_pre_apply_compaction());
        sqlx::query("PRAGMA foreign_keys=OFF")
            .execute(&mut conn)
            .await
            .unwrap();
        step.preflight(&mut conn).await.unwrap();
        step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA foreign_keys=ON")
            .execute(&mut conn)
            .await
            .unwrap();
        sqlx::query("PRAGMA user_version=52")
            .execute(&mut conn)
            .await
            .unwrap();

        let sql: String = sqlx::query_scalar(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='read_log_touches'",
        )
        .fetch_one(&mut conn)
        .await
        .unwrap();
        assert!(
            sql.to_uppercase().contains("WITHOUT ROWID"),
            "clustered table sql: {sql}"
        );
        let autoindex: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master
              WHERE name = 'sqlite_autoindex_read_log_touches_1'",
        )
        .fetch_one(&mut conn)
        .await
        .unwrap();
        assert_eq!(autoindex, 0);
        assert_eq!(read_log_logical_digest(&mut conn).await, before);
        let after = crate::db::schema_shape_contract_sha256_for_test(&mut conn)
            .await
            .unwrap();
        assert_eq!(after, crate::db::ENGINE_52_SHAPE_CONTRACT_SHA256);
        assert!(crate::db::validate_engine_shape_on_for_test(&mut conn, 52)
            .await
            .unwrap());

        let dangling = sqlx::query(
            "INSERT INTO read_log_touches (call_seq, record_id, interaction)
             VALUES (999999, 'missing', 'opened')",
        )
        .execute(&mut conn)
        .await
        .unwrap_err();
        assert!(dangling.to_string().contains("FOREIGN KEY"), "{dangling}");
        sqlx::query("DELETE FROM read_log_calls WHERE id='call-a'")
            .execute(&mut conn)
            .await
            .unwrap();
        let leftover: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM read_log_touches WHERE call_seq=?")
                .bind(seq)
                .fetch_one(&mut conn)
                .await
                .unwrap();
        assert_eq!(leftover, 0);
    }

    /// Same-invocation 51→CURRENT: one `migrate_database_with_reservation`
    /// so the runner sees the original `(from=51, to=CURRENT)` preimage
    /// reservation and compact immediately after rebuild on that connection.
    /// Intermediate 52 bytes/freelist live in
    /// [`engine_51_to_53_split_exposes_rebuild_freelist_then_compacts`].
    #[tokio::test]
    async fn engine_51_to_current_runner_preserves_read_log_compacts_and_keeps_fts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("read-log-compact.db");
        create_current_schema(&path).await;
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        const HIGH_0: &str = "aaaaaaaa-aaaa-4aaa-8aaa-00000000aaa0";
        const HIGH_1: &str = "aaaaaaaa-aaaa-4aaa-8aaa-00000000aaa1";
        const HOLE_1: &str = "aaaaaaaa-aaaa-4aaa-8aaa-00000000bbb1";
        const HOLE_2: &str = "aaaaaaaa-aaaa-4aaa-8aaa-00000000bbb2";
        const HOLE_3: &str = "aaaaaaaa-aaaa-4aaa-8aaa-00000000bbb3";
        const AFTER: &str = "aaaaaaaa-aaaa-4aaa-8aaa-00000000ccc0";

        let db = crate::open_existing_database_at(&path).await.unwrap();
        for (id, name, body) in [
            (HIGH_0, "zebraprefix high", "padding"),
            (HIGH_1, "other", "xylophone high"),
        ] {
            crate::store::create_record(
                &db,
                serde_json::json!({
                    "id": id,
                    "type": "Document",
                    "kind": "note",
                    "name": name,
                    "body": body,
                    "home_id": crate::schema::ROOT_RECORD_ID,
                }),
            )
            .await
            .unwrap();
        }
        crate::store::create_record(
            &db,
            serde_json::json!({
                "id": HOLE_1,
                "type": "Document",
                "kind": "note",
                "name": "zebraprefix low",
                "body": "padding",
                "home_id": crate::schema::ROOT_RECORD_ID,
            }),
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO records (id, type, kind, name, body, home_id, policy_anchor_id)
             VALUES (?, 'Document', 'note', 'gone', 'xylophone gone', ?, ?)",
        )
        .bind(HOLE_2)
        .bind(crate::schema::ROOT_RECORD_ID)
        .bind(crate::schema::ROOT_RECORD_ID)
        .execute(db.write_pool())
        .await
        .unwrap();
        sqlx::query("DELETE FROM records WHERE id=?")
            .bind(HOLE_2)
            .execute(db.write_pool())
            .await
            .unwrap();
        crate::store::create_record(
            &db,
            serde_json::json!({
                "id": HOLE_3,
                "type": "Document",
                "kind": "note",
                "name": "keep",
                "body": "xylophone keep",
                "home_id": crate::schema::ROOT_RECORD_ID,
            }),
        )
        .await
        .unwrap();
        db.close().await;

        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        relocate_record_rowid(&mut conn, HIGH_0, 1_000_000_008).await;
        relocate_record_rowid(&mut conn, HIGH_1, 1_000_000_009).await;
        relocate_record_rowid(&mut conn, HOLE_1, 2_000_000_001).await;
        relocate_record_rowid(&mut conn, HOLE_3, 2_000_000_003).await;
        let rowids: Vec<(String, i64)> = sqlx::query_as(
            "SELECT id, rowid FROM records
              WHERE id IN (?, ?, ?, ?)
              ORDER BY id",
        )
        .bind(HIGH_0)
        .bind(HIGH_1)
        .bind(HOLE_1)
        .bind(HOLE_3)
        .fetch_all(&mut conn)
        .await
        .unwrap();
        assert_eq!(
            rowids.iter().map(|(id, _)| id.as_str()).collect::<Vec<_>>(),
            [HIGH_0, HIGH_1, HOLE_1, HOLE_3]
        );
        assert!(
            rowids[0].1 > 1_000_000_000 && rowids[1].1 > 1_000_000_000,
            "high-range FTS docs must land above 1e9: {rowids:?}"
        );
        assert!(
            rowids[2].1 > 1_999_000_000 && rowids[3].1 > 1_999_000_000,
            "hole-range FTS docs must land above 2e9: {rowids:?}"
        );
        assert!(
            rowids[3].1 > rowids[2].1 + 1,
            "rec-hole-3 must sit past the deleted FTS hole: {rowids:?}"
        );
        revert_to_engine_51(&mut conn).await;
        sqlx::query("PRAGMA user_version=51")
            .execute(&mut conn)
            .await
            .unwrap();

        insert_read_log_rows(&mut conn, 2_000).await;

        let body_sql = "SELECT r.id FROM records_fts
             JOIN records r ON r.rowid = records_fts.rowid
             WHERE records_fts MATCH ?
             ORDER BY r.id";
        let name_sql = "SELECT r.id FROM records_name_idx
             JOIN records r ON r.rowid = records_name_idx.rowid
             WHERE records_name_idx MATCH ?
             ORDER BY r.id";
        let expected_body = match_record_ids(&mut conn, body_sql, "\"xylophone\"").await;
        let expected_name = match_record_ids(&mut conn, name_sql, "\"zebraprefix\"*").await;
        assert_eq!(expected_body, vec![HIGH_1.to_string(), HOLE_3.to_string()]);
        assert_eq!(expected_name, vec![HIGH_0.to_string(), HOLE_1.to_string()]);
        assert!(fts_rank1_ok(&mut conn, "records_fts").await);
        assert!(fts_rank1_ok(&mut conn, "records_name_idx").await);

        let logical_before = read_log_logical_digest(&mut conn).await;
        let size_before = checkpoint_file_bytes(&mut conn, &path).await;
        conn.close().await.unwrap();

        let offbox = tempfile::tempdir().unwrap();
        let backup = test_preimage_store(offbox.path(), dir.path());
        let reserved = Arc::new(Mutex::new(None::<(i64, i64, String)>));
        let reserve: AttemptReservationFn = Arc::new({
            let reserved = reserved.clone();
            move |from, to, preimage: PreimageBackup| {
                *reserved.lock().unwrap() = Some((from, to, preimage.key.clone()));
                async { Ok(()) }.boxed()
            }
        });
        let report = migrate_database_with_reservation(
            &path,
            "readlog-user",
            "readlog-run-51-to-current",
            CURRENT_ENGINE_SCHEMA_VERSION,
            &EngineMigrationRegistry::production(),
            &backup,
            always_fenced(),
            Some(reserve),
            None,
            None,
        )
        .await;
        assert_eq!(report.outcome, "migrated", "{report:?}");
        assert!(report.backup.is_some());
        {
            let held = reserved.lock().unwrap();
            assert_eq!(
                held.as_ref().map(|(from, to, _)| (*from, *to)),
                Some((51, CURRENT_ENGINE_SCHEMA_VERSION))
            );
        }
        assert_eq!(header_version(&path), CURRENT_ENGINE_SCHEMA_VERSION);

        let mut at_53 = SqliteConnection::connect_with(&options).await.unwrap();
        assert_eq!(read_log_logical_digest(&mut at_53).await, logical_before);
        assert!(crate::db::validate_engine_shape_on_for_test(
            &mut at_53,
            CURRENT_ENGINE_SCHEMA_VERSION
        )
        .await
        .unwrap());
        let current_digest = crate::db::schema_shape_contract_sha256_for_test(&mut at_53)
            .await
            .unwrap();
        // The runner must land the exact current shape, whatever the current
        // schema is: compare against a fresh database built from this build's
        // DDL rather than a frozen historical pin.
        let reference_dir = tempfile::tempdir().unwrap();
        let reference_path = reference_dir.path().join("current-reference.db");
        create_current_schema(&reference_path).await;
        let reference_options =
            SqliteConnectOptions::from_str(&format!("sqlite:{}", reference_path.display()))
                .unwrap()
                .foreign_keys(true);
        let mut reference_conn = SqliteConnection::connect_with(&reference_options)
            .await
            .unwrap();
        let reference_digest =
            crate::db::schema_shape_contract_sha256_for_test(&mut reference_conn)
                .await
                .unwrap();
        assert_eq!(current_digest, reference_digest);
        let sql: String = sqlx::query_scalar(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='read_log_touches'",
        )
        .fetch_one(&mut at_53)
        .await
        .unwrap();
        assert!(sql.to_uppercase().contains("WITHOUT ROWID"));
        let size_53 = checkpoint_file_bytes(&mut at_53, &path).await;
        assert!(
            size_53 <= size_before,
            "compacted live file must not exceed pre-rebuild bytes; before={size_before} at-53={size_53}"
        );
        assert_eq!(
            match_record_ids(&mut at_53, body_sql, "\"xylophone\"").await,
            expected_body
        );
        assert_eq!(
            match_record_ids(&mut at_53, name_sql, "\"zebraprefix\"*").await,
            expected_name
        );
        assert!(fts_rank1_ok(&mut at_53, "records_fts").await);
        assert!(fts_rank1_ok(&mut at_53, "records_name_idx").await);
        at_53.close().await.unwrap();

        crate::open_existing_database_at(&path)
            .await
            .unwrap()
            .close()
            .await;

        let mut after = SqliteConnection::connect_with(&options).await.unwrap();
        sqlx::query(
            "INSERT INTO records (id, type, kind, name, body, home_id, policy_anchor_id)
             VALUES (?, 'Document', 'note', 'zebraprefix after', 'xylophone after', ?, ?)",
        )
        .bind(AFTER)
        .bind(crate::schema::ROOT_RECORD_ID)
        .bind(crate::schema::ROOT_RECORD_ID)
        .execute(&mut after)
        .await
        .unwrap();
        sqlx::query("UPDATE records SET body='xylophone updated' WHERE id=?")
            .bind(HOLE_3)
            .execute(&mut after)
            .await
            .unwrap();
        sqlx::query("DELETE FROM records WHERE id=?")
            .bind(HIGH_1)
            .execute(&mut after)
            .await
            .unwrap();
        assert_eq!(
            match_record_ids(&mut after, body_sql, "\"xylophone\"").await,
            vec![HOLE_3.to_string(), AFTER.to_string()]
        );
        assert!(match_record_ids(&mut after, name_sql, "\"zebraprefix\"*")
            .await
            .contains(&AFTER.to_string()));
        assert!(fts_rank1_ok(&mut after, "records_fts").await);
        assert!(fts_rank1_ok(&mut after, "records_name_idx").await);
        after.close().await.unwrap();
    }

    #[tokio::test]
    async fn engine_51_to_53_split_exposes_rebuild_freelist_then_compacts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("read-log-split.db");
        create_current_schema(&path).await;
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        revert_to_engine_51(&mut conn).await;
        sqlx::query("PRAGMA user_version=51")
            .execute(&mut conn)
            .await
            .unwrap();
        insert_read_log_rows(&mut conn, 800).await;
        let logical_before = read_log_logical_digest(&mut conn).await;
        let size_before = checkpoint_file_bytes(&mut conn, &path).await;
        let freelist_before: i64 = sqlx::query_scalar("PRAGMA freelist_count")
            .fetch_one(&mut conn)
            .await
            .unwrap();
        conn.close().await.unwrap();

        let offbox = tempfile::tempdir().unwrap();
        let backup = test_preimage_store(offbox.path(), dir.path());
        let reserved = Arc::new(Mutex::new(None::<(i64, i64, String)>));
        let reserve: AttemptReservationFn = Arc::new({
            let reserved = reserved.clone();
            move |from, to, preimage: PreimageBackup| {
                *reserved.lock().unwrap() = Some((from, to, preimage.key.clone()));
                async { Ok(()) }.boxed()
            }
        });
        let to_52 = migrate_database_with_reservation(
            &path,
            "readlog-user",
            "readlog-run-split-52",
            52,
            &EngineMigrationRegistry::production(),
            &backup,
            always_fenced(),
            Some(reserve.clone()),
            None,
            None,
        )
        .await;
        assert_eq!(to_52.outcome, "migrated", "{to_52:?}");
        {
            let held = reserved.lock().unwrap();
            assert_eq!(
                held.as_ref().map(|(from, to, _)| (*from, *to)),
                Some((51, 52))
            );
        }
        assert_eq!(header_version(&path), 52);

        let mut at_52 = SqliteConnection::connect_with(&options).await.unwrap();
        assert_eq!(read_log_logical_digest(&mut at_52).await, logical_before);
        let sql: String = sqlx::query_scalar(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='read_log_touches'",
        )
        .fetch_one(&mut at_52)
        .await
        .unwrap();
        assert!(sql.to_uppercase().contains("WITHOUT ROWID"));
        let size_52 = checkpoint_file_bytes(&mut at_52, &path).await;
        let freelist_52: i64 = sqlx::query_scalar("PRAGMA freelist_count")
            .fetch_one(&mut at_52)
            .await
            .unwrap();
        assert!(
            freelist_52 > freelist_before,
            "rebuild must leave freelist pages; before={freelist_before} at-52={freelist_52}"
        );
        at_52.close().await.unwrap();

        let to_53 = migrate_database_with_reservation(
            &path,
            "readlog-user",
            "readlog-run-split-53",
            53,
            &EngineMigrationRegistry::production(),
            &backup,
            always_fenced(),
            Some(reserve),
            None,
            None,
        )
        .await;
        assert_eq!(to_53.outcome, "migrated", "{to_53:?}");
        {
            let held = reserved.lock().unwrap();
            assert_eq!(
                held.as_ref().map(|(from, to, _)| (*from, *to)),
                Some((52, 53))
            );
        }
        assert_eq!(header_version(&path), 53);

        let mut at_53 = SqliteConnection::connect_with(&options).await.unwrap();
        assert_eq!(read_log_logical_digest(&mut at_53).await, logical_before);
        let size_53 = checkpoint_file_bytes(&mut at_53, &path).await;
        let freelist_53: i64 = sqlx::query_scalar("PRAGMA freelist_count")
            .fetch_one(&mut at_53)
            .await
            .unwrap();
        assert!(
            size_53 <= size_before,
            "compacted live file must not exceed pre-rebuild bytes; before={size_before} at-52={size_52} at-53={size_53}"
        );
        assert!(
            freelist_53 < freelist_52,
            "compaction must reclaim freelist; at-52={freelist_52} at-53={freelist_53}"
        );
        at_53.close().await.unwrap();
    }

    #[tokio::test]
    async fn engine_52_to_53_compact_write_lock_retains_pending_version_and_retries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("compact-lock.db");
        create_current_schema(&path).await;
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        revert_to_engine_53(&mut conn).await;
        sqlx::query("PRAGMA user_version=52")
            .execute(&mut conn)
            .await
            .unwrap();
        conn.close().await.unwrap();

        let held = Arc::new(Mutex::new(None::<rusqlite::Connection>));
        let calls = Arc::new(AtomicUsize::new(0));
        let fence: FenceFn = Arc::new({
            let held = held.clone();
            let calls = calls.clone();
            let path = path.clone();
            move || {
                let call = calls.fetch_add(1, Ordering::SeqCst);
                let held = held.clone();
                let path = path.clone();
                async move {
                    if call == 1 {
                        let locker = rusqlite::Connection::open(&path).unwrap();
                        locker
                            .busy_timeout(std::time::Duration::from_millis(1))
                            .unwrap();
                        locker.execute_batch("BEGIN EXCLUSIVE").unwrap();
                        *held.lock().unwrap() = Some(locker);
                    }
                    Ok(())
                }
                .boxed()
            }
        });
        let offbox = tempfile::tempdir().unwrap();
        let backup = test_preimage_store(offbox.path(), dir.path());
        let failed = migrate_database_with_reservation(
            &path,
            "lock-user",
            "lock-run",
            53,
            &EngineMigrationRegistry::production(),
            &backup,
            fence,
            None,
            None,
            None,
        )
        .await;
        assert_eq!(failed.outcome, "failed", "{failed:?}");
        assert_eq!(failed.error_kind.as_deref(), Some("compact"));
        assert!(failed.backup.is_some());
        drop(held.lock().unwrap().take());
        assert_eq!(header_version(&path), 52);

        let retry = migrate_database_with_reservation(
            &path,
            "lock-user",
            "lock-retry",
            53,
            &EngineMigrationRegistry::production(),
            &backup,
            always_fenced(),
            None,
            None,
            None,
        )
        .await;
        assert_eq!(retry.outcome, "migrated", "{retry:?}");
        assert_eq!(header_version(&path), 53);
    }

    #[tokio::test]
    async fn engine_52_to_53_post_stamp_fence_loss_rolls_back_and_retries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("compact-fence.db");
        create_current_schema(&path).await;
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        revert_to_engine_53(&mut conn).await;
        sqlx::query("PRAGMA user_version=52")
            .execute(&mut conn)
            .await
            .unwrap();
        conn.close().await.unwrap();

        let calls = Arc::new(AtomicUsize::new(0));
        let fence: FenceFn = Arc::new({
            let calls = calls.clone();
            move || {
                let call = calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    // 0 pre-backup, 1 pre-step, 2 post-VACUUM, 3 pre-stamp,
                    // 4 post-stamp — the autocommit hatch could not roll this
                    // last one back.
                    if call == 4 {
                        Err(Error::engine("lease taken over after stamp"))
                    } else {
                        Ok(())
                    }
                }
                .boxed()
            }
        });
        let offbox = tempfile::tempdir().unwrap();
        let backup = test_preimage_store(offbox.path(), dir.path());
        let failed = migrate_database_with_reservation(
            &path,
            "fence-user",
            "fence-run",
            53,
            &EngineMigrationRegistry::production(),
            &backup,
            fence,
            None,
            None,
            None,
        )
        .await;
        assert_eq!(failed.outcome, "failed", "{failed:?}");
        assert_eq!(failed.error_kind.as_deref(), Some("apply"));
        assert!(failed.backup.is_some());
        assert_eq!(header_version(&path), 52);

        let retry = migrate_database_with_reservation(
            &path,
            "fence-user",
            "fence-retry",
            53,
            &EngineMigrationRegistry::production(),
            &backup,
            always_fenced(),
            None,
            None,
            None,
        )
        .await;
        assert_eq!(retry.outcome, "migrated", "{retry:?}");
        assert_eq!(header_version(&path), 53);
    }

    #[tokio::test]
    async fn engine_53_to_55_dictionary_preserves_exact_touches_preimage_and_compacts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dictionary.db");
        create_current_schema(&path).await;
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        revert_to_engine_53(&mut conn).await;
        insert_read_log_rows(&mut conn, 2_000).await;
        let historical_ids = [
            "",
            "not-a-uuid",
            "quote'identifier",
            "café/历史",
            "ABCDEF01-ABCD-ABCD-ABCD-ABCDEF012345",
            "abcdef01-abcd-abcd-abcd-abcdef012345",
        ];
        for id in historical_ids {
            for (interaction, rank) in [
                ("surfaced", None),
                ("opened", Some(0_i64)),
                ("mutated", Some(-1)),
            ] {
                sqlx::query("INSERT INTO read_log_touches(call_seq,record_id,interaction,result_rank) VALUES(1,?,?,?)")
                    .bind(id).bind(interaction).bind(rank).execute(&mut conn).await.unwrap();
            }
        }
        // AUTOINCREMENT may legitimately be ahead of every retained call.
        // A dictionary rebuild must preserve the next allocation as well.
        sqlx::query("UPDATE sqlite_sequence SET seq=42000 WHERE name='read_log_calls'")
            .execute(&mut conn)
            .await
            .unwrap();
        let before = read_log_logical_digest(&mut conn).await;
        let before_count: i64 = sqlx::query_scalar("SELECT count(*) FROM read_log_touches")
            .fetch_one(&mut conn)
            .await
            .unwrap();
        let before_size = checkpoint_file_bytes(&mut conn, &path).await;
        assert_eq!(
            crate::db::schema_shape_contract_sha256_for_test(&mut conn)
                .await
                .unwrap(),
            crate::db::ENGINE_53_SHAPE_CONTRACT_SHA256
        );
        conn.close().await.unwrap();

        let offbox = tempfile::tempdir().unwrap();
        let backup = test_preimage_store(offbox.path(), dir.path());
        let to_54 = migrate_database_with_reservation(
            &path,
            "dictionary-user",
            "dictionary-54",
            54,
            &EngineMigrationRegistry::production(),
            &backup,
            always_fenced(),
            None,
            None,
            None,
        )
        .await;
        assert_eq!(to_54.outcome, "migrated", "{to_54:?}");
        assert_eq!(header_version(&path), 54);
        let preimage = offbox.path().join(&to_54.backup.unwrap().key);
        assert_eq!(header_version(&preimage), 53);
        let pre_options = SqliteConnectOptions::new()
            .filename(&preimage)
            .read_only(true);
        let mut restored = SqliteConnection::connect_with(&pre_options).await.unwrap();
        assert_eq!(read_log_logical_digest(&mut restored).await, before);
        restored.close().await.unwrap();

        let mut at_54 = SqliteConnection::connect_with(&options).await.unwrap();
        assert_eq!(read_log_logical_digest(&mut at_54).await, before);
        assert_eq!(
            crate::db::schema_shape_contract_sha256_for_test(&mut at_54)
                .await
                .unwrap(),
            crate::db::ENGINE_54_SHAPE_CONTRACT_SHA256
        );
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM read_log_touches")
            .fetch_one(&mut at_54)
            .await
            .unwrap();
        assert_eq!(count, before_count);
        for id in historical_ids {
            let rows: Vec<(String, Option<i64>)> = sqlx::query_as(
                "SELECT t.interaction,t.result_rank FROM read_log_touches t JOIN read_log_record_ids d USING(record_ref) WHERE t.call_seq=1 AND d.record_id=? ORDER BY t.interaction",
            ).bind(id).fetch_all(&mut at_54).await.unwrap();
            assert_eq!(
                rows,
                vec![
                    ("mutated".into(), Some(-1)),
                    ("opened".into(), Some(0)),
                    ("surfaced".into(), None)
                ]
            );
        }
        let missing_dictionary =
            sqlx::query("INSERT INTO read_log_touches VALUES(1,9223372036854775807,'opened',NULL)")
                .execute(&mut at_54)
                .await
                .unwrap_err();
        assert!(missing_dictionary.to_string().contains("FOREIGN KEY"));
        let allocated_54 = checkpoint_file_bytes(&mut at_54, &path).await;
        let free_54: i64 = sqlx::query_scalar("PRAGMA freelist_count")
            .fetch_one(&mut at_54)
            .await
            .unwrap();
        assert!(
            free_54 > 0,
            "rebuild should leave displaced pages before compaction"
        );
        at_54.close().await.unwrap();

        let to_55 = migrate_database_with_reservation(
            &path,
            "dictionary-user",
            "dictionary-55",
            55,
            &EngineMigrationRegistry::production(),
            &backup,
            always_fenced(),
            None,
            None,
            None,
        )
        .await;
        assert_eq!(to_55.outcome, "migrated", "{to_55:?}");
        assert_eq!(header_version(&path), 55);
        let mut at_55 = SqliteConnection::connect_with(&options).await.unwrap();
        assert_eq!(read_log_logical_digest(&mut at_55).await, before);
        assert!(crate::db::validate_engine_shape_on_for_test(&mut at_55, 55)
            .await
            .unwrap());
        let size_55 = checkpoint_file_bytes(&mut at_55, &path).await;
        assert!(
            size_55 < allocated_54 && size_55 < before_size,
            "before={before_size}, rebuilt={allocated_54}, compacted={size_55}"
        );
        let free_55: i64 = sqlx::query_scalar("PRAGMA freelist_count")
            .fetch_one(&mut at_55)
            .await
            .unwrap();
        assert_eq!(free_55, 0);
        let integrity: String = sqlx::query_scalar("PRAGMA integrity_check")
            .fetch_one(&mut at_55)
            .await
            .unwrap();
        assert_eq!(integrity, "ok");
        let next_call = sqlx::query("INSERT INTO read_log_calls(id,tool,outcome,started_at,ended_at) VALUES('after-dictionary','test','ok','2026-09-12','2026-09-12')")
            .execute(&mut at_55).await.unwrap().last_insert_rowid();
        assert_eq!(next_call, 42001);

        sqlx::query("DELETE FROM read_log_calls WHERE seq=1")
            .execute(&mut at_55)
            .await
            .unwrap();
        let remaining: i64 =
            sqlx::query_scalar("SELECT count(*) FROM read_log_touches WHERE call_seq=1")
                .fetch_one(&mut at_55)
                .await
                .unwrap();
        assert_eq!(remaining, 0);
        // History is independent of current records; interning is not record ownership.
        let retained: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM read_log_record_ids WHERE record_id='not-a-uuid'",
        )
        .fetch_one(&mut at_55)
        .await
        .unwrap();
        assert_eq!(retained, 1);
        at_55.close().await.unwrap();
    }

    #[tokio::test]
    async fn dictionary_and_compaction_post_stamp_fence_loss_roll_back_and_retry() {
        for from in [53, 54] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("dictionary-fence.db");
            create_current_schema(&path).await;
            let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
                .unwrap()
                .foreign_keys(true);
            let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
            revert_to_engine_53(&mut conn).await;
            insert_read_log_rows(&mut conn, 40).await;
            let before = read_log_logical_digest(&mut conn).await;
            conn.close().await.unwrap();
            let offbox = tempfile::tempdir().unwrap();
            let backup = test_preimage_store(offbox.path(), dir.path());
            if from == 54 {
                let preparation = migrate_database_with_reservation(
                    &path,
                    "fence-user",
                    "prepare-54",
                    54,
                    &EngineMigrationRegistry::production(),
                    &backup,
                    always_fenced(),
                    None,
                    None,
                    None,
                )
                .await;
                assert_eq!(preparation.outcome, "migrated", "{preparation:?}");
            }
            let calls = Arc::new(AtomicUsize::new(0));
            let fence: FenceFn = Arc::new(move || {
                let call = calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    // Compaction adds one fence after its autocommit VACUUM.
                    if call == if from == 53 { 3 } else { 4 } {
                        Err(Error::engine(
                            "lease lost after dictionary/compaction stamp",
                        ))
                    } else {
                        Ok(())
                    }
                }
                .boxed()
            });
            let failed = migrate_database_with_reservation(
                &path,
                "fence-user",
                "fail-after-stamp",
                from + 1,
                &EngineMigrationRegistry::production(),
                &backup,
                fence,
                None,
                None,
                None,
            )
            .await;
            assert_eq!(failed.outcome, "failed", "{failed:?}");
            assert_eq!(failed.error_kind.as_deref(), Some("apply"));
            assert!(failed.backup.is_some());
            assert_eq!(header_version(&path), from);
            let mut rolled_back = SqliteConnection::connect_with(&options).await.unwrap();
            assert_eq!(read_log_logical_digest(&mut rolled_back).await, before);
            let dictionary_present: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name='read_log_record_ids'",
            ).fetch_one(&mut rolled_back).await.unwrap();
            assert_eq!(dictionary_present, i64::from(from == 54));
            rolled_back.close().await.unwrap();
            let retry = migrate_database_with_reservation(
                &path,
                "fence-user",
                "retry-after-stamp",
                55,
                &EngineMigrationRegistry::production(),
                &backup,
                always_fenced(),
                None,
                None,
                None,
            )
            .await;
            assert_eq!(retry.outcome, "migrated", "{retry:?}");
            assert_eq!(header_version(&path), 55);
            let mut retried = SqliteConnection::connect_with(&options).await.unwrap();
            assert_eq!(read_log_logical_digest(&mut retried).await, before);
            retried.close().await.unwrap();
        }
    }

    #[tokio::test]
    async fn current_engine_migration_is_a_no_op_without_vacuum() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("current.db");
        create_current_schema(&path).await;
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        let size_before = checkpoint_file_bytes(&mut conn, &path).await;
        let mtime_before = std::fs::metadata(&path).unwrap().modified().unwrap();
        conn.close().await.unwrap();

        let offbox = tempfile::tempdir().unwrap();
        let backup = test_preimage_store(offbox.path(), dir.path());
        let report = migrate_database_with_reservation(
            &path,
            "current-user",
            "current-run",
            CURRENT_ENGINE_SCHEMA_VERSION,
            &EngineMigrationRegistry::production(),
            &backup,
            always_fenced(),
            None,
            None,
            None,
        )
        .await;
        assert_eq!(report.outcome, "current", "{report:?}");
        assert!(report.backup.is_none());
        assert_eq!(header_version(&path), CURRENT_ENGINE_SCHEMA_VERSION);
        let size_after = std::fs::metadata(&path).unwrap().len();
        let mtime_after = std::fs::metadata(&path).unwrap().modified().unwrap();
        assert_eq!(size_after, size_before);
        assert_eq!(mtime_after, mtime_before);
    }

    /// Acceptance criterion 4: migration from engine 55 leaves every
    /// existing row unstamped and grouping-unknown, records the cutover,
    /// and fabricates no grouping. The first post-cutover write allocates
    /// act 1 on a counter that starts at zero.
    #[tokio::test]
    async fn engine_55_to_56_leaves_legacy_rows_unstamped_and_records_cutover() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("act-cutover.db");
        create_current_schema(&path).await;
        let db = crate::open_existing_database_at(&path).await.unwrap();
        crate::store::create_record(
            &db,
            serde_json::json!({
                "id": "1a7e4000-0000-4000-8000-000000000055",
                "type": "Document",
                "kind": "note",
                "name": "pre-cutover record"
            }),
        )
        .await
        .unwrap();
        let legacy_content_seq: i64 = sqlx::query_scalar("SELECT MAX(seq) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert!(legacy_content_seq > 0);
        db.close().await;

        // Reconstruct the engine-55 preimage, then run the real 55->56 edge.
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        revert_to_engine_55(&mut conn).await;
        sqlx::query("PRAGMA user_version=55")
            .execute(&mut conn)
            .await
            .unwrap();
        let digest = crate::db::schema_shape_contract_sha256_for_test(&mut conn)
            .await
            .unwrap();
        assert_eq!(digest, crate::db::ENGINE_55_SHAPE_CONTRACT_SHA256);
        let step = EngineMigrationRegistry::production()
            .pending(55, 56)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(step.name(), "engine-55-to-56-act-number-stamping");
        step.preflight(&mut conn).await.unwrap();
        step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version=56")
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(crate::db::validate_engine_shape_on_for_test(&mut conn, 56)
            .await
            .unwrap());
        // The 56→57 edge only installs the content-event append-only
        // triggers, so the migrated database under test continues to current.
        let step = EngineMigrationRegistry::production()
            .pending(56, 57)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(step.name(), "engine-56-to-57-content-events-append-only");
        step.preflight(&mut conn).await.unwrap();
        step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version=57")
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(crate::db::validate_engine_shape_on_for_test(&mut conn, 57)
            .await
            .unwrap());
        // Run the remaining edges before
        // reopening: this keeps the test's subject the 55→56 edge while
        // leaving a file ordinary serving accepts.
        let step = EngineMigrationRegistry::production()
            .pending(57, 58)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(step.name(), "engine-57-to-58-agent-run-client-identity");
        step.preflight(&mut conn).await.unwrap();
        step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version=58")
            .execute(&mut conn)
            .await
            .unwrap();
        advance_engine_58_to_current(&mut conn, 58).await;
        conn.close().await.unwrap();

        // Every pre-cutover row is unstamped: grouping unknown, fabricated
        // for none of them.
        let migrated = crate::open_existing_database_at(&path).await.unwrap();
        for table in crate::act::CANONICAL_EVENT_TABLES {
            let nulls: i64 =
                sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE act IS NULL"))
                    .fetch_one(migrated.write_pool())
                    .await
                    .unwrap();
            let total: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
                .fetch_one(migrated.write_pool())
                .await
                .unwrap();
            assert_eq!(
                nulls, total,
                "{table}: migration must not fabricate grouping for legacy rows"
            );
        }
        // The cutover records the per-domain legacy frontier from engine 55.
        let content_cutover = migrated.act_cutover_for("content_events").await.unwrap();
        assert_eq!(content_cutover, Some(legacy_content_seq));
        for table in crate::act::CANONICAL_EVENT_TABLES {
            let cutover = migrated.act_cutover_for(table).await.unwrap();
            assert!(
                cutover.is_some(),
                "{table}: migration must record a cutover"
            );
        }
        // The counter starts at zero: no act is consumed by the migration.
        assert_eq!(migrated.current_act().await.unwrap(), 0);

        // The first post-cutover write allocates act 1.
        let event = crate::store::append(
            &migrated,
            crate::store::AppendSpec {
                record_id: "1a7e4000-0000-4000-8000-000000000056".into(),
                event_type: "record.created".into(),
                payload: serde_json::json!({
                    "type": "Document",
                    "kind": "note",
                    "name": "post-cutover record"
                }),
                actor: None,
            },
        )
        .await
        .unwrap();
        let act: Option<i64> = sqlx::query_scalar("SELECT act FROM content_events WHERE seq = ?")
            .bind(event.local_seq)
            .fetch_one(migrated.write_pool())
            .await
            .unwrap();
        assert_eq!(act, Some(1));
        assert_eq!(migrated.current_act().await.unwrap(), 1);
        migrated.close().await;
    }

    /// Acceptance criterion 7: `PRAGMA integrity_check` and existing
    /// conformance (authoritative-log rebuild plus projection diff) pass on
    /// a migrated database.
    #[tokio::test]
    async fn migrated_database_passes_integrity_and_conformance() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("act-conformance.db");
        create_current_schema(&path).await;
        let db = crate::open_existing_database_at(&path).await.unwrap();
        crate::store::create_record(
            &db,
            serde_json::json!({
                "id": "1a7e4000-0000-4000-8000-000000000057",
                "type": "Document",
                "kind": "note",
                "name": "conformance witness",
                "body": "migrated databases must still rebuild cleanly"
            }),
        )
        .await
        .unwrap();
        db.close().await;

        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        revert_to_engine_55(&mut conn).await;
        sqlx::query("PRAGMA user_version=55")
            .execute(&mut conn)
            .await
            .unwrap();
        let step = EngineMigrationRegistry::production()
            .pending(55, 56)
            .unwrap()
            .pop()
            .unwrap();
        step.preflight(&mut conn).await.unwrap();
        step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version=56")
            .execute(&mut conn)
            .await
            .unwrap();
        // Continue through the remaining edges to the current schema.
        let step = EngineMigrationRegistry::production()
            .pending(56, 57)
            .unwrap()
            .pop()
            .unwrap();
        step.preflight(&mut conn).await.unwrap();
        step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version=57")
            .execute(&mut conn)
            .await
            .unwrap();
        let step = EngineMigrationRegistry::production()
            .pending(57, 58)
            .unwrap()
            .pop()
            .unwrap();
        step.preflight(&mut conn).await.unwrap();
        step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version=58")
            .execute(&mut conn)
            .await
            .unwrap();
        advance_engine_58_to_current(&mut conn, 58).await;
        let integrity: String = sqlx::query_scalar("PRAGMA integrity_check")
            .fetch_one(&mut conn)
            .await
            .unwrap();
        assert_eq!(integrity, "ok");
        conn.close().await.unwrap();

        let migrated = crate::open_existing_database_at(&path).await.unwrap();
        let report = crate::conformance::run_conformance(&migrated).await;
        assert!(report.ok, "conformance must pass on a migrated database");
        migrated.close().await;
    }

    /// Fresh current databases reject content-event rewrites while ordinary
    /// appends keep working.
    #[tokio::test]
    async fn fresh_database_rejects_content_event_update_and_delete() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        crate::store::create_record(
            &db,
            serde_json::json!({
                "id": "1a7e4000-0000-4000-8000-000000000071",
                "type": "Document",
                "kind": "note",
                "name": "append-only witness"
            }),
        )
        .await
        .unwrap();
        for statement in [
            "UPDATE content_events SET payload='{}' WHERE seq=1",
            "DELETE FROM content_events WHERE seq=1",
        ] {
            let error = sqlx::query(statement)
                .execute(db.write_pool())
                .await
                .unwrap_err();
            assert!(
                error.to_string().contains("content_events is append-only"),
                "{statement}: {error}"
            );
        }
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert!(rows > 0, "rejected rewrites must remove nothing");
        // Ordinary appends still land.
        crate::store::create_record(
            &db,
            serde_json::json!({
                "id": "1a7e4000-0000-4000-8000-000000000072",
                "type": "Document",
                "kind": "note",
                "name": "post-guard record"
            }),
        )
        .await
        .unwrap();
        let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(after, rows + 1);
        db.close().await;
    }

    #[tokio::test]
    async fn merged_engine_58_through_63_shape_pins_are_reproducible() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let mut conn = db.write_pool().acquire().await.unwrap();
        revert_to_engine_64(&mut conn).await;
        let engine_62 = crate::db::schema_shape_contract_sha256_for_test(&mut conn)
            .await
            .unwrap();
        assert_eq!(engine_62, crate::db::ENGINE_62_SHAPE_CONTRACT_SHA256);
        assert_eq!(engine_62, crate::db::ENGINE_63_SHAPE_CONTRACT_SHA256);
        let drop_statements = [
            "DROP INDEX idx_external_observations_act",
            "ALTER TABLE external_observations DROP COLUMN act",
            "DROP INDEX idx_awareness_command_intents_act",
            "ALTER TABLE awareness_command_intents DROP COLUMN act",
        ];
        for statement in drop_statements {
            sqlx::query(statement).execute(&mut *conn).await.unwrap();
        }
        let engine_61 = crate::db::schema_shape_contract_sha256_for_test(&mut conn)
            .await
            .unwrap();
        for statement in [
            "DROP INDEX idx_content_events_act",
            "DROP INDEX idx_policy_events_act",
            "DROP INDEX idx_awareness_events_act",
            "DROP INDEX idx_notification_candidate_events_act",
            "DROP INDEX idx_binding_audit_act",
            "DROP INDEX idx_database_identity_audit_act",
            "DROP INDEX idx_meta_events_act",
            "DROP INDEX idx_control_events_act",
            "DROP INDEX idx_derivation_events_act",
            "DROP INDEX idx_relationship_events_act",
            "DROP TRIGGER binding_systems_no_insert",
            "DROP TRIGGER binding_systems_no_update",
            "DROP TRIGGER binding_systems_no_delete",
        ] {
            sqlx::query(statement).execute(&mut *conn).await.unwrap();
        }
        let engine_60 = crate::db::schema_shape_contract_sha256_for_test(&mut conn)
            .await
            .unwrap();
        sqlx::query("DROP INDEX idx_provenance_validity_act")
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("ALTER TABLE provenance_attestation_validity_events DROP COLUMN act")
            .execute(&mut *conn)
            .await
            .unwrap();
        let engine_59 = crate::db::schema_shape_contract_sha256_for_test(&mut conn)
            .await
            .unwrap();
        sqlx::query("DROP TABLE record_mentions")
            .execute(&mut *conn)
            .await
            .unwrap();
        let engine_58 = crate::db::schema_shape_contract_sha256_for_test(&mut conn)
            .await
            .unwrap();
        assert_eq!(engine_58, crate::db::ENGINE_58_SHAPE_CONTRACT_SHA256);
        assert_eq!(engine_59, crate::db::ENGINE_59_SHAPE_CONTRACT_SHA256);
        assert_eq!(engine_60, crate::db::ENGINE_60_SHAPE_CONTRACT_SHA256);
        assert_eq!(engine_61, crate::db::ENGINE_61_SHAPE_CONTRACT_SHA256);

        sqlx::query("PRAGMA user_version=58")
            .execute(&mut *conn)
            .await
            .unwrap();
        advance_engine_58_to_current(&mut conn, 58).await;
    }

    /// The 56→57 edge installs the content-event append-only triggers on an
    /// already-existing database without touching its rows, and the migrated
    /// database reopens with the same rejection behavior as a fresh one.
    #[tokio::test]
    async fn engine_56_to_57_installs_content_event_triggers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("content-append-only.db");
        create_current_schema(&path).await;
        let db = crate::open_existing_database_at(&path).await.unwrap();
        crate::store::create_record(
            &db,
            serde_json::json!({
                "id": "1a7e4000-0000-4000-8000-000000000073",
                "type": "Document",
                "kind": "note",
                "name": "pre-migration record"
            }),
        )
        .await
        .unwrap();
        let legacy_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert!(legacy_rows > 0);
        db.close().await;

        // Reconstruct the engine-56 preimage, then run the real 56→57 edge.
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        revert_to_engine_56(&mut conn).await;
        let digest = crate::db::schema_shape_contract_sha256_for_test(&mut conn)
            .await
            .unwrap();
        assert_eq!(digest, crate::db::ENGINE_56_SHAPE_CONTRACT_SHA256);
        let step = EngineMigrationRegistry::production()
            .pending(56, 57)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(step.name(), "engine-56-to-57-content-events-append-only");
        step.preflight(&mut conn).await.unwrap();
        step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version=57")
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(crate::db::validate_engine_shape_on_for_test(&mut conn, 57)
            .await
            .unwrap());
        // Run the remaining edges before
        // reopening: this keeps the test's subject the 56→57 edge while
        // leaving a file ordinary serving accepts.
        let step = EngineMigrationRegistry::production()
            .pending(57, 58)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(step.name(), "engine-57-to-58-agent-run-client-identity");
        step.preflight(&mut conn).await.unwrap();
        step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version=58")
            .execute(&mut conn)
            .await
            .unwrap();
        advance_engine_58_to_current(&mut conn, 58).await;
        conn.close().await.unwrap();

        let migrated = crate::open_existing_database_at(&path).await.unwrap();
        // No row is touched by the migration.
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(migrated.write_pool())
            .await
            .unwrap();
        assert_eq!(rows, legacy_rows);
        for statement in [
            "UPDATE content_events SET payload='{}' WHERE seq=1",
            "DELETE FROM content_events WHERE seq=1",
        ] {
            let error = sqlx::query(statement)
                .execute(migrated.write_pool())
                .await
                .unwrap_err();
            assert!(
                error.to_string().contains("content_events is append-only"),
                "{statement}: {error}"
            );
        }
        // Ordinary appends and reopen keep working on the migrated database.
        crate::store::create_record(
            &migrated,
            serde_json::json!({
                "id": "1a7e4000-0000-4000-8000-000000000074",
                "type": "Document",
                "kind": "note",
                "name": "post-migration record"
            }),
        )
        .await
        .unwrap();
        migrated.close().await;
        let reopened = crate::open_existing_database_at(&path).await.unwrap();
        let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(reopened.write_pool())
            .await
            .unwrap();
        assert_eq!(after, legacy_rows + 1);
        reopened.close().await;
    }

    /// The 57→58 edge adds three nullable `agent_runs` columns without
    /// touching any row, and the migrated database reopens with the same
    /// shape as a fresh one.
    #[tokio::test]
    async fn engine_57_to_58_adds_agent_run_client_identity_columns() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent-run-client-identity.db");
        create_current_schema(&path).await;
        let db = crate::open_existing_database_at(&path).await.unwrap();
        crate::control::ensure_agent_run(
            &db,
            "scout-chair-a748b2",
            "acct_alice",
            crate::control::ReportedRunIdentity::default(),
        )
        .await
        .unwrap();
        let legacy_runs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agent_runs")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(legacy_runs, 1);
        db.close().await;

        // Reconstruct the engine-57 preimage, then run the real 57→58 edge.
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        revert_to_engine_57(&mut conn).await;
        let digest = crate::db::schema_shape_contract_sha256_for_test(&mut conn)
            .await
            .unwrap();
        assert_eq!(digest, crate::db::ENGINE_57_SHAPE_CONTRACT_SHA256);
        let step = EngineMigrationRegistry::production()
            .pending(57, 58)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(step.name(), "engine-57-to-58-agent-run-client-identity");
        step.preflight(&mut conn).await.unwrap();
        step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version=58")
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(crate::db::validate_engine_shape_on_for_test(&mut conn, 58)
            .await
            .unwrap());
        advance_engine_58_to_current(&mut conn, 58).await;
        conn.close().await.unwrap();

        let migrated = crate::open_existing_database_at(&path).await.unwrap();
        // No row is touched by the migration; the pre-existing run keeps
        // NULL reported identity.
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agent_runs")
            .fetch_one(migrated.write_pool())
            .await
            .unwrap();
        assert_eq!(rows, legacy_runs);
        let identity =
            crate::control::read_agent_run_reported_identity(&migrated, "scout-chair-a748b2")
                .await
                .unwrap()
                .expect("migrated run reads back");
        assert_eq!(identity, crate::control::ReportedRunIdentity::default());
        // Ordinary admission keeps working on the migrated database.
        crate::control::ensure_agent_run(
            &migrated,
            "scout-chair-b748b2",
            "acct_alice",
            crate::control::ReportedRunIdentity {
                client_name: Some("hazel".into()),
                client_version: Some("2.1.0".into()),
                model: None,
            },
        )
        .await
        .unwrap();
        let stored =
            crate::control::read_agent_run_reported_identity(&migrated, "scout-chair-b748b2")
                .await
                .unwrap()
                .expect("post-migration run reads back");
        assert_eq!(stored.client_name.as_deref(), Some("hazel"));
        migrated.close().await;
    }

    /// The 58→59 DDL is transition text, but the objects it creates must stay
    /// byte-identical to the fresh-schema DDL: migrated databases are
    /// byte-identical to fresh ones under the shape contract only while both
    /// spellings agree.
    #[test]
    fn engine_58_to_59_statements_match_fresh_ddl() {
        for statement in ENGINE_58_TO_59_STATEMENTS {
            let prefix = if statement.starts_with("CREATE TABLE record_mentions (") {
                "CREATE TABLE record_mentions ("
            } else if statement.starts_with("CREATE INDEX idx_record_mentions_lookup") {
                "CREATE INDEX idx_record_mentions_lookup"
            } else if statement.starts_with("CREATE INDEX idx_record_mentions_source") {
                "CREATE INDEX idx_record_mentions_source"
            } else {
                panic!("unexpected 58→59 statement: {statement}");
            };
            let fresh = crate::schema::DDL_STATEMENTS
                .iter()
                .find(|candidate| candidate.starts_with(prefix))
                .unwrap_or_else(|| panic!("58→59 statement has no fresh-DDL twin: {prefix}"));
            assert_eq!(*fresh, statement, "58→59 statement drifted from fresh DDL");
        }
    }

    /// Dump the whole `record_mentions` projection as comparable text, with
    /// integer columns decoded as integers so value drift (not just row
    /// presence drift) fails the comparison.
    async fn dump_record_mentions(connection: &mut SqliteConnection) -> Vec<String> {
        sqlx::query(
            "SELECT source_id, occurrence_ix, source_event_seq, span_start, span_end,
                    authored_reference, lookup_key, form, parser_version
               FROM record_mentions ORDER BY source_id, occurrence_ix",
        )
        .fetch_all(&mut *connection)
        .await
        .unwrap()
        .iter()
        .map(|row| {
            format!(
                "{}|{}|{}|{}|{}|{}|{}|{}|{}",
                row.try_get::<String, _>("source_id").unwrap(),
                row.try_get::<i64, _>("occurrence_ix").unwrap(),
                row.try_get::<i64, _>("source_event_seq").unwrap(),
                row.try_get::<i64, _>("span_start").unwrap(),
                row.try_get::<i64, _>("span_end").unwrap(),
                row.try_get::<String, _>("authored_reference").unwrap(),
                row.try_get::<String, _>("lookup_key").unwrap(),
                row.try_get::<String, _>("form").unwrap(),
                row.try_get::<i64, _>("parser_version").unwrap(),
            )
        })
        .collect()
    }

    /// The 58→59 edge creates the projection and backfills it from live
    /// current bodies with latest-text-body provenance — and the backfilled
    /// database matches the pre-migration live fold row for row, including
    /// removal, tombstone and post-body metadata-update histories.
    #[tokio::test]
    async fn engine_58_to_59_backfills_live_bodies_with_text_provenance() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("record-mentions-backfill.db");
        create_current_schema(&path).await;
        let db = crate::open_existing_database_at(&path).await.unwrap();
        let body_a = "See abc1234 and [[My Note]] end.";
        let body_b = "Now https://n8v.to/def5678 only.";
        let kept = crate::store::create_record(
            &db,
            serde_json::json!({"type": "Document", "kind": "note", "name": "kept", "body": body_a}),
        )
        .await
        .unwrap();
        let replaced = crate::store::create_record(
            &db,
            serde_json::json!({"type": "Document", "kind": "note", "name": "replaced", "body": body_a}),
        )
        .await
        .unwrap();
        crate::store::update_record(&db, &replaced, serde_json::json!({"body": body_b}))
            .await
            .unwrap();
        // A non-body update after the body replacement carries a higher
        // sequence but no body: the backfill must stamp the body event, not
        // MAX(seq), exactly as the live fold kept it.
        crate::store::update_record(&db, &replaced, serde_json::json!({"summary": "touched"}))
            .await
            .unwrap();
        let renamed = crate::store::create_record(
            &db,
            serde_json::json!({"type": "Document", "kind": "note", "name": "renamed", "body": body_b}),
        )
        .await
        .unwrap();
        crate::store::update_record(&db, &renamed, serde_json::json!({"name": "renamed-again"}))
            .await
            .unwrap();
        let emptied = crate::store::create_record(
            &db,
            serde_json::json!({"type": "Document", "kind": "note", "name": "emptied", "body": body_a}),
        )
        .await
        .unwrap();
        crate::store::update_record(&db, &emptied, serde_json::json!({"body": null}))
            .await
            .unwrap();
        let tombstoned = crate::store::create_record(
            &db,
            serde_json::json!({"type": "Document", "kind": "note", "name": "tombstoned", "body": body_a}),
        )
        .await
        .unwrap();
        crate::store::delete_record(&db, &tombstoned).await.unwrap();
        let plain = crate::store::create_record(
            &db,
            serde_json::json!({"type": "Document", "kind": "note", "name": "plain"}),
        )
        .await
        .unwrap();
        // The live fold's answer, captured before the revert destroys it.
        let mut live_conn = db.write_pool().acquire().await.unwrap();
        let expected = dump_record_mentions(&mut live_conn).await;
        assert!(!expected.is_empty(), "fixture must fold some mentions live");
        drop(live_conn);
        for id in [&emptied, &tombstoned, &plain] {
            let rows: Vec<String> =
                sqlx::query_scalar("SELECT source_id FROM record_mentions WHERE source_id = ?")
                    .bind(id)
                    .fetch_all(db.write_pool())
                    .await
                    .unwrap();
            assert!(rows.is_empty(), "live fold leaves no rows for {id}");
        }
        // The replaced source keeps its body event's sequence, not the
        // later metadata update's.
        let body_seq: i64 = sqlx::query_scalar(
            "SELECT seq FROM content_events WHERE record_id = ? AND json_type(payload, '$.body') = 'text'
              ORDER BY seq DESC LIMIT 1",
        )
        .bind(&replaced)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        let max_seq: i64 =
            sqlx::query_scalar("SELECT MAX(seq) FROM content_events WHERE record_id = ?")
                .bind(&replaced)
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        assert!(
            max_seq > body_seq,
            "fixture needs a post-body non-body event"
        );
        let live_stamp: i64 = sqlx::query_scalar(
            "SELECT DISTINCT source_event_seq FROM record_mentions WHERE source_id = ?",
        )
        .bind(&replaced)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(live_stamp, body_seq);
        let _ = (kept, renamed);
        db.close().await;

        // Reconstruct the engine-58 preimage, then run the real 58→59 edge.
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        revert_to_engine_58(&mut conn).await;
        let digest = crate::db::schema_shape_contract_sha256_for_test(&mut conn)
            .await
            .unwrap();
        assert_eq!(digest, crate::db::ENGINE_58_SHAPE_CONTRACT_SHA256);
        let step = EngineMigrationRegistry::production()
            .pending(58, 59)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(step.name(), "engine-58-to-59-record-mentions-projection");
        step.preflight(&mut conn).await.unwrap();
        step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version=59")
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(crate::db::validate_engine_shape_on_for_test(&mut conn, 59)
            .await
            .unwrap());
        // Backfill ran inside the edge: the migrated table already matches
        // the live fold before reopening.
        assert_eq!(dump_record_mentions(&mut conn).await, expected);
        advance_engine_58_to_current(&mut conn, 59).await;
        conn.close().await.unwrap();

        let migrated = crate::open_existing_database_at(&path).await.unwrap();
        let mut migrated_conn = migrated.write_pool().acquire().await.unwrap();
        assert_eq!(dump_record_mentions(&mut migrated_conn).await, expected);
        drop(migrated_conn);
        // Replay from the log converges with the backfilled live state.
        let result = crate::conformance::rebuild_and_diff(&migrated)
            .await
            .unwrap();
        assert!(
            result.equal,
            "rebuild drift after 58→59: {}",
            serde_json::to_string_pretty(&result.tables).unwrap()
        );
        // Ordinary writes keep folding on the migrated database.
        let fresh = crate::store::create_record(
            &migrated,
            serde_json::json!({"type": "Document", "kind": "note", "name": "post", "body": body_a}),
        )
        .await
        .unwrap();
        let rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM record_mentions WHERE source_id = ?")
                .bind(&fresh)
                .fetch_one(migrated.write_pool())
                .await
                .unwrap();
        assert_eq!(rows, 2);
        migrated.close().await;
    }

    /// The 62→63 and 63→64 edges move no schema objects. A current-shape
    /// fixture stamped to 62 is their exact source; this is not a rollback API.
    async fn revert_to_engine_62(connection: &mut SqliteConnection) {
        revert_to_engine_64(connection).await;
        sqlx::query("PRAGMA user_version=62")
            .execute(&mut *connection)
            .await
            .unwrap();
    }

    async fn compact_63_to_64_and_stamp(connection: &mut SqliteConnection) {
        let compact = EngineMigrationRegistry::production()
            .pending(63, 64)
            .unwrap()
            .pop()
            .unwrap();
        compact.preflight(&mut *connection).await.unwrap();
        compact_database_in_place(connection, compact.as_ref(), "fixture")
            .await
            .unwrap();
        compact.apply(connection).await.unwrap();
        sqlx::query("PRAGMA user_version=64")
            .execute(&mut *connection)
            .await
            .unwrap();
    }

    /// The 62→63 edge moves no schema objects: a file stamped back to 62
    /// admits the frozen engine-62 shape, and the edge leaves that shape —
    /// and current-shape validation — intact.
    #[tokio::test]
    async fn engine_62_shape_is_the_data_only_source_shape() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("read-log-cleanup-shape.db");
        create_current_schema(&path).await;
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        revert_to_engine_62(&mut conn).await;
        let digest = crate::db::schema_shape_contract_sha256_for_test(&mut conn)
            .await
            .unwrap();
        assert_eq!(digest, crate::db::ENGINE_62_SHAPE_CONTRACT_SHA256);
        let step = EngineMigrationRegistry::production()
            .pending(62, 63)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(step.name(), "engine-62-to-63-read-log-selective-cleanup");
        step.preflight(&mut conn).await.unwrap();
        step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version=63")
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(crate::db::validate_engine_shape_on_for_test(&mut conn, 63)
            .await
            .unwrap());
        assert_eq!(
            crate::db::schema_shape_contract_sha256_for_test(&mut conn)
                .await
                .unwrap(),
            crate::db::ENGINE_63_SHAPE_CONTRACT_SHA256
        );
        let compact = EngineMigrationRegistry::production()
            .pending(63, 64)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(
            compact.name(),
            "engine-63-to-64-read-log-freelist-compaction"
        );
        compact.preflight(&mut conn).await.unwrap();
        compact_database_in_place(&mut conn, compact.as_ref(), "fixture")
            .await
            .unwrap();
        compact.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version=64")
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(crate::db::validate_engine_shape_on_for_test(&mut conn, 64)
            .await
            .unwrap());
        conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn engine_63_to_64_compaction_shrinks_and_retries_after_lost_fence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("engine-63-freelist.db");
        create_current_schema(&path).await;
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        revert_to_engine_64(&mut conn).await;
        sqlx::query("PRAGMA user_version=63")
            .execute(&mut conn)
            .await
            .unwrap();
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut conn)
            .await
            .unwrap();
        let arguments = "x".repeat(4096);
        for seq in 1..=600 {
            sqlx::query("INSERT INTO read_log_calls(id,tool,arguments,outcome,started_at,ended_at) VALUES(?,?,?,?,?,?)")
                .bind(format!("compaction-{seq}"))
                .bind("unknown-retained-tool")
                .bind(&arguments)
                .bind("ok")
                .bind("2026-09-23T00:00:00Z")
                .bind("2026-09-23T00:00:01Z")
                .execute(&mut conn)
                .await
                .unwrap();
        }
        sqlx::query("COMMIT").execute(&mut conn).await.unwrap();
        sqlx::query("DELETE FROM read_log_calls WHERE seq > 1")
            .execute(&mut conn)
            .await
            .unwrap();
        let before_size = checkpoint_file_bytes(&mut conn, &path).await;
        let before_free: i64 = sqlx::query_scalar("PRAGMA freelist_count")
            .fetch_one(&mut conn)
            .await
            .unwrap();
        assert!(before_free > 0);
        let retained: String =
            sqlx::query_scalar("SELECT arguments FROM read_log_calls WHERE seq=1")
                .fetch_one(&mut conn)
                .await
                .unwrap();
        let high_water: i64 =
            sqlx::query_scalar("SELECT seq FROM sqlite_sequence WHERE name='read_log_calls'")
                .fetch_one(&mut conn)
                .await
                .unwrap();
        assert_eq!(high_water, 600);
        conn.close().await.unwrap();

        let offbox = tempfile::tempdir().unwrap();
        let backup = test_preimage_store(offbox.path(), dir.path());
        let calls = Arc::new(AtomicUsize::new(0));
        let fence: FenceFn = Arc::new({
            let calls = calls.clone();
            move || {
                let call = calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    if call == 2 {
                        Err(Error::engine("lost fence after VACUUM"))
                    } else {
                        Ok(())
                    }
                }
                .boxed()
            }
        });
        let failed = migrate_database_with_reservation(
            &path,
            "compaction-user",
            "compaction-lost-fence",
            64,
            &EngineMigrationRegistry::production(),
            &backup,
            fence,
            None,
            None,
            None,
        )
        .await;
        assert_eq!(failed.outcome, "failed", "{failed:?}");
        assert_eq!(failed.error_kind.as_deref(), Some("fence"));
        assert!(failed.backup.is_some());
        assert_eq!(header_version(&path), 63);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        let compacted_size = std::fs::metadata(&path).unwrap().len();
        assert!(
            compacted_size < before_size,
            "{before_size} -> {compacted_size}"
        );

        // The retry covers the same source and stamps only after VACUUM,
        // integrity, FK, shape, and fence checks. The test verifier keeps this
        // recovery test focused; production always runs full conformance.
        let verifier: PostMigrationVerifier =
            Arc::new(|_| async { PostMigrationVerification::Passed }.boxed());
        let retry = migrate_database_with_reservation(
            &path,
            "compaction-user",
            "compaction-retry",
            64,
            &EngineMigrationRegistry::production(),
            &backup,
            always_fenced(),
            None,
            Some(verifier),
            None,
        )
        .await;
        assert_eq!(retry.outcome, "migrated", "{retry:?}");
        assert_eq!(header_version(&path), 64);
        let mut after = SqliteConnection::connect_with(&options).await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, String>("SELECT arguments FROM read_log_calls WHERE seq=1")
                .fetch_one(&mut after)
                .await
                .unwrap(),
            retained
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT seq FROM sqlite_sequence WHERE name='read_log_calls'"
            )
            .fetch_one(&mut after)
            .await
            .unwrap(),
            high_water
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("PRAGMA freelist_count")
                .fetch_one(&mut after)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>("PRAGMA integrity_check")
                .fetch_one(&mut after)
                .await
                .unwrap(),
            "ok"
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM pragma_foreign_key_check")
                .fetch_one(&mut after)
                .await
                .unwrap(),
            0
        );
        assert!(crate::db::validate_engine_shape_on_for_test(&mut after, 64)
            .await
            .unwrap());
        after.close().await.unwrap();
    }

    #[tokio::test]
    async fn engine_63_to_64_refuses_nonfrozen_source_before_backup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("engine-63-unknown-shape.db");
        create_current_schema(&path).await;
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        revert_to_engine_64(&mut conn).await;
        sqlx::query("PRAGMA user_version=63")
            .execute(&mut conn)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE unreviewed_schema_object (id INTEGER PRIMARY KEY)")
            .execute(&mut conn)
            .await
            .unwrap();
        conn.close().await.unwrap();
        let offbox = tempfile::tempdir().unwrap();
        let backup = test_preimage_store(offbox.path(), dir.path());
        let failed = migrate_database_with_reservation(
            &path,
            "compaction-user",
            "unknown-source",
            64,
            &EngineMigrationRegistry::production(),
            &backup,
            always_fenced(),
            None,
            None,
            None,
        )
        .await;
        assert_eq!(failed.outcome, "failed", "{failed:?}");
        assert_eq!(failed.error_kind.as_deref(), Some("preflight"));
        assert!(failed.backup.is_none());
        assert_eq!(header_version(&path), 63);
    }

    #[tokio::test]
    async fn engine_62_to_65_runner_cleans_compacts_and_fully_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("engine-62-to-65.db");
        create_current_schema(&path).await;
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        revert_to_engine_62(&mut conn).await;
        sqlx::query("INSERT INTO read_log_calls(id,tool,arguments,outcome,started_at,ended_at) VALUES('disposable-read','get_record','{}','ok','2026-09-23','2026-09-23')")
            .execute(&mut conn)
            .await
            .unwrap();
        conn.close().await.unwrap();
        let offbox = tempfile::tempdir().unwrap();
        let backup = test_preimage_store(offbox.path(), dir.path());
        let result = migrate_database_with_reservation(
            &path,
            "multi-hop-user",
            "multi-hop-run",
            65,
            &EngineMigrationRegistry::production(),
            &backup,
            always_fenced(),
            None,
            None,
            None,
        )
        .await;
        assert_eq!(result.outcome, "migrated", "{result:?}");
        assert!(result.backup.is_some());
        assert_eq!(header_version(&path), 65);
        let mut after = SqliteConnection::connect_with(&options).await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM read_log_calls")
                .fetch_one(&mut after)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("PRAGMA freelist_count")
                .fetch_one(&mut after)
                .await
                .unwrap(),
            0
        );
        after.close().await.unwrap();
    }

    /// The cleanup's frozen tool sets match the reviewed PR A disposition.
    /// Every tool from that snapshot
    /// lands in exactly one bucket, `bootstrap` stays issuance-side,
    /// `set_intent` stays mutation-side, and no action-evidence surface is
    /// ever classified disposable-pure-read. A future tool addition or
    /// disposition change fails here and forces a migration review instead
    /// of silently changing what historical cleanup deletes.
    #[test]
    fn read_log_cleanup_predicate_covers_every_shipped_tool() {
        use std::collections::BTreeSet;

        use crate::mcp::action_evidence;
        let pure: BTreeSet<&str> = read_log_disposable_pure_reads().into_iter().collect();
        let mixed: BTreeSet<&str> = read_log_mixed_reads()
            .iter()
            .map(|(tool, actions)| {
                assert!(
                    !actions.is_empty(),
                    "{tool} must list at least one read action"
                );
                *tool
            })
            .collect();
        let mutation: BTreeSet<&str> = ENGINE_62_TO_63_MUTATION_TOOLS.iter().copied().collect();
        assert!(
            pure.is_disjoint(&mixed) && pure.is_disjoint(&mutation) && mixed.is_disjoint(&mutation),
            "cleanup buckets must partition the shipped tools"
        );
        let covered: BTreeSet<&str> = pure.union(&mixed).chain(mutation.iter()).copied().collect();
        let all: BTreeSet<&str> = ToolKind::ALL.iter().map(|kind| kind.name()).collect();
        // Bootstrap is issuance. The explicitly listed post-freeze tool is
        // retained as unknown historical evidence by this edge.
        let mut expected_outside = vec![ToolKind::Bootstrap.name()];
        expected_outside.extend_from_slice(ENGINE_62_TO_63_POST_FREEZE_TOOLS);
        expected_outside.sort_unstable();
        let mut actual_outside: Vec<&str> = all.difference(&covered).copied().collect();
        actual_outside.sort_unstable();
        assert_eq!(
            actual_outside, expected_outside,
            "only issuance and explicitly reviewed post-freeze tools may be outside the cleanup buckets"
        );
        assert!(
            !pure.contains(ToolKind::Bootstrap.name()),
            "bootstrap is issuance, never disposable exhaust"
        );
        assert!(
            mutation.contains(ToolKind::SetIntent.name()),
            "set_intent declarations must survive historical cleanup"
        );
        for surface in action_evidence::action_evidence_surfaces() {
            assert!(
                !pure.contains(surface),
                "{surface} is action evidence and must never be disposable-pure-read"
            );
        }
        for kind in action_evidence::ANNOTATION_SURFACES {
            assert!(
                !pure.contains(kind.name()),
                "{:?} can carry a retained annotation and must never be disposable-pure-read",
                kind.name()
            );
        }
    }

    /// The frozen 62→63 policy equals the reviewed PR A disposition after
    /// subtracting only explicitly named post-freeze additions. Historical
    /// deletion replays this frozen classification, so another tool addition
    /// or reclassification fails here until deliberately reviewed.
    #[test]
    fn engine_62_to_63_frozen_policy_matches_current_disposition() {
        let mut derived_pure: Vec<&str> = ToolKind::ALL
            .iter()
            .filter(|kind| {
                matches!(
                    kind.authoritative_disposition(),
                    AuthoritativeDisposition::Read
                ) && **kind != ToolKind::Bootstrap
            })
            .map(|kind| kind.name())
            .collect();
        derived_pure.retain(|name| !ENGINE_62_TO_63_POST_FREEZE_TOOLS.contains(name));
        derived_pure.sort_unstable();
        let mut frozen_pure = ENGINE_62_TO_63_PURE_READ_TOOLS.to_vec();
        frozen_pure.sort_unstable();
        assert_eq!(
            frozen_pure, derived_pure,
            "frozen pure-read list drifted from current disposition"
        );
        let mut derived_mixed: Vec<(&str, Vec<&str>)> = ToolKind::ALL
            .iter()
            .filter_map(|kind| match kind.authoritative_disposition() {
                AuthoritativeDisposition::Actions(actions) => {
                    let mut reads = actions.to_vec();
                    reads.sort_unstable();
                    Some((kind.name(), reads))
                }
                AuthoritativeDisposition::Read | AuthoritativeDisposition::Mutation => None,
            })
            .collect();
        derived_mixed.retain(|(name, _)| !ENGINE_62_TO_63_POST_FREEZE_TOOLS.contains(name));
        derived_mixed.sort_unstable_by(|a, b| a.0.cmp(b.0));
        let mut frozen_mixed: Vec<(&str, Vec<&str>)> = ENGINE_62_TO_63_MIXED_READS
            .iter()
            .map(|(tool, actions)| {
                let mut reads = actions.to_vec();
                reads.sort_unstable();
                (*tool, reads)
            })
            .collect();
        frozen_mixed.sort_unstable_by(|a, b| a.0.cmp(b.0));
        assert_eq!(
            frozen_mixed, derived_mixed,
            "frozen mixed-read list drifted from current disposition"
        );
        let mut derived_mutation: Vec<&str> = ToolKind::ALL
            .iter()
            .filter(|kind| {
                matches!(
                    kind.authoritative_disposition(),
                    AuthoritativeDisposition::Mutation
                )
            })
            .map(|kind| kind.name())
            .collect();
        derived_mutation.sort_unstable();
        let mut frozen_mutation = ENGINE_62_TO_63_MUTATION_TOOLS.to_vec();
        frozen_mutation.sort_unstable();
        assert_eq!(
            frozen_mutation, derived_mutation,
            "frozen mutation list drifted from current disposition"
        );
    }

    #[tokio::test]
    async fn engine_62_to_63_retains_post_freeze_authority_act_reads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("authority-act-read-retention.db");
        create_current_schema(&path).await;
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut connection = SqliteConnection::connect_with(&options).await.unwrap();
        revert_to_engine_62(&mut connection).await;
        for (seq, tool) in [(1, "authority_act_head"), (2, "authority_act_delta")] {
            insert_read_log_call(
                &mut connection,
                seq,
                tool,
                Some("run:act"),
                None,
                None,
                r#"{"cursor":"historical"}"#,
                "ok",
                None,
            )
            .await;
        }
        let report = read_log_62_to_63_attention_report(&mut connection)
            .await
            .unwrap();
        assert_eq!(report.total_calls, 2);
        assert_eq!(report.disposable_calls, 0);
        assert_eq!(report.unknown_tool_calls, 0);
        let step = EngineMigrationRegistry::production()
            .pending(62, 63)
            .unwrap()
            .pop()
            .unwrap();
        step.preflight(&mut connection).await.unwrap();
        step.apply(&mut connection).await.unwrap();
        let retained: Vec<(String, String)> =
            sqlx::query_as("SELECT tool, arguments FROM read_log_calls ORDER BY seq")
                .fetch_all(&mut connection)
                .await
                .unwrap();
        assert_eq!(
            retained,
            vec![
                (
                    "authority_act_head".into(),
                    r#"{"cursor":"historical"}"#.into()
                ),
                (
                    "authority_act_delta".into(),
                    r#"{"cursor":"historical"}"#.into()
                ),
            ]
        );
    }

    #[allow(clippy::too_many_arguments)]
    async fn insert_read_log_call(
        connection: &mut SqliteConnection,
        seq: i64,
        tool: &str,
        run_key: Option<&str>,
        parent_key: Option<&str>,
        intent: Option<&str>,
        arguments: &str,
        outcome: &str,
        annotation: Option<&str>,
    ) {
        sqlx::query(
            "INSERT INTO read_log_calls
             (seq, id, tool, run_key, parent_key, intent, actor, arguments,
              outcome, error_kind, result_count, result_bytes,
              started_at, ended_at, result_annotation)
             VALUES (?, ?, ?, ?, ?, ?, 'test-actor', ?, ?, \
                     CASE WHEN ? = 'error' THEN 'test_error' ELSE NULL END, \
                     NULL, NULL, '2026-09-01T00:00:00.000Z', \
                     '2026-09-01T00:00:' || printf('%02d', ?) || '.000Z', ?)",
        )
        .bind(seq)
        .bind(format!("call-{seq:04}"))
        .bind(tool)
        .bind(run_key)
        .bind(parent_key)
        .bind(intent)
        .bind(arguments)
        .bind(outcome)
        .bind(outcome)
        .bind(seq)
        .bind(annotation)
        .execute(&mut *connection)
        .await
        .unwrap();
    }

    async fn insert_read_log_touch(
        connection: &mut SqliteConnection,
        call_seq: i64,
        record_ref: i64,
        interaction: &str,
        result_rank: Option<i64>,
    ) {
        sqlx::query(
            "INSERT INTO read_log_touches (call_seq, record_ref, interaction, result_rank)
             VALUES (?, ?, ?, ?)",
        )
        .bind(call_seq)
        .bind(record_ref)
        .bind(interaction)
        .bind(result_rank)
        .execute(&mut *connection)
        .await
        .unwrap();
    }

    /// The 62→63 edge keeps exactly PR A's retention classes with verbatim
    /// evidence, deletes disposable exhaust (cascading its touches), strips
    /// issuance touches and non-selector arguments, purges newly orphaned
    /// dictionary entries, and preserves `seq`, ordering, parentage, and the
    /// `AUTOINCREMENT` high-water mark. Re-applying the edge is a no-op.
    #[tokio::test]
    async fn engine_62_to_63_selective_cleanup_retains_action_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("read-log-cleanup-fixture.db");
        create_current_schema(&path).await;
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        revert_to_engine_62(&mut conn).await;
        for (record_ref, record_id) in [
            (1, "fixture-record-a"),
            (2, "fixture-record-b"),
            (3, "fixture-record-c"),
            (4, "fixture-record-d"),
            (5, "fixture-record-e"),
            (6, "fixture-record-f"),
            (7, "fixture-preexisting-orphan"),
        ] {
            sqlx::query("INSERT INTO read_log_record_ids (record_ref, record_id) VALUES (?, ?)")
                .bind(record_ref)
                .bind(record_id)
                .execute(&mut conn)
                .await
                .unwrap();
        }
        // Disposable pure reads.
        insert_read_log_call(
            &mut conn,
            1,
            "get_record",
            Some("r1"),
            None,
            None,
            r#"{"id":"fixture-record-a"}"#,
            "ok",
            None,
        )
        .await;
        insert_read_log_touch(&mut conn, 1, 1, "surfaced", Some(1)).await;
        insert_read_log_call(
            &mut conn,
            2,
            "search",
            Some("r1"),
            None,
            None,
            r#"{"query":"width"}"#,
            "ok",
            None,
        )
        .await;
        // Run issuance: kept as identity, stripped of attention.
        insert_read_log_call(
            &mut conn,
            3,
            "bootstrap",
            Some("run:r1"),
            None,
            None,
            r#"{"orientation":"deep"}"#,
            "ok",
            None,
        )
        .await;
        insert_read_log_touch(&mut conn, 3, 2, "surfaced", Some(1)).await;
        insert_read_log_touch(&mut conn, 3, 2, "opened", None).await;
        insert_read_log_call(
            &mut conn,
            4,
            "get_record",
            None,
            Some("r0"),
            None,
            r#"{"id":"fixture-record-c","run_key":"new:scout"}"#,
            "ok",
            None,
        )
        .await;
        insert_read_log_touch(&mut conn, 4, 3, "surfaced", Some(2)).await;
        // Declarations: success and failed attempt.
        insert_read_log_call(
            &mut conn,
            5,
            "set_intent",
            Some("r1"),
            None,
            Some("hunt"),
            r#"{"intent":"hunt","run_key":"r1"}"#,
            "ok",
            None,
        )
        .await;
        insert_read_log_call(
            &mut conn,
            6,
            "set_intent",
            Some("r1"),
            None,
            None,
            r#"{"intent":"hunt"}"#,
            "error",
            None,
        )
        .await;
        // Annotation-bearing read: kept with its touches.
        insert_read_log_call(
            &mut conn,
            7,
            "get_record",
            Some("r1"),
            None,
            None,
            r#"{"id":"fixture-record-d"}"#,
            "ok",
            Some(r#"{"overlap":"o1"}"#),
        )
        .await;
        insert_read_log_touch(&mut conn, 7, 4, "opened", Some(2)).await;
        // Mutations and mixed writes: kept.
        insert_read_log_call(
            &mut conn,
            8,
            "update_record",
            Some("r1"),
            Some("r1"),
            None,
            r#"{"id":"fixture-record-b","body":"b"}"#,
            "ok",
            None,
        )
        .await;
        insert_read_log_touch(&mut conn, 8, 2, "mutated", None).await;
        insert_read_log_call(
            &mut conn,
            9,
            "manage_links",
            Some("r1"),
            None,
            None,
            r#"{"action":"add","target_id":"fixture-record-b"}"#,
            "ok",
            None,
        )
        .await;
        insert_read_log_touch(&mut conn, 9, 2, "mutated", None).await;
        // Mixed read action: disposable.
        insert_read_log_call(
            &mut conn,
            10,
            "manage_links",
            Some("r1"),
            None,
            None,
            r#"{"action":"list"}"#,
            "ok",
            None,
        )
        .await;
        insert_read_log_touch(&mut conn, 10, 2, "surfaced", Some(3)).await;
        // Mixed unknown/malformed actions: fail closed (kept).
        insert_read_log_call(
            &mut conn,
            11,
            "manage_links",
            Some("r1"),
            None,
            None,
            r#"{"action":"bogus-future"}"#,
            "ok",
            None,
        )
        .await;
        insert_read_log_call(
            &mut conn,
            12,
            "manage_links",
            Some("r1"),
            None,
            None,
            r#"{}"#,
            "ok",
            None,
        )
        .await;
        // Mutation surface without a mutated touch: kept by disposition.
        insert_read_log_call(
            &mut conn,
            13,
            "create_record",
            Some("r1"),
            None,
            None,
            r#"{"type":"Document","kind":"note"}"#,
            "ok",
            None,
        )
        .await;
        insert_read_log_touch(&mut conn, 13, 5, "surfaced", Some(1)).await;
        // Failed mutation attempt: kept. Failed pure read: dropped.
        insert_read_log_call(
            &mut conn,
            14,
            "delete_record",
            Some("r1"),
            None,
            None,
            r#"{"id":"fixture-record-b"}"#,
            "error",
            None,
        )
        .await;
        insert_read_log_call(
            &mut conn,
            15,
            "get_record",
            Some("r1"),
            None,
            None,
            r#"{"id":"fixture-record-b"}"#,
            "error",
            None,
        )
        .await;
        // Unknown tool: fail closed (kept with touches).
        insert_read_log_call(
            &mut conn,
            16,
            "nonexistent_tool_fixture",
            Some("r1"),
            None,
            None,
            r#"{}"#,
            "ok",
            None,
        )
        .await;
        insert_read_log_touch(&mut conn, 16, 6, "surfaced", None).await;
        // Mixed read vs write on a coordination surface.
        insert_read_log_call(
            &mut conn,
            17,
            "start_work",
            Some("r1"),
            None,
            None,
            r#"{"action":"preview"}"#,
            "ok",
            None,
        )
        .await;
        insert_read_log_touch(&mut conn, 17, 2, "surfaced", None).await;
        insert_read_log_call(
            &mut conn,
            18,
            "start_work",
            Some("r1"),
            None,
            None,
            r#"{"action":"release","run_key":"r1"}"#,
            "ok",
            None,
        )
        .await;
        insert_read_log_touch(&mut conn, 18, 2, "mutated", None).await;
        // Malformed historical arguments: retained byte-identical with their
        // touches, whatever the tool. A known pure read and a mixed tool
        // cannot match through JSON extracts; a `bootstrap` issuance row
        // still strips attention touches (no JSON needed) but keeps its
        // exact argument bytes.
        insert_read_log_call(
            &mut conn,
            19,
            "get_record",
            Some("r1"),
            None,
            None,
            "{invalid-json",
            "ok",
            None,
        )
        .await;
        insert_read_log_touch(&mut conn, 19, 2, "surfaced", None).await;
        insert_read_log_call(
            &mut conn,
            20,
            "manage_links",
            Some("r1"),
            None,
            None,
            "[1,2",
            "ok",
            None,
        )
        .await;
        insert_read_log_call(
            &mut conn,
            21,
            "bootstrap",
            Some("run:r2"),
            None,
            None,
            "garbage",
            "ok",
            None,
        )
        .await;
        insert_read_log_touch(&mut conn, 21, 2, "surfaced", None).await;
        // SQL NULL is distinct from malformed text and must also fail closed.
        for (seq, tool) in [(22, "get_record"), (23, "manage_links")] {
            insert_read_log_call(
                &mut conn,
                seq,
                tool,
                Some("r1"),
                None,
                None,
                "{}",
                "ok",
                None,
            )
            .await;
            sqlx::query("UPDATE read_log_calls SET arguments = NULL WHERE seq = ?")
                .bind(seq)
                .execute(&mut conn)
                .await
                .unwrap();
            insert_read_log_touch(&mut conn, seq, 2, "surfaced", None).await;
        }

        let high_water: i64 =
            sqlx::query_scalar("SELECT seq FROM sqlite_sequence WHERE name = 'read_log_calls'")
                .fetch_one(&mut conn)
                .await
                .unwrap();
        assert_eq!(high_water, 23);

        let report = read_log_62_to_63_attention_report(&mut conn).await.unwrap();
        assert_eq!(report.total_calls, 23);
        assert_eq!(report.disposable_calls, 5);
        assert_eq!(report.retained_calls, 18);
        assert_eq!(report.issuance_calls, 3);
        assert_eq!(report.unknown_tool_calls, 1);
        assert_eq!(report.null_arguments_calls, 2);
        assert_eq!(report.malformed_arguments_calls, 3);
        assert_eq!(report.mixed_missing_or_nontext_action_calls, 1);
        assert_eq!(report.mixed_unmatched_text_action_calls, 3);
        assert_eq!(report.total_touches, 16);
        assert_eq!(report.removable_touches, 7);
        assert_eq!(report.total_dictionary_entries, 7);
        assert_eq!(report.projected_orphan_dictionary_entries, 3);

        let step = EngineMigrationRegistry::production()
            .pending(62, 63)
            .unwrap()
            .pop()
            .unwrap();
        step.preflight(&mut conn).await.unwrap();
        step.apply(&mut conn).await.unwrap();

        let remaining: Vec<i64> = sqlx::query_scalar("SELECT seq FROM read_log_calls ORDER BY seq")
            .fetch_all(&mut conn)
            .await
            .unwrap();
        assert_eq!(
            remaining,
            vec![3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 16, 18, 19, 20, 21, 22, 23]
        );
        // Issuance rows keep identity columns but lose attention touches and
        // non-selector arguments. The malformed `bootstrap` row (21) strips
        // touches without JSON, while the malformed non-issuance rows (19,
        // 20) keep theirs.
        let issuance_touches: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM read_log_touches WHERE call_seq IN (3, 4, 21)",
        )
        .fetch_one(&mut conn)
        .await
        .unwrap();
        assert_eq!(issuance_touches, 0);
        for (seq, arguments) in [(19, "{invalid-json"), (20, "[1,2"), (21, "garbage")] {
            let stored: String =
                sqlx::query_scalar("SELECT arguments FROM read_log_calls WHERE seq = ?")
                    .bind(seq)
                    .fetch_one(&mut conn)
                    .await
                    .unwrap();
            assert_eq!(stored, arguments, "seq {seq} must keep exact bytes");
        }
        for seq in [22, 23] {
            let stored: Option<String> =
                sqlx::query_scalar("SELECT arguments FROM read_log_calls WHERE seq = ?")
                    .bind(seq)
                    .fetch_one(&mut conn)
                    .await
                    .unwrap();
            assert_eq!(stored, None, "seq {seq} must keep SQL NULL arguments");
        }
        let bootstrap2_run_key: Option<String> =
            sqlx::query_scalar("SELECT run_key FROM read_log_calls WHERE seq = 21")
                .fetch_one(&mut conn)
                .await
                .unwrap();
        assert_eq!(bootstrap2_run_key.as_deref(), Some("run:r2"));
        let bootstrap_args: String =
            sqlx::query_scalar("SELECT arguments FROM read_log_calls WHERE seq = 3")
                .fetch_one(&mut conn)
                .await
                .unwrap();
        assert_eq!(bootstrap_args, "{}");
        let bootstrap_run_key: Option<String> =
            sqlx::query_scalar("SELECT run_key FROM read_log_calls WHERE seq = 3")
                .fetch_one(&mut conn)
                .await
                .unwrap();
        assert_eq!(bootstrap_run_key.as_deref(), Some("run:r1"));
        let scout_args: String =
            sqlx::query_scalar("SELECT arguments FROM read_log_calls WHERE seq = 4")
                .fetch_one(&mut conn)
                .await
                .unwrap();
        assert_eq!(scout_args, r#"{"run_key":"new:scout"}"#);
        // Retained evidence stays verbatim: arguments, annotation, touches
        // (with rank), ordering, and parentage.
        let intent_args: String =
            sqlx::query_scalar("SELECT arguments FROM read_log_calls WHERE seq = 5")
                .fetch_one(&mut conn)
                .await
                .unwrap();
        assert_eq!(intent_args, r#"{"intent":"hunt","run_key":"r1"}"#);
        let annotation: Option<String> =
            sqlx::query_scalar("SELECT result_annotation FROM read_log_calls WHERE seq = 7")
                .fetch_one(&mut conn)
                .await
                .unwrap();
        assert_eq!(annotation.as_deref(), Some(r#"{"overlap":"o1"}"#));
        let touches: Vec<(i64, i64, String, Option<i64>)> = sqlx::query_as(
            "SELECT call_seq, record_ref, interaction, result_rank
             FROM read_log_touches ORDER BY call_seq, record_ref, interaction",
        )
        .fetch_all(&mut conn)
        .await
        .unwrap();
        assert_eq!(
            touches,
            vec![
                (7, 4, "opened".to_owned(), Some(2)),
                (8, 2, "mutated".to_owned(), None),
                (9, 2, "mutated".to_owned(), None),
                (13, 5, "surfaced".to_owned(), Some(1)),
                (16, 6, "surfaced".to_owned(), None),
                (18, 2, "mutated".to_owned(), None),
                (19, 2, "surfaced".to_owned(), None),
                (22, 2, "surfaced".to_owned(), None),
                (23, 2, "surfaced".to_owned(), None),
            ]
        );
        let parentage: Option<String> =
            sqlx::query_scalar("SELECT parent_key FROM read_log_calls WHERE seq = 8")
                .fetch_one(&mut conn)
                .await
                .unwrap();
        assert_eq!(parentage.as_deref(), Some("r1"));
        // Dictionary entries survive only while referenced: refs 1 and 3
        // were orphaned by the cleanup and 7 was already orphaned.
        let dictionary: Vec<i64> =
            sqlx::query_scalar("SELECT record_ref FROM read_log_record_ids ORDER BY record_ref")
                .fetch_all(&mut conn)
                .await
                .unwrap();
        assert_eq!(dictionary, vec![2, 4, 5, 6]);
        // The AUTOINCREMENT high-water mark survives: new rows continue above
        // the pre-cleanup maximum rather than reusing deleted sequence values.
        let high_water_after: i64 =
            sqlx::query_scalar("SELECT seq FROM sqlite_sequence WHERE name = 'read_log_calls'")
                .fetch_one(&mut conn)
                .await
                .unwrap();
        assert_eq!(high_water_after, 23);
        let violations: Vec<(String, Option<i64>, String, i64)> =
            sqlx::query_as("SELECT \"table\", rowid, parent, fkid FROM pragma_foreign_key_check")
                .fetch_all(&mut conn)
                .await
                .unwrap();
        assert!(violations.is_empty(), "FK violations: {violations:?}");
        // Re-applying the edge over the cleaned file is a no-op retry.
        step.apply(&mut conn).await.unwrap();
        let remaining_retry: Vec<i64> =
            sqlx::query_scalar("SELECT seq FROM read_log_calls ORDER BY seq")
                .fetch_all(&mut conn)
                .await
                .unwrap();
        assert_eq!(remaining_retry, remaining);
        let post_report = read_log_62_to_63_attention_report(&mut conn).await.unwrap();
        assert_eq!(post_report.disposable_calls, 0);
        assert_eq!(post_report.removable_touches, 0);
        assert_eq!(post_report.projected_orphan_dictionary_entries, 0);
        sqlx::query("PRAGMA user_version=63")
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(crate::db::validate_engine_shape_on_for_test(&mut conn, 63)
            .await
            .unwrap());
        compact_63_to_64_and_stamp(&mut conn).await;
        let alpha_step = EngineMigrationRegistry::production()
            .pending(64, 65)
            .unwrap()
            .pop()
            .unwrap();
        alpha_step.preflight(&mut conn).await.unwrap();
        alpha_step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version=65")
            .execute(&mut conn)
            .await
            .unwrap();
        conn.close().await.unwrap();

        // The migrated file opens and passes post-migration verification:
        // current shape, open behavior, and the full conformance suite.
        assert!(matches!(
            verify_migrated_database(path.clone(), "fixture").await,
            PostMigrationVerification::Passed
        ));
        // New captures continue above the retained high-water mark.
        let migrated = crate::open_existing_database_at(&path).await.unwrap();
        sqlx::query(
            "INSERT INTO read_log_calls
             (id, tool, outcome, started_at, ended_at)
             VALUES ('post-cleanup-probe', 'get_record', 'ok',
                     '2026-09-01T00:00:00.000Z', '2026-09-01T00:01:00.000Z')",
        )
        .execute(migrated.write_pool())
        .await
        .unwrap();
        let probe_seq: i64 =
            sqlx::query_scalar("SELECT seq FROM read_log_calls WHERE id = 'post-cleanup-probe'")
                .fetch_one(migrated.write_pool())
                .await
                .unwrap();
        assert_eq!(probe_seq, 24);
        migrated.close().await;
    }

    /// Reconstruct the released engine-64 (main64) shape: current DDL minus
    /// exactly the `alpha_tab_installs` projection table and its artifact
    /// index. Dropping the table removes its index with it; the reverted
    /// schema compares equal to fresh main64 DDL under the shape contract.
    /// Test fixtures only; this is not a rollback API.
    async fn revert_to_engine_64(connection: &mut SqliteConnection) {
        sqlx::query("DROP TABLE alpha_tab_installs")
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query("PRAGMA user_version=64")
            .execute(&mut *connection)
            .await
            .unwrap();
    }

    /// The 64→65 DDL is transition text, but the objects it creates must stay
    /// byte-identical to the fresh-schema DDL: migrated databases are
    /// byte-identical to fresh ones under the shape contract only while both
    /// spellings agree.
    #[test]
    fn engine_64_to_65_statements_match_fresh_ddl() {
        for statement in ENGINE_64_TO_65_STATEMENTS {
            let prefix = if statement.starts_with("CREATE TABLE alpha_tab_installs (") {
                "CREATE TABLE alpha_tab_installs ("
            } else if statement.starts_with("CREATE INDEX idx_alpha_tab_installs_artifact") {
                "CREATE INDEX idx_alpha_tab_installs_artifact"
            } else {
                panic!("unexpected 64→65 statement: {statement}");
            };
            let fresh = crate::schema::DDL_STATEMENTS
                .iter()
                .find(|candidate| candidate.starts_with(prefix))
                .unwrap_or_else(|| panic!("64→65 statement has no fresh-DDL twin: {prefix}"));
            assert_eq!(*fresh, statement, "64→65 statement drifted from fresh DDL");
        }
    }

    /// The 64→65 edge adds the empty `alpha_tab_installs` projection: the
    /// migrated database validates at schema 65, the table starts empty, and
    /// ordinary control writes keep folding on the migrated database.
    #[tokio::test]
    async fn engine_64_to_65_adds_empty_alpha_tab_installs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("alpha-tab-installs-edge.db");
        create_current_schema(&path).await;
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        revert_to_engine_64(&mut conn).await;
        let digest = crate::db::schema_shape_contract_sha256_for_test(&mut conn)
            .await
            .unwrap();
        assert_eq!(digest, crate::db::ENGINE_64_SHAPE_CONTRACT_SHA256);
        let step = EngineMigrationRegistry::production()
            .pending(64, 65)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(step.name(), "engine-64-to-65-alpha-tab-installs-projection");
        step.preflight(&mut conn).await.unwrap();
        step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version=65")
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(crate::db::validate_engine_shape_on_for_test(&mut conn, 65)
            .await
            .unwrap());
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM alpha_tab_installs")
            .fetch_one(&mut conn)
            .await
            .unwrap();
        assert_eq!(rows, 0);
        conn.close().await.unwrap();

        let migrated = crate::open_existing_database_at(&path).await.unwrap();
        let result = crate::conformance::rebuild_and_diff_control(&migrated)
            .await
            .unwrap();
        assert!(
            result.equal,
            "rebuild drift after 64→65: {}",
            serde_json::to_string_pretty(&result.tables).unwrap()
        );
        migrated.close().await;
    }
}
