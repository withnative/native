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
        Arc::new(Engine65To66Migration),
        Arc::new(Engine66To67Migration),
        Arc::new(Engine67To68Migration),
        Arc::new(Engine68To69Migration),
        Arc::new(Engine69To70Migration),
        Arc::new(Engine70To71Migration),
        Arc::new(Engine71To72Migration),
        Arc::new(Engine72To73Migration),
        Arc::new(Engine73To74Migration),
        Arc::new(Engine74To75Migration),
        Arc::new(Engine75To76Migration),
        Arc::new(Engine76To77Migration),
        Arc::new(Engine77To78Migration),
        Arc::new(Engine78To79Migration),
        Arc::new(Engine79To80Migration),
        Arc::new(Engine80To81Migration),
        Arc::new(Engine81To82Migration),
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

/// The exact engine-65-to-66 DDL: the single authoritative source for this
/// schema edge's structural change.
///
/// Both the reference SQLite runner (`Engine65To66Migration::apply` below)
/// and the Turso-local runner
/// (`crate::turso_local::migrate_existing_engine_schema`) execute this same
/// sequence. The edge is DDL-only: `authorization_grant_revision` is new
/// install state with no pre-existing rows to backfill, so a migrated
/// database gains the empty counter and converges with a fresh database.
/// Seeding at 0 is sound because the realtime stream uses a new hash domain
/// for this counter, distinct from pre-66 contexts derived from the broad
/// authorization revision.
///
/// The statements must stay byte-identical to the corresponding
/// `crate::schema::DDL_STATEMENTS` entries; the 65→66 migration test asserts
/// that rather than assuming it.
pub(crate) const ENGINE_65_TO_66_STATEMENTS: [&str; 19] = [
    r#"CREATE TABLE IF NOT EXISTS authorization_grant_revision (
     id     INTEGER PRIMARY KEY CHECK (id = 1),
     epoch  INTEGER NOT NULL
   )"#,
    r#"INSERT OR IGNORE INTO authorization_grant_revision (id, epoch) VALUES (1, 0)"#,
    r#"CREATE TRIGGER IF NOT EXISTS authorization_grant_record_policies_insert AFTER INSERT ON record_policies
       BEGIN UPDATE authorization_grant_revision SET epoch = epoch + 1 WHERE id = 1; END"#,
    r#"CREATE TRIGGER IF NOT EXISTS authorization_grant_record_policies_delete AFTER DELETE ON record_policies
       WHEN EXISTS (SELECT 1 FROM records WHERE id = OLD.record_id)
       BEGIN UPDATE authorization_grant_revision SET epoch = epoch + 1 WHERE id = 1; END"#,
    r#"CREATE TRIGGER IF NOT EXISTS authorization_grant_record_policies_update AFTER UPDATE ON record_policies
       WHEN OLD.record_id IS NOT NEW.record_id
       BEGIN UPDATE authorization_grant_revision SET epoch = epoch + 1 WHERE id = 1; END"#,
    r#"CREATE TRIGGER IF NOT EXISTS authorization_grant_policy_entries_insert AFTER INSERT ON policy_entries
       BEGIN UPDATE authorization_grant_revision SET epoch = epoch + 1 WHERE id = 1; END"#,
    r#"CREATE TRIGGER IF NOT EXISTS authorization_grant_policy_entries_delete AFTER DELETE ON policy_entries
       WHEN EXISTS (SELECT 1 FROM records WHERE id = OLD.policy_anchor_id)
       BEGIN UPDATE authorization_grant_revision SET epoch = epoch + 1 WHERE id = 1; END"#,
    r#"CREATE TRIGGER IF NOT EXISTS authorization_grant_policy_entries_update AFTER UPDATE ON policy_entries
       WHEN OLD.policy_anchor_id IS NOT NEW.policy_anchor_id
         OR OLD.subject_kind IS NOT NEW.subject_kind
         OR OLD.subject_id IS NOT NEW.subject_id
         OR OLD.effect IS NOT NEW.effect
         OR OLD.capability IS NOT NEW.capability
       BEGIN UPDATE authorization_grant_revision SET epoch = epoch + 1 WHERE id = 1; END"#,
    r#"CREATE TRIGGER IF NOT EXISTS authorization_grant_bindings_insert AFTER INSERT ON bindings
       WHEN NEW.system = 'account'
       BEGIN UPDATE authorization_grant_revision SET epoch = epoch + 1 WHERE id = 1; END"#,
    r#"CREATE TRIGGER IF NOT EXISTS authorization_grant_bindings_delete AFTER DELETE ON bindings
       WHEN OLD.system = 'account'
       BEGIN UPDATE authorization_grant_revision SET epoch = epoch + 1 WHERE id = 1; END"#,
    r#"CREATE TRIGGER IF NOT EXISTS authorization_grant_bindings_update AFTER UPDATE ON bindings
       WHEN (OLD.system = 'account' OR NEW.system = 'account')
        AND (OLD.record_id IS NOT NEW.record_id
          OR OLD.system IS NOT NEW.system
          OR OLD.identifier IS NOT NEW.identifier
          OR OLD.is_canonical IS NOT NEW.is_canonical)
       BEGIN UPDATE authorization_grant_revision SET epoch = epoch + 1 WHERE id = 1; END"#,
    r#"CREATE TRIGGER IF NOT EXISTS authorization_grant_records_update
       AFTER UPDATE OF owner_id, policy_anchor_id, deleted_at, type, kind ON records
       WHEN OLD.owner_id IS NOT NEW.owner_id
         OR OLD.policy_anchor_id IS NOT NEW.policy_anchor_id
         OR OLD.type IS NOT NEW.type
         OR OLD.kind IS NOT NEW.kind
         OR (OLD.deleted_at IS NOT NEW.deleted_at
           AND (EXISTS (SELECT 1 FROM links JOIN records src ON src.id = links.source_id WHERE links.target_id = OLD.id AND links.relationship = 'part_of' AND src.deleted_at IS NULL AND (src.type = 'Annotation' OR (src.type = 'Document' AND src.kind = 'attachment')))
             OR EXISTS (SELECT 1 FROM semantic_units JOIN records u ON u.id = semantic_units.unit_id WHERE semantic_units.authority_bearer_record_id = OLD.id AND u.deleted_at IS NULL)))
       BEGIN UPDATE authorization_grant_revision SET epoch = epoch + 1 WHERE id = 1; END"#,
    r#"CREATE TRIGGER IF NOT EXISTS authorization_grant_records_delete BEFORE DELETE ON records
       WHEN EXISTS (SELECT 1 FROM links JOIN records src ON src.id = links.source_id WHERE links.target_id = OLD.id AND links.relationship = 'part_of' AND src.deleted_at IS NULL AND (src.type = 'Annotation' OR (src.type = 'Document' AND src.kind = 'attachment')))
         OR EXISTS (SELECT 1 FROM semantic_units JOIN records u ON u.id = semantic_units.unit_id WHERE semantic_units.authority_bearer_record_id = OLD.id AND u.deleted_at IS NULL)
       BEGIN UPDATE authorization_grant_revision SET epoch = epoch + 1 WHERE id = 1; END"#,
    r#"CREATE TRIGGER IF NOT EXISTS authorization_grant_links_insert AFTER INSERT ON links
       WHEN NEW.relationship = 'part_of'
        AND EXISTS (SELECT 1 FROM records WHERE id = NEW.source_id AND deleted_at IS NULL AND (type = 'Annotation' OR (type = 'Document' AND kind = 'attachment')))
        AND (SELECT COUNT(*) FROM links WHERE source_id = NEW.source_id AND relationship = 'part_of') > 1
       BEGIN UPDATE authorization_grant_revision SET epoch = epoch + 1 WHERE id = 1; END"#,
    r#"CREATE TRIGGER IF NOT EXISTS authorization_grant_links_delete AFTER DELETE ON links
       WHEN OLD.relationship = 'part_of'
        AND EXISTS (SELECT 1 FROM records WHERE id = OLD.source_id AND deleted_at IS NULL AND (type = 'Annotation' OR (type = 'Document' AND kind = 'attachment')))
        AND (SELECT COUNT(*) FROM links WHERE source_id = OLD.source_id AND relationship = 'part_of') = 0
       BEGIN UPDATE authorization_grant_revision SET epoch = epoch + 1 WHERE id = 1; END"#,
    r#"CREATE TRIGGER IF NOT EXISTS authorization_grant_links_update AFTER UPDATE ON links
       WHEN (OLD.relationship = 'part_of' OR NEW.relationship = 'part_of')
        AND (OLD.source_id IS NOT NEW.source_id
          OR OLD.target_id IS NOT NEW.target_id
          OR OLD.relationship IS NOT NEW.relationship)
        AND (EXISTS (SELECT 1 FROM records WHERE id = OLD.source_id AND deleted_at IS NULL AND (type = 'Annotation' OR (type = 'Document' AND kind = 'attachment')))
          OR EXISTS (SELECT 1 FROM records WHERE id = NEW.source_id AND deleted_at IS NULL AND (type = 'Annotation' OR (type = 'Document' AND kind = 'attachment'))))
       BEGIN UPDATE authorization_grant_revision SET epoch = epoch + 1 WHERE id = 1; END"#,
    r#"CREATE TRIGGER IF NOT EXISTS authorization_grant_semantic_units_write AFTER INSERT ON semantic_units
       BEGIN UPDATE authorization_grant_revision SET epoch = epoch + 1 WHERE id = 1; END"#,
    r#"CREATE TRIGGER IF NOT EXISTS authorization_grant_semantic_units_delete AFTER DELETE ON semantic_units
       BEGIN UPDATE authorization_grant_revision SET epoch = epoch + 1 WHERE id = 1; END"#,
    r#"CREATE TRIGGER IF NOT EXISTS authorization_grant_semantic_units_update AFTER UPDATE OF authority_bearer_record_id ON semantic_units
       WHEN OLD.authority_bearer_record_id IS NOT NEW.authority_bearer_record_id
       BEGIN UPDATE authorization_grant_revision SET epoch = epoch + 1 WHERE id = 1; END"#,
];

/// The grant-only realtime authorization revision edge (engine 65 → 66).
#[derive(Debug)]
struct Engine65To66Migration;

impl EngineMigrationStep for Engine65To66Migration {
    fn from(&self) -> i64 {
        65
    }

    fn to(&self) -> i64 {
        66
    }

    fn name(&self) -> &str {
        "engine-65-to-66-grant-only-realtime-authorization-revision"
    }

    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await?;
            if version == 65 {
                crate::db::validate_supported_engine_migration_source(connection, 65).await?;
            }
            Ok(())
        }
        .boxed()
    }

    fn apply<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            for statement in ENGINE_65_TO_66_STATEMENTS {
                sqlx::query(statement).execute(&mut *connection).await?;
            }
            Ok(())
        }
        .boxed()
    }
}

/// The exact engine-66-to-67 DDL + deterministic backfill: the single
/// authoritative source for this schema edge's structural change.
///
/// Both the reference SQLite runner (`Engine66To67Migration::apply` below)
/// and the Turso-local runner
/// (`crate::turso_local::migrate_existing_engine_schema`) execute this same
/// sequence.
///
/// The edge adds caller-independent `records.archived` (INTEGER 0/1) and
/// backfills it from the engine-reserved `archived` facet presence:
/// `archived=1` iff a `facet_values` row with `key='archived'` exists.
/// The default is 0, so only the 1-side needs writing. This matches the
/// content projector's write-time maintenance (facet.set archived → 1,
/// facet.unset archived → 0, both non-observation_only only), so a migrated
/// database converges with a fresh database replayed through the same
/// projector.
///
/// The ADD COLUMN text must stay token-identical (after schema normalization)
/// to the `archived` column in `crate::schema::DDL_STATEMENTS`' records
/// table, which is positioned last for ALTER-append convergence; the 66→67
/// migration test asserts the twin relationship rather than assuming it.
pub(crate) const ENGINE_66_TO_67_STATEMENTS: [&str; 2] = [
    "ALTER TABLE records ADD COLUMN archived INTEGER NOT NULL DEFAULT 0 CHECK (archived IN (0,1))",
    "UPDATE records SET archived=1 WHERE EXISTS (SELECT 1 FROM facet_values WHERE record_id=records.id AND key='archived')",
];

/// The exact engine-67-to-68 DDL: the single authoritative source for this
/// schema edge's structural change (task `c5d3820` alpha-tab order).
///
/// Both the reference SQLite runner (`Engine67To68Migration::apply` below)
/// and the Turso-local runner
/// (`crate::turso_local::migrate_existing_engine_schema`) execute this same
/// sequence. The edge is DDL-only: `alpha_tab_orders` is new per-account
/// order state with no pre-existing rows to backfill, so a migrated database
/// gains the empty preference table and converges with a fresh database
/// trivially.
///
/// The statement must stay byte-identical to the corresponding
/// `crate::schema::DDL_STATEMENTS` entry; the 67→68 migration test asserts
/// that rather than assuming it.
pub(crate) const ENGINE_67_TO_68_STATEMENTS: [&str; 1] = [r#"CREATE TABLE alpha_tab_orders (
     account_id TEXT NOT NULL PRIMARY KEY CHECK (length(trim(account_id)) > 0),
     tab_order  TEXT NOT NULL CHECK (json_valid(tab_order) AND json_type(tab_order) = 'array'),
     event_id   TEXT NOT NULL UNIQUE REFERENCES control_events(id),
     event_seq  INTEGER NOT NULL UNIQUE REFERENCES control_events(seq),
     updated_at TEXT NOT NULL
    )"#];

/// The exact engine-68-to-69 DDL + backfill: the single authoritative source
/// for this schema edge's structural change (task `73e5b92` claim metadata).
///
/// Both the reference SQLite runner (`Engine68To69Migration::apply` below)
/// and the Turso-local runner
/// (`crate::turso_local::migrate_existing_engine_schema`) execute this same
/// sequence.
///
/// The table and trigger statements must stay byte-identical to the
/// corresponding `crate::schema::DDL_STATEMENTS` entries; the 68→69 migration
/// test asserts that rather than assuming it. The backfill classifies every
/// pre-existing row, of every event type, from its stored payload: presence
/// bits use the `->` existence test (explicit JSON nulls count as present,
/// matching the history rule), and `claim_class` applies the strict
/// text/null pair rule. The edge never UPDATEs `content_events` itself, so
/// the append-only triggers are untouched; new rows are classified by the
/// trigger at insert time under full write limits.
/// The `->` (not `json_type`) spelling is shared so the Turso-local runner,
/// whose read path already relies on `->` presence semantics, executes the
/// identical statements.
///
/// Malformed payloads are deliberately asymmetric: the trigger lets `->`
/// raise, so a fresh malformed insert fails loudly (governed admission
/// always serializes a JSON object and the projector rejects anything else,
/// so no supported path can hit this), while the backfill guards every
/// classification with `json_valid(payload) = 1` so one legacy oddity
/// classifies `other` instead of bricking the offline migration. SQL NULL
/// and valid non-object payloads classify all-absent `other` on both paths
/// because `->` yields NULL there.
pub(crate) const ENGINE_68_TO_69_STATEMENTS: [&str; 3] = [
    r#"CREATE TABLE content_event_claim_meta (
     event_seq          INTEGER PRIMARY KEY REFERENCES content_events(seq) ON DELETE CASCADE,
     has_claimed_by     INTEGER NOT NULL CHECK (has_claimed_by IN (0,1)),
     has_claimed_run    INTEGER NOT NULL CHECK (has_claimed_run IN (0,1)),
     has_released_from  INTEGER NOT NULL CHECK (has_released_from IN (0,1)),
     claim_class        TEXT NOT NULL CHECK (claim_class IN ('claim','release','other'))
    )"#,
    r#"CREATE TRIGGER content_event_claim_meta_insert AFTER INSERT ON content_events
     BEGIN
      INSERT INTO content_event_claim_meta(event_seq, has_claimed_by, has_claimed_run, has_released_from, claim_class)
      VALUES (
       NEW.seq,
       (NEW.payload -> 'claimed_by_account') IS NOT NULL,
       (NEW.payload -> 'claimed_run_key') IS NOT NULL,
       (NEW.payload -> 'released_from_run_key') IS NOT NULL,
       CASE WHEN (NEW.payload -> 'claimed_by_account') LIKE '"%"'
                 AND (NEW.payload -> 'claimed_run_key') LIKE '"%"' THEN 'claim'
            WHEN (NEW.payload -> 'claimed_by_account') = 'null'
                 AND (NEW.payload -> 'claimed_run_key') = 'null' THEN 'release'
            ELSE 'other' END
      );
     END"#,
    r#"INSERT INTO content_event_claim_meta(event_seq, has_claimed_by, has_claimed_run, has_released_from, claim_class)
     SELECT seq,
      CASE WHEN json_valid(payload) = 1 THEN (payload -> 'claimed_by_account') IS NOT NULL ELSE 0 END,
      CASE WHEN json_valid(payload) = 1 THEN (payload -> 'claimed_run_key') IS NOT NULL ELSE 0 END,
      CASE WHEN json_valid(payload) = 1 THEN (payload -> 'released_from_run_key') IS NOT NULL ELSE 0 END,
      CASE WHEN json_valid(payload) = 1 THEN
       CASE WHEN (payload -> 'claimed_by_account') LIKE '"%"'
                 AND (payload -> 'claimed_run_key') LIKE '"%"' THEN 'claim'
            WHEN (payload -> 'claimed_by_account') = 'null'
                 AND (payload -> 'claimed_run_key') = 'null' THEN 'release'
            ELSE 'other' END
      ELSE 'other' END
      FROM content_events"#,
];

/// The exact engine-69-to-70 DDL (task `fef3469`, D2 slice T2): the
/// `facet_times` table and its two indexes, which are
/// [`crate::schema::FACET_TIMES_DDL`] itself, so the edge and fresh DDL cannot
/// drift apart.
///
/// Both the reference SQLite runner (`Engine69To70Migration::apply` below)
/// and the Turso-local runner
/// (`crate::turso_local::migrate_existing_engine_schema`) execute these
/// statements. The projection's only source is `facet.set` events that carry
/// `time_kind`, a payload member no binary below engine 70 writes, so a
/// database genuinely written at engine 69 or earlier has nothing to
/// backfill. The
/// SQLite edge still runs the shared rebuild
/// ([`crate::projector::rebuild_facet_times`]) after the DDL rather than
/// assuming that: its existence probe returns at once when no event carries
/// the marker, and when one does (a file that was touched by a newer binary,
/// or a test that plants typed events) the rebuild folds exactly what replay
/// would. The Turso-local mirror is DDL-only and relies on that marker
/// never appearing below engine 70.
pub(crate) const ENGINE_69_TO_70_STATEMENTS: [&str; 3] = crate::schema::FACET_TIMES_DDL;

/// The typed time projection edge (engine 69 → 70, task `fef3469`).
#[derive(Debug)]
struct Engine69To70Migration;

impl EngineMigrationStep for Engine69To70Migration {
    fn from(&self) -> i64 {
        69
    }

    fn to(&self) -> i64 {
        70
    }

    fn name(&self) -> &str {
        "engine-69-to-70-facet-times"
    }

    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await?;
            if version == 69 {
                crate::db::validate_supported_engine_migration_source(connection, 69).await?;
            }
            Ok(())
        }
        .boxed()
    }

    fn apply<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            for statement in ENGINE_69_TO_70_STATEMENTS {
                sqlx::query(statement).execute(&mut *connection).await?;
            }
            crate::projector::rebuild_facet_times(connection).await?;
            Ok(())
        }
        .boxed()
    }
}

/// The exact engine-70-to-71 DDL (task `68b48e5`, `records.changes.v1`): a
/// partial index over each record's content events that leaves out the
/// event types that tab read never shows. Its `WHERE` is
/// `crate::query::events::FIELD_CHANGE_ROWS_PREDICATE` byte for byte, so
/// the read walks only rows a viewer can see and a hidden row can neither
/// cost work nor shape a page.
///
/// Both the reference SQLite runner (`Engine70To71Migration::apply` below)
/// and the Turso-local runner execute this same sequence. The edge is
/// DDL-only and additive: an index derives entirely from existing rows, so a
/// migrated database converges with a fresh one. The statement must stay
/// byte-identical to its `crate::schema::DDL_STATEMENTS` entry; the 70→71
/// migration test asserts that.
pub(crate) const ENGINE_70_TO_71_STATEMENTS: [&str; 1] = [
    r#"CREATE INDEX idx_content_events_record_changes ON content_events(record_id, seq) WHERE type NOT IN ('occurrence.bound.v1','receipt.dependency_audited.v1','reconciliation.recorded.v1','unit.superseded.v1')"#,
];

/// The field-change index edge (engine 70 → 71, task `68b48e5`).
#[derive(Debug)]
struct Engine70To71Migration;

impl EngineMigrationStep for Engine70To71Migration {
    fn from(&self) -> i64 {
        70
    }

    fn to(&self) -> i64 {
        71
    }

    fn name(&self) -> &str {
        "engine-70-to-71-record-changes-index"
    }

    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await?;
            if version == 70 {
                crate::db::validate_supported_engine_migration_source(connection, 70).await?;
            }
            Ok(())
        }
        .boxed()
    }

    fn apply<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            for statement in ENGINE_70_TO_71_STATEMENTS {
                sqlx::query(statement).execute(&mut *connection).await?;
            }
            Ok(())
        }
        .boxed()
    }
}

/// The exact engine-71-to-72 DDL + copy: the single authoritative source
/// for this schema edge's structural change (task `f1d80b0` shell auto-adopt
/// plus install request text).
///
/// Both the reference SQLite runner (`Engine71To72Migration::apply` below)
/// and the Turso-local runner
/// (`crate::turso_local::migrate_existing_engine_schema`) execute this same
/// sequence.
///
/// The edge rebuilds `alpha_tab_installs` in place: the `adoption` CHECK
/// widens to `shell_auto.v1` and a nullable display-only `request` column
/// appears after `adoption`. Existing rows copy across with `request = NULL`
/// (pre-72 installs carry no request text; the tier default covers them),
/// so a migrated database converges with a fresh database replayed through
/// the same projector.
///
/// The CREATE TABLE and CREATE INDEX statements must stay byte-identical to
/// the corresponding `crate::schema::DDL_STATEMENTS` entries; the 71→72
/// migration test asserts that rather than assuming it.
pub(crate) const ENGINE_71_TO_72_STATEMENTS: [&str; 7] = [
    "PRAGMA legacy_alter_table=ON",
    "ALTER TABLE alpha_tab_installs RENAME TO alpha_tab_installs_v71",
    r#"CREATE TABLE alpha_tab_installs (
     account_id                TEXT NOT NULL CHECK (length(trim(account_id)) > 0),
     package                   TEXT NOT NULL CHECK (length(trim(package)) > 0),
     version                   TEXT NOT NULL CHECK (length(trim(version)) > 0),
     digest                    TEXT NOT NULL CHECK (length(trim(digest)) > 0),
     artifact_id               TEXT NOT NULL REFERENCES records(id),
     consented_source_revision TEXT NOT NULL CHECK (length(trim(consented_source_revision)) > 0),
     declaration_digest        TEXT NOT NULL CHECK (length(declaration_digest) = 64),
     consented_declaration     TEXT NOT NULL CHECK (json_valid(consented_declaration) AND json_type(consented_declaration) = 'object'),
     adoption                  TEXT NOT NULL CHECK (adoption IN ('caller_asserted','shell_adopt.v1','shell_auto.v1')),
     request                   TEXT CHECK (request IS NULL OR (length(trim(request)) > 0 AND length(request) <= 500)),
     status                    TEXT NOT NULL CHECK (status IN ('installed','disabled','removed')),
     event_id                  TEXT NOT NULL UNIQUE REFERENCES control_events(id),
     event_seq                 INTEGER NOT NULL UNIQUE REFERENCES control_events(seq),
     updated_at                TEXT NOT NULL,
     PRIMARY KEY (account_id, package)
    )"#,
    r#"INSERT INTO alpha_tab_installs
         (account_id,package,version,digest,artifact_id,consented_source_revision,
          declaration_digest,consented_declaration,adoption,request,status,event_id,event_seq,updated_at)
       SELECT account_id,package,version,digest,artifact_id,consented_source_revision,
          declaration_digest,consented_declaration,adoption,NULL,status,event_id,event_seq,updated_at
         FROM alpha_tab_installs_v71"#,
    "DROP TABLE alpha_tab_installs_v71",
    r#"CREATE INDEX idx_alpha_tab_installs_artifact ON alpha_tab_installs(artifact_id)"#,
    "PRAGMA legacy_alter_table=OFF",
];

/// The exact engine-72-to-73 DDL + deterministic backfill: the single
/// authoritative source for this schema edge's structural change (E3 M1
/// currency counts).
///
/// Both the reference SQLite runner (`Engine72To73Migration::apply` below)
/// and any future Turso-local mirror execute this same sequence. (This
/// increment ships the SQLite runner only; Turso/Postgres/catalog exposure
/// is an explicit follow-on.)
///
/// The edge adds caller-independent currency counts `records.is_current`
/// (tri-state: 1 = no live incoming `supersedes`, NULL = scope unknown) and
/// `records.successor_count` (live incoming `supersedes` count, deleted
/// source excluded). `is_current` defaults to 1 (a created record has no
/// incoming links), so the backfill only writes the unknown side plus the
/// counts: `successor_count` is recomputed row-for-row from live incoming
/// links, then `is_current` is nulled where the count is positive. This
/// matches the content projector's write-time maintenance (supersedes
/// link add → recompute target; link remove → recompute target; successor
/// tombstone → recompute its targets), so a migrated database converges
/// with a fresh database replayed through the same projector. `is_current=0`
/// is never written by this edge; the column CHECK admits it so a future
/// explicit whole-record assertion needs no migration. No successor names
/// are stored: naming stays caller-relative in `get_record` after visibility
/// filtering. `archived` stays orthogonal: the backfill never reads or
/// writes it.
///
/// The ADD COLUMN texts must stay token-identical (after schema normalization)
/// to the `is_current`/`successor_count` columns in
/// `crate::schema::DDL_STATEMENTS`' records table, which are positioned last
/// for ALTER-append convergence; the 72→73 migration test asserts the twin
/// relationship rather than assuming it.
pub(crate) const ENGINE_72_TO_73_STATEMENTS: [&str; 4] = [
    "ALTER TABLE records ADD COLUMN is_current INTEGER NULL DEFAULT 1 CHECK (is_current IS NULL OR is_current IN (0,1))",
    "ALTER TABLE records ADD COLUMN successor_count INTEGER NOT NULL DEFAULT 0 CHECK (successor_count >= 0)",
    "UPDATE records SET successor_count=(SELECT COUNT(*) FROM links l JOIN records s ON s.id=l.source_id WHERE l.target_id=records.id AND l.relationship='supersedes' AND s.deleted_at IS NULL)",
    "UPDATE records SET is_current=NULL WHERE successor_count>0",
];

/// The archived-projection edge (engine 66 → 67, E3 M1 slice 1).
#[derive(Debug)]
struct Engine66To67Migration;

impl EngineMigrationStep for Engine66To67Migration {
    fn from(&self) -> i64 {
        66
    }

    fn to(&self) -> i64 {
        67
    }

    fn name(&self) -> &str {
        "engine-66-to-67-archived-projection"
    }

    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await?;
            if version == 66 {
                crate::db::validate_supported_engine_migration_source(connection, 66).await?;
            }
            Ok(())
        }
        .boxed()
    }

    fn apply<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            for statement in ENGINE_66_TO_67_STATEMENTS {
                sqlx::query(statement).execute(&mut *connection).await?;
            }
            Ok(())
        }
        .boxed()
    }
}

/// The personal alpha-tab order projection edge (engine 67 → 68, task
/// `c5d3820`).
#[derive(Debug)]
struct Engine67To68Migration;

impl EngineMigrationStep for Engine67To68Migration {
    fn from(&self) -> i64 {
        67
    }

    fn to(&self) -> i64 {
        68
    }

    fn name(&self) -> &str {
        "engine-67-to-68-alpha-tab-orders"
    }

    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await?;
            if version == 67 {
                crate::db::validate_supported_engine_migration_source(connection, 67).await?;
            }
            Ok(())
        }
        .boxed()
    }

    fn apply<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            for statement in ENGINE_67_TO_68_STATEMENTS {
                sqlx::query(statement).execute(&mut *connection).await?;
            }
            Ok(())
        }
        .boxed()
    }
}

/// The content-event claim-metadata edge (engine 68 → 69, task `73e5b92`).
#[derive(Debug)]
struct Engine68To69Migration;

impl EngineMigrationStep for Engine68To69Migration {
    fn from(&self) -> i64 {
        68
    }

    fn to(&self) -> i64 {
        69
    }

    fn name(&self) -> &str {
        "engine-68-to-69-content-event-claim-meta"
    }

    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await?;
            if version == 68 {
                crate::db::validate_supported_engine_migration_source(connection, 68).await?;
            }
            Ok(())
        }
        .boxed()
    }

    fn apply<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            for statement in ENGINE_68_TO_69_STATEMENTS {
                sqlx::query(statement).execute(&mut *connection).await?;
            }
            Ok(())
        }
        .boxed()
    }
}

/// The alpha-tab install request + shell-auto adoption edge (engine 71 → 72,
/// task `f1d80b0`).
#[derive(Debug)]
struct Engine71To72Migration;

impl EngineMigrationStep for Engine71To72Migration {
    fn from(&self) -> i64 {
        71
    }

    fn to(&self) -> i64 {
        72
    }

    fn name(&self) -> &str {
        "engine-71-to-72-alpha-tab-request-and-shell-auto"
    }

    fn requires_foreign_keys_disabled(&self) -> bool {
        true
    }

    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await?;
            if version == 71 {
                crate::db::validate_supported_engine_migration_source(connection, 71).await?;
            }
            Ok(())
        }
        .boxed()
    }

    fn apply<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            for statement in ENGINE_71_TO_72_STATEMENTS {
                sqlx::query(statement).execute(&mut *connection).await?;
            }
            Ok(())
        }
        .boxed()
    }
}

/// The currency-counts edge (engine 72 → 73, E3 M1).
#[derive(Debug)]
struct Engine72To73Migration;

impl EngineMigrationStep for Engine72To73Migration {
    fn from(&self) -> i64 {
        72
    }

    fn to(&self) -> i64 {
        73
    }

    fn name(&self) -> &str {
        "engine-72-to-73-currency-counts"
    }

    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await?;
            if version == 72 {
                crate::db::validate_supported_engine_migration_source(connection, 72).await?;
            }
            Ok(())
        }
        .boxed()
    }

    fn apply<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            for statement in ENGINE_72_TO_73_STATEMENTS {
                sqlx::query(statement).execute(&mut *connection).await?;
            }
            Ok(())
        }
        .boxed()
    }
}

/// Both the reference SQLite runner (`Engine73To74Migration::apply` below)
/// and the Turso-local runner
/// (`crate::turso_local::migrate_existing_engine_schema`) execute this same
/// sequence.
///
/// The edge adds the caller-independent `body_task_items` projection table
/// (E3 M3 increment 2A): one row per GFM task-list item in each record's
/// current body, stamped with that body's provenance event. The table is a
/// pure function of current bodies — creation scans the stored body, updates
/// carrying a body delete and re-scan, deletion keeps rows (a tombstone
/// carries no body and the caller-visible view excludes deleted records, so
/// retaining rows keeps migration, live folding and replay converged).
/// Extraction is fail-closed: an [`ExtractError`](crate::body_task_items::ExtractError)
/// aborts the migration with the offending record's identity rather than
/// persisting partial or empty rows. `Unknown` markers never reach storage:
/// the extractor refuses them, and the insert path below refuses them again.
///
/// The two statements must stay byte-identical to the corresponding
/// `crate::schema::DDL_STATEMENTS` entries; the 73→74 migration test asserts
/// the twin relationship rather than assuming it. The data backfill is a Rust
/// loop over the parser (see `backfill_body_task_items`), so it cannot be
/// shared as SQL:
///
/// - SQLite applies DDL + backfill together, inside the runner's
///   `BEGIN IMMEDIATE` transaction.
/// - Turso-local applies DDL + its own `backfill_body_task_items` mirror
///   together, inside the same `BEGIN IMMEDIATE` transaction. Both backfills
///   share `record_body::BODY_CARRYING_EVENT_SQL` and the same scan/coercion
///   semantics, so a migrated database converges with the live fold and replay
///   on either backend.
pub(crate) const ENGINE_73_TO_74_STATEMENTS: [&str; 2] = [
    r#"CREATE TABLE body_task_items (
      record_id          TEXT NOT NULL REFERENCES records(id) ON DELETE CASCADE,
      item_index         INTEGER NOT NULL,
      source_event_seq   INTEGER NOT NULL REFERENCES content_events(seq),
      marker             TEXT NOT NULL CHECK (marker IN ('-', '*', '+', 'ordered')),
      checked            INTEGER NOT NULL CHECK (checked IN (0,1)),
      in_quote           INTEGER NOT NULL CHECK (in_quote IN (0,1)),
      start_offset       INTEGER NOT NULL CHECK (start_offset >= 0),
      end_offset         INTEGER NOT NULL CHECK (end_offset >= 0),
      PRIMARY KEY (record_id, item_index)
    )"#,
    r#"CREATE INDEX idx_body_task_items_record
        ON body_task_items(record_id)"#,
];

/// The body-task-items projection edge (engine 73 → 74, E3 M3 increment 2A).
#[derive(Debug)]
struct Engine73To74Migration;

impl EngineMigrationStep for Engine73To74Migration {
    fn from(&self) -> i64 {
        73
    }

    fn to(&self) -> i64 {
        74
    }

    fn name(&self) -> &str {
        "engine-73-to-74-body-task-items"
    }

    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await?;
            if version == 73 {
                crate::db::validate_supported_engine_migration_source(connection, 73).await?;
            }
            Ok(())
        }
        .boxed()
    }

    fn apply<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            for statement in ENGINE_73_TO_74_STATEMENTS {
                sqlx::query(statement).execute(&mut *connection).await?;
            }
            backfill_body_task_items(connection).await?;
            Ok(())
        }
        .boxed()
    }
}

/// E3 M3 physical block projection. This table is deliberately absent from
/// caller SQL until the separate admission increment. The 16 MiB body and
/// 4096 chunk ceilings are new projection admission policy: an older body
/// beyond either ceiling refuses migration atomically with its record ID.
pub(crate) const ENGINE_74_TO_75_STATEMENTS: [&str; 1] = [r#"CREATE TABLE body_blocks (
      record_id          TEXT NOT NULL REFERENCES records(id) ON DELETE CASCADE,
      block_index        INTEGER NOT NULL CHECK (block_index >= 0),
      chunk_index        INTEGER NOT NULL CHECK (chunk_index >= 0),
      chunk_count        INTEGER NOT NULL CHECK (chunk_count > 0 AND chunk_index < chunk_count),
      source_event_seq   INTEGER NOT NULL REFERENCES content_events(seq),
      heading_path       TEXT NOT NULL CHECK (json_valid(heading_path) AND json_type(heading_path) = 'array'),
      block_kind         TEXT NOT NULL CHECK (block_kind IN ('heading','paragraph','code','blockquote','list','table','html','thematic_break','definition','footnote_definition','other','interstitial','opaque')),
      text               TEXT NOT NULL CHECK (length(CAST(text AS BLOB)) BETWEEN 1 AND 32768),
      start_offset       INTEGER NOT NULL CHECK (start_offset >= 0),
      end_offset         INTEGER NOT NULL CHECK (end_offset > start_offset),
      PRIMARY KEY (record_id, block_index, chunk_index)
    )"#];

#[derive(Debug)]
struct Engine74To75Migration;

impl EngineMigrationStep for Engine74To75Migration {
    fn from(&self) -> i64 {
        74
    }
    fn to(&self) -> i64 {
        75
    }
    fn name(&self) -> &str {
        "engine-74-to-75-body-blocks"
    }
    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await?;
            if version == 74 {
                crate::db::validate_supported_engine_migration_source(connection, 74).await?;
            }
            Ok(())
        }
        .boxed()
    }
    fn apply<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            for statement in ENGINE_74_TO_75_STATEMENTS {
                sqlx::query(statement).execute(&mut *connection).await?;
            }
            crate::body_blocks_projection::backfill_sqlite(connection).await
        }
        .boxed()
    }
}

/// Current vocabulary metadata becomes a bounded, occurrence-preserving JSON
/// projection. An invalid or over-budget source aborts the full migration.
#[derive(Debug)]
struct Engine75To76Migration;

impl EngineMigrationStep for Engine75To76Migration {
    fn from(&self) -> i64 {
        75
    }
    fn to(&self) -> i64 {
        76
    }
    fn name(&self) -> &str {
        "engine-75-to-76-vocabulary-metadata-json-nodes"
    }
    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await?;
            if version == 75 {
                crate::db::validate_supported_engine_migration_source(connection, 75).await?;
            }
            Ok(())
        }
        .boxed()
    }
    fn apply<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            sqlx::query(crate::schema::ddl::VOCABULARY_VALUE_JSON_NODES_DDL)
                .execute(&mut *connection)
                .await?;
            crate::json_nodes_projection::backfill_sqlite(connection).await
        }
        .boxed()
    }
}

/// Exact source validator shared with the Turso structural migration mirror.
/// Refusal is deliberately stronger than the old winning-addition-only fold:
/// no historical reaction event is silently dropped, even when superseded.
pub(crate) fn validate_reaction_meta_source(
    id: &str,
    payload: Option<&str>,
    actor: Option<&str>,
) -> Result<()> {
    let validate = || -> Result<()> {
        let raw = payload.ok_or_else(|| Error::engine("Message reaction has no payload"))?;
        let payload: crate::events::MessageReactionPayload = serde_json::from_str(raw)?;
        payload.validate(actor)
    };
    validate().map_err(|error| {
        Error::engine(format!(
            "reaction metadata migration refuses event {id}: {error}"
        ))
    })
}

pub(crate) const ENGINE_76_TO_77_STATEMENTS: [&str; 3] = crate::schema::ddl::REACTION_META_DDL;
pub(crate) const REACTION_META_BACKFILL: &str =
    "INSERT INTO content_event_reaction_meta(event_seq,record_id,actor,legacy_emoji,emoji,executor_kind,reaction_class,created_at)
     SELECT seq,record_id,actor,json_extract(payload,'$.emoji'),
      json_extract(payload,CASE WHEN json_type(payload)='array' THEN '$[1]' ELSE '$.emoji' END),
      json_extract(payload,CASE WHEN json_type(payload)='array' THEN '$[6]' ELSE '$.executor_kind' END),
      CASE type WHEN 'message.reaction.added.v1' THEN 'added' ELSE 'removed' END,created_at
     FROM content_events WHERE type IN ('message.reaction.added.v1','message.reaction.removed.v1')";

#[derive(Debug)]
struct Engine76To77Migration;
impl EngineMigrationStep for Engine76To77Migration {
    fn from(&self) -> i64 {
        76
    }
    fn to(&self) -> i64 {
        77
    }
    fn name(&self) -> &str {
        "engine-76-to-77-reaction-meta"
    }
    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await?;
            if version == 76 {
                crate::db::validate_supported_engine_migration_source(connection, 76).await?;
            }
            Ok(())
        }
        .boxed()
    }
    fn apply<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            // Bound memory by one event, rather than fetching the whole historical log.
            // All source events are retained; only the reaction family is copied.
            let mut after = i64::MIN;
            loop {
                let row: Option<(i64,String,Option<String>,Option<String>)> = sqlx::query_as(
                    "SELECT seq,id,payload,actor FROM content_events WHERE seq>=? AND type IN ('message.reaction.added.v1','message.reaction.removed.v1') ORDER BY seq LIMIT 1"
                ).bind(after).fetch_optional(&mut *connection).await?;
                let Some((seq,id,payload,actor)) = row else { break; };
                validate_reaction_meta_source(&id,payload.as_deref(),actor.as_deref())?;
                let Some(next) = seq.checked_add(1) else { break; };
                after = next;
            }
            for statement in ENGINE_76_TO_77_STATEMENTS {
                sqlx::query(statement).execute(&mut *connection).await?;
            }
            sqlx::query(REACTION_META_BACKFILL).execute(&mut *connection).await?;
            Ok(())
        }.boxed()
    }
}

pub(crate) const ENGINE_77_TO_78_STATEMENT: &str =
    "ALTER TABLE alpha_tab_installs ADD COLUMN adoption_provenance TEXT CHECK (adoption_provenance IS NULL OR (json_valid(adoption_provenance) AND json_type(adoption_provenance) = 'object'))";

#[derive(Debug)]
struct Engine77To78Migration;
impl EngineMigrationStep for Engine77To78Migration {
    fn from(&self) -> i64 {
        77
    }
    fn to(&self) -> i64 {
        78
    }
    fn name(&self) -> &str {
        "engine-77-to-78-alpha-tab-adoption-provenance"
    }
    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await?;
            if version == 77 {
                crate::db::validate_supported_engine_migration_source(connection, 77).await?;
            }
            Ok(())
        }
        .boxed()
    }
    fn apply<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            sqlx::query(ENGINE_77_TO_78_STATEMENT)
                .execute(&mut *connection)
                .await?;
            crate::control::alpha_tab_provenance::backfill(connection).await
        }
        .boxed()
    }
}

/// Inert nullable reader pointer. Historical adoption never mints this field.
pub(crate) const ENGINE_78_TO_79_STATEMENT: &str =
    "ALTER TABLE alpha_tab_installs ADD COLUMN body_read_admission_event_id TEXT REFERENCES control_events(id)";

#[derive(Debug)]
struct Engine78To79Migration;
impl EngineMigrationStep for Engine78To79Migration {
    fn from(&self) -> i64 {
        78
    }
    fn to(&self) -> i64 {
        79
    }
    fn name(&self) -> &str {
        "engine-78-to-79-inert-body-reader-pointer"
    }
    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await?;
            if version == 78 {
                crate::db::validate_supported_engine_migration_source(connection, 78).await?;
            }
            Ok(())
        }
        .boxed()
    }
    fn apply<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            sqlx::query(ENGINE_78_TO_79_STATEMENT)
                .execute(connection)
                .await?;
            Ok(())
        }
        .boxed()
    }
}

/// Production v1 storage edge. Historical79 shape is checked before any DDL.
#[derive(Debug)]
struct Engine79To80Migration;
impl EngineMigrationStep for Engine79To80Migration {
    fn from(&self) -> i64 {
        79
    }
    fn to(&self) -> i64 {
        80
    }
    fn name(&self) -> &str {
        "engine-79-to-80-workspace-rule-installations"
    }
    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await?;
            // All pending preflights inspect the original preimage. Earlier
            // edges validate their own released source before reaching 79.
            if version == 79 {
                crate::db::validate_supported_engine_migration_source(connection, 79).await?;
            }
            Ok(())
        }
        .boxed()
    }
    fn apply<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            // Check the actual intermediate shape inside the write transaction,
            // including when the original preimage preceded schema 79.
            crate::db::validate_supported_engine_migration_source(connection, 79).await?;
            for statement in crate::schema::ddl::WORKSPACE_RULE_INSTALLATION_DDL {
                sqlx::query(statement).execute(&mut *connection).await?;
            }
            Ok(())
        }
        .boxed()
    }
}

/// SQLite-only config node carrier. The runner owns BEGIN/stamp/COMMIT;
/// invalid legacy data rolls back the entire edge, including its new table.
#[derive(Debug)]
struct Engine80To81Migration;
impl EngineMigrationStep for Engine80To81Migration {
    fn from(&self) -> i64 {
        80
    }
    fn to(&self) -> i64 {
        81
    }
    fn name(&self) -> &str {
        "engine-80-to-81-schema-config-json-nodes"
    }
    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await?;
            if version == 80 {
                crate::db::validate_supported_engine_migration_source(connection, 80).await?;
            }
            Ok(())
        }
        .boxed()
    }
    fn apply<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            // Validate the actual intermediate workspace80 shape, including
            // historical chains whose preflights inspected an earlier stamp.
            crate::db::validate_supported_engine_migration_source(connection, 80).await?;
            sqlx::query(crate::schema::ddl::SCHEMA_CONFIG_JSON_NODES_DDL)
                .execute(&mut *connection)
                .await?;
            crate::schema_config_json_nodes::backfill(connection).await
        }
        .boxed()
    }
}

/// SQLite-only facet-value node carrier. The runner owns BEGIN/stamp/COMMIT.
/// Unlike config nodes, malformed or over-budget facet text is skipped by the
/// backfill rather than aborting the edge: a facet write must never fail
/// because its value cannot be projected.
#[derive(Debug)]
struct Engine81To82Migration;
impl EngineMigrationStep for Engine81To82Migration {
    fn from(&self) -> i64 {
        81
    }
    fn to(&self) -> i64 {
        82
    }
    fn name(&self) -> &str {
        "engine-81-to-82-facet-value-json-nodes"
    }
    fn preflight<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await?;
            if version == 81 {
                crate::db::validate_supported_engine_migration_source(connection, 81).await?;
            }
            Ok(())
        }
        .boxed()
    }
    fn apply<'a>(&'a self, connection: &'a mut SqliteConnection) -> BoxFuture<'a, Result<()>> {
        async move {
            crate::db::validate_supported_engine_migration_source(connection, 81).await?;
            sqlx::query(crate::schema::ddl::FACET_VALUE_JSON_NODES_DDL)
                .execute(&mut *connection)
                .await?;
            crate::facet_value_json_nodes::backfill(connection).await
        }
        .boxed()
    }
}

/// Backfill `body_task_items` from current bodies.
///
/// For each record whose stored body is non-empty text, scan the CURRENT body
/// text and stamp every row with the latest body-carrying event's sequence,
/// not `MAX(seq)` overall — the same provenance rule as
/// [`backfill_record_mentions`]: metadata-only updates carry higher sequences
/// but no body, and stamping those would diverge from the live fold, which
/// keeps the body's own event sequence. The event set is exactly the
/// projector's body writers (`crate::record_body::BODY_CARRYING_EVENT_SQL`).
///
/// Unlike mentions, deleted records are NOT excluded: a tombstone carries no
/// body and the live fold keeps the deleted record's rows, so excluding them
/// here would diverge from a fresh replay, which retains those same rows.
/// Tombstoned, removed (null/empty body) and never-written sources yield no
/// rows — the same replacement semantics as the live fold, so backfill, live
/// folding and replay converge.
///
/// Fail-closed: an extraction error aborts the whole migration with the
/// offending record's identity. A body with no body-carrying event (only
/// possible when the row was written outside the projector, never through an
/// append) is left without rows rather than stamped with an invented
/// sequence; the next body-carrying write folds it, and a replay over the
/// same log produces no rows either, preserving rebuild equality.
///
/// `typeof(body)='text'` excludes non-text storage classes the parser cannot
/// read; a stored body is already the canonical text the projector coerced,
/// so the live fold scans the same bytes.
pub(crate) async fn backfill_body_task_items(connection: &mut SqliteConnection) -> Result<()> {
    let sources: Vec<(String, String)> = sqlx::query_as(
        "SELECT id, body FROM records
          WHERE typeof(body) = 'text' AND body <> ''
          ORDER BY id",
    )
    .fetch_all(&mut *connection)
    .await?;
    let provenance_sql = format!(
        "SELECT MAX(seq) FROM content_events
          WHERE record_id = ? AND ({})",
        crate::record_body::BODY_CARRYING_EVENT_SQL
    );
    for (record_id, body) in sources {
        let source_event_seq: Option<i64> = sqlx::query_scalar(&provenance_sql)
            .bind(&record_id)
            .fetch_one(&mut *connection)
            .await?;
        let Some(source_event_seq) = source_event_seq else {
            continue;
        };
        let items = crate::body_task_items::extract_task_items(&body).map_err(|error| {
            crate::error::Error::engine(format!(
                "engine-74 backfill cannot extract task items for record {record_id}: {error}"
            ))
        })?;
        sqlx::query("DELETE FROM body_task_items WHERE record_id = ?")
            .bind(&record_id)
            .execute(&mut *connection)
            .await?;
        for item in &items {
            let marker = crate::body_task_items::TaskMarker::as_str(&item.marker).ok_or_else(|| {
                crate::error::Error::engine(format!(
                    "engine-74 backfill refuses unrepresentable marker for record {record_id} item {}",
                    item.index
                ))
            })?;
            sqlx::query(
                "INSERT INTO body_task_items
                   (record_id, item_index, source_event_seq, marker,
                    checked, in_quote, start_offset, end_offset)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&record_id)
            .bind(item.index as i64)
            .bind(source_event_seq)
            .bind(marker)
            .bind(i64::from(item.checked))
            .bind(i64::from(item.in_quote))
            .bind(item.start_offset as i64)
            .bind(item.end_offset as i64)
            .execute(&mut *connection)
            .await?;
        }
    }
    Ok(())
}

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

/// Read actions that arrived after the 62→63 freeze on already-shipped
/// mixed-disposition tools. This list is a review record for the frozen-policy
/// test only: historical deletion replay reads [`ENGINE_62_TO_63_MIXED_READS`]
/// unchanged, so a post-freeze read action is retained (kept) by the frozen
/// replay exactly like an unknown action — fail-closed. Adding here requires
/// the same deliberate review as widening the frozen list itself.
#[cfg(test)]
const ENGINE_62_TO_63_POST_FREEZE_READ_ACTIONS: &[(&str, &[&str])] =
    &[("manage_instructions", &["resolve"])];

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
    /// Requested selection, even when verification was never reached.
    pub verification_profile: crate::conformance::ConformanceProfile,
    /// Set only after the conformance dispatcher actually ran.
    pub executed_verification_profile: Option<crate::conformance::ConformanceProfile>,
    pub verification_status: MigrationVerificationStatus,
    /// Checks omitted by an executed profile; no check is reported as passed
    /// merely because it was deferred.
    pub deferred_checks: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationVerificationStatus {
    NotRun,
    NotRunCurrent,
    NotRunHistoricalTarget,
    /// The executed profile passed; deferred checks have no pass claim.
    Passed,
    Failed,
}

impl DatabaseMigrationReport {
    fn with_conformance(
        mut self,
        profile: crate::conformance::ConformanceProfile,
        status: MigrationVerificationStatus,
    ) -> Self {
        self.executed_verification_profile = Some(profile);
        self.verification_status = status;
        self.deferred_checks = profile
            .deferred_checks()
            .iter()
            .map(|name| (*name).into())
            .collect();
        self
    }
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

/// Migrate with an explicit post-migration verification selection.
/// Migration, preimage, integrity and fencing behavior is invariant across profiles.
#[allow(clippy::too_many_arguments)]
pub async fn migrate_database_with_profile(
    path: &Path,
    db_id: &str,
    run_id: &str,
    target: i64,
    registry: &EngineMigrationRegistry,
    backup_options: &dyn MigrationPreimageStore,
    fence: FenceFn,
    profile: crate::conformance::ConformanceProfile,
) -> DatabaseMigrationReport {
    migrate_database_with_reservation_and_profile(
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
        profile,
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
    migrate_database_with_reservation_and_profile(
        path,
        db_id,
        run_id,
        target,
        registry,
        backup_options,
        fence,
        reserve_attempt,
        verifier,
        #[cfg(test)]
        probe_override,
        crate::conformance::ConformanceProfile::Full,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn migrate_database_with_reservation_and_profile(
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
    profile: crate::conformance::ConformanceProfile,
) -> DatabaseMigrationReport {
    let mut report = migrate_database_with_reservation_impl(
        path,
        db_id,
        run_id,
        target,
        registry,
        backup_options,
        fence,
        reserve_attempt,
        verifier,
        #[cfg(test)]
        probe_override,
        profile,
    )
    .await;
    report.verification_profile = profile;
    report
}

#[allow(clippy::too_many_arguments)]
async fn migrate_database_with_reservation_impl(
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
    profile: crate::conformance::ConformanceProfile,
) -> DatabaseMigrationReport {
    if let Err(error) = crate::managed_custody::refuse_maintenance(path) {
        return failed(path, None, target, "custody", error.to_string());
    }
    // The durable reservation seam also fences pathname reopens. The caller
    // supplies the authority (HOSTED composes lease + path admission); the
    // portable runner has no managed-root policy. Ordinary migrate-db without
    // a reservation retains its existing fence timing.
    let reopen_fence = reserve_attempt.as_ref().map(|_| fence.clone());
    if let Some(guard) = &reopen_fence {
        if let Err(err) = guard().await {
            return failed(path, None, target, "fence", err.to_string());
        }
    }
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
            verification_profile: crate::conformance::ConformanceProfile::Full,
            executed_verification_profile: None,
            verification_status: MigrationVerificationStatus::NotRunCurrent,
            deferred_checks: Vec::new(),
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
    if let Some(guard) = &reopen_fence {
        if let Err(err) = guard().await {
            return failed(path, Some(from), target, "fence", err.to_string());
        }
    }
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

    if let Some(guard) = &reopen_fence {
        if let Err(err) = guard().await {
            return failed(path, Some(from), target, "fence", err.to_string());
        }
    }
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
        // The transaction and version stamp have already committed. A
        // failing reopen fence preserves the preimage and reports failure;
        // callers must not interpret `fence` as proof of rollback.
        if let Some(guard) = &reopen_fence {
            if let Err(err) = guard().await {
                return failed_with_backup(path, from, target, "fence", err.to_string(), backup);
            }
        }
        let verification = match verifier.clone() {
            Some(verifier) => verifier(path.to_path_buf()).await,
            None => {
                verify_migrated_database_fenced_with_profile(
                    path.to_path_buf(),
                    db_id,
                    reopen_fence,
                    profile,
                )
                .await
            }
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
                return failed_with_backup(path, from, target, "conformance", message, backup)
                    .with_conformance(profile, MigrationVerificationStatus::Failed);
            }
        }
    }
    let report = DatabaseMigrationReport {
        path: path.to_path_buf(),
        from_version: Some(from),
        to_version: target,
        outcome: "migrated".into(),
        backup: Some(backup),
        error_kind: None,
        error_message: None,
        verification_profile: profile,
        executed_verification_profile: None,
        verification_status: MigrationVerificationStatus::NotRunHistoricalTarget,
        deferred_checks: Vec::new(),
    };
    if target == CURRENT_ENGINE_SCHEMA_VERSION {
        report.with_conformance(profile, MigrationVerificationStatus::Passed)
    } else {
        report
    }
}

/// Run one database migration with a durable attempt-reservation hook.
///
/// Hosted fleet orchestration uses this seam to record the verified pre-image
/// before the first mutation without moving catalog ownership into the
/// portable migration module.
/// Reopen fences also run after commit, so a failed fence can leave the
/// target stamp committed. The durable reservation and verified preimage
/// must remain unresolved until restoration or explicit recovery authority.
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

/// Attempt-reservation migration with explicit verification selection.
/// Existing hosted callers continue to use the FULL wrapper above.
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub async fn migrate_database_with_attempt_reservation_and_profile(
    path: &Path,
    db_id: &str,
    run_id: &str,
    target: i64,
    registry: &EngineMigrationRegistry,
    backup_options: &dyn MigrationPreimageStore,
    fence: FenceFn,
    reserve_attempt: AttemptReservationFn,
    profile: crate::conformance::ConformanceProfile,
) -> DatabaseMigrationReport {
    migrate_database_with_reservation_and_profile(
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
        profile,
    )
    .await
}

#[cfg(test)]
async fn verify_migrated_database(path: PathBuf, db_id: &str) -> PostMigrationVerification {
    verify_migrated_database_fenced_with_profile(
        path,
        db_id,
        None,
        crate::conformance::ConformanceProfile::Full,
    )
    .await
}

async fn verify_migrated_database_fenced_with_profile(
    path: PathBuf,
    db_id: &str,
    reopen_fence: Option<FenceFn>,
    profile: crate::conformance::ConformanceProfile,
) -> PostMigrationVerification {
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
    if let Some(guard) = &reopen_fence {
        if let Err(err) = guard().await {
            return PostMigrationVerification::VerifyOpenFailed(err.to_string());
        }
    }
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
    eprintln!(
        "migration-verification db_id={db_id:?} profile={profile} deferred_checks={:?}",
        profile.deferred_checks()
    );
    let conformance = crate::conformance::run_conformance_with_profile_and_progress(&db, profile, |name, elapsed| {
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
        verification_profile: crate::conformance::ConformanceProfile::Full,
        executed_verification_profile: None,
        verification_status: MigrationVerificationStatus::NotRun,
        deferred_checks: Vec::new(),
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

    // Compare all persisted tables, including event logs and backfill projections.
    // Debug-encoded typed SQLite values preserve NULL/blob/text distinctions.
    fn persisted_state(path: &Path) -> Vec<(String, Vec<String>)> {
        let connection = rusqlite::Connection::open(path).unwrap();
        let mut schema = connection
            .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
            .unwrap();
        let names = schema
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        names
            .into_iter()
            .map(|name| {
                let quoted = name.replace('"', "\"\"");
                let mut statement = connection
                    .prepare(&format!("SELECT * FROM \"{quoted}\""))
                    .unwrap();
                let columns = statement.column_count();
                let mut rows = statement
                    .query_map([], |row| {
                        (0..columns)
                            .map(|column| row.get::<_, rusqlite::types::Value>(column))
                            .collect::<std::result::Result<Vec<_>, _>>()
                            .map(|values| format!("{values:?}"))
                    })
                    .unwrap()
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .unwrap();
                rows.sort();
                (name, rows)
            })
            .collect()
    }

    #[tokio::test]
    async fn verification_profiles_preserve_multihop_migration_and_backfill_state() {
        use crate::conformance::ConformanceProfile;
        let dir = tempfile::tempdir().unwrap();
        let seed = dir.path().join("legacy.db");
        let db = crate::create_database(&seed.to_string_lossy())
            .await
            .unwrap();
        let body = format!("# Backfill\n\n```\n{}\n```\n", "é".repeat(160_000));
        let id = crate::store::create_record(&db, serde_json::json!({"type":"Document","kind":"note","name":"migration backfill","body":body})).await.unwrap();
        let expected_blocks: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM body_blocks WHERE record_id=?")
                .bind(&id)
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert!(expected_blocks > 8);
        let expected_nodes: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM vocabulary_value_json_nodes")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert!(expected_nodes > 0);
        db.close().await;
        let mut connection =
            SqliteConnection::connect_with(&single_connection_options(&seed).unwrap())
                .await
                .unwrap();
        revert_to_engine_75(&mut connection).await;
        sqlx::query("DROP TABLE body_blocks")
            .execute(&mut connection)
            .await
            .unwrap();
        sqlx::query("PRAGMA user_version=74")
            .execute(&mut connection)
            .await
            .unwrap();
        connection.close().await.unwrap();
        let full_path = dir.path().join("full.db");
        let core_path = dir.path().join("core.db");
        std::fs::copy(&seed, &full_path).unwrap();
        std::fs::copy(&seed, &core_path).unwrap();
        let offbox = tempfile::tempdir().unwrap();
        let backup = test_preimage_store(offbox.path(), dir.path());
        let registry = EngineMigrationRegistry::production();
        let full = migrate_database(
            &full_path,
            "full",
            "full-run",
            CURRENT_ENGINE_SCHEMA_VERSION,
            &registry,
            &backup,
            Arc::new(|| async { Ok(()) }.boxed()),
        )
        .await;
        let core = migrate_database_with_profile(
            &core_path,
            "core",
            "core-run",
            CURRENT_ENGINE_SCHEMA_VERSION,
            &registry,
            &backup,
            Arc::new(|| async { Ok(()) }.boxed()),
            ConformanceProfile::Core,
        )
        .await;
        for report in [&full, &core] {
            assert_eq!(report.outcome, "migrated", "{report:?}");
            assert_eq!(report.from_version, Some(74));
            assert_eq!(
                report.verification_status,
                MigrationVerificationStatus::Passed
            );
            assert!(report.backup.is_some());
            assert_eq!(header_version(&report.path), CURRENT_ENGINE_SCHEMA_VERSION);
            let db = crate::open_existing_database_at(&report.path)
                .await
                .unwrap();
            let blocks: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM body_blocks WHERE record_id=?")
                    .bind(&id)
                    .fetch_one(db.pool())
                    .await
                    .unwrap();
            let nodes: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vocabulary_value_json_nodes")
                .fetch_one(db.pool())
                .await
                .unwrap();
            assert_eq!(blocks, expected_blocks);
            assert_eq!(nodes, expected_nodes);
            db.close().await;
        }
        assert_eq!(full.verification_profile, ConformanceProfile::Full);
        assert_eq!(
            full.executed_verification_profile,
            Some(ConformanceProfile::Full)
        );
        assert!(full.deferred_checks.is_empty());
        assert_eq!(
            core.executed_verification_profile,
            Some(ConformanceProfile::Core)
        );
        assert_eq!(
            core.deferred_checks,
            ConformanceProfile::Core.deferred_checks()
        );
        assert_eq!(persisted_state(&full_path), persisted_state(&core_path));
        assert_eq!(
            serde_json::to_value(&core).unwrap()["verification_profile"],
            "production-release"
        );
    }

    #[tokio::test]
    async fn verification_profiles_never_claim_current_or_historical_target_conformance() {
        use crate::conformance::ConformanceProfile;
        for profile in [ConformanceProfile::Full, ConformanceProfile::Core] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("user.db");
            create_current_schema(&path).await;
            let db = crate::open_existing_database_at(&path).await.unwrap();
            // A full comparison would fail, but neither no-op/historical-target
            // outcome is allowed to pretend it executed that comparison.
            sqlx::query("INSERT INTO links (id,source_id,target_id,relationship,created_at) VALUES ('unverified-drift','native:root','native:root','corrupt projection','2026-01-01T00:00:00Z')")
                .execute(db.write_pool()).await.unwrap();
            db.close().await;
            let offbox = tempfile::tempdir().unwrap();
            let backup = test_preimage_store(offbox.path(), dir.path());
            let registry = synthetic_zero_to_current_registry();
            let current = migrate_database_with_profile(
                &path,
                "user",
                "current",
                CURRENT_ENGINE_SCHEMA_VERSION,
                &registry,
                &backup,
                Arc::new(|| async { Ok(()) }.boxed()),
                profile,
            )
            .await;
            assert_eq!(current.outcome, "current");
            assert_eq!(
                current.verification_status,
                MigrationVerificationStatus::NotRunCurrent
            );
            assert!(current.backup.is_none());
            let historical = migrate_database_with_reservation_and_profile(
                &path,
                "user",
                "historical",
                CURRENT_ENGINE_SCHEMA_VERSION - 1,
                &registry,
                &backup,
                Arc::new(|| async { Ok(()) }.boxed()),
                None,
                None,
                Some(DatabaseVersionState::Known(0)),
                profile,
            )
            .await;
            assert_eq!(historical.outcome, "migrated", "{historical:?}");
            assert_eq!(
                historical.verification_status,
                MigrationVerificationStatus::NotRunHistoricalTarget
            );
            assert!(historical.backup.is_some());
            for report in [&current, &historical] {
                assert_eq!(report.verification_profile, profile);
                assert_eq!(report.executed_verification_profile, None);
                assert!(report.deferred_checks.is_empty());
                let json = serde_json::to_value(report).unwrap();
                assert!(json["executed_verification_profile"].is_null());
                assert_ne!(json["verification_status"], "passed");
            }
        }
    }

    #[tokio::test]
    async fn production_release_retained_failure_is_failed_with_preimage() {
        use crate::conformance::ConformanceProfile;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("user.db");
        create_current_schema(&path).await;
        let offbox = tempfile::tempdir().unwrap();
        let backup = test_preimage_store(offbox.path(), dir.path());
        // Fault immediately before the real dispatcher so shape/open admission
        // cannot mask whether CORE still executes authorization validation.
        let verifier: PostMigrationVerifier = Arc::new(|path| {
            async move {
                let db = crate::open_existing_database_at(&path).await.unwrap();
                sqlx::query("DROP TRIGGER authorization_revision_records_insert")
                    .execute(db.write_pool())
                    .await
                    .unwrap();
                let report =
                    crate::conformance::run_conformance_with_profile(&db, ConformanceProfile::Core)
                        .await;
                db.close().await;
                assert!(!report.ok);
                assert!(
                    !report
                        .checks
                        .iter()
                        .find(|check| check.check == "authorization-revision-state")
                        .unwrap()
                        .ok
                );
                PostMigrationVerification::ConformanceFailed(format!("{report:?}"))
            }
            .boxed()
        });
        let report = migrate_database_with_reservation_and_profile(
            &path,
            "user",
            "failure",
            CURRENT_ENGINE_SCHEMA_VERSION,
            &synthetic_zero_to_current_registry(),
            &backup,
            Arc::new(|| async { Ok(()) }.boxed()),
            None,
            Some(verifier),
            Some(DatabaseVersionState::Known(0)),
            ConformanceProfile::Core,
        )
        .await;
        assert_eq!(report.outcome, "failed");
        assert_eq!(report.error_kind.as_deref(), Some("conformance"));
        assert_eq!(
            report.verification_status,
            MigrationVerificationStatus::Failed
        );
        assert_eq!(
            report.executed_verification_profile,
            Some(ConformanceProfile::Core)
        );
        assert_eq!(
            report.deferred_checks,
            ConformanceProfile::Core.deferred_checks()
        );
        let restored = dir.path().join("restored.db");
        backup
            .sink
            .get(report.backup.unwrap().key, restored.clone())
            .await
            .unwrap();
        crate::open_existing_database_at(&restored)
            .await
            .unwrap()
            .close()
            .await;
    }

    #[tokio::test]
    async fn production_release_verifier_retains_shape_and_reopen_fence_refusals() {
        use crate::conformance::ConformanceProfile;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("valid.db");
        create_current_schema(&path).await;
        let refusal: FenceFn =
            Arc::new(|| async { Err(Error::engine("lost reopen authority")) }.boxed());
        assert!(matches!(
            verify_migrated_database_fenced_with_profile(path.clone(), "fixture", Some(refusal), ConformanceProfile::Core).await,
            PostMigrationVerification::VerifyOpenFailed(message) if message.contains("lost reopen authority")
        ));
        let db = crate::open_existing_database_at(&path).await.unwrap();
        sqlx::query("DROP TABLE jobs")
            .execute(db.write_pool())
            .await
            .unwrap();
        db.close().await;
        assert!(matches!(
            verify_migrated_database_fenced_with_profile(
                path,
                "fixture",
                None,
                ConformanceProfile::Core
            )
            .await,
            PostMigrationVerification::StructuralFailed(_)
        ));
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

    #[tokio::test]
    async fn unreserved_portable_migration_preserves_precommit_only_fence_timing() {
        assert!(
            matches!(CURRENT_ENGINE_SCHEMA_VERSION, 75..=82),
            "refresh historical edge fixture"
        );
        let dir = tempfile::tempdir().unwrap();
        // This plain portable target is deliberately outside HOSTED layouts.
        let path = dir.path().join("portable.db");
        create_current_schema(&path).await;
        {
            let connection = rusqlite::Connection::open(&path).unwrap();
            connection
                .execute_batch("DROP TABLE schema_config_json_nodes;")
                .unwrap();
            if CURRENT_ENGINE_SCHEMA_VERSION >= 82 {
                connection
                    .execute_batch("DROP TABLE facet_value_json_nodes;")
                    .unwrap();
            }
            if CURRENT_ENGINE_SCHEMA_VERSION >= 80 {
                connection
                    .execute_batch("DROP TABLE workspace_rule_installations;")
                    .unwrap();
            }
            if CURRENT_ENGINE_SCHEMA_VERSION >= 79 {
                connection
                    .execute_batch(
                        "ALTER TABLE alpha_tab_installs DROP COLUMN body_read_admission_event_id;",
                    )
                    .unwrap();
            }
            if CURRENT_ENGINE_SCHEMA_VERSION >= 78 {
                connection
                    .execute_batch(
                        "ALTER TABLE alpha_tab_installs DROP COLUMN adoption_provenance;",
                    )
                    .unwrap();
            }
            if CURRENT_ENGINE_SCHEMA_VERSION >= 77 {
                connection
                    .execute_batch("DROP TRIGGER content_event_reaction_meta_insert; DROP TABLE content_event_reaction_meta;")
                    .unwrap();
            }
            if CURRENT_ENGINE_SCHEMA_VERSION >= 76 {
                connection
                    .execute_batch("DROP TABLE vocabulary_value_json_nodes;")
                    .unwrap();
            }
            connection
                .execute_batch("DROP TABLE body_blocks; PRAGMA user_version=74;")
                .unwrap();
        }
        let offbox = tempfile::tempdir().unwrap();
        let backup = test_preimage_store(offbox.path(), dir.path());
        let after_commit = Arc::new(AtomicUsize::new(0));
        let fence: FenceFn = Arc::new({
            let path = path.clone();
            let after_commit = after_commit.clone();
            move || {
                let path = path.clone();
                let after_commit = after_commit.clone();
                async move {
                    let version: i64 = {
                        let connection = rusqlite::Connection::open_with_flags(
                            &path,
                            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
                        )
                        .unwrap();
                        connection
                            .pragma_query_value(None, "user_version", |row| row.get(0))
                            .unwrap()
                    };
                    if version == CURRENT_ENGINE_SCHEMA_VERSION {
                        after_commit.fetch_add(1, Ordering::SeqCst);
                        return Err(Error::engine(
                            "portable fence unexpectedly called after commit",
                        ));
                    }
                    // A later edge's precommit fence sees only its earlier committed stamps;
                    // only a fence after the final target commit is forbidden.
                    assert!(
                        matches!(
                            (CURRENT_ENGINE_SCHEMA_VERSION, version),
                            (75, 74)
                                | (76, 74..=75)
                                | (77, 74..=76)
                                | (78, 74..=77)
                                | (79, 74..=78)
                                | (80, 74..=79)
                                | (81, 74..=80)
                                | (82, 74..=81)
                        ),
                        "unexpected committed source/intermediate stamp {version}"
                    );
                    Ok(())
                }
                .boxed()
            }
        });
        // The ordinary public API passes reserve_attempt=None and retains
        // its historical guard timing through real shape/conformance opens.
        let report = migrate_database(
            &path,
            "portable-user",
            "portable-run",
            CURRENT_ENGINE_SCHEMA_VERSION,
            &EngineMigrationRegistry::production(),
            &backup,
            fence,
        )
        .await;
        assert_eq!(report.outcome, "migrated", "{report:?}");
        assert_eq!(report.from_version, Some(74));
        assert!(report.backup.is_some());
        assert_eq!(after_commit.load(Ordering::SeqCst), 0);
        assert_eq!(header_version(&path), CURRENT_ENGINE_SCHEMA_VERSION);
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
    async fn advance_engine_to_current(connection: &mut SqliteConnection, start: i64) {
        for (from, to, name) in [
            (58, 59, "engine-58-to-59-record-mentions-projection"),
            (59, 60, "engine-59-to-60-provenance-validity-act-stamping"),
            (60, 61, "engine-60-to-61-canonical-act-range-indexes"),
            (61, 62, "engine-61-to-62-observation-intent-act-stamping"),
            (62, 63, "engine-62-to-63-read-log-selective-cleanup"),
            (63, 64, "engine-63-to-64-read-log-freelist-compaction"),
            (64, 65, "engine-64-to-65-alpha-tab-installs-projection"),
            (
                65,
                66,
                "engine-65-to-66-grant-only-realtime-authorization-revision",
            ),
            (66, 67, "engine-66-to-67-archived-projection"),
            (67, 68, "engine-67-to-68-alpha-tab-orders"),
            (68, 69, "engine-68-to-69-content-event-claim-meta"),
            (69, 70, "engine-69-to-70-facet-times"),
            (70, 71, "engine-70-to-71-record-changes-index"),
            (71, 72, "engine-71-to-72-alpha-tab-request-and-shell-auto"),
            (72, 73, "engine-72-to-73-currency-counts"),
            (73, 74, "engine-73-to-74-body-task-items"),
            (74, 75, "engine-74-to-75-body-blocks"),
            (75, 76, "engine-75-to-76-vocabulary-metadata-json-nodes"),
            (76, 77, "engine-76-to-77-reaction-meta"),
            (77, 78, "engine-77-to-78-alpha-tab-adoption-provenance"),
            (78, 79, "engine-78-to-79-inert-body-reader-pointer"),
            (79, 80, "engine-79-to-80-workspace-rule-installations"),
            (80, 81, "engine-80-to-81-schema-config-json-nodes"),
            (81, 82, "engine-81-to-82-facet-value-json-nodes"),
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
        advance_engine_to_current(&mut conn, 58).await;
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
        advance_engine_to_current(&mut conn, 58).await;
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
        advance_engine_to_current(&mut conn, 58).await;
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
        advance_engine_to_current(&mut conn, 58).await;
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
        advance_engine_to_current(&mut conn, 58).await;
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
        advance_engine_to_current(&mut conn, 59).await;
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
        for (name, reads) in &mut derived_mixed {
            if let Some((_, post_freeze)) = ENGINE_62_TO_63_POST_FREEZE_READ_ACTIONS
                .iter()
                .find(|(tool, _)| tool == name)
            {
                reads.retain(|action| !post_freeze.contains(action));
            }
        }
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
        let grant_step = EngineMigrationRegistry::production()
            .pending(65, 66)
            .unwrap()
            .pop()
            .unwrap();
        grant_step.preflight(&mut conn).await.unwrap();
        grant_step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version=66")
            .execute(&mut conn)
            .await
            .unwrap();
        // Binary is at 67: continue through the archived-projection edge so
        // the final open sees current.
        apply_remaining_production_steps(&mut conn, 66).await;
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
    /// index, and minus the engine-66 grant revision. Dropping the tables
    /// removes their indexes with it; grant triggers owned by other tables
    /// go through the engine-65 revert first. The reverted schema compares
    /// equal to fresh main64 DDL under the shape contract.
    /// Test fixtures only; this is not a rollback API.
    async fn revert_to_engine_64(connection: &mut SqliteConnection) {
        revert_to_engine_65(connection).await;
        sqlx::query("DROP TABLE alpha_tab_installs")
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query("PRAGMA user_version=64")
            .execute(&mut *connection)
            .await
            .unwrap();
    }

    /// Reconstruct the released engine-66 shape: current DDL minus exactly
    /// the `records.archived` column and the `alpha_tab_orders` preference
    /// table. `DROP COLUMN` rewrites the stored table text, so the reverted
    /// table compares equal to fresh pre-67 DDL under the shape contract.
    /// Test fixtures only; this is not a rollback API.
    async fn revert_to_engine_66(connection: &mut SqliteConnection) {
        revert_to_engine_67(connection).await;
        sqlx::query("ALTER TABLE records DROP COLUMN archived")
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query("PRAGMA user_version=66")
            .execute(&mut *connection)
            .await
            .unwrap();
    }

    /// Reconstruct the released engine-75 shape: current DDL minus exactly the
    /// engine-76 `vocabulary_value_json_nodes` parser projection. Every edge
    /// fixture below 76 walks back through here first, so a later engine-76
    /// addition can never leak into a released-shape pin. Test fixtures only;
    /// this is not a rollback API.
    async fn revert_to_engine_75(connection: &mut SqliteConnection) {
        revert_to_engine_76(connection).await;
        sqlx::query("DROP TABLE vocabulary_value_json_nodes")
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query("PRAGMA user_version=75")
            .execute(&mut *connection)
            .await
            .unwrap();
    }

    /// Reconstruct the released engine-72 shape: current DDL minus the
    /// engine-76 parser projection, the engine-75 `body_blocks` and engine-74
    /// `body_task_items` tables, and exactly the `records.is_current` and
    /// `records.successor_count` currency columns. `DROP COLUMN` rewrites the
    /// stored table text, so the reverted table compares equal to fresh pre-73
    /// DDL under the shape contract. Test fixtures only; this is not a
    /// rollback API.
    async fn revert_to_engine_72(connection: &mut SqliteConnection) {
        revert_to_engine_75(connection).await;
        sqlx::query("DROP TABLE body_blocks")
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query("DROP TABLE body_task_items")
            .execute(&mut *connection)
            .await
            .unwrap();
        for column in ["is_current", "successor_count"] {
            sqlx::query(&format!("ALTER TABLE records DROP COLUMN {column}"))
                .execute(&mut *connection)
                .await
                .unwrap();
        }
        sqlx::query("PRAGMA user_version=72")
            .execute(&mut *connection)
            .await
            .unwrap();
    }

    /// Reconstruct the released engine-71 shape: current DDL with the
    /// `alpha_tab_installs` table rebuilt to its pre-72 text (two-value
    /// adoption CHECK, no request column). Rows copy across minus the
    /// request text, which pre-72 installs never carried. Test fixtures
    /// only; this is not a rollback API.
    async fn revert_to_engine_71(connection: &mut SqliteConnection) {
        revert_to_engine_72(connection).await;
        for statement in [
            "PRAGMA legacy_alter_table=ON",
            "ALTER TABLE alpha_tab_installs RENAME TO alpha_tab_installs_v72revert",
            ENGINE_64_TO_65_STATEMENTS[0],
            r#"INSERT INTO alpha_tab_installs
                 (account_id,package,version,digest,artifact_id,consented_source_revision,
                  declaration_digest,consented_declaration,adoption,status,event_id,event_seq,updated_at)
               SELECT account_id,package,version,digest,artifact_id,consented_source_revision,
                  declaration_digest,consented_declaration,adoption,status,event_id,event_seq,updated_at
                 FROM alpha_tab_installs_v72revert"#,
            "DROP TABLE alpha_tab_installs_v72revert",
            ENGINE_64_TO_65_STATEMENTS[1],
            "PRAGMA legacy_alter_table=OFF",
        ] {
            sqlx::query(statement)
                .execute(&mut *connection)
                .await
                .unwrap();
        }
        sqlx::query("PRAGMA user_version=71")
            .execute(&mut *connection)
            .await
            .unwrap();
    }

    /// Reconstruct the released engine-70 shape: current DDL minus exactly
    /// the `idx_content_events_record_changes` partial index.
    /// Test fixtures only; this is not a rollback API.
    async fn revert_to_engine_70(connection: &mut SqliteConnection) {
        revert_to_engine_71(connection).await;
        sqlx::query("DROP INDEX idx_content_events_record_changes")
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query("PRAGMA user_version=70")
            .execute(&mut *connection)
            .await
            .unwrap();
    }

    /// Continue a fixture at engine 70 through the 70→71 field-change index
    /// edge (checking the engine-71 shape on the way) and every later
    /// production edge, so a ladder that ends at 70 reopens at current.
    async fn continue_from_engine_70(connection: &mut SqliteConnection) {
        let step = EngineMigrationRegistry::production()
            .pending(70, 71)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(step.name(), "engine-70-to-71-record-changes-index");
        step.preflight(&mut *connection).await.unwrap();
        step.apply(&mut *connection).await.unwrap();
        sqlx::query("PRAGMA user_version=71")
            .execute(&mut *connection)
            .await
            .unwrap();
        assert!(crate::db::validate_engine_shape_on_for_test(connection, 71)
            .await
            .unwrap());
        apply_remaining_production_steps(connection, 71).await;
    }

    /// Reconstruct the released engine-69 shape: current DDL minus exactly
    /// the `facet_times` table. Dropping it drops its two indexes and nothing
    /// else; the reverted schema compares equal to fresh pre-70 DDL under the
    /// shape contract.
    /// Test fixtures only; this is not a rollback API.
    async fn revert_to_engine_69(connection: &mut SqliteConnection) {
        revert_to_engine_70(connection).await;
        sqlx::query("DROP TABLE facet_times")
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query("PRAGMA user_version=69")
            .execute(&mut *connection)
            .await
            .unwrap();
    }

    /// Run the 69→70 edge (checking the engine-70 shape on the way) and every
    /// later production edge, for a test whose own edge ends at 69, so the
    /// final open sees the binary's current schema.
    async fn continue_from_engine_69(connection: &mut SqliteConnection) {
        let step = EngineMigrationRegistry::production()
            .pending(69, 70)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(step.name(), "engine-69-to-70-facet-times");
        step.preflight(&mut *connection).await.unwrap();
        step.apply(&mut *connection).await.unwrap();
        sqlx::query("PRAGMA user_version=70")
            .execute(&mut *connection)
            .await
            .unwrap();
        assert!(crate::db::validate_engine_shape_on_for_test(connection, 70)
            .await
            .unwrap());
        continue_from_engine_70(connection).await;
    }

    /// Reconstruct the released engine-68 shape: current DDL minus exactly
    /// the `content_event_claim_meta` table and its insert trigger. Dropping
    /// the table removes the trigger's target and the explicit trigger drop
    /// keeps the helper sound standing alone; the reverted schema compares
    /// equal to fresh pre-69 DDL under the shape contract.
    /// Test fixtures only; this is not a rollback API.
    async fn revert_to_engine_68(connection: &mut SqliteConnection) {
        revert_to_engine_69(connection).await;
        sqlx::query("DROP TRIGGER IF EXISTS content_event_claim_meta_insert")
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query("DROP TABLE content_event_claim_meta")
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query("PRAGMA user_version=68")
            .execute(&mut *connection)
            .await
            .unwrap();
    }

    /// Reconstruct the released engine-67 shape: current DDL minus exactly
    /// the `alpha_tab_orders` preference table. Dropping the table removes
    /// nothing else; the reverted schema compares equal to fresh pre-68 DDL
    /// under the shape contract.
    /// Test fixtures only; this is not a rollback API.
    async fn revert_to_engine_67(connection: &mut SqliteConnection) {
        revert_to_engine_68(connection).await;
        sqlx::query("DROP TABLE alpha_tab_orders")
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query("PRAGMA user_version=67")
            .execute(&mut *connection)
            .await
            .unwrap();
    }

    /// Reconstruct the released engine-65 shape: current DDL minus exactly
    /// the `records.archived` column plus the `authorization_grant_revision`
    /// table and its 17 triggers.
    /// Dropping the table does not remove triggers owned by other tables,
    /// so each grant trigger is dropped explicitly; the reverted schema
    /// compares equal to fresh pre-66 DDL under the shape contract.
    /// Test fixtures only; this is not a rollback API.
    async fn revert_to_engine_65(connection: &mut SqliteConnection) {
        revert_to_engine_66(connection).await;
        for trigger in [
            "authorization_grant_record_policies_insert",
            "authorization_grant_record_policies_delete",
            "authorization_grant_record_policies_update",
            "authorization_grant_policy_entries_insert",
            "authorization_grant_policy_entries_delete",
            "authorization_grant_policy_entries_update",
            "authorization_grant_bindings_insert",
            "authorization_grant_bindings_delete",
            "authorization_grant_bindings_update",
            "authorization_grant_records_update",
            "authorization_grant_records_delete",
            "authorization_grant_links_insert",
            "authorization_grant_links_delete",
            "authorization_grant_links_update",
            "authorization_grant_semantic_units_write",
            "authorization_grant_semantic_units_delete",
            "authorization_grant_semantic_units_update",
        ] {
            sqlx::query(&format!("DROP TRIGGER {trigger}"))
                .execute(&mut *connection)
                .await
                .unwrap();
        }
        sqlx::query("DROP TABLE authorization_grant_revision")
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query("PRAGMA user_version=65")
            .execute(&mut *connection)
            .await
            .unwrap();
    }

    /// The 65→66 DDL is transition text, but the objects it creates must stay
    /// byte-identical to the fresh-schema DDL: migrated databases are
    /// byte-identical to fresh ones under the shape contract only while both
    /// spellings agree.
    #[test]
    fn engine_65_to_66_statements_match_fresh_ddl() {
        for statement in ENGINE_65_TO_66_STATEMENTS {
            assert!(
                crate::schema::DDL_STATEMENTS.contains(&statement),
                "65→66 statement has no fresh-DDL twin: {}",
                statement.chars().take(80).collect::<String>()
            );
        }
    }

    /// The 65→66 edge adds the empty grant-only realtime revision: the
    /// migrated database validates at schema 66, the counter starts at 0,
    /// and the reverted pre-image pins the released engine-65 shape.
    #[tokio::test]
    async fn engine_65_to_66_adds_empty_grant_revision() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grant-revision-edge.db");
        create_current_schema(&path).await;
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        revert_to_engine_65(&mut conn).await;
        let digest = crate::db::schema_shape_contract_sha256_for_test(&mut conn)
            .await
            .unwrap();
        assert_eq!(digest, crate::db::ENGINE_65_SHAPE_CONTRACT_SHA256);
        let step = EngineMigrationRegistry::production()
            .pending(65, 66)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(
            step.name(),
            "engine-65-to-66-grant-only-realtime-authorization-revision"
        );
        step.preflight(&mut conn).await.unwrap();
        step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version=66")
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(crate::db::validate_engine_shape_on_for_test(&mut conn, 66)
            .await
            .unwrap());
        let epoch: i64 =
            sqlx::query_scalar("SELECT epoch FROM authorization_grant_revision WHERE id = 1")
                .fetch_one(&mut conn)
                .await
                .unwrap();
        assert_eq!(epoch, 0);
        assert!(crate::authorization_grant::state_violations_on(&mut conn)
            .await
            .unwrap()
            .is_empty());
        // The edge under test ends at 66, but the binary is at 72: continue
        // through the archived-projection edge so the final open sees current.
        apply_remaining_production_steps(&mut conn, 66).await;
        conn.close().await.unwrap();

        let migrated = crate::open_existing_database_at(&path).await.unwrap();
        let result = crate::conformance::rebuild_and_diff_control(&migrated)
            .await
            .unwrap();
        assert!(
            result.equal,
            "rebuild drift after 65→66: {}",
            serde_json::to_string_pretty(&result.tables).unwrap()
        );
        migrated.close().await;
    }

    /// The 66→67 ADD COLUMN is transition text, but the column it adds must
    /// stay token-identical to the fresh-schema records definition: migrated
    /// databases converge with fresh ones under the shape contract only while
    /// both spellings agree. The backfill UPDATE has no fresh-DDL twin by
    /// construction (fresh databases fold archived from the log).
    #[test]
    fn engine_66_to_67_statements_match_fresh_ddl() {
        assert_eq!(ENGINE_66_TO_67_STATEMENTS.len(), 2);
        let add = ENGINE_66_TO_67_STATEMENTS[0];
        assert!(
            add.starts_with("ALTER TABLE records ADD COLUMN archived "),
            "66→67 first statement must add records.archived: {add}"
        );
        let fresh = crate::schema::DDL_STATEMENTS
            .iter()
            .find(|candidate| candidate.starts_with("CREATE TABLE records ("))
            .expect("fresh DDL contains records");
        // Token-identical after schema normalization (whitespace/comments
        // stripped): the migrated rewrite must spell the column like fresh.
        let normalize = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
        let column_def = "archived INTEGER NOT NULL DEFAULT 0 CHECK (archived IN (0,1))";
        assert!(
            normalize(fresh).contains(&normalize(column_def)),
            "fresh records DDL must carry the archived column"
        );
        assert!(
            normalize(add).contains(&normalize(column_def)),
            "66→67 ADD COLUMN drifted from fresh DDL"
        );
        assert!(
            ENGINE_66_TO_67_STATEMENTS[1].contains("facet_values")
                && ENGINE_66_TO_67_STATEMENTS[1].contains("key='archived'"),
            "66→67 backfill must derive from the reserved archived facet"
        );
    }

    /// The 66→67 edge adds caller-independent `records.archived` with a
    /// deterministic facet-presence backfill: the migrated database validates
    /// at schema 67, archived matches facet_values presence row-for-row, the
    /// reverted pre-image pins the released engine-66 shape, and content
    /// rebuild-and-diff proves replay convergence.
    #[tokio::test]
    async fn engine_66_to_67_backfills_archived_from_facet() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archived-projection-edge.db");
        create_current_schema(&path).await;
        let db = crate::open_existing_database_at(&path).await.unwrap();
        let kept = crate::store::create_record(
            &db,
            serde_json::json!({"type": "Document", "kind": "note", "name": "kept"}),
        )
        .await
        .unwrap();
        let archived = crate::store::create_record(
            &db,
            serde_json::json!({"type": "Document", "kind": "note", "name": "archived"}),
        )
        .await
        .unwrap();
        crate::store::archive_record(&db, &archived).await.unwrap();
        let restored = crate::store::create_record(
            &db,
            serde_json::json!({"type": "Document", "kind": "note", "name": "restored"}),
        )
        .await
        .unwrap();
        crate::store::archive_record(&db, &restored).await.unwrap();
        crate::store::restore_record(&db, &restored).await.unwrap();
        // Live fold's answer, captured before the revert destroys it.
        let expected: Vec<(String, i64)> =
            sqlx::query_as("SELECT id, archived FROM records WHERE id IN (?, ?, ?) ORDER BY id")
                .bind(&kept)
                .bind(&archived)
                .bind(&restored)
                .fetch_all(db.write_pool())
                .await
                .unwrap();
        assert_eq!(expected.len(), 3);
        let archived_flag = |id: &str| {
            expected
                .iter()
                .find(|(row_id, _)| row_id == id)
                .map(|(_, flag)| *flag)
                .unwrap()
        };
        assert_eq!(archived_flag(&kept), 0);
        assert_eq!(archived_flag(&archived), 1);
        assert_eq!(archived_flag(&restored), 0);
        // Facet presence agrees with the physical column on the live fold.
        for id in [&kept, &archived, &restored] {
            let facet_count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM facet_values WHERE record_id = ? AND key = 'archived'",
            )
            .bind(id)
            .fetch_one(db.write_pool())
            .await
            .unwrap();
            assert_eq!(facet_count, archived_flag(id));
        }
        db.close().await;

        // Reconstruct the engine-66 preimage, then run the real 66→67 edge.
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        revert_to_engine_66(&mut conn).await;
        let digest = crate::db::schema_shape_contract_sha256_for_test(&mut conn)
            .await
            .unwrap();
        assert_eq!(digest, crate::db::ENGINE_66_SHAPE_CONTRACT_SHA256);
        let step = EngineMigrationRegistry::production()
            .pending(66, 67)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(step.name(), "engine-66-to-67-archived-projection");
        step.preflight(&mut conn).await.unwrap();
        step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version=67")
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(crate::db::validate_engine_shape_on_for_test(&mut conn, 67)
            .await
            .unwrap());
        // Backfill ran inside the edge: the migrated column already matches
        // the live fold before reopening.
        let migrated_flags: Vec<(String, i64)> =
            sqlx::query_as("SELECT id, archived FROM records WHERE id IN (?, ?, ?) ORDER BY id")
                .bind(&kept)
                .bind(&archived)
                .bind(&restored)
                .fetch_all(&mut conn)
                .await
                .unwrap();
        assert_eq!(migrated_flags, expected);
        // The edge under test ends at 67, but the binary is at 72: continue
        // through the tab-order and claim-meta edges so the final open sees
        // current.
        let order_step = EngineMigrationRegistry::production()
            .pending(67, 68)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(order_step.name(), "engine-67-to-68-alpha-tab-orders");
        order_step.preflight(&mut conn).await.unwrap();
        order_step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version=68")
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(crate::db::validate_engine_shape_on_for_test(&mut conn, 68)
            .await
            .unwrap());
        let claim_step = EngineMigrationRegistry::production()
            .pending(68, 69)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(
            claim_step.name(),
            "engine-68-to-69-content-event-claim-meta"
        );
        claim_step.preflight(&mut conn).await.unwrap();
        claim_step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version=69")
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(crate::db::validate_engine_shape_on_for_test(&mut conn, 69)
            .await
            .unwrap());
        continue_from_engine_69(&mut conn).await;
        conn.close().await.unwrap();

        let migrated = crate::open_existing_database_at(&path).await.unwrap();
        let result = crate::conformance::rebuild_and_diff(&migrated)
            .await
            .unwrap();
        assert!(
            result.equal,
            "rebuild drift after 66→67: {}",
            serde_json::to_string_pretty(&result.tables).unwrap()
        );
        // Ordinary archive/restore keeps folding on the migrated database,
        // and replay still converges afterwards.
        crate::store::archive_record(&migrated, &kept)
            .await
            .unwrap();
        let flag: i64 = sqlx::query_scalar("SELECT archived FROM records WHERE id = ?")
            .bind(&kept)
            .fetch_one(migrated.write_pool())
            .await
            .unwrap();
        assert_eq!(flag, 1);
        crate::store::restore_record(&migrated, &kept)
            .await
            .unwrap();
        let flag: i64 = sqlx::query_scalar("SELECT archived FROM records WHERE id = ?")
            .bind(&kept)
            .fetch_one(migrated.write_pool())
            .await
            .unwrap();
        assert_eq!(flag, 0);
        let replayed = crate::conformance::rebuild_and_diff(&migrated)
            .await
            .unwrap();
        assert!(
            replayed.equal,
            "replay drift after post-migration archive/restore: {}",
            serde_json::to_string_pretty(&replayed.tables).unwrap()
        );
        migrated.close().await;
    }

    /// The 73→74 statements are transition text, but the objects they create
    /// must stay byte-identical to the fresh-schema DDL: migrated databases
    /// converge with fresh ones under the shape contract only while every
    /// spelling agrees. The backfill is a Rust loop with no SQL twin by
    /// construction (fresh databases fold task items from the log).
    #[test]
    fn engine_73_to_74_statements_match_fresh_ddl() {
        assert_eq!(ENGINE_73_TO_74_STATEMENTS.len(), 2);
        let fresh: Vec<&str> = crate::schema::DDL_STATEMENTS
            .iter()
            .filter(|candidate| {
                candidate.starts_with("CREATE TABLE body_task_items")
                    || candidate.starts_with("CREATE INDEX idx_body_task_items_")
            })
            .copied()
            .collect();
        assert_eq!(
            fresh.len(),
            2,
            "fresh DDL must carry exactly the body_task_items table and its index"
        );
        for (statement, entry) in ENGINE_73_TO_74_STATEMENTS.iter().zip(fresh.iter()) {
            assert_eq!(
                statement, entry,
                "73→74 statement drifted from fresh DDL: {statement}"
            );
        }
    }

    async fn schema79_connection(version: i64) -> SqliteConnection {
        let options = SqliteConnectOptions::from_str("sqlite::memory:")
            .unwrap()
            .foreign_keys(true);
        let mut connection = SqliteConnection::connect_with(&options).await.unwrap();
        for statement in crate::schema::DDL_STATEMENTS {
            if version < 81 && statement.starts_with("CREATE TABLE schema_config_json_nodes") {
                continue;
            }
            if version < 82 && statement.starts_with("CREATE TABLE facet_value_json_nodes") {
                continue;
            }
            if version < 80 && statement.contains("workspace_rule_installations") {
                continue;
            }
            let statement =
                crate::schema::contract::alpha_tab_installs_create_for_version(statement, version);
            sqlx::query(&statement)
                .execute(&mut connection)
                .await
                .unwrap();
        }
        sqlx::query(&format!("PRAGMA user_version={version}"))
            .execute(&mut connection)
            .await
            .unwrap();
        connection
    }

    #[tokio::test]
    async fn engine_79_to_80_historical_shape_upgrade_fresh_and_drift_refusal() {
        let mut source = schema79_connection(79).await;
        assert_eq!(
            crate::db::schema_shape_contract_sha256_for_test(&mut source)
                .await
                .unwrap(),
            crate::db::ENGINE_79_SHAPE_CONTRACT_SHA256
        );
        Engine79To80Migration.preflight(&mut source).await.unwrap();
        let mut tx = source.begin().await.unwrap();
        Engine79To80Migration.apply(&mut tx).await.unwrap();
        sqlx::query("PRAGMA user_version=80")
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert!(
            crate::db::validate_engine_shape_on_for_test(&mut source, 80)
                .await
                .unwrap()
        );
        type ForeignKeyRow = (i64, i64, String, String, String, String, String, String);
        let foreign_keys: Vec<ForeignKeyRow> =
            sqlx::query_as("PRAGMA foreign_key_list(workspace_rule_installations)")
                .fetch_all(&mut source)
                .await
                .unwrap();
        assert!(foreign_keys.is_empty());
        source.close().await.unwrap();
        for change in [
            "ALTER TABLE meta_events ADD COLUMN forged TEXT",
            "CREATE TABLE workspace_rule_installations(bad TEXT)",
        ] {
            let mut bad = schema79_connection(79).await;
            sqlx::query(change).execute(&mut bad).await.unwrap();
            assert!(Engine79To80Migration.preflight(&mut bad).await.is_err());
            assert_eq!(
                sqlx::query_scalar::<_, i64>("PRAGMA user_version")
                    .fetch_one(&mut bad)
                    .await
                    .unwrap(),
                79
            );
            bad.close().await.unwrap();
        }
    }

    // Frozen measurements use the existing authoritative Rust shape/DDL functions.
    // Values were measured at 35df7e3; no replacement fingerprint algorithm.
    #[tokio::test]
    async fn schema79_measure_contracts() {
        let mut source = schema79_connection(78).await;
        let mut fresh = schema79_connection(79).await;
        assert_eq!(
            crate::db::schema_shape_contract_sha256_for_test(&mut source)
                .await
                .unwrap(),
            crate::db::ENGINE_78_SHAPE_CONTRACT_SHA256
        );
        assert_eq!(
            crate::db::schema_shape_contract_sha256_for_test(&mut fresh)
                .await
                .unwrap(),
            "4e0d87b74b7facb2ce66ef4bab29d79fd24ed2ff3ebe276f84a9bd68e7a28095"
        );
        assert_eq!(
            crate::schema::contract::ddl_sha256(),
            crate::schema::contract::FROZEN_DDL_SHA256
        );
        source.close().await.unwrap();
        fresh.close().await.unwrap();
    }

    #[tokio::test]
    async fn engine_78_to_79_fresh_migrated_and_null_foreign_key() {
        let (db, _, _) = crate::control::alpha_tab_provenance_tests::fixture(Some(
            crate::control::ALPHA_TAB_ADOPTION_VERIFIED,
        ))
        .await;
        let mut connection = db.write_pool().acquire().await.unwrap();
        let before: Option<String> =
            sqlx::query_scalar("SELECT adoption_provenance FROM alpha_tab_installs")
                .fetch_one(&mut *connection)
                .await
                .unwrap();
        assert!(before.is_some());
        sqlx::query("DROP TABLE facet_value_json_nodes")
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query("DROP TABLE schema_config_json_nodes")
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query("DROP TABLE workspace_rule_installations")
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query("ALTER TABLE alpha_tab_installs DROP COLUMN body_read_admission_event_id")
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query("PRAGMA user_version=78")
            .execute(&mut *connection)
            .await
            .unwrap();
        assert_eq!(
            crate::db::schema_shape_contract_sha256_for_test(&mut connection)
                .await
                .unwrap(),
            crate::db::ENGINE_78_SHAPE_CONTRACT_SHA256
        );
        Engine78To79Migration
            .preflight(&mut connection)
            .await
            .unwrap();
        let mut tx = connection.begin().await.unwrap();
        Engine78To79Migration.apply(&mut tx).await.unwrap();
        sqlx::query("PRAGMA user_version=79")
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert!(
            crate::db::validate_engine_shape_on_for_test(&mut connection, 79)
                .await
                .unwrap()
        );
        assert_eq!(
            sqlx::query_scalar::<_, Option<String>>(
                "SELECT adoption_provenance FROM alpha_tab_installs"
            )
            .fetch_one(&mut *connection)
            .await
            .unwrap(),
            before
        );
        assert_eq!(sqlx::query_scalar::<_,i64>("SELECT COUNT(*) FROM alpha_tab_installs WHERE body_read_admission_event_id IS NOT NULL").fetch_one(&mut *connection).await.unwrap(),0);
        assert!(sqlx::query(
            "UPDATE alpha_tab_installs SET body_read_admission_event_id='no-such-control-event'"
        )
        .execute(&mut *connection)
        .await
        .is_err());
        drop(connection);
        assert!(
            crate::conformance::rebuild::rebuild_and_diff_control(&db)
                .await
                .unwrap()
                .equal
        );
        db.close().await;
    }

    #[tokio::test]
    async fn engine_78_to_79_rejects_alternate_and_drift_before_mutation() {
        for isolated in [false, true] {
            let mut connection = schema79_connection(78).await;
            if isolated {
                sqlx::query("ALTER TABLE alpha_tab_installs DROP COLUMN adoption_provenance")
                    .execute(&mut connection)
                    .await
                    .unwrap();
                sqlx::query(ENGINE_78_TO_79_STATEMENT)
                    .execute(&mut connection)
                    .await
                    .unwrap();
            } else {
                sqlx::query("CREATE TABLE unregistered_schema_drift(value TEXT)")
                    .execute(&mut connection)
                    .await
                    .unwrap();
            }
            let before = crate::db::schema_shape_contract_sha256_for_test(&mut connection)
                .await
                .unwrap();
            assert!(Engine78To79Migration
                .preflight(&mut connection)
                .await
                .is_err());
            assert_eq!(
                crate::db::schema_shape_contract_sha256_for_test(&mut connection)
                    .await
                    .unwrap(),
                before
            );
            assert_eq!(
                sqlx::query_scalar::<_, i64>("PRAGMA user_version")
                    .fetch_one(&mut connection)
                    .await
                    .unwrap(),
                78
            );
            connection.close().await.unwrap();
        }
    }

    #[tokio::test]
    async fn engine_78_to_79_preserves_released_77_and_78_shapes() {
        let mut connection = schema79_connection(77).await;
        assert_eq!(
            crate::db::schema_shape_contract_sha256_for_test(&mut connection)
                .await
                .unwrap(),
            crate::db::ENGINE_77_SHAPE_CONTRACT_SHA256
        );
        Engine77To78Migration
            .preflight(&mut connection)
            .await
            .unwrap();
        Engine77To78Migration.apply(&mut connection).await.unwrap();
        sqlx::query("PRAGMA user_version=78")
            .execute(&mut connection)
            .await
            .unwrap();
        assert!(
            crate::db::validate_engine_shape_on_for_test(&mut connection, 78)
                .await
                .unwrap()
        );
        Engine78To79Migration
            .preflight(&mut connection)
            .await
            .unwrap();
        Engine78To79Migration.apply(&mut connection).await.unwrap();
        sqlx::query("PRAGMA user_version=79")
            .execute(&mut connection)
            .await
            .unwrap();
        assert!(
            crate::db::validate_engine_shape_on_for_test(&mut connection, 79)
                .await
                .unwrap()
        );
        connection.close().await.unwrap();
    }

    async fn revert_to_engine_76(connection: &mut SqliteConnection) {
        sqlx::query("DROP TABLE IF EXISTS facet_value_json_nodes")
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query("DROP TABLE IF EXISTS schema_config_json_nodes")
            .execute(&mut *connection)
            .await
            .unwrap();
        let columns: Vec<String> =
            sqlx::query_scalar("SELECT name FROM pragma_table_info('alpha_tab_installs')")
                .fetch_all(&mut *connection)
                .await
                .unwrap();
        if columns
            .iter()
            .any(|name| name == "body_read_admission_event_id")
        {
            sqlx::query("DROP TABLE IF EXISTS workspace_rule_installations")
                .execute(&mut *connection)
                .await
                .unwrap();
            sqlx::query("ALTER TABLE alpha_tab_installs DROP COLUMN body_read_admission_event_id")
                .execute(&mut *connection)
                .await
                .unwrap();
        }
        if columns.iter().any(|name| name == "adoption_provenance") {
            sqlx::query("ALTER TABLE alpha_tab_installs DROP COLUMN adoption_provenance")
                .execute(&mut *connection)
                .await
                .unwrap();
        }
        sqlx::query("DROP TRIGGER IF EXISTS content_event_reaction_meta_insert")
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query("DROP TABLE IF EXISTS content_event_reaction_meta")
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query("PRAGMA user_version=76")
            .execute(&mut *connection)
            .await
            .unwrap();
    }

    #[test]
    fn engine_76_to_77_ddl_matches_fresh() {
        let fresh: Vec<_> = crate::schema::DDL_STATEMENTS
            .iter()
            .filter(|sql| {
                sql.contains("CREATE TABLE content_event_reaction_meta")
                    || sql.contains("CREATE INDEX idx_content_event_reaction_meta_")
                    || sql.contains("CREATE TRIGGER content_event_reaction_meta_insert")
            })
            .copied()
            .collect();
        assert_eq!(fresh, ENGINE_76_TO_77_STATEMENTS);
    }

    fn reaction_payload(emoji: &str, command: &str, actor: &str) -> serde_json::Value {
        serde_json::json!({"format":"native.message-reaction.v1","emoji":emoji,"command":command,"changed":true,"actor_account_id":actor,"executor_kind":"local","reason":"r".repeat(32_000),"idempotency_key":"k".repeat(32_000)})
    }

    async fn insert_reaction(
        connection: &mut SqliteConnection,
        id: &str,
        kind: &str,
        actor: Option<&str>,
        payload: Option<&str>,
    ) -> Result<()> {
        sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,causal_envelope_version,causal_status,created_at) VALUES (?,'reaction-message',?,?,?,1,'legacy_unknown','2026-10-01T00:00:00Z')")
            .bind(id).bind(kind).bind(payload).bind(actor).execute(connection).await?;
        Ok(())
    }

    #[tokio::test]
    async fn engine_76_to_77_fresh_header_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fresh-header.db");
        create_current_schema(&path).await;
        assert_eq!(header_version(&path), CURRENT_ENGINE_SCHEMA_VERSION);
        crate::open_existing_database_at(&path)
            .await
            .unwrap()
            .close()
            .await;
        assert_eq!(header_version(&path), CURRENT_ENGINE_SCHEMA_VERSION);
        // Execute the published DDL directly too, without a database helper
        // or manual stamp concealing a wrong final PRAGMA.
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        for sql in crate::schema::DDL_STATEMENTS {
            conn.execute_batch(sql).unwrap();
        }
        let version: i64 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, CURRENT_ENGINE_SCHEMA_VERSION);
    }

    #[tokio::test]
    async fn engine_76_to_77_backfill_matches_live_and_payload_free_fold() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("reaction-edge.db");
        create_current_schema(&path).await;
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        for (id, actor, emoji, command) in [
            ("add-a", "alice", "👍", "add_reaction"),
            ("add-b", "bea", "👍", "add_reaction"),
            ("remove-a", "alice", "👍", "remove_reaction"),
            ("undo-a", "alice", "👍", "add_reaction"),
            ("other-emoji", "alice", "👀", "add_reaction"),
            ("remove-b", "bea", "👍", "remove_reaction"),
        ] {
            let kind = if command == "remove_reaction" {
                "message.reaction.removed.v1"
            } else {
                "message.reaction.added.v1"
            };
            insert_reaction(
                &mut conn,
                id,
                kind,
                Some(actor),
                Some(&reaction_payload(emoji, command, actor).to_string()),
            )
            .await
            .unwrap();
        }
        for (id, emoji, command) in [
            ("seq-add", "🎉", "add_reaction"),
            ("seq-remove", "😂", "remove_reaction"),
            ("seq-undo", "❤️", "add_reaction"),
        ] {
            let payload = serde_json::json!([
                "native.message-reaction.v1",
                emoji,
                "key",
                command,
                true,
                "alice",
                "local",
                null,
                "reason"
            ]);
            validate_reaction_meta_source(id, Some(&payload.to_string()), Some("alice")).unwrap();
            let kind = if command == "remove_reaction" {
                "message.reaction.removed.v1"
            } else {
                "message.reaction.added.v1"
            };
            insert_reaction(
                &mut conn,
                id,
                kind,
                Some("alice"),
                Some(&payload.to_string()),
            )
            .await
            .unwrap();
        }
        type Meta = (
            i64,
            String,
            String,
            Option<String>,
            String,
            String,
            String,
            String,
        );
        let select = "SELECT event_seq,record_id,actor,legacy_emoji,emoji,executor_kind,reaction_class,created_at FROM content_event_reaction_meta ORDER BY event_seq";
        let live: Vec<Meta> = sqlx::query_as(select).fetch_all(&mut conn).await.unwrap();
        assert_eq!(live.len(), 9);
        let source: Vec<Meta> = sqlx::query_as("SELECT seq,record_id,actor,json_extract(payload,'$.emoji'),
      json_extract(payload,CASE WHEN json_type(payload)='array' THEN '$[1]' ELSE '$.emoji' END),
      json_extract(payload,CASE WHEN json_type(payload)='array' THEN '$[6]' ELSE '$.executor_kind' END),CASE type WHEN 'message.reaction.added.v1' THEN 'added' ELSE 'removed' END,created_at FROM content_events WHERE type IN ('message.reaction.added.v1','message.reaction.removed.v1') ORDER BY seq").fetch_all(&mut conn).await.unwrap();
        assert_eq!(live, source);
        let fold = "WITH ranked AS (SELECT actor,legacy_emoji,emoji,executor_kind,created_at,reaction_class,ROW_NUMBER() OVER (PARTITION BY actor,legacy_emoji ORDER BY event_seq DESC) recency FROM content_event_reaction_meta WHERE record_id='reaction-message') SELECT actor,emoji,executor_kind,created_at FROM ranked WHERE recency=1 AND reaction_class='added' ORDER BY legacy_emoji,actor";
        let expected: Vec<(String, String, String, String)> =
            sqlx::query_as(fold).fetch_all(&mut conn).await.unwrap();
        assert_eq!(expected.len(), 3);
        let payload_fold: Vec<(String,String,String)> = sqlx::query_as(
            "WITH ranked AS (SELECT actor,payload,created_at,type,ROW_NUMBER() OVER (PARTITION BY actor,json_extract(payload,'$.emoji') ORDER BY seq DESC) recency FROM content_events WHERE record_id='reaction-message' AND type IN ('message.reaction.added.v1','message.reaction.removed.v1')) SELECT actor,payload,created_at FROM ranked WHERE recency=1 AND type='message.reaction.added.v1' ORDER BY json_extract(payload,'$.emoji'),actor"
        ).fetch_all(&mut conn).await.unwrap();
        let parsed: Vec<_> = payload_fold
            .into_iter()
            .map(|(actor, payload, created_at)| {
                let payload: crate::events::MessageReactionPayload =
                    serde_json::from_str(&payload).unwrap();
                payload.validate(Some(&actor)).unwrap();
                (actor, payload.emoji, payload.executor_kind, created_at)
            })
            .collect();
        assert_eq!(expected, parsed);
        revert_to_engine_76(&mut conn).await;
        let digest = crate::db::schema_shape_contract_sha256_for_test(&mut conn)
            .await
            .unwrap();
        assert_eq!(digest, crate::db::ENGINE_76_SHAPE_CONTRACT_SHA256);
        let step = EngineMigrationRegistry::production()
            .pending(76, 77)
            .unwrap()
            .pop()
            .unwrap();
        step.preflight(&mut conn).await.unwrap();
        step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version=77")
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(crate::db::validate_engine_shape_on_for_test(&mut conn, 77)
            .await
            .unwrap());
        let migrated: Vec<Meta> = sqlx::query_as(select).fetch_all(&mut conn).await.unwrap();
        assert_eq!(migrated, live);
        // Append-only guards continue to reject source mutations.
        for sql in [
            "UPDATE content_events SET payload=NULL",
            "DELETE FROM content_events",
        ] {
            assert!(sqlx::query(sql).execute(&mut conn).await.is_err());
        }
        let actual: Vec<(String, String, String, String)> =
            sqlx::query_as(fold).fetch_all(&mut conn).await.unwrap();
        assert_eq!(actual, expected);
        conn.close().await.unwrap();
        let reader = rusqlite::Connection::open(&path).unwrap();
        reader.authorizer(Some(|ctx: rusqlite::hooks::AuthContext<'_>| {
            if matches!(
                ctx.action,
                rusqlite::hooks::AuthAction::Read {
                    table_name: "content_events",
                    ..
                }
            ) {
                rusqlite::hooks::Authorization::Deny
            } else {
                rusqlite::hooks::Authorization::Allow
            }
        }));
        assert!(reader
            .prepare("SELECT payload FROM content_events")
            .is_err());
        let actual: Vec<(String, String, String, String)> = reader
            .prepare(fold)
            .unwrap()
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn engine_76_to_77_runner_preserves_preimage_and_header_on_refusal() {
        let dir = tempfile::tempdir().unwrap();
        let offbox = tempfile::tempdir().unwrap();
        let backup = test_preimage_store(offbox.path(), dir.path());
        for invalid in [false, true] {
            let path = dir.path().join(format!("runner-{invalid}.db"));
            let db = crate::create_database(&path.to_string_lossy())
                .await
                .unwrap();
            let message=crate::store::create_record(&db,serde_json::json!({"type":"Message","kind":"message","name":"runner","body":"body"})).await.unwrap();
            crate::store::append(
                &db,
                crate::store::AppendSpec {
                    record_id: message,
                    event_type: "message.reaction.added.v1".into(),
                    actor: Some("alice".into()),
                    payload: serde_json::json!([
                        "native.message-reaction.v1",
                        "👍",
                        "key",
                        "add_reaction",
                        true,
                        "alice",
                        "local",
                        null,
                        "reason"
                    ]),
                },
            )
            .await
            .unwrap();
            db.close().await;
            let options =
                SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display())).unwrap();
            let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
            revert_to_engine_76(&mut conn).await;
            if invalid {
                insert_reaction(
                    &mut conn,
                    "historical-invalid",
                    "message.reaction.removed.v1",
                    Some("alice"),
                    Some(&reaction_payload("invalid", "remove_reaction", "alice").to_string()),
                )
                .await
                .unwrap();
            }
            conn.close().await.unwrap();
            let report = migrate_database(
                &path,
                "reaction-runner",
                &format!("reaction-{invalid}"),
                77,
                &EngineMigrationRegistry::production(),
                &backup,
                Arc::new(|| async { Ok(()) }.boxed()),
            )
            .await;
            assert_eq!(
                report.outcome,
                if invalid { "failed" } else { "migrated" },
                "{report:?}"
            );
            assert_eq!(header_version(&path), if invalid { 76 } else { 77 });
            let preimage = report.backup.expect("verified preimage before migration");
            let restored = dir.path().join(format!("restored-{invalid}.db"));
            backup
                .sink
                .get(preimage.key, restored.clone())
                .await
                .unwrap();
            assert_eq!(header_version(&restored), 76);
            let mut restored_conn = SqliteConnection::connect_with(
                &SqliteConnectOptions::from_str(&format!("sqlite:{}", restored.display())).unwrap(),
            )
            .await
            .unwrap();
            Engine76To77Migration
                .preflight(&mut restored_conn)
                .await
                .unwrap();
            restored_conn.close().await.unwrap();
            if invalid {
                assert!(report.error_message.unwrap().contains("historical-invalid"));
                let conn = rusqlite::Connection::open(&path).unwrap();
                let tables:i64=conn.query_row("SELECT count(*) FROM sqlite_schema WHERE name='content_event_reaction_meta'",[],|r|r.get(0)).unwrap();
                assert_eq!(
                    tables, 0,
                    "failed runner transaction leaves the predecessor schema"
                );
                let count: i64 = conn
                    .query_row(
                        "SELECT count(*) FROM content_events WHERE id='historical-invalid'",
                        [],
                        |r| r.get(0),
                    )
                    .unwrap();
                assert_eq!(count, 1);
            } else {
                // The focused runner proved 76→77 above. Ordinary serving
                // opens only the current schema, so finish successor edges.
                let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
                advance_engine_to_current(&mut conn, 77).await;
                conn.close().await.unwrap();
                crate::open_existing_database_at(&path)
                    .await
                    .unwrap()
                    .close()
                    .await;
            }
        }
    }

    #[tokio::test]
    async fn engine_76_to_77_backfill_covers_signed_sequence_extremes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seq-extremes.db");
        create_current_schema(&path).await;
        let mut conn = SqliteConnection::connect_with(
            &SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display())).unwrap(),
        )
        .await
        .unwrap();
        revert_to_engine_76(&mut conn).await;
        for seq in [i64::MIN, i64::MAX] {
            sqlx::query("INSERT INTO content_events(seq,id,record_id,type,payload,actor,causal_envelope_version,causal_status) VALUES (?,?,'reaction-message','message.reaction.added.v1',?,'alice',1,'legacy_unknown')").bind(seq).bind(format!("event-{seq}")).bind(reaction_payload("👍","add_reaction","alice").to_string()).execute(&mut conn).await.unwrap();
        }
        Engine76To77Migration.apply(&mut conn).await.unwrap();
        let actual: Vec<i64> = sqlx::query_scalar(
            "SELECT event_seq FROM content_event_reaction_meta ORDER BY event_seq",
        )
        .fetch_all(&mut conn)
        .await
        .unwrap();
        assert_eq!(actual, [i64::MIN, i64::MAX]);
    }

    #[tokio::test]
    async fn engine_76_to_77_invalid_payloads_refuse_without_partial_projection() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("reaction-invalid.db");
        create_current_schema(&path).await;
        let options =
            SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display())).unwrap();
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        let base = reaction_payload("👍", "add_reaction", "alice");
        let mut invalid = vec![
            None,
            Some("not JSON".into()),
            Some("null".into()),
            Some("[]".into()),
            Some("{}".into()),
        ];
        for (key, value) in [
            ("emoji", serde_json::json!("x")),
            ("changed", serde_json::json!("true")),
            ("format", serde_json::json!("wrong")),
            ("reason", serde_json::json!("\u{2003}")),
            ("idempotency_key", serde_json::json!(0)),
            ("actor_account_id", serde_json::json!("bea")),
            ("executor_kind", serde_json::json!("invalid")),
            ("executor_kind", serde_json::json!("agent")),
            ("idempotency_key", serde_json::json!("\u{2003}")),
            ("executor_ref", serde_json::json!("forbidden")),
            ("command", serde_json::json!("invalid")),
            ("unknown", serde_json::json!(true)),
        ] {
            let mut payload = base.clone();
            payload[key] = value;
            invalid.push(Some(payload.to_string()));
        }
        let mut bad_ack = base.clone();
        bad_ack["command"] = serde_json::json!("satisfy_acknowledgement_expectation_with_reaction");
        bad_ack["emoji"] = serde_json::json!("👀");
        invalid.push(Some(bad_ack.to_string()));
        let mut bad_ref = base.clone();
        bad_ref["executor_kind"] = serde_json::json!("agent");
        bad_ref["executor_ref"] = serde_json::json!("\u{2003}");
        invalid.push(Some(bad_ref.to_string()));
        let mut missing = base.clone();
        missing.as_object_mut().unwrap().remove("emoji");
        invalid.push(Some(missing.to_string()));
        invalid.push(Some(base.to_string().replacen(
            "{",
            "{\"emoji\":\"👍\",",
            1,
        )));
        for (index, payload) in invalid.iter().enumerate() {
            let id = format!("bad-{index}");
            assert!(
                insert_reaction(
                    &mut conn,
                    &id,
                    "message.reaction.added.v1",
                    Some("alice"),
                    payload.as_deref()
                )
                .await
                .is_err(),
                "{index}"
            );
        }
        assert!(insert_reaction(
            &mut conn,
            "null-actor",
            "message.reaction.added.v1",
            None,
            Some(&base.to_string())
        )
        .await
        .is_err());
        let events: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events WHERE type IN ('message.reaction.added.v1','message.reaction.removed.v1')")
            .fetch_one(&mut conn)
            .await
            .unwrap();
        assert_eq!(
            events, 0,
            "every rejected insert rolls back its source and projections"
        );
        for (kind, reference) in [
            ("local", None),
            ("authenticated_principal", None),
            ("human_attested", Some("human:ref")),
            ("agent", Some("agent:ref")),
            ("delegated_service", Some("service:ref")),
        ] {
            let mut payload = base.clone();
            payload["executor_kind"] = serde_json::json!(kind);
            payload["executor_ref"] = serde_json::json!(reference);
            payload["changed"] = serde_json::json!(false);
            validate_reaction_meta_source(kind, Some(&payload.to_string()), Some("alice")).unwrap();
            insert_reaction(
                &mut conn,
                kind,
                "message.reaction.added.v1",
                Some("alice"),
                Some(&payload.to_string()),
            )
            .await
            .unwrap();
        }
        let projected: i64 = sqlx::query_scalar("SELECT count(*) FROM content_event_reaction_meta")
            .fetch_one(&mut conn)
            .await
            .unwrap();
        assert_eq!(
            projected, 5,
            "every valid executor and no-change event is retained"
        );
        // Historical malformed events need no invented sentinel: each refuses
        // migration before any new schema is installed, naming the source id.
        revert_to_engine_76(&mut conn).await;
        sqlx::query("DROP TRIGGER content_event_claim_meta_insert")
            .execute(&mut conn)
            .await
            .unwrap();
        let valid = base.to_string();
        let historical = invalid
            .iter()
            .map(|payload| (payload.as_deref(), Some("alice")))
            .chain(std::iter::once((Some(valid.as_str()), None)));
        for (index, (payload, actor)) in historical.enumerate() {
            sqlx::query("SAVEPOINT invalid_case")
                .execute(&mut conn)
                .await
                .unwrap();
            let id = format!("historic-{index}");
            // Explicit negative local sequences are representable historical
            // SQLite input; validation must not assume AUTOINCREMENT origins.
            sqlx::query("INSERT INTO content_events(seq,id,record_id,type,payload,actor,causal_envelope_version,causal_status) VALUES (-1,?,'reaction-message','message.reaction.removed.v1',?,?,1,'legacy_unknown')").bind(&id).bind(payload).bind(actor).execute(&mut conn).await.unwrap();
            let claim_trigger = crate::schema::DDL_STATEMENTS
                .iter()
                .find(|sql| sql.starts_with("CREATE TRIGGER content_event_claim_meta_insert"))
                .unwrap();
            sqlx::query(claim_trigger).execute(&mut conn).await.unwrap();
            Engine76To77Migration.preflight(&mut conn).await.unwrap();
            let error = Engine76To77Migration
                .apply(&mut conn)
                .await
                .unwrap_err()
                .to_string();
            assert!(error.contains(&id), "{error}");
            let count: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM sqlite_schema WHERE name='content_event_reaction_meta'",
            )
            .fetch_one(&mut conn)
            .await
            .unwrap();
            assert_eq!(count, 0);
            let version: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut conn)
                .await
                .unwrap();
            assert_eq!(version, 76);
            let preserved: i64 =
                sqlx::query_scalar("SELECT count(*) FROM content_events WHERE id=?")
                    .bind(&id)
                    .fetch_one(&mut conn)
                    .await
                    .unwrap();
            assert_eq!(preserved, 1);
            sqlx::query("ROLLBACK TO invalid_case")
                .execute(&mut conn)
                .await
                .unwrap();
            sqlx::query("RELEASE invalid_case")
                .execute(&mut conn)
                .await
                .unwrap();
        }
    }

    #[test]
    fn engine_74_to_75_ddl_matches_fresh() {
        let fresh: Vec<_> = crate::schema::DDL_STATEMENTS
            .iter()
            .filter(|statement| statement.starts_with("CREATE TABLE body_blocks"))
            .collect();
        assert_eq!(fresh.len(), 1);
        assert_eq!(&ENGINE_74_TO_75_STATEMENTS[0], fresh[0]);
    }

    /// Allocated measurement entry. Reconstructs genuine workspace80 with the
    /// existing historical DDL transform, not the old unmerged JSON80 shape.
    /// Reports shapes independently of historical admission pins and the DDL freeze.
    #[tokio::test]
    async fn schema81_measure_contracts() {
        let mut source79 = schema79_connection(79).await;
        let mut source80 = schema79_connection(80).await;
        let mut current = schema79_connection(81).await;
        let old_shape = crate::db::schema_shape_contract_sha256_for_test(&mut source79)
            .await
            .unwrap();
        assert_eq!(old_shape, crate::db::ENGINE_79_SHAPE_CONTRACT_SHA256);
        let workspace_shape = crate::db::schema_shape_contract_sha256_for_test(&mut source80)
            .await
            .unwrap();
        let current_shape = crate::db::schema_shape_contract_sha256_for_test(&mut current)
            .await
            .unwrap();
        let workspace_ddl = crate::schema::contract::historical_ddl_for_test(80);
        use sha2::{Digest, Sha256};
        println!(
            "{}",
            serde_json::json!({
                "engine_version":81,"source79_shape_sha256":old_shape,
                "source80_shape_sha256":workspace_shape,
                "source80_ddl_sha256":hex::encode(Sha256::digest(workspace_ddl.as_bytes())),
                "source80_ddl_bytes":workspace_ddl.len(),
                "source80_ddl_statements":crate::schema::DDL_STATEMENTS.len()-1,
                "current_shape_sha256":current_shape,
                "current_ddl_sha256":crate::schema::contract::ddl_sha256(),
                "current_ddl_bytes":crate::schema::canonical_ddl().len(),
                "current_ddl_statements":crate::schema::DDL_STATEMENTS.len()
            })
        );
        source79.close().await.unwrap();
        source80.close().await.unwrap();
        current.close().await.unwrap();
    }

    #[tokio::test]
    async fn engine_80_admission_accepts_released_workspace_shape_and_refuses_drift() {
        let mut source = schema79_connection(80).await;
        assert_eq!(
            crate::db::schema_shape_contract_sha256_for_test(&mut source)
                .await
                .unwrap(),
            "a5c0e65d4d1f709940ab7cd8b158b2d2d885e086af6771780310bd728528aab5"
        );
        assert!(
            crate::db::validate_engine_shape_on_for_test(&mut source, 80)
                .await
                .unwrap()
        );
        sqlx::query("ALTER TABLE workspace_rule_installations ADD COLUMN unexpected TEXT")
            .execute(&mut source)
            .await
            .unwrap();
        assert!(
            !crate::db::validate_engine_shape_on_for_test(&mut source, 80)
                .await
                .unwrap()
        );
        source.close().await.unwrap();
    }

    #[tokio::test]
    async fn engine_79_to_81_preserves_workspace_edge_and_config_literals() {
        let mut connection = schema79_connection(79).await;
        sqlx::query(r#"INSERT INTO schema_config(id,layer,data) VALUES('','user','{"n":1.00}')"#)
            .execute(&mut connection)
            .await
            .unwrap();
        let edges = EngineMigrationRegistry::production()
            .pending(79, 81)
            .unwrap();
        assert_eq!(edges.len(), 2);
        for edge in &edges {
            edge.preflight(&mut connection).await.unwrap();
        }
        let mut tx = connection.begin().await.unwrap();
        for edge in edges {
            edge.apply(&mut tx).await.unwrap();
            sqlx::query(&format!("PRAGMA user_version={}", edge.to()))
                .execute(&mut *tx)
                .await
                .unwrap();
        }
        tx.commit().await.unwrap();
        assert!(
            crate::db::validate_engine_shape_on_for_test(&mut connection, 81)
                .await
                .unwrap()
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM workspace_rule_installations")
                .fetch_one(&mut connection)
                .await
                .unwrap(),
            0
        );
        let literal: (String,i64,String) = sqlx::query_as("SELECT path,parent_ordinal,number_text FROM schema_config_json_nodes WHERE config_id='' AND ordinal=1").fetch_one(&mut connection).await.unwrap();
        assert_eq!(literal, ("/n".into(), 0, "1.00".into()));
        connection.close().await.unwrap();
    }

    #[test]
    fn engine_80_to_81_ddl_is_the_fresh_config_carrier() {
        let fresh: Vec<_> = crate::schema::DDL_STATEMENTS
            .iter()
            .filter(|statement| statement.starts_with("CREATE TABLE schema_config_json_nodes"))
            .collect();
        assert_eq!(
            fresh,
            vec![&crate::schema::ddl::SCHEMA_CONFIG_JSON_NODES_DDL]
        );
    }

    #[tokio::test]
    async fn engine_80_to_81_backfills_lowest_key_lexemes_and_matches_fresh_shape() {
        let mut connection = schema79_connection(80).await;
        // The empty ID is legal in the persisted TEXT PRIMARY KEY. A cursor
        // beginning after "" would skip the first source and its entire tree.
        sqlx::query(
            "INSERT INTO schema_config(id,layer,data) VALUES('', 'user', ?), ('z','user','{}')",
        )
        .bind(r#"{"a":{"n":1.00},"a":{"n":2E+09}}"#)
        .execute(&mut connection)
        .await
        .unwrap();
        Engine80To81Migration
            .preflight(&mut connection)
            .await
            .unwrap();
        let mut tx = connection.begin().await.unwrap();
        Engine80To81Migration.apply(&mut tx).await.unwrap();
        sqlx::query("PRAGMA user_version=81")
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        type ConfigNodeRow = (String, i64, String, Option<i64>, Option<String>);
        let rows: Vec<ConfigNodeRow> = sqlx::query_as(
            "SELECT config_id,ordinal,path,parent_ordinal,number_text FROM schema_config_json_nodes ORDER BY config_id,ordinal"
        ).fetch_all(&mut connection).await.unwrap();
        assert_eq!(
            rows,
            vec![
                ("".into(), 0, "".into(), None, None),
                ("".into(), 1, "/a".into(), Some(0), None),
                ("".into(), 2, "/a/n".into(), Some(1), Some("1.00".into())),
                ("".into(), 3, "/a".into(), Some(0), None),
                ("".into(), 4, "/a/n".into(), Some(3), Some("2E+09".into())),
                ("z".into(), 0, "".into(), None, None),
            ]
        );
        let mut fresh = schema79_connection(81).await;
        assert_eq!(
            crate::db::schema_shape_contract_sha256_for_test(&mut connection)
                .await
                .unwrap(),
            crate::db::schema_shape_contract_sha256_for_test(&mut fresh)
                .await
                .unwrap()
        );
        assert!(
            crate::db::validate_engine_shape_on_for_test(&mut connection, 81)
                .await
                .unwrap()
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>("SELECT data FROM schema_config WHERE id=''")
                .fetch_one(&mut connection)
                .await
                .unwrap(),
            r#"{"a":{"n":1.00},"a":{"n":2E+09}}"#
        );
    }

    #[tokio::test]
    async fn engine_80_to_81_runner_rolls_back_every_invalid_source_and_prior_backfill() {
        for (source, message) in crate::schema_config_json_nodes::invalid_sources() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("legacy-config.db");
            let db = crate::create_database(path.to_str().unwrap())
                .await
                .unwrap();
            crate::meta::schema_config::write_user_schema_config(
                &db,
                "{}",
                crate::meta::schema_config::SchemaConfigOptions {
                    id: Some("".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
            let events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM meta_events")
                .fetch_one(db.write_pool())
                .await
                .unwrap();
            // Install legacy bytes directly, then reconstruct the exact v80
            // source shape. Malformed config data had no SQLite JSON CHECK.
            sqlx::query("INSERT INTO schema_config(id,layer,data) VALUES('zz:invalid','user',?)")
                .bind(&source)
                .execute(db.write_pool())
                .await
                .unwrap();
            // Uninterpreted physical storage sentinel, not a rule admission receipt.
            sqlx::query("INSERT INTO workspace_rule_installations(root,namespace,name,snapshot_json,snapshot_digest,event_seq,actor,created_at) VALUES('native:root','fixture','preserved','{}',?,1,'fixture:physical','2000-01-01T00:00:00Z')")
                .bind("a".repeat(64)).execute(db.write_pool()).await.unwrap();
            sqlx::query("DROP TABLE facet_value_json_nodes")
                .execute(db.write_pool())
                .await
                .unwrap();
            sqlx::query("DROP TABLE schema_config_json_nodes")
                .execute(db.write_pool())
                .await
                .unwrap();
            sqlx::query("PRAGMA user_version=80")
                .execute(db.write_pool())
                .await
                .unwrap();
            db.close().await;
            let offbox = tempfile::tempdir().unwrap();
            let backup = test_preimage_store(offbox.path(), dir.path());
            let report = migrate_database(
                &path,
                "config-invalid",
                "config-invalid-run",
                81,
                &EngineMigrationRegistry::production(),
                &backup,
                Arc::new(|| async { Ok(()) }.boxed()),
            )
            .await;
            assert_ne!(report.outcome, "migrated", "{report:?}");
            assert!(
                format!("{report:?}").contains(message),
                "{message}: {report:?}"
            );
            assert_eq!(header_version(&path), 80);
            let mut conn =
                SqliteConnection::connect_with(&single_connection_options(&path).unwrap())
                    .await
                    .unwrap();
            assert!(crate::db::validate_engine_shape_on_for_test(&mut conn, 80)
                .await
                .unwrap());
            assert_eq!(sqlx::query_scalar::<_,String>("SELECT actor||':'||snapshot_json||':'||event_seq FROM workspace_rule_installations WHERE namespace='fixture' AND name='preserved'").fetch_one(&mut conn).await.unwrap(),"fixture:physical:{}:1");
            assert_eq!(
                sqlx::query_scalar::<_, i64>(
                    "SELECT count(*) FROM sqlite_master WHERE name='schema_config_json_nodes'"
                )
                .fetch_one(&mut conn)
                .await
                .unwrap(),
                0
            );
            assert_eq!(
                sqlx::query_scalar::<_, String>(
                    "SELECT data FROM schema_config WHERE id='zz:invalid'"
                )
                .fetch_one(&mut conn)
                .await
                .unwrap(),
                source
            );
            assert_eq!(
                sqlx::query_scalar::<_, String>("SELECT data FROM schema_config WHERE id=''")
                    .fetch_one(&mut conn)
                    .await
                    .unwrap(),
                "{}"
            );
            assert_eq!(
                sqlx::query_scalar::<_, i64>("SELECT count(*) FROM meta_events")
                    .fetch_one(&mut conn)
                    .await
                    .unwrap(),
                events
            );
            conn.close().await.unwrap();
        }
    }

    #[tokio::test]
    async fn engine_80_to_81_preflight_refuses_drift_before_table_creation() {
        let mut connection = schema79_connection(80).await;
        sqlx::query("ALTER TABLE schema_config ADD COLUMN unreviewed TEXT")
            .execute(&mut connection)
            .await
            .unwrap();
        assert!(Engine80To81Migration
            .preflight(&mut connection)
            .await
            .is_err());
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM sqlite_master WHERE name='schema_config_json_nodes'"
            )
            .fetch_one(&mut connection)
            .await
            .unwrap(),
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("PRAGMA user_version")
                .fetch_one(&mut connection)
                .await
                .unwrap(),
            80
        );
    }

    /// Engine 82 projects flattenable facet text and skips every value that
    /// cannot produce nodes, without aborting the edge.
    #[tokio::test]
    async fn engine_81_to_82_backfills_flattenable_facets_and_skips_bad_values() {
        let mut connection = schema79_connection(81).await;
        sqlx::query("INSERT INTO records(id,type,kind) VALUES('r1','Document','note')")
            .execute(&mut connection)
            .await
            .unwrap();
        let oversize = format!(
            "{{\"a\":\"{}\"}}",
            "x".repeat(crate::json_nodes::MAX_JSON_SOURCE_BYTES)
        );
        let facets: [(&str, &str); 6] = [
            ("fv:r1:obj", r#"{"a":1}"#),
            ("fv:r1:arr", "[true]"),
            ("fv:r1:scalar", "5"),
            ("fv:r1:plain", "plain text"),
            ("fv:r1:malformed", "{oops"),
            ("fv:r1:big", oversize.as_str()),
        ];
        for (id, value) in facets {
            sqlx::query("INSERT INTO facet_values(id,record_id,key,value) VALUES(?,?,?,?)")
                .bind(id)
                .bind("r1")
                .bind(id.rsplit(':').next().unwrap())
                .bind(value)
                .execute(&mut connection)
                .await
                .unwrap();
        }
        Engine81To82Migration
            .preflight(&mut connection)
            .await
            .unwrap();
        let mut tx = connection.begin().await.unwrap();
        Engine81To82Migration.apply(&mut tx).await.unwrap();
        sqlx::query("PRAGMA user_version=82")
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        type FacetNodeRow = (String, i64, String, String);
        let rows: Vec<FacetNodeRow> = sqlx::query_as(
            "SELECT facet_id,ordinal,path,node_type FROM facet_value_json_nodes ORDER BY facet_id,ordinal",
        )
        .fetch_all(&mut connection)
        .await
        .unwrap();
        assert_eq!(
            rows,
            vec![
                ("fv:r1:arr".into(), 0, "".into(), "array".into()),
                ("fv:r1:arr".into(), 1, "/0".into(), "boolean".into()),
                ("fv:r1:obj".into(), 0, "".into(), "object".into()),
                ("fv:r1:obj".into(), 1, "/a".into(), "number".into()),
            ]
        );
        assert!(
            crate::db::validate_engine_shape_on_for_test(&mut connection, 82)
                .await
                .unwrap()
        );
    }

    #[test]
    fn engine_75_to_76_ddl_matches_fresh() {
        let fresh: Vec<_> = crate::schema::DDL_STATEMENTS
            .iter()
            .filter(|statement| statement.starts_with("CREATE TABLE vocabulary_value_json_nodes"))
            .collect();
        assert_eq!(
            fresh,
            vec![&crate::schema::ddl::VOCABULARY_VALUE_JSON_NODES_DDL]
        );
    }

    #[tokio::test]
    async fn engine_75_to_76_backfills_stored_metadata_and_rolls_back_on_cap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("json-nodes-edge.db");
        create_current_schema(&path).await;
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        sqlx::query("INSERT INTO vocabularies(id,name) VALUES('voc:test','test')")
            .execute(&mut conn)
            .await
            .unwrap();
        sqlx::query("INSERT INTO vocabulary_values(id,vocabulary_id,value,metadata) VALUES('vv:test','voc:test','test',?)")
            .bind(r#"{"x":1.00,"x":2E+09}"#)
            .execute(&mut conn).await.unwrap();
        revert_to_engine_75(&mut conn).await;
        let step = EngineMigrationRegistry::production()
            .pending(75, 76)
            .unwrap()
            .pop()
            .unwrap();
        step.preflight(&mut conn).await.unwrap();
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut conn)
            .await
            .unwrap();
        step.apply(&mut conn).await.unwrap();
        sqlx::query("COMMIT").execute(&mut conn).await.unwrap();
        let lexemes: Vec<String> = sqlx::query_scalar(
            "SELECT number_text FROM vocabulary_value_json_nodes WHERE value_id='vv:test' AND node_type='number' ORDER BY ordinal",
        ).fetch_all(&mut conn).await.unwrap();
        assert_eq!(lexemes, ["1.00", "2E+09"]);

        sqlx::query("DROP TABLE vocabulary_value_json_nodes")
            .execute(&mut conn)
            .await
            .unwrap();
        let oversize = format!(
            "\"{}\"",
            "x".repeat(crate::json_nodes::MAX_JSON_SOURCE_BYTES)
        );
        sqlx::query("UPDATE vocabulary_values SET metadata=? WHERE id='vv:test'")
            .bind(oversize)
            .execute(&mut conn)
            .await
            .unwrap();
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut conn)
            .await
            .unwrap();
        let error = step.apply(&mut conn).await.unwrap_err();
        assert!(error.to_string().contains("source exceeds"), "{error}");
        sqlx::query("ROLLBACK").execute(&mut conn).await.unwrap();
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE name='vocabulary_value_json_nodes'",
        )
        .fetch_one(&mut conn)
        .await
        .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn engine_74_to_75_backfills_exact_body_event_and_rebuilds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks-edge.db");
        create_current_schema(&path).await;
        let db = crate::open_existing_database_at(&path).await.unwrap();
        let body = format!("# H\n\n```\n{}\n```\n", "é".repeat(160_000));
        let id = crate::store::create_record(
            &db,
            serde_json::json!({"type":"Document","kind":"note","name":"large","body":body.clone()}),
        )
        .await
        .unwrap();
        let opaque_id = crate::store::create_record(
            &db,
            serde_json::json!({"type":"Document","kind":"note","name":"opaque","body":{"heading":"# not Markdown"}}),
        ).await.unwrap();
        crate::store::update_record(&db, &id, serde_json::json!({"summary":"later metadata"}))
            .await
            .unwrap();
        type BodyBlockRow = (i64, i64, i64, i64, String, String, String, i64, i64);
        let expected: Vec<BodyBlockRow> = sqlx::query_as(
            "SELECT block_index,chunk_index,chunk_count,source_event_seq,heading_path,block_kind,text,start_offset,end_offset FROM body_blocks WHERE record_id=? ORDER BY block_index,chunk_index"
        ).bind(&id).fetch_all(db.write_pool()).await.unwrap();
        assert!(expected.len() > 8);
        db.close().await;
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        revert_to_engine_75(&mut conn).await;
        sqlx::query("DROP TABLE body_blocks")
            .execute(&mut conn)
            .await
            .unwrap();
        sqlx::query("PRAGMA user_version=74")
            .execute(&mut conn)
            .await
            .unwrap();
        assert_eq!(
            crate::db::schema_shape_contract_sha256_for_test(&mut conn)
                .await
                .unwrap(),
            crate::db::ENGINE_74_SHAPE_CONTRACT_SHA256,
        );
        let step = EngineMigrationRegistry::production()
            .pending(74, 75)
            .unwrap()
            .pop()
            .unwrap();
        step.preflight(&mut conn).await.unwrap();
        step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version=75")
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(crate::db::validate_engine_shape_on_for_test(&mut conn, 75)
            .await
            .unwrap());
        let actual: Vec<BodyBlockRow> = sqlx::query_as(
            "SELECT block_index,chunk_index,chunk_count,source_event_seq,heading_path,block_kind,text,start_offset,end_offset FROM body_blocks WHERE record_id=? ORDER BY block_index,chunk_index"
        ).bind(&id).fetch_all(&mut conn).await.unwrap();
        assert_eq!(actual, expected);
        assert_eq!(
            actual.iter().map(|row| row.6.as_str()).collect::<String>(),
            body
        );
        let opaque: (String, String) =
            sqlx::query_as("SELECT block_kind,heading_path FROM body_blocks WHERE record_id=?")
                .bind(&opaque_id)
                .fetch_one(&mut conn)
                .await
                .unwrap();
        assert_eq!(opaque, ("opaque".into(), "[]".into()));
        // Serving requires the current schema. Keep the historical v75 shape
        // and row assertions above, then apply the 75→76 edge before opening
        // this file through the runtime for replay.
        advance_engine_to_current(&mut conn, 75).await;
        conn.close().await.unwrap();
        let reopened = crate::open_existing_database_at(&path).await.unwrap();
        assert!(
            crate::conformance::rebuild_and_diff(&reopened)
                .await
                .unwrap()
                .equal
        );
        reopened.close().await;
    }

    #[tokio::test]
    async fn engine_74_to_75_refuses_oversized_existing_body_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oversized-block-edge.db");
        create_current_schema(&path).await;
        let options = SqliteConnectOptions::new().filename(&path);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        let record_id = "oversized-body";
        let body = "x".repeat(crate::body_blocks::MAX_PROJECTED_BODY_BYTES + 1);
        sqlx::query("INSERT INTO records(id,type,kind,name,body,created_at,updated_at) VALUES(?,'Document','note','oversized',?,datetime('now'),datetime('now'))")
            .bind(record_id).bind(&body).execute(&mut conn).await.unwrap();
        sqlx::query("INSERT INTO content_events(id,record_id,type,payload,causal_envelope_version,causal_status) VALUES('oversized-event',?,'record.created',?,1,'legacy_unknown')")
            .bind(record_id).bind(serde_json::json!({"body":body}).to_string()).execute(&mut conn).await.unwrap();
        revert_to_engine_75(&mut conn).await;
        sqlx::query("DROP TABLE body_blocks")
            .execute(&mut conn)
            .await
            .unwrap();
        sqlx::query("PRAGMA user_version=74")
            .execute(&mut conn)
            .await
            .unwrap();
        let step = EngineMigrationRegistry::production()
            .pending(74, 75)
            .unwrap()
            .pop()
            .unwrap();
        step.preflight(&mut conn).await.unwrap();
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut conn)
            .await
            .unwrap();
        let error = step.apply(&mut conn).await.unwrap_err();
        assert!(error.to_string().contains("16777216-byte"), "{error}");
        sqlx::query("ROLLBACK").execute(&mut conn).await.unwrap();
        let table: Option<String> = sqlx::query_scalar(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='body_blocks'",
        )
        .fetch_optional(&mut conn)
        .await
        .unwrap();
        assert_eq!(table, None);
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&mut conn)
            .await
            .unwrap();
        assert_eq!(version, 74);
    }

    /// The 73→74 edge adds the body-task-items projection with a deterministic
    /// current-body backfill: the migrated database validates at schema 74,
    /// `body_task_items` rows match the live fold row-for-row (all markers,
    /// checked/quoted/ordered rows stored; tombstoned records keep rows; empty
    /// and body-less records yield none), the reverted pre-image pins the
    /// released engine-73 shape, and content rebuild-and-diff proves replay
    /// convergence — including after a post-migration body fold.
    #[tokio::test]
    async fn engine_73_to_74_backfills_task_items() {
        type TaskItemRow = (String, i64, i64, String, i64, i64, i64, i64);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("task-items-edge.db");
        create_current_schema(&path).await;
        let db = crate::open_existing_database_at(&path).await.unwrap();
        let doc = |name: &str, body: serde_json::Value| {
            let mut fields = serde_json::json!({"type": "Document", "kind": "note", "name": name});
            if !body.is_null() {
                fields["body"] = body;
            }
            fields
        };
        let tasks = crate::store::create_record(
            &db,
            doc("tasks", "- [ ] dash\n* [ ] star\n+ [ ] plus".into()),
        )
        .await
        .unwrap();
        // A later event without body must not become the task rows' provenance.
        crate::store::update_record(&db, &tasks, serde_json::json!({"summary":"metadata only"}))
            .await
            .unwrap();
        let mixed = crate::store::create_record(
            &db,
            doc(
                "mixed",
                "- [x] done\n> - [ ] quoted\n```\n- [ ] fenced\n```\n1. [ ] ordered".into(),
            ),
        )
        .await
        .unwrap();
        let doomed = crate::store::create_record(&db, doc("doomed", "- [ ] doomed task".into()))
            .await
            .unwrap();
        // A tombstone keeps the record's task rows: deletion carries no body.
        crate::store::delete_record(&db, &doomed).await.unwrap();
        let empty = crate::store::create_record(&db, doc("empty", "".into()))
            .await
            .unwrap();
        let _plain = crate::store::create_record(
            &db,
            serde_json::json!({"type": "Document", "kind": "note", "name": "plain"}),
        )
        .await
        .unwrap();
        // Live fold's answer, captured before the revert destroys it.
        let expected: Vec<TaskItemRow> = sqlx::query_as(
            "SELECT record_id, item_index, source_event_seq, marker,
                    checked, in_quote, start_offset, end_offset
             FROM body_task_items ORDER BY record_id, item_index",
        )
        .fetch_all(db.write_pool())
        .await
        .unwrap();
        let rows_for = |id: &str| {
            expected
                .iter()
                .filter(|(row_id, _, _, _, _, _, _, _)| row_id == id)
                .count()
        };
        assert_eq!(rows_for(&tasks), 3);
        // done + quoted + ordered; the fenced line is not a task.
        assert_eq!(rows_for(&mixed), 3);
        // The tombstoned record keeps its row.
        assert_eq!(rows_for(&doomed), 1);
        assert_eq!(rows_for(&empty), 0);
        // Markers and flags stored exactly: dash/star/plus unchecked
        // unquoted, done checked, quoted flagged, ordered stored.
        let markers: Vec<(String, i64, i64)> = expected
            .iter()
            .filter(|(row_id, _, _, _, _, _, _, _)| row_id == &mixed)
            .map(|(_, _, _, marker, checked, in_quote, _, _)| (marker.clone(), *checked, *in_quote))
            .collect();
        assert!(markers.contains(&("ordered".to_string(), 0, 0)));
        assert!(markers.contains(&("-".to_string(), 1, 0)));
        assert!(markers.contains(&("-".to_string(), 0, 1)));
        db.close().await;

        // Reconstruct the engine-73 preimage, then run the real 73→74 edge.
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        revert_to_engine_75(&mut conn).await;
        sqlx::query("DROP TABLE body_blocks")
            .execute(&mut conn)
            .await
            .unwrap();
        sqlx::query("DROP TABLE body_task_items")
            .execute(&mut conn)
            .await
            .unwrap();
        sqlx::query("PRAGMA user_version=73")
            .execute(&mut conn)
            .await
            .unwrap();
        let digest = crate::db::schema_shape_contract_sha256_for_test(&mut conn)
            .await
            .unwrap();
        assert_eq!(digest, crate::db::ENGINE_73_SHAPE_CONTRACT_SHA256);
        let step = EngineMigrationRegistry::production()
            .pending(73, 74)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(step.name(), "engine-73-to-74-body-task-items");
        step.preflight(&mut conn).await.unwrap();
        step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version=74")
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(crate::db::validate_engine_shape_on_for_test(&mut conn, 74)
            .await
            .unwrap());
        // Backfill ran inside the edge: the migrated rows already match the
        // live fold before reopening.
        let migrated: Vec<TaskItemRow> = sqlx::query_as(
            "SELECT record_id, item_index, source_event_seq, marker,
                    checked, in_quote, start_offset, end_offset
             FROM body_task_items ORDER BY record_id, item_index",
        )
        .fetch_all(&mut conn)
        .await
        .unwrap();
        assert_eq!(migrated, expected);
        advance_engine_to_current(&mut conn, 74).await;
        conn.close().await.unwrap();

        let migrated = crate::open_existing_database_at(&path).await.unwrap();
        let result = crate::conformance::rebuild_and_diff(&migrated)
            .await
            .unwrap();
        assert!(
            result.equal,
            "rebuild drift after 73→74: {}",
            serde_json::to_string_pretty(&result.tables).unwrap()
        );
        // Ordinary body folds keep working on the migrated database: a body
        // replacement re-scans, and replay still converges afterwards.
        crate::store::update_record(&migrated, &tasks, serde_json::json!({"body": "- [ ] only"}))
            .await
            .unwrap();
        let after: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM body_task_items WHERE record_id = ?")
                .bind(&tasks)
                .fetch_one(migrated.write_pool())
                .await
                .unwrap();
        assert_eq!(after, 1);
        let replayed = crate::conformance::rebuild_and_diff(&migrated)
            .await
            .unwrap();
        assert!(
            replayed.equal,
            "replay drift after post-migration body fold: {}",
            serde_json::to_string_pretty(&replayed.tables).unwrap()
        );
        migrated.close().await;
    }
    /// The 64→65 DDL is frozen transition text: it creates the engine-65
    /// alpha-tab shape (two-value adoption CHECK, no request column), which
    /// the 71→72 edge later rebuilds. It matches fresh DDL with the pre-72
    /// rewrite applied — the same rewrite `historical()` uses for version <
    /// 72 — so migrated databases stay byte-identical to the engine-65 shape
    /// under the shape contract while fresh databases move on.
    #[test]
    fn engine_64_to_65_statements_match_engine_65_shape() {
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
            let expected =
                crate::schema::contract::alpha_tab_installs_create_for_version(fresh, 65);
            assert_eq!(
                expected, statement,
                "64→65 statement drifted from engine-65 shape"
            );
        }
    }

    /// The 71→72 DDL is frozen transition text matching the engine-72
    /// table shape, before successor edges add columns. Pragmas and data-copy statements have no fresh twin
    /// and are skipped; the table and index rebuilds are the contract.
    #[test]
    fn engine_71_to_72_statements_match_fresh_ddl() {
        let mut twins = 0;
        for statement in ENGINE_71_TO_72_STATEMENTS {
            let prefix = if statement.starts_with("CREATE TABLE alpha_tab_installs (") {
                "CREATE TABLE alpha_tab_installs ("
            } else if statement.starts_with("CREATE INDEX idx_alpha_tab_installs_artifact") {
                "CREATE INDEX idx_alpha_tab_installs_artifact"
            } else {
                continue;
            };
            let fresh = crate::schema::DDL_STATEMENTS
                .iter()
                .find(|candidate| candidate.starts_with(prefix))
                .unwrap_or_else(|| panic!("71→72 statement has no fresh-DDL twin: {prefix}"));
            let expected =
                crate::schema::contract::alpha_tab_installs_create_for_version(fresh, 72);
            assert_eq!(
                expected, statement,
                "71→72 statement drifted from engine-72 DDL"
            );
            twins += 1;
        }
        assert_eq!(twins, 2, "71→72 must twin exactly the table and its index");
    }

    /// The 71→72 edge rebuilds `alpha_tab_installs` in place: the adoption
    /// CHECK widens to `shell_auto.v1` and the nullable request column
    /// appears. A governed pre-72 install survives the rebuild with its pin
    /// and event token intact, the migrated database validates at schema 72,
    /// then advances to the current schema before replay and a fresh install
    /// with request text fold through the governed path.
    #[tokio::test]
    async fn engine_71_to_72_rebuilds_alpha_tab_installs_preserving_rows() {
        use crate::control::{
            alpha_tab_aggregate_id, append_control_event, AlphaTabStatePayload,
            ControlEventPayload, NewControlEvent,
        };

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("alpha-tab-71-72.db");
        create_current_schema(&path).await;
        let db = crate::open_existing_database_at(&path).await.unwrap();
        crate::store::create_record(
            &db,
            serde_json::json!({"id": "c07f0000-0000-4000-8000-000000000070",
                "type": "Document", "kind": "artifact", "name": "alpha-7172"}),
        )
        .await
        .unwrap();
        let installed = append_control_event(
            &db,
            NewControlEvent::authored(
                "alpha-install-7172",
                alpha_tab_aggregate_id("acct_alice", "agent.attention-cockpit"),
                "acct_alice",
                Some("run-7172".into()),
                "Pre-72 install without request text.",
                ControlEventPayload::AlphaTabInstalled(AlphaTabStatePayload {
                    account_id: "acct_alice".into(),
                    package: "agent.attention-cockpit".into(),
                    version: "0.1.0".into(),
                    digest: format!("sha256:{}", "a".repeat(64)),
                    artifact_id: "c07f0000-0000-4000-8000-000000000070".into(),
                    consented_source_revision: "rev-1".into(),
                    declaration_digest: "b".repeat(64),
                    consented_declaration: serde_json::json!({"needs": [], "effects": []}),
                    adoption: crate::control::ALPHA_TAB_ADOPTION_CALLER_ASSERTED.into(),
                    request: None,
                    previous_event_id: None,
                }),
            )
            .unwrap(),
        )
        .await
        .unwrap();
        db.close().await;

        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        revert_to_engine_71(&mut conn).await;
        assert!(crate::db::validate_engine_shape_on_for_test(&mut conn, 71)
            .await
            .unwrap());
        let step = EngineMigrationRegistry::production()
            .pending(71, 72)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(
            step.name(),
            "engine-71-to-72-alpha-tab-request-and-shell-auto"
        );
        step.preflight(&mut conn).await.unwrap();
        step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version=72")
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(crate::db::validate_engine_shape_on_for_test(&mut conn, 72)
            .await
            .unwrap());
        // The pin and event token survive; the pre-72 text is NULL.
        let row: (String, String, Option<String>, String) = sqlx::query_as(
            "SELECT adoption, status, request, event_id FROM alpha_tab_installs
              WHERE account_id='acct_alice' AND package='agent.attention-cockpit'",
        )
        .fetch_one(&mut conn)
        .await
        .unwrap();
        assert_eq!(
            row,
            (
                crate::control::ALPHA_TAB_ADOPTION_CALLER_ASSERTED.to_string(),
                "installed".to_string(),
                None,
                installed.id.clone(),
            )
        );
        // The rebuilt table text carries the widened CHECK; the row itself
        // is untouched above, so replay conformance below still holds.
        let table_sql: String =
            sqlx::query_scalar("SELECT sql FROM sqlite_master WHERE name='alpha_tab_installs'")
                .fetch_one(&mut conn)
                .await
                .unwrap();
        assert!(
            table_sql.contains("adoption IN ('caller_asserted','shell_adopt.v1','shell_auto.v1')"),
            "migrated table lacks the widened adoption CHECK: {table_sql}",
        );
        // Serving requires the current schema. Keep the historical v72 shape
        // and row assertions above, then apply the real next edge before
        // opening this file through the runtime for replay/write checks.
        let next = EngineMigrationRegistry::production()
            .pending(72, 73)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(next.name(), "engine-72-to-73-currency-counts");
        next.preflight(&mut conn).await.unwrap();
        next.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version=73")
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(crate::db::validate_engine_shape_on_for_test(&mut conn, 73)
            .await
            .unwrap());
        let next = EngineMigrationRegistry::production()
            .pending(73, 74)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(next.name(), "engine-73-to-74-body-task-items");
        next.preflight(&mut conn).await.unwrap();
        next.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version=74")
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(crate::db::validate_engine_shape_on_for_test(&mut conn, 74)
            .await
            .unwrap());
        advance_engine_to_current(&mut conn, 74).await;
        conn.close().await.unwrap();

        // The migrated database is fully live with replay conformance
        // intact, and a fresh install with request text folds through the
        // governed path with the text stored.
        let migrated = crate::open_existing_database_at(&path).await.unwrap();
        let result = crate::conformance::rebuild_and_diff_control(&migrated)
            .await
            .unwrap();
        assert!(
            result.equal,
            "rebuild drift after 71→72: {}",
            serde_json::to_string_pretty(&result.tables).unwrap()
        );
        let live = append_control_event(
            &migrated,
            NewControlEvent::authored(
                "alpha-install-7172-live",
                alpha_tab_aggregate_id("acct_alice", "agent.second-cockpit"),
                "acct_alice",
                Some("run-7172".into()),
                "Install with request text on the migrated shape.",
                ControlEventPayload::AlphaTabInstalled(AlphaTabStatePayload {
                    account_id: "acct_alice".into(),
                    package: "agent.second-cockpit".into(),
                    version: "0.1.0".into(),
                    digest: format!("sha256:{}", "a".repeat(64)),
                    artifact_id: "c07f0000-0000-4000-8000-000000000070".into(),
                    consented_source_revision: "rev-1".into(),
                    declaration_digest: "b".repeat(64),
                    consented_declaration: serde_json::json!({"needs": [], "effects": []}),
                    adoption: crate::control::ALPHA_TAB_ADOPTION_CALLER_ASSERTED.into(),
                    request: Some("make it green".into()),
                    previous_event_id: None,
                }),
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let live_request: Option<String> = sqlx::query_scalar(
            "SELECT request FROM alpha_tab_installs
              WHERE account_id='acct_alice' AND package='agent.second-cockpit'",
        )
        .fetch_one(migrated.write_pool())
        .await
        .unwrap();
        assert_eq!(
            live_request.as_deref(),
            Some("make it green"),
            "request text folds on the migrated shape (event {})",
            live.id,
        );
        migrated.close().await;
    }

    /// The 72→73 ADD COLUMNs are transition text, but the columns they add
    /// must stay token-identical to the fresh-schema records definition:
    /// migrated databases converge with fresh ones under the shape contract
    /// only while both spellings agree. The backfill UPDATEs have no
    /// fresh-DDL twin by construction (fresh databases fold currency from
    /// the log).
    #[test]
    fn engine_72_to_73_statements_match_fresh_ddl() {
        assert_eq!(ENGINE_72_TO_73_STATEMENTS.len(), 4);
        let fresh = crate::schema::DDL_STATEMENTS
            .iter()
            .find(|candidate| candidate.starts_with("CREATE TABLE records ("))
            .expect("fresh DDL contains records");
        // Token-identical after schema normalization (whitespace/comments
        // stripped): the migrated rewrite must spell the columns like fresh.
        let normalize = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
        let columns = [
            "is_current INTEGER NULL DEFAULT 1 CHECK (is_current IS NULL OR is_current IN (0,1))",
            "successor_count INTEGER NOT NULL DEFAULT 0 CHECK (successor_count >= 0)",
        ];
        for (add, column_def) in [
            (&ENGINE_72_TO_73_STATEMENTS[0], columns[0]),
            (&ENGINE_72_TO_73_STATEMENTS[1], columns[1]),
        ] {
            assert!(
                add.starts_with("ALTER TABLE records ADD COLUMN "),
                "72→73 DDL statement must add a records column: {add}"
            );
            assert!(
                normalize(fresh).contains(&normalize(column_def)),
                "fresh records DDL must carry the currency column: {column_def}"
            );
            assert!(
                normalize(add).contains(&normalize(column_def)),
                "72→73 ADD COLUMN drifted from fresh DDL: {add}"
            );
        }
        assert!(
            ENGINE_72_TO_73_STATEMENTS[2].contains("relationship='supersedes'")
                && ENGINE_72_TO_73_STATEMENTS[2].contains("s.deleted_at IS NULL"),
            "72→73 count backfill must count live incoming supersedes only"
        );
        assert!(
            ENGINE_72_TO_73_STATEMENTS[3].contains("is_current=NULL")
                && ENGINE_72_TO_73_STATEMENTS[3].contains("successor_count>0"),
            "72→73 tri-state backfill must null is_current exactly where counted"
        );
    }

    /// The 72→73 edge adds caller-independent `records.is_current` /
    /// `records.successor_count` with a deterministic live-incoming backfill:
    /// the migrated database validates at schema 73, the columns match the
    /// live fold row-for-row (tombstoned successor excluded, unrelated
    /// relationship ignored, archived orthogonal, reserved 0 absent), the
    /// reverted pre-image pins the released engine-72 shape, and content
    /// rebuild-and-diff proves replay convergence.
    #[tokio::test]
    async fn engine_72_to_73_backfills_currency_counts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("currency-counts-edge.db");
        create_current_schema(&path).await;
        let db = crate::open_existing_database_at(&path).await.unwrap();
        let target = crate::store::create_record(
            &db,
            serde_json::json!({"type": "Document", "kind": "note", "name": "target"}),
        )
        .await
        .unwrap();
        let successor = crate::store::create_record(
            &db,
            serde_json::json!({"type": "Document", "kind": "note", "name": "successor"}),
        )
        .await
        .unwrap();
        let tombstoned = crate::store::create_record(
            &db,
            serde_json::json!({"type": "Document", "kind": "note", "name": "tombstoned"}),
        )
        .await
        .unwrap();
        let unrelated = crate::store::create_record(
            &db,
            serde_json::json!({"type": "Document", "kind": "note", "name": "unrelated"}),
        )
        .await
        .unwrap();
        let link = |source: &str, relationship: &str| crate::events::LinkAddedPayload {
            id: None,
            source_id: source.to_string(),
            target_id: target.clone(),
            relationship: relationship.to_string(),
            note: None,
        };
        crate::store::add_link(&db, link(&successor, "supersedes"))
            .await
            .unwrap();
        crate::store::add_link(&db, link(&tombstoned, "supersedes"))
            .await
            .unwrap();
        crate::store::delete_record(&db, &tombstoned).await.unwrap();
        crate::store::add_link(&db, link(&unrelated, "relates_to"))
            .await
            .unwrap();
        // Archived stays orthogonal: the target carries archived=1 while its
        // currency still reflects the one live incoming successor.
        crate::store::archive_record(&db, &target).await.unwrap();
        // Live fold's answer, captured before the revert destroys it.
        let expected: Vec<(String, Option<i64>, i64, i64)> = sqlx::query_as(
            "SELECT id, is_current, successor_count, archived FROM records
              WHERE id IN (?, ?, ?, ?) ORDER BY id",
        )
        .bind(&target)
        .bind(&successor)
        .bind(&tombstoned)
        .bind(&unrelated)
        .fetch_all(db.write_pool())
        .await
        .unwrap();
        assert_eq!(expected.len(), 4);
        let row = |id: &str| {
            expected
                .iter()
                .find(|(row_id, _, _, _)| row_id == id)
                .map(|(_, current, count, archived)| (*current, *count, *archived))
                .unwrap()
        };
        assert_eq!(row(&target), (None, 1, 1));
        assert_eq!(row(&successor), (Some(1), 0, 0));
        assert_eq!(row(&tombstoned), (Some(1), 0, 0));
        assert_eq!(row(&unrelated), (Some(1), 0, 0));
        let reserved: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records WHERE is_current=0")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(reserved, 0);
        db.close().await;

        // Reconstruct the engine-72 preimage, then run the real 72→73 edge.
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        revert_to_engine_72(&mut conn).await;
        let digest = crate::db::schema_shape_contract_sha256_for_test(&mut conn)
            .await
            .unwrap();
        assert_eq!(digest, crate::db::ENGINE_72_SHAPE_CONTRACT_SHA256);
        let step = EngineMigrationRegistry::production()
            .pending(72, 73)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(step.name(), "engine-72-to-73-currency-counts");
        step.preflight(&mut conn).await.unwrap();
        step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version=73")
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(crate::db::validate_engine_shape_on_for_test(&mut conn, 73)
            .await
            .unwrap());
        // Backfill ran inside the edge: the migrated columns already match
        // the live fold before reopening.
        let migrated: Vec<(String, Option<i64>, i64, i64)> = sqlx::query_as(
            "SELECT id, is_current, successor_count, archived FROM records
              WHERE id IN (?, ?, ?, ?) ORDER BY id",
        )
        .bind(&target)
        .bind(&successor)
        .bind(&tombstoned)
        .bind(&unrelated)
        .fetch_all(&mut conn)
        .await
        .unwrap();
        assert_eq!(migrated, expected);

        // Preserve the v73 backfill assertions above, then reach the current
        // schema through the next production edge before reopening.
        let next = EngineMigrationRegistry::production()
            .pending(73, 74)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(next.name(), "engine-73-to-74-body-task-items");
        next.preflight(&mut conn).await.unwrap();
        next.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version=74")
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(crate::db::validate_engine_shape_on_for_test(&mut conn, 74)
            .await
            .unwrap());
        advance_engine_to_current(&mut conn, 74).await;
        conn.close().await.unwrap();

        // The migrated database now opens for replay conformance.
        let migrated = crate::open_existing_database_at(&path).await.unwrap();
        let result = crate::conformance::rebuild_and_diff(&migrated)
            .await
            .unwrap();
        assert!(
            result.equal,
            "rebuild drift after 72→73: {}",
            serde_json::to_string_pretty(&result.tables).unwrap()
        );
        migrated.close().await;
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
        // The edge under test ends at 65, but the binary is at 72: continue
        // through the grant-revision, archived-projection, and tab-order
        // edges so the final open sees current.
        let grant_step = EngineMigrationRegistry::production()
            .pending(65, 66)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(
            grant_step.name(),
            "engine-65-to-66-grant-only-realtime-authorization-revision"
        );
        grant_step.preflight(&mut conn).await.unwrap();
        grant_step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version=66")
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(crate::db::validate_engine_shape_on_for_test(&mut conn, 66)
            .await
            .unwrap());
        apply_remaining_production_steps(&mut conn, 66).await;
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

    /// The 67→68 DDL is transition text, but the object it creates must stay
    /// byte-identical to the fresh-schema DDL: migrated databases are
    /// byte-identical to fresh ones under the shape contract only while both
    /// spellings agree.
    #[test]
    fn engine_67_to_68_statements_match_fresh_ddl() {
        assert_eq!(ENGINE_67_TO_68_STATEMENTS.len(), 1);
        for statement in ENGINE_67_TO_68_STATEMENTS {
            let prefix = "CREATE TABLE alpha_tab_orders";
            assert!(
                statement.starts_with(prefix),
                "unexpected 67→68 statement: {statement}"
            );
            let fresh = crate::schema::DDL_STATEMENTS
                .iter()
                .find(|candidate| candidate.starts_with(prefix))
                .unwrap_or_else(|| panic!("67→68 statement has no fresh-DDL twin: {prefix}"));
            assert_eq!(*fresh, statement, "67→68 statement drifted from fresh DDL");
        }
    }

    /// The 67→68 edge adds the empty `alpha_tab_orders` preference: the
    /// migrated database validates at schema 68, the table starts empty, and
    /// ordinary control writes keep folding on the migrated database.
    #[tokio::test]
    async fn engine_67_to_68_adds_empty_alpha_tab_orders() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("alpha-tab-orders-edge.db");
        create_current_schema(&path).await;
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        revert_to_engine_67(&mut conn).await;
        let digest = crate::db::schema_shape_contract_sha256_for_test(&mut conn)
            .await
            .unwrap();
        assert_eq!(digest, crate::db::ENGINE_67_SHAPE_CONTRACT_SHA256);
        let step = EngineMigrationRegistry::production()
            .pending(67, 68)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(step.name(), "engine-67-to-68-alpha-tab-orders");
        step.preflight(&mut conn).await.unwrap();
        step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version=68")
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(crate::db::validate_engine_shape_on_for_test(&mut conn, 68)
            .await
            .unwrap());
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM alpha_tab_orders")
            .fetch_one(&mut conn)
            .await
            .unwrap();
        assert_eq!(rows, 0);
        // The edge under test ends at 68, but the binary is at 72: continue
        // through the claim-meta edge so the final open sees current.
        let claim_step = EngineMigrationRegistry::production()
            .pending(68, 69)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(
            claim_step.name(),
            "engine-68-to-69-content-event-claim-meta"
        );
        claim_step.preflight(&mut conn).await.unwrap();
        claim_step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version=69")
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(crate::db::validate_engine_shape_on_for_test(&mut conn, 69)
            .await
            .unwrap());
        continue_from_engine_69(&mut conn).await;
        conn.close().await.unwrap();

        let migrated = crate::open_existing_database_at(&path).await.unwrap();
        let result = crate::conformance::rebuild_and_diff_control(&migrated)
            .await
            .unwrap();
        assert!(
            result.equal,
            "rebuild drift after 67→68: {}",
            serde_json::to_string_pretty(&result.tables).unwrap()
        );
        migrated.close().await;
    }

    /// The 68→69 DDL is transition text, but the table and trigger it creates
    /// must stay byte-identical to the fresh-schema DDL: migrated databases
    /// are byte-identical to fresh ones under the shape contract only while
    /// both spellings agree. The backfill SELECT has no fresh twin.
    #[test]
    fn engine_68_to_69_statements_match_fresh_ddl() {
        assert_eq!(ENGINE_68_TO_69_STATEMENTS.len(), 3);
        for statement in ENGINE_68_TO_69_STATEMENTS {
            let prefix = if statement.starts_with("CREATE TABLE content_event_claim_meta (") {
                "CREATE TABLE content_event_claim_meta ("
            } else if statement.starts_with("CREATE TRIGGER content_event_claim_meta_insert") {
                "CREATE TRIGGER content_event_claim_meta_insert"
            } else if statement.starts_with("INSERT INTO content_event_claim_meta") {
                continue;
            } else {
                panic!("unexpected 68→69 statement: {statement}");
            };
            let fresh = crate::schema::DDL_STATEMENTS
                .iter()
                .find(|candidate| candidate.starts_with(prefix))
                .unwrap_or_else(|| panic!("68→69 statement has no fresh-DDL twin: {prefix}"));
            assert_eq!(*fresh, statement, "68→69 statement drifted from fresh DDL");
        }
    }

    /// The 68→69 edge classifies every legacy row, of every event type,
    /// without touching the log: the migrated database validates at schema
    /// 69, an over-ceiling legacy payload backfills, and the governed
    /// readers disclose the backfilled run lineage past the ceiling. Raw
    /// fixture rows skip the live projector by construction, so replay
    /// conformance stays out of this test: the governed-writes twin below
    /// proves replay convergence on projectable fixtures instead.
    /// NULL/malformed legacy payloads are covered by the dedicated backfill
    /// and trigger tests below: they cannot project, so they stay out of
    /// every rebuild-covered fixture set.
    #[tokio::test]
    async fn engine_68_to_69_claim_meta_backfills_all_shapes_and_discloses_after_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("claim-meta-edge.db");
        create_current_schema(&path).await;
        // Base records through the real store path, so every rebuilt event
        // projects (raw `record.created` rows would need a valid home and
        // policy anchor by hand).
        let db = crate::open_existing_database_at(&path).await.unwrap();
        let rec_plain = crate::store::create_record(
            &db,
            serde_json::json!({"type": "Document", "kind": "note", "name": "plain"}),
        )
        .await
        .unwrap();
        let rec_claimed = crate::store::create_record(
            &db,
            serde_json::json!({"type": "Document", "kind": "note", "name": "claimed"}),
        )
        .await
        .unwrap();
        let home_id: String = sqlx::query_scalar("SELECT home_id FROM records WHERE id = ?")
            .bind(&rec_plain)
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        db.close().await;

        // Legacy history, written while the trigger did not exist.
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        revert_to_engine_68(&mut conn).await;
        let digest = crate::db::schema_shape_contract_sha256_for_test(&mut conn)
            .await
            .unwrap();
        assert_eq!(digest, crate::db::ENGINE_68_SHAPE_CONTRACT_SHA256);

        async fn insert_event(
            conn: &mut SqliteConnection,
            id: &str,
            record_id: &str,
            event_type: &str,
            payload: &str,
        ) {
            insert_stamped_event(conn, id, record_id, event_type, payload, None, None).await;
        }

        async fn insert_stamped_event(
            conn: &mut SqliteConnection,
            id: &str,
            record_id: &str,
            event_type: &str,
            payload: &str,
            run_key: Option<&str>,
            parent_key: Option<&str>,
        ) {
            sqlx::query(
                "INSERT INTO content_events(id, record_id, type, payload, actor, run_key, parent_key, created_at, causal_envelope_version, causal_status)
                 VALUES (?, ?, ?, ?, 'alice', ?, ?, '2026-01-01T00:00:00.000Z', 1, 'legacy_unknown')",
            )
            .bind(id)
            .bind(record_id)
            .bind(event_type)
            .bind(payload)
            .bind(run_key)
            .bind(parent_key)
            .execute(&mut *conn)
            .await
            .unwrap();
        }

        // A non-`record.updated` claim shape: the fold ignores the claim
        // keys on creation, but the classifier still marks presence.
        let created_claim = serde_json::json!({
            "type": "Document",
            "kind": "note",
            "name": "created-claimed",
            "home_id": home_id,
            "claimed_by_account": "alice",
            "claimed_run_key": "run-a",
        })
        .to_string();
        insert_event(
            &mut conn,
            "evt-claim-created",
            "rec-created-claimed",
            "record.created",
            &created_claim,
        )
        .await;
        insert_event(
            &mut conn,
            "evt-claim",
            &rec_claimed,
            "record.updated",
            r#"{"claimed_by_account":"alice","claimed_run_key":"run-a"}"#,
        )
        .await;
        insert_event(
            &mut conn,
            "evt-release",
            &rec_claimed,
            "record.updated",
            r#"{"claimed_by_account":null,"claimed_run_key":null}"#,
        )
        .await;
        insert_event(
            &mut conn,
            "evt-takeover",
            &rec_claimed,
            "record.updated",
            r#"{"claimed_by_account":null,"claimed_run_key":null,"released_from_run_key":"run-a"}"#,
        )
        .await;
        insert_event(
            &mut conn,
            "evt-null-key",
            &rec_plain,
            "record.updated",
            r#"{"claimed_by_account":"alice","claimed_run_key":null}"#,
        )
        .await;
        insert_event(
            &mut conn,
            "evt-plain-updated",
            &rec_plain,
            "record.updated",
            r#"{"summary":"touched"}"#,
        )
        .await;
        // Over-ceiling legacy payload: the backfill runs at full write
        // limits, so this classifies where the lowered read ceiling fails.
        let big_body = "x".repeat(300_000);
        let big_payload = serde_json::json!({
            "body": big_body,
            "claimed_by_account": "alice",
            "claimed_run_key": "run-a",
        })
        .to_string();
        assert!(
            big_payload.len() > 256 * 1024,
            "fixture must exceed the read ceiling"
        );
        // Stamp the envelope columns the disclosure proof needs: the run
        // lineage a governed agent write stamps alongside the payload.
        insert_stamped_event(
            &mut conn,
            "evt-big-claim",
            &rec_plain,
            "record.updated",
            &big_payload,
            Some("run-a"),
            Some("run-a"),
        )
        .await;

        let step = EngineMigrationRegistry::production()
            .pending(68, 69)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(step.name(), "engine-68-to-69-content-event-claim-meta");
        step.preflight(&mut conn).await.unwrap();
        step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version=69")
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(crate::db::validate_engine_shape_on_for_test(&mut conn, 69)
            .await
            .unwrap());
        continue_from_engine_69(&mut conn).await;

        // (has_claimed_by, has_claimed_run, has_released_from, claim_class).
        async fn meta_for(conn: &mut SqliteConnection, id: &str) -> (i64, i64, i64, String) {
            sqlx::query_as(
                "SELECT m.has_claimed_by, m.has_claimed_run, m.has_released_from, m.claim_class
                   FROM content_event_claim_meta m
                   JOIN content_events e ON e.seq = m.event_seq
                  WHERE e.id = ?",
            )
            .bind(id)
            .fetch_one(&mut *conn)
            .await
            .unwrap()
        }
        assert_eq!(
            meta_for(&mut conn, "evt-claim-created").await,
            (1, 1, 0, "claim".into())
        );
        assert_eq!(
            meta_for(&mut conn, "evt-claim").await,
            (1, 1, 0, "claim".into())
        );
        assert_eq!(
            meta_for(&mut conn, "evt-release").await,
            (1, 1, 0, "release".into())
        );
        assert_eq!(
            meta_for(&mut conn, "evt-takeover").await,
            (1, 1, 1, "release".into())
        );
        // Run-less claim: an explicit JSON null still counts as present for
        // the bit, but the strict pair rule leaves the class `other`.
        assert_eq!(
            meta_for(&mut conn, "evt-null-key").await,
            (1, 1, 0, "other".into())
        );
        assert_eq!(
            meta_for(&mut conn, "evt-plain-updated").await,
            (0, 0, 0, "other".into())
        );
        assert_eq!(
            meta_for(&mut conn, "evt-big-claim").await,
            (1, 1, 0, "claim".into())
        );
        let meta_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_event_claim_meta")
            .fetch_one(&mut conn)
            .await
            .unwrap();
        let event_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(&mut conn)
            .await
            .unwrap();
        assert_eq!(
            meta_rows, event_rows,
            "backfill must cover every legacy row"
        );

        // Post-migration inserts classify through the trigger, including a
        // non-`record.updated` type the old view predicates also covered.
        insert_event(
            &mut conn,
            "evt-live-claim",
            &rec_plain,
            "record.updated",
            r#"{"claimed_by_account":"bea","claimed_run_key":"run-b"}"#,
        )
        .await;
        assert_eq!(
            meta_for(&mut conn, "evt-live-claim").await,
            (1, 1, 0, "claim".into())
        );

        // The log stays append-only: the edge adds a trigger but never an
        // exception to the no-update/no-delete pair.
        assert!(
            sqlx::query("UPDATE content_events SET payload='{}' WHERE id='evt-claim'")
                .execute(&mut conn)
                .await
                .is_err()
        );
        assert!(
            sqlx::query("DELETE FROM content_events WHERE id='evt-claim'")
                .execute(&mut conn)
                .await
                .is_err()
        );
        conn.close().await.unwrap();

        let migrated = crate::open_existing_database_at(&path).await.unwrap();
        // The governed readers use the backfilled metadata past the
        // ceiling: the holder-actor sees the stamped run lineage on the
        // legacy oversized claim row, while a disclosable non-holder sees
        // the row with its run hidden.
        crate::authorization::replace_explicit_policy(
            &migrated,
            "test:claim-meta",
            &rec_plain,
            vec![
                crate::authorization::AllowEntry::account(
                    "alice",
                    crate::authorization::Capability::View,
                ),
                crate::authorization::AllowEntry::account(
                    "bea",
                    crate::authorization::Capability::View,
                ),
            ],
        )
        .await
        .unwrap();
        let alice = crate::query::QueryPrincipal::authenticated("alice", true);
        let disclosed = crate::query::sql::query_sql(
            &migrated,
            alice,
            &format!(
                "SELECT id, run_key, parent_key FROM content_events
                  WHERE record_id = '{rec_plain}' AND run_key = 'run-a' ORDER BY local_seq"
            ),
        )
        .await
        .unwrap();
        assert_eq!(disclosed.row_count, 1);
        assert_eq!(disclosed.rows[0]["id"].as_str().unwrap(), "evt-big-claim");
        assert_eq!(disclosed.rows[0]["run_key"].as_str().unwrap(), "run-a");
        assert_eq!(disclosed.rows[0]["parent_key"].as_str().unwrap(), "run-a");
        let bea = crate::query::QueryPrincipal::authenticated("bea", true);
        let hidden = crate::query::sql::query_sql(
            &migrated,
            bea,
            "SELECT id, actor, run_key, parent_key FROM content_events
              WHERE id = 'evt-big-claim'",
        )
        .await
        .unwrap();
        assert_eq!(hidden.row_count, 1);
        assert_eq!(hidden.rows[0]["run_key"], serde_json::Value::Null);
        assert_eq!(hidden.rows[0]["parent_key"], serde_json::Value::Null);
        migrated.close().await;
    }

    /// The live trigger classifies governed writes at insert time — which
    /// backfill alone cannot prove — and replay regenerates the side table
    /// from the log. Every fixture here passes admission and projects, so
    /// the live fold and the replay fold converge exactly, including the
    /// over-ceiling plain rows and the start_work-owned claim cycle.
    #[tokio::test]
    async fn engine_68_to_69_claim_meta_governed_writes_converge_on_replay() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("claim-meta-governed.db");
        create_current_schema(&path).await;
        let migrated = crate::open_existing_database_at(&path).await.unwrap();
        let rec_plain = crate::store::create_record(
            &migrated,
            serde_json::json!({"type": "Document", "kind": "note", "name": "plain"}),
        )
        .await
        .unwrap();
        let rec_claimed = crate::store::create_record(
            &migrated,
            serde_json::json!({"type": "Document", "kind": "note", "name": "claimed"}),
        )
        .await
        .unwrap();
        let home_id: String = sqlx::query_scalar("SELECT home_id FROM records WHERE id = ?")
            .bind(&rec_plain)
            .fetch_one(migrated.write_pool())
            .await
            .unwrap();
        crate::authorization::replace_explicit_policy(
            &migrated,
            "test:claim-meta-governed",
            &rec_claimed,
            vec![crate::authorization::AllowEntry::account(
                "alice",
                crate::authorization::Capability::Edit,
            )],
        )
        .await
        .unwrap();
        let mut registry = crate::mcp::ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut registry).unwrap();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        let claim = |record_id: &str, action: &str, run_key: &str| {
            serde_json::json!({
                "record_id": record_id,
                "action": action,
                "run_key": run_key,
            })
        };
        let release = |record_id: &str, run_key: &str, expected_holder_run_key: Option<&str>| {
            let mut args = serde_json::json!({
                "record_id": record_id,
                "action": "release",
                "run_key": run_key,
            });
            if let Some(expected) = expected_holder_run_key {
                args["expected_holder_run_key"] = serde_json::Value::String(expected.into());
            }
            args
        };
        let alice_caller = || crate::mcp::Caller::authenticated("alice");
        // Claim, release, reclaim, then a same-account takeover release:
        // the mined classes must read claim, release, claim, release with
        // the takeover carrying its released_from marker. Run keys in tool
        // arguments pass format validation, so they use real handle-word
        // shapes rather than the bare tokens the raw fixtures use.
        registry
            .call(
                migrated.clone(),
                alice_caller(),
                "start_work",
                claim(&rec_claimed, "claim", "scout-chair-c748b2"),
            )
            .await
            .unwrap();
        registry
            .call(
                migrated.clone(),
                alice_caller(),
                "start_work",
                release(&rec_claimed, "scout-chair-c748b2", None),
            )
            .await
            .unwrap();
        registry
            .call(
                migrated.clone(),
                alice_caller(),
                "start_work",
                claim(&rec_claimed, "claim", "scout-chair-c748b2"),
            )
            .await
            .unwrap();
        registry
            .call(
                migrated.clone(),
                alice_caller(),
                "start_work",
                release(
                    &rec_claimed,
                    "scout-chair-d748b2",
                    Some("scout-chair-c748b2"),
                ),
            )
            .await
            .unwrap();
        // Governed plain updates, one of them over the ceiling with run
        // stamps mirroring an agent tool dispatch.
        crate::store::update_record(
            &migrated,
            &rec_plain,
            serde_json::json!({"summary": "touched"}),
        )
        .await
        .unwrap();
        let live_big_body = "y".repeat(300_000);
        assert!(live_big_body.len() > 256 * 1024);
        let live_updated = crate::store::with_event_annotations(
            crate::store::EventAnnotations {
                run_key: Some("scout-chair-c748b2".into()),
                parent_key: Some("scout-chair-c748b2".into()),
                intent: None,
            },
            crate::store::append(
                &migrated,
                crate::store::AppendSpec {
                    record_id: rec_plain.clone(),
                    event_type: "record.updated".into(),
                    payload: serde_json::json!({ "body": live_big_body }),
                    actor: Some("alice".into()),
                },
            ),
        )
        .await
        .unwrap();
        let live_created = crate::store::with_event_annotations(
            crate::store::EventAnnotations {
                run_key: Some("scout-chair-c748b2".into()),
                parent_key: Some("scout-chair-c748b2".into()),
                intent: None,
            },
            crate::store::create_record_as(
                &migrated,
                serde_json::json!({
                    "type": "Document",
                    "kind": "note",
                    "name": "live-big",
                    "home_id": home_id,
                    "body": "z".repeat(300_000),
                }),
                Some("alice"),
            ),
        )
        .await
        .unwrap();
        // The trigger classified every governed write at insert time.
        let mut live_conn = migrated.write_pool().acquire().await.unwrap();
        let claim_cycle: Vec<(i64, i64, i64, String)> = sqlx::query_as(
            "SELECT m.has_claimed_by, m.has_claimed_run, m.has_released_from, m.claim_class
               FROM content_event_claim_meta m
               JOIN content_events e ON e.seq = m.event_seq
              WHERE e.record_id = ? AND e.type = 'record.updated'
              ORDER BY e.seq",
        )
        .bind(&rec_claimed)
        .fetch_all(&mut *live_conn)
        .await
        .unwrap();
        assert_eq!(
            claim_cycle,
            vec![
                (1, 1, 0, "claim".to_string()),
                (1, 1, 0, "release".to_string()),
                (1, 1, 0, "claim".to_string()),
                (1, 1, 1, "release".to_string()),
            ]
        );
        let live_update_meta: (i64, i64, i64, String) = sqlx::query_as(
            "SELECT m.has_claimed_by, m.has_claimed_run, m.has_released_from, m.claim_class
               FROM content_event_claim_meta m
              WHERE m.event_seq = ?",
        )
        .bind(live_updated.local_seq)
        .fetch_one(&mut *live_conn)
        .await
        .unwrap();
        assert_eq!(live_update_meta, (0, 0, 0, "other".to_string()));
        drop(live_conn);

        // Run disclosure works on the live oversized row past the ceiling.
        crate::authorization::replace_explicit_policy(
            &migrated,
            "test:claim-meta-governed",
            &rec_plain,
            vec![crate::authorization::AllowEntry::account(
                "alice",
                crate::authorization::Capability::View,
            )],
        )
        .await
        .unwrap();
        let alice = crate::query::QueryPrincipal::authenticated("alice", true);
        let disclosed = crate::query::sql::query_sql(
            &migrated,
            alice,
            &format!(
                "SELECT id, run_key, parent_key FROM content_events
                  WHERE record_id = '{rec_plain}' AND run_key = 'scout-chair-c748b2' ORDER BY local_seq"
            ),
        )
        .await
        .unwrap();
        assert_eq!(disclosed.row_count, 1);
        assert_eq!(
            disclosed.rows[0]["id"].as_str().unwrap(),
            live_updated.id.as_str()
        );
        assert_eq!(
            disclosed.rows[0]["run_key"].as_str().unwrap(),
            "scout-chair-c748b2"
        );
        assert_eq!(
            disclosed.rows[0]["parent_key"].as_str().unwrap(),
            "scout-chair-c748b2"
        );
        let _ = live_created;
        let result = crate::conformance::rebuild_and_diff(&migrated)
            .await
            .unwrap();
        assert!(
            result.equal,
            "rebuild drift after governed 68→69 writes: {}",
            serde_json::to_string_pretty(&result.tables).unwrap()
        );
        migrated.close().await;
    }

    /// The claim trigger never invents claim shape and never fails a valid
    /// write: SQL NULL and valid non-object payloads classify as all-absent
    /// `other` because `->` yields NULL there, while a malformed payload
    /// aborts the insert (`->` raises). Governed admission always serializes
    /// a JSON object (see `ProjectorIntent::from_event`, which rejects
    /// missing/unparseable payloads), so no supported path can hit the
    /// abort; raw SQL is the only way to reach it, and failing loudly beats
    /// storing a row the projector must refuse. No rebuild runs here: NULL
    /// payloads cannot project by design.
    #[tokio::test]
    async fn claim_meta_trigger_marks_null_as_other_and_refuses_malformed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("claim-meta-malformed.db");
        create_current_schema(&path).await;
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();

        for (id, payload) in [
            ("evt-null-payload", None::<&str>),
            ("evt-json-array", Some("[1,2]")),
            ("evt-json-number", Some("5")),
            ("evt-json-null", Some("null")),
            ("evt-unrelated-object", Some(r#"{"body":"hi"}"#)),
        ] {
            sqlx::query(
                "INSERT INTO content_events(id, record_id, type, payload, actor, created_at, causal_envelope_version, causal_status)
                 VALUES (?, 'rec-x', 'record.updated', ?, 'alice', '2026-01-01T00:00:00.000Z', 1, 'legacy_unknown')",
            )
            .bind(id)
            .bind(payload)
            .execute(&mut conn)
            .await
            .unwrap();
            let row: (i64, i64, i64, String) = sqlx::query_as(
                "SELECT m.has_claimed_by, m.has_claimed_run, m.has_released_from, m.claim_class
                   FROM content_event_claim_meta m
                   JOIN content_events e ON e.seq = m.event_seq
                  WHERE e.id = ?",
            )
            .bind(id)
            .fetch_one(&mut conn)
            .await
            .unwrap();
            assert_eq!(row, (0, 0, 0, "other".to_string()), "wrong class for {id}");
        }
        // Malformed JSON fails the insert rather than storing an
        // unclassifiable row.
        assert!(sqlx::query(
            "INSERT INTO content_events(id, record_id, type, payload, actor, created_at, causal_envelope_version, causal_status)
             VALUES ('evt-bad-json', 'rec-x', 'record.updated', 'not json', 'alice', '2026-01-01T00:00:00.000Z', 1, 'legacy_unknown')",
        )
        .execute(&mut conn)
        .await
        .is_err());
        conn.close().await.unwrap();
    }

    /// The 68→69 backfill tolerates legacy oddities the trigger refuses:
    /// malformed and NULL payloads predate the trigger and classify `other`
    /// instead of bricking the migration. No rebuild runs here: such rows
    /// cannot project by design, so replay conformance stays on the main
    /// 68→69 test's projectable fixtures.
    #[tokio::test]
    async fn engine_68_to_69_claim_meta_backfill_marks_legacy_malformed_as_other() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("claim-meta-legacy-malformed.db");
        create_current_schema(&path).await;
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        revert_to_engine_68(&mut conn).await;
        for (id, payload) in [
            ("evt-legacy-bad", Some("not json")),
            ("evt-legacy-half", Some("{bad")),
            ("evt-legacy-null", None::<&str>),
            // Single-key shapes: presence per key, class `other` outside the
            // strict pair rule. (The projector's pair rule would reject these
            // on replay, which is why they live in this non-rebuild test.)
            (
                "evt-legacy-single-null",
                Some(r#"{"claimed_by_account":null}"#),
            ),
            (
                "evt-legacy-single-run",
                Some(r#"{"claimed_run_key":"run-a"}"#),
            ),
        ] {
            sqlx::query(
                "INSERT INTO content_events(id, record_id, type, payload, actor, created_at, causal_envelope_version, causal_status)
                 VALUES (?, 'rec-x', 'record.updated', ?, 'alice', '2026-01-01T00:00:00.000Z', 1, 'legacy_unknown')",
            )
            .bind(id)
            .bind(payload)
            .execute(&mut conn)
            .await
            .unwrap();
        }
        let step = EngineMigrationRegistry::production()
            .pending(68, 69)
            .unwrap()
            .pop()
            .unwrap();
        step.preflight(&mut conn).await.unwrap();
        step.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version=69")
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(crate::db::validate_engine_shape_on_for_test(&mut conn, 69)
            .await
            .unwrap());
        continue_from_engine_69(&mut conn).await;
        for (id, expected) in [
            ("evt-legacy-bad", (0, 0, 0, "other".to_string())),
            ("evt-legacy-half", (0, 0, 0, "other".to_string())),
            ("evt-legacy-null", (0, 0, 0, "other".to_string())),
            ("evt-legacy-single-null", (1, 0, 0, "other".to_string())),
            ("evt-legacy-single-run", (0, 1, 0, "other".to_string())),
        ] {
            let row: (i64, i64, i64, String) = sqlx::query_as(
                "SELECT m.has_claimed_by, m.has_claimed_run, m.has_released_from, m.claim_class
                   FROM content_event_claim_meta m
                   JOIN content_events e ON e.seq = m.event_seq
                  WHERE e.id = ?",
            )
            .bind(id)
            .fetch_one(&mut conn)
            .await
            .unwrap();
            assert_eq!(row, expected, "wrong class for {id}");
        }
        conn.close().await.unwrap();
    }

    /// The 69→70 statements are the fresh-DDL entries themselves, so the
    /// migrated and fresh `facet_times` cannot drift apart.
    #[test]
    fn engine_69_to_70_statements_are_the_fresh_ddl() {
        assert_eq!(ENGINE_69_TO_70_STATEMENTS.len(), 3);
        assert!(ENGINE_69_TO_70_STATEMENTS[0].starts_with("CREATE TABLE facet_times"));
        for statement in ENGINE_69_TO_70_STATEMENTS {
            assert!(
                crate::schema::DDL_STATEMENTS.contains(&statement),
                "69→70 statement has no fresh-DDL twin: {statement}"
            );
        }
    }

    /// The 69→70 edge adds `facet_times` and rebuilds it from the content
    /// log. No engine below 70 wrote `time_kind`, so a real engine-69 file
    /// backfills nothing; this test plants typed `facet.set` events first to
    /// prove the rebuild folds exactly what replay does: the current typed
    /// value per key, not an unset one, an untyped overwrite, or an
    /// observation. The reverted pre-image pins the engine-69 shape.
    #[tokio::test]
    async fn engine_69_to_70_adds_facet_times_rebuilt_from_the_log() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("facet-times-edge.db");
        create_current_schema(&path).await;
        let db = crate::open_existing_database_at(&path).await.unwrap();
        let record = crate::store::create_record(
            &db,
            serde_json::json!({"type": "WorkItem", "kind": "task", "name": "typed time"}),
        )
        .await
        .unwrap();
        let set = |payload: serde_json::Value| crate::store::AppendSpec {
            record_id: record.clone(),
            event_type: "facet.set".into(),
            payload,
            actor: None,
        };
        for payload in [
            serde_json::json!({"key": "due", "value": "2026-10-05", "time_kind": "date"}),
            serde_json::json!({"key": "meeting", "value": "{\"all_day\":false,\"start\":{\"local\":\"2026-10-24T10:00\",\"tz\":\"Europe/London\",\"offset\":\"+01:00\",\"tzdb\":\"2025b\"},\"end\":{\"local\":\"2026-10-25T10:00\",\"tz\":\"Europe/London\",\"offset\":\"+00:00\",\"tzdb\":\"2025b\"}}", "time_kind": "when"}),
            serde_json::json!({"key": "gone", "value": "2026-10-06", "time_kind": "date"}),
            serde_json::json!({"key": "untyped_later", "value": "2026-10-07", "time_kind": "date"}),
            serde_json::json!({"key": "untyped_later", "value": "next week"}),
            serde_json::json!({"key": "due", "value": "2020-01-01", "time_kind": "date", "as_of": "2020-01-01T00:00:00.000Z", "observation_only": true}),
        ] {
            crate::store::append(&db, set(payload)).await.unwrap();
        }
        crate::store::unset_facet(&db, &record, "gone")
            .await
            .unwrap();
        type Row = (
            String,
            String,
            i64,
            Option<String>,
            Option<String>,
            Option<i64>,
            Option<i64>,
            Option<String>,
        );
        let rows = "SELECT key, kind, all_day, start_date, end_date, start_ms, end_ms, tz FROM facet_times ORDER BY key";
        let live: Vec<Row> = sqlx::query_as(rows)
            .fetch_all(db.write_pool())
            .await
            .unwrap();
        assert_eq!(
            live,
            vec![
                (
                    "due".into(),
                    "date".into(),
                    1,
                    Some("2026-10-05".into()),
                    Some("2026-10-06".into()),
                    None,
                    None,
                    None
                ),
                (
                    "meeting".into(),
                    "when".into(),
                    0,
                    None,
                    None,
                    Some(1_792_832_400_000),
                    Some(1_792_922_400_000),
                    Some("Europe/London".into())
                ),
            ]
        );
        db.close().await;

        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        revert_to_engine_69(&mut conn).await;
        let digest = crate::db::schema_shape_contract_sha256_for_test(&mut conn)
            .await
            .unwrap();
        assert_eq!(digest, crate::db::ENGINE_69_SHAPE_CONTRACT_SHA256);
        continue_from_engine_69(&mut conn).await;
        let migrated_rows: Vec<Row> = sqlx::query_as(rows).fetch_all(&mut conn).await.unwrap();
        assert_eq!(migrated_rows, live);
        conn.close().await.unwrap();

        let migrated = crate::open_existing_database_at(&path).await.unwrap();
        let result = crate::conformance::rebuild_and_diff(&migrated)
            .await
            .unwrap();
        assert!(
            result.equal,
            "rebuild drift after 69→70: {}",
            serde_json::to_string_pretty(&result.tables).unwrap()
        );
        migrated.close().await;
    }

    /// The rebuild returns at once when no event carries `time_kind`, and
    /// otherwise folds its candidates page by page with the same result as
    /// replay, however the pages fall.
    #[tokio::test]
    async fn facet_times_rebuild_probes_first_and_pages_to_the_live_fold() {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut conn = db.write_pool().acquire().await.unwrap();
        assert_eq!(
            crate::projector::rebuild_facet_times(&mut conn)
                .await
                .unwrap(),
            0
        );
        drop(conn);
        let mut records = Vec::new();
        for day in 1..=5 {
            let record = crate::store::create_record(
                &db,
                serde_json::json!({"type": "Document", "kind": "note", "name": format!("day {day}")}),
            )
            .await
            .unwrap();
            for (key, value) in [
                ("due", format!("2026-10-0{day}")),
                ("again", format!("2026-11-0{day}")),
            ] {
                crate::store::append(
                    &db,
                    crate::store::AppendSpec {
                        record_id: record.clone(),
                        event_type: "facet.set".into(),
                        payload: serde_json::json!({"key": key, "value": value, "time_kind": "date"}),
                        actor: None,
                    },
                )
                .await
                .unwrap();
            }
            records.push(record);
        }
        // One key later loses its type, another is unset.
        crate::store::append(
            &db,
            crate::store::AppendSpec {
                record_id: records[0].clone(),
                event_type: "facet.set".into(),
                payload: serde_json::json!({"key": "again", "value": "untyped"}),
                actor: None,
            },
        )
        .await
        .unwrap();
        crate::store::unset_facet(&db, &records[1], "due")
            .await
            .unwrap();
        let dump =
            "SELECT record_id, key, start_date, end_date FROM facet_times ORDER BY record_id, key";
        let live: Vec<(String, String, Option<String>, Option<String>)> = sqlx::query_as(dump)
            .fetch_all(db.write_pool())
            .await
            .unwrap();
        assert_eq!(live.len(), 8);
        for page in [1, 2, 3, 500] {
            let mut conn = db.write_pool().acquire().await.unwrap();
            let rebuilt = crate::projector::rebuild_facet_times_paged(&mut conn, page)
                .await
                .unwrap();
            assert_eq!(rebuilt, 8, "page {page}");
            let rows: Vec<(String, String, Option<String>, Option<String>)> =
                sqlx::query_as(dump).fetch_all(&mut *conn).await.unwrap();
            assert_eq!(rows, live, "page {page}");
            let leftover: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM sqlite_temp_master WHERE name = '_facet_times_rebuild'",
            )
            .fetch_one(&mut *conn)
            .await
            .unwrap();
            assert_eq!(leftover, 0, "the working table is dropped");
        }
    }

    /// The 70→71 index must stay byte-identical to its fresh-DDL twin, and
    /// its `WHERE` to the predicate the field-change read states, or SQLite
    /// would not use it for that read.
    #[test]
    fn engine_70_to_71_statements_match_fresh_ddl_and_the_read_predicate() {
        assert_eq!(ENGINE_70_TO_71_STATEMENTS.len(), 1);
        let statement = ENGINE_70_TO_71_STATEMENTS[0];
        let fresh = crate::schema::DDL_STATEMENTS
            .iter()
            .find(|candidate| {
                candidate.starts_with("CREATE INDEX idx_content_events_record_changes ")
            })
            .expect("70→71 statement has no fresh-DDL twin");
        assert_eq!(*fresh, statement, "70→71 statement drifted from fresh DDL");
        assert!(statement.starts_with(&format!(
            "CREATE INDEX {} ON content_events(record_id, seq) WHERE ",
            crate::query::events::FIELD_CHANGE_ROWS_INDEX
        )));
        assert!(statement.ends_with(&format!(
            " WHERE {}",
            crate::query::events::FIELD_CHANGE_ROWS_PREDICATE
        )));
        assert_eq!(
            crate::query::events::FIELD_CHANGE_ROWS_PREDICATE,
            crate::query::events::visibility_predicates::not_in(
                &crate::query::events::visibility_predicates::field_change_excluded_types()
            )
        );
    }

    /// The 70→71 edge adds the partial index over an existing log: the
    /// migrated database validates at schema 71, the index holds exactly the
    /// rows the field-change read may see, the read's statement plans on it,
    /// and a rebuild converges.
    #[tokio::test]
    async fn engine_70_to_71_adds_the_record_changes_index() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("record-changes-index-edge.db");
        {
            let db = crate::create_database(&path.to_string_lossy())
                .await
                .unwrap();
            crate::store::create_record(
                &db,
                serde_json::json!({
                    "id": "0e5c0a4e-7d1b-4c5e-9f3a-1b2c3d4e5f60", "type": "Document", "kind": "note", "name": "Edge",
                }),
            )
            .await
            .unwrap();
            db.close().await;
        }
        let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
            .unwrap()
            .foreign_keys(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        revert_to_engine_70(&mut conn).await;
        let digest = crate::db::schema_shape_contract_sha256_for_test(&mut conn)
            .await
            .unwrap();
        assert_eq!(digest, crate::db::ENGINE_70_SHAPE_CONTRACT_SHA256);
        continue_from_engine_70(&mut conn).await;
        // `INDEXED BY` refuses to prepare unless SQLite can use the index
        // for the statement, so this is the read's own statement shape
        // proving the partial index serves it.
        let indexed: Vec<String> = sqlx::query_scalar(&format!(
            "SELECT id FROM content_events INDEXED BY {} \
              WHERE record_id = ? AND seq < ? AND {} ORDER BY seq DESC LIMIT 16",
            crate::query::events::FIELD_CHANGE_ROWS_INDEX,
            crate::query::events::FIELD_CHANGE_ROWS_PREDICATE
        ))
        .bind("0e5c0a4e-7d1b-4c5e-9f3a-1b2c3d4e5f60")
        .bind(i64::MAX)
        .fetch_all(&mut conn)
        .await
        .unwrap();
        assert_eq!(indexed.len(), 1);
        conn.close().await.unwrap();

        let migrated = crate::open_existing_database_at(&path).await.unwrap();
        let result = crate::conformance::rebuild_and_diff(&migrated)
            .await
            .unwrap();
        assert!(
            result.equal,
            "rebuild drift after 70→71: {}",
            serde_json::to_string_pretty(&result.tables).unwrap()
        );
        migrated.close().await;
    }
}
