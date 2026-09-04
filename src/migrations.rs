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
    sqlx::query("VACUUM INTO ?")
        .bind(snapshot.to_string_lossy().into_owned())
        .execute(&mut *connection)
        .await?;
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
    backup
        .store_verified_preimage(run_id, db_id, &snapshot)
        .await
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
    }
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
    let _ = connection.close().await;
    if target == CURRENT_ENGINE_SCHEMA_VERSION {
        let verification = match verifier.clone() {
            Some(verifier) => verifier(path.to_path_buf()).await,
            None => verify_migrated_database(path.to_path_buf()).await,
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

async fn verify_migrated_database(path: PathBuf) -> PostMigrationVerification {
    if let Err(err) = crate::db::validate_current_engine_shape_read_only(&path).await {
        return PostMigrationVerification::StructuralFailed(err.to_string());
    }
    let db = match crate::db::open_existing_database_at(&path).await {
        Ok(db) => db,
        Err(err) => {
            return PostMigrationVerification::VerifyOpenFailed(err.to_string());
        }
    };
    let conformance = crate::conformance::run_conformance(&db).await;
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

    #[tokio::test]
    async fn real_post_migration_verifier_covers_pass_and_structural_failure() {
        let dir = tempfile::tempdir().unwrap();
        let passing = dir.path().join("passing.db");
        create_current_schema(&passing).await;
        assert!(matches!(
            verify_migrated_database(passing).await,
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
            verify_migrated_database(nonconformant).await,
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
            .pending(49, CURRENT_ENGINE_SCHEMA_VERSION)
            .unwrap()
            .pop()
            .unwrap();
        successor.preflight(&mut conn).await.unwrap();
        successor.apply(&mut conn).await.unwrap();
        sqlx::query("PRAGMA user_version = 50")
            .execute(&mut conn)
            .await
            .unwrap();
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
            .pending(49, CURRENT_ENGINE_SCHEMA_VERSION)
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
            .pending(49, CURRENT_ENGINE_SCHEMA_VERSION)
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
}
