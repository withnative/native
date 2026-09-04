#![cfg(feature = "turso-tests")]

//! Executable physical-compatibility probe for the split Turso profiles.
//!
//! This is deliberately not a `ContractHarness` or production backend. It
//! answers the narrower question needed before such work is justified: which
//! parts of Native's SQLite implementation contract run unchanged on Turso's
//! SQLite frontend, and which parts require an engine-owned implementation?

use std::collections::BTreeSet;

use native_ce::schema::DDL_STATEMENTS;
use rusqlite::Connection as SqliteConnection;
use tempfile::tempdir;
use turso::{Builder, Connection};

const TURSO_FACET_VALUES_DDL: &str = r#"CREATE TABLE facet_values (
     id          TEXT PRIMARY KEY,
     record_id   TEXT NOT NULL REFERENCES records(id) ON DELETE CASCADE,
     key         TEXT NOT NULL,
     value       TEXT,
     value_num   REAL,
     vocab_ref   TEXT,
     created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
     UNIQUE (record_id, key)
    )"#;

fn sqlite_fts_statement(statement: &str) -> bool {
    statement.contains("records_fts") || statement.contains("records_name_idx")
}

async fn scalar_i64(connection: &Connection, sql: &str) -> i64 {
    let mut rows = connection.query(sql, ()).await.unwrap();
    rows.next()
        .await
        .unwrap()
        .expect("scalar query returned a row")
        .get(0)
        .unwrap()
}

#[tokio::test]
async fn turso_applies_native_ddl_with_only_declared_physical_overlays() {
    let database = Builder::new_local(":memory:").build().await.unwrap();
    let connection = database.connect().unwrap();
    connection
        .execute("PRAGMA foreign_keys = ON", ())
        .await
        .unwrap();

    let mut overlays = BTreeSet::new();
    for (index, statement) in DDL_STATEMENTS.iter().enumerate() {
        if sqlite_fts_statement(statement) {
            overlays.insert("search.sqlite-fts5");
            continue;
        }
        let statement = if statement.contains("GENERATED ALWAYS AS") {
            overlays.insert("projection.facet-value-number");
            TURSO_FACET_VALUES_DDL
        } else {
            statement
        };
        connection
            .execute(statement, ())
            .await
            .unwrap_or_else(|error| {
                panic!("Turso rejected Native DDL statement {index}: {statement}\n{error}")
            });
    }

    assert_eq!(
        overlays,
        BTreeSet::from(["projection.facet-value-number", "search.sqlite-fts5"])
    );
    assert_eq!(
        scalar_i64(&connection, "PRAGMA user_version").await,
        native_ce::CURRENT_ENGINE_SCHEMA_VERSION
    );
    assert_eq!(
        scalar_i64(
            &connection,
            "SELECT COUNT(*) FROM sqlite_schema WHERE name = 'facet_values'"
        )
        .await,
        1
    );
    assert_eq!(
        scalar_i64(
            &connection,
            "SELECT COUNT(*) FROM sqlite_schema WHERE name IN ('records_fts', 'records_name_idx')"
        )
        .await,
        0,
        "SQLite FTS5 is a physical implementation contract, not portable DDL"
    );
}

#[tokio::test]
async fn turso_preserves_atomic_event_and_projection_transactions() {
    let database = Builder::new_local(":memory:").build().await.unwrap();
    let connection = database.connect().unwrap();
    connection
        .execute_batch(
            "CREATE TABLE content_events(seq INTEGER PRIMARY KEY, record_id TEXT NOT NULL);\n\
             CREATE TABLE records(id TEXT PRIMARY KEY, body TEXT);",
        )
        .await
        .unwrap();

    connection.execute("BEGIN IMMEDIATE", ()).await.unwrap();
    connection
        .execute(
            "INSERT INTO content_events VALUES(1, 'portable:record')",
            (),
        )
        .await
        .unwrap();
    connection
        .execute(
            "INSERT INTO records VALUES('portable:record', 'rolled back')",
            (),
        )
        .await
        .unwrap();
    connection.execute("ROLLBACK", ()).await.unwrap();
    assert_eq!(
        scalar_i64(&connection, "SELECT COUNT(*) FROM content_events").await,
        0
    );
    assert_eq!(
        scalar_i64(&connection, "SELECT COUNT(*) FROM records").await,
        0
    );

    connection.execute("BEGIN IMMEDIATE", ()).await.unwrap();
    connection
        .execute(
            "INSERT INTO content_events VALUES(1, 'portable:record')",
            (),
        )
        .await
        .unwrap();
    connection
        .execute(
            "INSERT INTO records VALUES('portable:record', 'committed')",
            (),
        )
        .await
        .unwrap();
    connection.execute("COMMIT", ()).await.unwrap();
    assert_eq!(
        scalar_i64(&connection, "SELECT COUNT(*) FROM content_events").await,
        1
    );
    assert_eq!(
        scalar_i64(&connection, "SELECT COUNT(*) FROM records").await,
        1
    );
}

#[tokio::test]
async fn local_turso_and_stock_sqlite_round_trip_a_portable_file() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("portable.db");
    let path = path.to_str().unwrap();

    {
        let database = Builder::new_local(path).build().await.unwrap();
        let connection = database.connect().unwrap();
        connection
            .execute(
                "CREATE TABLE portable_values(\
                 id TEXT PRIMARY KEY, json_value TEXT NOT NULL, bytes BLOB NOT NULL)",
                (),
            )
            .await
            .unwrap();
        connection
            .execute(
                "INSERT INTO portable_values VALUES\
                 ('from-turso', '{\"number\":1}', X'00ff')",
                (),
            )
            .await
            .unwrap();
        let mut checkpoint = connection
            .query("PRAGMA wal_checkpoint(TRUNCATE)", ())
            .await
            .unwrap();
        while checkpoint.next().await.unwrap().is_some() {}
    }

    {
        let connection = SqliteConnection::open(path).unwrap();
        let value: String = connection
            .query_row(
                "SELECT json_value FROM portable_values WHERE id = 'from-turso'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(value, "{\"number\":1}");
        connection
            .execute(
                "INSERT INTO portable_values VALUES\
                 ('from-sqlite', '{\"number\":2}', X'ff00')",
                [],
            )
            .unwrap();
    }

    {
        let database = Builder::new_local(path).build().await.unwrap();
        let connection = database.connect().unwrap();
        assert_eq!(
            scalar_i64(&connection, "SELECT COUNT(*) FROM portable_values").await,
            2
        );
    }
}

#[tokio::test]
async fn turso_search_is_an_engine_overlay_not_sqlite_fts5() {
    let database = Builder::new_local(":memory:")
        .experimental_index_method(true)
        .build()
        .await
        .unwrap();
    let connection = database.connect().unwrap();
    connection
        .execute(
            "CREATE TABLE documents(id TEXT PRIMARY KEY, name TEXT, body TEXT)",
            (),
        )
        .await
        .unwrap();

    let sqlite_fts = connection
        .execute(
            "CREATE VIRTUAL TABLE documents_fts USING fts5(name, body)",
            (),
        )
        .await;
    assert!(
        sqlite_fts.is_err(),
        "Turso unexpectedly accepted SQLite FTS5"
    );

    connection
        .execute(
            "CREATE INDEX documents_turso_fts ON documents USING fts(name, body)",
            (),
        )
        .await
        .unwrap();
    connection
        .execute(
            "INSERT INTO documents VALUES\
             ('portable:search', 'Portable search', 'same intent, different index')",
            (),
        )
        .await
        .unwrap();
    let mut rows = connection
        .query("SELECT id FROM documents WHERE name MATCH 'portable'", ())
        .await
        .unwrap();
    let id: String = rows.next().await.unwrap().unwrap().get(0).unwrap();
    assert_eq!(id, "portable:search");
}

#[test]
fn draft_storage_profiles_are_machine_readable_and_keep_axes_separate() {
    let schema = serde_json::from_str::<serde_json::Value>(include_str!(
        "../../protocol/storage-portability/v1/profile.schema.json"
    ))
    .unwrap();
    assert!(
        jsonschema::meta::is_valid(&schema),
        "storage profile schema must itself be valid JSON Schema"
    );
    let validator = jsonschema::validator_for(&schema).unwrap();

    let fixtures = [
        (
            "sqlite-local",
            include_str!("../../protocol/storage-portability/v1/profiles/sqlite-local.json"),
        ),
        (
            "postgres-server",
            include_str!("../../protocol/storage-portability/v1/profiles/postgres-server.json"),
        ),
        (
            "turso-local",
            include_str!("../../protocol/storage-portability/v1/profiles/turso-local.json"),
        ),
        (
            "turso-remote",
            include_str!("../../protocol/storage-portability/v1/profiles/turso-remote.json"),
        ),
        (
            "turso-embedded-sync",
            include_str!("../../protocol/storage-portability/v1/profiles/turso-embedded-sync.json"),
        ),
        (
            "turso-local@2",
            include_str!("../../protocol/storage-portability/v1/profiles/turso-local-v2.json"),
        ),
        (
            "turso-local@3",
            include_str!("../../protocol/storage-portability/v1/profiles/turso-local-v3.json"),
        ),
        (
            "turso-local@4",
            include_str!("../../protocol/storage-portability/v1/profiles/turso-local-v4.json"),
        ),
        (
            "turso-remote@2",
            include_str!("../../protocol/storage-portability/v1/profiles/turso-remote-v2.json"),
        ),
        (
            "turso-embedded-sync@2",
            include_str!(
                "../../protocol/storage-portability/v1/profiles/turso-embedded-sync-v2.json"
            ),
        ),
        (
            "libsql-embedded-replica@1",
            include_str!(
                "../../protocol/storage-portability/v1/profiles/libsql-embedded-replica.json"
            ),
        ),
    ];
    let profiles = fixtures
        .into_iter()
        .map(|(name, fixture)| {
            let profile = serde_json::from_str::<serde_json::Value>(fixture).unwrap();
            let errors = validator
                .iter_errors(&profile)
                .map(|error| error.to_string())
                .collect::<Vec<_>>();
            assert!(
                errors.is_empty(),
                "storage profile {name} violated profile.schema.json:\n{}",
                errors.join("\n")
            );

            let declared_modes = profile["connection"]["modes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|mode| mode.as_str().unwrap())
                .collect::<BTreeSet<_>>();
            for (capability, claim) in profile["capabilities"].as_object().unwrap() {
                let Some(mode_support) = claim.get("mode_support") else {
                    continue;
                };
                let scoped_modes = mode_support
                    .as_object()
                    .unwrap()
                    .keys()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>();
                assert_eq!(
                    scoped_modes, declared_modes,
                    "storage profile {name} capability {capability} must declare mode_support for exactly its connection modes"
                );
            }
            profile
        })
        .collect::<Vec<_>>();

    assert!(profiles
        .iter()
        .all(|profile| profile["format"] == "native.storage-profile.v1"));
    assert_eq!(profiles[0]["engine"]["family"], "sqlite");
    assert_eq!(profiles[1]["engine"]["family"], "postgresql");
    assert!(profiles[2..10]
        .iter()
        .all(|profile| profile["engine"]["family"] == "turso"));
    assert_eq!(profiles[10]["engine"]["family"], "libsql");
    assert_eq!(profiles[0]["frontend"]["dialect"], "sqlite");
    assert_eq!(profiles[1]["frontend"]["dialect"], "postgres");
    assert!(profiles[2..]
        .iter()
        .all(|profile| profile["frontend"]["dialect"] == "sqlite"));
    assert_ne!(
        profiles[0]["engine"]["family"], profiles[2]["engine"]["family"],
        "sharing a dialect must not collapse SQLite and Turso into one engine"
    );

    for index in [5, 6, 7, 8, 9, 10] {
        let mut incomplete = profiles[index].clone();
        incomplete
            .as_object_mut()
            .unwrap()
            .remove("operational_identity");
        assert!(
            !validator.is_valid(&incomplete),
            "the protocol schema must require the rebased profile's operational identity"
        );
    }
}

#[test]
fn current_turso_profiles_pin_four_non_transferable_operational_identities() {
    let local = serde_json::from_str::<serde_json::Value>(include_str!(
        "../../protocol/storage-portability/v1/profiles/turso-local-v4.json"
    ))
    .unwrap();
    let remote = serde_json::from_str::<serde_json::Value>(include_str!(
        "../../protocol/storage-portability/v1/profiles/turso-remote-v2.json"
    ))
    .unwrap();
    let sync = serde_json::from_str::<serde_json::Value>(include_str!(
        "../../protocol/storage-portability/v1/profiles/turso-embedded-sync-v2.json"
    ))
    .unwrap();
    let legacy = serde_json::from_str::<serde_json::Value>(include_str!(
        "../../protocol/storage-portability/v1/profiles/libsql-embedded-replica.json"
    ))
    .unwrap();

    assert_eq!(
        local["connection"]["modes"],
        serde_json::json!(["embedded"])
    );
    assert!(local["connection"]["driver"]
        .as_str()
        .unwrap()
        .contains("turso::Builder::new_local"));
    assert_eq!(
        remote["connection"]["modes"],
        serde_json::json!(["network"])
    );
    assert!(remote["connection"]["driver"]
        .as_str()
        .unwrap()
        .contains("turso_serverless::Builder::new_remote"));
    assert_eq!(sync["connection"]["modes"], serde_json::json!(["sync"]));
    assert!(sync["connection"]["driver"]
        .as_str()
        .unwrap()
        .contains("turso::sync::Builder::new_remote"));
    assert_eq!(
        legacy["connection"]["modes"],
        serde_json::json!(["embedded-replica"])
    );
    assert!(legacy["connection"]["driver"]
        .as_str()
        .unwrap()
        .contains("libsql::Builder::new_remote_replica"));

    let sync_identity = &sync["operational_identity"];
    assert!(sync_identity["write_authority"]
        .as_str()
        .unwrap()
        .contains("local transaction commit"));
    assert!(sync_identity["consistency"]
        .as_str()
        .unwrap()
        .contains("Exactly one active writable replica"));
    assert!(sync_identity["promotion_rules"]
        .as_array()
        .unwrap()
        .iter()
        .any(|rule| rule
            .as_str()
            .unwrap()
            .contains("Multiple active writable replicas remain unsupported")));

    let legacy_identity = &legacy["operational_identity"];
    assert!(legacy_identity["write_authority"]
        .as_str()
        .unwrap()
        .contains("remote libSQL primary"));
    assert_ne!(sync["topology"]["kind"], legacy["topology"]["kind"]);
    assert_eq!(legacy["status"], "retired");
}

#[test]
fn turso_local_profile_claims_only_the_bounded_shared_runtime() {
    let immutable_v2: serde_json::Value = serde_json::from_str(include_str!(
        "../../protocol/storage-portability/v1/profiles/turso-local-v2.json"
    ))
    .unwrap();
    let profile: serde_json::Value = serde_json::from_str(include_str!(
        "../../protocol/storage-portability/v1/profiles/turso-local-v4.json"
    ))
    .unwrap();
    assert_eq!(immutable_v2["revision"], 2);
    assert_eq!(
        immutable_v2["capabilities"]["native.raw-sql"]["support"],
        "unsupported"
    );
    assert_eq!(
        profile["capabilities"]["native.operation.snapshot-export.v1"]["support"],
        "unsupported"
    );
    assert!(
        profile["capabilities"]["native.operation.snapshot-export.v1"]["notes"]
            .as_str()
            .unwrap()
            .contains("No Turso-local snapshot handler")
    );
    assert!(profile["capabilities"]["native.domain-mcp.v1"]["notes"]
        .as_str()
        .unwrap()
        .contains("shared backend-neutral domain transaction seam"));
    assert!(profile["capabilities"]["native.domain-mcp.v1"]["notes"]
        .as_str()
        .unwrap()
        .contains("profile remains a spike"));
    assert!(
        profile["capabilities"]["native.describe-physical-schema"]["provider"]
            .as_str()
            .unwrap()
            .contains("exact ordinary value_num column maintained atomically")
    );
    assert_eq!(profile["capabilities"]["native.raw-sql"]["support"], "full");
    assert_eq!(
        profile["capabilities"]["native.raw-sql"]["portability"],
        "profile-specific"
    );
    assert!(profile["capabilities"]["native.raw-sql"]["provider"]
        .as_str()
        .unwrap()
        .contains("MemoryIO projection"));
}
