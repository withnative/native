//! Executable spike for caller-filtered `query_sql` (Native task f40021f).
//!
//! The successful prototype uses an explicitly acquired pooled connection,
//! connection-local TEMP views, and a one-row TEMP principal table populated
//! only inside the user query's transaction. Explicit completion rolls the
//! transaction back. Cancellation and panic use SQLx's transaction drop,
//! which enqueues a rollback on the connection worker before the connection
//! can execute a later request. The tests below make that ordering observable
//! on a one-connection pool and under two-principal contention.
//!
//! This module is not production code. In particular, its small ACL fixture is
//! evidence for the principal boundary and relation contract, not the eventual
//! permission schema.

use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::{stream, FutureExt, StreamExt};
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions, SqliteRow};
use sqlx::{Acquire, Row, Sqlite, SqlitePool, Transaction};
use tempfile::TempDir;

use super::principal::QueryPrincipal;
use crate::error::{Error, Result};

use super::sql;

use super::error::contract_violation;

const LOGICAL_RELATIONS: [&str; 7] = [
    "records",
    "content_events",
    "links",
    "facet_values",
    "facet_observations",
    "bindings",
    "blobs",
];

const RAW_RELATIONS: [&str; 10] = [
    "records",
    "content_events",
    "links",
    "facet_values",
    "facet_observations",
    "bindings",
    "blobs",
    "records_fts",
    "records_name_idx",
    "policy_grants",
];

const RAW_SCHEMA: &str = r#"
CREATE TABLE records (
    rowid INTEGER PRIMARY KEY,
    id TEXT NOT NULL UNIQUE,
    type TEXT NOT NULL,
    kind TEXT,
    name TEXT NOT NULL,
    body TEXT
);
CREATE TABLE policy_grants (
    record_id TEXT NOT NULL,
    account_id TEXT NOT NULL,
    PRIMARY KEY (record_id, account_id)
);
CREATE TABLE content_events (
    id TEXT PRIMARY KEY,
    record_id TEXT NOT NULL,
    payload TEXT
);
CREATE TABLE links (
    id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    relationship TEXT NOT NULL
);
CREATE TABLE facet_values (
    id TEXT PRIMARY KEY,
    record_id TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT
);
CREATE TABLE facet_observations (
    id TEXT PRIMARY KEY,
    record_id TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT
);
CREATE TABLE bindings (
    record_id TEXT NOT NULL,
    system TEXT NOT NULL,
    identifier TEXT NOT NULL
);
CREATE TABLE blobs (
    id TEXT PRIMARY KEY,
    bytes BLOB,
    original_filename TEXT
);
CREATE VIRTUAL TABLE records_fts USING fts5(
    name, body,
    content='records', content_rowid='rowid'
);
CREATE TRIGGER records_fts_ai AFTER INSERT ON records BEGIN
    INSERT INTO records_fts(rowid, name, body)
    VALUES (new.rowid, new.name, new.body);
END;
CREATE VIRTUAL TABLE records_name_idx USING fts5(
    name,
    content='records', content_rowid='rowid'
);
CREATE TRIGGER records_name_idx_ai AFTER INSERT ON records BEGIN
    INSERT INTO records_name_idx(rowid, name) VALUES (new.rowid, new.name);
END;
"#;

const TEMP_CONTRACT: &str = r#"
CREATE TEMP TABLE IF NOT EXISTS _query_sql_principal (
    account_id TEXT NOT NULL
);
CREATE TEMP VIEW IF NOT EXISTS records AS
SELECT r.id, r.type, r.kind, r.name, r.body
FROM main.records AS r
WHERE EXISTS (
    SELECT 1
    FROM main.policy_grants AS g
    JOIN temp._query_sql_principal AS p ON p.account_id = g.account_id
    WHERE g.record_id = r.id
);
CREATE TEMP VIEW IF NOT EXISTS content_events AS
SELECT e.id, e.record_id, e.payload
FROM main.content_events AS e
WHERE EXISTS (
    SELECT 1
    FROM main.policy_grants AS g
    JOIN temp._query_sql_principal AS p ON p.account_id = g.account_id
    WHERE g.record_id = e.record_id
);
CREATE TEMP VIEW IF NOT EXISTS facet_values AS
SELECT f.id, f.record_id, f.key, f.value
FROM main.facet_values AS f
WHERE EXISTS (
    SELECT 1 FROM main.policy_grants AS g
    JOIN temp._query_sql_principal AS p ON p.account_id = g.account_id
    WHERE g.record_id = f.record_id
);
CREATE TEMP VIEW IF NOT EXISTS facet_observations AS
SELECT f.id, f.record_id, f.key, f.value
FROM main.facet_observations AS f
WHERE EXISTS (
    SELECT 1 FROM main.policy_grants AS g
    JOIN temp._query_sql_principal AS p ON p.account_id = g.account_id
    WHERE g.record_id = f.record_id
);
-- Both endpoints must be readable: a visible endpoint cannot disclose a
-- hidden endpoint's id merely because a link row exists.
CREATE TEMP VIEW IF NOT EXISTS links AS
SELECT l.id, l.source_id, l.target_id
FROM main.links AS l
WHERE EXISTS (
    SELECT 1 FROM main.policy_grants AS g
    JOIN temp._query_sql_principal AS p ON p.account_id = g.account_id
    WHERE g.record_id = l.source_id
)
AND EXISTS (
    SELECT 1 FROM main.policy_grants AS g
    JOIN temp._query_sql_principal AS p ON p.account_id = g.account_id
    WHERE g.record_id = l.target_id
);
-- Portable account bindings are caller-owned even when the bearer record is
-- readable. Other binding systems follow their readable bearer record.
CREATE TEMP VIEW IF NOT EXISTS bindings AS
SELECT b.record_id, b.system, b.identifier
FROM main.bindings AS b
WHERE EXISTS (
    SELECT 1 FROM main.policy_grants AS g
    JOIN temp._query_sql_principal AS p ON p.account_id = g.account_id
    WHERE g.record_id = b.record_id
)
AND (
    b.system NOT IN ('account', 'email')
    OR EXISTS (
        SELECT 1
        FROM main.bindings AS own_account
        JOIN temp._query_sql_principal AS p
          ON p.account_id = own_account.identifier
        WHERE own_account.record_id = b.record_id
          AND own_account.system = 'account'
    )
);
CREATE TEMP VIEW IF NOT EXISTS blobs AS
SELECT b.id, b.bytes, b.original_filename
FROM main.blobs AS b
WHERE EXISTS (
    SELECT 1
    FROM main.records AS attachment
    JOIN main.facet_values AS blob_ref
      ON blob_ref.record_id = attachment.id
     AND blob_ref.key = 'blob_ref'
     AND blob_ref.value = b.id
    JOIN main.links AS bearer
      ON bearer.source_id = attachment.id
     AND bearer.relationship = 'part_of'
    JOIN main.policy_grants AS attachment_grant
      ON attachment_grant.record_id = attachment.id
    JOIN main.policy_grants AS bearer_grant
      ON bearer_grant.record_id = bearer.target_id
     AND bearer_grant.account_id = attachment_grant.account_id
    JOIN temp._query_sql_principal AS p
      ON p.account_id = attachment_grant.account_id
    WHERE attachment.type = 'Document'
      AND attachment.kind = 'attachment'
);
"#;

// The second prepare has only the public logical contract, all in TEMP. It is
// intentionally not a second copy of the raw schema: a user-qualified
// `main.records` must not resolve here even though it will exist at runtime.
// The collision-schema prepare above separately proves the real views expand.
const STRICT_LOGICAL_SCHEMA: &str = r#"
CREATE TEMP TABLE records (id TEXT, type TEXT, kind TEXT, name TEXT, body TEXT);
CREATE TEMP TABLE content_events (id TEXT, record_id TEXT, payload TEXT);
CREATE TEMP TABLE links (id TEXT, source_id TEXT, target_id TEXT);
CREATE TEMP TABLE facet_values (id TEXT, record_id TEXT, key TEXT, value TEXT);
CREATE TEMP TABLE facet_observations (id TEXT, record_id TEXT, key TEXT, value TEXT);
CREATE TEMP TABLE bindings (record_id TEXT, system TEXT, identifier TEXT);
CREATE TEMP TABLE blobs (id TEXT, bytes BLOB, original_filename TEXT);
"#;

struct Fixture {
    _dir: Arc<TempDir>,
    pool: SqlitePool,
}

async fn fixture(max_connections: u32) -> Fixture {
    let dir = Arc::new(tempfile::tempdir().unwrap());
    let path = dir.path().join("acl-spike.db");
    let options = format!("sqlite:{}", path.display())
        .parse::<SqliteConnectOptions>()
        .unwrap()
        .create_if_missing(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(max_connections)
        .connect_with(options)
        .await
        .unwrap();
    sqlx::raw_sql(RAW_SCHEMA).execute(&pool).await.unwrap();
    sqlx::raw_sql(
        r#"
        INSERT INTO records(id, type, kind, name, body) VALUES
          ('alice-private', 'Document', NULL, 'Alice private', 'sharedterm alice-only exclusivealpha'),
          ('bea-private', 'Document', NULL, 'Bea private', 'sharedterm bea-only'),
          ('common', 'Document', NULL, 'Common', 'sharedterm common'),
          ('attachment-alice', 'Document', 'attachment', 'alice.txt', NULL),
          ('attachment-bea', 'Document', 'attachment', 'bea.txt', NULL),
          ('attachment-common', 'Document', 'attachment', 'common.txt', NULL);
        INSERT INTO policy_grants(record_id, account_id) VALUES
          ('alice-private', 'alice'), ('common', 'alice'),
          ('bea-private', 'bea'), ('common', 'bea'),
          ('common', 'stdio-account'),
          ('attachment-alice', 'alice'),
          ('attachment-bea', 'bea'),
          ('attachment-common', 'alice'), ('attachment-common', 'bea'),
          ('attachment-common', 'stdio-account');
        INSERT INTO content_events(id, record_id, payload) VALUES
          ('event-alice', 'alice-private', 'alice event'),
          ('event-bea', 'bea-private', 'bea event'),
          ('event-common', 'common', 'common event');
        INSERT INTO facet_values(id, record_id, key, value) VALUES
          ('facet-alice', 'alice-private', 'secret', 'alice facet'),
          ('facet-bea', 'bea-private', 'secret', 'bea facet'),
          ('facet-common', 'common', 'public', 'common facet'),
          ('blob-ref-alice', 'attachment-alice', 'blob_ref', 'blob-alice'),
          ('blob-ref-bea', 'attachment-bea', 'blob_ref', 'blob-bea'),
          ('blob-ref-common', 'attachment-common', 'blob_ref', 'blob-common');
        INSERT INTO facet_observations(id, record_id, key, value) VALUES
          ('observation-alice', 'alice-private', 'secret', 'alice old facet'),
          ('observation-bea', 'bea-private', 'secret', 'bea old facet'),
          ('observation-common', 'common', 'public', 'common old facet');
        INSERT INTO links(id, source_id, target_id, relationship) VALUES
          ('link-alice-common', 'alice-private', 'common', 'relates_to'),
          ('link-common-bea', 'common', 'bea-private', 'relates_to'),
          ('link-alice-bea', 'alice-private', 'bea-private', 'relates_to'),
          ('bearer-alice', 'attachment-alice', 'alice-private', 'part_of'),
          ('bearer-bea', 'attachment-bea', 'bea-private', 'part_of'),
          ('bearer-common', 'attachment-common', 'common', 'part_of');
        INSERT INTO bindings(record_id, system, identifier) VALUES
          ('alice-private', 'account', 'alice'),
          ('alice-private', 'email', 'alice-private@example.test'),
          ('bea-private', 'account', 'bea'),
          ('bea-private', 'email', 'bea-private@example.test'),
          ('common', 'github', 'public/repository'),
          ('common', 'account', 'alice'),
          ('common', 'email', 'alice-public@example.test');
        INSERT INTO blobs(id, bytes, original_filename) VALUES
          ('blob-alice', X'41', 'alice.txt'),
          ('blob-bea', X'42', 'bea.txt'),
          ('blob-common', X'43', 'common.txt');
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();
    Fixture { _dir: dir, pool }
}

fn authorize_view_expansion(context: AuthContext<'_>) -> Authorization {
    match context.action {
        AuthAction::Select | AuthAction::Recursive => Authorization::Allow,
        AuthAction::Read { table_name, .. } => {
            // A main table and a TEMP filtered view deliberately share each
            // public name. Name-only authorization is a bypass: users can say
            // `main.records`. Direct reads must resolve to TEMP; main/temp
            // dependencies are admitted only when SQLite identifies a
            // controlled view as the accessor.
            let direct_logical =
                context.database_name == Some("temp") && LOGICAL_RELATIONS.contains(&table_name);
            let through_logical = context
                .accessor
                .is_some_and(|view| LOGICAL_RELATIONS.contains(&view));
            if direct_logical || through_logical {
                Authorization::Allow
            } else {
                Authorization::Deny
            }
        }
        AuthAction::Function { function_name }
            if !function_name.eq_ignore_ascii_case("load_extension") =>
        {
            Authorization::Allow
        }
        _ => Authorization::Deny,
    }
}

fn authorize_strict_logical(context: AuthContext<'_>) -> Authorization {
    match context.action {
        AuthAction::Select | AuthAction::Recursive => Authorization::Allow,
        AuthAction::Read { table_name, .. }
            if context.database_name == Some("temp") && LOGICAL_RELATIONS.contains(&table_name) =>
        {
            Authorization::Allow
        }
        // CTEs and derived relations have no backing database. Their source
        // reads are authorized independently against the TEMP-only contract.
        AuthAction::Read { .. } if context.database_name.is_none() => Authorization::Allow,
        AuthAction::Function { function_name }
            if !function_name.eq_ignore_ascii_case("load_extension") =>
        {
            Authorization::Allow
        }
        _ => Authorization::Deny,
    }
}

fn prepare_under_authorizer(
    conn: &rusqlite::Connection,
    sql_text: &str,
    authorizer: fn(AuthContext<'_>) -> Authorization,
) -> Result<()> {
    conn.authorizer(Some(authorizer));
    let prepared = conn.prepare(sql_text.trim().trim_end_matches(';'));
    conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
    match prepared {
        Ok(statement) if statement.readonly() => Ok(()),
        Ok(_) => Err(contract_violation("ACL spike validator: statement writes")),
        Err(error) => Err(contract_violation(format!("ACL spike validator: {error}"))),
    }
}

fn validate_view_expansion_only(sql_text: &str) -> Result<()> {
    let conn = rusqlite::Connection::open_in_memory()
        .map_err(|e| contract_violation(format!("ACL spike validator setup failed: {e}")))?;
    conn.execute_batch(RAW_SCHEMA)
        .and_then(|_| conn.execute_batch(TEMP_CONTRACT))
        .map_err(|e| contract_violation(format!("ACL spike validator setup failed: {e}")))?;
    prepare_under_authorizer(&conn, sql_text, authorize_view_expansion)
}

/// The schema-only connection creates the exact TEMP logical contract used by
/// real execution. The authorizer admits base reads only when SQLite identifies
/// one of those controlled views as the accessor.
fn validate_logical(sql_text: &str) -> Result<()> {
    // Reuse the shipping input checks (single statement and SELECT/WITH only).
    // Its broader current allowlist is then narrowed by the logical authorizer.
    sql::validate_input(sql_text)?;
    validate_view_expansion_only(sql_text)?;

    // SQLite's authorizer reports a CTE named `records` as accessor `records`,
    // the same string as the controlled view. A view-aware authorizer alone is
    // therefore spoofable. A second prepare against TEMP-only logical tables
    // makes the user contract structural: main/raw relations cannot resolve.
    let strict = rusqlite::Connection::open_in_memory()
        .map_err(|e| contract_violation(format!("ACL spike validator setup failed: {e}")))?;
    strict
        .execute_batch(STRICT_LOGICAL_SCHEMA)
        .map_err(|e| contract_violation(format!("ACL spike validator setup failed: {e}")))?;
    prepare_under_authorizer(&strict, sql_text, authorize_strict_logical)
}

async fn install_temp_contract(connection: &mut sqlx::SqliteConnection) -> Result<()> {
    sqlx::raw_sql(TEMP_CONTRACT).execute(connection).await?;
    Ok(())
}

async fn begin_principal<'a>(
    connection: &'a mut sqlx::pool::PoolConnection<Sqlite>,
    caller: &QueryPrincipal,
) -> Result<Transaction<'a, Sqlite>> {
    install_temp_contract(connection).await?;
    // Clear stale state *outside* the request transaction. Rolling back a
    // DELETE performed inside the request would restore the stale row. The
    // connection is exclusively acquired; if the clear itself fails, discard
    // the physical connection instead of returning uncertain state to the pool.
    if let Err(error) = sqlx::query("DELETE FROM temp._query_sql_principal")
        .execute(&mut **connection)
        .await
    {
        connection.close_on_drop();
        return Err(error.into());
    }
    let mut transaction = connection.begin().await?;
    sqlx::query("INSERT INTO temp._query_sql_principal(account_id) VALUES (?)")
        .bind(caller.credential())
        .execute(&mut *transaction)
        .await?;
    Ok(transaction)
}

fn first_column(rows: &[SqliteRow]) -> Result<Vec<String>> {
    rows.iter()
        .map(|row| row.try_get::<String, _>(0).map_err(Error::from))
        .collect()
}

async fn prototype_query_sql(
    pool: &SqlitePool,
    caller: &QueryPrincipal,
    sql_text: &str,
) -> Result<Vec<String>> {
    validate_logical(sql_text)?;
    prototype_execute(pool, caller, sql_text).await
}

async fn prototype_execute(
    pool: &SqlitePool,
    caller: &QueryPrincipal,
    sql_text: &str,
) -> Result<Vec<String>> {
    let mut connection = pool.acquire().await?;
    let mut transaction = begin_principal(&mut connection, caller).await?;
    let query_result = sqlx::query(sql_text).fetch_all(&mut *transaction).await;
    // Explicit on every ordinary/error return. If this future is cancelled or
    // panics before here, Transaction::drop enqueues the same rollback.
    let rollback_result = transaction.rollback().await;
    let rows = query_result?;
    rollback_result?;
    first_column(&rows)
}

/// FTS5's MATCH left operand must be a virtual table, not a view. Therefore raw
/// FTS is unavailable to arbitrary SQL in the successful reduced contract.
/// This trusted application query proves rows, snippets, and the windowed pool
/// count are caller-filtered. It deliberately returns SQLite's raw BM25 score
/// so the negative control can prove rank is *not* visibility-isolated.
async fn trusted_fts(
    pool: &SqlitePool,
    caller: &QueryPrincipal,
    term: &str,
) -> Result<Vec<(String, String, i64, f64)>> {
    let mut connection = pool.acquire().await?;
    let mut transaction = begin_principal(&mut connection, caller).await?;
    let result = sqlx::query(
        r#"
        WITH visible_hits AS (
          SELECT r.id,
                 snippet(records_fts, 1, '[', ']', '...', 8) AS excerpt,
                 bm25(records_fts) AS raw_rank
          FROM main.records_fts
          JOIN main.records AS r ON r.rowid = records_fts.rowid
          WHERE records_fts MATCH ?
            AND EXISTS (
              SELECT 1 FROM main.policy_grants AS g
              JOIN temp._query_sql_principal AS p ON p.account_id = g.account_id
              WHERE g.record_id = r.id
            )
        )
        SELECT id, excerpt, count(*) OVER () AS pool_count, raw_rank
        FROM visible_hits ORDER BY id
        "#,
    )
    .bind(term)
    .fetch_all(&mut *transaction)
    .await;
    let rollback_result = transaction.rollback().await;
    let rows = result?;
    rollback_result?;
    rows.into_iter()
        .map(|row| {
            Ok((
                row.try_get(0)?,
                row.try_get(1)?,
                row.try_get(2)?,
                row.try_get(3)?,
            ))
        })
        .collect()
}

async fn context_is_empty(pool: &SqlitePool) -> bool {
    let mut connection = pool.acquire().await.unwrap();
    install_temp_contract(&mut connection).await.unwrap();
    sqlx::query_scalar::<_, i64>("SELECT count(*) FROM temp._query_sql_principal")
        .fetch_one(&mut *connection)
        .await
        .unwrap()
        == 0
}

async fn seed_stale_principal(pool: &SqlitePool, account: &str) {
    let mut connection = pool.acquire().await.unwrap();
    install_temp_contract(&mut connection).await.unwrap();
    sqlx::query("DELETE FROM temp._query_sql_principal")
        .execute(&mut *connection)
        .await
        .unwrap();
    sqlx::query("INSERT INTO temp._query_sql_principal(account_id) VALUES (?)")
        .bind(account)
        .execute(&mut *connection)
        .await
        .unwrap();
}

#[tokio::test]
async fn negative_controls_expose_todays_bypass_and_unsafe_connection_state() {
    // Production now carries the spike's restriction: a base-table-shaped
    // query resolves only against the caller-filtered logical relation.
    // Qualified physical access is rejected by the shipping dual prepare.
    sql::validate("SELECT body FROM main.records WHERE id = 'alice-private'").unwrap_err();

    // An intentionally unsafe prototype writes connection-local state outside
    // a rollback scope. Reacquiring the one pool connection observes Alice.
    let fixture = fixture(1).await;
    let mut connection = fixture.pool.acquire().await.unwrap();
    install_temp_contract(&mut connection).await.unwrap();
    sqlx::query("INSERT INTO temp._query_sql_principal VALUES ('alice')")
        .execute(&mut *connection)
        .await
        .unwrap();
    drop(connection);
    let mut reused = fixture.pool.acquire().await.unwrap();
    let leaked: String = sqlx::query_scalar("SELECT account_id FROM temp._query_sql_principal")
        .fetch_one(&mut *reused)
        .await
        .unwrap();
    assert_eq!(
        leaked, "alice",
        "negative control must demonstrate the leak"
    );
    sqlx::query("DELETE FROM temp._query_sql_principal")
        .execute(&mut *reused)
        .await
        .unwrap();
}

#[tokio::test]
async fn logical_contract_covers_records_aggregates_and_scoped_relations() {
    let fixture = fixture(2).await;
    let alice = QueryPrincipal::authenticated("alice");
    let bea = QueryPrincipal::authenticated("bea");

    assert_eq!(
        prototype_query_sql(
            &fixture.pool,
            &alice,
            "SELECT id FROM records WHERE kind IS NULL ORDER BY id"
        )
        .await
        .unwrap(),
        ["alice-private", "common"]
    );
    assert_eq!(
        prototype_query_sql(
            &fixture.pool,
            &bea,
            "SELECT id FROM records WHERE id = 'alice-private'"
        )
        .await
        .unwrap(),
        Vec::<String>::new()
    );
    assert_eq!(
        prototype_query_sql(
            &fixture.pool,
            &bea,
            "SELECT CAST(count(*) AS TEXT) FROM records WHERE kind IS NULL"
        )
        .await
        .unwrap(),
        ["2"]
    );
    assert_eq!(
        prototype_query_sql(
            &fixture.pool,
            &bea,
            "SELECT record_id FROM content_events ORDER BY record_id"
        )
        .await
        .unwrap(),
        ["bea-private", "common"]
    );
    assert_eq!(
        prototype_query_sql(
            &fixture.pool,
            &alice,
            "SELECT record_id FROM facet_values WHERE key <> 'blob_ref' ORDER BY record_id"
        )
        .await
        .unwrap(),
        ["alice-private", "common"]
    );
    assert_eq!(
        prototype_query_sql(
            &fixture.pool,
            &bea,
            "SELECT record_id FROM facet_observations ORDER BY record_id"
        )
        .await
        .unwrap(),
        ["bea-private", "common"]
    );
    assert_eq!(
        prototype_query_sql(
            &fixture.pool,
            &alice,
            "SELECT id FROM links WHERE id LIKE 'link-%' ORDER BY id"
        )
        .await
        .unwrap(),
        ["link-alice-common"]
    );
    assert_eq!(
        prototype_query_sql(
            &fixture.pool,
            &bea,
            "SELECT id FROM links WHERE id LIKE 'link-%' ORDER BY id"
        )
        .await
        .unwrap(),
        ["link-common-bea"]
    );
    assert_eq!(
        prototype_query_sql(
            &fixture.pool,
            &alice,
            "SELECT DISTINCT system || ':' || identifier FROM bindings ORDER BY 1"
        )
        .await
        .unwrap(),
        [
            "account:alice",
            "email:alice-private@example.test",
            "email:alice-public@example.test",
            "github:public/repository"
        ]
    );
    assert_eq!(
        prototype_query_sql(
            &fixture.pool,
            &bea,
            "SELECT DISTINCT system || ':' || identifier FROM bindings ORDER BY 1"
        )
        .await
        .unwrap(),
        [
            "account:bea",
            "email:bea-private@example.test",
            "github:public/repository"
        ]
    );
    assert_eq!(
        prototype_query_sql(&fixture.pool, &bea, "SELECT id FROM blobs ORDER BY id")
            .await
            .unwrap(),
        ["blob-bea", "blob-common"]
    );
}

#[tokio::test]
async fn ctes_joins_validator_policy_changes_fts_and_stdio_are_consistent() {
    let fixture = fixture(2).await;
    let alice = QueryPrincipal::authenticated("alice");
    let bea = QueryPrincipal::authenticated("bea");
    let stdio = QueryPrincipal::authenticated("stdio-account");

    let cte = "WITH visible AS (SELECT id FROM records) \
               SELECT CAST(count(*) AS TEXT) FROM visible v \
               JOIN content_events e ON e.record_id = v.id";
    assert_eq!(
        prototype_query_sql(&fixture.pool, &alice, cte)
            .await
            .unwrap(),
        ["2"]
    );

    let accessor_spoof = "WITH records AS (SELECT * FROM main.records) SELECT * FROM records";
    assert!(
        validate_view_expansion_only(accessor_spoof).is_ok(),
        "negative control: SQLite accessor names alone should be spoofable by a colliding CTE"
    );

    let mut forbidden_queries = vec![
        "SELECT * FROM policy_grants".to_string(),
        "SELECT * FROM temp._query_sql_principal".to_string(),
        "SELECT * FROM main.\"records\"".to_string(),
        accessor_spoof.to_string(),
        "SELECT * FROM sqlite_master".to_string(),
    ];
    for relation in RAW_RELATIONS {
        forbidden_queries.push(format!("SELECT * FROM main.{relation}"));
        forbidden_queries.push(format!("SELECT raw.* FROM main.{relation} AS raw"));
        forbidden_queries.push(format!(
            "WITH stolen AS (SELECT * FROM main.{relation}) SELECT * FROM stolen"
        ));
    }
    for forbidden in &forbidden_queries {
        assert!(
            validate_logical(forbidden).is_err(),
            "base/policy/context relation unexpectedly admitted: {forbidden}"
        );
    }
    // The exact logical contract prepares on the schema-only validator.
    for allowed in [
        "SELECT id FROM records",
        "SELECT e.id FROM content_events e JOIN records r ON r.id=e.record_id",
        "WITH x AS (SELECT id FROM records) SELECT count(*) FROM x",
    ] {
        validate_logical(allowed).unwrap_or_else(|error| panic!("{allowed}: {error}"));
    }

    let alice_hits = trusted_fts(&fixture.pool, &alice, "sharedterm")
        .await
        .unwrap();
    assert_eq!(
        alice_hits
            .iter()
            .map(|hit| hit.0.as_str())
            .collect::<Vec<_>>(),
        ["alice-private", "common"]
    );
    assert!(alice_hits.iter().all(|hit| hit.2 == 2));
    assert!(alice_hits.iter().all(|hit| !hit.1.contains("bea-only")));
    let bea_hits = trusted_fts(&fixture.pool, &bea, "sharedterm")
        .await
        .unwrap();
    assert_eq!(bea_hits.len(), 2);
    assert!(bea_hits.iter().all(|hit| hit.2 == 2));
    assert!(bea_hits.iter().all(|hit| !hit.1.contains("alice-only")));

    // FTS5 computes BM25/IDF over the entire virtual-table corpus before the
    // visibility predicate. A hidden Bea-only document changes Alice's score
    // even though Alice's rows, snippet, and pool count remain identical.
    let rank_before = trusted_fts(&fixture.pool, &alice, "exclusivealpha")
        .await
        .unwrap();
    assert_eq!(rank_before.len(), 1);
    sqlx::query(
        "INSERT INTO main.records(id, type, kind, name, body) \
         VALUES ('bea-rank-control', 'Document', NULL, 'Hidden rank control', \
                 'exclusivealpha exclusivealpha exclusivealpha')",
    )
    .execute(&fixture.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO main.policy_grants(record_id, account_id) \
         VALUES ('bea-rank-control', 'bea')",
    )
    .execute(&fixture.pool)
    .await
    .unwrap();
    let rank_after = trusted_fts(&fixture.pool, &alice, "exclusivealpha")
        .await
        .unwrap();
    assert_eq!(rank_after.len(), 1);
    assert_eq!(rank_after[0].0, "alice-private");
    assert_eq!(rank_after[0].2, 1);
    assert!(!rank_after[0].1.contains("Hidden rank control"));
    assert_ne!(
        rank_before[0].3.to_bits(),
        rank_after[0].3.to_bits(),
        "negative control: hidden corpus must demonstrably affect raw BM25"
    );

    // Membership/grant changes are live on the next request: no copied grants
    // or rebuilt views are involved.
    sqlx::query("INSERT INTO policy_grants(record_id, account_id) VALUES ('alice-private','bea')")
        .execute(&fixture.pool)
        .await
        .unwrap();
    assert_eq!(
        prototype_query_sql(
            &fixture.pool,
            &bea,
            "SELECT id FROM records WHERE id = 'alice-private'"
        )
        .await
        .unwrap(),
        ["alice-private"]
    );

    // stdio carries a process-adopted portable caller through the same seam.
    // The filter is identical, but this is advisory: filesystem holders can
    // bypass the process and read SQLite directly.
    assert_eq!(
        prototype_query_sql(
            &fixture.pool,
            &stdio,
            "SELECT id FROM records WHERE kind IS NULL"
        )
        .await
        .unwrap(),
        ["common"]
    );
    const STDIO_ENFORCEMENT: &str = "advisory";
    assert_eq!(STDIO_ENFORCEMENT, "advisory");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_thousand_interleaved_and_reused_requests_never_cross_principals() {
    let concurrent_fixture = fixture(2).await;
    let pool = concurrent_fixture.pool.clone();
    let observations = stream::iter(0..1_000usize)
        .map(|index| {
            let pool = pool.clone();
            async move {
                let expected = if index % 2 == 0 {
                    "alice-private"
                } else {
                    "bea-private"
                };
                let caller =
                    QueryPrincipal::authenticated(if index % 2 == 0 { "alice" } else { "bea" });
                let rows = prototype_query_sql(
                    &pool,
                    &caller,
                    "SELECT id FROM records WHERE kind IS NULL AND id <> 'common'",
                )
                .await
                .unwrap();
                (expected.to_string(), rows)
            }
        })
        .buffer_unordered(32)
        .collect::<Vec<_>>()
        .await;
    assert_eq!(observations.len(), 1_000);
    for (expected, rows) in observations {
        assert_eq!(rows, [expected]);
    }
    assert!(context_is_empty(&concurrent_fixture.pool).await);

    // Force sequential Alice→Bea→Alice reuse on exactly one connection too.
    let single = fixture(1).await;
    for index in 0..100 {
        let account = if index % 2 == 0 { "alice" } else { "bea" };
        let expected = format!("{account}-private");
        assert_eq!(
            prototype_query_sql(
                &single.pool,
                &QueryPrincipal::authenticated(account),
                "SELECT id FROM records WHERE kind IS NULL AND id <> 'common'"
            )
            .await
            .unwrap(),
            [expected]
        );
    }
    assert!(context_is_empty(&single.pool).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn success_denial_execution_error_handler_error_cancellation_and_timeout_clean_up() {
    let fixture = fixture(1).await;
    let alice = QueryPrincipal::authenticated("alice");
    let bea = QueryPrincipal::authenticated("bea");

    // Seed the exact dirty state the defensive clear exists to repair. Because
    // clear is outside the request transaction, Bea's rollback returns the
    // physical connection to an empty context rather than restoring Alice.
    seed_stale_principal(&fixture.pool, "alice").await;
    assert_eq!(
        prototype_query_sql(
            &fixture.pool,
            &bea,
            "SELECT id FROM records WHERE kind IS NULL AND id <> 'common'"
        )
        .await
        .unwrap(),
        ["bea-private"]
    );
    assert!(context_is_empty(&fixture.pool).await);

    prototype_query_sql(&fixture.pool, &alice, "SELECT id FROM records")
        .await
        .unwrap();
    assert!(context_is_empty(&fixture.pool).await);

    assert!(
        prototype_query_sql(&fixture.pool, &alice, "SELECT * FROM main.policy_grants")
            .await
            .is_err()
    );
    assert!(context_is_empty(&fixture.pool).await);
    assert!(
        prototype_query_sql(&fixture.pool, &alice, "SELECT FROM records")
            .await
            .is_err()
    );
    assert!(context_is_empty(&fixture.pool).await);

    seed_stale_principal(&fixture.pool, "alice").await;
    let runtime_error = prototype_query_sql(
        &fixture.pool,
        &bea,
        "SELECT CAST(abs(-9223372036854775808) AS TEXT) FROM records",
    )
    .await;
    assert!(runtime_error.is_err());
    assert!(context_is_empty(&fixture.pool).await);

    // A later handler/serialization failure occurs after the SQL wrapper has
    // already rolled back its principal transaction.
    let handler_result: Result<()> = async {
        prototype_query_sql(&fixture.pool, &alice, "SELECT id FROM records").await?;
        Err(contract_violation("synthetic handler failure"))
    }
    .await;
    assert!(handler_result.is_err());
    assert!(context_is_empty(&fixture.pool).await);

    // Unwind while the principal transaction is live. Transaction::drop must
    // queue rollback before the pooled connection can serve Bea.
    let panic_result = std::panic::AssertUnwindSafe(async {
        let mut connection = fixture.pool.acquire().await.unwrap();
        let _transaction = begin_principal(&mut connection, &alice).await.unwrap();
        panic!("synthetic handler panic");
    })
    .catch_unwind()
    .await;
    assert!(panic_result.is_err());
    assert_eq!(
        prototype_query_sql(
            &fixture.pool,
            &bea,
            "SELECT id FROM records WHERE kind IS NULL AND id <> 'common'"
        )
        .await
        .unwrap(),
        ["bea-private"]
    );
    assert!(context_is_empty(&fixture.pool).await);

    seed_stale_principal(&fixture.pool, "bea").await;
    let runaway = prototype_query_sql(
        &fixture.pool,
        &alice,
        "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x < 5000000) \
         SELECT CAST(sum(x) AS TEXT) FROM n",
    );
    assert!(tokio::time::timeout(Duration::from_millis(5), runaway)
        .await
        .is_err());
    // Immediate reuse is the proof: SQLx's queued rollback must run before
    // this Bea request on the same physical connection.
    assert_eq!(
        prototype_query_sql(
            &fixture.pool,
            &bea,
            "SELECT id FROM records WHERE kind IS NULL AND id <> 'common'"
        )
        .await
        .unwrap(),
        ["bea-private"]
    );
    assert!(context_is_empty(&fixture.pool).await);

    // Explicit task cancellation exercises the same Transaction::drop path.
    seed_stale_principal(&fixture.pool, "alice").await;
    let mut cancelled_connection = fixture.pool.acquire().await.unwrap();
    let mut cancelled_transaction = begin_principal(&mut cancelled_connection, &bea)
        .await
        .unwrap();
    let mut cancelled = Box::pin(
        sqlx::query_scalar::<_, i64>(
            "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x < 5000000) \
         SELECT sum(x) FROM n",
        )
        .fetch_one(&mut *cancelled_transaction),
    );
    tokio::select! {
        result = &mut cancelled => panic!("runaway query unexpectedly completed: {result:?}"),
        _ = tokio::time::sleep(Duration::from_millis(5)) => {}
    }
    drop(cancelled);
    drop(cancelled_transaction);
    drop(cancelled_connection);
    assert!(context_is_empty(&fixture.pool).await);
    assert_eq!(
        prototype_query_sql(
            &fixture.pool,
            &bea,
            "SELECT id FROM records WHERE kind IS NULL AND id <> 'common'"
        )
        .await
        .unwrap(),
        ["bea-private"]
    );
    assert!(context_is_empty(&fixture.pool).await);
}

async fn raw_query(pool: &SqlitePool, sql_text: &str) {
    sqlx::query(sql_text).fetch_all(pool).await.unwrap();
}

async fn elapsed_per_call<F, Fut>(iterations: u32, mut call: F) -> f64
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let started = Instant::now();
    for _ in 0..iterations {
        call().await;
    }
    started.elapsed().as_secs_f64() * 1_000_000.0 / f64::from(iterations)
}

/// Not a stable performance gate; run with `--nocapture` to collect comparable
/// same-process evidence for the implementation report.
#[tokio::test]
async fn benchmark_current_shape_against_transaction_scoped_principal() {
    let fixture = fixture(1).await;
    let alice = QueryPrincipal::authenticated("alice");
    let iterations = 100;
    let current_validation_us = elapsed_per_call(iterations, || async {
        sql::validate("SELECT id FROM records WHERE id='alice-private'").unwrap();
    })
    .await;
    let logical_validation_us = elapsed_per_call(iterations, || async {
        validate_logical("SELECT id FROM records WHERE id='alice-private'").unwrap();
    })
    .await;
    eprintln!(
        "ACL_SPIKE_BENCH validation: current_full_schema={current_validation_us:.1}us spike_logical_schema={logical_validation_us:.1}us (schema sizes differ)"
    );
    let shapes = [
        (
            "record",
            "SELECT id FROM main.records WHERE id='alice-private'",
            "SELECT id FROM records WHERE id='alice-private'",
        ),
        (
            "count",
            "SELECT CAST(count(*) AS TEXT) FROM main.records",
            "SELECT CAST(count(*) AS TEXT) FROM records",
        ),
        (
            "join",
            "SELECT e.id FROM main.content_events e JOIN main.records r ON r.id=e.record_id",
            "SELECT e.id FROM content_events e JOIN records r ON r.id=e.record_id",
        ),
    ];
    for (name, raw, protected) in shapes {
        let raw_us = elapsed_per_call(iterations, || raw_query(&fixture.pool, raw)).await;
        let protected_us = elapsed_per_call(iterations, || async {
            prototype_execute(&fixture.pool, &alice, protected)
                .await
                .unwrap();
        })
        .await;
        eprintln!(
            "ACL_SPIKE_BENCH {name}: raw={raw_us:.1}us protected={protected_us:.1}us overhead={:.1}us ratio={:.2}x",
            protected_us - raw_us,
            protected_us / raw_us
        );
    }

    let raw_fts = elapsed_per_call(iterations, || async {
        raw_query(
            &fixture.pool,
            "SELECT r.id FROM main.records_fts JOIN main.records r \
             ON r.rowid=records_fts.rowid \
             WHERE records_fts MATCH 'sharedterm'",
        )
        .await;
    })
    .await;
    let protected_fts = elapsed_per_call(iterations, || async {
        trusted_fts(&fixture.pool, &alice, "sharedterm")
            .await
            .unwrap();
    })
    .await;
    eprintln!(
        "ACL_SPIKE_BENCH fts: raw={raw_fts:.1}us protected={protected_fts:.1}us overhead={:.1}us ratio={:.2}x",
        protected_fts - raw_fts,
        protected_fts / raw_fts
    );
}
