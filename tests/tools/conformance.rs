//! The conformance suite's own tests: a conforming database passes, every
//! violation class is detected, probes never mutate the database under test,
//! and the substrate tier stays open (extra tables are tolerated).

use crate::common::count;
use native_ce::conformance::{
    check_frozen_ddl, format_report, run_conformance, CheckResult, ConformanceReport,
};
use native_ce::events::{FacetSetPayload, LinkAddedPayload};
use native_ce::schema::{ddl_sha256, DDL_STATEMENTS, FROZEN_DDL_SHA256};
use native_ce::store::{add_link, create_record, set_facet};
use native_ce::{
    create_database, open_database, open_database_at, open_existing_database_at, Db,
    CURRENT_ENGINE_SCHEMA_VERSION,
};
use serde_json::json;

fn check<'r>(report: &'r ConformanceReport, name: &str) -> &'r CheckResult {
    report
        .checks
        .iter()
        .find(|c| c.check == name)
        .unwrap_or_else(|| panic!("check '{name}' missing from report"))
}

/// Stand up a database from a (possibly doctored) DDL statement list.
async fn db_with(ddl: &[String]) -> Db {
    let db = open_database(":memory:").await.unwrap();
    let mut tx = crate::common::fixture_write_pool(&db)
        .await
        .begin()
        .await
        .unwrap();
    for statement in ddl {
        sqlx::query(statement).execute(&mut *tx).await.unwrap();
    }
    tx.commit().await.unwrap();
    db
}

/// Doctor the DDL by exact-substring replacement, asserting the target existed.
fn doctored(target: &str, replacement: &str) -> Vec<String> {
    let out: Vec<String> = DDL_STATEMENTS
        .iter()
        .map(|s| s.replace(target, replacement))
        .collect();
    assert_ne!(
        out.join(","),
        DDL_STATEMENTS.join(","),
        "doctor target not found: {target}"
    );
    out
}

const TYPE_CHECK: &str =
    "CHECK (type IN ('Document','Program','WorkItem','Outcome','Entity','Collection','Resolution','Conversation','Message','Annotation'))";
const PERSISTENCE_COLUMN: &str =
    "persistence   TEXT NOT NULL DEFAULT 'enduring' CHECK (persistence IN ('enduring','occurrent')),";

// ---- A conforming database passes ----

#[tokio::test]
async fn fresh_install_is_stamped_with_the_current_engine_schema_version() {
    let client = create_database(":memory:").await.unwrap();
    let version: i64 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(client.pool())
        .await
        .unwrap();

    assert_eq!(version, CURRENT_ENGINE_SCHEMA_VERSION);
    client.close().await;
}

#[tokio::test]
async fn passes_on_a_fresh_install_and_does_not_mutate_it() {
    let client = create_database(":memory:").await.unwrap();
    let report = run_conformance(&client).await;
    assert!(report.ok, "{}", format_report(&report));
    for (table, expected) in [
        ("content_events", 2),
        ("records", 2),
        ("links", 0),
        ("facet_values", 0),
        ("facet_observations", 0),
    ] {
        assert_eq!(
            count(&client, &format!("SELECT COUNT(*) AS n FROM {table}")).await,
            expected,
            "probe residue in {table}"
        );
    }
    client.close().await;
}

#[tokio::test]
async fn passes_on_a_database_with_real_data_written_through_the_event_log() {
    let client = create_database(":memory:").await.unwrap();
    let doc = create_record(
        &client,
        json!({ "type": "Document", "kind": "note", "name": "n" }),
    )
    .await
    .unwrap();
    let goal = create_record(
        &client,
        json!({ "type": "Outcome", "kind": "target", "name": "g" }),
    )
    .await
    .unwrap();
    add_link(
        &client,
        LinkAddedPayload {
            id: None,
            source_id: doc.clone(),
            target_id: goal,
            relationship: "implements".into(),
            note: None,
        },
    )
    .await
    .unwrap();
    set_facet(
        &client,
        &doc,
        FacetSetPayload {
            key: "confidence".into(),
            value: Some("likely".into()),
            vocab_ref: None,
            as_of: None,
            observation_only: false,
        },
    )
    .await
    .unwrap();
    let report = run_conformance(&client).await;
    assert!(report.ok, "{}", format_report(&report));
    client.close().await;
}

async fn assert_revision_corruption_rejected(path: &std::path::Path, trigger: &str) {
    let error = open_existing_database_at(path)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("malformed authorization revision state") && error.contains(trigger),
        "{error}"
    );

    let db = open_database_at(path).await.unwrap();
    let report = run_conformance(&db).await;
    assert!(!report.ok, "{}", format_report(&report));
    let revision = check(&report, "authorization-revision-state");
    assert!(!revision.ok);
    assert!(revision.violations.join("\n").contains(trigger));
    db.close().await;
}

#[tokio::test]
async fn schema_twelve_missing_authorization_trigger_fails_open_and_conformance() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing-authorization-trigger.db");
    let db = create_database(&path.to_string_lossy()).await.unwrap();
    sqlx::query("DROP TRIGGER authorization_revision_records_insert")
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    db.close().await;

    assert_revision_corruption_rejected(&path, "authorization_revision_records_insert").await;
}

#[tokio::test]
async fn schema_twelve_duplicate_reserved_table_and_trigger_name_fails_open_and_conformance() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("duplicate-authorization-revision-name.db");
    let db = create_database(&path.to_string_lossy()).await.unwrap();
    sqlx::query(
        "CREATE TRIGGER authorization_revision
           AFTER INSERT ON records BEGIN SELECT 1; END",
    )
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    db.close().await;

    assert_revision_corruption_rejected(&path, "authorization_revision").await;
}

#[tokio::test]
async fn schema_twelve_modified_noop_authorization_trigger_fails_open_and_conformance() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("modified-authorization-trigger.db");
    let db = create_database(&path.to_string_lossy()).await.unwrap();
    let mut connection = crate::common::fixture_write_pool(&db)
        .await
        .acquire()
        .await
        .unwrap();
    sqlx::query("DROP TRIGGER authorization_revision_bindings_update")
        .execute(&mut *connection)
        .await
        .unwrap();
    sqlx::query(
        "CREATE TRIGGER authorization_revision_bindings_update
           AFTER UPDATE ON bindings BEGIN SELECT 1; END",
    )
    .execute(&mut *connection)
    .await
    .unwrap();
    drop(connection);
    db.close().await;

    assert_revision_corruption_rejected(&path, "authorization_revision_bindings_update").await;
}

#[tokio::test]
async fn schema_twelve_modified_trigger_literal_case_fails_open_and_conformance() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("modified-authorization-trigger-literal.db");
    let db = create_database(&path.to_string_lossy()).await.unwrap();
    let mut connection = crate::common::fixture_write_pool(&db)
        .await
        .acquire()
        .await
        .unwrap();
    sqlx::query("DROP TRIGGER authorization_revision_bindings_insert")
        .execute(&mut *connection)
        .await
        .unwrap();
    // Lowercasing the whole definition during comparison would incorrectly
    // accept this semantic mutation even though stored account systems are
    // lowercase and the trigger would therefore never fire.
    sqlx::query(
        "CREATE TRIGGER authorization_revision_bindings_insert AFTER INSERT ON bindings
         WHEN NEW.system = 'ACCOUNT'
         BEGIN UPDATE authorization_revision SET epoch = epoch + 1 WHERE id = 1; END",
    )
    .execute(&mut *connection)
    .await
    .unwrap();
    drop(connection);
    db.close().await;

    assert_revision_corruption_rejected(&path, "authorization_revision_bindings_insert").await;
}

#[tokio::test]
async fn schema_twelve_missing_authorization_revision_singleton_fails_open_and_conformance() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing-authorization-revision-row.db");
    let db = create_database(&path.to_string_lossy()).await.unwrap();
    sqlx::query("DELETE FROM authorization_revision")
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    db.close().await;

    let error = open_existing_database_at(&path)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("must contain exactly one row"), "{error}");
    let db = open_database_at(&path).await.unwrap();
    let report = run_conformance(&db).await;
    let revision = check(&report, "authorization-revision-state");
    assert!(!revision.ok);
    assert!(revision
        .violations
        .join("\n")
        .contains("must contain exactly one row"));
    db.close().await;
}

#[tokio::test]
async fn tolerates_an_extra_table_the_substrate_tier_is_open() {
    let client = create_database(":memory:").await.unwrap();
    // The stress-test's worked example: the quantified-self 'Observation' lands
    // as a narrow-row substrate primitive, NOT as an 8th top-level type.
    sqlx::query("CREATE TABLE observations (series_id TEXT NOT NULL, ts TEXT NOT NULL, value REAL, unit TEXT)")
        .execute(&crate::common::fixture_write_pool(&client).await)
        .await
        .unwrap();
    let report = run_conformance(&client).await;
    assert!(report.ok, "{}", format_report(&report));
    client.close().await;
}

// ---- Every violation class is detected ----

#[tokio::test]
async fn fails_closed_types_when_the_type_check_is_missing_and_flags_rogue_rows() {
    let client = db_with(&doctored(TYPE_CHECK, "CHECK (1 = 1)")).await;
    sqlx::query("INSERT INTO records (id, type) VALUES ('r1', 'Recipe')")
        .execute(&crate::common::fixture_write_pool(&client).await)
        .await
        .unwrap();
    let report = run_conformance(&client).await;
    assert!(!report.ok);
    let closed = check(&report, "closed-types");
    assert!(!closed.ok);
    let text = closed.violations.join("\n");
    assert!(
        text.contains("non-spine top-level type was accepted"),
        "{text}"
    );
    assert!(text.contains("non-spine type 'Recipe'"), "{text}");
    assert!(!check(&report, "substrate-boundary").ok);
    client.close().await;
}

#[tokio::test]
async fn fails_spine_facets_when_persistence_is_nullable_unchecked() {
    let client = db_with(&doctored(PERSISTENCE_COLUMN, "persistence   TEXT,")).await;
    sqlx::query("INSERT INTO records (id, type, persistence) VALUES ('r1', 'Entity', NULL)")
        .execute(&crate::common::fixture_write_pool(&client).await)
        .await
        .unwrap();
    let report = run_conformance(&client).await;
    let facets = check(&report, "spine-facets");
    assert!(!facets.ok);
    let text = facets.violations.join("\n");
    assert!(text.contains("NOT NULL"), "{text}");
    assert!(text.contains("NULL persistence was accepted"), "{text}");
    assert!(text.contains("invalid persistence value"), "{text}");
    client.close().await;
}

#[tokio::test]
async fn fails_closed_types_when_records_type_is_nullable() {
    // A CHECK alone passes NULL.
    let client = db_with(&doctored(
        "type          TEXT NOT NULL,",
        "type          TEXT,",
    ))
    .await;
    sqlx::query("INSERT INTO records (id, type) VALUES ('r1', NULL)")
        .execute(&crate::common::fixture_write_pool(&client).await)
        .await
        .unwrap();
    let report = run_conformance(&client).await;
    assert!(!report.ok);
    let closed = check(&report, "closed-types");
    assert!(!closed.ok);
    let text = closed.violations.join("\n");
    assert!(text.contains("records.type must be NOT NULL"), "{text}");
    assert!(text.contains("NULL type was accepted"), "{text}");
    assert!(text.contains("NULL (untyped)"), "{text}");
    client.close().await;
}

#[tokio::test]
async fn reports_not_crashes_when_a_spine_facet_column_is_missing_entirely() {
    let client = db_with(&doctored(PERSISTENCE_COLUMN, "")).await;
    let report = run_conformance(&client).await;
    assert!(!report.ok);
    let facets = check(&report, "spine-facets");
    assert!(!facets.ok);
    let text = facets.violations.join("\n");
    assert!(
        text.contains("spine facet 'persistence' has no column"),
        "{text}"
    );
    client.close().await;
}

#[tokio::test]
async fn fails_required_tables_when_a_required_table_is_missing() {
    for table in ["jobs", "occurrences"] {
        let client = create_database(":memory:").await.unwrap();
        sqlx::query(&format!("DROP TABLE {table}"))
            .execute(&crate::common::fixture_write_pool(&client).await)
            .await
            .unwrap();
        let report = run_conformance(&client).await;
        let tables = check(&report, "required-tables");
        assert!(!tables.ok);
        assert!(tables
            .violations
            .contains(&format!("required table missing: {table}")));
        client.close().await;
    }
}

#[tokio::test]
async fn fails_event_log_shape_when_either_log_loses_a_contract_column() {
    // `doctored` rewrites every DDL statement, and both logs declare `actor` —
    // so this strips it from content_events AND meta_events, and BOTH shape
    // checks must fail. Asserting both is the point: the meta log is held to the
    // same contract as the content log (ba9f97e), and a check that only ever
    // fired for one tier would let the other's shape rot unnoticed.
    let without_content_actor = doctored("actor                   TEXT,", "");
    let without_either_actor = without_content_actor
        .into_iter()
        .map(|statement| statement.replace("actor      TEXT,", ""))
        .collect::<Vec<_>>();
    let client = db_with(&without_either_actor).await;
    let report = run_conformance(&client).await;

    let shape = check(&report, "event-log-shape");
    assert!(!shape.ok);
    assert!(shape
        .violations
        .contains(&"content_events column missing: actor".to_string()));

    let meta_shape = check(&report, "meta-event-log-shape");
    assert!(!meta_shape.ok);
    assert!(meta_shape
        .violations
        .contains(&"meta_events column missing: actor".to_string()));

    client.close().await;
}

#[tokio::test]
async fn reports_not_panics_when_the_event_log_carries_undecodable_values() {
    // A malformed log (TEXT in `events.seq`) must land in the report as a
    // rebuild-and-diff violation — the suite's contract is a report + exit
    // code, never a crash (a bare `Row::get` here panicked on decode).
    let client = db_with(&doctored(
        "seq                     INTEGER PRIMARY KEY AUTOINCREMENT,",
        "seq                     TEXT,",
    ))
    .await;
    sqlx::query(
        "INSERT INTO content_events (seq, id, record_id, type, payload, actor, created_at, causal_envelope_version, causal_status)
          VALUES ('not-a-number', 'e1', 'r1', 'record.created', '{}', NULL, '2026-01-01T00:00:00.000Z', 1, 'legacy_unknown')",
    )
    .execute(&crate::common::fixture_write_pool(&client).await)
    .await
    .unwrap();
    let report = run_conformance(&client).await;
    assert!(!report.ok);
    let drift = check(&report, "rebuild-and-diff");
    assert!(!drift.ok);
    assert!(
        drift
            .violations
            .join("\n")
            .contains("could not be replayed"),
        "{}",
        drift.violations.join("\n")
    );
    client.close().await;
}

#[tokio::test]
async fn fails_rebuild_and_diff_on_projection_drift() {
    // An ad-hoc UPDATE outside the log.
    let client = create_database(":memory:").await.unwrap();
    let id = create_record(
        &client,
        json!({ "type": "WorkItem", "kind": "task", "name": "honest" }),
    )
    .await
    .unwrap();
    sqlx::query("UPDATE records SET name = 'hacked' WHERE id = ?")
        .bind(&id)
        .execute(&crate::common::fixture_write_pool(&client).await)
        .await
        .unwrap();
    let report = run_conformance(&client).await;
    assert!(!report.ok);
    let drift = check(&report, "rebuild-and-diff");
    assert!(!drift.ok);
    assert!(drift.violations.join("\n").contains("drift in 'records'"));
    client.close().await;
}

// ---- The freeze ----

#[test]
fn the_compiled_ddl_hashes_to_the_current_fingerprint() {
    assert_eq!(ddl_sha256(), FROZEN_DDL_SHA256);
    assert!(check_frozen_ddl().ok);
}

#[test]
fn frozen_records_ddl_carries_the_projected_claim_contract() {
    let ddl = DDL_STATEMENTS.join("\n;\n");
    assert!(ddl.contains("claimed_by_account TEXT"));
    assert!(ddl.contains("claimed_run_key    TEXT"));
    assert!(ddl.contains("claimed_at         TEXT"));
    assert!(ddl.contains(
        "CHECK ((claimed_by_account IS NULL AND claimed_run_key IS NULL AND claimed_at IS NULL)"
    ));
    assert!(ddl.contains(
        "ON records(claimed_by_account, claimed_at DESC)\n       WHERE claimed_by_account IS NOT NULL AND deleted_at IS NULL"
    ));
    assert!(ddl.ends_with("PRAGMA user_version = 50"));
}

#[test]
fn frozen_content_log_ddl_carries_versioned_causality_without_seq_overclaim() {
    let ddl = DDL_STATEMENTS.join("\n;\n");
    assert!(ddl
        .contains("causal_envelope_version INTEGER NOT NULL CHECK (causal_envelope_version = 1)"));
    assert!(ddl.contains(
        "causal_status           TEXT NOT NULL CHECK (causal_status IN ('complete','import_incomplete','legacy_unknown'))"
    ));
    assert!(ddl.contains("CREATE TABLE content_event_causal_frontier"));
    assert!(ddl.contains("parent_event_id TEXT NOT NULL"));
    assert!(!ddl.contains("parent_event_id TEXT NOT NULL REFERENCES content_events"));
    assert!(ddl.contains("CREATE TABLE content_event_causal_cutover"));
    assert!(ddl.contains("VALUES (1,0,strftime('%Y-%m-%dT%H:%M:%fZ','now'),NULL)"));
}
