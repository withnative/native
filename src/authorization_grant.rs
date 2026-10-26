//! Integrity checks for the grant-only realtime authorization revision.
//!
//! The workspace grant epoch remains a wake-up and cache fence. Hosted v1
//! streams hash subject-addressed counters instead. Both sets of frozen
//! objects are validated here: missing counters or classification triggers
//! must never silently suppress a revocation prompt.

use std::collections::BTreeMap;

use sqlx::{Row, SqliteConnection};

use crate::db::Db;
use crate::error::Result;
use crate::schema::DDL_STATEMENTS;

pub(crate) const GRANT_REVISION_TABLE: &str = "authorization_grant_revision";

pub(crate) const GRANT_REVISION_TRIGGERS: [&str; 17] = [
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
];

fn normalized_schema_sql(sql: &str) -> String {
    sql.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replacen("CREATE TABLE IF NOT EXISTS ", "CREATE TABLE ", 1)
        .replacen("CREATE TRIGGER IF NOT EXISTS ", "CREATE TRIGGER ", 1)
}

fn expected_objects() -> BTreeMap<&'static str, (&'static str, String)> {
    let mut expected = BTreeMap::new();
    let table = DDL_STATEMENTS
        .iter()
        .find(|statement| {
            statement.starts_with("CREATE TABLE IF NOT EXISTS authorization_grant_revision ")
        })
        .expect("frozen DDL contains authorization_grant_revision table");
    expected.insert(
        GRANT_REVISION_TABLE,
        ("table", normalized_schema_sql(table)),
    );
    for name in GRANT_REVISION_TRIGGERS {
        let prefix = format!("CREATE TRIGGER IF NOT EXISTS {name}");
        let statement = DDL_STATEMENTS
            .iter()
            .find(|statement| {
                statement
                    .strip_prefix(&prefix)
                    .is_some_and(|suffix| suffix.chars().next().is_some_and(char::is_whitespace))
            })
            .unwrap_or_else(|| panic!("frozen DDL contains {name}"));
        expected.insert(name, ("trigger", normalized_schema_sql(statement)));
    }
    for statement in crate::schema::ddl::AUTHORIZATION_SUBJECT_DDL {
        let kind = if statement.starts_with("CREATE TABLE ") {
            "table"
        } else if statement.starts_with("CREATE TRIGGER ") {
            "trigger"
        } else {
            continue;
        };
        let name = statement
            .strip_prefix("CREATE TABLE ")
            .or_else(|| statement.strip_prefix("CREATE TRIGGER IF NOT EXISTS "))
            .expect("subject DDL")
            .split_whitespace()
            .next()
            .unwrap();
        expected.insert(name, (kind, normalized_schema_sql(statement)));
    }
    expected
}

/// Reject every reserved object that could make current `IF NOT EXISTS`
/// creation silently skip the canonical table or one of its triggers.
pub(crate) async fn state_violations(db: &Db) -> Result<Vec<String>> {
    let mut connection = db.write_pool().acquire().await?;
    state_violations_on(&mut connection).await
}

pub(crate) async fn state_violations_on(connection: &mut SqliteConnection) -> Result<Vec<String>> {
    let expected = expected_objects();
    let rows = sqlx::query(
        "SELECT type, name, sql FROM sqlite_schema
          WHERE lower(name) = 'authorization_grant_revision'
             OR lower(name) GLOB 'authorization_grant_*'
             OR lower(name) GLOB 'authorization_subject_*'
          ORDER BY name, type",
    )
    .fetch_all(&mut *connection)
    .await?;
    let actual = rows
        .into_iter()
        .map(|row| {
            Ok((
                row.try_get::<String, _>("name")?,
                row.try_get::<String, _>("type")?,
                row.try_get::<Option<String>, _>("sql")?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut violations = Vec::new();
    for (name, (expected_type, expected_sql)) in &expected {
        let named = actual
            .iter()
            .filter(|(actual_name, _, _)| actual_name == name)
            .collect::<Vec<_>>();
        if named.len() > 1 {
            violations.push(format!(
                "reserved object name appears {} times: {name}",
                named.len()
            ));
        }
        match named.as_slice() {
            [] => violations.push(format!("required {expected_type} missing: {name}")),
            [(_, actual_type, _)] if actual_type.as_str() != *expected_type => violations.push(
                format!("reserved object {name} must be a {expected_type}, found {actual_type}"),
            ),
            [(_, _, None)] => violations.push(format!("reserved object {name} has no SQL")),
            [(_, _, Some(actual_sql))] if normalized_schema_sql(actual_sql) != *expected_sql => {
                violations.push(format!(
                    "reserved object {name} does not match the frozen engine-66 definition"
                ));
            }
            [_] | [_, ..] => {}
        }
    }
    for (name, object_type, _) in &actual {
        match expected.get(name.as_str()) {
            Some((expected_type, _)) if object_type == expected_type => {}
            Some((expected_type, _)) => violations.push(format!(
                "unexpected reserved grant-revision object: {object_type} {name} (expected {expected_type})"
            )),
            None => violations.push(format!(
                "unexpected reserved grant-revision object: {object_type} {name}"
            )),
        }
    }
    if actual
        .iter()
        .any(|(name, kind, _)| name == "authorization_subject_revision" && kind == "table")
    {
        let global: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM authorization_subject_revision WHERE subject_kind = 'global' AND subject_id = '' AND typeof(revision) = 'integer' AND revision >= 0").fetch_one(&mut *connection).await?;
        if global != 1 {
            violations.push("subject revision requires its global row".into());
        }
        let invalid: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM authorization_subject_revision WHERE typeof(revision) != 'integer' OR revision < 0").fetch_one(&mut *connection).await?;
        if invalid != 0 {
            violations.push("invalid subject revision counter".into());
        }
    }
    for table in [
        "authorization_subject_births",
        "authorization_subject_birth_fence",
    ] {
        if actual
            .iter()
            .any(|(name, kind, _)| name == table && kind == "table")
        {
            let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
                .fetch_one(&mut *connection)
                .await?;
            if count != 0 {
                violations.push(format!(
                    "transaction-only authorization state persisted: {table}"
                ));
            }
        }
    }
    let table_objects = actual
        .iter()
        .filter(|(name, _, _)| name == GRANT_REVISION_TABLE)
        .collect::<Vec<_>>();
    let table_is_exact = match table_objects.as_slice() {
        [(_, object_type, Some(sql))] => {
            let expected_table_sql = &expected[GRANT_REVISION_TABLE].1;
            object_type == "table" && normalized_schema_sql(sql) == *expected_table_sql
        }
        _ => false,
    };
    if table_is_exact {
        let rows = sqlx::query(
            "SELECT id, epoch, typeof(id) AS id_type, typeof(epoch) AS epoch_type
               FROM authorization_grant_revision ORDER BY id",
        )
        .fetch_all(&mut *connection)
        .await?;
        if rows.len() != 1 {
            violations.push(format!(
                "authorization_grant_revision must contain exactly one row, found {}",
                rows.len()
            ));
        } else {
            let row = &rows[0];
            let id: i64 = row.try_get("id")?;
            let epoch: i64 = row.try_get("epoch")?;
            let id_type: String = row.try_get("id_type")?;
            let epoch_type: String = row.try_get("epoch_type")?;
            if id != 1 || id_type != "integer" {
                violations
                    .push("authorization_grant_revision singleton id must be integer 1".into());
            }
            if epoch < 0 || epoch_type != "integer" {
                violations.push(
                    "authorization_grant_revision singleton epoch must be a non-negative integer"
                        .into(),
                );
            }
        }
    }
    Ok(violations)
}

/// Only governed composed creation calls this, before record.created. SQLite
/// serializes writers, and the deferred impossible FK prevents an uncleared
/// certification from being committed or reused by another transaction.
/// Existing dependents decline certification, conservatively retaining global
/// prompts. Every probe is indexed; no visibility evaluation is involved.
pub(crate) async fn certify_birth_on(conn: &mut SqliteConnection, id: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO authorization_subject_births(record_id)
        SELECT ?1
        WHERE (SELECT foreign_keys FROM pragma_foreign_keys) = 1
          AND NOT EXISTS (SELECT 1 FROM records WHERE id = ?1)
          AND NOT EXISTS (SELECT 1 FROM records WHERE home_id = ?1 AND deleted_at IS NULL)
          AND NOT EXISTS (SELECT 1 FROM records WHERE policy_anchor_id = ?1)
          AND NOT EXISTS (SELECT 1 FROM links WHERE target_id = ?1 AND relationship = 'part_of')
          AND NOT EXISTS (SELECT 1 FROM semantic_units WHERE authority_bearer_record_id = ?1)",
    )
    .bind(id)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

pub(crate) async fn finish_birth_on(conn: &mut SqliteConnection, id: &str) -> Result<()> {
    sqlx::query("DELETE FROM authorization_subject_births WHERE record_id = ?")
        .bind(id)
        .execute(conn)
        .await?;
    Ok(())
}

#[cfg(test)]
mod subject_tests {
    use super::*;
    use crate::authorization::{replace_explicit_policy, AllowEntry, Capability};

    async fn revisions(db: &Db) -> Vec<(String, String, i64)> {
        sqlx::query_as("SELECT subject_kind, subject_id, revision FROM authorization_subject_revision ORDER BY subject_kind, subject_id")
            .fetch_all(db.pool()).await.unwrap()
    }

    #[tokio::test]
    async fn subject_policy_diff_preserves_identical_and_addresses_both_update_subjects() {
        let db = crate::create_database(":memory:").await.unwrap();
        let id = crate::store::create_record(
            &db,
            serde_json::json!({"type":"Document","kind":"note","name":"subject test"}),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:subject",
            &id,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();
        let before = revisions(&db).await;
        replace_explicit_policy(
            &db,
            "test:subject",
            &id,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();
        assert_eq!(revisions(&db).await, before);
        let global = before
            .iter()
            .find(|(kind, _, _)| kind == "global")
            .unwrap()
            .2;
        sqlx::query("UPDATE policy_entries SET subject_id='bob' WHERE policy_anchor_id=? AND subject_id='alice'").bind(&id).execute(db.write_pool()).await.unwrap();
        let after = revisions(&db).await;
        assert_eq!(
            after
                .iter()
                .find(|(kind, _, _)| kind == "global")
                .unwrap()
                .2,
            global
        );
        assert!(after
            .iter()
            .any(|(_, account, revision)| account == "alice" && *revision == 2));
        assert!(after
            .iter()
            .any(|(_, account, revision)| account == "bob" && *revision == 1));
        assert!(state_violations(&db).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn subject_migration_and_integrity_are_required() {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut conn = db.write_pool().acquire().await.unwrap();
        crate::schema::step_down::step_down(&mut conn, 90)
            .await
            .unwrap();
        let edge = crate::migrations::EngineMigrationRegistry::production();
        let pending = edge.pending(90, 91).unwrap();
        assert_eq!(pending.len(), 1);
        pending[0].preflight(&mut conn).await.unwrap();
        pending[0].apply(&mut conn).await.unwrap();
        assert!(crate::db::validate_engine_shape_on_for_test(&mut conn, 91)
            .await
            .unwrap());
        assert!(state_violations_on(&mut conn).await.unwrap().is_empty());
        sqlx::query("DELETE FROM authorization_subject_revision WHERE subject_kind='global'")
            .execute(&mut *conn)
            .await
            .unwrap();
        assert!(!state_violations_on(&mut conn).await.unwrap().is_empty());
    }
    #[tokio::test]
    async fn subject_birth_marker_cannot_escape_transaction_and_existing_rows_stay_global() {
        let db = crate::create_database(":memory:").await.unwrap();
        let id = "adf7a000-0000-4000-8000-000000000001";
        let mut tx = db.write_pool().begin().await.unwrap();
        certify_birth_on(&mut tx, id).await.unwrap();
        assert!(
            tx.commit().await.is_err(),
            "a forgotten marker must refuse COMMIT"
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM authorization_subject_births")
                .fetch_one(db.pool())
                .await
                .unwrap(),
            0
        );

        let existing = crate::store::create_record(
            &db,
            serde_json::json!({"type":"Document","kind":"note","name":"existing dependency"}),
        )
        .await
        .unwrap();
        let mut tx = db.write_pool().begin().await.unwrap();
        certify_birth_on(&mut tx, id).await.unwrap();
        sqlx::query("INSERT INTO records(id,type,kind,policy_anchor_id) VALUES(?,'Document','note','native:root')").bind(id).execute(&mut *tx).await.unwrap();
        let before: i64 = sqlx::query_scalar(
            "SELECT revision FROM authorization_subject_revision WHERE subject_kind='global'",
        )
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO record_policies(record_id,created_at) VALUES(?,'2026-10-22T00:00:00Z')",
        )
        .bind(id)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query("UPDATE records SET policy_anchor_id=? WHERE id=?")
            .bind(id)
            .bind(id)
            .execute(&mut *tx)
            .await
            .unwrap();
        let after: i64 = sqlx::query_scalar(
            "SELECT revision FROM authorization_subject_revision WHERE subject_kind='global'",
        )
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        assert_eq!(
            before, after,
            "certified birth initializes only its own boundary"
        );
        sqlx::query("UPDATE records SET policy_anchor_id=? WHERE id=?")
            .bind(id)
            .bind(&existing)
            .execute(&mut *tx)
            .await
            .unwrap();
        let changed: i64 = sqlx::query_scalar(
            "SELECT revision FROM authorization_subject_revision WHERE subject_kind='global'",
        )
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        assert!(changed > after, "an existing dependent stays global");
        finish_birth_on(&mut tx, id).await.unwrap();
        tx.commit().await.unwrap();
        assert!(state_violations(&db).await.unwrap().is_empty());

        let mut tx = db.write_pool().begin().await.unwrap();
        certify_birth_on(&mut tx, id).await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM authorization_subject_births")
                .fetch_one(&mut *tx)
                .await
                .unwrap(),
            0,
            "existing records cannot certify again"
        );
    }
    #[tokio::test]
    async fn subject_unit_insert_requires_certification_and_later_bearer_changes_are_global() {
        let db = crate::create_database(":memory:").await.unwrap();
        let bearer = crate::store::create_record(
            &db,
            serde_json::json!({"type":"Document","kind":"note","name":"bearer"}),
        )
        .await
        .unwrap();
        let events: Vec<(String, i64)> =
            sqlx::query_as("SELECT id, seq FROM content_events ORDER BY seq LIMIT 2")
                .fetch_all(db.pool())
                .await
                .unwrap();
        for (index, (id, certified)) in [
            ("adf7a000-0000-4000-8000-000000000002", true),
            ("adf7a000-0000-4000-8000-000000000003", false),
        ]
        .into_iter()
        .enumerate()
        {
            let event = &events[index];
            let mut tx = db.write_pool().begin().await.unwrap();
            if certified {
                certify_birth_on(&mut tx, id).await.unwrap();
            }
            sqlx::query("INSERT INTO records(id,type,kind,policy_anchor_id) VALUES(?,'Entity','semantic-unit','native:root')").bind(id).execute(&mut *tx).await.unwrap();
            let before: i64 = sqlx::query_scalar(
                "SELECT revision FROM authorization_subject_revision WHERE subject_kind='global'",
            )
            .fetch_one(&mut *tx)
            .await
            .unwrap();
            sqlx::query("INSERT INTO semantic_units(unit_id,authority_bearer_record_id,creation_event_id,creation_event_seq,created_at) VALUES(?,?,?,?, '2026-10-22T00:00:00Z')")
                .bind(id).bind(&bearer).bind(&event.0).bind(event.1).execute(&mut *tx).await.unwrap();
            let after: i64 = sqlx::query_scalar(
                "SELECT revision FROM authorization_subject_revision WHERE subject_kind='global'",
            )
            .fetch_one(&mut *tx)
            .await
            .unwrap();
            assert_eq!(after > before, !certified);
            finish_birth_on(&mut tx, id).await.unwrap();
            tx.commit().await.unwrap();
        }
        let before = revisions(&db).await;
        sqlx::query("UPDATE semantic_units SET authority_bearer_record_id='native:root' WHERE unit_id='adf7a000-0000-4000-8000-000000000002'").execute(db.write_pool()).await.unwrap();
        assert_ne!(revisions(&db).await, before);
    }
}
