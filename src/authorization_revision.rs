//! Integrity checks for the monotonic authorization-revision cache fence.
//!
//! The schema-11 DDL is frozen, so runtime validation derives the authoritative
//! table and trigger definitions directly from that DDL rather than maintaining
//! a second handwritten copy. SQLite removes `IF NOT EXISTS` when persisting
//! schema SQL; normalization accounts only for that and insignificant
//! whitespace. Quoted literals/identifiers and all remaining text retain their
//! case, so a behavior-changing `'account'` → `'ACCOUNT'` edit is rejected.

use std::collections::BTreeMap;

use sqlx::{Row, SqliteConnection};

use crate::db::Db;
use crate::error::Result;
use crate::schema::DDL_STATEMENTS;

pub(crate) const AUTHORIZATION_REVISION_TABLE: &str = "authorization_revision";

pub(crate) const AUTHORIZATION_REVISION_TRIGGERS: [&str; 15] = [
    "authorization_revision_records_insert",
    "authorization_revision_records_delete",
    "authorization_revision_records_update",
    "authorization_revision_record_policies_insert",
    "authorization_revision_record_policies_delete",
    "authorization_revision_record_policies_update",
    "authorization_revision_policy_entries_insert",
    "authorization_revision_policy_entries_delete",
    "authorization_revision_policy_entries_update",
    "authorization_revision_bindings_insert",
    "authorization_revision_bindings_delete",
    "authorization_revision_bindings_update",
    "authorization_revision_links_insert",
    "authorization_revision_links_delete",
    "authorization_revision_links_update",
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
            statement.starts_with("CREATE TABLE IF NOT EXISTS authorization_revision ")
        })
        .expect("frozen DDL contains authorization_revision table");
    expected.insert(
        AUTHORIZATION_REVISION_TABLE,
        ("table", normalized_schema_sql(table)),
    );
    for name in AUTHORIZATION_REVISION_TRIGGERS {
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
          WHERE lower(name) = 'authorization_revision'
             OR lower(name) GLOB 'authorization_revision_*'
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
        let named_objects = actual
            .iter()
            .filter(|(actual_name, _, _)| actual_name == name)
            .collect::<Vec<_>>();
        if named_objects.len() > 1 {
            violations.push(format!(
                "reserved object name appears {} times: {name}",
                named_objects.len()
            ));
        }
        match named_objects.as_slice() {
            [] => violations.push(format!("required {expected_type} missing: {name}")),
            [(_, actual_type, _)] if actual_type.as_str() != *expected_type => violations.push(
                format!("reserved object {name} must be a {expected_type}, found {actual_type}"),
            ),
            [(_, _, None)] => violations.push(format!("reserved object {name} has no SQL")),
            [(_, _, Some(actual_sql))] if normalized_schema_sql(actual_sql) != *expected_sql => {
                violations.push(format!(
                    "reserved object {name} does not match the frozen schema-11 definition"
                ));
            }
            [_] | [_, ..] => {}
        }
    }
    for (name, object_type, _) in &actual {
        match expected.get(name.as_str()) {
            Some((expected_type, _)) if object_type == expected_type => {}
            Some((expected_type, _)) => violations.push(format!(
                "unexpected reserved authorization-revision object: {object_type} {name} (expected {expected_type})"
            )),
            None => violations.push(format!(
                "unexpected reserved authorization-revision object: {object_type} {name}"
            )),
        }
    }

    let table_objects = actual
        .iter()
        .filter(|(name, _, _)| name == AUTHORIZATION_REVISION_TABLE)
        .collect::<Vec<_>>();
    let table_is_exact = match table_objects.as_slice() {
        [(_, object_type, Some(sql))] => {
            let expected_table_sql = &expected[AUTHORIZATION_REVISION_TABLE].1;
            object_type == "table" && normalized_schema_sql(sql) == *expected_table_sql
        }
        _ => false,
    };
    if table_is_exact {
        let rows = sqlx::query(
            "SELECT id, epoch, typeof(id) AS id_type, typeof(epoch) AS epoch_type
               FROM authorization_revision ORDER BY id",
        )
        .fetch_all(&mut *connection)
        .await?;
        if rows.len() != 1 {
            violations.push(format!(
                "authorization_revision must contain exactly one row, found {}",
                rows.len()
            ));
        } else {
            let row = &rows[0];
            let id: i64 = row.try_get("id")?;
            let epoch: i64 = row.try_get("epoch")?;
            let id_type: String = row.try_get("id_type")?;
            let epoch_type: String = row.try_get("epoch_type")?;
            if id != 1 || id_type != "integer" {
                violations.push("authorization_revision singleton id must be integer 1".into());
            }
            if epoch < 0 || epoch_type != "integer" {
                violations.push(
                    "authorization_revision singleton epoch must be a non-negative integer".into(),
                );
            }
        }
    }
    Ok(violations)
}
