//! Toolchain smoke test (cargo + tokio + module resolution). Substantive
//! coverage lives in `schema.rs` and `engine.rs`.

use native_ce::schema::DDL_STATEMENTS;
use native_ce::{CURRENT_ENGINE_SCHEMA_VERSION, ENGINE_NAME};
use rusqlite::Connection;

#[test]
fn exposes_the_engine_name() {
    assert_eq!(ENGINE_NAME, "native-ce");
}

#[test]
fn ships_a_non_empty_ddl() {
    assert!(!DDL_STATEMENTS.is_empty());
    assert!(DDL_STATEMENTS
        .iter()
        .any(|s| s.contains("CREATE TABLE content_events")));
}

#[test]
fn exported_ddl_batch_stamps_the_current_semantic_schema() {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            &DDL_STATEMENTS
                .iter()
                .map(|s| format!("{s};\n"))
                .collect::<String>(),
        )
        .unwrap();
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(version, CURRENT_ENGINE_SCHEMA_VERSION);
}
