//! SQLite fold and v75→76 backfill for stored vocabulary metadata JSON.

use sqlx::{Row, SqliteConnection};

use crate::error::{Error, Result};
use crate::json_nodes::{self, Interpretation};

/// Validate the entire source before replacing any node rows. The caller owns
/// the meta-event transaction, so the metadata cell and its nodes commit as one.
pub(crate) async fn replace_sqlite(
    conn: &mut SqliteConnection,
    value_id: &str,
    stored_metadata: &str,
) -> Result<()> {
    let document = json_nodes::extract_json_nodes(stored_metadata, Interpretation::DeclaredJson)
        .map_err(|error| {
            Error::engine(format!(
                "vocabulary metadata JSON projection failed for {value_id}: {error}"
            ))
        })?
        .expect("declared valid JSON always produces a document");

    sqlx::query("DELETE FROM vocabulary_value_json_nodes WHERE value_id=?")
        .bind(value_id)
        .execute(&mut *conn)
        .await?;
    for node in document.nodes {
        sqlx::query(
            "INSERT INTO vocabulary_value_json_nodes
             (value_id,ordinal,path,parent_path,parent_ordinal,member_key,
              array_index,depth,node_type,text_value,number_text,bool_value)
             VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(value_id)
        .bind(node.ordinal as i64)
        .bind(node.path)
        .bind(node.parent_path)
        .bind(node.parent_ordinal.map(|value| value as i64))
        .bind(node.member_key)
        .bind(node.array_index.map(|value| value as i64))
        .bind(node.depth as i64)
        .bind(node.node_type.as_str())
        .bind(node.text_value)
        .bind(node.number_text)
        .bind(node.bool_value.map(i64::from))
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

/// Bounded keyset scan. Any malformed or oversized historical metadata aborts
/// the enclosing migration transaction; no source is silently omitted.
pub(crate) async fn backfill_sqlite(conn: &mut SqliteConnection) -> Result<()> {
    let mut after = String::new();
    loop {
        let row =
            sqlx::query("SELECT id,metadata FROM vocabulary_values WHERE id>? ORDER BY id LIMIT 1")
                .bind(&after)
                .fetch_optional(&mut *conn)
                .await?;
        let Some(row) = row else { break };
        let id: String = row.try_get("id")?;
        let metadata: String = row.try_get("metadata")?;
        replace_sqlite(conn, &id, &metadata).await?;
        after = id;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Connection;

    async fn fixture() -> SqliteConnection {
        let mut conn = SqliteConnection::connect("sqlite::memory:").await.unwrap();
        sqlx::query("PRAGMA foreign_keys=ON")
            .execute(&mut conn)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE vocabulary_values(id TEXT PRIMARY KEY,metadata TEXT NOT NULL)")
            .execute(&mut conn)
            .await
            .unwrap();
        sqlx::query(crate::schema::ddl::VOCABULARY_VALUE_JSON_NODES_DDL)
            .execute(&mut conn)
            .await
            .unwrap();
        conn
    }

    #[tokio::test]
    async fn stored_syntax_keeps_duplicates_lexemes_and_parent_occurrences() {
        let mut conn = fixture().await;
        let source = r#"{"a":{"x":1.00},"a":{"x":2E+09},"~\/":null}"#;
        sqlx::query("INSERT INTO vocabulary_values VALUES('v',?)")
            .bind(source)
            .execute(&mut conn)
            .await
            .unwrap();
        replace_sqlite(&mut conn, "v", source).await.unwrap();
        let rows = sqlx::query(
            "SELECT ordinal,path,parent_ordinal,number_text FROM vocabulary_value_json_nodes WHERE value_id='v' ORDER BY ordinal",
        )
        .fetch_all(&mut conn)
        .await
        .unwrap();
        assert_eq!(rows.len(), 6);
        assert_eq!(rows[2].get::<String, _>("number_text"), "1.00");
        assert_eq!(rows[4].get::<String, _>("number_text"), "2E+09");
        assert_eq!(rows[2].get::<i64, _>("parent_ordinal"), 1);
        assert_eq!(rows[4].get::<i64, _>("parent_ordinal"), 3);
        assert_eq!(rows[5].get::<String, _>("path"), "/~0~1");
        replace_sqlite(&mut conn, "v", "[]").await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vocabulary_value_json_nodes")
            .fetch_one(&mut conn)
            .await
            .unwrap();
        assert_eq!(count, 1);
        let error = replace_sqlite(&mut conn, "v", "{").await.unwrap_err();
        assert!(error.to_string().contains("invalid JSON"));
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vocabulary_value_json_nodes")
            .fetch_one(&mut conn)
            .await
            .unwrap();
        assert_eq!(count, 1, "failed extraction must keep the prior projection");
        sqlx::query("DELETE FROM vocabulary_values WHERE id='v'")
            .execute(&mut conn)
            .await
            .unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vocabulary_value_json_nodes")
            .fetch_one(&mut conn)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn backfill_refuses_oversize_without_partial_rows() {
        let mut conn = fixture().await;
        sqlx::query("INSERT INTO vocabulary_values VALUES('a','{}')")
            .execute(&mut conn)
            .await
            .unwrap();
        let oversize = format!("\"{}\"", "x".repeat(json_nodes::MAX_JSON_SOURCE_BYTES));
        sqlx::query("INSERT INTO vocabulary_values VALUES('b',?)")
            .bind(oversize)
            .execute(&mut conn)
            .await
            .unwrap();
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut conn)
            .await
            .unwrap();
        let error = backfill_sqlite(&mut conn).await.unwrap_err();
        assert!(error.to_string().contains("source exceeds"));
        sqlx::query("ROLLBACK").execute(&mut conn).await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vocabulary_value_json_nodes")
            .fetch_one(&mut conn)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }
}
