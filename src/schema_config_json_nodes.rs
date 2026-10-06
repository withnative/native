//! SQLite schema-config occurrence projection. Source and nodes share the meta transaction.
use crate::error::{Error, Result};
use crate::json_nodes::{self, Interpretation, JsonDocument, NodeType};
use sqlx::{Row, SqliteConnection};

/// Validate before touching source or nodes. Do not parse through Value: Text
/// configs retain duplicate keys and number tokens. Legacy/replayed data must
/// uphold the public writer's object-root invariant too.
pub(crate) fn prepare(source: &str) -> Result<JsonDocument> {
    let document = json_nodes::extract_json_nodes(source, Interpretation::DeclaredJson)
        .map_err(|error| Error::engine(format!("schema_config JSON projection failed: {error}")))?
        .expect("declared JSON produces a document");
    if document.nodes.first().map(|node| node.node_type) != Some(NodeType::Object) {
        return Err(Error::engine("schema_config data must be a JSON object"));
    }
    // Pointer escaping can expand a legal source beyond the governed SQLite
    // value ceiling. Validate every projected TEXT cell before any persistence;
    // keep the shared body/vocabulary extractor and its budgets unchanged.
    // This is a per-cell UTF-8 bound, not a stored-row size cap: operations
    // encoding wider rows and JSON results retain their existing SQL limits.
    let limit = crate::query::sql::MAX_SQLITE_VALUE_BYTES as usize;
    for node in &document.nodes {
        for (column, value) in [
            ("path", Some(node.path.as_str())),
            ("parent_path", node.parent_path.as_deref()),
            ("member_key", node.member_key.as_deref()),
            ("node_type", Some(node.node_type.as_str())),
            ("text_value", node.text_value.as_deref()),
            ("number_text", node.number_text.as_deref()),
        ] {
            if let Some(value) = value {
                if value.len() > limit {
                    return Err(Error::engine(format!(
                        "schema_config JSON projection {column} at ordinal {} exceeds the {limit}-byte SQLite SQL value limit ({} UTF-8 bytes); shorten the key or value",
                        node.ordinal, value.len()
                    )));
                }
            }
        }
    }
    Ok(document)
}

/// The caller owns the transaction, including the source upsert and event.
pub(crate) async fn replace_prepared(
    conn: &mut SqliteConnection,
    config_id: &str,
    document: JsonDocument,
) -> Result<()> {
    sqlx::query("DELETE FROM schema_config_json_nodes WHERE config_id=?")
        .bind(config_id)
        .execute(&mut *conn)
        .await?;
    for node in document.nodes {
        sqlx::query(
            "INSERT INTO schema_config_json_nodes
            (config_id,ordinal,path,parent_path,parent_ordinal,member_key,
             array_index,depth,node_type,text_value,number_text,bool_value)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(config_id)
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

/// Deterministic keyset scan, including the empty text ID permitted by legacy
/// SQLite. Any bad source aborts the enclosing migration edge, never truncates.
pub(crate) async fn backfill(conn: &mut SqliteConnection) -> Result<()> {
    let mut after: Option<String> = None;
    loop {
        let row = sqlx::query("SELECT id,data FROM schema_config WHERE (? IS NULL OR id>?) ORDER BY id COLLATE BINARY LIMIT 1")
            .bind(&after).bind(&after).fetch_optional(&mut *conn).await?;
        let Some(row) = row else {
            break;
        };
        let id: String = row.try_get("id")?;
        let source: String = row.try_get("data")?;
        let document = prepare(&source)?;
        replace_prepared(conn, &id, document).await?;
        after = Some(id);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn invalid_sources() -> Vec<(String, &'static str)> {
    // Inputs and error labels are literal, independent of extraction output.
    // The projection case has a 1KiB key repeated along 32 ancestors, then
    // 100 null siblings: stored source < 256KiB, nodes < 4096, depth < 64,
    // but repeated path + parent_path cells alone exceed 4MiB.
    let key = "k".repeat(1024);
    let prefix = format!("{{\"{key}\":").repeat(32);
    vec![
        ("{".into(), "invalid JSON"),
        ("[]".into(), "must be a JSON object"),
        ("null".into(), "must be a JSON object"),
        ("true".into(), "must be a JSON object"),
        ("1.00".into(), "must be a JSON object"),
        ("\"text\"".into(), "must be a JSON object"),
        (
            format!("{{\"s\":\"{}\"}}", "x".repeat(262_144)),
            "source exceeds",
        ),
        (
            format!("{{\"a\":{}0{}}}", "[".repeat(64), "]".repeat(64)),
            "nesting exceeds",
        ),
        (
            format!("{{\"a\":[{}]}}", vec!["0"; 4095].join(",")),
            "4096 nodes",
        ),
        (
            format!(
                "{prefix}[{}]{}",
                vec!["null"; 100].join(","),
                "}".repeat(32)
            ),
            "projection exceeds",
        ),
        (
            format!("{{\"{}\":0}}", "/".repeat(140_000)),
            "SQLite SQL value limit",
        ),
        (
            format!("{{\"{}\":0}}", "~".repeat(131_072)),
            "SQLite SQL value limit",
        ),
        (
            format!("{{\"{}{}aa\":0}}", "/".repeat(65_535), "é".repeat(65_536)),
            "SQLite SQL value limit",
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_config_projection_sql_value_boundary_counts_utf8_cells() {
        assert_eq!(crate::query::sql::MAX_SQLITE_VALUE_BYTES, 262_144);
        for key in [
            "/".repeat(131_071),
            "~".repeat(131_071),
            format!("{}{}", "/".repeat(65_535), "é".repeat(65_536)),
        ] {
            // Literal UTF-8/pointer arithmetic: the ceiling and the byte below
            // it are admitted; the next byte is refused. The shared extractor
            // still accepts all three because its source/aggregate bounds fit.
            for (suffix, path_bytes) in [("", 262_143), ("a", 262_144), ("aa", 262_145)] {
                let source = format!("{{\"{key}{suffix}\":0}}");
                assert!(source.len() < 262_144);
                let extracted =
                    json_nodes::extract_json_nodes(&source, Interpretation::DeclaredJson)
                        .unwrap()
                        .unwrap();
                assert_eq!(extracted.nodes[1].path.len(), path_bytes);
                if suffix == "aa" {
                    let error = prepare(&source).unwrap_err().to_string();
                    assert!(error.contains("path at ordinal 1"), "{error}");
                    assert!(error.contains("SQLite SQL value limit"), "{error}");
                } else {
                    assert_eq!(prepare(&source).unwrap(), extracted);
                }
            }
        }
    }
}
