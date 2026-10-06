//! SQLite facet-value JSON occurrence projection.
//!
//! Facet values are stored as text and the authored type is erased: a facet
//! written as an object, an array, and a string containing JSON are all just
//! text in `facet_values.value`. This projection flattens stored text that
//! parses as a JSON **object or array**. Bare scalars (including quoted JSON
//! text), malformed text and any value past the extractor's budgets produce no
//! nodes — and never fail the facet write. Every node is a
//! `parsed_text_candidate`: the stored bytes record syntax, not authored type.
use crate::error::Result;
use crate::json_nodes::{self, Interpretation, JsonDocument, NodeType};
use sqlx::{Row, SqliteConnection};

/// Which value shapes flatten. Only object and array roots produce nodes.
fn flattenable(node_type: NodeType) -> bool {
    matches!(node_type, NodeType::Object | NodeType::Array)
}

/// Extract the flattenable document for one stored value, or `None`.
///
/// `None` covers everything that must not fail the write: a non-object/array
/// root, malformed text, and every resource-limit error (`SourceTooLarge`,
/// `TooDeep`, `TooManyNodes`, `ProjectionTooLarge`). The cheap root-byte
/// pre-check avoids parsing ordinary scalar text at all.
pub(crate) fn project(value: &str) -> Option<JsonDocument> {
    let trimmed = value.trim_start();
    if !(trimmed.starts_with('{') || trimmed.starts_with('[')) {
        return None;
    }
    match json_nodes::extract_json_nodes(value, Interpretation::ParsedTextCandidate) {
        Ok(Some(document))
            if document
                .nodes
                .first()
                .is_some_and(|node| flattenable(node.node_type)) =>
        {
            Some(document)
        }
        _ => None,
    }
}

/// Replace every node for one facet in the caller's transaction. A value with
/// no flattenable document leaves the facet with no nodes. The caller owns the
/// transaction, including the source upsert or delete.
pub(crate) async fn replace(
    conn: &mut SqliteConnection,
    facet_id: &str,
    value: Option<&str>,
) -> Result<()> {
    sqlx::query("DELETE FROM facet_value_json_nodes WHERE facet_id=?")
        .bind(facet_id)
        .execute(&mut *conn)
        .await?;
    let Some(value) = value else {
        return Ok(());
    };
    let Some(document) = project(value) else {
        return Ok(());
    };
    for node in document.nodes {
        sqlx::query(
            "INSERT INTO facet_value_json_nodes
            (facet_id,ordinal,path,parent_path,parent_ordinal,member_key,
             array_index,depth,node_type,text_value,number_text,bool_value)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(facet_id)
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

/// Deterministic keyset scan over every current facet. Malformed, scalar and
/// over-budget values are skipped with no nodes rather than aborting the
/// enclosing migration edge or canonical import.
pub(crate) async fn backfill(conn: &mut SqliteConnection) -> Result<()> {
    let mut after: Option<String> = None;
    loop {
        let row = sqlx::query(
            "SELECT id,value FROM facet_values WHERE (? IS NULL OR id>?) ORDER BY id COLLATE BINARY LIMIT 1",
        )
        .bind(&after)
        .bind(&after)
        .fetch_optional(&mut *conn)
        .await?;
        let Some(row) = row else {
            break;
        };
        let id: String = row.try_get("id")?;
        let value: Option<String> = row.try_get("value")?;
        replace(conn, &id, value.as_deref()).await?;
        after = Some(id);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json_nodes::{MAX_JSON_NODES, MAX_JSON_SOURCE_BYTES};

    fn paths(value: &str) -> Option<Vec<(usize, String, NodeType)>> {
        project(value).map(|document| {
            document
                .nodes
                .iter()
                .map(|node| (node.ordinal, node.path.clone(), node.node_type))
                .collect()
        })
    }

    #[test]
    fn only_object_and_array_roots_flatten() {
        assert_eq!(
            paths(r#"{"a":1}"#),
            Some(vec![
                (0, "".into(), NodeType::Object),
                (1, "/a".into(), NodeType::Number)
            ])
        );
        assert_eq!(
            paths("[1,2]"),
            Some(vec![
                (0, "".into(), NodeType::Array),
                (1, "/0".into(), NodeType::Number),
                (2, "/1".into(), NodeType::Number),
            ])
        );
    }

    #[test]
    fn scalars_malformed_and_limits_produce_no_nodes() {
        for value in ["5", "true", "null", "\"plain text\"", "plain text", "{oops"] {
            assert!(project(value).is_none(), "{value}");
        }
        let oversize = format!("{{\"a\":\"{}\"}}", "x".repeat(MAX_JSON_SOURCE_BYTES));
        assert!(project(&oversize).is_none());
        let many = format!("[{}]", vec!["0"; MAX_JSON_NODES + 1].join(","));
        assert!(project(&many).is_none());
    }
}
