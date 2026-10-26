//! Strict, SQL-bounded legacy body readers. These do not coerce payload values.
//!
//! Callers must authorize the record first and pass the connection from their
//! existing snapshot/write transaction. No helper opens or commits a transaction.
//! Budgets cap SQL result cells before transport, not total SQL parsing work.

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sqlx::{Row, SqliteConnection};

use crate::error::{Error, Result};

/// Independent decoded body and encoded unit-content transport budgets.
#[derive(Clone, Copy)]
pub(crate) struct BodyReadLimits {
    pub(crate) body_bytes: usize,
    pub(crate) unit_encoded_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BodyEventRef {
    pub(crate) event_id: String,
    pub(crate) seq: i64,
    pub(crate) event_type: String,
}

impl BodyEventRef {
    pub(crate) fn validate_for(&self, tool: &str) -> Result<()> {
        let refuse = |code: &str| Error::engine(format!("{tool}: {code}"));
        if self.event_id.is_empty()
            || self.event_id.len() > 256
            || self.event_id.chars().any(char::is_control)
        {
            return Err(refuse("invalid_identity"));
        }
        if self.seq <= 0
            || !matches!(
                self.event_type.as_str(),
                "record.created"
                    | "record.updated"
                    | "receipt.committed.v1"
                    | "unit.revision.recorded.v1"
                    | "message.revision.recorded.v1"
            )
        {
            return Err(refuse("invalid_history_reference"));
        }
        Ok(())
    }
}

// serde_json::Value erases duplicates. Reject them recursively BEFORE
// typed deserialization, including nested admission pins and summaries.
pub(crate) struct UniqueJson(pub(crate) Value);

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = UniqueJson;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("unique-key JSON")
            }
            fn visit_bool<E: serde::de::Error>(
                self,
                v: bool,
            ) -> std::result::Result<UniqueJson, E> {
                Ok(UniqueJson(json!(v)))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> std::result::Result<UniqueJson, E> {
                Ok(UniqueJson(json!(v)))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> std::result::Result<UniqueJson, E> {
                Ok(UniqueJson(json!(v)))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> std::result::Result<UniqueJson, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| UniqueJson(Value::Number(n)))
                    .ok_or_else(|| E::custom("nonfinite JSON"))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> std::result::Result<UniqueJson, E> {
                Ok(UniqueJson(json!(v)))
            }
            fn visit_string<E: serde::de::Error>(
                self,
                v: String,
            ) -> std::result::Result<UniqueJson, E> {
                Ok(UniqueJson(Value::String(v)))
            }
            fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<UniqueJson, E> {
                Ok(UniqueJson(Value::Null))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<UniqueJson, A::Error> {
                let mut values = Vec::new();
                while let Some(UniqueJson(v)) = seq.next_element()? {
                    values.push(v);
                }
                Ok(UniqueJson(Value::Array(values)))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<UniqueJson, A::Error> {
                let mut values = Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate JSON key"));
                    }
                    let UniqueJson(value) = map.next_value()?;
                    values.insert(key, value);
                }
                Ok(UniqueJson(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

// No raw payload crosses the SQL cell boundary. BLOB lengths count UTF8
// bytes even across NUL; SQLite text length would truncate that proof.
// Malformed candidate families participate in selection and then refuse.
pub(crate) async fn strict_history_on(
    conn: &mut SqliteConnection,
    target: &str,
    through: i64,
    limits: BodyReadLimits,
    tool: &str,
) -> Result<(BodyEventRef, BodyEventRef, Option<String>)> {
    let refuse = |code: &str| Error::engine(format!("{tool}: {code}"));
    let creations: i64 = sqlx::query_scalar("SELECT count(*) FROM
        (SELECT seq FROM content_events WHERE record_id=? AND type='record.created' AND seq<=? LIMIT 2)")
        .bind(target).bind(through).fetch_one(&mut *conn).await?;
    if creations != 1 {
        return Err(refuse("creation_missing_or_ambiguous"));
    }
    let creation_row = sqlx::query("SELECT id,seq,type,
        CASE WHEN json_valid(payload) THEN json_type(payload) ELSE 'invalid' END AS root_type,
        CASE WHEN json_valid(payload) THEN (SELECT count(*) FROM json_each(payload) WHERE key='body') ELSE 0 END AS body_keys
        FROM content_events WHERE record_id=? AND type='record.created' AND seq<=? LIMIT 1")
        .bind(target).bind(through).fetch_one(&mut *conn).await?;
    if creation_row.try_get::<String, _>("root_type")? != "object"
        || creation_row.try_get::<i64, _>("body_keys")? > 1
    {
        return Err(refuse("malformed_creation"));
    }
    let creation = BodyEventRef {
        event_id: creation_row.try_get("id")?,
        seq: creation_row.try_get("seq")?,
        event_type: creation_row.try_get("type")?,
    };
    let row = sqlx::query("WITH candidate AS (
        SELECT id,seq,type,payload FROM content_events WHERE record_id=? AND seq<=?
        AND type IN ('record.created','record.updated','receipt.committed.v1','unit.revision.recorded.v1','message.revision.recorded.v1')
        AND CASE WHEN json_valid(payload) THEN
            CASE WHEN json_type(payload)='object' THEN
                type IN ('record.created','unit.revision.recorded.v1') OR json_type(payload,'$.body') IS NOT NULL
            ELSE 1 END ELSE 1 END
        ORDER BY seq DESC LIMIT 1
    ), classified AS (
        SELECT id,seq,type,payload,
        CASE WHEN json_valid(payload) THEN json_type(payload) ELSE 'invalid' END AS root_type,
        CASE WHEN json_valid(payload) THEN
            CASE WHEN type='unit.revision.recorded.v1' THEN json_type(payload,'$.content.content') ELSE json_type(payload,'$.body') END
        ELSE 'invalid' END AS body_type
        FROM candidate
    ), fragments AS (
        SELECT *, CASE WHEN body_type='text' THEN
            CASE WHEN type='unit.revision.recorded.v1' THEN json_extract(payload,'$.content.content') ELSE json_extract(payload,'$.body') END
        END AS fragment FROM classified
    ) SELECT id,seq,type,root_type,body_type,
        CASE WHEN body_type='text' THEN length(CAST(fragment AS BLOB)) END AS body_bytes,
        CASE WHEN body_type='text' AND length(CAST(fragment AS BLOB))<=? THEN fragment END AS body,
        CASE WHEN root_type='object' THEN
            (SELECT count(*) FROM json_each(payload) WHERE key=CASE WHEN f.type='unit.revision.recorded.v1' THEN 'content' ELSE 'body' END)
        ELSE 0 END AS key_count,
        CASE WHEN root_type='object' AND type='unit.revision.recorded.v1' AND json_type(payload,'$.content')='object' THEN
            (SELECT count(*) FROM json_each(payload,'$.content') WHERE key='content')
        ELSE 0 END AS nested_count,
        CASE WHEN type='unit.revision.recorded.v1' AND root_type='object' AND body_type='text'
            AND length(CAST(fragment AS BLOB))<=?
            AND length(CAST(payload -> '$.content' AS BLOB))<=? THEN payload -> '$.content' END AS unit_content,
        CASE WHEN type='unit.revision.recorded.v1' AND root_type='object' AND json_type(payload,'$.format')='text'
            AND length(CAST(json_extract(payload,'$.format') AS BLOB))<=256 THEN
            json_extract(payload,'$.format') END AS unit_format,
        CASE WHEN type='unit.revision.recorded.v1' AND root_type='object' AND json_type(payload,'$.semantic_contract_version')='text'
            AND length(CAST(json_extract(payload,'$.semantic_contract_version') AS BLOB))<=256 THEN
            json_extract(payload,'$.semantic_contract_version') END AS unit_semantic,
        CASE WHEN type='unit.revision.recorded.v1' AND root_type='object' AND json_type(payload,'$.content_sha256')='text'
            AND length(CAST(json_extract(payload,'$.content_sha256') AS BLOB))=64 THEN
            json_extract(payload,'$.content_sha256') END AS unit_sha256,
        CASE WHEN type='unit.revision.recorded.v1' AND root_type='object' THEN
            (SELECT count(*)=3 AND count(DISTINCT key)=3 FROM json_each(payload)
                WHERE key IN ('format','semantic_contract_version','content_sha256'))
        ELSE 0 END AS unit_headers_valid
        FROM fragments AS f")
        .bind(target).bind(through).bind(limits.body_bytes as i64).bind(limits.body_bytes as i64).bind(limits.unit_encoded_bytes as i64).fetch_optional(&mut *conn).await?.ok_or_else(|| refuse("inverse_missing"))?;
    let reference = BodyEventRef {
        event_id: row.try_get("id")?,
        seq: row.try_get("seq")?,
        event_type: row.try_get("type")?,
    };
    creation.validate_for(tool)?;
    reference.validate_for(tool)?;
    if reference.seq < creation.seq || row.try_get::<String, _>("root_type")? != "object" {
        return Err(refuse("malformed_history"));
    }
    let kind: Option<String> = row.try_get("body_type")?;
    let keys: i64 = row.try_get("key_count")?;
    let unit = reference.event_type == "unit.revision.recorded.v1";
    if keys > 1 || (unit && (keys != 1 || row.try_get::<i64, _>("nested_count")? != 1)) {
        return Err(refuse("malformed_history"));
    }
    let body = match kind.as_deref() {
        None if reference.event_type == "record.created" && keys == 0 => None,
        Some("null") if !unit && keys == 1 => None,
        Some("text") if keys == 1 => {
            let bytes: i64 = row.try_get("body_bytes")?;
            if bytes > limits.body_bytes as i64 {
                return Err(refuse("body_or_inverse_oversize"));
            }
            let text: String = row.try_get("body")?;
            if text.len() as i64 != bytes {
                return Err(refuse("history_transport_incomplete"));
            }
            Some(text)
        }
        _ => return Err(refuse("malformed_history")),
    };
    if unit {
        let content_json: String = row.try_get("unit_content")?;
        let UniqueJson(value) =
            serde_json::from_str(&content_json).map_err(|_| refuse("malformed_unit_content"))?;
        let content: crate::freshness::UnitContent =
            serde_json::from_value(value).map_err(|_| refuse("malformed_unit_content"))?;
        content.validate()?;
        if body.as_deref() != Some(content.content.as_str())
            || !row.try_get::<bool, _>("unit_headers_valid")?
            || row.try_get::<Option<String>, _>("unit_format")?.as_deref()
                != Some(crate::freshness::UNIT_REVISION_FORMAT)
            || row
                .try_get::<Option<String>, _>("unit_semantic")?
                .as_deref()
                != Some(crate::freshness::SEMANTIC_CONTRACT_VERSION)
            || row.try_get::<Option<String>, _>("unit_sha256")?.as_deref()
                != Some(content.sha256().as_str())
        {
            return Err(refuse("malformed_unit_content"));
        }
    }
    Ok((creation, reference, body))
}

/// One exact pinned HTML body source. Malformed, duplicate, non-text, missing
/// and over-budget sources all remain unavailable. Receipt is a legacy source;
/// unit revisions are deliberately outside this artifact contract.
/// Does not load raw payloads, select a substitute revision, or verify a digest.
pub(crate) async fn exact_html_source_on(
    conn: &mut SqliteConnection,
    record_id: &str,
    event_id: &str,
    body_limit: usize,
) -> Result<Option<String>> {
    Ok(sqlx::query_scalar::<_, Option<String>>(
        "SELECT CASE WHEN json_valid(payload)
            AND json_type(payload,'$.body')='text'
            AND length(CAST(json_extract(payload,'$.body') AS BLOB))<=?
            AND (SELECT count(*) FROM json_each(payload) WHERE key='body')=1
            THEN json_extract(payload,'$.body') END
            FROM content_events WHERE id=? AND record_id=?
            AND type IN ('record.created','record.updated','receipt.committed.v1')",
    )
    .bind(body_limit as i64)
    .bind(event_id)
    .bind(record_id)
    .fetch_optional(conn)
    .await?
    .flatten())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Connection;

    // Deliberately raw legacy rows: store admission would reject malformed JSON.
    async fn log() -> SqliteConnection {
        let mut conn = SqliteConnection::connect(":memory:").await.unwrap();
        sqlx::query("CREATE TABLE content_events(seq INTEGER PRIMARY KEY,id TEXT,record_id TEXT,type TEXT,payload TEXT)")
            .execute(&mut conn).await.unwrap();
        conn
    }

    async fn insert(conn: &mut SqliteConnection, seq: i64, family: &str, raw: &str) {
        sqlx::query("INSERT INTO content_events VALUES(?,?,'record',?,?)")
            .bind(seq)
            .bind(format!("event-{seq}"))
            .bind(family)
            .bind(raw)
            .execute(conn)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn exact_source_refuses_malformed_duplicate_and_oversize_without_substitution() {
        let mut conn = log().await;
        insert(&mut conn, 1, "record.created", r#"{"body":"older"}"#).await;
        for (index, raw) in [
            "broken JSON",
            "[]",
            "{}",
            r#"{"body":null}"#,
            r#"{"body":17}"#,
            r#"{"body":"x","body":"y"}"#,
            r#"{"body":"\u0000汉"}"#,
        ]
        .into_iter()
        .enumerate()
        {
            let seq = index as i64 + 2;
            insert(&mut conn, seq, "record.updated", raw).await;
            // The last case is four UTF-8 bytes despite SQLite length(text)=0.
            assert_eq!(
                exact_html_source_on(&mut conn, "record", &format!("event-{seq}"), 3)
                    .await
                    .unwrap(),
                None
            );
        }
        assert_eq!(
            exact_html_source_on(&mut conn, "record", "event-8", 4)
                .await
                .unwrap()
                .as_deref(),
            Some("\0汉")
        );
        assert_eq!(
            exact_html_source_on(&mut conn, "other", "event-1", 5)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            exact_html_source_on(&mut conn, "record", "missing", 5)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            exact_html_source_on(&mut conn, "record", "event-1", 5)
                .await
                .unwrap()
                .as_deref(),
            Some("older")
        );
        insert(&mut conn, 9, "receipt.committed.v1", r#"{"body":""}"#).await;
        assert_eq!(
            exact_html_source_on(&mut conn, "record", "event-9", 0)
                .await
                .unwrap(),
            Some(String::new())
        );
        insert(
            &mut conn,
            10,
            "unit.revision.recorded.v1",
            r#"{"content":{"content":"unit"}}"#,
        )
        .await;
        assert_eq!(
            exact_html_source_on(&mut conn, "record", "event-10", 10)
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn strict_history_tiny_budgets_pin_horizon_and_refuse_latest_invalid_source() {
        let mut conn = log().await;
        let limits = BodyReadLimits {
            body_bytes: 4,
            unit_encoded_bytes: 1024,
        };
        insert(&mut conn, 1, "record.created", "{}").await;
        insert(
            &mut conn,
            2,
            "receipt.committed.v1",
            r#"{"body":"\u0000汉"}"#,
        )
        .await;
        insert(&mut conn, 3, "record.updated", r#"{"body":null}"#).await;
        insert(&mut conn, 4, "record.updated", r#"{"body":""}"#).await;
        insert(&mut conn, 5, "record.updated", r#"{"summary":"metadata"}"#).await;
        for (through, seq, body) in [
            (1, 1, None),
            (2, 2, Some("\0汉")),
            (3, 3, None),
            (5, 4, Some("")),
        ] {
            let (creation, revision, actual) =
                strict_history_on(&mut conn, "record", through, limits, "fixture")
                    .await
                    .unwrap();
            assert_eq!(creation.seq, 1);
            assert_eq!(
                (revision.seq, revision.event_id),
                (seq, format!("event-{seq}"))
            );
            assert_eq!(actual.as_deref(), body);
        }
        let error = strict_history_on(
            &mut conn,
            "record",
            2,
            BodyReadLimits {
                body_bytes: 3,
                ..limits
            },
            "fixture",
        )
        .await
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("fixture: body_or_inverse_oversize"));
        for (seq, raw) in [
            (6, r#"{"body":"a","body":"b"}"#),
            (7, "broken JSON"),
            (8, r#"{"body":false}"#),
        ] {
            insert(&mut conn, seq, "record.updated", raw).await;
            assert!(
                strict_history_on(&mut conn, "record", seq, limits, "fixture")
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("fixture: malformed_history")
            );
        }
        // A later failure never contaminates the inclusive earlier horizon.
        assert_eq!(
            strict_history_on(&mut conn, "record", 2, limits, "fixture")
                .await
                .unwrap()
                .2
                .as_deref(),
            Some("\0汉")
        );
    }

    #[tokio::test]
    async fn strict_unit_content_requires_independent_encoded_budget_and_unique_digest_bound_shape()
    {
        let mut conn = log().await;
        insert(&mut conn, 1, "record.created", "{}").await;
        let content = crate::freshness::UnitContent::text("unit").unwrap();
        let mut payload = json!({
            "format": crate::freshness::UNIT_REVISION_FORMAT,
            "semantic_contract_version": crate::freshness::SEMANTIC_CONTRACT_VERSION,
            "content_sha256": content.sha256(),
            "content": content,
        });
        insert(
            &mut conn,
            2,
            "unit.revision.recorded.v1",
            &payload.to_string(),
        )
        .await;
        let limits = BodyReadLimits {
            body_bytes: 4,
            unit_encoded_bytes: payload["content"].to_string().len(),
        };
        assert_eq!(
            strict_history_on(&mut conn, "record", 2, limits, "fixture")
                .await
                .unwrap()
                .2
                .as_deref(),
            Some("unit")
        );
        assert!(strict_history_on(
            &mut conn,
            "record",
            2,
            BodyReadLimits {
                unit_encoded_bytes: limits.unit_encoded_bytes - 1,
                ..limits
            },
            "fixture"
        )
        .await
        .is_err());
        payload["content_sha256"] = json!("0".repeat(64));
        insert(
            &mut conn,
            3,
            "unit.revision.recorded.v1",
            &payload.to_string(),
        )
        .await;
        assert!(strict_history_on(&mut conn, "record", 3, limits, "fixture")
            .await
            .unwrap_err()
            .to_string()
            .contains("malformed_unit_content"));
        payload["content_sha256"] = json!(content.sha256());
        // Duplicate a non-body member inside content: path counts alone cannot detect it.
        let raw = payload.to_string().replace(
            r#""content_media_type":"text/plain""#,
            r#""content_media_type":"text/plain","content_media_type":"text/plain""#,
        );
        assert_ne!(raw, payload.to_string());
        insert(&mut conn, 4, "unit.revision.recorded.v1", &raw).await;
        assert!(strict_history_on(
            &mut conn,
            "record",
            4,
            BodyReadLimits {
                unit_encoded_bytes: 1024,
                ..limits
            },
            "fixture"
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("malformed_unit_content"));
    }
}
