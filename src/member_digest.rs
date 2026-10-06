//! Member content digest (contract c323277 rev 4 §1.4).
//!
//! `content_digest = SHA-256(JCS([profile_id, member_schema_digest,
//! T_1, …, T_n]))`, computed over a member-profile SQLite connection by the
//! producer at the cut and recomputed by the consumer at admission (§3.4).
//! Both sides call [`content_digest`], so the encoding below is the whole
//! agreement.
//!
//! - Tables: shipped tables ([`shipped_tables`], i.e.
//!   `MEMBER_TABLE_DISPOSITIONS` order restricted to Included / CallerBound /
//!   ServerComputed), each as `[table_name, rows]`. Derived indexes
//!   (`records_fts`, `records_name_idx`), the manifest's capture times and
//!   `own_writes` never enter: the first are not shipped tables, the rest
//!   are not table values at all.
//! - Rows: sorted by primary key (discovered via `PRAGMA table_info`, all
//!   keys ascending), each row the array of every shipped column in
//!   allowlist order (member-only physical columns appended last, as the
//!   read schema emits them).
//! - Values, tagged by SQLite storage class (JCS renders REAL 5.0 as
//!   `5`, identical to INTEGER 5, so every cell carries its class):
//!   - NULL → JSON null;
//!   - INTEGER → `["i", "<decimal>"]`: i64 decimal is lossless at any
//!     magnitude, so there is no 2^53 limit;
//!   - REAL → `["r", "<text>"]` where `<text>` is the ECMAScript
//!     Number-to-String form of the f64 (RFC 8785 §3.2.2.3), i.e. exactly
//!     the text JCS itself uses for that number — reproducible without
//!     Rust from any conforming JCS/ES implementation. In particular
//!     `1e21` is `"1e+21"` (never a 22-digit expansion) and `-0.0` is
//!     `"0"`, so `-0.0` and `0.0` digest identically, as JCS does.
//!     Non-finite values (NaN/±inf, which JCS rejects) are a
//!     [`ContentDigestError`], never silently digested;
//!   - TEXT → `["t", <string>]`, verbatim;
//!   - BLOB `blobs.bytes` → `["b", <sha256-or-null>]`: the row's `sha256`
//!     TEXT value (or null): inline bytes are covered by `sha256` (§1.4),
//!     so the digest never reads multi-megabyte bodies to compare
//!     generations;
//!   - any other BLOB cell (none in the v1 profile) → `["b",
//!     "<hex-sha256>"]` of its bytes. A NULL cell of any type (including
//!     a null BLOB) is plain JSON `null`, never `["b", null]`.
//! - The top-level array is JCS-serialised (RFC 8785) and the digest is the
//!   lowercase hex SHA-256 of those bytes. A hidden change that touches a
//!   shipped value (visible timestamps, display-reference lengths) moves
//!   the digest: allowed timing disclosure (R1a, S1).

use rusqlite::types::Value as SqliteValue;
use sha2::Digest as _;

use crate::canonical_json::digest_json;
use crate::schema::member_classification::shipped_column_order;
use crate::schema::member_schema::{member_schema_digest, shipped_tables};

/// Profile id component of the digest input.
pub const MEMBER_CONTENT_PROFILE_ID: &str = "member-read-v1";

/// Typed digest failure. The digest runs in the hosted producer, so it
/// returns errors instead of panicking; both sides fail closed on them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContentDigestError {
    /// A REAL cell is NaN or ±infinity, which JCS cannot carry. Carries
    /// the row's primary key so the producer can identify the row.
    NonFiniteReal {
        table: String,
        column: String,
        pk: String,
    },
    /// The member connection did not answer (missing table, unreadable
    /// row, keyless table). Never a value judgment: only plumbing.
    Storage { table: String, detail: String },
}

impl std::fmt::Display for ContentDigestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonFiniteReal { table, column, pk } => write!(
                f,
                "content digest: non-finite REAL {table}.{column} at pk {pk}"
            ),
            Self::Storage { table, detail } => {
                write!(f, "content digest: cannot read {table}: {detail}")
            }
        }
    }
}

/// Primary-key columns of a member table, in key order, via `PRAGMA
/// table_info`. Every shipped table has a primary key by construction.
fn primary_key_columns(
    conn: &rusqlite::Connection,
    table: &str,
) -> Result<Vec<String>, ContentDigestError> {
    let storage = |detail: String| ContentDigestError::Storage {
        table: table.to_owned(),
        detail,
    };
    let mut keyed: Vec<(i64, String)> = conn
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(|e| storage(e.to_string()))?
        .query_map([], |row| {
            let name: String = row.get(1)?;
            let pk: i64 = row.get(5)?;
            Ok((pk, name))
        })
        .map_err(|e| storage(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| storage(e.to_string()))?
        .into_iter()
        .filter(|(pk, _)| *pk > 0)
        .collect();
    keyed.sort();
    let keys: Vec<String> = keyed.into_iter().map(|(_, name)| name).collect();
    if keys.is_empty() {
        return Err(storage("no primary key".to_owned()));
    }
    Ok(keys)
}

fn quote_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// Physical column order of a member table: allowlist order with the
/// member-only physical columns appended, matching the read schema.
fn digest_columns(table: &str) -> Vec<String> {
    let mut columns: Vec<String> = shipped_column_order(table)
        .into_iter()
        .map(str::to_owned)
        .collect();
    if table == "blobs" {
        columns.push(crate::schema::member_schema::EXTERNAL_REF_WITHHELD_COLUMN.to_owned());
    }
    columns
}

/// Diagnostic rendering of one cell (primary-key context in errors).
fn format_cell(value: &SqliteValue) -> String {
    match value {
        SqliteValue::Null => "null".to_owned(),
        SqliteValue::Integer(int) => int.to_string(),
        SqliteValue::Real(real) => real.to_string(),
        SqliteValue::Text(text) => text.clone(),
        SqliteValue::Blob(bytes) => hex::encode(sha2::Sha256::digest(bytes)),
    }
}

fn encode_cell(
    table: &str,
    column: &str,
    pk: &str,
    value: SqliteValue,
    row_sha256: &Option<String>,
) -> Result<serde_json::Value, ContentDigestError> {
    let tag = |t: &str, v: serde_json::Value| serde_json::json!([t, v]);
    Ok(match value {
        SqliteValue::Null => serde_json::Value::Null,
        SqliteValue::Integer(int) => tag("i", int.to_string().into()),
        SqliteValue::Real(real) => {
            if !real.is_finite() {
                return Err(ContentDigestError::NonFiniteReal {
                    table: table.to_owned(),
                    column: column.to_owned(),
                    pk: pk.to_owned(),
                });
            }
            // ECMAScript Number-to-String (RFC 8785 §3.2.2.3) via the same
            // JCS serialiser the envelope uses: independent implementations
            // reproduce this text without Rust. Finite f64 always
            // serialises; the error arm fails closed on plumbing only.
            let text = serde_jcs::to_string(&real).map_err(|e| ContentDigestError::Storage {
                table: table.to_owned(),
                detail: e.to_string(),
            })?;
            tag("r", text.into())
        }
        SqliteValue::Text(text) => tag("t", text.into()),
        SqliteValue::Blob(bytes) => {
            if table == "blobs" && column == "bytes" {
                tag(
                    "b",
                    row_sha256
                        .clone()
                        .map_or(serde_json::Value::Null, Into::into),
                )
            } else {
                tag("b", hex::encode(sha2::Sha256::digest(&bytes)).into())
            }
        }
    })
}

/// `[table_name, rows]` for one shipped table.
fn digest_table(
    conn: &rusqlite::Connection,
    table: &str,
) -> Result<serde_json::Value, ContentDigestError> {
    let storage = |detail: String| ContentDigestError::Storage {
        table: table.to_owned(),
        detail,
    };
    let columns = digest_columns(table);
    let keys = primary_key_columns(conn, table)?;
    let select = columns
        .iter()
        .map(|c| quote_ident(c))
        .collect::<Vec<_>>()
        .join(", ");
    let order = keys
        .iter()
        .map(|k| quote_ident(k))
        .collect::<Vec<_>>()
        .join(", ");
    let mut query = conn
        .prepare(&format!(
            "SELECT {select} FROM {table} ORDER BY {order}",
            table = quote_ident(table)
        ))
        .map_err(|e| storage(e.to_string()))?;
    let sha256_pos = (table == "blobs").then(|| {
        columns
            .iter()
            .position(|column| column == "sha256")
            .ok_or_else(|| storage("member blobs must carry sha256".to_owned()))
    });
    let sha256_pos = sha256_pos.transpose()?;
    let key_pos: Vec<usize> = keys
        .iter()
        .map(|key| {
            columns
                .iter()
                .position(|column| column == key)
                .ok_or_else(|| storage(format!("primary key {key} is not a digest column")))
        })
        .collect::<Result<_, _>>()?;
    let raw: Vec<Vec<SqliteValue>> = query
        .query_map([], |row| {
            let mut cells = Vec::with_capacity(columns.len());
            for (index, _) in columns.iter().enumerate() {
                cells.push(row.get::<_, SqliteValue>(index)?);
            }
            Ok(cells)
        })
        .map_err(|e| storage(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| storage(e.to_string()))?;
    let mut rows = Vec::with_capacity(raw.len());
    for cells in raw {
        let pk = key_pos
            .iter()
            .map(|pos| format_cell(&cells[*pos]))
            .collect::<Vec<_>>()
            .join("/");
        let row_sha256: Option<String> = match sha256_pos {
            None => None,
            Some(pos) => match &cells[pos] {
                SqliteValue::Text(text) => Some(text.clone()),
                SqliteValue::Null => None,
                other => {
                    return Err(storage(format!(
                        "member blobs.sha256 must be text or null, found {other:?}"
                    )));
                }
            },
        };
        let mut encoded = Vec::with_capacity(cells.len());
        for (index, cell) in cells.into_iter().enumerate() {
            encoded.push(encode_cell(table, &columns[index], &pk, cell, &row_sha256)?);
        }
        rows.push(serde_json::Value::Array(encoded));
    }
    Ok(serde_json::json!([table, rows]))
}

/// Member content digest (§1.4): `SHA-256(JCS([profile_id,
/// member_schema_digest, T_1, …, T_n]))` over a member-profile SQLite
/// connection. Value encoding is documented in the module docs; producer
/// and consumer share this function, so they cannot disagree.
pub fn content_digest(conn: &rusqlite::Connection) -> Result<String, ContentDigestError> {
    let mut input = vec![
        serde_json::Value::String(MEMBER_CONTENT_PROFILE_ID.to_owned()),
        serde_json::Value::String(member_schema_digest()),
    ];
    for table in shipped_tables() {
        input.push(digest_table(conn, table)?);
    }
    Ok(digest_json(&serde_json::Value::Array(input)))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::schema::member_schema::member_ddl_statements;

    const CONTENT_DIGEST_GOLDEN: &str =
        "db8b59951e30fca153a85c02beaae3baf646be938ff640ccb6fb02c4ad7e25b0";

    fn digest(conn: &rusqlite::Connection) -> String {
        content_digest(conn).expect("test digest must succeed")
    }

    fn member_db() -> rusqlite::Connection {
        let conn =
            rusqlite::Connection::open_in_memory().expect("member digest test database must open");
        conn.execute_batch(&member_ddl_statements().join(";\n"))
            .expect("member DDL must apply");
        conn
    }

    /// Tiny fixture: NULLs, an integer PK part, a REAL, inline blob bytes
    /// with sha256, a gated NULL with the F5 marker, and display refs.
    fn fixture(conn: &rusqlite::Connection) {
        conn.execute_batch(
            "INSERT INTO records (id, type, kind, name, body, lifecycle, persistence, maturity, summary, last_activity_at, created_at, updated_at, deleted_at, archived) VALUES
               ('r1', 'Document', 'note', 'alpha', 'hello', 'active', 'enduring', NULL, 'sum', '2026-09-29T00:00:00Z', '2026-09-29T00:00:00Z', '2026-09-29T00:00:01Z', NULL, 0),
               ('r2', 'Document', NULL, 'beta', NULL, NULL, 'enduring', NULL, NULL, '2026-09-29T00:00:00Z', '2026-09-29T00:00:00Z', '2026-09-29T00:00:00Z', NULL, 0);
             INSERT INTO links (id, source_id, target_id, relationship, note, created_at) VALUES
               ('l1', 'r1', 'r2', 'ref', NULL, '2026-09-29T00:00:00Z');
             INSERT INTO facet_values (id, record_id, key, value, vocab_ref, created_at) VALUES
               ('f1', 'r1', 'k', '\"v\"', NULL, '2026-09-29T00:00:00Z');
             INSERT INTO facet_times (record_id, key, kind, all_day, start_date, end_date, start_ms, end_ms, tz, tzdb_version) VALUES
               ('r1', 'when', 'instant', 0, NULL, NULL, 1, 2, NULL, NULL);
             INSERT INTO vocabularies (id, name, created_at) VALUES ('v1', 'vocab', '2026-09-29T00:00:00Z');
             INSERT INTO vocabulary_values (id, vocabulary_id, value, gloss, status, ordinal, terminality, metadata, alias_of) VALUES
               ('vv1', 'v1', 'term', NULL, 'active', 1.5, 'open', '{}', NULL);
             INSERT INTO schema_config (id, layer, name, data, applies_to_collection_id, version_lineage, created_at) VALUES
               ('s1', 'user', NULL, '{}', NULL, NULL, '2026-09-29T00:00:00Z');
             INSERT INTO blobs (id, bytes, mime, size_bytes, sha256, original_filename, storage_tier, external_ref, created_at, external_ref_withheld) VALUES
               ('b1', x'0102', 'application/octet-stream', 2, 'aaa', NULL, 'inline', NULL, '2026-09-29T00:00:00Z', 0),
               ('b2', NULL, NULL, NULL, NULL, NULL, 'external', NULL, '2026-09-29T00:00:00Z', 1);
             INSERT INTO annotation_targets (annotation_id, target_record_id, source_slot, blob_id, source_sha256, selectors, purpose, created_at, updated_at) VALUES
               ('r1', 'r2', 'body', NULL, 'abc', '[]', NULL, 't', 't');
             INSERT INTO record_mentions (source_id, occurrence_ix, span_start, span_end, authored_reference, lookup_key, form, parser_version) VALUES
               ('r1', 0, 0, 1, 'x', 'y', 'url', 1);
             INSERT INTO bindings (record_id, system, identifier, is_canonical, url, etag, last_seen_at) VALUES
               ('r1', 'account', 'a1', 1, NULL, NULL, NULL);
             INSERT INTO member_contexts (account_id, person_record_id, root_record_id, created_at) VALUES
               ('a1', 'r1', 'r2', 't');
             INSERT INTO instruction_bindings (id, scope_kind, scope_id, source_record_id, position, enabled, created_at, updated_at) VALUES
               ('i1', 'account', 'a1', 'r1', 0, 1, 't', 't');
             INSERT INTO member_display_references (record_id, display_reference) VALUES
               ('r1', 'a1b2'), ('r2', 'c3d4');",
        )
        .expect("digest fixture must insert");
    }

    #[test]
    fn content_digest_golden_and_stable() {
        let conn = member_db();
        fixture(&conn);
        assert_eq!(
            digest(&conn),
            CONTENT_DIGEST_GOLDEN,
            "content digest changed: intentional only with a profile-minor justification"
        );
    }

    #[test]
    fn content_digest_ignores_insertion_order_but_sees_every_change() {
        let first = member_db();
        fixture(&first);
        let baseline = digest(&first);
        // Same logical content, shuffled insertion order: identical digest.
        // Reverse-chronological inserts plus a link inserted before its
        // records exist (FKs are unenforced here by default).
        let second = member_db();
        second
            .execute_batch("PRAGMA foreign_keys = OFF;")
            .expect("pragma must apply");
        second
            .execute_batch(
                "INSERT INTO member_display_references (record_id, display_reference) VALUES ('r2', 'c3d4'), ('r1', 'a1b2');
                 INSERT INTO links (id, source_id, target_id, relationship, note, created_at) VALUES ('l1', 'r1', 'r2', 'ref', NULL, '2026-09-29T00:00:00Z');
                 INSERT INTO records (id, type, kind, name, body, lifecycle, persistence, maturity, summary, last_activity_at, created_at, updated_at, deleted_at, archived) VALUES
                   ('r2', 'Document', NULL, 'beta', NULL, NULL, 'enduring', NULL, NULL, '2026-09-29T00:00:00Z', '2026-09-29T00:00:00Z', '2026-09-29T00:00:00Z', NULL, 0),
                   ('r1', 'Document', 'note', 'alpha', 'hello', 'active', 'enduring', NULL, 'sum', '2026-09-29T00:00:00Z', '2026-09-29T00:00:00Z', '2026-09-29T00:00:01Z', NULL, 0);",
            )
            .expect("shuffled records must insert");
        // Remaining tables identical to the fixture.
        second
            .execute_batch(
                "INSERT INTO facet_values (id, record_id, key, value, vocab_ref, created_at) VALUES ('f1', 'r1', 'k', '\"v\"', NULL, '2026-09-29T00:00:00Z');
                 INSERT INTO facet_times (record_id, key, kind, all_day, start_date, end_date, start_ms, end_ms, tz, tzdb_version) VALUES ('r1', 'when', 'instant', 0, NULL, NULL, 1, 2, NULL, NULL);
                 INSERT INTO vocabularies (id, name, created_at) VALUES ('v1', 'vocab', '2026-09-29T00:00:00Z');
                 INSERT INTO vocabulary_values (id, vocabulary_id, value, gloss, status, ordinal, terminality, metadata, alias_of) VALUES ('vv1', 'v1', 'term', NULL, 'active', 1.5, 'open', '{}', NULL);
                 INSERT INTO schema_config (id, layer, name, data, applies_to_collection_id, version_lineage, created_at) VALUES ('s1', 'user', NULL, '{}', NULL, NULL, '2026-09-29T00:00:00Z');
                 INSERT INTO blobs (id, bytes, mime, size_bytes, sha256, original_filename, storage_tier, external_ref, created_at, external_ref_withheld) VALUES ('b1', x'0102', 'application/octet-stream', 2, 'aaa', NULL, 'inline', NULL, '2026-09-29T00:00:00Z', 0), ('b2', NULL, NULL, NULL, NULL, NULL, 'external', NULL, '2026-09-29T00:00:00Z', 1);
                 INSERT INTO annotation_targets (annotation_id, target_record_id, source_slot, blob_id, source_sha256, selectors, purpose, created_at, updated_at) VALUES ('r1', 'r2', 'body', NULL, 'abc', '[]', NULL, 't', 't');
                 INSERT INTO record_mentions (source_id, occurrence_ix, span_start, span_end, authored_reference, lookup_key, form, parser_version) VALUES ('r1', 0, 0, 1, 'x', 'y', 'url', 1);
                 INSERT INTO bindings (record_id, system, identifier, is_canonical, url, etag, last_seen_at) VALUES ('r1', 'account', 'a1', 1, NULL, NULL, NULL);
                 INSERT INTO member_contexts (account_id, person_record_id, root_record_id, created_at) VALUES ('a1', 'r1', 'r2', 't');
                 INSERT INTO instruction_bindings (id, scope_kind, scope_id, source_record_id, position, enabled, created_at, updated_at) VALUES ('i1', 'account', 'a1', 'r1', 0, 1, 't', 't');",
            )
            .expect("shuffled remainder must insert");
        assert_eq!(
            digest(&second),
            baseline,
            "insertion order must not move the digest"
        );
        // Any shipped value change moves it: body text, timestamp, ordinal.
        for change in [
            "UPDATE records SET body = 'bye' WHERE id = 'r1'",
            "UPDATE records SET updated_at = '2026-09-29T00:00:02Z' WHERE id = 'r1'",
            "UPDATE vocabulary_values SET ordinal = 2.5 WHERE id = 'vv1'",
            "UPDATE member_display_references SET display_reference = 'a1b2c' WHERE record_id = 'r1'",
            "DELETE FROM links WHERE id = 'l1'",
        ] {
            let changed = member_db();
            fixture(&changed);
            changed.execute_batch(change).expect("mutation must apply");
            assert_ne!(
                digest(&changed),
                baseline,
                "shipped change must move the digest: {change}"
            );
        }
    }

    #[test]
    fn content_digest_ignores_unshipped_state() {
        let conn = member_db();
        fixture(&conn);
        let baseline = digest(&conn);
        // A junk table (the digest reads shipped tables only, so an FTS
        // rebuild, a scratch table, or any operational row is invisible).
        conn.execute_batch(
            "CREATE TABLE records_fts (name TEXT, body TEXT);
             INSERT INTO records_fts (name, body) VALUES ('alpha', 'hello');
             CREATE TABLE scratch (id TEXT PRIMARY KEY, note TEXT);
             INSERT INTO scratch VALUES ('s1', 'junk');",
        )
        .expect("unshipped state must apply");
        assert_eq!(
            digest(&conn),
            baseline,
            "unshipped tables must not move the digest"
        );
        // ...but the junk table really exists, so the test is not vacuous.
        let tables: BTreeSet<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(tables.contains("records_fts"));
        assert!(tables.contains("scratch"));
    }

    #[test]
    fn content_digest_carries_integers_past_2_to_53_losslessly() {
        let conn = member_db();
        fixture(&conn);
        // occurrence_ix carries no CHECK; values past 2^53 travel as
        // decimal strings, so neighbours must digest distinctly.
        conn.execute_batch("UPDATE record_mentions SET occurrence_ix = 9007199254740993")
            .expect("large integer must store");
        let big = digest(&conn);
        conn.execute_batch("UPDATE record_mentions SET occurrence_ix = 9007199254740995")
            .expect("larger integer must store");
        assert_ne!(digest(&conn), big, "integers past 2^53 must not collide");
    }

    #[test]
    fn content_digest_reals_use_ecmascript_number_to_string() {
        // N1: the REAL text must be reproducible without Rust, so it is the
        // ECMAScript Number-to-String form (RFC 8785 §3.2.2.3), not Rust
        // Display (which never emits an exponent).
        let cell = |real: f64| {
            encode_cell(
                "vocabulary_values",
                "ordinal",
                "vv1",
                SqliteValue::Real(real),
                &None,
            )
            .expect("finite real must encode")
        };
        assert_eq!(cell(1e21), serde_json::json!(["r", "1e+21"]));
        assert_eq!(cell(1e-7), serde_json::json!(["r", "1e-7"]));
        assert_eq!(cell(0.1), serde_json::json!(["r", "0.1"]));
        assert_eq!(cell(1.5), serde_json::json!(["r", "1.5"]));
        // JCS renders -0 as "0": negative zero digests exactly like zero,
        // which is what an independent JCS implementation does too.
        assert_eq!(cell(-0.0), serde_json::json!(["r", "0"]));
        assert_eq!(cell(0.0), serde_json::json!(["r", "0"]));
    }

    #[test]
    fn content_digest_errors_on_non_finite_reals() {
        let conn = member_db();
        fixture(&conn);
        conn.execute_batch("UPDATE vocabulary_values SET ordinal = 1e400 WHERE id = 'vv1'")
            .expect("infinite real must store");
        assert_eq!(
            content_digest(&conn),
            Err(ContentDigestError::NonFiniteReal {
                table: "vocabulary_values".to_owned(),
                column: "ordinal".to_owned(),
                pk: "vv1".to_owned(),
            }),
            "NaN/±inf must fail closed with row context, not panic"
        );
    }
}
