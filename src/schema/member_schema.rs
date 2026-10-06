//! Compiled `member-read-v1` SQLite schema (contract c323277 rev 5, §1.3
//! "Physical form", §3.1, §3.3, §3.4, F5).
//!
//! The member profile is SQLite with the same logical table and column names
//! as the engine, restricted to the disposition map in
//! [`super::member_classification`]: only Included / CallerBound engine
//! tables, only shipped / nulled_if_hidden / gated columns, plus the
//! member-only side table. It is generated programmatically from that map and
//! the live engine DDL, so engine drift (a new table, column, or constraint)
//! fails the build instead of silently shipping.
//!
//! What the generator keeps and drops, per table:
//! - column definitions whose disposition is shipped, nulled_if_hidden or
//!   gated; dropped and derived columns are omitted entirely;
//! - table-level constraints (CHECK / PRIMARY KEY / UNIQUE / FOREIGN KEY)
//!   only when they mention no dropped column;
//! - `REFERENCES` clauses only when the target table ships in the member
//!   profile (both sides must ship);
//! - `NOT NULL` is relaxed on nulled_if_hidden columns and on the explicit
//!   [`NOT_NULL_OVERRIDES`] (§3.4 closure self-check allows NULL there);
//! - no indexes, no triggers (authorization triggers never travel; lookup
//!   and FTS indexes are rebuilt on the device), no policy tables (excluded
//!   by the map), no Postgres-style `external_ref IS NOT NULL` CHECK (the
//!   SQLite engine DDL carries none; F5 admits gated NULLs).
//!
//! Member-only additions (no engine source):
//! - `blobs.external_ref_withheld` (F5): marks a gated NULL so the closure
//!   self-check (§3.4) can tell it from a malformed row;
//! - `member_display_references` (Q6c server-computed side table).
//!
//! ## Canonicalisation (`member_schema_digest`)
//!
//! The digest covers the exact generated statement strings, in
//! `MEMBER_TABLE_DISPOSITIONS` order (the content-digest order, §1.4):
//! 1. one `CREATE TABLE <name> (...)` statement per shipped table, fields in
//!    engine order (member-only columns appended last), each field trimmed,
//!    joined as `"CREATE TABLE {name} (\n  {f1},\n  {f2}\n)"`;
//! 2. statements joined with a single `"\n"` (no trailing newline), UTF-8;
//! 3. `member_schema_digest` is the lowercase hex of the SHA-256 of those
//!    bytes. The golden value in [`MEMBER_SCHEMA_DIGEST_GOLDEN`] pins it: an
//!    unintended change fails the build; an intended one re-blesses the
//!    golden with a profile-minor justification.

use std::collections::{BTreeMap, BTreeSet};

use sha2::Digest as _;

use super::member_classification::{
    MemberColumnKind, MemberTableKind, MEMBER_COLUMN_DISPOSITIONS, MEMBER_ONLY_TABLES,
    MEMBER_ONLY_TABLE_COLUMNS, MEMBER_TABLE_DISPOSITIONS,
};
use crate::schema::DDL_STATEMENTS;

/// Columns that must accept NULL in the member profile even though the
/// engine DDL declares them `NOT NULL`. `annotation_targets.target_record_id`
/// may reference a hidden target (§3.4: "present or NULL"); nulled_if_hidden
/// columns (`records.home_id`, `records.owner_id`) are handled by
/// disposition, not by this list.
const NOT_NULL_OVERRIDES: &[(&str, &str)] = &[("annotation_targets", "target_record_id")];

/// The pinned digest of the compiled `member-read-v1` schema. Re-bless only
/// with a profile-minor justification (see module docs).
pub(crate) const MEMBER_SCHEMA_DIGEST_GOLDEN: &str =
    "ae44bffff97794ded06b3c25bf1490d89a2aa54a08a4db22f278660070343eec";

/// Tables that ship rows in the member profile, in digest order.
pub(crate) fn shipped_tables() -> Vec<&'static str> {
    MEMBER_TABLE_DISPOSITIONS
        .iter()
        .filter(|(_, kind)| {
            matches!(
                kind,
                MemberTableKind::Included
                    | MemberTableKind::CallerBound
                    | MemberTableKind::ServerComputed
            )
        })
        .map(|(table, _)| *table)
        .collect()
}

/// Column dispositions for one table: column -> kind.
fn column_kinds(table: &str) -> BTreeMap<&'static str, MemberColumnKind> {
    MEMBER_COLUMN_DISPOSITIONS
        .iter()
        .filter(|(name, _, _)| *name == table)
        .map(|(_, column, kind)| (*column, *kind))
        .collect()
}

/// The engine `CREATE TABLE` statement for a regular (non-virtual) table.
fn engine_create_table(table: &str) -> &'static str {
    DDL_STATEMENTS
        .iter()
        .find(|statement| {
            let words = statement.split_ascii_whitespace().collect::<Vec<_>>();
            words
                .first()
                .is_some_and(|word| word.eq_ignore_ascii_case("CREATE"))
                && !words
                    .iter()
                    .any(|word| word.eq_ignore_ascii_case("VIRTUAL"))
                && words.iter().any(|word| word.eq_ignore_ascii_case("TABLE"))
                && table_name(statement).as_deref() == Some(table)
        })
        .unwrap_or_else(|| panic!("no regular engine CREATE TABLE for {table}"))
}

/// Table name of a `CREATE TABLE` statement (regular or virtual).
fn table_name(statement: &str) -> Option<String> {
    let words = statement.split_ascii_whitespace().collect::<Vec<_>>();
    let table_pos = words
        .iter()
        .position(|word| word.eq_ignore_ascii_case("TABLE"))?;
    let mut cursor = table_pos + 1;
    if words
        .get(cursor)
        .is_some_and(|word| word.eq_ignore_ascii_case("IF"))
    {
        cursor += 3;
    }
    let raw = words.get(cursor)?.trim_end_matches('(');
    let unqualified = raw.rsplit('.').next().unwrap_or(raw);
    let table = unqualified.trim_matches(|c| matches!(c, '`' | '"' | '[' | ']'));
    (!table.is_empty()).then(|| table.to_owned())
}

/// Strip `--` line comments, respecting single-quoted literals. DDL
/// commentary contains commas that would otherwise split phantom fields.
fn strip_line_comments(statement: &str) -> String {
    let mut out = String::with_capacity(statement.len());
    let mut in_string = false;
    for line in statement.split_inclusive('\n') {
        let mut cut = line.len();
        let mut chars = line.char_indices().peekable();
        while let Some((index, ch)) = chars.next() {
            if in_string {
                if ch == '\'' {
                    if chars.peek().is_some_and(|(_, next)| *next == '\'') {
                        chars.next();
                    } else {
                        in_string = false;
                    }
                }
                continue;
            }
            if ch == '\'' {
                in_string = true;
            } else if ch == '-' && chars.peek().is_some_and(|(_, next)| *next == '-') {
                cut = index;
                break;
            }
        }
        out.push_str(&line[..cut]);
    }
    out
}

/// Split a parenthesised table body on top-level commas.
fn split_fields(body: &str) -> Vec<&str> {
    let mut fields = Vec::new();
    let mut start = 0;
    let mut depth = 0;
    for (index, byte) in body.bytes().enumerate() {
        match byte {
            b'(' => depth += 1,
            b')' => depth -= 1,
            b',' if depth == 0 => {
                fields.push(&body[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    fields.push(&body[start..]);
    fields
}

/// Body between the outer parens of a `CREATE TABLE` statement.
fn table_body(statement: &str) -> &str {
    let start = statement
        .find('(')
        .unwrap_or_else(|| panic!("CREATE TABLE has no column list: {statement}"));
    let bytes = statement.as_bytes();
    let mut depth = 0usize;
    for (index, byte) in bytes.iter().enumerate().skip(start) {
        match byte {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return &statement[start + 1..index];
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced parens in statement: {statement}")
}

const CONSTRAINT_LEADS: &[&str] = &["CHECK", "PRIMARY", "FOREIGN", "UNIQUE", "CONSTRAINT"];

/// First token of a column definition, or `None` for table constraints.
fn column_of(field: &str) -> Option<&str> {
    let field = field.trim();
    if field.is_empty() {
        return None;
    }
    let first = field.split_ascii_whitespace().next().unwrap_or_default();
    if CONSTRAINT_LEADS
        .iter()
        .any(|lead| first.eq_ignore_ascii_case(lead))
    {
        return None;
    }
    Some(
        first
            .trim_matches(|c| matches!(c, '`' | '"' | '[' | ']'))
            .trim_end_matches('('),
    )
}

/// Identifier tokens of a constraint, uppercased, for dropped-column checks.
fn constraint_idents(field: &str) -> BTreeSet<String> {
    field
        .split(|c: char| !(c.is_alphanumeric() || c == '_' || c == '$'))
        .filter(|token| !token.is_empty())
        .map(|token| token.to_ascii_uppercase())
        .collect()
}

/// Remove a `NOT NULL` marker outside string literals.
fn strip_not_null(field: &str) -> String {
    let mut out = String::with_capacity(field.len());
    let mut in_string = false;
    let chars: Vec<(usize, char)> = field.char_indices().collect();
    let mut index = 0;
    while index < chars.len() {
        let (_, ch) = chars[index];
        if in_string {
            out.push(ch);
            if ch == '\'' {
                if chars.get(index + 1).is_some_and(|(_, n)| *n == '\'') {
                    out.push('\'');
                    index += 1;
                } else {
                    in_string = false;
                }
            }
            index += 1;
            continue;
        }
        if ch == '\'' {
            in_string = true;
            out.push(ch);
            index += 1;
            continue;
        }
        if (ch == 'N' || ch == 'n')
            && chars[index..]
                .iter()
                .take(8)
                .map(|(_, c)| *c)
                .collect::<String>()
                .eq_ignore_ascii_case("NOT NULL")
            && (index == 0 || !chars[index - 1].1.is_alphanumeric())
            && (index + 8 >= chars.len() || !chars[index + 8].1.is_alphanumeric())
        {
            index += 8;
            continue;
        }
        out.push(ch);
        index += 1;
    }
    out
}

/// Target table of a `REFERENCES <table> (...)` clause, if any.
fn references_target(field: &str) -> Option<String> {
    let words: Vec<&str> = field.split_ascii_whitespace().collect();
    let pos = words
        .iter()
        .position(|word| word.eq_ignore_ascii_case("REFERENCES"))?;
    let raw = words.get(pos + 1)?;
    let unqualified = raw.split('(').next().unwrap_or(raw);
    let target = unqualified
        .trim_matches(|c| matches!(c, '`' | '"' | '[' | ']' | ';'))
        .trim_end_matches('(');
    (!target.is_empty()).then(|| target.to_owned())
}

/// Cut a `REFERENCES ...` clause (with its `ON DELETE/UPDATE` actions) from a
/// column definition. Engine `REFERENCES` clauses never sit inside string
/// literals, so a keyword cut is exact.
fn strip_references(field: &str) -> String {
    let words: Vec<&str> = field.split_ascii_whitespace().collect();
    let end = words
        .iter()
        .position(|word| word.eq_ignore_ascii_case("REFERENCES"))
        .unwrap_or(words.len());
    words[..end].join(" ")
}

/// Collapse runs of ASCII whitespace to one space, then trim.
fn collapse_ws(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut pending = false;
    for ch in text.chars() {
        if ch.is_ascii_whitespace() {
            pending = true;
        } else {
            if pending && !out.is_empty() {
                out.push(' ');
            }
            pending = false;
            out.push(ch);
        }
    }
    out
}

/// Generate the member-profile `CREATE TABLE` for one shipped engine table.
fn engine_member_table(table: &str) -> String {
    let kinds = column_kinds(table);
    let dropped: BTreeSet<String> = kinds
        .iter()
        .filter(|(_, kind)| **kind == MemberColumnKind::Dropped)
        .map(|(column, _)| column.to_ascii_uppercase())
        .collect();
    let statement = strip_line_comments(engine_create_table(table));
    let mut kept = Vec::new();
    for field in split_fields(table_body(&statement)) {
        let field = field.trim();
        if field.is_empty() || field.starts_with("--") {
            continue;
        }
        match column_of(field) {
            Some(column) => {
                let Some(kind) = kinds.get(column) else {
                    panic!("engine column {table}.{column} has no member disposition");
                };
                match kind {
                    MemberColumnKind::Shipped
                    | MemberColumnKind::NulledIfHidden
                    | MemberColumnKind::Gated => {
                        let mut def = field.to_owned();
                        if *kind == MemberColumnKind::NulledIfHidden
                            || NOT_NULL_OVERRIDES.contains(&(table, column))
                        {
                            def = strip_not_null(&def);
                        }
                        if let Some(target) = references_target(&def) {
                            let target_ships = shipped_tables().contains(&target.as_str())
                                || MEMBER_ONLY_TABLES.contains(&target.as_str());
                            def = if target_ships {
                                def
                            } else {
                                strip_references(&def)
                            };
                        }
                        kept.push(collapse_ws(&def));
                    }
                    MemberColumnKind::Derived | MemberColumnKind::Dropped => {}
                }
            }
            None => {
                let mentions_dropped = !constraint_idents(field)
                    .intersection(&dropped)
                    .collect::<Vec<_>>()
                    .is_empty();
                if !mentions_dropped {
                    kept.push(collapse_ws(field));
                }
            }
        }
    }
    assert!(!kept.is_empty(), "member table {table} kept no definitions");
    format!("CREATE TABLE {table} (\n  {}\n)", kept.join(",\n  "))
}

/// F5: the one member-only physical column (marks a gated NULL so the
/// closure self-check tells it from a malformed row). Single source of truth:
/// the schema DDL, the digest column order, and the closure tests all read
/// this name.
pub const EXTERNAL_REF_WITHHELD_COLUMN: &str = "external_ref_withheld";

/// Extra member-only columns appended to a generated engine table, in order.
/// F5: a gated NULL `external_ref` must be distinguishable from a malformed
/// row, so the member profile carries `external_ref_withheld` (the SQLite
/// engine DDL has no `external_ref IS NOT NULL` CHECK to conflict with it).
fn extra_columns(table: &str) -> Vec<String> {
    match table {
        "blobs" => vec![format!(
            "{EXTERNAL_REF_WITHHELD_COLUMN} INTEGER NOT NULL DEFAULT 0 CHECK ({EXTERNAL_REF_WITHHELD_COLUMN} IN (0, 1))"
        )],
        _ => Vec::new(),
    }
}

/// `CREATE TABLE` for a declared member-only table. Column definitions are
/// member-profile DDL (there is no engine source); the disposition map must
/// cover exactly the declared columns.
fn member_only_table(table: &str) -> String {
    let (_, columns) = MEMBER_ONLY_TABLE_COLUMNS
        .iter()
        .find(|(name, _)| *name == table)
        .unwrap_or_else(|| panic!("member-only table {table} declares no columns"));
    let disposed: BTreeSet<&str> = MEMBER_COLUMN_DISPOSITIONS
        .iter()
        .filter(|(name, _, _)| *name == table)
        .map(|(_, column, _)| *column)
        .collect();
    let declared: BTreeSet<&str> = columns.iter().copied().collect();
    assert_eq!(
        declared, disposed,
        "member-only table {table}: declared columns and dispositions differ"
    );
    let defs: Vec<&str> = match table {
        // Q6c server-computed side table: the online display_reference value
        // for each record in E(m).
        "member_display_references" => vec![
            "record_id TEXT PRIMARY KEY REFERENCES records(id) ON DELETE CASCADE",
            "display_reference TEXT NOT NULL",
        ],
        _ => panic!("member-only table {table} has no member-profile definition"),
    };
    assert_eq!(
        defs.len(),
        columns.len(),
        "member-only table {table}: definition covers every declared column"
    );
    format!("CREATE TABLE {table} (\n  {}\n)", defs.join(",\n  "))
}

/// The compiled `member-read-v1` schema: one `CREATE TABLE` per shipped
/// table, in `MEMBER_TABLE_DISPOSITIONS` (content-digest) order.
pub(crate) fn member_ddl_statements() -> Vec<String> {
    shipped_tables()
        .iter()
        .map(|table| {
            if MEMBER_ONLY_TABLES.contains(table) {
                member_only_table(table)
            } else {
                let mut statement = engine_member_table(table);
                for extra in extra_columns(table) {
                    let prefix = statement
                        .strip_suffix("\n)")
                        .unwrap_or_else(|| panic!("malformed generated table {table}"));
                    statement = format!("{prefix},\n  {extra}\n)");
                }
                statement
            }
        })
        .collect()
}

/// Stable digest of the compiled `member-read-v1` schema (canonicalisation
/// in the module docs): lowercase hex SHA-256 over the UTF-8 bytes of
/// [`member_ddl_statements`] joined with `"\n"`.
pub(crate) fn member_schema_digest() -> String {
    hex::encode(sha2::Sha256::digest(
        member_ddl_statements().join("\n").into_bytes(),
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{
        member_ddl_statements, member_schema_digest, EXTERNAL_REF_WITHHELD_COLUMN,
        MEMBER_SCHEMA_DIGEST_GOLDEN,
    };
    use crate::schema::member_classification::{
        MemberColumnKind, MEMBER_COLUMN_DISPOSITIONS, MEMBER_TABLE_DISPOSITIONS,
    };

    fn apply_member_schema() -> rusqlite::Connection {
        let conn =
            rusqlite::Connection::open_in_memory().expect("member schema test database must open");
        conn.execute_batch(&member_ddl_statements().join(";\n"))
            .expect("member DDL must apply to a fresh SQLite database");
        conn
    }

    fn member_tables(conn: &rusqlite::Connection) -> BTreeSet<String> {
        conn.prepare(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .expect("sqlite_master must be readable")
        .query_map([], |row| row.get(0))
        .expect("table list must query")
        .collect::<Result<BTreeSet<_>, _>>()
        .expect("table names must read")
    }

    fn member_columns(conn: &rusqlite::Connection, table: &str) -> BTreeSet<String> {
        conn.prepare(&format!("PRAGMA table_info({table})"))
            .expect("PRAGMA table_info must prepare")
            .query_map([], |row| row.get::<_, String>(1))
            .expect("table_info must query")
            .collect::<Result<BTreeSet<_>, _>>()
            .expect("column names must read")
    }

    #[test]
    fn member_ddl_applies_and_holds_only_shipped_tables() {
        let conn = apply_member_schema();
        let expected = MEMBER_TABLE_DISPOSITIONS
            .iter()
            .filter(|(_, kind)| {
                matches!(
                    kind,
                    super::MemberTableKind::Included
                        | super::MemberTableKind::CallerBound
                        | super::MemberTableKind::ServerComputed
                )
            })
            .map(|(table, _)| (*table).to_owned())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            member_tables(&conn),
            expected,
            "member profile holds exactly the shipped tables: no excluded table may exist"
        );
    }

    #[test]
    fn member_tables_hold_only_shipped_columns() {
        let conn = apply_member_schema();
        let shipped: BTreeSet<(&str, &str)> = MEMBER_COLUMN_DISPOSITIONS
            .iter()
            .filter(|(_, _, kind)| {
                matches!(
                    kind,
                    MemberColumnKind::Shipped
                        | MemberColumnKind::NulledIfHidden
                        | MemberColumnKind::Gated
                )
            })
            .map(|(table, column, _)| (*table, *column))
            .collect();
        for (table, _) in MEMBER_TABLE_DISPOSITIONS.iter().filter(|(_, kind)| {
            matches!(
                kind,
                super::MemberTableKind::Included
                    | super::MemberTableKind::CallerBound
                    | super::MemberTableKind::ServerComputed
            )
        }) {
            let mut expected: BTreeSet<String> = shipped
                .iter()
                .filter_map(|(name, column)| (*name == *table).then_some((*column).to_owned()))
                .collect();
            if *table == "blobs" {
                expected.insert(EXTERNAL_REF_WITHHELD_COLUMN.to_owned());
            }
            assert_eq!(
                member_columns(&conn, table),
                expected,
                "member table {table} holds exactly its shipped columns: no dropped column may exist"
            );
        }
    }

    fn foreign_key_violations(conn: &rusqlite::Connection) -> usize {
        conn.prepare("PRAGMA foreign_key_check")
            .expect("foreign_key_check must prepare")
            .query_map([], |_| Ok(()))
            .expect("foreign_key_check must query")
            .count()
    }

    #[test]
    fn member_foreign_keys_are_satisfiable_and_enforced() {
        let conn = apply_member_schema();
        assert_eq!(
            foreign_key_violations(&conn),
            0,
            "empty member profile must be FK-clean"
        );
        // A minimal valid graph: every shipped FK target exists.
        conn.execute_batch(
            "INSERT INTO records (id, type, name) VALUES ('r1', 'Document', 'one');
             INSERT INTO records (id, type, name, home_id, owner_id) VALUES ('r2', 'Document', 'two', 'r1', 'r1');
             INSERT INTO links (id, source_id, target_id, relationship) VALUES ('l1', 'r2', 'r1', 'ref');
             INSERT INTO facet_values (id, record_id, key, value) VALUES ('f1', 'r1', 'k', '\"v\"');
             INSERT INTO facet_times (record_id, key, kind, all_day, start_ms, end_ms) VALUES ('r1', 'when', 'instant', 0, 1, 2);
             INSERT INTO vocabularies (id, name) VALUES ('v1', 'vocab');
             INSERT INTO vocabulary_values (id, vocabulary_id, value) VALUES ('vv1', 'v1', 'term');
             INSERT INTO schema_config (id, layer, data) VALUES ('s1', 'user', '{}');
             INSERT INTO blobs (id) VALUES ('b1');
             INSERT INTO annotation_targets (annotation_id, target_record_id, source_slot, source_sha256, selectors, purpose, created_at, updated_at) VALUES ('r2', 'r1', 'body', 'abc', '[]', NULL, 't', 't');
             INSERT INTO record_mentions (source_id, occurrence_ix, span_start, span_end, authored_reference, lookup_key, form, parser_version) VALUES ('r1', 0, 0, 1, 'x', 'y', 'url', 1);
             INSERT INTO bindings (record_id, system, identifier) VALUES ('r1', 'account', 'a1');
             INSERT INTO member_contexts (account_id, person_record_id, root_record_id, created_at) VALUES ('a1', 'r1', 'r2', 't');
             INSERT INTO instruction_bindings (id, scope_kind, scope_id, source_record_id, position, created_at, updated_at) VALUES ('i1', 'account', 'a1', 'r1', 0, 't', 't');
             INSERT INTO member_display_references (record_id, display_reference) VALUES ('r1', 'a1b2');
             INSERT INTO blobs (id, external_ref, external_ref_withheld) VALUES ('b2', NULL, 1);",
        )
        .expect("valid member fixture must insert");
        assert_eq!(
            foreign_key_violations(&conn),
            0,
            "valid member fixture must be FK-clean"
        );
        // Nullable anchors accept NULL (§3.4): hidden parent/target.
        conn.execute_batch(
            "INSERT INTO records (id, type, name, home_id, owner_id) VALUES ('r3', 'Document', 'orphan', NULL, NULL);
             INSERT INTO annotation_targets (annotation_id, target_record_id, source_slot, source_sha256, selectors, purpose, created_at, updated_at) VALUES ('r3', NULL, 'body', 'abc', '[]', NULL, 't', 't');",
        )
        .expect("nulled references must insert");
        assert_eq!(foreign_key_violations(&conn), 0);
        // FKs are enforced, not decorative: a dangling endpoint is reported.
        conn.execute("PRAGMA foreign_keys = OFF", [])
            .expect("pragma must apply");
        conn.execute(
            "INSERT INTO links (id, source_id, target_id, relationship) VALUES ('bad', 'r1', 'missing', 'ref')",
            [],
        )
        .expect("dangling insert must apply with enforcement off");
        assert_eq!(
            foreign_key_violations(&conn),
            1,
            "foreign_key_check must report the dangling link endpoint"
        );
    }

    #[test]
    fn member_schema_digest_is_stable() {
        assert_eq!(
            member_schema_digest(),
            MEMBER_SCHEMA_DIGEST_GOLDEN,
            "member-read-v1 schema changed: re-bless the golden only with a profile-minor justification"
        );
    }

    #[test]
    fn member_ddl_carries_no_excluded_shape() {
        let ddl = member_ddl_statements().join("\n");
        for dropped in [
            "policy_anchor_id",
            "claimed_by_account",
            "claimed_run_key",
            "claimed_at",
            "source_event_seq",
            "value_num",
            "created_by",
        ] {
            assert!(
                !ddl.split(|c: char| !(c.is_alphanumeric() || c == '_'))
                    .any(|token| token == dropped),
                "dropped column {dropped} must not appear in member DDL"
            );
        }
        // F5: no Postgres-style external-tier NOT NULL guard; gated NULLs
        // are admitted and marked instead.
        assert!(
            !ddl.contains("external_ref IS NOT NULL"),
            "member DDL must not carry the Postgres external_ref guard"
        );
        assert!(
            ddl.contains("external_ref_withheld"),
            "member blobs must carry the F5 withheld marker column"
        );
    }
}
