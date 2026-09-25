//! Data-driven cross-engine conformance corpus for `query_sql` (E1 M1 slice A).
//!
//! Each case is one statement plus its parameters plus the exact rows every
//! engine must return for the shared [`SEED_SQL`] below, read as alice (who
//! sees `conf:common` and `conf:alice` but must never see `conf:bea`).
//!
//! How to add a case (later milestones keep extending [`corpus`]):
//! 1. Seed every row the case reads in [`SEED_SQL`] with a `conf:`-prefixed
//!    id, using raw SQL that runs verbatim on SQLite and Turso.
//! 2. Project only stable columns (`id`, `name`, keys, values, counts).
//!    Timestamps and digests differ per run and can never appear in
//!    `expected_rows`.
//! 3. End every multi-row statement with `ORDER BY` over a unique key so
//!    row order is deterministic on every engine (`corpus()` panics
//!    otherwise; single-row and empty cases are order-free).
//! 4. Visibility is part of the contract: prefer reading through alice, and
//!    assert hidden seed rows are absent (see the `hidden_*` cases).
//! 5. Keep placeholder syntax engine-neutral (`?1`): the Postgres path
//!    rewrites `?N` to `$N` (`rewrite_placeholders_for_postgres` in
//!    `sql_contract`) before executing.
//! 6. Catalog and value-model changes land here with their corpus cases:
//!    slice B added the `*_ms` companions and bumped the catalog revision,
//!    and every relation change must extend `corpus()` the same way.
//!
//! Postgres execution of the corpus is out of scope for slice A, but it is
//! not designed out: [`check_case`] takes only a [`QuerySqlResult`], so a
//! future Postgres test can seed, run, and check unchanged.

use serde_json::Value;

use super::sql_contract::{
    catalog_column_rows, catalog_relation_rows, QuerySqlParameter, QuerySqlRequest, QuerySqlResult,
    CARD_WORKED_STATEMENTS,
};

/// A card worked statement scoped to the `conf:%` seed, derived from
/// `CARD_WORKED_STATEMENTS` so the shipped string is what runs. The scope
/// predicate is injected before ORDER BY; parameters stay positional.
/// Leaks one small string per call: corpus construction is test-only.
pub(crate) fn scoped_card_sql(intent: &str, scope: &str) -> &'static str {
    let sql = CARD_WORKED_STATEMENTS
        .iter()
        .find(|(label, _)| *label == intent)
        .unwrap_or_else(|| panic!("no card statement named '{intent}'"))
        .1;
    let (head, tail) = sql
        .split_once(" ORDER BY")
        .unwrap_or_else(|| panic!("card statement '{intent}' has no ORDER BY"));
    Box::leak(format!("{head} AND {scope} ORDER BY{tail}").into_boxed_str())
}

/// Raw-SQL seed shared by every engine runner. It runs verbatim on SQLite
/// (`write_pool`) and on Turso (domain connection), so both engines start
/// from the same rows. Explicit `content_events.seq` values keep the
/// freshness stamp deterministic; runners read the head back after seeding
/// rather than assuming anything about migration seeds outside `conf:` rows.
///
/// The seed holds no policy rows on purpose: the governance funnel test
/// (`tests/governance/policy_write_funnel.rs`) forbids hand-written
/// `record_policies`/`policy_entries` writes outside the projector and its
/// explicit exceptions. Each runner admits visibility through its own
/// sanctioned path instead — the SQLite runner calls
/// `replace_explicit_policy` so the projector produces the policy rows
/// (which also makes the hidden-row cases exercise real visibility), and
/// the Turso runner executes a strip-listed supplement in `turso_local.rs`
/// (Turso has no test-accessible policy write path). Records carry a
/// self-anchor and no owner, so visibility resolves purely through the
/// projected grants.
pub(crate) const SEED_SQL: &[&str] = &[
    "INSERT INTO records(id,type,kind,name,body,home_id,owner_id,policy_anchor_id) VALUES
      ('conf:common','Document','note','Common','common body quoting `- [ ]` inline',NULL,NULL,'conf:common'),
      ('conf:alice','Document','note','Alice note','alice body\n- [ ] buy milk',NULL,NULL,'conf:alice'),
      ('conf:bea','Document','note','Bea note','bea body',NULL,NULL,'conf:bea'),
      ('conf:tomb','Document','note','Tomb','tomb body',NULL,NULL,'conf:tomb'),
      ('conf:sort-a','Document','note','apple',NULL,NULL,NULL,'conf:sort-a'),
      ('conf:sort-b','Document','note','Banana',NULL,NULL,NULL,'conf:sort-b'),
      ('conf:sort-c','Document','note','Äpfel',NULL,NULL,NULL,'conf:sort-c')",
    "UPDATE records SET created_at='2026-01-01T00:00:00.000Z',updated_at='2026-01-01T00:00:00.000Z' WHERE id LIKE 'conf:%'",
    "UPDATE records SET created_at='2026-01-02T00:00:00.000Z',updated_at='2026-01-02T00:00:00.000Z' WHERE id='conf:alice'",
    "UPDATE records SET type='WorkItem',lifecycle='open' WHERE id='conf:alice'",
    "UPDATE records SET type='WorkItem',lifecycle='in_progress' WHERE id='conf:common'",
    "UPDATE records SET home_id='conf:common' WHERE id='conf:alice'",
    "UPDATE records SET deleted_at='2026-01-02T00:00:00.000Z' WHERE id='conf:tomb'",
    "INSERT INTO links(id,source_id,target_id,relationship,note,created_at) VALUES
      ('conf:link-open','conf:common','conf:alice','relates_to',NULL,'2026-01-01T00:00:00.000Z'),
      ('conf:link-part','conf:common','conf:alice','part_of',NULL,'2026-01-01T00:00:00.000Z'),
      ('conf:link-sealed','conf:common','conf:bea','relates_to',NULL,'2026-01-01T00:00:00.000Z')",
    "INSERT INTO content_events(seq,id,record_id,type,created_at,causal_envelope_version,causal_status) VALUES
      (91001,'conf:event-common','conf:common','record.updated','2026-01-01T00:00:00.000Z',1,'legacy_unknown'),
      (91002,'conf:event-hidden','conf:bea','record.updated','2026-01-01T00:00:00Z',1,'legacy_unknown'),
      (91004,'conf:event-common-2','conf:common','record.updated','2026-01-05T00:00:00Z',1,'legacy_unknown')",
    "UPDATE records SET last_activity_at='2026-01-05T00:00:00.000Z' WHERE id='conf:common'",
    "UPDATE records SET last_activity_at='2026-01-03T00:00:00.000Z' WHERE id='conf:alice'",
    "INSERT INTO facet_values(id,record_id,key,value,vocab_ref,created_at) VALUES
      ('conf:facet-color','conf:common','color','blue',NULL,'2026-01-01T00:00:00.000Z'),
      ('conf:facet-shape','conf:common','shape','round',NULL,'2026-01-01T00:00:00.000Z'),
      ('conf:facet-alice','conf:alice','color','green',NULL,'2026-01-01T00:00:00.000Z'),
      ('conf:facet-hidden','conf:bea','color','red',NULL,'2026-01-01T00:00:00.000Z'),
      ('conf:facet-n1','conf:common','score','10',NULL,'2026-01-01T00:00:00.000Z'),
      ('conf:facet-n2','conf:alice','score','20',NULL,'2026-01-01T00:00:00.000Z'),
      ('conf:facet-n3','conf:sort-a','score','30',NULL,'2026-01-01T00:00:00.000Z')",
    "INSERT INTO bindings(record_id,system,identifier,is_canonical,url,etag,last_seen_at) VALUES
      ('conf:common','account','alice',1,NULL,NULL,'2026-01-01T00:00:00.000Z'),
      ('conf:common','email','alice@example.test',1,NULL,NULL,'2026-01-02T12:30:45.123Z'),
      ('conf:common','email','stale@example.test',0,NULL,NULL,NULL)",
];

/// Seed-contributed content head. Runners assert against the read-back head,
/// not this constant; it exists so future cases can pick non-colliding
/// explicit `seq` values above it.
pub(crate) const SEED_MIN_HEAD: i64 = 91002;

/// One corpus case: a statement, its parameters, and the exact columns and
/// rows every engine must return for the shared seed when read as alice.
pub(crate) struct ConformanceCase {
    pub name: &'static str,
    pub sql: &'static str,
    pub parameters: Vec<QuerySqlParameter>,
    pub expected_columns: Vec<&'static str>,
    pub expected_rows: Vec<Value>,
}

impl ConformanceCase {
    pub(crate) fn request(&self) -> QuerySqlRequest {
        QuerySqlRequest {
            sql: self.sql.into(),
            parameters: self.parameters.clone(),
        }
    }
}

/// The corpus. Append new cases here; every engine runner picks them up.
/// Multi-row cases must carry ORDER BY: `check_case` compares rows in
/// order, and without it that order is engine-specific. This is enforced
/// below (single-row and empty cases are order-free).
pub(crate) fn corpus() -> Vec<ConformanceCase> {
    let cases = vec![
        ConformanceCase {
            name: "records_project_stable_columns",
            sql: "SELECT id, name FROM records WHERE type = 'Document' AND id LIKE 'conf:%' ORDER BY id",
            parameters: Vec::new(),
            expected_columns: vec!["id", "name"],
            expected_rows: vec![
                serde_json::json!({"id": "conf:sort-a", "name": "apple"}),
                serde_json::json!({"id": "conf:sort-b", "name": "Banana"}),
                serde_json::json!({"id": "conf:sort-c", "name": "Äpfel"}),
            ],
        },
        ConformanceCase {
            name: "links_require_both_endpoints_visible",
            sql: "SELECT id, source_id, target_id, relationship FROM links WHERE id LIKE 'conf:%' ORDER BY id",
            parameters: Vec::new(),
            expected_columns: vec!["id", "source_id", "target_id", "relationship"],
            expected_rows: vec![
                serde_json::json!({"id": "conf:link-open", "source_id": "conf:common", "target_id": "conf:alice", "relationship": "relates_to"}),
                serde_json::json!({"id": "conf:link-part", "source_id": "conf:common", "target_id": "conf:alice", "relationship": "part_of"}),
            ],
        },
        ConformanceCase {
            name: "facet_values_follow_record_visibility",
            sql: "SELECT record_id, key, value FROM facet_values WHERE id LIKE 'conf:%' ORDER BY id",
            parameters: Vec::new(),
            expected_columns: vec!["record_id", "key", "value"],
            expected_rows: vec![
                serde_json::json!({"record_id": "conf:alice", "key": "color", "value": "green"}),
                serde_json::json!({"record_id": "conf:common", "key": "color", "value": "blue"}),
                serde_json::json!({"record_id": "conf:common", "key": "score", "value": "10"}),
                serde_json::json!({"record_id": "conf:alice", "key": "score", "value": "20"}),
                serde_json::json!({"record_id": "conf:sort-a", "key": "score", "value": "30"}),
                serde_json::json!({"record_id": "conf:common", "key": "shape", "value": "round"}),
            ],
        },
        ConformanceCase {
            name: "hidden_row_not_counted",
            sql: "SELECT count(*) AS n FROM records WHERE id LIKE 'conf:%'",
            parameters: Vec::new(),
            expected_columns: vec!["n"],
            // Alice sees conf:common, conf:alice and the three sort rows.
            // conf:bea is hidden by the absence of a grant; conf:tomb is
            // deleted.
            expected_rows: vec![serde_json::json!({"n": 5})],
        },
        ConformanceCase {
            name: "hidden_row_direct_lookup_empty",
            sql: "SELECT id FROM records WHERE id = ?1",
            parameters: vec![QuerySqlParameter::Text {
                value: Some("conf:bea".into()),
            }],
            // Empty results report no column labels on SQLite (labels come
            // from the first row) but prepared labels on Turso. That shape
            // divergence is out of scope for slice A; the corpus pins rows,
            // and columns are asserted only for non-empty results.
            expected_columns: Vec::new(),
            expected_rows: Vec::new(),
        },
        ConformanceCase {
            name: "timestamp_ms_integer_arithmetic",
            sql: "SELECT id, created_at_ms - 1767225600000 AS delta_ms FROM records WHERE id IN ('conf:common','conf:alice') ORDER BY id",
            parameters: Vec::new(),
            expected_columns: vec!["id", "delta_ms"],
            // conf:common was created at 2026-01-01T00:00:00.000Z
            // (1767225600000 ms); conf:alice a day later. Portable date
            // maths is integer arithmetic over the companions.
            expected_rows: vec![
                serde_json::json!({"id": "conf:alice", "delta_ms": 86400000}),
                serde_json::json!({"id": "conf:common", "delta_ms": 0}),
            ],
        },
        ConformanceCase {
            name: "boolean_filter_uses_zero_one",
            sql: "SELECT identifier, is_canonical FROM bindings WHERE is_canonical = 1 ORDER BY identifier",
            parameters: Vec::new(),
            expected_columns: vec!["identifier", "is_canonical"],
            expected_rows: vec![
                serde_json::json!({"identifier": "alice", "is_canonical": 1}),
                serde_json::json!({"identifier": "alice@example.test", "is_canonical": 1}),
            ],
        },
        ConformanceCase {
            // E1 M2 Option N: computed booleans encode as 1/0 on every
            // engine (Postgres normalises in its result encoder), and
            // NULL stays null. Single row, so no ORDER BY is needed.
            name: "computed_booleans_encode_as_zero_one",
            sql: "SELECT (1 = 1) AS t, (1 = 2) AS f, (NULL = 1) AS n",
            parameters: Vec::new(),
            expected_columns: vec!["t", "f", "n"],
            expected_rows: vec![serde_json::json!({"t": 1, "f": 0, "n": null})],
        },
        ConformanceCase {
            name: "text_sorts_in_binary_order",
            sql: "SELECT name FROM records WHERE id LIKE 'conf:sort-%' ORDER BY name",
            parameters: Vec::new(),
            expected_columns: vec!["name"],
            // Binary (C) order: 'B' (0x42) < 'a' (0x61) < 'Ä' (0xC3..).
            // Locale collations sort 'apple' first; the views pin binary.
            expected_rows: vec![
                serde_json::json!({"name": "Banana"}),
                serde_json::json!({"name": "apple"}),
                serde_json::json!({"name": "Äpfel"}),
            ],
        },
        ConformanceCase {
            name: "avg_returns_one_number",
            sql: "SELECT avg(value_num) AS avg_num FROM facet_values WHERE key = 'score'",
            parameters: Vec::new(),
            expected_columns: vec!["avg_num"],
            expected_rows: vec![
                serde_json::json!({"avg_num": 20.0}),
            ],
        },
        ConformanceCase {
            name: "sum_returns_one_number",
            sql: "SELECT sum(value_num) AS sum_num FROM facet_values WHERE key = 'score'",
            parameters: Vec::new(),
            expected_columns: vec!["sum_num"],
            expected_rows: vec![
                serde_json::json!({"sum_num": 60.0}),
            ],
        },
        ConformanceCase {
            name: "catalog_columns_lists_links_columns_in_position",
            sql: "SELECT relation_name, column_name, column_position FROM catalog_columns WHERE relation_name = 'links' ORDER BY column_position",
            parameters: Vec::new(),
            expected_columns: vec!["relation_name", "column_name", "column_position"],
            expected_rows: vec![
                serde_json::json!({"relation_name": "links", "column_name": "id", "column_position": 0}),
                serde_json::json!({"relation_name": "links", "column_name": "source_id", "column_position": 1}),
                serde_json::json!({"relation_name": "links", "column_name": "target_id", "column_position": 2}),
                serde_json::json!({"relation_name": "links", "column_name": "relationship", "column_position": 3}),
                serde_json::json!({"relation_name": "links", "column_name": "note", "column_position": 4}),
                serde_json::json!({"relation_name": "links", "column_name": "created_at", "column_position": 5}),
                serde_json::json!({"relation_name": "links", "column_name": "created_at_ms", "column_position": 6}),
            ],
        },
        ConformanceCase {
            name: "catalog_relations_describes_records",
            sql: "SELECT relation_name, identity, semantic_version, caller_relative, completeness, profiles FROM catalog_relations WHERE relation_name = 'records'",
            parameters: Vec::new(),
            expected_columns: vec!["relation_name", "identity", "semantic_version", "caller_relative", "completeness", "profiles"],
            expected_rows: vec![
                serde_json::json!({"relation_name": "records", "identity": "native.query-sql.records", "semantic_version": 1, "caller_relative": 1, "completeness": "complete", "profiles": "sqlite-local,postgres-server,turso-local"}),
            ],
        },
        ConformanceCase {
            name: "catalog_columns_lists_full_catalog",
            sql: "SELECT relation_name, column_name, column_position FROM catalog_columns ORDER BY relation_name, column_position",
            parameters: Vec::new(),
            expected_columns: vec!["relation_name", "column_name", "column_position"],
            // Expected rows derive from the same contract the views are
            // generated from; the cross-engine assertion this case exists
            // for is that every backend materializes those rows identically
            // (all names are lowercase, so ORDER BY is collation-neutral).
            // Single-relation spot cases above pin exact values by hand.
            expected_rows: {
                let mut rows = catalog_column_rows();
                rows.sort_by(|a, b| (a.0, a.2).cmp(&(b.0, b.2)));
                rows.into_iter()
                    .map(|(relation, column, position)| {
                        serde_json::json!({
                            "relation_name": relation,
                            "column_name": column,
                            "column_position": position,
                        })
                    })
                    .collect()
            },
        },
        ConformanceCase {
            name: "catalog_relations_lists_full_catalog",
            sql: "SELECT relation_name, identity, semantic_version, caller_relative, completeness, profiles, comment FROM catalog_relations ORDER BY relation_name",
            parameters: Vec::new(),
            expected_columns: vec!["relation_name", "identity", "semantic_version", "caller_relative", "completeness", "profiles", "comment"],
            expected_rows: {
                let mut rows = catalog_relation_rows();
                rows.sort_by(|a, b| a.0.cmp(b.0));
                rows.into_iter()
                    .map(
                        |(name, identity, version, caller_relative, completeness, profiles, comment)| {
                            serde_json::json!({
                                "relation_name": name,
                                "identity": identity,
                                "semantic_version": version,
                                "caller_relative": caller_relative,
                                "completeness": completeness,
                                "profiles": profiles,
                                "comment": comment,
                            })
                        },
                    )
                    .collect()
            },
        },
        ConformanceCase {
            name: "worked_current_work_orders_by_recency",
            sql: scoped_card_sql("Current work", "id LIKE 'conf:%'"),
            parameters: Vec::new(),
            expected_columns: vec!["id", "type", "name", "lifecycle"],
            // conf:common is the most recently active (newer than
            // conf:alice despite sorting after it by id), so this case
            // proves recency ordering rather than the id tiebreak.
            // conf:bea is hidden and conf:tomb deleted.
            expected_rows: vec![
                serde_json::json!({"id": "conf:common", "type": "WorkItem", "name": "Common", "lifecycle": "in_progress"}),
                serde_json::json!({"id": "conf:alice", "type": "WorkItem", "name": "Alice note", "lifecycle": "open"}),
            ],
        },
        ConformanceCase {
            name: "worked_direct_children_of_a_record",
            sql: scoped_card_sql("Direct children of a folder or record", "id LIKE 'conf:%'"),
            parameters: vec![QuerySqlParameter::Text {
                value: Some("conf:common".into()),
            }],
            expected_columns: vec!["id", "type", "name"],
            expected_rows: vec![
                serde_json::json!({"id": "conf:alice", "type": "WorkItem", "name": "Alice note"}),
            ],
        },
        ConformanceCase {
            name: "worked_parts_of_a_record",
            sql: scoped_card_sql(
                "Parts of a record (semantic part_of links run child source -> parent target)",
                "r.id LIKE 'conf:%'",
            ),
            parameters: vec![QuerySqlParameter::Text {
                value: Some("conf:alice".into()),
            }],
            expected_columns: vec!["source_id", "name"],
            // part_of runs child source -> parent target: conf:common is
            // the part, conf:alice the whole.
            expected_rows: vec![
                serde_json::json!({"source_id": "conf:common", "name": "Common"}),
            ],
        },
        ConformanceCase {
            name: "worked_recent_history_of_one_record",
            sql: scoped_card_sql("Recent history of one record", "record_id LIKE 'conf:%'"),
            parameters: vec![QuerySqlParameter::Text {
                value: Some("conf:common".into()),
            }],
            expected_columns: vec!["local_seq", "type", "created_at"],
            expected_rows: vec![
                serde_json::json!({"local_seq": 91004, "type": "record.updated", "created_at": "2026-01-05T00:00:00.000Z"}),
                serde_json::json!({"local_seq": 91001, "type": "record.updated", "created_at": "2026-01-01T00:00:00.000Z"}),
            ],
        },
        ConformanceCase {
            name: "worked_unchecked_checklist_items",
            sql: "SELECT id FROM records WHERE (body LIKE '- [ ]%' OR body LIKE '%\n- [ ]%') AND id LIKE 'conf:%' ORDER BY id",
            parameters: Vec::new(),
            expected_columns: vec!["id"],
            // conf:alice carries a real checkbox; conf:common only quotes
            // the syntax in inline code and must not match.
            expected_rows: vec![
                serde_json::json!({"id": "conf:alice"}),
            ],
        },
    ];
    for case in &cases {
        if case.expected_rows.len() > 1 && !case.sql.to_ascii_uppercase().contains("ORDER BY") {
            panic!(
                "conformance case '{}' expects {} rows but its statement has no ORDER BY; row order is engine-specific without one",
                case.name,
                case.expected_rows.len()
            );
        }
    }
    cases
}

/// Assert one executed case: exact columns and rows, untruncated, and the
/// freshness stamp equal to the workspace head the runner read back after
/// seeding. The stamp assertion is per-engine (each backend reports its own
/// head); row equality is what must hold across engines.
pub(crate) fn check_case(result: &QuerySqlResult, case: &ConformanceCase, head: i64) {
    // Column labels are asserted only for non-empty results: see the
    // `hidden_row_direct_lookup_empty` case note.
    if !case.expected_rows.is_empty() {
        assert_eq!(
            result.columns, case.expected_columns,
            "columns for {}",
            case.name
        );
    }
    assert_eq!(result.rows, case.expected_rows, "rows for {}", case.name);
    assert_eq!(
        result.row_count,
        case.expected_rows.len(),
        "row_count for {}",
        case.name
    );
    assert!(!result.truncated, "truncated for {}", case.name);
    assert_eq!(result.as_of_seq, head, "as_of_seq for {}", case.name);
}

#[cfg(test)]
mod tests {
    use super::super::sql::query_sql_request_owned;
    use super::super::sql_contract::CARD_WORKED_STATEMENTS;
    use super::*;
    use crate::db::Db;
    use crate::query::QueryPrincipal;
    use sqlx::Acquire as _;

    #[test]
    fn every_card_statement_has_a_conformance_case() {
        // Worked cases derive their SQL from the card via scoped_card_sql
        // (seed scope injected before ORDER BY), so assert the exact head
        // and tail rather than a substring: a typo in ORDER BY, LIMIT or a
        // ?N index fails here instead of shipping green.
        for (intent, sql) in CARD_WORKED_STATEMENTS {
            let (head, tail) = sql
                .split_once(" ORDER BY")
                .unwrap_or_else(|| panic!("card statement '{intent}' has no ORDER BY"));
            assert!(
                corpus()
                    .iter()
                    .any(|case| case.sql.starts_with(head) && case.sql.ends_with(tail)),
                "card statement '{intent}' has no conformance case running it verbatim"
            );
        }
    }

    // Visibility runs through the real write path: the projector
    // produces the policy rows, never a hand-written INSERT. The
    // tombstone needs no grant: deleted records are invisible anyway,
    // and the projector refuses grants on them.
    async fn grant_conformance_policies(db: &Db) {
        for (id, accounts) in [
            ("conf:common", vec!["alice", "bea"]),
            ("conf:alice", vec!["alice"]),
            ("conf:bea", vec!["bea"]),
            ("conf:sort-a", vec!["alice"]),
            ("conf:sort-b", vec!["alice"]),
            ("conf:sort-c", vec!["alice"]),
        ] {
            crate::authorization::replace_explicit_policy(
                db,
                "test:policy",
                id,
                accounts
                    .into_iter()
                    .map(|account| {
                        crate::authorization::AllowEntry::account(
                            account,
                            crate::authorization::Capability::View,
                        )
                    })
                    .collect(),
            )
            .await
            .unwrap_or_else(|error| panic!("conformance policy grant failed for {id}: {error}"));
        }
    }

    async fn seeded_sqlite() -> (Db, QueryPrincipal, i64) {
        let db = crate::create_database(":memory:").await.unwrap();
        for statement in SEED_SQL {
            sqlx::query(statement)
                .execute(db.write_pool())
                .await
                .unwrap_or_else(|error| panic!("conformance seed failed for {statement}: {error}"));
        }
        grant_conformance_policies(&db).await;
        let head: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert!(head >= SEED_MIN_HEAD, "seed must own the head, got {head}");
        (db, QueryPrincipal::authenticated("alice", true), head)
    }

    async fn run_owned(db: &Db, principal: QueryPrincipal, sql: &str) -> QuerySqlResult {
        query_sql_request_owned(
            db.clone(),
            principal,
            QuerySqlRequest {
                sql: sql.into(),
                parameters: Vec::new(),
            },
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn sqlite_truncated_results_carry_the_keyset_hint() {
        // vocabularies is caller-independent, so 1001 rows need no grants.
        let (db, alice, _) = seeded_sqlite().await;
        let mut insert = String::from("INSERT INTO vocabularies(id,name,created_at) VALUES ");
        for index in 0..1001 {
            if index > 0 {
                insert.push(',');
            }
            insert.push_str(&format!(
                "('bulk:{index:04}','Bulk {index}','2026-01-01T00:00:00Z')"
            ));
        }
        sqlx::query(&insert).execute(db.write_pool()).await.unwrap();
        let result = run_owned(
            &db,
            alice,
            "SELECT id FROM vocabularies WHERE id LIKE 'bulk:%' ORDER BY id",
        )
        .await;
        assert!(result.truncated);
        assert_eq!(result.row_count, 1000);
        assert_eq!(
            result.truncation_hint,
            Some(crate::query::sql_contract::truncation_hint())
        );
        let small = run_owned(
            &db,
            QueryPrincipal::authenticated("alice", true),
            "SELECT id FROM vocabularies WHERE id = 'bulk:0000'",
        )
        .await;
        assert!(!small.truncated);
        assert_eq!(small.truncation_hint, None);
    }

    #[tokio::test]
    async fn sqlite_rejects_gapped_placeholders() {
        // I1 review: `?2` with one parameter fails instead of binding a
        // silent NULL; the Turso and Postgres engines assert the same.
        let (db, alice, _) = seeded_sqlite().await;
        let error = query_sql_request_owned(
            db.clone(),
            alice,
            QuerySqlRequest {
                sql: "SELECT id FROM records WHERE id = ?2".into(),
                parameters: vec![QuerySqlParameter::Text {
                    value: Some("conf:common".into()),
                }],
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("ordered parameters and `?N` placeholders must match exactly"),
            "unexpected refusal: {error}"
        );
    }

    #[tokio::test]
    async fn sqlite_runs_conformance_corpus() {
        let (db, alice, head) = seeded_sqlite().await;
        for case in corpus() {
            let result = query_sql_request_owned(db.clone(), alice.clone(), case.request())
                .await
                .unwrap_or_else(|error| panic!("sqlite failed {}: {error}", case.name));
            check_case(&result, &case, head);
        }
    }

    #[tokio::test]
    async fn as_of_seq_matches_the_workspace_head() {
        let (db, alice, head) = seeded_sqlite().await;
        let result = run_owned(&db, alice, "SELECT 1 AS one").await;
        assert_eq!(result.as_of_seq, head);
        assert!(result.as_of_seq >= SEED_MIN_HEAD);
    }

    #[tokio::test]
    async fn as_of_seq_advances_after_a_write() {
        let (db, alice, _) = seeded_sqlite().await;
        let before = run_owned(&db, alice.clone(), "SELECT count(*) AS n FROM records").await;
        // The public writer requires a canonical UUID id; the raw `conf:`
        // seed rows bypass it through SQL, which is fine for fixtures.
        crate::store::create_record(
            &db,
            serde_json::json!({
                "id": "9e795000-0000-4000-8000-0000f00d00a1",
                "type": "Document",
                "kind": "note",
                "name": "Fresh",
                "home_id": crate::schema::ROOT_RECORD_ID,
            }),
        )
        .await
        .unwrap();
        let after = run_owned(&db, alice, "SELECT count(*) AS n FROM records").await;
        assert!(
            after.as_of_seq > before.as_of_seq,
            "stamp must advance: {} -> {}",
            before.as_of_seq,
            after.as_of_seq
        );
    }

    #[tokio::test]
    async fn as_of_seq_and_rows_share_one_snapshot() {
        use super::super::sql::query_sql_request_in;
        // File-backed on purpose: every `:memory:` connection gets a
        // private database, so an intervening commit from another
        // connection needs a file. WAL pins this transaction's snapshot
        // at its first read; the write below commits into frames this
        // snapshot cannot see.
        let directory = tempfile::tempdir().unwrap();
        let db = crate::create_database(directory.path().join("snapshot.db").to_str().unwrap())
            .await
            .unwrap();
        for statement in SEED_SQL {
            sqlx::query(statement)
                .execute(db.write_pool())
                .await
                .unwrap();
        }
        // Grants first: even the trusted bypass requires an explicit
        // policy anchor row before a record is visible.
        grant_conformance_policies(&db).await;
        let trusted = unsafe { QueryPrincipal::trusted_local_unchecked("test") };
        let request = || QuerySqlRequest {
            sql: "SELECT id FROM records WHERE id LIKE 'conf:%' ORDER BY id".into(),
            parameters: Vec::new(),
        };
        let mut connection = db.write_pool().acquire().await.unwrap();
        let mut tx = connection.begin().await.unwrap();
        let first = query_sql_request_in(&mut tx, trusted.clone(), request())
            .await
            .unwrap();
        // A write committed on another connection after the read's snapshot
        // was taken. The row is conf:-prefixed, so the in-transaction rows
        // assertion below can actually fail; the grant runs through the
        // projector and the event advances the workspace head.
        sqlx::query(
            "INSERT INTO records(id,type,kind,name,home_id,owner_id,policy_anchor_id,created_at,updated_at) VALUES \
             ('conf:late','Document','note','Late',NULL,NULL,'conf:late','2026-01-01T00:00:00.000Z','2026-01-01T00:00:00.000Z')",
        )
        .execute(db.write_pool())
        .await
        .unwrap();
        crate::authorization::replace_explicit_policy(
            &db,
            "test:policy",
            "conf:late",
            vec![crate::authorization::AllowEntry::account(
                "alice",
                crate::authorization::Capability::View,
            )],
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO content_events(id,record_id,type,created_at,causal_envelope_version,causal_status) VALUES \
             ('conf:event-late','conf:late','record.updated','2026-01-01T00:00:00.000Z',1,'legacy_unknown')",
        )
        .execute(db.write_pool())
        .await
        .unwrap();
        let second = query_sql_request_in(&mut tx, trusted.clone(), request())
            .await
            .unwrap();
        // Same transaction: neither rows nor stamp may move.
        assert_eq!(second.rows, first.rows);
        assert!(
            !second.rows.iter().any(|row| row["id"] == "conf:late"),
            "intervening commit leaked into the read snapshot: {:?}",
            second.rows
        );
        assert_eq!(second.as_of_seq, first.as_of_seq);
        tx.rollback().await.unwrap();
        // Fresh read: the committed write is visible under a newer stamp.
        let third = run_owned(
            &db,
            trusted,
            "SELECT id FROM records WHERE id LIKE 'conf:%' ORDER BY id",
        )
        .await;
        assert_eq!(third.rows.len(), first.rows.len() + 1);
        assert!(third.as_of_seq > first.as_of_seq);
        assert!(third.rows.iter().any(|row| row["id"] == "conf:late"));
    }

    #[tokio::test]
    async fn as_of_seq_covers_the_returned_rows() {
        // Trusted-local sees everything, so the check is purely temporal: no
        // returned record may own an event newer than the stamp, and a record
        // written after the first read must be absent from it yet present
        // under a newer stamp.
        use super::super::sql::query_sql;
        let (db, _, _) = seeded_sqlite().await;
        let trusted = unsafe { QueryPrincipal::trusted_local_unchecked("test") };
        const FRESH_ID: &str = "9e795000-0000-4000-8000-0000f00d00a2";
        let first = query_sql(&db, trusted.clone(), "SELECT id FROM records")
            .await
            .unwrap();
        let first_ids: Vec<String> = first
            .rows
            .iter()
            .map(|row| row["id"].as_str().unwrap().to_string())
            .collect();
        assert!(!first_ids.contains(&FRESH_ID.to_string()));
        crate::store::create_record(
            &db,
            serde_json::json!({
                "id": FRESH_ID,
                "type": "Document",
                "kind": "note",
                "name": "Fresh",
                "home_id": crate::schema::ROOT_RECORD_ID,
            }),
        )
        .await
        .unwrap();
        let second = query_sql(&db, trusted, "SELECT id FROM records")
            .await
            .unwrap();
        assert!(second.as_of_seq > first.as_of_seq);
        let second_ids: Vec<String> = second
            .rows
            .iter()
            .map(|row| row["id"].as_str().unwrap().to_string())
            .collect();
        assert!(second_ids.contains(&FRESH_ID.to_string()));
        // Every returned record's newest event must predate the stamp that
        // covered it: a write committed after the read's snapshot can never
        // appear under the older stamp, and the stamp always covers its rows.
        for (result, label) in [(&first, "first"), (&second, "second")] {
            for id in result.rows.iter().map(|row| row["id"].as_str().unwrap()) {
                let newest: i64 = sqlx::query_scalar(
                    "SELECT COALESCE(MAX(seq), 0) FROM content_events WHERE record_id = ?",
                )
                .bind(id)
                .fetch_one(db.write_pool())
                .await
                .unwrap();
                assert!(
                    newest <= result.as_of_seq,
                    "{label} read row {id} with event {newest} past stamp {}",
                    result.as_of_seq
                );
            }
        }
    }
}
