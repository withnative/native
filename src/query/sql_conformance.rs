//! Data-driven cross-engine conformance corpus for `query_sql` (E1 M1 slice A).
//!
//! Each case is one statement plus parameters and the exact rows its selected
//! profiles return for the shared [`SEED_SQL`] below, read as alice (who
//! sees `conf:common` and `conf:alice` but must never see `conf:bea`).
//!
//! How to add a case (later milestones keep extending [`corpus`]):
//! 1. Seed every row the case reads in [`SEED_SQL`] with a fixture-prefixed
//!    id (`conf:` or `m2:`), using raw SQL verbatim on SQLite and Turso.
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
//! PostgreSQL runs a named, non-divergent subset through its translated
//! fixture. Recursive containment is SQLite only; PostgreSQL and Turso pin
//! their deliberate validator/read-only refusals against the same recipe.

use serde_json::Value;

use super::sql_contract::ASSUMED_ORDER_REASON;
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
/// self-anchor and no owner in the original corpus; containment fixtures
/// reuse those projected grants through their policy_anchor_id.
pub(crate) const SEED_SQL: &[&str] = &[
    "INSERT INTO records(id,type,kind,name,body,home_id,owner_id,policy_anchor_id) VALUES
      ('conf:common','Document','note','Common','common body quoting `- [ ]` inline',NULL,NULL,'conf:common'),
      ('conf:alice','Document','note','Alice note','alice body\n- [ ] buy milk\n> * [ ] quoted\n- [x] done\n```\n- [ ] fenced\n```',NULL,NULL,'conf:alice'),
      ('conf:bea','Document','note','Bea note','bea body\n- [ ] private',NULL,NULL,'conf:bea'),
      ('conf:tomb','Document','note','Tomb','tomb body',NULL,NULL,'conf:tomb'),
      ('conf:sort-a','Document','note','apple',NULL,NULL,NULL,'conf:sort-a'),
      ('conf:sort-b','Document','note','Banana',NULL,NULL,NULL,'conf:sort-b'),
      ('conf:sort-c','Document','note','Äpfel',NULL,NULL,NULL,'conf:sort-c')",
    "INSERT INTO records(id,type,kind,name,home_id,policy_anchor_id) VALUES
      ('m2:deep:00','Document','note','Deep 00',NULL,'conf:common'),
      ('m2:deep:01','Document','note','Deep 01','m2:deep:00','conf:common'),
      ('m2:deep:02','Document','note','Deep 02','m2:deep:01','conf:common'),
      ('m2:deep:03','Document','note','Deep 03','m2:deep:02','conf:common'),
      ('m2:deep:04','Document','note','Deep 04','m2:deep:03','conf:common'),
      ('m2:deep:05','Document','note','Deep 05','m2:deep:04','conf:common'),
      ('m2:deep:06','Document','note','Deep 06','m2:deep:05','conf:common'),
      ('m2:deep:07','Document','note','Deep 07','m2:deep:06','conf:common'),
      ('m2:deep:08','Document','note','Deep 08','m2:deep:07','conf:common'),
      ('m2:deep:09','Document','note','Deep 09','m2:deep:08','conf:common'),
      ('m2:deep:10','Document','note','Deep 10','m2:deep:09','conf:common'),
      ('m2:deep:11','Document','note','Deep 11','m2:deep:10','conf:common'),
      ('m2:deep:12','Document','note','Deep 12','m2:deep:11','conf:common'),
      ('m2:deep:13','Document','note','Deep 13','m2:deep:12','conf:common'),
      ('m2:deep:14','Document','note','Deep 14','m2:deep:13','conf:common'),
      ('m2:deep:15','Document','note','Deep 15','m2:deep:14','conf:common'),
      ('m2:deep:16','Document','note','Deep 16','m2:deep:15','conf:common'),
      ('m2:deep:17','Document','note','Deep 17','m2:deep:16','conf:common'),
      ('m2:deep:18','Document','note','Deep 18','m2:deep:17','conf:common'),
      ('m2:deep:19','Document','note','Deep 19','m2:deep:18','conf:common'),
      ('m2:deep:20','Document','note','Deep 20','m2:deep:19','conf:common'),
      ('m2:deep:21','Document','note','Deep 21','m2:deep:20','conf:common'),
      ('m2:deep:22','Document','note','Deep 22','m2:deep:21','conf:common'),
      ('m2:deep:23','Document','note','Deep 23','m2:deep:22','conf:common'),
      ('m2:deep:24','Document','note','Deep 24','m2:deep:23','conf:common'),
      ('m2:deep:25','Document','note','Deep 25','m2:deep:24','conf:common'),
      ('m2:deep:26','Document','note','Deep 26','m2:deep:25','conf:common'),
      ('m2:deep:27','Document','note','Deep 27','m2:deep:26','conf:common'),
      ('m2:deep:28','Document','note','Deep 28','m2:deep:27','conf:common'),
      ('m2:deep:29','Document','note','Deep 29','m2:deep:28','conf:common'),
      ('m2:deep:30','Document','note','Deep 30','m2:deep:29','conf:common'),
      ('m2:deep:31','Document','note','Deep 31','m2:deep:30','conf:common'),
      ('m2:deep:32','Document','note','Deep 32','m2:deep:31','conf:common'),
      ('m2:deep:33','Document','note','Deep 33','m2:deep:32','conf:common')",
    // M2 containment fixtures: visible rows reuse conf:common's grant; the
    // private branch reuses conf:bea's. No new policy write exception.
    // These are supplied projection inputs, including corrupt containment
    // cycles; they test visible SQL reachability, not policy inheritance.
    "INSERT INTO records(id,type,kind,name,home_id,policy_anchor_id,archived,deleted_at) VALUES
      ('m2:root','Collection','folder','Root',NULL,'conf:common',0,NULL),
      ('m2:a','Document','note','A','m2:root','conf:common',0,NULL),
      ('m2:b','Document','note','B','m2:a','conf:common',0,NULL),
      ('m2:c','Document','note','C','m2:b','conf:common',0,NULL),
      ('m2:arch','Collection','folder','Archived','m2:root','conf:common',1,NULL),
      ('m2:arch-child','Document','note','Archived child','m2:arch','conf:common',0,NULL),
      ('m2:excluded','Entity','person','Excluded','m2:root','conf:common',0,NULL),
      ('m2:excluded-child','Document','note','Excluded child','m2:excluded','conf:common',0,NULL),
      ('m2:private','Collection','folder','Private','m2:root','conf:bea',0,NULL),
      ('m2:private-child','Document','note','Visible child','m2:private','conf:common',0,NULL),
      ('m2:deleted','Collection','folder','Deleted','m2:root','conf:common',0,'2026-01-01T00:00:00.000Z'),
      ('m2:deleted-child','Document','note','Deleted child','m2:deleted','conf:common',0,NULL),
      ('m2:hidden','Annotation','attribution','Hidden','m2:root','conf:common',0,NULL),
      ('m2:hidden-child','Document','note','Hidden child','m2:hidden','conf:common',0,NULL),
      ('m2:cycle-a','Collection','folder','Cycle A','m2:cycle-b','conf:common',0,NULL),
      ('m2:cycle-b','Collection','folder','Cycle B','m2:cycle-a','conf:common',0,NULL),
      ('m2:self','Collection','folder','Self','m2:self','conf:common',0,NULL)",

    // The recipe and tree.rs use archive facet presence; keep the physical
    // archived projection consistent too; traversal uses facet presence.
    "INSERT INTO facet_values(id,record_id,key,value,created_at) VALUES
      ('m2:facet-arch','m2:arch','archived','true','2026-01-01T00:00:00.000Z')",
    "UPDATE records SET created_at='2026-01-01T00:00:00.000Z',updated_at='2026-01-01T00:00:00.000Z' WHERE id LIKE 'conf:%'",
    "UPDATE records SET created_at='2026-01-02T00:00:00.000Z',updated_at='2026-01-02T00:00:00.000Z' WHERE id='conf:alice'",
    "UPDATE records SET type='WorkItem',lifecycle='open' WHERE id='conf:alice'",
    "UPDATE records SET type='WorkItem',lifecycle='in_progress' WHERE id='conf:common'",
    "UPDATE records SET home_id='conf:common' WHERE id='conf:alice'",
    "UPDATE records SET deleted_at='2026-01-02T00:00:00.000Z' WHERE id='conf:tomb'",
    "INSERT INTO links(id,source_id,target_id,relationship,note,created_at) VALUES
      ('conf:link-open','conf:common','conf:alice','relates_to',NULL,'2026-01-01T00:00:00.000Z'),
      ('conf:link-part','conf:common','conf:alice','part_of',NULL,'2026-01-01T00:00:00.000Z'),
      ('conf:link-sealed','conf:common','conf:bea','relates_to',NULL,'2026-01-01T00:00:00.000Z'),
      ('currency:edge','conf:alice','conf:common','supersedes',NULL,'2026-01-01T00:00:00.000Z')",
    "UPDATE records SET is_current=NULL,successor_count=1 WHERE id='conf:common'",
    // Archive is independent of supersession and remains visible in records.
    "UPDATE records SET archived=1 WHERE id IN ('conf:common','conf:alice','conf:bea')",
    // Citation-shaped ordinary links do not certify a source as current; the
    // real selector-backed citation/write path is qualified in records/citations.
    "INSERT INTO links(id,source_id,target_id,relationship,note,created_at) VALUES
      ('currency:cited-unknown','conf:sort-a','conf:common','cites',NULL,'2026-01-01T00:00:00.000Z'),
      ('currency:cited-current','conf:sort-a','conf:alice','cites',NULL,'2026-01-01T00:00:00.000Z')",
    "INSERT INTO content_events(seq,id,record_id,type,created_at,causal_envelope_version,causal_status) VALUES
      (91001,'conf:event-common','conf:common','record.updated','2026-01-01T00:00:00.000Z',1,'legacy_unknown'),
      (91002,'conf:event-hidden','conf:bea','record.updated','2026-01-01T00:00:00Z',1,'legacy_unknown'),
      (91004,'conf:event-common-2','conf:common','record.updated','2026-01-05T00:00:00Z',1,'legacy_unknown'),
      (91003,'task:event-alice','conf:alice','record.updated','2026-01-03T00:00:00Z',1,'legacy_unknown')",
    // Projection rows are the current body's GFM tasks. The inline checkbox
    // on common and fenced checkbox on alice have no rows. Bea's task is
    // present physically but must disappear through caller visibility.
    "INSERT INTO body_task_items(record_id,item_index,source_event_seq,marker,checked,in_quote,start_offset,end_offset) VALUES
      ('conf:alice',0,91003,'-',0,0,11,25),
      ('conf:alice',1,91003,'*',0,1,28,40),
      ('conf:alice',2,91003,'-',1,0,41,51),
      ('conf:bea',0,91002,'-',0,0,9,22)",
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
    // E1 M4: missing ALL_PROFILES relations. facet_observations follows
    // record visibility (conf:bea hidden); vocabularies and
    // vocabulary_values are caller-independent; schema_config with a NULL
    // collection scope is visible to every caller. Runs verbatim on SQLite
    // and Turso. Blobs stay out: their view gate needs an attachment
    // record plus blob_ref plus part_of link (follow-on).
    "INSERT INTO facet_observations(id,record_id,key,value,op,vocab_ref,as_of,observed_at,event_seq) VALUES
      ('conf:obs-common','conf:common','color','blue','set',NULL,'2026-01-01T00:00:00.000Z','2026-01-01T00:00:00.000Z',91001),
      ('conf:obs-hidden','conf:bea','color','red','set',NULL,'2026-01-01T00:00:00.000Z','2026-01-01T00:00:00.000Z',91002)",
    "INSERT INTO vocabularies(id,name,created_at) VALUES
      ('conf:vocab','Conf vocabulary','2026-01-01T00:00:00.000Z')",
    "INSERT INTO vocabulary_values(id,vocabulary_id,value,gloss,status,ordinal,terminality,metadata,alias_of) VALUES
      ('conf:vv-blue','conf:vocab','blue','Conf blue','active',1,'open','{}',NULL),
      ('conf:vv-green','conf:vocab','green',NULL,'active',2,'open','{}',NULL)",
    "INSERT INTO schema_config(id,layer,name,data,applies_to_collection_id,version_lineage,created_at) VALUES
      ('conf:cfg','user','conf-test','{}',NULL,'v1','2026-01-01T00:00:00.000Z')",
];

/// Seed-contributed content head. Runners assert against the read-back head,
/// not this constant; it exists so future cases can pick non-colliding
/// explicit `seq` values above it.
pub(crate) const SEED_MIN_HEAD: i64 = 91002;

/// One corpus case: a statement, its parameters, and the exact columns and
/// rows the selected profiles must return for the shared seed as alice.
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

/// SQLite/Turso corpus. PostgreSQL selects named portable cases explicitly.
/// SQLite-only containment cases live in containment_corpus().
/// Multi-row cases must carry ORDER BY: `check_case` compares rows in
/// order, and without it that order is engine-specific. This is enforced
/// below (single-row and empty cases are order-free).
pub(crate) fn corpus() -> Vec<ConformanceCase> {
    let mut cases = vec![
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
            name: "records_currency_counts_match_physical_projection",
            sql: "SELECT id, is_current, successor_count FROM records WHERE id IN ('conf:alice','conf:common') ORDER BY id",
            parameters: Vec::new(),
            expected_columns: vec!["id", "is_current", "successor_count"],
            expected_rows: vec![
                serde_json::json!({"id": "conf:alice", "is_current": 1, "successor_count": 0}),
                serde_json::json!({"id": "conf:common", "is_current": null, "successor_count": 1}),
            ],
        },
        ConformanceCase {
            name: "records_archived_currency_orthogonal",
            sql: "SELECT r.id,r.archived,r.is_current,r.successor_count FROM records r JOIN links l ON l.target_id=r.id WHERE l.relationship='cites' ORDER BY r.id",
            parameters: Vec::new(),
            expected_columns: vec!["id", "archived", "is_current", "successor_count"],
            expected_rows: vec![
                serde_json::json!({"id":"conf:alice","archived":1,"is_current":1,"successor_count":0}),
                serde_json::json!({"id":"conf:common","archived":1,"is_current":null,"successor_count":1}),
            ],
        },
        ConformanceCase {
            name: "records_archived_does_not_disclose_hidden_rows",
            sql: "SELECT id,archived FROM records WHERE archived=1 AND id LIKE 'conf:%' ORDER BY id",
            parameters: Vec::new(),
            expected_columns: vec!["id", "archived"],
            expected_rows: vec![
                serde_json::json!({"id":"conf:alice","archived":1}),
                serde_json::json!({"id":"conf:common","archived":1}),
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
            name: "nulls_sort_first_on_asc",
            sql: "SELECT x FROM (SELECT 'a' AS x UNION ALL SELECT NULL AS x) ORDER BY x",
            parameters: Vec::new(),
            expected_columns: vec!["x"],
            // I3: the target null ordering (NULLS FIRST on ASC) is native
            // on SQLite/Turso and normalised on Postgres, so nulls lead on
            // every engine.
            expected_rows: vec![
                serde_json::json!({"x": null}),
                serde_json::json!({"x": "a"}),
            ],
        },
        ConformanceCase {
            name: "nulls_sort_last_on_desc",
            sql: "SELECT x FROM (SELECT 'a' AS x UNION ALL SELECT NULL AS x) ORDER BY x DESC",
            parameters: Vec::new(),
            expected_columns: vec!["x"],
            // I3: NULLS LAST on DESC, native or normalised per engine.
            expected_rows: vec![
                serde_json::json!({"x": "a"}),
                serde_json::json!({"x": null}),
            ],
        },
        ConformanceCase {
            name: "zero_divisors_yield_null",
            sql: "SELECT 1 / 0 AS d, 5 % 0 AS m, 1 / NULLIF(0, 0) AS n",
            parameters: Vec::new(),
            expected_columns: vec!["d", "m", "n"],
            // I3: zero divisors yield NULL — natively on SQLite/Turso, via
            // NULLIF normalisation on Postgres. Single row: no ORDER BY.
            expected_rows: vec![
                serde_json::json!({"d": null, "m": null, "n": null}),
            ],
        },
        ConformanceCase {
            name: "like_matches_ascii_case_insensitively",
            sql: "SELECT ('ABC' LIKE 'abc') AS m",
            parameters: Vec::new(),
            expected_columns: vec!["m"],
            // I4: bare LIKE is case-insensitive on every engine — natively
            // on SQLite/Turso (ASCII folding), via the LIKE→ILIKE AST
            // rewrite on Postgres (booleans encode as 0/1 there, matching
            // the integer SQLite/Turso return). Single row: no ORDER BY.
            expected_rows: vec![serde_json::json!({"m": 1})],
        },
        ConformanceCase {
            name: "like_leaves_non_ascii_case_unfolded",
            sql: "SELECT id FROM records WHERE name LIKE 'äpfel' ORDER BY id",
            parameters: Vec::new(),
            // Empty on every engine, so no column labels are asserted
            // (they diverge on empty results: SQLite reports none, Turso
            // reports prepared labels — see hidden_row_direct_lookup_empty).
            expected_columns: Vec::new(),
            // I4: measured ASCII-only folding on every engine. SQLite and
            // Turso LIKE never fold non-ASCII ('Äpfel' LIKE 'äpfel' is
            // false); Postgres ILIKE would fold 'É' to 'é' under the
            // default collation, but the logical views project every text
            // column with COLLATE "C", under which ILIKE folds ASCII only
            // (verified live on PG16) — so through the views all engines
            // agree that 'Äpfel' does not match 'äpfel'. Bare non-ASCII
            // literals outside the views are outside the portable
            // contract: 'É' LIKE 'é' is 1 on Postgres, 0 on SQLite/Turso.
            expected_rows: Vec::new(),
        },
        ConformanceCase {
            name: "widened_scalar_functions_agree",
            sql: "SELECT lower('AbC') AS lo, upper('AbC') AS hi, trim(' x ') AS t, replace('aab', 'a', 'c') AS r, substr('hello', 2, 3) AS s, coalesce(NULL, 'z') AS c, nullif('a', 'a') AS n, abs(-3) AS a, length('hey') AS l",
            parameters: Vec::new(),
            expected_columns: vec!["lo", "hi", "t", "r", "s", "c", "n", "a", "l"],
            // I2: the widened intersection executes identically on
            // SQLite and Turso (the Postgres runner reuses `check_case`).
            // Single row, so no ORDER BY is required.
            expected_rows: vec![
                serde_json::json!({"lo": "abc", "hi": "ABC", "t": "x", "r": "ccb", "s": "ell", "c": "z", "n": null, "a": 3, "l": 3}),
            ],
        },
        ConformanceCase {
            name: "utc_date_label_vectors_agree",
            sql: "SELECT utc_date_label(0) AS epoch, utc_date_label(-1) AS pre_epoch, utc_date_label(-86400000) AS pre_day, utc_date_label(1790294400000) AS slate_fri, utc_date_label(1790294399999) AS slate_thu, utc_date_label(1709164800000) AS leap, utc_date_label(1790380799999) AS fri_late, utc_date_label(1790380800000) AS sat, utc_date_label(-62167219200000) AS min_label, utc_date_label(253402300799999) AS max_label, utc_date_label(NULL) AS null_label",
            parameters: Vec::new(),
            expected_columns: vec![
                "epoch",
                "pre_epoch",
                "pre_day",
                "slate_fri",
                "slate_thu",
                "leap",
                "fri_late",
                "sat",
                "min_label",
                "max_label",
                "null_label",
            ],
            // Native e25665c: the portable UTC label executes identically
            // on every engine (SQLite/Turso via the `strftime` lowering,
            // Postgres via the `to_timestamp`/`EXTRACT` lowering; the PG
            // runner reuses `check_case`). Integer epoch milliseconds in,
            // English `DDD D MMM` in UTC out (Sunday zero, no year, no
            // leading day zero), NULL in NULL out. Single row: no ORDER BY.
            // The supported UTC years 0000–9999 are bounded by min/max
            // endpoint columns so real-PG CI proves the claimed boundary;
            // outside that range the engines diverge (SQLite yields NULL,
            // Turso labels on, Postgres raises), so extremes stay out of
            // this shared case by design. Year-0 weekday assumes
            // proleptic-Gregorian agreement (SQLite/Turso pin Saturday
            // locally); if PG computes it differently, CI decides and the
            // min endpoint narrows.
            expected_rows: vec![
                serde_json::json!({"epoch": "Thu 1 Jan", "pre_epoch": "Wed 31 Dec", "pre_day": "Wed 31 Dec", "slate_fri": "Fri 25 Sep", "slate_thu": "Thu 24 Sep", "leap": "Thu 29 Feb", "fri_late": "Fri 25 Sep", "sat": "Sat 26 Sep", "min_label": "Sat 1 Jan", "max_label": "Fri 31 Dec", "null_label": null}),
            ],
        },
        ConformanceCase {
            name: "trim_with_chars_agrees",
            sql: "SELECT trim('xxhelloxx', 'x') AS t",
            parameters: Vec::new(),
            expected_columns: vec!["t"],
            // I2 review: two-argument `trim(x, chars)` is `btrim(x,
            // chars)` on Postgres with identical semantics, so every
            // engine returns the same result. Single row, so no ORDER BY
            // is required.
            expected_rows: vec![serde_json::json!({"t": "hello"})],
        },
        ConformanceCase {
            name: "regexp_matches_text",
            sql: "SELECT id, regexp('milk', body) AS hit FROM records WHERE id IN ('conf:common','conf:alice') ORDER BY id",
            parameters: Vec::new(),
            expected_columns: vec!["id", "hit"],
            // E1 M3: canonical regexp(pattern, haystack) returns 1/0 on
            // every engine (SQLite via with_regexp, Turso builtin, Postgres
            // via the regexp_like lowering; PG booleans encode as 0/1).
            // Only conf:alice's body mentions milk.
            expected_rows: vec![
                serde_json::json!({"id": "conf:alice", "hit": 1}),
                serde_json::json!({"id": "conf:common", "hit": 0}),
            ],
        },
        ConformanceCase {
            name: "regexp_subset_constructs_agree",
            sql: "SELECT regexp('[a-z]+@[0-9]{2,4}', 'user@42') AS yes, regexp('[a-z]+@[0-9]{2,4}', 'nope') AS no, regexp('banana', 'Banana') AS case_sensitive, regexp('^a.c$', 'abc') AS anchors",
            parameters: Vec::new(),
            expected_columns: vec!["yes", "no", "case_sensitive", "anchors"],
            // E1 M3: ranges, bounded repetition, anchors and alternation
            // from the portable subset; matching stays case-sensitive on
            // every engine (unlike LIKE). Single row: no ORDER BY.
            expected_rows: vec![
                serde_json::json!({"yes": 1, "no": 0, "case_sensitive": 0, "anchors": 1}),
            ],
        },
        ConformanceCase {
            name: "regexp_placeholder_pattern_is_runtime",
            sql: "SELECT id FROM records WHERE regexp(?1, name) AND id LIKE 'conf:sort-%' ORDER BY id",
            parameters: vec![QuerySqlParameter::Text {
                value: Some("^[aB]".into()),
            }],
            expected_columns: vec!["id"],
            // E1 M3: placeholder patterns skip the literal subset check
            // and evaluate at runtime on every engine; the bare boolean
            // form works because PG yields boolean and SQLite/Turso 1/0.
            expected_rows: vec![
                serde_json::json!({"id": "conf:sort-a"}),
                serde_json::json!({"id": "conf:sort-b"}),
            ],
        },
        ConformanceCase {
            name: "regexp_null_inputs_yield_null",
            sql: "SELECT regexp(NULL, name) AS a, regexp('a', NULL) AS b, regexp(NULL, NULL) AS c FROM records WHERE id = 'conf:common'",
            parameters: Vec::new(),
            expected_columns: vec!["a", "b", "c"],
            // E1 M3: NULL in, NULL out on every engine (SQLite UDF,
            // Turso builtin, PG regexp_like). Single row: no ORDER BY.
            expected_rows: vec![serde_json::json!({"a": null, "b": null, "c": null})],
        },
        ConformanceCase {
            name: "regexp_null_haystack_filters_rows",
            sql: "SELECT id FROM records WHERE regexp('a', body) AND id LIKE 'conf:sort-%' ORDER BY id",
            parameters: Vec::new(),
            // Empty on every engine (sort-row bodies are NULL, and NULL
            // filters), so no column labels are asserted — see
            // hidden_row_direct_lookup_empty.
            expected_columns: Vec::new(),
            expected_rows: Vec::new(),
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
            name: "catalog_columns_lists_content_events_columns_in_position",
            sql: "SELECT relation_name, column_name, column_position FROM catalog_columns WHERE relation_name = 'content_events' ORDER BY column_position",
            parameters: Vec::new(),
            expected_columns: vec!["relation_name", "column_name", "column_position"],
            expected_rows: vec![
                serde_json::json!({"relation_name": "content_events", "column_name": "local_seq", "column_position": 0}),
                serde_json::json!({"relation_name": "content_events", "column_name": "id", "column_position": 1}),
                serde_json::json!({"relation_name": "content_events", "column_name": "record_id", "column_position": 2}),
                serde_json::json!({"relation_name": "content_events", "column_name": "type", "column_position": 3}),
                serde_json::json!({"relation_name": "content_events", "column_name": "actor", "column_position": 4}),
                serde_json::json!({"relation_name": "content_events", "column_name": "run_key", "column_position": 5}),
                serde_json::json!({"relation_name": "content_events", "column_name": "parent_key", "column_position": 6}),
                serde_json::json!({"relation_name": "content_events", "column_name": "channel_kind", "column_position": 7}),
                serde_json::json!({"relation_name": "content_events", "column_name": "created_at", "column_position": 8}),
                serde_json::json!({"relation_name": "content_events", "column_name": "created_at_ms", "column_position": 9}),
            ],
        },
        ConformanceCase {
            name: "content_events_attribution_is_null_when_unstamped",
            sql: "SELECT id, actor, run_key, parent_key FROM content_events WHERE id LIKE 'conf:event-%' ORDER BY id",
            parameters: Vec::new(),
            expected_columns: vec!["id", "actor", "run_key", "parent_key"],
            // The seed writes no actor/run lineage, and conf:event-hidden
            // sits on conf:bea, which alice must never see.
            expected_rows: vec![
                serde_json::json!({"id": "conf:event-common", "actor": null, "run_key": null, "parent_key": null}),
                serde_json::json!({"id": "conf:event-common-2", "actor": null, "run_key": null, "parent_key": null}),
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
        ConformanceCase {
            name: "body_task_items_keep_typed_shape_and_visibility",
            sql: "SELECT record_id,item_index,marker,checked,in_quote,start_offset,end_offset FROM body_task_items WHERE record_id LIKE 'conf:%' ORDER BY record_id,item_index",
            parameters: Vec::new(),
            expected_columns: vec!["record_id", "item_index", "marker", "checked", "in_quote", "start_offset", "end_offset"],
            // Bea's row is physically present but hidden. Common's inline
            // checkbox and Alice's fenced checkbox were never projected.
            expected_rows: vec![
                serde_json::json!({"record_id":"conf:alice","item_index":0,"marker":"-","checked":0,"in_quote":0,"start_offset":11,"end_offset":25}),
                serde_json::json!({"record_id":"conf:alice","item_index":1,"marker":"*","checked":0,"in_quote":1,"start_offset":28,"end_offset":40}),
                serde_json::json!({"record_id":"conf:alice","item_index":2,"marker":"-","checked":1,"in_quote":0,"start_offset":41,"end_offset":51}),
            ],
        },
        ConformanceCase {
            name: "body_task_items_strict_unchecked_candidates",
            sql: "SELECT record_id,item_index FROM body_task_items WHERE checked=0 AND in_quote=0 AND marker IN ('-','*','+') AND record_id LIKE 'conf:%' ORDER BY record_id,item_index",
            parameters: Vec::new(),
            expected_columns: vec!["record_id", "item_index"],
            expected_rows: vec![serde_json::json!({"record_id":"conf:alice","item_index":0})],
        },
        ConformanceCase {
            name: "body_task_items_hidden_direct_lookup_empty",
            sql: "SELECT record_id FROM body_task_items WHERE record_id='conf:bea'",
            parameters: Vec::new(),
            expected_columns: Vec::new(),
            expected_rows: Vec::new(),
        },
        ConformanceCase {
            name: "facet_observations_follow_record_visibility",
            sql: "SELECT record_id, key, value FROM facet_observations WHERE id LIKE 'conf:obs-%' ORDER BY id",
            parameters: Vec::new(),
            expected_columns: vec!["record_id", "key", "value"],
            // conf:obs-hidden sits on conf:bea, which alice must never
            // see; only the conf:common observation survives.
            expected_rows: vec![
                serde_json::json!({"record_id": "conf:common", "key": "color", "value": "blue"}),
            ],
        },
        ConformanceCase {
            name: "vocabularies_are_caller_independent",
            sql: "SELECT id, name FROM vocabularies WHERE id LIKE 'conf:%' ORDER BY id",
            parameters: Vec::new(),
            expected_columns: vec!["id", "name"],
            expected_rows: vec![
                serde_json::json!({"id": "conf:vocab", "name": "Conf vocabulary"}),
            ],
        },
        ConformanceCase {
            name: "vocabulary_values_join_vocabularies",
            sql: "SELECT v.value, v.ordinal FROM vocabulary_values AS v JOIN vocabularies AS s ON s.id = v.vocabulary_id WHERE s.id LIKE 'conf:%' ORDER BY v.ordinal",
            parameters: Vec::new(),
            expected_columns: vec!["value", "ordinal"],
            expected_rows: vec![
                serde_json::json!({"value": "blue", "ordinal": 1.0}),
                serde_json::json!({"value": "green", "ordinal": 2.0}),
            ],
        },
        ConformanceCase {
            name: "schema_config_null_scope_visible",
            sql: "SELECT id, layer, name FROM schema_config WHERE id LIKE 'conf:%' ORDER BY id",
            parameters: Vec::new(),
            expected_columns: vec!["id", "layer", "name"],
            expected_rows: vec![
                serde_json::json!({"id": "conf:cfg", "layer": "user", "name": "conf-test"}),
            ],
        },
        ConformanceCase {
            name: "scalar_min_max_agree",
            sql: "SELECT min(value_num) AS mn, max(value_num) AS mx FROM facet_values WHERE key = 'score'",
            parameters: Vec::new(),
            expected_columns: vec!["mn", "mx"],
            // Scores are 10/20/30 (visible rows only). Single row.
            // round() stays out of the shared corpus: round(numeric) is
            // integral on Postgres (JSON integer) but REAL on
            // SQLite/Turso (JSON real) — open M4 divergence, see the
            // divergence notes below, no semantic decision taken here.
            // Window functions stay SQLite-only below: the shared registry
            // scopes the six window rows off TursoLocal (exact 0.8.0
            // resolves the names but compiles every window program as
            // non-read-only, refused by the isolated query-only
            // projection), and the Turso validator fails them closed with
            // plain per-engine advice instead of executing them.
            expected_rows: vec![
                serde_json::json!({"mn": 10.0, "mx": 30.0}),
            ],
        },
        ConformanceCase {
            name: "in_double_paren_subquery_matches",
            sql: "SELECT id FROM records WHERE id IN ((SELECT record_id FROM facet_values WHERE key = 'score')) ORDER BY id",
            parameters: Vec::new(),
            expected_columns: vec!["id"],
            // turso_parser 0.8.0 parses the doubled parens as InSelect
            // (was InList); both engines execute the subquery form.
            expected_rows: vec![
                serde_json::json!({"id": "conf:alice"}),
                serde_json::json!({"id": "conf:common"}),
                serde_json::json!({"id": "conf:sort-a"}),
            ],
        },
        ConformanceCase {
            name: "blob_literal_matches",
            sql: "SELECT x'616263' AS b",
            parameters: Vec::new(),
            expected_columns: vec!["b"],
            // Both engines base64-encode blob cells; single row, no ORDER BY.
            expected_rows: vec![
                serde_json::json!({"b": "YWJj"}),
            ],
        },
    ];
    cases.push(ConformanceCase {
        name: "containment_catalog_hides_parent_gaps",
        sql: "SELECT id, home_id FROM records WHERE id IN ('m2:private-child','m2:deleted-child','m2:hidden-child') ORDER BY id",
        parameters: vec![], expected_columns: vec!["id", "home_id"],
        expected_rows: vec![
            serde_json::json!({"id":"m2:deleted-child","home_id":null}),
            serde_json::json!({"id":"m2:hidden-child","home_id":null}),
            serde_json::json!({"id":"m2:private-child","home_id":null}),
        ],
    });
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

/// Run the exact shipped recipe, so guide edits cannot silently diverge from
/// profile conformance. PostgreSQL/Turso pin their deliberate refusals separately.
pub(crate) fn containment_sql() -> &'static str {
    include_str!("../mcp/guides/query-sql.md.in")
        .split_once("<!-- BOUNDED_VISIBLE_CONTAINMENT -->\n```sql\n")
        .expect("containment recipe marker")
        .1
        .split_once("\n```")
        .expect("containment recipe fence")
        .0
}

/// Exact SQLite visible sets; other profiles test refusal of this same SQL.
/// A cycle is terminated by the
/// depth ceiling, not string paths (which would assume an id delimiter).
pub(crate) fn containment_corpus() -> Vec<ConformanceCase> {
    let rows = |pairs: &[(&str, i64)]| {
        pairs
            .iter()
            .map(|(id, depth)| serde_json::json!({"id":id,"depth":depth}))
            .collect()
    };
    let baseline = [("m2:root", 0), ("m2:a", 1), ("m2:b", 2), ("m2:c", 3)];
    let definitions =
        vec![
        (
            "containment_prunes_subtrees",
            "m2:root",
            32,
            0,
            Some("Entity"),
            rows(&baseline),
        ),
        (
            "containment_depth_zero",
            "m2:root",
            0,
            0,
            Some("Entity"),
            rows(&baseline[..1]),
        ),
        (
            "containment_depth_one",
            "m2:root",
            1,
            0,
            Some("Entity"),
            rows(&baseline[..2]),
        ),
        (
            "containment_depth_two",
            "m2:root",
            2,
            0,
            Some("Entity"),
            rows(&baseline[..3]),
        ),
        (
            "containment_include_archived",
            "m2:root",
            32,
            1,
            Some("Entity"),
            rows(&[
                ("m2:root", 0),
                ("m2:a", 1),
                ("m2:arch", 1),
                ("m2:arch-child", 2),
                ("m2:b", 2),
                ("m2:c", 3),
            ]),
        ),
        (
            "containment_no_type_exclusion",
            "m2:root",
            32,
            0,
            None,
            rows(&[
                ("m2:root", 0),
                ("m2:a", 1),
                ("m2:excluded", 1),
                ("m2:b", 2),
                ("m2:excluded-child", 2),
                ("m2:c", 3),
            ]),
        ),
        (
            "containment_include_all_visible", "m2:root", 32, 1, None,
            rows(&[
                ("m2:root",0),("m2:a",1),("m2:arch",1),("m2:excluded",1),
                ("m2:arch-child",2),("m2:b",2),("m2:excluded-child",2),("m2:c",3),
            ]),
        ),
        (
            "containment_archived_root",
            "m2:arch",
            32,
            0,
            Some("Entity"),
            rows(&[("m2:arch", 0), ("m2:arch-child", 1)]),
        ),
        (
            "containment_excluded_root",
            "m2:excluded",
            32,
            0,
            Some("Entity"),
            rows(&[("m2:excluded", 0), ("m2:excluded-child", 1)]),
        ),
        (
            "containment_private_root",
            "m2:private",
            32,
            1,
            None,
            vec![],
        ),
        (
            "containment_deleted_root",
            "m2:deleted",
            32,
            1,
            None,
            vec![],
        ),
        ("containment_hidden_root", "m2:hidden", 32, 1, None, vec![]),
        (
            "containment_missing_root",
            "m2:missing",
            32,
            1,
            None,
            vec![],
        ),
        (
            "containment_visible_root_below_gap",
            "m2:private-child",
            32,
            0,
            None,
            rows(&[("m2:private-child", 0)]),
        ),
        (
            "containment_cycle",
            "m2:cycle-a",
            32,
            0,
            None,
            rows(&[("m2:cycle-a", 0), ("m2:cycle-b", 1)]),
        ),
        (
            "containment_self_cycle",
            "m2:self",
            32,
            0,
            None,
            rows(&[("m2:self", 0)]),
        ),
        (
            "containment_depth_ceiling",
            "m2:deep:00",
            32,
            0,
            None,
            (0..=32)
                .map(|depth| serde_json::json!({"id":format!("m2:deep:{depth:02}"),"depth":depth}))
                .collect(),
        ),
        ("containment_negative_depth", "m2:root", -1, 0, None, vec![]),
        ("containment_over_ceiling", "m2:root", 33, 0, None, vec![]),
        (
            "containment_invalid_archive_flag",
            "m2:root",
            32,
            2,
            None,
            vec![],
        ),
    ];
    definitions
        .into_iter()
        .map(
            |(name, root, depth, archived, excluded, expected_rows)| ConformanceCase {
                name,
                sql: containment_sql(),
                parameters: vec![
                    QuerySqlParameter::Text {
                        value: Some(root.into()),
                    },
                    QuerySqlParameter::Integer {
                        value: Some(depth.to_string()),
                    },
                    QuerySqlParameter::Integer {
                        value: Some(archived.to_string()),
                    },
                    QuerySqlParameter::Text {
                        value: excluded.map(str::to_owned),
                    },
                ],
                expected_columns: vec!["id", "depth"],
                expected_rows,
            },
        )
        .collect()
}

/// One server-default-ordering case: an unordered top-level LIMIT plus the
/// same statement with the explicit `ORDER BY 1, .., n` the server injects.
/// Kept out of [`corpus`] on purpose: the multi-row ORDER BY guard above
/// would reject the unordered spelling, and engines wire the default in
/// slices (SQLite and Turso here; Postgres follows). Runners execute both
/// spellings and prove identical rows in identical order.
pub(crate) struct DefaultOrderCase {
    pub name: &'static str,
    pub sql: &'static str,
    pub explicit_sql: &'static str,
    pub parameters: Vec<QuerySqlParameter>,
    pub expected_columns: Vec<&'static str>,
    pub expected_rows: Vec<Value>,
}

/// Default-ordering coverage: NULLs, binary text, duplicate rows, compound,
/// CTE-prefixed, and OFFSET shapes. Every case pins exact rows (the
/// deterministic all-columns order) as well as agreement with the explicit
/// spelling.
pub(crate) fn default_order_corpus() -> Vec<DefaultOrderCase> {
    vec![
        DefaultOrderCase {
            name: "default_order_nulls_first",
            sql: "SELECT x FROM (SELECT 'b' AS x UNION ALL SELECT NULL AS x UNION ALL SELECT 'a' AS x) LIMIT 2",
            explicit_sql: "SELECT x FROM (SELECT 'b' AS x UNION ALL SELECT NULL AS x UNION ALL SELECT 'a' AS x) ORDER BY 1 LIMIT 2",
            parameters: Vec::new(),
            expected_columns: vec!["x"],
            expected_rows: vec![
                serde_json::json!({"x": null}),
                serde_json::json!({"x": "a"}),
            ],
        },
        DefaultOrderCase {
            name: "default_order_binary_text",
            sql: "SELECT name FROM records WHERE id LIKE 'conf:sort-%' LIMIT 2",
            explicit_sql: "SELECT name FROM records WHERE id LIKE 'conf:sort-%' ORDER BY 1 LIMIT 2",
            parameters: Vec::new(),
            expected_columns: vec!["name"],
            // Binary (C) order, as in `text_sorts_in_binary_order`.
            expected_rows: vec![
                serde_json::json!({"name": "Banana"}),
                serde_json::json!({"name": "apple"}),
            ],
        },
        DefaultOrderCase {
            name: "default_order_duplicate_rows",
            sql: "SELECT x FROM (SELECT 'a' AS x UNION ALL SELECT 'a' AS x UNION ALL SELECT 'b' AS x) LIMIT 2",
            explicit_sql: "SELECT x FROM (SELECT 'a' AS x UNION ALL SELECT 'a' AS x UNION ALL SELECT 'b' AS x) ORDER BY 1 LIMIT 2",
            parameters: Vec::new(),
            expected_columns: vec!["x"],
            expected_rows: vec![
                serde_json::json!({"x": "a"}),
                serde_json::json!({"x": "a"}),
            ],
        },
        DefaultOrderCase {
            name: "default_order_compound",
            sql: "SELECT 'b' AS v UNION ALL SELECT 'a' AS v UNION ALL SELECT 'c' AS v LIMIT 2",
            explicit_sql: "SELECT 'b' AS v UNION ALL SELECT 'a' AS v UNION ALL SELECT 'c' AS v ORDER BY 1 LIMIT 2",
            parameters: Vec::new(),
            expected_columns: vec!["v"],
            expected_rows: vec![
                serde_json::json!({"v": "a"}),
                serde_json::json!({"v": "b"}),
            ],
        },
        DefaultOrderCase {
            name: "default_order_cte_prefixed",
            sql: "WITH c AS (SELECT 'b' AS v UNION ALL SELECT 'a' AS v) SELECT v FROM c LIMIT 2",
            explicit_sql: "WITH c AS (SELECT 'b' AS v UNION ALL SELECT 'a' AS v) SELECT v FROM c ORDER BY 1 LIMIT 2",
            parameters: Vec::new(),
            expected_columns: vec!["v"],
            expected_rows: vec![
                serde_json::json!({"v": "a"}),
                serde_json::json!({"v": "b"}),
            ],
        },
        DefaultOrderCase {
            name: "default_order_offset",
            sql: "SELECT x FROM (SELECT 'c' AS x UNION ALL SELECT 'a' AS x UNION ALL SELECT 'b' AS x) LIMIT 2 OFFSET 1",
            explicit_sql: "SELECT x FROM (SELECT 'c' AS x UNION ALL SELECT 'a' AS x UNION ALL SELECT 'b' AS x) ORDER BY 1 LIMIT 2 OFFSET 1",
            parameters: Vec::new(),
            expected_columns: vec!["x"],
            expected_rows: vec![
                serde_json::json!({"x": "b"}),
                serde_json::json!({"x": "c"}),
            ],
        },
    ]
}

/// Assert one executed default-ordering case: the unordered spelling
/// discloses the assumed order (exact labels and ordinal clause), both
/// spellings return the pinned rows in order, and both share the snapshot.
pub(crate) fn check_default_order_case(
    unordered: &QuerySqlResult,
    explicit: &QuerySqlResult,
    case: &DefaultOrderCase,
    head: i64,
) {
    let assumed = unordered
        .assumed_order
        .as_ref()
        .unwrap_or_else(|| panic!("assumed_order for {}", case.name));
    assert_eq!(
        assumed.columns, case.expected_columns,
        "columns for {}",
        case.name
    );
    assert_eq!(
        assumed.reason, ASSUMED_ORDER_REASON,
        "reason for {}",
        case.name
    );
    let positions = (1..=case.expected_columns.len())
        .map(|position| position.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    assert_eq!(
        assumed.order_by,
        format!("ORDER BY {positions}"),
        "order_by for {}",
        case.name
    );
    assert!(
        explicit.assumed_order.is_none(),
        "explicit spelling must not assume for {}",
        case.name
    );
    assert_eq!(
        unordered.columns, case.expected_columns,
        "columns for {}",
        case.name
    );
    assert_eq!(unordered.rows, case.expected_rows, "rows for {}", case.name);
    assert_eq!(
        explicit.rows, case.expected_rows,
        "explicit rows for {}",
        case.name
    );
    assert!(!unordered.truncated, "truncated for {}", case.name);
    assert_eq!(unordered.as_of_seq, head, "as_of_seq for {}", case.name);
    assert_eq!(
        explicit.as_of_seq, head,
        "explicit as_of_seq for {}",
        case.name
    );
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

/// One negative case: a statement every engine must refuse, plus the repair
/// substring the refusal must carry. Positive coverage lives in [`corpus`];
/// this table is the M4 "every validator rejection" mechanism. It runs
/// through the real execution gate (SQLite here, Turso/PG in their runners),
/// so a validator bypass that executes instead of refusing fails here.
///
/// Formal pointer to the unit suites that pin the same rules in isolation
/// (this table proves the end-to-end refusal; those prove the classifier):
/// - contract classifier: `crates/query-contract/src/sql_contract.rs`
///   (`validate_portable_calls`, `regexp_literal_patterns_outside_the_subset_are_rejected`,
///   `classifier_rejects_multiple_and_data_modifying_ctes`,
///   `multi_argument_max_min_names_case_before_group_by`);
/// - SQLite authorizer: `src/query/sql.rs` (`SAFE_FUNCTIONS`, `authorize_view_expansion`);
/// - Turso defence: `src/query/turso_validate.rs` plus `src/query/turso_ast_rules.rs`;
/// - Postgres closed walk: `src/postgres/query_sql.rs` (`validate`, arity/repair tests).
pub(crate) struct RejectionCase {
    pub name: &'static str,
    pub sql: &'static str,
    pub parameters: Vec<QuerySqlParameter>,
    pub expected_repair_substring: &'static str,
}

/// Validator rejections every engine must agree on. Keep engine-neutral
/// (`?1` placeholders); the Postgres path rewrites to `$N` after validation
/// like the positive corpus.
pub(crate) fn rejection_corpus() -> Vec<RejectionCase> {
    vec![
        RejectionCase {
            name: "dropped_julianday_suggests_timestamp_columns",
            sql: "SELECT julianday(created_at) FROM records WHERE id LIKE 'conf:%' ORDER BY id",
            parameters: Vec::new(),
            expected_repair_substring: "M1 timestamp columns",
        },
        RejectionCase {
            name: "two_arg_round_rejected",
            sql: "SELECT round(value_num, 1) FROM facet_values WHERE key = 'score' ORDER BY id",
            parameters: Vec::new(),
            expected_repair_substring: "two-argument round",
        },
        RejectionCase {
            name: "two_arg_max_beside_column_names_case",
            sql: "SELECT id, max(value_num, 0) FROM facet_values WHERE key = 'score'",
            parameters: Vec::new(),
            expected_repair_substring: "CASE expression with explicit NULL handling",
        },
        RejectionCase {
            name: "three_arg_max_rejected",
            sql: "SELECT max(value_num, 0, 100) FROM facet_values WHERE key = 'score'",
            parameters: Vec::new(),
            expected_repair_substring: "CASE expression with explicit NULL handling",
        },
        RejectionCase {
            name: "two_arg_min_rejected",
            sql: "SELECT min(value_num, 100) FROM facet_values WHERE key = 'score'",
            parameters: Vec::new(),
            expected_repair_substring: "CASE expression with explicit NULL handling",
        },
        RejectionCase {
            name: "three_arg_min_rejected",
            sql: "SELECT min(value_num, 0, 100) FROM facet_values WHERE key = 'score'",
            parameters: Vec::new(),
            expected_repair_substring: "CASE expression with explicit NULL handling",
        },
        RejectionCase {
            name: "unknown_relation_points_at_catalog",
            sql: "SELECT id FROM nope_records WHERE id LIKE 'conf:%' ORDER BY id",
            parameters: Vec::new(),
            expected_repair_substring: "not a queryable",
        },
        RejectionCase {
            name: "regexp_out_of_subset_rejected_with_repair",
            sql: "SELECT id FROM records WHERE regexp('(?=a)a', name) AND id LIKE 'conf:%' ORDER BY id",
            parameters: Vec::new(),
            expected_repair_substring: "portable subset",
        },
        RejectionCase {
            name: "regexp_column_pattern_rejected_with_shape_repair",
            sql: "SELECT id FROM records WHERE regexp(name, name) AND id LIKE 'conf:%' ORDER BY id",
            parameters: Vec::new(),
            expected_repair_substring: "single-quoted text literal",
        },
        RejectionCase {
            name: "gapped_placeholder_rejected",
            sql: "SELECT id FROM records WHERE id = ?2",
            parameters: vec![QuerySqlParameter::Text {
                value: Some("conf:common".into()),
            }],
            expected_repair_substring: "must match exactly",
        },
    ]
}

/// Open M4 divergences (24 Sep slice-B re-review, carried here). No semantic
/// decision is taken; these are reproducible probes, not corpus cases.
///
/// - `avg`/1-arg `round` over INTEGER inputs: Postgres `avg(bigint)` and
///   `round(numeric, n)` return `numeric`; the exact-integer encoder emits a
///   JSON integer when integral (e.g. `20`), while SQLite/Turso emit a real
///   (`20.0`). Repro: `SELECT avg(x) FROM (SELECT 10 AS x UNION ALL SELECT 20
///   UNION ALL SELECT 30)` and `SELECT round(2.5)`. Options stand:
///   accept+document the split, or make `avg` always real. Needs one
///   int-column case proving the choice (left for the follow-on).
/// - NaN: Postgres numeric NaN is rejected by sqlx before `numeric_cell`,
///   surfacing as category `engine` rather than the contract's
///   `syntax_or_type`. No portable NaN generator exists (SQLite divides to
///   NULL; PG errors), so no case can exist until a probe is found. Low
///   severity, predates M4.
///
/// SQLite-only relations are intentionally absent from the shared corpus:
/// `body_blocks`, `body_block_headings`, `effective_relationships`, `agent_activity`, `agent_activity_claims`,
/// `actors`, `runs`, `run_intents`, `messages_awaiting_reply`,
/// `my_message_state` and `my_mentions` declare
/// `profiles: ["sqlite-local"]` in
/// `LOGICAL_RELATIONS`, so Turso must never run them (the Turso projection
/// filters by profile). They keep per-engine tests, not shared cases.
/// `now_ms()` time-dependent cases wait for M3 (corpus asserts `as_of_seq`;
/// clock-dependent cases need a stamp-aware rule).
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
        run_params(db, principal, sql, Vec::new()).await
    }

    async fn run_params(
        db: &Db,
        principal: QueryPrincipal,
        sql: &str,
        parameters: Vec<QuerySqlParameter>,
    ) -> QuerySqlResult {
        query_sql_request_owned(
            db.clone(),
            principal,
            QuerySqlRequest {
                sql: sql.into(),
                parameters,
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
    async fn sqlite_regexp_bound_patterns_meet_literal_rules() {
        // E1 M3 repair: placeholder patterns skip the literal subset check,
        // so bound values are validated against the same subset and cap at
        // execution — before any engine sees them. Columns and expressions
        // never get that far: the classifier rejects them with the shape
        // repair.
        let (db, alice, _) = seeded_sqlite().await;
        for (sql, parameters, repair) in [
            (
                "SELECT id FROM records WHERE regexp(?1, name) AND id LIKE 'conf:sort-%' ORDER BY id",
                vec![QuerySqlParameter::Text {
                    value: Some("(?=".into()),
                }],
                "outside the portable subset",
            ),
            (
                "SELECT id FROM records WHERE regexp(?1, name) AND id LIKE 'conf:sort-%' ORDER BY id",
                vec![QuerySqlParameter::Text {
                    value: Some("a".repeat(1025)),
                }],
                "1024-byte",
            ),
            (
                "SELECT id FROM records WHERE regexp(?1, name) AND id LIKE 'conf:sort-%' ORDER BY id",
                vec![QuerySqlParameter::Integer {
                    value: Some("3".into()),
                }],
                "must be text",
            ),
            (
                "SELECT id FROM records WHERE regexp(pattern, name) AND id LIKE 'conf:sort-%' ORDER BY id",
                Vec::new(),
                "single-quoted text literal",
            ),
        ] {
            let error = query_sql_request_owned(
                db.clone(),
                alice.clone(),
                QuerySqlRequest {
                    sql: sql.into(),
                    parameters,
                },
            )
            .await
            .unwrap_err()
            .to_string();
            assert!(error.contains(repair), "{sql}: unexpected refusal: {error}");
        }
        // A bound NULL pattern stays NULL on every engine, like a NULL
        // literal (see the corpus null case).
        let result = query_sql_request_owned(
            db.clone(),
            alice,
            QuerySqlRequest {
                sql: "SELECT regexp(?1, name) AS hit FROM records WHERE id = 'conf:common'".into(),
                parameters: vec![QuerySqlParameter::Text { value: None }],
            },
        )
        .await
        .unwrap();
        assert_eq!(result.rows[0]["hit"], serde_json::Value::Null);
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
    async fn sqlite_now_ms_two_uses_agree_and_stamp_matches() {
        // E1 M3: one statement-fixed value per statement — two uses agree
        // with each other and with the result stamp beside `as_of_seq`.
        let (db, alice, _) = seeded_sqlite().await;
        let result = run_owned(&db, alice.clone(), "SELECT now_ms() AS a, NOW_MS() AS b").await;
        assert!(result.time_dependent, "now_ms() must mark time dependence");
        let stamp = result.now_ms_ms.expect("now_ms() must stamp the result");
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0]["a"].as_i64().unwrap(), stamp);
        assert_eq!(result.rows[0]["b"].as_i64().unwrap(), stamp);
        // The stamp is a live clock, not a fixture constant: within a
        // generous tolerance of this process's own clock.
        let skewed = (chrono::Utc::now().timestamp_millis() - stamp).abs();
        assert!(skewed < 60_000, "stamp {stamp} is too far from now");
        // Integer week arithmetic is exact: the motivating "past week" tab
        // cutoff reproduces deterministically off the same statement's
        // stamp (each statement fixes its own value).
        let week = run_owned(
            &db,
            alice.clone(),
            "SELECT now_ms() - 7*86400000 AS week_ago",
        )
        .await;
        let week_stamp = week.now_ms_ms.expect("week query must stamp");
        assert_eq!(
            week_stamp - week.rows[0]["week_ago"].as_i64().unwrap(),
            7 * 86_400_000,
            "week arithmetic must be exact off one fixed value"
        );
    }

    #[tokio::test]
    async fn sqlite_statements_without_now_ms_carry_no_clock_stamp() {
        // E1 M3: the stamp is present only when the statement used the
        // clock, so clock-free results stay exactly as before.
        let (db, alice, _) = seeded_sqlite().await;
        let result = run_owned(
            &db,
            alice,
            "SELECT id FROM records WHERE id = 'conf:common'",
        )
        .await;
        assert!(!result.time_dependent);
        assert_eq!(result.now_ms_ms, None);
    }

    #[tokio::test]
    async fn sqlite_caller_placeholders_cannot_spoof_the_hidden_clock() {
        // E1 M3: the hidden index is `parameters.len() + 1`, and the
        // exact-set check refuses any caller text naming it.
        let (db, alice, _) = seeded_sqlite().await;
        for (sql, parameters) in [
            (
                "SELECT ?2, now_ms()",
                vec![QuerySqlParameter::Text {
                    value: Some("conf:common".into()),
                }],
            ),
            (
                "SELECT now_ms()",
                vec![QuerySqlParameter::Text {
                    value: Some("conf:common".into()),
                }],
            ),
            ("SELECT ?1, now_ms()", Vec::new()),
        ] {
            let error = query_sql_request_owned(
                db.clone(),
                alice.clone(),
                QuerySqlRequest {
                    sql: sql.into(),
                    parameters,
                },
            )
            .await
            .unwrap_err()
            .to_string();
            assert!(
                error.contains("must match exactly"),
                "{sql}: unexpected refusal: {error}"
            );
        }
        // The legitimate mix still works: `?1` binds the caller value and
        // the hidden `?2` carries the clock.
        let result = run_params(
            &db,
            alice,
            "SELECT ?1 AS id, now_ms() AS t",
            vec![QuerySqlParameter::Text {
                value: Some("conf:common".into()),
            }],
        )
        .await;
        assert_eq!(result.rows[0]["id"], "conf:common");
        assert_eq!(
            result.rows[0]["t"].as_i64().unwrap(),
            result.now_ms_ms.unwrap()
        );
    }

    #[tokio::test]
    async fn sqlite_keyword_clocks_are_refused_with_repair() {
        // E1 M3: engine keyword clocks fail at execution with the portable
        // repair, never by reading the engine's own clock.
        let (db, alice, _) = seeded_sqlite().await;
        for sql in [
            "SELECT CURRENT_TIMESTAMP AS t",
            "SELECT current_date AS t FROM records",
        ] {
            let error = query_sql_request_owned(
                db.clone(),
                alice.clone(),
                QuerySqlRequest {
                    sql: sql.into(),
                    parameters: Vec::new(),
                },
            )
            .await
            .unwrap_err()
            .to_string();
            assert!(
                error.contains("now_ms()"),
                "{sql}: unexpected refusal: {error}"
            );
        }
    }

    #[tokio::test]
    async fn sqlite_utc_date_label_matches_contract_vectors() {
        // Native e25665c: English `DDD D MMM`, UTC, Sunday zero, no year,
        // no leading day zero, NULL in NULL out. Vectors pin epoch,
        // negative epochs, midnight boundaries, leap day, and both
        // supported-range bounds (0000-01-01, 9999-12-31).
        let (db, alice, _) = seeded_sqlite().await;
        for (ms, expected) in [
            (0_i64, "Thu 1 Jan"),
            (-1, "Wed 31 Dec"),
            (-86_400_000, "Wed 31 Dec"),
            (1_790_294_400_000, "Fri 25 Sep"),
            (1_790_294_399_999, "Thu 24 Sep"),
            (1_709_164_800_000, "Thu 29 Feb"),
            (1_790_380_799_999, "Fri 25 Sep"),
            (1_790_380_800_000, "Sat 26 Sep"),
            (-62_167_219_200_000, "Sat 1 Jan"),
            (253_402_300_799_999, "Fri 31 Dec"),
        ] {
            let result = run_params(
                &db,
                alice.clone(),
                "SELECT utc_date_label(?1) AS label",
                vec![QuerySqlParameter::Integer {
                    value: Some(ms.to_string()),
                }],
            )
            .await;
            assert_eq!(
                result.rows[0]["label"],
                serde_json::Value::String(expected.into()),
                "ms={ms}"
            );
            // Literal and UTC-prefixed forms agree with the placeholder.
            let literal = run_owned(
                &db,
                alice.clone(),
                &format!("SELECT utc_date_label({ms}) AS label"),
            )
            .await;
            assert_eq!(literal.rows[0]["label"], result.rows[0]["label"], "ms={ms}");
        }
        // NULL in, NULL out; arity stays exact at execution.
        let null = run_owned(&db, alice.clone(), "SELECT utc_date_label(NULL) AS label").await;
        assert_eq!(null.rows[0]["label"], serde_json::Value::Null);
        for sql in [
            "SELECT utc_date_label() AS label",
            "SELECT utc_date_label(1, 2) AS label",
        ] {
            let error = query_sql_request_owned(
                db.clone(),
                alice.clone(),
                QuerySqlRequest {
                    sql: sql.into(),
                    parameters: Vec::new(),
                },
            )
            .await
            .unwrap_err()
            .to_string();
            assert!(
                error.contains("exactly one argument"),
                "{sql}: unexpected refusal: {error}"
            );
        }
        // A label over a fixed timestamp agrees with the UTC calendar.
        let seed = run_owned(
            &db,
            alice.clone(),
            "SELECT utc_date_label(1786752000000) AS label",
        )
        .await;
        assert_eq!(seed.rows[0]["label"], "Sat 15 Aug");
        // Text inputs are refused with the integer repair instead of
        // forking per engine (SQLite would coerce, Postgres would error).
        for (sql, parameters) in [
            ("SELECT utc_date_label('abc') AS label", Vec::new()),
            (
                "SELECT utc_date_label(?1) AS label",
                vec![QuerySqlParameter::Text {
                    value: Some("abc".into()),
                }],
            ),
        ] {
            let error = query_sql_request_owned(
                db.clone(),
                alice.clone(),
                QuerySqlRequest {
                    sql: sql.into(),
                    parameters,
                },
            )
            .await
            .unwrap_err()
            .to_string();
            assert!(
                error.contains("integer epoch milliseconds"),
                "{sql}: unexpected refusal: {error}"
            );
        }
        // Out-of-range extremes are outside the portable contract and this
        // assertion pins SQLite-only behavior, not parity: past 9999
        // SQLite yields NULL, Turso keeps labelling (measured `Sat 1 Jan`
        // for 10000-01-01), and Postgres raises. The supported UTC years
        // are 0000–9999.
        for ms in [253_402_300_800_000_i64, 9_223_372_036_854_775_807] {
            let result = run_params(
                &db,
                alice.clone(),
                "SELECT utc_date_label(?1) AS label",
                vec![QuerySqlParameter::Integer {
                    value: Some(ms.to_string()),
                }],
            )
            .await;
            assert_eq!(result.rows[0]["label"], serde_json::Value::Null, "ms={ms}");
        }
    }

    #[tokio::test]
    async fn sqlite_runs_conformance_corpus() {
        let (db, alice, head) = seeded_sqlite().await;
        for case in corpus().into_iter().chain(containment_corpus()) {
            let result = query_sql_request_owned(db.clone(), alice.clone(), case.request())
                .await
                .unwrap_or_else(|error| panic!("sqlite failed {}: {error}", case.name));
            check_case(&result, &case, head);
        }
    }

    #[tokio::test]
    async fn sqlite_body_block_headings_preserve_object_fields_and_chunk_membership() {
        let (db, alice, _) = seeded_sqlite().await;
        // Independent stored object fixtures: no extractor or new SQL builds expectations.
        let root = r#"[{"depth":1,"title":"Plan","title_truncated":false,"block_index":1}]"#;
        let nested = r#"[{"depth":1,"title":"Plan","title_truncated":false,"block_index":1},{"depth":3,"title":"Café \"go\" \\ path","title_truncated":false,"block_index":3}]"#;
        let repeated = r#"[{"depth":1,"title":"Plan","title_truncated":false,"block_index":6}]"#;
        for (block, chunk, chunks, path) in [
            (0, 0, 1, "[]"),
            (1, 0, 1, root),
            (3, 0, 1, nested),
            (4, 0, 2, nested),
            (4, 1, 2, nested),
            (6, 0, 1, repeated),
        ] {
            sqlx::query("INSERT INTO body_blocks(record_id,block_index,chunk_index,chunk_count,source_event_seq,heading_path,block_kind,text,start_offset,end_offset) VALUES ('conf:common',?1,?2,?3,91001,?4,'paragraph','x',0,1)")
                .bind(block).bind(chunk).bind(chunks).bind(path)
                .execute(db.write_pool()).await.unwrap();
        }
        let result = run_owned(&db, alice.clone(), "SELECT * FROM body_block_headings WHERE record_id='conf:common' ORDER BY block_index,chunk_index,heading_index").await;
        assert_eq!(
            result.columns,
            [
                "record_id",
                "block_index",
                "chunk_index",
                "heading_index",
                "depth",
                "title",
                "title_truncated",
                "heading_block_index"
            ]
        );
        let values: Vec<Vec<serde_json::Value>> = result
            .rows
            .iter()
            .map(|row| {
                result
                    .columns
                    .iter()
                    .map(|column| row[column].clone())
                    .collect()
            })
            .collect();
        assert_eq!(
            serde_json::json!(values),
            serde_json::json!([
                ["conf:common", 1, 0, 0, 1, "Plan", 0, 1],
                ["conf:common", 3, 0, 0, 1, "Plan", 0, 1],
                ["conf:common", 3, 0, 1, 3, "Café \"go\" \\ path", 0, 3],
                ["conf:common", 4, 0, 0, 1, "Plan", 0, 1],
                ["conf:common", 4, 0, 1, 3, "Café \"go\" \\ path", 0, 3],
                ["conf:common", 4, 1, 0, 1, "Plan", 0, 1],
                ["conf:common", 4, 1, 1, 3, "Café \"go\" \\ path", 0, 3],
                ["conf:common", 6, 0, 0, 1, "Plan", 0, 6]
            ])
        );
        // The guide's section query counts blocks, including heading self,
        // and keeps repeated titles distinct by revision-local heading ordinal.
        let sections = run_owned(&db, alice.clone(), "SELECT record_id, heading_block_index, count(DISTINCT block_index) AS blocks FROM body_block_headings WHERE title = 'Plan' AND title_truncated = 0 GROUP BY record_id, heading_block_index ORDER BY record_id, heading_block_index").await;
        assert_eq!(
            sections.rows,
            vec![
                serde_json::json!({"record_id":"conf:common","heading_block_index":1,"blocks":3}),
                serde_json::json!({"record_id":"conf:common","heading_block_index":6,"blocks":1})
            ]
        );
        let joined = run_owned(&db, alice.clone(), "SELECT h.block_index,h.chunk_index,h.heading_index,b.text FROM body_block_headings h JOIN body_blocks b ON b.record_id=h.record_id AND b.block_index=h.block_index AND b.chunk_index=h.chunk_index WHERE h.record_id='conf:common' ORDER BY h.block_index,h.chunk_index,h.heading_index").await;
        assert_eq!(
            joined.rows,
            vec![
                serde_json::json!({"block_index":1,"chunk_index":0,"heading_index":0,"text":"x"}),
                serde_json::json!({"block_index":3,"chunk_index":0,"heading_index":0,"text":"x"}),
                serde_json::json!({"block_index":3,"chunk_index":0,"heading_index":1,"text":"x"}),
                serde_json::json!({"block_index":4,"chunk_index":0,"heading_index":0,"text":"x"}),
                serde_json::json!({"block_index":4,"chunk_index":0,"heading_index":1,"text":"x"}),
                serde_json::json!({"block_index":4,"chunk_index":1,"heading_index":0,"text":"x"}),
                serde_json::json!({"block_index":4,"chunk_index":1,"heading_index":1,"text":"x"}),
                serde_json::json!({"block_index":6,"chunk_index":0,"heading_index":0,"text":"x"})
            ]
        );
        let duplicates = run_owned(&db, alice, "SELECT record_id,block_index,chunk_index,heading_index,count(*) AS n FROM body_block_headings GROUP BY record_id,block_index,chunk_index,heading_index HAVING count(*)>1 ORDER BY record_id,block_index,chunk_index,heading_index").await;
        assert!(duplicates.rows.is_empty());
    }

    #[tokio::test]
    async fn sqlite_body_block_headings_refresh_on_public_writes_and_empty_opaque_bodies() {
        let (db, alice, _) = seeded_sqlite().await;
        let id = crate::store::create_record(
            &db,
            serde_json::json!({
                "type":"Document","kind":"note","name":"heading refresh",
                "body":"# Plan\n\nx\n\n### Gap\n\ny\n\n# Plan\n\nz\n"
            }),
        )
        .await
        .unwrap();
        crate::authorization::replace_explicit_policy(
            &db,
            "test:headings",
            &id,
            vec![crate::authorization::AllowEntry::account(
                "alice",
                crate::authorization::Capability::View,
            )],
        )
        .await
        .unwrap();
        let sql = "SELECT block_index,chunk_index,heading_index,depth,title,title_truncated,heading_block_index FROM body_block_headings WHERE record_id=?1 ORDER BY block_index,chunk_index,heading_index";
        let params = || {
            vec![QuerySqlParameter::Text {
                value: Some(id.clone()),
            }]
        };
        let before = run_params(&db, alice.clone(), sql, params()).await;
        let values = |result: &QuerySqlResult| -> Vec<Vec<serde_json::Value>> {
            result
                .rows
                .iter()
                .map(|row| {
                    result
                        .columns
                        .iter()
                        .map(|column| row[column].clone())
                        .collect()
                })
                .collect()
        };
        assert_eq!(
            serde_json::json!(values(&before)),
            serde_json::json!([
                [0, 0, 0, 1, "Plan", 0, 0],
                [1, 0, 0, 1, "Plan", 0, 0],
                [2, 0, 0, 1, "Plan", 0, 0],
                [2, 0, 1, 3, "Gap", 0, 2],
                [3, 0, 0, 1, "Plan", 0, 0],
                [3, 0, 1, 3, "Gap", 0, 2],
                [4, 0, 0, 1, "Plan", 0, 4],
                [5, 0, 0, 1, "Plan", 0, 4]
            ])
        );
        let long_body = format!("# {}\n\n{}", "é".repeat(121), "x".repeat(32 * 1024 + 1));
        crate::store::update_record(&db, &id, serde_json::json!({"body":long_body}))
            .await
            .unwrap();
        let after = run_params(&db, alice.clone(), sql, params()).await;
        let excerpt = "é".repeat(120);
        assert_eq!(
            serde_json::json!(values(&after)),
            serde_json::json!([
                [0, 0, 0, 1, excerpt, 1, 0],
                [1, 0, 0, 1, excerpt, 1, 0],
                [1, 1, 0, 1, excerpt, 1, 0]
            ])
        );
        assert!(after.as_of_seq > before.as_of_seq);
        let exact = run_params(&db,alice.clone(),"SELECT title FROM body_block_headings WHERE record_id=?1 AND title=?2 AND title_truncated=0 ORDER BY block_index,chunk_index,heading_index",vec![
            QuerySqlParameter::Text {value:Some(id.clone())}, QuerySqlParameter::Text {value:Some(excerpt)}
        ]).await;
        assert!(exact.rows.is_empty());
        for body in [
            serde_json::json!({"heading":"# opaque"}),
            serde_json::Value::Null,
            serde_json::json!(""),
        ] {
            crate::store::update_record(&db, &id, serde_json::json!({"body":body}))
                .await
                .unwrap();
            assert!(run_params(&db, alice.clone(), sql, params())
                .await
                .rows
                .is_empty());
        }
        crate::store::update_record(&db, &id, serde_json::json!({"body":"# Back"}))
            .await
            .unwrap();
        assert_eq!(
            run_params(&db, alice.clone(), sql, params()).await.rows,
            vec![serde_json::json!({
                "block_index":0,"chunk_index":0,"heading_index":0,"depth":1,"title":"Back","title_truncated":0,"heading_block_index":0
            })]
        );
        crate::store::delete_record(&db, &id).await.unwrap();
        assert!(run_params(&db, alice, sql, params()).await.rows.is_empty());
    }

    #[tokio::test]
    async fn sqlite_body_block_headings_follow_two_caller_visibility_and_tombstones() {
        let (db, alice, _) = seeded_sqlite().await;
        for (id, seq) in [
            ("conf:common", 91001),
            ("conf:alice", 91001),
            ("conf:bea", 91002),
            ("conf:tomb", 91001),
        ] {
            sqlx::query(r#"INSERT INTO body_blocks(record_id,block_index,chunk_index,chunk_count,source_event_seq,heading_path,block_kind,text,start_offset,end_offset) VALUES (?1,0,0,1,?2,'[{"depth":1,"title":"Private","title_truncated":false,"block_index":0}]','heading','# Private',0,9)"#)
                .bind(id).bind(seq).execute(db.write_pool()).await.unwrap();
        }
        let bea = QueryPrincipal::authenticated("bea", true);
        // Repeated alternating callers exercise governed TEMP teardown/reuse.
        for (caller, expected, hidden) in [
            (alice.clone(), vec!["conf:alice", "conf:common"], "conf:bea"),
            (bea.clone(), vec!["conf:bea", "conf:common"], "conf:alice"),
            (alice.clone(), vec!["conf:alice", "conf:common"], "conf:bea"),
        ] {
            let rows = run_owned(&db,caller.clone(),"SELECT h.record_id,b.text FROM body_block_headings h JOIN body_blocks b ON b.record_id=h.record_id AND b.block_index=h.block_index AND b.chunk_index=h.chunk_index JOIN records r ON r.id=h.record_id WHERE h.record_id LIKE 'conf:%' ORDER BY h.record_id").await;
            for id in &expected {
                let visible = run_params(
                    &db,
                    caller.clone(),
                    "SELECT EXISTS(SELECT 1 FROM body_block_headings WHERE record_id=?1) AS present",
                    vec![QuerySqlParameter::Text {
                        value: Some((*id).into()),
                    }],
                )
                .await;
                assert_eq!(visible.rows, vec![serde_json::json!({"present":1})]);
            }
            assert_eq!(
                rows.rows,
                expected
                    .into_iter()
                    .map(|id| serde_json::json!({"record_id":id,"text":"# Private"}))
                    .collect::<Vec<_>>()
            );
            for id in [hidden, "conf:tomb"] {
                let direct = run_params(
                    &db,
                    caller.clone(),
                    "SELECT count(*) AS n FROM body_block_headings WHERE record_id=?1",
                    vec![QuerySqlParameter::Text {
                        value: Some(id.into()),
                    }],
                )
                .await;
                assert_eq!(direct.rows, vec![serde_json::json!({"n":0})]);
                let absent = run_params(
                    &db,
                    caller.clone(),
                    "SELECT EXISTS(SELECT 1 FROM body_block_headings WHERE record_id=?1) AS present",
                    vec![QuerySqlParameter::Text {
                        value: Some(id.into()),
                    }],
                )
                .await;
                assert_eq!(absent.rows, vec![serde_json::json!({"present":0})]);
            }
        }
    }

    #[tokio::test]
    async fn sqlite_body_block_headings_catalog_order_and_caller_refusals() {
        let (db, alice, _) = seeded_sqlite().await;
        let columns = run_owned(&db,alice.clone(),"SELECT column_name,column_position FROM catalog_columns WHERE relation_name='body_block_headings' ORDER BY column_position").await;
        assert_eq!(
            columns.rows,
            vec![
                serde_json::json!({"column_name":"record_id","column_position":0}),
                serde_json::json!({"column_name":"block_index","column_position":1}),
                serde_json::json!({"column_name":"chunk_index","column_position":2}),
                serde_json::json!({"column_name":"heading_index","column_position":3}),
                serde_json::json!({"column_name":"depth","column_position":4}),
                serde_json::json!({"column_name":"title","column_position":5}),
                serde_json::json!({"column_name":"title_truncated","column_position":6}),
                serde_json::json!({"column_name":"heading_block_index","column_position":7})
            ]
        );
        let relation = run_owned(&db,alice.clone(),"SELECT identity,semantic_version,caller_relative,completeness,profiles FROM catalog_relations WHERE relation_name='body_block_headings'").await;
        assert_eq!(
            relation.rows,
            vec![
                serde_json::json!({"identity":"native.query-sql.body-block-headings","semantic_version":1,"caller_relative":1,"completeness":"complete","profiles":"sqlite-local"})
            ]
        );
        assert_eq!(crate::query::sql_contract::LOGICAL_CATALOG_REVISION, 4);
        sqlx::query(r#"INSERT INTO body_blocks(record_id,block_index,chunk_index,chunk_count,source_event_seq,heading_path,block_kind,text,start_offset,end_offset) VALUES ('conf:common',0,0,1,91001,'[{"depth":1,"title":"Zulu","title_truncated":false,"block_index":0},{"depth":2,"title":"Alpha","title_truncated":false,"block_index":1}]','paragraph','x',0,1)"#).execute(db.write_pool()).await.unwrap();
        let unordered = run_owned(
            &db,
            alice.clone(),
            "SELECT title,heading_index FROM body_block_headings LIMIT 1",
        )
        .await;
        assert_eq!(
            unordered.rows,
            vec![serde_json::json!({"title":"Alpha","heading_index":1})]
        );
        assert!(unordered.assumed_order.is_some());
        for sql in [
            "SELECT * FROM main.body_block_headings",
            "SELECT heading_path FROM main.body_blocks",
            "SELECT * FROM _query_sql_heading_source",
            "SELECT json_extract(heading_path,'$[0].title') FROM body_blocks",
            "SELECT value FROM json_each('[1]')",
            "WITH body_block_headings AS (SELECT heading_path FROM main.body_blocks) SELECT * FROM body_block_headings",
            "WITH body_block_headings AS (SELECT json_extract('[1]','$[0]') AS title) SELECT title FROM body_block_headings",
            "SELECT source_event_seq FROM body_block_headings",
        ] {
            let error = query_sql_request_owned(db.clone(),alice.clone(),QuerySqlRequest {sql:sql.into(),parameters:Vec::new()}).await;
            assert!(error.is_err(),"caller SQL unexpectedly admitted: {sql}");
        }
    }

    #[tokio::test]
    async fn sqlite_body_block_headings_keep_row_limits_deadline_and_reuse() {
        let (db, alice, _) = seeded_sqlite().await;
        let id = crate::store::create_record(&db,serde_json::json!({
            "type":"Document","kind":"note","name":"many sections","body":"# Section\n\n".repeat(1001)
        })).await.unwrap();
        crate::authorization::replace_explicit_policy(
            &db,
            "test:headings",
            &id,
            vec![crate::authorization::AllowEntry::account(
                "alice",
                crate::authorization::Capability::View,
            )],
        )
        .await
        .unwrap();
        let params = vec![QuerySqlParameter::Text { value: Some(id) }];
        let bounded = run_params(&db,alice.clone(),"SELECT heading_block_index FROM body_block_headings WHERE record_id=?1 ORDER BY heading_block_index",params.clone()).await;
        assert_eq!(bounded.row_count, 1000);
        assert!(bounded.truncated);
        assert_eq!(
            bounded.rows[0],
            serde_json::json!({"heading_block_index":0})
        );
        assert_eq!(
            bounded.rows[999],
            serde_json::json!({"heading_block_index":999})
        );
        let timeout = query_sql_request_owned(db.clone(),alice.clone(),QuerySqlRequest {
            sql:"SELECT sum(a.depth+b.depth+c.depth) AS n FROM body_block_headings a CROSS JOIN body_block_headings b CROSS JOIN body_block_headings c".into(),
            parameters:Vec::new()
        }).await.unwrap_err().to_string();
        assert!(timeout.contains("query_sql [timeout]"), "{timeout}");
        let exists = run_params(
            &db,
            alice.clone(),
            "SELECT EXISTS(SELECT 1 FROM body_block_headings WHERE record_id=?1) AS present",
            params.clone(),
        )
        .await;
        assert_eq!(exists.rows, vec![serde_json::json!({"present":1})]);
        let count = run_params(
            &db,
            alice,
            "SELECT count(*) AS n FROM body_block_headings WHERE record_id=?1",
            params,
        )
        .await;
        assert_eq!(count.rows, vec![serde_json::json!({"n":1001})]);
    }

    #[tokio::test]
    async fn sqlite_body_blocks_follow_record_visibility_and_hide_provenance() {
        let (db, alice, _) = seeded_sqlite().await;
        for (record_id, event_seq, text) in [
            ("conf:common", 91001, "visible"),
            ("conf:bea", 91002, "private"),
            ("conf:tomb", 91001, "deleted"),
        ] {
            sqlx::query("INSERT INTO body_blocks(record_id,block_index,chunk_index,chunk_count,source_event_seq,heading_path,block_kind,text,start_offset,end_offset) VALUES (?1,0,0,1,?2,'[]','paragraph',?3,0,?4)")
                .bind(record_id)
                .bind(event_seq)
                .bind(text)
                .bind(text.len() as i64)
                .execute(db.write_pool())
                .await
                .unwrap();
        }
        let rows = run_owned(&db, alice.clone(), "SELECT record_id, text FROM body_blocks WHERE record_id LIKE 'conf:%' ORDER BY record_id, block_index, chunk_index").await;
        assert_eq!(
            rows.rows,
            vec![serde_json::json!({"record_id":"conf:common","text":"visible"})]
        );
        let columns = run_owned(&db, alice.clone(), "SELECT column_name FROM catalog_columns WHERE relation_name='body_blocks' ORDER BY column_position").await;
        assert_eq!(columns.rows.len(), 9);
        let relation = run_owned(&db, alice.clone(), "SELECT identity, semantic_version, caller_relative, completeness, profiles FROM catalog_relations WHERE relation_name='body_blocks'").await;
        assert_eq!(
            relation.rows,
            vec![serde_json::json!({
                "identity":"native.query-sql.body-blocks",
                "semantic_version":1,
                "caller_relative":1,
                "completeness":"complete",
                "profiles":"sqlite-local"
            })]
        );
        assert!(!columns
            .rows
            .iter()
            .any(|row| row["column_name"] == "source_event_seq"));
        let error = query_sql_request_owned(
            db.clone(),
            alice.clone(),
            QuerySqlRequest {
                sql: "SELECT source_event_seq FROM body_blocks".into(),
                parameters: Vec::new(),
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("source_event_seq"), "{error}");
        let unordered_limit = run_owned(&db, alice, "SELECT text FROM body_blocks LIMIT 1").await;
        assert_eq!(unordered_limit.rows.len(), 1);
        assert!(unordered_limit.assumed_order.is_some());
    }

    #[tokio::test]
    async fn sqlite_body_blocks_page_and_reassemble_over_cell_ceiling() {
        let (db, alice, _) = seeded_sqlite().await;
        let body = format!("# Heading\n\n```\n{}\n```\n", "é".repeat(160_000));
        assert!(body.len() > crate::query::sql_contract::MAX_CELL_ENCODED_BYTES);
        let id = crate::store::create_record(
            &db,
            serde_json::json!({
                "type":"Document", "kind":"note", "name":"large body", "body":body
            }),
        )
        .await
        .unwrap();
        crate::authorization::replace_explicit_policy(
            &db,
            "test:body-blocks",
            &id,
            vec![crate::authorization::AllowEntry::account(
                "alice",
                crate::authorization::Capability::View,
            )],
        )
        .await
        .unwrap();
        let mut rebuilt = String::new();
        let mut last_block = -1_i64;
        let mut last_chunk = -1_i64;
        let mut total = 0_usize;
        loop {
            let page = run_params(&db, alice.clone(),
                "SELECT block_index, chunk_index, chunk_count, heading_path, block_kind, text, start_offset, end_offset FROM body_blocks WHERE record_id=?1 AND (block_index>?2 OR (block_index=?2 AND chunk_index>?3)) ORDER BY block_index, chunk_index LIMIT 3",
                vec![
                    QuerySqlParameter::Text { value: Some(id.clone()) },
                    QuerySqlParameter::Integer { value: Some(last_block.to_string()) },
                    QuerySqlParameter::Integer { value: Some(last_chunk.to_string()) },
                ]).await;
            if page.rows.is_empty() {
                break;
            }
            assert!(page.rows.len() <= 3);
            for row in page.rows {
                let block = row["block_index"].as_i64().unwrap();
                let chunk = row["chunk_index"].as_i64().unwrap();
                assert!((block, chunk) > (last_block, last_chunk));
                assert!(row["chunk_count"].as_i64().unwrap() > chunk);
                assert!(row["heading_path"].is_string());
                assert!(row["block_kind"].is_string());
                assert!(
                    row["end_offset"].as_i64().unwrap() > row["start_offset"].as_i64().unwrap()
                );
                rebuilt.push_str(row["text"].as_str().unwrap());
                last_block = block;
                last_chunk = chunk;
                total += 1;
            }
        }
        assert!(total > 8, "large body must span several pages");
        assert_eq!(rebuilt, body);
    }

    #[tokio::test]
    async fn sqlite_default_order_matches_explicit_ordering() {
        // E2 default ORDER BY: each unordered spelling discloses the assumed
        // order and returns exactly the explicit spelling's rows. Turso runs
        // the same table in its own runner; Postgres follows when wired.
        let (db, alice, head) = seeded_sqlite().await;
        for case in default_order_corpus() {
            let unordered = query_sql_request_owned(
                db.clone(),
                alice.clone(),
                QuerySqlRequest {
                    sql: case.sql.into(),
                    parameters: case.parameters.clone(),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("sqlite failed {}: {error}", case.name));
            let explicit = query_sql_request_owned(
                db.clone(),
                alice.clone(),
                QuerySqlRequest {
                    sql: case.explicit_sql.into(),
                    parameters: case.parameters.clone(),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("sqlite failed explicit {}: {error}", case.name));
            check_default_order_case(&unordered, &explicit, &case, head);
        }
    }

    #[tokio::test]
    async fn sqlite_refuses_rejection_corpus_with_repairs() {
        // E1 M4 negative-case mechanism: every rejection must fail closed
        // with its repair, never execute. Turso and Postgres run the same
        // table in their own runners (advisory for PG).
        let (db, alice, _) = seeded_sqlite().await;
        for case in rejection_corpus() {
            let error = query_sql_request_owned(
                db.clone(),
                alice.clone(),
                QuerySqlRequest {
                    sql: case.sql.into(),
                    parameters: case.parameters,
                },
            )
            .await
            .unwrap_err()
            .to_string();
            assert!(
                error.contains(case.expected_repair_substring),
                "{}: expected repair {:?} in refusal: {error}",
                case.name,
                case.expected_repair_substring
            );
        }
    }

    #[tokio::test]
    async fn sqlite_documents_avg_round_integer_divergence() {
        // Open M4 divergence, no semantic decision: over INTEGER inputs
        // SQLite (and Turso) return REAL while Postgres returns numeric
        // encoded as JSON integer when integral. Reproducible here; the
        // shared corpus stays on REAL inputs until the choice is ratified.
        let (db, alice, _) = seeded_sqlite().await;
        let avg = run_owned(
            &db,
            alice.clone(),
            "SELECT avg(x) AS a FROM (SELECT 10 AS x UNION ALL SELECT 20 UNION ALL SELECT 30)",
        )
        .await;
        assert_eq!(avg.rows, vec![serde_json::json!({"a": 20.0})]);
        let round = run_owned(&db, alice.clone(), "SELECT round(2.5) AS r").await;
        assert_eq!(round.rows, vec![serde_json::json!({"r": 3.0})]);
        // NaN has no portable generator (SQLite divides to NULL, PG
        // errors before numeric_cell), so there is no NaN case to pin.
        let div = run_owned(&db, alice.clone(), "SELECT 1 / 0 AS d").await;
        assert_eq!(div.rows, vec![serde_json::json!({"d": null})]);
    }

    #[tokio::test]
    async fn sqlite_documents_window_functions_for_turso_gap() {
        // The six registered window functions execute on SQLite (and, via
        // the same lowering, are expected on Postgres). Exact Turso 0.8.0
        // resolves the six names but compiles every window program as
        // non-read-only, refused by the isolated query-only projection, so
        // the Turso validator rejects them with that repair and they stay
        // out of the shared corpus. Scores 10/20/30 are distinct, so every
        // ranking is deterministic.
        let (db, alice, _) = seeded_sqlite().await;
        let result = run_owned(
            &db,
            alice,
            "SELECT record_id, row_number() OVER (ORDER BY record_id, id) AS rn, rank() OVER (ORDER BY value_num) AS rk, dense_rank() OVER (ORDER BY value_num) AS dr, ntile(2) OVER (ORDER BY value_num) AS nt, cume_dist() OVER (ORDER BY value_num) AS cd, percent_rank() OVER (ORDER BY value_num) AS pr FROM facet_values WHERE key = 'score' ORDER BY record_id, id",
        )
        .await;
        assert_eq!(
            result.rows,
            vec![
                serde_json::json!({"record_id": "conf:alice", "rn": 1, "rk": 2, "dr": 2, "nt": 1, "cd": 0.6666666666666666, "pr": 0.5}),
                serde_json::json!({"record_id": "conf:common", "rn": 2, "rk": 1, "dr": 1, "nt": 1, "cd": 0.3333333333333333, "pr": 0.0}),
                serde_json::json!({"record_id": "conf:sort-a", "rn": 3, "rk": 3, "dr": 3, "nt": 2, "cd": 1.0, "pr": 1.0}),
            ]
        );
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
