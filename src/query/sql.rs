//! Caller-filtered, validated read-only SQL (tool 18, `query_sql`).
//!
//! User SQL never reaches a physical content or policy relation. Every call is
//! prepared twice against the public logical contract, then executed on one
//! explicitly acquired physical connection whose portable principal exists
//! only inside a rolled-back transaction. The TEMP schema is connection-local;
//! pool release removes both principal state and the progress handler.

use std::time::{Duration, Instant};

use futures::TryStreamExt;
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use sqlx::query::Query;
use sqlx::sqlite::SqliteArguments;
use sqlx::sqlite::SqliteRow;
use sqlx::{Acquire, Column, Row, Sqlite, TypeInfo, ValueRef};

use super::principal::QueryPrincipal;
use super::sql_contract::{
    self, QuerySqlErrorCategory, QuerySqlParameter, QuerySqlRequest, QuerySqlResult,
};
use crate::db::Db;
use crate::error::Result;
use crate::schema::DDL_STATEMENTS;

use super::error::contract_violation;

const CONTROLLED_ACCESSORS: [&str; 21] = [
    "_query_sql_bearer_walk",
    "_query_sql_authorization_subjects",
    "_query_sql_visible_records",
    "records",
    "content_events",
    "links",
    "facet_values",
    "facet_observations",
    "bindings",
    "blobs",
    "vocabularies",
    "vocabulary_values",
    "schema_config",
    "effective_relationships",
    "agent_activity",
    "agent_activity_claims",
    "_query_sql_activity_observations",
    "_query_sql_agent_activity_durable",
    "_query_sql_agent_activity_admitted",
    "_query_sql_agent_activity_claim_events",
    "messages_awaiting_reply",
];

const MAX_ROWS: i64 = sql_contract::MAX_ROWS as i64;
#[cfg(test)]
const MAX_SQL_BYTES: usize = sql_contract::MAX_SQL_BYTES;
const MAX_COLUMNS: usize = sql_contract::MAX_COLUMNS;
const MAX_CELL_ENCODED_BYTES: usize = sql_contract::MAX_CELL_ENCODED_BYTES;
const MAX_RESULT_ENCODED_BYTES: usize = sql_contract::MAX_RESULT_ENCODED_BYTES;
const MAX_SQLITE_VALUE_BYTES: i32 = 256 * 1024;
const PROGRESS_OPS: i32 = 1_000;
const QUERY_DEADLINE: Duration = Duration::from_millis(sql_contract::QUERY_DEADLINE_MS);
const MAX_AWAITING_REPLY_CANDIDATES: i64 = 10_000;

/// Deliberately conservative: every callable function is denied unless its
/// output is intrinsically small or a familiar numeric/min/max aggregate. The
/// SQLite runtime value ceiling is still mandatory for min/max over text.
/// Operators and CAST remain available. Blob constructors, value-returning
/// string/JSON/window functions, concatenating aggregates, extension loaders,
/// and introspection helpers never prepare.
const SAFE_FUNCTIONS: [&str; 29] = [
    "abs",
    "avg",
    "count",
    "cume_dist",
    "date",
    "datetime",
    "dense_rank",
    "glob",
    "instr",
    "json_array_length",
    "json_type",
    "json_valid",
    "julianday",
    "length",
    "like",
    "max",
    "min",
    "ntile",
    "percent_rank",
    "rank",
    "round",
    "row_number",
    "strftime",
    "sum",
    "time",
    "total",
    "typeof",
    "unicode",
    "unixepoch",
];

/// The connection-local contract. `_query_sql_visible_records` is an internal
/// helper, absent from the strict public schema, so caller SQL cannot name it.
/// A routed/adopted credential is a live member for this request; membership
/// alone matters only when the explicit anchor grants `native:members`.
const TEMP_CONTRACT: &str = r#"
CREATE TEMP TABLE IF NOT EXISTS _query_sql_principal (
  singleton           INTEGER PRIMARY KEY CHECK (singleton = 1),
  account_id          TEXT NOT NULL,
  trusted_local_bypass INTEGER NOT NULL CHECK (trusted_local_bypass IN (0, 1)),
  activity_read        INTEGER NOT NULL CHECK (activity_read IN (0, 1)),
  observed_at         TEXT NOT NULL
);
CREATE TEMP TABLE IF NOT EXISTS _query_sql_messages_awaiting_reply (
  message_id TEXT PRIMARY KEY
);
CREATE TEMP TABLE IF NOT EXISTS _query_sql_activity_observations (
  run_key TEXT PRIMARY KEY,
  last_observed_at TEXT NOT NULL
);
CREATE TEMP TABLE IF NOT EXISTS _query_sql_activity_members (
  account_id TEXT PRIMARY KEY,
  member_ref TEXT NOT NULL UNIQUE
);
-- Derived artifacts do not carry independent visibility in v1. Each live
-- record resolves through a chain of exactly-one outgoing part_of links until
-- the first ordinary live bearer. Missing/multiple bearers, tombstones,
-- cycles, and chains longer than the defensive recursion ceiling produce no
-- subject row.
--
-- The walk runs *bearer-first* (subject -> derived artifact) rather than
-- artifact-first. Both directions describe the same relation, because the
-- exactly-one-outgoing-part_of rule makes every derived artifact's bearer
-- chain a single deterministic path: seeding at the ordinary terminals and
-- descending the reverse edges visits each derived artifact exactly once.
-- The artifact-first form re-walked the whole remaining chain from every
-- origin, so a chain of D edges cost O(D^2) walk rows and, because the
-- artifact-first cycle guard rescanned a growing json path per step, O(D^3)
-- json_each iterations. The `records` view alone references
-- `_query_sql_visible_records` twice (once for the row, once through the
-- home_id LEFT JOIN added when home_id became caller-visible), and a
-- non-materialized view is re-evaluated per reference — EXPLAIN QUERY PLAN
-- shows the walk twice — so that cost was paid twice per statement on every
-- projection of `records`. That is the mechanism that put this
-- query at the edge of the QUERY_DEADLINE_MS budget on the qualification
-- fixtures, which deliberately contain a MAX_DERIVED_BEARER_DEPTH-long chain.
--
-- Bearer-first has no such term: the row count is bounded by the number of
-- live records, independent of chain depth, and no per-row cycle guard is
-- needed because an unresolvable cycle is simply never reachable from an
-- ordinary terminal. Measured on the query_sql parity fixture (119 records,
-- 113 links, one 101-edge chain) with the system SQLite 3.45.1: 93ms -> 0.8ms
-- for one evaluation of this view, i.e. roughly two orders of magnitude of
-- headroom against the 2s deadline instead of the previous single order.
-- `depth` is still counted and still bounded, so an over-depth artifact stays
-- invisible exactly as before.
CREATE TEMP VIEW IF NOT EXISTS _query_sql_authorization_subjects AS
WITH RECURSIVE _query_sql_bearer_walk(record_id, subject_id, depth) AS (
  SELECT ordinary.id, ordinary.id, 0
  FROM main.records AS ordinary
  WHERE ordinary.deleted_at IS NULL
    AND NOT (ordinary.type = 'Annotation'
             OR (ordinary.type = 'Document' AND ordinary.kind IS 'attachment'))
  UNION ALL
  SELECT derived.id, walk.subject_id, walk.depth + 1
  FROM _query_sql_bearer_walk AS walk
  JOIN main.links AS part
    ON part.target_id = walk.record_id AND part.relationship = 'part_of'
  JOIN main.records AS derived ON derived.id = part.source_id
  WHERE derived.deleted_at IS NULL
    AND (derived.type = 'Annotation'
         OR (derived.type = 'Document' AND derived.kind IS 'attachment'))
    AND (SELECT COUNT(*) FROM main.links AS all_parts
         WHERE all_parts.source_id = derived.id
           AND all_parts.relationship = 'part_of') = 1
    AND walk.depth < __MAX_DERIVED_BEARER_DEPTH__
)
SELECT walk.record_id AS record_id, walk.subject_id AS subject_id
FROM _query_sql_bearer_walk AS walk;

CREATE TEMP VIEW IF NOT EXISTS _query_sql_visible_records AS
SELECT r.id
FROM main.records AS r
JOIN temp._query_sql_authorization_subjects AS resolved
  ON resolved.record_id = r.id
JOIN main.records AS authorization_subject
  ON authorization_subject.id = resolved.subject_id
CROSS JOIN temp._query_sql_principal AS principal
WHERE r.deleted_at IS NULL
  -- Governed attribution annotations are intentionally absent from every
  -- generic surface. Their bearer-derived authorization is consumed only by
  -- the dedicated attribution reader and must not admit the hidden record or
  -- its events through query_sql's shared visibility relation.
  AND NOT (r.type = 'Annotation' AND r.kind IN ('attribution','acknowledgement'))
  -- Units and derived artefacts resolving to Units are subordinate to the
  -- dedicated/direct surfaces, and cannot be admitted on envelope policy.
  AND NOT (r.type = 'Entity' AND r.kind IS 'semantic-unit')
  AND NOT EXISTS (
        SELECT 1 FROM main.semantic_units AS semantic_subject
        WHERE semantic_subject.unit_id = authorization_subject.id
      )
  AND EXISTS (
       SELECT 1 FROM main.record_policies AS explicit_policy
       WHERE explicit_policy.record_id = authorization_subject.policy_anchor_id
     )
  AND (principal.trusted_local_bypass = 1 OR (EXISTS (
        SELECT 1 FROM main.bindings AS owner_account
        WHERE owner_account.record_id = authorization_subject.owner_id
          AND owner_account.system = 'account'
          AND owner_account.identifier = principal.account_id
          AND owner_account.is_canonical = 1
      )
   OR EXISTS (
        SELECT 1 FROM main.policy_entries AS entry
        WHERE entry.policy_anchor_id = authorization_subject.policy_anchor_id
          AND entry.effect = 'allow'
          AND entry.capability IN ('view', 'edit', 'manage')
          AND (
            (entry.subject_kind = 'members'
             AND entry.subject_id = 'native:members')
            OR
            (entry.subject_kind = 'account'
             AND entry.subject_id = principal.account_id)
          )
      )));

CREATE TEMP VIEW IF NOT EXISTS records AS
SELECT r.id, r.type, r.kind, r.name, r.body,
       CASE WHEN parent_visible.id IS NULL THEN NULL ELSE r.home_id END AS home_id,
       r.lifecycle, r.persistence, r.maturity, r.summary,
       r.last_activity_at, r.created_at, r.updated_at, r.deleted_at
FROM main.records AS r
JOIN temp._query_sql_visible_records AS visible ON visible.id = r.id
LEFT JOIN temp._query_sql_visible_records AS parent_visible
       ON parent_visible.id = r.home_id;

-- Payload, actor, and run lineage are deliberately absent until their event
-- classes have a bearer/identity exposure audit.
CREATE TEMP VIEW IF NOT EXISTS content_events AS
SELECT e.seq AS local_seq, e.id, e.record_id,
       CASE WHEN e.type='receipt.committed.v1' THEN 'record.updated' ELSE e.type END AS type,
       e.created_at
FROM main.content_events AS e
JOIN temp._query_sql_visible_records AS visible ON visible.id = e.record_id
WHERE e.type NOT IN (
    'reconciliation.recorded.v1','unit.superseded.v1','receipt.dependency_audited.v1'
);

CREATE TEMP VIEW IF NOT EXISTS links AS
SELECT l.id, l.source_id, l.target_id, l.relationship, l.note, l.created_at
FROM main.links AS l
JOIN temp._query_sql_visible_records AS source_visible
  ON source_visible.id = l.source_id
JOIN temp._query_sql_visible_records AS target_visible
  ON target_visible.id = l.target_id;

CREATE TEMP VIEW IF NOT EXISTS facet_values AS
SELECT f.id, f.record_id, f.key, f.value, f.value_num, f.vocab_ref, f.created_at
FROM main.facet_values AS f
JOIN temp._query_sql_visible_records AS visible ON visible.id = f.record_id;

CREATE TEMP VIEW IF NOT EXISTS facet_observations AS
SELECT f.id, f.record_id, f.key, f.value, f.op, f.vocab_ref,
       f.as_of, f.observed_at, f.event_seq
FROM main.facet_observations AS f
JOIN temp._query_sql_visible_records AS visible ON visible.id = f.record_id;

-- Account/email bindings are caller-owned. No non-identity system has yet
-- completed the explicit exposure audit, so unknown systems fail closed.
CREATE TEMP VIEW IF NOT EXISTS bindings AS
SELECT b.record_id, b.system, b.identifier, b.is_canonical,
       b.url, b.etag, b.last_seen_at
FROM main.bindings AS b
CROSS JOIN temp._query_sql_principal AS principal
JOIN temp._query_sql_visible_records AS visible ON visible.id = b.record_id
WHERE b.system IN ('account', 'email')
  AND EXISTS (
        SELECT 1 FROM main.bindings AS own_account
        WHERE own_account.record_id = b.record_id
          AND own_account.system = 'account'
          AND own_account.identifier = principal.account_id
          AND own_account.is_canonical = 1
      );

CREATE TEMP VIEW IF NOT EXISTS blobs AS
SELECT blob.id, blob.bytes, blob.mime, blob.size_bytes, blob.sha256,
       blob.original_filename, blob.storage_tier, blob.external_ref,
       blob.created_at
FROM main.blobs AS blob
WHERE EXISTS (
  SELECT 1
  FROM main.records AS attachment
  JOIN temp._query_sql_visible_records AS attachment_visible
    ON attachment_visible.id = attachment.id
  JOIN main.facet_values AS blob_ref
    ON blob_ref.record_id = attachment.id
   AND blob_ref.key = 'blob_ref'
   AND blob_ref.value = blob.id
  JOIN main.links AS bearer
    ON bearer.source_id = attachment.id
   AND bearer.relationship = 'part_of'
  JOIN temp._query_sql_visible_records AS bearer_visible
    ON bearer_visible.id = bearer.target_id
  WHERE attachment.type = 'Document' AND attachment.kind = 'attachment'
);

CREATE TEMP VIEW IF NOT EXISTS vocabularies AS
SELECT id, name, created_at FROM main.vocabularies;

CREATE TEMP VIEW IF NOT EXISTS vocabulary_values AS
SELECT id, vocabulary_id, value, gloss, status, ordinal, terminality,
       metadata, alias_of
FROM main.vocabulary_values;

CREATE TEMP VIEW IF NOT EXISTS schema_config AS
SELECT config.id, config.layer, config.name, config.data,
       config.applies_to_collection_id, config.version_lineage,
       config.created_at
FROM main.schema_config AS config
WHERE config.applies_to_collection_id IS NULL
   OR EXISTS (
        SELECT 1 FROM temp._query_sql_visible_records AS visible
        WHERE visible.id = config.applies_to_collection_id
      );

-- Governed receiver-local reduction, deliberately excluding assertion and
-- evidence rows. Every endpoint must resolve to a caller-visible local record;
-- otherwise the relationship is absent, matching the dedicated read surface.
CREATE TEMP VIEW IF NOT EXISTS effective_relationships AS
SELECT rel.relationship_origin_db_id, rel.relationship_id,
       rel.relationship_type, rel.type_definition_id, rel.endpoint_semantics,
       (SELECT json_group_array(json_object(
            'ordinal', ordered.ordinal, 'role', ordered.role,
            'portable_ref', ordered.portable_ref,
            'record_type', ordered.record_type, 'record_kind', ordered.record_kind,
            'record_id', ordered.record_id))
          FROM (SELECT ep.ordinal, ep.role, ep.portable_ref, ep.record_type,
                       ep.record_kind, ep.record_id
                  FROM main.relationship_endpoints ep
                 WHERE ep.relationship_origin_db_id=rel.relationship_origin_db_id
                   AND ep.relationship_id=rel.relationship_id
                 ORDER BY ep.ordinal) AS ordered) AS endpoints,
       eff.effective_state, eff.epistemic_state, eff.support_count,
       eff.contest_count, eff.recomputed_at
  FROM main.relationships rel
  JOIN main.effective_relationships eff
    ON eff.relationship_origin_db_id=rel.relationship_origin_db_id
   AND eff.relationship_id=rel.relationship_id
 WHERE NOT EXISTS (
       SELECT 1 FROM main.relationship_endpoints hidden
        WHERE hidden.relationship_origin_db_id=rel.relationship_origin_db_id
          AND hidden.relationship_id=rel.relationship_id
          AND (hidden.record_id IS NULL OR NOT EXISTS (
              SELECT 1 FROM temp._query_sql_visible_records visible
               WHERE visible.id=hidden.record_id)))
   AND EXISTS (
       SELECT 1 FROM main.relationship_endpoints present
        WHERE present.relationship_origin_db_id=rel.relationship_origin_db_id
          AND present.relationship_id=rel.relationship_id);

-- Minimal run presence derives from durable lifecycle and content evidence.
-- The protected helper contributes disposable capture when it is available;
-- its absence leaves the durable subset intact. Claim tuple updates are
-- excluded here so hiding a claim can never alter presence or ordering.
CREATE TEMP VIEW IF NOT EXISTS agent_activity AS
WITH _query_sql_agent_activity_durable AS (
  SELECT run.activity_id, run.run_key, run.account_id, run.started_at, run.ended_at,
         max(run.started_at,
             coalesce(run.ended_at, run.started_at),
              coalesce((SELECT max(event.created_at)
                          FROM main.content_events event
                         WHERE event.run_key=run.run_key
                           AND event.actor=run.account_id
                           AND NOT (event.type='record.updated'
                                    AND (json_type(event.payload,'$.claimed_by_account') IS NOT NULL
                                         OR json_type(event.payload,'$.claimed_run_key') IS NOT NULL))
                           AND (run.ended_at IS NULL
                                OR julianday(event.created_at)<=julianday(run.ended_at))),
                       run.started_at),
             coalesce(observed.last_observed_at, run.started_at)) AS last_observed_activity_at
    FROM main.agent_runs run
    LEFT JOIN temp._query_sql_activity_observations observed ON observed.run_key=run.run_key
), _query_sql_agent_activity_admitted AS (
  SELECT durable.*,
         member.member_ref,
         principal.observed_at,
         principal.trusted_local_bypass
    FROM _query_sql_agent_activity_durable durable
    CROSS JOIN temp._query_sql_principal principal
    LEFT JOIN temp._query_sql_activity_members member
      ON member.account_id=durable.account_id
   WHERE principal.activity_read=1
      AND (member.member_ref IS NOT NULL
           OR (principal.trusted_local_bypass=1
               AND durable.account_id=principal.account_id))
)
SELECT activity_id,
       run_key,
       coalesce(member_ref, 'native:local-operator') AS principal_ref,
       NULL AS principal_display_name,
       started_at,
       ended_at,
       last_observed_activity_at,
       strftime('%Y-%m-%dT%H:%M:%fZ', last_observed_activity_at, '+5 minutes') AS active_until,
       CASE WHEN ended_at IS NULL
                  AND julianday(observed_at) < julianday(last_observed_activity_at, '+5 minutes')
            THEN 1 ELSE 0 END AS appears_active
  FROM _query_sql_agent_activity_admitted
 WHERE julianday(last_observed_activity_at) >= julianday(observed_at, '-24 hours');

-- One caller-visible durable claim event. Release is the first subsequent
-- engine-owned claim-clear update. Exclusive claim state prevents another
-- claim from interleaving before it. Visibility is applied before rows reach
-- logical SQL and never feeds the independent presence relation above.
CREATE TEMP VIEW IF NOT EXISTS agent_activity_claims AS
WITH _query_sql_agent_activity_claim_events AS (
   SELECT event.id AS claim_id, event.record_id, event.run_key,
          event.actor AS claim_actor,
          json_extract(event.payload,'$.claimed_by_account') AS claimed_by_account,
          event.created_at AS claimed_at,
         (SELECT release.created_at
            FROM main.content_events release
           WHERE release.record_id=event.record_id AND release.seq>event.seq
             AND release.type='record.updated'
             AND json_type(release.payload,'$.claimed_by_account')='null'
             AND json_type(release.payload,'$.claimed_run_key')='null'
             AND ((release.actor=event.actor AND release.run_key=event.run_key)
                  OR release.actor='local')
            ORDER BY release.seq
            LIMIT 1) AS released_at
    FROM main.content_events event
    CROSS JOIN temp._query_sql_principal principal
   WHERE event.type='record.updated'
     AND json_type(event.payload,'$.claimed_by_account')='text'
     AND json_type(event.payload,'$.claimed_run_key')='text'
     AND (julianday(event.created_at)>=julianday(principal.observed_at,'-24 hours')
          OR EXISTS (
               SELECT 1 FROM main.records current
                WHERE current.id=event.record_id
                  AND current.claimed_run_key=event.run_key
                  AND current.claimed_at=event.created_at
          ))
)
SELECT claim.claim_id, run.activity_id, claim.record_id, claim.claimed_at,
       claim.released_at, CASE WHEN claim.released_at IS NULL THEN 1 ELSE 0 END AS is_current
  FROM _query_sql_agent_activity_claim_events claim
   JOIN main.agent_runs run ON run.run_key=claim.run_key
                            AND run.account_id=claim.claim_actor
                            AND run.account_id=claim.claimed_by_account
  JOIN temp.agent_activity activity ON activity.activity_id=run.activity_id
  JOIN temp._query_sql_visible_records visible ON visible.id=claim.record_id
 WHERE run.ended_at IS NULL OR julianday(claim.claimed_at)<=julianday(run.ended_at);

-- This narrow negative-state relation is populated lazily by the Rust
-- expectation evaluator only when caller SQL actually depends on it. The
-- public row intentionally carries no evidence id, count, or diagnostic.
CREATE TEMP VIEW IF NOT EXISTS messages_awaiting_reply AS
SELECT message_id FROM temp._query_sql_messages_awaiting_reply;
"#;

fn temp_contract() -> String {
    TEMP_CONTRACT.replace(
        "__MAX_DERIVED_BEARER_DEPTH__",
        &crate::authorization::MAX_DERIVED_BEARER_DEPTH.to_string(),
    )
}

/// The second prepare contains only public names and columns in TEMP. It has
/// no main schema at all, structurally rejecting `main.records`, raw relations,
/// and the colliding-CTE accessor spoof that defeats a view-aware callback.
pub(crate) const STRICT_LOGICAL_SCHEMA: &str = r#"
CREATE TEMP TABLE records (
  id TEXT, type TEXT, kind TEXT, name TEXT, body TEXT, home_id TEXT,
  lifecycle TEXT, persistence TEXT, maturity TEXT, summary TEXT,
  last_activity_at TEXT, created_at TEXT, updated_at TEXT, deleted_at TEXT
);
CREATE TEMP TABLE content_events (
  local_seq INTEGER, id TEXT, record_id TEXT, type TEXT, created_at TEXT
);
CREATE TEMP TABLE links (
  id TEXT, source_id TEXT, target_id TEXT, relationship TEXT, note TEXT,
  created_at TEXT
);
CREATE TEMP TABLE facet_values (
  id TEXT, record_id TEXT, key TEXT, value TEXT, value_num REAL,
  vocab_ref TEXT, created_at TEXT
);
CREATE TEMP TABLE facet_observations (
  id TEXT, record_id TEXT, key TEXT, value TEXT, op TEXT, vocab_ref TEXT,
  as_of TEXT, observed_at TEXT, event_seq INTEGER
);
CREATE TEMP TABLE bindings (
  record_id TEXT, system TEXT, identifier TEXT, is_canonical INTEGER,
  url TEXT, etag TEXT, last_seen_at TEXT
);
CREATE TEMP TABLE blobs (
  id TEXT, bytes BLOB, mime TEXT, size_bytes INTEGER, sha256 TEXT,
  original_filename TEXT, storage_tier TEXT, external_ref TEXT, created_at TEXT
);
CREATE TEMP TABLE vocabularies (id TEXT, name TEXT, created_at TEXT);
CREATE TEMP TABLE vocabulary_values (
  id TEXT, vocabulary_id TEXT, value TEXT, gloss TEXT, status TEXT,
  ordinal REAL, terminality TEXT, metadata TEXT, alias_of TEXT
);
CREATE TEMP TABLE schema_config (
  id TEXT, layer TEXT, name TEXT, data TEXT, applies_to_collection_id TEXT,
  version_lineage TEXT, created_at TEXT
);
CREATE TEMP TABLE effective_relationships (
  relationship_origin_db_id TEXT, relationship_id TEXT,
  relationship_type TEXT, type_definition_id TEXT, endpoint_semantics TEXT,
  endpoints TEXT, effective_state TEXT, epistemic_state TEXT,
  support_count INTEGER, contest_count INTEGER, recomputed_at TEXT
);
CREATE TEMP TABLE agent_activity (
  activity_id TEXT, run_key TEXT, principal_ref TEXT, principal_display_name TEXT,
  started_at TEXT, ended_at TEXT, last_observed_activity_at TEXT,
  active_until TEXT, appears_active INTEGER
);
CREATE TEMP TABLE agent_activity_claims (
  claim_id TEXT, activity_id TEXT, record_id TEXT, claimed_at TEXT,
  released_at TEXT, is_current INTEGER
);
CREATE TEMP TABLE messages_awaiting_reply (message_id TEXT);
"#;

pub type SqlResult = QuerySqlResult;

#[derive(Clone, Debug)]
pub(crate) struct GovernedSqlObservation {
    pub observed_at: String,
    /// Highest caller-visible content event in this authorization snapshot.
    /// A hidden claim therefore cannot perturb receipt diagnostics.
    pub content_event_seq: Option<i64>,
    pub lifecycle_event_seq: Option<i64>,
    /// Opaque caller- and dependency-scoped authorization boundary. Raw
    /// database-global epochs are never exposed through governed receipts.
    pub authorization_boundary: String,
    pub transient_watermark: Option<i64>,
    pub transient_available: bool,
}

async fn prepare_activity_observations(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
) -> Result<(bool, Option<i64>)> {
    sqlx::query("DELETE FROM temp._query_sql_activity_observations")
        .execute(&mut **transaction)
        .await?;
    let available: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM main.sqlite_master WHERE type='table' AND name='read_log_calls')",
    )
    .fetch_one(&mut **transaction)
    .await?;
    if !available {
        return Ok((false, None));
    }
    sqlx::query(
        "INSERT INTO temp._query_sql_activity_observations(run_key,last_observed_at)
         SELECT calls.run_key,max(calls.ended_at)
           FROM main.read_log_calls calls
           JOIN main.agent_runs run ON run.run_key=calls.run_key
          WHERE calls.run_key IS NOT NULL AND calls.outcome='ok'
            AND calls.tool!='start_work'
            AND calls.actor=run.account_id
            AND (EXISTS (SELECT 1 FROM temp._query_sql_activity_members member
                          WHERE member.account_id=run.account_id)
                 OR ((SELECT trusted_local_bypass FROM temp._query_sql_principal)=1
                     AND run.account_id=(SELECT account_id FROM temp._query_sql_principal)))
            AND julianday(calls.ended_at)<=julianday((SELECT observed_at FROM temp._query_sql_principal))
            AND (run.ended_at IS NULL OR julianday(calls.ended_at)<=julianday(run.ended_at))
          GROUP BY calls.run_key",
    )
    .execute(&mut **transaction)
    .await?;
    let watermark = sqlx::query_scalar(
        "SELECT max(calls.seq)
           FROM main.read_log_calls calls
           JOIN main.agent_runs run ON run.run_key=calls.run_key
          WHERE calls.outcome='ok'
            AND calls.tool!='start_work'
            AND calls.actor=run.account_id
            AND (EXISTS (SELECT 1 FROM temp._query_sql_activity_members member
                          WHERE member.account_id=run.account_id)
                 OR ((SELECT trusted_local_bypass FROM temp._query_sql_principal)=1
                     AND run.account_id=(SELECT account_id FROM temp._query_sql_principal)))
            AND julianday(calls.ended_at)<=julianday((SELECT observed_at FROM temp._query_sql_principal))
            AND (run.ended_at IS NULL OR julianday(calls.ended_at)<=julianday(run.ended_at))
            AND julianday(max(run.started_at,coalesce(run.ended_at,run.started_at),calls.ended_at))
                >=julianday((SELECT observed_at FROM temp._query_sql_principal),'-24 hours')",
    )
        .fetch_one(&mut **transaction)
        .await?;
    Ok((true, watermark))
}

async fn populate_activity_members(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    principal: &QueryPrincipal,
) -> Result<()> {
    if principal.trusted_local_bypass() {
        let workspace_id: String =
            sqlx::query_scalar("SELECT origin_db_id FROM main.database_identity WHERE singleton=1")
                .fetch_one(&mut **transaction)
                .await?;
        let accounts: Vec<String> =
            sqlx::query_scalar("SELECT account_id FROM main.member_contexts ORDER BY account_id")
                .fetch_all(&mut **transaction)
                .await?;
        for account_id in accounts {
            sqlx::query(
                "INSERT INTO temp._query_sql_activity_members(account_id,member_ref) VALUES(?,?)",
            )
            .bind(&account_id)
            .bind(crate::identity::activity_member_ref(
                &workspace_id,
                &account_id,
            ))
            .execute(&mut **transaction)
            .await?;
        }
    } else {
        for member in principal.activity_roster() {
            sqlx::query(
                "INSERT INTO temp._query_sql_activity_members(account_id,member_ref) VALUES(?,?)",
            )
            .bind(member.account_id())
            .bind(member.member_ref())
            .execute(&mut **transaction)
            .await?;
        }
    }
    Ok(())
}

fn authorize_view_expansion(context: AuthContext<'_>) -> Authorization {
    match context.action {
        AuthAction::Select | AuthAction::Recursive => Authorization::Allow,
        AuthAction::Read { table_name, .. } => {
            let public_temp = context.database_name == Some("temp")
                && sql_contract::is_logical_relation(table_name);
            let through_controlled = context
                .accessor
                .is_some_and(|view| CONTROLLED_ACCESSORS.contains(&view));
            if public_temp || through_controlled {
                Authorization::Allow
            } else {
                Authorization::Deny
            }
        }
        AuthAction::Function { function_name }
            if context
                .accessor
                .is_some_and(|view| CONTROLLED_ACCESSORS.contains(&view))
                && !function_name.eq_ignore_ascii_case("load_extension") =>
        {
            Authorization::Allow
        }
        AuthAction::Function { function_name }
            if SAFE_FUNCTIONS
                .iter()
                .any(|safe| function_name.eq_ignore_ascii_case(safe)) =>
        {
            Authorization::Allow
        }
        AuthAction::Function { .. } => Authorization::Deny,
        _ => Authorization::Deny,
    }
}

fn authorize_strict(context: AuthContext<'_>) -> Authorization {
    match context.action {
        AuthAction::Select | AuthAction::Recursive => Authorization::Allow,
        AuthAction::Read { table_name, .. }
            if context.database_name == Some("temp")
                && sql_contract::is_logical_relation(table_name) =>
        {
            Authorization::Allow
        }
        AuthAction::Read { .. } if context.database_name.is_none() => Authorization::Allow,
        AuthAction::Function { function_name }
            if SAFE_FUNCTIONS
                .iter()
                .any(|safe| function_name.eq_ignore_ascii_case(safe)) =>
        {
            Authorization::Allow
        }
        _ => Authorization::Deny,
    }
}

fn prepare_under_authorizer(
    conn: &rusqlite::Connection,
    statement: &str,
    authorizer: fn(AuthContext<'_>) -> Authorization,
) -> Result<()> {
    conn.authorizer(Some(authorizer));
    let prepared = conn.prepare(statement);
    conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
    match prepared {
        Ok(statement) if statement.readonly() => {
            let mut labels = std::collections::HashSet::new();
            if let Some(duplicate) = statement
                .column_names()
                .into_iter()
                .find(|label| !labels.insert(*label))
            {
                return Err(sql_contract::categorized_error(
                    QuerySqlErrorCategory::DuplicateColumns,
                    format!("duplicate output column label '{duplicate}'"),
                ));
            }
            Ok(())
        }
        Ok(_) => Err(sql_contract::categorized_error(
            QuerySqlErrorCategory::UnsafeStatement,
            "read-only statement writes",
        )),
        Err(error) => {
            let detail = error.to_string();
            let category = if detail.contains("not authorized")
                || detail.contains("access to")
                || detail.contains("no such table")
            {
                QuerySqlErrorCategory::UnauthorizedRelation
            } else {
                QuerySqlErrorCategory::SyntaxOrType
            };
            Err(sql_contract::categorized_error(category, detail))
        }
    }
}

fn validate_view_expansion(statement: &str) -> Result<()> {
    let conn = rusqlite::Connection::open_in_memory()
        .map_err(|e| contract_violation(format!("query_sql: validator setup failed: {e}")))?;
    let ddl: String = DDL_STATEMENTS
        .iter()
        .map(|sql| format!("{sql};\n"))
        .collect();
    conn.execute_batch(&ddl)
        .and_then(|_| conn.execute_batch(&temp_contract()))
        .map_err(|e| contract_violation(format!("query_sql: validator setup failed: {e}")))?;
    prepare_under_authorizer(&conn, statement, authorize_view_expansion)
}

fn validate_strict(statement: &str) -> Result<()> {
    let conn = rusqlite::Connection::open_in_memory()
        .map_err(|e| contract_violation(format!("query_sql: validator setup failed: {e}")))?;
    conn.execute_batch(STRICT_LOGICAL_SCHEMA)
        .map_err(|e| contract_violation(format!("query_sql: validator setup failed: {e}")))?;
    prepare_under_authorizer(&conn, statement, authorize_strict)
}

/// Validate caller SQL against both the real view expansion and a strict
/// public-only schema. This is security enforcement, not linting.
pub fn validate(sql: &str) -> Result<()> {
    let statement = sql_contract::classify_single_read_statement(
        sql_contract::QuerySqlProfile::SqliteLocal,
        sql,
    )?;
    validate_view_expansion(&statement)?;
    validate_strict(&statement)
}

/// Return the labels SQLite assigns to a validated statement without running
/// it. Saved SQL uses this at admission so an empty result cannot defer output
/// schema drift until a later execution happens to produce rows.
pub(crate) fn validated_output_columns(sql: &str) -> Result<Vec<String>> {
    let statement = sql_contract::classify_single_read_statement(
        sql_contract::QuerySqlProfile::SqliteLocal,
        sql,
    )?;
    validate_view_expansion(&statement)?;
    let conn = rusqlite::Connection::open_in_memory()
        .map_err(|e| contract_violation(format!("query_sql: validator setup failed: {e}")))?;
    conn.execute_batch(STRICT_LOGICAL_SCHEMA)
        .map_err(|e| contract_violation(format!("query_sql: validator setup failed: {e}")))?;
    conn.authorizer(Some(authorize_strict));
    let prepared = conn.prepare(&statement);
    conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
    let prepared = prepared.map_err(|error| {
        sql_contract::categorized_error(QuerySqlErrorCategory::SyntaxOrType, error.to_string())
    })?;
    Ok(prepared
        .column_names()
        .into_iter()
        .map(str::to_owned)
        .collect())
}

/// Resolve the logical relations actually read by a validated statement.
/// SQLite's authoritative prepare/authorizer path naturally ignores names in
/// comments and literals and does not mistake a same-named CTE for a catalog
/// dependency.
pub(crate) fn validated_relation_dependencies(
    sql: &str,
) -> Result<std::collections::BTreeSet<String>> {
    let statement = sql_contract::classify_single_read_statement(
        sql_contract::QuerySqlProfile::SqliteLocal,
        sql,
    )?;
    validate_view_expansion(&statement)?;
    let conn = rusqlite::Connection::open_in_memory()
        .map_err(|e| contract_violation(format!("query_sql: validator setup failed: {e}")))?;
    conn.execute_batch(STRICT_LOGICAL_SCHEMA)
        .map_err(|e| contract_violation(format!("query_sql: validator setup failed: {e}")))?;
    let dependencies = std::sync::Arc::new(std::sync::Mutex::new(std::collections::BTreeSet::<
        String,
    >::new()));
    let observed = dependencies.clone();
    conn.authorizer(Some(move |context: AuthContext<'_>| {
        if let AuthAction::Read { table_name, .. } = context.action {
            if context.database_name == Some("temp")
                && sql_contract::is_logical_relation(table_name)
            {
                observed
                    .lock()
                    .expect("dependency lock")
                    .insert(table_name.to_owned());
            }
        }
        authorize_strict(context)
    }));
    let prepared = conn.prepare(&statement);
    conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
    let prepared = prepared.map_err(|error| {
        sql_contract::categorized_error(QuerySqlErrorCategory::SyntaxOrType, error.to_string())
    })?;
    if !prepared.readonly() {
        return Err(sql_contract::categorized_error(
            QuerySqlErrorCategory::UnsafeStatement,
            "read-only statement writes",
        ));
    }
    drop(prepared);
    Ok(std::sync::Arc::try_unwrap(dependencies)
        .expect("validator releases dependency observer")
        .into_inner()
        .expect("dependency lock"))
}

/// Compatibility entry point for the authorization spike's independent
/// backend validator. Backend preparation remains authoritative there.
#[cfg(test)]
pub(super) fn validate_input(sql: &str) -> Result<()> {
    sql_contract::classify_single_read_statement(sql_contract::QuerySqlProfile::SqliteLocal, sql)?;
    Ok(())
}

fn json_cell(row: &SqliteRow, index: usize) -> Result<Value> {
    let raw = row.try_get_raw(index)?;
    if raw.is_null() {
        return Ok(Value::Null);
    }
    let value = match raw.type_info().name().to_uppercase().as_str() {
        "INTEGER" => Value::Number(row.try_get::<i64, _>(index)?.into()),
        "REAL" => Number::from_f64(row.try_get::<f64, _>(index)?)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        "BLOB" => {
            use base64::Engine as _;
            let bytes: Vec<u8> = row.try_get(index)?;
            let encoded_len = bytes.len().saturating_add(2) / 3 * 4 + 2;
            if encoded_len > MAX_CELL_ENCODED_BYTES {
                return Err(sql_contract::categorized_error(
                    QuerySqlErrorCategory::ResultTooLarge,
                    format!("a cell exceeds the {MAX_CELL_ENCODED_BYTES}-byte encoded limit"),
                ));
            }
            Value::String(base64::engine::general_purpose::STANDARD.encode(bytes))
        }
        _ => {
            let text: String = row.try_get(index)?;
            if text.len() > MAX_CELL_ENCODED_BYTES {
                return Err(sql_contract::categorized_error(
                    QuerySqlErrorCategory::ResultTooLarge,
                    format!("a cell exceeds the {MAX_CELL_ENCODED_BYTES}-byte encoded limit"),
                ));
            }
            Value::String(text)
        }
    };
    if serde_json::to_vec(&value)?.len() > MAX_CELL_ENCODED_BYTES {
        return Err(sql_contract::categorized_error(
            QuerySqlErrorCategory::ResultTooLarge,
            format!("a cell exceeds the {MAX_CELL_ENCODED_BYTES}-byte encoded limit"),
        ));
    }
    Ok(value)
}

async fn populate_messages_awaiting_reply(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    principal: &QueryPrincipal,
) -> Result<()> {
    let started = Instant::now();
    let ensure_budget = || {
        if started.elapsed() >= QUERY_DEADLINE {
            Err(sql_contract::categorized_error(
                QuerySqlErrorCategory::Timeout,
                "messages_awaiting_reply exceeded the query execution deadline",
            ))
        } else {
            Ok(())
        }
    };
    sqlx::query("DELETE FROM temp._query_sql_messages_awaiting_reply")
        .execute(&mut **transaction)
        .await?;
    // Caller-relative audience resolution is deliberately exact. Missing or
    // ambiguous account/person/principal bindings produce the same
    // content-free failure and never leak which part was unavailable. An
    // empty relation would falsely claim that a current member was resolved.
    let identities = sqlx::query(
        "SELECT account.record_id, native_principal.identifier
           FROM main.bindings account
           JOIN main.records person ON person.id=account.record_id
           JOIN main.bindings native_principal
             ON native_principal.record_id=account.record_id
            AND native_principal.system='native-principal'
            AND native_principal.is_canonical=1
          WHERE account.system='account' AND account.identifier=?
            AND account.is_canonical=1 AND person.deleted_at IS NULL
            AND person.type='Entity' AND person.kind='person'
          ORDER BY account.record_id,native_principal.identifier LIMIT 2",
    )
    .bind(principal.credential())
    .fetch_all(&mut **transaction)
    .await?;
    ensure_budget()?;
    if identities.len() != 1 {
        return Err(sql_contract::categorized_error(
            QuerySqlErrorCategory::Engine,
            "current member unavailable",
        ));
    }
    let native_principal: String = identities[0].try_get("identifier")?;

    let mut candidates = sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT message.id
           FROM main.records message
           JOIN temp._query_sql_visible_records visible ON visible.id=message.id
           JOIN main.facet_values expectation
             ON expectation.record_id=message.id
            AND expectation.key='expectation' AND expectation.value='reply'
           JOIN main.message_audiences audience
             ON audience.message_id=message.id
            AND audience.source='addressed_to' AND audience.principal_id=?
          WHERE message.type='Message' AND message.deleted_at IS NULL
          ORDER BY message.id LIMIT ?",
    )
    .bind(native_principal)
    .bind(MAX_AWAITING_REPLY_CANDIDATES + 1)
    .fetch_all(&mut **transaction)
    .await?;
    ensure_budget()?;
    if candidates.len() > MAX_AWAITING_REPLY_CANDIDATES as usize {
        return Err(sql_contract::categorized_error(
            QuerySqlErrorCategory::ResultTooLarge,
            format!(
                "messages_awaiting_reply exceeds the {MAX_AWAITING_REPLY_CANDIDATES}-candidate evaluation limit"
            ),
        ));
    }

    for message_id in candidates.drain(..) {
        ensure_budget()?;
        let derivation =
            crate::message_expectation::derive_message_expectation_state_for_viewer_in(
                transaction,
                &message_id,
                principal.credential(),
            )
            .await?;
        ensure_budget()?;
        if derivation.expectation.as_deref() == Some("reply")
            && derivation.state == crate::message_expectation::MessageExpectationState::Open
        {
            sqlx::query(
                "INSERT INTO temp._query_sql_messages_awaiting_reply(message_id) VALUES (?)",
            )
            .bind(message_id)
            .execute(&mut **transaction)
            .await?;
        }
    }
    Ok(())
}

/// Run one caller-filtered query. The caller is transport-authenticated and is
/// never derived from tool arguments. Every explicit outcome rolls back; drop
/// does the same for cancellation/unwind, and pool release clears the TEMP
/// state plus progress callback before any later borrower can use it.
pub(crate) async fn query_sql_request_owned(
    db: Db,
    principal: QueryPrincipal,
    request: QuerySqlRequest,
) -> Result<SqlResult> {
    sql_contract::require_available(sql_contract::QuerySqlProfile::SqliteLocal)?;
    request.validate()?;
    validate(&request.sql)?;
    let statement = sql_contract::classify_single_read_statement(
        sql_contract::QuerySqlProfile::SqliteLocal,
        &request.sql,
    )?;
    let relation_dependencies = validated_relation_dependencies(&statement)?;
    let needs_awaiting_reply = relation_dependencies.contains("messages_awaiting_reply");
    let activity_dependent = relation_dependencies
        .iter()
        .any(|name| matches!(name.as_str(), "agent_activity" | "agent_activity_claims"));
    let pool = db.write_pool().clone();
    let mut connection = pool.acquire().await?;
    let contract = temp_contract();
    for temp_statement in contract.split(';').map(str::trim).filter(|s| !s.is_empty()) {
        if let Err(error) = sqlx::query(temp_statement).execute(&mut *connection).await {
            connection.close_on_drop();
            return Err(error.into());
        }
    }
    // This clear is deliberately outside the transaction: rolling it back
    // would restore a stale principal. Uncertain physical state is discarded.
    if let Err(error) = sqlx::query("DELETE FROM temp._query_sql_principal")
        .execute(&mut *connection)
        .await
    {
        connection.close_on_drop();
        return Err(error.into());
    }
    if let Err(error) = sqlx::query("DELETE FROM temp._query_sql_messages_awaiting_reply")
        .execute(&mut *connection)
        .await
    {
        connection.close_on_drop();
        return Err(error.into());
    }
    if let Err(error) = sqlx::query("DELETE FROM temp._query_sql_activity_members")
        .execute(&mut *connection)
        .await
    {
        connection.close_on_drop();
        return Err(error.into());
    }
    let mut transaction = connection.begin().await?;
    // Hosted roster installation touches only TEMP state. Establish the main
    // snapshot explicitly before sampling the inference clock so a concurrent
    // commit can never enter rows after their observation time.
    let _: Option<(i64,)> = sqlx::query_as("SELECT 1 FROM main.database_identity LIMIT 1")
        .fetch_optional(&mut *transaction)
        .await?;
    if activity_dependent {
        populate_activity_members(&mut transaction, &principal).await?;
    }
    sqlx::query(
        "INSERT INTO temp._query_sql_principal(singleton, account_id, trusted_local_bypass, activity_read, observed_at)
         VALUES (1, ?, ?, ?, ?)",
    )
    .bind(principal.credential().to_string())
    .bind(principal.trusted_local_bypass())
    .bind(principal.activity_read())
    .bind(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
    .execute(&mut *transaction)
    .await?;
    if activity_dependent {
        prepare_activity_observations(&mut transaction).await?;
    }
    let previous_value_limit = {
        let mut handle = transaction.lock_handle().await?;
        // SAFETY: `lock_handle` gives exclusive access to this connection's
        // live sqlite3 handle for the duration of the call.
        let previous = unsafe {
            libsqlite3_sys::sqlite3_limit(
                handle.as_raw_handle().as_ptr(),
                libsqlite3_sys::SQLITE_LIMIT_LENGTH,
                MAX_SQLITE_VALUE_BYTES,
            )
        };
        // Start the wall-clock budget when SQLite first executes caller VM
        // work, not when this async task registers the callback. Under process
        // load the task can be descheduled between registration and fetch;
        // charging that queue/scheduler delay made bounded queries fail with
        // SQLITE_INTERRUPT despite doing no work during the elapsed time.
        let mut query_started = None;
        handle.set_progress_handler(PROGRESS_OPS, move || {
            query_started.get_or_insert_with(Instant::now).elapsed() < QUERY_DEADLINE
        });
        previous
    };

    // The outer cap preserves every caller predicate/aggregate while bounding
    // row work. Rows are streamed and encoded under independent cell/result
    // byte ceilings; the progress handler independently bounds VM work.
    let capped = format!("SELECT * FROM ({statement}) LIMIT {}", MAX_ROWS + 1);
    let mut limit_breached = false;
    let query_result: Result<(Vec<String>, Vec<Value>, bool)> = async {
        if needs_awaiting_reply {
            populate_messages_awaiting_reply(&mut transaction, &principal).await?;
        }
        let query = bind_parameters(sqlx::query(&capped), &request.parameters)?;
        let mut stream = query.fetch(&mut *transaction);
        let mut columns = Vec::new();
        let mut output = Vec::new();
        let mut encoded_bytes = 2_usize; // JSON array brackets.
        let mut truncated = false;
        while let Some(row) = stream.try_next().await.map_err(|error| {
            let detail = error.to_string();
            let category = if detail.to_ascii_lowercase().contains("interrupted") {
                QuerySqlErrorCategory::Timeout
            } else {
                QuerySqlErrorCategory::SyntaxOrType
            };
            sql_contract::categorized_error(category, detail)
        })? {
            if output.len() as i64 == MAX_ROWS {
                truncated = true;
                break;
            }
            if columns.is_empty() {
                if row.columns().len() > MAX_COLUMNS {
                    limit_breached = true;
                    return Err(sql_contract::categorized_error(
                        QuerySqlErrorCategory::ResultTooLarge,
                        format!("result exceeds the {MAX_COLUMNS}-column limit"),
                    ));
                }
                columns = row
                    .columns()
                    .iter()
                    .map(|column| column.name().to_string())
                    .collect();
                let mut unique = std::collections::HashSet::new();
                if let Some(duplicate) = columns
                    .iter()
                    .find(|column| !unique.insert(column.as_str()))
                {
                    limit_breached = true;
                    return Err(sql_contract::categorized_error(
                        QuerySqlErrorCategory::DuplicateColumns,
                        format!("duplicate output column label '{duplicate}'"),
                    ));
                }
                encoded_bytes = encoded_bytes.saturating_add(serde_json::to_vec(&columns)?.len());
            }
            let mut object = Map::new();
            for (index, column) in row.columns().iter().enumerate() {
                object.insert(column.name().to_string(), json_cell(&row, index)?);
            }
            let value = Value::Object(object);
            encoded_bytes = encoded_bytes
                .saturating_add(serde_json::to_vec(&value)?.len())
                .saturating_add(1);
            if encoded_bytes > MAX_RESULT_ENCODED_BYTES {
                limit_breached = true;
                return Err(sql_contract::categorized_error(
                    QuerySqlErrorCategory::ResultTooLarge,
                    format!("encoded result exceeds the {MAX_RESULT_ENCODED_BYTES}-byte limit"),
                ));
            }
            output.push(value);
        }
        Ok((columns, output, truncated))
    }
    .await;

    let query_failed = query_result.is_err();
    let rollback_result = transaction.rollback().await;
    let deadline_result = async {
        let mut handle = connection.lock_handle().await?;
        handle.remove_progress_handler();
        // SAFETY: as above; restore the exact per-connection limit observed
        // before caller SQL ran. Pool release has an independent backstop for
        // cancellation/unwind before this point.
        unsafe {
            libsqlite3_sys::sqlite3_limit(
                handle.as_raw_handle().as_ptr(),
                libsqlite3_sys::SQLITE_LIMIT_LENGTH,
                previous_value_limit,
            );
        }
        Result::<()>::Ok(())
    }
    .await;
    if query_failed || limit_breached || rollback_result.is_err() || deadline_result.is_err() {
        connection.close_on_drop();
    }
    let (columns, rows, truncated) = query_result?;
    rollback_result?;
    deadline_result?;
    let row_count = rows.len();
    Ok(SqlResult {
        columns,
        rows,
        row_count,
        truncated,
    })
}

/// Snapshot-preserving form for artifact input resolution. The caller owns the
/// surrounding read transaction and must roll it back; this function installs
/// only connection-local TEMP views/principal state and restores VM limits and
/// the progress handler before returning.
#[cfg(test)]
pub(crate) async fn query_sql_request_in(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    principal: QueryPrincipal,
    request: QuerySqlRequest,
) -> Result<SqlResult> {
    query_sql_request_in_with_row_limit(transaction, principal, request, MAX_ROWS)
        .await
        .map(|(result, _)| result)
}

/// Internal saved-query execution retains one extra row so the governed
/// envelope can validate the identity/order boundary before truncating it.
pub(crate) async fn query_sql_request_in_for_saved(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    principal: QueryPrincipal,
    request: QuerySqlRequest,
) -> Result<(SqlResult, GovernedSqlObservation)> {
    query_sql_request_in_with_row_limit(transaction, principal, request, MAX_ROWS + 1).await
}

async fn query_sql_request_in_with_row_limit(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    principal: QueryPrincipal,
    request: QuerySqlRequest,
    row_limit: i64,
) -> Result<(SqlResult, GovernedSqlObservation)> {
    sql_contract::require_available(sql_contract::QuerySqlProfile::SqliteLocal)?;
    request.validate()?;
    validate(&request.sql)?;
    let statement = sql_contract::classify_single_read_statement(
        sql_contract::QuerySqlProfile::SqliteLocal,
        &request.sql,
    )?;
    let relation_dependencies = validated_relation_dependencies(&statement)?;
    let needs_awaiting_reply = relation_dependencies.contains("messages_awaiting_reply");
    let activity_dependent = relation_dependencies
        .iter()
        .any(|name| matches!(name.as_str(), "agent_activity" | "agent_activity_claims"));
    let presence_only =
        relation_dependencies.len() == 1 && relation_dependencies.contains("agent_activity");
    for temp_statement in temp_contract()
        .split(';')
        .map(str::trim)
        .filter(|statement| !statement.is_empty())
    {
        sqlx::query(temp_statement)
            .execute(&mut **transaction)
            .await?;
    }
    sqlx::query("DELETE FROM temp._query_sql_principal")
        .execute(&mut **transaction)
        .await?;
    sqlx::query("DELETE FROM temp._query_sql_messages_awaiting_reply")
        .execute(&mut **transaction)
        .await?;
    sqlx::query("DELETE FROM temp._query_sql_activity_members")
        .execute(&mut **transaction)
        .await?;
    // SQLite transactions are deferred: establish the main-database snapshot
    // before sampling the wall clock used for both row inference and receipt
    // metadata. Otherwise a concurrent commit could enter the result after the
    // sampled observation time.
    let _: Option<(i64,)> = sqlx::query_as("SELECT 1 FROM main.database_identity LIMIT 1")
        .fetch_optional(&mut **transaction)
        .await?;
    let observed_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    if activity_dependent {
        populate_activity_members(transaction, &principal).await?;
    }
    sqlx::query(
        "INSERT INTO temp._query_sql_principal(singleton, account_id, trusted_local_bypass, activity_read, observed_at)
         VALUES (1, ?, ?, ?, ?)",
    )
    .bind(principal.credential().to_string())
    .bind(principal.trusted_local_bypass())
    .bind(principal.activity_read())
    .bind(&observed_at)
    .execute(&mut **transaction)
    .await?;
    let (transient_available, transient_watermark) = if activity_dependent {
        prepare_activity_observations(transaction).await?
    } else {
        (true, None)
    };
    let visible_content_event_seq: i64 =
        sqlx::query_scalar("SELECT coalesce(max(local_seq),0) FROM temp.content_events")
            .fetch_one(&mut **transaction)
            .await?;
    let (activity_content_event_seq, control_event_seq): (i64, i64) = if activity_dependent {
        sqlx::query_as(
            "SELECT coalesce((SELECT max(event.seq)
                                FROM main.content_events event
                                JOIN main.agent_runs run ON run.run_key=event.run_key
                               WHERE event.actor=run.account_id
                                 AND NOT (event.type='record.updated'
                                          AND (json_type(event.payload,'$.claimed_by_account') IS NOT NULL
                                               OR json_type(event.payload,'$.claimed_run_key') IS NOT NULL))
                                 AND (EXISTS (SELECT 1 FROM temp._query_sql_activity_members member
                                               WHERE member.account_id=run.account_id)
                                      OR ((SELECT trusted_local_bypass FROM temp._query_sql_principal)=1
                                          AND run.account_id=(SELECT account_id FROM temp._query_sql_principal)))
                                 AND (run.ended_at IS NULL
                                  OR julianday(event.created_at)<=julianday(run.ended_at))),0),
                coalesce((SELECT max(max(start_event_seq,coalesce(close_event_seq,start_event_seq)))
                            FROM main.agent_runs run
                           WHERE EXISTS (SELECT 1 FROM temp._query_sql_activity_members member
                                           WHERE member.account_id=run.account_id)
                              OR ((SELECT trusted_local_bypass FROM temp._query_sql_principal)=1
                                  AND run.account_id=(SELECT account_id FROM temp._query_sql_principal))),0)",
        )
        .fetch_one(&mut **transaction)
        .await?
    } else {
        (0, 0)
    };
    let content_event_seq = if presence_only {
        Some(activity_content_event_seq)
    } else if activity_dependent {
        Some(visible_content_event_seq.max(activity_content_event_seq))
    } else {
        Some(visible_content_event_seq)
    };
    let authorization_boundary = if presence_only {
        // Presence authorization is independent of record policy state. Hash
        // exactly the request-local roster installed for this query.
        let admitted_accounts: Vec<(String, String)> = sqlx::query_as(
            "SELECT account_id,member_ref FROM temp._query_sql_activity_members ORDER BY account_id",
        )
        .fetch_all(&mut **transaction)
        .await?;
        let source = serde_json::to_vec(&(
            principal.credential(),
            principal.trusted_local_bypass(),
            principal.activity_read(),
            admitted_accounts,
        ))?;
        format!(
            "native.authorization-snapshot.v1.{:x}",
            Sha256::digest(source)
        )
    } else {
        // Hash the effective caller-visible authorization set rather than the
        // database-global policy epoch. Hidden, unrelated policy mutations
        // cannot perturb this token, while every hide/unhide changes it.
        let mut digest = Sha256::new();
        let prefix = serde_json::to_vec(&(
            principal.credential(),
            principal.trusted_local_bypass(),
            relation_dependencies.iter().cloned().collect::<Vec<_>>(),
        ))?;
        digest.update((prefix.len() as u64).to_be_bytes());
        digest.update(prefix);
        let mut visible = sqlx::query("SELECT id FROM temp._query_sql_visible_records ORDER BY id")
            .fetch(&mut **transaction);
        while let Some(row) = visible.try_next().await? {
            let id: String = row.try_get(0)?;
            digest.update((id.len() as u64).to_be_bytes());
            digest.update(id.as_bytes());
        }
        format!("native.authorization-snapshot.v1.{:x}", digest.finalize())
    };
    let observation = GovernedSqlObservation {
        observed_at,
        content_event_seq,
        lifecycle_event_seq: activity_dependent.then_some(control_event_seq),
        authorization_boundary,
        transient_watermark,
        transient_available,
    };
    let previous_value_limit = {
        let mut handle = transaction.lock_handle().await?;
        // SAFETY: lock_handle gives exclusive access to this sqlite handle.
        let previous = unsafe {
            libsqlite3_sys::sqlite3_limit(
                handle.as_raw_handle().as_ptr(),
                libsqlite3_sys::SQLITE_LIMIT_LENGTH,
                MAX_SQLITE_VALUE_BYTES,
            )
        };
        let mut query_started = None;
        handle.set_progress_handler(PROGRESS_OPS, move || {
            query_started.get_or_insert_with(Instant::now).elapsed() < QUERY_DEADLINE
        });
        previous
    };
    let capped = format!("SELECT * FROM ({statement}) LIMIT {}", row_limit + 1);
    let query_result: Result<(Vec<String>, Vec<Value>, bool)> = async {
        if needs_awaiting_reply {
            populate_messages_awaiting_reply(transaction, &principal).await?;
        }
        let query = bind_parameters(sqlx::query(&capped), &request.parameters)?;
        let mut stream = query.fetch(&mut **transaction);
        let mut columns = Vec::new();
        let mut output = Vec::new();
        let mut encoded_bytes = 2_usize;
        let mut truncated = false;
        while let Some(row) = stream.try_next().await.map_err(|error| {
            let detail = error.to_string();
            let category = if detail.to_ascii_lowercase().contains("interrupted") {
                QuerySqlErrorCategory::Timeout
            } else {
                QuerySqlErrorCategory::SyntaxOrType
            };
            sql_contract::categorized_error(category, detail)
        })? {
            if output.len() as i64 == row_limit {
                truncated = true;
                break;
            }
            if columns.is_empty() {
                if row.columns().len() > MAX_COLUMNS {
                    return Err(sql_contract::categorized_error(
                        QuerySqlErrorCategory::ResultTooLarge,
                        format!("result exceeds the {MAX_COLUMNS}-column limit"),
                    ));
                }
                columns = row
                    .columns()
                    .iter()
                    .map(|column| column.name().to_string())
                    .collect();
                let mut unique = std::collections::HashSet::new();
                if let Some(duplicate) = columns
                    .iter()
                    .find(|column| !unique.insert(column.as_str()))
                {
                    return Err(sql_contract::categorized_error(
                        QuerySqlErrorCategory::DuplicateColumns,
                        format!("duplicate output column label '{duplicate}'"),
                    ));
                }
                encoded_bytes = encoded_bytes.saturating_add(serde_json::to_vec(&columns)?.len());
            }
            let mut object = Map::new();
            for (index, column) in row.columns().iter().enumerate() {
                object.insert(column.name().to_string(), json_cell(&row, index)?);
            }
            let value = Value::Object(object);
            encoded_bytes = encoded_bytes
                .saturating_add(serde_json::to_vec(&value)?.len())
                .saturating_add(1);
            if encoded_bytes > MAX_RESULT_ENCODED_BYTES {
                return Err(sql_contract::categorized_error(
                    QuerySqlErrorCategory::ResultTooLarge,
                    format!("encoded result exceeds the {MAX_RESULT_ENCODED_BYTES}-byte limit"),
                ));
            }
            output.push(value);
        }
        Ok((columns, output, truncated))
    }
    .await;
    {
        let mut handle = transaction.lock_handle().await?;
        handle.remove_progress_handler();
        // SAFETY: same exclusive handle; restore the exact previous limit.
        unsafe {
            libsqlite3_sys::sqlite3_limit(
                handle.as_raw_handle().as_ptr(),
                libsqlite3_sys::SQLITE_LIMIT_LENGTH,
                previous_value_limit,
            );
        }
    }
    // The TEMP catalog is connection-scoped and shadows physical table names.
    // Artifact resolution continues in this same transaction to hydrate the
    // selected record IDs, so remove the governed projection before invoking
    // ordinary domain reads. The already-materialized result remains valid.
    let cleanup_result: Result<()> = async {
        for relation in sql_contract::LOGICAL_RELATIONS.iter().rev() {
            sqlx::query(&format!("DROP VIEW IF EXISTS temp.{}", relation.name))
                .execute(&mut **transaction)
                .await?;
        }
        sqlx::query("DROP VIEW IF EXISTS temp._query_sql_visible_records")
            .execute(&mut **transaction)
            .await?;
        sqlx::query("DROP VIEW IF EXISTS temp._query_sql_authorization_subjects")
            .execute(&mut **transaction)
            .await?;
        sqlx::query("DROP TABLE IF EXISTS temp._query_sql_messages_awaiting_reply")
            .execute(&mut **transaction)
            .await?;
        sqlx::query("DROP TABLE IF EXISTS temp._query_sql_principal")
            .execute(&mut **transaction)
            .await?;
        sqlx::query("DROP TABLE IF EXISTS temp._query_sql_activity_observations")
            .execute(&mut **transaction)
            .await?;
        sqlx::query("DROP TABLE IF EXISTS temp._query_sql_activity_members")
            .execute(&mut **transaction)
            .await?;
        Ok(())
    }
    .await;
    let (columns, rows, truncated) = query_result?;
    cleanup_result?;
    Ok((
        SqlResult {
            row_count: rows.len(),
            columns,
            rows,
            truncated,
        },
        observation,
    ))
}

fn bind_parameters<'q>(
    mut query: Query<'q, Sqlite, SqliteArguments<'q>>,
    parameters: &[QuerySqlParameter],
) -> Result<Query<'q, Sqlite, SqliteArguments<'q>>> {
    for parameter in parameters {
        query = match parameter {
            QuerySqlParameter::Boolean { value } => query.bind(*value),
            QuerySqlParameter::Integer { value } => query.bind(
                value
                    .as_deref()
                    .map(str::parse::<i64>)
                    .transpose()
                    .map_err(|_| {
                        sql_contract::categorized_error(
                            QuerySqlErrorCategory::InvalidArguments,
                            "integer parameter must be a signed 64-bit decimal string",
                        )
                    })?,
            ),
            QuerySqlParameter::Real { value } => query.bind(*value),
            QuerySqlParameter::Text { value } => query.bind(value.clone()),
            QuerySqlParameter::Bytes { value } => {
                use base64::Engine as _;
                query.bind(
                    value
                        .as_deref()
                        .map(|value| base64::engine::general_purpose::STANDARD.decode(value))
                        .transpose()
                        .map_err(|_| {
                            sql_contract::categorized_error(
                                QuerySqlErrorCategory::InvalidArguments,
                                "bytes parameter must be canonical base64",
                            )
                        })?,
                )
            }
            QuerySqlParameter::Json { value } => query.bind(value.clone()),
            QuerySqlParameter::Timestamp { value } => query.bind(value.clone()),
        };
    }
    Ok(query)
}

/// Backwards-compatible owned entrypoint retained for internal callers.
pub(crate) async fn query_sql_owned(
    db: Db,
    principal: QueryPrincipal,
    sql: String,
) -> Result<SqlResult> {
    query_sql_request_owned(
        db,
        principal,
        QuerySqlRequest {
            sql,
            parameters: Vec::new(),
        },
    )
    .await
}

/// Library-facing borrowed form. Tool dispatch uses the owned counterpart so
/// its boxed handler future remains `Send + 'static`. Accepts anything that
/// converts into a [`QueryPrincipal`] — in particular `&mcp::Caller`.
pub async fn query_sql(
    db: &Db,
    principal: impl Into<QueryPrincipal>,
    sql: &str,
) -> Result<SqlResult> {
    query_sql_owned(db.clone(), principal.into(), sql.to_string()).await
}

#[cfg(test)]
pub(crate) async fn principal_context_is_empty(db: &Db) -> Result<bool> {
    let mut connection = db.write_pool().acquire().await?;
    let contract = temp_contract();
    for temp_statement in contract.split(';').map(str::trim).filter(|s| !s.is_empty()) {
        sqlx::query(temp_statement)
            .execute(&mut *connection)
            .await?;
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM temp._query_sql_principal")
        .fetch_one(&mut *connection)
        .await?;
    Ok(count == 0)
}

#[cfg(test)]
mod logical_catalog_contract_tests {
    use super::*;

    fn columns(connection: &rusqlite::Connection, relation: &str) -> Vec<String> {
        let mut statement = connection
            .prepare(&format!("PRAGMA temp.table_info('{relation}')"))
            .unwrap();
        statement
            .query_map([], |row| row.get(1))
            .unwrap()
            .collect::<std::result::Result<Vec<String>, _>>()
            .unwrap()
    }

    #[test]
    fn logical_catalog_metadata_matches_both_sqlite_schemas_exactly() {
        let expanded = rusqlite::Connection::open_in_memory().unwrap();
        let ddl = DDL_STATEMENTS
            .iter()
            .map(|sql| format!("{sql};\n"))
            .collect::<String>();
        expanded.execute_batch(&ddl).unwrap();
        expanded.execute_batch(&temp_contract()).unwrap();

        let strict = rusqlite::Connection::open_in_memory().unwrap();
        strict.execute_batch(STRICT_LOGICAL_SCHEMA).unwrap();

        for relation in sql_contract::LOGICAL_RELATIONS {
            let expected = relation
                .columns
                .iter()
                .map(|column| (*column).to_owned())
                .collect::<Vec<_>>();
            assert_eq!(
                columns(&expanded, relation.name),
                expected,
                "expanded {}",
                relation.name
            );
            assert_eq!(
                columns(&strict, relation.name),
                expected,
                "strict {}",
                relation.name
            );
        }
    }

    #[test]
    fn additive_relation_keeps_the_saved_query_breaking_epoch() {
        assert_eq!(sql_contract::LOGICAL_CATALOG_REVISION, 3);
        let relation = sql_contract::LOGICAL_RELATIONS
            .iter()
            .find(|relation| relation.name == "messages_awaiting_reply")
            .expect("additive Messages relation is registered");
        assert_eq!(relation.semantic_version, 1);
        assert_eq!(relation.profiles, ["sqlite-local"]);
        assert!(relation.caller_relative);
        assert_eq!(relation.columns, ["message_id"]);
        let activity = sql_contract::LOGICAL_RELATIONS
            .iter()
            .find(|relation| relation.name == "agent_activity")
            .expect("agent activity relation is registered");
        assert_eq!(activity.semantic_version, 2);
    }
}

#[cfg(test)]
mod production_acl_tests {
    use std::time::Duration;

    use futures::{stream, FutureExt, StreamExt};
    use serde_json::json;

    use super::*;
    use crate::authorization::{
        effective_capability, replace_explicit_policy, AllowEntry, Capability, Principal,
        MAX_DERIVED_BEARER_DEPTH,
    };
    use crate::events::{FacetSetPayload, LinkAddedPayload};
    use crate::store::{add_link, create_record, delete_record, set_facet};

    // Pinned fixture record ids. Three properties of the old slugs were
    // load-bearing and are preserved deliberately:
    //
    //   * `LIKE 'artifact-%'` selected exactly the artifact fixtures, so those
    //     ids now share `ARTIFACT_ID_PREFIX` and nothing else does.
    //   * `LIKE '%-private'` selected exactly Alice's and Bea's private notes,
    //     so those two ids now share `PRIVATE_ID_SUFFIX` and nothing else does.
    //   * Several assertions read rows back `ORDER BY id` (and blob filenames
    //     `ORDER BY 1`, which are `{id}.txt`). The numbering below keeps every
    //     one of those orders: alice/bea before common, hidden before kindless,
    //     attachment-alice before attachment-common.
    const ARTIFACT_ID_PREFIX: &str = "9e795a47-";
    const PRIVATE_ID_SUFFIX: &str = "0b1a7e";
    const ALICE_PRIVATE_ID: &str = "9e795000-0000-4000-8000-0000010b1a7e";
    const BEA_PRIVATE_ID: &str = "9e795000-0000-4000-8000-0000020b1a7e";
    const COMMON_ID: &str = "9e795000-0000-4000-8000-000003000000";
    const TOMBSTONE_ID: &str = "9e795000-0000-4000-8000-000004000000";
    const KINDLESS_BEARER_ALICE_ID: &str = "9e795000-0000-4000-8000-000005000000";
    const ATTACHMENT_ALICE_ID: &str = "9e795000-0000-4000-8000-000006000000";
    const ATTACHMENT_COMMON_ID: &str = "9e795000-0000-4000-8000-000007000000";
    const ARTIFACT_HIDDEN_BEARER_ID: &str = "9e795a47-0000-4000-8000-000000000001";
    const ARTIFACT_KINDLESS_BEARER_ID: &str = "9e795a47-0000-4000-8000-000000000002";
    const ARTIFACT_VISIBLE_BEARER_ID: &str = "9e795a47-0000-4000-8000-000000000003";
    const ARTIFACT_BEARERLESS_ID: &str = "9e795a47-0000-4000-8000-000000000004";
    const ARTIFACT_MULTIPLE_ID: &str = "9e795a47-0000-4000-8000-000000000005";
    const ARTIFACT_CYCLE_A_ID: &str = "9e795a47-0000-4000-8000-000000000006";
    const ARTIFACT_CYCLE_B_ID: &str = "9e795a47-0000-4000-8000-000000000007";
    const ARTIFACT_TOMBSTONED_BEARER_ID: &str = "9e795a47-0000-4000-8000-000000000008";
    const DEPTH_TERMINAL_ID: &str = "9e795000-0000-4000-8000-000008000000";
    const LOCAL_MALFORMED_ID: &str = "9e795000-0000-4000-8000-00000a000000";
    const LOCAL_TOMBSTONE_ID: &str = "9e795000-0000-4000-8000-00000b000000";
    const LOCAL_MALFORMED_ANCHOR_ID: &str = "9e795000-0000-4000-8000-00000c000000";
    const OVERSIZE_CELL_ID: &str = "9e795000-0000-4000-8000-00000d000000";
    const REPEATED_BYTES_ID: &str = "9e795000-0000-4000-8000-00000e000000";

    async fn protected_fixture() -> (Db, QueryPrincipal, QueryPrincipal) {
        let db = crate::create_database(":memory:").await.unwrap();
        for (id, name, body) in [
            (ALICE_PRIVATE_ID, "Alice private", "sharedterm alice-only"),
            (BEA_PRIVATE_ID, "Bea private", "sharedterm bea-only"),
            (COMMON_ID, "Common", "sharedterm common"),
            (TOMBSTONE_ID, "Tombstone", "sharedterm removed"),
        ] {
            create_record(
                &db,
                json!({
                    "id": id,
                    "type": "Document",
                    "kind": "note",
                    "name": name,
                    "body": body,
                    "home_id": crate::schema::ROOT_RECORD_ID
                }),
            )
            .await
            .unwrap();
        }
        create_record(
            &db,
            json!({
                "id": KINDLESS_BEARER_ALICE_ID,
                "type": "Document",
                "kind": "note",
                "name": "Kindless bearer Alice",
                "home_id": crate::schema::ROOT_RECORD_ID
            }),
        )
        .await
        .unwrap();
        sqlx::query(&format!(
            "UPDATE records SET kind = NULL WHERE id = '{KINDLESS_BEARER_ALICE_ID}'"
        ))
        .execute(db.write_pool())
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            ALICE_PRIVATE_ID,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            BEA_PRIVATE_ID,
            vec![AllowEntry::account("bea", Capability::View)],
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            COMMON_ID,
            vec![
                AllowEntry::account("alice", Capability::View),
                AllowEntry::account("bea", Capability::View),
            ],
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            TOMBSTONE_ID,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            KINDLESS_BEARER_ALICE_ID,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();
        for (record_id, account, email) in [
            (ALICE_PRIVATE_ID, "alice", "alice@example.test"),
            (BEA_PRIVATE_ID, "bea", "bea@example.test"),
        ] {
            sqlx::query(
                "INSERT INTO bindings(record_id, system, identifier, is_canonical)
                 VALUES (?, 'account', ?, 1), (?, 'email', ?, 1)",
            )
            .bind(record_id)
            .bind(account)
            .bind(record_id)
            .bind(email)
            .execute(db.write_pool())
            .await
            .unwrap();
            set_facet(
                &db,
                record_id,
                FacetSetPayload {
                    key: "secret".into(),
                    value: Some(format!("{account}-facet")),
                    vocab_ref: None,
                    as_of: None,
                    observation_only: false,
                },
            )
            .await
            .unwrap();
        }
        add_link(
            &db,
            LinkAddedPayload {
                id: Some("alice-common".into()),
                source_id: ALICE_PRIVATE_ID.into(),
                target_id: COMMON_ID.into(),
                relationship: "mentions".into(),
                note: None,
            },
        )
        .await
        .unwrap();
        add_link(
            &db,
            LinkAddedPayload {
                id: Some("common-bea".into()),
                source_id: COMMON_ID.into(),
                target_id: BEA_PRIVATE_ID.into(),
                relationship: "mentions".into(),
                note: None,
            },
        )
        .await
        .unwrap();

        for (attachment_id, bearer_id, grants) in [
            (ATTACHMENT_ALICE_ID, ALICE_PRIVATE_ID, vec!["alice"]),
            (ATTACHMENT_COMMON_ID, COMMON_ID, vec!["alice", "bea"]),
        ] {
            create_record(
                &db,
                json!({
                    "id": attachment_id,
                    "type": "Document",
                    "kind": "attachment",
                    "name": format!("{attachment_id}.txt"),
                    "home_id": crate::schema::ROOT_RECORD_ID
                }),
            )
            .await
            .unwrap();
            replace_explicit_policy(
                &db,
                "test:policy",
                attachment_id,
                grants
                    .into_iter()
                    .map(|account| AllowEntry::account(account, Capability::View))
                    .collect(),
            )
            .await
            .unwrap();
            let blob = crate::blob::insert_blob(
                &db,
                attachment_id.as_bytes(),
                Some("text/plain"),
                Some(&format!("{attachment_id}.txt")),
            )
            .await
            .unwrap();
            set_facet(
                &db,
                attachment_id,
                FacetSetPayload {
                    key: "blob_ref".into(),
                    value: Some(blob.id),
                    vocab_ref: None,
                    as_of: None,
                    observation_only: false,
                },
            )
            .await
            .unwrap();
            add_link(
                &db,
                LinkAddedPayload {
                    id: Some(format!("bearer-{attachment_id}")),
                    source_id: attachment_id.into(),
                    target_id: bearer_id.into(),
                    relationship: "part_of".into(),
                    note: None,
                },
            )
            .await
            .unwrap();
        }

        for (id, record_type, kind, grants) in [
            (
                ARTIFACT_HIDDEN_BEARER_ID,
                "Annotation",
                "citation",
                vec!["bea"],
            ),
            (
                ARTIFACT_VISIBLE_BEARER_ID,
                "Document",
                "attachment",
                vec!["alice"],
            ),
            (
                ARTIFACT_BEARERLESS_ID,
                "Annotation",
                "citation",
                vec!["bea"],
            ),
            (ARTIFACT_MULTIPLE_ID, "Annotation", "citation", vec!["bea"]),
            (ARTIFACT_CYCLE_A_ID, "Annotation", "citation", vec!["bea"]),
            (ARTIFACT_CYCLE_B_ID, "Annotation", "citation", vec!["bea"]),
            (
                ARTIFACT_TOMBSTONED_BEARER_ID,
                "Annotation",
                "citation",
                vec!["bea"],
            ),
            (
                ARTIFACT_KINDLESS_BEARER_ID,
                "Annotation",
                "citation",
                vec!["bea"],
            ),
        ] {
            create_record(
                &db,
                json!({
                    "id": id,
                    "type": record_type,
                    "kind": kind,
                    "name": id,
                    "home_id": crate::schema::ROOT_RECORD_ID
                }),
            )
            .await
            .unwrap();
            replace_explicit_policy(
                &db,
                "test:policy",
                id,
                grants
                    .into_iter()
                    .map(|account| AllowEntry::account(account, Capability::View))
                    .collect(),
            )
            .await
            .unwrap();
        }
        for (id, source, target) in [
            (
                "part-artifact-hidden",
                ARTIFACT_HIDDEN_BEARER_ID,
                ALICE_PRIVATE_ID,
            ),
            (
                "part-artifact-visible",
                ARTIFACT_VISIBLE_BEARER_ID,
                BEA_PRIVATE_ID,
            ),
            ("part-artifact-multiple-a", ARTIFACT_MULTIPLE_ID, COMMON_ID),
            (
                "part-artifact-multiple-b",
                ARTIFACT_MULTIPLE_ID,
                BEA_PRIVATE_ID,
            ),
            (
                "part-artifact-cycle-a",
                ARTIFACT_CYCLE_A_ID,
                ARTIFACT_CYCLE_B_ID,
            ),
            (
                "part-artifact-cycle-b",
                ARTIFACT_CYCLE_B_ID,
                ARTIFACT_CYCLE_A_ID,
            ),
            (
                "part-artifact-tombstone",
                ARTIFACT_TOMBSTONED_BEARER_ID,
                TOMBSTONE_ID,
            ),
            (
                "part-artifact-kindless",
                ARTIFACT_KINDLESS_BEARER_ID,
                KINDLESS_BEARER_ALICE_ID,
            ),
        ] {
            add_link(
                &db,
                LinkAddedPayload {
                    id: Some(id.into()),
                    source_id: source.into(),
                    target_id: target.into(),
                    relationship: "part_of".into(),
                    note: None,
                },
            )
            .await
            .unwrap();
        }
        set_facet(
            &db,
            TOMBSTONE_ID,
            FacetSetPayload {
                key: "secret".into(),
                value: Some("removed".into()),
                vocab_ref: None,
                as_of: None,
                observation_only: false,
            },
        )
        .await
        .unwrap();
        delete_record(&db, TOMBSTONE_ID).await.unwrap();
        (
            db,
            QueryPrincipal::authenticated("alice"),
            QueryPrincipal::authenticated("bea"),
        )
    }

    async fn governed_query(
        db: &Db,
        principal: QueryPrincipal,
        sql: &str,
    ) -> (SqlResult, GovernedSqlObservation) {
        let mut connection = db.write_pool().acquire().await.unwrap();
        let mut transaction = connection.begin().await.unwrap();
        let result = query_sql_request_in_for_saved(
            &mut transaction,
            principal,
            QuerySqlRequest {
                sql: sql.to_string(),
                parameters: Vec::new(),
            },
        )
        .await
        .unwrap();
        transaction.rollback().await.unwrap();
        result
    }

    fn first_strings(result: &SqlResult) -> Vec<String> {
        result
            .rows
            .iter()
            .map(|row| {
                row.as_object()
                    .unwrap()
                    .values()
                    .next()
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .into()
            })
            .collect()
    }

    #[tokio::test]
    async fn bearer_depth_boundary_agrees_across_rust_fts_and_restricted_sql() {
        let db = crate::create_database(":memory:").await.unwrap();
        create_record(
            &db,
            json!({
                "id": DEPTH_TERMINAL_ID,
                "type": "WorkItem",
                "kind": "task",
                "name": "Depth terminal"
            }),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            DEPTH_TERMINAL_ID,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();

        let mut bearer = DEPTH_TERMINAL_ID.to_string();
        let mut boundary = String::new();
        let mut over_limit = String::new();
        for depth in 1..=MAX_DERIVED_BEARER_DEPTH + 1 {
            let id = format!("9e795000-0000-4000-8000-0000090{depth:05}");
            create_record(
                &db,
                json!({
                    "id": id,
                    "type": "Document",
                    "kind": "attachment",
                    "name": format!("Depth artifact {depth}"),
                    "body": "depthlimitterm"
                }),
            )
            .await
            .unwrap();
            add_link(
                &db,
                LinkAddedPayload {
                    id: Some(format!("depth-part-{depth:03}")),
                    source_id: id.clone(),
                    target_id: bearer,
                    relationship: "part_of".into(),
                    note: None,
                },
            )
            .await
            .unwrap();
            bearer = id.clone();
            if depth == MAX_DERIVED_BEARER_DEPTH {
                boundary = id;
            } else if depth == MAX_DERIVED_BEARER_DEPTH + 1 {
                over_limit = id;
            }
        }

        let principal = Principal::bound("alice", true);
        assert_eq!(
            effective_capability(&db, principal, &boundary)
                .await
                .unwrap(),
            Capability::View
        );
        assert!(effective_capability(&db, principal, &over_limit)
            .await
            .is_err());

        let hits = crate::query::fts::search(
            &db,
            "alice",
            "depthlimitterm",
            &crate::query::fts::FtsOptions {
                limit: Some(200),
                ..crate::query::fts::FtsOptions::default()
            },
        )
        .await
        .unwrap();
        let hit_ids: std::collections::HashSet<&str> =
            hits.iter().map(|hit| hit.id.as_str()).collect();
        assert!(hit_ids.contains(boundary.as_str()));
        assert!(!hit_ids.contains(over_limit.as_str()));

        let caller = QueryPrincipal::authenticated("alice");
        let sql = format!(
            "SELECT id FROM records WHERE id IN ('{boundary}', '{over_limit}') ORDER BY id"
        );
        let rows = query_sql(&db, &caller, &sql).await.unwrap();
        assert_eq!(first_strings(&rows), [boundary]);

        // Complexity guard. This fixture is the shape that used to sit on the
        // QUERY_DEADLINE_MS edge: a MAX_DERIVED_BEARER_DEPTH-long derived
        // chain, projected through `records`, which references the visibility
        // relation twice (once for the row, once for the home_id LEFT JOIN).
        // The bearer-first walk makes that cost proportional to the live
        // record count instead of to chain depth.
        //
        // Deliberately NOT a wall-clock threshold. `query_sql` already
        // enforces QUERY_DEADLINE internally, so a return to depth-quadratic
        // cost fails this call on its own; a second, tighter time bound would
        // only fire for regressions the deadline already catches, while adding
        // exactly the host-speed-decides-the-outcome flake this task exists to
        // remove. If this projection starts failing, the walk's complexity
        // changed — it is not "the usual timeout".
        let projected = query_sql(&db, &caller, "SELECT id, home_id FROM records ORDER BY id")
            .await
            .unwrap();
        assert!(!projected.rows.is_empty());
        db.close().await;
    }

    #[tokio::test]
    async fn trusted_local_bypasses_grants_but_not_live_shape_or_explicit_anchor_checks() {
        let (db, _alice, _bea) = protected_fixture().await;
        sqlx::query(&format!(
            "UPDATE records SET name = 'localbypassterm valid' WHERE id = '{ATTACHMENT_ALICE_ID}'"
        ))
        .execute(db.write_pool())
        .await
        .unwrap();

        for id in [LOCAL_MALFORMED_ID, LOCAL_TOMBSTONE_ID] {
            create_record(
                &db,
                json!({
                    "id": id,
                    "type": "Document",
                    "kind": "attachment",
                    "name": format!("localbypassterm {id}")
                }),
            )
            .await
            .unwrap();
        }
        for (id, source, target) in [
            ("local-malformed-a", LOCAL_MALFORMED_ID, ALICE_PRIVATE_ID),
            ("local-malformed-b", LOCAL_MALFORMED_ID, BEA_PRIVATE_ID),
            ("local-tombstone-part", LOCAL_TOMBSTONE_ID, BEA_PRIVATE_ID),
        ] {
            add_link(
                &db,
                LinkAddedPayload {
                    id: Some(id.into()),
                    source_id: source.into(),
                    target_id: target.into(),
                    relationship: "part_of".into(),
                    note: None,
                },
            )
            .await
            .unwrap();
        }
        delete_record(&db, LOCAL_TOMBSTONE_ID).await.unwrap();

        create_record(
            &db,
            json!({
                "id": LOCAL_MALFORMED_ANCHOR_ID,
                "type": "Document",
                "kind": "note",
                "name": "localbypassterm malformed anchor",
                "owner_id": ALICE_PRIVATE_ID
            }),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            LOCAL_MALFORMED_ANCHOR_ID,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();
        sqlx::query(&format!(
            "DELETE FROM record_policies WHERE record_id = '{LOCAL_MALFORMED_ANCHOR_ID}'"
        ))
        .execute(db.write_pool())
        .await
        .unwrap();

        // Hold four of the five pool slots so restricted SQL and the following
        // ordinary FTS query must reuse the same physical connection. This
        // guards against leaked TEMP views shadowing main relations.
        let mut held_connections = Vec::new();
        for _ in 0..4 {
            held_connections.push(db.write_pool().acquire().await.unwrap());
        }
        // SAFETY: test-only construction of the trusted-local fixture.
        let trusted = unsafe { QueryPrincipal::trusted_local_unchecked("local") };
        let authenticated = QueryPrincipal::authenticated("local");
        let statement = &format!(
            "SELECT id FROM records WHERE id IN (
                '{ATTACHMENT_ALICE_ID}', '{LOCAL_MALFORMED_ID}',
                '{LOCAL_TOMBSTONE_ID}', '{LOCAL_MALFORMED_ANCHOR_ID}'
            ) ORDER BY id"
        );
        assert_eq!(
            first_strings(&query_sql(&db, &trusted, statement).await.unwrap()),
            [ATTACHMENT_ALICE_ID]
        );
        assert!(query_sql(&db, &authenticated, statement)
            .await
            .unwrap()
            .rows
            .is_empty());

        let opts = crate::query::fts::FtsOptions {
            limit: Some(20),
            ..crate::query::fts::FtsOptions::default()
        };
        let trusted_hits = crate::query::fts::search_with_policy_bypass(
            &db,
            trusted.credential(),
            true,
            "localbypassterm",
            &opts,
        )
        .await
        .unwrap();
        assert_eq!(
            trusted_hits
                .iter()
                .map(|hit| hit.id.as_str())
                .collect::<Vec<_>>(),
            [ATTACHMENT_ALICE_ID]
        );
        assert!(
            crate::query::fts::search(&db, "local", "localbypassterm", &opts)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(effective_capability(
            &db,
            Principal::bound("alice", true),
            LOCAL_MALFORMED_ANCHOR_ID
        )
        .await
        .is_err());
        drop(held_connections);
        db.close().await;
    }

    #[tokio::test]
    async fn production_relations_filter_rows_counts_and_tombstoned_bearers() {
        let (db, alice, bea) = protected_fixture().await;
        let alice_rows = query_sql(
            &db,
            &alice,
            "SELECT id FROM records WHERE kind = 'note' ORDER BY id",
        )
        .await
        .unwrap();
        assert_eq!(first_strings(&alice_rows), [ALICE_PRIVATE_ID, COMMON_ID]);
        let bea_rows = query_sql(
            &db,
            &bea,
            "SELECT id FROM records WHERE kind = 'note' ORDER BY id",
        )
        .await
        .unwrap();
        assert_eq!(first_strings(&bea_rows), [BEA_PRIVATE_ID, COMMON_ID]);
        let kindless_document = query_sql(
            &db,
            &alice,
            &format!("SELECT id FROM records WHERE id = '{KINDLESS_BEARER_ALICE_ID}'"),
        )
        .await
        .unwrap();
        assert_eq!(
            first_strings(&kindless_document),
            [KINDLESS_BEARER_ALICE_ID]
        );
        let alice_artifacts = query_sql(
            &db,
            &alice,
            &format!("SELECT id FROM records WHERE id LIKE '{ARTIFACT_ID_PREFIX}%' ORDER BY id"),
        )
        .await
        .unwrap();
        assert_eq!(
            first_strings(&alice_artifacts),
            [ARTIFACT_HIDDEN_BEARER_ID, ARTIFACT_KINDLESS_BEARER_ID]
        );
        let bea_artifacts = query_sql(
            &db,
            &bea,
            &format!("SELECT id FROM records WHERE id LIKE '{ARTIFACT_ID_PREFIX}%' ORDER BY id"),
        )
        .await
        .unwrap();
        assert_eq!(first_strings(&bea_artifacts), [ARTIFACT_VISIBLE_BEARER_ID]);
        let count = query_sql(
            &db,
            &bea,
            "SELECT CAST(count(*) AS TEXT) AS n FROM records WHERE kind = 'note'",
        )
        .await
        .unwrap();
        assert_eq!(first_strings(&count), ["2"]);
        let alice_links = query_sql(
            &db,
            &alice,
            "SELECT id FROM links WHERE relationship = 'mentions' ORDER BY id",
        )
        .await
        .unwrap();
        assert_eq!(first_strings(&alice_links), ["alice-common"]);
        let bea_links = query_sql(
            &db,
            &bea,
            "SELECT id FROM links WHERE relationship = 'mentions' ORDER BY id",
        )
        .await
        .unwrap();
        assert_eq!(first_strings(&bea_links), ["common-bea"]);
        let alice_bindings = query_sql(
            &db,
            &alice,
            "SELECT system || ':' || identifier AS binding FROM bindings ORDER BY binding",
        )
        .await
        .unwrap();
        assert_eq!(
            first_strings(&alice_bindings),
            ["account:alice", "email:alice@example.test"]
        );
        let bea_bindings = query_sql(
            &db,
            &bea,
            "SELECT system || ':' || identifier AS binding FROM bindings ORDER BY binding",
        )
        .await
        .unwrap();
        assert_eq!(
            first_strings(&bea_bindings),
            ["account:bea", "email:bea@example.test"]
        );
        let alice_blobs = query_sql(
            &db,
            &alice,
            "SELECT original_filename FROM blobs ORDER BY 1",
        )
        .await
        .unwrap();
        assert_eq!(
            first_strings(&alice_blobs),
            [
                format!("{ATTACHMENT_ALICE_ID}.txt"),
                format!("{ATTACHMENT_COMMON_ID}.txt")
            ]
        );
        let bea_blobs = query_sql(&db, &bea, "SELECT original_filename FROM blobs ORDER BY 1")
            .await
            .unwrap();
        assert_eq!(
            first_strings(&bea_blobs),
            [format!("{ATTACHMENT_COMMON_ID}.txt")]
        );
        for relation in ["content_events", "facet_values", "facet_observations"] {
            let statement =
                format!("SELECT record_id FROM {relation} WHERE record_id = '{TOMBSTONE_ID}'");
            assert!(query_sql(&db, &alice, &statement)
                .await
                .unwrap()
                .rows
                .is_empty());
        }
        assert!(principal_context_is_empty(&db).await.unwrap());
    }

    #[test]
    fn dual_prepare_rejects_every_raw_qualified_and_spoofed_route() {
        let raw = [
            "records",
            "content_events",
            "policy_events",
            "control_events",
            "links",
            "facet_values",
            "facet_observations",
            "bindings",
            "blobs",
            "record_policies",
            "policy_entries",
            "member_contexts",
            "instruction_bindings",
            "onboarding_programmes",
            "onboarding_programme_sources",
            "member_obligations",
            "member_obligation_progress",
            "seeded_instruction_sources",
            "control_event_applications",
            "records_fts",
            "records_name_idx",
            "embeddings",
            "meta_events",
            "jobs",
            "annotation_targets",
            "read_log_calls",
            "read_log_touches",
        ];
        for relation in raw {
            for statement in [
                format!("SELECT * FROM main.{relation}"),
                format!("SELECT raw.* FROM main.{relation} AS raw"),
                format!("WITH stolen AS (SELECT * FROM main.{relation}) SELECT * FROM stolen"),
            ] {
                assert!(
                    validate(&statement).is_err(),
                    "unexpectedly admitted {statement}"
                );
            }
        }
        for statement in [
            "SELECT * FROM temp._query_sql_principal",
            "SELECT * FROM sqlite_master",
            "WITH records AS (SELECT * FROM main.records) SELECT * FROM records",
            "SELECT * FROM pragma_table_info('records')",
            "SELECT * FROM records_fts_data",
        ] {
            assert!(
                validate(statement).is_err(),
                "unexpectedly admitted {statement}"
            );
        }
        for statement in [
            "SELECT randomblob(1000000000)",
            "SELECT zeroblob(1000000000)",
            "SELECT printf('%1000000000s', 'x')",
            "SELECT json_group_array(body) FROM records",
            "SELECT load_extension('anything')",
        ] {
            assert!(
                validate(statement).is_err(),
                "unexpectedly admitted unsafe function in {statement}"
            );
        }
        for statement in [
            "SELECT id FROM records",
            "SELECT e.id FROM content_events e JOIN records r ON r.id=e.record_id",
            "WITH visible AS (SELECT id FROM records) SELECT count(*) FROM visible",
            "SELECT id FROM vocabularies",
            "SELECT id FROM schema_config",
        ] {
            validate(statement).unwrap_or_else(|error| panic!("{statement}: {error}"));
        }
    }

    #[tokio::test]
    async fn sql_input_cells_and_cumulative_results_are_bounded_and_discard_cleanly() {
        let (db, alice, bea) = protected_fixture().await;
        for (id, body) in [
            (OVERSIZE_CELL_ID, "x".repeat(MAX_CELL_ENCODED_BYTES + 1)),
            (REPEATED_BYTES_ID, "y".repeat(32 * 1024)),
        ] {
            create_record(
                &db,
                json!({
                    "id": id,
                    "type": "Document",
                    "kind": "note",
                    "name": id,
                    "body": body,
                    "home_id": crate::schema::ROOT_RECORD_ID
                }),
            )
            .await
            .unwrap();
            replace_explicit_policy(
                &db,
                "test:policy",
                id,
                vec![AllowEntry::account("alice", Capability::View)],
            )
            .await
            .unwrap();
        }

        let too_long = format!("SELECT id FROM records --{}", "x".repeat(MAX_SQL_BYTES));
        assert!(query_sql(&db, &alice, &too_long).await.is_err());
        for statement in [
            "SELECT randomblob(1000000000)",
            "SELECT zeroblob(1000000000)",
        ] {
            assert!(query_sql(&db, &alice, statement).await.is_err());
        }

        // Pin all work to one available slot. Both breaches must discard the
        // physical connection and leave its replacement clean for Bea.
        let mut held = Vec::new();
        for _ in 0..4 {
            held.push(db.write_pool().acquire().await.unwrap());
        }
        assert!(query_sql(
            &db,
            &alice,
            &format!("SELECT body FROM records WHERE id = '{OVERSIZE_CELL_ID}'"),
        )
        .await
        .is_err());
        let after_cell = query_sql(
            &db,
            &bea,
            &format!("SELECT id FROM records WHERE id LIKE '%{PRIVATE_ID_SUFFIX}'"),
        )
        .await
        .unwrap();
        assert_eq!(first_strings(&after_cell), [BEA_PRIVATE_ID]);

        assert!(query_sql(
            &db,
            &alice,
            &format!("SELECT min(body) FROM records WHERE id = '{OVERSIZE_CELL_ID}'"),
        )
        .await
        .is_err());
        let after_function = query_sql(
            &db,
            &bea,
            &format!("SELECT id FROM records WHERE id LIKE '%{PRIVATE_ID_SUFFIX}'"),
        )
        .await
        .unwrap();
        assert_eq!(first_strings(&after_function), [BEA_PRIVATE_ID]);

        assert!(query_sql(
            &db,
            &alice,
            &format!(
                "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x < 200)
                 SELECT body FROM records, n WHERE id = '{REPEATED_BYTES_ID}'"
            ),
        )
        .await
        .is_err());
        let after_total = query_sql(
            &db,
            &bea,
            &format!("SELECT id FROM records WHERE id LIKE '%{PRIVATE_ID_SUFFIX}'"),
        )
        .await
        .unwrap();
        assert_eq!(first_strings(&after_total), [BEA_PRIVATE_ID]);
        assert!(principal_context_is_empty(&db).await.unwrap());
        drop(held);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn one_thousand_interleaved_and_forced_single_connection_reuse_isolate_callers() {
        let (db, alice, bea) = protected_fixture().await;
        let observations = stream::iter(0..1_000usize)
            .map(|index| {
                let db = db.clone();
                let caller = if index % 2 == 0 {
                    alice.clone()
                } else {
                    bea.clone()
                };
                async move {
                    let expected = if index % 2 == 0 {
                        ALICE_PRIVATE_ID
                    } else {
                        BEA_PRIVATE_ID
                    };
                    let result = query_sql_owned(
                        db,
                        caller,
                        format!("SELECT id FROM records WHERE id LIKE '%{PRIVATE_ID_SUFFIX}'"),
                    )
                    .await
                    .unwrap();
                    (expected.to_string(), first_strings(&result))
                }
            })
            // Stay above the five-connection pool so requests must queue and
            // reuse physical connections, while leaving the full parallel
            // suite's scheduler load out of SQLx's 30-second acquire timeout.
            .buffer_unordered(8)
            .collect::<Vec<_>>()
            .await;
        for (expected, actual) in observations {
            assert_eq!(actual, [expected]);
        }

        // Hold four of the five pooled connections: every alternation below
        // must reuse the one remaining physical connection.
        let mut held = Vec::new();
        for _ in 0..4 {
            held.push(db.write_pool().acquire().await.unwrap());
        }
        for index in 0..100 {
            let (caller, expected) = if index % 2 == 0 {
                (&alice, ALICE_PRIVATE_ID)
            } else {
                (&bea, BEA_PRIVATE_ID)
            };
            let result = query_sql(
                &db,
                caller,
                &format!("SELECT id FROM records WHERE id LIKE '%{PRIVATE_ID_SUFFIX}'"),
            )
            .await
            .unwrap();
            assert_eq!(first_strings(&result), [expected]);
        }
        assert!(principal_context_is_empty(&db).await.unwrap());
        drop(held);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancellation_and_deadline_cannot_poison_or_indefinitely_delay_reuse() {
        let (db, alice, bea) = protected_fixture().await;
        let mut held = Vec::new();
        for _ in 0..4 {
            held.push(db.write_pool().acquire().await.unwrap());
        }

        // Force an unwind after principal installation and progress-handler
        // registration on the sole available physical connection. Transaction
        // drop queues rollback; pool release must remove every connection-local
        // remnant before Bea can borrow it.
        let panic_result = std::panic::AssertUnwindSafe(async {
            let mut connection = db.write_pool().acquire().await.unwrap();
            let contract = temp_contract();
            for statement in contract.split(';').map(str::trim).filter(|s| !s.is_empty()) {
                sqlx::query(statement)
                    .execute(&mut *connection)
                    .await
                    .unwrap();
            }
            sqlx::query("DELETE FROM temp._query_sql_principal")
                .execute(&mut *connection)
                .await
                .unwrap();
            let mut transaction = connection.begin().await.unwrap();
            sqlx::query(
                "INSERT INTO temp._query_sql_principal(singleton, account_id, trusted_local_bypass, activity_read, observed_at)
                 VALUES (1, 'alice', 0, 0, '2026-08-31T00:00:00.000Z')",
            )
            .execute(&mut *transaction)
            .await
            .unwrap();
            {
                let mut handle = transaction.lock_handle().await.unwrap();
                handle.set_progress_handler(PROGRESS_OPS, || true);
            }
            panic!("synthetic query handler unwind");
        })
        .catch_unwind()
        .await;
        assert!(panic_result.is_err());
        let after_unwind = query_sql(
            &db,
            &bea,
            &format!("SELECT id FROM records WHERE id LIKE '%{PRIVATE_ID_SUFFIX}'"),
        )
        .await
        .unwrap();
        assert_eq!(first_strings(&after_unwind), [BEA_PRIVATE_ID]);
        assert!(principal_context_is_empty(&db).await.unwrap());

        let runaway = query_sql_owned(
            db.clone(),
            alice,
            "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x < 5000000000) SELECT sum(x) AS n FROM n".into(),
        );
        assert!(tokio::time::timeout(Duration::from_millis(5), runaway)
            .await
            .is_err());
        let started = Instant::now();
        let result = query_sql(
            &db,
            &bea,
            &format!("SELECT id FROM records WHERE id LIKE '%{PRIVATE_ID_SUFFIX}'"),
        )
        .await
        .unwrap();
        assert_eq!(first_strings(&result), [BEA_PRIVATE_ID]);
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(principal_context_is_empty(&db).await.unwrap());
        drop(held);
    }

    #[tokio::test]
    async fn agent_activity_and_claims_enforce_authority_lifecycle_and_visibility() {
        let (db, alice, bea) = protected_fixture().await;
        for (account, person, root) in [
            ("alice", ALICE_PRIVATE_ID, ALICE_PRIVATE_ID),
            ("bea", BEA_PRIVATE_ID, BEA_PRIVATE_ID),
        ] {
            sqlx::query(
                "INSERT INTO member_contexts(account_id,person_record_id,root_record_id,created_at)
                 VALUES(?,?,?,'2026-08-31T00:00:00.000Z')",
            )
            .bind(account)
            .bind(person)
            .bind(root)
            .execute(db.write_pool())
            .await
            .unwrap();
        }

        let current_run = "scout-chair-a748b2";
        let stale_run = "scout-chair-b748b2";
        let current = crate::control::ensure_agent_run(&db, current_run, "alice")
            .await
            .unwrap();
        let stale = crate::control::ensure_agent_run(&db, stale_run, "alice")
            .await
            .unwrap();
        assert_ne!(current.activity_id, stale.activity_id);

        // A credential supplied to the public query API cannot self-assert
        // activity.read. The transport-established member authority is a
        // separate, unsafe construction seam.
        let unauthorized = query_sql(&db, &alice, "SELECT run_key FROM agent_activity")
            .await
            .unwrap();
        assert_eq!(unauthorized.row_count, 0);
        // SAFETY: exercising the transport-only bit without a live membership
        // demonstrates that database admission remains independently required.
        let departed = unsafe { QueryPrincipal::activity_reader_unchecked("departed", Vec::new()) };
        assert_eq!(
            query_sql(&db, &departed, "SELECT run_key FROM agent_activity")
                .await
                .unwrap()
                .row_count,
            0
        );
        // SAFETY: this test models the authenticated hosted ingress after it
        // has admitted Bea's live member context; no SQL argument controls it.
        let bea_activity = unsafe {
            QueryPrincipal::activity_reader_unchecked(
                "bea",
                vec![
                    crate::query::principal::ActivityRosterMember::verified_unchecked(
                        "alice",
                        "native:workspace-member:alice",
                    ),
                    crate::query::principal::ActivityRosterMember::verified_unchecked(
                        "bea",
                        "native:workspace-member:bea",
                    ),
                ],
            )
        };
        let two_runs = query_sql(
            &db,
            &bea_activity,
            "SELECT activity_id,run_key,principal_ref,principal_display_name FROM agent_activity ORDER BY activity_id",
        )
        .await
        .unwrap()
        ;
        assert_eq!(two_runs.row_count, 2);
        let mut visible_run_keys = two_runs
            .rows
            .iter()
            .map(|row| row["run_key"].as_str().unwrap())
            .collect::<Vec<_>>();
        visible_run_keys.sort_unstable();
        assert_eq!(visible_run_keys, [current_run, stale_run]);
        assert!(two_runs
            .rows
            .iter()
            .all(|row| row["principal_ref"] == "native:workspace-member:alice"));
        assert!(two_runs
            .rows
            .iter()
            .all(|row| row["principal_display_name"].is_null()));

        // Portable member_contexts survive hosted offboarding. A current
        // roster that omits Alice must therefore suppress her lifecycle even
        // while that stale projection remains in the workspace file.
        let bea_after_alice_departed = unsafe {
            QueryPrincipal::activity_reader_unchecked(
                "bea",
                vec![
                    crate::query::principal::ActivityRosterMember::verified_unchecked(
                        "bea",
                        "native:workspace-member:bea",
                    ),
                ],
            )
        };
        assert_eq!(
            query_sql(
                &db,
                &bea_after_alice_departed,
                "SELECT run_key FROM agent_activity",
            )
            .await
            .unwrap()
            .row_count,
            0
        );

        // The inference clock is execution-owned: advancing only observed_at
        // flips appears_active while every factual timestamp stays byte-stable.
        let started = chrono::DateTime::parse_from_rfc3339(&current.started_at).unwrap();
        let within = (started + chrono::Duration::minutes(4))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let expired = (started + chrono::Duration::minutes(6))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let mut clock_connection = db.write_pool().acquire().await.unwrap();
        for statement in temp_contract()
            .split(';')
            .map(str::trim)
            .filter(|statement| !statement.is_empty())
        {
            sqlx::query(statement)
                .execute(&mut *clock_connection)
                .await
                .unwrap();
        }
        sqlx::query(
            "INSERT OR REPLACE INTO temp._query_sql_principal
             (singleton,account_id,trusted_local_bypass,activity_read,observed_at)
             VALUES (1,'bea',0,1,?)",
        )
        .bind(&within)
        .execute(&mut *clock_connection)
        .await
        .unwrap();
        sqlx::query(
            "INSERT OR REPLACE INTO temp._query_sql_activity_members(account_id,member_ref)
             VALUES ('alice','native:workspace-member:alice'),
                    ('bea','native:workspace-member:bea')",
        )
        .execute(&mut *clock_connection)
        .await
        .unwrap();
        let fresh: (String, String, Option<String>, i64) = sqlx::query_as(
            "SELECT started_at,last_observed_activity_at,ended_at,appears_active
               FROM temp.agent_activity WHERE activity_id=?",
        )
        .bind(&current.activity_id)
        .fetch_one(&mut *clock_connection)
        .await
        .unwrap();
        sqlx::query("UPDATE temp._query_sql_principal SET observed_at=? WHERE singleton=1")
            .bind(&expired)
            .execute(&mut *clock_connection)
            .await
            .unwrap();
        let expired_row: (String, String, Option<String>, i64) = sqlx::query_as(
            "SELECT started_at,last_observed_activity_at,ended_at,appears_active
               FROM temp.agent_activity WHERE activity_id=?",
        )
        .bind(&current.activity_id)
        .fetch_one(&mut *clock_connection)
        .await
        .unwrap();
        assert_eq!(
            (&fresh.0, &fresh.1, &fresh.2),
            (&expired_row.0, &expired_row.1, &expired_row.2)
        );
        assert_eq!((fresh.3, expired_row.3), (1, 0));
        drop(clock_connection);

        // An inactive run older than the fixed observation window disappears;
        // explicit closure remains visible but can never appear active.
        sqlx::query(
            "UPDATE agent_runs SET started_at='2020-01-01T00:00:00.000Z' WHERE activity_id=?",
        )
        .bind(&stale.activity_id)
        .execute(db.write_pool())
        .await
        .unwrap();
        sqlx::query(
            "UPDATE agent_runs
                SET started_at=strftime('%Y-%m-%dT%H:%M:%fZ','now','-10 minutes')
              WHERE activity_id=?",
        )
        .bind(&current.activity_id)
        .execute(db.write_pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO read_log_calls
             (id,tool,run_key,actor,outcome,started_at,ended_at)
             VALUES ('cross-account-spoof','get_dashboard',?,'bea','ok',
                     strftime('%Y-%m-%dT%H:%M:%fZ','now','-1 minute'),
                     strftime('%Y-%m-%dT%H:%M:%fZ','now','-1 minute'))",
        )
        .bind(current_run)
        .execute(db.write_pool())
        .await
        .unwrap();
        let lifecycle = query_sql(
            &db,
            &bea_activity,
            "SELECT activity_id,ended_at,appears_active FROM agent_activity ORDER BY activity_id",
        )
        .await
        .unwrap();
        assert_eq!(lifecycle.row_count, 1);
        assert_eq!(lifecycle.rows[0]["activity_id"], current.activity_id);
        assert!(lifecycle.rows[0]["ended_at"].is_null());
        assert_eq!(
            lifecycle.rows[0]["appears_active"], 0,
            "a different account cannot refresh an admitted run by reusing its key"
        );

        let presence_sql =
            "SELECT activity_id,ended_at,appears_active FROM agent_activity ORDER BY activity_id";
        let (before_claims, before_claim_receipt) =
            governed_query(&db, bea_activity.clone(), presence_sql).await;
        replace_explicit_policy(
            &db,
            "test:activity-policy",
            ALICE_PRIVATE_ID,
            vec![AllowEntry::account("alice", Capability::Edit)],
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:activity-policy",
            COMMON_ID,
            vec![
                AllowEntry::account("alice", Capability::Edit),
                AllowEntry::account("bea", Capability::View),
            ],
        )
        .await
        .unwrap();
        let mut registry = crate::mcp::ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut registry).unwrap();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        let claim = |record_id: &str, action: &str| {
            json!({
                "record_id": record_id,
                "action": action,
                "run_key": current_run,
            })
        };
        registry
            .call(
                db.clone(),
                crate::mcp::Caller::authenticated("alice"),
                "start_work",
                claim(ALICE_PRIVATE_ID, "claim"),
            )
            .await
            .unwrap();
        let (after_hidden_claim, after_hidden_claim_receipt) =
            governed_query(&db, bea_activity.clone(), presence_sql).await;
        assert_eq!(after_hidden_claim.rows, before_claims.rows);
        assert_eq!(after_hidden_claim.row_count, before_claims.row_count);
        assert_eq!(
            after_hidden_claim.rows[0]["activity_id"],
            current.activity_id
        );
        assert_eq!(
            (
                after_hidden_claim_receipt.content_event_seq,
                after_hidden_claim_receipt.lifecycle_event_seq,
                &after_hidden_claim_receipt.authorization_boundary,
                after_hidden_claim_receipt.transient_watermark,
                after_hidden_claim_receipt.transient_available,
            ),
            (
                before_claim_receipt.content_event_seq,
                before_claim_receipt.lifecycle_event_seq,
                &before_claim_receipt.authorization_boundary,
                before_claim_receipt.transient_watermark,
                before_claim_receipt.transient_available,
            ),
            "a hidden claim must not perturb the presence receipt; observed_at is execution-owned"
        );

        // Changing only record visibility changes the claims join, never the
        // already-admitted presence bytes.
        replace_explicit_policy(
            &db,
            "test:activity-policy",
            ALICE_PRIVATE_ID,
            vec![
                AllowEntry::account("alice", Capability::Edit),
                AllowEntry::account("bea", Capability::View),
            ],
        )
        .await
        .unwrap();
        let after_unhide = query_sql(
            &db,
            &bea_activity,
            "SELECT activity_id,ended_at,appears_active FROM agent_activity ORDER BY activity_id",
        )
        .await
        .unwrap();
        assert_eq!(after_unhide.rows, after_hidden_claim.rows);
        assert_eq!(
            query_sql(
                &db,
                &bea_activity,
                "SELECT claim_id FROM agent_activity_claims ORDER BY claim_id",
            )
            .await
            .unwrap()
            .row_count,
            1
        );
        replace_explicit_policy(
            &db,
            "test:activity-policy",
            ALICE_PRIVATE_ID,
            vec![AllowEntry::account("alice", Capability::Edit)],
        )
        .await
        .unwrap();
        let after_rehide = query_sql(
            &db,
            &bea_activity,
            "SELECT activity_id,ended_at,appears_active FROM agent_activity ORDER BY activity_id",
        )
        .await
        .unwrap();
        assert_eq!(after_rehide.rows, after_hidden_claim.rows);

        registry
            .call(
                db.clone(),
                crate::mcp::Caller::authenticated("alice"),
                "start_work",
                claim(COMMON_ID, "claim"),
            )
            .await
            .unwrap();
        let visible_claim: String = sqlx::query_scalar(
            "SELECT id FROM content_events WHERE record_id=? AND type='record.updated'
             AND json_type(payload,'$.claimed_by_account')='text' ORDER BY seq DESC LIMIT 1",
        )
        .bind(COMMON_ID)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        registry
            .call(
                db.clone(),
                crate::mcp::Caller::authenticated("alice"),
                "start_work",
                claim(COMMON_ID, "release"),
            )
            .await
            .unwrap();

        let claims = query_sql(
            &db,
            &bea_activity,
            "SELECT claim_id,activity_id,record_id,claimed_at,released_at,is_current FROM agent_activity_claims ORDER BY claim_id",
        )
        .await
        .unwrap();
        assert_eq!(claims.row_count, 1, "Alice's private claim must be absent");
        assert_eq!(claims.rows[0]["claim_id"], visible_claim);
        assert_eq!(claims.rows[0]["activity_id"], current.activity_id);
        assert_eq!(claims.rows[0]["record_id"], COMMON_ID);
        assert!(claims.rows[0]["released_at"].is_string());
        assert_eq!(claims.rows[0]["is_current"], 0);

        // Claim/release are admitted activity, but cannot perturb presence
        // membership or ordering.
        let after_claims = query_sql(
            &db,
            &bea_activity,
            "SELECT activity_id,ended_at,appears_active FROM agent_activity ORDER BY activity_id",
        )
        .await
        .unwrap();
        assert_eq!(after_claims.row_count, before_claims.row_count);
        assert_eq!(after_claims.rows[0]["activity_id"], current.activity_id);

        crate::control::close_agent_run(&db, current_run, "alice")
            .await
            .unwrap();
        let closed = query_sql(
            &db,
            &bea_activity,
            "SELECT activity_id,ended_at,appears_active FROM agent_activity ORDER BY activity_id",
        )
        .await
        .unwrap();
        assert!(closed.rows[0]["ended_at"].is_string());
        assert_eq!(closed.rows[0]["appears_active"], 0);
        let post_close_claim = registry
            .call(
                db.clone(),
                crate::mcp::Caller::authenticated("alice"),
                "start_work",
                claim(COMMON_ID, "claim"),
            )
            .await
            .unwrap_err();
        assert!(post_close_claim.to_string().contains("run is closed"));

        sqlx::query("ALTER TABLE read_log_calls RENAME TO read_log_calls_unavailable")
            .execute(db.write_pool())
            .await
            .unwrap();
        let durable_only = query_sql(
            &db,
            &bea_activity,
            "SELECT activity_id,ended_at,appears_active FROM agent_activity ORDER BY activity_id",
        )
        .await
        .unwrap();
        assert_eq!(durable_only.rows, closed.rows);

        // Preserve the fixture's ordinary caller-relative assertions elsewhere.
        assert_eq!(bea.credential(), "bea");
    }

    #[tokio::test]
    async fn same_transaction_executor_removes_every_temp_object_after_success_and_error() {
        let (db, alice, _) = protected_fixture().await;
        let mut connection = db.write_pool().acquire().await.unwrap();
        let mut tx = connection.begin().await.unwrap();
        query_sql_request_in(
            &mut tx,
            alice.clone(),
            QuerySqlRequest {
                sql: "SELECT id FROM records ORDER BY id LIMIT 1".into(),
                parameters: vec![],
            },
        )
        .await
        .unwrap();
        const TEMP_COUNT_SQL: &str = "SELECT COUNT(*) FROM sqlite_temp_master WHERE name LIKE '_query_sql_%' OR name IN ('records','content_events','links','facet_values','facet_observations','bindings','blobs','vocabularies','vocabulary_values','schema_config','effective_relationships','agent_activity','agent_activity_claims','messages_awaiting_reply')";
        let count: i64 = sqlx::query_scalar(TEMP_COUNT_SQL)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(count, 0);
        let error = query_sql_request_in(
            &mut tx,
            alice,
            QuerySqlRequest {
                sql: "SELECT abs(-9223372036854775808) AS overflow".into(),
                parameters: vec![],
            },
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("integer overflow"), "{error}");
        let count: i64 = sqlx::query_scalar(TEMP_COUNT_SQL)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(count, 0);
        tx.rollback().await.unwrap();
    }
}
