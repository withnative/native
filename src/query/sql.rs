//! Caller-filtered, validated read-only SQL (tool 18, `query_sql`).
//!
//! User SQL never reaches a physical content or policy relation. Every call is
//! prepared twice against the public logical contract, then executed on one
//! explicitly acquired connection from the dedicated governed-SQL pool whose
//! portable principal exists only inside a rolled-back transaction. The TEMP
//! schema is connection-local; pool release removes both principal state and
//! the progress handler. The governed pool is never shared with ordinary
//! writes or with the physically read-only observation tier, so a burst of
//! governed reads can saturate only its own bounded slots — never the
//! writer's connections — and retained TEMP state there cannot shadow the
//! unqualified names `bootstrap` and `get_structure` rely on.

use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::sync::OnceLock;
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

const CONTROLLED_ACCESSORS: [&str; 22] = [
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
    "_query_sql_activity_capture",
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
/// Failure-path SQLITE_TOOBIG probe only. Twelve named rows bounds the
/// error while leaving headroom above the exclusion hint's 10-id display
/// cap, so the "(first 10 of N oversized rows)" count is reachable through
/// the wired path. 16384
/// candidate rowids covers the live workspace (~4.5k records) with headroom.
/// 500ms is well under QUERY_DEADLINE_MS so the probe cannot consume the
/// caller's budget; incremental blob reads never copy the oversized payload.
const MAX_TOOBIG_NAMED: usize = 12;
const MAX_TOOBIG_PROBE_ROWS: i64 = 16_384;
const TOOBIG_PROBE_BUDGET: Duration = Duration::from_millis(500);

/// A single governed visibility evaluation and its database snapshot fences.
/// The caller may intersect these ids with an index only when all fences match.
/// The set is reference-counted so cache hits share it without copying.
pub(crate) struct WorkspaceVisibleSet {
    pub ids: std::sync::Arc<HashSet<String>>,
    pub content_seq: i64,
    pub relationship_seq: i64,
    pub authorization_epoch: i64,
    pub unit_seq_max: i64,
}

/// Evaluate the same private visibility view that backs governed `query_sql`.
/// No caller SQL, row cap, or second authorization algorithm is involved.
pub(crate) async fn workspace_visible_set(
    db: &Db,
    principal: QueryPrincipal,
) -> Result<WorkspaceVisibleSet> {
    let mut connection = db.governed_pool().acquire().await?;
    for statement in temp_contract()
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if let Err(error) = sqlx::query(statement).execute(&mut *connection).await {
            connection.close_on_drop();
            return Err(error.into());
        }
    }
    // Clearing outside the transaction prevents rollback from restoring an
    // earlier principal on a reused governed connection.
    if let Err(error) = sqlx::query("DELETE FROM temp._query_sql_principal")
        .execute(&mut *connection)
        .await
    {
        connection.close_on_drop();
        return Err(error.into());
    }
    let mut tx = connection.begin().await?;
    let result: Result<WorkspaceVisibleSet> = async {
        // Fix the main database snapshot before installing request-local state.
        let content_seq: i64 =
            sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM main.content_events")
                .fetch_one(&mut *tx)
                .await?;
        let relationship_seq: i64 =
            sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM main.relationship_events")
                .fetch_one(&mut *tx)
                .await?;
        let authorization_epoch: i64 =
            sqlx::query_scalar("SELECT epoch FROM main.authorization_revision WHERE id = 1")
                .fetch_one(&mut *tx)
                .await?;
        // Second fence (Tier 1.4, record fd6c1f2): unit-created projections
        // move the visible set without moving the epoch, so the key carries
        // both. The UNIQUE index makes this one cheap scalar probe in the
        // same snapshot as the evaluation below.
        let unit_seq_max: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(creation_event_seq), 0) FROM main.semantic_units",
        )
        .fetch_one(&mut *tx)
        .await?;
        let cache_key = crate::visible_set_cache::VisibleSetCacheKey {
            credential: principal.credential().to_string(),
            trusted_local_bypass: principal.trusted_local_bypass(),
            activity_read: principal.activity_read(),
            is_member: principal.is_member(),
            authorization_epoch,
            unit_seq_max,
        };
        if let Some(ids) = db.visible_set_cache_get(&cache_key) {
            crate::mcp::request_timing::record_visible_set_lookup(true);
            // Hit: fences match, so the stored set equals a fresh evaluation;
            // content/relationship stamps are current by construction. M2's
            // own live-triple gate still applies downstream.
            return Ok(WorkspaceVisibleSet {
                ids,
                content_seq,
                relationship_seq,
                authorization_epoch,
                unit_seq_max,
            });
        }
        crate::mcp::request_timing::record_visible_set_lookup(false);
        db.visible_set_cache_record_miss();
        sqlx::query(
            "INSERT INTO temp._query_sql_principal \
             (singleton, account_id, trusted_local_bypass, activity_read, is_member, observed_at) \
             VALUES (1, ?, ?, ?, ?, ?)",
        )
        .bind(principal.credential())
        .bind(principal.trusted_local_bypass())
        .bind(principal.activity_read())
        .bind(principal.is_member())
        .bind(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        .execute(&mut *tx)
        .await?;
        let mut ids = HashSet::new();
        let mut rows =
            sqlx::query("SELECT id FROM temp._query_sql_visible_records").fetch(&mut *tx);
        while let Some(row) = rows.try_next().await? {
            ids.insert(row.try_get(0)?);
        }
        let evaluated = WorkspaceVisibleSet {
            ids: std::sync::Arc::new(ids),
            content_seq,
            relationship_seq,
            authorization_epoch,
            unit_seq_max,
        };
        // Refusal keeps the just-computed live answer; the cache never holds
        // a subset. Rollback below affects connection reuse, not the reads
        // above, so storing before it is sound.
        db.visible_set_cache_insert(cache_key, evaluated.ids.clone());
        Ok(evaluated)
    }
    .await;
    let rollback = tx.rollback().await;
    if result.is_err() || rollback.is_err() {
        connection.close_on_drop();
    }
    rollback?;
    result
}

/// Deliberately conservative: every callable function is denied unless it is
/// in the shared portable subset (`sql_contract::is_portable_function`,
/// plus function-form `like`), whose output is intrinsically small or a
/// familiar numeric/min/max aggregate. The SQLite runtime value ceiling is
/// still mandatory for min/max over text. Operators and CAST remain
/// available. Dropped names never reach the authorizer: the classifier
/// rejects them first with the portable replacement, so a deny here means
/// an unknown function. Blob constructors, other value-returning
/// string/JSON/window functions, concatenating aggregates, extension
/// loaders, and introspection helpers never prepare.
/// The connection-local contract. `_query_sql_visible_records` is an internal
/// helper, absent from the strict public schema, so caller SQL cannot name it.
/// A routed credential resolves with its folded catalog footing for this
/// request; membership alone matters only when the explicit anchor grants
/// `native:members`, and guests never match that subject.
const TEMP_CONTRACT: &str = r#"
CREATE TEMP TABLE IF NOT EXISTS _query_sql_principal (
  singleton           INTEGER PRIMARY KEY CHECK (singleton = 1),
  account_id          TEXT NOT NULL,
  trusted_local_bypass INTEGER NOT NULL CHECK (trusted_local_bypass IN (0, 1)),
  activity_read        INTEGER NOT NULL CHECK (activity_read IN (0, 1)),
  is_member            INTEGER NOT NULL CHECK (is_member IN (0, 1)),
  observed_at         TEXT NOT NULL
);
CREATE TEMP TABLE IF NOT EXISTS _query_sql_messages_awaiting_reply (
  message_id TEXT PRIMARY KEY
);
CREATE TEMP TABLE IF NOT EXISTS _query_sql_activity_observations (
  run_key TEXT PRIMARY KEY,
  last_observed_at TEXT NOT NULL,
  declared_intent TEXT
);
-- Whether the disposable read-log capture contributed to this observation.
-- The activity helper sets exactly one row per governed execution. Zero means
-- the `read_log_calls` table was absent. A standby export strips read-log
-- rows but keeps the tables, so a stripped-but-present read log still reads
-- one and its empty rows report `none`, not `unavailable`. That conflation is
-- a known gap, closing it needs a durable capture-removed signal the export
-- writes, and table existence cannot carry it. The `agent_activity` view reads
-- this flag to report an unavailable disclosure state rather than a silent
-- empty column, and `unavailable` shadows `withheld` by design, since there
-- is nothing to withhold when capture contributed nothing
CREATE TEMP TABLE IF NOT EXISTS _query_sql_activity_capture (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  available INTEGER NOT NULL CHECK (available IN (0, 1))
);
CREATE TEMP TABLE IF NOT EXISTS _query_sql_activity_members (
  account_id TEXT PRIMARY KEY,
  member_ref TEXT NOT NULL UNIQUE
);
-- Claim and claim-clear candidate rows, populated by the engine-owned
-- prepared step before the caller value ceiling is lowered (same precedent
-- as `_query_sql_activity_observations`). The claims view reads only these
-- narrow projected columns and never opens `content_events.payload`, so an
-- over-limit payload cannot fail the relation however the planner orders the
-- view. Shape matching happens once at population time at the full limit.
-- TEMP_CONTRACT statements are split on semicolons by the installers, so no
-- comment in this contract may contain one.
CREATE TEMP TABLE IF NOT EXISTS _query_sql_claim_candidates (
  seq INTEGER PRIMARY KEY,
  claim_id TEXT NOT NULL,
  record_id TEXT NOT NULL,
  run_key TEXT,
  claim_actor TEXT,
  claimed_by_account TEXT,
  claimed_at TEXT NOT NULL
);
CREATE TEMP TABLE IF NOT EXISTS _query_sql_claim_releases (
  seq INTEGER PRIMARY KEY,
  record_id TEXT NOT NULL,
  actor TEXT NOT NULL,
  created_at TEXT NOT NULL
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
    -- Per-anchor decision: the caller-visible anchor set depends only on the
    -- principal row, so it is computed once per statement and probed per
    -- record, instead of re-matching all of the caller's entries for every
    -- record. Membership is unchanged: for a non-null anchor this admits
    -- exactly the anchors the former correlated EXISTS matched, and a null
    -- anchor admits nothing under either form
    OR authorization_subject.policy_anchor_id IN (
         SELECT entry.policy_anchor_id
         FROM main.policy_entries AS entry
         CROSS JOIN temp._query_sql_principal AS anchor_principal
         WHERE entry.effect = 'allow'
           AND entry.capability IN ('view', 'edit', 'manage')
           AND (
             (entry.subject_kind = 'members'
              AND entry.subject_id = 'native:members'
              AND anchor_principal.is_member = 1)
             OR
             (entry.subject_kind = 'account'
              AND entry.subject_id = anchor_principal.account_id)
           )
       )));

CREATE TEMP VIEW IF NOT EXISTS records AS
SELECT r.id, r.type, r.kind, r.name, r.body,
       CASE WHEN parent_visible.id IS NULL THEN NULL ELSE r.home_id END AS home_id,
       r.lifecycle, r.persistence, r.maturity, r.summary,
       -- Portable value model (E1 M1 slice B): every engine-managed
       -- timestamp presents fixed UTC millis text plus an integer
       -- epoch-millis companion, so date maths is portable integer
       -- arithmetic. SQLite's default text ordering is already BINARY.
       strftime('%Y-%m-%dT%H:%M:%fZ', r.last_activity_at) AS last_activity_at,
       CAST(strftime('%s', r.last_activity_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', r.last_activity_at), 4, 3) AS INTEGER) AS last_activity_at_ms,
       strftime('%Y-%m-%dT%H:%M:%fZ', r.created_at) AS created_at,
       CAST(strftime('%s', r.created_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', r.created_at), 4, 3) AS INTEGER) AS created_at_ms,
       strftime('%Y-%m-%dT%H:%M:%fZ', r.updated_at) AS updated_at,
       CAST(strftime('%s', r.updated_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', r.updated_at), 4, 3) AS INTEGER) AS updated_at_ms,
       strftime('%Y-%m-%dT%H:%M:%fZ', r.deleted_at) AS deleted_at,
       CAST(strftime('%s', r.deleted_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', r.deleted_at), 4, 3) AS INTEGER) AS deleted_at_ms
FROM main.records AS r
JOIN temp._query_sql_visible_records AS visible ON visible.id = r.id
LEFT JOIN temp._query_sql_visible_records AS parent_visible
       ON parent_visible.id = r.home_id;

-- Payload, actor, and run lineage are deliberately absent until their event
-- classes have a bearer/identity exposure audit.
CREATE TEMP VIEW IF NOT EXISTS content_events AS
SELECT e.seq AS local_seq, e.id, e.record_id,
       CASE WHEN e.type='receipt.committed.v1' THEN 'record.updated' ELSE e.type END AS type,
       strftime('%Y-%m-%dT%H:%M:%fZ', e.created_at) AS created_at,
       CAST(strftime('%s', e.created_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', e.created_at), 4, 3) AS INTEGER) AS created_at_ms
FROM main.content_events AS e
JOIN temp._query_sql_visible_records AS visible ON visible.id = e.record_id
WHERE e.type NOT IN (
    'reconciliation.recorded.v1','unit.superseded.v1','receipt.dependency_audited.v1'
);

CREATE TEMP VIEW IF NOT EXISTS links AS
SELECT l.id, l.source_id, l.target_id, l.relationship, l.note,
       strftime('%Y-%m-%dT%H:%M:%fZ', l.created_at) AS created_at,
       CAST(strftime('%s', l.created_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', l.created_at), 4, 3) AS INTEGER) AS created_at_ms
FROM main.links AS l
JOIN temp._query_sql_visible_records AS source_visible
  ON source_visible.id = l.source_id
JOIN temp._query_sql_visible_records AS target_visible
  ON target_visible.id = l.target_id;

CREATE TEMP VIEW IF NOT EXISTS facet_values AS
SELECT f.id, f.record_id, f.key, f.value, f.value_num, f.vocab_ref,
       strftime('%Y-%m-%dT%H:%M:%fZ', f.created_at) AS created_at,
       CAST(strftime('%s', f.created_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', f.created_at), 4, 3) AS INTEGER) AS created_at_ms
FROM main.facet_values AS f
JOIN temp._query_sql_visible_records AS visible ON visible.id = f.record_id;

CREATE TEMP VIEW IF NOT EXISTS facet_observations AS
SELECT f.id, f.record_id, f.key, f.value, f.op, f.vocab_ref,
       f.as_of,
       strftime('%Y-%m-%dT%H:%M:%fZ', f.observed_at) AS observed_at,
       CAST(strftime('%s', f.observed_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', f.observed_at), 4, 3) AS INTEGER) AS observed_at_ms,
       f.event_seq
FROM main.facet_observations AS f
JOIN temp._query_sql_visible_records AS visible ON visible.id = f.record_id;

-- Account/email bindings are caller-owned. No non-identity system has yet
-- completed the explicit exposure audit, so unknown systems fail closed.
CREATE TEMP VIEW IF NOT EXISTS bindings AS
SELECT b.record_id, b.system, b.identifier, b.is_canonical,
       b.url, b.etag,
       strftime('%Y-%m-%dT%H:%M:%fZ', b.last_seen_at) AS last_seen_at,
       CAST(strftime('%s', b.last_seen_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', b.last_seen_at), 4, 3) AS INTEGER) AS last_seen_at_ms
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
       strftime('%Y-%m-%dT%H:%M:%fZ', blob.created_at) AS created_at,
       CAST(strftime('%s', blob.created_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', blob.created_at), 4, 3) AS INTEGER) AS created_at_ms
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
SELECT id, name,
       strftime('%Y-%m-%dT%H:%M:%fZ', created_at) AS created_at,
       CAST(strftime('%s', created_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', created_at), 4, 3) AS INTEGER) AS created_at_ms
FROM main.vocabularies;

CREATE TEMP VIEW IF NOT EXISTS vocabulary_values AS
SELECT id, vocabulary_id, value, gloss, status, ordinal, terminality,
       metadata, alias_of
FROM main.vocabulary_values;

CREATE TEMP VIEW IF NOT EXISTS schema_config AS
SELECT config.id, config.layer, config.name, config.data,
       config.applies_to_collection_id, config.version_lineage,
       strftime('%Y-%m-%dT%H:%M:%fZ', config.created_at) AS created_at,
       CAST(strftime('%s', config.created_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', config.created_at), 4, 3) AS INTEGER) AS created_at_ms
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
       eff.contest_count,
       strftime('%Y-%m-%dT%H:%M:%fZ', eff.recomputed_at) AS recomputed_at,
       CAST(strftime('%s', eff.recomputed_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', eff.recomputed_at), 4, 3) AS INTEGER) AS recomputed_at_ms
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
-- Declared intent is caller-authored disclosure, not verified fact: the view
-- surfaces the latest `set_intent` text only to the declaring account and
-- reports an engine-authored disclosure state beside it, so a withheld intent
-- never reads as an absent one.
CREATE TEMP VIEW IF NOT EXISTS agent_activity AS
WITH _query_sql_agent_activity_durable AS (
  SELECT run.activity_id, run.run_key, run.account_id, run.started_at, run.ended_at,
         observed.declared_intent,
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
         principal.account_id AS viewer_account_id,
         principal.observed_at,
         principal.trusted_local_bypass
    FROM _query_sql_agent_activity_durable durable
    CROSS JOIN temp._query_sql_principal principal
    LEFT JOIN temp._query_sql_activity_members member
      ON member.account_id=durable.account_id
   WHERE principal.activity_read=1
      AND principal.is_member=1
      AND (member.member_ref IS NOT NULL
           OR (principal.trusted_local_bypass=1
               AND durable.account_id=principal.account_id))
)
SELECT activity_id,
       run_key,
       coalesce(member_ref, 'native:local-operator') AS principal_ref,
       NULL AS principal_display_name,
       strftime('%Y-%m-%dT%H:%M:%fZ', started_at) AS started_at,
       CAST(strftime('%s', started_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', started_at), 4, 3) AS INTEGER) AS started_at_ms,
       strftime('%Y-%m-%dT%H:%M:%fZ', ended_at) AS ended_at,
       CAST(strftime('%s', ended_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', ended_at), 4, 3) AS INTEGER) AS ended_at_ms,
       strftime('%Y-%m-%dT%H:%M:%fZ', last_observed_activity_at) AS last_observed_activity_at,
       CAST(strftime('%s', last_observed_activity_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', last_observed_activity_at), 4, 3) AS INTEGER) AS last_observed_activity_at_ms,
        strftime('%Y-%m-%dT%H:%M:%fZ', last_observed_activity_at, '+5 minutes') AS active_until,
        CAST(strftime('%s', last_observed_activity_at, '+5 minutes') AS INTEGER) * 1000 + CAST(substr(strftime('%f', last_observed_activity_at, '+5 minutes'), 4, 3) AS INTEGER) AS active_until_ms,
        CASE WHEN ended_at IS NULL
                   AND julianday(observed_at) < julianday(last_observed_activity_at, '+5 minutes')
             THEN 1 ELSE 0 END AS appears_active,
        CASE WHEN coalesce((SELECT available FROM temp._query_sql_activity_capture), 0) != 1 THEN NULL
             WHEN account_id = viewer_account_id THEN declared_intent
             ELSE NULL END AS declared_intent,
        CASE WHEN coalesce((SELECT available FROM temp._query_sql_activity_capture), 0) != 1 THEN 'unavailable'
             WHEN account_id != viewer_account_id THEN 'withheld'
             WHEN declared_intent IS NULL THEN 'none'
             ELSE 'disclosed' END AS declared_intent_state
   FROM _query_sql_agent_activity_admitted
  WHERE julianday(last_observed_activity_at) >= julianday(observed_at, '-24 hours');

-- One caller-visible durable claim event. Release is the first subsequent
-- engine-owned claim-clear update. Exclusive claim state prevents another
-- claim from interleaving before it. Visibility is applied before rows reach
-- logical SQL and never feeds the independent presence relation above.
--
-- Both CTE inputs are engine-populated narrow projections (see the
-- `_query_sql_claim_candidates` contract note). The CTE itself opens no
-- payload: every column it reads is a short identity or timestamp value.
-- The joined `agent_activity` relation is outside that guarantee: its
-- durable CTE still reads `content_events.payload` for run-scoped events
-- under the caller ceiling, so a run-stamped over-limit payload can fail
-- this view through that join. That sibling defect is tracked separately
-- and is out of scope here.
-- The window and records terms below re-apply the population filter on
-- those narrow columns. They disclose exactly what the previous
-- payload-reading form disclosed: NULL-actor rows could never join
-- `agent_runs` and NULL-actor releases could never satisfy the actor
-- disjunction.
CREATE TEMP VIEW IF NOT EXISTS agent_activity_claims AS
WITH _query_sql_agent_activity_claim_events AS (
   SELECT candidate.claim_id, candidate.record_id, candidate.run_key,
          candidate.claim_actor,
          candidate.claimed_by_account,
          candidate.claimed_at,
          (SELECT rc.created_at
             FROM temp._query_sql_claim_releases rc
            WHERE rc.record_id=candidate.record_id AND rc.seq>candidate.seq
              AND ((rc.actor=candidate.claim_actor)
                   OR rc.actor='local')
             ORDER BY rc.seq
             LIMIT 1) AS released_at
     FROM temp._query_sql_claim_candidates candidate
     CROSS JOIN temp._query_sql_principal principal
    WHERE (julianday(candidate.claimed_at)>=julianday(principal.observed_at,'-24 hours')
           OR EXISTS (
                SELECT 1 FROM main.records current
                 WHERE current.id=candidate.record_id
                   AND current.claimed_run_key=candidate.run_key
                   AND current.claimed_at=candidate.claimed_at
           ))
)
SELECT claim.claim_id, run.activity_id, claim.record_id,
       strftime('%Y-%m-%dT%H:%M:%fZ', claim.claimed_at) AS claimed_at,
       CAST(strftime('%s', claim.claimed_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', claim.claimed_at), 4, 3) AS INTEGER) AS claimed_at_ms,
       strftime('%Y-%m-%dT%H:%M:%fZ', claim.released_at) AS released_at,
       CAST(strftime('%s', claim.released_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', claim.released_at), 4, 3) AS INTEGER) AS released_at_ms,
       CASE WHEN claim.released_at IS NULL THEN 1 ELSE 0 END AS is_current
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
    let mut contract = TEMP_CONTRACT.replace(
        "__MAX_DERIVED_BEARER_DEPTH__",
        &crate::authorization::MAX_DERIVED_BEARER_DEPTH.to_string(),
    );
    // The served catalog is generated from LOGICAL_RELATIONS (E2 I-2), so
    // the rows an agent reads always match the admission catalog.
    for statement in sql_contract::catalog_view_statements(true) {
        contract.push_str(&statement);
        contract.push_str(";\n");
    }
    contract
}

/// The second prepare contains only public names and columns in TEMP. It has
/// no main schema at all, structurally rejecting `main.records`, raw relations,
/// and the colliding-CTE accessor spoof that defeats a view-aware callback.
pub(crate) const STRICT_LOGICAL_SCHEMA: &str = r#"
CREATE TEMP TABLE records (
  id TEXT, type TEXT, kind TEXT, name TEXT, body TEXT, home_id TEXT,
  lifecycle TEXT, persistence TEXT, maturity TEXT, summary TEXT,
  last_activity_at TEXT, last_activity_at_ms INTEGER,
  created_at TEXT, created_at_ms INTEGER,
  updated_at TEXT, updated_at_ms INTEGER,
  deleted_at TEXT, deleted_at_ms INTEGER
);
CREATE TEMP TABLE content_events (
  local_seq INTEGER, id TEXT, record_id TEXT, type TEXT,
  created_at TEXT, created_at_ms INTEGER
);
CREATE TEMP TABLE links (
  id TEXT, source_id TEXT, target_id TEXT, relationship TEXT, note TEXT,
  created_at TEXT, created_at_ms INTEGER
);
CREATE TEMP TABLE facet_values (
  id TEXT, record_id TEXT, key TEXT, value TEXT, value_num REAL,
  vocab_ref TEXT, created_at TEXT, created_at_ms INTEGER
);
CREATE TEMP TABLE facet_observations (
  id TEXT, record_id TEXT, key TEXT, value TEXT, op TEXT, vocab_ref TEXT,
  as_of TEXT, observed_at TEXT, observed_at_ms INTEGER, event_seq INTEGER
);
CREATE TEMP TABLE bindings (
  record_id TEXT, system TEXT, identifier TEXT, is_canonical INTEGER,
  url TEXT, etag TEXT, last_seen_at TEXT, last_seen_at_ms INTEGER
);
CREATE TEMP TABLE blobs (
  id TEXT, bytes BLOB, mime TEXT, size_bytes INTEGER, sha256 TEXT,
  original_filename TEXT, storage_tier TEXT, external_ref TEXT,
  created_at TEXT, created_at_ms INTEGER
);
CREATE TEMP TABLE vocabularies (
  id TEXT, name TEXT, created_at TEXT, created_at_ms INTEGER
);
CREATE TEMP TABLE vocabulary_values (
  id TEXT, vocabulary_id TEXT, value TEXT, gloss TEXT, status TEXT,
  ordinal REAL, terminality TEXT, metadata TEXT, alias_of TEXT
);
CREATE TEMP TABLE schema_config (
  id TEXT, layer TEXT, name TEXT, data TEXT, applies_to_collection_id TEXT,
  version_lineage TEXT, created_at TEXT, created_at_ms INTEGER
);
CREATE TEMP TABLE effective_relationships (
  relationship_origin_db_id TEXT, relationship_id TEXT,
  relationship_type TEXT, type_definition_id TEXT, endpoint_semantics TEXT,
  endpoints TEXT, effective_state TEXT, epistemic_state TEXT,
  support_count INTEGER, contest_count INTEGER,
  recomputed_at TEXT, recomputed_at_ms INTEGER
);
CREATE TEMP TABLE agent_activity (
  activity_id TEXT, run_key TEXT, principal_ref TEXT, principal_display_name TEXT,
  started_at TEXT, started_at_ms INTEGER,
  ended_at TEXT, ended_at_ms INTEGER,
  last_observed_activity_at TEXT, last_observed_activity_at_ms INTEGER,
  active_until TEXT, active_until_ms INTEGER,
  appears_active INTEGER, declared_intent TEXT,
  declared_intent_state TEXT
);
CREATE TEMP TABLE agent_activity_claims (
  claim_id TEXT, activity_id TEXT, record_id TEXT,
  claimed_at TEXT, claimed_at_ms INTEGER,
  released_at TEXT, released_at_ms INTEGER, is_current INTEGER
);
CREATE TEMP TABLE messages_awaiting_reply (message_id TEXT);
CREATE TEMP TABLE catalog_relations (
  relation_name TEXT, identity TEXT, semantic_version INTEGER,
  caller_relative INTEGER, completeness TEXT, profiles TEXT, comment TEXT
);
CREATE TEMP TABLE catalog_columns (
  relation_name TEXT, column_name TEXT, column_position INTEGER
);
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
    sqlx::query("DELETE FROM temp._query_sql_activity_capture")
        .execute(&mut **transaction)
        .await?;
    let available: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM main.sqlite_master WHERE type='table' AND name='read_log_calls')",
    )
    .fetch_one(&mut **transaction)
    .await?;
    if !available {
        sqlx::query(
            "INSERT INTO temp._query_sql_activity_capture(singleton,available) VALUES(1,0)",
        )
        .execute(&mut **transaction)
        .await?;
        return Ok((false, None));
    }
    sqlx::query(
        "INSERT INTO temp._query_sql_activity_observations(run_key,last_observed_at,declared_intent)
         SELECT calls.run_key,max(calls.ended_at),
                (SELECT intent_calls.intent
                   FROM main.read_log_calls intent_calls
                  WHERE intent_calls.run_key=calls.run_key
                    AND intent_calls.tool='set_intent'
                    AND intent_calls.outcome='ok'
                    AND intent_calls.intent IS NOT NULL
                    AND intent_calls.actor=run.account_id
                    AND julianday(intent_calls.ended_at)<=julianday((SELECT observed_at FROM temp._query_sql_principal))
                    AND (run.ended_at IS NULL OR julianday(intent_calls.ended_at)<=julianday(run.ended_at))
                  ORDER BY intent_calls.seq DESC
                  LIMIT 1)
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
    sqlx::query("INSERT INTO temp._query_sql_activity_capture(singleton,available) VALUES(1,1)")
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

/// Materialise the claim and claim-clear candidate rows before the caller
/// value ceiling is lowered. Shape matching on `content_events.payload`
/// happens here at the full limit, and only for agent-stamped
/// `record.updated` rows inside the activity window or matching the
/// still-current `records` identity. The claims view then reads the narrow
/// projected columns alone, so caller SQL can never open an over-limit
/// payload through this relation.
///
/// The `actor IS NOT NULL` term is disclosure-neutral: every engine-owned
/// claim and claim-clear event carries an actor, while a NULL-actor row
/// could never join `agent_runs` (claim) or satisfy the release actor
/// disjunction against a non-null claim actor (release).
///
/// Release completeness: a genuine release always has a higher event seq
/// than its claim, so bounding the release scan below by the oldest
/// candidate claim seq keeps every release a disclosed claim can observe.
/// Seq comparison needs no date parsing. An empty candidate set yields a
/// NULL bound and inserts no releases.
async fn prepare_claim_candidates(transaction: &mut sqlx::Transaction<'_, Sqlite>) -> Result<()> {
    sqlx::query("DELETE FROM temp._query_sql_claim_candidates")
        .execute(&mut **transaction)
        .await?;
    sqlx::query("DELETE FROM temp._query_sql_claim_releases")
        .execute(&mut **transaction)
        .await?;
    sqlx::query(
        "INSERT INTO temp._query_sql_claim_candidates(seq, claim_id, record_id, run_key, claim_actor, claimed_by_account, claimed_at)
          SELECT event.seq, event.id, event.record_id, event.run_key, event.actor,
                 json_extract(event.payload,'$.claimed_by_account'), event.created_at
            FROM main.content_events event
            CROSS JOIN temp._query_sql_principal principal
           WHERE event.type='record.updated'
             AND event.actor IS NOT NULL
             AND json_type(event.payload,'$.claimed_by_account')='text'
             AND json_type(event.payload,'$.claimed_run_key')='text'
             AND (julianday(event.created_at)>=julianday(principal.observed_at,'-24 hours')
                  OR EXISTS (
                       SELECT 1 FROM main.records current
                        WHERE current.id=event.record_id
                          AND current.claimed_run_key=event.run_key
                          AND current.claimed_at=event.created_at
                  ))",
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "INSERT INTO temp._query_sql_claim_releases(seq, record_id, actor, created_at)
          SELECT event.seq, event.record_id, event.actor, event.created_at
            FROM main.content_events event
           WHERE event.type='record.updated'
             AND event.actor IS NOT NULL
             AND json_type(event.payload,'$.claimed_by_account')='null'
             AND json_type(event.payload,'$.claimed_run_key')='null'
             AND event.seq>=(
                   SELECT min(seq)
                     FROM temp._query_sql_claim_candidates
                 )",
    )
    .execute(&mut **transaction)
    .await?;
    Ok(())
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

/// Richard 25 Sep (Native e25665c): already-stored governed SQL
/// keeps working under the pinned engine's pre-I2 function rules, nothing
/// added: the legacy allowance is exactly the portable subset plus every
/// other name the pre-I2 SQLite authorizer admitted (`SAFE_FUNCTIONS` as of
/// the I2 base, minus the portable overlap). Before I2 `group_concat` was
/// already refused ("not authorized to use function"), so it stays refused
/// for stored definitions too. Ad-hoc `query_sql` and SQL being saved stay
/// on the portable subset.
const LEGACY_SAVED_SQL_EXTRA_FUNCTIONS: [&str; 15] = [
    "date",
    "datetime",
    "glob",
    "instr",
    "json_array_length",
    "json_type",
    "json_valid",
    "julianday",
    "strftime",
    "substring",
    "time",
    "total",
    "typeof",
    "unicode",
    "unixepoch",
];

fn is_legacy_saved_sql_function(function_name: &str) -> bool {
    sql_contract::is_portable_function(function_name)
        || function_name.eq_ignore_ascii_case("like")
        || LEGACY_SAVED_SQL_EXTRA_FUNCTIONS
            .iter()
            .any(|safe| function_name.eq_ignore_ascii_case(safe))
}

fn authorize_view_expansion_legacy_saved_sql(context: AuthContext<'_>) -> Authorization {
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
        AuthAction::Function { function_name } if is_legacy_saved_sql_function(function_name) => {
            Authorization::Allow
        }
        AuthAction::Function { .. } => Authorization::Deny,
        _ => Authorization::Deny,
    }
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
            if sql_contract::is_portable_function(function_name)
                || function_name.eq_ignore_ascii_case("like") =>
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
            if sql_contract::is_portable_function(function_name)
                || function_name.eq_ignore_ascii_case("like") =>
        {
            Authorization::Allow
        }
        _ => Authorization::Deny,
    }
}

fn authorize_strict_legacy_saved_sql(context: AuthContext<'_>) -> Authorization {
    match context.action {
        AuthAction::Select | AuthAction::Recursive => Authorization::Allow,
        AuthAction::Read { table_name, .. }
            if context.database_name == Some("temp")
                && sql_contract::is_logical_relation(table_name) =>
        {
            Authorization::Allow
        }
        AuthAction::Read { .. } if context.database_name.is_none() => Authorization::Allow,
        AuthAction::Function { function_name } if is_legacy_saved_sql_function(function_name) => {
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
            if category == QuerySqlErrorCategory::UnauthorizedRelation {
                if let Some(repair) = blocked_probe_repair(statement, &detail) {
                    return Err(sql_contract::categorized_error(
                        category,
                        format!("{detail} {repair}"),
                    ));
                }
            }
            Err(sql_contract::categorized_error(category, detail))
        }
    }
}

/// E2 I-1: name the fix when a catalog probe or physical table is blocked.
/// Runs only on an already-rejected UnauthorizedRelation, so it rewords a
/// failure and never admits a statement. Function denies (e.g.
/// GROUP_CONCAT) name no table and resolve to logical targets, so they
/// fall through untouched for the function-allowlist repair to own.
fn blocked_probe_repair(statement: &str, detail: &str) -> Option<String> {
    if let Some(tail) = detail
        .find("access to ")
        .map(|index| &detail[index + "access to ".len()..])
    {
        let name = tail
            .split(['.', ' ', '\t', '\n'])
            .next()
            .unwrap_or_default();
        if let Some(repair) =
            sql_contract::blocked_relation_repair(name, sql_contract::QuerySqlProfile::SqliteLocal)
        {
            return Some(repair);
        }
    }
    if let Some(tail) = detail.find("no such table").and_then(|index| {
        detail[index..]
            .find(':')
            .map(|off| &detail[index + off + 1..])
    }) {
        let qualified = tail
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
            .find(|token| !token.is_empty())
            .unwrap_or_default();
        let short = qualified.rsplit('.').next().unwrap_or_default();
        // Prefer the qualified name: `information_schema.tables` is a probe
        // even though bare `tables` is not.
        if let Some(repair) = sql_contract::blocked_relation_repair(
            qualified,
            sql_contract::QuerySqlProfile::SqliteLocal,
        )
        .filter(|_| qualified != short)
        .or_else(|| {
            sql_contract::blocked_relation_repair(short, sql_contract::QuerySqlProfile::SqliteLocal)
        }) {
            return Some(repair);
        }
    }
    first_non_logical_target(statement).and_then(|name| {
        sql_contract::blocked_relation_repair(&name, sql_contract::QuerySqlProfile::SqliteLocal)
    })
}

/// First FROM/JOIN target that is not a logical relation, qualifiers
/// (`main.`/`temp.`) stripped. Returns `None` when every target resolves.
fn first_non_logical_target(statement: &str) -> Option<String> {
    let tokens: Vec<&str> = statement
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
        .filter(|token| !token.is_empty())
        .collect();
    let mut expect_table = false;
    for token in tokens {
        if token.eq_ignore_ascii_case("from") || token.eq_ignore_ascii_case("join") {
            expect_table = true;
            continue;
        }
        if expect_table {
            expect_table = false;
            let short = token.rsplit('.').next().unwrap_or(token);
            if short.eq_ignore_ascii_case("select") || short.eq_ignore_ascii_case("with") {
                continue;
            }
            if !sql_contract::is_logical_relation(&short.to_ascii_lowercase()) {
                return Some(short.to_string());
            }
        }
    }
    None
}

/// Tier 1.1: the frozen schemas are process-constant, so their batch text is
/// assembled once and each thread keeps one prepared validator connection per
/// schema. Validation itself never writes to these connections — it only sets
/// a per-call authorizer, prepares, then clears the authorizer — so reuse is
/// behavior-preserving. A global lock would serialize every caller prepare
/// across threads; thread-local reuse keeps prepares parallel while still
/// reaching zero schema rebuilds after per-thread warm-up.
static FROZEN_DDL_BATCH: OnceLock<String> = OnceLock::new();
static FROZEN_TEMP_CONTRACT_BATCH: OnceLock<String> = OnceLock::new();

thread_local! {
    static FROZEN_VALIDATOR: RefCell<Option<rusqlite::Connection>> = const { RefCell::new(None) };
    static STRICT_VALIDATOR: RefCell<Option<rusqlite::Connection>> = const { RefCell::new(None) };
    /// Observability for the tier-1.1 acceptance: how many validator
    /// connections this thread built. Thread-local like the caches, so one
    /// thread's warm-up never moves another thread's count. Incremented only
    /// on the cold path, so reading it is free on every governed call.
    static FROZEN_VALIDATOR_BUILDS: Cell<usize> = const { Cell::new(0) };
    static STRICT_VALIDATOR_BUILDS: Cell<usize> = const { Cell::new(0) };
}

fn frozen_ddl_batch() -> &'static str {
    FROZEN_DDL_BATCH.get_or_init(|| {
        DDL_STATEMENTS
            .iter()
            .map(|sql| format!("{sql};\n"))
            .collect()
    })
}

fn frozen_temp_contract_batch() -> &'static str {
    FROZEN_TEMP_CONTRACT_BATCH.get_or_init(temp_contract)
}

fn build_frozen_validator() -> Result<rusqlite::Connection> {
    let conn = rusqlite::Connection::open_in_memory()
        .map_err(|e| contract_violation(format!("query_sql: validator setup failed: {e}")))?;
    conn.execute_batch(frozen_ddl_batch())
        .and_then(|_| conn.execute_batch(frozen_temp_contract_batch()))
        .map_err(|e| contract_violation(format!("query_sql: validator setup failed: {e}")))?;
    FROZEN_VALIDATOR_BUILDS.with(|builds| builds.set(builds.get() + 1));
    Ok(conn)
}

fn build_strict_validator() -> Result<rusqlite::Connection> {
    let conn = rusqlite::Connection::open_in_memory()
        .map_err(|e| contract_violation(format!("query_sql: validator setup failed: {e}")))?;
    conn.execute_batch(STRICT_LOGICAL_SCHEMA)
        .map_err(|e| contract_violation(format!("query_sql: validator setup failed: {e}")))?;
    STRICT_VALIDATOR_BUILDS.with(|builds| builds.set(builds.get() + 1));
    Ok(conn)
}

fn with_frozen_validator<T>(
    operation: impl FnOnce(&rusqlite::Connection) -> Result<T>,
) -> Result<T> {
    FROZEN_VALIDATOR.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_none() {
            *slot = Some(build_frozen_validator()?);
        }
        let conn = slot.as_ref().expect("validator slot populated above");
        operation(conn)
    })
}

fn with_strict_validator<T>(
    operation: impl FnOnce(&rusqlite::Connection) -> Result<T>,
) -> Result<T> {
    STRICT_VALIDATOR.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_none() {
            *slot = Some(build_strict_validator()?);
        }
        let conn = slot.as_ref().expect("validator slot populated above");
        operation(conn)
    })
}

fn validate_view_expansion(statement: &str) -> Result<()> {
    with_frozen_validator(|conn| {
        prepare_under_authorizer(conn, statement, authorize_view_expansion)
    })
}

fn validate_view_expansion_legacy_saved_sql(statement: &str) -> Result<()> {
    with_frozen_validator(|conn| {
        prepare_under_authorizer(conn, statement, authorize_view_expansion_legacy_saved_sql)
    })
}

fn validate_strict(statement: &str) -> Result<()> {
    with_strict_validator(|conn| prepare_under_authorizer(conn, statement, authorize_strict))
}

fn validate_strict_legacy_saved_sql(statement: &str) -> Result<()> {
    with_strict_validator(|conn| {
        prepare_under_authorizer(conn, statement, authorize_strict_legacy_saved_sql)
    })
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

/// Stored governed SQL only (Native e25665c): identical gates except
/// the I2 portable-function rules are replaced by the legacy allowance, in
/// both the shared classifier and the engine authorizers.
pub(crate) fn validate_legacy_saved_sql(sql: &str) -> Result<()> {
    let statement =
        sql_contract::classify_stored_saved_sql(sql_contract::QuerySqlProfile::SqliteLocal, sql)?;
    validate_view_expansion_legacy_saved_sql(&statement)?;
    validate_strict_legacy_saved_sql(&statement)
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
    with_strict_validator(|conn| {
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
    })
}

/// Stored governed SQL only (Native e25665c): same labels under the
/// legacy function allowance.
pub(crate) fn validated_output_columns_legacy_saved_sql(sql: &str) -> Result<Vec<String>> {
    let statement =
        sql_contract::classify_stored_saved_sql(sql_contract::QuerySqlProfile::SqliteLocal, sql)?;
    validate_view_expansion_legacy_saved_sql(&statement)?;
    with_strict_validator(|conn| {
        conn.authorizer(Some(authorize_strict_legacy_saved_sql));
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
    })
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
    let dependencies = std::sync::Arc::new(std::sync::Mutex::new(std::collections::BTreeSet::<
        String,
    >::new()));
    let observed = dependencies.clone();
    with_strict_validator(|conn| {
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
        Ok(())
    })?;
    Ok(std::sync::Arc::try_unwrap(dependencies)
        .expect("validator releases dependency observer")
        .into_inner()
        .expect("dependency lock"))
}

/// Stored governed SQL only (Native e25665c): same relation
/// observation under the legacy function allowance.
pub(crate) fn validated_relation_dependencies_legacy_saved_sql(
    sql: &str,
) -> Result<std::collections::BTreeSet<String>> {
    let statement =
        sql_contract::classify_stored_saved_sql(sql_contract::QuerySqlProfile::SqliteLocal, sql)?;
    validate_view_expansion_legacy_saved_sql(&statement)?;
    let dependencies = std::sync::Arc::new(std::sync::Mutex::new(std::collections::BTreeSet::<
        String,
    >::new()));
    let observed = dependencies.clone();
    with_strict_validator(|conn| {
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
            authorize_strict_legacy_saved_sql(context)
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
        Ok(())
    })?;
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

/// Author-facing timeout diagnostic. SQLite reports the progress-handler
/// interrupt as its own terse text ("interrupted"), which names neither the
/// governed deadline nor the usual author-side cause, so replace it here.
/// Internal table names stay out: only the caller-relative relations authors
/// already write against (`records`, `links`) are named.
fn governed_sql_timeout() -> crate::error::Error {
    sql_contract::categorized_error(
        QuerySqlErrorCategory::Timeout,
        sql_contract::deadline_hint(),
    )
}

fn map_stream_error(error: sqlx::Error) -> crate::error::Error {
    if error
        .to_string()
        .to_ascii_lowercase()
        .contains("interrupted")
    {
        governed_sql_timeout()
    } else {
        sql_contract::categorized_error(QuerySqlErrorCategory::SyntaxOrType, error.to_string())
    }
}

/// Bound one validated statement for execution. Ordinary statements run under
/// an outer cap that preserves every caller predicate/aggregate while bounding
/// row work. `EXPLAIN QUERY PLAN` returns the plan rather than record data and
/// cannot be a subquery operand, so it runs as classified; the streaming loop
/// still enforces the row/column/cell/result limits and the progress-handler
/// deadline. The classifier normalizes the only admitted `EXPLAIN` form to
/// this exact prefix over an already-admissible statement.
fn cap_statement(statement: &str, row_limit: i64) -> String {
    if statement.starts_with("EXPLAIN QUERY PLAN ") {
        statement.to_owned()
    } else {
        format!("SELECT * FROM ({statement}) LIMIT {}", row_limit + 1)
    }
}

/// Run one caller-filtered query. The caller is transport-authenticated and is
/// never derived from tool arguments. The owned path acquires from the
/// dedicated governed-SQL pool, never the write pool, so governed reads —
/// which hold their connection through per-row JSON encoding — cannot starve
/// ordinary writers. Every explicit outcome rolls back; drop does the same
/// for cancellation/unwind, and pool release clears the TEMP state plus
/// progress callback before any later borrower can use it.
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
    // I1 review: `?2` with one parameter must fail, not bind a silent
    // NULL. The `?N` set has to be exactly `1..=parameters.len()`.
    sql_contract::check_positional_arguments(
        sql_contract::QuerySqlProfile::SqliteLocal,
        &statement,
        request.parameters.len(),
    )?;
    let relation_dependencies = validated_relation_dependencies(&statement)?;
    let needs_awaiting_reply = relation_dependencies.contains("messages_awaiting_reply");
    let activity_dependent = relation_dependencies
        .iter()
        .any(|name| matches!(name.as_str(), "agent_activity" | "agent_activity_claims"));
    let needs_claims = relation_dependencies.contains("agent_activity_claims");
    let pool = db.governed_pool().clone();
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
    if let Err(error) = sqlx::query("DELETE FROM temp._query_sql_claim_candidates")
        .execute(&mut *connection)
        .await
    {
        connection.close_on_drop();
        return Err(error.into());
    }
    if let Err(error) = sqlx::query("DELETE FROM temp._query_sql_claim_releases")
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
    // Freshness stamp (E1 M1 slice A): the workspace content sequence observed
    // inside this same read transaction, so the returned rows and the stamp
    // share one snapshot. This is the unfiltered workspace head, not the
    // caller-visible maximum: hidden writes still advance it.
    let as_of_seq: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM main.content_events")
            .fetch_one(&mut *transaction)
            .await?;
    if activity_dependent {
        populate_activity_members(&mut transaction, &principal).await?;
    }
    sqlx::query(
        "INSERT INTO temp._query_sql_principal(singleton, account_id, trusted_local_bypass, activity_read, is_member, observed_at)
         VALUES (1, ?, ?, ?, ?, ?)",
    )
    .bind(principal.credential().to_string())
    .bind(principal.trusted_local_bypass())
    .bind(principal.activity_read())
    .bind(principal.is_member())
    .bind(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
    .execute(&mut *transaction)
    .await?;
    if activity_dependent {
        prepare_activity_observations(&mut transaction).await?;
    }
    if needs_claims {
        prepare_claim_candidates(&mut transaction).await?;
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
    let capped = cap_statement(&statement, MAX_ROWS);
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
        while let Some(row) = stream.try_next().await.map_err(map_stream_error)? {
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

    let query_result = annotate_sqlite_toobig_error(
        &mut transaction,
        &relation_dependencies,
        &request.sql,
        query_result,
    )
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
        truncation_hint: sql_contract::truncation_hint_for(truncated),
        as_of_seq,
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
    query_sql_request_in_with_row_limit(
        transaction,
        principal,
        request,
        MAX_ROWS,
        sql_contract::FunctionAllowance::Portable,
    )
    .await
    .map(|(result, _)| result)
}

/// Internal saved-query execution retains one extra row so the governed
/// envelope can validate the identity/order boundary before truncating it.
/// Stored definitions run under the legacy saved-SQL function allowance
/// (Native e25665c): the only caller executing stored governed SQL.
pub(crate) async fn query_sql_request_in_for_saved(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    principal: QueryPrincipal,
    request: QuerySqlRequest,
) -> Result<(SqlResult, GovernedSqlObservation)> {
    query_sql_request_in_with_row_limit(
        transaction,
        principal,
        request,
        MAX_ROWS + 1,
        sql_contract::FunctionAllowance::LegacySavedSql,
    )
    .await
}

/// Bounded governed read inside the caller's transaction. The probe row
/// beyond `row_limit` is how a preparer proves a complete result instead
/// of digesting a truncation (`cap_statement` requests `row_limit + 1`
/// and reports `truncated`).
pub(crate) async fn query_sql_request_in_with_row_limit(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    principal: QueryPrincipal,
    request: QuerySqlRequest,
    row_limit: i64,
    allowance: sql_contract::FunctionAllowance,
) -> Result<(SqlResult, GovernedSqlObservation)> {
    use sql_contract::FunctionAllowance;
    sql_contract::require_available(sql_contract::QuerySqlProfile::SqliteLocal)?;
    request.validate()?;
    match allowance {
        FunctionAllowance::Portable => validate(&request.sql)?,
        FunctionAllowance::LegacySavedSql => validate_legacy_saved_sql(&request.sql)?,
    }
    let statement = match allowance {
        FunctionAllowance::Portable => sql_contract::classify_single_read_statement(
            sql_contract::QuerySqlProfile::SqliteLocal,
            &request.sql,
        )?,
        FunctionAllowance::LegacySavedSql => sql_contract::classify_stored_saved_sql(
            sql_contract::QuerySqlProfile::SqliteLocal,
            &request.sql,
        )?,
    };
    // I1 review: `?2` with one parameter must fail, not bind a silent
    // NULL. The `?N` set has to be exactly `1..=parameters.len()`.
    sql_contract::check_positional_arguments(
        sql_contract::QuerySqlProfile::SqliteLocal,
        &statement,
        request.parameters.len(),
    )?;
    let relation_dependencies = match allowance {
        FunctionAllowance::Portable => validated_relation_dependencies(&statement)?,
        FunctionAllowance::LegacySavedSql => {
            validated_relation_dependencies_legacy_saved_sql(&statement)?
        }
    };
    let needs_awaiting_reply = relation_dependencies.contains("messages_awaiting_reply");
    let activity_dependent = relation_dependencies
        .iter()
        .any(|name| matches!(name.as_str(), "agent_activity" | "agent_activity_claims"));
    let needs_claims = relation_dependencies.contains("agent_activity_claims");
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
    sqlx::query("DELETE FROM temp._query_sql_claim_candidates")
        .execute(&mut **transaction)
        .await?;
    sqlx::query("DELETE FROM temp._query_sql_claim_releases")
        .execute(&mut **transaction)
        .await?;
    // SQLite transactions are deferred: establish the main-database snapshot
    // before sampling the wall clock used for both row inference and receipt
    // metadata. Otherwise a concurrent commit could enter the result after the
    // sampled observation time.
    let _: Option<(i64,)> = sqlx::query_as("SELECT 1 FROM main.database_identity LIMIT 1")
        .fetch_optional(&mut **transaction)
        .await?;
    // Freshness stamp (E1 M1 slice A): same-snapshot workspace head as the
    // owned path above. Unfiltered on purpose; hidden writes advance it.
    let as_of_seq: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM main.content_events")
            .fetch_one(&mut **transaction)
            .await?;
    let observed_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    if activity_dependent {
        populate_activity_members(transaction, &principal).await?;
    }
    sqlx::query(
        "INSERT INTO temp._query_sql_principal(singleton, account_id, trusted_local_bypass, activity_read, is_member, observed_at)
         VALUES (1, ?, ?, ?, ?, ?)",
    )
    .bind(principal.credential().to_string())
    .bind(principal.trusted_local_bypass())
    .bind(principal.activity_read())
    .bind(principal.is_member())
    .bind(&observed_at)
    .execute(&mut **transaction)
    .await?;
    let (transient_available, transient_watermark) = if activity_dependent {
        prepare_activity_observations(transaction).await?
    } else {
        (true, None)
    };
    if needs_claims {
        prepare_claim_candidates(transaction).await?;
    }
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
    let capped = cap_statement(&statement, row_limit);
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
        while let Some(row) = stream.try_next().await.map_err(map_stream_error)? {
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
    // Probe while the progress handler is still installed so the 500ms
    // stored-value scan cannot run unbounded. diagnose() replaces the
    // handler with the probe budget; cleanup below removes it.
    let query_result = annotate_sqlite_toobig_error(
        transaction,
        &relation_dependencies,
        &request.sql,
        query_result,
    )
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
        sqlx::query("DROP TABLE IF EXISTS temp._query_sql_activity_capture")
            .execute(&mut **transaction)
            .await?;
        sqlx::query("DROP TABLE IF EXISTS temp._query_sql_activity_members")
            .execute(&mut **transaction)
            .await?;
        sqlx::query("DROP TABLE IF EXISTS temp._query_sql_claim_candidates")
            .execute(&mut **transaction)
            .await?;
        sqlx::query("DROP TABLE IF EXISTS temp._query_sql_claim_releases")
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
            truncation_hint: sql_contract::truncation_hint_for(truncated),
            as_of_seq,
        },
        observation,
    ))
}

struct OversizedStoredValue {
    relation: &'static str,
    column: &'static str,
    id: String,
    bytes: i32,
}

struct ProbeReport {
    offenders: Vec<OversizedStoredValue>,
    incomplete: Option<&'static str>,
}

struct TooBigBlobTarget {
    relation: &'static str,
    physical_table: &'static str,
    columns: &'static [&'static str],
    visible_rowids_sql: &'static str,
}

/// Physical TEXT/BLOB columns that can exceed SQLITE_LIMIT_LENGTH. Candidate
/// ids are taken from `_query_sql_visible_records` (or the same join the
/// logical view uses) so the probe cannot name a row the caller cannot see.
/// `facet_values.value` is the stored TEXT column; the generated virtual
/// `value_num` is never opened.
const TOOBIG_BLOB_TARGETS: &[TooBigBlobTarget] = &[
    TooBigBlobTarget {
        relation: "records",
        physical_table: "records",
        columns: &["body", "name", "summary"],
        visible_rowids_sql: "SELECT visible.id, physical.rowid
             FROM temp._query_sql_visible_records AS visible
             JOIN main.records AS physical ON physical.id = visible.id
             ORDER BY visible.id",
    },
    TooBigBlobTarget {
        relation: "facet_values",
        physical_table: "facet_values",
        columns: &["value"],
        visible_rowids_sql: "SELECT physical.id, physical.rowid
             FROM main.facet_values AS physical
             JOIN temp._query_sql_visible_records AS visible
               ON visible.id = physical.record_id
             ORDER BY physical.id",
    },
    TooBigBlobTarget {
        relation: "facet_observations",
        physical_table: "facet_observations",
        columns: &["value"],
        visible_rowids_sql: "SELECT physical.id, physical.rowid
             FROM main.facet_observations AS physical
             JOIN temp._query_sql_visible_records AS visible
               ON visible.id = physical.record_id
             ORDER BY physical.id",
    },
    TooBigBlobTarget {
        relation: "schema_config",
        physical_table: "schema_config",
        columns: &["data"],
        visible_rowids_sql: "SELECT config.id, config.rowid
             FROM main.schema_config AS config
            WHERE config.applies_to_collection_id IS NULL
               OR EXISTS (
                    SELECT 1 FROM temp._query_sql_visible_records AS visible
                     WHERE visible.id = config.applies_to_collection_id
                  )
            ORDER BY config.id",
    },
    TooBigBlobTarget {
        relation: "links",
        physical_table: "links",
        columns: &["note"],
        visible_rowids_sql: "SELECT physical.id, physical.rowid
             FROM main.links AS physical
             JOIN temp._query_sql_visible_records AS source_visible
               ON source_visible.id = physical.source_id
             JOIN temp._query_sql_visible_records AS target_visible
               ON target_visible.id = physical.target_id
             ORDER BY physical.id",
    },
    TooBigBlobTarget {
        relation: "blobs",
        physical_table: "blobs",
        columns: &["bytes"],
        // Inline, non-null bytes only: `size_bytes` describes the external
        // object when storage_tier='external' and bytes IS NULL, so it cannot
        // raise SQLITE_TOOBIG. Length comes from sqlite3_blob_bytes, not the
        // size_bytes column, which is not required to match even for inline.
        visible_rowids_sql: "SELECT blob.id, blob.rowid
             FROM main.blobs AS blob
            WHERE blob.bytes IS NOT NULL
              AND blob.storage_tier = 'inline'
              AND EXISTS (
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
                     WHERE attachment.type = 'Document'
                       AND attachment.kind = 'attachment'
                  )
            ORDER BY blob.id",
    },
];

fn sqlite_error_is_toobig(error: &crate::Error) -> bool {
    error
        .to_string()
        .to_ascii_lowercase()
        .contains("string or blob too big")
}

fn sqlite_toobig_engine_detail(error: &crate::Error) -> String {
    let rendered = error.to_string();
    rendered
        .strip_prefix("query_sql [syntax_or_type]: ")
        .unwrap_or(&rendered)
        .to_string()
}

fn projected_column_names(sql: &str) -> std::collections::HashSet<String> {
    validated_output_columns(sql)
        .map(|columns| {
            columns
                .into_iter()
                .map(|column| column.to_ascii_lowercase())
                .collect()
        })
        .unwrap_or_default()
}

async fn annotate_sqlite_toobig_error(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    relation_dependencies: &std::collections::BTreeSet<String>,
    sql: &str,
    query_result: Result<(Vec<String>, Vec<Value>, bool)>,
) -> Result<(Vec<String>, Vec<Value>, bool)> {
    match query_result {
        Err(error) if sqlite_error_is_toobig(&error) => Err(sql_contract::categorized_error(
            QuerySqlErrorCategory::SyntaxOrType,
            format_sqlite_toobig_detail(
                &sqlite_toobig_engine_detail(&error),
                &projected_column_names(sql),
                diagnose_oversized_visible_values(transaction, relation_dependencies).await,
            ),
        )),
        other => other,
    }
}

async fn diagnose_oversized_visible_values(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    relation_dependencies: &std::collections::BTreeSet<String>,
) -> ProbeReport {
    let started = Instant::now();
    let mut handle = match transaction.lock_handle().await {
        Ok(handle) => handle,
        Err(_) => {
            return ProbeReport {
                offenders: Vec::new(),
                incomplete: Some("the stored-value probe could not lock the connection"),
            };
        }
    };
    handle.set_progress_handler(PROGRESS_OPS, move || {
        started.elapsed() < TOOBIG_PROBE_BUDGET
    });
    let db = handle.as_raw_handle().as_ptr();
    let mut report = ProbeReport {
        offenders: Vec::new(),
        incomplete: None,
    };
    for target in TOOBIG_BLOB_TARGETS {
        if report.offenders.len() >= MAX_TOOBIG_NAMED {
            break;
        }
        if !relation_dependencies.contains(target.relation) {
            continue;
        }
        if started.elapsed() >= TOOBIG_PROBE_BUDGET {
            report.incomplete = Some("the stored-value probe reached its 500ms budget");
            break;
        }
        if let Err(reason) = probe_one_target(db, target, started, &mut report.offenders) {
            report.incomplete = Some(reason);
            break;
        }
    }
    if report.incomplete.is_none() && report.offenders.len() >= MAX_TOOBIG_NAMED {
        report.incomplete =
            Some("the stored-value probe named 12 values and stopped; more may exist");
    }
    report
}

fn probe_one_target(
    db: *mut libsqlite3_sys::sqlite3,
    target: &TooBigBlobTarget,
    started: Instant,
    named: &mut Vec<OversizedStoredValue>,
) -> std::result::Result<(), &'static str> {
    let sql = format!(
        "{} LIMIT {}",
        target.visible_rowids_sql, MAX_TOOBIG_PROBE_ROWS
    );
    let sql = std::ffi::CString::new(sql).map_err(|_| "a stored-value probe query was invalid")?;
    let mut stmt = std::ptr::null_mut();
    // SAFETY: `db` is the exclusive live handle from `lock_handle`. The SQL is
    // engine-authored and NUL-terminated. Finalize via PreparedStmt on every path.
    let rc = unsafe {
        libsqlite3_sys::sqlite3_prepare_v2(db, sql.as_ptr(), -1, &mut stmt, std::ptr::null_mut())
    };
    if rc != libsqlite3_sys::SQLITE_OK {
        if !stmt.is_null() {
            unsafe {
                libsqlite3_sys::sqlite3_finalize(stmt);
            }
        }
        return Err("a stored-value probe query failed to prepare");
    }
    let _guard = PreparedStmt(stmt);
    loop {
        if named.len() >= MAX_TOOBIG_NAMED {
            return Ok(());
        }
        if started.elapsed() >= TOOBIG_PROBE_BUDGET {
            return Err("the stored-value probe reached its 500ms budget");
        }
        // SAFETY: `stmt` is a live prepared statement on `db`.
        let step = unsafe { libsqlite3_sys::sqlite3_step(stmt) };
        match step {
            libsqlite3_sys::SQLITE_DONE => return Ok(()),
            libsqlite3_sys::SQLITE_INTERRUPT => {
                return Err("the stored-value probe reached its 500ms budget");
            }
            libsqlite3_sys::SQLITE_ROW => {
                let id = unsafe { sqlite_column_text(stmt, 0) }
                    .ok_or("a stored-value probe row was missing its id")?;
                let rowid = unsafe { libsqlite3_sys::sqlite3_column_int64(stmt, 1) };
                for column in target.columns {
                    if named.len() >= MAX_TOOBIG_NAMED {
                        return Ok(());
                    }
                    if started.elapsed() >= TOOBIG_PROBE_BUDGET {
                        return Err("the stored-value probe reached its 500ms budget");
                    }
                    let Some(bytes) = stored_value_bytes(db, target.physical_table, column, rowid)
                    else {
                        continue;
                    };
                    if bytes > MAX_SQLITE_VALUE_BYTES {
                        named.push(OversizedStoredValue {
                            relation: target.relation,
                            column,
                            id: id.clone(),
                            bytes,
                        });
                    }
                }
            }
            _ => return Err("a stored-value probe query failed"),
        }
    }
}

struct PreparedStmt(*mut libsqlite3_sys::sqlite3_stmt);

impl Drop for PreparedStmt {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: prepared in probe_one_target and not yet finalized.
            unsafe {
                libsqlite3_sys::sqlite3_finalize(self.0);
            }
            self.0 = std::ptr::null_mut();
        }
    }
}

/// Copy a TEXT column before the next `step` or `blob_open` invalidates it.
unsafe fn sqlite_column_text(
    stmt: *mut libsqlite3_sys::sqlite3_stmt,
    index: i32,
) -> Option<String> {
    let ptr = unsafe { libsqlite3_sys::sqlite3_column_text(stmt, index) };
    if ptr.is_null() {
        return None;
    }
    unsafe { std::ffi::CStr::from_ptr(ptr.cast()) }
        .to_str()
        .ok()
        .map(str::to_owned)
}

/// Byte length of one stored TEXT/BLOB cell, from the record header only.
fn stored_value_bytes(
    handle: *mut libsqlite3_sys::sqlite3,
    table: &str,
    column: &str,
    rowid: i64,
) -> Option<i32> {
    let db = std::ffi::CString::new("main").ok()?;
    let table = std::ffi::CString::new(table).ok()?;
    let column = std::ffi::CString::new(column).ok()?;
    let mut blob = std::ptr::null_mut();
    // SAFETY: `handle` is the exclusive live connection from `lock_handle`.
    // sqlite3_blob_open reads the record header without copying the payload.
    let rc = unsafe {
        libsqlite3_sys::sqlite3_blob_open(
            handle,
            db.as_ptr(),
            table.as_ptr(),
            column.as_ptr(),
            rowid,
            0,
            &mut blob,
        )
    };
    if rc != libsqlite3_sys::SQLITE_OK {
        if !blob.is_null() {
            // SAFETY: SQLite documented that a non-NULL *ppBlob on error is live.
            unsafe {
                let _ = libsqlite3_sys::sqlite3_blob_close(blob);
            }
        }
        return None;
    }
    // SAFETY: open succeeded; close before returning so the handle cannot leak.
    let bytes = unsafe { libsqlite3_sys::sqlite3_blob_bytes(blob) };
    unsafe {
        let _ = libsqlite3_sys::sqlite3_blob_close(blob);
    }
    Some(bytes)
}

fn format_offender_list(offenders: &[OversizedStoredValue]) -> String {
    let mut message = String::new();
    let mut index = 0;
    let mut first_group = true;
    while index < offenders.len() {
        let relation = offenders[index].relation;
        let column = offenders[index].column;
        if !first_group {
            message.push_str("; ");
        }
        first_group = false;
        message.push_str(&format!("{relation}.{column} for "));
        let mut first_row = true;
        while index < offenders.len()
            && offenders[index].relation == relation
            && offenders[index].column == column
        {
            if !first_row {
                message.push_str(", ");
            }
            first_row = false;
            message.push_str(&format!(
                "id {} ({} bytes)",
                offenders[index].id, offenders[index].bytes
            ));
            index += 1;
        }
    }
    message
}

fn format_sqlite_toobig_detail(
    original: &str,
    projected: &std::collections::HashSet<String>,
    report: ProbeReport,
) -> String {
    let ceiling = MAX_SQLITE_VALUE_BYTES;
    let mut message = format!(
        "the statement exceeded the {ceiling}-byte SQLite value ceiling. Original error: {original}."
    );
    // Projected-column match is label-only and therefore advisory: output
    // names are matched against physical column names with no relation
    // qualification. An unaliased stored column usually under-blames, which
    // is safe. An alias can over-blame — `WITH RECURSIVE d(body) AS (…)
    // SELECT body FROM d WHERE (SELECT count(id) FROM records) >= 0` yields
    // label `body` and promotes an unrelated oversized `records.body` to
    // Offending. The original engine detail is still present either way.
    // Collect (relation, id) pairs before the partition below consumes the
    // report. Ids are per relation, so the exclusion hint groups them by
    // relation instead of mixing id domains into one unqualified predicate.
    // Owned ids: the partition moves `report.offenders` while the hint
    // borrows these pairs.
    let offender_pairs: Vec<(&str, String)> = report
        .offenders
        .iter()
        .map(|offender| (offender.relation, offender.id.clone()))
        .collect();
    let offender_refs: Vec<(&str, &str)> = offender_pairs
        .iter()
        .map(|(relation, id)| (*relation, id.as_str()))
        .collect();
    let (projected_offenders, incidental): (Vec<_>, Vec<_>) = report
        .offenders
        .into_iter()
        .partition(|offender| projected.contains(&offender.column.to_ascii_lowercase()));
    if projected_offenders.is_empty() && incidental.is_empty() {
        message.push_str(
            " The cause may be a stored value or a computed intermediate; truncation cannot help if a stored value is responsible.",
        );
    } else {
        if !projected_offenders.is_empty() {
            message.push_str(" Offending: ");
            message.push_str(&format_offender_list(&projected_offenders));
            message.push('.');
        }
        if !incidental.is_empty() {
            message.push_str(" The statement also reads these oversized values: ");
            message.push_str(&format_offender_list(&incidental));
            message.push('.');
        }
        message.push_str(
            " These values cannot be read, truncated or matched by any query; select other columns or exclude these records.",
        );
        if let Some(hint) = sql_contract::oversized_exclusion_hint(&offender_refs) {
            message.push(' ');
            message.push_str(&hint);
        }
    }
    if let Some(reason) = report.incomplete {
        message.push(' ');
        message.push_str(reason);
        message.push('.');
    }
    message
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
    let mut connection = db.governed_pool().acquire().await?;
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
mod frozen_schema_cache_tests {
    use super::*;

    /// Statements the shipping validator admits. `EXPLAIN QUERY PLAN` is
    /// admitted by the classifier (it plans without running), so it belongs
    /// here alongside the reads.
    const ADMITTED: [&str; 10] = [
        "SELECT id FROM records",
        "SELECT ID FROM RECORDS",
        "SELECT count(*) FROM records",
        "SELECT e.id FROM content_events e JOIN records r ON r.id=e.record_id",
        "WITH visible AS (SELECT id FROM records) SELECT count(*) FROM visible",
        "EXPLAIN QUERY PLAN SELECT id FROM records",
        "SELECT id FROM vocabularies",
        "SELECT id FROM schema_config",
        "SELECT message_id FROM messages_awaiting_reply",
        "SELECT activity_id FROM agent_activity",
    ];

    /// Statements the shipping validator rejects: raw-qualified routes,
    /// TEMP/system probes, spoofed CTEs, unsafe functions, writes, duplicate
    /// labels, non-`?N` placeholders (I1), and syntax errors.
    const REJECTED: [&str; 17] = [
        "SELECT * FROM main.records",
        "SELECT raw.* FROM main.links AS raw",
        "WITH stolen AS (SELECT * FROM main.records) SELECT * FROM stolen",
        "SELECT * FROM temp._query_sql_principal",
        "SELECT * FROM sqlite_master",
        "WITH records AS (SELECT * FROM main.records) SELECT * FROM records",
        "SELECT * FROM pragma_table_info('records')",
        "SELECT * FROM records_fts_data",
        "SELECT randomblob(1000000000)",
        "SELECT load_extension('anything')",
        "SELECT json_group_array(body) FROM records",
        "DELETE FROM records",
        "SELECT id AS dup, name AS dup FROM records",
        "SELECT FROM WHERE",
        "SELECT id FROM records WHERE id = $1",
        "SELECT id FROM records WHERE id = ?",
        "SELECT id FROM records WHERE id = :name",
    ];

    fn rendered(result: Result<()>) -> String {
        result
            .map(|_| "ok".to_owned())
            .unwrap_or_else(|error| error.to_string())
    }

    /// Pre-change behavior: a throwaway connection per leg, batch text
    /// assembled inline. The oracle for "rejected before ⇒ rejected now,
    /// with the same message".
    fn fresh_validate(sql: &str) -> Result<()> {
        let statement = sql_contract::classify_single_read_statement(
            sql_contract::QuerySqlProfile::SqliteLocal,
            sql,
        )?;
        fresh_view_expansion(&statement)?;
        fresh_strict(&statement, |conn, statement| {
            prepare_under_authorizer(conn, statement, authorize_strict)
        })
    }

    fn fresh_view_expansion(statement: &str) -> Result<()> {
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

    fn fresh_strict<T>(
        statement: &str,
        operation: impl FnOnce(&rusqlite::Connection, &str) -> Result<T>,
    ) -> Result<T> {
        let conn = rusqlite::Connection::open_in_memory()
            .map_err(|e| contract_violation(format!("query_sql: validator setup failed: {e}")))?;
        conn.execute_batch(STRICT_LOGICAL_SCHEMA)
            .map_err(|e| contract_violation(format!("query_sql: validator setup failed: {e}")))?;
        operation(&conn, statement)
    }

    fn fresh_dependencies(sql: &str) -> Result<std::collections::BTreeSet<String>> {
        let statement = sql_contract::classify_single_read_statement(
            sql_contract::QuerySqlProfile::SqliteLocal,
            sql,
        )?;
        fresh_view_expansion(&statement)?;
        fresh_strict(&statement, |conn, statement| {
            let dependencies = std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::BTreeSet::<String>::new(),
            ));
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
            let prepared = conn.prepare(statement);
            conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
            let prepared = prepared.map_err(|error| {
                sql_contract::categorized_error(
                    QuerySqlErrorCategory::SyntaxOrType,
                    error.to_string(),
                )
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
        })
    }

    fn fresh_columns(sql: &str) -> Result<Vec<String>> {
        let statement = sql_contract::classify_single_read_statement(
            sql_contract::QuerySqlProfile::SqliteLocal,
            sql,
        )?;
        fresh_view_expansion(&statement)?;
        fresh_strict(&statement, |conn, statement| {
            conn.authorizer(Some(authorize_strict));
            let prepared = conn.prepare(statement);
            conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
            let prepared = prepared.map_err(|error| {
                sql_contract::categorized_error(
                    QuerySqlErrorCategory::SyntaxOrType,
                    error.to_string(),
                )
            })?;
            Ok(prepared
                .column_names()
                .into_iter()
                .map(str::to_owned)
                .collect())
        })
    }

    #[test]
    fn cached_batch_text_matches_old_style_assembly() {
        let ddl: String = DDL_STATEMENTS
            .iter()
            .map(|sql| format!("{sql};\n"))
            .collect();
        assert_eq!(frozen_ddl_batch(), ddl.as_str());
        assert_eq!(frozen_temp_contract_batch(), temp_contract().as_str());
    }

    #[test]
    fn cached_validation_matches_fresh_connections_exactly() {
        for sql in ADMITTED.into_iter().chain(REJECTED) {
            assert_eq!(
                rendered(validate(sql)),
                rendered(fresh_validate(sql)),
                "{sql}"
            );
        }
    }

    #[test]
    fn blocked_probes_name_the_catalog_fix() {
        let probe = rendered(validate("SELECT * FROM sqlite_master"));
        assert!(probe.contains("catalog introspection"), "{probe}");
        assert!(probe.contains("FROM catalog_columns"), "{probe}");
        let pragma = rendered(validate("SELECT * FROM pragma_table_info('records')"));
        assert!(pragma.contains("catalog introspection"), "{pragma}");
        let mapped = rendered(validate("SELECT * FROM relationships"));
        assert!(mapped.contains("effective_relationships"), "{mapped}");
        let unmapped = rendered(validate("SELECT * FROM member_contexts"));
        assert!(
            unmapped.contains("Queryable relations on sqlite-local:"),
            "{unmapped}"
        );
        // Function denies belong to the allowlist repair, not this one.
        let func = rendered(validate("SELECT GROUP_CONCAT(name) FROM records"));
        assert!(func.contains("GROUP_CONCAT"), "{func}");
        assert!(!func.contains("catalog introspection"), "{func}");
        assert!(!func.contains("Queryable relations on"), "{func}");
        // Raw-qualified and spoofed routes keep their engine detail alone.
        let raw = rendered(validate("SELECT * FROM main.records"));
        assert!(!raw.contains("not a queryable"), "{raw}");
    }

    #[test]
    fn strict_catalog_tables_match_generated_views() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(STRICT_LOGICAL_SCHEMA).unwrap();
        let columns_of = |conn: &rusqlite::Connection, table: &str| {
            conn.prepare(&format!("SELECT name FROM pragma_table_info('{table}')"))
                .unwrap()
                .query_map([], |row| row.get::<_, String>(0))
                .unwrap()
                .collect::<std::result::Result<Vec<String>, _>>()
                .unwrap()
        };
        let strict_relations = columns_of(&conn, "catalog_relations");
        let strict_columns = columns_of(&conn, "catalog_columns");
        // A view cannot shadow the strict table of the same name, so drop
        // the tables before installing the generated views.
        conn.execute_batch("DROP TABLE catalog_relations; DROP TABLE catalog_columns;")
            .unwrap();
        for statement in sql_contract::catalog_view_statements(true) {
            conn.execute_batch(&statement).unwrap();
        }
        assert_eq!(columns_of(&conn, "catalog_relations"), strict_relations);
        assert_eq!(columns_of(&conn, "catalog_columns"), strict_columns);
        for (table, strict) in [
            ("catalog_relations", strict_relations),
            ("catalog_columns", strict_columns),
        ] {
            assert_eq!(
                strict,
                sql_contract::LOGICAL_RELATIONS
                    .iter()
                    .find(|r| r.name == table)
                    .unwrap()
                    .columns
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>(),
                "{table}"
            );
        }
    }

    #[test]
    fn cached_dependencies_and_columns_match_fresh_connections() {
        for sql in ADMITTED {
            let cached = validated_relation_dependencies(sql)
                .map(|set| set.into_iter().collect::<Vec<_>>())
                .map_err(|error| error.to_string());
            let fresh = fresh_dependencies(sql)
                .map(|set| set.into_iter().collect::<Vec<_>>())
                .map_err(|error| error.to_string());
            assert_eq!(cached, fresh, "dependencies {sql}");
            let cached = validated_output_columns(sql).map_err(|error| error.to_string());
            let fresh = fresh_columns(sql).map_err(|error| error.to_string());
            assert_eq!(cached, fresh, "columns {sql}");
        }
        for sql in REJECTED {
            let cached = validated_relation_dependencies(sql)
                .map(|set| set.into_iter().collect::<Vec<_>>())
                .map_err(|error| error.to_string());
            let fresh = fresh_dependencies(sql)
                .map(|set| set.into_iter().collect::<Vec<_>>())
                .map_err(|error| error.to_string());
            assert_eq!(cached, fresh, "rejected dependencies {sql}");
        }
    }

    #[test]
    fn positional_placeholders_pass_and_others_name_the_repair() {
        // I1 (E1 M2): `?N` is the only admitted spelling. A `$1`/`:x` inside
        // a string literal is data and stays admitted.
        validate("SELECT id FROM records WHERE id = ?1").unwrap();
        validate("SELECT id FROM records WHERE name = '$1'").unwrap();
        let bare = validate("SELECT id FROM records WHERE id = ?").unwrap_err();
        assert!(
            bare.to_string()
                .contains("Postgres `?`/`?|`/`?&` operators"),
            "missing jsonb note: {bare}"
        );
        for sql in [
            "SELECT id FROM records WHERE id = $1",
            "SELECT id FROM records WHERE id = ?0",
            "SELECT id FROM records WHERE id = :name",
            "SELECT id FROM records WHERE id = @name",
            "SELECT id FROM records WHERE id = $name",
        ] {
            let error = validate(sql).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("use positional `?N` placeholders"),
                "{sql}: missing repair: {error}"
            );
        }
    }

    #[test]
    fn widened_functions_validate_and_dropped_ones_name_the_repair() {
        // I2: preparing proves SQLite itself executes the widened set.
        validate("SELECT lower('AbC'), upper('AbC') FROM records").unwrap();
        validate("SELECT trim(' x '), replace('aab', 'a', 'c') FROM records").unwrap();
        // I2 review: the two-argument `trim(x, chars)` matches Postgres
        // `btrim(x, chars)` exactly, so it validates on every engine.
        validate("SELECT trim('xxhelloxx', 'x') FROM records").unwrap();
        validate("SELECT substr('hello', 2, 3) FROM records").unwrap();
        validate("SELECT coalesce(NULL, 'z'), nullif('a', 'a') FROM records").unwrap();
        validate("SELECT abs(-3), length('hey'), round(1.5) FROM records").unwrap();
        validate("SELECT avg(id), count(*), sum(id), min(id), max(id) FROM records").unwrap();
        validate("SELECT rank() OVER (ORDER BY id) FROM records").unwrap();
        validate("SELECT CASE WHEN id = 1 THEN 'one' ELSE 'other' END FROM records").unwrap();
        validate("SELECT CAST(id AS TEXT) FROM records").unwrap();
        // LIKE (either spelling) still validates.
        validate("SELECT id FROM records WHERE name LIKE 'conf:%'").unwrap();
        validate("SELECT id FROM records WHERE lower(name) LIKE 'conf:%'").unwrap();
        for (sql, repair) in [
            (
                "SELECT instr(body, 'x') FROM records",
                "use substr() or LIKE",
            ),
            ("SELECT glob('*', name) FROM records", "use LIKE"),
            (
                "SELECT date(created_at) FROM records",
                "M1 timestamp columns",
            ),
            (
                "SELECT json_type(body) FROM records",
                "facet_values, facet_observations",
            ),
            ("SELECT typeof(name) FROM records", "catalog column types"),
            // Richard 25 Sep: I2 dropped functions stay rejected ad-hoc even
            // though already-stored governed SQL keeps the legacy allowance.
            (
                "SELECT strftime('%w', 'now') FROM records",
                "M1 timestamp columns",
            ),
            (
                "SELECT julianday('now') FROM records",
                "M1 timestamp columns",
            ),
            (
                "SELECT group_concat(name) FROM records",
                "aggregate client-side",
            ),
            (
                "SELECT group_concat(name) FROM records",
                "aggregate client-side",
            ),
            ("SELECT total(id) FROM records", "use sum"),
            ("SELECT floor(value) FROM records", "CAST(x AS INTEGER)"),
            ("SELECT char_length(name) FROM records", "use length"),
            ("SELECT greatest(a, b) FROM records", "CASE"),
            (
                "SELECT round(avg(id), 2) FROM records",
                "catalog numeric type",
            ),
            // I2 review: quoting the name bypasses nothing — the shared
            // classifier runs the same dropped-name and arity checks on
            // `"name"(`, `` `name` `` and `[name](` calls.
            (
                "SELECT \"round\"(1.5, 2) FROM records",
                "catalog numeric type",
            ),
            (
                "SELECT \"instr\"(body, 'x') FROM records",
                "use substr() or LIKE",
            ),
        ] {
            let error = validate(sql).unwrap_err().to_string();
            assert!(error.contains(repair), "{sql}: missing repair: {error}");
        }
    }

    #[test]
    fn governed_validation_builds_schemas_at_most_once() {
        // Mirror a governed call's validation footprint: validate() plus the
        // dependency pass, over admitted and rejected statements alike. The
        // build counts are thread-local like the caches, so this asserts the
        // current thread reuses its validators — other threads warming up
        // their own cannot move these counts.
        fn builds() -> (usize, usize) {
            (
                FROZEN_VALIDATOR_BUILDS.with(|builds| builds.get()),
                STRICT_VALIDATOR_BUILDS.with(|builds| builds.get()),
            )
        }
        let footprint = |sql: &str| {
            let _ = validate(sql);
            let _ = validated_relation_dependencies(sql);
            let _ = validated_output_columns(sql);
        };
        for sql in ADMITTED.into_iter().chain(REJECTED) {
            footprint(sql);
        }
        let warm = builds();
        for sql in ADMITTED.into_iter().chain(REJECTED) {
            footprint(sql);
        }
        assert_eq!(builds(), warm, "validators rebuilt after warm-up");
    }
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
    fn temp_contract_comments_survive_naive_semicolon_splitting() {
        // Installers run `temp_contract().split(';')`, which is not
        // comment-aware, unlike `execute_batch`. Any semicolon that is not
        // the last non-whitespace character of its comment line leaves a
        // following fragment starting with bare prose, which fails every
        // query_sql call with a syntax error. A trailing semicolon is
        // harmless: the next fragment still opens with a comment or a
        // statement.
        for line in temp_contract().lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("--") {
                assert!(
                    trimmed
                        .split(';')
                        .skip(1)
                        .all(|after| after.trim().is_empty()),
                    "semicolon not at end of contract comment line: {line}"
                );
            }
        }
    }

    #[test]
    fn additive_relation_keeps_the_saved_query_breaking_epoch() {
        assert_eq!(sql_contract::LOGICAL_CATALOG_REVISION, 4);
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
        assert_eq!(activity.semantic_version, 3);
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
    use crate::store::{
        add_link, append, create_record, delete_record, set_facet, update_record, AppendSpec,
    };

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
    const TOOBIG_ALICE_ID: &str = "9e795000-0000-4000-8000-00000f000000";
    const TOOBIG_BEA_ID: &str = "9e795000-0000-4000-8000-000010000000";
    const TOOBIG_ALICE_BYTES: usize = 264_975;
    const TOOBIG_BEA_BYTES: usize = 479_257;
    const TOOBIG_ALICE_ATTACHMENT_ID: &str = "9e795000-0000-4000-8000-000011000000";
    const TOOBIG_BEA_ATTACHMENT_ID: &str = "9e795000-0000-4000-8000-000012000000";
    const TOOBIG_EXTERNAL_ATTACHMENT_ID: &str = "9e795000-0000-4000-8000-000013000000";
    const TOOBIG_EXTERNAL_BLOB_ID: &str = "9e795000-0000-4000-8000-000014000000";
    const COMPUTED_TOOBIG_SQL: &str = "WITH RECURSIVE d(s) AS (
         SELECT 'x' UNION ALL SELECT s||s FROM d WHERE length(s) < 1000000
       ) SELECT s FROM d";

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
            QueryPrincipal::authenticated("alice", true),
            QueryPrincipal::authenticated("bea", true),
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

    /// Hold every governed-pool slot but one so the queries below must reuse a
    /// single physical connection. This is the Tier 1.2 form of the old
    /// hold-four-of-five write-pool pinning: governed TEMP state now lives on
    /// the governed pool, so pinning write slots would no longer force any
    /// governed reuse. Sized from the configured pool size so the pinning
    /// stays exact under `NATIVE_CE_GOVERNED_SQL_POOL_SIZE` overrides.
    async fn hold_all_but_one_governed_slot(
        db: &Db,
    ) -> Vec<sqlx::pool::PoolConnection<sqlx::Sqlite>> {
        let mut held = Vec::new();
        for _ in 0..crate::db::governed_sql_pool_size().max(1) - 1 {
            held.push(db.governed_pool().acquire().await.unwrap());
        }
        held
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
    async fn workspace_filter_matches_governed_relations_and_exclusions() {
        let (db, alice, bea) = protected_fixture().await;
        let attribution = "9e795000-0000-4000-8000-000015000000";
        let unit = "9e795000-0000-4000-8000-000016000000";
        let unit_child = "9e795000-0000-4000-8000-000017000000";
        for (id, record_type, kind) in [
            (attribution, "Annotation", "attribution"),
            (unit, "Entity", "semantic-unit"),
            (unit_child, "Document", "attachment"),
        ] {
            // These are projection fixtures. The public record writer
            // correctly reserves attribution and semantic-unit creation for
            // their atomic aggregate APIs.
            sqlx::query(
                "INSERT INTO records(id, type, kind, name, home_id, policy_anchor_id) \
                 VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(id)
            .bind(record_type)
            .bind(kind)
            .bind(kind)
            .bind(crate::schema::ROOT_RECORD_ID)
            .bind(COMMON_ID)
            .execute(db.write_pool())
            .await
            .unwrap();
        }
        for (id, source, target) in [
            ("attribution-bearer", attribution, COMMON_ID),
            ("unit-child", unit_child, unit),
        ] {
            sqlx::query(
                "INSERT INTO links(id, source_id, target_id, relationship) \
                 VALUES (?, ?, ?, 'part_of')",
            )
            .bind(id)
            .bind(source)
            .bind(target)
            .execute(db.write_pool())
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO content_events(id, record_id, type, payload, actor, \
             causal_envelope_version, causal_status) \
             VALUES ('9e795000-0000-4000-8000-000019000000', ?, \
             'record.created', '{}', 'test:projection', 1, 'complete')",
        )
        .bind(unit)
        .execute(db.write_pool())
        .await
        .unwrap();
        let receipt_event_id = "9e795000-0000-4000-8000-000019000001";
        sqlx::query(
            "INSERT INTO content_events(id, record_id, type, payload, actor, \
             causal_envelope_version, causal_status) \
             VALUES (?, ?, 'receipt.committed.v1', '{}', 'test:projection', 1, 'complete')",
        )
        .bind(receipt_event_id)
        .bind(COMMON_ID)
        .execute(db.write_pool())
        .await
        .unwrap();
        let (creation_event_id, creation_seq): (String, i64) = sqlx::query_as(
            "SELECT id, seq FROM content_events WHERE record_id = ? ORDER BY seq LIMIT 1",
        )
        .bind(unit)
        .fetch_one(db.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO semantic_units(unit_id, authority_bearer_record_id, creation_event_id, creation_event_seq, created_at) \
             VALUES (?, ?, ?, ?, '2026-09-23T00:00:00.000Z')"
        ).bind(unit).bind(COMMON_ID).bind(creation_event_id).bind(creation_seq)
            .execute(db.write_pool()).await.unwrap();

        // SAFETY: this test models the hosted ingress setting activity_read
        // for an authenticated member. Record visibility must remain governed
        // by the same view regardless of that capability.
        let alice_activity =
            unsafe { QueryPrincipal::activity_reader_unchecked("alice", Vec::new(), true) };
        for principal in [alice, bea, alice_activity] {
            let filtered = db
                .filtered_workspace_index(principal.clone())
                .await
                .unwrap()
                .unwrap();
            let governed = |sql: &'static str, principal: QueryPrincipal| async {
                let result = query_sql(&db, principal, sql).await.unwrap();
                first_strings(&result).into_iter().collect::<HashSet<_>>()
            };
            let expected_records = governed("SELECT id FROM records", principal.clone()).await;
            let expected_facets = governed("SELECT id FROM facet_values", principal.clone()).await;
            let expected_links = governed("SELECT id FROM links", principal.clone()).await;
            let expected_events = query_sql(
                &db,
                principal.clone(),
                "SELECT id, type FROM content_events",
            )
            .await
            .unwrap()
            .rows
            .into_iter()
            .map(|row| {
                let row = row.as_object().unwrap();
                (
                    row["id"].as_str().unwrap().to_string(),
                    row["type"].as_str().unwrap().to_string(),
                )
            })
            .collect::<HashSet<_>>();
            assert_eq!(
                filtered.records.keys().cloned().collect::<HashSet<_>>(),
                expected_records
            );
            assert_eq!(
                filtered.facets.keys().cloned().collect::<HashSet<_>>(),
                expected_facets
            );
            assert_eq!(
                filtered.links.keys().cloned().collect::<HashSet<_>>(),
                expected_links
            );
            assert_eq!(
                filtered
                    .content_events
                    .iter()
                    .map(|e| (e.id.clone(), e.event_type.clone()))
                    .collect::<HashSet<_>>(),
                expected_events
            );
            assert!(expected_events
                .contains(&(receipt_event_id.to_string(), "record.updated".to_string())));
            assert!(!filtered.records.contains_key(attribution));
            assert!(!filtered.records.contains_key(unit));
            assert!(!filtered.records.contains_key(unit_child));
            assert!(!filtered.links.contains_key("attribution-bearer"));
            assert!(!filtered.links.contains_key("unit-child"));
            let epoch: i64 =
                sqlx::query_scalar("SELECT epoch FROM authorization_revision WHERE id = 1")
                    .fetch_one(db.pool())
                    .await
                    .unwrap();
            assert_eq!(filtered.authorization_epoch, epoch);
            let seq: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM content_events")
                .fetch_one(db.pool())
                .await
                .unwrap();
            assert_eq!(filtered.content_seq, seq);
        }
    }

    /// Tier 1.4: the (epoch, unit fence) key. A derived artifact attached to
    /// an un-unitized `Entity`/`semantic-unit` envelope is visible; the later
    /// unit.created projection flips it hidden with the authorization epoch
    /// unmoved — the stale risk a pure-epoch key would serve. Every
    /// transition below runs through supported write seams (each `append` is
    /// one write transaction), so the interleaving is reachable, not
    /// constructed. The oracle is governed `query_sql` itself, compared per
    /// principal at every phase, plus a narrowing epoch bump and the
    /// activity-reader shape.
    ///
    /// Seam distinction this relies on: the MCP-facing `create_record`
    /// writer reserves kind `semantic-unit`, but the public lower-level
    /// event seam (`store::append`) admits both the envelope record.created
    /// and unit.created.v1 — only attribution, claims, receipts, and
    /// type-corrections are rejected there (`reject_public_runtime_event`,
    /// `reject_public_governed_attribution_in`).
    #[tokio::test]
    async fn visible_set_cache_invalidates_on_unit_fence_without_epoch_move() {
        let (db, alice, bea) = protected_fixture().await;
        let envelope = "9e796100-0000-4000-8000-000001000000";
        let derived = "9e796100-0000-4000-8000-000002000000";
        // SAFETY: this test models the hosted ingress setting activity_read
        // for an authenticated member. Record visibility must remain governed
        // by the same view regardless of that capability.
        let alice_activity =
            unsafe { QueryPrincipal::activity_reader_unchecked("alice", Vec::new(), true) };
        append(
            &db,
            AppendSpec {
                record_id: envelope.to_string(),
                event_type: "record.created".into(),
                payload: json!({
                    "type": "Entity",
                    "kind": "semantic-unit",
                    "name": "tier14-envelope",
                    "home_id": crate::schema::ROOT_RECORD_ID,
                }),
                actor: None,
            },
        )
        .await
        .unwrap();
        create_record(
            &db,
            json!({
                "id": derived,
                "type": "Document",
                "kind": "attachment",
                "name": "tier14-derived",
                "home_id": crate::schema::ROOT_RECORD_ID,
            }),
        )
        .await
        .unwrap();
        // Anchor the derived where both principals may see it, whatever the
        // creation planner assigned.
        let derived_anchor: String =
            sqlx::query_scalar("SELECT policy_anchor_id FROM records WHERE id = ?")
                .bind(derived)
                .fetch_one(db.pool())
                .await
                .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            &derived_anchor,
            vec![
                AllowEntry::account("alice", Capability::View),
                AllowEntry::account("bea", Capability::View),
            ],
        )
        .await
        .unwrap();
        add_link(
            &db,
            LinkAddedPayload {
                id: Some("tier14-child".to_string()),
                source_id: derived.to_string(),
                target_id: envelope.to_string(),
                relationship: "part_of".to_string(),
                note: None,
            },
        )
        .await
        .unwrap();
        let governed = |principal: QueryPrincipal| async {
            first_strings(
                &query_sql(&db, principal, "SELECT id FROM records")
                    .await
                    .unwrap(),
            )
            .into_iter()
            .collect::<HashSet<_>>()
        };
        let epoch_of = || async {
            sqlx::query_scalar::<_, i64>("SELECT epoch FROM authorization_revision WHERE id = 1")
                .fetch_one(db.pool())
                .await
                .unwrap()
        };
        // Phase 1: envelope un-unitized, derived visible to both principals.
        let epoch_before = epoch_of().await;
        let first_timing = crate::mcp::request_timing::RequestTiming::new();
        first_timing.enable_visible_set_lookups();
        let first = first_timing
            .scope(workspace_visible_set(&db, alice.clone()))
            .await
            .unwrap();
        assert_eq!(
            first_timing.visible_set_lookups(),
            Some(crate::mcp::request_timing::VisibleSetLookups { hits: 0, misses: 1 })
        );
        assert!(first.ids.contains(derived));
        assert!(!first.ids.contains(envelope));
        assert_eq!(*first.ids, governed(alice.clone()).await);
        assert_eq!(db.visible_set_cache_stats(), (0, 1));
        let second_timing = crate::mcp::request_timing::RequestTiming::new();
        second_timing.enable_visible_set_lookups();
        let second = second_timing
            .scope(workspace_visible_set(&db, alice.clone()))
            .await
            .unwrap();
        assert_eq!(
            second_timing.visible_set_lookups(),
            Some(crate::mcp::request_timing::VisibleSetLookups { hits: 1, misses: 0 })
        );
        assert_eq!(second.ids, first.ids);
        assert_eq!(db.visible_set_cache_stats(), (1, 1));
        // Second principal and activity reader hold their own entries; the
        // reader's set equals the member's (activity_read gates only the
        // activity views, never the visible set).
        let bea_first = workspace_visible_set(&db, bea.clone()).await.unwrap();
        assert!(bea_first.ids.contains(derived));
        assert_eq!(*bea_first.ids, governed(bea.clone()).await);
        let activity_first = workspace_visible_set(&db, alice_activity.clone())
            .await
            .unwrap();
        assert_eq!(activity_first.ids, first.ids);
        assert_eq!(db.visible_set_cache_stats(), (1, 3));
        // Phase 2: unitize the envelope through the same public seam — its
        // own write transaction, after the link committed. The live set
        // changes; the epoch must not.
        append(
            &db,
            AppendSpec {
                record_id: envelope.to_string(),
                event_type: "unit.created.v1".into(),
                payload: json!({
                    "semantic_contract_version": "native.freshness-kernel.v1",
                    "authority_bearer_record_id": COMMON_ID,
                    "label": "tier14-unit",
                }),
                actor: Some("test:unit".to_string()),
            },
        )
        .await
        .unwrap();
        assert_eq!(epoch_of().await, epoch_before);
        let unit_max: i64 =
            sqlx::query_scalar("SELECT COALESCE(MAX(creation_event_seq), 0) FROM semantic_units")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert!(unit_max > 0);
        // The moved fence is a miss, and the fresh answer hides the derived.
        let third = workspace_visible_set(&db, alice.clone()).await.unwrap();
        assert!(!third.ids.contains(derived));
        assert_eq!(*third.ids, governed(alice.clone()).await);
        assert_eq!(db.visible_set_cache_stats(), (1, 4));
        let fourth = workspace_visible_set(&db, alice.clone()).await.unwrap();
        assert_eq!(fourth.ids, third.ids);
        assert_eq!(db.visible_set_cache_stats(), (2, 4));
        let bea_second = workspace_visible_set(&db, bea.clone()).await.unwrap();
        assert!(!bea_second.ids.contains(derived));
        assert_eq!(*bea_second.ids, governed(bea.clone()).await);
        // Phase 3: narrowing epoch bump revokes bea without leaking.
        replace_explicit_policy(
            &db,
            "test:policy",
            COMMON_ID,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();
        let narrowed_bea = workspace_visible_set(&db, bea.clone()).await.unwrap();
        assert!(!narrowed_bea.ids.contains(COMMON_ID));
        assert!(!narrowed_bea.ids.contains(derived));
        assert_eq!(*narrowed_bea.ids, governed(bea.clone()).await);
        let narrowed_alice = workspace_visible_set(&db, alice.clone()).await.unwrap();
        assert!(narrowed_alice.ids.contains(COMMON_ID));
        assert_eq!(*narrowed_alice.ids, governed(alice.clone()).await);
        db.close().await;
    }

    /// Tier 1.4 fixture-C measurement and agreement proof. Opens a caller
    /// supplied COPY (never the source) via `GSQL_TIER14_COPY`; returns
    /// immediately when unset so CI without the fixture stays green. Asserts
    /// the cached set equals governed `query_sql` on live-shaped data and
    /// prints miss/hit timings plus the cached byte size (`--nocapture`).
    /// Timings are reported, never asserted — the host is shared and noisy.
    #[tokio::test]
    async fn visible_set_cache_fixture_c_agreement_and_timing() {
        let copy = match std::env::var("GSQL_TIER14_COPY") {
            Ok(path) => path,
            Err(_) => {
                eprintln!("skipping fixture-C measurement: GSQL_TIER14_COPY unset");
                return;
            }
        };
        // Non-migrating open: the export predates the current engine schema
        // and the lens needs only long-stable projection tables. The copy is
        // expendable; the source must never be opened in place.
        let db = crate::open_database_at(std::path::Path::new(&copy))
            .await
            .unwrap();
        let principal =
            QueryPrincipal::authenticated("acct_404434c8f87443c88b162247bb53bbc8", true);
        let timed = |label: &str, millis: f64| {
            eprintln!("tier14 fixture-C {label}: {millis:.2}ms");
        };
        let start = std::time::Instant::now();
        let miss = workspace_visible_set(&db, principal.clone()).await.unwrap();
        timed(
            "miss (full evaluation)",
            start.elapsed().as_secs_f64() * 1000.0,
        );
        // Paged oracle: one governed statement serves at most MAX_ROWS
        // (1,000) rows while fixture C holds ~4.6k visible records. Keyset
        // pagination (`WHERE id > last`) terminates on the empty page, so a
        // short page — whatever caps it — can never end the walk early.
        // Page shape, not semantics.
        let mut governed = HashSet::new();
        let mut last = String::new();
        loop {
            let page = first_strings(
                &query_sql(
                    &db,
                    principal.clone(),
                    &format!(
                        "SELECT id FROM records WHERE id > '{last}' \
                         ORDER BY id LIMIT {}",
                        sql_contract::MAX_ROWS,
                    ),
                )
                .await
                .unwrap(),
            );
            if page.is_empty() {
                break;
            }
            last = page.iter().max().unwrap().clone();
            governed.extend(page);
        }
        // Bounded diff reporter: fixture-C sets are thousands of ids, so a
        // bare assert_eq would dump megabytes. Report counts plus samples.
        fn assert_same_set(context: &str, left: &HashSet<String>, right: &HashSet<String>) {
            if left != right {
                let mut only_left: Vec<&str> = left.difference(right).map(String::as_str).collect();
                let mut only_right: Vec<&str> =
                    right.difference(left).map(String::as_str).collect();
                only_left.sort_unstable();
                only_right.sort_unstable();
                panic!(
                    "{context}: left={} right={} only_left={:?} only_right={:?}",
                    left.len(),
                    right.len(),
                    &only_left[..only_left.len().min(10)],
                    &only_right[..only_right.len().min(10)],
                );
            }
        }
        assert_same_set("fixture-C miss vs governed", &miss.ids, &governed);
        eprintln!(
            "tier14 fixture-C cached ids: {} bytes over {} records",
            miss.ids.iter().map(|id| id.len()).sum::<usize>(),
            miss.ids.len()
        );
        let mut hits = Vec::new();
        for _ in 0..5 {
            let start = std::time::Instant::now();
            let hit = workspace_visible_set(&db, principal.clone()).await.unwrap();
            hits.push(start.elapsed().as_secs_f64() * 1000.0);
            assert_same_set("fixture-C hit vs governed", &hit.ids, &governed);
        }
        hits.sort_by(|a, b| a.partial_cmp(b).unwrap());
        timed("hit min", hits[0]);
        timed("hit median", hits[hits.len() / 2]);
        assert_eq!(db.visible_set_cache_stats(), (5, 1));
        db.close().await;
    }

    #[tokio::test]
    async fn workspace_filter_rebuilds_after_epoch_narrows_visibility() {
        let (db, alice, _) = protected_fixture().await;
        let before = db
            .filtered_workspace_index(alice.clone())
            .await
            .unwrap()
            .unwrap();
        assert!(before.records.contains_key(COMMON_ID));
        let old_epoch = before.authorization_epoch;
        replace_explicit_policy(
            &db,
            "test:policy",
            COMMON_ID,
            vec![AllowEntry::account("bea", Capability::View)],
        )
        .await
        .unwrap();
        let after = db
            .filtered_workspace_index(alice.clone())
            .await
            .unwrap()
            .unwrap();
        assert!(after.authorization_epoch > old_epoch);
        assert!(!after.records.contains_key(COMMON_ID));
        assert!(!after.links.contains_key("alice-common"));
        let governed = query_sql(&db, alice, "SELECT id FROM records")
            .await
            .unwrap();
        assert_eq!(
            after.records.keys().cloned().collect::<HashSet<_>>(),
            first_strings(&governed).into_iter().collect::<HashSet<_>>()
        );
    }

    #[tokio::test]
    async fn workspace_filter_repairs_subtree_anchor_and_relationship_only_changes() {
        let (db, alice, _) = protected_fixture().await;
        let child = "9e795000-0000-4000-8000-000020000000";
        let grandchild = "9e795000-0000-4000-8000-000021000000";
        create_record(
            &db,
            json!({
                "id": child, "type": "Collection", "kind": "folder", "name": "branch",
                "home_id": crate::schema::ROOT_RECORD_ID
            }),
        )
        .await
        .unwrap();
        create_record(
            &db,
            json!({
                "id": grandchild, "type": "Document", "kind": "note", "name": "descendant",
                "home_id": child
            }),
        )
        .await
        .unwrap();
        let before = db
            .filtered_workspace_index(alice.clone())
            .await
            .unwrap()
            .unwrap();
        assert!(before.records.contains_key(grandchild));

        // The policy replacement changes a subtree of projected anchors, but
        // its content event names only the child, leaving the held grandchild
        // stale until a full rebuild.
        replace_explicit_policy(
            &db,
            "test:policy",
            child,
            vec![AllowEntry::account("bea", Capability::View)],
        )
        .await
        .unwrap();
        let narrowed = db
            .filtered_workspace_index(alice.clone())
            .await
            .unwrap()
            .unwrap();
        assert!(narrowed.authorization_epoch > before.authorization_epoch);
        assert!(!narrowed.records.contains_key(child));
        assert!(!narrowed.records.contains_key(grandchild));
        let relationship_before: i64 =
            sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM relationship_events")
                .fetch_one(db.pool())
                .await
                .unwrap();

        // The index is now settled at the new policy epoch. The next write
        // changes only the relationship stream; no policy or record write
        // follows before the second snapshot.
        let mut registry = crate::mcp::ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        let asserted = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "manage_relationships",
                json!({
                    "action":"assert", "relationship_type":"relates_to",
                    "endpoints":[
                        {"role":"participant", "record_id":ALICE_PRIVATE_ID},
                        {"role":"participant", "record_id":COMMON_ID}
                    ],
                    "idempotency_key":"workspace-index-fence"
                }),
            )
            .await
            .unwrap();
        let link_id = format!(
            "rel:{}:{}",
            asserted["relationship_origin_db_id"].as_str().unwrap(),
            asserted["relationship_id"].as_str().unwrap()
        );

        let after = db
            .filtered_workspace_index(alice.clone())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.authorization_epoch, narrowed.authorization_epoch);
        assert_eq!(after.content_seq, narrowed.content_seq);
        assert!(!after.records.contains_key(child));
        assert!(!after.records.contains_key(grandchild));
        assert!(after.links.contains_key(&link_id));
        let relationship_after: i64 =
            sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM relationship_events")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert!(relationship_after > relationship_before);
        let governed_records = query_sql(&db, alice.clone(), "SELECT id FROM records")
            .await
            .unwrap();
        let governed_links = query_sql(&db, alice, "SELECT id FROM links").await.unwrap();
        assert_eq!(
            after.records.keys().cloned().collect::<HashSet<_>>(),
            first_strings(&governed_records)
                .into_iter()
                .collect::<HashSet<_>>()
        );
        assert_eq!(
            after.links.keys().cloned().collect::<HashSet<_>>(),
            first_strings(&governed_links)
                .into_iter()
                .collect::<HashSet<_>>()
        );
    }

    #[tokio::test]
    async fn workspace_filter_signals_governed_fallback_above_cap() {
        let db = crate::create_database(":memory:").await.unwrap();
        let id = "9e795000-0000-4000-8000-000018000000";
        create_record(
            &db,
            json!({
                "id": id, "type": "Document", "kind": "note", "name": "large",
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
        let large_summary = "x".repeat(25 * 1024 * 1024);
        sqlx::query("UPDATE records SET summary = ? WHERE id = ?")
            .bind(large_summary)
            .bind(id)
            .execute(db.write_pool())
            .await
            .unwrap();
        let built = crate::workspace_index::build_on(db.pool()).await.unwrap();
        assert!(!built.within_cap(crate::workspace_index::MAX_INDEX_BYTES));
        let alice = QueryPrincipal::authenticated("alice", true);
        assert!(db
            .filtered_workspace_index(alice.clone())
            .await
            .unwrap()
            .is_none());
        assert!(!db.workspace_index_built_for_tests().await);
        let governed = query_sql(
            &db,
            alice,
            &format!("SELECT id FROM records WHERE id = '{id}'"),
        )
        .await
        .unwrap();
        assert_eq!(first_strings(&governed), [id]);
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
            true,
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

        let caller = QueryPrincipal::authenticated("alice", true);
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

        // Pin governed work to one available slot so restricted SQL must reuse
        // the same physical connection; the following ordinary FTS query runs
        // on the write pool, which never sees governed TEMP state at all.
        // This guards against leaked TEMP views shadowing main relations.
        let held_connections = hold_all_but_one_governed_slot(&db).await;
        // SAFETY: test-only construction of the trusted-local fixture.
        let trusted = unsafe { QueryPrincipal::trusted_local_unchecked("local") };
        let authenticated = QueryPrincipal::authenticated("local", true);
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
            crate::query::fts::search(&db, "local", true, "localbypassterm", &opts)
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

    /// Frozen pre-per-anchor fold, renamed so it can sit beside the shipping
    /// TEMP contract in one snapshot. This text is the oracle for the Tier 1.5
    /// fold change: it is the exact `_query_sql_visible_records` view logic
    /// the per-anchor rewrite replaces, with only the temp object names
    /// changed (`_query_sql_visible_records` -> `_qs_legacy_visible_records`,
    /// `records`/`links` -> `_qs_legacy_records`/`_qs_legacy_links`). Any
    /// change that alters membership fails the comparison below. Do not update
    /// this text when the shipping view changes; that disagreement is the
    /// signal.
    const LEGACY_FOLD_CONTRACT: &str = r#"
CREATE TEMP VIEW IF NOT EXISTS _qs_legacy_visible_records AS
SELECT r.id
FROM main.records AS r
JOIN temp._query_sql_authorization_subjects AS resolved
  ON resolved.record_id = r.id
JOIN main.records AS authorization_subject
  ON authorization_subject.id = resolved.subject_id
CROSS JOIN temp._query_sql_principal AS principal
WHERE r.deleted_at IS NULL
  AND NOT (r.type = 'Annotation' AND r.kind IN ('attribution','acknowledgement'))
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
             AND entry.subject_id = 'native:members'
             AND principal.is_member = 1)
            OR
            (entry.subject_kind = 'account'
             AND entry.subject_id = principal.account_id)
          )
      )));

CREATE TEMP VIEW IF NOT EXISTS _qs_legacy_records AS
SELECT r.id
FROM main.records AS r
JOIN temp._qs_legacy_visible_records AS visible ON visible.id = r.id
LEFT JOIN temp._qs_legacy_visible_records AS parent_visible
       ON parent_visible.id = r.home_id;

CREATE TEMP VIEW IF NOT EXISTS _qs_legacy_links AS
SELECT l.id
FROM main.links AS l
JOIN temp._qs_legacy_visible_records AS source_visible
  ON source_visible.id = l.source_id
JOIN temp._qs_legacy_visible_records AS target_visible
  ON target_visible.id = l.target_id;
"#;

    /// The visibility fold does not change with the per-anchor rewrite. For
    /// every caller shape — per-account, trusted-local bypass, and a stranger
    /// with no grants — the shipping view must hold exactly the row set the
    /// frozen fold computes, and the governed `records`/`links` projections
    /// must agree end to end. The added anchors cover the shapes the shared
    /// fixture lacks: members grants, edit/manage capabilities, an empty
    /// explicit policy, and an inherited (non-explicit) anchor.
    #[tokio::test]
    async fn per_anchor_fold_matches_the_legacy_fold_model() {
        const MEMBERS_ID: &str = "9e796000-0000-4000-8000-000001000000";
        const EDIT_ID: &str = "9e796000-0000-4000-8000-000002000000";
        const MANAGE_ID: &str = "9e796000-0000-4000-8000-000003000000";
        const EMPTY_ID: &str = "9e796000-0000-4000-8000-000004000000";
        const PARENT_ID: &str = "9e796000-0000-4000-8000-000005000000";
        const CHILD_ID: &str = "9e796000-0000-4000-8000-000006000000";

        let (db, alice, bea) = protected_fixture().await;
        for (id, record_type, kind, name) in [
            (MEMBERS_ID, "Document", "note", "Oracle members"),
            (EDIT_ID, "Document", "note", "Oracle edit"),
            (MANAGE_ID, "Document", "note", "Oracle manage"),
            (EMPTY_ID, "Document", "note", "Oracle empty"),
            (PARENT_ID, "Collection", "folder", "Oracle parent"),
        ] {
            create_record(
                &db,
                json!({
                    "id": id,
                    "type": record_type,
                    "kind": kind,
                    "name": name,
                    "home_id": crate::schema::ROOT_RECORD_ID
                }),
            )
            .await
            .unwrap();
        }
        create_record(
            &db,
            json!({
                "id": CHILD_ID,
                "type": "Document",
                "kind": "note",
                "name": "Oracle child",
                "home_id": PARENT_ID
            }),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            MEMBERS_ID,
            vec![AllowEntry::members(Capability::View)],
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            EDIT_ID,
            vec![AllowEntry::account("bea", Capability::Edit)],
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            MANAGE_ID,
            vec![AllowEntry::account("alice", Capability::Manage)],
        )
        .await
        .unwrap();
        replace_explicit_policy(&db, "test:policy", EMPTY_ID, Vec::new())
            .await
            .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            PARENT_ID,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();

        // SAFETY: test-only construction of the trusted-local fixture.
        let trusted = unsafe { QueryPrincipal::trusted_local_unchecked("local") };
        // A guest footing: the members arm is dead for this caller, so the
        // members-grant anchor below must stay invisible to it under both
        // formulations.
        let stranger = QueryPrincipal::authenticated("nobody", false);
        for (label, principal) in [
            ("alice", alice.clone()),
            ("bea", bea.clone()),
            ("trusted", trusted.clone()),
            ("stranger", stranger.clone()),
        ] {
            let mut connection = db.write_pool().acquire().await.unwrap();
            for statement in temp_contract()
                .split(';')
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                sqlx::query(statement)
                    .execute(&mut *connection)
                    .await
                    .unwrap();
            }
            for statement in LEGACY_FOLD_CONTRACT
                .split(';')
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                sqlx::query(statement)
                    .execute(&mut *connection)
                    .await
                    .unwrap();
            }
            let mut transaction = connection.begin().await.unwrap();
            let _: Option<(i64,)> = sqlx::query_as("SELECT 1 FROM main.database_identity LIMIT 1")
                .fetch_optional(&mut *transaction)
                .await
                .unwrap();
            sqlx::query(
                "INSERT INTO temp._query_sql_principal(singleton, account_id, trusted_local_bypass, activity_read, is_member, observed_at)
                 VALUES (1, ?, ?, ?, ?, '2026-09-17T00:00:00.000Z')",
            )
            .bind(principal.credential().to_string())
            .bind(principal.trusted_local_bypass())
            .bind(principal.activity_read())
            .bind(principal.is_member())
            .execute(&mut *transaction)
            .await
            .unwrap();
            async fn visible_sorted(
                transaction: &mut sqlx::Transaction<'_, Sqlite>,
                relation: &str,
            ) -> Vec<String> {
                sqlx::query_scalar(&format!("SELECT id FROM temp.{relation} ORDER BY id"))
                    .fetch_all(&mut **transaction)
                    .await
                    .unwrap()
            }
            let shipping: Vec<String> =
                visible_sorted(&mut transaction, "_query_sql_visible_records").await;
            let legacy: Vec<String> =
                visible_sorted(&mut transaction, "_qs_legacy_visible_records").await;
            assert_eq!(
                shipping,
                legacy,
                "visible set differs for {label}: shipping {} rows, legacy {} rows",
                shipping.len(),
                legacy.len()
            );
            assert_eq!(
                visible_sorted(&mut transaction, "records").await,
                visible_sorted(&mut transaction, "_qs_legacy_records").await,
                "records projection differs for {label}"
            );
            assert_eq!(
                visible_sorted(&mut transaction, "links").await,
                visible_sorted(&mut transaction, "_qs_legacy_links").await,
                "links projection differs for {label}"
            );
            // Spot-check the added shapes on the shipping view, so a future
            // fixture change that silently drops them fails loudly.
            let has = |id: &str| shipping.iter().any(|seen| seen == id);
            match label {
                "alice" => {
                    assert!(has(MEMBERS_ID) && has(MANAGE_ID));
                    assert!(has(PARENT_ID) && has(CHILD_ID));
                    assert!(!has(EDIT_ID) && !has(EMPTY_ID));
                }
                "bea" => {
                    assert!(has(MEMBERS_ID) && has(EDIT_ID));
                    assert!(!has(MANAGE_ID) && !has(EMPTY_ID));
                    assert!(!has(CHILD_ID));
                }
                "stranger" => {
                    // Guest footing: no account grants, no owner bindings,
                    // and the members arm requires is_member = 1. Empty under
                    // both formulations.
                    assert!(
                        shipping.is_empty(),
                        "guest stranger sees {} rows: {shipping:?}",
                        shipping.len()
                    );
                }
                "trusted" => {
                    for id in [MEMBERS_ID, EDIT_ID, MANAGE_ID, PARENT_ID, CHILD_ID] {
                        assert!(has(id), "trusted misses {id}");
                    }
                }
                _ => unreachable!(),
            }
            transaction.rollback().await.unwrap();
        }
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
            "read_log_record_ids",
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
            "SELECT substr(name, 1, 5) AS preview FROM records",
            "SELECT substr(body, 1, 10) AS preview FROM records",
        ] {
            validate(statement).unwrap_or_else(|error| panic!("{statement}: {error}"));
        }
    }

    #[tokio::test]
    async fn substr_truncates_text_in_sql() {
        let (db, alice, _bea) = protected_fixture().await;
        // "Common" / "sharedterm common" are the COMMON_ID fixture values.
        let preview = query_sql(
            &db,
            &alice,
            &format!("SELECT substr(name, 1, 5) AS preview FROM records WHERE id = '{COMMON_ID}'"),
        )
        .await
        .unwrap();
        assert_eq!(first_strings(&preview), ["Commo"]);
        let tail = query_sql(
            &db,
            &alice,
            &format!("SELECT substr(name, 4) AS tail FROM records WHERE id = '{COMMON_ID}'"),
        )
        .await
        .unwrap();
        assert_eq!(first_strings(&tail), ["mon"]);
        // I2: `substring` is dropped everywhere (Turso never had it);
        // the repair names `substr`.
        let dropped = query_sql(
            &db,
            &alice,
            &format!(
                "SELECT substring(body, 1, 10) AS preview FROM records WHERE id = '{COMMON_ID}'"
            ),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            dropped.contains("function 'substring' is unavailable — use substr"),
            "missing repair: {dropped}"
        );
        assert!(principal_context_is_empty(&db).await.unwrap());
    }

    #[test]
    fn governed_sql_timeout_names_the_deadline_and_the_usual_cause() {
        let rendered = governed_sql_timeout().to_string();
        assert_eq!(
            rendered,
            format!("query_sql [timeout]: {}", sql_contract::deadline_hint())
        );
        assert!(rendered.contains(&format!("{}ms", sql_contract::QUERY_DEADLINE_MS)));
        assert!(rendered.contains("LIMIT with ORDER BY"));
    }

    #[tokio::test]
    async fn runaway_query_surfaces_the_governed_sql_timeout() {
        let (db, alice, _bea) = protected_fixture().await;
        let error = query_sql_owned(
            db.clone(),
            alice,
            "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x < 5000000000) SELECT sum(x) AS n FROM n".into(),
        )
        .await
        .unwrap_err();
        let rendered = error.to_string();
        assert!(rendered.contains("[timeout]"), "{rendered}");
        assert!(rendered.contains("governed SQL deadline"), "{rendered}");
        assert!(!rendered.contains("interrupted"), "{rendered}");
        assert!(principal_context_is_empty(&db).await.unwrap());
    }

    #[tokio::test]
    async fn explain_query_plan_reports_plans_without_widening_the_surface() {
        let (db, alice, _bea) = protected_fixture().await;
        validate(&format!(
            "EXPLAIN QUERY PLAN SELECT id FROM records WHERE id = '{COMMON_ID}'"
        ))
        .unwrap();
        let plan = query_sql(
            &db,
            &alice,
            &format!("EXPLAIN QUERY PLAN SELECT id FROM records WHERE id = '{COMMON_ID}'"),
        )
        .await
        .unwrap();
        // The plan column labels are SQLite-version cosmetics (older
        // selectid/order/from, newer id/parent/notused); pin the stable
        // shape instead: four columns ending in the human-readable detail.
        assert_eq!(plan.columns.len(), 4);
        assert_eq!(plan.columns[3], "detail");
        assert!(!plan.rows.is_empty());
        for row in &plan.rows {
            let object = row.as_object().unwrap();
            assert_eq!(object.len(), 4);
            assert!(object["detail"].as_str().is_some());
        }
        // Bare EXPLAIN and any explained statement that is not itself
        // admissible stay rejected, through validation and through execution.
        for statement in [
            "EXPLAIN SELECT id FROM records".to_string(),
            "EXPLAIN QUERY PLAN DELETE FROM records".to_string(),
            "EXPLAIN QUERY PLAN SELECT randomblob(1)".to_string(),
            "EXPLAIN QUERY PLAN SELECT * FROM main.records".to_string(),
        ] {
            assert!(
                validate(&statement).is_err(),
                "unexpectedly admitted {statement}"
            );
            assert!(
                query_sql(&db, &alice, &statement).await.is_err(),
                "unexpectedly executed {statement}"
            );
        }
        assert!(principal_context_is_empty(&db).await.unwrap());
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

        // Pin all governed work to one available slot. Both breaches must
        // discard the physical connection and leave its replacement clean
        // for Bea.
        let held = hold_all_but_one_governed_slot(&db).await;
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
            // Stay above the governed pool size so requests must queue and
            // reuse physical connections, while leaving the full parallel
            // suite's scheduler load out of the governed acquire timeout.
            .buffer_unordered(8)
            .collect::<Vec<_>>()
            .await;
        for (expected, actual) in observations {
            assert_eq!(actual, [expected]);
        }

        // Hold every governed-pool slot but one: every alternation below must
        // reuse the one remaining physical connection.
        let held = hold_all_but_one_governed_slot(&db).await;
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

    /// Tier 1.2: governed reads must not occupy write-pool connections. Hold
    /// every write slot, then require a governed query to succeed — before
    /// this rung it would have waited on a writer's slot.
    #[tokio::test]
    async fn governed_reads_do_not_occupy_write_pool_connections() {
        let (db, alice, _) = protected_fixture().await;
        let mut held = Vec::new();
        for _ in 0..5 {
            held.push(db.write_pool().acquire().await.unwrap());
        }
        let rows = query_sql(
            &db,
            &alice,
            &format!("SELECT id FROM records WHERE id LIKE '%{PRIVATE_ID_SUFFIX}'"),
        )
        .await
        .unwrap();
        assert_eq!(first_strings(&rows), [ALICE_PRIVATE_ID]);
        assert!(principal_context_is_empty(&db).await.unwrap());
        drop(held);
        db.close().await;
    }

    /// Tier 1.2, other direction: saturating the governed pool must leave
    /// ordinary writes unaffected — the availability win this rung exists for.
    #[tokio::test]
    async fn writes_proceed_while_the_governed_pool_is_saturated() {
        let (db, alice, _) = protected_fixture().await;
        let mut held = Vec::new();
        for _ in 0..crate::db::governed_sql_pool_size() {
            held.push(db.governed_pool().acquire().await.unwrap());
        }
        create_record(
            &db,
            json!({
                "id": "9e795000-0000-4000-8000-00000f000000",
                "type": "Document",
                "kind": "note",
                "name": "Written while governed is saturated",
            }),
        )
        .await
        .unwrap();
        drop(held);
        let rows = query_sql(
            &db,
            &alice,
            "SELECT id FROM records WHERE id = '9e795000-0000-4000-8000-00000f000000'",
        )
        .await
        .unwrap();
        assert_eq!(rows.row_count, 1);
        db.close().await;
    }

    /// Tier 1.2: the governed pool is the concurrency limit. A burst several
    /// times the pool size must queue and complete — every caller isolated —
    /// rather than exhausting writer connections or cross-contaminating TEMP
    /// principal state.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn governed_burst_beyond_pool_size_queues_and_completes() {
        let (db, alice, bea) = protected_fixture().await;
        let burst = 4 * crate::db::governed_sql_pool_size() as usize;
        let outcomes = stream::iter(0..burst)
            .map(|index| {
                let db = db.clone();
                let caller = if index % 2 == 0 {
                    alice.clone()
                } else {
                    bea.clone()
                };
                let expected = if index % 2 == 0 {
                    ALICE_PRIVATE_ID
                } else {
                    BEA_PRIVATE_ID
                };
                async move {
                    let result = query_sql(
                        &db,
                        &caller,
                        &format!("SELECT id FROM records WHERE id LIKE '%{PRIVATE_ID_SUFFIX}'"),
                    )
                    .await
                    .unwrap();
                    (expected, first_strings(&result))
                }
            })
            .buffer_unordered(burst)
            .collect::<Vec<_>>()
            .await;
        for (expected, actual) in outcomes {
            assert_eq!(actual, [expected]);
        }
        assert!(principal_context_is_empty(&db).await.unwrap());
        db.close().await;
    }

    /// Tier 1.2: the pool bound is visible at checkout. With every slot
    /// checked out, a further `try_acquire` fails immediately rather than
    /// minting contention the engine cannot see. (A plain `acquire` still
    /// queues, bounded by the pool's acquire timeout — the limit is the pool
    /// size, not a refusal to wait.)
    #[tokio::test]
    async fn governed_pool_full_pool_refuses_checkout() {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut held = Vec::new();
        for _ in 0..crate::db::governed_sql_pool_size() {
            held.push(db.governed_pool().acquire().await.unwrap());
        }
        assert!(
            db.governed_pool().try_acquire().is_none(),
            "governed pool admitted a checkout beyond its configured size"
        );
        drop(held);
        db.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancellation_and_deadline_cannot_poison_or_indefinitely_delay_reuse() {
        let (db, alice, bea) = protected_fixture().await;
        let held = hold_all_but_one_governed_slot(&db).await;

        // Force an unwind after principal installation and progress-handler
        // registration on the sole available governed-pool connection.
        // Transaction drop queues rollback; pool release must remove every
        // connection-local remnant before Bea can borrow it.
        let panic_result = std::panic::AssertUnwindSafe(async {
            let mut connection = db.governed_pool().acquire().await.unwrap();
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
                "INSERT INTO temp._query_sql_principal(singleton, account_id, trusted_local_bypass, activity_read, is_member, observed_at)
                 VALUES (1, 'alice', 0, 0, 1, '2026-08-31T00:00:00.000Z')",
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
        let current = crate::control::ensure_agent_run(
            &db,
            current_run,
            "alice",
            crate::control::ReportedRunIdentity::default(),
        )
        .await
        .unwrap();
        let stale = crate::control::ensure_agent_run(
            &db,
            stale_run,
            "alice",
            crate::control::ReportedRunIdentity::default(),
        )
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
        let departed =
            unsafe { QueryPrincipal::activity_reader_unchecked("departed", Vec::new(), true) };
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
                true,
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

        // A guest on the same roster keeps attribution presence but sees no
        // agent activity: the admission consults membership, not just roster.
        let guest_activity = unsafe {
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
                false,
            )
        };
        let no_runs = query_sql(
            &db,
            &guest_activity,
            "SELECT activity_id FROM agent_activity",
        )
        .await
        .unwrap();
        assert_eq!(no_runs.row_count, 0);

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
                true,
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
        let mut clock_connection = db.governed_pool().acquire().await.unwrap();
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
             (singleton,account_id,trusted_local_bypass,activity_read,is_member,observed_at)
             VALUES (1,'bea',0,1,1,?)",
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
    async fn agent_activity_declared_intent_discloses_same_account_only() {
        let (db, _alice, _bea) = protected_fixture().await;
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
        let alice_run = "scout-chair-a748b2";
        let alice_quiet_run = "scout-chair-a749b2";
        let bea_run = "scout-chair-b748b2";
        crate::control::ensure_agent_run(
            &db,
            alice_run,
            "alice",
            crate::control::ReportedRunIdentity::default(),
        )
        .await
        .unwrap();
        crate::control::ensure_agent_run(
            &db,
            alice_quiet_run,
            "alice",
            crate::control::ReportedRunIdentity::default(),
        )
        .await
        .unwrap();
        crate::control::ensure_agent_run(
            &db,
            bea_run,
            "bea",
            crate::control::ReportedRunIdentity::default(),
        )
        .await
        .unwrap();
        // The spoof row carries the highest seq on Alice's key, so the
        // latest-declaration lookup must skip it on the actor filter rather
        // than on ordering alone.
        for (id, tool, run_key, actor, intent) in [
            (
                "intent-alice-first",
                "set_intent",
                alice_run,
                "alice",
                Some("First framing"),
            ),
            (
                "intent-alice-latest",
                "set_intent",
                alice_run,
                "alice",
                Some("Reframed aim"),
            ),
            (
                "intent-alice-spoof",
                "set_intent",
                alice_run,
                "bea",
                Some("Spoofed aim"),
            ),
            (
                "intent-bea-only",
                "set_intent",
                bea_run,
                "bea",
                Some("Bea private plan"),
            ),
            (
                "call-alice-quiet",
                "get_record",
                alice_quiet_run,
                "alice",
                None,
            ),
            ("call-bea", "get_record", bea_run, "bea", None),
        ] {
            sqlx::query(
                "INSERT INTO read_log_calls
                 (id,tool,run_key,actor,intent,outcome,started_at,ended_at)
                 VALUES (?,?,?,?,?,'ok',
                         strftime('%Y-%m-%dT%H:%M:%fZ','now'),
                         strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
            )
            .bind(id)
            .bind(tool)
            .bind(run_key)
            .bind(actor)
            .bind(intent)
            .execute(db.write_pool())
            .await
            .unwrap();
        }
        // SAFETY: these tests model the authenticated hosted ingress after it
        // has admitted the live member roster; no SQL argument controls it.
        let viewer = |credential: &str| unsafe {
            QueryPrincipal::activity_reader_unchecked(
                credential,
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
                true,
            )
        };
        let intent_sql =
            "SELECT run_key,declared_intent,declared_intent_state FROM agent_activity ORDER BY run_key";
        let as_alice = query_sql(&db, viewer("alice"), intent_sql).await.unwrap();
        assert_eq!(as_alice.row_count, 3);
        assert_eq!(as_alice.rows[0]["run_key"], alice_run);
        assert_eq!(as_alice.rows[0]["declared_intent"], "Reframed aim");
        assert_eq!(as_alice.rows[0]["declared_intent_state"], "disclosed");
        assert_eq!(as_alice.rows[1]["run_key"], alice_quiet_run);
        assert!(as_alice.rows[1]["declared_intent"].is_null());
        assert_eq!(as_alice.rows[1]["declared_intent_state"], "none");
        assert_eq!(as_alice.rows[2]["run_key"], bea_run);
        assert!(as_alice.rows[2]["declared_intent"].is_null());
        assert_eq!(as_alice.rows[2]["declared_intent_state"], "withheld");

        let as_bea = query_sql(&db, viewer("bea"), intent_sql).await.unwrap();
        assert_eq!(as_bea.row_count, 3);
        assert!(as_bea.rows[0]["declared_intent"].is_null());
        assert_eq!(as_bea.rows[0]["declared_intent_state"], "withheld");
        assert!(as_bea.rows[1]["declared_intent"].is_null());
        assert_eq!(as_bea.rows[1]["declared_intent_state"], "withheld");
        assert_eq!(as_bea.rows[2]["declared_intent"], "Bea private plan");
        assert_eq!(as_bea.rows[2]["declared_intent_state"], "disclosed");

        // Without the read-log capture table the column reads unavailable
        // with a reason, never a silent empty. This covers only the absent
        // table shape (RENAME here, DROP TABLE in conformance), not a standby
        // replica whose export strips the rows but keeps the tables, which
        // still reads `none`. That stripped-but-present gap is known and
        // needs a durable capture-removed signal the export writes.
        sqlx::query("ALTER TABLE read_log_calls RENAME TO read_log_calls_unavailable")
            .execute(db.write_pool())
            .await
            .unwrap();
        let degraded = query_sql(&db, viewer("alice"), intent_sql).await.unwrap();
        assert_eq!(degraded.row_count, 3);
        assert!(
            degraded
                .rows
                .iter()
                .all(|row| row["declared_intent"].is_null()
                    && row["declared_intent_state"] == "unavailable"),
            "unexpected degraded rows: {:?}",
            degraded.rows
        );
    }

    #[tokio::test]
    async fn same_principal_release_from_another_run_closes_the_claim() {
        let (db, _alice, _bea) = protected_fixture().await;
        let first_run = "scout-chair-a748b2";
        let second_run = "scout-chair-b748b2";
        crate::control::ensure_agent_run(
            &db,
            first_run,
            "alice",
            crate::control::ReportedRunIdentity::default(),
        )
        .await
        .unwrap();
        crate::control::ensure_agent_run(
            &db,
            second_run,
            "alice",
            crate::control::ReportedRunIdentity::default(),
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
                true,
            )
        };
        registry
            .call(
                db.clone(),
                crate::mcp::Caller::authenticated("alice"),
                "start_work",
                json!({ "record_id": COMMON_ID, "run_key": first_run }),
            )
            .await
            .unwrap();
        let open = query_sql(
            &db,
            &bea_activity,
            "SELECT claim_id,is_current,released_at FROM agent_activity_claims ORDER BY claim_id",
        )
        .await
        .unwrap();
        assert_eq!(open.row_count, 1);
        assert_eq!(open.rows[0]["is_current"], 1);
        assert!(open.rows[0]["released_at"].is_null());
        registry
            .call(
                db.clone(),
                crate::mcp::Caller::authenticated("alice"),
                "start_work",
                json!({
                    "record_id": COMMON_ID,
                    "action": "release",
                    "run_key": second_run,
                    "expected_holder_run_key": first_run,
                }),
            )
            .await
            .unwrap();
        let closed = query_sql(
            &db,
            &bea_activity,
            "SELECT claim_id,is_current,released_at FROM agent_activity_claims ORDER BY claim_id",
        )
        .await
        .unwrap();
        assert_eq!(closed.row_count, 1);
        assert_eq!(closed.rows[0]["claim_id"], open.rows[0]["claim_id"]);
        assert!(closed.rows[0]["released_at"].is_string());
        assert_eq!(closed.rows[0]["is_current"], 0);
    }

    // Covers the non-run-scoped shape only: the oversized payload here
    // carries no run_key/actor stamp. A run-stamped over-limit payload can
    // still fail this relation through the joined `agent_activity`
    // relation, which is the separately tracked sibling defect.
    #[tokio::test]
    async fn claims_ignore_oversized_event_payloads_outside_the_activity_window() {
        let (db, _alice, _bea) = protected_fixture().await;
        update_record(
            &db,
            COMMON_ID,
            json!({ "body": "x".repeat(MAX_SQLITE_VALUE_BYTES as usize + 1024) }),
        )
        .await
        .unwrap();
        let (oversized_event_id, payload_bytes): (String, i64) = sqlx::query_as(
            "SELECT id,length(CAST(payload AS BLOB))
               FROM content_events
              WHERE record_id=? AND type='record.updated'
              ORDER BY seq DESC LIMIT 1",
        )
        .bind(COMMON_ID)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert!(payload_bytes > MAX_SQLITE_VALUE_BYTES as i64);

        update_record(&db, COMMON_ID, json!({ "body": "small current body" }))
            .await
            .unwrap();
        // content_events is append-only by trigger; this test deliberately
        // backdates one event to exercise the bounded activity window. Drop
        // only the update guard and restore its exact sqlite_master SQL on the
        // same connection around that test-only mutation.
        let mut fixture = db.write_pool().acquire().await.unwrap();
        let update_guard: String = sqlx::query_scalar(
            "SELECT sql FROM sqlite_master WHERE type='trigger' AND name='content_events_no_update'",
        )
        .fetch_one(&mut *fixture)
        .await
        .unwrap();
        sqlx::query("DROP TRIGGER content_events_no_update")
            .execute(&mut *fixture)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE content_events
                SET created_at=strftime('%Y-%m-%dT%H:%M:%fZ','now','-48 hours')
              WHERE id=?",
        )
        .bind(&oversized_event_id)
        .execute(&mut *fixture)
        .await
        .unwrap();
        sqlx::query(&update_guard)
            .execute(&mut *fixture)
            .await
            .unwrap();
        drop(fixture);

        let run_key = "scout-chair-c748b2";
        crate::control::ensure_agent_run(
            &db,
            run_key,
            "alice",
            crate::control::ReportedRunIdentity::default(),
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
        registry
            .call(
                db.clone(),
                crate::mcp::Caller::authenticated("alice"),
                "start_work",
                json!({ "record_id": COMMON_ID, "run_key": run_key }),
            )
            .await
            .unwrap();
        let alice_activity = unsafe {
            QueryPrincipal::activity_reader_unchecked(
                "alice",
                vec![
                    crate::query::principal::ActivityRosterMember::verified_unchecked(
                        "alice",
                        "native:workspace-member:alice",
                    ),
                ],
                true,
            )
        };

        let claims = query_sql(
            &db,
            &alice_activity,
            "SELECT claim_id,record_id,is_current FROM agent_activity_claims",
        )
        .await
        .unwrap();
        assert_eq!(claims.row_count, 1);
        assert_eq!(claims.rows[0]["record_id"], COMMON_ID);
        assert_eq!(claims.rows[0]["is_current"], 1);
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

    async fn create_policy_scoped_note(db: &Db, id: &str, account: &str, body: &str) {
        create_record(
            db,
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
            db,
            "test:policy",
            id,
            vec![AllowEntry::account(account, Capability::View)],
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn sqlite_toobig_error_names_the_oversized_visible_row() {
        let (db, alice, _) = protected_fixture().await;
        create_policy_scoped_note(
            &db,
            TOOBIG_ALICE_ID,
            "alice",
            &"x".repeat(TOOBIG_ALICE_BYTES),
        )
        .await;

        let ids_only = query_sql(
            &db,
            &alice,
            &format!("SELECT id FROM records WHERE id = '{TOOBIG_ALICE_ID}'"),
        )
        .await
        .unwrap();
        assert_eq!(first_strings(&ids_only), [TOOBIG_ALICE_ID]);

        let error = query_sql(&db, &alice, "SELECT body FROM records")
            .await
            .unwrap_err()
            .to_string();
        assert!(error.starts_with("query_sql [syntax_or_type]: "), "{error}");
        assert!(error.contains("string or blob too big"), "{error}");
        assert!(error.contains("Offending:"), "{error}");
        assert!(
            error.contains(&format!("{TOOBIG_ALICE_BYTES} bytes")),
            "{error}"
        );
        assert!(error.contains("records.body"), "{error}");
        assert!(error.contains(TOOBIG_ALICE_ID), "{error}");
        assert!(
            error.contains("cannot be read, truncated or matched"),
            "{error}"
        );
        assert!(
            error.contains(&format!("WHERE records.id NOT IN ('{TOOBIG_ALICE_ID}')")),
            "{error}"
        );
        assert!(
            !error.contains(&"x".repeat(32)),
            "oversized payload leaked into the error"
        );
    }

    #[tokio::test]
    async fn sqlite_toobig_hint_qualifies_exclusions_per_relation() {
        let (db, alice, _) = protected_fixture().await;
        create_policy_scoped_note(
            &db,
            TOOBIG_ALICE_ID,
            "alice",
            &"x".repeat(TOOBIG_ALICE_BYTES),
        )
        .await;
        sqlx::query("UPDATE links SET note = ? WHERE id = 'alice-common'")
            .bind("a".repeat(TOOBIG_ALICE_BYTES))
            .execute(db.write_pool())
            .await
            .unwrap();
        // A second alice-visible link with a small note, so the repaired
        // retry below still returns rows after both culprits are excluded.
        add_link(
            &db,
            LinkAddedPayload {
                id: Some("common-alice-small".into()),
                source_id: COMMON_ID.into(),
                target_id: ALICE_PRIVATE_ID.into(),
                relationship: "mentions".into(),
                note: Some("small".into()),
            },
        )
        .await
        .unwrap();

        let error = query_sql(
            &db,
            &alice,
            "SELECT r.body, l.note FROM records r JOIN links l ON l.source_id = r.id",
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("string or blob too big"), "{error}");
        // One qualified clause per relation: ids are per-relation id domains,
        // so a single unqualified predicate would mix them and could be
        // ambiguous in the joined statement.
        assert!(
            error.contains(&format!("records.id NOT IN ('{TOOBIG_ALICE_ID}')")),
            "{error}"
        );
        assert!(
            error.contains("links.id NOT IN ('alice-common')"),
            "{error}"
        );
        assert!(!error.contains("WHERE id NOT IN"), "{error}");
        // The repair, applied with the statement's aliases, excludes both
        // oversized rows and lets the join run.
        let retried = query_sql(
            &db,
            &alice,
            &format!(
                "SELECT r.body, l.note FROM records r JOIN links l ON l.source_id = r.id \
                 WHERE r.id NOT IN ('{TOOBIG_ALICE_ID}') AND l.id NOT IN ('alice-common')"
            ),
        )
        .await
        .unwrap();
        // Joined records with no body project as null, so look for the
        // surviving small link row rather than first-column strings.
        let notes: Vec<String> = retried
            .rows
            .iter()
            .filter_map(|row| row.as_object().and_then(|row| row.get("note")))
            .filter_map(serde_json::Value::as_str)
            .map(str::to_owned)
            .collect();
        assert!(
            notes.contains(&"small".to_owned()),
            "repaired join lost the surviving link row: {notes:?}"
        );
    }

    #[tokio::test]
    async fn sqlite_toobig_hint_counts_beyond_the_display_cap() {
        let (db, alice, _) = protected_fixture().await;
        // Eleven visible oversized rows: more than the hint's 10-id display
        // cap, fewer than the probe's 12-row stop, so the wired path emits
        // the "(first 10 of 11 oversized rows)" count.
        for index in 0..11 {
            create_policy_scoped_note(
                &db,
                &format!("9e795000-0000-4000-8000-{index:012}"),
                "alice",
                &"x".repeat(TOOBIG_ALICE_BYTES),
            )
            .await;
        }
        let error = query_sql(&db, &alice, "SELECT body FROM records")
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("string or blob too big"), "{error}");
        assert!(error.contains("(first 10 of 11 oversized rows)"), "{error}");
        assert!(error.contains("records.id NOT IN ("), "{error}");
    }

    #[tokio::test]
    async fn sqlite_toobig_error_does_not_name_an_invisible_oversized_row() {
        let (db, alice, bea) = protected_fixture().await;
        create_policy_scoped_note(
            &db,
            TOOBIG_ALICE_ID,
            "alice",
            &"a".repeat(TOOBIG_ALICE_BYTES),
        )
        .await;
        create_policy_scoped_note(&db, TOOBIG_BEA_ID, "bea", &"b".repeat(TOOBIG_BEA_BYTES)).await;

        let error = query_sql(&db, &alice, "SELECT body FROM records")
            .await
            .unwrap_err()
            .to_string();
        assert!(error.starts_with("query_sql [syntax_or_type]: "), "{error}");
        assert!(error.contains("string or blob too big"), "{error}");
        assert!(error.contains("Offending:"), "{error}");
        assert!(error.contains("records.body"), "{error}");
        assert!(error.contains(TOOBIG_ALICE_ID), "{error}");
        assert!(
            error.contains(&format!("{TOOBIG_ALICE_BYTES} bytes")),
            "{error}"
        );
        assert!(
            !error.contains(TOOBIG_BEA_ID),
            "named a record the caller cannot see: {error}"
        );
        assert!(
            !error.contains(&format!("{TOOBIG_BEA_BYTES} bytes")),
            "named an invisible size: {error}"
        );

        let bea_error = query_sql(&db, &bea, "SELECT body FROM records")
            .await
            .unwrap_err()
            .to_string();
        assert!(bea_error.contains(TOOBIG_BEA_ID), "{bea_error}");
        assert!(
            !bea_error.contains(TOOBIG_ALICE_ID),
            "named a record the caller cannot see: {bea_error}"
        );
    }

    #[tokio::test]
    async fn sqlite_toobig_computed_value_hedges_and_keeps_the_engine_detail() {
        let (db, alice, _) = protected_fixture().await;
        let error = query_sql(&db, &alice, COMPUTED_TOOBIG_SQL)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.starts_with("query_sql [syntax_or_type]: "), "{error}");
        assert!(error.contains("string or blob too big"), "{error}");
        assert!(
            error.contains("stored value or a computed intermediate"),
            "{error}"
        );
        assert!(!error.contains("Offending:"), "{error}");
        assert!(
            !error.contains("also reads these oversized values"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn sqlite_toobig_does_not_blame_an_unprojected_stored_value() {
        let (db, alice, _) = protected_fixture().await;
        create_policy_scoped_note(
            &db,
            TOOBIG_ALICE_ID,
            "alice",
            &"x".repeat(TOOBIG_ALICE_BYTES),
        )
        .await;
        let sql = format!("{COMPUTED_TOOBIG_SQL} WHERE (SELECT count(id) FROM records) >= 0");
        let error = query_sql(&db, &alice, &sql).await.unwrap_err().to_string();
        assert!(error.contains("string or blob too big"), "{error}");
        assert!(
            error.contains("also reads these oversized values"),
            "{error}"
        );
        assert!(error.contains("records.body"), "{error}");
        assert!(error.contains(TOOBIG_ALICE_ID), "{error}");
        assert!(!error.contains("Offending:"), "{error}");
    }

    #[tokio::test]
    async fn sqlite_toobig_links_require_both_endpoints_visible() {
        let (db, alice, _) = protected_fixture().await;
        sqlx::query("UPDATE links SET note = ? WHERE id = 'alice-common'")
            .bind("a".repeat(TOOBIG_ALICE_BYTES))
            .execute(db.write_pool())
            .await
            .unwrap();
        sqlx::query("UPDATE links SET note = ? WHERE id = 'common-bea'")
            .bind("b".repeat(TOOBIG_BEA_BYTES))
            .execute(db.write_pool())
            .await
            .unwrap();
        // Mirror of common-bea: invisible source, visible target. Without
        // this row, dropping `source_visible` from the probe is a no-op.
        add_link(
            &db,
            LinkAddedPayload {
                id: Some("bea-common".into()),
                source_id: BEA_PRIVATE_ID.into(),
                target_id: COMMON_ID.into(),
                relationship: "mentions".into(),
                note: None,
            },
        )
        .await
        .unwrap();
        sqlx::query("UPDATE links SET note = ? WHERE id = 'bea-common'")
            .bind("c".repeat(TOOBIG_BEA_BYTES))
            .execute(db.write_pool())
            .await
            .unwrap();

        let error = query_sql(&db, &alice, "SELECT note FROM links")
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("Offending:"), "{error}");
        assert!(error.contains("links.note"), "{error}");
        assert!(error.contains("alice-common"), "{error}");
        assert!(
            error.contains(&format!("{TOOBIG_ALICE_BYTES} bytes")),
            "{error}"
        );
        assert!(
            !error.contains("common-bea"),
            "named a link with an invisible target: {error}"
        );
        assert!(
            !error.contains("bea-common"),
            "named a link with an invisible source: {error}"
        );
        assert!(
            !error.contains(&format!("{TOOBIG_BEA_BYTES} bytes")),
            "named an invisible link size: {error}"
        );
    }

    async fn create_attachment_with_blob(
        db: &Db,
        attachment_id: &str,
        bearer_id: &str,
        grants: &[&str],
        bytes: &[u8],
    ) -> String {
        create_record(
            db,
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
            db,
            "test:policy",
            attachment_id,
            grants
                .iter()
                .map(|account| AllowEntry::account(*account, Capability::View))
                .collect(),
        )
        .await
        .unwrap();
        let blob = crate::blob::insert_blob(
            db,
            bytes,
            Some("text/plain"),
            Some(&format!("{attachment_id}.txt")),
        )
        .await
        .unwrap();
        set_facet(
            db,
            attachment_id,
            FacetSetPayload {
                key: "blob_ref".into(),
                value: Some(blob.id.clone()),
                vocab_ref: None,
                as_of: None,
                observation_only: false,
            },
        )
        .await
        .unwrap();
        add_link(
            db,
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
        blob.id
    }

    #[tokio::test]
    async fn sqlite_toobig_blobs_require_visible_bearer_and_ignore_external_size() {
        let (db, alice, _) = protected_fixture().await;
        let alice_blob = create_attachment_with_blob(
            &db,
            TOOBIG_ALICE_ATTACHMENT_ID,
            ALICE_PRIVATE_ID,
            &["alice"],
            &vec![b'a'; TOOBIG_ALICE_BYTES],
        )
        .await;
        let hidden_blob = create_attachment_with_blob(
            &db,
            TOOBIG_BEA_ATTACHMENT_ID,
            BEA_PRIVATE_ID,
            &["alice", "bea"],
            &vec![b'b'; TOOBIG_BEA_BYTES],
        )
        .await;

        create_record(
            &db,
            json!({
                "id": TOOBIG_EXTERNAL_ATTACHMENT_ID,
                "type": "Document",
                "kind": "attachment",
                "name": "external.bin",
                "home_id": crate::schema::ROOT_RECORD_ID
            }),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            TOOBIG_EXTERNAL_ATTACHMENT_ID,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO blobs(id, bytes, mime, size_bytes, sha256, original_filename, storage_tier)
             VALUES (?, NULL, 'application/octet-stream', ?, '00', 'external.bin', 'external')",
        )
        .bind(TOOBIG_EXTERNAL_BLOB_ID)
        .bind((MAX_SQLITE_VALUE_BYTES as i64) + 1_000_000)
        .execute(db.write_pool())
        .await
        .unwrap();
        set_facet(
            &db,
            TOOBIG_EXTERNAL_ATTACHMENT_ID,
            FacetSetPayload {
                key: "blob_ref".into(),
                value: Some(TOOBIG_EXTERNAL_BLOB_ID.into()),
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
                id: Some("bearer-external-toobig".into()),
                source_id: TOOBIG_EXTERNAL_ATTACHMENT_ID.into(),
                target_id: ALICE_PRIVATE_ID.into(),
                relationship: "part_of".into(),
                note: None,
            },
        )
        .await
        .unwrap();

        let error = query_sql(&db, &alice, "SELECT bytes FROM blobs")
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("Offending:"), "{error}");
        assert!(error.contains("blobs.bytes"), "{error}");
        assert!(error.contains(&alice_blob), "{error}");
        assert!(
            error.contains(&format!("{TOOBIG_ALICE_BYTES} bytes")),
            "{error}"
        );
        assert!(
            !error.contains(&hidden_blob),
            "named a blob whose bearer is invisible: {error}"
        );
        assert!(
            !error.contains(TOOBIG_EXTERNAL_BLOB_ID),
            "named an external blob by size_bytes: {error}"
        );
    }
}
