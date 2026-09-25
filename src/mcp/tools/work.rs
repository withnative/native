//! Tool 31 — `start_work` (docs/tool-surface.md §Work coordination).
//!
//! Claims are projected coordination state, authored only by this tool through
//! ordinary `record.updated` events. They never displace `lifecycle`: claiming
//! and releasing each append exactly one event and update only the engine-owned
//! claim tuple on `records`.
//!
//! SQLite `BEGIN IMMEDIATE` serializes the read/predicate/append sequence. A
//! claim succeeds only while `claimed_by_account IS NULL`; an ordinary release
//! succeeds for the exact stored account/run tuple, or for another run of the
//! SAME account presenting `expected_holder_run_key` as a compare-and-release.
//! Cross-principal releases stay refused. Trusted local callers retain a
//! recovery path for a stuck current claim.

use std::collections::HashMap;

use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{QueryBuilder, Row, Sqlite, SqliteConnection, SqlitePool};

use crate::authorization::Capability;
use crate::db::Db;
use crate::error::{Error, Result};
use crate::query::lifecycle::{LifecycleInterpretation, LifecycleInterpreter};
use crate::query::read;
use crate::store::{append_in, AppendSpec};

use super::super::registry::{Caller, ToolRegistry};
use super::super::ToolKind;
use super::{parse_args, require_record, require_record_in, visible_ids_in_pool};

/// How long a holder run keeps reading `open` after its last observed
/// activity. This shares the `active_until` horizon the `agent_activity`
/// relation publishes (`+5 minutes` in `src/query/sql.rs`): the value is
/// shared, so moving it is a change to a ratified relation semantic, not a
/// local tuning knob. Sharing the value does not mean the two surfaces
/// agree about the same run — [`neighbour_run_state_at`] lists the
/// deliberate divergences, in both directions. *This* derivation reads
/// durable content events and nothing else; the relation also folds in
/// read-log observations when its capture helper is present, and that fold
/// is a tolerated legacy rather than a standard to match. Native builds
/// collective intelligence from acts, not attention. A delegate's reads are
/// oversight for its principal to inspect, and enter the shared world only
/// when an act names them, so reads never move this horizon. Claim and
/// release events do count — they are calls on a coordination surface,
/// which are acts.
const HOLDER_ACTIVE_HORIZON: &str = "+5 minutes";

const ACTION_CLAIM: &str = "claim";
const ACTION_PREVIEW: &str = "preview";
const ACTION_RELEASE: &str = "release";
const ACTIONS: [&str; 3] = [ACTION_CLAIM, ACTION_PREVIEW, ACTION_RELEASE];

#[derive(Debug, Clone)]
struct ClaimState {
    lifecycle: Option<String>,
    claimed_by_account: Option<String>,
    claimed_run_key: Option<String>,
    claimed_at: Option<String>,
}

#[derive(Debug)]
struct ProjectedClaimState {
    record_id: String,
    claimed_by_account: Option<String>,
    claimed_run_key: Option<String>,
    claimed_at: Option<String>,
    claim_event_id: Option<String>,
    activity_id: Option<String>,
    /// Holder liveness resolved with the canonical [`neighbour_run_state`].
    /// Preview (`work_state`) and the overlap notice carry it as `run_state`
    /// alongside `holder_tier`; the claim refusal (`already_claimed`) returns
    /// `Err` before any `work_state` is assembled, so it carries only
    /// `holder_tier` and the run key, never `run_state`.
    /// Meaningful only for same-account rows; cross-principal rows stay
    /// `withheld` before it is read.
    holder_run_state: &'static str,
}

impl ProjectedClaimState {
    fn is_same_account(&self, caller: &Caller) -> bool {
        self.claimed_by_account.as_deref() == Some(caller.credential())
    }

    fn work_state(&self, caller: &Caller) -> Value {
        let Some(account) = self.claimed_by_account.as_deref() else {
            return json!({ "state": "unclaimed" });
        };

        if !self.is_same_account(caller) {
            return json!({
                "state": "claimed",
                "details": { "visibility": "withheld" },
                "target": { "visibility": "withheld" },
            });
        }

        json!({
            "state": "claimed",
            "claim_status": "current",
            "details": {
                "visibility": "visible",
                "claim_id": self.claim_event_id,
                "claimed_at": self.claimed_at,
            },
            "target": {
                "visibility": "visible",
                "account": account,
                "run_key": self.claimed_run_key,
                "activity_id": self.activity_id,
                "run_state": self.holder_run_state,
                "holder_tier": holder_tier(caller, account, self.claimed_run_key.as_deref()),
            },
        })
    }
}

/// Project current claim occupancy for a bounded record set on one
/// connection. This is the reusable seam for record queries: one projection
/// query observes every requested record at the same boundary, while the
/// pure response fold keeps exact-holder disclosure uniform with
/// `start_work`.
///
/// Single-connection by convention: a handler holding a transaction or a
/// pooled connection must not take a second pool connection from the same
/// pool (five such handlers deadlock the 5-slot write pool). The cross-pool
/// form below exists only for the `as_of` arm, where the projection
/// (scratch) and live-target pools genuinely differ.
pub(super) async fn project_work_states_in(
    conn: &mut SqliteConnection,
    caller: &Caller,
    record_ids: &[String],
) -> Result<HashMap<String, Value>> {
    if record_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows = projection_rows(&mut *conn, record_ids).await?;
    let holder_keys = holder_keys_for(&rows, caller)?;
    let mut holder_run_states: HashMap<Option<String>, &'static str> = HashMap::new();
    for key in &holder_keys {
        let run_state = neighbour_run_state_on(conn, caller.credential(), key.as_deref()).await?;
        holder_run_states.insert(key.clone(), run_state);
    }
    let holder_activities = holder_activities_on(conn, caller, &holder_keys).await?;
    fold_projected_states(rows, caller, &holder_run_states, &holder_activities)
}

/// Cross-pool form for the `as_of` query arm only: record rows come from the
/// replay scratch projection while holder liveness and activity stay live.
/// Everywhere else the single-connection form above applies.
pub(super) async fn project_work_states_in_cross_pool(
    projection_conn: &mut SqliteConnection,
    live_target_pool: &SqlitePool,
    caller: &Caller,
    record_ids: &[String],
) -> Result<HashMap<String, Value>> {
    if record_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows = projection_rows(&mut *projection_conn, record_ids).await?;
    let holder_keys = holder_keys_for(&rows, caller)?;
    // One live-pool checkout serves every holder-liveness and activity read
    // through the shared single-connection helpers below; the scratch
    // projection connection never sits alongside a second live slot.
    let mut live_conn = live_target_pool.acquire().await?;
    let mut holder_run_states: HashMap<Option<String>, &'static str> = HashMap::new();
    for key in &holder_keys {
        let run_state =
            neighbour_run_state_on(&mut live_conn, caller.credential(), key.as_deref()).await?;
        holder_run_states.insert(key.clone(), run_state);
    }
    let holder_activities = holder_activities_on(&mut live_conn, caller, &holder_keys).await?;
    fold_projected_states(rows, caller, &holder_run_states, &holder_activities)
}

async fn projection_rows(
    conn: &mut SqliteConnection,
    record_ids: &[String],
) -> Result<Vec<sqlx::sqlite::SqliteRow>> {
    let mut query = QueryBuilder::<Sqlite>::new(
        "SELECT r.id, r.claimed_by_account, r.claimed_run_key, r.claimed_at, \
                (SELECT event.id FROM content_events event \
                   WHERE event.record_id=r.id AND event.type='record.updated' \
                     AND event.created_at=r.claimed_at \
                     AND json_extract(event.payload,'$.claimed_by_account')=r.claimed_by_account \
                     AND ((r.claimed_run_key IS NULL \
                           AND json_type(event.payload,'$.claimed_run_key')='null') \
                          OR json_extract(event.payload,'$.claimed_run_key')=r.claimed_run_key) \
                   ORDER BY event.seq DESC LIMIT 1) AS claim_event_id \
            FROM records r \
           WHERE r.deleted_at IS NULL AND r.id IN (",
    );
    let mut separated = query.separated(", ");
    for record_id in record_ids {
        separated.push_bind(record_id);
    }
    separated.push_unseparated(") ORDER BY r.id");
    Ok(query.build().fetch_all(conn).await?)
}

/// Distinct holder run keys needing liveness for the caller's own account.
///
/// A run key is caller-supplied correlation, not authority. Holder liveness
/// resolves with the canonical `neighbour_run_state` for same-account
/// holders only — account-scoped, so a reused run key from another account
/// never enriches the holder's target — while `activity_id` still comes
/// from one batch lookup. Withheld holder tuples must not become a timing
/// or error oracle either way.
fn holder_keys_for(
    rows: &[sqlx::sqlite::SqliteRow],
    caller: &Caller,
) -> Result<Vec<Option<String>>> {
    let mut holder_keys: Vec<Option<String>> = Vec::new();
    for row in rows {
        let account: Option<String> = row.try_get("claimed_by_account")?;
        if account.as_deref() == Some(caller.credential()) {
            let run_key: Option<String> = row.try_get("claimed_run_key")?;
            if !holder_keys.contains(&run_key) {
                holder_keys.push(run_key);
            }
        }
    }
    Ok(holder_keys)
}

async fn holder_activities_on(
    conn: &mut SqliteConnection,
    caller: &Caller,
    holder_keys: &[Option<String>],
) -> Result<HashMap<String, String>> {
    let mut holder_activities: HashMap<String, String> = HashMap::new();
    let holder_some_keys: Vec<&String> =
        holder_keys.iter().filter_map(|key| key.as_ref()).collect();
    if !holder_some_keys.is_empty() {
        let mut activity_query = QueryBuilder::<Sqlite>::new(
            "SELECT run_key, activity_id FROM agent_runs WHERE account_id=",
        );
        activity_query.push_bind(caller.credential());
        activity_query.push(" AND run_key IN (");
        let mut separated = activity_query.separated(", ");
        for run_key in &holder_some_keys {
            separated.push_bind(*run_key);
        }
        separated.push_unseparated(")");
        for row in activity_query.build().fetch_all(&mut *conn).await? {
            let run_key: String = row.try_get("run_key")?;
            let activity_id: String = row.try_get("activity_id")?;
            holder_activities.insert(run_key, activity_id);
        }
    }
    Ok(holder_activities)
}

fn fold_projected_states(
    rows: Vec<sqlx::sqlite::SqliteRow>,
    caller: &Caller,
    holder_run_states: &HashMap<Option<String>, &'static str>,
    holder_activities: &HashMap<String, String>,
) -> Result<HashMap<String, Value>> {
    let mut projected = HashMap::with_capacity(rows.len());
    for row in rows {
        let claimed_run_key: Option<String> = row.try_get("claimed_run_key")?;
        let claimed_by_account: Option<String> = row.try_get("claimed_by_account")?;
        let (activity_id, holder_run_state) =
            if claimed_by_account.as_deref() == Some(caller.credential()) {
                let activity_id = claimed_run_key
                    .as_deref()
                    .and_then(|holder_run| holder_activities.get(holder_run).cloned());
                // Every same-account holder key was resolved above, including
                // `None`; the fallback is unreachable defensive padding.
                let holder_run_state = holder_run_states
                    .get(&claimed_run_key)
                    .copied()
                    .unwrap_or("missing");
                (activity_id, holder_run_state)
            } else {
                (None, "missing")
            };
        let state = ProjectedClaimState {
            record_id: row.try_get("id")?,
            claimed_by_account,
            claimed_run_key,
            claimed_at: row.try_get("claimed_at")?,
            claim_event_id: row.try_get("claim_event_id")?,
            activity_id,
            holder_run_state,
        };
        projected.insert(state.record_id.clone(), state.work_state(caller));
    }
    Ok(projected)
}

async fn project_work_state(db: &Db, caller: &Caller, record_id: &str) -> Result<Value> {
    let mut conn = db.write_pool().acquire().await?;
    project_work_states_in(&mut conn, caller, &[record_id.to_string()])
        .await?
        .remove(record_id)
        .ok_or_else(|| Error::engine(format!("start_work: record {record_id} does not exist")))
}

// ---------------------------------------------------------------------------
// Work overlap — a claim-time notice about neighbouring claims
// ---------------------------------------------------------------------------

/// Bounds the notice to a legible size once the visible claimed overlap in a
/// relation has been counted. Never applied to the SQL candidate scan itself:
/// every neighbourhood query below is restricted to CLAIMED, non-deleted
/// records from the start, so the candidate set is bounded by active work
/// (rare) rather than by a container's total fan-out (unbounded). Capping the
/// scan itself, tried first, made `truncated` fire on rows the caller cannot
/// even see (a one-bit existence oracle) and could drop a visible claimed
/// record with no truncation signal at all.
const OVERLAP_RELATION_CAP: usize = 50;

/// The disclosable relations between a focus record and a neighbourhood
/// candidate. The record itself is never a candidate of the neighbourhood
/// queries below: every query excludes the focus id directly, so "a caller's
/// own fresh claim is not an overlap" is a structural property of the queries,
/// not a tier-dependent exclusion applied afterward.
///
/// `SameRecord` is the one exception, and only when a caller opts in (the
/// `set_intent` briefing, where the anchor itself matters): the focus record's
/// own claim tuple is read separately and folded in with this relation. The
/// claim path keeps excluding the anchor, since a first claim must stay
/// byte-identical.
///
/// Declaration order is precedence order for a candidate that matches more
/// than one relation (e.g. `C part_of T` and `C part_of T`'s parent `P`, with
/// `T` itself `part_of P`, makes `C` both a `Sibling` of `T` via `P` and a
/// `Child` of `T` directly): `SameRecord` is resolved first, then `Parent`,
/// then `Sibling`, then `Child`, and the first relation to claim a candidate
/// keeps it. The same order is also the sort key used to make the
/// per-relation cap deterministic below. The opted-in self row can never
/// collide with a neighbourhood row — the queries exclude the focus id — so
/// leading with it changes nothing for the other relations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum OverlapRelation {
    SameRecord,
    Parent,
    Sibling,
    Child,
}

impl OverlapRelation {
    fn as_str(self) -> &'static str {
        match self {
            OverlapRelation::SameRecord => "same_record",
            OverlapRelation::Parent => "parent",
            OverlapRelation::Sibling => "sibling",
            OverlapRelation::Child => "child",
        }
    }
}

/// One claimed neighbourhood candidate: its resolved relation and the claim
/// tuple read alongside it, so a second round trip is not needed to fold it
/// into a response item.
struct OverlapCandidate {
    relation: OverlapRelation,
    account: String,
    run_key: Option<String>,
    claimed_at: Option<String>,
}

fn candidate_from_row(
    found: &mut HashMap<String, OverlapCandidate>,
    row: sqlx::sqlite::SqliteRow,
    relation: OverlapRelation,
) -> Result<()> {
    let id: String = row.try_get("id")?;
    if found.contains_key(&id) {
        // An earlier relation already claimed this id — precedence order
        // keeps it, matching the exclusions each query below already applies.
        return Ok(());
    }
    let account: String = row.try_get("claimed_by_account")?;
    let run_key: Option<String> = row.try_get("claimed_run_key")?;
    let claimed_at: Option<String> = row.try_get("claimed_at")?;
    found.insert(
        id,
        OverlapCandidate {
            relation,
            account,
            run_key,
            claimed_at,
        },
    );
    Ok(())
}

/// Resolve every CLAIMED, visible-relation candidate in the neighbourhood of
/// `record_id`: its `part_of` link targets and `home_id` parent (`Parent`);
/// the `part_of` children of those parents, excluding the record itself
/// (`Sibling`); and the record's own `part_of` children (`Child`). No LIMIT is
/// applied here — claims are rare, so the candidate set is bounded by active
/// work, not by fan-out — and `record_id` itself is excluded from every query
/// so it can never appear as its own overlap.
async fn overlap_neighbourhood(
    pool: &SqlitePool,
    record_id: &str,
) -> Result<HashMap<String, OverlapCandidate>> {
    let mut found: HashMap<String, OverlapCandidate> = HashMap::new();

    // The record's parents (home_id and part_of targets) regardless of THEIR
    // claim state — needed below to resolve siblings even when the parent
    // itself carries no claim.
    let all_parent_ids: Vec<String> = sqlx::query(
        "SELECT id FROM records \
          WHERE deleted_at IS NULL AND id <> ?1 \
            AND id IN ( \
              SELECT home_id FROM records WHERE id = ?1 AND home_id IS NOT NULL \
              UNION \
              SELECT target_id FROM links WHERE source_id = ?1 AND relationship = 'part_of' \
            )",
    )
    .bind(record_id)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|row| row.try_get::<String, _>("id"))
    .collect::<std::result::Result<_, _>>()?;

    // Parent and Sibling both range over the parent set, so it is bound ONCE
    // as a single JSON-array parameter (the `visible_ids_in_pool` pattern) —
    // binding one id per placeholder would spend SQLite's ~999-variable
    // budget on the parent list before the claim itself ever runs, on a
    // container with a large claimed family.
    if !all_parent_ids.is_empty() {
        let parent_ids_json = serde_json::to_string(&all_parent_ids)?;

        // Parent — claimed parents only.
        let rows = sqlx::query(
            "SELECT id, claimed_by_account, claimed_run_key, claimed_at FROM records \
              WHERE deleted_at IS NULL AND claimed_by_account IS NOT NULL \
                AND id IN (SELECT value FROM json_each(?1))",
        )
        .bind(&parent_ids_json)
        .fetch_all(pool)
        .await?;
        for row in rows {
            candidate_from_row(&mut found, row, OverlapRelation::Parent)?;
        }

        // Sibling — claimed part_of children of the (full, claim-state-
        // agnostic) parent set, excluding the record itself. No `NOT IN` for
        // ids a Parent match already claimed: `candidate_from_row` already
        // skips an id already present in `found`, so re-listing them as bind
        // parameters here would only spend more of that same budget for no
        // behavioural change.
        let rows = sqlx::query(
            "SELECT o.id, o.claimed_by_account, o.claimed_run_key, o.claimed_at \
               FROM links l JOIN records o ON o.id = l.source_id \
              WHERE l.relationship = 'part_of' AND o.deleted_at IS NULL \
                AND o.claimed_by_account IS NOT NULL AND o.id <> ?1 \
                AND l.target_id IN (SELECT value FROM json_each(?2))",
        )
        .bind(record_id)
        .bind(&parent_ids_json)
        .fetch_all(pool)
        .await?;
        for row in rows {
            candidate_from_row(&mut found, row, OverlapRelation::Sibling)?;
        }
    }

    // Child — the record's own claimed part_of children, excluding the
    // record itself. Same reasoning as Sibling above: no `NOT IN` against
    // `found`, since `candidate_from_row` is where that exclusion actually
    // happens.
    let rows = sqlx::query(
        "SELECT o.id, o.claimed_by_account, o.claimed_run_key, o.claimed_at \
           FROM links l JOIN records o ON o.id = l.source_id \
          WHERE l.target_id = ?1 AND l.relationship = 'part_of' AND o.deleted_at IS NULL \
            AND o.claimed_by_account IS NOT NULL AND o.id <> ?1",
    )
    .bind(record_id)
    .fetch_all(pool)
    .await?;
    for row in rows {
        candidate_from_row(&mut found, row, OverlapRelation::Child)?;
    }

    Ok(found)
}

/// Same-credential run liveness for a neighbourhood holder, resolved the same
/// way `project_work_states_in` resolves it for the caller's own exact tuple:
/// `open` when observed inside the horizon, `silent` when observable but
/// quiet past it, `closed` once it ended, `missing` when no `agent_runs` row
/// exists for the key, `not_applicable` when the claim carries no run key at
/// all. Only ever called for a holder sharing the caller's account —
/// resolving it for another principal would build the cross-account oracle
/// the projection above deliberately refuses.
async fn neighbour_run_state(
    pool: &SqlitePool,
    account: &str,
    run_key: Option<&str>,
) -> Result<&'static str> {
    // One checkout, then the shared connection-scoped body: callers that
    // already hold a connection must use `neighbour_run_state_on` directly,
    // so this pool form exists only where no connection is held.
    if run_key.is_none() {
        return Ok("not_applicable");
    }
    let mut conn = pool.acquire().await?;
    neighbour_run_state_on(&mut conn, account, run_key).await
}

/// Connection-scoped form of [`neighbour_run_state`], and the single place
/// the `agent_runs` liveness query lives: a handler already holding a
/// connection reads liveness on it instead of taking a second pool slot.
///
/// Delegates to [`neighbour_run_state_at`] against the engine clock.
async fn neighbour_run_state_on(
    conn: &mut SqliteConnection,
    account: &str,
    run_key: Option<&str>,
) -> Result<&'static str> {
    neighbour_run_state_at(conn, account, run_key, &crate::store::now_iso()).await
}

/// Resolve a holder run's state against an injected observation time.
///
/// `open` means observed within the horizon, not merely un-closed. The
/// distinction matters because `ended_at` is written by `close_run`, a
/// terminal act the overwhelming majority of runs never perform: reading
/// liveness from it alone reports every abandoned holder as `open`, which
/// makes a claim held by a dead run indistinguishable from one held by a
/// run working right now. Recency is derived from activity the run cannot
/// omit, so it needs no cooperation from the holder.
///
/// The four values:
///
/// * `missing` — no such run for this account.
/// * `closed` — the run ended. Terminal, and takes precedence over recency.
/// * `open` — observed inside the horizon.
/// * `silent` — observable, and quiet past the horizon. This is evidence
///   about the run, never proof: silence cannot prove inactivity, and an
///   agent that is working without calling Native is silent by definition.
///
/// Two deliberate divergences from the `agent_activity` relation, which
/// derives the same recency (`src/query/sql.rs`):
///
/// 1. The relation excludes claim-tuple updates from recency so that hiding
///    a claim can never alter presence or ordering. That guarantee protects
///    a surface this one is inside: holder liveness resolves for
///    same-account holders only, and the caller already sees the claim. The
///    exclusion also costs a `json_type` scan of every run-scoped payload
///    under the caller ceiling, which is the open defect `768eb1d`; this
///    path opens no payload and so cannot inherit it.
/// 2. The relation folds in the disposable read-log observation when the
///    protected helper is available. That helper is a temp projection built
///    per governed query and is absent here, leaving the durable subset —
///    which is what the relation itself falls back to.
///
/// An unparseable stored timestamp yields `silent` rather than an error,
/// matching the relation, whose `appears_active` likewise resolves false
/// when its comparison is not computable.
async fn neighbour_run_state_at(
    conn: &mut SqliteConnection,
    account: &str,
    run_key: Option<&str>,
    observed_at: &str,
) -> Result<&'static str> {
    let Some(run_key) = run_key else {
        return Ok("not_applicable");
    };
    let row: Option<(i64, i64)> = sqlx::query_as(&format!(
        "WITH holder AS ( \
           SELECT run.ended_at AS ended_at, \
                  max(run.started_at, \
                      coalesce((SELECT max(event.created_at) FROM content_events event \
                                  WHERE event.run_key=run.run_key \
                                    AND event.actor=run.account_id), \
                               run.started_at)) AS last_observed_activity_at \
             FROM agent_runs run \
            WHERE run.run_key=? AND run.account_id=? \
         ) \
         SELECT ended_at IS NOT NULL AS closed, \
                coalesce(julianday(?) \
                         < julianday(last_observed_activity_at, '{HOLDER_ACTIVE_HORIZON}'), 0) \
                  AS within_horizon \
           FROM holder"
    ))
    .bind(run_key)
    .bind(account)
    .bind(observed_at)
    .fetch_optional(&mut *conn)
    .await?;
    Ok(match row {
        None => "missing",
        Some((closed, _)) if closed != 0 => "closed",
        Some((_, within_horizon)) if within_horizon != 0 => "open",
        Some(_) => "silent",
    })
}

/// How a neighbourhood holder relates to the caller's own credential and run.
///
/// `this_run` requires an EXACT run-key match — the engine cannot tell two
/// keyless sessions of the same account apart, so a holder with no run key is
/// never `this_run` even when the caller also has none; it is reported as
/// `another_agent_of_yours` (with `run_state: not_applicable`, since there is
/// no key to resolve liveness from) instead. The record being claimed can
/// never itself be a neighbour (see [`overlap_neighbourhood`]), so this
/// stricter rule cannot mislabel a caller's own fresh claim — the engine
/// refuses a second claim on the same record while the first still holds it,
/// so that case cannot arise here at all.
fn holder_tier(caller: &Caller, account: &str, run_key: Option<&str>) -> &'static str {
    if account != caller.credential() {
        return "another_principal";
    }
    match (caller.run_key(), run_key) {
        (Some(caller_run), Some(holder_run)) if caller_run == holder_run => "this_run",
        (Some(caller_run), Some(holder_run))
            if crate::runkey::agent_key_of(caller_run)
                == crate::runkey::agent_key_of(holder_run) =>
        {
            "another_run_of_this_agent"
        }
        _ => "another_agent_of_yours",
    }
}

/// The claim-time overlap notice: every OTHER active claim in the bounded
/// neighbourhood of `record_id`, filtered to what the caller may `View`.
/// Existence and relation are always disclosed; holder identity, timestamp,
/// run key and intent only when the holder's account matches the caller's own
/// credential. Returns `None` when there is nothing to disclose, so the
/// caller can omit `work_overlap` entirely and keep an overlap-free claim
/// response byte-identical to one from before this notice existed.
///
/// `include_self` folds the focus record's own claim in as a `same_record`
/// item — for surfaces where the anchor itself matters (the `set_intent`
/// briefing, `create_record` never needs it: the new record is unclaimed).
/// A self claim held by the caller's own exact run tuple is still excluded,
/// so one's own anchor never reports overlap with itself; anything else goes
/// through the ordinary tier rules below.
pub(super) async fn work_overlap_for_record(
    db: &Db,
    caller: &Caller,
    record_id: &str,
    include_self: bool,
) -> Result<Option<Value>> {
    let pool = db.write_pool();
    let mut candidates = overlap_neighbourhood(pool, record_id).await?;
    if include_self {
        let own: Option<(String, Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT claimed_by_account, claimed_run_key, claimed_at FROM records \
              WHERE id = ?1 AND deleted_at IS NULL AND claimed_by_account IS NOT NULL",
        )
        .bind(record_id)
        .fetch_optional(pool)
        .await?;
        if let Some((account, run_key, claimed_at)) = own {
            if holder_tier(caller, &account, run_key.as_deref()) != "this_run" {
                candidates.insert(
                    record_id.to_string(),
                    OverlapCandidate {
                        relation: OverlapRelation::SameRecord,
                        account,
                        run_key,
                        claimed_at,
                    },
                );
            }
        }
    }
    if candidates.is_empty() {
        return Ok(None);
    }

    // Batch the View filter over the whole claimed candidate set — the same
    // seam the links fold uses — rather than a per-row `can_record` call.
    let ids: Vec<String> = candidates.keys().cloned().collect();
    let visible = visible_ids_in_pool(pool, caller, ids).await?;

    // Deterministic order across the whole overlap keeps the same items on
    // every call once the cap trims the tail: relation precedence, then
    // `claimed_at`, then id.
    let mut ordered: Vec<(&String, &OverlapCandidate)> = candidates
        .iter()
        .filter(|(id, _)| visible.contains(*id))
        .collect();
    ordered.sort_by(|(id_a, candidate_a), (id_b, candidate_b)| {
        candidate_a
            .relation
            .cmp(&candidate_b.relation)
            .then_with(|| candidate_a.claimed_at.cmp(&candidate_b.claimed_at))
            .then_with(|| id_a.cmp(id_b))
    });

    // Counted BEFORE the per-relation cap below, over exactly the visible
    // claimed candidates — an invisible row never moves this number, and
    // `truncated` is derived from it rather than from the SQL scan.
    let total_count = ordered.len();
    if total_count == 0 {
        return Ok(None);
    }

    let mut per_relation_count: HashMap<OverlapRelation, usize> = HashMap::new();
    let mut items = Vec::new();
    for (id, candidate) in ordered {
        let count = per_relation_count.entry(candidate.relation).or_insert(0);
        if *count >= OVERLAP_RELATION_CAP {
            continue;
        }
        *count += 1;

        let tier = holder_tier(caller, &candidate.account, candidate.run_key.as_deref());
        let mut item = json!({
            "record_id": id,
            "relation": candidate.relation.as_str(),
            "holder_tier": tier,
        });
        if tier != "another_principal" {
            let object = item.as_object_mut().expect("item is an object");
            let run_state =
                neighbour_run_state(pool, &candidate.account, candidate.run_key.as_deref()).await?;
            object.insert("run_state".into(), json!(run_state));
            if let Some(claimed_at) = &candidate.claimed_at {
                object.insert("claimed_at".into(), json!(claimed_at));
            }
            if let Some(run_key) = candidate.run_key.as_deref() {
                object.insert("run_key".into(), json!(run_key));
                // Account-scoped: a run key is a hashtag any account can
                // reuse, so resolving intent by key alone could hand this
                // holder another account's declared sentence.
                if let Some(intent) =
                    crate::runkey::intent_at_for_actor(db, Some(run_key), &candidate.account).await
                {
                    object.insert("intent".into(), json!(intent));
                }
            }
        }
        items.push(item);
    }
    if items.is_empty() {
        return Ok(None);
    }
    let truncated = total_count > items.len();
    Ok(Some(json!({
        "items": items,
        "total_count": total_count,
        "truncated": truncated,
    })))
}

/// The `start_work.claim` notice: the shared window with the anchor itself
/// always excluded, since a first claim must stay byte-identical.
async fn work_overlap_for_claim(
    db: &Db,
    caller: &Caller,
    record_id: &str,
) -> Result<Option<Value>> {
    work_overlap_for_record(db, caller, record_id, false).await
}

impl ClaimState {
    fn is_claimed(&self) -> bool {
        self.claimed_by_account.is_some()
    }

    fn is_owned_by(&self, caller: &Caller) -> bool {
        self.claimed_by_account.as_deref() == Some(caller.credential())
            && self.claimed_run_key.as_deref() == caller.run_key()
    }

    fn is_same_account(&self, caller: &Caller) -> bool {
        self.claimed_by_account.as_deref() == Some(caller.credential())
    }

    fn held_by(&self) -> Option<String> {
        self.claimed_run_key
            .as_deref()
            .map(crate::runkey::handle_of)
            .map(String::from)
            .or_else(|| self.claimed_by_account.clone())
    }
}

fn claim_state_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<ClaimState> {
    Ok(ClaimState {
        lifecycle: row.try_get("lifecycle")?,
        claimed_by_account: row.try_get("claimed_by_account")?,
        claimed_run_key: row.try_get("claimed_run_key")?,
        claimed_at: row.try_get("claimed_at")?,
    })
}

async fn claim_state(db: &Db, record_id: &str) -> Result<ClaimState> {
    let row = sqlx::query(
        "SELECT lifecycle, claimed_by_account, claimed_run_key, claimed_at
           FROM records WHERE id = ? AND deleted_at IS NULL",
    )
    .bind(record_id)
    .fetch_optional(db.write_pool())
    .await?
    .ok_or_else(|| Error::engine(format!("start_work: record {record_id} does not exist")))?;
    claim_state_from_row(&row)
}

async fn claim_state_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    record_id: &str,
) -> Result<ClaimState> {
    let row = sqlx::query(
        "SELECT lifecycle, claimed_by_account, claimed_run_key, claimed_at
           FROM records WHERE id = ? AND deleted_at IS NULL",
    )
    .bind(record_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| Error::engine(format!("start_work: record {record_id} does not exist")))?;
    claim_state_from_row(&row)
}

fn already_claimed(tool: &str, id: &str, state: &ClaimState, caller: &Caller) -> Error {
    if let Some(holder) = state.held_by() {
        if state.is_owned_by(caller) {
            return Error::engine(format!(
                "{tool}: record {id} is already claimed by {holder} — release it first"
            ));
        }
    }
    if let Some(account) = state.claimed_by_account.as_deref() {
        if account == caller.credential() {
            // Same vocabulary as the overlap notice: the tier and run key the
            // caller would also see in preview and `work_overlap`.
            let tier = holder_tier(caller, account, state.claimed_run_key.as_deref());
            let holder_run = state.claimed_run_key.as_deref().unwrap_or("null");
            return Error::engine(format!(
                "{tool}: record {id} is already claimed by run {holder_run} \
                 (holder_tier={tier}) — preview to inspect, then release with \
                 expected_holder_run_key to take the claim back"
            ));
        }
    }
    Error::engine(format!(
        "{tool}: record {id} is already claimed — release it first"
    ))
}

// ---------------------------------------------------------------------------
// Working context
// ---------------------------------------------------------------------------

const WORK_COMMENT_ROOT_LIMIT: usize = 10;
const WORK_COMMENT_REPLY_LIMIT: usize = 20;

/// The SQL fragment excluding archived rows for the aliased table `o`.
const OTHER_NOT_ARCHIVED: &str = "NOT EXISTS (SELECT 1 FROM facet_values av \
     WHERE av.record_id = o.id AND av.key = 'archived')";

fn linked_entry(row: &sqlx::sqlite::SqliteRow) -> Result<Value> {
    Ok(json!({
        "id": row.try_get::<String, _>("id")?,
        "type": row.try_get::<String, _>("type")?,
        "kind": row.try_get::<Option<String>, _>("kind")?,
        "name": row.try_get::<String, _>("name")?,
        "lifecycle": row.try_get::<Option<String>, _>("lifecycle")?,
        "summary": row.try_get::<Option<String>, _>("summary")?,
        "relationship": row.try_get::<String, _>("relationship")?,
        "direction": row.try_get::<String, _>("direction")?,
        "note": row.try_get::<Option<String>, _>("note")?,
    }))
}

fn dependency_entry(
    row: &sqlx::sqlite::SqliteRow,
    lifecycle_interpreter: &LifecycleInterpreter,
) -> Result<(bool, Value)> {
    let record_type: String = row.try_get("type")?;
    let kind: Option<String> = row.try_get("kind")?;
    let home_id: Option<String> = row.try_get("home_id")?;
    let lifecycle: Option<String> = row.try_get("lifecycle")?;
    let interpretation = lifecycle_interpreter.interpret(
        &record_type,
        kind.as_deref(),
        home_id.as_deref(),
        lifecycle.as_deref(),
    );
    let satisfaction = match &interpretation {
        LifecycleInterpretation::Governed(governed)
            if governed.terminality == "terminal_positive" =>
        {
            "satisfied"
        }
        LifecycleInterpretation::Governed(governed)
            if governed.terminality == "terminal_negative" =>
        {
            "unsatisfied"
        }
        LifecycleInterpretation::Governed(_) => "waiting",
        LifecycleInterpretation::Absent(_) | LifecycleInterpretation::Unclassified(_) => {
            "ambiguous"
        }
    };
    let mut entry = linked_entry(row)?;
    let object = entry.as_object_mut().expect("linked entry is an object");
    object.insert(
        "lifecycle_interpretation".into(),
        serde_json::to_value(interpretation)?,
    );
    object.insert("satisfaction".into(), json!(satisfaction));
    Ok((satisfaction == "satisfied", entry))
}

/// The governance a claimant is answerable to: `Resolution` records linked to
/// this one, in either direction, live and unarchived. Only the record's OWN
/// links — inherited governance is a walk
/// this tool deliberately does not take, because the ancestor path comes back
/// with the record and can be followed.
async fn governance(db: &Db, caller: &Caller, id: &str) -> Result<Vec<Value>> {
    let sql = format!(
        "SELECT o.id AS id, o.type AS type, o.kind AS kind, o.name AS name,
                o.lifecycle AS lifecycle, o.summary AS summary,
                l.relationship AS relationship, l.note AS note, 'out' AS direction
           FROM links l JOIN records o ON o.id = l.target_id
          WHERE l.source_id = ?1 AND o.deleted_at IS NULL
            AND o.type = 'Resolution' AND {OTHER_NOT_ARCHIVED}
          UNION ALL
         SELECT o.id AS id, o.type AS type, o.kind AS kind, o.name AS name,
                o.lifecycle AS lifecycle, o.summary AS summary,
                l.relationship AS relationship, l.note AS note, 'in' AS direction
           FROM links l JOIN records o ON o.id = l.source_id
          WHERE l.target_id = ?1 AND o.deleted_at IS NULL
            AND o.type = 'Resolution' AND {OTHER_NOT_ARCHIVED}
          ORDER BY direction, relationship, name, id"
    );
    let rows = sqlx::query(&sql)
        .bind(id)
        .fetch_all(db.write_pool())
        .await?;
    let mut visible = Vec::new();
    for row in &rows {
        let related_id: String = row.try_get("id")?;
        if super::can_record(db, caller, &related_id, Capability::View).await? {
            visible.push(linked_entry(row)?);
        }
    }
    Ok(visible)
}

/// A live, visible outgoing `depends_on` target is satisfied only when its
/// governed lifecycle is terminal-positive. Governed open, terminal-negative,
/// absent, and unclassified lifecycles remain under `waiting_on`, with their
/// interpretation and satisfaction attached so callers can distinguish an
/// active prerequisite from a failed or ambiguous one. Incoming `blocks`
/// remains an explicit statement of current prevention and is not inferred
/// from lifecycle. Tombstoning or archiving either endpoint releases it.
///
/// `ready` is advisory context, not a claim gate: a non-ready record remains
/// claimable, and the claimant is told what it is walking into.
async fn dependencies(db: &Db, caller: &Caller, id: &str) -> Result<Value> {
    let sql = format!(
        "SELECT o.id AS id, o.type AS type, o.kind AS kind, o.name AS name, o.home_id AS home_id,
                o.lifecycle AS lifecycle, o.summary AS summary,
                l.relationship AS relationship, l.note AS note, 'out' AS direction
           FROM links l JOIN records o ON o.id = l.target_id
          WHERE l.source_id = ?1 AND l.relationship = 'depends_on'
            AND o.deleted_at IS NULL AND {OTHER_NOT_ARCHIVED}
          ORDER BY name, id"
    );
    let waiting_rows = sqlx::query(&sql)
        .bind(id)
        .fetch_all(db.write_pool())
        .await?;
    let lifecycle_interpreter = if waiting_rows.is_empty() {
        None
    } else {
        let principal = (!super::is_legacy_local(caller)).then(|| super::principal(caller));
        Some(LifecycleInterpreter::load(db, principal).await?)
    };
    let mut waiting_on = Vec::new();
    let mut satisfied = Vec::new();
    for row in &waiting_rows {
        let related_id: String = row.try_get("id")?;
        if super::can_record(db, caller, &related_id, Capability::View).await? {
            let (is_satisfied, entry) = dependency_entry(
                row,
                lifecycle_interpreter
                    .as_ref()
                    .expect("waiting rows require lifecycle interpretation"),
            )?;
            if is_satisfied {
                satisfied.push(entry);
            } else {
                waiting_on.push(entry);
            }
        }
    }
    let sql = format!(
        "SELECT o.id AS id, o.type AS type, o.kind AS kind, o.name AS name,
                o.lifecycle AS lifecycle, o.summary AS summary,
                l.relationship AS relationship, l.note AS note, 'in' AS direction
           FROM links l JOIN records o ON o.id = l.source_id
          WHERE l.target_id = ?1 AND l.relationship = 'blocks'
            AND o.deleted_at IS NULL AND {OTHER_NOT_ARCHIVED}
          ORDER BY name, id"
    );
    let blocked_rows = sqlx::query(&sql)
        .bind(id)
        .fetch_all(db.write_pool())
        .await?;
    let mut blocked_by = Vec::new();
    for row in &blocked_rows {
        let related_id: String = row.try_get("id")?;
        if super::can_record(db, caller, &related_id, Capability::View).await? {
            blocked_by.push(linked_entry(row)?);
        }
    }
    Ok(json!({
        "ready": waiting_on.is_empty() && blocked_by.is_empty(),
        "waiting_on": waiting_on,
        "satisfied": satisfied,
        "blocked_by": blocked_by,
    }))
}

/// The working context, read AFTER any write so it shows the record as claimed.
/// Ancestors ride along on the enriched record.
///
/// The record's existence was established at the top of the call, so a miss
/// here means it was hard-deleted underneath us — reported rather than folded
/// into a null.
async fn working_context(db: &Db, caller: &Caller, tool: &str, id: &str) -> Result<Value> {
    let Some(mut record) = read::get_record(db, id).await? else {
        return Err(Error::engine(format!(
            "{tool}: record {id} disappeared mid-call"
        )));
    };
    super::lifecycle::filter_enriched_record_with_auth(
        db,
        db,
        caller,
        &mut record,
        read::EnrichOptions::default(),
    )
    .await?;
    let lens = crate::query::lens::ReadLens::live(db);
    let principal = (!super::is_legacy_local(caller)).then(|| super::principal(caller));
    let direct = read::comment_window_for_work(
        &lens,
        id,
        principal,
        Some("open"),
        WORK_COMMENT_ROOT_LIMIT as i64,
        0,
    )
    .await?;
    let open_thread_count = direct.total;
    let mut open_threads = Vec::new();
    for root in direct.comments {
        let replies = read::comment_window_for_work(
            &lens,
            &root.id,
            principal,
            None,
            WORK_COMMENT_REPLY_LIMIT as i64,
            0,
        )
        .await?;
        open_threads.push(json!({
            "root": root,
            "replies": replies.comments,
            "reply_count": replies.total,
            "replies_limit": WORK_COMMENT_REPLY_LIMIT,
        }));
    }
    Ok(json!({
        "record": record,
        "governance": governance(db, caller, id).await?,
        "dependencies": dependencies(db, caller, id).await?,
        "comments": {
            "open_threads": open_threads,
            "open_thread_count": open_thread_count,
            "roots_limit": WORK_COMMENT_ROOT_LIMIT,
            "replies_limit": WORK_COMMENT_REPLY_LIMIT,
        },
    }))
}

// ---------------------------------------------------------------------------
// Tool 31 — start_work
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StartWorkArgs {
    record_id: String,
    action: Option<String>,
    /// Accepted only for wire compatibility. Identity comes from `Caller`.
    #[serde(rename = "agent_id")]
    _agent_id: Option<String>,
    /// Compare-and-release guard for same-account recovery. Presence is the
    /// opt-in: absent means no expectation, explicit null expects an
    /// account-only holder, a string expects that exact holder run key.
    #[serde(default, deserialize_with = "deserialize_expected_holder_run_key")]
    expected_holder_run_key: Option<Option<String>>,
}

fn deserialize_expected_holder_run_key<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Some(Option::<String>::deserialize(deserializer)?))
}

#[derive(Debug)]
struct Outcome {
    changed: bool,
    claimed: bool,
    lifecycle: Option<String>,
    held_by: Option<String>,
    held_by_account: Option<String>,
    held_by_run_key: Option<String>,
    claimed_at: Option<String>,
    act: Option<i64>,
}

impl Outcome {
    fn from_state(changed: bool, state: ClaimState) -> Self {
        let held_by = state.held_by();
        Self {
            changed,
            claimed: state.is_claimed(),
            lifecycle: state.lifecycle,
            held_by,
            held_by_account: state.claimed_by_account,
            held_by_run_key: state.claimed_run_key,
            claimed_at: state.claimed_at,
            act: None,
        }
    }
}

async fn claim(db: &Db, caller: &Caller, tool: &str, args: &StartWorkArgs) -> Result<Outcome> {
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let mut act_alloc = crate::act::ActAllocation::new();
    require_record_in(&mut tx, caller, tool, &args.record_id, Capability::Edit).await?;
    if let Some(run_key) = caller.run_key() {
        let lifecycle: Option<(String, Option<String>)> =
            sqlx::query_as("SELECT account_id,ended_at FROM agent_runs WHERE run_key=?")
                .bind(run_key)
                .fetch_optional(&mut *tx)
                .await?;
        if let Some((account_id, ended_at)) = lifecycle {
            if account_id != caller.credential() {
                return Err(Error::engine(format!(
                    "{tool}: run correlation is already bound to another principal"
                )));
            }
            if ended_at.is_some() {
                return Err(Error::engine(format!("{tool}: run is closed")));
            }
        }
    }
    let state = claim_state_in(&mut tx, &args.record_id).await?;
    if state.is_claimed() {
        return if state.is_owned_by(caller) {
            Ok(Outcome::from_state(false, state))
        } else {
            Err(already_claimed(tool, &args.record_id, &state, caller))
        };
    }
    let event = append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: args.record_id.clone(),
            event_type: "record.updated".into(),
            payload: json!({
                "claimed_by_account": caller.credential(),
                "claimed_run_key": caller.run_key(),
            }),
            actor: Some(caller.actor().to_string()),
        },
        &mut act_alloc,
    )
    .await?;
    db.commit_content(tx).await?;
    Ok(Outcome {
        changed: true,
        claimed: true,
        lifecycle: state.lifecycle,
        held_by: Some(
            caller
                .run_key()
                .map(crate::runkey::handle_of)
                .unwrap_or(caller.credential())
                .to_string(),
        ),
        held_by_account: Some(caller.credential().to_string()),
        held_by_run_key: caller.run_key().map(String::from),
        claimed_at: Some(event.created_at),
        act: act_alloc.get(),
    })
}

async fn release(db: &Db, caller: &Caller, tool: &str, args: &StartWorkArgs) -> Result<Outcome> {
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let mut act_alloc = crate::act::ActAllocation::new();
    require_record_in(&mut tx, caller, tool, &args.record_id, Capability::Edit).await?;
    let state = claim_state_in(&mut tx, &args.record_id).await?;
    if !state.is_claimed() {
        return Err(Error::engine(format!(
            "{tool}: record {} is not claimed — nothing to release",
            args.record_id,
        )));
    }
    let is_exact_holder = state.is_owned_by(caller);
    let is_trusted_local = super::is_legacy_local(caller);
    let is_same_account = state.is_same_account(caller);
    if is_exact_holder {
        if let Some(expected) = args.expected_holder_run_key.as_ref() {
            if expected.as_deref() != state.claimed_run_key.as_deref() {
                return Err(Error::engine(format!(
                    "{tool}: expected_holder_run_key does not match the current holder — \
                     preview and retry with the current holder"
                )));
            }
        }
    } else if is_trusted_local {
        // Recovery path unchanged: permission bypasses ownership.
    } else if is_same_account {
        match args.expected_holder_run_key.as_ref() {
            None => {
                let holder_run = state.claimed_run_key.as_deref().unwrap_or("null");
                return Err(Error::engine(format!(
                    "{tool}: record {} is claimed by run {holder_run} — pass \
                     expected_holder_run_key to take the claim back",
                    args.record_id,
                )));
            }
            Some(expected) => {
                if expected.as_deref() != state.claimed_run_key.as_deref() {
                    return Err(Error::engine(format!(
                        "{tool}: claim holder changed — preview and retry with the current holder"
                    )));
                }
            }
        }
    } else {
        return Err(Error::engine(format!(
            "{tool}: record {} is claimed by another caller",
            args.record_id
        )));
    }
    let mut payload = json!({
        "claimed_by_account": Value::Null,
        "claimed_run_key": Value::Null,
    });
    if !is_exact_holder {
        payload["released_from_run_key"] = match state.claimed_run_key.as_deref() {
            Some(run_key) => Value::String(run_key.to_string()),
            None => Value::Null,
        };
    }
    append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: args.record_id.clone(),
            event_type: "record.updated".into(),
            payload,
            actor: Some(caller.actor().to_string()),
        },
        &mut act_alloc,
    )
    .await?;
    db.commit_content(tx).await?;
    Ok(Outcome {
        changed: true,
        claimed: false,
        lifecycle: state.lifecycle,
        held_by: None,
        held_by_account: None,
        held_by_run_key: None,
        claimed_at: None,
        act: act_alloc.get(),
    })
}

async fn start_work(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    const TOOL: &str = "start_work";
    let args: StartWorkArgs = parse_args(TOOL, arguments)?;
    let action = args.action.as_deref().unwrap_or(ACTION_CLAIM);
    if !ACTIONS.contains(&action) {
        return Err(Error::engine(format!(
            "{TOOL}: unknown action '{action}' (expected {})",
            ACTIONS.join(", ")
        )));
    }

    require_record(
        &db,
        &caller,
        TOOL,
        &args.record_id,
        if action == ACTION_PREVIEW {
            Capability::View
        } else {
            Capability::Edit
        },
    )
    .await?;

    let mut outcome = match action {
        ACTION_PREVIEW => Outcome::from_state(false, claim_state(&db, &args.record_id).await?),
        ACTION_RELEASE => release(&db, &caller, TOOL, &args).await?,
        _ => claim(&db, &caller, TOOL, &args).await?,
    };

    if outcome.held_by_account.as_deref() != Some(caller.credential()) {
        outcome.held_by = None;
        outcome.held_by_account = None;
        outcome.held_by_run_key = None;
        outcome.claimed_at = None;
    }
    let work_state = project_work_state(&db, &caller, &args.record_id).await?;
    let context = working_context(&db, &caller, TOOL, &args.record_id).await?;
    let work_overlap = if action == ACTION_CLAIM {
        work_overlap_for_claim(&db, &caller, &args.record_id).await?
    } else {
        None
    };

    let mut response = json!({
        "record_id": args.record_id,
        "action": action,
        "changed": outcome.changed,
        "claimed": outcome.claimed,
        "lifecycle": outcome.lifecycle,
        "held_by": outcome.held_by,
        "held_by_account": outcome.held_by_account,
        "held_by_run_key": outcome.held_by_run_key,
        "claimed_at": outcome.claimed_at,
        "work_state": work_state,
        "context": context,
    });
    if let Some(overlap) = work_overlap {
        response
            .as_object_mut()
            .expect("start_work response is an object")
            .insert("work_overlap".into(), overlap);
    }
    // A preview or an already-held claim appended nothing canonical and
    // allocates no act; omit the field rather than reporting a value.
    if let Some(act) = outcome.act {
        response
            .as_object_mut()
            .expect("start_work response is an object")
            .insert("act".into(), act.into());
    }
    Ok(response)
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

/// Register legacy catalogue tool 31, shipping surface ordinal 26.
pub fn register_work_tools(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(
        ToolKind::StartWork,
        "Claim a record and get context: the record, ancestors, linked \
         resolutions, dependency readiness, and a bounded window of direct \
         open comment roots. Comments are pull-shaped discovery, not an inbox. \
         The claim is one conditional coordination write that leaves lifecycle \
         unchanged — a second claimant is refused, not queued. Actions: claim \
         (default), preview, release.",
        json!({
            "type": "object",
            "properties": {
                "record_id": { "type": "string", "description": "Record to claim, preview or release." },
                "action": {
                    "type": "string",
                    "enum": ACTIONS,
                    "description": "claim (default), preview (no write), or release."
                },
                "agent_id": {
                    "type": "string",
                    "description": "Deprecated; ignored."
                },
                "expected_holder_run_key": {
                    "type": ["string", "null"],
                    "description": "Same-account compare-and-release: the holding run key (null when account-only). Unneeded for your own run."
                }
            },
            "required": ["record_id"],
            "additionalProperties": false
        }),
        start_work,
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests — projected claim tuple
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::create_database;

    fn args(id: &str, action: &str) -> StartWorkArgs {
        StartWorkArgs {
            record_id: id.into(),
            action: Some(action.into()),
            _agent_id: None,
            expected_holder_run_key: None,
        }
    }

    fn args_with_expected(id: &str, action: &str, expected: Option<Option<&str>>) -> StartWorkArgs {
        StartWorkArgs {
            record_id: id.into(),
            action: Some(action.into()),
            _agent_id: None,
            expected_holder_run_key: expected.map(|inner| inner.map(String::from)),
        }
    }

    async fn subject(db: &Db) -> String {
        crate::store::create_record(
            db,
            json!({
                "type": "WorkItem",
                "kind": "x-test-fixture",
                "name": "Projected",
                "lifecycle": "in_progress"
            }),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn claim_and_release_leave_lifecycle_unchanged() {
        let db = create_database(":memory:").await.unwrap();
        let id = subject(&db).await;
        let caller = Caller::authenticated("account:a");
        let claimed = claim(&db, &caller, "start_work", &args(&id, ACTION_CLAIM))
            .await
            .unwrap();
        assert!(claimed.claimed && claimed.changed);
        assert_eq!(claimed.lifecycle.as_deref(), Some("in_progress"));
        let released = release(&db, &caller, "start_work", &args(&id, ACTION_RELEASE))
            .await
            .unwrap();
        assert!(!released.claimed && released.changed);
        assert_eq!(released.lifecycle.as_deref(), Some("in_progress"));
    }

    #[tokio::test]
    async fn stale_holder_tuple_cannot_release_a_later_claim() {
        let db = create_database(":memory:").await.unwrap();
        let id = subject(&db).await;
        let first = Caller::authenticated("account:a")
            .with_run_context(Some("scout-chair-a748b2".into()), None);
        let later = Caller::authenticated("account:a")
            .with_run_context(Some("scout-chair-b748b2".into()), None);
        claim(&db, &first, "start_work", &args(&id, ACTION_CLAIM))
            .await
            .unwrap();
        release(&db, &first, "start_work", &args(&id, ACTION_RELEASE))
            .await
            .unwrap();
        claim(&db, &later, "start_work", &args(&id, ACTION_CLAIM))
            .await
            .unwrap();
        // A stale same-account run retrying a bare release is refused: the
        // compare-and-release guard is required, and the later claim survives.
        let error = release(&db, &first, "start_work", &args(&id, ACTION_RELEASE))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("expected_holder_run_key"));
        assert!(error.contains("scout-chair-b748b2"));
        let current = claim_state(&db, &id).await.unwrap();
        assert_eq!(current.claimed_run_key, later.run_key().map(String::from));
    }

    #[tokio::test]
    async fn same_account_other_run_release_succeeds_with_expected_holder() {
        let db = create_database(":memory:").await.unwrap();
        let id = subject(&db).await;
        let first = Caller::authenticated("account:a")
            .with_run_context(Some("scout-chair-a748b2".into()), None);
        let second = Caller::authenticated("account:a")
            .with_run_context(Some("scout-chair-b748b2".into()), None);
        claim(&db, &first, "start_work", &args(&id, ACTION_CLAIM))
            .await
            .unwrap();
        let released = release(
            &db,
            &second,
            "start_work",
            &args_with_expected(&id, ACTION_RELEASE, Some(Some("scout-chair-a748b2"))),
        )
        .await
        .unwrap();
        assert!(!released.claimed && released.changed);
        let current = claim_state(&db, &id).await.unwrap();
        assert!(!current.is_claimed());
        let payload: serde_json::Value = sqlx::query_scalar(
            "SELECT payload FROM content_events WHERE record_id=? AND type='record.updated' \
             ORDER BY seq DESC LIMIT 1",
        )
        .bind(&id)
        .fetch_one(db.write_pool())
        .await
        .map(|raw: String| serde_json::from_str(&raw).unwrap())
        .unwrap();
        assert_eq!(payload["claimed_by_account"], serde_json::Value::Null);
        assert_eq!(payload["claimed_run_key"], serde_json::Value::Null);
        assert_eq!(payload["released_from_run_key"], "scout-chair-a748b2");
        // The extra release key projects through the claim fold: the record is
        // unclaimed and a rebuild still reproduces the projections.
        let diff = crate::conformance::rebuild_and_diff(&db).await.unwrap();
        assert!(
            diff.equal,
            "projections diverge from replay: {:?}",
            diff.tables
        );
    }

    #[tokio::test]
    async fn same_account_release_without_expected_names_holder_run_key() {
        let db = create_database(":memory:").await.unwrap();
        let id = subject(&db).await;
        let holder = Caller::authenticated("account:a")
            .with_run_context(Some("scout-chair-a748b2".into()), None);
        let other = Caller::authenticated("account:a")
            .with_run_context(Some("scout-chair-b748b2".into()), None);
        claim(&db, &holder, "start_work", &args(&id, ACTION_CLAIM))
            .await
            .unwrap();
        let error = release(&db, &other, "start_work", &args(&id, ACTION_RELEASE))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("scout-chair-a748b2"));
        assert!(error.contains("expected_holder_run_key"));
        let current = claim_state(&db, &id).await.unwrap();
        assert_eq!(
            current.claimed_run_key.as_deref(),
            Some("scout-chair-a748b2")
        );
    }

    #[tokio::test]
    async fn same_account_release_with_wrong_expected_is_refused_without_clearing() {
        let db = create_database(":memory:").await.unwrap();
        let id = subject(&db).await;
        let holder = Caller::authenticated("account:a")
            .with_run_context(Some("scout-chair-a748b2".into()), None);
        let other = Caller::authenticated("account:a")
            .with_run_context(Some("scout-chair-b748b2".into()), None);
        claim(&db, &holder, "start_work", &args(&id, ACTION_CLAIM))
            .await
            .unwrap();
        let error = release(
            &db,
            &other,
            "start_work",
            &args_with_expected(&id, ACTION_RELEASE, Some(Some("scout-chair-c748b2"))),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("holder changed"));
        assert!(error.contains("preview"));
        assert!(!error.contains("scout-chair-a748b2"));
        let current = claim_state(&db, &id).await.unwrap();
        assert_eq!(
            current.claimed_run_key.as_deref(),
            Some("scout-chair-a748b2")
        );
    }

    #[tokio::test]
    async fn same_account_account_only_holder_releases_with_null_expectation() {
        let db = create_database(":memory:").await.unwrap();
        let id = subject(&db).await;
        let holder = Caller::authenticated("account:a");
        let other = Caller::authenticated("account:a")
            .with_run_context(Some("scout-chair-b748b2".into()), None);
        claim(&db, &holder, "start_work", &args(&id, ACTION_CLAIM))
            .await
            .unwrap();
        let bare = release(&db, &other, "start_work", &args(&id, ACTION_RELEASE))
            .await
            .unwrap_err()
            .to_string();
        assert!(bare.contains("expected_holder_run_key"));
        release(
            &db,
            &other,
            "start_work",
            &args_with_expected(&id, ACTION_RELEASE, Some(None)),
        )
        .await
        .unwrap();
        assert!(!claim_state(&db, &id).await.unwrap().is_claimed());
    }

    #[tokio::test]
    async fn other_account_release_stays_refused_without_disclosure() {
        let db = create_database(":memory:").await.unwrap();
        let id = subject(&db).await;
        let holder = Caller::authenticated("account:a")
            .with_run_context(Some("scout-chair-a748b2".into()), None);
        let attacker = Caller::authenticated("account:b")
            .with_run_context(Some("scout-chair-a748b2".into()), None);
        claim(&db, &holder, "start_work", &args(&id, ACTION_CLAIM))
            .await
            .unwrap();
        for with_expected in [
            args(&id, ACTION_RELEASE),
            args_with_expected(&id, ACTION_RELEASE, Some(Some("scout-chair-a748b2"))),
        ] {
            let error = release(&db, &attacker, "start_work", &with_expected)
                .await
                .unwrap_err()
                .to_string();
            assert!(error.contains("claimed by another caller"));
            assert!(!error.contains("scout-chair-a748b2"));
            assert!(!error.contains("account:a"));
        }
        let current = claim_state(&db, &id).await.unwrap();
        assert_eq!(
            current.claimed_run_key.as_deref(),
            Some("scout-chair-a748b2")
        );
    }

    #[tokio::test]
    async fn exact_holder_with_mismatched_expected_is_refused() {
        let db = create_database(":memory:").await.unwrap();
        let id = subject(&db).await;
        let holder = Caller::authenticated("account:a")
            .with_run_context(Some("scout-chair-a748b2".into()), None);
        claim(&db, &holder, "start_work", &args(&id, ACTION_CLAIM))
            .await
            .unwrap();
        let error = release(
            &db,
            &holder,
            "start_work",
            &args_with_expected(&id, ACTION_RELEASE, Some(Some("scout-chair-b748b2"))),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("expected_holder_run_key"));
        assert!(claim_state(&db, &id).await.unwrap().is_claimed());
    }

    #[tokio::test]
    async fn holder_projection_reports_open_closed_and_missing_run_state() {
        let db = create_database(":memory:").await.unwrap();
        let account = "account:a";
        let open_run = "scout-chair-a748b2";
        let closed_run = "pilot-river-b748b2";
        let missing_run = "heron-river-c748b2";
        let open = subject(&db).await;
        let closed = subject(&db).await;
        let missing = subject(&db).await;

        crate::control::ensure_agent_run(
            &db,
            open_run,
            account,
            crate::control::ReportedRunIdentity::default(),
        )
        .await
        .unwrap();
        crate::control::ensure_agent_run(
            &db,
            closed_run,
            account,
            crate::control::ReportedRunIdentity::default(),
        )
        .await
        .unwrap();
        let open_holder =
            Caller::authenticated(account).with_run_context(Some(open_run.to_string()), None);
        let closed_holder =
            Caller::authenticated(account).with_run_context(Some(closed_run.to_string()), None);
        let missing_holder =
            Caller::authenticated(account).with_run_context(Some(missing_run.to_string()), None);
        claim(&db, &open_holder, "start_work", &args(&open, ACTION_CLAIM))
            .await
            .unwrap();
        claim(
            &db,
            &closed_holder,
            "start_work",
            &args(&closed, ACTION_CLAIM),
        )
        .await
        .unwrap();
        claim(
            &db,
            &missing_holder,
            "start_work",
            &args(&missing, ACTION_CLAIM),
        )
        .await
        .unwrap();
        crate::control::close_agent_run(&db, closed_run, account)
            .await
            .unwrap();

        let ids = vec![open.clone(), closed.clone(), missing.clone()];
        let mut conn = db.write_pool().acquire().await.unwrap();
        let open_projection = project_work_states_in(&mut conn, &open_holder, &ids)
            .await
            .unwrap();
        assert_eq!(open_projection[&open]["target"]["run_state"], "open");
        assert_eq!(open_projection[&open]["claim_status"], "current");
        assert_eq!(open_projection[&open]["target"]["holder_tier"], "this_run");
        // Same account, different run: still visible, with the HOLDER's
        // run_state and tier — not the viewer's.
        assert_eq!(open_projection[&closed]["target"]["visibility"], "visible");
        assert_eq!(open_projection[&closed]["target"]["run_state"], "closed");
        assert_eq!(
            open_projection[&closed]["target"]["holder_tier"],
            "another_agent_of_yours"
        );
        assert_eq!(open_projection[&closed]["claim_status"], "current");
        assert_eq!(open_projection[&missing]["target"]["run_state"], "missing");

        let closed_projection = project_work_states_in(&mut conn, &closed_holder, &ids)
            .await
            .unwrap();
        assert_eq!(closed_projection[&closed]["target"]["run_state"], "closed");
        assert_eq!(closed_projection[&closed]["claim_status"], "current");

        let missing_projection = project_work_states_in(&mut conn, &missing_holder, &ids)
            .await
            .unwrap();
        assert_eq!(
            missing_projection[&missing]["target"]["run_state"],
            "missing"
        );
        assert_eq!(missing_projection[&missing]["claim_status"], "current");

        // Correlation keys are not authority: another account later creating
        // the claimed key must not enrich the original holder's target.
        crate::control::ensure_agent_run(
            &db,
            missing_run,
            "account:other",
            crate::control::ReportedRunIdentity::default(),
        )
        .await
        .unwrap();
        let reused_projection = project_work_states_in(&mut conn, &missing_holder, &ids)
            .await
            .unwrap();
        assert_eq!(
            reused_projection[&missing]["target"]["run_state"],
            "missing"
        );
        assert!(reused_projection[&missing]["target"]["activity_id"].is_null());

        // Another principal still gets withheld with no claim_status.
        let outsider = Caller::authenticated("account:other");
        let withheld_projection = project_work_states_in(&mut conn, &outsider, &ids)
            .await
            .unwrap();
        for id in &ids {
            assert_eq!(withheld_projection[id]["target"]["visibility"], "withheld");
            assert_eq!(withheld_projection[id]["details"]["visibility"], "withheld");
            assert!(withheld_projection[id].get("claim_status").is_none());
            assert!(withheld_projection[id].get("holder_tier").is_none());
            assert!(!serde_json::to_string(&withheld_projection[id])
                .unwrap()
                .contains(account));
        }

        // Same-agent different-run tiering: scout-chair-* shares the agent key.
        let same_agent_other_run = Caller::authenticated(account)
            .with_run_context(Some("scout-chair-b748b2".into()), None);
        let tiered = project_work_states_in(&mut conn, &same_agent_other_run, &ids)
            .await
            .unwrap();
        assert_eq!(
            tiered[&open]["target"]["holder_tier"],
            "another_run_of_this_agent"
        );

        // Canonical keyless semantics, shared with the overlap notice: an
        // account-only holder is never `this_run`, even for a keyless caller
        // of the same account — there is no key to resolve liveness from.
        let keyless_id = subject(&db).await;
        let keyless_holder = Caller::authenticated(account);
        claim(
            &db,
            &keyless_holder,
            "start_work",
            &args(&keyless_id, ACTION_CLAIM),
        )
        .await
        .unwrap();
        let keyless_projection = project_work_states_in(
            &mut conn,
            &keyless_holder,
            std::slice::from_ref(&keyless_id),
        )
        .await
        .unwrap();
        assert_eq!(
            keyless_projection[&keyless_id]["target"]["holder_tier"],
            "another_agent_of_yours"
        );
        assert_eq!(
            keyless_projection[&keyless_id]["target"]["run_state"],
            "not_applicable"
        );
        assert_eq!(keyless_projection[&keyless_id]["claim_status"], "current");
    }

    #[tokio::test]
    async fn trusted_local_can_clear_a_stuck_claim() {
        let db = create_database(":memory:").await.unwrap();
        let id = subject(&db).await;
        let holder = Caller::authenticated("account:gone");
        claim(&db, &holder, "start_work", &args(&id, ACTION_CLAIM))
            .await
            .unwrap();
        let recovered = release(
            &db,
            &Caller::local(),
            "start_work",
            &args(&id, ACTION_RELEASE),
        )
        .await
        .unwrap();
        assert!(!recovered.claimed);
    }

    /// Far-future observation time used to push a run started "now" past the
    /// 5-minute horizon without backdating any stored timestamp.
    const FAR_FUTURE_OBSERVED_AT: &str = "2999-01-01T00:00:00.000Z";

    async fn run_state_at(
        db: &Db,
        account: &str,
        run_key: Option<&str>,
        observed_at: &str,
    ) -> &'static str {
        let mut conn = db.write_pool().acquire().await.unwrap();
        neighbour_run_state_at(&mut conn, account, run_key, observed_at)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn neighbour_run_state_at_resolves_liveness_states() {
        let db = create_database(":memory:").await.unwrap();
        let account = "account:a";

        // No key, no liveness question.
        assert_eq!(
            run_state_at(&db, account, None, FAR_FUTURE_OBSERVED_AT).await,
            "not_applicable"
        );
        // Admitted keys are account-scoped: another account's row is missing.
        crate::control::ensure_agent_run(
            &db,
            "scout-chair-d748b2",
            "account:other",
            crate::control::ReportedRunIdentity::default(),
        )
        .await
        .unwrap();
        assert_eq!(
            run_state_at(
                &db,
                account,
                Some("scout-chair-d748b2"),
                FAR_FUTURE_OBSERVED_AT
            )
            .await,
            "missing"
        );
        // Never-admitted key for this account is missing too.
        assert_eq!(
            run_state_at(
                &db,
                account,
                Some("heron-river-d748b2"),
                FAR_FUTURE_OBSERVED_AT
            )
            .await,
            "missing"
        );

        // Admitted run observed at its own start is inside the horizon.
        let live = crate::control::ensure_agent_run(
            &db,
            "scout-chair-e748b2",
            account,
            crate::control::ReportedRunIdentity::default(),
        )
        .await
        .unwrap();
        assert_eq!(
            run_state_at(&db, account, Some("scout-chair-e748b2"), &live.started_at).await,
            "open"
        );
        // The same run observed far past the horizon is silent, not open:
        // nobody called close_run, yet recency still reports the quiet.
        assert_eq!(
            run_state_at(
                &db,
                account,
                Some("scout-chair-e748b2"),
                FAR_FUTURE_OBSERVED_AT
            )
            .await,
            "silent"
        );

        // Terminality takes precedence over recency: a closed run observed
        // at its own (recent) start still reads closed.
        let closing = crate::control::ensure_agent_run(
            &db,
            "pilot-river-d748b2",
            account,
            crate::control::ReportedRunIdentity::default(),
        )
        .await
        .unwrap();
        crate::control::close_agent_run(&db, "pilot-river-d748b2", account)
            .await
            .unwrap();
        assert_eq!(
            run_state_at(
                &db,
                account,
                Some("pilot-river-d748b2"),
                &closing.started_at
            )
            .await,
            "closed"
        );
        assert_eq!(
            run_state_at(
                &db,
                account,
                Some("pilot-river-d748b2"),
                FAR_FUTURE_OBSERVED_AT
            )
            .await,
            "closed"
        );
    }

    #[tokio::test]
    async fn neighbour_run_state_at_counts_later_content_event_as_activity() {
        // The case the ended_at-only read got wrong: started_at is far past
        // the horizon at observation time, but a later run-correlated event
        // keeps the holder open.
        let db = create_database(":memory:").await.unwrap();
        let account = "account:a";
        let run_key = "scout-chair-f748b2";
        crate::control::ensure_agent_run(
            &db,
            run_key,
            account,
            crate::control::ReportedRunIdentity::default(),
        )
        .await
        .unwrap();
        // Baseline without any event: started_at is ~973 years stale here.
        assert_eq!(
            run_state_at(&db, account, Some(run_key), FAR_FUTURE_OBSERVED_AT).await,
            "silent"
        );

        let record_id = subject(&db).await;
        // An event stamped with this run key but another actor is not the
        // run's activity, so the holder stays silent.
        sqlx::query(
            "INSERT INTO content_events(id,record_id,type,payload,actor,run_key,\
             created_at,causal_envelope_version,causal_status) \
             VALUES(?,?,?,?,?,?,?,1,'complete')",
        )
        .bind("11111111-1111-4111-8111-111111111111")
        .bind(&record_id)
        .bind("test.activity-probe")
        .bind("{}")
        .bind("account:other")
        .bind(run_key)
        .bind(FAR_FUTURE_OBSERVED_AT)
        .execute(db.write_pool())
        .await
        .unwrap();
        assert_eq!(
            run_state_at(&db, account, Some(run_key), FAR_FUTURE_OBSERVED_AT).await,
            "silent"
        );

        // The run's own later event observes it inside the horizon.
        sqlx::query(
            "INSERT INTO content_events(id,record_id,type,payload,actor,run_key,\
             created_at,causal_envelope_version,causal_status) \
             VALUES(?,?,?,?,?,?,?,1,'complete')",
        )
        .bind("22222222-2222-4222-8222-222222222222")
        .bind(&record_id)
        .bind("test.activity-probe")
        .bind("{}")
        .bind(account)
        .bind(run_key)
        .bind(FAR_FUTURE_OBSERVED_AT)
        .execute(db.write_pool())
        .await
        .unwrap();
        assert_eq!(
            run_state_at(&db, account, Some(run_key), FAR_FUTURE_OBSERVED_AT).await,
            "open"
        );
    }

    #[tokio::test]
    async fn neighbour_run_state_at_boundary_is_exclusive() {
        // The horizon comparison is strict `<`, matching the relation: at
        // precisely last_observed + 5 minutes the holder is already silent.
        let db = create_database(":memory:").await.unwrap();
        let account = "account:a";
        let run_key = "scout-chair-c749b2";
        crate::control::ensure_agent_run(
            &db,
            run_key,
            account,
            crate::control::ReportedRunIdentity::default(),
        )
        .await
        .unwrap();
        sqlx::query("UPDATE agent_runs SET started_at=? WHERE run_key=?")
            .bind("2026-01-01T00:00:00.000Z")
            .bind(run_key)
            .execute(db.write_pool())
            .await
            .unwrap();
        // Just inside the horizon is still open ...
        assert_eq!(
            run_state_at(&db, account, Some(run_key), "2026-01-01T00:04:59.999Z").await,
            "open"
        );
        // ... while the exact boundary instant is silent.
        assert_eq!(
            run_state_at(&db, account, Some(run_key), "2026-01-01T00:05:00.000Z").await,
            "silent"
        );
    }

    #[tokio::test]
    async fn neighbour_run_state_at_unparseable_timestamp_resolves_silent() {
        // An uncomputable recency comparison resolves `silent`, never an
        // error — matching the relation, whose `appears_active` likewise
        // resolves false. NULL stored timestamps take the same `coalesce`
        // path; the schema forbids NULL `started_at`, so a garbage string
        // exercises the shared julianday-NULL branch.
        let db = create_database(":memory:").await.unwrap();
        let account = "account:a";
        let run_key = "scout-chair-d749b2";
        crate::control::ensure_agent_run(
            &db,
            run_key,
            account,
            crate::control::ReportedRunIdentity::default(),
        )
        .await
        .unwrap();
        sqlx::query("UPDATE agent_runs SET started_at=? WHERE run_key=?")
            .bind("not-a-timestamp")
            .bind(run_key)
            .execute(db.write_pool())
            .await
            .unwrap();
        assert_eq!(
            run_state_at(&db, account, Some(run_key), FAR_FUTURE_OBSERVED_AT).await,
            "silent"
        );
    }

    #[tokio::test]
    async fn neighbour_run_state_on_reads_through_engine_clock() {
        // Drive the production path — the engine-clock `neighbour_run_state_on`
        // form the handlers actually call — rather than only the
        // injected-clock `_at` form: a freshly admitted run is `open`, and a
        // closed one stays `closed`.
        let db = create_database(":memory:").await.unwrap();
        let account = "account:a";
        let run_key = "scout-chair-e749b2";
        crate::control::ensure_agent_run(
            &db,
            run_key,
            account,
            crate::control::ReportedRunIdentity::default(),
        )
        .await
        .unwrap();
        let mut conn = db.write_pool().acquire().await.unwrap();
        assert_eq!(
            neighbour_run_state_on(&mut conn, account, Some(run_key))
                .await
                .unwrap(),
            "open"
        );
        crate::control::close_agent_run(&db, run_key, account)
            .await
            .unwrap();
        assert_eq!(
            neighbour_run_state_on(&mut conn, account, Some(run_key))
                .await
                .unwrap(),
            "closed"
        );
    }

    #[tokio::test]
    async fn neighbour_run_state_at_counts_the_holders_own_claim() {
        // Regression guard for the other half of the acts-not-attention
        // stance, symmetric with `neighbour_run_state_at_ignores_reads`.
        // The `agent_activity` relation excludes claim-tuple updates from
        // recency so that hiding a claim cannot alter presence or ordering.
        // This derivation counts them, deliberately: a claim is a call on a
        // coordination surface, which is an act, and the caller already sees
        // the claim it is being told about. Align this path with the
        // relation's exclusion and a holder whose only act is its own fresh
        // claim flips to `silent` the moment `started_at` ages out.
        let db = create_database(":memory:").await.unwrap();
        let account = "account:a";
        let run_key = "scout-chair-g749b2";
        crate::control::ensure_agent_run(
            &db,
            run_key,
            account,
            crate::control::ReportedRunIdentity::default(),
        )
        .await
        .unwrap();
        // Stale admission: the run started well outside the horizon.
        sqlx::query("UPDATE agent_runs SET started_at=? WHERE run_key=?")
            .bind("2026-01-01T00:00:00.000Z")
            .bind(run_key)
            .execute(db.write_pool())
            .await
            .unwrap();
        let record_id = subject(&db).await;
        let claimed_at = "2026-01-01T02:00:00.000Z";
        let observed_at = "2026-01-01T02:03:00.000Z";
        // Baseline: nothing but the stale admission, so the holder is quiet.
        assert_eq!(
            run_state_at(&db, account, Some(run_key), observed_at).await,
            "silent"
        );

        // A claim-shaped durable act: `record.updated` carrying the claim
        // tuple, stamped with the holder's actor and run key exactly as the
        // dispatch choke point stamps a real `start_work` claim.
        sqlx::query(
            "INSERT INTO content_events(id,record_id,type,payload,actor,run_key,\
             created_at,causal_envelope_version,causal_status) \
             VALUES(?,?,'record.updated',?,?,?,?,1,'complete')",
        )
        .bind("44444444-4444-4444-8444-444444444444")
        .bind(&record_id)
        .bind(format!(
            "{{\"claimed_by_account\":\"{account}\",\"claimed_run_key\":\"{run_key}\"}}"
        ))
        .bind(account)
        .bind(run_key)
        .bind(claimed_at)
        .execute(db.write_pool())
        .await
        .unwrap();

        // Three minutes after the claim, inside the horizon: the act counts.
        assert_eq!(
            run_state_at(&db, account, Some(run_key), observed_at).await,
            "open"
        );
        // And it still ages out on its own recency, not the run's.
        assert_eq!(
            run_state_at(&db, account, Some(run_key), "2026-01-01T02:06:00.000Z").await,
            "silent"
        );
    }

    #[tokio::test]
    async fn neighbour_run_state_at_ignores_reads() {
        // Regression guard for the acts-not-attention stance: a holder whose
        // only activity since its last content event is *reading* still reads
        // `silent`. The read log is oversight for the principal to inspect,
        // not a stigmergic substrate, so read-log calls must never move the
        // liveness horizon — only durable content events do.
        let db = create_database(":memory:").await.unwrap();
        let account = "account:a";
        let run_key = "scout-chair-f749b2";
        crate::control::ensure_agent_run(
            &db,
            run_key,
            account,
            crate::control::ReportedRunIdentity::default(),
        )
        .await
        .unwrap();
        sqlx::query("UPDATE agent_runs SET started_at=? WHERE run_key=?")
            .bind("2026-01-01T00:00:00.000Z")
            .bind(run_key)
            .execute(db.write_pool())
            .await
            .unwrap();
        let observed_at = "2026-01-01T00:10:00.000Z";
        // Baseline: ten minutes past the only content signal, silent.
        assert_eq!(
            run_state_at(&db, account, Some(run_key), observed_at).await,
            "silent"
        );

        // The holder reads right at the observation instant: a read-log call
        // with an `opened` touch, the same shape a real read leaves behind.
        let record_id = subject(&db).await;
        let call_id = sqlx::query(
            "INSERT INTO read_log_calls(id,tool,run_key,actor,arguments,outcome,\
             started_at,ended_at) \
             VALUES(?,?,?,?,?,'ok',?,?)",
        )
        .bind("33333333-3333-4333-8333-333333333333")
        .bind("search")
        .bind(run_key)
        .bind(account)
        .bind("{}")
        .bind(observed_at)
        .bind(observed_at)
        .execute(db.write_pool())
        .await
        .unwrap()
        .last_insert_rowid();
        sqlx::query("INSERT OR IGNORE INTO read_log_record_ids (record_id) VALUES (?)")
            .bind(&record_id)
            .execute(db.write_pool())
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO read_log_touches(call_seq,record_ref,interaction,result_rank) \
             VALUES(?,(SELECT record_ref FROM read_log_record_ids WHERE record_id=?),'opened',NULL)",
        )
        .bind(call_id)
        .bind(&record_id)
        .execute(db.write_pool())
        .await
        .unwrap();

        // Reading moved nothing: still silent, not open.
        assert_eq!(
            run_state_at(&db, account, Some(run_key), observed_at).await,
            "silent"
        );
    }
}
