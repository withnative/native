//! `query::events` — the public reader of the authoritative `events` log.
//! Backs `get_history` and the prefix resolver used by structured `as_of`
//! reads; the same source also feeds the rebuild harness.
//!
//! Paging is keyset on `seq` (the log's primary key): pass the last seq you saw
//! as `after_seq`. History supports either direction; replay prefixes remain
//! oldest-first, the projector's fold order.

use std::collections::HashSet;
use std::future::Future;

use serde::Serialize;
use sqlx::{Row, Sqlite, Transaction};

use crate::db::Db;
use crate::error::Result;
use crate::events::{CausalEnvelopeV1, CausalFrontierV1, EventRow};

use super::error::contract_violation;

/// Compatibility re-export for the payload-free content-log DTO now owned by
/// the pure query-contract member.
pub use native_query_contract::events::ContentInvalidation;

/// Ceiling on a single page — the whole log is reachable by paging.
const MAX_PAGE: i64 = 1000;
const PUBLIC_HISTORY_FILTER: &str = "type NOT IN ('reconciliation.recorded.v1','unit.superseded.v1','receipt.dependency_audited.v1')";

/// Default and maximum caller-visible page sizes for `whats_changed`.
/// The tool reads the raw log in chunks capped at the same maximum, but hidden
/// and filter-rejected rows never occupy caller-visible page slots.
pub const DEFAULT_CHANGE_WINDOW_LIMIT: i64 = 200;
pub const MAX_CHANGE_WINDOW_LIMIT: i64 = MAX_PAGE;

/// Highest durable content cursor currently committed in this database.
pub async fn content_high_water(db: &Db) -> Result<i64> {
    content_high_water_on(db.write_pool()).await
}

pub(crate) async fn content_high_water_on(pool: &sqlx::SqlitePool) -> Result<i64> {
    Ok(
        sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM content_events")
            .fetch_one(pool)
            .await?,
    )
}

/// Oldest reconnect cursor retained by this database. V1 never prunes the
/// content log, so zero remains valid even after the first event is written.
pub async fn content_retention_floor(db: &Db) -> Result<i64> {
    content_retention_floor_on(db.write_pool()).await
}

pub(crate) async fn content_retention_floor_on(_pool: &sqlx::SqlitePool) -> Result<i64> {
    Ok(0)
}

/// Read payload-free content invalidations strictly after `after`, never past
/// the durable fence. Results are keyset-paged in ascending sequence order.
pub async fn content_invalidations(
    db: &Db,
    after: i64,
    fence: i64,
    limit: i64,
) -> Result<Vec<ContentInvalidation>> {
    content_invalidations_on(db.write_pool(), after, fence, limit).await
}

pub(crate) async fn content_invalidations_on(
    pool: &sqlx::SqlitePool,
    after: i64,
    fence: i64,
    limit: i64,
) -> Result<Vec<ContentInvalidation>> {
    if limit <= 0 {
        return Err(contract_violation("realtime page limit must be positive"));
    }
    let rows = sqlx::query(
        "SELECT seq, id, record_id,
                CASE WHEN type='receipt.committed.v1' THEN 'record.updated' ELSE type END AS type,
                created_at
           FROM content_events
          WHERE seq > ? AND seq <= ?
          ORDER BY seq
          LIMIT ?",
    )
    .bind(after)
    .bind(fence)
    .bind(limit.min(MAX_PAGE))
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(ContentInvalidation {
                local_seq: row.try_get("seq")?,
                id: row.try_get("id")?,
                record_id: row.try_get("record_id")?,
                event_type: row.try_get("type")?,
                created_at: row.try_get("created_at")?,
            })
        })
        .collect()
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EventOrder {
    #[default]
    OldestFirst,
    NewestFirst,
}

impl EventOrder {
    fn comparison(self) -> &'static str {
        match self {
            Self::OldestFirst => ">",
            Self::NewestFirst => "<",
        }
    }

    fn sql(self) -> &'static str {
        match self {
            Self::OldestFirst => "ASC",
            Self::NewestFirst => "DESC",
        }
    }

    pub(crate) fn initial_cursor(self) -> i64 {
        match self {
            Self::OldestFirst => 0,
            Self::NewestFirst => i64::MAX,
        }
    }
}

/// One keyset-paged slice of the log in the requested order.
#[derive(Debug, Serialize)]
pub struct EventsPage {
    pub events: Vec<EventRow>,
    /// Pass back as `after_seq` for the next page; `None` means exhausted.
    pub next_after_seq: Option<i64>,
}

/// One bounded raw slice of a caller-held, high-water-pinned change traversal.
///
/// Filters deliberately do not live here: this query primitive advances over
/// the global authoritative log. The tool consumes as many bounded slices as
/// necessary to make its own `limit` a caller-visible result limit.
#[derive(Debug, Serialize)]
pub struct ChangeWindowPage {
    pub after_seq: i64,
    pub scanned_through_seq: i64,
    pub high_water_seq: i64,
    pub has_more: bool,
    pub events: Vec<EventRow>,
}

/// Snapshot-consistent membership sets accompanying one raw change window.
/// The tool applies them before caller-visible page occupancy, while keeping
/// membership, the high water, and the first bounded raw slice on one SQLite
/// snapshot.
#[derive(Debug)]
pub struct ChangeWindowSnapshot {
    pub page: ChangeWindowPage,
    pub scope_ids: Option<HashSet<String>>,
    pub run_keys: Option<HashSet<String>>,
}

/// The membership sets a change window resolves alongside its raw rows.
///
/// Read once, on the traversal's first page: later pages carry
/// `ChangeMembership::default()`, because re-resolving a subtree or run set
/// mid-traversal would let the answer move under a pinned window.
#[derive(Clone, Copy, Default)]
pub(crate) struct ChangeMembership<'a> {
    pub(crate) scope_record_id: Option<&'a str>,
    pub(crate) for_run: Option<&'a str>,
    pub(crate) include_child_runs: bool,
}

/// Caller-requested actor narrowing applied inside the `content_events` window
/// query, so rows that cannot survive the caller's actor filter never enter a
/// raw page.
///
/// Every variant is a superset of the post-redaction check the tool applies:
/// redaction only ever nulls an actor (never invents one), and the caller's
/// own token is always disclosable to itself, so `Only` is exact while
/// `Others`/`AnyOf` additionally keep rows whose actor redaction will hide —
/// the tool's post-redaction re-check drops those with comparisons only. That
/// re-check runs after the row's top-level per-record authorization, so it
/// adds no further authorization work; it restores exactness the SQL
/// superset deliberately gives up. `None` matches nothing; it is how an
/// unsatisfiable
/// scope/accounts conjunction (for example `self` plus an account list that
/// does not contain the caller) keeps the pinned-window cursor contract
/// without special-casing the traversal loop.
#[derive(Clone, Debug, Default)]
pub(crate) enum ChangeActorFilter {
    #[default]
    All,
    Only(String),
    Others {
        caller: String,
    },
    AnyOf(Vec<String>),
    None,
}

impl ChangeActorFilter {
    fn predicate(&self) -> (String, Vec<String>) {
        match self {
            Self::All => (String::new(), Vec::new()),
            Self::Only(actor) => (" AND actor = ?".into(), vec![actor.clone()]),
            Self::Others { caller } => (
                " AND (actor IS NULL OR actor != ?)".into(),
                vec![caller.clone()],
            ),
            Self::AnyOf(actors) => {
                if actors.is_empty() {
                    return (" AND 1 = 0".into(), Vec::new());
                }
                let placeholders = actors.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
                (format!(" AND actor IN ({placeholders})"), actors.clone())
            }
            Self::None => (" AND 1 = 0".into(), Vec::new()),
        }
    }
}

/// Stable predicates that shape one raw change-window query.
struct ChangeWindowQuery<'a> {
    membership: ChangeMembership<'a>,
    actor_filter: &'a ChangeActorFilter,
}

pub(crate) fn event_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<EventRow> {
    let version: i64 = row.try_get("causal_envelope_version")?;
    if version != 1 {
        return Err(crate::Error::engine(
            "unsupported stored causal envelope version",
        ));
    }
    let frontier = CausalFrontierV1::new(serde_json::from_str::<Vec<String>>(
        &row.try_get::<String, _>("causal_frontier")?,
    )?)?;
    let causal_envelope = match row.try_get::<String, _>("causal_status")?.as_str() {
        "complete" => CausalEnvelopeV1::complete(frontier),
        "import_incomplete" => CausalEnvelopeV1::import_incomplete(frontier),
        "legacy_unknown" if frontier.is_empty() => CausalEnvelopeV1::legacy_unknown(),
        _ => return Err(crate::Error::engine("invalid stored causal envelope")),
    };
    Ok(EventRow {
        local_seq: row.try_get("seq")?,
        id: row.try_get("id")?,
        record_id: row.try_get("record_id")?,
        event_type: row.try_get("type")?,
        payload: row.try_get("payload")?,
        actor: row.try_get("actor")?,
        run_key: row.try_get("run_key")?,
        parent_key: row.try_get("parent_key")?,
        intent: row.try_get("intent")?,
        created_at: row.try_get("created_at")?,
        causal_envelope,
    })
}

fn public_event_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<EventRow> {
    let mut event = event_from_row(row)?;
    if event.event_type == "receipt.committed.v1" {
        let raw = event
            .payload
            .as_deref()
            .ok_or_else(|| contract_violation("aggregate Receipt payload is missing"))?;
        let payload: serde_json::Value = serde_json::from_str(raw)?;
        let body = payload
            .get("body")
            .cloned()
            .ok_or_else(|| contract_violation("aggregate Receipt body is missing"))?;
        event.event_type = "record.updated".into();
        event.payload = Some(serde_json::to_string(&serde_json::json!({ "body": body }))?);
    }
    Ok(event)
}

async fn page(
    db: &Db,
    record_id: Option<&str>,
    after_seq: Option<i64>,
    limit: i64,
    order: EventOrder,
) -> Result<EventsPage> {
    if limit <= 0 {
        return Err(contract_violation("events page limit must be positive"));
    }
    let limit = limit.min(MAX_PAGE);
    let after = after_seq.unwrap_or_else(|| order.initial_cursor());
    // Fetch one extra row to learn whether another page exists.
    let rows = match record_id {
        Some(record_id) => {
            sqlx::query(&format!(
                "SELECT seq, id, record_id, type, payload, actor,
                        run_key, parent_key, intent, created_at,
                        causal_envelope_version, causal_status,
                        (SELECT json_group_array(parent_event_id)
                           FROM content_event_causal_frontier
                          WHERE event_id = content_events.id) AS causal_frontier
                  FROM content_events WHERE record_id = ? AND seq {} ? AND {PUBLIC_HISTORY_FILTER}
                  ORDER BY seq {} LIMIT ?",
                order.comparison(),
                order.sql()
            ))
            .bind(record_id)
            .bind(after)
            .bind(limit + 1)
            .fetch_all(db.write_pool())
            .await?
        }
        None => {
            sqlx::query(&format!(
                "SELECT seq, id, record_id, type, payload, actor,
                        run_key, parent_key, intent, created_at,
                        causal_envelope_version, causal_status,
                        (SELECT json_group_array(parent_event_id)
                           FROM content_event_causal_frontier
                          WHERE event_id = content_events.id) AS causal_frontier
                  FROM content_events WHERE seq {} ? AND {PUBLIC_HISTORY_FILTER}
                  ORDER BY seq {} LIMIT ?",
                order.comparison(),
                order.sql()
            ))
            .bind(after)
            .bind(limit + 1)
            .fetch_all(db.write_pool())
            .await?
        }
    };
    let has_more = rows.len() as i64 > limit;
    let events = rows[..rows.len().min(limit as usize)]
        .iter()
        .map(public_event_from_row)
        .collect::<Result<Vec<_>>>()?;
    let next_after_seq = if has_more {
        events.last().map(|e| e.local_seq)
    } else {
        None
    };
    Ok(EventsPage {
        events,
        next_after_seq,
    })
}

/// A page of events belonging to one run, optionally including every run whose
/// asserted content-tier parent chain reaches it. Events remain in global log
/// order so one keyset cursor covers the whole selected tree.
pub async fn events_for_run(
    db: &Db,
    run_key: &str,
    include_child_runs: bool,
    record_id: Option<&str>,
    after_seq: Option<i64>,
    limit: i64,
) -> Result<EventsPage> {
    events_for_run_ordered(
        db,
        run_key,
        include_child_runs,
        record_id,
        after_seq,
        limit,
        EventOrder::OldestFirst,
    )
    .await
}

pub async fn events_for_run_ordered(
    db: &Db,
    run_key: &str,
    include_child_runs: bool,
    record_id: Option<&str>,
    after_seq: Option<i64>,
    limit: i64,
    order: EventOrder,
) -> Result<EventsPage> {
    if limit <= 0 {
        return Err(contract_violation("events page limit must be positive"));
    }
    let limit = limit.min(MAX_PAGE);
    let after = after_seq.unwrap_or_else(|| order.initial_cursor());
    let comparison = order.comparison();
    let ordering = order.sql();

    // Exact-run reads use idx_content_events_run. The recursive form deliberately
    // stays on the existing content tier: CE-scale descendant traversal does not
    // justify a parent_key index or a schema re-freeze.
    let rows = match (include_child_runs, record_id) {
        (false, Some(record_id)) => {
            sqlx::query(&format!(
                "SELECT seq, id, record_id, type, payload, actor,
                        run_key, parent_key, intent, created_at,
                        causal_envelope_version, causal_status,
                        (SELECT json_group_array(parent_event_id)
                           FROM content_event_causal_frontier
                          WHERE event_id = content_events.id) AS causal_frontier
                   FROM content_events
                  WHERE run_key = ? AND record_id = ? AND seq {comparison} ? AND {PUBLIC_HISTORY_FILTER}
                  ORDER BY seq {ordering} LIMIT ?"
            ))
            .bind(run_key)
            .bind(record_id)
            .bind(after)
            .bind(limit + 1)
            .fetch_all(db.write_pool())
            .await?
        }
        (false, None) => {
            sqlx::query(&format!(
                "SELECT seq, id, record_id, type, payload, actor,
                        run_key, parent_key, intent, created_at,
                        causal_envelope_version, causal_status,
                        (SELECT json_group_array(parent_event_id)
                           FROM content_event_causal_frontier
                          WHERE event_id = content_events.id) AS causal_frontier
                   FROM content_events
                  WHERE run_key = ? AND seq {comparison} ? AND {PUBLIC_HISTORY_FILTER}
                  ORDER BY seq {ordering} LIMIT ?"
            ))
            .bind(run_key)
            .bind(after)
            .bind(limit + 1)
            .fetch_all(db.write_pool())
            .await?
        }
        (true, Some(record_id)) => {
            sqlx::query(&format!(
                "WITH RECURSIVE included_runs(run_key) AS (
                     SELECT ?
                     UNION
                     SELECT event.run_key
                       FROM content_events event
                       JOIN included_runs parent ON event.parent_key = parent.run_key
                      WHERE event.run_key IS NOT NULL
                 )
                 SELECT event.seq, event.id, event.record_id, event.type, event.payload,
                        event.actor, event.run_key, event.parent_key, event.intent,
                        event.created_at, event.causal_envelope_version,
                        event.causal_status,
                        (SELECT json_group_array(parent_event_id)
                           FROM content_event_causal_frontier frontier
                          WHERE frontier.event_id = event.id) AS causal_frontier
                   FROM content_events event
                   JOIN included_runs included ON event.run_key = included.run_key
                  WHERE event.record_id = ? AND event.seq {comparison} ?
                    AND event.type NOT IN ('reconciliation.recorded.v1','unit.superseded.v1','receipt.dependency_audited.v1')
                  ORDER BY event.seq {ordering} LIMIT ?"
            ))
            .bind(run_key)
            .bind(record_id)
            .bind(after)
            .bind(limit + 1)
            .fetch_all(db.write_pool())
            .await?
        }
        (true, None) => {
            sqlx::query(&format!(
                "WITH RECURSIVE included_runs(run_key) AS (
                     SELECT ?
                     UNION
                     SELECT event.run_key
                       FROM content_events event
                       JOIN included_runs parent ON event.parent_key = parent.run_key
                      WHERE event.run_key IS NOT NULL
                 )
                 SELECT event.seq, event.id, event.record_id, event.type, event.payload,
                        event.actor, event.run_key, event.parent_key, event.intent,
                        event.created_at, event.causal_envelope_version,
                        event.causal_status,
                        (SELECT json_group_array(parent_event_id)
                           FROM content_event_causal_frontier frontier
                          WHERE frontier.event_id = event.id) AS causal_frontier
                   FROM content_events event
                   JOIN included_runs included ON event.run_key = included.run_key
                  WHERE event.seq {comparison} ?
                    AND event.type NOT IN ('reconciliation.recorded.v1','unit.superseded.v1','receipt.dependency_audited.v1')
                  ORDER BY event.seq {ordering} LIMIT ?"
            ))
            .bind(run_key)
            .bind(after)
            .bind(limit + 1)
            .fetch_all(db.write_pool())
            .await?
        }
    };

    let has_more = rows.len() as i64 > limit;
    let events = rows[..rows.len().min(limit as usize)]
        .iter()
        .map(public_event_from_row)
        .collect::<Result<Vec<_>>>()?;
    let next_after_seq = if has_more {
        events.last().map(|event| event.local_seq)
    } else {
        None
    };
    Ok(EventsPage {
        events,
        next_after_seq,
    })
}

/// A page of one record's event stream (its authoritative audit trail).
pub async fn events_for_record(
    db: &Db,
    record_id: &str,
    after_seq: Option<i64>,
    limit: i64,
) -> Result<EventsPage> {
    page(
        db,
        Some(record_id),
        after_seq,
        limit,
        EventOrder::OldestFirst,
    )
    .await
}

pub async fn events_for_record_ordered(
    db: &Db,
    record_id: &str,
    after_seq: Option<i64>,
    limit: i64,
    order: EventOrder,
) -> Result<EventsPage> {
    page(db, Some(record_id), after_seq, limit, order).await
}

pub(crate) async fn events_for_record_ordered_in(
    tx: &mut Transaction<'_, Sqlite>,
    record_id: &str,
    after_seq: Option<i64>,
    limit: i64,
    order: EventOrder,
) -> Result<EventsPage> {
    if limit <= 0 {
        return Err(contract_violation("events page limit must be positive"));
    }
    let limit = limit.min(MAX_PAGE);
    let after = after_seq.unwrap_or_else(|| order.initial_cursor());
    let rows = sqlx::query(&format!(
        "SELECT seq, id, record_id, type, payload, actor,
                run_key, parent_key, intent, created_at,
                causal_envelope_version, causal_status,
                (SELECT json_group_array(parent_event_id)
                   FROM content_event_causal_frontier
                  WHERE event_id = content_events.id) AS causal_frontier
           FROM content_events
          WHERE record_id = ? AND seq {} ? AND {PUBLIC_HISTORY_FILTER}
          ORDER BY seq {} LIMIT ?",
        order.comparison(),
        order.sql()
    ))
    .bind(record_id)
    .bind(after)
    .bind(limit + 1)
    .fetch_all(&mut **tx)
    .await?;
    let has_more = rows.len() as i64 > limit;
    let events = rows[..rows.len().min(limit as usize)]
        .iter()
        .map(public_event_from_row)
        .collect::<Result<Vec<_>>>()?;
    let next_after_seq =
        has_more.then(|| events.last().expect("extra row implies a page").local_seq);
    Ok(EventsPage {
        events,
        next_after_seq,
    })
}

/// A page of the whole log.
pub async fn all_events(db: &Db, after_seq: Option<i64>, limit: i64) -> Result<EventsPage> {
    page(db, None, after_seq, limit, EventOrder::OldestFirst).await
}

pub async fn all_events_ordered(
    db: &Db,
    after_seq: Option<i64>,
    limit: i64,
    order: EventOrder,
) -> Result<EventsPage> {
    page(db, None, after_seq, limit, order).await
}

/// Read the next raw page in a stable global event-log window.
///
/// On the first page the high water and raw rows are read in one SQLite read
/// transaction. Later pages validate the caller's pinned `through_seq`
/// against the current log head, but continue to exclude newer rows.
pub async fn change_window(
    db: &Db,
    after_seq: i64,
    through_seq: Option<i64>,
    limit: i64,
) -> Result<ChangeWindowPage> {
    change_window_in_pool(db.write_pool(), after_seq, through_seq, limit).await
}

pub(crate) async fn change_window_in_pool(
    pool: &sqlx::SqlitePool,
    after_seq: i64,
    through_seq: Option<i64>,
    limit: i64,
) -> Result<ChangeWindowPage> {
    Ok(change_window_with_membership(
        pool,
        after_seq,
        through_seq,
        limit,
        ChangeMembership::default(),
        EventOrder::OldestFirst,
    )
    .await?
    .page)
}

/// Read a raw window and every scope/run membership set used to filter it from
/// one SQLite snapshot. Current label and actor-name enrichment intentionally
/// remains outside this query: those values are output conveniences and never
/// affect membership, ordering, or cursor boundaries.
pub(crate) async fn change_window_with_membership(
    pool: &sqlx::SqlitePool,
    after_seq: i64,
    through_seq: Option<i64>,
    limit: i64,
    membership: ChangeMembership<'_>,
    order: EventOrder,
) -> Result<ChangeWindowSnapshot> {
    let actor_filter = ChangeActorFilter::All;
    change_window_with_membership_filtered(
        pool,
        after_seq,
        through_seq,
        limit,
        membership,
        order,
        &actor_filter,
    )
    .await
}

/// Actor-narrowed form of [`change_window_with_membership`]. Unlike membership
/// sets, the actor predicate is stable for the whole traversal — it is a pure
/// function of each row — so the caller passes it on every page, not just the
/// first.
pub(crate) async fn change_window_with_membership_filtered(
    pool: &sqlx::SqlitePool,
    after_seq: i64,
    through_seq: Option<i64>,
    limit: i64,
    membership: ChangeMembership<'_>,
    order: EventOrder,
    actor_filter: &ChangeActorFilter,
) -> Result<ChangeWindowSnapshot> {
    change_window_with_membership_and_hook(
        pool,
        after_seq,
        through_seq,
        limit,
        order,
        ChangeWindowQuery {
            membership,
            actor_filter,
        },
        || async {},
    )
    .await
}

async fn change_window_with_membership_and_hook<F, Fut>(
    pool: &sqlx::SqlitePool,
    after_seq: i64,
    through_seq: Option<i64>,
    limit: i64,
    order: EventOrder,
    query: ChangeWindowQuery<'_>,
    after_membership: F,
) -> Result<ChangeWindowSnapshot>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = ()>,
{
    let ChangeWindowQuery {
        membership,
        actor_filter,
    } = query;
    if after_seq < 0 {
        return Err(contract_violation(
            "whats_changed after_local_seq must be >= 0",
        ));
    }
    if let Some(through_seq) = through_seq {
        if through_seq < 0 {
            return Err(contract_violation(
                "whats_changed through_local_seq must be >= 0",
            ));
        }
    }
    if !(1..=MAX_CHANGE_WINDOW_LIMIT).contains(&limit) {
        return Err(contract_violation(format!(
            "whats_changed limit must be between 1 and {MAX_CHANGE_WINDOW_LIMIT}"
        )));
    }
    if membership.include_child_runs && membership.for_run.is_none() {
        return Err(contract_violation(
            "whats_changed include_child_runs requires for_run",
        ));
    }

    let mut tx = pool.begin().await?;
    let scope_ids = match membership.scope_record_id {
        Some(root) => {
            let ids = super::tree::subtree_ids_in(&mut tx, root).await?;
            if ids.is_empty() {
                return Err(contract_violation(
                    "whats_changed: scope record does not exist",
                ));
            }
            Some(ids.into_iter().collect())
        }
        None => None,
    };
    let run_keys = match membership.for_run {
        Some(root) if membership.include_child_runs => {
            let rows = sqlx::query(
                "WITH RECURSIVE included_runs(run_key) AS (
                     SELECT ?
                     UNION
                     SELECT event.run_key
                       FROM content_events event
                       JOIN included_runs parent ON event.parent_key = parent.run_key
                      WHERE event.run_key IS NOT NULL
                 )
                 SELECT run_key FROM included_runs",
            )
            .bind(root)
            .fetch_all(&mut *tx)
            .await?;
            Some(
                rows.iter()
                    .map(|row| row.try_get::<String, _>("run_key").map_err(Into::into))
                    .collect::<Result<HashSet<_>>>()?,
            )
        }
        Some(root) => Some(HashSet::from([root.to_string()])),
        None => None,
    };

    // Test-only callers use this seam to commit a concurrent projection/log
    // mutation after membership has established the read snapshot. Production
    // passes a no-op; keeping the hook private prevents it becoming API.
    after_membership().await;

    let current_max: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM content_events")
        .fetch_one(&mut *tx)
        .await?;
    let high_water_seq = through_seq.unwrap_or(current_max);
    if high_water_seq > current_max {
        return Err(contract_violation(
            "whats_changed through_local_seq is beyond available history",
        ));
    }
    // Oldest-first ascends towards the pin, so a cursor past it is a caller
    // error. Newest-first descends from it, and its opening cursor is
    // deliberately above every existing sequence; clamp rather than reject so
    // an unspecified public `after_local_seq` means "start at the pin".
    let after_seq = match order {
        EventOrder::OldestFirst => {
            if after_seq > high_water_seq {
                return Err(contract_violation(format!(
                    "whats_changed after_local_seq {after_seq} must not exceed high_water_local_seq \
                     {high_water_seq}"
                )));
            }
            after_seq
        }
        EventOrder::NewestFirst => after_seq.min(high_water_seq.saturating_add(1)),
    };

    // One look-ahead row establishes whether raw events remain. It is not part
    // of the scanned slice and therefore never contributes to counters,
    // filters, grouping, or cursor advancement.
    //
    // The actor predicate bounds which rows enter a page, never the pinned
    // window itself: the traversal cursor still advances across rejected
    // sequence positions exactly as the unfiltered window did (see
    // `raw_seq_before_lookahead`), which keeps keyset paging gap- and
    // duplicate-free while bounding the rows every later stage must
    // consider.
    let (actor_predicate, actor_params) = actor_filter.predicate();
    let rows = {
        let sql = format!(
            "SELECT seq, id, record_id, type, payload, actor,
                    run_key, parent_key, intent, created_at,
                    causal_envelope_version, causal_status,
                    (SELECT json_group_array(parent_event_id)
                       FROM content_event_causal_frontier
                      WHERE event_id = content_events.id) AS causal_frontier
               FROM content_events
              WHERE seq {} ? AND seq <= ?{actor_predicate}
              ORDER BY seq {}
              LIMIT ?",
            order.comparison(),
            order.sql()
        );
        let mut query = sqlx::query(&sql).bind(after_seq).bind(high_water_seq);
        for param in &actor_params {
            query = query.bind(param);
        }
        query.bind(limit + 1).fetch_all(&mut *tx).await?
    };
    tx.commit().await?;

    let has_more = rows.len() as i64 > limit;
    let events = rows[..rows.len().min(limit as usize)]
        .iter()
        .map(public_event_from_row)
        .collect::<Result<Vec<_>>>()?;
    // Exhausting the window lands the traversal cursor at the far end of it:
    // the pin when ascending, the bottom of the log when descending.
    let scanned_through_seq = if has_more {
        events
            .last()
            .map(|event| event.local_seq)
            .unwrap_or(after_seq)
    } else {
        match order {
            EventOrder::OldestFirst => high_water_seq,
            EventOrder::NewestFirst => 0,
        }
    };

    Ok(ChangeWindowSnapshot {
        page: ChangeWindowPage {
            after_seq,
            scanned_through_seq,
            high_water_seq,
            has_more,
            events,
        },
        scope_ids,
        run_keys,
    })
}

/// The traversal cursor to report when a caller-visible look-ahead event is
/// found: the nearest committed sequence on the pinned side of the
/// look-ahead, i.e. the position the unfiltered window would have scanned
/// through before reaching it.
///
/// The actor predicate keeps rejected rows out of raw pages, so the tool loop
/// cannot observe that predecessor by stepping. Recomputing it here preserves
/// the public cursor contract exactly: `scanned_through_local_seq` and the
/// continued `after_local_seq` advance across actor-filtered gaps exactly as
/// the legacy traversal did, and resumption from either position stays
/// gap-free under the same stable predicate.
///
/// This runs outside the window snapshot, which is safe rather than racy:
/// the content log is append-only, so every sequence below the look-ahead is
/// immutable, and both bounds (`traversal_start`, `high_water_seq`) pin the
/// aggregate to the traversal's window. A concurrent commit can only add
/// sequences above the pin, which the `seq <= high_water_seq` bound
/// excludes. With no predecessor in the window the traversal start itself is
/// returned, matching a loop that never advanced.
pub(crate) async fn raw_seq_before_lookahead(
    pool: &sqlx::SqlitePool,
    order: EventOrder,
    traversal_start: i64,
    lookahead_seq: i64,
    high_water_seq: i64,
) -> Result<i64> {
    let (aggregate, comparison) = match order {
        EventOrder::OldestFirst => ("MAX", ">"),
        EventOrder::NewestFirst => ("MIN", "<"),
    };
    let seq: Option<i64> = sqlx::query_scalar(&format!(
        "SELECT {aggregate}(seq) FROM content_events \
          WHERE seq {comparison} ? AND seq <= ? \
            AND seq {} ?",
        match order {
            EventOrder::OldestFirst => "<",
            EventOrder::NewestFirst => ">",
        }
    ))
    .bind(traversal_start)
    .bind(high_water_seq)
    .bind(lookahead_seq)
    .fetch_one(pool)
    .await?;
    Ok(seq.unwrap_or(traversal_start))
}

/// The full log prefix up to and including `up_to_seq`, oldest-first — the
/// input to historical structured reads, replayed through the one projector.
pub async fn log_prefix(db: &Db, up_to_seq: i64) -> Result<Vec<EventRow>> {
    log_prefix_in_pool(db.write_pool(), up_to_seq).await
}

pub(crate) async fn log_prefix_in_pool(
    pool: &sqlx::SqlitePool,
    up_to_seq: i64,
) -> Result<Vec<EventRow>> {
    let rows = sqlx::query(
        "SELECT seq, id, record_id, type, payload, actor,
                run_key, parent_key, intent, created_at,
                causal_envelope_version, causal_status,
                (SELECT json_group_array(parent_event_id)
                   FROM content_event_causal_frontier
                  WHERE event_id = content_events.id) AS causal_frontier
          FROM content_events WHERE seq <= ? ORDER BY seq",
    )
    .bind(up_to_seq)
    .fetch_all(pool)
    .await?;
    rows.iter().map(event_from_row).collect()
}

#[cfg(test)]
mod change_window_snapshot_tests {
    use serde_json::json;

    use super::*;
    use crate::authorization::Principal;
    use crate::db::create_database;
    use crate::schema::ROOT_RECORD_ID;
    use crate::store::{create_record, update_record};
    use crate::{apply_schema, open_database};

    const ROOT_RUN: &str = "scout-chair-a748b2";
    const CHILD_RUN: &str = "heron-river-b748b2";

    #[tokio::test]
    async fn membership_high_water_and_raw_rows_share_one_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("snapshot.db");
        let db = open_database(&path.to_string_lossy()).await.unwrap();
        apply_schema(&db).await.unwrap();

        for (id, record_type, kind, name, home_id) in [
            ("scope:root", "Collection", Some("folder"), "Root", None),
            (
                "scope:outside",
                "Collection",
                Some("folder"),
                "Outside",
                None,
            ),
            (
                "scope:member",
                "Document",
                Some("note"),
                "Member",
                Some("scope:root"),
            ),
        ] {
            sqlx::query(
                "INSERT INTO records (id, type, kind, name, home_id, persistence) \
                 VALUES (?, ?, ?, ?, ?, 'enduring')",
            )
            .bind(id)
            .bind(record_type)
            .bind(kind)
            .bind(name)
            .bind(home_id)
            .execute(db.write_pool())
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO content_events \
                (id, record_id, type, payload, actor, run_key, created_at, causal_envelope_version, causal_status) \
             VALUES ('event:before', 'scope:member', 'record.updated', \
                     '{\"summary\":\"before\"}', 'account:self', ?, \
                     '2026-08-02T00:00:00.000Z', 1, 'legacy_unknown')",
        )
        .bind(ROOT_RUN)
        .execute(db.write_pool())
        .await
        .unwrap();

        let writer = db.clone();
        let snapshot = change_window_with_membership_and_hook(
            db.write_pool(),
            0,
            None,
            10,
            EventOrder::OldestFirst,
            ChangeWindowQuery {
                membership: ChangeMembership {
                    scope_record_id: Some("scope:root"),
                    for_run: Some(ROOT_RUN),
                    include_child_runs: true,
                },
                actor_filter: &ChangeActorFilter::All,
            },
            move || async move {
                let mut tx = writer.write_pool().begin().await.unwrap();
                sqlx::query("UPDATE records SET home_id = ? WHERE id = ?")
                    .bind("scope:outside")
                    .bind("scope:member")
                    .execute(&mut *tx)
                    .await
                    .unwrap();
                sqlx::query(
                    "INSERT INTO content_events \
                        (id, record_id, type, payload, actor, run_key, parent_key, created_at, causal_envelope_version, causal_status) \
                     VALUES ('event:concurrent', 'scope:member', 'record.updated', \
                             '{\"home_id\":\"scope:outside\"}', 'account:self', ?, ?, \
                             '2026-08-02T00:00:01.000Z', 1, 'legacy_unknown')",
                )
                .bind(CHILD_RUN)
                .bind(ROOT_RUN)
                .execute(&mut *tx)
                .await
                .unwrap();
                tx.commit().await.unwrap();
            },
        )
        .await
        .unwrap();

        assert_eq!(snapshot.page.high_water_seq, 1);
        assert_eq!(snapshot.page.scanned_through_seq, 1);
        assert_eq!(snapshot.page.events.len(), 1);
        assert_eq!(snapshot.page.events[0].id, "event:before");
        assert!(snapshot.scope_ids.unwrap().contains("scope:member"));
        assert_eq!(snapshot.run_keys.unwrap(), HashSet::from([ROOT_RUN.into()]));

        let live_home: String =
            sqlx::query_scalar("SELECT home_id FROM records WHERE id = 'scope:member'")
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        let live_max: i64 = sqlx::query_scalar("SELECT MAX(seq) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(live_home, "scope:outside");
        assert_eq!(live_max, 2);
        db.close().await;
    }

    #[tokio::test]
    async fn record_history_page_stays_on_the_authorization_snapshot() {
        let db = create_database(":memory:").await.unwrap();
        create_record(
            &db,
            json!({
                "id": "9e7e0000-0000-4000-8000-000000000001",
                "type": "Collection",
                "kind": "folder",
                "name": "before",
                "home_id": ROOT_RECORD_ID,
            }),
        )
        .await
        .unwrap();

        let mut snapshot = db.write_pool().begin().await.unwrap();
        crate::authorization::effective_capability_on(
            &mut snapshot,
            Principal::bound("history-snapshot-account", true),
            "9e7e0000-0000-4000-8000-000000000001",
        )
        .await
        .unwrap();
        update_record(
            &db,
            "9e7e0000-0000-4000-8000-000000000001",
            json!({ "name": "after" }),
        )
        .await
        .unwrap();

        let pinned = events_for_record_ordered_in(
            &mut snapshot,
            "9e7e0000-0000-4000-8000-000000000001",
            None,
            1000,
            EventOrder::OldestFirst,
        )
        .await
        .unwrap();
        assert_eq!(pinned.events.len(), 1);
        snapshot.rollback().await.unwrap();

        let current = events_for_record_ordered(
            &db,
            "9e7e0000-0000-4000-8000-000000000001",
            None,
            1000,
            EventOrder::OldestFirst,
        )
        .await
        .unwrap();
        assert_eq!(current.events.len(), 2);
    }

    #[test]
    fn actor_filter_predicates_narrow_the_window_without_touching_other_clauses() {
        let (sql, params) = ChangeActorFilter::All.predicate();
        assert_eq!(sql, "");
        assert!(params.is_empty());

        let (sql, params) = ChangeActorFilter::Only("account:self".into()).predicate();
        assert_eq!(sql, " AND actor = ?");
        assert_eq!(params, vec!["account:self".to_string()]);

        let (sql, params) = ChangeActorFilter::Others {
            caller: "account:self".into(),
        }
        .predicate();
        assert_eq!(sql, " AND (actor IS NULL OR actor != ?)");
        assert_eq!(params, vec!["account:self".to_string()]);

        let (sql, params) =
            ChangeActorFilter::AnyOf(vec!["account:bea".into(), "account:cid".into()]).predicate();
        assert_eq!(sql, " AND actor IN (?, ?)");
        assert_eq!(
            params,
            vec!["account:bea".to_string(), "account:cid".into()]
        );

        // Unsatisfiable conjunctions and empty account sets match nothing
        // rather than widening back to the whole log.
        let (sql, params) = ChangeActorFilter::None.predicate();
        assert_eq!(sql, " AND 1 = 0");
        assert!(params.is_empty());
        let (sql, _) = ChangeActorFilter::AnyOf(Vec::new()).predicate();
        assert_eq!(sql, " AND 1 = 0");
    }

    /// Pins the SSE wire shape of the invalidation envelope at its new home:
    /// exactly `local_seq, id, record_id, type, created_at`, with `event_type`
    /// serialized as `type`.
    #[test]
    fn content_invalidation_serializes_with_the_pinned_field_set() {
        let value = serde_json::to_value(ContentInvalidation {
            local_seq: 7,
            id: "evt-1".into(),
            record_id: "rec-1".into(),
            event_type: "record.updated".into(),
            created_at: "2026-08-12T00:00:00Z".into(),
        })
        .unwrap();
        let object = value.as_object().unwrap();
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["created_at", "id", "local_seq", "record_id", "type"]);
        assert_eq!(object["type"], "record.updated");
    }
}
