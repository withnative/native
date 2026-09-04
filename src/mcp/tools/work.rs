//! Tool 31 — `start_work` (docs/tool-surface.md §Work coordination).
//!
//! Claims are projected coordination state, authored only by this tool through
//! ordinary `record.updated` events. They never displace `lifecycle`: claiming
//! and releasing each append exactly one event and update only the engine-owned
//! claim tuple on `records`.
//!
//! SQLite `BEGIN IMMEDIATE` serializes the read/predicate/append sequence. A
//! claim succeeds only while `claimed_by_account IS NULL`; an ordinary release
//! succeeds only for the exact stored account/run tuple. Trusted local callers
//! retain a recovery path for a stuck current claim.

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
use super::{parse_args, require_record, require_record_in};

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
    run_ended_at: Option<String>,
}

impl ProjectedClaimState {
    fn is_owned_by(&self, caller: &Caller) -> bool {
        self.claimed_by_account.as_deref() == Some(caller.credential())
            && self.claimed_run_key.as_deref() == caller.run_key()
    }

    fn work_state(&self, caller: &Caller) -> Value {
        let Some(account) = self.claimed_by_account.as_deref() else {
            return json!({ "state": "unclaimed" });
        };

        if !self.is_owned_by(caller) {
            return json!({
                "state": "claimed",
                "details": { "visibility": "withheld" },
                "target": { "visibility": "withheld" },
            });
        }

        let run_state = match self.claimed_run_key.as_deref() {
            Some(_) if self.activity_id.is_none() => "missing",
            Some(_) if self.run_ended_at.is_some() => "closed",
            Some(_) => "open",
            None => "not_applicable",
        };

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
                "run_state": run_state,
            },
        })
    }
}

/// Project current claim occupancy for a bounded record set inside the caller's
/// existing content transaction. This is the reusable seam for record queries:
/// one projection query observes every requested record at the same boundary,
/// while the pure response fold keeps exact-holder disclosure uniform with
/// `start_work`.
pub(super) async fn project_work_states_in(
    projection_conn: &mut SqliteConnection,
    live_target_pool: &SqlitePool,
    caller: &Caller,
    record_ids: &[String],
) -> Result<HashMap<String, Value>> {
    if record_ids.is_empty() {
        return Ok(HashMap::new());
    }

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

    let rows = query.build().fetch_all(&mut *projection_conn).await?;
    // A run key is caller-supplied correlation, not authority. Consult live
    // target state only for the one account+run tuple the caller is allowed to
    // see; withheld holder tuples must not become a timing or error oracle.
    let visible_target = if let Some(caller_run) = caller.run_key() {
        let owns_presented_tuple = rows.iter().any(|row| {
            row.try_get::<Option<String>, _>("claimed_by_account")
                .ok()
                .flatten()
                .as_deref()
                == Some(caller.credential())
                && row
                    .try_get::<Option<String>, _>("claimed_run_key")
                    .ok()
                    .flatten()
                    .as_deref()
                    == Some(caller_run)
        });
        if owns_presented_tuple {
            sqlx::query(
                "SELECT activity_id,ended_at FROM agent_runs WHERE run_key=? AND account_id=?",
            )
            .bind(caller_run)
            .bind(caller.credential())
            .fetch_optional(live_target_pool)
            .await?
            .map(|row| {
                Ok::<_, Error>((
                    row.try_get::<String, _>("activity_id")?,
                    row.try_get::<Option<String>, _>("ended_at")?,
                ))
            })
            .transpose()?
        } else {
            None
        }
    } else {
        None
    };
    let mut projected = HashMap::with_capacity(rows.len());
    for row in rows {
        let claimed_run_key: Option<String> = row.try_get("claimed_run_key")?;
        let (activity_id, run_ended_at) = if row
            .try_get::<Option<String>, _>("claimed_by_account")?
            .as_deref()
            == Some(caller.credential())
            && claimed_run_key.as_deref() == caller.run_key()
        {
            visible_target
                .as_ref()
                .map(|(activity_id, ended_at)| (Some(activity_id.clone()), ended_at.clone()))
                .unwrap_or((None, None))
        } else {
            (None, None)
        };
        let state = ProjectedClaimState {
            record_id: row.try_get("id")?,
            claimed_by_account: row.try_get("claimed_by_account")?,
            claimed_run_key,
            claimed_at: row.try_get("claimed_at")?,
            claim_event_id: row.try_get("claim_event_id")?,
            activity_id,
            run_ended_at,
        };
        projected.insert(state.record_id.clone(), state.work_state(caller));
    }
    Ok(projected)
}

async fn project_work_state(db: &Db, caller: &Caller, record_id: &str) -> Result<Value> {
    let mut conn = db.write_pool().acquire().await?;
    project_work_states_in(&mut conn, db.write_pool(), caller, &[record_id.to_string()])
        .await?
        .remove(record_id)
        .ok_or_else(|| Error::engine(format!("start_work: record {record_id} does not exist")))
}

impl ClaimState {
    fn is_claimed(&self) -> bool {
        self.claimed_by_account.is_some()
    }

    fn is_owned_by(&self, caller: &Caller) -> bool {
        self.claimed_by_account.as_deref() == Some(caller.credential())
            && self.claimed_run_key.as_deref() == caller.run_key()
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
    match state.held_by() {
        Some(holder) if state.is_owned_by(caller) => Error::engine(format!(
            "{tool}: record {id} is already claimed by {holder} — release it first"
        )),
        _ => Error::engine(format!(
            "{tool}: record {id} is already claimed — release it first"
        )),
    }
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
        }
    }
}

async fn claim(db: &Db, caller: &Caller, tool: &str, args: &StartWorkArgs) -> Result<Outcome> {
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
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
    })
}

async fn release(db: &Db, caller: &Caller, tool: &str, args: &StartWorkArgs) -> Result<Outcome> {
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    require_record_in(&mut tx, caller, tool, &args.record_id, Capability::Edit).await?;
    let state = claim_state_in(&mut tx, &args.record_id).await?;
    if !state.is_claimed() {
        return Err(Error::engine(format!(
            "{tool}: record {} is not claimed — nothing to release",
            args.record_id,
        )));
    }
    if !state.is_owned_by(caller) && !super::is_legacy_local(caller) {
        return Err(Error::engine(format!(
            "{tool}: record {} is claimed by another caller",
            args.record_id
        )));
    }
    append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: args.record_id.clone(),
            event_type: "record.updated".into(),
            payload: json!({
                "claimed_by_account": Value::Null,
                "claimed_run_key": Value::Null,
            }),
            actor: Some(caller.actor().to_string()),
        },
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

    if outcome.held_by_account.as_deref() != Some(caller.credential())
        || outcome.held_by_run_key.as_deref() != caller.run_key()
    {
        outcome.held_by = None;
        outcome.held_by_account = None;
        outcome.held_by_run_key = None;
        outcome.claimed_at = None;
    }
    let work_state = project_work_state(&db, &caller, &args.record_id).await?;
    let context = working_context(&db, &caller, TOOL, &args.record_id).await?;

    Ok(json!({
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
    }))
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

/// Register legacy catalogue tool 31, shipping surface ordinal 26.
pub fn register_work_tools(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(
        ToolKind::StartWork,
        "Claim a record and get the context to work on it: the record with its \
         ancestor path, linked resolutions, dependency \
         readiness, and a bounded newest-first window of direct open comment \
         roots with bounded oldest-first direct replies. Comments stay pull-shaped: \
         this context is deliberate discovery, not an inbox or notification. \
         The claim is one conditional coordination write that leaves lifecycle \
         unchanged — a second claimant is refused, not queued. Use action 'preview' to inspect \
         without claiming, or 'release' to hand the claim back.",
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
                    "description": "Deprecated and ignored. Claim ownership comes from the authenticated account and validated run_key."
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
        let error = release(&db, &first, "start_work", &args(&id, ACTION_RELEASE))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("claimed by another caller"));
        let current = claim_state(&db, &id).await.unwrap();
        assert_eq!(current.claimed_run_key, later.run_key().map(String::from));
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

        crate::control::ensure_agent_run(&db, open_run, account)
            .await
            .unwrap();
        crate::control::ensure_agent_run(&db, closed_run, account)
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
        let open_projection =
            project_work_states_in(&mut conn, db.write_pool(), &open_holder, &ids)
                .await
                .unwrap();
        assert_eq!(open_projection[&open]["target"]["run_state"], "open");
        assert_eq!(open_projection[&open]["claim_status"], "current");
        assert_eq!(open_projection[&closed]["target"]["visibility"], "withheld");

        let closed_projection =
            project_work_states_in(&mut conn, db.write_pool(), &closed_holder, &ids)
                .await
                .unwrap();
        assert_eq!(closed_projection[&closed]["target"]["run_state"], "closed");
        assert_eq!(closed_projection[&closed]["claim_status"], "current");

        let missing_projection =
            project_work_states_in(&mut conn, db.write_pool(), &missing_holder, &ids)
                .await
                .unwrap();
        assert_eq!(
            missing_projection[&missing]["target"]["run_state"],
            "missing"
        );
        assert_eq!(missing_projection[&missing]["claim_status"], "current");

        // Correlation keys are not authority: another account later creating
        // the claimed key must not enrich the original holder's target.
        crate::control::ensure_agent_run(&db, missing_run, "account:other")
            .await
            .unwrap();
        let reused_projection =
            project_work_states_in(&mut conn, db.write_pool(), &missing_holder, &ids)
                .await
                .unwrap();
        assert_eq!(
            reused_projection[&missing]["target"]["run_state"],
            "missing"
        );
        assert!(reused_projection[&missing]["target"]["activity_id"].is_null());
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
}
