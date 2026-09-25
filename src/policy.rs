//! Authoritative policy event log and its synchronous projection fold.
//!
//! `policy_events` is independent of both content and meta history. Its two
//! full-state verbs are sufficient to reproduce `record_policies` and
//! `policy_entries`; `records.policy_anchor_id` remains a containment-derived
//! index maintained by the authorization write path.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sqlx::{Row, SqliteConnection};

use crate::authorization::{Capability, MEMBERS_SUBJECT_ID};
use crate::db::{begin_write, Db};
use crate::error::{Error, Result};
use crate::schema::{DDL_STATEMENTS, ROOT_RECORD_ID};
use crate::store::now_iso;

pub use native_policy_kernel::NormalizedPolicyEntry;

pub const POLICY_EVENT_TYPES: [&str; 2] = ["policy.replaced", "policy.inheritance_restored"];

const POLICY_EVENT_OBJECTS: [&str; 3] = [
    "policy_events",
    "policy_events_no_update",
    "policy_events_no_delete",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEventRow {
    pub seq: i64,
    pub id: String,
    pub record_id: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub payload: Option<String>,
    pub actor: String,
    pub reason: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyReplacedPayload {
    pub entries: Vec<NormalizedPolicyEntry>,
}

fn validate_actor(actor: &str) -> Result<()> {
    if actor.trim().is_empty() {
        return Err(Error::engine("policy event actor cannot be empty"));
    }
    Ok(())
}

fn validate_reason(reason: &str) -> Result<()> {
    if reason.trim().is_empty() {
        return Err(Error::engine("policy event reason cannot be empty"));
    }
    Ok(())
}

pub(crate) fn validate_authored_actor(actor: &str) -> Result<()> {
    validate_actor(actor)?;
    if actor.starts_with("engine:") {
        return Err(Error::engine(format!(
            "policy event actor '{actor}' is reserved for engine-authored history"
        )));
    }
    Ok(())
}

fn validate_entries(entries: &[NormalizedPolicyEntry]) -> Result<()> {
    let mut prior: Option<&NormalizedPolicyEntry> = None;
    for entry in entries {
        let valid = match entry.subject_kind.as_str() {
            "members" => {
                entry.subject_id == MEMBERS_SUBJECT_ID
                    && matches!(entry.capability.as_str(), "view" | "edit")
            }
            "account" => {
                !entry.subject_id.is_empty()
                    && matches!(entry.capability.as_str(), "view" | "edit" | "manage")
            }
            _ => false,
        };
        if entry.effect != "allow" || !valid {
            return Err(Error::engine(format!(
                "unsupported normalized policy entry {}:{} {} {}",
                entry.subject_kind, entry.subject_id, entry.effect, entry.capability
            )));
        }
        if prior.is_some_and(|previous| previous >= entry) {
            return Err(Error::engine(
                "policy.replaced entries must be unique and canonically sorted",
            ));
        }
        prior = Some(entry);
    }
    Ok(())
}

pub(crate) fn replaced_payload(event: &PolicyEventRow) -> Result<PolicyReplacedPayload> {
    let payload = event.payload.as_deref().ok_or_else(|| {
        Error::engine(format!(
            "policy event {} ({}) has no payload",
            event.id, event.event_type
        ))
    })?;
    let payload: PolicyReplacedPayload = serde_json::from_str(payload)?;
    validate_entries(&payload.entries)?;
    Ok(payload)
}

pub(crate) fn validate_event(event: &PolicyEventRow) -> Result<()> {
    if event.seq < 1 {
        return Err(Error::engine("policy event sequence must be positive"));
    }
    if event.id.trim().is_empty() || event.record_id.trim().is_empty() {
        return Err(Error::engine(
            "policy event id and record id cannot be empty",
        ));
    }
    if event.created_at.trim().is_empty() {
        return Err(Error::engine("policy event created_at cannot be empty"));
    }
    chrono::DateTime::parse_from_rfc3339(&event.created_at).map_err(|_| {
        Error::engine(format!(
            "policy event {} has a non-RFC3339 created_at",
            event.id
        ))
    })?;
    validate_actor(&event.actor)?;
    validate_reason(&event.reason)?;
    match event.event_type.as_str() {
        "policy.replaced" => {
            replaced_payload(event)?;
            Ok(())
        }
        "policy.inheritance_restored" if event.record_id == ROOT_RECORD_ID => Err(Error::engine(
            "the canonical root policy cannot restore inheritance",
        )),
        "policy.inheritance_restored" if event.payload.is_none() => Ok(()),
        "policy.inheritance_restored" => Err(Error::engine(
            "policy.inheritance_restored must not carry a payload",
        )),
        other => Err(Error::engine(format!("unknown policy event type: {other}"))),
    }
}

/// Fold one policy event into the two policy projections. This is the only
/// runtime writer of those tables; callers maintain the independent derived
/// nearest-anchor index after this fold succeeds.
pub(crate) async fn project_policy(
    conn: &mut SqliteConnection,
    event: &PolicyEventRow,
) -> Result<()> {
    validate_event(event)?;
    project_policy_rows(conn, event).await?;
    // Every applied policy operation advances the epoch at least once, even
    // when it wrote no projection row. Hosted clients use the SSE
    // authorization frame as their acknowledgement that a policy write landed,
    // so an operation that is a no-op in the projections must still be
    // acknowledged or the caller waits forever. Re-asserting an identical
    // empty explicit policy is exactly that case: `INSERT OR IGNORE` suppresses
    // the record_policies trigger, the entry DELETE and re-INSERT touch no
    // rows, and the anchor refresh writes nothing. The trigger fences remain
    // the authority for what changed; this is an explicit "an operation was
    // applied" statement, not a substitute for them.
    sqlx::query("UPDATE authorization_revision SET epoch = epoch + 1 WHERE id = 1")
        .execute(&mut *conn)
        .await?;
    Ok(())
}

async fn project_policy_rows(conn: &mut SqliteConnection, event: &PolicyEventRow) -> Result<()> {
    match event.event_type.as_str() {
        "policy.replaced" => {
            let payload = replaced_payload(event)?;
            sqlx::query(
                "INSERT OR IGNORE INTO record_policies (record_id, created_at) VALUES (?, ?)",
            )
            .bind(&event.record_id)
            .bind(&event.created_at)
            .execute(&mut *conn)
            .await?;
            sqlx::query("DELETE FROM policy_entries WHERE policy_anchor_id = ?")
                .bind(&event.record_id)
                .execute(&mut *conn)
                .await?;
            for entry in payload.entries {
                sqlx::query(
                    "INSERT INTO policy_entries
                        (policy_anchor_id, subject_kind, subject_id, effect, capability)
                     VALUES (?, ?, ?, ?, ?)",
                )
                .bind(&event.record_id)
                .bind(entry.subject_kind)
                .bind(entry.subject_id)
                .bind(entry.effect)
                .bind(entry.capability)
                .execute(&mut *conn)
                .await?;
            }
            Ok(())
        }
        "policy.inheritance_restored" => {
            let deleted = sqlx::query("DELETE FROM record_policies WHERE record_id = ?")
                .bind(&event.record_id)
                .execute(&mut *conn)
                .await?;
            if deleted.rows_affected() != 1 {
                return Err(Error::engine(format!(
                    "policy event {} restores inheritance for non-explicit record '{}'",
                    event.id, event.record_id
                )));
            }
            Ok(())
        }
        other => Err(Error::engine(format!("unknown policy event type: {other}"))),
    }
}

pub(crate) async fn append_replaced_in(
    conn: &mut SqliteConnection,
    record_id: &str,
    entries: Vec<NormalizedPolicyEntry>,
    actor: &str,
    reason: &str,
    act_alloc: &mut crate::act::ActAllocation,
) -> Result<PolicyEventRow> {
    validate_actor(actor)?;
    validate_reason(reason)?;
    validate_entries(&entries)?;
    append_in(
        conn,
        record_id,
        "policy.replaced",
        Some(serde_json::to_string(&PolicyReplacedPayload { entries })?),
        actor,
        reason,
        &now_iso(),
        act_alloc,
    )
    .await
}

pub(crate) async fn append_inheritance_restored_in(
    conn: &mut SqliteConnection,
    record_id: &str,
    actor: &str,
    reason: &str,
    act_alloc: &mut crate::act::ActAllocation,
) -> Result<PolicyEventRow> {
    validate_actor(actor)?;
    validate_reason(reason)?;
    append_in(
        conn,
        record_id,
        "policy.inheritance_restored",
        None,
        actor,
        reason,
        &now_iso(),
        act_alloc,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn append_in(
    conn: &mut SqliteConnection,
    record_id: &str,
    event_type: &str,
    payload: Option<String>,
    actor: &str,
    reason: &str,
    created_at: &str,
    act_alloc: &mut crate::act::ActAllocation,
) -> Result<PolicyEventRow> {
    let mut event = PolicyEventRow {
        seq: -1,
        id: uuid::Uuid::new_v4().to_string(),
        record_id: record_id.into(),
        event_type: event_type.into(),
        payload,
        actor: actor.into(),
        reason: reason.into(),
        created_at: created_at.into(),
    };
    validate_event(&PolicyEventRow {
        seq: 1,
        ..event.clone()
    })?;
    let stores_reason: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('policy_events') WHERE name='reason')",
    )
    .fetch_one(&mut *conn)
    .await?;
    event.seq = if stores_reason {
        sqlx::query_scalar(
            "INSERT INTO policy_events (id, record_id, type, payload, actor, reason, created_at, act)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING seq",
        )
        .bind(&event.id)
        .bind(&event.record_id)
        .bind(&event.event_type)
        .bind(&event.payload)
        .bind(&event.actor)
        .bind(&event.reason)
        .bind(&event.created_at)
        .bind(act_alloc.get_or_allocate(conn).await?)
        .fetch_one(&mut *conn)
        .await?
    } else {
        // Only reachable while an offline pre-v22 migration composes policy
        // changes before the later reason-column step in the same transaction.
        // Those schemas predate both the `reason` and the `act` columns (and
        // the act counter), so this branch keeps its historical column list.
        sqlx::query_scalar(
            "INSERT INTO policy_events (id, record_id, type, payload, actor, created_at)
             VALUES (?, ?, ?, ?, ?, ?) RETURNING seq",
        )
        .bind(&event.id)
        .bind(&event.record_id)
        .bind(&event.event_type)
        .bind(&event.payload)
        .bind(&event.actor)
        .bind(&event.created_at)
        .fetch_one(&mut *conn)
        .await?
    };
    project_policy(conn, &event).await?;
    Ok(event)
}

/// Fresh-database policy genesis. This is deliberately not called by database
/// open: an existing file with missing genesis is malformed, never repaired.
pub(crate) async fn seed_root_policy(db: &Db) -> Result<()> {
    let mut tx = begin_write(db.write_pool()).await?;
    let mut act_alloc = crate::act::ActAllocation::new();
    let root_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM records WHERE id = ? AND deleted_at IS NULL)",
    )
    .bind(ROOT_RECORD_ID)
    .fetch_one(&mut *tx)
    .await?;
    if !root_exists {
        return Err(Error::engine(
            "root policy genesis requires the canonical root content record",
        ));
    }
    let event_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policy_events")
        .fetch_one(&mut *tx)
        .await?;
    let policy_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM record_policies")
        .fetch_one(&mut *tx)
        .await?;
    if event_count != 0 || policy_count != 0 {
        return Err(Error::engine(
            "fresh policy genesis requires empty policy log and projections",
        ));
    }
    append_replaced_in(
        &mut tx,
        ROOT_RECORD_ID,
        vec![NormalizedPolicyEntry::new(
            "members".into(),
            MEMBERS_SUBJECT_ID.into(),
            Capability::Edit,
        )],
        "engine:seed",
        "canonical root policy genesis",
        &mut act_alloc,
    )
    .await?;
    crate::authorization::refresh_policy_anchor_subtree(&mut tx, ROOT_RECORD_ID).await?;
    tx.commit().await?;
    Ok(())
}

fn row_from_sql(row: sqlx::sqlite::SqliteRow) -> Result<PolicyEventRow> {
    Ok(PolicyEventRow {
        seq: row.try_get("seq")?,
        id: row.try_get("id")?,
        record_id: row.try_get("record_id")?,
        event_type: row.try_get("type")?,
        payload: row.try_get("payload")?,
        actor: row.try_get("actor")?,
        reason: row.try_get("reason")?,
        created_at: row.try_get("created_at")?,
    })
}

pub(crate) async fn read_all_policy_events(
    conn: &mut SqliteConnection,
) -> Result<Vec<PolicyEventRow>> {
    sqlx::query(
        "SELECT seq, id, record_id, type, payload, actor, reason, created_at
           FROM policy_events ORDER BY seq",
    )
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .map(row_from_sql)
    .collect()
}

/// The policy-only act-range reader: exactly the rows whose `act` falls in the
/// half-open interval `(from_exclusive, to_inclusive]`, in `seq` order, decoded
/// by the same [`row_from_sql`] the full reader uses. Legacy rows whose act is
/// `NULL` never satisfy the strict `act > ?` predicate and are excluded.
#[allow(dead_code)] // R3 wires the bounded fold; the reader lands ahead of its caller.
pub(crate) async fn policy_events_in_act_range(
    conn: &mut SqliteConnection,
    from_exclusive_act: i64,
    to_inclusive_act: i64,
) -> Result<Vec<PolicyEventRow>> {
    sqlx::query(
        "SELECT seq, id, record_id, type, payload, actor, reason, created_at
           FROM policy_events WHERE act > ? AND act <= ? ORDER BY seq",
    )
    .bind(from_exclusive_act)
    .bind(to_inclusive_act)
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .map(row_from_sql)
    .collect()
}

pub(crate) async fn replay_policy(
    conn: &mut SqliteConnection,
    events: &[PolicyEventRow],
) -> Result<()> {
    for event in events {
        project_policy(conn, event).await?;
    }
    Ok(())
}

fn normalized_schema_sql(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn expected_objects() -> BTreeMap<&'static str, (&'static str, String)> {
    let mut expected = BTreeMap::new();
    for name in POLICY_EVENT_OBJECTS {
        let (kind, prefix) = if name == "policy_events" {
            ("table", "CREATE TABLE policy_events")
        } else {
            (
                "trigger",
                if name == "policy_events_no_update" {
                    "CREATE TRIGGER policy_events_no_update"
                } else {
                    "CREATE TRIGGER policy_events_no_delete"
                },
            )
        };
        let statement = DDL_STATEMENTS
            .iter()
            .find(|statement| statement.starts_with(prefix))
            .unwrap_or_else(|| panic!("frozen DDL contains {name}"));
        expected.insert(name, (kind, normalized_schema_sql(statement)));
    }
    expected
}

pub async fn state_violations(db: &Db) -> Result<Vec<String>> {
    let mut snapshot = db.write_pool().begin().await?;
    let violations = state_violations_on(&mut snapshot).await?;
    snapshot.rollback().await?;
    Ok(violations)
}

pub async fn state_violations_on(conn: &mut SqliteConnection) -> Result<Vec<String>> {
    let expected = expected_objects();
    let actual = sqlx::query(
        "SELECT type, name, sql FROM sqlite_schema
          WHERE lower(name) = 'policy_events'
             OR lower(name) GLOB 'policy_events_no_*'
          ORDER BY name, type",
    )
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .map(|row| {
        Ok((
            row.try_get::<String, _>("name")?,
            row.try_get::<String, _>("type")?,
            row.try_get::<Option<String>, _>("sql")?,
        ))
    })
    .collect::<Result<Vec<_>>>()?;
    let mut violations = Vec::new();
    for (name, (expected_type, expected_sql)) in &expected {
        match actual
            .iter()
            .find(|(actual_name, _, _)| actual_name == name)
        {
            None => violations.push(format!("required {expected_type} missing: {name}")),
            Some((_, actual_type, _)) if actual_type != expected_type => violations.push(format!(
                "reserved object {name} must be a {expected_type}, found {actual_type}"
            )),
            Some((_, _, Some(actual_sql)))
                if normalized_schema_sql(actual_sql) != *expected_sql =>
            {
                violations.push(format!(
                    "reserved object {name} does not match the frozen schema-15 definition"
                ));
            }
            Some((_, _, None)) => {
                violations.push(format!("reserved object {name} has no SQL"));
            }
            Some(_) => {}
        }
    }
    for (name, kind, _) in &actual {
        if !expected.contains_key(name.as_str()) {
            violations.push(format!(
                "unexpected reserved policy-log object: {kind} {name}"
            ));
        }
    }

    if violations.is_empty() {
        let events = read_all_policy_events(conn).await?;
        let mut explicit = std::collections::BTreeSet::new();
        let mut root_genesis_seen = false;
        for (index, event) in events.iter().enumerate() {
            let expected_seq = index as i64 + 1;
            if event.seq != expected_seq {
                violations.push(format!(
                    "policy event sequence is not contiguous: expected {expected_seq}, found {}",
                    event.seq
                ));
            }
            if let Err(error) = validate_event(event) {
                violations.push(format!("policy event {} is malformed: {error}", event.id));
                continue;
            }
            match event.event_type.as_str() {
                "policy.replaced" => {
                    explicit.insert(event.record_id.as_str());
                    root_genesis_seen |= event.record_id == ROOT_RECORD_ID;
                }
                "policy.inheritance_restored" if !explicit.remove(event.record_id.as_str()) => {
                    violations.push(format!(
                        "policy event {} restores inheritance without a preceding explicit boundary",
                        event.id
                    ));
                }
                _ => {}
            }
        }
        if !root_genesis_seen {
            violations.push("policy event log has no canonical root genesis replacement".into());
        }
    }
    Ok(violations)
}

#[cfg(test)]
mod act_range_tests {
    use std::collections::BTreeMap;

    use serde_json::json;
    use sqlx::Row;

    use super::*;
    use crate::authorization::replace_explicit_policy;
    use crate::db::create_database;
    use crate::store::create_record;

    const RECORD: &str = "90200000-0000-4000-8000-000000000001";
    const LEGACY: &str = "policy-event-legacy-null-act";

    /// Bounded policy reads select exactly the half-open `(from, to]` interval,
    /// preserve `seq` order, exclude a legacy `NULL` act, and agree exactly with
    /// the full reader filtered to the same observed acts.
    #[tokio::test]
    async fn policy_events_in_act_range_is_bounded_ordered_and_excludes_null_acts() {
        let db = create_database(":memory:").await.unwrap();
        create_record(
            &db,
            json!({"id": RECORD, "type": "Document", "kind": "note", "name": "policy range"}),
        )
        .await
        .unwrap();
        // Three real authored replacements, each committed by its own seam call
        // so each carries its own act stamp.
        for _ in 0..3 {
            replace_explicit_policy(&db, "acct:alice", RECORD, vec![])
                .await
                .unwrap();
        }
        // A legacy grouping-unknown row: `NULL` act, schema-valid, narrow.
        sqlx::query(
            "INSERT INTO policy_events (id, record_id, type, payload, actor, reason, created_at, act)
             VALUES (?, ?, 'policy.replaced', '{}', 'engine:seed', 'legacy act witness',
                     '2026-01-01T00:00:00.000Z', NULL)",
        )
        .bind(LEGACY)
        .bind(RECORD)
        .execute(db.write_pool())
        .await
        .unwrap();

        let mut conn = db.pool().acquire().await.unwrap();
        let full = read_all_policy_events(&mut conn).await.unwrap();

        let act_of: BTreeMap<i64, Option<i64>> = sqlx::query("SELECT seq, act FROM policy_events")
            .fetch_all(&mut *conn)
            .await
            .unwrap()
            .into_iter()
            .map(|row| (row.get("seq"), row.get("act")))
            .collect();
        let mut acts: Vec<i64> = act_of.values().flatten().copied().collect();
        acts.sort_unstable();
        acts.dedup();
        assert!(
            acts.len() >= 3,
            "the test expects at least three stamped acts"
        );

        for (from_exclusive, to_inclusive) in
            [(acts[0], acts[2]), (acts[1], acts[2]), (acts[0], acts[1])]
        {
            let bounded = policy_events_in_act_range(&mut conn, from_exclusive, to_inclusive)
                .await
                .unwrap();
            assert!(bounded.windows(2).all(|pair| pair[0].seq < pair[1].seq));
            let expected: Vec<PolicyEventRow> = full
                .iter()
                .filter(|event| {
                    act_of[&event.seq]
                        .is_some_and(|act| act > from_exclusive && act <= to_inclusive)
                })
                .cloned()
                .collect();
            assert_eq!(
                bounded, expected,
                "range ({from_exclusive}, {to_inclusive}]"
            );
            assert!(
                !bounded.iter().any(|event| event.id == LEGACY),
                "a NULL-act row never matches the range predicate"
            );
        }

        // Equal bounds are the empty half-open interval, not a widening.
        assert!(policy_events_in_act_range(&mut conn, acts[2], acts[2])
            .await
            .unwrap()
            .is_empty());
        // The NULL row is still part of the full log, proving it was excluded by
        // the predicate and not dropped by the decoder.
        assert!(full.iter().any(|event| event.id == LEGACY));
    }
}
