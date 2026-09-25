//! Binding-audit replay: `binding_audit` -> `bindings`.
//!
//! `bindings` is the compact live uniqueness index for governed external
//! identities, and `binding_audit` is its append-only ledger. This module makes
//! the ledger authoritative: one typed row decoder feeds both the whole-log
//! reader and the bounded act-range reader, and one append-free, act-free
//! projector folds a row into `bindings`.
//!
//! Three deliberate scoping rules hold here:
//!
//! * **One decoder.** [`binding_audit_row_from_sql`] is the only place the
//!   sixteen-column row shape is decoded, so the full reader and
//!   [`binding_audit_in_act_range`] can never drift from each other or from the
//!   schema.
//! * **One projector.** [`project_binding_audit_event`] covers exactly the four
//!   audited actions the live writers emit — `add`, `canonicalize` (demote and
//!   promote), `remove`, and `transfer`. `reconcile` is not an action: the
//!   reconcile path records `transfer`, so no reconciler semantics are
//!   duplicated here.
//! * **`binding_systems` is immutable.** The projector reads it only to reject
//!   an unknown system; it never writes it, and it never re-derives policy.
//!
//! The projector is append-free: it writes no `binding_systems` row, allocates
//! no act, and appends no audit row. Its only direct mutation is `bindings`;
//! for `account`-system rows the schema's authorization triggers also bump the
//! local `authorization_revision` epoch, which is expected.
//!
//! **Trust boundary.** The projector validates each row's shape and its
//! preconditions against live state, but it deliberately does not re-run the
//! add/remove policy engine: whether a caller may claim an identity is decided
//! once, by the live writer, when the row is authored. Replay therefore assumes
//! a complete, authenticated, canonical `binding_audit` log; that integrity is
//! load-bearing, and a forged or truncated log is out of scope here.
//!
//! The live writers stay on their existing paths for this slice, and whole-log
//! replay is proven equal to live state by test.

use sqlx::sqlite::SqliteRow;
use sqlx::{Row, SqliteConnection};

use crate::error::{Error, Result};

/// The exact decoded column list, shared by both readers and the decoder so a
/// new column cannot be read by one path and not the other.
const BINDING_AUDIT_COLUMNS: &str = "seq,id,action,system,identifier,old_record_id,new_record_id,\
     old_canonical,new_canonical,actor,reason,run_key,parent_key,intent,created_at,act";

/// One `binding_audit` row, carried verbatim from the canonical log.
///
/// `old_canonical`/`new_canonical` are the row's stored 0/1 flags decoded as
/// `bool`; the DDL's per-action CHECK makes their shape part of the action's
/// identity. `act` is the act-range coordinate: retained so the bounded fold can
/// select and carry stamped rows, never re-derived by the projector. Legacy
/// pre-cutover rows keep `act = None` and are excluded by the strict `act > ?`
/// predicate.
#[derive(Clone, Debug)]
#[allow(dead_code)] // R3 wires the bounded fold; the row lands with its readers.
pub(crate) struct BindingAuditRow {
    pub seq: i64,
    pub id: String,
    pub action: String,
    pub system: String,
    pub identifier: String,
    pub old_record_id: Option<String>,
    pub new_record_id: Option<String>,
    pub old_canonical: Option<bool>,
    pub new_canonical: Option<bool>,
    pub actor: String,
    pub reason: String,
    pub run_key: Option<String>,
    pub parent_key: Option<String>,
    pub intent: Option<String>,
    pub created_at: String,
    pub act: Option<i64>,
}

/// The one decoder for a `binding_audit` row. Both readers map every row
/// through it, so the whole-log rebuild and the bounded act-range replay decode
/// the same fields identically.
fn binding_audit_row_from_sql(row: SqliteRow) -> Result<BindingAuditRow> {
    Ok(BindingAuditRow {
        seq: row.try_get("seq")?,
        id: row.try_get("id")?,
        action: row.try_get("action")?,
        system: row.try_get("system")?,
        identifier: row.try_get("identifier")?,
        old_record_id: row.try_get("old_record_id")?,
        new_record_id: row.try_get("new_record_id")?,
        old_canonical: row.try_get("old_canonical")?,
        new_canonical: row.try_get("new_canonical")?,
        actor: row.try_get("actor")?,
        reason: row.try_get("reason")?,
        run_key: row.try_get("run_key")?,
        parent_key: row.try_get("parent_key")?,
        intent: row.try_get("intent")?,
        created_at: row.try_get("created_at")?,
        act: row.try_get("act")?,
    })
}

/// The whole binding-audit log in `seq` order — the input to a whole-log
/// binding rebuild.
#[allow(dead_code)] // R3 wires the bounded fold; the reader lands ahead of its caller.
pub(crate) async fn read_all_binding_audit(
    conn: &mut SqliteConnection,
) -> Result<Vec<BindingAuditRow>> {
    sqlx::query(&format!(
        "SELECT {BINDING_AUDIT_COLUMNS} FROM binding_audit ORDER BY seq"
    ))
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .map(binding_audit_row_from_sql)
    .collect()
}

/// The binding-audit act-range reader: exactly the rows whose `act` falls in the
/// half-open interval `(from_exclusive, to_inclusive]`, in `seq` order, decoded
/// by the same [`binding_audit_row_from_sql`] the full reader uses. Legacy rows
/// whose act is `NULL` never satisfy the strict `act > ?` predicate and are
/// excluded.
#[allow(dead_code)] // R3 wires the bounded fold; the reader lands ahead of its caller.
pub(crate) async fn binding_audit_in_act_range(
    conn: &mut SqliteConnection,
    from_exclusive_act: i64,
    to_inclusive_act: i64,
) -> Result<Vec<BindingAuditRow>> {
    sqlx::query(&format!(
        "SELECT {BINDING_AUDIT_COLUMNS} FROM binding_audit \
         WHERE act > ? AND act <= ? ORDER BY seq"
    ))
    .bind(from_exclusive_act)
    .bind(to_inclusive_act)
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .map(binding_audit_row_from_sql)
    .collect()
}

/// Fold one binding-audit row into `bindings`.
///
/// This is the only ledger-driven writer of `bindings` in this module. It
/// allocates no act and appends no row, and it never touches `binding_systems`
/// beyond a read that rejects an unknown system. Each action's legal old/new
/// record and canonical shape is validated before any write, so a malformed,
/// unknown, or impossible row fails closed instead of half-applying.
#[allow(dead_code)] // R3 wires the bounded fold; live writers are unchanged this slice.
pub(crate) async fn project_binding_audit_event(
    conn: &mut SqliteConnection,
    event: &BindingAuditRow,
) -> Result<()> {
    require_known_binding_system(conn, &event.system).await?;
    match event.action.as_str() {
        "add" => project_add(conn, event).await,
        "remove" => project_remove(conn, event).await,
        "canonicalize" => project_canonicalize(conn, event).await,
        "transfer" => project_transfer(conn, event).await,
        action => Err(Error::engine(format!(
            "unknown binding audit action '{action}'"
        ))),
    }
}

/// Fold every binding-audit row in order through
/// [`project_binding_audit_event`].
///
/// The caller owns the transaction. A whole-log or bounded-range replay should
/// run inside one write transaction so a row rejected mid-replay rolls back
/// every earlier row of that replay instead of leaving a partial fold behind.
#[allow(dead_code)] // R3 wires the bounded fold; live writers are unchanged this slice.
pub(crate) async fn replay_bindings(
    conn: &mut SqliteConnection,
    events: &[BindingAuditRow],
) -> Result<()> {
    for event in events {
        project_binding_audit_event(conn, event).await?;
    }
    Ok(())
}

/// Whether `database_identity_audit` holds any row in `(from_exclusive,
/// to_inclusive]`. A mint or rekey in a delta's act range invalidates every
/// `native-record` identifier encoded against the retired origin.
///
/// Rows with `act IS NULL` predate the act-stamped base and therefore fall
/// outside every `(F1, F2]` interval; this helper addresses stamped delta rows
/// only, exactly like the binding ledger it guards.
#[allow(dead_code)] // R3 wires the bounded fold; the seam lands ahead of its caller.
pub(crate) async fn identity_change_in_act_range(
    conn: &mut SqliteConnection,
    from_exclusive_act: i64,
    to_inclusive_act: i64,
) -> Result<bool> {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM database_identity_audit WHERE act > ? AND act <= ?)",
    )
    .bind(from_exclusive_act)
    .bind(to_inclusive_act)
    .fetch_one(&mut *conn)
    .await
    .map_err(Error::from)
}

/// The whole-snapshot fallback seam for a bounded binding delta.
///
/// Binding replay deliberately does not fold a database rekey: the rekey moves
/// the origin every `native-record` identifier is encoded against, so a
/// `bindings`-only fold over the affected act range would rebuild identifiers
/// that no longer resolve. When [`identity_change_in_act_range`] finds a mint or
/// rekey row in the range, this refuses the incremental path and requires the
/// caller to take a whole snapshot instead. It is a seam, not the unified
/// materialiser: it neither folds rekeys nor rebuilds content.
#[allow(dead_code)] // R3 wires the bounded fold; the seam lands ahead of its caller.
pub(crate) async fn require_whole_snapshot_for_identity_change(
    conn: &mut SqliteConnection,
    from_exclusive_act: i64,
    to_inclusive_act: i64,
) -> Result<()> {
    if identity_change_in_act_range(conn, from_exclusive_act, to_inclusive_act).await? {
        return Err(Error::engine(
            "database identity change in act range requires whole-snapshot fallback",
        ));
    }
    Ok(())
}

/// Reject a row for a system the immutable registry never seeded. The projector
/// reads `binding_systems`; it never writes it.
async fn require_known_binding_system(conn: &mut SqliteConnection, system: &str) -> Result<()> {
    let known: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM binding_systems WHERE system = ?)")
            .bind(system)
            .fetch_one(&mut *conn)
            .await?;
    if !known {
        return Err(Error::engine(format!(
            "unknown binding audit system '{system}'"
        )));
    }
    Ok(())
}

/// `add` inserts exactly one new binding and carries no previous state. An
/// existing row at the same primary key, an identity already owned elsewhere,
/// or a second canonical for the same record+system is impossible in a log the
/// live writer produced, so each fails closed.
async fn project_add(conn: &mut SqliteConnection, event: &BindingAuditRow) -> Result<()> {
    if event.old_record_id.is_some() || event.old_canonical.is_some() {
        return Err(Error::engine(
            "binding add audit carries a previous record or canonical state",
        ));
    }
    let record_id = event
        .new_record_id
        .as_deref()
        .ok_or_else(|| Error::engine("binding add audit is missing its new record"))?;
    let canonical = event
        .new_canonical
        .ok_or_else(|| Error::engine("binding add audit is missing its canonical state"))?;

    let owner: Option<String> =
        sqlx::query_scalar("SELECT record_id FROM bindings WHERE system = ? AND identifier = ?")
            .bind(&event.system)
            .bind(&event.identifier)
            .fetch_optional(&mut *conn)
            .await?;
    match owner.as_deref() {
        Some(owner) if owner == record_id => {
            return Err(Error::engine(
                "binding add audit targets an already-present binding",
            ))
        }
        Some(_) => {
            return Err(Error::engine(
                "binding add audit collides with another record's identity",
            ))
        }
        None => {}
    }
    if canonical {
        let occupied: Option<String> = sqlx::query_scalar(
            "SELECT identifier FROM bindings
              WHERE record_id = ? AND system = ? AND is_canonical = 1",
        )
        .bind(record_id)
        .bind(&event.system)
        .fetch_optional(&mut *conn)
        .await?;
        if occupied.is_some() {
            return Err(Error::engine(
                "binding add audit would create a second canonical identity",
            ));
        }
    }
    sqlx::query(
        "INSERT INTO bindings(record_id,system,identifier,is_canonical) VALUES(?1,?2,?3,?4)",
    )
    .bind(record_id)
    .bind(&event.system)
    .bind(&event.identifier)
    .bind(i64::from(canonical))
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// `remove` deletes exactly the binding the row names and carries no new state.
/// A missing row or a stored canonical flag that disagrees with the log is an
/// impossible precondition.
async fn project_remove(conn: &mut SqliteConnection, event: &BindingAuditRow) -> Result<()> {
    if event.new_record_id.is_some() || event.new_canonical.is_some() {
        return Err(Error::engine(
            "binding remove audit carries a new record or canonical state",
        ));
    }
    let record_id = event
        .old_record_id
        .as_deref()
        .ok_or_else(|| Error::engine("binding remove audit is missing its prior record"))?;
    let was_canonical = event
        .old_canonical
        .ok_or_else(|| Error::engine("binding remove audit is missing its canonical state"))?;

    let current: Option<i64> = sqlx::query_scalar(
        "SELECT is_canonical FROM bindings WHERE record_id = ? AND system = ? AND identifier = ?",
    )
    .bind(record_id)
    .bind(&event.system)
    .bind(&event.identifier)
    .fetch_optional(&mut *conn)
    .await?;
    match current {
        Some(current) if (current != 0) == was_canonical => {}
        Some(_) => {
            return Err(Error::engine(
                "binding remove audit canonical state does not match the live binding",
            ))
        }
        None => {
            return Err(Error::engine(
                "binding remove audit has no live binding to remove",
            ))
        }
    }
    sqlx::query("DELETE FROM bindings WHERE record_id = ? AND system = ? AND identifier = ?")
        .bind(record_id)
        .bind(&event.system)
        .bind(&event.identifier)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// `canonicalize` names one record on both sides and flips its stored canonical
/// flag. A demote is `old_canonical = true, new_canonical = false`; a promote is
/// the reverse. Both are the same update, but each is validated against the
/// live binding first, and a promote that would leave two canonicals fails
/// closed.
async fn project_canonicalize(conn: &mut SqliteConnection, event: &BindingAuditRow) -> Result<()> {
    let old_record_id = event
        .old_record_id
        .as_deref()
        .ok_or_else(|| Error::engine("binding canonicalize audit is missing its record"))?;
    let new_record_id = event
        .new_record_id
        .as_deref()
        .ok_or_else(|| Error::engine("binding canonicalize audit is missing its record"))?;
    if old_record_id != new_record_id {
        return Err(Error::engine(
            "binding canonicalize audit must name one record on both sides",
        ));
    }
    let was_canonical = event
        .old_canonical
        .ok_or_else(|| Error::engine("binding canonicalize audit is missing its prior state"))?;
    let becomes_canonical = event
        .new_canonical
        .ok_or_else(|| Error::engine("binding canonicalize audit is missing its next state"))?;
    if was_canonical == becomes_canonical {
        return Err(Error::engine(
            "binding canonicalize audit must change the canonical state",
        ));
    }

    let current: Option<i64> = sqlx::query_scalar(
        "SELECT is_canonical FROM bindings WHERE record_id = ? AND system = ? AND identifier = ?",
    )
    .bind(old_record_id)
    .bind(&event.system)
    .bind(&event.identifier)
    .fetch_optional(&mut *conn)
    .await?;
    match current {
        Some(current) if (current != 0) == was_canonical => {}
        Some(_) => {
            return Err(Error::engine(
                "binding canonicalize audit canonical state does not match the live binding",
            ))
        }
        None => {
            return Err(Error::engine(
                "binding canonicalize audit targets a missing binding",
            ))
        }
    }
    if becomes_canonical {
        let other: Option<String> = sqlx::query_scalar(
            "SELECT identifier FROM bindings
              WHERE record_id = ? AND system = ? AND is_canonical = 1 AND identifier <> ?",
        )
        .bind(old_record_id)
        .bind(&event.system)
        .bind(&event.identifier)
        .fetch_optional(&mut *conn)
        .await?;
        if other.is_some() {
            return Err(Error::engine(
                "binding canonicalize audit would create a second canonical identity",
            ));
        }
    }
    sqlx::query(
        "UPDATE bindings SET is_canonical = ?1
          WHERE record_id = ?2 AND system = ?3 AND identifier = ?4",
    )
    .bind(i64::from(becomes_canonical))
    .bind(old_record_id)
    .bind(&event.system)
    .bind(&event.identifier)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// `transfer` moves the identity's owner and preserves its canonical flag. The
/// source must exist with the logged flag, the identity must still be owned by
/// the source, and a canonical transfer must not land on a record that already
/// has a canonical identity for the system.
async fn project_transfer(conn: &mut SqliteConnection, event: &BindingAuditRow) -> Result<()> {
    let old_record_id = event
        .old_record_id
        .as_deref()
        .ok_or_else(|| Error::engine("binding transfer audit is missing its source record"))?;
    let new_record_id = event
        .new_record_id
        .as_deref()
        .ok_or_else(|| Error::engine("binding transfer audit is missing its target record"))?;
    if old_record_id == new_record_id {
        return Err(Error::engine(
            "binding transfer audit must move between two distinct records",
        ));
    }
    let old_canonical = event
        .old_canonical
        .ok_or_else(|| Error::engine("binding transfer audit is missing its prior state"))?;
    let new_canonical = event
        .new_canonical
        .ok_or_else(|| Error::engine("binding transfer audit is missing its next state"))?;
    if old_canonical != new_canonical {
        return Err(Error::engine(
            "binding transfer audit must preserve the canonical state",
        ));
    }

    let current: Option<i64> = sqlx::query_scalar(
        "SELECT is_canonical FROM bindings WHERE record_id = ? AND system = ? AND identifier = ?",
    )
    .bind(old_record_id)
    .bind(&event.system)
    .bind(&event.identifier)
    .fetch_optional(&mut *conn)
    .await?;
    match current {
        Some(current) if (current != 0) == old_canonical => {}
        Some(_) => {
            return Err(Error::engine(
                "binding transfer audit canonical state does not match the live binding",
            ))
        }
        None => {
            return Err(Error::engine(
                "binding transfer audit has no source binding to move",
            ))
        }
    }
    let owner: Option<String> =
        sqlx::query_scalar("SELECT record_id FROM bindings WHERE system = ? AND identifier = ?")
            .bind(&event.system)
            .bind(&event.identifier)
            .fetch_optional(&mut *conn)
            .await?;
    if owner.as_deref() != Some(old_record_id) {
        return Err(Error::engine(
            "binding transfer audit does not own the identity it moves",
        ));
    }
    if old_canonical {
        let occupied: Option<String> = sqlx::query_scalar(
            "SELECT identifier FROM bindings
              WHERE record_id = ? AND system = ? AND is_canonical = 1",
        )
        .bind(new_record_id)
        .bind(&event.system)
        .fetch_optional(&mut *conn)
        .await?;
        if occupied.is_some() {
            return Err(Error::engine(
                "binding transfer audit would create a second canonical identity",
            ));
        }
    }
    sqlx::query("UPDATE bindings SET record_id = ?1 WHERE record_id = ?2 AND system = ?3 AND identifier = ?4")
        .bind(new_record_id)
        .bind(old_record_id)
        .bind(&event.system)
        .bind(&event.identifier)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{
        add_binding, canonicalize_binding, reconcile_bindings, remove_binding, resolve_external,
        resolve_stdio_account_identity, BindingClaim, MutationContext, StubHints,
    };
    use crate::Db;

    fn principal(id: &str) -> BindingClaim {
        BindingClaim {
            system: "native-principal".into(),
            identifier: format!("native/{id}"),
        }
    }

    fn context<'a>(actor: &'a str, reason: &'a str) -> MutationContext<'a> {
        MutationContext {
            actor,
            reason,
            run_key: Some("test-agent-abc123"),
            parent_key: None,
            intent: Some("exercise binding audit replay"),
            is_member: true,
            internal: false,
            source_read_authorized: false,
        }
    }

    async fn acquire(db: &Db) -> sqlx::pool::PoolConnection<sqlx::Sqlite> {
        db.write_pool().acquire().await.unwrap()
    }

    async fn binding_rows(
        db: &Db,
    ) -> Vec<(
        String,
        String,
        String,
        i64,
        Option<String>,
        Option<String>,
        Option<String>,
    )> {
        sqlx::query_as(
            "SELECT record_id,system,identifier,is_canonical,url,etag,last_seen_at
               FROM bindings ORDER BY record_id,system,identifier",
        )
        .fetch_all(db.pool())
        .await
        .unwrap()
    }

    #[allow(clippy::too_many_arguments)] // fixture helper mirrors the 15-column row
    async fn insert_audit(
        db: &Db,
        id: &str,
        action: &str,
        system: &str,
        identifier: &str,
        old_record: Option<&str>,
        new_record: Option<&str>,
        old_canonical: Option<i64>,
        new_canonical: Option<i64>,
        act: Option<i64>,
    ) {
        sqlx::query(
            "INSERT INTO binding_audit
               (id,action,system,identifier,old_record_id,new_record_id,old_canonical,new_canonical,
                actor,reason,created_at,act)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'test:actor','range test','2026-01-01T00:00:00.000Z',?9)",
        )
        .bind(id)
        .bind(action)
        .bind(system)
        .bind(identifier)
        .bind(old_record)
        .bind(new_record)
        .bind(old_canonical)
        .bind(new_canonical)
        .bind(act)
        .execute(db.write_pool())
        .await
        .unwrap();
    }

    fn row(
        action: &str,
        system: &str,
        identifier: &str,
        old_record: Option<&str>,
        new_record: Option<&str>,
        old_canonical: Option<bool>,
        new_canonical: Option<bool>,
    ) -> BindingAuditRow {
        BindingAuditRow {
            seq: 0,
            id: "constructed".into(),
            action: action.into(),
            system: system.into(),
            identifier: identifier.into(),
            old_record_id: old_record.map(str::to_owned),
            new_record_id: new_record.map(str::to_owned),
            old_canonical,
            new_canonical,
            actor: "test:actor".into(),
            reason: "constructed".into(),
            run_key: None,
            parent_key: None,
            intent: None,
            created_at: "2026-01-01T00:00:00.000Z".into(),
            act: Some(1),
        }
    }

    /// R3.0c: one decoder, two readers. The bounded reader selects exactly the
    /// half-open `(from, to]` interval in `seq` order, includes the maximum act
    /// at the inclusive upper bound, and never returns a legacy NULL-act row.
    #[tokio::test]
    async fn act_range_reader_is_bounded_ordered_and_excludes_legacy_null_acts() {
        let db = crate::create_database(":memory:").await.unwrap();
        insert_audit(
            &db,
            "a10",
            "add",
            "native-principal",
            "native/r1",
            None,
            Some("rec-1"),
            None,
            Some(0),
            Some(10),
        )
        .await;
        insert_audit(
            &db,
            "a20",
            "canonicalize",
            "native-principal",
            "native/r1",
            Some("rec-1"),
            Some("rec-1"),
            Some(0),
            Some(1),
            Some(20),
        )
        .await;
        insert_audit(
            &db,
            "a30",
            "remove",
            "native-principal",
            "native/r1",
            Some("rec-1"),
            None,
            Some(1),
            None,
            Some(30),
        )
        .await;
        insert_audit(
            &db,
            "legacy",
            "add",
            "native-principal",
            "native/r2",
            None,
            Some("rec-2"),
            None,
            Some(0),
            None,
        )
        .await;

        let mut conn = acquire(&db).await;
        let full = read_all_binding_audit(&mut conn).await.unwrap();
        assert_eq!(full.len(), 4, "three stamped rows plus one legacy row");
        assert!(full.iter().any(|row| row.act.is_none()));
        assert_eq!(full[1].old_canonical, Some(false));
        assert_eq!(full[1].new_canonical, Some(true));

        let all_stamped = binding_audit_in_act_range(&mut conn, 0, i64::MAX)
            .await
            .unwrap();
        assert_eq!(all_stamped.len(), 3, "the NULL-act legacy row is excluded");
        assert_eq!(
            all_stamped.iter().map(|row| row.seq).collect::<Vec<_>>(),
            vec![full[0].seq, full[1].seq, full[2].seq],
            "bounded rows stay in seq order"
        );
        assert_eq!(all_stamped.last().unwrap().act, Some(30));

        let exclusive_lower = binding_audit_in_act_range(&mut conn, 10, 30).await.unwrap();
        assert_eq!(
            exclusive_lower
                .iter()
                .map(|row| row.act)
                .collect::<Vec<_>>(),
            vec![Some(20), Some(30)],
            "the lower bound is exclusive and the upper bound inclusive"
        );
        let below_max = binding_audit_in_act_range(&mut conn, 10, 29).await.unwrap();
        assert_eq!(
            below_max.iter().map(|row| row.act).collect::<Vec<_>>(),
            vec![Some(20)]
        );
        assert!(
            binding_audit_in_act_range(&mut conn, 30, i64::MAX)
                .await
                .unwrap()
                .is_empty(),
            "a range above the maximum act is empty"
        );
        drop(conn);
        db.close().await;
    }

    /// R3.0c: a real live sequence — add, canonicalize demote and promote,
    /// remove, transfer — folds back to exactly the live `bindings` table from
    /// the whole `binding_audit` log. `url`, `etag`, and `last_seen_at` stay
    /// NULL, as the live writers leave them, and `binding_systems` is untouched.
    #[tokio::test]
    async fn whole_log_binding_replay_reproduces_live_bindings_exactly() {
        let db = crate::create_database(":memory:").await.unwrap();
        let actor = resolve_stdio_account_identity(&db, None).await.unwrap();
        let ctx = context(&actor, "live binding sequence");

        let source = resolve_external(&db, &ctx, &[principal("r3c-source")], &StubHints::default())
            .await
            .unwrap();
        add_binding(&db, &ctx, &source.record_id, &principal("r3c-alias"), false)
            .await
            .unwrap();
        assert!(
            canonicalize_binding(&db, &ctx, &source.record_id, &principal("r3c-alias"))
                .await
                .unwrap(),
            "promoting the alias demotes the previous canonical"
        );
        assert!(
            remove_binding(&db, &ctx, &source.record_id, &principal("r3c-alias"))
                .await
                .unwrap()
        );
        let target = resolve_external(&db, &ctx, &[principal("r3c-target")], &StubHints::default())
            .await
            .unwrap();
        let transferred = reconcile_bindings(
            &db,
            &ctx,
            &target.record_id,
            &source.record_id,
            &[principal("r3c-source")],
            true,
        )
        .await
        .unwrap();
        assert_eq!(transferred, vec![principal("r3c-source")]);

        let actions: Vec<String> =
            sqlx::query_scalar("SELECT action FROM binding_audit ORDER BY seq")
                .fetch_all(db.pool())
                .await
                .unwrap();
        for expected in [
            "add",
            "add",
            "canonicalize",
            "canonicalize",
            "remove",
            "add",
            "transfer",
        ] {
            assert!(
                actions.contains(&expected.to_string()),
                "the live audit log covers '{expected}': {actions:?}"
            );
        }

        let systems_before: Vec<(String, i64, i64)> = sqlx::query_as(
            "SELECT system,stub_allowed,required_durable FROM binding_systems ORDER BY system",
        )
        .fetch_all(db.pool())
        .await
        .unwrap();
        let live = binding_rows(&db).await;
        assert!(live
            .iter()
            .all(|row| row.4.is_none() && row.5.is_none() && row.6.is_none()));

        let mut conn = acquire(&db).await;
        let audit = read_all_binding_audit(&mut conn).await.unwrap();
        assert!(audit.len() >= 7, "the whole audited log is present");
        let audit_count_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM binding_audit")
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        let next_act_before: i64 =
            sqlx::query_scalar("SELECT next_act FROM act_state WHERE singleton = 1")
                .fetch_one(&mut *conn)
                .await
                .unwrap();
        sqlx::query("DELETE FROM bindings")
            .execute(&mut *conn)
            .await
            .unwrap();
        replay_bindings(&mut conn, &audit).await.unwrap();
        let audit_count_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM binding_audit")
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        let next_act_after: i64 =
            sqlx::query_scalar("SELECT next_act FROM act_state WHERE singleton = 1")
                .fetch_one(&mut *conn)
                .await
                .unwrap();
        drop(conn);
        assert_eq!(
            audit_count_after, audit_count_before,
            "the projector must append no audit row"
        );
        assert_eq!(
            next_act_after, next_act_before,
            "the projector must allocate no act"
        );

        let rebuilt = binding_rows(&db).await;
        assert_eq!(
            rebuilt, live,
            "whole-log replay must reproduce live bindings exactly"
        );
        assert!(
            rebuilt
                .iter()
                .all(|row| row.4.is_none() && row.5.is_none() && row.6.is_none()),
            "the projector must not invent url/etag/last_seen_at"
        );
        let systems_after: Vec<(String, i64, i64)> = sqlx::query_as(
            "SELECT system,stub_allowed,required_durable FROM binding_systems ORDER BY system",
        )
        .fetch_all(db.pool())
        .await
        .unwrap();
        assert_eq!(
            systems_after, systems_before,
            "binding_systems must never be mutated"
        );
        assert!(crate::identity::state_violations(&db)
            .await
            .unwrap()
            .is_empty());
        db.close().await;
    }

    /// R3.0c: bounded composition. Split a real live history at one act
    /// boundary `F1`, rebuild the exact projected prefix through `F1`, read the
    /// delta through `binding_audit_in_act_range(F1, F2)`, and replay only the
    /// delta. The composition must equal the live table, and the prefix and
    /// delta must partition the seq order.
    #[tokio::test]
    async fn bounded_range_replay_composes_with_a_rebuilt_prefix_to_match_live() {
        let db = crate::create_database(":memory:").await.unwrap();
        let actor = resolve_stdio_account_identity(&db, None).await.unwrap();
        let ctx = context(&actor, "bounded composition");

        let source = resolve_external(
            &db,
            &ctx,
            &[principal("r3c-comp-source")],
            &StubHints::default(),
        )
        .await
        .unwrap();
        add_binding(
            &db,
            &ctx,
            &source.record_id,
            &principal("r3c-comp-alias"),
            false,
        )
        .await
        .unwrap();
        assert!(
            canonicalize_binding(&db, &ctx, &source.record_id, &principal("r3c-comp-alias"))
                .await
                .unwrap(),
            "promoting the alias demotes the previous canonical"
        );
        let target = resolve_external(
            &db,
            &ctx,
            &[principal("r3c-comp-target")],
            &StubHints::default(),
        )
        .await
        .unwrap();
        assert_eq!(
            reconcile_bindings(
                &db,
                &ctx,
                &target.record_id,
                &source.record_id,
                &[principal("r3c-comp-source")],
                true,
            )
            .await
            .unwrap(),
            vec![principal("r3c-comp-source")]
        );

        let live = binding_rows(&db).await;
        let mut conn = acquire(&db).await;
        let audit = read_all_binding_audit(&mut conn).await.unwrap();
        let mut acts: Vec<i64> = audit.iter().filter_map(|event| event.act).collect();
        acts.sort_unstable();
        acts.dedup();
        assert!(acts.len() >= 3, "the history spans several acts: {acts:?}");
        let f1 = acts[acts.len() / 2];
        let f2 = *acts.last().unwrap();

        let base = binding_audit_in_act_range(&mut conn, 0, f1).await.unwrap();
        let delta = binding_audit_in_act_range(&mut conn, f1, f2).await.unwrap();
        assert!(!base.is_empty(), "the prefix through {f1} is non-empty");
        assert!(!delta.is_empty(), "the delta ({f1}, {f2}] is non-empty");
        assert!(delta
            .iter()
            .all(|event| event.act.is_some_and(|act| act > f1 && act <= f2)));
        assert!(
            base.iter().map(|event| event.seq).max().unwrap()
                < delta.iter().map(|event| event.seq).min().unwrap(),
            "acts are monotone with seq, so the split is a contiguous prefix"
        );

        sqlx::query("DELETE FROM bindings")
            .execute(&mut *conn)
            .await
            .unwrap();
        replay_bindings(&mut conn, &base).await.unwrap();
        replay_bindings(&mut conn, &delta).await.unwrap();
        drop(conn);

        let rebuilt = binding_rows(&db).await;
        assert_eq!(
            rebuilt, live,
            "rebuilt prefix plus bounded delta must equal live bindings"
        );
        assert!(crate::identity::state_violations(&db)
            .await
            .unwrap()
            .is_empty());
        db.close().await;
    }

    /// R3.0c: the projector refuses unknown actions and systems, malformed
    /// action shapes, and impossible preconditions instead of half-applying.
    #[tokio::test]
    async fn binding_projector_refuses_unknown_malformed_and_impossible_rows() {
        let db = crate::create_database(":memory:").await.unwrap();
        let actor = resolve_stdio_account_identity(&db, None).await.unwrap();
        let ctx = context(&actor, "precondition fixtures");
        let record = resolve_external(
            &db,
            &ctx,
            &[principal("r3c-existing")],
            &StubHints::default(),
        )
        .await
        .unwrap();
        let mut conn = acquire(&db).await;
        // A second identity that really has an owner, so the collision case
        // below is refuted by live state rather than by an absent row.
        sqlx::query("INSERT INTO bindings(record_id,system,identifier,is_canonical) VALUES(?1,'native-principal','native/r3c-collides',0)")
            .bind(&record.record_id)
            .execute(&mut *conn)
            .await
            .unwrap();

        let cases: Vec<(&str, BindingAuditRow)> = vec![
            (
                "unknown action",
                row(
                    "reconcile",
                    "native-principal",
                    "native/x",
                    None,
                    Some("r"),
                    None,
                    Some(true),
                ),
            ),
            (
                "unknown system",
                row(
                    "add",
                    "not-a-system",
                    "x",
                    None,
                    Some("r"),
                    None,
                    Some(true),
                ),
            ),
            (
                "add without a new record",
                row(
                    "add",
                    "native-principal",
                    "native/x",
                    None,
                    None,
                    None,
                    Some(true),
                ),
            ),
            (
                "add with prior state",
                row(
                    "add",
                    "native-principal",
                    "native/x",
                    Some("r"),
                    Some("r"),
                    Some(false),
                    Some(true),
                ),
            ),
            (
                "add of an existing binding",
                row(
                    "add",
                    "native-principal",
                    "native/r3c-existing",
                    None,
                    Some(&record.record_id),
                    None,
                    Some(true),
                ),
            ),
            (
                "add colliding with another owner",
                row(
                    "add",
                    "native-principal",
                    "native/r3c-collides",
                    None,
                    Some("some-other-record"),
                    None,
                    Some(false),
                ),
            ),
            (
                "canonicalize across two records",
                row(
                    "canonicalize",
                    "native-principal",
                    "native/x",
                    Some("a"),
                    Some("b"),
                    Some(false),
                    Some(true),
                ),
            ),
            (
                "canonicalize with unchanged state",
                row(
                    "canonicalize",
                    "native-principal",
                    "native/x",
                    Some("a"),
                    Some("a"),
                    Some(false),
                    Some(false),
                ),
            ),
            (
                "canonicalize of a missing binding",
                row(
                    "canonicalize",
                    "native-principal",
                    "native/x",
                    Some("a"),
                    Some("a"),
                    Some(false),
                    Some(true),
                ),
            ),
            (
                "remove with new state",
                row(
                    "remove",
                    "native-principal",
                    "native/x",
                    Some("a"),
                    Some("b"),
                    Some(true),
                    Some(false),
                ),
            ),
            (
                "remove without prior state",
                row(
                    "remove",
                    "native-principal",
                    "native/x",
                    Some("a"),
                    None,
                    None,
                    None,
                ),
            ),
            (
                "remove of a missing binding",
                row(
                    "remove",
                    "native-principal",
                    "native/x",
                    Some("a"),
                    None,
                    Some(false),
                    None,
                ),
            ),
            (
                "transfer onto the same record",
                row(
                    "transfer",
                    "native-principal",
                    "native/x",
                    Some("a"),
                    Some("a"),
                    Some(false),
                    Some(false),
                ),
            ),
            (
                "transfer changing canonical state",
                row(
                    "transfer",
                    "native-principal",
                    "native/x",
                    Some("a"),
                    Some("b"),
                    Some(false),
                    Some(true),
                ),
            ),
            (
                "transfer of a missing source",
                row(
                    "transfer",
                    "native-principal",
                    "native/x",
                    Some("a"),
                    Some("b"),
                    Some(false),
                    Some(false),
                ),
            ),
        ];
        for (label, case) in cases {
            assert!(
                project_binding_audit_event(&mut conn, &case).await.is_err(),
                "expected refusal for {label}"
            );
        }
        drop(conn);
        db.close().await;
    }

    /// R3.0c: content `record.created` and the binding `add` share one act on
    /// the real `resolve_external` stub path. This proves binding-before-content
    /// replay is *safe* under deferred foreign keys — not that any scheduler
    /// chooses that order. With immediate enforcement (the default) the same
    /// binding write is rejected while the record is absent; inside one
    /// `defer_foreign_keys=ON` transaction it is accepted, the content event
    /// then restores the record, and the commit passes `foreign_key_check`. No
    /// other act-stamped reaction log shares the act.
    #[tokio::test]
    async fn same_act_binding_before_content_replay_is_safe_under_deferred_foreign_keys() {
        let db = crate::create_database(":memory:").await.unwrap();
        let actor = resolve_stdio_account_identity(&db, None).await.unwrap();
        let ctx = context(&actor, "same-act scheduling");
        let stub = resolve_external(
            &db,
            &ctx,
            &[principal("r3c-schedule")],
            &StubHints::default(),
        )
        .await
        .unwrap();
        assert!(stub.created);

        let content_act: Option<i64> = sqlx::query_scalar(
            "SELECT act FROM content_events WHERE record_id = ? AND type = 'record.created'",
        )
        .bind(&stub.record_id)
        .fetch_one(db.pool())
        .await
        .unwrap();
        let binding_act: Option<i64> = sqlx::query_scalar(
            "SELECT act FROM binding_audit WHERE new_record_id = ? AND action = 'add'",
        )
        .bind(&stub.record_id)
        .fetch_one(db.pool())
        .await
        .unwrap();
        let shared = content_act.expect("stub content event is stamped");
        assert_eq!(
            binding_act,
            Some(shared),
            "content and binding share the act"
        );

        for table in crate::act::ACT_STAMPED_TABLES {
            if matches!(table, "content_events" | "binding_audit") {
                continue;
            }
            let count: i64 =
                sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE act = ?"))
                    .bind(shared)
                    .fetch_one(db.pool())
                    .await
                    .unwrap();
            assert_eq!(
                count, 0,
                "reaction log '{table}' must not share the stub act"
            );
        }

        let mut conn = acquire(&db).await;
        let audit = read_all_binding_audit(&mut conn).await.unwrap();
        let add = audit
            .iter()
            .find(|event| {
                event.action == "add" && event.new_record_id.as_deref() == Some(&stub.record_id)
            })
            .expect("the stub binding add is in the audit log")
            .clone();
        drop(conn);
        let events = crate::query::events::log_prefix(&db, i64::MAX)
            .await
            .unwrap();
        let content = events
            .iter()
            .find(|event| event.record_id == stub.record_id && event.event_type == "record.created")
            .expect("the stub content event is readable")
            .clone();

        // Deterministic contrast on an orphan binding: immediate enforcement
        // rejects it outright, deferred enforcement accepts it and leaves the
        // decision to commit.
        let orphan = row(
            "add",
            "native-principal",
            "native/r3c-orphan",
            None,
            Some("r3c-absent-record"),
            None,
            Some(false),
        );
        let mut immediate = crate::db::begin_write(db.write_pool()).await.unwrap();
        assert!(
            project_binding_audit_event(&mut immediate, &orphan)
                .await
                .is_err(),
            "immediate enforcement rejects a binding ahead of its record"
        );
        immediate.rollback().await.unwrap();
        let mut deferred = crate::db::begin_write(db.write_pool()).await.unwrap();
        sqlx::query("PRAGMA defer_foreign_keys=ON")
            .execute(&mut *deferred)
            .await
            .unwrap();
        project_binding_audit_event(&mut deferred, &orphan)
            .await
            .expect("deferred enforcement accepts a binding ahead of its record");
        deferred.rollback().await.unwrap();

        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        sqlx::query("PRAGMA defer_foreign_keys=ON")
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("DELETE FROM bindings WHERE record_id = ?")
            .bind(&stub.record_id)
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("DELETE FROM records WHERE id = ?")
            .bind(&stub.record_id)
            .execute(&mut *tx)
            .await
            .unwrap();

        // Replay the binding first: its foreign key points at a record that does
        // not exist yet. Deferred enforcement permits the write.
        project_binding_audit_event(&mut tx, &add).await.unwrap();
        let binding_present: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM bindings WHERE record_id = ? AND system = 'native-principal'",
        )
        .bind(&stub.record_id)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        let record_absent: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records WHERE id = ?")
            .bind(&stub.record_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(binding_present, 1, "binding is projected before its record");
        assert_eq!(
            record_absent, 0,
            "the record is genuinely absent mid-transaction"
        );

        // Project the content event, which restores the record, then commit.
        crate::projector::project(&mut tx, &content).await.unwrap();
        tx.commit().await.unwrap();

        let record_present: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records WHERE id = ?")
            .bind(&stub.record_id)
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(record_present, 1);
        let violations: Vec<(String, i64, String, i64)> =
            sqlx::query_as("SELECT * FROM pragma_foreign_key_check")
                .fetch_all(db.pool())
                .await
                .unwrap();
        assert!(
            violations.is_empty(),
            "deferred FKs are satisfied at commit"
        );
        db.close().await;
    }

    /// R3.0c: a genesis mint or a rekey inside a bounded act range refuses the
    /// incremental binding path; an empty range above the change passes.
    #[tokio::test]
    async fn identity_change_in_act_range_requires_whole_snapshot_fallback() {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut conn = acquire(&db).await;
        let mint_act: i64 = sqlx::query_scalar(
            "SELECT act FROM database_identity_audit WHERE action = 'mint' ORDER BY seq LIMIT 1",
        )
        .fetch_one(&mut *conn)
        .await
        .unwrap();
        assert!(
            require_whole_snapshot_for_identity_change(&mut conn, 0, i64::MAX)
                .await
                .is_err(),
            "the genesis mint in range refuses the incremental path"
        );
        require_whole_snapshot_for_identity_change(&mut conn, mint_act, i64::MAX)
            .await
            .expect("an empty range above the change passes");

        let old = crate::identity::database_id(&db).await.unwrap();
        sqlx::query(
            "INSERT INTO database_identity_audit
               (id,action,old_origin_db_id,new_origin_db_id,actor,reason,created_at,act)
             VALUES ('rekey-test','rekey',?,?,'engine:test','rekey in range','2026-01-01T00:00:00.000Z',?)",
        )
        .bind(&old)
        .bind("ndb_ffffffffffffffffffffffffffffffff")
        .bind(mint_act + 1)
        .execute(&mut *conn)
        .await
        .unwrap();
        assert!(
            require_whole_snapshot_for_identity_change(&mut conn, mint_act, mint_act + 1)
                .await
                .is_err(),
            "a rekey in range refuses the incremental path"
        );
        assert!(
            !identity_change_in_act_range(&mut conn, mint_act + 1, i64::MAX)
                .await
                .unwrap(),
            "the rekey is outside the later range"
        );
        drop(conn);
        db.close().await;
    }
}
