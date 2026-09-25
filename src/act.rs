//! Per-workspace act number (decision 4e152d5, task acd735f).
//!
//! Native keeps ten separate sequenced logs. A single atomic write often spans
//! more than one of them, and nothing recorded that those rows were the same
//! write. The act number writes it down: one gapless counter per workspace,
//! bumped once per write transaction and stamped on every canonical event that
//! transaction appends.
//!
//! Two design decisions live here, made deliberately rather than by accident:
//!
//! * **Where the counter lives.** A singleton row (`act_state`, exactly one
//!   row with `singleton = 1`) updated inside the writing transaction. The
//!   bump rolls back with the transaction, which is what makes the counter
//!   gapless, and it adds no new serialization: decision 2885ba0 already
//!   serializes writers per workspace (`BEGIN IMMEDIATE` on SQLite, the
//!   per-log cursor row locks on Postgres), so the counter UPDATE rides
//!   inside a lock the writer already holds.
//! * **Column name.** The docs keep the word "act" because it is the term
//!   legible to non-engineers. The column is `act` too: `seq` is already
//!   taken by the per-domain replay positions, and `commit_seq`/`write_seq`
//!   invite confusion about which sequence orders what. `act` is distinct,
//!   short, and matches the decision language.
//!
//! Allocation is lazy and exactly-once per transaction: the first canonical
//! append bumps the counter, every later append in the same transaction
//! reuses the value. [`ActAllocation`] is the memo. Portable backends carry
//! the memo on their domain-transaction structs; the SQLite raw path threads
//! it explicitly through the append functions, so a transaction that appends
//! to several domains shares one value by construction.

use sqlx::SqliteConnection;

use crate::{Error, Result};

/// The ten sequenced canonical domains stamped with an act number. This is
/// the same membership as the ten `*_seq` event coordinates of
/// [`crate::standby_snapshot::CanonicalFrontierV1`]; the two remaining
/// frontier coordinates (`authorization_revision_epoch` and
/// `storage_portability_policy_revision`) are version stamps, not event logs,
/// and carry no act.
///
/// Keep this list exhaustive: the act-coverage test fails a build where a
/// sequenced log exists without an `act` column.
pub const CANONICAL_EVENT_TABLES: [&str; 10] = [
    "content_events",
    "policy_events",
    "awareness_events",
    "notification_candidate_events",
    "binding_audit",
    "database_identity_audit",
    "meta_events",
    "control_events",
    "derivation_events",
    "relationship_events",
];

/// Sequenced (`AUTOINCREMENT`) tables that are deliberately NOT canonical
/// event logs and therefore carry no act:
///
/// * `read_log_calls` is disposable surveillance evidence, droppable by
///   design without changing any behavioral tool.
/// * `webhook_deliveries` is transient operational transport state, not
///   canonical history.
pub const NON_CANONICAL_SEQUENCED_TABLES: [&str; 2] = ["read_log_calls", "webhook_deliveries"];

/// Canonical tables that carry an act but are NOT among the ten sequenced
/// logs, so they are not [`CanonicalFrontierV1`] coordinates and take no
/// `act_cutover` row.
///
/// `provenance_attestation_validity_events` is append-only canonical history:
/// an invalidation or restoration changes which attestations a replica should
/// honour, and that change must be observable in the act range a delta
/// carries. It has no global `seq` and no `AUTOINCREMENT` primary key,
/// because its replay position is `(attestation_id, ordinal)`, so there is no
/// per-domain frontier for `act_cutover.last_legacy_seq` to name. Its
/// grouping-unknown state is therefore per-row rather than a frontier:
/// pre-cutover rows keep a NULL act and the partial
/// `idx_provenance_validity_act` skips them.
///
/// `external_observations` and `awareness_command_intents` are the same kind:
/// append-only canonical history positioned by their own primary keys
/// (`id` and `(subject_account_id, idempotency_key)`), stamped per writing
/// transaction so a whole-act cut carries them exactly. Pre-stamping rows
/// keep a NULL act and their partial `idx_*_act` indexes skip them.
///
/// Keep this list exhaustive and in this order: the act-coverage test checks
/// every entry for an `act` column, the partial-index test checks every
/// entry for exactly one `WHERE act IS NOT NULL` index, and the
/// authority-head contract emits its per-table max-act vector in this order,
/// so a new non-sequenced canonical act-stamped table cannot ship unstamped,
/// unindexed, or unpinned.
pub const NON_SEQUENCED_ACT_STAMPED_TABLES: [&str; 3] = [
    "awareness_command_intents",
    "external_observations",
    "provenance_attestation_validity_events",
];

/// Every canonical table stamped with a workspace act: the ten sequenced logs
/// plus the three non-sequenced act-stamped logs. The act-coverage test
/// iterates this list, so it cannot silently omit either category.
pub const ACT_STAMPED_TABLES: [&str; 13] = [
    "content_events",
    "policy_events",
    "awareness_events",
    "notification_candidate_events",
    "binding_audit",
    "database_identity_audit",
    "meta_events",
    "control_events",
    "derivation_events",
    "relationship_events",
    "awareness_command_intents",
    "external_observations",
    "provenance_attestation_validity_events",
];

/// The first act a workspace allocates: `act_state.next_act` is seeded at 0
/// and bumped before the value is read, so act `1` belongs to the first write
/// transaction. Named because the honest-absence contract (`crate::holding`)
/// decides whether a replica reaches genesis by testing whether its oldest
/// held act *is* the first act, and that question deserves better than a
/// bare literal.
pub const FIRST_ACT: i64 = 1;

/// Per-transaction act memo: allocate lazily on the first canonical append,
/// reuse for every later append in the same transaction.
///
/// One value per transaction is enforced by sharing one memo across the
/// appends of that transaction. On the SQLite path the memo is an explicit
/// `&mut ActAllocation` parameter on every canonical append function, so a
/// second memo in the same scope is visibly wrong; on the portable path the
/// memo lives on the domain-transaction struct itself.
#[derive(Debug, Default)]
pub struct ActAllocation {
    act: Option<i64>,
}

impl ActAllocation {
    pub fn new() -> Self {
        Self { act: None }
    }

    /// The already-allocated act, if the transaction has appended before.
    pub fn get(&self) -> Option<i64> {
        self.act
    }

    /// Forget a memoized act whose database bump was undone. Only a
    /// savepoint rollback inside the transaction may call this: a full
    /// transaction rollback discards the memo with the transaction, and
    /// nothing else revokes a bump. See the savepoint wrappers in
    /// `crate::relationship::persistence`, which snapshot the memo before
    /// the savepoint and reset only when it held nothing then — a bump can
    /// only have happened inside the savepoint in that case, so the
    /// rollback necessarily revoked exactly the memoized value.
    pub(crate) fn reset(&mut self) {
        self.act = None;
    }

    /// Return this transaction's act, bumping the workspace counter on the
    /// first call. The bump is an in-transaction singleton UPDATE, so a
    /// rollback takes the allocation with it and the counter stays gapless.
    pub(crate) async fn get_or_allocate(&mut self, conn: &mut SqliteConnection) -> Result<i64> {
        if let Some(act) = self.act {
            return Ok(act);
        }
        let act: i64 = sqlx::query_scalar(
            "UPDATE act_state SET next_act = next_act + 1 WHERE singleton = 1 RETURNING next_act",
        )
        .fetch_one(&mut *conn)
        .await?;
        if act <= 0 {
            return Err(Error::engine("allocated act number is not positive"));
        }
        self.act = Some(act);
        Ok(act)
    }
}

/// Read the workspace's current act number without allocating one. This is
/// the read side the decision requires alongside production: the counter
/// value, i.e. the act of the most recently committed write transaction, or
/// 0 when no write has been stamped yet.
pub(crate) async fn current_act(conn: &mut SqliteConnection) -> Result<i64> {
    let current: Option<i64> =
        sqlx::query_scalar("SELECT next_act FROM act_state WHERE singleton = 1")
            .fetch_optional(&mut *conn)
            .await?;
    current
        .ok_or_else(|| Error::engine("act counter is missing: engine schema 56 requires act_state"))
}

/// Last grouping-unknown replay position per canonical domain, recorded by
/// the engine-56 migration. Rows at or below the cutover predate act
/// stamping and their transaction grouping is permanently unknown; rows
/// above it always carry an act.
pub async fn act_cutover_for(conn: &mut SqliteConnection, domain: &str) -> Result<Option<i64>> {
    sqlx::query_scalar("SELECT last_legacy_seq FROM act_cutover WHERE domain = ?")
        .bind(domain)
        .fetch_optional(&mut *conn)
        .await
        .map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn memdb() -> crate::db::Db {
        crate::db::create_database(":memory:").await.unwrap()
    }

    async fn table_act(db: &crate::db::Db, table: &str, seq: i64) -> Option<i64> {
        sqlx::query_scalar(&format!("SELECT act FROM {table} WHERE seq = ?"))
            .bind(seq)
            .fetch_optional(db.write_pool())
            .await
            .unwrap()
            .flatten()
    }

    /// Acceptance criterion 2: a rolled-back transaction consumes no act.
    /// Proven by exhausting the allocator (observing act 1), rolling back a
    /// transaction that appended, and showing the next committed transaction
    /// still allocates act 2 (no gap).
    #[tokio::test]
    async fn rolled_back_transaction_consumes_no_act() {
        let db = memdb().await;
        let first = crate::store::append(
            &db,
            crate::store::AppendSpec {
                record_id: "1a7e4000-0000-4000-8000-000000000001".into(),
                event_type: "record.created".into(),
                payload: serde_json::json!({
                    "type": "Document",
                    "kind": "note",
                    "name": "before rollback",
                }),
                actor: None,
            },
        )
        .await
        .unwrap();
        let first_act: Option<i64> =
            sqlx::query_scalar("SELECT act FROM content_events WHERE seq = ?")
                .bind(first.local_seq)
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        // Fresh databases already hold seeding writes; the first test write
        // takes whatever act is next.
        let first_act = first_act.expect("appended event carries an act");

        // A transaction that appends and then rolls back.
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut alloc = ActAllocation::new();
        crate::store::append_in(
            &db,
            &mut tx,
            crate::store::AppendSpec {
                record_id: "1a7e4000-0000-4000-8000-000000000002".into(),
                event_type: "record.created".into(),
                payload: serde_json::json!({
                    "type": "Document",
                    "kind": "note",
                    "name": "rolled back",
                }),
                actor: None,
            },
            &mut alloc,
        )
        .await
        .unwrap();
        tx.rollback().await.unwrap();

        // The counter did not advance: the next committed write reuses the
        // act the rolled-back transaction briefly held.
        let second = crate::store::append(
            &db,
            crate::store::AppendSpec {
                record_id: "1a7e4000-0000-4000-8000-000000000003".into(),
                event_type: "record.created".into(),
                payload: serde_json::json!({
                    "type": "Document",
                    "kind": "note",
                    "name": "after rollback",
                }),
                actor: None,
            },
        )
        .await
        .unwrap();
        let second_act: Option<i64> =
            sqlx::query_scalar("SELECT act FROM content_events WHERE seq = ?")
                .bind(second.local_seq)
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        assert_eq!(
            second_act,
            Some(first_act + 1),
            "rollback must not consume an act"
        );
        assert_eq!(
            table_act(&db, "content_events", first.local_seq).await,
            Some(first_act)
        );
        db.close().await;
    }

    /// Acceptance criterion 3 (five-domain case): one transaction writing
    /// to five different domains consumes exactly one act. This exercises
    /// the shared-transaction threading directly: content, policy,
    /// awareness, control and derivation appends in one `begin_write` scope
    /// share a single `ActAllocation`.
    #[tokio::test]
    async fn one_transaction_across_five_domains_consumes_one_act() {
        let db = memdb().await;
        let record = crate::store::append(
            &db,
            crate::store::AppendSpec {
                record_id: "1a7e4000-0000-4000-8000-000000000010".into(),
                event_type: "record.created".into(),
                payload: serde_json::json!({
                    "type": "Document",
                    "kind": "note",
                    "name": "five-domain act",
                }),
                actor: None,
            },
        )
        .await
        .unwrap();
        let _ = record;

        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut alloc = ActAllocation::new();
        crate::store::append_in(
            &db,
            &mut tx,
            crate::store::AppendSpec {
                record_id: "1a7e4000-0000-4000-8000-000000000010".into(),
                event_type: "record.updated".into(),
                payload: serde_json::json!({"summary": "five-domain act"}),
                actor: None,
            },
            &mut alloc,
        )
        .await
        .unwrap();
        crate::policy::append_replaced_in(
            &mut tx,
            "1a7e4000-0000-4000-8000-000000000010",
            vec![crate::policy::NormalizedPolicyEntry::new(
                "members".into(),
                crate::authorization::MEMBERS_SUBJECT_ID.into(),
                crate::authorization::Capability::Edit,
            )],
            "act-test",
            "five-domain act",
            &mut alloc,
        )
        .await
        .unwrap();
        crate::awareness::append_notification_candidate_in(
            &mut tx,
            "acct:act-test",
            "1a7e4000-0000-4000-8000-000000000010",
            "human_obligation",
            "routine",
            None,
            "metadata_only",
            "portable_default",
            "act-test-v1",
            "record.updated",
            "five-domain-source",
            &mut alloc,
        )
        .await
        .unwrap();
        crate::control::append_control_event_in(
            &mut tx,
            crate::control::NewControlEvent::authored(
                "act-test-run-start",
                "act-test-activity",
                "acct:act-test",
                Some("scout-chair-a748b2".into()),
                "five-domain act",
                crate::control::ControlEventPayload::AgentRunStarted(
                    crate::control::AgentRunStartedPayload {
                        activity_id: "act-test-activity".into(),
                        account_id: "acct:act-test".into(),
                        started_at: crate::store::now_iso(),
                        reported_mcp_client_name: None,
                        reported_mcp_client_version: None,
                        reported_model: None,
                    },
                ),
            )
            .unwrap(),
            &mut alloc,
        )
        .await
        .unwrap();
        crate::derivation::append_derivation_event_in(
            &mut tx,
            crate::derivation::NewDerivationEvent::authored(
                "act-test-series",
                "act-test",
                None,
                "five-domain act",
                crate::derivation::DerivationEventPayload::SeriesCreated(
                    crate::derivation::DerivationSeriesCreated {
                        id: "act-test-series".into(),
                        series_key: "act-test-series".into(),
                        definition: serde_json::json!({"act": "test"}),
                    },
                ),
            )
            .unwrap(),
            &mut alloc,
        )
        .await
        .unwrap();
        db.commit_content(tx).await.unwrap();

        let acts: Vec<Option<i64>> = sqlx::query_scalar(
            "SELECT act FROM content_events WHERE record_id = '1a7e4000-0000-4000-8000-000000000010' AND type = 'record.updated'
             UNION ALL SELECT act FROM policy_events WHERE record_id = '1a7e4000-0000-4000-8000-000000000010'
             UNION ALL SELECT act FROM notification_candidate_events WHERE message_id = '1a7e4000-0000-4000-8000-000000000010'
             UNION ALL SELECT act FROM control_events WHERE idempotency_key = 'act-test-run-start'
             UNION ALL SELECT act FROM derivation_events WHERE idempotency_key = 'act-test-series'",
        )
        .fetch_all(db.write_pool())
        .await
        .unwrap();
        assert_eq!(acts.len(), 5);
        let first = acts[0].expect("content event carries an act");
        assert!(
            acts.iter().all(|act| *act == Some(first)),
            "one transaction must stamp one act, got {acts:?}"
        );
        let counter: i64 = sqlx::query_scalar("SELECT next_act FROM act_state WHERE singleton = 1")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(
            counter, first,
            "the five-domain write bumps the counter once"
        );
        db.close().await;
    }

    /// Acceptance criterion 5: a sequenced canonical event table without an
    /// act number fails. The rule is structural — every `AUTOINCREMENT`-keyed
    /// log except the two documented non-canonical sequenced tables must be
    /// a listed canonical domain and must carry an `act` column — so a new
    /// canonical log added without one breaks this test rather than shipping
    /// silently unstamped.
    #[tokio::test]
    async fn every_canonical_event_table_carries_act() {
        let db = memdb().await;
        let tables: Vec<(String, Option<String>)> = sqlx::query_as(
            "SELECT name, sql FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .fetch_all(db.write_pool())
        .await
        .unwrap();
        let mut sequenced = Vec::new();
        for (name, sql) in &tables {
            if sql
                .as_deref()
                .is_some_and(|sql| sql.contains("INTEGER PRIMARY KEY AUTOINCREMENT"))
            {
                sequenced.push(name.clone());
            }
        }
        for table in &sequenced {
            if NON_CANONICAL_SEQUENCED_TABLES.contains(&table.as_str()) {
                continue;
            }
            assert!(
                CANONICAL_EVENT_TABLES.contains(&table.as_str()),
                "sequenced table '{table}' is neither canonical nor a documented exclusion: classify it"
            );
        }
        for table in ACT_STAMPED_TABLES {
            let has_act: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info(?) WHERE name = 'act')",
            )
            .bind(table)
            .fetch_one(db.write_pool())
            .await
            .unwrap();
            assert!(has_act, "canonical event table '{table}' has no act column");
        }
        // The two constants partition ACT_STAMPED_TABLES: the ten sequenced
        // logs plus the declared non-sequenced tables, with no overlap and no
        // gap. A future table added to either category without joining the
        // exhaustive list fails here rather than shipping unstamped.
        let mut expected = CANONICAL_EVENT_TABLES.to_vec();
        expected.extend(NON_SEQUENCED_ACT_STAMPED_TABLES);
        assert_eq!(
            expected, ACT_STAMPED_TABLES,
            "ACT_STAMPED_TABLES must be the sequenced logs plus the non-sequenced act-stamped tables"
        );
        // A non-sequenced act-stamped table must genuinely be absent from the
        // `AUTOINCREMENT` scan, which is what makes the explicit list
        // necessary rather than redundant.
        for table in NON_SEQUENCED_ACT_STAMPED_TABLES {
            assert!(
                !sequenced.iter().any(|name| name == table),
                "non-sequenced act-stamped table '{table}' is AUTOINCREMENT-sequenced; classify it as canonical"
            );
        }
        db.close().await;
    }

    /// Slice 1 of cb551d7, extended by prerequisite 781a566a: every
    /// sequenced canonical log carries exactly one partial `act` index
    /// covering only stamped rows, and every non-sequenced act-stamped log
    /// keeps exactly its own partial `act` index. The indexed set is exactly
    /// the ten sequenced logs plus [`NON_SEQUENCED_ACT_STAMPED_TABLES`]; a
    /// new sequenced log without its index — or an index on a table outside
    /// both lists — fails this test rather than shipping drift between the
    /// act-range query path and the schema.
    #[tokio::test]
    async fn every_sequenced_canonical_log_has_exactly_one_partial_act_index() {
        let db = memdb().await;
        for table in CANONICAL_EVENT_TABLES {
            let expected = format!("idx_{table}_act");
            let indexes: Vec<String> = sqlx::query_scalar(
                "SELECT name FROM sqlite_schema WHERE type='index' AND tbl_name = ? AND sql LIKE '%WHERE act IS NOT NULL%' ORDER BY name",
            )
            .bind(table)
            .fetch_all(db.write_pool())
            .await
            .unwrap();
            assert_eq!(
                indexes,
                vec![expected.clone()],
                "sequenced canonical log '{table}' must carry exactly one partial act index"
            );
            let definition: String =
                sqlx::query_scalar("SELECT sql FROM sqlite_schema WHERE type='index' AND name = ?")
                    .bind(&expected)
                    .fetch_one(db.write_pool())
                    .await
                    .unwrap();
            assert!(
                definition.contains(&format!("ON {table}(act)"))
                    && definition.contains("WHERE act IS NOT NULL"),
                "unexpected {expected} definition: {definition}"
            );
        }
        // Each non-sequenced act-stamped log keeps its own partial act
        // index, exactly once, and none of them may be mistaken for a
        // sequenced-log index. The inventory is mechanical over
        // [`NON_SEQUENCED_ACT_STAMPED_TABLES`], so a newly stamped table
        // without its index fails here rather than shipping drift between
        // the act-range query path and the schema.
        for table in NON_SEQUENCED_ACT_STAMPED_TABLES {
            let indexes: Vec<String> = sqlx::query_scalar(
                "SELECT name FROM sqlite_schema WHERE type='index' AND tbl_name = ? AND sql LIKE '%WHERE act IS NOT NULL%' ORDER BY name",
            )
            .bind(table)
            .fetch_all(db.write_pool())
            .await
            .unwrap();
            assert_eq!(
                indexes.len(),
                1,
                "non-sequenced act-stamped table '{table}' must carry exactly one partial act index"
            );
            let definition: String =
                sqlx::query_scalar("SELECT sql FROM sqlite_schema WHERE type='index' AND name = ?")
                    .bind(&indexes[0])
                    .fetch_one(db.write_pool())
                    .await
                    .unwrap();
            assert!(
                definition.contains(&format!("ON {table}(act)"))
                    && definition.contains("WHERE act IS NOT NULL"),
                "unexpected {} definition: {definition}",
                indexes[0]
            );
        }
        // No other table carries a partial act index: the indexed set is
        // exactly the ten sequenced logs plus the non-sequenced act-stamped
        // logs.
        let placeholders = NON_SEQUENCED_ACT_STAMPED_TABLES
            .iter()
            .map(|_| "?")
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT tbl_name, name FROM sqlite_schema WHERE type='index' AND sql LIKE '%WHERE act IS NOT NULL%' AND tbl_name NOT IN ({placeholders}) ORDER BY tbl_name"
        );
        let mut indexed = sqlx::query_as::<_, (String, String)>(&sql);
        for table in NON_SEQUENCED_ACT_STAMPED_TABLES {
            indexed = indexed.bind(table);
        }
        let other: Vec<(String, String)> = indexed.fetch_all(db.write_pool()).await.unwrap();
        let other_tables: Vec<String> = other.iter().map(|(table, _)| table.clone()).collect();
        let mut expected_tables = CANONICAL_EVENT_TABLES.to_vec();
        expected_tables.sort_unstable();
        assert_eq!(
            other_tables, expected_tables,
            "partial act indexes must cover exactly the ten sequenced canonical logs"
        );
        db.close().await;
    }

    /// Finding 2 of f1ede92 (task 26f2e4c): the authoritative-log rebuild
    /// must be act-faithful, not merely event-identical.
    ///
    /// Drives the `delete_record` Message seam's two writes — the content
    /// tombstone plus the candidate withdrawal, which that tool performs in
    /// one transaction under one act (`src/mcp/tools/lifecycle.rs`) — with a
    /// control append alongside, so one act is verified to span three
    /// domains. Both logs are then rebuilt through the replay paths and
    /// every row's act is compared against the source. Legacy NULL-act rows
    /// rebuild as NULL: grouping-unknown is reproduced, never fabricated.
    /// Either replay dropping `act` again turns this test red.
    #[tokio::test]
    async fn authoritative_rebuild_is_act_faithful() {
        let db = memdb().await;
        let record_id = "1a7e4000-0000-4000-8000-000000000020";
        crate::store::append(
            &db,
            crate::store::AppendSpec {
                record_id: record_id.into(),
                event_type: "record.created".into(),
                payload: serde_json::json!({
                    "type": "Document",
                    "kind": "note",
                    "name": "act-faithful rebuild",
                }),
                actor: None,
            },
        )
        .await
        .unwrap();

        // An effective candidate for the delete transaction to withdraw. Its
        // own transaction takes its own act; the shared act under test is the
        // delete transaction's below.
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut alloc = ActAllocation::new();
        crate::awareness::append_notification_candidate_in(
            &mut tx,
            "acct:act-rebuild",
            record_id,
            "human_obligation",
            "routine",
            None,
            "metadata_only",
            "portable_default",
            "act-test-v1",
            "record.updated",
            "act-rebuild-source",
            &mut alloc,
        )
        .await
        .unwrap();
        db.commit_content(tx).await.unwrap();

        // One transaction, one act, three domains: the content tombstone, the
        // candidate withdrawal, and a control event — the same sharing the
        // delete_record Message path relies on.
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut alloc = ActAllocation::new();
        let deletion = crate::store::append_in(
            &db,
            &mut tx,
            crate::store::AppendSpec {
                record_id: record_id.into(),
                event_type: "record.deleted".into(),
                payload: serde_json::json!({"reason": "act-faithful rebuild"}),
                actor: None,
            },
            &mut alloc,
        )
        .await
        .unwrap();
        let withdrawn = crate::awareness::withdraw_message_candidates_in(
            &mut tx,
            record_id,
            "record.deleted",
            &deletion.id,
            &mut alloc,
        )
        .await
        .unwrap();
        assert_eq!(withdrawn, 1);
        let control = crate::control::append_control_event_in(
            &mut tx,
            crate::control::NewControlEvent::authored(
                "act-rebuild-run-start",
                "act-rebuild-activity",
                "acct:act-rebuild",
                Some("scout-chair-a748b2".into()),
                "act-faithful rebuild",
                crate::control::ControlEventPayload::AgentRunStarted(
                    crate::control::AgentRunStartedPayload {
                        activity_id: "act-rebuild-activity".into(),
                        account_id: "acct:act-rebuild".into(),
                        started_at: crate::store::now_iso(),
                        reported_mcp_client_name: None,
                        reported_mcp_client_version: None,
                        reported_model: None,
                    },
                ),
            )
            .unwrap(),
            &mut alloc,
        )
        .await
        .unwrap();
        db.commit_content(tx).await.unwrap();

        // The act is verified multi-domain: all three tables agree, and the
        // returned rows report it.
        let content_act: Option<i64> =
            sqlx::query_scalar("SELECT act FROM content_events WHERE id = ?")
                .bind(&deletion.id)
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        let withdrawal_act: Option<i64> = sqlx::query_scalar(
            "SELECT act FROM notification_candidate_events WHERE message_id = ? AND action = 'withdrawn'",
        )
        .bind(record_id)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        let control_act: Option<i64> =
            sqlx::query_scalar("SELECT act FROM control_events WHERE id = ?")
                .bind(&control.id)
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        let shared = content_act.expect("deletion carries an act");
        assert_eq!(withdrawal_act, Some(shared));
        assert_eq!(control_act, Some(shared));
        assert_eq!(deletion.act, Some(shared));
        assert_eq!(control.act, Some(shared));

        // The row types carry the act to replay: dropping the column from
        // either reader fails here, before the rebuild comparison.
        let mut live_conn = db.write_pool().acquire().await.unwrap();
        let control_rows = crate::control::read_all_control_events(&mut live_conn)
            .await
            .unwrap();
        let control_row = control_rows
            .iter()
            .find(|event| event.id == control.id)
            .expect("control event is readable");
        assert_eq!(control_row.act, Some(shared));
        let content_rows = crate::query::events::log_prefix(&db, i64::MAX)
            .await
            .unwrap();
        let deletion_row = content_rows
            .iter()
            .find(|event| event.id == deletion.id)
            .expect("deletion event is readable");
        assert_eq!(deletion_row.act, Some(shared));
        drop(live_conn);

        // Legacy pre-cutover rows: unstamped by construction, grouping unknown.
        // They are projected on the live path exactly as the replay will
        // project them, so the log and its projections agree beforehand.
        let legacy_payload = serde_json::json!({
            "type": "Document",
            "kind": "note",
            "name": "legacy",
            "home_id": crate::schema::UNFILED_RECORD_ID,
            "persistence": "enduring",
        })
        .to_string();
        let legacy_seq: i64 = sqlx::query_scalar(
            "INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status)
             VALUES('act-rebuild-legacy-content','1a7e4000-0000-4000-8000-000000000021','record.created',?,'engine:seed','2026-01-01T00:00:00.000Z',1,'legacy_unknown')
             RETURNING seq",
        )
        .bind(&legacy_payload)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        {
            let mut conn = db.write_pool().acquire().await.unwrap();
            crate::projector::project(
                &mut conn,
                &crate::events::EventRow {
                    local_seq: legacy_seq,
                    id: "act-rebuild-legacy-content".into(),
                    record_id: "1a7e4000-0000-4000-8000-000000000021".into(),
                    event_type: "record.created".into(),
                    payload: Some(legacy_payload),
                    actor: Some("engine:seed".into()),
                    run_key: None,
                    parent_key: None,
                    intent: None,
                    created_at: "2026-01-01T00:00:00.000Z".into(),
                    causal_envelope: crate::events::CausalEnvelopeV1::legacy_unknown(),
                    act: None,
                },
            )
            .await
            .unwrap();
        }
        // Records behind the legacy context's foreign keys. Real rows on the
        // live side; the control rebuild seeds inert identities for the same
        // ids, which is all its projection FKs need.
        for (id, name) in [
            ("1a7e4000-0000-4000-8000-000000000022", "legacy person"),
            ("1a7e4000-0000-4000-8000-000000000023", "legacy root"),
        ] {
            crate::store::append(
                &db,
                crate::store::AppendSpec {
                    record_id: id.into(),
                    event_type: "record.created".into(),
                    payload: serde_json::json!({
                        "type": "Document",
                        "kind": "note",
                        "name": name,
                    }),
                    actor: None,
                },
            )
            .await
            .unwrap();
        }
        let legacy_control_seq: i64 = sqlx::query_scalar(
            "INSERT INTO control_events(id,idempotency_key,type,schema_version,aggregate_kind,aggregate_id,actor,reason,payload,created_at)
             VALUES('act-rebuild-legacy-control','act-rebuild-legacy-control','member_context.provisioned',1,'member_context','acct:act-legacy','engine:seed','legacy seed',?,?)
             RETURNING seq",
        )
        .bind(
            serde_json::json!({
                "account_id": "acct:act-legacy",
                "person_record_id": "1a7e4000-0000-4000-8000-000000000022",
                "root_record_id": "1a7e4000-0000-4000-8000-000000000023",
                "created_at": "2026-01-01T00:00:00.000Z",
            })
            .to_string(),
        )
        .bind("2026-01-01T00:00:00.000Z")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        // project_control is private; reproduce its two writes verbatim: the
        // projection row plus the exactly-once application marker.
        sqlx::query(
            "INSERT INTO member_contexts(account_id,person_record_id,root_record_id,created_at)
             VALUES('acct:act-legacy','1a7e4000-0000-4000-8000-000000000022','1a7e4000-0000-4000-8000-000000000023','2026-01-01T00:00:00.000Z')",
        )
        .execute(db.write_pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO control_event_applications(event_id,event_seq,applied_at) VALUES(?,?,?)",
        )
        .bind("act-rebuild-legacy-control")
        .bind(legacy_control_seq)
        .bind("2026-01-01T00:00:00.000Z")
        .execute(db.write_pool())
        .await
        .unwrap();

        // Rebuild the content log through the projector path and compare
        // every row's act, in seq order.
        let live_content: Vec<(i64, Option<i64>)> =
            sqlx::query_as("SELECT seq, act FROM content_events ORDER BY seq")
                .fetch_all(db.write_pool())
                .await
                .unwrap();
        assert!(
            live_content.iter().any(|(_, act)| act.is_none()),
            "the live log holds a legacy NULL-act row"
        );
        let rebuilt = crate::db::open_database(":memory:").await.unwrap();
        crate::db::apply_schema(&rebuilt).await.unwrap();
        {
            let mut conn = rebuilt.write_pool().acquire().await.unwrap();
            let events = crate::query::events::log_prefix(&db, i64::MAX)
                .await
                .unwrap();
            crate::projector::replay_with_blob_placeholders(&mut conn, &events)
                .await
                .unwrap();
        }
        let rebuilt_content: Vec<(i64, Option<i64>)> =
            sqlx::query_as("SELECT seq, act FROM content_events ORDER BY seq")
                .fetch_all(rebuilt.write_pool())
                .await
                .unwrap();
        assert_eq!(
            rebuilt_content, live_content,
            "rebuilt content log must carry the exact source acts"
        );

        // Rebuild the control log through replay_control the same way.
        let live_control: Vec<(i64, Option<i64>)> =
            sqlx::query_as("SELECT seq, act FROM control_events ORDER BY seq")
                .fetch_all(db.write_pool())
                .await
                .unwrap();
        let rebuilt_control_db = crate::db::open_database(":memory:").await.unwrap();
        crate::db::apply_schema(&rebuilt_control_db).await.unwrap();
        {
            let mut live_conn = db.write_pool().acquire().await.unwrap();
            let events = crate::control::read_all_control_events(&mut live_conn)
                .await
                .unwrap();
            drop(live_conn);
            let mut conn = rebuilt_control_db.write_pool().acquire().await.unwrap();
            // Inert record identities satisfy the member_contexts and
            // instruction-binding projection FKs, exactly as
            // rebuild_and_diff_control does.
            let mut record_ids = std::collections::BTreeSet::new();
            for event in &events {
                let payload: serde_json::Value = serde_json::from_str(&event.payload).unwrap();
                for key in [
                    "person_record_id",
                    "root_record_id",
                    "source_record_id",
                    "artifact_id",
                ] {
                    if let Some(id) = payload.get(key).and_then(serde_json::Value::as_str) {
                        record_ids.insert(id.to_string());
                    }
                }
            }
            for record_id in record_ids {
                sqlx::query("INSERT INTO records(id,type) VALUES(?,'Entity')")
                    .bind(record_id)
                    .execute(&mut *conn)
                    .await
                    .unwrap();
            }
            crate::control::replay_control(&mut conn, &events)
                .await
                .unwrap();
        }
        let rebuilt_control: Vec<(i64, Option<i64>)> =
            sqlx::query_as("SELECT seq, act FROM control_events ORDER BY seq")
                .fetch_all(rebuilt_control_db.write_pool())
                .await
                .unwrap();
        assert_eq!(
            rebuilt_control, live_control,
            "rebuilt control log must carry the exact source acts"
        );

        // Projections still agree: preserving acts changed the logs, not the fold.
        assert!(
            crate::conformance::rebuild_and_diff(&db)
                .await
                .unwrap()
                .equal
        );
        assert!(
            crate::conformance::rebuild_and_diff_control(&db)
                .await
                .unwrap()
                .equal
        );

        rebuilt.close().await;
        rebuilt_control_db.close().await;
        db.close().await;
    }
}
