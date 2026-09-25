//! Receiver-side destination-schema pinning and immutable ingest seam.
//!
//! Slice R1 of cb551d7. This is deliberately **not** a complete apply: it
//! validates an authority whole-act cut against the live local schema and
//! writes its rows in one deferred-foreign-key transaction, but it never
//! projects, never advances `act_state`/`act_cutover`, and never performs
//! frontier, cutover or generation promotion. Those belong to R2.
//!
//! The seam is destination-schema-pinned, not authority-trusted. Before the
//! first mutation it pins every act section and companion to the live
//! destination column list and declared primary key ([`validate_destination_section`]),
//! so a tampered cut cannot name a column the destination does not have. It
//! then refuses a deferred section rather than silently dropping canonical
//! rows, and only then ingests through the shared insert-or-verify primitive
//! with one conflict mode per table class:
//!
//! * act-stamped canonical logs use [`ConflictMode::ActLogRefuseExisting`] —
//!   every incoming primary key must be absent;
//! * immutable canonical companions use
//!   [`ConflictMode::ImmutableAllowIdentical`] — an exact retry is a no-op and
//!   any divergence refuses.
//!
//! Everything happens inside one write transaction with
//! `PRAGMA defer_foreign_keys = ON`, so an out-of-order child-before-parent
//! batch is admitted and a dangling reference fails atomically at commit.
//! Validation, conflict, binding, foreign-key and commit failures all leave
//! the destination unchanged.

#![allow(dead_code)] // v1 receiver seam; the R2 transport/materialiser wires it.

use crate::db::Db;
use crate::error::{Error, Result};
use crate::interchange::{
    ingest_section_rows, validate_destination_section, validate_section_shape, ConflictMode,
    Section,
};
use crate::standby::act_cut::AuthorityActCut;

/// Act-stamped tables the all-section receiver deliberately does not ingest
/// generically in R1.
///
/// `relationship_events` has a domain-specific preserved-act replay seam
/// (assertion heads, endpoint activity and the relationship federation
/// companions) whose application order this generic row writer must not guess.
/// Until R2 owns that seam, [`ingest_sections_atomically`] refuses any cut
/// carrying non-empty `relationship_events` rows rather than generically
/// inserting them and silently skipping the projection work. The table-level
/// primitives remain directly testable.
pub(crate) const RECEIVER_DEFERRED_ACT_TABLES: [&str; 1] = ["relationship_events"];

/// Row counts for one receiver ingest. A deliberately incomplete R1 apply
/// reports what it wrote and does not claim to have applied an act.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ReceiverIngestOutcome {
    pub(crate) inserted_rows: usize,
    pub(crate) identical_rows: usize,
    pub(crate) act_sections: usize,
    pub(crate) companion_sections: usize,
}

/// Ingest one in-process authority whole-act cut into `db`.
///
/// The cut is structurally validated first, its lanes are pinned to the exact
/// act-stamped logs and immutable companions, and only then are its sections
/// pinned to `db`'s live schema and written atomically. The authority head is
/// never advanced.
pub(crate) async fn ingest_authority_act_cut(
    db: &Db,
    cut: &AuthorityActCut,
) -> Result<ReceiverIngestOutcome> {
    cut.validate()?;
    // `AuthorityActCut::validate` already checks this. Repeating the lane pin
    // here keeps the receiver route closed to projections or arbitrary tables
    // even if a future cut type, or a copied cut, reaches this seam without
    // that validation. The generic `ingest_sections_atomically` below stays
    // table-generic because it is a lower-level seam reached directly by
    // crate-internal callers; the canonical interchange importer does not use
    // it, reaching `ingest_section_rows` through `import_section` instead.
    let act_names = cut
        .sections()
        .iter()
        .map(|section| section.name.as_str())
        .collect::<Vec<_>>();
    let companion_names = cut
        .companions()
        .iter()
        .map(|section| section.name.as_str())
        .collect::<Vec<_>>();
    require_authority_lanes(&act_names, &companion_names)?;
    ingest_sections_atomically(db, cut.sections(), cut.companions()).await
}

/// Pin the receiver's two lanes to exactly [`crate::act::ACT_STAMPED_TABLES`]
/// and [`super::companion_closure::COMPANION_TABLES`], in order. A projection,
/// an operational table, a reordered lane or a missing/extra companion is
/// refused before the transaction opens.
///
/// This is the shared lane pin for every authority carrying route: R1's
/// all-section receiver and R2's content-only materialiser both call it, so a
/// second route cannot accept a lane the first refuses. It is deliberately
/// crate-visible rather than public: there is no unpinned public receiver entry
/// point.
pub(crate) fn require_authority_lanes(act_names: &[&str], companion_names: &[&str]) -> Result<()> {
    require(
        act_names == crate::act::ACT_STAMPED_TABLES.as_slice(),
        "receiver act lane must be exactly ACT_STAMPED_TABLES in order",
    )?;
    require(
        companion_names == super::companion_closure::COMPANION_TABLES.as_slice(),
        "receiver companion lane must be exactly COMPANION_TABLES in order",
    )
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(Error::engine(message))
    }
}

/// The one-transaction receiver seam for an already-selected set of act
/// sections and companions. Public to the crate so R2 (and R1 tests) can drive
/// exact sections without a live authority.
///
/// Phase 1 pins every section to the live destination schema, phase 2 refuses
/// a non-empty deferred section in either lane, and phase 3 writes act logs in
/// [`ConflictMode::ActLogRefuseExisting`] order and companions in
/// [`ConflictMode::ImmutableAllowIdentical`] order. A failure in any phase
/// rolls the whole transaction back.
pub(crate) async fn ingest_sections_atomically(
    db: &Db,
    acts: &[Section],
    companions: &[Section],
) -> Result<ReceiverIngestOutcome> {
    let mut tx = db.write_pool().begin().await?;
    sqlx::query("PRAGMA defer_foreign_keys = ON")
        .execute(&mut *tx)
        .await?;

    let outcome = ingest_sections_in_transaction(&mut tx, acts, companions).await;

    match outcome {
        Ok(report) => {
            // `Transaction::commit` consumes the guard, and a failed COMMIT
            // leaves it open so sqlx queues a rollback as it drops: a
            // deferred-foreign-key failure at commit is still atomic.
            tx.commit().await?;
            Ok(report)
        }
        Err(error) => {
            let _ = tx.rollback().await;
            Err(error)
        }
    }
}

/// The validation-and-ingest kernel on a caller-owned transaction. It never
/// begins, commits or rolls back: the caller owns atomicity, which is what lets
/// R2 run exact ingest, projection and companion re-derivation in one
/// transaction without a nested one.
///
/// Phase 1 pins every section to the live destination schema, phase 2 refuses a
/// non-empty deferred section in either lane, and phase 3 writes act logs in
/// [`ConflictMode::ActLogRefuseExisting`] order and companions in
/// [`ConflictMode::ImmutableAllowIdentical`] order. This lower seam stays
/// table-generic: the lane pin lives at the authority entry points
/// ([`ingest_authority_act_cut`] and R2's content materialiser).
pub(crate) async fn ingest_sections_in_transaction(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    acts: &[Section],
    companions: &[Section],
) -> Result<ReceiverIngestOutcome> {
    // Phase 1: validate every act section and companion against the live
    // destination schema before the first mutation. A tampered column list
    // or primary key anywhere in the batch refuses here, with nothing
    // written.
    for section in acts.iter().chain(companions.iter()) {
        validate_section_shape(section)?;
        validate_destination_section(tx, section).await?;
    }
    // Phase 2: refuse a deferred table rather than silently dropping
    // canonical act rows. This is the documented R1 contract around
    // `relationship_events`, and it applies to either lane so a deferred
    // section cannot slip in as a companion.
    for section in acts.iter().chain(companions.iter()) {
        if RECEIVER_DEFERRED_ACT_TABLES.contains(&section.name.as_str()) && !section.rows.is_empty()
        {
            return Err(Error::engine(format!(
                "receiver defers '{}' to its domain-specific preserved-act replay; refusing this cut",
                section.name
            )));
        }
    }
    // Phase 3: ingest. Act logs refuse any existing key; companions admit
    // an exactly identical retry and refuse divergence.
    let mut aggregate = ReceiverIngestOutcome::default();
    for section in acts {
        if RECEIVER_DEFERRED_ACT_TABLES.contains(&section.name.as_str()) {
            continue;
        }
        let section_outcome =
            ingest_section_rows(tx, section, ConflictMode::ActLogRefuseExisting).await?;
        aggregate.act_sections += 1;
        aggregate.inserted_rows += section_outcome.inserted;
        aggregate.identical_rows += section_outcome.identical;
    }
    for section in companions {
        if RECEIVER_DEFERRED_ACT_TABLES.contains(&section.name.as_str()) {
            continue;
        }
        let section_outcome =
            ingest_section_rows(tx, section, ConflictMode::ImmutableAllowIdentical).await?;
        aggregate.companion_sections += 1;
        aggregate.inserted_rows += section_outcome.inserted;
        aggregate.identical_rows += section_outcome.identical;
    }
    Ok(aggregate)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::interchange::{Cell, Column, REVISION, SECTION_FORMAT};

    async fn custom_table(db: &Db, table: &str) {
        sqlx::query(&format!(
            "CREATE TABLE {table} (id TEXT NOT NULL, value TEXT, PRIMARY KEY (id))"
        ))
        .execute(db.write_pool())
        .await
        .unwrap();
    }

    fn simple_section(table: &str, id: &str, value: Option<&str>) -> Section {
        section(
            table,
            &[("id", "TEXT"), ("value", "TEXT")],
            &["id"],
            vec![vec![
                Cell::Text(id.into()),
                match value {
                    Some(value) => Cell::Text(value.into()),
                    None => Cell::Null,
                },
            ]],
        )
    }

    fn section(
        table: &str,
        columns: &[(&str, &str)],
        primary_key: &[&str],
        rows: Vec<Vec<Cell>>,
    ) -> Section {
        Section {
            format: SECTION_FORMAT.into(),
            revision: REVISION,
            name: table.into(),
            columns: columns
                .iter()
                .map(|(name, declared_type)| Column {
                    name: (*name).into(),
                    declared_type: (*declared_type).into(),
                })
                .collect(),
            primary_key: primary_key.iter().map(|name| (*name).into()).collect(),
            rows,
        }
    }

    async fn count(db: &Db, table: &str) -> i64 {
        sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(db.pool())
            .await
            .unwrap()
    }

    async fn value_of(db: &Db, table: &str, id: &str) -> String {
        sqlx::query_scalar(&format!("SELECT value FROM {table} WHERE id = ?"))
            .bind(id)
            .fetch_one(db.pool())
            .await
            .unwrap()
    }

    async fn append_record(db: &Db, record_id: &str, name: &str) {
        crate::store::append(
            db,
            crate::store::AppendSpec {
                record_id: record_id.into(),
                event_type: "record.created".into(),
                payload: serde_json::json!({"type": "Document", "kind": "note", "name": name}),
                actor: None,
            },
        )
        .await
        .unwrap();
    }

    async fn schema_only_destination() -> (tempfile::TempDir, Db) {
        let temp = tempfile::tempdir().unwrap();
        let db = crate::open_database_at(&temp.path().join("destination.db"))
            .await
            .unwrap();
        crate::apply_schema(&db).await.unwrap();
        (temp, db)
    }

    /// A tampered column list fails phase 1, which validates every section
    /// against the live destination schema before phase 3 issues any insert.
    /// The assertion is the observable end state after the error: the earlier,
    /// valid section's row is absent. Whole-transaction rollback is what
    /// guarantees that, so this pins no-partial-mutation rather than
    /// out-of-band statement ordering.
    #[tokio::test]
    async fn tampered_column_list_refuses_and_leaves_no_partial_mutation() {
        let db = crate::create_database(":memory:").await.unwrap();
        custom_table(&db, "ordered_first").await;
        custom_table(&db, "tampered_columns").await;

        let valid = simple_section("ordered_first", "first", Some("would-be"));
        // The destination declares `value TEXT`; claiming `INTEGER` must refuse.
        let tampered = section(
            "tampered_columns",
            &[("id", "TEXT"), ("value", "INTEGER")],
            &["id"],
            vec![vec![Cell::Text("second".into()), Cell::Integer(1)]],
        );

        let error = ingest_sections_atomically(&db, &[valid, tampered], &[])
            .await
            .unwrap_err();
        assert!(error.to_string().contains("destination schema"), "{error}");
        assert_eq!(count(&db, "ordered_first").await, 0, "no partial mutation");
        db.close().await;
    }

    /// A primary key that is internally consistent but reversed from the
    /// destination fails phase 1. As above, the assertion pins the observable
    /// no-partial-mutation end state, not statement ordering.
    #[tokio::test]
    async fn tampered_primary_key_refuses_and_leaves_no_partial_mutation() {
        let db = crate::create_database(":memory:").await.unwrap();
        custom_table(&db, "ordered_first").await;
        sqlx::query(
            "CREATE TABLE paired (
                 a TEXT NOT NULL,
                 b TEXT NOT NULL,
                 value TEXT,
                 PRIMARY KEY (a, b)
             )",
        )
        .execute(db.write_pool())
        .await
        .unwrap();

        let valid = simple_section("ordered_first", "first", Some("would-be"));
        let tampered = section(
            "paired",
            &[("a", "TEXT"), ("b", "TEXT"), ("value", "TEXT")],
            &["b", "a"],
            vec![vec![
                Cell::Text("x".into()),
                Cell::Text("y".into()),
                Cell::Text("z".into()),
            ]],
        );

        let error = ingest_sections_atomically(&db, &[valid, tampered], &[])
            .await
            .unwrap_err();
        assert!(error.to_string().contains("primary key"), "{error}");
        assert_eq!(count(&db, "ordered_first").await, 0, "no partial mutation");
        db.close().await;
    }

    /// Act logs refuse an existing key whether the existing row is identical
    /// (an overlap) or divergent, and the failure leaves the row untouched.
    #[tokio::test]
    async fn act_log_refuse_existing_refuses_overlap_and_divergence_with_rollback() {
        let db = crate::create_database(":memory:").await.unwrap();
        custom_table(&db, "act_log").await;
        sqlx::query("INSERT INTO act_log (id, value) VALUES ('k', 'original')")
            .execute(db.write_pool())
            .await
            .unwrap();

        let identical = simple_section("act_log", "k", Some("original"));
        let error = ingest_sections_atomically(&db, &[identical], &[])
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("refuses an existing primary key"),
            "{error}"
        );

        let divergent = simple_section("act_log", "k", Some("changed"));
        let error = ingest_sections_atomically(&db, &[divergent], &[])
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("refuses an existing primary key"),
            "{error}"
        );

        assert_eq!(value_of(&db, "act_log", "k").await, "original");
        assert_eq!(count(&db, "act_log").await, 1);
        db.close().await;
    }

    /// An exactly identical companion retry is an idempotent no-op; a changed
    /// value or a different SQLite storage class refuses and never updates.
    #[tokio::test]
    async fn immutable_allow_identical_accepts_retry_and_refuses_divergence() {
        let db = crate::create_database(":memory:").await.unwrap();
        custom_table(&db, "companion").await;

        let original = simple_section("companion", "k", Some("original"));
        let outcome = ingest_sections_atomically(&db, &[], std::slice::from_ref(&original))
            .await
            .unwrap();
        assert_eq!((outcome.inserted_rows, outcome.identical_rows), (1, 0));

        let retry = ingest_sections_atomically(&db, &[], &[original])
            .await
            .unwrap();
        assert_eq!(
            (retry.inserted_rows, retry.identical_rows),
            (0, 1),
            "an exact retry must be an idempotent no-op"
        );
        assert_eq!(count(&db, "companion").await, 1);
        assert_eq!(value_of(&db, "companion", "k").await, "original");

        let divergent = simple_section("companion", "k", Some("changed"));
        let error = ingest_sections_atomically(&db, &[], &[divergent])
            .await
            .unwrap_err();
        assert!(error.to_string().contains("diverged"), "{error}");
        assert_eq!(value_of(&db, "companion", "k").await, "original");

        // The same characters as TEXT versus an INTEGER is a storage-class
        // difference, so the retry refuses rather than coercing to equal.
        let numeric_text = simple_section("companion", "k2", Some("1"));
        ingest_sections_atomically(&db, &[], &[numeric_text])
            .await
            .unwrap();
        let numeric_integer = section(
            "companion",
            &[("id", "TEXT"), ("value", "TEXT")],
            &["id"],
            vec![vec![Cell::Text("k2".into()), Cell::Integer(1)]],
        );
        let error = ingest_sections_atomically(&db, &[], &[numeric_integer])
            .await
            .unwrap_err();
        assert!(error.to_string().contains("diverged"), "{error}");
        assert_eq!(value_of(&db, "companion", "k2").await, "1");
        db.close().await;
    }

    /// A conflict in a later section rolls back the earlier section's row that
    /// was already inserted inside the same transaction.
    #[tokio::test]
    async fn multi_section_conflict_rolls_back_the_earlier_insert() {
        let db = crate::create_database(":memory:").await.unwrap();
        custom_table(&db, "ordered_a").await;
        custom_table(&db, "ordered_b").await;
        sqlx::query("INSERT INTO ordered_b (id, value) VALUES ('existing', 'original')")
            .execute(db.write_pool())
            .await
            .unwrap();

        let first = simple_section("ordered_a", "new", Some("a"));
        let conflict = simple_section("ordered_b", "existing", Some("original"));
        let error = ingest_sections_atomically(&db, &[first, conflict], &[])
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("refuses an existing primary key"),
            "{error}"
        );
        assert_eq!(
            count(&db, "ordered_a").await,
            0,
            "the earlier insert must roll back"
        );
        assert_eq!(count(&db, "ordered_b").await, 1);
        db.close().await;
    }

    /// `defer_foreign_keys = ON` admits a child-before-parent batch, while a
    /// dangling child reference fails atomically at commit.
    #[tokio::test]
    async fn deferred_foreign_key_child_before_parent_commits_and_dangling_child_fails_atomically()
    {
        let db = crate::create_database(":memory:").await.unwrap();
        sqlx::query("CREATE TABLE fk_parent (id TEXT NOT NULL, PRIMARY KEY (id))")
            .execute(db.write_pool())
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE fk_child (
                 id TEXT NOT NULL,
                 parent_id TEXT NOT NULL REFERENCES fk_parent(id),
                 PRIMARY KEY (id)
             )",
        )
        .execute(db.write_pool())
        .await
        .unwrap();

        let child = section(
            "fk_child",
            &[("id", "TEXT"), ("parent_id", "TEXT")],
            &["id"],
            vec![vec![Cell::Text("c1".into()), Cell::Text("p1".into())]],
        );
        let parent = section(
            "fk_parent",
            &[("id", "TEXT")],
            &["id"],
            vec![vec![Cell::Text("p1".into())]],
        );
        ingest_sections_atomically(&db, &[child, parent], &[])
            .await
            .unwrap();
        assert_eq!(count(&db, "fk_child").await, 1);
        assert_eq!(count(&db, "fk_parent").await, 1);

        let dangling = section(
            "fk_child",
            &[("id", "TEXT"), ("parent_id", "TEXT")],
            &["id"],
            vec![vec![Cell::Text("c2".into()), Cell::Text("missing".into())]],
        );
        let error = ingest_sections_atomically(&db, &[dangling], &[])
            .await
            .unwrap_err();
        assert!(
            error.to_string().to_lowercase().contains("foreign key"),
            "{error}"
        );
        assert_eq!(
            count(&db, "fk_child").await,
            1,
            "the dangling child must not commit"
        );
        db.close().await;
    }

    /// The deferred-table inventory is exactly `relationship_events`, and it
    /// is one of the classified act-stamped logs.
    #[test]
    fn relationship_events_is_the_only_deferred_act_table() {
        assert_eq!(RECEIVER_DEFERRED_ACT_TABLES, ["relationship_events"]);
        for table in RECEIVER_DEFERRED_ACT_TABLES {
            assert!(
                crate::act::ACT_STAMPED_TABLES.contains(&table),
                "deferred table {table} is not an act-stamped log"
            );
        }
    }

    /// A cut carrying non-empty `relationship_events` refuses before any
    /// mutation rather than generically inserting rows into its domain, and
    /// the guard scans both the act and companion lanes.
    #[tokio::test]
    async fn non_empty_relationship_events_refuses_in_either_lane() {
        let source = crate::create_database(":memory:").await.unwrap();
        let head = super::super::authority_probe::read_authority_act_head(&source)
            .await
            .unwrap()
            .head_act;
        let cut = super::super::act_cut::read_authority_act_cut(&source, head, head)
            .await
            .unwrap();

        let mut relationship = cut.section("relationship_events").unwrap().clone();
        assert!(
            relationship.rows.is_empty(),
            "fixture must have an empty relationship log"
        );
        let mut row = vec![Cell::Null; relationship.columns.len()];
        let primary_key_index = relationship
            .columns
            .iter()
            .position(|column| column.name == relationship.primary_key[0])
            .unwrap();
        row[primary_key_index] = Cell::Text("refused".into());
        relationship.rows.push(row);

        for companion_lane in [false, true] {
            let (_temp, destination) = schema_only_destination().await;
            let error = if companion_lane {
                ingest_sections_atomically(&destination, &[], std::slice::from_ref(&relationship))
                    .await
            } else {
                ingest_sections_atomically(&destination, std::slice::from_ref(&relationship), &[])
                    .await
            }
            .unwrap_err();
            assert!(
                error.to_string().contains("relationship_events"),
                "companion_lane={companion_lane}: {error}"
            );
            assert_eq!(count(&destination, "relationship_events").await, 0);
            destination.close().await;
        }
        source.close().await;
    }

    /// The receiver lane pin is exactly `ACT_STAMPED_TABLES` and
    /// `COMPANION_TABLES`, in order: a projection, a missing or extra table,
    /// or a reordering is refused.
    #[test]
    fn receiver_lanes_refuse_projections_and_reordering() {
        let acts = crate::act::ACT_STAMPED_TABLES.to_vec();
        let companions = super::super::companion_closure::COMPANION_TABLES.to_vec();
        require_authority_lanes(&acts, &companions).unwrap();

        let mut with_projection = acts.clone();
        with_projection.push("records");
        assert!(require_authority_lanes(&with_projection, &companions).is_err());

        let mut missing_act = acts.clone();
        missing_act.pop();
        assert!(require_authority_lanes(&missing_act, &companions).is_err());

        let reordered = acts.iter().rev().copied().collect::<Vec<_>>();
        assert!(require_authority_lanes(&reordered, &companions).is_err());

        assert!(require_authority_lanes(&acts, &["records"]).is_err());

        let mut missing_companion = companions.clone();
        missing_companion.pop();
        assert!(require_authority_lanes(&acts, &missing_companion).is_err());
    }

    /// The lower atomic seam stays table-generic because interchange import
    /// uses it, so the receiver lane pin is what keeps a projection out of the
    /// authority route. This bypass regression proves the generic seam accepts
    /// the table while the pin refuses the lane.
    #[tokio::test]
    async fn authority_lane_pin_refuses_a_projection_the_generic_seam_would_accept() {
        let db = crate::create_database(":memory:").await.unwrap();
        custom_table(&db, "projection_like").await;
        let projection = simple_section("projection_like", "p", Some("v"));
        ingest_sections_atomically(&db, &[projection], &[])
            .await
            .unwrap();
        assert_eq!(count(&db, "projection_like").await, 1);
        assert!(require_authority_lanes(&["projection_like"], &[]).is_err());
        db.close().await;
    }

    /// A real authority cut ingests into a schema-only destination, and the
    /// deliberately incomplete R1 apply leaves the authority head untouched.
    #[tokio::test]
    async fn real_authority_act_cut_ingests_without_touching_the_authority_head() {
        let source = crate::create_database(":memory:").await.unwrap();
        let base = super::super::authority_probe::read_authority_act_head(&source)
            .await
            .unwrap()
            .head_act;
        append_record(
            &source,
            "1a7e4000-0000-4000-8000-0000000000f1",
            "receiver apply",
        )
        .await;
        let head = super::super::authority_probe::read_authority_act_head(&source)
            .await
            .unwrap()
            .head_act;
        assert_eq!(head, base + 1);
        let cut = super::super::act_cut::read_authority_act_cut(&source, base, head)
            .await
            .unwrap();

        let (_temp, destination) = schema_only_destination().await;
        let outcome = ingest_authority_act_cut(&destination, &cut).await.unwrap();
        let expected_rows: usize = cut
            .sections()
            .iter()
            .chain(cut.companions())
            .filter(|section| !RECEIVER_DEFERRED_ACT_TABLES.contains(&section.name.as_str()))
            .map(|section| section.rows.len())
            .sum();
        assert_eq!(outcome.inserted_rows, expected_rows);
        assert_eq!(outcome.identical_rows, 0);
        let copied: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(destination.pool())
            .await
            .unwrap();
        assert_eq!(copied, 1, "the one appended content event is copied");
        let next_act: i64 = sqlx::query_scalar("SELECT next_act FROM act_state")
            .fetch_one(destination.pool())
            .await
            .unwrap();
        assert_eq!(next_act, 0, "R1 must not advance the authority head");
        destination.close().await;
        source.close().await;
    }
}
