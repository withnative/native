//! Real rehome batch fixtures (Foci v2 G6 increment 1; design note 681a449
//! §8): 56 to 59 for the batch contract, 70 to 73 for the visibility-safe
//! counts and 81 for the id-space overlap, plus smoke tests for the driver
//! (its concurrency and restart proofs are increment 2). Fixture 55 is the
//! re-pointing of G7's recovery fixtures in `slots_recovery_tests`.
//!
//! "Hidden" means the principal has no View on the rows' home. Bulk rows are
//! inserted by direct SQL, as a raw importer would leave them.
use super::slots_batch::{
    rehome_batch, rehome_batch_in, rehome_batch_with, rehome_until_ready, rehome_until_ready_with,
    BatchHooks, BatchReceipt, BatchRefusal, DriveStop, NoBatchHooks, MAX_BATCH,
};
use super::slots_eval::CAPABILITY_EVALUATIONS;
use super::slots_eval::{SlotStatus, UnusableReason as Why};
use super::slots_ops::HomeProvisioner;
use super::slots_ops_tests::{Mode, TestProvisioner};
use super::slots_recovery::{
    kernel_id_space_overlap, visible_foreign_on, ForeignScope, VisibleForeign, CAP,
};
use super::slots_recovery_tests::{home_refusal, receipt, sorted, FailAfterMoves, Six};
use super::slots_tests::World;
use super::*;
use crate::v2_standard::foci::FOCUS_FAMILY;

/// Principal with `Six` in H1, then two replaces: H1 and H2 are earlier
/// homes and H3 is current.
struct Chain {
    p: String,
    six: Six,
    h2: String,
    h3: String,
}

impl World {
    /// `n` foreign (admin-owned) Foci rows in `home`, ids `{prefix}-{i:05}`.
    async fn bt_foreign(&self, home: &str, prefix: &str, n: i64) {
        sqlx::query(
            "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ?1) \
             INSERT INTO kernel_records (id, home_id, owner_id, primary_type, kind, accession, \
             pin_family, pin_version, pin_digest, created_seq, created_at) \
             SELECT ?2 || printf('-%05d', i), ?3, ?4, 'doc', 'focus', ?2 || printf('-acc-%05d', i), \
             ?5, 1, 'digest', 1, 'now' FROM n",
        )
        .bind(n)
        .bind(prefix)
        .bind(home)
        .bind(&self.admin)
        .bind(FOCUS_FAMILY)
        .execute(self.db.write_pool())
        .await
        .unwrap();
    }
    async fn bt_chain(&self, name: &str) -> Chain {
        let p = self.rc_principal(name).await;
        let six = self.rc_six(&p).await;
        let h2 = self.rc_widen_and_replace(&p, &six.home).await;
        let h3 = self.rc_widen_and_replace(&p, &h2).await;
        Chain { p, six, h2, h3 }
    }
    /// The principal loses View on foreign rows in `home` but stays its owner.
    async fn bt_owner_floor_only(&self, home: &str) {
        self.sql(
            "UPDATE kernel_policy_entries SET subject_id=? WHERE root_id=?",
            &[&self.admin, home],
        )
        .await;
    }
    async fn bt_visible(&self, p: &str, scope: ForeignScope, limit: i64) -> VisibleForeign {
        let mut tx = self.db.write_pool().begin().await.unwrap();
        let seen = visible_foreign_on(&mut tx, p, scope, limit).await.unwrap();
        tx.rollback().await.unwrap();
        seen
    }
    /// The naive per-row oracle: every foreign Foci row id in the scope's
    /// homes that is not a home id, kept if the evaluator gives View.
    async fn bt_oracle(&self, p: &str, homes: &[String]) -> Vec<String> {
        let mut tx = self.db.write_pool().begin().await.unwrap();
        let mut seen = Vec::new();
        for home in homes {
            let ids: Vec<String> = sqlx::query_scalar(
                "SELECT r.id FROM kernel_records r WHERE r.home_id=? \
                 AND (r.owner_id IS NULL OR r.owner_id<>?) AND r.pin_family=? \
                 AND NOT EXISTS (SELECT 1 FROM kernel_roots k WHERE k.root_id=r.id)",
            )
            .bind(home)
            .bind(p)
            .bind(FOCUS_FAMILY)
            .fetch_all(&mut *tx)
            .await
            .unwrap();
            for id in ids {
                if super::slots_eval::capability_on(&mut tx, p, &id)
                    .await
                    .unwrap()
                    .allows(Capability::View)
                {
                    seen.push(id);
                }
            }
        }
        tx.rollback().await.unwrap();
        sorted(seen)
    }
}

/// Fails admissibility of the `nth` moved record by handing it to another
/// owner after the moves; or, with `after_select`, makes the `nth` selected
/// source ineligible before the checks.
struct FlipOwner {
    nth: usize,
    owner: String,
    before_moves: bool,
}

impl FlipOwner {
    async fn flip(&self, tx: &mut Transaction<'static, Sqlite>, ids: &[String]) -> Result<()> {
        sqlx::query("UPDATE kernel_records SET owner_id=? WHERE id=?")
            .bind(&self.owner)
            .bind(&ids[self.nth])
            .execute(&mut **tx)
            .await?;
        Ok(())
    }
}

impl BatchHooks for FlipOwner {
    async fn after_select(
        &self,
        tx: &mut Transaction<'static, Sqlite>,
        sources: &[String],
    ) -> Result<()> {
        if self.before_moves {
            self.flip(tx, sources).await?;
        }
        Ok(())
    }
    async fn after_moves(
        &self,
        tx: &mut Transaction<'static, Sqlite>,
        moved: &[String],
    ) -> Result<()> {
        if !self.before_moves {
            self.flip(tx, moved).await?;
        }
        Ok(())
    }
}

fn message(error: &Error) -> String {
    match error {
        Error::Engine(message) => message.clone(),
        other => format!("{other:?}"),
    }
}

// -- fixture 56 -------------------------------------------------------------

/// Fixture 56: size 0, size above `MAX_BATCH` and a malformed target are
/// errors with zero writes. Size `MAX_BATCH` works, and `moved <= size`.
#[tokio::test]
async fn batch_size_and_target_are_validated() {
    let w = World::fresh().await;
    let p = w.other.clone();
    let six = w.rc_six(&p).await;
    let h2 = w.rc_widen_and_replace(&p, &six.home).await;

    let before = w.state().await;
    for (expected, size) in [
        (h2.as_str(), 0),
        (h2.as_str(), MAX_BATCH + 1),
        ("x", 3),
        ("", 3),
    ] {
        assert!(rehome_batch(&w.db, &p, expected, size).await.is_err());
        assert_eq!(before, w.state().await);
    }
    let batch = rehome_batch(&w.db, &p, &h2, MAX_BATCH)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(batch, receipt(&h2, 6, 0, 0));
    assert!(batch.moved <= MAX_BATCH);
}

// -- fixture 57 -------------------------------------------------------------

/// Fixture 57: `remaining` is exact below the cap while the foreign count
/// saturates at it, each with its own flag.
#[tokio::test]
async fn counts_are_exact_up_to_the_cap_then_saturate() {
    let w = World::fresh().await;
    let p = w.other.clone();
    let six = w.rc_six(&p).await;
    let extra = w.focus_in(&p, &six.home).await;
    assert_eq!(w.rc_homes(&[extra]).await, vec![six.home.clone()]);
    w.bt_foreign(&six.home, "f", CAP + 1).await;
    let h2 = w.rc_widen_and_replace(&p, &six.home).await;

    assert_eq!(
        w.rc_batch(&p, &h2, 3).await,
        BatchReceipt {
            target_id: h2.clone(),
            moved: 3,
            remaining: 4,
            remaining_capped: false,
            foreign_skipped: CAP,
            foreign_capped: true,
            complete: false,
        }
    );
}

// -- fixtures 58 and 59 -------------------------------------------------------

/// Fixture 58: a selected source that stops being eligible fails the whole
/// batch and the error names it. Nothing is written, the first record is not
/// moved, and the next batch succeeds.
#[tokio::test]
async fn an_ineligible_selected_source_fails_the_whole_batch_naming_it() {
    let w = World::fresh().await;
    let p = w.other.clone();
    let six = w.rc_six(&p).await;
    let h2 = w.rc_widen_and_replace(&p, &six.home).await;
    let order = w.rc_outstanding(&p, 100).await;

    let before = w.state().await;
    let hook = FlipOwner {
        nth: 1,
        owner: w.admin.clone(),
        before_moves: true,
    };
    let failed = rehome_batch_with(&w.db, &hook, &p, &h2, 3)
        .await
        .unwrap_err();
    assert!(
        message(&failed).contains(&order[1]),
        "the error names the record: {failed:?}"
    );
    assert_eq!(before, w.state().await);
    assert_eq!(w.rec_home_of(&order[0]).await, six.home);
    assert_eq!(w.rc_batch(&p, &h2, 3).await, receipt(&h2, 3, 3, 0));
}

/// Fixture 59: a moved record that fails the ordinary predicate rolls the
/// whole batch back, and the error names it.
#[tokio::test]
async fn a_moved_record_that_fails_the_ordinary_predicate_rolls_back_whole() {
    let w = World::fresh().await;
    let p = w.other.clone();
    let six = w.rc_six(&p).await;
    let h2 = w.rc_widen_and_replace(&p, &six.home).await;
    let order = w.rc_outstanding(&p, 100).await;

    let before = w.state().await;
    let hook = FlipOwner {
        nth: 2,
        owner: w.admin.clone(),
        before_moves: false,
    };
    let failed = rehome_batch_with(&w.db, &hook, &p, &h2, 3)
        .await
        .unwrap_err();
    assert!(message(&failed).contains(&order[2]), "{failed:?}");
    assert_eq!(before, w.state().await);
    let failed = rehome_batch_with(&w.db, &FailAfterMoves, &p, &h2, 3)
        .await
        .unwrap_err();
    assert!(message(&failed).contains("injected"));
    assert_eq!(before, w.state().await);
    assert_eq!(w.rc_batch(&p, &h2, 6).await, receipt(&h2, 6, 0, 0));
}

// -- fixture 70 -------------------------------------------------------------

/// Fixture 70: 1,500 foreign rows in a home the principal cannot View change
/// nothing: the batch receipt and the counts equal the state without them.
#[tokio::test]
async fn hidden_only_overflow_is_not_counted_or_flagged() {
    let w = World::fresh().await;
    let mut seen = Vec::new();
    for (name, hidden_rows) in [("with", 1_500), ("without", 0)] {
        let c = w.bt_chain(name).await;
        w.rc_hand_home_to(&c.six.home, &w.admin).await;
        w.rc_hand_home_to(&c.h2, &w.admin).await;
        if hidden_rows > 0 {
            w.bt_foreign(&c.six.home, "h", hidden_rows).await;
        }
        let earlier = w.bt_visible(&c.p, ForeignScope::Earlier, 50).await;
        assert_eq!(earlier, VisibleForeign::default());
        let batch = w.rc_batch(&c.p, &c.h3, 3).await;
        assert_eq!((batch.foreign_skipped, batch.foreign_capped), (0, false));
        seen.push(BatchReceipt {
            target_id: String::new(),
            ..batch
        });
    }
    assert_eq!(seen[0], seen[1]);
}

// -- fixture 71 -------------------------------------------------------------

/// Fixture 71: a visible row after a hidden prefix is counted. A cap on raw
/// candidates would have returned 0.
#[tokio::test]
async fn visible_rows_after_a_hidden_prefix_are_counted() {
    let w = World::fresh().await;
    let c = w.bt_chain("prefix").await;
    w.bt_foreign(&c.six.home, "a", 1_500).await;
    w.bt_foreign(&c.h2, "z", 3).await;
    w.rc_hand_home_to(&c.six.home, &w.admin).await;

    let seen = w.bt_visible(&c.p, ForeignScope::Earlier, 50).await;
    assert_eq!(seen.total, 3);
    assert!(!seen.capped);
    assert_eq!(
        seen.entries,
        vec!["z-00001".to_string(), "z-00002".into(), "z-00003".into()]
    );
}

// -- fixture 72 -------------------------------------------------------------

/// Fixture 72: exact at `CAP - 1` and `CAP`, saturated and flagged at
/// `CAP + 1`, and byte-identical with 1,200 hidden rows added. One visible
/// dataset is retained while only hidden rows come and go, and entries are
/// read with a positive limit so the comparison covers non-empty entries.
#[tokio::test]
async fn the_cap_is_exact_up_to_and_including_cap() {
    let w = World::fresh().await;
    for (n, capped) in [(CAP - 1, false), (CAP, false), (CAP + 1, true)] {
        let c = w.bt_chain(&format!("cap-{n}")).await;
        w.bt_foreign(&c.h2, &format!("v{n}"), n).await;
        let plain = w.bt_visible(&c.p, ForeignScope::Earlier, 50).await;
        assert_eq!((plain.total, plain.capped), (n.min(CAP), capped));
        assert_eq!(plain.entries.len(), 50, "entries are non-empty at {n}");
        w.bt_foreign(&c.six.home, &format!("h{n}"), 1_200).await;
        w.rc_hand_home_to(&c.six.home, &w.admin).await;
        let hidden = w.bt_visible(&c.p, ForeignScope::Earlier, 50).await;
        assert_eq!((hidden.total, hidden.capped), (n.min(CAP), capped));
        assert_eq!(plain, hidden, "hidden rows change nothing at {n}");
    }
}

// -- fixture 73 -------------------------------------------------------------

/// Fixture 73: for varied mixes of viewable, hidden and owner-floor-only
/// homes, current and earlier, the counts and entries equal the per-row
/// oracle, and capability evaluations stay within the number of homes.
#[tokio::test]
async fn per_home_visibility_equals_the_per_row_oracle() {
    let w = World::fresh().await;
    let mut state = 7u64;
    let mut next = move |bound: u64| {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (state >> 33) % bound
    };
    for trial in 0..6 {
        let c = w.bt_chain(&format!("oracle-{trial}")).await;
        let homes = [c.six.home.clone(), c.h2.clone(), c.h3.clone()];
        for (i, home) in homes.iter().enumerate() {
            let rows = next(4) as i64;
            if rows > 0 {
                w.bt_foreign(home, &format!("t{trial}h{i}"), rows).await;
            }
            match next(3) {
                0 => {}
                1 => w.rc_hand_home_to(home, &w.admin).await,
                _ => w.bt_owner_floor_only(home).await,
            }
        }
        for (scope, scope_homes) in [
            (ForeignScope::Earlier, &homes[..2]),
            (ForeignScope::Current, &homes[2..]),
        ] {
            let oracle = w.bt_oracle(&c.p, scope_homes).await;
            CAPABILITY_EVALUATIONS.with(|count| count.set(0));
            let seen = w.bt_visible(&c.p, scope, 100).await;
            let evaluations = CAPABILITY_EVALUATIONS.with(|count| count.get());
            assert_eq!(seen.entries, oracle, "trial {trial} {scope:?}");
            assert_eq!(seen.total, oracle.len() as i64);
            assert!(
                evaluations <= scope_homes.len(),
                "{evaluations} evaluations"
            );
        }
    }
}

// -- fixture 81 -------------------------------------------------------------

/// Fixture 81 (count and diagnostic halves): a foreign row whose id is also a
/// home id fails closed. The reviewer's counterexample: P is a home the
/// principal manages through the owner floor with an empty grant; a foreign
/// row with id P sits in hidden home H next to 1,200 ordinary hidden rows.
#[tokio::test]
async fn an_id_that_is_also_a_home_fails_closed() {
    let w = World::fresh().await;
    let c = w.bt_chain("overlap").await;
    // P: a child home the principal owns, its policy naming only the admin.
    let alias = create_home(&w.db, &c.h3, Some(&[(w.admin.as_str(), "manage")]), &c.p)
        .await
        .unwrap();
    w.bt_foreign(&c.six.home, "o", 1_200).await;
    w.rc_hand_home_to(&c.six.home, &w.admin).await;
    let clean = w.bt_visible(&c.p, ForeignScope::Earlier, 50).await;
    assert_eq!(clean, VisibleForeign::default());
    assert!(kernel_id_space_overlap(&w.db).await.unwrap().is_empty());

    // The alias row, planted by direct SQL because admission refuses it.
    let plant = |home: String| {
        let alias = alias.clone();
        let w = &w;
        async move {
            sqlx::query(
                "INSERT INTO kernel_records (id, home_id, owner_id, primary_type, kind, \
                 accession, pin_family, pin_version, pin_digest, created_seq, created_at) \
                 VALUES (?, ?, ?, 'doc', 'focus', 'alias-acc', ?, 1, 'digest', 1, 'now')",
            )
            .bind(&alias)
            .bind(home)
            .bind(&w.admin)
            .bind(FOCUS_FAMILY)
            .execute(w.db.write_pool())
            .await
            .unwrap();
        }
    };
    plant(c.six.home.clone()).await;
    assert_eq!(
        w.bt_visible(&c.p, ForeignScope::Earlier, 50).await,
        clean,
        "the alias is never the probe, so the hidden home stays hidden"
    );
    assert_eq!(
        kernel_id_space_overlap(&w.db).await.unwrap(),
        vec![alias.clone()]
    );
    w.sql("DELETE FROM kernel_records WHERE id=?", &[&alias])
        .await;

    // Variant: the alias sits in a home the principal can View.
    w.bt_foreign(&c.h2, "v", 2).await;
    plant(c.h2.clone()).await;
    let seen = w.bt_visible(&c.p, ForeignScope::Earlier, 50).await;
    assert_eq!(seen.total, 2);
    assert_eq!(seen.entries, vec!["v-00001".to_string(), "v-00002".into()]);
    assert!(!seen.entries.contains(&alias));
    w.sql("DELETE FROM kernel_records WHERE id=?", &[&alias])
        .await;

    // An owned outstanding row that is also a home id fails the batch whole,
    // naming it, whichever grants the alias home has.
    for grants in [
        &[(w.admin.as_str(), "manage")][..],
        &[(c.p.as_str(), "manage")],
    ] {
        let home = create_home(&w.db, &c.h3, Some(grants), &c.p).await.unwrap();
        sqlx::query(
            "INSERT INTO kernel_records (id, home_id, owner_id, primary_type, kind, \
             accession, pin_family, pin_version, pin_digest, created_seq, created_at) \
             VALUES (?, ?, ?, 'doc', 'focus', ?, ?, 1, 'digest', 1, 'now')",
        )
        .bind(&home)
        .bind(&c.h2)
        .bind(&c.p)
        .bind(format!("acc-{home}"))
        .bind(FOCUS_FAMILY)
        .execute(w.db.write_pool())
        .await
        .unwrap();
        assert!(w.rc_remaining(&c.p).await >= 7);
        let before = w.state().await;
        let failed = rehome_batch(&w.db, &c.p, &c.h3, 20).await.unwrap_err();
        assert!(message(&failed).contains(&home), "{failed:?}");
        assert_eq!(before, w.state().await);
        // The production rehome refuses it on its own, too.
        let mut tx = w.db.write_pool().begin().await.unwrap();
        let mut acts = crate::act::ActAllocation::new();
        assert!(
            rehome_record_in(&w.db, &mut tx, &mut acts, &c.p, &home, &c.h3)
                .await
                .is_err()
        );
        tx.rollback().await.unwrap();
        w.sql("DELETE FROM kernel_records WHERE id=?", &[&home])
            .await;
    }
    // With the aliases gone the six real sources remain and the batch moves them,
    // still skipping the two viewable foreign rows.
    assert_eq!(w.rc_batch(&c.p, &c.h3, 20).await, receipt(&c.h3, 6, 0, 2));
}

// -- the driver -----------------------------------------------------------------

/// The driver runs single batches to completion, keeps `expected_target`
/// fixed, and a `BatchLimit` call resumes with the same target. (Restart and
/// stall proofs are fixtures 63 and 77, increment 2.)
#[tokio::test]
async fn the_driver_completes_resumes_and_stops_on_a_refusal() {
    let w = World::fresh().await;
    let c = w.bt_chain("driver").await;

    let first = rehome_until_ready(&w.db, &c.p, &c.h3, 4, 1).await.unwrap();
    assert_eq!(first.stop, DriveStop::BatchLimit);
    assert_eq!((first.batches, first.moved_total), (1, 4));
    assert_eq!(first.last, Some(receipt(&c.h3, 4, 2, 0)));

    let second = rehome_until_ready(&w.db, &c.p, &c.h3, 4, 5).await.unwrap();
    assert_eq!(second.stop, DriveStop::Complete);
    assert_eq!((second.batches, second.moved_total), (1, 2));
    assert_eq!(second.last, Some(receipt(&c.h3, 2, 0, 0)));

    // Nothing outstanding: a first batch that moves nothing is `Complete`.
    let idle = rehome_until_ready_with(&w.db, &NoBatchHooks, &c.p, &c.h3, 4, 5)
        .await
        .unwrap();
    assert_eq!(idle.stop, DriveStop::Complete);
    assert_eq!((idle.batches, idle.moved_total), (1, 0));

    // A stale target stops the loop with the refusal; it is not updated.
    let stale = rehome_until_ready(&w.db, &c.p, &c.h2, 4, 5).await.unwrap();
    assert_eq!(
        stale.stop,
        DriveStop::Refused(BatchRefusal::GenerationChanged)
    );
    assert_eq!((stale.batches, stale.moved_total, stale.last), (0, 0, None));
    assert!(rehome_until_ready(&w.db, &c.p, &c.h3, 4, 0).await.is_err());
}

/// Fixture 63 (file): driver with batch size 2. One batch commits, the next
/// batch's transaction is dropped uncommitted mid-loop, the database is
/// closed and reopened, and a second invocation with a freshly observed
/// target completes. A replay variant gives equal tables.
#[tokio::test]
async fn the_driver_resumes_after_a_dropped_batch_and_reopen() {
    let mut w = World::fresh().await;
    let c = w.bt_chain("driver-crash").await;
    let slot = super::slots::HOME_FOCI_PRIVATE;

    let first = rehome_until_ready(&w.db, &c.p, &c.h3, 2, 1).await.unwrap();
    assert_eq!(first.stop, DriveStop::BatchLimit);
    assert_eq!((first.batches, first.moved_total), (1, 2));
    assert_eq!(first.last, Some(receipt(&c.h3, 2, 4, 0)));

    {
        let mut tx = begin_write(w.db.write_pool()).await.unwrap();
        let mut acts = crate::act::ActAllocation::new();
        let crashed = rehome_batch_in(&w.db, &mut tx, &mut acts, &NoBatchHooks, &c.p, &c.h3, 2)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(crashed.moved, 2);
        drop(tx);
    }
    let moved_events = w.rc_rehome_events().await;
    assert_eq!(moved_events, 2, "the dropped batch persisted nothing");

    w.reopen().await;
    let current = w.inspect(&c.p, slot).await.target_id.unwrap();
    assert_eq!(current, c.h3);
    let second = rehome_until_ready(&w.db, &c.p, &current, 2, 5)
        .await
        .unwrap();
    assert_eq!(second.stop, DriveStop::Complete);
    assert_eq!((second.batches, second.moved_total), (2, 4));
    assert_eq!(second.last, Some(receipt(&c.h3, 2, 0, 0)));
    assert_eq!(w.rc_rehome_events().await, 6);
    assert!(w.gate(&c.p, slot).await.is_ok());
    w.replay_equal().await;
}

/// Fixture 77 (initial-refusal half): driver and receipt shapes. `Complete`
/// on a clean run; `Refused(GenerationChanged)` when a replace landed between
/// calls (the stale target is not silently updated); `Refused(Home)` when a
/// widen landed between calls; `BatchLimit` with `max_batches = 1` followed
/// by a resuming call; a first batch with nothing outstanding (`Complete`
/// with `moved: 0`). Every `DriveReport` and `BatchReceipt` field is
/// asserted. Generation changes *during* one invocation are the next two
/// tests; the injected stall is the test after those.
#[tokio::test]
async fn the_driver_reports_complete_refusals_limits_and_idle() {
    let w = World::fresh().await;
    let slot = super::slots::HOME_FOCI_PRIVATE;

    let c = w.bt_chain("shapes-complete").await;
    let done = rehome_until_ready(&w.db, &c.p, &c.h3, 4, 5).await.unwrap();
    assert_eq!(done.stop, DriveStop::Complete);
    assert_eq!((done.batches, done.moved_total), (2, 6));
    assert_eq!(done.last, Some(receipt(&c.h3, 2, 0, 0)));
    let idle = rehome_until_ready(&w.db, &c.p, &c.h3, 4, 5).await.unwrap();
    assert_eq!(idle.stop, DriveStop::Complete);
    assert_eq!((idle.batches, idle.moved_total), (1, 0));
    assert_eq!(idle.last, Some(receipt(&c.h3, 0, 0, 0)));
    assert!(rehome_until_ready(&w.db, &c.p, &c.h3, 4, 0).await.is_err());

    let d = w.bt_chain("shapes-stale").await;
    let first = rehome_until_ready(&w.db, &d.p, &d.h3, 4, 1).await.unwrap();
    assert_eq!(first.stop, DriveStop::BatchLimit);
    assert_eq!((first.batches, first.moved_total), (1, 4));
    assert_eq!(first.last, Some(receipt(&d.h3, 4, 2, 0)));
    let h4 = w.rc_widen_and_replace(&d.p, &d.h3).await;
    let stale = rehome_until_ready(&w.db, &d.p, &d.h3, 4, 5).await.unwrap();
    assert_eq!(
        stale.stop,
        DriveStop::Refused(BatchRefusal::GenerationChanged)
    );
    assert_eq!((stale.batches, stale.moved_total, stale.last), (0, 0, None));
    let resumed = rehome_until_ready(&w.db, &d.p, &h4, 4, 5).await.unwrap();
    assert_eq!(resumed.stop, DriveStop::Complete);
    assert_eq!((resumed.batches, resumed.moved_total), (2, 6));
    assert_eq!(resumed.last, Some(receipt(&h4, 2, 0, 0)));

    let e = w.bt_chain("shapes-widen").await;
    w.widen(&e.h3, &e.p).await;
    let fenced = rehome_until_ready(&w.db, &e.p, &e.h3, 4, 5).await.unwrap();
    assert_eq!(
        fenced.stop,
        DriveStop::Refused(home_refusal(SlotStatus::Unusable, Some(Why::NotPrivate)))
    );
    assert_eq!(
        (fenced.batches, fenced.moved_total, fenced.last),
        (0, 0, None)
    );
    w.restore(&e.h3, &e.p).await;
    let recovered = rehome_until_ready(&w.db, &e.p, &e.h3, 4, 5).await.unwrap();
    assert_eq!(recovered.stop, DriveStop::Complete);
    assert_eq!((recovered.batches, recovered.moved_total), (2, 6));
    assert_eq!(recovered.last, Some(receipt(&e.h3, 2, 0, 0)));
    assert!(w.gate(&e.p, slot).await.is_ok());
}

// -- fixture 77: change within one invocation --------------------------------

// A generation change inside the batch's own transaction, composed from the
// same `_in` primitives `slots_ops::run` uses (policy append, provision,
// registration, rehome). A separate write would deadlock against the held
// writer lock, and anything committed after batch 1 races batch 2's begin
// with no FIFO order. The replacement commits atomically with batch 1, so
// batch 2 of the same invocation observes the new generation while batch 1's
// moves stay homed; batch 1's receipt still names its own target.
struct ReplaceMidLoop {
    db: crate::db::Db,
    admin: String,
    principal: String,
    expected: String,
    calls: std::sync::atomic::AtomicU32,
}

impl BatchHooks for ReplaceMidLoop {
    async fn after_moves(
        &self,
        tx: &mut Transaction<'static, Sqlite>,
        moved: &[String],
    ) -> Result<()> {
        if self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) > 0 {
            return Ok(());
        }
        let mut acts = crate::act::ActAllocation::new();
        crate::store::append_in(
            &self.db,
            tx,
            AppendSpec {
                record_id: self.expected.clone(),
                event_type: KERNEL_POLICY_REPLACED_EVENT.into(),
                payload: serde_json::json!({"entries": [
                    {"subject_id": &self.principal, "capability": "manage"},
                    {"subject_id": &self.admin, "capability": "view"},
                ]}),
                actor: Some(self.principal.clone()),
            },
            &mut acts,
        )
        .await?;
        let prov = TestProvisioner::new(&self.admin, Mode::Honest);
        let home = {
            let mut cx = super::slots_ops::SlotTxContext {
                db: &self.db,
                tx: &mut *tx,
                acts: &mut acts,
                principal: self.principal.as_str(),
            };
            match prov.provision_home_in(&mut cx).await? {
                super::slots_ops::ProvisionOutcome::Home(home) => home,
                super::slots_ops::ProvisionOutcome::Unavailable => {
                    return Err(Error::engine("mid-loop provisioner unavailable"));
                }
            }
        };
        super::slots::append_registration_in(
            &self.db,
            tx,
            &mut acts,
            &self.principal,
            super::slots::HOME_FOCI_PRIVATE,
            &home,
            Some(self.expected.as_str()),
            "test",
        )
        .await?;
        for id in moved {
            rehome_record_in(&self.db, tx, &mut acts, &self.principal, id, &home).await?;
        }
        Ok(())
    }
}

/// Fixture 77 (replace within one call): batch size 4, one invocation. Batch
/// 1 moves four sources; the hook widens H3, provisions and registers H4 and
/// re-homes the four into H4 inside batch 1's transaction. Batch 2 of the
/// same call holds `expected = H3` against current H4, so the driver stops
/// `Refused(GenerationChanged)` with batch 1's progress kept: four homed
/// records, eight rehome events, nothing rolled back.
#[tokio::test]
async fn the_driver_holds_its_target_when_a_replace_lands_mid_loop() {
    let w = World::fresh().await;
    let c = w.bt_chain("shapes-mid-replace").await;
    let hook = ReplaceMidLoop {
        db: w.db.clone(),
        admin: w.admin.clone(),
        principal: c.p.clone(),
        expected: c.h3.clone(),
        calls: std::sync::atomic::AtomicU32::new(0),
    };
    let report = rehome_until_ready_with(&w.db, &hook, &c.p, &c.h3, 4, 5)
        .await
        .unwrap();
    assert_eq!(
        report.stop,
        DriveStop::Refused(BatchRefusal::GenerationChanged)
    );
    assert_eq!((report.batches, report.moved_total), (1, 4));
    assert_eq!(report.last, Some(receipt(&c.h3, 4, 2, 0)));
    assert_eq!(hook.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    let h4 = w
        .inspect(&c.p, super::slots::HOME_FOCI_PRIVATE)
        .await
        .target_id
        .unwrap();
    assert_ne!(h4, c.h3);
    let mut homes = w.rc_homes(&c.six.all()).await;
    homes.sort();
    let mut want = vec![c.six.home.clone(), c.six.home.clone()];
    want.extend(vec![h4.clone(); 4]);
    want.sort();
    assert_eq!(homes, want);
    assert_eq!(w.rc_rehome_events().await, 8);
}

/// The analogous widen: the hook widens H3 inside batch 1's transaction via
/// the real policy append, so batch 2 of the same call meets a fenced home.
/// The driver stops with the exact `Home` refusal, batch 1's progress is
/// kept, and restoring the policy lets a new call finish the debt.
struct WidenMidLoop {
    db: crate::db::Db,
    admin: String,
    principal: String,
    home: String,
    calls: std::sync::atomic::AtomicU32,
}

impl BatchHooks for WidenMidLoop {
    async fn after_moves(
        &self,
        tx: &mut Transaction<'static, Sqlite>,
        _moved: &[String],
    ) -> Result<()> {
        if self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) > 0 {
            return Ok(());
        }
        let mut acts = crate::act::ActAllocation::new();
        crate::store::append_in(
            &self.db,
            tx,
            AppendSpec {
                record_id: self.home.clone(),
                event_type: KERNEL_POLICY_REPLACED_EVENT.into(),
                payload: serde_json::json!({"entries": [
                    {"subject_id": &self.principal, "capability": "manage"},
                    {"subject_id": &self.admin, "capability": "view"},
                ]}),
                actor: Some(self.principal.clone()),
            },
            &mut acts,
        )
        .await?;
        Ok(())
    }
}

/// Fixture 77 (widen within one call): batch size 4, one invocation. Batch 1
/// moves four sources and the hook widens H3 in the same transaction. Batch 2
/// meets the fence: `Refused(Home(Unusable, NotPrivate))` with batch 1's
/// progress kept. Restore plus a new call drains the rest.
#[tokio::test]
async fn the_driver_holds_its_target_when_a_widen_lands_mid_loop() {
    let w = World::fresh().await;
    let c = w.bt_chain("shapes-mid-widen").await;
    let hook = WidenMidLoop {
        db: w.db.clone(),
        admin: w.admin.clone(),
        principal: c.p.clone(),
        home: c.h3.clone(),
        calls: std::sync::atomic::AtomicU32::new(0),
    };
    let report = rehome_until_ready_with(&w.db, &hook, &c.p, &c.h3, 4, 5)
        .await
        .unwrap();
    assert_eq!(
        report.stop,
        DriveStop::Refused(home_refusal(SlotStatus::Unusable, Some(Why::NotPrivate)))
    );
    assert_eq!((report.batches, report.moved_total), (1, 4));
    assert_eq!(report.last, Some(receipt(&c.h3, 4, 2, 0)));
    assert_eq!(hook.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(w.rc_rehome_events().await, 4);
    w.restore(&c.h3, &c.p).await;
    let resumed = rehome_until_ready(&w.db, &c.p, &c.h3, 4, 5).await.unwrap();
    assert_eq!(resumed.stop, DriveStop::Complete);
    assert_eq!((resumed.batches, resumed.moved_total), (1, 2));
    assert_eq!(resumed.last, Some(receipt(&c.h3, 2, 0, 0)));
}

/// Injects the stall the driver guards against: on an empty selection with
/// no outstanding debt, the hook moves one owned current-home record back
/// into an earlier lineage home on the open transaction. The batch then moves
/// nothing while debt is positive, consistently with both debt predicates.
/// With `max_batches` above one, the driver must fail after exactly one batch
/// instead of looping.
struct StallOnce {
    record: String,
    earlier: String,
    /// Every `after_select` invocation, whatever the selection.
    calls: std::sync::atomic::AtomicU32,
    planted: std::sync::atomic::AtomicBool,
}

impl BatchHooks for StallOnce {
    async fn after_select(
        &self,
        tx: &mut Transaction<'static, Sqlite>,
        sources: &[String],
    ) -> Result<()> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if sources.is_empty() && !self.planted.swap(true, std::sync::atomic::Ordering::SeqCst) {
            sqlx::query("UPDATE kernel_records SET home_id=? WHERE id=?")
                .bind(&self.earlier)
                .bind(&self.record)
                .execute(&mut **tx)
                .await?;
        }
        Ok(())
    }
}

/// Fixture 77 (injected stall): drained of debt first, then one driver call
/// with the planting hook. The exact no-progress error surfaces and the hook
/// ran once despite `max_batches = 5`. The planted move commits with its
/// batch (the guard fires after commit), leaving ordinary debt a new call
/// drains.
#[tokio::test]
async fn the_driver_fails_after_one_stalled_batch() {
    let w = World::fresh().await;
    let c = w.bt_chain("shapes-stall").await;
    let drained = rehome_until_ready(&w.db, &c.p, &c.h3, 4, 5).await.unwrap();
    assert_eq!(drained.stop, DriveStop::Complete);
    let all = sorted(c.six.all());
    let hook = StallOnce {
        record: all[0].clone(),
        earlier: c.six.home.clone(),
        calls: std::sync::atomic::AtomicU32::new(0),
        planted: std::sync::atomic::AtomicBool::new(false),
    };
    let stalled = rehome_until_ready_with(&w.db, &hook, &c.p, &c.h3, 4, 5).await;
    let failed = stalled.unwrap_err();
    assert!(
        matches!(&failed, Error::Engine(m) if m == "rehome batch made no progress"),
        "exact stall error: {failed:?}"
    );
    assert_eq!(
        hook.calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "every after_select invocation counted: one batch attempted, no loop"
    );
    assert!(hook.planted.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(w.rec_home_of(&all[0]).await, c.six.home);
    assert_eq!(w.rc_remaining(&c.p).await, 1);
    let resumed = rehome_until_ready(&w.db, &c.p, &c.h3, 4, 5).await.unwrap();
    assert_eq!(resumed.stop, DriveStop::Complete);
    assert_eq!((resumed.batches, resumed.moved_total), (1, 1));
}
