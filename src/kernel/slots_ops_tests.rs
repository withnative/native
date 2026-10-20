//! Home slot `ensure` and `replace` fixtures (Foci v2 G7 increment 4): fixtures
//! 2, 6, 8 to 10, 26 to 29 and 37 to 39 of the design note, plus the
//! home-slot halves of 17, 18 and 25. (Fixture 20 concerns only
//! `replace(record)`, so it has no home half.) The record-slot halves belong
//! to increment 5.
//!
//! Every receipt assertion compares all nine fields and their explicit JSON;
//! every refusal and no-op also proves it wrote nothing (events, acts, the act
//! counter and both slot tables unchanged). The test provisioner appends a
//! real `kernel.home_created.v1` in the shared transaction. States the v2
//! writes cannot reach are made by direct SQL, and the fixture says so.
use super::slots::{self, HOME_FOCI_PRIVATE};
use super::slots_eval::{Refusal, SlotOutcome, SlotReceipt, SlotStatus, UnusableReason};
use super::slots_eval_tests::assert_receipt;
use super::slots_ops::{
    ensure_home, ensure_home_with, replace_home, replace_home_with, AttemptHooks, HomeProvisioner,
    NoProvisioner, ProvisionOutcome, SlotTxContext,
};
use super::slots_tests::{engine_error, World};
use super::*;
use serde_json::json;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

/// How a test provisioner behaves. `Honest` follows the creation contract;
/// every other mode breaks one clause of it, or fails.
#[derive(Clone, Debug)]
pub(super) enum Mode {
    Honest,
    /// No designated parent: the capability is missing.
    NoParent,
    /// A home owned by the host, not the beneficiary.
    WrongOwner,
    /// The beneficiary's Manage entry plus one more.
    ExtraEntry,
    /// No own anchor: the home inherits its parent's policy.
    NoAnchor,
    /// Returns this id without creating anything.
    Returns(String),
    /// Tries to begin a second write transaction.
    NestedTx,
    /// A storage error inside the provisioner.
    StorageFault,
    /// A malformed `home_created` event.
    MalformedEvent,
    /// Fails its first call with a typed UNIQUE storage error, and would
    /// succeed honestly if it were ever called again.
    UniqueOnce,
}

pub(super) struct TestProvisioner {
    host: String,
    mode: Mode,
    calls: AtomicU32,
}

impl TestProvisioner {
    pub(super) fn new(host: &str, mode: Mode) -> Self {
        Self {
            host: host.into(),
            mode,
            calls: AtomicU32::new(0),
        }
    }
}

impl HomeProvisioner for TestProvisioner {
    async fn provision_home_in(&self, cx: &mut SlotTxContext<'_>) -> Result<ProvisionOutcome> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        match &self.mode {
            Mode::UniqueOnce if call == 0 => {
                // A genuine duplicate primary key in the provisioner's own
                // storage work: the same typed error a registration
                // collision raises, from the wrong place.
                let insert = "INSERT INTO kernel_slots(principal_id,slot,target_id,generation,set_seq) VALUES(?,?,?,1,1)";
                for _ in 0..2 {
                    sqlx::query(insert)
                        .bind(cx.principal)
                        .bind(HOME_FOCI_PRIVATE)
                        .bind("injected")
                        .execute(&mut **cx.tx)
                        .await?;
                }
            }
            Mode::NoParent => return Ok(ProvisionOutcome::Unavailable),
            Mode::Returns(id) => return Ok(ProvisionOutcome::Home(id.clone())),
            Mode::NestedTx => {
                crate::db::begin_write_with_deadline(
                    cx.db.write_pool(),
                    std::time::Duration::from_millis(200),
                )
                .await?;
                return Err(Error::engine("a nested write transaction must not open"));
            }
            Mode::StorageFault => {
                sqlx::query("SELECT * FROM no_such_table")
                    .fetch_all(&mut **cx.tx)
                    .await?;
            }
            _ => {}
        }
        // The host principal's authority over the configured parent is
        // constructor state; lacking it is a fault, not `Unavailable`.
        kernel_require(&mut *cx.tx, &self.host, KERNEL_ROOT_ID, Capability::Manage).await?;
        let id = Uuid::new_v4().to_string();
        let (owner, entries) = match &self.mode {
            Mode::WrongOwner => (self.host.clone(), Some(vec![(self.host.clone(), "manage")])),
            Mode::ExtraEntry => (
                cx.principal.to_string(),
                Some(vec![
                    (cx.principal.to_string(), "manage"),
                    (self.host.clone(), "view"),
                ]),
            ),
            Mode::NoAnchor => (cx.principal.to_string(), None),
            _ => (
                cx.principal.to_string(),
                Some(vec![(cx.principal.to_string(), "manage")]),
            ),
        };
        // The generic route refuses owner ≠ actor (G6 inc 3b), so the creating
        // actor is the owner; the beneficiary for every mode but `WrongOwner`.
        let actor = owner.clone();
        let payload = if matches!(self.mode, Mode::MalformedEvent) {
            json!({"parent_id": KERNEL_ROOT_ID})
        } else {
            serde_json::to_value(KernelHomeCreatedPayload {
                source_record_id: None,
                parent_id: KERNEL_ROOT_ID.into(),
                owner_id: owner,
                entries: entries.map(|entries| {
                    entries
                        .into_iter()
                        .map(|(subject_id, capability)| KernelHomeEntryPayload {
                            subject_id,
                            capability: capability.into(),
                        })
                        .collect()
                }),
            })?
        };
        append_in(
            cx.db,
            &mut *cx.tx,
            AppendSpec {
                record_id: id.clone(),
                event_type: KERNEL_HOME_CREATED_EVENT.into(),
                payload,
                actor: Some(actor),
            },
            &mut *cx.acts,
        )
        .await?;
        Ok(ProvisionOutcome::Home(id))
    }
}

fn expect(
    status: SlotStatus,
    outcome: SlotOutcome,
    reason: Option<UnusableReason>,
    refusal: Option<Refusal>,
    target: Option<&str>,
    created: Option<bool>,
) -> SlotReceipt {
    SlotReceipt {
        slot: HOME_FOCI_PRIVATE.into(),
        status,
        outcome,
        reason,
        refusal,
        target_id: target.map(String::from),
        content_revision: None,
        policy_revision: None,
        created,
    }
}

/// `healthy` after `outcome`, with `created`.
pub(super) fn ready(outcome: SlotOutcome, target: &str, created: bool) -> SlotReceipt {
    expect(
        SlotStatus::Healthy,
        outcome,
        None,
        None,
        Some(target),
        Some(created),
    )
}

/// A refusal that reports the current mapping's status and reason.
fn refusal_of(
    status: SlotStatus,
    reason: Option<UnusableReason>,
    refusal: Option<Refusal>,
    target: Option<&str>,
) -> SlotReceipt {
    expect(status, SlotOutcome::Refused, reason, refusal, target, None)
}

impl World {
    fn honest(&self) -> TestProvisioner {
        TestProvisioner::new(&self.admin, Mode::Honest)
    }
    async fn ensure(&self, principal: &str) -> SlotReceipt {
        ensure_home(&self.db, &self.honest(), principal, "test")
            .await
            .unwrap()
    }
    async fn replace(&self, principal: &str, expected: &str) -> SlotReceipt {
        replace_home(&self.db, &self.honest(), principal, expected, "test")
            .await
            .unwrap()
    }
    /// A no-op or refusal: the receipt matches and nothing was written.
    async fn ensure_wrote_nothing(&self, principal: &str, expected: SlotReceipt) {
        let before = self.state().await;
        assert_receipt(&self.ensure(principal).await, &expected);
        assert_eq!(before, self.state().await);
    }
    async fn replace_wrote_nothing(&self, principal: &str, target: &str, expected: SlotReceipt) {
        let before = self.state().await;
        assert_receipt(&self.replace(principal, target).await, &expected);
        assert_eq!(before, self.state().await);
    }
    async fn ensured(&self, principal: &str) -> String {
        self.ensure(principal).await.target_id.unwrap()
    }
    /// A home the principal ensured, holding a Foci record they own, then
    /// widened: replacing it commits into `recovering`. Returns the home and
    /// the record.
    async fn exposed_with_debt(&self, principal: &str) -> (String, String) {
        let home = self.ensured(principal).await;
        let record = self.record_in(principal, &home).await;
        self.widen(&home, principal).await;
        (home, record)
    }
    async fn count(&self, statement: &str, bind: &str) -> i64 {
        sqlx::query_scalar(statement)
            .bind(bind)
            .fetch_one(self.db.pool())
            .await
            .unwrap()
    }
    async fn homes_owned_by(&self, principal: &str) -> i64 {
        self.count(
            "SELECT COUNT(*) FROM kernel_roots WHERE owner_id=? AND root_id<>'kernel:root'",
            principal,
        )
        .await
    }
    async fn slot_events(&self, event_type: &str) -> i64 {
        self.count(
            "SELECT COUNT(*) FROM content_events WHERE type=?",
            event_type,
        )
        .await
    }
}

/// Fixture 2: `ensure(home)` creates; the second call finds it. The create,
/// the home's own event and the slot event share one act and are consecutive;
/// the repeat writes nothing and allocates no act.
#[tokio::test]
async fn ensure_creates_the_home_once_in_one_act() {
    let w = World::fresh().await;
    let before = w.state().await;
    let max_seq: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let first = w.ensure(&w.other).await;
    let home = first.target_id.clone().unwrap();
    assert_receipt(&first, &ready(SlotOutcome::Created, &home, true));

    let rows: Vec<(i64, String, i64)> =
        sqlx::query_as("SELECT seq, type, act FROM content_events WHERE seq > ? ORDER BY seq")
            .bind(max_seq)
            .fetch_all(w.db.pool())
            .await
            .unwrap();
    assert_eq!(
        rows.iter().map(|r| r.1.as_str()).collect::<Vec<_>>(),
        [KERNEL_HOME_CREATED_EVENT, slots::PROVISIONED]
    );
    assert_eq!(
        rows[1].0,
        rows[0].0 + 1,
        "the slot event follows the create"
    );
    assert_eq!(rows[0].2, rows[1].2, "one transaction, one act");
    assert_eq!(rows[0].2, before.next_act + 1);
    // The home is the beneficiary's: owner, own anchor, sole Manage entry.
    let owner: String = sqlx::query_scalar("SELECT owner_id FROM kernel_roots WHERE root_id=?")
        .bind(&home)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    assert_eq!(owner, w.other);
    w.assert_inspect_ready(&w.other, &home).await;

    let after_first = w.state().await;
    let again = w.ensure(&w.other).await;
    assert_receipt(&again, &ready(SlotOutcome::Existing, &home, false));
    assert_eq!(after_first, w.state().await, "no event, no act");
    let lineage = w.slot_events(slots::PROVISIONED).await;
    assert_eq!(lineage, 1);
    w.replay_equal().await;
}

impl World {
    async fn assert_inspect_ready(&self, principal: &str, home: &str) {
        let got = self.inspect(principal, HOME_FOCI_PRIVATE).await;
        let want = SlotReceipt {
            outcome: SlotOutcome::Inspected,
            created: None,
            ..ready(SlotOutcome::Inspected, home, false)
        };
        assert_receipt(&got, &want);
    }
}

/// Fixture 6, home half: another principal starts absent, gets their own
/// home, and cannot use the first principal's id. Nothing of the first
/// principal's appears in their receipts.
#[tokio::test]
async fn principals_are_isolated() {
    let w = World::fresh().await;
    let a_home = w.ensured(&w.other).await;
    let b = create_principal(&w.db, "account", "B", "acct:b", &w.admin)
        .await
        .unwrap();
    assert_receipt(
        &w.inspect(&b, HOME_FOCI_PRIVATE).await,
        &SlotReceipt {
            created: None,
            ..expect(
                SlotStatus::Absent,
                SlotOutcome::Inspected,
                None,
                None,
                None,
                None,
            )
        },
    );
    let ensured = w.ensure(&b).await;
    let b_home = ensured.target_id.clone().unwrap();
    assert_ne!(a_home, b_home);
    assert_receipt(&ensured, &ready(SlotOutcome::Created, &b_home, true));
    // B's replace with A's id is a CAS mismatch that reports B's own mapping.
    let before = w.state().await;
    let refused = w.replace(&b, &a_home).await;
    assert_receipt(
        &refused,
        &refusal_of(
            SlotStatus::Healthy,
            None,
            Some(Refusal::CasMismatch),
            Some(&b_home),
        ),
    );
    assert_eq!(before, w.state().await);
    for receipt in [&ensured, &refused] {
        assert!(!serde_json::to_string(receipt).unwrap().contains(&a_home));
    }
    // B has no view of A's home, and A's mapping is untouched.
    let mut tx = w.db.write_pool().begin().await.unwrap();
    let seen = kernel_effective_capability_on(&mut tx, &b, &a_home).await;
    tx.rollback().await.unwrap();
    match seen {
        Err(Error::Engine(m)) => assert_eq!(m, HIDDEN_OR_MISSING),
        Ok(capability) => assert!(!capability.allows(Capability::View)),
        Err(error) => panic!("unexpected error {error:?}"),
    }
    w.assert_inspect_ready(&w.other, &a_home).await;
}

/// Two concurrent `ensure` calls for one principal: one `created`, one
/// `existing`, one home, one slot row.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_ensures_have_one_winner() {
    let w = World::fresh().await;
    let spawn = |w: &World| {
        let (db, admin, who) = (w.db.clone(), w.admin.clone(), w.other.clone());
        tokio::spawn(async move {
            ensure_home(
                &db,
                &TestProvisioner::new(&admin, Mode::Honest),
                &who,
                "race",
            )
            .await
            .unwrap()
        })
    };
    let (a, b) = (spawn(&w), spawn(&w));
    let (a, b) = (a.await.unwrap(), b.await.unwrap());
    let mut outcomes = [a.outcome, b.outcome];
    outcomes.sort_by_key(|o| format!("{o:?}"));
    assert_eq!(outcomes, [SlotOutcome::Created, SlotOutcome::Existing]);
    assert_eq!(a.target_id, b.target_id);
    assert_eq!(w.slot_events(slots::PROVISIONED).await, 1);
    assert_eq!(w.homes_owned_by(&w.other).await, 1);
    let rows = w.state().await.dump.slots;
    assert_eq!(rows.len(), 1);
    w.replay_equal().await;
}

/// Two concurrent `replace` calls with the same `expected_target`: one
/// `replaced`, the other `replayed` (the new home is ready) or
/// `already_replaced` (still recovering). Exactly one new home either way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_replaces_have_one_winner() {
    for with_debt in [false, true] {
        let w = World::fresh().await;
        let h1 = if with_debt {
            w.exposed_with_debt(&w.other).await.0
        } else {
            let h1 = w.ensured(&w.other).await;
            w.widen(&h1, &w.other).await;
            h1
        };
        let spawn = |w: &World| {
            let (db, admin, who, h1) = (w.db.clone(), w.admin.clone(), w.other.clone(), h1.clone());
            tokio::spawn(async move {
                replace_home(
                    &db,
                    &TestProvisioner::new(&admin, Mode::Honest),
                    &who,
                    &h1,
                    "race",
                )
                .await
                .unwrap()
            })
        };
        let (a, b) = (spawn(&w), spawn(&w));
        let mut got = [a.await.unwrap(), b.await.unwrap()];
        got.sort_by_key(|r| format!("{:?}", r.outcome));
        let h2 = got[0].target_id.clone().unwrap();
        assert_eq!(got[0].target_id, got[1].target_id);
        if with_debt {
            let recovering = |outcome, refusal, created| {
                expect(
                    SlotStatus::Unusable,
                    outcome,
                    Some(UnusableReason::RecoveryIncomplete),
                    refusal,
                    Some(&h2),
                    created,
                )
            };
            // `Refused` sorts before `Replaced`.
            assert_receipt(
                &got[0],
                &recovering(SlotOutcome::Refused, Some(Refusal::AlreadyReplaced), None),
            );
            assert_receipt(
                &got[1],
                &recovering(SlotOutcome::Replaced, None, Some(true)),
            );
        } else {
            // `Replaced` sorts before `Replayed`.
            assert_receipt(&got[0], &ready(SlotOutcome::Replaced, &h2, true));
            assert_receipt(&got[1], &ready(SlotOutcome::Replayed, &h2, false));
        }
        assert_eq!(w.homes_owned_by(&w.other).await, 2);
        assert_eq!(w.slot_events(slots::REPLACED).await, 1);
        w.replay_equal().await;
    }
}

/// Fixture 10's seam: injects a typed UNIQUE violation into the first
/// attempt's slot append, and once that attempt has rolled back and released
/// the writer lock commits a competing winner through an independent writer.
struct UniqueBackstop {
    db: Db,
    principal: String,
    /// The slot's target the winner replaces, if any.
    previous: Option<String>,
    inject_every_attempt: bool,
    baseline: (i64, i64),
    registers: AtomicU32,
    rollbacks: AtomicU32,
    winner: Mutex<Option<String>>,
}

impl UniqueBackstop {
    async fn new(w: &World, previous: Option<&str>, inject_every_attempt: bool) -> Arc<Self> {
        let state = w.state().await;
        Arc::new(Self {
            db: w.db.clone(),
            principal: w.other.clone(),
            previous: previous.map(String::from),
            inject_every_attempt,
            baseline: (state.events, state.next_act),
            registers: AtomicU32::new(0),
            rollbacks: AtomicU32::new(0),
            winner: Mutex::new(None),
        })
    }
}

impl AttemptHooks for UniqueBackstop {
    async fn before_register(
        &self,
        tx: &mut Transaction<'static, Sqlite>,
        attempt: u32,
    ) -> Result<()> {
        self.registers.fetch_add(1, Ordering::SeqCst);
        if attempt > 0 && !self.inject_every_attempt {
            return Ok(());
        }
        // A genuine duplicate primary key: the same typed error a collision
        // with a committed winner would raise. No error text is parsed.
        let insert = "INSERT INTO kernel_slots(principal_id,slot,target_id,generation,set_seq) VALUES(?,?,?,1,1)";
        for _ in 0..2 {
            sqlx::query(insert)
                .bind(&self.principal)
                .bind(HOME_FOCI_PRIVATE)
                .bind("injected")
                .execute(&mut **tx)
                .await?;
        }
        unreachable!("the second insert violates the primary key")
    }
    async fn after_rollback(&self, attempt: u32) {
        self.rollbacks.fetch_add(1, Ordering::SeqCst);
        // The failed attempt left no residue: events and the act counter are
        // where they started.
        let events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(self.db.pool())
            .await
            .unwrap();
        let next_act: i64 = sqlx::query_scalar("SELECT next_act FROM act_state WHERE singleton=1")
            .fetch_one(self.db.pool())
            .await
            .unwrap();
        assert_eq!(
            (events, next_act),
            self.baseline,
            "attempt {attempt} leaked"
        );
        if self.inject_every_attempt {
            return;
        }
        // Only now, with the writer lock free, does the winner commit.
        let id = Uuid::new_v4().to_string();
        let mut tx = begin_write(self.db.write_pool()).await.unwrap();
        let mut acts = crate::act::ActAllocation::new();
        append_in(
            &self.db,
            &mut tx,
            AppendSpec {
                record_id: id.clone(),
                event_type: KERNEL_HOME_CREATED_EVENT.into(),
                payload: serde_json::to_value(KernelHomeCreatedPayload {
                    source_record_id: None,
                    parent_id: KERNEL_ROOT_ID.into(),
                    owner_id: self.principal.clone(),
                    entries: Some(vec![KernelHomeEntryPayload {
                        subject_id: self.principal.clone(),
                        capability: "manage".into(),
                    }]),
                })
                .unwrap(),
                actor: Some(self.principal.clone()),
            },
            &mut acts,
        )
        .await
        .unwrap();
        slots::append_registration_in(
            &self.db,
            &mut tx,
            &mut acts,
            &self.principal,
            HOME_FOCI_PRIVATE,
            &id,
            self.previous.as_deref(),
            "winner",
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        *self.winner.lock().unwrap() = Some(id);
    }
}

/// Fixture 10, `ensure`: the first attempt's slot append fails with a typed
/// UNIQUE violation and rolls back whole; an independent writer then commits
/// a winner; exactly one retry rereads it and returns `existing`.
#[tokio::test]
async fn unique_backstop_rereads_once_for_ensure() {
    let w = World::fresh().await;
    let hook = UniqueBackstop::new(&w, None, false).await;
    let got = ensure_home_with(&w.db, &w.honest(), &*hook, &w.other, "race")
        .await
        .unwrap();
    let winner = hook.winner.lock().unwrap().clone().unwrap();
    assert_receipt(&got, &ready(SlotOutcome::Existing, &winner, false));
    // One failed attempt, one retry, and the retry registered nothing.
    assert_eq!(hook.registers.load(Ordering::SeqCst), 1);
    assert_eq!(hook.rollbacks.load(Ordering::SeqCst), 1);
    // The abandoned attempt's home does not exist: the winner's is the only one.
    assert_eq!(w.homes_owned_by(&w.other).await, 1);
    assert_eq!(w.slot_events(slots::PROVISIONED).await, 1);
    w.replay_equal().await;
}

/// Fixture 10, `replace`: the retry follows the replay rules of §6.4: the
/// winner's replacement of the same `expected_target` is `replayed`.
#[tokio::test]
async fn unique_backstop_rereads_once_for_replace() {
    let w = World::fresh().await;
    let h1 = w.ensured(&w.other).await;
    w.widen(&h1, &w.other).await;
    let hook = UniqueBackstop::new(&w, Some(&h1), false).await;
    let got = replace_home_with(&w.db, &w.honest(), &*hook, &w.other, &h1, "race")
        .await
        .unwrap();
    let winner = hook.winner.lock().unwrap().clone().unwrap();
    assert_receipt(&got, &ready(SlotOutcome::Replayed, &winner, false));
    assert_eq!(hook.registers.load(Ordering::SeqCst), 1);
    assert_eq!(hook.rollbacks.load(Ordering::SeqCst), 1);
    assert_eq!(w.homes_owned_by(&w.other).await, 2);
    assert_eq!(w.slot_events(slots::REPLACED).await, 1);
    w.replay_equal().await;
}

/// The retry is capped at one: a second UNIQUE violation is the caller's
/// error, with nothing written and the act counter untouched.
#[tokio::test]
async fn a_second_unique_violation_is_an_error() {
    let w = World::fresh().await;
    let hook = UniqueBackstop::new(&w, None, true).await;
    let before = w.state().await;
    let err = ensure_home_with(&w.db, &w.honest(), &*hook, &w.other, "race")
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Sqlx(sqlx::Error::Database(e)) if e.is_unique_violation()));
    assert_eq!(hook.registers.load(Ordering::SeqCst), 2);
    assert_eq!(hook.rollbacks.load(Ordering::SeqCst), 1);
    assert_eq!(before, w.state().await);
}

/// Fixture 26: after a replace that ended ready, a retry with the same
/// `expected_target` is `replayed` with `created:false` and writes nothing.
#[tokio::test]
async fn a_retried_replace_that_ended_ready_is_replayed() {
    let w = World::fresh().await;
    let h1 = w.ensured(&w.other).await;
    w.widen(&h1, &w.other).await;
    let first = w.replace(&w.other, &h1).await;
    let h2 = first.target_id.clone().unwrap();
    assert_ne!(h1, h2);
    assert_receipt(&first, &ready(SlotOutcome::Replaced, &h2, true));
    w.replace_wrote_nothing(&w.other, &h1, ready(SlotOutcome::Replayed, &h2, false))
        .await;
    w.replay_equal().await;
}

/// Fixture 27: a replace that ended recovering answers a retry
/// `already_replaced` (never repairing or resetting); once recovery completes
/// the same retry is `replayed`. Replacing the recovering home again, and
/// ensuring it, are refused.
#[tokio::test]
async fn a_retried_replace_is_already_replaced_until_recovery_completes() {
    let w = World::fresh().await;
    let (h1, record) = w.exposed_with_debt(&w.other).await;
    let focus = w.focus_in(&w.other, &h1).await;
    let first = w.replace(&w.other, &h1).await;
    let h2 = first.target_id.clone().unwrap();
    // Structure is sound but debt is outstanding: committed, fenced, and
    // both guards null.
    let recovering = |outcome, refusal, created| {
        expect(
            SlotStatus::Unusable,
            outcome,
            Some(UnusableReason::RecoveryIncomplete),
            refusal,
            Some(&h2),
            created,
        )
    };
    assert_receipt(&first, &recovering(SlotOutcome::Replaced, None, Some(true)));
    w.replace_wrote_nothing(
        &w.other,
        &h1,
        recovering(SlotOutcome::Refused, Some(Refusal::AlreadyReplaced), None),
    )
    .await;
    w.replace_wrote_nothing(
        &w.other,
        &h2,
        recovering(
            SlotOutcome::Refused,
            Some(Refusal::UnsupportedRecovery),
            None,
        ),
    )
    .await;
    w.ensure_wrote_nothing(&w.other, recovering(SlotOutcome::Refused, None, None))
        .await;
    // Rehome one record: still recovering. Rehome the other: ready.
    rehome_record_as(&w.db, &w.other, &record, &h2)
        .await
        .unwrap();
    w.replace_wrote_nothing(
        &w.other,
        &h1,
        recovering(SlotOutcome::Refused, Some(Refusal::AlreadyReplaced), None),
    )
    .await;
    rehome_record_as(&w.db, &w.other, &focus, &h2)
        .await
        .unwrap();
    w.replace_wrote_nothing(&w.other, &h1, ready(SlotOutcome::Replayed, &h2, false))
        .await;
    w.replay_equal().await;
}

/// Fixture 28: after replacing from the winner, a retry of the original
/// `expected_target` is `mapping_changed`, reporting the current target.
#[tokio::test]
async fn replacing_from_the_winner_makes_the_original_retry_mapping_changed() {
    let w = World::fresh().await;
    let h1 = w.ensured(&w.other).await;
    w.widen(&h1, &w.other).await;
    let h2 = w.replace(&w.other, &h1).await.target_id.unwrap();
    w.widen(&h2, &w.other).await;
    let h3 = w.replace(&w.other, &h2).await.target_id.unwrap();
    w.replace_wrote_nothing(
        &w.other,
        &h1,
        refusal_of(
            SlotStatus::Healthy,
            None,
            Some(Refusal::MappingChanged),
            Some(&h3),
        ),
    )
    .await;
    // The same retry against the current target's own replay is unaffected.
    w.replace_wrote_nothing(&w.other, &h2, ready(SlotOutcome::Replayed, &h3, false))
        .await;
}

/// Fixture 29: a wrong `expected_target`, a replace on a healthy home and a
/// replace on an absent slot are `cas_mismatch`, `not_unusable` and `absent`,
/// each reporting the current mapping and writing nothing.
#[tokio::test]
async fn replace_refuses_wrong_target_healthy_and_absent() {
    let w = World::fresh().await;
    let nowhere = Uuid::new_v4().to_string();
    w.replace_wrote_nothing(
        &w.other,
        &nowhere,
        refusal_of(SlotStatus::Absent, None, Some(Refusal::Absent), None),
    )
    .await;
    let h1 = w.ensured(&w.other).await;
    w.replace_wrote_nothing(
        &w.other,
        &nowhere,
        refusal_of(
            SlotStatus::Healthy,
            None,
            Some(Refusal::CasMismatch),
            Some(&h1),
        ),
    )
    .await;
    w.replace_wrote_nothing(
        &w.other,
        &h1,
        refusal_of(
            SlotStatus::Healthy,
            None,
            Some(Refusal::NotUnusable),
            Some(&h1),
        ),
    )
    .await;
    w.widen(&h1, &w.other).await;
    w.replace_wrote_nothing(
        &w.other,
        &nowhere,
        refusal_of(
            SlotStatus::Unusable,
            Some(UnusableReason::NotPrivate),
            Some(Refusal::CasMismatch),
            Some(&h1),
        ),
    )
    .await;
    // `ensure` of an unusable home refuses without a refusal code.
    w.ensure_wrote_nothing(
        &w.other,
        refusal_of(
            SlotStatus::Unusable,
            Some(UnusableReason::NotPrivate),
            None,
            Some(&h1),
        ),
    )
    .await;
}

/// Fixture 37: with no provisioner capability `ensure` and `replace` are
/// `refused`/`provisioner_unavailable`, report the current mapping, and write
/// nothing: no event, no act, and the counter untouched. `NoProvisioner` and a
/// provisioner with no designated parent behave the same.
#[tokio::test]
async fn an_unavailable_provisioner_refuses_without_writing() {
    let w = World::fresh().await;
    let no_parent = TestProvisioner::new(&w.admin, Mode::NoParent);
    let absent = refusal_of(
        SlotStatus::Absent,
        None,
        Some(Refusal::ProvisionerUnavailable),
        None,
    );
    let before = w.state().await;
    for got in [
        ensure_home(&w.db, &NoProvisioner, &w.other, "test")
            .await
            .unwrap(),
        ensure_home(&w.db, &no_parent, &w.other, "test")
            .await
            .unwrap(),
    ] {
        assert_receipt(&got, &absent);
    }
    assert_eq!(before, w.state().await);

    let h1 = w.ensured(&w.other).await;
    w.widen(&h1, &w.other).await;
    let exposed = refusal_of(
        SlotStatus::Unusable,
        Some(UnusableReason::NotPrivate),
        Some(Refusal::ProvisionerUnavailable),
        Some(&h1),
    );
    let before = w.state().await;
    for got in [
        replace_home(&w.db, &NoProvisioner, &w.other, &h1, "test")
            .await
            .unwrap(),
        replace_home(&w.db, &no_parent, &w.other, &h1, "test")
            .await
            .unwrap(),
    ] {
        assert_receipt(&got, &exposed);
    }
    assert_eq!(before, w.state().await);
}

/// Runs `ensure` on an absent slot and `replace` on an exposed home with a
/// provisioner of this mode, and expects an error each time with nothing
/// written.
async fn both_actions_fail(w: &World, mode: Mode, message: Option<&str>) {
    let provisioner = TestProvisioner::new(&w.admin, mode);
    let binding = format!("acct:{}", Uuid::new_v4());
    let beneficiary = create_principal(&w.db, "account", "Fresh", &binding, &w.admin)
        .await
        .unwrap();
    let before = w.state().await;
    let err = ensure_home(&w.db, &provisioner, &beneficiary, "test")
        .await
        .unwrap_err();
    if let Some(message) = message {
        assert_eq!(err.to_string(), message);
    }
    assert_eq!(before, w.state().await);

    let h1 = w.ensured(&beneficiary).await;
    w.widen(&h1, &beneficiary).await;
    let before = w.state().await;
    let err = replace_home(&w.db, &provisioner, &beneficiary, &h1, "test")
        .await
        .unwrap_err();
    if let Some(message) = message {
        assert_eq!(err.to_string(), message);
    }
    assert_eq!(before, w.state().await);
}

/// Fixture 38: a provisioner that breaks the creation contract is aborted
/// and nothing is written.
#[tokio::test]
async fn contract_violations_abort_with_nothing_written() {
    let w = World::fresh().await;
    let invalid = |reason: &str| format!("slot target is not valid for the slot: {reason}");
    both_actions_fail(&w, Mode::WrongOwner, Some(&invalid("forbidden"))).await;
    both_actions_fail(&w, Mode::ExtraEntry, Some(&invalid("not_private"))).await;
    both_actions_fail(&w, Mode::NoAnchor, Some(&invalid("not_private"))).await;
    // An id the provisioner did not create in this transaction: a record, a
    // home that already existed, and the root.
    let foreign = w.home(&w.other).await;
    let record = w.record_in(&w.other, &foreign).await;
    let not_here = "provisioned home was not created in this transaction";
    both_actions_fail(&w, Mode::Returns(foreign), Some(not_here)).await;
    both_actions_fail(&w, Mode::Returns(record), Some(not_here)).await;
    both_actions_fail(
        &w,
        Mode::Returns(KERNEL_ROOT_ID.into()),
        Some("provisioned home id is not a canonical id"),
    )
    .await;
    // A second write transaction cannot open while the operation holds the
    // writer lock; the provisioner's attempt surfaces as an error.
    both_actions_fail(&w, Mode::NestedTx, Some(crate::db::SQL_WORKSPACE_BUSY)).await;
}

/// Fixture 39: provisioner faults are errors, never `provisioner_unavailable`:
/// a host principal without Manage on the parent, a storage error, and a
/// malformed event. The transaction rolls back and nothing is written.
#[tokio::test]
async fn provisioner_faults_are_errors_not_unavailable() {
    let w = World::fresh().await;
    // The configured host principal lacks Manage on the designated parent.
    let powerless = TestProvisioner::new(&w.other, Mode::Honest);
    let before = w.state().await;
    assert!(ensure_home(&w.db, &powerless, &w.other, "test")
        .await
        .is_err());
    assert_eq!(before, w.state().await);
    both_actions_fail(&w, Mode::StorageFault, None).await;
    both_actions_fail(&w, Mode::MalformedEvent, None).await;
    w.replay_equal().await;
}

impl World {
    /// Direct SQL: delete a home's projection rows, leaving the slot mapping
    /// and its events alone. The mapping stays replayable; the target is gone.
    async fn delete_home_rows(&self, home: &str) {
        self.sql("DELETE FROM kernel_policies WHERE root_id=?", &[home])
            .await;
        self.sql("DELETE FROM kernel_roots WHERE root_id=?", &[home])
            .await;
    }
    /// Direct SQL: hand a home to another owner whose policy names only them,
    /// so the beneficiary can no longer see it.
    async fn hand_home_to(&self, home: &str, owner: &str) {
        self.sql(
            "UPDATE kernel_roots SET owner_id=? WHERE root_id=?",
            &[owner, home],
        )
        .await;
        self.sql(
            "UPDATE kernel_policy_entries SET subject_id=? WHERE root_id=?",
            &[owner, home],
        )
        .await;
    }
}

/// Fixture 17, home half. Direct SQL: the home's rows are gone but its
/// mapping is intact. `missing` with the id still shown; `ensure` refuses;
/// `replace` replaces it and the lineage keeps the history. (The record half
/// is increment 5.)
#[tokio::test]
async fn a_missing_home_is_replaced() {
    let w = World::fresh().await;
    let h1 = w.ensured(&w.other).await;
    w.delete_home_rows(&h1).await;
    w.assert_inspect(
        &w.other,
        HOME_FOCI_PRIVATE,
        super::slots_eval_tests::unusable(HOME_FOCI_PRIVATE, UnusableReason::Missing, Some(&h1)),
    )
    .await;
    w.ensure_wrote_nothing(
        &w.other,
        refusal_of(
            SlotStatus::Unusable,
            Some(UnusableReason::Missing),
            None,
            Some(&h1),
        ),
    )
    .await;
    let got = w.replace(&w.other, &h1).await;
    let h2 = got.target_id.clone().unwrap();
    assert_receipt(&got, &ready(SlotOutcome::Replaced, &h2, true));
    let lineage: Vec<(i64, String, Option<String>)> = sqlx::query_as(
        "SELECT generation, target_id, previous_target_id FROM kernel_slot_lineage ORDER BY generation",
    )
    .fetch_all(w.db.pool())
    .await
    .unwrap();
    assert_eq!(lineage, vec![(1, h1.clone(), None), (2, h2, Some(h1))]);
}

/// Fixture 18, home half, hidden target. Direct SQL hands the home to another
/// owner: the beneficiary sees nothing of it, so `forbidden` and the id is
/// withheld from every receipt, including a CAS mismatch. A caller who knows
/// the id can still replace it.
#[tokio::test]
async fn a_hidden_home_is_withheld_and_replaceable() {
    let w = World::fresh().await;
    let h1 = w.ensured(&w.other).await;
    w.hand_home_to(&h1, &w.admin).await;
    let hidden = |refusal| {
        refusal_of(
            SlotStatus::Unusable,
            Some(UnusableReason::Forbidden),
            refusal,
            None,
        )
    };
    w.ensure_wrote_nothing(&w.other, hidden(None)).await;
    w.replace_wrote_nothing(
        &w.other,
        &Uuid::new_v4().to_string(),
        hidden(Some(Refusal::CasMismatch)),
    )
    .await;
    let got = w.replace(&w.other, &h1).await;
    let h2 = got.target_id.clone().unwrap();
    assert_receipt(&got, &ready(SlotOutcome::Replaced, &h2, true));
}

/// Fixture 18, home half, wrong target. Direct SQL points the admin's slot at
/// the workspace root, which the admin can manage: `wrong_target`, and
/// `ensure` refuses. The design lets `replace` repair it, but a mapping to the
/// root can never be a lineage predecessor (the fold admits only canonical
/// v4/v7 ids, and registration never admits the root), so the event would be
/// refused and a rebuild could not replay it. `replace` therefore fails closed
/// with an error, at the operation boundary, and writes nothing. Reviewed and
/// accepted as a deviation (0c7ad44).
#[tokio::test]
async fn a_home_mapped_to_the_root_is_wrong_target_and_not_replaceable() {
    let w = World::fresh().await;
    let _h1 = w.ensured(&w.admin).await;
    w.set_slot_target(&w.admin, HOME_FOCI_PRIVATE, KERNEL_ROOT_ID)
        .await;
    w.ensure_wrote_nothing(
        &w.admin,
        refusal_of(
            SlotStatus::Unusable,
            Some(UnusableReason::WrongTarget),
            None,
            Some(KERNEL_ROOT_ID),
        ),
    )
    .await;
    let before = w.state().await;
    engine_error(
        replace_home(&w.db, &w.honest(), &w.admin, KERNEL_ROOT_ID, "test").await,
        "invalid slot target id",
    );
    assert_eq!(before, w.state().await);
}

/// Fixture 25, home half. Direct SQL: the beneficiary's home belongs to
/// someone else and its policy names only them. The home is `forbidden` with
/// `target_id` null; `ensure` refuses; `replace` provisions a new home.
/// (`replace(record)` is increment 5.)
#[tokio::test]
async fn a_foreign_owned_home_is_forbidden_and_replaceable() {
    let w = World::fresh().await;
    let (h1, _record) = w.ready(&w.other).await;
    w.hand_home_to(&h1, &w.admin).await;
    w.assert_inspect(
        &w.other,
        HOME_FOCI_PRIVATE,
        super::slots_eval_tests::unusable(HOME_FOCI_PRIVATE, UnusableReason::Forbidden, None),
    )
    .await;
    w.ensure_wrote_nothing(
        &w.other,
        refusal_of(
            SlotStatus::Unusable,
            Some(UnusableReason::Forbidden),
            None,
            None,
        ),
    )
    .await;
    // The beneficiary's preferences record is still in the old home, so the
    // replacement commits into `recovering`.
    let got = w.replace(&w.other, &h1).await;
    let h2 = got.target_id.clone().unwrap();
    assert_ne!(h2, h1);
    assert_receipt(
        &got,
        &expect(
            SlotStatus::Unusable,
            SlotOutcome::Replaced,
            Some(UnusableReason::RecoveryIncomplete),
            None,
            Some(&h2),
            Some(true),
        ),
    );
}

/// A recovering home cannot be replaced, but an exposed one can, even with
/// debt outstanding: its records join the debt (state machine of §8.4).
#[tokio::test]
async fn replacing_again_is_allowed_only_from_exposed_or_broken() {
    let w = World::fresh().await;
    let (h1, _record) = w.exposed_with_debt(&w.other).await;
    let h2 = w.replace(&w.other, &h1).await.target_id.unwrap();
    // Recovering: refused.
    assert_eq!(
        w.replace(&w.other, &h2).await.refusal,
        Some(Refusal::UnsupportedRecovery)
    );
    // Exposed again: allowed, and the new home is still fenced by H1's debt.
    w.widen(&h2, &w.other).await;
    let got = w.replace(&w.other, &h2).await;
    let h3 = got.target_id.clone().unwrap();
    assert_receipt(
        &got,
        &expect(
            SlotStatus::Unusable,
            SlotOutcome::Replaced,
            Some(UnusableReason::RecoveryIncomplete),
            None,
            Some(&h3),
            Some(true),
        ),
    );
    w.replay_equal().await;
}

/// Malformed requests are errors with nothing written. Each case is isolated
/// so it cannot be masked by an earlier check: a blank reason (with a valid
/// target and account), and a principal that is not an account (with a valid
/// reason and target).
#[tokio::test]
async fn malformed_requests_are_errors() {
    let w = World::fresh().await;
    let agent = create_principal(&w.db, "agent", "Agent", "agent:a", &w.admin)
        .await
        .unwrap();
    let valid_target = Uuid::new_v4().to_string();
    let before = w.state().await;
    for reason in ["", "  "] {
        engine_error(
            ensure_home(&w.db, &w.honest(), &w.other, reason).await,
            "slot reason must not be blank",
        );
        engine_error(
            replace_home(&w.db, &w.honest(), &w.other, &valid_target, reason).await,
            "slot reason must not be blank",
        );
    }
    for result in [
        ensure_home(&w.db, &w.honest(), &agent, "test").await,
        replace_home(&w.db, &w.honest(), &agent, &valid_target, "test").await,
        ensure_home(&w.db, &w.honest(), &Uuid::new_v4().to_string(), "test").await,
        replace_home(
            &w.db,
            &w.honest(),
            &Uuid::new_v4().to_string(),
            &valid_target,
            "test",
        )
        .await,
    ] {
        engine_error(result, "slot principal must be an account");
    }
    assert_eq!(before, w.state().await);
}

/// A malformed `expected_target` is an error before any replay or state
/// decision, whether the slot is absent or present: never `absent` or
/// `cas_mismatch`. Malformed means not a canonical lowercase v4/v7 id of the
/// RFC 4122 variant. Nothing is written, including the act counter.
#[tokio::test]
async fn a_malformed_expected_target_is_an_error_not_a_refusal() {
    let w = World::fresh().await;
    let canonical = Uuid::new_v4().to_string();
    let bad = [
        ("not an id", "x".to_string()),
        ("empty", String::new()),
        ("uppercase", canonical.to_uppercase()),
        (
            "version 1",
            "6ba7b810-9dad-11d1-80b4-00c04fd430c8".to_string(),
        ),
        (
            "version 5",
            "886313e1-3b8a-5372-9b90-0c9aee199e5d".to_string(),
        ),
        // Version 4, but the variant nibble is 0 (the NCS variant).
        (
            "invalid variant",
            "550e8400-e29b-41d4-0716-446655440000".to_string(),
        ),
        ("the root", KERNEL_ROOT_ID.to_string()),
    ];
    // The slot is absent for `other` and present for `ready`.
    let ready = create_principal(
        &w.db,
        "account",
        "Ready",
        &format!("acct:{}", Uuid::new_v4()),
        &w.admin,
    )
    .await
    .unwrap();
    let _ = w.ensured(&ready).await;
    for principal in [&w.other, &ready] {
        for (what, target) in &bad {
            let before = w.state().await;
            let result = replace_home(&w.db, &w.honest(), principal, target, "test").await;
            match result {
                Err(Error::Engine(message)) => {
                    assert_eq!(message, "invalid slot target id", "{what}")
                }
                other => panic!("{what}: expected an error, got {other:?}"),
            }
            assert_eq!(before, w.state().await, "{what}");
        }
    }
    // A canonical id is not an error: it reaches the state decision.
    assert_eq!(
        w.replace(&w.other, &canonical).await.refusal,
        Some(Refusal::Absent)
    );
}

/// The collision retry is for the slot registration only. A provisioner that
/// fails once with a typed UNIQUE storage error, and would succeed if called
/// again, is invoked exactly once and its error reaches the caller. Events,
/// the act counter and every table are unchanged.
#[tokio::test]
async fn a_provisioner_unique_error_is_not_retried() {
    let w = World::fresh().await;
    // ensure on an absent slot.
    let provisioner = TestProvisioner::new(&w.admin, Mode::UniqueOnce);
    let before = w.state().await;
    let err = ensure_home(&w.db, &provisioner, &w.other, "test")
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Sqlx(sqlx::Error::Database(e)) if e.is_unique_violation()));
    assert_eq!(provisioner.calls.load(Ordering::SeqCst), 1);
    assert_eq!(before, w.state().await);

    // replace on an exposed home.
    let h1 = w.ensured(&w.other).await;
    w.widen(&h1, &w.other).await;
    let provisioner = TestProvisioner::new(&w.admin, Mode::UniqueOnce);
    let before = w.state().await;
    let err = replace_home(&w.db, &provisioner, &w.other, &h1, "test")
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Sqlx(sqlx::Error::Database(e)) if e.is_unique_violation()));
    assert_eq!(provisioner.calls.load(Ordering::SeqCst), 1);
    assert_eq!(before, w.state().await);

    // The same provisioner, called again, would have succeeded.
    let got = replace_home(&w.db, &provisioner, &w.other, &h1, "test")
        .await
        .unwrap();
    assert_eq!(got.outcome, SlotOutcome::Replaced);
    assert_eq!(provisioner.calls.load(Ordering::SeqCst), 2);
}
