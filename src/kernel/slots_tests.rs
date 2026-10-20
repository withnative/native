//! Slot-map storage fixtures (Foci v2 G7 increments 1 and 2): the fold, the
//! sealing of the two slot events, replay, and the registration admission
//! check. Fixtures 11, 40 (fold part), 41 and 42 of the G7 design note.
//!
//! Registration now checks structure at admission, so every passing fixture
//! uses structurally valid targets: a home owned by the beneficiary with its
//! own anchor and a sole Manage entry for them, and a preferences record
//! owned by them in the slot's current home. The helpers below build exactly
//! that and nothing else; invalid structure has its own negative fixtures in
//! `slots_eval_tests`.
use super::slots::{self, HOME_FOCI_PRIVATE, RECORD_FOCI_PREFERENCES};
use super::*;
use serde_json::{json, Value};

pub(super) fn engine_error<T: std::fmt::Debug>(result: Result<T>, expected: &str) {
    match result.unwrap_err() {
        Error::Engine(message) => assert_eq!(message, expected),
        error => panic!("expected Engine({expected}), got {error:?}"),
    }
}

/// A v2 database with the root admin and a second account, plus a helper to
/// mint the targets a slot can point at.
pub(super) struct World {
    _dir: tempfile::TempDir,
    pub(super) url: String,
    pub(super) db: Db,
    pub(super) admin: String,
    pub(super) other: String,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct State {
    pub(super) events: i64,
    pub(super) acts: i64,
    /// The act counter itself: a rollback must hand its allocation back.
    pub(super) next_act: i64,
    pub(super) dump: KernelTableDump,
}

impl World {
    pub(super) async fn fresh() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}", dir.path().join("slots.db").display());
        let (db, admin) = create_v2_database(&url, "account", "Admin", "acct:admin")
            .await
            .unwrap();
        let manifest = crate::v2_standard::foci::package();
        let identity = manifest.identity().unwrap();
        install_package_as(&db, &admin, &manifest).await.unwrap();
        adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &manifest, Some(&identity), &[])
            .await
            .unwrap();
        let other = create_principal(&db, "account", "Other", "acct:other", &admin)
            .await
            .unwrap();
        Self {
            _dir: dir,
            url,
            db,
            admin,
            other,
        }
    }
    /// Close every handle and reopen the same file: nothing but the file
    /// survives.
    pub(super) async fn reopen(&mut self) {
        self.db.close().await;
        self.db = open_database(&self.url).await.unwrap();
    }
    /// A test home for `beneficiary`: appends a real `kernel.home_created.v1`
    /// with owner and sole Manage entry both the beneficiary, in its own
    /// transaction, and registers nothing. The beneficiary is also the actor,
    /// because the shared admission hook (G6 inc 3b) refuses a generic home
    /// whose owner is not its actor; the sealed `home_created_for` route is
    /// the only way to create a home for someone else. It does not call
    /// `create_home`, which would need the beneficiary to hold Manage.
    pub(super) async fn home(&self, beneficiary: &str) -> String {
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
                    owner_id: beneficiary.into(),
                    entries: Some(vec![KernelHomeEntryPayload {
                        subject_id: beneficiary.into(),
                        capability: "manage".into(),
                    }]),
                })
                .unwrap(),
                actor: Some(beneficiary.into()),
            },
            &mut acts,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        id
    }
    /// A real preferences record owned by `owner`, created in `home`.
    pub(super) async fn record_in(&self, owner: &str, home: &str) -> String {
        create_json_as(
            &self.db,
            owner,
            crate::v2_standard::foci::PREFERENCES_FAMILY,
            "focus_preferences",
            r#"{"foci":[]}"#,
            home,
        )
        .await
        .unwrap()
    }
    pub(super) async fn state(&self) -> State {
        State {
            events: sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
                .fetch_one(self.db.pool())
                .await
                .unwrap(),
            acts: sqlx::query_scalar("SELECT COUNT(DISTINCT act) FROM content_events")
                .fetch_one(self.db.pool())
                .await
                .unwrap(),
            next_act: sqlx::query_scalar("SELECT next_act FROM act_state WHERE singleton=1")
                .fetch_one(self.db.pool())
                .await
                .unwrap(),
            dump: dump_all_kernel_tables(&self.db).await.unwrap(),
        }
    }
    /// The sealed route with a caller-built spec, committed on success.
    pub(super) async fn append_raw(&self, spec: AppendSpec) -> Result<EventRow> {
        let mut tx = begin_write(self.db.write_pool()).await?;
        let mut acts = crate::act::ActAllocation::new();
        let event = crate::store::append_kernel_slot_in(&self.db, &mut tx, spec, &mut acts).await?;
        tx.commit().await?;
        Ok(event)
    }
    pub(super) async fn register(
        &self,
        principal: &str,
        slot: &str,
        target: &str,
        previous: Option<&str>,
    ) -> Result<EventRow> {
        let mut tx = begin_write(self.db.write_pool()).await?;
        let mut acts = crate::act::ActAllocation::new();
        let event = slots::append_registration_in(
            &self.db, &mut tx, &mut acts, principal, slot, target, previous, "fixture",
        )
        .await?;
        tx.commit().await?;
        Ok(event)
    }
    /// Run a registration that must refuse, and prove it left nothing behind.
    pub(super) async fn refused(&self, spec: AppendSpec, message: &str) {
        let before = self.state().await;
        engine_error(self.append_raw(spec).await, message);
        assert_eq!(before, self.state().await);
    }
    pub(super) async fn replay_equal(&self) {
        let before = dump_all_kernel_tables(&self.db).await.unwrap();
        replay_all_projections(&self.db).await.unwrap();
        assert_eq!(before, dump_all_kernel_tables(&self.db).await.unwrap());
    }
}

pub(super) fn spec(principal: &str, event_type: &str, payload: Value) -> AppendSpec {
    AppendSpec {
        record_id: principal.into(),
        event_type: event_type.into(),
        payload,
        actor: Some(principal.into()),
    }
}
pub(super) fn provisioned(slot: &str, target: &str) -> Value {
    json!({"slot": slot, "target_id": target, "reason": "fixture"})
}
pub(super) fn replaced(slot: &str, previous: &str, target: &str) -> Value {
    json!({"slot": slot, "previous_target_id": previous, "target_id": target, "reason": "fixture"})
}

#[tokio::test]
async fn provision_and_replace_fold_into_slots_and_lineage() {
    let w = World::fresh().await;
    let (h1, h2) = (w.home(&w.other).await, w.home(&w.other).await);
    let first = w
        .register(&w.other, HOME_FOCI_PRIVATE, &h1, None)
        .await
        .unwrap();
    // The preferences record sits in the slot's current home, so the record
    // registration is structurally valid.
    let r1 = w.record_in(&w.other, &h1).await;
    let record_event = w
        .register(&w.other, RECORD_FOCI_PREFERENCES, &r1, None)
        .await
        .unwrap();
    // Replacing the home admits on structure alone: the old home still holds
    // the preferences record, which is recovery debt, not a registration error.
    let second = w
        .register(&w.other, HOME_FOCI_PRIVATE, &h2, Some(&h1))
        .await
        .unwrap();
    let dump = dump_all_kernel_tables(&w.db).await.unwrap();
    assert_eq!(
        dump.slots,
        vec![
            (
                w.other.clone(),
                HOME_FOCI_PRIVATE.to_string(),
                h2.clone(),
                2,
                second.local_seq
            ),
            (
                w.other.clone(),
                RECORD_FOCI_PREFERENCES.to_string(),
                r1.clone(),
                1,
                record_event.local_seq
            ),
        ]
    );
    // Every target the slot ever held stays in lineage, in generation order.
    assert_eq!(
        dump.slot_lineage,
        vec![
            (
                w.other.clone(),
                HOME_FOCI_PRIVATE.to_string(),
                1,
                h1.clone(),
                None,
                first.local_seq
            ),
            (
                w.other.clone(),
                HOME_FOCI_PRIVATE.to_string(),
                2,
                h2.clone(),
                Some(h1.clone()),
                second.local_seq
            ),
            (
                w.other.clone(),
                RECORD_FOCI_PREFERENCES.to_string(),
                1,
                r1,
                None,
                record_event.local_seq
            ),
        ]
    );
    // The event is the principal's own: the aggregate and the actor.
    let (record_id, actor): (String, String) =
        sqlx::query_as("SELECT record_id, actor FROM content_events WHERE seq=?")
            .bind(first.local_seq)
            .fetch_one(w.db.pool())
            .await
            .unwrap();
    assert_eq!((record_id, actor), (w.other.clone(), w.other.clone()));
}

/// Design fixture 11: a replaced-away target cannot return, and no two
/// principals can register one target.
#[tokio::test]
async fn fold_refuses_a_replaced_away_or_foreign_target() {
    let w = World::fresh().await;
    let (h1, h2) = (w.home(&w.other).await, w.home(&w.other).await);
    w.register(&w.other, HOME_FOCI_PRIVATE, &h1, None)
        .await
        .unwrap();
    w.register(&w.other, HOME_FOCI_PRIVATE, &h2, Some(&h1))
        .await
        .unwrap();
    // The replaced-away home cannot come back as a third generation.
    w.refused(
        spec(
            &w.other,
            slots::REPLACED,
            replaced(HOME_FOCI_PRIVATE, &h2, &h1),
        ),
        "slot target is already registered",
    )
    .await;
    // Another principal cannot register the target the first one holds.
    w.refused(
        spec(
            &w.admin,
            slots::PROVISIONED,
            provisioned(HOME_FOCI_PRIVATE, &h2),
        ),
        "slot target is already registered",
    )
    .await;
    // Nor can another principal register the replaced-away target afresh.
    w.refused(
        spec(
            &w.admin,
            slots::PROVISIONED,
            provisioned(HOME_FOCI_PRIVATE, &h1),
        ),
        "slot target is already registered",
    )
    .await;
    w.replay_equal().await;
}

/// Design fixture 40, fold part: malformed events are refused with no write.
#[tokio::test]
async fn fold_refuses_malformed_slot_events() {
    let w = World::fresh().await;
    let home = w.home(&w.other).await;
    let other_home = w.home(&w.other).await;
    let p = w.other.clone();

    // Unknown field, unknown slot, blank reason.
    let mut extra = provisioned(HOME_FOCI_PRIVATE, &home);
    extra["unexpected"] = json!(true);
    assert!(w
        .append_raw(spec(&p, slots::PROVISIONED, extra))
        .await
        .is_err());
    w.refused(
        spec(
            &p,
            slots::PROVISIONED,
            provisioned("home:not_registered", &home),
        ),
        "unknown slot",
    )
    .await;
    for reason in ["", "   "] {
        w.refused(
            spec(
                &p,
                slots::PROVISIONED,
                json!({"slot": HOME_FOCI_PRIVATE, "target_id": home, "reason": reason}),
            ),
            "slot event reason must not be blank",
        )
        .await;
    }

    // Ids must be canonical lowercase v4 or v7 with the RFC 4122 variant.
    for bad in [
        home.to_uppercase(),
        "11111111-1111-1111-8111-111111111111".to_string(), // version 1
        "55555555-5555-5555-8555-555555555555".to_string(), // version 5
        "44444444-4444-4444-c444-444444444444".to_string(), // wrong variant
        "not-a-uuid".to_string(),
    ] {
        w.refused(
            spec(&p, slots::PROVISIONED, provisioned(HOME_FOCI_PRIVATE, &bad)),
            "invalid slot target id",
        )
        .await;
        w.refused(
            spec(
                &p,
                slots::REPLACED,
                replaced(HOME_FOCI_PRIVATE, &bad, &home),
            ),
            "invalid slot target id",
        )
        .await;
    }
    w.refused(
        spec(
            &p,
            slots::REPLACED,
            replaced(HOME_FOCI_PRIVATE, &home, &home),
        ),
        "slot replacement must change the target",
    )
    .await;

    // The actor must be the principal, and the principal an account.
    w.refused(
        AppendSpec {
            actor: Some(w.admin.clone()),
            ..spec(
                &p,
                slots::PROVISIONED,
                provisioned(HOME_FOCI_PRIVATE, &home),
            )
        },
        "slot event actor must be the slot principal",
    )
    .await;
    let agent = create_principal(&w.db, "agent", "Agent", "agent:a", &w.admin)
        .await
        .unwrap();
    w.refused(
        spec(
            &agent,
            slots::PROVISIONED,
            provisioned(HOME_FOCI_PRIVATE, &home),
        ),
        "slot principal must be an account",
    )
    .await;
    w.refused(
        spec(
            &Uuid::new_v4().to_string(),
            slots::PROVISIONED,
            provisioned(HOME_FOCI_PRIVATE, &home),
        ),
        "slot principal must be an account",
    )
    .await;

    // Targets must exist, in the table the slot's type names.
    let missing = Uuid::new_v4().to_string();
    for slot in [HOME_FOCI_PRIVATE, RECORD_FOCI_PREFERENCES] {
        w.refused(
            spec(&p, slots::PROVISIONED, provisioned(slot, &missing)),
            "slot target does not exist",
        )
        .await;
    }
    w.refused(
        spec(
            &p,
            slots::PROVISIONED,
            provisioned(RECORD_FOCI_PREFERENCES, &home),
        ),
        "slot target does not exist",
    )
    .await;
    w.refused(
        spec(
            &p,
            slots::PROVISIONED,
            provisioned(HOME_FOCI_PRIVATE, KERNEL_ROOT_ID),
        ),
        "invalid slot target id",
    )
    .await;

    // Lineage must agree with the current row.
    w.refused(
        spec(
            &p,
            slots::REPLACED,
            replaced(HOME_FOCI_PRIVATE, &home, &other_home),
        ),
        "slot replacement has no current target",
    )
    .await;
    w.register(&p, HOME_FOCI_PRIVATE, &home, None)
        .await
        .unwrap();
    w.refused(
        spec(
            &p,
            slots::PROVISIONED,
            provisioned(HOME_FOCI_PRIVATE, &other_home),
        ),
        "slot is already provisioned",
    )
    .await;
    let stale = w.home(&p).await;
    w.refused(
        spec(
            &p,
            slots::REPLACED,
            replaced(HOME_FOCI_PRIVATE, &stale, &other_home),
        ),
        "slot replacement does not match the current target",
    )
    .await;
    w.replay_equal().await;
}

/// The sealed route accepts only slot events.
#[tokio::test]
async fn sealed_route_accepts_only_slot_events() {
    let w = World::fresh().await;
    let home = w.home(&w.other).await;
    w.refused(
        spec(
            &w.other,
            KERNEL_HOME_CREATED_EVENT,
            json!({"parent_id": KERNEL_ROOT_ID, "owner_id": w.other}),
        ),
        "kernel slot admission requires a slot event",
    )
    .await;
    w.refused(
        spec(
            &w.other,
            "record.created",
            provisioned(HOME_FOCI_PRIVATE, &home),
        ),
        "kernel slot admission requires a slot event",
    )
    .await;
}

/// Design fixture 41: the generic, public, import and projector-intent seams
/// refuse every slot event (the two registrations and, from G6, the sealed
/// home creation), and nothing is written.
#[tokio::test]
async fn generic_public_import_and_projector_seams_refuse_slot_events() {
    use crate::domain_transaction::{EventCursorPort, ProjectorIntent, ProjectorPort};
    use crate::events::{CausalAdmission, CausalEnvelopeV1, CausalFrontierV1};
    use crate::portable_sql::ExecutionControl;
    struct NoAppend;
    impl EventCursorPort for NoAppend {
        fn append_event<'a>(
            &'a mut self,
            _: &'a mut EventRow,
            _: &'a CausalAdmission,
            _: &'a ExecutionControl,
        ) -> futures::future::BoxFuture<'a, Result<i64>> {
            Box::pin(async { panic!("generic slot append reached physical storage") })
        }
    }
    impl ProjectorPort for NoAppend {
        fn apply_projector<'a>(
            &'a mut self,
            _: &'a ProjectorIntent,
            _: &'a EventRow,
            _: &'a ExecutionControl,
        ) -> futures::future::BoxFuture<'a, Result<()>> {
            Box::pin(async { panic!("generic slot import reached projection") })
        }
    }
    let w = World::fresh().await;
    let home = w.home(&w.other).await;
    let other_home = w.home(&w.other).await;
    for (event_type, payload) in [
        (slots::PROVISIONED, provisioned(HOME_FOCI_PRIVATE, &home)),
        (
            slots::REPLACED,
            replaced(HOME_FOCI_PRIVATE, &home, &other_home),
        ),
        // Design fixture 48: the sealed home-creation type is refused by the
        // same five barriers and the unlogged-event projector check.
        (
            slots::HOME_CREATED_FOR,
            json!({"parent_id": home, "owner_id": w.other, "slot": HOME_FOCI_PRIVATE}),
        ),
    ] {
        let before = w.state().await;
        let slot_spec = || spec(&w.other, event_type, payload.clone());

        // Public append.
        engine_error(
            crate::store::append(&w.db, slot_spec()).await,
            "slot events are kernel slot-route-owned and cannot be appended through the public event seam",
        );
        // Generic in-transaction append.
        let mut tx = begin_write(w.db.write_pool()).await.unwrap();
        let mut acts = crate::act::ActAllocation::new();
        engine_error(
            append_in(&w.db, &mut tx, slot_spec(), &mut acts).await,
            "slot events require the sealed kernel slot route",
        );
        tx.rollback().await.unwrap();
        // Import.
        let mut conn = w.db.write_pool().begin().await.unwrap();
        engine_error(
            crate::store::append_migration_on(
                &mut conn,
                Uuid::new_v4().to_string(),
                slot_spec(),
                "2026-10-13T00:00:00Z",
            )
            .await,
            "slot events cannot be imported through the generic event seam",
        );
        conn.rollback().await.unwrap();
        // The shared domain kernel, ordinary and governed import.
        let mut event = EventRow {
            local_seq: -1,
            id: Uuid::new_v4().to_string(),
            record_id: w.other.clone(),
            event_type: event_type.into(),
            payload: Some(payload.to_string()),
            actor: Some(w.other.clone()),
            created_at: "2026-10-13T00:00:00Z".into(),
            run_key: None,
            parent_key: None,
            intent: None,
            act: None,
            causal_envelope: CausalEnvelopeV1::legacy_unknown(),
        };
        engine_error(
            crate::domain_transaction::append_and_project(
                &mut NoAppend,
                &mut event,
                &ExecutionControl::default(),
            )
            .await,
            "slot events require the sealed kernel slot route",
        );
        let causal = CausalAdmission::GovernedImport(CausalEnvelopeV1::import_incomplete(
            CausalFrontierV1::empty(),
        ));
        engine_error(
            crate::domain_transaction::append_and_project_governed_import(
                &mut NoAppend,
                &mut event,
                &causal,
                &ExecutionControl::default(),
            )
            .await,
            "slot events require the sealed kernel slot route",
        );
        // Projecting an event the kernel never logged is refused: the fold
        // cannot be driven directly with a forged envelope.
        let mut tx = w.db.write_pool().begin().await.unwrap();
        engine_error(
            crate::projector::project(&mut tx, &event).await,
            "slot projection requires the kernel-issued logged event",
        );
        tx.rollback().await.unwrap();
        assert_eq!(before, w.state().await);
    }
    // The sealed route is closed to imported causality as well.
    let mut tx = begin_write(w.db.write_pool()).await.unwrap();
    let mut acts = crate::act::ActAllocation::new();
    slots::append_registration_in(
        &w.db,
        &mut tx,
        &mut acts,
        &w.other,
        HOME_FOCI_PRIVATE,
        &home,
        None,
        "fixture",
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    w.replay_equal().await;
}

/// Design fixture 42: dump, replay, dump again is the identity, after
/// provision, replace, several generations and a policy widen; and the same
/// holds from a database closed and reopened from its file. Replay is policy
/// independent: the fold never reads today's policy, so a widened home does
/// not change what is rebuilt. The recovery trace itself is increment 6.
#[tokio::test]
async fn replay_rebuilds_both_tables_identically() {
    let mut w = World::fresh().await;
    let h = [
        w.home(&w.other).await,
        w.home(&w.other).await,
        w.home(&w.other).await,
    ];
    let admin_home = w.home(&w.admin).await;
    w.register(&w.other, HOME_FOCI_PRIVATE, &h[0], None)
        .await
        .unwrap();
    w.replay_equal().await;
    let r0 = w.record_in(&w.other, &h[0]).await;
    w.register(&w.other, RECORD_FOCI_PREFERENCES, &r0, None)
        .await
        .unwrap();
    w.register(&w.admin, HOME_FOCI_PRIVATE, &admin_home, None)
        .await
        .unwrap();
    w.register(&w.other, HOME_FOCI_PRIVATE, &h[1], Some(&h[0]))
        .await
        .unwrap();
    w.register(&w.other, HOME_FOCI_PRIVATE, &h[2], Some(&h[1]))
        .await
        .unwrap();
    // r0 still sits in the first home (recovery debt). Move it to the current
    // home, as a recovery batch would, so a replacement record is admissible.
    rehome_record_as(&w.db, &w.other, &r0, &h[2]).await.unwrap();
    let r1 = w.record_in(&w.other, &h[2]).await;
    w.register(&w.other, RECORD_FOCI_PREFERENCES, &r1, Some(&r0))
        .await
        .unwrap();
    w.replay_equal().await;
    let dump = dump_all_kernel_tables(&w.db).await.unwrap();
    assert_eq!(dump.slots.len(), 3);
    assert_eq!(dump.slot_lineage.len(), 6);
    let index: Option<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_kernel_records_home_owner'",
    )
    .fetch_optional(w.db.pool())
    .await
    .unwrap();
    assert!(index.is_some());

    // Widen the current home, then replay: the fold ignores today's policy.
    replace_home_policy(
        &w.db,
        &w.other,
        &h[2],
        &[(&w.other, "manage"), (&w.admin, "view")],
    )
    .await
    .unwrap();
    w.replay_equal().await;
    // The widen changed the policy tables but not the slot tables.
    let widened = dump_all_kernel_tables(&w.db).await.unwrap();
    assert_ne!(dump.entries, widened.entries);
    assert_eq!(dump.slots, widened.slots);
    assert_eq!(dump.slot_lineage, widened.slot_lineage);

    // Close every handle and reopen the same file. The persisted projections
    // equal what a replay rebuilds, and the replay is still the identity.
    let before = dump_all_kernel_tables(&w.db).await.unwrap();
    w.reopen().await;
    assert_eq!(before, dump_all_kernel_tables(&w.db).await.unwrap());
    w.replay_equal().await;
    // Today's policy is read from data, not carried in memory: the widened
    // home is still reported after the reopen.
    let receipt = super::slots_eval::inspect(&w.db, &w.other, HOME_FOCI_PRIVATE)
        .await
        .unwrap();
    assert_eq!(
        receipt.reason,
        Some(super::slots_eval::UnusableReason::NotPrivate)
    );
}
