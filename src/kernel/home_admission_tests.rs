//! Shared home admission fixtures (Foci v2 G6 increment 3b; design note 681a449
//! §3.3, §4.2, §7, §8): fixture 49 for owner = actor on the generic home event
//! and fixture 79 for record and home id disjointness. Both run on every route
//! that appends, including the direct migration path, which calls the hook
//! explicitly. The governed-import route lives in `store.rs`, because only that
//! module can build a prepared event with authenticated source facts.
use super::slots::{self, HOME_FOCI_PRIVATE};
use super::slots_home_for_tests::Fx;
use super::slots_tests::{engine_error, World};
use super::*;
use serde_json::{json, Value};

const OWNER_NOT_ACTOR: &str =
    "a home can be created for another owner only through the sealed home_created_for route";
const NOT_FRESH: &str = "home id is not fresh";
const RECORD_IS_HOME: &str = "record id is already a home";

/// Every route that reaches `append_prepared_admitted`, plus the migration
/// path that bypasses it. Each attempt runs in its own transaction, rolled
/// back, so one world serves every route; the public seams commit their own
/// transaction and are only used with a spec that must refuse.
const ROUTES: [&str; 8] = [
    "append_in",
    "append_with_event_id_in",
    "append_engine_provisioned_in",
    "append_engine_derived_in",
    "append_engine_seed_batch",
    "append (public)",
    "append_batch (public)",
    "append_migration_on",
];

async fn attempt(w: &World, route: &str, spec: AppendSpec) -> Result<()> {
    use crate::store;
    let mut tx = begin_write(w.db.write_pool()).await?;
    let mut acts = crate::act::ActAllocation::new();
    let outcome = match route {
        "append_in" => store::append_in(&w.db, &mut tx, spec, &mut acts)
            .await
            .map(drop),
        "append_with_event_id_in" => store::append_with_event_id_in(
            &w.db,
            &mut tx,
            Uuid::new_v4().to_string(),
            spec,
            &mut acts,
        )
        .await
        .map(drop),
        "append_engine_provisioned_in" => {
            store::append_engine_provisioned_in(&w.db, &mut tx, spec, &mut acts)
                .await
                .map(drop)
        }
        "append_engine_derived_in" => {
            store::append_engine_derived_in(&w.db, &mut tx, spec, &mut acts)
                .await
                .map(drop)
        }
        "append_engine_seed_batch" => {
            tx.rollback().await?;
            return store::append_engine_seed_batch(&w.db, vec![spec])
                .await
                .map(drop);
        }
        "append (public)" => {
            tx.rollback().await?;
            return store::append(&w.db, spec).await.map(drop);
        }
        "append_batch (public)" => {
            tx.rollback().await?;
            return store::append_batch(&w.db, vec![spec]).await.map(drop);
        }
        "append_migration_on" => store::append_migration_on(
            &mut tx,
            Uuid::new_v4().to_string(),
            spec,
            "2026-10-15T00:00:00Z",
        )
        .await
        .map(drop),
        other => panic!("unknown route {other}"),
    };
    tx.rollback().await?;
    outcome
}

/// The attempt is refused with `message` on every route, and writes nothing.
async fn refused_everywhere(w: &World, spec: impl Fn() -> AppendSpec, message: &str) {
    for route in ROUTES {
        let before = w.state().await;
        let result = attempt(w, route, spec()).await;
        match result {
            Err(Error::Engine(got)) => assert_eq!(got, message, "route {route}"),
            other => panic!("route {route}: expected Engine({message}), got {other:?}"),
        }
        assert_eq!(before, w.state().await, "route {route} wrote");
    }
}

fn home_spec(id: &str, actor: &str, owner: &str) -> AppendSpec {
    AppendSpec {
        record_id: id.into(),
        event_type: KERNEL_HOME_CREATED_EVENT.into(),
        payload: json!({"parent_id": KERNEL_ROOT_ID, "owner_id": owner, "entries": []}),
        actor: Some(actor.into()),
    }
}

fn record_spec(id: &str, actor: &str) -> AppendSpec {
    AppendSpec {
        record_id: id.into(),
        event_type: "kernel.record_created.v1".into(),
        payload: serde_json::to_value(KernelRecordPayload {
            home_id: KERNEL_ROOT_ID.into(),
            owner_id: None,
            primary_type: None,
            kind: None,
            accession: None,
            pin: None,
            interpreter: None,
            fields: None,
        })
        .unwrap(),
        actor: Some(actor.into()),
    }
}

/// Run `project` on an event that is neither admitted nor logged, in a
/// transaction that is rolled back: the historical fold, driven directly.
async fn fold_direct(w: &World, event: EventRow) -> Result<()> {
    let mut tx = begin_write(w.db.write_pool()).await?;
    let result = match event.event_type.as_str() {
        KERNEL_HOME_CREATED_EVENT => project_kernel_home_created(&mut tx, &event).await,
        "kernel.record_created.v1" => project_kernel_record_created(&mut tx, &event).await,
        other => panic!("unexpected fold {other}"),
    };
    tx.rollback().await?;
    result
}

async fn max_seq(w: &World) -> i64 {
    sqlx::query_scalar("SELECT COALESCE(MAX(seq),1) FROM content_events")
        .fetch_one(w.db.pool())
        .await
        .unwrap()
}

fn as_event(w_seq: i64, spec: AppendSpec) -> EventRow {
    EventRow {
        local_seq: w_seq,
        id: Uuid::new_v4().to_string(),
        record_id: spec.record_id,
        event_type: spec.event_type,
        payload: Some(spec.payload.to_string()),
        actor: spec.actor,
        run_key: None,
        parent_key: None,
        intent: None,
        created_at: "2026-10-15T00:00:00.000Z".into(),
        act: None,
        causal_envelope: crate::events::CausalEnvelopeV1::legacy_unknown(),
    }
}

/// Design fixture 49: the generic `home_created.v1` refuses owner ≠ actor on
/// every route, the migration path included; owner = actor and `create_home`
/// are accepted; the historical fold still accepts an owner ≠ actor row, so
/// replay of an existing log works.
#[tokio::test]
async fn generic_home_event_refuses_a_foreign_owner_on_every_route() {
    let w = World::fresh().await;
    let new_id = || Uuid::new_v4().to_string();

    // Owner ≠ actor, for the admin acting and for the owner's own id.
    refused_everywhere(
        &w,
        || home_spec(&new_id(), &w.admin, &w.other),
        OWNER_NOT_ACTOR,
    )
    .await;
    refused_everywhere(
        &w,
        || home_spec(&new_id(), &w.other, &w.admin),
        OWNER_NOT_ACTOR,
    )
    .await;
    // No actor at all cannot equal an owner.
    refused_everywhere(
        &w,
        || AppendSpec {
            actor: None,
            ..home_spec(&new_id(), &w.admin, &w.other)
        },
        OWNER_NOT_ACTOR,
    )
    .await;

    // Owner = actor is accepted on the in-transaction route and on the
    // migration path (the positive controls), and through `create_home`.
    for route in ["append_in", "append_migration_on"] {
        attempt(&w, route, home_spec(&new_id(), &w.other, &w.other))
            .await
            .unwrap_or_else(|e| panic!("route {route} refused owner = actor: {e}"));
    }
    let home = create_home(&w.db, KERNEL_ROOT_ID, Some(&[(&w.other, "view")]), &w.admin)
        .await
        .unwrap();
    let owner: String = sqlx::query_scalar("SELECT owner_id FROM kernel_roots WHERE root_id=?")
        .bind(&home)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    assert_eq!(owner, w.admin);

    // The fold itself stays permissive: replaying an old log must not fail.
    let seq = max_seq(&w).await;
    fold_direct(&w, as_event(seq, home_spec(&new_id(), &w.admin, &w.other)))
        .await
        .expect("the historical fold accepts owner != actor");
    w.replay_equal().await;
}

/// Design fixture 79: the record and home id spaces stay disjoint on every
/// route. A record id may not already be a home; a home id may not already be
/// a record, for the generic and the sealed type alike. The historical folds
/// stay permissive for the legacy types; the sealed type's fold refuses.
#[tokio::test]
async fn record_and_home_ids_stay_disjoint_on_every_route() {
    let fx = Fx::fresh().await;
    let w = &fx.w;
    let home = w.home(&w.other).await;
    let record = w.record_in(&w.other, &home).await;

    // A record id that is already a home.
    refused_everywhere(w, || record_spec(&home, &w.other), RECORD_IS_HOME).await;
    // The workspace root is a home too.
    refused_everywhere(w, || record_spec(KERNEL_ROOT_ID, &w.other), RECORD_IS_HOME).await;
    // A generic home id that is already a record.
    refused_everywhere(w, || home_spec(&record, &w.other, &w.other), NOT_FRESH).await;

    // The sealed type: its route is the slot route only, so the shared hook is
    // reached through `append_kernel_slot_in`. The type is refused on every
    // other route before admission (fixture 48), so only the sealed route is
    // exercised here.
    let sealed = |id: &str| AppendSpec {
        record_id: id.into(),
        event_type: slots::HOME_CREATED_FOR.into(),
        payload: json!({"parent_id": fx.p0, "owner_id": w.other, "slot": HOME_FOCI_PRIVATE}),
        actor: Some(fx.svc.clone()),
    };
    w.refused(sealed(&record), NOT_FRESH).await;
    w.refused(sealed(&home), NOT_FRESH).await;
    w.refused(sealed(&fx.p0), NOT_FRESH).await;
    w.refused(sealed(KERNEL_ROOT_ID), "home id is not a canonical id")
        .await;

    // Fresh ids still pass, so the guard is not a blanket refusal.
    attempt(
        w,
        "append_in",
        record_spec(&Uuid::new_v4().to_string(), &w.other),
    )
    .await
    .unwrap();
    attempt(
        w,
        "append_in",
        home_spec(&Uuid::new_v4().to_string(), &w.other, &w.other),
    )
    .await
    .unwrap();

    // The legacy folds accept an overlapping row, so an existing log replays.
    let seq = max_seq(w).await;
    fold_direct(w, as_event(seq, record_spec(&home, &w.other)))
        .await
        .expect("the legacy record fold accepts a home id");
    fold_direct(w, as_event(seq, home_spec(&record, &w.other, &w.other)))
        .await
        .expect("the legacy home fold accepts a record id");

    // The sealed type's fold refuses an overlap. The event is logged by hand
    // so that the fold's logged-match check passes and its own rule decides.
    let payload: Value =
        json!({"parent_id": fx.p0, "owner_id": w.other, "slot": HOME_FOCI_PRIVATE});
    let mut tx = begin_write(w.db.write_pool()).await.unwrap();
    let created_at = "2026-10-15T00:00:00.000Z";
    let id = Uuid::new_v4().to_string();
    let seq: i64 = sqlx::query_scalar(
        "INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status)
         VALUES(?,?,?,?,?,?,1,'legacy_unknown') RETURNING seq",
    )
    .bind(&id)
    .bind(&record)
    .bind(slots::HOME_CREATED_FOR)
    .bind(payload.to_string())
    .bind(&fx.svc)
    .bind(created_at)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    let event = EventRow {
        id,
        local_seq: seq,
        created_at: created_at.into(),
        payload: Some(payload.to_string()),
        ..as_event(
            seq,
            AppendSpec {
                record_id: record.clone(),
                event_type: slots::HOME_CREATED_FOR.into(),
                payload: json!({}),
                actor: Some(fx.svc.clone()),
            },
        )
    };
    engine_error(slots::project(&mut tx, &event).await, NOT_FRESH);
    tx.rollback().await.unwrap();
    w.replay_equal().await;
}
