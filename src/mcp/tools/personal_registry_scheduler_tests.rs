use super::*;
use crate::db::Db;
use crate::mcp::{register_surface_tools, ToolRegistry};
use crate::need_subscriptions::{params_digest, NeedSinkFrame, SurfaceBinding};
use serde_json::json;

const ARTIFACT: &str = "47f00000-0000-4000-8000-000000000001";
const PACKAGE: &str = "agent.attention-cockpit";

// Seed a fully pinned stored install, not an adoption authority proof. All
// scheduler evaluation, SQL, access/source gates and sink delivery are real.
async fn fixture() -> (
    tempfile::TempDir,
    Db,
    NeedScheduler,
    ConnectionToken,
    SubscriptionId,
    tokio::sync::mpsc::Receiver<NeedSinkFrame>,
) {
    let dir = tempfile::tempdir().unwrap();
    let db = crate::create_database(dir.path().join("scheduler.sqlite").to_str().unwrap())
        .await
        .unwrap();
    let mut tools = ToolRegistry::new();
    register_surface_tools(&mut tools).unwrap();
    let body = r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Scheduler</title></head><body><main>Fixture</main></body></html>"#;
    Box::pin(tools.call(db.clone(), Caller::local(), "create_record", json!({"id":ARTIFACT,"type":"Document","kind":"artifact","name":"Scheduler", "body":body,"facets":{"runtime":"native.html.v1"},"reason":"Scheduler retirement fixture."}))).await.unwrap();
    crate::authorization::replace_explicit_policy(
        &db,
        "test:policy",
        ARTIFACT,
        vec![crate::authorization::AllowEntry::account(
            "alice",
            crate::authorization::Capability::View,
        )],
    )
    .await
    .unwrap();
    let source: String = sqlx::query_scalar("SELECT id FROM content_events WHERE record_id=? AND json_type(payload,'$.body') IS NOT NULL ORDER BY seq DESC LIMIT 1").bind(ARTIFACT).fetch_one(db.pool()).await.unwrap();
    let declaration = json!({"needs":["attention.query.v1",{"need":"sql.snapshot.v1","key":"graph.neighbours","label":"Names","sql":"SELECT name FROM records WHERE id = ?1 ORDER BY id","params":[{"name":"record_id","type":"text","max_len":64}]}],"effects":[]});
    use crate::mcp::tools::alpha_tabs::{
        alpha_tab_bundle_digest, alpha_tab_declaration_digest, alpha_tab_digest,
    };
    let decl = alpha_tab_declaration_digest(&declaration).unwrap();
    let digest = alpha_tab_digest(&alpha_tab_bundle_digest(body), &decl, "native.html.v1");
    let installed = Box::pin(tools.call(db.clone(), Caller::authenticated("alice"), "manage_alpha_tabs", json!({"action":"install","package":PACKAGE,"version":"0.1.0","digest":digest,"artifact_id":ARTIFACT,"source_revision":source,"declaration":declaration,"reason":"Pinned scheduler fixture."}))).await.unwrap();
    let previous_event = installed["install"]["event_id"]
        .as_str()
        .unwrap()
        .to_owned();
    // Canonical adopted control history, as in control_tests. Receipt fields
    // are fixture assertions, not a preview/consent authority proof. Reopen
    // must validate the actual log/projection without a direct row patch.
    use crate::control::{self, AlphaTabAdoptPayload, ControlEventPayload, NewControlEvent};
    let adopted = control::append_control_event(
        &db,
        NewControlEvent::authored(
            "scheduler-adopt-fixture",
            control::alpha_tab_aggregate_id("alice", PACKAGE),
            "alice",
            None,
            "Scheduler fixture adopted history.",
            ControlEventPayload::AlphaTabAdopted(AlphaTabAdoptPayload {
                account_id: "alice".into(),
                package: PACKAGE.into(),
                version: "0.1.0".into(),
                digest,
                artifact_id: ARTIFACT.into(),
                consented_source_revision: source,
                declaration_digest: decl,
                consented_declaration: declaration,
                adoption: control::ALPHA_TAB_ADOPTION_VERIFIED.into(),
                previous_event_id: previous_event,
                receipt_id: Some("preview_scheduler_fixture".into()),
                preview_session: Some("scheduler-fixture-session".into()),
                launch_id: None,
                authored_run_key: None,
                request: None,
            }),
        )
        .unwrap(),
    )
    .await
    .unwrap();
    let event = adopted.id;
    let (db, hub) = RealtimeHub::attach(db, None).await.unwrap();
    hub.refresh_scheduler_handle(&db);
    let database = crate::identity::database_id(&db).await.unwrap();
    let mut registry = hub.need_registry().lock().unwrap();
    let token = registry.register_connection("alice", &database, true);
    let id = registry
        .subscribe_pending(
            &token,
            "alice",
            &database,
            SurfaceBinding::alpha_tab(PACKAGE, &event),
            "attention.query.v1",
            &params_digest(None),
        )
        .unwrap();
    registry.activate(&token, &id, "old-snapshot");
    let (sender, receiver) = tokio::sync::mpsc::channel(32);
    registry.register_sink(&token, sender);
    drop(registry);
    (dir, db, NeedScheduler::new(hub), token, id, receiver)
}

async fn interrupted(phase: &'static str, terminal: bool) {
    let (dir, db, mut scheduler, token, id, mut sink) = fixture().await;
    let hub = scheduler.hub.clone();
    let event = hub
        .need_registry()
        .lock()
        .unwrap()
        .subscription_state(&token, &id)
        .unwrap()
        .binding
        .install_event_id;
    if phase == "keyed" {
        let (_, baseline, _, _) = rerun_snapshot_for_scheduler(
            &db,
            &Caller::authenticated("alice").with_hosting_member(true),
            PACKAGE,
            &event,
            &mut false,
            None,
        )
        .await
        .unwrap();
        let database = crate::identity::database_id(&db).await.unwrap();
        let mut registry = hub.need_registry().lock().unwrap();
        registry.activate(&token, &id, &baseline);
        registry.admit_keyed_read(
            &token,
            &id,
            "alice",
            &database,
            PACKAGE,
            &event,
            crate::keyed_freshness::KeyedFingerprint {
                key: "graph.neighbours".into(),
                params: json!({"record_id":ARTIFACT}),
                params_digest: params_digest(Some(&json!({"record_id":ARTIFACT}))),
                revision: "prior-keyed-revision".into(),
                relations: std::collections::BTreeSet::from(["records".into()]),
            },
        );
    }
    {
        let mut registry = hub.need_registry().lock().unwrap();
        if phase != "keyed" {
            registry.activate_with_clock(&token, &id, "old-snapshot", true);
            registry.set_clock_due_for_test(&token, &id, Instant::now() - Duration::from_secs(1));
            registry.mark_due_clock_ticks(Instant::now());
        }
        registry.mark_content_event_with_act(Some(77));
        registry.mark_content_event_with_act(None);
        registry.enqueue_dirty_with_trigger(&token, &id, true, Trigger::Control);
    }
    let original = hub
        .need_registry()
        .lock()
        .unwrap()
        .subscription_state(&token, &id)
        .unwrap();
    let held_hub = hub.clone();
    let handle = db.clone();
    let token_for_hook = token.clone();
    let id_for_hook = id.clone();
    let hook: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(move |point| {
        if point == phase {
            if terminal {
                held_hub.terminalize();
            } else {
                held_hub.retire_scheduler_handle(&handle);
                // A later wake races the drained work; merging must retain both.
                let mut registry = held_hub.need_registry().lock().unwrap();
                registry.mark_content_event_with_act(Some(78));
                if phase != "keyed" {
                    registry.set_clock_due_for_test(
                        &token_for_hook,
                        &id_for_hook,
                        Instant::now() - Duration::from_secs(1),
                    );
                    registry.mark_due_clock_ticks(Instant::now());
                }
            }
        }
    });
    if phase == "closed" {
        db.close().await;
    }
    assert!(
        RETIREMENT_BOUNDARY
            .scope(hook, scheduler.drain_one(&token))
            .await
    );
    assert!(sink.try_recv().is_err());
    if terminal {
        assert!(hub.is_terminal());
        assert_eq!(hub.need_registry().lock().unwrap().dirty_len(&token), 0);
        assert!(!scheduler.drain_one(&token).await);
        db.close().await;
        return;
    }
    {
        let registry = hub.need_registry().lock().unwrap();
        let state = registry.subscription_state(&token, &id).unwrap();
        assert!(state.dirty && !state.in_flight);
        assert_eq!(
            state.pending_acts,
            if phase == "closed" {
                std::collections::VecDeque::from([77])
            } else {
                std::collections::VecDeque::from([77, 78])
            }
        );
        assert!(state.unknown_act_pending);
        assert_eq!(state.dirty_trigger, original.dirty_trigger);
        assert!(registry.peek_dirty(&token).unwrap().forcing);
        if phase != "keyed" {
            if phase == "closed" {
                assert_eq!(state.clock_due_generation, original.clock_due_generation);
            } else {
                assert!(state.clock_due_generation > original.clock_due_generation);
            }
            assert!(state.clock_evaluated_generation < state.clock_due_generation);
        }
        if phase == "evaluation" || phase == "closed" {
            assert_eq!(state.clock_evaluated_generation, 0);
        }
        if phase == "keyed" {
            assert!(state.keyed_dirty);
            assert_eq!(state.keyed.variants().count(), 1);
        }
    }
    if phase == "evaluation" || phase == "closed" {
        assert_eq!(
            hub.need_metrics()
                .lock()
                .unwrap()
                .pre_evaluation_association_drops,
            0
        );
    }
    // Actual close/reopen and acceptance, with no intervening content/control
    // write. The existing queue alone must recover, not a new wake or probe.
    db.close().await;
    let reopened =
        crate::open_existing_database(dir.path().join("scheduler.sqlite").to_str().unwrap())
            .await
            .unwrap();
    let (reopened, _) = RealtimeHub::attach(reopened, Some(hub.clone()))
        .await
        .unwrap();
    hub.refresh_scheduler_handle(&reopened);
    assert!(scheduler.drain_one(&token).await);
    let frame = sink
        .try_recv()
        .expect("queued work recovered without write");
    if phase == "keyed" {
        assert!(matches!(frame, NeedSinkFrame::Keyed(_)));
    } else {
        assert!(matches!(frame, NeedSinkFrame::Need(_)));
    }
    {
        let registry = hub.need_registry().lock().unwrap();
        let state = registry.subscription_state(&token, &id).unwrap();
        assert!(!state.dirty && !state.in_flight);
        assert!(state.pending_acts.is_empty());
        assert_eq!(registry.dirty_len(&token), 0);
    }
    reopened.close().await;
}

#[tokio::test]
async fn personal_alpha_registry_scheduler_retirement_before_evaluation_preserves_drained_work() {
    interrupted("evaluation", false).await;
}
#[tokio::test]
async fn personal_alpha_registry_scheduler_retirement_before_emit_recovers_without_write() {
    interrupted("emit", false).await;
}
#[tokio::test]
async fn personal_alpha_registry_scheduler_retirement_before_keyed_gate_preserves_variants() {
    interrupted("keyed", false).await;
}
#[tokio::test]
async fn personal_alpha_registry_scheduler_terminal_teardown_never_requeues() {
    for phase in ["evaluation", "emit", "keyed"] {
        interrupted(phase, true).await;
    }
}

#[tokio::test]
async fn personal_alpha_registry_scheduler_retry_merge_bounds_acts_without_rewinding_clock_epoch() {
    let (_dir, db, scheduler, token, id, _sink) = fixture().await;
    {
        let mut registry = scheduler.hub.need_registry().lock().unwrap();
        registry.activate_with_clock(&token, &id, "old", true);
        registry.enqueue_dirty(&token, &id, true);
        for act in 0..crate::need_metrics::COMMIT_WINDOW as i64 {
            registry.mark_content_event_with_act(Some(act));
        }
        registry.mark_content_event_with_act(None);
        registry.pop_dirty(&token).unwrap();
        let work = registry.clear_dirty(&token, &id).unwrap();
        // A new clock schedule is legitimate concurrent state, never restore the
        // drained epoch or reset its generations/coverage from a stale measurement.
        registry.activate_with_clock(&token, &id, "new", false);
        registry.mark_content_event_with_act(Some(crate::need_metrics::COMMIT_WINDOW as i64 - 1));
        registry.mark_content_event_with_act(Some(crate::need_metrics::COMMIT_WINDOW as i64));
        let before = registry.subscription_state(&token, &id).unwrap();
        assert!(registry.restore_rerun_work(&token, &id, &work, true, true, true));
        registry.finish_rerun(&token, &id);
        let state = registry.subscription_state(&token, &id).unwrap();
        assert_eq!(state.pending_acts.len(), crate::need_metrics::COMMIT_WINDOW);
        assert_eq!(state.pending_acts.front(), Some(&1));
        assert_eq!(
            state.pending_acts.back(),
            Some(&(crate::need_metrics::COMMIT_WINDOW as i64))
        );
        assert!(state.unknown_act_pending && state.keyed_dirty && state.saw_content_event);
        assert_eq!(state.clock_schedule_epoch, before.clock_schedule_epoch);
        assert_eq!(state.clock_due_generation, before.clock_due_generation);
        assert_eq!(
            state.clock_evaluated_generation,
            before.clock_evaluated_generation
        );
        assert!(registry.peek_dirty(&token).unwrap().forcing);
        assert_eq!(registry.dirty_len(&token), 1);
    }
    db.close().await;
}

#[tokio::test]
async fn personal_alpha_registry_scheduler_closed_accepted_pools_preserve_work_until_reopen() {
    interrupted("closed", false).await;
}
