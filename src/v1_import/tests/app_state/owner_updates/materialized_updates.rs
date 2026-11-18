//! Cross-owner installed catalog updates require a fresh private source and a
//! fresh person receipt. The old owner's source is never an update target.
use super::*;

fn person() -> Caller {
    Caller::authenticated("account-b")
        .with_hosting_context("account-b", "hq-fixture")
        .with_hosting_owner(true)
}
fn materialize(key: &str) -> Value {
    json!({"action":"materialize_catalog_update","package":"agent.docs","version":"0.5.0","expected_install_event_id":"install-b","predecessor_artifact_id":"secret","reason":"Review the host's Docs release in my personal artifact","idempotency_key":key})
}
async fn setup() -> (Fixture, Db, String, String) {
    let f = Fixture::new().await;
    let (db, a, b) = fixture(&f, "agent.docs").await;
    k::rehome_record_as(&db, &a, "secret", KERNEL_ROOT_ID)
        .await
        .unwrap();
    (f, db, a, b)
}
async fn prepare_materialized(db: &Db, created: &Value) -> Value {
    let mut args = prepare(created["body_digest"].as_str().unwrap());
    args["package"] = json!("agent.docs");
    args["artifact_id"] = created["artifact_id"].clone();
    let result = call(db, person(), "manage_alpha_tabs", args).await.unwrap();
    assert_eq!(result["ready"], true, "{result}");
    result
}
async fn count(db: &Db) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap()
}
async fn old_source_snapshot(db: &Db, a: &str) -> Value {
    type SourceEvent = (String, String, Option<String>, Option<String>, Option<i64>);
    let artifact = k::read_record_as(db, a, "secret").await.unwrap();
    let events: Vec<SourceEvent> = sqlx::query_as("SELECT id,type,payload,actor,act FROM content_events WHERE record_id='secret' ORDER BY seq").fetch_all(db.pool()).await.unwrap();
    let closure: Option<String> = sqlx::query_scalar(
        "SELECT descriptor FROM kernel_artifact_closures WHERE artifact_id='secret'",
    )
    .fetch_optional(db.pool())
    .await
    .unwrap();
    let other:(String,String,Option<String>,String)=sqlx::query_as("SELECT row_json,generation,source_body,status FROM kernel_app_installs WHERE principal=? AND package='agent.docs'").bind(a).fetch_one(db.pool()).await.unwrap();
    let policy:Vec<(String,String,String,String,String)>=sqlx::query_as("SELECT root_id,subject_kind,subject_id,effect,capability FROM kernel_policy_entries WHERE root_id=(SELECT home_id FROM kernel_records WHERE id='secret') ORDER BY root_id,subject_kind,subject_id,effect,capability").fetch_all(db.pool()).await.unwrap();
    json!({"artifact":artifact,"events":events,"closure":closure,"other":other,"policy":policy})
}

#[tokio::test]
async fn materialized_catalog_foreign_owner_full_lifecycle_preserves_both_predecessors_and_replays()
{
    let (_f, db, a, b) = setup().await;
    let before = old_source_snapshot(&db, &a).await;
    let old = k::app_installs::inspect_as(&db, &b, "agent.docs")
        .await
        .unwrap();
    let oldrow = &old["install"];
    let mut oldpin = k::app_installs::InstallRequest {
        package: "agent.docs".into(),
        version: "0.4.0".into(),
        digest: oldrow["digest"].as_str().unwrap().into(),
        artifact_id: "secret".into(),
        source_revision: "source".into(),
        declaration: json!({"contract":"native.app.v2","needs":[],"effects":[]}),
        reason: "Preview current source".into(),
        request: None,
        idempotency_key: None,
        expected_install_event_id: Some("install-b".into()),
    };
    let initial_review = k::app_installs::preview_as(
        &db,
        &b,
        &native_app_hosted_caller("account-b", &oldpin, false).with_hosting_owner(true),
        oldpin.clone(),
    )
    .await
    .unwrap();
    // The inherited fixture has a legacy label but no carry provenance. Start
    // a real person adoption root so cross-artifact non-carry is actually owed.
    let old_adopt = k::app_installs::adopt_as(
        &db,
        &b,
        &native_app_hosted_caller("account-b", &oldpin, true).with_hosting_owner(true),
        k::app_installs::AdoptRequest {
            scope: None,
            pin: oldpin.clone(),
            receipt_id: initial_review.receipt.receipt_id,
            nonce: initial_review.receipt.nonce,
            preview_session: initial_review.receipt.preview_session,
        },
    )
    .await
    .unwrap();
    let old_generation = old_adopt.outcome.generation;
    oldpin.expected_install_event_id = Some(old_generation.clone());
    let previous_receipt = k::app_installs::preview_as(
        &db,
        &b,
        &native_app_hosted_caller("account-b", &oldpin, false).with_hosting_owner(true),
        oldpin,
    )
    .await
    .unwrap();
    k::verify_v2_ready(&db).await.unwrap();
    let mut intent = materialize("personal-docs");
    intent["expected_install_event_id"] = json!(old_generation);
    let created = call(&db, person(), "manage_alpha_tabs", intent.clone())
        .await
        .unwrap();
    k::verify_v2_ready(&db).await.unwrap();
    assert_ne!(created["artifact_id"], "secret");
    let after = count(&db).await;
    assert_eq!(
        created,
        call(&db, person(), "manage_alpha_tabs", intent.clone())
            .await
            .unwrap()
    );
    assert_eq!(
        after,
        count(&db).await,
        "retry recovers the exact target without allocating another record"
    );
    assert_eq!(before, old_source_snapshot(&db, &a).await);
    let target = created["artifact_id"].as_str().unwrap();
    let mut tx = db.write_pool().begin().await.unwrap();
    assert!(
        k::read_record_on(&mut tx, &a, target)
            .await
            .unwrap()
            .is_none(),
        "the old source owner receives no target access"
    );
    let own = k::read_record_on(&mut tx, &b, target)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(own.owner_id.as_deref(), Some(b.as_str()));
    assert_eq!(own.body.as_deref(), Some(NEW));
    tx.rollback().await.unwrap();
    let prepared = prepare_materialized(&db, &created).await;
    let staged = call(
        &db,
        person(),
        "manage_alpha_tabs",
        prepared["next_call"]["arguments"].clone(),
    )
    .await
    .unwrap();
    assert_eq!(
        staged["install"]["pending_update"], true,
        "identical declaration must never carry adoption across artifacts"
    );
    let inspected = k::app_installs::inspect_as(&db, &b, "agent.docs")
        .await
        .unwrap();
    assert_eq!(inspected["install"]["artifact_id"], "secret");
    assert_eq!(inspected["install"]["event_id"], old_generation);
    let mut tx = db.write_pool().begin().await.unwrap();
    assert_eq!(
        k::app_installs::admit_install_on(&mut tx, &b, "agent.docs", &old_generation)
            .await
            .unwrap()
            .body,
        OLD
    );
    tx.rollback().await.unwrap();
    let mut pin = request(&prepared["next_call"]["arguments"]);
    pin.expected_install_event_id = Some(staged["install"]["event_id"].as_str().unwrap().into());
    let adopting = native_app_hosted_caller("account-b", &pin, true).with_hosting_owner(true);
    let stale = k::app_installs::AdoptRequest {
        scope: None,
        pin: pin.clone(),
        receipt_id: previous_receipt.receipt.receipt_id,
        nonce: previous_receipt.receipt.nonce,
        preview_session: previous_receipt.receipt.preview_session,
    };
    assert!(
        k::app_installs::adopt_as(&db, &b, &adopting, stale)
            .await
            .is_err(),
        "the predecessor's browser receipt cannot authorize a different artifact"
    );
    let fresh = k::app_installs::preview_as(
        &db,
        &b,
        &native_app_hosted_caller("account-b", &pin, false).with_hosting_owner(true),
        pin.clone(),
    )
    .await
    .unwrap();
    assert_eq!(fresh.body, NEW);
    let adoption = k::app_installs::AdoptRequest {
        scope: None,
        pin: pin.clone(),
        receipt_id: fresh.receipt.receipt_id,
        nonce: fresh.receipt.nonce,
        preview_session: fresh.receipt.preview_session,
    };
    let adopted = k::app_installs::adopt_as(&db, &b, &adopting, adoption.clone())
        .await
        .unwrap();
    assert_eq!(adopted.install["artifact_id"], target);
    assert!(
        !k::app_installs::adopt_as(&db, &b, &adopting, adoption)
            .await
            .unwrap()
            .outcome
            .changed
    );
    let mut tx = db.write_pool().begin().await.unwrap();
    assert_eq!(
        k::app_installs::admit_install_on(&mut tx, &b, "agent.docs", &adopted.outcome.generation)
            .await
            .unwrap()
            .body,
        NEW
    );
    tx.rollback().await.unwrap();
    assert_eq!(before, old_source_snapshot(&db, &a).await);
    let projected = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(projected, k::dump_all_kernel_tables(&db).await.unwrap());
    k::verify_v2_ready(&db).await.unwrap();
    assert_eq!(before, old_source_snapshot(&db, &a).await);
}

#[tokio::test]
async fn materialized_catalog_refuses_stale_cas_pending_keys_callers_and_target_substitution_atomically(
) {
    let (_f, db, _a, b) = setup().await;
    for (field, value) in [
        ("expected_install_event_id", json!("stale")),
        ("predecessor_artifact_id", json!("wrong")),
        ("version", json!("0.99.0")),
        ("artifact_id", json!("orphan")),
        ("declaration", json!({})),
    ] {
        let before = k::dump_all_kernel_tables(&db).await.unwrap();
        let events = count(&db).await;
        let mut args = materialize("guards");
        args[field] = value;
        assert!(
            call(&db, person(), "manage_alpha_tabs", args)
                .await
                .is_err(),
            "{field}"
        );
        assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
        assert_eq!(events, count(&db).await);
    }
    for caller in [
        person().with_hosting_owner(false),
        person().with_host_asserted_app(
            crate::mcp::app_attribution::AppAttribution::new("agent.docs", "0.4.0", "install-b")
                .unwrap(),
        ),
    ] {
        let before = count(&db).await;
        assert!(
            call(&db, caller, "manage_alpha_tabs", materialize("guards"))
                .await
                .is_err()
        );
        assert_eq!(before, count(&db).await);
    }
    let created = call(&db, person(), "manage_alpha_tabs", materialize("guards"))
        .await
        .unwrap();
    let mut changed = materialize("guards");
    changed["reason"] = json!("other intent");
    let before = count(&db).await;
    assert!(call(&db, person(), "manage_alpha_tabs", changed)
        .await
        .is_err());
    assert_eq!(before, count(&db).await);
    let mut foreign_prepare = prepare(created["body_digest"].as_str().unwrap());
    foreign_prepare["package"] = json!("agent.docs");
    foreign_prepare["artifact_id"] = created["artifact_id"].clone();
    assert_ne!(
        call(&db, owner(), "manage_alpha_tabs", foreign_prepare)
            .await
            .unwrap()["ready"],
        true
    );
    let second = call(
        &db,
        person(),
        "manage_alpha_tabs",
        materialize("second-explicit-intent"),
    )
    .await
    .unwrap();
    assert_ne!(created["artifact_id"], second["artifact_id"]);
    let second_prepared = prepare_materialized(&db, &second).await;
    let prepared = prepare_materialized(&db, &created).await;
    let mut substituted = prepared["next_call"]["arguments"].clone();
    substituted["artifact_id"] = json!("note");
    assert!(call(&db, person(), "manage_alpha_tabs", substituted)
        .await
        .is_err());
    call(
        &db,
        person(),
        "manage_alpha_tabs",
        prepared["next_call"]["arguments"].clone(),
    )
    .await
    .unwrap();
    let events = count(&db).await;
    let state = k::dump_all_kernel_tables(&db).await.unwrap();
    let first_pending = k::app_installs::inspect_as(&db, &b, "agent.docs")
        .await
        .unwrap()["pending_update"]
        .clone();
    let mut second_install = second_prepared["next_call"]["arguments"].clone();
    second_install["idempotency_key"] = json!("stage-second-materialized-target");
    let error = call(&db, person(), "manage_alpha_tabs", second_install)
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("competing pending update"),
        "{error}"
    );
    assert_eq!(state, k::dump_all_kernel_tables(&db).await.unwrap());
    assert_eq!(events, count(&db).await);
    assert_eq!(
        first_pending,
        k::app_installs::inspect_as(&db, &b, "agent.docs")
            .await
            .unwrap()["pending_update"]
    );
    assert!(
        call(&db, person(), "manage_alpha_tabs", materialize("competing"))
            .await
            .is_err()
    );
    assert_eq!(state, k::dump_all_kernel_tables(&db).await.unwrap());
    assert_eq!(events, count(&db).await);
    // The generic publication fence is unchanged even after materialization:
    // its new artifact is not the installed artifact before adoption.
    let publish = json!({"action":"publish_catalog_update","artifact_id":created["artifact_id"],"package":"agent.docs","version":"0.5.0","expected_install_event_id":"install-b","expected_body_digest":created["body_digest"],"reason":"Try generic publication"});
    assert!(call(&db, person(), "manage_alpha_tabs", publish)
        .await
        .is_err());
    assert_eq!(
        k::app_installs::inspect_as(&db, &b, "agent.docs")
            .await
            .unwrap()["install"]["artifact_id"],
        "secret"
    );
}

#[tokio::test]
async fn materialized_catalog_rechecks_target_privacy_body_and_offboarding_after_stage() {
    for tamper in ["policy", "body", "owner", "offboard"] {
        let (_f, db, a, b) = setup().await;
        let created = call(
            &db,
            person(),
            "manage_alpha_tabs",
            materialize("target-guards"),
        )
        .await
        .unwrap();
        let prepared = prepare_materialized(&db, &created).await;
        let staged = call(
            &db,
            person(),
            "manage_alpha_tabs",
            prepared["next_call"]["arguments"].clone(),
        )
        .await
        .unwrap();
        let mut pin = request(&prepared["next_call"]["arguments"]);
        pin.expected_install_event_id =
            Some(staged["install"]["event_id"].as_str().unwrap().into());
        let fresh = k::app_installs::preview_as(
            &db,
            &b,
            &native_app_hosted_caller("account-b", &pin, false).with_hosting_owner(true),
            pin.clone(),
        )
        .await
        .unwrap();
        let target = created["artifact_id"].as_str().unwrap();
        if tamper == "offboard" {
            app_roster(&db, "account-a", &["account-a"]).await;
        } else {
            // Isolated projection corruption fixture; no production path
            // bypasses the ordinary owner-only catalog publication fence.
            match tamper {
                "policy" => {
                    sqlx::query("INSERT INTO kernel_policy_entries(root_id,subject_kind,subject_id,effect,capability) SELECT home_id,'account',?,'allow','view' FROM kernel_records WHERE id=?").bind(&a).bind(target).execute(db.write_pool()).await.unwrap();
                }
                "body" => {
                    sqlx::query(
                        "UPDATE kernel_record_bodies SET body='tampered' WHERE record_id=?",
                    )
                    .bind(target)
                    .execute(db.write_pool())
                    .await
                    .unwrap();
                }
                "owner" => {
                    sqlx::query("UPDATE kernel_records SET owner_id=? WHERE id=?")
                        .bind(&a)
                        .bind(target)
                        .execute(db.write_pool())
                        .await
                        .unwrap();
                }
                _ => unreachable!(),
            }
        }
        let state = k::dump_all_kernel_tables(&db).await.unwrap();
        let events = count(&db).await;
        assert!(
            k::app_installs::adopt_as(
                &db,
                &b,
                &native_app_hosted_caller("account-b", &pin, true).with_hosting_owner(true),
                k::app_installs::AdoptRequest {
                    scope: None,
                    pin,
                    receipt_id: fresh.receipt.receipt_id,
                    nonce: fresh.receipt.nonce,
                    preview_session: fresh.receipt.preview_session
                }
            )
            .await
            .is_err(),
            "{tamper}"
        );
        assert_eq!(state, k::dump_all_kernel_tables(&db).await.unwrap());
        assert_eq!(events, count(&db).await);
        if tamper == "offboard" {
            k::replay_all_projections(&db).await.unwrap();
            assert_eq!(
                state,
                k::dump_all_kernel_tables(&db).await.unwrap(),
                "materialization and staging replay against preceding membership after offboarding"
            );
        }
        assert_eq!(
            k::app_installs::inspect_as(&db, &a, "agent.docs")
                .await
                .unwrap()["install"]["artifact_id"],
            "secret"
        );
    }
}

#[tokio::test]
async fn materialized_catalog_rolls_back_creation_and_rejects_retained_predecessor_corruption() {
    let (_f, db, _a, _b) = setup().await;
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    let events = count(&db).await;
    sqlx::query("CREATE TRIGGER reject_test_materialization BEFORE INSERT ON content_events WHEN NEW.type='kernel.app_catalog_update_materialized.v1' BEGIN SELECT RAISE(ABORT,'test materialization failure'); END").execute(db.write_pool()).await.unwrap();
    assert!(
        call(&db, person(), "manage_alpha_tabs", materialize("atomic"))
            .await
            .is_err()
    );
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    assert_eq!(events, count(&db).await);
    sqlx::query("DROP TRIGGER reject_test_materialization")
        .execute(db.write_pool())
        .await
        .unwrap();
    let created = call(&db, person(), "manage_alpha_tabs", materialize("atomic"))
        .await
        .unwrap();
    let mut tx = db.write_pool().begin().await.unwrap();
    let event = crate::conformance::rebuild::read_all_events(&mut tx)
        .await
        .unwrap()
        .into_iter()
        .find(|e| e.event_type == k::app_installs::materialized::MATERIALIZED)
        .unwrap();
    let payload: Value = serde_json::from_str(event.payload.as_deref().unwrap()).unwrap();
    k::app_installs::materialized::verify(
        &payload,
        &event.record_id,
        &event.id,
        created["source_revision"].as_str().unwrap(),
        NEW,
    )
    .unwrap();
    for field in ["principal", "result", "source_revision"] {
        let mut bad = payload.clone();
        if field == "result" {
            bad["result"]["artifact_id"] = json!("other-target");
        } else {
            bad[field] = json!("other");
        }
        assert!(
            k::app_installs::materialized::verify(
                &bad,
                &event.record_id,
                &event.id,
                created["source_revision"].as_str().unwrap(),
                NEW
            )
            .is_err(),
            "{field}"
        );
    }
    tx.rollback().await.unwrap();
    // Match the retained row too, so projection reaches predecessor verification.
    let mut tx = db.write_pool().begin().await.unwrap();
    sqlx::query("DROP TRIGGER IF EXISTS content_events_no_update")
        .execute(&mut *tx)
        .await
        .unwrap();
    let mut corrupted = event.clone();
    let mut bad = payload.clone();
    bad["predecessor_pin"]["digest"] = json!("substituted");
    corrupted.payload = Some(bad.to_string());
    sqlx::query("UPDATE content_events SET payload=? WHERE id=?")
        .bind(&corrupted.payload)
        .bind(&event.id)
        .execute(&mut *tx)
        .await
        .unwrap();
    let error = k::app_installs::materialized::project(&mut tx, &corrupted)
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("predecessor pin changed"),
        "{error}"
    );
    tx.rollback().await.unwrap();
    let mut replaced = ToolRegistry::new();
    replaced.set_catalog_assets(crate::mcp::tools::catalog_assets::fixture_assets(
        "later release",
        "agent.docs",
        "0.6.0",
    ));
    crate::mcp::register_builtin_tools(&mut replaced).unwrap();
    crate::mcp::tools::register_surface_tools(&mut replaced).unwrap();
    crate::mcp::kernel_v2::register_kernel_v2_tools(&mut replaced).unwrap();
    assert_eq!(
        created,
        replaced
            .call_engine(
                EngineHandle::KernelV2(db.clone()),
                person(),
                "manage_alpha_tabs",
                materialize("atomic")
            )
            .await
            .unwrap(),
        "uncertain retries recover the recorded catalog release after host replacement"
    );
    let projected = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(projected, k::dump_all_kernel_tables(&db).await.unwrap());
}
