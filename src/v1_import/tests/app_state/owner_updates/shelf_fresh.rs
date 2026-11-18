//! Workspace app shelf on a new workspace whose import carried no v1 apps.
//!
//! There is no frozen app custody to verify, so the operator's frozen-app
//! activation has nothing to protect and the shelf must work. A workspace whose
//! import did carry app custody keeps refusing until it is activated.
use super::shelf_enable::{
    add, add_to_shelf, app_of, enable, head, install_events, list_as, my_status, principal, remove,
    status_as, who, World, PKG,
};
use super::*;

/// A new shared workspace as cutover produces it: imported, with no v1 apps
/// at all, and never activated by the operator.
async fn fresh_world() -> World {
    let f = Fixture::new().await;
    let report = run(f.options(&["note"], false)).await.unwrap();
    assert!(report.refusals.is_empty());
    let db = f.db().await;
    app_roster(&db, "account-a", &["account-a", "account-b", "account-c"]).await;
    let (a, b, c) = (
        principal(&db, "account-a").await,
        principal(&db, "account-b").await,
        principal(&db, "account-c").await,
    );
    // Workspace-root policy: a manages, b edits, c may only view.
    k::replace_home_policy(
        &db,
        &a,
        KERNEL_ROOT_ID,
        &[(&a, "manage"), (&b, "edit"), (&c, "view")],
    )
    .await
    .unwrap();
    World { _f: f, db, a, b, c }
}

async fn activation_events(db: &Db) -> i64 {
    sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM content_events WHERE type='kernel.app_installs_activated.v1') + (SELECT count(*) FROM kernel_app_state)",
    )
    .fetch_one(db.pool())
    .await
    .unwrap()
}

#[tokio::test]
async fn fresh_workspace_writer_adds_and_members_enable_and_the_app_runs() {
    let w = fresh_world().await;
    assert_eq!(
        activation_events(&w.db).await,
        0,
        "no app custody and no activation"
    );
    let entry = add_to_shelf(&w).await;
    assert_eq!(entry["package"], PKG);
    assert_eq!(
        activation_events(&w.db).await,
        0,
        "adding activates nothing"
    );

    let start = head(&w.db).await;
    let (gen_b, _) = enable(&w, "account-b", &entry, None).await.unwrap();
    let kinds: Vec<_> = install_events(&w.db, start)
        .await
        .into_iter()
        .map(|(t, actor, _)| (t, actor))
        .collect();
    assert_eq!(
        kinds,
        [
            (
                "kernel.app_install_recorded.v1".to_owned(),
                Some(w.b.clone())
            ),
            (
                "kernel.app_install_adopted.v1".to_owned(),
                Some(w.b.clone())
            ),
        ]
    );
    assert_eq!(my_status(&list_as(&w.db, "account-b").await), "installed");
    // Nobody else is enabled by it.
    assert_eq!(my_status(&list_as(&w.db, "account-a").await), "available");
    // The enabled app passes app-call admission as its member.
    let app = app_of("account-b", &gen_b);
    status_as(&w.db, &app, "note").await.unwrap();
    // Removal still works and then stops the app for the member.
    let shelf_event = entry["shelf_event_id"].as_str().unwrap();
    call(
        &w.db,
        who("account-a"),
        "manage_alpha_tabs",
        remove(shelf_event),
    )
    .await
    .unwrap();
    assert!(enable(&w, "account-c", &entry, None).await.is_err());
    k::verify_v2_ready(&w.db).await.unwrap();
}

#[tokio::test]
async fn fresh_workspace_keeps_the_shelf_writer_boundary() {
    let w = fresh_world().await;
    let before = head(&w.db).await;
    // A view-only member cannot add, activated or not.
    let refused = call(&w.db, who("account-c"), "manage_alpha_tabs", add("c1"))
        .await
        .unwrap_err()
        .to_string();
    assert!(!refused.contains("not activated"), "{refused}");
    assert_eq!(head(&w.db).await, before, "a refusal appends nothing");
    // A non-member is refused too.
    assert!(
        call(&w.db, who("account-z"), "manage_alpha_tabs", add("z1"))
            .await
            .is_err()
    );
    assert_eq!(head(&w.db).await, before);
}

#[tokio::test]
async fn imported_but_unactivated_workspace_still_refuses_the_shelf() {
    // Imported and given its hosted roster, but the operator has not activated
    // frozen apps: the gate must hold exactly as before.
    let f = Fixture::new().await;
    super::super::native_install_source_with_pin(&f, super::OLD, "agent.docs", "0.4.0").await;
    let mut source = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&f.source),
    )
    .await
    .unwrap();
    source.execute("INSERT INTO facet_values VALUES('secret','app_package','true',NULL,NULL,'2026-01-01T00:00:00Z'); INSERT INTO facet_observations VALUES('secret','app_package','2026-01-01T00:00:00Z',1); DELETE FROM artifact_source_attestations; DELETE FROM artifact_inputs;").await.unwrap();
    source.close().await.unwrap();
    let mut options = f.options(&["secret", "note"], false);
    options.history = true;
    let run_report = run(options).await.unwrap();
    assert!(run_report.refusals.is_empty());
    let db = f.db().await;
    let custody: i64 = sqlx::query_scalar("SELECT count(*) FROM kernel_app_state")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert!(custody > 0, "the import carried app custody");
    app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    let a = principal(&db, "account-a").await;
    let before = head_of(&db).await;
    for (account, args) in [
        ("account-a", add("k1")),
        ("account-b", json!({"action":"list","workspace_apps":true})),
    ] {
        let refused = call(&db, who(account), "manage_alpha_tabs", args)
            .await
            .unwrap_err()
            .to_string();
        assert!(refused.contains("not activated"), "{account}: {refused}");
    }
    assert_eq!(head_of(&db).await, before, "refusals append nothing");
    let _ = a;
}

async fn head_of(db: &Db) -> i64 {
    head(db).await
}
