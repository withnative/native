use super::*;
use crate::identity::hosted::{
    reconcile_hosted_identity, HostedMembershipArrival, HostedMembershipRole,
    HostedMembershipSource,
};
struct Fixture {
    dir: tempfile::TempDir,
    source: Db,
    target: Db,
    path: std::path::PathBuf,
    owner: String,
    member: String,
    workspace: String,
    personal: String,
}
fn caller(account: &str, owner: bool) -> Caller {
    Caller::authenticated(account)
        .with_hosting_context("fixture-user", "fixture-db")
        .with_hosting_member(true)
        .with_hosting_owner(owner)
}
async fn tool(db: &Db, v2: bool, account: &str, owner: bool, args: Value) -> Result<Value> {
    registry()
        .call_engine(
            if v2 {
                EngineHandle::KernelV2(db.clone())
            } else {
                EngineHandle::Sqlite(db.clone())
            },
            caller(account, owner),
            "manage_surface_bindings",
            args,
        )
        .await
}
async fn resume(f: &Fixture) -> crate::v1_import::Report {
    let r = crate::v1_import::run(crate::v1_import::Options {
        source: f.dir.path().join("source.db"),
        target: f.path.clone(),
        seeds: vec![],
        all: true,
        history: true,
        resume: true,
        members_file: Some(f.dir.path().join("members.txt")),
    })
    .await
    .unwrap();
    assert!(
        r.refusals.is_empty(),
        "{}",
        serde_json::to_string(&r.refusals).unwrap()
    );
    assert!(r.review.is_empty());
    assert!(r.state.surface_bindings_prepared);
    r
}
async fn fixture() -> Fixture {
    fixture_with_hidden_identity(false).await
}
async fn fixture_with_hidden_identity(hidden: bool) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("target.db");
    let source = crate::create_database(dir.path().join("source.db").to_str().unwrap())
        .await
        .unwrap();
    let mut accounts = vec![];
    for (label, role) in [
        ("owner", HostedMembershipRole::Owner),
        ("member", HostedMembershipRole::Member),
    ] {
        accounts.push(
            reconcile_hosted_identity(
                &source,
                &format!("{label}@example.test"),
                label,
                &HostedMembershipArrival::new(
                    role,
                    HostedMembershipSource::Direct,
                    "2026-10-20T00:00:00Z".into(),
                )
                .unwrap(),
                None,
            )
            .await
            .unwrap(),
        );
    }
    let owner = accounts.remove(0);
    let member = accounts.remove(0);
    registry().call(source.clone(),Caller::local(),"manage_record_policy",json!({"action":"grant","record_id":"native:root","subject":{"kind":"account","account_id":owner},"capability":"manage","reason":"synthetic source owner"})).await.unwrap();
    registry().call(source.clone(),Caller::local(),"manage_record_policy",json!({"action":"set_members_baseline","record_id":crate::schema::UNFILED_RECORD_ID,"capability":"edit","reason":"synthetic filing permission"})).await.unwrap();
    let workspace=registry().call(source.clone(),caller(&owner,true),"create_record",json!({"type":"Document","kind":"artifact","name":"Workspace Home","body":"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Workspace</title></head><body><main>WORKSPACE</main></body></html>","facets":{"runtime":"native.html.v1"},"reason":"synthetic binding"})).await.unwrap()["id"].as_str().unwrap().to_owned();
    let personal=registry().call(source.clone(),caller(&member,false),"create_record",json!({"type":"Document","kind":"artifact","name":"PRIVATE PERSONAL HOME","body":"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Personal</title></head><body><main>PRIVATE PERSONAL BODY</main></body></html>","facets":{"runtime":"native.html.v1"},"access_policy":"account_only","reason":"synthetic private binding"})).await.unwrap()["id"].as_str().unwrap().to_owned();
    for (account, owner, scope, target) in [
        (&owner, true, "workspace", &workspace),
        (&member, false, "personal", &personal),
    ] {
        tool(
            &source,
            false,
            account,
            owner,
            json!({"action":"set","surface":"home","scope":scope,"target_id":target}),
        )
        .await
        .unwrap();
    }
    if hidden {
        let owner_person:String=sqlx::query_scalar("SELECT record_id FROM bindings WHERE system='account' AND is_canonical=1 AND identifier=?").bind(&owner).fetch_one(source.pool()).await.unwrap();
        let member_person:String=sqlx::query_scalar("SELECT record_id FROM bindings WHERE system='account' AND is_canonical=1 AND identifier=?").bind(&member).fetch_one(source.pool()).await.unwrap();
        // Legitimate v1 source setup through its operator and guarded policy
        // funnels; no direct policy or v2 projection writes.
        registry().call(source.clone(),Caller::local(),"update_record",json!({"id":member_person,"owner_id":owner_person,"reason":"Synthetic pre-existing Person with another owner"})).await.unwrap();
        for id in [&member_person, "native:root"] {
            let policy = registry()
                .call(
                    source.clone(),
                    caller(&owner, true),
                    "manage_record_policy",
                    json!({"action":"list","record_id":id}),
                )
                .await
                .unwrap();
            registry().call(source.clone(),caller(&owner,true),"manage_record_policy",json!({"action":"replace","record_id":id,"if_policy_revision":policy["policy_revision"],"entries":[{"subject":{"kind":"account","account_id":owner},"capability":"manage"}],"reason":"Synthetic hidden identity and root"})).await.unwrap();
        }
    }
    std::fs::write(
        dir.path().join("members.txt"),
        format!("{owner}\n{member}\n"),
    )
    .unwrap();
    let r = crate::v1_import::run(crate::v1_import::Options {
        source: dir.path().join("source.db"),
        target: path.clone(),
        seeds: vec![],
        all: true,
        history: true,
        resume: false,
        members_file: Some(dir.path().join("members.txt")),
    })
    .await
    .unwrap();
    assert!(
        r.refusals.is_empty(),
        "{}",
        serde_json::to_string(&r.refusals).unwrap()
    );
    assert!(r.review.is_empty());
    assert!(r.state.surface_bindings_prepared);
    assert_eq!(r.state.sections["surface_bindings"].source, 2);
    let target = kernel::open_marked_v2_database(path.to_str().unwrap())
        .await
        .unwrap();
    Fixture {
        dir,
        source,
        target,
        path,
        owner,
        member,
        workspace,
        personal,
    }
}
async fn parity(f: &Fixture) {
    for (account, owner) in [(&f.owner, true), (&f.member, false)] {
        for args in [
            json!({"action":"get","surface":"home"}),
            json!({"action":"get","surface":"home","subject":"environment"}),
        ] {
            assert_eq!(
                tool(&f.target, true, account, owner, args.clone())
                    .await
                    .unwrap(),
                tool(&f.source, false, account, owner, args).await.unwrap()
            );
        }
    }
}
#[tokio::test]
async fn kernel_v2_surface_bindings_preserve_root_personal_precedence_and_delta_removals() {
    let f = fixture().await;
    parity(&f).await;
    let owner = tool(
        &f.target,
        true,
        &f.owner,
        true,
        json!({"action":"get","surface":"home"}),
    )
    .await
    .unwrap();
    assert_eq!(owner["target_id"], f.workspace);
    assert!(!owner.to_string().contains(&f.personal));
    let member = tool(
        &f.target,
        true,
        &f.member,
        false,
        json!({"action":"get","surface":"home"}),
    )
    .await
    .unwrap();
    assert_eq!(member["target_id"], f.personal);
    registry()
        .call(
            f.source.clone(),
            caller(&f.member, false),
            "archive_record",
            json!({"id":f.personal,"reason":"synthetic archive"}),
        )
        .await
        .unwrap();
    resume(&f).await;
    parity(&f).await;
    let archived = tool(
        &f.target,
        true,
        &f.member,
        false,
        json!({"action":"get","surface":"home"}),
    )
    .await
    .unwrap();
    assert_eq!(archived["target_id"], f.workspace);
    assert_eq!(archived["skipped"][0]["reason"], "archived");
    for (account, owner, scope) in [
        (&f.member, false, "personal"),
        (&f.owner, true, "workspace"),
    ] {
        tool(
            &f.source,
            false,
            account,
            owner,
            json!({"action":"reset","surface":"home","scope":scope,"expected_target_id":if scope=="personal" {&f.personal}else{&f.workspace}}),
        )
        .await
        .unwrap();
        resume(&f).await;
        parity(&f).await;
    }
    let fallback = tool(
        &f.target,
        true,
        &f.member,
        false,
        json!({"action":"get","surface":"home"}),
    )
    .await
    .unwrap();
    assert_eq!(fallback["fallback"], true);
    assert_eq!(fallback["source"], "app_fallback");
    let before = kernel::dump_all_kernel_tables(&f.target).await.unwrap();
    kernel::replay_all_projections(&f.target).await.unwrap();
    assert_eq!(
        before,
        kernel::dump_all_kernel_tables(&f.target).await.unwrap()
    );
    parity(&f).await;
    f.source.close().await;
    f.target.close().await;
}
#[tokio::test]
async fn kernel_v2_surface_bindings_read_only_and_arguments_match_v1() {
    let f = fixture().await;
    let global = registry()
        .call_engine(
            EngineHandle::KernelV2(f.target.clone()),
            caller(&f.owner, true),
            "get_history",
            json!({"limit":1000}),
        )
        .await
        .unwrap();
    assert!(!global.to_string().contains(&f.personal));
    let private_events:Vec<String>=sqlx::query_scalar("SELECT id FROM content_events WHERE type='kernel.v1_state_imported.v1' AND json_extract(payload,'$.section')='surface_bindings' AND instr(json_extract(payload,'$.value_json'),?)>0").bind(&f.personal).fetch_all(f.target.pool()).await.unwrap();
    assert!(!private_events.is_empty());
    for event in private_events {
        let error = registry()
            .call_engine(
                EngineHandle::KernelV2(f.target.clone()),
                caller(&f.owner, true),
                "get_event_context",
                json!({"event_id":event}),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("does not exist"));
        assert!(!error.contains(&f.personal));
    }
    let sql = registry()
        .call_engine(
            EngineHandle::KernelV2(f.target.clone()),
            caller(&f.owner, true),
            "query_sql",
            json!({"sql":"SELECT id FROM content_events WHERE type='kernel.v1_state_imported.v1'"}),
        )
        .await
        .unwrap();
    assert_eq!(sql["rows"], json!([]));
    let before = kernel::dump_all_kernel_tables(&f.target).await.unwrap();
    let readonly = crate::db::open_marked_v2_database_read_only_at(&f.path)
        .await
        .unwrap();
    assert_eq!(
        tool(
            &readonly,
            true,
            &f.member,
            false,
            json!({"action":"get","surface":"home"})
        )
        .await
        .unwrap(),
        tool(
            &f.source,
            false,
            &f.member,
            false,
            json!({"action":"get","surface":"home"})
        )
        .await
        .unwrap()
    );
    for args in [
        json!({"action":"get","surface":"unknown"}),
        json!({"action":"get","surface":"home","subject":"record"}),
        json!({"action":"get","surface":"home","extra":1}),
    ] {
        assert!(tool(&f.source, false, &f.owner, true, args.clone())
            .await
            .is_err());
        assert!(tool(&f.target, true, &f.owner, true, args).await.is_err());
    }
    readonly.close().await;
    assert_eq!(
        before,
        kernel::dump_all_kernel_tables(&f.target).await.unwrap()
    );
    f.source.close().await;
    f.target.close().await;
}
#[tokio::test]
async fn kernel_v2_surface_binding_capture_is_required_before_serving_and_can_resume() {
    let f = fixture().await;
    let plan:Vec<String>=sqlx::query("EXPLAIN QUERY PLAN SELECT json_extract(payload,'$.origin') FROM main.content_events WHERE type='kernel.import_source_head.v1' ORDER BY seq DESC LIMIT 1").fetch_all(f.target.pool()).await.unwrap().iter().map(|r|sqlx::Row::get::<String,_>(r,"detail")).collect();
    assert!(
        plan.iter()
            .any(|p| p.contains("idx_kernel_import_source_head")),
        "{plan:?}"
    );
    // Simulate a structurally prepared copy without its current data receipt.
    sqlx::query("DELETE FROM kernel_v1_state WHERE section='surface_bindings_capture'")
        .execute(f.target.write_pool())
        .await
        .unwrap();
    let before = kernel::dump_all_kernel_tables(&f.target).await.unwrap();
    assert!(kernel::verify_marked_v2_file_read_only(&f.path)
        .await
        .unwrap_err()
        .to_string()
        .contains("resume the original import before H3 activation"));
    // Existing record operations retain structural readiness; the new surface
    // and cutover target verification require their separate data receipt.
    let reopened = kernel::open_marked_v2_database(f.path.to_str().unwrap())
        .await
        .unwrap();
    reopened.close().await;
    assert!(tool(
        &f.target,
        true,
        &f.owner,
        true,
        json!({"action":"get","surface":"home"})
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("surface bindings need preparation"));
    assert_eq!(
        before,
        kernel::dump_all_kernel_tables(&f.target).await.unwrap()
    );
    // Structural preparation alone never invents absent binding metadata.
    kernel::prepare_v2_database(&f.target).await.unwrap();
    assert!(kernel::verify_marked_v2_file_read_only(&f.path)
        .await
        .is_err());
    resume(&f).await;
    kernel::verify_marked_v2_file_read_only(&f.path)
        .await
        .unwrap();
    parity(&f).await;
    f.source.close().await;
    f.target.close().await;
}

#[tokio::test]
async fn kernel_v2_surface_bindings_keep_own_metadata_when_person_and_root_are_hidden() {
    let f = fixture_with_hidden_identity(true).await;
    parity(&f).await;
    let person: String = sqlx::query_scalar(
        "SELECT record_id FROM bindings WHERE system='account' AND is_canonical=1 AND identifier=?",
    )
    .bind(&f.member)
    .fetch_one(f.source.pool())
    .await
    .unwrap();
    let actor = kernel::resolve_principal_by_binding(&f.target, &f.member)
        .await
        .unwrap()
        .unwrap()
        .0;
    for id in [&person, crate::events::KERNEL_ROOT_ID] {
        assert!(kernel::read_record_as(&f.target, &actor, id)
            .await
            .unwrap()
            .is_none());
    }
    let mut tx = f.target.pool().begin().await.unwrap();
    assert!(
        super::super::identity_read::principal_identity_on(&mut tx, &actor, &actor)
            .await
            .unwrap()
            .unwrap()
            .person_id
            .is_none()
    );
    tx.rollback().await.unwrap();
    let own = tool(
        &f.target,
        true,
        &f.member,
        false,
        json!({"action":"get","surface":"home"}),
    )
    .await
    .unwrap();
    assert_eq!(own["target_id"], f.personal);
    tool(
        &f.source,
        false,
        &f.member,
        false,
        json!({"action":"reset","surface":"home","scope":"personal"}),
    )
    .await
    .unwrap_err(); // mutation still needs Edit on the hidden Person
    f.source.close().await;
    f.target.close().await;
}
