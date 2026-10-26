use super::*;
use crate::identity::hosted::{
    reconcile_hosted_identity, HostedMembershipArrival, HostedMembershipRole,
    HostedMembershipSource,
};

struct Pair {
    _dir: tempfile::TempDir,
    source: Db,
    target: Db,
    path: std::path::PathBuf,
    owner: String,
    member: String,
    member_principal: String,
    shared: String,
    private: String,
}
fn caller(account: &str, owner: bool) -> Caller {
    Caller::authenticated(account)
        .with_hosting_context("synthetic-catalog", "synthetic-db")
        .with_hosting_member(true)
        .with_hosting_owner(owner)
}
async fn call(
    db: &Db,
    v2: bool,
    account: &str,
    owner: bool,
    tool: &str,
    args: Value,
) -> Result<Value> {
    registry()
        .call_engine(
            if v2 {
                EngineHandle::KernelV2(db.clone())
            } else {
                EngineHandle::Sqlite(db.clone())
            },
            caller(account, owner),
            tool,
            args,
        )
        .await
}
async fn pair() -> Pair {
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
                &format!("synthetic-{label}"),
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
    registry().call(source.clone(),Caller::local(),"manage_record_policy",json!({"action":"grant","record_id":"native:root","subject":{"kind":"account","account_id":owner},"capability":"manage","reason":"synthetic configuration owner"})).await.unwrap();
    let shared=call(&source,false,&owner,true,"create_record",json!({"type":"Document","kind":"note","name":"Shared instructions","body":"Real instruction text","reason":"configuration fixture"})).await.unwrap()["id"].as_str().unwrap().to_owned();
    let private=call(&source,false,&owner,true,"create_record",json!({"type":"Document","kind":"note","name":"PRIVATE OWNER SOURCE","body":"PRIVATE INSTRUCTION BODY","reason":"configuration privacy fixture"})).await.unwrap()["id"].as_str().unwrap().to_owned();
    for id in [&shared, &private] {
        call(&source,false,&owner,true,"manage_record_policy",json!({"action":"set_members_baseline","record_id":id,"capability":"view","reason":"initial shared instruction sources"})).await.unwrap();
    }
    let workspace_position = call(
        &source,
        false,
        &owner,
        true,
        "manage_instructions",
        json!({"action":"list","scope":"workspace"}),
    )
    .await
    .unwrap()["bindings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|b| b["position"].as_i64())
        .max()
        .unwrap_or(0)
        + 100;
    let member_position = call(
        &source,
        false,
        &member,
        false,
        "manage_instructions",
        json!({"action":"list","scope":"member"}),
    )
    .await
    .unwrap()["bindings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|b| b["position"].as_i64())
        .max()
        .unwrap_or(0)
        + 100;
    for (account, is_owner, scope, source_id, enabled, position, key) in [
        (
            owner.as_str(),
            true,
            "workspace",
            shared.as_str(),
            true,
            workspace_position + 100,
            "workspace-fixture",
        ),
        (
            owner.as_str(),
            true,
            "workspace",
            private.as_str(),
            false,
            workspace_position,
            "hidden-fixture",
        ),
        (
            member.as_str(),
            false,
            "member",
            shared.as_str(),
            true,
            member_position,
            "member-fixture",
        ),
    ] {
        call(&source,false,account,is_owner,"manage_instructions",json!({"action":"create_binding","scope":scope,"source_record_id":source_id,"position":position,"enabled":enabled,"idempotency_key":key,"reason":"synthetic instruction binding"})).await.unwrap();
    }
    call(&source,false,&owner,true,"manage_onboarding",json!({"action":"create_programme","programme_id":"fixture-programme","trigger_key":"on_member_joined","position":200,"enabled":false,"idempotency_key":"programme-fixture","reason":"synthetic programme"})).await.unwrap();
    call(&source,false,&owner,true,"manage_onboarding",json!({"action":"add_source","programme_id":"fixture-programme","source_record_id":shared,"source_role":"guidance","position":100,"idempotency_key":"programme-source-fixture","reason":"synthetic programme source"})).await.unwrap();
    // V1 requires a workspace source to be initially readable by its entire
    // audience, even when disabled. Exercise later loss through the policy API.
    let policy = call(
        &source,
        false,
        &owner,
        true,
        "manage_record_policy",
        json!({"action":"list","record_id":private}),
    )
    .await
    .unwrap();
    call(&source,false,&owner,true,"manage_record_policy",json!({"action":"replace","record_id":private,"if_policy_revision":policy["policy_revision"],"entries":[{"subject":{"kind":"account","account_id":owner},"capability":"manage"}],"reason":"synthetic later privacy change"})).await.unwrap();
    std::fs::write(
        dir.path().join("members.txt"),
        format!("{owner}\n{member}\n"),
    )
    .unwrap();
    let report = crate::v1_import::run(crate::v1_import::Options {
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
        report.app_state.capture_complete && report.refusals.is_empty() && report.review.is_empty(),
        "{}",
        serde_json::to_string(&report.refusals).unwrap()
    );
    let target = kernel::open_marked_v2_database(path.to_str().unwrap())
        .await
        .unwrap();
    let member_principal = report.principals[&member].clone();
    Pair {
        _dir: dir,
        source,
        target,
        path,
        owner,
        member,
        member_principal,
        shared,
        private,
    }
}
fn normalized(mut result: Value, key: &str) -> Value {
    for entry in result[key].as_array_mut().unwrap() {
        entry.as_object_mut().unwrap().remove("source_updated_at");
        // This projection does not retain template provenance. Compare v1's
        // same null-shaped seed fields, without claiming the source was custom.
        if let Some(seed) = entry.get_mut("seed").and_then(Value::as_object_mut) {
            for value in seed.values_mut() {
                *value = Value::Null;
            }
        }
        if let Some(sources) = entry.get_mut("sources").and_then(Value::as_array_mut) {
            for source in sources {
                source.as_object_mut().unwrap().remove("source_updated_at");
                if let Some(seed) = source.get_mut("seed").and_then(Value::as_object_mut) {
                    for value in seed.values_mut() {
                        *value = Value::Null;
                    }
                }
            }
        }
    }
    result[key].clone()
}

#[tokio::test]
async fn kernel_v2_configuration_lists_match_v1_scope_order_privacy_and_read_only_serving() {
    let f = pair().await;
    let before = kernel::dump_all_kernel_tables(&f.target).await.unwrap();
    for (account, owner) in [(&f.owner, true), (&f.member, false)] {
        for scope in [None, Some("workspace"), Some("member")] {
            let mut args = json!({"action":"list"});
            if let Some(scope) = scope {
                args["scope"] = json!(scope);
            }
            let v1 = call(
                &f.source,
                false,
                account,
                owner,
                "manage_instructions",
                args.clone(),
            )
            .await
            .unwrap();
            let v2 = call(&f.target, true, account, owner, "manage_instructions", args)
                .await
                .unwrap();
            assert_eq!(
                normalized(v2.clone(), "bindings"),
                normalized(v1, "bindings")
            );
            assert_eq!(v2["mutations_available"], false);
            assert_eq!(
                v2["template_provenance"],
                "unavailable_in_imported_projection"
            );
            if !owner {
                assert!(!v2.to_string().contains("PRIVATE"));
            }
            for binding in v2["bindings"].as_array().unwrap() {
                assert!(chrono::DateTime::parse_from_rfc3339(
                    binding["source_updated_at"].as_str().unwrap()
                )
                .is_ok());
            }
        }
    }
    let args = json!({"action":"list_programmes"});
    let v1 = call(
        &f.source,
        false,
        &f.owner,
        true,
        "manage_onboarding",
        args.clone(),
    )
    .await
    .unwrap();
    let v2 = call(
        &f.target,
        true,
        &f.owner,
        true,
        "manage_onboarding",
        args.clone(),
    )
    .await
    .unwrap();
    assert_eq!(
        normalized(v2.clone(), "programmes"),
        normalized(v1, "programmes")
    );
    assert_eq!(v2["delivery_enabled"], false);
    assert!(call(
        &f.source,
        false,
        &f.member,
        false,
        "manage_onboarding",
        args.clone()
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("database owner host role required"));
    assert!(
        call(&f.target, true, &f.member, false, "manage_onboarding", args)
            .await
            .unwrap_err()
            .to_string()
            .contains("database owner host role required")
    );
    assert_eq!(
        before,
        kernel::dump_all_kernel_tables(&f.target).await.unwrap()
    );
    let readonly = crate::db::open_marked_v2_database_read_only_at(&f.path)
        .await
        .unwrap();
    for (tool, args) in [
        ("manage_instructions", json!({"action":"list"})),
        ("manage_onboarding", json!({"action":"list_programmes"})),
    ] {
        assert!(call(&readonly, true, &f.owner, true, tool, args)
            .await
            .is_ok());
    }
    readonly.close().await;
    kernel::replay_all_projections(&f.target).await.unwrap();
    assert_eq!(
        before,
        kernel::dump_all_kernel_tables(&f.target).await.unwrap()
    );
    f.source.close().await;
    f.target.close().await;
}

#[tokio::test]
async fn kernel_v2_configuration_own_unreadable_source_refuses_without_identifiers() {
    let f = pair().await;
    let workspace_before = call(
        &f.target,
        true,
        &f.member,
        false,
        "manage_instructions",
        json!({"action":"list","scope":"workspace"}),
    )
    .await
    .unwrap();
    let home = kernel::read_record_as(&f.target, &f.member_principal, &f.shared)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let owner = kernel::resolve_principal_by_binding(&f.target, &f.owner)
        .await
        .unwrap()
        .unwrap()
        .0;
    kernel::replace_home_policy(&f.target, &owner, &home, &[(&owner, "manage")])
        .await
        .unwrap();
    let error = call(
        &f.target,
        true,
        &f.member,
        false,
        "manage_instructions",
        json!({"action":"list"}),
    )
    .await
    .unwrap_err();
    assert!(error
        .to_string()
        .contains("manage_instructions: an instruction source is not readable"));
    assert!(!error.to_string().contains(&f.shared));
    let workspace = call(
        &f.target,
        true,
        &f.member,
        false,
        "manage_instructions",
        json!({"action":"list","scope":"workspace"}),
    )
    .await
    .unwrap();
    let retained: Vec<Value> = workspace_before["bindings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|b| b["source_record_id"] != f.shared)
        .cloned()
        .collect();
    assert_eq!(workspace["bindings"], json!(retained));
    f.source.close().await;
    f.target.close().await;
}

#[tokio::test]
async fn kernel_v2_configuration_argument_and_mutation_refusals_do_not_write() {
    let registered = registry();
    for (tool, read, actions) in [
        (
            "manage_instructions",
            "list",
            &[
                "compare_seeded_default",
                "reset_seeded_default",
                "apply_seeded_default",
                "create_binding",
                "enable_binding",
                "disable_binding",
                "reorder_binding",
                "retarget_binding",
                "remove_binding",
            ][..],
        ),
        (
            "manage_onboarding",
            "list_programmes",
            &[
                "create_programme",
                "configure_programme",
                "add_source",
                "remove_source",
                "change_source",
                "reorder_source",
                "preview_generation",
                "publish_generation",
            ][..],
        ),
    ] {
        assert!(registered.has_engine_operation(
            tool,
            EngineKind::KernelV2,
            Some(("action", read))
        ));
        for action in actions {
            assert!(!registered.has_engine_operation(
                tool,
                EngineKind::KernelV2,
                Some(("action", action))
            ));
            assert!(registered.has_engine_operation(
                tool,
                EngineKind::Sqlite,
                Some(("action", action))
            ));
        }
    }
    let f = pair().await;
    let before = kernel::dump_all_kernel_tables(&f.target).await.unwrap();
    for args in [
        json!({"action":"list","scope":"other"}),
        json!({"action":"list","extra":true}),
    ] {
        assert!(
            call(&f.target, true, &f.owner, true, "manage_instructions", args)
                .await
                .is_err()
        );
    }
    for (tool, args) in [
        (
            "manage_instructions",
            json!({"action":"compare_seeded_default","source_record_id":f.shared}),
        ),
        (
            "manage_onboarding",
            json!({"action":"preview_generation","programme_id":"fixture-programme","audience":{"kind":"all"}}),
        ),
    ] {
        let error = call(&f.target, true, &f.owner, true, tool, args)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("isn't available on this workspace yet"),
            "{error}"
        );
    }
    assert_eq!(
        before,
        kernel::dump_all_kernel_tables(&f.target).await.unwrap()
    );
    f.source.close().await;
    f.target.close().await;
}

#[tokio::test]
async fn kernel_v2_configuration_owner_unreadable_workspace_source_names_repair_target() {
    let f = pair().await;
    // The fixture already has an owner-authored private workspace source.
    // A different member becoming workspace owner gains configuration repair
    // information, never private-record View through that workspace role.
    assert!(
        kernel::read_record_as(&f.target, &f.member_principal, &f.private)
            .await
            .unwrap()
            .is_none()
    );
    let error = call(
        &f.target,
        true,
        &f.member,
        true,
        "manage_instructions",
        json!({"action":"list","scope":"workspace"}),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains(&f.private), "{error}");
    assert!(error
        .to_string()
        .contains("Workspace ownership does not override a record's private access policy"));
    assert!(error
        .to_string()
        .contains("Ask the record owner to grant you access"));
    assert!(!error.to_string().contains("PRIVATE OWNER SOURCE"));
    assert!(!error.to_string().contains("PRIVATE INSTRUCTION BODY"));
    f.source.close().await;
    f.target.close().await;
}
