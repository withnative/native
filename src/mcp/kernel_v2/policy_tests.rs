use super::*;
use crate::identity::hosted::{
    reconcile_hosted_identity, HostedMembershipArrival, HostedMembershipRole,
    HostedMembershipSource,
};
use crate::mcp::kernel_v2::tests::registry;

struct Fixture {
    _dir: tempfile::TempDir,
    source: Db,
    db: Db,
    target: std::path::PathBuf,
    owner: String,
    member: String,
    owner_principal: String,
    member_principal: String,
    folder: String,
    private: String,
    shared: String,
    comment: String,
}
async fn v1(db: &Db, account: &str, tool: &str, args: Value) -> Result<Value> {
    registry()
        .call(db.clone(), Caller::authenticated(account), tool, args)
        .await
}
async fn v2(f: &Fixture, account: &str, tool: &str, args: Value) -> Result<Value> {
    registry()
        .call_engine(
            EngineHandle::KernelV2(f.db.clone()),
            Caller::authenticated(account),
            tool,
            args,
        )
        .await
}
async fn fixture(one_member: bool) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let source_path = dir.path().join("source.db");
    let target = dir.path().join("target.db");
    let source = crate::create_database(source_path.to_str().unwrap())
        .await
        .unwrap();
    let mut accounts = Vec::new();
    for (label, role) in [
        ("owner", HostedMembershipRole::Owner),
        ("member", HostedMembershipRole::Member),
    ] {
        accounts.push(
            reconcile_hosted_identity(
                &source,
                &format!("{label}@example.test"),
                &format!("catalog-{label}"),
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
    let owner = accounts[0].clone();
    let member = accounts[1].clone();
    registry()
        .call(
            source.clone(),
            Caller::local(),
            "manage_record_policy",
            json!({
        "action":"grant","record_id":"native:root","subject":{"kind":"account","account_id":owner},
        "capability":"manage","reason":"establish the synthetic importer admin"}),
        )
        .await
        .unwrap();

    let folder=v1(&source,&owner,"create_record",json!({"type":"Collection","kind":"folder","name":"Shared policy fixture","reason":"policy fixture"})).await.unwrap()["id"].as_str().unwrap().to_owned();
    let folder_policy = v1(
        &source,
        &owner,
        "manage_record_policy",
        json!({"action":"list","record_id":folder}),
    )
    .await
    .unwrap();
    v1(
        &source,
        &owner,
        "manage_record_policy",
        json!({"action":"replace","record_id":folder,
        "if_policy_revision":folder_policy["policy_revision"],
        "entries":[{"subject":{"kind":"members"},"capability":"edit"}],
        "reason":"members-only folder fixture"}),
    )
    .await
    .unwrap();
    let private=v1(&source,&owner,"create_record",json!({"type":"Document","kind":"note","name":"Private fixture","body":"private before","home_id":folder,"access_policy":"account_only","reason":"policy fixture"})).await.unwrap()["id"].as_str().unwrap().to_owned();
    let shared=v1(&source,&owner,"create_record",json!({"type":"Document","kind":"note","name":"Shared fixture","body":"shared before","home_id":folder,"reason":"policy fixture"})).await.unwrap()["id"].as_str().unwrap().to_owned();
    let comment=v1(&source,&owner,"create_record",json!({"type":"Annotation","kind":"comment","body":"Comment before","links":[{"target_id":private,"relationship":"part_of"}],"reason":"policy fixture"})).await.unwrap()["id"].as_str().unwrap().to_owned();
    let members = dir.path().join("members.txt");
    std::fs::write(
        &members,
        if one_member {
            format!("{owner}\n")
        } else {
            format!("{owner}\n{member}\n")
        },
    )
    .unwrap();
    let report = crate::v1_import::run(crate::v1_import::Options {
        source: source_path,
        target: target.clone(),
        seeds: vec![],
        all: true,
        history: true,
        resume: false,
        members_file: Some(members),
    })
    .await
    .unwrap();
    assert!(
        report.refusals.is_empty(),
        "{}",
        serde_json::to_string(&report.refusals).unwrap()
    );
    assert!(report.review.is_empty());
    let owner_principal = report.principals[&owner].clone();
    let member_principal = report.principals[&member].clone();
    let db = kernel::open_marked_v2_database(target.to_str().unwrap())
        .await
        .unwrap();
    Fixture {
        _dir: dir,
        source,
        db,
        target,
        owner,
        member,
        owner_principal,
        member_principal,
        folder,
        private,
        shared,
        comment,
    }
}
async fn listed(f: &Fixture, id: &str) -> Value {
    v2(
        f,
        &f.owner,
        "manage_record_policy",
        json!({"action":"list","record_id":id}),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn kernel_v2_policy_list_matches_v1_and_is_read_only() {
    let f = fixture(false).await;
    let before = kernel::dump_all_kernel_tables(&f.db).await.unwrap();
    for id in [
        f.private.as_str(),
        f.shared.as_str(),
        f.folder.as_str(),
        f.comment.as_str(),
        "native:root",
    ] {
        let mut expected = v1(
            &f.source,
            &f.owner,
            "manage_record_policy",
            json!({"action":"list","record_id":id}),
        )
        .await
        .unwrap();
        let mut actual = listed(&f, id).await;
        assert!(actual["policy_revision"]
            .as_str()
            .unwrap()
            .starts_with("prv2:"));
        actual.as_object_mut().unwrap().remove("policy_revision");
        expected.as_object_mut().unwrap().remove("policy_revision");
        assert_eq!(actual, expected);
    }
    assert_eq!(
        listed(&f, &f.comment).await["policy_revision"],
        listed(&f, &f.private).await["policy_revision"]
    );
    assert_eq!(before, kernel::dump_all_kernel_tables(&f.db).await.unwrap());
    let expected = listed(&f, &f.private).await;
    kernel::replay_all_projections(&f.db).await.unwrap();
    assert_eq!(expected, listed(&f, &f.private).await);
    f.source.close().await;
    f.db.close().await;
}

#[tokio::test]
async fn kernel_v2_policy_members_are_not_a_one_account_privacy_proof() {
    let f = fixture(true).await;
    let actual = listed(&f, &f.folder).await;
    let physical: Vec<(String, String)> =
        sqlx::query_as("SELECT subject_id,capability FROM kernel_policy_entries WHERE root_id=?")
            .bind(crate::v1_import::derived(&f.folder))
            .fetch_all(f.db.pool())
            .await
            .unwrap();
    assert_eq!(physical, vec![(f.owner_principal.clone(), "edit".into())]);

    assert_eq!(
        actual["entries"],
        json!([{"subject":{"kind":"members"},"capability":"edit"}])
    );
    assert_eq!(
        listed(&f, &f.private).await["entries"][0]["subject"]["account_id"],
        f.owner
    );
    f.source.close().await;
    f.db.close().await;
}

#[tokio::test]
async fn kernel_v2_policy_list_refuses_non_managers_and_mutations_without_disclosure() {
    let f = fixture(false).await;
    let before = kernel::dump_all_kernel_tables(&f.db).await.unwrap();
    for id in [f.private.as_str(), f.shared.as_str(), "missing"] {
        let error = v2(
            &f,
            &f.member,
            "manage_record_policy",
            json!({"action":"list","record_id":id}),
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            Error::engine("manage_record_policy: record does not exist").to_string()
        );
    }
    assert!(v2(&f,&f.owner,"manage_record_policy",json!({"action":"grant","record_id":f.private,"subject":{"kind":"members"},"capability":"view","reason":"unsupported mutation"})).await.is_err());
    let r = registry();
    assert!(r.has_engine_operation(
        "manage_record_policy",
        EngineKind::KernelV2,
        Some(("action", "list"))
    ));
    assert!(!r.has_engine_operation(
        "manage_record_policy",
        EngineKind::KernelV2,
        Some(("action", "grant"))
    ));
    assert!(r.has_engine_operation(
        "manage_record_policy",
        EngineKind::Sqlite,
        Some(("action", "grant"))
    ));
    assert_eq!(before, kernel::dump_all_kernel_tables(&f.db).await.unwrap());
    f.source.close().await;
    f.db.close().await;
}

#[tokio::test]
async fn kernel_v2_policy_guard_matches_v1_and_keyed_retry_precedes_current_guard() {
    let f = fixture(false).await;
    let old = listed(&f, &f.private).await["policy_revision"].clone();
    let old_v1 = v1(
        &f.source,
        &f.owner,
        "manage_record_policy",
        json!({"action":"list","record_id":f.private}),
    )
    .await
    .unwrap()["policy_revision"]
        .clone();
    let args = json!({"id":f.private,"name":"Guarded rename","if_policy_revision":old,"idempotency_key":"policy-save","reason":"guarded rename"});
    let mut source_args = args.clone();
    source_args["if_policy_revision"] = old_v1;
    let expected = v1(&f.source, &f.owner, "update_record", source_args.clone())
        .await
        .unwrap();
    let actual = v2(&f, &f.owner, "update_record", args.clone())
        .await
        .unwrap();
    assert_eq!(
        listed(&f, &f.private).await["policy_revision"],
        old,
        "content alone must not change policy revision"
    );
    let home: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
        .bind(&f.private)
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    kernel::replace_home_policy(
        &f.db,
        &f.owner_principal,
        &home,
        &[
            (&f.owner_principal, "manage"),
            (&f.member_principal, "edit"),
        ],
    )
    .await
    .unwrap();
    v1(&f.source,&f.owner,"manage_record_policy",json!({"action":"grant","record_id":f.private,"subject":{"kind":"account","account_id":f.member},"capability":"edit","reason":"policy changed"})).await.unwrap();
    assert_ne!(listed(&f, &f.private).await["policy_revision"], old);
    let before = kernel::dump_all_kernel_tables(&f.db).await.unwrap();
    assert_eq!(
        actual,
        v2(&f, &f.owner, "update_record", args.clone())
            .await
            .unwrap()
    );
    assert_eq!(
        expected,
        v1(&f.source, &f.owner, "update_record", source_args.clone())
            .await
            .unwrap()
    );
    let mut stale = args;
    stale.as_object_mut().unwrap().remove("idempotency_key");
    stale["name"] = json!("must not save");
    let mut source_stale = source_args;
    source_stale
        .as_object_mut()
        .unwrap()
        .remove("idempotency_key");
    source_stale["name"] = json!("must not save");
    for result in [
        v2(&f, &f.owner, "update_record", stale).await,
        v1(&f.source, &f.owner, "update_record", source_stale).await,
    ] {
        assert!(
            matches!(result,Err(Error::Conflict(ref message)) if message.contains("policy revision conflict"))
        );
    }
    assert_eq!(before, kernel::dump_all_kernel_tables(&f.db).await.unwrap());
    f.source.close().await;
    f.db.close().await;
}

#[tokio::test]
async fn kernel_v2_policy_guard_follows_the_bearer_and_rejects_empty_or_wrong_types() {
    let f = fixture(false).await;
    let token = listed(&f, &f.comment).await["policy_revision"].clone();
    let digest = crate::mcp::tools::lifecycle::body_digest(Some("Comment before"));
    let actual=v2(&f,&f.owner,"update_record",json!({"id":f.comment,"body_set":"Comment after","if_body_digest":digest,"if_policy_revision":token,"reason":"bearer policy guard"})).await.unwrap();
    assert_eq!(actual["changed"], true);
    assert_eq!(
        listed(&f, &f.comment).await["policy_revision"],
        listed(&f, &f.private).await["policy_revision"]
    );
    let before = kernel::dump_all_kernel_tables(&f.db).await.unwrap();
    for invalid in [
        json!(""),
        json!("   "),
        json!(false),
        json!(1),
        json!("stale"),
    ] {
        assert!(v2(&f,&f.owner,"update_record",json!({"id":f.private,"name":"must not save","if_policy_revision":invalid,"reason":"invalid guard"})).await.is_err());
        assert!(v1(&f.source,&f.owner,"update_record",json!({"id":f.private,"name":"must not save","if_policy_revision":invalid,"reason":"invalid guard"})).await.is_err());
    }
    assert_eq!(before, kernel::dump_all_kernel_tables(&f.db).await.unwrap());
    f.source.close().await;
    f.db.close().await;
}

#[tokio::test]
async fn kernel_v2_policy_list_works_on_a_physically_read_only_file() {
    let mut f = fixture(false).await;
    let expected = listed(&f, &f.private).await;
    f.db.close().await;
    f.db = crate::db::open_marked_v2_database_read_only_at(&f.target)
        .await
        .unwrap();
    assert_eq!(expected, listed(&f, &f.private).await);
    assert!(v2(
        &f,
        &f.owner,
        "update_record",
        json!({"id":f.private,"name":"must not write","reason":"read-only fixture"})
    )
    .await
    .is_err());
    f.source.close().await;
    f.db.close().await;
}

#[tokio::test]
async fn kernel_v2_policy_root_repair_exception_never_extends_to_private_descendants() {
    let f = fixture(false).await;
    let root_owner: String =
        sqlx::query_scalar("SELECT owner_id FROM kernel_roots WHERE root_id=?")
            .bind(crate::events::KERNEL_ROOT_ID)
            .fetch_one(f.db.pool())
            .await
            .unwrap();
    kernel::replace_home_policy(&f.db, &root_owner, crate::events::KERNEL_ROOT_ID, &[])
        .await
        .unwrap();
    assert_eq!(root_owner, f.owner_principal);
    let account = &f.member;
    assert!(v2(
        &f,
        account,
        "manage_record_policy",
        json!({"action":"list","record_id":"native:root"})
    )
    .await
    .is_err());
    // Trusted synthetic catalogue role. This is a Caller attribute, never a
    // tool argument; the same exact-root exception exists in v1 policy_access.
    let caller = Caller::authenticated(account)
        .with_hosting_context("catalog-member", "policy-fixture")
        .with_hosting_member(true)
        .with_hosting_owner(true);
    let root = registry()
        .call_engine(
            EngineHandle::KernelV2(f.db.clone()),
            caller.clone(),
            "manage_record_policy",
            json!({"action":"list","record_id":"native:root"}),
        )
        .await
        .unwrap();
    assert_eq!(root["caller_capability"], "none");
    assert_eq!(root["policy_administration_authorized"], true);
    assert_eq!(root["entries"], json!([]));
    assert!(registry()
        .call_engine(
            EngineHandle::KernelV2(f.db.clone()),
            caller,
            "manage_record_policy",
            json!({"action":"list","record_id":f.private})
        )
        .await
        .is_err());
    f.source.close().await;
    f.db.close().await;
}

#[tokio::test]
async fn kernel_v2_policy_list_authorizes_before_describing_malformed_policy() {
    let f = fixture(false).await;
    let home = crate::v1_import::derived(&f.folder);
    kernel::replace_home_policy(
        &f.db,
        &f.owner_principal,
        &home,
        &[
            (&f.owner_principal, "manage"),
            (&f.member_principal, "view"),
        ],
    )
    .await
    .unwrap();
    // A projection with an unsupported description row still gives the member
    // View through a supported grant, never policy administration.
    sqlx::query(
        "INSERT INTO kernel_policy_entries VALUES(?, 'account', 'unrelated-principal', 'allow', 'malformed')",
    )
    .bind(&home)
    .execute(f.db.write_pool())
    .await
    .unwrap();
    let error = v2(
        &f,
        &f.member,
        "manage_record_policy",
        json!({"action":"list","record_id":f.folder}),
    )
    .await
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        Error::engine("manage_record_policy: record does not exist").to_string()
    );
    // Ensure the malformed row really would fail a description, rather than
    // accidentally testing an otherwise valid policy.
    let mut tx = f.db.pool().begin().await.unwrap();
    let description =
        kernel::policy_read::snapshot_on(&mut tx, &f.member_principal, &f.folder, false).await;
    assert!(
        matches!(description, Err(Error::Engine(ref e)) if e == "unsupported kernel policy capability 'malformed'")
    );
    tx.rollback().await.unwrap();
    f.source.close().await;
    f.db.close().await;
}

#[path = "account_config_tests.rs"]
mod account_config_tests;
async fn batch_guard(f: &Fixture, source: bool, id: &str) -> Value {
    let query = json!({"sql":"SELECT updated_at FROM records WHERE id=?1","parameters":[{"type":"text","value":id}]});
    let policy = json!({"action":"list","record_id":id});
    let (time, policy) = if source {
        (
            v1(&f.source, &f.owner, "query_sql", query).await.unwrap(),
            v1(&f.source, &f.owner, "manage_record_policy", policy)
                .await
                .unwrap(),
        )
    } else {
        (
            v2(f, &f.owner, "query_sql", query).await.unwrap(),
            v2(f, &f.owner, "manage_record_policy", policy)
                .await
                .unwrap(),
        )
    };
    json!({"op":"update","id":id,"if_unmodified_since":time["rows"][0]["updated_at"],"if_policy_revision":policy["policy_revision"]})
}
fn normalize_batch_receipt(mut receipt: Value) -> Value {
    receipt.as_object_mut().unwrap().remove("act");
    receipt
        .as_object_mut()
        .unwrap()
        .remove("action_attestation_ids");
    for item in receipt["results"].as_array_mut().unwrap() {
        assert!(item["previous_event_id"].is_string());
        item.as_object_mut().unwrap().remove("previous_seq");
        item.as_object_mut().unwrap().remove("previous_event_id");
    }
    receipt
}

#[tokio::test]
async fn kernel_v2_batch_archive_reopen_matches_v1_atomic_shell_receipts() {
    let f = fixture(false).await;
    for archived in [true, true, false, false] {
        let source_args = json!({"reason":"Shell archive parity","items":[batch_guard(&f,true,&f.private).await,{"op":"archive","id":f.private,"archived":archived}]});
        let args = json!({"reason":"Shell archive parity","items":[batch_guard(&f,false,&f.private).await,{"op":"archive","id":f.private,"archived":archived}]});
        let expected = v1(&f.source, &f.owner, "batch_write", source_args)
            .await
            .unwrap();
        let actual = v2(&f, &f.owner, "batch_write", args).await.unwrap();
        assert_eq!(
            normalize_batch_receipt(actual),
            normalize_batch_receipt(expected)
        );
        let get = v2(&f, &f.owner, "get_record", json!({"ids":[f.private]}))
            .await
            .unwrap();
        assert_eq!(get["records"][0]["archived"], archived);
    }
    let before = kernel::dump_all_kernel_tables(&f.db).await.unwrap();
    kernel::replay_all_projections(&f.db).await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&f.db).await.unwrap());
    f.source.close().await;
    f.db.close().await;
}

#[tokio::test]
async fn kernel_v2_batch_archive_late_stale_guard_rolls_back_the_entire_cohort() {
    let f = fixture(false).await;
    for source in [true, false] {
        let db = if source { &f.source } else { &f.db };
        for (field, bad) in [
            ("if_policy_revision", json!("stale")),
            ("if_unmodified_since", json!("2000-01-01T00:00:00Z")),
            ("if_unmodified_since", json!("2099-01-01T00:00:00Z")),
        ] {
            let mut guard = batch_guard(&f, source, &f.private).await;
            guard[field] = bad;
            let args = json!({"reason":"all or nothing","idempotency_key":"failed-batch","items":[{"op":"archive","id":f.shared,"archived":true},guard,{"op":"archive","id":f.private,"archived":true}]});
            let before: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
                .fetch_one(db.pool())
                .await
                .unwrap();
            let result = if source {
                v1(db, &f.owner, "batch_write", args).await
            } else {
                v2(&f, &f.owner, "batch_write", args).await
            };
            assert!(result.is_err());
            assert_eq!(
                before,
                sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events")
                    .fetch_one(db.pool())
                    .await
                    .unwrap()
            );
            let get = if source {
                v1(
                    db,
                    &f.owner,
                    "get_record",
                    json!({"ids":[f.shared,f.private]}),
                )
                .await
                .unwrap()
            } else {
                v2(
                    &f,
                    &f.owner,
                    "get_record",
                    json!({"ids":[f.shared,f.private]}),
                )
                .await
                .unwrap()
            };
            for record in get["records"].as_array().unwrap() {
                assert_ne!(record["archived"], true);
            }
        }
    }
    f.source.close().await;
    f.db.close().await;
}

#[tokio::test]
async fn kernel_v2_batch_retry_precedes_old_guards_and_requires_current_view() {
    let f = fixture(false).await;
    for source in [true, false] {
        let args = json!({"reason":"retry archive","idempotency_key":"archive-once","items":[batch_guard(&f,source,&f.private).await,{"op":"archive","id":f.private,"archived":true}]});
        let expected = if source {
            v1(&f.source, &f.owner, "batch_write", args.clone())
                .await
                .unwrap()
        } else {
            v2(&f, &f.owner, "batch_write", args.clone()).await.unwrap()
        };
        let edit = json!({"id":f.private,"name":"changed since archive","reason":"invalidate original time guard"});
        if source {
            v1(&f.source, &f.owner, "update_record", edit)
                .await
                .unwrap();
        } else {
            v2(&f, &f.owner, "update_record", edit).await.unwrap();
        }
        let db = if source { &f.source } else { &f.db };
        let before: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let replay = if source {
            v1(db, &f.owner, "batch_write", args.clone()).await.unwrap()
        } else {
            v2(&f, &f.owner, "batch_write", args.clone()).await.unwrap()
        };
        assert_eq!(expected, replay);
        assert_eq!(
            before,
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events")
                .fetch_one(db.pool())
                .await
                .unwrap()
        );
        let mut changed = args.clone();
        changed["reason"] = json!("different request");
        let conflict = if source {
            v1(db, &f.owner, "batch_write", changed).await
        } else {
            v2(&f, &f.owner, "batch_write", changed).await
        };
        assert!(conflict.is_err());
        let denied = if source {
            v1(db, &f.member, "batch_write", args).await
        } else {
            v2(&f, &f.member, "batch_write", args).await
        };
        assert!(denied.is_err());
    }
    f.source.close().await;
    f.db.close().await;
}

#[tokio::test]
async fn kernel_v2_batch_refuses_invalid_and_unqualified_forms_without_partial_writes() {
    let f = fixture(false).await;
    let guard = batch_guard(&f, false, &f.private).await;
    let archive = json!({"op":"archive","id":f.private,"archived":true});
    let before = kernel::dump_all_kernel_tables(&f.db).await.unwrap();
    for items in [
        json!([]),
        json!([{"op":"update","id":f.private}]),
        json!([archive, guard]),
        json!([archive, archive]),
        json!([guard, archive, archive]),
        json!([{"op":"archive","id":"short-id"}]),
        json!([{"op":"archive","id":f.private,"archived":"true"}]),
        json!([{"op":"update","id":f.private,"body":"unsupported"}]),
        json!([{"op":"add_link","source_id":f.private,"target_id":f.shared,"relationship":"relates_to"}]),
        json!(vec![archive.clone(); 26]),
    ] {
        assert!(v2(
            &f,
            &f.owner,
            "batch_write",
            json!({"reason":"invalid batch","items":items})
        )
        .await
        .is_err());
        assert_eq!(before, kernel::dump_all_kernel_tables(&f.db).await.unwrap());
    }
    for patch in [
        json!({"reason":" "}),
        json!({"idempotency_key":" "}),
        json!({"sources":[]}),
        json!({"unknown":true}),
    ] {
        let mut args = json!({"reason":"invalid metadata","items":[guard,archive]});
        args.as_object_mut()
            .unwrap()
            .extend(patch.as_object().unwrap().clone());
        assert!(v2(&f, &f.owner, "batch_write", args).await.is_err());
        assert_eq!(before, kernel::dump_all_kernel_tables(&f.db).await.unwrap());
    }
    f.source.close().await;
    f.db.close().await;
}

#[tokio::test]
async fn kernel_v2_batch_committed_replay_allows_view_demotion_but_not_revocation() {
    let f = fixture(false).await;
    let home = crate::v1_import::derived(&f.folder);
    for source in [true, false] {
        let account = &f.member;
        let set_policy = |cap: Option<&str>| {
            let mut entries = vec![
                json!({"subject":{"kind":"account","account_id":f.owner},"capability":"manage"}),
            ];
            if let Some(cap) = cap {
                entries.push(
                    json!({"subject":{"kind":"account","account_id":account},"capability":cap}),
                );
            }
            entries
        };
        if source {
            let revision = v1(
                &f.source,
                &f.owner,
                "manage_record_policy",
                json!({"action":"list","record_id":f.folder}),
            )
            .await
            .unwrap()["policy_revision"]
                .clone();
            v1(&f.source,&f.owner,"manage_record_policy",json!({"action":"replace","record_id":f.folder,"entries":set_policy(Some("manage")),"if_policy_revision":revision,"reason":"initial command authority"})).await.unwrap();
        } else {
            kernel::replace_home_policy(
                &f.db,
                &f.owner_principal,
                &home,
                &[
                    (&f.owner_principal, "manage"),
                    (&f.member_principal, "manage"),
                ],
            )
            .await
            .unwrap();
        }
        let time_args = json!({"sql":"SELECT updated_at FROM records WHERE id=?1","parameters":[{"type":"text","value":f.shared}]});
        let time = if source {
            v1(&f.source, account, "query_sql", time_args)
                .await
                .unwrap()
        } else {
            v2(&f, account, "query_sql", time_args).await.unwrap()
        };
        let args = json!({"reason":"retry after demotion","idempotency_key":"demotion","items":[{"op":"update","id":f.shared,"if_unmodified_since":time["rows"][0]["updated_at"]},{"op":"archive","id":f.shared,"archived":true}]});
        let receipt = if source {
            v1(&f.source, account, "batch_write", args.clone())
                .await
                .unwrap()
        } else {
            v2(&f, account, "batch_write", args.clone()).await.unwrap()
        };
        for cap in [Some("view"), None] {
            if source {
                let revision = v1(
                    &f.source,
                    &f.owner,
                    "manage_record_policy",
                    json!({"action":"list","record_id":f.folder}),
                )
                .await
                .unwrap()["policy_revision"]
                    .clone();
                v1(&f.source,&f.owner,"manage_record_policy",json!({"action":"replace","record_id":f.folder,"entries":set_policy(cap),"if_policy_revision":revision,"reason":"demote original writer"})).await.unwrap();
            } else {
                let mut entries = vec![(f.owner_principal.as_str(), "manage")];
                if let Some(cap) = cap {
                    entries.push((f.member_principal.as_str(), cap));
                }
                kernel::replace_home_policy(&f.db, &f.owner_principal, &home, &entries)
                    .await
                    .unwrap();
            }
            let result = if source {
                v1(&f.source, account, "batch_write", args.clone()).await
            } else {
                v2(&f, account, "batch_write", args.clone()).await
            };
            if cap.is_some() {
                assert_eq!(receipt, result.unwrap());
            } else {
                assert!(result.is_err());
            }
            let mut fresh = args.clone();
            fresh["idempotency_key"] = json!("new-after-demotion");
            let result = if source {
                v1(&f.source, account, "batch_write", fresh).await
            } else {
                v2(&f, account, "batch_write", fresh).await
            };
            assert!(result.is_err());
        }
    }
    f.source.close().await;
    f.db.close().await;
}

#[tokio::test]
async fn kernel_v2_identity_sql_portable_account_lookup_matches_v1_disclosure() {
    let f = fixture(false).await;
    for caller in [&f.owner, &f.member] {
        for identifier in [&f.owner, &f.member] {
            let args = json!({"sql":"SELECT record_id FROM bindings WHERE system = ?1 AND identifier = ?2 ORDER BY record_id LIMIT 1","parameters":[{"type":"text","value":"account"},{"type":"text","value":identifier}]});
            let expected = v1(&f.source, caller, "query_sql", args.clone())
                .await
                .unwrap();
            let actual = v2(&f, caller, "query_sql", args).await.unwrap();
            assert_eq!(actual["rows"], expected["rows"]);
        }
    }
    f.source.close().await;
    f.db.close().await;
}

#[tokio::test]
async fn kernel_v2_workspace_snapshot_imported_metadata_matches_v1_and_is_read_only() {
    let f = fixture(false).await;
    let before = kernel::dump_all_kernel_tables(&f.db).await.unwrap();
    for account in [&f.owner, &f.member] {
        let expected = v1(
            &f.source,
            account,
            "get_workspace_snapshot",
            json!({"action":"open"}),
        )
        .await
        .unwrap();
        let actual = v2(
            &f,
            account,
            "get_workspace_snapshot",
            json!({"action":"open"}),
        )
        .await
        .unwrap();
        assert!(actual["snapshot_token"].is_string(), "{actual}");
        for section in ["records", "facets", "links", "content_events"] {
            let old=v1(&f.source,account,"get_workspace_snapshot",json!({"action":"page","snapshot_token":expected["snapshot_token"],"section":section,"limit":1000})).await.unwrap();
            let new=v2(&f,account,"get_workspace_snapshot",json!({"action":"page","snapshot_token":actual["snapshot_token"],"section":section,"limit":1000})).await.unwrap();
            assert_eq!(old["section"], new["section"]);
            assert_eq!(old["has_more"], new["has_more"]);
            if section == "records" {
                for id in [&f.folder, &f.shared, &f.private, &f.comment] {
                    let old = old["rows"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|r| r["id"] == *id);
                    let new = new["rows"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|r| r["id"] == *id);
                    assert_eq!(old.is_some(), new.is_some(), "{id}");
                    if let (Some(old), Some(new)) = (old, new) {
                        for key in [
                            "id",
                            "type",
                            "kind",
                            "name",
                            "home_id",
                            "summary",
                            "persistence",
                            "maturity",
                            "created_at",
                        ] {
                            if key == "home_id" && id == &f.comment {
                                // Sealed import deliberately places derived
                                // records with their terminal bearer (#2545),
                                // repairing v1's stale/unfiled placement. Pins
                                // must agree with current get/SQL, not revive it.
                                assert_eq!(old[key], "native:unfiled");
                                // The bearer has an explicit self-policy home;
                                // that home's logical binding is the bearer ID.
                                assert_eq!(new[key], f.private);
                                let get = v2(
                                    &f,
                                    account,
                                    "get_record",
                                    json!({"ids":[id],"children_limit":0}),
                                )
                                .await
                                .unwrap();
                                assert_eq!(new[key], get["records"][0][key]);
                            } else {
                                assert_eq!(old[key], new[key], "{key}");
                            }
                        }
                    }
                }
            }
            if account == &f.member {
                assert!(!new["rows"].to_string().contains(&f.private));
            }
        }
    }
    assert_eq!(before, kernel::dump_all_kernel_tables(&f.db).await.unwrap());
    f.source.close().await;
    f.db.close().await;
}

#[tokio::test]
async fn kernel_v2_get_record_containment_context_matches_v1_and_native_nested_folders() {
    let f = fixture(false).await;
    for account in [&f.owner, &f.member] {
        for id in ["native:root", f.folder.as_str(), f.shared.as_str()] {
            let args = json!({"ids":[id],"children_limit":0,"links_limit":0});
            let expected = v1(&f.source, account, "get_record", args.clone())
                .await
                .unwrap();
            let actual = v2(&f, account, "get_record", args).await.unwrap();
            assert_eq!(expected["records"][0]["containment_path_visible"], true);
            assert_eq!(
                actual["records"][0]["containment_path_visible"],
                expected["records"][0]["containment_path_visible"]
            );
        }
    }
    let folder = v2(
        &f,
        &f.owner,
        "create_record",
        json!({"type":"Collection","kind":"folder",
        "name":"Native nested folder","home_id":f.folder,"reason":"context fixture"}),
    )
    .await
    .unwrap();
    let child = v2(
        &f,
        &f.owner,
        "create_record",
        json!({"type":"Document","kind":"note",
        "name":"Native nested child","home_id":folder["id"],"reason":"context fixture"}),
    )
    .await
    .unwrap();
    let before = kernel::dump_all_kernel_tables(&f.db).await.unwrap();
    for account in [&f.owner, &f.member] {
        let result = v2(
            &f,
            account,
            "get_record",
            json!({"ids":[folder["id"],child["id"]],
            "children_limit":0,"links_limit":0}),
        )
        .await
        .unwrap();
        for record in result["records"].as_array().unwrap() {
            assert_eq!(record["containment_path_visible"], true);
            assert!(record["ancestors"]
                .as_array()
                .unwrap()
                .iter()
                .any(|a| a["id"] == f.folder));
        }
        assert_eq!(result["records"][1]["home_id"], folder["id"]);
    }
    assert_eq!(before, kernel::dump_all_kernel_tables(&f.db).await.unwrap());
    f.source.close().await;
    f.db.close().await;
}

#[tokio::test]
async fn kernel_v2_get_record_containment_context_does_not_claim_a_hidden_path() {
    let f = fixture(false).await;
    // Keep the note independently visible while hiding its filing folder.
    let revision = v1(
        &f.source,
        &f.owner,
        "manage_record_policy",
        json!({"action":"list","record_id":f.shared}),
    )
    .await
    .unwrap();
    v1(
        &f.source,
        &f.owner,
        "manage_record_policy",
        json!({"action":"replace",
        "record_id":f.shared,"if_policy_revision":revision["policy_revision"],
        "entries":[{"subject":{"kind":"account","account_id":f.member},"capability":"view"}],
        "reason":"Visible note behind a hidden ancestor"}),
    )
    .await
    .unwrap();
    v1(
        &f.source,
        &f.owner,
        "manage_record_policy",
        json!({"action":"set_members_baseline",
        "record_id":f.folder,"capability":null,"reason":"Hide the filing parent"}),
    )
    .await
    .unwrap();
    let report = crate::v1_import::run(crate::v1_import::Options {
        source: f._dir.path().join("source.db"),
        target: f.target.clone(),
        seeds: vec![],
        all: true,
        history: true,
        resume: true,
        members_file: Some(f._dir.path().join("members.txt")),
    })
    .await
    .unwrap();
    assert!(report.refusals.is_empty());
    assert!(report.review.is_empty());
    let before = kernel::dump_all_kernel_tables(&f.db).await.unwrap();
    for (account, visible) in [(&f.member, false)] {
        let args = json!({"ids":[f.shared],"children_limit":0,"links_limit":0});
        let expected = v1(&f.source, account, "get_record", args.clone())
            .await
            .unwrap();
        let actual = v2(&f, account, "get_record", args).await.unwrap();
        assert_eq!(expected["records"][0]["containment_path_visible"], visible);
        assert_eq!(actual["records"][0]["containment_path_visible"], visible);
        assert_eq!(actual["records"][0]["id"], f.shared);
        if !visible {
            assert!(!actual["records"][0]["ancestors"]
                .as_array()
                .unwrap()
                .iter()
                .any(|a| a["id"] == f.folder));
        }
    }
    assert_eq!(before, kernel::dump_all_kernel_tables(&f.db).await.unwrap());
    f.source.close().await;
    f.db.close().await;
}

#[tokio::test]
async fn kernel_v2_browser_bootstrap_roots_match_visible_structure_and_v1_folder_shape() {
    let f = fixture(false).await;
    for account in [&f.owner, &f.member] {
        let expected = v1(&f.source, account, "bootstrap", json!({}))
            .await
            .unwrap();
        let actual = v2(&f, account, "bootstrap", json!({})).await.unwrap();
        assert_eq!(actual["roots"]["total"], 1);
        let root = &actual["roots"]["items"][0];
        for key in ["id", "type", "kind", "name", "persistence"] {
            assert_eq!(root[key], expected["roots"]["items"][0][key], "{key}");
        }
        let structure = v2(
            &f,
            account,
            "get_structure",
            json!({"root_id":"native:root",
            "max_depth":0,"max_children_per_node":0}),
        )
        .await
        .unwrap();
        assert_eq!(actual["roots"]["items"], structure["nodes"]);
        assert_eq!(root["containment_path_visible"], true);
    }
    kernel::replace_home_policy(
        &f.db,
        &f.owner_principal,
        crate::events::KERNEL_ROOT_ID,
        &[(&f.owner_principal, "manage")],
    )
    .await
    .unwrap();
    let hidden = v2(&f, &f.member, "bootstrap", json!({})).await.unwrap();
    assert_eq!(hidden["roots"]["total"], 0);
    assert_eq!(hidden["roots"]["items"], json!([]));
    // Read-only/frozen bootstrap must still expose a permitted root without
    // writing a run or any other kernel projection.
    let before = kernel::dump_all_kernel_tables(&f.db).await.unwrap();
    let frozen = registry()
        .call_engine(
            EngineHandle::KernelV2(f.db.clone()),
            Caller::authenticated(&f.owner).with_suppressed_request_persistence(),
            "bootstrap",
            json!({}),
        )
        .await
        .unwrap();
    assert_eq!(frozen["roots"]["total"], 1);
    assert_eq!(before, kernel::dump_all_kernel_tables(&f.db).await.unwrap());
    f.source.close().await;
    f.db.close().await;
}
