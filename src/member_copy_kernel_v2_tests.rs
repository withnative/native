use super::*;
use crate::{db::Db, events::KERNEL_ROOT_ID};
use serde_json::json;

const OWNER: &str = "acct_00000000000000000000000000000001";
const MEMBER: &str = "acct_00000000000000000000000000000002";

async fn cut(db: &Db, account: &str) -> NativeMemberSource {
    let mut snapshot = db.pool().begin().await.unwrap();
    // Fixtures independently pin their source identity; production adapters
    // must use the authenticated route/install binding instead.
    let generation = kernel_v2::coordinates(&mut snapshot).await.unwrap();
    let origin = kernel_v2::origin(&mut snapshot, &generation).await.unwrap();
    let result = capture_in(&mut snapshot, &origin, account).await.unwrap();
    snapshot.rollback().await.unwrap();
    result
}
pub(super) fn ready(result: NativeMemberSource) -> NativeMemberCut {
    match result {
        NativeMemberSource::Ready(cut) => cut,
        NativeMemberSource::Revoked(reason) => panic!("unexpected authority loss: {reason:?}"),
        NativeMemberSource::Refused(reason) => panic!("unexpected source refusal: {reason:?}"),
    }
}

pub(super) async fn activate(db: &Db, actor: &str, members: &[&str]) {
    kernel::hosted_identity::reconcile_hosted_caller(db, |_| async {
        // SAFETY: complete portable-account roster owned by this fixture.
        Ok(unsafe {
            kernel::hosted_identity::VerifiedHostedMembership::from_accounts_unchecked(
                actor.into(),
                members.iter().map(|member| (*member).into()).collect(),
            )
        })
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn native_member_unactivated_source_refuses_even_with_root_view() {
    let dir = tempfile::tempdir().unwrap();
    let (db, owner) = kernel::create_v2_database(
        dir.path().join("source.db").to_str().unwrap(),
        "account",
        "Owner",
        OWNER,
    )
    .await
    .unwrap();
    let member = kernel::create_principal(&db, "account", "Member", MEMBER, &owner)
        .await
        .unwrap();
    kernel::replace_home_policy(
        &db,
        &owner,
        KERNEL_ROOT_ID,
        &[(&owner, "manage"), (&member, "view")],
    )
    .await
    .unwrap();
    assert!(
        kernel::kernel_effective_capability(&db, &member, KERNEL_ROOT_ID)
            .await
            .unwrap()
            .allows(Capability::View)
    );
    for account in [OWNER, MEMBER] {
        assert!(matches!(
            cut(&db, account).await,
            NativeMemberSource::Refused(MemberSourceRefusal::NotActivated)
        ));
    }
    kernel::replay_all_projections(&db).await.unwrap();
    assert!(matches!(
        cut(&db, MEMBER).await,
        NativeMemberSource::Refused(MemberSourceRefusal::NotActivated)
    ));
    activate(&db, OWNER, &[OWNER, MEMBER]).await;
    assert!(matches!(
        cut(&db, MEMBER).await,
        NativeMemberSource::Ready(_)
    ));
    db.close().await;
}

#[tokio::test]
async fn native_member_unknown_account_binding_refuses_without_claiming_revocation() {
    let dir = tempfile::tempdir().unwrap();
    let (db, _) = kernel::create_v2_database(
        dir.path().join("source.db").to_str().unwrap(),
        "account",
        "Owner",
        OWNER,
    )
    .await
    .unwrap();
    activate(&db, OWNER, &[OWNER]).await;
    let events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert!(matches!(
        cut(&db, "missing-account").await,
        NativeMemberSource::Refused(MemberSourceRefusal::UnknownAccountBinding)
    ));
    // N1 keeps its existing explicit error; only the member-source boundary
    // converts the shared lookup's absence to a non-purge typed refusal.
    assert!(
        crate::mcp::standby_stdio::resolve_kernel_account(&db, Some("missing-account"))
            .await
            .unwrap_err()
            .to_string()
            .contains("selected standby account has no kernel-v2 account auth_binding")
    );
    assert_eq!(
        events,
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap()
    );
    kernel::replay_all_projections(&db).await.unwrap();
    assert!(matches!(
        cut(&db, "missing-account").await,
        NativeMemberSource::Refused(MemberSourceRefusal::UnknownAccountBinding)
    ));
    assert!(matches!(
        cut(&db, OWNER).await,
        NativeMemberSource::Ready(_)
    ));
    db.close().await;
}

#[tokio::test]
async fn native_member_source_cuts_isolate_accounts_and_survive_replay() {
    let dir = tempfile::tempdir().unwrap();
    let (db, owner) = kernel::create_v2_database(
        dir.path().join("source.db").to_str().unwrap(),
        "account",
        "Owner",
        OWNER,
    )
    .await
    .unwrap();
    let member = kernel::create_principal(&db, "account", "Member", MEMBER, &owner)
        .await
        .unwrap();
    kernel::replace_home_policy(
        &db,
        &owner,
        KERNEL_ROOT_ID,
        &[(&owner, "manage"), (&member, "view")],
    )
    .await
    .unwrap();
    activate(&db, OWNER, &[OWNER, MEMBER]).await;
    let bearer = kernel::create_record_as(&db, &owner, KERNEL_ROOT_ID)
        .await
        .unwrap();
    let facet_pin = crate::named_views::inject_v2_reader_fixture(&db, &bearer).await;
    // Model an older generation. Replay below reinstalls the optional index,
    // but member cuts and their authorization fences must remain identical.
    sqlx::query("DROP INDEX idx_kernel_named_view_admissions")
        .execute(db.write_pool())
        .await
        .unwrap();
    sqlx::query(crate::named_views::INDEX_DDL)
        .execute(db.write_pool())
        .await
        .unwrap();
    let indexed = ready(cut(&db, OWNER).await);
    sqlx::query("DROP INDEX idx_kernel_named_view_lifecycle")
        .execute(db.write_pool())
        .await
        .unwrap();
    let a = ready(cut(&db, OWNER).await);
    assert!(a == indexed);
    let b = ready(cut(&db, MEMBER).await);
    assert_eq!(a.origin_database_id, b.origin_database_id);
    assert_eq!(a.genesis_event_id, b.genesis_event_id);
    assert_eq!(a.account_binding, OWNER);
    assert_eq!(b.account_binding, MEMBER);
    assert_eq!(a.principal_id, owner);
    assert_eq!(b.principal_id, member);
    assert_ne!(a.authorization_fence, b.authorization_fence);
    let a_identity = a.profile_identity();
    let b_identity = b.profile_identity();
    assert_eq!(a_identity.account_binding, OWNER);
    assert_eq!(b_identity.account_binding, MEMBER);
    assert_eq!(a_identity.principal_id, owner);
    assert_eq!(b_identity.principal_id, member);
    assert_eq!(a_identity.genesis_event_id, a.genesis_event_id);
    let declaration = serde_json::to_string(&a_identity).unwrap();
    assert!(!declaration.contains(&a.authorization_fence));
    for field in [
        "authorization_fence",
        "content_event_seq",
        "meta_event_seq",
        "head_act",
        "projection_tables",
    ] {
        assert!(!declaration.contains(field));
    }
    kernel::replay_all_projections(&db).await.unwrap();
    assert!(
        crate::named_views::storage::verify_index_on(&mut db.pool().acquire().await.unwrap())
            .await
            .unwrap()
    );
    let mut snapshot = db.pool().begin().await.unwrap();
    let state = crate::named_views::load_prefix(&mut snapshot, i64::MAX, None)
        .await
        .unwrap();
    assert!(state.revisions.contains_key(&facet_pin.revision_id));
    snapshot.rollback().await.unwrap();
    assert_eq!(a_identity, ready(cut(&db, OWNER).await).profile_identity());
    assert_eq!(b_identity, ready(cut(&db, MEMBER).await).profile_identity());
    assert!(a == ready(cut(&db, OWNER).await));
    assert!(b == ready(cut(&db, MEMBER).await));
    db.close().await;
}

#[tokio::test]
async fn native_member_root_view_loss_is_typed_revocation_in_the_same_read_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let (db, owner) = kernel::create_v2_database(
        dir.path().join("source.db").to_str().unwrap(),
        "account",
        "Owner",
        OWNER,
    )
    .await
    .unwrap();
    let member = kernel::create_principal(&db, "account", "Member", MEMBER, &owner)
        .await
        .unwrap();
    kernel::replace_home_policy(
        &db,
        &owner,
        KERNEL_ROOT_ID,
        &[(&owner, "manage"), (&member, "view")],
    )
    .await
    .unwrap();
    activate(&db, OWNER, &[OWNER, MEMBER]).await;
    let mut snapshot = db.pool().begin().await.unwrap();
    let generation = kernel_v2::coordinates(&mut snapshot).await.unwrap();
    let origin = kernel_v2::origin(&mut snapshot, &generation).await.unwrap();
    let before = ready(capture_in(&mut snapshot, &origin, MEMBER).await.unwrap());
    kernel::replace_home_policy(&db, &owner, KERNEL_ROOT_ID, &[(&owner, "manage")])
        .await
        .unwrap();
    assert!(before == ready(capture_in(&mut snapshot, &origin, MEMBER).await.unwrap()));
    snapshot.rollback().await.unwrap();
    assert!(matches!(
        cut(&db, MEMBER).await,
        NativeMemberSource::Revoked(MemberAuthorityLoss::RootView)
    ));
    assert!(matches!(
        cut(&db, OWNER).await,
        NativeMemberSource::Ready(_)
    ));
    kernel::replay_all_projections(&db).await.unwrap();
    assert!(matches!(
        cut(&db, MEMBER).await,
        NativeMemberSource::Revoked(MemberAuthorityLoss::RootView)
    ));
    db.close().await;
}

#[tokio::test]
async fn native_member_import_cutover_keeps_n1_account_binding_through_vault_publication_and_roster_loss(
) {
    use crate::identity::hosted::{
        reconcile_hosted_identity, HostedMembershipArrival, HostedMembershipRole,
        HostedMembershipSource,
    };
    use crate::mcp::{Caller, ToolRegistry};
    let dir = tempfile::tempdir().unwrap();
    let source_path = dir.path().join("source.db");
    let target_path = dir.path().join("target.db");
    let source = crate::create_database(source_path.to_str().unwrap())
        .await
        .unwrap();
    let mut accounts = vec![];
    for (user, role) in [
        ("owner", HostedMembershipRole::Owner),
        ("member", HostedMembershipRole::Member),
    ] {
        accounts.push(
            reconcile_hosted_identity(
                &source,
                &format!("{user}@example.test"),
                user,
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
    let owner = &accounts[0];
    let member = &accounts[1];
    let mut registry = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
    registry.call(source.clone(),Caller::local(),"manage_record_policy",json!({"action":"grant","record_id":"native:root","subject":{"kind":"account","account_id":owner},"capability":"manage","reason":"synthetic continuity owner"})).await.unwrap();
    registry.call(source.clone(),Caller::authenticated(owner),"create_record",json!({"type":"Document","kind":"note","name":"Continuity note","body":"Synthetic continuity body","reason":"cutover fixture"})).await.unwrap();
    let before_account =
        crate::mcp::standby_stdio::resolve_standby_account_identity(&source, Some(owner))
            .await
            .unwrap();
    let before = crate::query::sql::projection_snapshot(
        &source,
        crate::query::QueryPrincipal::authenticated(&before_account, true),
    )
    .await
    .unwrap();
    let vault = dir.path().join("vault");
    let mut publisher = crate::markdown_vault::Publisher::open(&vault).unwrap();
    assert!(publisher.cycle(&before).unwrap().is_empty());
    let members = dir.path().join("members.txt");
    std::fs::write(&members, format!("{owner}\n{member}\n")).unwrap();
    let report = crate::v1_import::run(crate::v1_import::Options {
        source: source_path,
        target: target_path.clone(),
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
    assert!(
        report.review.is_empty(),
        "{}",
        serde_json::to_string(&report.review).unwrap()
    );
    // The actual N1 opener and stdio account selection, with no installed node.
    let readonly = crate::db::open_kernel_v2_standby_read_only(target_path.to_str().unwrap())
        .await
        .unwrap();
    let after_account =
        crate::mcp::standby_stdio::resolve_kernel_account(&readonly, Some(&before_account))
            .await
            .unwrap();
    assert_eq!(before_account, after_account);
    assert_ne!(after_account, report.principals[owner]);
    let after = crate::markdown_vault::kernel_v2::snapshot(&readonly, &after_account)
        .await
        .unwrap();
    assert_eq!(before.origin, after.origin);
    assert_eq!(before.account, after.account);
    assert!(publisher.cycle(&after).unwrap().is_empty());
    assert!(matches!(
        cut(&readonly, member).await,
        NativeMemberSource::Refused(MemberSourceRefusal::NotActivated)
    ));
    readonly.close().await;

    let target = kernel::open_marked_v2_database(target_path.to_str().unwrap())
        .await
        .unwrap();
    let roster = [
        ("owner".to_owned(), "owner@example.test".to_owned()),
        ("member".to_owned(), "member@example.test".to_owned()),
    ]
    .into_iter()
    .collect::<std::collections::BTreeMap<_, _>>();
    kernel::hosted_identity::reconcile_hosted_caller(&target, |_| async {
        // SAFETY: this complete synthetic catalogue/roster is owned by the fixture.
        Ok(unsafe {
            kernel::hosted_identity::VerifiedHostedMembership::from_catalog_unchecked(
                "owner".into(),
                roster.clone(),
                roster.clone(),
            )
        })
    })
    .await
    .unwrap();
    assert_eq!(ready(cut(&target, member).await).account_binding, *member);
    let mut connection = target.pool().acquire().await.unwrap();
    let mapped = ready(
        capture_authenticated_catalog_in(&mut connection, &before.origin, "member")
            .await
            .unwrap(),
    );
    assert_eq!(mapped.account_binding, *member);
    assert_ne!(
        mapped.account_binding, "member",
        "catalogue id is not the portable account"
    );
    drop(connection);
    kernel::hosted_identity::reconcile_hosted_caller(&target, |_| async {
        // SAFETY: the same fixture catalogue now has only its owner as a member.
        Ok(unsafe {
            kernel::hosted_identity::VerifiedHostedMembership::from_catalog_unchecked(
                "owner".into(),
                [("owner".to_owned(), "owner@example.test".to_owned())]
                    .into_iter()
                    .collect(),
                roster,
            )
        })
    })
    .await
    .unwrap();
    assert!(matches!(
        cut(&target, member).await,
        NativeMemberSource::Revoked(MemberAuthorityLoss::RosterMembership)
    ));
    assert!(matches!(
        cut(&target, owner).await,
        NativeMemberSource::Ready(_)
    ));
    kernel::replay_all_projections(&target).await.unwrap();
    assert!(matches!(
        cut(&target, member).await,
        NativeMemberSource::Revoked(MemberAuthorityLoss::RosterMembership)
    ));
    let mut connection = target.pool().acquire().await.unwrap();
    assert!(matches!(
        capture_authenticated_catalog_in(&mut connection, &before.origin, "member")
            .await
            .unwrap(),
        NativeMemberSource::Revoked(MemberAuthorityLoss::RosterMembership)
    ));
    drop(connection);
    source.close().await;
    target.close().await;
}

#[tokio::test]
async fn native_member_wrong_source_refuses_before_activation_or_revocation() {
    let dir = tempfile::tempdir().unwrap();
    let (db, owner) = kernel::create_v2_database(
        dir.path().join("source.db").to_str().unwrap(),
        "account",
        "Owner",
        OWNER,
    )
    .await
    .unwrap();
    kernel::create_principal(&db, "account", "Member", MEMBER, &owner)
        .await
        .unwrap();
    let wrong_origin = "ndb_00000000000000000000000000000000";
    for stage in 0..4 {
        if stage == 1 {
            activate(&db, OWNER, &[OWNER, MEMBER]).await;
        } else if stage == 2 {
            activate(&db, OWNER, &[OWNER]).await;
        } else if stage == 3 {
            activate(&db, OWNER, &[OWNER, MEMBER]).await;
            kernel::replace_home_policy(&db, &owner, KERNEL_ROOT_ID, &[(&owner, "manage")])
                .await
                .unwrap();
        }
        let before = kernel::dump_all_kernel_tables(&db).await.unwrap();
        let mut snapshot = db.pool().begin().await.unwrap();
        for expected in [wrong_origin, "", "not-a-database-id"] {
            assert!(matches!(
                capture_in(&mut snapshot, expected, MEMBER).await.unwrap(),
                NativeMemberSource::Refused(MemberSourceRefusal::SourceIdentityMismatch)
            ));
        }
        snapshot.rollback().await.unwrap();
        assert_eq!(before, kernel::dump_all_kernel_tables(&db).await.unwrap());
        if stage == 2 {
            assert!(matches!(
                cut(&db, MEMBER).await,
                NativeMemberSource::Revoked(MemberAuthorityLoss::RosterMembership)
            ));
        }
        if stage == 3 {
            assert!(matches!(
                cut(&db, MEMBER).await,
                NativeMemberSource::Revoked(MemberAuthorityLoss::RootView)
            ));
        }
        kernel::replay_all_projections(&db).await.unwrap();
        let mut snapshot = db.pool().begin().await.unwrap();
        assert!(matches!(
            capture_in(&mut snapshot, wrong_origin, MEMBER)
                .await
                .unwrap(),
            NativeMemberSource::Refused(MemberSourceRefusal::SourceIdentityMismatch)
        ));
        snapshot.rollback().await.unwrap();
    }
    db.close().await;
}

#[tokio::test]
async fn native_member_authenticated_catalog_mapping_retains_typed_roster_revocation_on_replay() {
    let dir = tempfile::tempdir().unwrap();
    let (db, _) = kernel::create_v2_database(
        dir.path().join("source.db").to_str().unwrap(),
        "account",
        "Synthetic owner",
        "catalog-owner",
    )
    .await
    .unwrap();
    let reconcile = |include_member: bool| {
        let db = db.clone();
        async move {
            kernel::hosted_identity::reconcile_hosted_caller(&db, |_| async move {
                let mut users = std::collections::BTreeMap::from([(
                    "catalog-owner".into(),
                    "owner@example.test".into(),
                )]);
                if include_member {
                    users.insert("catalog-member".into(), "member@example.test".into());
                }
                // SAFETY: this synthetic fixture owns its complete catalogue roster.
                Ok(unsafe {
                    kernel::hosted_identity::VerifiedHostedMembership::from_catalog_unchecked(
                        "catalog-owner".into(),
                        users,
                        Default::default(),
                    )
                })
            })
            .await
            .unwrap();
        }
    };
    reconcile(true).await;
    let mut conn = db.pool().acquire().await.unwrap();
    let generation = kernel_v2::coordinates(&mut conn).await.unwrap();
    let expected_origin = kernel_v2::origin(&mut conn, &generation).await.unwrap();
    assert!(matches!(
        capture_authenticated_catalog_in(&mut conn, &expected_origin, "unmapped-catalog-user")
            .await
            .unwrap(),
        NativeMemberSource::Refused(MemberSourceRefusal::UnknownAccountBinding)
    ));
    reconcile(false).await;
    assert!(matches!(
        capture_authenticated_catalog_in(&mut conn, &expected_origin, "catalog-member")
            .await
            .unwrap(),
        NativeMemberSource::Revoked(MemberAuthorityLoss::RosterMembership)
    ));
    assert!(matches!(
        capture_authenticated_catalog_in(
            &mut conn,
            "ndb_00000000000000000000000000000000",
            "catalog-member"
        )
        .await
        .unwrap(),
        NativeMemberSource::Refused(MemberSourceRefusal::SourceIdentityMismatch)
    ));
    drop(conn);
    kernel::replay_all_projections(&db).await.unwrap();
    let mut conn = db.pool().acquire().await.unwrap();
    assert!(matches!(
        capture_authenticated_catalog_in(&mut conn, &expected_origin, "catalog-member")
            .await
            .unwrap(),
        NativeMemberSource::Revoked(MemberAuthorityLoss::RosterMembership)
    ));
    drop(conn);
    db.close().await;
}
