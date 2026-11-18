use super::*;

#[tokio::test]
async fn offboarding_transfers_private_content_retires_activity_and_rejoin_is_plain_member() {
    let dir = tempfile::tempdir().unwrap();
    let (db, departing) = create_v2_database(
        &format!("sqlite://{}", dir.path().join("cleanup.db").display()),
        "account",
        "Departing",
        "departing",
    )
    .await
    .unwrap();
    let recipient = create_principal(&db, "account", "Recipient", "recipient", &departing)
        .await
        .unwrap();
    let host = resolve_principal_by_binding(&db, hq::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    hq::import_home_policy_as(
        &db,
        &host,
        KERNEL_ROOT_ID,
        &[(&departing, "manage"), (&recipient, "edit")],
    )
    .await
    .unwrap();
    import_policy(
        &db,
        &host,
        KERNEL_ROOT_ID,
        BTreeMap::from([(departing.clone(), "manage".into())]),
        Some("edit".into()),
    )
    .await
    .unwrap();
    async fn live(db: &Db, actor: &str, both: bool) -> Result<crate::mcp::Caller> {
        reconcile_hosted_caller(db, |_| async move {
            let mut users = BTreeMap::from([("recipient".into(), "recipient@example.test".into())]);
            if both {
                users.insert("departing".into(), "departing@example.test".into());
            }
            // SAFETY: complete synthetic host catalogue, no request input.
            Ok(unsafe {
                VerifiedHostedMembership::from_catalog_unchecked(
                    actor.into(),
                    users,
                    BTreeMap::new(),
                )
            })
        })
        .await
    }
    live(&db, "departing", true).await.unwrap();
    let private = create_home(
        &db,
        KERNEL_ROOT_ID,
        Some(&[(&departing, "manage")]),
        &departing,
    )
    .await
    .unwrap();
    let content = create_record_as(&db, &departing, &private).await.unwrap();
    let shared = create_home(
        &db,
        KERNEL_ROOT_ID,
        Some(&[(&departing, "manage"), (&recipient, "view")]),
        &departing,
    )
    .await
    .unwrap();
    // A native policy replacement must be cleaned too, not just the imported template.
    replace_home_policy(
        &db,
        &departing,
        &shared,
        &[(&departing, "manage"), (&recipient, "view")],
    )
    .await
    .unwrap();
    let manifest = crate::v2_standard::claims_v1::package();
    let package = install_package_as(&db, &departing, &manifest)
        .await
        .unwrap();
    adopt_package_at(
        &db,
        &departing,
        KERNEL_ROOT_ID,
        &manifest,
        Some(&package),
        &manifest.declared_reads,
    )
    .await
    .unwrap();
    let (_, run) = run_ledger::mint_run_with_context_as(&db, &departing, None)
        .await
        .unwrap();
    let claim = claims_port::prepare_claim_as(
        &db,
        &run,
        &content,
        "claim-before-offboard",
        crate::v2_standard::claims_v1::Command::Claim,
    )
    .await
    .unwrap();
    claims_port::commit_claim_as(&db, &run, &claim)
        .await
        .unwrap();
    // This subject remains member-visible after rejoin, so visibility cannot
    // hide a stale receipt before the retry reaches the idempotency lookup.
    let visible = create_record_as(&db, &recipient, KERNEL_ROOT_ID)
        .await
        .unwrap();
    let visible_claim = claims_port::prepare_claim_as(
        &db,
        &run,
        &visible,
        "visible-claim-before-offboard",
        crate::v2_standard::claims_v1::Command::Claim,
    )
    .await
    .unwrap();
    claims_port::commit_claim_as(&db, &run, &visible_claim)
        .await
        .unwrap();
    live(&db, "recipient", false).await.unwrap();
    let op_id = Uuid::new_v4().to_string();
    let proof = || unsafe {
        offboarding::VerifiedOffboarding::from_catalog_unchecked(
            op_id.clone(),
            "recipient".into(),
            "departing".into(),
            "recipient".into(),
            "member removed".into(),
        )
    };
    let counts = offboarding::apply(&db, proof()).await.unwrap();
    assert!(counts.transferred_record_count >= 3);
    assert!(counts.removed_grant_count >= 3);
    assert_eq!(offboarding::apply(&db, proof()).await.unwrap(), counts);
    for replay in [false, true] {
        if replay {
            replay_all_projections(&db).await.unwrap();
        }
        assert_eq!(
            sqlx::query_scalar::<_, String>("SELECT owner_id FROM kernel_records WHERE id=?")
                .bind(&content)
                .fetch_one(db.pool())
                .await
                .unwrap(),
            recipient
        );
        assert_eq!(
            kernel_effective_capability(&db, &recipient, KERNEL_ROOT_ID)
                .await
                .unwrap(),
            Capability::Manage,
            "root ownership transfer retains workspace manage"
        );
        let receipts: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM kernel_provider_receipts WHERE principal_id=?",
        )
        .bind(&departing)
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(
            receipts, 0,
            "old membership receipts must not survive replay"
        );
        assert!(run_ledger::run_witness_as(&db, &run).await.unwrap().closed);
        assert!(
            !claims_port::claims_as(&db, &recipient, std::slice::from_ref(&content))
                .await
                .unwrap()[0]
                .occupied
        );
    }
    live(&db, "departing", true).await.unwrap();
    replay_all_projections(&db).await.unwrap();
    assert_eq!(
        kernel_effective_capability(&db, &departing, KERNEL_ROOT_ID)
            .await
            .unwrap(),
        Capability::Edit
    );
    assert_eq!(
        kernel_effective_capability(&db, &departing, &private)
            .await
            .unwrap(),
        Capability::None
    );
    assert_eq!(
        kernel_effective_capability(&db, &departing, &shared)
            .await
            .unwrap(),
        Capability::None
    );
    assert_eq!(
        kernel_effective_capability(&db, &departing, &content)
            .await
            .unwrap(),
        Capability::None
    );
    assert!(kernel_effective_capability(&db, &departing, &visible)
        .await
        .unwrap()
        .allows(Capability::View));
    let retry = claims_port::commit_claim_as(&db, &run, &visible_claim)
        .await
        .unwrap_err();
    assert!(
        retry.to_string().contains("run_closed"),
        "honest retry: {retry}"
    );
    db.close().await;
}

async fn admit(db: &Db, account: &str, members: &[&str]) -> Result<crate::mcp::Caller> {
    reconcile_hosted_caller(db, |_| async {
        // SAFETY: this synthetic catalogue fixture is host-owned. No request
        // arguments, labels or chosen principal IDs participate in resolution.
        Ok(unsafe {
            VerifiedHostedMembership::from_accounts_unchecked(
                account.into(),
                members.iter().map(|s| (*s).into()).collect(),
            )
        })
    })
    .await
}

#[tokio::test]
async fn catalogue_membership_mints_revokes_and_preserves_policy_boundaries() {
    let dir = tempfile::tempdir().unwrap();
    let (db, admin) = create_v2_database(
        &format!("sqlite://{}", dir.path().join("identity.db").display()),
        "account",
        "Owner",
        "owner",
    )
    .await
    .unwrap();
    let imported = create_principal(&db, "account", "Imported", "imported", &admin)
        .await
        .unwrap();
    let host = resolve_principal_by_binding(&db, hq::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    hq::import_home_policy_as(
        &db,
        &host,
        KERNEL_ROOT_ID,
        &[(&admin, "manage"), (&imported, "edit")],
    )
    .await
    .unwrap();
    import_policy(
        &db,
        &host,
        KERNEL_ROOT_ID,
        BTreeMap::from([(admin.clone(), "manage".into())]),
        Some("edit".into()),
    )
    .await
    .unwrap();
    let record = create_record_as(&db, &admin, KERNEL_ROOT_ID).await.unwrap();
    let private = create_home(&db, KERNEL_ROOT_ID, Some(&[(&admin, "manage")]), &admin)
        .await
        .unwrap();
    let secret = create_record_as(&db, &admin, &private).await.unwrap();
    let caller = admit(&db, "imported", &["owner", "imported"])
        .await
        .unwrap();
    assert_eq!(caller.credential(), "imported");
    assert_eq!(
        crate::mcp::kernel_v2::principal(&db, &caller)
            .await
            .unwrap(),
        imported
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    admit(&db, "imported", &["owner", "imported"])
        .await
        .unwrap();
    assert_eq!(
        count,
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap()
    );
    let newcomer = admit(&db, "new", &["owner", "imported", "new"])
        .await
        .unwrap();
    let new_id = crate::mcp::kernel_v2::principal(&db, &newcomer)
        .await
        .unwrap();
    assert_ne!(new_id, imported);
    assert_eq!(
        kernel_effective_capability(&db, &new_id, &record)
            .await
            .unwrap(),
        Capability::Edit
    );
    assert_eq!(
        kernel_effective_capability(&db, &new_id, &secret)
            .await
            .unwrap(),
        Capability::None
    );
    let owned = create_record_as(&db, &new_id, KERNEL_ROOT_ID)
        .await
        .unwrap();
    assert!(admit(&db, "new", &["owner", "imported"]).await.is_err());
    assert!(crate::mcp::kernel_v2::principal(&db, &newcomer)
        .await
        .is_err());
    assert_eq!(
        kernel_effective_capability(&db, &new_id, &owned)
            .await
            .unwrap(),
        Capability::None
    );
    assert!(list_records_as(&db, &new_id).await.unwrap().is_empty());
    assert!(admit(&db, "guest", &["owner", "imported"]).await.is_err());
    assert!(resolve_principal_by_binding(&db, "guest")
        .await
        .unwrap()
        .is_none());
    assert!(
        admit(&db, &admin, &["owner", "imported"]).await.is_err(),
        "a principal ID cannot select an account"
    );
    replay_all_projections(&db).await.unwrap();
    assert_eq!(
        kernel_effective_capability(&db, &new_id, &owned)
            .await
            .unwrap(),
        Capability::None
    );
    // A later ordinary policy replacement is authoritative over the template.
    replace_home_policy(&db, &admin, KERNEL_ROOT_ID, &[(&admin, "manage")])
        .await
        .unwrap();
    admit(&db, "new", &["owner", "imported", "new"])
        .await
        .unwrap();
    assert_eq!(
        kernel_effective_capability(&db, &new_id, &record)
            .await
            .unwrap(),
        Capability::None
    );
    replay_all_projections(&db).await.unwrap();
    assert_eq!(
        kernel_effective_capability(&db, &new_id, &record)
            .await
            .unwrap(),
        Capability::None
    );
    db.close().await;
}

#[tokio::test]
async fn host_events_cannot_be_supplied_by_callers_and_old_imports_refuse() {
    let dir = tempfile::tempdir().unwrap();
    let (db, admin) = create_v2_database(
        &format!("sqlite://{}", dir.path().join("sealed.db").display()),
        "account",
        "Owner",
        "owner",
    )
    .await
    .unwrap();
    let host = resolve_principal_by_binding(&db, hq::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    for event in [
        ROSTER_EVENT,
        POLICY_EVENT,
        IDENTITY_EVENT,
        offboarding::EVENT,
    ] {
        assert!(crate::store::append(
            &db,
            AppendSpec {
                record_id: KERNEL_ROOT_ID.into(),
                event_type: event.into(),
                payload: serde_json::json!({}),
                actor: Some(host.clone())
            }
        )
        .await
        .is_err());
    }
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert!(admit(&db, "guest", &["owner"]).await.is_err());
    assert_eq!(
        before,
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap()
    );
    hq::import_home_policy_as(&db, &host, KERNEL_ROOT_ID, &[(&admin, "manage")])
        .await
        .unwrap();
    assert!(admit(&db, "owner", &["owner"])
        .await
        .unwrap_err()
        .to_string()
        .contains("provenance"));
    assert!(admit(&db, "host:v1-import", &["host:v1-import"])
        .await
        .is_err());
    for binding in [
        hq::HOST_IMPORT_BINDING,
        relates_to_port::HOST_TRANSFORM_BINDING,
        "host:not-created",
    ] {
        let error = reconcile_hosted_caller_read_only(&db, |_| async {
            // SAFETY: deliberately invalid synthetic catalogue identity.
            Ok(unsafe {
                VerifiedHostedMembership::from_accounts_unchecked(
                    binding.into(),
                    [binding.into()].into_iter().collect(),
                )
            })
        })
        .await
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("invalid hosted catalogue account"),
            "{error}"
        );
    }

    db.close().await;
}

#[tokio::test]
async fn catalogue_ids_bind_imported_tokens_once_without_email_rebinding() {
    let dir = tempfile::tempdir().unwrap();
    let (db, admin) = create_v2_database(
        &format!("sqlite://{}", dir.path().join("mapped.db").display()),
        "account",
        "Owner",
        "acct_owner",
    )
    .await
    .unwrap();
    let imported = create_principal(&db, "account", "Imported", "acct_imported", &admin)
        .await
        .unwrap();
    let returning = create_principal(&db, "account", "Returning", "acct_returning", &admin)
        .await
        .unwrap();
    let host = resolve_principal_by_binding(&db, hq::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    hq::import_home_policy_as(
        &db,
        &host,
        KERNEL_ROOT_ID,
        &[(&admin, "manage"), (&imported, "edit")],
    )
    .await
    .unwrap();
    import_policy(
        &db,
        &host,
        KERNEL_ROOT_ID,
        BTreeMap::from([(admin.clone(), "manage".into())]),
        Some("edit".into()),
    )
    .await
    .unwrap();
    import_accounts(
        &db,
        &host,
        vec![
            ("owner@example.test".into(), "acct_owner".into()),
            ("member@example.test".into(), "acct_imported".into()),
            ("returner@example.test".into(), "acct_returning".into()),
        ],
    )
    .await
    .unwrap();
    let private = create_home(&db, KERNEL_ROOT_ID, Some(&[(&imported, "view")]), &admin)
        .await
        .unwrap();
    let record = create_record_as(&db, &admin, &private).await.unwrap();
    #[cfg(feature = "v2-kernel-probe")]
    let person = {
        let package = crate::v2_standard::v1_compat::package();
        let identity = package.identity().unwrap();
        install_package_as(&db, &admin, &package).await.unwrap();
        adopt_package_at(
            &db,
            &admin,
            KERNEL_ROOT_ID,
            &package,
            Some(&identity),
            &package.declared_reads,
        )
        .await
        .unwrap();
        let person = "person:mapped-member";
        hq::import_record_as(
            &db,
            &host,
            person,
            KERNEL_ROOT_ID,
            Some(&admin),
            &hq::ImportRecordState {
                message_principal: Some(imported.clone()),
                definition: Some(hq::ImportDefinition {
                    pin: RevisionIdentity {
                        family: package.definitions[0].family.clone(),
                        version: package.definitions[0].version,
                        digest: package.definitions[0].digest.clone(),
                    },
                    primary_type: "V1".into(),
                    kind: crate::v2_standard::v1_compat::KIND.into(),
                    fields: crate::v2_standard::v1_compat::compat_fields(
                        "Entity",
                        "person",
                        Some("Member"),
                        None,
                        None,
                    ),
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        person
    };
    async fn load(db: &Db, actor: &str, ids: &[(&str, &str)]) -> Result<crate::mcp::Caller> {
        reconcile_hosted_caller(db, |_| async {
            // SAFETY: this complete host fixture owns catalogue IDs and emails.
            Ok(unsafe {
                VerifiedHostedMembership::from_catalog_unchecked(
                    actor.into(),
                    ids.iter()
                        .map(|(id, email)| ((*id).into(), (*email).into()))
                        .collect(),
                    [
                        ("catalog-owner".into(), "owner@example.test".into()),
                        ("catalog-member".into(), "member@example.test".into()),
                        ("catalog-returner".into(), "returner@example.test".into()),
                    ]
                    .into_iter()
                    .collect(),
                )
            })
        })
        .await
    }
    let caller = load(
        &db,
        "catalog-member",
        &[
            ("catalog-owner", "owner@example.test"),
            ("catalog-member", "member@example.test"),
        ],
    )
    .await
    .unwrap();
    assert_eq!(caller.credential(), "acct_imported");
    let established = try_reconcile_hosted_caller_read_only(&db, |_| async {
        Ok(unsafe {
            VerifiedHostedMembership::from_catalog_unchecked(
                "catalog-member".into(),
                BTreeMap::from([
                    ("catalog-owner".into(), "renamed-owner@example.test".into()),
                    (
                        "catalog-member".into(),
                        "renamed-member@example.test".into(),
                    ),
                ]),
                BTreeMap::new(),
            )
        })
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        established.credential(),
        "acct_imported",
        "the read preflight must preserve imported bindings across email changes"
    );

    #[cfg(feature = "v2-kernel-probe")]
    {
        assert_eq!(
            visible_member_identity_as(&db, &imported, "catalog-member")
                .await
                .unwrap(),
            Some((imported.clone(), person.into()))
        );
        let hidden = create_home(&db, KERNEL_ROOT_ID, Some(&[(&admin, "manage")]), &admin)
            .await
            .unwrap();
        rehome_record_as(&db, &admin, person, &hidden)
            .await
            .unwrap();
        assert!(visible_member_identity_as(&db, &imported, "catalog-member")
            .await
            .unwrap()
            .is_none());
        rehome_record_as(&db, &admin, person, KERNEL_ROOT_ID)
            .await
            .unwrap();
    }
    assert_eq!(
        resolve_principal_by_binding(&db, caller.credential())
            .await
            .unwrap()
            .unwrap()
            .0,
        imported
    );
    let reused = load(
        &db,
        "catalog-new",
        &[
            ("catalog-owner", "owner@example.test"),
            ("catalog-new", "member@example.test"),
        ],
    )
    .await
    .unwrap();
    #[cfg(feature = "v2-kernel-probe")]
    {
        assert!(
            visible_member_identity_as(&db, &admin, "catalog-member")
                .await
                .unwrap()
                .is_none(),
            "a roster drop cannot retain identity disclosure"
        );
        assert!(
            visible_member_identity_as(&db, &admin, "catalog-new")
                .await
                .unwrap()
                .is_none(),
            "email reuse cannot inherit the source Person"
        );
    }
    assert_eq!(
        reused.credential(),
        "catalog-new",
        "a reused email cannot choose the imported principal after activation"
    );
    let new_id = resolve_principal_by_binding(&db, reused.credential())
        .await
        .unwrap()
        .unwrap()
        .0;
    assert_eq!(
        kernel_effective_capability(&db, &new_id, &record)
            .await
            .unwrap(),
        Capability::None
    );
    assert_eq!(
        kernel_effective_capability(&db, &imported, &record)
            .await
            .unwrap(),
        Capability::None
    );
    let rejoined = load(
        &db,
        "catalog-member",
        &[
            ("catalog-owner", "changed-owner@example.test"),
            ("catalog-member", "changed-member@example.test"),
        ],
    )
    .await
    .unwrap();
    assert_eq!(rejoined.credential(), "acct_imported");
    #[cfg(feature = "v2-kernel-probe")]
    assert_eq!(
        visible_member_identity_as(&db, &imported, "catalog-member")
            .await
            .unwrap(),
        Some((imported.clone(), person.into()))
    );
    assert_eq!(
        kernel_effective_capability(&db, &imported, &record)
            .await
            .unwrap(),
        Capability::View
    );
    assert_eq!(
        kernel_effective_capability(&db, &returning, KERNEL_ROOT_ID)
            .await
            .unwrap(),
        Capability::None
    );
    let returned = load(
        &db,
        "catalog-returner",
        &[
            ("catalog-owner", "changed-owner@example.test"),
            ("catalog-returner", "changed-returner@example.test"),
        ],
    )
    .await
    .unwrap();
    assert_eq!(returned.credential(), "acct_returning");
    assert_eq!(
        resolve_principal_by_binding(&db, returned.credential())
            .await
            .unwrap()
            .unwrap()
            .0,
        returning
    );
    replay_all_projections(&db).await.unwrap();
    assert_eq!(
        kernel_effective_capability(&db, &returning, KERNEL_ROOT_ID)
            .await
            .unwrap(),
        Capability::Edit
    );
    db.close().await;
}

#[tokio::test]
async fn bulk_home_policy_matches_single_gate_across_roster_and_policy_changes() {
    let dir = tempfile::tempdir().unwrap();
    let (db, admin) = create_v2_database(
        dir.path().join("bulk.db").to_str().unwrap(),
        "account",
        "Owner",
        "owner",
    )
    .await
    .unwrap();
    let member = create_principal(&db, "account", "Member", "member", &admin)
        .await
        .unwrap();
    let host = resolve_principal_by_binding(&db, hq::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    hq::import_home_policy_as(
        &db,
        &host,
        KERNEL_ROOT_ID,
        &[(&admin, "manage"), (&member, "view")],
    )
    .await
    .unwrap();
    import_policy(
        &db,
        &host,
        KERNEL_ROOT_ID,
        BTreeMap::from([(admin.clone(), "manage".into())]),
        Some("view".into()),
    )
    .await
    .unwrap();
    let private = create_home(&db, KERNEL_ROOT_ID, Some(&[(&admin, "manage")]), &admin)
        .await
        .unwrap();
    create_home(&db, &private, None, &admin).await.unwrap();
    create_home(&db, KERNEL_ROOT_ID, None, &admin)
        .await
        .unwrap();
    async fn compare(db: &Db, principals: &[&str]) {
        let mut tx = db.pool().begin().await.unwrap();
        for principal in principals {
            let bulk = visible_home_anchors_as(&mut tx, principal).await.unwrap();
            let admitted = admitted(&mut tx, principal).await.unwrap();
            if !admitted {
                assert!(bulk.homes.is_empty());
                continue;
            }
            for home in bulk.homes {
                match kernel_policy_capability_on(&mut tx, principal, &home.home_id).await {
                    Ok(cap) => {
                        assert!(home.policy_valid);
                        assert_eq!(home.policy_view, cap.allows(Capability::View));
                    }
                    Err(Error::Engine(message)) if message == HIDDEN_OR_MISSING => {
                        assert!(!home.policy_valid);
                        assert!(!home.policy_view);
                    }
                    Err(e) => panic!("single gate failed: {e}"),
                }
            }
        }
        tx.rollback().await.unwrap();
    }
    compare(&db, &[&admin, &member]).await;
    admit(&db, "owner", &["owner", "member"]).await.unwrap();
    compare(&db, &[&admin, &member]).await;
    admit(&db, "owner", &["owner"]).await.unwrap();
    compare(&db, &[&admin, &member]).await;
    admit(&db, "owner", &["owner", "member"]).await.unwrap();
    replace_home_policy(&db, &admin, KERNEL_ROOT_ID, &[(&admin, "manage")])
        .await
        .unwrap();
    compare(&db, &[&admin, &member]).await;
    sqlx::query("INSERT INTO kernel_policy_entries(root_id,subject_kind,subject_id,effect,capability) VALUES(?,'bogus','bad','bogus','view')").bind(private).execute(db.write_pool()).await.unwrap();
    compare(&db, &[&admin, &member]).await;
    db.close().await;
}

/// The frontier lookup beside the template lookup has the same constraint.
#[tokio::test]
async fn policy_frontier_lookup_never_scans_the_event_log() {
    let dir = tempfile::tempdir().unwrap();
    let (db, _) = create_v2_database(
        dir.path().join("frontier-plan.db").to_str().unwrap(),
        "account",
        "Owner",
        "owner",
    )
    .await
    .unwrap();
    let plan: Vec<(i64, i64, i64, String)> =
        sqlx::query_as(&format!("EXPLAIN QUERY PLAN {POLICY_FRONTIERS_SQL}"))
            .fetch_all(db.pool())
            .await
            .unwrap();
    let details: Vec<&str> = plan.iter().map(|row| row.3.as_str()).collect();
    let scans_events = |detail: &&str| {
        let target = detail
            .strip_prefix("SCAN TABLE ")
            .or_else(|| detail.strip_prefix("SCAN "));
        target.is_some_and(|t| {
            t.starts_with("e ") || t == "e" || t.starts_with("main.content_events")
        })
    };
    assert!(
        !details.iter().any(scans_events),
        "policy frontier lookup scans the event log: {details:?}"
    );
    db.close().await;
}

/// Bulk visibility runs on every v2 read. Its template lookup must reach
/// events through each policy home's record_id index, never by scanning the
/// whole event log (which cost ~460 ms per read on HQ before 9 Nov 2026).
#[tokio::test]
async fn policy_template_lookup_never_scans_the_event_log() {
    let dir = tempfile::tempdir().unwrap();
    let (db, _) = create_v2_database(
        dir.path().join("plan.db").to_str().unwrap(),
        "account",
        "Owner",
        "owner",
    )
    .await
    .unwrap();
    let plan: Vec<(i64, i64, i64, String)> =
        sqlx::query_as(&format!("EXPLAIN QUERY PLAN {POLICY_TEMPLATES_SQL}"))
            .bind(POLICY_EVENT)
            .fetch_all(db.pool())
            .await
            .unwrap();
    let details: Vec<&str> = plan.iter().map(|row| row.3.as_str()).collect();
    // `e` and `main.content_events` are the event log's two aliases here;
    // SQLite before 3.36 words a scan as `SCAN TABLE <name>`.
    let scans_events = |detail: &&str| {
        let target = detail
            .strip_prefix("SCAN TABLE ")
            .or_else(|| detail.strip_prefix("SCAN "));
        target.is_some_and(|t| {
            t.starts_with("e ") || t == "e" || t.starts_with("main.content_events")
        })
    };
    assert!(
        !details.iter().any(scans_events),
        "policy template lookup scans the event log: {details:?}"
    );
    db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn write_request_read_caches_follow_roster_events() {
    let dir = tempfile::tempdir().unwrap();
    let (db, admin) = create_v2_database(
        dir.path().join("roster-cache.db").to_str().unwrap(),
        "account",
        "Owner",
        "owner",
    )
    .await
    .unwrap();
    let viewer = create_principal(&db, "account", "Member", "member", &admin)
        .await
        .unwrap();
    let host = resolve_principal_by_binding(&db, hq::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    hq::import_home_policy_as(
        &db,
        &host,
        KERNEL_ROOT_ID,
        &[(&admin, "manage"), (&viewer, "view")],
    )
    .await
    .unwrap();
    import_policy(
        &db,
        &host,
        KERNEL_ROOT_ID,
        BTreeMap::from([(admin.clone(), "manage".into())]),
        Some("view".into()),
    )
    .await
    .unwrap();
    admit(&db, "owner", &["owner", "member"]).await.unwrap();
    let record = create_record_as(&db, &admin, KERNEL_ROOT_ID).await.unwrap();
    read_cache::scope_request(async {
        let namespaces = [
            "home_visibility",
            "lifecycle",
            "ancestor_descriptors",
            "disclosed_accounts",
        ];
        let mut snapshot = db.write_pool().begin().await.unwrap();
        let mut before = Vec::new();
        for namespace in namespaces {
            let key = read_cache::key_on(&mut snapshot, &viewer, namespace)
                .await
                .unwrap();
            read_cache::put(key.clone(), std::sync::Arc::new(17usize));
            before.push(key);
        }
        assert!(read_record_on(&mut snapshot, &viewer, &record)
            .await
            .unwrap()
            .is_some());
        snapshot.rollback().await.unwrap();
        admit(&db, "owner", &["owner"]).await.unwrap();
        let mut snapshot = db.write_pool().begin().await.unwrap();
        for (namespace, old) in namespaces.into_iter().zip(before) {
            let key = read_cache::key_on(&mut snapshot, &viewer, namespace)
                .await
                .unwrap();
            assert!(key != old, "{namespace}");
            assert!(read_cache::get::<usize>(&key).is_none());
        }
        assert!(read_record_on(&mut snapshot, &viewer, &record)
            .await
            .unwrap()
            .is_none());
        snapshot.rollback().await.unwrap();
    })
    .await;
    db.close().await;
}

use bundles::{
    BundleDefinition, BundleSetting, BUNDLE_DEFINED_EVENT, BUNDLE_UPDATED_EVENT, ROSTER_V2_EVENT,
};

fn expected_seeded_values(id: &str) -> BTreeMap<String, serde_json::Value> {
    let mut values = BTreeMap::new();
    for setting in BundleSetting::all() {
        let value = match id {
            bundles::OWNER_BUNDLE_ID => setting != BundleSetting::ExpiryRequired,
            bundles::MEMBER_BUNDLE_ID => !matches!(
                setting,
                BundleSetting::ExpiryRequired
                    | BundleSetting::ManageAccess
                    | BundleSetting::ManageWorkspace
            ),
            bundles::GUEST_BUNDLE_ID => setting == BundleSetting::ExpiryRequired,
            _ => panic!("unexpected seeded bundle {id}"),
        };
        values.insert(setting.as_str().to_string(), serde_json::Value::Bool(value));
    }
    values
}

#[tokio::test]
#[allow(clippy::explicit_auto_deref)]
async fn membership_bundles_seed_owner_member_guest_with_table_values() {
    let dir = tempfile::tempdir().unwrap();
    let (db, _admin) = create_v2_database(
        &format!("sqlite://{}", dir.path().join("bundles.db").display()),
        "account",
        "Owner",
        "owner",
    )
    .await
    .unwrap();
    // Seeding happens at creation, before any roster: standalone databases
    // carry the bundles with no membership at all.
    assert!(roster_on(&mut *db.pool().acquire().await.unwrap())
        .await
        .unwrap()
        .is_none());
    let mut conn = db.pool().acquire().await.unwrap();
    let found = bundles::list_membership_bundles_on(&mut *conn)
        .await
        .unwrap();
    assert_eq!(
        found
            .iter()
            .map(|bundle| bundle.id.as_str())
            .collect::<Vec<_>>(),
        vec!["guest", "member", "owner"]
    );
    for bundle in &found {
        assert!(bundle.seeded, "{}", bundle.id);
        assert!(!bundle.name.trim().is_empty(), "{}", bundle.id);
        assert!(!bundle.description.trim().is_empty(), "{}", bundle.id);
        assert_eq!(
            bundle.settings.version,
            bundles::BUNDLE_SETTINGS_VERSION,
            "{}",
            bundle.id
        );
        assert_eq!(
            bundle.settings.values,
            expected_seeded_values(&bundle.id),
            "{}",
            bundle.id
        );
    }
    // Typed reads agree with the design table for every setting.
    let owner = found.iter().find(|bundle| bundle.id == "owner").unwrap();
    assert_eq!(owner.setting(BundleSetting::MembersBaseline), Some(true));
    assert_eq!(owner.setting(BundleSetting::ExpiryRequired), Some(false));
    let member = found.iter().find(|bundle| bundle.id == "member").unwrap();
    assert_eq!(member.setting(BundleSetting::ManageAccess), Some(false));
    assert_eq!(member.setting(BundleSetting::ManageWorkspace), Some(false));
    assert_eq!(member.setting(BundleSetting::Mcp), Some(true));
    let guest = found.iter().find(|bundle| bundle.id == "guest").unwrap();
    assert_eq!(guest.setting(BundleSetting::ExpiryRequired), Some(true));
    assert_eq!(guest.setting(BundleSetting::Mcp), Some(false));
    assert_eq!(guest.setting(BundleSetting::MembersBaseline), Some(false));
    // Setting names parse exactly, and nothing else does.
    for setting in BundleSetting::all() {
        assert_eq!(BundleSetting::parse(setting.as_str()), Some(setting));
    }
    assert_eq!(BundleSetting::parse("owner"), None);
    assert_eq!(BundleSetting::parse(""), None);
    // The pool connection must return before close drains the pools.
    drop(conn);
    db.close().await;
}

async fn write_bundle_event(
    db: &Db,
    event_type: &str,
    definition: &BundleDefinition,
    actor: &str,
) -> Result<()> {
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let mut acts = crate::act::ActAllocation::new();
    let result =
        bundles::append_bundle_event_in(db, &mut tx, event_type, definition, actor, &mut acts)
            .await;
    match result {
        Ok(()) => {
            tx.commit().await?;
            Ok(())
        }
        Err(error) => {
            tx.rollback().await?;
            Err(error)
        }
    }
}

#[tokio::test]
#[allow(clippy::explicit_auto_deref)]
async fn membership_bundle_defined_then_updated_projects_and_unknown_keys_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let (db, _admin) = create_v2_database(
        &format!("sqlite://{}", dir.path().join("bundle-edit.db").display()),
        "account",
        "Owner",
        "owner",
    )
    .await
    .unwrap();
    let host = resolve_principal_by_binding(&db, hq::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let mut values = BTreeMap::from([(
        BundleSetting::ManageAccess.as_str().to_string(),
        serde_json::Value::Bool(true),
    )]);
    // Unknown future keys must survive a write/read round-trip untouched.
    values.insert("mailbox_quota".to_string(), serde_json::json!(5));
    values.insert("future_flag".to_string(), serde_json::json!("soon"));
    let defined = BundleDefinition {
        id: "steward".to_string(),
        name: "Steward".to_string(),
        description: "Custom access administration.".to_string(),
        seeded: false,
        settings: bundles::BundleSettings {
            version: bundles::BUNDLE_SETTINGS_VERSION,
            values,
        },
    };
    // An update for an undefined id refuses before anything is stored.
    assert!(
        write_bundle_event(&db, BUNDLE_UPDATED_EVENT, &defined, &host)
            .await
            .is_err()
    );
    write_bundle_event(&db, BUNDLE_DEFINED_EVENT, &defined, &host)
        .await
        .unwrap();
    // Defining the same id twice refuses; updates are the edit path.
    assert!(
        write_bundle_event(&db, BUNDLE_DEFINED_EVENT, &defined, &host)
            .await
            .is_err()
    );
    // A non-host actor cannot write bundle events even through the sealed route.
    assert!(
        write_bundle_event(&db, BUNDLE_UPDATED_EVENT, &defined, "owner")
            .await
            .is_err()
    );
    let mut conn = db.pool().acquire().await.unwrap();
    let read = bundles::bundle_before(&mut *conn, "steward", i64::MAX)
        .await
        .unwrap()
        .expect("defined bundle reads back");
    assert_eq!(read, defined);
    assert_eq!(read.setting(BundleSetting::ManageAccess), Some(true));
    let mut updated = defined.clone();
    updated.settings.values.insert(
        BundleSetting::ManageAccess.as_str().to_string(),
        serde_json::Value::Bool(false),
    );
    write_bundle_event(&db, BUNDLE_UPDATED_EVENT, &updated, &host)
        .await
        .unwrap();
    let read = bundles::bundle_before(&mut *conn, "steward", i64::MAX)
        .await
        .unwrap()
        .expect("updated bundle reads back");
    assert_eq!(read, updated);
    assert_eq!(read.setting(BundleSetting::ManageAccess), Some(false));
    // Unknown keys survive the update untouched.
    assert_eq!(
        read.settings.values.get("mailbox_quota"),
        Some(&serde_json::json!(5))
    );
    assert_eq!(
        read.settings.values.get("future_flag"),
        Some(&serde_json::json!("soon"))
    );
    // An update may rename, but must not flip the seeded flag either way.
    let mut reseeded = updated.clone();
    reseeded.seeded = true;
    assert!(
        write_bundle_event(&db, BUNDLE_UPDATED_EVENT, &reseeded, &host)
            .await
            .is_err()
    );
    let mut unseeded = bundles::seeded_bundle(bundles::OWNER_BUNDLE_ID).unwrap();
    unseeded.description = "Still the owner bundle.".to_string();
    unseeded.seeded = false;
    assert!(
        write_bundle_event(&db, BUNDLE_UPDATED_EVENT, &unseeded, &host)
            .await
            .is_err()
    );
    assert!(bundles::bundle_before(&mut *conn, "missing", i64::MAX)
        .await
        .unwrap()
        .is_none());
    let found = bundles::list_membership_bundles_on(&mut *conn)
        .await
        .unwrap();
    assert_eq!(found.len(), 4);
    assert!(found.iter().any(|bundle| bundle.id == "steward"));
    replay_all_projections(&db).await.unwrap();
    let replayed = bundles::list_membership_bundles_on(&mut *conn)
        .await
        .unwrap();
    assert_eq!(replayed, found);
    drop(conn);
    db.close().await;
}

#[tokio::test]
async fn membership_bundle_seeding_is_idempotent_for_existing_databases() {
    let dir = tempfile::tempdir().unwrap();
    let (db, _admin) = create_v2_database(
        &format!("sqlite://{}", dir.path().join("bundle-seed.db").display()),
        "account",
        "Owner",
        "owner",
    )
    .await
    .unwrap();
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM content_events WHERE record_id=? AND type=?")
            .bind(KERNEL_ROOT_ID)
            .bind(BUNDLE_DEFINED_EVENT)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(count, 3);
    // The host calls this for databases created before bundle seeding; on a
    // seeded database it must store nothing new.
    bundles::ensure_seeded_bundles(&db).await.unwrap();
    let again: i64 =
        sqlx::query_scalar("SELECT count(*) FROM content_events WHERE record_id=? AND type=?")
            .bind(KERNEL_ROOT_ID)
            .bind(BUNDLE_DEFINED_EVENT)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(again, 3);
    db.close().await;
}

#[tokio::test]
#[allow(clippy::explicit_auto_deref)]
async fn roster_reader_handles_v1_and_v2_events_with_none_bundles_for_v1() {
    let dir = tempfile::tempdir().unwrap();
    let (db, _admin) = create_v2_database(
        &format!(
            "sqlite://{}",
            dir.path().join("roster-versions.db").display()
        ),
        "account",
        "Owner",
        "owner",
    )
    .await
    .unwrap();
    admit(&db, "owner", &["owner", "member"]).await.unwrap();
    let mut conn = db.pool().acquire().await.unwrap();
    let (_, view) = bundles::roster_view_before(&mut *conn, i64::MAX)
        .await
        .unwrap()
        .expect("v1 roster reads as a view");
    assert_eq!(view.members.len(), 2);
    // A v1 member stores no bundle, so the view reports None.
    for member in view.members.values() {
        assert!(member.bundle.is_none());
        assert!(!member.principal.trim().is_empty());
    }
    // Ordinary admission keeps working from the converted v1 shape.
    assert!(admitted(&mut *conn, &view.members["owner"].principal)
        .await
        .unwrap());
    let v1_seq: i64 =
        sqlx::query_scalar("SELECT max(seq) FROM content_events WHERE record_id=? AND type=?")
            .bind(KERNEL_ROOT_ID)
            .bind(ROSTER_EVENT)
            .fetch_one(&mut *conn)
            .await
            .unwrap();
    let host = resolve_principal_by_binding(&db, hq::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let owner_id = resolve_principal_by_binding(&db, "owner")
        .await
        .unwrap()
        .unwrap()
        .0;
    let member_id = resolve_principal_by_binding(&db, "member")
        .await
        .unwrap()
        .unwrap()
        .0;
    let payload = serde_json::json!({
        "members": {
            "owner": {"principal": owner_id, "bundle": "owner"},
            "member": {"principal": member_id, "bundle": "member"},
        },
        "catalog_accounts": {},
    });
    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    let mut acts = crate::act::ActAllocation::new();
    crate::store::append_in(
        &db,
        &mut tx,
        AppendSpec {
            record_id: KERNEL_ROOT_ID.into(),
            event_type: ROSTER_V2_EVENT.into(),
            payload,
            actor: Some(host),
        },
        &mut acts,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    // A horizon before the v2 write still sees the v1 roster with None bundles.
    let (_, before) = bundles::roster_view_before(&mut *conn, v1_seq + 1)
        .await
        .unwrap()
        .expect("v1 roster visible before the v2 write");
    assert!(before
        .members
        .values()
        .all(|member| member.bundle.is_none()));
    // The latest event wins: v2 members carry their bundle ids.
    let (_, after) = bundles::roster_view_before(&mut *conn, i64::MAX)
        .await
        .unwrap()
        .expect("v2 roster reads as a view");
    assert_eq!(
        after.members["owner"].bundle.as_deref(),
        Some(bundles::OWNER_BUNDLE_ID)
    );
    assert_eq!(
        after.members["member"].bundle.as_deref(),
        Some(bundles::MEMBER_BUNDLE_ID)
    );
    // The view carries the v2 catalogue accounts alongside the bundles.
    let converted_first = roster_on(&mut *conn).await.unwrap().unwrap();
    assert_eq!(after.catalog_accounts, converted_first.catalog_accounts);
    // Admission reads the v1 roster only, so the v2 event is invisible to it:
    // the converted roster still carries the v1 member set.
    assert!(admitted(&mut *conn, &owner_id).await.unwrap());
    assert!(admitted(&mut *conn, &member_id).await.unwrap());
    let converted = roster_on(&mut *conn).await.unwrap().unwrap();
    assert_eq!(converted.members["owner"], owner_id);
    assert_eq!(converted.members["member"], member_id);
    replay_all_projections(&db).await.unwrap();
    let (_, replayed) = bundles::roster_view_before(&mut *conn, i64::MAX)
        .await
        .unwrap()
        .expect("v2 roster survives replay");
    assert_eq!(
        replayed.members["owner"].bundle.as_deref(),
        Some(bundles::OWNER_BUNDLE_ID)
    );
    drop(conn);
    db.close().await;
}

#[tokio::test]
#[allow(clippy::explicit_auto_deref)]
async fn v2_roster_with_different_members_does_not_change_admission() {
    let dir = tempfile::tempdir().unwrap();
    let (db, _admin) = create_v2_database(
        &format!(
            "sqlite://{}",
            dir.path().join("roster-v2-fence.db").display()
        ),
        "account",
        "Owner",
        "owner",
    )
    .await
    .unwrap();
    admit(&db, "owner", &["owner", "member"]).await.unwrap();
    let host = resolve_principal_by_binding(&db, hq::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let owner_id = resolve_principal_by_binding(&db, "owner")
        .await
        .unwrap()
        .unwrap()
        .0;
    let member_id = resolve_principal_by_binding(&db, "member")
        .await
        .unwrap()
        .unwrap()
        .0;
    // A principal the v1 roster never admitted, carried only by the v2 event.
    create_principal(&db, "account", "Intruder", "intruder", &owner_id)
        .await
        .unwrap();
    let intruder_id = resolve_principal_by_binding(&db, "intruder")
        .await
        .unwrap()
        .unwrap()
        .0;
    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    let mut acts = crate::act::ActAllocation::new();
    crate::store::append_in(
        &db,
        &mut tx,
        AppendSpec {
            record_id: KERNEL_ROOT_ID.into(),
            event_type: ROSTER_V2_EVENT.into(),
            payload: serde_json::json!({
                "members": {
                    "owner": {"principal": owner_id, "bundle": "owner"},
                    "intruder": {"principal": intruder_id, "bundle": "guest"},
                },
                "catalog_accounts": {},
            }),
            actor: Some(host),
        },
        &mut acts,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let mut conn = db.pool().acquire().await.unwrap();
    // The view follows the v2 event, including the guest bundle id.
    let (_, view) = bundles::roster_view_before(&mut *conn, i64::MAX)
        .await
        .unwrap()
        .expect("v2 roster reads as a view");
    assert_eq!(
        view.members["intruder"].bundle.as_deref(),
        Some(bundles::GUEST_BUNDLE_ID)
    );
    let fenced = roster_on(&mut *conn).await.unwrap().unwrap();
    assert_eq!(view.catalog_accounts, fenced.catalog_accounts);
    // Admission still reads the v1 roster only: the v2-only principal stays
    // out, the v2-dropped member stays in, and roster_on is unchanged.
    assert!(!admitted(&mut *conn, &intruder_id).await.unwrap());
    assert!(admitted(&mut *conn, &owner_id).await.unwrap());
    assert!(admitted(&mut *conn, &member_id).await.unwrap());
    let roster = roster_on(&mut *conn).await.unwrap().unwrap();
    assert_eq!(roster.members.len(), 2);
    assert_eq!(roster.members["member"], member_id);
    assert!(!roster.members.contains_key("intruder"));
    drop(conn);
    db.close().await;
}

#[tokio::test]
async fn bundle_and_v2_roster_events_are_refused_on_the_public_seam() {
    let dir = tempfile::tempdir().unwrap();
    let (db, _admin) = create_v2_database(
        &format!("sqlite://{}", dir.path().join("bundle-sealed.db").display()),
        "account",
        "Owner",
        "owner",
    )
    .await
    .unwrap();
    let host = resolve_principal_by_binding(&db, hq::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    // Every payload below is valid for the sealed route (it would project
    // cleanly), so only the public-seam gate can refuse them. Deleting the
    // `reject_public_runtime_event` lines for these types must turn this
    // test red.
    let mut owner = bundles::seeded_bundle(bundles::OWNER_BUNDLE_ID).unwrap();
    owner.description = "Edited through the public seam.".to_string();
    let steward = bundles::BundleDefinition {
        id: "steward".to_string(),
        name: "Steward".to_string(),
        description: "Custom access administration.".to_string(),
        seeded: false,
        settings: bundles::BundleSettings {
            version: bundles::BUNDLE_SETTINGS_VERSION,
            values: BTreeMap::from([(
                BundleSetting::ManageAccess.as_str().to_string(),
                serde_json::Value::Bool(true),
            )]),
        },
    };
    for (event_type, payload) in [
        (
            BUNDLE_DEFINED_EVENT,
            serde_json::to_value(&steward).unwrap(),
        ),
        (BUNDLE_UPDATED_EVENT, serde_json::to_value(&owner).unwrap()),
        (
            ROSTER_V2_EVENT,
            serde_json::json!({"members": {}, "catalog_accounts": {}}),
        ),
    ] {
        let refused = crate::store::append(
            &db,
            AppendSpec {
                record_id: KERNEL_ROOT_ID.into(),
                event_type: event_type.into(),
                payload,
                actor: Some(host.clone()),
            },
        )
        .await;
        assert!(refused.is_err(), "{event_type}");
    }
    db.close().await;
}

async fn bundle_defined_count(db: &Db) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM content_events WHERE record_id=? AND type=?")
        .bind(KERNEL_ROOT_ID)
        .bind(BUNDLE_DEFINED_EVENT)
        .fetch_one(db.pool())
        .await
        .unwrap()
}

async fn delete_bundle_events(db: &Db) {
    // Fixture-only concession (links_v2_tests precedent): the canonical log
    // is append-only by trigger, so simulating a pre-2a database means
    // dropping the delete guard first. These databases are per-test
    // tempfiles, discarded afterwards.
    sqlx::query("DROP TRIGGER IF EXISTS content_events_no_delete")
        .execute(db.write_pool())
        .await
        .unwrap();
    sqlx::query("DELETE FROM main.content_events WHERE record_id=? AND type IN (?,?)")
        .bind(KERNEL_ROOT_ID)
        .bind(BUNDLE_DEFINED_EVENT)
        .bind(BUNDLE_UPDATED_EVENT)
        .execute(db.write_pool())
        .await
        .unwrap();
}

async fn total_content_events(db: &Db) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap()
}

#[tokio::test]
#[allow(clippy::explicit_auto_deref)]
async fn admission_seeds_bundles_once_on_a_pre_2a_database() {
    let dir = tempfile::tempdir().unwrap();
    let (db, _admin) = create_v2_database(
        &format!("sqlite://{}", dir.path().join("admit-seed.db").display()),
        "account",
        "Owner",
        "owner",
    )
    .await
    .unwrap();
    // Simulate a database created before 2a: no bundle events at all.
    delete_bundle_events(&db).await;
    assert_eq!(bundle_defined_count(&db).await, 0);

    // First admission seeds under the same write lock/actor/transaction as
    // the roster reconcile, and still admits.
    let caller = admit(&db, "owner", &["owner"]).await.unwrap();
    assert_eq!(caller.credential(), "owner");
    assert_eq!(bundle_defined_count(&db).await, 3);
    let mut conn = db.pool().acquire().await.unwrap();
    let found = bundles::list_membership_bundles_on(&mut *conn)
        .await
        .unwrap();
    assert_eq!(found.len(), 3);
    drop(conn);

    // Second admission is a no-op: no new bundle or roster events.
    let before = total_content_events(&db).await;
    let again = admit(&db, "owner", &["owner"]).await.unwrap();
    assert_eq!(again.credential(), "owner");
    assert_eq!(bundle_defined_count(&db).await, 3);
    assert_eq!(total_content_events(&db).await, before);
    db.close().await;
}

#[tokio::test]
#[allow(clippy::explicit_auto_deref)]
async fn admission_rolls_back_a_refused_bundle_seed() {
    let dir = tempfile::tempdir().unwrap();
    let (db, _admin) = create_v2_database(
        &format!(
            "sqlite://{}",
            dir.path().join("admit-refused-seed.db").display()
        ),
        "account",
        "Owner",
        "owner",
    )
    .await
    .unwrap();
    delete_bundle_events(&db).await;
    assert_eq!(bundle_defined_count(&db).await, 0);

    // Refuse `member` at projection: the kernel append inserts the event row
    // before projecting it, so without savepoint fencing the `owner` row (and
    // the refused `member` row) would commit with the roster. Admission must
    // still succeed, the roster must commit, and the seed set must be
    // all-or-nothing.
    let caller =
        bundles::with_refused_bundle_id("member", async { admit(&db, "owner", &["owner"]).await })
            .await
            .unwrap();
    assert_eq!(caller.credential(), "owner");
    let mut conn = db.pool().acquire().await.unwrap();
    assert!(
        roster_on(&mut *conn).await.unwrap().is_some(),
        "roster commits despite the refused seed"
    );
    drop(conn);
    assert_eq!(
        bundle_defined_count(&db).await,
        0,
        "refused seed commits no bundle event"
    );
    replay_all_projections(&db).await.unwrap();

    // A clean admission afterwards seeds all three.
    let seeded = admit(&db, "owner", &["owner"]).await.unwrap();
    assert_eq!(seeded.credential(), "owner");
    assert_eq!(bundle_defined_count(&db).await, 3);
    replay_all_projections(&db).await.unwrap();
    db.close().await;
}

#[tokio::test]
#[allow(clippy::explicit_auto_deref)]
async fn admission_fails_when_the_bundle_seed_rollback_fails() {
    let dir = tempfile::tempdir().unwrap();
    let (db, _admin) = create_v2_database(
        &format!(
            "sqlite://{}",
            dir.path().join("admit-broken-rollback.db").display()
        ),
        "account",
        "Owner",
        "owner",
    )
    .await
    .unwrap();
    delete_bundle_events(&db).await;
    assert_eq!(bundle_defined_count(&db).await, 0);

    // Refuse `member` so seeding fails, and break the rollback so the
    // failure cannot be contained: admission must fail rather than run the
    // roster outside the write lock. The admission transaction is dropped,
    // so neither the roster nor any bundle event commits.
    let refused = bundles::with_refused_bundle_id("member", async {
        with_broken_bundle_seed_rollback(async { admit(&db, "owner", &["owner"]).await }).await
    })
    .await;
    assert!(
        refused
            .unwrap_err()
            .to_string()
            .contains("bundle seed rollback failed"),
        "uncontained seed failure must fail admission"
    );
    let mut conn = db.pool().acquire().await.unwrap();
    assert!(roster_on(&mut *conn).await.unwrap().is_none());
    drop(conn);
    assert_eq!(bundle_defined_count(&db).await, 0);
    replay_all_projections(&db).await.unwrap();
    db.close().await;
}

#[tokio::test]
async fn frozen_admission_writes_nothing_and_does_not_seed() {
    let dir = tempfile::tempdir().unwrap();
    let (db, _admin) = create_v2_database(
        &format!("sqlite://{}", dir.path().join("frozen-seed.db").display()),
        "account",
        "Owner",
        "owner",
    )
    .await
    .unwrap();
    // Activate the roster through the catalog-shaped membership (so the frozen
    // read can pin the account), then remove bundles while keeping the
    // roster: the frozen path must not bring them back.
    let catalog_owner = || async {
        // SAFETY: synthetic admitted fixture; no request input participates.
        Ok(unsafe {
            VerifiedHostedMembership::from_catalog_unchecked(
                "owner".into(),
                BTreeMap::from([("owner".into(), "owner@example.test".into())]),
                BTreeMap::new(),
            )
        })
    };
    reconcile_hosted_caller(&db, |first| async move {
        assert!(first);
        catalog_owner().await
    })
    .await
    .unwrap();
    delete_bundle_events(&db).await;
    assert_eq!(bundle_defined_count(&db).await, 0);

    let before = total_content_events(&db).await;
    let caller = reconcile_hosted_caller_read_only(&db, |_| catalog_owner())
        .await
        .unwrap();
    assert_eq!(caller.credential(), "owner");
    assert_eq!(total_content_events(&db).await, before);
    assert_eq!(bundle_defined_count(&db).await, 0);
    db.close().await;
}

#[tokio::test]
async fn admission_outcome_is_unchanged_for_member_and_nonmember() {
    let dir = tempfile::tempdir().unwrap();
    let (db, _admin) = create_v2_database(
        &format!("sqlite://{}", dir.path().join("admit-outcome.db").display()),
        "account",
        "Owner",
        "owner",
    )
    .await
    .unwrap();
    // Owner/member admit; a nonmember (the kernel shape of a guest refusal)
    // is refused before and after seeding runs.
    let owner = admit(&db, "owner", &["owner"]).await.unwrap();
    assert_eq!(owner.credential(), "owner");
    let member = admit(&db, "member", &["owner", "member"]).await.unwrap();
    assert_eq!(member.credential(), "member");
    let refused = admit(&db, "intruder", &["owner", "member"]).await;
    assert!(
        refused.is_err(),
        "nonmember admission stays refused with seeding on"
    );
    assert_eq!(bundle_defined_count(&db).await, 3);
    db.close().await;
}

// Catalog-shaped facts, including verified emails, exercise immutable mapping
// rather than the synthetic already-resolved binding API.
fn established_catalog(actor: &str, members: &[&str], email: &str) -> VerifiedHostedMembership {
    unsafe {
        VerifiedHostedMembership::from_catalog_unchecked(
            actor.into(),
            members
                .iter()
                .map(|id| (id.to_string(), email.to_string()))
                .collect(),
            BTreeMap::new(),
        )
    }
}

#[tokio::test]
async fn established_read_admits_with_an_active_writer_and_changed_email() {
    let dir = tempfile::tempdir().unwrap();
    let (db, _) = create_v2_database(
        &format!("sqlite://{}", dir.path().join("established.db").display()),
        "account",
        "Owner",
        "owner",
    )
    .await
    .unwrap();
    reconcile_hosted_caller(&db, |_| async {
        Ok(established_catalog(
            "owner",
            &["owner", "member"],
            "old@example.test",
        ))
    })
    .await
    .unwrap();
    let before = total_content_events(&db).await;
    let writer = begin_write(db.write_pool()).await.unwrap();
    let read = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        try_reconcile_hosted_caller_read_only(&db, |first| async move {
            assert!(!first);
            Ok(established_catalog(
                "owner",
                &["owner", "member"],
                "changed@example.test",
            ))
        }),
    )
    .await
    .expect("established admission must finish while the writer remains held")
    .unwrap()
    .unwrap();
    assert_eq!(read.credential(), "owner");
    assert_eq!(total_content_events(&db).await, before);
    writer.rollback().await.unwrap();
    // Other-member removal is not the frozen actor-only shortcut.
    assert!(try_reconcile_hosted_caller_read_only(&db, |_| async {
        Ok(established_catalog(
            "owner",
            &["owner"],
            "changed@example.test",
        ))
    })
    .await
    .unwrap()
    .is_none());
    assert!(
        try_reconcile_hosted_caller_read_only(&db, |_| async {
            Ok(established_catalog(
                "member",
                &["owner"],
                "changed@example.test",
            ))
        })
        .await
        .unwrap()
        .is_none(),
        "removed actors must persist exclusions in the writer path"
    );
    assert!(
        try_reconcile_hosted_caller_read_only(&db, |_| async {
            Ok(
                established_catalog("owner", &["owner", "member"], "changed@example.test")
                    .requiring_catalog_accounts(BTreeMap::from([("owner".into(), "wrong".into())])),
            )
        })
        .await
        .unwrap()
        .is_none(),
        "staging account expectations still constrain admission"
    );
    db.close().await;
}

#[tokio::test]
async fn established_read_requires_activation_and_all_bundle_seeds() {
    let dir = tempfile::tempdir().unwrap();
    let (db, _) = create_v2_database(
        &format!(
            "sqlite://{}",
            dir.path().join("established-seeds.db").display()
        ),
        "account",
        "Owner",
        "owner",
    )
    .await
    .unwrap();
    assert!(
        try_reconcile_hosted_caller_read_only(&db, |first| async move {
            assert!(
                !first,
                "the preflight must never request the activation directory"
            );
            Ok(established_catalog(
                "owner",
                &["owner"],
                "owner@example.test",
            ))
        })
        .await
        .unwrap()
        .is_none()
    );
    reconcile_hosted_caller(&db, |_| async {
        Ok(established_catalog(
            "owner",
            &["owner"],
            "owner@example.test",
        ))
    })
    .await
    .unwrap();
    delete_bundle_events(&db).await;
    assert!(try_reconcile_hosted_caller_read_only(&db, |_| async {
        Ok(established_catalog(
            "owner",
            &["owner"],
            "owner@example.test",
        ))
    })
    .await
    .unwrap()
    .is_none());
    // Keep the original savepoint failure/retry semantics for an established
    // workspace too: failed seeding can admit, but cannot enable the fast path.
    bundles::with_refused_bundle_id("member", async {
        reconcile_hosted_caller(&db, |_| async {
            Ok(established_catalog(
                "owner",
                &["owner"],
                "owner@example.test",
            ))
        })
        .await
        .unwrap();
    })
    .await;
    assert_eq!(bundle_defined_count(&db).await, 0);
    assert!(try_reconcile_hosted_caller_read_only(&db, |_| async {
        Ok(established_catalog(
            "owner",
            &["owner"],
            "owner@example.test",
        ))
    })
    .await
    .unwrap()
    .is_none());
    reconcile_hosted_caller(&db, |_| async {
        Ok(established_catalog(
            "owner",
            &["owner"],
            "owner@example.test",
        ))
    })
    .await
    .unwrap();
    assert!(try_reconcile_hosted_caller_read_only(&db, |_| async {
        Ok(established_catalog(
            "owner",
            &["owner"],
            "owner@example.test",
        ))
    })
    .await
    .unwrap()
    .is_some());
    db.close().await;
}

#[tokio::test]
async fn established_read_refuses_invalid_bindings_and_missing_import_provenance() {
    let dir = tempfile::tempdir().unwrap();
    let (db, owner) = create_v2_database(
        &format!(
            "sqlite://{}",
            dir.path().join("established-provenance.db").display()
        ),
        "account",
        "Owner",
        "owner",
    )
    .await
    .unwrap();
    reconcile_hosted_caller(&db, |_| async {
        Ok(established_catalog(
            "owner",
            &["owner"],
            "owner@example.test",
        ))
    })
    .await
    .unwrap();
    sqlx::query("UPDATE kernel_principals SET kind='agent' WHERE principal_id=?")
        .bind(&owner)
        .execute(db.write_pool())
        .await
        .unwrap();
    assert!(try_reconcile_hosted_caller_read_only(&db, |_| async {
        Ok(established_catalog(
            "owner",
            &["owner"],
            "owner@example.test",
        ))
    })
    .await
    .unwrap()
    .is_none());
    assert!(reconcile_hosted_caller(&db, |_| async {
        Ok(established_catalog(
            "owner",
            &["owner"],
            "owner@example.test",
        ))
    })
    .await
    .unwrap_err()
    .to_string()
    .contains("not an account principal"));
    sqlx::query("UPDATE kernel_principals SET kind='account' WHERE principal_id=?")
        .bind(&owner)
        .execute(db.write_pool())
        .await
        .unwrap();
    // Fixture-only corruption bypasses projection validation to model legacy
    // imports with missing provenance, which both paths must refuse.
    sqlx::query("DROP TRIGGER IF EXISTS content_events_no_update")
        .execute(db.write_pool())
        .await
        .unwrap();
    sqlx::query("UPDATE content_events SET type='kernel.import_home.v1' WHERE seq=(SELECT min(seq) FROM content_events WHERE type=?)")
        .bind(BUNDLE_DEFINED_EVENT).execute(db.write_pool()).await.unwrap();
    assert!(try_reconcile_hosted_caller_read_only(&db, |_| async {
        Ok(established_catalog(
            "owner",
            &["owner"],
            "owner@example.test",
        ))
    })
    .await
    .unwrap_err()
    .to_string()
    .contains("member-policy provenance"));
    sqlx::query("UPDATE content_events SET type=? WHERE type='kernel.import_home.v1'")
        .bind(BUNDLE_DEFINED_EVENT)
        .execute(db.write_pool())
        .await
        .unwrap();
    sqlx::query("UPDATE content_events SET type='kernel.import_members_roster.v1' WHERE type=?")
        .bind(BUNDLE_DEFINED_EVENT)
        .execute(db.write_pool())
        .await
        .unwrap();
    assert!(try_reconcile_hosted_caller_read_only(&db, |_| async {
        Ok(established_catalog(
            "owner",
            &["owner"],
            "owner@example.test",
        ))
    })
    .await
    .unwrap_err()
    .to_string()
    .contains("imported identity provenance"));
    sqlx::query("UPDATE content_events SET type=? WHERE type='kernel.import_members_roster.v1'")
        .bind(IDENTITY_EVENT)
        .execute(db.write_pool())
        .await
        .unwrap();
    assert!(
        try_reconcile_hosted_caller_read_only(&db, |_| async {
            Ok(established_catalog(
                "owner",
                &["owner"],
                "owner@example.test",
            ))
        })
        .await
        .is_err(),
        "malformed imported identity provenance must be refused"
    );
    db.close().await;
}

#[tokio::test]
async fn established_read_defers_repairable_roster_bindings_to_the_writer() {
    let dir = tempfile::tempdir().unwrap();
    let (db, _) = create_v2_database(
        &format!(
            "sqlite://{}",
            dir.path().join("established-repair.db").display()
        ),
        "account",
        "Owner",
        "owner",
    )
    .await
    .unwrap();
    reconcile_hosted_caller(&db, |_| async {
        Ok(established_catalog(
            "owner",
            &["owner", "member"],
            "owner@example.test",
        ))
    })
    .await
    .unwrap();
    // Fixture-only projection damage: the writer has always resolved the
    // binding afresh and repaired the v1 roster with its current principal ID.
    sqlx::query("UPDATE kernel_principals SET principal_id='replacement-member' WHERE auth_binding='member'")
        .execute(db.write_pool()).await.unwrap();
    for missing in [false, true] {
        if missing {
            sqlx::query("DELETE FROM kernel_principals WHERE auth_binding='member'")
                .execute(db.write_pool())
                .await
                .unwrap();
        }
        assert!(
            try_reconcile_hosted_caller_read_only(&db, |_| async {
                Ok(established_catalog(
                    "owner",
                    &["owner", "member"],
                    "owner@example.test",
                ))
            })
            .await
            .unwrap()
            .is_none(),
            "damaged roster requires writer repair"
        );
        reconcile_hosted_caller(&db, |_| async {
            Ok(established_catalog(
                "owner",
                &["owner", "member"],
                "owner@example.test",
            ))
        })
        .await
        .unwrap();
        let principal: String = sqlx::query_scalar(
            "SELECT principal_id FROM kernel_principals WHERE auth_binding='member'",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        let mut conn = db.pool().acquire().await.unwrap();
        let roster = roster_on(&mut conn).await.unwrap().unwrap();
        assert_eq!(roster.members.get("member"), Some(&principal));
        drop(conn);
        assert!(
            try_reconcile_hosted_caller_read_only(&db, |_| async {
                Ok(established_catalog(
                    "owner",
                    &["owner", "member"],
                    "owner@example.test",
                ))
            })
            .await
            .unwrap()
            .is_some(),
            "repaired roster must regain read admission"
        );
    }
    db.close().await;
}

#[tokio::test]
async fn established_read_compares_catalog_with_the_latest_workspace_roster() {
    let dir = tempfile::tempdir().unwrap();
    let (db, _) = create_v2_database(
        &format!(
            "sqlite://{}",
            dir.path().join("established-aba.db").display()
        ),
        "account",
        "Owner",
        "owner",
    )
    .await
    .unwrap();
    reconcile_hosted_caller(&db, |_| async {
        Ok(established_catalog(
            "owner",
            &["owner", "member"],
            "owner@example.test",
        ))
    })
    .await
    .unwrap();
    let caller = try_reconcile_hosted_caller_read_only(&db, |_| async {
        // Deterministic ABA schedule: while the host loads catalogue facts,
        // another request persists a removal. The catalogue subsequently
        // restores the member, but that join still needs writer reconciliation.
        reconcile_hosted_caller(&db, |_| async {
            Ok(established_catalog(
                "owner",
                &["owner"],
                "owner@example.test",
            ))
        })
        .await
        .unwrap();
        Ok(established_catalog(
            "member",
            &["owner", "member"],
            "member@example.test",
        ))
    })
    .await
    .unwrap();
    assert!(
        caller.is_none(),
        "an old full roster must not conceal a persisted exclusion"
    );
    reconcile_hosted_caller(&db, |_| async {
        Ok(established_catalog(
            "member",
            &["owner", "member"],
            "member@example.test",
        ))
    })
    .await
    .unwrap();
    assert!(try_reconcile_hosted_caller_read_only(&db, |_| async {
        Ok(established_catalog(
            "member",
            &["owner", "member"],
            "member@example.test",
        ))
    })
    .await
    .unwrap()
    .is_some());
    db.close().await;
}
