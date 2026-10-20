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
