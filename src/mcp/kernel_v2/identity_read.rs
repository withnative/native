//! Shared read-only identity enrichment for hosted v2 member/account surfaces.
//! Catalogue membership remains the host's authority. Never infer identity from
//! labels, current email, or a supplied Person id, and never provision on read.
use super::*;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PortableIdentity {
    pub account_id: String,
    pub person_id: Option<String>,
}

/// Resolve a verified catalogue member's portable account and visible Person.
///
/// The host must authorize directory access against its current catalogue before
/// calling this helper, and pass only current owner/member catalogue targets.
/// The kernel also filters retained former-member mappings against its roster.
/// The caller must carry the H3-verified route identity;
/// a bare account credential or stale/forged catalogue mapping is insufficient.
/// Missing portable identity is `None`; a hidden/missing Person is `person_id:
/// None`. Neither case writes, repairs, or invents a Person record.
pub async fn hosted_identity_as(
    db: &Db,
    caller: &Caller,
    catalog_user_id: &str,
) -> Result<Option<PortableIdentity>> {
    let catalog_actor = caller
        .hosting_principal()
        .filter(|_| caller.is_host_member() && caller.hosting_database().is_some())
        .ok_or_else(|| Error::engine("database membership not found"))?;
    let mut tx = db.pool().begin().await?;
    let actor: Option<String> = sqlx::query_scalar(
        "SELECT principal_id FROM main.kernel_principals WHERE auth_binding=? AND kind='account'",
    )
    .bind(caller.credential())
    .fetch_optional(&mut *tx)
    .await?;
    let actor = actor.ok_or_else(|| Error::engine("database membership not found"))?;
    if !kernel::hosted_identity::catalog_account_matches_on(
        &mut tx,
        catalog_actor,
        caller.credential(),
        &actor,
    )
    .await?
    {
        return Err(Error::engine("database membership not found"));
    }
    kernel::app_installs::admit_dispatched_on(&mut tx, &actor).await?;
    let Some(account_id) =
        kernel::hosted_identity::catalog_account_on(&mut tx, catalog_user_id).await?
    else {
        return Ok(None);
    };
    let person: Option<String> = sqlx::query_scalar(
        "SELECT m.person_id FROM main.kernel_message_people m JOIN main.kernel_principals p ON p.principal_id=m.principal_id WHERE p.auth_binding=? AND p.kind='account'",
    ).bind(&account_id).fetch_optional(&mut *tx).await?;
    let person_id = match person {
        Some(id)
            if kernel::read_record_on(&mut tx, &actor, &id)
                .await?
                .is_some() =>
        {
            Some(id)
        }
        _ => None,
    };
    Ok(Some(PortableIdentity {
        account_id,
        person_id,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::KERNEL_ROOT_ID;
    use std::collections::BTreeMap;

    async fn reconcile(db: &Db, actor: &str, include_member: bool) -> Caller {
        let caller = kernel::hosted_identity::reconcile_hosted_caller(db, |_| async move {
            let mut users = BTreeMap::from([("catalog-owner".into(), "owner@example.test".into())]);
            if include_member {
                users.insert("catalog-member".into(), "member@example.test".into());
            }
            // SAFETY: complete synthetic catalogue snapshot; no tool input.
            Ok(unsafe {
                kernel::hosted_identity::VerifiedHostedMembership::from_catalog_unchecked(
                    actor.into(),
                    users,
                    BTreeMap::new(),
                )
            })
        })
        .await
        .unwrap();
        // SAFETY: the fixture above admitted this exact catalogue identity.
        unsafe {
            caller.with_verified_hosted_v2_identity(actor, "fixture-db", actor == "catalog-owner")
        }
    }

    async fn fixture() -> (tempfile::TempDir, Db, String, String) {
        let dir = tempfile::tempdir().unwrap();
        let (db, owner) = kernel::create_v2_database(
            dir.path().join("identity.db").to_str().unwrap(),
            "account",
            "Owner",
            "portable-owner",
        )
        .await
        .unwrap();
        let member = kernel::create_principal(&db, "account", "Member", "portable-member", &owner)
            .await
            .unwrap();
        let host = kernel::resolve_principal_by_binding(&db, kernel::HOST_IMPORT_BINDING)
            .await
            .unwrap()
            .unwrap()
            .0;
        kernel::hosted_identity::import_accounts(
            &db,
            &host,
            vec![
                ("owner@example.test".into(), "portable-owner".into()),
                ("member@example.test".into(), "portable-member".into()),
            ],
        )
        .await
        .unwrap();
        let definition = json!({"family":"fixture.person","version":1,"interpreter":"native.defn/4","primary_type":"Entity","kinds":[{"token":"person","description":"Synthetic Person","maturity":"current","identity":{"mode":"record"},"fields":[],"links":[]}]});
        let pin = kernel::install_definition_as(
            &db,
            &owner,
            "fixture.person",
            1,
            &serde_json::to_vec(&definition).unwrap(),
        )
        .await
        .unwrap();
        kernel::adopt_definition_as(&db, &owner, &pin.family, Some(&pin))
            .await
            .unwrap();
        let home = kernel::create_home(
            &db,
            KERNEL_ROOT_ID,
            Some(&[(&owner, "manage"), (&member, "view")]),
            &owner,
        )
        .await
        .unwrap();
        kernel::import_record_as(
            &db,
            &host,
            "fixture-person",
            &home,
            Some(&owner),
            &kernel::ImportRecordState {
                message_principal: Some(owner.clone()),
                definition: Some(kernel::ImportDefinition {
                    pin,
                    primary_type: "Entity".into(),
                    kind: "person".into(),
                    fields: serde_json::Map::new(),
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        reconcile(&db, "catalog-owner", true).await;
        (dir, db, owner, home)
    }

    #[tokio::test]
    async fn identity_read_preserves_portable_mapping_visibility_and_replay() {
        let (_dir, db, owner, home) = fixture().await;
        let caller = reconcile(&db, "catalog-member", true).await;
        let expected = Some(PortableIdentity {
            account_id: "portable-owner".into(),
            person_id: Some("fixture-person".into()),
        });
        let before = kernel::dump_all_kernel_tables(&db).await.unwrap();
        assert_eq!(
            hosted_identity_as(&db, &caller, "catalog-owner")
                .await
                .unwrap(),
            expected
        );
        assert_eq!(
            hosted_identity_as(&db, &caller, "catalog-member")
                .await
                .unwrap(),
            Some(PortableIdentity {
                account_id: "portable-member".into(),
                person_id: None
            })
        );
        assert_eq!(
            hosted_identity_as(&db, &caller, "missing").await.unwrap(),
            None
        );
        assert_eq!(before, kernel::dump_all_kernel_tables(&db).await.unwrap());
        kernel::replay_all_projections(&db).await.unwrap();
        assert_eq!(
            hosted_identity_as(&db, &caller, "catalog-owner")
                .await
                .unwrap(),
            expected
        );
        kernel::replace_home_policy(&db, &owner, &home, &[(&owner, "manage")])
            .await
            .unwrap();
        let hidden = hosted_identity_as(&db, &caller, "catalog-owner")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(hidden.account_id, "portable-owner");
        assert_eq!(hidden.person_id, None);
        db.close().await;
    }

    #[tokio::test]
    async fn identity_read_refuses_unverified_guest_and_removed_callers() {
        let (_dir, db, _owner, _home) = fixture().await;
        let member = reconcile(&db, "catalog-member", true).await;
        for caller in [
            Caller::authenticated("portable-member"),
            member.clone().with_hosting_member(false),
            Caller::authenticated("portable-member")
                .with_hosting_context("catalog-owner", "fixture-db"),
            Caller::authenticated("missing").with_hosting_context("catalog-member", "fixture-db"),
        ] {
            assert!(hosted_identity_as(&db, &caller, "catalog-owner")
                .await
                .is_err());
        }
        let owner = reconcile(&db, "catalog-owner", false).await;
        assert_eq!(
            hosted_identity_as(&db, &owner, "catalog-member")
                .await
                .unwrap(),
            None
        );
        kernel::replay_all_projections(&db).await.unwrap();
        assert_eq!(
            hosted_identity_as(&db, &owner, "catalog-member")
                .await
                .unwrap(),
            None
        );
        assert!(hosted_identity_as(&db, &member, "catalog-owner")
            .await
            .is_err());
        db.close().await;
    }
}
