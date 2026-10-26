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
    Ok(Some(
        account_identity_on(&mut tx, &actor, account_id).await?,
    ))
}

/// Display names of the People among `person_ids` that the caller's account
/// can read on a hosted kernel v2 database (`manage_memberships list` with
/// `include_person`). Unreadable or missing People are absent from the map.
pub async fn visible_person_names_as(
    db: &Db,
    caller: &Caller,
    person_ids: &[String],
) -> Result<std::collections::BTreeMap<String, String>> {
    let mut names = std::collections::BTreeMap::new();
    if person_ids.is_empty() {
        return Ok(names);
    }
    let mut tx = db.pool().begin().await?;
    let actor: Option<String> = sqlx::query_scalar(
        "SELECT principal_id FROM main.kernel_principals WHERE auth_binding=? AND kind='account'",
    )
    .bind(caller.credential())
    .fetch_optional(&mut *tx)
    .await?;
    let actor = actor.ok_or_else(|| Error::engine("database membership not found"))?;
    for id in person_ids {
        if let Some(record) = kernel::read_record_on(&mut tx, &actor, id).await? {
            if let Some(name) = record
                .fields
                .get("title")
                .and_then(serde_json::Value::as_str)
            {
                names.insert(id.clone(), name.to_owned());
            }
        }
    }
    Ok(names)
}

/// Internal enrichment after the calling tool has authorized its own target.
/// This translates a stored policy subject, not a supplied Person or a new
/// catalogue directory authority. Keep all Person disclosure in this module.
pub(crate) async fn principal_identity_on(
    conn: &mut sqlx::SqliteConnection,
    actor: &str,
    principal: &str,
) -> Result<Option<PortableIdentity>> {
    let account = principal_account_on(conn, principal).await?;
    let Some(account) = account else {
        return Ok(None);
    };
    Ok(Some(account_identity_on(conn, actor, account).await?))
}

/// The account half of the shared lookup, for surfaces that do not require a
/// Person. Optional Person visibility must not prevent reading private config.
pub(crate) async fn principal_account_on(
    conn: &mut sqlx::SqliteConnection,
    principal: &str,
) -> Result<Option<String>> {
    let account: Option<String> = sqlx::query_scalar(
        "SELECT auth_binding FROM main.kernel_principals WHERE principal_id=? AND kind='account'",
    )
    .bind(principal)
    .fetch_optional(&mut *conn)
    .await?;
    Ok(account)
}

/// The caller's own control-metadata namespace does not disclose the Person
/// record. v1 resolves personal Home settings even when that record is hidden.
/// Record enrichment (including hosted directory and SQL) must still use the
/// visibility-filtered identity helpers above.
pub(crate) async fn own_person_on(
    conn: &mut sqlx::SqliteConnection,
    actor: &str,
) -> Result<Option<String>> {
    let Some(account) = principal_account_on(conn, actor).await? else {
        return Ok(None);
    };
    person_for_account_on(conn, &account).await
}
async fn person_for_account_on(
    conn: &mut sqlx::SqliteConnection,
    account: &str,
) -> Result<Option<String>> {
    Ok(sqlx::query_scalar("SELECT m.person_id FROM main.kernel_message_people m JOIN main.kernel_principals p ON p.principal_id=m.principal_id JOIN main.kernel_records r ON r.id=m.person_id WHERE p.auth_binding=? AND p.kind='account' AND NOT EXISTS(SELECT 1 FROM main.kernel_import_tombstones t WHERE t.record_id=r.id)")
        .bind(account).fetch_optional(conn).await?)
}

async fn account_identity_on(
    conn: &mut sqlx::SqliteConnection,
    actor: &str,
    account_id: String,
) -> Result<PortableIdentity> {
    let person = person_for_account_on(conn, &account_id).await?;
    let person_id = match person {
        Some(id) if kernel::read_record_on(conn, actor, &id).await?.is_some() => Some(id),
        _ => None,
    };
    Ok(PortableIdentity {
        account_id,
        person_id,
    })
}

/// Check a known intervention target without disclosing a hidden Person. The
/// calling handler already admitted this account against the current roster.
pub(crate) async fn owns_intervention_target_on(
    conn: &mut sqlx::SqliteConnection,
    actor: &str,
    person: &str,
    native_principal: &str,
) -> Result<bool> {
    let owned:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.kernel_message_people p JOIN main.kernel_principals a ON a.principal_id=p.principal_id AND a.kind='account' JOIN main.kernel_records r ON r.id=p.person_id WHERE p.principal_id=? AND p.person_id=? AND NOT EXISTS(SELECT 1 FROM main.kernel_import_tombstones t WHERE t.record_id=r.id))").bind(actor).bind(person).fetch_one(&mut *conn).await?;
    if !owned {
        return Ok(false);
    }
    // Public additions after cutover are current canonical authority. Do not
    // fabricate imported public bindings in that projection.
    let current:Option<String>=sqlx::query_scalar("SELECT identifier FROM main.kernel_identity_bindings WHERE record_id=? AND system='native-principal' AND is_canonical=1").bind(person).fetch_optional(&mut *conn).await?;
    if let Some(current) = current {
        return Ok(current == native_principal);
    }
    kernel::v1_state::require_identity_directory_capture_on(&mut *conn).await?;
    let raw:Option<String>=sqlx::query_scalar("SELECT payload FROM main.kernel_v1_state WHERE section='account_directory' AND account_principal=? AND record_id=?").bind(actor).bind(person).fetch_optional(conn).await?;
    let value:Value=raw.map(|r|serde_json::from_str(&r)).transpose()?.ok_or_else(||Error::engine("manage_interventions: canonical source identity needs preparation; resume the original import before H3 activation"))?;
    if value.get("native_principal_id").is_none() {
        return Err(Error::engine("manage_interventions: canonical source identity needs preparation; resume the original import before H3 activation"));
    }
    Ok(value["native_principal_id"].as_str() == Some(native_principal))
}

/// Shell identity SQL is caller-scoped, just like v1's account/email view.
/// Only actual portable bindings and verified H3 aliases are representable.
/// Raw email bindings are not live kernel identity data; never infer them from
/// labels or echo an arbitrary query parameter as a binding.
pub(super) async fn sql_bindings_on(
    conn: &mut sqlx::SqliteConnection,
    actor: &str,
) -> Result<Vec<(String, String)>> {
    let Some(identity) = principal_identity_on(conn, actor, actor).await? else {
        return Ok(vec![]);
    };
    let Some(person) = identity.person_id else {
        return Ok(vec![]);
    };
    let mut identifiers =
        kernel::hosted_identity::catalog_identifiers_on(conn, actor, &identity.account_id).await?;
    identifiers.push(identity.account_id);
    identifiers.sort();
    identifiers.dedup();
    Ok(identifiers
        .into_iter()
        .map(|id| (person.clone(), id))
        .collect())
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
        fixture_with_member_person(false).await
    }
    async fn fixture_with_member_person(
        include_member: bool,
    ) -> (tempfile::TempDir, Db, String, String) {
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
                    pin: pin.clone(),
                    primary_type: "Entity".into(),
                    kind: "person".into(),
                    fields: serde_json::Map::new(),
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        if include_member {
            kernel::import_record_as(
                &db,
                &host,
                "fixture-member-person",
                &home,
                Some(&owner),
                &kernel::ImportRecordState {
                    message_principal: Some(member),
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
        }
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

    #[test]
    fn kernel_v2_binding_schema_keeps_v1_validators_unchanged() {
        use crate::query::{sql::*, sql_contract};
        use std::collections::BTreeSet;
        let wide = sql_contract::LOGICAL_RELATIONS
            .iter()
            .find(|r| r.name == "bindings")
            .unwrap()
            .columns
            .iter()
            .map(|c| (*c).to_owned())
            .collect::<Vec<_>>();
        assert!(wide.contains(&"is_canonical".to_owned()));
        for _ in 0..2 {
            assert_eq!(
                validated_output_columns_ad_hoc("SELECT * FROM bindings").unwrap(),
                wide
            );
            for statement in [
                "SELECT * FROM bindings",
                "SELECT b.* FROM bindings b",
                "WITH own AS (SELECT * FROM bindings) SELECT * FROM own",
            ] {
                validate_kernel_v2_ad_hoc(statement).unwrap();
                assert_eq!(
                    validated_kernel_v2_output_columns(statement).unwrap(),
                    vec!["record_id", "system", "identifier", "is_canonical"]
                );
                assert_eq!(
                    public_reads_ad_hoc(statement).unwrap(),
                    BTreeSet::from([
                        ("bindings".into(), "record_id".into()),
                        ("bindings".into(), "system".into()),
                        ("bindings".into(), "identifier".into()),
                        ("bindings".into(), "is_canonical".into())
                    ])
                );
            }
            assert!(validate_kernel_v2_ad_hoc("SELECT * FROM main.bindings").is_err());
            assert_eq!(
                validated_kernel_v2_output_columns("SELECT is_canonical FROM bindings").unwrap(),
                vec!["is_canonical"]
            );
            validate_ad_hoc("SELECT is_canonical FROM bindings").unwrap();
        }
    }

    async fn sql(db: &Db, account: &str, statement: &str, parameters: Value) -> Result<Value> {
        crate::mcp::kernel_v2::tests::registry()
            .call_engine(
                EngineHandle::KernelV2(db.clone()),
                Caller::authenticated(account),
                "query_sql",
                json!({"sql":statement,"parameters":parameters}),
            )
            .await
    }
    async fn lookup(db: &Db, caller: &str, system: &str, identifier: &str) -> Value {
        sql(db,caller,"SELECT record_id FROM bindings WHERE system = ?1 AND identifier = ?2 ORDER BY record_id LIMIT 1",
            json!([{"type":"text","value":system},{"type":"text","value":identifier}])).await.unwrap()
    }
    #[tokio::test]
    async fn identity_sql_uses_stored_portable_and_catalog_aliases_without_email_inference() {
        let (_dir, db, owner, _home) = fixture().await;
        let before = kernel::dump_all_kernel_tables(&db).await.unwrap();
        for identifier in ["portable-owner", "catalog-owner"] {
            assert_eq!(
                lookup(&db, "portable-owner", "account", identifier).await["rows"],
                json!([{"record_id":"fixture-person"}])
            );
        }
        for (system, id) in [
            ("account", "catalog-member"),
            ("account", "portable-member"),
            ("account", "missing"),
            ("account", "v1:portable-owner"),
            ("email", "owner@example.test"),
            ("email", "member@example.test"),
        ] {
            assert_eq!(
                lookup(&db, "portable-owner", system, id).await["rows"],
                json!([])
            );
        }
        // Person availability is not fabricated for an admitted account that
        // has never had a canonical Person binding.
        assert_eq!(
            lookup(&db, "portable-member", "account", "catalog-member").await["rows"],
            json!([])
        );
        let all = sql(
            &db,
            "portable-owner",
            "SELECT * FROM bindings ORDER BY is_canonical, identifier",
            json!([]),
        )
        .await
        .unwrap();
        assert_eq!(
            all["columns"],
            json!(["record_id", "system", "identifier", "is_canonical"])
        );
        // Portable, hosted catalog and native-principal aliases all resolve
        // to this caller's verified Person, with no other member exposed.
        // Imported event actors normalize to native principals in the SQL
        // event projection; no synthetic v1:<account> binding is needed.
        assert_eq!(
            all["rows"],
            json!([
                {"record_id":"fixture-person","system":"account","identifier":"catalog-owner","is_canonical":0},
                {"record_id":"fixture-person","system":"account","identifier":"portable-owner","is_canonical":0},
                {"record_id":"fixture-person","system":"account","identifier":owner,"is_canonical":1}
            ])
        );
        let joined=sql(&db,"portable-owner","SELECT r.id FROM bindings b JOIN records r ON r.id=b.record_id WHERE b.identifier=?1 ORDER BY r.id",json!([{"type":"text","value":"catalog-owner"}])).await.unwrap();
        assert_eq!(joined["rows"], json!([{"id":"fixture-person"}]));
        assert_eq!(before, kernel::dump_all_kernel_tables(&db).await.unwrap());
        kernel::replay_all_projections(&db).await.unwrap();
        assert_eq!(before, kernel::dump_all_kernel_tables(&db).await.unwrap());
        assert_eq!(
            lookup(&db, "portable-owner", "account", "catalog-owner").await["rows"],
            json!([{"record_id":"fixture-person"}])
        );
        db.close().await;
    }
    #[tokio::test]
    async fn frozen_viewer_sql_selects_one_canonical_native_identity() {
        let (_dir, db, owner, _home) = fixture().await;
        let statement="SELECT b.record_id,b.identifier,b.is_canonical FROM bindings b JOIN records r ON r.id=b.record_id WHERE b.system='account' AND b.identifier=current_principal() AND b.is_canonical=1";
        let before = kernel::dump_all_kernel_tables(&db).await.unwrap();
        assert_eq!(
            sql(&db, "portable-owner", statement, json!([]))
                .await
                .unwrap()["rows"],
            json!([{"record_id":"fixture-person","identifier":owner,"is_canonical":1}])
        );
        assert_eq!(
            sql(
                &db,
                "portable-owner",
                "SELECT count(*) AS n FROM bindings WHERE is_canonical=1",
                json!([])
            )
            .await
            .unwrap()["rows"],
            json!([{"n":1}])
        );
        assert_eq!(
            sql(&db, "portable-member", statement, json!([]))
                .await
                .unwrap()["rows"],
            json!([]),
            "a Person is not invented for an unrepresented identity"
        );
        assert_eq!(before, kernel::dump_all_kernel_tables(&db).await.unwrap());
        kernel::replay_all_projections(&db).await.unwrap();
        assert_eq!(
            sql(&db, "portable-owner", statement, json!([]))
                .await
                .unwrap()["rows"],
            json!([{"record_id":"fixture-person","identifier":owner,"is_canonical":1}])
        );
        db.close().await;
    }
    #[tokio::test]
    async fn identity_sql_never_returns_another_members_binding_or_a_hidden_person() {
        let (_dir, db, owner, home) = fixture_with_member_person(true).await;
        assert_eq!(
            lookup(&db, "portable-member", "account", "catalog-member").await["rows"],
            json!([{"record_id":"fixture-member-person"}])
        );
        assert_eq!(
            lookup(&db, "portable-member", "account", "catalog-owner").await["rows"],
            json!([])
        );
        assert_eq!(
            lookup(&db, "portable-owner", "account", "catalog-member").await["rows"],
            json!([])
        );
        kernel::replace_home_policy(&db, &owner, &home, &[(&owner, "manage")])
            .await
            .unwrap();
        assert_eq!(
            lookup(&db, "portable-member", "account", "catalog-member").await["rows"],
            json!([])
        );
        reconcile(&db, "catalog-owner", false).await;
        assert!(sql(
            &db,
            "portable-member",
            "SELECT count(*) AS n FROM bindings",
            json!([])
        )
        .await
        .is_err());
        // Retained H3 catalogue aliases never re-admit an offboarded member.
        assert_eq!(
            lookup(&db, "portable-owner", "account", "catalog-member").await["rows"],
            json!([])
        );
        db.close().await;
    }
    #[tokio::test]
    async fn identity_sql_refuses_unrepresented_metadata_and_physical_state() {
        let (_dir, db, _owner, _home) = fixture().await;
        let before = kernel::dump_all_kernel_tables(&db).await.unwrap();
        for column in ["url", "etag", "last_seen_at", "last_seen_at_ms"] {
            let error = sql(
                &db,
                "portable-owner",
                &format!("SELECT {column} FROM bindings"),
                json!([]),
            )
            .await
            .unwrap_err();
            assert!(error.to_string().contains("no such column"), "{error}");
        }
        for query in [
            "SELECT * FROM main.kernel_message_people",
            "SELECT * FROM main.kernel_principals",
            "DELETE FROM bindings",
        ] {
            assert!(sql(&db, "portable-owner", query, json!([])).await.is_err());
        }
        let schema=sql(&db,"portable-owner","SELECT column_name FROM catalog_columns WHERE relation_name='bindings' ORDER BY column_position",json!([])).await.unwrap();
        assert_eq!(
            schema["rows"],
            json!([{"column_name":"record_id"},{"column_name":"system"},{"column_name":"identifier"},{"column_name":"is_canonical"}])
        );
        assert_eq!(before, kernel::dump_all_kernel_tables(&db).await.unwrap());
        db.close().await;
    }
    #[tokio::test]
    async fn identity_sql_reads_a_physically_read_only_prepared_file() {
        let (dir, db, _owner, _home) = fixture().await;
        db.close().await;
        let read = crate::db::open_marked_v2_database_read_only_at(&dir.path().join("identity.db"))
            .await
            .unwrap();
        assert_eq!(
            lookup(&read, "portable-owner", "account", "catalog-owner").await["rows"],
            json!([{"record_id":"fixture-person"}])
        );
        read.close().await;
    }
}
