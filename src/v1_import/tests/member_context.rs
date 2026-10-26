//! Synthetic source association continuity, not an installed-node qualification.
use super::*;
use k::v1_state::member_context as context;

async fn fixture() -> Fixture {
    let f = Fixture::new().await;
    let mut s = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    for (id, typ, kind, home, owner, policy) in [
        (
            "person-a",
            "Entity",
            "person",
            "native:root",
            "person-a",
            "native:root",
        ),
        (
            "person-b",
            "Entity",
            "person",
            "native:root",
            "person-b",
            "native:root",
        ),
        (
            "private-b",
            "Collection",
            "folder",
            "native:root",
            "person-b",
            "private-b",
        ),
    ] {
        sqlx::query("INSERT INTO records(id,type,kind,name,body,home_id,owner_id,lifecycle,created_at,updated_at,archived,policy_anchor_id) VALUES(?,?,?,?,'',?,?,'open','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',0,?)")
            .bind(id).bind(typ).bind(kind).bind(id).bind(home).bind(owner).bind(policy).execute(&mut s).await.unwrap();
    }
    s.execute("INSERT INTO record_policies VALUES('private-b'); INSERT INTO policy_entries VALUES('private-b','account','account-b','manage'); INSERT INTO member_contexts VALUES('account-a','person-a','private','2026-01-01T00:00:00Z'),('account-b','person-b','private-b','2026-01-01T00:00:00Z')").await.unwrap();
    f
}
async fn import(f: &Fixture, resume: bool) -> Report {
    let r = run(f.options(
        &["person-a", "person-b", "private", "private-b", "note"],
        resume,
    ))
    .await
    .unwrap();
    assert!(
        r.refusals.is_empty(),
        "{:?}",
        r.refusals.iter().map(|r| &r.reason).collect::<Vec<_>>()
    );
    assert!(r.state.member_contexts_prepared);
    r
}
async fn online(db: &Db, actor: &str) -> Value {
    let mut tx = db.pool().begin().await.unwrap();
    context::online_on(&mut tx, actor).await.unwrap()
}
#[tokio::test]
async fn imported_member_context_exact_capture_retry_removal_and_replay() {
    let f = fixture().await;
    let r = import(&f, false).await;
    let db = f.db().await;
    let a = &r.principals["account-a"];
    let b = &r.principals["account-b"];
    assert_eq!(r.state.sections[context::SECTION].source, 2);
    let oa = online(&db, a).await;
    let ob = online(&db, b).await;
    assert_eq!(oa["person_record_id"], "person-a");
    assert_eq!(oa["root_record_id"], "private");
    assert_eq!(ob["person_record_id"], "person-b");
    assert_eq!(ob["root_record_id"], "private-b");
    assert!(!oa.to_string().contains("person-b"));
    assert!(!ob.to_string().contains("\"private\""));
    let mut tx = db.pool().begin().await.unwrap();
    assert_eq!(
        context::member_delivery_on(&mut tx, a)
            .await
            .unwrap()
            .unwrap(),
        json!({"person_record_id":"person-a","root_record_id":"private"})
    );
    tx.rollback().await.unwrap();
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM content_events WHERE type='kernel.v1_state_imported.v1' AND json_extract(payload,'$.section') IN ('member_contexts','member_context_capture')").fetch_one(db.pool()).await.unwrap();
    import(&f, true).await;
    let after:i64=sqlx::query_scalar("SELECT count(*) FROM content_events WHERE type='kernel.v1_state_imported.v1' AND json_extract(payload,'$.section') IN ('member_contexts','member_context_capture')").fetch_one(db.pool()).await.unwrap();
    assert_eq!(count, after);
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source
        .execute("DELETE FROM member_contexts WHERE account_id='account-b'")
        .await
        .unwrap();
    source
        .execute("UPDATE member_contexts SET root_record_id='folder' WHERE account_id='account-a'")
        .await
        .unwrap();
    let removed = import(&f, true).await;
    assert_eq!(removed.state.sections[context::SECTION].removed, 1);
    assert_eq!(online(&db, b).await["status"], "absent");
    assert_eq!(online(&db, a).await["root_record_id"], "folder");
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
}
#[tokio::test]
async fn imported_member_context_empty_receipt_missing_table_and_context_only_account() {
    let f = Fixture::new().await;
    let r = run(f.options(&["note"], false)).await.unwrap();
    assert!(r.state.member_contexts_prepared);
    assert_eq!(r.state.sections[context::SECTION].source, 0);
    let db = f.db().await;
    let mut tx = db.pool().begin().await.unwrap();
    context::require_capture_on(&mut tx).await.unwrap();
    tx.rollback().await.unwrap();
    let mut s = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    s.execute("INSERT INTO member_contexts VALUES('context-only','absent-person','absent-root','2026-01-01T00:00:00Z')").await.unwrap();
    let r = run(f.options(&["note"], true)).await.unwrap();
    assert!(r.principals.contains_key("context-only"));
    assert!(r.state.member_contexts_prepared);
    assert_eq!(
        online(&db, &r.principals["context-only"]).await["status"],
        "unavailable"
    );
    s.execute("DROP TABLE member_contexts").await.unwrap();
    assert!(run(f.options(&["note"], true)).await.is_err());
    let fresh = Fixture::new().await;
    let mut s = SqliteConnection::connect(fresh.source.to_str().unwrap())
        .await
        .unwrap();
    s.execute("DROP TABLE member_contexts").await.unwrap();
    let r = run(fresh.options(&["note"], false)).await.unwrap();
    assert!(!r.state.member_contexts_source_present);
    assert!(!r.state.member_contexts_prepared);
    let db = fresh.db().await;
    assert_eq!(
        online(&db, &r.principals["account-a"]).await["reason"],
        "source_capture_not_prepared"
    );
}
#[tokio::test]
async fn imported_member_context_invalid_tuple_is_retained_and_blocks_preparation() {
    let f = fixture().await;
    let mut s = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    s.execute(
        "UPDATE member_contexts SET person_record_id='person-a' WHERE account_id='account-b'",
    )
    .await
    .unwrap();
    let r = run(f.options(&["person-a", "person-b", "private", "private-b"], false))
        .await
        .unwrap();
    assert_eq!(r.state.member_contexts_invalid, 1);
    assert!(!r.state.member_contexts_prepared);
    assert!(!r.refusals.is_empty());
    let db = f.db().await;
    let raw:String=sqlx::query_scalar("SELECT payload FROM kernel_v1_state WHERE section='member_contexts' AND json_extract(payload,'$.account_id')='account-b'").fetch_one(db.pool()).await.unwrap();
    let raw: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(raw["person_record_id"], "person-a");
    assert_eq!(raw["invalid"], true);
    let mut tx = db.pool().begin().await.unwrap();
    assert!(context::require_capture_on(&mut tx).await.is_err());
}
#[tokio::test]
async fn imported_member_context_envelope_wrong_account_origin_and_closed_import_refuse() {
    let f = fixture().await;
    let r = import(&f, false).await;
    let db = f.db().await;
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let (raw,origin,observed_at):(String,String,String)=sqlx::query_as("SELECT payload,origin,observed_at FROM kernel_v1_state WHERE section='member_contexts' AND account_principal=?").bind(&r.principals["account-a"]).fetch_one(db.pool()).await.unwrap();
    let row = k::v1_state::ImportedState {
        section: context::SECTION.into(),
        source_id: serde_json::to_string(&["account-a"]).unwrap(),
        origin,
        value_json: Some(raw),
        account_principal: Some(r.principals["account-a"].clone()),
        record_id: Some("private".into()),
        observed_at,
        snapshot: json!({}),
    };
    for wrong in [0, 1, 2] {
        let mut bad = row.clone();
        match wrong {
            0 => bad.account_principal = Some(r.principals["account-b"].clone()),
            1 => bad.source_id = "wrong-key".into(),
            _ => bad.origin = "different-origin".into(),
        };
        let before = k::dump_all_kernel_tables(&db).await.unwrap();
        assert!(k::v1_state::import_state_batch_as(&db, &host, &[bad])
            .await
            .is_err());
        assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    }
    k::hosted_identity::reconcile_hosted_caller(&db, |_| async {
        // SAFETY: host-owned complete synthetic membership, never tool input.
        Ok(unsafe {
            k::hosted_identity::VerifiedHostedMembership::from_catalog_unchecked(
                "account-a".into(),
                BTreeMap::from([
                    ("account-a".into(), "a@example.test".into()),
                    ("account-b".into(), "b@example.test".into()),
                ]),
                BTreeMap::new(),
            )
        })
    })
    .await
    .unwrap();
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    assert!(k::v1_state::import_state_batch_as(&db, &host, &[row])
        .await
        .is_err());
    assert!(
        run(f.options(&["person-a", "person-b", "private", "private-b"], true))
            .await
            .is_err()
    );
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
}

#[tokio::test]
async fn imported_member_context_online_gates_are_independent_delivery_requires_both() {
    let f = fixture().await;
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    // Person is unreadable to b while b's existing private root remains its own.
    // Keep source placement and its derived policy anchor coherent.
    source
        .execute(
            "UPDATE records SET home_id='private',owner_id='person-a',policy_anchor_id='private' WHERE id='person-b'",
        )
        .await
        .unwrap();
    let r = import(&f, false).await;
    let db = f.db().await;
    let b = &r.principals["account-b"];
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    let value = online(&db, b).await;
    assert_eq!(value["person_record_id"], Value::Null);
    assert_eq!(value["root_record_id"], "private-b");
    assert!(!value.to_string().contains("person-b"));
    let mut tx = db.pool().begin().await.unwrap();
    assert!(context::member_delivery_on(&mut tx, b)
        .await
        .unwrap()
        .is_none());
    tx.rollback().await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    // Removing the exact source association cannot fall back to a visible home,
    // account config or canonical Person mapping.
    source
        .execute("DELETE FROM member_contexts WHERE account_id='account-b'")
        .await
        .unwrap();
    import(&f, true).await;
    assert_eq!(online(&db, b).await["status"], "absent");
}

#[tokio::test]
async fn imported_member_context_missing_and_tombstoned_references_are_not_disclosed() {
    let f = fixture().await;
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source.execute("UPDATE records SET deleted_at='2026-02-02T00:00:00Z' WHERE id='person-b'; UPDATE member_contexts SET root_record_id='missing-root' WHERE account_id='account-b'").await.unwrap();
    let r = import(&f, false).await;
    let db = f.db().await;
    let b = &r.principals["account-b"];
    let value = online(&db, b).await;
    assert_eq!(value["status"], "unavailable");
    assert!(!value.to_string().contains("person-b"));
    assert!(!value.to_string().contains("missing-root"));
    let mut tx = db.pool().begin().await.unwrap();
    assert!(context::member_delivery_on(&mut tx, b)
        .await
        .unwrap()
        .is_none());
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_member_context_ordinary_bootstrap_adds_source_footing_without_run_or_workspace_changes(
) {
    use crate::mcp::{registry::EngineHandle, Caller};
    let f = fixture().await;
    let r = import(&f, false).await;
    let db = f.db().await;
    let mut registry = crate::mcp::ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
    crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    let value = registry
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            Caller::authenticated("account-b").with_suppressed_request_persistence(),
            "bootstrap",
            json!({}),
        )
        .await
        .unwrap();
    assert_eq!(
        value["principal"]["principal_id"],
        r.principals["account-b"]
    );
    assert_eq!(
        value["workspace"]["primary_workspace"]["id"],
        KERNEL_ROOT_ID
    );
    assert_eq!(value["source_context"]["root_record_id"], "private-b");
    assert_eq!(value["run"]["durable"], false);
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
}

#[tokio::test]
async fn imported_member_context_email_matching_keeps_aliases_without_raw_presentation() {
    let f = fixture().await;
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source.execute("INSERT INTO bindings VALUES('person-a','email','Primary@Example.test',1),('person-a','email','secondary@example.test',0),('person-b','email','member@example.test',1)").await.unwrap();
    import(&f, false).await;
    let db = f.db().await;
    let raw: String = sqlx::query_scalar(
        "SELECT payload FROM content_events WHERE type=? ORDER BY seq DESC LIMIT 1",
    )
    .bind(k::hosted_identity::IDENTITY_EVENT)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert!(!raw.contains("Primary@"));
    assert!(!raw.contains("secondary@"));
    assert!(!raw.contains("is_canonical"));
    let matching: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(matching["emails"].as_object().unwrap().len(), 3);
    // Duplicate normalized alias on another canonical account must refuse;
    // canonical-vs-secondary email is not a separate authentication authority.
    source
        .execute("INSERT INTO bindings VALUES('person-b','email','primary@example.test',0)")
        .await
        .unwrap();
    assert!(
        run(f.options(&["person-a", "person-b", "private", "private-b"], true))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn imported_member_context_email_primary_and_secondary_match_same_portable_account() {
    for alias in ["primary@example.test", "secondary@example.test"] {
        let f = fixture().await;
        let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
            .await
            .unwrap();
        source.execute("INSERT INTO bindings VALUES('person-a','email','Primary@Example.test',1),('person-a','email','secondary@example.test',0),('person-b','email','member@example.test',1)").await.unwrap();
        import(&f, false).await;
        let db = f.db().await;
        let caller = k::hosted_identity::reconcile_hosted_caller(&db, |_| async {
            // SAFETY: complete synthetic host catalogue; aliases are supplied
            // by the fixture, never an unverified caller matching parameter.
            Ok(unsafe {
                k::hosted_identity::VerifiedHostedMembership::from_catalog_unchecked(
                    "catalog-owner".into(),
                    BTreeMap::from([
                        ("catalog-owner".into(), alias.into()),
                        ("catalog-member".into(), "member@example.test".into()),
                    ]),
                    BTreeMap::new(),
                )
            })
        })
        .await
        .unwrap();
        assert_eq!(caller.credential(), "account-a");
    }
}

#[tokio::test]
async fn imported_member_context_email_matching_excludes_deleted_nonperson_and_uncanonical_accounts(
) {
    let f = fixture().await;
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    for (id, deleted) in [
        ("deleted-person", Some("2026-02-01T00:00:00Z")),
        ("unverified-person", None),
    ] {
        sqlx::query("INSERT INTO records SELECT ?,type,kind,name,body,home_id,owner_id,lifecycle,summary,created_at,updated_at,archived,policy_anchor_id,?,persistence,maturity,last_activity_at FROM records WHERE id='person-a'").bind(id).bind(deleted).execute(&mut source).await.unwrap();
    }
    source.execute("INSERT INTO bindings VALUES('person-a','email','valid@example.test',1),('deleted-person','account','deleted-account',1),('deleted-person','email','deleted@example.test',1),('unverified-person','account','unverified-account',0),('unverified-person','email','unverified@example.test',1),('note','account','not-person-account',1),('note','email','not-person@example.test',1)").await.unwrap();
    import(&f, false).await;
    let db = f.db().await;
    let raw: String = sqlx::query_scalar(
        "SELECT payload FROM content_events WHERE type=? ORDER BY seq DESC LIMIT 1",
    )
    .bind(k::hosted_identity::IDENTITY_EVENT)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let matching: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(matching["emails"].as_object().unwrap().len(), 1);
}

#[tokio::test]
async fn imported_member_context_visible_person_does_not_authorize_root_without_manage() {
    let f = fixture().await;
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    // Exact source row is retained even if a later source policy only permits
    // View on its root. A visible Person is never a substitute for root Manage.
    source.execute("DELETE FROM member_contexts WHERE account_id='account-b'; UPDATE member_contexts SET root_record_id='private-b' WHERE account_id='account-a'; INSERT INTO policy_entries VALUES('private-b','account','account-a','view')").await.unwrap();
    let r = import(&f, false).await;
    let db = f.db().await;
    let a = &r.principals["account-a"];
    assert_eq!(
        k::kernel_effective_capability(&db, a, "private-b")
            .await
            .unwrap(),
        crate::authorization::Capability::View
    );
    let value = online(&db, a).await;
    assert_eq!(value["person_record_id"], "person-a");
    assert_eq!(value["root_record_id"], Value::Null);
    assert!(!value.to_string().contains("private-b"));
}
