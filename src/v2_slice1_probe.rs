//! v2 slice 1, increment 1: owned subset schema + two principals (`:memory:`).

#[tokio::test]
async fn v2_two_principals_no_person() {
    // The v2 path uses the current frozen engine schema.
    assert_eq!(crate::schema::DDL_STATEMENTS.len(), 358);
    assert_eq!(
        crate::schema::ddl_sha256(),
        crate::schema::FROZEN_DDL_SHA256,
    );

    let (db, a) = crate::kernel::create_v2_database(":memory:", "account", "A", "acct:a")
        .await
        .unwrap();

    // v1 record/policy tables absent; store + kernel tables present.
    let tables: Vec<String> =
        sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
            .fetch_all(db.write_pool())
            .await
            .unwrap();
    for absent in ["records", "record_policies", "links", "policy_entries"] {
        assert!(
            !tables.contains(&absent.to_string()),
            "v2 DB holds {absent}"
        );
    }
    for present in [
        "content_events",
        "content_event_causal_frontier",
        "act_state",
        "kernel_roots",
        "kernel_principals",
    ] {
        assert!(
            tables.contains(&present.to_string()),
            "v2 DB lacks {present}"
        );
    }

    // Exactly the genesis root, event one.
    let roots: Vec<(String, i64)> = sqlx::query_as("SELECT root_id, created_seq FROM kernel_roots")
        .fetch_all(db.write_pool())
        .await
        .unwrap();
    assert_eq!(roots.len(), 1);
    assert_eq!(roots[0].0, crate::events::KERNEL_ROOT_ID);
    assert_eq!(roots[0].1, 1);

    // Genesis already created admin A with the bootstrap; B comes through the
    // real append path. No Person anywhere.
    let b = crate::kernel::create_principal(&db, "agent", "B", "agent:b", "test:v2")
        .await
        .unwrap();
    assert_ne!(a, b);
    let ra = crate::kernel::resolve_principal_by_binding(&db, "acct:a")
        .await
        .unwrap()
        .expect("A resolvable from its binding");
    assert_eq!(ra, (a.clone(), "account".into(), "A".into()));
    let rb = crate::kernel::resolve_principal_by_binding(&db, "agent:b")
        .await
        .unwrap()
        .expect("B resolvable from its binding");
    assert_eq!(rb, (b.clone(), "agent".into(), "B".into()));
    assert!(
        crate::kernel::resolve_principal_by_binding(&db, "acct:nobody")
            .await
            .unwrap()
            .is_none()
    );
    let kinds: Vec<String> =
        sqlx::query_scalar("SELECT DISTINCT kind FROM kernel_principals ORDER BY kind")
            .fetch_all(db.write_pool())
            .await
            .unwrap();
    assert_eq!(kinds, vec!["account".to_string(), "agent".to_string()]);

    // Log shape: genesis, admin creation, attributed bootstrap, B creation.
    let history: Vec<String> = sqlx::query_scalar("SELECT type FROM content_events ORDER BY seq")
        .fetch_all(db.write_pool())
        .await
        .unwrap();
    assert_eq!(
        history,
        vec![
            "kernel.root_created.v1",
            "kernel.principal_created.v1",
            "kernel.root_admin_bootstrapped.v1",
            "kernel.principal_created.v1",
        ]
    );
    // A is root admin from genesis; a later bootstrap refuses event-free.
    assert_eq!(
        crate::kernel::kernel_effective_capability(&db, &a, crate::events::KERNEL_ROOT_ID)
            .await
            .unwrap(),
        crate::authorization::Capability::Manage
    );
    let events_at_setup: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    assert!(crate::kernel::bootstrap_root_admin(&db, &b).await.is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap(),
        events_at_setup
    );

    // Replay through the single entry point reproduces all tables exactly.
    let before = crate::kernel::dump_all_kernel_tables(&db).await.unwrap();
    assert_eq!(before.roots.len(), 1);
    assert_eq!(before.principals.len(), 2);
    assert_eq!(before.bootstrap.len(), 1);
    crate::kernel::replay_all_projections(&db).await.unwrap();
    let after = crate::kernel::dump_all_kernel_tables(&db).await.unwrap();
    assert_eq!(before, after);

    // v1 control still seeds the canonical Collection roots.
    let v1 = crate::db::create_database(":memory:").await.unwrap();
    let v1roots: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM records WHERE id IN ('native:root', 'native:unfiled')",
    )
    .fetch_one(v1.write_pool())
    .await
    .unwrap();
    assert_eq!(v1roots, 2);
}

#[tokio::test]
async fn v2_b_refused_read_write_edges_query() {
    use crate::kernel as v2;

    let (db, a) = v2::create_v2_database(":memory:", "account", "A", "acct:a")
        .await
        .unwrap();
    let b = v2::create_principal(&db, "account", "B", "acct:b", "test:v2")
        .await
        .unwrap();
    // Home H: only A. Home G: A edits, B views.
    let root = crate::events::KERNEL_ROOT_ID;
    let h = v2::create_home(&db, root, Some(&[(a.as_str(), "manage")]), &a)
        .await
        .unwrap();
    let g = v2::create_home(
        &db,
        root,
        Some(&[(a.as_str(), "edit"), (b.as_str(), "view")]),
        &a,
    )
    .await
    .unwrap();
    let r1 = v2::create_record_as(&db, &a, &h).await.unwrap();
    let r2 = v2::create_record_as(&db, &a, &h).await.unwrap();
    v2::link_records_as(&db, &a, &r1, &r2).await.unwrap();
    let p = v2::create_record_as(&db, &a, &g).await.unwrap();
    v2::link_records_as(&db, &a, &p, &r1).await.unwrap();
    let events_after_setup: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();

    // B reads P but not R1; B's view of P's edges omits R1 without a leak.
    assert!(v2::read_record_as(&db, &b, &p).await.unwrap().is_some());
    assert!(v2::read_record_as(&db, &b, &r1).await.unwrap().is_none());
    assert!(v2::read_record_as(&db, &b, "missing-record")
        .await
        .unwrap()
        .is_none());
    assert!(v2::links_from_as(&db, &b, &p).await.unwrap().is_empty());
    assert!(v2::links_from_as(&db, &b, &r1).await.unwrap().is_empty());
    let b_list = v2::list_records_as(&db, &b).await.unwrap();
    assert_eq!(b_list.len(), 1);
    assert_eq!(b_list[0].id, p);

    // B cannot write: no create in H, no link out of R1 (refusals are event-free).
    assert!(v2::create_record_as(&db, &b, &h).await.is_err());
    assert!(v2::link_records_as(&db, &b, &r1, &r2).await.is_err());
    assert!(v2::link_records_as(&db, &b, &p, &r1).await.is_err());
    let events_after_refusal: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    assert_eq!(events_after_setup, events_after_refusal);

    // A can do all of it.
    let r1_view = v2::read_record_as(&db, &a, &r1)
        .await
        .unwrap()
        .expect("A reads R1");
    assert_eq!(r1_view.owner_id.as_deref(), Some(a.as_str()));
    assert_eq!(
        v2::links_from_as(&db, &a, &p).await.unwrap(),
        vec![(r1.clone(), "relates_to".to_string())]
    );
    assert_eq!(
        v2::links_from_as(&db, &a, &r1).await.unwrap(),
        vec![(r2.clone(), "relates_to".to_string())]
    );
    let a_list = v2::list_records_as(&db, &a).await.unwrap();
    assert_eq!(a_list.len(), 3);

    // Owner floor: H's entries replaced with an empty list via the event path;
    // A keeps Manage, B still sees nothing.
    v2::replace_home_policy(&db, &a, &h, &[]).await.unwrap();
    assert_eq!(
        v2::kernel_effective_capability(&db, &a, &r1).await.unwrap(),
        crate::authorization::Capability::Manage
    );
    assert!(v2::read_record_as(&db, &a, &r1).await.unwrap().is_some());
    assert!(v2::read_record_as(&db, &b, &r1).await.unwrap().is_none());
    assert_eq!(
        v2::kernel_effective_capability(&db, &b, &r1).await.unwrap(),
        crate::authorization::Capability::None
    );
}

#[tokio::test]
async fn v2_grant_revoke_attributed_owner_attribution() {
    use crate::kernel as v2;

    let (db, a) = v2::create_v2_database(":memory:", "account", "A", "acct:a")
        .await
        .unwrap();
    let b = v2::create_principal(&db, "account", "B", "acct:b", "test:v2")
        .await
        .unwrap();
    let root = crate::events::KERNEL_ROOT_ID;
    let h = v2::create_home(&db, root, Some(&[(a.as_str(), "manage")]), &a)
        .await
        .unwrap();
    let r1 = v2::create_record_as(&db, &a, &h).await.unwrap();
    assert!(v2::read_record_as(&db, &b, &r1).await.unwrap().is_none());

    // A grants B View on H as an attributed event; B can now read R1.
    v2::replace_home_policy(&db, &a, &h, &[(a.as_str(), "manage"), (b.as_str(), "view")])
        .await
        .unwrap();
    assert!(v2::read_record_as(&db, &b, &r1).await.unwrap().is_some());
    let grant: (String, Option<String>) = sqlx::query_as(
        "SELECT type, actor FROM content_events WHERE type = 'kernel.home_policy_replaced.v1' ORDER BY seq LIMIT 1",
    )
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    assert_eq!(grant.1.as_deref(), Some(a.as_str()));

    // Attribution while B views the record but not the root: actors redacted.
    let hidden = v2::history_as(&db, &b, &r1).await.unwrap();
    assert!(!hidden.is_empty());
    assert!(hidden.iter().all(|event| event.actor.is_none()));

    // A grants B View on the workspace root; the same history discloses A.
    v2::replace_home_policy(
        &db,
        &a,
        crate::events::KERNEL_ROOT_ID,
        &[(a.as_str(), "manage"), (b.as_str(), "view")],
    )
    .await
    .unwrap();
    let shown = v2::history_as(&db, &b, &r1).await.unwrap();
    assert_eq!(shown.len(), hidden.len());
    assert!(shown
        .iter()
        .all(|event| event.actor.as_deref() == Some(a.as_str())));
    let own = v2::history_as(&db, &a, &r1).await.unwrap();
    assert!(own
        .iter()
        .all(|event| event.actor.as_deref() == Some(a.as_str())));

    // A revokes: B refused again. The revoke is attributed to A, like the grant.
    v2::replace_home_policy(&db, &a, &h, &[(a.as_str(), "manage")])
        .await
        .unwrap();
    assert!(v2::read_record_as(&db, &b, &r1).await.unwrap().is_none());
    let revoke_actor: Option<String> = sqlx::query_scalar(
        "SELECT actor FROM content_events WHERE type = 'kernel.home_policy_replaced.v1' AND record_id = ? ORDER BY seq DESC LIMIT 1",
    )
    .bind(&h)
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    assert_eq!(revoke_actor.as_deref(), Some(a.as_str()));
    // B cannot replace H's policy; no event appended.
    let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    assert!(
        v2::replace_home_policy(&db, &b, &h, &[(b.as_str(), "manage")])
            .await
            .is_err()
    );
    let events_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    assert_eq!(events_before, events_after);

    // Owner floor through the event path: emptied entries keep A at Manage.
    v2::replace_home_policy(&db, &a, &h, &[]).await.unwrap();
    assert_eq!(
        v2::kernel_effective_capability(&db, &a, &r1).await.unwrap(),
        crate::authorization::Capability::Manage
    );

    // Replay through the single entry point reproduces all tables exactly.
    let before = v2::dump_all_kernel_tables(&db).await.unwrap();
    assert_eq!(before.bootstrap.len(), 1);
    v2::replay_all_projections(&db).await.unwrap();
    assert_eq!(v2::dump_all_kernel_tables(&db).await.unwrap(), before);
}

#[tokio::test]
async fn v2_rehome_atomic_no_stale_revoked_hidden() {
    use crate::kernel as v2;

    let root = crate::events::KERNEL_ROOT_ID;
    let (db, a) = v2::create_v2_database(":memory:", "account", "A", "acct:a")
        .await
        .unwrap();
    let b = v2::create_principal(&db, "account", "B", "acct:b", "test:v2")
        .await
        .unwrap();
    let c = v2::create_principal(&db, "account", "C", "acct:c", "test:v2")
        .await
        .unwrap();
    // Genesis already bootstrapped A; a later bootstrap refuses, event-free.
    let events_at_bootstrap: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    assert!(v2::bootstrap_root_admin(&db, &b).await.is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap(),
        events_at_bootstrap
    );

    let h = v2::create_home(&db, root, Some(&[(a.as_str(), "manage")]), &a)
        .await
        .unwrap();
    // H2 inherits: no own policy row.
    let h2 = v2::create_home(&db, &h, None, &a).await.unwrap();
    let h3 = v2::create_home(
        &db,
        root,
        Some(&[(a.as_str(), "manage"), (b.as_str(), "view")]),
        &a,
    )
    .await
    .unwrap();
    let r1 = v2::create_record_as(&db, &a, &h).await.unwrap();
    let r2 = v2::create_record_as(&db, &a, &h2).await.unwrap();

    // 1. Nested inheritance follows the parent's current policy.
    v2::replace_home_policy(&db, &a, &h, &[(a.as_str(), "manage"), (b.as_str(), "view")])
        .await
        .unwrap();
    assert!(v2::read_record_as(&db, &b, &r2).await.unwrap().is_some());
    v2::replace_home_policy(&db, &a, &h, &[(a.as_str(), "manage")])
        .await
        .unwrap();
    assert!(v2::read_record_as(&db, &b, &r2).await.unwrap().is_none());

    // 2. Rehome R1 H -> H3: B reads immediately; back to H: refused immediately.
    v2::rehome_record_as(&db, &a, &r1, &h3).await.unwrap();
    assert!(v2::read_record_as(&db, &b, &r1).await.unwrap().is_some());
    v2::rehome_record_as(&db, &a, &r1, &h).await.unwrap();
    assert!(v2::read_record_as(&db, &b, &r1).await.unwrap().is_none());

    // 3. C holds Edit on R1 but only View on H3: refused, event-free, unmoved.
    v2::replace_home_policy(&db, &a, &h, &[(a.as_str(), "manage"), (c.as_str(), "edit")])
        .await
        .unwrap();
    v2::replace_home_policy(
        &db,
        &a,
        &h3,
        &[
            (a.as_str(), "manage"),
            (b.as_str(), "view"),
            (c.as_str(), "view"),
        ],
    )
    .await
    .unwrap();
    let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    assert!(v2::rehome_record_as(&db, &c, &r1, &h3).await.is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap(),
        events_before
    );
    assert_eq!(
        v2::read_record_as(&db, &a, &r1)
            .await
            .unwrap()
            .unwrap()
            .home_id,
        h
    );

    // 4. Revocation durability: B reads R1 under a grant, then history and
    // reads go dark together after revoke.
    v2::replace_home_policy(
        &db,
        &a,
        &h,
        &[
            (a.as_str(), "manage"),
            (c.as_str(), "edit"),
            (b.as_str(), "view"),
        ],
    )
    .await
    .unwrap();
    assert!(v2::read_record_as(&db, &b, &r1).await.unwrap().is_some());
    assert!(!v2::history_as(&db, &b, &r1).await.unwrap().is_empty());
    v2::replace_home_policy(&db, &a, &h, &[(a.as_str(), "manage"), (c.as_str(), "edit")])
        .await
        .unwrap();
    assert!(v2::read_record_as(&db, &b, &r1).await.unwrap().is_none());
    assert!(v2::history_as(&db, &b, &r1).await.unwrap().is_empty());

    // 5. Principal creation alone grants nothing.
    let d = v2::create_principal(&db, "agent", "D", "agent:d", "test:v2")
        .await
        .unwrap();
    assert!(v2::read_record_as(&db, &d, &r1).await.unwrap().is_none());
    assert_eq!(
        v2::kernel_effective_capability(&db, &d, &r1).await.unwrap(),
        crate::authorization::Capability::None
    );

    // 6. Full replay through the single entry point reproduces all tables.
    let before = v2::dump_all_kernel_tables(&db).await.unwrap();
    assert_eq!(
        before
            .bootstrap
            .iter()
            .map(|(id, _)| id)
            .collect::<Vec<_>>(),
        vec![&a]
    );
    v2::replay_all_projections(&db).await.unwrap();
    assert_eq!(v2::dump_all_kernel_tables(&db).await.unwrap(), before);
}

struct PersonWorld {
    db: crate::db::Db,
    a: String,
    b: String,
    h: String,
    r1: String,
    person: Option<String>,
    pin_digest: Option<String>,
}

async fn build_person_world(with_person: bool) -> PersonWorld {
    use crate::kernel as v2;

    let root = crate::events::KERNEL_ROOT_ID;
    let (db, a) = v2::create_v2_database(":memory:", "account", "A", "acct:a")
        .await
        .unwrap();
    let b = v2::create_principal(&db, "account", "B", "acct:b", "test:v2")
        .await
        .unwrap();
    let h = v2::create_home(&db, root, Some(&[(a.as_str(), "manage")]), &a)
        .await
        .unwrap();
    let r1 = v2::create_record_as(&db, &a, &h).await.unwrap();
    let (person, pin_digest) = if with_person {
        let bytes = serde_json::json!({
            "family": "local.person", "version": 1, "primary_type": "Person",
            "display": "display name",
            "kinds": [{"token": "member"}],
        })
        .to_string();
        let identity = v2::install_definition_as(&db, &a, "local.person", 1, bytes.as_bytes())
            .await
            .unwrap();
        v2::adopt_definition_as(&db, &a, "local.person", Some(&identity))
            .await
            .unwrap();
        let p = v2::create_package_record_as(
            &db,
            &a,
            &h,
            "Person",
            "member",
            "PER-001",
            "local.person",
        )
        .await
        .unwrap();
        v2::link_records_as(&db, &a, &p, &a).await.unwrap();
        (Some(p), Some(identity.digest))
    } else {
        (None, None)
    };
    PersonWorld {
        db,
        a,
        b,
        h,
        r1,
        person,
        pin_digest,
    }
}

fn history_shape(events: &[crate::kernel::KernelHistoryEvent]) -> Vec<(String, Option<String>)> {
    events
        .iter()
        .map(|e| (e.event_type.clone(), e.actor.clone()))
        .collect()
}

#[tokio::test]
async fn v2_person_disabled_a_unaffected_edge_lives() {
    use crate::kernel as v2;

    let w = build_person_world(true).await;
    let person = w.person.clone().expect("person installed");
    let digest = w.pin_digest.clone().expect("pin digest");
    let view_person =
        "SELECT primary_type, kind, pin_family, pin_version, pin_digest FROM kernel_records WHERE id = ?";
    let person_row = || async {
        sqlx::query_as::<
            _,
            (
                Option<String>,
                Option<String>,
                Option<String>,
                Option<i64>,
                Option<String>,
            ),
        >(view_person)
        .bind(&person)
        .fetch_one(w.db.write_pool())
        .await
        .unwrap()
    };

    // Snapshots before disable.
    let cap_a_r1 = v2::kernel_effective_capability(&w.db, &w.a, &w.r1)
        .await
        .unwrap();
    let cap_a_workspace =
        v2::kernel_effective_capability(&w.db, &w.a, crate::events::KERNEL_ROOT_ID)
            .await
            .unwrap();
    let hist_a = history_shape(&v2::history_as(&w.db, &w.a, &w.r1).await.unwrap());
    let hist_b = history_shape(&v2::history_as(&w.db, &w.b, &w.r1).await.unwrap());
    let link = v2::links_from_as(&w.db, &w.a, &person).await.unwrap();
    let row_before = person_row().await;
    assert_eq!(cap_a_r1, crate::authorization::Capability::Manage);
    assert_eq!(cap_a_workspace, crate::authorization::Capability::Manage);
    assert_eq!(link, vec![(w.a.clone(), "relates_to".to_string())]);
    assert_eq!(
        row_before,
        (
            Some("Person".into()),
            Some("member".into()),
            Some("local.person".into()),
            Some(1),
            Some(digest.clone())
        )
    );
    // The binding IS the link: its target resolves to principal A.
    let label: String =
        sqlx::query_scalar("SELECT display_label FROM kernel_principals WHERE principal_id = ?")
            .bind(&link[0].0)
            .fetch_one(w.db.write_pool())
            .await
            .unwrap();
    assert_eq!(label, "A");

    // Disable authoring as an attributed event; new Persons refuse event-free.
    v2::adopt_definition_as(&w.db, &w.a, "local.person", None)
        .await
        .unwrap();
    let disable_actor: Option<String> = sqlx::query_scalar(
        "SELECT actor FROM meta_events WHERE type = 'definition_adoption.set.v1' ORDER BY seq DESC LIMIT 1",
    )
    .fetch_one(w.db.write_pool())
    .await
    .unwrap();
    assert_eq!(disable_actor.as_deref(), Some(w.a.as_str()));
    let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(w.db.write_pool())
        .await
        .unwrap();
    assert!(v2::create_package_record_as(
        &w.db,
        &w.a,
        &w.h,
        "Person",
        "member",
        "PER-002",
        "local.person"
    )
    .await
    .is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM content_events")
            .fetch_one(w.db.write_pool())
            .await
            .unwrap(),
        events_before
    );

    // Everything else unchanged.
    assert_eq!(
        v2::kernel_effective_capability(&w.db, &w.a, &w.r1)
            .await
            .unwrap(),
        cap_a_r1
    );
    assert_eq!(
        v2::kernel_effective_capability(&w.db, &w.a, crate::events::KERNEL_ROOT_ID)
            .await
            .unwrap(),
        cap_a_workspace
    );
    assert_eq!(
        history_shape(&v2::history_as(&w.db, &w.a, &w.r1).await.unwrap()),
        hist_a
    );
    assert_eq!(
        history_shape(&v2::history_as(&w.db, &w.b, &w.r1).await.unwrap()),
        hist_b
    );
    assert_eq!(v2::links_from_as(&w.db, &w.a, &person).await.unwrap(), link);
    assert_eq!(person_row().await, row_before);

    // Owner floor with the home entries emptied through the event path.
    v2::replace_home_policy(&w.db, &w.a, &w.h, &[])
        .await
        .unwrap();
    assert_eq!(
        v2::kernel_effective_capability(&w.db, &w.a, &w.r1)
            .await
            .unwrap(),
        crate::authorization::Capability::Manage
    );

    // A twin that never installed Person decides identically: same capabilities,
    // same history shape (record creation by its own A), same hidden B.
    let t = build_person_world(false).await;
    assert_eq!(
        v2::kernel_effective_capability(&t.db, &t.a, &t.r1)
            .await
            .unwrap(),
        cap_a_r1
    );
    assert_eq!(
        v2::kernel_effective_capability(&t.db, &t.a, crate::events::KERNEL_ROOT_ID)
            .await
            .unwrap(),
        cap_a_workspace
    );
    assert_eq!(
        history_shape(&v2::history_as(&t.db, &t.a, &t.r1).await.unwrap()),
        vec![("kernel.record_created.v1".to_string(), Some(t.a.clone()))]
    );
    assert_eq!(
        hist_a,
        vec![("kernel.record_created.v1".to_string(), Some(w.a.clone()))]
    );
    assert!(hist_b.is_empty());
    assert!(history_shape(&v2::history_as(&t.db, &t.b, &t.r1).await.unwrap()).is_empty());

    // Full replay through the single entry point reproduces all tables.
    let before = v2::dump_all_kernel_tables(&w.db).await.unwrap();
    v2::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(v2::dump_all_kernel_tables(&w.db).await.unwrap(), before);
}

const SPECIMEN_BYTES: &str = r#"{"family":"lab.specimen","version":1,"primary_type":"Specimen","kinds":[{"token":"field-sample"},{"token":"lab-aliquot"}]}"#;

#[tokio::test]
async fn v2_specimen_pinned_file_db() {
    use crate::kernel as v2;

    // Current frozen statements, digest, prod event types, and v1 roots.
    assert_eq!(crate::schema::DDL_STATEMENTS.len(), 358);
    assert_eq!(
        crate::schema::ddl_sha256(),
        crate::schema::FROZEN_DDL_SHA256
    );
    assert_eq!(crate::events::EVENT_TYPES.len(), 46);
    let v1 = crate::db::create_database(":memory:").await.unwrap();
    let v1roots: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM records WHERE id IN ('native:root', 'native:unfiled')",
    )
    .fetch_one(v1.write_pool())
    .await
    .unwrap();
    assert_eq!(v1roots, 2);
    let v1total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records")
        .fetch_one(v1.write_pool())
        .await
        .unwrap();
    assert_eq!(
        v1total, 2,
        "default constructor seeds exactly the two roots"
    );
    let v1anchor: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM record_policies WHERE record_id = 'native:root'")
            .fetch_one(v1.write_pool())
            .await
            .unwrap();
    assert_eq!(v1anchor, 1, "default constructor seeds the root policy");

    let dir = tempfile::tempdir().unwrap();
    let url = dir
        .path()
        .join("v2-specimen.db")
        .to_str()
        .unwrap()
        .to_string();
    let (db, a) = v2::create_v2_database(&url, "account", "A", "acct:a")
        .await
        .unwrap();
    let root = crate::events::KERNEL_ROOT_ID;
    let h = v2::create_home(&db, root, Some(&[(a.as_str(), "manage")]), &a)
        .await
        .unwrap();

    // Refusal before adoption appends nothing.
    let count = || async {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap()
    };
    assert!(v2::create_package_record_as(
        &db,
        &a,
        &h,
        "Specimen",
        "field-sample",
        "LAB-001",
        "lab.specimen"
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("not adopted"));
    let installed =
        v2::install_definition_as(&db, &a, "lab.specimen", 1, SPECIMEN_BYTES.as_bytes())
            .await
            .unwrap();
    v2::adopt_definition_as(&db, &a, "lab.specimen", Some(&installed))
        .await
        .unwrap();

    // Mismatches refuse without events.
    let before = count().await;
    assert!(v2::create_package_record_as(
        &db,
        &a,
        &h,
        "Jar",
        "field-sample",
        "LAB-X",
        "lab.specimen"
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("disagrees"));
    assert!(v2::create_package_record_as(
        &db,
        &a,
        &h,
        "Specimen",
        "unknown-kind",
        "LAB-X",
        "lab.specimen"
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("absent"));
    assert_eq!(count().await, before);

    let s = v2::create_package_record_as(
        &db,
        &a,
        &h,
        "Specimen",
        "field-sample",
        "LAB-001",
        "lab.specimen",
    )
    .await
    .unwrap();
    let pin_row =
        "SELECT pin_family, pin_version, pin_digest, interpreter FROM kernel_records WHERE id = ?";
    let pinned: (Option<String>, Option<i64>, Option<String>, Option<String>) =
        sqlx::query_as(pin_row)
            .bind(&s)
            .fetch_one(db.write_pool())
            .await
            .unwrap();
    assert_eq!(
        pinned,
        (
            Some("lab.specimen".into()),
            Some(1),
            Some(installed.digest.clone()),
            Some("native.defn/1".into())
        )
    );

    // Close and reopen the file; the Specimen reads back whole.
    db.close().await;
    let reopened = crate::db::open_database(&url).await.unwrap();
    let view = v2::read_record_as(&reopened, &a, &s)
        .await
        .unwrap()
        .expect("specimen survives reopen");
    assert_eq!(view.owner_id.as_deref(), Some(a.as_str()));
    let repinned: (Option<String>, Option<i64>, Option<String>, Option<String>) =
        sqlx::query_as(pin_row)
            .bind(&s)
            .fetch_one(reopened.write_pool())
            .await
            .unwrap();
    assert_eq!(repinned, pinned);
    assert!(!v2::history_as(&reopened, &a, &s).await.unwrap().is_empty());

    // After disable the Specimen still reads with its exact pin; history intact.
    v2::adopt_definition_as(&reopened, &a, "lab.specimen", None)
        .await
        .unwrap();
    assert!(v2::create_package_record_as(
        &reopened,
        &a,
        &h,
        "Specimen",
        "field-sample",
        "LAB-002",
        "lab.specimen"
    )
    .await
    .is_err());
    let still: (Option<String>, Option<i64>, Option<String>, Option<String>) =
        sqlx::query_as(pin_row)
            .bind(&s)
            .fetch_one(reopened.write_pool())
            .await
            .unwrap();
    assert_eq!(still, pinned);
    assert!(!v2::history_as(&reopened, &a, &s).await.unwrap().is_empty());
    reopened.close().await;
}

fn content_event(
    record_id: &str,
    event_type: &str,
    payload: serde_json::Value,
) -> crate::events::EventRow {
    crate::events::EventRow {
        local_seq: 99,
        id: uuid::Uuid::new_v4().to_string(),
        record_id: record_id.to_string(),
        event_type: event_type.to_string(),
        payload: Some(serde_json::to_string(&payload).unwrap()),
        actor: Some("test:v2".to_string()),
        run_key: None,
        parent_key: None,
        intent: None,
        created_at: "2026-01-01T00:00:00.000Z".to_string(),
        causal_envelope: crate::events::CausalEnvelopeV1::complete(
            crate::events::CausalFrontierV1::empty(),
        ),
        act: None,
    }
}

#[tokio::test]
async fn v2_specimen_pinned_replay_loud() {
    use crate::kernel as v2;

    // Destructive replay with adoption already disabled: the Specimen still
    // reconstructs, because the fold resolves the pin through retained bytes.
    let root = crate::events::KERNEL_ROOT_ID;
    let (db, a) = v2::create_v2_database(":memory:", "account", "A", "acct:a")
        .await
        .unwrap();
    let h = v2::create_home(&db, root, Some(&[(a.as_str(), "manage")]), &a)
        .await
        .unwrap();
    let installed =
        v2::install_definition_as(&db, &a, "lab.specimen", 1, SPECIMEN_BYTES.as_bytes())
            .await
            .unwrap();
    v2::adopt_definition_as(&db, &a, "lab.specimen", Some(&installed))
        .await
        .unwrap();
    let s = v2::create_package_record_as(
        &db,
        &a,
        &h,
        "Specimen",
        "field-sample",
        "LAB-001",
        "lab.specimen",
    )
    .await
    .unwrap();
    v2::adopt_definition_as(&db, &a, "lab.specimen", None)
        .await
        .unwrap();

    // Full replay through the single entry point reproduces all tables.
    let before = v2::dump_all_kernel_tables(&db).await.unwrap();
    assert_eq!(before.records.len(), 1);
    v2::replay_all_projections(&db).await.unwrap();
    let after = v2::dump_all_kernel_tables(&db).await.unwrap();
    assert_eq!(before, after);
    assert_eq!(after.records[0].0, s);
    assert_eq!(after.records[0].7, Some(1));
    assert_eq!(
        after.records[0].8.as_deref(),
        Some(installed.digest.as_str())
    );
    assert_eq!(after.records[0].9.as_deref(), Some("native.defn/1"));

    // (a) Tampered artifact bytes: digest mismatch fails the meta replay loudly.
    let tampered = {
        let (db, _) = v2::create_v2_database(":memory:", "account", "T", "test:t")
            .await
            .unwrap();
        let poison = crate::meta::events::MetaEventRow {
            seq: 1,
            id: uuid::Uuid::new_v4().to_string(),
            subject_id: "vv:voc:ontology:definition-artifact:x.y@1#0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            event_type: "definition_artifact.installed".to_string(),
            payload: Some(r#"{"vocabulary_id":"voc:ontology:definition-artifact","value":"x.y@1#0000000000000000000000000000000000000000000000000000000000000000","family":"x.y","version":1,"digest":"0000000000000000000000000000000000000000000000000000000000000000","artifact_bytes":"{\"family\":\"x.y\",\"version\":1,\"kinds\":[]}","request_key":null}"#.to_string()),
            actor: Some("test:v2".to_string()),
            created_at: "2026-01-01T00:00:00.000Z".to_string(),
        };
        let mut conn = db.write_pool().acquire().await.unwrap();
        let err = crate::projector::meta::replay_meta(&mut conn, &[poison])
            .await
            .unwrap_err()
            .to_string();
        drop(conn);
        db.close().await;
        err
    };
    assert!(tampered.contains("digest mismatch"), "{tampered}");

    // (b) Pinned event with no retained artifact fails the content fold loudly.
    let missing = {
        let (db, t) = v2::create_v2_database(":memory:", "account", "T", "test:t")
            .await
            .unwrap();
        let home = v2::create_home(&db, root, Some(&[]), &t).await.unwrap();
        let record_id = uuid::Uuid::new_v4().to_string();
        let event = content_event(
            &record_id,
            "kernel.record_created.v1",
            serde_json::json!({
                "home_id": home, "owner_id": None::<String>,
                "primary_type": "Specimen", "kind": "field-sample", "accession": "LAB-9",
                "pin": {"family": "ghost.fam", "version": 1,
                    "digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                "interpreter": "native.defn/1",
            }),
        );
        let mut conn = db.write_pool().acquire().await.unwrap();
        let err = crate::projector::project(&mut conn, &event)
            .await
            .unwrap_err()
            .to_string();
        drop(conn);
        db.close().await;
        (err, record_id)
    };
    assert!(missing.0.contains(&missing.1), "{missing:?}");
    assert!(
        missing.0.contains("missing definition artifact"),
        "{missing:?}"
    );

    // (c) Unknown interpreter version fails loudly; nothing is projected.
    let unknown = {
        let (db, t) = v2::create_v2_database(":memory:", "account", "T", "test:t")
            .await
            .unwrap();
        let home = v2::create_home(&db, root, Some(&[]), &t).await.unwrap();
        let record_id = uuid::Uuid::new_v4().to_string();
        let event = content_event(
            &record_id,
            "kernel.record_created.v1",
            serde_json::json!({
                "home_id": home, "owner_id": None::<String>,
                "primary_type": "Specimen", "kind": "field-sample", "accession": "LAB-9",
                "pin": {"family": "lab.specimen", "version": 1, "digest": &installed.digest},
                "interpreter": "native.defn/999",
            }),
        );
        let mut conn = db.write_pool().acquire().await.unwrap();
        let err = crate::projector::project(&mut conn, &event)
            .await
            .unwrap_err()
            .to_string();
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM kernel_records")
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        drop(conn);
        db.close().await;
        (err, record_id, rows)
    };
    assert!(unknown.0.contains(&unknown.1), "{unknown:?}");
    assert!(
        unknown.0.contains("unknown definition interpreter"),
        "{unknown:?}"
    );
    assert_eq!(unknown.2, 0);
}

// ---------------------------------------------------------------------------
// Reviewer-added probes, inverted: each now asserts the fixed behaviour.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn v2_review_bootstrap_cannot_be_seized() {
    use crate::kernel as v2;
    // Genesis names the admin; no first-come window exists.
    let (db, a) = v2::create_v2_database(":memory:", "account", "A", "acct:a")
        .await
        .unwrap();
    let b = v2::create_principal(&db, "account", "B", "acct:b", "test:v2")
        .await
        .unwrap();
    let root = crate::events::KERNEL_ROOT_ID;
    assert_eq!(
        v2::kernel_effective_capability(&db, &a, root)
            .await
            .unwrap(),
        crate::authorization::Capability::Manage
    );
    assert_eq!(
        v2::kernel_effective_capability(&db, &b, root)
            .await
            .unwrap(),
        crate::authorization::Capability::None
    );
    // B cannot bootstrap afterwards, appends nothing, and cannot install.
    let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    assert!(v2::bootstrap_root_admin(&db, &b).await.is_err());
    assert!(
        v2::install_definition_as(&db, &b, "lab.specimen", 1, SPECIMEN_BYTES.as_bytes())
            .await
            .is_err()
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap(),
        events_before
    );
    // B cannot create homes either (no Manage on the root); A is never locked out.
    assert!(v2::create_home(&db, root, Some(&[]), &b).await.is_err());
    assert_eq!(
        v2::kernel_effective_capability(&db, &a, root)
            .await
            .unwrap(),
        crate::authorization::Capability::Manage
    );
    let home = v2::create_home(&db, root, Some(&[(a.as_str(), "manage")]), &a)
        .await
        .unwrap();
    assert_eq!(
        v2::kernel_effective_capability(&db, &a, &home)
            .await
            .unwrap(),
        crate::authorization::Capability::Manage
    );
    // Slice-2 carry-over: the owner floor keeps an emptied home recoverable
    // by its owner, so an explicitly empty anchor no longer denies the
    // creating owner (a non-owner still sees None).
    let closed = v2::create_home(&db, root, Some(&[]), &a).await.unwrap();
    assert_eq!(
        v2::kernel_effective_capability(&db, &a, &closed)
            .await
            .unwrap(),
        crate::authorization::Capability::Manage
    );
    assert_eq!(
        v2::kernel_effective_capability(&db, &b, &closed)
            .await
            .unwrap(),
        crate::authorization::Capability::None
    );
}

#[tokio::test]
async fn v2_review_write_errors_hide_existence() {
    use crate::kernel as v2;
    let (db, a) = v2::create_v2_database(":memory:", "account", "A", "acct:a")
        .await
        .unwrap();
    let b = v2::create_principal(&db, "account", "B", "acct:b", "test:v2")
        .await
        .unwrap();
    let root = crate::events::KERNEL_ROOT_ID;
    let ha = v2::create_home(&db, root, Some(&[(a.as_str(), "manage")]), &a)
        .await
        .unwrap();
    let hidden = v2::create_record_as(&db, &a, &ha).await.unwrap();
    let hb = v2::create_home(&db, root, Some(&[(b.as_str(), "manage")]), &a)
        .await
        .unwrap();
    let own = v2::create_record_as(&db, &b, &hb).await.unwrap();
    // The read surface hides the record.
    assert!(v2::read_record_as(&db, &b, &hidden)
        .await
        .unwrap()
        .is_none());
    // The write surface refuses identically: one uniform error, no id.
    let e_hidden = v2::link_records_as(&db, &b, &own, &hidden)
        .await
        .unwrap_err()
        .to_string();
    let absent = uuid::Uuid::new_v4().to_string();
    let e_absent = v2::link_records_as(&db, &b, &own, &absent)
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(e_hidden, e_absent);
    assert!(!e_hidden.contains(&hidden));
}

#[tokio::test]
async fn v2_review_owner_id_redacted_without_root_view() {
    use crate::kernel as v2;
    let (db, a) = v2::create_v2_database(":memory:", "account", "A", "acct:a")
        .await
        .unwrap();
    let b = v2::create_principal(&db, "account", "B", "acct:b", "test:v2")
        .await
        .unwrap();
    let root = crate::events::KERNEL_ROOT_ID;
    let h = v2::create_home(
        &db,
        root,
        Some(&[(a.as_str(), "manage"), (b.as_str(), "view")]),
        &a,
    )
    .await
    .unwrap();
    let r = v2::create_record_as(&db, &a, &h).await.unwrap();
    // B sees the record but not its owner: same rule as history actors.
    let view = v2::read_record_as(&db, &b, &r)
        .await
        .unwrap()
        .expect("B sees r");
    assert_eq!(view.owner_id, None);
    let hist = v2::history_as(&db, &b, &r).await.unwrap();
    assert!(!hist.is_empty());
    assert!(hist.iter().all(|e| e.actor.is_none()));
    // A sees both (self), and B sees the owner after a root View grant.
    let own = v2::read_record_as(&db, &a, &r)
        .await
        .unwrap()
        .expect("A sees r");
    assert_eq!(own.owner_id.as_deref(), Some(a.as_str()));
    v2::replace_home_policy(
        &db,
        &a,
        root,
        &[(a.as_str(), "manage"), (b.as_str(), "view")],
    )
    .await
    .unwrap();
    let granted = v2::read_record_as(&db, &b, &r)
        .await
        .unwrap()
        .expect("B sees r");
    assert_eq!(granted.owner_id.as_deref(), Some(a.as_str()));
}

#[tokio::test]
async fn v2_review_content_replay_refuses_tampered_bytes() {
    use crate::kernel as v2;
    let (db, a) = v2::create_v2_database(":memory:", "account", "A", "acct:a")
        .await
        .unwrap();
    let root = crate::events::KERNEL_ROOT_ID;
    let h = v2::create_home(&db, root, Some(&[(a.as_str(), "manage")]), &a)
        .await
        .unwrap();
    let installed =
        v2::install_definition_as(&db, &a, "lab.specimen", 1, SPECIMEN_BYTES.as_bytes())
            .await
            .unwrap();
    v2::adopt_definition_as(&db, &a, "lab.specimen", Some(&installed))
        .await
        .unwrap();
    let s = v2::create_package_record_as(
        &db,
        &a,
        &h,
        "Specimen",
        "field-sample",
        "LAB-001",
        "lab.specimen",
    )
    .await
    .unwrap();
    // Tamper the retained bytes directly, leaving the digest column intact.
    sqlx::query(
        "UPDATE definition_artifacts SET artifact_bytes = ? WHERE family = 'lab.specimen' AND version = 1",
    )
    .bind("{\"family\":\"lab.specimen\",\"version\":1,\"primary_type\":\"EVIL\",\"kinds\":[]}")
    .execute(db.write_pool())
    .await
    .unwrap();
    // Content-only destructive replay must now fail loudly naming record+pin.
    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    let events = crate::conformance::rebuild::read_all_events(&mut tx)
        .await
        .unwrap();
    for table in [
        "kernel_links",
        "kernel_records",
        "kernel_adoptions",
        "kernel_policy_entries",
        "kernel_policies",
        "kernel_root_bootstrap",
        // Roots before principals: homes reference their owner principal.
        "kernel_roots",
        "kernel_principals",
    ] {
        sqlx::query(&format!("DELETE FROM {table}"))
            .execute(&mut *tx)
            .await
            .unwrap();
    }
    let mut failure = None;
    for event in &events {
        if let Err(error) = crate::projector::project(&mut tx, event).await {
            failure = Some(error.to_string());
            break;
        }
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM kernel_records")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    let err = failure.expect("content replay must refuse tampered bytes");
    assert!(err.contains(&s), "{err}");
    assert!(err.contains("lab.specimen"), "{err}");
    assert_eq!(count, 0, "no governed record from tampered bytes");
}
