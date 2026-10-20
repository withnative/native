use super::*;
async fn world() -> (Db, String, String, String, String) {
    let (db, admin) = create_v2_database(":memory:", "account", "Admin", "test:admin")
        .await
        .unwrap();
    let host = resolve_principal_by_binding(&db, HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let a = create_record_as(&db, &admin, KERNEL_ROOT_ID).await.unwrap();
    let b = create_record_as(&db, &admin, KERNEL_ROOT_ID).await.unwrap();
    (db, admin, host, a, b)
}
#[tokio::test]
async fn generic_link_lifecycle_permissions_pagination_and_replay() {
    let (db, admin, host, a, b) = world().await;
    let target_revision = read_record_as(&db, &admin, &b)
        .await
        .unwrap()
        .unwrap()
        .revision;
    assert!(add_generic_link_as(&db, &host, &a, &b, "part_of", None)
        .await
        .is_err());
    for rel in [
        "relates_to",
        "",
        &"x".repeat(MAX_LINK_RELATIONSHIP_BYTES + 1),
    ] {
        assert!(add_generic_link_as(&db, &admin, &a, &b, rel, None)
            .await
            .is_err());
    }
    let first = add_generic_link_as(&db, &admin, &a, &b, "part_of", Some("note".into()))
        .await
        .unwrap()
        .link;
    assert!(remove_generic_link_as(&db, &host, &a, &first.link_id)
        .await
        .is_err());
    let second = add_generic_link_as(&db, &admin, &a, &b, "related_to", None)
        .await
        .unwrap()
        .link;
    let page = generic_links_as(&db, &admin, &a, false, None, None, 1)
        .await
        .unwrap();
    assert_eq!(page.links.len(), 1);
    let next = generic_links_as(&db, &admin, &a, false, None, page.next.as_deref(), 1)
        .await
        .unwrap();
    assert_eq!(next.links.len(), 1);
    assert_ne!(page.links[0].link_id, next.links[0].link_id);
    assert!(next.next.is_none());
    assert_eq!(
        generic_links_as(&db, &admin, &b, true, Some("part_of"), None, 10)
            .await
            .unwrap()
            .links,
        vec![first.clone()]
    );
    assert!(generic_links_as(&db, &host, &a, false, None, None, 10)
        .await
        .unwrap()
        .links
        .is_empty());
    assert_eq!(
        generic_links_as(&db, &host, &a, false, None, None, 10)
            .await
            .unwrap(),
        generic_links_as(&db, &host, "missing", false, None, None, 10)
            .await
            .unwrap()
    );
    remove_generic_link_as(&db, &admin, &a, &first.link_id)
        .await
        .unwrap();
    assert!(remove_generic_link_as(&db, &admin, &a, &first.link_id)
        .await
        .is_err());
    let again = add_generic_link_as(&db, &admin, &a, &b, "part_of", None)
        .await
        .unwrap()
        .link;
    assert_ne!(first.link_id, again.link_id);
    assert_eq!(
        read_record_as(&db, &admin, &b)
            .await
            .unwrap()
            .unwrap()
            .revision,
        target_revision
    );
    assert!(
        read_record_as(&db, &admin, &a)
            .await
            .unwrap()
            .unwrap()
            .revision
            > target_revision
    );
    assert_eq!(
        generic_links_as(&db, &admin, &b, true, Some("related_to"), None, 10)
            .await
            .unwrap()
            .links,
        vec![second]
    );
    let dump = dump_all_kernel_tables(&db).await.unwrap();
    replay_all_projections(&db).await.unwrap();
    assert_eq!(dump_all_kernel_tables(&db).await.unwrap(), dump);
}
#[tokio::test]
async fn generic_link_import_preserves_identity_and_retry_witness() {
    let (db, admin, host, a, b) = world().await;
    let original = GenericLink {
        link_id: "v1-original-link".into(),
        source_id: a.clone(),
        target_id: b.clone(),
        relationship: "relates-to".into(),
        note: Some("original note".into()),
        created_at: "2020-01-02T03:04:05Z".into(),
        actor: Some("original author".into()),
    };
    assert!(import_generic_link_as(&db, &admin, &original)
        .await
        .is_err());
    assert_eq!(
        import_generic_link_as(&db, &host, &original).await.unwrap(),
        GenericLinkOutcome::Created
    );
    let before = dump_all_kernel_tables(&db).await.unwrap();
    assert_eq!(
        import_generic_link_as(&db, &host, &original).await.unwrap(),
        GenericLinkOutcome::Unchanged
    );
    assert_eq!(before, dump_all_kernel_tables(&db).await.unwrap());
    let mut expected = original.clone();
    expected.actor = Some("v1:original author".into());
    assert_eq!(
        generic_links_as(&db, &admin, &a, false, None, None, 10)
            .await
            .unwrap()
            .links,
        vec![expected]
    );
    let mut changed = original.clone();
    changed.note = None;
    assert_eq!(
        import_generic_link_as(&db, &host, &changed).await.unwrap(),
        GenericLinkOutcome::Updated
    );
    assert_eq!(
        import_generic_link_as(&db, &host, &changed).await.unwrap(),
        GenericLinkOutcome::Unchanged
    );
    let mut bad_metadata = changed.clone();
    bad_metadata.actor = Some("someone else".into());
    assert!(matches!(
        import_generic_link_as(&db, &host, &bad_metadata).await,
        Err(Error::Conflict(_))
    ));
    changed.relationship = "relates_to".into();
    changed.link_id = "other".into();
    assert!(import_generic_link_as(&db, &host, &changed).await.is_err());
    remove_generic_link_as(&db, &admin, &a, &original.link_id)
        .await
        .unwrap();
    assert_eq!(
        import_generic_link_as(&db, &host, &original).await.unwrap(),
        GenericLinkOutcome::Updated
    );
    assert!(generic_links_as(&db, &admin, &a, false, None, None, 10)
        .await
        .unwrap()
        .links
        .is_empty());
    let dump = dump_all_kernel_tables(&db).await.unwrap();
    replay_all_projections(&db).await.unwrap();
    assert_eq!(dump_all_kernel_tables(&db).await.unwrap(), dump);
}

#[tokio::test]
async fn generic_link_endpoint_visibility_including_history_and_raw_admission() {
    let (db, admin, _, a, b) = world().await;
    let reader = create_principal(&db, "account", "Reader", "acct:reader", &admin)
        .await
        .unwrap();
    let shared = [(&admin[..], "manage"), (&reader[..], "edit")];
    replace_home_policy(&db, &admin, KERNEL_ROOT_ID, &shared)
        .await
        .unwrap();
    let target_view = [(&admin[..], "manage"), (&reader[..], "view")];
    let home = create_home(&db, KERNEL_ROOT_ID, Some(&target_view), &admin)
        .await
        .unwrap();
    rehome_record_as(&db, &admin, &b, &home).await.unwrap();
    let link = add_generic_link_as(&db, &reader, &a, &b, " part_of ", None)
        .await
        .unwrap()
        .link;
    assert_eq!(link.relationship, " part_of ");
    replace_home_policy(&db, &admin, &home, &[(&admin, "manage")])
        .await
        .unwrap();
    assert!(generic_links_as(&db, &reader, &a, false, None, None, 10)
        .await
        .unwrap()
        .links
        .is_empty());
    assert!(generic_links_as(&db, &reader, &b, true, None, None, 10)
        .await
        .unwrap()
        .links
        .is_empty());
    assert!(!history_as(&db, &reader, &a)
        .await
        .unwrap()
        .iter()
        .any(|e| e.event_type == ADDED));
    for target in [&b[..], "missing"] {
        let err = add_generic_link_as(&db, &reader, &a, target, "part_of", None)
            .await
            .unwrap_err();
        assert!(matches!(err,Error::Engine(ref text) if text==HIDDEN_OR_MISSING));
    }
    assert!(add_generic_link_as(
        &db,
        &reader,
        &a,
        &b,
        " part_of ",
        Some("hidden note change".into())
    )
    .await
    .is_err());
    assert!(remove_generic_link_as(&db, &reader, &a, &link.link_id)
        .await
        .is_err());
    replace_home_policy(&db, &admin, &home, &shared)
        .await
        .unwrap();
    replace_home_policy(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        &[(&admin, "manage"), (&reader, "view")],
    )
    .await
    .unwrap();
    assert!(crate::store::append(
        &db,
        AppendSpec {
            record_id: a.clone(),
            event_type: REMOVED.into(),
            payload: serde_json::json!({"link_id":link.link_id}),
            actor: Some(reader.clone())
        }
    )
    .await
    .is_err());
    assert!(crate::store::append(
        &db,
        AppendSpec {
            record_id: a,
            event_type: IMPORTED.into(),
            payload: serde_json::to_value(link).unwrap(),
            actor: Some(reader)
        }
    )
    .await
    .is_err());
}

#[tokio::test]
async fn active_triple_upsert_preserves_identity_and_records_note_changes() {
    let (db, admin, host, a, b) = world().await;
    let created = add_generic_link_as(&db, &admin, &a, &b, "part_of", Some("first".into()))
        .await
        .unwrap();
    assert_eq!(created.outcome, GenericLinkOutcome::Created);
    let history = history_as(&db, &admin, &a).await.unwrap();
    let retry = add_generic_link_as(&db, &admin, &a, &b, "part_of", Some("first".into()))
        .await
        .unwrap();
    assert_eq!(retry.outcome, GenericLinkOutcome::Unchanged);
    assert_eq!(retry.link, created.link);
    assert_eq!(history_as(&db, &admin, &a).await.unwrap(), history);
    assert!(
        add_generic_link_as(&db, &host, &a, &b, "part_of", Some("denied".into()))
            .await
            .is_err()
    );
    for kind in [NOTE, IMPORTED_NOTE] {
        assert!(crate::store::append(
            &db,
            AppendSpec {
                record_id: a.clone(),
                event_type: kind.into(),
                actor: Some(host.clone()),
                payload: serde_json::to_value(LinkNote {
                    link_id: created.link.link_id.clone(),
                    note: Some("forged".into())
                })
                .unwrap()
            }
        )
        .await
        .is_err());
    }
    let changed = add_generic_link_as(&db, &admin, &a, &b, "part_of", None)
        .await
        .unwrap();
    assert_eq!(changed.outcome, GenericLinkOutcome::Updated);
    let mut expected = created.link.clone();
    expected.note = None;
    assert_eq!(changed.link, expected);
    assert_eq!(
        history_as(&db, &admin, &a)
            .await
            .unwrap()
            .last()
            .unwrap()
            .event_type,
        NOTE
    );
    // Raw events cannot bypass the active-triple rule.
    let history = history_as(&db, &admin, &a).await.unwrap();
    assert!(crate::store::append(
        &db,
        AppendSpec {
            record_id: a.clone(),
            event_type: ADDED.into(),
            actor: Some(admin.clone()),
            payload: serde_json::to_value(LinkCreation {
                link_id: "duplicate-id".into(),
                source_id: a.clone(),
                target_id: b.clone(),
                relationship: "part_of".into(),
                note: None
            })
            .unwrap()
        }
    )
    .await
    .is_err());
    assert_eq!(history_as(&db, &admin, &a).await.unwrap(), history);
    remove_generic_link_triple_as(&db, &admin, &a, &b, "part_of")
        .await
        .unwrap();
    assert!(generic_links_as(&db, &admin, &a, false, None, None, 10)
        .await
        .unwrap()
        .links
        .is_empty());
    let successor = add_generic_link_as(&db, &admin, &a, &b, "part_of", None)
        .await
        .unwrap();
    assert_ne!(successor.link.link_id, created.link.link_id);
    assert_eq!(
        generic_links_as(&db, &admin, &a, false, None, None, 10)
            .await
            .unwrap()
            .links
            .len(),
        1
    );
    let dump = dump_all_kernel_tables(&db).await.unwrap();
    replay_all_projections(&db).await.unwrap();
    assert_eq!(dump_all_kernel_tables(&db).await.unwrap(), dump);
}

fn imported(id: &str, source: &str, target: &str) -> GenericLink {
    GenericLink {
        link_id: id.into(),
        source_id: source.into(),
        target_id: target.into(),
        relationship: "part_of".into(),
        note: None,
        created_at: "2020-01-02 03:04:05.123".into(),
        actor: Some("author".into()),
    }
}
#[tokio::test]
async fn import_active_identity_conflicts_and_clear_missing_endpoints() {
    let (db, admin, host, a, b) = world().await;
    let original = imported("old-v1-id", &a, &b);
    import_generic_link_as(&db, &host, &original).await.unwrap();
    let successor = imported("successor-v1-id", &a, &b);
    let error = import_generic_link_as(&db, &host, &successor)
        .await
        .unwrap_err();
    assert!(
        matches!(error,Error::Conflict(ref text) if text.contains("old-v1-id") && text.contains("successor-v1-id"))
    );
    remove_generic_link_triple_as(&db, &admin, &a, &b, "part_of")
        .await
        .unwrap();
    import_generic_link_as(&db, &host, &successor)
        .await
        .unwrap();
    let mut changed_original = original.clone();
    changed_original.note = Some("changed note".into());
    assert!(
        matches!(import_generic_link_as(&db,&host,&changed_original).await,Err(Error::Conflict(ref text)) if text.contains("old-v1-id") && text.contains("successor-v1-id"))
    );
    assert_eq!(
        generic_links_as(&db, &admin, &a, false, None, None, 10)
            .await
            .unwrap()
            .links,
        vec![GenericLink {
            actor: Some("v1:author".into()),
            ..successor
        }]
    );
    for (source, target) in [("missing", &b[..]), (&a[..], "missing")] {
        let bad = imported("missing-endpoint", source, target);
        assert!(
            matches!(import_generic_link_as(&db,&host,&bad).await,Err(Error::Engine(ref text)) if text=="link import requires both source and target records to exist")
        );
    }
    let dump = dump_all_kernel_tables(&db).await.unwrap();
    replay_all_projections(&db).await.unwrap();
    assert_eq!(dump_all_kernel_tables(&db).await.unwrap(), dump);
}

#[tokio::test]
async fn identical_import_retry_after_v2_readd_is_unchanged() {
    let (db, admin, host, a, b) = world().await;
    let original = imported("retired-v1-id", &a, &b);
    import_generic_link_as(&db, &host, &original).await.unwrap();
    remove_generic_link_triple_as(&db, &admin, &a, &b, "part_of")
        .await
        .unwrap();
    let successor = add_generic_link_as(&db, &admin, &a, &b, "part_of", None)
        .await
        .unwrap()
        .link;
    assert_ne!(successor.link_id, original.link_id);
    let dump = dump_all_kernel_tables(&db).await.unwrap();
    for replay in [false, true] {
        if replay {
            replay_all_projections(&db).await.unwrap();
        }
        assert_eq!(
            import_generic_link_as(&db, &host, &original).await.unwrap(),
            GenericLinkOutcome::Unchanged
        );
        assert_eq!(dump_all_kernel_tables(&db).await.unwrap(), dump);
        assert_eq!(
            generic_links_as(&db, &admin, &a, false, Some("part_of"), None, 10)
                .await
                .unwrap()
                .links,
            vec![successor.clone()]
        );
    }
}

#[tokio::test]
async fn link_timestamps_and_reserved_surface_binding() {
    let (db, admin, host, a, b) = world().await;
    for (i, time) in [
        "2020-01-02T03:04:05Z",
        "2020-01-02 03:04:05",
        "2020-01-02 03:04:05.123",
        "2020-01-02T03:04:05",
        "2020-01-02T03:04:05+08:00",
        "Thu, 2 Jan 2020 03:04:05 +0000",
        "2020-01-02",
    ]
    .iter()
    .enumerate()
    {
        let mut link = imported(&format!("timestamp-{i}"), &a, &b);
        link.created_at = (*time).into();
        link.relationship = format!("timestamp-{i}");
        import_generic_link_as(&db, &host, &link).await.unwrap();
        let links = generic_links_as(&db, &admin, &a, false, Some(&link.relationship), None, 10)
            .await
            .unwrap()
            .links;
        assert_eq!(links[0].created_at, *time);
    }
    let mut bad = imported("unparseable", &a, &b);
    bad.created_at = "no such timestamp".into();
    assert!(import_generic_link_as(&db, &host, &bad).await.is_err());
    let reserved = crate::surface_binding::SURFACE_BINDING_RELATIONSHIP;
    assert!(add_generic_link_as(&db, &admin, &a, &b, reserved, None)
        .await
        .is_err());
    bad.created_at = "2020-01-02".into();
    bad.relationship = reserved.into();
    assert!(import_generic_link_as(&db, &host, &bad).await.is_err());
    assert!(crate::store::append(
        &db,
        AppendSpec {
            record_id: a.clone(),
            event_type: ADDED.into(),
            actor: Some(admin),
            payload: serde_json::to_value(LinkCreation {
                link_id: "reserved".into(),
                source_id: a,
                target_id: b,
                relationship: reserved.into(),
                note: None
            })
            .unwrap()
        }
    )
    .await
    .is_err());
}

#[tokio::test]
async fn hidden_rows_straddle_both_direction_page_boundaries() {
    let (db, admin, host, a, b) = world().await;
    let reader = create_principal(&db, "account", "Reader", "acct:reader", &admin)
        .await
        .unwrap();
    replace_home_policy(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        &[(&admin, "manage"), (&reader, "view")],
    )
    .await
    .unwrap();
    let home = create_home(&db, KERNEL_ROOT_ID, Some(&[(&admin, "manage")]), &admin)
        .await
        .unwrap();
    let hidden = create_record_as(&db, &admin, &home).await.unwrap();
    // Ordered identities force three hidden rows between visible hits, and
    // another three after the last visible hit. Page limit is only one.
    for incoming in [false, true] {
        for (i, other) in [&b, &hidden, &hidden, &hidden, &b, &hidden, &hidden, &hidden]
            .iter()
            .enumerate()
        {
            let (source, target) = if incoming { (*other, &a) } else { (&a, *other) };
            let mut link = imported(
                &format!("{}-{i}", if incoming { "in" } else { "out" }),
                source,
                target,
            );
            // Distinct relationships allow multiple hidden links to one endpoint.
            link.relationship = format!("relation-{i}");
            import_generic_link_as(&db, &host, &link).await.unwrap();
        }
        let first = generic_links_as(&db, &reader, &a, incoming, None, None, 1)
            .await
            .unwrap();
        assert_eq!(first.links.len(), 1);
        assert!(first.links[0].link_id.ends_with("-0"));
        let second = generic_links_as(&db, &reader, &a, incoming, None, first.next.as_deref(), 1)
            .await
            .unwrap();
        assert_eq!(second.links.len(), 1);
        assert!(second.links[0].link_id.ends_with("-4"));
        assert!(second.next.is_none());
    }
}

#[tokio::test]
async fn self_links_follow_v1_upsert_and_triple_removal() {
    let (db, admin, host, a, _) = world().await;
    let first = add_generic_link_as(&db, &admin, &a, &a, "references", None)
        .await
        .unwrap();
    let update = add_generic_link_as(&db, &admin, &a, &a, "references", Some("self".into()))
        .await
        .unwrap();
    assert_eq!(update.link.link_id, first.link.link_id);
    assert_eq!(update.outcome, GenericLinkOutcome::Updated);
    for incoming in [false, true] {
        assert_eq!(
            generic_links_as(&db, &admin, &a, incoming, None, None, 10)
                .await
                .unwrap()
                .links,
            vec![update.link.clone()]
        );
    }
    remove_generic_link_triple_as(&db, &admin, &a, &a, "references")
        .await
        .unwrap();
    let link = imported("self-import", &a, &a);
    import_generic_link_as(&db, &host, &link).await.unwrap();
    let dump = dump_all_kernel_tables(&db).await.unwrap();
    replay_all_projections(&db).await.unwrap();
    assert_eq!(dump_all_kernel_tables(&db).await.unwrap(), dump);
}

#[tokio::test]
async fn anchored_link_read_plans_use_both_endpoint_indexes_and_upgrade_old_databases() {
    let (db, admin, _, a, _) = world().await;
    // Simulate a pre-review probe database, then exercise the ordinary open upgrade.
    for index in [
        "idx_kernel_links_target",
        "idx_kernel_provider_subjects_aggregate",
    ] {
        sqlx::query(&format!("DROP INDEX {index}"))
            .execute(db.write_pool())
            .await
            .unwrap();
    }
    ensure_link_read_indexes(&db).await.unwrap();
    ensure_link_read_indexes(&db).await.unwrap();
    let plan: Vec<(i64, i64, i64, String)> = sqlx::query_as(&format!(
        "EXPLAIN QUERY PLAN {}",
        visible_generic_links_sql()
    ))
    .bind(serde_json::json!([{"id": KERNEL_ROOT_ID, "view": true}]).to_string())
    .bind(&admin)
    .bind(&a)
    .fetch_all(db.pool())
    .await
    .unwrap();
    // SQLite may prefer the active-triple index to source_page. Require an
    // indexed equality search in each direction without forcing a named index.
    for endpoint in ["source_id", "target_id"] {
        assert!(
            plan.iter().any(|row| row.3.contains("SEARCH")
                && row.3.contains("idx_kernel_generic_links_")
                && row.3.contains(&format!("({endpoint}=?"))),
            "{plan:?}"
        );
    }
    for (sql, index) in [
        (
            "SELECT * FROM kernel_links WHERE target_id=?",
            "idx_kernel_links_target",
        ),
        (
            "SELECT * FROM kernel_provider_subjects WHERE aggregate_id=?",
            "idx_kernel_provider_subjects_aggregate",
        ),
    ] {
        let plan: Vec<(i64, i64, i64, String)> =
            sqlx::query_as(&format!("EXPLAIN QUERY PLAN {sql}"))
                .bind(&a)
                .fetch_all(db.pool())
                .await
                .unwrap();
        assert!(
            plan.iter()
                .any(|row| row.3.contains("SEARCH") && row.3.contains(index)),
            "{plan:?}"
        );
    }
    db.close().await;
}
