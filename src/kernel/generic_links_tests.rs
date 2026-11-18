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
    for (candidate, sql) in [
        (false, visible_generic_links_sql()),
        (true, visible_generic_links_candidate_sql()),
    ] {
        let plan: Vec<(i64, i64, i64, String)> =
            sqlx::query_as(&format!("EXPLAIN QUERY PLAN {sql}"))
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
        assert!(
            plan.iter()
                .any(|row| row.3.starts_with("SEARCH r ") && row.3.contains("(id=?)")),
            "{plan:?}"
        );
        assert!(
            !plan
                .iter()
                .any(|row| row.3 == "SCAN r" || row.3.starts_with("SCAN r ")),
            "visibility must not scan every record: {plan:?}"
        );
        if candidate {
            assert!(
                plan.iter().any(|row| row.3 == "MATERIALIZE candidates"),
                "{plan:?}"
            );
        }
        assert!(
            !plan.iter().any(|row| matches!(
                row.3.as_str(),
                "MATERIALIZE visible" | "MATERIALIZE endpoints"
            )),
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

async fn paired_endpoint_visibility(
    db: &Db,
    principal: &str,
    anchors: &[String],
    batch: bool,
) -> Vec<GenericLink> {
    let mut tx = db.pool().begin().await.unwrap();
    let scope = visible_home_anchors_as(&mut tx, principal).await.unwrap();
    let homes = serde_json::to_string(
        &scope
            .homes
            .into_iter()
            .filter(|h| h.policy_valid)
            .map(|h| serde_json::json!({"id":h.home_id,"view":h.policy_view}))
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let argument = if batch {
        serde_json::to_string(anchors).unwrap()
    } else {
        anchors[0].clone()
    };
    let mut results = Vec::new();
    for mut sql in [
        visible_generic_links_sql(),
        visible_generic_links_candidate_sql(),
    ] {
        if batch {
            sql = sql
                .replace(
                    "source_id<>?3",
                    "source_id NOT IN (SELECT value FROM json_each(?3))",
                )
                .replace(
                    "source_id=?3",
                    "source_id IN (SELECT value FROM json_each(?3))",
                )
                .replace(
                    "target_id=?3",
                    "target_id IN (SELECT value FROM json_each(?3))",
                );
        }
        let mut links: Vec<GenericLink> = sqlx::query_as(&sql)
            .bind(&homes)
            .bind(principal)
            .bind(&argument)
            .fetch_all(&mut *tx)
            .await
            .unwrap();
        links.sort_by(|a, b| a.link_id.cmp(&b.link_id));
        results.push(links);
    }
    assert_eq!(
        results[0], results[1],
        "principal={principal}, anchors={anchors:?}, batch={batch}"
    );
    tx.rollback().await.unwrap();
    results.pop().unwrap()
}

#[tokio::test]
async fn bounded_generic_visibility_preserves_off_candidate_bearers_and_endpoint_gates() {
    let (db, admin, _, anchor, ordinary) = Box::pin(world()).await;
    let reader = create_principal(&db, "account", "Reader", "bounded:reader", &admin)
        .await
        .unwrap();
    let outsider = create_principal(&db, "account", "Outsider", "bounded:outsider", &admin)
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
    let private = create_home(&db, KERNEL_ROOT_ID, Some(&[(&admin, "manage")]), &admin)
        .await
        .unwrap();
    let mut records = std::collections::BTreeMap::new();
    for (name, home) in [
        ("private", private.as_str()),
        ("owner-floor", private.as_str()),
        ("terminal-visible", KERNEL_ROOT_ID),
        ("terminal-floor", private.as_str()),
        ("terminal-private", private.as_str()),
        ("terminal-dead", KERNEL_ROOT_ID),
        ("comment", KERNEL_ROOT_ID),
        ("attachment", KERNEL_ROOT_ID),
        ("hidden-bearer", KERNEL_ROOT_ID),
        ("tombstone-bearer", KERNEL_ROOT_ID),
        ("message-visible", KERNEL_ROOT_ID),
        ("message-private", private.as_str()),
        ("message-unsealed", KERNEL_ROOT_ID),
        ("unsealed-bearer", KERNEL_ROOT_ID),
        ("tombstone", KERNEL_ROOT_ID),
        ("missing-bearer", KERNEL_ROOT_ID),
        ("duplicate-bearer", KERNEL_ROOT_ID),
        ("cycle-a", KERNEL_ROOT_ID),
        ("cycle-b", KERNEL_ROOT_ID),
    ] {
        records.insert(
            name,
            Box::pin(create_record_as(&db, &admin, home)).await.unwrap(),
        );
    }
    // Disposable imported-carrier projections exercise the exact serving gate,
    // including invalid/orphan states that canonical writes correctly refuse.
    // This fixture makes no importer or replay qualification claim.
    let mut fixture = db.write_pool().acquire().await.unwrap();
    let pin = crate::v2_standard::v1_compat::package().definitions[0]
        .digest
        .clone();
    for (name, typ, kind) in [
        ("comment", "Annotation", "comment"),
        ("attachment", "Document", "attachment"),
        ("hidden-bearer", "Annotation", "comment"),
        ("tombstone-bearer", "Document", "attachment"),
        ("unsealed-bearer", "Annotation", "comment"),
        ("missing-bearer", "Annotation", "comment"),
        ("duplicate-bearer", "Annotation", "comment"),
        ("cycle-a", "Annotation", "comment"),
        ("cycle-b", "Annotation", "comment"),
        ("message-visible", "Message", "text"),
        ("message-private", "Message", "text"),
        ("message-unsealed", "Message", "text"),
    ] {
        let id = &records[name];
        sqlx::query("UPDATE kernel_records SET primary_type='V1',kind='record',accession=id,pin_family='native.v1.record',pin_version=1,pin_digest=?,interpreter='native.defn/5' WHERE id=?")
            .bind(&pin).bind(id).execute(&mut *fixture).await.unwrap();
        for (field, value) in [("v1_type", typ), ("v1_kind", kind)] {
            sqlx::query("INSERT INTO kernel_record_fields SELECT id,?,json_quote(?),created_seq FROM kernel_records WHERE id=?")
                .bind(field).bind(value).bind(id).execute(&mut *fixture).await.unwrap();
        }
    }
    for name in [
        "owner-floor",
        "terminal-floor",
        "hidden-bearer",
        "missing-bearer",
    ] {
        sqlx::query("UPDATE kernel_records SET owner_id=? WHERE id=?")
            .bind(&reader)
            .bind(&records[name])
            .execute(&mut *fixture)
            .await
            .unwrap();
    }
    for (name, audience) in [("message-visible", &admin), ("message-private", &reader)] {
        let state = MessageState {
            audience: std::collections::BTreeMap::from([(audience.clone(), "to".into())]),
            author: Some(admin.clone()),
            ..Default::default()
        };
        sqlx::query(
            "INSERT INTO kernel_messages SELECT id,?,created_seq FROM kernel_records WHERE id=?",
        )
        .bind(serde_json::to_string(&state).unwrap())
        .bind(&records[name])
        .execute(&mut *fixture)
        .await
        .unwrap();
    }
    // Foreign-key-off is restricted to this disposable fixture connection, so
    // principal-only and absent generic targets can be checked explicitly.
    sqlx::query("PRAGMA foreign_keys=OFF")
        .execute(&mut *fixture)
        .await
        .unwrap();
    let mut links = vec![
        ("basic", anchor.as_str(), ordinary.as_str(), "references", 1),
        (
            "incoming",
            ordinary.as_str(),
            anchor.as_str(),
            "references",
            1,
        ),
        ("self", anchor.as_str(), anchor.as_str(), "references", 1),
        (
            "inactive",
            anchor.as_str(),
            ordinary.as_str(),
            "inactive",
            0,
        ),
        (
            "principal",
            anchor.as_str(),
            reader.as_str(),
            "references",
            1,
        ),
        (
            "missing",
            anchor.as_str(),
            "bounded:missing-record",
            "references",
            1,
        ),
    ];
    for name in [
        "private",
        "owner-floor",
        "comment",
        "attachment",
        "hidden-bearer",
        "tombstone-bearer",
        "message-visible",
        "message-private",
        "unsealed-bearer",
        "tombstone",
        "missing-bearer",
        "duplicate-bearer",
        "cycle-a",
    ] {
        links.push((
            name,
            anchor.as_str(),
            records[name].as_str(),
            "references",
            1,
        ));
    }
    for (name, source, target) in [
        ("bearer-comment", "comment", "terminal-visible"),
        ("bearer-attachment", "attachment", "terminal-floor"),
        ("bearer-hidden", "hidden-bearer", "terminal-private"),
        ("bearer-tombstoned", "tombstone-bearer", "terminal-dead"),
        ("bearer-unsealed", "unsealed-bearer", "message-unsealed"),
        ("bearer-duplicate-a", "duplicate-bearer", "terminal-visible"),
        ("bearer-duplicate-b", "duplicate-bearer", "terminal-floor"),
        ("bearer-cycle-a", "cycle-a", "cycle-b"),
        ("bearer-cycle-b", "cycle-b", "cycle-a"),
    ] {
        links.push((
            name,
            records[source].as_str(),
            records[target].as_str(),
            "part_of",
            1,
        ));
    }
    for (id, source, target, relationship, active) in links {
        sqlx::query(
            "INSERT INTO kernel_generic_links VALUES(?,?,?,?,?,'2026-11-09T00:00:00Z',?,?,1,1)",
        )
        .bind(id)
        .bind(source)
        .bind(target)
        .bind(relationship)
        .bind(format!("retained note {id}"))
        .bind(&admin)
        .bind(active)
        .execute(&mut *fixture)
        .await
        .unwrap();
    }
    sqlx::query("PRAGMA foreign_keys=ON")
        .execute(&mut *fixture)
        .await
        .unwrap();
    for name in ["tombstone", "terminal-dead"] {
        sqlx::query("INSERT INTO kernel_import_tombstones SELECT id,'2026-11-09',created_seq FROM kernel_records WHERE id=?")
            .bind(&records[name]).execute(&mut *fixture).await.unwrap();
    }
    drop(fixture);
    for name in [
        "terminal-visible",
        "terminal-floor",
        "terminal-private",
        "terminal-dead",
        "message-unsealed",
    ] {
        let incident: i64 = sqlx::query_scalar("SELECT count(*) FROM kernel_generic_links WHERE active=1 AND ((source_id=?1 AND target_id=?2) OR (target_id=?1 AND source_id=?2))")
            .bind(&anchor).bind(&records[name]).fetch_one(db.pool()).await.unwrap();
        assert_eq!(
            incident, 0,
            "bearer {name} must be outside endpoint candidates"
        );
    }
    for (actor, extra) in [
        (&reader, vec![]),
        (&admin, vec!["private", "hidden-bearer", "message-private"]),
        (&outsider, vec![]),
    ] {
        let mut expected = if actor == &outsider {
            vec![]
        } else {
            vec![
                "basic",
                "incoming",
                "self",
                "owner-floor",
                "comment",
                "attachment",
                "message-visible",
            ]
        };
        expected.extend(extra);
        expected.sort_unstable();
        for batch in [false, true] {
            let anchors = if batch {
                vec![
                    anchor.clone(),
                    anchor.clone(),
                    ordinary.clone(),
                    "bounded:missing-anchor".into(),
                ]
            } else {
                vec![anchor.clone()]
            };
            let actual = paired_endpoint_visibility(&db, actor, &anchors, batch).await;
            assert_eq!(
                actual
                    .iter()
                    .map(|link| link.link_id.as_str())
                    .collect::<Vec<_>>(),
                expected,
                "actor={actor},batch={batch}"
            );
        }
        for absent in [
            "bounded:missing-anchor".to_owned(),
            records["tombstone"].clone(),
        ] {
            assert!(paired_endpoint_visibility(&db, actor, &[absent], false)
                .await
                .is_empty());
        }
    }
    db.close().await;
}
