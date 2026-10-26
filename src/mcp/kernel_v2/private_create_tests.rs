use super::*;

#[tokio::test]
async fn kernel_v2_private_create_matches_v1_account_only_and_declared_none() {
    use crate::identity::hosted::{
        reconcile_hosted_identity, HostedMembershipArrival, HostedMembershipRole,
        HostedMembershipSource,
    };
    let (w, home) = fixture().await;
    let v1 = crate::create_database(":memory:").await.unwrap();
    let mut accounts = Vec::new();
    for (label, role) in [
        ("a", HostedMembershipRole::Owner),
        ("b", HostedMembershipRole::Member),
    ] {
        accounts.push(
            reconcile_hosted_identity(
                &v1,
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
    let args = json!({"type":"Document","kind":"note","name":"Private parity","body":"Private parity body",
        "access_policy":"account_only","sources":[],"reason":"personal state"});
    let expected = registry()
        .call(
            v1.clone(),
            Caller::authenticated(&accounts[0]),
            "create_record",
            args.clone(),
        )
        .await
        .unwrap();
    let mut actual_args = args.clone();
    actual_args["home_id"] = json!(home);
    let actual = call(&w, "create_record", actual_args).await.unwrap();
    assert_eq!(actual["basis"], expected["basis"]);
    for (db, engine, owner, other, id) in [
        (
            v1.clone(),
            false,
            accounts[0].as_str(),
            accounts[1].as_str(),
            expected["id"].as_str().unwrap(),
        ),
        (
            w.db.clone(),
            true,
            "acct:viewer",
            "acct:admin",
            actual["id"].as_str().unwrap(),
        ),
    ] {
        let handle = if engine {
            EngineHandle::KernelV2(db.clone())
        } else {
            EngineHandle::Sqlite(db.clone())
        };
        let mut destination_args = json!({"type":"Collection","kind":"folder","name":"Private move destination","reason":"move parity"});
        if engine {
            destination_args["home_id"] = json!(home);
        }
        let destination = registry()
            .call_engine(
                handle.clone(),
                Caller::authenticated(owner),
                "create_record",
                destination_args,
            )
            .await
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned();
        registry()
            .call_engine(
                handle,
                Caller::authenticated(owner),
                "update_record",
                json!({"id":id,"home_id":destination,"reason":"move keeps explicit policy"}),
            )
            .await
            .unwrap();
        for (credential, hidden) in [(owner, false), (other, true)] {
            let handle = if engine {
                EngineHandle::KernelV2(db.clone())
            } else {
                EngineHandle::Sqlite(db.clone())
            };
            let get = registry()
                .call_engine(
                    handle,
                    Caller::authenticated(credential),
                    "get_record",
                    json!({"ids":[id]}),
                )
                .await
                .unwrap();
            assert_eq!(get["records"][0]["status"] == "not_found", hidden, "{get}");
            if !hidden {
                assert_eq!(get["records"][0]["home_id"], destination);
            }
        }
    }
    v1.close().await;
    w.db.close().await;
}

async fn fixture() -> (World, String) {
    let w = world().await;
    install_comment_carrier(&w).await;
    for package in [
        crate::v2_standard::document4_package(),
        crate::v2_standard::relates_to::package(),
    ] {
        let identity = kernel::install_package_as(&w.db, &w.admin, &package)
            .await
            .unwrap();
        kernel::adopt_package_at(
            &w.db,
            &w.admin,
            KERNEL_ROOT_ID,
            &package,
            Some(&identity),
            &package.declared_reads,
        )
        .await
        .unwrap();
    }

    let home = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        &home,
        &[(&w.admin, "manage"), (&w.viewer, "edit")],
    )
    .await
    .unwrap();
    (w, home)
}

#[tokio::test]
async fn kernel_v2_private_create_is_atomic_private_filed_and_replayable() {
    let (w, home) = fixture().await;
    let args = json!({"type":"Document","kind":"note","name":"private canary","body":"privatecanary",
        "home_id":home,"access_policy":"account_only","sources":[],"idempotency_key":"private-note","reason":"personal state"});
    let created = call(&w, "create_record", args.clone()).await.unwrap();
    let id = created["id"].as_str().unwrap();
    assert_eq!(
        created["basis"],
        json!({"status":"declared_none","source_count":0,"message":"basis: declared as none"})
    );
    for credential in ["acct:viewer", "acct:admin"] {
        let own = credential == "acct:viewer";
        let get = call_as(&w, credential, "get_record", json!({"ids":[id]}))
            .await
            .unwrap();
        assert_eq!(get["records"][0]["status"] == "not_found", !own);
        if own {
            assert_eq!(get["records"][0]["home_id"], home);
        }
        let sql = call_as(&w,credential,"query_sql",json!({"sql":"SELECT id,home_id FROM records WHERE id=?1","parameters":[{"type":"text","value":id}]})).await.unwrap();
        assert_eq!(sql["rows"].as_array().unwrap().len(), usize::from(own));
        if own {
            assert_eq!(sql["rows"][0]["home_id"], home);
        }
        let search = call_as(&w, credential, "search", json!({"query":"privatecanary"}))
            .await
            .unwrap();
        assert_eq!(search.to_string().contains(id), own);
    }
    // A visible record's link to private state cannot disclose the endpoint.
    let ordinary = call(
        &w,
        "create_record",
        json!({"type":"Document","kind":"note","name":"ordinary","home_id":home,
        "links":[{"target_id":id,"relationship":"relates_to"}]}),
    )
    .await
    .unwrap();
    let visible = call_as(
        &w,
        "acct:admin",
        "get_record",
        json!({"ids":[ordinary["id"]]}),
    )
    .await
    .unwrap();
    assert_ne!(visible["records"][0]["status"], "not_found");
    assert!(!visible.to_string().contains(id));
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    assert_eq!(
        created,
        call(&w, "create_record", args.clone()).await.unwrap()
    );
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    assert_eq!(
        created,
        call(&w, "create_record", args.clone()).await.unwrap()
    );
    let stored: String = sqlx::query_scalar("SELECT json_extract(payload,'$.basis') FROM content_events WHERE record_id=? AND type='kernel.record_created.v1'")
        .bind(id).fetch_one(w.db.pool()).await.unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&stored).unwrap(),
        json!({"format":"native.source-basis.v1","sources":[]})
    );
    // The viewer owns this note but has no root Edit. That refusal is
    // destination authority, not a ban on moving an explicit-policy note.
    let before_refused_move = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    call(
        &w,
        "update_record",
        json!({"id":id,"home_id":KERNEL_ROOT_ID}),
    )
    .await
    .unwrap_err();
    assert_eq!(
        before_refused_move,
        kernel::dump_all_kernel_tables(&w.db).await.unwrap()
    );
    let destination = call(&w,"create_record",json!({"type":"Collection","kind":"folder","name":"Shared move destination","home_id":home})).await.unwrap()["id"].as_str().unwrap().to_owned();
    let private_home: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
        .bind(id)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let policy: Vec<(String,String,String)> = sqlx::query_as("SELECT subject_kind,subject_id,capability FROM kernel_policy_entries WHERE root_id=? ORDER BY subject_kind,subject_id,capability").bind(&private_home).fetch_all(w.db.pool()).await.unwrap();
    let comment = call(&w,"create_record",json!({"type":"Annotation","kind":"comment","body":"private comment canary","links":[{"target_id":id,"relationship":"part_of"}]})).await.unwrap()["id"].as_str().unwrap().to_owned();
    for target in [&destination, &home] {
        call(
            &w,
            "update_record",
            json!({"id":id,"home_id":target,"reason":"private filing move"}),
        )
        .await
        .unwrap();
        let stored_home: String =
            sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
                .bind(id)
                .fetch_one(w.db.pool())
                .await
                .unwrap();
        assert_eq!(stored_home, private_home);
        let after_policy: Vec<(String,String,String)> = sqlx::query_as("SELECT subject_kind,subject_id,capability FROM kernel_policy_entries WHERE root_id=? ORDER BY subject_kind,subject_id,capability").bind(&private_home).fetch_all(w.db.pool()).await.unwrap();
        assert_eq!(policy, after_policy);
        for credential in ["acct:viewer", "acct:admin"] {
            let own = credential == "acct:viewer";
            let get = call_as(&w, credential, "get_record", json!({"ids":[id,comment]}))
                .await
                .unwrap();
            for record in get["records"].as_array().unwrap() {
                assert_eq!(record["status"] == "not_found", !own);
                if own {
                    assert_eq!(record["home_id"], *target);
                }
            }
            let sql=call_as(&w,credential,"query_sql",json!({"sql":"SELECT id,home_id FROM records WHERE id=?1 OR id=?2","parameters":[{"type":"text","value":id},{"type":"text","value":comment}]})).await.unwrap();
            assert_eq!(
                sql["rows"].as_array().unwrap().len(),
                if own { 2 } else { 0 }
            );
            if own {
                for row in sql["rows"].as_array().unwrap() {
                    assert_eq!(row["home_id"], *target);
                }
            }
            let search = call_as(&w, credential, "search", json!({"query":"privatecanary"}))
                .await
                .unwrap();
            assert_eq!(search.to_string().contains(id), own);
        }
        let visible = call_as(
            &w,
            "acct:admin",
            "get_record",
            json!({"ids":[ordinary["id"]]}),
        )
        .await
        .unwrap();
        assert!(!visible.to_string().contains(id));
    }
    // Neither exact-id history nor guessed event ids disclose private content.
    let history = call(&w, "get_history", json!({"record_id":id}))
        .await
        .unwrap();
    assert!(!history["events"].as_array().unwrap().is_empty());
    let denied = call_as(&w, "acct:admin", "get_history", json!({"record_id":id}))
        .await
        .unwrap_err();
    assert_eq!(
        denied.to_string(),
        Error::engine(format!("get_history: record {id} does not exist")).to_string()
    );
    for event in history["events"].as_array().unwrap() {
        let event_id = event["id"].as_str().unwrap();
        let denied = call_as(
            &w,
            "acct:admin",
            "get_event_context",
            json!({"event_id":event_id}),
        )
        .await
        .unwrap_err();
        assert_eq!(
            denied.to_string(),
            Error::engine(format!(
                "get_event_context: event {event_id} does not exist"
            ))
            .to_string()
        );
    }
    let global = call_as(&w, "acct:admin", "get_history", json!({"limit":1000}))
        .await
        .unwrap();
    for secret in [
        id,
        comment.as_str(),
        "privatecanary",
        "private comment canary",
    ] {
        assert!(!global.to_string().contains(secret));
    }
    let before_replay = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(
        before_replay,
        kernel::dump_all_kernel_tables(&w.db).await.unwrap()
    );
    let mut changed = args;
    changed["body"] = json!("different");
    assert!(matches!(
        call(&w, "create_record", changed).await,
        Err(Error::Conflict(_))
    ));
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_private_folder_keeps_children_private_and_can_move() {
    let (w, home) = fixture().await;
    let folder=call(&w,"create_record",json!({"type":"Collection","kind":"folder","name":"Personal","home_id":home,"access_policy":"account_only"})).await.unwrap()["id"].as_str().unwrap().to_owned();
    let child = call(
        &w,
        "create_record",
        json!({"type":"Document","kind":"note","name":"Personal child","home_id":folder}),
    )
    .await
    .unwrap()["id"]
        .clone();
    call(&w, "update_record", json!({"id":folder,"home_id":home}))
        .await
        .unwrap();
    let get = call_as(
        &w,
        "acct:admin",
        "get_record",
        json!({"ids":[folder,child]}),
    )
    .await
    .unwrap();
    assert!(get["records"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["status"] == "not_found"));
    assert_eq!(
        call(&w, "get_record", json!({"ids":[child]}))
            .await
            .unwrap()["records"][0]["home_id"],
        folder
    );
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_create_source_basis_keeps_real_revisions_and_v1_shape() {
    let (w, home) = fixture().await;
    let revision: String = sqlx::query_scalar(
        "SELECT id FROM content_events WHERE record_id=? AND type='kernel.record_created.v1'",
    )
    .bind(&w.first)
    .fetch_one(w.db.pool())
    .await
    .unwrap();
    let args = json!({"type":"Document","kind":"note","name":"Cited","home_id":home,"sources":[{"record_id":w.first,"reason":"read earlier revision","role":"context","revision_event_id":revision},w.second]});
    let receipt = call(&w, "create_record", args).await.unwrap();
    assert_eq!(
        receipt["basis"],
        json!({"status":"declared","source_count":2,"message":"basis: 2 sources recorded"})
    );
    let basis: String=sqlx::query_scalar("SELECT json_extract(payload,'$.basis') FROM content_events WHERE record_id=? AND type='kernel.record_created.v1'")
        .bind(receipt["id"].as_str().unwrap()).fetch_one(w.db.pool()).await.unwrap();
    let basis: Value = serde_json::from_str(&basis).unwrap();
    assert_eq!(
        basis["sources"][0],
        json!({"ordinal":0,"record_id":w.first,"revision_event_id":revision,"revision_supplied_by":"caller","role":"context","reason":"read earlier revision"})
    );
    assert_eq!(basis["sources"][1]["revision_supplied_by"], "engine");
    let event: String = sqlx::query_scalar(
        "SELECT id FROM content_events WHERE record_id=? AND type='kernel.record_created.v1'",
    )
    .bind(receipt["id"].as_str().unwrap())
    .fetch_one(w.db.pool())
    .await
    .unwrap();
    let context = call(&w, "get_event_context", json!({"event_id":event}))
        .await
        .unwrap();
    assert!(context.to_string().contains(&revision));
    // Later revocation redacts evidence too, including raw event payload and
    // revision identities. The cited record is not a capability grant.
    kernel::replace_home_policy(&w.db, &w.admin, &home, &[])
        .await
        .unwrap();
    // The created evidence record retains its own owner floor.
    let redacted = call(&w, "get_event_context", json!({"event_id":event}))
        .await
        .unwrap();
    assert!(!redacted.to_string().contains(&revision));
    assert!(!redacted.to_string().contains(&w.first));
    assert!(!redacted.to_string().contains("read earlier revision"));
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_private_create_and_sources_refuse_without_any_partial_act() {
    let (w, home) = fixture().await;
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    for patch in [
        json!({"access_policy":"workspace"}),
        json!({"access_policy":true}),
        json!({"sources":null}),
        json!({"sources":"not an array"}),
        json!({"sources":[w.hidden]}),
        json!({"sources":[w.first,w.first]}),
        json!({"sources":[{"record_id":w.first,"reason":" "}]}),
        json!({"sources":[{"record_id":w.first,"reason":"read","revision_event_id":"missing"}]}),
        json!({"type":"Annotation","kind":"comment","access_policy":"account_only","links":[{"relationship":"part_of","target_id":w.first}]}),
        json!({"home_id":w.hidden,"access_policy":"account_only"}),
    ] {
        let mut args = json!({"type":"Document","kind":"note","name":"must roll back","home_id":home,"access_policy":"account_only"});
        args.as_object_mut()
            .unwrap()
            .extend(patch.as_object().unwrap().clone());
        assert!(
            call(&w, "create_record", args.clone()).await.is_err(),
            "{args}"
        );
        assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    }
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_workspace_snapshot_self_policy_rehome_keeps_fence_and_visibility() {
    let (w, home) = fixture().await;
    let id = call(&w, "create_record", json!({"type":"Document","kind":"note","name":"Private filing","home_id":home,"access_policy":"account_only","reason":"self-policy snapshot proof"})).await.unwrap()["id"].as_str().unwrap().to_owned();
    let destination = call(&w, "create_record", json!({"type":"Collection","kind":"folder","name":"New filing","home_id":home,"reason":"self-policy snapshot proof"})).await.unwrap()["id"].as_str().unwrap().to_owned();
    let self_home = kernel::read_record_as(&w.db, &w.viewer, &id)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let mut pins = Vec::new();
    for (credential, actor, visible) in [
        ("acct:viewer", &w.viewer, true),
        ("acct:admin", &w.admin, false),
    ] {
        assert_eq!(
            kernel::read_record_as(&w.db, actor, &id)
                .await
                .unwrap()
                .is_some(),
            visible
        );
        let opened = call_as(
            &w,
            credential,
            "get_workspace_snapshot",
            json!({"action":"open"}),
        )
        .await
        .unwrap();
        assert!(opened["snapshot_token"].is_string(), "{opened}");
        pins.push((credential, actor, visible, opened));
    }
    let before = {
        let mut conn = w.db.pool().acquire().await.unwrap();
        super::workspace_snapshot::fences_on(&mut conn)
            .await
            .unwrap()
    };
    call(
        &w,
        "update_record",
        json!({"id":id,"home_id":destination,"reason":"refile without changing access"}),
    )
    .await
    .unwrap();
    let (event_type, physical_home): (String, String) = sqlx::query_as("SELECT type,json_extract(payload,'$.new_home_id') FROM content_events WHERE record_id=? AND type LIKE 'kernel.record_rehomed.%' ORDER BY seq DESC LIMIT 1").bind(&id).fetch_one(w.db.pool()).await.unwrap();
    assert_eq!(event_type, "kernel.record_rehomed.v2");
    assert_eq!(
        physical_home, self_home,
        "re-filing keeps the record's own policy home"
    );
    let after = {
        let mut conn = w.db.pool().acquire().await.unwrap();
        super::workspace_snapshot::fences_on(&mut conn)
            .await
            .unwrap()
    };
    assert_eq!(
        after, before,
        "self-policy rehome does not change authority"
    );
    for (credential, actor, visible, opened) in pins {
        assert_eq!(
            kernel::read_record_as(&w.db, actor, &id)
                .await
                .unwrap()
                .is_some(),
            visible
        );
        let page = call_as(&w, credential, "get_workspace_snapshot", json!({"action":"page","snapshot_token":opened["snapshot_token"],"section":"records","limit":1000})).await.unwrap();
        assert!(page["rows"].is_array(), "{page}");
        assert_eq!(
            page["rows"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["id"] == id),
            visible
        );
        let delta = call_as(
            &w,
            credential,
            "get_workspace_snapshot",
            json!({"action":"catch_up","snapshot_token":opened["snapshot_token"]}),
        )
        .await
        .unwrap();
        assert!(delta["upsert_records"].is_array(), "{delta}");
        assert_eq!(delta["authorization_epoch"], opened["authorization_epoch"]);
        assert_eq!(
            delta["upsert_records"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["id"] == id),
            visible
        );
        if !visible {
            assert!(!delta.to_string().contains(&id));
        }
    }
    w.db.close().await;
}
