use super::*;
const TOOL: &str = "manage_account_config";
const KIND: &str = "focus_preferences";
const APPROVED: &str = include_str!("../tools/account_config/preferences-shape.json");

async fn install(f: &Fixture) {
    let id = crate::meta::propose_value_with_kind_metadata_as(
        &f.source,
        "kind:Configuration",
        KIND,
        None,
        0.0,
        crate::meta::VocabularyValueTerminality::Open,
        Some(crate::meta::KindMetadataV1::legacy("Configuration", KIND)),
        None,
    )
    .await
    .unwrap();
    crate::meta::promote_value(&f.source, &id).await.unwrap();
    crate::meta::write_user_schema_config(&f.source,json!({"shapes":{"Configuration:focus_preferences":{"facets":{"focus.preferences":serde_json::from_str::<Value>(APPROVED).unwrap()}}}}),crate::meta::SchemaConfigOptions::default()).await.unwrap();
    registry().call(f.source.clone(),Caller::local(),"manage_record_policy",json!({"action":"set_members_baseline","record_id":crate::schema::UNFILED_RECORD_ID,"capability":"edit","reason":"synthetic members may file private preferences"})).await.unwrap();
}
async fn resume(f: &Fixture) -> crate::v1_import::Report {
    let report = crate::v1_import::run(crate::v1_import::Options {
        source: f._dir.path().join("source.db"),
        target: f.target.clone(),
        seeds: vec![],
        all: true,
        history: true,
        resume: true,
        members_file: Some(f._dir.path().join("members.txt")),
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
    report
}
fn receipt(mut r: Value) -> Value {
    r.as_object_mut().unwrap().remove("run_context");
    r.as_object_mut().unwrap().remove("action_attestation_ids");
    r.as_object_mut().unwrap().remove("act");
    r
}
fn logical(mut r: Value, same_record: bool) -> Value {
    r = receipt(r);
    r.as_object_mut().unwrap().remove("engine");
    r.as_object_mut().unwrap().remove("content_revision");
    r.as_object_mut().unwrap().remove("policy_revision");
    if !same_record {
        r.as_object_mut().unwrap().remove("record_id");
    }
    r
}
async fn verify_revisions(f: &Fixture, account: &str, r: &Value) {
    let id = r["record_id"].as_str().unwrap();
    let sql=v2(f,account,"query_sql",json!({"sql":"SELECT updated_at FROM records WHERE id=?1","parameters":[{"type":"text","value":id}]})).await.unwrap();
    assert_eq!(r["content_revision"], sql["rows"][0]["updated_at"]);
    let policy = v2(
        f,
        account,
        "manage_record_policy",
        json!({"action":"list","record_id":id}),
    )
    .await
    .unwrap();
    assert_eq!(r["policy_revision"], policy["policy_revision"]);
    assert_eq!(
        policy["entries"],
        json!([{"subject":{"kind":"account","account_id":account,"person":policy["entries"][0]["subject"]["person"]},"capability":"manage"}])
    );
}

#[tokio::test]
async fn kernel_v2_account_config_import_preserves_the_canonical_mapping_and_receipts() {
    let f = fixture(false).await;
    install(&f).await;
    let source = v1(
        &f.source,
        &f.owner,
        TOOL,
        json!({"action":"ensure","kind":KIND,"reason":"source canonical preferences"}),
    )
    .await
    .unwrap();
    let report = resume(&f).await;
    assert_eq!(report.state.sections["account_configs"].source, 1);
    assert_eq!(report.state.sections["account_configs"].verified, 1);
    let inspect = v2(&f, &f.owner, TOOL, json!({"action":"inspect","kind":KIND}))
        .await
        .unwrap();
    let expected = v1(
        &f.source,
        &f.owner,
        TOOL,
        json!({"action":"inspect","kind":KIND}),
    )
    .await
    .unwrap();
    assert_eq!(inspect["engine"], "kernel_v2");
    assert_eq!(inspect["record_id"], source["record_id"]);
    assert_eq!(logical(inspect.clone(), true), logical(expected, true));
    verify_revisions(&f, &f.owner, &inspect).await;
    let before = kernel::dump_all_kernel_tables(&f.db).await.unwrap();
    let actual = v2(
        &f,
        &f.owner,
        TOOL,
        json!({"action":"ensure","kind":KIND,"reason":"must not replace imported state"}),
    )
    .await
    .unwrap();
    assert_eq!(actual["outcome"], "existing");
    assert_eq!(actual["created"], false);
    assert_eq!(actual["record_id"], source["record_id"]);
    assert_eq!(before, kernel::dump_all_kernel_tables(&f.db).await.unwrap());
    let unchanged = resume(&f).await;
    assert_eq!(unchanged.state.sections["account_configs"].unchanged, 1);
    kernel::replay_all_projections(&f.db).await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&f.db).await.unwrap());
    let heads: Vec<String> =
        sqlx::query_scalar("SELECT event_id FROM content_event_heads ORDER BY 1")
            .fetch_all(f.db.write_pool())
            .await
            .unwrap();
    let scanned: Vec<String> = sqlx::query_scalar(
        "SELECT e.id FROM content_events e WHERE NOT EXISTS
         (SELECT 1 FROM content_event_causal_frontier f WHERE f.parent_event_id=e.id) ORDER BY 1",
    )
    .fetch_all(f.db.write_pool())
    .await
    .unwrap();
    assert_eq!(
        heads, scanned,
        "replay must leave causal heads equal to the scan"
    );
    f.source.close().await;
    f.db.close().await;
}

#[tokio::test]
async fn kernel_v2_account_config_inspect_is_read_only_and_ensure_converges_privately() {
    let f = fixture(false).await;
    install(&f).await;
    resume(&f).await;
    let before = kernel::dump_all_kernel_tables(&f.db).await.unwrap();
    let args = json!({"action":"inspect","kind":KIND});
    let inspected = receipt(v2(&f, &f.member, TOOL, args.clone()).await.unwrap());
    let mut expected = receipt(v1(&f.source, &f.member, TOOL, args).await.unwrap());
    expected["engine"] = json!("kernel_v2");
    assert_eq!(inspected, expected);
    assert_eq!(before, kernel::dump_all_kernel_tables(&f.db).await.unwrap());
    let args = json!({"action":"ensure","kind":KIND,"reason":"personal preferences"});
    let (a, b) = tokio::join!(
        v2(&f, &f.member, TOOL, args.clone()),
        v2(&f, &f.member, TOOL, args.clone())
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    assert_eq!(a["record_id"], b["record_id"]);
    assert_eq!(
        usize::from(a["created"] == true) + usize::from(b["created"] == true),
        1
    );
    let created = if a["created"] == true { a } else { b };
    let expected = v1(&f.source, &f.member, TOOL, args).await.unwrap();
    assert_eq!(logical(created.clone(), false), logical(expected, false));
    verify_revisions(&f, &f.member, &created).await;
    let id = created["record_id"].as_str().unwrap();
    let hidden = v2(&f, &f.owner, "get_record", json!({"ids":[id]}))
        .await
        .unwrap();
    assert_eq!(hidden["records"][0]["status"], "not_found");
    let sql=v2(&f,&f.owner,"query_sql",json!({"sql":"SELECT id FROM records WHERE id=?1","parameters":[{"type":"text","value":id}]})).await.unwrap();
    assert_eq!(sql["rows"], json!([]));
    let before = kernel::dump_all_kernel_tables(&f.db).await.unwrap();
    kernel::replay_all_projections(&f.db).await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&f.db).await.unwrap());
    assert_eq!(
        receipt(
            v2(&f, &f.member, TOOL, json!({"action":"inspect","kind":KIND}))
                .await
                .unwrap()
        )["record_id"],
        id
    );
    let readonly = crate::db::open_marked_v2_database_read_only_at(&f.target)
        .await
        .unwrap();
    let read = registry()
        .call_engine(
            EngineHandle::KernelV2(readonly.clone()),
            Caller::authenticated(&f.member),
            TOOL,
            json!({"action":"inspect","kind":KIND}),
        )
        .await
        .unwrap();
    assert_eq!(read["record_id"], id);
    assert_eq!(read["status"], "healthy");
    readonly.close().await;
    assert_eq!(before, kernel::dump_all_kernel_tables(&f.db).await.unwrap());
    f.source.close().await;
    f.db.close().await;
}

#[tokio::test]
async fn kernel_v2_account_config_archived_and_invalid_content_never_reprovision() {
    let f = fixture(false).await;
    install(&f).await;
    let source = v1(
        &f.source,
        &f.owner,
        TOOL,
        json!({"action":"ensure","kind":KIND,"reason":"retain user data"}),
    )
    .await
    .unwrap();
    resume(&f).await;
    let id = source["record_id"].as_str().unwrap();
    for source in [true, false] {
        let args = json!({"id":id,"archived":true,"reason":"archived config fixture"});
        if source {
            v1(&f.source, &f.owner, "archive_record", args)
                .await
                .unwrap();
        } else {
            v2(&f, &f.owner, "archive_record", args).await.unwrap();
        }
    }
    for action in ["inspect", "ensure"] {
        let mut args = json!({"action":action,"kind":KIND});
        if action == "ensure" {
            args["reason"] = json!("refuse replacement");
        }
        let expected = v1(&f.source, &f.owner, TOOL, args.clone()).await.unwrap();
        let before = kernel::dump_all_kernel_tables(&f.db).await.unwrap();
        let actual = v2(&f, &f.owner, TOOL, args).await.unwrap();
        assert_eq!(actual["reason"], "archived");
        assert_eq!(logical(actual, true), logical(expected, true));
        assert_eq!(before, kernel::dump_all_kernel_tables(&f.db).await.unwrap());
    }
    v2(
        &f,
        &f.owner,
        "archive_record",
        json!({"id":id,"archived":false,"reason":"guarded restoration"}),
    )
    .await
    .unwrap();
    v1(
        &f.source,
        &f.owner,
        "archive_record",
        json!({"id":id,"archived":false,"reason":"restore source"}),
    )
    .await
    .unwrap();
    let focus = uuid::Uuid::new_v4().to_string();
    // JSON-schema-valid input can violate the singleton reader's stronger
    // unique-focus-id invariant. Exercise ordinary v1 and v2 writes, not a
    // forged native target projection.
    let bad = json!({"id":id,"facets":{"focus.preferences":{"version":1,"foci":[{"focus_id":focus,"tier":"now","hidden":false},{"focus_id":focus,"tier":"background","hidden":true}]}},"reason":"invalid content parity"});
    v1(&f.source, &f.owner, "update_record", bad.clone())
        .await
        .unwrap();
    v2(&f, &f.owner, "update_record", bad).await.unwrap();
    for action in ["inspect", "ensure"] {
        let mut args = json!({"action":action,"kind":KIND});
        if action == "ensure" {
            args["reason"] = json!("retain invalid content");
        }
        let expected = v1(&f.source, &f.owner, TOOL, args.clone()).await.unwrap();
        let before = kernel::dump_all_kernel_tables(&f.db).await.unwrap();
        let actual = v2(&f, &f.owner, TOOL, args).await.unwrap();
        assert_eq!(actual["reason"], "invalid_content");
        assert_eq!(actual["record_id"], id);
        assert_eq!(logical(actual, true), logical(expected, true));
        assert_eq!(before, kernel::dump_all_kernel_tables(&f.db).await.unwrap());
    }
    f.source.close().await;
    f.db.close().await;
}

#[tokio::test]
async fn kernel_v2_account_config_and_writes_share_the_public_facet_clock() {
    let f = fixture(false).await;
    install(&f).await;
    resume(&f).await;
    let first = v2(
        &f,
        &f.owner,
        TOOL,
        json!({"action":"ensure","kind":KIND,"reason":"clock parity"}),
    )
    .await
    .unwrap();
    let id = first["record_id"].as_str().unwrap();
    let focus = uuid::Uuid::new_v4().to_string();
    // RFC3339 spelling is not part of the CAS: Z and +00:00 are the same instant.
    let equivalent_revision =
        chrono::DateTime::parse_from_rfc3339(first["content_revision"].as_str().unwrap())
            .unwrap()
            .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, false);
    assert!(equivalent_revision.ends_with("+00:00"));
    let args = json!({"id":id,"facets":{"focus.preferences":{"version":1,"foci":[{"focus_id":focus,"tier":"now","hidden":false}]}},"if_unmodified_since":equivalent_revision,"if_policy_revision":first["policy_revision"],"reason":"facet-only save"});
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let saved = v2(&f, &f.owner, "update_record", args.clone())
        .await
        .unwrap();
    let inspect = v2(&f, &f.owner, TOOL, json!({"action":"inspect","kind":KIND}))
        .await
        .unwrap();
    verify_revisions(&f, &f.owner, &inspect).await;
    assert_eq!(saved["updated_at"], inspect["content_revision"]);
    assert_ne!(first["content_revision"], inspect["content_revision"]);
    let before = kernel::dump_all_kernel_tables(&f.db).await.unwrap();
    assert!(matches!(
        v2(&f, &f.owner, "update_record", args).await,
        Err(Error::Conflict(_))
    ));
    assert!(matches!(v2(&f,&f.owner,"update_record",json!({"id":id,"name":"must not change","if_unmodified_since":"2099-01-01T00:00:00Z","reason":"future guard"})).await,Err(Error::Conflict(_))));
    assert_eq!(before, kernel::dump_all_kernel_tables(&f.db).await.unwrap());
    f.source.close().await;
    f.db.close().await;
}

#[tokio::test]
async fn kernel_v2_account_config_refuses_invalid_arguments_and_unregistered_creation() {
    let f = fixture(false).await;
    let before = kernel::dump_all_kernel_tables(&f.db).await.unwrap();
    for args in [
        json!({"action":"inspect","kind":"unknown"}),
        json!({"action":"ensure","kind":KIND,"reason":" "}),
        json!({"action":"ensure","kind":KIND,"reason":"not registered"}),
        json!({"action":"inspect","kind":KIND,"reason":"not an inspect argument"}),
        json!({"action":"replace","kind":KIND,"expected_record_id":f.private,"reason":"not available"}),
    ] {
        assert!(v2(&f, &f.owner, TOOL, args).await.is_err());
        assert_eq!(before, kernel::dump_all_kernel_tables(&f.db).await.unwrap());
    }
    f.source.close().await;
    f.db.close().await;
}

#[tokio::test]
async fn kernel_v2_account_config_imported_deleted_mapping_is_not_absent() {
    let f = fixture(false).await;
    install(&f).await;
    let created = v1(
        &f.source,
        &f.owner,
        TOOL,
        json!({"action":"ensure","kind":KIND,"reason":"source preferences"}),
    )
    .await
    .unwrap();
    resume(&f).await;
    let id = created["record_id"].as_str().unwrap();
    v1(
        &f.source,
        &f.owner,
        "delete_record",
        json!({"id":id,"reason":"member deleted their configuration"}),
    )
    .await
    .unwrap();
    resume(&f).await;
    for action in ["inspect", "ensure"] {
        let mut args = json!({"action":action,"kind":KIND});
        if action == "ensure" {
            args["reason"] = json!("do not replace a deleted singleton");
        }
        let expected = v1(&f.source, &f.owner, TOOL, args.clone()).await.unwrap();
        let before = kernel::dump_all_kernel_tables(&f.db).await.unwrap();
        let actual = v2(&f, &f.owner, TOOL, args).await.unwrap();
        assert_eq!(actual["reason"], "deleted");
        assert_eq!(actual["record_id"], id);
        assert_eq!(logical(actual, true), logical(expected, true));
        assert_eq!(before, kernel::dump_all_kernel_tables(&f.db).await.unwrap());
    }
    f.source.close().await;
    f.db.close().await;
}

#[tokio::test]
async fn kernel_v2_account_config_widened_policy_refuses_without_replacement() {
    let f = fixture(false).await;
    install(&f).await;
    let created = v1(
        &f.source,
        &f.owner,
        TOOL,
        json!({"action":"ensure","kind":KIND,"reason":"source preferences"}),
    )
    .await
    .unwrap();
    let id = created["record_id"].as_str().unwrap();
    v1(&f.source,&f.owner,"manage_record_policy",json!({"action":"grant","record_id":id,"subject":{"kind":"account","account_id":f.member},"capability":"view","reason":"widened source configuration"})).await.unwrap();
    resume(&f).await;
    for action in ["inspect", "ensure"] {
        let mut args = json!({"action":action,"kind":KIND});
        if action == "ensure" {
            args["reason"] = json!("refuse nonprivate singleton");
        }
        let expected = v1(&f.source, &f.owner, TOOL, args.clone()).await.unwrap();
        let before = kernel::dump_all_kernel_tables(&f.db).await.unwrap();
        let actual = v2(&f, &f.owner, TOOL, args).await.unwrap();
        assert_eq!(actual["reason"], "policy_not_account_only");
        assert_eq!(logical(actual, true), logical(expected, true));
        assert_eq!(before, kernel::dump_all_kernel_tables(&f.db).await.unwrap());
    }
    f.source.close().await;
    f.db.close().await;
}

#[tokio::test]
async fn kernel_v2_account_config_forbidden_mapping_hides_the_target_like_v1() {
    let f = fixture(false).await;
    install(&f).await;
    let own = v1(
        &f.source,
        &f.owner,
        TOOL,
        json!({"action":"ensure","kind":KIND,"reason":"own source preferences"}),
    )
    .await
    .unwrap();
    let other = v1(
        &f.source,
        &f.member,
        TOOL,
        json!({"action":"ensure","kind":KIND,"reason":"other source preferences"}),
    )
    .await
    .unwrap();
    // Fixture-only corrupted v1 source mapping, never the v2 target. This is
    // the unavailable-pointer health case; no tool is allowed to create it.
    sqlx::query("DELETE FROM account_configs WHERE account_id=? AND kind=?")
        .bind(&f.member)
        .bind(KIND)
        .execute(f.source.write_pool())
        .await
        .unwrap();
    sqlx::query("UPDATE account_configs SET record_id=? WHERE account_id=? AND kind=?")
        .bind(other["record_id"].as_str().unwrap())
        .bind(&f.owner)
        .bind(KIND)
        .execute(f.source.write_pool())
        .await
        .unwrap();
    resume(&f).await;
    for action in ["inspect", "ensure"] {
        let mut args = json!({"action":action,"kind":KIND});
        if action == "ensure" {
            args["reason"] = json!("unavailable pointer");
        }
        let expected = v1(&f.source, &f.owner, TOOL, args.clone()).await.unwrap();
        let before = kernel::dump_all_kernel_tables(&f.db).await.unwrap();
        let actual = v2(&f, &f.owner, TOOL, args).await.unwrap();
        assert_eq!(actual["reason"], "forbidden");
        for key in ["record_id", "content_revision", "policy_revision"] {
            assert!(actual[key].is_null());
        }
        assert_eq!(logical(actual, true), logical(expected, true));
        assert_eq!(before, kernel::dump_all_kernel_tables(&f.db).await.unwrap());
    }
    // Neither the original configuration nor the unavailable one was altered.
    assert_ne!(own["record_id"], other["record_id"]);
    f.source.close().await;
    f.db.close().await;
}

#[tokio::test]
async fn kernel_v2_account_config_old_import_requires_capture_and_missing_map_never_reprovisions() {
    let f = fixture(false).await;
    install(&f).await;
    resume(&f).await;
    // Synthetic old prepared copy: schema exists but this import section has
    // not been captured. These are isolated projection corruption fixtures.
    sqlx::query("DELETE FROM kernel_v1_state WHERE section='account_config_capture'")
        .execute(f.db.write_pool())
        .await
        .unwrap();
    for action in ["inspect", "ensure"] {
        let mut args = json!({"action":action,"kind":KIND});
        if action == "ensure" {
            args["reason"] = json!("do not infer absence");
        }
        let before = kernel::dump_all_kernel_tables(&f.db).await.unwrap();
        let error = v2(&f, &f.owner, TOOL, args).await.unwrap_err();
        assert!(error
            .to_string()
            .contains("imported account mappings need preparation"));
        assert_eq!(before, kernel::dump_all_kernel_tables(&f.db).await.unwrap());
    }
    kernel::replay_all_projections(&f.db).await.unwrap();
    let created = v2(
        &f,
        &f.owner,
        TOOL,
        json!({"action":"ensure","kind":KIND,"reason":"prepared preferences"}),
    )
    .await
    .unwrap();
    sqlx::query("DELETE FROM kernel_account_configs WHERE principal_id=? AND kind=?")
        .bind(&f.owner_principal)
        .bind(KIND)
        .execute(f.db.write_pool())
        .await
        .unwrap();
    let before = kernel::dump_all_kernel_tables(&f.db).await.unwrap();
    let error = v2(
        &f,
        &f.owner,
        TOOL,
        json!({"action":"ensure","kind":KIND,"reason":"do not clone lost mapping"}),
    )
    .await
    .unwrap_err();
    assert!(error
        .to_string()
        .contains("canonical mapping projection incomplete"));
    assert_eq!(before, kernel::dump_all_kernel_tables(&f.db).await.unwrap());
    kernel::replay_all_projections(&f.db).await.unwrap();
    assert_eq!(
        v2(&f, &f.owner, TOOL, json!({"action":"inspect","kind":KIND}))
            .await
            .unwrap()["record_id"],
        created["record_id"]
    );
    f.source.close().await;
    f.db.close().await;
}

#[tokio::test]
async fn kernel_v2_account_config_failed_ensure_leaves_no_temp_catalogue_in_the_pool() {
    let f = fixture(false).await;
    assert!(v2(
        &f,
        &f.owner,
        TOOL,
        json!({"action":"ensure","kind":KIND,"reason":"unregistered fixture"})
    )
    .await
    .is_err());
    let mut held = Vec::new();
    for _ in 0..f.db.write_pool().options().get_max_connections() {
        let mut slot = f.db.write_pool().acquire().await.unwrap();
        let leftovers:i64=sqlx::query_scalar("SELECT count(*) FROM temp.sqlite_master WHERE name IN ('schema_config','vocabularies','vocabulary_values')").fetch_one(&mut *slot).await.unwrap();
        assert_eq!(leftovers, 0);
        held.push(slot);
    }
    drop(held);
    f.source.close().await;
    f.db.close().await;
}

#[tokio::test]
async fn kernel_v2_account_config_deleted_home_with_live_native_data_still_requires_review() {
    let f = fixture(false).await;
    install(&f).await;
    let created = v1(
        &f.source,
        &f.owner,
        TOOL,
        json!({"action":"ensure","kind":KIND,"reason":"source private config"}),
    )
    .await
    .unwrap();
    resume(&f).await;
    let id = created["record_id"].as_str().unwrap();
    v2(&f,&f.owner,"create_record",json!({"type":"Annotation","kind":"comment","body":"native data must not be accepted away","links":[{"target_id":id,"relationship":"part_of"}],"reason":"protect unexpected staged writes"})).await.unwrap();
    v1(
        &f.source,
        &f.owner,
        "delete_record",
        json!({"id":id,"reason":"source deletion"}),
    )
    .await
    .unwrap();
    let report = crate::v1_import::run(crate::v1_import::Options {
        source: f._dir.path().join("source.db"),
        target: f.target.clone(),
        seeds: vec![],
        all: true,
        history: true,
        resume: true,
        members_file: Some(f._dir.path().join("members.txt")),
    })
    .await
    .unwrap();
    assert!(report
        .review
        .iter()
        .any(|i| i.id == id && i.reason.contains("source tombstone")));
    f.source.close().await;
    f.db.close().await;
}

#[tokio::test]
async fn kernel_v2_account_config_cannot_adopt_an_older_private_record_by_claiming_its_act() {
    let f = fixture(false).await;
    install(&f).await;
    resume(&f).await;
    let created = v2(&f, &f.owner, "create_record", json!({"type":"Configuration","kind":KIND,"home_id":crate::schema::UNFILED_RECORD_ID,"access_policy":"account_only","facets":{"focus.preferences":{"version":1,"foci":[]}},"reason":"not the canonical configuration"})).await.unwrap();
    let id = created["id"].as_str().unwrap();
    let act: i64 = sqlx::query_scalar(
        "SELECT act FROM content_events WHERE record_id=? AND type='kernel.record_created.v1'",
    )
    .bind(id)
    .fetch_one(f.db.pool())
    .await
    .unwrap();
    let before = kernel::dump_all_kernel_tables(&f.db).await.unwrap();
    let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
    let error = crate::store::append_in(&f.db, &mut tx, crate::store::AppendSpec {
        record_id:id.into(), event_type:kernel::account_config::EVENT.into(),
        actor:Some(f.owner_principal.clone()), payload:json!({"created_act":act,"principal_id":f.owner_principal,"kind":KIND,"record_id":id})
    }, &mut crate::act::ActAllocation::new()).await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("account config creation act differs from its binding"),
        "{error}"
    );
    tx.rollback().await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&f.db).await.unwrap());
    assert_eq!(
        v2(&f, &f.owner, TOOL, json!({"action":"inspect","kind":KIND}))
            .await
            .unwrap()["status"],
        "absent"
    );
    f.source.close().await;
    f.db.close().await;
}

#[tokio::test]
async fn kernel_v2_account_config_source_head_checks_use_an_index_and_inspect_needs_no_person() {
    let f = fixture(false).await;
    let (db, _) = kernel::create_v2_database(
        f._dir.path().join("native.db").to_str().unwrap(),
        "account",
        "Owner",
        &f.owner,
    )
    .await
    .unwrap();
    for statement in ["EXPLAIN QUERY PLAN SELECT payload FROM main.content_events WHERE type='kernel.import_source_head.v1' ORDER BY seq DESC LIMIT 1","EXPLAIN QUERY PLAN SELECT payload FROM main.content_events WHERE type='kernel.import_source_head.v1' AND seq<100 ORDER BY seq DESC LIMIT 1"] {
        let plan:Vec<String>=sqlx::query(statement).fetch_all(db.pool()).await.unwrap().iter().map(|r|sqlx::Row::get::<String,_>(r,"detail")).collect();
        assert!(plan.iter().any(|p|p.contains("idx_kernel_import_source_head")),"{plan:?}");
    }
    let before = kernel::dump_all_kernel_tables(&db).await.unwrap();
    let result = registry()
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            Caller::authenticated(&f.owner),
            TOOL,
            json!({"action":"inspect","kind":KIND}),
        )
        .await
        .unwrap();
    assert_eq!(result["status"], "absent");
    assert_eq!(before, kernel::dump_all_kernel_tables(&db).await.unwrap());
    sqlx::query("DROP INDEX idx_kernel_import_source_head")
        .execute(db.write_pool())
        .await
        .unwrap();
    kernel::prepare_v2_database(&db).await.unwrap();
    let present:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='index' AND name='idx_kernel_import_source_head')").fetch_one(db.pool()).await.unwrap();
    assert!(present);
    db.close().await;
    f.source.close().await;
    f.db.close().await;
}
