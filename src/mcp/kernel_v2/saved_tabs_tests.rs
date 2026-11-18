#![cfg(feature = "v2-kernel-probe")]

use super::*;
use sqlx::Row as _;
const TOOL: &str = "manage_saved_tabs";
fn create(key: &str) -> Value {
    json!({"action":"create","creation_key":key,"app":"docs","initial_record_id":null,"reason":"admitted local working slot"})
}
async fn make(f: &Fixture, key: &str) -> Value {
    v2(f, &f.member, TOOL, create(key)).await.unwrap()["tab"].clone()
}
fn rename(tab: &Value, op: &str, title: Value) -> Value {
    json!({"action":"rename","record_id":tab["record_id"],"expected_revision":tab["revision"],"operation_id":op,"custom_title":title,"reason":"personal tab label"})
}
fn retire(tab: &Value, op: &str) -> Value {
    json!({"action":"retire","record_id":tab["record_id"],"expected_revision":tab["revision"],"operation_id":op,"reason":"forget working slot"})
}

#[tokio::test]
async fn saved_tabs_success_receipts_use_canonical_event_ids_without_workspace_counters() {
    async fn member_call(f: &Fixture, args: Value) -> Value {
        let caller = Caller::authenticated(&f.member)
            .with_hosting_context("host:saved-tab-member", "db:saved-tab-counter-proof")
            .with_hosting_owner(false)
            .with_hosting_member(true);
        assert!(!caller.counter_footing().is_owner());
        let value = registry()
            .call_engine(EngineHandle::KernelV2(f.db.clone()), caller, TOOL, args)
            .await
            .unwrap();
        assert!(
            crate::mcp::counter_fence::find_counters(&value).is_empty(),
            "{value}"
        );
        for tab in value.get("tab").into_iter().chain(
            value
                .get("tabs")
                .and_then(Value::as_array)
                .into_iter()
                .flatten(),
        ) {
            let revision = tab["revision"].as_str().unwrap();
            let event_id = revision.strip_prefix("saved-tab:").unwrap();
            uuid::Uuid::parse_str(event_id).expect(
                "revision carries a canonical event identity, never a numeric log position",
            );
            let canonical: String = sqlx::query_scalar("SELECT e.id FROM kernel_saved_tabs s JOIN content_events e ON e.seq=s.event_seq WHERE s.record_id=?").bind(tab["record_id"].as_str().unwrap()).fetch_one(f.db.pool()).await.unwrap();
            assert_eq!(event_id, canonical);
        }
        value
    }
    let f = fixture(false).await;
    let created = member_call(&f, create("counter-proof")).await;
    assert_eq!(created["outcome"], "created");
    let first = created["tab"].clone();
    let existing = member_call(&f, create("counter-proof")).await;
    assert_eq!(existing["tab"], first);
    let private_seq: i64 =
        sqlx::query_scalar("SELECT event_seq FROM kernel_saved_tabs WHERE record_id=?")
            .bind(first["record_id"].as_str().unwrap())
            .fetch_one(f.db.pool())
            .await
            .unwrap();
    let mut numeric_attempt = rename(&first, "numeric-clock-probe", json!("Must not apply"));
    numeric_attempt["expected_revision"] = json!(format!("saved-tab:{private_seq}"));
    let refused = member_call(&f, numeric_attempt).await;
    assert_eq!(
        refused["outcome"], "conflict",
        "even the correct numeric clock is never valid client CAS authority"
    );
    assert_eq!(refused["changed"], false);
    assert_eq!(refused["tab"], first);
    let head_before: i64 = sqlx::query_scalar("SELECT max(seq) FROM content_events")
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    let hidden = v2(&f, &f.member, "get_record", json!({"ids":[f.private]}))
        .await
        .unwrap();
    assert_eq!(hidden["records"][0]["status"], "not_found");
    for name in ["Hidden one", "Hidden two", "Hidden three"] {
        v2(
            &f,
            &f.owner,
            "update_record",
            json!({"id":f.private,"name":name,"reason":"unrelated hidden activity"}),
        )
        .await
        .unwrap();
    }
    let head_after: i64 = sqlx::query_scalar("SELECT max(seq) FROM content_events")
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    assert!(head_after >= head_before + 3);
    let read = member_call(&f, json!({"action":"get","record_id":first["record_id"]})).await;
    assert_eq!(
        read["tab"], first,
        "hidden activity cannot change the scoped revision"
    );
    member_call(&f, json!({"action":"list"})).await;
    let attempted = rename(&first, "counter-rename", json!("Private work"));
    let updated = member_call(&f, attempted.clone()).await;
    assert_eq!(updated["outcome"], "updated");
    let conflict = member_call(
        &f,
        rename(&first, "counter-conflict", json!("Another name")),
    )
    .await;
    assert_eq!(conflict["outcome"], "conflict");
    let converged = member_call(
        &f,
        rename(&first, "counter-converged", json!("Private work")),
    )
    .await;
    assert_eq!(converged["outcome"], "converged");
    let reset = member_call(&f, rename(&converged["tab"], "counter-reset", Value::Null)).await;
    assert_eq!(reset["outcome"], "updated");
    let retired = member_call(&f, retire(&reset["tab"], "counter-retire")).await;
    assert_eq!(retired["outcome"], "retired");
    let replayed = member_call(&f, attempted).await;
    assert_eq!(replayed["outcome"], "replayed");
    assert_eq!(
        replayed["tab"], retired["tab"],
        "lost-ack replay exposes only current authority"
    );
    assert_eq!(
        member_call(&f, create("counter-proof")).await["tab"],
        retired["tab"]
    );
    member_call(&f, json!({"action":"list","include_retired":true})).await;
    kernel::replay_all_projections(&f.db).await.unwrap();
    assert_eq!(
        member_call(&f, json!({"action":"get","record_id":first["record_id"]})).await["tab"],
        retired["tab"]
    );
}

#[tokio::test]
async fn saved_tabs_private_creation_scoped_paging_and_terminal_idempotency() {
    let f = fixture(false).await;
    let first = make(&f, "one").await;
    let retry = v2(&f, &f.member, TOOL, create("one")).await.unwrap();
    assert_eq!(retry["outcome"], "existing");
    assert_eq!(retry["tab"], first);
    let mut changed = create("one");
    changed["app"] = json!("spaces");
    assert!(v2(&f, &f.member, TOOL, changed).await.is_err());
    let second = make(&f, "two").await;
    assert_ne!(first["record_id"], second["record_id"]);
    let owner = v2(&f, &f.owner, TOOL, json!({"action":"list"}))
        .await
        .unwrap();
    assert_eq!(owner["tabs"], json!([]));
    assert!(v2(
        &f,
        &f.owner,
        TOOL,
        json!({"action":"get","record_id":first["record_id"]})
    )
    .await
    .is_err());
    let hidden = v2(
        &f,
        &f.owner,
        "get_record",
        json!({"ids":[first["record_id"]]}),
    )
    .await
    .unwrap();
    assert_eq!(hidden["records"][0]["status"], "not_found");
    let p1 = v2(&f, &f.member, TOOL, json!({"action":"list","limit":1}))
        .await
        .unwrap();
    assert_eq!(p1["tabs"].as_array().unwrap().len(), 1);
    let p2 = v2(
        &f,
        &f.member,
        TOOL,
        json!({"action":"list","limit":1,"after":p1["next_cursor"]}),
    )
    .await
    .unwrap();
    assert_eq!(p2["tabs"].as_array().unwrap().len(), 1);
    assert_ne!(p1["tabs"][0]["record_id"], p2["tabs"][0]["record_id"]);
    assert_eq!(p2["next_cursor"], Value::Null);
    let policy = v2(
        &f,
        &f.member,
        "manage_record_policy",
        json!({"action":"list","record_id":first["record_id"]}),
    )
    .await
    .unwrap();
    assert_eq!(policy["entries"].as_array().unwrap().len(), 1);
    assert_eq!(policy["entries"][0]["subject"]["account_id"], f.member);
    let forgotten = v2(&f, &f.member, TOOL, retire(&first, "forget"))
        .await
        .unwrap();
    assert_eq!(forgotten["tab"]["definition"]["state"], "retired");
    let record = kernel::read_record_as(
        &f.db,
        &f.member_principal,
        first["record_id"].as_str().unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    let resurrect = kernel::revise_json_as_expected(
        &f.db,
        &f.member_principal,
        first["record_id"].as_str().unwrap(),
        r#"{"state":"active"}"#,
        Some(record.revision),
    )
    .await
    .unwrap_err();
    assert!(
        resurrect
            .to_string()
            .contains("saved tabs require scoped mutation"),
        "{resurrect}"
    );
    let recreate = v2(&f, &f.member, TOOL, create("one")).await.unwrap();
    assert_eq!(recreate["outcome"], "retired");
    assert_eq!(recreate["tab"]["record_id"], first["record_id"]);
    let stale = v2(&f, &f.member, TOOL, rename(&first, "queued", json!("late")))
        .await
        .unwrap();
    assert_eq!(stale["outcome"], "retired");
    assert_eq!(stale["tab"]["definition"]["customTitle"], Value::Null);
    let active = v2(&f, &f.member, TOOL, json!({"action":"list"}))
        .await
        .unwrap();
    assert_eq!(active["tabs"].as_array().unwrap().len(), 1);
    let all = v2(
        &f,
        &f.member,
        TOOL,
        json!({"action":"list","include_retired":true}),
    )
    .await
    .unwrap();
    assert_eq!(all["tabs"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn saved_tabs_cas_normalization_reset_replay_and_reconstruction() {
    let f = fixture(false).await;
    let tab = make(&f, "rename").await;
    let attempt = rename(&tab, "first", json!("  My   work  "));
    let accepted = v2(&f, &f.member, TOOL, attempt.clone()).await.unwrap();
    assert_eq!(accepted["outcome"], "updated");
    assert_eq!(accepted["tab"]["definition"]["customTitle"], "My work");
    let replay = v2(&f, &f.member, TOOL, attempt.clone()).await.unwrap();
    assert_eq!(replay["outcome"], "replayed");
    assert_eq!(replay["tab"], accepted["tab"]);
    let mut reuse = attempt;
    reuse["custom_title"] = json!("other");
    assert!(v2(&f, &f.member, TOOL, reuse).await.is_err());
    let conflict = v2(
        &f,
        &f.member,
        TOOL,
        rename(&tab, "offline", json!("offline")),
    )
    .await
    .unwrap();
    assert_eq!(conflict["outcome"], "conflict");
    assert_eq!(conflict["tab"], accepted["tab"]);
    let converge = v2(&f, &f.member, TOOL, rename(&tab, "same", json!("My work")))
        .await
        .unwrap();
    assert_eq!(converge["outcome"], "converged");
    let reset = v2(
        &f,
        &f.member,
        TOOL,
        rename(&converge["tab"], "reset", Value::Null),
    )
    .await
    .unwrap();
    assert_eq!(reset["tab"]["definition"]["customTitle"], Value::Null);
    let forgotten = v2(&f, &f.member, TOOL, retire(&reset["tab"], "forget"))
        .await
        .unwrap();
    // Lost acknowledgement of an earlier rename cannot echo a stale active tab.
    let replay = v2(&f, &f.member, TOOL, rename(&tab, "first", json!("My work")))
        .await
        .unwrap();
    assert_eq!(replay["outcome"], "replayed");
    assert_eq!(replay["tab"], forgotten["tab"]);
    let before = kernel::dump_all_kernel_tables(&f.db).await.unwrap();
    kernel::replay_all_projections(&f.db).await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&f.db).await.unwrap());
    let after = v2(
        &f,
        &f.member,
        TOOL,
        json!({"action":"get","record_id":tab["record_id"]}),
    )
    .await
    .unwrap();
    assert_eq!(after["tab"], forgotten["tab"]);
}

#[tokio::test]
async fn saved_tabs_generic_paths_cannot_edit_share_archive_move_or_delete() {
    let f = fixture(false).await;
    let tab = make(&f, "protected").await;
    let id = tab["record_id"].as_str().unwrap();
    let policy = v2(
        &f,
        &f.member,
        "manage_record_policy",
        json!({"action":"list","record_id":id}),
    )
    .await
    .unwrap();
    for (tool, args) in [
        (
            "update_record",
            json!({"id":id,"name":"Generic rename","reason":"must refuse"}),
        ),
        (
            "update_record",
            json!({"id":id,"facets":{"saved.tab":{"state":"active"}},"reason":"must refuse"}),
        ),
        ("archive_record", json!({"id":id,"reason":"must refuse"})),
        (
            "manage_record_policy",
            json!({"action":"grant","record_id":id,"subject":{"kind":"members"},"capability":"view","reason":"must refuse"}),
        ),
        (
            "manage_record_policy",
            json!({"action":"replace","record_id":id,"if_policy_revision":policy["policy_revision"],"entries":[{"subject":{"kind":"members"},"capability":"manage"}],"reason":"must refuse"}),
        ),
        (
            "manage_record_policy",
            json!({"action":"restore_inheritance","record_id":id,"if_policy_revision":policy["policy_revision"],"reason":"must refuse"}),
        ),
        ("delete_record", json!({"id":id,"reason":"must refuse"})),
    ] {
        assert!(
            v2(&f, &f.member, tool, args).await.is_err(),
            "{tool} unexpectedly succeeded"
        );
    }
    let record = kernel::read_record_as(&f.db, &f.member_principal, id)
        .await
        .unwrap()
        .unwrap();
    let bypass = kernel::revise_json_as_expected(
        &f.db,
        &f.member_principal,
        id,
        r#"{"customTitle":"generic bypass"}"#,
        Some(record.revision),
    )
    .await
    .unwrap_err();
    assert!(
        bypass
            .to_string()
            .contains("saved tabs require scoped mutation"),
        "{bypass}"
    );
    assert!(kernel::rehome_record_as(
        &f.db,
        &f.member_principal,
        id,
        crate::events::KERNEL_ROOT_ID
    )
    .await
    .is_err());
    // The low-level supported kernel path hits the same append guard.
    let home: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
        .bind(id)
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    let widened = kernel::replace_home_policy(
        &f.db,
        &f.member_principal,
        &home,
        &[(f.owner_principal.as_str(), "manage")],
    )
    .await
    .unwrap_err();
    assert!(
        widened
            .to_string()
            .contains("saved tabs require scoped mutation"),
        "{widened}"
    );
    let after = v2(&f, &f.member, TOOL, json!({"action":"get","record_id":id}))
        .await
        .unwrap();
    assert_eq!(after["tab"], tab);
    let hidden = v2(&f, &f.owner, "get_record", json!({"ids":[id]}))
        .await
        .unwrap();
    assert_eq!(hidden["records"][0]["status"], "not_found");
}

#[tokio::test]
async fn saved_tabs_reject_invalid_titles_scope_spoofing_and_legacy_engine() {
    let f = fixture(false).await;
    let tab = make(&f, "validation").await;
    for title in [
        "",
        "   ",
        "\u{feff}",
        "a\nb",
        "x\u{202e}y",
        &"🦦".repeat(257),
    ] {
        assert!(
            v2(&f, &f.member, TOOL, rename(&tab, "invalid", json!(title)))
                .await
                .is_err()
        );
    }
    let mut spoof = create("spoof");
    spoof["principal_id"] = json!(f.owner);
    assert!(v2(&f, &f.member, TOOL, spoof).await.is_err());
    assert!(
        v2(&f, &f.member, TOOL, json!({"action":"list","limit":101}))
            .await
            .is_err()
    );
    assert!(v1(&f.source, &f.member, TOOL, create("legacy"))
        .await
        .unwrap_err()
        .to_string()
        .contains("unsupported engine"));
}

#[tokio::test]
async fn saved_tabs_upgrade_is_explicit_and_configuration_discovery_avoids_work_clutter() {
    let mut f = fixture(false).await;
    let tab = make(&f, "discovery").await;
    let search = v2(&f, &f.member, "search", json!({"query":"Saved docs tab"}))
        .await
        .unwrap();
    assert!(!search
        .to_string()
        .contains(tab["record_id"].as_str().unwrap()));
    let changes = v2(&f, &f.member, "whats_changed", json!({})).await.unwrap();
    assert!(!changes
        .to_string()
        .contains(tab["record_id"].as_str().unwrap()));
    assert!(v2(
        &f,
        &f.member,
        "create_record",
        json!({"type":"Configuration","kind":"saved_tab","name":"spoof","reason":"generic spoof"})
    )
    .await
    .is_err());
    // Simulate an older v2 database without the additive projections. Serving
    // must not repair it, or advertise saved-tab capability on an empty scan.
    sqlx::query("DROP TABLE kernel_saved_tab_operations")
        .execute(f.db.write_pool())
        .await
        .unwrap();
    sqlx::query("DROP TABLE kernel_saved_tabs")
        .execute(f.db.write_pool())
        .await
        .unwrap();
    let unavailable = v2(&f, &f.member, TOOL, json!({"action":"list"}))
        .await
        .unwrap();
    assert_eq!(unavailable["outcome"], "unavailable");
    assert_eq!(unavailable["requirement"], "saved_tabs_not_prepared");
    assert!(kernel::verify_v2_ready(&f.db).await.is_err());
    f.db.close().await;
    assert!(
        crate::native_cli::maintenance::prepare_saved_tabs(&f.target, &f.member)
            .await
            .is_err()
    );
    let args = vec![
        "saved-tabs".into(),
        "--db".into(),
        f.target.to_str().unwrap().into(),
        "--as".into(),
        f.owner.clone(),
    ];
    let exit = tokio::task::spawn_blocking(move || crate::native_cli::maintenance::run_cli(&args))
        .await
        .unwrap();
    assert_eq!(exit, std::process::ExitCode::SUCCESS);
    f.db = kernel::open_marked_v2_database(f.target.to_str().unwrap())
        .await
        .unwrap();
    kernel::verify_v2_ready(&f.db).await.unwrap();
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    f.db.close().await;
    let retry = crate::native_cli::maintenance::prepare_saved_tabs(&f.target, &f.owner)
        .await
        .unwrap();
    assert_eq!(retry["reconstructed"], false);
    f.db = kernel::open_marked_v2_database(f.target.to_str().unwrap())
        .await
        .unwrap();
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    assert_eq!(
        before, after,
        "maintenance retry must not append duplicate canonical events"
    );
    let restored = v2(
        &f,
        &f.member,
        TOOL,
        json!({"action":"get","record_id":tab["record_id"]}),
    )
    .await
    .unwrap();
    assert_eq!(restored["tab"], tab);
    // A prepared schema without the package's adopted definition is unavailable.
    let (fresh, _) = kernel::create_v2_database(
        f._dir
            .path()
            .join("unprepared-package.db")
            .to_str()
            .unwrap(),
        "account",
        "Admin",
        &f.owner,
    )
    .await
    .unwrap();
    let unavailable = registry()
        .call_engine(
            EngineHandle::KernelV2(fresh),
            Caller::authenticated(&f.owner),
            TOOL,
            json!({"action":"list"}),
        )
        .await
        .unwrap();
    assert_eq!(unavailable["outcome"], "unavailable");
}

#[tokio::test]
async fn saved_tabs_guard_and_active_listing_use_bounded_index_lookups() {
    let f = fixture(false).await;
    let rows = sqlx::query(&format!(
        "EXPLAIN QUERY PLAN {}",
        kernel::saved_tabs::PROTECTED_SQL
    ))
    .bind("target")
    .fetch_all(f.db.pool())
    .await
    .unwrap();
    let details: Vec<String> = rows.iter().map(|r| r.get("detail")).collect();
    assert_eq!(
        details
            .iter()
            .filter(|d| d.starts_with("SEARCH") && d.contains("kernel_saved_tabs"))
            .count(),
        2,
        "{details:?}"
    );
    assert!(
        !details
            .iter()
            .any(|d| d.starts_with("SCAN") && d.contains("kernel_saved_tabs")),
        "{details:?}"
    );
    let rows=sqlx::query("EXPLAIN QUERY PLAN SELECT record_id FROM kernel_saved_tabs WHERE principal_id=? AND json_extract(definition,'$.state')='active' AND record_id>? ORDER BY record_id LIMIT 101")
        .bind(&f.member_principal).bind("").fetch_all(f.db.pool()).await.unwrap();
    let details: Vec<String> = rows.iter().map(|r| r.get("detail")).collect();
    assert!(
        details
            .iter()
            .any(|d| d.contains("idx_kernel_saved_tab_active")
                && d.contains("principal_id=?")
                && d.contains("record_id>?")),
        "{details:?}"
    );
}

#[tokio::test]
async fn explicit_root_filing_leaves_saved_tab_private_home_unchanged() {
    let f = fixture(false).await;
    let created = v2(&f, &f.member, TOOL, create("root-filing-private-tab"))
        .await
        .unwrap();
    assert!(created.get("redirected_home").is_none());
    let id = created["tab"]["record_id"].as_str().unwrap();
    let home: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
        .bind(id)
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    assert_ne!(home, "native:unfiled");
    assert_ne!(home, crate::events::KERNEL_ROOT_ID);
    let own:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE record_id=? AND type='kernel.home_created.v1' AND json_extract(payload,'$.source_record_id')=?)")
        .bind(home).bind(id).fetch_one(f.db.pool()).await.unwrap();
    assert!(own);
}
