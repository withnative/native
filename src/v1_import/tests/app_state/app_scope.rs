//! Folder-scoped grants for installed apps: enforcement on every surface.
//! The imported world has folder `folder` (task, epic, note, subfolder/
//! nested), folder `private` (secret, the app source), a root record, and
//! two account-only records whose logical folders are `folder` and
//! `private` respectively.
use super::*;
use crate::mcp::{Caller, EngineHandle, ToolRegistry};

const APP_BODY: &str = r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Scoped</title></head><body><main>Sample</main></body></html>"#;

pub(super) async fn seed_scope_records(f: &Fixture) {
    let mut source = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&f.source),
    )
    .await
    .unwrap();
    for (id, typ, kind, home, policy, body) in [
        (
            "subfolder",
            "Collection",
            "folder",
            "folder",
            "native:root",
            "subfolder",
        ),
        (
            "nested",
            "Document",
            "note",
            "subfolder",
            "native:root",
            "nestedneedle",
        ),
        (
            "outsidedoc",
            "Document",
            "note",
            "native:root",
            "native:root",
            "outsideneedle",
        ),
        (
            "privdoc",
            "Document",
            "note",
            "folder",
            "privdoc",
            "privneedle",
        ),
        (
            "privout",
            "Document",
            "note",
            "private",
            "privout",
            "privoutneedle",
        ),
    ] {
        sqlx::query("INSERT INTO records(id,type,kind,name,body,home_id,owner_id,lifecycle,summary,created_at,updated_at,archived,policy_anchor_id,deleted_at) VALUES(?,?,?,?,?,?,'person-a','open','summary','2026-01-01T00:00:00Z','2026-02-01T00:00:00Z',0,?,NULL)")
            .bind(id).bind(typ).bind(kind).bind(id).bind(body).bind(home).bind(policy)
            .execute(&mut source).await.unwrap();
        sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at) VALUES(?,?,'record.created','{}','original-creator','2026-01-01T00:00:00Z')")
            .bind(format!("created:{id}")).bind(id).execute(&mut source).await.unwrap();
    }
    source
        .execute(
            "INSERT INTO record_policies VALUES('privdoc'),('privout');
             INSERT INTO policy_entries VALUES('privdoc','account','account-a','manage'),('privout','account','account-a','manage');
             INSERT INTO links VALUES('link-scope-out','task','outsidedoc','relates_to','scope probe','2026-01-01T00:00:00Z');",
        )
        .await
        .unwrap();
    source.close().await.unwrap();
}

async fn scoped_world() -> (Fixture, Db, super::super::Report) {
    let f = Fixture::new().await;
    seed_scope_records(&f).await;
    native_install_source(&f, APP_BODY).await;
    add_derived_attachment(&f, "task-attachment", "task", "person-a").await;
    add_derived_attachment(&f, "secret-attachment", "secret", "person-a").await;
    let report = run(f.options(
        &[
            "secret",
            "note",
            "task",
            "epic",
            "folder",
            "subfolder",
            "nested",
            "outsidedoc",
            "privdoc",
            "privout",
            "task-attachment",
            "secret-attachment",
        ],
        false,
    ))
    .await
    .unwrap();
    assert!(
        report.refusals.is_empty(),
        "{}",
        serde_json::to_string(&report.refusals).unwrap()
    );
    let db = f.db().await;
    app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    k::app_installs::activate_as(&db, &host, app_activation_proof(&db).await)
        .await
        .unwrap();
    (f, db, report)
}

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
    crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
    registry
}

fn person() -> Caller {
    Caller::authenticated("account-a")
}

fn app() -> Caller {
    person().with_host_asserted_app(
        crate::mcp::app_attribution::AppAttribution::new("agent.docs", "0.8.2", "install").unwrap(),
    )
}

async fn call(db: &Db, caller: Caller, tool: &str, args: Value) -> crate::Result<Value> {
    registry()
        .call_engine(EngineHandle::KernelV2(db.clone()), caller, tool, args)
        .await
}

async fn get_status(db: &Db, caller: Caller, id: &str) -> crate::Result<Value> {
    let got = call(db, caller, "get_record", json!({"ids":[id]})).await?;
    Ok(got["records"][0]["status"].clone())
}

fn assert_outside_scope(error: &crate::Error) {
    assert!(
        error.to_string().contains("outside_app_scope"),
        "expected outside_app_scope, got: {error}"
    );
}

#[tokio::test]
async fn record_hook_kinds_preserve_the_installed_folder_grant() {
    let (_f, db, _report) = scoped_world().await;
    // Sort a real admitted nonmatching Document first. Removing the kind
    // predicate must change the first page, not merely its hidden suffix.
    let report = call(
        &db,
        person(),
        "create_record",
        json!({
            "type":"Document", "kind":"report", "name":"000 non-note",
            "home_id":"folder", "reason":"Prove kind filtering before paging"
        }),
    )
    .await
    .unwrap();
    // Imported kind spellings are definition-dependent. Seed a native note
    // through the same public operation as the report, rather than assume an
    // imported Document has the current literal kind "note".
    call(
        &db,
        person(),
        "create_record",
        json!({
            "type":"Document", "kind":"note", "name":"Native note",
            "home_id":"folder", "reason":"Seed the admitted matching kind"
        }),
    )
    .await
    .unwrap();
    call(
        &db,
        person(),
        "manage_alpha_tabs",
        json!({
            "action":"set_scope", "package":"agent.docs",
            "scope":{"kind":"folders", "folder_ids":["folder"]}
        }),
    )
    .await
    .unwrap();
    let positive = call(&db, app(), "query_record", json!({
        "projection":"record_hook.v1", "limit":1,
        "steps":[{"step":"filter", "types":["Document"], "kinds":["report"], "home_id":"folder"}]
    })).await.unwrap();
    assert_eq!(
        positive["records"][0]["id"], report["id"],
        "the nonmatching control must itself be admitted"
    );
    for home in ["folder", "private"] {
        let page = call(
            &db,
            app(),
            "query_record",
            json!({
                "projection":"record_hook.v1", "order":"name_nocase", "limit":1,
                "steps":[{"step":"filter", "types":["Document"], "kinds":["note"], "home_id":home}]
            }),
        )
        .await
        .unwrap();
        let sql = call(&db, app(), "query_sql", json!({
            "sql":"SELECT id FROM records WHERE deleted_at IS NULL AND archived = 0 AND type = 'Document' AND kind = 'note' AND home_id = ?1 ORDER BY name COLLATE NOCASE ASC, id ASC LIMIT 2",
            "parameters":[{"type":"text", "value":home}]
        })).await.unwrap();
        let expected = sql["rows"].as_array().unwrap();
        let records = page["records"].as_array().unwrap();
        assert_eq!(
            records.iter().map(|r| &r["id"]).collect::<Vec<_>>(),
            expected
                .iter()
                .take(1)
                .map(|r| &r["id"])
                .collect::<Vec<_>>()
        );
        assert_eq!(page["has_more"], expected.len() > 1);
        if home == "private" {
            assert!(
                records.is_empty(),
                "a matching kind must not widen the app's folder grant"
            );
        } else {
            assert!(
                !records.is_empty(),
                "the parity check must exercise an admitted matching note"
            );
        }
    }
}

#[tokio::test]
async fn scoped_app_is_refused_or_omitted_outside_its_folders_on_every_surface() {
    let (_f, db, report) = scoped_world().await;
    let principal = report.principals["account-a"].clone();
    // Unscoped first: exactly today's behaviour, source artifact included.
    assert_eq!(get_status(&db, app(), "secret").await.unwrap(), "found");
    assert_eq!(get_status(&db, app(), "task").await.unwrap(), "found");
    let listed = call(&db, person(), "manage_alpha_tabs", json!({"action":"list"}))
        .await
        .unwrap();
    assert_eq!(listed["installs"][0]["scope"], json!({"kind":"all"}));

    // The person narrows the app to `folder` (duplicates/unsorted input
    // canonicalises); list and inspect echo the effective scope.
    let set = call(
        &db,
        person(),
        "manage_alpha_tabs",
        json!({"action":"set_scope","package":"agent.docs",
               "scope":{"kind":"folders","folder_ids":["folder","folder"]}}),
    )
    .await
    .unwrap();
    assert_eq!(set["changed"], true, "{set}");
    assert_eq!(
        set["install"]["scope"],
        json!({"kind":"folders","folder_ids":["folder"]})
    );
    assert_eq!(
        set["scope"],
        json!({"kind":"folders","folder_ids":["folder"]}),
        "the effective scope is echoed at the top level too"
    );
    let inspected = call(
        &db,
        person(),
        "manage_alpha_tabs",
        json!({"action":"inspect","package":"agent.docs"}),
    )
    .await
    .unwrap();
    assert_eq!(
        inspected["install"]["scope"],
        json!({"kind":"folders","folder_ids":["folder"]})
    );

    // Direct reads: in scope, beneath the folder, and by logical folder.
    assert_eq!(get_status(&db, app(), "task").await.unwrap(), "found");
    assert_eq!(get_status(&db, app(), "nested").await.unwrap(), "found");
    assert_eq!(get_status(&db, app(), "privdoc").await.unwrap(), "found");
    for out in ["secret", "outsidedoc", "privout"] {
        assert_outside_scope(
            &call(&db, app(), "get_record", json!({"ids":[out]}))
                .await
                .unwrap_err(),
        );
    }
    // The granted folder itself is directly reachable.
    assert_eq!(get_status(&db, app(), "folder").await.unwrap(), "found");

    // Search omits out-of-scope hits.
    for (query, present) in [
        ("nestedneedle", true),
        ("privneedle", true),
        ("outsideneedle", false),
        ("privoutneedle", false),
    ] {
        let found = call(&db, app(), "search", json!({"query":query}))
            .await
            .unwrap();
        assert_eq!(
            found["total"].as_u64().unwrap_or(0) > 0,
            present,
            "search {query}: {found}"
        );
    }

    // SQL omits out-of-scope rows, including through a join to links.
    let rows = call(
        &db,
        app(),
        "query_sql",
        json!({"sql":"SELECT id FROM records WHERE id IN ('task','nested','outsidedoc','privdoc','privout','secret') ORDER BY id"}),
    )
    .await
    .unwrap();
    let ids: Vec<&str> = rows["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["nested", "privdoc", "task"], "{rows}");
    let joined = call(
        &db,
        app(),
        "query_sql",
        json!({"sql":"SELECT l.target_id FROM links l JOIN records r ON r.id=l.target_id WHERE l.source_id='task' ORDER BY l.target_id"}),
    )
    .await
    .unwrap();
    assert!(
        !joined.to_string().contains("outsidedoc"),
        "link join leaked an out-of-scope target: {joined}"
    );
    // Link listing on an in-scope record shows no out-of-scope target.
    let task = call(&db, app(), "get_record", json!({"ids":["task"]}))
        .await
        .unwrap();
    assert!(
        !task.to_string().contains("outsidedoc"),
        "get_record enrichment leaked a link target: {task}"
    );

    // Attachments follow their bearer.
    let read = call(
        &db,
        app(),
        "read_attachment",
        json!({"attachment_id":"task-attachment"}),
    )
    .await
    .unwrap();
    assert_eq!(read["content"], "Derivedneedle bytes");
    assert_outside_scope(
        &call(
            &db,
            app(),
            "read_attachment",
            json!({"attachment_id":"secret-attachment"}),
        )
        .await
        .unwrap_err(),
    );
    assert_outside_scope(
        &call(
            &db,
            app(),
            "manage_attachments",
            json!({"action":"list","record_id":"secret"}),
        )
        .await
        .unwrap_err(),
    );

    // History: native records created after import, in and out of scope.
    let histin = call(
        &db,
        person(),
        "create_record",
        json!({"type":"Document","kind":"note","name":"histin","home_id":"folder","reason":"scope test"}),
    )
    .await
    .unwrap()["id"]
        .clone();
    let histout = call(
        &db,
        person(),
        "create_record",
        json!({"type":"Document","kind":"note","name":"histout","reason":"scope test"}),
    )
    .await
    .unwrap()["id"]
        .clone();
    let history = call(&db, app(), "get_history", json!({"record_id":histin}))
        .await
        .unwrap();
    assert!(
        history["events"]
            .as_array()
            .is_some_and(|events| !events.is_empty()),
        "{history}"
    );
    assert_outside_scope(
        &call(&db, app(), "get_history", json!({"record_id":histout}))
            .await
            .unwrap_err(),
    );

    let _ = principal;
}

#[tokio::test]
async fn scoped_app_writes_messages_and_scope_management_are_refused_outside_the_grant() {
    let (_f, db, _report) = scoped_world().await;
    call(
        &db,
        person(),
        "manage_alpha_tabs",
        json!({"action":"set_scope","package":"agent.docs",
               "scope":{"kind":"folders","folder_ids":["folder"]}}),
    )
    .await
    .unwrap();

    // Create: into the granted folder works; into another folder or the
    // workspace root refuses typed.
    let created = call(
        &db,
        app(),
        "create_record",
        json!({"type":"Document","kind":"note","name":"app-created","home_id":"folder","reason":"scope test"}),
    )
    .await
    .unwrap();
    let created_id = created["id"].clone();
    assert_outside_scope(
        &call(
            &db,
            app(),
            "create_record",
            json!({"type":"Document","kind":"note","name":"app-outside","home_id":"private","reason":"scope test"}),
        )
        .await
        .unwrap_err(),
    );
    assert_outside_scope(
        &call(
            &db,
            app(),
            "create_record",
            json!({"type":"Document","kind":"note","name":"app-root","reason":"scope test"}),
        )
        .await
        .unwrap_err(),
    );

    // Update: in scope works, out of scope refuses.
    call(
        &db,
        app(),
        "update_record",
        json!({"id":"nested","name":"nested renamed"}),
    )
    .await
    .unwrap();
    assert_outside_scope(
        &call(
            &db,
            app(),
            "update_record",
            json!({"id":"outsidedoc","name":"outside renamed"}),
        )
        .await
        .unwrap_err(),
    );

    // Move: within the grant works; out of it, or of an out-of-scope
    // record into it, refuses.
    call(
        &db,
        app(),
        "update_record",
        json!({"id":created_id,"home_id":"subfolder"}),
    )
    .await
    .unwrap();
    assert_outside_scope(
        &call(
            &db,
            app(),
            "update_record",
            json!({"id":created_id,"home_id":"private"}),
        )
        .await
        .unwrap_err(),
    );
    assert_outside_scope(
        &call(
            &db,
            app(),
            "update_record",
            json!({"id":"outsidedoc","home_id":"folder"}),
        )
        .await
        .unwrap_err(),
    );
    // A record the person moves out drops out of the grant.
    call(
        &db,
        person(),
        "update_record",
        json!({"id":created_id,"home_id":"private"}),
    )
    .await
    .unwrap();
    assert_outside_scope(
        &call(&db, app(), "get_record", json!({"ids":[created_id]}))
            .await
            .unwrap_err(),
    );

    // Links: adding a link to an out-of-scope target refuses.
    assert_outside_scope(
        &call(
            &db,
            app(),
            "manage_links",
            json!({"action":"add","source_id":"task","target_id":"outsidedoc","relationship":"relates_to"}),
        )
        .await
        .unwrap_err(),
    );

    // Attach text to an out-of-scope record refuses.
    assert_outside_scope(
        &call(
            &db,
            app(),
            "attach_text",
            json!({"record_id":"outsidedoc","text":"stowaway"}),
        )
        .await
        .unwrap_err(),
    );

    // Messages: a scoped app gets none, in either direction.
    assert_outside_scope(
        &call(
            &db,
            app(),
            "manage_messages",
            json!({"action":"list_inbox"}),
        )
        .await
        .unwrap_err(),
    );
    let claim =
        crate::mcp::app_attribution::AppAttribution::new("agent.docs", "0.8.2", "install").unwrap();
    assert_outside_scope(
        &crate::mcp::app_attribution::admit_kernel_v2(
            &db,
            "account-a",
            "manage_memberships",
            &json!({"action":"list"}),
            &claim,
        )
        .await
        .unwrap_err(),
    );

    // An app caller cannot widen (or otherwise manage) its own grant.
    assert!(call(
        &db,
        app(),
        "manage_alpha_tabs",
        json!({"action":"set_scope","package":"agent.docs","scope":{"kind":"all"}}),
    )
    .await
    .is_err());

    // Invalid grants refuse before anything is stored.
    for scope in [
        json!({"kind":"folders","folder_ids":["task"]}),
        json!({"kind":"folders","folder_ids":["no-such-record"]}),
        json!({"kind":"folders","folder_ids":[]}),
        json!({"kind":"everything"}),
    ] {
        assert!(
            call(
                &db,
                person(),
                "manage_alpha_tabs",
                json!({"action":"set_scope","package":"agent.docs","scope":scope}),
            )
            .await
            .is_err(),
            "invalid scope accepted: {scope}"
        );
    }

    // Clearing the grant restores today's behaviour on the next call.
    let cleared = call(
        &db,
        person(),
        "manage_alpha_tabs",
        json!({"action":"set_scope","package":"agent.docs","scope":{"kind":"all"}}),
    )
    .await
    .unwrap();
    assert_eq!(cleared["install"]["scope"], json!({"kind":"all"}));
    assert_eq!(cleared["scope"], json!({"kind":"all"}));
    assert_eq!(get_status(&db, app(), "secret").await.unwrap(), "found");
}

#[tokio::test]
async fn scope_change_does_not_reuse_the_read_cache() {
    let (_f, db, report) = scoped_world().await;
    let principal = report.principals["account-a"].clone();
    call(
        &db,
        person(),
        "manage_alpha_tabs",
        json!({"action":"set_scope","package":"agent.docs",
               "scope":{"kind":"folders","folder_ids":["folder"]}}),
    )
    .await
    .unwrap();
    // One shared read-cache scope: the person's memoized view of `secret`
    // must not be replayed for the scoped app (or the reverse).
    let claim = app();
    let dispatch = crate::provenance::ProvenanceDispatch::from_caller(
        &claim,
        "get_record",
        &json!({"ids":["secret"]}),
        None,
    );
    k::read_cache::scope_request(k::read_cache::with_capabilities(async {
        let as_person = k::read_record_as(&db, &principal, "secret").await.unwrap();
        assert!(as_person.is_some(), "person still reads secret");
        let as_app = dispatch
            .scope(k::read_record_as(&db, &principal, "secret"))
            .await
            .unwrap();
        assert!(
            as_app.is_none(),
            "scoped app must not reuse the person view"
        );
        let as_person_again = k::read_record_as(&db, &principal, "secret").await.unwrap();
        assert!(
            as_person_again.is_some(),
            "person view survives the app's narrowed read"
        );
    }))
    .await;
}

/// Hosted serving also keeps a cross-request visible-ID cache keyed by
/// person. A narrowed app must not inherit that person's broader IDs, or
/// publish its narrower IDs into the person's cache.
#[tokio::test]
async fn scoped_app_reuses_and_narrows_the_persons_serving_visible_cache() {
    let (_f, db, report) = scoped_world().await;
    let cache = crate::mcp::kernel_v2::sql::visible_cache::enable_for_test(&db).await;
    let sql = json!({"sql":"SELECT id FROM records ORDER BY id"});
    for _ in 0..2 {
        let rows = call(&db, person(), "query_sql", sql.clone()).await.unwrap();
        assert!(rows["rows"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["id"] == "secret"));
    }
    let before = *cache.stats.lock().unwrap();
    assert!(before.hits > 0, "the broader person cache must be warm");
    scope_to_folder(&db).await;
    let rows = call(&db, app(), "query_sql", sql.clone()).await.unwrap();
    let ids = rows["rows"].as_array().unwrap();
    assert!(ids.iter().any(|r| r["id"] == "task"));
    assert!(!ids
        .iter()
        .any(|r| r["id"] == "secret" || r["id"] == "outsidedoc"));
    // Both timer and read-triggered refreshes use this path: a background
    // task must carry the grant explicitly rather than refresh as the person.
    crate::mcp::kernel_v2::sql::visible_cache::refresh_scope_for_test(
        &db,
        &report.principals["account-a"],
        k::app_installs::AppScope::Folders(vec!["folder".into()]),
    )
    .await
    .unwrap();
    let rows = call(&db, app(), "query_sql", sql.clone()).await.unwrap();
    assert!(!rows["rows"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["id"] == "secret"));
    call(
        &db,
        person(),
        "manage_alpha_tabs",
        json!({"action":"set_scope","package":"agent.docs",
               "scope":{"kind":"folders","folder_ids":["private"]}}),
    )
    .await
    .unwrap();
    let rows = call(&db, app(), "query_sql", sql.clone()).await.unwrap();
    let ids = rows["rows"].as_array().unwrap();
    assert!(ids.iter().any(|r| r["id"] == "secret"));
    assert!(!ids
        .iter()
        .any(|r| r["id"] == "task" || r["id"] == "outsidedoc"));
    let after = *cache.stats.lock().unwrap();
    assert!(
        after.hits >= before.hits + 3,
        "scoped reads must reuse cached sets"
    );
    assert_eq!(
        after.misses, before.misses,
        "a broader known set can seed either grant"
    );
    let rows = call(&db, person(), "query_sql", sql).await.unwrap();
    assert!(rows["rows"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["id"] == "outsidedoc"));
    crate::mcp::kernel_v2::stop_serving_visible_cache(&db);
}

/// The install/preview/adopt future stack is deep; keep it in its own
/// frame so the test body's registry calls start from a fresh stack.
async fn adopt_scoped_app() -> (Fixture, Db, Caller) {
    let f = Fixture::new().await;
    seed_scope_records(&f).await;
    native_install_source(&f, APP_BODY).await;
    let report = run(f.options(&["secret", "note", "task", "folder", "outsidedoc"], false))
        .await
        .unwrap();
    assert!(
        report.refusals.is_empty(),
        "{}",
        serde_json::to_string(&report.refusals).unwrap()
    );
    let db = f.db().await;
    let administrator = report.principals["account-a"].clone();
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    k::app_installs::activate_as(&db, &host, app_activation_proof(&db).await)
        .await
        .unwrap();
    // The adopting member must be able to view the app source.
    k::rehome_record_as(&db, &administrator, "secret", KERNEL_ROOT_ID)
        .await
        .unwrap();
    app_roster(&db, "account-c", &["account-a", "account-b", "account-c"]).await;
    let principal = k::resolve_principal_by_binding(&db, "account-c")
        .await
        .unwrap()
        .unwrap()
        .0;
    let pins = k::app_installs::frozen_sources_as(&db, &principal)
        .await
        .unwrap();
    let mut pin = k::app_installs::InstallRequest {
        package: pins[0]["package"].as_str().unwrap().into(),
        version: pins[0]["version"].as_str().unwrap().into(),
        digest: pins[0]["digest"].as_str().unwrap().into(),
        artifact_id: "secret".into(),
        source_revision: "source".into(),
        declaration: serde_json::from_str(pins[0]["consented_declaration"].as_str().unwrap())
            .unwrap(),
        reason: "Adopt with a folder grant".into(),
        request: None,
        idempotency_key: Some("scope-adopt-install".into()),
        expected_install_event_id: None,
    };
    let staged = k::app_installs::install_as(&db, &principal, pin.clone())
        .await
        .unwrap();
    pin.expected_install_event_id = Some(staged.generation.clone());
    pin.idempotency_key = None;
    let preview = k::app_installs::preview_as(
        &db,
        &principal,
        &native_app_hosted_caller("account-c", &pin, false),
        pin.clone(),
    )
    .await
    .unwrap();
    let adopting = native_app_hosted_caller("account-c", &pin, true);
    let mut adopt = k::app_installs::AdoptRequest {
        pin: pin.clone(),
        receipt_id: preview.receipt.receipt_id.clone(),
        nonce: preview.receipt.nonce.clone(),
        preview_session: preview.receipt.preview_session.clone(),
        scope: Some(json!({"kind":"folders","folder_ids":["task"]})),
    };
    adopt.pin.idempotency_key = Some("scope-adopt".into());
    // An invalid grant refuses the whole adoption: no generation change.
    assert!(
        k::app_installs::adopt_as(&db, &principal, &adopting, adopt.clone())
            .await
            .is_err()
    );
    let entry = k::app_installs::inspect_as(&db, &principal, &pin.package)
        .await
        .unwrap();
    assert_eq!(entry["install"]["event_id"], staged.generation);
    assert_eq!(entry["install"]["scope"], json!({"kind":"all"}));

    adopt.scope = Some(json!({"kind":"folders","folder_ids":["folder"]}));
    let adopted = k::app_installs::adopt_as(&db, &principal, &adopting, adopt)
        .await
        .unwrap();
    assert!(adopted.outcome.changed);
    assert_eq!(
        adopted.install["scope"],
        json!({"kind":"folders","folder_ids":["folder"]}),
        "adopt echoes the scope it applied"
    );
    // The adopted app is scoped from its first call.
    let caller = Caller::authenticated("account-c").with_host_asserted_app(
        crate::mcp::app_attribution::AppAttribution::new(
            &pin.package,
            &pin.version,
            &adopted.outcome.generation,
        )
        .unwrap(),
    );
    (f, db, caller)
}

#[tokio::test]
async fn adopt_applies_its_scope_atomically() {
    let (_f, db, caller) = adopt_scoped_app().await;
    assert_eq!(
        get_status(&db, caller.clone(), "task").await.unwrap(),
        "found"
    );
    assert_outside_scope(
        &call(&db, caller, "get_record", json!({"ids":["outsidedoc"]}))
            .await
            .unwrap_err(),
    );
}

async fn scope_to_folder(db: &Db) {
    call(
        db,
        person(),
        "manage_alpha_tabs",
        json!({"action":"set_scope","package":"agent.docs",
               "scope":{"kind":"folders","folder_ids":["folder"]}}),
    )
    .await
    .unwrap();
}

/// Review P1: non-record SQL relations (runs/intents et al.) are staged by
/// account ownership, not folders — a scoped app must be refused them.
#[tokio::test]
async fn scoped_app_sql_refuses_non_record_relations() {
    let (_f, db, report) = scoped_world().await;
    let principal = report.principals["account-a"].clone();
    let run = k::mint_run_as(&db, &principal, None).await.unwrap();
    let context = k::open_run_as(&db, &principal, &run).await.unwrap();
    k::set_run_intent_as(&db, &context, "SCOPE_REVIEW_PRIVATE_INTENT")
        .await
        .unwrap();
    // Unscoped, the app sees the person's run intent (today's behaviour).
    let before = call(
        &db,
        app(),
        "query_sql",
        json!({"sql":"SELECT intent FROM run_intents WHERE run_key=?1","parameters":[{"type":"text","value":run}]}),
    )
    .await
    .unwrap();
    assert!(
        before.to_string().contains("SCOPE_REVIEW_PRIVATE_INTENT"),
        "{before}"
    );
    scope_to_folder(&db).await;
    for sql in [
        "SELECT intent FROM run_intents".to_owned(),
        "WITH leaked AS (SELECT intent FROM run_intents) SELECT intent FROM leaked".to_owned(),
        "SELECT (SELECT MAX(intent) FROM run_intents) AS intent".to_owned(),
        "SELECT i.intent FROM run_intents i JOIN runs r ON r.run_key=i.run_key".to_owned(),
        "SELECT run_key FROM runs".to_owned(),
        "SELECT * FROM agent_activity".to_owned(),
        "SELECT * FROM vocabularies".to_owned(),
        "SELECT * FROM my_message_state".to_owned(),
        format!("SELECT intent FROM run_intents WHERE run_key='{run}'"),
    ] {
        let error = call(&db, app(), "query_sql", json!({ "sql": sql }))
            .await
            .unwrap_err();
        assert_outside_scope(&error);
    }
    // Record relations keep working for the scoped app.
    let rows = call(
        &db,
        app(),
        "query_sql",
        json!({"sql":"SELECT id FROM records WHERE id='task'"}),
    )
    .await
    .unwrap();
    assert_eq!(rows["rows"][0]["id"], "task");
}

#[tokio::test]
async fn scoped_app_declared_sql_respects_relation_allowlist() {
    use crate::mcp::kernel_v2::NativeAppDataNeeds;
    use crate::realtime::v2::{AppDataNeeds, AppDataRequest};

    let declaration = json!({
        "needs": [
            {"need":"sql.snapshot.v1","key":"review.runs","label":"Run intents",
             "sql":"SELECT intent FROM run_intents ORDER BY run_key,ordinal"},
            {"need":"sql.snapshot.v1","key":"review.records","label":"Records",
             "sql":"SELECT id,body FROM records WHERE id='note' ORDER BY id"}
        ],
        "effects": []
    });
    let (_f, db, report) = super::declarative_apps::fixture(&declaration).await;
    let principal = &report.principals["account-a"];
    let run = k::mint_run_as(&db, principal, None).await.unwrap();
    let context = k::open_run_as(&db, principal, &run).await.unwrap();
    k::set_run_intent_as(&db, &context, "SCOPE_REVIEW_DECLARED_PRIVATE_INTENT")
        .await
        .unwrap();
    let callers = [
        Caller::authenticated("account-a"),
        Caller::authenticated("account-a").with_host_asserted_app(
            crate::mcp::app_attribution::AppAttribution::new(
                "agent.notion-pages",
                "999.42.0",
                "install",
            )
            .unwrap(),
        ),
    ];
    let request = AppDataRequest {
        package: "agent.notion-pages".into(),
        expected_install_event_id: "install".into(),
        need: None,
        params: json!({}),
    };
    let evaluator = NativeAppDataNeeds;
    // Both subscription caller routes can read the declared relation before
    // scope is set, so a later refusal cannot pass merely on missing data.
    for caller in &callers {
        let snapshot = evaluator.evaluate(&db, caller, &request).await.unwrap();
        assert!(snapshot
            .result
            .to_string()
            .contains("SCOPE_REVIEW_DECLARED_PRIVATE_INTENT"));
    }
    k::app_installs::scope::set_scope_as(
        &db,
        principal,
        "agent.notion-pages",
        k::app_installs::AppScope::Folders(vec!["private".into()]),
    )
    .await
    .unwrap();
    for caller in &callers {
        // Default snapshots and keyed needs both execute through READ_SESSION.
        for need in [None, Some("review.runs".into())] {
            let error = evaluator
                .evaluate(
                    &db,
                    caller,
                    &AppDataRequest {
                        need,
                        ..request.clone()
                    },
                )
                .await
                .unwrap_err();
            assert_outside_scope(&error);
        }
        let records = evaluator
            .evaluate(
                &db,
                caller,
                &AppDataRequest {
                    need: Some("review.records".into()),
                    ..request.clone()
                },
            )
            .await
            .unwrap();
        assert_eq!(records.result["result"]["rows"][0]["id"], "note");
        assert_eq!(records.result["result"]["rows"][0]["body"], "Before");
    }
}

/// Review P1: a Message filed into the granted folder is still not the
/// app's: read, SQL, search and archive all refuse or omit it.
#[tokio::test]
async fn scoped_app_cannot_reach_messages_in_its_folders() {
    let (_f, db, _) = scoped_world().await;
    scope_to_folder(&db).await;
    let sent = call(
        &db,
        person(),
        "manage_messages",
        json!({"action":"send","body":"SCOPE_REVIEW_MESSAGE_BODY",
               "origin":{"type":"collection","collection_id":"folder"},
               "addressed_to":[],"expectation":"none",
               "idempotency_key":"scope-review-message-1","reason":"scope review"}),
    )
    .await
    .unwrap();
    let message_id = sent["id"].as_str().unwrap().to_owned();
    assert_eq!(
        get_status(&db, person(), &message_id).await.unwrap(),
        "found"
    );
    assert_outside_scope(
        &call(&db, app(), "get_record", json!({"ids":[message_id]}))
            .await
            .unwrap_err(),
    );
    let rows = call(
        &db,
        app(),
        "query_sql",
        json!({"sql":format!("SELECT id,body FROM records WHERE id='{message_id}'")}),
    )
    .await
    .unwrap();
    assert!(rows["rows"].as_array().unwrap().is_empty(), "{rows}");
    assert!(!rows.to_string().contains("SCOPE_REVIEW_MESSAGE_BODY"));
    let found = call(
        &db,
        app(),
        "search",
        json!({"query":"SCOPE_REVIEW_MESSAGE_BODY"}),
    )
    .await
    .unwrap();
    assert_eq!(found["total"], 0, "{found}");
    assert_outside_scope(
        &call(
            &db,
            app(),
            "archive_record",
            json!({"id":message_id,"archived":true,"reason":"scope review"}),
        )
        .await
        .unwrap_err(),
    );
    assert_eq!(
        get_status(&db, person(), &message_id).await.unwrap(),
        "found"
    );
}

/// The grant is folded from events alone onto the install row: a full
/// projection replay reproduces it, and enforcement still applies.
#[tokio::test]
async fn scope_survives_full_projection_replay() {
    let (_f, db, _) = scoped_world().await;
    scope_to_folder(&db).await;
    let before: String = sqlx::query_scalar(
        "SELECT json_extract(row_json,'$.scope') FROM kernel_app_installs WHERE package='agent.docs' AND principal IN (SELECT principal_id FROM kernel_principals WHERE auth_binding='account-a')",
    )
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    k::replay_all_projections(&db).await.unwrap();
    let after: String = sqlx::query_scalar(
        "SELECT json_extract(row_json,'$.scope') FROM kernel_app_installs WHERE package='agent.docs' AND principal IN (SELECT principal_id FROM kernel_principals WHERE auth_binding='account-a')",
    )
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    assert_eq!(before, after);
    assert_eq!(
        serde_json::from_str::<Value>(&after).unwrap(),
        json!({"kind":"folders","folder_ids":["folder"]})
    );
    assert_eq!(get_status(&db, app(), "task").await.unwrap(), "found");
    assert_outside_scope(
        &call(&db, app(), "get_record", json!({"ids":["outsidedoc"]}))
            .await
            .unwrap_err(),
    );
}

/// An app update (re-record of the package) rewrites the install row;
/// the person's grant survives it.
#[tokio::test]
async fn app_update_keeps_the_grant() {
    let (_f, db, report) = scoped_world().await;
    scope_to_folder(&db).await;
    let principal = report.principals["account-a"].clone();
    // A new-generation install fully rewrites the install row. Drive one
    // the way the fold admits it: remove, then install against the removed
    // generation, using the frozen source pin.
    let generation: String = sqlx::query_scalar(
        "SELECT generation FROM kernel_app_installs WHERE principal=? AND package='agent.docs'",
    )
    .bind(&principal)
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    let removed = k::app_installs::remove_as(&db, &principal, "agent.docs", &generation)
        .await
        .unwrap();
    // Removal itself does not wipe the stored grant either.
    let stored: Option<String> = sqlx::query_scalar(
        "SELECT json_extract(row_json,'$.scope') FROM kernel_app_installs WHERE principal=? AND package='agent.docs'",
    )
    .bind(&principal)
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&stored.unwrap()).unwrap(),
        json!({"kind":"folders","folder_ids":["folder"]})
    );
    let pins = k::app_installs::frozen_sources_as(&db, &principal)
        .await
        .unwrap();
    let pin = pins
        .iter()
        .find(|pin| pin["package"] == "agent.docs")
        .expect("frozen agent.docs pin");
    let updated = k::app_installs::install_as(
        &db,
        &principal,
        k::app_installs::InstallRequest {
            package: "agent.docs".into(),
            version: pin["version"].as_str().unwrap().into(),
            digest: pin["digest"].as_str().unwrap().into(),
            artifact_id: "secret".into(),
            source_revision: "source".into(),
            declaration: serde_json::from_str(pin["consented_declaration"].as_str().unwrap())
                .unwrap(),
            reason: "reinstall after update".into(),
            request: None,
            idempotency_key: Some("scope-update-1".into()),
            expected_install_event_id: Some(removed),
        },
    )
    .await
    .unwrap();
    assert!(updated.changed);
    let inspected = call(
        &db,
        person(),
        "manage_alpha_tabs",
        json!({"action":"inspect","package":"agent.docs"}),
    )
    .await
    .unwrap();
    assert_eq!(
        inspected["install"]["scope"],
        json!({"kind":"folders","folder_ids":["folder"]}),
        "the update must not drop the grant"
    );
    let scope = {
        let mut tx = db.write_pool().begin().await.unwrap();
        let found = k::app_installs::scope::scope_on(&mut tx, &principal, "agent.docs")
            .await
            .unwrap();
        tx.rollback().await.unwrap();
        found
    };
    assert_eq!(
        scope.to_json(),
        json!({"kind":"folders","folder_ids":["folder"]})
    );
}

/// Adoption and its scope event are one write: exactly one act.
#[tokio::test]
async fn adoption_and_scope_share_one_act() {
    let (_f, db, caller) = adopt_scoped_app().await;
    let acts: Vec<Option<i64>> = sqlx::query_scalar(
        "SELECT act FROM main.content_events WHERE type IN ('kernel.app_install_adopted.v1','kernel.app_install_scope_set.v1') ORDER BY seq DESC LIMIT 2",
    )
    .fetch_all(db.write_pool())
    .await
    .unwrap();
    assert_eq!(acts.len(), 2);
    assert!(acts[0].is_some(), "adoption events carry an act");
    assert_eq!(acts[0], acts[1], "adoption and scope must share one act");
    assert_eq!(
        get_status(&db, caller.clone(), "task").await.unwrap(),
        "found"
    );
}

// ---- merge_body with a real installed app (flag controlled, app-attributed).

const REVOKED_MARK: &str = "database membership not found";
const REMOVED_MARK: &str = "native app installation changed [cas_mismatch]";

fn merge_on() -> crate::body_merge_flag::ScopedConfig {
    crate::body_merge_flag::scoped(crate::body_merge_flag::BodyMergeConfig {
        enabled: true,
        accounts: None,
    })
}

async fn merge_target(db: &Db, id: &str) -> (String, String) {
    let seq: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events WHERE record_id=?")
            .bind(id)
            .fetch_one(db.pool())
            .await
            .unwrap();
    let got = call(db, person(), "get_record", json!({"ids":[id]}))
        .await
        .unwrap();
    let body = got["records"][0]["body"].as_str().unwrap_or("").to_owned();
    (format!("rec:{seq}"), body)
}

fn merge_args(id: &str, version: &str, base: &str, mine: &str, key: &str) -> Value {
    json!({"record_id":id,"base_version":version,"base_text":base,"my_text":mine,
        "reason":"app held edit","idempotency_key":key})
}

async fn app_action_kinds(db: &Db) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT type FROM content_events WHERE type LIKE 'kernel.app_action_%' ORDER BY seq",
    )
    .fetch_all(db.pool())
    .await
    .unwrap()
}

async fn merge_receipt_rows(db: &Db) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM kernel_mcp_write_receipts WHERE operation='merge_body'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap()
}

#[tokio::test]
async fn app_merge_body_is_attributed_replays_for_the_app_and_never_crosses_callers() {
    let _on = merge_on();
    let (_f, db, _report) = scoped_world().await;
    let (version, base) = merge_target(&db, "nested").await;
    let mine = format!("{base} mine");
    let args = merge_args("nested", &version, &base, &mine, "app-key");
    let started = app_action_kinds(&db).await.len();

    let first = call(&db, app(), "merge_body", args.clone()).await.unwrap();
    assert_eq!(first["outcome"], "merged", "{first}");
    assert_eq!(first["result"]["body"], mine);
    let attribution = &first["app_attribution"];
    assert_eq!(attribution["schema"], "native.app-action.v1");
    assert_eq!(attribution["package"], "agent.docs");
    let kinds = app_action_kinds(&db).await;
    assert_eq!(kinds.len(), started + 2, "{kinds:?}");
    assert_eq!(kinds[started], "kernel.app_action_started.v1");
    assert_eq!(kinds[started + 1], "kernel.app_action_recorded.v1");
    // The started fact precedes the body event, the recorded fact follows it.
    let started_act: i64 = sqlx::query_scalar(
        "SELECT act FROM content_events WHERE type='kernel.app_action_started.v1' ORDER BY seq DESC LIMIT 1",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    let order: Vec<String> =
        sqlx::query_scalar("SELECT type FROM content_events WHERE act=? ORDER BY seq")
            .bind(started_act)
            .fetch_all(db.pool())
            .await
            .unwrap();
    let pos = |t: &str| order.iter().position(|x| x == t).unwrap();
    assert!(pos("kernel.app_action_started.v1") < pos("kernel.body_set.v1"));
    assert!(pos("kernel.body_set.v1") < pos("kernel.app_action_recorded.v1"));

    // Same key and arguments replay verbatim for the same app, with no writes.
    let events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(
        call(&db, app(), "merge_body", args.clone()).await.unwrap(),
        first
    );
    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(events, after);
    // An ordinary caller may not read or reuse the app's receipt.
    let ordinary = call(&db, person(), "merge_body", args.clone()).await;
    assert!(
        ordinary
            .as_ref()
            .is_err_and(|e| e.to_string().contains("idempotency_key reused")),
        "{ordinary:?}"
    );
    // And an app may not read an ordinary caller's receipt.
    let (v2, b2) = merge_target(&db, "nested").await;
    let ordinary_args = merge_args("nested", &v2, &b2, &format!("{b2} again"), "ordinary-key");
    let plain = call(&db, person(), "merge_body", ordinary_args.clone())
        .await
        .unwrap();
    assert!(plain.get("app_attribution").is_none());
    let crossed = call(&db, app(), "merge_body", ordinary_args).await;
    assert!(
        crossed
            .as_ref()
            .is_err_and(|e| e.to_string().contains("idempotency_key reused")),
        "{crossed:?}"
    );
    assert_eq!(merge_receipt_rows(&db).await, 2);
}

#[tokio::test]
async fn app_merge_body_records_the_action_for_clash_and_unchanged_outcomes() {
    let _on = merge_on();
    let (_f, db, _report) = scoped_world().await;
    let counts = |db: Db| async move {
        let kinds = app_action_kinds(&db).await;
        (
            kinds.iter().filter(|k| k.ends_with("started.v1")).count(),
            kinds.iter().filter(|k| k.ends_with("recorded.v1")).count(),
        )
    };
    // The `outputs` of the most recent recorded app action.
    let last_outputs = |db: Db| async move {
        let raw: String = sqlx::query_scalar(
            "SELECT payload FROM content_events WHERE type='kernel.app_action_recorded.v1' ORDER BY seq DESC LIMIT 1",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        serde_json::from_str::<Value>(&raw).unwrap()["outputs"].clone()
    };
    let body_event = |db: Db| async move {
        let id: String = sqlx::query_scalar(
            "SELECT id FROM content_events WHERE record_id='nested' AND type='kernel.body_set.v1' ORDER BY seq DESC LIMIT 1",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        id
    };

    // Writing merge: exactly one pair, outputs are exactly the body_set event.
    let (version, base) = merge_target(&db, "nested").await;
    let before = counts(db.clone()).await;
    let written = call(
        &db,
        app(),
        "merge_body",
        merge_args(
            "nested",
            &version,
            &base,
            &format!("{base} more"),
            "written",
        ),
    )
    .await
    .unwrap();
    assert_eq!(written["outcome"], "merged", "{written}");
    assert_eq!(counts(db.clone()).await, (before.0 + 1, before.1 + 1));
    let outputs = last_outputs(db.clone()).await;
    let outputs = outputs.as_array().unwrap();
    assert_eq!(outputs.len(), 1, "{outputs:?}");
    assert_eq!(outputs[0]["event_id"], body_event(db.clone()).await);

    // Unchanged: my_text equals base, nothing to apply.
    let (version, base) = merge_target(&db, "nested").await;
    let before = counts(db.clone()).await;
    let unchanged = call(
        &db,
        app(),
        "merge_body",
        merge_args("nested", &version, &base, &base, "unchanged"),
    )
    .await
    .unwrap();
    assert_eq!(unchanged["outcome"], "merged");
    assert_eq!(unchanged["changed"], false);
    assert!(unchanged.get("write_receipt").is_none());
    assert_eq!(unchanged["app_attribution"]["package"], "agent.docs");
    assert_eq!(counts(db.clone()).await, (before.0 + 1, before.1 + 1));
    assert_eq!(last_outputs(db.clone()).await, json!([]));

    // Clash-only: both sides change the same character, so no hunk applies.
    let (version, base) = merge_target(&db, "nested").await;
    let set_abc = call(
        &db,
        person(),
        "merge_body",
        merge_args("nested", &version, &base, "abc", "set-abc"),
    )
    .await
    .unwrap();
    assert_eq!(set_abc["outcome"], "merged", "{set_abc}");
    let (version, base) = merge_target(&db, "nested").await;
    assert_eq!(base, "abc");
    let set_ayc = call(
        &db,
        person(),
        "merge_body",
        merge_args("nested", &version, "abc", "ayc", "set-ayc"),
    )
    .await
    .unwrap();
    assert_eq!(set_ayc["outcome"], "merged", "{set_ayc}");
    let before = counts(db.clone()).await;
    let clashed = call(
        &db,
        app(),
        "merge_body",
        merge_args("nested", &version, "abc", "axc", "clash"),
    )
    .await
    .unwrap();
    assert_eq!(clashed["outcome"], "merged_with_clashes", "{clashed}");
    assert_eq!(clashed["app_attribution"]["package"], "agent.docs");
    assert_eq!(counts(db.clone()).await, (before.0 + 1, before.1 + 1));
    assert_eq!(last_outputs(db.clone()).await, json!([]));
    // The clash receipt replays verbatim and records nothing more.
    let replay = call(
        &db,
        app(),
        "merge_body",
        merge_args("nested", &version, "abc", "axc", "clash"),
    )
    .await
    .unwrap();
    assert_eq!(replay, clashed);
    assert_eq!(counts(db.clone()).await, (before.0 + 1, before.1 + 1));
}

#[tokio::test]
async fn app_merge_body_is_refused_when_flag_off_removed_or_outside_scope() {
    let (_f, db, report) = scoped_world().await;
    let (version, base) = merge_target(&db, "nested").await;
    let args = merge_args("nested", &version, &base, &format!("{base} x"), "refused");
    let baseline: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let unchanged = |db: Db| async move {
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        n
    };
    // Flag off (the default): refused, nothing recorded, no receipt.
    {
        let _off = crate::body_merge_flag::scoped(crate::body_merge_flag::BodyMergeConfig {
            enabled: false,
            accounts: None,
        });
        let refused = call(&db, app(), "merge_body", args.clone()).await.unwrap();
        assert_eq!(refused["outcome"], "refused", "{refused}");
        assert_eq!(refused["reason"], "feature_not_enabled", "{refused}");
    }
    assert_eq!(unchanged(db.clone()).await, baseline);
    assert_eq!(merge_receipt_rows(&db).await, 0);

    let _on = merge_on();
    // Folder scope: a record outside the grant is not reachable.
    call(
        &db,
        person(),
        "manage_alpha_tabs",
        json!({"action":"set_scope","package":"agent.docs",
               "scope":{"kind":"folders","folder_ids":["folder"]}}),
    )
    .await
    .unwrap();
    let baseline: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let (ov, ob) = merge_target(&db, "outsidedoc").await;
    let outside = call(
        &db,
        app(),
        "merge_body",
        merge_args("outsidedoc", &ov, &ob, &format!("{ob} x"), "outside"),
    )
    .await;
    // The folder grant narrows the capability to nothing, which reads as a
    // missing record: a receipt-less refusal, not an outside_app_scope error.
    let outside = outside.unwrap();
    assert_eq!(outside["outcome"], "refused", "{outside}");
    assert_eq!(outside["reason"], "record_missing", "{outside}");
    assert_eq!(outside["applied"], false, "{outside}");
    assert_eq!(unchanged(db.clone()).await, baseline);
    assert_eq!(merge_receipt_rows(&db).await, 0);
    // In scope it still works.
    let ok = call(&db, app(), "merge_body", args.clone()).await.unwrap();
    assert_eq!(ok["outcome"], "merged", "{ok}");

    // Consent revoked (the account drops off the hosted roster): the app is
    // refused at the registry preflight, a replay of the earlier success
    // included, and nothing is written.
    app_roster(&db, "account-b", &["account-b"]).await;
    let before = unchanged(db.clone()).await;
    let revoked = call(&db, app(), "merge_body", args.clone())
        .await
        .unwrap_err();
    assert!(
        revoked.to_string().contains(REVOKED_MARK),
        "wrong refusal: {revoked}"
    );
    assert_eq!(unchanged(db.clone()).await, before);
    app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    let restored = call(&db, app(), "merge_body", args.clone()).await.unwrap();
    assert_eq!(restored, ok, "consent restored: the receipt replays");

    // Uninstalled: refused, including a replay of the earlier success.
    let actor = &report.principals["account-a"];
    k::app_installs::remove_as(&db, actor, "agent.docs", "install")
        .await
        .unwrap();
    let before = unchanged(db.clone()).await;
    let removed = call(&db, app(), "merge_body", args).await.unwrap_err();
    assert!(
        removed.to_string().contains(REMOVED_MARK),
        "wrong refusal: {removed}"
    );
    let (v, b) = merge_target(&db, "nested").await;
    let fresh = call(
        &db,
        app(),
        "merge_body",
        merge_args("nested", &v, &b, &format!("{b} y"), "after-removal"),
    )
    .await
    .unwrap_err();
    assert!(
        fresh.to_string().contains(REMOVED_MARK),
        "wrong refusal: {fresh}"
    );
    assert_eq!(unchanged(db.clone()).await, before);
    assert_eq!(merge_receipt_rows(&db).await, 1);
    // The in-transaction re-admission (merge_body.rs `admit_dispatched_on`)
    // is not exercised here: revocation cannot be made to land between the
    // registry preflight and the writer transaction without a new test gate.
}

/// Regression for 85bf4cd: a granted folder identity is already known to the
/// app even when the folder record's own parent home is outside that grant.
#[tokio::test]
async fn scoped_folder_lists_keep_the_authorized_logical_home_identity() {
    let (_f, db, _report) = scoped_world().await;
    let created = call(
        &db,
        person(),
        "create_record",
        json!({
            "type":"Document", "kind":"note", "name":"Scoped placement witness",
            "home_id":"folder", "reason":"Prove authorized logical home disclosure"
        }),
    )
    .await
    .unwrap();
    call(
        &db,
        person(),
        "manage_alpha_tabs",
        json!({
            "action":"set_scope", "package":"agent.docs",
            "scope":{"kind":"folders", "folder_ids":["folder"]}
        }),
    )
    .await
    .unwrap();
    let direct = call(&db, app(), "get_record", json!({"ids":[created["id"]]}))
        .await
        .unwrap();
    let rows = call(
        &db,
        app(),
        "query_sql",
        json!({
            "sql":"SELECT id, home_id FROM records ORDER BY id"
        }),
    )
    .await
    .unwrap();
    // Uses only the existing main contract: no optional kinds filter.
    let list = call(
        &db,
        app(),
        "query_record",
        json!({
            "projection":"record_hook.v1",
            "steps":[{"step":"filter", "types":["Document"], "home_id":"folder"}]
        }),
    )
    .await
    .unwrap();
    assert_eq!(direct["records"][0]["status"], "found", "{direct}");
    assert_eq!(direct["records"][0]["home_id"], "folder", "{direct}");
    let row = rows["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == created["id"])
        .expect("the SQL relation must still admit the created record");
    assert_eq!(row["home_id"], "folder", "sql={rows}; typed list={list}");
    assert!(
        list["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == created["id"]),
        "{list}"
    );
    for hidden in ["secret", "outsidedoc", "privout", "folder"] {
        assert!(
            !rows["rows"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["id"] == hidden),
            "must not widen row visibility: {rows}"
        );
    }
}

fn sql_rows(value: &Value) -> Vec<Value> {
    value["rows"].as_array().cloned().unwrap_or_default()
}

fn home_of(rows: &[Value], id: &str) -> Option<Value> {
    rows.iter()
        .find(|row| row["id"] == id)
        .map(|row| row["home_id"].clone())
}

async fn set_folder_scope(db: &Db, folders: &[&str]) {
    call(
        db,
        person(),
        "manage_alpha_tabs",
        json!({
            "action":"set_scope", "package":"agent.docs",
            "scope":{"kind":"folders", "folder_ids":folders}
        }),
    )
    .await
    .unwrap();
}

async fn typed_folder_list(db: &Db, caller: Caller, folder: &str) -> Vec<String> {
    let list = call(
        db,
        caller,
        "query_record",
        json!({
            "projection":"record_hook.v1",
            "steps":[{"step":"filter", "types":["Document"], "home_id":folder}]
        }),
    )
    .await
    .unwrap();
    list["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["id"].as_str().unwrap().to_owned())
        .collect()
}

/// Boundaries for 85bf4cd: the granted folder's id is the only thing the
/// scoped call learns about it. Rows outside the grant, the folder's own
/// values, sibling and parent folders, and person-level placement (root
/// aliasing included) are exactly as before.
#[tokio::test]
async fn scoped_logical_home_identity_never_widens_the_grant() {
    let (_f, db, _report) = scoped_world().await;
    let sibling = call(
        &db,
        person(),
        "create_record",
        json!({"type":"Collection","kind":"folder","name":"Sibling folder",
               "home_id":"native:root","reason":"Sibling disclosure probe"}),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let in_sibling = call(
        &db,
        person(),
        "create_record",
        json!({"type":"Document","kind":"note","name":"Sibling witness",
               "home_id":sibling,"reason":"Sibling disclosure probe"}),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let witness = call(
        &db,
        person(),
        "create_record",
        json!({"type":"Document","kind":"note","name":"Granted folder witness",
               "home_id":"folder","reason":"Granted folder probe"}),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let all = json!({"sql":"SELECT id, home_id FROM records ORDER BY id"});

    // Person callers: placement unchanged, including root aliasing.
    let person_before = sql_rows(&call(&db, person(), "query_sql", all.clone()).await.unwrap());
    assert_eq!(home_of(&person_before, "task"), Some(json!("folder")));
    assert_eq!(home_of(&person_before, "nested"), Some(json!("subfolder")));
    assert_eq!(home_of(&person_before, "privdoc"), Some(json!("folder")));
    assert_eq!(
        home_of(&person_before, "outsidedoc"),
        Some(json!("native:root"))
    );
    assert_eq!(
        home_of(&person_before, "folder"),
        Some(json!("native:root"))
    );
    assert_eq!(home_of(&person_before, &in_sibling), Some(json!(sibling)));

    set_folder_scope(&db, &["folder"]).await;
    let rows = sql_rows(&call(&db, app(), "query_sql", all.clone()).await.unwrap());
    // In the grant: the folder's own placement is its id, including the
    // imported, private-ACL (logical folder) and nested rows.
    assert_eq!(home_of(&rows, "task"), Some(json!("folder")), "{rows:?}");
    assert_eq!(home_of(&rows, &witness), Some(json!("folder")), "{rows:?}");
    assert_eq!(home_of(&rows, "privdoc"), Some(json!("folder")), "{rows:?}");
    assert_eq!(
        home_of(&rows, "subfolder"),
        Some(json!("folder")),
        "{rows:?}"
    );
    assert_eq!(
        home_of(&rows, "nested"),
        Some(json!("subfolder")),
        "{rows:?}"
    );
    // Outside the grant: still excluded, the folder's own row included.
    for hidden in [
        "secret",
        "outsidedoc",
        "privout",
        "folder",
        &sibling,
        &in_sibling,
    ] {
        assert!(
            home_of(&rows, hidden).is_none(),
            "{hidden} leaked: {rows:?}"
        );
    }
    // No scoped row names a home beyond the granted id or its own rows.
    let row_ids: Vec<&Value> = rows.iter().map(|row| &row["id"]).collect();
    for row in &rows {
        let home = &row["home_id"];
        assert!(
            home.is_null() || home == "folder" || row_ids.contains(&home),
            "unauthorised logical home disclosed: {row}"
        );
    }
    // The folder's own values stay hidden: only its id is authorised.
    let folder_values = call(
        &db,
        app(),
        "query_sql",
        json!({"sql":"SELECT id, name, home_id FROM records WHERE id='folder'"}),
    )
    .await
    .unwrap();
    assert!(sql_rows(&folder_values).is_empty(), "{folder_values}");
    // The typed folder hook lists the grant's own rows, and only those.
    let listed = typed_folder_list(&db, app(), "folder").await;
    assert!(listed.contains(&witness), "{listed:?}");
    assert!(listed.contains(&"privdoc".to_owned()), "{listed:?}");
    assert!(!listed.contains(&"nested".to_owned()), "{listed:?}");
    assert!(!listed.contains(&in_sibling), "{listed:?}");
    assert!(typed_folder_list(&db, app(), &sibling).await.is_empty());
    assert!(typed_folder_list(&db, app(), "native:root")
        .await
        .is_empty());
    assert_eq!(
        typed_folder_list(&db, app(), "subfolder").await,
        vec!["nested".to_owned()]
    );

    // A nested grant authorises only its own id, never its parent's.
    set_folder_scope(&db, &["subfolder"]).await;
    let nested_rows = sql_rows(&call(&db, app(), "query_sql", all.clone()).await.unwrap());
    assert_eq!(
        home_of(&nested_rows, "nested"),
        Some(json!("subfolder")),
        "{nested_rows:?}"
    );
    for hidden in [
        "subfolder",
        "folder",
        "task",
        "privdoc",
        "secret",
        "outsidedoc",
        &witness,
    ] {
        assert!(
            home_of(&nested_rows, hidden).is_none(),
            "{hidden}: {nested_rows:?}"
        );
    }
    assert!(
        nested_rows.iter().all(|row| row["home_id"] != "folder"),
        "parent folder disclosed: {nested_rows:?}"
    );
    assert_eq!(
        typed_folder_list(&db, app(), "subfolder").await,
        vec!["nested".to_owned()]
    );
    assert!(typed_folder_list(&db, app(), "folder").await.is_empty());

    // The person's own reads never see the app's grant.
    let person_after = sql_rows(&call(&db, person(), "query_sql", all).await.unwrap());
    assert_eq!(person_before, person_after);
}

/// `gated` is a folder inside `gatehost`, whose own anchor gives the person
/// View and account-b Manage. `gateddoc` sits in `gated` under its own
/// anchor granting the person, so revoking the person from `gatehost` hides
/// the folder but leaves that content readable. account-b owns all three,
/// so the person has no owner floor on the folder.
async fn gated_world() -> (Fixture, Db, super::super::Report) {
    let f = Fixture::new().await;
    seed_scope_records(&f).await;
    let mut source = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&f.source),
    )
    .await
    .unwrap();
    for (id, typ, kind, home, policy) in [
        (
            "gatehost",
            "Collection",
            "folder",
            "native:root",
            "gatehost",
        ),
        ("gated", "Collection", "folder", "gatehost", "gatehost"),
        ("gateddoc", "Document", "note", "gated", "gateddoc"),
    ] {
        sqlx::query("INSERT INTO records(id,type,kind,name,body,home_id,owner_id,lifecycle,summary,created_at,updated_at,archived,policy_anchor_id,deleted_at) VALUES(?,?,?,?,?,?,'person-b','open','summary','2026-01-01T00:00:00Z','2026-02-01T00:00:00Z',0,?,NULL)")
            .bind(id).bind(typ).bind(kind).bind(id).bind(format!("{id}needle")).bind(home).bind(policy)
            .execute(&mut source).await.unwrap();
        sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at) VALUES(?,?,'record.created','{}','original-creator','2026-01-01T00:00:00Z')")
            .bind(format!("created:{id}")).bind(id).execute(&mut source).await.unwrap();
    }
    source
        .execute(
            "INSERT INTO record_policies VALUES('gatehost'),('gateddoc');
             INSERT INTO policy_entries VALUES('gatehost','account','account-a','view'),('gatehost','account','account-b','manage'),('gateddoc','account','account-a','manage');",
        )
        .await
        .unwrap();
    source.close().await.unwrap();
    native_install_source(&f, APP_BODY).await;
    let report = run(f.options(
        &[
            "secret",
            "note",
            "task",
            "epic",
            "folder",
            "subfolder",
            "nested",
            "outsidedoc",
            "privdoc",
            "privout",
            "gatehost",
            "gated",
            "gateddoc",
        ],
        false,
    ))
    .await
    .unwrap();
    assert!(
        report.refusals.is_empty(),
        "{}",
        serde_json::to_string(&report.refusals).unwrap()
    );
    let db = f.db().await;
    app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    k::app_installs::activate_as(&db, &host, app_activation_proof(&db).await)
        .await
        .unwrap();
    (f, db, report)
}

/// The policy anchor `gated` inherits from: walk its physical home's parents
/// to the nearest kernel policy boundary.
async fn gated_anchor_home(db: &Db) -> String {
    let mut home: String =
        sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id='gated'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    for _ in 0..100 {
        let boundary: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_policies WHERE root_id=?)")
                .bind(&home)
                .fetch_one(db.pool())
                .await
                .unwrap();
        if boundary {
            return home;
        }
        home = sqlx::query_scalar("SELECT parent_id FROM kernel_roots WHERE root_id=?")
            .bind(&home)
            .fetch_one(db.pool())
            .await
            .unwrap();
    }
    panic!("no policy boundary above gated");
}

/// Access loss for 85bf4cd: a grant authorises its folder's id only while
/// the person can still see that folder. Revoking the person's View of the
/// folder masks the id again, while content they can still read stays
/// readable, on the staged path and through a warmed visible-set cache.
#[tokio::test]
async fn scoped_logical_home_identity_follows_the_persons_folder_access() {
    let (_f, db, report) = gated_world().await;
    let cache = crate::mcp::kernel_v2::sql::visible_cache::enable_for_test(&db).await;
    let all = json!({"sql":"SELECT id, home_id FROM records ORDER BY id"});
    let folder_values =
        json!({"sql":"SELECT id, name, body, home_id FROM records WHERE id='gated'"});
    assert_eq!(get_status(&db, person(), "gated").await.unwrap(), "found");
    set_folder_scope(&db, &["gated"]).await;

    // While the person can see the folder, the app sees its id, and the
    // set-cache is warm for the scoped read.
    for _ in 0..2 {
        let rows = sql_rows(&call(&db, app(), "query_sql", all.clone()).await.unwrap());
        assert_eq!(home_of(&rows, "gateddoc"), Some(json!("gated")), "{rows:?}");
        assert!(home_of(&rows, "gated").is_none(), "{rows:?}");
    }
    assert!(
        cache.stats.lock().unwrap().hits > 0,
        "the scoped visible-set cache must be warm before the access change"
    );
    assert_eq!(
        typed_folder_list(&db, app(), "gated").await,
        vec!["gateddoc".to_owned()]
    );

    // Revoke the person's View of the folder's anchor; the app grant and
    // the content's own anchor are untouched.
    let b = report.principals["account-b"].clone();
    let anchor = gated_anchor_home(&db).await;
    k::replace_home_policy(&db, &b, &anchor, &[(b.as_str(), "manage")])
        .await
        .unwrap();
    assert_ne!(get_status(&db, person(), "gated").await.unwrap(), "found");
    assert_eq!(
        get_status(&db, person(), "gateddoc").await.unwrap(),
        "found"
    );
    let listed = call(&db, person(), "manage_alpha_tabs", json!({"action":"list"}))
        .await
        .unwrap();
    assert_eq!(
        listed["installs"][0]["scope"],
        json!({"kind":"folders","folder_ids":["gated"]}),
        "the grant itself is unchanged"
    );

    // Cached and freshly staged reads alike: content stays readable, the
    // folder's id is masked again, and its row and values stay hidden.
    for round in 0..2 {
        let rows = sql_rows(&call(&db, app(), "query_sql", all.clone()).await.unwrap());
        assert_eq!(
            home_of(&rows, "gateddoc"),
            Some(Value::Null),
            "round {round}: revoked folder id still disclosed: {rows:?}"
        );
        assert!(home_of(&rows, "gated").is_none(), "{rows:?}");
        assert!(
            rows.iter().all(|row| row["home_id"] != "gated"),
            "round {round}: {rows:?}"
        );
        let values = call(&db, app(), "query_sql", folder_values.clone())
            .await
            .unwrap();
        assert!(sql_rows(&values).is_empty(), "{values}");
        assert!(
            typed_folder_list(&db, app(), "gated").await.is_empty(),
            "round {round}: typed folder list still names the revoked folder"
        );
        if round == 0 {
            crate::mcp::kernel_v2::sql::visible_cache::refresh_scope_for_test(
                &db,
                &report.principals["account-a"],
                k::app_installs::AppScope::Folders(vec!["gated".into()]),
            )
            .await
            .unwrap();
        }
    }
    let gateddoc = call(
        &db,
        app(),
        "query_sql",
        json!({"sql":"SELECT id, name FROM records WHERE id='gateddoc'"}),
    )
    .await
    .unwrap();
    assert_eq!(sql_rows(&gateddoc).len(), 1, "{gateddoc}");
    crate::mcp::kernel_v2::stop_serving_visible_cache(&db);
}
