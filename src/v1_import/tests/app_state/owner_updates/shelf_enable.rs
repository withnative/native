//! Workspace app shelf, slice 2: members enable a shelf app for themselves, and
//! removal from the workspace stops it (design: S2 workspace-wide app installs,
//! tests 2 to 8, plus R3 and R5).
//!
//! Cast: account-a is Richard (workspace owner, adds to the shelf), account-b
//! George (edit access), account-c Hana (view only) and account-d a member who
//! joins after the app was added. Real MCP calls, real hosted preview and
//! adopt, real app-call admission and full projection replay.
use super::*;
use crate::kernel::app_installs::{AdoptRequest, InstallRequest};
use crate::mcp::app_attribution::AppAttribution;

pub(super) const PKG: &str = "agent.docs";
const VERSION: &str = "0.5.0";

pub(super) fn who(account: &str) -> Caller {
    Caller::authenticated(account).with_hosting_context(account, "hq-fixture")
}
pub(super) fn add(key: &str) -> Value {
    json!({"action":"shelf_add","package":PKG,"idempotency_key":key})
}
pub(super) fn remove(event: &str) -> Value {
    json!({"action":"shelf_remove","package":PKG,"expected_shelf_event_id":event})
}
pub(super) fn enable_args(event: &str, key: &str) -> Value {
    json!({"action":"install","package":PKG,"from_shelf":true,"shelf_event_id":event,"idempotency_key":key})
}
pub(super) fn app_of(account: &str, generation: &str) -> Caller {
    app_at(account, VERSION, generation)
}
pub(super) fn app_at(account: &str, version: &str, generation: &str) -> Caller {
    Caller::authenticated(account)
        .with_host_asserted_app(AppAttribution::new(PKG, version, generation).unwrap())
}

pub(super) struct World {
    pub(super) _f: Fixture,
    pub(super) db: Db,
    pub(super) a: String,
    pub(super) b: String,
    pub(super) c: String,
}

/// `personal`: the package account-b already has as a personal install.
pub(super) async fn world(personal: &str) -> World {
    let f = Fixture::new().await;
    super::super::app_scope::seed_scope_records(&f).await;
    let mut source = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&f.source),
    )
    .await
    .unwrap();
    // A second folder, disjoint from `folder`, so two grants can differ.
    for (id, typ, kind, home, body) in [
        ("folderb", "Collection", "folder", "native:root", "folderb"),
        ("bdoc", "Document", "note", "folderb", "bdocneedle"),
    ] {
        sqlx::query("INSERT INTO records(id,type,kind,name,body,home_id,owner_id,lifecycle,summary,created_at,updated_at,archived,policy_anchor_id,deleted_at) VALUES(?,?,?,?,?,?,'person-a','open','summary','2026-01-01T00:00:00Z','2026-02-01T00:00:00Z',0,'native:root',NULL)")
            .bind(id).bind(typ).bind(kind).bind(id).bind(body).bind(home)
            .execute(&mut source).await.unwrap();
        sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at) VALUES(?,?,'record.created','{}','original-creator','2026-01-01T00:00:00Z')")
            .bind(format!("created:{id}")).bind(id).execute(&mut source).await.unwrap();
    }
    source.close().await.unwrap();
    let (db, a, b) = fixture_with(
        &f,
        personal,
        &[
            "secret",
            "note",
            "task",
            "folder",
            "outsidedoc",
            "privdoc",
            "folderb",
            "bdoc",
        ],
    )
    .await;
    app_roster(
        &db,
        "account-a",
        &["account-a", "account-b", "account-c", "account-d"],
    )
    .await;
    let c = principal(&db, "account-c").await;
    let d = principal(&db, "account-d").await;
    // Workspace-root policy: a manages, b edits, c and d may only view.
    k::replace_home_policy(
        &db,
        &a,
        KERNEL_ROOT_ID,
        &[(&a, "manage"), (&b, "edit"), (&c, "view"), (&d, "view")],
    )
    .await
    .unwrap();
    World { _f: f, db, a, b, c }
}

pub(super) async fn principal(db: &Db, account: &str) -> String {
    k::resolve_principal_by_binding(db, account)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("{account} admitted"))
        .0
}

pub(super) async fn head(db: &Db) -> i64 {
    sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap()
}

/// Install-family events after `seq`: (type, actor, aggregate).
pub(super) async fn install_events(db: &Db, seq: i64) -> Vec<(String, Option<String>, String)> {
    sqlx::query_as("SELECT type,actor,record_id FROM content_events WHERE seq>? AND type LIKE 'kernel.app_install_%' ORDER BY seq")
        .bind(seq)
        .fetch_all(db.pool())
        .await
        .unwrap()
}

pub(super) async fn rows(db: &Db) -> Vec<(String, String, String, String, String)> {
    sqlx::query_as("SELECT principal,package,row_json,generation,status FROM kernel_app_installs ORDER BY principal,package")
        .fetch_all(db.pool())
        .await
        .unwrap()
}

pub(super) async fn row_of(db: &Db, principal: &str, package: &str) -> Option<Value> {
    sqlx::query_scalar::<_, String>(
        "SELECT row_json FROM kernel_app_installs WHERE principal=? AND package=?",
    )
    .bind(principal)
    .bind(package)
    .fetch_optional(db.pool())
    .await
    .unwrap()
    .map(|raw| serde_json::from_str(&raw).unwrap())
}

pub(super) async fn add_to_shelf(w: &World) -> Value {
    call(&w.db, who("account-a"), "manage_alpha_tabs", add("k1"))
        .await
        .unwrap()["entry"]
        .clone()
}

/// Enable from the shelf and give the one-click consent, as `account`.
/// Returns the adopted generation and the pin.
pub(super) async fn enable(
    w: &World,
    account: &str,
    entry: &Value,
    scope: Option<Value>,
) -> crate::Result<(String, InstallRequest)> {
    let key = format!("enable-{account}-{}", head(&w.db).await);
    enable_keyed(w, account, entry, scope, Some(&key)).await
}

/// As `enable`, but the enable call may omit its idempotency key.
async fn enable_keyed(
    w: &World,
    account: &str,
    entry: &Value,
    scope: Option<Value>,
    key: Option<&str>,
) -> crate::Result<(String, InstallRequest)> {
    let me = principal(&w.db, account).await;
    let mut args = enable_args(entry["shelf_event_id"].as_str().unwrap(), "");
    match key {
        Some(key) => args["idempotency_key"] = json!(key),
        None => {
            args.as_object_mut().unwrap().remove("idempotency_key");
        }
    }
    let staged = call(&w.db, who(account), "manage_alpha_tabs", args).await?;
    let install = &staged["install"];
    let pin = InstallRequest {
        package: PKG.into(),
        version: install["version"].as_str().unwrap().into(),
        digest: install["digest"].as_str().unwrap().into(),
        artifact_id: install["artifact_id"].as_str().unwrap().into(),
        source_revision: install["consented_source_revision"]
            .as_str()
            .unwrap()
            .into(),
        declaration: install["consented_declaration"].clone(),
        reason: "Review the workspace app".into(),
        request: None,
        idempotency_key: None,
        expected_install_event_id: Some(install["event_id"].as_str().unwrap().into()),
    };
    let preview = k::app_installs::preview_as(
        &w.db,
        &me,
        &native_app_hosted_caller(account, &pin, false),
        pin.clone(),
    )
    .await?;
    let mut adopt = AdoptRequest {
        pin: pin.clone(),
        receipt_id: preview.receipt.receipt_id,
        nonce: preview.receipt.nonce,
        preview_session: preview.receipt.preview_session,
        scope,
    };
    adopt.pin.idempotency_key = Some(format!("adopt-{account}-{}", head(&w.db).await));
    let adopted = k::app_installs::adopt_as(
        &w.db,
        &me,
        &native_app_hosted_caller(account, &pin, true),
        adopt,
    )
    .await?;
    Ok((adopted.outcome.generation, pin))
}

pub(super) async fn status_as(
    db: &Db,
    caller: &Caller,
    id: &str,
) -> std::result::Result<String, String> {
    match call(db, caller.clone(), "get_record", json!({"ids":[id]})).await {
        Ok(v) => Ok(v["records"][0]["status"]
            .as_str()
            .unwrap_or_default()
            .to_owned()),
        Err(e) => Err(e.to_string()),
    }
}

pub(super) async fn list_as(db: &Db, account: &str) -> Value {
    call(
        db,
        who(account),
        "manage_alpha_tabs",
        json!({"action":"list","workspace_apps":true}),
    )
    .await
    .unwrap()
}

pub(super) fn my_status(list: &Value) -> Value {
    list["shelf"]["entries"][0]["my_status"].clone()
}

pub(super) fn folder(id: &str) -> Value {
    json!({"kind":"folders","folder_ids":[id]})
}

// Design test 2 and 8: adding creates nothing for anyone, and a member who
// joins later sees the shelf with nothing enabled.
#[tokio::test]
async fn add_creates_nothing_for_anyone_and_a_new_member_sees_the_shelf_unenabled() {
    let w = world("personal.owner-slides").await;
    let before = head(&w.db).await;
    let rows_before = rows(&w.db).await;
    let entry = add_to_shelf(&w).await;
    assert!(
        install_events(&w.db, before).await.is_empty(),
        "an add writes no install, consent or tab event for anyone"
    );
    assert_eq!(rows(&w.db).await, rows_before);
    for account in ["account-a", "account-b", "account-c", "account-d"] {
        let listed = list_as(&w.db, account).await;
        assert_eq!(my_status(&listed), "available", "{account}");
        assert!(
            listed["installs"]
                .as_array()
                .unwrap()
                .iter()
                .all(|row| row["package"] != PKG),
            "{account} has no row for the shelf app"
        );
        assert!(
            !listed["tab_order"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p == PKG),
            "{account} has no tab for it"
        );
    }
    // account-d joined after the add (the roster is complete here, but d has
    // never done anything): first open is the one-click consent, once.
    let d = principal(&w.db, "account-d").await;
    let start = head(&w.db).await;
    enable(&w, "account-d", &entry, None).await.unwrap();
    let events = install_events(&w.db, start).await;
    let kinds: Vec<_> = events.iter().map(|(t, _, _)| t.as_str()).collect();
    assert_eq!(
        kinds,
        [
            "kernel.app_install_recorded.v1",
            "kernel.app_install_adopted.v1"
        ]
    );
    assert!(events
        .iter()
        .all(|(_, actor, _)| actor.as_deref() == Some(&d)));
    assert_eq!(my_status(&list_as(&w.db, "account-d").await), "installed");
    assert_eq!(my_status(&list_as(&w.db, "account-a").await), "available");
    k::verify_v2_ready(&w.db).await.unwrap();
}

// Design tests 3 and 4: George's enabling is exactly one install and adopt by
// George; each member's folder grant confines only their own app; nothing of
// Richard's install state reaches George or Hana.
#[tokio::test]
async fn each_member_consents_for_themself_with_their_own_grant_and_sees_only_their_own_state() {
    let w = world("personal.owner-slides").await;
    let entry = add_to_shelf(&w).await;
    let start = head(&w.db).await;
    let (gen_b, _) = enable(&w, "account-b", &entry, Some(folder("folderb")))
        .await
        .unwrap();
    let events = install_events(&w.db, start).await;
    let count = |kind: &str| events.iter().filter(|(t, _, _)| t == kind).count();
    assert_eq!(count("kernel.app_install_recorded.v1"), 1, "{events:?}");
    assert_eq!(count("kernel.app_install_adopted.v1"), 1, "{events:?}");
    assert!(
        events
            .iter()
            .all(|(_, actor, _)| actor.as_deref() == Some(w.b.as_str())),
        "George is the only actor: {events:?}"
    );
    let aggregates: std::collections::BTreeSet<_> =
        events.iter().map(|(_, _, record)| record.clone()).collect();
    assert_eq!(aggregates.len(), 1, "writes only his own install aggregate");
    assert!(
        row_of(&w.db, &w.a, PKG).await.is_none(),
        "Richard (the adder) still has no install"
    );

    let (gen_a, _) = enable(&w, "account-a", &entry, Some(folder("folder")))
        .await
        .unwrap();
    assert_ne!(gen_a, gen_b);
    let (richard, george) = (
        row_of(&w.db, &w.a, PKG).await.unwrap(),
        row_of(&w.db, &w.b, PKG).await.unwrap(),
    );
    assert_eq!(richard["shelf_event_id"], entry["shelf_event_id"]);
    assert_eq!(george["shelf_event_id"], entry["shelf_event_id"]);
    assert_eq!(richard["scope"], folder("folder"));
    assert_eq!(george["scope"], folder("folderb"));

    // Each app acts only within its own member's grant.
    let (app_a, app_b) = (app_of("account-a", &gen_a), app_of("account-b", &gen_b));
    assert_eq!(status_as(&w.db, &app_a, "task").await.unwrap(), "found");
    assert!(status_as(&w.db, &app_a, "bdoc")
        .await
        .unwrap_err()
        .contains("outside_app_scope"));
    assert_eq!(status_as(&w.db, &app_b, "bdoc").await.unwrap(), "found");
    assert!(status_as(&w.db, &app_b, "task")
        .await
        .unwrap_err()
        .contains("outside_app_scope"));
    // Changing one grant moves nobody else's.
    call(
        &w.db,
        who("account-a"),
        "manage_alpha_tabs",
        json!({"action":"set_scope","package":PKG,"scope":folder("folderb")}),
    )
    .await
    .unwrap();
    assert_eq!(
        row_of(&w.db, &w.b, PKG).await.unwrap()["scope"],
        folder("folderb")
    );
    assert_eq!(status_as(&w.db, &app_b, "bdoc").await.unwrap(), "found");
    assert!(status_as(&w.db, &app_b, "task").await.is_err());

    // No leakage: George and Hana see none of Richard's state.
    let secrets = [gen_a.as_str(), w.a.as_str()];
    for account in ["account-b", "account-c"] {
        let listed = list_as(&w.db, account).await;
        let inspected = call(
            &w.db,
            who(account),
            "manage_alpha_tabs",
            json!({"action":"inspect","package":PKG}),
        )
        .await
        .unwrap();
        for text in [listed.to_string(), inspected.to_string()] {
            for secret in secrets {
                assert!(!text.contains(secret), "{account} saw {secret}: {text}");
            }
        }
        let mine: Vec<_> = listed["installs"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["package"] == PKG)
            .collect();
        if account == "account-b" {
            assert_eq!(mine.len(), 1);
            assert_eq!(mine[0]["event_id"], gen_b.as_str());
            assert_eq!(my_status(&listed), "installed");
        } else {
            assert!(mine.is_empty(), "Hana has no row: {listed}");
            assert_eq!(inspected["installed"], false);
            assert_eq!(my_status(&listed), "available");
        }
    }
    k::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(
        row_of(&w.db, &w.b, PKG).await.unwrap()["scope"],
        folder("folderb")
    );
    k::verify_v2_ready(&w.db).await.unwrap();
}

// Design test 5 and R5: a view-only member may enable a shelf app for herself,
// the app acts with only her read-only access, and that path writes nothing but
// her own install row.
#[tokio::test]
async fn a_view_only_member_enables_for_herself_and_the_path_writes_nothing_else() {
    let w = world("personal.owner-slides").await;
    let entry = add_to_shelf(&w).await;
    let shelf_id = entry["shelf_event_id"].as_str().unwrap().to_owned();
    let others_before: Vec<_> = rows(&w.db)
        .await
        .into_iter()
        .filter(|row| row.0 != w.c)
        .collect();
    let records_before: i64 = sqlx::query_scalar("SELECT count(*) FROM kernel_records")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let policy_before: i64 = sqlx::query_scalar("SELECT count(*) FROM kernel_policy_entries")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let start = head(&w.db).await;

    // Hana is refused every write the shelf gates behind edit access.
    for (name, args) in [("add", add("hana-add")), ("remove", remove(&shelf_id))] {
        let refused = call(&w.db, who("account-c"), "manage_alpha_tabs", args).await;
        assert!(refused.is_err(), "view-only member must not {name}");
    }
    assert!(install_events(&w.db, start).await.is_empty());

    let (gen_c, _) = enable(&w, "account-c", &entry, Some(folder("folder")))
        .await
        .expect("a view-only member may enable a shelf app for herself");

    // R5: the whole path appended only her own install-row events, and changed
    // no record, policy, shelf event or anyone else's install.
    let new: Vec<(String, Option<String>, String)> =
        sqlx::query_as("SELECT type,actor,record_id FROM content_events WHERE seq>? ORDER BY seq")
            .bind(start)
            .fetch_all(w.db.pool())
            .await
            .unwrap();
    assert!(!new.is_empty());
    for (kind, actor, record) in &new {
        assert!(
            matches!(
                kind.as_str(),
                "kernel.app_install_recorded.v1"
                    | "kernel.app_install_adopted.v1"
                    | "kernel.app_install_scope_set.v1"
            ),
            "unexpected event {kind}"
        );
        assert_eq!(actor.as_deref(), Some(w.c.as_str()));
        assert!(record.starts_with("kernel:app-installs:"), "{record}");
    }
    let aggregates: std::collections::BTreeSet<_> = new.iter().map(|e| e.2.clone()).collect();
    assert_eq!(aggregates.len(), 1, "one aggregate: her own row");
    let others_after: Vec<_> = rows(&w.db)
        .await
        .into_iter()
        .filter(|row| row.0 != w.c)
        .collect();
    assert_eq!(others_before, others_after);
    let records_after: i64 = sqlx::query_scalar("SELECT count(*) FROM kernel_records")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let policy_after: i64 = sqlx::query_scalar("SELECT count(*) FROM kernel_policy_entries")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    assert_eq!(
        (records_before, policy_before),
        (records_after, policy_after)
    );

    // The app acts with only her read-only access: it reads what she can read,
    // is refused what she cannot, and can write nothing. A writer's app, with
    // the same grant, can.
    let hana = app_of("account-c", &gen_c);
    assert_eq!(status_as(&w.db, &hana, "task").await.unwrap(), "found");
    let (gen_a, _) = enable(&w, "account-a", &entry, Some(folder("folder")))
        .await
        .unwrap();
    let richard = app_of("account-a", &gen_a);
    assert_eq!(
        status_as(&w.db, &richard, "privdoc").await.unwrap(),
        "found"
    );
    assert_ne!(
        status_as(&w.db, &hana, "privdoc").await.ok().as_deref(),
        Some("found"),
        "her app sees nothing she cannot see"
    );
    let write = json!({"type":"Document","kind":"note","name":"app-made","home_id":"folder","reason":"slice 2 test"});
    assert!(
        call(&w.db, hana.clone(), "create_record", write.clone())
            .await
            .is_err(),
        "a view-only member's app cannot create"
    );
    assert!(
        call(
            &w.db,
            hana.clone(),
            "update_record",
            json!({"id":"task","name":"renamed by hana's app"})
        )
        .await
        .is_err(),
        "a view-only member's app cannot update"
    );
    call(&w.db, richard, "create_record", write)
        .await
        .expect("the same app for a writer can create");

    // Nothing about enabling opens any other write for her, or lets a request
    // choose its pin. Every attempt is refused and appends nothing.
    let source = entry["artifact_id"].as_str().unwrap();
    let digest = crate::mcp::tools::lifecycle::body_digest(Some(NEW));
    let stranger =
        Caller::authenticated("account-z").with_hosting_context("account-z", "hq-fixture");
    let george_explicit = json!({"action":"install","package":PKG,"version":entry["version"],
        "digest":entry["digest"],"artifact_id":source,"source_revision":entry["source_revision"],
        "declaration":{"contract":"native.app.v2","needs":[],"effects":[]},"reason":"explicit pin"});
    let mut smuggled = enable_args(&shelf_id, "smuggle");
    smuggled["artifact_id"] = json!("secret");
    let mut stale = enable_args("not-the-live-entry", "stale");
    stale["idempotency_key"] = json!("stale");
    let mut flagless = enable_args(&shelf_id, "flagless");
    flagless["from_shelf"] = json!(false);
    let before = head(&w.db).await;
    let snapshot = k::dump_all_kernel_tables(&w.db).await.unwrap();
    let attempts: Vec<(&str, Caller, Value)> = vec![
        ("request-chosen pin field", who("account-d"), smuggled),
        ("unknown shelf entry", who("account-d"), stale),
        ("from_shelf false", who("account-d"), flagless),
        (
            "explicit install of the shared source (not via the shelf)",
            who("account-d"),
            george_explicit,
        ),
        (
            "app call enabling",
            app_of("account-c", &gen_c),
            enable_args(&shelf_id, "app"),
        ),
        ("non-member", stranger, enable_args(&shelf_id, "stranger")),
        (
            "edit the shared source",
            who("account-c"),
            json!({"id":source,"body_set":OLD,"if_body_digest":digest,"idempotency_key":"hana-edit","reason":"must refuse"}),
        ),
        (
            "archive the shared source",
            who("account-c"),
            json!({"id":source,"archived":true,"reason":"must refuse"}),
        ),
    ];
    for (name, caller, args) in attempts {
        let tool = if args.get("action").is_some() {
            "manage_alpha_tabs"
        } else if args.get("archived").is_some() {
            "archive_record"
        } else {
            "update_record"
        };
        let outcome = call(&w.db, caller, tool, args).await;
        assert!(outcome.is_err(), "{name} must be refused, got {outcome:?}");
    }
    assert_eq!(head(&w.db).await, before, "refusals append nothing");
    assert_eq!(k::dump_all_kernel_tables(&w.db).await.unwrap(), snapshot);
    k::replay_all_projections(&w.db).await.unwrap();
    k::verify_v2_ready(&w.db).await.unwrap();
}

// Design test 6: a member's own removal is personal. v2 has no disable/restore
// action (those exist on v1 only), so "restore" is enabling again from the shelf.
#[tokio::test]
async fn a_members_own_removal_and_re_enable_touch_nobody_else() {
    let w = world("personal.owner-slides").await;
    let entry = add_to_shelf(&w).await;
    let (gen_a, _) = enable(&w, "account-a", &entry, Some(folder("folder")))
        .await
        .unwrap();
    let (gen_b, _) = enable(&w, "account-b", &entry, Some(folder("folderb")))
        .await
        .unwrap();
    let richard_before = row_of(&w.db, &w.a, PKG).await.unwrap();

    call(
        &w.db,
        who("account-b"),
        "manage_alpha_tabs",
        json!({"action":"remove","package":PKG,"expected_install_event_id":gen_b,"reason":"not for me"}),
    )
    .await
    .unwrap();
    assert_eq!(row_of(&w.db, &w.a, PKG).await.unwrap(), richard_before);
    assert_eq!(
        status_as(&w.db, &app_of("account-a", &gen_a), "task")
            .await
            .unwrap(),
        "found"
    );
    assert!(status_as(&w.db, &app_of("account-b", &gen_b), "bdoc")
        .await
        .is_err());
    let listed = list_as(&w.db, "account-b").await;
    assert_eq!(my_status(&listed), "available");
    assert_eq!(
        call(
            &w.db,
            who("account-a"),
            "manage_alpha_tabs",
            json!({"action":"list"})
        )
        .await
        .unwrap()["shelf"]["entries"]
            .as_array()
            .unwrap()
            .len(),
        1,
        "the shelf is unchanged by a personal removal"
    );

    // Back on: a fresh one-click consent, his folder grant kept, Richard's row untouched.
    let (gen_b2, _) = enable(&w, "account-b", &entry, None).await.unwrap();
    assert_ne!(gen_b2, gen_b);
    let george = row_of(&w.db, &w.b, PKG).await.unwrap();
    assert_eq!(george["scope"], folder("folderb"));
    assert_eq!(george["shelf_event_id"], entry["shelf_event_id"]);
    assert_eq!(
        status_as(&w.db, &app_of("account-b", &gen_b2), "bdoc")
            .await
            .unwrap(),
        "found"
    );
    assert_eq!(row_of(&w.db, &w.a, PKG).await.unwrap(), richard_before);
    k::replay_all_projections(&w.db).await.unwrap();
    k::verify_v2_ready(&w.db).await.unwrap();
}

// Design test 7: removal from the workspace stops shelf-origin apps for everyone
// at their next check; nothing is deleted; adding the same pin back restores
// everyone without a new consent; a personal-origin install is never affected.
#[tokio::test]
async fn removal_from_the_workspace_stops_shelf_apps_and_re_adding_restores_them() {
    // The imported world gives Richard and George a personal agent.docs install
    // each, so the shelf entry for the same package is where origin matters.
    // Hana and account-d enable from the shelf.
    let w = world(PKG).await;
    // The personal apps' source must be readable by their members to run.
    k::rehome_record_as(&w.db, &w.a, "secret", KERNEL_ROOT_ID)
        .await
        .unwrap();
    let d = principal(&w.db, "account-d").await;
    k::replace_home_policy(
        &w.db,
        &w.a,
        KERNEL_ROOT_ID,
        &[
            (&w.a, "manage"),
            (&w.b, "edit"),
            (&w.c, "view"),
            (&d, "edit"),
        ],
    )
    .await
    .unwrap();
    let mut personal = Vec::new();
    for (account, principal_id) in [("account-a", &w.a), ("account-b", &w.b)] {
        let (generation, version): (String, String) = sqlx::query_as(
            "SELECT generation,json_extract(row_json,'$.version') FROM kernel_app_installs WHERE principal=? AND package=?",
        )
        .bind(principal_id)
        .bind(PKG)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
        let app = app_at(account, &version, &generation);
        assert_eq!(status_as(&w.db, &app, "task").await.unwrap(), "found");
        personal.push(app);
    }

    let entry = add_to_shelf(&w).await;
    assert_eq!(
        my_status(&list_as(&w.db, "account-b").await),
        "installed",
        "a personal install of the package reads as installed"
    );
    let (gen_c, _) = enable(&w, "account-c", &entry, Some(folder("folder")))
        .await
        .unwrap();
    let (gen_d, _) = enable(&w, "account-d", &entry, Some(folder("folderb")))
        .await
        .unwrap();
    // Slice 4: enabling now stages George's own move off his personal chain,
    // but only as a pending update (his imported row has no verified v2
    // adoption root, so nothing carries); his running row is untouched.
    let george_before = row_of(&w.db, &w.b, PKG).await;
    let staged = call(
        &w.db,
        who("account-b"),
        "manage_alpha_tabs",
        enable_args(entry["shelf_event_id"].as_str().unwrap(), "george"),
    )
    .await
    .unwrap();
    assert_eq!(staged["install"]["pending_update"], true, "{staged}");
    assert_eq!(row_of(&w.db, &w.b, PKG).await, george_before);
    let (hana, dee) = (app_of("account-c", &gen_c), app_of("account-d", &gen_d));
    let made = call(
        &w.db,
        dee.clone(),
        "create_record",
        json!({"type":"Document","kind":"note","name":"written-by-the-app","home_id":"folderb","reason":"slice 2 test"}),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(status_as(&w.db, &hana, "task").await.unwrap(), "found");

    let rows_before = rows(&w.db).await;
    let installs_head = head(&w.db).await;
    call(
        &w.db,
        who("account-b"),
        "manage_alpha_tabs",
        remove(entry["shelf_event_id"].as_str().unwrap()),
    )
    .await
    .unwrap();

    // Next check: both shelf-origin apps are refused with the typed result; the
    // personal-origin installs keep running.
    for (app, id) in [(&hana, "task"), (&dee, "bdoc")] {
        let refused = status_as(&w.db, app, id).await.unwrap_err();
        assert!(refused.contains("workspace_removed"), "{refused}");
    }
    for app in &personal {
        assert_eq!(status_as(&w.db, app, "task").await.unwrap(), "found");
    }
    let listed = list_as(&w.db, "account-d").await;
    let mine = listed["installs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["package"] == PKG)
        .unwrap();
    assert_eq!(mine["status"], "installed", "the row stays");
    assert_eq!(mine["target_resolves"], false);
    assert_eq!(mine["target_skip_reason"], "workspace_removed");
    assert_eq!(mine["skip_reason"], "workspace_removed");
    assert_eq!(mine["shelf_event_id"], entry["shelf_event_id"]);
    for account in ["account-a", "account-b"] {
        let listed = list_as(&w.db, account).await;
        let own = listed["installs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["package"] == PKG)
            .unwrap();
        assert_eq!(own["target_resolves"], true, "{account}: {own}");
        assert!(own.get("shelf_event_id").is_none());
    }
    // Enable is refused too, so a removed app cannot be re-consented.
    let refused = call(
        &w.db,
        who("account-d"),
        "manage_alpha_tabs",
        enable_args(entry["shelf_event_id"].as_str().unwrap(), "after"),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(refused.contains("workspace_removed"), "{refused}");

    // Nothing is deleted: rows and the app's data are exactly as they were,
    // and removal appended no install event for anyone.
    assert_eq!(rows(&w.db).await, rows_before);
    assert!(install_events(&w.db, installs_head).await.is_empty());
    assert_eq!(
        call(
            &w.db,
            who("account-d"),
            "get_record",
            json!({"ids":[made.clone()]})
        )
        .await
        .unwrap()["records"][0]["status"],
        "found"
    );

    // Re-add the same pin: everyone's earlier consent and grant revive with no
    // new prompt and no new generation.
    let readded = call(&w.db, who("account-a"), "manage_alpha_tabs", add("k2"))
        .await
        .unwrap();
    assert_eq!(readded["changed"], true);
    assert_ne!(readded["entry"]["shelf_event_id"], entry["shelf_event_id"]);
    assert_eq!(rows(&w.db).await, rows_before, "no row is rewritten");
    assert!(install_events(&w.db, installs_head).await.is_empty());
    assert_eq!(status_as(&w.db, &hana, "task").await.unwrap(), "found");
    assert_eq!(status_as(&w.db, &dee, "bdoc").await.unwrap(), "found");
    assert!(status_as(&w.db, &dee, "task")
        .await
        .unwrap_err()
        .contains("outside_app_scope"));
    k::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(status_as(&w.db, &hana, "task").await.unwrap(), "found");
    for app in &personal {
        assert_eq!(status_as(&w.db, app, "task").await.unwrap(), "found");
    }
    k::verify_v2_ready(&w.db).await.unwrap();
}

// Slice 1 hand-off: the shared source record can be archived (or an edit
// attempted) after members consented. That must neither change what they consented
// to nor blank their app, and no member can alter another's consented pin (R3).
#[tokio::test]
async fn editing_or_archiving_the_shared_source_changes_no_consented_pin() {
    let w = world("personal.owner-slides").await;
    let entry = add_to_shelf(&w).await;
    let source = entry["artifact_id"].as_str().unwrap().to_owned();
    let (gen_a, _) = enable(&w, "account-a", &entry, Some(folder("folder")))
        .await
        .unwrap();
    let (gen_b, _) = enable(&w, "account-b", &entry, Some(folder("folderb")))
        .await
        .unwrap();
    let rows_after_consent = rows(&w.db).await;
    let body_before: Vec<Option<String>> = sqlx::query_scalar(
        "SELECT source_body FROM kernel_app_installs WHERE package=? ORDER BY principal",
    )
    .bind(PKG)
    .fetch_all(w.db.pool())
    .await
    .unwrap();

    // R3, while the shared source is live: its owner cannot publish over a
    // source other members have consented to.
    let digest = crate::mcp::tools::lifecycle::body_digest(Some(OLD));
    let publish = json!({"action":"publish_catalog_update","artifact_id":source,"package":PKG,
        "version":VERSION,"expected_body_digest":digest,"expected_install_event_id":gen_a,
        "idempotency_key":"richard-publish","reason":"publish over the shared source"});
    let refused = call(
        &w.db,
        who("account-a").with_hosting_owner(true),
        "manage_alpha_tabs",
        publish,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        refused.contains("adding the new version to the shelf"),
        "{refused}"
    );

    // Body edits of a package source are guarded: George (edit access) is not its
    // owner, and its owner Richard cannot publish over a source others use.
    let edit = |key: &str| {
        json!({"id":source,"body_set":OLD,"if_body_digest":crate::mcp::tools::lifecycle::body_digest(Some(NEW)),
            "idempotency_key":key,"reason":"edit the shared source"})
    };
    for (account, key) in [("account-b", "george-edit"), ("account-a", "richard-edit")] {
        let refused = call(&w.db, who(account), "update_record", edit(key)).await;
        assert!(
            refused.is_err(),
            "{account} must not rewrite the shared source"
        );
    }
    // Richard, its owner, can archive the record; that is an ordinary record
    // action and it must not blank anyone's app.
    call(
        &w.db,
        who("account-a"),
        "archive_record",
        json!({"id":source,"archived":true,"reason":"archive the shared source"}),
    )
    .await
    .unwrap();

    // Consent is untouched and the apps keep running from the pinned revision.
    assert_eq!(rows(&w.db).await, rows_after_consent);
    let body_after: Vec<Option<String>> = sqlx::query_scalar(
        "SELECT source_body FROM kernel_app_installs WHERE package=? ORDER BY principal",
    )
    .bind(PKG)
    .fetch_all(w.db.pool())
    .await
    .unwrap();
    assert_eq!(body_before, body_after);
    assert_eq!(body_after[0].as_deref(), Some(NEW));
    assert_eq!(
        status_as(&w.db, &app_of("account-a", &gen_a), "task")
            .await
            .unwrap(),
        "found"
    );
    assert_eq!(
        status_as(&w.db, &app_of("account-b", &gen_b), "bdoc")
            .await
            .unwrap(),
        "found"
    );
    for account in ["account-a", "account-b"] {
        let listed = list_as(&w.db, account).await;
        let mine = listed["installs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["package"] == PKG)
            .unwrap();
        assert_eq!(
            mine["target_resolves"], true,
            "{account} is not blanked: {mine}"
        );
        assert!(mine["target_skip_reason"].is_null(), "{mine}");
    }

    // A member who enables afterwards is shown the pinned release bytes, not the
    // edited record.
    let d = principal(&w.db, "account-d").await;
    let staged = call(
        &w.db,
        who("account-d"),
        "manage_alpha_tabs",
        enable_args(entry["shelf_event_id"].as_str().unwrap(), "d1"),
    )
    .await
    .unwrap();
    let pin = InstallRequest {
        package: PKG.into(),
        version: staged["install"]["version"].as_str().unwrap().into(),
        digest: staged["install"]["digest"].as_str().unwrap().into(),
        artifact_id: source.clone(),
        source_revision: entry["source_revision"].as_str().unwrap().into(),
        declaration: staged["install"]["consented_declaration"].clone(),
        reason: "review".into(),
        request: None,
        idempotency_key: None,
        expected_install_event_id: Some(staged["install"]["event_id"].as_str().unwrap().into()),
    };
    let preview = k::app_installs::preview_as(
        &w.db,
        &d,
        &native_app_hosted_caller("account-d", &pin, false),
        pin.clone(),
    )
    .await
    .unwrap();
    assert_eq!(preview.body, NEW);

    // R3: nothing relaxed lets one member alter another's consented pin or
    // publish over the shared artifact.
    let attempts = [
        (
            "George removes using Richard's generation",
            "account-b",
            json!({"action":"remove","package":PKG,"expected_install_event_id":gen_a,"reason":"x"}),
        ),
        (
            "Richard installs the shared source with an explicit pin",
            "account-a",
            json!({"action":"install","package":PKG,"version":VERSION,"digest":entry["digest"],
                "artifact_id":source,"source_revision":entry["source_revision"],
                "declaration":{"contract":"native.app.v2","needs":[],"effects":[]},"reason":"x",
                "expected_install_event_id":gen_a}),
        ),
    ];
    for (name, account, args) in attempts {
        let outcome = call(&w.db, who(account), "manage_alpha_tabs", args).await;
        assert!(outcome.is_err(), "{name} must be refused, got {outcome:?}");
    }
    let without_d = |all: Vec<(String, String, String, String, String)>| -> Vec<_> {
        all.into_iter().filter(|row| row.0 != d).collect()
    };
    assert_eq!(
        without_d(rows(&w.db).await),
        rows_after_consent,
        "both consented rows are untouched"
    );
    k::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(without_d(rows(&w.db).await), rows_after_consent);
    k::verify_v2_ready(&w.db).await.unwrap();
}

// Omitting the idempotency_key is allowed by the API: a fresh enable after a
// personal removal must still work, and a retry of one attempt must be
// idempotent.
#[tokio::test]
async fn enable_without_a_key_works_again_after_a_personal_removal() {
    let w = world("personal.owner-slides").await;
    let entry = add_to_shelf(&w).await;
    let event = entry["shelf_event_id"].as_str().unwrap();
    let keyless = || async {
        let mut args = enable_args(event, "");
        args.as_object_mut().unwrap().remove("idempotency_key");
        call(&w.db, who("account-b"), "manage_alpha_tabs", args).await
    };
    let (gen1, _) = enable_keyed(&w, "account-b", &entry, Some(folder("folderb")), None)
        .await
        .unwrap();
    call(
        &w.db,
        who("account-b"),
        "manage_alpha_tabs",
        json!({"action":"remove","package":PKG,"expected_install_event_id":gen1,"reason":"not for me"}),
    )
    .await
    .unwrap();

    // Re-enable with no key: a retry of this same attempt stages nothing new.
    let first = keyless().await.unwrap();
    let head_after_first = head(&w.db).await;
    let retry = keyless().await.unwrap();
    assert_eq!(retry["install"]["event_id"], first["install"]["event_id"]);
    assert_eq!(
        head(&w.db).await,
        head_after_first,
        "a retry appends nothing"
    );
    assert_ne!(first["install"]["event_id"], json!(gen1));

    // The attempt completes: consent, and the member ends up installed.
    let (gen2, _) = enable_keyed(&w, "account-b", &entry, None, None)
        .await
        .unwrap();
    assert_ne!(gen2, gen1);
    let row = row_of(&w.db, &w.b, PKG).await.unwrap();
    assert_eq!(row["shelf_event_id"], entry["shelf_event_id"]);
    assert_eq!(
        status_as(&w.db, &app_of("account-b", &gen2), "bdoc")
            .await
            .unwrap(),
        "found"
    );
    k::replay_all_projections(&w.db).await.unwrap();
    k::verify_v2_ready(&w.db).await.unwrap();
}

// A retry of the same keyless enable after its consent was adopted is a no-op
// that returns the adopted install; it never asks for consent again.
#[tokio::test]
async fn keyless_enable_retry_after_adoption_returns_the_adopted_install() {
    let w = world("personal.owner-slides").await;
    let entry = add_to_shelf(&w).await;
    let event = entry["shelf_event_id"].as_str().unwrap();
    let keyless = || async {
        let mut args = enable_args(event, "");
        args.as_object_mut().unwrap().remove("idempotency_key");
        call(&w.db, who("account-b"), "manage_alpha_tabs", args).await
    };

    // First enable, adopted.
    let (gen1, _) = enable_keyed(&w, "account-b", &entry, Some(folder("folderb")), None)
        .await
        .unwrap();
    let mark = head(&w.db).await;
    let retry = keyless().await.unwrap();
    assert_eq!(retry["changed"], false);
    assert_eq!(retry["install"]["event_id"], json!(gen1));
    assert_eq!(head(&w.db).await, mark, "a retry appends nothing");

    // Remove, re-enable, adopt again: the retry follows the new adoption.
    call(
        &w.db,
        who("account-b"),
        "manage_alpha_tabs",
        json!({"action":"remove","package":PKG,"expected_install_event_id":gen1,"reason":"not for me"}),
    )
    .await
    .unwrap();
    let (gen2, _) = enable_keyed(&w, "account-b", &entry, None, None)
        .await
        .unwrap();
    assert_ne!(gen2, gen1);
    let mark = head(&w.db).await;
    let retry = keyless().await.unwrap();
    assert_eq!(retry["changed"], false);
    assert_eq!(retry["install"]["event_id"], json!(gen2));
    assert_eq!(head(&w.db).await, mark, "a retry appends nothing");
    k::replay_all_projections(&w.db).await.unwrap();
    k::verify_v2_ready(&w.db).await.unwrap();
}

// The same recovery never papers over an unrelated change: a keyed retry of an
// adopted attempt still refuses once the member has removed the app.
#[tokio::test]
async fn keyed_enable_retry_after_adoption_and_removal_still_refuses() {
    let w = world("personal.owner-slides").await;
    let entry = add_to_shelf(&w).await;
    let event = entry["shelf_event_id"].as_str().unwrap();
    let (gen1, _) = enable_keyed(&w, "account-b", &entry, None, Some("attempt-1"))
        .await
        .unwrap();
    let same = call(
        &w.db,
        who("account-b"),
        "manage_alpha_tabs",
        enable_args(event, "attempt-1"),
    )
    .await
    .unwrap();
    assert_eq!(same["changed"], false);
    assert_eq!(same["install"]["event_id"], json!(gen1));
    call(
        &w.db,
        who("account-b"),
        "manage_alpha_tabs",
        json!({"action":"remove","package":PKG,"expected_install_event_id":gen1,"reason":"not for me"}),
    )
    .await
    .unwrap();
    let mark = head(&w.db).await;
    let refused = call(
        &w.db,
        who("account-b"),
        "manage_alpha_tabs",
        enable_args(event, "attempt-1"),
    )
    .await
    .expect_err("an unrelated removal must still refuse the old attempt")
    .to_string();
    assert!(refused.contains("changed"), "{refused}");
    assert_eq!(head(&w.db).await, mark);
}

// A carried update also records the generation it replaced in
// `previous_generation`, so a running row whose `previous_generation` is the
// retried attempt is no proof that the attempt was adopted. Shelf packages are
// catalogue packages, which take no source updates, so the carried state is
// written straight into the projection: a running generation that is not an
// adoption event but names the staged attempt as its predecessor. The retry is
// refused and appends nothing.
#[tokio::test]
async fn retrying_a_shelf_enable_whose_running_generation_is_a_carried_update_is_refused() {
    let w = world("personal.owner-slides").await;
    let entry = add_to_shelf(&w).await;
    let event = entry["shelf_event_id"].as_str().unwrap();
    let keyless = || async {
        let mut args = enable_args(event, "");
        args.as_object_mut().unwrap().remove("idempotency_key");
        call(&w.db, who("account-b"), "manage_alpha_tabs", args).await
    };
    let staged = keyless().await.unwrap()["install"]["event_id"]
        .as_str()
        .unwrap()
        .to_owned();
    enable_keyed(&w, "account-b", &entry, None, None)
        .await
        .unwrap();
    sqlx::query("UPDATE kernel_app_installs SET generation='carried-update',previous_generation=? WHERE principal=? AND package=?")
        .bind(&staged).bind(&w.b).bind(PKG)
        .execute(w.db.write_pool()).await.unwrap();
    let mark = head(&w.db).await;
    let refused = keyless()
        .await
        .expect_err("a carried update is not an adoption of the retried attempt")
        .to_string();
    assert!(refused.contains("changed"), "{refused}");
    assert_eq!(head(&w.db).await, mark);
}
