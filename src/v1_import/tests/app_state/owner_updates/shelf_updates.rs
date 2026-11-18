//! Workspace app shelf, slice 4: updates to a newer shelf pin, and the lazy
//! move of an existing personal install onto the shared source (design: S2
//! sections 5.3 and 6, tests 9 and 11, and R3).
//!
//! Decisions under test:
//! - `shelf_add` of a newer catalogue version supersedes the live entry; the
//!   old pin's source stays retained, so members keep running what they
//!   consented to until they move.
//! - Moving is the member's own act: `install` with `from_shelf` on a live row
//!   (an earlier shelf pin or a personal install). Unchanged declaration with
//!   a verified adoption carries consent, folder grant and order with no
//!   prompt; anything else stages a pending update that needs the one-click
//!   consent. Nothing writes to another member's row.
use super::shelf_enable::principal;
use super::shelf_enable::*;
use super::*;
use crate::kernel::app_installs::{AdoptRequest, InstallRequest};
use crate::mcp::tools::catalog_assets::{fixture_assets, CatalogAssets};

const NEWER: &str = r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Personal</title></head><body><main>Newer generation</main></body></html>"#;

fn release(body: &str, version: &str) -> CatalogAssets {
    fixture_assets(body, PKG, version)
}
async fn call_with(
    db: &Db,
    caller: Caller,
    assets: &CatalogAssets,
    args: Value,
) -> crate::Result<Value> {
    let mut r = ToolRegistry::new();
    r.set_catalog_assets(assets.clone());
    crate::mcp::register_builtin_tools(&mut r).unwrap();
    crate::mcp::tools::register_surface_tools(&mut r).unwrap();
    crate::mcp::kernel_v2::register_kernel_v2_tools(&mut r).unwrap();
    r.call_engine(
        EngineHandle::KernelV2(db.clone()),
        caller,
        "manage_alpha_tabs",
        args,
    )
    .await
}

/// Put a (newer) release on the shelf as `account-a`; returns the new entry.
async fn shelf_release(w: &World, assets: &CatalogAssets, key: &str) -> Value {
    let added = call_with(&w.db, who("account-a"), assets, add(key))
        .await
        .unwrap();
    assert_eq!(added["changed"], true, "{added}");
    added["entry"].clone()
}

/// A member's own move onto `entry`. Returns the call result.
async fn move_to(w: &World, account: &str, entry: &Value) -> crate::Result<Value> {
    call_with(
        &w.db,
        who(account),
        &release(NEW, "0.5.0"),
        enable_args(
            entry["shelf_event_id"].as_str().unwrap(),
            &format!("move-{account}-{}", head(&w.db).await),
        ),
    )
    .await
}

/// The usual preview and one-click adopt of a staged (pending) update.
async fn consent_to(
    w: &World,
    account: &str,
    staged: &Value,
    scope: Option<Value>,
) -> crate::Result<String> {
    let me = principal(&w.db, account).await;
    let install = &staged["install"];
    assert_eq!(install["pending_update"], true, "{staged}");
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
        reason: "Review the update".into(),
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
    Ok(k::app_installs::adopt_as(
        &w.db,
        &me,
        &native_app_hosted_caller(account, &pin, true),
        adopt,
    )
    .await?
    .outcome
    .generation)
}

fn entry_of(list: &Value) -> Value {
    list["shelf"]["entries"][0].clone()
}

async fn running(w: &World, account: &str, version: &str, generation: &str, id: &str) -> String {
    status_as(&w.db, &app_at(account, version, generation), id)
        .await
        .unwrap()
}

async fn tab_order(w: &World, account: &str) -> Value {
    list_as(&w.db, account).await["tab_order"].clone()
}

// Design test 9, unchanged declaration: each member keeps consent, folder grant
// and order, and moves only when they themself do. Old pins keep running
// before, during and after the shelf moves on.
#[tokio::test]
async fn an_update_with_an_unchanged_declaration_carries_each_members_consent_grant_and_order() {
    let w = world("personal.owner-slides").await;
    let v1 = add_to_shelf(&w).await;
    let (gen_a, _) = enable(&w, "account-a", &v1, Some(folder("folder")))
        .await
        .unwrap();
    let (gen_b, _) = enable(&w, "account-b", &v1, Some(folder("folderb")))
        .await
        .unwrap();
    let order_b = tab_order(&w, "account-b").await;
    let b_before = row_of(&w.db, &w.b, PKG).await.unwrap();

    // The shelf moves on: a newer version supersedes the live entry.
    let newer = release(NEWER, "0.6.0");
    let v2 = shelf_release(&w, &newer, "k2").await;
    assert_ne!(v2["shelf_event_id"], v1["shelf_event_id"]);
    assert_eq!(v2["version"], "0.6.0");
    let listed = list_as(&w.db, "account-a").await;
    assert_eq!(
        listed["shelf"]["entries"].as_array().unwrap().len(),
        1,
        "one live entry per package: the newer pin supersedes"
    );
    assert_eq!(entry_of(&listed)["shelf_event_id"], v2["shelf_event_id"]);
    assert_eq!(my_status(&listed), "needs_update");
    assert_eq!(
        entry_of(&listed)["update"],
        json!({"from":"shelf","consent":"unchanged","candidate_version":"0.6.0","candidate_matches":false,"shelf_event_id":v2["shelf_event_id"]})
    );

    // Nothing moved on its own, and both old pins keep running.
    assert_eq!(row_of(&w.db, &w.b, PKG).await.unwrap(), b_before);
    assert_eq!(
        running(&w, "account-a", "0.5.0", &gen_a, "task").await,
        "found"
    );
    assert_eq!(
        running(&w, "account-b", "0.5.0", &gen_b, "bdoc").await,
        "found"
    );

    // George moves: silently, with his grant and order, and Richard is untouched.
    let a_before = row_of(&w.db, &w.a, PKG).await.unwrap();
    let start = head(&w.db).await;
    let moved = move_to(&w, "account-b", &v2).await.unwrap();
    assert_eq!(moved["changed"], true, "{moved}");
    assert_ne!(moved["install"]["pending_update"], true, "{moved}");
    assert_eq!(moved["install"]["adoption_basis"], "carried");
    let events = install_events(&w.db, start).await;
    assert_eq!(events.len(), 1, "one recorded event, no prompt: {events:?}");
    assert_eq!(events[0].1.as_deref(), Some(w.b.as_str()));
    let b_after = row_of(&w.db, &w.b, PKG).await.unwrap();
    assert_eq!(b_after["version"], "0.6.0");
    assert_eq!(b_after["shelf_event_id"], v2["shelf_event_id"]);
    assert_eq!(b_after["scope"], b_before["scope"], "grant carried");
    assert_eq!(b_after["scope"]["folder_ids"], json!(["folderb"]));
    assert_eq!(b_after["adoption"], "shell_adopt.v1");
    assert_eq!(tab_order(&w, "account-b").await, order_b, "order kept");
    assert_eq!(row_of(&w.db, &w.a, PKG).await.unwrap(), a_before);
    assert_eq!(
        running(&w, "account-a", "0.5.0", &gen_a, "task").await,
        "found",
        "Richard still runs the pin he consented to"
    );
    let gen_b2 = b_after["event_id"].as_str().unwrap().to_owned();
    assert_eq!(
        running(&w, "account-b", "0.6.0", &gen_b2, "bdoc").await,
        "found"
    );
    // George's grant still confines him after the move.
    assert!(
        status_as(&w.db, &app_at("account-b", "0.6.0", &gen_b2), "task")
            .await
            .is_err(),
        "outside his folder grant"
    );

    // Richard then moves too, and keeps his own different grant.
    move_to(&w, "account-a", &v2).await.unwrap();
    let a_after = row_of(&w.db, &w.a, PKG).await.unwrap();
    assert_eq!(a_after["scope"]["folder_ids"], json!(["folder"]));
    assert_eq!(a_after["shelf_event_id"], v2["shelf_event_id"]);
    assert_eq!(my_status(&list_as(&w.db, "account-a").await), "installed");

    // Moving again at the same pin is refused rather than rewriting anything.
    assert!(move_to(&w, "account-a", &v2).await.is_err());

    let projected = k::dump_all_kernel_tables(&w.db).await.unwrap();
    k::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(projected, k::dump_all_kernel_tables(&w.db).await.unwrap());
    k::verify_v2_ready(&w.db).await.unwrap();
}

// Design test 9, consent asked again: a move that cannot carry (here, personal
// rows whose adoption is only a legacy import label, not a verified v2 root)
// stages a pending update. Each member is asked separately; the running row
// and everyone else's row are untouched until that member consents.
//
// Note: in the engine "access expands" takes this same non-carry branch
// (declaration digest differs), but the catalogue contract `native.app.v2`
// fixes an empty declaration, so a real expansion cannot be built from a
// catalogue pin yet.
#[tokio::test]
async fn a_move_that_cannot_carry_asks_each_member_separately_and_touches_nobody_else() {
    let w = world(PKG).await;
    // The personal source must be readable by its members for the apps to run.
    k::rehome_record_as(&w.db, &w.a, "secret", KERNEL_ROOT_ID)
        .await
        .unwrap();
    let v1 = add_to_shelf(&w).await;
    let before = rows(&w.db).await;
    assert_eq!(before.len(), 2);
    let gen_of = |p: &str| before.iter().find(|r| r.0 == p).unwrap().3.clone();
    let (a_before, b_before) = (
        row_of(&w.db, &w.a, PKG).await.unwrap(),
        row_of(&w.db, &w.b, PKG).await.unwrap(),
    );

    let staged = move_to(&w, "account-a", &v1).await.unwrap();
    assert_eq!(staged["install"]["pending_update"], true, "{staged}");
    assert_eq!(row_of(&w.db, &w.a, PKG).await.unwrap(), a_before);
    assert_eq!(row_of(&w.db, &w.b, PKG).await.unwrap(), b_before);
    assert_eq!(
        running(&w, "account-a", "0.4.0", &gen_of(&w.a), "task").await,
        "found"
    );

    consent_to(&w, "account-a", &staged, Some(folder("folder")))
        .await
        .unwrap();
    let a_after = row_of(&w.db, &w.a, PKG).await.unwrap();
    assert_eq!(a_after["shelf_event_id"], v1["shelf_event_id"]);
    assert_eq!(a_after["artifact_id"], v1["artifact_id"]);
    assert_eq!(row_of(&w.db, &w.b, PKG).await.unwrap(), b_before);
    assert_eq!(
        running(&w, "account-b", "0.4.0", &gen_of(&w.b), "task").await,
        "found"
    );

    let staged = move_to(&w, "account-b", &v1).await.unwrap();
    assert_eq!(staged["install"]["pending_update"], true, "{staged}");
    consent_to(&w, "account-b", &staged, Some(folder("folderb")))
        .await
        .unwrap();
    assert_eq!(
        row_of(&w.db, &w.b, PKG).await.unwrap()["shelf_event_id"],
        v1["shelf_event_id"]
    );
    let projected = k::dump_all_kernel_tables(&w.db).await.unwrap();
    k::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(projected, k::dump_all_kernel_tables(&w.db).await.unwrap());
    k::verify_v2_ready(&w.db).await.unwrap();
}

// R3: no update path lets one member change another's consented pin, and the
// owner of the shared artifact cannot publish over what members consented to.
#[tokio::test]
async fn no_update_path_alters_another_members_consented_pin() {
    let w = world("personal.owner-slides").await;
    let v1 = add_to_shelf(&w).await;
    let (gen_a, _) = enable(&w, "account-a", &v1, Some(folder("folder")))
        .await
        .unwrap();
    let (gen_b, _) = enable(&w, "account-b", &v1, Some(folder("folderb")))
        .await
        .unwrap();
    let newer = release(NEWER, "0.6.0");
    let v2 = shelf_release(&w, &newer, "k2").await;
    let rows_before = rows(&w.db).await;
    let start = head(&w.db).await;

    // A superseded entry cannot be used to (re)move anyone onto an old pin.
    let stale = call_with(
        &w.db,
        who("account-b"),
        &newer,
        enable_args(v1["shelf_event_id"].as_str().unwrap(), "stale"),
    )
    .await;
    assert!(stale.is_err(), "stale shelf entry: {stale:?}");
    // The shared source cannot be consented to by explicit pin fields.
    let explicit = call_with(
        &w.db,
        who("account-b"),
        &newer,
        json!({"action":"install","package":PKG,"version":"0.6.0","digest":v2["digest"],
            "artifact_id":v2["artifact_id"],"source_revision":v2["source_revision"],
            "declaration":{"contract":"native.app.v2","needs":[],"effects":[]},
            "reason":"x","expected_install_event_id":gen_b}),
    )
    .await;
    assert!(explicit.is_err(), "explicit pin: {explicit:?}");
    // George cannot drive Richard's row through any action.
    for (name, args) in [
        (
            "remove",
            json!({"action":"remove","package":PKG,"expected_install_event_id":gen_a,"reason":"x"}),
        ),
        (
            "disable",
            json!({"action":"disable","package":PKG,"expected_install_event_id":gen_a,"reason":"x"}),
        ),
    ] {
        let outcome = call_with(&w.db, who("account-b"), &newer, args).await;
        // Whatever it does, it acts on George's own row (the generation does
        // not match), so it must not succeed against Richard's.
        assert!(
            outcome.is_err(),
            "{name} with Richard's generation: {outcome:?}"
        );
    }
    // The owner of the shared artifact cannot publish over it, with others
    // consented and (below) even when no one else is.
    let owner_footing = owner();
    let source = v1["artifact_id"].as_str().unwrap();
    let publish = json!({"action":"publish_catalog_update","artifact_id":source,"package":PKG,
        "version":"0.6.0","expected_install_event_id":gen_a,
        "expected_body_digest":crate::mcp::tools::lifecycle::body_digest(Some(NEW)),
        "reason":"publish over the shared source"});
    let published = call_with(&w.db, owner_footing.clone(), &newer, publish.clone()).await;
    assert!(published.is_err(), "owner publish: {published:?}");
    assert!(
        published
            .unwrap_err()
            .to_string()
            .contains("adding the new version to the shelf"),
        "the shelf guard names the real path"
    );
    assert_eq!(head(&w.db).await, start, "refusals append nothing");
    assert_eq!(rows(&w.db).await, rows_before);

    // Remove George's consent so Richard is the only holder: the owner still
    // cannot publish over the shared artifact in place.
    call_with(
        &w.db,
        who("account-b"),
        &newer,
        json!({"action":"remove","package":PKG,"expected_install_event_id":gen_b,"reason":"leave"}),
    )
    .await
    .unwrap();
    let published = call_with(&w.db, owner_footing, &newer, publish).await;
    assert!(
        published.is_err(),
        "sole-holder owner publish: {published:?}"
    );

    // A real move writes only the mover's own aggregate.
    let start = head(&w.db).await;
    move_to(&w, "account-a", &v2).await.unwrap();
    let events = install_events(&w.db, start).await;
    assert!(!events.is_empty());
    let aggregates: std::collections::BTreeSet<_> = events.iter().map(|e| e.2.clone()).collect();
    assert_eq!(aggregates.len(), 1);
    assert!(events
        .iter()
        .all(|(_, actor, _)| actor.as_deref() == Some(w.a.as_str())));
    k::replay_all_projections(&w.db).await.unwrap();
    k::verify_v2_ready(&w.db).await.unwrap();
}

/// Establish a real v2 adoption root for `account`'s imported personal install
/// (the imported fixture rows carry only a legacy label, which cannot carry).
async fn adopt_root(w: &World, account: &str) -> String {
    let me = principal(&w.db, account).await;
    let install = row_of(&w.db, &me, PKG).await.unwrap();
    let pin = InstallRequest {
        package: PKG.into(),
        version: install["version"].as_str().unwrap().into(),
        digest: install["digest"].as_str().unwrap().into(),
        artifact_id: install["artifact_id"].as_str().unwrap().into(),
        source_revision: install["consented_source_revision"]
            .as_str()
            .unwrap()
            .into(),
        declaration: serde_json::from_str(install["consented_declaration"].as_str().unwrap())
            .unwrap(),
        reason: "Establish a verified v2 adoption root".into(),
        request: None,
        idempotency_key: None,
        expected_install_event_id: Some(install["event_id"].as_str().unwrap().into()),
    };
    let preview = k::app_installs::preview_as(
        &w.db,
        &me,
        &native_app_hosted_caller(account, &pin, false).with_hosting_owner(true),
        pin.clone(),
    )
    .await
    .unwrap();
    k::app_installs::adopt_as(
        &w.db,
        &me,
        &native_app_hosted_caller(account, &pin, true).with_hosting_owner(true),
        AdoptRequest {
            scope: None,
            pin,
            receipt_id: preview.receipt.receipt_id,
            nonce: preview.receipt.nonce,
            preview_session: preview.receipt.preview_session,
        },
    )
    .await
    .unwrap()
    .outcome
    .generation
}

// Design test 11: HQ-style personal rows survive a shelf add byte for byte and
// keep running through shelf changes; a lazy move onto the shared source keeps
// consent, scope and order; a differing declaration is not moved.
#[tokio::test]
async fn existing_personal_installs_survive_the_shelf_and_move_lazily_with_consent_scope_and_order()
{
    // Richard, George and Hana all have a personal agent.docs install.
    let w = world(PKG).await;
    // The personal source must be readable by its members for the apps to run.
    k::rehome_record_as(&w.db, &w.a, "secret", KERNEL_ROOT_ID)
        .await
        .unwrap();
    let before = rows(&w.db).await;
    assert_eq!(before.len(), 2);
    let orders: Vec<_> = {
        let mut v = Vec::new();
        for account in ["account-a", "account-b"] {
            v.push(tab_order(&w, account).await);
        }
        v
    };
    let personal_gen = |rows: &[(String, String, String, String, String)], p: &str| {
        rows.iter().find(|r| r.0 == p).unwrap().3.clone()
    };

    // Adding to the shelf, then removing it, changes nothing for personal rows.
    let v1 = add_to_shelf(&w).await;
    assert_eq!(
        rows(&w.db).await,
        before,
        "shelf add rewrites no personal row"
    );
    for (account, p) in [("account-a", &w.a), ("account-b", &w.b)] {
        let listed = list_as(&w.db, account).await;
        assert_eq!(my_status(&listed), "installed", "{account}");
        assert_eq!(
            entry_of(&listed)["update"]["from"],
            "personal",
            "{account} is told a move exists"
        );
        // A legacy-imported row has no v2 adoption root, so a move would ask.
        assert_eq!(entry_of(&listed)["update"]["consent"], "required");
        assert_eq!(
            running(&w, account, "0.4.0", &personal_gen(&before, p), "task").await,
            "found"
        );
    }
    call(
        &w.db,
        who("account-a"),
        "manage_alpha_tabs",
        remove(v1["shelf_event_id"].as_str().unwrap()),
    )
    .await
    .unwrap();
    assert_eq!(
        rows(&w.db).await,
        before,
        "shelf removal does not touch personal-origin rows"
    );
    assert_eq!(
        running(
            &w,
            "account-b",
            "0.4.0",
            &personal_gen(&before, &w.b),
            "task"
        )
        .await,
        "found",
        "a personal row keeps running through shelf removal"
    );
    // Re-add (a new live entry), then give George a real adoption root, a
    // grant and an order, and leave Richard and Hana legacy.
    let v1 = call(&w.db, who("account-a"), "manage_alpha_tabs", add("k-readd"))
        .await
        .unwrap()["entry"]
        .clone();
    adopt_root(&w, "account-b").await;
    call(
        &w.db,
        who("account-b"),
        "manage_alpha_tabs",
        json!({"action":"set_scope","package":PKG,"scope":folder("folderb")}),
    )
    .await
    .unwrap();
    let order_b = tab_order(&w, "account-b").await;
    let rows_mid = rows(&w.db).await;
    let b_personal = row_of(&w.db, &w.b, PKG).await.unwrap();
    assert!(b_personal.get("shelf_event_id").is_none());
    assert_eq!(
        entry_of(&list_as(&w.db, "account-b").await)["update"],
        json!({"from":"personal","consent":"unchanged","candidate_version":"0.5.0","candidate_matches":false,"shelf_event_id":v1["shelf_event_id"]})
    );

    // George moves: consent, scope and order carry; the row gains the shelf id.
    let moved = move_to(&w, "account-b", &v1).await.unwrap();
    assert_eq!(moved["install"]["adoption_basis"], "carried", "{moved}");
    let b_after = row_of(&w.db, &w.b, PKG).await.unwrap();
    assert_eq!(b_after["shelf_event_id"], v1["shelf_event_id"]);
    assert_eq!(b_after["artifact_id"], v1["artifact_id"]);
    assert_eq!(b_after["scope"], b_personal["scope"]);
    assert_eq!(b_after["scope"]["folder_ids"], json!(["folderb"]));
    assert_eq!(b_after["adoption"], "shell_adopt.v1");
    assert_eq!(tab_order(&w, "account-b").await, order_b);
    // Nobody else's row moved or changed by a byte.
    let others = |all: Vec<(String, String, String, String, String)>| -> Vec<_> {
        all.into_iter().filter(|r| r.0 != w.b).collect()
    };
    assert_eq!(others(rows(&w.db).await), others(rows_mid));
    assert_eq!(tab_order(&w, "account-a").await, orders[0]);

    // After the move George follows shelf semantics; Richard (not moved) does not.
    call(
        &w.db,
        who("account-a"),
        "manage_alpha_tabs",
        remove(v1["shelf_event_id"].as_str().unwrap()),
    )
    .await
    .unwrap();
    let gen_b = b_after["event_id"].as_str().unwrap();
    let stopped = status_as(&w.db, &app_at("account-b", "0.5.0", gen_b), "task").await;
    assert!(
        stopped
            .as_ref()
            .is_err_and(|e| e.contains("workspace_removed")),
        "a moved row stops with the shelf: {stopped:?}"
    );
    assert_eq!(
        running(
            &w,
            "account-a",
            "0.4.0",
            &personal_gen(&before, &w.a),
            "task"
        )
        .await,
        "found"
    );

    let projected = k::dump_all_kernel_tables(&w.db).await.unwrap();
    k::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(projected, k::dump_all_kernel_tables(&w.db).await.unwrap());
    k::verify_v2_ready(&w.db).await.unwrap();
}
