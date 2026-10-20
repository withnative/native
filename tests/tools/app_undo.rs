//! Undo an app's writes since T — engine preview and apply (task `650d870`,
//! plan `182cd53`, increment 1).
//!
//! Every app write here goes through the production registry with a
//! host-asserted app on a real adopted v2 install, so the undo selects
//! exactly what I5 attribution recorded.

use std::time::Duration;

use native_ce::mcp::app_attribution::AppAttribution;
use native_ce::mcp::tools::app_undo::{
    apply_app_undo, preview_app_undo, AppUndoOutcome, AppUndoRequest, UndoItem, UndoStatus,
};
use native_ce::mcp::{Caller, ToolRegistry};
use native_ce::Db;
use serde_json::{json, Value};

use crate::alpha_tabs::{
    adopted_package_with_declaration_as, adopted_with_declaration, adopted_with_declaration_as,
    call_as, configure_preview_launch, v2_declaration, ALICE, BEA,
};

/// The package `adopted_with_declaration` installs.
const PACKAGE: &str = "agent.search";
const ALICE_PERSON: &str = "a1d00000-0000-4000-8000-0000000000a1";
const BEA_PERSON: &str = "a1d00000-0000-4000-8000-0000000000b1";

async fn fixture() -> (Db, ToolRegistry) {
    configure_preview_launch();
    let db = native_ce::create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    native_ce::mcp::register_surface_tools(&mut registry).unwrap();
    // Each account needs a portable person binding to create records.
    for (person, account) in [(ALICE_PERSON, ALICE), (BEA_PERSON, BEA)] {
        registry
            .call(
                db.clone(),
                Caller::local(),
                "create_record",
                json!({
                    "id": person, "type": "Entity", "kind": "person", "name": account,
                    "reason": "Person fixture for the app undo tests."
                }),
            )
            .await
            .unwrap();
        let principal = format!("native/{account}");
        for (system, identifier) in [
            ("native-principal", principal.as_str()),
            ("account", account),
        ] {
            sqlx::query(
                "INSERT INTO bindings(record_id,system,identifier,is_canonical) VALUES(?,?,?,1)",
            )
            .bind(person)
            .bind(system)
            .bind(identifier)
            .execute(&crate::common::fixture_write_pool(&db).await)
            .await
            .unwrap();
        }
    }
    (db, registry)
}

fn app_caller(account: &str, install: &str) -> Caller {
    Caller::authenticated(account)
        .with_host_asserted_app(AppAttribution::new(PACKAGE, "0.1.0", install).unwrap())
}

async fn create_note(registry: &ToolRegistry, db: &Db, caller: Caller, name: &str) -> String {
    let created = call_as(
        registry,
        db,
        caller,
        "create_record",
        json!({"type": "Document", "kind": "note", "name": name,
               "summary": format!("{name} summary"), "body": format!("{name} body"),
               "reason": "Note for the app undo tests."}),
    )
    .await
    .unwrap();
    created["id"].as_str().unwrap().to_string()
}

async fn update(registry: &ToolRegistry, db: &Db, caller: Caller, id: &str, fields: Value) {
    let mut arguments = fields;
    arguments["id"] = json!(id);
    arguments["reason"] = json!("Update for the app undo tests.");
    call_as(registry, db, caller, "update_record", arguments)
        .await
        .unwrap();
}

/// A `since` strictly after everything written so far.
async fn mark_time() -> String {
    tokio::time::sleep(Duration::from_millis(15)).await;
    let since = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    tokio::time::sleep(Duration::from_millis(15)).await;
    since
}

fn request(since: &str) -> AppUndoRequest {
    AppUndoRequest {
        package: PACKAGE.into(),
        since: since.into(),
        version: None,
        reason: "Undo what the app did since the test began.".into(),
    }
}

fn item<'a>(outcome: &'a AppUndoOutcome, record_id: &str, aspect: &str) -> &'a UndoItem {
    outcome
        .items
        .iter()
        .find(|item| item.record_id == record_id && item.aspect == aspect)
        .unwrap_or_else(|| panic!("no {aspect} item for {record_id}: {:#?}", outcome.items))
}

async fn field(db: &Db, id: &str, column: &str) -> Option<String> {
    sqlx::query_scalar(&format!("SELECT {column} FROM records WHERE id = ?"))
        .bind(id)
        .fetch_one(&crate::common::fixture_write_pool(db).await)
        .await
        .unwrap()
}

async fn facet(db: &Db, id: &str, key: &str) -> Option<String> {
    sqlx::query_scalar("SELECT value FROM facet_values WHERE record_id = ? AND key = ?")
        .bind(id)
        .bind(key)
        .fetch_optional(&crate::common::fixture_write_pool(db).await)
        .await
        .unwrap()
}

/// A relationship-owned link (`relates_to`) is live while its legacy-link
/// relationship is effective.
async fn related(db: &Db, source: &str, target: &str) -> bool {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM relationships r
           JOIN relationship_endpoints s USING (relationship_origin_db_id, relationship_id)
           JOIN relationship_endpoints t USING (relationship_origin_db_id, relationship_id)
           JOIN effective_relationships e USING (relationship_origin_db_id, relationship_id)
          WHERE r.relationship_type = 'relates_to'
            AND s.role = 'source' AND s.record_id = ?
            AND t.role = 'target' AND t.record_id = ?
            AND e.effective_state = 'active'",
    )
    .bind(source)
    .bind(target)
    .fetch_one(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap()
        > 0
}

/// A plain content link (`derived_from`) lives in `links`.
async fn derived(db: &Db, source: &str, target: &str) -> bool {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM links WHERE source_id = ? AND target_id = ? AND relationship = 'derived_from'",
    )
    .bind(source)
    .bind(target)
    .fetch_one(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap()
        > 0
}

async fn event_count(db: &Db) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(&crate::common::fixture_write_pool(db).await)
        .await
        .unwrap()
}

#[tokio::test]
async fn preview_lists_app_writes_and_apply_reverts_them_leaving_the_users_own() {
    let (db, registry) = fixture().await;
    let install = adopted_with_declaration(&registry, &db, v2_declaration()).await;
    let alice = || Caller::authenticated(ALICE);
    let app = || app_caller(ALICE, &install);

    let edited = create_note(&registry, &db, alice(), "edited").await;
    let target = create_note(&registry, &db, alice(), "target").await;
    let archived = create_note(&registry, &db, alice(), "archived").await;
    let untouched = create_note(&registry, &db, alice(), "untouched").await;
    // Written by the app before T: outside the window, never reverted.
    update(&registry, &db, app(), &edited, json!({"maturity": "draft"})).await;
    let since = mark_time().await;

    // The app's writes since T.
    let created = create_note(&registry, &db, app(), "made by the app").await;
    update(
        &registry,
        &db,
        app(),
        &edited,
        json!({"name": "renamed by the app", "summary": "summary by the app",
               "body_append": "\nappended by the app", "facets": {"colour": "blue"}}),
    )
    .await;
    for relationship in ["relates_to", "derived_from"] {
        call_as(
            &registry,
            &db,
            app(),
            "manage_links",
            json!({"action": "add", "source_id": edited, "target_id": target,
                   "relationship": relationship}),
        )
        .await
        .unwrap();
    }
    assert!(related(&db, &edited, &target).await);
    assert!(derived(&db, &edited, &target).await);
    call_as(
        &registry,
        &db,
        app(),
        "archive_record",
        json!({"id": archived, "reason": "The app archived it."}),
    )
    .await
    .unwrap();

    // The user's own writes, directly, after the app's.
    update(
        &registry,
        &db,
        alice(),
        &edited,
        json!({"facets": {"mood": "calm"}}),
    )
    .await;
    update(
        &registry,
        &db,
        alice(),
        &untouched,
        json!({"summary": "the user's own summary"}),
    )
    .await;

    let before_preview = event_count(&db).await;
    let preview = preview_app_undo(&db, &alice(), &request(&since))
        .await
        .unwrap();
    assert_eq!(
        event_count(&db).await,
        before_preview,
        "preview writes nothing"
    );
    assert!(!preview.applied);
    for (record, aspect) in [
        (&created, "existence"),
        (&edited, "field:name"),
        (&edited, "field:summary"),
        (&edited, "body"),
        (&edited, "facet:colour"),
        (&edited, &format!("link:relates_to:{target}")),
        (&edited, &format!("link:derived_from:{target}")),
        (&archived, "facet:archived"),
    ] {
        let planned = item(&preview, record, aspect);
        assert_eq!(planned.status, UndoStatus::Revert, "{planned:#?}");
        assert!(!planned.reverses.is_empty(), "{planned:#?}");
    }
    let summary = item(&preview, &edited, "field:summary");
    assert_eq!(summary.from, Some(json!("summary by the app")));
    assert_eq!(summary.to, Some(json!("edited summary")));
    assert!(
        preview.items.iter().all(|item| item.record_id != untouched
            && item.aspect != "field:maturity"
            && item.aspect != "facet:mood"),
        "the user's own writes and the app's pre-T writes are not planned: {:#?}",
        preview.items
    );

    let applied = apply_app_undo(&db, &alice(), &request(&since))
        .await
        .unwrap();
    assert!(applied.applied);
    assert_eq!(applied.count(UndoStatus::Revert), 0);
    assert_eq!(
        applied.count(UndoStatus::Reverted),
        8,
        "{:#?}",
        applied.items
    );
    assert_eq!(
        applied.action_attestation_ids.len(),
        1,
        "the undo is one attested action"
    );

    // The app's writes are reverted.
    assert_eq!(
        facet(&db, &created, "archived").await.as_deref(),
        Some("true")
    );
    assert_eq!(field(&db, &edited, "name").await.as_deref(), Some("edited"));
    assert_eq!(
        field(&db, &edited, "summary").await.as_deref(),
        Some("edited summary")
    );
    assert_eq!(
        field(&db, &edited, "body").await.as_deref(),
        Some("edited body")
    );
    assert_eq!(facet(&db, &edited, "colour").await, None);
    assert!(!related(&db, &edited, &target).await);
    assert!(!derived(&db, &edited, &target).await);
    assert_eq!(facet(&db, &archived, "archived").await, None);
    // The user's own writes, and the app's write before T, are untouched.
    assert_eq!(facet(&db, &edited, "mood").await.as_deref(), Some("calm"));
    assert_eq!(
        field(&db, &untouched, "summary").await.as_deref(),
        Some("the user's own summary")
    );
    assert_eq!(
        field(&db, &edited, "maturity").await.as_deref(),
        Some("draft")
    );

    // One attestation, under the undo operation, covering every inverse
    // event; the person is the actor and no app is attributed.
    let pool = crate::common::fixture_write_pool(&db).await;
    let attestation = &applied.action_attestation_ids[0];
    let operation: String =
        sqlx::query_scalar("SELECT operation FROM provenance_action_attestations WHERE id = ?")
            .bind(attestation)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(operation, "undo_app_writes");
    let mut attested: Vec<String> = sqlx::query_scalar(
        "SELECT output_event_id FROM provenance_action_outputs WHERE action_attestation_id = ?",
    )
    .bind(attestation)
    .fetch_all(&pool)
    .await
    .unwrap();
    let mut written: Vec<String> = applied
        .items
        .iter()
        .flat_map(|item| item.written.iter().cloned())
        .collect();
    attested.sort();
    written.sort();
    assert_eq!(attested, written);
    let (others, app_rows): (i64, i64) = sqlx::query_as(
        "SELECT
           (SELECT COUNT(*) FROM content_events e
              JOIN provenance_action_outputs o ON o.output_event_id = e.id
             WHERE o.action_attestation_id = ?1 AND e.actor IS NOT 'alice'),
           (SELECT COUNT(*) FROM provenance_action_app_attributions
             WHERE action_attestation_id = ?1)",
    )
    .bind(attestation)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((others, app_rows), (0, 0));
    let content_markers: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT id, json_extract(payload, '$.undo.package') FROM content_events
          WHERE id IN (SELECT value FROM json_each(?))",
    )
    .bind(serde_json::to_string(&written).unwrap())
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(
        !content_markers.is_empty(),
        "at least one written event is a content event: {written:?}"
    );
    for (id, marker) in content_markers {
        assert_eq!(marker.as_deref(), Some(PACKAGE), "content event {id}");
    }

    // Re-running the apply changes nothing.
    let before_rerun = event_count(&db).await;
    let rerun = apply_app_undo(&db, &alice(), &request(&since))
        .await
        .unwrap();
    assert_eq!(event_count(&db).await, before_rerun);
    assert_eq!(rerun.count(UndoStatus::Reverted), 0, "{:#?}", rerun.items);
    assert_eq!(rerun.count(UndoStatus::Conflict), 0, "{:#?}", rerun.items);
    assert_eq!(rerun.count(UndoStatus::Unchanged), 8, "{:#?}", rerun.items);
    assert!(rerun.action_attestation_ids.is_empty());
}

#[tokio::test]
async fn a_later_edit_by_someone_else_is_reported_and_not_overwritten() {
    let (db, registry) = fixture().await;
    let install = adopted_with_declaration(&registry, &db, v2_declaration()).await;
    let alice = || Caller::authenticated(ALICE);
    let note = create_note(&registry, &db, alice(), "shared").await;
    let since = mark_time().await;

    update(
        &registry,
        &db,
        app_caller(ALICE, &install),
        &note,
        json!({"name": "renamed by the app", "summary": "summary by the app"}),
    )
    .await;
    // Someone else edits the summary after the app did.
    update(
        &registry,
        &db,
        Caller::local(),
        &note,
        json!({"summary": "summary by someone else"}),
    )
    .await;

    let preview = preview_app_undo(&db, &alice(), &request(&since))
        .await
        .unwrap();
    let conflict = item(&preview, &note, "field:summary");
    assert_eq!(conflict.status, UndoStatus::Conflict, "{conflict:#?}");
    assert_eq!(conflict.reason.as_deref(), Some("edited_since"));
    assert_eq!(
        conflict.conflict.as_ref().and_then(|c| c.actor.as_deref()),
        Some("local")
    );
    assert_eq!(
        item(&preview, &note, "field:name").status,
        UndoStatus::Revert
    );

    let applied = apply_app_undo(&db, &alice(), &request(&since))
        .await
        .unwrap();
    assert_eq!(
        item(&applied, &note, "field:summary").status,
        UndoStatus::Conflict
    );
    assert_eq!(
        item(&applied, &note, "field:name").status,
        UndoStatus::Reverted
    );
    assert_eq!(
        field(&db, &note, "summary").await.as_deref(),
        Some("summary by someone else"),
        "the later edit is not overwritten"
    );
    assert_eq!(field(&db, &note, "name").await.as_deref(), Some("shared"));

    // Still reported, still not written, on a re-run.
    let before = event_count(&db).await;
    let rerun = apply_app_undo(&db, &alice(), &request(&since))
        .await
        .unwrap();
    assert_eq!(event_count(&db).await, before);
    assert_eq!(
        item(&rerun, &note, "field:summary").status,
        UndoStatus::Conflict
    );
    assert_eq!(
        item(&rerun, &note, "field:name").status,
        UndoStatus::Unchanged
    );
}

#[tokio::test]
async fn another_accounts_app_writes_are_never_touched() {
    let (db, registry) = fixture().await;
    let alice_install = adopted_with_declaration(&registry, &db, v2_declaration()).await;
    let bea_install = adopted_with_declaration_as(&registry, &db, BEA, v2_declaration()).await;
    let bea_note = create_note(&registry, &db, Caller::authenticated(BEA), "bea's").await;
    let since = mark_time().await;

    // Bea's install of the same package writes to Bea's records.
    let bea_created = create_note(
        &registry,
        &db,
        app_caller(BEA, &bea_install),
        "made by bea's app",
    )
    .await;
    update(
        &registry,
        &db,
        app_caller(BEA, &bea_install),
        &bea_note,
        json!({"summary": "summary by bea's app"}),
    )
    .await;
    // Alice's install writes one note.
    let alice_created = create_note(
        &registry,
        &db,
        app_caller(ALICE, &alice_install),
        "made by alice's app",
    )
    .await;

    let preview = preview_app_undo(&db, &Caller::authenticated(ALICE), &request(&since))
        .await
        .unwrap();
    assert_eq!(
        item(&preview, &alice_created, "existence").status,
        UndoStatus::Revert
    );
    assert!(
        preview
            .items
            .iter()
            .all(|item| item.record_id != bea_note && item.record_id != bea_created),
        "{:#?}",
        preview.items
    );

    let applied = apply_app_undo(&db, &Caller::authenticated(ALICE), &request(&since))
        .await
        .unwrap();
    assert_eq!(
        applied.count(UndoStatus::Reverted),
        1,
        "{:#?}",
        applied.items
    );
    assert_eq!(
        facet(&db, &alice_created, "archived").await.as_deref(),
        Some("true")
    );
    assert_eq!(facet(&db, &bea_created, "archived").await, None);
    assert_eq!(
        field(&db, &bea_note, "summary").await.as_deref(),
        Some("summary by bea's app")
    );
}

#[tokio::test]
async fn unsupported_outputs_are_listed_not_written() {
    let (db, registry) = fixture().await;
    let install = adopted_with_declaration(&registry, &db, v2_declaration()).await;
    let alice = || Caller::authenticated(ALICE);
    let doomed = create_note(&registry, &db, alice(), "doomed").await;
    let since = mark_time().await;
    call_as(
        &registry,
        &db,
        app_caller(ALICE, &install),
        "delete_record",
        json!({"id": doomed, "reason": "The app deleted it."}),
    )
    .await
    .unwrap();

    let before = event_count(&db).await;
    let applied = apply_app_undo(&db, &alice(), &request(&since))
        .await
        .unwrap();
    assert_eq!(event_count(&db).await, before);
    let deleted = item(&applied, &doomed, "record");
    assert_eq!(deleted.status, UndoStatus::Unsupported);
    assert_eq!(deleted.reason.as_deref(), Some("deleted"));
    assert!(applied.action_attestation_ids.is_empty());
}

#[tokio::test]
async fn malformed_requests_are_refused() {
    let (db, _registry) = fixture().await;
    let alice = Caller::authenticated(ALICE);
    for (package, since, reason) in [
        ("", "2026-10-07T00:00:00Z", "r"),
        (PACKAGE, "yesterday", "r"),
        (PACKAGE, "2026-10-07T00:00:00Z", " "),
    ] {
        let request = AppUndoRequest {
            package: package.into(),
            since: since.into(),
            version: None,
            reason: reason.into(),
        };
        assert!(preview_app_undo(&db, &alice, &request).await.is_err());
        assert!(apply_app_undo(&db, &alice, &request).await.is_err());
    }
}

#[tokio::test]
async fn an_app_folder_with_members_is_reported_and_the_rest_still_reverts() {
    let (db, registry) = fixture().await;
    let install = adopted_with_declaration(&registry, &db, v2_declaration()).await;
    let alice = || Caller::authenticated(ALICE);
    let app = || app_caller(ALICE, &install);
    let since = mark_time().await;

    let folder = call_as(
        &registry,
        &db,
        app(),
        "create_record",
        json!({"type": "Collection", "kind": "folder", "name": "app folder",
               "reason": "The app makes a folder."}),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let loose = create_note(&registry, &db, app(), "loose app note").await;
    // The user files their own note in the app's folder.
    let filed = call_as(
        &registry,
        &db,
        alice(),
        "create_record",
        json!({"type": "Document", "kind": "note", "name": "filed by the user",
               "home_id": folder, "reason": "The user files a note in the app's folder."}),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    let applied = apply_app_undo(&db, &alice(), &request(&since))
        .await
        .unwrap();
    let blocked = item(&applied, &folder, "existence");
    assert_eq!(blocked.status, UndoStatus::Conflict, "{blocked:#?}");
    assert_eq!(blocked.reason.as_deref(), Some("has_members"));
    assert_eq!(
        item(&applied, &loose, "existence").status,
        UndoStatus::Reverted
    );
    assert_eq!(facet(&db, &folder, "archived").await, None);
    assert_eq!(facet(&db, &filed, "archived").await, None);
    assert_eq!(
        facet(&db, &loose, "archived").await.as_deref(),
        Some("true")
    );
}

#[tokio::test]
async fn overwritten_foreign_edits_revert_and_the_users_own_later_edit_is_a_conflict() {
    let (db, registry) = fixture().await;
    let install = adopted_with_declaration(&registry, &db, v2_declaration()).await;
    let alice = || Caller::authenticated(ALICE);
    let app = || app_caller(ALICE, &install);
    let note = create_note(&registry, &db, alice(), "contested").await;
    let since = mark_time().await;

    // Someone else's summary edit that the app itself later overwrote is
    // already gone, so reverting the app's summary loses nothing of theirs.
    update(
        &registry,
        &db,
        app(),
        &note,
        json!({"summary": "app first"}),
    )
    .await;
    update(
        &registry,
        &db,
        Caller::local(),
        &note,
        json!({"summary": "someone else"}),
    )
    .await;
    update(
        &registry,
        &db,
        app(),
        &note,
        json!({"summary": "app again"}),
    )
    .await;
    // The user's own direct body edit after the app's counts as a conflict.
    update(
        &registry,
        &db,
        app(),
        &note,
        json!({"body_append": "\nby the app"}),
    )
    .await;
    update(
        &registry,
        &db,
        alice(),
        &note,
        json!({"body_append": "\nby the user"}),
    )
    .await;

    let applied = apply_app_undo(&db, &alice(), &request(&since))
        .await
        .unwrap();
    assert_eq!(
        item(&applied, &note, "field:summary").status,
        UndoStatus::Reverted
    );
    let body = item(&applied, &note, "body");
    assert_eq!(body.status, UndoStatus::Conflict, "{body:#?}");
    assert_eq!(
        body.conflict.as_ref().and_then(|c| c.actor.as_deref()),
        Some(ALICE)
    );
    assert_eq!(
        field(&db, &note, "summary").await.as_deref(),
        Some("contested summary")
    );
    assert_eq!(
        field(&db, &note, "body").await.as_deref(),
        Some("contested body\nby the app\nby the user")
    );
}

#[tokio::test]
async fn an_app_cannot_undo() {
    let (db, registry) = fixture().await;
    let install = adopted_with_declaration(&registry, &db, v2_declaration()).await;
    let request = request("2026-10-07T00:00:00Z");
    for result in [
        preview_app_undo(&db, &app_caller(ALICE, &install), &request).await,
        apply_app_undo(&db, &app_caller(ALICE, &install), &request).await,
    ] {
        let message = result.unwrap_err().to_string();
        assert!(message.contains("app_operation_refused"), "{message}");
    }
}

#[tokio::test]
async fn a_revert_right_after_the_last_peer_leaves_is_not_blocked() {
    use native_ce::coedit::live::{self, OpenRequest};
    use native_ce::coedit::PeerKind;

    let (db, registry) = fixture().await;
    let install = adopted_with_declaration(&registry, &db, v2_declaration()).await;
    let alice = || Caller::authenticated(ALICE);
    let note = create_note(&registry, &db, alice(), "co-edited").await;
    let since = mark_time().await;
    update(
        &registry,
        &db,
        app_caller(ALICE, &install),
        &note,
        json!({"body_append": "\nby the app"}),
    )
    .await;
    let open = |resume_peer| {
        let db = db.clone();
        let note = note.clone();
        async move {
            live::open(
                &db,
                &Caller::authenticated(ALICE),
                OpenRequest {
                    record_id: note,
                    mode: PeerKind::Edit,
                    resume_peer,
                },
            )
            .await
            .unwrap()
        }
    };

    // A peer is attached: the body is held.
    let (peer, opened) = open(None).await;
    let preview = preview_app_undo(&db, &alice(), &request(&since))
        .await
        .unwrap();
    let held = item(&preview, &note, "body");
    assert_eq!(held.status, UndoStatus::Conflict, "{held:#?}");
    assert_eq!(held.reason.as_deref(), Some("live_session"));
    assert_eq!(
        held.detail.as_deref(),
        Some("someone is editing this live; try again once they have closed it")
    );

    // The last peer leaves; the clean doc stays in its grace window (a
    // reopen resumes the same peer), and an ordinary body write may proceed.
    peer.leave().await;
    let (peer, reopened) = open(Some(opened.peer.clone())).await;
    assert!(reopened.resumed, "the grace doc is still held");
    peer.leave().await;
    let preview = preview_app_undo(&db, &alice(), &request(&since))
        .await
        .unwrap();
    assert_eq!(item(&preview, &note, "body").status, UndoStatus::Revert);
    let applied = apply_app_undo(&db, &alice(), &request(&since))
        .await
        .unwrap();
    assert_eq!(item(&applied, &note, "body").status, UndoStatus::Reverted);
    assert_eq!(
        field(&db, &note, "body").await.as_deref(),
        Some("co-edited body")
    );
}

#[tokio::test]
async fn a_link_the_app_re_added_with_another_note_gets_its_note_back() {
    let (db, registry) = fixture().await;
    let install = adopted_with_declaration(&registry, &db, v2_declaration()).await;
    let alice = || Caller::authenticated(ALICE);
    let source = create_note(&registry, &db, alice(), "source").await;
    let target = create_note(&registry, &db, alice(), "target").await;
    let add = |note: &str| {
        json!({"action": "add", "source_id": source, "target_id": target,
               "relationship": "derived_from", "note": note})
    };
    call_as(
        &registry,
        &db,
        alice(),
        "manage_links",
        add("the user's note"),
    )
    .await
    .unwrap();
    let since = mark_time().await;
    call_as(
        &registry,
        &db,
        app_caller(ALICE, &install),
        "manage_links",
        add("the app's note"),
    )
    .await
    .unwrap();

    let aspect = format!("link:derived_from:{target}");
    let preview = preview_app_undo(&db, &alice(), &request(&since))
        .await
        .unwrap();
    let planned = item(&preview, &source, &aspect);
    assert_eq!(planned.status, UndoStatus::Revert, "{planned:#?}");
    assert_eq!(planned.action, Some("add_link"));
    assert_eq!(
        planned.from,
        Some(json!({"linked": true, "note": "the app's note"}))
    );
    assert_eq!(
        planned.to,
        Some(json!({"linked": true, "note": "the user's note"}))
    );
    let applied = apply_app_undo(&db, &alice(), &request(&since))
        .await
        .unwrap();
    assert_eq!(
        item(&applied, &source, &aspect).status,
        UndoStatus::Reverted
    );
    let note: Option<String> = sqlx::query_scalar(
        "SELECT note FROM links WHERE source_id = ? AND target_id = ? AND relationship = 'derived_from'",
    )
    .bind(&source)
    .bind(&target)
    .fetch_one(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    assert_eq!(note.as_deref(), Some("the user's note"));
}

#[tokio::test]
async fn an_earlier_undo_of_another_package_does_not_hide_a_conflict() {
    const OTHER: &str = "agent.other";
    let (db, registry) = fixture().await;
    let install = adopted_with_declaration(&registry, &db, v2_declaration()).await;
    let other_install =
        adopted_package_with_declaration_as(&registry, &db, ALICE, OTHER, v2_declaration()).await;
    let alice = || Caller::authenticated(ALICE);
    let other_app = || {
        Caller::authenticated(ALICE)
            .with_host_asserted_app(AppAttribution::new(OTHER, "0.1.0", &other_install).unwrap())
    };
    let source = create_note(&registry, &db, alice(), "source").await;
    let target = create_note(&registry, &db, alice(), "target").await;
    let link = |action: &str| {
        json!({"action": action, "source_id": source, "target_id": target,
               "relationship": "relates_to"})
    };

    // This package links them; the other package then unlinks them.
    let since = mark_time().await;
    call_as(
        &registry,
        &db,
        app_caller(ALICE, &install),
        "manage_links",
        link("add"),
    )
    .await
    .unwrap();
    let other_since = mark_time().await;
    call_as(&registry, &db, other_app(), "manage_links", link("remove"))
        .await
        .unwrap();
    assert!(!related(&db, &source, &target).await);

    // Undoing the other package relinks them, under the caller's own undo.
    let mut other_request = request(&other_since);
    other_request.package = OTHER.into();
    let other_undo = apply_app_undo(&db, &alice(), &other_request).await.unwrap();
    let aspect = format!("link:relates_to:{target}");
    let relinked = item(&other_undo, &source, &aspect);
    assert_eq!(relinked.status, UndoStatus::Reverted, "{relinked:#?}");
    assert!(related(&db, &source, &target).await);

    // That undo belongs to the other package's chain, not this one's: it is
    // a later write by someone else here, so this package's link is a
    // conflict, not "already reverted".
    let preview = preview_app_undo(&db, &alice(), &request(&since))
        .await
        .unwrap();
    let conflict = item(&preview, &source, &aspect);
    assert_eq!(conflict.status, UndoStatus::Conflict, "{conflict:#?}");
    let blocker = &conflict.conflict.as_ref().unwrap().event_id;
    assert!(relinked.written.contains(blocker), "{conflict:#?}");
}

/// Known increment-1 limit, pinned so increment 2 changes it deliberately:
/// a relationship link's base is the last stance before the app's first
/// assertion, so a support retracted before T still reads as "linked".
#[tokio::test]
async fn a_retracted_support_before_the_app_is_a_known_base_gap() {
    let (db, registry) = fixture().await;
    let install = adopted_with_declaration(&registry, &db, v2_declaration()).await;
    let alice = || Caller::authenticated(ALICE);
    let source = create_note(&registry, &db, alice(), "source").await;
    let target = create_note(&registry, &db, alice(), "target").await;
    let link = json!({"action": "add", "source_id": source, "target_id": target,
                      "relationship": "relates_to"});
    let added = call_as(&registry, &db, alice(), "manage_links", link.clone())
        .await
        .unwrap();
    call_as(
        &registry,
        &db,
        alice(),
        "manage_relationships",
        json!({"action": "retract",
               "assertion_issuer_origin_db_id": added["relationship_origin_db_id"],
               "assertion_id": added["assertion_id"],
               "reason": "The user withdraws the link.",
               "idempotency_key": "retract-before-the-app"}),
    )
    .await
    .unwrap();
    assert!(!related(&db, &source, &target).await, "retracted: unlinked");
    let since = mark_time().await;
    call_as(
        &registry,
        &db,
        app_caller(ALICE, &install),
        "manage_links",
        link,
    )
    .await
    .unwrap();
    assert!(related(&db, &source, &target).await);

    // The true base is "unlinked", but the retraction is not folded in, so
    // the app's link reads as already at its base and is left in place.
    let applied = apply_app_undo(&db, &alice(), &request(&since))
        .await
        .unwrap();
    let gap = item(&applied, &source, &format!("link:relates_to:{target}"));
    assert_eq!(gap.status, UndoStatus::Unchanged, "{gap:#?}");
    assert!(related(&db, &source, &target).await);
}

#[tokio::test]
async fn an_empty_note_is_not_the_same_as_no_note() {
    let (db, registry) = fixture().await;
    let install = adopted_with_declaration(&registry, &db, v2_declaration()).await;
    let alice = || Caller::authenticated(ALICE);
    let source = create_note(&registry, &db, alice(), "source").await;
    let target = create_note(&registry, &db, alice(), "target").await;
    let link = json!({"action": "add", "source_id": source, "target_id": target,
                      "relationship": "derived_from"});
    call_as(&registry, &db, alice(), "manage_links", link.clone())
        .await
        .unwrap();
    let since = mark_time().await;
    let mut empty = link;
    empty["note"] = json!("");
    call_as(
        &registry,
        &db,
        app_caller(ALICE, &install),
        "manage_links",
        empty,
    )
    .await
    .unwrap();
    let stored_note = || async {
        sqlx::query_scalar::<_, Option<String>>(
            "SELECT note FROM links WHERE source_id = ? AND target_id = ? AND relationship = 'derived_from'",
        )
        .bind(&source)
        .bind(&target)
        .fetch_one(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap()
    };
    assert_eq!(stored_note().await.as_deref(), Some(""));

    let aspect = format!("link:derived_from:{target}");
    let applied = apply_app_undo(&db, &alice(), &request(&since))
        .await
        .unwrap();
    let reverted = item(&applied, &source, &aspect);
    assert_eq!(reverted.status, UndoStatus::Reverted, "{reverted:#?}");
    assert_eq!(reverted.from, Some(json!({"linked": true, "note": ""})));
    assert_eq!(reverted.to, Some(json!({"linked": true, "note": null})));
    assert_eq!(
        stored_note().await,
        None,
        "the note is absent again, not empty"
    );
}

#[tokio::test]
async fn an_invalidated_undo_no_longer_counts_as_the_apps_own() {
    let (db, registry) = fixture().await;
    let install = adopted_with_declaration(&registry, &db, v2_declaration()).await;
    let alice = || Caller::authenticated(ALICE);
    let app = || app_caller(ALICE, &install);
    let note = create_note(&registry, &db, alice(), "twice").await;
    let since = mark_time().await;
    update(
        &registry,
        &db,
        app(),
        &note,
        json!({"summary": "app first"}),
    )
    .await;
    let later_since = mark_time().await;
    update(
        &registry,
        &db,
        app(),
        &note,
        json!({"summary": "app second"}),
    )
    .await;

    // An undo over the later window restores the app's first summary.
    let earlier_undo = apply_app_undo(&db, &alice(), &request(&later_since))
        .await
        .unwrap();
    let restored = item(&earlier_undo, &note, "field:summary").clone();
    assert_eq!(restored.status, UndoStatus::Reverted, "{restored:#?}");
    assert_eq!(
        field(&db, &note, "summary").await.as_deref(),
        Some("app first")
    );

    // Over the whole window that undo is the caller's own chain, so the
    // app's writes revert through it.
    let preview = preview_app_undo(&db, &alice(), &request(&since))
        .await
        .unwrap();
    assert_eq!(
        item(&preview, &note, "field:summary").status,
        UndoStatus::Revert
    );

    // Once its attestation is invalidated it is no longer trusted as an
    // undo, so it reads as someone else's later write.
    sqlx::query(
        "INSERT INTO provenance_attestation_validity_events
         (id, attestation_id, ordinal, status, reason, issuer, issued_at)
         VALUES (?, ?, 0, 'invalidated', 'undo test compromise',
                 'undo test operator', '2026-10-08T00:00:00.000Z')",
    )
    .bind(format!(
        "validity:{}",
        earlier_undo.action_attestation_ids[0]
    ))
    .bind(&earlier_undo.action_attestation_ids[0])
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    let preview = preview_app_undo(&db, &alice(), &request(&since))
        .await
        .unwrap();
    let conflict = item(&preview, &note, "field:summary");
    assert_eq!(conflict.status, UndoStatus::Conflict, "{conflict:#?}");
    assert_eq!(
        conflict.conflict.as_ref().map(|c| c.event_id.as_str()),
        restored.written.first().map(String::as_str)
    );
}

#[tokio::test]
async fn an_assertion_naming_the_package_is_not_an_undo_without_its_attestation() {
    let (db, registry) = fixture().await;
    let install = adopted_with_declaration(&registry, &db, v2_declaration()).await;
    let alice = || Caller::authenticated(ALICE);
    let source = create_note(&registry, &db, alice(), "source").await;
    let target = create_note(&registry, &db, alice(), "target").await;
    let link = |action: &str| {
        json!({"action": action, "source_id": source, "target_id": target,
               "relationship": "relates_to"})
    };
    let added = call_as(&registry, &db, alice(), "manage_links", link("add"))
        .await
        .unwrap();
    let since = mark_time().await;
    call_as(
        &registry,
        &db,
        app_caller(ALICE, &install),
        "manage_links",
        link("remove"),
    )
    .await
    .unwrap();
    assert!(!related(&db, &source, &target).await);

    // A later assertion whose rationale copies an undo's package marker but
    // which no undo attestation produced. `manage_relationships` refuses to
    // assert on a legacy link (its anchor rule does not match `source`/
    // `target`), so the row is written directly, as a forged log entry.
    let forged = "f0f0f0f0-0000-4000-8000-00000000f0f0";
    let origin = added["relationship_origin_db_id"].as_str().unwrap();
    sqlx::query(
        "INSERT INTO relationship_events
           (id, stream_kind, stream_id, stream_version, relationship_origin_db_id,
            relationship_id, type, payload, actor, issuer_origin_db_id,
            occurred_at, ingested_at)
         VALUES (?1, 'assertion', ?2, 1, ?3, ?4, 'assertion.created.v1', ?5, ?6, ?3,
                 strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
    )
    .bind(forged)
    .bind(format!("forged-{forged}"))
    .bind(origin)
    .bind(added["relationship_id"].as_str().unwrap())
    .bind(
        json!({"stance": "support",
               "rationale": format!("undo_app_writes compatibility add; package={PACKAGE}")})
        .to_string(),
    )
    .bind(ALICE)
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();

    let preview = preview_app_undo(&db, &alice(), &request(&since))
        .await
        .unwrap();
    let conflict = item(&preview, &source, &format!("link:relates_to:{target}"));
    assert_eq!(conflict.status, UndoStatus::Conflict, "{conflict:#?}");
    assert_eq!(
        conflict.conflict.as_ref().map(|c| c.event_id.as_str()),
        Some(forged),
        "the marker alone does not make an undo"
    );
}
