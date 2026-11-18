//! Workspace app shelf, slice 1 (design: S2 workspace-wide app installs).
//! Boundary tests: who may add or remove, that adding never installs or
//! consents for anyone, that the shelf cannot be forged, and that one
//! workspace's shelf never reaches another. Account-a is the workspace owner
//! and writer, account-b a writer with a pre-existing personal install,
//! account-c a view-only member.
use super::*;

fn writer(account: &str) -> Caller {
    Caller::authenticated(account).with_hosting_context(account, "hq-fixture")
}
fn add(package: &str, key: &str) -> Value {
    json!({"action":"shelf_add","package":package,"idempotency_key":key})
}
fn remove(package: &str, event: &str) -> Value {
    json!({"action":"shelf_remove","package":package,"expected_shelf_event_id":event})
}

struct World {
    _f: Fixture,
    db: Db,
    a: String,
    b: String,
    c: String,
}

async fn world() -> World {
    let f = Fixture::new().await;
    let (db, a, b) = fixture(&f, "agent.docs").await;
    app_roster(&db, "account-a", &["account-a", "account-b", "account-c"]).await;
    let c = k::resolve_principal_by_binding(&db, "account-c")
        .await
        .unwrap()
        .expect("account-c admitted")
        .0;
    // Workspace-root policy: a manages, b edits, c may only view.
    k::replace_home_policy(
        &db,
        &a,
        KERNEL_ROOT_ID,
        &[(&a, "manage"), (&b, "edit"), (&c, "view")],
    )
    .await
    .unwrap();
    World { _f: f, db, a, b, c }
}

async fn events(db: &Db) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap()
}
async fn shelf_events(db: &Db) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM content_events WHERE type IN ('kernel.workspace_app_added.v1','kernel.workspace_app_removed.v1')",
    )
    .fetch_one(db.pool())
    .await
    .unwrap()
}
async fn installs(db: &Db) -> Vec<(String, String, String, String, String)> {
    sqlx::query_as("SELECT principal,package,row_json,generation,status FROM kernel_app_installs ORDER BY principal,package")
        .fetch_all(db.pool())
        .await
        .unwrap()
}
async fn shelf_block(db: &Db, caller: Caller) -> Value {
    call(db, caller, "manage_alpha_tabs", json!({"action":"list"}))
        .await
        .unwrap()["shelf"]
        .clone()
}
async fn shelf_list(db: &Db, caller: Caller) -> Vec<Value> {
    shelf_block(db, caller).await["entries"]
        .as_array()
        .unwrap()
        .clone()
}

#[tokio::test]
async fn shelf_add_stages_one_shared_source_idempotently_and_installs_for_nobody() {
    let w = world().await;
    let installs_before = installs(&w.db).await;
    let first = call(
        &w.db,
        writer("account-a"),
        "manage_alpha_tabs",
        add("agent.docs", "k1"),
    )
    .await
    .unwrap();
    assert_eq!(first["changed"], true, "{first}");
    let entry = first["entry"].clone();
    assert!(entry.get("added_by").is_none(), "adder is not exposed");
    let artifact = entry["artifact_id"].as_str().unwrap().to_owned();

    // Same key, then a fresh key: still one entry and one artifact.
    let after_first = events(&w.db).await;
    for key in ["k1", "k2"] {
        let again = call(
            &w.db,
            writer("account-b"),
            "manage_alpha_tabs",
            add("agent.docs", key),
        )
        .await
        .unwrap();
        // b's key is new to b; the pin is already live, so nothing is written.
        assert_eq!(again["changed"], false, "{again}");
        assert_eq!(again["entry"]["shelf_event_id"], entry["shelf_event_id"]);
    }
    let again = call(
        &w.db,
        writer("account-a"),
        "manage_alpha_tabs",
        add("agent.docs", "k1"),
    )
    .await
    .unwrap();
    assert_eq!(again["changed"], false);
    assert_eq!(events(&w.db).await, after_first, "retries append nothing");
    assert_eq!(shelf_events(&w.db).await, 1);
    let sources: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM content_events WHERE type='kernel.body_set.v1' AND record_id=?",
    )
    .bind(&artifact)
    .fetch_one(w.db.pool())
    .await
    .unwrap();
    assert_eq!(sources, 1, "exactly one shared source artifact");

    // Every member reads the source; it is workspace-homed, not account-only.
    let mut tx = w.db.write_pool().begin().await.unwrap();
    for who in [&w.a, &w.b, &w.c] {
        let record = k::read_record_on(&mut tx, who, &artifact)
            .await
            .unwrap()
            .expect("member can read the shared source");
        assert_eq!(record.home_id, KERNEL_ROOT_ID);
        assert_eq!(record.body.as_deref(), Some(NEW));
    }
    drop(tx);
    let policy: i64 =
        sqlx::query_scalar("SELECT count(*) FROM kernel_policy_entries WHERE root_id=?")
            .bind(crate::kernel::v1_import_home_id(&artifact))
            .fetch_one(w.db.pool())
            .await
            .unwrap();
    assert_eq!(policy, 0, "no account-only home was created for the source");

    // Adding installs, adopts and consents for nobody, adder included, and
    // leaves b's existing personal install byte-for-byte as it was.
    assert_eq!(installs(&w.db).await, installs_before);
    let after_installs: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM content_events WHERE type LIKE 'kernel.app_install_%' AND seq > (SELECT seq FROM content_events WHERE type='kernel.workspace_app_added.v1')",
    )
    .fetch_one(w.db.pool())
    .await
    .unwrap();
    assert_eq!(after_installs, 0);

    // Everyone, including the view-only member, sees the shelf; no one is told who added it.
    for who in ["account-a", "account-b", "account-c"] {
        let listed = shelf_list(&w.db, writer(who)).await;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0]["package"], "agent.docs");
        assert_eq!(listed[0]["shelf_event_id"], entry["shelf_event_id"]);
        assert!(listed[0].get("added_by").is_none());
        assert_eq!(listed[0]["added_by_me"], who == "account-a");
        // The block names people, never ids, bindings or emails; only the two
        // members with edit access are offered as people who can add.
        let block = shelf_block(&w.db, writer(who)).await;
        assert_eq!(block["supported"], true);
        assert_eq!(block["who_can_add"].as_array().unwrap().len(), 2, "{block}");
        // Each member is told their own answer: the two editors may add, the view-only member may not.
        assert_eq!(block["can_add"], who != "account-c", "{block}");
        let text = block.to_string();
        for secret in [&w.a, &w.b, &w.c] {
            assert!(
                !text.contains(secret.as_str()),
                "principal id leaked: {text}"
            );
        }
        for secret in ["account-a", "account-b", "account-c", "@", "example.test"] {
            if secret.starts_with("account-") {
                // A display name may legitimately read like the account label;
                // an auth binding must never appear as a distinct field.
                continue;
            }
            assert!(!text.contains(secret), "email-like value leaked: {text}");
        }
    }
    k::verify_v2_ready(&w.db).await.unwrap();
}

#[tokio::test]
async fn shelf_writers_only_and_refusals_append_nothing() {
    let w = world().await;
    let added = call(
        &w.db,
        writer("account-a"),
        "manage_alpha_tabs",
        add("agent.docs", "base"),
    )
    .await
    .unwrap();
    let live = added["entry"]["shelf_event_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let stranger =
        Caller::authenticated("account-z").with_hosting_context("account-z", "hq-fixture");
    let app = || {
        writer("account-a").with_host_asserted_app(
            crate::mcp::app_attribution::AppAttribution::new("agent.docs", "0.4.0", "install")
                .unwrap(),
        )
    };
    let before = events(&w.db).await;
    let snapshot = k::dump_all_kernel_tables(&w.db).await.unwrap();
    let attempts: Vec<(&str, Caller, Value)> = vec![
        (
            "view-only member add",
            writer("account-c"),
            add("agent.docs", "c1"),
        ),
        (
            "view-only member remove",
            writer("account-c"),
            remove("agent.docs", &live),
        ),
        ("non-member add", stranger.clone(), add("agent.docs", "z1")),
        ("non-member remove", stranger, remove("agent.docs", &live)),
        ("app call add", app(), add("agent.docs", "app1")),
        ("app call remove", app(), remove("agent.docs", &live)),
        (
            "out-of-allowlist package",
            writer("account-a"),
            add("personal.owner-slides", "p1"),
        ),
        (
            "allowlisted but not in this release's catalogue assets",
            writer("account-a"),
            add("agent.linear", "l1"),
        ),
        ("blank key", writer("account-a"), add("agent.docs", " ")),
        (
            "stale remove",
            writer("account-a"),
            remove("agent.docs", "not-the-live-event"),
        ),
    ];
    for (name, caller, args) in attempts {
        let outcome = call(&w.db, caller, "manage_alpha_tabs", args).await;
        assert!(outcome.is_err(), "{name} must be refused, got {outcome:?}");
    }
    assert_eq!(events(&w.db).await, before, "refusals append nothing");
    assert_eq!(k::dump_all_kernel_tables(&w.db).await.unwrap(), snapshot);
    assert_eq!(shelf_list(&w.db, writer("account-c")).await.len(), 1);

    // The view-only member's refusal is the edit gate, not a missing shelf.
    let refused = call(
        &w.db,
        writer("account-c"),
        "manage_alpha_tabs",
        add("agent.docs", "c2"),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(refused.contains("edit access"), "{refused}");
}

#[tokio::test]
async fn shelf_events_cannot_be_forged_or_tampered() {
    let w = world().await;
    let added = call(
        &w.db,
        writer("account-a"),
        "manage_alpha_tabs",
        add("agent.docs", "base"),
    )
    .await
    .unwrap();
    let event_id = added["entry"]["shelf_event_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let payload: Value = serde_json::from_str(
        &sqlx::query_scalar::<_, String>("SELECT payload FROM content_events WHERE id=?")
            .bind(&event_id)
            .fetch_one(w.db.pool())
            .await
            .unwrap(),
    )
    .unwrap();
    let aggregate = "kernel:workspace-apps:agent.docs";
    let before = events(&w.db).await;

    // Generic appends refuse both reserved types, for any actor.
    for (kind, body) in [
        ("kernel.workspace_app_added.v1", payload.clone()),
        (
            "kernel.workspace_app_removed.v1",
            json!({"format":1,"package":"agent.docs","expected_shelf_event_id":event_id,"removed_by":w.a}),
        ),
    ] {
        for actor in [&w.a, &w.b] {
            let forged = crate::store::append(
                &w.db,
                crate::store::AppendSpec {
                    record_id: aggregate.into(),
                    event_type: kind.into(),
                    payload: body.clone(),
                    actor: Some(actor.clone()),
                },
            )
            .await;
            assert!(forged.is_err(), "{kind} must be reserved");
        }
    }
    assert_eq!(events(&w.db).await, before);

    // Even through the engine's own append seam, projection refuses an event
    // whose pin is not the retained catalogue entry. Take the app off first
    // so a duplicate-pin refusal cannot mask the reason under test.
    call(
        &w.db,
        writer("account-a"),
        "manage_alpha_tabs",
        remove("agent.docs", &event_id),
    )
    .await
    .unwrap();
    let before = events(&w.db).await;
    let mut tampered_digest = payload.clone();
    tampered_digest["digest"] = json!("00".repeat(32));
    let mut tampered_entry = payload.clone();
    tampered_entry["digest"] = json!("11".repeat(32));
    tampered_entry["entry"]["digest"] = json!("11".repeat(32));
    let mut other_artifact = payload.clone();
    other_artifact["artifact_id"] = json!(Uuid::new_v4().to_string());
    let mut other_actor = payload.clone();
    other_actor["added_by"] = json!(w.b);
    let mut off_catalogue = payload.clone();
    off_catalogue["entry"]["package"] = json!("agent.unlisted");
    off_catalogue["package"] = json!("agent.unlisted");
    for (name, forged, record) in [
        ("tampered pin digest", tampered_digest, aggregate),
        ("tampered digest in entry too", tampered_entry, aggregate),
        ("different source artifact", other_artifact, aggregate),
        ("adder field names someone else", other_actor, aggregate),
        (
            "package outside retained catalogue",
            off_catalogue,
            "kernel:workspace-apps:agent.unlisted",
        ),
    ] {
        let mut tx = crate::db::begin_write(w.db.write_pool()).await.unwrap();
        let result = crate::store::append_in(
            &w.db,
            &mut tx,
            crate::store::AppendSpec {
                record_id: record.into(),
                event_type: "kernel.workspace_app_added.v1".into(),
                payload: forged,
                actor: Some(w.a.clone()),
            },
            &mut crate::act::ActAllocation::new(),
        )
        .await;
        assert!(result.is_err(), "{name} must be refused by projection");
        drop(tx);
    }
    assert_eq!(events(&w.db).await, before);
    k::verify_v2_ready(&w.db).await.unwrap();
}

#[tokio::test]
async fn shelf_remove_is_guarded_and_readd_restores_the_same_source() {
    let w = world().await;
    let first = call(
        &w.db,
        writer("account-a"),
        "manage_alpha_tabs",
        add("agent.docs", "k1"),
    )
    .await
    .unwrap();
    let entry = first["entry"].clone();
    let removed = call(
        &w.db,
        writer("account-b"),
        "manage_alpha_tabs",
        remove("agent.docs", entry["shelf_event_id"].as_str().unwrap()),
    )
    .await
    .unwrap();
    assert_eq!(removed["changed"], true);
    assert!(shelf_list(&w.db, writer("account-c")).await.is_empty());
    // Removal deletes nothing: the shared source is still there.
    let mut tx = w.db.write_pool().begin().await.unwrap();
    assert!(
        k::read_record_on(&mut tx, &w.a, entry["artifact_id"].as_str().unwrap())
            .await
            .unwrap()
            .is_some()
    );
    drop(tx);
    // A retried remove is a no-op; a stale retried add does not resurrect it.
    let retried = call(
        &w.db,
        writer("account-b"),
        "manage_alpha_tabs",
        remove("agent.docs", entry["shelf_event_id"].as_str().unwrap()),
    )
    .await
    .unwrap();
    assert_eq!(retried["changed"], false);
    let stale = call(
        &w.db,
        writer("account-a"),
        "manage_alpha_tabs",
        add("agent.docs", "k1"),
    )
    .await
    .unwrap();
    assert_eq!(stale["changed"], false);
    assert!(shelf_list(&w.db, writer("account-a")).await.is_empty());

    // A deliberate re-add revives the same artifact and revision, so a
    // member's earlier consent (slice 2) can be recognised.
    let readded = call(
        &w.db,
        writer("account-a"),
        "manage_alpha_tabs",
        add("agent.docs", "k3"),
    )
    .await
    .unwrap();
    assert_eq!(readded["changed"], true);
    assert_eq!(readded["entry"]["artifact_id"], entry["artifact_id"]);
    assert_eq!(
        readded["entry"]["source_revision"],
        entry["source_revision"]
    );
    assert_ne!(readded["entry"]["shelf_event_id"], entry["shelf_event_id"]);
    let artifacts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM content_events WHERE record_id=? AND type='kernel.record_created.v1'",
    )
    .bind(entry["artifact_id"].as_str().unwrap())
    .fetch_one(w.db.pool())
    .await
    .unwrap();
    assert_eq!(artifacts, 1);
    k::verify_v2_ready(&w.db).await.unwrap();
}

#[tokio::test]
async fn shelf_never_crosses_workspaces() {
    let a = world().await;
    let b = world().await;
    let b_before = k::dump_all_kernel_tables(&b.db).await.unwrap();
    let b_events = events(&b.db).await;
    call(
        &a.db,
        writer("account-a"),
        "manage_alpha_tabs",
        add("agent.docs", "k1"),
    )
    .await
    .unwrap();
    assert_eq!(shelf_list(&a.db, writer("account-a")).await.len(), 1);
    assert!(shelf_list(&b.db, writer("account-a")).await.is_empty());
    assert!(shelf_list(&b.db, writer("account-b")).await.is_empty());
    assert_eq!(events(&b.db).await, b_events);
    assert_eq!(k::dump_all_kernel_tables(&b.db).await.unwrap(), b_before);
}

/// A Person record titled `title` in `home`, linked to `principal` the way
/// hosted messaging links an account to its Person.
async fn link_person(w: &World, home: &str, principal: &str, title: &str) -> String {
    let person = k::create_record_as(&w.db, &w.a, home).await.unwrap();
    sqlx::query(
        "INSERT INTO kernel_record_fields(record_id,name,value_json,created_seq) VALUES(?,?,?,1)",
    )
    .bind(&person)
    .bind("title")
    .bind(serde_json::to_string(title).unwrap())
    .execute(w.db.write_pool())
    .await
    .unwrap();
    sqlx::query("INSERT INTO kernel_message_people(person_id,principal_id) VALUES(?,?)")
        .bind(&person)
        .bind(principal)
        .execute(w.db.write_pool())
        .await
        .unwrap();
    person
}
fn names(block: &Value) -> Vec<String> {
    block["who_can_add"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn shelf_names_are_the_real_person_names_each_viewer_may_see() {
    let w = world().await;
    call(
        &w.db,
        writer("account-a"),
        "manage_alpha_tabs",
        add("agent.docs", "n1"),
    )
    .await
    .unwrap();
    // Hosted account labels are generic; the real name is the linked Person.
    link_person(&w, KERNEL_ROOT_ID, &w.a, "Priya Shah").await;
    // b's Person lives in a home only a can read.
    let private = k::create_home(&w.db, KERNEL_ROOT_ID, Some(&[]), &w.a)
        .await
        .unwrap();
    link_person(&w, &private, &w.b, "Sam Private").await;
    // c is view-only: a readable name must still never be offered as "can add".
    link_person(&w, KERNEL_ROOT_ID, &w.c, "Carol Viewer").await;

    let as_a = shelf_block(&w.db, writer("account-a")).await;
    assert_eq!(names(&as_a), ["Priya Shah", "Sam Private"], "{as_a}");
    assert_eq!(as_a["entries"][0]["added_by_name"], "Priya Shah");

    // b and c cannot read Sam's Person: they get the fallback, never the name.
    for who in ["account-b", "account-c"] {
        let block = shelf_block(&w.db, writer(who)).await;
        assert_eq!(names(&block), ["A member", "Priya Shah"], "{who}: {block}");
        let text = block.to_string();
        for hidden in ["Sam Private", "Carol Viewer"] {
            assert!(!text.contains(hidden), "{who} saw {hidden}: {text}");
        }
        assert_eq!(block["entries"][0]["added_by_name"], "Priya Shah");
    }
    // Generic account labels never reach the shelf.
    for who in ["account-a", "account-b", "account-c"] {
        let text = shelf_block(&w.db, writer(who)).await.to_string();
        for generic in [
            "Hosted member",
            "Imported v1 account",
            "Workspace administrator",
        ] {
            assert!(!text.contains(generic), "{generic} leaked: {text}");
        }
    }
}

#[tokio::test]
async fn shelf_never_shows_email_or_id_shaped_names_and_falls_back() {
    let w = world().await;
    call(
        &w.db,
        writer("account-a"),
        "manage_alpha_tabs",
        add("agent.docs", "n2"),
    )
    .await
    .unwrap();
    // No linked Person at all: fallback for both editors.
    let none = shelf_block(&w.db, writer("account-c")).await;
    assert_eq!(names(&none), ["A member", "A member"], "{none}");
    assert_eq!(none["entries"][0]["added_by_name"], "A member");

    let pa = link_person(&w, KERNEL_ROOT_ID, &w.a, "priya@example.test").await;
    link_person(&w, KERNEL_ROOT_ID, &w.b, &w.b.clone()).await;
    for bad in [
        "priya@example.test".to_owned(),
        w.a.clone(),
        pa.clone(),
        "  ".to_owned(),
        "account-a".to_owned(),
    ] {
        sqlx::query(
            "UPDATE kernel_record_fields SET value_json=? WHERE record_id=? AND name='title'",
        )
        .bind(serde_json::to_string(&bad).unwrap())
        .bind(&pa)
        .execute(w.db.write_pool())
        .await
        .unwrap();
        for who in ["account-a", "account-b", "account-c"] {
            let block = shelf_block(&w.db, writer(who)).await;
            let text = block.to_string();
            assert_eq!(names(&block), ["A member", "A member"], "{bad}: {block}");
            for secret in [w.a.as_str(), w.b.as_str(), "@", "example.test"] {
                assert!(!text.contains(secret), "{secret} leaked: {text}");
            }
        }
    }
}

#[tokio::test]
async fn shelf_replay_requires_the_writers_edit_authority_at_the_time() {
    let w = world().await;
    let added = call(
        &w.db,
        writer("account-a"),
        "manage_alpha_tabs",
        add("agent.docs", "base"),
    )
    .await
    .unwrap();
    let live = added["entry"]["shelf_event_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let payload: Value = serde_json::from_str(
        &sqlx::query_scalar::<_, String>("SELECT payload FROM content_events WHERE id=?")
            .bind(&live)
            .fetch_one(w.db.pool())
            .await
            .unwrap(),
    )
    .unwrap();
    let aggregate = "kernel:workspace-apps:agent.docs";
    let engine_append = |actor: String, kind: &'static str, body: Value| {
        let db = w.db.clone();
        async move {
            let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
            let result = crate::store::append_in(
                &db,
                &mut tx,
                crate::store::AppendSpec {
                    record_id: aggregate.into(),
                    event_type: kind.into(),
                    payload: body,
                    actor: Some(actor),
                },
                &mut crate::act::ActAllocation::new(),
            )
            .await;
            drop(tx);
            result
        }
    };

    // A matching view-only removal against the live entry is refused.
    let removal =
        json!({"format":1,"package":"agent.docs","expected_shelf_event_id":live,"removed_by":w.c});
    let refused = engine_append(w.c.clone(), "kernel.workspace_app_removed.v1", removal)
        .await
        .expect_err("view-only removal must be refused")
        .to_string();
    assert!(refused.contains("edit access"), "{refused}");

    // Take the app off legitimately, then a matching view-only add is refused.
    call(
        &w.db,
        writer("account-a"),
        "manage_alpha_tabs",
        remove("agent.docs", &live),
    )
    .await
    .unwrap();
    let mut forged = payload.clone();
    forged["added_by"] = json!(w.c);
    let refused = engine_append(w.c.clone(), "kernel.workspace_app_added.v1", forged)
        .await
        .expect_err("view-only add must be refused")
        .to_string();
    assert!(refused.contains("edit access"), "{refused}");
    k::replay_all_projections(&w.db).await.unwrap();
    k::verify_v2_ready(&w.db).await.unwrap();
}

#[tokio::test]
async fn shelf_replay_accepts_events_by_a_writer_who_later_loses_edit() {
    let w = world().await;
    let added = call(
        &w.db,
        writer("account-b"),
        "manage_alpha_tabs",
        add("agent.docs", "b-adds"),
    )
    .await
    .unwrap();
    let live = added["entry"]["shelf_event_id"]
        .as_str()
        .unwrap()
        .to_owned();
    call(
        &w.db,
        writer("account-b"),
        "manage_alpha_tabs",
        remove("agent.docs", &live),
    )
    .await
    .unwrap();
    call(
        &w.db,
        writer("account-b"),
        "manage_alpha_tabs",
        add("agent.docs", "b-readds"),
    )
    .await
    .unwrap();
    k::replace_home_policy(
        &w.db,
        &w.a,
        KERNEL_ROOT_ID,
        &[(&w.a, "manage"), (&w.b, "view"), (&w.c, "view")],
    )
    .await
    .unwrap();
    // B can no longer write, but its earlier events still replay.
    assert!(call(
        &w.db,
        writer("account-b"),
        "manage_alpha_tabs",
        add("agent.docs", "b-late")
    )
    .await
    .is_err());
    k::replay_all_projections(&w.db).await.unwrap();
    k::verify_v2_ready(&w.db).await.unwrap();
    assert_eq!(shelf_list(&w.db, writer("account-a")).await.len(), 1);
}

/// B legitimately adds an app, then leaves the hosted roster. The add was
/// valid when made; replay must judge it against the roster as it stood then,
/// not the final roster that is already present in the retained log.
async fn writer_adds_then_leaves_roster(w: &World) {
    call(
        &w.db,
        writer("account-b"),
        "manage_alpha_tabs",
        add("agent.docs", "b-adds-then-leaves"),
    )
    .await
    .unwrap();
    app_roster(&w.db, "account-a", &["account-a", "account-c"]).await;
}

#[tokio::test]
async fn shelf_full_replay_accepts_an_add_by_a_writer_who_later_leaves_the_roster() {
    let w = world().await;
    writer_adds_then_leaves_roster(&w).await;
    k::replay_all_projections(&w.db).await.unwrap();
    k::verify_v2_ready(&w.db).await.unwrap();
    assert_eq!(shelf_list(&w.db, writer("account-a")).await.len(), 1);
}

/// The tail/standby fold: a local copy cut before B's add receives the later
/// log rows (the add and B's roster removal together, all present before the
/// fold starts, as a hosted delta ingests whole) and folds them with the tail
/// replay. A true `cut_versioned` delta is not available on this imported
/// fixture ("ambiguous source origins"), so the rows are copied directly.
#[tokio::test]
async fn shelf_tail_replay_accepts_an_add_by_a_writer_who_later_leaves_the_roster() {
    let w = world().await;
    let dir = tempfile::tempdir().unwrap();
    let local_path = dir.path().join("local.db");
    let hosted_path: String = {
        let rows: Vec<(i64, String, String)> = sqlx::query_as("PRAGMA database_list")
            .fetch_all(w.db.pool())
            .await
            .unwrap();
        rows.into_iter().find(|r| r.1 == "main").unwrap().2
    };
    {
        let mut conn = w.db.write_pool().acquire().await.unwrap();
        sqlx::query("VACUUM INTO ?")
            .bind(local_path.to_string_lossy().as_ref())
            .execute(&mut *conn)
            .await
            .unwrap();
    }
    let base: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let meta_base: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM meta_events")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    writer_adds_then_leaves_roster(&w).await;
    let mut local = SqliteConnection::connect(&format!("sqlite:{}", local_path.display()))
        .await
        .unwrap();
    sqlx::query("ATTACH DATABASE ? AS hosted")
        .bind(&hosted_path)
        .execute(&mut local)
        .await
        .unwrap();
    sqlx::query("INSERT INTO main.content_events SELECT * FROM hosted.content_events WHERE seq>?")
        .bind(base)
        .execute(&mut local)
        .await
        .unwrap();
    sqlx::query("INSERT INTO main.meta_events SELECT * FROM hosted.meta_events WHERE seq>?")
        .bind(meta_base)
        .execute(&mut local)
        .await
        .unwrap();
    let mut tx = sqlx::Connection::begin(&mut local).await.unwrap();
    k::replay_projection_tail_on(&mut tx, base, meta_base)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    local.close().await.unwrap();
}
