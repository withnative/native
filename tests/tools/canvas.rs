//! Native Canvas v1 — the batch protocol through the tool surface.
//!
//! Each test is one property from the architecture note's proof section
//! (`0a355ee` §8): batches are atomic, replay appends nothing, a stale
//! precondition conflicts instead of overwriting, two actors editing different
//! version groups of one object both land, limits and duplicates reject, and a
//! record the caller may not see appears on no read path. Every behaviour test
//! ends with `rebuild_and_diff` equal so the live fold and the replayed fold
//! agree byte for byte.

use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
use native_ce::canvas::{apply_batch, Op, OriginKind, PropsAuthority};
use native_ce::conformance::rebuild_and_diff;
use native_ce::mcp::{
    register_builtin_tools, register_snapshot_tool, register_surface_tools, Caller,
    ExposureProfile, ToolKind, ToolRegistry,
};
use native_ce::{create_database, Db};
use serde_json::{json, Value};
use std::collections::BTreeMap;

const BATCH_VERSION: &str = "native.canvas-batch.v1";

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

fn alice() -> Caller {
    Caller::authenticated("acct:alice")
        .with_hosting_context("host:alice", "db:test")
        .with_hosting_owner(false)
}

fn bea() -> Caller {
    Caller::authenticated("acct:bea")
        .with_hosting_context("host:bea", "db:test")
        .with_hosting_owner(false)
}

async fn bind_account(db: &Db, person: &str, account: &str) {
    sqlx::query(
        "INSERT INTO bindings (record_id, system, identifier, is_canonical)
         VALUES (?, 'account', ?, 1)",
    )
    .bind(person)
    .bind(account)
    .execute(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap();
}

async fn create_local(registry: &ToolRegistry, db: &Db, mut arguments: Value) -> String {
    arguments["reason"] = json!("canvas integration fixture");
    registry
        .call(db.clone(), Caller::local(), "create_record", arguments)
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string()
}

struct Fixture {
    db: Db,
    registry: ToolRegistry,
    canvas: String,
    /// A record both principals may see.
    shared: String,
    /// A record only Alice may see.
    private: String,
}

/// Alice owns everything; Bea holds Edit on the canvas and View on the shared
/// record, and nothing on the private one.
async fn fixture() -> Fixture {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let alice_person = create_local(
        &registry,
        &db,
        json!({ "type": "Entity", "kind": "person", "name": "Alice" }),
    )
    .await;
    let bea_person = create_local(
        &registry,
        &db,
        json!({ "type": "Entity", "kind": "person", "name": "Bea" }),
    )
    .await;
    bind_account(&db, &alice_person, "acct:alice").await;
    bind_account(&db, &bea_person, "acct:bea").await;
    let canvas = create_local(
        &registry,
        &db,
        json!({ "type": "Document", "kind": "canvas", "name": "Sprint sketch", "owner_id": alice_person }),
    )
    .await;
    let shared = create_local(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "Ship the canvas", "owner_id": alice_person, "lifecycle": "open" }),
    )
    .await;
    let private = create_local(
        &registry,
        &db,
        json!({ "type": "Document", "kind": "note", "name": "Salary bands", "owner_id": alice_person }),
    )
    .await;
    for (record, entries) in [
        (
            &canvas,
            vec![
                AllowEntry::account("acct:alice", Capability::Manage),
                AllowEntry::account("acct:bea", Capability::Edit),
            ],
        ),
        (
            &shared,
            vec![
                AllowEntry::account("acct:alice", Capability::Manage),
                AllowEntry::account("acct:bea", Capability::View),
            ],
        ),
        (
            &private,
            vec![AllowEntry::account("acct:alice", Capability::Manage)],
        ),
    ] {
        replace_explicit_policy(&db, "test:canvas-policy", record, entries)
            .await
            .unwrap();
    }
    Fixture {
        db,
        registry,
        canvas,
        shared,
        private,
    }
}

fn batch(canvas: &str, batch_id: &str, ops: Value) -> Value {
    json!({
        "action": "commit_batch",
        "batch": {
            "version": BATCH_VERSION,
            "canvas_id": canvas,
            "batch_id": batch_id,
            "origin": { "kind": "agent" },
            "ops": ops,
        }
    })
}

fn note(id: &str, x: f64, text: &str) -> Value {
    json!({ "op": "create", "object": {
        "id": id, "kind": "note", "x": x, "y": 20, "w": 200, "h": 120, "z": format!("a{id}"),
        "props": { "text": text, "color": "yellow" }
    }})
}

async fn commit(fx: &Fixture, caller: Caller, arguments: Value) -> Value {
    fx.registry
        .call(fx.db.clone(), caller, "manage_canvas", arguments)
        .await
        .unwrap()
}

async fn scene(fx: &Fixture, caller: Caller) -> Value {
    fx.registry
        .call(
            fx.db.clone(),
            caller,
            "read_canvas",
            json!({ "action": "get_scene", "canvas_id": fx.canvas, "include_deleted": true }),
        )
        .await
        .unwrap()
}

async fn changes(fx: &Fixture, caller: Caller, after: &str) -> Value {
    fx.registry
        .call(
            fx.db.clone(),
            caller,
            "read_canvas",
            json!({ "action": "changes", "canvas_id": fx.canvas, "after": after }),
        )
        .await
        .unwrap()
}

fn object<'a>(scene: &'a Value, id: &str) -> &'a Value {
    scene["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|object| object["id"] == id)
        .unwrap_or_else(|| panic!("object {id} in {scene:#}"))
}

async fn content_event_count(db: &Db) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(&crate::common::fixture_write_pool(db).await)
        .await
        .unwrap()
}

async fn assert_replay_exact(db: &Db) {
    assert!(rebuild_and_diff(db).await.unwrap().equal);
}

#[tokio::test]
async fn a_batch_commits_atomically_and_the_scene_reads_back() {
    let fx = fixture().await;
    let result = commit(
        &fx,
        alice(),
        batch(
            &fx.canvas,
            "b-1",
            json!([
                note("n1", 10.0, "hello"),
                { "op": "create", "object": { "id": "s1", "kind": "shape", "x": 300, "y": 20, "w": 80, "h": 80, "z": "b", "props": { "shape": "ellipse" } } },
                { "op": "create", "object": { "id": "k1", "kind": "stroke", "x": 0, "y": 0, "w": 10, "h": 10, "z": "c", "props": { "points": [[0, 0], [5, 5], [10, 3]], "width": 2 } } }
            ]),
        ),
    )
    .await;
    assert_eq!(result["outcome"], "committed", "{result:#}");
    assert_eq!(result["version"], "native.canvas-batch-result.v1");
    let version = result["canvas_version"].as_str().unwrap();
    assert!(version.starts_with("canvas:"));
    assert_eq!(result["objects"]["n1"]["geometry"], version);
    assert_eq!(result["objects"]["n1"]["content"], version);

    let scene = scene(&fx, bea()).await;
    assert_eq!(scene["canvas_version"], version);
    assert_eq!(scene["live_objects"], 3);
    let n1 = object(&scene, "n1");
    assert_eq!(n1["kind"], "note");
    assert_eq!(n1["x"], 10.0);
    assert_eq!(n1["props"]["text"], "hello");
    assert_eq!(n1["versions"]["geometry"], version);
    assert_eq!(n1["deleted"], false);
    assert_eq!(scene["objects"].as_array().unwrap().len(), 3);
    assert_replay_exact(&fx.db).await;
}

#[tokio::test]
async fn a_replayed_batch_returns_the_original_result_and_appends_nothing() {
    let fx = fixture().await;
    let first = commit(
        &fx,
        alice(),
        batch(&fx.canvas, "b-1", json!([note("n1", 0.0, "a")])),
    )
    .await;
    assert_eq!(first["outcome"], "committed");
    let events = content_event_count(&fx.db).await;

    let again = commit(
        &fx,
        alice(),
        batch(&fx.canvas, "b-1", json!([note("n1", 0.0, "a")])),
    )
    .await;
    assert_eq!(again["outcome"], "replayed", "{again:#}");
    assert_eq!(again["canvas_version"], first["canvas_version"]);
    assert_eq!(again["event_id"], first["event_id"]);
    assert_eq!(again["objects"], first["objects"]);
    assert_eq!(content_event_count(&fx.db).await, events);

    // Same id, different intent: refused, never silently merged.
    let reused = commit(
        &fx,
        alice(),
        batch(&fx.canvas, "b-1", json!([note("n2", 0.0, "b")])),
    )
    .await;
    assert_eq!(reused["outcome"], "rejected");
    assert_eq!(reused["error"]["code"], "batch_id_reused");
    // Same ops, different actor: also a different intent.
    let other = commit(
        &fx,
        bea(),
        batch(&fx.canvas, "b-1", json!([note("n1", 0.0, "a")])),
    )
    .await;
    assert_eq!(other["outcome"], "rejected");
    assert_eq!(other["error"]["code"], "batch_id_reused");
    assert_eq!(content_event_count(&fx.db).await, events);
    assert_replay_exact(&fx.db).await;
}

#[tokio::test]
async fn a_stale_precondition_conflicts_names_the_competing_actor_and_writes_nothing() {
    let fx = fixture().await;
    let created = commit(
        &fx,
        alice(),
        batch(&fx.canvas, "b-1", json!([note("n1", 0.0, "a")])),
    )
    .await;
    let v1 = created["canvas_version"].as_str().unwrap().to_string();

    // Bea moves it first.
    let moved = commit(
        &fx,
        bea(),
        batch(
            &fx.canvas,
            "b-2",
            json!([{ "op": "patch", "id": "n1", "expected": { "geometry": v1 }, "set": { "x": 50 } }]),
        ),
    )
    .await;
    assert_eq!(moved["outcome"], "committed", "{moved:#}");
    let v2 = moved["canvas_version"].as_str().unwrap().to_string();
    let events = content_event_count(&fx.db).await;

    // Alice, still holding v1, tries to move it too.
    let stale = commit(
        &fx,
        alice(),
        batch(
            &fx.canvas,
            "b-3",
            json!([
                note("n2", 0.0, "unrelated but in the same batch"),
                { "op": "patch", "id": "n1", "expected": { "geometry": v1 }, "set": { "x": 99 } }
            ]),
        ),
    )
    .await;
    assert_eq!(stale["outcome"], "conflict", "{stale:#}");
    let conflict = &stale["conflicts"][0];
    assert_eq!(conflict["id"], "n1");
    assert_eq!(conflict["group"], "geometry");
    assert_eq!(conflict["code"], "version_mismatch");
    assert_eq!(conflict["current"]["geometry"], v2);
    assert_eq!(conflict["current"]["content"], v1);
    assert_eq!(conflict["competing_actor"]["id"], "acct:bea");
    assert_eq!(conflict["competing_actor"]["display_name"], "Bea");
    // Whole-batch atomicity: the unrelated note did not land either.
    assert_eq!(content_event_count(&fx.db).await, events);
    let scene = scene(&fx, alice()).await;
    assert_eq!(object(&scene, "n1")["x"], 50.0);
    assert!(scene["objects"]
        .as_array()
        .unwrap()
        .iter()
        .all(|o| o["id"] != "n2"));

    // Retried against what the host reported, the same gesture commits.
    let retry = commit(
        &fx,
        alice(),
        batch(
            &fx.canvas,
            "b-4",
            json!([{ "op": "patch", "id": "n1", "expected": { "geometry": v2 }, "set": { "x": 99 } }]),
        ),
    )
    .await;
    assert_eq!(retry["outcome"], "committed", "{retry:#}");
    assert_replay_exact(&fx.db).await;
}

#[tokio::test]
async fn geometry_and_content_edits_from_two_actors_both_land() {
    let fx = fixture().await;
    let created = commit(
        &fx,
        alice(),
        batch(&fx.canvas, "b-1", json!([note("n1", 0.0, "draft")])),
    )
    .await;
    let v1 = created["canvas_version"].as_str().unwrap().to_string();

    let moved = commit(
        &fx,
        alice(),
        batch(
            &fx.canvas,
            "b-2",
            json!([{ "op": "patch", "id": "n1", "expected": { "geometry": v1 }, "set": { "x": 120, "y": 80 } }]),
        ),
    )
    .await;
    assert_eq!(moved["outcome"], "committed");
    let v2 = moved["canvas_version"].as_str().unwrap().to_string();

    // Bea still holds v1 for content; geometry moved, but she is not
    // touching geometry, so her edit lands.
    let typed = commit(
        &fx,
        bea(),
        batch(
            &fx.canvas,
            "b-3",
            json!([{ "op": "patch", "id": "n1", "expected": { "content": v1 }, "set": { "props": { "text": "final", "color": null } } }]),
        ),
    )
    .await;
    assert_eq!(typed["outcome"], "committed", "{typed:#}");
    let v3 = typed["canvas_version"].as_str().unwrap().to_string();
    assert_eq!(typed["objects"]["n1"]["geometry"], v2);
    assert_eq!(typed["objects"]["n1"]["content"], v3);

    let scene = scene(&fx, alice()).await;
    let n1 = object(&scene, "n1");
    assert_eq!(n1["x"], 120.0);
    assert_eq!(n1["props"], json!({ "text": "final" }));
    assert_eq!(n1["versions"]["geometry"], v2);
    assert_eq!(n1["versions"]["content"], v3);

    // The change feed carries the pre-image so the edit is invertible.
    let feed = changes(&fx, bea(), &v2).await;
    assert_eq!(feed["batches"].as_array().unwrap().len(), 1);
    let last = &feed["batches"][0];
    assert_eq!(last["batch_id"], "b-3");
    assert_eq!(last["actor"]["id"], "acct:bea");
    assert_eq!(
        last["pre_images"]["n1"]["props"],
        json!({ "text": "draft", "color": "yellow" })
    );
    assert_eq!(
        last["pre_images"]["n1"]["content"],
        v1.trim_start_matches("canvas:").parse::<i64>().unwrap()
    );
    assert_eq!(feed["more"], false);
    assert_eq!(feed["canvas_version"], v3);
    let full = changes(&fx, bea(), "canvas:0").await;
    assert_eq!(full["batches"].as_array().unwrap().len(), 3);
    assert_replay_exact(&fx.db).await;
}

#[tokio::test]
async fn delete_restore_and_frames_fold_and_tombstones_stay_readable() {
    let fx = fixture().await;
    let created = commit(
        &fx,
        alice(),
        batch(
            &fx.canvas,
            "b-1",
            json!([
                { "op": "create", "object": { "id": "f1", "kind": "frame", "x": 0, "y": 0, "w": 500, "h": 500, "z": "a", "props": { "title": "Backlog" } } },
                { "op": "create", "object": { "id": "n1", "kind": "note", "x": 10, "y": 10, "w": 100, "h": 100, "z": "b", "parent": "f1", "props": { "text": "child" } } }
            ]),
        ),
    )
    .await;
    assert_eq!(created["outcome"], "committed", "{created:#}");
    let v1 = created["canvas_version"].as_str().unwrap().to_string();

    let deleted = commit(
        &fx,
        alice(),
        batch(
            &fx.canvas,
            "b-2",
            json!([{ "op": "delete", "id": "f1", "expected": { "geometry": v1, "content": v1 } }]),
        ),
    )
    .await;
    assert_eq!(deleted["outcome"], "committed", "{deleted:#}");
    let v2 = deleted["canvas_version"].as_str().unwrap().to_string();
    let scene_after = scene(&fx, alice()).await;
    assert_eq!(scene_after["live_objects"], 1);
    assert_eq!(object(&scene_after, "f1")["deleted"], true);
    // Deleting a frame detaches its children in the same fold step, and
    // the commit result reports the child's new geometry token so a client
    // holding the old one learns it moved.
    let n1 = object(&scene_after, "n1");
    assert_eq!(n1["parent"], Value::Null);
    assert_eq!(n1["versions"]["geometry"], v2);
    assert_eq!(n1["versions"]["content"], v1);
    assert_eq!(deleted["objects"]["n1"]["geometry"], v2);
    assert_eq!(deleted["objects"]["n1"]["content"], v1);
    let feed = changes(&fx, alice(), &v1).await;
    assert_eq!(feed["batches"][0]["detached"], json!(["n1"]));
    assert_eq!(feed["batches"][0]["pre_images"]["n1"]["parent"], "f1");
    let replayed = commit(
        &fx,
        alice(),
        batch(
            &fx.canvas,
            "b-2",
            json!([{ "op": "delete", "id": "f1", "expected": { "geometry": v1, "content": v1 } }]),
        ),
    )
    .await;
    assert_eq!(replayed["outcome"], "replayed");
    assert_eq!(replayed["objects"], deleted["objects"]);

    // A tombstone cannot be patched; restoring it is a fold, not a resurrection.
    let patch_dead = commit(
        &fx,
        alice(),
        batch(
            &fx.canvas,
            "b-3",
            json!([{ "op": "patch", "id": "f1", "expected": { "geometry": v2 }, "set": { "x": 5 } }]),
        ),
    )
    .await;
    assert_eq!(patch_dead["outcome"], "conflict");
    assert_eq!(patch_dead["conflicts"][0]["code"], "object_deleted");
    let restored = commit(
        &fx,
        alice(),
        batch(
            &fx.canvas,
            "b-4",
            json!([{ "op": "restore", "id": "f1", "expected": { "geometry": v2, "content": v2 } }]),
        ),
    )
    .await;
    assert_eq!(restored["outcome"], "committed", "{restored:#}");
    assert_eq!(scene(&fx, alice()).await["live_objects"], 2);
    assert_replay_exact(&fx.db).await;
}

#[tokio::test]
async fn malformed_duplicate_and_oversized_batches_reject_without_writing() {
    let fx = fixture().await;
    let events = content_event_count(&fx.db).await;

    let twice = commit(
        &fx,
        alice(),
        batch(
            &fx.canvas,
            "b-1",
            json!([note("n1", 0.0, "a"), note("n1", 1.0, "b")]),
        ),
    )
    .await;
    assert_eq!(twice["outcome"], "rejected", "{twice:#}");
    assert_eq!(twice["error"]["code"], "duplicate_object");
    assert_eq!(twice["error"]["object_id"], "n1");

    let too_many = (0..201)
        .map(|i| note(&format!("n{i}"), i as f64, "x"))
        .collect::<Vec<_>>();
    let limit = commit(
        &fx,
        alice(),
        batch(&fx.canvas, "b-2", Value::Array(too_many)),
    )
    .await;
    assert_eq!(limit["outcome"], "rejected");
    assert_eq!(limit["error"]["code"], "limit_exceeded");
    assert_eq!(limit["error"]["limit"], "ops_per_batch");

    let unknown = commit(
        &fx,
        alice(),
        batch(
            &fx.canvas,
            "b-3",
            json!([{ "op": "patch", "id": "ghost", "expected": { "geometry": "canvas:1" }, "set": { "x": 1 } }]),
        ),
    )
    .await;
    assert_eq!(unknown["outcome"], "rejected", "{unknown:#}");
    assert_eq!(unknown["error"]["code"], "unknown_object");

    let bad_props = commit(
        &fx,
        alice(),
        batch(
            &fx.canvas,
            "b-4",
            json!([{ "op": "create", "object": { "id": "s1", "kind": "shape", "x": 0, "y": 0, "w": 1, "h": 1, "z": "a", "props": { "shape": "triangle" } } }]),
        ),
    )
    .await;
    assert_eq!(bad_props["outcome"], "rejected");
    assert_eq!(bad_props["error"]["code"], "invalid_envelope");

    let wrong_version = commit(
        &fx,
        alice(),
        json!({ "action": "commit_batch", "batch": { "version": "native.canvas-batch.v0", "canvas_id": fx.canvas, "batch_id": "b-5", "origin": { "kind": "agent" }, "ops": [note("n1", 0.0, "a")] } }),
    )
    .await;
    assert_eq!(wrong_version["outcome"], "rejected");
    assert_eq!(wrong_version["error"]["code"], "invalid_envelope");

    assert_eq!(content_event_count(&fx.db).await, events);
    let scene = scene(&fx, alice()).await;
    assert_eq!(scene["objects"].as_array().unwrap().len(), 0);
    assert_replay_exact(&fx.db).await;
}

#[tokio::test]
async fn a_record_the_caller_may_not_see_appears_on_no_read_path() {
    let fx = fixture().await;
    // Alice summons both records as cards.
    let created = commit(
        &fx,
        alice(),
        batch(
            &fx.canvas,
            "b-1",
            json!([
                { "op": "create", "object": { "id": "c-shared", "kind": "record_card", "x": 0, "y": 0, "w": 240, "h": 120, "z": "a", "props": { "record_id": fx.shared } } },
                { "op": "create", "object": { "id": "c-private", "kind": "record_card", "x": 300, "y": 0, "w": 240, "h": 120, "z": "b", "props": { "record_id": fx.private } } }
            ]),
        ),
    )
    .await;
    assert_eq!(created["outcome"], "committed", "{created:#}");
    let v1 = created["canvas_version"].as_str().unwrap().to_string();

    // Alice sees both faces.
    let as_alice = scene(&fx, alice()).await;
    assert_eq!(
        object(&as_alice, "c-private")["props"]["record_id"],
        fx.private
    );
    assert_eq!(
        object(&as_alice, "c-private")["record"]["name"],
        "Salary bands"
    );
    assert_eq!(
        object(&as_alice, "c-shared")["record"]["name"],
        "Ship the canvas"
    );
    assert_eq!(object(&as_alice, "c-shared")["record"]["type"], "WorkItem");

    // Bea sees the shared face, and a placeholder with geometry for the other.
    let as_bea = scene(&fx, bea()).await;
    let hidden = object(&as_bea, "c-private");
    assert_eq!(hidden["props"]["record_id"], "withheld");
    assert!(hidden.get("record").is_none());
    assert_eq!(hidden["x"], 300.0);
    assert_eq!(object(&as_bea, "c-shared")["record"]["id"], fx.shared);
    assert!(!as_bea.to_string().contains(&fx.private));

    // Bea can still move the placeholder.
    let moved = commit(
        &fx,
        bea(),
        batch(
            &fx.canvas,
            "b-2",
            json!([{ "op": "patch", "id": "c-private", "expected": { "geometry": v1 }, "set": { "x": 320 } }]),
        ),
    )
    .await;
    assert_eq!(moved["outcome"], "committed", "{moved:#}");
    assert!(!moved.to_string().contains(&fx.private));

    // The change feed redacts the create op for Bea and not for Alice.
    let feed_bea = changes(&fx, bea(), "canvas:0").await;
    assert!(!feed_bea.to_string().contains(&fx.private), "{feed_bea:#}");
    assert_eq!(
        feed_bea["batches"][0]["ops"][1]["object"]["props"]["record_id"],
        "withheld"
    );
    let feed_alice = changes(&fx, alice(), "canvas:0").await;
    assert_eq!(
        feed_alice["batches"][0]["ops"][1]["object"]["props"]["record_id"],
        fx.private
    );

    // Generic history summarises the batch and never carries the ops.
    for detail in ["metadata", "full"] {
        let history = fx
            .registry
            .call(
                fx.db.clone(),
                bea(),
                "get_history",
                json!({ "record_id": fx.canvas, "detail": detail }),
            )
            .await
            .unwrap();
        assert!(
            !history.to_string().contains(&fx.private),
            "{detail}: {history:#}"
        );
        let events = history["events"].as_array().unwrap();
        let batch_event = events
            .iter()
            .find(|event| event["type"] == "canvas.batch.committed.v1")
            .unwrap_or_else(|| panic!("{detail}: {history:#}"));
        if detail == "full" {
            assert_eq!(batch_event["payload"]["op_count"], 2);
            assert_eq!(batch_event["payload"]["see"], "read_canvas.changes");
            assert_eq!(batch_event["payload"]["batch"], "b-1");
            assert_eq!(batch_event["payload"]["canvas_version"], v1);
            assert_eq!(batch_event["payload"]["origin"]["kind"], "agent");
            assert!(batch_event["payload"].get("ops").is_none());
        } else {
            assert!(batch_event.get("payload").is_none());
        }
    }

    // A patch may not carry a record id at all, even unchanged, so the
    // change feed never has one to redact in a patch or a pre-image.
    let resend = commit(
        &fx,
        alice(),
        batch(
            &fx.canvas,
            "b-2b",
            json!([{ "op": "patch", "id": "c-shared", "expected": { "content": v1 }, "set": { "props": { "record_id": fx.shared } } }]),
        ),
    )
    .await;
    assert_eq!(resend["outcome"], "rejected", "{resend:#}");
    assert_eq!(resend["error"]["code"], "invalid_envelope");

    // Bea cannot summon the hidden record herself.
    let summon = commit(
        &fx,
        bea(),
        batch(
            &fx.canvas,
            "b-3",
            json!([{ "op": "create", "object": { "id": "c-again", "kind": "record_card", "x": 0, "y": 0, "w": 1, "h": 1, "z": "z", "props": { "record_id": fx.private } } }]),
        ),
    )
    .await;
    assert_eq!(summon["outcome"], "rejected", "{summon:#}");
    assert_eq!(summon["error"]["code"], "record_not_visible");
    assert_replay_exact(&fx.db).await;
}

#[tokio::test]
async fn a_hidden_canvas_and_a_lost_edit_fail_closed_without_disclosure() {
    let fx = fixture().await;
    commit(
        &fx,
        alice(),
        batch(&fx.canvas, "b-1", json!([note("n1", 0.0, "a")])),
    )
    .await;

    // Revoke Bea's Edit: the next batch is refused, reads continue.
    replace_explicit_policy(
        &fx.db,
        "test:canvas-policy",
        &fx.canvas,
        vec![
            AllowEntry::account("acct:alice", Capability::Manage),
            AllowEntry::account("acct:bea", Capability::View),
        ],
    )
    .await
    .unwrap();
    let refused = commit(
        &fx,
        bea(),
        batch(&fx.canvas, "b-2", json!([note("n2", 0.0, "b")])),
    )
    .await;
    assert_eq!(refused["outcome"], "rejected", "{refused:#}");
    assert_eq!(refused["error"]["code"], "permission_denied");
    assert_eq!(scene(&fx, bea()).await["live_objects"], 1);

    // Revoke View: every read and write reports a non-existent record.
    replace_explicit_policy(
        &fx.db,
        "test:canvas-policy",
        &fx.canvas,
        vec![AllowEntry::account("acct:alice", Capability::Manage)],
    )
    .await
    .unwrap();
    let read = fx
        .registry
        .call(
            fx.db.clone(),
            bea(),
            "read_canvas",
            json!({ "action": "get_scene", "canvas_id": fx.canvas }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(read.contains("does not exist"), "{read}");
    assert!(!read.contains("Sprint sketch"));
    let feed = fx
        .registry
        .call(
            fx.db.clone(),
            bea(),
            "read_canvas",
            json!({ "action": "changes", "canvas_id": fx.canvas, "after": "canvas:0" }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(feed.contains("does not exist"), "{feed}");
    let write = commit(
        &fx,
        bea(),
        batch(&fx.canvas, "b-3", json!([note("n3", 0.0, "c")])),
    )
    .await;
    assert_eq!(write["outcome"], "rejected");
    assert_eq!(write["error"]["code"], "unknown_canvas");

    // A non-canvas record is not a canvas, even to someone who may see it.
    let not_canvas = commit(
        &fx,
        alice(),
        batch(&fx.shared, "b-4", json!([note("n4", 0.0, "d")])),
    )
    .await;
    assert_eq!(not_canvas["outcome"], "rejected");
    assert_eq!(not_canvas["error"]["code"], "unknown_canvas");
    assert_replay_exact(&fx.db).await;
}

#[tokio::test]
async fn get_scene_honours_as_of_for_geometry_while_faces_stay_live() {
    let fx = fixture().await;
    let first = commit(
        &fx,
        alice(),
        batch(&fx.canvas, "b-1", json!([note("n1", 0.0, "a")])),
    )
    .await;
    let v1 = first["canvas_version"].as_str().unwrap().to_string();
    let seq1: i64 = v1.trim_start_matches("canvas:").parse().unwrap();
    let second = commit(
        &fx,
        alice(),
        batch(
            &fx.canvas,
            "b-2",
            json!([{ "op": "patch", "id": "n1", "expected": { "geometry": v1 }, "set": { "x": 77 } }]),
        ),
    )
    .await;
    assert_eq!(second["outcome"], "committed");
    let historical = fx
        .registry
        .call(
            fx.db.clone(),
            alice(),
            "read_canvas",
            json!({ "action": "get_scene", "canvas_id": fx.canvas, "as_of": { "content_seq": seq1 } }),
        )
        .await
        .unwrap();
    assert_eq!(historical["canvas_version"], v1);
    assert_eq!(object(&historical, "n1")["x"], 0.0);
    assert_eq!(historical["resolved_content_seq"], seq1);
    assert_eq!(
        scene(&fx, alice()).await["canvas_version"],
        second["canvas_version"]
    );
}

/// Hosted boot validates both descriptor budgets on the registry shape that
/// `serve.rs` builds. No other test measures the lens Complete profile with
/// the experimental tool present, and that profile is the binding one.
#[test]
fn canvas_descriptors_fit_the_boot_shaped_profile_budgets() {
    let mut registry = ToolRegistry::new();
    register_builtin_tools(&mut registry).unwrap();
    register_surface_tools(&mut registry).unwrap();
    native_ce::mcp::register_build_enabled_experimental_tools(&mut registry).unwrap();
    register_snapshot_tool(
        &mut registry,
        std::sync::Arc::new(native_ce::export::LocalSnapshotSource::new()),
    )
    .unwrap();
    assert!(registry.get("read_canvas").unwrap().kind == Some(ToolKind::ReadCanvas));
    assert!(registry.get("manage_canvas").unwrap().kind == Some(ToolKind::ManageCanvas));
    assert!(!registry
        .specs_for_profile(ExposureProfile::Focused)
        .any(|spec| matches!(spec.name.as_str(), "read_canvas" | "manage_canvas")));
    registry
        .validate_profile_budgets()
        .expect("ordinary Complete and Focused budgets");
    native_ce::mcp::validate_lens_profile_budgets(&registry)
        .expect("federated-lens Complete and Focused budgets");

    // Fitting here is not the same as booting. This registry is smaller than
    // the one a hosted server builds: `serve` also registers the hosted
    // membership tool, and the federated-lens Complete profile is where
    // everything lands together. Promotion's arguments first went over that
    // limit in CI while this test passed, and the failure presented as eight
    // held tests reporting "serve never reported a listening address" rather
    // than as a budget error. Reproduce the hosted total here so the next
    // widening of a canvas descriptor fails on this line instead.
    //
    // The delta is measured, not guessed: a hosted boot came to 196,733 bytes
    // where this registry came to 188,785, and `manage_memberships` is 7,947
    // of that. It will drift as hosted-only tools change; treat a surprise
    // here as a reason to re-measure rather than to raise the number.
    const HOSTED_ONLY_BYTES: usize = 7_948;
    let lens_bytes = native_ce::mcp::descriptor_projection_bytes(
        &native_ce::mcp::lens_descriptor_projection(&registry, ExposureProfile::Complete).unwrap(),
    );
    let hosted = lens_bytes + HOSTED_ONLY_BYTES;
    let margin = native_ce::mcp::COMPLETE_PROFILE_MAX_BYTES.saturating_sub(hosted);
    assert!(
        margin >= 256,
        "a hosted federated-lens Complete boot would be {hosted} bytes against \
         a {} limit, leaving {margin}. The profile is very close to full and \
         canvas is not the only thing in it: trim a descriptor here, or take \
         the budget itself to whoever owns the surface.",
        native_ce::mcp::COMPLETE_PROFILE_MAX_BYTES
    );

    for tool in ["read_canvas", "manage_canvas"] {
        let spec = registry.get(tool).unwrap();
        let bytes = serde_json::to_vec(&json!({
            "name": spec.name, "description": spec.description, "inputSchema": spec.input_schema
        }))
        .unwrap()
        .len();
        // This bound is this suite's own discipline, not a hosted
        // constraint: the binding gates are the two profile budgets
        // validated above, and both still pass. It was 1,600 while the tools
        // carried three actions between them; promotion's plan arguments are
        // the largest single addition the protocol will make, and the
        // grammar for all of them lives in docs/canvas-protocol-v1.md rather
        // than in the descriptor (A3).
        assert!(
            bytes < 2_200,
            "{tool} descriptor is {bytes} bytes; keep the grammar in the protocol doc"
        );
    }
}

// ---------------------------------------------------------------------------
// Milestone 2: describe, and connectors that can become governed links.
// ---------------------------------------------------------------------------

fn frame(id: &str, x: f64, title: &str) -> Value {
    json!({ "op": "create", "object": {
        "id": id, "kind": "frame", "x": x, "y": 0, "w": 400, "h": 300, "z": format!("a{id}"),
        "props": { "title": title, "color": "grey" }
    }})
}

fn card(id: &str, x: f64, record: &str) -> Value {
    json!({ "op": "create", "object": {
        "id": id, "kind": "record_card", "x": x, "y": 400, "w": 240, "h": 120, "z": format!("a{id}"),
        "props": { "record_id": record }
    }})
}

fn connector(id: &str, from: &str, to: &str) -> Value {
    json!({ "op": "create", "object": {
        "id": id, "kind": "connector", "x": 0, "y": 0, "w": 0, "h": 0, "z": format!("a{id}"),
        "props": { "from": { "object": from }, "to": { "object": to }, "style": "arrow" }
    }})
}

async fn describe(fx: &Fixture, caller: Caller) -> Value {
    fx.registry
        .call(
            fx.db.clone(),
            caller,
            "read_canvas",
            json!({ "action": "describe", "canvas_id": fx.canvas }),
        )
        .await
        .unwrap()
}

async fn assert_connector(fx: &Fixture, caller: Caller, object_id: &str, token: &str) -> Value {
    commit(
        fx,
        caller,
        json!({
            "action": "assert_connector",
            "canvas_id": fx.canvas,
            "object_id": object_id,
            "relationship": token,
        }),
    )
    .await
}

/// Seed a canvas holding a framed note and two cards, one of which points at a
/// record Bea cannot see, plus a connector joining the two cards.
async fn seeded() -> Fixture {
    let fx = fixture().await;
    let mut framed_note = note("n1", 40.0, "ship the canvas");
    framed_note["object"]["parent"] = json!("f1");
    commit(
        &fx,
        alice(),
        batch(
            &fx.canvas,
            "seed",
            json!([
                frame("f1", 0.0, "Plan"),
                framed_note,
                card("c-shared", 400.0, &fx.shared),
                card("c-private", 700.0, &fx.private),
                connector("k1", "c-shared", "c-private"),
            ]),
        ),
    )
    .await;
    fx
}

#[tokio::test]
async fn describe_outlines_the_scene_and_counts_withheld_cards_without_naming_them() {
    let fx = seeded().await;

    let mine = describe(&fx, alice()).await;
    let outline = mine["outline"].as_str().unwrap();
    assert!(
        outline.contains("Plan") && outline.contains("ship the canvas"),
        "the frame and its child should be outlined: {outline}"
    );
    assert!(
        outline.contains("Ship the canvas") && outline.contains("Salary bands"),
        "Alice sees both cards by title: {outline}"
    );
    assert_eq!(mine["withheld_cards"], json!(0));

    // Bea holds Edit on the canvas and View on the shared record only.
    let theirs = describe(&fx, bea()).await;
    let outline = theirs["outline"].as_str().unwrap();
    assert!(
        outline.contains("Ship the canvas"),
        "the visible card is still named: {outline}"
    );
    assert!(
        !outline.contains("Salary bands") && !outline.contains(&fx.private),
        "describe is a read path like any other: {outline}"
    );
    assert_eq!(theirs["withheld_cards"], json!(1));
    assert!(
        outline.contains("cannot see"),
        "the withheld card is counted, not hidden: {outline}"
    );

    assert!(rebuild_and_diff(&fx.db).await.unwrap().equal);
}

#[tokio::test]
async fn asserting_a_connector_writes_one_governed_link_and_replays() {
    let fx = seeded().await;

    let first = assert_connector(&fx, alice(), "k1", "relates_to").await;
    assert_eq!(first["outcome"], json!("committed"));
    let link_id = first["link_id"].as_str().unwrap().to_string();
    assert!(!link_id.is_empty());

    let objects = scene(&fx, alice()).await;
    let connector = objects["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|object| object["id"] == json!("k1"))
        .unwrap()
        .clone();
    assert_eq!(connector["props"]["semantic"]["status"], json!("asserted"));
    assert_eq!(connector["props"]["semantic"]["link_id"], json!(link_id));

    // Re-asserting the same connector replays: one link, not two.
    let again = assert_connector(&fx, alice(), "k1", "relates_to").await;
    assert_eq!(again["outcome"], json!("replayed"));
    assert_eq!(again["link_id"], json!(link_id));

    let links: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM links WHERE source_id=? AND target_id=?")
            .bind(&fx.shared)
            .bind(&fx.private)
            .fetch_one(&crate::common::fixture_write_pool(&fx.db).await)
            .await
            .unwrap();
    assert_eq!(links, 1, "re-assertion must not write a second link");

    assert!(rebuild_and_diff(&fx.db).await.unwrap().equal);
}

#[tokio::test]
async fn a_connector_reads_broken_once_its_link_is_removed_elsewhere() {
    let fx = seeded().await;
    assert_connector(&fx, alice(), "k1", "relates_to").await;

    fx.registry
        .call(
            fx.db.clone(),
            alice(),
            "manage_links",
            json!({
                "action": "remove",
                "source_id": fx.shared,
                "target_id": fx.private,
                "relationship": "relates_to",
            }),
        )
        .await
        .unwrap();

    let objects = scene(&fx, alice()).await;
    let connector = objects["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|object| object["id"] == json!("k1"))
        .unwrap()
        .clone();
    assert_eq!(
        connector["props"]["semantic"]["status"],
        json!("broken"),
        "broken is derived from the link's absence, never stored"
    );

    assert!(rebuild_and_diff(&fx.db).await.unwrap().equal);
}

#[tokio::test]
async fn assert_connector_needs_edit_on_the_source_record_and_view_on_the_target() {
    let fx = seeded().await;

    // Bea may edit the canvas but holds only View on the shared record and
    // nothing at all on the private one.
    let refused = assert_connector(&fx, bea(), "k1", "relates_to").await;
    assert_eq!(refused["outcome"], json!("rejected"));
    assert_eq!(refused["error"]["code"], json!("permission_denied"));

    let body = serde_json::to_string(&refused).unwrap();
    assert!(
        !body.contains(&fx.private),
        "a refusal must not disclose the record it protected: {body}"
    );

    let links: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM links WHERE source_id=?")
        .bind(&fx.shared)
        .fetch_one(&crate::common::fixture_write_pool(&fx.db).await)
        .await
        .unwrap();
    assert_eq!(links, 0, "a refused assertion writes nothing");

    assert!(rebuild_and_diff(&fx.db).await.unwrap().equal);
}

/// The replay branch is an authorization boundary, not just a fast path.
///
/// A content-owned link id spells `lnk:{source}:{target}:{relationship}`, so
/// returning `replayed` before checking the endpoint records would hand a
/// canvas editor the two record ids `get_scene` withholds from them, plus
/// confirmation that the link exists.
#[tokio::test]
async fn a_replayed_assertion_still_refuses_a_caller_who_may_not_see_the_records() {
    let fx = seeded().await;
    let first = assert_connector(&fx, alice(), "k1", "relates_to").await;
    assert_eq!(first["outcome"], json!("committed"));

    // Bea edits the canvas, holds only View on the shared record and nothing
    // on the private one, and asks for exactly the assertion that already
    // succeeded.
    let refused = assert_connector(&fx, bea(), "k1", "relates_to").await;
    assert_eq!(
        refused["outcome"],
        json!("rejected"),
        "an already-asserted connector must not replay for an unauthorized caller"
    );
    let body = serde_json::to_string(&refused).unwrap();
    assert!(
        !body.contains(&fx.private) && !body.contains("lnk:"),
        "the replay path must not disclose the link or its endpoints: {body}"
    );

    assert!(rebuild_and_diff(&fx.db).await.unwrap().equal);
}

/// An assertion is withheld whole, not merely stripped of its id: the
/// relationship and the status carry the same fact about records the caller
/// cannot see.
#[tokio::test]
async fn an_assertion_is_withheld_whole_from_a_caller_who_cannot_see_both_ends() {
    let fx = seeded().await;
    assert_connector(&fx, alice(), "k1", "relates_to").await;

    let objects = scene(&fx, bea()).await;
    let connector = objects["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|object| object["id"] == json!("k1"))
        .unwrap()
        .clone();
    assert_eq!(
        connector["props"]["semantic"],
        json!("withheld"),
        "relationship and status disclose the link as surely as link_id does"
    );

    let outline = describe(&fx, bea()).await;
    let body = serde_json::to_string(&outline).unwrap();
    assert!(
        !body.contains("relates_to") && !body.contains(&fx.private),
        "describe restates the scene, so it inherits the same withholding: {body}"
    );

    // Alice, who sees both ends, still gets the whole assertion.
    let mine = scene(&fx, alice()).await;
    let connector = mine["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|object| object["id"] == json!("k1"))
        .unwrap()
        .clone();
    assert_eq!(
        connector["props"]["semantic"]["relationship"],
        json!("relates_to")
    );
    assert_eq!(connector["props"]["semantic"]["status"], json!("asserted"));

    assert!(rebuild_and_diff(&fx.db).await.unwrap().equal);
}

#[tokio::test]
async fn a_client_cannot_forge_an_engine_authored_batch_or_a_semantic_connector() {
    let fx = seeded().await;

    // The origin kinds that license governed props are engine-only.
    let mut forged = batch(
        &fx.canvas,
        "forge-1",
        json!([note("n9", 900.0, "mine now")]),
    );
    forged["batch"]["origin"] = json!({ "kind": "assertion" });
    let refused = commit(&fx, alice(), forged).await;
    assert_eq!(refused["outcome"], json!("rejected"));
    assert_eq!(refused["error"]["code"], json!("invalid_envelope"));

    // And the props themselves are refused at the client seam.
    let mut semantic = connector("k9", "c-shared", "c-private");
    semantic["object"]["props"]["semantic"] =
        json!({ "relationship": "relates_to", "link_id": "lnk:forged", "status": "asserted" });
    let refused = commit(
        &fx,
        alice(),
        batch(&fx.canvas, "forge-2", json!([semantic])),
    )
    .await;
    assert_eq!(refused["outcome"], json!("rejected"));
    assert_eq!(refused["error"]["code"], json!("invalid_envelope"));

    assert!(rebuild_and_diff(&fx.db).await.unwrap().equal);
}

/// The change feed is a read path like any other.
#[tokio::test]
async fn the_change_feed_withholds_an_assertion_whole() {
    let fx = seeded().await;
    assert_connector(&fx, alice(), "k1", "relates_to").await;

    let feed = fx
        .registry
        .call(
            fx.db.clone(),
            bea(),
            "read_canvas",
            json!({ "action": "changes", "canvas_id": fx.canvas, "after": "canvas:0" }),
        )
        .await
        .unwrap();
    let body = serde_json::to_string(&feed).unwrap();
    assert!(
        !body.contains("relates_to") && !body.contains("lnk:") && !body.contains(&fx.private),
        "relationship and status disclose the link as surely as link_id: {body}"
    );

    assert!(rebuild_and_diff(&fx.db).await.unwrap().equal);
}

/// Re-asserting under a different token would leave the first governed link
/// in place with nothing on the canvas recording it.
#[tokio::test]
async fn a_connector_asserted_under_one_relationship_refuses_another() {
    let fx = seeded().await;
    assert_connector(&fx, alice(), "k1", "relates_to").await;

    let refused = assert_connector(&fx, alice(), "k1", "supersedes").await;
    assert_eq!(refused["outcome"], json!("rejected"));
    assert_eq!(refused["error"]["code"], json!("invalid_precondition"));

    let links: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM links WHERE source_id=? AND target_id=?")
            .bind(&fx.shared)
            .bind(&fx.private)
            .fetch_one(&crate::common::fixture_write_pool(&fx.db).await)
            .await
            .unwrap();
    assert_eq!(
        links, 1,
        "the second assertion must not orphan the first link"
    );

    assert!(rebuild_and_diff(&fx.db).await.unwrap().equal);
}

/// A stale client must be refused, not quietly given a link between records
/// it never chose.
#[tokio::test]
async fn assert_connector_honours_a_caller_supplied_precondition() {
    let fx = seeded().await;
    let stale = commit(
        &fx,
        alice(),
        json!({
            "action": "assert_connector",
            "canvas_id": fx.canvas,
            "object_id": "k1",
            "relationship": "relates_to",
            "expected": { "content": "canvas:1" },
        }),
    )
    .await;
    assert_eq!(stale["outcome"], json!("conflict"));
    assert_eq!(stale["conflicts"][0]["code"], json!("version_mismatch"));

    let links: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM links WHERE source_id=?")
        .bind(&fx.shared)
        .fetch_one(&crate::common::fixture_write_pool(&fx.db).await)
        .await
        .unwrap();
    assert_eq!(links, 0, "a refused precondition writes nothing");

    // The version the scene actually reports is accepted.
    let objects = scene(&fx, alice()).await;
    let current = objects["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|object| object["id"] == json!("k1"))
        .unwrap()["versions"]["content"]
        .as_str()
        .unwrap()
        .to_string();
    let accepted = commit(
        &fx,
        alice(),
        json!({
            "action": "assert_connector",
            "canvas_id": fx.canvas,
            "object_id": "k1",
            "relationship": "relates_to",
            "expected": { "content": current },
        }),
    )
    .await;
    assert_eq!(accepted["outcome"], json!("committed"));

    assert!(rebuild_and_diff(&fx.db).await.unwrap().equal);
}

/// The stored link id must name a row that exists, so it is read back from
/// `links` rather than minted from the triple.
#[tokio::test]
async fn the_stored_link_id_names_the_row_that_actually_exists() {
    let fx = seeded().await;
    assert_connector(&fx, alice(), "k1", "relates_to").await;

    let objects = scene(&fx, alice()).await;
    let stored = objects["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|object| object["id"] == json!("k1"))
        .unwrap()["props"]["semantic"]["link_id"]
        .as_str()
        .unwrap()
        .to_string();
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM links WHERE id=?")
        .bind(&stored)
        .fetch_one(&crate::common::fixture_write_pool(&fx.db).await)
        .await
        .unwrap();
    assert_eq!(rows, 1, "the cited link id {stored} resolves to no row");

    assert!(rebuild_and_diff(&fx.db).await.unwrap().equal);
}

// ---------------------------------------------------------------------------
// Milestone 2: promotion.
// ---------------------------------------------------------------------------

async fn plan(fx: &Fixture, caller: Caller, extra: Value) -> Value {
    let mut arguments = json!({
        "action": "promote",
        "canvas_id": fx.canvas,
        "reason": "the sketch settled",
        "items": [{
            "object_id": "n1",
            "type": "WorkItem",
            "kind": "task",
            "name": "Ship the connector work",
        }],
    });
    for (key, value) in extra.as_object().unwrap() {
        arguments[key] = value.clone();
    }
    commit(fx, caller, arguments).await
}

#[tokio::test]
async fn a_promotion_dry_run_assesses_every_item_and_writes_nothing() {
    let fx = seeded().await;
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records")
        .fetch_one(&crate::common::fixture_write_pool(&fx.db).await)
        .await
        .unwrap();

    let planned = plan(&fx, alice(), json!({ "dry_run": true })).await;
    assert_eq!(planned["outcome"], json!("planned"));
    assert_eq!(planned["items"][0]["status"], json!("would_accept"));
    assert!(planned["plan_digest"]
        .as_str()
        .is_some_and(|d| d.len() == 64));

    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records")
        .fetch_one(&crate::common::fixture_write_pool(&fx.db).await)
        .await
        .unwrap();
    assert_eq!(before, after, "preparation does not mutate");

    assert!(rebuild_and_diff(&fx.db).await.unwrap().equal);
}

#[tokio::test]
async fn executing_a_plan_mints_the_record_and_converts_the_object_in_place() {
    let fx = seeded().await;
    let planned = plan(&fx, alice(), json!({ "dry_run": true })).await;
    let digest = planned["plan_digest"].as_str().unwrap().to_string();

    let done = plan(
        &fx,
        alice(),
        json!({ "dry_run": false, "plan_digest": digest }),
    )
    .await;
    assert_eq!(done["outcome"], json!("committed"));
    let record_id = done["promoted"][0]["record_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(done["promoted"][0]["object_id"], json!("n1"));

    // The object is now a card on the new record, at the same id.
    let objects = scene(&fx, alice()).await;
    let card = objects["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|object| object["id"] == json!("n1"))
        .unwrap()
        .clone();
    assert_eq!(card["kind"], json!("record_card"));
    assert_eq!(card["props"]["record_id"], json!(record_id));
    assert_eq!(card["props"]["promoted_from"]["object_id"], json!("n1"));
    assert!(
        card["props"].get("text").is_none(),
        "the note's text must not survive onto a record card: {card}"
    );
    assert_eq!(card["record"]["name"], json!("Ship the connector work"));

    // Provenance: a derived_from link back to the canvas, and the facet.
    let linked: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM links WHERE source_id=? AND target_id=? AND relationship='derived_from'",
    )
    .bind(&record_id)
    .bind(&fx.canvas)
    .fetch_one(&crate::common::fixture_write_pool(&fx.db).await)
    .await
    .unwrap();
    assert_eq!(linked, 1, "every promoted record points back at its canvas");

    let facet: Option<String> = sqlx::query_scalar(
        "SELECT value FROM facet_values WHERE record_id=? AND key='canvas.promoted_from'",
    )
    .bind(&record_id)
    .fetch_optional(&crate::common::fixture_write_pool(&fx.db).await)
    .await
    .unwrap();
    let facet: Value = serde_json::from_str(&facet.expect("promotion writes the facet")).unwrap();
    assert_eq!(facet["canvas_id"], json!(fx.canvas));
    assert_eq!(facet["object_id"], json!("n1"));
    assert_eq!(facet["batch_event_id"], done["event_id"]);
    assert_eq!(
        facet["attestation_id"], card["props"]["promoted_from"]["attestation_id"],
        "the card and the facet name the same promotion"
    );

    assert!(rebuild_and_diff(&fx.db).await.unwrap().equal);
}

#[tokio::test]
async fn a_stale_plan_is_a_conflict_that_writes_nothing() {
    let fx = seeded().await;
    let planned = plan(&fx, alice(), json!({ "dry_run": true })).await;
    let digest = planned["plan_digest"].as_str().unwrap().to_string();

    // Someone edits the very object the plan promotes.
    let objects = scene(&fx, alice()).await;
    let content = objects["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|object| object["id"] == json!("n1"))
        .unwrap()["versions"]["content"]
        .as_str()
        .unwrap()
        .to_string();
    commit(
        &fx,
        bea(),
        batch(
            &fx.canvas,
            "moved-on",
            json!([{
                "op": "patch", "id": "n1",
                "expected": { "content": content },
                "set": { "props": { "text": "actually, not this" } }
            }]),
        ),
    )
    .await;

    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records")
        .fetch_one(&crate::common::fixture_write_pool(&fx.db).await)
        .await
        .unwrap();
    let error = fx
        .registry
        .call(
            fx.db.clone(),
            alice(),
            "manage_canvas",
            json!({
                "action": "promote",
                "canvas_id": fx.canvas,
                "reason": "the sketch settled",
                "dry_run": false,
                "plan_digest": digest,
                "items": [{ "object_id": "n1", "type": "WorkItem", "kind": "task", "name": "Ship the connector work" }],
            }),
        )
        .await
        .expect_err("a stale plan must not execute");
    let message = error.to_string();
    assert!(
        message.contains("revision conflict"),
        "the plan runtime keys plan_stale off this phrase: {message}"
    );

    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records")
        .fetch_one(&crate::common::fixture_write_pool(&fx.db).await)
        .await
        .unwrap();
    assert_eq!(before, after, "a refused plan writes nothing");

    assert!(rebuild_and_diff(&fx.db).await.unwrap().equal);
}

#[tokio::test]
async fn promotion_writes_intra_cluster_links_between_records_that_did_not_exist_yet() {
    let fx = seeded().await;
    let mut second = note("n2", 300.0, "and this one");
    second["object"]["y"] = json!(60);
    commit(&fx, alice(), batch(&fx.canvas, "second", json!([second]))).await;

    let arguments = json!({
        "action": "promote",
        "canvas_id": fx.canvas,
        "reason": "two halves of one plan",
        "dry_run": true,
        "items": [
            { "object_id": "n1", "type": "WorkItem", "kind": "task", "name": "First" },
            { "object_id": "n2", "type": "WorkItem", "kind": "task", "name": "Second" },
        ],
        "links": [{ "from": "n2", "to": "n1", "relationship": "depends_on" }],
    });
    let planned = commit(&fx, alice(), arguments.clone()).await;
    assert_eq!(planned["outcome"], json!("planned"));

    let mut execute = arguments;
    execute["dry_run"] = json!(false);
    execute["plan_digest"] = planned["plan_digest"].clone();
    let done = commit(&fx, alice(), execute).await;
    assert_eq!(done["outcome"], json!("committed"));

    let ids: Vec<String> = done["promoted"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["record_id"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(ids.len(), 2);
    let between: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM links WHERE relationship='depends_on' AND source_id IN (?,?) AND target_id IN (?,?)",
    )
    .bind(&ids[0]).bind(&ids[1]).bind(&ids[0]).bind(&ids[1])
    .fetch_one(&crate::common::fixture_write_pool(&fx.db).await)
    .await
    .unwrap();
    assert_eq!(
        between, 1,
        "an intra-cluster link is why promotion has to be composite"
    );

    assert!(rebuild_and_diff(&fx.db).await.unwrap().equal);
}

#[tokio::test]
async fn promotion_needs_edit_on_the_canvas() {
    let fx = seeded().await;
    // Bea holds Edit on the canvas, so drop her to View to test the boundary.
    replace_explicit_policy(
        &fx.db,
        "test:canvas-policy",
        &fx.canvas,
        vec![
            AllowEntry::account("acct:alice", Capability::Manage),
            AllowEntry::account("acct:bea", Capability::View),
        ],
    )
    .await
    .unwrap();

    let refused = plan(&fx, bea(), json!({ "dry_run": true })).await;
    assert_eq!(refused["outcome"], json!("rejected"));
    assert_eq!(refused["error"]["code"], json!("permission_denied"));

    assert!(rebuild_and_diff(&fx.db).await.unwrap().equal);
}

/// A record card cannot parent anything, so a frame that still holds children
/// cannot become one without stranding them.
#[tokio::test]
async fn promoting_a_frame_that_still_holds_children_is_refused() {
    let fx = seeded().await;
    let planned = commit(
        &fx,
        alice(),
        json!({
            "action": "promote",
            "canvas_id": fx.canvas,
            "reason": "the frame is really a milestone",
            "dry_run": true,
            "items": [{ "object_id": "f1", "type": "WorkItem", "kind": "task", "name": "Plan" }],
        }),
    )
    .await;
    assert_eq!(planned["items"][0]["status"], json!("would_conflict"));
    assert!(planned["items"][0]["note"]
        .as_str()
        .unwrap()
        .contains("still holds objects"));

    assert!(rebuild_and_diff(&fx.db).await.unwrap().equal);
}

/// Promoting an asserted connector would drop the `semantic` that names its
/// governed link, leaving the link in place with nothing on the canvas
/// recording it -- the stranding `assert_connector` itself refuses.
#[tokio::test]
async fn promoting_an_asserted_connector_is_refused() {
    let fx = seeded().await;
    let asserted = assert_connector(&fx, alice(), "k1", "relates_to").await;
    assert_eq!(asserted["outcome"], json!("committed"));

    let planned = commit(
        &fx,
        alice(),
        json!({
            "action": "promote",
            "canvas_id": fx.canvas,
            "reason": "make the arrow a record",
            "dry_run": true,
            "items": [{ "object_id": "k1", "type": "WorkItem", "kind": "task", "name": "Arrow" }],
        }),
    )
    .await;
    assert_eq!(planned["items"][0]["status"], json!("would_conflict"));
    assert!(planned["items"][0]["note"]
        .as_str()
        .unwrap()
        .contains("asserted link"));

    assert!(rebuild_and_diff(&fx.db).await.unwrap().equal);
}

/// The dry run assesses the links too, and shows them rather than counting
/// them: approving a promotion means approving what it writes onto records
/// that already exist.
#[tokio::test]
async fn the_dry_run_assesses_links_rather_than_counting_them() {
    let fx = seeded().await;
    let planned = commit(
        &fx,
        alice(),
        json!({
            "action": "promote",
            "canvas_id": fx.canvas,
            "reason": "the sketch settled",
            "dry_run": true,
            "items": [{ "object_id": "n1", "type": "WorkItem", "kind": "task", "name": "Ship" }],
            "links": [{ "from": "n1", "to": "n1", "relationship": "  " }],
        }),
    )
    .await;
    let link = &planned["links"][0];
    assert_eq!(link["status"], json!("would_conflict"));
    assert!(link["note"].as_str().unwrap().contains("must not be blank"));
    assert_eq!(link["from_promoted"], json!(true));

    assert!(rebuild_and_diff(&fx.db).await.unwrap().equal);
}

/// The reason is durable -- it lands in every minted record, every
/// `derived_from` note and the batch origin -- so two promotions that would
/// commit different effects must not share a plan digest.
#[tokio::test]
async fn the_plan_digest_binds_the_reason() {
    let fx = seeded().await;
    let first = plan(&fx, alice(), json!({ "dry_run": true })).await;
    let digest = first["plan_digest"].as_str().unwrap().to_string();

    let mut arguments = json!({
        "action": "promote",
        "canvas_id": fx.canvas,
        "reason": "a different reason entirely",
        "dry_run": true,
        "items": [{
            "object_id": "n1",
            "type": "WorkItem",
            "kind": "task",
            "name": "Ship the connector work",
        }],
    });
    let second = commit(&fx, alice(), arguments.clone()).await;
    assert_ne!(
        second["plan_digest"], first["plan_digest"],
        "the reason is part of what was planned"
    );

    // And the first digest cannot be spent on the second plan: a digest that
    // no longer describes the request is a conflict, which the plan runtime
    // turns into a 409.
    arguments["dry_run"] = json!(false);
    arguments["plan_digest"] = json!(digest);
    let refused = fx
        .registry
        .call(fx.db.clone(), alice(), "manage_canvas", arguments)
        .await
        .expect_err("a digest that names a different plan cannot be spent");
    assert!(
        refused.to_string().contains("revision conflict"),
        "{refused}"
    );

    assert!(rebuild_and_diff(&fx.db).await.unwrap().equal);
}

// ---------------------------------------------------------------------------
// Milestone 3, PR A, CHUNK 1: the export bundle (`read_canvas.export`).
// ---------------------------------------------------------------------------

async fn export_as(fx: &Fixture, caller: Caller, arguments: Value) -> Value {
    fx.registry
        .call(fx.db.clone(), caller, "read_canvas", arguments)
        .await
        .unwrap()
}

/// F.1: export of a seeded canvas has `complete: true` for the owner,
/// carries every batch from `canvas:0` in order, and its `scene` equals
/// `get_scene { include_deleted: true }`.
#[tokio::test]
async fn export_bundles_scene_and_full_history_with_complete_true_for_the_owner() {
    let fx = seeded().await;

    let bundle = export_as(
        &fx,
        alice(),
        json!({ "action": "export", "canvas_id": fx.canvas }),
    )
    .await;
    assert_eq!(bundle["action"], json!("export"));
    assert_eq!(bundle["version"], json!("native.canvas-export.v1"));
    assert!(bundle["exported_at"].is_string(), "{bundle:#}");
    assert_eq!(bundle["exported_by"]["id"], json!("acct:alice"));
    assert_eq!(bundle["exported_by"]["display_name"], json!("Alice"));

    // The scene section is get_scene with tombstones, byte for byte.
    let live = scene(&fx, alice()).await;
    assert_eq!(bundle["scene"]["version"], json!("native.canvas-scene.v1"));
    assert_eq!(bundle["scene"]["objects"], live["objects"]);
    assert_eq!(bundle["canvas_version"], live["canvas_version"]);

    // The history carries every batch from canvas:0 in order.
    let feed = changes(&fx, alice(), "canvas:0").await;
    assert_eq!(feed["more"], false);
    assert_eq!(
        bundle["history"]["version"],
        json!("native.canvas-changes.v1")
    );
    assert_eq!(bundle["history"]["batches"], feed["batches"]);
    assert_eq!(bundle["history"]["batches"][0]["batch_id"], json!("seed"));
    let versions: Vec<String> = bundle["history"]["batches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|batch| batch["canvas_version"].as_str().unwrap().to_string())
        .collect();
    assert!(
        versions.windows(2).all(|pair| pair[0] < pair[1]),
        "batches in order: {versions:?}"
    );

    // The shell names the canvas record.
    assert_eq!(bundle["canvas"]["id"], json!(fx.canvas));
    assert_eq!(bundle["canvas"]["type"], json!("Document"));
    assert_eq!(bundle["canvas"]["kind"], json!("canvas"));
    assert_eq!(bundle["canvas"]["name"], json!("Sprint sketch"));
    // The fixture canvas carries the default home, which Alice may see.
    assert_eq!(bundle["canvas"]["home_id"], json!("native:unfiled"));
    assert_eq!(bundle["canvas"]["archived"], json!(false));
    assert!(
        bundle["canvas"]["record_version"]
            .as_str()
            .is_some_and(|version| version.starts_with("rec:")),
        "{bundle:#}"
    );

    // Nothing withheld for the owner on a canvas with no assertions.
    assert_eq!(bundle["disclosure"]["withheld_records"], json!(0));
    assert_eq!(bundle["disclosure"]["withheld_assertions"], json!(0));
    assert_eq!(bundle["disclosure"]["complete"], json!(true));

    // References are derived: both cards by face name, no links yet (the
    // seed connector is unasserted) and no attestations (nothing promoted).
    let records = bundle["references"]["records"].as_array().unwrap();
    assert_eq!(records.len(), 2, "{bundle:#}");
    for (id, name) in [
        (&fx.shared, "Ship the canvas"),
        (&fx.private, "Salary bands"),
    ] {
        let entry = records
            .iter()
            .find(|entry| entry["id"] == *id)
            .unwrap_or_else(|| panic!("record {id} in {bundle:#}"));
        assert_eq!(entry["name"], json!(name));
    }
    assert_eq!(bundle["references"]["links"], json!([]));
    assert_eq!(bundle["references"]["attestations"], json!([]));

    assert_eq!(bundle["limits"]["ops_per_batch"], json!(200));
    assert_eq!(bundle["limits"]["batch_bytes"], json!(256 * 1024));
    assert_eq!(bundle["limits"]["live_objects"], json!(5000));
    assert_eq!(bundle["limits"]["export_bytes"], json!(8 * 1024 * 1024));
    assert_eq!(bundle["limits"]["export_batches"], json!(10_000));

    // After an assertion the visible link is listed and the owner's bundle
    // stays complete: the `changes` feed withholds a connector `semantic`
    // whole and unconditionally for every caller (an op carries no endpoint
    // context on which to resolve View), so that withholding is a uniform
    // property of the feed rather than redaction of this caller. Counting
    // it would make the flag false for the owner of any canvas that has
    // ever had a connector asserted, which discriminates nothing. Replay
    // is not free of it, though: an assertion batch cannot be re-folded
    // verbatim, and a replayer restores `semantic` from the bundle's own
    // scene first (see the replay recipe in docs/canvas-protocol-v1.md).
    let asserted = assert_connector(&fx, alice(), "k1", "relates_to").await;
    assert_eq!(asserted["outcome"], json!("committed"));
    let bundle = export_as(
        &fx,
        alice(),
        json!({ "action": "export", "canvas_id": fx.canvas }),
    )
    .await;
    let links = bundle["references"]["links"].as_array().unwrap();
    assert_eq!(links.len(), 1, "{bundle:#}");
    assert_eq!(links[0]["relationship"], json!("relates_to"));
    assert!(links[0]["id"].is_string(), "{bundle:#}");
    assert_eq!(bundle["disclosure"]["complete"], json!(true));
    assert_eq!(bundle["limits"]["export_batches"], json!(10_000));
    let scene_after = scene(&fx, alice()).await;
    assert_eq!(bundle["scene"]["objects"], scene_after["objects"]);
    let feed = changes(&fx, alice(), "canvas:0").await;
    assert_eq!(bundle["history"]["batches"], feed["batches"]);

    // The other direction of the distinction: Bea cannot see the private
    // end, so the SCENE withholds the assertion from her — and that one IS
    // caller-specific, hence counted and completeness-falsifying.
    let bundle = export_as(
        &fx,
        bea(),
        json!({ "action": "export", "canvas_id": fx.canvas }),
    )
    .await;
    assert_eq!(bundle["disclosure"]["complete"], json!(false));
    assert_eq!(bundle["disclosure"]["withheld_records"], json!(1));
    assert_eq!(bundle["disclosure"]["withheld_assertions"], json!(1));
    assert_eq!(bundle["references"]["links"], json!([]));
    let records = bundle["references"]["records"].as_array().unwrap();
    assert_eq!(records.len(), 1, "{bundle:#}");
    assert_eq!(records[0]["id"], json!(fx.shared));
    let scene_bea = scene(&fx, bea()).await;
    assert_eq!(bundle["scene"]["objects"], scene_bea["objects"]);

    assert_replay_exact(&fx.db).await;
}

/// Insert `count` minimal, well-formed canvas batches straight into the
/// ledger. The projector never ran for these rows, so this helper is only
/// for export size-cap tests that must never call `rebuild_and_diff`.
async fn stuff_batches(fx: &Fixture, count: usize, payload: &Value) {
    let pool = crate::common::fixture_write_pool(&fx.db).await;
    let base: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events")
        .fetch_one(&pool)
        .await
        .unwrap();
    let payload = serde_json::to_string(payload).unwrap();
    sqlx::query("BEGIN").execute(&pool).await.unwrap();
    for i in 0..count {
        let seq = base + i as i64 + 1;
        let event_id = format!("cap-evt-{seq}");
        sqlx::query(
            "INSERT INTO content_events(seq,id,record_id,type,payload,actor,\
             causal_envelope_version,causal_status) \
             VALUES (?,?,?,?,?,?,1,'complete')",
        )
        .bind(seq)
        .bind(&event_id)
        .bind(&fx.canvas)
        .bind("canvas.batch.committed.v1")
        .bind(&payload)
        .bind("acct:alice")
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO canvas_batches(canvas_id,batch_id,actor,event_id,event_seq,\
             ops_sha256,origin_kind) VALUES (?,?,?,?,?,?,?)",
        )
        .bind(&fx.canvas)
        .bind(format!("cap-{seq}"))
        .bind("acct:alice")
        .bind(&event_id)
        .bind(seq)
        .bind("0".repeat(64))
        .bind("agent")
        .execute(&pool)
        .await
        .unwrap();
    }
    sqlx::query("COMMIT").execute(&pool).await.unwrap();
}

fn minimal_batch_payload() -> Value {
    json!({
        "version": BATCH_VERSION,
        "batch_id": "cap",
        "origin": { "kind": "agent" },
        "ops": [],
        "ops_sha256": "0".repeat(64),
    })
}

/// F.5: export refuses `as_of`; refuses over the byte and batch caps naming
/// the limit; `include_history: false` returns `history: null`.
#[tokio::test]
async fn export_refuses_as_of_and_caps_while_shell_mode_returns_null_history() {
    let fx = fixture().await;

    // `as_of` is refused for export, as it is for `changes` and `describe`.
    let refused = fx
        .registry
        .call(
            fx.db.clone(),
            alice(),
            "read_canvas",
            json!({ "action": "export", "canvas_id": fx.canvas, "as_of": { "content_seq": 1 } }),
        )
        .await
        .expect_err("export must refuse as_of");
    assert!(refused.to_string().contains("as_of"), "{refused}");

    // Over the batch cap the export names `export_batches` and points at
    // `changes` paging; the shell fallback still works on the same canvas.
    stuff_batches(&fx, 10_001, &minimal_batch_payload()).await;
    let refused = fx
        .registry
        .call(
            fx.db.clone(),
            alice(),
            "read_canvas",
            json!({ "action": "export", "canvas_id": fx.canvas }),
        )
        .await
        .expect_err("history over the batch cap must refuse");
    assert!(refused.to_string().contains("export_batches"), "{refused}");
    assert!(refused.to_string().contains("changes"), "{refused}");
    let shell = export_as(
        &fx,
        alice(),
        json!({ "action": "export", "canvas_id": fx.canvas, "include_history": false }),
    )
    .await;
    assert_eq!(shell["history"], Value::Null);
    assert_eq!(shell["scene"]["version"], json!("native.canvas-scene.v1"));
    assert_eq!(shell["limits"]["export_batches"], json!(10_000));

    // Over the byte cap the export names `export_bytes`. One huge but
    // well-formed batch is enough: the scene stays empty (only the history
    // carries it), so `include_history: false` is the fallback again.
    let fx = fixture().await;
    let big = "x".repeat(9 * 1024 * 1024);
    stuff_batches(
        &fx,
        1,
        &json!({
            "version": BATCH_VERSION,
            "batch_id": "big-1",
            "origin": { "kind": "agent" },
            "ops": [{ "op": "create", "object": {
                "id": "big", "kind": "note", "x": 0, "y": 0, "w": 1, "h": 1, "z": "a",
                "props": { "text": big, "color": "yellow" },
            } }],
            "ops_sha256": "0".repeat(64),
        }),
    )
    .await;
    let refused = fx
        .registry
        .call(
            fx.db.clone(),
            alice(),
            "read_canvas",
            json!({ "action": "export", "canvas_id": fx.canvas }),
        )
        .await
        .expect_err("an export over the byte cap must refuse");
    assert!(refused.to_string().contains("export_bytes"), "{refused}");
    assert!(refused.to_string().contains("changes"), "{refused}");
    let shell = export_as(
        &fx,
        alice(),
        json!({ "action": "export", "canvas_id": fx.canvas, "include_history": false }),
    )
    .await;
    assert_eq!(shell["history"], Value::Null);
}

/// F.6: a caller without View gets the same non-existent-record refusal
/// `get_scene` gives.
#[tokio::test]
async fn export_without_view_fails_like_get_scene() {
    let fx = fixture().await;
    commit(
        &fx,
        alice(),
        batch(&fx.canvas, "b-1", json!([note("n1", 0.0, "a")])),
    )
    .await;
    replace_explicit_policy(
        &fx.db,
        "test:canvas-policy",
        &fx.canvas,
        vec![AllowEntry::account("acct:alice", Capability::Manage)],
    )
    .await
    .unwrap();

    let scene_err = fx
        .registry
        .call(
            fx.db.clone(),
            bea(),
            "read_canvas",
            json!({ "action": "get_scene", "canvas_id": fx.canvas }),
        )
        .await
        .expect_err("get_scene without View must refuse")
        .to_string();
    let export_err = fx
        .registry
        .call(
            fx.db.clone(),
            bea(),
            "read_canvas",
            json!({ "action": "export", "canvas_id": fx.canvas }),
        )
        .await
        .expect_err("export without View must refuse")
        .to_string();
    assert!(export_err.contains("does not exist"), "{export_err}");
    assert_eq!(export_err, scene_err);
    assert!(!export_err.contains("Sprint sketch"));
    assert_replay_exact(&fx.db).await;
}

// ---------------------------------------------------------------------------
// Milestone 3, PR A, CHUNK 2: replay proofs.
// ---------------------------------------------------------------------------

/// Map each batch's `canvas_version` token to its 1-based ordinal, so two
/// scenes folded at different absolute `content_events.seq` values can be
/// compared. Absolute `canvas:N` tokens cannot survive a move between
/// databases; the ordinal of the batch that stamped them can.
fn replay_ordinal_map(batches: &[Value]) -> BTreeMap<String, u64> {
    batches
        .iter()
        .enumerate()
        .map(|(index, batch)| {
            (
                batch["canvas_version"].as_str().unwrap_or("").to_string(),
                (index + 1) as u64,
            )
        })
        .collect()
}

/// Clone scene objects with `versions.geometry`/`versions.content` replaced
/// by batch ordinals, sorted by id so fold order cannot matter.
fn normalised_scene(objects: &[Value], ordinals: &BTreeMap<String, u64>) -> Vec<Value> {
    let mut out: Vec<Value> = objects
        .iter()
        .map(|object| {
            let mut object = object.clone();
            for group in ["geometry", "content"] {
                let token = object
                    .pointer(&format!("/versions/{group}"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let ordinal = ordinals
                    .get(&token)
                    .copied()
                    .unwrap_or_else(|| panic!("version token {token} names no batch in {object}"));
                *object
                    .pointer_mut(&format!("/versions/{group}"))
                    .expect("versions group") = json!(ordinal);
            }
            object
        })
        .collect();
    out.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    out
}

async fn scene_versions(fx: &Fixture, caller: Caller) -> BTreeMap<String, (String, String)> {
    scene(fx, caller).await["objects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|object| {
            (
                object["id"].as_str().unwrap().to_string(),
                (
                    object["versions"]["geometry"].as_str().unwrap().to_string(),
                    object["versions"]["content"].as_str().unwrap().to_string(),
                ),
            )
        })
        .collect()
}

/// F.2: engine replay. Fold every exported batch's ops, in order, into a
/// fresh canvas in a fresh database through `canvas::apply_batch` with
/// `PropsAuthority::of(origin.kind)`, in one transaction, and compare the
/// scene modulo version ordinals.
///
/// No production-code change was needed for this: the authority already
/// travels with the batch through the public, pure `PropsAuthority::of`,
/// and `apply_batch` never consults `validate_envelope` — the PR #997
/// client seam (engine origins refused at submission) is untouched, since
/// the test folds stored/exported ops directly and never submits an
/// engine origin through `commit_batch`.
///
/// Two honest normalisations apply, both asserted rather than hidden:
/// - The feed withholds a connector `semantic` unconditionally, so the
///   exported assertion op carries `"semantic": "withheld"`, which even the
///   Engine fold refuses. It is repaired from the bundle's own scene, which
///   carries the owner's visible assertion. (A promotion patch's
///   `record_id`/`promoted_from` needed the same repair until the feed
///   learned to harvest patch ids and spare null placeholders; the feed
///   now carries them for a caller who may see the record, so that repair
///   is gone.)
/// - Record cards name records absent from the fresh database, so they
///   read back `record_id: "withheld"` with no face (B3). The pre-redaction
///   props are verified straight from `canvas_objects` instead.
#[tokio::test]
async fn engine_replay_through_apply_batch_reproduces_the_scene_modulo_remapping() {
    let fx = fixture().await;
    // A stream with every op kind, a frame delete that detaches a child, an
    // assertion and a promotion — so engine-authored origins are in it.
    let first = commit(
        &fx,
        alice(),
        batch(
            &fx.canvas,
            "f2-seed",
            json!([
                frame("f1", 0.0, "Plan"),
                { "op": "create", "object": { "id": "n1", "kind": "note", "x": 40, "y": 10, "w": 100, "h": 100, "z": "b", "parent": "f1", "props": { "text": "child" } } },
                { "op": "create", "object": { "id": "s1", "kind": "shape", "x": 300, "y": 20, "w": 80, "h": 80, "z": "c", "props": { "shape": "rect" } } },
                { "op": "create", "object": { "id": "t1", "kind": "stroke", "x": 0, "y": 0, "w": 10, "h": 10, "z": "d", "props": { "points": [[0, 0], [5, 5]], "width": 2 } } },
                card("c-shared", 400.0, &fx.shared),
                card("c-private", 700.0, &fx.private),
                // The connector carries a `label` so the replay comparison
                // below exercises it rather than merely listing it: a fold
                // that dropped `label` must fail.
                { "op": "create", "object": { "id": "k1", "kind": "connector", "x": 0, "y": 0, "w": 0, "h": 0, "z": "ak1", "props": { "from": { "object": "c-shared" }, "to": { "object": "c-private" }, "style": "arrow", "label": "ships it" } } },
                note("n2", 900.0, "to be promoted"),
            ]),
        ),
    )
    .await;
    assert_eq!(first["outcome"], json!("committed"), "{first:#}");
    let v1 = first["canvas_version"].as_str().unwrap().to_string();
    let moved = commit(
        &fx,
        alice(),
        batch(
            &fx.canvas,
            "f2-touch",
            json!([
                { "op": "patch", "id": "n1", "expected": { "geometry": v1 }, "set": { "x": 60 } },
                { "op": "patch", "id": "n2", "expected": { "content": v1 }, "set": { "props": { "text": "edited" } } },
            ]),
        ),
    )
    .await;
    assert_eq!(moved["outcome"], json!("committed"), "{moved:#}");
    let asserted = assert_connector(&fx, alice(), "k1", "relates_to").await;
    assert_eq!(asserted["outcome"], json!("committed"));
    let planned = commit(
        &fx,
        alice(),
        json!({
            "action": "promote",
            "canvas_id": fx.canvas,
            "reason": "f.2 replay seed",
            "dry_run": true,
            "items": [{ "object_id": "n2", "type": "WorkItem", "kind": "task", "name": "Promoted in F.2" }],
        }),
    )
    .await;
    assert_eq!(planned["outcome"], json!("planned"), "{planned:#}");
    let done = commit(
        &fx,
        alice(),
        json!({
            "action": "promote",
            "canvas_id": fx.canvas,
            "reason": "f.2 replay seed",
            "dry_run": false,
            "plan_digest": planned["plan_digest"],
            "items": [{ "object_id": "n2", "type": "WorkItem", "kind": "task", "name": "Promoted in F.2" }],
        }),
    )
    .await;
    assert_eq!(done["outcome"], json!("committed"), "{done:#}");
    let versions = scene_versions(&fx, alice()).await;
    let dropped = commit(
        &fx,
        alice(),
        batch(
            &fx.canvas,
            "f2-drop",
            json!([{ "op": "delete", "id": "f1",
                "expected": { "geometry": versions["f1"].0, "content": versions["f1"].1 } }]),
        ),
    )
    .await;
    assert_eq!(dropped["outcome"], json!("committed"), "{dropped:#}");
    let versions = scene_versions(&fx, alice()).await;
    let restored = commit(
        &fx,
        alice(),
        batch(
            &fx.canvas,
            "f2-back",
            json!([{ "op": "restore", "id": "f1",
                "expected": { "geometry": versions["f1"].0, "content": versions["f1"].1 } }]),
        ),
    )
    .await;
    assert_eq!(restored["outcome"], json!("committed"), "{restored:#}");

    let bundle = export_as(
        &fx,
        alice(),
        json!({ "action": "export", "canvas_id": fx.canvas }),
    )
    .await;
    // The promotion's record and `promoted_from` survive the feed for a
    // caller who may see them (patch-id harvesting, null placeholders
    // spared), so the owner's bundle is complete.
    assert_eq!(bundle["disclosure"]["withheld_records"], json!(0));
    assert_eq!(bundle["disclosure"]["withheld_assertions"], json!(0));
    assert_eq!(bundle["disclosure"]["complete"], json!(true));
    let batches = bundle["history"]["batches"].as_array().unwrap().clone();
    assert_eq!(batches.len(), 6, "{bundle:#}");
    let exp_objects = bundle["scene"]["objects"].as_array().unwrap().clone();

    // Semantic repair from the bundle's own scene: the feed's uniform
    // withholding does not re-fold, but the owner's scene carries the
    // visible assertion the stored batch wrote.
    let mut semantics = BTreeMap::new();
    for object in &exp_objects {
        let id = object["id"].as_str().unwrap().to_string();
        if object["kind"] == json!("connector") && object["props"]["semantic"].is_object() {
            semantics.insert(id, object["props"]["semantic"].clone());
        }
    }

    let fresh = create_database(":memory:").await.unwrap();
    let fresh_registry = registry();
    let fresh_canvas = create_local(
        &fresh_registry,
        &fresh,
        json!({ "type": "Document", "kind": "canvas", "name": "Replay" }),
    )
    .await;
    let pool = crate::common::fixture_write_pool(&fresh).await;
    let mut conn = pool.acquire().await.unwrap();
    // Replay reads before writing. Acquire the writer lock up front so the
    // fixture's busy timeout can wait for the setup call's background capture.
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut *conn)
        .await
        .unwrap();
    for (index, batch) in batches.iter().enumerate() {
        let kind: OriginKind = serde_json::from_value(batch["origin"]["kind"].clone()).unwrap();
        let mut ops: Vec<Op> = serde_json::from_value(batch["ops"].clone()).unwrap();
        for op in &mut ops {
            if let Op::Patch { id, set, .. } = op {
                if let Some(props) = set.props.as_mut() {
                    if props.get("semantic") == Some(&Value::String("withheld".into())) {
                        let restored = semantics.get(id.as_str()).unwrap_or_else(|| {
                            panic!("no visible semantic to restore for connector {id}")
                        });
                        props.insert("semantic".into(), restored.clone());
                    }
                }
            }
        }
        if let Err(error) = apply_batch(
            &mut conn,
            &fresh_canvas,
            (index + 1) as i64,
            &ops,
            PropsAuthority::of(kind),
        )
        .await
        {
            panic!("replay of batch {} failed: {:?}", batch["batch_id"], error);
        }
    }
    sqlx::query("COMMIT").execute(&mut *conn).await.unwrap();
    drop(conn);

    let rep_scene = fresh_registry
        .call(
            fresh.clone(),
            Caller::local(),
            "read_canvas",
            json!({ "action": "get_scene", "canvas_id": fresh_canvas, "include_deleted": true }),
        )
        .await
        .unwrap();
    let rep_objects = rep_scene["objects"].as_array().unwrap().clone();
    let exp_map = replay_ordinal_map(&batches);
    let rep_versions: Vec<Value> = (1..=batches.len())
        .map(|seq| json!({ "canvas_version": format!("canvas:{seq}") }))
        .collect();
    let rep_map = replay_ordinal_map(&rep_versions);
    let exp = normalised_scene(&exp_objects, &exp_map);
    let rep = normalised_scene(&rep_objects, &rep_map);
    assert_eq!(exp.len(), rep.len(), "object count survives replay");
    for (e, r) in exp.iter().zip(rep.iter()) {
        let id = e["id"].as_str().unwrap();
        assert_eq!(r["id"], e["id"], "stable object id");
        for field in [
            "kind", "x", "y", "w", "h", "z", "parent", "deleted", "versions",
        ] {
            assert_eq!(&r[field], &e[field], "object {id} field {field}");
        }
        if e["kind"] == json!("record_card") {
            // B3: the records live only in the source database, so the
            // replayed faces resolve to nothing — and with the record
            // wholly absent (not merely deleted) the id itself withholds.
            assert_eq!(r["props"]["record_id"], json!("withheld"), "card {id}");
            assert!(r.get("record").is_none(), "card {id} face");
            assert_eq!(r["props"].as_object().unwrap().len(), 1, "card {id}");
            assert_ne!(e["props"]["record_id"], json!("withheld"));
            assert!(e["record"].is_object(), "exported card {id} face");
        } else if e["kind"] == json!("connector") {
            // Pinned so the loop below exercises `label` rather than
            // merely listing it: both sides must carry the seeded value.
            assert_eq!(e["props"]["label"], json!("ships it"), "seed carries label");
            for field in ["from", "to", "style", "label"] {
                assert_eq!(&r["props"][field], &e["props"][field], "connector {id}");
            }
            assert_eq!(e["props"]["semantic"]["status"], json!("asserted"));
            // In the fresh database neither endpoint record exists, so the
            // scene withholds the whole assertion — the same caller-specific
            // rule that hides it from anyone who cannot see both ends. The
            // stored assertion itself is verified below straight from
            // `canvas_objects`, where redaction cannot reach it.
            assert_eq!(r["props"]["semantic"], json!("withheld"));
        } else {
            assert_eq!(r["props"], e["props"], "object {id} props");
        }
    }

    // Beneath redaction the engine transitions landed verbatim.
    let props_n2: String =
        sqlx::query_scalar("SELECT props FROM canvas_objects WHERE canvas_id=? AND object_id='n2'")
            .bind(&fresh_canvas)
            .fetch_one(&pool)
            .await
            .unwrap();
    let props_n2: Value = serde_json::from_str(&props_n2).unwrap();
    let exported_n2 = exp.iter().find(|o| o["id"] == json!("n2")).unwrap();
    assert_eq!(props_n2["record_id"], exported_n2["props"]["record_id"]);
    assert_eq!(
        props_n2["promoted_from"],
        exported_n2["props"]["promoted_from"]
    );
    let props_k1: String =
        sqlx::query_scalar("SELECT props FROM canvas_objects WHERE canvas_id=? AND object_id='k1'")
            .bind(&fresh_canvas)
            .fetch_one(&pool)
            .await
            .unwrap();
    let props_k1: Value = serde_json::from_str(&props_k1).unwrap();
    assert_eq!(props_k1["semantic"], semantics["k1"]);

    // The source log is internally consistent. The fresh database gets no
    // rebuild check: its projections were written directly by the test fold
    // and it carries no event log to rebuild from — there is nothing for
    // `rebuild_and_diff` to replay there.
    assert!(rebuild_and_diff(&fx.db).await.unwrap().equal);
}

/// F.3: protocol replay — the recipe an agent can actually run today. For a
/// bundle whose batches are all client-authored, re-submit each batch
/// through `manage_canvas.commit_batch` into a new canvas as a new `agent`
/// batch, rewriting every `expected` token from the previous result's
/// `objects` map, and compare the scenes modulo ordinals. Same database,
/// so the records behind the cards resolve identically on both sides and
/// the comparison is strict.
#[tokio::test]
async fn protocol_replay_through_commit_batch_reproduces_the_scene_modulo_remapping() {
    let fx = fixture().await;
    let first = commit(
        &fx,
        alice(),
        batch(
            &fx.canvas,
            "f3-seed",
            json!([
                frame("f1", 0.0, "Plan"),
                { "op": "create", "object": { "id": "n1", "kind": "note", "x": 40, "y": 10, "w": 100, "h": 100, "z": "b", "parent": "f1", "props": { "text": "child" } } },
                { "op": "create", "object": { "id": "s1", "kind": "shape", "x": 300, "y": 20, "w": 80, "h": 80, "z": "c", "props": { "shape": "rect" } } },
                { "op": "create", "object": { "id": "t1", "kind": "stroke", "x": 0, "y": 0, "w": 10, "h": 10, "z": "d", "props": { "points": [[0, 0], [5, 5]], "width": 2 } } },
                card("c-shared", 400.0, &fx.shared),
                card("c-private", 700.0, &fx.private),
                note("n9", 900.0, "doomed"),
            ]),
        ),
    )
    .await;
    assert_eq!(first["outcome"], json!("committed"), "{first:#}");
    let v1 = first["canvas_version"].as_str().unwrap().to_string();
    let touched = commit(
        &fx,
        alice(),
        batch(
            &fx.canvas,
            "f3-touch",
            json!([
                { "op": "patch", "id": "n1", "expected": { "geometry": v1 }, "set": { "x": 60 } },
                { "op": "patch", "id": "n9", "expected": { "content": v1 }, "set": { "props": { "text": "edited" } } },
            ]),
        ),
    )
    .await;
    assert_eq!(touched["outcome"], json!("committed"), "{touched:#}");
    let versions = scene_versions(&fx, alice()).await;
    let dropped = commit(
        &fx,
        alice(),
        batch(
            &fx.canvas,
            "f3-drop",
            json!([{ "op": "delete", "id": "f1",
                "expected": { "geometry": versions["f1"].0, "content": versions["f1"].1 } }]),
        ),
    )
    .await;
    assert_eq!(dropped["outcome"], json!("committed"), "{dropped:#}");
    let versions = scene_versions(&fx, alice()).await;
    let restored = commit(
        &fx,
        alice(),
        batch(
            &fx.canvas,
            "f3-back",
            json!([{ "op": "restore", "id": "f1",
                "expected": { "geometry": versions["f1"].0, "content": versions["f1"].1 } }]),
        ),
    )
    .await;
    assert_eq!(restored["outcome"], json!("committed"), "{restored:#}");
    let versions = scene_versions(&fx, alice()).await;
    let tombstoned = commit(
        &fx,
        alice(),
        batch(
            &fx.canvas,
            "f3-tomb",
            json!([{ "op": "delete", "id": "n9",
                "expected": { "geometry": versions["n9"].0, "content": versions["n9"].1 } }]),
        ),
    )
    .await;
    assert_eq!(tombstoned["outcome"], json!("committed"), "{tombstoned:#}");

    let bundle = export_as(
        &fx,
        alice(),
        json!({ "action": "export", "canvas_id": fx.canvas }),
    )
    .await;
    // Client-authored throughout, fully visible to the owner: complete.
    assert_eq!(bundle["disclosure"]["complete"], json!(true));
    let batches = bundle["history"]["batches"].as_array().unwrap().clone();
    assert_eq!(batches.len(), 5, "{bundle:#}");
    let exp_objects = bundle["scene"]["objects"].as_array().unwrap().clone();

    let target = create_local(
        &fx.registry,
        &fx.db,
        json!({ "type": "Document", "kind": "canvas", "name": "Replay target" }),
    )
    .await;
    replace_explicit_policy(
        &fx.db,
        "test:canvas-replay",
        &target,
        vec![AllowEntry::account("acct:alice", Capability::Manage)],
    )
    .await
    .unwrap();
    // Batch ids are namespaced per canvas by the idempotency ledger, so the
    // exported ids are safe to reuse on the new canvas.
    let mut versions: BTreeMap<String, Value> = BTreeMap::new();
    let mut rep_versions = Vec::new();
    for batch in &batches {
        let mut ops = batch["ops"].clone();
        for op in ops.as_array_mut().unwrap() {
            if let Some(id) = op.get("id").and_then(Value::as_str) {
                let current = versions
                    .get(id)
                    .unwrap_or_else(|| panic!("no committed versions yet for {id}"));
                op["expected"] =
                    json!({ "geometry": current["geometry"], "content": current["content"] });
            }
        }
        let result = commit(
            &fx,
            alice(),
            json!({ "action": "commit_batch", "batch": {
                "version": BATCH_VERSION,
                "canvas_id": target,
                "batch_id": batch["batch_id"],
                "origin": { "kind": "agent" },
                "ops": ops,
            }}),
        )
        .await;
        assert_eq!(result["outcome"], json!("committed"), "{result:#}");
        rep_versions.push(json!({ "canvas_version": result["canvas_version"] }));
        for (id, tokens) in result["objects"].as_object().unwrap() {
            versions.insert(id.clone(), tokens.clone());
        }
    }

    let rep_objects = fx
        .registry
        .call(
            fx.db.clone(),
            alice(),
            "read_canvas",
            json!({ "action": "get_scene", "canvas_id": target, "include_deleted": true }),
        )
        .await
        .unwrap()["objects"]
        .as_array()
        .unwrap()
        .clone();
    let exp = normalised_scene(&exp_objects, &replay_ordinal_map(&batches));
    let rep = normalised_scene(&rep_objects, &replay_ordinal_map(&rep_versions));
    assert_eq!(
        exp, rep,
        "protocol replay reproduces the scene modulo ordinals"
    );

    assert_replay_exact(&fx.db).await;
}

/// F.4: `export` is the seventh disclosure path. Structured exactly like
/// the six-path test above (`a_record_the_caller_may_not_see_appears_on_no_read_path`):
/// Alice summons both records as cards; Bea holds View on the shared one
/// only. As Bea, the whole bundle never contains the hidden record's id,
/// `disclosure.complete` is false, and `disclosure.withheld_records`
/// counts it. (F.1 already shows the withheld side counts on an asserted
/// canvas; this test pins the full-string absence the other tests assert
/// per read path.)
#[tokio::test]
async fn export_never_names_a_record_the_caller_may_not_see() {
    let fx = fixture().await;
    let created = commit(
        &fx,
        alice(),
        batch(
            &fx.canvas,
            "b-1",
            json!([
                card("c-shared", 0.0, &fx.shared),
                card("c-private", 300.0, &fx.private),
            ]),
        ),
    )
    .await;
    assert_eq!(created["outcome"], json!("committed"), "{created:#}");

    // Control: Alice's bundle names both records and is complete.
    let mine = export_as(
        &fx,
        alice(),
        json!({ "action": "export", "canvas_id": fx.canvas }),
    )
    .await;
    let body = serde_json::to_string(&mine).unwrap();
    assert!(body.contains(&fx.shared), "the visible card is named");
    assert!(body.contains(&fx.private), "Alice may see both records");
    assert_eq!(mine["disclosure"]["complete"], json!(true));

    // Bea's bundle: no hidden id anywhere — scene, history, references —
    // counted once and marked incomplete.
    let theirs = export_as(
        &fx,
        bea(),
        json!({ "action": "export", "canvas_id": fx.canvas }),
    )
    .await;
    let body = serde_json::to_string(&theirs).unwrap();
    assert!(
        !body.contains(&fx.private),
        "export is a read path like any other: {body:#}"
    );
    assert!(body.contains(&fx.shared), "the visible card is still named");
    assert_eq!(theirs["disclosure"]["complete"], json!(false));
    assert_eq!(theirs["disclosure"]["withheld_records"], json!(1));

    assert_replay_exact(&fx.db).await;
}
