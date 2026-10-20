//! Keyed replay for multi-output writes (task 8bef361, slice A2):
//! `create_many` and `instantiate_artifact`, on the A0 harness in
//! `keyed_replay.rs`. `attach_from_url` needs a local HTTP server and lives
//! in `fetch_guard.rs`; `resolve_external` refuses a key and is pinned here.

use native_ce::mcp::Caller;
use serde_json::{json, Value};

use crate::keyed_replay::{
    assert_concurrent_calls_write_once, assert_replays_without_writing,
    assert_reuse_with_other_args_conflicts, assert_same_receipt, call, db, hosted, hosted_person,
    registry, write_footprint, KeyedCase,
};

// ---------------------------------------------------------------------------
// create_many
// ---------------------------------------------------------------------------

/// A small graph: a folder, a child homed in it that links to and mentions
/// it, and an independent note. The ids the server mints are what a replay
/// has to reproduce.
fn graph(key: &str, mode: &str) -> Value {
    json!({
        "reason": "Create a connected graph.",
        "response_mode": mode,
        "idempotency_key": key,
        "records": [
            {"ref": "child", "type": "Document", "kind": "note", "name": "Child",
             "parent_ref": "folder", "body": "See [[folder]].",
             "links": [{"target_ref": "folder", "relationship": "relates_to"}]},
            {"ref": "folder", "type": "Collection", "kind": "folder", "name": "Folder"},
            {"type": "Document", "kind": "note", "name": "Loose", "body": "loose",
             "facets": {"status": "draft"}},
        ],
    })
}

fn ids_of(receipt: &Value) -> Vec<String> {
    receipt["ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| id.as_str().unwrap_or_default().to_owned())
        .collect()
}

async fn record_column(db: &native_ce::Db, id: &str, column: &str) -> Option<String> {
    sqlx::query_scalar(&format!("SELECT {column} FROM records WHERE id = ?"))
        .bind(id)
        .fetch_one(db.pool())
        .await
        .unwrap()
}

async fn creates(db: &native_ce::Db) -> i64 {
    crate::common::count(
        db,
        "SELECT COUNT(*) AS n FROM content_events WHERE type = 'record.created'",
    )
    .await
}

#[tokio::test]
async fn create_many_replays_the_minted_graph_and_conflicts_on_other_records() {
    for mode in ["summary", "verbose"] {
        let registry = registry();
        let db = db().await;
        let mut conflicting = graph("graph", mode);
        conflicting["records"][2]["name"] = json!("Renamed");
        let case = KeyedCase {
            tool: "create_many",
            args: graph("graph", mode),
            conflicting,
        };
        let before = creates(&db).await;
        let first = assert_replays_without_writing(&registry, &db, Caller::local(), &case).await;
        assert_eq!(first["ok"], json!(true), "{mode}: {first}");
        assert_eq!(creates(&db).await, before + 3, "{mode}");
        let ids = ids_of(&first);
        assert_eq!(
            record_column(&db, &ids[0], "home_id").await.as_deref(),
            Some(ids[1].as_str()),
            "{mode}"
        );
        assert_eq!(
            record_column(&db, &ids[0], "body").await,
            Some(format!("See [[{}]].", ids[1])),
            "{mode}"
        );
        // One attestation per created item, no whole-call anchor.
        let rows = crate::common::count(
            &db,
            "SELECT COUNT(*) AS n FROM provenance_action_attestations WHERE operation = 'create_many'",
        )
        .await;
        assert_eq!(rows, 3, "{mode}");
        assert_reuse_with_other_args_conflicts(&registry, &db, Caller::local(), &case).await;
        // The other response mode is a presentation choice, not a new command.
        let other = if mode == "summary" {
            "verbose"
        } else {
            "summary"
        };
        let replayed = call(
            &registry,
            &db,
            Caller::local(),
            "create_many",
            graph("graph", other),
        )
        .await
        .unwrap();
        assert_eq!(ids_of(&replayed), ids, "{mode}");
        assert_eq!(creates(&db).await, before + 3, "{mode}");
    }
}

#[tokio::test]
async fn create_many_concurrent_same_key_creates_each_record_once() {
    let registry = registry();
    let db = db().await;
    let case = KeyedCase {
        tool: "create_many",
        args: graph("race", "summary"),
        conflicting: Value::Null,
    };
    let before = creates(&db).await;
    let receipt =
        assert_concurrent_calls_write_once(registry, &db, Caller::local(), &case, 6).await;
    assert_eq!(receipt["ok"], json!(true), "{receipt}");
    assert_eq!(creates(&db).await, before + 3);
}

/// A failed item writes nothing and leaves no row, so the key never replays
/// the partial result as complete: a retry replays the items that were
/// created and attempts the others again, binding them to the records the
/// first call minted.
#[tokio::test]
async fn create_many_partial_failure_resumes_instead_of_replaying_as_complete() {
    let registry = registry();
    let db = db().await;
    let missing = uuid::Uuid::new_v4().to_string();
    let args = json!({
        "reason": "Create a folder and a linked child.",
        "idempotency_key": "partial",
        "records": [
            {"ref": "folder", "type": "Collection", "kind": "folder", "name": "Folder"},
            {"type": "Document", "kind": "note", "name": "Child", "parent_ref": "folder",
             "links": [{"target_id": missing, "relationship": "relates_to"}]},
        ],
    });
    let first = call(&registry, &db, Caller::local(), "create_many", args.clone())
        .await
        .unwrap();
    assert_eq!(first["ok"], json!(false), "{first}");
    assert_eq!(first["errors"][0]["index"], json!(1), "{first}");
    let folder = ids_of(&first)[0].clone();
    assert!(!folder.is_empty());

    // A retry before anything changes fails the same item again, and does
    // not create the folder twice.
    let before = creates(&db).await;
    let again = call(&registry, &db, Caller::local(), "create_many", args.clone())
        .await
        .unwrap();
    assert_eq!(again["ok"], json!(false), "{again}");
    assert_eq!(ids_of(&again)[0], folder);
    assert_eq!(creates(&db).await, before);

    // Once the link target exists, the retry completes the call.
    call(
        &registry,
        &db,
        Caller::local(),
        "create_record",
        json!({"id": missing, "type": "Document", "kind": "note", "name": "Target"}),
    )
    .await
    .unwrap();
    let before = creates(&db).await;
    let resumed = call(&registry, &db, Caller::local(), "create_many", args.clone())
        .await
        .unwrap();
    assert_eq!(resumed["ok"], json!(true), "{resumed}");
    let ids = ids_of(&resumed);
    assert_eq!(ids[0], folder, "the folder is replayed, not recreated");
    assert_eq!(creates(&db).await, before + 1, "only the child is created");
    assert_eq!(
        record_column(&db, &ids[1], "home_id").await,
        Some(folder),
        "bound to the first call's folder"
    );

    // Now complete, the key replays without writing.
    let footprint = write_footprint(&db).await;
    let replay = call(&registry, &db, Caller::local(), "create_many", args)
        .await
        .unwrap();
    assert_same_receipt(&replay, &resumed, "completed create_many");
    assert_eq!(write_footprint(&db).await, footprint);
}

/// Replay runs inside each item's own transaction, after its authorization:
/// a caller who lost Edit on the home gets the per-item refusal a fresh key
/// gets, and the record the first call created is not disclosed.
#[tokio::test]
async fn create_many_replay_after_lost_access_matches_a_fresh_key() {
    let registry = registry();
    let db = db().await;
    hosted_person(&registry, &db, "acct:alice").await;
    let home = call(
        &registry,
        &db,
        Caller::local(),
        "create_record",
        json!({"type": "Collection", "kind": "folder", "name": "shared home"}),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let args = json!({
        "reason": "Create under a shared home.",
        "idempotency_key": "lost-home",
        "records": [{"type": "Document", "kind": "note", "name": "Inside", "home_id": home}],
    });
    let first = call(
        &registry,
        &db,
        hosted("acct:alice"),
        "create_many",
        args.clone(),
    )
    .await
    .unwrap();
    assert_eq!(first["ok"], json!(true), "{first}");
    let created = ids_of(&first)[0].clone();
    call(
        &registry,
        &db,
        Caller::local(),
        "manage_record_policy",
        json!({"action": "set_members_baseline", "record_id": home,
               "reason": "Revoke the members baseline for the replay test."}),
    )
    .await
    .unwrap();
    let footprint = write_footprint(&db).await;
    let replay = call(
        &registry,
        &db,
        hosted("acct:alice"),
        "create_many",
        args.clone(),
    )
    .await
    .unwrap();
    let mut fresh_args = args;
    fresh_args["idempotency_key"] = json!("never-used");
    let fresh = call(
        &registry,
        &db,
        hosted("acct:alice"),
        "create_many",
        fresh_args,
    )
    .await
    .unwrap();
    assert_eq!(replay["ok"], json!(false), "{replay}");
    assert_eq!(replay, fresh, "replay refusal must match a fresh key's");
    assert!(!replay.to_string().contains(&created), "{replay}");
    assert_eq!(write_footprint(&db).await, footprint);
}

// ---------------------------------------------------------------------------
// instantiate_artifact
// ---------------------------------------------------------------------------

const BOARD: &str = include_str!("../fixtures/native-board-v1.json");

async fn artifact(registry: &native_ce::mcp::ToolRegistry, db: &native_ce::Db) -> String {
    call(
        registry,
        db,
        Caller::local(),
        "create_record",
        json!({"type": "Document", "kind": "artifact", "name": "Reusable board",
               "body": BOARD, "facets": {"runtime": "native.board.v1"}}),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn instantiate_artifact_replays_the_one_copy_and_conflicts() {
    let registry = registry();
    let db = db().await;
    let source = artifact(&registry, &db).await;
    let case = KeyedCase {
        tool: "instantiate_artifact",
        args: json!({"source_id": source, "title": "Copy", "idempotency_key": "copy"}),
        conflicting: json!({"source_id": source, "title": "Other", "idempotency_key": "copy"}),
    };
    let before = creates(&db).await;
    let first = assert_replays_without_writing(&registry, &db, Caller::local(), &case).await;
    assert_eq!(creates(&db).await, before + 1);
    assert_reuse_with_other_args_conflicts(&registry, &db, Caller::local(), &case).await;

    // The source's liveness is a state precondition: archiving it after the
    // copy was made does not stop the retry from replaying.
    call(
        &registry,
        &db,
        Caller::local(),
        "archive_record",
        json!({"id": source}),
    )
    .await
    .unwrap();
    let replay = call(
        &registry,
        &db,
        Caller::local(),
        "instantiate_artifact",
        case.args.clone(),
    )
    .await
    .unwrap();
    assert_same_receipt(&replay, &first, "replay after archiving the source");

    // Once the copy is written again, the replay still names it as created.
    call(
        &registry,
        &db,
        Caller::local(),
        "update_record",
        json!({"id": first["id"], "name": "Renamed copy"}),
    )
    .await
    .unwrap();
    let footprint = write_footprint(&db).await;
    let replay = call(
        &registry,
        &db,
        Caller::local(),
        "instantiate_artifact",
        case.args,
    )
    .await
    .unwrap();
    assert_eq!(replay["id"], first["id"]);
    assert_eq!(replay["name"], json!("Copy"), "{replay}");
    assert_eq!(replay["act"], first["act"]);
    assert_eq!(replay["body_digest"], first["body_digest"]);
    assert_same_receipt(&replay, &first, "replay after a later write");
    assert_eq!(write_footprint(&db).await, footprint);
}

#[tokio::test]
async fn instantiate_artifact_concurrent_same_key_copies_once() {
    let registry = registry();
    let db = db().await;
    let source = artifact(&registry, &db).await;
    let case = KeyedCase {
        tool: "instantiate_artifact",
        args: json!({"source_id": source, "idempotency_key": "race"}),
        conflicting: Value::Null,
    };
    let before = creates(&db).await;
    assert_concurrent_calls_write_once(registry, &db, Caller::local(), &case, 6).await;
    assert_eq!(creates(&db).await, before + 1);
}

#[tokio::test]
async fn instantiate_artifact_replay_after_lost_access_matches_a_fresh_key() {
    let registry = registry();
    let db = db().await;
    hosted_person(&registry, &db, "acct:alice").await;
    let source = artifact(&registry, &db).await;
    let args = json!({"source_id": source, "idempotency_key": "lost-source"});
    let first = call(
        &registry,
        &db,
        hosted("acct:alice"),
        "instantiate_artifact",
        args.clone(),
    )
    .await
    .unwrap();
    call(
        &registry,
        &db,
        Caller::local(),
        "manage_record_policy",
        json!({"action": "set_members_baseline", "record_id": source,
               "reason": "Revoke the members baseline for the replay test."}),
    )
    .await
    .unwrap();
    let footprint = write_footprint(&db).await;
    let denied = call(
        &registry,
        &db,
        hosted("acct:alice"),
        "instantiate_artifact",
        args.clone(),
    )
    .await
    .unwrap_err()
    .to_string();
    let mut fresh = args;
    fresh["idempotency_key"] = json!("never-used");
    let fresh = call(
        &registry,
        &db,
        hosted("acct:alice"),
        "instantiate_artifact",
        fresh,
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(denied, fresh);
    assert!(!denied.contains(first["id"].as_str().unwrap()), "{denied}");
    assert_eq!(write_footprint(&db).await, footprint);
}

// ---------------------------------------------------------------------------
// resolve_external
// ---------------------------------------------------------------------------

/// `resolve_external` commits outside the attested path and is find-or-create
/// by binding, so it takes no key: a real key is refused by name, with
/// nothing written, and a blank one means no key.
#[tokio::test]
async fn resolve_external_refuses_a_key_by_name_and_ignores_a_blank_one() {
    let registry = registry();
    let db = db().await;
    let claim = json!({
        "bindings": [{"system": "native-principal", "identifier": "acct:someone-else"}],
        "hints": {"record_type": "Entity", "kind": "person", "name": "Someone"},
    });
    let footprint = write_footprint(&db).await;
    let mut keyed = claim.clone();
    keyed["idempotency_key"] = json!("resolve");
    let refused = call(&registry, &db, Caller::local(), "resolve_external", keyed)
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        refused,
        "resolve_external does not accept idempotency_key: repeating the same claims \
         resolves the same record without writing again, and reports created:false; \
         retry without a key"
    );
    assert_eq!(write_footprint(&db).await, footprint);

    let mut blank = claim.clone();
    blank["idempotency_key"] = json!(" ");
    let with_blank = call(&registry, &db, Caller::local(), "resolve_external", blank)
        .await
        .map_err(|error| error.to_string());
    let without = call(&registry, &db, Caller::local(), "resolve_external", claim)
        .await
        .map_err(|error| error.to_string());
    match (&with_blank, &without) {
        (Ok(first), Ok(second)) => assert_eq!(first["record_id"], second["record_id"]),
        (Err(first), Err(second)) => assert_eq!(first, second),
        _ => panic!("a blank key changed the outcome: {with_blank:?} vs {without:?}"),
    }
}

// ---------------------------------------------------------------------------
// create_many: review S3
// ---------------------------------------------------------------------------

/// The up-front reuse check exists for this case: the first call failed to
/// create index 0 but created index 1. A reuse with different records and
/// fewer items must still conflict, through the index-1 row, rather than
/// create the new item under the old key.
#[tokio::test]
async fn create_many_reuse_after_a_partial_failure_conflicts_through_any_created_item() {
    let registry = registry();
    let db = db().await;
    let missing = uuid::Uuid::new_v4().to_string();
    let first = call(
        &registry,
        &db,
        Caller::local(),
        "create_many",
        json!({
            "reason": "Partly fails.", "idempotency_key": "partial-reuse",
            "records": [
                {"type": "Document", "kind": "note", "name": "Fails",
                 "links": [{"target_id": missing, "relationship": "relates_to"}]},
                {"type": "Document", "kind": "note", "name": "Created"},
            ],
        }),
    )
    .await
    .unwrap();
    assert_eq!(first["ok"], json!(false), "{first}");
    assert!(first["ids"][0].is_null() && first["ids"][1].is_string());
    let footprint = write_footprint(&db).await;
    let error = call(
        &registry,
        &db,
        Caller::local(),
        "create_many",
        json!({
            "reason": "Partly fails.", "idempotency_key": "partial-reuse",
            "records": [{"type": "Document", "kind": "note", "name": "Different"}],
        }),
    )
    .await
    .unwrap_err();
    assert!(error.is_idempotency_conflict(), "{error}");
    assert_eq!(write_footprint(&db).await, footprint, "nothing written");
}

/// A retry where an item the first call created now fails authorization,
/// while an item the first call could not create now succeeds: the receipt
/// says so (`ok: false`), refuses the first item exactly as a fresh key
/// would, never discloses its id, and creates the second item once.
#[tokio::test]
async fn create_many_retry_mixes_a_refused_replay_with_a_fresh_creation() {
    let registry = registry();
    let db = db().await;
    hosted_person(&registry, &db, "acct:alice").await;
    let home = call(
        &registry,
        &db,
        Caller::local(),
        "create_record",
        json!({"type": "Collection", "kind": "folder", "name": "shared home"}),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let missing = uuid::Uuid::new_v4().to_string();
    let records = json!([
        {"type": "Document", "kind": "note", "name": "In the home", "home_id": home},
        {"type": "Document", "kind": "note", "name": "Linked later",
         "links": [{"target_id": missing, "relationship": "relates_to"}]},
    ]);
    let args = json!({"reason": "Mixed.", "idempotency_key": "mixed", "records": records});
    let first = call(
        &registry,
        &db,
        hosted("acct:alice"),
        "create_many",
        args.clone(),
    )
    .await
    .unwrap();
    let in_home = first["ids"][0].as_str().unwrap().to_owned();
    assert!(first["ids"][1].is_null(), "{first}");

    call(
        &registry,
        &db,
        Caller::local(),
        "manage_record_policy",
        json!({"action": "set_members_baseline", "record_id": home,
               "reason": "Revoke the members baseline for the replay test."}),
    )
    .await
    .unwrap();
    call(
        &registry,
        &db,
        Caller::local(),
        "create_record",
        json!({"id": missing, "type": "Document", "kind": "note", "name": "Target"}),
    )
    .await
    .unwrap();
    let before = creates(&db).await;
    let retry = call(
        &registry,
        &db,
        hosted("acct:alice"),
        "create_many",
        args.clone(),
    )
    .await
    .unwrap();
    assert_eq!(retry["ok"], json!(false), "{retry}");
    assert!(retry["ids"][0].is_null(), "{retry}");
    assert!(retry["ids"][1].is_string(), "{retry}");
    assert!(!retry.to_string().contains(&in_home), "{retry}");
    assert_eq!(
        creates(&db).await,
        before + 1,
        "only the linked item is created"
    );

    let mut fresh = args;
    fresh["idempotency_key"] = json!("never-used");
    let fresh = call(&registry, &db, hosted("acct:alice"), "create_many", fresh)
        .await
        .unwrap();
    assert_eq!(
        retry["errors"][0], fresh["errors"][0],
        "the fresh-key refusal"
    );
}

/// Caller-supplied item ids: the first call creates them, and a replay
/// returns them without writing; a dependant still binds by ref.
#[tokio::test]
async fn create_many_replays_caller_supplied_ids() {
    let registry = registry();
    let db = db().await;
    let folder = uuid::Uuid::new_v4().to_string();
    let child = uuid::Uuid::new_v4().to_string();
    let case = KeyedCase {
        tool: "create_many",
        args: json!({
            "reason": "Supplied ids.", "idempotency_key": "supplied",
            "records": [
                {"ref": "folder", "id": folder, "type": "Collection", "kind": "folder", "name": "F"},
                {"id": child, "type": "Document", "kind": "note", "name": "C", "parent_ref": "folder"},
            ],
        }),
        conflicting: Value::Null,
    };
    let first = assert_replays_without_writing(&registry, &db, Caller::local(), &case).await;
    assert_eq!(first["ids"], json!([folder, child]), "{first}");
    assert_eq!(
        record_column(&db, &child, "home_id").await.as_deref(),
        Some(folder.as_str())
    );
}
