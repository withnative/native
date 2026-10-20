//! Keyed replays at workspace scale (task 8bef361, slice A2 review S1/S2).
//!
//! A committed keyed write must stay replayable however large the workspace
//! is. The historical rebuild refuses beyond a budget over the whole
//! workspace log, so these tests lower that budget (`AttestedRebuildLimits`)
//! until a few dozen unrelated events exceed it, then retry.

use serde_json::{json, Value};

use native_artifact_runtime::mdx;

use super::artifacts::WaitForMdxCompiler;
use super::lifecycle::AttestedRebuildLimits;
use crate::db::Db;
use crate::mcp::{Caller, ToolRegistry};

const BOARD: &str = include_str!("../../../tests/fixtures/native-board-v1.json");
pub(super) const MODULE: &str = r#"export const nativeModule = {
  schema: "native.mdx.module.v1",
  inputs: {},
  exports: { Hello: { kind: "component", props: { label: { type: "string", required: true } }, uses_inputs: [] } },
  module_inputs: {},
  capability_requests: []
}
export function Hello({ label }, native) { return <Callout tone="info" title={label}>{label}</Callout> }
"#;

pub(super) async fn fixture() -> (Db, ToolRegistry) {
    let db = crate::create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    crate::mcp::register_surface_tools(&mut registry).unwrap();
    (db, registry)
}

pub(super) async fn call(registry: &ToolRegistry, db: &Db, tool: &str, mut args: Value) -> Value {
    if !matches!(tool, "instantiate_artifact" | "manage_mdx_modules")
        && args.get("reason").is_none()
    {
        args["reason"] = json!("keyed replay at scale");
    }
    registry
        .call(db.clone(), Caller::local(), tool, args)
        .await
        .unwrap()
}

pub(super) async fn id_of(registry: &ToolRegistry, db: &Db, args: Value) -> String {
    call(registry, db, "create_record", args).await["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// Unrelated writes that put the workspace log over the lowered budget.
pub(super) async fn pad_workspace(registry: &ToolRegistry, db: &Db) {
    for index in 0..30 {
        call(
            registry,
            db,
            "create_record",
            json!({"type": "Document", "kind": "note", "name": format!("unrelated {index}")}),
        )
        .await;
    }
}

pub(super) async fn footprint(db: &Db) -> (i64, i64) {
    let content = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    let attestations = sqlx::query_scalar("SELECT COUNT(*) FROM provenance_action_attestations")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    (content, attestations)
}

/// A graph of the item shapes the compact fold used to refuse: a
/// Resolution, a Program, a targeted Annotation (which appends
/// `annotation.target.set`) and a Document that depends on the Resolution.
async fn graph(registry: &ToolRegistry, db: &Db, mode: &str) -> Value {
    let source = id_of(
        registry,
        db,
        json!({"type": "Document", "kind": "note", "name": "source", "body": "alpha beta"}),
    )
    .await;
    let bearer = id_of(
        registry,
        db,
        json!({"type": "WorkItem", "kind": "task", "name": "bearer"}),
    )
    .await;
    json!({
        "reason": "Create a mixed graph.",
        "response_mode": mode,
        "idempotency_key": format!("scale-{mode}"),
        "records": [
            {"ref": "decision", "type": "Resolution", "kind": "decision", "name": "Decision"},
            {"type": "Program", "kind": "module", "name": "Module", "body": MODULE,
             "facets": {"runtime": "native.mdx.v2"}},
            {"type": "Annotation", "kind": "citation", "name": "Evidence", "body": "why",
             "links": [{"target_id": bearer, "relationship": "part_of"}],
             "target": {"target_record_id": source, "source_slot": "body",
                        "selectors": [{"type": "text_quote", "exact": "alpha"}]}},
            {"type": "Document", "kind": "note", "name": "Follows", "body": "See [[decision]].",
             "links": [{"target_ref": "decision", "relationship": "relates_to"}]},
        ],
    })
}

/// Keeps a scale test off the process-wide MDX compile slots' worst case.
/// The graph's Program item compiles MDX; tests in this binary that saturate
/// the slots on purpose hold `mdx::test_guard()`, so holding it here keeps
/// them from running meanwhile, and the compiler check waits for a free slot
/// instead of being refused when other tests happen to be compiling. The
/// calls under test are then single, plain calls: nothing here resumes a
/// refused item, so a receipt compared against its replay was made by one
/// call.
pub(super) fn serial_mdx() -> (std::sync::MutexGuard<'static, ()>, WaitForMdxCompiler) {
    (mdx::test_guard(), WaitForMdxCompiler::enable())
}

/// The first keyed call: it must create every item.
async fn create_many_created(registry: &ToolRegistry, db: &Db, args: &Value) -> Value {
    let receipt = call(registry, db, "create_many", args.clone()).await;
    assert_eq!(receipt["ok"], json!(true), "{receipt}");
    receipt
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn create_many_summary_replay_of_every_item_shape_survives_a_large_workspace() {
    let _serial = serial_mdx();
    let (db, registry) = fixture().await;
    let args = graph(&registry, &db, "summary").await;
    let first = create_many_created(&registry, &db, &args).await;
    pad_workspace(&registry, &db).await;
    let before = footprint(&db).await;
    let _limits = AttestedRebuildLimits::lowered(20, 400 * 1024);
    let replay = call(&registry, &db, "create_many", args).await;
    assert_eq!(
        replay.to_string(),
        first.to_string(),
        "summary replay is exact"
    );
    assert_eq!(footprint(&db).await, before, "a replay appends nothing");
}

/// Verbose replays rebuild the full record view through the bounded
/// workspace-prefix rebuild. Where that refuses, the item replays its pinned
/// summary, marked, rather than failing a write that committed.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn create_many_verbose_replay_degrades_to_the_marked_summary_instead_of_failing() {
    let _serial = serial_mdx();
    let (db, registry) = fixture().await;
    let args = graph(&registry, &db, "verbose").await;
    let first = create_many_created(&registry, &db, &args).await;
    pad_workspace(&registry, &db).await;
    let before = footprint(&db).await;
    let _limits = AttestedRebuildLimits::lowered(20, 400 * 1024);
    let replay = call(&registry, &db, "create_many", args).await;
    assert_eq!(replay["ok"], json!(true), "{replay}");
    assert_eq!(replay["ids"], first["ids"]);
    for (index, result) in replay["results"].as_array().unwrap().iter().enumerate() {
        let record = &result["record"];
        let original = &first["results"][index]["record"];
        assert_eq!(record["replay_view"], json!("summary"), "{record}");
        for field in ["id", "type", "kind", "name", "body_digest", "act"] {
            assert_eq!(record[field], original[field], "item {index} {field}");
        }
    }
    assert_eq!(footprint(&db).await, before, "a replay appends nothing");
}

#[tokio::test]
async fn instantiate_artifact_replay_after_the_copy_is_edited_survives_a_large_workspace() {
    let (db, registry) = fixture().await;
    let source = id_of(
        &registry,
        &db,
        json!({"type": "Document", "kind": "artifact", "name": "Board", "body": BOARD,
               "facets": {"runtime": "native.board.v1"}}),
    )
    .await;
    let args = json!({"source_id": source, "idempotency_key": "copy-at-scale"});
    let first = call(&registry, &db, "instantiate_artifact", args.clone()).await;
    call(
        &registry,
        &db,
        "update_record",
        json!({"id": first["id"], "name": "Renamed copy"}),
    )
    .await;
    pad_workspace(&registry, &db).await;
    let before = footprint(&db).await;
    let _limits = AttestedRebuildLimits::lowered(20, 400 * 1024);
    let replay = call(&registry, &db, "instantiate_artifact", args).await;
    assert_eq!(replay["replay_view"], json!("summary"), "{replay}");
    for field in ["id", "type", "kind", "act", "source_id", "previous_seq"] {
        assert_eq!(replay[field], first[field], "{field}");
    }
    assert_eq!(replay["name"], json!("Board"), "pinned at the command");
    assert_eq!(footprint(&db).await, before, "a replay appends nothing");
}

/// Larger than the old limit: the rebuild charges payload at 6x against a
/// 16 MiB budget, and the folds used to charge the body too.
fn large_body() -> String {
    "a body line well past the old replay limit\n".repeat(3 * 1024 * 1024 / 43)
}

/// A keyed create with a body over the old limit, edited after the keyed call:
/// the summary replay is exact, and the verbose replay, whose full rebuild
/// cannot take a body this size, degrades to the marked summary instead of
/// refusing.
#[tokio::test]
async fn create_record_with_a_body_over_the_old_limit_replays_after_an_edit() {
    let (db, registry) = fixture().await;
    let body = large_body();
    let summary_args = json!({"type": "Document", "kind": "note", "name": "Large",
                              "body": body, "idempotency_key": "large-create"});
    let first = call(&registry, &db, "create_record", summary_args.clone()).await;
    call(
        &registry,
        &db,
        "update_record",
        json!({"id": first["id"], "name": "Edited after the keyed create"}),
    )
    .await;
    let before = footprint(&db).await;
    let replay = call(&registry, &db, "create_record", summary_args.clone()).await;
    assert_eq!(
        replay.to_string(),
        first.to_string(),
        "summary replay is exact"
    );

    let mut verbose_args = summary_args;
    verbose_args["response_mode"] = json!("verbose");
    let verbose = call(&registry, &db, "create_record", verbose_args).await;
    assert_eq!(
        verbose["replay_view"],
        json!("summary"),
        "{}",
        &verbose.to_string()[..400.min(verbose.to_string().len())]
    );
    for field in ["id", "name", "body_digest", "act", "source_event_id"] {
        assert_eq!(verbose[field], first[field], "{field}");
    }
    assert!(
        verbose.get("body").is_none(),
        "the fallback carries no body"
    );
    assert_eq!(footprint(&db).await, before, "a replay appends nothing");
}

#[tokio::test]
async fn update_record_with_a_body_over_the_old_limit_replays_after_a_later_write() {
    let (db, registry) = fixture().await;
    let created = call(
        &registry,
        &db,
        "create_record",
        json!({"type": "Document", "kind": "note", "name": "Grows", "body": "start"}),
    )
    .await;
    let id = created["id"].as_str().unwrap().to_owned();
    let args = json!({"id": id, "body_set": large_body(), "if_body_digest": created["body_digest"],
                      "idempotency_key": "large-update"});
    let first = call(&registry, &db, "update_record", args.clone()).await;
    call(
        &registry,
        &db,
        "update_record",
        json!({"id": id, "name": "Written since"}),
    )
    .await;
    let before = footprint(&db).await;
    let replay = call(&registry, &db, "update_record", args.clone()).await;
    assert_eq!(
        replay.to_string(),
        first.to_string(),
        "summary replay is exact"
    );

    let mut verbose_args = args;
    verbose_args["response_mode"] = json!("verbose");
    let verbose = call(&registry, &db, "update_record", verbose_args).await;
    assert_eq!(verbose["replay_view"], json!("summary"));
    for field in [
        "id",
        "name",
        "body_digest",
        "act",
        "previous_seq",
        "body_receipt",
    ] {
        assert_eq!(verbose[field], first[field], "{field}");
    }
    assert_eq!(footprint(&db).await, before, "a replay appends nothing");
}
