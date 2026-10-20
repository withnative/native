//! Keyed replays at their resource bounds (task 8bef361, slice C0).
//!
//! A replay that finds its committed write but cannot rebuild the receipt
//! inside a bound is a retryable, outcome-known failure
//! ([`Error::ReplayBounded`], 503 over HTTP), never a refusal. These tests pin
//! that for the folds, which now run on a read transaction under a deadline,
//! and that every capacity class of the full-view rebuild degrades to the
//! marked summary.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use native_artifact_runtime::mdx;

use super::artifacts::WaitForMdxCompilerOff;
use super::keyed_replay_scale_tests::{
    call, fixture, footprint, id_of, pad_workspace, serial_mdx, MODULE,
};
use super::lifecycle::{
    attested_scratch_opens, AttestedRebuildEnvelope, AttestedRebuildLimits, AttestedReplayPause,
    ReplayFoldGate, ReplayFoldGateGuard, ATTESTED_REPLAY_PAUSE,
};
use crate::db::Db;
use crate::error::{Error, ReplayBound};
use crate::mcp::{Caller, ToolRegistry};

const BOARD: &str = include_str!("../../../tests/fixtures/native-board-v1.json");

/// The scale helper's call, as a `Result`: a keyed call and its retry must go
/// through the same defaults (`reason` is part of the key's digest), so every
/// call in this file does.
async fn try_call(
    registry: &ToolRegistry,
    db: &Db,
    tool: &str,
    mut args: Value,
) -> crate::Result<Value> {
    if !matches!(tool, "instantiate_artifact" | "manage_mdx_modules")
        && args.get("reason").is_none()
    {
        args["reason"] = json!("keyed replay at scale");
    }
    registry.call(db.clone(), Caller::local(), tool, args).await
}

/// A committed keyed call `first` of `tool`, its `args` as the retry sends
/// them. The replay's fold must neither hold the writer nor outlive its
/// deadline, and a retry after a missed deadline must succeed.
async fn assert_replay_fold_is_bounded(
    registry: &ToolRegistry,
    db: &Db,
    tool: &str,
    args: Value,
    first: Value,
    expected_applied: Value,
) {
    // The fold is in flight while an independent writer runs to completion.
    // Were the fold to hold BEGIN IMMEDIATE, the writer would wait on it and
    // the fold on the writer: the 60 s guard turns that deadlock into a failure.
    {
        let gate = ReplayFoldGate::closed();
        let _installed = ReplayFoldGateGuard::install(gate.clone());
        let other = id_of(
            registry,
            db,
            json!({"type": "Document", "kind": "note", "name": "independent writer"}),
        )
        .await;
        let writer = async {
            tokio::time::timeout(Duration::from_secs(20), gate.fold_entered())
                .await
                .expect("the replay never reached its fold");
            let written = call(
                registry,
                db,
                "update_record",
                json!({"id": other, "name": "written during the fold"}),
            )
            .await;
            gate.open();
            written
        };
        let (replay, written) = tokio::time::timeout(Duration::from_secs(60), async {
            tokio::join!(try_call(registry, db, tool, args.clone()), writer)
        })
        .await
        .expect("a replay's fold must not hold the writer");
        assert_eq!(
            replay.unwrap().to_string(),
            first.to_string(),
            "{tool}: the replay"
        );
        assert_eq!(written["name"], json!("written during the fold"));
    }

    // A fold that misses its deadline is the typed, retryable error.
    let before = footprint(db).await;
    {
        let _envelope = AttestedRebuildEnvelope::install(2, Duration::from_millis(150));
        let _installed = ReplayFoldGateGuard::install(ReplayFoldGate::closed());
        let error = try_call(registry, db, tool, args.clone())
            .await
            .expect_err("a stalled fold must hit its deadline");
        assert!(
            matches!(
                error,
                Error::ReplayBounded {
                    bound: ReplayBound::Deadline,
                    ..
                }
            ),
            "{tool}: {error:?}"
        );
        assert!(
            !error.is_idempotency_conflict(),
            "{tool}: a bound is not a conflict"
        );
        let wire = crate::mcp::protocol::call_error_content(&error, Value::Null, None);
        let structured = &wire["structuredContent"];
        assert_eq!(wire["isError"], json!(true));
        assert_eq!(structured["error_code"], json!("REPLAY_BOUND_EXCEEDED"));
        assert_eq!(structured["applied"], expected_applied, "{tool}");
        assert_eq!(structured["retryable"], json!(true));
    }
    assert_eq!(
        footprint(db).await,
        before,
        "{tool}: a bounded replay wrote"
    );

    // The same key, retried without the stall, replays.
    let retry = try_call(registry, db, tool, args)
        .await
        .unwrap_or_else(|error| panic!("{tool}: the retry must replay: {error}"));
    assert_eq!(retry.to_string(), first.to_string(), "{tool}: the retry");
}

#[tokio::test]
async fn update_record_summary_replay_is_bounded_and_off_the_writer() {
    let (db, registry) = fixture().await;
    let id = id_of(
        &registry,
        &db,
        json!({"type": "Document", "kind": "note", "name": "Edited", "body": "start"}),
    )
    .await;
    let args = json!({"id": id, "body_append": " keyed", "idempotency_key": "bound-update"});
    let first = call(&registry, &db, "update_record", args.clone()).await;
    call(
        &registry,
        &db,
        "update_record",
        json!({"id": id, "name": "written since"}),
    )
    .await;
    assert_replay_fold_is_bounded(&registry, &db, "update_record", args, first, json!(true)).await;
}

#[tokio::test]
async fn create_record_summary_replay_is_bounded_and_off_the_writer() {
    let (db, registry) = fixture().await;
    let args = json!({"type": "Document", "kind": "note", "name": "Created", "body": "start",
                      "idempotency_key": "bound-create"});
    let first = call(&registry, &db, "create_record", args.clone()).await;
    call(
        &registry,
        &db,
        "update_record",
        json!({"id": first["id"], "name": "written since"}),
    )
    .await;
    assert_replay_fold_is_bounded(&registry, &db, "create_record", args, first, json!(true)).await;
}

/// A create_many whose item replay hits a bound fails the call with the
/// retryable error. It is not an item-level `create_failed`, which would read
/// as a refusal and mark the items that depend on it `dependency_failed`.
#[tokio::test]
async fn create_many_item_replay_is_bounded_and_off_the_writer() {
    let (db, registry) = fixture().await;
    let args = json!({
        "reason": "Create two notes.",
        "idempotency_key": "bound-many",
        "records": [
            {"type": "Document", "kind": "note", "name": "one", "body": "first"},
            {"type": "Document", "kind": "note", "name": "two", "body": "second"},
        ],
    });
    let first = call(&registry, &db, "create_many", args.clone()).await;
    assert_eq!(first["ok"], json!(true), "{first}");
    assert_replay_fold_is_bounded(&registry, &db, "create_many", args, first, json!("partial"))
        .await;
}

/// R2: an over-cap workspace refuses a full-view rebuild with one bounded
/// COUNT, before a permit, a scratch database or its schema are spent. A
/// verbose create_many replay over N items then costs N counts, not N
/// scratch databases.
#[tokio::test]
async fn an_over_cap_rebuild_refuses_before_opening_a_scratch_database() {
    let (db, registry) = fixture().await;
    // The rebuild replays the log up to the command's own horizon, so the
    // workspace must already be large when the keyed call lands.
    pad_workspace(&registry, &db).await;
    let args = json!({"type": "Document", "kind": "note", "name": "Verbose", "body": "start",
                      "response_mode": "verbose", "idempotency_key": "over-cap"});
    let first = call(&registry, &db, "create_record", args.clone()).await;

    // Control: within the cap, the verbose replay rebuilds, so it opens one.
    let opens = attested_scratch_opens();
    let rebuilt = call(&registry, &db, "create_record", args.clone()).await;
    assert_eq!(attested_scratch_opens(), opens + 1, "the control rebuilds");
    assert!(rebuilt.get("replay_view").is_none(), "{rebuilt}");

    let _limits = AttestedRebuildLimits::lowered(20, 400 * 1024);
    let opens = attested_scratch_opens();
    let degraded = call(&registry, &db, "create_record", args).await;
    assert_eq!(
        attested_scratch_opens(),
        opens,
        "an over-cap workspace must not open a scratch database"
    );
    assert_eq!(degraded["replay_view"], json!("summary"), "{degraded}");
    assert_eq!(degraded["id"], first["id"]);
}

/// The verbose rebuild refuses for three different reasons (its budget, its
/// admission, its deadline). Each is the same typed error, and each degrades
/// to the pinned summary, marked, for every tool that takes the fallback.
#[derive(Clone, Copy, Debug)]
enum Capacity {
    Budget,
    Admission,
    Deadline,
}

/// Run `replay` (a call that takes the rebuild) with `capacity` exhausted.
async fn replay_with<F, Fut>(capacity: Capacity, replay: F) -> Value
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Value>,
{
    match capacity {
        Capacity::Budget => {
            let _limits = AttestedRebuildLimits::lowered(1, 1024 * 1024);
            replay().await
        }
        Capacity::Admission => {
            // No permit is ever free: admission runs out its deadline.
            let _envelope = AttestedRebuildEnvelope::install(0, Duration::from_millis(200));
            replay().await
        }
        Capacity::Deadline => {
            // A permit is free, and the rebuild parks mid-fold until the
            // deadline cancels it.
            let _envelope = AttestedRebuildEnvelope::install(1, Duration::from_millis(200));
            let pause = Arc::new(AttestedReplayPause {
                reached: tokio::sync::Notify::new(),
                release: tokio::sync::Notify::new(),
                scratch: std::sync::Mutex::new(None),
                projected: std::sync::atomic::AtomicUsize::new(0),
            });
            ATTESTED_REPLAY_PAUSE.scope(pause, replay()).await
        }
    }
}

fn assert_marked_summary(replay: &Value, first: &Value, label: &str) {
    assert_eq!(replay["replay_view"], json!("summary"), "{label}: {replay}");
    for field in ["id", "type", "kind", "body_digest", "act"] {
        assert_eq!(replay[field], first[field], "{label}: {field}");
    }
}

#[tokio::test]
async fn every_capacity_class_degrades_every_tool_to_the_marked_summary() {
    for capacity in [Capacity::Budget, Capacity::Admission, Capacity::Deadline] {
        let label = format!("{capacity:?}");

        // create_record, verbose.
        {
            let (db, registry) = fixture().await;
            let args = json!({"type": "Document", "kind": "note", "name": "C", "body": "b",
                              "response_mode": "verbose", "idempotency_key": "cap-create"});
            let first = call(&registry, &db, "create_record", args.clone()).await;
            let before = footprint(&db).await;
            let replay = replay_with(capacity, || {
                call(&registry, &db, "create_record", args.clone())
            })
            .await;
            assert_marked_summary(&replay, &first, &format!("{label} create_record"));
            assert_eq!(footprint(&db).await, before, "{label}: replay wrote");
        }

        // update_record, verbose, after a later write.
        {
            let (db, registry) = fixture().await;
            let id = id_of(
                &registry,
                &db,
                json!({"type": "Document", "kind": "note", "name": "U", "body": "b"}),
            )
            .await;
            let args = json!({"id": id, "body_append": " more", "response_mode": "verbose",
                              "idempotency_key": "cap-update"});
            let first = call(&registry, &db, "update_record", args.clone()).await;
            call(
                &registry,
                &db,
                "update_record",
                json!({"id": id, "name": "since"}),
            )
            .await;
            let replay = replay_with(capacity, || {
                call(&registry, &db, "update_record", args.clone())
            })
            .await;
            assert_eq!(
                replay["replay_view"],
                json!("summary"),
                "{label} update_record: {replay}"
            );
            for field in ["id", "body_digest", "act", "previous_seq"] {
                assert_eq!(replay[field], first[field], "{label} update_record {field}");
            }
        }

        // create_many, verbose: every item degrades.
        {
            let (db, registry) = fixture().await;
            let args = json!({
                "reason": "Two notes.", "response_mode": "verbose", "idempotency_key": "cap-many",
                "records": [
                    {"type": "Document", "kind": "note", "name": "m1", "body": "x"},
                    {"type": "Document", "kind": "note", "name": "m2", "body": "y"},
                ],
            });
            let first = call(&registry, &db, "create_many", args.clone()).await;
            let replay = replay_with(capacity, || {
                call(&registry, &db, "create_many", args.clone())
            })
            .await;
            assert_eq!(replay["ok"], json!(true), "{label} create_many: {replay}");
            assert_eq!(replay["ids"], first["ids"]);
            for (index, result) in replay["results"].as_array().unwrap().iter().enumerate() {
                assert_marked_summary(
                    &result["record"],
                    &first["results"][index]["record"],
                    &format!("{label} create_many item {index}"),
                );
            }
        }

        // instantiate_artifact, whose copy was edited since: its replay has
        // no summary mode, so the marked summary is its only degraded shape.
        {
            let (db, registry) = fixture().await;
            let source = id_of(
                &registry,
                &db,
                json!({"type": "Document", "kind": "artifact", "name": "Board", "body": BOARD,
                       "facets": {"runtime": "native.board.v1"}}),
            )
            .await;
            let args = json!({"source_id": source, "idempotency_key": "cap-copy"});
            let first = call(&registry, &db, "instantiate_artifact", args.clone()).await;
            call(
                &registry,
                &db,
                "update_record",
                json!({"id": first["id"], "name": "Renamed copy"}),
            )
            .await;
            let replay = replay_with(capacity, || {
                call(&registry, &db, "instantiate_artifact", args.clone())
            })
            .await;
            assert_eq!(
                replay["replay_view"],
                json!("summary"),
                "{label} instantiate_artifact: {replay}"
            );
            for field in ["id", "act", "source_id"] {
                assert_eq!(replay[field], first[field], "{label} instantiate {field}");
            }
        }
    }
}

/// A keyed `create_record` Message draft (no origin, so nothing is sent)
/// replays through the same per-record fold as any other create: exactly in
/// summary mode, and as the marked summary where the rebuild refuses.
#[tokio::test]
async fn a_keyed_message_draft_replays_through_the_fold() {
    let (db, registry) = fixture().await;
    let sender = id_of(
        &registry,
        &db,
        json!({"type": "Entity", "kind": "person", "name": "Sender"}),
    )
    .await;
    for (system, identifier) in [
        ("native-principal", "native/draft-sender"),
        ("account", "acct_draft_sender"),
    ] {
        sqlx::query(
            "INSERT INTO bindings(record_id,system,identifier,is_canonical) VALUES (?,?,?,1)",
        )
        .bind(&sender)
        .bind(system)
        .bind(identifier)
        .execute(db.write_pool())
        .await
        .unwrap();
    }
    let args = json!({"type": "Message", "kind": "text", "name": "Draft", "owner_id": sender,
                      "body": "not yet sent", "addressed_to": [],
                      "facets": {"expectation": "none"}, "idempotency_key": "message-draft"});
    let first = call(&registry, &db, "create_record", args.clone()).await;
    pad_workspace(&registry, &db).await;
    let before = footprint(&db).await;
    let replay = call(&registry, &db, "create_record", args.clone()).await;
    assert_eq!(
        replay.to_string(),
        first.to_string(),
        "summary replay is exact"
    );

    let mut verbose = args;
    verbose["response_mode"] = json!("verbose");
    let _limits = AttestedRebuildLimits::lowered(1, 1024 * 1024);
    let degraded = call(&registry, &db, "create_record", verbose).await;
    assert_marked_summary(&degraded, &first, "message draft");
    assert_eq!(footprint(&db).await, before, "a replay appends nothing");
}

/// Every MDX compile slot held, as a saturated process leaves them.
fn saturate_mdx_compiler() -> Vec<tokio::sync::OwnedSemaphorePermit> {
    let mut held = Vec::new();
    while let Ok(permit) = mdx::try_admit() {
        held.push(permit);
    }
    held
}

fn assert_refused_for_compiler_capacity(result: crate::Result<Value>, what: &str) {
    let error = result.expect_err(what).to_string();
    assert!(
        error.contains("mdx_resource_limit_exceeded"),
        "{what}: {error}"
    );
}

/// A replay compiles nothing, so it must not need a compile slot: a retry of
/// a committed MDX create under compiler load replays, where a fresh key is
/// refused by admission.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn a_keyed_mdx_create_replays_without_a_compile_slot() {
    let _serial = serial_mdx();
    let (db, registry) = fixture().await;
    let args = json!({"type": "Program", "kind": "module", "name": "Mod", "body": MODULE,
                      "facets": {"runtime": "native.mdx.v2"}, "idempotency_key": "mdx-create"});
    let first = call(&registry, &db, "create_record", args.clone()).await;
    let before = footprint(&db).await;

    let _held = saturate_mdx_compiler();
    let _no_wait = WaitForMdxCompilerOff::disable();
    let replay = try_call(&registry, &db, "create_record", args.clone())
        .await
        .expect("a replay needs no compile slot");
    assert_eq!(replay.to_string(), first.to_string());
    assert_eq!(footprint(&db).await, before);

    let mut fresh = args;
    fresh["idempotency_key"] = json!("mdx-create-fresh");
    assert_refused_for_compiler_capacity(
        try_call(&registry, &db, "create_record", fresh).await,
        "a fresh create compiles, so it needs a slot",
    );
}

/// The same for `manage_mdx_modules.publish`: its keyed retry claims the
/// compiler slot only after the replay lookup misses.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn a_keyed_mdx_publish_replays_without_a_compile_slot() {
    let (_mdx, _wait) = serial_mdx();
    let (db, registry) = fixture().await;
    let module = id_of(
        &registry,
        &db,
        json!({"type": "Program", "kind": "module", "name": "Publishable", "body": MODULE,
               "facets": {"runtime": "native.mdx.v2"}}),
    )
    .await;
    let source_event: String = sqlx::query_scalar(
        "SELECT id FROM content_events WHERE record_id=? AND json_type(payload,'$.body') IS NOT NULL
          ORDER BY seq DESC LIMIT 1",
    )
    .bind(&module)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let args = json!({"action": "publish", "module_id": module,
                      "expected_source_event_id": source_event,
                      "expected_source_sha256": mdx::sha256_hex(MODULE.as_bytes()),
                      "idempotency_key": "mdx-publish"});
    let first = call(&registry, &db, "manage_mdx_modules", args.clone()).await;
    assert_eq!(first["status"], json!("published"), "{first}");
    let before = footprint(&db).await;

    let _held = saturate_mdx_compiler();
    let _no_wait = WaitForMdxCompilerOff::disable();
    let replay = try_call(&registry, &db, "manage_mdx_modules", args.clone())
        .await
        .expect("a replay needs no compile slot");
    assert_eq!(replay.to_string(), first.to_string());
    assert_eq!(footprint(&db).await, before);

    let mut fresh = args.clone();
    fresh["idempotency_key"] = json!("mdx-publish-fresh");
    assert_refused_for_compiler_capacity(
        try_call(&registry, &db, "manage_mdx_modules", fresh).await,
        "a fresh publish compiles, so it needs a slot",
    );
    let mut unkeyed = args;
    unkeyed.as_object_mut().unwrap().remove("idempotency_key");
    assert_refused_for_compiler_capacity(
        try_call(&registry, &db, "manage_mdx_modules", unkeyed).await,
        "an unkeyed publish still claims its slot first",
    );
}

/// `create_many` makes several writes, so a bound hit partway cannot claim the
/// whole call applied: that would tell a host not to retry, and strand the
/// items after the one that hit it. The error says `applied: "partial"` with
/// the counts, stays retryable, and a retry with the same key resumes, creating
/// each remaining item exactly once.
#[tokio::test]
async fn create_many_bound_midway_is_partial_and_a_retry_completes_the_rest_exactly_once() {
    let (db, registry) = fixture().await;
    // Item 2 links to a record that does not exist yet, so the first call
    // creates items 0 and 1 and refuses item 2 without leaving a row for it.
    let target = uuid::Uuid::new_v4().to_string();
    let args = json!({
        "reason": "Three notes.", "idempotency_key": "partial-many",
        "records": [
            {"type": "Document", "kind": "note", "name": "p0", "body": "zero"},
            {"type": "Document", "kind": "note", "name": "p1", "body": "one"},
            {"type": "Document", "kind": "note", "name": "p2", "body": "two",
             "links": [{"target_id": target, "relationship": "relates_to"}]},
        ],
    });
    let first = call(&registry, &db, "create_many", args.clone()).await;
    assert_eq!(first["ok"], json!(false), "{first}");
    let named = |name: &'static str| {
        let db = db.clone();
        async move {
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM records WHERE name = ?")
                .bind(name)
                .fetch_one(db.write_pool())
                .await
                .unwrap()
        }
    };
    assert_eq!(
        (named("p0").await, named("p1").await, named("p2").await),
        (1, 1, 0)
    );
    id_of(
        &registry,
        &db,
        json!({"id": target, "type": "Document", "kind": "note", "name": "target"}),
    )
    .await;

    // The retry replays item 0, and item 1's replay hits its bound: items 0 and
    // 1 are confirmed committed (item 1 only missed its receipt), item 2 is not.
    let before = footprint(&db).await;
    let error = {
        let _envelope = AttestedRebuildEnvelope::install(2, Duration::from_millis(150));
        let _gate = ReplayFoldGateGuard::install(ReplayFoldGate::closed_after(1));
        try_call(&registry, &db, "create_many", args.clone())
            .await
            .expect_err("item 1's replay must hit its bound")
    };
    assert!(
        matches!(
            error,
            Error::ReplayBounded {
                bound: ReplayBound::Deadline,
                applied: crate::error::ReplayApplied::Partial {
                    completed: 2,
                    total: 3
                },
                ..
            }
        ),
        "{error:?}"
    );
    let wire = crate::mcp::protocol::call_error_content(&error, Value::Null, None);
    let structured = &wire["structuredContent"];
    assert_eq!(structured["applied"], json!("partial"));
    assert_eq!(structured["completed_items"], json!(2));
    assert_eq!(structured["total_items"], json!(3));
    assert_eq!(structured["retryable"], json!(true));
    assert_eq!(structured["error_code"], json!("REPLAY_BOUND_EXCEEDED"));
    assert_eq!(footprint(&db).await, before, "the bounded call wrote");
    assert_eq!(named("p2").await, 0, "item 2 was never reached");

    // The same key and arguments resume: items 0 and 1 replay, item 2 is
    // created once, and a further retry is a pure replay.
    let resumed = call(&registry, &db, "create_many", args.clone()).await;
    assert_eq!(resumed["ok"], json!(true), "{resumed}");
    assert_eq!(resumed["ids"][0], first["ids"][0]);
    assert_eq!(resumed["ids"][1], first["ids"][1]);
    assert_eq!(
        (named("p0").await, named("p1").await, named("p2").await),
        (1, 1, 1)
    );
    let settled = footprint(&db).await;
    let again = call(&registry, &db, "create_many", args).await;
    assert_eq!(again.to_string(), resumed.to_string());
    assert_eq!(footprint(&db).await, settled, "a further retry wrote");
}

/// The property the hosted verbose-replay integration test used to bound by
/// wall clock, asserted without one. The rebuild is parked after its first
/// folded event, holding its permit and scratch database: an independent
/// writer must run to completion meanwhile. Then the rebuild is released and
/// must finish the live enrichment, contribution and filter reads that follow
/// (which run under a live snapshot of the writer) without self-locking, as
/// the full view and not the capacity fallback. It runs on a private permit
/// pool and a deadline far beyond any test's, so neither sibling tests nor
/// host load decide the outcome; a self-lock fails as a hang or as the
/// degraded summary.
#[tokio::test]
async fn a_writer_runs_while_a_hosted_verbose_rebuild_is_parked_and_the_rebuild_then_completes() {
    let (db, registry) = fixture().await;
    let person = id_of(
        &registry,
        &db,
        json!({"type": "Entity", "kind": "person", "name": "Alice"}),
    )
    .await;
    sqlx::query(
        "INSERT INTO bindings (record_id, system, identifier, is_canonical)
         VALUES (?, 'account', 'acct:verbose-alice', 1)",
    )
    .bind(&person)
    .execute(db.write_pool())
    .await
    .unwrap();
    let alice = Caller::authenticated("acct:verbose-alice")
        .with_hosting_context("host:acct:verbose-alice", "db:test");
    let args = json!({"type": "Document", "kind": "note", "name": "hosted verbose",
                      "body": "start", "reason": "hosted verbose", "response_mode": "verbose",
                      "idempotency_key": "hosted-verbose"});
    let first = registry
        .call(db.clone(), alice.clone(), "create_record", args.clone())
        .await
        .unwrap();
    id_of(
        &registry,
        &db,
        json!({"type": "Document", "kind": "note", "name": "unrelated"}),
    )
    .await;

    let _envelope = AttestedRebuildEnvelope::install(1, Duration::from_secs(120));
    let pause = Arc::new(AttestedReplayPause {
        reached: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
        scratch: std::sync::Mutex::new(None),
        projected: std::sync::atomic::AtomicUsize::new(0),
    });
    let opens = attested_scratch_opens();
    let replay = ATTESTED_REPLAY_PAUSE.scope(
        pause.clone(),
        registry.call(db.clone(), alice, "create_record", args),
    );
    let driver = async {
        tokio::time::timeout(Duration::from_secs(60), pause.reached.notified())
            .await
            .expect("the rebuild never reached its parked fold");
        let written = call(
            &registry,
            &db,
            "create_record",
            json!({"type": "Document", "kind": "note", "name": "parallel writer"}),
        )
        .await;
        pause.release.notify_one();
        written
    };
    let (replay, written) = tokio::time::timeout(Duration::from_secs(180), async {
        tokio::join!(replay, driver)
    })
    .await
    .expect("a parked rebuild must not hold the writer");
    assert_eq!(written["name"], json!("parallel writer"));
    assert_eq!(attested_scratch_opens(), opens + 1, "the rebuild ran");
    let replay = replay.unwrap();
    assert!(
        replay.get("replay_view").is_none(),
        "the full view must be rebuilt, not the capacity fallback: {replay}"
    );
    assert_eq!(replay, first);
}
