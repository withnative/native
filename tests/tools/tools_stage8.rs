//! Stage 8's legacy catalogue tool 31, `start_work`, remains immediately before
//! the suggestion resolver; the suggestion-review App launcher follows both.

use std::sync::Arc;

use native_ce::conformance::rebuild_and_diff;
use native_ce::events::{FacetSetPayload, EVENT_TYPES};
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::schema::FROZEN_DDL_SHA256;
use native_ce::{create_database, Db};
use serde_json::{json, Value};

use crate::common::count;

async fn db() -> Db {
    create_database(":memory:").await.unwrap()
}

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

async fn call(registry: &ToolRegistry, db: &Db, tool: &str, args: Value) -> Value {
    let caller = if matches!(tool, "archive_record" | "delete_record") {
        Caller::local()
    } else {
        Caller::authenticated(
            args.get("agent_id")
                .and_then(Value::as_str)
                .unwrap_or("test:local"),
        )
    };
    let result = registry
        .call(
            db.clone(),
            caller,
            tool,
            crate::common::with_test_reason(tool, args),
        )
        .await
        .unwrap();
    db.drain_captures_for_tests().await;
    result
}

async fn call_err(registry: &ToolRegistry, db: &Db, tool: &str, args: Value) -> String {
    let caller = Caller::authenticated(
        args.get("agent_id")
            .and_then(Value::as_str)
            .unwrap_or("test:local"),
    );
    let error = registry
        .call(
            db.clone(),
            caller,
            tool,
            crate::common::with_test_reason(tool, args),
        )
        .await
        .unwrap_err()
        .to_string();
    db.drain_captures_for_tests().await;
    error
}

async fn create(registry: &ToolRegistry, db: &Db, args: Value) -> String {
    registry
        .call(
            db.clone(),
            Caller::local(),
            "create_record",
            crate::common::with_test_reason("create_record", args),
        )
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string()
}

/// A WorkItem with a lifecycle, the ordinary subject of a claim.
async fn task(registry: &ToolRegistry, db: &Db, name: &str, lifecycle: &str) -> String {
    create(
        registry,
        db,
        json!({ "type": "WorkItem", "kind": "task", "name": name, "lifecycle": lifecycle }),
    )
    .await
}

async fn link(registry: &ToolRegistry, db: &Db, source: &str, rel: &str, target: &str) {
    call(
        registry,
        db,
        "manage_links",
        json!({ "action": "add", "source_id": source, "target_id": target, "relationship": rel }),
    )
    .await;
}

/// Minting as an authenticated (non-local) caller requires the caller's own
/// portable account binding; the intent suite keeps the same fixture for its
/// account. Without this, `create_record` refuses with "caller has no
/// portable account binding".
async fn ensure_account_binding(db: &Db, account: &str, person_id: &str) {
    let pool = crate::common::fixture_write_pool(db).await;
    sqlx::query(
        "INSERT OR IGNORE INTO records
            (id, type, kind, name, home_id, policy_anchor_id, persistence)
         VALUES (?, 'Entity', 'person', 'Test account', ?, ?, 'enduring')",
    )
    .bind(person_id)
    .bind(native_ce::schema::UNFILED_RECORD_ID)
    .bind(native_ce::schema::ROOT_RECORD_ID)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT OR IGNORE INTO bindings
            (record_id, system, identifier, is_canonical)
         VALUES (?, 'account', ?, 1)",
    )
    .bind(person_id)
    .bind(account)
    .execute(&pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn caller_supplied_agent_id_cannot_forge_the_claim_holder() {
    let db = db().await;
    let registry = registry();
    let id = task(&registry, &db, "Unforgeable", "in_progress").await;

    let out = registry
        .call(
            db.clone(),
            Caller::authenticated("authenticated:owner"),
            "start_work",
            json!({ "record_id": id, "agent_id": "forged:holder" }),
        )
        .await
        .unwrap();
    assert_eq!(out["held_by"], "authenticated:owner");
    assert_eq!(out["held_by_account"], "authenticated:owner");
    assert_eq!(out["held_by_run_key"], Value::Null);

    // Guessing the compatibility argument cannot turn a different
    // authenticated caller into an idempotent re-claim by the real holder.
    let err = registry
        .call(
            db.clone(),
            Caller::authenticated("authenticated:attacker"),
            "start_work",
            json!({ "record_id": id, "agent_id": "authenticated:owner" }),
        )
        .await
        .unwrap_err();
    let message = err.to_string();
    assert!(message.contains("is already claimed — release it first"));
    assert!(!message.contains("authenticated:owner"));

    let actor: Option<String> = sqlx::query_scalar(
        "SELECT actor FROM content_events WHERE record_id = ? ORDER BY seq DESC LIMIT 1",
    )
    .bind(&id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(actor.as_deref(), Some("authenticated:owner"));
}

#[tokio::test]
async fn claim_ownership_requires_the_exact_account_and_full_run_pair() {
    let db = db().await;
    let registry = registry();
    let id = task(&registry, &db, "Structured owner", "in_progress").await;
    let first_run = "scout-chair-a748b2";
    let second_run = "scout-chair-f748b2";

    let first = registry
        .call(
            db.clone(),
            Caller::authenticated("account:a"),
            "start_work",
            json!({ "record_id": id, "run_key": first_run }),
        )
        .await
        .unwrap();
    assert_eq!(first["held_by"], "scout", "compatibility display label");
    assert_eq!(first["held_by_account"], "account:a");
    assert_eq!(first["held_by_run_key"], first_run);

    let resumed = registry
        .call(
            db.clone(),
            Caller::authenticated("account:a"),
            "start_work",
            json!({ "record_id": id, "run_key": first_run }),
        )
        .await
        .unwrap();
    assert_eq!(resumed["changed"], false, "the exact pair is idempotent");

    let same_account_other_run = registry
        .call(
            db.clone(),
            Caller::authenticated("account:a"),
            "start_work",
            json!({ "record_id": id, "run_key": second_run }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(same_account_other_run.contains("is already claimed by run"));
    assert!(same_account_other_run.contains(first_run));
    assert!(same_account_other_run.contains("holder_tier="));
    assert!(same_account_other_run.contains("expected_holder_run_key"));

    let same_run_other_account = registry
        .call(
            db.clone(),
            Caller::authenticated("account:b"),
            "start_work",
            json!({ "record_id": id, "run_key": first_run }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(same_run_other_account.contains("is already claimed — release it first"));
    assert!(!same_run_other_account.contains("scout"));

    let claim_event = sqlx::query_as::<_, (String, Option<String>)>(
        "SELECT actor, run_key FROM content_events
         WHERE record_id = ? AND json_extract(payload, '$.claimed_by_account') = 'account:a'",
    )
    .bind(&id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(claim_event, ("account:a".into(), Some(first_run.into())));

    registry
        .call(
            db.clone(),
            Caller::authenticated("account:a"),
            "start_work",
            json!({ "record_id": id, "action": "release", "run_key": first_run }),
        )
        .await
        .unwrap();
    registry
        .call(
            db.clone(),
            Caller::authenticated("account:a"),
            "start_work",
            json!({ "record_id": id, "run_key": second_run }),
        )
        .await
        .unwrap();
    let stale_release = registry
        .call(
            db.clone(),
            Caller::authenticated("account:a"),
            "start_work",
            json!({ "record_id": id, "action": "release", "run_key": first_run }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(stale_release.contains("expected_holder_run_key"));
    assert!(stale_release.contains(second_run));
    let current: Option<String> = sqlx::query_scalar(
        "SELECT claimed_run_key FROM records WHERE id = ? AND claimed_by_account = 'account:a'",
    )
    .bind(&id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(current.as_deref(), Some(second_run));

    // Same-principal compare-and-release: the stale run takes the claim back
    // by naming the current holder.
    let recovered = registry
        .call(
            db.clone(),
            Caller::authenticated("account:a"),
            "start_work",
            json!({
                "record_id": id,
                "action": "release",
                "run_key": first_run,
                "expected_holder_run_key": second_run,
            }),
        )
        .await
        .unwrap();
    assert_eq!(recovered["claimed"], false);
    let payload: Value = sqlx::query_scalar(
        "SELECT payload FROM content_events WHERE record_id = ? AND type = 'record.updated' \
         ORDER BY seq DESC LIMIT 1",
    )
    .bind(&id)
    .fetch_one(db.pool())
    .await
    .map(|raw: String| serde_json::from_str(&raw).unwrap())
    .unwrap();
    assert_eq!(payload["claimed_by_account"], Value::Null);
    assert_eq!(payload["claimed_run_key"], Value::Null);
    assert_eq!(payload["released_from_run_key"], second_run);
    db.close().await;
}

#[tokio::test]
async fn ordinary_reads_and_query_sql_do_not_expose_claim_credentials() {
    let db = db().await;
    let registry = registry();
    let id = task(&registry, &db, "Private claim", "in_progress").await;
    let run_key = "scout-chair-a748b2";
    registry
        .call(
            db.clone(),
            Caller::authenticated("account:private"),
            "start_work",
            json!({ "record_id": id, "run_key": run_key }),
        )
        .await
        .unwrap();

    let record = registry
        .call(
            db.clone(),
            Caller::authenticated("account:private"),
            "get_record",
            json!({ "ids": [id.clone()], "run_key": run_key }),
        )
        .await
        .unwrap();
    let rendered = serde_json::to_string(&record["records"]).unwrap();
    assert!(!rendered.contains("account:private"));
    assert!(!rendered.contains(run_key));
    assert!(!rendered.contains("claimed_by_account"));
    assert!(!rendered.contains("claimed_run_key"));
    assert!(!rendered.contains("claimed_at"));

    let non_holder_record = registry
        .call(
            db.clone(),
            Caller::authenticated("account:viewer"),
            "get_record",
            json!({ "ids": [id.clone()] }),
        )
        .await
        .unwrap();
    let rendered = serde_json::to_string(&non_holder_record["records"]).unwrap();
    assert!(!rendered.contains("account:private"));
    assert!(!rendered.contains(run_key));
    assert!(!rendered.contains("claimed_by_account"));
    assert!(!rendered.contains("claimed_run_key"));
    assert!(!rendered.contains("claimed_at"));

    let history = registry
        .call(
            db.clone(),
            Caller::authenticated("account:viewer"),
            "get_history",
            json!({ "record_id": id.clone(), "detail": "full" }),
        )
        .await
        .unwrap();
    let rendered = serde_json::to_string(&history).unwrap();
    assert!(!rendered.contains("account:private"));
    assert!(!rendered.contains(run_key));

    // A same-account compare-and-release from a second run must not leak
    // either run key to another principal through history surfaces.
    let second_run = "scout-chair-b748b2";
    registry
        .call(
            db.clone(),
            Caller::authenticated("account:private"),
            "start_work",
            json!({
                "record_id": id,
                "action": "release",
                "run_key": second_run,
                "expected_holder_run_key": run_key,
            }),
        )
        .await
        .unwrap();
    let release_event_id: String = sqlx::query_scalar(
        "SELECT id FROM content_events WHERE record_id = ? AND type = 'record.updated' \
         ORDER BY seq DESC LIMIT 1",
    )
    .bind(&id)
    .fetch_one(db.pool())
    .await
    .unwrap();

    let released_history = registry
        .call(
            db.clone(),
            Caller::authenticated("account:viewer"),
            "get_history",
            json!({ "record_id": id.clone(), "detail": "full" }),
        )
        .await
        .unwrap();
    let rendered = serde_json::to_string(&released_history).unwrap();
    assert!(!rendered.contains("account:private"));
    assert!(!rendered.contains(run_key));
    assert!(!rendered.contains(second_run));

    let event_context = registry
        .call(
            db.clone(),
            Caller::authenticated("account:viewer"),
            "get_event_context",
            json!({ "event_id": release_event_id }),
        )
        .await
        .unwrap();
    let rendered = serde_json::to_string(&event_context).unwrap();
    assert!(!rendered.contains("account:private"));
    assert!(!rendered.contains(run_key));
    assert!(!rendered.contains(second_run));

    let changes = registry
        .call(
            db.clone(),
            Caller::authenticated("account:viewer"),
            "whats_changed",
            json!({}),
        )
        .await
        .unwrap();
    let rendered = serde_json::to_string(&changes).unwrap();
    assert!(!rendered.contains("account:private"));
    assert!(!rendered.contains(run_key));
    assert!(!rendered.contains(second_run));

    let query = registry
        .call(
            db.clone(),
            Caller::authenticated("account:private"),
            "query_sql",
            json!({ "sql": "SELECT * FROM records WHERE id = ?1", "parameters": [{"type":"text", "value":id}], "run_key":run_key }),
        )
        .await
        .unwrap();
    let columns = query["columns"].as_array().unwrap();
    assert!(!columns.iter().any(|column| {
        matches!(
            column.as_str(),
            Some("claimed_by_account" | "claimed_run_key" | "claimed_at")
        )
    }));
    let rendered = serde_json::to_string(&query["rows"]).unwrap();
    assert!(!rendered.contains("account:private"));
    assert!(!rendered.contains(run_key));
}

#[tokio::test]
async fn public_record_update_cannot_author_claim_projection() {
    let db = db().await;
    let registry = registry();
    let id = task(&registry, &db, "Owned seam", "open").await;
    let error = native_ce::store::update_record(
        &db,
        &id,
        json!({ "claimed_by_account": "account:forged", "claimed_run_key": null }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("start_work-owned"), "{error}");
}

#[tokio::test]
async fn trusted_local_release_recovers_a_stuck_current_claim() {
    let db = db().await;
    let registry = registry();
    let id = task(&registry, &db, "Stuck", "blocked").await;
    registry
        .call(
            db.clone(),
            Caller::authenticated("account:gone"),
            "start_work",
            json!({ "record_id": id }),
        )
        .await
        .unwrap();
    let released = registry
        .call(
            db.clone(),
            Caller::local(),
            "start_work",
            json!({ "record_id": id, "action": "release" }),
        )
        .await
        .unwrap();
    assert_eq!(released["claimed"], false);
    assert_eq!(released["lifecycle"], "blocked");
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

#[tokio::test]
async fn start_work_and_suggestion_tools_keep_their_relative_order() {
    let registry = registry();
    let names: Vec<&str> = registry.specs().map(|t| t.name.as_str()).collect();
    assert_eq!(
        names
            .iter()
            .position(|name| *name == "start_work")
            .and_then(|index| names.get(index)),
        Some(&"start_work"),
        "start_work is shipping ordinal 26"
    );
    let start = names.iter().position(|name| *name == "start_work").unwrap();
    let resolve = names
        .iter()
        .position(|name| *name == "resolve_suggestions")
        .unwrap();
    assert_eq!(resolve, start + 1);
    assert_eq!(names.get(resolve + 1), Some(&"render_suggestion_review"));
    assert_eq!(
        names.iter().filter(|n| **n == "start_work").count(),
        1,
        "registered exactly once"
    );
}

// ---------------------------------------------------------------------------
// The claim is one record.updated projected into engine-owned columns
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_claim_is_one_record_updated_and_leaves_lifecycle_unchanged() {
    let db = db().await;
    let registry = registry();
    let id = create(
        &registry,
        &db,
        json!({
            "type": "WorkItem",
            "kind": "task",
            "name": "Ship it",
            "lifecycle": "in_progress"
        }),
    )
    .await;
    let before = count(&db, "SELECT COUNT(*) AS n FROM content_events").await;

    let out = call(
        &registry,
        &db,
        "start_work",
        json!({ "record_id": id, "agent_id": "agent:impl" }),
    )
    .await;
    assert_eq!(out["changed"], true);
    assert_eq!(out["claimed"], true);
    assert_eq!(out["lifecycle"], "in_progress");
    assert!(out.get("previous_lifecycle").is_none());
    assert_eq!(out["held_by"], "agent:impl");
    assert_eq!(
        out["context"]["record"]["lifecycle_interpretation"]["value"]["raw"],
        "in_progress"
    );

    // Exactly ONE event, of an existing type, carrying the actor.
    assert_eq!(
        count(&db, "SELECT COUNT(*) AS n FROM content_events").await,
        before + 1
    );
    let history = registry
        .call(
            db.clone(),
            Caller::authenticated("agent:impl"),
            "get_history",
            json!({ "record_id": id.clone(), "detail": "full" }),
        )
        .await
        .unwrap();
    let events = history["events"].as_array().unwrap();
    let claim = events.last().unwrap();
    assert_eq!(claim["type"], "record.updated");
    assert_eq!(claim["actor"], "agent:impl");
    assert_eq!(
        claim["payload"],
        json!({ "claimed_by_account": "agent:impl", "claimed_run_key": null })
    );
}

#[tokio::test]
async fn claiming_adds_no_event_type_or_claims_table() {
    let db = db().await;
    let registry = registry();
    let id = task(&registry, &db, "Ship it", "in_progress").await;
    call(&registry, &db, "start_work", json!({ "record_id": id })).await;

    assert_eq!(
        EVENT_TYPES,
        [
            "record.created",
            "record.updated",
            "record.type_corrected.v1",
            "record.deleted",
            "facet.set",
            "facet.unset",
            "link.added",
            "link.removed",
            "annotation.target.set",
            "annotation.target.removed",
            "attribution.target.bound.v1",
            "attribution.asserted.v1",
            "attribution.evidence.added.v1",
            "attribution.retracted.v1",
            "message.audience.declared",
            "message.audience.legacy_unknown",
            "message.origin.declared.v1",
            "message.shared",
            "message.send_evaluated.v1",
            "message.delivery.authorized.v1",
            "message.reaction.added.v1",
            "message.reaction.removed.v1",
            "intervention.raised.v1",
            "intervention.cancelled.v1",
            "intervention.execution_resumed.v1",
            "module.release_published",
            "module.release_deprecated",
            "module.release_withdrawn",
            "recipe.release_published",
            "recipe.release_deprecated",
            "recipe.release_withdrawn",
            "artifact.source_attested",
            "artifact.input_bound",
            "artifact.input_carried",
            "artifact.input_unbound",
            "artifact.module_grant_set",
            "artifact.module_grant_carried",
            "artifact.module_grant_unset",
            "unit.created.v1",
            "unit.revision.recorded.v1",
            "occurrence.bound.v1",
            "receipt.committed.v1",
            "reconciliation.recorded.v1",
            "unit.superseded.v1",
            "receipt.dependency_audited.v1",
            "canvas.batch.committed.v1",
        ],
        "claiming must leave the current event vocabulary unchanged"
    );
    assert!(!EVENT_TYPES.contains(&"record.claimed"));
    let claim_event_type: String = sqlx::query_scalar(
        "SELECT type FROM content_events WHERE record_id=? ORDER BY seq DESC LIMIT 1",
    )
    .bind(&id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(claim_event_type, "record.updated");
    let schema = call(&registry, &db, "describe_schema", json!({})).await;
    assert_eq!(schema["engine"]["ddl_fingerprint"], FROZEN_DDL_SHA256);
    // No claims table appeared under the tool.
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) AS n FROM sqlite_master WHERE type = 'table' AND name LIKE '%claim%'"
        )
        .await,
        0
    );
}

// ---------------------------------------------------------------------------
// Exclusivity — the acceptance case
// ---------------------------------------------------------------------------

/// Eight claimants, started together against one record, on a real
/// multi-threaded runtime: the exclusivity property is that exactly ONE commits
/// a claim. A sequential simulation would not exercise the compare-and-set at
/// all — `BEGIN IMMEDIATE` serializes the writers, and it is the in-transaction
/// check, not the serialization, that refuses the losers.
///
/// The barrier is what makes that real rather than hoped for: instrumented, it
/// puts all contenders against the in-transaction occupancy predicate rather
/// than relying on a lucky sequential ordering. Eight
/// claimants rather than two, because two can serialize cleanly and leave the
/// conditional untested.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_claimants_leave_exactly_one_winner_and_no_lost_update() {
    const CLAIMANTS: usize = 8;
    let db = db().await;
    let registry = Arc::new(registry());
    let id = task(&registry, &db, "Contended", "in_progress").await;
    let before = count(&db, "SELECT COUNT(*) AS n FROM content_events").await;

    let barrier = Arc::new(tokio::sync::Barrier::new(CLAIMANTS));
    let mut handles = Vec::new();
    for n in 0..CLAIMANTS {
        let (registry, db, id, barrier) = (
            Arc::clone(&registry),
            db.clone(),
            id.clone(),
            Arc::clone(&barrier),
        );
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            registry
                .call(
                    db,
                    Caller::authenticated(format!("agent:{n}")),
                    "start_work",
                    json!({ "record_id": id, "agent_id": format!("agent:{n}") }),
                )
                .await
        }));
    }

    let mut winners = Vec::new();
    let mut losers = Vec::new();
    for handle in handles {
        match handle.await.unwrap() {
            Ok(out) => winners.push(out),
            Err(err) => losers.push(err.to_string()),
        }
    }
    assert_eq!(winners.len(), 1, "exactly one claimant wins: {losers:?}");
    assert_eq!(losers.len(), CLAIMANTS - 1);

    for message in &losers {
        assert!(
            message.contains("is already claimed"),
            "a losing claimant is told plainly why: {message}"
        );
        assert!(
            !message.contains("agent:"),
            "holder remains private: {message}"
        );
    }

    // No lost update: one claim, one event, and the record holds the winner's.
    assert_eq!(
        count(&db, "SELECT COUNT(*) AS n FROM content_events").await,
        before + 1,
        "the losers wrote nothing at all"
    );
    let preview = call(
        &registry,
        &db,
        "start_work",
        json!({ "record_id": id, "action": "preview" }),
    )
    .await;
    assert_eq!(preview["claimed"], true);
    assert_eq!(preview["lifecycle"], "in_progress");
    assert_eq!(preview["held_by"], Value::Null);
}

#[tokio::test]
async fn a_second_claimant_is_refused_without_disclosing_who_holds_it() {
    let db = db().await;
    let registry = registry();
    let id = task(&registry, &db, "Held", "in_progress").await;
    call(
        &registry,
        &db,
        "start_work",
        json!({ "record_id": id, "agent_id": "agent:a" }),
    )
    .await;

    let err = call_err(
        &registry,
        &db,
        "start_work",
        json!({ "record_id": id, "agent_id": "agent:b" }),
    )
    .await;
    assert!(err.contains("is already claimed"), "unexpected: {err}");
    assert!(!err.contains("agent:a"), "unexpected: {err}");
    assert!(err.contains("release it first"), "unexpected: {err}");
}

#[tokio::test]
async fn re_claiming_as_the_same_agent_returns_the_context_unchanged() {
    let db = db().await;
    let registry = registry();
    let id = task(&registry, &db, "Resumed", "in_progress").await;
    call(
        &registry,
        &db,
        "start_work",
        json!({ "record_id": id, "agent_id": "agent:a" }),
    )
    .await;
    let events = count(&db, "SELECT COUNT(*) AS n FROM content_events").await;

    let out = call(
        &registry,
        &db,
        "start_work",
        json!({ "record_id": id, "agent_id": "agent:a" }),
    )
    .await;
    assert_eq!(out["changed"], false, "a resuming agent writes nothing");
    assert_eq!(out["held_by"], "agent:a");
    assert_eq!(
        count(&db, "SELECT COUNT(*) AS n FROM content_events").await,
        events,
        "no second claim event"
    );
}

#[tokio::test]
async fn the_trusted_local_caller_can_resume_its_claim() {
    let db = db().await;
    let registry = registry();
    let id = task(&registry, &db, "Anonymous", "in_progress").await;
    call(&registry, &db, "start_work", json!({ "record_id": id })).await;

    let out = call(&registry, &db, "start_work", json!({ "record_id": id })).await;
    assert_eq!(out["changed"], false);
    assert_eq!(out["held_by"], "test:local");
}

// ---------------------------------------------------------------------------
// preview
// ---------------------------------------------------------------------------

#[tokio::test]
async fn preview_inspects_without_claiming() {
    let db = db().await;
    let registry = registry();
    let id = task(&registry, &db, "Untouched", "in_progress").await;
    let before = count(&db, "SELECT COUNT(*) AS n FROM content_events").await;

    let out = call(
        &registry,
        &db,
        "start_work",
        json!({ "record_id": id, "action": "preview", "agent_id": "agent:a" }),
    )
    .await;
    assert_eq!(out["changed"], false);
    assert_eq!(out["lifecycle"], "in_progress");
    assert_eq!(out["held_by"], Value::Null);
    assert_eq!(out["work_state"], json!({ "state": "unclaimed" }));
    assert!(out["context"]["record"].is_object());
    assert_eq!(
        count(&db, "SELECT COUNT(*) AS n FROM content_events").await,
        before,
        "preview writes nothing"
    );

    // And it does not refuse a record someone else holds — inspection is not a
    // claim.
    call(
        &registry,
        &db,
        "start_work",
        json!({ "record_id": id, "agent_id": "agent:a" }),
    )
    .await;
    let out = call(
        &registry,
        &db,
        "start_work",
        json!({ "record_id": id, "action": "preview", "agent_id": "agent:b" }),
    )
    .await;
    assert_eq!(out["held_by"], Value::Null);
    assert_eq!(out["work_state"]["state"], "claimed");
    assert!(out["work_state"].get("claim_status").is_none());
    assert_eq!(out["work_state"]["details"]["visibility"], "withheld");
    assert_eq!(out["work_state"]["target"]["visibility"], "withheld");
}

#[tokio::test]
async fn same_account_preview_sees_holder_run_state_tier_and_top_level_fields() {
    let db = db().await;
    let registry = registry();
    let id = task(&registry, &db, "Same account visibility", "in_progress").await;
    let holder_run = "scout-chair-a748b2";
    let other_run = "scout-chair-b748b2";
    registry
        .call(
            db.clone(),
            Caller::authenticated("account:holder"),
            "set_intent",
            json!({ "intent": "Hold the claim.", "run_key": holder_run }),
        )
        .await
        .unwrap();
    registry
        .call(
            db.clone(),
            Caller::authenticated("account:holder"),
            "start_work",
            json!({ "record_id": id, "run_key": holder_run }),
        )
        .await
        .unwrap();
    let preview = registry
        .call(
            db.clone(),
            Caller::authenticated("account:holder"),
            "start_work",
            json!({ "record_id": id, "action": "preview", "run_key": other_run }),
        )
        .await
        .unwrap();
    assert_eq!(preview["claimed"], true);
    assert_eq!(preview["held_by_account"], "account:holder");
    assert_eq!(preview["held_by_run_key"], holder_run);
    assert!(preview["held_by"].is_string());
    assert!(preview["claimed_at"].is_string());
    assert_eq!(preview["work_state"]["claim_status"], "current");
    assert_eq!(preview["work_state"]["details"]["visibility"], "visible");
    assert_eq!(preview["work_state"]["target"]["visibility"], "visible");
    assert_eq!(preview["work_state"]["target"]["account"], "account:holder");
    assert_eq!(preview["work_state"]["target"]["run_key"], holder_run);
    assert_eq!(
        preview["work_state"]["target"]["holder_tier"],
        "another_run_of_this_agent"
    );
    assert!(preview["work_state"]["target"]["run_state"].is_string());
    db.close().await;
}

#[tokio::test]
async fn work_state_discloses_claim_and_run_targets_only_to_the_exact_holder() {
    let db = db().await;
    let registry = registry();
    let id = task(&registry, &db, "Visible coordination", "in_progress").await;
    let run_key = "scout-chair-a748b2";
    let holder = Caller::authenticated("account:holder");

    registry
        .call(
            db.clone(),
            holder.clone(),
            "set_intent",
            json!({ "intent": "Coordinate the visible claim.", "run_key": run_key }),
        )
        .await
        .unwrap();

    let claimed = registry
        .call(
            db.clone(),
            holder.clone(),
            "start_work",
            json!({ "record_id": id, "run_key": run_key }),
        )
        .await
        .unwrap();
    assert_eq!(claimed["work_state"]["state"], "claimed");
    assert_eq!(claimed["work_state"]["claim_status"], "current");
    assert_eq!(claimed["work_state"]["details"]["visibility"], "visible");
    assert!(claimed["work_state"]["details"]["claim_id"]
        .as_str()
        .is_some_and(|id| !id.is_empty()));
    assert_eq!(
        claimed["work_state"]["details"]["claimed_at"],
        claimed["claimed_at"]
    );
    assert_eq!(claimed["work_state"]["target"]["visibility"], "visible");
    assert_eq!(claimed["work_state"]["target"]["account"], "account:holder");
    assert_eq!(claimed["work_state"]["target"]["run_key"], run_key);
    assert_eq!(claimed["work_state"]["target"]["run_state"], "open");
    assert!(claimed["work_state"]["target"]["activity_id"]
        .as_str()
        .is_some_and(|id| !id.is_empty()));

    let claim_id = claimed["work_state"]["details"]["claim_id"]
        .as_str()
        .unwrap()
        .to_string();
    let activity_id = claimed["work_state"]["target"]["activity_id"]
        .as_str()
        .unwrap()
        .to_string();
    let withheld = registry
        .call(
            db.clone(),
            Caller::authenticated("account:viewer"),
            "start_work",
            json!({ "record_id": id, "action": "preview" }),
        )
        .await
        .unwrap();
    assert_eq!(withheld["claimed"], true);
    assert!(withheld["held_by"].is_null());
    assert!(withheld["claimed_at"].is_null());
    assert!(withheld["work_state"].get("claim_status").is_none());
    assert!(withheld["work_state"].get("stale_reason").is_none());
    assert_eq!(
        withheld["work_state"]["details"],
        json!({ "visibility": "withheld" })
    );
    assert_eq!(
        withheld["work_state"]["target"],
        json!({ "visibility": "withheld" })
    );
    let rendered = serde_json::to_string(&withheld["work_state"]).unwrap();
    for secret in ["account:holder", run_key, &claim_id, &activity_id] {
        assert!(!rendered.contains(secret), "withheld state leaked {secret}");
    }
}

#[tokio::test]
async fn withheld_work_state_does_not_disclose_run_lifecycle() {
    let db = db().await;
    let registry = registry();
    let closed_id = task(&registry, &db, "Closed claim", "in_progress").await;
    let missing_id = task(&registry, &db, "Missing claim", "in_progress").await;
    let open_id = task(&registry, &db, "Open idle claim", "in_progress").await;
    let closed_run = "scout-chair-a748b2";
    let missing_run = "pilot-river-b748b2";
    let open_run = "heron-river-c748b2";

    for (run_key, intent) in [
        (closed_run, "Close this coordination target."),
        (open_run, "Leave this coordination target open."),
    ] {
        registry
            .call(
                db.clone(),
                Caller::authenticated("account:holder"),
                "set_intent",
                json!({ "intent": intent, "run_key": run_key }),
            )
            .await
            .unwrap();
    }

    for (id, run_key) in [
        (&closed_id, closed_run),
        (&missing_id, missing_run),
        (&open_id, open_run),
    ] {
        registry
            .call(
                db.clone(),
                Caller::authenticated("account:holder"),
                "start_work",
                json!({ "record_id": id, "run_key": run_key }),
            )
            .await
            .unwrap();
    }
    registry
        .call(
            db.clone(),
            Caller::authenticated("account:holder"),
            "close_run",
            json!({ "run_key": closed_run }),
        )
        .await
        .unwrap();
    let fixture_pool = crate::common::fixture_write_pool(&db).await;
    sqlx::query("DELETE FROM agent_runs WHERE run_key=?")
        .bind(missing_run)
        .execute(&fixture_pool)
        .await
        .unwrap();
    sqlx::query("UPDATE agent_runs SET started_at='2020-01-01T00:00:00.000Z' WHERE run_key=?")
        .bind(open_run)
        .execute(&fixture_pool)
        .await
        .unwrap();

    let viewer = Caller::authenticated("account:viewer");
    let closed = registry
        .call(
            db.clone(),
            viewer.clone(),
            "start_work",
            json!({ "record_id": closed_id, "action": "preview" }),
        )
        .await
        .unwrap();
    assert!(closed["work_state"].get("claim_status").is_none());
    assert!(closed["work_state"].get("stale_reason").is_none());
    assert_eq!(closed["work_state"]["target"]["visibility"], "withheld");

    let missing = registry
        .call(
            db.clone(),
            viewer.clone(),
            "start_work",
            json!({ "record_id": missing_id, "action": "preview" }),
        )
        .await
        .unwrap();
    assert!(missing["work_state"].get("claim_status").is_none());
    assert!(missing["work_state"].get("stale_reason").is_none());
    assert_eq!(missing["work_state"]["target"]["visibility"], "withheld");

    let open = registry
        .call(
            db.clone(),
            viewer,
            "start_work",
            json!({ "record_id": open_id, "action": "preview" }),
        )
        .await
        .unwrap();
    assert!(open["work_state"].get("claim_status").is_none());
    assert!(open["work_state"].get("stale_reason").is_none());
}

// ---------------------------------------------------------------------------
// work_overlap
// ---------------------------------------------------------------------------

#[tokio::test]
async fn work_overlap_discloses_full_detail_for_the_same_accounts_other_run_on_parent_and_sibling()
{
    let db = db().await;
    let registry = registry();

    let parent = task(&registry, &db, "Parent container", "in_progress").await;
    let target = task(&registry, &db, "Target", "in_progress").await;
    link(&registry, &db, &target, "part_of", &parent).await;
    let sibling = task(&registry, &db, "Sibling", "in_progress").await;
    link(&registry, &db, &sibling, "part_of", &parent).await;

    let holder_run = "scout-chair-a748b2";
    let holder = Caller::authenticated("account:a");
    registry
        .call(
            db.clone(),
            holder.clone(),
            "set_intent",
            json!({ "intent": "Coordinate the parent rollout.", "run_key": holder_run }),
        )
        .await
        .unwrap();
    registry
        .call(
            db.clone(),
            holder.clone(),
            "start_work",
            json!({ "record_id": parent, "run_key": holder_run }),
        )
        .await
        .unwrap();
    registry
        .call(
            db.clone(),
            holder.clone(),
            "start_work",
            json!({ "record_id": sibling, "run_key": holder_run }),
        )
        .await
        .unwrap();

    // A different run of the SAME agent key ("scout-chair"), same account.
    let caller_run = "scout-chair-z748b2";
    let out = registry
        .call(
            db.clone(),
            Caller::authenticated("account:a"),
            "start_work",
            json!({ "record_id": target, "run_key": caller_run }),
        )
        .await
        .unwrap();

    let items = out["work_overlap"]["items"].as_array().unwrap();
    assert_eq!(out["work_overlap"]["total_count"], items.len());
    assert_eq!(out["work_overlap"]["truncated"], false);
    assert_eq!(items.len(), 2, "{items:#?}");
    assert!(
        items.iter().all(|item| item["record_id"] != target),
        "the caller's own fresh claim must never appear as an overlap: {items:#?}"
    );

    let by_id = |id: &str| {
        items
            .iter()
            .find(|item| item["record_id"] == id)
            .unwrap_or_else(|| panic!("{id} missing from {items:#?}"))
    };
    let parent_item = by_id(&parent);
    assert_eq!(parent_item["relation"], "parent");
    assert_eq!(parent_item["holder_tier"], "another_run_of_this_agent");
    assert_eq!(parent_item["run_state"], "open");
    assert_eq!(parent_item["run_key"], holder_run);
    assert_eq!(parent_item["intent"], "Coordinate the parent rollout.");
    assert!(parent_item["claimed_at"]
        .as_str()
        .is_some_and(|at| !at.is_empty()));

    let sibling_item = by_id(&sibling);
    assert_eq!(sibling_item["relation"], "sibling");
    assert_eq!(sibling_item["holder_tier"], "another_run_of_this_agent");
    assert_eq!(sibling_item["run_state"], "open");
    assert_eq!(sibling_item["run_key"], holder_run);
    assert_eq!(sibling_item["intent"], "Coordinate the parent rollout.");

    let rendered = native_ce::mcp::render::render("start_work", &out).unwrap();
    assert!(rendered.contains("Work overlap (2)"), "{rendered}");
    assert!(rendered.contains(&parent), "{rendered}");
    assert!(rendered.contains(&sibling), "{rendered}");
    assert!(
        rendered.contains("Coordinate the parent rollout."),
        "{rendered}"
    );

    // The notice is claim-only: a preview of the same target never carries it.
    let preview = registry
        .call(
            db.clone(),
            Caller::authenticated("account:a"),
            "start_work",
            json!({ "record_id": target, "action": "preview", "run_key": caller_run }),
        )
        .await
        .unwrap();
    assert!(preview.get("work_overlap").is_none());
}

#[tokio::test]
async fn work_overlap_limits_another_principal_to_existence_and_relation() {
    let db = db().await;
    let registry = registry();

    let target = task(&registry, &db, "Target", "in_progress").await;
    let child = task(&registry, &db, "Child", "in_progress").await;
    link(&registry, &db, &child, "part_of", &target).await;

    registry
        .call(
            db.clone(),
            Caller::authenticated("account:other"),
            "start_work",
            json!({ "record_id": child, "run_key": "pilot-river-b748b2" }),
        )
        .await
        .unwrap();

    let out = registry
        .call(
            db.clone(),
            Caller::authenticated("account:a"),
            "start_work",
            json!({ "record_id": target, "run_key": "scout-chair-a748b2" }),
        )
        .await
        .unwrap();

    let items = out["work_overlap"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    let item = &items[0];
    assert_eq!(item["record_id"], child);
    assert_eq!(item["relation"], "child");
    assert_eq!(item["holder_tier"], "another_principal");
    let mut keys: Vec<&str> = item
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort();
    assert_eq!(
        keys,
        vec!["holder_tier", "record_id", "relation"],
        "another_principal must leak nothing beyond existence and relation: {item:#?}"
    );

    let rendered = native_ce::mcp::render::render("start_work", &out).unwrap();
    assert!(!rendered.contains("account:other"), "{rendered}");
    assert!(!rendered.contains("pilot-river-b748b2"), "{rendered}");
}

#[tokio::test]
async fn work_overlap_reports_closed_run_state_for_a_stale_same_account_holder() {
    let db = db().await;
    let registry = registry();

    let target = task(&registry, &db, "Target", "in_progress").await;
    let child = task(&registry, &db, "Child", "in_progress").await;
    link(&registry, &db, &child, "part_of", &target).await;

    let stale_run = "scout-chair-a748b2";
    registry
        .call(
            db.clone(),
            Caller::authenticated("account:a"),
            "set_intent",
            json!({ "intent": "Finish this before it goes stale.", "run_key": stale_run }),
        )
        .await
        .unwrap();
    registry
        .call(
            db.clone(),
            Caller::authenticated("account:a"),
            "start_work",
            json!({ "record_id": child, "run_key": stale_run }),
        )
        .await
        .unwrap();
    registry
        .call(
            db.clone(),
            Caller::authenticated("account:a"),
            "close_run",
            json!({ "run_key": stale_run }),
        )
        .await
        .unwrap();

    let out = registry
        .call(
            db.clone(),
            Caller::authenticated("account:a"),
            "start_work",
            json!({ "record_id": target, "run_key": "scout-chair-z748b2" }),
        )
        .await
        .unwrap();

    let items = out["work_overlap"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{items:#?}");
    assert_eq!(items[0]["record_id"], child);
    assert_eq!(items[0]["relation"], "child");
    assert_eq!(items[0]["holder_tier"], "another_run_of_this_agent");
    assert_eq!(items[0]["run_state"], "closed");
    assert_eq!(items[0]["run_key"], stale_run);
}

#[tokio::test]
async fn work_overlap_caps_sibling_candidates_at_fifty_and_flags_truncation() {
    let db = db().await;
    let registry = registry();

    let parent = task(&registry, &db, "Big parent", "in_progress").await;
    let target = task(&registry, &db, "Target", "in_progress").await;
    link(&registry, &db, &target, "part_of", &parent).await;

    let holder_run = "scout-chair-a748b2";
    for n in 0..51 {
        let sibling = task(&registry, &db, &format!("Sibling {n}"), "in_progress").await;
        link(&registry, &db, &sibling, "part_of", &parent).await;
        registry
            .call(
                db.clone(),
                Caller::authenticated("account:a"),
                "start_work",
                json!({ "record_id": sibling, "run_key": holder_run }),
            )
            .await
            .unwrap();
    }

    let out = registry
        .call(
            db.clone(),
            Caller::authenticated("account:a"),
            "start_work",
            json!({ "record_id": target, "run_key": "scout-chair-z748b2" }),
        )
        .await
        .unwrap();

    assert_eq!(out["work_overlap"]["total_count"], 51);
    assert_eq!(out["work_overlap"]["truncated"], true);
    let items = out["work_overlap"]["items"].as_array().unwrap();
    assert_eq!(
        items.len(),
        50,
        "the cap bounds the DISPLAYED items, not the visible claimed count"
    );
    assert!(items
        .iter()
        .all(|item| item["relation"] == "sibling"
            && item["holder_tier"] == "another_run_of_this_agent"));
}

#[tokio::test]
async fn work_overlap_ignores_unclaimed_siblings_entirely() {
    let db = db().await;
    let registry = registry();

    let parent = task(&registry, &db, "Big parent", "in_progress").await;
    let target = task(&registry, &db, "Target", "in_progress").await;
    link(&registry, &db, &target, "part_of", &parent).await;

    // 50 siblings that are never claimed — they must never become candidates
    // at all, since the neighbourhood SQL itself is restricted to claimed
    // records from the start.
    for n in 0..50 {
        let sibling = task(&registry, &db, &format!("Idle sibling {n}"), "in_progress").await;
        link(&registry, &db, &sibling, "part_of", &parent).await;
    }
    // A 51st sibling that IS claimed and visible.
    let claimed_sibling = task(&registry, &db, "Claimed sibling", "in_progress").await;
    link(&registry, &db, &claimed_sibling, "part_of", &parent).await;
    registry
        .call(
            db.clone(),
            Caller::authenticated("account:a"),
            "start_work",
            json!({ "record_id": claimed_sibling, "run_key": "scout-chair-a748b2" }),
        )
        .await
        .unwrap();

    let out = registry
        .call(
            db.clone(),
            Caller::authenticated("account:a"),
            "start_work",
            json!({ "record_id": target, "run_key": "scout-chair-z748b2" }),
        )
        .await
        .unwrap();

    assert_eq!(out["work_overlap"]["total_count"], 1);
    assert_eq!(out["work_overlap"]["truncated"], false);
    let items = out["work_overlap"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{items:#?}");
    assert_eq!(items[0]["record_id"], claimed_sibling);
}

#[tokio::test]
async fn work_overlap_never_lets_an_invisible_sibling_move_truncated_or_total_count() {
    let db = db().await;
    let registry = registry();

    let parent = task(&registry, &db, "Parent", "in_progress").await;
    let target = task(&registry, &db, "Target", "in_progress").await;
    link(&registry, &db, &target, "part_of", &parent).await;

    let visible_sibling = task(&registry, &db, "Visible sibling", "in_progress").await;
    link(&registry, &db, &visible_sibling, "part_of", &parent).await;
    registry
        .call(
            db.clone(),
            Caller::authenticated("account:a"),
            "start_work",
            json!({ "record_id": visible_sibling, "run_key": "scout-chair-a748b2" }),
        )
        .await
        .unwrap();

    // A second sibling, claimed by a different account, whose explicit
    // policy admits only its own claimant — never account:a.
    let hidden_sibling = task(&registry, &db, "Hidden sibling", "in_progress").await;
    link(&registry, &db, &hidden_sibling, "part_of", &parent).await;
    native_ce::authorization::replace_explicit_policy(
        &db,
        "test:policy",
        &hidden_sibling,
        vec![native_ce::authorization::AllowEntry::account(
            "account:other",
            native_ce::authorization::Capability::Edit,
        )],
    )
    .await
    .unwrap();
    registry
        .call(
            db.clone(),
            Caller::authenticated("account:other"),
            "start_work",
            json!({ "record_id": hidden_sibling, "run_key": "pilot-river-b748b2" }),
        )
        .await
        .unwrap();

    let out = registry
        .call(
            db.clone(),
            Caller::authenticated("account:a"),
            "start_work",
            json!({ "record_id": target, "run_key": "scout-chair-z748b2" }),
        )
        .await
        .unwrap();

    assert_eq!(
        out["work_overlap"]["total_count"], 1,
        "the admission-hidden sibling must not be counted at all"
    );
    assert_eq!(out["work_overlap"]["truncated"], false);
    let items = out["work_overlap"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{items:#?}");
    assert_eq!(items[0]["record_id"], visible_sibling);
}

#[tokio::test]
async fn work_overlap_prefers_sibling_over_child_in_a_diamond() {
    let db = db().await;
    let registry = registry();

    // T part_of P; C part_of T AND C part_of P — a diamond where C is both a
    // Sibling of T (via P) and a Child of T (directly). Sibling must win.
    let parent = task(&registry, &db, "Diamond parent", "in_progress").await;
    let target = task(&registry, &db, "Diamond target", "in_progress").await;
    link(&registry, &db, &target, "part_of", &parent).await;
    let corner = task(&registry, &db, "Diamond corner", "in_progress").await;
    link(&registry, &db, &corner, "part_of", &target).await;
    link(&registry, &db, &corner, "part_of", &parent).await;

    registry
        .call(
            db.clone(),
            Caller::authenticated("account:a"),
            "start_work",
            json!({ "record_id": corner, "run_key": "scout-chair-a748b2" }),
        )
        .await
        .unwrap();

    let out = registry
        .call(
            db.clone(),
            Caller::authenticated("account:a"),
            "start_work",
            json!({ "record_id": target, "run_key": "scout-chair-z748b2" }),
        )
        .await
        .unwrap();

    let items = out["work_overlap"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{items:#?}");
    assert_eq!(items[0]["record_id"], corner);
    assert_eq!(items[0]["relation"], "sibling", "{items:#?}");
}

#[tokio::test]
async fn work_overlap_intent_is_scoped_to_the_holders_own_account() {
    let db = db().await;
    let registry = registry();

    let target = task(&registry, &db, "Target", "in_progress").await;
    let sibling = task(&registry, &db, "Sibling", "in_progress").await;
    let parent = task(&registry, &db, "Parent", "in_progress").await;
    link(&registry, &db, &target, "part_of", &parent).await;
    link(&registry, &db, &sibling, "part_of", &parent).await;

    // The run key is a hashtag: a different account can call set_intent under
    // the exact same key string the real holder claims with. account:a
    // claims FIRST, under a key with no agent_runs row yet (claim() only
    // reads that table, it never creates a row) — so nothing here blocks
    // account:b's later set_intent call under the identical key string from
    // succeeding too, exactly the collision finding #5 describes.
    let collided_run = "scout-chair-a748b2";
    registry
        .call(
            db.clone(),
            Caller::authenticated("account:a"),
            "start_work",
            json!({ "record_id": sibling, "run_key": collided_run }),
        )
        .await
        .unwrap();
    registry
        .call(
            db.clone(),
            Caller::authenticated("account:b"),
            "set_intent",
            json!({ "intent": "B's rogue sentence.", "run_key": collided_run }),
        )
        .await
        .unwrap();

    let out = registry
        .call(
            db.clone(),
            Caller::authenticated("account:a"),
            "start_work",
            json!({ "record_id": target, "run_key": "scout-chair-z748b2" }),
        )
        .await
        .unwrap();

    let items = out["work_overlap"]["items"].as_array().unwrap();
    let item = items
        .iter()
        .find(|item| item["record_id"] == sibling)
        .unwrap_or_else(|| panic!("sibling missing from {items:#?}"));
    assert_ne!(
        item.get("intent"),
        Some(&Value::String("B's rogue sentence.".into())),
        "account:b's declaration must never surface under account:a's holder tuple: {item:#?}"
    );
    assert!(item.get("intent").is_none(), "{item:#?}");

    let rendered = native_ce::mcp::render::render("start_work", &out).unwrap();
    assert!(!rendered.contains("B's rogue sentence."), "{rendered}");
}

#[tokio::test]
async fn work_overlap_never_labels_a_keyless_neighbour_this_run() {
    let db = db().await;
    let registry = registry();

    let target = task(&registry, &db, "Target", "in_progress").await;
    let sibling = task(&registry, &db, "Sibling", "in_progress").await;
    let parent = task(&registry, &db, "Parent", "in_progress").await;
    link(&registry, &db, &target, "part_of", &parent).await;
    link(&registry, &db, &sibling, "part_of", &parent).await;

    // Same account, no run key on either side — the engine cannot tell two
    // keyless sessions apart, so this must never read as this_run.
    registry
        .call(
            db.clone(),
            Caller::authenticated("account:a"),
            "start_work",
            json!({ "record_id": sibling }),
        )
        .await
        .unwrap();

    let out = registry
        .call(
            db.clone(),
            Caller::authenticated("account:a"),
            "start_work",
            json!({ "record_id": target }),
        )
        .await
        .unwrap();

    let items = out["work_overlap"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{items:#?}");
    assert_eq!(items[0]["record_id"], sibling);
    assert_eq!(items[0]["holder_tier"], "another_agent_of_yours");
    assert_eq!(items[0]["run_state"], "not_applicable");
    assert!(items[0].get("run_key").is_none());
    assert!(items[0]["claimed_at"]
        .as_str()
        .is_some_and(|at| !at.is_empty()));
}

#[tokio::test]
async fn claim_with_no_neighbours_carries_no_work_overlap_key() {
    let db = db().await;
    let registry = registry();
    let id = task(&registry, &db, "Solo", "in_progress").await;

    let out = call(
        &registry,
        &db,
        "start_work",
        json!({ "record_id": id, "agent_id": "agent:solo" }),
    )
    .await;
    assert!(
        out.as_object().unwrap().get("work_overlap").is_none(),
        "{out:#?}"
    );

    let rendered = native_ce::mcp::render::render("start_work", &out).unwrap();
    assert!(!rendered.contains("Work overlap"), "{rendered}");
}

// ---------------------------------------------------------------------------
// create_record work_overlap
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_record_overlap_names_a_claimed_sibling_at_create_time() {
    let db = db().await;
    let registry = registry();
    ensure_account_binding(&db, "account:a", "test:account-a-person").await;

    let parent = task(&registry, &db, "Parent container", "in_progress").await;
    let sibling = task(&registry, &db, "Sibling", "in_progress").await;
    link(&registry, &db, &sibling, "part_of", &parent).await;

    let holder_run = "scout-chair-a748b2";
    let holder = Caller::authenticated("account:a");
    registry
        .call(
            db.clone(),
            holder.clone(),
            "set_intent",
            json!({ "intent": "Coordinate the parent rollout.", "run_key": holder_run }),
        )
        .await
        .unwrap();
    registry
        .call(
            db.clone(),
            holder,
            "start_work",
            json!({ "record_id": sibling, "run_key": holder_run }),
        )
        .await
        .unwrap();

    // A different run of the SAME agent key ("scout-chair"), same account,
    // creates the new child with its part_of link inline.
    let caller_run = "scout-chair-z748b2";
    let fresh = json!({
        "type": "WorkItem",
        "kind": "task",
        "name": "Fresh child",
        "lifecycle": "in_progress",
        "links": [{ "target_id": parent, "relationship": "part_of" }],
        "run_key": caller_run,
    });
    let out = registry
        .call(
            db.clone(),
            Caller::authenticated("account:a"),
            "create_record",
            crate::common::with_test_reason("create_record", fresh),
        )
        .await
        .unwrap();

    let new_id = out["id"].as_str().unwrap().to_string();
    let items = out["work_overlap"]["items"].as_array().unwrap();
    assert_eq!(out["work_overlap"]["total_count"], items.len());
    assert_eq!(out["work_overlap"]["truncated"], false);
    assert_eq!(items.len(), 1, "{items:#?}");
    assert_eq!(items[0]["record_id"], sibling);
    assert_eq!(items[0]["relation"], "sibling");
    assert_eq!(items[0]["holder_tier"], "another_run_of_this_agent");
    assert_eq!(items[0]["run_state"], "open");
    assert_eq!(items[0]["run_key"], holder_run);
    assert_eq!(items[0]["intent"], "Coordinate the parent rollout.");
    assert!(
        items[0]["claimed_at"]
            .as_str()
            .is_some_and(|at| !at.is_empty()),
        "{items:#?}"
    );
    assert!(
        items.iter().all(|item| item["record_id"] != new_id),
        "the unclaimed new record must never appear as its own overlap: {items:#?}"
    );

    let rendered = native_ce::mcp::render::render("create_record", &out).unwrap();
    assert!(rendered.contains("Work overlap (1)"), "{rendered}");
    assert!(rendered.contains(&sibling), "{rendered}");
    assert!(
        rendered.contains("Coordinate the parent rollout."),
        "{rendered}"
    );
}

#[tokio::test]
async fn create_record_overlap_replay_carries_no_key_and_keeps_the_receipt() {
    let db = db().await;
    let registry = registry();
    ensure_account_binding(&db, "account:a", "test:account-a-person").await;

    let parent = task(&registry, &db, "Parent container", "in_progress").await;
    let sibling = task(&registry, &db, "Sibling", "in_progress").await;
    link(&registry, &db, &sibling, "part_of", &parent).await;

    let holder_run = "scout-chair-a748b2";
    registry
        .call(
            db.clone(),
            Caller::authenticated("account:a"),
            "start_work",
            json!({ "record_id": sibling, "run_key": holder_run }),
        )
        .await
        .unwrap();

    let keyed = || {
        crate::common::with_test_reason(
            "create_record",
            json!({
                "type": "WorkItem",
                "kind": "task",
                "name": "Keyed child",
                "lifecycle": "in_progress",
                "links": [{ "target_id": parent, "relationship": "part_of" }],
                "idempotency_key": "create-overlap-key-1",
                "run_key": "scout-chair-z748b2",
            }),
        )
    };
    let first = registry
        .call(
            db.clone(),
            Caller::authenticated("account:a"),
            "create_record",
            keyed(),
        )
        .await
        .unwrap();
    assert!(
        first.get("work_overlap").is_some(),
        "the fresh create names the claimed sibling: {first:#?}"
    );

    let retry = registry
        .call(
            db.clone(),
            Caller::authenticated("account:a"),
            "create_record",
            keyed(),
        )
        .await
        .unwrap();
    assert!(
        retry.as_object().unwrap().get("work_overlap").is_none(),
        "an idempotent replay must not carry the advisory: {retry:#?}"
    );
    let mut expected = first.clone();
    expected.as_object_mut().unwrap().remove("work_overlap");
    // `run_context` is live per-call wrapper echo, not part of the pinned
    // receipt: the replay may carry a fresh run-key displacement note.
    expected.as_object_mut().unwrap().remove("run_context");
    let mut replay_body = retry.clone();
    replay_body.as_object_mut().unwrap().remove("run_context");
    assert_eq!(
        replay_body, expected,
        "the replayed receipt is otherwise identical to the fresh one"
    );
    assert_eq!(retry["id"], first["id"]);
    assert_eq!(retry["body_digest"], first["body_digest"]);
    assert_eq!(
        retry["action_attestation_ids"],
        first["action_attestation_ids"]
    );
}

#[tokio::test]
async fn create_record_without_overlap_keeps_every_other_create_byte_identical() {
    let db = db().await;
    let registry = registry();
    ensure_account_binding(&db, "account:a", "test:account-a-person").await;

    let document = registry
        .call(
            db.clone(),
            Caller::authenticated("account:a"),
            "create_record",
            crate::common::with_test_reason(
                "create_record",
                json!({
                    "type": "Document",
                    "kind": "note",
                    "name": "Plain document",
                    "run_key": "scout-chair-a748b2",
                }),
            ),
        )
        .await
        .unwrap();
    assert!(
        document.as_object().unwrap().get("work_overlap").is_none(),
        "{document:#?}"
    );

    let lone_task = registry
        .call(
            db.clone(),
            Caller::authenticated("account:a"),
            "create_record",
            crate::common::with_test_reason(
                "create_record",
                json!({
                    "type": "WorkItem",
                    "kind": "task",
                    "name": "Linkless task",
                    "lifecycle": "in_progress",
                    "run_key": "scout-chair-a748b2",
                }),
            ),
        )
        .await
        .unwrap();
    assert!(
        lone_task.as_object().unwrap().get("work_overlap").is_none(),
        "{lone_task:#?}"
    );

    for out in [&document, &lone_task] {
        let rendered = native_ce::mcp::render::render("create_record", out).unwrap();
        assert!(!rendered.contains("Work overlap"), "{rendered}");
        assert!(
            !rendered.contains("work_overlap"),
            "the advisory must never leak as a raw receipt key: {rendered}"
        );
    }
}

#[tokio::test]
async fn overlap_notices_persist_only_their_safe_emission_annotations() {
    let db = db().await;
    let registry = registry();
    ensure_account_binding(&db, "account:a", "test:account-a-emission-person").await;

    let parent = task(&registry, &db, "Emission parent", "in_progress").await;
    let sibling = task(&registry, &db, "Emission sibling", "in_progress").await;
    let target = task(&registry, &db, "Emission target", "in_progress").await;
    link(&registry, &db, &sibling, "part_of", &parent).await;
    link(&registry, &db, &target, "part_of", &parent).await;

    let holder = Caller::authenticated("account:a");
    registry
        .call(
            db.clone(),
            holder,
            "start_work",
            json!({ "record_id": sibling, "run_key": "scout-chair-a748b2" }),
        )
        .await
        .unwrap();

    let caller = Caller::authenticated("account:a");
    // Establish the caller's run before it claims work. The initial briefing
    // is intentionally overlap-free; the later declaration is the surface
    // that must emit an evidence annotation after the claim exists.
    let initial_intent = registry
        .call(
            db.clone(),
            caller.clone(),
            "set_intent",
            json!({ "intent": "prepare an overlap measurement", "run_key": "pilot-river-b748b2" }),
        )
        .await
        .unwrap();
    assert!(initial_intent["briefing"]["overlapping_claims"]["items"]
        .as_array()
        .is_some_and(Vec::is_empty));
    let claim = registry
        .call(
            db.clone(),
            caller.clone(),
            "start_work",
            json!({ "record_id": target, "action": "claim", "run_key": "pilot-river-b748b2" }),
        )
        .await
        .unwrap();
    assert!(claim.get("work_overlap").is_some());

    let fresh_create = registry
        .call(
            db.clone(),
            caller.clone(),
            "create_record",
            crate::common::with_test_reason(
                "create_record",
                json!({
                    "type": "WorkItem",
                    "kind": "task",
                    "name": "Emission fresh create",
                    "lifecycle": "in_progress",
                    "links": [{ "target_id": parent, "relationship": "part_of" }],
                    "run_key": "pilot-river-b748b2",
                }),
            ),
        )
        .await
        .unwrap();
    assert!(fresh_create.get("work_overlap").is_some());

    // `set_intent` notices are based on its bounded briefing anchors. Touch a
    // record that its existing response is authorized to disclose as claimed,
    // then declare again to exercise this independent notice surface.
    registry
        .call(
            db.clone(),
            caller.clone(),
            "get_record",
            json!({ "ids": [sibling], "run_key": "pilot-river-b748b2" }),
        )
        .await
        .unwrap();

    let intent = registry
        .call(
            db.clone(),
            caller.clone(),
            "set_intent",
            json!({ "intent": "measure a real disclosed overlap", "run_key": "pilot-river-b748b2" }),
        )
        .await
        .unwrap();
    assert!(intent["briefing"]["overlapping_claims"]["items"]
        .as_array()
        .is_some_and(|items| !items.is_empty()));

    let replay_arguments = || {
        crate::common::with_test_reason(
            "create_record",
            json!({
                "type": "WorkItem",
                "kind": "task",
                "name": "Emission replay",
                "lifecycle": "in_progress",
                "links": [{ "target_id": parent, "relationship": "part_of" }],
                "idempotency_key": "emission-overlap-replay",
                "run_key": "pilot-river-b748b2",
            }),
        )
    };
    let first = registry
        .call(
            db.clone(),
            caller.clone(),
            "create_record",
            replay_arguments(),
        )
        .await
        .unwrap();
    let replay = registry
        .call(
            db.clone(),
            caller.clone(),
            "create_record",
            replay_arguments(),
        )
        .await
        .unwrap();
    assert!(first.get("work_overlap").is_some());
    assert!(replay.get("work_overlap").is_none());

    let preview = registry
        .call(
            db.clone(),
            caller.clone(),
            "start_work",
            json!({ "record_id": target, "action": "preview", "run_key": "pilot-river-b748b2" }),
        )
        .await
        .unwrap();
    assert!(preview.get("work_overlap").is_none());
    let quiet = registry
        .call(
            db.clone(),
            Caller::authenticated("account:quiet"),
            "set_intent",
            json!({ "intent": "no overlaps here", "run_key": "scout-chair-z748b2" }),
        )
        .await
        .unwrap();
    assert!(quiet["briefing"]["overlapping_claims"]["items"]
        .as_array()
        .is_some_and(Vec::is_empty));

    let annotation_rows: Vec<String> = sqlx::query_scalar(
        "SELECT result_annotation FROM read_log_calls
          WHERE result_annotation IS NOT NULL ORDER BY seq",
    )
    .fetch_all(db.pool())
    .await
    .unwrap();
    let annotations = annotation_rows
        .iter()
        .map(|row| serde_json::from_str::<Value>(row).unwrap())
        .collect::<Vec<_>>();
    let surfaces = annotations
        .iter()
        .map(|annotation| annotation["surface"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(surfaces, ["claim", "create", "set_intent", "create"]);
    for annotation in &annotations {
        assert_eq!(annotation["kind"], "work_overlap_emission");
        assert_eq!(annotation["version"], 1);
        let object = annotation.as_object().unwrap();
        assert_eq!(object.len(), 4);
        assert!(object
            .keys()
            .all(|key| matches!(key.as_str(), "kind" | "version" | "surface" | "anchors")));
        for anchor in annotation["anchors"].as_array().unwrap() {
            let anchor = anchor.as_object().unwrap();
            assert_eq!(anchor.len(), 5);
            assert!(anchor.keys().all(|key| matches!(
                key.as_str(),
                "record_id"
                    | "overlap_record_ids"
                    | "overlap_item_count"
                    | "overlap_total_count"
                    | "truncated"
            )));
        }
        let text = serde_json::to_string(annotation).unwrap();
        for forbidden in [
            "holder_tier",
            "holder_identity",
            "run_key",
            "claimed_at",
            "measure a real disclosed overlap",
        ] {
            assert!(
                !text.contains(forbidden),
                "annotation leaked {forbidden}: {text}"
            );
        }
    }

    let replay_annotations: Vec<Option<String>> = sqlx::query_scalar(
        "SELECT result_annotation FROM read_log_calls
          WHERE tool='create_record'
            AND json_extract(arguments, '$.idempotency_key')='emission-overlap-replay'
          ORDER BY seq",
    )
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert!(replay_annotations[0].is_some());
    assert_eq!(replay_annotations[1], None);
    let no_notice_annotations: Vec<Option<String>> = sqlx::query_scalar(
        "SELECT result_annotation FROM read_log_calls
          WHERE (tool='start_work' AND json_extract(arguments, '$.action')='preview')
             OR (tool='set_intent' AND json_extract(arguments, '$.intent')='no overlaps here')",
    )
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(no_notice_annotations, vec![None, None]);
}

// ---------------------------------------------------------------------------
// Working context
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_context_carries_ancestors_governance_and_dependency_readiness() {
    let db = db().await;
    let registry = registry();
    let root = create(
        &registry,
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Programme" }),
    )
    .await;
    let epic = create(
        &registry,
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Epic", "home_id": root }),
    )
    .await;
    let id = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "Leaf", "home_id": epic, "lifecycle": "in_progress" }),
    )
    .await;

    let decision = create(
        &registry,
        &db,
        json!({ "type": "Resolution", "kind": "decision", "name": "Rust, not TypeScript" }),
    )
    .await;
    let rule = create(
        &registry,
        &db,
        json!({ "type": "Resolution", "kind": "rule", "name": "No direct projection writes" }),
    )
    .await;
    let noise = create(
        &registry,
        &db,
        json!({ "type": "Document", "name": "Notes" }),
    )
    .await;
    let blocker = task(&registry, &db, "Upstream", "in_progress").await;
    let gate = task(&registry, &db, "Gate", "in_progress").await;

    link(&registry, &db, &id, "implements", &decision).await;
    link(&registry, &db, &rule, "relates_to", &id).await;
    link(&registry, &db, &id, "relates_to", &noise).await;
    link(&registry, &db, &id, "depends_on", &blocker).await;
    link(&registry, &db, &gate, "blocks", &id).await;

    let out = call(
        &registry,
        &db,
        "start_work",
        json!({ "record_id": id, "agent_id": "agent:a" }),
    )
    .await;
    let context = &out["context"];

    let ancestors: Vec<&str> = context["record"]["ancestors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        ancestors,
        vec!["Workspace", "Unfiled", "Programme", "Epic"],
        "root first"
    );

    let governance = context["governance"].as_array().unwrap();
    let names: Vec<&str> = governance
        .iter()
        .map(|g| g["name"].as_str().unwrap())
        .collect();
    assert_eq!(governance.len(), 2, "resolutions only: {names:?}");
    assert!(names.contains(&"Rust, not TypeScript"));
    assert!(names.contains(&"No direct projection writes"));
    assert!(
        !names.contains(&"Notes"),
        "a plain linked document is not governance"
    );
    // Both link directions are reported, with the relationship that reached it.
    let directions: Vec<&str> = governance
        .iter()
        .map(|g| g["direction"].as_str().unwrap())
        .collect();
    assert!(directions.contains(&"in") && directions.contains(&"out"));

    let dependencies = &context["dependencies"];
    assert_eq!(dependencies["ready"], false);
    assert_eq!(dependencies["waiting_on"][0]["name"], "Upstream");
    assert_eq!(dependencies["waiting_on"][0]["lifecycle"], "in_progress");
    assert_eq!(dependencies["waiting_on"][0]["satisfaction"], "waiting");
    assert_eq!(
        dependencies["waiting_on"][0]["lifecycle_interpretation"]["status"],
        "governed"
    );
    assert_eq!(
        dependencies["waiting_on"][0]["lifecycle_interpretation"]["axis"]["key"],
        "work_status"
    );
    assert_eq!(
        dependencies["waiting_on"][0]["lifecycle_interpretation"]["terminality"],
        "open"
    );
    assert!(dependencies["satisfied"].as_array().unwrap().is_empty());
    assert_eq!(dependencies["blocked_by"][0]["name"], "Gate");
    // Readiness is context, not policy: a blocked record still claims.
    assert_eq!(out["changed"], true);
}

#[tokio::test]
async fn dependency_readiness_distinguishes_satisfied_unsatisfied_and_ambiguous_targets() {
    let db = db().await;
    let registry = registry();
    let downstream = task(&registry, &db, "Downstream", "open").await;
    let completed = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "Completed", "lifecycle": "completed" }),
    )
    .await;
    let failed = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "Failed", "lifecycle": "closed" }),
    )
    .await;
    let active = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "Active", "lifecycle": "in_progress" }),
    )
    .await;
    let absent = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "Absent" }),
    )
    .await;
    let unknown = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "Unknown", "lifecycle": "open" }),
    )
    .await;
    sqlx::query("UPDATE records SET lifecycle = NULL WHERE id = ?")
        .bind(&absent)
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    sqlx::query("UPDATE records SET lifecycle = 'retired' WHERE id = ?")
        .bind(&unknown)
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();

    for dependency in [&completed, &failed, &active, &absent, &unknown] {
        link(&registry, &db, &downstream, "depends_on", dependency).await;
    }

    let out = call(
        &registry,
        &db,
        "start_work",
        json!({ "record_id": downstream, "action": "preview" }),
    )
    .await;
    let dependencies = &out["context"]["dependencies"];
    assert_eq!(dependencies["ready"], false);
    assert_eq!(dependencies["satisfied"].as_array().unwrap().len(), 1);
    assert_eq!(dependencies["satisfied"][0]["id"], completed);
    assert_eq!(dependencies["satisfied"][0]["satisfaction"], "satisfied");
    assert_eq!(
        dependencies["satisfied"][0]["lifecycle_interpretation"]["terminality"],
        "terminal_positive"
    );

    let waiting = dependencies["waiting_on"].as_array().unwrap();
    let by_id = |id: &str| {
        waiting
            .iter()
            .find(|entry| entry["id"] == id)
            .unwrap_or_else(|| panic!("dependency {id} missing from {waiting:#?}"))
    };
    assert_eq!(by_id(&active)["satisfaction"], "waiting");
    assert_eq!(by_id(&failed)["satisfaction"], "unsatisfied");
    assert_eq!(
        by_id(&failed)["lifecycle_interpretation"]["terminality"],
        "terminal_negative"
    );
    assert_eq!(by_id(&absent)["satisfaction"], "ambiguous");
    assert_eq!(
        by_id(&absent)["lifecycle_interpretation"]["status"],
        "absent"
    );
    assert_eq!(by_id(&unknown)["satisfaction"], "ambiguous");
    assert_eq!(
        by_id(&unknown)["lifecycle_interpretation"]["reason"],
        "unknown_or_inactive_value"
    );

    let rendered = native_ce::mcp::render::render("start_work", &out).unwrap();
    assert!(rendered.contains("Satisfied (1)"), "{rendered}");
    assert!(rendered.contains("terminal_positive"), "{rendered}");
    assert!(rendered.contains("terminal_negative"), "{rendered}");
    assert!(rendered.contains("unknown_or_inactive_value"), "{rendered}");

    let ready = task(&registry, &db, "Ready after prerequisite", "open").await;
    link(&registry, &db, &ready, "depends_on", &completed).await;
    let preview = call(
        &registry,
        &db,
        "start_work",
        json!({ "record_id": ready, "action": "preview", "agent_id": "claimant" }),
    )
    .await;
    assert_eq!(preview["context"]["dependencies"]["ready"], true);
    assert!(preview["context"]["dependencies"]["waiting_on"]
        .as_array()
        .unwrap()
        .is_empty());
    let claimed = call(
        &registry,
        &db,
        "start_work",
        json!({ "record_id": ready, "agent_id": "claimant" }),
    )
    .await;
    assert_eq!(claimed["changed"], true);
    assert_eq!(claimed["context"]["dependencies"]["ready"], true);
    assert_eq!(
        claimed["context"]["dependencies"], preview["context"]["dependencies"],
        "claim and preview must classify the same dependency snapshot"
    );
}

#[tokio::test]
async fn a_blocker_stops_blocking_once_it_is_archived_or_tombstoned() {
    let db = db().await;
    let registry = registry();
    let id = task(&registry, &db, "Downstream", "in_progress").await;
    let archived = task(&registry, &db, "Archived blocker", "in_progress").await;
    let deleted = task(&registry, &db, "Deleted blocker", "in_progress").await;
    link(&registry, &db, &id, "depends_on", &archived).await;
    link(&registry, &db, &id, "depends_on", &deleted).await;

    let preview = |args: Value| async { call(&registry, &db, "start_work", args).await };
    let out = preview(json!({ "record_id": id, "action": "preview" })).await;
    assert_eq!(out["context"]["dependencies"]["ready"], false);

    call(
        &registry,
        &db,
        "archive_record",
        json!({ "id": archived.clone() }),
    )
    .await;
    call(
        &registry,
        &db,
        "delete_record",
        json!({ "id": deleted.clone() }),
    )
    .await;

    let out = call(
        &registry,
        &db,
        "start_work",
        json!({ "record_id": id, "action": "preview" }),
    )
    .await;
    assert_eq!(
        out["context"]["dependencies"]["ready"], true,
        "archiving or tombstoning a blocker releases what it blocked"
    );
    assert_eq!(
        out["context"]["dependencies"]["waiting_on"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
}

// ---------------------------------------------------------------------------
// release
// ---------------------------------------------------------------------------

#[tokio::test]
async fn release_leaves_the_record_lifecycle_unchanged() {
    let db = db().await;
    let registry = registry();
    let id = create(
        &registry,
        &db,
        json!({
            "type": "WorkItem",
            "kind": "epic",
            "name": "Round trip",
            "lifecycle": "blocked"
        }),
    )
    .await;
    call(
        &registry,
        &db,
        "start_work",
        json!({ "record_id": id, "agent_id": "agent:a" }),
    )
    .await;

    let out = call(
        &registry,
        &db,
        "start_work",
        json!({ "record_id": id, "action": "release", "agent_id": "agent:a" }),
    )
    .await;
    assert_eq!(out["changed"], true);
    assert_eq!(out["claimed"], false);
    assert!(out.get("previous_lifecycle").is_none());
    assert_eq!(out["lifecycle"], "blocked");
    assert_eq!(out["held_by"], Value::Null);
    assert_eq!(
        out["context"]["record"]["lifecycle_interpretation"]["value"]["raw"],
        "blocked"
    );

    // And the record is claimable again, by anyone.
    let out = call(
        &registry,
        &db,
        "start_work",
        json!({ "record_id": id, "agent_id": "agent:b" }),
    )
    .await;
    assert_eq!(out["held_by"], "agent:b");
}

#[tokio::test]
async fn release_restores_a_lifecycle_that_was_set_as_a_spine_facet() {
    let db = db().await;
    let registry = registry();
    let id = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "name": "Faceted" }),
    )
    .await;
    // Work coordination is orthogonal to all lifecycle writers.
    native_ce::store::set_facet(
        &db,
        &id,
        FacetSetPayload {
            key: "lifecycle".into(),
            value: Some("in_progress".into()),
            vocab_ref: None,
            as_of: None,
            observation_only: false,
        },
    )
    .await
    .unwrap();

    call(&registry, &db, "start_work", json!({ "record_id": id })).await;
    let out = call(
        &registry,
        &db,
        "start_work",
        json!({ "record_id": id, "action": "release" }),
    )
    .await;
    assert_eq!(out["lifecycle"], "in_progress");
}

#[tokio::test]
async fn release_leaves_the_lifecycle_unset_when_the_claim_found_it_unset() {
    let db = db().await;
    let registry = registry();
    let id = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "name": "Bare" }),
    )
    .await;

    let out = call(&registry, &db, "start_work", json!({ "record_id": id })).await;
    assert_eq!(out["claimed"], true);
    assert!(out.get("previous_lifecycle").is_none());
    let out = call(
        &registry,
        &db,
        "start_work",
        json!({ "record_id": id, "action": "release" }),
    )
    .await;
    assert_eq!(out["lifecycle"], Value::Null);
    assert_eq!(out["context"]["record"]["lifecycle"], Value::Null);
}

#[tokio::test]
async fn release_requires_the_holder_to_ask_for_it() {
    let db = db().await;
    let registry = registry();
    let id = task(&registry, &db, "Stranded", "in_progress").await;
    call(
        &registry,
        &db,
        "start_work",
        json!({ "record_id": id, "agent_id": "agent:gone" }),
    )
    .await;

    let err = call_err(
        &registry,
        &db,
        "start_work",
        json!({ "record_id": id, "action": "release", "agent_id": "agent:janitor" }),
    )
    .await;
    assert!(err.contains("claimed by another caller"), "{err}");
}

#[tokio::test]
async fn releasing_an_unclaimed_record_errors() {
    let db = db().await;
    let registry = registry();
    let id = task(&registry, &db, "Free", "in_progress").await;
    let err = call_err(
        &registry,
        &db,
        "start_work",
        json!({ "record_id": id, "action": "release" }),
    )
    .await;
    assert!(
        err.contains("is not claimed — nothing to release"),
        "unexpected: {err}"
    );
}

// ---------------------------------------------------------------------------
// Argument and liveness errors
// ---------------------------------------------------------------------------

#[tokio::test]
async fn missing_tombstoned_and_malformed_calls_error_clearly() {
    let db = db().await;
    let registry = registry();

    let err = call_err(
        &registry,
        &db,
        "start_work",
        json!({ "record_id": "ghost" }),
    )
    .await;
    assert!(
        err.contains("record ghost does not exist"),
        "unexpected: {err}"
    );

    let gone = task(&registry, &db, "Gone", "in_progress").await;
    call(
        &registry,
        &db,
        "delete_record",
        json!({ "id": gone.clone() }),
    )
    .await;
    let err = call_err(&registry, &db, "start_work", json!({ "record_id": gone })).await;
    assert!(err.contains("does not exist"), "unexpected: {err}");

    let id = task(&registry, &db, "Fine", "in_progress").await;
    let err = call_err(
        &registry,
        &db,
        "start_work",
        json!({ "record_id": id, "action": "steal" }),
    )
    .await;
    assert!(err.contains("unknown action 'steal'"), "unexpected: {err}");

    let err = call_err(
        &registry,
        &db,
        "start_work",
        json!({ "record_id": id, "lifecycle": "done" }),
    )
    .await;
    assert!(
        err.contains("invalid arguments for start_work"),
        "unexpected: {err}"
    );

    let err = call_err(
        &registry,
        &db,
        "start_work",
        json!({ "record_id": id, "agent": "typo" }),
    )
    .await;
    assert!(
        err.contains("invalid arguments for start_work"),
        "unexpected: {err}"
    );
}

// ---------------------------------------------------------------------------
// The acceptance test: replay still reproduces the projections
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rebuild_and_diff_passes_after_a_claim_release_cycle() {
    let db = db().await;
    let registry = registry();
    let root = create(
        &registry,
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Everything" }),
    )
    .await;
    let decision = create(
        &registry,
        &db,
        json!({ "type": "Resolution", "kind": "decision", "name": "One conditional update" }),
    )
    .await;
    let blocker = task(&registry, &db, "Upstream", "in_progress").await;
    let id = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "Claimed", "home_id": root, "lifecycle": "in_progress" }),
    )
    .await;
    link(&registry, &db, &id, "implements", &decision).await;
    link(&registry, &db, &id, "depends_on", &blocker).await;

    call(
        &registry,
        &db,
        "start_work",
        json!({ "record_id": id, "agent_id": "agent:a" }),
    )
    .await;
    call(
        &registry,
        &db,
        "start_work",
        json!({ "record_id": id, "action": "preview" }),
    )
    .await;
    call(
        &registry,
        &db,
        "start_work",
        json!({ "record_id": id, "action": "release", "agent_id": "agent:a" }),
    )
    .await;
    call(
        &registry,
        &db,
        "start_work",
        json!({ "record_id": id, "agent_id": "agent:b" }),
    )
    .await;
    call(
        &registry,
        &db,
        "start_work",
        json!({ "record_id": id, "action": "release", "agent_id": "agent:b" }),
    )
    .await;

    let diff = rebuild_and_diff(&db).await.unwrap();
    assert!(
        diff.equal,
        "projections diverge from replay: {:?}",
        diff.tables
    );
}
