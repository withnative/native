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
    registry
        .call(
            db.clone(),
            caller,
            tool,
            crate::common::with_test_reason(tool, args),
        )
        .await
        .unwrap()
}

async fn call_err(registry: &ToolRegistry, db: &Db, tool: &str, args: Value) -> String {
    let caller = Caller::authenticated(
        args.get("agent_id")
            .and_then(Value::as_str)
            .unwrap_or("test:local"),
    );
    registry
        .call(
            db.clone(),
            caller,
            tool,
            crate::common::with_test_reason(tool, args),
        )
        .await
        .unwrap_err()
        .to_string()
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
    assert!(same_account_other_run.contains("is already claimed — release it first"));
    assert!(!same_account_other_run.contains("scout"));

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
    assert!(stale_release.contains("claimed by another caller"));
    let current: Option<String> = sqlx::query_scalar(
        "SELECT claimed_run_key FROM records WHERE id = ? AND claimed_by_account = 'account:a'",
    )
    .bind(&id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(current.as_deref(), Some(second_run));
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
