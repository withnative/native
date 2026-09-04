use native_ce::conformance::rebuild_and_diff;
use native_ce::events::LinkAddedPayload;
use native_ce::generated::kinds::CoreKind;
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::meta::{KindMetadataV1, VocabularyValueTerminality};
use native_ce::query::lifecycle::{LifecycleInterpretation, LifecycleInterpreter};
use native_ce::store::{add_link, create_record as store_create_record};
use native_ce::{create_database, Db};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::Row;

async fn db() -> Db {
    let db = create_database(":memory:").await.unwrap();
    native_ce::meta::seed_vocabularies(&db).await.unwrap();
    db
}

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

async fn call(registry: &ToolRegistry, db: &Db, tool: &str, args: Value) -> Value {
    registry
        .call(db.clone(), Caller::local(), tool, args)
        .await
        .unwrap()
}

async fn call_err(registry: &ToolRegistry, db: &Db, tool: &str, args: Value) -> String {
    registry
        .call(db.clone(), Caller::local(), tool, args)
        .await
        .unwrap_err()
        .to_string()
}

async fn create(registry: &ToolRegistry, db: &Db, mut args: Value) -> String {
    let object = args.as_object_mut().unwrap();
    let kind = match object.get("type").and_then(Value::as_str) {
        Some("Annotation") => "suggestion",
        Some("Document") => "note",
        _ => "task",
    };
    object.entry("kind").or_insert_with(|| json!(kind));
    object
        .entry("reason")
        .or_insert(json!("Suggestion integration fixture"));
    call(registry, db, "create_record", args).await["id"]
        .as_str()
        .unwrap()
        .to_string()
}

fn digest(body: &str) -> String {
    hex::encode(Sha256::digest(body.as_bytes()))
}

struct SuggestionFixture<'a> {
    target: &'a str,
    name: &'a str,
    replacement: &'a str,
    precondition: &'a str,
    old: Option<&'a str>,
    base_digest: Option<&'a str>,
}

async fn suggestion(registry: &ToolRegistry, db: &Db, fixture: SuggestionFixture<'_>) -> String {
    let mut facets = serde_json::Map::new();
    facets.insert("proposal.precondition".into(), json!(fixture.precondition));
    if let Some(old) = fixture.old {
        facets.insert("anchor.old".into(), json!(old));
    }
    if let Some(base_digest) = fixture.base_digest {
        facets.insert("anchor.base_digest".into(), json!(base_digest));
    }
    create(
        registry,
        db,
        json!({
            "type": "Annotation",
            "kind": "suggestion",
            "name": fixture.name,
            "lifecycle": "open",
            "body": fixture.replacement,
            "facets": facets,
            "links": [{ "target_id": fixture.target, "relationship": "part_of" }],
        }),
    )
    .await
}

async fn body_and_lifecycle(db: &Db, id: &str) -> (Option<String>, Option<String>) {
    let row = sqlx::query("SELECT body, lifecycle FROM records WHERE id = ?")
        .bind(id)
        .fetch_one(db.pool())
        .await
        .unwrap();
    (row.get("body"), row.get("lifecycle"))
}

async fn last_update_payload(db: &Db, id: &str) -> Value {
    let payload: String = sqlx::query_scalar(
        "SELECT payload FROM content_events
          WHERE record_id = ? AND type = 'record.updated'
          ORDER BY seq DESC LIMIT 1",
    )
    .bind(id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    serde_json::from_str(&payload).unwrap()
}

#[tokio::test]
async fn suggestion_authoring_requires_governed_open_and_refuses_the_facet_form() {
    let db = db().await;
    let registry = registry();

    for (index, (id, lifecycle)) in [
        ("missing", None),
        ("null", Some(Value::Null)),
        ("accepted", Some(json!("accepted"))),
        ("rejected", Some(json!("rejected"))),
        ("stale", Some(json!("stale"))),
        ("typo", Some(json!("opne"))),
        ("wrong-type", Some(json!(42))),
    ]
    .into_iter()
    .enumerate()
    {
        let mut args = json!({
            "id": format!("5a99e571-0000-4000-8000-{:012}", 200 + index),
            "type": "Annotation",
            "kind": "suggestion",
            "facets": { "proposal.precondition": "none" },
            "reason": "Exercise suggestion authoring"
        });
        if let Some(lifecycle) = lifecycle {
            args["lifecycle"] = lifecycle;
        }
        let error = call_err(&registry, &db, "create_record", args).await;
        // A non-string carrier is refused by argument parsing, which reports the
        // shape rather than the field, so it does not name `lifecycle`.
        let refused = if id == "wrong-type" {
            error.contains("expected a string")
        } else {
            error.contains("lifecycle")
                && (error.contains("resolve_suggestions")
                    || error.contains("active member")
                    || error.contains("must be authored"))
        };
        assert!(refused, "{id}: {error}");
    }

    let top = create(
        &registry,
        &db,
        json!({
            "id": "5a99e571-0000-4000-8000-000000000002",
            "type": "Annotation",
            "lifecycle": "open",
            "facets": { "proposal.precondition": "none" }
        }),
    )
    .await;
    assert_eq!(
        body_and_lifecycle(&db, &top).await.1.as_deref(),
        Some("open")
    );

    // `lifecycle` is a spine facet: a column, not a `facet_values` row. It is
    // carried by the top-level argument on every tool, and suggestions are no
    // exception — governing this kind does not open a second write form for it.
    let via_facet = call_err(
        &registry,
        &db,
        "create_record",
        json!({
            "id": "5a99e571-0000-4000-8000-000000000001",
            "type": "Annotation",
            "kind": "suggestion",
            "facets": { "lifecycle": "open", "proposal.precondition": "none" },
            "reason": "Refuse the facet carrier"
        }),
    )
    .await;
    assert!(via_facet.contains("spine facet"), "{via_facet}");

    let interpreter = LifecycleInterpreter::load(&db, None).await.unwrap();
    for (value, terminality) in [
        ("open", "open"),
        ("accepted", "terminal_positive"),
        ("rejected", "terminal_negative"),
        ("stale", "terminal_negative"),
    ] {
        let LifecycleInterpretation::Governed(governed) =
            interpreter.interpret("Annotation", Some("suggestion"), None, Some(value))
        else {
            panic!("{value} was not governed")
        };
        assert_eq!(governed.vocabulary.id, "voc:suggestion-lifecycle");
        assert_eq!(governed.terminality, terminality);
    }
}

#[tokio::test]
async fn ordinary_updates_only_preserve_or_repair_suggestion_lifecycle() {
    let db = db().await;
    let registry = registry();
    let target = create(
        &registry,
        &db,
        json!({ "id": "5a99e571-0000-4000-8000-000000000008", "type": "Document" }),
    )
    .await;
    let open = create(
        &registry,
        &db,
        json!({
            "id": "5a99e571-0000-4000-8000-000000000007",
            "type": "Annotation",
            "lifecycle": "open",
            "facets": { "proposal.precondition": "none" },
            "links": [{ "target_id": target, "relationship": "part_of" }]
        }),
    )
    .await;

    for lifecycle in [
        Value::Null,
        json!("accepted"),
        json!("rejected"),
        json!("stale"),
    ] {
        let error = call_err(
            &registry,
            &db,
            "update_record",
            json!({
                "id": open,
                "lifecycle": lifecycle,
                "reason": "Attempt a direct transition"
            }),
        )
        .await;
        assert!(
            error.contains("cannot be cleared") || error.contains("terminal transitions"),
            "{error}"
        );
    }

    let via_facet = call_err(
        &registry,
        &db,
        "update_record",
        json!({
            "id": open,
            "facets": { "lifecycle": "accepted" },
            "reason": "Refuse the facet carrier"
        }),
    )
    .await;
    assert!(via_facet.contains("spine facet"), "{via_facet}");

    for (id, legacy) in [
        ("5a99e571-0000-4000-8000-000000000005", None),
        ("5a99e571-0000-4000-8000-000000000004", Some("opne")),
    ] {
        let mut payload = json!({
            "id": id,
            "type": "Annotation",
            "kind": "suggestion",
            "facets": { "proposal.precondition": "none" }
        });
        if let Some(legacy) = legacy {
            payload["lifecycle"] = json!(legacy);
        }
        store_create_record(&db, payload).await.unwrap();
        add_link(
            &db,
            LinkAddedPayload {
                id: Some(format!("link:{id}")),
                source_id: id.into(),
                target_id: target.clone(),
                relationship: "part_of".into(),
                note: None,
            },
        )
        .await
        .unwrap();
        let repaired = call(
            &registry,
            &db,
            "update_record",
            json!({
                "id": id,
                "lifecycle": "open",
                "reason": "Repair legacy suggestion state"
            }),
        )
        .await;
        assert_eq!(
            repaired["lifecycle_interpretation"]["value"]["canonical"],
            "open"
        );
    }

    store_create_record(
        &db,
        json!({
            "id": "5a99e571-0000-4000-8000-000000000006",
            "type": "Annotation",
            "kind": "suggestion",
            "lifecycle": "accepted",
            "facets": { "proposal.precondition": "none" }
        }),
    )
    .await
    .unwrap();
    add_link(
        &db,
        LinkAddedPayload {
            id: Some("5a99e571-0000-4000-8000-000000000101".into()),
            source_id: "5a99e571-0000-4000-8000-000000000006".into(),
            target_id: target.clone(),
            relationship: "part_of".into(),
            note: None,
        },
    )
    .await
    .unwrap();
    let preserved = call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": "5a99e571-0000-4000-8000-000000000006",
            "lifecycle": "accepted",
            "reason": "Preserve the terminal value"
        }),
    )
    .await;
    assert_eq!(
        preserved["lifecycle_interpretation"]["value"]["canonical"],
        "accepted"
    );
    let reopen = call_err(
        &registry,
        &db,
        "update_record",
        json!({
            "id": "5a99e571-0000-4000-8000-000000000006",
            "lifecycle": "open",
            "reason": "Attempt to reopen"
        }),
    )
    .await;
    assert!(reopen.contains("cannot resolve or reopen"), "{reopen}");

    let entering = create(
        &registry,
        &db,
        json!({
            "id": "5a99e571-0000-4000-8000-000000000003",
            "type": "Annotation",
            "kind": "note",
            "links": [{ "target_id": target, "relationship": "part_of" }]
        }),
    )
    .await;
    let entered = call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": entering,
            "kind": "suggestion",
            "lifecycle": "open",
            "facets": { "proposal.precondition": "none" },
            "reason": "Enter the governed suggestion shape"
        }),
    )
    .await;
    assert_eq!(entered["kind"], "suggestion");
    assert_eq!(
        entered["lifecycle_interpretation"]["value"]["canonical"],
        "open"
    );
    let left = call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": entering,
            "kind": "note",
            "lifecycle": null,
            "reason": "Leave the governed suggestion shape"
        }),
    )
    .await;
    assert_eq!(left["kind"], "note");
    assert_eq!(left["lifecycle_interpretation"]["status"], "absent");
}

#[tokio::test]
async fn resolver_destinations_are_checked_against_the_live_vocabulary_before_writes() {
    for (index, destination) in ["accepted", "rejected", "stale"].into_iter().enumerate() {
        let db = db().await;
        let registry = registry();
        let target = create(
            &registry,
            &db,
            json!({
                "id": format!("5a99e571-0000-4000-8000-{:012}", 300 + index),
                "type": "Document",
                "body": "current"
            }),
        )
        .await;
        let id = suggestion(
            &registry,
            &db,
            SuggestionFixture {
                target: &target,
                name: "Vocabulary destination",
                replacement: "replacement",
                precondition: if destination == "stale" {
                    "span"
                } else {
                    "none"
                },
                old: (destination == "stale").then_some("missing"),
                base_digest: None,
            },
        )
        .await;
        native_ce::meta::deprecate_value(
            &db,
            &format!("vv:voc:suggestion-lifecycle:{destination}"),
        )
        .await
        .unwrap();

        let error = call_err(
            &registry,
            &db,
            "resolve_suggestions",
            json!({
                "action": if destination == "rejected" { "reject" } else { "accept" },
                "suggestion_ids": [&id],
                "reason": "Exercise resolver vocabulary validation"
            }),
        )
        .await;
        assert!(
            error.contains("not an active member") && error.contains("suggestion-lifecycle"),
            "{destination}: {error}"
        );
        assert_eq!(
            body_and_lifecycle(&db, &id).await.1.as_deref(),
            Some("open")
        );
        assert_eq!(
            body_and_lifecycle(&db, &target).await.0.as_deref(),
            Some("current")
        );
    }
}

/// Governing the suggestion lifecycle must not quietly open `facets.lifecycle`
/// as a second write form for everyone else. It stays refused on both entry
/// points, for a kind that has a governed lifecycle of its own.
#[tokio::test]
async fn the_lifecycle_facet_form_stays_refused_for_non_suggestion_shapes() {
    let db = db().await;
    let registry = registry();
    let created = call_err(
        &registry,
        &db,
        "create_record",
        json!({
            "id": "5a99e571-0000-4000-8000-000000000009",
            "type": "WorkItem",
            "kind": "task",
            "facets": { "lifecycle": "in_progress" },
            "reason": "Refuse the facet carrier on create"
        }),
    )
    .await;
    assert!(created.contains("spine facet"), "{created}");

    let id = create(
        &registry,
        &db,
        json!({
            "id": "5a99e571-0000-4000-8000-000000000010",
            "type": "WorkItem",
            "kind": "task",
            "lifecycle": "in_progress"
        }),
    )
    .await;
    let updated = call_err(
        &registry,
        &db,
        "update_record",
        json!({
            "id": id,
            "facets": { "lifecycle": "completed" },
            "reason": "Refuse the facet carrier on update"
        }),
    )
    .await;
    assert!(updated.contains("spine facet"), "{updated}");
}

#[tokio::test]
async fn ordered_span_batch_updates_target_and_every_suggestion_atomically() {
    let db = db().await;
    let registry = registry();
    let target = create(
        &registry,
        &db,
        json!({ "type": "Document", "name": "Target", "body": "alpha beta" }),
    )
    .await;
    let first = suggestion(
        &registry,
        &db,
        SuggestionFixture {
            target: &target,
            name: "First",
            replacement: "A",
            precondition: "span",
            old: Some("alpha"),
            base_digest: Some(&digest("alpha beta")),
        },
    )
    .await;
    let second = suggestion(
        &registry,
        &db,
        SuggestionFixture {
            target: &target,
            name: "Second",
            replacement: "B",
            precondition: "span",
            old: Some("beta"),
            base_digest: Some(&digest("alpha beta")),
        },
    )
    .await;

    let outcome = call(
        &registry,
        &db,
        "resolve_suggestions",
        json!({
            "action": "accept",
            "suggestion_ids": [&first, &second],
            "reason": "Both bounded edits are correct",
        }),
    )
    .await;
    assert_eq!(outcome["status"], "accepted");
    assert_eq!(outcome["suggestion_ids"], json!([first, second]));
    assert_eq!(
        body_and_lifecycle(&db, &target).await.0.as_deref(),
        Some("A B")
    );
    assert_eq!(
        body_and_lifecycle(&db, &first).await.1.as_deref(),
        Some("accepted")
    );
    assert_eq!(
        body_and_lifecycle(&db, &second).await.1.as_deref(),
        Some("accepted")
    );
    assert_eq!(
        last_update_payload(&db, &target).await["reason"],
        "Both bounded edits are correct"
    );
    assert!(rebuild_and_diff(&db).await.unwrap().equal);
}

#[tokio::test]
async fn failed_batch_marks_only_failures_stale_and_leaves_target_and_siblings_open() {
    let db = db().await;
    let registry = registry();
    let target = create(
        &registry,
        &db,
        json!({ "type": "Document", "name": "Target", "body": "alpha beta" }),
    )
    .await;
    let passing = suggestion(
        &registry,
        &db,
        SuggestionFixture {
            target: &target,
            name: "Passing",
            replacement: "A",
            precondition: "span",
            old: Some("alpha"),
            base_digest: None,
        },
    )
    .await;
    let failing = suggestion(
        &registry,
        &db,
        SuggestionFixture {
            target: &target,
            name: "Failing",
            replacement: "G",
            precondition: "span",
            old: Some("gamma"),
            base_digest: None,
        },
    )
    .await;

    let outcome = call(
        &registry,
        &db,
        "resolve_suggestions",
        json!({
            "action": "accept",
            "suggestion_ids": [&passing, &failing],
            "reason": "Try the selected batch",
        }),
    )
    .await;
    assert_eq!(outcome["status"], "stale");
    assert_eq!(outcome["suggestion_ids"], json!([failing]));
    assert_eq!(outcome["causes"][0]["code"], "span_missing");
    assert_eq!(
        body_and_lifecycle(&db, &target).await.0.as_deref(),
        Some("alpha beta")
    );
    assert_eq!(
        body_and_lifecycle(&db, &passing).await.1.as_deref(),
        Some("open")
    );
    assert_eq!(
        body_and_lifecycle(&db, &failing).await.1.as_deref(),
        Some("stale")
    );
    let summary: Option<String> = sqlx::query_scalar("SELECT summary FROM records WHERE id = ?")
        .bind(&failing)
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(summary.as_deref(), Some("Stale: span_missing"));
    let stale_payload = last_update_payload(&db, &failing).await;
    assert_eq!(stale_payload["summary"], "Stale: span_missing");
    assert!(
        stale_payload.get("reason").is_none(),
        "the failed machine precondition is the stale reason"
    );
}

#[tokio::test]
async fn concurrent_accept_has_one_winner_and_one_structured_conflict() {
    let db = db().await;
    let registry = registry();
    let target = create(
        &registry,
        &db,
        json!({ "type": "Document", "name": "Target", "body": "before" }),
    )
    .await;
    let id = suggestion(
        &registry,
        &db,
        SuggestionFixture {
            target: &target,
            name: "Edit",
            replacement: "after",
            precondition: "span",
            old: Some("before"),
            base_digest: None,
        },
    )
    .await;
    let args = json!({
        "action": "accept",
        "suggestion_ids": [&id],
        "reason": "Accept once",
    });
    let left = registry.call(
        db.clone(),
        Caller::local(),
        "resolve_suggestions",
        args.clone(),
    );
    let right = registry.call(db.clone(), Caller::local(), "resolve_suggestions", args);
    let (left, right) = tokio::join!(left, right);
    let mut statuses = vec![
        left.unwrap()["status"].as_str().unwrap().to_string(),
        right.unwrap()["status"].as_str().unwrap().to_string(),
    ];
    statuses.sort();
    assert_eq!(statuses, ["accepted", "conflict"]);
    assert_eq!(
        body_and_lifecycle(&db, &target).await.0.as_deref(),
        Some("after")
    );
    let touches: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM read_log_touches t
          JOIN read_log_calls c ON c.seq = t.call_seq
         WHERE c.tool = 'resolve_suggestions' AND t.interaction = 'mutated'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(
        touches, 2,
        "only the winning call mutates target + suggestion"
    );
}

#[tokio::test]
async fn rejection_persists_reason_and_terminal_calls_conflict_without_writing() {
    let db = db().await;
    let registry = registry();
    let target = create(
        &registry,
        &db,
        json!({ "type": "Document", "name": "Target" }),
    )
    .await;
    let id = suggestion(
        &registry,
        &db,
        SuggestionFixture {
            target: &target,
            name: "Reject me",
            replacement: "new",
            precondition: "none",
            old: None,
            base_digest: None,
        },
    )
    .await;
    let args = json!({
        "action": "reject",
        "suggestion_ids": [&id],
        "reason": "It removes necessary context",
    });
    assert_eq!(
        call(&registry, &db, "resolve_suggestions", args.clone()).await["status"],
        "rejected"
    );
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let conflict = call(&registry, &db, "resolve_suggestions", args).await;
    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(conflict["status"], "conflict");
    assert_eq!(before, after);
    let summary: Option<String> = sqlx::query_scalar("SELECT summary FROM records WHERE id = ?")
        .bind(&id)
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(
        summary.as_deref(),
        Some("Rejected: It removes necessary context")
    );
    assert_eq!(
        last_update_payload(&db, &id).await["reason"],
        "It removes necessary context"
    );
    let touches: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM read_log_touches t
          JOIN read_log_calls c ON c.seq = t.call_seq
         WHERE c.tool = 'resolve_suggestions' AND t.interaction = 'mutated'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(
        touches, 1,
        "reject mutates the suggestion; conflict mutates nothing"
    );
}

#[tokio::test]
async fn whole_body_preconditions_are_single_only_and_unsupported_shapes_stay_open() {
    let db = db().await;
    let registry = registry();
    let target = create(
        &registry,
        &db,
        json!({ "type": "Document", "name": "Target", "body": "before" }),
    )
    .await;
    let digest_id = suggestion(
        &registry,
        &db,
        SuggestionFixture {
            target: &target,
            name: "Digest",
            replacement: "whole",
            precondition: "digest",
            old: None,
            base_digest: Some(&digest("before")),
        },
    )
    .await;
    let span_id = suggestion(
        &registry,
        &db,
        SuggestionFixture {
            target: &target,
            name: "Span",
            replacement: "AFTER",
            precondition: "span",
            old: Some("before"),
            base_digest: None,
        },
    )
    .await;
    let error = call_err(
        &registry,
        &db,
        "resolve_suggestions",
        json!({ "action": "accept", "suggestion_ids": [&digest_id, &span_id], "reason": "bad mix" }),
    )
    .await;
    assert!(error.contains("must be accepted alone"));
    assert_eq!(
        body_and_lifecycle(&db, &digest_id).await.1.as_deref(),
        Some("open")
    );

    let outcome = call(
        &registry,
        &db,
        "resolve_suggestions",
        json!({ "action": "accept", "suggestion_ids": [&digest_id], "reason": "whole body is correct" }),
    )
    .await;
    assert_eq!(outcome["status"], "accepted");
    assert_eq!(
        body_and_lifecycle(&db, &target).await.0.as_deref(),
        Some("whole")
    );

    let unsupported = suggestion(
        &registry,
        &db,
        SuggestionFixture {
            target: &target,
            name: "Unsupported",
            replacement: "x",
            precondition: "field_equals",
            old: None,
            base_digest: None,
        },
    )
    .await;
    let error = call_err(
        &registry,
        &db,
        "resolve_suggestions",
        json!({ "action": "accept", "suggestion_ids": [&unsupported], "reason": "try" }),
    )
    .await;
    assert!(error.contains("unsupported for body suggestions"));
    assert_eq!(
        body_and_lifecycle(&db, &unsupported).await.1.as_deref(),
        Some("open")
    );
}

#[tokio::test]
async fn selected_batch_collisions_conflict_without_misclassifying_world_staleness() {
    let db = db().await;
    let registry = registry();
    let target = create(
        &registry,
        &db,
        json!({ "type": "Document", "name": "Target", "body": "alpha beta" }),
    )
    .await;
    let covering = suggestion(
        &registry,
        &db,
        SuggestionFixture {
            target: &target,
            name: "Cover both",
            replacement: "alpha",
            precondition: "span",
            old: Some("alpha beta"),
            base_digest: None,
        },
    )
    .await;
    let nested = suggestion(
        &registry,
        &db,
        SuggestionFixture {
            target: &target,
            name: "Nested span",
            replacement: "B",
            precondition: "span",
            old: Some("beta"),
            base_digest: None,
        },
    )
    .await;

    let outcome = call(
        &registry,
        &db,
        "resolve_suggestions",
        json!({
            "action": "accept",
            "suggestion_ids": [&covering, &nested],
            "reason": "Exercise overlap classification",
        }),
    )
    .await;
    assert_eq!(outcome["status"], "conflict");
    assert_eq!(outcome["causes"][0]["code"], "batch_overlap");
    assert_eq!(
        body_and_lifecycle(&db, &target).await.0.as_deref(),
        Some("alpha beta")
    );
    assert_eq!(
        body_and_lifecycle(&db, &covering).await.1.as_deref(),
        Some("open")
    );
    assert_eq!(
        body_and_lifecycle(&db, &nested).await.1.as_deref(),
        Some("open")
    );
}

#[tokio::test]
async fn unchecked_exact_span_drift_is_stale_not_an_authored_shape_error() {
    let db = db().await;
    let registry = registry();
    let target = create(
        &registry,
        &db,
        json!({ "type": "Document", "name": "Target", "body": "current" }),
    )
    .await;
    let id = suggestion(
        &registry,
        &db,
        SuggestionFixture {
            target: &target,
            name: "Unchecked drift",
            replacement: "new",
            precondition: "none",
            old: Some("prior"),
            base_digest: None,
        },
    )
    .await;

    let outcome = call(
        &registry,
        &db,
        "resolve_suggestions",
        json!({ "action": "accept", "suggestion_ids": [&id], "reason": "Check current span" }),
    )
    .await;
    assert_eq!(outcome["status"], "stale");
    assert_eq!(outcome["causes"][0]["code"], "span_missing");
    assert_eq!(
        body_and_lifecycle(&db, &target).await.0.as_deref(),
        Some("current")
    );
    assert_eq!(
        body_and_lifecycle(&db, &id).await.1.as_deref(),
        Some("stale")
    );
}

#[tokio::test]
async fn dry_run_stale_reports_without_writing_and_reject_is_invalid() {
    let db = db().await;
    let registry = registry();
    let target = create(
        &registry,
        &db,
        json!({ "type": "Document", "name": "Target", "body": "current" }),
    )
    .await;
    let id = suggestion(
        &registry,
        &db,
        SuggestionFixture {
            target: &target,
            name: "Drifted",
            replacement: "next",
            precondition: "span",
            old: Some("missing"),
            base_digest: None,
        },
    )
    .await;
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let outcome = call(
        &registry,
        &db,
        "resolve_suggestions",
        json!({
            "action": "accept", "suggestion_ids": [&id], "reason": "Preview", "dry_run": true
        }),
    )
    .await;
    assert_eq!(outcome["status"], "would_stale");
    assert_eq!(
        body_and_lifecycle(&db, &id).await.1.as_deref(),
        Some("open")
    );
    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(
        before, after,
        "dry-run cannot append target or stale lifecycle events"
    );
    let error = call_err(
        &registry,
        &db,
        "resolve_suggestions",
        json!({
            "action": "reject", "suggestion_ids": [&id], "reason": "Preview", "dry_run": true
        }),
    )
    .await;
    assert!(error.contains("dry_run is only valid with action accept"));
}

#[tokio::test]
async fn dry_run_body_matches_subsequent_commit_for_every_precondition_shape() {
    for (precondition, old, initial, replacement) in [
        ("span", Some("before"), "before tail", "after"),
        ("digest", None, "before", "after"),
        ("none", None, "before", "after"),
    ] {
        let db = db().await;
        let registry = registry();
        let target = create(
            &registry,
            &db,
            json!({ "type": "Document", "name": "Target", "body": initial }),
        )
        .await;
        let digest_value = digest(initial);
        let id = suggestion(
            &registry,
            &db,
            SuggestionFixture {
                target: &target,
                name: "Edit",
                replacement,
                precondition,
                old,
                base_digest: (precondition == "digest").then_some(digest_value.as_str()),
            },
        )
        .await;
        let args = json!({ "action": "accept", "suggestion_ids": [&id], "reason": "Apply" });
        let mut preview_args = args.clone();
        preview_args["dry_run"] = json!(true);
        let preview = call(&registry, &db, "resolve_suggestions", preview_args).await;
        assert_eq!(preview["status"], "would_accept");
        let committed = call(&registry, &db, "resolve_suggestions", args).await;
        assert_eq!(committed["status"], "accepted");
        assert_eq!(
            preview["prospective_body"],
            body_and_lifecycle(&db, &target).await.0.unwrap()
        );
    }
}

#[tokio::test]
async fn dry_run_batch_overlap_is_a_no_write_would_conflict() {
    let db = db().await;
    let registry = registry();
    let target = create(
        &registry,
        &db,
        json!({ "type": "Document", "name": "Target", "body": "alpha beta" }),
    )
    .await;
    let first = suggestion(
        &registry,
        &db,
        SuggestionFixture {
            target: &target,
            name: "Cover",
            replacement: "alpha",
            precondition: "span",
            old: Some("alpha beta"),
            base_digest: None,
        },
    )
    .await;
    let second = suggestion(
        &registry,
        &db,
        SuggestionFixture {
            target: &target,
            name: "Nested",
            replacement: "B",
            precondition: "span",
            old: Some("beta"),
            base_digest: None,
        },
    )
    .await;
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let outcome = call(&registry, &db, "resolve_suggestions", json!({ "action": "accept", "suggestion_ids": [&first, &second], "reason": "Preview", "dry_run": true })).await;
    assert_eq!(outcome["status"], "would_conflict");
    assert_eq!(outcome["causes"][0]["code"], "batch_overlap");
    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(before, after);
}

#[tokio::test]
async fn suggestion_windows_are_bounded_independent_and_reach_past_one_hundred() {
    let db = db().await;
    let registry = registry();
    let target = create(
        &registry,
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Wide suggestion target", "body": "body" }),
    )
    .await;
    let ordinary = create(
        &registry,
        &db,
        json!({ "type": "Document", "name": "Ordinary related record",
                "links": [{ "target_id": target, "relationship": "part_of" }] }),
    )
    .await;
    let mut authored = Vec::new();
    for index in 0..105 {
        let name = format!("Suggestion {index:03}");
        authored.push(
            suggestion(
                &registry,
                &db,
                SuggestionFixture {
                    target: &target,
                    name: &name,
                    replacement: "replacement",
                    precondition: "none",
                    old: None,
                    base_digest: None,
                },
            )
            .await,
        );
    }

    let first = call(
        &registry,
        &db,
        "get_record",
        json!({
            "ids": [&target],
            "include_suggestions": true,
            "suggestions_limit": 100,
            "suggestions_offset": 0,
            "children_limit": 1,
        }),
    )
    .await;
    assert_eq!(first["suggestions_limit"], 100);
    assert_eq!(first["suggestions_offset"], 0);
    assert_eq!(first["records"][0]["suggestion_count"], 105);
    assert_eq!(
        first["records"][0]["suggestions"].as_array().unwrap().len(),
        100
    );
    assert_eq!(first["records"][0]["child_count"], 0);
    assert!(first["records"][0]["children"]
        .as_array()
        .unwrap()
        .is_empty());

    let second = call(
        &registry,
        &db,
        "get_record",
        json!({
            "ids": [&target],
            "include_suggestions": true,
            "suggestions_limit": 100,
            "suggestions_offset": 100,
            "children_limit": 0,
        }),
    )
    .await;
    assert_eq!(
        second["records"][0]["suggestions"]
            .as_array()
            .unwrap()
            .len(),
        5
    );
    assert_eq!(second["records"][0]["child_count"], 0);
    assert_ne!(ordinary, target);
    let mut seen = first["records"][0]["suggestions"]
        .as_array()
        .unwrap()
        .iter()
        .chain(second["records"][0]["suggestions"].as_array().unwrap())
        .map(|item| item["id"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    seen.sort();
    authored.sort();
    assert_eq!(seen, authored);

    let error = call_err(
        &registry,
        &db,
        "get_record",
        json!({
            "ids": [&target],
            "include_suggestions": true,
            "suggestions_limit": 101,
        }),
    )
    .await;
    assert!(
        error.contains("suggestions limit must be <= 100"),
        "{error}"
    );
}

#[tokio::test]
async fn suggestions_are_hidden_by_default_but_explicitly_readable_with_counts() {
    let db = db().await;
    let registry = registry();
    let target = create(
        &registry,
        &db,
        json!({ "type": "Document", "name": "Visible target", "body": "before" }),
    )
    .await;
    let ordinary = create(
        &registry,
        &db,
        json!({ "type": "Document", "name": "Ordinary related record",
                "links": [{ "target_id": target, "relationship": "part_of" }] }),
    )
    .await;
    let hidden = suggestion(
        &registry,
        &db,
        SuggestionFixture {
            target: &target,
            name: "Hidden escrow phrase",
            replacement: "hidden replacement phrase",
            precondition: "span",
            old: Some("before"),
            base_digest: None,
        },
    )
    .await;
    let alias_id = native_ce::meta::propose_value_with_kind_metadata_as(
        &db,
        "kind:Annotation",
        "edit_suggestion",
        None,
        0.0,
        VocabularyValueTerminality::Open,
        Some(KindMetadataV1::legacy("Annotation", "edit_suggestion")),
        None,
    )
    .await
    .unwrap();
    native_ce::meta::promote_value(&db, &alias_id)
        .await
        .unwrap();
    native_ce::meta::alias_value(&db, &alias_id, CoreKind::AnnotationSuggestion.value_id())
        .await
        .unwrap();
    // Imported history can retain the old spelling; supported writes now
    // canonicalise it, so use the event seam to model that historical row.
    let alias_hidden = native_ce::store::create_record(
        &db,
        json!({
            "type": "Annotation",
            "kind": "edit_suggestion",
            "name": "Hidden escrow phrase through alias",
            "lifecycle": "open"
        }),
    )
    .await
    .unwrap();
    native_ce::store::add_link(
        &db,
        native_ce::events::LinkAddedPayload {
            id: None,
            source_id: alias_hidden.clone(),
            target_id: target.clone(),
            relationship: "part_of".into(),
            note: None,
        },
    )
    .await
    .unwrap();

    let default_get = call(&registry, &db, "get_record", json!({ "ids": [&target] })).await;
    let record = &default_get["records"][0];
    assert_eq!(record["child_count"], 0);
    assert_eq!(record["suggestion_count"], 2);
    assert!(record["children"].as_array().unwrap().is_empty());
    assert_ne!(ordinary, hidden);
    assert!(record.get("suggestions").is_none());

    let explicit_get = call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": [&target], "include_suggestions": true }),
    )
    .await;
    let explicit_ids = explicit_get["records"][0]["suggestions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["id"].as_str().unwrap())
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(
        explicit_ids,
        std::collections::HashSet::from([hidden.as_str(), alias_hidden.as_str()])
    );
    assert_eq!(explicit_get["records"][0]["child_count"], 0);

    let tree = call(
        &registry,
        &db,
        "get_structure",
        json!({ "root_id": &target, "max_depth": 1 }),
    )
    .await;
    assert!(tree["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .all(|node| node["id"] != hidden && node["id"] != alias_hidden));
    assert_eq!(tree["nodes"][0]["child_count"], 0);

    let search = call(
        &registry,
        &db,
        "search",
        json!({ "query": "hidden escrow phrase" }),
    )
    .await;
    assert!(search["hits"].as_array().unwrap().is_empty());
    assert!(
        !search.to_string().contains(&hidden),
        "near-miss prefix/infix/sibling paths must not leak suggestions"
    );

    let dashboard = call(&registry, &db, "get_dashboard", json!({})).await;
    assert!(!dashboard.to_string().contains(&hidden));

    let scan = call(&registry, &db, "scan", json!({ "query": "hidden" })).await;
    assert!(!scan.to_string().contains(&hidden));

    let default_query = call(
        &registry,
        &db,
        "query_record",
        json!({ "steps": [{ "step": "filter", "home_id": native_ce::schema::UNFILED_RECORD_ID }] }),
    )
    .await;
    assert!(default_query["records"]
        .as_array()
        .unwrap()
        .iter()
        .all(|row| row["id"] != hidden && row["id"] != alias_hidden));
    let traversed = call(
        &registry,
        &db,
        "query_record",
        json!({
            "steps": [
                { "step": "filter", "name_contains": "Visible target" },
                { "step": "traverse", "target": "children" }
            ]
        }),
    )
    .await;
    assert!(traversed["records"]
        .as_array()
        .unwrap()
        .iter()
        .all(|row| row["id"] != hidden && row["id"] != alias_hidden));
    let explicit_query = call(
        &registry,
        &db,
        "query_record",
        json!({ "steps": [{ "step": "filter", "home_id": native_ce::schema::UNFILED_RECORD_ID, "kinds": ["suggestion"] }] }),
    )
    .await;
    assert_eq!(explicit_query["total"], 2);
    assert!(explicit_query["records"]
        .as_array()
        .unwrap()
        .iter()
        .any(|row| row["id"] == alias_hidden));

    let explicit_then_lifecycle = call(
        &registry,
        &db,
        "query_record",
        json!({
            "steps": [
                { "step": "filter", "kinds": ["suggestion"] },
                { "step": "filter", "lifecycle": ["open"] }
            ]
        }),
    )
    .await;
    assert_eq!(explicit_then_lifecycle["total"], 2);

    let ancestor_and_explicit = call(
        &registry,
        &db,
        "query_record",
        json!({
            "steps": [{
                "step": "filter",
                "ancestor_id": &target,
                "kinds": ["suggestion"]
            }]
        }),
    )
    .await;
    assert_eq!(ancestor_and_explicit["total"], 0);

    let traverse_then_explicit = call(
        &registry,
        &db,
        "query_record",
        json!({
            "steps": [
                { "step": "filter", "name_contains": "Visible target" },
                { "step": "traverse", "target": "links", "relationship": "part_of", "direction": "in" },
                { "step": "filter", "kinds": ["suggestion"] }
            ]
        }),
    )
    .await;
    assert_eq!(traverse_then_explicit["total"], 2);

    let explicit_alias_query = call(
        &registry,
        &db,
        "query_record",
        json!({ "steps": [{ "step": "filter", "home_id": native_ce::schema::UNFILED_RECORD_ID, "kinds": ["edit_suggestion"] }] }),
    )
    .await;
    assert_eq!(explicit_alias_query["total"], 2);

    let review = call(
        &registry,
        &db,
        "render_suggestion_review",
        json!({ "record_id": &target }),
    )
    .await;
    assert_eq!(review["suggestion_count"], 2);
}
