//! The write-path contract break (spec fbfaf25 §3): required `reason` on the
//! twelve reason-bearing mutation tools, a populated `actor`, a run key on every
//! tool — required
//! in the schema since ecc586d, though gated on nowhere — key issuance on
//! `bootstrap`/`quickstart` and via the `"new"` sentinel, and the echo after
//! either issuer.
//!
//! The two done-when assertions the vehicle task specifies are
//! [`no_write_tool_is_callable_without_a_reason`] and
//! [`actor_is_populated_on_every_event_a_write_tool_appends`]; everything else
//! here guards a property that would otherwise be enforced only by reading the
//! code.

use native_ce::mcp::{register_surface_tools, Caller, ToolKind, ToolRegistry};
use native_ce::runkey::{validate, KeyOutcome};
use native_ce::{create_database, Db};
use serde_json::{json, Value};

/// Valid by construction: `scout` is a handle, `chair` a disambiguator, and
/// `a748b2` a lowercase Crockford Base32 run id.
const RUN: &str = "scout-chair-a748b2";

/// The twelve public mutation tools that require durable rationale (§3.1).
const REASON_REQUIRED: [&str; 12] = [
    "create_record",
    "create_many",
    // A composite authoring act is still an authoring act. `create_exploration`
    // mints a collection and every candidate in it, so it sits on the durable
    // authored-change side of the line, not the mechanics side.
    "create_exploration",
    "update_record",
    "claim_unowned_record",
    "correct_record_type",
    "archive_record",
    "delete_record",
    "manage_citations",
    "resolve_suggestions",
    "observe_external",
    "resolve_external",
];

async fn db() -> Db {
    create_database(":memory:").await.unwrap()
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

async fn seed(registry: &ToolRegistry, db: &Db) -> String {
    call(
        registry,
        db,
        "create_record",
        json!({ "type": "WorkItem", "kind": "task", "name": "subject", "reason": "Seed for a write-path test." }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_string()
}

/// One otherwise-valid call for every reason-required tool. Keeping the
/// missing- and blank-reason tests on this shared matrix prevents either
/// runtime contract from silently covering fewer tools than the schema audit.
fn reason_required_calls(record_id: &str) -> [(&'static str, Value); 12] {
    let external_binding = json!({
        "system": "native-principal",
        "identifier": "native/write-path-reason-contract"
    });
    let external_hints = json!({
        "record_type": "Entity",
        "kind": "person",
        "name": "Write-path reason contract"
    });
    [
        (
            "create_exploration",
            json!({
                "exploration": { "create": { "name": "Reason contract exploration" } },
                "candidates": [{ "type": "Document", "kind": "note", "name": "A", "body": "a" }]
            }),
        ),
        (
            "create_record",
            json!({ "type": "Document", "kind": "note", "name": "x" }),
        ),
        (
            "create_many",
            json!({
                "records": [{ "type": "Document", "kind": "note", "name": "x" }]
            }),
        ),
        ("update_record", json!({ "id": record_id, "summary": "x" })),
        ("claim_unowned_record", json!({ "record_id": record_id })),
        (
            "correct_record_type",
            json!({
                "record_id": record_id,
                "target_type": "Document",
                "target_kind": "note"
            }),
        ),
        ("archive_record", json!({ "id": record_id })),
        ("delete_record", json!({ "id": record_id })),
        (
            "manage_citations",
            json!({ "action": "remove", "citation_id": "rec_missing" }),
        ),
        (
            "resolve_suggestions",
            json!({ "action": "accept", "suggestion_ids": ["rec_missing"] }),
        ),
        (
            "observe_external",
            json!({
                "bindings": [external_binding.clone()],
                "source_binding": external_binding.clone(),
                "hints": external_hints.clone(),
                "quality": "reported",
                "materialization_policy": "identity_only",
                "provenance": {
                    "freshness": "unknown",
                    "retention_state": "none",
                    "source_availability": "unknown",
                    "refresh_outcome": "not_attempted"
                }
            }),
        ),
        (
            "resolve_external",
            json!({
                "bindings": [external_binding],
                "hints": external_hints
            }),
        ),
    ]
}

// ---------------------------------------------------------------------------
// `reason` — required, and on exactly twelve tools
// ---------------------------------------------------------------------------

/// Done-when 1: no write tool is callable without a `reason`.
///
/// Asserted through the registry rather than by inspecting the schema, because a
/// schema is advertising and this is enforcement — a caller that ignores the
/// advertised `required` must still be refused.
#[tokio::test]
async fn no_write_tool_is_callable_without_a_reason() {
    let db = db().await;
    let registry = registry();
    let id = seed(&registry, &db).await;

    for (tool, args) in reason_required_calls(&id) {
        let err = call_err(&registry, &db, tool, args).await;
        assert!(
            err.contains("missing field `reason`"),
            "{tool} was callable without a reason: {err}"
        );
    }
    db.close().await;
}

/// All twelve tools ADVERTISE it as required, and the description asks for the
/// reasoning rather than the record.
///
/// The wording is the feature, not decoration: a vague prompt gets filled with a
/// restatement of the title, and the failure would then be in the question rather
/// than in the fill rate. So the test pins that the field asks about
/// alternatives and argument, and explicitly rules out restatement.
#[tokio::test]
async fn the_reason_field_asks_for_reasoning_not_a_restatement() {
    let registry = registry();
    for tool in REASON_REQUIRED {
        let schema = &registry.get(tool).expect("registered").input_schema;
        let required: Vec<&str> = schema["required"]
            .as_array()
            .expect("required list")
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(
            required.contains(&"reason"),
            "{tool} does not require reason"
        );

        let description = schema["properties"]["reason"]["description"]
            .as_str()
            .unwrap_or_else(|| panic!("{tool}: reason has no description"));
        for phrase in ["alternatives", "arguing against", "not an answer"] {
            assert!(
                description.contains(phrase),
                "{tool}: the reason description must ask for the reasoning — missing '{phrase}' in: {description}"
            );
        }
    }
}

/// And on EXACTLY those twelve. The line is durable authored or governed change
/// versus mechanics: links and lifecycle transitions usually execute a choice
/// captured elsewhere, while external resolution and observation make durable
/// identity/provenance claims of their own. Mandatory prose on the remaining
/// mechanics would produce noise.
#[tokio::test]
async fn exactly_twelve_tools_require_a_reason() {
    let registry = registry();
    let mut actual = Vec::new();
    for spec in registry.specs() {
        let required = spec.input_schema["required"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        if required.iter().any(|v| v == "reason") {
            actual.push(spec.name.as_str());
        }
    }
    actual.sort_unstable();
    let mut expected = REASON_REQUIRED.to_vec();
    expected.sort_unstable();
    assert_eq!(
        actual, expected,
        "the exactly-twelve reason/mechanics boundary moved"
    );
}

/// Runtime enforcement is independent of JSON Schema: empty and whitespace-only
/// strings must fail before any of the twelve handlers mutates authoritative or
/// audit state.
#[tokio::test]
async fn blank_reasons_are_rejected_before_mutation_on_all_twelve_tools() {
    let db = db().await;
    let registry = registry();
    let id = seed(&registry, &db).await;
    let before: (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM content_events),
                (SELECT COUNT(*) FROM binding_audit),
                (SELECT COUNT(*) FROM external_observations)",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();

    for blank in ["", "   \t\n"] {
        for (tool, mut args) in reason_required_calls(&id) {
            args.as_object_mut()
                .expect("reason-required call arguments are objects")
                .insert("reason".into(), blank.into());
            let err = call_err(&registry, &db, tool, args).await;
            assert!(
                err.contains("reason") && err.contains("non-whitespace"),
                "{tool} accepted {blank:?}: {err}"
            );
        }
    }
    let after: (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM content_events),
                (SELECT COUNT(*) FROM binding_audit),
                (SELECT COUNT(*) FROM external_observations)",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(
        after, before,
        "a blank-reason call mutated content, binding audit, or observation state"
    );
    db.close().await;
}

/// `reason` is PAYLOAD, not a column: it rides in the event JSON, which is why
/// this whole break needs no DDL of its own. The projector reads `records`
/// columns from an explicit allowlist, so the prose is inert to the fold.
#[tokio::test]
async fn the_reason_lands_in_the_event_payload_and_not_in_a_column() {
    let db = db().await;
    let registry = registry();
    let reason = "Chose a Task over a Document because the thing has an owner and an end.";
    let id = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "WorkItem", "kind": "task", "name": "subject", "reason": reason }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_string();

    let payload = crate::common::text_of(
        &db,
        "SELECT payload FROM content_events
         WHERE type = 'record.created' AND actor <> 'engine:seed' ORDER BY seq LIMIT 1",
        "payload",
    )
    .await
    .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&payload).unwrap()["reason"],
        reason
    );

    // No column anywhere holds it, and the record is unpolluted.
    let columns = sqlx::query_scalar::<_, String>("SELECT name FROM pragma_table_info('records')")
        .fetch_all(db.pool())
        .await
        .unwrap();
    assert!(
        !columns.iter().any(|c| c == "reason"),
        "reason became a column: structural correlation keys are columns, prose is payload"
    );

    // And the fold ignores it — a stray key in a create payload must not appear
    // in the projection or break replay.
    let rebuilt = native_ce::conformance::rebuild_and_diff(&db).await.unwrap();
    assert!(
        rebuilt.equal,
        "a reason in the payload broke rebuild-and-diff"
    );
    let _ = id;
    db.close().await;
}

/// A facet-only update still records its reason. It emits no `record.updated`,
/// so attaching the prose there unconditionally would silently drop a field the
/// caller was REQUIRED to supply — the quiet failure worth a test.
#[tokio::test]
async fn a_facet_only_update_still_records_its_reason() {
    let db = db().await;
    let registry = registry();
    let id = seed(&registry, &db).await;
    let reason = "Downgraded confidence: the source turned out to be a draft.";

    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": id, "facets": { "confidence": "low" }, "reason": reason }),
    )
    .await;

    let payload = crate::common::text_of(
        &db,
        "SELECT payload FROM content_events WHERE type = 'facet.set' ORDER BY seq DESC LIMIT 1",
        "payload",
    )
    .await
    .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&payload).unwrap()["reason"],
        reason,
        "a facet-only update dropped the reason it required"
    );
    db.close().await;
}

// ---------------------------------------------------------------------------
// `actor`
// ---------------------------------------------------------------------------

/// Done-when 2: `content_events.actor` is populated rather than NULL.
#[tokio::test]
async fn actor_is_populated_on_every_event_a_write_tool_appends() {
    let db = db().await;
    let registry = registry();
    let id = seed(&registry, &db).await;
    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": id, "summary": "s", "reason": "r" }),
    )
    .await;
    call(
        &registry,
        &db,
        "archive_record",
        json!({ "id": id, "reason": "r" }),
    )
    .await;
    call(
        &registry,
        &db,
        "delete_record",
        json!({ "id": id, "reason": "r" }),
    )
    .await;

    let actors =
        sqlx::query_scalar::<_, Option<String>>("SELECT actor FROM content_events ORDER BY seq")
            .fetch_all(db.pool())
            .await
            .unwrap();
    assert!(!actors.is_empty());
    assert!(
        actors.iter().all(Option::is_some),
        "actor is NULL on some event: {actors:?}"
    );
    db.close().await;
}

/// `actor` is always the authenticated credential. Run identity remains in the
/// adjacent full `run_key` on both durable and disposable event envelopes.
#[tokio::test]
async fn actor_is_the_credential_with_or_without_a_run_key() {
    let db = db().await;
    let registry = registry();

    call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "WorkItem", "kind": "task", "name": "keyed", "reason": "r", "run_key": RUN }),
    )
    .await;
    call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "WorkItem", "kind": "task", "name": "unkeyed", "reason": "r" }),
    )
    .await;

    let actors = sqlx::query_scalar::<_, String>(
        "SELECT actor FROM content_events WHERE actor <> 'engine:seed' ORDER BY seq",
    )
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(actors, ["local", "local"]);

    let calls = sqlx::query_as::<_, (String, Option<String>)>(
        "SELECT actor, run_key FROM read_log_calls ORDER BY seq",
    )
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(
        calls,
        [("local".into(), Some(RUN.into())), ("local".into(), None)],
        "read-log attribution follows the same account + run product shape"
    );
    db.close().await;
}

/// The permanent content log receives the validated context from the real
/// registry write path. The lineage tests' direct SQL inserts are not enough:
/// without this integration assertion the annotation columns can exist forever
/// while every production append leaves them NULL.
#[tokio::test]
async fn a_registry_write_stamps_run_and_parent_context_on_content_events() {
    let db = db().await;
    let registry = registry();
    let parent = "heron-river-c748b2";
    let id = call(
        &registry,
        &db,
        "create_record",
        json!({
            "type": "WorkItem",
            "kind": "task",
            "name": "annotated",
            "reason": "Prove the real append path carries its caller context.",
            "run_key": RUN,
            "parent_key": parent,
        }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_string();

    let row =
        sqlx::query("SELECT run_key, parent_key, intent FROM content_events WHERE record_id = ?")
            .bind(&id)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(
        sqlx::Row::try_get::<Option<String>, _>(&row, "run_key")
            .unwrap()
            .as_deref(),
        Some(RUN)
    );
    assert_eq!(
        sqlx::Row::try_get::<Option<String>, _>(&row, "parent_key")
            .unwrap()
            .as_deref(),
        Some(parent)
    );
    assert_eq!(
        sqlx::Row::try_get::<Option<String>, _>(&row, "intent").unwrap(),
        None,
        "without a successful declaration there is no intent to copy forward"
    );

    let history = call(
        &registry,
        &db,
        "get_history",
        json!({ "record_id": id, "run_key": RUN }),
    )
    .await;
    assert_eq!(history["events"][0]["run_key"], RUN);
    assert_eq!(history["events"][0]["parent_key"], parent);
    assert_eq!(history["events"][0]["intent"], Value::Null);
    db.close().await;
}

/// The current exact-run intent is both echoed and copied to later permanent
/// events; deleting the attention tier afterward cannot erase that annotation.
#[tokio::test]
async fn response_intent_is_echoed_and_copied_to_later_events() {
    let db = db().await;
    let registry = registry();
    let intent = "Review the permanent write-path intent boundary.";
    sqlx::query(
        "INSERT INTO read_log_calls \
         (id, tool, run_key, intent, outcome, started_at, ended_at) \
         VALUES ('intent-fixture', 'set_intent', ?, ?, 'ok', \
                 '2026-07-30T18:00:00Z', '2026-07-30T18:00:01Z')",
    )
    .bind(RUN)
    .bind(intent)
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();

    let response = call(
        &registry,
        &db,
        "create_record",
        json!({
            "type": "WorkItem",
            "kind": "task",
            "name": "intent boundary",
            "reason": "Prove exact-run intent copy-forward at the permanent event boundary.",
            "run_key": RUN,
        }),
    )
    .await;
    assert_eq!(response["run_context"]["intent"], intent);

    let stored: Option<String> =
        sqlx::query_scalar("SELECT intent FROM content_events WHERE record_id = ?")
            .bind(response["id"].as_str().unwrap())
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(stored.as_deref(), Some(intent));

    sqlx::query("DELETE FROM read_log_calls")
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    let durable: Option<String> =
        sqlx::query_scalar("SELECT intent FROM content_events WHERE record_id = ?")
            .bind(response["id"].as_str().unwrap())
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(durable.as_deref(), Some(intent));
    db.close().await;
}

// ---------------------------------------------------------------------------
// Run keys — accepted by every run-participating tool, validated for shape
// only, fail-open
// ---------------------------------------------------------------------------

/// Correlation has to be on every participating call or it is not correlation,
/// so BOTH arguments are advertised by every run-participating tool. QuickStart
/// is the explicit static-launcher exception: it neither accepts nor
/// participates in run context.
#[tokio::test]
async fn every_tool_advertises_run_key_and_parent_key() {
    let registry = registry();
    let mut checked = 0;
    for spec in registry.specs() {
        if spec
            .kind
            .is_some_and(ToolKind::ignores_run_context_arguments)
        {
            for arg in ["run_key", "parent_key"] {
                assert!(
                    spec.input_schema["properties"].get(arg).is_none(),
                    "{} must not advertise {arg}",
                    spec.name
                );
            }
            checked += 1;
            continue;
        }
        for arg in ["run_key", "parent_key"] {
            assert!(
                spec.input_schema["properties"][arg].is_object(),
                "{} does not advertise {arg} — correlation on some calls is not correlation",
                spec.name
            );
        }
        checked += 1;
    }
    assert!(checked >= 26, "expected the full surface, saw {checked}");
}

/// Shape and membership, never liveness. A key the server has never seen is
/// accepted, because a key becomes real by being used — it is a hashtag, not a
/// session token, and correlation does not need authority.
#[tokio::test]
async fn an_invented_key_the_server_has_never_seen_is_accepted() {
    assert_eq!(
        validate(Some("heron-river-c748b2")),
        KeyOutcome::Valid("heron-river-c748b2".into())
    );
    let db = db().await;
    let registry = registry();
    let out = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "WorkItem", "kind": "task", "name": "x", "reason": "r", "run_key": "heron-river-c748b2" }),
    )
    .await;
    assert_eq!(out["run_context"]["run_key"], "heron-river-c748b2");
    db.close().await;
}

/// FAIL-OPEN, the invariant. A malformed key is recorded as null and the call
/// still succeeds — rejecting it would make the read log the reason a tool
/// fails, which is the outcome fail-open exists to prevent.
#[tokio::test]
async fn a_malformed_key_never_fails_the_call() {
    let db = db().await;
    let registry = registry();

    for bad in [
        "not a legal key",
        "scout-chair",
        "scout-chair-a748b2-extra",
        "notalabel-chair-a748b2",
        "scout-notaword-a748b2",
        "",
    ] {
        let out = call(
            &registry,
            &db,
            "query_record",
            json!({ "steps": [{ "step": "filter", "types": ["WorkItem"] }] , "run_key": bad }),
        )
        .await;
        assert_eq!(
            out["run_context"]["run_key"],
            Value::Null,
            "malformed key '{bad}' was recorded rather than nulled"
        );
    }

    // And on a WRITE, where the stakes are higher: the event lands, with a null
    // key and the credential as actor.
    let out = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "WorkItem", "kind": "task", "name": "x", "reason": "r", "run_key": "scout-nonsense-a748b2" }),
    )
    .await;
    assert!(out["id"].is_string(), "a bad key failed a write");
    let actor = sqlx::query_scalar::<_, Option<String>>(
        "SELECT actor FROM content_events WHERE actor <> 'engine:seed' ORDER BY seq",
    )
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(actor[0].as_deref(), Some("local"));
    db.close().await;
}

/// The future capture wrapper receives the caller's exact JSON, while handlers
/// receive a stripped clone. This pins non-string values as values rather than
/// their lossy/stringified display forms.
#[tokio::test]
async fn malformed_raw_context_is_preserved_exactly_for_capture() {
    let db = db().await;
    let registry = registry();
    let original = json!({
        "steps": [{ "step": "filter", "types": ["WorkItem"] }],
        "run_key": { "raw": ["not", "a", "string"] },
        "parent_key": [1, true, null],
    });
    let detailed = registry
        .call_detailed(
            db.clone(),
            Caller::local(),
            "query_record",
            original.clone(),
        )
        .await
        .unwrap();
    assert_eq!(detailed.original_arguments, original);
    assert!(
        detailed.outcome.is_ok(),
        "malformed correlation must fail open"
    );
    assert_eq!(detailed.run_context["run_key"], Value::Null);
    let notes = detailed.run_context["notes"].as_array().unwrap();
    assert!(
        notes.iter().any(|note| note
            .as_str()
            .is_some_and(|text| text.contains("expected a string"))),
        "non-string repair feedback missing: {notes:?}"
    );

    let explicit_null = json!({
        "steps": [{ "step": "filter", "types": ["WorkItem"] }],
        "run_key": null,
    });
    let null_outcome = registry
        .call_detailed(
            db.clone(),
            Caller::local(),
            "query_record",
            explicit_null.clone(),
        )
        .await
        .unwrap();
    assert_eq!(null_outcome.original_arguments, explicit_null);
    assert_eq!(null_outcome.run_context["run_key"], Value::Null);
    assert!(null_outcome.run_context["notes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|note| note
            .as_str()
            .is_some_and(|text| text.contains("expected a string, got null"))));
    db.close().await;
}

#[tokio::test]
async fn supplied_whitespace_variants_are_malformed_not_absent_or_normalized() {
    let db = db().await;
    let registry = registry();
    for raw in ["", "   ", " scout-chair-a748b2", "scout-chair-a748b2 "] {
        let detailed = registry
            .call_detailed(
                db.clone(),
                Caller::local(),
                "query_record",
                json!({
                    "steps": [{ "step": "filter", "types": ["WorkItem"] }],
                    "run_key": raw,
                }),
            )
            .await
            .unwrap();
        assert!(detailed.outcome.is_ok(), "{raw:?} failed the call");
        assert_eq!(detailed.run_context["run_key"], Value::Null);
        let notes = detailed.run_context["notes"].as_array().unwrap();
        assert!(
            notes
                .iter()
                .any(|note| note.as_str().is_some_and(|text| text.contains(raw))),
            "raw value {raw:?} was not represented in repair feedback: {notes:?}"
        );
    }
    db.close().await;
}

/// The distance floor buys CORRECTION, not merely rejection: a single-character
/// garble has exactly one nearest valid word, so a mistyped key comes back with
/// the key it meant.
#[tokio::test]
async fn a_single_character_garble_is_repaired_rather_than_merely_rejected() {
    // A transposition, which is among the commonest garbles and the reason the
    // metric is Damerau rather than plain Levenshtein.
    let outcome = validate(Some("scout-chiar-a748b2"));
    let KeyOutcome::Malformed { suggestion, .. } = &outcome else {
        panic!("expected a malformed outcome, got {outcome:?}");
    };
    assert_eq!(suggestion.as_deref(), Some("scout-chair-a748b2"));

    // Nonsense gets no confident guess — a wrong suggestion is worse than none.
    let outcome = validate(Some("scout-zzzzzzz-a748b2"));
    let KeyOutcome::Malformed { suggestion, .. } = &outcome else {
        panic!("expected a malformed outcome, got {outcome:?}");
    };
    assert_eq!(suggestion.as_deref(), None);
}

/// `run_key` is required in the SCHEMA and gated on NOWHERE — the two halves of
/// ecc586d, which amends fbfaf25 §3.2's position that it should not be required
/// at all.
///
/// Requiring is a capture decision, not a trust decision (33b4e59's own
/// carve-out), and this server has no schema validator: the required array
/// reaches the client and nothing else. So the forcing function lands at
/// call-construction time, where no harness can skip it, while an absent key
/// still resolves to null and still gets the nudge. §3.2's arguments 3 and 4
/// survive precisely because of that asymmetry.
///
/// `parent_key` stays optional, and the difference is not an oversight: a
/// lineage claim is an assertion about a run that already exists, so a caller
/// without a parent has nothing honest to put there. The sentinel has no
/// analogue on that side.
#[tokio::test]
async fn run_key_is_required_in_schema_but_parent_key_is_not() {
    let registry = registry();
    for spec in registry.specs() {
        let required = spec.input_schema["required"]
            .as_array()
            .cloned()
            .unwrap_or_default();

        // QuickStart is callable before Bootstrap but does not issue or
        // participate in run context, so it must advertise neither argument.
        if spec
            .kind
            .is_some_and(ToolKind::ignores_run_context_arguments)
        {
            assert!(
                !required.iter().any(|value| value == "run_key"),
                "{} must not require run_key",
                spec.name
            );
            for arg in ["run_key", "parent_key"] {
                assert!(
                    spec.input_schema["properties"].get(arg).is_none(),
                    "{} must not accept {arg}",
                    spec.name
                );
            }
            continue;
        }

        // Bootstrap is the sole issuer: requiring a key to call the tool that
        // provides it is a deadlock. It must still ACCEPT both arguments.
        let expected = !spec.kind.is_some_and(ToolKind::issues_run_key);
        assert_eq!(
            required.iter().any(|value| value == "run_key"),
            expected,
            "{} run_key requiredness",
            spec.name
        );
        assert!(
            spec.input_schema["properties"]["run_key"].is_object(),
            "{} must still accept run_key",
            spec.name
        );
        assert!(
            !required.iter().any(|value| value == "parent_key"),
            "{} requires parent_key — a lineage claim has no honest default",
            spec.name
        );
    }
}

/// The sentinel is what makes required-ness safe: it is always valid, it mints,
/// and the call still succeeds. Without this the amendment is fbfaf25 §3.2's
/// feared conversion of visible absence into invisible wrongness.
#[tokio::test]
async fn the_new_sentinel_mints_a_key_and_the_call_still_succeeds() {
    let db = db().await;
    let registry = registry();

    let out = call(
        &registry,
        &db,
        "describe_schema",
        json!({ "run_key": "new" }),
    )
    .await;
    let minted = out["run_context"]["run_key"].as_str().unwrap();

    // What came back is a real key, not the sentinel echoed.
    assert_ne!(minted, "new");
    assert!(matches!(validate(Some(minted)), KeyOutcome::Valid(_)));

    // And the caller is told to carry it, in band, without having had to know
    // `bootstrap` existed — the cold-agent onboarding path.
    let notes = out["run_context"]["notes"].to_string();
    assert!(
        notes.contains(minted),
        "the minted key must be handed back: {notes}"
    );

    // Reusing it is an ordinary valid key, and mints nothing further.
    let again = call(
        &registry,
        &db,
        "describe_schema",
        json!({ "run_key": minted }),
    )
    .await;
    assert_eq!(again["run_context"]["run_key"], json!(minted));

    // Absence still works — the schema asks, the server never insists.
    let absent = call(&registry, &db, "describe_schema", json!({})).await;
    assert_eq!(absent["run_context"]["run_key"], json!(null));
}

#[tokio::test]
async fn the_new_sentinel_is_not_valid_for_parent_key() {
    let db = db().await;
    let registry = registry();
    let original = json!({
        "run_key": RUN,
        "parent_key": "new",
    });

    let detailed = registry
        .call_detailed(
            db.clone(),
            Caller::local(),
            "describe_schema",
            original.clone(),
        )
        .await
        .unwrap();

    assert!(detailed.outcome.is_ok(), "malformed parent must fail open");
    assert_eq!(detailed.original_arguments, original);
    assert_eq!(detailed.run_context["run_key"], RUN);
    assert!(detailed.run_context.get("parent_key").is_none());
    let notes = detailed.run_context["notes"].as_array().unwrap();
    assert!(
        notes.iter().any(|note| note.as_str().is_some_and(|text| {
            text.contains("parent key 'new' was not recorded")
                && text.contains("parent_key does not support the 'new' sentinel")
        })),
        "parent sentinel repair feedback missing: {notes:?}"
    );

    db.close().await;
}

/// The schema's model-facing copy must push stable reuse even though the v1
/// validator remains fail-open. The rhetoric and the acceptance policy are
/// intentionally separate contracts.
#[test]
fn every_tool_advertises_required_stable_run_key_reuse_without_tolerance_copy() {
    let registry = registry();
    for spec in registry.specs() {
        if spec
            .kind
            .is_some_and(ToolKind::ignores_run_context_arguments)
        {
            assert!(
                spec.input_schema["properties"].get("run_key").is_none(),
                "{} must not advertise run_key reuse copy",
                spec.name
            );
            continue;
        }
        let description = spec.input_schema["properties"]["run_key"]["description"]
            .as_str()
            .unwrap();
        for required in [
            "Run correlation handle from bootstrap",
            "same key on every call",
            "reads included",
            "new:<agent_key>",
            "coordination guide",
        ] {
            assert!(
                description.contains(required),
                "{} is missing {required:?}: {description}",
                spec.name
            );
        }
        for forbidden in [
            "scout-jam-d748b2",
            "Optional correlation",
            "Never required",
            "malformed key never fails",
            "any legal key is accepted",
        ] {
            assert!(
                !description.contains(forbidden),
                "{} advertises tolerance via {forbidden:?}: {description}",
                spec.name
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Issuance and echo
// ---------------------------------------------------------------------------

/// Bootstrap is one fail-open minting point, and what it returns is legal.
#[tokio::test]
async fn bootstrap_mints_a_valid_key() {
    let db = db().await;
    let registry = registry();
    let out = call(&registry, &db, "bootstrap", json!({})).await;
    let run = out["run"].as_object().unwrap();
    let minted = run["run_key"].as_str().unwrap();
    assert!(
        !run.contains_key("suggested_run_key"),
        "the serialized run object must not frame the key as a suggestion: {run:?}"
    );
    assert!(
        matches!(validate(Some(minted)), KeyOutcome::Valid(_)),
        "bootstrap minted a key its own validator rejects: {minted}"
    );
    db.close().await;
}

/// A mid-run bootstrap must echo the existing key rather than invite the agent
/// to rotate it and fragment the run already in progress.
#[tokio::test]
async fn bootstrap_echoes_an_existing_key_rather_than_minting_a_rival() {
    let db = db().await;
    let registry = registry();
    let out = call(&registry, &db, "bootstrap", json!({ "run_key": RUN })).await;
    assert_eq!(out["run"]["run_key"], RUN);
    assert!(out["run"].get("suggested_run_key").is_none());
    db.close().await;
}

/// The echo rides on every post-bootstrap response, reads included — forgetting is mostly a
/// compaction failure, and a key that appears only in the first result of a long
/// run is the likeliest thing to be summarised away.
#[tokio::test]
async fn every_post_bootstrap_response_echoes_the_key_in_force() {
    let db = db().await;
    let registry = registry();
    let id = seed(&registry, &db).await;

    for (tool, args) in [
        ("get_record", json!({ "ids": [&id], "run_key": RUN })),
        (
            "query_record",
            json!({ "steps": [{ "step": "filter", "types": ["WorkItem"] }] , "run_key": RUN }),
        ),
        ("search", json!({ "query": "subject", "run_key": RUN })),
        ("get_structure", json!({ "root_id": &id, "run_key": RUN })),
        (
            "update_record",
            json!({ "id": &id, "summary": "s", "reason": "r", "run_key": RUN }),
        ),
    ] {
        let out = call(&registry, &db, tool, args).await;
        assert_eq!(
            out["run_context"]["run_key"], RUN,
            "{tool} did not echo the key in force"
        );
        assert!(
            out["run_context"].get("intent").is_some(),
            "{tool} did not echo the intent slot"
        );
    }
    db.close().await;
}

/// With no key, the echo becomes the NUDGE. That is the whole cover for an agent
/// that never calls bootstrap — weaker than minting one for it, and deliberately
/// so, since identity belongs on the identity call.
#[tokio::test]
async fn the_echo_becomes_a_nudge_when_there_is_no_key() {
    let db = db().await;
    let registry = registry();
    let out = call(
        &registry,
        &db,
        "query_record",
        json!({ "steps": [{ "step": "filter", "types": ["WorkItem"] }] }),
    )
    .await;
    assert_eq!(out["run_context"]["run_key"], Value::Null);
    let notes = out["run_context"]["notes"].as_array().unwrap();
    assert!(
        notes
            .iter()
            .any(|n| n.as_str().unwrap().contains("bootstrap")),
        "the absent-key echo must say what to do about it: {notes:?}"
    );
    db.close().await;
}

/// A malformed key gets a repair note on the response, not an error — the loud
/// failure arrives with a suggested fix rather than a dead end.
#[tokio::test]
async fn a_malformed_key_returns_a_repair_note_on_the_response() {
    let db = db().await;
    let registry = registry();
    let out = call(
        &registry,
        &db,
        "query_record",
        json!({ "steps": [{ "step": "filter", "types": ["WorkItem"] }] , "run_key": "scout-chiar-a748b2" }),
    )
    .await;
    let notes = out["run_context"]["notes"].as_array().unwrap();
    let joined = notes
        .iter()
        .map(|n| n.as_str().unwrap())
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        joined.contains("scout-chair-a748b2"),
        "no repair offered: {joined}"
    );
    assert!(
        joined.contains("every subsequent call"),
        "the note must tell the caller how to resume correlation: {joined}"
    );
    assert!(!joined.contains("succeeded regardless"), "{joined}");
    db.close().await;
}

/// `parent_key` gets the same treatment and the same absence of verification —
/// an unverifiable assertion by the child about its parent, licensed by there
/// being no adversary here: one user, one credential, one file.
#[tokio::test]
async fn parent_key_is_accepted_unverified_and_echoed() {
    let db = db().await;
    let registry = registry();
    let out = call(
        &registry,
        &db,
        "query_record",
        json!({ "steps": [{ "step": "filter", "types": ["WorkItem"] }] , "run_key": RUN, "parent_key": "heron-river-c748b2" }),
    )
    .await;
    assert_eq!(out["run_context"]["parent_key"], "heron-river-c748b2");
    db.close().await;
}
