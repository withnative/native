use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::meta::{
    create_vocabulary, promote_value, propose_value_with_metadata_as, write_user_schema_config,
    SchemaConfigOptions, VocabularyValueTerminality,
};
use native_ce::{create_database, Db};
use serde_json::{json, Value};
use sqlx::Row;

const RUN: &str = "scout-chair-a748b2";
const OTHER_RUN: &str = "scout-chair-b748b2";

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

async fn call(registry: &ToolRegistry, db: &Db, tool: &str, arguments: Value) -> Value {
    sqlx::query(
        "INSERT OR IGNORE INTO records
            (id, type, kind, name, home_id, policy_anchor_id, persistence)
         VALUES ('test:acct-person', 'Entity', 'person', 'Test account',
                 ?, ?, 'enduring')",
    )
    .bind(native_ce::schema::UNFILED_RECORD_ID)
    .bind(native_ce::schema::ROOT_RECORD_ID)
    .execute(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap();
    sqlx::query(
        "INSERT OR IGNORE INTO bindings
            (record_id, system, identifier, is_canonical)
         VALUES ('test:acct-person', 'account', 'acct:test', 1)",
    )
    .execute(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap();
    let result = registry
        .call(
            db.clone(),
            Caller::authenticated("acct:test"),
            tool,
            crate::common::with_test_reason(tool, arguments),
        )
        .await
        .unwrap();
    // Captures run on the handle's background queue; later assertions read
    // them back, so drain each sequential call. `set_intent` declarations
    // are additionally synchronous by construction (see the
    // `set_intent_declaration_is_durable_before_response` unit test), which
    // this drain does not mask — it only settles ordinary captures.
    db.drain_captures_for_tests().await;
    result
}

#[tokio::test]
async fn set_intent_echoes_and_includes_its_pending_declaration_without_touches() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let intent = "Review the bounded briefing without exposing trace content.";

    let result = call(
        &registry,
        &db,
        "set_intent",
        json!({ "intent": intent, "run_key": RUN }),
    )
    .await;

    assert_eq!(result["accepted_intent"], intent);
    // v2: a declaration's `touched_records` now folds DECLARED sources rather
    // than touched records, so the response family version moved.
    assert_eq!(result["briefing_version"], 2);
    assert_eq!(result["run_context"]["intent"], intent);
    assert_eq!(result["briefing"]["resume"], Value::Null);
    assert!(result["briefing"].get("divergence").is_none());
    let declarations = &result["briefing"]["this_run"]["declarations"];
    assert_eq!(declarations["total_count"], 1);
    assert_eq!(declarations["truncated"], false);
    assert_eq!(declarations["items"][0]["intent"], intent);
    assert_eq!(
        declarations["items"][0]["touched_records"]["items"],
        json!([])
    );

    let row = sqlx::query("SELECT intent, arguments FROM read_log_calls WHERE tool = 'set_intent'")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(row.get::<String, _>("intent"), intent);
    let arguments: Value = serde_json::from_str(&row.get::<String, _>("arguments")).unwrap();
    assert_eq!(arguments["run_key"], RUN);
    let touches: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM read_log_touches t
          JOIN read_log_calls c ON c.seq = t.call_seq
         WHERE c.tool = 'set_intent'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(touches, 0);

    let schema = &registry.get("set_intent").unwrap().input_schema;
    assert!(schema["required"]
        .as_array()
        .unwrap()
        .contains(&json!("intent")));
    assert!(schema["required"]
        .as_array()
        .unwrap()
        .contains(&json!("run_key")));
}

#[tokio::test]
async fn successful_intent_admits_one_stable_caller_bound_activity() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();

    call(
        &registry,
        &db,
        "set_intent",
        json!({ "intent": "Admit durable activity.", "run_key": RUN }),
    )
    .await;
    let first: (String, String, String, Option<String>) = sqlx::query_as(
        "SELECT activity_id,run_key,account_id,ended_at FROM agent_runs WHERE run_key=?",
    )
    .bind(RUN)
    .fetch_one(db.pool())
    .await
    .unwrap();

    call(
        &registry,
        &db,
        "set_intent",
        json!({ "intent": "A safe retry.", "run_key": RUN }),
    )
    .await;
    let second: (String, i64) = sqlx::query_as(
        "SELECT activity_id,(SELECT count(*) FROM agent_runs WHERE run_key=?) FROM agent_runs WHERE run_key=?",
    )
    .bind(RUN)
    .bind(RUN)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(second, (first.0.clone(), 1));
    assert_eq!(first.1, RUN);
    assert_eq!(first.2, "acct:test");
    assert_eq!(first.3, None);

    sqlx::query("DELETE FROM read_log_calls")
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    let after_transient_loss: (String, Option<String>) =
        sqlx::query_as("SELECT activity_id,ended_at FROM agent_runs WHERE run_key=?")
            .bind(RUN)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(after_transient_loss, (first.0.clone(), None));

    let rejected = registry
        .call_detailed(
            db.clone(),
            Caller::authenticated("acct:test"),
            "set_intent",
            json!({ "intent": "Invalid declaration.", "unknown": true, "run_key": OTHER_RUN }),
        )
        .await
        .unwrap();
    assert!(rejected.outcome.is_err());
    let rejected_count: i64 = sqlx::query_scalar("SELECT count(*) FROM agent_runs WHERE run_key=?")
        .bind(OTHER_RUN)
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(rejected_count, 0);

    let collision = registry
        .call_detailed(
            db.clone(),
            Caller::authenticated("acct:other"),
            "set_intent",
            json!({ "intent": "Must not steal the run.", "run_key": RUN }),
        )
        .await
        .unwrap();
    assert!(collision.outcome.is_err());
    let binding: String = sqlx::query_scalar("SELECT account_id FROM agent_runs WHERE run_key=?")
        .bind(RUN)
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(binding, "acct:test");
}

#[tokio::test]
async fn close_run_is_explicit_caller_bound_and_idempotent() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    call(
        &registry,
        &db,
        "set_intent",
        json!({ "intent": "Close only when requested.", "run_key": RUN }),
    )
    .await;

    let wrong_caller = registry
        .call_detailed(
            db.clone(),
            Caller::authenticated("acct:other"),
            "close_run",
            json!({ "run_key": RUN }),
        )
        .await
        .unwrap();
    assert!(wrong_caller.outcome.is_err());
    let still_open: Option<String> =
        sqlx::query_scalar("SELECT ended_at FROM agent_runs WHERE run_key=?")
            .bind(RUN)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(still_open, None);

    let first = call(&registry, &db, "close_run", json!({ "run_key": RUN })).await;
    assert_eq!(first["changed"], true);
    assert!(first["ended_at"].is_string());
    let second = call(&registry, &db, "close_run", json!({ "run_key": RUN })).await;
    assert_eq!(second["changed"], false);
    assert_eq!(second["activity_id"], first["activity_id"]);
    assert_eq!(second["ended_at"], first["ended_at"]);

    let redeclare = registry
        .call_detailed(
            db.clone(),
            Caller::authenticated("acct:test"),
            "set_intent",
            json!({ "intent": "A closed activity stays closed.", "run_key": RUN }),
        )
        .await
        .unwrap();
    assert!(redeclare.outcome.is_err());

    let close_events: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM control_events WHERE type='agent_run.closed.v1' AND run_key=?",
    )
    .bind(RUN)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(close_events, 1);
    let start_events: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM control_events WHERE type='agent_run.started.v2' AND run_key=?",
    )
    .bind(RUN)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(start_events, 1);
}

#[tokio::test]
async fn run_discovery_is_bounded_pinned_and_same_account_only() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    call(
        &registry,
        &db,
        "set_intent",
        json!({ "intent": "Review the qualification model.", "run_key": RUN }),
    )
    .await;
    call(
        &registry,
        &db,
        "set_intent",
        json!({ "intent": "Test the independent alternative.", "run_key": OTHER_RUN }),
    )
    .await;
    call(&registry, &db, "close_run", json!({ "run_key": OTHER_RUN })).await;
    registry
        .call(
            db.clone(),
            Caller::authenticated("acct:other"),
            "set_intent",
            crate::common::with_test_reason(
                "set_intent",
                json!({
                    "intent": "This must not be discoverable by acct:test.",
                    "run_key": "other-chair-c748b2"
                }),
            ),
        )
        .await
        .unwrap();

    let first = call(&registry, &db, "get_run_activity", json!({ "limit": 1 })).await;
    assert_eq!(first["mode"], "discovery");
    assert_eq!(first["scope"], "own_account");
    assert_eq!(first["availability"]["status"], "available");
    assert_eq!(first["availability"]["details"], "best_effort");
    assert_eq!(first["returned"], 1);
    assert_eq!(first["has_more"], true);
    assert!(first["observed_at"].is_string());
    assert!(first["next_cursor"].is_object());
    assert!(first["runs"][0]["intent"]["declared_at"].is_string());

    let second = call(
        &registry,
        &db,
        "get_run_activity",
        json!({ "limit": 1, "cursor": first["next_cursor"].clone() }),
    )
    .await;
    assert_eq!(second["observed_at"], first["observed_at"]);
    assert_eq!(second["returned"], 1);
    assert_eq!(second["has_more"], false);
    let discovered = [first["runs"][0].clone(), second["runs"][0].clone()];
    let run_keys = discovered
        .iter()
        .map(|run| run["run_key"].as_str().unwrap())
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(run_keys, std::collections::HashSet::from([RUN, OTHER_RUN]));
    assert!(discovered
        .iter()
        .all(|run| run["intent"]["status"] == "available"));
    assert!(!serde_json::to_string(&discovered)
        .unwrap()
        .contains("This must not be discoverable"));

    let rendered = native_ce::mcp::render::render("get_run_activity", &first).unwrap();
    assert!(rendered.contains("Own-account run discovery"), "{rendered}");
    assert!(rendered.contains("next_cursor"), "{rendered}");

    sqlx::query("DELETE FROM read_log_calls WHERE actor='acct:test'")
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    let without_retained_intent =
        call(&registry, &db, "get_run_activity", json!({ "limit": 2 })).await;
    assert!(without_retained_intent["runs"]
        .as_array()
        .unwrap()
        .iter()
        .all(|run| run["intent"]["status"] == "not_retained"));

    let invalid = registry
        .call(
            db.clone(),
            Caller::authenticated("acct:test"),
            "get_run_activity",
            json!({ "limit": 51 }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(invalid.contains("between 1 and 50"), "{invalid}");
    db.close().await;
}

#[tokio::test]
async fn malformed_agent_key_sentinels_fail_open_preserve_raw_input_and_offer_repairs() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let raw_values = [
        "new:notahandle-chair",
        "new:scout-notaword",
        "new:scout-chiar",
    ];

    let mut results = Vec::new();
    for raw in raw_values {
        let result = call(&registry, &db, "get_dashboard", json!({ "run_key": raw })).await;
        assert_eq!(result["run_context"]["run_key"], Value::Null, "{raw}");
        results.push(result);
    }

    let rows = sqlx::query_as::<_, (Option<String>, String)>(
        "SELECT run_key, arguments FROM read_log_calls ORDER BY seq",
    )
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(rows.len(), raw_values.len());
    for ((stored, arguments), raw) in rows.iter().zip(raw_values) {
        assert_eq!(stored, &None, "{raw}");
        let captured: Value = serde_json::from_str(arguments).unwrap();
        assert_eq!(captured["run_key"], raw);
    }

    let typo_notes = results[2]["run_context"]["notes"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join(" ");
    assert!(typo_notes.contains("new:scout-chair"), "{typo_notes}");
}

#[tokio::test]
async fn intent_copy_forward_is_exact_run_and_survives_log_deletion() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    call(
        &registry,
        &db,
        "set_intent",
        json!({ "intent": "Ship exact-run copy-forward.", "run_key": RUN }),
    )
    .await;

    let same = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Document", "name": "same run", "run_key": RUN }),
    )
    .await;
    let fresh = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Document", "name": "fresh run", "run_key": OTHER_RUN }),
    )
    .await;

    let same_intent: Option<String> =
        sqlx::query_scalar("SELECT intent FROM content_events WHERE record_id = ?")
            .bind(same["id"].as_str().unwrap())
            .fetch_one(db.pool())
            .await
            .unwrap();
    let fresh_intent: Option<String> =
        sqlx::query_scalar("SELECT intent FROM content_events WHERE record_id = ?")
            .bind(fresh["id"].as_str().unwrap())
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(same_intent.as_deref(), Some("Ship exact-run copy-forward."));
    assert_eq!(fresh_intent, None);

    sqlx::query("DROP TABLE read_log_touches")
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    sqlx::query("DROP TABLE read_log_calls")
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    let after_drop = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Document", "name": "after drop", "run_key": RUN }),
    )
    .await;
    let after_drop_intent: Option<String> =
        sqlx::query_scalar("SELECT intent FROM content_events WHERE record_id = ?")
            .bind(after_drop["id"].as_str().unwrap())
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(after_drop_intent, None);

    let durable: Option<String> =
        sqlx::query_scalar("SELECT intent FROM content_events WHERE record_id = ?")
            .bind(same["id"].as_str().unwrap())
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(durable.as_deref(), Some("Ship exact-run copy-forward."));
}

#[tokio::test]
async fn rejected_set_intent_is_only_an_attempt_and_cannot_replace_current_intent() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    call(
        &registry,
        &db,
        "set_intent",
        json!({ "intent": "Accepted A", "run_key": RUN }),
    )
    .await;

    let rejected = registry
        .call_detailed(
            db.clone(),
            Caller::authenticated("acct:test"),
            "set_intent",
            json!({ "intent": "Rejected B", "unknown": true, "run_key": RUN }),
        )
        .await
        .unwrap();
    assert!(rejected.outcome.is_err());
    assert_eq!(rejected.run_context["intent"], "Accepted A");

    // Failed declarations are ordinary queued captures; wait for this attempt
    // before inspecting its persisted outcome.
    db.drain_captures_for_tests().await;
    let failed = sqlx::query(
        "SELECT intent, outcome FROM read_log_calls
          WHERE tool = 'set_intent' ORDER BY seq DESC LIMIT 1",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(failed.get::<Option<String>, _>("intent"), None);
    assert_eq!(failed.get::<String, _>("outcome"), "error");

    let created = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Document", "name": "After rejection", "run_key": RUN }),
    )
    .await;
    let copied: Option<String> =
        sqlx::query_scalar("SELECT intent FROM content_events WHERE record_id = ?")
            .bind(created["id"].as_str().unwrap())
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(copied.as_deref(), Some("Accepted A"));
}

#[tokio::test]
async fn agent_key_minting_and_displaced_key_nudge_obey_agent_boundaries() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();

    let bare = call(&registry, &db, "get_dashboard", json!({ "run_key": "new" })).await;
    assert!(!bare["run_context"]["notes"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|note| note
            .as_str()
            .is_some_and(|note| note.contains("may have displaced"))));

    let minted = call(
        &registry,
        &db,
        "get_dashboard",
        json!({ "run_key": "new:scout-chair" }),
    )
    .await;
    let minted_key = minted["run_context"]["run_key"].as_str().unwrap();
    assert!(minted_key.starts_with("scout-chair-"));
    assert_eq!(minted_key.len(), "scout-chair-".len() + 6);
    let captured: String = sqlx::query_scalar(
        "SELECT arguments FROM read_log_calls
          WHERE tool = 'get_dashboard' ORDER BY seq DESC LIMIT 1",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&captured).unwrap()["run_key"],
        "new:scout-chair"
    );
    let second_mint = call(
        &registry,
        &db,
        "get_dashboard",
        json!({ "run_key": "new:scout-chair" }),
    )
    .await;
    assert_ne!(second_mint["run_context"]["run_key"], minted_key);
    assert!(!second_mint["run_context"]["notes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|note| note
            .as_str()
            .is_some_and(|note| note.contains("may have displaced"))));

    // A full-key dashboard read alone no longer establishes retained run
    // evidence. A declaration does, and remains eligible for the nudge.
    call(
        &registry,
        &db,
        "set_intent",
        json!({ "intent": "Earlier run", "run_key": "scout-chair-j9e00t" }),
    )
    .await;
    sqlx::query(
        "UPDATE read_log_calls SET ended_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
          WHERE run_key = 'scout-chair-j9e00t'",
    )
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    let displaced = call(
        &registry,
        &db,
        "get_dashboard",
        json!({ "run_key": "scout-chair-j9e0t0" }),
    )
    .await;
    let notes = displaced["run_context"]["notes"].as_array().unwrap();
    assert!(notes.iter().any(|note| note
        .as_str()
        .is_some_and(|note| note.contains("scout-chair-j9e00t"))));

    // The nudge is advisory on a disposable read. Bootstrap persists this
    // run's issuance so the next call knows the key has been adopted.
    call(
        &registry,
        &db,
        "bootstrap",
        json!({ "run_key": "scout-chair-j9e0t0" }),
    )
    .await;

    let second = call(
        &registry,
        &db,
        "get_dashboard",
        json!({ "run_key": "scout-chair-j9e0t0" }),
    )
    .await;
    assert!(!second["run_context"]["notes"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|note| note
            .as_str()
            .is_some_and(|note| note.contains("may have displaced"))));

    let other_agent = call(
        &registry,
        &db,
        "get_dashboard",
        json!({ "run_key": "scout-bread-j9e0t0" }),
    )
    .await;
    assert!(!other_agent["run_context"]["notes"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|note| note
            .as_str()
            .is_some_and(|note| note.contains("may have displaced"))));

    call(
        &registry,
        &db,
        "set_intent",
        json!({ "intent": "Earlier ranger run", "run_key": "ranger-chair-j9e00t" }),
    )
    .await;
    let failed_prior = registry
        .call_detailed(
            db.clone(),
            Caller::authenticated("acct:test"),
            "set_intent",
            json!({ "intent": "Rejected ranger run", "run_key": "ranger-chair-k9e00t", "unknown": true }),
        )
        .await
        .unwrap();
    assert!(failed_prior.outcome.is_err());
    db.drain_captures_for_tests().await;
    sqlx::query(
        "UPDATE read_log_calls
            SET ended_at = CASE run_key
                WHEN 'ranger-chair-j9e00t' THEN strftime('%Y-%m-%dT%H:%M:%fZ','now','-5 minutes')
                WHEN 'ranger-chair-k9e00t' THEN strftime('%Y-%m-%dT%H:%M:%fZ','now','-1 minute')
            END
          WHERE run_key IN ('ranger-chair-j9e00t', 'ranger-chair-k9e00t')",
    )
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    let most_recent = call(
        &registry,
        &db,
        "get_dashboard",
        json!({ "run_key": "ranger-chair-j9e0t0" }),
    )
    .await;
    let most_recent_notes = most_recent["run_context"]["notes"].as_array().unwrap();
    assert!(most_recent_notes.iter().any(|note| note
        .as_str()
        .is_some_and(|note| note.contains("ranger-chair-k9e00t"))));
    assert!(!most_recent_notes.iter().any(|note| note
        .as_str()
        .is_some_and(|note| note.contains("ranger-chair-j9e00t"))));

    call(
        &registry,
        &db,
        "bootstrap",
        json!({ "run_key": "heron-chair-a748b2" }),
    )
    .await;
    sqlx::query(
        "UPDATE read_log_calls
            SET ended_at = strftime('%Y-%m-%dT%H:%M:%fZ','now','-31 minutes')
          WHERE run_key = 'heron-chair-a748b2'",
    )
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    let old = call(
        &registry,
        &db,
        "get_dashboard",
        json!({ "run_key": "heron-chair-b748b2" }),
    )
    .await;
    assert!(!old["run_context"]["notes"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|note| note
            .as_str()
            .is_some_and(|note| note.contains("may have displaced"))));
}

#[tokio::test]
async fn an_unissued_pure_read_key_is_not_a_resumable_prior_run() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let prior = "heron-chair-c748b2";
    let current = "heron-chair-d748b2";
    call(&registry, &db, "get_dashboard", json!({ "run_key": prior })).await;
    let retained: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM read_log_calls WHERE run_key=?")
        .bind(prior)
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(retained, 0);
    let declared = call(
        &registry,
        &db,
        "set_intent",
        json!({ "intent": "New run", "run_key": current }),
    )
    .await;
    assert_eq!(declared["briefing"]["resume"], Value::Null);
    db.close().await;
}

#[tokio::test]
async fn displaced_nudge_recalls_only_the_newest_1024_calls() {
    async fn insert_call(db: &Db, id: &str, run_key: &str, actor: &str, ended_offset: &str) {
        sqlx::query(
            "INSERT INTO read_log_calls
              (id, tool, run_key, actor, outcome, started_at, ended_at)
              VALUES (?, 'get_dashboard', ?, ?, 'ok',
                      strftime('%Y-%m-%dT%H:%M:%fZ','now'),
                      strftime('%Y-%m-%dT%H:%M:%fZ','now', ?))",
        )
        .bind(id)
        .bind(run_key)
        .bind(actor)
        .bind(ended_offset)
        .execute(&crate::common::fixture_write_pool(db).await)
        .await
        .unwrap();
    }

    fn notes_of(result: &Value) -> Vec<String> {
        result["run_context"]["notes"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect()
    }

    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    // Oldest rows: a matching prior and the to-be-queried seen key itself,
    // both recent enough to advise under the unbounded scan.
    insert_call(
        &db,
        "window-prior",
        "scout-chair-000001",
        "acct:test",
        "-1 minutes",
    )
    .await;
    insert_call(
        &db,
        "window-seen",
        "scout-chair-000007",
        "acct:test",
        "-1 minutes",
    )
    .await;
    // Push both below the newest-1024 candidate window with non-matching
    // filler (another actor, another agent key). Raw log inserts only: no
    // thousand-record fixture build.
    for index in 0..1025 {
        insert_call(
            &db,
            &format!("window-filler-{index:04}"),
            &format!("other-bread-{index:06}"),
            "acct:nobody",
            "-2 minutes",
        )
        .await;
    }

    // Beyond-window matching prior: intentional advisory silence.
    let beyond = call(
        &registry,
        &db,
        "get_dashboard",
        json!({ "run_key": "scout-chair-999999" }),
    )
    .await;
    assert!(
        !notes_of(&beyond)
            .iter()
            .any(|note| note.contains("may have displaced")),
        "{}",
        serde_json::to_string(&beyond["run_context"]["notes"]).unwrap()
    );
    // Seen-key suppression still spans the full log: the key below is as old
    // as the silenced prior, yet no note is emitted because the EXISTS check
    // is not windowed.
    let seen = call(
        &registry,
        &db,
        "get_dashboard",
        json!({ "run_key": "scout-chair-000007" }),
    )
    .await;
    assert!(
        !notes_of(&seen)
            .iter()
            .any(|note| note.contains("may have displaced")),
        "{}",
        serde_json::to_string(&seen["run_context"]["notes"]).unwrap()
    );
    // Control on the same database: a newest-row prior is inside the window
    // and still advises.
    insert_call(
        &db,
        "window-fresh",
        "scout-chair-000002",
        "acct:test",
        "+0 minutes",
    )
    .await;
    let within = call(
        &registry,
        &db,
        "get_dashboard",
        json!({ "run_key": "scout-chair-999998" }),
    )
    .await;
    assert!(
        notes_of(&within)
            .iter()
            .any(|note| note.contains("scout-chair-000002")),
        "{}",
        serde_json::to_string(&within["run_context"]["notes"]).unwrap()
    );
    db.close().await;
}

#[tokio::test]
async fn briefing_is_bounded_agent_scoped_and_contains_no_raw_trace_content() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let prior = "scout-chair-c748b2";
    let current = "scout-chair-d748b2";
    let other_agent = "scout-bread-e748b2";

    call(
        &registry,
        &db,
        "set_intent",
        json!({ "intent": "Prior declaration", "run_key": prior }),
    )
    .await;
    for index in 1..12 {
        call(
            &registry,
            &db,
            "set_intent",
            json!({ "intent": format!("Prior {index}"), "run_key": prior }),
        )
        .await;
    }
    for index in 0..21 {
        let created = call(
            &registry,
            &db,
            "create_record",
            json!({
                "type": "WorkItem",
                "kind": "task",
                "name": format!("Touched {index}"),
                "body": "SECRET-BODY-MUST-NOT-LEAK",
                "lifecycle": "open",
                "run_key": prior,
            }),
        )
        .await;
        call(
            &registry,
            &db,
            "start_work",
            json!({ "record_id": created["id"], "run_key": prior }),
        )
        .await;
    }

    let outsider = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "WorkItem", "kind": "task", "name": "Other agent", "lifecycle": "open", "run_key": other_agent }),
    )
    .await;
    call(
        &registry,
        &db,
        "start_work",
        json!({ "record_id": outsider["id"], "run_key": other_agent }),
    )
    .await;

    // Persist the current run's lineage before set_intent, whose own call row
    // is captured only after its briefing has been built. Bootstrap is the
    // retained run-issuance surface; a dashboard read is disposable.
    call(
        &registry,
        &db,
        "bootstrap",
        json!({ "run_key": current, "parent_key": prior }),
    )
    .await;
    let result = call(
        &registry,
        &db,
        "set_intent",
        json!({ "intent": "Resume safely", "run_key": current, "parent_key": prior }),
    )
    .await;

    assert_eq!(result["briefing"]["resume"]["run_key"], prior);
    assert!(result["briefing"]["resume"]["duration_ms"]
        .as_i64()
        .is_some());
    let resume_declarations = &result["briefing"]["resume"]["declarations"];
    assert_eq!(resume_declarations["total_count"], 12);
    assert_eq!(resume_declarations["items"].as_array().unwrap().len(), 10);
    assert_eq!(resume_declarations["truncated"], true);
    assert_eq!(resume_declarations["items"][0]["intent"], "Prior 2");
    assert_eq!(resume_declarations["items"][9]["intent"], "Prior 11");
    // Per-declaration lists fold DECLARED sources from content events, not
    // touches: nothing here was declared, so every episode is empty even
    // though the run-level touch list below stays at full strength.
    assert_eq!(
        resume_declarations["items"][9]["touched_records"]["total_count"],
        0
    );
    let touched = &result["briefing"]["resume"]["touched_records"];
    assert_eq!(
        result["briefing"]["resume"]["touched_records_completeness"],
        "retained_rows_only"
    );
    assert!(touched["total_count"].as_u64().unwrap() >= 21);
    assert_eq!(touched["items"].as_array().unwrap().len(), 20);
    assert_eq!(touched["truncated"], true);
    let unfinished = &result["briefing"]["resume"]["left_non_terminal"];
    assert_eq!(unfinished["items"].as_array().unwrap().len(), 20);
    assert_eq!(unfinished["truncated"], true);

    let lineage = &result["briefing"]["working_under"];
    assert_eq!(lineage["items"][0]["run_key"], current);
    assert_eq!(lineage["items"][0]["intent"], "Resume safely");
    assert_eq!(lineage["items"][1]["run_key"], prior);
    assert_eq!(lineage["end"], "rooted");

    let claims = &result["briefing"]["open_claims"];
    assert_eq!(claims["total_count"], 21);
    assert_eq!(claims["items"].as_array().unwrap().len(), 20);
    assert_eq!(claims["truncated"], true);
    assert!(claims["items"]
        .as_array()
        .unwrap()
        .iter()
        .all(|claim| { claim["run_key"] == prior && claim["id"] != outsider["id"] }));

    let rendered = native_ce::mcp::render::render("set_intent", &result).unwrap();
    for expected in [
        "Briefing availability: available",
        "Resume declarations: 10 returned of 12; producer window truncated",
        "Resume touches cover retained rows only; omitted reads may have occurred.",
        "Resume touched records: 20 returned of",
        "Resume left non-terminal: 20 returned of",
        "Working-under end: \"rooted\" (complete rooted path)",
        "Open claims: 20 returned; 21 qualifying item(s) found",
    ] {
        assert!(
            rendered.contains(expected),
            "missing {expected:?}: {rendered}"
        );
    }
    assert!(rendered.contains(prior), "{rendered}");
    assert!(!rendered.contains("SECRET-BODY-MUST-NOT-LEAK"));

    let serialized = serde_json::to_string(&result["briefing"]).unwrap();
    assert!(!serialized.contains("SECRET-BODY-MUST-NOT-LEAK"));
    assert!(!serialized.contains("arguments"));
    assert!(!serialized.contains("query"));
    for item in touched["items"].as_array().unwrap() {
        let keys = item
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(
            keys,
            [
                "id",
                "name",
                "type",
                "lifecycle",
                "interactions",
                "last_touched_at"
            ]
        );
    }
}

#[tokio::test]
async fn resume_classifies_lifecycle_by_kind_and_reports_unclassified_values() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let prior = "scout-chair-c748b2";
    let current = "scout-chair-d748b2";

    call(
        &registry,
        &db,
        "set_intent",
        json!({ "intent": "Classify lifecycle values", "run_key": prior }),
    )
    .await;

    for (name, lifecycle) in [
        ("open task", "open"),
        ("in progress task", "in_progress"),
        ("blocked task", "blocked"),
        ("completed task", "completed"),
        ("closed task", "closed"),
    ] {
        let record = call(
            &registry,
            &db,
            "create_record",
            json!({
                "type": "WorkItem",
                "kind": "task",
                "name": name,
                "lifecycle": lifecycle,
                "run_key": prior,
            }),
        )
        .await;
        call(
            &registry,
            &db,
            "start_work",
            json!({ "record_id": record["id"], "run_key": prior }),
        )
        .await;
    }

    for (name, lifecycle) in [
        ("open epic", "open"),
        ("in progress epic", "in_progress"),
        ("completed epic", "completed"),
        ("closed epic", "closed"),
    ] {
        let record = call(
            &registry,
            &db,
            "create_record",
            json!({
                "type": "WorkItem",
                "kind": "epic",
                "name": name,
                "lifecycle": lifecycle,
                "run_key": prior,
            }),
        )
        .await;
        call(
            &registry,
            &db,
            "start_work",
            json!({ "record_id": record["id"], "run_key": prior }),
        )
        .await;
    }

    // Two kind-specific vocabularies intentionally give the same raw token
    // different meanings. This proves the briefing follows the effective
    // schema, rather than treating a token as globally terminal/non-terminal.
    crate::common::govern_kind(&db, "WorkItem", "kind-open").await;
    crate::common::govern_kind(&db, "WorkItem", "kind-terminal").await;
    create_vocabulary(&db, "kind-open-lifecycle", Some("voc:kind-open-lifecycle"))
        .await
        .unwrap();
    create_vocabulary(
        &db,
        "kind-terminal-lifecycle",
        Some("voc:kind-terminal-lifecycle"),
    )
    .await
    .unwrap();
    for (vocabulary, terminality) in [
        ("kind-open-lifecycle", VocabularyValueTerminality::Open),
        (
            "kind-terminal-lifecycle",
            VocabularyValueTerminality::TerminalPositive,
        ),
    ] {
        let value =
            propose_value_with_metadata_as(&db, vocabulary, "ready", None, 1.0, terminality, None)
                .await
                .unwrap();
        promote_value(&db, &value).await.unwrap();
    }
    write_user_schema_config(
        &db,
        json!({
            "shapes": {
                "WorkItem:kind-open": {
                    "facets": { "lifecycle": {
                        "axis": { "key": "test_state", "label": "Test state" },
                        "vocab_ref": "rec:voc:kind-open-lifecycle"
                    } }
                },
                "WorkItem:kind-terminal": {
                    "facets": { "lifecycle": {
                        "axis": { "key": "test_state", "label": "Test state" },
                        "vocab_ref": "rec:voc:kind-terminal-lifecycle"
                    } }
                }
            }
        }),
        SchemaConfigOptions::default(),
    )
    .await
    .unwrap();
    for (kind, name) in [
        ("kind-open", "kind-specific open"),
        ("kind-terminal", "kind-specific terminal"),
    ] {
        let record = call(
            &registry,
            &db,
            "create_record",
            json!({
                "type": "WorkItem",
                "kind": kind,
                "name": name,
                "lifecycle": "ready",
                "run_key": prior,
            }),
        )
        .await;
        call(
            &registry,
            &db,
            "start_work",
            json!({ "record_id": record["id"], "run_key": prior }),
        )
        .await;
    }

    // A lifecycle on this governed-but-unshaped collection kind has no
    // governing lifecycle vocabulary. Ordinary authoring refuses it, so use
    // the explicit raw fixture seam to model retained historical evidence.
    let ungoverned = call(
        &registry,
        &db,
        "create_record",
        json!({
            "type": "Collection",
            "kind": "folder",
            "name": "ungoverned lifecycle",
            "persistence": "enduring",
            "run_key": prior,
        }),
    )
    .await;
    sqlx::query("UPDATE records SET lifecycle = 'ready' WHERE id = ?")
        .bind(ungoverned["id"].as_str().unwrap())
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    call(
        &registry,
        &db,
        "start_work",
        json!({ "record_id": ungoverned["id"], "run_key": prior }),
    )
    .await;

    // Historical/corrupt projections can carry a token that is not in an
    // otherwise valid governing vocabulary. It must remain distinct from the
    // no-governance case.
    let unknown_value = call(
        &registry,
        &db,
        "create_record",
        json!({
            "type": "WorkItem",
            "kind": "task",
            "name": "unknown lifecycle value",
            "lifecycle": "open",
            "run_key": prior,
        }),
    )
    .await;
    call(
        &registry,
        &db,
        "start_work",
        json!({ "record_id": unknown_value["id"], "run_key": prior }),
    )
    .await;
    sqlx::query("UPDATE records SET lifecycle = 'ready' WHERE id = ?")
        .bind(unknown_value["id"].as_str().unwrap())
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();

    // A scoped shape whose vocabulary reference is not interpretable should
    // classify only this record as such, without blanking the whole briefing.
    let malformed_home = call(
        &registry,
        &db,
        "create_record",
        json!({
            "type": "Collection",
            "kind": "folder",
            "name": "malformed lifecycle home",
            "persistence": "enduring",
            "run_key": prior,
        }),
    )
    .await;
    let malformed_schema = call(
        &registry,
        &db,
        "create_record",
        json!({
            "type": "Document",
            "kind": "x-test-fixture",
            "name": "malformed lifecycle schema",
            "home_id": malformed_home["id"],
            "run_key": prior,
        }),
    )
    .await;
    sqlx::query("UPDATE records SET lifecycle = 'ready' WHERE id = ?")
        .bind(malformed_schema["id"].as_str().unwrap())
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    call(
        &registry,
        &db,
        "start_work",
        json!({ "record_id": malformed_schema["id"], "run_key": prior }),
    )
    .await;
    let malformed_home_id: String = sqlx::query_scalar("SELECT home_id FROM records WHERE id = ?")
        .bind(malformed_schema["id"].as_str().unwrap())
        .fetch_one(db.pool())
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO schema_config
            (id, layer, name, data, applies_to_collection_id)
         VALUES ('intent:malformed-lifecycle-schema', 'user',
                 'Malformed lifecycle schema', ?, ?)",
    )
    .bind(
        json!({
            "shapes": {
                "Document:x-test-fixture": {
                    "facets": { "lifecycle": { "vocab_ref": 42 } }
                }
            }
        })
        .to_string(),
    )
    .bind(&malformed_home_id)
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();

    call(
        &registry,
        &db,
        "get_dashboard",
        json!({ "run_key": current, "parent_key": prior }),
    )
    .await;
    let result = call(
        &registry,
        &db,
        "set_intent",
        json!({ "intent": "Resume lifecycle classification", "run_key": current }),
    )
    .await;
    let resume = &result["briefing"]["resume"];
    let left = resume["left_non_terminal"]["items"].as_array().unwrap();
    for name in [
        "open task",
        "in progress task",
        "blocked task",
        "open epic",
        "in progress epic",
        "kind-specific open",
    ] {
        assert!(
            left.iter().any(|item| item["name"] == name),
            "{name}: {left:?}"
        );
    }
    for name in [
        "completed task",
        "closed task",
        "completed epic",
        "closed epic",
        "kind-specific terminal",
    ] {
        assert!(
            !left.iter().any(|item| item["name"] == name),
            "{name}: {left:?}"
        );
    }
    let unclassified = &resume["unclassified_lifecycle"];
    assert_eq!(unclassified["total_count"], 3);
    let unclassified_items = unclassified["items"].as_array().unwrap();
    assert_eq!(unclassified_items.len(), 3);
    for (record, reason) in [
        (&ungoverned, "no_governing_vocabulary"),
        (&unknown_value, "unknown_or_inactive_value"),
        (&malformed_schema, "uninterpretable_schema_or_value"),
    ] {
        let item = unclassified_items
            .iter()
            .find(|item| item["id"] == record["id"])
            .unwrap();
        assert_eq!(item["reason"], reason);
    }
    assert_eq!(unclassified["truncated"], false);
}

#[tokio::test]
async fn briefing_omits_records_whose_access_was_revoked_after_touch_and_claim() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let prior = "scout-chair-f748b2";
    let current = "scout-chair-f748b3";

    call(
        &registry,
        &db,
        "set_intent",
        json!({ "intent": "Work before revocation", "run_key": prior }),
    )
    .await;
    let record = native_ce::store::create_record(
        &db,
        json!({
            "type": "WorkItem", "kind": "task",
            "name": "Revoked briefing secret", "lifecycle": "open"
        }),
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        "test:policy",
        &record,
        vec![AllowEntry::account("acct:test", Capability::Manage)],
    )
    .await
    .unwrap();
    call(
        &registry,
        &db,
        "start_work",
        json!({ "record_id": record, "run_key": prior }),
    )
    .await;
    // Keep the regression's tally exact: authoring tools also touch structural
    // support records, which are unrelated to the revoked record under test.
    sqlx::query(
        "DELETE FROM read_log_touches
          WHERE call_seq IN (SELECT seq FROM read_log_calls WHERE run_key = ?)
            AND record_ref <> (SELECT record_ref FROM read_log_record_ids WHERE record_id = ?)",
    )
    .bind(prior)
    .bind(&record)
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();

    let before_revocation = call(
        &registry,
        &db,
        "set_intent",
        json!({ "intent": "Resume before revocation", "run_key": current }),
    )
    .await;
    let before_briefing = &before_revocation["briefing"];
    assert!(before_briefing.to_string().contains(&record));
    assert!(before_briefing
        .to_string()
        .contains("Revoked briefing secret"));

    replace_explicit_policy(
        &db,
        "test:policy",
        &record,
        vec![AllowEntry::account("acct:revoked", Capability::Manage)],
    )
    .await
    .unwrap();
    let resumed = call(
        &registry,
        &db,
        "set_intent",
        json!({ "intent": "Resume after revocation", "run_key": current }),
    )
    .await;

    let resume = &resumed["briefing"]["resume"];
    let before_resume = &before_briefing["resume"];
    assert_eq!(resume["run_key"], prior);
    assert_eq!(
        resume["touched_records"]["total_count"].as_u64().unwrap() + 1,
        before_resume["touched_records"]["total_count"]
            .as_u64()
            .unwrap()
    );
    assert_eq!(
        resume["left_non_terminal"]["total_count"].as_u64().unwrap() + 1,
        before_resume["left_non_terminal"]["total_count"]
            .as_u64()
            .unwrap()
    );
    let before_declarations = before_resume["declarations"]["items"].as_array().unwrap();
    let after_declarations = resume["declarations"]["items"].as_array().unwrap();
    assert_eq!(after_declarations.len(), before_declarations.len());
    // Per-declaration lists fold declared sources, not touches, and this run
    // declared nothing: both sides are empty, and revocation visibility for
    // declarations is covered where declarations exist. The revoked record's
    // absence from the briefing below still holds through the run-level
    // touch list and the open claims, which stay touch- and claim-based.
    for (before, after) in before_declarations.iter().zip(after_declarations) {
        assert_eq!(before["touched_records"]["total_count"], 0);
        assert_eq!(after["touched_records"]["total_count"], 0);
    }
    assert_eq!(
        resumed["briefing"]["open_claims"]["total_count"]
            .as_u64()
            .unwrap()
            + 1,
        before_briefing["open_claims"]["total_count"]
            .as_u64()
            .unwrap()
    );
    let briefing = resumed["briefing"].to_string();
    assert!(!briefing.contains(&record));
    assert!(!briefing.contains("Revoked briefing secret"));
    db.close().await;
}

#[tokio::test]
async fn open_claims_bounds_the_indexed_account_candidate_window() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();

    // The 100 newest account-owned candidates belong to another agent key. A
    // matching but older 101st claim must not force an unbounded account scan;
    // truncation tells the caller that the bounded candidate window was hit.
    for index in 0..101 {
        let (run_key, claimed_at) = if index == 0 {
            (
                "scout-chair-000000".to_string(),
                "2026-01-01T00:00:00.000Z".to_string(),
            )
        } else {
            (
                format!("scout-bread-{index:06}"),
                format!("2026-01-02T00:00:{index:03}.000Z"),
            )
        };
        sqlx::query(
            "INSERT INTO records
                (id,type,kind,name,home_id,lifecycle,claimed_by_account,
                 claimed_run_key,claimed_at,policy_anchor_id,persistence)
             VALUES (?, 'WorkItem', 'x-test-fixture', ?, ?, 'open', 'acct:test',
                     ?, ?, ?, 'enduring')",
        )
        .bind(format!("bounded-claim-{index:03}"))
        .bind(format!("Bounded claim {index}"))
        .bind(native_ce::schema::UNFILED_RECORD_ID)
        .bind(run_key)
        .bind(claimed_at)
        .bind(native_ce::schema::ROOT_RECORD_ID)
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    }

    let result = call(
        &registry,
        &db,
        "set_intent",
        json!({ "intent": "Bounded claims", "run_key": "scout-chair-d748b2" }),
    )
    .await;
    let claims = &result["briefing"]["open_claims"];
    assert_eq!(claims["items"], json!([]));
    assert_eq!(claims["total_count"], 0);
    assert_eq!(claims["truncated"], true);
    db.close().await;
}

async fn insert_lineage_call(db: &Db, run_key: &str, parent_key: &str) {
    sqlx::query(
        "INSERT INTO read_log_calls
         (id, tool, run_key, parent_key, actor, outcome, started_at, ended_at)
         VALUES (?, 'get_dashboard', ?, ?, 'acct:test', 'ok',
                 strftime('%Y-%m-%dT%H:%M:%fZ','now'),
                 strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
    )
    .bind(format!("lineage:{run_key}"))
    .bind(run_key)
    .bind(parent_key)
    .execute(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap();
}

#[tokio::test]
async fn briefing_lineage_cycles_and_depth_cap_return_truncated_paths() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();

    for index in 0..33 {
        insert_lineage_call(
            &db,
            &format!("scout-chair-{index:06}"),
            &format!("scout-chair-{:06}", index + 1),
        )
        .await;
    }
    let depth = call(
        &registry,
        &db,
        "set_intent",
        json!({ "intent": "Inspect depth", "run_key": "scout-chair-000000" }),
    )
    .await;
    let depth_path = &depth["briefing"]["working_under"];
    assert_eq!(depth_path["items"].as_array().unwrap().len(), 32);
    assert_eq!(depth_path["total_count"], 32);
    assert_eq!(depth_path["truncated"], true);
    assert_eq!(depth_path["end"], "depth_cap");

    insert_lineage_call(&db, "heron-chair-000001", "heron-chair-000002").await;
    insert_lineage_call(&db, "heron-chair-000002", "heron-chair-000001").await;
    let cycle = call(
        &registry,
        &db,
        "set_intent",
        json!({ "intent": "Inspect cycle", "run_key": "heron-chair-000001" }),
    )
    .await;
    let cycle_path = &cycle["briefing"]["working_under"];
    assert_eq!(cycle_path["items"].as_array().unwrap().len(), 2);
    assert_eq!(cycle_path["total_count"], 2);
    assert_eq!(cycle_path["truncated"], true);
    assert_eq!(cycle_path["end"], "cycle");
}

#[tokio::test]
async fn dropped_read_log_keeps_declaration_and_writes_operational_with_empty_briefing() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    call(
        &registry,
        &db,
        "set_intent",
        json!({ "intent": "Seed partial-drop resume", "run_key": OTHER_RUN }),
    )
    .await;
    call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Document", "name": "Touched before partial drop", "run_key": OTHER_RUN }),
    )
    .await;
    sqlx::query("DROP TABLE read_log_touches")
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    let partial = call(
        &registry,
        &db,
        "set_intent",
        json!({ "intent": "Partial log also degrades", "run_key": RUN }),
    )
    .await;
    assert_eq!(
        partial["briefing"]["this_run"]["declarations"]["items"],
        json!([])
    );
    assert_eq!(partial["briefing"]["resume"], Value::Null);
    assert_eq!(
        partial["briefing"]["availability"],
        json!({ "status": "unavailable", "reason": "briefing_failed" })
    );
    let partial_text = native_ce::mcp::render::render("set_intent", &partial).unwrap();
    assert!(partial_text.contains("Briefing unavailable: briefing_failed"));
    assert!(!partial_text.contains("Resume: none"));
    assert!(!partial_text.contains("Open claims: 0"));
    sqlx::query("DROP TABLE read_log_calls")
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();

    let bare_minted = call(&registry, &db, "get_dashboard", json!({ "run_key": "new" })).await;
    let bare_key = bare_minted["run_context"]["run_key"].as_str().unwrap();
    assert!(matches!(
        native_ce::runkey::validate(Some(bare_key)),
        native_ce::runkey::KeyOutcome::Valid(_)
    ));
    let agent_minted = call(
        &registry,
        &db,
        "get_dashboard",
        json!({ "run_key": "new:scout-chair" }),
    )
    .await;
    assert!(agent_minted["run_context"]["run_key"]
        .as_str()
        .unwrap()
        .starts_with("scout-chair-"));
    assert!(!agent_minted["run_context"]["notes"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|note| note
            .as_str()
            .is_some_and(|note| note.contains("may have displaced"))));

    let no_log_nudge = call(
        &registry,
        &db,
        "get_dashboard",
        json!({ "run_key": "scout-chair-z748b2" }),
    )
    .await;
    assert!(!no_log_nudge["run_context"]["notes"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|note| note
            .as_str()
            .is_some_and(|note| note.contains("may have displaced"))));

    let declared = call(
        &registry,
        &db,
        "set_intent",
        json!({ "intent": "Continue without attention data", "run_key": RUN }),
    )
    .await;
    assert_eq!(
        declared["accepted_intent"],
        "Continue without attention data"
    );
    assert_eq!(
        declared["run_context"]["intent"],
        "Continue without attention data"
    );
    assert_eq!(
        declared["briefing"]["this_run"]["declarations"]["items"],
        json!([])
    );
    assert_eq!(declared["briefing"]["resume"], Value::Null);
    assert_eq!(declared["briefing"]["working_under"]["items"], json!([]));
    assert_eq!(declared["briefing"]["open_claims"]["items"], json!([]));
    assert_eq!(
        declared["briefing"]["availability"],
        json!({ "status": "unavailable", "reason": "read_log_unavailable" })
    );
    let declared_text = native_ce::mcp::render::render("set_intent", &declared).unwrap();
    assert!(declared_text.contains("Briefing unavailable: read_log_unavailable"));
    assert!(!declared_text.contains("Resume: none"));
    assert!(!declared_text.contains("Open claims: 0"));

    let created = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Document", "name": "Core write survives", "run_key": RUN }),
    )
    .await;
    let intent: Option<String> =
        sqlx::query_scalar("SELECT intent FROM content_events WHERE record_id = ?")
            .bind(created["id"].as_str().unwrap())
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(intent, None);
}

// ---------------------------------------------------------------------------
// overlapping_claims
// ---------------------------------------------------------------------------

async fn other_principal_claim(
    registry: &ToolRegistry,
    db: &Db,
    name: &str,
    run_key: &str,
) -> String {
    // Minting as a second account needs that account's own portable binding;
    // the shared `call` helper only provisions `acct:test`.
    sqlx::query(
        "INSERT OR IGNORE INTO records
            (id, type, kind, name, home_id, policy_anchor_id, persistence)
         VALUES ('test:other-person', 'Entity', 'person', 'Other account',
                 ?, ?, 'enduring')",
    )
    .bind(native_ce::schema::UNFILED_RECORD_ID)
    .bind(native_ce::schema::ROOT_RECORD_ID)
    .execute(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap();
    sqlx::query(
        "INSERT OR IGNORE INTO bindings
            (record_id, system, identifier, is_canonical)
         VALUES ('test:other-person', 'account', 'acct:other', 1)",
    )
    .execute(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap();
    let created = registry
        .call(
            db.clone(),
            Caller::authenticated("acct:other"),
            "create_record",
            crate::common::with_test_reason(
                "create_record",
                json!({
                    "type": "WorkItem",
                    "kind": "task",
                    "name": name,
                    "lifecycle": "open",
                    "run_key": run_key,
                }),
            ),
        )
        .await
        .unwrap();
    let id = created["id"].as_str().unwrap().to_string();
    registry
        .call(
            db.clone(),
            Caller::authenticated("acct:other"),
            "start_work",
            json!({ "record_id": id, "run_key": run_key }),
        )
        .await
        .unwrap();
    id
}

async fn declare_overlap_source(registry: &ToolRegistry, db: &Db, id: &str, run_key: &str) {
    declare_write(
        registry,
        db,
        run_key,
        "overlap basis",
        json!([{ "record_id": id, "reason": "work basis" }]),
    )
    .await;
}

#[tokio::test]
async fn overlapping_claims_names_a_declared_source_claimed_by_another_principal() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();

    let held = other_principal_claim(&registry, &db, "Held elsewhere", OTHER_RUN).await;
    declare_overlap_source(&registry, &db, &held, RUN).await;

    let result = call(
        &registry,
        &db,
        "set_intent",
        json!({ "intent": "Walk into the held record.", "run_key": RUN }),
    )
    .await;

    let section = &result["briefing"]["overlapping_claims"];
    assert_eq!(section["total_count"], 1);
    assert_eq!(section["truncated"], false);
    let items = section["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{items:#?}");
    assert_eq!(items[0]["record_id"], held);

    let overlap = &items[0]["overlap"];
    let overlap_items = overlap["items"].as_array().unwrap();
    assert_eq!(overlap_items.len(), 1, "{overlap_items:#?}");
    assert_eq!(overlap_items[0]["record_id"], held);
    assert_eq!(overlap_items[0]["relation"], "same_record");
    assert_eq!(overlap_items[0]["holder_tier"], "another_principal");
    let mut keys: Vec<&str> = overlap_items[0]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort();
    assert_eq!(
        keys,
        vec!["holder_tier", "record_id", "relation"],
        "another_principal must leak nothing beyond existence and relation: {overlap_items:#?}"
    );

    let rendered = native_ce::mcp::render::render("set_intent", &result).unwrap();
    assert!(
        rendered.contains("Overlapping claims: 1 returned of 1."),
        "{rendered}"
    );
    assert!(rendered.contains(&held), "{rendered}");
}

#[tokio::test]
async fn overlapping_claims_is_present_but_empty_without_overlap() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();

    let result = call(
        &registry,
        &db,
        "set_intent",
        json!({ "intent": "Start clear.", "run_key": RUN }),
    )
    .await;

    assert_eq!(
        result["briefing"]["overlapping_claims"],
        json!({ "items": [], "total_count": 0, "truncated": false })
    );

    let rendered = native_ce::mcp::render::render("set_intent", &result).unwrap();
    assert!(
        rendered.contains("Overlapping claims: 0 returned of 0."),
        "{rendered}"
    );
}

#[tokio::test]
async fn overlapping_claims_caps_anchors_at_ten_and_flags_truncation() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();

    let mut held_ids = Vec::new();
    for index in 0..12 {
        let run_key = format!("pilot-river-b{index:04b}2");
        held_ids
            .push(other_principal_claim(&registry, &db, &format!("Held {index}"), &run_key).await);
    }
    for id in &held_ids {
        declare_overlap_source(&registry, &db, id, RUN).await;
    }

    let result = call(
        &registry,
        &db,
        "set_intent",
        json!({ "intent": "Survey the held records.", "run_key": RUN }),
    )
    .await;

    let section = &result["briefing"]["overlapping_claims"];
    assert_eq!(section["total_count"], 12);
    assert_eq!(section["truncated"], true);
    let items = section["items"].as_array().unwrap();
    assert_eq!(items.len(), 10, "{items:#?}");
    for item in items {
        let overlap = &item["overlap"];
        assert!(
            overlap["items"]
                .as_array()
                .is_some_and(|overlap_items| !overlap_items.is_empty()),
            "every emitted anchor carries a non-empty window: {item:#?}"
        );
    }

    let rendered = native_ce::mcp::render::render("set_intent", &result).unwrap();
    assert!(
        rendered.contains("Overlapping claims: 10 returned of 12; producer window truncated"),
        "{rendered}"
    );
}

#[tokio::test]
async fn set_intent_declared_model_confirmation_records_first_declaration() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    // An unrecognised string is still the claim that was made: stored
    // exactly as given, never normalised or rejected against a list.
    let model = "definitely-not-a-known-model-zzz";

    let result = call(
        &registry,
        &db,
        "set_intent",
        json!({ "intent": "Declare under test.", "model": model, "run_key": RUN }),
    )
    .await;
    assert_eq!(result["declared_model"]["declared"], model);
    assert_eq!(result["declared_model"]["recorded"], model);
    assert_eq!(result["declared_model"]["refused"], false);
    let note = result["declared_model"]["note"].as_str().unwrap();
    assert!(
        note.contains("Recorded 'definitely-not-a-known-model-zzz'"),
        "{note}"
    );
    // The honesty payload travels in the response itself.
    assert!(note.contains("mid-run model switch"), "{note}");
    assert!(note.contains("no launcher-independent source"), "{note}");
    assert!(note.contains("grants no capability"), "{note}");
    assert!(
        note.contains("does not affect routing, permission, gating or rendering priority"),
        "{note}"
    );

    let stored: Option<String> =
        sqlx::query_scalar("SELECT reported_model FROM agent_runs WHERE run_key=?")
            .bind(RUN)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(stored.as_deref(), Some(model));

    // Repeating the recorded value is benign and confirms the same record.
    let repeat = call(
        &registry,
        &db,
        "set_intent",
        json!({ "intent": "Declare again.", "model": model, "run_key": RUN }),
    )
    .await;
    assert_eq!(repeat["declared_model"]["recorded"], model);
    assert!(
        repeat["declared_model"]["note"]
            .as_str()
            .unwrap()
            .contains("already records declared model"),
        "{}",
        repeat["declared_model"]["note"]
    );

    // A differing second declaration is refused in the response — while the
    // call itself still succeeds: the new intent lands (the reviewer's probe:
    // "Aim two" replaces "Aim one") and the briefing is returned, but the
    // recorded model is unchanged.
    let diverged = registry
        .call_detailed(
            db.clone(),
            Caller::authenticated("acct:test"),
            "set_intent",
            crate::common::with_test_reason(
                "set_intent",
                json!({ "intent": "Aim two, materially changed.", "model": "another-model", "run_key": RUN }),
            ),
        )
        .await
        .unwrap();
    assert!(diverged.outcome.is_ok());
    let body = diverged.outcome.unwrap();
    assert_eq!(
        body.structured["accepted_intent"],
        "Aim two, materially changed."
    );
    assert_eq!(
        body.structured["declared_model"]["declared"],
        "another-model"
    );
    assert_eq!(
        body.structured["declared_model"]["recorded"],
        "definitely-not-a-known-model-zzz"
    );
    assert_eq!(body.structured["declared_model"]["refused"], true);
    let refusal_note = body.structured["declared_model"]["note"].as_str().unwrap();
    assert!(
        refusal_note.contains("already records declared model 'definitely-not-a-known-model-zzz'"),
        "{refusal_note}"
    );
    assert!(
        refusal_note.contains("is refused and the recorded model is unchanged"),
        "{refusal_note}"
    );
    assert_eq!(
        diverged.run_context["intent"],
        "Aim two, materially changed."
    );
    assert!(
        body.structured["briefing"]["availability"]["status"] == "available",
        "the briefing is still returned: {}",
        body.structured["briefing"]["availability"]
    );
    let kept: Option<String> =
        sqlx::query_scalar("SELECT reported_model FROM agent_runs WHERE run_key=?")
            .bind(RUN)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(kept.as_deref(), Some(model));

    // The text render carries the refusal without inventing more.
    let refused_text = native_ce::mcp::render::render("set_intent", &body.structured).unwrap();
    assert!(
        refused_text.contains("The declaration of another-model was refused"),
        "{refused_text}"
    );
    assert!(
        refused_text.contains("Intent accepted: Aim two, materially changed."),
        "{refused_text}"
    );

    // The operation description teaches the rule at the point of declaring.
    let schema = &registry.get("set_intent").unwrap().input_schema;
    assert_eq!(schema["properties"]["model"]["type"], "string");
    assert!(schema["properties"]["model"]["description"]
        .as_str()
        .unwrap()
        .contains("first declaration wins"));
    let required = schema["required"].as_array().unwrap();
    assert!(required.contains(&json!("intent")));
    assert!(!required.contains(&json!("model")), "model stays optional");
    let description = &registry.get("set_intent").unwrap().description;
    assert!(
        description.contains("first declaration wins"),
        "{description}"
    );
    assert!(description.contains("grants nothing"), "{description}");

    // The text render confirms what was recorded without inventing more.
    let rendered = native_ce::mcp::render::render("set_intent", &result).unwrap();
    assert!(
        rendered.contains("Declared model recorded for this run: definitely-not-a-known-model-zzz"),
        "{rendered}"
    );
    db.close().await;
}

#[tokio::test]
async fn set_intent_declared_model_is_length_bounded_not_rejected() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let long = format!("{}é", "m".repeat(300));

    let result = call(
        &registry,
        &db,
        "set_intent",
        json!({ "intent": "Declare long.", "model": long, "run_key": RUN }),
    )
    .await;
    // The declaration itself stands: length never rejects admission.
    assert_eq!(result["declared_model"]["declared"], long);
    let recorded = result["declared_model"]["recorded"].as_str().unwrap();
    assert_eq!(recorded, "m".repeat(256));
    assert!(recorded.is_char_boundary(recorded.len()));
    db.close().await;
}

#[tokio::test]
async fn declared_model_changes_no_routing_permission_gating_or_rendering_decision() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let model = "ledger-model-a";
    let intent = "Same declared aim on both runs.";

    let with_model = call(
        &registry,
        &db,
        "set_intent",
        json!({ "intent": intent, "model": model, "run_key": RUN }),
    )
    .await;
    let without_model = call(
        &registry,
        &db,
        "set_intent",
        json!({ "intent": intent, "run_key": OTHER_RUN }),
    )
    .await;
    // The one sanctioned difference: the confirmation itself.
    assert_eq!(with_model["declared_model"]["recorded"], model);
    assert_eq!(without_model["declared_model"]["recorded"], Value::Null);
    // Everything the run uses to decide is identical.
    assert_eq!(
        with_model["accepted_intent"],
        without_model["accepted_intent"]
    );
    assert_eq!(
        with_model["briefing_version"],
        without_model["briefing_version"]
    );
    assert_eq!(
        with_model["briefing"]["availability"],
        without_model["briefing"]["availability"]
    );

    // Permission: a visible record reads identically from both runs; a
    // record gated to another account refuses both runs with the same
    // refusal. Neither decision consults the declared model.
    let visible = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Document", "name": "Visible to acct:test", "run_key": RUN }),
    )
    .await;
    let mut reads = Vec::new();
    for run in [RUN, OTHER_RUN] {
        let seen = registry
            .call(
                db.clone(),
                Caller::authenticated("acct:test"),
                "get_record",
                crate::common::with_test_reason(
                    "get_record",
                    json!({ "ids": [visible["id"]], "run_key": run }),
                ),
            )
            .await
            .unwrap();
        assert_eq!(seen["records"][0]["status"], "found", "run {run}");
        reads.push(seen["records"].clone());
    }
    assert_eq!(reads[0], reads[1], "model must not change a read");
    let gated = native_ce::store::create_record(
        &db,
        json!({"type": "Document", "kind": "x-test-fixture", "name": "Gated record"}),
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        "test:policy",
        &gated,
        vec![AllowEntry::account("acct:revoked", Capability::Manage)],
    )
    .await
    .unwrap();
    let mut refusals = Vec::new();
    for run in [RUN, OTHER_RUN] {
        let refused = registry
            .call(
                db.clone(),
                Caller::authenticated("acct:test"),
                "start_work",
                crate::common::with_test_reason(
                    "start_work",
                    json!({ "record_id": gated, "run_key": run }),
                ),
            )
            .await
            .unwrap_err()
            .to_string();
        refusals.push(refused);
    }
    assert!(refusals[0].contains("does not exist"), "{}", refusals[0]);
    assert_eq!(refusals[0], refusals[1], "model must not change refusal");

    // Gating: each run can claim its own work identically.
    for (run, name) in [
        (RUN, "Claimed under model"),
        (OTHER_RUN, "Claimed without model"),
    ] {
        let record = call(
            &registry,
            &db,
            "create_record",
            json!({
                "type": "WorkItem", "kind": "task",
                "name": name, "lifecycle": "open", "run_key": run,
            }),
        )
        .await;
        let claimed = call(
            &registry,
            &db,
            "start_work",
            json!({ "record_id": record["id"], "run_key": run }),
        )
        .await;
        assert_eq!(claimed["record_id"], record["id"], "run {run}");
        assert_eq!(claimed["claimed"], true, "run {run}");
    }

    // Rendering: the model string reaches no other surface's text, and the
    // set_intent texts differ only by the confirmation line.
    for run in [RUN, OTHER_RUN] {
        let dashboard = call(&registry, &db, "get_dashboard", json!({ "run_key": run })).await;
        let text = native_ce::mcp::render::render("get_dashboard", &dashboard).unwrap();
        assert!(
            !text.contains(model),
            "dashboard text for run {run}: {text}"
        );
    }
    let with_text = native_ce::mcp::render::render("set_intent", &with_model).unwrap();
    assert!(
        with_text.contains("Declared model recorded for this run: ledger-model-a"),
        "{with_text}"
    );
    let without_text = native_ce::mcp::render::render("set_intent", &without_model).unwrap();
    assert!(
        without_text.contains("Declared model: none recorded for this run."),
        "{without_text}"
    );
    db.close().await;
}

#[tokio::test]
async fn set_intent_bootstrap_names_declared_model_guidance() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let bootstrap = registry
        .call(
            db.clone(),
            Caller::local(),
            "bootstrap",
            crate::common::with_test_reason("bootstrap", json!({})),
        )
        .await
        .unwrap();
    db.drain_captures_for_tests().await;
    let guidance = &bootstrap["intentful_sessions"]["declared_model"];
    assert!(
        guidance["how"]
            .as_str()
            .unwrap()
            .contains("first set_intent"),
        "{guidance}"
    );
    assert!(
        guidance["why"]
            .as_str()
            .unwrap()
            .contains("knows which model claimed it"),
        "{guidance}"
    );
    assert!(
        guidance["why"]
            .as_str()
            .unwrap()
            .contains("evaluation ledger"),
        "{guidance}"
    );
    assert!(
        guidance["limits"]
            .as_str()
            .unwrap()
            .contains("grants nothing"),
        "{guidance}"
    );
    assert!(
        guidance["limits"].as_str().unwrap().contains("per-run"),
        "{guidance}"
    );
    assert!(
        guidance["limits"]
            .as_str()
            .unwrap()
            .contains("no launcher-independent source"),
        "{guidance}"
    );
    let text = native_ce::mcp::render::render("bootstrap", &bootstrap).unwrap();
    assert!(text.contains("self-declare its model"), "{text}");
    db.close().await;
}

// ---------------------------------------------------------------------------
// Declared source basis per episode (slice E): declarations fold
// `native.source-basis.v1` envelopes on content events, not touch rows.
// ---------------------------------------------------------------------------

/// A `create_record` in `run` citing `sources`, returning the new id.
async fn declare_write(
    registry: &ToolRegistry,
    db: &Db,
    run: &str,
    name: &str,
    sources: Value,
) -> String {
    call(
        registry,
        db,
        "create_record",
        json!({
            "type": "Document",
            "kind": "note",
            "name": name,
            "body": format!("Work resting on {name}."),
            "sources": sources,
            "run_key": run,
        }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn declare_intent(registry: &ToolRegistry, db: &Db, run: &str, intent: &str) -> Value {
    call(
        registry,
        db,
        "set_intent",
        json!({ "intent": intent, "run_key": run }),
    )
    .await
}

fn episode_items(result: &Value) -> Vec<Value> {
    result["briefing"]["this_run"]["declarations"]["items"]
        .as_array()
        .unwrap()
        .clone()
}

fn episode_source_ids(episode: &Value) -> Vec<String> {
    episode["touched_records"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["id"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn an_episode_folds_declared_sources_and_ignores_mere_touches() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let run = "scout-chair-a748b2";

    let source = declare_write(&registry, &db, run, "cited-source", json!([])).await;
    let opened_only = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Document", "kind": "note", "name": "opened-only", "run_key": run }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_string();

    declare_intent(&registry, &db, run, "First episode").await;
    // Touched but never declared: opened after the declaration, so a
    // touch-based fold would list it in this episode.
    call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": [opened_only], "run_key": run }),
    )
    .await;
    declare_write(
        &registry,
        &db,
        run,
        "citing-write",
        json!([{ "record_id": source, "reason": "the reading this rested on", "role": "primary" }]),
    )
    .await;
    let result = declare_intent(&registry, &db, run, "Second episode").await;

    let items = episode_items(&result);
    // One durable declaration plus the pending one, which stays empty until
    // a write under it declares sources.
    assert_eq!(items.len(), 2);
    assert_eq!(items[1]["intent"], "Second episode");
    assert_eq!(items[1]["touched_records"]["items"], json!([]));

    let first = &items[0];
    assert_eq!(first["intent"], "First episode");
    let ids = episode_source_ids(first);
    assert_eq!(ids, vec![source.clone()], "{first}");
    let item = &first["touched_records"]["items"][0];
    assert_eq!(item["name"], "cited-source");
    assert_eq!(item["type"], "Document");
    assert_eq!(item["reason"], "the reading this rested on");
    assert_eq!(item["role"], "primary");
    assert!(item["revision_event_id"].as_str().is_some(), "{item}");
    assert_eq!(item["revision_supplied_by"], "engine");
    assert!(
        item.get("interactions").is_none(),
        "touches were not consulted: {item}"
    );
    assert!(
        !ids.contains(&opened_only),
        "a touched-only record is not a declared source: {ids:?}"
    );
    db.close().await;
}

#[tokio::test]
async fn declared_none_and_absent_writes_yield_no_source_items() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let run = "scout-chair-a748b2";

    declare_intent(&registry, &db, run, "None episode").await;
    declare_write(&registry, &db, run, "rests-on-nothing", json!([])).await;
    declare_intent(&registry, &db, run, "Silent episode").await;
    call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Document", "kind": "note", "name": "says-nothing", "run_key": run }),
    )
    .await;
    let result = declare_intent(&registry, &db, run, "Tail").await;

    let items = episode_items(&result);
    assert_eq!(items.len(), 3);
    for episode in &items[0..2] {
        assert_eq!(episode["touched_records"]["items"], json!([]), "{episode}");
        assert_eq!(episode["touched_records"]["total_count"], 0, "{episode}");
        assert_eq!(episode["touched_records"]["truncated"], false, "{episode}");
    }
    db.close().await;
}

/// Episodes are temporal windows between declaration response times. This
/// fixture is built so both plausible shortcuts give the wrong answer:
/// - `read_log_calls.seq` vs `content_events.seq` are unrelated counters,
///   and the read burst below pushes every declaration's read-log seq far
///   past the citing writes' content seqs, so any cross-tier seq comparison
///   drops the writes out of their episodes;
/// - both episodes declare the byte-identical intent text, so grouping by
///   intent text merges the two episodes into one.
/// Timestamps are pinned to distinct seconds so the correct temporal
/// attribution is deterministic, not a same-millisecond coin flip.
#[tokio::test]
async fn episodes_hold_under_identical_intent_text_and_diverged_counters() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let run = "scout-chair-a748b2";

    let first_source = declare_write(&registry, &db, run, "first-source", json!([])).await;
    let second_source = declare_write(&registry, &db, run, "second-source", json!([])).await;
    // A read burst: six read-log rows, zero content events. Declaration seqs
    // will run well ahead of content seqs from here on.
    for _ in 0..6 {
        call(
            &registry,
            &db,
            "get_record",
            json!({ "ids": [first_source], "run_key": run }),
        )
        .await;
    }

    declare_intent(&registry, &db, run, "Same aim").await;
    let first_write = declare_write(
        &registry,
        &db,
        run,
        "first-citing",
        json!([{ "record_id": first_source, "reason": "first reading" }]),
    )
    .await;
    declare_intent(&registry, &db, run, "Same aim").await;
    let second_write = declare_write(
        &registry,
        &db,
        run,
        "second-citing",
        json!([{ "record_id": second_source, "reason": "second reading" }]),
    )
    .await;

    // Pin the clocks: declaration responses and citing writes on distinct
    // seconds, in wall order, so temporal windows are exact.
    let pool = crate::common::fixture_write_pool(&db).await;
    let decl_seqs: Vec<i64> = sqlx::query_scalar(
        "SELECT seq FROM read_log_calls WHERE run_key = ? AND tool = 'set_intent' AND outcome = 'ok' ORDER BY seq",
    )
    .bind(run)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(decl_seqs.len(), 2);
    for (seq, stamp) in decl_seqs
        .iter()
        .zip(["2026-09-01T00:00:01.000Z", "2026-09-01T00:00:03.000Z"])
    {
        sqlx::query("UPDATE read_log_calls SET started_at = ?, ended_at = ? WHERE seq = ?")
            .bind(stamp)
            .bind(stamp)
            .bind(seq)
            .execute(&pool)
            .await
            .unwrap();
    }
    // The log is append-only by trigger; a test-only rewrite drops and
    // restores the guard around the surgical timestamp pins.
    let guard: String = sqlx::query_scalar(
        "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'content_events_no_update'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::query("DROP TRIGGER content_events_no_update")
        .execute(&pool)
        .await
        .unwrap();
    for (record, stamp) in [
        (first_write.as_str(), "2026-09-01T00:00:02.000Z"),
        (second_write.as_str(), "2026-09-01T00:00:04.000Z"),
    ] {
        sqlx::query("UPDATE content_events SET created_at = ? WHERE record_id = ?")
            .bind(stamp)
            .bind(record)
            .execute(&pool)
            .await
            .unwrap();
    }
    sqlx::query(&guard).execute(&pool).await.unwrap();
    // The clocks above establish distinct temporal episodes. Read-log and
    // content-event sequences are independent and cannot be compared.

    let result = declare_intent(&registry, &db, run, "Same aim").await;
    let items = episode_items(&result);
    assert_eq!(items.len(), 3);
    assert_eq!(items[0]["intent"], "Same aim");
    assert_eq!(items[1]["intent"], "Same aim");
    assert_eq!(
        episode_source_ids(&items[0]),
        vec![first_source.clone()],
        "first episode must hold exactly its own declaration"
    );
    assert_eq!(
        episode_source_ids(&items[1]),
        vec![second_source.clone()],
        "identical text must not merge episodes"
    );
    assert_eq!(items[2]["touched_records"]["items"], json!([]));
    db.close().await;
}

/// The episode window is half-open: the lower edge is inclusive, the next
/// declaration's `ended_at` is exclusive. A write stamped exactly on the
/// current declaration's response time belongs to that episode; a write
/// stamped exactly on the NEXT declaration's response time belongs only to
/// the new episode, never to both.
#[tokio::test]
async fn an_exact_boundary_write_belongs_only_to_the_new_episode() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let run = "scout-chair-a748b2";

    let first_source = declare_write(&registry, &db, run, "boundary-source-a", json!([])).await;
    let second_source = declare_write(&registry, &db, run, "boundary-source-b", json!([])).await;

    declare_intent(&registry, &db, run, "Episode A").await;
    let first_write = declare_write(
        &registry,
        &db,
        run,
        "boundary-citing-a",
        json!([{ "record_id": first_source, "reason": "read before the boundary" }]),
    )
    .await;
    declare_intent(&registry, &db, run, "Episode B").await;
    let second_write = declare_write(
        &registry,
        &db,
        run,
        "boundary-citing-b",
        json!([{ "record_id": second_source, "reason": "read exactly at the boundary" }]),
    )
    .await;

    // Pin the clocks so the exact-equality case is deterministic: decl A and
    // its write share one second; decl B and its write share the next.
    let pool = crate::common::fixture_write_pool(&db).await;
    let decl_seqs: Vec<i64> = sqlx::query_scalar(
        "SELECT seq FROM read_log_calls WHERE run_key = ? AND tool = 'set_intent' AND outcome = 'ok' ORDER BY seq",
    )
    .bind(run)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(decl_seqs.len(), 2);
    for (seq, stamp) in decl_seqs.iter().zip([
        "2026-09-02T00:00:01.000Z", // Episode A's response time.
        "2026-09-02T00:00:02.000Z", // Episode B's response time.
    ]) {
        sqlx::query("UPDATE read_log_calls SET started_at = ?, ended_at = ? WHERE seq = ?")
            .bind(stamp)
            .bind(stamp)
            .bind(seq)
            .execute(&pool)
            .await
            .unwrap();
    }
    // The log is append-only by trigger; a test-only rewrite drops and
    // restores the guard around the surgical timestamp pins.
    let guard: String = sqlx::query_scalar(
        "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'content_events_no_update'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::query("DROP TRIGGER content_events_no_update")
        .execute(&pool)
        .await
        .unwrap();
    for (record, stamp) in [
        // Lower edge of A: inclusive, so this write is in A.
        (first_write.as_str(), "2026-09-02T00:00:01.000Z"),
        // Lower edge of B and upper edge of A: exclusive at A's end, so this
        // write is in B only.
        (second_write.as_str(), "2026-09-02T00:00:02.000Z"),
    ] {
        sqlx::query("UPDATE content_events SET created_at = ? WHERE record_id = ?")
            .bind(stamp)
            .bind(record)
            .execute(&pool)
            .await
            .unwrap();
    }
    sqlx::query(&guard).execute(&pool).await.unwrap();

    let result = declare_intent(&registry, &db, run, "Tail").await;
    let items = episode_items(&result);
    assert_eq!(items.len(), 3);
    assert_eq!(items[0]["intent"], "Episode A");
    assert_eq!(items[1]["intent"], "Episode B");
    assert_eq!(
        episode_source_ids(&items[0]),
        vec![first_source.clone()],
        "a write exactly on the lower edge belongs to the episode"
    );
    assert_eq!(
        episode_source_ids(&items[1]),
        vec![second_source.clone()],
        "a write exactly on the next declaration's ended_at belongs only to the new episode"
    );
    // The boundary write must not be double-counted into the closed episode.
    assert!(
        !episode_source_ids(&items[0]).contains(&second_source),
        "the boundary write leaked into the earlier episode"
    );
    db.close().await;
}

#[tokio::test]
async fn a_hidden_declared_source_is_omitted_from_its_episode() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let run = "scout-chair-a748b2";

    // Created with no run and no owner: the only trace of these records in
    // this run's briefing is the declaration itself, so the visibility
    // assertion below isolates the declared-source fold rather than the
    // touch surfaces. Ownership retains visibility past explicit policy, so
    // the secret is store-created (ownerless) where an ordinary create would
    // keep it visible to its author no matter the policy.
    let secret = native_ce::store::create_record(
        &db,
        json!({ "type": "Document", "kind": "note", "name": "episode-secret" }),
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        "test:policy",
        &secret,
        vec![AllowEntry::account("acct:test", Capability::Manage)],
    )
    .await
    .unwrap();
    let open = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Document", "kind": "note", "name": "episode-open", "sources": [] }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_string();
    declare_intent(&registry, &db, run, "Filtered episode").await;
    declare_write(
        &registry,
        &db,
        run,
        "filtered-citing",
        json!([
            { "record_id": secret, "reason": "the confidential reading" },
            { "record_id": open, "reason": "the ordinary reading" },
        ]),
    )
    .await;

    replace_explicit_policy(
        &db,
        "test:policy",
        &secret,
        vec![AllowEntry::account("someone-else", Capability::Manage)],
    )
    .await
    .unwrap();

    let result = declare_intent(&registry, &db, run, "Tail").await;
    let serialized = result.to_string();
    assert!(
        !serialized.contains(&secret),
        "a hidden source must leak neither name nor existence"
    );
    assert!(serialized.contains(&open));
    let items = episode_items(&result);
    let episode = &items[0];
    assert_eq!(episode_source_ids(episode), vec![open]);
    // The hidden source is not even counted: its existence is undisclosed.
    assert_eq!(episode["touched_records"]["total_count"], 1);
    db.close().await;
}

#[tokio::test]
async fn episode_sources_deduplicate_and_stay_bounded() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let run = "scout-chair-a748b2";

    declare_intent(&registry, &db, run, "Crowded episode").await;
    let repeated = declare_write(&registry, &db, run, "repeated-source", json!([])).await;
    declare_write(
        &registry,
        &db,
        run,
        "first-cite",
        json!([{ "record_id": repeated, "reason": "first reading" }]),
    )
    .await;
    declare_write(
        &registry,
        &db,
        run,
        "second-cite",
        json!([{ "record_id": repeated, "reason": "second reading" }]),
    )
    .await;
    for index in 0..20 {
        let extra = declare_write(
            &registry,
            &db,
            run,
            &format!("extra-source-{index}"),
            json!([]),
        )
        .await;
        declare_write(
            &registry,
            &db,
            run,
            &format!("extra-cite-{index}"),
            json!([{ "record_id": extra, "reason": "extra reading" }]),
        )
        .await;
    }
    let result = declare_intent(&registry, &db, run, "Tail").await;

    let items = episode_items(&result);
    let episode = &items[0];
    let window = &episode["touched_records"];
    // 22 citations of 21 distinct records: the twice-cited one counts once.
    assert_eq!(window["total_count"], 21);
    assert_eq!(window["truncated"], true);
    assert_eq!(window["items"].as_array().unwrap().len(), 20);
    let ids = episode_source_ids(episode);
    let mut sorted = ids.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), ids.len(), "no duplicate items: {ids:?}");
    db.close().await;
}
