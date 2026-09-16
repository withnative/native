//! `get_record(include_history_summary)` — opt-in oldest/newest visible-event
//! attribution for bylines, exercised through the registry like any caller.
//!
//! The summary must match what two `limit: 1` metadata `get_history` reads
//! (oldest-first and newest-first) report for the same record and viewer —
//! same visibility, same redaction, same actor names, same metadata shape —
//! while `contribution.revision` deliberately keeps answering a different
//! question (the last *body* change).

use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::store::{create_record, update_record};
use native_ce::{create_database, Db};
use serde_json::{json, Value};

async fn db() -> Db {
    // Full genesis (schema, root folders, root policy, identity): bound
    // member accounts can author and read ordinary records.
    create_database(":memory:").await.unwrap()
}

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

async fn call(registry: &ToolRegistry, db: &Db, tool: &str, args: Value) -> Value {
    let result = registry
        .call(
            db.clone(),
            Caller::local(),
            tool,
            crate::common::with_test_reason(tool, args),
        )
        .await
        .unwrap();
    db.drain_captures_for_tests().await;
    result
}

async fn call_as(
    registry: &ToolRegistry,
    db: &Db,
    caller: Caller,
    tool: &str,
    args: Value,
) -> Value {
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
    let error = registry
        .call(
            db.clone(),
            Caller::local(),
            tool,
            crate::common::with_test_reason(tool, args),
        )
        .await
        .unwrap_err()
        .to_string();
    db.drain_captures_for_tests().await;
    error
}

fn record<'a>(out: &'a Value, id: &str) -> &'a Value {
    out["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"] == json!(id))
        .unwrap()
}

async fn limit1(registry: &ToolRegistry, db: &Db, caller: Caller, id: &str, order: &str) -> Value {
    call_as(
        registry,
        db,
        caller,
        "get_history",
        json!({ "record_id": id, "limit": 1, "order": order, "detail": "metadata" }),
    )
    .await["events"][0]
        .clone()
}

#[tokio::test]
async fn history_summary_matches_limit1_metadata_and_tracks_non_body_touches() {
    let db = db().await;
    let registry = registry();
    let id = create_record(
        &db,
        json!({ "type": "Document", "kind": "note", "name": "first", "body": "v1" }),
    )
    .await
    .unwrap();
    // A name-only update touches the record without producing a new body, so
    // the latest visible event must move while contribution.revision stays
    // on the creation event.
    update_record(&db, &id, json!({ "name": "second" }))
        .await
        .unwrap();

    let out = call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": [id], "include_history_summary": true }),
    )
    .await;
    assert_eq!(out["include_history_summary"], json!(true));
    let found = record(&out, &id);
    let summary = &found["history_summary"];
    assert_eq!(summary["oldest"]["type"], "record.created");
    assert_eq!(summary["latest"]["type"], "record.updated");
    assert_ne!(summary["oldest"]["id"], summary["latest"]["id"]);
    // Metadata shape: no payload, size + changed fields instead.
    assert!(summary["latest"].get("payload").is_none());
    assert_eq!(summary["latest"]["payload_omitted"], true);
    assert_eq!(summary["latest"]["changed_fields"], json!(["name"]));

    // Exact parity with the two one-event metadata reads the workbench
    // byline used to issue.
    let oldest = limit1(&registry, &db, Caller::local(), &id, "oldest_first").await;
    let latest = limit1(&registry, &db, Caller::local(), &id, "newest_first").await;
    assert_eq!(summary["oldest"], oldest);
    assert_eq!(summary["latest"], latest);

    // contribution.revision answers the last body change, not the latest
    // touch: it still names the creation event.
    assert_eq!(found["contribution"]["revision"]["event_id"], oldest["id"]);
}

#[tokio::test]
async fn history_summary_is_absent_unless_opted_in() {
    let db = db().await;
    let registry = registry();
    let id = create_record(
        &db,
        json!({ "type": "Document", "kind": "note", "name": "plain" }),
    )
    .await
    .unwrap();

    let out = call(&registry, &db, "get_record", json!({ "ids": [id] })).await;
    assert!(record(&out, &id).get("history_summary").is_none());
    assert_eq!(out["include_history_summary"], json!(false));
}

#[tokio::test]
async fn history_summary_single_event_names_both_ends() {
    let db = db().await;
    let registry = registry();
    let id = create_record(
        &db,
        json!({ "type": "Document", "kind": "note", "name": "only" }),
    )
    .await
    .unwrap();

    let out = call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": [id], "include_history_summary": true }),
    )
    .await;
    let summary = &record(&out, &id)["history_summary"];
    assert_eq!(summary["oldest"]["type"], "record.created");
    assert_eq!(summary["oldest"]["id"], summary["latest"]["id"]);
}

#[tokio::test]
async fn history_summary_reports_null_ends_for_a_record_without_history() {
    let db = db().await;
    let registry = registry();
    // A bare projected row with no content log behind it: the capability key
    // is present, but there is no visible event on either end.
    let id = "9e7e0000-0000-4000-8000-000000000099";
    sqlx::query("INSERT INTO records (id, type) VALUES (?, 'Document')")
        .bind(id)
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();

    let out = call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": [id], "include_history_summary": true }),
    )
    .await;
    let found = record(&out, id);
    assert_eq!(found["status"], "found");
    assert_eq!(
        found["history_summary"],
        json!({ "oldest": null, "latest": null })
    );
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

#[tokio::test]
async fn history_summary_redaction_matches_history_for_an_outsider() {
    let db = db().await;
    let registry = registry();
    // Bound members: the writer can author, the viewer can read, but the
    // writer's actor is not disclosable to the viewer.
    let writer_person = create_record(
        &db,
        json!({ "type": "Entity", "kind": "person", "name": "Writer" }),
    )
    .await
    .unwrap();
    let viewer_person = create_record(
        &db,
        json!({ "type": "Entity", "kind": "person", "name": "Viewer" }),
    )
    .await
    .unwrap();
    bind_account(&db, &writer_person, "acct:writer").await;
    bind_account(&db, &viewer_person, "acct:viewer").await;
    // The writer's person record is visible only to the writer, so the
    // writer's actor is not disclosable to anyone else — while records the
    // writer authors stay world-readable.
    let pool = crate::common::fixture_write_pool(&db).await;
    sqlx::query("INSERT INTO record_policies(record_id) VALUES(?)")
        .bind(&writer_person)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE records SET policy_anchor_id=? WHERE id=?")
        .bind(&writer_person)
        .bind(&writer_person)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO policy_entries(policy_anchor_id,subject_kind,subject_id,effect,capability) \
         VALUES(?,'account','acct:writer','allow','manage')",
    )
    .bind(&writer_person)
    .execute(&pool)
    .await
    .unwrap();
    let writer = Caller::authenticated("acct:writer");
    // Unbound outsider: can read ordinary records but is owed no actor
    // disclosure, so redaction engages on both paths under test.
    let viewer = Caller::authenticated("acct:outsider");
    let created = call_as(
        &registry,
        &db,
        writer.clone(),
        "create_record",
        json!({ "type": "Document", "kind": "note", "name": "wrote" }),
    )
    .await;
    let id = created["id"].as_str().unwrap().to_string();
    call_as(
        &registry,
        &db,
        writer,
        "update_record",
        json!({ "id": id, "name": "rewrote" }),
    )
    .await;

    // The stored actor is the writer: redaction has something to withhold.
    let stored = limit1(&registry, &db, Caller::local(), &id, "newest_first").await;
    assert_eq!(stored["actor"], "acct:writer");

    let out = call_as(
        &registry,
        &db,
        viewer.clone(),
        "get_record",
        json!({ "ids": [id], "include_history_summary": true }),
    )
    .await;
    let summary = &record(&out, &id)["history_summary"];
    assert!(summary["oldest"]["actor"].is_null());
    assert!(summary["latest"]["actor"].is_null());
    assert!(summary["latest"]["run_key"].is_null());

    // Parity under the same viewer: identical redacted ends.
    let oldest = limit1(&registry, &db, viewer.clone(), &id, "oldest_first").await;
    let latest = limit1(&registry, &db, viewer, &id, "newest_first").await;
    assert_eq!(summary["oldest"], oldest);
    assert_eq!(summary["latest"], latest);
}

/// Store one `occurrence.bound.v1` row below the public append seam: a
/// well-formed envelope whose artefact subject is `subject_id`. Whether a
/// viewer sees it turns only on `View` of that subject, which is what makes
/// it a hidden event rather than a malformed one.
async fn insert_hidden_occurrence(db: &Db, record_id: &str, subject_id: &str, tag: &str) {
    let payload = json!({
        "semantic_contract_version": "native.freshness-kernel.v1",
        "occurrence_id": format!("occ-hidden-{tag}"),
        "unit_revision": {
            "subject_kind": "unit",
            "subject_id": format!("unit-hidden-{tag}"),
            "revision_event_id": format!("event-unit-hidden-{tag}"),
            "revision_seq": 1,
            "source_slot": "unit_content",
            "sha256": "a".repeat(64),
        },
        "artefact_revision": {
            "subject_kind": "artefact",
            "subject_id": subject_id,
            "revision_event_id": format!("event-artefact-hidden-{tag}"),
            "revision_seq": 1,
            "source_slot": "record_body",
            "sha256": "b".repeat(64),
        },
        "selectors": [{ "type": "text_quote", "exact": "hidden phrase" }],
        "expression_role": "quotation",
        "command": {
            "operation": "bind",
            "scope_record_id": subject_id,
            "idempotency_key": format!("hidden-{tag}"),
            "intent_sha256": "c".repeat(64),
            "authorization_revision_observed": 0,
        },
    });
    sqlx::query(
        "INSERT INTO content_events
            (id, record_id, type, payload, actor, created_at, causal_envelope_version, causal_status)
         VALUES (?, ?, 'occurrence.bound.v1', ?, 'acct:writer',
                 strftime('%Y-%m-%dT%H:%M:%fZ', '2026-08-02T00:00:00Z'), 1, 'legacy_unknown')",
    )
    .bind(format!("event:hidden-{tag}"))
    .bind(record_id)
    .bind(payload.to_string())
    .execute(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap();
}

#[tokio::test]
async fn history_summary_skips_hidden_events_at_both_ends() {
    let db = db().await;
    let registry = registry();
    let writer_person = create_record(
        &db,
        json!({ "type": "Entity", "kind": "person", "name": "Writer" }),
    )
    .await
    .unwrap();
    let viewer_person = create_record(
        &db,
        json!({ "type": "Entity", "kind": "person", "name": "Viewer" }),
    )
    .await
    .unwrap();
    bind_account(&db, &writer_person, "acct:writer").await;
    bind_account(&db, &viewer_person, "acct:viewer").await;
    // The writer's person record doubles as the hidden occurrence subject:
    // visible only to the writer, so the occurrence rows below are hidden
    // events for the viewer but ordinary visible ones for the writer.
    let pool = crate::common::fixture_write_pool(&db).await;
    sqlx::query("INSERT INTO record_policies(record_id) VALUES(?)")
        .bind(&writer_person)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE records SET policy_anchor_id=? WHERE id=?")
        .bind(&writer_person)
        .bind(&writer_person)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO policy_entries(policy_anchor_id,subject_kind,subject_id,effect,capability) \
         VALUES(?,'account','acct:writer','allow','manage')",
    )
    .bind(&writer_person)
    .execute(&pool)
    .await
    .unwrap();
    let writer = Caller::authenticated("acct:writer");
    let viewer = Caller::authenticated("acct:viewer");

    // Fixed id so a hidden row can lead the stream: the cursor loop must
    // advance past it from the oldest end, and past the trailing one from
    // the newest end.
    let id = "9e7e0000-0000-4000-8000-000000000097";
    insert_hidden_occurrence(&db, id, &writer_person, "before").await;
    call_as(
        &registry,
        &db,
        writer.clone(),
        "create_record",
        json!({ "id": id, "type": "Document", "kind": "note", "name": "edged" }),
    )
    .await;
    insert_hidden_occurrence(&db, id, &writer_person, "after").await;
    call_as(
        &registry,
        &db,
        writer.clone(),
        "update_record",
        json!({ "id": id, "name": "edged twice" }),
    )
    .await;

    // The writer sees every row, hidden ends included: the envelope parses
    // and only subject visibility hides it, so this also proves the rows are
    // well-formed rather than skipped as malformed.
    let writer_out = call_as(
        &registry,
        &db,
        writer.clone(),
        "get_record",
        json!({ "ids": [id], "include_history_summary": true }),
    )
    .await;
    let writer_summary = &record(&writer_out, id)["history_summary"];
    assert_eq!(writer_summary["oldest"]["type"], "occurrence.bound.v1");
    assert_eq!(writer_summary["oldest"]["id"], "event:hidden-before");
    assert_eq!(writer_summary["latest"]["type"], "record.updated");
    let writer_oldest = limit1(&registry, &db, writer, id, "oldest_first").await;
    assert_eq!(writer_summary["oldest"], writer_oldest);

    // The viewer steps over both hidden rows to the visible middle.
    let out = call_as(
        &registry,
        &db,
        viewer.clone(),
        "get_record",
        json!({ "ids": [id], "include_history_summary": true }),
    )
    .await;
    let summary = &record(&out, id)["history_summary"];
    assert_eq!(summary["oldest"]["type"], "record.created");
    assert_eq!(summary["latest"]["type"], "record.updated");
    let oldest = limit1(&registry, &db, viewer.clone(), id, "oldest_first").await;
    let latest = limit1(&registry, &db, viewer, id, "newest_first").await;
    assert_eq!(summary["oldest"], oldest);
    assert_eq!(summary["latest"], latest);
}

#[tokio::test]
async fn history_summary_cannot_combine_with_as_of() {
    let db = db().await;
    let registry = registry();
    let id = create_record(
        &db,
        json!({ "type": "Document", "kind": "note", "name": "pinned" }),
    )
    .await
    .unwrap();
    let history = call(
        &registry,
        &db,
        "get_history",
        json!({ "record_id": id, "limit": 1 }),
    )
    .await;
    let seq = history["events"][0]["local_seq"].as_i64().unwrap();

    let err = call_err(
        &registry,
        &db,
        "get_record",
        json!({ "ids": [id], "include_history_summary": true, "as_of": { "content_seq": seq } }),
    )
    .await;
    assert!(
        err.contains("include_history_summary cannot be combined with as_of"),
        "{err}"
    );
}
