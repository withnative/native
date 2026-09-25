//! `get_event_context` — the moment projection behind a byline deep-link.
//!
//! The distinctions under test are the ones a reader would otherwise get
//! wrong: an exact historical delta versus a diff against the current body,
//! opened versus surfaced, one open versus three, an empty list versus an
//! unavailable log, and a bounded list versus a complete one.

use native_ce::mcp::{register_surface_tools, render, Caller, ToolRegistry};
use native_ce::provenance::Channel;
use native_ce::{create_database, Db};
use serde_json::{json, Value};

// Fixture record ids. Record ids must be canonical lowercase v4/v7 UUIDs,
// so these pinned literals stand in for the readable slugs they are named
// after. They are hardcoded rather than generated so assertions stay
// deterministic.
/// `richard`
const RICHARD: &str = "e0e70000-0000-4000-8000-000000000001";
/// `addressed`
const ADDRESSED: &str = "e0e70000-0000-4000-8000-000000000002";
/// `edited`
const EDITED: &str = "e0e70000-0000-4000-8000-000000000003";
/// `born`
const BORN: &str = "e0e70000-0000-4000-8000-000000000004";
/// `renamed`
const RENAMED: &str = "e0e70000-0000-4000-8000-000000000005";
/// `early`
const EARLY: &str = "e0e70000-0000-4000-8000-000000000006";
/// `late`
const LATE: &str = "e0e70000-0000-4000-8000-000000000007";
/// `alpha`
const ALPHA: &str = "e0e70000-0000-4000-8000-000000000008";
/// `beta`
const BETA: &str = "e0e70000-0000-4000-8000-000000000009";
/// `subject`
const SUBJECT: &str = "e0e70000-0000-4000-8000-00000000000a";
/// `opened-one`
const OPENED_ONE: &str = "e0e70000-0000-4000-8000-00000000000b";
/// `merely-surfaced`
const MERELY_SURFACED: &str = "e0e70000-0000-4000-8000-00000000000c";
/// `surfaced-subject`
const SURFACED_SUBJECT: &str = "e0e70000-0000-4000-8000-00000000000d";
/// `self-target`
const SELF_TARGET: &str = "e0e70000-0000-4000-8000-00000000000e";
/// `before-boundary`
const BEFORE_BOUNDARY: &str = "e0e70000-0000-4000-8000-00000000000f";
/// `after-boundary`
const AFTER_BOUNDARY: &str = "e0e70000-0000-4000-8000-000000000010";
/// `episode-subject`
const EPISODE_SUBJECT: &str = "e0e70000-0000-4000-8000-000000000011";
/// `bulk-subject`
const BULK_SUBJECT: &str = "e0e70000-0000-4000-8000-000000000012";
/// `secret-source`
const SECRET_SOURCE: &str = "e0e70000-0000-4000-8000-000000000013";
/// `open-source`
const OPEN_SOURCE: &str = "e0e70000-0000-4000-8000-000000000014";
/// `filtered-subject`
const FILTERED_SUBJECT: &str = "e0e70000-0000-4000-8000-000000000015";
/// `logless`
const LOGLESS: &str = "e0e70000-0000-4000-8000-000000000016";
/// `limited`
const LIMITED: &str = "e0e70000-0000-4000-8000-000000000017";
/// `queried`
const QUERIED: &str = "e0e70000-0000-4000-8000-000000000018";
/// `query-subject`
const QUERY_SUBJECT: &str = "e0e70000-0000-4000-8000-000000000019";
/// `neighbour-one`
const NEIGHBOUR_ONE: &str = "e0e70000-0000-4000-8000-00000000001a";
/// `neighbour-two`
const NEIGHBOUR_TWO: &str = "e0e70000-0000-4000-8000-00000000001b";
/// `neighbour-three`
const NEIGHBOUR_THREE: &str = "e0e70000-0000-4000-8000-00000000001c";
/// `other-run`
const OTHER_RUN: &str = "e0e70000-0000-4000-8000-00000000001d";
/// `basis-caller-source`
const BASIS_CALLER_SOURCE: &str = "e0e70000-0000-4000-8000-00000000001e";
/// `basis-engine-source`
const BASIS_ENGINE_SOURCE: &str = "e0e70000-0000-4000-8000-00000000001f";
/// `basis-citing`
const BASIS_CITING: &str = "e0e70000-0000-4000-8000-000000000020";
/// `basis-none`
const BASIS_NONE: &str = "e0e70000-0000-4000-8000-000000000021";
/// `basis-absent`
const BASIS_ABSENT: &str = "e0e70000-0000-4000-8000-000000000022";
/// `basis-self-target`
const BASIS_SELF_TARGET: &str = "e0e70000-0000-4000-8000-000000000023";
/// `basis-secret`
const BASIS_SECRET: &str = "e0e70000-0000-4000-8000-000000000024";
/// `basis-open`
const BASIS_OPEN: &str = "e0e70000-0000-4000-8000-000000000025";
/// `basis-filtered-subject`
const BASIS_FILTERED_SUBJECT: &str = "e0e70000-0000-4000-8000-000000000026";
/// `basis-reshaped`
const BASIS_RESHAPED: &str = "e0e70000-0000-4000-8000-000000000027";

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

/// A database whose `local` credential has a portable account binding, which
/// ordinary authoring requires.
async fn fixture() -> (Db, ToolRegistry) {
    let db = create_database(":memory:").await.unwrap();
    native_ce::meta::seed_vocabularies(&db).await.unwrap();
    let registry = registry();
    // Created as the trusted local caller, which is exempt from the binding
    // requirement it is about to satisfy.
    registry
        .call(
            db.clone(),
            Caller::local(),
            "create_record",
            crate::common::with_test_reason(
                "create_record",
                json!({ "id": RICHARD, "type": "Entity", "kind": "person", "name": "Richard" }),
            ),
        )
        .await
        .unwrap();
    sqlx::query(&format!(
        "INSERT INTO bindings(record_id,system,identifier,is_canonical)
         VALUES('{RICHARD}','account','local',1)"
    ))
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    (db, registry)
}

fn agent() -> Caller {
    Caller::authenticated("local").with_channel(Channel::Mcp)
}

fn in_run(run_key: &str, mut args: Value) -> Value {
    args.as_object_mut()
        .expect("tool arguments are an object")
        .insert("run_key".into(), json!(run_key));
    args
}

async fn call(registry: &ToolRegistry, db: &Db, tool: &str, args: Value) -> Value {
    let result = registry
        .call(
            db.clone(),
            agent(),
            tool,
            crate::common::with_test_reason(tool, args),
        )
        .await
        .unwrap_or_else(|error| panic!("{tool} failed: {error}"));
    db.drain_captures_for_tests().await;
    result
}

/// Model an already-retained historical read. New read calls deliberately do
/// not create these rows; the context reader must still interpret old ones.
async fn legacy_touch(db: &Db, run: &str, id: &str, tool: &str, interaction: &str) {
    let pool = crate::common::fixture_write_pool(db).await;
    let call = sqlx::query(
        "INSERT INTO read_log_calls
         (id,tool,run_key,actor,outcome,started_at,ended_at)
         VALUES (lower(hex(randomblob(16))),?,?,'local','ok',
                 strftime('%Y-%m-%dT%H:%M:%fZ','now'),
                 strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
    )
    .bind(tool)
    .bind(run)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT OR IGNORE INTO read_log_record_ids(record_id) VALUES(?)")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO read_log_touches(call_seq,record_ref,interaction)
         VALUES(?,(SELECT record_ref FROM read_log_record_ids WHERE record_id=?),?)",
    )
    .bind(call.last_insert_rowid())
    .bind(id)
    .bind(interaction)
    .execute(&pool)
    .await
    .unwrap();
}

async fn note(registry: &ToolRegistry, db: &Db, run: &str, id: &str, body: &str) -> Value {
    call(
        registry,
        db,
        "create_record",
        in_run(
            run,
            json!({ "id": id, "type": "Document", "kind": "note", "name": id, "body": body }),
        ),
    )
    .await
}

/// The immutable id of the newest body-producing event on a record.
async fn latest_body_event(db: &Db, record_id: &str) -> String {
    sqlx::query_scalar(
        "SELECT id FROM content_events
          WHERE record_id = ?
            AND (type = 'record.created'
              OR (type = 'record.updated' AND json_type(payload,'$.body') IS NOT NULL))
          ORDER BY seq DESC LIMIT 1",
    )
    .bind(record_id)
    .fetch_one(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap()
}

async fn creation_event(db: &Db, record_id: &str) -> String {
    sqlx::query_scalar(
        "SELECT id FROM content_events WHERE record_id = ? AND type = 'record.created'
          ORDER BY seq LIMIT 1",
    )
    .bind(record_id)
    .fetch_one(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap()
}

async fn body_digest(registry: &ToolRegistry, db: &Db, id: &str) -> String {
    call(registry, db, "get_record", json!({ "ids": [id] })).await["records"][0]["body_digest"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn edit(registry: &ToolRegistry, db: &Db, run: &str, id: &str, body: &str) {
    let digest = body_digest(registry, db, id).await;
    call(
        registry,
        db,
        "update_record",
        in_run(
            run,
            json!({ "id": id, "body": body, "if_body_digest": digest }),
        ),
    )
    .await;
}

// ---------------------------------------------------------------------------
// Addressing and the exact historical delta
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_event_is_addressed_by_immutable_id_and_reports_its_own_run() {
    let (db, registry) = fixture().await;
    note(
        &registry,
        &db,
        "scout-chair-a748b2",
        ADDRESSED,
        "First body.",
    )
    .await;
    let event_id = creation_event(&db, ADDRESSED).await;

    let context = call(
        &registry,
        &db,
        "get_event_context",
        json!({ "event_id": event_id }),
    )
    .await;
    assert_eq!(context["event"]["id"], json!(event_id));
    assert_eq!(context["event"]["record_id"], json!(ADDRESSED));
    assert_eq!(context["run"]["run_key"], json!("scout-chair-a748b2"));
    assert_eq!(context["run"]["agent_key"], json!("scout-chair"));
    assert_eq!(
        context["run"]["assurance"],
        json!("correlation_only"),
        "a run key groups calls; it does not identify a persistent agent"
    );
    let text = render::render("get_event_context", &context).unwrap();
    assert!(text.contains("Selected event"), "{text}");
    assert!(text.contains(&event_id), "{text}");
    assert!(text.contains(ADDRESSED), "{text}");
    assert!(text.contains("Run correlation"), "{text}");
    assert!(text.contains("scout-chair-a748b2"), "{text}");
    assert!(text.contains("scout-chair"), "{text}");
    assert!(text.contains("correlation_only"), "{text}");
}

#[tokio::test]
async fn the_delta_is_the_change_that_event_made_even_after_later_edits() {
    let (db, registry) = fixture().await;
    note(&registry, &db, "scout-chair-a748b2", EDITED, "Version one.").await;
    edit(&registry, &db, "scout-chair-a748b2", EDITED, "Version two.").await;
    let second_event = latest_body_event(&db, EDITED).await;
    // Two further edits AFTER the event under inspection. A diff against the
    // record's current body would report the accumulated difference; this must
    // report only what the selected event itself did.
    edit(
        &registry,
        &db,
        "scout-chair-a748b2",
        EDITED,
        "Version three.",
    )
    .await;
    edit(
        &registry,
        &db,
        "scout-chair-a748b2",
        EDITED,
        "Version four.",
    )
    .await;

    let context = call(
        &registry,
        &db,
        "get_event_context",
        json!({ "event_id": second_event }),
    )
    .await;
    assert_eq!(context["delta"]["kind"], json!("body_revision"));
    assert_eq!(context["delta"]["before"], json!("Version one."));
    assert_eq!(context["delta"]["after"], json!("Version two."));
    assert_eq!(context["delta"]["is_creation"], json!(false));
    let text = render::render("get_event_context", &context).unwrap();
    assert!(text.contains("Delta details"), "{text}");
    assert!(text.contains("Before body: \"Version one.\""), "{text}");
    assert!(text.contains("After body: \"Version two.\""), "{text}");
    assert!(!text.contains("Before body: \"Version three.\""), "{text}");
    assert!(!text.contains("After body: \"Version four.\""), "{text}");
}

#[tokio::test]
async fn a_creation_event_has_no_before_body() {
    let (db, registry) = fixture().await;
    note(
        &registry,
        &db,
        "scout-chair-a748b2",
        BORN,
        "Born with this body.",
    )
    .await;
    let event_id = creation_event(&db, BORN).await;
    let context = call(
        &registry,
        &db,
        "get_event_context",
        json!({ "event_id": event_id }),
    )
    .await;
    assert_eq!(context["delta"]["is_creation"], json!(true));
    assert!(context["delta"]["before"].is_null());
    assert_eq!(context["delta"]["after"], json!("Born with this body."));
}

#[tokio::test]
async fn a_non_body_event_is_named_rather_than_diffed() {
    let (db, registry) = fixture().await;
    note(&registry, &db, "scout-chair-a748b2", RENAMED, "Body.").await;
    call(
        &registry,
        &db,
        "update_record",
        in_run(
            "scout-chair-a748b2",
            json!({ "id": RENAMED, "name": "A new name" }),
        ),
    )
    .await;
    let event_id: String = sqlx::query_scalar(
        "SELECT id FROM content_events WHERE record_id = ? ORDER BY seq DESC LIMIT 1",
    )
    .bind(RENAMED)
    .fetch_one(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    let context = call(
        &registry,
        &db,
        "get_event_context",
        json!({ "event_id": event_id }),
    )
    .await;
    assert_eq!(context["delta"]["kind"], json!("not_a_body_revision"));
}

#[tokio::test]
async fn an_unknown_event_id_is_refused() {
    let (db, registry) = fixture().await;
    let error = registry
        .call(
            db.clone(),
            agent(),
            "get_event_context",
            json!({ "event_id": "no-such-event" }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("does not exist"), "{error}");
}

// ---------------------------------------------------------------------------
// Event-local intent
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_intent_shown_is_the_one_in_force_at_that_event_not_the_runs_latest() {
    let (db, registry) = fixture().await;
    call(
        &registry,
        &db,
        "set_intent",
        in_run(
            "scout-chair-a748b2",
            json!({ "intent": "Draft the first section" }),
        ),
    )
    .await;
    note(&registry, &db, "scout-chair-a748b2", EARLY, "Early work.").await;
    let early_event = creation_event(&db, EARLY).await;
    call(
        &registry,
        &db,
        "set_intent",
        in_run(
            "scout-chair-a748b2",
            json!({ "intent": "Something else entirely" }),
        ),
    )
    .await;
    note(&registry, &db, "scout-chair-a748b2", LATE, "Later work.").await;

    let context = call(
        &registry,
        &db,
        "get_event_context",
        json!({ "event_id": early_event }),
    )
    .await;
    assert_eq!(
        context["intent_at_event"],
        json!("Draft the first section"),
        "a later declaration must not be retro-attached to an earlier write"
    );
    let text = render::render("get_event_context", &context).unwrap();
    assert!(
        text.contains("Intent in force at this event: \"Draft the first section\""),
        "{text}"
    );
    assert!(
        !text.contains("Intent in force at this event: \"Something else entirely\""),
        "{text}"
    );
}

// ---------------------------------------------------------------------------
// Consulted-record evidence
// ---------------------------------------------------------------------------

async fn consulted(context: &Value) -> Vec<Value> {
    context["consulted"]["records"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

#[tokio::test]
async fn opened_records_are_listed_newest_first_and_deduplicated() {
    let (db, registry) = fixture().await;
    let run = "scout-chair-a748b2";
    note(&registry, &db, run, ALPHA, "A").await;
    note(&registry, &db, run, BETA, "B").await;

    // Open A, then B twice. B is one consulted record with its latest open
    // time, not two entries, and it sorts ahead of A.
    call(
        &registry,
        &db,
        "get_record",
        in_run(run, json!({ "ids": [ALPHA] })),
    )
    .await;
    legacy_touch(&db, run, ALPHA, "get_record", "opened").await;
    call(
        &registry,
        &db,
        "get_record",
        in_run(run, json!({ "ids": [BETA] })),
    )
    .await;
    legacy_touch(&db, run, BETA, "get_record", "opened").await;
    call(
        &registry,
        &db,
        "get_record",
        in_run(run, json!({ "ids": [BETA] })),
    )
    .await;
    legacy_touch(&db, run, BETA, "get_record", "opened").await;

    note(&registry, &db, run, SUBJECT, "Written after consulting.").await;
    let event_id = creation_event(&db, SUBJECT).await;
    let context = call(
        &registry,
        &db,
        "get_event_context",
        json!({ "event_id": event_id }),
    )
    .await;

    let records = consulted(&context).await;
    let ids: Vec<&str> = records
        .iter()
        .map(|record| record["record_id"].as_str().unwrap())
        .collect();
    assert!(
        ids.contains(&BETA) && ids.contains(&ALPHA),
        "both opens are evidence: {ids:?}"
    );
    assert_eq!(
        ids.iter().filter(|id| **id == BETA).count(),
        1,
        "a record opened repeatedly is one consulted record"
    );
    assert!(
        ids.iter().position(|id| *id == BETA) < ids.iter().position(|id| *id == ALPHA),
        "newest open first: {ids:?}"
    );
    for record in &records {
        assert_eq!(record["interaction"], json!("opened"));
    }
    assert_eq!(
        context["consulted"]["label"],
        json!("Opened before this event")
    );
    assert_eq!(context["consulted"]["limit"], json!(8));
    let text = render::render("get_event_context", &context).unwrap();
    assert!(text.contains("Opened before this event"), "{text}");
    assert!(text.contains(ALPHA), "{text}");
    assert!(text.contains(BETA), "{text}");
    assert!(text.contains("opened"), "{text}");
    assert!(text.contains("at most 8"), "{text}");
}

#[tokio::test]
async fn surfaced_records_are_a_separate_weaker_count_and_never_consulted() {
    let (db, registry) = fixture().await;
    let run = "scout-chair-a748b2";
    note(&registry, &db, run, OPENED_ONE, "Opened deliberately.").await;
    note(
        &registry,
        &db,
        run,
        MERELY_SURFACED,
        "Appears in results only.",
    )
    .await;

    call(
        &registry,
        &db,
        "get_record",
        in_run(run, json!({ "ids": [OPENED_ONE] })),
    )
    .await;
    legacy_touch(&db, run, OPENED_ONE, "get_record", "opened").await;
    // A search surfaces its hits without opening them.
    call(
        &registry,
        &db,
        "search",
        in_run(run, json!({ "query": "surfaced" })),
    )
    .await;
    legacy_touch(&db, run, MERELY_SURFACED, "search", "surfaced").await;

    note(&registry, &db, run, SURFACED_SUBJECT, "Body.").await;
    let event_id = creation_event(&db, SURFACED_SUBJECT).await;
    let context = call(
        &registry,
        &db,
        "get_event_context",
        json!({ "event_id": event_id }),
    )
    .await;

    let ids: Vec<String> = consulted(&context)
        .await
        .iter()
        .map(|record| record["record_id"].as_str().unwrap().to_owned())
        .collect();
    assert!(ids.contains(&OPENED_ONE.to_string()));
    assert!(
        !ids.contains(&MERELY_SURFACED.to_string()),
        "surfacing is weaker evidence and must not read as consulting: {ids:?}"
    );
    assert!(
        context["consulted"]["other_records_surfaced"]
            .as_i64()
            .unwrap()
            >= 1,
        "the collapsed surfaced count is still reported, separately"
    );
}

#[tokio::test]
async fn the_events_own_target_is_labelled_rather_than_silently_removed() {
    let (db, registry) = fixture().await;
    let run = "scout-chair-a748b2";
    note(&registry, &db, run, SELF_TARGET, "Original.").await;
    call(
        &registry,
        &db,
        "get_record",
        in_run(run, json!({ "ids": [SELF_TARGET] })),
    )
    .await;
    legacy_touch(&db, run, SELF_TARGET, "get_record", "opened").await;
    edit(
        &registry,
        &db,
        run,
        SELF_TARGET,
        "Rewritten after reading it.",
    )
    .await;
    let event_id = latest_body_event(&db, SELF_TARGET).await;
    let context = call(
        &registry,
        &db,
        "get_event_context",
        json!({ "event_id": event_id }),
    )
    .await;

    let target = consulted(&context)
        .await
        .into_iter()
        .find(|record| record["record_id"] == json!(SELF_TARGET));
    let target = target.expect("the run opened the record it then wrote to");
    assert_eq!(target["is_event_target"], json!(true));
}

#[tokio::test]
async fn the_consulted_scan_is_bounded_to_the_active_intent_episode() {
    let (db, registry) = fixture().await;
    let run = "scout-chair-a748b2";
    note(&registry, &db, run, BEFORE_BOUNDARY, "Earlier episode.").await;
    call(
        &registry,
        &db,
        "get_record",
        in_run(run, json!({ "ids": [BEFORE_BOUNDARY] })),
    )
    .await;
    legacy_touch(&db, run, BEFORE_BOUNDARY, "get_record", "opened").await;

    // A new declaration closes the previous episode.
    call(
        &registry,
        &db,
        "set_intent",
        in_run(run, json!({ "intent": "A new aim entirely" })),
    )
    .await;
    // SQLite timestamps have millisecond precision. Force the earlier read to
    // share the boundary timestamp so this proves episode selection uses the
    // read log's monotonic sequence rather than an ambiguous time comparison.
    sqlx::query(
        "UPDATE read_log_calls
            SET ended_at = (
                SELECT ended_at FROM read_log_calls
                 WHERE run_key = ?1 AND tool = 'set_intent'
                 ORDER BY seq DESC LIMIT 1
            )
          WHERE run_key = ?1 AND tool = 'get_record'",
    )
    .bind(run)
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    note(&registry, &db, run, AFTER_BOUNDARY, "Later episode.").await;
    call(
        &registry,
        &db,
        "get_record",
        in_run(run, json!({ "ids": [AFTER_BOUNDARY] })),
    )
    .await;
    legacy_touch(&db, run, AFTER_BOUNDARY, "get_record", "opened").await;

    note(&registry, &db, run, EPISODE_SUBJECT, "Body.").await;
    let event_id = creation_event(&db, EPISODE_SUBJECT).await;
    let context = call(
        &registry,
        &db,
        "get_event_context",
        json!({ "event_id": event_id }),
    )
    .await;

    let ids: Vec<String> = consulted(&context)
        .await
        .iter()
        .map(|record| record["record_id"].as_str().unwrap().to_owned())
        .collect();
    assert!(ids.contains(&AFTER_BOUNDARY.to_string()), "{ids:?}");
    assert!(
        !ids.contains(&BEFORE_BOUNDARY.to_string()),
        "reads from a closed intent episode are not this moment's context: {ids:?}"
    );
}

#[tokio::test]
async fn more_than_eight_opens_truncate_and_say_so() {
    let (db, registry) = fixture().await;
    let run = "scout-chair-a748b2";
    for index in 0..10 {
        let id = format!("e0e70000-0000-4000-8000-0000000009{index:02}");
        note(&registry, &db, run, &id, "Body.").await;
        call(
            &registry,
            &db,
            "get_record",
            in_run(run, json!({ "ids": [id] })),
        )
        .await;
        legacy_touch(&db, run, &id, "get_record", "opened").await;
    }
    note(&registry, &db, run, BULK_SUBJECT, "Body.").await;
    let event_id = creation_event(&db, BULK_SUBJECT).await;
    let context = call(
        &registry,
        &db,
        "get_event_context",
        json!({ "event_id": event_id }),
    )
    .await;

    assert_eq!(consulted(&context).await.len(), 8);
    assert_eq!(
        context["consulted"]["status"],
        json!("partial"),
        "a truncated list must never be mistaken for a complete one"
    );
    let text = render::render("get_event_context", &context).unwrap();
    assert!(text.contains("Opened before this event"), "{text}");
    assert!(text.contains("partial"), "{text}");
    assert!(text.contains("at most 8"), "{text}");
}

#[tokio::test]
async fn a_hidden_opened_record_is_omitted_without_disclosing_it() {
    let (db, registry) = fixture().await;
    let run = "scout-chair-a748b2";
    note(&registry, &db, run, SECRET_SOURCE, "Confidential.").await;
    note(&registry, &db, run, OPEN_SOURCE, "Ordinary.").await;
    call(
        &registry,
        &db,
        "get_record",
        in_run(run, json!({ "ids": [SECRET_SOURCE, OPEN_SOURCE] })),
    )
    .await;
    legacy_touch(&db, run, SECRET_SOURCE, "get_record", "opened").await;
    legacy_touch(&db, run, OPEN_SOURCE, "get_record", "opened").await;
    note(&registry, &db, run, FILTERED_SUBJECT, "Body.").await;
    let event_id = creation_event(&db, FILTERED_SUBJECT).await;

    native_ce::authorization::replace_explicit_policy(
        &db,
        "test:policy",
        SECRET_SOURCE,
        vec![native_ce::authorization::AllowEntry::account(
            "someone-else",
            native_ce::authorization::Capability::Manage,
        )],
    )
    .await
    .unwrap();

    let stranger = Caller::authenticated("stranger").with_channel(Channel::Mcp);
    let context = registry
        .call(
            db.clone(),
            stranger,
            "get_event_context",
            json!({ "event_id": event_id }),
        )
        .await
        .unwrap();
    let serialized = context.to_string();
    assert!(
        !serialized.contains(SECRET_SOURCE),
        "the deep-link grants no read authority and discloses no hidden identity"
    );
    assert!(serialized.contains(OPEN_SOURCE));
    assert_eq!(
        context["consulted"]["status"],
        json!("partial"),
        "filtering truncates, and truncation is reported"
    );
}

#[tokio::test]
async fn an_absent_read_log_reports_unavailable_not_an_empty_list() {
    let (db, registry) = fixture().await;
    let run = "scout-chair-a748b2";
    note(&registry, &db, run, LOGLESS, "Body.").await;
    let event_id = creation_event(&db, LOGLESS).await;

    // The read log is disposable operational evidence. Dropping it must not
    // convert "we cannot tell" into "nothing was opened".
    let pool = crate::common::fixture_write_pool(&db).await;
    sqlx::query("DELETE FROM read_log_touches")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM read_log_calls")
        .execute(&pool)
        .await
        .unwrap();

    let context = call(
        &registry,
        &db,
        "get_event_context",
        json!({ "event_id": event_id }),
    )
    .await;
    assert_eq!(context["consulted"]["status"], json!("unavailable"));
    assert_eq!(context["consulted"]["records"], json!([]));
    let text = render::render("get_event_context", &context).unwrap();
    assert!(text.contains("Opened before this event"), "{text}");
    assert!(text.contains("unavailable"), "{text}");
    assert!(text.contains("best-effort"), "{text}");
    assert!(!text.contains("no qualifying opens"), "{text}");
}

#[tokio::test]
async fn every_response_carries_the_interpretation_limitations() {
    let (db, registry) = fixture().await;
    note(&registry, &db, "scout-chair-a748b2", LIMITED, "Body.").await;
    let event_id = creation_event(&db, LIMITED).await;
    let context = call(
        &registry,
        &db,
        "get_event_context",
        json!({ "event_id": event_id }),
    )
    .await;
    let limits: Vec<&str> = context["interpretation_limits"]
        .as_array()
        .unwrap()
        .iter()
        .map(|limit| limit.as_str().unwrap())
        .collect();
    for expected in [
        "opened_does_not_establish_comprehension_or_reliance",
        "consulted_context_is_bounded",
        "consulted_context_may_be_visibility_filtered",
        "read_log_is_best_effort_not_canonical_history",
        "basis_is_declared_not_verified",
    ] {
        assert!(limits.contains(&expected), "missing {expected}: {limits:?}");
    }
    let text = render::render("get_event_context", &context).unwrap();
    assert!(text.contains("Interpretation limits"), "{text}");
    for expected in limits {
        assert!(text.contains(expected), "missing {expected}: {text}");
    }
}

#[tokio::test]
async fn raw_tool_arguments_and_query_text_never_reach_the_response() {
    let (db, registry) = fixture().await;
    let run = "scout-chair-a748b2";
    note(&registry, &db, run, QUERIED, "Body.").await;
    call(
        &registry,
        &db,
        "search",
        in_run(run, json!({ "query": "a-distinctive-secret-query-string" })),
    )
    .await;
    note(&registry, &db, run, QUERY_SUBJECT, "Body.").await;
    let event_id = creation_event(&db, QUERY_SUBJECT).await;
    let context = call(
        &registry,
        &db,
        "get_event_context",
        json!({ "event_id": event_id }),
    )
    .await;
    assert!(
        !context
            .to_string()
            .contains("a-distinctive-secret-query-string"),
        "read-log payloads are potentially sensitive and are never returned"
    );
}

#[tokio::test]
async fn neighbouring_events_come_from_the_same_exact_run() {
    let (db, registry) = fixture().await;
    note(&registry, &db, "scout-chair-a748b2", NEIGHBOUR_ONE, "One.").await;
    note(&registry, &db, "scout-chair-a748b2", NEIGHBOUR_TWO, "Two.").await;
    note(&registry, &db, "plover-archery-bbbbbb", OTHER_RUN, "Other.").await;
    note(
        &registry,
        &db,
        "scout-chair-a748b2",
        NEIGHBOUR_THREE,
        "Three.",
    )
    .await;

    let event_id = creation_event(&db, NEIGHBOUR_TWO).await;
    let context = call(
        &registry,
        &db,
        "get_event_context",
        json!({ "event_id": event_id }),
    )
    .await;
    let neighbours = context["neighbouring_events"].as_array().unwrap();
    assert!(!neighbours.is_empty());
    for event in neighbours {
        assert_eq!(
            event["run_key"],
            json!("scout-chair-a748b2"),
            "a sibling run's writes are not what this run was in the middle of"
        );
        assert_ne!(event["id"], json!(event_id));
    }
    let text = render::render("get_event_context", &context).unwrap();
    assert!(text.contains("Neighbouring events"), "{text}");
    for event in neighbours {
        assert!(
            text.contains(event["id"].as_str().unwrap()),
            "missing neighboring event {}: {text}",
            event["id"]
        );
    }
    assert!(!text.contains(OTHER_RUN), "{text}");
}

// ---------------------------------------------------------------------------
// Declared source basis: the run's own account of what a write rested on
// ---------------------------------------------------------------------------

/// A citing write declaring one caller-pinned and one engine-stamped source.
async fn cite_two_sources(registry: &ToolRegistry, db: &Db, run: &str) -> Value {
    note(registry, db, run, BASIS_CALLER_SOURCE, "Pinned source.").await;
    note(registry, db, run, BASIS_ENGINE_SOURCE, "Stamped source.").await;
    let pinned = latest_body_event(db, BASIS_CALLER_SOURCE).await;
    call(
        registry,
        db,
        "create_record",
        in_run(
            run,
            json!({
                "id": BASIS_CITING,
                "type": "Document",
                "kind": "note",
                "name": BASIS_CITING,
                "body": "Composed from both sources.",
                "sources": [
                    {
                        "record_id": BASIS_CALLER_SOURCE,
                        "reason": "the pinned reading",
                        "role": "primary",
                        "revision_event_id": pinned,
                    },
                    {
                        "record_id": BASIS_ENGINE_SOURCE,
                        "reason": "the stamped reading",
                    },
                ],
            }),
        ),
    )
    .await
}

#[tokio::test]
async fn a_declared_basis_is_returned_with_revision_provenance() {
    let (db, registry) = fixture().await;
    let run = "scout-chair-a748b2";
    cite_two_sources(&registry, &db, run).await;
    let event_id = creation_event(&db, BASIS_CITING).await;
    let context = call(
        &registry,
        &db,
        "get_event_context",
        json!({ "event_id": event_id }),
    )
    .await;

    let basis = &context["basis"];
    assert_eq!(basis["label"], json!("Sources"));
    assert_eq!(basis["status"], json!("declared"));
    assert_eq!(basis["completeness"], json!("complete"));
    let sources = basis["sources"].as_array().unwrap();
    assert_eq!(sources.len(), 2, "{basis}");
    assert_eq!(sources[0]["record_id"], json!(BASIS_CALLER_SOURCE));
    assert_eq!(sources[0]["name"], json!(BASIS_CALLER_SOURCE));
    assert_eq!(sources[0]["type"], json!("Document"));
    assert_eq!(sources[0]["kind"], json!("note"));
    assert_eq!(
        sources[0]["revision_event_id"],
        json!(latest_body_event(&db, BASIS_CALLER_SOURCE).await)
    );
    assert_eq!(sources[0]["revision_supplied_by"], json!("caller"));
    assert_eq!(sources[0]["role"], json!("primary"));
    assert_eq!(sources[0]["reason"], json!("the pinned reading"));
    assert_eq!(sources[0]["is_event_target"], json!(false));
    assert_eq!(sources[1]["record_id"], json!(BASIS_ENGINE_SOURCE));
    assert_eq!(sources[1]["revision_supplied_by"], json!("engine"));
    assert_eq!(
        sources[1]["revision_event_id"],
        json!(latest_body_event(&db, BASIS_ENGINE_SOURCE).await)
    );
    assert_eq!(sources[1]["role"], json!(null));
    assert_eq!(sources[1]["is_event_target"], json!(false));

    let limits: Vec<&str> = context["interpretation_limits"]
        .as_array()
        .unwrap()
        .iter()
        .map(|limit| limit.as_str().unwrap())
        .collect();
    assert!(
        limits.contains(&"basis_is_declared_not_verified"),
        "declarations carry their own authored-claim limit: {limits:?}"
    );

    let text = render::render("get_event_context", &context).unwrap();
    assert!(text.contains("Declared sources: declared"), "{text}");
    assert!(text.contains("complete"), "{text}");
    assert!(text.contains(BASIS_CALLER_SOURCE), "{text}");
    assert!(
        text.contains("authored claim of use, not verified use"),
        "{text}"
    );
}

#[tokio::test]
async fn an_explicit_empty_basis_reads_declared_none() {
    let (db, registry) = fixture().await;
    let run = "scout-chair-a748b2";
    call(
        &registry,
        &db,
        "create_record",
        in_run(
            run,
            json!({
                "id": BASIS_NONE,
                "type": "Document",
                "kind": "note",
                "name": BASIS_NONE,
                "body": "Transcribed verbatim; rested on nothing.",
                "sources": [],
            }),
        ),
    )
    .await;
    let event_id = creation_event(&db, BASIS_NONE).await;
    let context = call(
        &registry,
        &db,
        "get_event_context",
        json!({ "event_id": event_id }),
    )
    .await;

    assert_eq!(context["basis"]["label"], json!("Sources"));
    assert_eq!(context["basis"]["status"], json!("declared_none"));
    assert_eq!(context["basis"]["completeness"], json!("complete"));
    assert_eq!(context["basis"]["sources"], json!([]));
    let text = render::render("get_event_context", &context).unwrap();
    assert!(
        text.contains("Declared sources: declared as none"),
        "{text}"
    );
}

#[tokio::test]
async fn an_absent_basis_reads_not_declared() {
    let (db, registry) = fixture().await;
    let run = "scout-chair-a748b2";
    note(&registry, &db, run, BASIS_ABSENT, "No declaration.").await;
    let event_id = creation_event(&db, BASIS_ABSENT).await;
    let context = call(
        &registry,
        &db,
        "get_event_context",
        json!({ "event_id": event_id }),
    )
    .await;

    assert_eq!(context["basis"]["label"], json!("Sources"));
    assert_eq!(context["basis"]["status"], json!("not_declared"));
    assert_eq!(context["basis"]["completeness"], json!("complete"));
    assert_eq!(context["basis"]["sources"], json!([]));
    let text = render::render("get_event_context", &context).unwrap();
    assert!(text.contains("Declared sources: not declared"), "{text}");
}

#[tokio::test]
async fn the_event_target_is_labelled_not_removed() {
    let (db, registry) = fixture().await;
    let run = "scout-chair-a748b2";
    note(&registry, &db, run, BASIS_SELF_TARGET, "First version.").await;
    let digest = body_digest(&registry, &db, BASIS_SELF_TARGET).await;
    call(
        &registry,
        &db,
        "update_record",
        in_run(
            run,
            json!({
                "id": BASIS_SELF_TARGET,
                "body": "Second version, resting on the first.",
                "if_body_digest": digest,
                "sources": [{ "record_id": BASIS_SELF_TARGET, "reason": "reworked my own draft" }],
            }),
        ),
    )
    .await;
    let event_id = latest_body_event(&db, BASIS_SELF_TARGET).await;
    let context = call(
        &registry,
        &db,
        "get_event_context",
        json!({ "event_id": event_id }),
    )
    .await;

    assert_eq!(context["basis"]["status"], json!("declared"));
    let sources = context["basis"]["sources"].as_array().unwrap();
    assert_eq!(sources.len(), 1, "{sources:?}");
    assert_eq!(sources[0]["record_id"], json!(BASIS_SELF_TARGET));
    assert_eq!(sources[0]["is_event_target"], json!(true));
}

#[tokio::test]
async fn a_hidden_declared_source_is_omitted_without_disclosure() {
    let (db, registry) = fixture().await;
    let run = "scout-chair-a748b2";
    note(&registry, &db, run, BASIS_SECRET, "Confidential.").await;
    note(&registry, &db, run, BASIS_OPEN, "Ordinary.").await;
    call(
        &registry,
        &db,
        "create_record",
        in_run(
            run,
            json!({
                "id": BASIS_FILTERED_SUBJECT,
                "type": "Document",
                "kind": "note",
                "name": BASIS_FILTERED_SUBJECT,
                "body": "Composed from both.",
                "sources": [
                    {
                        "record_id": BASIS_SECRET,
                        "reason": "confidential-basis-reason-must-not-leak",
                        "role": "confidential-basis-role-must-not-leak",
                    },
                    { "record_id": BASIS_OPEN, "reason": "the ordinary reading" },
                ],
            }),
        ),
    )
    .await;
    let event_id = creation_event(&db, BASIS_FILTERED_SUBJECT).await;

    native_ce::authorization::replace_explicit_policy(
        &db,
        "test:policy",
        BASIS_SECRET,
        vec![native_ce::authorization::AllowEntry::account(
            "someone-else",
            native_ce::authorization::Capability::Manage,
        )],
    )
    .await
    .unwrap();

    let stranger = Caller::authenticated("stranger").with_channel(Channel::Mcp);
    let context = registry
        .call(
            db.clone(),
            stranger,
            "get_event_context",
            json!({ "event_id": event_id }),
        )
        .await
        .unwrap();
    // Whole-response regression: the hidden entry is removed entire — id,
    // reason and role — from the sibling block AND the redacted payload
    // echo, where generic redaction alone would keep the prose beside a
    // nulled id. The visible entry survives intact, proving the scrub is
    // narrow rather than a wholesale envelope drop.
    let serialized = context.to_string();
    for leaked in [
        BASIS_SECRET,
        "confidential-basis-reason-must-not-leak",
        "confidential-basis-role-must-not-leak",
    ] {
        assert!(
            !serialized.contains(leaked),
            "a hidden source must leak neither name, existence, reason nor role: {leaked}"
        );
    }
    assert!(serialized.contains(BASIS_OPEN));
    assert!(serialized.contains("the ordinary reading"));
    // Absent and empty never collapse: a declaration with a hidden member is
    // still a declaration, reported partial rather than complete or none.
    assert_eq!(context["basis"]["status"], json!("declared"));
    assert_eq!(context["basis"]["completeness"], json!("partial"));
    let sources = context["basis"]["sources"].as_array().unwrap();
    assert_eq!(sources.len(), 1, "{sources:?}");
    assert_eq!(sources[0]["record_id"], json!(BASIS_OPEN));
}

/// The selected event is visible and declares nothing, but a neighbouring
/// event in the same run cites a source that later becomes hidden. That
/// neighbour's echoed payload must be scrubbed whole-entry too: generic
/// redaction alone would null the record id and keep the reason and role,
/// disclosing a hidden source on the same response.
#[tokio::test]
async fn a_hidden_declared_source_is_scrubbed_from_a_neighbouring_echo() {
    let (db, registry) = fixture().await;
    let run = "scout-chair-a748b2";
    note(&registry, &db, run, SECRET_SOURCE, "Confidential.").await;
    note(&registry, &db, run, OPEN_SOURCE, "Ordinary.").await;
    // The citing write is the neighbour. It lands while both sources are
    // still visible to the author; the policy change below comes afterwards,
    // exactly as it would for a basis that went stale or was later restricted.
    call(
        &registry,
        &db,
        "create_record",
        in_run(
            run,
            json!({
                "id": NEIGHBOUR_ONE,
                "type": "Document",
                "kind": "note",
                "name": NEIGHBOUR_ONE,
                "body": "Neighbour resting on a source that later becomes hidden.",
                "sources": [
                    {
                        "record_id": SECRET_SOURCE,
                        "reason": "neighbour-secret-reason-must-not-leak",
                        "role": "neighbour-secret-role-must-not-leak",
                    },
                    { "record_id": OPEN_SOURCE, "reason": "neighbour-open-reason" },
                ],
            }),
        ),
    )
    .await;
    // The selected event, visible to the caller, one step later in the same
    // run, so the citing write is inside the neighbour window.
    note(&registry, &db, run, NEIGHBOUR_TWO, "Selected body.").await;
    let event_id = creation_event(&db, NEIGHBOUR_TWO).await;

    native_ce::authorization::replace_explicit_policy(
        &db,
        "test:policy",
        SECRET_SOURCE,
        vec![native_ce::authorization::AllowEntry::account(
            "someone-else",
            native_ce::authorization::Capability::Manage,
        )],
    )
    .await
    .unwrap();

    let stranger = Caller::authenticated("stranger").with_channel(Channel::Mcp);
    let context = registry
        .call(
            db.clone(),
            stranger,
            "get_event_context",
            json!({ "event_id": event_id }),
        )
        .await
        .unwrap();
    // The citing neighbour is actually present; otherwise the scrub would be
    // vacuously satisfied.
    let neighbour_records: Vec<&str> = context["neighbouring_events"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|event| event["record_id"].as_str())
        .collect();
    assert!(
        neighbour_records.contains(&NEIGHBOUR_ONE),
        "the citing write must be a returned neighbour: {neighbour_records:?}"
    );

    let serialized = context.to_string();
    for leaked in [
        SECRET_SOURCE,
        "neighbour-secret-reason-must-not-leak",
        "neighbour-secret-role-must-not-leak",
    ] {
        assert!(
            !serialized.contains(leaked),
            "a hidden source must not leak from a neighbouring echo: {leaked}"
        );
    }
    // The visible entry on the SAME neighbour survives, so the scrub is
    // narrow rather than a wholesale neighbour-payload drop.
    assert!(serialized.contains(OPEN_SOURCE));
    assert!(serialized.contains("neighbour-open-reason"));

    let text = render::render("get_event_context", &context).unwrap();
    for leaked in [
        SECRET_SOURCE,
        "neighbour-secret-reason-must-not-leak",
        "neighbour-secret-role-must-not-leak",
    ] {
        assert!(
            !text.contains(leaked),
            "the rendered text must not leak a hidden neighbour source: {leaked}"
        );
    }
    assert!(text.contains(OPEN_SOURCE), "{text}");
}

/// Overwrite one event's stored payload with a hand-built envelope. The write
/// path validates, so malformed and future-format envelopes can only arrive
/// through forward compatibility or direct storage edits; the read path must
/// still answer honestly rather than misread or fail.
async fn rewrite_basis_payload(db: &Db, record_id: &str, basis: Value) {
    let pool = crate::common::fixture_write_pool(db).await;
    let raw: String = sqlx::query_scalar(
        "SELECT payload FROM content_events WHERE record_id = ? AND type = 'record.created' ORDER BY seq LIMIT 1",
    )
    .bind(record_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let mut payload: Value = serde_json::from_str(&raw).unwrap();
    payload
        .as_object_mut()
        .unwrap()
        .insert("basis".into(), basis);
    // The log is append-only by trigger; a test-only rewrite drops and
    // restores the guard around the single surgical update.
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
    sqlx::query(
        "UPDATE content_events SET payload = ? WHERE record_id = ? AND type = 'record.created'",
    )
    .bind(serde_json::to_string(&payload).unwrap())
    .bind(record_id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(&guard).execute(&pool).await.unwrap();
}

#[tokio::test]
async fn an_unrecognized_envelope_reads_not_declared_never_misread() {
    let (db, registry) = fixture().await;
    let run = "scout-chair-a748b2";
    for (id, basis) in [
        (
            BASIS_RESHAPED,
            // A future format version must not be parsed as v1.
            json!({ "format": "native.source-basis.v9", "sources": [{ "record_id": BASIS_OPEN, "reason": "x" }] }),
        ),
        (
            "e0e70000-0000-4000-8000-000000000028",
            // A different format string is not this version either.
            json!({ "format": "native.source-basis", "sources": [] }),
        ),
        (
            "e0e70000-0000-4000-8000-000000000029",
            // A non-object envelope names nothing.
            json!("declared"),
        ),
        (
            "e0e70000-0000-4000-8000-00000000002a",
            // An object with no format is unrecognized, not v1.
            json!({ "sources": [{ "record_id": BASIS_OPEN, "reason": "x" }] }),
        ),
    ] {
        note(&registry, &db, run, id, "Body.").await;
        rewrite_basis_payload(&db, id, basis).await;
        let event_id = creation_event(&db, id).await;
        let context = call(
            &registry,
            &db,
            "get_event_context",
            json!({ "event_id": event_id }),
        )
        .await;
        assert_eq!(context["basis"]["status"], json!("not_declared"), "{id}");
        assert_eq!(context["basis"]["completeness"], json!("complete"), "{id}");
        assert_eq!(context["basis"]["sources"], json!([]), "{id}");
    }
}

#[tokio::test]
async fn a_recognized_v1_envelope_without_usable_sources_reads_declared_partial() {
    let (db, registry) = fixture().await;
    let run = "scout-chair-a748b2";
    for (id, basis) in [
        (
            BASIS_RESHAPED,
            // v1 with no sources key: a declaration this server cannot
            // enumerate — declared, not "nothing was declared".
            json!({ "format": "native.source-basis.v1" }),
        ),
        (
            "e0e70000-0000-4000-8000-00000000002b",
            // v1 with a non-array sources value: same answer.
            json!({ "format": "native.source-basis.v1", "sources": "malformed" }),
        ),
    ] {
        note(&registry, &db, run, id, "Body.").await;
        rewrite_basis_payload(&db, id, basis).await;
        let event_id = creation_event(&db, id).await;
        let context = call(
            &registry,
            &db,
            "get_event_context",
            json!({ "event_id": event_id }),
        )
        .await;
        assert_eq!(context["basis"]["status"], json!("declared"), "{id}");
        assert_eq!(context["basis"]["completeness"], json!("partial"), "{id}");
        assert_eq!(context["basis"]["sources"], json!([]), "{id}");
        // Never a fourth status: the three-state distinction still holds.
        assert_ne!(context["basis"]["status"], json!("not_declared"), "{id}");
        let text = render::render("get_event_context", &context).unwrap();
        assert!(
            text.contains("Declared sources: declared"),
            "declaration must render as declared, not not-declared: {text}"
        );
        assert!(text.contains("partial"), "{text}");
    }
}

#[tokio::test]
async fn a_malformed_entry_is_skipped_and_reported_partial() {
    let (db, registry) = fixture().await;
    let run = "scout-chair-a748b2";
    note(&registry, &db, run, BASIS_OPEN, "Ordinary.").await;
    note(&registry, &db, run, BASIS_RESHAPED, "Citing.").await;
    let head = latest_body_event(&db, BASIS_OPEN).await;
    rewrite_basis_payload(
        &db,
        BASIS_RESHAPED,
        json!({
            "format": "native.source-basis.v1",
            "sources": [
                // No record id: names nothing showable, skipped like a hidden
                // source rather than hiding the well-formed sibling.
                { "reason": "an entry that names nothing" },
                {
                    "ordinal": 1,
                    "record_id": BASIS_OPEN,
                    "revision_event_id": head,
                    "revision_supplied_by": "caller",
                    "role": null,
                    "reason": "the ordinary reading",
                },
            ],
        }),
    )
    .await;
    let event_id = creation_event(&db, BASIS_RESHAPED).await;
    let context = call(
        &registry,
        &db,
        "get_event_context",
        json!({ "event_id": event_id }),
    )
    .await;

    assert_eq!(context["basis"]["status"], json!("declared"));
    assert_eq!(context["basis"]["completeness"], json!("partial"));
    let sources = context["basis"]["sources"].as_array().unwrap();
    assert_eq!(sources.len(), 1, "{sources:?}");
    assert_eq!(sources[0]["record_id"], json!(BASIS_OPEN));
}
