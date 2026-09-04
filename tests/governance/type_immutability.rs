//! TYPE IS RIGID (task 1ed2c74, closing F6a of the OntoClean verdict 6285fa8).
//!
//! A record carries one of the 10 spine types for life. That was previously a
//! convention of ONE STRUCT'S FIELD LIST — `UpdateRecordArgs` simply had no
//! `type` field — while `store::update_record` is `pub`, takes arbitrary JSON,
//! and the projector's `RECORD_COLUMN_FOR` happily mapped `type` onto the
//! column. The invariant the whole closed-type extension model rests on (2e5ed3e)
//! held only as far as the MCP surface reached.
//!
//! These tests pin it at all three tiers, and pin the reason it matters:
//! **nothing else guards link semantics.** The nine spine relationships are the
//! interop floor portable skills hard-dispatch on, their meaning comes entirely
//! from the types at each end, and `add_link` never inspects an endpoint. A
//! silent type flip would void every inbound `implements` edge with no
//! constraint anywhere to notice — which is why the fold rejects LOUDLY rather
//! than dropping the key.

use crate::common::{count, ev, project_one};
use native_ce::conformance::{rebuild_and_diff, run_conformance};
use native_ce::events::LinkAddedPayload;
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::store::{add_link, create_record, update_record};
use native_ce::{create_database, Db};
use serde_json::{json, Value};

async fn db() -> Db {
    create_database(":memory:").await.unwrap()
}

async fn a_document(db: &Db) -> String {
    create_record(
        db,
        json!({ "type": "Document", "kind": "note", "name": "Acme Corp" }),
    )
    .await
    .unwrap()
}

async fn type_of(db: &Db, id: &str) -> String {
    crate::common::text_of(
        db,
        &format!("SELECT type FROM records WHERE id = '{id}'"),
        "type",
    )
    .await
    .expect("record has a type")
}

/// Install the governed event through the privileged historical-storage seam.
///
/// This is intentionally not a second authoring path: the public generic
/// append API must reject this event. Acceptance coverage needs an
/// authoritative log row, though, so it models a correction already admitted
/// by the operation-owned writer and applies that exact row through the
/// production projector in the same transaction.
async fn append_correction_fixture(db: &Db, record_id: &str) -> i64 {
    let payload = json!({
        "from": {"type": "Document", "kind": "note"},
        "to": {"type": "Resolution", "kind": "decision"},
        "mode": "confirmed",
        "reason": "Exercise historical replay and rebuild parity.",
        "plan_id": "plan:test-replay-correction",
        "effect_digest": format!("sha256:{}", "d".repeat(64)),
        "schema_state_revision": "schema-state-v1:meta:1:content:2",
        "confirmation_required": true
    });
    let event_id = format!("record.type_corrected.v1:{record_id}:replay");
    let created_at = "2099-01-01T00:00:00.000Z";
    let fixture_pool = crate::common::fixture_write_pool(db).await;
    let mut tx = fixture_pool.begin().await.unwrap();
    let seq: i64 = sqlx::query_scalar(
        "INSERT INTO content_events (id, record_id, type, payload, created_at, causal_envelope_version, causal_status)
         VALUES (?, ?, 'record.type_corrected.v1', ?, ?, 1, 'legacy_unknown') RETURNING seq",
    )
    .bind(&event_id)
    .bind(record_id)
    .bind(payload.to_string())
    .bind(created_at)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    let event = native_ce::events::EventRow {
        local_seq: seq,
        id: event_id,
        record_id: record_id.to_owned(),
        event_type: "record.type_corrected.v1".into(),
        payload: Some(payload.to_string()),
        actor: None,
        run_key: None,
        parent_key: None,
        intent: None,
        created_at: created_at.into(),
        causal_envelope: native_ce::events::CausalEnvelopeV1::legacy_unknown(),
    };
    native_ce::projector::project(&mut tx, &event)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    seq
}

// ---------------------------------------------------------------------------
// 1. The engine tier — the hole this task named
// ---------------------------------------------------------------------------

#[tokio::test]
async fn engine_rejects_a_type_change_through_the_public_store_api() {
    let db = db().await;
    let id = a_document(&db).await;

    let err = update_record(&db, &id, json!({ "type": "Entity" }))
        .await
        .expect_err("`type` must be refused at the fold, not only at the tool surface");
    let message = err.to_string();
    assert!(
        message.contains("immutable"),
        "the error must name the invariant, got: {message}"
    );

    assert_eq!(type_of(&db, &id).await, "Document");
}

/// A rejected promotion must leave NOTHING behind. `append` folds inside the
/// same write transaction as the log insert, so a projection failure has to roll
/// the event back too — otherwise the log would carry an event that replay
/// refuses, and every future rebuild-and-diff would fail on it.
#[tokio::test]
async fn a_rejected_type_change_writes_no_event_and_no_partial_update() {
    let db = db().await;
    let id = a_document(&db).await;
    let events_before = count(&db, "SELECT COUNT(*) AS n FROM content_events").await;

    let _ = update_record(
        &db,
        &id,
        json!({ "type": "Entity", "name": "Acme (the org)" }),
    )
    .await;

    assert_eq!(
        count(&db, "SELECT COUNT(*) AS n FROM content_events").await,
        events_before,
        "the refused update must not land in the log"
    );
    assert_eq!(type_of(&db, &id).await, "Document");
    assert_eq!(
        crate::common::text_of(
            &db,
            &format!("SELECT name FROM records WHERE id = '{id}'"),
            "name"
        )
        .await
        .unwrap(),
        "Acme Corp",
        "the legal half of a mixed payload must not apply either"
    );
}

/// The projector is the tier that actually holds the line, so probe it directly
/// with a synthetic event — the shape a hand-written log or a third-party writer
/// would produce.
#[tokio::test]
async fn the_fold_refuses_a_synthetic_type_carrying_update() {
    let db = db().await;
    let id = a_document(&db).await;

    let err = project_one(
        &db,
        &ev(
            &id,
            "record.updated",
            "2026-01-01T00:00:00.000Z",
            json!({ "type": "Entity" }),
        ),
    )
    .await
    .expect_err("the fold must refuse a type-carrying record.updated");
    assert!(err.to_string().contains("immutable"));

    // An explicit null is a present key, and must be refused the same way — it
    // would otherwise NULL the column and fail the CHECK far from the cause.
    assert!(project_one(
        &db,
        &ev(
            &id,
            "record.updated",
            "2026-01-01T00:00:01.000Z",
            json!({ "type": Value::Null })
        ),
    )
    .await
    .is_err());

    assert_eq!(type_of(&db, &id).await, "Document");
}

#[tokio::test]
async fn only_the_dedicated_event_can_change_projected_type() {
    let db = db().await;
    let id = a_document(&db).await;
    let body_before: Option<String> = sqlx::query_scalar("SELECT body FROM records WHERE id=?")
        .bind(&id)
        .fetch_one(db.pool())
        .await
        .unwrap();
    let correction = ev(
        &id,
        "record.type_corrected.v1",
        "2026-01-01T00:00:02.000Z",
        json!({
            "from": {"type": "Document", "kind": "note"},
            "to": {"type": "Resolution", "kind": "decision"},
            "mode": "confirmed",
            "reason": "Exercise the dedicated governed correction fold.",
            "plan_id": "plan:test-correction",
            "effect_digest": format!("sha256:{}", "b".repeat(64)),
            "schema_state_revision": "schema-state-v1:meta:1:content:2",
            "confirmation_required": true
        }),
    );
    project_one(&db, &correction).await.unwrap();

    assert_eq!(type_of(&db, &id).await, "Resolution");
    assert_eq!(
        crate::common::text_of(
            &db,
            &format!("SELECT kind FROM records WHERE id = '{id}'"),
            "kind"
        )
        .await
        .as_deref(),
        Some("decision")
    );
    let body_after: Option<String> = sqlx::query_scalar("SELECT body FROM records WHERE id=?")
        .bind(&id)
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(body_after, body_before);

    let replay = project_one(&db, &correction).await.unwrap_err();
    assert!(replay
        .to_string()
        .contains("no longer matches from identity"));
}

#[tokio::test]
async fn generic_append_cannot_mint_the_governed_correction_event() {
    let db = db().await;
    let id = a_document(&db).await;
    let events_before = count(&db, "SELECT COUNT(*) AS n FROM content_events").await;
    let error = native_ce::store::append(
        &db,
        native_ce::store::AppendSpec {
            record_id: id.clone(),
            event_type: "record.type_corrected.v1".into(),
            payload: json!({
                "from": {"type": "Document", "kind": "note"},
                "to": {"type": "Resolution", "kind": "decision"},
                "mode": "confirmed",
                "reason": "A raw caller must not mint governed corrections.",
                "plan_id": "plan:raw-correction",
                "effect_digest": format!("sha256:{}", "c".repeat(64)),
                "schema_state_revision": "schema-state-v1:meta:1:content:2",
                "confirmation_required": true
            }),
            actor: None,
        },
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("correction-operation-owned"));
    assert_eq!(
        count(&db, "SELECT COUNT(*) AS n FROM content_events").await,
        events_before
    );
    assert_eq!(type_of(&db, &id).await, "Document");
}

#[tokio::test]
async fn correction_is_visible_only_at_and_after_its_historical_prefix_and_rebuilds_equal() {
    let db = db().await;
    let id = a_document(&db).await;
    let before_correction: i64 =
        sqlx::query_scalar("SELECT MAX(seq) FROM content_events WHERE record_id = ?")
            .bind(&id)
            .fetch_one(db.pool())
            .await
            .unwrap();
    let correction_seq = append_correction_fixture(&db, &id).await;

    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    let before = registry
        .call(
            db.clone(),
            Caller::local(),
            "get_record",
            json!({"ids": [&id], "as_of": {"content_seq": before_correction}}),
        )
        .await
        .unwrap();
    assert_eq!(before["records"][0]["type"], "Document");
    assert_eq!(before["records"][0]["kind"], "note");

    let after = registry
        .call(
            db.clone(),
            Caller::local(),
            "get_record",
            json!({"ids": [&id], "as_of": {"content_seq": correction_seq}}),
        )
        .await
        .unwrap();
    assert_eq!(after["records"][0]["type"], "Resolution");
    assert_eq!(after["records"][0]["kind"], "decision");
    assert_eq!(after["resolved_content_seq"], correction_seq);

    let diff = rebuild_and_diff(&db).await.unwrap();
    assert!(diff.equal, "correction replay diverged: {diff:?}");
}

/// The positive control. Without it every assertion above is satisfied by an
/// engine that has simply broken `record.updated`.
#[tokio::test]
async fn ordinary_updates_and_the_kind_axis_still_work() {
    let db = db().await;
    let id = a_document(&db).await;

    update_record(&db, &id, json!({ "kind": "sheet", "name": "Q3 budget" }))
        .await
        .expect("note -> sheet is a KIND change and must still work");

    assert_eq!(type_of(&db, &id).await, "Document");
    assert_eq!(
        crate::common::text_of(
            &db,
            &format!("SELECT kind FROM records WHERE id = '{id}'"),
            "kind"
        )
        .await
        .unwrap(),
        "sheet"
    );
}

// ---------------------------------------------------------------------------
// 2. Why it is load-bearing — link semantics have no other guard
// ---------------------------------------------------------------------------

/// `add_link` accepts any non-empty relationship string and never inspects an
/// endpoint's type, so an `Outcome -> Document` flip would silently void an inbound
/// `part_of` edge. This test documents the exposure by proving the ONLY thing
/// standing in front of it is the immutability rule.
#[tokio::test]
async fn a_type_flip_would_void_inbound_spine_links_and_is_refused() {
    let db = db().await;
    let goal = create_record(
        &db,
        json!({ "type": "Outcome", "kind": "target", "name": "Ship CE" }),
    )
    .await
    .unwrap();
    let task = create_record(
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "Freeze the DDL" }),
    )
    .await
    .unwrap();
    add_link(
        &db,
        LinkAddedPayload {
            id: None,
            source_id: task.clone(),
            target_id: goal.clone(),
            relationship: "part_of".into(),
            note: None,
        },
    )
    .await
    .unwrap();

    assert!(update_record(&db, &goal, json!({ "type": "Document" }))
        .await
        .is_err());

    assert_eq!(type_of(&db, &goal).await, "Outcome");
    assert_eq!(
        count(
            &db,
            &format!(
                "SELECT COUNT(*) AS n FROM links
                  WHERE target_id = '{goal}' AND relationship = 'part_of'"
            )
        )
        .await,
        1,
        "the edge survives because the type did"
    );
}

// ---------------------------------------------------------------------------
// 3. The tool surface — regression guard on the behaviour that always held
// ---------------------------------------------------------------------------

#[tokio::test]
async fn update_record_still_rejects_a_type_argument() {
    let db = db().await;
    let id = a_document(&db).await;
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();

    let err = registry
        .call(
            db.clone(),
            Caller::authenticated("test:local"),
            "update_record",
            crate::common::with_test_reason("update_record", json!({ "id": id, "type": "Entity" })),
        )
        .await
        .expect_err("update_record has no `type` field and denies unknown ones");
    assert!(
        err.to_string().contains("type"),
        "the rejection should name the offending field"
    );

    assert_eq!(type_of(&db, &id).await, "Document");
}

// ---------------------------------------------------------------------------
// 4. The conformance check (F6a)
// ---------------------------------------------------------------------------

fn verdict(report: &native_ce::conformance::ConformanceReport, name: &str) -> (bool, Vec<String>) {
    let check = report
        .checks
        .iter()
        .find(|c| c.check == name)
        .unwrap_or_else(|| panic!("check '{name}' missing from report"));
    (check.ok, check.violations.clone())
}

#[tokio::test]
async fn conformance_reports_type_immutability_and_a_clean_database_passes() {
    let db = db().await;
    let id = a_document(&db).await;
    update_record(&db, &id, json!({ "kind": "sheet" }))
        .await
        .unwrap();

    let report = run_conformance(&db).await;
    let (ok, violations) = verdict(&report, "type-immutability");
    assert!(ok, "clean database must pass: {violations:?}");
    assert!(report.ok, "and the suite overall: {:?}", report.checks);
}

/// The data-scan half: a log written by a permissive build must fail the check
/// even though today's binary would refuse to write it. The event is inserted
/// straight into `content_events` — `store` can no longer produce one.
#[tokio::test]
async fn conformance_catches_a_type_carrying_event_left_by_a_permissive_build() {
    let db = db().await;
    let id = a_document(&db).await;

    sqlx::query(
        "INSERT INTO content_events (id, record_id, type, payload, created_at, causal_envelope_version, causal_status)
         VALUES (?, ?, 'record.updated', ?, '2026-01-01T00:00:00.000Z', 1, 'legacy_unknown')",
    )
    .bind("legacy-type-change")
    .bind(&id)
    .bind(r#"{"type":"Entity"}"#)
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();

    let report = run_conformance(&db).await;
    let (ok, violations) = verdict(&report, "type-immutability");
    assert!(!ok, "a type-carrying event in the log is a violation");
    assert!(
        violations.iter().any(|v| v.contains("carry `type`")),
        "got: {violations:?}"
    );
}

/// The suite must never mutate the database it validates — the probes run inside
/// rolled-back transactions, and the new check adds two of them.
#[tokio::test]
async fn the_type_immutability_probes_leave_no_trace() {
    let db = db().await;
    let id = a_document(&db).await;
    let before = count(&db, "SELECT COUNT(*) AS n FROM records").await;

    run_conformance(&db).await;

    assert_eq!(
        count(&db, "SELECT COUNT(*) AS n FROM records").await,
        before
    );
    assert_eq!(type_of(&db, &id).await, "Document");
    assert!(
        rebuild_and_diff(&db)
            .await
            .unwrap()
            .tables
            .iter()
            .all(|t| t.mismatches.is_empty() && t.live == t.rebuilt),
        "probing must not drift the projections from the log"
    );
}
