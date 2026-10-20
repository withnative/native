//! The deferred scratch fold must be indistinguishable, at a completed
//! boundary, from folding the same events one statement at a time with every
//! trigger enabled. "Indistinguishable" is checked on the COMPLETE logical
//! state — every non-FTS-shadow table, all columns — and on both FTS indexes
//! by full hit sets and FTS5's own `integrity-check`, not on a sample.

use std::collections::BTreeMap;

use serde_json::json;

use super::{replay_projection_events_in_mode, FoldMode, FoldStage, DEFERRED_FOLD_MIN_EVENTS};

const MODES: [FoldMode; 2] = [FoldMode::Immediate, FoldMode::Deferred];

async fn fold(scratch: &Db, events: &[EventRow], mode: FoldMode) -> crate::error::Result<()> {
    replay_projection_events_in_mode(scratch, events, mode, None).await
}
use crate::authorization::Principal;
use crate::db::{apply_schema, create_database, open_database, Db};
use crate::events::EventRow;
use crate::freshness::*;
use crate::store::{archive_record, create_record, delete_record, restore_record, update_record};

const ACTOR: &str = "test:deferred-fold";
const ACCOUNT: &str = "acct:deferred-fold";

/// Fold `events` into `scratch` exactly as the seam did before deferral: one
/// transaction, immediate body derivations, every trigger enabled.
async fn fold_direct(scratch: &Db, events: &[EventRow]) -> crate::error::Result<()> {
    let mut tx = scratch.write_pool().begin().await?;
    crate::projector::replay_with_blob_placeholders(&mut tx, events).await?;
    tx.commit().await?;
    Ok(())
}

async fn fresh_scratch() -> Db {
    let scratch = open_database(":memory:").await.unwrap();
    apply_schema(&scratch).await.unwrap();
    scratch
}

/// FTS5 shadow tables of the two indexes: their bytes legitimately differ
/// between incremental maintenance and a rebuild, so they are compared only
/// through the indexes' answers.
fn is_fts_shadow(table: &str) -> bool {
    ["records_fts", "records_name_idx"]
        .iter()
        .any(|fts| table == *fts || table.starts_with(&format!("{fts}_")))
}

/// Columns `apply_schema` stamps with the wall-clock time it ran. The fold
/// never writes them (the neighbouring columns of the same rows, which it does
/// write, stay compared), and two scratches installed milliseconds apart differ
/// in them whatever the fold does.
const INSTALL_TIME_COLUMNS: &[(&str, &str)] = &[
    ("act_cutover", "cutover_at"),
    ("content_event_causal_cutover", "cutover_at"),
];

/// Every ordinary table's full contents as sorted `quote()`d rows, plus every
/// trigger and index definition, so a dropped or altered trigger is a
/// difference too. `quote()` distinguishes NULL, integer, real, text and blob
/// for the values these fixtures write; it is not a lossless serialization of
/// arbitrary values (text containing NUL, for instance), so this is an
/// equality check for the fixtures here, not a general oracle.
async fn logical_state(scratch: &Db) -> BTreeMap<String, Vec<String>> {
    snapshot(scratch, true, &[]).await
}

/// [`logical_state`] with install-time columns compared too, for checks on a
/// single scratch across a failed or cancelled fold, where nothing may change.
async fn exact_state(scratch: &Db) -> BTreeMap<String, Vec<String>> {
    snapshot(scratch, false, &[]).await
}

async fn snapshot(
    scratch: &Db,
    mask_install_time: bool,
    skip_tables: &[&str],
) -> BTreeMap<String, Vec<String>> {
    let pool = scratch.write_pool();
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master
          WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    let mut state = BTreeMap::new();
    for table in tables
        .into_iter()
        .filter(|table| !is_fts_shadow(table) && !skip_tables.contains(&table.as_str()))
    {
        // `table_xinfo`, not `table_info`, so generated columns are compared.
        let columns: Vec<String> =
            sqlx::query_scalar(&format!("SELECT name FROM pragma_table_xinfo('{table}')"))
                .fetch_all(pool)
                .await
                .unwrap();
        let row = columns
            .iter()
            .map(|column| {
                if mask_install_time
                    && INSTALL_TIME_COLUMNS.contains(&(table.as_str(), column.as_str()))
                {
                    "'<install time>'".to_owned()
                } else {
                    format!("quote(\"{column}\")")
                }
            })
            .collect::<Vec<_>>()
            .join(" || '|' || ");
        let mut rows: Vec<String> = sqlx::query_scalar(&format!("SELECT {row} FROM \"{table}\""))
            .fetch_all(pool)
            .await
            .unwrap();
        rows.sort();
        state.insert(format!("table {table}"), rows);
    }
    let definitions: Vec<String> = sqlx::query_scalar(
        "SELECT type || ' ' || name || ' ' || COALESCE(sql,'') FROM sqlite_master
          WHERE type IN ('trigger','index') ORDER BY type, name",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    state.insert("definitions".into(), definitions);
    state
}

/// Queries exercising both indexes: a word, a prefix, a stemmed form (the
/// body index is `porter`, the name index is not), and name-only words.
const FTS_QUERIES: &[&str] = &[
    "foo",
    "foo*",
    "run",
    "running",
    "beta",
    "task",
    "alpha",
    "renamed",
    "gamma",
    "archived",
    "k",
    "\"foo bar\"",
    "name: renamed",
    "nosuchword",
];

/// Full hit sets with bm25 ranks for both indexes, plus FTS5 `integrity-check`
/// (rank=1 checks an external-content index against `records`).
async fn fts_state(scratch: &Db) -> BTreeMap<String, Vec<String>> {
    let pool = scratch.write_pool();
    let mut state = BTreeMap::new();
    for table in ["records_fts", "records_name_idx"] {
        for query in FTS_QUERIES {
            // `name:` column filters only mean something on the two-column
            // index; the single-column one simply sees the same words.
            let hits: Vec<String> = sqlx::query_scalar(&format!(
                "SELECT r.id || ' ' || printf('%.9f', bm25({table}))
                   FROM {table} JOIN records r ON r.rowid = {table}.rowid
                  WHERE {table} MATCH ? ORDER BY r.id"
            ))
            .bind(query)
            .fetch_all(pool)
            .await
            .unwrap_or_else(|error| panic!("{table} MATCH {query}: {error}"));
            state.insert(format!("{table} MATCH {query}"), hits);
        }
        sqlx::query(&format!(
            "INSERT INTO {table}({table}, rank) VALUES('integrity-check', 1)"
        ))
        .execute(pool)
        .await
        .unwrap_or_else(|error| panic!("{table} integrity-check: {error}"));
    }
    state
}

async fn assert_scratches_equal(left: &Db, right: &Db, context: &str) {
    let (left_state, right_state) = (logical_state(left).await, logical_state(right).await);
    assert_eq!(
        left_state.keys().collect::<Vec<_>>(),
        right_state.keys().collect::<Vec<_>>(),
        "{context}: table sets differ"
    );
    for (key, rows) in &left_state {
        assert_eq!(rows, &right_state[key], "{context}: {key} differs");
    }
    let (left_fts, right_fts) = (fts_state(left).await, fts_state(right).await);
    assert_eq!(left_fts, right_fts, "{context}: FTS answers differ");
}

/// Append a type-correction event through the privileged historical-storage
/// seam (the public append path refuses it, by design), projecting it in the
/// same transaction as production would.
async fn correct_type(db: &Db, record_id: &str) {
    let payload = json!({
        "from": {"type": "Document", "kind": "note"},
        "to": {"type": "Resolution", "kind": "decision"},
        "mode": "confirmed",
        "reason": "Exercise the deferred fold.",
        "plan_id": "plan:deferred-fold",
        "effect_digest": format!("sha256:{}", "d".repeat(64)),
        "schema_state_revision": "schema-state-v1:meta:1:content:2",
        "confirmation_required": true
    });
    let event_id = format!("record.type_corrected.v1:{record_id}:deferred-fold");
    let created_at = "2099-01-01T00:00:00.000Z";
    let mut tx = db.write_pool().begin().await.unwrap();
    let seq: i64 = sqlx::query_scalar(
        "INSERT INTO content_events
           (id, record_id, type, payload, created_at, causal_envelope_version, causal_status)
         VALUES (?, ?, 'record.type_corrected.v1', ?, ?, 1, 'legacy_unknown') RETURNING seq",
    )
    .bind(&event_id)
    .bind(record_id)
    .bind(payload.to_string())
    .bind(created_at)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    let event = EventRow {
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
        causal_envelope: crate::events::CausalEnvelopeV1::legacy_unknown(),
        act: None,
    };
    crate::projector::project(&mut tx, &event).await.unwrap();
    tx.commit().await.unwrap();
}

/// Unit promotion + revision (`unit.revision.recorded.v1`, which writes all
/// four body tables) and a durable output commit (`receipt.committed.v1`,
/// which synthesizes a body update under the receipt's own sequence).
async fn freshness_history(db: &Db) {
    let principal = || Principal::bound(ACCOUNT, true);
    let sentence = "Audience: technical founders foo.";
    let source_id = "f9e50000-0000-4000-8000-000000000101";
    let consumer_id = "f9e50000-0000-4000-8000-000000000301";
    create_record(
        db,
        json!({"id": source_id, "type": "Document", "kind": "note", "name": "Source doc",
               "body": sentence}),
    )
    .await
    .unwrap();
    let source_revision = current_record_body_revision(db, source_id).await.unwrap();
    let promoted = promote_idea(
        db,
        principal(),
        ACTOR,
        PromoteIdeaInput {
            source_revision,
            selectors: vec![OccurrenceSelector::TextQuote {
                exact: sentence.into(),
                prefix: None,
                suffix: None,
                position_hint: None,
            }],
            first_content: UnitContent::text("Primary audience: technical founders foo.").unwrap(),
            expression_role: ExpressionRole::Canonical,
            label: Some("Audience".into()),
            requested_unit_id: Some(
                UnitId::new("f9e50000-0000-4000-8000-000000000201".to_owned()).unwrap(),
            ),
            requested_occurrence_id: Some(OccurrenceId::new("deferred:occurrence").unwrap()),
            idempotency_key: IdempotencyKey::new("deferred:promote").unwrap(),
        },
    )
    .await
    .unwrap();
    create_record(
        db,
        json!({"id": consumer_id, "type": "Document", "kind": "note", "name": "Consumer",
               "body": "Initial consumer body."}),
    )
    .await
    .unwrap();
    let initial = current_record_body_revision(db, consumer_id).await.unwrap();
    let request = || ContextRequest {
        intent: "Exercise the deferred fold".into(),
        task_scope: "deferred fold".into(),
        risk_inputs: vec!["audience accuracy".into()],
    };
    let assembly = assemble_context(
        db,
        principal(),
        request(),
        Some(consumer_id),
        vec![promoted.unit_id.as_str().into()],
    )
    .await
    .unwrap();
    let mut policy = ResolutionPolicy::agent_speed_default();
    policy.dependency_budget = 1;
    commit_durable_output(
        db,
        principal(),
        ACTOR,
        CommitDurableOutputInput {
            consumer_record_id: consumer_id.to_owned(),
            expected_consumer_revision: initial,
            output_body:
                "Committed output for technical founders foo.\n\n- [x] shipped [[Beta Note]]\n- [ ] follow up"
                    .into(),
            assembly,
            policy,
            provenance: vec![ProvenanceUse {
                source_revision: promoted.first_revision.clone(),
                reason: "Audience evidence".into(),
            }],
            dependencies: vec![DependencyInput {
                dependency_id: DependencyId::new("deferred:dc1").unwrap(),
                source_revision: promoted.first_revision.clone(),
                semantic_role: "audience premise".into(),
                affected_conclusion: AffectedConclusion {
                    key: "hero.audience".into(),
                    description: "Audience named by the hero".into(),
                },
                rationale: "The output names the selected audience".into(),
                reconsideration_trigger: "The audience changes".into(),
                confidence: Some(0.9),
            }],
            assessments: vec![],
            reconciliations: vec![],
            unresolved_uncertainty: vec![],
            idempotency_key: IdempotencyKey::new("deferred:commit").unwrap(),
        },
    )
    .await
    .unwrap();
    // A second and third Unit body, so the unit record's body is rewritten.
    let revised = revise_unit(
        db,
        principal(),
        ACTOR,
        ReviseUnitInput {
            unit_id: promoted.unit_id.clone(),
            expected_current: promoted.first_revision,
            // Populates mentions and task rows that the next revision must
            // replace (with JSON object text, which leaves none of either).
            content: UnitContent::text(
                "Primary audience: nontechnical operators running foo.\n\n- [ ] confirm [[Alpha]]",
            )
            .unwrap(),
            rationale: "First revision".into(),
            idempotency_key: IdempotencyKey::new("deferred:revise-1").unwrap(),
        },
    )
    .await
    .unwrap();
    revise_unit(
        db,
        principal(),
        ACTOR,
        ReviseUnitInput {
            unit_id: promoted.unit_id,
            expected_current: revised.new_revision,
            content: UnitContent::text(r#"{"audience":"operators","tag":"foo gamma"}"#).unwrap(),
            rationale: "Second revision".into(),
            idempotency_key: IdempotencyKey::new("deferred:revise-2").unwrap(),
        },
    )
    .await
    .unwrap();
}

/// A live database whose history reaches every deferred writer: create,
/// repeated body updates, a bodyless update, delete followed by later events,
/// string vs non-string JSON bodies with identical coerced text, a Message,
/// Unit revisions, a receipt, archive/restore and a type correction.
async fn fixture() -> (Db, Vec<EventRow>) {
    let db = create_database(":memory:").await.unwrap();

    let alpha = create_record(
        &db,
        json!({"type": "Document", "kind": "note", "name": "Alpha foo project",
               "body": "alpha [[Beta Note]] beta abcdef1\n\n- [ ] task one"}),
    )
    .await
    .unwrap();
    for round in 0..4 {
        update_record(
            &db,
            &alpha,
            json!({"body": format!(
                "# Plan {round}\n\nfoo running runs beta [[Beta Note]]\n\n- [ ] task a\n- [x] task b\n\n{}",
                "filler ".repeat(round + 1)
            )}),
        )
        .await
        .unwrap();
    }
    // A bodyless update must leave every derived row and its provenance alone.
    update_record(&db, &alpha, json!({"name": "Alpha renamed foobar"}))
        .await
        .unwrap();

    // The same coerced text, once as a JSON string and once as a JSON object:
    // their `body_blocks` differ (Markdown vs Opaque) though `records.body`
    // is identical, which is why the deferred entry keeps the format.
    let text = r#"{"k":"v","text":"foo bar"}"#;
    let as_string = create_record(
        &db,
        json!({"type": "Document", "kind": "note", "name": "String body", "body": text}),
    )
    .await
    .unwrap();
    let as_object = create_record(
        &db,
        json!({"type": "Document", "kind": "note", "name": "Object body",
               "body": {"k": "v", "text": "foo bar"}}),
    )
    .await
    .unwrap();
    update_record(
        &db,
        &as_object,
        json!({"body": {"k": "v2", "text": "foo bar"}}),
    )
    .await
    .unwrap();
    update_record(
        &db,
        &as_object,
        json!({"body": {"k": "v", "text": "foo bar"}}),
    )
    .await
    .unwrap();
    update_record(&db, &as_string, json!({"body": text}))
        .await
        .unwrap();
    // Explicit null and empty replacements remove the derived rows.
    let nulled = create_record(
        &db,
        json!({"type": "Document", "kind": "note", "name": "Nulled", "body": "gamma - [ ] t"}),
    )
    .await
    .unwrap();
    update_record(&db, &nulled, json!({"body": null}))
        .await
        .unwrap();
    let emptied = create_record(
        &db,
        json!({"type": "Document", "kind": "note", "name": "Emptied", "body": "gamma [[x y]]"}),
    )
    .await
    .unwrap();
    update_record(&db, &emptied, json!({"body": ""}))
        .await
        .unwrap();

    // A tombstone clears mentions only: blocks, tasks and JSON nodes stay.
    let doomed = create_record(
        &db,
        json!({"type": "Document", "kind": "note", "name": "Doomed foo",
               "body": "foo [[Alpha]] - [ ] doomed task"}),
    )
    .await
    .unwrap();
    update_record(
        &db,
        &doomed,
        json!({"body": "foo again [[Alpha]]\n\n- [ ] still a task"}),
    )
    .await
    .unwrap();
    delete_record(&db, &doomed).await.unwrap();
    // A JSON-bodied tombstone: its record-body nodes must survive the delete.
    let doomed_json = create_record(
        &db,
        json!({"type": "Document", "kind": "note", "name": "Doomed json",
               "body": {"k": "doomed", "text": "foo"}}),
    )
    .await
    .unwrap();
    delete_record(&db, &doomed_json).await.unwrap();
    // ... and events after the delete, on other records.
    update_record(
        &db,
        &alpha,
        json!({"body": "after delete foo [[Beta Note]] running"}),
    )
    .await
    .unwrap();

    let archived = create_record(
        &db,
        json!({"type": "Document", "kind": "note", "name": "Archived foo", "body": "archived foo"}),
    )
    .await
    .unwrap();
    archive_record(&db, &archived).await.unwrap();
    restore_record(&db, &archived).await.unwrap();
    archive_record(&db, &archived).await.unwrap();

    let corrected = create_record(
        &db,
        json!({"type": "Document", "kind": "note", "name": "Corrected", "body": "foo corrected"}),
    )
    .await
    .unwrap();
    correct_type(&db, &corrected).await;

    // A Message, whose own mentions table is cleared on delete.
    let message = create_record(
        &db,
        json!({"type": "Message", "kind": "text", "name": "Message foo",
               "body": "hello foo [[Alpha]]"}),
    )
    .await
    .unwrap();
    delete_record(&db, &message).await.unwrap();

    freshness_history(&db).await;

    let head: i64 = sqlx::query_scalar("SELECT MAX(seq) FROM content_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    let events = crate::query::events::log_prefix(&db, head).await.unwrap();
    for needed in [
        "record.created",
        "record.updated",
        "record.deleted",
        "record.type_corrected.v1",
        "unit.revision.recorded.v1",
        "receipt.committed.v1",
    ] {
        assert!(
            events.iter().any(|event| event.event_type == needed),
            "fixture must contain {needed}"
        );
    }
    (db, events)
}

/// Expected rows per writer, independent of any second fold: the differential
/// comparison shares the body helper between both paths, so it cannot see a
/// regression common to them.
async fn assert_writer_rows(scratch: &Db, events: &[EventRow]) {
    let pool = scratch.write_pool();
    let seq_of = |event_type: &str, record_id: &str| {
        events
            .iter()
            .filter(|event| event.event_type == event_type && event.record_id == record_id)
            .map(|event| event.local_seq)
            .max()
            .unwrap_or_else(|| panic!("fixture has no {event_type} for {record_id}"))
    };
    let seqs = |table: &'static str, column: &'static str, id_column: &'static str, id: String| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>(&format!(
                "SELECT DISTINCT {column} FROM {table} WHERE {id_column}=?"
            ))
            .bind(id)
            .fetch_all(&pool)
            .await
            .unwrap()
        }
    };
    let count = |table: &'static str, id_column: &'static str, id: String| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>(&format!(
                "SELECT COUNT(*) FROM {table} WHERE {id_column}=?"
            ))
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };
    let id_named = |name: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, String>("SELECT id FROM records WHERE name=?")
                .bind(name)
                .fetch_one(&pool)
                .await
                .unwrap()
        }
    };

    // `receipt.committed.v1` synthesizes the update: every derived row keeps
    // the RECEIPT's own sequence, and its output replaced the earlier body.
    let consumer = "f9e50000-0000-4000-8000-000000000301".to_owned();
    let receipt_seq = seq_of("receipt.committed.v1", &consumer);
    for (table, id_column) in [
        ("body_blocks", "record_id"),
        ("body_task_items", "record_id"),
        ("record_mentions", "source_id"),
    ] {
        assert_eq!(
            seqs(table, "source_event_seq", id_column, consumer.clone()).await,
            vec![receipt_seq],
            "{table} for the receipt's consumer"
        );
    }
    assert_eq!(count("body_task_items", "record_id", consumer).await, 2);

    // The last Unit revision is JSON object text: it replaced the populated
    // mention and task rows of the one before it, and left JSON nodes.
    let unit = "f9e50000-0000-4000-8000-000000000201".to_owned();
    assert_eq!(count("record_mentions", "source_id", unit.clone()).await, 0);
    assert_eq!(count("body_task_items", "record_id", unit.clone()).await, 0);
    assert!(count("record_body_json_nodes", "record_id", unit.clone()).await > 0);
    assert_eq!(
        seqs("body_blocks", "source_event_seq", "record_id", unit.clone()).await,
        vec![seq_of("unit.revision.recorded.v1", &unit)]
    );

    // A tombstone clears mentions only.
    for (name, expect_tasks, expect_nodes) in
        [("Doomed foo", true, false), ("Doomed json", false, true)]
    {
        let id = id_named(name).await;
        assert_eq!(
            count("record_mentions", "source_id", id.clone()).await,
            0,
            "{name}"
        );
        assert!(
            count("body_blocks", "record_id", id.clone()).await > 0,
            "{name}"
        );
        assert_eq!(
            count("body_task_items", "record_id", id.clone()).await > 0,
            expect_tasks,
            "{name}"
        );
        assert_eq!(
            count("record_body_json_nodes", "record_id", id).await > 0,
            expect_nodes,
            "{name}"
        );
    }
}

#[tokio::test]
async fn deferred_fold_equals_direct_fold_on_complete_state() {
    let (live, events) = fixture().await;

    let direct = fresh_scratch().await;
    fold_direct(&direct, &events).await.unwrap();
    // Both seam modes must equal the all-triggers, event-by-event fold.
    for mode in MODES {
        let scratch = fresh_scratch().await;
        fold(&scratch, &events, mode).await.unwrap();
        assert_scratches_equal(&direct, &scratch, &format!("whole fold, {mode:?}")).await;
        scratch.close().await;
    }
    let deferred = fresh_scratch().await;
    fold(&deferred, &events, FoldMode::Deferred).await.unwrap();
    for scratch in [&direct, &deferred] {
        assert_writer_rows(scratch, &events).await;
    }

    // The fixture is only evidence if the compared tables are populated.
    let state = logical_state(&deferred).await;
    for table in [
        "records",
        "body_blocks",
        "record_mentions",
        "body_task_items",
        "record_body_json_nodes",
        "message_mentions",
        "content_events",
    ] {
        let rows = &state[&format!("table {table}")];
        if table == "message_mentions" {
            continue; // declared by Messages with mentions; compared regardless
        }
        assert!(
            !rows.is_empty(),
            "{table} is empty: the fixture proves nothing"
        );
    }
    // Both forms of the same coerced text are present and distinguishable.
    let blocks = &state["table body_blocks"];
    assert!(
        blocks
            .iter()
            .any(|row| row.contains("opaque") || row.contains("Opaque")),
        "an Opaque (non-string) body block must exist"
    );
    for scratch in [&direct, &deferred] {
        scratch.close().await;
    }
    live.close().await;
}

/// The scratch is read between two folds (the version diff reads after the
/// first call and then advances it), and an empty slice is a legal call. Every
/// combination of modes must give the same boundary and the same end state —
/// in particular a deferred first slice followed by an immediate small tail,
/// which is what a version diff's second slice becomes.
#[tokio::test]
async fn two_slices_equal_one_fold_and_the_boundary_is_observable() {
    let (live, events) = fixture().await;
    let whole = fresh_scratch().await;
    fold_direct(&whole, &events).await.unwrap();

    for split in [
        0,
        1,
        events.len() / 3,
        events.len() / 2,
        events.len() - 3,
        events.len(),
    ] {
        let (first, second) = events.split_at(split);
        let prefix = fresh_scratch().await;
        fold_direct(&prefix, first).await.unwrap();
        for first_mode in MODES {
            for second_mode in MODES {
                let context = format!("split {split}, {first_mode:?} then {second_mode:?}");
                let advancing = fresh_scratch().await;
                fold(&advancing, first, first_mode).await.unwrap();

                // Observable boundary: the scratch after slice A alone is a
                // direct fold of A — fully materialised, triggers restored —
                // before B.
                assert_scratches_equal(&prefix, &advancing, &format!("after A ({context})")).await;

                fold(&advancing, second, second_mode).await.unwrap();
                assert_scratches_equal(&whole, &advancing, &format!("A then B ({context})")).await;
                advancing.close().await;
            }
        }
        prefix.close().await;
    }
    whole.close().await;
    live.close().await;
}

/// A bare scratch can be advanced through many one-event slices (every
/// boundary materialised each time) and still match one fold — in either mode,
/// and alternating between them.
#[tokio::test]
async fn single_event_slices_equal_one_fold() {
    let (live, events) = fixture().await;
    let whole = fresh_scratch().await;
    fold_direct(&whole, &events).await.unwrap();
    for (name, pick) in [
        (
            "immediate",
            (|_| FoldMode::Immediate) as fn(usize) -> FoldMode,
        ),
        ("deferred", |_| FoldMode::Deferred),
        ("alternating", |index| MODES[index % 2]),
    ] {
        let stepped = fresh_scratch().await;
        for (index, event) in events.iter().enumerate() {
            fold(&stepped, std::slice::from_ref(event), pick(index))
                .await
                .unwrap();
        }
        assert_scratches_equal(&whole, &stepped, &format!("one event at a time, {name}")).await;
        stepped.close().await;
    }
    whole.close().await;
    live.close().await;
}

/// Slices below the threshold fold immediately and larger ones defer.
#[test]
fn small_slices_take_the_immediate_path() {
    assert_eq!(FoldMode::for_slice(0), FoldMode::Immediate);
    assert_eq!(
        FoldMode::for_slice(DEFERRED_FOLD_MIN_EVENTS - 1),
        FoldMode::Immediate
    );
    assert_eq!(
        FoldMode::for_slice(DEFERRED_FOLD_MIN_EVENTS),
        FoldMode::Deferred
    );
}

fn with_body(template: &EventRow, seq: i64, id: &str, body: &str) -> EventRow {
    let mut event = template.clone();
    event.local_seq = seq;
    event.id = id.to_owned();
    event.payload = Some(json!({ "body": body }).to_string());
    event
}

/// More than 4096 paragraph blocks exceeds the block projection's chunk
/// limit, so `body_blocks` extraction refuses it.
fn invalid_body() -> String {
    "p\n\n".repeat(5000)
}

fn first_update_for(events: &[EventRow], record_id: &str) -> EventRow {
    events
        .iter()
        .find(|event| event.event_type == "record.updated" && event.record_id == record_id)
        .cloned()
        .expect("fixture updates the record")
}

async fn alpha_id(live: &Db) -> String {
    sqlx::query_scalar("SELECT id FROM records WHERE name='Alpha renamed foobar'")
        .fetch_one(live.write_pool())
        .await
        .unwrap()
}

/// An invalid body that a later event supersedes: the immediate fold (and the
/// low-level helpers) abort at it, the deferred fold accepts it. The accepted
/// result must be the same scratch as folding the history with that body made
/// valid — everything but the logged payload of the superseded event.
#[tokio::test]
async fn invalid_superseded_body_folds_deferred_and_matches_a_valid_reference() {
    let (live, events) = fixture().await;
    let alpha = alpha_id(&live).await;
    let template = first_update_for(&events, &alpha);
    let head = events.last().unwrap().local_seq;
    let created_at = events.last().unwrap().created_at.clone();
    let mut bad = with_body(&template, head + 1, "deferred-bad-1", &invalid_body());
    bad.created_at = created_at.clone();
    let mut good = with_body(&template, head + 2, "deferred-good-2", "recovered foo body");
    good.created_at = created_at.clone();
    let mut superseded = events.clone();
    superseded.extend([bad.clone(), good.clone()]);

    // Low-level replay, and the seam's immediate mode, still fail AT the bad
    // event even though a later event supersedes it.
    let low_level = fresh_scratch().await;
    let error = fold_direct(&low_level, &superseded).await.unwrap_err();
    assert!(
        error.to_string().contains("block projection limit") || error.to_string().contains("chunk"),
        "unexpected low-level error: {error}"
    );
    let immediate = fresh_scratch().await;
    let error = fold(&immediate, &superseded, FoldMode::Immediate)
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("body_blocks extraction failed"),
        "{error}"
    );
    low_level.close().await;
    immediate.close().await;

    // Deferred accepts it. The reference is the same history with the
    // superseded body made valid, so only the logged payload of that one
    // event may differ (`content_events`); every other table and both FTS
    // indexes — final records, bodies, epochs, metadata — must be identical.
    let mut valid_bad = bad.clone();
    valid_bad.payload = Some(json!({"body": "valid intermediate foo body"}).to_string());
    let mut reference_events = events.clone();
    reference_events.extend([valid_bad, good.clone()]);
    let reference = fresh_scratch().await;
    fold_direct(&reference, &reference_events).await.unwrap();
    let deferred = fresh_scratch().await;
    fold(&deferred, &superseded, FoldMode::Deferred)
        .await
        .unwrap();
    assert_eq!(
        snapshot(&reference, true, &["content_events"]).await,
        snapshot(&deferred, true, &["content_events"]).await,
        "state differs from the valid-body reference"
    );
    assert_eq!(fts_state(&reference).await, fts_state(&deferred).await);
    let final_body: String = sqlx::query_scalar("SELECT body FROM records WHERE id=?")
        .bind(&alpha)
        .fetch_one(deferred.write_pool())
        .await
        .unwrap();
    assert_eq!(final_body, "recovered foo body");
    reference.close().await;
    deferred.close().await;
    live.close().await;
}

#[tokio::test]
async fn invalid_final_body_rolls_back_and_the_scratch_advances_afterwards() {
    let (live, events) = fixture().await;
    let alpha = alpha_id(&live).await;
    let template = first_update_for(&events, &alpha);
    let head = events.last().unwrap().local_seq;
    let created_at = events.last().unwrap().created_at.clone();
    let mut bad = with_body(&template, head + 1, "deferred-bad-1", &invalid_body());
    bad.created_at = created_at.clone();
    let mut good = with_body(&template, head + 2, "deferred-good-2", "recovered foo body");
    good.created_at = created_at;

    // An invalid FINAL body fails the fold and leaves the scratch untouched —
    // including the six triggers the fold had dropped and the install-time
    // columns the comparisons elsewhere mask.
    let advancing = fresh_scratch().await;
    fold(&advancing, &events, FoldMode::Deferred).await.unwrap();
    let before = exact_state(&advancing).await;
    let before_fts = fts_state(&advancing).await;
    let failure = fold(&advancing, std::slice::from_ref(&bad), FoldMode::Deferred)
        .await
        .unwrap_err();
    assert!(
        failure
            .to_string()
            .contains("body_blocks extraction failed"),
        "{failure}"
    );
    assert_eq!(
        exact_state(&advancing).await,
        before,
        "failed slice left state behind"
    );
    assert_eq!(fts_state(&advancing).await, before_fts);
    assert_eq!(fts_trigger_count(&advancing).await, 6);
    // ... and the scratch still advances normally afterwards: the bad body is
    // superseded within this slice, so it folds.
    fold(&advancing, &[bad, good], FoldMode::Deferred)
        .await
        .unwrap();
    advancing.close().await;
    live.close().await;
}

async fn fts_trigger_count(scratch: &Db) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name IN
         ('records_fts_ai','records_fts_ad','records_fts_au',
          'records_name_idx_ai','records_name_idx_ad','records_name_idx_au')",
    )
    .fetch_one(scratch.write_pool())
    .await
    .unwrap()
}

// --- connection settings -------------------------------------------------
//
// The fold changes `synchronous` and `temp_store` on one pooled connection.
// These tests hold EVERY connection the pool can hold, so they inspect each
// physical connection that exists rather than whichever one a query happens
// to check out, and start from settings the fold does not use.

/// The settings the fold applies; a connection showing either has leaked.
const FOLD_SYNCHRONOUS: i64 = 0; // OFF
const FOLD_TEMP_STORE: i64 = 2; // MEMORY
/// Distinctive "original" settings: NORMAL and FILE.
const ORIGINAL: (i64, i64) = (1, 1);

async fn hold_every_connection(scratch: &Db) -> Vec<sqlx::pool::PoolConnection<sqlx::Sqlite>> {
    let capacity = scratch.write_pool().options().get_max_connections();
    let mut held = Vec::new();
    for _ in 0..capacity {
        held.push(scratch.write_pool().acquire().await.unwrap());
    }
    held
}

async fn settings_of(conn: &mut sqlx::SqliteConnection) -> (i64, i64) {
    (
        sqlx::query_scalar("PRAGMA synchronous")
            .fetch_one(&mut *conn)
            .await
            .unwrap(),
        sqlx::query_scalar("PRAGMA temp_store")
            .fetch_one(&mut *conn)
            .await
            .unwrap(),
    )
}

/// Put every connection on [`ORIGINAL`] and fill the pool to capacity.
async fn start_from_original_settings(scratch: &Db) {
    for mut conn in hold_every_connection(scratch).await {
        sqlx::query("PRAGMA synchronous = NORMAL")
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("PRAGMA temp_store = FILE")
            .execute(&mut *conn)
            .await
            .unwrap();
        assert_eq!(settings_of(&mut conn).await, ORIGINAL);
    }
}

async fn every_connection_settings(scratch: &Db) -> Vec<(i64, i64)> {
    let mut settings = Vec::new();
    for mut conn in hold_every_connection(scratch).await {
        settings.push(settings_of(&mut conn).await);
    }
    settings
}

fn assert_no_leak(settings: &[(i64, i64)], context: &str) {
    assert!(!settings.is_empty());
    for (synchronous, temp_store) in settings {
        assert_ne!(
            *synchronous, FOLD_SYNCHRONOUS,
            "{context}: synchronous leaked: {settings:?}"
        );
        assert_ne!(
            *temp_store, FOLD_TEMP_STORE,
            "{context}: temp_store leaked: {settings:?}"
        );
    }
}

/// A completed fold, and one that returns an error, restore the original
/// settings on the connection they used (and leave the others alone).
#[tokio::test]
async fn fold_pragmas_are_restored_after_success_and_after_an_error() {
    let (live, events) = fixture().await;
    let alpha = alpha_id(&live).await;
    let template = first_update_for(&events, &alpha);
    let mut bad = with_body(
        &template,
        events.last().unwrap().local_seq + 1,
        "bad",
        &invalid_body(),
    );
    bad.created_at = events.last().unwrap().created_at.clone();

    let scratch = fresh_scratch().await;
    start_from_original_settings(&scratch).await;
    fold(&scratch, &events, FoldMode::Deferred).await.unwrap();
    let settings = every_connection_settings(&scratch).await;
    assert!(
        settings.iter().all(|settings| *settings == ORIGINAL),
        "after success: {settings:?}"
    );
    fold(&scratch, std::slice::from_ref(&bad), FoldMode::Deferred)
        .await
        .unwrap_err();
    let settings = every_connection_settings(&scratch).await;
    assert!(
        settings.iter().all(|settings| *settings == ORIGINAL),
        "after an error: {settings:?}"
    );
    scratch.close().await;
    live.close().await;
}

/// Pause the deferred fold of `events` at `stage` and drop the future there.
async fn fold_dropped_at(scratch: &Db, events: &[EventRow], stage: FoldStage) {
    let reached = std::sync::Arc::new(tokio::sync::Notify::new());
    let probe = {
        let reached = reached.clone();
        move |at: FoldStage| -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
            let reached = reached.clone();
            Box::pin(async move {
                if at == stage {
                    reached.notify_one();
                    std::future::pending::<()>().await;
                }
            })
        }
    };
    let fold = replay_projection_events_in_mode(scratch, events, FoldMode::Deferred, Some(&probe));
    tokio::select! {
        result = fold => panic!("fold finished before reaching {stage:?}: {result:?}"),
        () = reached.notified() => {}
    }
    // `fold` was dropped here, at `stage`, by leaving the select.
}

/// Dropping the future at any point before the commit leaves the scratch as
/// it was; at any point at all, no pooled connection keeps the fold's
/// settings and the scratch still advances to the right end state.
#[tokio::test]
async fn a_dropped_fold_leaves_no_leaked_pragmas_and_no_partial_state() {
    let (live, events) = fixture().await;
    let whole = fresh_scratch().await;
    fold_direct(&whole, &events).await.unwrap();
    let split = events.len() / 2;
    let (first, second) = events.split_at(split);

    for stage in [
        FoldStage::PragmasPartlyEntered,
        FoldStage::AfterPragmas,
        FoldStage::AfterTriggersDropped,
        FoldStage::AfterReplay,
        FoldStage::AfterFlush,
        FoldStage::AfterRebuild,
        FoldStage::BeforeCommit,
        FoldStage::AfterCommit,
        FoldStage::PragmasPartlyRestored,
    ] {
        let committed = matches!(
            stage,
            FoldStage::AfterCommit | FoldStage::PragmasPartlyRestored
        );
        let scratch = fresh_scratch().await;
        start_from_original_settings(&scratch).await;
        fold(&scratch, first, FoldMode::Deferred).await.unwrap();
        let before = exact_state(&scratch).await;
        let before_fts = fts_state(&scratch).await;

        fold_dropped_at(&scratch, second, stage).await;

        assert_no_leak(
            &every_connection_settings(&scratch).await,
            &format!("{stage:?}"),
        );
        assert_eq!(fts_trigger_count(&scratch).await, 6, "{stage:?}");
        if committed {
            // The commit is the line: the slice stands, fully materialised.
            assert_scratches_equal(&whole, &scratch, &format!("dropped at {stage:?}")).await;
        } else {
            assert_eq!(
                exact_state(&scratch).await,
                before,
                "state after drop at {stage:?}"
            );
            assert_eq!(
                fts_state(&scratch).await,
                before_fts,
                "FTS after drop at {stage:?}"
            );
            // Usable: the same slice folds cleanly afterwards.
            fold(&scratch, second, FoldMode::Deferred).await.unwrap();
            assert_scratches_equal(&whole, &scratch, &format!("retry after {stage:?}")).await;
        }
        assert_no_leak(
            &every_connection_settings(&scratch).await,
            &format!("{stage:?} after"),
        );
        scratch.close().await;
    }
    whole.close().await;
    live.close().await;
}
