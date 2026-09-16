// Equivalence between the per-record body fold (`crate::record_body`) and
// the whole-log scratch replay it replaced, plus a scale guard proving
// anchored reads no longer cost the workspace log.

use native_ce::authorization::Principal;
use native_ce::freshness::{
    assemble_context, commit_durable_output, current_record_body_revision, promote_idea,
    revise_unit, AffectedConclusion, CommitDurableOutputInput, ContextRequest, DependencyId,
    DependencyInput, ExpressionRole, IdempotencyKey, OccurrenceSelector, PromoteIdeaInput,
    ProvenanceUse, ResolutionPolicy, ReviseUnitInput, UnitContent,
};
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::query::events::log_prefix;
use native_ce::store::{append, AppendSpec};
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
        .call(
            db.clone(),
            Caller::local(),
            tool,
            crate::common::with_test_reason(tool, args),
        )
        .await
        .unwrap()
}

async fn current_body_digest(registry: &ToolRegistry, db: &Db, id: &str) -> String {
    call(registry, db, "get_record", json!({ "ids": [id] })).await["records"][0]["body_digest"]
        .as_str()
        .expect("get_record exposes body_digest")
        .to_owned()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The pre-fix implementation, kept only in this test: load the whole log
/// prefix, replay it in a scratch database, read one body.
async fn replay_body_at(db: &Db, record_id: &str, seq: i64) -> Option<Vec<u8>> {
    let prefix = log_prefix(db, seq).await.unwrap();
    let scratch = native_ce::open_database(":memory:").await.unwrap();
    native_ce::apply_schema(&scratch).await.unwrap();
    let fixture = crate::common::fixture_write_pool(&scratch).await;
    let mut conn = fixture.acquire().await.unwrap();
    native_ce::projector::replay_with_blob_seeds(db, &mut conn, &prefix, None)
        .await
        .unwrap();
    let body: Option<Option<String>> = sqlx::query_scalar("SELECT body FROM records WHERE id = ?")
        .bind(record_id)
        .fetch_optional(&mut *conn)
        .await
        .unwrap();
    drop(conn);
    scratch.close().await;
    body.map(|body| body.unwrap_or_default().into_bytes())
}

async fn fold_body_at(db: &Db, record_id: &str, seq: i64) -> Option<Vec<u8>> {
    let pool = crate::common::fixture_write_pool(db).await;
    native_ce::record_body::body_at_seq_in_pool(&pool, record_id, seq)
        .await
        .unwrap()
}

async fn anchored_comment(
    registry: &ToolRegistry,
    db: &Db,
    id: &str,
    bearer: &str,
    source: &str,
    exact: &str,
) {
    let start = source.find(exact).unwrap();
    let end = start + exact.len();
    let prefix = source[..start]
        .chars()
        .rev()
        .take(32)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<String>();
    let suffix = source[end..].chars().take(32).collect::<String>();
    call(
        registry,
        db,
        "create_record",
        json!({
            "id": id,
            "type": "Annotation",
            "kind": "comment",
            "body": format!("comment on {exact}"),
            "lifecycle": "open",
            "links": [{ "target_id": bearer, "relationship": "part_of" }],
            "target": {
                "target_record_id": bearer,
                "source_slot": "body",
                "purpose": "comment_context",
                "selectors": [
                    { "type": "text_quote", "exact": exact, "prefix": prefix, "suffix": suffix },
                    { "type": "data_position", "start": start, "end": end }
                ]
            }
        }),
    )
    .await;
}

async fn set_body(registry: &ToolRegistry, db: &Db, id: &str, body: Value) {
    let digest = current_body_digest(registry, db, id).await;
    call(
        registry,
        db,
        "update_record",
        json!({ "id": id, "body_set": body, "if_body_digest": digest }),
    )
    .await;
}

#[tokio::test]
async fn per_record_fold_matches_whole_log_replay_for_every_body_anchor() {
    let db = db().await;
    let registry = registry();
    let target = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Document", "kind": "note", "name": "Source", "body": "alpha brave passage one" }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // An anchor at each of several body revisions, exercising set / append /
    // surgical replace. Each comment pins the revision current at its own
    // creation, so the anchor rows carry distinct source_event_seq values.
    anchored_comment(
        &registry,
        &db,
        "c0aa0000-0000-4000-8000-000000000101",
        &target,
        "alpha brave passage one",
        "brave passage",
    )
    .await;
    set_body(&registry, &db, &target, json!("alpha brave passage two")).await;
    anchored_comment(
        &registry,
        &db,
        "c0aa0000-0000-4000-8000-000000000102",
        &target,
        "alpha brave passage two",
        "brave passage",
    )
    .await;
    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": target, "body_append": " plus tail" }),
    )
    .await;
    anchored_comment(
        &registry,
        &db,
        "c0aa0000-0000-4000-8000-000000000103",
        &target,
        "alpha brave passage two plus tail",
        "brave passage",
    )
    .await;
    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": target, "body_replace": [{ "old": "brave", "new": "bold" }] }),
    )
    .await;
    // A comment placed, then the body edited underneath it.
    anchored_comment(
        &registry,
        &db,
        "c0aa0000-0000-4000-8000-000000000104",
        &target,
        "alpha bold passage two plus tail",
        "bold passage",
    )
    .await;
    // Null the body after anchoring: the anchor must still resolve the
    // revision it pinned, and the null revision folds to empty.
    set_body(&registry, &db, &target, Value::Null).await;
    let null_seq: i64 = sqlx::query_scalar("SELECT MAX(seq) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    // Revive from null so a later anchor pins a post-null revision.
    set_body(&registry, &db, &target, json!("fresh start")).await;
    anchored_comment(
        &registry,
        &db,
        "c0aa0000-0000-4000-8000-000000000105",
        &target,
        "fresh start",
        "fresh",
    )
    .await;

    // Every body-slot anchor row: fold bytes must equal replay bytes, and the
    // stored digest must hash exactly those bytes (so validation.status is
    // unchanged by the implementation swap).
    let rows = sqlx::query(
        "SELECT annotation_id, target_record_id, source_event_seq, source_sha256
           FROM annotation_targets WHERE source_slot = 'body'",
    )
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert!(rows.len() >= 5, "expected five body anchors");
    for row in &rows {
        let annotation_id: String = row.try_get("annotation_id").unwrap();
        let target_record_id: String = row.try_get("target_record_id").unwrap();
        let seq: Option<i64> = row.try_get("source_event_seq").unwrap();
        let stored_sha: String = row.try_get("source_sha256").unwrap();
        let seq = seq.expect("body anchors carry a source seq");
        let folded = fold_body_at(&db, &target_record_id, seq).await;
        let replayed = replay_body_at(&db, &target_record_id, seq).await;
        assert_eq!(folded, replayed, "fold/replay diverge for {annotation_id}");
        let bytes = folded.expect("anchored seq must resolve a body");
        assert_eq!(
            sha256_hex(&bytes),
            stored_sha,
            "digest drift for {annotation_id}"
        );
    }

    // A nulled revision folds to empty under both implementations.
    assert_eq!(fold_body_at(&db, &target, null_seq).await, Some(Vec::new()));
    assert_eq!(
        replay_body_at(&db, &target, null_seq).await,
        Some(Vec::new())
    );

    // Anchored bytes stay pinned while the live body moves: before the
    // delete, every anchor is available with the revision it captured.
    let read = call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": [target], "include_comments": true }),
    )
    .await;
    for comment in read["records"][0]["comments"].as_array().unwrap() {
        assert_eq!(comment["target"]["anchored"]["available"], true);
    }

    // Soft-delete the bearer: the row survives in a replay, so the fold must
    // still return the pinned bytes (current becomes unavailable → stale).
    call(&registry, &db, "delete_record", json!({ "id": target })).await;
    for row in &rows {
        let target_record_id: String = row.try_get("target_record_id").unwrap();
        let seq: i64 = row
            .try_get::<Option<i64>, _>("source_event_seq")
            .unwrap()
            .unwrap();
        assert_eq!(
            fold_body_at(&db, &target_record_id, seq).await,
            replay_body_at(&db, &target_record_id, seq).await,
            "fold/replay diverge after delete",
        );
    }
    let read = call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": [target], "include_comments": true }),
    )
    .await;
    // The tombstoned bearer still reads, but every anchored target is stale
    // with its pinned evidence intact.
    for comment in read["records"][0]["comments"].as_array().unwrap() {
        assert_eq!(comment["target"]["anchored"]["available"], true);
        assert_eq!(comment["target"]["validation"]["status"], "stale");
    }

    // No body-bearing event at or before the seq: both report no body.
    assert_eq!(fold_body_at(&db, "no-such-record", 1).await, None);
    assert_eq!(replay_body_at(&db, "no-such-record", 1).await, None);
    let created_seq: i64 = sqlx::query_scalar(
        "SELECT seq FROM content_events WHERE record_id = ? AND type = 'record.created'",
    )
    .bind(&target)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(fold_body_at(&db, &target, created_seq - 1).await, None);
    assert_eq!(replay_body_at(&db, &target, created_seq - 1).await, None);
}

/// The two body writers beyond `record.created` / `record.updated`: a
/// `unit.revision.recorded.v1` anchor on a semantic Unit and a
/// `receipt.committed.v1` anchor on its consumer. Both pin body bytes through
/// events the pre-existing attribution fold never honoured.
#[tokio::test]
async fn fold_matches_replay_for_unit_revision_and_receipt_body_writers() {
    const ACCOUNT: &str = "acct:anchored-body-fold";
    const ACTOR: &str = "test:anchored-body-fold";
    let principal = || Principal::bound(ACCOUNT, true);

    let db = db().await;
    let registry = registry();

    // Semantic Unit with two revisions; the anchor pins the second.
    let source = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Document", "kind": "note", "name": "Idea source", "body": "Audience: technical founders." }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let promoted = promote_idea(
        &db,
        principal(),
        ACTOR,
        PromoteIdeaInput {
            source_revision: current_record_body_revision(&db, &source).await.unwrap(),
            selectors: vec![OccurrenceSelector::TextQuote {
                exact: "Audience: technical founders.".into(),
                prefix: None,
                suffix: None,
                position_hint: None,
            }],
            first_content: UnitContent::text("Primary audience: technical founders.").unwrap(),
            expression_role: ExpressionRole::Canonical,
            label: None,
            requested_unit_id: None,
            requested_occurrence_id: None,
            idempotency_key: IdempotencyKey::new("fold-unit-promote").unwrap(),
        },
    )
    .await
    .unwrap();
    let unit_id = promoted.unit_id.as_str().to_owned();
    let revised_content = "Revised audience: technical founders everywhere.";
    revise_unit(
        &db,
        principal(),
        ACTOR,
        ReviseUnitInput {
            unit_id: promoted.unit_id.clone(),
            expected_current: promoted.first_revision.clone(),
            content: UnitContent::text(revised_content).unwrap(),
            rationale: "Second revision for the fold corpus.".into(),
            idempotency_key: IdempotencyKey::new("fold-unit-revise").unwrap(),
        },
    )
    .await
    .unwrap();
    anchored_comment(
        &registry,
        &db,
        "c0aa0000-0000-4000-8000-000000000401",
        &unit_id,
        revised_content,
        "technical founders",
    )
    .await;

    // Durable-output receipt on a consumer record; the anchor pins the
    // receipt's synthesized body write.
    let consumer = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Document", "kind": "note", "name": "Homepage", "body": "Old homepage." }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let assembly = assemble_context(
        &db,
        principal(),
        ContextRequest {
            intent: "Draft positioning".into(),
            task_scope: "homepage hero".into(),
            risk_inputs: vec!["audience accuracy".into()],
        },
        Some(&consumer),
        vec![unit_id.clone()],
    )
    .await
    .unwrap();
    let source_revision = assembly.sources[0].clone();
    commit_durable_output(
        &db,
        principal(),
        ACTOR,
        CommitDurableOutputInput {
            consumer_record_id: consumer.clone(),
            expected_consumer_revision: current_record_body_revision(&db, &consumer).await.unwrap(),
            output_body: "Built for technical founders.".into(),
            assembly,
            policy: ResolutionPolicy::agent_speed_default(),
            provenance: vec![ProvenanceUse {
                source_revision: source_revision.clone(),
                reason: "Used to draft the audience line".into(),
            }],
            dependencies: vec![DependencyInput {
                dependency_id: DependencyId::new("dep-fold-corpus").unwrap(),
                source_revision,
                semantic_role: "audience premise".into(),
                affected_conclusion: AffectedConclusion {
                    key: "hero.audience".into(),
                    description: "Who the homepage addresses".into(),
                },
                rationale: "The output names the audience".into(),
                reconsideration_trigger: "Audience premise changes".into(),
                confidence: Some(0.9),
            }],
            assessments: vec![],
            reconciliations: vec![],
            unresolved_uncertainty: vec![],
            idempotency_key: IdempotencyKey::new("fold-receipt-commit").unwrap(),
        },
    )
    .await
    .unwrap();
    anchored_comment(
        &registry,
        &db,
        "c0aa0000-0000-4000-8000-000000000402",
        &consumer,
        "Built for technical founders.",
        "technical founders",
    )
    .await;

    for annotation_id in [
        "c0aa0000-0000-4000-8000-000000000401",
        "c0aa0000-0000-4000-8000-000000000402",
    ] {
        let row = sqlx::query(
            "SELECT target_record_id, source_event_seq, source_sha256
               FROM annotation_targets WHERE annotation_id = ?",
        )
        .bind(annotation_id)
        .fetch_one(db.pool())
        .await
        .unwrap();
        let target_record_id: String = row.try_get("target_record_id").unwrap();
        let seq: i64 = row
            .try_get::<Option<i64>, _>("source_event_seq")
            .unwrap()
            .expect("body anchors carry a source seq");
        let stored_sha: String = row.try_get("source_sha256").unwrap();
        let folded = fold_body_at(&db, &target_record_id, seq).await;
        let replayed = replay_body_at(&db, &target_record_id, seq).await;
        assert_eq!(folded, replayed, "fold/replay diverge for {annotation_id}");
        let bytes = folded.expect("anchored seq must resolve a body");
        assert_eq!(
            sha256_hex(&bytes),
            stored_sha,
            "digest drift for {annotation_id}"
        );
    }
}
/// Non-string bodies written as raw events: the projector binds them through
/// `push_json_arg` into a `TEXT` column, and the fold must reproduce that
/// coercion (integers/bools as decimal text, floats as `%.15g`, arrays and
/// objects as JSON text) rather than mapping everything non-string to empty.
#[tokio::test]
async fn fold_matches_replay_for_non_string_bodies() {
    let db = db().await;
    let registry = registry();
    let target = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Document", "kind": "note", "name": "Coercion", "body": "start" }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    for body in [
        json!(42),
        json!(-7),
        json!(42.0),
        json!(18446744073709551615u64),
        json!(true),
        json!(false),
        json!(4.5),
        json!(100000.0),
        json!(1e14),
        json!(150000000000000.0),
        json!(123456789012345.0),
        json!(999999999999999.0),
        json!(9.99e14),
        json!(1e15),
        json!(1e300),
        json!(0.00001),
        json!([1, "two"]),
        json!({ "k": "v" }),
        Value::Null,
    ] {
        let event = append(
            &db,
            AppendSpec {
                record_id: target.clone(),
                event_type: "record.updated".into(),
                payload: json!({ "body": body }),
                actor: None,
            },
        )
        .await
        .unwrap();
        let folded = fold_body_at(&db, &target, event.local_seq).await;
        let replayed = replay_body_at(&db, &target, event.local_seq).await;
        assert_eq!(folded, replayed, "fold/replay diverge for body {body}");
    }
}

/// Two comments quoting different passages of one unchanged revision share
/// the anchored fold but must never share a target view: each comment's
/// target carries its own annotation id, selectors, and excerpt.
#[tokio::test]
async fn sibling_anchors_on_one_revision_keep_their_own_views() {
    let db = db().await;
    let registry = registry();
    let body = "first passage and second passage";
    let target = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Document", "kind": "note", "name": "Source", "body": body }),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    // No body change between the two placements, so both anchors pin the
    // same source_event_seq; only their selectors differ.
    for (id, exact) in [
        ("c0aa0000-0000-4000-8000-000000000301", "first passage"),
        ("c0aa0000-0000-4000-8000-000000000302", "second passage"),
    ] {
        anchored_comment(&registry, &db, id, &target, body, exact).await;
    }

    let read = call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": [target], "include_comments": true }),
    )
    .await;
    let comments = read["records"][0]["comments"].as_array().unwrap();
    assert_eq!(comments.len(), 2);
    for (id, exact) in [
        ("c0aa0000-0000-4000-8000-000000000301", "first passage"),
        ("c0aa0000-0000-4000-8000-000000000302", "second passage"),
    ] {
        let comment = comments
            .iter()
            .find(|comment| comment["id"] == id)
            .unwrap_or_else(|| panic!("comment {id} missing from page"));
        assert_eq!(comment["target"]["annotation_id"], id);
        assert!(
            comment["target"]["selectors"].to_string().contains(exact),
            "selectors carry the wrong passage: {}",
            comment["target"]["selectors"]
        );
        assert_eq!(comment["target"]["anchored"]["excerpt"]["text"], exact);
        assert_eq!(comment["target"]["validation"]["status"], "current");
    }

    // Same through the start_work comment window.
    let out = call(
        &registry,
        &db,
        "start_work",
        json!({ "record_id": target, "action": "preview" }),
    )
    .await;
    let threads = out["context"]["comments"]["open_threads"]
        .as_array()
        .unwrap();
    assert_eq!(threads.len(), 2);
    for (id, exact) in [
        ("c0aa0000-0000-4000-8000-000000000301", "first passage"),
        ("c0aa0000-0000-4000-8000-000000000302", "second passage"),
    ] {
        let thread = threads
            .iter()
            .find(|thread| thread["root"]["id"] == id)
            .unwrap_or_else(|| panic!("thread {id} missing from window"));
        assert_eq!(thread["root"]["target"]["annotation_id"], id);
        assert_eq!(
            thread["root"]["target"]["anchored"]["excerpt"]["text"],
            exact
        );
    }
}
