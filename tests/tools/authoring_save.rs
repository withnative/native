//! Focused `save_account` contract tests.

use native_ce::authoring::SaveAccountInput;
use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
use native_ce::freshness::current_record_body_revision;
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::{create_database, Db};
use serde_json::{json, Value};

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

async fn fixture() -> (Db, ToolRegistry) {
    (create_database(":memory:").await.unwrap(), registry())
}

async fn call(
    registry: &ToolRegistry,
    db: &Db,
    caller: Caller,
    tool: &str,
    args: Value,
) -> native_ce::Result<Value> {
    registry
        .call(
            db.clone(),
            caller,
            tool,
            crate::common::with_test_reason(tool, args),
        )
        .await
}

async fn document(registry: &ToolRegistry, db: &Db, kind: &str, body: &str) -> String {
    call(
        registry,
        db,
        Caller::local(),
        "create_record",
        json!({"type":"Document","kind":kind,"name":"fixture","body":body}),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn request(db: &Db, output: &str, source: &str, key: &str, body: &str) -> Value {
    let output_revision = current_record_body_revision(db, output).await.unwrap();
    let source_revision = current_record_body_revision(db, source).await.unwrap();
    json!({
        "record_id": output,
        "expected_revision_event_id": output_revision.revision_event_id,
        "body": body,
        "sources": [{
            "record_id": source,
            "revision_event_id": source_revision.revision_event_id,
            "role": "Reviewed premise",
            "reason": "This exact text was used for the account."
        }],
        "idempotency_key": key,
        "reason": "Preserve the exact inspected basis."
    })
}

async fn receipt_count(db: &Db) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM content_events WHERE type='receipt.committed.v1'")
        .fetch_one(db.pool())
        .await
        .unwrap()
}

#[tokio::test]
async fn replay_survives_changed_heads_but_rechecks_source_authority() {
    let (db, registry) = fixture().await;
    let source = document(&registry, &db, "note", "Premise one.").await;
    let output = document(&registry, &db, "note", "Draft.").await;
    for id in [&source, &output] {
        replace_explicit_policy(
            &db,
            "fixture",
            id,
            vec![AllowEntry::account("writer", Capability::Manage)],
        )
        .await
        .unwrap();
    }
    let args = request(
        &db,
        &output,
        &source,
        "replay-after-change",
        "Line one.\n\nLine two.",
    )
    .await;
    let first = call(
        &registry,
        &db,
        Caller::authenticated("writer"),
        "save_account",
        args.clone(),
    )
    .await
    .unwrap();
    assert_eq!(first["record_id"], output);
    assert_eq!(receipt_count(&db).await, 1);
    let actor: String =
        sqlx::query_scalar("SELECT actor FROM content_events WHERE type='receipt.committed.v1'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(
        actor, "writer",
        "event actor must be transport-authenticated caller"
    );

    call(
        &registry,
        &db,
        Caller::local(),
        "update_record",
        json!({"id":source,"body_append":" Premise two."}),
    )
    .await
    .unwrap();
    let replay = call(
        &registry,
        &db,
        Caller::authenticated("writer"),
        "save_account",
        args.clone(),
    )
    .await
    .unwrap();
    assert_eq!(replay, first);
    assert_eq!(receipt_count(&db).await, 1);

    replace_explicit_policy(
        &db,
        "fixture",
        &source,
        vec![AllowEntry::account("custodian", Capability::Manage)],
    )
    .await
    .unwrap();
    let before = receipt_count(&db).await;
    let error = call(
        &registry,
        &db,
        Caller::authenticated("writer"),
        "save_account",
        args,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("unavailable"), "{error}");
    assert!(!error.contains(&source), "hidden source id leaked: {error}");
    assert_eq!(receipt_count(&db).await, before);
    db.close().await;
}

#[tokio::test]
async fn same_key_changed_request_conflicts_without_writing() {
    let (db, registry) = fixture().await;
    let source = document(&registry, &db, "note", "Premise.").await;
    let output = document(&registry, &db, "note", "Draft.").await;
    let args = request(&db, &output, &source, "same-key", "First body.").await;
    call(
        &registry,
        &db,
        Caller::local(),
        "save_account",
        args.clone(),
    )
    .await
    .unwrap();
    let mut changed = args;
    changed["body"] = json!("Changed body.");
    let error = call(&registry, &db, Caller::local(), "save_account", changed)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("idempotency key"), "{error}");
    assert_eq!(receipt_count(&db).await, 1);
    db.close().await;
}

#[tokio::test]
async fn concurrent_identical_first_attempts_converge_on_one_receipt() {
    let (db, registry) = fixture().await;
    let source = document(&registry, &db, "note", "Premise.").await;
    let output = document(&registry, &db, "note", "Draft.").await;
    for id in [&source, &output] {
        replace_explicit_policy(
            &db,
            "fixture",
            id,
            vec![AllowEntry::account("writer", Capability::Manage)],
        )
        .await
        .unwrap();
    }
    let input: SaveAccountInput = serde_json::from_value(
        request(
            &db,
            &output,
            &source,
            "concurrent-first-attempt",
            "One durable result.",
        )
        .await,
    )
    .unwrap();
    let left_input = input.clone();
    let right_input = input;
    let left = native_ce::authoring::save_account(
        &db,
        native_ce::authorization::Principal::bound("writer", true),
        "writer",
        left_input,
    );
    let right = native_ce::authoring::save_account(
        &db,
        native_ce::authorization::Principal::bound("writer", true),
        "writer",
        right_input,
    );
    let (left, right) = tokio::join!(left, right);
    assert_eq!(left.unwrap(), right.unwrap());
    assert_eq!(receipt_count(&db).await, 1);
    db.close().await;
}

#[tokio::test]
async fn stale_output_base_and_stale_source_are_refused_without_writing() {
    let (db, registry) = fixture().await;
    let source = document(&registry, &db, "note", "Premise one.").await;
    let output = document(&registry, &db, "note", "Draft one.").await;
    let stale_base = request(&db, &output, &source, "stale-base", "Authored.").await;
    call(
        &registry,
        &db,
        Caller::local(),
        "update_record",
        json!({"id":output,"body_append":" Draft two."}),
    )
    .await
    .unwrap();
    let before = receipt_count(&db).await;
    let base_error = call(&registry, &db, Caller::local(), "save_account", stale_base)
        .await
        .unwrap_err()
        .to_string();
    assert!(base_error.contains("changed since"), "{base_error}");
    assert_eq!(receipt_count(&db).await, before);

    let stale_source = request(
        &db,
        &output,
        &source,
        "stale-source",
        "Authored from old premise.",
    )
    .await;
    call(
        &registry,
        &db,
        Caller::local(),
        "update_record",
        json!({"id":source,"body_append":" Premise two."}),
    )
    .await
    .unwrap();
    let source_error = call(
        &registry,
        &db,
        Caller::local(),
        "save_account",
        stale_source,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(source_error.contains("no longer current"), "{source_error}");
    assert_eq!(receipt_count(&db).await, before);
    db.close().await;
}

#[tokio::test]
async fn source_permission_is_checked_before_revision_disclosure() {
    let (db, registry) = fixture().await;
    let source = document(&registry, &db, "note", "Private premise.").await;
    let output = document(&registry, &db, "note", "Draft.").await;
    replace_explicit_policy(
        &db,
        "fixture",
        &output,
        vec![AllowEntry::account("writer", Capability::Manage)],
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        "fixture",
        &source,
        vec![AllowEntry::account("custodian", Capability::Manage)],
    )
    .await
    .unwrap();
    let output_revision = current_record_body_revision(&db, &output).await.unwrap();
    let args = json!({
        "record_id": output,
        "expected_revision_event_id": output_revision.revision_event_id,
        "body": "Attempted body.",
        "sources": [{"record_id":source,"revision_event_id":"secret-or-stale-probe",
            "role":"premise","reason":"attempt"}],
        "idempotency_key":"denied-source",
        "reason":"Permission ordering proof."
    });
    let before = receipt_count(&db).await;
    let error = call(
        &registry,
        &db,
        Caller::authenticated("writer"),
        "save_account",
        args,
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(error.matches("secret-or-stale-probe").count(), 0, "{error}");
    assert!(!error.contains(&source), "{error}");
    assert_eq!(receipt_count(&db).await, before);
    db.close().await;
}

#[tokio::test]
async fn only_governed_ordinary_notes_are_supported() {
    let (db, registry) = fixture().await;
    let source = document(&registry, &db, "note", "Premise.").await;
    let term = native_ce::meta::propose_value(&db, "glossary", "Example term", None)
        .await
        .unwrap();
    native_ce::meta::promote_value(&db, &term).await.unwrap();
    let definition = call(
        &registry,
        &db,
        Caller::local(),
        "create_record",
        json!({
            "type":"Document", "kind":"definition", "name":"Defined term",
            "body":"Defined term.", "facets":{"term":"Example term"}
        }),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let args = request(&db, &definition, &source, "not-a-note", "Replacement.").await;
    let error = call(&registry, &db, Caller::local(), "save_account", args)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("unavailable"), "{error}");
    assert_eq!(receipt_count(&db).await, 0);

    let artifact = call(
        &registry,
        &db,
        Caller::local(),
        "create_record",
        json!({
            "type":"Document", "kind":"artifact", "name":"Executable artifact",
            "body":"export const nativeArtifact = { schema: \"native.mdx.artifact.v2\", inputs: {}, module_inputs: {}, capability_requests: [] };\n\n# Rendered",
            "facets":{"runtime":"native.mdx.v2"}
        }),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let artifact_args = request(&db, &artifact, &source, "artifact-output", "Replacement.").await;
    let artifact_error = call(
        &registry,
        &db,
        Caller::local(),
        "save_account",
        artifact_args,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(artifact_error.contains("unavailable"), "{artifact_error}");
    assert_eq!(receipt_count(&db).await, 0);
    db.close().await;
}

#[tokio::test]
async fn dependency_ids_are_unique_across_repeated_saves_and_consumers() {
    let (db, registry) = fixture().await;
    let source = document(&registry, &db, "note", "Stable premise.").await;
    let first = document(&registry, &db, "note", "Draft one.").await;
    let second = document(&registry, &db, "note", "Draft two.").await;
    for (consumer, key, body) in [
        (&first, "first-r1", "First revision."),
        (&first, "first-r2", "Second revision."),
        (&second, "second-r1", "Other consumer."),
    ] {
        let args = request(&db, consumer, &source, key, body).await;
        call(&registry, &db, Caller::local(), "save_account", args)
            .await
            .unwrap();
    }
    let counts: (i64, i64) =
        sqlx::query_as("SELECT COUNT(*),COUNT(DISTINCT dependency_id) FROM dependencies")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(counts, (3, 3));
    db.close().await;
}

#[tokio::test]
async fn revised_source_save_carries_unresolved_change_instead_of_assuming_validity() {
    let (db, registry) = fixture().await;
    let source = document(&registry, &db, "note", "Premise one.").await;
    let output = document(&registry, &db, "note", "Draft.").await;
    let first = request(&db, &output, &source, "change-r1", "First account.").await;
    call(&registry, &db, Caller::local(), "save_account", first)
        .await
        .unwrap();
    call(
        &registry,
        &db,
        Caller::local(),
        "update_record",
        json!({"id":source,"body_append":" Premise two changes the evidence."}),
    )
    .await
    .unwrap();
    let second = request(
        &db,
        &output,
        &source,
        "change-r2",
        "Second account with changed evidence.",
    )
    .await;
    let saved = call(&registry, &db, Caller::local(), "save_account", second)
        .await
        .unwrap();
    assert_eq!(saved["disclosure"], json!("surface_now"));
    let outcomes: Vec<String> = sqlx::query_scalar(
        "SELECT outcome FROM dependency_assessments ORDER BY assessment_event_seq",
    )
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(outcomes, vec!["unable_to_assess"]);
    let uncertainty: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM receipt_uncertainty_lineage")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(uncertainty, 1);
    db.close().await;
}
