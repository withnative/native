use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability, Principal};
use native_ce::create_database;
use native_ce::events::LinkAddedPayload;
use native_ce::freshness::{
    assemble_context, commit_durable_output, current_record_body_revision, promote_idea,
    AffectedConclusion, CommitDurableOutputInput, ContextRequest, DependencyId, DependencyInput,
    ExpressionRole, IdempotencyKey, OccurrenceSelector, PromoteIdeaInput, ResolutionPolicy,
    UnitContent,
};
use native_ce::interchange::{export_canonical_interchange, import_canonical_interchange};
use native_ce::store::{add_link, create_record};
use serde_json::json;

/// Fixture record ids. Record ids must be canonical lowercase UUIDs, so the
/// readable name lives in the constant. Pinned literals, never generated.
/// `portable:link` below is a *link* id, not a record id, and stays as it is.
const PORTABLE_COLLECTION: &str = "ca0a0000-0000-4000-8000-000000000001";
const PORTABLE_WORK_ITEM: &str = "ca0a0000-0000-4000-8000-000000000002";
const PORTABLE_AFTER_FAILURE: &str = "ca0a0000-0000-4000-8000-000000000003";

async fn representative_source(path: &std::path::Path) -> native_ce::Db {
    let db = create_database(path.to_str().unwrap()).await.unwrap();
    create_record(
        &db,
        json!({
            "id": PORTABLE_COLLECTION,
            "type": "Collection",
            "kind": "folder",
            "name": "Portable collection"
        }),
    )
    .await
    .unwrap();
    create_record(
        &db,
        json!({
            "id": PORTABLE_WORK_ITEM,
            "type": "WorkItem",
            "kind": "task",
            "name": "Round-trip this task 📦",
            "home_id": PORTABLE_COLLECTION
        }),
    )
    .await
    .unwrap();
    add_link(
        &db,
        LinkAddedPayload {
            id: Some("portable:link".into()),
            source_id: PORTABLE_COLLECTION.into(),
            target_id: PORTABLE_WORK_ITEM.into(),
            relationship: "mentions".into(),
            note: Some("representative relationship".into()),
        },
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        "test:interchange",
        PORTABLE_WORK_ITEM,
        vec![AllowEntry::members(Capability::View)],
    )
    .await
    .unwrap();
    db
}

#[tokio::test]
async fn deterministic_round_trip_preserves_authority_and_projections() {
    let temp = tempfile::tempdir().unwrap();
    let source = representative_source(&temp.path().join("source.db")).await;

    let first = export_canonical_interchange(&source).await.unwrap();
    let second = export_canonical_interchange(&source).await.unwrap();
    assert_eq!(
        first, second,
        "unchanged exports must be byte-for-byte stable"
    );
    validate_protocol_schemas(&first);

    let imported_path = temp.path().join("imported.db");
    let imported = import_canonical_interchange(&first, &imported_path)
        .await
        .unwrap();
    let reexported = export_canonical_interchange(&imported).await.unwrap();
    assert_eq!(first, reexported);

    for (table, minimum) in [
        ("content_events", 4_i64),
        ("policy_events", 2),
        ("records", 4),
        ("record_policies", 2),
        ("policy_entries", 1),
        ("links", 1),
        ("database_identity", 1),
    ] {
        let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(imported.pool())
            .await
            .unwrap();
        assert!(
            count >= minimum,
            "expected {table} to contain representative data"
        );
    }
    let relationship: String =
        sqlx::query_scalar("SELECT relationship FROM links WHERE id='portable:link'")
            .fetch_one(imported.pool())
            .await
            .unwrap();
    assert_eq!(relationship, "mentions");
    let engine_roots: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM records WHERE id IN ('native:root', 'native:unfiled')",
    )
    .fetch_one(imported.pool())
    .await
    .unwrap();
    assert_eq!(
        engine_roots, 2,
        "fresh-database logical seeds must round-trip"
    );

    imported.close().await;
    source.close().await;
}

#[tokio::test]
async fn canonical_round_trip_preserves_units_occurrences_and_aggregate_receipts() {
    const ACCOUNT: &str = "acct:canonical-freshness";
    const ACTOR: &str = "test:canonical-freshness";
    let principal = Principal::bound(ACCOUNT, true);
    let temp = tempfile::tempdir().unwrap();
    let source = create_database(temp.path().join("freshness-source.db").to_str().unwrap())
        .await
        .unwrap();
    let idea = create_record(
        &source,
        json!({
            "type":"Document",
            "kind":"note",
            "name":"Idea",
            "body":"Audience: technical founders."
        }),
    )
    .await
    .unwrap();
    let consumer = create_record(
        &source,
        json!({
            "type":"Document",
            "kind":"note",
            "name":"Homepage",
            "body":"Initial homepage."
        }),
    )
    .await
    .unwrap();
    let promoted = promote_idea(
        &source,
        principal,
        ACTOR,
        PromoteIdeaInput {
            source_revision: current_record_body_revision(&source, &idea).await.unwrap(),
            selectors: vec![OccurrenceSelector::TextQuote {
                exact: "Audience: technical founders.".into(),
                prefix: None,
                suffix: None,
                position_hint: None,
            }],
            first_content: UnitContent::text("Primary audience: technical founders.").unwrap(),
            expression_role: ExpressionRole::Canonical,
            label: Some("Audience".into()),
            requested_unit_id: None,
            requested_occurrence_id: None,
            idempotency_key: IdempotencyKey::new("canonical-promote").unwrap(),
        },
    )
    .await
    .unwrap();
    let assembly = assemble_context(
        &source,
        principal,
        ContextRequest {
            intent: "Draft positioning".into(),
            task_scope: "homepage hero".into(),
            risk_inputs: vec![],
        },
        Some(&consumer),
        vec![promoted.unit_id.as_str().into()],
    )
    .await
    .unwrap();
    let selected = assembly.sources[0].clone();
    let expected_consumer_revision = current_record_body_revision(&source, &consumer)
        .await
        .unwrap();
    commit_durable_output(
        &source,
        principal,
        ACTOR,
        CommitDurableOutputInput {
            consumer_record_id: consumer,
            expected_consumer_revision,
            output_body: "Built for technical founders.".into(),
            assembly,
            policy: ResolutionPolicy::agent_speed_default(),
            provenance: vec![],
            dependencies: vec![DependencyInput {
                dependency_id: DependencyId::new("canonical-dependency").unwrap(),
                source_revision: selected,
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
            idempotency_key: IdempotencyKey::new("canonical-receipt").unwrap(),
        },
    )
    .await
    .unwrap();

    let canonical = export_canonical_interchange(&source).await.unwrap();
    let imported =
        import_canonical_interchange(&canonical, &temp.path().join("freshness-imported.db"))
            .await
            .unwrap();
    for table in [
        "semantic_units",
        "unit_revisions",
        "occurrences",
        "freshness_command_results",
        "freshness_runtime_command_results",
        "receipts",
        "dependencies",
    ] {
        let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(imported.pool())
            .await
            .unwrap();
        assert!(count > 0, "expected {table} to survive canonical import");
    }
    assert!(
        native_ce::conformance::rebuild_and_diff(&imported)
            .await
            .unwrap()
            .equal
    );
    assert_eq!(
        canonical,
        export_canonical_interchange(&imported).await.unwrap()
    );
    imported.close().await;
    source.close().await;
}

#[tokio::test]
async fn strict_policy_survives_canonical_import_and_subsequent_reopen() {
    let temp = tempfile::tempdir().unwrap();
    let source = representative_source(&temp.path().join("strict-source.db")).await;
    native_ce::storage_profile::update_portability_policy(
        &source,
        native_ce::storage_profile::PortabilityPolicyUpdate {
            if_policy_revision: 0,
            enforcement: native_ce::storage_profile::PortabilityEnforcement::Strict,
            target_profiles: vec![native_ce::storage_profile::StorageTarget {
                id: "postgres-server".into(),
                revision: 2,
                mode: "network".into(),
            }],
            allow_conversions: vec![],
        },
    )
    .await
    .unwrap();
    let bytes = export_canonical_interchange(&source).await.unwrap();

    let imported_path = temp.path().join("strict-imported.db");
    let imported = import_canonical_interchange(&bytes, &imported_path)
        .await
        .unwrap();
    assert_eq!(
        native_ce::storage_profile::portability_policy_report(&imported)
            .await
            .unwrap()["enforcement"],
        "strict"
    );
    imported.close().await;

    let reopened = native_ce::open_existing_database_at(&imported_path)
        .await
        .unwrap();
    let report = native_ce::storage_profile::portability_policy_report(&reopened)
        .await
        .unwrap();
    assert_eq!(report["enforcement"], "strict");
    assert_eq!(report["policy_revision"], 1);
    reopened.close().await;
    source.close().await;
}

fn validate_protocol_schemas(export: &[u8]) {
    let manifest_schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../protocol/storage-portability/v1/interchange/manifest.schema.json"
    ))
    .unwrap();
    let section_schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../protocol/storage-portability/v1/interchange/section.schema.json"
    ))
    .unwrap();
    let bundle_schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../protocol/storage-portability/v1/interchange/bundle.schema.json"
    ))
    .unwrap();
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../protocol/storage-portability/v1/interchange/fixtures/canonical-cell-types.section.json"
    ))
    .unwrap();

    let manifest_validator = jsonschema::validator_for(&manifest_schema).unwrap();
    let section_validator = jsonschema::validator_for(&section_schema).unwrap();
    let export: serde_json::Value = serde_json::from_slice(export).unwrap();
    assert!(manifest_validator.is_valid(&export["manifest"]));
    for section in export["sections"].as_array().unwrap() {
        assert!(section_validator.is_valid(section));
    }
    assert!(section_validator.is_valid(&fixture));

    let registry = jsonschema::Registry::new()
        .add(
            "https://withnative.com/protocol/storage-portability/v1/interchange/manifest.schema.json",
            &manifest_schema,
        )
        .unwrap()
        .add(
            "https://withnative.com/protocol/storage-portability/v1/interchange/section.schema.json",
            &section_schema,
        )
        .unwrap()
        .prepare()
        .unwrap();
    let bundle_validator = jsonschema::options()
        .with_registry(&registry)
        .build(&bundle_schema)
        .unwrap();
    assert!(bundle_validator.is_valid(&export));
}

#[tokio::test]
async fn corruption_and_partial_input_are_rejected_before_destination_mutation() {
    let temp = tempfile::tempdir().unwrap();
    let source = representative_source(&temp.path().join("source.db")).await;
    let bytes = export_canonical_interchange(&source).await.unwrap();

    let mut corrupt: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    corrupt["sections"][0]["rows"][0][0] = json!({"type": "text", "value": "corrupt"});
    let corrupt_destination = temp.path().join("corrupt.db");
    let error =
        import_canonical_interchange(&serde_json::to_vec(&corrupt).unwrap(), &corrupt_destination)
            .await
            .expect_err("corrupt interchange must fail");
    assert!(error.to_string().contains("integrity"));
    assert!(!corrupt_destination.exists());

    let mut partial: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    partial["sections"].as_array_mut().unwrap().pop();
    let partial_destination = temp.path().join("partial.db");
    let error =
        import_canonical_interchange(&serde_json::to_vec(&partial).unwrap(), &partial_destination)
            .await
            .expect_err("partial interchange must fail");
    assert!(error.to_string().contains("inventory"));
    assert!(!partial_destination.exists());

    let mut unsupported: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    unsupported["manifest"]["revision"] = json!(3);
    let unsupported_destination = temp.path().join("unsupported.db");
    let error = import_canonical_interchange(
        &serde_json::to_vec(&unsupported).unwrap(),
        &unsupported_destination,
    )
    .await
    .expect_err("unsupported revision must fail");
    assert!(error
        .to_string()
        .contains("unsupported interchange revision"));
    assert!(!unsupported_destination.exists());

    let occupied_destination = temp.path().join("occupied.db");
    std::fs::write(&occupied_destination, b"sentinel").unwrap();
    let error = import_canonical_interchange(&bytes, &occupied_destination)
        .await
        .expect_err("an existing destination must not be replaced");
    assert!(error.to_string().contains("already exists"));
    assert_eq!(std::fs::read(&occupied_destination).unwrap(), b"sentinel");

    // Failed imports do not consume, close, or otherwise damage the source.
    let records: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records")
        .fetch_one(source.pool())
        .await
        .unwrap();
    assert!(records >= 4);
    create_record(
        &source,
        json!({
            "id":PORTABLE_AFTER_FAILURE,
            "type":"Document",
            "kind":"note",
            "name":"still usable"
        }),
    )
    .await
    .unwrap();
    source.close().await;
}
