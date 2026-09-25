//! Qualification: existing Receipt runtime supports ordinary Document saves
//! with exact Native record-body sources, without a second content authority
//! or a mandatory public Unit grammar.
//!
//! All sources and consumers below are ordinary `Document` records. No
//! `promote_idea` / `revise_unit` / Unit APIs are used. The tests reuse only
//! the existing runtime APIs: `assemble_context`, `commit_durable_output`,
//! `current_record_body_revision`, `explain_freshness`, and
//! `list_impact_candidates`, plus the ordinary `create_record` /
//! `update_record` write path.

use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability, Principal};
use native_ce::freshness::*;
use native_ce::store::{create_record, update_record};
use serde_json::json;

const ACTOR: &str = "test:authoring-receipt";
const ACCOUNT: &str = "acct:authoring-receipt";
const OTHER: &str = "acct:authoring-reader";

fn principal() -> Principal<'static> {
    Principal::bound(ACCOUNT, true)
}

fn other() -> Principal<'static> {
    Principal::bound(OTHER, true)
}

async fn document(db: &native_ce::Db, name: &str, body: &str) -> String {
    create_record(
        db,
        json!({"type":"Document","kind":"note","name":name,"body":body}),
    )
    .await
    .unwrap()
}

fn request(scope: &str) -> ContextRequest {
    ContextRequest {
        intent: "Draft the authoring note".into(),
        task_scope: scope.into(),
        risk_inputs: vec!["source accuracy".into()],
    }
}

fn conclusion() -> AffectedConclusion {
    AffectedConclusion {
        key: "note.basis".into(),
        description: "Which source basis the note relies on".into(),
    }
}

fn dependency(id: &str, source: RevisionRef) -> DependencyInput {
    DependencyInput {
        dependency_id: DependencyId::new(id).unwrap(),
        source_revision: source,
        semantic_role: "source premise".into(),
        affected_conclusion: conclusion(),
        rationale: "The note restates the source premise".into(),
        reconsideration_trigger: "The source premise changes".into(),
        confidence: Some(0.9),
    }
}

async fn event_count(db: &native_ce::Db) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap()
}

/// Assemble against ordinary Document sources and package a durable save.
async fn package(
    db: &native_ce::Db,
    consumer: &str,
    source_ids: Vec<String>,
    output_body: &str,
    key: &str,
) -> CommitDurableOutputInput {
    let assembly = assemble_context(
        db,
        principal(),
        request("authoring note"),
        Some(consumer),
        source_ids,
    )
    .await
    .unwrap();
    assert!(
        !assembly.sources.is_empty(),
        "ordinary Document sources must bind"
    );
    for source in &assembly.sources {
        assert_eq!(source.subject_kind, RevisionSubjectKind::Artefact);
        assert_eq!(source.source_slot, RevisionSourceSlot::RecordBody);
    }
    let provenance = assembly
        .sources
        .iter()
        .map(|source| ProvenanceUse {
            source_revision: source.clone(),
            reason: "Used to draft the note".into(),
        })
        .collect::<Vec<_>>();
    let dependencies = assembly
        .sources
        .iter()
        .enumerate()
        .map(|(index, source)| dependency(&format!("dep-{key}-{index}"), source.clone()))
        .collect::<Vec<_>>();
    CommitDurableOutputInput {
        consumer_record_id: consumer.into(),
        expected_consumer_revision: current_record_body_revision(db, consumer).await.unwrap(),
        output_body: output_body.into(),
        assembly,
        policy: ResolutionPolicy::agent_speed_default(),
        provenance,
        dependencies,
        assessments: vec![],
        reconciliations: vec![],
        unresolved_uncertainty: vec![],
        idempotency_key: IdempotencyKey::new(key).unwrap(),
    }
}

#[tokio::test]
async fn ordinary_document_sources_bind_exact_body_revisions() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let source_a = document(&db, "Source A", "Premise A holds.").await;
    let source_b = document(&db, "Source B", "Premise B holds.").await;
    let consumer = document(&db, "Consumer", "Initial.").await;

    let assembly = assemble_context(
        &db,
        principal(),
        request("authoring note"),
        Some(&consumer),
        vec![source_a.clone(), source_b.clone()],
    )
    .await
    .unwrap();
    assert_eq!(assembly.sources.len(), 2);
    for source in &assembly.sources {
        assert_eq!(source.subject_kind, RevisionSubjectKind::Artefact);
        assert_eq!(source.source_slot, RevisionSourceSlot::RecordBody);
    }
    // Exactness: sealed sources equal the live body heads.
    for record_id in [&source_a, &source_b] {
        let live = current_record_body_revision(&db, record_id).await.unwrap();
        assert!(assembly.sources.contains(&live));
    }
    assert!(assembly.comparisons.is_empty());
    assert!(!assembly.withheld_context);
}

#[tokio::test]
async fn receipt_save_is_atomic_and_declares_ordinary_basis() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let source = document(&db, "Basis source", "The premise stands.").await;
    let consumer = document(&db, "Authored note", "Initial.").await;
    let input = package(
        &db,
        &consumer,
        vec![source.clone()],
        "Note restating the premise.",
        "authoring-atomic",
    )
    .await;
    let sealed_source = input.assembly.sources[0].clone();
    let before = event_count(&db).await;

    let committed = commit_durable_output(&db, principal(), ACTOR, input)
        .await
        .unwrap();
    // One aggregate event for the whole save + declared basis.
    assert_eq!(event_count(&db).await, before + 1);
    assert_eq!(committed.dependency_ids.len(), 1);
    assert_eq!(committed.execution, ExecutionDisposition::Continued);
    assert_eq!(committed.disclosure, DisclosureDecision::Silent);

    // Output revision is an ordinary Document body revision on the consumer.
    assert_eq!(committed.output_revision.subject_id, consumer);
    assert_eq!(
        committed.output_revision.subject_kind,
        RevisionSubjectKind::Artefact
    );
    assert_eq!(
        committed.output_revision.source_slot,
        RevisionSourceSlot::RecordBody
    );
    assert_eq!(
        current_record_body_revision(&db, &consumer).await.unwrap(),
        committed.output_revision
    );
    let payload: serde_json::Value = serde_json::from_str(
        &sqlx::query_scalar::<_, String>("SELECT payload FROM content_events WHERE id=?")
            .bind(&committed.output_revision.revision_event_id)
            .fetch_one(db.pool())
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(payload["body"], json!("Note restating the premise."));

    // Declared basis is the exact sealed source revision.
    let explanation = explain_freshness(&db, principal(), committed.receipt_id.clone())
        .await
        .unwrap();
    assert_eq!(explanation.visible_dependencies.len(), 1);
    assert_eq!(
        explanation.visible_dependencies[0].source_revision,
        sealed_source
    );
    assert_eq!(explanation.visible_provenance.len(), 1);
    assert_eq!(
        explanation.provenance_completeness,
        ProvenanceCompleteness::Complete
    );
}

#[tokio::test]
async fn stale_consumer_base_is_rejected_without_writing() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let source = document(&db, "Stale-base source", "Premise.").await;
    let consumer = document(&db, "Stale-base note", "Initial.").await;
    let first = package(
        &db,
        &consumer,
        vec![source.clone()],
        "First save.",
        "stale-base-r1",
    )
    .await;
    let stale_expected = first.expected_consumer_revision.clone();
    commit_durable_output(&db, principal(), ACTOR, first)
        .await
        .unwrap();

    // Fresh assembly but a stale expected base.
    let mut second = package(
        &db,
        &consumer,
        vec![source.clone()],
        "Second save on stale base.",
        "stale-base-r2",
    )
    .await;
    second.expected_consumer_revision = stale_expected;
    let before = event_count(&db).await;
    let error = commit_durable_output(&db, principal(), ACTOR, second)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("output consumer changed since its expected revision"),
        "{error}"
    );
    assert_eq!(event_count(&db).await, before);
}

#[tokio::test]
async fn idempotent_retry_returns_same_receipt_without_duplicate_event() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let source = document(&db, "Retry source", "Premise.").await;
    let consumer = document(&db, "Retry note", "Initial.").await;
    let input = package(
        &db,
        &consumer,
        vec![source.clone()],
        "Retry save.",
        "authoring-retry",
    )
    .await;
    let before = event_count(&db).await;
    let first = commit_durable_output(&db, principal(), ACTOR, input.clone())
        .await
        .unwrap();
    assert_eq!(event_count(&db).await, before + 1);
    let second = commit_durable_output(&db, principal(), ACTOR, input)
        .await
        .unwrap();
    assert_eq!(second, first);
    assert_eq!(event_count(&db).await, before + 1);

    // Same key with a different body is a conflict, not a retry.
    let mut conflict = package(
        &db,
        &consumer,
        vec![source.clone()],
        "Different body under the same key.",
        "authoring-retry-conflict-probe",
    )
    .await;
    conflict.idempotency_key = IdempotencyKey::new("authoring-retry").unwrap();
    // The conflict path reuses the occupied key; the runtime reports reuse.
    let error = commit_durable_output(&db, principal(), ACTOR, conflict)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("different runtime command"), "{error}");
    assert_eq!(event_count(&db).await, before + 1);
}

#[tokio::test]
async fn ordinary_edit_makes_old_receipt_basis_historical() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let source = document(&db, "Historical source", "Premise.").await;
    let consumer = document(&db, "Historical note", "Initial.").await;
    let committed = commit_durable_output(
        &db,
        principal(),
        ACTOR,
        package(
            &db,
            &consumer,
            vec![source.clone()],
            "Receipt save.",
            "historical-r1",
        )
        .await,
    )
    .await
    .unwrap();

    // Ordinary write-path edit advances the consumer head past the Receipt.
    update_record(&db, &consumer, json!({"body":"Ordinary follow-up edit."}))
        .await
        .unwrap();
    let live = current_record_body_revision(&db, &consumer).await.unwrap();
    assert_ne!(live, committed.output_revision);

    // The old Receipt basis is historical: fresh assembly on the edited head
    // carries no live comparisons for the old consumer revision, and impact
    // lookup on the edited consumer is empty.
    let fresh = assemble_context(
        &db,
        principal(),
        request("authoring note"),
        Some(&consumer),
        vec![source.clone()],
    )
    .await
    .unwrap();
    assert!(fresh.comparisons.is_empty());
    let impacts = list_impact_candidates(&db, principal(), &consumer)
        .await
        .unwrap();
    assert!(impacts.candidates.is_empty());
    assert!(!impacts.withheld_context);
}

#[tokio::test]
async fn explanation_is_permission_aware_for_ordinary_sources() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let source = document(&db, "Private premise", "Private premise.").await;
    let consumer = document(&db, "Shared note", "Initial.").await;
    let committed = commit_durable_output(
        &db,
        principal(),
        ACTOR,
        package(
            &db,
            &consumer,
            vec![source.clone()],
            "Note using the private premise.",
            "permission-r1",
        )
        .await,
    )
    .await
    .unwrap();

    // Full explanation is complete for the author.
    let full = explain_freshness(&db, principal(), committed.receipt_id.clone())
        .await
        .unwrap();
    assert_eq!(full.visible_dependencies.len(), 1);
    assert_eq!(
        full.provenance_completeness,
        ProvenanceCompleteness::Complete
    );

    // Hide the ordinary source from OTHER while keeping the consumer visible.
    replace_explicit_policy(
        &db,
        ACTOR,
        &source,
        vec![AllowEntry::account(ACCOUNT, Capability::Manage)],
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        ACTOR,
        &consumer,
        vec![
            AllowEntry::account(ACCOUNT, Capability::Manage),
            AllowEntry::account(OTHER, Capability::View),
        ],
    )
    .await
    .unwrap();

    let redacted = explain_freshness(&db, other(), committed.receipt_id)
        .await
        .unwrap();
    assert!(redacted.visible_dependencies.is_empty());
    assert!(redacted.visible_provenance.is_empty());
    assert_eq!(
        redacted.provenance_completeness,
        ProvenanceCompleteness::Withheld
    );
    let wire = serde_json::to_string(&redacted).unwrap();
    assert!(!wire.contains(&source), "withheld source id must not leak");
}
