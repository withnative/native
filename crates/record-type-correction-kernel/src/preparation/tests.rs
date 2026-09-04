use std::collections::BTreeMap;

use serde_json::{json, Value};

use super::*;
use crate::Eligibility;

fn identity(record_type: &str, kind: &str) -> Identity {
    Identity {
        record_type: record_type.into(),
        kind: kind.into(),
    }
}

fn counts(pairs: &[(&str, i64)]) -> BTreeMap<String, i64> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_string(), *value))
        .collect()
}

fn bounded(pairs: &[(&str, &[&str])]) -> BTreeMap<String, Vec<String>> {
    pairs
        .iter()
        .map(|(key, ids)| {
            (
                (*key).to_string(),
                ids.iter().map(|id| (*id).to_string()).collect(),
            )
        })
        .collect()
}

fn fences(pairs: &[(&str, Value)]) -> BTreeMap<String, Value> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_string(), value.clone()))
        .collect()
}

/// One coherent snapshot every backend could legitimately observe.
fn facts() -> CorrectionFacts {
    CorrectionFacts {
        record_id: "rec_1".into(),
        reason: "stored kind was quarantined on the wrong spine".into(),
        name: "Quarterly decision".into(),
        body_digest: "b".repeat(64),
        updated_at: "2026-09-02T10:00:00.000Z".into(),
        previous_seq: 7,
        schema_state_revision: "schema-state-v1:meta:3:content:9".into(),
        current: identity("Document", "decision"),
        target: identity("Resolution", "decision"),
        target_active: true,
        unique_wrong_type_match: true,
        same_run_provenance: true,
        preserved_state_counts: counts(&[
            ("bindings", 0),
            ("children", 0),
            ("incoming_links", 1),
            ("relationships", 0),
        ]),
        bounded_identifiers: bounded(&[
            ("bindings", &[]),
            ("children", &[]),
            ("incoming_links", &["rec_2"]),
            ("relationships", &[]),
        ]),
        dependency_fences: fences(&[("binding_audit_seq", json!(4))]),
        blockers: vec![],
    }
}

fn plan(facts: CorrectionFacts) -> CorrectionPlan {
    CorrectionPlan::new(facts).expect("plan")
}

#[test]
fn autonomous_facts_produce_the_full_prepared_correction() {
    let prepared = plan(facts()).prepared().expect("prepared");

    assert_eq!(
        prepared.effect_summary,
        "Autonomous same-run correction eligible: correct Quarterly decision (rec_1) from Document/decision to Resolution/decision; record id and body digest remain unchanged"
    );
    assert_eq!(prepared.target, "Quarterly decision (rec_1)");
    assert_eq!(prepared.target_id, "rec_1");
    assert_eq!(prepared.effect["eligibility"], json!("autonomous"));
    assert_eq!(prepared.effect["confirmation_required"], json!(false));
    assert_eq!(prepared.effect["does_not_reembed_body"], json!(true));
    assert_eq!(
        prepared.effect["new_bearer_guidance"],
        json!(NEW_BEARER_GUIDANCE)
    );
    assert_eq!(
        prepared.effect["identity_and_body"],
        json!({"record_id_unchanged": true, "body_digest_unchanged": "b".repeat(64)})
    );
    assert_eq!(
        prepared.effect["expected_changes"],
        json!({
            "projection": ["type", "kind", "updated_at", "last_activity_at", "record_version"],
            "derived": ["governed_identity", "capabilities", "dispatch", "current_query_membership"],
        })
    );
    // `incompatibilities` mirrors `reasons` exactly, as every adapter did.
    assert_eq!(
        prepared.effect["incompatibilities"],
        prepared.effect["reasons"]
    );
    assert_eq!(
        prepared.canonical_source_arguments["mode"],
        json!("autonomous")
    );
    assert_eq!(
        prepared.state_revision,
        format!(
            "content-seq:7;schema:schema-state-v1:meta:3:content:9;dependencies:{}",
            prepared.canonical_source_arguments["if_dependency_digest"]
                .as_str()
                .unwrap()
        )
    );
    assert_eq!(
        prepared.target_state_digest,
        correction_digest(&prepared.operation_evidence).unwrap()
    );
}

#[test]
fn confirmation_wording_and_mode_follow_eligibility() {
    let mut confirmed = facts();
    confirmed.same_run_provenance = false;
    let prepared = plan(confirmed).prepared().expect("prepared");

    assert!(prepared
        .effect_summary
        .starts_with("Human confirmation required before execution: correct "));
    assert_eq!(prepared.effect["confirmation_required"], json!(true));
    assert_eq!(
        prepared.canonical_source_arguments["confirmation_required"],
        json!(true)
    );
    assert_eq!(
        prepared.canonical_source_arguments["mode"],
        json!("confirmed")
    );
}

#[test]
fn blockers_own_exactly_one_code_and_detail_each() {
    let cases = [
        (
            Blocker::EngineFilingRecord,
            "engine_filing_record",
            "engine-provisioned filing records have immutable identity",
        ),
        (
            Blocker::MessageTargetShape,
            "specialised_target_shape",
            "Message identity must be created atomically with its audience state",
        ),
        (
            Blocker::GovernedAnnotationTargetShape,
            "specialised_target_shape",
            "governed or targeted Annotation identity must be created atomically",
        ),
        (
            Blocker::SpecialisedTargetShape,
            "specialised_target_shape",
            "the target identity must be created atomically with its specialised state",
        ),
        (
            Blocker::ProgramRuntimeTargetShape,
            "specialised_target_shape",
            "Program correction requires its governed kind and exact interpreter runtime",
        ),
        (
            Blocker::SemanticUnit,
            "semantic_unit",
            "semantic Unit identity cannot be corrected",
        ),
        (
            Blocker::TargetedAnnotation,
            "targeted_annotation",
            "a targeted Annotation cannot be corrected",
        ),
        (
            Blocker::GovernedAttribution,
            "governed_attribution",
            "governed attribution identity cannot be corrected",
        ),
        (
            Blocker::MessageDeliveryState,
            "message_delivery_state",
            "a Message with non-local delivery state cannot be corrected",
        ),
        (
            Blocker::SpecialisedAggregate,
            "specialised_aggregate",
            "published artifact, module, recipe, or derivation state fixes this bearer's identity",
        ),
        (
            Blocker::IncompatibleIdentityBinding,
            "incompatible_identity_binding",
            "a preserved external identity binding rejects the target type/kind",
        ),
        (
            Blocker::RequiredFacetMissing {
                facet: "owner_id".into(),
            },
            "required_facet_missing",
            "preserved state is missing target-required facet 'owner_id'",
        ),
        (
            Blocker::IncompatibleFacetValue {
                detail: "engine detail".into(),
            },
            "incompatible_facet_value",
            "engine detail",
        ),
        (
            Blocker::ProspectiveProgramShape {
                detail: "validator detail".into(),
            },
            "specialised_target_shape",
            "validator detail",
        ),
    ];

    for (blocker, code, detail) in cases {
        assert_eq!(blocker.code(), code);
        assert_eq!(blocker.detail(), detail);
        let reason = blocker.reason();
        assert_eq!(reason.code, code);
        assert_eq!(reason.detail, detail);
    }
}

#[test]
fn blockers_dominate_and_reach_the_prepared_effect_sorted() {
    let mut blocked = facts();
    blocked.blockers = vec![Blocker::SemanticUnit, Blocker::EngineFilingRecord];
    let prepared = plan(blocked).prepared().expect("prepared");

    assert_eq!(prepared.effect["eligibility"], json!("ineligible"));
    assert_eq!(
        prepared.effect["reasons"],
        json!([
            {
                "code": "engine_filing_record",
                "detail": "engine-provisioned filing records have immutable identity"
            },
            {"code": "semantic_unit", "detail": "semantic Unit identity cannot be corrected"}
        ])
    );
    assert_eq!(
        prepared.canonical_source_arguments["mode"],
        json!("ineligible")
    );
}

#[test]
fn shared_use_is_forced_by_relationships_bindings_truncation_or_provenance() {
    let base = facts();
    assert_eq!(
        plan(base.clone()).classification().eligibility,
        Eligibility::Autonomous
    );

    for key in ["relationships", "bindings"] {
        let mut present = base.clone();
        present.preserved_state_counts.insert(key.into(), 1);
        present
            .bounded_identifiers
            .insert(key.into(), vec!["x".into()]);
        assert_eq!(
            plan(present).classification().eligibility,
            Eligibility::ConfirmationRequired,
            "{key}"
        );
    }

    // A truncated preview must never read as autonomous proof: the count
    // exceeds the identifiers actually inspected.
    let mut truncated = base.clone();
    truncated
        .preserved_state_counts
        .insert("children".into(), 40);
    let truncated = plan(truncated);
    assert_eq!(
        truncated.classification().eligibility,
        Eligibility::ConfirmationRequired
    );
    assert_eq!(
        truncated.effect()["bounded_identifiers_truncated"]["children"],
        json!(true)
    );

    let mut replicated = base;
    replicated.same_run_provenance = false;
    assert_eq!(
        plan(replicated).classification().eligibility,
        Eligibility::ConfirmationRequired
    );
}

#[test]
fn truncation_flags_cover_every_counted_category() {
    let prepared = plan(facts()).prepared().expect("prepared");
    assert_eq!(
        prepared.effect["bounded_identifiers_truncated"],
        json!({
            "bindings": false,
            "children": false,
            "incoming_links": false,
            "relationships": false,
        })
    );
}

// ---------------------------------------------------------------------------
// Cross-backend equivalence fixtures
// ---------------------------------------------------------------------------

/// Facts as the SQLite/MCP adapter assembles them.
fn sqlite_facts() -> CorrectionFacts {
    let mut facts = facts();
    facts.dependency_fences = fences(&[
        ("binding_audit_seq", json!(4)),
        ("relationship_event_seq", json!(11)),
    ]);
    facts
}

/// Facts as the Turso-local adapter assembles them: identical observations,
/// different fence key names for the same append-only heads.
fn turso_facts() -> CorrectionFacts {
    let mut facts = facts();
    facts.dependency_fences = fences(&[
        ("binding_audit_head", json!(4)),
        ("relationship_event_head", json!(11)),
    ]);
    facts
}

/// Facts as the Postgres adapter assembles them: no portable
/// `content_event_sources`, so provenance fails closed, and per-record heads
/// stand in for a relationship-event fence it cannot observe.
fn postgres_facts() -> CorrectionFacts {
    let mut facts = facts();
    facts.same_run_provenance = false;
    facts.dependency_fences = fences(&[
        ("binding_audit_head", json!(4)),
        ("dependency_heads", json!({"rec_1": 7, "rec_2": 2})),
    ]);
    facts
}

#[test]
fn equivalent_facts_produce_byte_equivalent_evidence_and_digests_on_every_backend() {
    // The backend a fact set came from is not an input. Two adapters that
    // observe the same snapshot must serialize the same canonical bytes.
    let one = plan(sqlite_facts()).prepared().expect("prepared");
    let two = plan(sqlite_facts()).prepared().expect("prepared");

    assert_eq!(
        serde_jcs::to_vec(&one.effect).unwrap(),
        serde_jcs::to_vec(&two.effect).unwrap()
    );
    assert_eq!(
        serde_jcs::to_vec(&one.operation_evidence).unwrap(),
        serde_jcs::to_vec(&two.operation_evidence).unwrap()
    );
    assert_eq!(
        serde_jcs::to_vec(&one.canonical_source_arguments).unwrap(),
        serde_jcs::to_vec(&two.canonical_source_arguments).unwrap()
    );
    assert_eq!(one.target_state_digest, two.target_state_digest);
    assert_eq!(one.state_revision, two.state_revision);
    assert_eq!(one.effect_summary, two.effect_summary);
}

#[test]
fn fence_material_is_the_only_source_of_cross_backend_digest_divergence() {
    let sqlite = plan(sqlite_facts());
    let turso = plan(turso_facts());
    let postgres = plan(postgres_facts());

    // Different fence names for the same heads are load-bearing backend
    // divergence, deliberately preserved: the digests differ.
    assert_ne!(sqlite.dependency_digest(), turso.dependency_digest());
    assert_ne!(sqlite.dependency_digest(), postgres.dependency_digest());

    // Everything outside the fence keys is shared, so stripping the fences
    // leaves byte-identical evidence.
    let strip = |plan: &CorrectionPlan| {
        let mut evidence = plan.dependency_evidence().clone();
        let object = evidence.as_object_mut().unwrap();
        object.retain(|key, _| {
            matches!(
                key.as_str(),
                "previous_seq" | "updated_at" | "schema_state_revision" | "counts" | "bounded_ids"
            )
        });
        serde_jcs::to_vec(&evidence).unwrap()
    };
    assert_eq!(strip(&sqlite), strip(&turso));
    assert_eq!(strip(&sqlite), strip(&postgres));

    // Postgres fails provenance closed, which is a facts-level difference and
    // must therefore change eligibility rather than be papered over.
    assert_eq!(sqlite.classification().eligibility, Eligibility::Autonomous);
    assert_eq!(
        postgres.classification().eligibility,
        Eligibility::ConfirmationRequired
    );
}

#[test]
fn identical_fence_names_make_two_backends_digest_identically() {
    // Give the SQLite fact set Turso's fence names and the two backends agree
    // byte for byte, proving the transform itself is backend-neutral.
    let mut aligned = sqlite_facts();
    aligned.dependency_fences = turso_facts().dependency_fences;

    assert_eq!(
        plan(aligned).dependency_digest(),
        plan(turso_facts()).dependency_digest()
    );
}

#[test]
fn dependency_evidence_carries_the_base_shape_plus_adapter_fences() {
    let plan = plan(sqlite_facts());
    assert_eq!(
        plan.dependency_evidence(),
        &json!({
            "previous_seq": 7,
            "updated_at": "2026-09-02T10:00:00.000Z",
            "schema_state_revision": "schema-state-v1:meta:3:content:9",
            "counts": {"bindings": 0, "children": 0, "incoming_links": 1, "relationships": 0},
            "bounded_ids": {
                "bindings": [],
                "children": [],
                "incoming_links": ["rec_2"],
                "relationships": [],
            },
            "binding_audit_seq": 4,
            "relationship_event_seq": 11,
        })
    );
}

#[test]
fn correction_digest_is_canonical_json_hashed_with_sha256() {
    // Key order is not an input: RFC 8785 canonicalization sorts before
    // hashing, which is what lets adapters build evidence in any order.
    assert_eq!(
        correction_digest(&json!({"a": 1, "b": [2, 3]})).unwrap(),
        correction_digest(&json!({"b": [2, 3], "a": 1})).unwrap()
    );
    assert_eq!(
        correction_digest(&json!({"a": 1, "b": [2, 3]})).unwrap(),
        // Independently reproducible: sha256 of the exact bytes
        // `{"a":1,"b":[2,3]}`.
        "efbd0040190fb0871831e606c581f8a66db79d8e2bb836745a70051306956070"
    );
}
