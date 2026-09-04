use native_ce::freshness::{
    HistoryHighWater, IdempotencyKey, OccurrenceId, RevisionRef, RevisionSourceSlot,
    RevisionSubjectKind, UnitContent, UnitContentMediaType, UnitEncodingVersion, UnitId,
    SEMANTIC_CONTRACT_VERSION,
};
use serde_json::json;

#[test]
fn exact_references_reject_ambient_currentness_and_malformed_coordinates() {
    let exact = RevisionRef {
        subject_kind: RevisionSubjectKind::Unit,
        subject_id: "unit-a".into(),
        revision_event_id: "event-a".into(),
        revision_seq: 4,
        source_slot: RevisionSourceSlot::UnitContent,
        sha256: "a".repeat(64),
    };
    exact.validate().unwrap();

    let mut invalid = exact.clone();
    invalid.revision_seq = 0;
    assert!(invalid.validate().is_err());
    invalid = exact.clone();
    invalid.source_slot = RevisionSourceSlot::RecordBody;
    assert!(invalid.validate().is_err());
    invalid = exact;
    invalid.sha256 = "LATEST".into();
    assert!(invalid.validate().is_err());
}

#[test]
fn unit_content_digest_covers_representation_metadata_and_bytes() {
    let text = UnitContent::text("Primary audience: technical founders.").unwrap();
    let markdown = UnitContent::new(
        "Primary audience: technical founders.",
        UnitContentMediaType::new("text/markdown").unwrap(),
        UnitEncodingVersion::v1(),
    )
    .unwrap();
    assert_ne!(text.sha256(), markdown.sha256());
    assert_eq!(text.sha256().len(), 64);
    assert_eq!(text, UnitContent::text(text.content.clone()).unwrap());
}

#[test]
fn opaque_ids_and_high_water_fail_closed() {
    assert!(UnitId::new("  ").is_err());
    assert!(IdempotencyKey::new("").is_err());
    assert!(HistoryHighWater {
        content_seq: 3,
        authorization_revision_observed: 2,
        semantic_contract_version: SEMANTIC_CONTRACT_VERSION.into(),
    }
    .validate()
    .is_ok());
    assert!(HistoryHighWater {
        content_seq: -1,
        authorization_revision_observed: 2,
        semantic_contract_version: SEMANTIC_CONTRACT_VERSION.into(),
    }
    .validate()
    .is_err());
}

#[test]
fn constrained_values_cannot_be_deserialized_around_their_constructors() {
    assert!(serde_json::from_value::<UnitId>(json!(" ")).is_err());
    assert!(serde_json::from_value::<OccurrenceId>(json!("x".repeat(201))).is_err());
    assert!(serde_json::from_value::<IdempotencyKey>(json!("bad\nkey")).is_err());
    assert!(serde_json::from_value::<UnitContentMediaType>(json!("plain-text")).is_err());
    assert!(serde_json::from_value::<UnitEncodingVersion>(json!(0)).is_err());
    assert!(serde_json::from_value::<UnitContent>(json!({
        "content":"   ",
        "content_media_type":"text/plain",
        "encoding_version":1
    }))
    .is_err());
    assert!(serde_json::from_value::<UnitContent>(json!({
        "content":"valid",
        "content_media_type":"invalid",
        "encoding_version":1
    }))
    .is_err());
}
