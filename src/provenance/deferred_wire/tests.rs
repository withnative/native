use super::*;
use ed25519_dalek::{Signature, VerifyingKey};
const KEY: &[u8] = include_bytes!("fixtures/key.json");
fn v2(bytes: &[u8]) -> EntryV2 {
    serde_json::from_slice(bytes).unwrap()
}
#[test]
fn frozen_messages_and_signatures_preserve_preextraction_bytes() {
    let key: WindowPublicKey = serde_json::from_slice(KEY).unwrap();
    assert_eq!(digest(&key.public_key).unwrap(), key.key_id);
    assert_ne!(hex::encode(Sha256::digest(key.public_key)), key.key_id);
    let public = VerifyingKey::from_bytes(&key.public_key).unwrap();
    for (bytes, expected) in [
        (
            include_bytes!("fixtures/intent-entry.json").as_slice(),
            include_bytes!("fixtures/intent-message.bin").as_slice(),
        ),
        (
            include_bytes!("fixtures/null-intent-entry.json").as_slice(),
            include_bytes!("fixtures/null-intent-message.bin").as_slice(),
        ),
    ] {
        let entry = v2(bytes);
        assert_eq!(serde_jcs::to_vec(&entry).unwrap(), bytes);
        let message = v2_message(
            &key,
            &entry.call,
            entry.received_seq,
            entry.received_at,
            &entry.attestation,
        )
        .unwrap();
        assert_eq!(message, expected);
        let signature =
            Signature::from_slice(&hex::decode(&entry.attestation.signature).unwrap()).unwrap();
        public.verify_strict(&message, &signature).unwrap();
    }
    let value: Value = serde_json::from_slice(include_bytes!("fixtures/v1-entry.json")).unwrap();
    let call: NewEntry = serde_json::from_value(value["call"].clone()).unwrap();
    let att: Attestation = serde_json::from_value(value["attestation"].clone()).unwrap();
    validate_v1_digests(&call).unwrap();
    let key: WindowPublicKey =
        serde_json::from_slice(include_bytes!("fixtures/v1-key.json")).unwrap();
    let message = v1_message(
        &key,
        &call,
        value["received_seq"].as_i64().unwrap(),
        value["received_at"].as_i64().unwrap(),
        &att,
    )
    .unwrap();
    assert_eq!(message, include_bytes!("fixtures/v1-message.bin"));
    VerifyingKey::from_bytes(&key.public_key)
        .unwrap()
        .verify_strict(
            &message,
            &Signature::from_slice(&hex::decode(att.signature).unwrap()).unwrap(),
        )
        .unwrap();
}
#[test]
fn wire_defaults_nullable_intent_and_algorithm_type_are_unchanged() {
    let call: NewEntry =
        serde_json::from_slice(include_bytes!("fixtures/v1-missing-ingress.json")).unwrap();
    assert!(call.author.ingress.is_none());
    assert_eq!(
        serde_jcs::to_vec(&call).unwrap(),
        include_bytes!("fixtures/v1-default-ingress.json")
    );
    let some = v2(include_bytes!("fixtures/intent-entry.json"));
    let none = v2(include_bytes!("fixtures/null-intent-entry.json"));
    assert_eq!(
        some.call.command.resolved_intent_digest,
        intent_digest(Some("immutable intent")).unwrap()
    );
    assert!(none.call.command.intent_text.is_none());
    assert!(none.call.command.resolved_intent_digest.is_none());
    let raw = serde_json::to_value(&none).unwrap();
    assert!(raw["call"]["command"]["intent_text"].is_null());
    assert!(raw["call"]["command"]["resolved_intent_digest"].is_null());
    for name in [
        "HS256", "HS384", "HS512", "ES256", "ES384", "RS256", "RS384", "RS512", "PS256", "PS384",
        "PS512", "EdDSA",
    ] {
        let algorithm: jsonwebtoken::Algorithm =
            serde_json::from_value(serde_json::json!(name)).unwrap();
        assert_eq!(
            serde_json::to_value(algorithm).unwrap(),
            serde_json::json!(name)
        );
    }
}
#[cfg(feature = "mcp-executor-prototype")]
#[test]
fn extracted_structural_checks_preserve_eligibility_without_a_scheduler_grant() {
    let original = v2(include_bytes!("fixtures/intent-entry.json"));
    validate_v2_call(&original.call).unwrap();
    let mut call = original.call.clone();
    call.command.depends_on.push("ancestor".into());
    // Standalone structural validation always allowed representation. The
    // unchanged Hosting journal/replay layers must still refuse dependencies.
    validate_v2_call(&call).unwrap();
    call = original.call.clone();
    call.command.prepared_arguments["name"] = serde_json::json!("changed");
    assert!(validate_v2_call(&call).is_err());
    call = original.call.clone();
    call.app.assertion = "peer".into();
    assert!(validate_v2_call(&call).is_err());
    call = original.call.clone();
    call.command.prepared_arguments["sources"] = serde_json::json!(["source"]);
    assert!(validate_v2_call(&call).is_err());
    let mut append = original.call.clone();
    append.command.operation = "update_record".into();
    append.command.stable_create_ids.clear();
    append.command.original_arguments = serde_json::json!({"id":"target","body_append":"tail","run_key":append.command.run_key,"idempotency_key":append.command.idempotency_key});
    append.command.prepared_arguments = append.command.original_arguments.clone();
    append.command.meaning_digest = crate::provenance::action_digest(
        &append.command.operation,
        &append.command.original_arguments,
    );
    validate_v2_call(&append).unwrap();
    append.command.prepared_arguments["body_set"] = serde_json::json!("replacement");
    assert!(validate_v2_call(&append).is_err());
}
#[cfg(not(feature = "mcp-executor-prototype"))]
#[test]
fn featureoff_keeps_wire_data_but_refuses_v2_eligibility() {
    let entry = v2(include_bytes!("fixtures/intent-entry.json"));
    assert!(validate_v2_call(&entry.call)
        .unwrap_err()
        .to_string()
        .contains("outbox_v2_executor_unsupported"));
}
