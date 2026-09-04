//! Initial executable checks for the experimental public federation contract.
//!
//! These checks intentionally stop at the boundary documented by the profile:
//! Ed25519 objects are real and verified; JOSE–HPKE ciphertext remains a
//! FINAL-RFC structural placeholder until the upstream RFC is published.

use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

const PROFILE: &str = "native-fed/experimental-jose-hpke-1";

fn profile_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../protocol/federation/experimental-jose-hpke-1")
}

fn load(relative: &str) -> Value {
    let path = profile_root().join(relative);
    let bytes = fs::read(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|err| panic!("parse {} as JSON: {err}", path.display()))
}

/// Sufficient JCS for these fixtures: all member names are ASCII and all
/// numbers are safe integers. Production implementations must use full RFC
/// 8785, as the specification says.
fn fixture_jcs(value: &Value) -> String {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => serde_json::to_string(value).unwrap(),
        Value::Number(number) => {
            assert!(number.as_i64().is_some() || number.as_u64().is_some());
            number.to_string()
        }
        Value::Array(values) => format!(
            "[{}]",
            values.iter().map(fixture_jcs).collect::<Vec<_>>().join(",")
        ),
        Value::Object(object) => {
            assert!(object.keys().all(|key| key.is_ascii()));
            let mut keys = object.keys().collect::<Vec<_>>();
            keys.sort();
            format!(
                "{{{}}}",
                keys.into_iter()
                    .map(|key| format!(
                        "{}:{}",
                        serde_json::to_string(key).unwrap(),
                        fixture_jcs(&object[key])
                    ))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
    }
}

fn b64u_sha256(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(bytes))
}

fn protocol_digest(value: &Value) -> String {
    format!("sha-256:{}", b64u_sha256(fixture_jcs(value).as_bytes()))
}

fn bytes_digest(bytes: &[u8]) -> String {
    format!("sha-256:{}", b64u_sha256(bytes))
}

fn public_key(jwk: &Value) -> VerifyingKey {
    assert_eq!(jwk["kty"], "OKP");
    assert_eq!(jwk["crv"], "Ed25519");
    let x = URL_SAFE_NO_PAD.decode(jwk["x"].as_str().unwrap()).unwrap();
    VerifyingKey::from_bytes(x.as_slice().try_into().unwrap()).unwrap()
}

fn expected_kid(jwk: &Value, purpose: &str) -> String {
    let thumbprint = serde_json::json!({
        "crv": jwk["crv"],
        "kty": jwk["kty"],
        "x": jwk["x"],
    });
    format!(
        "n1.{purpose}.{}",
        b64u_sha256(fixture_jcs(&thumbprint).as_bytes())
    )
}

fn detached_protected(compact: &str) -> Value {
    let parts = compact.split('.').collect::<Vec<_>>();
    assert_eq!(parts.len(), 3, "detached JWS has three segments");
    assert!(parts[1].is_empty(), "detached payload segment is empty");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap()
}

fn detached_kid(compact: &str) -> String {
    detached_protected(compact)["kid"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn verify_detached(payload: &Value, compact: &str, jwk: &Value, typ: &str) {
    let parts = compact.split('.').collect::<Vec<_>>();
    let protected = detached_protected(compact);
    assert_eq!(
        protected,
        serde_json::json!({"alg":"EdDSA","kid":jwk["kid"],"typ":typ})
    );
    assert_eq!(parts[0], URL_SAFE_NO_PAD.encode(fixture_jcs(&protected)));
    let signing_input = format!(
        "{}.{}",
        parts[0],
        URL_SAFE_NO_PAD.encode(fixture_jcs(payload))
    );
    let signature_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
    let signature = Signature::from_slice(&signature_bytes).unwrap();
    public_key(jwk)
        .verify(signing_input.as_bytes(), &signature)
        .unwrap();
}

fn jwk_matches_purpose(jwk: &Value, purpose: &str) -> bool {
    let algorithm_matches = match purpose {
        "encryption" => {
            jwk["kty"] == "OKP"
                && jwk["crv"] == "X25519"
                && jwk["alg"] == "HPKE-3-KE"
                && jwk["use"] == "enc"
        }
        "root" | "signing" | "installation" | "authority" | "relay" => {
            jwk["kty"] == "OKP"
                && jwk["crv"] == "Ed25519"
                && jwk["alg"] == "EdDSA"
                && jwk["use"] == "sig"
        }
        _ => false,
    };
    algorithm_matches && jwk["kid"] == expected_kid(jwk, purpose)
}

fn validate_principal_key_purposes(document: &Value) -> Result<(), &'static str> {
    if document["root_keys"]
        .as_array()
        .unwrap()
        .iter()
        .any(|key| !jwk_matches_purpose(&key["jwk"], "root"))
    {
        return Err("invalid_request");
    }
    if document["operational_keys"]
        .as_array()
        .unwrap()
        .iter()
        .any(|key| {
            !key["purpose"]
                .as_str()
                .is_some_and(|purpose| jwk_matches_purpose(&key["jwk"], purpose))
        })
    {
        return Err("invalid_request");
    }
    if document["installations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|installation| !jwk_matches_purpose(&installation["jwk"], "installation"))
    {
        return Err("invalid_request");
    }
    Ok(())
}

fn active_service_jwk<'a>(descriptor: &'a Value, set: &str, kid: &str) -> Option<&'a Value> {
    descriptor[set].as_array().unwrap().iter().find_map(|key| {
        (key["status"] == "active" && key["jwk"]["kid"] == kid).then_some(&key["jwk"])
    })
}

fn active_operational_jwk<'a>(document: &'a Value, purpose: &str, kid: &str) -> Option<&'a Value> {
    document["operational_keys"]
        .as_array()
        .unwrap()
        .iter()
        .find_map(|key| {
            (key["status"] == "active"
                && key["purpose"] == purpose
                && key["jwk"]["kid"] == kid
                && jwk_matches_purpose(&key["jwk"], purpose))
            .then_some(&key["jwk"])
        })
}

fn binding(principal: &Value) -> String {
    format!(
        "{}/{}",
        principal["network_id"].as_str().unwrap(),
        principal["principal_id"].as_str().unwrap()
    )
}

fn address_valid(principal: &Value) -> bool {
    let Some(network) = principal.get("network_id").and_then(Value::as_str) else {
        return false;
    };
    let Some(id) = principal.get("principal_id").and_then(Value::as_str) else {
        return false;
    };
    let network_valid = network == "native"
        || network.strip_prefix("dns:").is_some_and(valid_dns_name)
        || network.strip_prefix("key:").is_some_and(|digest| {
            digest.len() == 43
                && digest
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    let id_bytes = id.as_bytes();
    let edge = |b: u8| b.is_ascii_alphanumeric();
    network_valid
        && network.len() <= 257
        && (1..=64).contains(&id_bytes.len())
        && edge(id_bytes[0])
        && edge(id_bytes[id_bytes.len() - 1])
        && id_bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~'))
}

fn valid_dns_name(dns: &str) -> bool {
    !dns.is_empty()
        && dns.len() <= 253
        && dns
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'.'))
        && dns.split('.').all(|label| {
            let bytes = label.as_bytes();
            (1..=63).contains(&bytes.len())
                && bytes[0].is_ascii_alphanumeric()
                && bytes[bytes.len() - 1].is_ascii_alphanumeric()
        })
}

fn encryption_context(envelope: &Value) -> Value {
    let mut context = Map::new();
    for (key, value) in envelope.as_object().unwrap() {
        if key != "jwe" && key != "ciphertext_digest" {
            context.insert(key.clone(), value.clone());
        }
    }
    Value::Object(context)
}

fn validate_envelope(
    wrapper: &Value,
    known_capabilities: &HashSet<&str>,
) -> Result<(), &'static str> {
    let envelope = &wrapper["envelope"];
    assert_eq!(envelope["profile"], PROFILE);
    assert!(address_valid(&envelope["sender_principal"]));
    if envelope["sender_key_id"]
        != detached_protected(wrapper["signature"].as_str().unwrap())["kid"]
    {
        return Err("signature_invalid");
    }

    let recipients = envelope["recipients"].as_array().unwrap();
    if recipients
        .windows(2)
        .any(|pair| binding(&pair[0]["principal"]) >= binding(&pair[1]["principal"]))
    {
        return Err("invalid_request");
    }
    let jwe_recipients = envelope["jwe"]["recipients"].as_array().unwrap();
    if recipients.len() != jwe_recipients.len()
        || recipients
            .iter()
            .zip(jwe_recipients)
            .any(|(outer, inner)| outer["encryption_key_id"] != inner["header"]["kid"])
    {
        return Err("recipient_mismatch");
    }

    let context = encryption_context(envelope);
    if envelope["jwe"]["aad"] != URL_SAFE_NO_PAD.encode(fixture_jcs(&context)) {
        return Err("malformed_envelope");
    }
    let encoded_protected = envelope["jwe"]["protected"].as_str().unwrap();
    let Ok(protected_bytes) = URL_SAFE_NO_PAD.decode(encoded_protected) else {
        return Err("malformed_envelope");
    };
    let Ok(protected) = serde_json::from_slice::<Value>(&protected_bytes) else {
        return Err("malformed_envelope");
    };
    let expected_protected = serde_json::json!({
        "alg": "HPKE-3-KE",
        "enc": "A256GCM",
        "typ": "native-federation+jwe",
        "cty": envelope["content_type"],
        "native_profile": PROFILE,
        "crit": ["native_profile"],
    });
    if protected != expected_protected
        || encoded_protected != URL_SAFE_NO_PAD.encode(fixture_jcs(&expected_protected))
    {
        return Err("malformed_envelope");
    }

    let ciphertext = URL_SAFE_NO_PAD
        .decode(envelope["jwe"]["ciphertext"].as_str().unwrap())
        .unwrap();
    assert_eq!(envelope["ciphertext_digest"], bytes_digest(&ciphertext));

    if envelope["required_capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .any(|capability| !known_capabilities.contains(capability.as_str().unwrap()))
    {
        return Err("required_capability_unsupported");
    }
    Ok(())
}

fn validate_receipt(wrapper: &Value, descriptor: &Value) -> Result<(), &'static str> {
    let receipt = &wrapper["receipt"];
    let signature_kid = detached_kid(wrapper["signature"].as_str().unwrap());
    if receipt["relay_key_id"] != signature_kid {
        return Err("signature_invalid");
    }
    let Some(relay) = active_service_jwk(descriptor, "relay_keys", &signature_kid) else {
        return Err("signature_invalid");
    };
    if !jwk_matches_purpose(relay, "relay") {
        return Err("signature_invalid");
    }

    let has = |field: &str| receipt.get(field).is_some();
    let state_valid = match receipt["state"].as_str().unwrap() {
        "queued" => {
            !has("previous_state") && !has("collector_installation_id") && !has("reason_code")
        }
        "collected" => {
            receipt["previous_state"] == "queued"
                && has("collector_installation_id")
                && !has("reason_code")
        }
        "acknowledged" => {
            receipt["previous_state"] == "collected"
                && has("collector_installation_id")
                && !has("reason_code")
        }
        "rejected" => has("reason_code") && !has("collector_installation_id"),
        _ => false,
    };
    state_valid.then_some(()).ok_or("invalid_request")
}

fn visit_refs(value: &Value, base: &Path) {
    match value {
        Value::Array(values) => values.iter().for_each(|value| visit_refs(value, base)),
        Value::Object(object) => {
            if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
                if !reference.starts_with('#') && !reference.starts_with("https://") {
                    let file = reference.split('#').next().unwrap();
                    assert!(
                        base.join(file).is_file(),
                        "unresolved schema ref: {reference}"
                    );
                }
            }
            object.values().for_each(|value| visit_refs(value, base));
        }
        _ => {}
    }
}

#[test]
fn schemas_and_manifest_are_closed_over_checked_in_files() {
    let schemas = profile_root().join("schemas");
    let mut ids = BTreeSet::new();
    for entry in fs::read_dir(&schemas).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            value["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        assert!(ids.insert(value["$id"].as_str().unwrap().to_owned()));
        visit_refs(&value, &schemas);
    }

    let manifest = load("fixtures/manifest.json");
    assert_eq!(manifest["profile"], PROFILE);
    assert_eq!(manifest["jose_hpke_status"], "work-in-progress");
    assert!(profile_root()
        .join(manifest["verification_keys"].as_str().unwrap())
        .is_file());
    assert!(profile_root()
        .join(manifest["request_proof_signing"].as_str().unwrap())
        .is_file());
    let common = load("schemas/common.schema.json");
    assert!(common["$defs"]["jwsTyp"]["enum"]
        .as_array()
        .unwrap()
        .contains(&Value::String("native-profile-negotiation+jws".to_owned())));
    let cases = manifest["cases"].as_array().unwrap();
    assert!(cases.len() >= 48, "expanded corpus unexpectedly shrank");
    let mut case_ids = HashSet::new();
    for case in cases {
        assert!(case_ids.insert(case["id"].as_str().unwrap()));
        let fixture = profile_root().join(case["path"].as_str().unwrap());
        assert!(fixture.is_file());
        let schema = case["schema"].as_str().unwrap();
        if !schema.starts_with("scenario:") {
            let schema_file = schema.split('#').next().unwrap();
            assert!(profile_root().join(schema_file).is_file(), "{schema}");
        }
        if case["expect"] == "invalid" {
            assert!(case.get("error").is_some());
        }
        assert!(!case["validation_layers"].as_array().unwrap().is_empty());
        if schema == "schemas/scenario.schema.json" {
            let value: Value = serde_json::from_slice(&fs::read(fixture).unwrap()).unwrap();
            assert_eq!(value["scenario_id"], case["id"]);
            assert_eq!(value["profile"], PROFILE);
            assert_eq!(value["clock"], "2026-08-02T09:10:00Z");
            assert!(!value["steps"].as_array().unwrap().is_empty());
            if case["expect"] == "invalid" {
                assert_eq!(value["expect_error"], case["error"]);
                assert!(case["validation_layers"]
                    .as_array()
                    .unwrap()
                    .contains(&value["validation_layer"]));
            }
        }
        if case["validation_layers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|layer| layer == "context" || layer == "recipient-mapping")
        {
            assert_eq!(case["crypto_status"], "FINAL-RFC-structural-placeholder");
        }
    }
}

#[test]
fn expanded_manifest_covers_identity_transport_and_relay_boundaries() {
    let manifest = load("fixtures/manifest.json");
    let cases = manifest["cases"].as_array().unwrap();
    let ids = cases
        .iter()
        .map(|case| case["id"].as_str().unwrap())
        .collect::<HashSet<_>>();
    for required in [
        "principal-document-rotated",
        "principal-document-revoked-signing-key",
        "principal-document-rollback",
        "alias-reassignment-stale",
        "directory-etag-revalidation",
        "directory-precondition-failed",
        "directory-profile-negotiate",
        "envelope-many-recipients",
        "envelope-replay-identical",
        "envelope-profile-downgrade",
        "relay-fanout-lifecycle",
        "relay-lease-redelivery",
        "relay-concurrent-lease",
        "relay-ack-retry",
        "relay-quota-exceeded",
        "relay-terminal-transition",
    ] {
        assert!(ids.contains(required), "missing expanded case {required}");
    }

    let layers = cases
        .iter()
        .flat_map(|case| case["validation_layers"].as_array().unwrap())
        .map(|layer| layer.as_str().unwrap())
        .collect::<HashSet<_>>();
    for required in [
        "schema",
        "jws",
        "key-state",
        "freshness",
        "alias",
        "etag",
        "authorization",
        "negotiation",
        "capability",
        "recipient-order",
        "replay",
        "downgrade",
        "idempotency",
        "fan-out",
        "lease",
        "acknowledgement",
        "quota",
        "protocol-state",
        "service-behaviour",
    ] {
        assert!(
            layers.contains(required),
            "missing validation layer {required}"
        );
    }
}

#[test]
fn rotated_principal_is_signed_by_the_new_active_key() {
    let wrapper = load("fixtures/positive/principal-document-rotated.json");
    let document = &wrapper["document"];
    assert_eq!(document["document_version"], 2);
    let signature_kid = detached_kid(wrapper["principal_signature"].as_str().unwrap());
    let signing = document["operational_keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| {
            key["purpose"] == "signing"
                && key["status"] == "active"
                && key["jwk"]["kid"] == signature_kid
        })
        .expect("rotated document must be signed by its active signing key");
    verify_detached(
        document,
        wrapper["principal_signature"].as_str().unwrap(),
        &signing["jwk"],
        "native-principal+jws",
    );
    assert_eq!(
        wrapper["authority_attestation"]["statement"]["document_digest"],
        protocol_digest(document)
    );
}

#[test]
fn principal_addresses_have_exact_normalization_and_bounds() {
    for valid in [
        serde_json::json!({"network_id":"native","principal_id":"A"}),
        serde_json::json!({"network_id":"dns:example.com","principal_id":"p_01J.foo~9"}),
        serde_json::json!({"network_id":format!("key:{}", "A".repeat(43)),"principal_id":"z9"}),
    ] {
        assert!(address_valid(&valid), "{valid}");
    }
    for invalid in [
        load("fixtures/negative/principal-address-invalid.json"),
        serde_json::json!({"network_id":"native","principal_id":"/"}),
        serde_json::json!({"network_id":"dns:example.com.","principal_id":"a"}),
        serde_json::json!({"network_id":"native","principal_id":"_edge"}),
        serde_json::json!({"network_id":"native","principal_id":"a".repeat(65)}),
    ] {
        assert!(!address_valid(&invalid), "{invalid}");
    }
}

#[test]
fn network_descriptor_is_authority_signed_and_pins_service_key_purposes() {
    let wrapper = load("fixtures/positive/network-descriptor.json");
    let descriptor = &wrapper["descriptor"];
    assert!(descriptor["authority_keys"]
        .as_array()
        .unwrap()
        .iter()
        .all(|key| jwk_matches_purpose(&key["jwk"], "authority")));
    assert!(descriptor["relay_keys"]
        .as_array()
        .unwrap()
        .iter()
        .all(|key| jwk_matches_purpose(&key["jwk"], "relay")));
    assert_eq!(descriptor["profile_preference"][0], PROFILE);
    let signature_kid = detached_kid(wrapper["signature"].as_str().unwrap());
    let authority = active_service_jwk(descriptor, "authority_keys", &signature_kid)
        .expect("descriptor signature must resolve to an active authority key");
    verify_detached(
        descriptor,
        wrapper["signature"].as_str().unwrap(),
        authority,
        "native-network-descriptor+jws",
    );
}

#[test]
fn positive_principal_document_has_real_jws_authority_and_key_chain() {
    let wrapper = load("fixtures/positive/principal-document.json");
    let network = load("fixtures/positive/network-descriptor.json");
    let descriptor = &network["descriptor"];
    let document = &wrapper["document"];
    let root = &document["root_keys"][0]["jwk"];
    validate_principal_key_purposes(document).unwrap();

    let principal_signature_kid = detached_kid(wrapper["principal_signature"].as_str().unwrap());
    let signing = active_operational_jwk(document, "signing", &principal_signature_kid)
        .expect("principal signature must resolve to an active signing key");

    for key in document["operational_keys"].as_array().unwrap() {
        let authorization_kid = detached_kid(key["authorization"]["signature"].as_str().unwrap());
        assert_eq!(authorization_kid, root["kid"]);
        verify_detached(
            &key["authorization"]["statement"],
            key["authorization"]["signature"].as_str().unwrap(),
            root,
            "native-key-authorization+jws",
        );
    }
    verify_detached(
        &document["installations"][0]["authorization"]["statement"],
        document["installations"][0]["authorization"]["signature"]
            .as_str()
            .unwrap(),
        signing,
        "native-key-authorization+jws",
    );
    verify_detached(
        document,
        wrapper["principal_signature"].as_str().unwrap(),
        signing,
        "native-principal+jws",
    );
    assert_eq!(
        wrapper["authority_attestation"]["statement"]["document_digest"],
        protocol_digest(document)
    );
    let attestation_kid = detached_kid(
        wrapper["authority_attestation"]["signature"]
            .as_str()
            .unwrap(),
    );
    let authority = active_service_jwk(descriptor, "authority_keys", &attestation_kid)
        .expect("principal attestation must resolve to an active authority key");
    verify_detached(
        &wrapper["authority_attestation"]["statement"],
        wrapper["authority_attestation"]["signature"]
            .as_str()
            .unwrap(),
        authority,
        "native-principal-attestation+jws",
    );
}

#[test]
fn positive_envelopes_are_signed_context_bound_and_n_recipient() {
    let principal = load("fixtures/positive/principal-document.json");
    let known = HashSet::new();
    for path in [
        "fixtures/positive/envelope-one-recipient.json",
        "fixtures/positive/envelope-many-recipients.json",
    ] {
        let wrapper = load(path);
        let signature_kid = detached_kid(wrapper["signature"].as_str().unwrap());
        let signing = active_operational_jwk(&principal["document"], "signing", &signature_kid)
            .expect("envelope signature must resolve to an active signing key");
        verify_detached(
            &wrapper["envelope"],
            wrapper["signature"].as_str().unwrap(),
            signing,
            "native-envelope+jws",
        );
        validate_envelope(&wrapper, &known).unwrap();
    }
    assert_eq!(
        load("fixtures/positive/envelope-many-recipients.json")["envelope"]["recipients"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn positive_receipt_is_relay_signed_and_scoped_to_exact_envelope() {
    let network = load("fixtures/positive/network-descriptor.json");
    let descriptor = &network["descriptor"];
    let envelope = load("fixtures/positive/envelope-one-recipient.json");
    let receipt = load("fixtures/positive/receipt-queued.json");
    validate_receipt(&receipt, descriptor).unwrap();
    let signature_kid = detached_kid(receipt["signature"].as_str().unwrap());
    let relay = active_service_jwk(descriptor, "relay_keys", &signature_kid)
        .expect("receipt signature must resolve to an active relay key");
    verify_detached(
        &receipt["receipt"],
        receipt["signature"].as_str().unwrap(),
        relay,
        "native-relay-receipt+jws",
    );
    assert_eq!(receipt["receipt"]["state"], "queued");
    assert_eq!(
        receipt["receipt"]["envelope_digest"],
        protocol_digest(&envelope)
    );
}

#[test]
fn negative_fixtures_fail_at_the_named_contract_boundary() {
    let known = HashSet::new();
    assert_eq!(
        validate_envelope(
            &load("fixtures/negative/envelope-recipient-order.json"),
            &known
        ),
        Err("invalid_request")
    );
    assert_eq!(
        validate_envelope(
            &load("fixtures/negative/envelope-recipient-mismatch.json"),
            &known
        ),
        Err("recipient_mismatch")
    );
    assert_eq!(
        validate_envelope(
            &load("fixtures/negative/envelope-protected-header.json"),
            &known
        ),
        Err("malformed_envelope")
    );
    assert_eq!(
        validate_envelope(
            &load("fixtures/negative/envelope-sender-key-mismatch.json"),
            &known
        ),
        Err("signature_invalid")
    );
    assert_eq!(
        validate_envelope(
            &load("fixtures/negative/envelope-required-capability.json"),
            &known
        ),
        Err("required_capability_unsupported")
    );

    let bad_principal = load("fixtures/negative/principal-document-bad-kid.json");
    let bad_signing = &bad_principal["document"]["operational_keys"][0]["jwk"];
    assert_ne!(bad_signing["kid"], expected_kid(bad_signing, "signing"));

    let purpose_confused = load("fixtures/negative/principal-document-purpose-confusion.json");
    assert_eq!(
        validate_principal_key_purposes(&purpose_confused["document"]),
        Err("invalid_request")
    );

    let bad_receipt = load("fixtures/negative/receipt-envelope-digest.json");
    let envelope = load("fixtures/positive/envelope-one-recipient.json");
    assert_ne!(
        bad_receipt["receipt"]["envelope_digest"],
        protocol_digest(&envelope)
    );
    let network = load("fixtures/positive/network-descriptor.json");
    assert_eq!(
        validate_receipt(
            &load("fixtures/negative/receipt-queued-fields.json"),
            &network["descriptor"]
        ),
        Err("invalid_request")
    );
    assert_eq!(
        validate_receipt(
            &load("fixtures/negative/receipt-invalid-transition.json"),
            &network["descriptor"]
        ),
        Err("invalid_request")
    );
    assert_eq!(
        validate_receipt(
            &load("fixtures/negative/receipt-relay-key-mismatch.json"),
            &network["descriptor"]
        ),
        Err("signature_invalid")
    );

    let conflict = load("fixtures/negative/idempotency-conflict.json");
    assert_eq!(
        conflict["first"]["envelope"]["envelope_id"],
        conflict["retry"]["envelope"]["envelope_id"]
    );
    assert_ne!(
        protocol_digest(&conflict["first"]),
        protocol_digest(&conflict["retry"])
    );
}
