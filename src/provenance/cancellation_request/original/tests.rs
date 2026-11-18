use super::*;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
const CHILD: &str = "NATIVE_TEST_CANCEL_ORIGINAL_CHILD";
pub(crate) fn config(secret: u8) -> serde_json::Value {
    let public = SigningKey::from_bytes(&[secret; 32])
        .verifying_key()
        .to_bytes();
    json!({"version":2,"role":ROLE,"issuer":"successor","key_id":digest(&public),"public_key":hex::encode(public),"scope":{"realm":"fixture","public_origin":"https://native.test","workspace":"workspace","origin":"ndb_11111111111111111111111111111111"}})
}
fn catalogue() -> crate::mcp::executor_prototype::HostedExecutorAdmission {
    let mut r = crate::mcp::ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut r).unwrap();
    crate::mcp::register_surface_tools(&mut r).unwrap();
    crate::mcp::executor_prototype::HostedExecutorAdmission::new(
        &r,
        &crate::mcp::ExperimentalExecutors::empty(),
    )
    .unwrap()
}
pub(crate) fn fixture(operation: &str) -> (wire::EntryV2, wire::WindowPublicKey) {
    let mut e: wire::EntryV2 = serde_json::from_slice(include_bytes!(
        "../../deferred_wire/fixtures/intent-entry.json"
    ))
    .unwrap();
    let cat = catalogue();
    // Both eligible operations MUST actually exist in the populated catalogue.
    for op in ["create_record", "update_record"] {
        assert!(cat
            .deferred_contract_identity("records_write", op)
            .is_some());
    }
    let (version, contract) = cat
        .deferred_contract_identity("records_write", operation)
        .unwrap();
    let c = &mut e.call.command;
    c.contract_version = version.into();
    c.contract_digest = contract.into();
    c.author.workspace.origin = config(5)["scope"]["origin"].as_str().unwrap().into();
    c.author.workspace.activity_epoch = 0;
    c.operation = operation.into();
    if operation == "update_record" {
        c.original_arguments = json!({"id":"target","body_append":"append","idempotency_key":c.idempotency_key,"run_key":c.run_key,"reason":"fixture"});
        c.prepared_arguments = c.original_arguments.clone();
        c.stable_create_ids.clear();
        c.meaning_digest = crate::provenance::action_digest(operation, &c.original_arguments);
    }
    let public = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
    let k = wire::WindowPublicKey {
        window_id: c.window_id.clone(),
        deployment_id: "deployment".into(),
        base_snapshot_digest: digest(b"base"),
        key_id: wire::digest(&public).unwrap(),
        public_key: public,
    };
    resign(&mut e, &k);
    (e, k)
}
pub(crate) fn resign(e: &mut wire::EntryV2, k: &wire::WindowPublicKey) {
    e.attestation.key_id = k.key_id.clone();
    e.attestation.envelope_digest = wire::digest(&e.call).unwrap();
    e.attestation.signature = hex::encode(
        SigningKey::from_bytes(&[9; 32])
            .sign(
                &wire::v2_message(k, &e.call, e.received_seq, e.received_at, &e.attestation)
                    .unwrap(),
            )
            .to_bytes(),
    );
}
pub(crate) fn claims(e: &wire::EntryV2, k: &wire::WindowPublicKey) -> Claims {
    let now = chrono::Utc::now().timestamp_millis();
    let c = &e.call.command;
    let original = super::super::Original {
        window: k.window_id.clone(),
        deployment: k.deployment_id.clone(),
        epoch: 1,
        window_key_id: k.key_id.clone(),
        base_snapshot_digest: k.base_snapshot_digest.clone(),
        entry_id: c.entry_id.clone(),
        received_seq: e.received_seq,
        received_at: e.received_at,
        operation: c.operation.clone(),
        idempotency_key: c.idempotency_key.clone(),
        meaning_digest: c.meaning_digest.clone(),
        intent_digest: c.resolved_intent_digest.clone(),
        package: e.call.app.package.clone(),
        package_version: e.call.app.package_version.clone(),
        install_event_id: e.call.app.install_event_id.clone(),
    };
    let bytes = String::from_utf8(serde_jcs::to_vec(e).unwrap()).unwrap();
    Claims {
        version: 2,
        issuer: "successor".into(),
        key_id: config(5)["key_id"].as_str().unwrap().into(),
        audience: AUDIENCE.into(),
        purpose: PURPOSE.into(),
        scope: serde_json::from_value(config(5)["scope"].clone()).unwrap(),
        nonce: uuid::Uuid::new_v4().to_string(),
        issued_at: now,
        deadline: now + 30_000,
        requester: c.author.clone(),
        credential_sha256: wire::digest(&c.author.credential).unwrap(),
        key_observation: KeyObservation {
            source: "authenticated_readonly_control".into(),
            observed_at: now,
            epoch: 1,
            phase: "draining".into(),
            key: k.clone(),
        },
        binding: Binding {
            original,
            author: c.author.clone(),
            run_key: c.run_key.clone(),
            parent_key: c.parent_key.clone(),
            stable_create_ids: c.stable_create_ids.clone(),
            app: e.call.app.clone(),
            made_at: e.call.made_at.clone(),
            command_identity_digest: super::super::super::command_identity_digest(
                &c.prepared_arguments,
            )
            .unwrap(),
            app_context_digest: app_context_digest(&e.call.app).unwrap(),
        },
        original_sha256: digest(bytes.as_bytes()),
        original_bytes: bytes,
    }
}
pub(crate) fn packet(c: Claims) -> Vec<u8> {
    let signature = hex::encode(
        SigningKey::from_bytes(&[5; 32])
            .sign(&signing_message(&c).unwrap())
            .to_bytes(),
    );
    serde_jcs::to_vec(&Packet {
        claims: c,
        signature,
    })
    .unwrap()
}
#[test]
fn original_integrity_production_loader_and_crypto_matrix() {
    if std::env::var_os(CHILD).is_some() {
        return;
    }
    for case in [
        "disabled",
        "configured",
        "malformed",
        "old_profile",
        "same_key",
        "scope",
        "sticky",
        "rotation",
    ] {
        let mut p = std::process::Command::new(std::env::current_exe().unwrap());
        p.args([
            "provenance::cancellation_request::original::tests::original_integrity_child",
            "--exact",
            "--nocapture",
        ])
        .env(CHILD, case)
        .env_remove(PIN_ENV)
        .env_remove(super::super::PIN_ENV);
        let mut c = config(if case == "rotation" { 6 } else { 5 });
        if case == "old_profile" {
            c["version"] = json!(1);
        }
        if case == "scope" {
            c["scope"]["public_origin"] = json!("https://native.test/path");
        }
        if case != "disabled" {
            p.env(
                PIN_ENV,
                if matches!(case, "malformed" | "sticky") {
                    "bad".into()
                } else {
                    c.to_string()
                },
            );
        }
        if case == "same_key" {
            let mut old = c.clone();
            old.as_object_mut().unwrap().remove("role");
            old["version"] = json!(1);
            old["issuer"] = json!("different-issuer");
            old["scope"]["realm"] = json!("different-realm");
            p.env(super::super::PIN_ENV, old.to_string());
        }
        let out = p.output().unwrap();
        assert!(
            out.status.success(),
            "{case}: {} {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
#[test]
fn original_integrity_child() {
    let Ok(case) = std::env::var(CHILD) else {
        return;
    };
    super::super::initialize_from_process().unwrap();
    let result = initialize_from_process();
    if matches!(
        case.as_str(),
        "malformed" | "old_profile" | "same_key" | "scope" | "sticky"
    ) {
        assert!(result.is_err());
        // Mutation only in this disposable process; the production loader stays
        // permanently invalid despite replacement configuration. No reset API.
        std::env::set_var(PIN_ENV, config(5).to_string());
        assert!(initialize_from_process().is_err());
        return;
    }
    result.unwrap();
    let (entry, key) = fixture("create_record");
    let c = claims(&entry, &key);
    if case == "disabled" {
        assert!(fingerprint().unwrap().is_none());
        assert!(inspect_packet(&packet(c.clone())).is_err());
        std::env::set_var(PIN_ENV, config(5).to_string());
        initialize_from_process().unwrap();
        assert!(fingerprint().unwrap().is_none());
        assert!(inspect_packet(&packet(c)).is_err());
        return;
    }
    if case == "rotation" {
        assert!(inspect_packet(&packet(c.clone())).is_err());
        assert_eq!(fingerprint().unwrap().unwrap().key_id, config(6)["key_id"]);
        let mut rotated = c;
        rotated.key_id = config(6)["key_id"].as_str().unwrap().into();
        let signature = hex::encode(
            SigningKey::from_bytes(&[6; 32])
                .sign(&signing_message(&rotated).unwrap())
                .to_bytes(),
        );
        assert!(inspect_packet(
            &serde_jcs::to_vec(&Packet {
                claims: rotated,
                signature
            })
            .unwrap()
        )
        .is_ok());
        // A runtime env replacement cannot rotate the immutable loaded key.
        std::env::set_var(PIN_ENV, config(5).to_string());
        initialize_from_process().unwrap();
        assert_eq!(fingerprint().unwrap().unwrap().key_id, config(6)["key_id"]);
        return;
    }
    for op in ["create_record", "update_record"] {
        let (e, k) = fixture(op);
        let mut nullable = e.clone();
        nullable.call.command.intent_text = None;
        nullable.call.command.resolved_intent_digest = None;
        resign(&mut nullable, &k);
        assert!(inspect_packet(&packet(claims(&nullable, &k))).is_ok());
        let mut historical = e.clone();
        historical.call.command.author.credential = Some(wire::CredentialEvidence::OAuth {
            issuer: "old-issuer".into(),
            subject: "old-subject".into(),
            audience: vec!["old-resource".into()],
            kid: "old-key".into(),
            algorithm: jsonwebtoken::Algorithm::RS256,
            key_thumbprint: "old-thumbprint".into(),
            iat: 0,
            exp: 10,
            jti: None,
            org_id: None,
            resource: "old-resource".into(),
            staging_identity: None,
        });
        historical.attestation.deadline = 10_000;
        resign(&mut historical, &k);
        let mut renewed_snapshot = claims(&historical, &k);
        renewed_snapshot.requester.credential = e.call.command.author.credential.clone();
        renewed_snapshot.credential_sha256 =
            wire::digest(&renewed_snapshot.requester.credential).unwrap();
        assert!(
            inspect_packet(&packet(renewed_snapshot)).is_ok(),
            "expired original OAuth integrity with fresh separate requester snapshot"
        );
        for public in [
            SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes(),
            [0; 32],
        ] {
            let mut substituted = k.clone();
            substituted.public_key = public;
            substituted.key_id = wire::digest(&public).unwrap();
            let mut wrong = e.clone();
            resign(&mut wrong, &substituted);
            assert!(inspect_packet(&packet(claims(&wrong, &substituted))).is_err());
        }

        let c = claims(&e, &k);
        assert!(
            e.attestation.deadline < chrono::Utc::now().timestamp_millis(),
            "expired original is integrity-only"
        );
        assert_eq!(
            inspect_packet(&packet(c.clone()))
                .unwrap()
                .original_sha256(),
            c.original_sha256
        );
        assert!(inspect_packet(&packet(c.clone())).is_ok());
        for label in [
            "purpose",
            "audience",
            "nonce",
            "scope",
            "deadline",
            "future",
            "observed",
            "future_observation",
            "key",
            "keyid",
            "author",
            "membership",
            "negative_epoch",
            "window_epoch",
            "credential",
            "binding",
            "app",
            "made",
            "meaning",
            "intent",
            "parent",
            "run",
            "stable",
            "contract",
            "contract_version",
            "dependencies",
            "prepared",
            "signature",
            "original_oauth",
            "unknown",
            "noncanonical",
        ] {
            let mut bad = c.clone();
            match label {
                "purpose" => bad.purpose = super::super::PURPOSE.into(),
                "audience" => bad.audience = super::super::AUDIENCE.into(),
                "nonce" => bad.nonce = "bad".into(),
                "scope" => bad.scope.origin = "ndb_22222222222222222222222222222222".into(),
                "deadline" => bad.deadline = bad.issued_at,
                "future" => bad.issued_at += 60_000,
                "observed" => bad.key_observation.observed_at = bad.deadline,
                "future_observation" => bad.key_observation.observed_at = bad.issued_at + 20_000,
                "key" => {
                    bad.key_observation.key.public_key =
                        SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes()
                }
                "keyid" => bad.key_observation.key.key_id = digest(&key.public_key),
                "author" => bad.requester.account_id = "other".into(),
                "membership" => bad.requester.membership.generation = Some(2),
                "window_epoch" => {
                    bad.key_observation.epoch = 0;
                    bad.binding.original.epoch = 0;
                }
                "credential" => bad.credential_sha256 = "bad".into(),
                "binding" => bad.binding.original.idempotency_key = "other".into(),
                "app" => bad.binding.app.package_version = "2.0.0".into(),
                "made" => bad.binding.made_at.reported_unix_ms += 1,
                "meaning" => bad.binding.original.meaning_digest = "bad".into(),
                "intent" => bad.binding.original.intent_digest = None,
                "parent" => bad.binding.parent_key = Some("other".into()),
                "run" => bad.binding.run_key = "other".into(),
                "stable" => bad.binding.stable_create_ids.push("other".into()),
                _ => {
                    let mut changed = e.clone();
                    match label {
                        "negative_epoch" => {
                            changed.call.command.author.workspace.activity_epoch = -1
                        }
                        "contract" => changed.call.command.contract_digest = "bad".into(),
                        "contract_version" => changed.call.command.contract_version = "999".into(),
                        "dependencies" => changed.call.command.depends_on.push("ancestor".into()),
                        "prepared" => {
                            changed.call.command.prepared_arguments["reason"] = json!("changed")
                        }
                        "signature" => changed.attestation.signature = "00".repeat(64),
                        "original_oauth" => {
                            changed.call.command.author.credential =
                                Some(wire::CredentialEvidence::OAuth {
                                    issuer: "iss".into(),
                                    subject: "sub".into(),
                                    audience: vec![],
                                    kid: "kid".into(),
                                    algorithm: jsonwebtoken::Algorithm::RS256,
                                    key_thumbprint: "thumb".into(),
                                    iat: 0,
                                    exp: 1,
                                    jti: None,
                                    org_id: None,
                                    resource: "resource".into(),
                                    staging_identity: None,
                                })
                        }
                        "unknown" | "noncanonical" => {}
                        _ => unreachable!(),
                    };
                    if label != "signature" {
                        resign(&mut changed, &k);
                    }
                    bad = claims(&changed, &k);
                    if label == "unknown" {
                        let mut v = serde_json::to_value(&changed).unwrap();
                        v["extra"] = json!(true);
                        bad.original_bytes =
                            String::from_utf8(serde_jcs::to_vec(&v).unwrap()).unwrap();
                    }
                    if label == "noncanonical" {
                        bad.original_bytes.push(' ');
                    }
                    bad.original_sha256 = digest(bad.original_bytes.as_bytes());
                }
            }
            assert!(inspect_packet(&packet(bad)).is_err(), "{op}/{label}");
        }
        let mut tampered = packet(c);
        tampered.push(b' ');
        assert!(inspect_packet(&tampered).is_err());
    }
}
