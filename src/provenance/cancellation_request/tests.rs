use super::*;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
const CHILD: &str = "NATIVE_TEST_CANCEL_PACKET_CHILD";
fn config(secret: u8) -> serde_json::Value {
    let public = SigningKey::from_bytes(&[secret; 32])
        .verifying_key()
        .to_bytes();
    json!({"version":1,"issuer":"fixture-gateway","key_id":digest(&public),"public_key":hex::encode(public),"scope":{"realm":"fixture","public_origin":"https://native.test","workspace":"workspace","origin":"ndb_11111111111111111111111111111111"}})
}
fn packet(secret: u8, change: impl FnOnce(&mut Claims)) -> Vec<u8> {
    let pin: Config = serde_json::from_value(config(secret)).unwrap();
    let now = chrono::Utc::now().timestamp_millis();
    // Deliberately no signed original command. A1 proves ONLY gateway packet
    // integrity, never original authority or permission; no seal API is used.
    let mut c = Claims {
        version: 1,
        issuer: pin.issuer,
        key_id: pin.key_id,
        scope: pin.scope,
        audience: AUDIENCE.into(),
        purpose: PURPOSE.into(),
        nonce: uuid::Uuid::new_v4().to_string(),
        issued_at: now,
        deadline: now + 30_000,
        requester: Requester {
            user: "user".into(),
            principal: "account".into(),
            account: "account".into(),
            person: None,
            membership_generation: 1,
            activity_epoch: 1,
            created_at: "birth".into(),
            provisioned_at: None,
            credential_sha256: digest(b"fixture"),
        },
        original: Original {
            window: "window".into(),
            deployment: "deployment".into(),
            epoch: 1,
            window_key_id: digest(b"key"),
            base_snapshot_digest: digest(b"snapshot"),
            entry_id: "entry".into(),
            received_seq: 1,
            received_at: 0,
            operation: "create_record".into(),
            idempotency_key: "key".into(),
            meaning_digest: digest(b"meaning"),
            intent_digest: None,
            package: "app".into(),
            package_version: "1.0.0".into(),
            install_event_id: "install".into(),
        },
        original_bytes: "{}".into(),
        original_sha256: digest(b"{}"),
    };
    change(&mut c);
    let signature = hex::encode(
        SigningKey::from_bytes(&[secret; 32])
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
fn cancellation_packet_startup_subprocess_matrix() {
    if std::env::var_os(CHILD).is_some() {
        return;
    }
    for case in [
        "disabled",
        "configured",
        "malformed",
        "duplicate",
        "scope",
        "rotation",
    ] {
        let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
        cmd.args([
            "provenance::cancellation_request::tests::cancellation_packet_loader_child",
            "--exact",
            "--nocapture",
        ])
        .env(CHILD, case)
        .env_remove(PIN_ENV);
        match case {
            "disabled" => {}
            "malformed" => {
                cmd.env(PIN_ENV, "{not-config");
            }
            "duplicate" => {
                cmd.env(
                    PIN_ENV,
                    serde_json::to_string(&config(3)).unwrap().replacen(
                        "\"version\":1",
                        "\"version\":1,\"version\":1",
                        1,
                    ),
                );
            }
            "scope" => {
                let mut c = config(3);
                c["scope"]["public_origin"] = json!("https://native.test/path");
                cmd.env(PIN_ENV, c.to_string());
            }
            "rotation" => {
                cmd.env(PIN_ENV, config(4).to_string());
            }
            _ => {
                cmd.env(PIN_ENV, config(3).to_string());
            }
        }
        let out = cmd.output().unwrap();
        assert!(
            out.status.success(),
            "{case}: {}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
}
#[test]
fn cancellation_packet_loader_child() {
    let Ok(case) = std::env::var(CHILD) else {
        return;
    };
    if matches!(case.as_str(), "malformed" | "duplicate" | "scope") {
        assert!(initialize_from_process().is_err());
        assert!(initialize_from_process().is_err());
        assert!(fingerprint().is_err());
        return;
    }
    initialize_from_process().unwrap();
    if case == "disabled" {
        assert_eq!(fingerprint().unwrap(), None);
        assert!(inspect_packet(&packet(3, |_| {})).is_err());
        return;
    }
    let secret = if case == "rotation" { 4 } else { 3 };
    let original = fingerprint().unwrap();
    let threads: Vec<_> = (0..4)
        .map(|_| {
            std::thread::spawn(|| {
                initialize_from_process().unwrap();
                fingerprint().unwrap()
            })
        })
        .collect();
    for t in threads {
        assert_eq!(t.join().unwrap(), original);
    }
    let good = packet(secret, |_| {});
    assert_eq!(
        inspect_packet(&good).unwrap().original_sha256(),
        digest(b"{}")
    );
    assert!(inspect_packet(&packet(if secret == 3 { 4 } else { 3 }, |_| {})).is_err());
    for which in [
        "purpose", "audience", "issuer", "key", "scope", "future", "expired", "long", "nonce",
        "digest", "version",
    ] {
        let bad = packet(secret, |c| match which {
            "purpose" => c.purpose = "quarantine_metadata_read".into(),
            "audience" => c.audience = "native.outbox.service.v1".into(),
            "issuer" => c.issuer = "peer".into(),
            "key" => c.key_id = digest(b"peer"),
            "scope" => c.scope.workspace = "other".into(),
            "future" => {
                c.issued_at += 60_000;
                c.deadline += 60_000;
            }
            "expired" => {
                c.issued_at -= 60_000;
                c.deadline -= 60_000;
            }
            "long" => c.deadline += 1,
            "nonce" => c.nonce = "peer".into(),
            "digest" => c.original_bytes = "changed".into(),
            "version" => c.version = 2,
            _ => unreachable!(),
        });
        assert!(inspect_packet(&bad).is_err(), "{which}");
    }
    let mut v: serde_json::Value = serde_json::from_slice(&good).unwrap();
    v["claims"]["cancel_authorized"] = json!(true);
    assert!(inspect_packet(&serde_jcs::to_vec(&v).unwrap()).is_err());
    let mut v: serde_json::Value = serde_json::from_slice(&good).unwrap();
    v["signature"] = json!("00".repeat(64));
    assert!(inspect_packet(&serde_jcs::to_vec(&v).unwrap()).is_err());
    assert!(inspect_packet(b"status.jwt.token").is_err());
    assert!(inspect_packet(&vec![b' '; MAX_BYTES + 1]).is_err());
    let dup = String::from_utf8(good).unwrap().replacen(
        "\"version\":1",
        "\"version\":1,\"version\":1",
        1,
    );
    assert!(inspect_packet(dup.as_bytes()).is_err());
}
