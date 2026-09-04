use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::{to_bytes, Body};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::Router;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::{DateTime, SecondsFormat, Utc};
use ed25519_dalek::{Signer as _, SigningKey};
use native_federation::crypto::{
    canonical_json, sha256_digest, sign_detached, signing_key_from_base64url,
};
use native_federation::relay::Ed25519RelaySigner;
use native_federation::{
    relay_router, PreverifiedSnapshotAuthority, Relay, RelayClock, RelayConfig, RelayLimits,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tower::ServiceExt as _;

const ORIGIN: &str = "http://127.0.0.1:39001";
const FIXTURE_ROOT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../protocol/federation/experimental-jose-hpke-1/fixtures"
);

#[derive(Clone)]
struct TestClock(Arc<Mutex<DateTime<Utc>>>);

impl TestClock {
    fn new(value: &str) -> Self {
        Self(Arc::new(Mutex::new(
            DateTime::parse_from_rfc3339(value)
                .unwrap()
                .with_timezone(&Utc),
        )))
    }

    fn set(&self, value: &str) {
        *self.0.lock().unwrap() = DateTime::parse_from_rfc3339(value)
            .unwrap()
            .with_timezone(&Utc);
    }
}

impl RelayClock for TestClock {
    fn now(&self) -> DateTime<Utc> {
        *self.0.lock().unwrap()
    }
}

struct Harness {
    _directory: TempDir,
    db: std::path::PathBuf,
    relay: Arc<Relay>,
    app: Router,
    clock: TestClock,
    proof: Value,
    limits: RelayLimits,
}

impl Harness {
    async fn new(limits: RelayLimits, mutate_authority: impl FnOnce(&mut Value)) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let db = directory.path().join("relay.db");
        let mut proof: Value = serde_json::from_slice(
            &std::fs::read(format!("{FIXTURE_ROOT}/request-proof-signing.json")).unwrap(),
        )
        .unwrap();
        mutate_authority(&mut proof);
        let authority = Arc::new(
            PreverifiedSnapshotAuthority::from_slice(&serde_json::to_vec(&proof).unwrap()).unwrap(),
        );
        let verification: Value = serde_json::from_slice(
            &std::fs::read(format!("{FIXTURE_ROOT}/verification-keys.json")).unwrap(),
        )
        .unwrap();
        let kid = verification["relay"]["kid"].as_str().unwrap().to_owned();
        let signer = Arc::new(
            Ed25519RelaySigner::new(
                "native-conformance-relay".into(),
                kid,
                signing_key_from_base64url(&fixture_seed("native-relay")).unwrap(),
            )
            .unwrap(),
        );
        let clock = TestClock::new("2026-08-02T09:10:00Z");
        let relay = Relay::open(
            &db,
            RelayConfig {
                public_origin: ORIGIN.into(),
                limits: limits.clone(),
            },
            authority,
            signer,
            Arc::new(clock.clone()),
        )
        .await
        .unwrap();
        let app = relay_router(relay.clone());
        Self {
            _directory: directory,
            db,
            relay,
            app,
            clock,
            proof,
            limits,
        }
    }

    async fn restart(&mut self) {
        self.relay.close().await;
        let authority = Arc::new(
            PreverifiedSnapshotAuthority::from_slice(&serde_json::to_vec(&self.proof).unwrap())
                .unwrap(),
        );
        let verification: Value = fixture("verification-keys.json");
        let signer = Arc::new(
            Ed25519RelaySigner::new(
                "native-conformance-relay".into(),
                verification["relay"]["kid"].as_str().unwrap().into(),
                signing_key_from_base64url(&fixture_seed("native-relay")).unwrap(),
            )
            .unwrap(),
        );
        self.relay = Relay::open(
            &self.db,
            RelayConfig {
                public_origin: ORIGIN.into(),
                limits: self.limits.clone(),
            },
            authority,
            signer,
            Arc::new(self.clock.clone()),
        )
        .await
        .unwrap();
        self.app = relay_router(self.relay.clone());
    }

    async fn request(
        &self,
        path: &str,
        operation: &str,
        signer: &str,
        body: Value,
    ) -> (StatusCode, Value) {
        signed_request(
            self.app.clone(),
            &self.proof,
            path,
            operation,
            signer,
            body,
            self.clock.now(),
        )
        .await
    }
}

#[tokio::test]
async fn fanout_is_idempotent_and_survives_restart() {
    let mut harness = Harness::new(RelayLimits::default(), |_| {}).await;
    let envelope = fixture("positive/envelope-many-recipients.json");
    let body = json!({"operation": "relay.submit", "envelope": envelope});
    let (status, first) = harness
        .request(
            "/v1/envelopes",
            "relay.submit",
            "alice_signing",
            body.clone(),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["results"].as_array().unwrap().len(), 2);
    let (_, duplicate) = harness
        .request(
            "/v1/envelopes",
            "relay.submit",
            "alice_signing",
            body.clone(),
        )
        .await;
    assert_eq!(first, duplicate);

    harness.restart().await;
    let (_, after_restart) = harness
        .request("/v1/envelopes", "relay.submit", "alice_signing", body)
        .await;
    assert_eq!(
        first, after_restart,
        "ids and exact signed receipts changed after restart"
    );
}

#[tokio::test]
async fn request_id_reuse_with_another_body_conflicts_even_with_a_new_nonce() {
    let harness = Harness::new(RelayLimits::default(), |_| {}).await;
    let request_id = uuid::Uuid::new_v4().to_string();
    let first = json!({
        "operation": "relay.submit",
        "envelope": fixture("positive/envelope-one-recipient.json")
    });
    let second = json!({
        "operation": "relay.submit",
        "envelope": fixture("positive/envelope-many-recipients.json")
    });
    let first_nonce = URL_SAFE_NO_PAD.encode([1_u8; 16]);
    let second_nonce = URL_SAFE_NO_PAD.encode([2_u8; 16]);
    assert_eq!(
        signed_request_with_ids(
            harness.app.clone(),
            &harness.proof,
            "/v1/envelopes",
            "relay.submit",
            "alice_signing",
            first,
            harness.clock.now(),
            &request_id,
            &first_nonce,
        )
        .await
        .0,
        StatusCode::OK
    );
    let (status, problem) = signed_request_with_ids(
        harness.app,
        &harness.proof,
        "/v1/envelopes",
        "relay.submit",
        "alice_signing",
        second,
        harness.clock.now(),
        &request_id,
        &second_nonce,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(problem["code"], "idempotency_conflict");
}

#[tokio::test]
async fn concurrent_collectors_do_not_share_a_live_lease_and_expired_lease_redelivers() {
    let mut harness = Harness::new(RelayLimits::default(), |authority| {
        authority["principals"]["bob"]["document"]["fresh_until"] = json!("2026-08-02T09:30:00Z");
    })
    .await;
    let body = json!({
        "operation": "relay.submit",
        "envelope": fixture("positive/envelope-one-recipient.json")
    });
    assert_eq!(
        harness
            .request("/v1/envelopes", "relay.submit", "alice_signing", body)
            .await
            .0,
        StatusCode::OK
    );
    let collect = json!({"operation":"relay.collect","limit":100,"wait_seconds":0});
    let first = signed_request(
        harness.app.clone(),
        &harness.proof,
        "/v1/mailboxes/00000000-0000-4000-8000-000000000201:collect",
        "relay.collect",
        "bob_installation",
        collect.clone(),
        harness.clock.now(),
    );
    let second = signed_request(
        harness.app.clone(),
        &harness.proof,
        "/v1/mailboxes/00000000-0000-4000-8000-000000000201:collect",
        "relay.collect",
        "bob_installation",
        collect.clone(),
        harness.clock.now(),
    );
    let (first, second) = tokio::join!(first, second);
    let counts = [
        first.1["deliveries"].as_array().unwrap().len(),
        second.1["deliveries"].as_array().unwrap().len(),
    ];
    assert!(counts == [1, 0] || counts == [0, 1]);
    let leased = if counts[0] == 1 { &first.1 } else { &second.1 };
    let collected_receipt = leased["deliveries"][0]["collected_receipt"].clone();
    let old_token = leased["deliveries"][0]["lease_token"].clone();

    harness.clock.set("2026-08-02T09:15:00Z");
    harness.restart().await;
    let (_, redelivered) = harness
        .request(
            "/v1/mailboxes/00000000-0000-4000-8000-000000000201:collect",
            "relay.collect",
            "bob_installation",
            collect,
        )
        .await;
    assert_eq!(redelivered["deliveries"][0]["attempt"], 2);
    assert_ne!(redelivered["deliveries"][0]["lease_token"], old_token);
    assert_eq!(
        redelivered["deliveries"][0]["collected_receipt"],
        collected_receipt
    );
}

#[tokio::test]
async fn acknowledgement_retry_is_stable_and_wrong_mailbox_fails_closed() {
    let harness = Harness::new(RelayLimits::default(), add_secondary_bob_installation).await;
    let submit = json!({
        "operation": "relay.submit",
        "envelope": fixture("positive/envelope-many-recipients.json")
    });
    harness
        .request("/v1/envelopes", "relay.submit", "alice_signing", submit)
        .await;
    let (_, collected) = harness
        .request(
            "/v1/mailboxes/00000000-0000-4000-8000-000000000201:collect",
            "relay.collect",
            "bob_installation",
            json!({"operation":"relay.collect","limit":100,"wait_seconds":0}),
        )
        .await;
    let delivery = &collected["deliveries"][0];
    let ack = json!({
        "operation":"relay.acknowledge",
        "acknowledgements":[{
            "delivery_id": delivery["delivery_id"],
            "envelope_id": delivery["envelope"]["envelope"]["envelope_id"],
            "envelope_digest": delivery["envelope_digest"],
            "lease_token": delivery["lease_token"],
            "disposition":"received"
        }]
    });
    let (status, first) = harness
        .request(
            "/v1/mailboxes/00000000-0000-4000-8000-000000000201/acknowledgements",
            "relay.acknowledge",
            "bob_installation",
            ack.clone(),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, retry) = harness
        .request(
            "/v1/mailboxes/00000000-0000-4000-8000-000000000201/acknowledgements",
            "relay.acknowledge",
            "bob_installation",
            ack.clone(),
        )
        .await;
    assert_eq!(first, retry);
    let mut wrong_token = ack.clone();
    wrong_token["acknowledgements"][0]["lease_token"] = json!(URL_SAFE_NO_PAD.encode([9_u8; 32]));
    let (status, problem) = harness
        .request(
            "/v1/mailboxes/00000000-0000-4000-8000-000000000201/acknowledgements",
            "relay.acknowledge",
            "bob_installation",
            wrong_token,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(problem["code"], "forbidden");
    let (status, problem) = harness
        .request(
            "/v1/mailboxes/00000000-0000-4000-8000-000000000299/acknowledgements",
            "relay.acknowledge",
            "bob_secondary_installation",
            ack.clone(),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(problem["code"], "forbidden");
    let (status, problem) = harness
        .request(
            "/v1/mailboxes/00000000-0000-4000-8000-000000000202/acknowledgements",
            "relay.acknowledge",
            "carol_installation",
            ack,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(problem["code"], "forbidden");
}

#[tokio::test]
async fn quotas_revocation_expiry_and_scope_are_explicit() {
    let limits = RelayLimits {
        mailbox_deliveries: 1,
        ..RelayLimits::default()
    };
    let harness = Harness::new(limits, |_| {}).await;
    harness
        .request(
            "/v1/envelopes",
            "relay.submit",
            "alice_signing",
            json!({"operation":"relay.submit","envelope":fixture("positive/envelope-many-recipients.json")}),
        )
        .await;
    let (_, quota) = harness
        .request(
            "/v1/envelopes",
            "relay.submit",
            "alice_signing",
            json!({"operation":"relay.submit","envelope":fixture("positive/envelope-one-recipient.json")}),
        )
        .await;
    assert_eq!(quota["results"][0]["outcome"], "error");
    assert_eq!(quota["results"][0]["code"], "quota_exceeded");
    let (status, problem) = harness
        .request(
            "/v1/envelopes",
            "relay.submit",
            "alice_root",
            json!({"operation":"relay.submit","envelope":fixture("positive/envelope-one-recipient.json")}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(problem["code"], "forbidden");

    harness.clock.set("2026-08-09T09:06:00Z");
    let cleanup = harness.relay.cleanup().await.unwrap();
    assert_eq!(cleanup.expired, 2);
    assert!(cleanup.rate_counters_deleted > 0);

    let revoked = Harness::new(RelayLimits::default(), |authority| {
        authority["principals"]["bob"]["document"]["operational_keys"][1]["status"] =
            json!("revoked");
    })
    .await;
    let (_, response) = revoked
        .request(
            "/v1/envelopes",
            "relay.submit",
            "alice_signing",
            json!({"operation":"relay.submit","envelope":fixture("positive/envelope-many-recipients.json")}),
        )
        .await;
    assert_eq!(response["results"][0]["outcome"], "rejected");
    assert_eq!(response["results"][0]["code"], "key_revoked");
    assert_eq!(response["results"][1]["outcome"], "queued");
}

#[tokio::test]
async fn strict_ijson_rejects_information_losing_and_oversized_values() {
    let harness = Harness::new(RelayLimits::default(), |_| {}).await;
    let mut oversized_object =
        String::from(r#"{"operation":"relay.collect","limit":1,"wait_seconds":0"#);
    for index in 0..257 {
        oversized_object.push_str(&format!(r#", "k{index}":0"#));
    }
    oversized_object.push('}');
    let oversized_array = format!(
        r#"{{"operation":"relay.collect","limit":1,"wait_seconds":0,"extra":[{}]}}"#,
        vec!["0"; 257].join(",")
    );
    let too_deep = format!(
        r#"{{"operation":"relay.collect","limit":1,"wait_seconds":0,"extra":{}null{}}}"#,
        "[".repeat(33),
        "]".repeat(33)
    );
    let mut invalid_unicode =
        br#"{"operation":"relay.collect","limit":1,"wait_seconds":0,"cursor":""#.to_vec();
    invalid_unicode.push(0xff);
    invalid_unicode.extend_from_slice(br#""}"#);
    let cases = vec![
        br#"{"operation":"relay.collect","oper\u0061tion":"relay.collect","limit":1,"wait_seconds":0}"#.to_vec(),
        br#"{"operation":"relay.collect","limit":1.0,"wait_seconds":0}"#.to_vec(),
        br#"{"operation":"relay.collect","limit":9007199254740992,"wait_seconds":0}"#.to_vec(),
        format!(
            r#"{{"operation":"relay.collect","limit":1,"wait_seconds":0,"cursor":"{}"}}"#,
            "x".repeat(4097)
        )
        .into_bytes(),
        oversized_object.into_bytes(),
        oversized_array.into_bytes(),
        too_deep.into_bytes(),
        invalid_unicode,
    ];
    for (index, raw) in cases.into_iter().enumerate() {
        let response = signed_raw_request_with_ids(
            harness.app.clone(),
            &harness.proof,
            "/v1/mailboxes/00000000-0000-4000-8000-000000000201:collect",
            "relay.collect",
            "bob_installation",
            raw,
            harness.clock.now(),
            &uuid::Uuid::new_v4().to_string(),
            &URL_SAFE_NO_PAD.encode(&Sha256::digest(format!("strict:{index}").as_bytes())[..16]),
            "application/vnd.native.federation+json",
            None,
        )
        .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "case {index}");
        assert_eq!(response.body["code"], "invalid_request", "case {index}");
    }

    let duplicate_wrapper = br#"{"operation":"relay.submit","envelope":{"envelope":{},"envel\u006fpe":{},"signature":"x"}}"#.to_vec();
    let response = signed_raw_request_with_ids(
        harness.app.clone(),
        &harness.proof,
        "/v1/envelopes",
        "relay.submit",
        "alice_signing",
        duplicate_wrapper,
        harness.clock.now(),
        &uuid::Uuid::new_v4().to_string(),
        &URL_SAFE_NO_PAD.encode([7_u8; 16]),
        "application/vnd.native.federation+json",
        None,
    )
    .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(response.body["code"], "invalid_request");

    let body = json!({
        "operation":"relay.submit",
        "envelope":fixture("positive/envelope-one-recipient.json")
    });
    let duplicate_extension = serde_json::to_string(&body)
        .unwrap()
        .replace(
            r#""extensions":{}"#,
            r#""extensions":{"native.x":1,"native.\u0078":2}"#,
        )
        .into_bytes();
    let response = signed_raw_request_with_ids(
        harness.app.clone(),
        &harness.proof,
        "/v1/envelopes",
        "relay.submit",
        "alice_signing",
        duplicate_extension,
        harness.clock.now(),
        &uuid::Uuid::new_v4().to_string(),
        &URL_SAFE_NO_PAD.encode([14_u8; 16]),
        "application/vnd.native.federation+json",
        None,
    )
    .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(response.body["code"], "invalid_request");

    let oversized_document = vec![b' '; 1_048_577];
    let response = signed_raw_request_with_ids(
        harness.app,
        &harness.proof,
        "/v1/envelopes",
        "relay.submit",
        "alice_signing",
        oversized_document,
        harness.clock.now(),
        &uuid::Uuid::new_v4().to_string(),
        &URL_SAFE_NO_PAD.encode([8_u8; 16]),
        "application/vnd.native.federation+json",
        None,
    )
    .await;
    assert_eq!(response.status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn envelope_order_dns_and_token_grammars_fail_closed() {
    let harness = Harness::new(RelayLimits::default(), |_| {}).await;
    let base = fixture("positive/envelope-many-recipients.json");
    let mut cases = Vec::new();

    let mut unsorted = base.clone();
    unsorted["envelope"]["recipients"]
        .as_array_mut()
        .unwrap()
        .swap(0, 1);
    cases.push(unsorted);

    for network in [
        "dns:-bad.example",
        "dns:bad..example",
        "dns:bad.example.",
        "dns:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789aa.example",
    ] {
        let mut invalid = base.clone();
        invalid["envelope"]["recipients"][0]["principal"]["network_id"] = json!(network);
        cases.push(invalid);
    }

    let mut capability = base.clone();
    capability["envelope"]["required_capabilities"] = json!(["vendor_feature"]);
    cases.push(capability);
    let mut long_capability = base.clone();
    long_capability["envelope"]["required_capabilities"] =
        json!([format!("native.{}", "x".repeat(90))]);
    cases.push(long_capability);
    let mut too_many_capabilities = base.clone();
    too_many_capabilities["envelope"]["required_capabilities"] = Value::Array(
        (0..33)
            .map(|index| json!(format!("native.x{index}")))
            .collect(),
    );
    cases.push(too_many_capabilities);
    let mut extension = base.clone();
    extension["envelope"]["extensions"] = json!({"native..invalid": true});
    cases.push(extension);
    let mut too_many_extensions = base;
    let extensions = too_many_extensions["envelope"]["extensions"]
        .as_object_mut()
        .unwrap();
    for index in 0..65 {
        extensions.insert(format!("native.x{index}"), Value::Null);
    }
    cases.push(too_many_extensions);

    for (index, envelope) in cases.into_iter().enumerate() {
        let (status, problem) = harness
            .request(
                "/v1/envelopes",
                "relay.submit",
                "alice_signing",
                json!({"operation":"relay.submit","envelope":envelope}),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "case {index}: {problem}");
        assert_eq!(problem["code"], "malformed_envelope", "case {index}");
    }
}

#[tokio::test]
async fn envelope_identity_conflicts_for_disjoint_recipient_sets() {
    let harness = Harness::new(RelayLimits::default(), |_| {}).await;
    let many = fixture("positive/envelope-many-recipients.json");
    let carol_only = subset_and_resign_envelope(&many, 1, &harness.proof);
    let bob_only = subset_and_resign_envelope(&many, 0, &harness.proof);
    assert_eq!(
        harness
            .request(
                "/v1/envelopes",
                "relay.submit",
                "alice_signing",
                json!({"operation":"relay.submit","envelope":carol_only}),
            )
            .await
            .0,
        StatusCode::OK
    );
    let (status, problem) = harness
        .request(
            "/v1/envelopes",
            "relay.submit",
            "alice_signing",
            json!({"operation":"relay.submit","envelope":bob_only}),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(problem["code"], "idempotency_conflict");
}

#[tokio::test]
async fn domain_media_types_and_authenticated_request_ids_are_exact() {
    let harness = Harness::new(RelayLimits::default(), |_| {}).await;
    let request_id = uuid::Uuid::new_v4().to_string();
    let inbound = uuid::Uuid::new_v4().to_string();
    let response = signed_raw_request_with_ids(
        harness.app.clone(),
        &harness.proof,
        "/v1/mailboxes/00000000-0000-4000-8000-000000000201:collect",
        "relay.collect",
        "bob_installation",
        serde_json::to_vec(&json!({"operation":"relay.collect","limit":1,"wait_seconds":0}))
            .unwrap(),
        harness.clock.now(),
        &request_id,
        &URL_SAFE_NO_PAD.encode([11_u8; 16]),
        "application/vnd.native.federation+json",
        Some(&inbound),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(
        response.headers["content-type"],
        "application/vnd.native.federation+json"
    );
    assert_eq!(response.headers["native-request-id"], request_id);

    let error_request_id = uuid::Uuid::new_v4().to_string();
    let response = signed_raw_request_with_ids(
        harness.app.clone(),
        &harness.proof,
        "/v1/mailboxes/00000000-0000-4000-8000-000000000201:collect",
        "relay.collect",
        "bob_installation",
        br#"{"operation":"relay.collect"}"#.to_vec(),
        harness.clock.now(),
        &error_request_id,
        &URL_SAFE_NO_PAD.encode([12_u8; 16]),
        "application/vnd.native.federation+json",
        Some(&inbound),
    )
    .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(response.headers["content-type"], "application/problem+json");
    assert_eq!(response.headers["native-request-id"], error_request_id);
    assert_eq!(response.body["request_id"], error_request_id);

    let response = signed_raw_request_with_ids(
        harness.app,
        &harness.proof,
        "/v1/mailboxes/00000000-0000-4000-8000-000000000201:collect",
        "relay.collect",
        "bob_installation",
        br#"{"operation":"relay.collect","limit":1,"wait_seconds":0}"#.to_vec(),
        harness.clock.now(),
        &uuid::Uuid::new_v4().to_string(),
        &URL_SAFE_NO_PAD.encode([13_u8; 16]),
        "application/json",
        None,
    )
    .await;
    assert_eq!(response.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(response.body["code"], "unsupported_media_type");
}

#[tokio::test]
async fn foreign_native_databases_are_rejected_without_mutation() {
    for table in ["records", "users"] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(format!("{table}.db"));
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute(&format!("CREATE TABLE {table}(id TEXT PRIMARY KEY)"), [])
            .unwrap();
        drop(connection);

        let proof = fixture("request-proof-signing.json");
        let authority = Arc::new(
            PreverifiedSnapshotAuthority::from_slice(&serde_json::to_vec(&proof).unwrap()).unwrap(),
        );
        let verification: Value = fixture("verification-keys.json");
        let signer = Arc::new(
            Ed25519RelaySigner::new(
                "native-conformance-relay".into(),
                verification["relay"]["kid"].as_str().unwrap().into(),
                signing_key_from_base64url(&fixture_seed("native-relay")).unwrap(),
            )
            .unwrap(),
        );
        let error = match Relay::open(
            &path,
            RelayConfig {
                public_origin: ORIGIN.into(),
                limits: RelayLimits::default(),
            },
            authority,
            signer,
            Arc::new(TestClock::new("2026-08-02T09:10:00Z")),
        )
        .await
        {
            Ok(_) => panic!("foreign database was accepted"),
            Err(error) => error,
        };
        assert_eq!(error.code, "invalid_request");
        let connection = rusqlite::Connection::open_with_flags(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let relay_tables: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE name LIKE 'relay_%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(relay_tables, 0, "foreign database was mutated");
    }
}

#[test]
fn preverified_authority_rejects_duplicate_identity_keys() {
    let original = fixture("request-proof-signing.json");

    let mut duplicate_principal = original.clone();
    duplicate_principal["principals"]["alice-copy"] =
        duplicate_principal["principals"]["alice"].clone();
    assert!(PreverifiedSnapshotAuthority::from_slice(
        &serde_json::to_vec(&duplicate_principal).unwrap()
    )
    .is_err());

    let mut duplicate_signing = original.clone();
    let signing =
        duplicate_signing["principals"]["alice"]["document"]["operational_keys"][0].clone();
    duplicate_signing["principals"]["bob"]["document"]["operational_keys"]
        .as_array_mut()
        .unwrap()
        .push(signing);
    assert!(PreverifiedSnapshotAuthority::from_slice(
        &serde_json::to_vec(&duplicate_signing).unwrap()
    )
    .is_err());

    let mut duplicate_encryption = original;
    let encryption =
        duplicate_encryption["principals"]["bob"]["document"]["operational_keys"][1].clone();
    duplicate_encryption["principals"]["carol"]["document"]["operational_keys"]
        .as_array_mut()
        .unwrap()
        .push(encryption);
    assert!(PreverifiedSnapshotAuthority::from_slice(
        &serde_json::to_vec(&duplicate_encryption).unwrap()
    )
    .is_err());
}

fn add_secondary_bob_installation(authority: &mut Value) {
    let key = SigningKey::from_bytes(&[42_u8; 32]);
    let public = URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes());
    let kid = format!(
        "n1.installation.{}",
        URL_SAFE_NO_PAD.encode(Sha256::digest(public.as_bytes()))
    );
    let installation_id = "00000000-0000-4000-8000-000000000299";
    let jwk = json!({
        "kty":"OKP",
        "crv":"Ed25519",
        "x":public,
        "alg":"EdDSA",
        "use":"sig",
        "kid":kid
    });
    authority["principals"]["bob"]["document"]["installations"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "installation_id":installation_id,
            "jwk":jwk,
            "status":"active",
            "endpoint_origin":"https://secondary.bob.example",
            "scopes":["relay.collect","relay.acknowledge"]
        }));
    authority["signers"]["bob_secondary_installation"] = json!({
        "principal":{"network_id":"native","principal_id":"bob00001"},
        "installation_id":installation_id,
        "jwk":{
            "kty":"OKP",
            "crv":"Ed25519",
            "x":public,
            "d":URL_SAFE_NO_PAD.encode(key.to_bytes()),
            "alg":"EdDSA",
            "use":"sig",
            "kid":kid
        }
    });
}

fn subset_and_resign_envelope(wrapper: &Value, recipient_index: usize, proof: &Value) -> Value {
    let mut wrapper = wrapper.clone();
    let recipient = wrapper["envelope"]["recipients"][recipient_index].clone();
    let jwe_recipient = wrapper["envelope"]["jwe"]["recipients"][recipient_index].clone();
    wrapper["envelope"]["recipients"] = json!([recipient]);
    wrapper["envelope"]["jwe"]["recipients"] = json!([jwe_recipient]);
    let mut context = wrapper["envelope"].as_object().unwrap().clone();
    context.remove("jwe");
    context.remove("ciphertext_digest");
    wrapper["envelope"]["jwe"]["aad"] =
        json!(URL_SAFE_NO_PAD.encode(canonical_json(&Value::Object(context)).unwrap()));
    let signer = &proof["signers"]["alice_signing"]["jwk"];
    let key = SigningKey::from_bytes(
        &URL_SAFE_NO_PAD
            .decode(signer["d"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    );
    wrapper["signature"] = json!(sign_detached(
        &wrapper["envelope"],
        &key,
        signer["kid"].as_str().unwrap(),
        "native-envelope+jws",
    )
    .unwrap());
    wrapper
}

fn fixture(relative: &str) -> Value {
    serde_json::from_slice(&std::fs::read(format!("{FIXTURE_ROOT}/{relative}")).unwrap()).unwrap()
}

async fn signed_request(
    app: Router,
    proof_fixture: &Value,
    path: &str,
    operation: &str,
    signer_name: &str,
    body: Value,
    now: DateTime<Utc>,
) -> (StatusCode, Value) {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nonce =
        URL_SAFE_NO_PAD.encode(&Sha256::digest(format!("nonce:{counter}").as_bytes())[..16]);
    signed_request_with_ids(
        app,
        proof_fixture,
        path,
        operation,
        signer_name,
        body,
        now,
        &uuid::Uuid::new_v4().to_string(),
        &nonce,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn signed_request_with_ids(
    app: Router,
    proof_fixture: &Value,
    path: &str,
    operation: &str,
    signer_name: &str,
    body: Value,
    now: DateTime<Utc>,
    request_id: &str,
    nonce: &str,
) -> (StatusCode, Value) {
    let raw = serde_json::to_vec(&body).unwrap();
    let response = signed_raw_request_with_ids(
        app,
        proof_fixture,
        path,
        operation,
        signer_name,
        raw,
        now,
        request_id,
        nonce,
        "application/vnd.native.federation+json",
        None,
    )
    .await;
    (response.status, response.body)
}

struct SignedResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Value,
}

#[allow(clippy::too_many_arguments)]
async fn signed_raw_request_with_ids(
    app: Router,
    proof_fixture: &Value,
    path: &str,
    operation: &str,
    signer_name: &str,
    raw: Vec<u8>,
    now: DateTime<Utc>,
    request_id: &str,
    nonce: &str,
    content_type: &str,
    inbound_request_id: Option<&str>,
) -> SignedResponse {
    let signer = &proof_fixture["signers"][signer_name];
    let payload = json!({
        "protocol_version":"1.0",
        "operation":operation,
        "aud":ORIGIN,
        "principal":signer["principal"],
        "installation_id":signer["installation_id"],
        "request_id":request_id,
        "body_digest":sha256_digest(&raw),
        "created_at":now.to_rfc3339_opts(SecondsFormat::Secs,true),
        "expires_at":(now + chrono::Duration::minutes(5)).to_rfc3339_opts(SecondsFormat::Secs,true),
        "nonce":nonce
    });
    let protected = json!({
        "alg":"EdDSA",
        "kid":signer["jwk"]["kid"],
        "typ":"native-request-proof+jws"
    });
    let protected = URL_SAFE_NO_PAD.encode(canonical_json(&protected).unwrap());
    let encoded_payload = URL_SAFE_NO_PAD.encode(canonical_json(&payload).unwrap());
    let key = SigningKey::from_bytes(
        &URL_SAFE_NO_PAD
            .decode(signer["jwk"]["d"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let signature = key.sign(format!("{protected}.{encoded_payload}").as_bytes());
    let compact = format!(
        "{protected}.{encoded_payload}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    );
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", content_type)
        .header("authorization", format!("NativeJWS {compact}"));
    if let Some(inbound_request_id) = inbound_request_id {
        builder = builder.header("Native-Request-Id", inbound_request_id);
    }
    let response = app
        .oneshot(builder.body(Body::from(raw)).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .unwrap();
    SignedResponse {
        status,
        headers,
        body: serde_json::from_slice(&body).unwrap(),
    }
}

fn fixture_seed(label: &str) -> String {
    let mut output = Vec::new();
    for counter in 0.. {
        output.extend_from_slice(&Sha256::digest(
            format!("native-fed-fixture:{label}:{counter}").as_bytes(),
        ));
        if output.len() >= 32 {
            break;
        }
    }
    URL_SAFE_NO_PAD.encode(&output[..32])
}
