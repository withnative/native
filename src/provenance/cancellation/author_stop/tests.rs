//! Root-only signed gateway fixtures exercise registry admission/transactions.
//! These are NOT genuine Hosting authentication; the Hosting tests cover that.
use super::*;
use crate::mcp::{
    deployment_read_only::{DeploymentAdmission, DeploymentMutationBarrier, OperationAccess},
    host_writer_pause::WriterPause,
    ToolRegistry,
};
use crate::provenance::cancellation_request::original::tests as original_fixture;
use ed25519_dalek::{Signer, SigningKey};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::sync::Notify;
const CHILD: &str = "NATIVE_TEST_HELD_STOP_CHILD";
#[derive(Default)]
struct Pause {
    entered: Notify,
    release: Notify,
    abort: AtomicBool,
}
tokio::task_local! { static AFTER_STAGE: Arc<Pause>; }
pub(super) async fn after_stage() -> Result<()> {
    if let Ok(p) = AFTER_STAGE.try_with(Arc::clone) {
        p.entered.notify_one();
        p.release.notified().await;
        if p.abort.load(Ordering::SeqCst) {
            return Err(Error::engine("test STOP rollback"));
        }
    }
    Ok(())
}
fn pin(scope: &request::Scope, secret: u8) -> Value {
    let key = SigningKey::from_bytes(&[secret; 32])
        .verifying_key()
        .to_bytes();
    json!({"version":1,"role":wire::ROLE,"issuer":"stop-gateway","key_id":request::digest(&key),"public_key":hex::encode(key),"scope":scope})
}
fn sign(c: wire::Claims) -> Vec<u8> {
    let signature = hex::encode(
        SigningKey::from_bytes(&[8; 32])
            .sign(&wire::signing_message(&c).unwrap())
            .to_bytes(),
    );
    serde_jcs::to_vec(&wire::Packet {
        claims: c,
        signature,
    })
    .unwrap()
}
fn claims(scope: &request::Scope, key: &str, operation: &str) -> wire::Claims {
    claims_with_append(scope, key, operation, None)
}
fn claims_with_append(
    scope: &request::Scope,
    key: &str,
    operation: &str,
    append: Option<&str>,
) -> wire::Claims {
    let (mut e, mut k) = original_fixture::fixture(operation);
    let c = &mut e.call.command;
    c.author.workspace.origin = scope.origin.clone();
    c.idempotency_key = key.into();
    c.original_arguments["idempotency_key"] = json!(key);
    c.prepared_arguments["idempotency_key"] = json!(key);
    if let Some(text) = append {
        c.original_arguments["body_append"] = json!(text);
        c.prepared_arguments["body_append"] = json!(text);
    }
    c.meaning_digest = action_digest(operation, &c.original_arguments);
    let base = json!({"fixture":"base"});
    k.base_snapshot_digest = request::digest(&serde_jcs::to_vec(&base).unwrap());
    original_fixture::resign(&mut e, &k);
    let mut nested = original_fixture::claims(&e, &k);
    nested.scope = scope.clone();
    let original_packet = String::from_utf8(original_fixture::packet(nested.clone())).unwrap();
    // Ordinary serde raw text is intentionally NOT the nested JCS argument.
    let raw_payload = serde_json::to_string(&e).unwrap();
    wire::Claims {
        version: 1,
        issuer: "stop-gateway".into(),
        key_id: pin(scope, 8)["key_id"].as_str().unwrap().into(),
        scope: scope.clone(),
        purpose: wire::PURPOSE.into(),
        audience: wire::AUDIENCE.into(),
        target: "canonical_command".into(),
        nonce: Uuid::new_v4().to_string(),
        issued_at: nested.issued_at,
        deadline: nested.deadline,
        requester: nested.requester,
        credential_sha256: nested.credential_sha256,
        original_packet_sha256: request::digest(original_packet.as_bytes()),
        original_packet,
        holder: wire::HolderBinding {
            raw_sha256: request::digest(raw_payload.as_bytes()),
            payload_bytes: raw_payload.len() as i64,
            raw_payload,
            entry_id: e.call.command.entry_id.clone(),
            window_id: e.call.command.window_id.clone(),
            workspace_id: e.call.command.workspace_id.clone(),
            principal: e.call.command.author.principal.clone(),
            operation: operation.into(),
            idempotency_key: key.into(),
            reservation_digest: crate::provenance::deferred_wire::v2_reservation_digest(&e.call)
                .unwrap(),
            received_seq: e.received_seq,
            ledger_phase: "waiting".into(),
            revision: 1,
            hold: "quarantined".into(),
            deployment_id: k.deployment_id,
            epoch: 1,
            window_phase: "draining".into(),
            base_snapshot: serde_json::to_string(&base).unwrap(),
            base_snapshot_digest: k.base_snapshot_digest,
        },
    }
}
fn lease(
    b: &DeploymentMutationBarrier,
) -> crate::mcp::deployment_read_only::DeploymentPersistenceLease {
    match b
        .for_database("workspace")
        .admit(
            &crate::DeploymentReadOnlyOperation::server("held_command.author_stop"),
            OperationAccess::Mutation,
        )
        .unwrap()
    {
        DeploymentAdmission::Writable(l) => l,
        _ => panic!("actual scoped mutation lease required"),
    }
}
fn gates(dir: &std::path::Path) -> (ToolRegistry, DeploymentMutationBarrier, WriterPause) {
    let b = DeploymentMutationBarrier::default().with_database_freezes(dir);
    let p = WriterPause::new();
    let mut r = ToolRegistry::new();
    r.set_deployment_mutation_barrier(b.clone());
    r.bind_held_stop_pause(p.clone()).unwrap();
    (r, b, p)
}
async fn invoke(
    r: &ToolRegistry,
    b: &DeploymentMutationBarrier,
    p: &WriterPause,
    db: &Db,
    packet: &[u8],
) -> Result<wire::CommittedHeldStop> {
    r.stop_held_command_with_persistence(db.clone(), packet, lease(b), p.try_begin().unwrap())
        .await
}
async fn anchors(db: &Db) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM provenance_local_command_cancellations")
        .fetch_one(db.write_pool())
        .await
        .unwrap()
}
#[tokio::test]
async fn stop_production_loader_and_registry_transaction_matrix() {
    loader_cases(&[
        "disabled",
        "malformed",
        "same_a2b",
        "same_a1",
        "scope",
        "configured",
        "reconcile",
        "rotation",
        "readonly",
        "strict",
    ])
    .await;
}
async fn loader_cases(cases: &[&str]) {
    if std::env::var_os(CHILD).is_some() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stop.db");
    let db = crate::create_database(path.to_str().unwrap())
        .await
        .unwrap();
    let scope = request::Scope {
        realm: "fixture".into(),
        public_origin: "https://native.test".into(),
        workspace: "workspace".into(),
        origin: crate::identity::database_id(&db).await.unwrap(),
    };
    drop(db);
    for &case in cases {
        let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
        cmd.args([
            "provenance::cancellation::author_stop::tests::stop_child",
            "--exact",
            "--nocapture",
        ])
        .env(CHILD, case)
        .env("NATIVE_TEST_HELD_STOP_DB", &path)
        .env_remove(request::PIN_ENV)
        .env_remove(wire::PIN_ENV);
        let mut a2 = original_fixture::config(5);
        a2["scope"] = serde_json::to_value(&scope).unwrap();
        cmd.env(original::PIN_ENV, a2.to_string());
        if case == "same_a1" {
            let mut a1 = pin(&scope, 8);
            a1.as_object_mut().unwrap().remove("role");
            a1["issuer"] = json!("different-A1-issuer");
            a1["scope"]["realm"] = json!("different-A1-realm");
            cmd.env(request::PIN_ENV, a1.to_string());
        }
        if case != "disabled" {
            let mut stop = pin(
                &scope,
                if case == "same_a2b" {
                    5
                } else if case == "rotation" {
                    7
                } else {
                    8
                },
            );
            if case == "scope" {
                stop["scope"]["workspace"] = json!("other");
            }
            cmd.env(
                wire::PIN_ENV,
                if case == "malformed" {
                    "bad".into()
                } else {
                    stop.to_string()
                },
            );
        }
        let out = tokio::task::spawn_blocking(move || cmd.output().unwrap())
            .await
            .unwrap();
        assert!(
            out.status.success(),
            "{case}: {} {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
#[tokio::test]
async fn stop_child() {
    let Ok(case) = std::env::var(CHILD) else {
        return;
    };
    request::initialize_from_process().unwrap();
    original::initialize_from_process().unwrap();
    if matches!(
        case.as_str(),
        "malformed" | "same_a2b" | "same_a1" | "scope"
    ) {
        assert!(initialize().is_err());
        assert!(initialize().is_err());
        return;
    }
    initialize().unwrap();
    if case == "disabled" {
        assert!(fingerprint().unwrap().is_none());
        assert!(preflight(b"{}").is_err());
        return;
    }
    let scope = fingerprint().unwrap().unwrap().scope;
    let db = crate::db::open_existing_database(&std::env::var("NATIVE_TEST_HELD_STOP_DB").unwrap())
        .await
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let (r, b, p) = gates(dir.path());
    if case.starts_with("lookup") {
        lookup_tests::exercise(&case, &scope, &db, &r, &b, &p).await;
        return;
    }
    if case == "rotation" {
        let old = claims(&scope, "cancel-first", "create_record");
        assert!(preflight(&sign(old.clone())).is_err());
        let mut next = old;
        next.key_id = pin(&scope, 7)["key_id"].as_str().unwrap().into();
        let signature = hex::encode(
            SigningKey::from_bytes(&[7; 32])
                .sign(&wire::signing_message(&next).unwrap())
                .to_bytes(),
        );
        let bytes = serde_jcs::to_vec(&wire::Packet {
            claims: next,
            signature,
        })
        .unwrap();
        assert!(matches!(
            invoke(&r, &b, &p, &db, &bytes).await.unwrap(),
            wire::CommittedHeldStop::Cancelled { .. }
        ));
        assert_eq!(anchors(&db).await, 1);
        return;
    }
    if case == "readonly" {
        let readonly = crate::db::open_existing_database_standby_read_only(
            &std::env::var("NATIVE_TEST_HELD_STOP_DB").unwrap(),
        )
        .await
        .unwrap();
        assert!(invoke(
            &r,
            &b,
            &p,
            &readonly,
            &sign(claims(&scope, "readonly", "create_record"))
        )
        .await
        .is_err());
        assert_eq!(anchors(&db).await, 1);
        return;
    }
    if case == "strict" {
        crate::storage_profile::update_portability_policy(
            &db,
            crate::storage_profile::PortabilityPolicyUpdate {
                if_policy_revision: 0,
                enforcement: crate::storage_profile::PortabilityEnforcement::Strict,
                target_profiles: vec![crate::storage_profile::StorageTarget {
                    id: "postgres-server".into(),
                    revision: 5,
                    mode: "network".into(),
                }],
                allow_conversions: vec![],
            },
        )
        .await
        .unwrap();
        let error = invoke(
            &r,
            &b,
            &p,
            &db,
            &sign(claims(&scope, "strict", "create_record")),
        )
        .await
        .unwrap_err();
        assert!(
            error.to_string().contains("strict_portability_blocked"),
            "{error}"
        );
        assert_eq!(anchors(&db).await, 1);
        return;
    }
    if case == "reconcile" {
        let existing: String =
            sqlx::query_scalar("SELECT event_id FROM provenance_local_command_cancellations")
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        let receipt = invoke(
            &r,
            &b,
            &p,
            &db,
            &sign(claims(&scope, "cancel-first", "create_record")),
        )
        .await
        .unwrap();
        assert_eq!(
            receipt,
            wire::CommittedHeldStop::Cancelled { event_id: existing }
        );
        assert_eq!(anchors(&db).await, 1);
        return;
    }

    // Separate STOP signature is indispensable even with a valid A2b proof.
    let c = claims(&scope, "cancel-first", "create_record");
    let packet = sign(c.clone());
    assert!(preflight(&packet).is_ok());
    for change in [
        "purpose",
        "raw",
        "raw_rebind",
        "nested_forgery",
        "requester",
        "deadline",
        "nonce",
        "key_id",
        "revision",
        "scope",
        "signature",
    ] {
        let mut bad = c.clone();
        match change {
            "purpose" => bad.purpose = original::PURPOSE.into(),
            "raw" => bad.holder.raw_payload.push(' '),
            "raw_rebind" => {
                let mut entry: crate::provenance::deferred_wire::EntryV2 =
                    serde_json::from_str(&bad.holder.raw_payload).unwrap();
                entry.call.made_at.reported_unix_ms += 1;
                bad.holder.reservation_digest =
                    crate::provenance::deferred_wire::v2_reservation_digest(&entry.call).unwrap();
                bad.holder.raw_payload = serde_json::to_string(&entry).unwrap();
                bad.holder.raw_sha256 = request::digest(bad.holder.raw_payload.as_bytes());
                bad.holder.payload_bytes = bad.holder.raw_payload.len() as i64;
            }
            "nested_forgery" => {
                let mut nested: original::Packet =
                    serde_json::from_str(&bad.original_packet).unwrap();
                nested.signature = "0".repeat(128);
                bad.original_packet =
                    String::from_utf8(serde_jcs::to_vec(&nested).unwrap()).unwrap();
                bad.original_packet_sha256 = request::digest(bad.original_packet.as_bytes());
            }
            "requester" => bad.requester.account_id = "other".into(),
            "deadline" => bad.deadline = bad.issued_at + 30_001,
            "nonce" => bad.nonce = "invalid".into(),
            "key_id" => bad.key_id = "0".repeat(64),
            "revision" => bad.holder.revision = 0,
            "scope" => bad.scope.origin = "ndb_22222222222222222222222222222222".into(),
            _ => {}
        }
        let mut bytes = sign(bad);
        if change == "signature" {
            let n = bytes.len();
            bytes[n - 3] ^= 1;
        }
        assert!(invoke(&r, &b, &p, &db, &bytes).await.is_err(), "{change}");
        assert_eq!(anchors(&db).await, 0);
    }
    let foreign_db = crate::create_database(":memory:").await.unwrap();
    assert!(invoke(&r, &b, &p, &foreign_db, &packet).await.is_err());
    assert_eq!(anchors(&foreign_db).await, 0);
    // Missing/replaced gates, foreign passes and fleet-only leases cannot write.
    assert!(ToolRegistry::new()
        .stop_held_command_with_persistence(db.clone(), &packet, lease(&b), p.try_begin().unwrap())
        .await
        .is_err());
    assert!(r
        .stop_held_command_with_persistence(
            db.clone(),
            &packet,
            lease(&b),
            WriterPause::new().try_begin().unwrap()
        )
        .await
        .is_err());
    let fleet = match b
        .admit(
            &crate::DeploymentReadOnlyOperation::server("held_command.author_stop"),
            OperationAccess::Mutation,
        )
        .unwrap()
    {
        DeploymentAdmission::Writable(l) => l,
        _ => unreachable!(),
    };
    assert!(r
        .stop_held_command_with_persistence(db.clone(), &packet, fleet, p.try_begin().unwrap())
        .await
        .is_err());
    let other = DeploymentMutationBarrier::default().with_database_freezes(dir.path());
    assert!(r
        .stop_held_command_with_persistence(
            db.clone(),
            &packet,
            lease(&other),
            p.try_begin().unwrap()
        )
        .await
        .is_err());
    let (mut replaced, rb, rp) = gates(dir.path());
    replaced.set_deployment_mutation_barrier(rb.clone());
    assert!(invoke(&replaced, &rb, &rp, &db, &packet).await.is_err());
    assert_eq!(anchors(&db).await, 0);
    // Already-admitted pass remains valid after pause; no new pass may start.
    let pass = p.try_begin().unwrap();
    let admitted = lease(&b);
    p.pause();
    assert!(p.try_begin().is_none());
    // Poll the real freeze once: intent is registered while the retained lease
    // prevents completion. No sleeps or pause-flag revocation of existing work.
    let store = crate::mcp::database_freeze::DatabaseFreezeStore::new(dir.path());
    let freeze = store.freeze("workspace");
    tokio::pin!(freeze);
    assert!(matches!(
        futures::poll!(freeze.as_mut()),
        std::task::Poll::Pending
    ));
    assert!(b
        .for_database("workspace")
        .admit(
            &crate::DeploymentReadOnlyOperation::server("held_command.author_stop"),
            OperationAccess::Mutation
        )
        .is_err());
    let first = r
        .stop_held_command_with_persistence(db.clone(), &packet, admitted, pass)
        .await
        .unwrap();
    p.resume();
    assert_eq!(
        freeze.await.unwrap(),
        crate::mcp::database_freeze::DatabaseFreezeStatus::Frozen
    );
    store.unfreeze("workspace").unwrap();
    assert!(matches!(first, wire::CommittedHeldStop::Cancelled { .. }));
    assert_eq!(anchors(&db).await, 1);
    // A lost response is reconciled with the SAME immutable command, never a new key.
    assert_eq!(
        invoke(
            &r,
            &b,
            &p,
            &db,
            &sign(claims(&scope, "cancel-first", "create_record"))
        )
        .await
        .unwrap(),
        first
    );
    // Explicit test-only deferred constraint failure at COMMIT, not staging.
    sqlx::raw_sql("CREATE TABLE stop_proof_parent(id INTEGER PRIMARY KEY);CREATE TABLE stop_proof_child(id INTEGER REFERENCES stop_proof_parent(id) DEFERRABLE INITIALLY DEFERRED);CREATE TRIGGER stop_commit_failure AFTER INSERT ON provenance_local_command_cancellations BEGIN INSERT INTO stop_proof_child VALUES(99);END;").execute(db.write_pool()).await.unwrap();
    let bytes = sign(claims(&scope, "commit-failure", "create_record"));
    let result = r
        .stop_held_command_observation_with_persistence(
            db.clone(),
            &bytes,
            lease(&b),
            p.try_begin().unwrap(),
        )
        .await;
    assert!(result.is_err());
    assert_eq!(anchors(&db).await, 1);
    sqlx::raw_sql("DROP TRIGGER stop_commit_failure;DROP TABLE stop_proof_child;DROP TABLE stop_proof_parent;").execute(db.write_pool()).await.unwrap();
    // Root-only staging interruption rolls the tombstone back.
    let pause = Arc::new(Pause::default());
    pause.abort.store(true, Ordering::SeqCst);
    let paused = pause.clone();
    let rollback_bytes = sign(claims(&scope, "rollback", "update_record"));
    let task = AFTER_STAGE.scope(paused, invoke(&r, &b, &p, &db, &rollback_bytes));
    tokio::pin!(task);
    tokio::select! {_=&mut task=>panic!("stage must wait"),_=pause.entered.notified()=>{}}
    pause.release.notify_one();
    assert!(task.await.is_err());
    assert_eq!(anchors(&db).await, 1);
    // The post-stage check is independently reached with a valid pre-stage packet.
    let mut short = claims(&scope, "stage-expiry", "create_record");
    short.deadline = chrono::Utc::now().timestamp_millis() + 1500;
    let deadline = short.deadline;
    let bytes = sign(short);
    let pause = Arc::new(Pause::default());
    let task = AFTER_STAGE.scope(pause.clone(), invoke(&r, &b, &p, &db, &bytes));
    tokio::pin!(task);
    tokio::select! {_=&mut task=>panic!("stage must wait"),_=pause.entered.notified()=>{}}
    tokio::time::sleep(std::time::Duration::from_millis(
        (deadline - chrono::Utc::now().timestamp_millis() + 1).max(1) as u64,
    ))
    .await;
    pause.release.notify_one();
    assert!(task.await.is_err());
    assert_eq!(anchors(&db).await, 1);
    // An expired request queued behind an actual writer must fail after BEGIN.
    let mut short = claims(&scope, "blocked-expiry", "create_record");
    short.deadline = chrono::Utc::now().timestamp_millis() + 1500;
    let deadline = short.deadline;
    let bytes = sign(short);
    let blocker = crate::db::begin_write(db.write_pool()).await.unwrap();
    let entered = Arc::new(Notify::new());
    let task = crate::db::with_before_begin_write_notification(
        entered.clone(),
        invoke(&r, &b, &p, &db, &bytes),
    );
    tokio::pin!(task);
    tokio::select! {_=&mut task=>panic!("writer must block"),_=entered.notified()=>{}}
    tokio::time::sleep(std::time::Duration::from_millis(
        (deadline - chrono::Utc::now().timestamp_millis() + 1).max(1) as u64,
    ))
    .await;
    blocker.rollback().await.unwrap();
    assert!(task.await.is_err());
    assert_eq!(anchors(&db).await, 1);
}

#[path = "../lookup/tests.rs"]
mod lookup_tests;
