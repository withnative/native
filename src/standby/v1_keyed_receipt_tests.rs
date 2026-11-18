//! A no-op keyed result remains authoritative after a verified standby delta.
use super::act_materialise::apply_authority_act_delta_and_finalize_head;
use super::delta_transport::*;
use super::generation_store::tests::{observed, stage};
use super::*;
use crate::mcp::registry::{Caller, ToolRegistry};
use serde_json::{json, Value};
use std::sync::Arc;

struct Hosted(crate::Db);
impl AuthorityActHttpClient for Hosted {
    fn call(&self, _endpoint: String, _bearer: String, body: Value) -> AuthorityCallFuture {
        let db = self.0.clone();
        Box::pin(async move {
            let from = body["params"]["arguments"]["arguments"]["from_exclusive_act"]
                .as_i64()
                .unwrap();
            let value = observe_authority_act_delta(&db, "route-1", from).await?;
            Ok(serde_json::to_vec(
                &json!({"jsonrpc":"2.0","id":body["id"],
                "result":{"isError":false,"content":[],"structuredContent":value}}),
            )?)
        })
    }
}
fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
    registry
}
async fn call(db: &crate::Db, name: &str, args: Value) -> crate::Result<Value> {
    registry()
        .call(db.clone(), Caller::local(), name, args)
        .await
}

#[tokio::test]
async fn v1_promoted_all_unchanged_multiupdate_replays_without_later_effect() {
    let dir = tempfile::tempdir().unwrap();
    let db = crate::create_database(":memory:").await.unwrap();
    let mut ids = Vec::new();
    for name in ["First", "Second"] {
        ids.push(call(&db, "create_record", json!({"type":"Document","kind":"note","name":name,"body":"preserved","reason":"fixture"}))
            .await.unwrap()["id"].as_str().unwrap().to_owned());
    }
    // Start with a real multi-target write, then snapshot before its keyed no-op.
    call(
        &db,
        "update_record",
        json!({"ids":ids,"maturity":"active","reason":"fixture"}),
    )
    .await
    .unwrap();
    let head = observe_authority_act_head(&db, "route-1").await.unwrap();
    let origin = head.head().origin_database_id();
    let store =
        GenerationStore::open(dir.path().join("replica"), "route-1", Some(origin.into())).unwrap();
    let (snapshot, manifest) = stage(&store, &db, "before-noop").await;
    let base = store
        .install_staged(&snapshot, &manifest, &observed())
        .await
        .unwrap();
    let args = json!({"ids":ids,"maturity":"active","reason":"keyed no-op","idempotency_key":"multi-noop"});
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let original = call(&db, "update_record", args.clone()).await.unwrap();
    assert_eq!(original["changed"], 0);
    assert_eq!(original["unchanged"], 2);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        before
    );
    // Exercise the actual multi-target no-op producer, including the same
    // conformance check that previously rejected output-less attestations.
    let violations = crate::provenance::state_violations(&db).await.unwrap();
    assert!(violations.is_empty(), "{violations:?}");
    let anchors: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM provenance_action_attestations a \
         JOIN provenance_local_attestation_authority l ON l.attestation_id=a.id \
         JOIN control_events c ON c.type='provenance.keyed_command_receipt.v1' \
            AND json_extract(c.payload,'$.attestation_id')=a.id \
         WHERE a.operation='update_record' AND a.command_identity_digest IS NOT NULL \
         AND NOT EXISTS(SELECT 1 FROM provenance_action_outputs o WHERE o.action_attestation_id=a.id)"
    ).fetch_one(db.pool()).await.unwrap();
    assert_eq!(
        anchors, 1,
        "the real no-op producer must persist one recoverable empty anchor"
    );
    let after_noop = observe_authority_act_head(&db, "route-1").await.unwrap();
    assert!(
        after_noop.head().head_act() > head.head().head_act(),
        "a receipt-only key must advance recoverable authority state"
    );
    // A fresh evaluation of the original request would now change both rows.
    call(
        &db,
        "update_record",
        json!({"ids":ids,"maturity":"draft","reason":"later writer"}),
    )
    .await
    .unwrap();
    let transport = AuthorityActTransport::with_client(
        "https://fixture.example",
        "route-1",
        origin,
        "test-token",
        Arc::new(Hosted(db.clone())),
    )
    .unwrap();
    let delta = transport.delta(head.head().head_act()).await.unwrap();
    let scratch = dir.path().join("delta-scratch.db");
    std::fs::copy(&base.snapshot_path, &scratch).unwrap();
    let mut permissions = std::fs::metadata(&scratch).unwrap().permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(0o600);
    }
    #[cfg(not(unix))]
    permissions.set_readonly(false);
    std::fs::set_permissions(&scratch, permissions).unwrap();
    let applied = crate::db::open_existing_database(scratch.to_str().unwrap())
        .await
        .unwrap();
    apply_authority_act_delta_and_finalize_head(&applied, &delta)
        .await
        .unwrap();
    // Publish a verified complete generation from the delta output, then copy
    // it to a disposable replacement canonical DB for the same-key retry.
    let (snapshot, manifest) = stage(&store, &applied, "after-delta").await;
    let promoted = store
        .install_staged(&snapshot, &manifest, &observed())
        .await
        .unwrap();
    let replacement_path = dir.path().join("replacement-canonical.db");
    std::fs::copy(&promoted.snapshot_path, &replacement_path).unwrap();
    let mut permissions = std::fs::metadata(&replacement_path).unwrap().permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(0o600);
    }
    #[cfg(not(unix))]
    permissions.set_readonly(false);
    std::fs::set_permissions(&replacement_path, permissions).unwrap();
    let replacement = crate::db::open_existing_database(replacement_path.to_str().unwrap())
        .await
        .unwrap();
    let violations = crate::provenance::state_violations(&replacement)
        .await
        .unwrap();
    assert!(
        violations.is_empty(),
        "promoted receipt conformance: {violations:?}"
    );
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(replacement.pool())
        .await
        .unwrap();
    assert_eq!(
        call(&replacement, "update_record", args.clone())
            .await
            .unwrap(),
        original
    );
    let mut changed = args;
    changed["reason"] = json!("another intent under the same key");
    assert!(call(&replacement, "update_record", changed).await.is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM content_events")
            .fetch_one(replacement.pool())
            .await
            .unwrap(),
        before
    );
    for id in &ids {
        assert_eq!(
            sqlx::query_scalar::<_, String>("SELECT maturity FROM records WHERE id=?")
                .bind(id)
                .fetch_one(replacement.pool())
                .await
                .unwrap(),
            "draft"
        );
    }
    replacement.close().await;
    applied.close().await;
    db.close().await;
}

#[tokio::test]
async fn v1_receipt_coverage_refuses_missing_and_mismatched_attestation_references() {
    for missing in [true, false] {
        let db = crate::create_database(":memory:").await.unwrap();
        let record = call(
            &db,
            "create_record",
            json!({"type":"Document","kind":"note","name":"Reference proof","reason":"fixture"}),
        )
        .await
        .unwrap();
        let id = record["id"].as_str().unwrap();
        call(
            &db,
            "update_record",
            json!({"ids":[id],"maturity":"active","reason":"fixture"}),
        )
        .await
        .unwrap();
        call(
            &db,
            "update_record",
            json!({"ids":[id],"maturity":"active","reason":"no-op","idempotency_key":"empty"}),
        )
        .await
        .unwrap();
        let attestation: String = if missing {
            uuid::Uuid::new_v4().to_string()
        } else {
            sqlx::query_scalar("SELECT id FROM provenance_action_attestations WHERE operation='update_record' AND command_identity_digest IS NOT NULL").fetch_one(db.pool()).await.unwrap()
        };
        crate::control::append_control_event(
            &db,
            crate::control::NewControlEvent::authored(
                "forged-reference",
                &attestation,
                "different-principal",
                None,
                "adversarial reference fixture",
                crate::control::ControlEventPayload::KeyedCommandReceipt(
                    crate::provenance::KeyedCommandReceiptAnchor {
                        attestation_id: attestation.clone(),
                    },
                ),
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let mut read = db.pool().begin().await.unwrap();
        let error = crate::provenance::verify_keyed_receipt_anchor_coverage_on(&mut read)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains(if missing {
                "missing attestation"
            } else {
                "does not match an empty keyed attestation"
            }),
            "{error}"
        );
        read.rollback().await.unwrap();
        db.close().await;
    }
}
