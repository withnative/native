//! Actual wire-v2 in-place receipt carriage: fast composition, schema reseed,
//! transactional refusal, and the explicit old-profile FULL boundary.
use super::*;
use crate::standby::generation_store::kernel_in_place::{
    InPlaceApplied, InPlaceCrash, IntegrityDepth,
};
use crate::standby::phase_timings::PhaseTimings;
use sqlx::Connection as _;

struct WireV2(Db);
impl AuthorityActHttpClient for WireV2 {
    fn call(&self, _endpoint: String, _bearer: String, body: Value) -> AuthorityCallFuture {
        let db = self.0.clone();
        Box::pin(async move {
            let envelope = &body["params"]["arguments"];
            let args = &envelope["arguments"];
            let result = if envelope["operation"] == "authority_act_head" {
                serde_json::to_value(
                    observe_authority_act_head_advertising(&db, "route-1", true).await?,
                )?
            } else {
                let inventory: Vec<String> =
                    serde_json::from_value(args["blob_inventory"].clone())?;
                serde_json::to_value(
                    observe_authority_act_delta_versioned(
                        &db,
                        "route-1",
                        args["from_exclusive_act"].as_i64().unwrap(),
                        Some(&inventory),
                        args["kernel_delta_version"].as_u64().unwrap() as u32,
                    )
                    .await?,
                )?
            };
            Ok(serde_json::to_vec(
                &json!({"jsonrpc":"2.0","id":body["id"],"result":{"isError":false,"content":[],"structuredContent":result}}),
            )?)
        })
    }
}
struct Warm {
    recovery: Recovery,
    transport: AuthorityActTransport,
    _reader: std::fs::File,
}
impl Warm {
    async fn new(db: &Db) -> Self {
        let recovery = Recovery::snapshot(db).await;
        let origin = observe_authority_act_head(db, "route-1")
            .await
            .unwrap()
            .head()
            .origin_database_id()
            .to_owned();
        let transport = AuthorityActTransport::with_client(
            "https://fixture.example",
            "route-1",
            &origin,
            "test-token",
            Arc::new(WireV2(db.clone())),
        )
        .unwrap();
        transport.head().await.unwrap();
        let reader = recovery
            .store
            .hold_serving_reader(&recovery.base.id)
            .unwrap();
        recovery
            .store
            .record_serving_reader(&recovery.base.id, &observed())
            .unwrap();
        Self {
            recovery,
            transport,
            _reader: reader,
        }
    }
    async fn conn(&self) -> sqlx::SqliteConnection {
        sqlx::SqliteConnection::connect_with(
            &sqlx::sqlite::SqliteConnectOptions::new().filename(&self.recovery.base.snapshot_path),
        )
        .await
        .unwrap()
    }
    async fn delta(&self) -> super::super::kernel_v2_delta::TrustedKernelDelta {
        let mut conn = self.conn().await;
        let from = crate::act::current_act(&mut conn).await.unwrap();
        conn.close().await.unwrap();
        let inventory = kernel_v2::blob_inventory_path(&self.recovery.base.snapshot_path)
            .await
            .unwrap();
        let delta = self.transport.kernel_delta(from, &inventory).await.unwrap();
        assert_eq!(delta.delta().version, 2);
        delta
    }
    async fn apply(
        &self,
        delta: &super::super::kernel_v2_delta::TrustedKernelDelta,
        crash: Option<InPlaceCrash>,
    ) -> PhaseTimings {
        let timing = PhaseTimings::default();
        assert_eq!(
            self.recovery
                .store
                .apply_kernel_delta_in_place(
                    &self.recovery.base,
                    delta,
                    &chrono::Utc::now().to_rfc3339(),
                    &timing,
                    crash
                )
                .await
                .unwrap(),
            InPlaceApplied::Applied
        );
        timing
    }
    async fn state(&self) -> Value {
        let mut conn = self.conn().await;
        let state: (i64,i64,i64,i64,String,String) = sqlx::query_as(
            "SELECT (SELECT next_act FROM act_state),(SELECT COUNT(*) FROM content_events), \
             (SELECT COUNT(*) FROM kernel_standby_apply_receipts), \
             (SELECT MAX(ordinal) FROM kernel_standby_apply_receipts), \
             (SELECT group_concat(chain_sha256,'|') FROM (SELECT chain_sha256 FROM kernel_standby_apply_receipts ORDER BY ordinal)), \
             (SELECT json_group_array(json_object('p',principal_id,'o',operation,'k',operation_key,'q',request_json,'r',receipt_json)) \
              FROM (SELECT * FROM kernel_mcp_write_receipts ORDER BY principal_id,operation,operation_key))"
        ).fetch_one(&mut conn).await.unwrap();
        conn.close().await.unwrap();
        json!({"db":state,"head":self.recovery.store.generation_head(&self.recovery.base.id).unwrap()})
    }
    async fn shape(&self) -> (String, Option<String>, Option<String>) {
        let mut conn = self.conn().await;
        let shape = sqlx::query_as("SELECT kind,projection_sha256,projection_set_sha256 FROM kernel_standby_apply_receipts ORDER BY ordinal DESC LIMIT 1")
            .fetch_one(&mut conn).await.unwrap();
        conn.close().await.unwrap();
        shape
    }
}
async fn noop(db: &Db, id: &str, key: &str) -> Value {
    call(
        db,
        "update_record",
        json!({"id":id,"facets":{},"reason":"receipt only","idempotency_key":key}),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn wire_v2_warm_receipt_only_delta_captures_ledger_without_full_scan() {
    let (db, _) = fixture().await;
    let id = record(&db, "preserved").await;
    kernel::mcp_write_receipts::prepare(&db).await.unwrap();
    let warm = Warm::new(&db).await;
    let mut original = noop(&db, &id, "warm-only").await;
    let delta = warm.delta().await;
    let timing = warm.apply(&delta, None).await;
    assert_eq!(timing.set_path_json()["kind"], "fast");
    assert!(
        timing.set_path_json()["capture"]["touches"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(
        timing.full_scan_evidence().is_none(),
        "warm ledger capture must not scan the full projection"
    );
    let shape = warm.shape().await;
    assert_eq!(shape.0, "delta-set");
    assert!(shape.1.is_none());
    assert!(shape.2.is_some());
    let mut conn = warm.conn().await;
    let raw: String = sqlx::query_scalar(
        "SELECT receipt_json FROM kernel_mcp_write_receipts WHERE operation_key='warm-only'",
    )
    .fetch_one(&mut conn)
    .await
    .unwrap();
    let source_raw: String = sqlx::query_scalar(
        "SELECT receipt_json FROM kernel_mcp_write_receipts WHERE operation_key='warm-only'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(
        raw, source_raw,
        "in-place carriage preserves every stored response byte"
    );
    let mut carried: Value = serde_json::from_str(&raw).unwrap();
    crate::mcp::counter_fence::withhold_receipt_acts("update_record", &mut carried);
    // Registry run correlation is an outward call envelope, not stored
    // outcome content. Compare the entire stable response after that envelope.
    original.as_object_mut().unwrap().remove("run_context");
    assert_eq!(carried, original);
    conn.close().await.unwrap();
    db.close().await;
}

#[tokio::test]
async fn first_lazy_receipt_index_reseeds_dual_then_next_delta_is_warm() {
    let (db, _) = fixture().await;
    let id = record(&db, "preserved").await;
    // The private expression index belongs to content_events, not the ledger.
    sqlx::query("DROP INDEX IF EXISTS idx_kernel_mcp_write_receipt_events")
        .execute(db.write_pool())
        .await
        .unwrap();
    let warm = Warm::new(&db).await;
    noop(&db, &id, "first-schema").await;
    let first = warm.delta().await;
    let timing = warm.apply(&first, None).await;
    assert_eq!(timing.set_path_json()["kind"], "anomaly");
    assert!(timing.full_scan_evidence().is_some());
    let shape = warm.shape().await;
    assert!(
        shape.1.is_some() && shape.2.is_some(),
        "schema anomaly must certify both full digests"
    );
    noop(&db, &id, "next-warm").await;
    let next = warm.delta().await;
    let timing = warm.apply(&next, None).await;
    assert_eq!(timing.set_path_json()["kind"], "fast");
    assert!(timing.full_scan_evidence().is_none());
    db.close().await;
}

#[tokio::test]
async fn late_in_place_failure_rolls_back_domain_body_act_ledger_and_apply_chain() {
    let (db, admin) = fixture().await;
    let id = record(&db, "preserved").await;
    let warm = Warm::new(&db).await;
    noop(&db, &id, "establish-warm").await;
    warm.apply(&warm.delta().await, None).await;
    let before = warm.state().await;
    let current = kernel::read_record_as(&db, &admin, &id)
        .await
        .unwrap()
        .unwrap();
    let body_digest = crate::mcp::tools::lifecycle::body_digest(current.body.as_deref());
    call(&db, "update_record", json!({"id":id,"body_set":"later","if_body_digest":body_digest,"reason":"atomic effect","idempotency_key":"late-failure"})).await.unwrap();
    let delta = warm.delta().await;
    let timing = PhaseTimings::default();
    let error = warm
        .recovery
        .store
        .apply_kernel_delta_in_place(
            &warm.recovery.base,
            &delta,
            &chrono::Utc::now().to_rfc3339(),
            &timing,
            Some(InPlaceCrash::BeforeCommit),
        )
        .await
        .unwrap_err();
    assert!(
        format!("{error:?}").contains("injected_in_place_crash"),
        "{error:?}"
    );
    assert_eq!(warm.state().await, before);
    let reader = crate::db::open_kernel_v2_standby_read_only(
        warm.recovery.base.snapshot_path.to_str().unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(
        kernel::read_record_as(&reader, &admin, &id)
            .await
            .unwrap()
            .unwrap()
            .body
            .as_deref(),
        Some("preserved")
    );
    reader.close().await;
    db.close().await;
}

/// The transaction-owned in-place seams reproduce `apply_with_hook`: folding
/// and certifying a delta on a caller-owned transaction over the serving file
/// writes the next receipt in the chain, and the full integrity check passes.
#[tokio::test]
async fn in_place_fold_seam_matches_apply_with_hook_receipt() {
    use crate::standby::kernel_v2_delta::{
        certify_fold_in_transaction, fold_in_transaction, ApplyMode,
    };
    let (db, _) = fixture().await;
    let id = record(&db, "preserved").await;
    let warm = Warm::new(&db).await;
    noop(&db, &id, "first-seam").await;
    let first = warm.delta().await;
    warm.apply(&first, None).await;
    noop(&db, &id, "second-seam").await;
    let second = warm.delta().await;
    // Seam path: fold + certify on a caller-owned transaction over the
    // serving file, then commit — the only commit in this test.
    let writer = crate::db::open_kernel_v2_in_place_writer(&warm.recovery.base.snapshot_path)
        .await
        .unwrap();
    let mut tx = crate::db::begin_write(writer.write_pool()).await.unwrap();
    let timings = PhaseTimings::default();
    let folded = fold_in_transaction(&mut tx, &second, &timings, ApplyMode::InPlace)
        .await
        .unwrap();
    assert_eq!(
        folded.before().head_act,
        first.delta().head.head_act,
        "fold starts from the previously applied head"
    );
    let certified = certify_fold_in_transaction(&mut tx, &second, folded, &timings)
        .await
        .unwrap();
    let receipt = certified
        .receipt
        .expect("in-place certification writes a receipt");
    assert_eq!(receipt.ordinal, 2, "base 0, first delta 1, seam delta 2");
    assert_eq!(receipt.from_act, first.delta().head.head_act);
    assert_eq!(receipt.to_act, second.delta().head.head_act);
    assert_eq!(receipt.delta_sha256, second.delta().content_sha256);
    assert_eq!(certified.facts.to_act, second.delta().head.head_act);
    tx.commit().await.unwrap();
    writer.close().await;
    // The full integrity check passes over the seam-applied copy, and the
    // serving coordinates match the delta head.
    warm.recovery
        .store
        .check_in_place_integrity(&warm.recovery.base, IntegrityDepth::Full)
        .await
        .unwrap();
    let mut conn = warm.conn().await;
    let after = crate::standby::kernel_v2::coordinates(&mut conn)
        .await
        .unwrap();
    conn.close().await.unwrap();
    assert_eq!(after, second.delta().head.generation);
    db.close().await;
}

#[tokio::test]
async fn corrupted_receipt_projection_fails_full_integrity_without_advancing_any_state() {
    let (db, _) = fixture().await;
    let id = record(&db, "preserved").await;
    let warm = Warm::new(&db).await;
    noop(&db, &id, "corrupt").await;
    warm.apply(&warm.delta().await, None).await;
    let mut conn = warm.conn().await;
    sqlx::query(
        "UPDATE kernel_mcp_write_receipts SET receipt_json='{}' WHERE operation_key='corrupt'",
    )
    .execute(&mut conn)
    .await
    .unwrap();
    conn.close().await.unwrap();
    let before = warm.state().await;
    assert!(warm
        .recovery
        .store
        .check_in_place_integrity(&warm.recovery.base, IntegrityDepth::Full)
        .await
        .is_err());
    assert_eq!(
        warm.state().await,
        before,
        "integrity refusal must not advance head, rows, acts or apply chain"
    );
    db.close().await;
}

// Raw preimage backup stays available. Receipt-profile admission belongs to
// the standby manifest built from that completed owned export.
async fn assert_standby_full_refuses_old_profile(db: &Db) {
    use crate::standby_snapshot::{
        HostedStandbyManifestContext, ProducerBuildIdentity, StandbyConsumerIdentity,
        STANDBY_CONSUMER_CONTRACT,
    };
    let export = match crate::export::export_connected_db(db, None).await {
        Ok(export) => export,
        Err(error) => {
            assert!(
                error.to_string().contains("receipt"),
                "unexpected backup/export refusal: {error}"
            );
            return;
        }
    };
    let identity = observed();
    let consumer = StandbyConsumerIdentity {
        kernel_v2_reader: Default::default(),
        contract: STANDBY_CONSUMER_CONTRACT.into(),
        version: 1,
        platform: identity.platform,
        source_sha: identity.source_sha,
        artifact_sha256: identity.artifact_sha256,
        engine_schema_version: identity.engine_schema_version,
        ddl_sha256: identity.ddl_sha256,
    };
    let context = HostedStandbyManifestContext::new_with_producer(
        "route-1".into(),
        consumer,
        ProducerBuildIdentity::new("a".repeat(40), crate::schema::FROZEN_DDL_SHA256.into())
            .unwrap(),
    )
    .unwrap();
    let result = crate::standby_snapshot::manifest_from_completed_export(
        &export.path(),
        export.size_bytes(),
        crate::standby_snapshot::sha256_bytes(&std::fs::read(export.path()).unwrap()),
        export.captured_at().into(),
        export.snapshot_completed_at().into(),
        context,
    )
    .await;
    export.cleanup().await;
    assert!(
        result.is_err(),
        "an old receipt profile must not acquire a standby manifest"
    );
}

#[tokio::test]
async fn legacy_populated_uncarried_ledger_refuses_head_and_full_export_until_maintenance() {
    let (db, admin) = fixture().await;
    let receipt = json!({"id":"legacy","changed":false}).to_string();
    sqlx::query(
        "INSERT INTO kernel_mcp_write_receipts VALUES(?,'update_record','legacy-profile','{}',?)",
    )
    .bind(admin)
    .bind(&receipt)
    .execute(db.write_pool())
    .await
    .unwrap();
    assert!(observe_authority_act_head(&db, "route-1").await.is_err());
    assert_standby_full_refuses_old_profile(&db).await;
    kernel::mcp_write_receipts::prepare(&db).await.unwrap();
    let head = observe_authority_act_head(&db, "route-1").await.unwrap();
    assert!(head.head().head_act() > 0);
    // A fresh verified FULL is the supported boundary after canonical repair.
    let full = Recovery::snapshot(&db).await;
    assert!(full.base.manifest.kernel_v2.is_some());
    db.close().await;
}

#[tokio::test]
async fn missing_ledger_old_profile_requires_canonical_preparation_and_fresh_full() {
    let (db, _) = fixture().await;
    sqlx::query("DROP TABLE kernel_mcp_write_receipts")
        .execute(db.write_pool())
        .await
        .unwrap();
    assert!(observe_authority_act_head(&db, "route-1").await.is_err());
    assert_standby_full_refuses_old_profile(&db).await;
    kernel::mcp_write_receipts::prepare(&db).await.unwrap();
    let full = Recovery::snapshot(&db).await;
    assert!(full.base.manifest.kernel_v2.is_some());
    db.close().await;
}
