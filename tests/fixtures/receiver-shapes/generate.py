#!/usr/bin/env python3
"""Capture real engine-95 output in a disposable, Paseo-managed source checkout.

The temporary test calls the producer's existing app fixture and production
registry/export/replay code. It does not implement observation/ordinal writes.
Regenerate from B's final reviewed code before B is allowed to emit its shape.
"""
import argparse
import gzip
import json
import os
from pathlib import Path
import subprocess

REFERENCE = "79570567dc19b5fd1b91191d302a7a573265073f"
HARNESS = r'''

#[tokio::test]
async fn receiver95_capture_real_producer_fixture() {
    let output = std::path::PathBuf::from(std::env::var("NATIVE_RECEIVER95_FIXTURE_OUTPUT").unwrap());
    std::fs::create_dir_all(&output).unwrap();
    let contracts = crate::mcp::executor_prototype::NodeOperationContracts::hosted_kernel_v2().unwrap();
    let mut evidence = serde_json::Map::new();
    for operation in ["update_record", "manage_links.add", "attach_text"] {
        evidence.insert(operation.into(), serde_json::to_value(contracts.holding_contract("records_write", operation).unwrap()).unwrap());
    }
    std::fs::write(output.join("contracts95.json"), serde_json::to_vec_pretty(&evidence).unwrap()).unwrap();
    let v1 = crate::db::create_database(":memory:").await.unwrap();
    let v1_head = crate::standby::delta_transport::observe_authority_act_head(&v1, "route-1").await.unwrap();
    let v1_base = crate::export::export_connected_db(&v1, None).await.unwrap();
    std::fs::copy(v1_base.path(), output.join("v1-base95.sqlite")).unwrap();
    v1_base.cleanup().await;
    crate::store::create_record(&v1, json!({"type":"Document","kind":"note","name":"Real95 v1 change"})).await.unwrap();
    let v1_delta = crate::standby::delta_transport::observe_authority_act_delta(&v1, "route-1", v1_head.head().head_act()).await.unwrap();
    let v1_after = crate::standby::delta_transport::observe_authority_act_head(&v1, "route-1").await.unwrap();
    let v1_empty = crate::standby::delta_transport::observe_authority_act_delta(&v1, "route-1", v1_after.head().head_act()).await.unwrap();
    for (name, delta) in [("v1-delta-response.json",v1_delta),("v1-empty-delta-response.json",v1_empty)] {
        std::fs::write(output.join(name), serde_json::to_vec(&delta).unwrap()).unwrap();
    }
    v1.close().await;
    let (fixture, w, id) = m1_app_writer().await;
    let registration = kernel_writes::register_writer_fixture_owner_for_test(&w.db, Arc::clone(&fixture.owner));
    let (peer, _) = room(&w, &id).await;
    let before = crate::standby::delta_transport::observe_authority_act_head(&w.db, "route-1").await.unwrap();
    let base_act = before.head().head_act();
    let inventory: Vec<String> = sqlx::query_scalar("SELECT sha256 FROM kernel_blobs ORDER BY sha256").fetch_all(w.db.pool()).await.unwrap();
    let base_export = crate::export::export_connected_db(&w.db, None).await.unwrap();
    std::fs::copy(base_export.path(), output.join("base.sqlite")).unwrap();
    base_export.cleanup().await;
    let app_receipt = update(&w, json!({"id":id,"body_append":" receiver fixture", "name":"Real95 app action",
        "observed_basis":"rendered"})).await.unwrap();
    assert!(app_receipt["caller_write_ordinal"].is_number());
    peer.leave().await;
    drop(registration);
    let plain = World { caller: Caller::authenticated("account-a"), ..w.clone() };
    let noop_id = record(&plain, "Document", "note", Some("keyed no-op seed")).await;
    let noop = update(&plain, json!({"id":noop_id,"facets":{},
        "idempotency_key":"receiver95-noop", "observed_basis":"delivered"})).await.unwrap();
    assert_eq!(noop["changed"], false);
    assert!(noop["caller_write_ordinal"].is_number());
    let action_count: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events WHERE type='kernel.app_action_recorded.v1' AND json_type(payload,'$.caller_write_ordinal')='integer'")
        .fetch_one(w.db.pool()).await.unwrap();
    let outcome_count: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events WHERE type='kernel.mcp_write_receipt_recorded.v1' AND caller_write_ordinal IS NOT NULL")
        .fetch_one(w.db.pool()).await.unwrap();
    assert!(action_count > 0 && outcome_count > 0);
    let delta = crate::standby::delta_transport::observe_authority_act_delta_with_inventory(&w.db, "route-1", base_act, Some(&inventory)).await.unwrap();
    std::fs::write(output.join("delta-response.json"), serde_json::to_vec(&delta).unwrap()).unwrap();
    let projection = crate::kernel::projection_dump::dump(&w.db).await.unwrap();
    std::fs::write(output.join("projection.json"), serde_json::to_vec(&projection).unwrap()).unwrap();
    let generation = crate::standby::kernel_v2::coordinates(&mut w.db.pool().acquire().await.unwrap()).await.unwrap();
    let full_export = crate::export::export_connected_db(&w.db, None).await.unwrap();
    std::fs::copy(full_export.path(), output.join("full.sqlite")).unwrap();
    full_export.cleanup().await;
    std::fs::write(output.join("metadata.json"), serde_json::to_vec(&json!({
        "producer":std::env::var("NATIVE_RECEIVER95_SOURCE_REVISION").unwrap(),
        "generation":generation,"base_act":base_act,"record_id":id,
        "principal":fixture.owner.principal,"administrator":w.admin,
        "app_receipt":app_receipt,"noop_receipt":noop,
        "action_facts_with_ordinal":action_count,"keyed_outcomes_with_ordinal":outcome_count
    })).unwrap()).unwrap();
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--revision", default=REFERENCE)
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    root = args.source_root.resolve(strict=True)
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    if revision != args.revision:
        raise SystemExit(f"source revision {revision} is not requested {args.revision}")
    if root == Path(__file__).resolve().parents[3]:
        raise SystemExit("use an explicitly managed disposable producer checkout")
    module = root / "src/coedit/kernel_writer_tests.rs"
    original = module.read_bytes()
    origin_module = root / "src/v1_import/tests.rs"
    original_origin = origin_module.read_bytes()
    if b"receiver95_capture_real_producer_fixture" in original:
        raise SystemExit("producer fixture harness is already present")
    raw = root / "target/receiver95-fixture"
    env = dict(os.environ, RUST_MIN_STACK="67108864", NATIVE_RECEIVER95_FIXTURE_OUTPUT=str(raw),
               NATIVE_RECEIVER95_SOURCE_REVISION=revision, NATIVE_CE_GIT_SHA=revision)
    try:
        module.write_bytes(original + HARNESS.encode())
        # The reusable import fixture's synthetic "test-origin" is deliberately
        # invalid for standby. Supply a valid fixture input before import;
        # never rewrite canonical exported event payloads or provenance.
        origin_module.write_bytes(original_origin.replace(
            b"INSERT INTO database_identity VALUES(1,'test-origin')",
            b"INSERT INTO database_identity VALUES(1,'ndb_11111111111141118111111111111111')"))
        subprocess.run(["cargo", "test", "-p", "native-ce", "--lib", "--features", "v2-kernel-probe",
                        "receiver95_capture_real_producer_fixture", "--", "--nocapture"],
                       cwd=root, env=env, check=True)
        metadata = json.loads((raw / "metadata.json").read_text())
        if metadata["producer"] != revision:
            raise SystemExit("fixture producer mismatch")
        args.output.mkdir(parents=True, exist_ok=True)
        for name in ["base.sqlite", "full.sqlite", "delta-response.json", "projection.json", "v1-delta-response.json", "v1-empty-delta-response.json", "v1-base95.sqlite"]:
            (args.output / f"{name}.gz").write_bytes(gzip.compress((raw / name).read_bytes(), mtime=0))
        (args.output / "contracts95.json").write_bytes((raw / "contracts95.json").read_bytes())
        (args.output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    finally:
        module.write_bytes(original)
        origin_module.write_bytes(original_origin)


if __name__ == "__main__":
    main()
