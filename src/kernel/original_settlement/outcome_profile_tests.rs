//! Provider qualification using the real collector, fold and ReplaySavepoint.
//! This is a faithful owner harness, not the node's publication/ACK adapter.
use super::*;
use crate::kernel::{
    original_settlement::{self as settlement, tests::*},
    working_undo::{self, with_handle},
};
use sqlx::Connection;

#[tokio::test]
async fn outcome_capability_native_profiles_empty_legacy_and_tampering() {
    for typed in [false, true] {
        for version in [94, 95] {
            let (db, _) =
                crate::kernel::create_v2_database(":memory:", "account", "Profiles", "acct:owner")
                    .await
                    .unwrap();
            if !typed {
                sqlx::query("DROP TABLE IF EXISTS kernel_mcp_write_receipts")
                    .execute(db.write_pool())
                    .await
                    .unwrap();
            }
            if typed {
                settlement::prepare(&db, true).await.unwrap();
            }
            if version == 95 {
                crate::standby::shapes::tests::upgrade_fixture_to_95(&db).await;
            }
            let mut conn = db.write_pool().acquire().await.unwrap();
            assert!(verified_outcomes_on(&mut conn).await.is_err());
            let mut tx = conn.begin().await.unwrap();
            {
                let mut cap = verified_outcomes_on(&mut tx).await.unwrap();
                assert_eq!(
                    cap.profile(),
                    if typed {
                        OutcomeProfile::Typed2
                    } else {
                        OutcomeProfile::Legacy1
                    }
                );
                match cap
                    .lookup("actor", "update_record", "absent")
                    .await
                    .unwrap()
                {
                    OutcomeLookup::Legacy(None) if !typed => {}
                    OutcomeLookup::Typed(KeyedOutcome::Absent) if typed => {}
                    _ => panic!("no fabricated receipt or native refs"),
                }
            }
            tx.rollback().await.unwrap();
            sqlx::query("PRAGMA recursive_triggers=ON")
                .execute(&mut *conn)
                .await
                .unwrap();
            let mut tx = conn.begin().await.unwrap();
            assert!(matches!(
                verified_outcomes_on(&mut tx).await,
                Err(OutcomeProfileError::WrongConnectionMode)
            ));
            tx.rollback().await.unwrap();
            sqlx::query("PRAGMA recursive_triggers=OFF")
                .execute(&mut *conn)
                .await
                .unwrap();
            let mut tx = conn.begin().await.unwrap();
            sqlx::query(if typed {
                "DROP TRIGGER kernel_mcp_terminal_no_replace"
            } else {
                "CREATE TABLE IF NOT EXISTS kernel_mcp_write_receipts(principal_id TEXT)"
            })
            .execute(&mut *tx)
            .await
            .unwrap();
            assert!(verified_outcomes_on(&mut tx).await.is_err());
            tx.rollback().await.unwrap();
        }
    }
}

#[tokio::test]
async fn outcome_capability_real_owned_capture_fold_terminal_and_single_cleanup() {
    use crate::standby::kernel_v2_delta::{self, TrustedKernelDelta, WorkingFold};
    let w = world().await;
    let seed = crate::kernel::create_record_as(&w.db, &w.admin, &w.home)
        .await
        .unwrap();
    let before = kernel_v2::coordinates(&mut w.db.pool().acquire().await.unwrap())
        .await
        .unwrap();
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("working.db");
    sqlx::query("VACUUM main INTO ?")
        .bind(path.to_str().unwrap())
        .execute(w.db.write_pool())
        .await
        .unwrap();
    let request = create(&w, "owned-terminal");
    settlement::settle(&w.db, &route(&w), request.clone())
        .await
        .unwrap();
    let mut source = w.db.pool().begin().await.unwrap();
    let cut = kernel_v2_delta::cut(&mut source, before.head_act, &[])
        .await
        .unwrap();
    source.rollback().await.unwrap();
    let trusted = TrustedKernelDelta::assume_trusted_for_test(cut).unwrap();
    let db = crate::db::open_existing_v2_file(path.to_str().unwrap())
        .await
        .unwrap();
    let mut conn = db.write_pool().acquire().await.unwrap();
    let mut tx = conn.begin().await.unwrap();
    let owner = WorkingKernelSchema::from_fresh_native(&mut tx)
        .await
        .unwrap();
    for (_, ddl) in crate::kernel::working_undo_schema::WORKING_METADATA {
        sqlx::query(ddl).execute(&mut *tx).await.unwrap();
    }
    tx.commit().await.unwrap();
    let collector = with_handle(&mut conn, |raw| {
        let keys = working_undo::registered_primary_keys(raw)
            .map_err(|e| crate::Error::engine(e.to_string()))?;
        Collector::install(raw, &keys, 100000, 16777216)
            .map_err(|e| crate::Error::engine(e.to_string()))
    })
    .await
    .unwrap();
    let mut tx = conn.begin().await.unwrap();
    // Only genuine accepted native fold, capture disabled. No test projection insert.
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT enabled FROM working_undo_control")
            .fetch_one(&mut *tx)
            .await
            .unwrap(),
        0
    );
    WorkingFold::new(&mut tx, &collector, &owner, &before, &w.origin)
        .await
        .unwrap()
        .fold(
            &trusted,
            &crate::standby::phase_timings::PhaseTimings::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM working_undo")
            .fetch_one(&mut *tx)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM working_undo_boundaries")
            .fetch_one(&mut *tx)
            .await
            .unwrap(),
        0
    );
    // Real claim, then acknowledged manual SAVEPOINT (SQLx root depth remains one).
    let scope = crate::mcp::kernel_v2::writes::replay::ReplaySavepoint::claim();
    sqlx::query(&format!("SAVEPOINT {}", scope.name()))
        .execute(&mut *tx)
        .await
        .unwrap();
    with_handle(&mut tx, |raw| {
        collector
            .proposal(raw, "proposal")
            .map_err(|e| crate::Error::engine(e.to_string()))
    })
    .await
    .unwrap();
    sqlx::query("UPDATE kernel_records SET created_at='speculative' WHERE id=?")
        .bind(&seed)
        .execute(&mut *tx)
        .await
        .unwrap();
    // Populated real capture must qualify; coordinates_on would reject here.
    assert!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM working_undo")
            .fetch_one(&mut *tx)
            .await
            .unwrap()
            > 0
    );
    let typed = {
        let mut cap = verified_working_outcomes_on(&owner, &mut tx, &collector)
            .await
            .unwrap();
        assert_eq!(cap.profile(), OutcomeProfile::Typed2);
        let outcome = cap
            .lookup(&w.principal, "create_record", "owned-terminal")
            .await
            .unwrap();
        outcome
            .terminal_conflict()
            .expect("typed Terminal, no Exact/Absent/string")
    };
    // The supported proposal changed only a record. Capture trigger bytes stay
    // compatible with existing working copies; inverse preflight separately
    // refuses any terminal images from unsupported direct DML.
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM working_undo WHERE t='kernel_mcp_write_receipts' OR (t='content_events' AND (before_image LIKE '%6B65726E656C2E6D63705F77726974655F66656E6365642E7631%' OR after_image LIKE '%6B65726E656C2E6D63705F77726974655F66656E6365642E7631%'))").fetch_one(&mut *tx).await.unwrap(),0);
    // Borrow dropped first. Outer owner alone acknowledges exactly one cleanup.
    scope.rollback_abandoned(&mut tx).await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM working_undo_boundaries")
            .fetch_one(&mut *tx)
            .await
            .unwrap(),
        0
    );
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM kernel_mcp_write_receipts WHERE outcome_kind='unapplied_terminal'").fetch_one(&mut *tx).await.unwrap(),1);
    let KeyedOutcome::Terminal { fact, .. } =
        settlement::lookup_outcome_on(&mut tx, &w.principal, "create_record", "owned-terminal")
            .await
            .unwrap()
    else {
        panic!("terminal lost")
    };
    assert_eq!(typed.fence_id, fact.terminal.fence_id);
    // A later legitimate neighboring proposal can be undone without touching terminals.
    with_handle(&mut tx, |raw| {
        collector
            .proposal(raw, "neighbor")
            .map_err(|e| crate::Error::engine(e.to_string()))?;
        raw.execute("UPDATE kernel_records SET created_at='neighbor'", [])
            .map_err(|e| crate::Error::engine(e.to_string()))?;
        collector
            .finish_proposal(raw, "neighbor")
            .map_err(|e| crate::Error::engine(e.to_string()))?;
        collector
            .undo(raw, "neighbor")
            .map_err(|e| crate::Error::engine(e.to_string()))
    })
    .await
    .unwrap();
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM kernel_mcp_write_receipts WHERE outcome_kind='unapplied_terminal'").fetch_one(&mut *tx).await.unwrap(),1);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM content_events WHERE type='kernel.mcp_write_fenced.v1'"
        )
        .fetch_one(&mut *tx)
        .await
        .unwrap(),
        1
    );
    // Wrong owner mode is refused without changing the PRAGMA.
    // Guard presence while suppression is active grants no capability.
    with_handle(&mut tx, |raw| {
        raw.set_db_config(
            rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER,
            false,
        )
        .unwrap();
        Ok(())
    })
    .await
    .unwrap();
    assert!(matches!(
        verified_working_outcomes_on(&owner, &mut tx, &collector).await,
        Err(OutcomeProfileError::WrongConnectionMode)
    ));
    with_handle(&mut tx, |raw| {
        raw.set_db_config(
            rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER,
            true,
        )
        .unwrap();
        Ok(())
    })
    .await
    .unwrap();
    {
        let mut nested = tx.begin().await.unwrap();
        assert!(matches!(
            verified_working_outcomes_on(&owner, &mut nested, &collector).await,
            Err(OutcomeProfileError::TransactionRequired)
        ));
        nested.rollback().await.unwrap();
    }
    sqlx::query("PRAGMA recursive_triggers=OFF")
        .execute(&mut *tx)
        .await
        .unwrap();
    assert!(matches!(
        verified_working_outcomes_on(&owner, &mut tx, &collector).await,
        Err(OutcomeProfileError::WrongConnectionMode)
    ));
    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn outcome_capability_legacy_tuple_stays_byte_exact_without_native_refs() {
    let (db, _) =
        crate::kernel::create_v2_database(":memory:", "account", "Legacy tuple", "acct:owner")
            .await
            .unwrap();
    let request = " legacy request bytes ";
    let receipt = " legacy receipt bytes ";
    sqlx::query(crate::kernel::MCP_WRITE_RECEIPTS_DDL)
        .execute(db.write_pool())
        .await
        .unwrap();
    sqlx::query("INSERT INTO kernel_mcp_write_receipts VALUES('actor','update_record','key',?,?)")
        .bind(request)
        .bind(receipt)
        .execute(db.write_pool())
        .await
        .unwrap();
    let mut tx = db.write_pool().begin().await.unwrap();
    let mut cap = verified_outcomes_on(&mut tx).await.unwrap();
    let OutcomeLookup::Legacy(Some((actual_request, actual_receipt))) =
        cap.lookup("actor", "update_record", "key").await.unwrap()
    else {
        panic!("must remain legacy")
    };
    assert_eq!(actual_request, request);
    assert_eq!(actual_receipt, receipt);
    drop(cap);
    tx.rollback().await.unwrap();
}
#[tokio::test]
async fn outcome_capability_partial_typed_coverage_never_falls_back() {
    let w = world().await;
    settlement::settle(&w.db, &route(&w), create(&w, "coverage"))
        .await
        .unwrap();
    let mut tx = w.db.write_pool().begin().await.unwrap();
    // Deliberate storage-corruption fixture: ordinary SQL correctly refuses
    // this append-only edit. Restore trigger enforcement before qualification.
    with_handle(&mut tx, |raw| {
        use rusqlite::config::DbConfig;
        raw.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)
            .unwrap();
        let corrupt = raw.execute(
            "UPDATE content_events SET payload='{}' WHERE type='kernel.mcp_write_fenced.v1'",
            [],
        );
        raw.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, true)
            .unwrap();
        corrupt.map_err(|e| crate::Error::engine(e.to_string()))?;
        Ok(())
    })
    .await
    .unwrap();
    // An earlier readiness failure is also fail-closed.
    if let Ok(mut cap) = verified_outcomes_on(&mut tx).await {
        assert!(matches!(
            cap.lookup(&w.principal, "create_record", "coverage").await,
            Err(OutcomeProfileError::CoverageUnverified { .. })
        ));
    }
    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn outcome_capability_populated_working_profiles_include_empty_legacy_and_native95() {
    for (version, typed, empty) in [
        (94, false, false),
        (94, false, true),
        (95, false, false),
        (95, false, true),
        (94, true, false),
        (95, true, false),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("owned-working.db");
        let (db, actor) = crate::kernel::create_v2_database(
            path.to_str().unwrap(),
            "account",
            "Working profiles",
            "acct:owner",
        )
        .await
        .unwrap();
        let record = crate::kernel::create_record_as(&db, &actor, crate::events::KERNEL_ROOT_ID)
            .await
            .unwrap();
        if typed {
            settlement::prepare(&db, true).await.unwrap();
        }
        if version == 95 {
            shapes::tests::upgrade_fixture_to_95(&db).await;
        }
        let mut conn = db.write_pool().acquire().await.unwrap();
        let mut tx = conn.begin().await.unwrap();
        let verified_owner = WorkingKernelSchema::from_fresh_native(&mut tx)
            .await
            .unwrap();
        if empty {
            sqlx::query("DROP TABLE kernel_mcp_write_receipts")
                .execute(&mut *tx)
                .await
                .unwrap();
        }
        for (_, ddl) in crate::kernel::working_undo_schema::WORKING_METADATA {
            sqlx::query(ddl).execute(&mut *tx).await.unwrap();
        }
        tx.commit().await.unwrap();
        let collector = with_handle(&mut conn, |raw| {
            let keys = working_undo::registered_primary_keys(raw)
                .map_err(|e| crate::Error::engine(e.to_string()))?;
            Collector::install(raw, &keys, 100000, 16777216)
                .map_err(|e| crate::Error::engine(e.to_string()))
        })
        .await
        .unwrap();
        let mut tx = conn.begin().await.unwrap();
        // Genuine retained-owner inventory admission, BEFORE capture. Empty W
        // gains no coordinate/effect authority from the outcome helper.
        let owner = if empty {
            WorkingKernelSchema::from_retained_native(&verified_owner, &mut tx, &collector)
                .await
                .unwrap()
        } else {
            verified_owner
        };
        with_handle(&mut tx, |raw| {
            collector
                .proposal(raw, "profiles")
                .map_err(|e| crate::Error::engine(e.to_string()))
        })
        .await
        .unwrap();
        sqlx::query("UPDATE kernel_records SET created_at='captured proposal' WHERE id=?")
            .bind(&record)
            .execute(&mut *tx)
            .await
            .unwrap();
        let before: i64 = sqlx::query_scalar("SELECT count(*) FROM working_undo")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert!(before > 0);
        {
            let mut cap = verified_working_outcomes_on(&owner, &mut tx, &collector)
                .await
                .unwrap();
            assert_eq!(
                cap.profile(),
                if typed {
                    OutcomeProfile::Typed2
                } else {
                    OutcomeProfile::Legacy1
                },
                "{version} typed={typed} empty={empty}"
            );
            match cap.lookup(&actor, "update_record", "unused").await.unwrap() {
                OutcomeLookup::Legacy(None) if !typed => {}
                OutcomeLookup::Typed(KeyedOutcome::Absent) if typed => {}
                _ => panic!("profile must drive exhaustive handling"),
            }
        }
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM working_undo")
                .fetch_one(&mut *tx)
                .await
                .unwrap(),
            before,
            "verification adds no captured rows"
        );
        if empty {
            assert!(!sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='kernel_mcp_write_receipts')").fetch_one(&mut *tx).await.unwrap(),"no lazy DDL");
        }
        tx.rollback().await.unwrap();
        // Changing PRAGMA mode outside the root must not be corrected by a probe.
        sqlx::query("PRAGMA foreign_keys=OFF")
            .execute(&mut *conn)
            .await
            .unwrap();
        let mut tx = conn.begin().await.unwrap();
        assert!(matches!(
            verified_working_outcomes_on(&owner, &mut tx, &collector).await,
            Err(OutcomeProfileError::WrongConnectionMode)
        ));
        tx.rollback().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("PRAGMA foreign_keys")
                .fetch_one(&mut *conn)
                .await
                .unwrap(),
            0
        );
        drop(conn);
        db.close().await;
    }
}

/// Operational rollout: existing primary-reader equality is unchanged. The
/// deployed artifact must be confirmed format-2-capable before preparation.
#[tokio::test]
async fn outcome_capability_operational_export_and_receiver_need_no_negotiation() {
    use crate::standby_snapshot::{
        HostedStandbyManifestContext, ProducerBuildIdentity, StandbyConsumerIdentity,
        STANDBY_CONSUMER_CONTRACT,
    };
    let w = world().await;
    settlement::settle(&w.db, &route(&w), create(&w, "operational-fence"))
        .await
        .unwrap();
    // Reuse the deterministic identity fixture used by snapshot admission tests.
    // This qualifies the export/receiver gates, not the executing test artifact.
    let observed = crate::standby::generation_store::tests::observed();
    let consumer = StandbyConsumerIdentity {
        kernel_v2_reader: observed.kernel_v2_reader.clone(),
        contract: STANDBY_CONSUMER_CONTRACT.into(),
        version: 1,
        platform: observed.platform,
        source_sha: observed.source_sha.clone(),
        artifact_sha256: observed.artifact_sha256.clone(),
        engine_schema_version: observed.engine_schema_version,
        ddl_sha256: observed.ddl_sha256.clone(),
    };
    assert_eq!(
        consumer.kernel_v2_reader.reader_format, 1,
        "do not globally flip the legacy primary"
    );
    // This is the unchanged hosted export gate at standby_snapshot.rs:568.
    let context = HostedStandbyManifestContext::for_engine_with_producer(
        "test-db".into(),
        consumer.clone(),
        ProducerBuildIdentity::new("a".repeat(40), crate::schema::FROZEN_DDL_SHA256.into())
            .unwrap(),
        true,
    )
    .unwrap();
    let export = crate::export::export_connected_db(&w.db, None)
        .await
        .unwrap();
    let bytes = std::fs::read(export.path()).unwrap();
    let manifest = crate::standby_snapshot::manifest_from_completed_export(
        &export.path(),
        bytes.len() as u64,
        crate::standby_snapshot::sha256_bytes(&bytes),
        export.captured_at().into(),
        export.snapshot_completed_at().into(),
        context,
    )
    .await
    .unwrap();
    assert_eq!(manifest.kernel_v2.as_ref().unwrap().reader_format, 2);
    assert_eq!(manifest.consumer, consumer);
    manifest.validate_observed_installed(&observed).unwrap();
    let json = serde_json::to_value(&manifest).unwrap();
    assert!(json.get("reader_negotiation_mode").is_none());
    assert!(json.get("selected_kernel_v2_reader").is_none());
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("receiver");
    let store = crate::standby::GenerationStore::open(
        &root,
        "test-db",
        Some(manifest.origin_database_id.clone()),
    )
    .unwrap();
    let stage = store.staging_dir().join("full.db");
    let metadata = store.staging_dir().join("full.json");
    std::fs::write(&stage, &bytes).unwrap();
    std::fs::write(&metadata, manifest.canonical_json().unwrap()).unwrap();
    let installed = store
        .install_staged(&stage, &metadata, &observed)
        .await
        .unwrap();
    assert_eq!(
        installed.manifest.kernel_v2.as_ref().unwrap().reader_format,
        2
    );
    let mut conn = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&installed.snapshot_path)
            .read_only(true)
            .immutable(true),
    )
    .await
    .unwrap();
    assert!(matches!(
        settlement::lookup_outcome_on(
            &mut conn,
            &w.principal,
            "create_record",
            "operational-fence"
        )
        .await
        .unwrap(),
        KeyedOutcome::Terminal { .. }
    ));
    conn.close().await.unwrap();
    drop(store);
    let store = crate::standby::GenerationStore::open(
        &root,
        "test-db",
        Some(manifest.origin_database_id.clone()),
    )
    .unwrap();
    assert!(matches!(
        store.activate_for_startup(&observed).await.unwrap(),
        crate::standby::StandbyStartupOutcome::Serving(_)
    ));
    // The pre-settlement a42acba6 registry supports only these reader-1
    // native shapes. Its advertised closed set cannot accept the typed file.
    let older=serde_json::json!({"version":1,"shapes":[shapes::v2(1,shapes::V2_94).unwrap().shape(),shapes::v2(1,shapes::V2_95).unwrap().shape()]}).to_string();
    let typed = shapes::v2(2, &manifest.kernel_v2.as_ref().unwrap().schema_sha256)
        .unwrap()
        .shape();
    assert!(shapes::negotiate(&typed, Some(&older)).is_err());
    assert_ne!(typed.schema_sha256, shapes::V2_94);
    assert_ne!(typed.schema_sha256, shapes::V2_95);
    let mut old_artifact = observed.clone();
    old_artifact.source_sha = "a42acba6d5fa65c6935408a250b2f6ce01d3a840".into();
    old_artifact.artifact_sha256 = "e".repeat(64);
    assert!(manifest.validate_observed_installed(&old_artifact).is_err());
    export.cleanup().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn original_settlement_reader_schema_evidence() {
    let (db, _) =
        crate::kernel::create_v2_database(":memory:", "account", "Reader evidence", "acct:owner")
            .await
            .unwrap();
    let legacy = kernel_v2::coordinates(&mut db.pool().acquire().await.unwrap())
        .await
        .unwrap();
    assert_eq!(legacy.reader_format, 1);
    assert_eq!(legacy.schema_sha256, crate::standby::shapes::V2_94);
    assert!(crate::kernel::original_settlement::prepare(&db, false)
        .await
        .is_err());
    assert_eq!(
        kernel_v2::coordinates(&mut db.pool().acquire().await.unwrap())
            .await
            .unwrap(),
        legacy
    );
    crate::kernel::original_settlement::prepare(&db, true)
        .await
        .unwrap();
    let before = kernel_v2::coordinates(&mut db.pool().acquire().await.unwrap())
        .await
        .unwrap();
    assert_eq!(before.reader_format, 2);
    assert_eq!(before.schema_sha256, crate::standby::shapes::V2_TERMINAL_94);
    crate::standby::shapes::tests::upgrade_fixture_to_95(&db).await;
    let after = kernel_v2::coordinates(&mut db.pool().acquire().await.unwrap())
        .await
        .unwrap();
    assert_eq!(after.reader_format, 2);
    assert_eq!(after.schema_sha256, crate::standby::shapes::V2_TERMINAL_95);
    assert!(crate::standby::shapes::v2(1, &before.schema_sha256).is_none());
    db.close().await;
}
