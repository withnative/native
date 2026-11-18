use super::*;
use crate::standby::shapes;

#[tokio::test]
async fn receiver_shape_pins_do_not_outlive_operator_v1_release() {
    let dir = tempfile::tempdir().unwrap();
    let v1 = crate::create_database(":memory:").await.unwrap();
    let origin = crate::identity::database_id(&v1).await.unwrap();
    let account = crate::identity::resolve_stdio_account_identity(&v1, None)
        .await
        .unwrap();
    let store =
        GenerationStore::open(dir.path().join("replica"), "route-1", Some(origin.clone())).unwrap();
    let observed = tests::observed();
    let (snapshot, manifest) = tests::stage(&store, &v1, "v1").await;
    let old = store
        .install_staged(&snapshot, &manifest, &observed)
        .await
        .unwrap();
    let (v2, admin) = crate::kernel::create_v2_database(":memory:", "account", "Owner", &account)
        .await
        .unwrap();
    let record = crate::kernel::create_record_as(&v2, &admin, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    let host = crate::kernel::resolve_principal_by_binding(&v2, crate::kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    crate::kernel::import_event_as(
        &v2,
        &host,
        &record,
        &crate::kernel::LegacyEvent {
            source: None,
            id: "receiver-v1-pin-provenance".into(),
            event_type: "v1.snapshot_provenance".into(),
            created_at: "2026-10-18T00:00:00Z".into(),
            actor: None,
            run_key: None,
            payload: serde_json::json!({"source_origin":origin,"record_id":record}),
        },
    )
    .await
    .unwrap();
    let (snapshot, manifest) = tests::stage(&store, &v2, "v2-94").await;
    // Cross-family publication retains its established operator pin, without
    // adding a generic pin or the generic transition's extra disk refusal.
    *store.shape_pin_space.lock().unwrap() = Some(0);
    let current = store
        .install_staged(&snapshot, &manifest, &observed)
        .await
        .unwrap();
    *store.shape_pin_space.lock().unwrap() = None;
    assert_eq!(
        store.pinned_v1_generation().unwrap().as_deref(),
        Some(old.id.as_str())
    );
    assert!(!store.shape_pin_contains(&old.id).unwrap());
    store.release_v1_pin(&observed, false).await.unwrap();
    assert_eq!(
        store.current_for_head_probe().unwrap().unwrap().id,
        current.id
    );
    store.remove_published_generation(&old.id).unwrap();
    assert!(
        !old.snapshot_path.exists(),
        "operator release leaves v1 prunable"
    );

    shapes::tests::upgrade_fixture_to_95(&v2).await;
    let (snapshot, manifest) = tests::stage(&store, &v2, "v2-95").await;
    store
        .install_staged(&snapshot, &manifest, &observed)
        .await
        .unwrap();
    assert!(store.shape_pin_contains(&current.id).unwrap());
    assert!(store.remove_published_generation(&current.id).is_err());
    assert!(
        current.snapshot_path.exists(),
        "same-family94 rollback stays pinned"
    );
    store.maintenance_idle().await;
    v1.close().await;
    v2.close().await;
}

#[tokio::test]
async fn receiver_shape_full_switch_rebind_and_pin() {
    let dir = tempfile::tempdir().unwrap();
    let (source, owner) =
        crate::kernel::create_v2_database(":memory:", "account", "Owner", "acct:fixture")
            .await
            .unwrap();
    let origin = {
        let mut conn = source.pool().acquire().await.unwrap();
        let k = super::super::kernel_v2::coordinates(&mut conn)
            .await
            .unwrap();
        super::super::kernel_v2::origin(&mut conn, &k)
            .await
            .unwrap()
    };
    let store = GenerationStore::open(dir.path().join("replica"), "route-1", Some(origin)).unwrap();
    let observed = tests::observed();
    let (snapshot, manifest) = tests::stage(&store, &source, "old94").await;
    let old = store
        .install_staged(&snapshot, &manifest, &observed)
        .await
        .unwrap();
    let active = store
        .activate_accepted(
            &store.accepted_identity_hint().unwrap().unwrap(),
            &observed,
            None,
        )
        .await
        .unwrap();
    shapes::tests::upgrade_fixture_to_95(&source).await;
    crate::kernel::create_record_as(&source, &owner, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    let (snapshot, manifest) = tests::stage(&store, &source, "new95").await;
    let new = store
        .install_staged(&snapshot, &manifest, &observed)
        .await
        .unwrap();
    assert_eq!(
        new.manifest.kernel_v2.as_ref().unwrap().schema_sha256,
        shapes::V2_95
    );
    assert!(store.shape_pin_contains(&old.id).unwrap());
    assert!(store.remove_published_generation(&old.id).is_err());
    let next = store
        .activate_accepted(
            &store.accepted_identity_hint().unwrap().unwrap(),
            &observed,
            Some(&active),
        )
        .await
        .unwrap();
    store.confirm_handoff(&next).unwrap();
    assert_eq!(next.generation.id, new.id);
    // A registered non-primary shape is a normal predecessor. Treating95 as
    // "other revision" would skip prefix parity and accept this corruption.
    let bad = store.staging_dir().join("changed-prefix95.db");
    fs::copy(&new.snapshot_path, &bad).unwrap();
    set_mode(&bad, 0o600).unwrap();
    let mut writer = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&bad)
            .create_if_missing(false),
    )
    .await
    .unwrap();
    let trigger: String =
        sqlx::query_scalar("SELECT sql FROM sqlite_schema WHERE name='content_events_no_update'")
            .fetch_one(&mut writer)
            .await
            .unwrap();
    sqlx::query("DROP TRIGGER content_events_no_update")
        .execute(&mut writer)
        .await
        .unwrap();
    sqlx::query("UPDATE content_events SET observed_act=1 WHERE seq=1")
        .execute(&mut writer)
        .await
        .unwrap();
    sqlx::query(&trigger).execute(&mut writer).await.unwrap();
    writer.close().await.unwrap();
    let mut bad_manifest = new.manifest.clone();
    bad_manifest.snapshot.sha256 = sha256_file(&bad).unwrap();
    bad_manifest.snapshot.size_bytes = fs::metadata(&bad).unwrap().len();
    let bad_manifest_path = store.staging_dir().join("changed-prefix95.json");
    fs::write(&bad_manifest_path, bad_manifest.canonical_json().unwrap()).unwrap();
    assert!(
        store
            .install_staged(&bad, &bad_manifest_path, &observed)
            .await
            .is_err(),
        "same95 FULL must preserve95 predecessor rows"
    );
    assert_eq!(
        store
            .accepted_identity_hint()
            .unwrap()
            .unwrap()
            .generation_id,
        new.id
    );
    // Offline binary upgrade: its primary can change while actual snapshots
    // remain readable. Attribution stays original, rebind records acceptance.
    let mut upgraded = observed.clone();
    upgraded.source_sha = "d".repeat(40);
    upgraded.artifact_sha256 = "e".repeat(64);
    upgraded.engine_schema_version = 95;
    upgraded.ddl_sha256 = shapes::V1_95.into();
    upgraded.kernel_v2_reader.schema_sha256 = shapes::V2_95.into();
    for id in [&old.id, &new.id] {
        store.ensure_consumer_binding(id, &upgraded).await.unwrap();
        let rebound = store.consumer_rebind(id, &upgraded).unwrap().unwrap();
        assert_eq!(rebound.original_consumer, old.manifest.consumer);
        assert_eq!(rebound.accepted_consumer, upgraded);
    }
    drop(next);
    drop(active);
    // No94 reader lease remains: the durable generic pin must survive actual
    // retention with more than three newer95 checkpoints, then explicit prune.
    for ordinal in 0..4 {
        crate::kernel::create_record_as(&source, &owner, crate::events::KERNEL_ROOT_ID)
            .await
            .unwrap();
        let (snapshot, manifest) =
            tests::stage(&store, &source, &format!("pin-retention-{ordinal}")).await;
        store
            .install_staged(&snapshot, &manifest, &observed)
            .await
            .unwrap();
        store.maintenance_idle().await;
    }
    store.maintain_generations(&observed, true).await.unwrap();
    assert!(
        old.snapshot_path.exists(),
        "rollback pin outlives every serving lease and ordinary retention"
    );
    assert!(store.remove_published_generation(&old.id).is_err());
    store.maintenance_idle().await;
    source.close().await;
}

#[tokio::test]
async fn receiver_v1_exact95_full_keeps94_while_unknown96_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let source = crate::db::create_database(":memory:").await.unwrap();
    let account = crate::identity::resolve_stdio_account_identity(&source, None)
        .await
        .unwrap();
    crate::store::create_record_as(&source,serde_json::json!({"id":"70110000-0000-4000-8000-000000000095",
        "type":"Document","kind":"note","name":"Receiver downgrade baseline","body":"Verified94 remains readable"}),Some(&account)).await.unwrap();
    let origin = crate::identity::database_id(&source).await.unwrap();
    let store = GenerationStore::open(dir.path().join("replica"), "route-1", Some(origin)).unwrap();
    let observed = tests::observed();
    let (snapshot, manifest) = tests::stage(&store, &source, "v1-old94").await;
    let old = store
        .install_staged(&snapshot, &manifest, &observed)
        .await
        .unwrap();
    let active = store
        .activate_accepted(
            &store.accepted_identity_hint().unwrap().unwrap(),
            &observed,
            None,
        )
        .await
        .unwrap();
    let before = fs::read(&old.snapshot_path).unwrap();
    let candidate = store.staging_dir().join("v1-95.db");
    for ddl in [
        "ALTER TABLE content_events ADD COLUMN observed_act INTEGER",
        "ALTER TABLE content_events ADD COLUMN observed_basis TEXT",
        "ALTER TABLE content_events ADD COLUMN caller_write_ordinal INTEGER",
        shapes::CALLER_INDEX,
        "PRAGMA user_version = 95",
    ] {
        sqlx::query(ddl).execute(source.write_pool()).await.unwrap();
    }
    sqlx::query("VACUUM INTO ?")
        .bind(candidate.to_str().unwrap())
        .execute(source.write_pool())
        .await
        .unwrap();
    let mut manifest = old.manifest.clone();
    manifest.engine.schema_version = 95;
    manifest.engine.ddl_sha256 = shapes::V1_95.into();
    manifest.snapshot.sha256 = sha256_file(&candidate).unwrap();
    manifest.snapshot.size_bytes = fs::metadata(&candidate).unwrap().len();
    let path = store.staging_dir().join("v1-95.json");
    let mut unknown = manifest.clone();
    unknown.engine.schema_version = 96;
    fs::write(&path, serde_json::to_vec(&unknown).unwrap()).unwrap();
    assert!(store
        .install_staged(&candidate, &path, &observed)
        .await
        .is_err());
    assert_eq!(fs::read(&old.snapshot_path).unwrap(), before);
    assert_eq!(
        store
            .accepted_identity_hint()
            .unwrap()
            .unwrap()
            .generation_id,
        old.id
    );
    fs::write(&path, manifest.canonical_json().unwrap()).unwrap();
    *store.shape_pin_space.lock().unwrap() = Some(0);
    let budget_error = store
        .install_staged(&candidate, &path, &observed)
        .await
        .unwrap_err();
    assert!(
        budget_error.to_string().contains("transition_disk_budget"),
        "{budget_error}"
    );
    assert_eq!(fs::read(&old.snapshot_path).unwrap(), before);
    assert_eq!(
        store
            .accepted_identity_hint()
            .unwrap()
            .unwrap()
            .generation_id,
        old.id
    );
    *store.shape_pin_space.lock().unwrap() = None;
    let new = store
        .install_staged(&candidate, &path, &observed)
        .await
        .unwrap();
    assert_eq!(new.manifest.engine.schema_version, 95);
    assert!(store.shape_pin_contains(&old.id).unwrap());
    let next = store
        .activate_accepted(
            &store.accepted_identity_hint().unwrap().unwrap(),
            &observed,
            Some(&active),
        )
        .await
        .unwrap();
    store.confirm_handoff(&next).unwrap();
    assert_eq!(next.generation.id, new.id);
    assert_eq!(fs::read(&old.snapshot_path).unwrap(), before);
    assert_eq!(store.receiver_writer_opens(), 0);
    if let Ok(destination) = std::env::var("NATIVE_RECEIVER_EXPORT_DOWNGRADE_STORE") {
        // Give the pre-A process an excess-generation retention case, not
        // merely the two files its ordinary three-generation floor keeps.
        let mut exported_current = new.clone();
        for ordinal in 0..3 {
            let snapshot = store
                .staging_dir()
                .join(format!("downgrade-retention-{ordinal}.db"));
            fs::copy(&new.snapshot_path, &snapshot).unwrap();
            let mut manifest = new.manifest.clone();
            let captured = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
            manifest.captured_at = captured.clone();
            manifest.snapshot_completed_at = captured;
            let path = store
                .staging_dir()
                .join(format!("downgrade-retention-{ordinal}.json"));
            fs::write(&path, manifest.canonical_json().unwrap()).unwrap();
            exported_current = store
                .install_staged(&snapshot, &path, &observed)
                .await
                .unwrap();
            store.maintenance_idle().await;
        }
        fn copy_tree(source: &Path, destination: &Path) {
            fs::create_dir_all(destination).unwrap();
            set_mode(destination, 0o700).unwrap();
            for entry in fs::read_dir(source).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_dir() {
                    copy_tree(&entry.path(), &destination.join(entry.file_name()));
                } else {
                    fs::copy(entry.path(), destination.join(entry.file_name())).unwrap();
                }
            }
            fs::set_permissions(destination, fs::metadata(source).unwrap().permissions()).unwrap();
        }
        let destination = PathBuf::from(destination);
        assert!(
            !destination.exists(),
            "qualification export must be a new private directory"
        );
        fs::create_dir_all(&destination).unwrap();
        set_mode(&destination, 0o700).unwrap();
        let replica = destination.join("replica");
        copy_tree(store.root.parent().unwrap(), &replica);
        fs::write(
            destination.join("standby.json"),
            serde_json::to_vec(&serde_json::json!({
            "replica_root":replica,"hosted_route_database_id":"route-1",
            "origin_database_id":old.manifest.origin_database_id}))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            destination.join("expected.json"),
            serde_json::to_vec(&serde_json::json!({
            "old_generation":old.id,"new_generation":exported_current.id,
            "record_id":"70110000-0000-4000-8000-000000000095",
            "old_snapshot_sha256":sha256_file(&old.snapshot_path).unwrap(),
            "new_snapshot_sha256":sha256_file(&exported_current.snapshot_path).unwrap()}))
            .unwrap(),
        )
        .unwrap();
    }
    drop(next);
    drop(active);
    store.maintenance_idle().await;
    source.close().await;
}

fn producer_bytes(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/receiver-shapes")
        .join(name);
    let mut bytes = Vec::new();
    flate2::read::GzDecoder::new(File::open(path).unwrap())
        .read_to_end(&mut bytes)
        .unwrap();
    bytes
}

#[tokio::test]
async fn receiver_registered_shapes_export_strip_retains_unknown_attached_drift() {
    for version in [94, 95] {
        let (db, _) =
            crate::kernel::create_v2_database(":memory:", "account", "Owner", "fixture-owner")
                .await
                .unwrap();
        if version == 95 {
            shapes::tests::upgrade_fixture_to_95(&db).await;
        }
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        crate::kernel::stored_visibility::install_on(&mut tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let export = crate::export::export_connected_db(&db, None).await.unwrap();
        let mut raw = sqlx::SqliteConnection::connect_with(
            &sqlx::sqlite::SqliteConnectOptions::new()
                .filename(export.path())
                .read_only(true),
        )
        .await
        .unwrap();
        let coordinate = super::super::kernel_v2::coordinates(&mut raw)
            .await
            .unwrap();
        assert_eq!(
            coordinate.schema_sha256,
            if version == 94 {
                shapes::V2_94
            } else {
                shapes::V2_95
            }
        );
        let marking: i64 =
            sqlx::query_scalar("SELECT count(*) FROM sqlite_schema WHERE name GLOB 'p_*'")
                .fetch_one(&mut raw)
                .await
                .unwrap();
        assert_eq!(
            marking, 0,
            "raw export strips the exact compiled marking set"
        );
        raw.close().await.unwrap();
        export.cleanup().await;

        // An unprefixed dependency must survive the export. Dropping its exact
        // parent would silently hide unknown drift from receiver admission.
        sqlx::query("CREATE INDEX dirty_by_key ON p_dirty(key)")
            .execute(db.write_pool())
            .await
            .unwrap();
        let export = crate::export::export_connected_db(&db, None).await.unwrap();
        let mut raw = sqlx::SqliteConnection::connect_with(
            &sqlx::sqlite::SqliteConnectOptions::new()
                .filename(export.path())
                .read_only(true),
        )
        .await
        .unwrap();
        let dependency: i64 =
            sqlx::query_scalar("SELECT count(*) FROM sqlite_schema WHERE name='dirty_by_key'")
                .fetch_one(&mut raw)
                .await
                .unwrap();
        assert_eq!(dependency, 1);
        assert!(super::super::kernel_v2::coordinates(&mut raw)
            .await
            .is_err());
        raw.close().await.unwrap();
        export.cleanup().await;
        db.close().await;
    }
}

#[tokio::test]
async fn receiver_real95_v1_audit_uses_only_disposable_registered_scratch() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("producer95.db");
    let published = dir.path().join("published95.db");
    let bytes = producer_bytes("v1-base95.sqlite.gz");
    fs::write(&source, &bytes).unwrap();
    fs::write(&published, &bytes).unwrap();
    set_mode(&source, 0o400).unwrap();
    set_mode(&published, 0o400).unwrap();
    verify_snapshot_database_deep(&published, dir.path(), false)
        .await
        .unwrap();
    assert_eq!(fs::read(&source).unwrap(), bytes);
    assert_eq!(fs::read(&published).unwrap(), bytes);

    // Corrupt only a private candidate's derived awareness state. The audit
    // may rebuild its scratch, but must neither repair nor accept the input.
    let drift = dir.path().join("drift.db");
    fs::write(&drift, &bytes).unwrap();
    let mut raw = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&drift)
            .foreign_keys(false),
    )
    .await
    .unwrap();
    sqlx::query("INSERT INTO message_preferences(subject_account_id,message_id,last_event_seq,version) VALUES ('audit:account','audit:message',1,1)")
        .execute(&mut raw).await.unwrap();
    raw.close().await.unwrap();
    let before = fs::read(&drift).unwrap();
    let error = verify_awareness_projections(&drift, dir.path())
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("awareness projection drift"),
        "{error}"
    );
    assert_eq!(fs::read(&drift).unwrap(), before);

    let unknown = dir.path().join("unknown96.db");
    fs::write(&unknown, &bytes).unwrap();
    let mut raw = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&unknown),
    )
    .await
    .unwrap();
    sqlx::query("PRAGMA user_version=96")
        .execute(&mut raw)
        .await
        .unwrap();
    raw.close().await.unwrap();
    let before = fs::read(&unknown).unwrap();
    assert!(verify_awareness_projections(&unknown, dir.path())
        .await
        .is_err());
    assert_eq!(fs::read(&unknown).unwrap(), before);
    assert_eq!(fs::read(&source).unwrap(), bytes);
    assert_eq!(fs::read(&published).unwrap(), bytes);
}

#[tokio::test]
async fn receiver_real95_working_fold_after_private_ddl() {
    use crate::standby::kernel_v2_delta::{KernelDelta, TrustedKernelDelta, WorkingFold};
    use base64::Engine as _;
    use sqlx::Connection as _;
    let dir = tempfile::tempdir().unwrap();
    let published = dir.path().join("published-base95.db");
    let private = dir.path().join("private-working95.db");
    let bytes = producer_bytes("base.sqlite.gz");
    fs::write(&published, &bytes).unwrap();
    fs::write(&private, &bytes).unwrap();
    let db = crate::db::open_existing_v2_file(private.to_str().unwrap())
        .await
        .unwrap();
    let response: serde_json::Value =
        serde_json::from_slice(&producer_bytes("delta-response.json.gz")).unwrap();
    let delta = KernelDelta::parse(
        &base64::engine::general_purpose::STANDARD
            .decode(response["data_base64"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    // The real producer cut is trusted only for this component fold test.
    // Transport, sealed admission and journal ownership remain separate proofs.
    let trusted = TrustedKernelDelta::assume_trusted_for_test(delta).unwrap();
    let mut connection = db.write_pool().acquire().await.unwrap();
    let mut tx = connection.begin().await.unwrap();
    let before = super::super::kernel_v2::coordinates(&mut tx).await.unwrap();
    let origin = super::super::kernel_v2::origin(&mut tx, &before)
        .await
        .unwrap();
    let schema = super::super::kernel_v2::WorkingKernelSchema::from_fresh_native(&mut tx)
        .await
        .unwrap();
    for (_, ddl) in crate::kernel::working_undo_schema::WORKING_METADATA {
        sqlx::query(ddl).execute(&mut *tx).await.unwrap();
    }
    tx.commit().await.unwrap();
    // Use the production collector, exact registered keys and the actual W
    // inventory witness. No alternate coordinate bypass or schema exemption.
    let collector = crate::kernel::working_undo::with_handle(&mut connection, |raw| {
        let keys = crate::kernel::working_undo::registered_primary_keys(raw)
            .map_err(|e| Error::engine(e.to_string()))?;
        crate::kernel::working_undo::Collector::install(raw, &keys, 100_000, 16 * 1024 * 1024)
            .map_err(|e| Error::engine(e.to_string()))
    })
    .await
    .unwrap();
    let before_projection = crate::kernel::projection_dump::dump(&db).await.unwrap();
    let mut tx = connection.begin().await.unwrap();
    let fold = WorkingFold::new(&mut tx, &collector, &schema, &before, &origin)
        .await
        .unwrap();
    let error = crate::projector::with_app_action_suffix_failure(fold.fold(
        &trusted,
        &crate::standby::phase_timings::PhaseTimings::default(),
    ))
    .await
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("injected app action suffix failure"),
        "the registered route must reach the shared suffix after projecting: {error}"
    );
    tx.rollback().await.unwrap();
    assert_eq!(
        crate::kernel::projection_dump::dump(&db).await.unwrap(),
        before_projection,
        "a suffix refusal must roll back every projected row"
    );
    let mut tx = connection.begin().await.unwrap();
    assert_eq!(
        schema.coordinates_on(&mut tx, &collector).await.unwrap(),
        before
    );
    let fold = WorkingFold::new(&mut tx, &collector, &schema, &before, &origin)
        .await
        .unwrap();
    let folded = fold
        .fold(
            &trusted,
            &crate::standby::phase_timings::PhaseTimings::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        schema.coordinates_on(&mut tx, &collector).await.unwrap(),
        folded
    );
    tx.commit().await.unwrap();
    let expected: serde_json::Value =
        serde_json::from_slice(&producer_bytes("projection.json.gz")).unwrap();
    // W metadata participates in the ordinary dump. Build the expected W
    // inventory from the independently captured producer FULL: first require
    // its complete native projection to equal the frozen producer output,
    // then install the exact same empty private metadata. No dump exemption.
    let reference = dir.path().join("reference-full95.db");
    fs::write(&reference, producer_bytes("full.sqlite.gz")).unwrap();
    let reference_db = crate::db::open_existing_v2_file(reference.to_str().unwrap())
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(
            crate::kernel::projection_dump::dump(&reference_db)
                .await
                .unwrap()
        )
        .unwrap(),
        expected
    );
    let mut reference_tx = reference_db.write_pool().begin().await.unwrap();
    for (_, ddl) in crate::kernel::working_undo_schema::WORKING_METADATA {
        sqlx::query(ddl).execute(&mut *reference_tx).await.unwrap();
    }
    reference_tx.commit().await.unwrap();
    assert_eq!(
        crate::kernel::projection_dump::dump(&db).await.unwrap(),
        crate::kernel::projection_dump::dump(&reference_db)
            .await
            .unwrap()
    );
    reference_db.close().await;
    let mut tx = connection.begin().await.unwrap();
    sqlx::query("CREATE TABLE unexpected_private_ddl(value)")
        .execute(&mut *tx)
        .await
        .unwrap();
    assert!(
        WorkingFold::new(&mut tx, &collector, &schema, &folded, &origin)
            .await
            .is_err(),
        "a decoder witness must never exempt private DDL drift"
    );
    tx.rollback().await.unwrap();
    drop(collector);
    drop(connection);
    db.close().await;
    assert_eq!(fs::read(&published).unwrap(), bytes);
    let unknown = dir.path().join("unknown-owned96.db");
    fs::write(&unknown, &bytes).unwrap();
    let mut raw = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&unknown),
    )
    .await
    .unwrap();
    sqlx::query("CREATE TABLE unknown_engine96(value)")
        .execute(&mut raw)
        .await
        .unwrap();
    let unknown_bytes = fs::read(&unknown).unwrap();
    let mut tx = raw.begin().await.unwrap();
    assert!(
        super::super::kernel_v2::WorkingKernelSchema::from_fresh_native(&mut tx)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    raw.close().await.unwrap();
    assert_eq!(fs::read(&unknown).unwrap(), unknown_bytes);
    assert_eq!(fs::read(&published).unwrap(), bytes);
}

#[tokio::test]
async fn receiver_real95_producer_full_and_delta_projection_equal_source() {
    use base64::Engine as _;
    let dir = tempfile::tempdir().unwrap();
    let expected: serde_json::Value =
        serde_json::from_slice(&producer_bytes("projection.json.gz")).unwrap();
    let full = dir.path().join("full95.db");
    fs::write(&full, producer_bytes("full.sqlite.gz")).unwrap();
    let coordinates = crate::standby::kernel_v2::verify_path(&full).await.unwrap();
    assert_eq!(coordinates.schema_sha256, shapes::V2_95);
    let db = crate::db::open_kernel_v2_head_writer(&full).await.unwrap();
    let metadata: serde_json::Value = serde_json::from_slice(
        &fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/receiver-shapes/metadata.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let rows = sqlx::query("SELECT *, (SELECT json_group_array(parent_event_id) FROM content_event_causal_frontier WHERE event_id=content_events.id) AS causal_frontier FROM content_events WHERE type IN ('kernel.app_action_recorded.v1','kernel.mcp_write_receipt_recorded.v1')")
        .fetch_all(db.pool()).await.unwrap();
    let mut app = false;
    let mut receipt = false;
    for row in rows {
        let event = crate::query::events::event_from_row(&row).unwrap();
        let public =
            crate::mcp::tools::history::event_to_value(&event, &std::collections::HashMap::new());
        if event.event_type == "kernel.app_action_recorded.v1" {
            app = true;
            assert!(public["payload"].get("caller_write_ordinal").is_none());
        } else {
            receipt = true;
            let bytes = public["payload"]["receipt_json"].as_str().unwrap();
            let value: serde_json::Value = serde_json::from_str(bytes).unwrap();
            for key in [
                "caller_write_ordinal",
                "observed_act",
                "observed_basis",
                "freshness_coordinate",
                "as_of_act",
            ] {
                assert!(value.get(key).is_none(), "local95 history must hide {key}");
            }
        }
        let mut authored = event.clone();
        authored.event_type = "record.updated".into();
        let body = serde_json::json!({"body":"{\"observed_act\":42}","facets":{"observed_basis":"authored"}});
        authored.payload = Some(body.to_string());
        assert_eq!(
            crate::mcp::tools::history::event_to_value(
                &authored,
                &std::collections::HashMap::new()
            )["payload"],
            body
        );
    }
    assert!(app && receipt);
    let sql = crate::mcp::kernel_v2::sql::query_sql(
        &db,
        metadata["principal"].as_str().unwrap(),
        serde_json::json!({"sql":"SELECT * FROM content_events LIMIT 1"}),
    )
    .await
    .unwrap();
    let public = serde_json::to_string(&sql).unwrap();
    for key in [
        "observed_act",
        "caller_write_ordinal",
        "freshness_coordinate",
    ] {
        assert!(!public.contains(key), "local SQL remains the94 contract");
    }
    type CanonicalEvent = (String, String, Option<i64>, Option<String>, Option<i64>);
    let canonical: Vec<CanonicalEvent> = sqlx::query_as(
        "SELECT id,payload,observed_act,observed_basis,caller_write_ordinal FROM content_events ORDER BY seq")
        .fetch_all(db.pool()).await.unwrap();
    assert!(canonical
        .iter()
        .any(|row| row.2.is_some() || row.3.is_some() || row.4.is_some()));
    assert_eq!(
        serde_json::to_value(crate::kernel::projection_dump::dump(&db).await.unwrap()).unwrap(),
        expected
    );
    // Canonical maintenance is permitted only on this disposable audit file.
    // Rebuilding through A's real decoders must preserve producer95 projection.
    crate::kernel::replay_all_projections(&db).await.unwrap();
    assert_eq!(
        serde_json::to_value(crate::kernel::projection_dump::dump(&db).await.unwrap()).unwrap(),
        expected
    );
    let after: Vec<CanonicalEvent> = sqlx::query_as(
        "SELECT id,payload,observed_act,observed_basis,caller_write_ordinal FROM content_events ORDER BY seq")
        .fetch_all(db.pool()).await.unwrap();
    assert_eq!(
        canonical, after,
        "decode-only tolerance never rewrites canonical facts"
    );
    db.close().await;

    let base = dir.path().join("base95.db");
    fs::write(&base, producer_bytes("base.sqlite.gz")).unwrap();
    let outer: serde_json::Value =
        serde_json::from_slice(&producer_bytes("delta-response.json.gz")).unwrap();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(outer["data_base64"].as_str().unwrap())
        .unwrap();
    let delta = crate::standby::kernel_v2_delta::KernelDelta::parse(&bytes).unwrap();
    // Transport authenticity is qualified separately; this test isolates the
    // real producer bytes and A's fold/projection equality boundary.
    let trusted =
        crate::standby::kernel_v2_delta::TrustedKernelDelta::assume_trusted_for_test(delta)
            .unwrap();
    let db = crate::db::open_kernel_v2_head_writer(&base).await.unwrap();
    crate::standby::kernel_v2_delta::apply(
        &db,
        &trusted,
        &crate::standby::phase_timings::PhaseTimings::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        serde_json::to_value(crate::kernel::projection_dump::dump(&db).await.unwrap()).unwrap(),
        expected
    );
    db.close().await;
}

#[tokio::test]
async fn receiver95_configured_origin_route_and_read_only_handles_remain_fenced() {
    let dir = tempfile::tempdir().unwrap();
    let (source, _) =
        crate::kernel::create_v2_database(":memory:", "account", "Owner", "acct:fixture")
            .await
            .unwrap();
    shapes::tests::upgrade_fixture_to_95(&source).await;
    let observed = tests::observed();
    for route in ["route-1", "other-route"] {
        let store = GenerationStore::open(
            dir.path().join(route),
            route,
            Some("ndb_11111111111141118111111111111111".into()),
        )
        .unwrap();
        let (snapshot, manifest) = tests::stage(&store, &source, "wrong-boundary95").await;
        let error = store
            .install_staged(&snapshot, &manifest, &observed)
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                Error::StandbyAdmission {
                    check: StandbyAdmissionCheck::RouteOrigin,
                    ..
                }
            ),
            "{error}"
        );
        assert!(store.accepted_identity_hint().unwrap().is_none());
    }
    source.close().await;
    let path = dir.path().join("actual95-read-only.db");
    fs::write(&path, producer_bytes("full.sqlite.gz")).unwrap();
    let before = sha256_file(&path).unwrap();
    let reader = crate::db::open_kernel_v2_standby_read_only(path.to_str().unwrap())
        .await
        .unwrap();
    for pool in [reader.pool(), reader.write_pool(), reader.governed_pool()] {
        assert!(
            sqlx::query("UPDATE act_state SET next_act=next_act+1 WHERE singleton=1")
                .execute(pool)
                .await
                .is_err(),
            "no user write may reach a95 serving handle"
        );
    }
    reader.close().await;
    assert_eq!(sha256_file(&path).unwrap(), before);
}
