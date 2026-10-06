use super::*;
use crate::authorization::{replace_explicit_policy, AllowEntry};
use crate::db::{begin_write, create_database, Db};
use serde_json::json;
use sqlx::Connection;

async fn fixture() -> Db {
    let db = create_database(":memory:").await.unwrap();
    replace_explicit_policy(
        &db,
        "test-policy",
        ROOT,
        vec![
            AllowEntry::account("acct:alice", Capability::Manage),
            AllowEntry::account("acct:bob", Capability::Manage),
            AllowEntry::account("acct:view", Capability::View),
        ],
    )
    .await
    .unwrap();
    db
}
fn revision() -> ri::RuleRevision {
    ri::RuleRevision {
        namespace: "test_ns".into(),
        name: "records".into(),
        language: "cel-subset@1".into(),
        binding_contract: Some(shape::BindingContractVersion::ScalarRowsV1),
        scalar_arguments: vec![],
        inputs: vec![ri::RuleInputDecl {
            name: "rows".into(),
            sql: "SELECT id FROM records ORDER BY id".into(),
            cardinality: ri::RuleCardinality::Many,
            required_fields: vec!["id".into()],
            parameters: vec![],
            contract: Some(shape::RuleInputContract::ScalarRowsV1 {
                fields: vec![shape::ScalarField {
                    name: "id".into(),
                    scalar_type: shape::ScalarType::String,
                    nullable: false,
                    canonical_integer_text: false,
                }],
                required_when: None,
            }),
        }],
        clauses: "true".into(),
        examples: vec![],
        definition_pins: vec![],
    }
}
// The ONLY issuer is compiled under cfg(test). Uses actual SQL/AST/profile
// machinery, explicitly fixture evidence; never impersonates a real validator.
fn admit(revision: ri::RuleRevision) -> VerifiedAdmission {
    admit_with_metadata(revision, None)
}
fn admit_with_metadata(revision: ri::RuleRevision, advisor: Option<Advisor>) -> VerifiedAdmission {
    let catalog = crate::query::sql::current_catalog_snapshot();
    let readsets: BTreeMap<_, _> = revision
        .inputs
        .iter()
        .map(|i| {
            (
                i.name.clone(),
                crate::query::sql::extract_rule_input_dependencies(&i.sql).unwrap(),
            )
        })
        .collect();
    let proofs: BTreeMap<_, _> = revision
        .inputs
        .iter()
        .map(|i| {
            (
                i.name.clone(),
                serde_json::from_value(
                    serde_json::to_value(crate::query::rule_order::validate_input_sql(i).unwrap())
                        .unwrap(),
                )
                .unwrap(),
            )
        })
        .collect();
    let r = Revision {
        version: RevisionVersion::WorkspaceRuleRevisionV1,
        content: revision,
    };
    let settings = Settings {
        version: SettingsVersion::WorkspaceRuleSettingsV1,
        content: EmptySettings {},
    };
    let metadata = Metadata {
        version: MetadataVersion::WorkspaceRuleMetadataV1,
        advisor,
    };
    let pins = Catalog {
        revision: catalog.revision,
        profile_id: catalog.profile_id,
        profile_revision: catalog.profile_revision,
    };
    let orders = Orders {
        version: OrderVersion::WorkspaceRuleOrderV1,
        input_order: ri::derive_input_order(&r.content).unwrap(),
        proofs,
    };
    let pairs: Vec<_> = readsets.iter().map(|(k, v)| (k.as_str(), v)).collect();
    let receipt = Receipt {
        version: ReceiptVersion::WorkspaceRuleReceiptV1,
        root: ROOT.into(),
        namespace: r.content.namespace.clone(),
        name: r.content.name.clone(),
        revision_digest: canonical::digest(&r.identity()),
        settings_digest: digest(&settings).unwrap(),
        metadata_digest: digest(&metadata).unwrap(),
        catalog_digest: digest(&pins).unwrap(),
        readset_digest: ri::readset_digest(
            pins.revision,
            &pins.profile_id,
            pins.profile_revision,
            &pairs,
        ),
        order_digest: digest(&orders).unwrap(),
        evidence: Evidence {
            revision_digest: ri::revision_digest(&r.content).unwrap(),
            settings_digest: ri::settings_digest(&json!({})).unwrap(),
            language_identity: r.content.language.clone(),
            policy_version: "fixture-policy-0".into(),
            engine_id: ri::FIXTURE_ENGINE_ID.into(),
            engine_version: "0.0.0-fixture".into(),
            bundle_sha256: None,
        },
    };
    let snapshot = Snapshot {
        version: SnapshotVersion::WorkspaceRuleSnapshotV1,
        root: ROOT.into(),
        revision: r,
        revision_digest: receipt.revision_digest.clone(),
        settings,
        settings_digest: receipt.settings_digest.clone(),
        metadata,
        metadata_digest: receipt.metadata_digest.clone(),
        catalog: pins,
        catalog_digest: receipt.catalog_digest.clone(),
        readsets,
        readset_digest: receipt.readset_digest.clone(),
        orders,
        order_digest: receipt.order_digest.clone(),
        receipt_digest: digest(&receipt).unwrap(),
        receipt,
        active: true,
        actor: "acct:alice".into(),
        previous_seq: None,
    };
    verify(
        &snapshot,
        &subject(
            &snapshot.revision.content.namespace,
            &snapshot.revision.content.name,
        ),
        Some(&snapshot.actor),
    )
    .unwrap();
    VerifiedAdmission { snapshot }
}
async fn set(
    db: &Db,
    actor: &str,
    admission: VerifiedAdmission,
    expected: Option<i64>,
) -> Result<(Stored, bool)> {
    let mut tx = begin_write(db.write_pool()).await?;
    let result = set_verified(
        &mut tx,
        Principal::bound(actor, false),
        admission,
        expected,
        &mut crate::act::ActAllocation::new(),
    )
    .await?;
    tx.commit().await?;
    Ok(result)
}
async fn count(db: &Db) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM meta_events WHERE type=?")
        .bind(EVENT)
        .fetch_one(db.write_pool())
        .await
        .unwrap()
}

#[tokio::test]
async fn strict_sequence_integrity_idempotence_and_fresh_actor() {
    let db = fixture().await;
    assert!(matches!(
        set(&db, "acct:alice", admit(revision()), Some(1)).await,
        Err(Error::Conflict(_))
    ));
    assert_eq!(count(&db).await, 0);
    let (first, appended) = set(&db, "acct:alice", admit(revision()), None)
        .await
        .unwrap();
    assert!(appended);
    assert!(set(&db, "acct:alice", admit(revision()), None)
        .await
        .is_err());
    assert!(
        set(&db, "acct:alice", admit(revision()), Some(first.seq - 1))
            .await
            .is_err()
    );
    let (retry, appended) = set(&db, "acct:alice", admit(revision()), Some(first.seq))
        .await
        .unwrap();
    assert!(!appended);
    assert_eq!(retry.seq, first.seq);
    let (other, appended) = set(&db, "acct:bob", admit(revision()), Some(first.seq))
        .await
        .unwrap();
    assert!(appended);
    assert_eq!(other.snapshot.actor, "acct:bob");
    assert!(other.seq > first.seq);
    assert_eq!(count(&db).await, 2);
    sqlx::query("UPDATE workspace_rule_installations SET snapshot_digest=?")
        .bind("f".repeat(64))
        .execute(db.write_pool())
        .await
        .unwrap();
    // Even a stale ExpectedSeq or nominally identical snapshot must expose
    // storage failure only after View/Manage, before Conflict/no-op.
    let err = set(&db, "acct:bob", admit(revision()), None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("integrity"));
    assert_eq!(count(&db).await, 2);
    db.close().await;
}

#[tokio::test]
async fn metadata_change_and_disable_preserve_incompatible_evidence() {
    let db = fixture().await;
    let (first, _) = set(&db, "acct:alice", admit(revision()), None)
        .await
        .unwrap();
    // A historical catalog can no longer be current. Reseal as historical
    // log evidence to model an upgrade without preparing historical SQL.
    let mut p = first.snapshot.clone();
    p.catalog.revision += 1;
    p.catalog_digest = digest(&p.catalog).unwrap();
    let pairs: Vec<_> = p.readsets.iter().map(|(k, v)| (k.as_str(), v)).collect();
    p.readset_digest = ri::readset_digest(
        p.catalog.revision,
        &p.catalog.profile_id,
        p.catalog.profile_revision,
        &pairs,
    );
    p.receipt.catalog_digest = p.catalog_digest.clone();
    p.receipt.readset_digest = p.readset_digest.clone();
    p.receipt_digest = digest(&p.receipt).unwrap();
    let (incompatible, _) = set(
        &db,
        "acct:alice",
        VerifiedAdmission {
            snapshot: p.clone(),
        },
        Some(first.seq),
    )
    .await
    .unwrap();
    assert!(
        native_query_contract::rule_contract::check_catalog_revision(
            &crate::query::sql::current_catalog_snapshot(),
            incompatible.snapshot.catalog.revision
        )
        .is_err()
    );
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    let (disabled, changed) = disable(
        &mut tx,
        Principal::bound("acct:alice", false),
        "test_ns",
        "records",
        Some(incompatible.seq),
        &mut crate::act::ActAllocation::new(),
    )
    .await
    .unwrap();
    assert!(changed);
    assert!(!disabled.snapshot.active);
    assert_eq!(disabled.snapshot.receipt, incompatible.snapshot.receipt);
    assert!(
        active_readsets(&mut tx, Principal::bound("acct:view", false))
            .await
            .unwrap()
            .is_empty()
    );
    tx.commit().await.unwrap();
    // No re-enable-from-stored API exists. New admission derives current pins.
    let mut fresh = admit(revision());
    fresh.snapshot.metadata.advisor = Some(Advisor {
        watch: Watch::WorkItemCompletionV1,
        hooks: vec![Hook::CreateRecord, Hook::UpdateRecord],
        level: Level::Warn,
    });
    fresh.snapshot.metadata_digest = digest(&fresh.snapshot.metadata).unwrap();
    fresh.snapshot.receipt.metadata_digest = fresh.snapshot.metadata_digest.clone();
    fresh.snapshot.receipt_digest = digest(&fresh.snapshot.receipt).unwrap();
    let (enabled, changed) = set(&db, "acct:alice", fresh, Some(disabled.seq))
        .await
        .unwrap();
    assert!(changed);
    assert!(enabled.snapshot.active);
    assert_ne!(enabled.snapshot.receipt, disabled.snapshot.receipt);
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    assert_eq!(
        active_readsets(&mut tx, Principal::bound("acct:view", false))
            .await
            .unwrap()
            .len(),
        1
    );
    tx.rollback().await.unwrap();
    db.close().await;
}

#[tokio::test]
async fn root_authority_precedes_private_diagnostics_and_membership_is_not_manage() {
    let db = fixture().await;
    let (first, _) = set(&db, "acct:alice", admit(revision()), None)
        .await
        .unwrap();
    sqlx::query("UPDATE workspace_rule_installations SET snapshot_digest=?")
        .bind("f".repeat(64))
        .execute(db.write_pool())
        .await
        .unwrap();
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    for caller in [
        Principal::bound("acct:hidden", false),
        Principal::unbound(true),
        Principal::trusted_local(),
    ] {
        let missing = inspect(&mut tx, caller, "test_ns", "missing")
            .await
            .unwrap_err()
            .to_string();
        let corrupt = inspect(&mut tx, caller, "test_ns", "records")
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(missing, corrupt);
        assert!(missing.contains("unavailable"));
    }
    let err = set_verified(
        &mut tx,
        Principal::bound("acct:view", true),
        admit(revision()),
        Some(first.seq),
        &mut crate::act::ActAllocation::new(),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("Manage"));
    assert!(!err.to_string().contains("integrity"));
    let missing = inspect(
        &mut tx,
        Principal::bound("acct:view", false),
        "test_ns",
        "missing",
    )
    .await
    .unwrap_err();
    assert!(missing.to_string().contains("unavailable"));
    assert!(inspect(
        &mut tx,
        Principal::bound("acct:view", false),
        "test_ns",
        "records"
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("integrity"));
    tx.rollback().await.unwrap();
    db.close().await;
}

#[tokio::test]
async fn projection_and_log_missing_or_tampered_sides_refuse() {
    for change in ["DELETE FROM workspace_rule_installations", "DELETE FROM meta_events WHERE type='workspace_rule_installation.set.v1'", "UPDATE workspace_rule_installations SET actor='other'", "UPDATE workspace_rule_installations SET event_seq=event_seq+1", "UPDATE workspace_rule_installations SET namespace='moved'", "UPDATE workspace_rule_installations SET created_at='wrong'", "UPDATE meta_events SET actor='other' WHERE type='workspace_rule_installation.set.v1'", "UPDATE meta_events SET subject_id=subject_id || 'moved' WHERE type='workspace_rule_installation.set.v1'", "UPDATE meta_events SET type='schema_config.set' WHERE type='workspace_rule_installation.set.v1'"] {
        let db=fixture().await;set(&db,"acct:alice",admit(revision()),None).await.unwrap();sqlx::query(change).execute(db.write_pool()).await.unwrap();
        let mut tx=begin_write(db.write_pool()).await.unwrap();assert!(active_readsets(&mut tx,Principal::bound("acct:view",false)).await.is_err(),"{change}");tx.rollback().await.unwrap();db.close().await;
    }
}

#[tokio::test]
async fn payload_binding_corruption_fails_actual_projector_and_verified_read() {
    for field in [
        "revision_digest",
        "settings_digest",
        "metadata_digest",
        "catalog_digest",
        "readset_digest",
        "order_digest",
        "receipt_digest",
        "actor",
        "root",
        "previous_seq",
        "orders",
        "receipt",
        "metadata",
        "revision",
    ] {
        let db = fixture().await;
        set(&db, "acct:alice", admit(revision()), None)
            .await
            .unwrap();
        let mut conn = db.write_pool().acquire().await.unwrap();
        let event = super::super::read_all_meta_events(&mut conn)
            .await
            .unwrap()
            .into_iter()
            .find(|e| e.event_type == EVENT)
            .unwrap();
        let mut raw: serde_json::Value =
            serde_json::from_str(event.payload.as_ref().unwrap()).unwrap();
        match field {
            "previous_seq" => raw[field] = json!(1),
            "orders" => raw[field]["proofs"]["rows"]["ordered_keys"] = json!(["fake"]),
            "receipt" => raw[field]["evidence"]["revision_digest"] = json!("e".repeat(64)),
            "metadata" => {
                raw[field]["advisor"] = json!({"watch":"work_item_completion_v1","hooks":["update_record"],"level":"warn"})
            }
            "revision" => raw[field]["content"]["inputs"][0]["sql"] = json!("changed"),
            _ => raw[field] = json!("f".repeat(64)),
        };
        let bytes = serde_json::to_string(&raw).unwrap();
        sqlx::query("UPDATE meta_events SET payload=? WHERE seq=?")
            .bind(&bytes)
            .bind(event.seq)
            .execute(&mut *conn)
            .await
            .unwrap();
        assert!(
            read_on(&mut conn, "test_ns", "records").await.is_err(),
            "{field}"
        );
        let mut forged = event.clone();
        forged.payload = Some(bytes);
        assert!(
            crate::projector::meta::project_meta(&mut conn, &forged)
                .await
                .is_err(),
            "{field}"
        );
        drop(conn);
        db.close().await;
    }
}

#[tokio::test]
async fn missing_historical_chain_and_previous_sequence_refuse() {
    let db = fixture().await;
    let (a, _) = set(&db, "acct:alice", admit(revision()), None)
        .await
        .unwrap();
    let (b, _) = set(&db, "acct:bob", admit(revision()), Some(a.seq))
        .await
        .unwrap();
    sqlx::query("DELETE FROM meta_events WHERE seq=?")
        .bind(a.seq)
        .execute(db.write_pool())
        .await
        .unwrap();
    let mut conn = db.write_pool().acquire().await.unwrap();
    assert!(read_on(&mut conn, "test_ns", "records").await.is_err());
    let events = super::super::read_all_meta_events(&mut conn).await.unwrap();
    sqlx::query("DELETE FROM workspace_rule_installations")
        .execute(&mut *conn)
        .await
        .unwrap();
    let event = events.iter().find(|e| e.seq == b.seq).unwrap();
    assert!(crate::projector::meta::project_meta(&mut conn, event)
        .await
        .is_err());
    drop(conn);
    db.close().await;
}

#[tokio::test]
async fn indexed_literal_census_isolates_foreign_roots_and_names() {
    let db = fixture().await;
    set(&db, "acct:alice", admit(revision()), None)
        .await
        .unwrap();
    let mut conn = db.write_pool().acquire().await.unwrap();
    for foreign in [
        "native:root:child",
        "native:root-extra",
        "native:roo",
        "other",
    ] {
        sqlx::query("INSERT INTO meta_events(id,subject_id,type,payload,created_at) VALUES(?,?,?,'{}','test')").bind(uuid::Uuid::new_v4().to_string()).bind(format!("workspace-rule:{}:test_ns:records",hex::encode(foreign))).bind(EVENT).execute(&mut *conn).await.unwrap();
    }
    let start = prefix();
    let end = format!("{};", start.trim_end_matches(':'));
    let plan:Vec<(i64,i64,i64,String)>=sqlx::query_as("EXPLAIN QUERY PLAN SELECT DISTINCT subject_id FROM meta_events WHERE subject_id>=? AND subject_id<? ORDER BY subject_id").bind(&start).bind(end).fetch_all(&mut *conn).await.unwrap();
    assert!(plan
        .iter()
        .any(|p| p.3.contains("idx_meta_events_subject") && p.3.contains("SEARCH")));
    assert_eq!(census_on(&mut conn).await.unwrap().len(), 1);
    sqlx::query("INSERT INTO meta_events(id,subject_id,type,payload,created_at) VALUES('own_bad',? ,?,'{}','test')").bind(subject("testXns","records")).bind(EVENT).execute(&mut *conn).await.unwrap();
    assert!(census_on(&mut conn).await.is_err());
    assert!(
        sqlx::query("UPDATE workspace_rule_installations SET root='native:root:child'")
            .execute(&mut *conn)
            .await
            .is_err()
    );
    drop(conn);
    db.close().await;
}

#[test]
fn closed_versions_fields_scope_pins_and_completion_sources_refuse() {
    let p = admit(revision()).snapshot;
    let original = serde_json::to_value(&p).unwrap();
    for pointer in [
        "/version",
        "/revision/version",
        "/settings/version",
        "/metadata/version",
        "/orders/version",
        "/receipt/version",
    ] {
        let mut raw = original.clone();
        *raw.pointer_mut(pointer).unwrap() = json!("future_version");
        assert!(decode(&serde_json::to_string(&raw).unwrap()).is_err());
    }
    for pointer in [
        "",
        "/revision",
        "/revision/content",
        "/settings/content",
        "/metadata",
        "/orders/proofs/rows",
        "/readsets/rows",
        "/readsets/rows/relations/0",
        "/receipt/evidence",
    ] {
        let mut raw = original.clone();
        raw.pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("forged".into(), json!(true));
        assert!(
            decode(&serde_json::to_string(&raw).unwrap()).is_err(),
            "{pointer}"
        );
    }
    let mut q = p.clone();
    q.revision.content.definition_pins.push(ri::DefinitionPin {
        family: "fake".into(),
        version: 1,
        digest: "a".repeat(64),
    });
    assert!(verify(&q, &subject("test_ns", "records"), Some("acct:alice")).is_err());
    let mut q = p.clone();
    q.revision.content.binding_contract = None;
    assert!(verify(&q, &subject("test_ns", "records"), Some("acct:alice")).is_err());
    let mut q = p.clone();
    q.revision
        .content
        .scalar_arguments
        .push(shape::ScalarArgument {
            name: "completed".into(),
            scalar_type: shape::ScalarType::Bool,
            nullable: true,
            source: shape::ScalarSource::CompletionV1 {
                fact: shape::CompletionFact::CompletionTransition,
            },
        });
    assert!(verify(&q, &subject("test_ns", "records"), Some("acct:alice")).is_err());
    let mut raw = serde_json::to_string(&original).unwrap();
    raw = raw.replacen(
        "\"root\":\"native:root\"",
        "\"root\":\"native:root\",\"root\":\"native:root\"",
        1,
    );
    assert!(decode(&raw).is_err());
    assert!(ri::ensure_non_fixture_evidence(&p.receipt.evidence.legacy()).is_err());
}

#[tokio::test]
async fn production_replay_dump_rebuild_export_before_content_or_policy() {
    let db = fixture().await;
    let mut r = revision();
    r.examples.push(ri::RuleExample {
        name: "unicode".into(),
        body: json!({"\u{e000}":1,"😀":[{"a":2,"\n":3}]}),
    });
    let (a, _) = set(&db, "acct:alice", admit(r.clone()), None)
        .await
        .unwrap();
    set(&db, "acct:bob", admit(r), Some(a.seq)).await.unwrap();
    let diff = crate::conformance::rebuild_and_diff_meta(&db)
        .await
        .unwrap();
    assert!(diff.equal, "{diff:?}");
    let mut live = db.write_pool().acquire().await.unwrap();
    let events = super::super::read_all_meta_events(&mut live).await.unwrap();
    let expected: String =
        sqlx::query_scalar("SELECT snapshot_json FROM workspace_rule_installations")
            .fetch_one(&mut *live)
            .await
            .unwrap();
    drop(live);
    let replay = create_database(":memory:").await.unwrap();
    let mut conn = replay.write_pool().acquire().await.unwrap();
    // Content-free schema from the actual DDL, not a substitute projector.
    sqlx::query("PRAGMA foreign_keys=OFF")
        .execute(&mut *conn)
        .await
        .unwrap();
    sqlx::query("DELETE FROM records")
        .execute(&mut *conn)
        .await
        .unwrap();
    sqlx::query("DELETE FROM policy_entries")
        .execute(&mut *conn)
        .await
        .unwrap();
    sqlx::query("DELETE FROM record_policies")
        .execute(&mut *conn)
        .await
        .unwrap();
    sqlx::query("PRAGMA foreign_keys=ON")
        .execute(&mut *conn)
        .await
        .unwrap();
    for table in crate::schema::META_PROJECTION_TABLES {
        sqlx::query(&format!("DELETE FROM {table}"))
            .execute(&mut *conn)
            .await
            .unwrap();
    }
    crate::projector::meta::replay_meta(&mut conn, &events)
        .await
        .unwrap();
    let actual: String =
        sqlx::query_scalar("SELECT snapshot_json FROM workspace_rule_installations")
            .fetch_one(&mut *conn)
            .await
            .unwrap();
    assert_eq!(actual, expected);
    drop(conn);
    replay.close().await;
    let dir = tempfile::tempdir().unwrap();
    let exported = crate::export::export_connected_db(&db, Some(dir.path()))
        .await
        .unwrap();
    let mut exported_conn = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new()
            .filename(exported.path())
            .read_only(true),
    )
    .await
    .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT snapshot_json FROM workspace_rule_installations")
            .fetch_one(&mut exported_conn)
            .await
            .unwrap(),
        expected
    );
    exported_conn.close().await.unwrap();
    db.close().await;
}

#[test]
fn fixture_receipt_is_explicit_and_only_test_issuer_can_mint_token() {
    let p = admit(revision()).snapshot;
    assert_eq!(p.receipt.evidence.engine_id, ri::FIXTURE_ENGINE_ID);
    assert!(ri::ensure_non_fixture_evidence(&p.receipt.evidence.legacy()).is_err());
    if let Ok(path) = std::env::var("V1_STORE_FIXTURE_OUT") {
        std::fs::write(
            path,
            serde_json::to_string(&serde_json::to_value(&p).unwrap()).unwrap(),
        )
        .unwrap();
    }
}

#[test]
fn unicode_new_store_bindings_preserve_historical_evidence_and_full_sequence() {
    let mut r = revision();
    r.examples.push(ri::RuleExample {
        name: "unicode-example".into(),
        body: json!({"\u{e000}":1,"😀":2}),
    });
    let mut p = admit(r.clone()).snapshot;
    // Independently reviewed exact old Unicode inputs, not updated legacy pins.
    assert_eq!(
        p.receipt.evidence.revision_digest,
        "d49074c7589acc36ecca7077ad7c55bc421351ebe338fd4fb7fa643a2a7267e6"
    );
    assert_eq!(
        p.receipt.evidence.settings_digest,
        "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
    );
    assert_eq!(
        p.readset_digest,
        "2416e0a5d8e0a56598c08d0f13507bc32ff59bbd81420baf80fdf4b2a298ff76"
    );
    assert_eq!(
        p.revision_digest,
        "90168689b885b62b81fb04153db332a7f12e67311b2fa093058f560810c496f6"
    );
    assert_ne!(
        p.revision_digest,
        crate::canonical_json::digest_json(&p.revision.identity())
    );
    assert_ne!(
        digest(&p).unwrap(),
        crate::canonical_json::digest_json(&serde_json::to_value(&p).unwrap())
    );
    // Host sequences have no unrelated example-safe-number cap or rounding.
    p.previous_seq = Some(i64::MAX);
    verify(&p, &subject("test_ns", "records"), Some("acct:alice")).unwrap();
    let bytes = serde_json::to_string(&serde_json::to_value(&p).unwrap()).unwrap();
    let decoded = decode(&bytes).unwrap();
    assert_eq!(decoded.previous_seq, Some(i64::MAX));
    assert_eq!(digest(&decoded).unwrap(), digest(&p).unwrap());
    assert!(
        String::from_utf8(canonical::encode(&serde_json::to_value(&p).unwrap()))
            .unwrap()
            .contains("\"previous_seq\":9223372036854775807")
    );
    let preimages = [
        ("revision", p.revision.identity()),
        ("settings", serde_json::to_value(&p.settings).unwrap()),
        ("metadata", serde_json::to_value(&p.metadata).unwrap()),
        ("catalog", serde_json::to_value(&p.catalog).unwrap()),
        ("orders", serde_json::to_value(&p.orders).unwrap()),
        ("receipt", serde_json::to_value(&p.receipt).unwrap()),
        ("snapshot", serde_json::to_value(&p).unwrap()),
    ];
    let expected = [
        &p.revision_digest,
        &p.settings_digest,
        &p.metadata_digest,
        &p.catalog_digest,
        &p.order_digest,
        &p.receipt_digest,
    ];
    for ((_, value), hash) in preimages.iter().zip(expected) {
        assert_eq!(&canonical::digest(value), hash);
    }
    if let Ok(path) = std::env::var("V1_STORE_CANONICAL_OUT") {
        let controls: Vec<_> = preimages
            .iter()
            .map(|(id, value)| {
                json!({
                    "id": id, "input": serde_json::to_string(value).unwrap(),
                    "bytes": String::from_utf8(canonical::encode(value)).unwrap(),
                    "sha256": canonical::digest(value)
                })
            })
            .collect();
        std::fs::write(path, serde_json::to_string_pretty(&controls).unwrap()).unwrap();
    }
    let mut bad = p.clone();
    bad.revision_digest = crate::canonical_json::digest_json(&bad.revision.identity());
    bad.receipt.revision_digest = bad.revision_digest.clone();
    bad.receipt_digest = digest(&bad.receipt).unwrap();
    assert!(verify(&bad, &subject("test_ns", "records"), Some("acct:alice")).is_err());
    r.examples[0].body = json!(9007199254740993u64);
    assert!(ri::validate_revision_shape(&r).is_err());
}

#[tokio::test]
async fn canonical_revision_permutation_does_not_mint_an_event() {
    let db = fixture().await;
    let mut original = revision();
    original.examples.push(ri::RuleExample {
        name: "unicode".into(),
        body: json!({"\u{e000}":1,"😀":2,"a":[{"\n":3,"z":4}]}),
    });
    original.inputs[0].sql = "SELECT id,name FROM records ORDER BY id".into();
    original.inputs[0].required_fields.push("name".into());
    let shape::RuleInputContract::ScalarRowsV1 { fields, .. } =
        original.inputs[0].contract.as_mut().unwrap();
    fields.push(shape::ScalarField {
        name: "name".into(),
        scalar_type: shape::ScalarType::String,
        nullable: true,
        canonical_integer_text: false,
    });
    let (first, _) = set(&db, "acct:alice", admit(original.clone()), None)
        .await
        .unwrap();
    original.inputs[0].required_fields.reverse();
    let shape::RuleInputContract::ScalarRowsV1 { fields, .. } =
        original.inputs[0].contract.as_mut().unwrap();
    fields.reverse();
    original.examples[0].body = json!({"a":[{"z":4,"\n":3}],"😀":2,"\u{e000}":1});
    let (retry, changed) = set(&db, "acct:alice", admit(original), Some(first.seq))
        .await
        .unwrap();
    assert!(!changed);
    assert_eq!(retry.seq, first.seq);
    assert_eq!(count(&db).await, 1);
    db.close().await;
}

#[tokio::test]
async fn complete_zero_sql_advisor_revision_and_guard_dag_survive_storage() {
    let db = fixture().await;
    let mut zero = revision();
    zero.name = "completion".into();
    zero.inputs.clear();
    zero.scalar_arguments.push(shape::ScalarArgument {
        name: "completed".into(),
        scalar_type: shape::ScalarType::Bool,
        nullable: true,
        source: shape::ScalarSource::CompletionV1 {
            fact: shape::CompletionFact::CompletionTransition,
        },
    });
    zero.clauses = "completed == true".into();
    let advisor = Advisor {
        watch: Watch::WorkItemCompletionV1,
        hooks: vec![Hook::CreateRecord, Hook::UpdateRecord],
        level: Level::Warn,
    };
    let (stored, _) = set(
        &db,
        "acct:alice",
        admit_with_metadata(zero.clone(), Some(advisor)),
        None,
    )
    .await
    .unwrap();
    assert_eq!(stored.snapshot.revision.content, zero);
    assert!(stored.snapshot.orders.proofs.is_empty());
    let mut dag = revision();
    dag.name = "dag".into();
    let mut first = dag.inputs[0].clone();
    first.name = "first".into();
    first.sql = "SELECT id FROM records WHERE id='first'".into();
    first.cardinality = ri::RuleCardinality::One;
    let mut second = first.clone();
    second.name = "second".into();
    second.sql = "SELECT id FROM records WHERE id='second'".into();
    let shape::RuleInputContract::ScalarRowsV1 { required_when, .. } =
        second.contract.as_mut().unwrap();
    *required_when = Some(shape::RequiredWhen {
        expression: "first != null".into(),
        inputs: vec!["first".into()],
    });
    dag.inputs = vec![second, first];
    let (stored, _) = set(&db, "acct:alice", admit(dag.clone()), None)
        .await
        .unwrap();
    assert_eq!(stored.snapshot.orders.input_order, vec!["first", "second"]);
    assert_eq!(stored.snapshot.revision.content, dag);
    let mut tampered = stored.snapshot.clone();
    tampered.orders.input_order.reverse();
    tampered.order_digest = digest(&tampered.orders).unwrap();
    tampered.receipt.order_digest = tampered.order_digest.clone();
    tampered.receipt_digest = digest(&tampered.receipt).unwrap();
    assert!(verify(&tampered, &subject("test_ns", "dag"), Some("acct:alice")).is_err());
    assert!(
        crate::conformance::rebuild_and_diff_meta(&db)
            .await
            .unwrap()
            .equal
    );
    db.close().await;
}
