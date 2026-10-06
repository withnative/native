use super::*;
use crate::conformance::rebuild_and_diff_control;
use crate::mcp::tools::alpha_tabs::alpha_tab_declaration_digest;
use serde_json::json;

const ARTIFACT: &str = "c07f0000-0000-4000-8000-000000000010";

async fn append(db: &Db, payload: ControlEventPayload) -> Result<ControlEventRow> {
    append_control_event(
        db,
        NewControlEvent::authored(
            uuid::Uuid::new_v4().to_string(),
            alpha_tab_aggregate_id("acct_alice", "test.provenance"),
            "acct_alice",
            None,
            "provenance foundation test",
            payload,
        )?,
    )
    .await
}

pub(crate) async fn fixture(method: Option<&str>) -> (Db, AlphaTabStatePayload, String) {
    let db = crate::create_database(":memory:").await.unwrap();
    crate::store::create_record(
        &db,
        json!({"id":ARTIFACT,"type":"Document","kind":"note","name":"test"}),
    )
    .await
    .unwrap();
    let declaration = json!({"needs":["z","a"],"effects":[]});
    let mut pin = AlphaTabStatePayload {
        account_id: "acct_alice".into(),
        package: "test.provenance".into(),
        version: "v1".into(),
        digest: format!("sha256:{}", "a".repeat(64)),
        artifact_id: ARTIFACT.into(),
        consented_source_revision: "source-1".into(),
        declaration_digest: alpha_tab_declaration_digest(&declaration).unwrap(),
        consented_declaration: declaration,
        adoption: ALPHA_TAB_ADOPTION_CALLER_ASSERTED.into(),
        request: Some("Keep this request".into()),
        previous_event_id: None,
    };
    let mut token = append(&db, ControlEventPayload::AlphaTabInstalled(pin.clone()))
        .await
        .unwrap()
        .id;
    if let Some(method) = method {
        token = adopt(&db, &pin, &token, method).await;
        pin.adoption = method.into();
    }
    (db, pin, token)
}

pub(crate) async fn adopt(
    db: &Db,
    pin: &AlphaTabStatePayload,
    token: &str,
    method: &str,
) -> String {
    let preview = method == ALPHA_TAB_ADOPTION_VERIFIED;
    append(
        db,
        ControlEventPayload::AlphaTabAdopted(AlphaTabAdoptPayload {
            account_id: pin.account_id.clone(),
            package: pin.package.clone(),
            version: pin.version.clone(),
            digest: pin.digest.clone(),
            artifact_id: pin.artifact_id.clone(),
            consented_source_revision: pin.consented_source_revision.clone(),
            declaration_digest: pin.declaration_digest.clone(),
            consented_declaration: pin.consented_declaration.clone(),
            adoption: method.into(),
            previous_event_id: token.into(),
            receipt_id: preview.then(|| "receipt".into()),
            preview_session: preview.then(|| "session".into()),
            launch_id: (!preview).then(|| "asserted-launch".into()),
            authored_run_key: (!preview).then(|| "asserted-pane-run".into()),
            request: (!preview).then(|| pin.request.clone()).flatten(),
        }),
    )
    .await
    .unwrap()
    .id
}

pub(crate) async fn provenance(db: &Db) -> Option<AlphaTabAdoptionProvenance> {
    let text: Option<String> = sqlx::query_scalar(
        "SELECT adoption_provenance FROM alpha_tab_installs WHERE package='test.provenance'",
    )
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    text.map(|text| serde_json::from_str(&text).unwrap())
}

pub(crate) async fn update(
    db: &Db,
    pin: &AlphaTabStatePayload,
    token: &str,
    declaration: Value,
) -> AlphaTabUpdatePayload {
    let declaration_digest = alpha_tab_declaration_digest(&declaration).unwrap();
    let mut p = provenance(db).await;
    let carry = p.is_some() && declaration_digest == pin.declaration_digest;
    if carry {
        p.as_mut().unwrap().carried_from_event_id = Some(token.into());
    } else {
        p = None;
    }
    let status: String =
        sqlx::query_scalar("SELECT status FROM alpha_tab_installs WHERE package='test.provenance'")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
    AlphaTabUpdatePayload {
        account_id: pin.account_id.clone(),
        package: pin.package.clone(),
        version: format!("{}+next", pin.version),
        digest: format!("sha256:{}", "c".repeat(64)),
        artifact_id: pin.artifact_id.clone(),
        consented_source_revision: format!("{}+next", pin.consented_source_revision),
        declaration_digest,
        consented_declaration: declaration,
        previous_event_id: token.into(),
        previous_pin_digest: alpha_tab_pin_digest(pin).unwrap(),
        status,
        request: pin.request.clone(),
        command_digest: "d".repeat(64),
        adoption: if carry {
            pin.adoption.clone()
        } else {
            ALPHA_TAB_ADOPTION_CALLER_ASSERTED.into()
        },
        adoption_basis: if carry {
            "carried"
        } else {
            "requires_adoption"
        }
        .into(),
        adoption_provenance: p,
    }
}

pub(crate) fn updated_pin(update: &AlphaTabUpdatePayload) -> AlphaTabStatePayload {
    AlphaTabStatePayload {
        account_id: update.account_id.clone(),
        package: update.package.clone(),
        version: update.version.clone(),
        digest: update.digest.clone(),
        artifact_id: update.artifact_id.clone(),
        consented_source_revision: update.consented_source_revision.clone(),
        declaration_digest: update.declaration_digest.clone(),
        consented_declaration: update.consented_declaration.clone(),
        adoption: update.adoption.clone(),
        request: update.request.clone(),
        previous_event_id: None,
    }
}

pub(crate) async fn append_update(db: &Db, update: &AlphaTabUpdatePayload) -> String {
    append(
        db,
        ControlEventPayload::AlphaTabUpdated(Box::new(update.clone())),
    )
    .await
    .unwrap()
    .id
}

pub(crate) async fn transition(
    db: &Db,
    pin: &AlphaTabStatePayload,
    token: &str,
    kind: &str,
) -> String {
    let mut value = pin.clone();
    value.previous_event_id = Some(token.into());
    // Match the existing public transition producer, including restore reset.
    value.adoption = ALPHA_TAB_ADOPTION_CALLER_ASSERTED.into();
    let payload = match kind {
        "disable" => ControlEventPayload::AlphaTabDisabled(value),
        "restore" => ControlEventPayload::AlphaTabRestored(value),
        "remove" => ControlEventPayload::AlphaTabRemoved(value),
        "install" => ControlEventPayload::AlphaTabInstalled(value),
        _ => unreachable!(),
    };
    append(db, payload).await.unwrap().id
}

#[tokio::test]
async fn alpha_tab_provenance_multiple_carries_keep_original_review_and_pending_breaks_chain() {
    let (db, mut pin, mut token) = fixture(Some(ALPHA_TAB_ADOPTION_VERIFIED)).await;
    let root = provenance(&db).await.unwrap();
    assert_eq!(root.original_adoption_event_id, token);
    assert_eq!(root.reviewed_source_revision.as_deref(), Some("source-1"));
    assert_eq!(
        root.reviewed_bundle_digest.as_deref(),
        Some(pin.digest.as_str())
    );
    let disabled = transition(&db, &pin, &token, "disable").await;
    assert_eq!(provenance(&db).await.as_ref(), Some(&root));
    let u = update(
        &db,
        &pin,
        &disabled,
        json!({"needs":["a","z"],"effects":[]}),
    )
    .await;
    assert_eq!(u.status, "disabled");
    token = append_update(&db, &u).await;
    pin = updated_pin(&u);
    assert!(rebuild_and_diff_control(&db).await.unwrap().equal);
    for _ in 0..2 {
        let u = update(&db, &pin, &token, pin.consented_declaration.clone()).await;
        assert_eq!(u.adoption_basis, "carried");
        token = append_update(&db, &u).await;
        pin = updated_pin(&u);
        let p = provenance(&db).await.unwrap();
        assert_eq!(
            p.original_adoption_event_id,
            root.original_adoption_event_id
        );
        assert_eq!(p.reviewed_source_revision, root.reviewed_source_revision);
        assert!(rebuild_and_diff_control(&db).await.unwrap().equal);
    }
    let changed = update(&db, &pin, &token, json!({"needs":["a"],"effects":[]})).await;
    assert_eq!(changed.adoption_basis, "requires_adoption");
    token = append_update(&db, &changed).await;
    pin = updated_pin(&changed);
    assert!(provenance(&db).await.is_none());
    let back = update(&db, &pin, &token, json!({"needs":["z","a"],"effects":[]})).await;
    assert_eq!(back.adoption, ALPHA_TAB_ADOPTION_CALLER_ASSERTED);
    assert_eq!(back.adoption_basis, "requires_adoption");
    token = append_update(&db, &back).await;
    pin = updated_pin(&back);
    assert!(provenance(&db).await.is_none());
    token = transition(&db, &pin, &token, "restore").await;
    token = adopt(&db, &pin, &token, ALPHA_TAB_ADOPTION_VERIFIED).await;
    pin.adoption = ALPHA_TAB_ADOPTION_VERIFIED.into();
    assert_ne!(
        provenance(&db).await.unwrap().original_adoption_event_id,
        root.original_adoption_event_id
    );
    let removed = transition(&db, &pin, &token, "remove").await;
    assert!(provenance(&db).await.is_none());
    pin.adoption = ALPHA_TAB_ADOPTION_CALLER_ASSERTED.into();
    token = transition(&db, &pin, &removed, "install").await;
    let reinstalled = update(&db, &pin, &token, pin.consented_declaration.clone()).await;
    assert_eq!(reinstalled.adoption_basis, "requires_adoption");
    append_update(&db, &reinstalled).await;
    assert!(rebuild_and_diff_control(&db).await.unwrap().equal);
    db.close().await;
}

#[tokio::test]
async fn alpha_tab_provenance_shell_auto_carry_never_claims_preview() {
    let (db, pin, token) = fixture(Some(ALPHA_TAB_ADOPTION_SHELL_AUTO)).await;
    let direct = provenance(&db).await.unwrap();
    assert!(direct.reviewed_source_revision.is_none());
    assert!(direct.reviewed_bundle_digest.is_none());
    assert_eq!(direct.launch_id.as_deref(), Some("asserted-launch"));
    assert_eq!(
        direct.original_source_revision,
        pin.consented_source_revision
    );
    let u = update(&db, &pin, &token, pin.consented_declaration.clone()).await;
    append_update(&db, &u).await;
    let carried = provenance(&db).await.unwrap();
    assert_eq!(
        carried.original_adoption_method,
        ALPHA_TAB_ADOPTION_SHELL_AUTO
    );
    assert_eq!(carried.authored_run_key, direct.authored_run_key);
    assert!(carried.reviewed_bundle_digest.is_none());
    let mut registry = crate::mcp::ToolRegistry::new();
    crate::mcp::tools::alpha_tabs::register_alpha_tab_tools(&mut registry).unwrap();
    for action in ["inspect", "list"] {
        let result = registry
            .call(
                db.clone(),
                crate::mcp::Caller::authenticated("acct_alice"),
                "manage_alpha_tabs",
                if action == "inspect" {
                    json!({"action":action,"package":pin.package})
                } else {
                    json!({"action":action})
                },
            )
            .await
            .unwrap();
        let displayed = if action == "inspect" {
            &result["install"]
        } else {
            &result["installs"][0]
        };
        let output = displayed["adoption_provenance"].as_object().unwrap();
        assert!(!output.contains_key("launch_id"));
        assert!(!output.contains_key("authored_run_key"));
    }
    assert!(rebuild_and_diff_control(&db).await.unwrap().equal);
    db.close().await;
}

#[tokio::test]
async fn alpha_tab_provenance_forged_carries_and_inconsistent_predecessors_rollback() {
    let (db, pin, token) = fixture(Some(ALPHA_TAB_ADOPTION_VERIFIED)).await;
    let good = update(&db, &pin, &token, pin.consented_declaration.clone()).await;
    let original = provenance(&db).await;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM control_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    let mut cases = Vec::new();
    let mut bad = good.clone();
    bad.adoption_provenance
        .as_mut()
        .unwrap()
        .original_adoption_event_id = "forged-root".into();
    cases.push(bad);
    let mut bad = good.clone();
    bad.adoption_provenance
        .as_mut()
        .unwrap()
        .carried_from_event_id = Some("forged-predecessor".into());
    cases.push(bad);
    let mut bad = good.clone();
    bad.declaration_digest = "f".repeat(64);
    cases.push(bad);
    let mut bad = good.clone();
    bad.previous_pin_digest = "f".repeat(64);
    cases.push(bad);
    let mut bad = good.clone();
    bad.previous_event_id = "stale".into();
    cases.push(bad);
    let mut bad = good.clone();
    bad.status = "disabled".into();
    cases.push(bad);
    let mut bad = good.clone();
    bad.request = None;
    cases.push(bad);
    let mut bad = good.clone();
    bad.consented_declaration = json!({"needs":[],"effects":[]});
    bad.declaration_digest = alpha_tab_declaration_digest(&bad.consented_declaration).unwrap();
    cases.push(bad);
    let mut bad = good.clone();
    bad.adoption = ALPHA_TAB_ADOPTION_SHELL_AUTO.into();
    cases.push(bad);
    let mut bad = good.clone();
    bad.adoption_provenance = None;
    cases.push(bad);
    for bad in cases {
        assert!(
            append(&db, ControlEventPayload::AlphaTabUpdated(Box::new(bad)))
                .await
                .is_err()
        );
        assert_eq!(provenance(&db).await, original);
        let now: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM control_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(now, count);
    }
    // Projection corruption cannot confer a carry, even if the incoming claim is honest.
    sqlx::query("UPDATE alpha_tab_installs SET adoption_provenance=NULL")
        .execute(db.write_pool())
        .await
        .unwrap();
    assert!(
        append(&db, ControlEventPayload::AlphaTabUpdated(Box::new(good)))
            .await
            .is_err()
    );
    db.close().await;
    let (db, pin, token) = fixture(None).await;
    let mut u = update(&db, &pin, &token, pin.consented_declaration.clone()).await;
    u.adoption = ALPHA_TAB_ADOPTION_VERIFIED.into();
    u.adoption_basis = "carried".into();
    u.adoption_provenance = original;
    assert!(
        append(&db, ControlEventPayload::AlphaTabUpdated(Box::new(u)))
            .await
            .is_err()
    );
    db.close().await;
}

#[tokio::test]
async fn alpha_tab_provenance_restore_clears_eligibility_and_fresh_adopt_starts_new_root() {
    for method in [ALPHA_TAB_ADOPTION_VERIFIED, ALPHA_TAB_ADOPTION_SHELL_AUTO] {
        let (db, mut pin, token) = fixture(Some(method)).await;
        let original = provenance(&db).await.unwrap();
        let disabled = transition(&db, &pin, &token, "disable").await;
        assert_eq!(provenance(&db).await.as_ref(), Some(&original));
        let u = update(&db, &pin, &disabled, pin.consented_declaration.clone()).await;
        assert_eq!(u.adoption_basis, "carried");
        assert_eq!(u.status, "disabled");
        let carried = append_update(&db, &u).await;
        pin = updated_pin(&u);
        assert!(rebuild_and_diff_control(&db).await.unwrap().equal);
        let restored = transition(&db, &pin, &carried, "restore").await;
        pin.adoption = ALPHA_TAB_ADOPTION_CALLER_ASSERTED.into();
        assert!(provenance(&db).await.is_none());
        let adoption: String = sqlx::query_scalar(
            "SELECT adoption FROM alpha_tab_installs WHERE package='test.provenance'",
        )
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(adoption, ALPHA_TAB_ADOPTION_CALLER_ASSERTED);
        let pending = update(&db, &pin, &restored, pin.consented_declaration.clone()).await;
        assert_eq!(pending.adoption_basis, "requires_adoption");
        let mut forged = pending.clone();
        forged.adoption = method.into();
        forged.adoption_basis = "carried".into();
        forged.adoption_provenance = Some(original.clone());
        assert!(
            append(&db, ControlEventPayload::AlphaTabUpdated(Box::new(forged)))
                .await
                .is_err()
        );
        let pending_token = append_update(&db, &pending).await;
        pin = updated_pin(&pending);
        let fresh = adopt(&db, &pin, &pending_token, method).await;
        pin.adoption = method.into();
        let root = provenance(&db).await.unwrap();
        assert_eq!(root.original_adoption_event_id, fresh);
        assert_ne!(
            root.original_adoption_event_id,
            original.original_adoption_event_id
        );
        assert!(root.carried_from_event_id.is_none());
        let next = update(&db, &pin, &fresh, pin.consented_declaration.clone()).await;
        assert_eq!(next.adoption_basis, "carried");
        append_update(&db, &next).await;
        assert!(rebuild_and_diff_control(&db).await.unwrap().equal);
        db.close().await;
    }
}

// Keep the historical migration future out of each caller's inline async frame.
// Custody, awaits, transactions and assertions stay in this borrowed test future.
fn migrate_77_and_compare(db: &Db) -> impl std::future::Future<Output = ()> + '_ {
    Box::pin(async move {
        let expected = provenance(db).await;
        let mut conn = db.write_pool().acquire().await.unwrap();
        sqlx::query("DROP TABLE facet_value_json_nodes")
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("DROP TABLE schema_config_json_nodes")
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("DROP TABLE workspace_rule_installations")
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("ALTER TABLE alpha_tab_installs DROP COLUMN body_read_admission_event_id")
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("ALTER TABLE alpha_tab_installs DROP COLUMN adoption_provenance")
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("PRAGMA user_version=77")
            .execute(&mut *conn)
            .await
            .unwrap();
        assert_eq!(
            crate::db::schema_shape_contract_sha256_for_test(&mut conn)
                .await
                .unwrap(),
            crate::db::ENGINE_77_SHAPE_CONTRACT_SHA256
        );
        let edge = crate::migrations::EngineMigrationRegistry::production()
            .pending(77, 78)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(edge.name(), "engine-77-to-78-alpha-tab-adoption-provenance");
        edge.preflight(&mut conn).await.unwrap();
        let mut tx = conn.begin().await.unwrap();
        edge.apply(&mut tx).await.unwrap();
        sqlx::query("PRAGMA user_version=78")
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert!(crate::db::validate_engine_shape_on_for_test(&mut conn, 78)
            .await
            .unwrap());
        alpha_tab_provenance::backfill(&mut conn).await.unwrap();
        let edge79 = crate::migrations::EngineMigrationRegistry::production()
            .pending(78, 79)
            .unwrap()
            .pop()
            .unwrap();
        edge79.preflight(&mut conn).await.unwrap();
        let mut tx = conn.begin().await.unwrap();
        edge79.apply(&mut tx).await.unwrap();
        sqlx::query("PRAGMA user_version=79")
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert!(crate::db::validate_engine_shape_on_for_test(&mut conn, 79)
            .await
            .unwrap());
        let minted: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM alpha_tab_installs WHERE body_read_admission_event_id IS NOT NULL",
        )
        .fetch_one(&mut *conn)
        .await
        .unwrap();
        assert_eq!(minted, 0);
        drop(conn);
        assert_eq!(provenance(db).await, expected);
        assert!(rebuild_and_diff_control(db).await.unwrap().equal);

        // Restore both current carriers after the historical alpha assertions
        // so the next lifecycle iteration starts from the same current schema.
        let mut conn = db.write_pool().acquire().await.unwrap();
        let edge80 = crate::migrations::EngineMigrationRegistry::production()
            .pending(79, 80)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(
            edge80.name(),
            "engine-79-to-80-workspace-rule-installations"
        );
        edge80.preflight(&mut conn).await.unwrap();
        let mut tx = conn.begin().await.unwrap();
        edge80.apply(&mut tx).await.unwrap();
        sqlx::query("PRAGMA user_version=80")
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert!(crate::db::validate_engine_shape_on_for_test(&mut conn, 80)
            .await
            .unwrap());
        let installations: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM workspace_rule_installations")
                .fetch_one(&mut *conn)
                .await
                .unwrap();
        assert_eq!(installations, 0);
        let edge81 = crate::migrations::EngineMigrationRegistry::production()
            .pending(80, 81)
            .unwrap()
            .pop()
            .unwrap();
        edge81.preflight(&mut conn).await.unwrap();
        let mut tx = conn.begin().await.unwrap();
        edge81.apply(&mut tx).await.unwrap();
        sqlx::query("PRAGMA user_version=81")
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert!(crate::db::validate_engine_shape_on_for_test(&mut conn, 81)
            .await
            .unwrap());
        let edge82 = crate::migrations::EngineMigrationRegistry::production()
            .pending(81, 82)
            .unwrap()
            .pop()
            .unwrap();
        edge82.preflight(&mut conn).await.unwrap();
        let mut tx = conn.begin().await.unwrap();
        edge82.apply(&mut tx).await.unwrap();
        sqlx::query("PRAGMA user_version=82")
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert!(crate::db::validate_engine_shape_on_for_test(&mut conn, 82)
            .await
            .unwrap());
    })
}

#[tokio::test]
async fn alpha_tab_provenance_engine_77_to_78_backfill_matches_fresh_and_rebuilt_lifecycle() {
    for method in [ALPHA_TAB_ADOPTION_VERIFIED, ALPHA_TAB_ADOPTION_SHELL_AUTO] {
        let (db, mut pin, mut token) = fixture(Some(method)).await;
        migrate_77_and_compare(&db).await;
        token = transition(&db, &pin, &token, "disable").await;
        migrate_77_and_compare(&db).await;
        token = transition(&db, &pin, &token, "restore").await;
        pin.adoption = ALPHA_TAB_ADOPTION_CALLER_ASSERTED.into();
        migrate_77_and_compare(&db).await;
        token = adopt(&db, &pin, &token, method).await;
        pin.adoption = method.into();
        migrate_77_and_compare(&db).await;
        token = transition(&db, &pin, &token, "remove").await;
        migrate_77_and_compare(&db).await;
        pin.adoption = ALPHA_TAB_ADOPTION_CALLER_ASSERTED.into();
        transition(&db, &pin, &token, "install").await;
        migrate_77_and_compare(&db).await;
        db.close().await;
    }
    let (db, _, _) = fixture(None).await;
    migrate_77_and_compare(&db).await;
    db.close().await;
}

#[tokio::test]
async fn alpha_tab_provenance_legacy_missing_adoption_evidence_is_not_guessed() {
    let (db, mut pin, token) = fixture(None).await;
    let removed = transition(&db, &pin, &token, "remove").await;
    // Legacy state events could contain shell_adopt without an adopted event.
    // Replay preserves their enum value, but cannot invent preview provenance.
    pin.adoption = ALPHA_TAB_ADOPTION_VERIFIED.into();
    pin.previous_event_id = Some(removed);
    let legacy = append(&db, ControlEventPayload::AlphaTabInstalled(pin.clone()))
        .await
        .unwrap();
    assert!(provenance(&db).await.is_none());
    migrate_77_and_compare(&db).await;
    let pending = update(&db, &pin, &legacy.id, pin.consented_declaration.clone()).await;
    assert_eq!(pending.adoption_basis, "requires_adoption");
    let mut u = pending.clone();
    u.adoption = ALPHA_TAB_ADOPTION_VERIFIED.into();
    u.adoption_basis = "carried".into();
    assert!(
        append(&db, ControlEventPayload::AlphaTabUpdated(Box::new(u)))
            .await
            .is_err()
    );
    append_update(&db, &pending).await;
    assert!(provenance(&db).await.is_none());
    assert!(rebuild_and_diff_control(&db).await.unwrap().equal);
    db.close().await;
}

#[tokio::test]
async fn alpha_tab_provenance_update_history_backfill_and_portable_export_replay_agree() {
    let (db, mut pin, token) = fixture(Some(ALPHA_TAB_ADOPTION_VERIFIED)).await;
    let u = update(&db, &pin, &token, pin.consented_declaration.clone()).await;
    let token = append_update(&db, &u).await;
    pin = updated_pin(&u);
    let disabled = transition(&db, &pin, &token, "disable").await;
    let u = update(&db, &pin, &disabled, pin.consented_declaration.clone()).await;
    append_update(&db, &u).await;
    let expected = provenance(&db).await;
    let mut conn = db.write_pool().acquire().await.unwrap();
    alpha_tab_provenance::backfill(&mut conn).await.unwrap();
    drop(conn);
    assert_eq!(provenance(&db).await, expected);
    assert!(rebuild_and_diff_control(&db).await.unwrap().equal);
    let bytes = crate::interchange::export_canonical_interchange(&db)
        .await
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    // The diagnostic fixture reached this await before default-stack overflow.
    // Box only its existing import future; keep it borrowed and awaited here.
    let copied = Box::pin(crate::interchange::import_canonical_interchange(
        &bytes,
        &dir.path().join("copy.db"),
        crate::interchange::ImportContinuity::ForeignBoundary,
    ))
    .await
    .unwrap();
    assert_eq!(provenance(&copied).await, None);
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT adoption FROM alpha_tab_installs")
            .fetch_one(copied.write_pool())
            .await
            .unwrap(),
        ALPHA_TAB_ADOPTION_CALLER_ASSERTED
    );
    assert!(rebuild_and_diff_control(&copied).await.unwrap().equal);
    migrate_77_and_compare(&copied).await;
    copied.close().await;
    db.close().await;
}

#[tokio::test]
async fn alpha_tab_provenance_inspect_and_list_expose_direct_carried_and_restored_basis() {
    let (db, mut pin, token) = fixture(Some(ALPHA_TAB_ADOPTION_VERIFIED)).await;
    let mut registry = crate::mcp::ToolRegistry::new();
    crate::mcp::tools::alpha_tabs::register_alpha_tab_tools(&mut registry).unwrap();
    let caller = crate::mcp::Caller::authenticated("acct_alice");
    let read = |operation: &str| json!({"action":operation,"package":"test.provenance"});
    let inspected = registry
        .call(
            db.clone(),
            caller.clone(),
            "manage_alpha_tabs",
            read("inspect"),
        )
        .await
        .unwrap();
    assert_eq!(inspected["install"]["adoption_basis"], "direct");
    let mut public_provenance = serde_json::to_value(provenance(&db).await.unwrap()).unwrap();
    let object = public_provenance.as_object_mut().unwrap();
    object.remove("launch_id");
    object.remove("authored_run_key");
    assert_eq!(
        inspected["install"]["adoption_provenance"],
        public_provenance
    );
    let u = update(&db, &pin, &token, pin.consented_declaration.clone()).await;
    let carried = append_update(&db, &u).await;
    pin = updated_pin(&u);
    let listed = registry
        .call(
            db.clone(),
            caller.clone(),
            "manage_alpha_tabs",
            json!({"action":"list"}),
        )
        .await
        .unwrap();
    assert_eq!(listed["installs"][0]["adoption_basis"], "carried");
    assert_eq!(
        listed["installs"][0]["adoption_provenance"]["carried_from_event_id"],
        token
    );
    let disabled = transition(&db, &pin, &carried, "disable").await;
    transition(&db, &pin, &disabled, "restore").await;
    let restored = registry
        .call(db.clone(), caller, "manage_alpha_tabs", read("inspect"))
        .await
        .unwrap();
    assert_eq!(restored["install"]["adoption_basis"], "requires_adoption");
    assert!(restored["install"]["adoption_provenance"].is_null());
    db.close().await;
}

#[tokio::test]
async fn alpha_tab_provenance_member_copy_v1_excludes_install_and_control_history() {
    use crate::standby_snapshot::{
        StandbyConsumerIdentity, StandbyConsumerPlatform, STANDBY_CONSUMER_CONTRACT,
    };
    let (db, pin, token) = fixture(Some(ALPHA_TAB_ADOPTION_VERIFIED)).await;
    let u = update(&db, &pin, &token, pin.consented_declaration.clone()).await;
    append_update(&db, &u).await;
    let dir = tempfile::tempdir().unwrap();
    let bytes = crate::interchange::export_canonical_interchange(&db)
        .await
        .unwrap();
    let imported = crate::interchange::import_canonical_interchange(
        &bytes,
        &dir.path().join("imported.db"),
        crate::interchange::ImportContinuity::ForeignBoundary,
    )
    .await
    .unwrap();
    let path = dir.path().join("member.db");
    crate::member_copy_producer::build_member_copy(
        &imported,
        crate::member_copy_producer::MemberCopyRequest {
            member_account: "acct_alice".into(),
            scope_ref: "scope-alpha".into(),
            hosted_route_database_id: "route-alpha".into(),
            ordinal: 1,
            out_path: path.clone(),
            consumer: StandbyConsumerIdentity {
                contract: STANDBY_CONSUMER_CONTRACT.into(),
                version: 1,
                platform: StandbyConsumerPlatform::LinuxX8664,
                source_sha: "c".repeat(40),
                artifact_sha256: "d".repeat(64),
                engine_schema_version: crate::CURRENT_ENGINE_SCHEMA_VERSION,
                ddl_sha256: "e".repeat(64),
            },
        },
    )
    .await
    .unwrap();
    let conn = rusqlite::Connection::open(path).unwrap();
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM sqlite_schema WHERE name IN ('alpha_tab_installs','control_events')",[], |row| row.get(0)).unwrap();
    assert_eq!(count, 0);
    imported.close().await;
    db.close().await;
}

#[tokio::test]
async fn alpha_tab_provenance_legacy_inconsistent_declaration_has_no_invented_preview() {
    let (db, pin, token) = fixture(None).await;
    // The historical adopt CAS compared stored digest strings, not declarations.
    // Preserve that historical fold, but annotate it with no proven root.
    let mut changed = pin.clone();
    changed.consented_declaration = json!({"needs":[],"effects":[]});
    adopt(&db, &changed, &token, ALPHA_TAB_ADOPTION_VERIFIED).await;
    assert!(provenance(&db).await.is_none());
    migrate_77_and_compare(&db).await;
    db.close().await;
}

#[tokio::test]
async fn alpha_tab_provenance_artifact_repoint_carry_passes_gate_and_keeps_original_preview() {
    use crate::mcp::tools::alpha_tabs::{evaluate_alpha_tab_install_gates, TargetState};
    let (db, pin, token) = fixture(Some(ALPHA_TAB_ADOPTION_VERIFIED)).await;
    let original = provenance(&db).await.unwrap();
    let artifact = "c07f0000-0000-4000-8000-000000000099";
    crate::store::create_record(
        &db,
        json!({"id":artifact,"type":"Document","kind":"artifact","name":"new artifact"}),
    )
    .await
    .unwrap();
    let mut carry = update(&db, &pin, &token, pin.consented_declaration.clone()).await;
    carry.artifact_id = artifact.into();
    let token = append_update(&db, &carry).await;
    let (status, adoption, actual_artifact): (String, String, String) =
        sqlx::query_as("SELECT status,adoption,artifact_id FROM alpha_tab_installs")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
    assert_eq!(actual_artifact, artifact);
    assert_eq!(
        evaluate_alpha_tab_install_gates(&status, &adoption, TargetState::Resolvable, true),
        Ok(())
    );
    let carried = provenance(&db).await.unwrap();
    assert_eq!(
        carried.reviewed_source_revision,
        original.reviewed_source_revision
    );
    assert_eq!(
        carried.reviewed_bundle_digest,
        original.reviewed_bundle_digest
    );
    assert_ne!(
        carried.reviewed_source_revision.as_deref(),
        Some(carry.consented_source_revision.as_str())
    );
    assert_ne!(
        carried.reviewed_bundle_digest.as_deref(),
        Some(carry.digest.as_str())
    );
    let mut registry = crate::mcp::ToolRegistry::new();
    crate::mcp::tools::alpha_tabs::register_alpha_tab_tools(&mut registry).unwrap();
    let inspected = registry
        .call(
            db.clone(),
            crate::mcp::Caller::authenticated("acct_alice"),
            "manage_alpha_tabs",
            json!({"action":"inspect","package":pin.package}),
        )
        .await
        .unwrap();
    assert_eq!(
        inspected["install"]["adoption_provenance"]["reviewed_source_revision"],
        original.reviewed_source_revision.unwrap()
    );
    let pin = updated_pin(&carry);
    let pending = update(&db, &pin, &token, json!({"needs":[],"effects":[]})).await;
    append_update(&db, &pending).await;
    let (status, adoption): (String, String) =
        sqlx::query_as("SELECT status,adoption FROM alpha_tab_installs")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
    assert_eq!(
        evaluate_alpha_tab_install_gates(&status, &adoption, TargetState::Resolvable, true),
        Err("adoption_unverified")
    );
    assert!(rebuild_and_diff_control(&db).await.unwrap().equal);
    db.close().await;
}

#[tokio::test]
async fn alpha_tab_provenance_new_restore_rejects_adopted_claim_but_legacy_replay_tolerates_it() {
    let (db, mut pin, token) = fixture(Some(ALPHA_TAB_ADOPTION_VERIFIED)).await;
    let disabled = transition(&db, &pin, &token, "disable").await;
    pin.previous_event_id = Some(disabled.clone());
    assert!(
        append(&db, ControlEventPayload::AlphaTabRestored(pin.clone()))
            .await
            .unwrap_err()
            .to_string()
            .contains("fresh adoption")
    );
    pin.adoption = ALPHA_TAB_ADOPTION_CALLER_ASSERTED.into();
    let restored = append(&db, ControlEventPayload::AlphaTabRestored(pin))
        .await
        .unwrap();
    // Simulate an immutable old log event without changing stored authority.
    let mut conn = db.write_pool().acquire().await.unwrap();
    let mut events = read_all_control_events(&mut conn).await.unwrap();
    let legacy = events
        .iter_mut()
        .find(|event| event.id == restored.id)
        .unwrap();
    let mut payload: AlphaTabStatePayload = decode(legacy).unwrap();
    payload.adoption = ALPHA_TAB_ADOPTION_VERIFIED.into();
    legacy.payload = serde_json::to_string(&payload).unwrap();
    assert!(validate_control_event(legacy).is_err());
    validate_stored_control_event(legacy).unwrap();
    drop(conn);
    let target = crate::create_database(":memory:").await.unwrap();
    crate::store::create_record(
        &target,
        json!({"id":ARTIFACT,"type":"Document","kind":"note","name":"legacy"}),
    )
    .await
    .unwrap();
    let mut conn = target.write_pool().acquire().await.unwrap();
    replay_control(&mut conn, &events).await.unwrap();
    let (adoption, provenance): (String, Option<String>) =
        sqlx::query_as("SELECT adoption,adoption_provenance FROM alpha_tab_installs")
            .fetch_one(&mut *conn)
            .await
            .unwrap();
    assert_eq!(adoption, ALPHA_TAB_ADOPTION_VERIFIED); // historical enum preserved
    assert!(provenance.is_none()); // restore cannot be an adoption root
    drop(conn);
    target.close().await;
    db.close().await;
}

#[tokio::test]
async fn alpha_tab_provenance_backfill_corrupt_chain_is_null_and_preserves_adoption() {
    let (db, pin, token) = fixture(Some(ALPHA_TAB_ADOPTION_VERIFIED)).await;
    // An inconsistent adoption method produces a history error, which the
    // additive backfill must log and downgrade to NULL evidence.
    let mut carry = update(&db, &pin, &token, pin.consented_declaration.clone()).await;
    append_update(&db, &carry).await;
    sqlx::query("UPDATE alpha_tab_installs SET adoption=?")
        .bind(ALPHA_TAB_ADOPTION_SHELL_AUTO)
        .execute(db.write_pool())
        .await
        .unwrap();
    let mut conn = db.write_pool().acquire().await.unwrap();
    alpha_tab_provenance::backfill(&mut conn).await.unwrap();
    let (adoption, provenance): (String, Option<String>) =
        sqlx::query_as("SELECT adoption,adoption_provenance FROM alpha_tab_installs")
            .fetch_one(&mut *conn)
            .await
            .unwrap();
    assert_eq!(adoption, ALPHA_TAB_ADOPTION_SHELL_AUTO);
    assert!(provenance.is_none());
    drop(conn);
    // An unknown future declaration key is digestible at the tier; mutable
    // producer allowlists must not prevent history fold.
    let (pending_db, pending_pin, token) = fixture(None).await;
    carry = update(
        &pending_db,
        &pending_pin,
        &token,
        json!({"needs":[],"effects":[],"future_producer_key":true}),
    )
    .await;
    append_update(&pending_db, &carry).await;
    assert!(rebuild_and_diff_control(&pending_db).await.unwrap().equal);
    pending_db.close().await;
    db.close().await;
}

#[tokio::test]
async fn alpha_tab_provenance_import_requires_a_durable_pending_boundary() {
    let (source, pin, original_root) = fixture(Some(ALPHA_TAB_ADOPTION_VERIFIED)).await;
    let bytes = crate::interchange::export_canonical_interchange(&source)
        .await
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let db = crate::interchange::import_canonical_interchange(
        &bytes,
        &dir.path().join("import.db"),
        crate::interchange::ImportContinuity::ForeignBoundary,
    )
    .await
    .unwrap();
    let (reset, status, adoption): (String, String, String) =
        sqlx::query_as("SELECT event_id,status,adoption FROM alpha_tab_installs")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
    assert_eq!(status, "installed");
    assert_eq!(adoption, ALPHA_TAB_ADOPTION_CALLER_ASSERTED);
    assert_ne!(reset, original_root);
    assert!(provenance(&db).await.is_none());
    assert!(rebuild_and_diff_control(&db).await.unwrap().equal);
    let mut pending_pin = pin.clone();
    pending_pin.adoption = ALPHA_TAB_ADOPTION_CALLER_ASSERTED.into();
    let pending = update(&db, &pending_pin, &reset, pin.consented_declaration.clone()).await;
    assert_eq!(pending.adoption_basis, "requires_adoption");
    assert!(pending.adoption_provenance.is_none());
    // A pre-import root can never authorize even a same-declaration carry.
    let mut forged = pending.clone();
    forged.adoption = ALPHA_TAB_ADOPTION_VERIFIED.into();
    forged.adoption_basis = "carried".into();
    let mut old = provenance(&source).await.unwrap();
    old.carried_from_event_id = Some(reset.clone());
    forged.adoption_provenance = Some(old);
    assert!(
        append(&db, ControlEventPayload::AlphaTabUpdated(Box::new(forged)))
            .await
            .is_err()
    );
    let pending_token = append_update(&db, &pending).await;
    pending_pin = updated_pin(&pending);
    assert!(rebuild_and_diff_control(&db).await.unwrap().equal);
    let new_root = adopt(
        &db,
        &pending_pin,
        &pending_token,
        ALPHA_TAB_ADOPTION_VERIFIED,
    )
    .await;
    pending_pin.adoption = ALPHA_TAB_ADOPTION_VERIFIED.into();
    let carry = update(
        &db,
        &pending_pin,
        &new_root,
        pin.consented_declaration.clone(),
    )
    .await;
    assert_eq!(carry.adoption_basis, "carried");
    assert_eq!(
        carry
            .adoption_provenance
            .as_ref()
            .unwrap()
            .original_adoption_event_id,
        new_root
    );
    assert_ne!(new_root, original_root);
    append_update(&db, &carry).await;
    assert!(rebuild_and_diff_control(&db).await.unwrap().equal);
    // A fresh adopt directly after reset also starts a root, without an update.
    let direct = crate::interchange::import_canonical_interchange(
        &bytes,
        &dir.path().join("direct.db"),
        crate::interchange::ImportContinuity::ForeignBoundary,
    )
    .await
    .unwrap();
    let token: String = sqlx::query_scalar("SELECT event_id FROM alpha_tab_installs")
        .fetch_one(direct.write_pool())
        .await
        .unwrap();
    let root = adopt(&direct, &pin, &token, ALPHA_TAB_ADOPTION_VERIFIED).await;
    let u = update(&direct, &pin, &root, pin.consented_declaration.clone()).await;
    assert_eq!(u.adoption_basis, "carried");
    append_update(&direct, &u).await;
    assert!(rebuild_and_diff_control(&direct).await.unwrap().equal);
    direct.close().await;
    db.close().await;
    source.close().await;
}

#[tokio::test]
async fn alpha_tab_provenance_import_reset_is_sealed_and_validated() {
    let (source, pin, _) = fixture(Some(ALPHA_TAB_ADOPTION_VERIFIED)).await;
    let bytes = crate::interchange::export_canonical_interchange(&source)
        .await
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let db = crate::interchange::import_canonical_interchange(
        &bytes,
        &dir.path().join("import.db"),
        crate::interchange::ImportContinuity::ForeignBoundary,
    )
    .await
    .unwrap();
    let mut conn = db.write_pool().acquire().await.unwrap();
    let reset = sqlx::query("SELECT seq,id,idempotency_key,type,schema_version,aggregate_kind,aggregate_id,actor,run_key,reason,payload,created_at,act FROM control_events WHERE type='alpha_tab.import_reset'")
        .fetch_one(&mut *conn).await.map(row_from_sql).unwrap().unwrap();
    assert!(validate_stored_control_event(&reset).is_ok());
    assert!(validate_control_event(&reset).is_err());
    let valid: AlphaTabImportResetPayload = decode(&reset).unwrap();
    for bad in [
        AlphaTabImportResetPayload {
            pin: pin.clone(),
            ..valid.clone()
        },
        AlphaTabImportResetPayload {
            adoption_provenance: Some(json!({})),
            ..valid.clone()
        },
    ] {
        let mut forged = reset.clone();
        forged.payload = serde_json::to_string(&bad).unwrap();
        assert!(validate_stored_control_event(&forged).is_err());
    }
    let mut bad_predecessor = valid.clone();
    bad_predecessor.pin.previous_event_id = Some("forged-predecessor".into());
    let mut forged = reset.clone();
    forged.seq += 1;
    forged.payload = serde_json::to_string(&bad_predecessor).unwrap();
    assert!(alpha_tab_provenance::fold_import_reset(&mut conn, &forged)
        .await
        .is_err());
    drop(conn);
    assert!(provenance(&db).await.is_none());
    assert!(append(&db, ControlEventPayload::AlphaTabImportReset(valid))
        .await
        .unwrap_err()
        .to_string()
        .contains("reserved for canonical import"));
    db.close().await;
    source.close().await;
}

#[tokio::test]
async fn alpha_tab_provenance_forged_import_events_never_confer_launch_eligibility() {
    use crate::mcp::tools::alpha_tabs::{evaluate_alpha_tab_install_gates, TargetState};
    for method in [ALPHA_TAB_ADOPTION_VERIFIED, ALPHA_TAB_ADOPTION_SHELL_AUTO] {
        // These test-authored event claims have no real preview receipt or pane
        // launch. They are structurally valid transport history, not consent.
        let (db, pin, token) = fixture(Some(method)).await;
        let carry = update(&db, &pin, &token, pin.consented_declaration.clone()).await;
        append_update(&db, &carry).await;
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM receipts")
                .fetch_one(db.write_pool())
                .await
                .unwrap(),
            0
        );
        let bytes = crate::interchange::export_canonical_interchange(&db)
            .await
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let imported = crate::interchange::import_canonical_interchange(
            &bytes,
            &dir.path().join("untrusted.db"),
            crate::interchange::ImportContinuity::ForeignBoundary,
        )
        .await
        .unwrap();
        let (status, adoption, provenance): (String, String, Option<String>) =
            sqlx::query_as("SELECT status,adoption,adoption_provenance FROM alpha_tab_installs")
                .fetch_one(imported.write_pool())
                .await
                .unwrap();
        assert_eq!(adoption, ALPHA_TAB_ADOPTION_CALLER_ASSERTED);
        assert!(provenance.is_none());
        assert_eq!(
            evaluate_alpha_tab_install_gates(&status, &adoption, TargetState::Resolvable, true),
            Err("adoption_unverified")
        );
        imported.close().await;
        db.close().await;
    }
}

#[tokio::test]
async fn alpha_tab_provenance_import_preserves_status_and_request_but_resets_every_chain() {
    for status in ["installed", "disabled", "removed"] {
        let (db, pin, token) = fixture(Some(ALPHA_TAB_ADOPTION_SHELL_AUTO)).await;
        if status != "installed" {
            transition(
                &db,
                &pin,
                &token,
                if status == "disabled" {
                    "disable"
                } else {
                    "remove"
                },
            )
            .await;
        }
        let bytes = crate::interchange::export_canonical_interchange(&db)
            .await
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let imported = crate::interchange::import_canonical_interchange(
            &bytes,
            &dir.path().join("copy.db"),
            crate::interchange::ImportContinuity::ForeignBoundary,
        )
        .await
        .unwrap();
        let (actual, request, adoption): (String, Option<String>, String) =
            sqlx::query_as("SELECT status,request,adoption FROM alpha_tab_installs")
                .fetch_one(imported.write_pool())
                .await
                .unwrap();
        assert_eq!(actual, status);
        assert_eq!(request, pin.request);
        assert_eq!(adoption, ALPHA_TAB_ADOPTION_CALLER_ASSERTED);
        assert!(provenance(&imported).await.is_none());
        assert!(rebuild_and_diff_control(&imported).await.unwrap().equal);
        migrate_77_and_compare(&imported).await;
        // Re-importing exported reset history creates another pending boundary.
        let again = crate::interchange::export_canonical_interchange(&imported)
            .await
            .unwrap();
        let twice = crate::interchange::import_canonical_interchange(
            &again,
            &dir.path().join("twice.db"),
            crate::interchange::ImportContinuity::ForeignBoundary,
        )
        .await
        .unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM control_events WHERE type='alpha_tab.import_reset'"
            )
            .fetch_one(twice.write_pool())
            .await
            .unwrap(),
            2
        );
        assert!(provenance(&twice).await.is_none());
        assert!(rebuild_and_diff_control(&twice).await.unwrap().equal);
        twice.close().await;
        imported.close().await;
        db.close().await;
    }
}
