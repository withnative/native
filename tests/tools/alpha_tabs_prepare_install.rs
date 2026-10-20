//! Preparation exercises the same registry/source/consent seams as installs.
use super::*;
use native_ce::mcp::tools::alpha_tabs::alpha_tab_bundle_digest;

fn prepare_args(artifact: &str, body: &str, declaration: Value) -> Value {
    json!({"action": "prepare_install", "artifact_id": artifact,
        "expected_body_digest": alpha_tab_bundle_digest(body),
        "package": "agent.prepared", "version": "1.0.0",
        "declaration": declaration, "reason": "Install the authored source."})
}

async fn prepare(registry: &ToolRegistry, db: &Db, args: Value) -> Value {
    call_as(
        registry,
        db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        args,
    )
    .await
    .unwrap()
}

async fn execute(registry: &ToolRegistry, db: &Db, prepared: &Value) -> native_ce::Result<Value> {
    let mut args = prepared["next_call"]["arguments"].clone();
    args["action"] = json!(prepared["next_call"]["operation"]
        .as_str()
        .unwrap()
        .strip_prefix("manage_alpha_tabs.")
        .unwrap());
    update_call(registry, db, args).await
}

#[tokio::test]
async fn prepare_install_returns_canonical_pin_without_writes_and_installs_it() {
    let (db, registry) = fixture().await;
    artifact(&registry, &db, ARTIFACT_A).await;
    grant(&db, ARTIFACT_A, ALICE, Capability::View).await;
    let declaration = declaration();
    let before = update_counts(&db).await;
    let prepared = prepare(
        &registry,
        &db,
        prepare_args(ARTIFACT_A, PREVIEW_BODY, declaration.clone()),
    )
    .await;
    assert_eq!(update_counts(&db).await, before);
    assert_eq!(prepared["ready"], true);
    assert_eq!(prepared["adoption"], "requires_person_preview_adopt");
    let vectors: Value = serde_json::from_str(include_str!(
        "../../packages/alpha-tab-kit/test/vectors/digest-vectors.json"
    ))
    .unwrap();
    assert_eq!(
        prepared["bundle_sha256"],
        vectors["bundle"][0]["bundle_sha256"]
    );
    assert_eq!(
        prepared["declaration_digest"],
        vectors["declaration"][0]["declaration_digest"]
    );
    assert_eq!(prepared["digest"], vectors["digest"][0]["digest"]);
    assert_eq!(
        prepared["source_revision"],
        preview_source_revision(&db, ARTIFACT_A).await
    );
    assert_eq!(
        prepared["next_call"]["operation"],
        "manage_alpha_tabs.install"
    );
    assert!(prepared["current_install_event_id"].is_null());
    assert_eq!(prepared["kit"]["available"], true);
    assert!(prepared["kit"]["policy"].is_null());
    let installed = execute(&registry, &db, &prepared).await.unwrap();
    assert_eq!(installed["install"]["digest"], prepared["digest"]);
    assert_eq!(installed["install"]["adoption"], "caller_asserted");
}

#[tokio::test]
async fn prepare_install_authorization_requires_view_and_scopes_install_to_caller() {
    let (db, registry) = fixture().await;
    let args = prepare_args(
        ARTIFACT_A,
        PREVIEW_BODY,
        json!({"needs": [], "effects": []}),
    );
    let missing = call_as(
        &registry,
        &db,
        Caller::authenticated(BEA),
        "manage_alpha_tabs",
        args.clone(),
    )
    .await
    .unwrap_err()
    .to_string();
    artifact(&registry, &db, ARTIFACT_A).await;
    grant(&db, ARTIFACT_A, ALICE, Capability::View).await;
    let alice = prepare(&registry, &db, args.clone()).await;
    assert_eq!(alice["ready"], true);
    let installed = execute(&registry, &db, &alice).await.unwrap();
    let alice_event = installed["install"]["event_id"].clone();

    let before = update_counts(&db).await;
    let denied = call_as(
        &registry,
        &db,
        Caller::authenticated(BEA),
        "manage_alpha_tabs",
        args.clone(),
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(denied, missing); // Neither source nor Alice's install is disclosed.
    assert_eq!(update_counts(&db).await, before);

    replace_explicit_policy(
        &db,
        "test:policy",
        ARTIFACT_A,
        vec![
            AllowEntry::account(ALICE, Capability::View),
            AllowEntry::account(BEA, Capability::View),
        ],
    )
    .await
    .unwrap();
    let before = update_counts(&db).await;
    let bea = call_as(
        &registry,
        &db,
        Caller::authenticated(BEA),
        "manage_alpha_tabs",
        args.clone(),
    )
    .await
    .unwrap();
    assert_eq!(bea["ready"], true);
    assert!(bea["current_install_event_id"].is_null());
    assert!(bea["current_install_status"].is_null());
    assert_eq!(bea["next_call"]["operation"], "manage_alpha_tabs.install");
    let alice = prepare(&registry, &db, args.clone()).await;
    assert_eq!(alice["current_install_event_id"], alice_event);
    assert_eq!(alice["next_call"]["operation"], "manage_alpha_tabs.update");
    assert_eq!(update_counts(&db).await, before);

    let mut install_args = bea["next_call"]["arguments"].clone();
    install_args["action"] = json!("install");
    let installed = call_as(
        &registry,
        &db,
        Caller::authenticated(BEA),
        "manage_alpha_tabs",
        install_args,
    )
    .await
    .unwrap();
    let bea_event = installed["install"]["event_id"].clone();
    assert_ne!(bea_event, alice_event);
    let bea = call_as(
        &registry,
        &db,
        Caller::authenticated(BEA),
        "manage_alpha_tabs",
        args.clone(),
    )
    .await
    .unwrap();
    assert_eq!(bea["current_install_event_id"], bea_event);
    assert_eq!(
        prepare(&registry, &db, args).await["current_install_event_id"],
        alice_event
    );
}

#[tokio::test]
async fn prepare_install_checks_guards_declaration_runtime_and_authority() {
    let (db, registry) = fixture().await;
    artifact(&registry, &db, ARTIFACT_A).await;
    note(&registry, &db, NOTE).await;
    grant(&db, ARTIFACT_A, ALICE, Capability::View).await;
    grant(&db, NOTE, ALICE, Capability::View).await;
    let good = prepare_args(
        ARTIFACT_A,
        PREVIEW_BODY,
        json!({"needs": [], "effects": []}),
    );
    let mut wrong = good.clone();
    wrong["expected_body_digest"] = json!("0".repeat(64));
    let refused = prepare(&registry, &db, wrong).await;
    assert_eq!(refused["findings"][0]["code"], "source_changed");
    assert!(refused["next_call"].is_null());
    let mut by_revision = good.clone();
    by_revision
        .as_object_mut()
        .unwrap()
        .remove("expected_body_digest");
    by_revision["expected_source_revision"] = json!(preview_source_revision(&db, ARTIFACT_A).await);
    assert_eq!(
        prepare(&registry, &db, by_revision.clone()).await["ready"],
        true
    );
    by_revision["expected_body_digest"] = json!("0".repeat(64));
    assert_eq!(
        prepare(&registry, &db, by_revision).await["findings"][0]["code"],
        "source_changed"
    );
    let mut bad_declaration = good.clone();
    bad_declaration["declaration"] =
        json!({"contract": "native.app.v2", "needs": ["attention.query.v1"], "effects": []});
    assert_eq!(
        prepare(&registry, &db, bad_declaration).await["findings"][0]["code"],
        "invalid_declaration"
    );
    let mut bad_target = good.clone();
    bad_target["artifact_id"] = json!(NOTE);
    assert_eq!(
        prepare(&registry, &db, bad_target).await["findings"][0]["code"],
        "invalid_target"
    );
    let denied = call_as(
        &registry,
        &db,
        Caller::authenticated(BEA),
        "manage_alpha_tabs",
        good.clone(),
    )
    .await;
    assert!(denied.is_err());
    // Normal writes enforce the required artifact facet. Legacy/imported
    // storage can lack it, and preparation must still refuse that source.
    sqlx::query("DELETE FROM facet_values WHERE record_id=? AND key='runtime'")
        .bind(ARTIFACT_A)
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    assert_eq!(
        prepare(&registry, &db, good).await["findings"][0]["code"],
        "runtime_mismatch"
    );
}

#[tokio::test]
async fn prepare_install_keeps_historical_pin_when_source_changes_and_requires_fresh_guard() {
    let (db, registry) = fixture().await;
    artifact(&registry, &db, ARTIFACT_A).await;
    grant(&db, ARTIFACT_A, ALICE, Capability::Manage).await;
    let args = prepare_args(
        ARTIFACT_A,
        PREVIEW_BODY,
        json!({"needs": [], "effects": []}),
    );
    let prepared = prepare(&registry, &db, args.clone()).await;
    let changed = PREVIEW_BODY.replace("Fixture", "Later bytes");
    update_call(
        &registry,
        &db,
        json!({"action": "inspect", "package": "agent.prepared"}),
    )
    .await
    .unwrap();
    registry
        .call(
            db.clone(),
            Caller::authenticated(ALICE),
            "update_record",
            json!({"id": ARTIFACT_A,
        "body_set": changed, "if_body_digest": prepared["bundle_sha256"],
        "reason": "Edit after preparation."}),
        )
        .await
        .unwrap();
    assert_eq!(
        prepare(&registry, &db, args).await["findings"][0]["code"],
        "source_changed"
    );
    // Install's existing historical pin semantics stay intact: later author
    // bytes are never substituted into the earlier prepared digest/revision.
    let installed = execute(&registry, &db, &prepared).await.unwrap();
    assert_eq!(
        installed["install"]["consented_source_revision"],
        prepared["source_revision"]
    );
    assert_eq!(installed["install"]["digest"], prepared["digest"]);
    let fresh = prepare(
        &registry,
        &db,
        prepare_args(ARTIFACT_A, &changed, json!({"needs": [], "effects": []})),
    )
    .await;
    assert_ne!(fresh["source_revision"], prepared["source_revision"]);
    assert_ne!(fresh["digest"], prepared["digest"]);
}

#[tokio::test]
async fn prepare_install_update_preserves_adoption_and_rejects_stale_install_event() {
    let (db, registry) = fixture().await;
    let declaration =
        json!({"needs": ["records.search.v1", "records.resolve_reference.v1"], "effects": []});
    let root = adopted_with_declaration(&registry, &db, declaration).await;
    let (_, body) = update_new_source(&registry, &db).await;
    let mut args = prepare_args(
        ARTIFACT_B,
        &body,
        json!({"effects": [], "needs": ["records.resolve_reference.v1", "records.search.v1"]}),
    );
    args["package"] = json!("agent.search");
    let prepared = prepare(&registry, &db, args).await;
    assert_eq!(prepared["current_install_event_id"], root);
    assert_eq!(prepared["adoption"], "carried");
    assert_eq!(
        prepared["next_call"]["operation"],
        "manage_alpha_tabs.update"
    );
    let updated = execute(&registry, &db, &prepared).await.unwrap();
    assert_eq!(updated["adoption_carried"], true);
    assert_eq!(updated["adoption_required"], false);
    let mut stale = prepared.clone();
    stale["next_call"]["arguments"]["version"] = json!("1.0.1");
    let error = execute(&registry, &db, &stale)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("cas_mismatch"), "{error}");
}

#[tokio::test]
async fn prepare_install_changed_declaration_requires_person_adoption() {
    let (db, registry) = fixture().await;
    adopted_with_declaration(
        &registry,
        &db,
        json!({
            "needs": ["records.search.v1", "records.resolve_reference.v1"], "effects": []
        }),
    )
    .await;
    let (_, body) = update_new_source(&registry, &db).await;
    let mut args = prepare_args(
        ARTIFACT_B,
        &body,
        json!({"needs": ["records.search.v1"], "effects": []}),
    );
    args["package"] = json!("agent.search");
    let prepared = prepare(&registry, &db, args).await;
    assert_eq!(prepared["ready"], true);
    assert_eq!(prepared["adoption"], "requires_person_preview_adopt");
    let updated = execute(&registry, &db, &prepared).await.unwrap();
    assert_eq!(updated["adoption_carried"], false);
    assert_eq!(updated["adoption_required"], true);
}

#[tokio::test]
async fn prepare_install_reinstall_passes_request_and_unadopted_update_requires_adopt() {
    let (db, registry) = fixture().await;
    artifact(&registry, &db, ARTIFACT_A).await;
    grant(&db, ARTIFACT_A, ALICE, Capability::View).await;
    let mut args = prepare_args(
        ARTIFACT_A,
        PREVIEW_BODY,
        json!({"needs": [], "effects": []}),
    );
    args["request"] = json!("Show my contacts");
    let prepared = prepare(&registry, &db, args.clone()).await;
    let installed = execute(&registry, &db, &prepared).await.unwrap();
    assert_eq!(installed["install"]["request"], "Show my contacts");
    let update = prepare(&registry, &db, args.clone()).await;
    assert_eq!(update["adoption"], "requires_person_preview_adopt");
    let mut bad_request = args.clone();
    bad_request["request"] = json!("Change the request");
    assert_eq!(prepare(&registry, &db, bad_request).await["ready"], false);
    let removed = update_call(&registry, &db, json!({"action": "remove", "package": "agent.prepared",
        "expected_install_event_id": installed["install"]["event_id"], "reason": "Test reinstall."})).await.unwrap();
    let reinstall = prepare(&registry, &db, args).await;
    assert_eq!(
        reinstall["next_call"]["operation"],
        "manage_alpha_tabs.install"
    );
    assert_eq!(
        reinstall["next_call"]["arguments"]["request"],
        "Show my contacts"
    );
    assert_eq!(
        reinstall["current_install_event_id"],
        removed["install"]["event_id"]
    );
    let installed = execute(&registry, &db, &reinstall).await.unwrap();
    assert_eq!(installed["install"]["request"], "Show my contacts");
}

#[tokio::test]
async fn prepare_install_bounds_echoed_declaration_and_keeps_shape_errors() {
    let (db, registry) = fixture().await;
    artifact(&registry, &db, ARTIFACT_A).await;
    grant(&db, ARTIFACT_A, ALICE, Capability::View).await;
    let oversized = json!({"needs": [], "effects": [], "extra": "x".repeat(65536)});
    let result = prepare(
        &registry,
        &db,
        prepare_args(ARTIFACT_A, PREVIEW_BODY, oversized),
    )
    .await;
    assert_eq!(result["ready"], false);
    assert_eq!(result["findings"][0]["code"], "invalid_declaration");
    assert!(result["findings"][0]["message"]
        .as_str()
        .unwrap()
        .contains("65536"));
    assert!(result["next_call"].is_null());
    let mut args = prepare_args(
        ARTIFACT_A,
        PREVIEW_BODY,
        json!({"needs": [], "effects": []}),
    );
    args["expected_body_digest"] = json!("bad");
    assert!(update_call(&registry, &db, args).await.is_err());
}

#[tokio::test]
async fn prepare_install_reports_kit_availability_and_bounds_findings() {
    let (db, registry) = fixture().await;
    let mut body = PREVIEW_BODY.replace("</head>", "<script type=\"application/json\" id=\"native-app-kit\">{\"schema\":\"native.app-kit.v1\",\"major\":2}</script></head>");
    body = body.replace("</body>", "<script>missingOne();missingTwo();missingThree();missingFour();missingFive();missingSix();missingSeven();missingEight();missingNine();</script></body>");
    registry.call(db.clone(), Caller::local(), "create_record", json!({"id": ARTIFACT_A,
        "type": "Document", "kind": "artifact", "name": "Unserved kit", "body": body,
        "facets": {"runtime": "native.html.v1"}, "reason": "Source with unavailable kit and warnings."})).await.unwrap();
    grant(&db, ARTIFACT_A, ALICE, Capability::View).await;
    let prepared = prepare(
        &registry,
        &db,
        prepare_args(ARTIFACT_A, &body, json!({"needs": [], "effects": []})),
    )
    .await;
    assert_eq!(prepared["ready"], true); // Availability does not change install admission.
    assert_eq!(prepared["kit"]["available"], false);
    assert_eq!(prepared["kit"]["basis"], "packaged_default");
    assert_eq!(prepared["findings"][0]["code"], "kit_major_unavailable");
    assert_eq!(prepared["findings"].as_array().unwrap().len(), 8);
    assert_eq!(prepared["findings_truncated"], true);
    for finding in prepared["findings"].as_array().unwrap() {
        assert!(finding["message"].as_str().unwrap().chars().count() <= 512);
    }
}

#[tokio::test]
async fn prepare_install_validates_historical_html_and_never_skips_a_body_clear() {
    let (db, registry) = fixture().await;
    artifact(&registry, &db, ARTIFACT_A).await;
    grant(&db, ARTIFACT_A, ALICE, Capability::View).await;
    let pool = crate::common::fixture_write_pool(&db).await;
    // Imported/legacy source can violate today's HTML admission. Exercise
    // preparation's validator rather than the create_record validator.
    let bad = PREVIEW_BODY.replace(
        "</body>",
        "<script src=\"https://example.test/app.js\"></script></body>",
    );
    for (id, body) in [
        ("prepare-bad-source", json!(bad)),
        ("prepare-cleared-source", Value::Null),
    ] {
        sqlx::query("INSERT INTO content_events (id,record_id,type,payload,causal_envelope_version,causal_status)
            VALUES (?,?,'record.updated',?,1,'complete')")
            .bind(id).bind(ARTIFACT_A).bind(json!({"body": body}).to_string()).execute(&pool).await.unwrap();
        let mut args = prepare_args(ARTIFACT_A, &bad, json!({"needs": [], "effects": []}));
        args.as_object_mut().unwrap().remove("expected_body_digest");
        args["expected_source_revision"] = json!(id);
        let refused = prepare(&registry, &db, args).await;
        assert_eq!(refused["ready"], false);
        assert!(refused["next_call"].is_null());
        if body.is_null() {
            assert_eq!(refused["findings"][0]["code"], "source_revision_unresolved");
        } else {
            assert_ne!(refused["findings"][0]["code"], "source_changed");
            assert!(refused["findings"][0]["message"]
                .as_str()
                .unwrap()
                .contains("script[src]"));
        }
    }
}
