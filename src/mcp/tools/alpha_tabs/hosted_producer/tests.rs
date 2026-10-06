use super::*;

// Capacity and busy-lock fixtures exercise the real process-global receipt
// store. Run each receipt test in its own process so those deliberate refusals
// cannot contaminate sibling producer or ordinary preview fixtures.
async fn isolated_receipt_process() -> bool {
    const CHILD: &str = "NATIVE_HOSTED_PRODUCER_RECEIPT_TEST";
    let name = std::thread::current()
        .name()
        .expect("named libtest receipt fixture")
        .to_owned();
    if std::env::var(CHILD).ok().as_deref() == Some(name.as_str()) {
        return false;
    }
    let output = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &name, "--test-threads=1", "--nocapture"])
            .env(CHILD, &name)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("bounded isolated receipt fixture")
    .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("test result: ok. 1 passed; 0 failed;"),
        "receipt child {name} failed or did not execute: stdout={stdout} stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    true
}

fn delivery() -> crate::artifact_html::LaunchDelivery {
    crate::artifact_html::LaunchDelivery::new(
        crate::artifact_html::RuntimeConfig::new(
            "http://localhost:8080",
            "http://artifact.localhost:8080",
        )
        .unwrap(),
    )
}
const BODY: &str = "\u{feff}<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Producer</title></head><body>Producer é😀</body></html>";
async fn fixture() -> (Db, Caller, Value) {
    let db = crate::create_database(":memory:").await.unwrap();
    let caller = Caller::local();
    let artifact = crate::store::create_record(
        &db,
        json!({"type":"Document","kind":"artifact","name":"Producer source","body":BODY}),
    )
    .await
    .unwrap();
    crate::store::set_facet(
        &db,
        &artifact,
        crate::events::FacetSetPayload {
            key: "runtime".into(),
            value: Some("native.html.v1".into()),
            vocab_ref: None,
            as_of: None,
            observation_only: false,
        },
    )
    .await
    .unwrap();
    let source: String = sqlx::query_scalar(
        "SELECT id FROM content_events WHERE record_id=? AND type='record.created'",
    )
    .bind(&artifact)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let d = json!({"needs":[{"need":BODY_READ_NEED,"scope":BODY_READ_SCOPE}],"effects":[]});
    let dd = "b543054776df55c1cee9a703a50ea398e88ac3df40f322e437264ab6d450cae4";
    let v = json!({"action":"install","package":"fixture.private-producer","version":"1.0.0",
        "digest":alpha_tab_digest(&alpha_tab_bundle_digest(BODY),dd,"native.html.v1"),
        "artifact_id":artifact,"source_revision":source,"declaration":d,"reason":"Genuine private install",
        "idempotency_key":"producer-install"});
    (db, caller, v)
}
fn request(v: &Value) -> Request {
    Request::parse(&serde_json::to_vec(v).unwrap()).unwrap()
}
async fn installed(db: &Db, c: &Caller, v: &Value) -> Outcome {
    let r = request(v);
    let g = unsafe { Ingress::from_verified_host(db, c, &r, Instant::now()) }.unwrap();
    install(&g).await.unwrap().original
}
async fn previewed(db: &Db, c: &Caller, v: &Value) -> Value {
    let r = request(v);
    let g = unsafe { Ingress::from_verified_host(db, c, &r, Instant::now()) }.unwrap();
    serde_json::from_slice(&preview(&g, &delivery()).await.unwrap().expose().unwrap()).unwrap()
}
async fn adopt(db: &Db, c: &Caller, v: &Value) -> Result<Outcome> {
    let r = request(v);
    let intent = r.adopt_intent()?;
    let g =
        unsafe { adoption_intent::Ingress::from_verified_host(db, c, &intent, Instant::now()) }?;
    match adoption_intent::begin(&g).await? {
        adoption_intent::Decision::Recovered(o) => Ok(o),
        adoption_intent::Decision::Fresh(f) => {
            f.prepare_current_pin()?
                .qualify()
                .await?
                .commit(r.nonce())
                .await
        }
    }
}
fn preview_request(v: &Value, id: &str) -> Value {
    let mut v = v.clone();
    v["action"] = json!("preview");
    v["expected_install_event_id"] = json!(id);
    v.as_object_mut().unwrap().remove("idempotency_key");
    v.as_object_mut().unwrap().remove("request");
    v
}
fn confirm(v: &Value, p: &Value) -> Value {
    let mut v = v.clone();
    v["action"] = json!("adopt");
    v["receipt_id"] = p["receipt"]["receipt_id"].clone();
    v["preview_session"] = p["receipt"]["preview_session"].clone();
    v["nonce"] = p["receipt"]["nonce"].clone();
    v["idempotency_key"] = json!("producer-adopt");
    v
}
async fn state(db: &Db) -> (i64, String, Option<String>) {
    sqlx::query_as("SELECT (SELECT COUNT(*) FROM control_events),event_id,body_read_admission_event_id FROM alpha_tab_installs")
        .fetch_one(db.pool()).await.unwrap()
}

#[tokio::test]
async fn same_pin_update_requires_new_human_preview_generation_and_coherent_v2_root() {
    if isolated_receipt_process().await {
        return;
    }
    let (db, c, v) = fixture().await;
    let installed = installed(&db, &c, &v).await;
    let old_request = preview_request(&v, &installed.event_id);
    let old_preview = previewed(&db, &c, &old_request).await;
    let declaration = v["declaration"].clone();
    let pin = crate::control::AlphaTabStatePayload {
        account_id: c.credential().into(),
        package: v["package"].as_str().unwrap().into(),
        version: v["version"].as_str().unwrap().into(),
        digest: v["digest"].as_str().unwrap().into(),
        artifact_id: v["artifact_id"].as_str().unwrap().into(),
        consented_source_revision: v["source_revision"].as_str().unwrap().into(),
        declaration_digest: crate::alpha_tab_body_admission_v1::declaration_digest(&declaration)
            .unwrap(),
        consented_declaration: declaration,
        adoption: "caller_asserted".into(),
        request: None,
        previous_event_id: Some(installed.event_id.clone()),
    };
    let update = crate::control::AlphaTabUpdatePayload {
        account_id: pin.account_id.clone(),
        package: pin.package.clone(),
        version: pin.version.clone(),
        digest: pin.digest.clone(),
        artifact_id: pin.artifact_id.clone(),
        consented_source_revision: pin.consented_source_revision.clone(),
        declaration_digest: pin.declaration_digest.clone(),
        consented_declaration: pin.consented_declaration.clone(),
        previous_event_id: installed.event_id,
        previous_pin_digest: crate::control::alpha_tab_pin_digest(&pin).unwrap(),
        status: "installed".into(),
        request: None,
        command_digest: "c".repeat(64),
        adoption: "caller_asserted".into(),
        adoption_basis: "requires_adoption".into(),
        adoption_provenance: None,
    };
    let updated = crate::control::append_control_event(
        &db,
        crate::control::NewControlEvent::authored(
            "producer-update-generation",
            crate::control::alpha_tab_aggregate_id(c.credential(), &pin.package),
            c.credential(),
            None,
            "Same pin still changes install generation",
            crate::control::ControlEventPayload::AlphaTabUpdated(Box::new(update)),
        )
        .unwrap(),
    )
    .await
    .unwrap();
    assert!(adopt(&db, &c, &confirm(&old_request, &old_preview))
        .await
        .is_err());
    assert!(
        !find_alpha_tab_preview_receipt(old_preview["receipt"]["receipt_id"].as_str().unwrap())
            .unwrap()
            .1
    );
    let current = preview_request(&v, &updated.id);
    let p = previewed(&db, &c, &current).await;
    let adopted = adopt(&db, &c, &confirm(&current, &p)).await.unwrap();
    let raw: String = sqlx::query_scalar("SELECT adoption_provenance FROM alpha_tab_installs")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let root: crate::control::AlphaTabAdoptionProvenance = serde_json::from_str(&raw).unwrap();
    assert_eq!(root.original_adoption_event_id, adopted.event_id);
    assert_eq!(root.original_adoption_method, "shell_adopt.v1");
    assert_eq!(root.original_bundle_digest, pin.digest);
    assert_eq!(
        root.reviewed_bundle_digest,
        Some(root.original_bundle_digest.clone())
    );
    assert_eq!(
        root.reviewed_source_revision,
        Some(pin.consented_source_revision.clone())
    );
    assert!(
        root.launch_id.is_none()
            && root.authored_run_key.is_none()
            && root.carried_from_event_id.is_none()
    );
    assert_eq!(state(&db).await.2, Some(adopted.event_id.clone()));
    // Ordinary human consent carries through a same-declaration update; body
    // authority is independently revoked even though the reviewed root survives.
    let mut carried = root.clone();
    carried.carried_from_event_id = Some(adopted.event_id.clone());
    let mut update = crate::control::AlphaTabUpdatePayload {
        account_id: pin.account_id.clone(),
        package: pin.package.clone(),
        version: pin.version.clone(),
        digest: pin.digest.clone(),
        artifact_id: pin.artifact_id.clone(),
        consented_source_revision: root.original_source_revision.clone(),
        declaration_digest: pin.declaration_digest.clone(),
        consented_declaration: pin.consented_declaration.clone(),
        previous_event_id: adopted.event_id,
        previous_pin_digest: crate::control::alpha_tab_pin_digest(&pin).unwrap(),
        status: "installed".into(),
        request: None,
        command_digest: "e".repeat(64),
        adoption: "shell_adopt.v1".into(),
        adoption_basis: "carried".into(),
        adoption_provenance: Some(carried.clone()),
    };
    let carried_event = crate::control::append_control_event(
        &db,
        crate::control::NewControlEvent::authored(
            "producer-human-carry",
            crate::control::alpha_tab_aggregate_id(c.credential(), &pin.package),
            c.credential(),
            None,
            "Same declaration human carry does not carry body authority",
            crate::control::ControlEventPayload::AlphaTabUpdated(Box::new(update.clone())),
        )
        .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(state(&db).await.2, None);
    let mut conn = db.write_pool().acquire().await.unwrap();
    crate::control::alpha_tab_provenance::backfill(&mut conn)
        .await
        .unwrap();
    let raw: String = sqlx::query_scalar("SELECT adoption_provenance FROM alpha_tab_installs")
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_str::<crate::control::AlphaTabAdoptionProvenance>(&raw).unwrap(),
        carried
    );
    drop(conn);
    // Changing the declaration returns to pending ordinary consent too.
    update.previous_event_id = carried_event.id;
    update.consented_declaration["needs"]
        .as_array_mut()
        .unwrap()
        .push(json!("inert.new-name"));
    update.declaration_digest =
        crate::alpha_tab_body_admission_v1::declaration_digest(&update.consented_declaration)
            .unwrap();
    update.digest = alpha_tab_digest(
        &alpha_tab_bundle_digest(BODY),
        &update.declaration_digest,
        "native.html.v1",
    );
    update.adoption = "caller_asserted".into();
    update.adoption_basis = "requires_adoption".into();
    update.adoption_provenance = None;
    update.command_digest = "f".repeat(64);
    crate::control::append_control_event(
        &db,
        crate::control::NewControlEvent::authored(
            "producer-human-changed-declaration",
            crate::control::alpha_tab_aggregate_id(c.credential(), &pin.package),
            c.credential(),
            None,
            "Changed declaration needs fresh ordinary consent",
            crate::control::ControlEventPayload::AlphaTabUpdated(Box::new(update)),
        )
        .unwrap(),
    )
    .await
    .unwrap();
    let pending: (String, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT adoption,adoption_provenance,body_read_admission_event_id FROM alpha_tab_installs",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(pending, ("caller_asserted".into(), None, None));
    assert!(
        crate::conformance::rebuild_and_diff_control(&db)
            .await
            .unwrap()
            .equal
    );
    db.close().await;
}

#[test]
fn raw_decoder_rejects_duplicates_before_value_without_semantic_admission() {
    let valid = r#"{"action":"install","package":"fixture.raw","version":"old","digest":"old","artifact_id":"a","source_revision":"r","reason":"original","declaration":{"needs":[{"need":"records.body.read.v1","scope":"viewer-visible-current-bodies"}],"effects":[]}}"#;
    assert!(Request::parse(valid.as_bytes()).is_ok());
    for raw in [
        valid.replace(
            "\"action\":\"install\"",
            "\"action\":\"install\",\"action\":\"install\"",
        ),
        valid.replace("\"needs\":[", "\"needs\":[],\"\\u006eeeds\":["),
        valid.replace(
            "\"scope\":",
            "\"\\u0073cope\":\"viewer-visible-current-bodies\",\"scope\":",
        ),
        valid.replace(
            "\"effects\":[]",
            "\"effects\":[],\"sessions\":[],\"sessions\":[]",
        ),
        valid.replace(
            "\"reason\":\"original\"",
            "\"reason\":\"original\",\"reason\":\"original\"",
        ),
    ] {
        assert!(Request::parse(raw.as_bytes()).is_err());
    }
    let mut v = json!({"action":"install","package":"unknown","version":"historic","digest":"historic",
        "artifact_id":"a","source_revision":"r","reason":"original",
        "declaration":{"unknown":{"ordered":[3,2,1]},"needs":[],"effects":[],"sessions":[]}});
    let r = request(&v);
    assert_eq!(r.declaration, v["declaration"]);
    assert!(r.declaration.get("sessions").is_some());
    v["declaration"].as_object_mut().unwrap().remove("sessions");
    assert!(request(&v).declaration.get("sessions").is_none());
    assert!(Request::parse(&vec![b' '; INPUT_BYTES + 1]).is_err());
}

#[tokio::test]
async fn genuine_install_preview_nonce_confirm_and_generic_receipt_refusal() {
    if isolated_receipt_process().await {
        return;
    }
    let (db, c, v) = fixture().await;
    let o = installed(&db, &c, &v).await;
    let before = state(&db).await;
    assert_eq!(before.0, 1);
    assert!(before.2.is_none());
    let pv = preview_request(&v, &o.event_id);
    let p = previewed(&db, &c, &pv).await;
    assert_eq!(p["scope"], BODY_READ_SCOPE);
    assert_eq!(p["preview"]["sample_only"], true);
    assert_eq!(p["preview"]["live_reads"], false);
    let generic = issue_alpha_tab_preview_receipt(
        c.credential(),
        v["package"].as_str().unwrap(),
        "1.0.0",
        v["digest"].as_str().unwrap(),
        v["artifact_id"].as_str().unwrap(),
        v["source_revision"].as_str().unwrap(),
        "b543054776df55c1cee9a703a50ea398e88ac3df40f322e437264ab6d450cae4",
        vec![],
        vec![],
        None,
        chrono::Utc::now().timestamp(),
    );
    let mut bad = confirm(&pv, &p);
    bad["receipt_id"] = json!(generic.receipt_id);
    bad["preview_session"] = json!(generic.preview_session);
    bad["nonce"] = json!(generic.nonce);
    assert!(adopt(&db, &c, &bad).await.is_err());
    assert_eq!(before, state(&db).await);
    assert!(
        !find_alpha_tab_preview_receipt(&generic.receipt_id)
            .unwrap()
            .1
    );
    let good = confirm(&pv, &p);
    let adopted = adopt(&db, &c, &good).await.unwrap();
    assert_eq!(adopted.event_type, "alpha_tab.adopted.v2");
    let after = state(&db).await;
    assert_eq!(after.0, 2);
    assert_eq!(after.2.as_deref(), Some(adopted.event_id.as_str()));
    assert!(
        find_alpha_tab_preview_receipt(p["receipt"]["receipt_id"].as_str().unwrap())
            .unwrap()
            .1
    );
    sqlx::query("UPDATE alpha_tab_installs SET status='disabled'")
        .execute(db.write_pool())
        .await
        .unwrap();
    sqlx::query("CREATE TRIGGER producer_no_append BEFORE INSERT ON control_events BEGIN SELECT RAISE(ABORT,'retry appended'); END")
        .execute(db.write_pool()).await.unwrap();
    let out = adopt(&db, &c, &good).await.unwrap();
    assert_eq!(out.event_id, adopted.event_id);
    assert_eq!(after, state(&db).await);
}

#[tokio::test]
async fn install_retry_preserves_optional_request_and_skips_current_source_projection() {
    if isolated_receipt_process().await {
        return;
    }
    for field in [
        None,
        Some(Value::Null),
        Some(json!("  ")),
        Some(json!("Original request")),
    ] {
        let (db, c, mut v) = fixture().await;
        if let Some(f) = field {
            v["request"] = f;
        }
        let o = installed(&db, &c, &v).await;
        sqlx::query("DELETE FROM alpha_tab_installs")
            .execute(db.write_pool())
            .await
            .unwrap();
        sqlx::query("CREATE TRIGGER producer_no_projection BEFORE INSERT ON alpha_tab_installs BEGIN SELECT RAISE(ABORT,'projected'); END")
            .execute(db.write_pool()).await.unwrap();
        crate::store::set_facet(
            &db,
            v["artifact_id"].as_str().unwrap(),
            crate::events::FacetSetPayload {
                key: "runtime".into(),
                value: Some("invalid-now".into()),
                vocab_ref: None,
                as_of: None,
                observation_only: false,
            },
        )
        .await
        .unwrap();
        let retried = installed(&db, &c, &v).await;
        assert_eq!(retried.event_id, o.event_id);
        assert_eq!(retried.original_request, o.original_request);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM control_events")
                .fetch_one(db.pool())
                .await
                .unwrap(),
            1
        );
        v["declaration"]["sessions"] = json!([]);
        let r = request(&v);
        let g = unsafe { Ingress::from_verified_host(&db, &c, &r, Instant::now()) }.unwrap();
        assert!(install(&g).await.is_err());
    }
}

#[tokio::test]
async fn exact_generation_scope_and_unexposed_receipt_are_required() {
    if isolated_receipt_process().await {
        return;
    }
    let (db, c, v) = fixture().await;
    let o = installed(&db, &c, &v).await;
    let pv = preview_request(&v, &o.event_id);
    let p = previewed(&db, &c, &pv).await;
    let good = confirm(&pv, &p);
    let before = state(&db).await;
    let id = p["receipt"]["receipt_id"].as_str().unwrap();
    for (generation, scope) in [
        (Uuid::new_v4().to_string(), BODY_READ_SCOPE.to_string()),
        (o.event_id.clone(), "wrong".into()),
    ] {
        {
            let mut store = preview_receipt_store().lock().unwrap();
            let b = store.get_mut(id).unwrap().2.as_mut().unwrap();
            b.install_event_id = generation;
            b.scope = scope;
        }
        assert!(adopt(&db, &c, &good).await.is_err());
        assert_eq!(before, state(&db).await);
        assert!(!find_alpha_tab_preview_receipt(id).unwrap().1);
    }
    let r = request(&pv);
    let g = unsafe { Ingress::from_verified_host(&db, &c, &r, Instant::now()) }.unwrap();
    let pending = preview(&g, &delivery()).await.unwrap();
    let owned = pending.receipt.receipt.receipt_id.clone();
    drop(pending);
    assert!(find_alpha_tab_preview_receipt(&owned).is_none());
    assert!(find_alpha_tab_preview_receipt(id).is_some());
}

#[tokio::test]
async fn publication_expiry_removes_only_new_owned_receipt() {
    if isolated_receipt_process().await {
        return;
    }
    let (db, c, v) = fixture().await;
    let o = installed(&db, &c, &v).await;
    let pv = preview_request(&v, &o.event_id);
    let unrelated = previewed(&db, &c, &pv).await;
    let r = request(&pv);
    let g = unsafe { Ingress::from_verified_host(&db, &c, &r, Instant::now()) }.unwrap();
    let pending = preview(&g, &delivery()).await.unwrap();
    let id = pending.receipt.receipt.receipt_id.clone();
    tokio::time::sleep(Duration::from_millis(5100)).await;
    assert!(pending.expose().is_err());
    assert!(find_alpha_tab_preview_receipt(&id).is_none());
    assert!(
        find_alpha_tab_preview_receipt(unrelated["receipt"]["receipt_id"].as_str().unwrap())
            .is_some()
    );
}

#[tokio::test]
async fn fresh_install_refuses_current_sql_and_installed_replacement() {
    if isolated_receipt_process().await {
        return;
    }
    let (db, c, mut v) = fixture().await;
    let o = installed(&db, &c, &v).await;
    let before = state(&db).await;
    v["idempotency_key"] = json!("other-key");
    v["expected_install_event_id"] = json!(o.event_id);
    let r = request(&v);
    let g = unsafe { Ingress::from_verified_host(&db, &c, &r, Instant::now()) }.unwrap();
    assert!(install(&g).await.is_err());
    assert_eq!(before, state(&db).await);
    let (db, c, mut v) = fixture().await;
    v["declaration"]["needs"].as_array_mut().unwrap().push(
        json!({"need":"sql.snapshot.v1","key":"bad","label":"Bad SQL","sql":"DELETE FROM records"}),
    );
    let dd = crate::alpha_tab_body_admission_v1::declaration_digest(&v["declaration"]).unwrap();
    v["digest"] = json!(alpha_tab_digest(
        &alpha_tab_bundle_digest(BODY),
        &dd,
        "native.html.v1"
    ));
    let r = request(&v);
    let g = unsafe { Ingress::from_verified_host(&db, &c, &r, Instant::now()) }.unwrap();
    assert!(install(&g).await.is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM control_events")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn producer_source_storage_guard_refuses_matching_rendered_nontext_and_malformed() {
    if isolated_receipt_process().await {
        return;
    }
    for (raw, blob, rendered) in [
        (
            Some(r#"{"body":{"x":"y"}}"#.as_bytes().to_vec()),
            false,
            r#"{"x":"y"}"#,
        ),
        (Some(r#"{"body":[]}"#.as_bytes().to_vec()), false, "[]"),
        (Some(r#"{"body":null}"#.as_bytes().to_vec()), false, ""),
        (Some(r#"{}"#.as_bytes().to_vec()), false, ""),
        (None, false, ""),
        (Some(r#"{"body":"BLOB"}"#.as_bytes().to_vec()), true, "BLOB"),
        (Some(b"{bad".to_vec()), false, ""),
    ] {
        let (db, c, mut v) = fixture().await;
        let source = Uuid::new_v4().to_string();
        if !blob
            && raw
                .as_ref()
                .is_some_and(|b| serde_json::from_slice::<Value>(b).is_err())
        {
            sqlx::query("DROP TRIGGER content_event_claim_meta_insert")
                .execute(db.write_pool())
                .await
                .unwrap();
        }
        let q=sqlx::query("INSERT INTO content_events(id,record_id,type,payload,causal_envelope_version,causal_status) VALUES(?,?,'record.updated',?,1,'legacy_unknown')")
            .bind(&source).bind(v["artifact_id"].as_str().unwrap());
        if blob {
            q.bind(raw).execute(db.write_pool()).await.unwrap();
        } else {
            q.bind(raw.map(|b| String::from_utf8(b).unwrap()))
                .execute(db.write_pool())
                .await
                .unwrap();
        }
        v["source_revision"] = json!(source);
        // MATCH extraction-rendered bytes deliberately. A digest mismatch
        // cannot hide an object/array/TEXT/null/BLOB guard regression.
        v["digest"] = json!(alpha_tab_digest(
            &alpha_tab_bundle_digest(rendered),
            "b543054776df55c1cee9a703a50ea398e88ac3df40f322e437264ab6d450cae4",
            "native.html.v1"
        ));
        let r = request(&v);
        let g = unsafe { Ingress::from_verified_host(&db, &c, &r, Instant::now()) }.unwrap();
        assert!(install(&g).await.is_err());
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM control_events")
                .fetch_one(db.pool())
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM alpha_tab_installs")
                .fetch_one(db.pool())
                .await
                .unwrap(),
            0
        );
    }
}

#[tokio::test]
async fn unknown_historical_install_declaration_recovers_without_fresh_classifier() {
    if isolated_receipt_process().await {
        return;
    }
    // Explicit inert legacy-history fixture, NOT the genuine producer positive.
    let (db, c, mut v) = fixture().await;
    v["declaration"] = json!({"old-unknown":{"arrays":[2,1]},"sessions":[]});
    let old = install_payload(
        c.credential(),
        v["package"].as_str().unwrap(),
        "1.0.0",
        v["digest"].as_str().unwrap(),
        v["artifact_id"].as_str().unwrap(),
        v["source_revision"].as_str().unwrap(),
        "b543054776df55c1cee9a703a50ea398e88ac3df40f322e437264ab6d450cae4",
        &v["declaration"],
        None,
        None,
    );
    let event = crate::control::append_control_event(
        &db,
        NewControlEvent::authored(
            "producer-install",
            alpha_tab_aggregate_id(c.credential(), v["package"].as_str().unwrap()),
            c.actor(),
            None,
            v["reason"].as_str().unwrap(),
            ControlEventPayload::AlphaTabInstalled(old),
        )
        .unwrap(),
    )
    .await
    .unwrap();
    let r = request(&v);
    let g = unsafe { Ingress::from_verified_host(&db, &c, &r, Instant::now()) }.unwrap();
    let out = install(&g).await.unwrap();
    assert!(!out.changed);
    assert_eq!(out.original.event_id, event.id);
    assert!(state(&db).await.2.is_none());
}

#[tokio::test]
async fn same_pin_remove_reinstall_invalidates_old_feature_receipt() {
    if isolated_receipt_process().await {
        return;
    }
    let (db, c, v) = fixture().await;
    let first = installed(&db, &c, &v).await;
    let oldpv = preview_request(&v, &first.event_id);
    let p = previewed(&db, &c, &oldpv).await;
    let raw: String = sqlx::query_scalar("SELECT payload FROM control_events WHERE id=?")
        .bind(&first.event_id)
        .fetch_one(db.pool())
        .await
        .unwrap();
    let mut removed: AlphaTabStatePayload = serde_json::from_str(&raw).unwrap();
    removed.previous_event_id = Some(first.event_id);
    let removal = crate::control::append_control_event(
        &db,
        NewControlEvent::authored(
            "producer-remove",
            alpha_tab_aggregate_id(c.credential(), &removed.package),
            c.actor(),
            None,
            "Remove for genuine reinstall",
            ControlEventPayload::AlphaTabRemoved(removed),
        )
        .unwrap(),
    )
    .await
    .unwrap();
    let mut again = v.clone();
    again["idempotency_key"] = json!("producer-reinstall");
    again["expected_install_event_id"] = json!(removal.id);
    let second = installed(&db, &c, &again).await;
    let newpv = preview_request(&v, &second.event_id);
    let stale = confirm(&newpv, &p);
    let before = state(&db).await;
    assert!(adopt(&db, &c, &stale).await.is_err());
    assert_eq!(before, state(&db).await);
    assert!(
        !find_alpha_tab_preview_receipt(p["receipt"]["receipt_id"].as_str().unwrap())
            .unwrap()
            .1
    );
    let fresh = previewed(&db, &c, &newpv).await;
    assert!(adopt(&db, &c, &confirm(&newpv, &fresh)).await.is_ok());
}

fn sample_headers() -> axum::http::HeaderMap {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::HOST,
        axum::http::HeaderValue::from_static("artifact.localhost:8080"),
    );
    headers
}
fn sample_refused(d: &crate::artifact_html::LaunchDelivery, url: &str) -> bool {
    matches!(
        d.lookup_launch(url.rsplit('/').next().unwrap(), &sample_headers()),
        crate::artifact_html::TicketLookup::Matched(crate::artifact_html::LaunchOutcome::Refused(
            _
        ))
    )
}
#[tokio::test]
async fn guarded_preview_insertion_failures_remove_only_exact_new_resources() {
    if isolated_receipt_process().await {
        return;
    }
    let (db, c, v) = fixture().await;
    let o = installed(&db, &c, &v).await;
    let pv = preview_request(&v, &o.event_id);
    let d = delivery();
    let r = request(&pv);
    let oldg = unsafe { Ingress::from_verified_host(&db, &c, &r, Instant::now()) }.unwrap();
    let old = preview(&oldg, &d).await.unwrap().expose().unwrap();
    let old: Value = serde_json::from_slice(&old).unwrap();
    for point in [
        PreviewFault::BeforeSample,
        PreviewFault::AfterSample,
        PreviewFault::BeforeReceipt,
        PreviewFault::AfterReceipt,
    ] {
        let mut g = unsafe { Ingress::from_verified_host(&db, &c, &r, Instant::now()) }.unwrap();
        let capture = std::sync::Arc::new(std::sync::Mutex::new(None));
        g.preview_fault = Some(point);
        g.preview_capture = Some(capture.clone());
        assert!(preview(&g, &d).await.is_err());
        let (url, id) = capture.lock().unwrap().clone().unwrap();
        if !url.is_empty() {
            assert!(sample_refused(&d, &url));
        }
        if let Some(id) = id {
            assert!(find_alpha_tab_preview_receipt(&id).is_none());
        }
        assert!(
            !find_alpha_tab_preview_receipt(old["receipt"]["receipt_id"].as_str().unwrap())
                .unwrap()
                .1
        );
    }
    assert!(matches!(
        d.lookup_launch(
            old["preview"]["launch"]["url"]
                .as_str()
                .unwrap()
                .rsplit('/')
                .next()
                .unwrap(),
            &sample_headers()
        ),
        crate::artifact_html::TicketLookup::Matched(
            crate::artifact_html::LaunchOutcome::Delivered(_)
        )
    ));
}
#[tokio::test]
async fn capped_fallible_response_and_panic_keep_both_guards_armed() {
    if isolated_receipt_process().await {
        return;
    }
    use axum::response::IntoResponse;
    let (db, c, v) = fixture().await;
    let o = installed(&db, &c, &v).await;
    let pv = preview_request(&v, &o.event_id);
    let r = request(&pv);
    let d = delivery();
    for mode in 0..4 {
        let g = unsafe { Ingress::from_verified_host(&db, &c, &r, Instant::now()) }.unwrap();
        let mut p = preview(&g, &d).await.unwrap();
        let id = p.receipt.receipt.receipt_id.clone();
        let url = p.sample.descriptor().url.clone();
        if mode < 2 {
            p.output["cap_probe"] = json!("");
            let base = serde_json::to_vec(&p.output).unwrap().len();
            p.output["cap_probe"] = json!("x".repeat(PREVIEW_OUTPUT_BYTES - base + mode));
            let expected = PREVIEW_OUTPUT_BYTES + mode;
            assert_eq!(serde_json::to_vec(&p.output).unwrap().len(), expected);
            let out = p.publish_http(|b| {
                Ok((
                    axum::http::StatusCode::OK,
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    b.into_bytes(),
                )
                    .into_response())
            });
            if mode == 0 {
                let response = out.unwrap();
                let bytes = axum::body::to_bytes(response.into_body(), PREVIEW_OUTPUT_BYTES)
                    .await
                    .unwrap();
                assert_eq!(bytes.len(), 16384);
                assert!(preview_receipt_store().lock().unwrap()[&id]
                    .2
                    .as_ref()
                    .unwrap()
                    .publication
                    .is_published());
                continue;
            }
            assert!(matches!(out, Err(PreviewPublicationFailure::OutputLimit)));
        } else if mode == 2 {
            assert!(matches!(
                p.publish_http(|_| Err(PreviewPublicationFailure::ResponseConstruction)),
                Err(PreviewPublicationFailure::ResponseConstruction)
            ));
        } else {
            assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                || p.publish_http(|_| panic!("isolated response construction fault"))
            ))
            .is_err());
        }
        assert!(find_alpha_tab_preview_receipt(&id).is_none());
        assert!(sample_refused(&d, &url));
    }
}
#[tokio::test]
async fn unpublished_and_busy_cleanup_receipts_never_authorize_adoption() {
    if isolated_receipt_process().await {
        return;
    }
    let (db, c, v) = fixture().await;
    let o = installed(&db, &c, &v).await;
    let pv = preview_request(&v, &o.event_id);
    let r = request(&pv);
    let d = delivery();
    let g = unsafe { Ingress::from_verified_host(&db, &c, &r, Instant::now()) }.unwrap();
    let p = preview(&g, &d).await.unwrap();
    let id = p.receipt.receipt.receipt_id.clone();
    let url = p.sample.descriptor().url.clone();
    assert!(find_alpha_tab_preview_receipt(&id).is_none());
    let checked = p.output.clone();
    let mut confirm = pv.clone();
    confirm["action"] = json!("adopt");
    confirm["idempotency_key"] = json!("not-yet-published");
    for key in ["receipt_id", "preview_session", "nonce"] {
        confirm[key] = checked["receipt"][key].clone();
    }
    let before = state(&db).await;
    assert!(adopt(&db, &c, &confirm).await.is_err());
    assert_eq!(before, state(&db).await);
    let marker = p.receipt.publication.clone();
    {
        let held = preview_receipt_store().lock().unwrap();
        drop(p);
        assert!(marker.is_invalid());
        assert!(held.contains_key(&id));
        assert!(!held[&id].1);
    }
    assert!(adopt(&db, &c, &confirm).await.is_err());
    assert_eq!(before, state(&db).await);
    assert!(sample_refused(&d, &url));
    // A subsequent bounded new-feature access sweeps only the invalid residual.
    let new = preview(&g, &d).await.unwrap();
    assert!(find_alpha_tab_preview_receipt(&id).is_none());
    drop(new);
}
#[tokio::test]
async fn final_original_deadline_after_response_construction_cleans_both_resources() {
    if isolated_receipt_process().await {
        return;
    }
    use axum::response::IntoResponse;
    let (db, c, v) = fixture().await;
    let o = installed(&db, &c, &v).await;
    let pv = preview_request(&v, &o.event_id);
    let r = request(&pv);
    let d = delivery();
    let g = unsafe { Ingress::from_verified_host(&db, &c, &r, Instant::now()) }.unwrap();
    let p = preview(&g, &d).await.unwrap();
    let id = p.receipt.receipt.receipt_id.clone();
    let url = p.sample.descriptor().url.clone();
    let started = Instant::now();
    let result = p.publish_http(|b| {
        let response = b.into_bytes().into_response();
        // Wait on the ORIGINAL ingress deadline, never rewrite/renew it.
        std::thread::sleep(g.deadline.saturating_duration_since(Instant::now()));
        Ok(response)
    });
    assert!(started.elapsed() < Duration::from_secs(6));
    assert!(matches!(result, Err(PreviewPublicationFailure::Deadline)));
    assert!(find_alpha_tab_preview_receipt(&id).is_none());
    assert!(sample_refused(&d, &url));
}

#[tokio::test]
async fn receipt_cleanup_never_removes_consumed_or_different_exact_owner() {
    if isolated_receipt_process().await {
        return;
    }
    let (db, c, v) = fixture().await;
    let o = installed(&db, &c, &v).await;
    let pv = preview_request(&v, &o.event_id);
    let r = request(&pv);
    let d = delivery();
    for mode in 0..4 {
        let g = unsafe { Ingress::from_verified_host(&db, &c, &r, Instant::now()) }.unwrap();
        let p = preview(&g, &d).await.unwrap();
        let id = p.receipt.receipt.receipt_id.clone();
        let other = d
            .reserve_sample_launch(
                BODY,
                &crate::artifact_html::validate(BODY).unwrap(),
                "different-owner",
                None,
                "a",
            )
            .unwrap();
        {
            let mut store = preview_receipt_store().lock().unwrap();
            let entry = store.get_mut(&id).unwrap();
            match mode {
                0 => entry.1 = true,
                1 => entry.0.nonce.push('x'),
                2 => entry.0.preview_session.push('x'),
                _ => entry.2.as_mut().unwrap().publication = other.publication_marker(),
            }
        }
        drop(p);
        assert!(preview_receipt_store().lock().unwrap().contains_key(&id));
        // Remove only this isolated negative ownership fixture after evidence.
        preview_receipt_store().lock().unwrap().remove(&id);
        drop(other);
    }
}

#[tokio::test]
async fn publication_busy_receipt_and_missing_receipt_keep_new_sample_unpublished() {
    if isolated_receipt_process().await {
        return;
    }
    use axum::response::IntoResponse;
    let (db, c, v) = fixture().await;
    let o = installed(&db, &c, &v).await;
    let pv = preview_request(&v, &o.event_id);
    let r = request(&pv);
    let d = delivery();
    for busy in [true, false] {
        let g = unsafe { Ingress::from_verified_host(&db, &c, &r, Instant::now()) }.unwrap();
        let p = preview(&g, &d).await.unwrap();
        let id = p.receipt.receipt.receipt_id.clone();
        let url = p.sample.descriptor().url.clone();
        let marker = p.receipt.publication.clone();
        if busy {
            let lock = preview_receipt_store().lock().unwrap();
            assert!(matches!(
                p.publish_http(|b| Ok(b.into_bytes().into_response())),
                Err(PreviewPublicationFailure::Busy)
            ));
            assert!(marker.is_invalid());
            assert!(lock.contains_key(&id));
            drop(lock);
            preview_receipt_store().lock().unwrap().remove(&id);
        } else {
            preview_receipt_store().lock().unwrap().remove(&id);
            assert!(matches!(
                p.publish_http(|b| Ok(b.into_bytes().into_response())),
                Err(PreviewPublicationFailure::Ownership)
            ));
            assert!(marker.is_invalid());
        }
        assert!(sample_refused(&d, &url));
    }
}

#[tokio::test]
async fn new_feature_receipt_capacity_refuses_without_evicting_older_live_receipts() {
    if isolated_receipt_process().await {
        return;
    }
    let (db, c, v) = fixture().await;
    let o = installed(&db, &c, &v).await;
    let pv = preview_request(&v, &o.event_id);
    let r = request(&pv);
    let d = delivery();
    let g = unsafe { Ingress::from_verified_host(&db, &c, &r, Instant::now()) }.unwrap();
    let published: Value =
        serde_json::from_slice(&preview(&g, &d).await.unwrap().expose().unwrap()).unwrap();
    let original = published["receipt"]["receipt_id"]
        .as_str()
        .unwrap()
        .to_owned();
    for global in [false, true] {
        // Negative capacity fixtures cloned from a genuine live receipt. They are
        // never consumed as authority; only actual preview refusal is qualified.
        let mut fixture_ids = Vec::new();
        let before;
        {
            let mut store = preview_receipt_store().lock().unwrap();
            let template = store[&original].clone();
            let existing = if global {
                store.len()
            } else {
                store
                    .values()
                    .filter(|e| e.0.account_id == c.credential())
                    .count()
            };
            let limit = if global {
                ALPHA_TAB_PREVIEW_RECEIPT_MAX_COUNT
            } else {
                ALPHA_TAB_PREVIEW_RECEIPTS_PER_ACCOUNT
            };
            for n in existing..limit {
                let id = format!("negative-capacity-{}-{n}", uuid::Uuid::new_v4());
                let mut entry = template.clone();
                entry.0.receipt_id = id.clone();
                if global {
                    entry.0.account_id = format!("negative-account-{n}");
                }
                assert!(store.insert(id.clone(), entry).is_none());
                fixture_ids.push(id);
            }
            before = store
                .keys()
                .cloned()
                .collect::<std::collections::HashSet<_>>();
        }
        let fresh = unsafe { Ingress::from_verified_host(&db, &c, &r, Instant::now()) }.unwrap();
        assert!(preview(&fresh, &delivery()).await.is_err());
        {
            let mut store = preview_receipt_store().lock().unwrap();
            assert_eq!(
                store
                    .keys()
                    .cloned()
                    .collect::<std::collections::HashSet<_>>(),
                before
            );
            assert!(!store[&original].1);
            for id in fixture_ids {
                store.remove(&id);
            }
        }
    }
    preview_receipt_store().lock().unwrap().remove(&original);
}
