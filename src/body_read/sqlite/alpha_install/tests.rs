use super::*;
use crate::control::{
    append_control_event, AlphaTabStatePayload, ControlEventPayload, NewControlEvent,
};
use crate::mcp::tools::alpha_tabs::adoption_intent::{self, Consent, Decision, Ingress, Intent};
use serde_json::json;
use tokio::sync::Barrier;
const PACKAGE: &str = "fixture.unit-b";
const BUNDLE: &str = "\u{feff}<!doctype html><html><body>Crab 🦀</body></html>";

#[tokio::test]
async fn two_fresh_receipts_retain_bounded_install_display_without_granting_request_authority() {
    Box::pin(async {
        use crate::mcp::tools::alpha_tabs::hosted_producer as producer;
        // The existing fixture supplies real viewer bindings and a target. This
        // separate package has no seeded install, outcome, receipt or pointer.
        let f = Box::pin(fixture()).await;
        let package = "fixture.receipt-request";
        let body = "\u{feff}<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Receipt request</title></head><body>é🦀</body></html>";
        let artifact = crate::store::create_record(&f.db, json!({"type":"Document","kind":"artifact","name":"Receipt source","body":body})).await.unwrap();
        crate::store::set_facet(&f.db, &artifact, crate::events::FacetSetPayload {
            key: "runtime".into(), value: Some("native.html.v1".into()), vocab_ref: None, as_of: None, observation_only: false,
        }).await.unwrap();
        let source: String = sqlx::query_scalar("SELECT id FROM content_events WHERE record_id=? AND type='record.created'").bind(&artifact).fetch_one(f.db.pool()).await.unwrap();
        let decl = declaration();
        let dd = crate::alpha_tab_body_admission_v1::declaration_digest(&decl).unwrap();
        let digest = crate::alpha_tab_body_admission_v1::install_digest(&hex::encode(Sha256::digest(body.as_bytes())), &dd, "native.html.v1");
        let retained = "Original install intent 🦀";
        let install = json!({"action":"install","package":package,"version":"1.0.0","digest":digest,"artifact_id":artifact,"source_revision":source,"declaration":decl,"request":retained,"reason":"Private receipt qualification","idempotency_key":"rq1-install"});
        let caller = viewer("acct_alice");
        let request = producer::Request::parse(&serde_json::to_vec(&install).unwrap()).unwrap();
        // Explicit privileged qualification boundary; this is not a public
        // Cookie/Origin or browser human-consent proof.
        let ingress = unsafe { producer::Ingress::from_verified_host(&f.db, &caller, &request, Instant::now()) }.unwrap();
        let mut generation = producer::install(&ingress).await.unwrap().original.event_id;
        let delivery = crate::artifact_html::LaunchDelivery::new(crate::artifact_html::RuntimeConfig::new("http://localhost:8080", "http://artifact.localhost:8080").unwrap());
        let mut prior_page: Option<Page> = None;
        let mut prior_receipt: Option<String> = None;
        for cycle in 0..2 {
            let mut preview = install.clone();
            preview["action"] = json!("preview");
            preview["expected_install_event_id"] = json!(generation);
            preview.as_object_mut().unwrap().remove("request");
            preview.as_object_mut().unwrap().remove("idempotency_key");
            let request = producer::Request::parse(&serde_json::to_vec(&preview).unwrap()).unwrap();
            let ingress = unsafe { producer::Ingress::from_verified_host(&f.db, &caller, &request, Instant::now()) }.unwrap();
            let bytes = producer::preview(&ingress, &delivery).await.unwrap().expose().unwrap();
            let checked: Value = serde_json::from_slice(&bytes).unwrap();
            let receipt = checked["receipt"]["receipt_id"].as_str().unwrap().to_owned();
            assert_ne!(prior_receipt.as_deref(), Some(receipt.as_str()));
            let mut confirm = preview;
            confirm["action"] = json!("adopt");
            for field in ["receipt_id", "preview_session", "nonce"] { confirm[field] = checked["receipt"][field].clone(); }
            confirm["idempotency_key"] = json!(format!("rq1-consent-{cycle}"));
            let request = producer::Request::parse(&serde_json::to_vec(&confirm).unwrap()).unwrap();
            let intent = request.adopt_intent().unwrap();
            let ingress = unsafe { Ingress::from_verified_host(&f.db, &caller, &intent, Instant::now()) }.unwrap();
            let Decision::Fresh(fresh) = adoption_intent::begin(&ingress).await.unwrap() else { panic!("new receipt must be fresh") };
            let outcome = fresh.prepare_current_pin().unwrap().qualify().await.unwrap().commit(request.nonce()).await.unwrap();
            let raw: String = sqlx::query_scalar("SELECT payload FROM control_events WHERE id=? AND type='alpha_tab.adopted.v2'").bind(&outcome.event_id).fetch_one(f.db.pool()).await.unwrap();
            let audit: crate::control::AlphaTabAdoptV2Payload = serde_json::from_str(&raw).unwrap();
            assert_eq!(audit.adoption, "shell_adopt.v1");
            assert_eq!(audit.receipt_id.as_deref(), Some(receipt.as_str()));
            assert_eq!(audit.preview_session.as_deref(), checked["receipt"]["preview_session"].as_str());
            assert!(audit.request.is_none());
            assert_eq!(audit.previous_event_id, generation);
            let display: Option<String> = sqlx::query_scalar("SELECT request FROM alpha_tab_installs WHERE account_id=? AND package=?").bind("acct_alice").bind(package).fetch_one(f.db.pool()).await.unwrap();
            assert_eq!(display.as_deref(), Some(retained));
            let page = execute_alpha_on(f.slots.clone(), f.db.clone(), caller.clone(), package.into(), serde_json::to_vec(&json!({"record_id":f.target,"page_bytes":32})).unwrap(), Instant::now()).await.unwrap();
            assert!(page.text.starts_with('\u{feff}'));
            assert_eq!(page.body_digest, hex::encode(Sha256::digest("\u{feff}🦀".repeat(70000).as_bytes())));
            if let Some(old) = &prior_page {
                assert_ne!(page.revision, old.revision);
                assert_eq!(execute_alpha_on(f.slots.clone(), f.db.clone(), caller.clone(), package.into(), serde_json::to_vec(&next(old)).unwrap(), Instant::now()).await.err(), Some(Failure::InvalidCursor));
            }
            generation = outcome.event_id;
            prior_page = Some(page);
            prior_receipt = Some(receipt);
        }
        // Isolated projection fault injection: no control/audit rewrite and no
        // widening of the accepted request storage/type/scalar bounds.
        let mut connection = f.db.write_pool().acquire().await.unwrap();
        sqlx::query("PRAGMA ignore_check_constraints=ON")
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query("UPDATE alpha_tab_installs SET request=x'6162' WHERE account_id=? AND package=?").bind("acct_alice").bind(package).execute(&mut *connection).await.unwrap();
        for bad in [None, Some(" ".to_owned()), Some("a".repeat(501))] {
            if let Some(bad) = bad { sqlx::query("UPDATE alpha_tab_installs SET request=? WHERE account_id=? AND package=?").bind(bad).bind("acct_alice").bind(package).execute(&mut *connection).await.unwrap(); }
            assert_eq!(execute_alpha_on(f.slots.clone(), f.db.clone(), caller.clone(), package.into(), serde_json::to_vec(&json!({"record_id":f.target})).unwrap(), Instant::now()).await.err(), Some(Failure::SourceIntegrity));
        }
        sqlx::query("UPDATE alpha_tab_installs SET request=? WHERE account_id=? AND package=?").bind(retained).bind("acct_alice").bind(package).execute(&mut *connection).await.unwrap();
        sqlx::query("PRAGMA ignore_check_constraints=OFF")
            .execute(&mut *connection)
            .await
            .unwrap();
        connection.close().await.unwrap();
        assert!(execute_alpha_on(f.slots.clone(), f.db.clone(), caller, package.into(), serde_json::to_vec(&json!({"record_id":f.target})).unwrap(), Instant::now()).await.is_ok());
        f.db.close().await;
    }).await;
}
fn declaration() -> Value {
    json!({"needs":[{"need":"records.body.read.v1","scope":"viewer-visible-current-bodies"}],"effects":[]})
}
fn viewer(name: &str) -> Caller {
    Caller::authenticated(name).with_hosting_member(true)
}
struct Fixture {
    _dir: tempfile::TempDir,
    db: Db,
    artifact: String,
    revision: String,
    target: String,
    intent: Intent,
    slots: Arc<Semaphore>,
    original: String,
}
async fn fixture() -> Fixture {
    fixture_with_source_body(BUNDLE).await
}
async fn fixture_with_source_body(source_body: &str) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let db = crate::create_database(dir.path().join("unit-b.db").to_str().unwrap())
        .await
        .unwrap();
    for (name, token) in [("Alice", "acct_alice"), ("Bea", "acct_bea")] {
        let person=crate::store::create_record(&db,json!({"type":"Entity","kind":"person","name":name,"home_id":crate::schema::ROOT_RECORD_ID})).await.unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act = crate::act::ActAllocation::new();
        Box::pin(crate::identity::add_binding_internal_in(
            &mut tx,
            "engine:unit-b-fixture",
            "Operator fixture account binding",
            &person,
            "account",
            token,
            true,
            &mut act,
        ))
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    let artifact=crate::store::create_record(&db,json!({"type":"Document","kind":"artifact","name":"Unit B app","home_id":crate::schema::ROOT_RECORD_ID,"body":source_body})).await.unwrap();
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
    let revision:String=sqlx::query_scalar("SELECT id FROM content_events WHERE record_id=? AND type='record.created' ORDER BY seq LIMIT 1").bind(&artifact).fetch_one(db.pool()).await.unwrap();
    let decl = declaration();
    let dd = crate::alpha_tab_body_admission_v1::declaration_digest(&decl).unwrap();
    let bundle = hex::encode(Sha256::digest(source_body.as_bytes()));
    let digest = crate::alpha_tab_body_admission_v1::install_digest(&bundle, &dd, "native.html.v1");
    // Operator-trusted install precondition ONLY. Actual service emits feature v2.
    let installed = append_control_event(
        &db,
        NewControlEvent::authored(
            "unit-b-install",
            crate::control::alpha_tab_aggregate_id("acct_alice", PACKAGE),
            "acct_alice",
            None,
            "Operator install qualification",
            ControlEventPayload::AlphaTabInstalled(AlphaTabStatePayload {
                account_id: "acct_alice".into(),
                package: PACKAGE.into(),
                version: "1.0.0".into(),
                digest: digest.clone(),
                artifact_id: artifact.clone(),
                consented_source_revision: revision.clone(),
                declaration_digest: dd,
                consented_declaration: decl.clone(),
                adoption: "caller_asserted".into(),
                request: Some("Unit B authored app".into()),
                previous_event_id: None,
            }),
        )
        .unwrap(),
    )
    .await
    .unwrap();
    let intent = Intent {
        package: PACKAGE.into(),
        version: "1.0.0".into(),
        digest,
        artifact_id: artifact.clone(),
        source_revision: revision.clone(),
        declaration: decl,
        expected_install_event_id: installed.id,
        reason: "Private Unit B adoption".into(),
        idempotency_key: Some("unit-b-adopt".into()),
        consent: Consent::Authored {
            launch_id: None,
            authored_run_key: None,
        },
    };
    let caller = viewer("acct_alice");
    // Privileged qualification ingress, not an externally reachable producer.
    let ingress =
        unsafe { Ingress::from_verified_host(&db, &caller, &intent, Instant::now()) }.unwrap();
    let Decision::Fresh(fresh) = adoption_intent::begin(&ingress).await.unwrap() else {
        panic!("fresh install")
    };
    let outcome = fresh
        .prepare_current_pin()
        .unwrap()
        .qualify()
        .await
        .unwrap()
        .commit(None)
        .await
        .unwrap();
    let target=crate::store::create_record(&db,json!({"type":"Document","kind":"note","name":"Target","home_id":crate::schema::ROOT_RECORD_ID,"body":"\u{feff}🦀".repeat(70000)})).await.unwrap();
    Fixture {
        _dir: dir,
        db,
        artifact,
        revision,
        target,
        intent,
        slots: Arc::new(Semaphore::new(2)),
        original: outcome.event_id,
    }
}
async fn read(f: &Fixture, request: Value) -> Result<Page> {
    execute_alpha_on(
        f.slots.clone(),
        f.db.clone(),
        viewer("acct_alice"),
        PACKAGE.into(),
        serde_json::to_vec(&request).unwrap(),
        Instant::now(),
    )
    .await
}
fn next(p: &Page) -> Value {
    json!({"record_id":p.record_id,"revision":p.revision,"cursor":p.next_cursor})
}
fn state(f: &Fixture, previous: &str, adoption: &str) -> AlphaTabStatePayload {
    AlphaTabStatePayload {
        account_id: "acct_alice".into(),
        package: PACKAGE.into(),
        version: f.intent.version.clone(),
        digest: f.intent.digest.clone(),
        artifact_id: f.artifact.clone(),
        consented_source_revision: f.revision.clone(),
        declaration_digest: crate::alpha_tab_body_admission_v1::declaration_digest(
            &f.intent.declaration,
        )
        .unwrap(),
        consented_declaration: f.intent.declaration.clone(),
        adoption: adoption.into(),
        request: Some("Unit B authored app".into()),
        previous_event_id: Some(previous.into()),
    }
}
async fn disable(f: &Fixture) -> String {
    // Match alpha_tabs::install_payload used by the real transition helper:
    // state carriers are caller_asserted; disabled projection preserves adoption.
    append_control_event(
        &f.db,
        NewControlEvent::authored(
            "unit-b-disable",
            crate::control::alpha_tab_aggregate_id("acct_alice", PACKAGE),
            "acct_alice",
            None,
            "Disable fixture",
            ControlEventPayload::AlphaTabDisabled(state(f, &f.original, "caller_asserted")),
        )
        .unwrap(),
    )
    .await
    .unwrap()
    .id
}

#[tokio::test]
async fn main_update_revokes_old_read_but_new_trusted_authored_generation_is_useful() {
    let mut f = Box::pin(fixture()).await;
    let old = read(&f, json!({"record_id":f.target,"page_bytes":32}))
        .await
        .unwrap();
    let pin = state(&f, &f.original, "shell_auto.v1");
    let raw: String =
        sqlx::query_scalar("SELECT adoption_provenance FROM alpha_tab_installs WHERE package=?")
            .bind(PACKAGE)
            .fetch_one(f.db.pool())
            .await
            .unwrap();
    let mut provenance: crate::control::AlphaTabAdoptionProvenance =
        serde_json::from_str(&raw).unwrap();
    provenance.carried_from_event_id = Some(f.original.clone());
    let update = crate::control::AlphaTabUpdatePayload {
        account_id: pin.account_id.clone(),
        package: pin.package.clone(),
        version: pin.version.clone(),
        digest: pin.digest.clone(),
        artifact_id: pin.artifact_id.clone(),
        consented_source_revision: pin.consented_source_revision.clone(),
        declaration_digest: pin.declaration_digest.clone(),
        consented_declaration: pin.consented_declaration.clone(),
        previous_event_id: f.original.clone(),
        previous_pin_digest: crate::control::alpha_tab_pin_digest(&pin).unwrap(),
        status: "installed".into(),
        request: pin.request.clone(),
        command_digest: "d".repeat(64),
        adoption: "shell_auto.v1".into(),
        adoption_basis: "carried".into(),
        adoption_provenance: Some(provenance),
    };
    let updated = append_control_event(
        &f.db,
        NewControlEvent::authored(
            "unit-b-main-update",
            crate::control::alpha_tab_aggregate_id("acct_alice", PACKAGE),
            "acct_alice",
            None,
            "Canonical same declaration update",
            ControlEventPayload::AlphaTabUpdated(Box::new(update)),
        )
        .unwrap(),
    )
    .await
    .unwrap();
    let pointer: Option<String> = sqlx::query_scalar(
        "SELECT body_read_admission_event_id FROM alpha_tab_installs WHERE package=?",
    )
    .bind(PACKAGE)
    .fetch_one(f.db.pool())
    .await
    .unwrap();
    assert!(pointer.is_none());
    assert_eq!(
        read(&f, json!({"record_id":"missing-target"})).await.err(),
        Some(Failure::AdoptionRequired)
    );
    let caller = viewer("acct_alice");
    // Old intent outcome is audit-only: no current projection or fresh consent.
    let g =
        unsafe { Ingress::from_verified_host(&f.db, &caller, &f.intent, Instant::now()) }.unwrap();
    let Decision::Recovered(out) = adoption_intent::begin(&g).await.unwrap() else {
        panic!("historical outcome");
    };
    assert_eq!(out.event_id, f.original);
    let mut connection = f.db.write_pool().acquire().await.unwrap();
    let expected: Option<String> =
        sqlx::query_scalar("SELECT adoption_provenance FROM alpha_tab_installs WHERE package=?")
            .bind(PACKAGE)
            .fetch_one(&mut *connection)
            .await
            .unwrap();
    crate::control::alpha_tab_provenance::backfill(&mut connection)
        .await
        .unwrap();
    let recomputed: Option<String> =
        sqlx::query_scalar("SELECT adoption_provenance FROM alpha_tab_installs WHERE package=?")
            .bind(PACKAGE)
            .fetch_one(&mut *connection)
            .await
            .unwrap();
    assert_eq!(recomputed, expected);
    drop(connection);
    f.intent.expected_install_event_id = updated.id;
    f.intent.idempotency_key = Some("unit-b-after-main-update".into());
    let g =
        unsafe { Ingress::from_verified_host(&f.db, &caller, &f.intent, Instant::now()) }.unwrap();
    let Decision::Fresh(fresh) = adoption_intent::begin(&g).await.unwrap() else {
        panic!("fresh generation");
    };
    fresh
        .prepare_current_pin()
        .unwrap()
        .qualify()
        .await
        .unwrap()
        .commit(None)
        .await
        .unwrap();
    let page = read(&f, json!({"record_id":f.target,"page_bytes":32}))
        .await
        .unwrap();
    assert_eq!(page.text, old.text);
    assert_eq!(page.body_digest, old.body_digest);
    assert_ne!(page.revision, old.revision);
    assert_eq!(
        read(&f, next(&old)).await.err(),
        Some(Failure::InvalidCursor)
    );
    assert!(
        crate::conformance::rebuild_and_diff_control(&f.db)
            .await
            .unwrap()
            .equal
    );
    // Isolated privileged SQL fault fixture, not a healthy writer/storage cap.
    // The reader must reserve its nine-copy predecessor work before hydration
    // or diagnostics about the deliberately missing target.
    let mut corrupt = f.db.write_pool().acquire().await.unwrap();
    sqlx::query("DROP TRIGGER control_events_no_update")
        .execute(&mut *corrupt)
        .await
        .unwrap();
    let raw: String = sqlx::query_scalar("SELECT payload FROM control_events WHERE id=?")
        .bind(&f.intent.expected_install_event_id)
        .fetch_one(&mut *corrupt)
        .await
        .unwrap();
    let mut payload: Value = serde_json::from_str(&raw).unwrap();
    payload["padding"] = json!("x".repeat(4 * 1024 * 1024));
    sqlx::query("UPDATE control_events SET payload=? WHERE id=?")
        .bind(payload.to_string())
        .bind(&f.intent.expected_install_event_id)
        .execute(&mut *corrupt)
        .await
        .unwrap();
    assert_eq!(
        read(&f, json!({"record_id":"missing-target"})).await.err(),
        Some(Failure::ProvenanceWork)
    );
    corrupt.close().await.unwrap();
    f.db.close().await;
}
#[tokio::test]
async fn foreign_import_clears_body_and_asserted_root_until_genuinely_fresh_adoption() {
    let mut f = Box::pin(fixture()).await;
    let old = read(&f, json!({"record_id": f.target, "page_bytes": 32}))
        .await
        .unwrap();
    let bytes = crate::interchange::export_canonical_interchange(&f.db)
        .await
        .unwrap();
    let destination = f._dir.path().join("foreign.db");
    let imported = crate::interchange::import_canonical_interchange(
        &bytes,
        &destination,
        crate::interchange::ImportContinuity::ForeignBoundary,
    )
    .await
    .unwrap();
    f.db.close().await;
    f.db = imported;
    let row: (String, String, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT event_id,adoption,adoption_provenance,body_read_admission_event_id FROM alpha_tab_installs WHERE account_id='acct_alice' AND package=?",
    ).bind(PACKAGE).fetch_one(f.db.pool()).await.unwrap();
    assert_eq!(row.1, "caller_asserted");
    assert!(row.2.is_none() && row.3.is_none());
    let kind: String = sqlx::query_scalar("SELECT type FROM control_events WHERE id=?")
        .bind(&row.0)
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    assert_eq!(kind, "alpha_tab.import_reset");
    assert_eq!(
        read(&f, json!({"record_id": "missing-target"})).await.err(),
        Some(Failure::AdoptionRequired)
    );
    f.intent.expected_install_event_id = row.0;
    f.intent.idempotency_key = Some("unit-b-after-foreign-import".into());
    let caller = viewer("acct_alice");
    // Existing privileged embedding boundary; import itself cannot mint authority.
    let ingress =
        unsafe { Ingress::from_verified_host(&f.db, &caller, &f.intent, Instant::now()) }.unwrap();
    let Decision::Fresh(fresh) = adoption_intent::begin(&ingress).await.unwrap() else {
        panic!("fresh consent after foreign boundary");
    };
    let outcome = fresh
        .prepare_current_pin()
        .unwrap()
        .qualify()
        .await
        .unwrap()
        .commit(None)
        .await
        .unwrap();
    assert_ne!(outcome.event_id, f.original);
    let page = read(&f, json!({"record_id": f.target, "page_bytes": 32}))
        .await
        .unwrap();
    assert_eq!(page.text, old.text);
    assert_eq!(page.body_digest, old.body_digest);
    assert_ne!(page.revision, old.revision);
    assert_eq!(
        read(&f, next(&old)).await.err(),
        Some(Failure::InvalidCursor)
    );
    assert!(
        crate::conformance::rebuild_and_diff_control(&f.db)
            .await
            .unwrap()
            .equal
    );
    f.db.close().await;
}

#[test]
fn golden_literal_tuples_and_closed_serving_identity_rules() {
    assert_eq!(
        tuple("source", &["acct_雪\"", PACKAGE, "artifact\\x"]).unwrap(),
        "cbfe19ff5bca697c19358b6d20e975488e04caf03136a6c14b0b061b71ddf05a"
    );
    assert_eq!(
        tuple(
            "generation",
            &[
                "11111111-1111-4111-8111-111111111111",
                "22222222-2222-4222-8222-222222222222",
                "33333333-3333-4333-8333-333333333333"
            ]
        )
        .unwrap(),
        "147563fe4c0829e61dd69668800bf477ed2dfe033673c373967c3e50fd58c193"
    );
    assert_eq!(
        tuple(
            "runtime-pin",
            &[
                "event-雪",
                "native.html.v1",
                &"a".repeat(64),
                &format!("sha256:{}", "b".repeat(64))
            ]
        )
        .unwrap(),
        "ee2923b79c4769a45ed8eb9022de0eff1bf510c473685dd880dc3965c015fcac"
    );
    for bad in [
        "", "alpha", "A.alpha", "a.-b", "a.b-", "a. b", "a..b", "a.雪",
    ] {
        assert!(!package_valid(bad), "{bad}");
    }
    assert!(package_valid(PACKAGE));
    assert!(!version("1.2"));
    assert!(!version("1.123456789.0"));
    assert!(version("1.2.3"));
}
#[tokio::test]
async fn actual_adopted_source_reconstructs_large_utf8_with_exact_guard_each_page() {
    let f = Box::pin(fixture()).await;
    let expected = "\u{feff}🦀".repeat(70000);
    let guard = hex::encode(Sha256::digest(expected.as_bytes()));
    let mut p = read(&f, json!({"record_id":f.target})).await.unwrap();
    let revision = p.revision.clone();
    let mut all = String::new();
    let mut pages = 0;
    loop {
        assert_eq!(p.revision, revision);
        assert_eq!(p.body_digest, guard);
        all.push_str(&p.text);
        pages += 1;
        if p.complete {
            break;
        }
        p = read(&f, next(&p)).await.unwrap();
    }
    assert_eq!(all, expected);
    assert!(pages > 8);
    assert!(expected.len() > 262144 && expected.chars().count() > 120000);
    assert_eq!(f.slots.available_permits(), 2);
    assert!(
        tokio::time::timeout(Duration::from_secs(2), f.db.fence_body_retirement().drain())
            .await
            .unwrap()
    );
    f.db.close().await;
}
#[tokio::test]
async fn source_disable_restore_and_fresh_readopt_precede_cursor_target_diagnostics() {
    let mut f = Box::pin(fixture()).await;
    let first = read(&f, json!({"record_id":f.target,"page_bytes":32}))
        .await
        .unwrap();
    let disabled = disable(&f).await;
    assert_eq!(
        read(&f, next(&first)).await.err(),
        Some(Failure::SourceIntegrity)
    );
    let restored = append_control_event(
        &f.db,
        NewControlEvent::authored(
            "unit-b-restore",
            crate::control::alpha_tab_aggregate_id("acct_alice", PACKAGE),
            "acct_alice",
            None,
            "Restore fixture",
            ControlEventPayload::AlphaTabRestored(state(&f, &disabled, "caller_asserted")),
        )
        .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(
        read(
            &f,
            json!({"record_id":"unavailable","cursor":"malformed","revision":"malformed"})
        )
        .await
        .err(),
        Some(Failure::AdoptionRequired)
    );
    f.intent.expected_install_event_id = restored.id;
    f.intent.idempotency_key = Some("unit-b-readopt".into());
    let caller = viewer("acct_alice");
    let ingress =
        unsafe { Ingress::from_verified_host(&f.db, &caller, &f.intent, Instant::now()) }.unwrap();
    let Decision::Fresh(fresh) = adoption_intent::begin(&ingress).await.unwrap() else {
        panic!("fresh")
    };
    fresh
        .prepare_current_pin()
        .unwrap()
        .qualify()
        .await
        .unwrap()
        .commit(None)
        .await
        .unwrap();
    assert_eq!(
        read(&f, next(&first)).await.err(),
        Some(Failure::InvalidCursor)
    );
    assert!(read(&f, json!({"record_id":f.target})).await.is_ok());
    f.db.close().await;
}
#[tokio::test]
async fn markerless_and_bare_history_are_distinct_without_target_disclosure() {
    let f = Box::pin(fixture()).await;
    sqlx::query("UPDATE alpha_tab_installs SET body_read_admission_event_id=NULL WHERE account_id='acct_alice' AND package=?").bind(PACKAGE).execute(f.db.write_pool()).await.unwrap();
    assert_eq!(
        read(&f, json!({"record_id":"absent"})).await.err(),
        Some(Failure::AdoptionRequired)
    );
    for decl in [
        json!({"needs":["records.body.read.v1"],"effects":[]}),
        json!({"needs":[],"effects":[]}),
    ] {
        sqlx::query("UPDATE alpha_tab_installs SET consented_declaration=? WHERE package=?")
            .bind(decl.to_string())
            .bind(PACKAGE)
            .execute(f.db.write_pool())
            .await
            .unwrap();
        assert_eq!(
            read(&f, json!({"record_id":"absent"})).await.err(),
            Some(Failure::UndeclaredRead)
        );
    }
    f.db.close().await;
}
#[tokio::test]
async fn exact_full_row_marker_runtime_and_retained_body_refuse_drift() {
    let f = Box::pin(fixture()).await;
    // Corruption stays in this isolated file; FK toggle is connection-local.
    let mut corrupt = f.db.write_pool().acquire().await.unwrap();
    sqlx::query("PRAGMA foreign_keys=OFF")
        .execute(&mut *corrupt)
        .await
        .unwrap();
    for (column, bad) in [
        ("event_id", "11111111-1111-4111-8111-111111111111"),
        ("version", "2.0.0"),
        ("digest", "sha256:bad"),
        ("artifact_id", "missing-artifact"),
        ("consented_source_revision", "missing-revision"),
        (
            "declaration_digest",
            "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
        ),
        ("request", "altered"),
        (
            "body_read_admission_event_id",
            "11111111-1111-4111-8111-111111111111",
        ),
    ] {
        let original: String = sqlx::query_scalar(&format!(
            "SELECT {column} FROM alpha_tab_installs WHERE package=?"
        ))
        .bind(PACKAGE)
        .fetch_one(f.db.pool())
        .await
        .unwrap();
        let sql = format!("UPDATE alpha_tab_installs SET {column}=? WHERE package=?");
        sqlx::query(&sql)
            .bind(bad)
            .bind(PACKAGE)
            .execute(&mut *corrupt)
            .await
            .unwrap();
        assert_eq!(
            read(&f, json!({"record_id":"absent"})).await.err(),
            Some(Failure::SourceIntegrity),
            "{column}"
        );
        sqlx::query(&sql)
            .bind(original)
            .bind(PACKAGE)
            .execute(&mut *corrupt)
            .await
            .unwrap();
    }
    sqlx::query(
        "UPDATE facet_values SET value='native.html.v2' WHERE record_id=? AND key='runtime'",
    )
    .bind(&f.artifact)
    .execute(&mut *corrupt)
    .await
    .unwrap();
    assert_eq!(
        read(&f, json!({"record_id":"absent"})).await.err(),
        Some(Failure::SourceIntegrity)
    );
    sqlx::query(
        "UPDATE facet_values SET value='native.html.v1' WHERE record_id=? AND key='runtime'",
    )
    .bind(&f.artifact)
    .execute(&mut *corrupt)
    .await
    .unwrap();
    // Isolated corruption fixture, never production trigger weakening.
    sqlx::query("DROP TRIGGER content_events_no_update")
        .execute(&mut *corrupt)
        .await
        .unwrap();
    for payload in [
        "null",
        "[]",
        "{}",
        "{\"body\":null}",
        "{\"body\":{}}",
        "{\"body\":\"different bytes\"}",
    ] {
        sqlx::query("UPDATE content_events SET payload=? WHERE id=?")
            .bind(payload)
            .bind(&f.revision)
            .execute(&mut *corrupt)
            .await
            .unwrap();
        assert_eq!(
            read(&f, json!({"record_id":"absent"})).await.err(),
            Some(Failure::SourceIntegrity)
        );
    }
    sqlx::query("PRAGMA foreign_keys=ON")
        .execute(&mut *corrupt)
        .await
        .unwrap();
    corrupt.close().await.unwrap();
    f.db.close().await;
}
#[tokio::test]
async fn source_and_target_snapshot_remain_paired_across_committed_mutation() {
    eprintln!("Unit B snapshot: fixture start");
    let f = Box::pin(fixture()).await;
    eprintln!("Unit B snapshot: fixture ready");
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    eprintln!("Unit B snapshot: spawning owned read");
    let job = tokio::spawn(Box::pin(execute_owned(
        f.slots.clone(),
        f.db.clone(),
        viewer("acct_alice"),
        SourceLocator::AlphaInstall {
            package: PACKAGE.into(),
            after_source: Some((entered.clone(), release.clone())),
        },
        serde_json::to_vec(&json!({"record_id":f.target,"page_bytes":32})).unwrap(),
        Instant::now(),
    )));
    tokio::time::timeout(Duration::from_secs(2), entered.wait())
        .await
        .unwrap();
    eprintln!("Unit B snapshot: source resolved; disabling");
    Box::pin(disable(&f)).await;
    eprintln!("Unit B snapshot: disabled; updating target");
    Box::pin(crate::store::update_record(
        &f.db,
        &f.target,
        json!({"body":"changed after snapshot"}),
    ))
    .await
    .unwrap();
    eprintln!("Unit B snapshot: target updated; releasing read");
    release.wait().await;
    let page = job.await.unwrap().unwrap();
    eprintln!("Unit B snapshot: read joined");
    assert!(page.text.starts_with('\u{feff}'));
    assert_eq!(page.total_bytes, ("\u{feff}🦀".repeat(70000)).len() as u64);
    assert_eq!(
        read(&f, next(&page)).await.err(),
        Some(Failure::SourceIntegrity)
    );
    f.db.close().await;
}
#[tokio::test]
async fn raw_ingress_expiry_and_locator_bounds_never_acquire() {
    let f = Box::pin(fixture()).await;
    let slots = Arc::new(Semaphore::new(0));
    for package in ["".to_string(), format!("a.{}", "b".repeat(257))] {
        assert_eq!(
            execute_alpha_on(
                slots.clone(),
                f.db.clone(),
                viewer("acct_alice"),
                package,
                b"{\"record_id\":\"absent\"}".to_vec(),
                Instant::now()
            )
            .await
            .err(),
            Some(Failure::SourceIntegrity)
        );
    }
    assert_eq!(
        execute_alpha_on(
            slots,
            f.db.clone(),
            viewer("acct_alice"),
            PACKAGE.into(),
            b"{\"record_id\":\"absent\"}".to_vec(),
            Instant::now() - Duration::from_secs(6)
        )
        .await
        .err(),
        Some(Failure::Timeout)
    );
    f.db.close().await;
}
#[tokio::test]
async fn proof_cpu_cancel_keeps_same_slot_until_completion_and_close_ack() {
    let f = Box::pin(fixture()).await;
    let slots = Arc::new(Semaphore::new(1));
    let mut holder = fixture_resources(&f.db, &slots).await;
    let gate = f.db.owned_portability_policy_gate();
    assert!(gate.try_write().is_err());
    let (started, start) = tokio::sync::oneshot::channel();
    let (send, wait) = std::sync::mpsc::channel();
    let Resources {
        cpu: slot, budget, ..
    } = &mut holder;
    let budget = budget.as_ref().unwrap();
    let deadline = budget.deadline;
    let cancel = budget.cancelled.clone();
    let result = tokio::time::timeout(
        Duration::from_millis(50),
        cpu(slot, budget, move || {
            let _ = started.send(());
            wait.recv().unwrap();
            Ok(CpuOutput::AlphaBody(String::new(), "proof".into()))
        }),
    )
    .await;
    assert!(result.is_err());
    start.await.unwrap();
    cancel.store(true, Ordering::SeqCst);
    assert_eq!(holder.budget.as_ref().unwrap().deadline, deadline);
    assert_eq!(holder.cpu.handles.len(), 1);
    assert!(!holder.cpu.handles[0].is_finished());
    drop(holder);
    assert!(slots.clone().try_acquire_owned().is_err());
    assert!(gate.try_write().is_err());
    send.send(()).unwrap();
    let permit = tokio::time::timeout(Duration::from_secs(2), slots.clone().acquire_owned())
        .await
        .unwrap()
        .unwrap();
    // Permit and pending policy gate release follow the consuming ticket's
    // actual registered CPU joins and raw driver shutdown, never pool size.
    assert!(gate.try_write().is_ok());
    let retirement = f.db.fence_body_retirement();
    assert!(retirement.body_complete());
    drop(permit);
    assert_eq!(slots.available_permits(), 1);
    f.db.close().await;
    assert!(retirement.retirement_complete());
}

#[tokio::test]
async fn two_genuinely_adopted_viewers_isolate_cursor_and_recheck_both_views() {
    let f = Box::pin(fixture()).await;
    let alice = read(&f, json!({"record_id":f.target,"page_bytes":32}))
        .await
        .unwrap();
    let mut initial = state(&f, &f.original, "caller_asserted");
    initial.account_id = "acct_bea".into();
    initial.previous_event_id = None;
    let installed = append_control_event(
        &f.db,
        NewControlEvent::authored(
            "unit-b-bea-install",
            crate::control::alpha_tab_aggregate_id("acct_bea", PACKAGE),
            "acct_bea",
            None,
            "Operator second viewer install",
            ControlEventPayload::AlphaTabInstalled(initial),
        )
        .unwrap(),
    )
    .await
    .unwrap();
    let mut intent = Intent {
        package: f.intent.package.clone(),
        version: f.intent.version.clone(),
        digest: f.intent.digest.clone(),
        artifact_id: f.intent.artifact_id.clone(),
        source_revision: f.intent.source_revision.clone(),
        declaration: f.intent.declaration.clone(),
        expected_install_event_id: String::new(),
        reason: f.intent.reason.clone(),
        idempotency_key: None,
        consent: Consent::Authored {
            launch_id: None,
            authored_run_key: None,
        },
    };
    intent.expected_install_event_id = installed.id;
    intent.idempotency_key = Some("unit-b-bea-adopt".into());
    let bea = viewer("acct_bea");
    let ingress =
        unsafe { Ingress::from_verified_host(&f.db, &bea, &intent, Instant::now()) }.unwrap();
    let Decision::Fresh(fresh) = adoption_intent::begin(&ingress).await.unwrap() else {
        panic!("fresh")
    };
    fresh
        .prepare_current_pin()
        .unwrap()
        .qualify()
        .await
        .unwrap()
        .commit(None)
        .await
        .unwrap();
    let bea_page = execute_alpha_on(
        f.slots.clone(),
        f.db.clone(),
        bea.clone(),
        PACKAGE.into(),
        serde_json::to_vec(&json!({"record_id":f.target,"page_bytes":32})).unwrap(),
        Instant::now(),
    )
    .await
    .unwrap();
    assert_eq!(bea_page.text, alice.text);
    assert_eq!(bea_page.body_digest, alice.body_digest);
    assert_ne!(bea_page.revision, alice.revision);
    assert_eq!(
        execute_alpha_on(
            f.slots.clone(),
            f.db.clone(),
            bea,
            PACKAGE.into(),
            serde_json::to_vec(&next(&alice)).unwrap(),
            Instant::now()
        )
        .await
        .err(),
        Some(Failure::InvalidCursor)
    );
    crate::authorization::replace_explicit_policy(&f.db, "test:unit-b", &f.target, vec![])
        .await
        .unwrap();
    assert_eq!(
        read(&f, next(&alice)).await.err(),
        Some(Failure::AccessLost)
    );
    crate::authorization::restore_inheritance(&f.db, "test:unit-b", &f.target)
        .await
        .unwrap();
    crate::authorization::replace_explicit_policy(&f.db, "test:unit-b", &f.artifact, vec![])
        .await
        .unwrap();
    assert_eq!(
        read(&f, next(&alice)).await.err(),
        Some(Failure::SourceIntegrity)
    );
    f.db.close().await;
}
#[tokio::test]
async fn cloned_handle_serves_but_reopen_fences_old_cursor_with_same_ndb_identity() {
    let mut f = Box::pin(fixture()).await;
    let first = read(&f, json!({"record_id":f.target,"page_bytes":32}))
        .await
        .unwrap();
    let identity = crate::identity::database_id(&f.db).await.unwrap();
    let handle = f.db.handle_id();
    assert!(read(&f, next(&first)).await.is_ok());
    let path = f.db.path().to_path_buf();
    f.db.close().await;
    f.db = crate::db::open_existing_database_at(&path).await.unwrap();
    assert_ne!(f.db.handle_id(), handle);
    assert_eq!(crate::identity::database_id(&f.db).await.unwrap(), identity);
    assert_eq!(
        read(&f, next(&first)).await.err(),
        Some(Failure::InvalidCursor)
    );
    assert!(read(&f, json!({"record_id":f.target})).await.is_ok());
    f.db.close().await;
}
#[tokio::test]
async fn marker_object_integrity_and_metadata_copy_work_fail_before_target_diagnostics() {
    let f = Box::pin(fixture()).await;
    let mut corrupt = f.db.write_pool().acquire().await.unwrap();
    sqlx::query("PRAGMA ignore_check_constraints=ON")
        .execute(&mut *corrupt)
        .await
        .unwrap();
    sqlx::query("DROP TRIGGER control_events_no_update")
        .execute(&mut *corrupt)
        .await
        .unwrap();
    let original: String = sqlx::query_scalar("SELECT payload FROM control_events WHERE id=?")
        .bind(&f.original)
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    let mut wrong: Value = serde_json::from_str(&original).unwrap();
    wrong["body_read_admission"]["scope"] = json!("wrong");
    let duplicate = format!(
        "{},\"account_id\":\"acct_alice\"}}",
        original.trim_end_matches('}')
    );
    for bad in [
        "null".to_string(),
        "[]".to_string(),
        wrong.to_string(),
        duplicate,
    ] {
        sqlx::query("UPDATE control_events SET payload=? WHERE id=?")
            .bind(bad)
            .bind(&f.original)
            .execute(&mut *corrupt)
            .await
            .unwrap();
        assert_eq!(
            read(&f, json!({"record_id":"absent"})).await.err(),
            Some(Failure::SourceIntegrity)
        );
    }
    sqlx::query("UPDATE control_events SET payload=? WHERE id=?")
        .bind(original)
        .bind(&f.original)
        .execute(&mut *corrupt)
        .await
        .unwrap();
    // Reservation alone exceeds 32MiB before hydration/serde. Not a writer cap.
    let large = json!({"needs":[],"effects":[],"padding":"x".repeat(4*1024*1024)}).to_string();
    sqlx::query("UPDATE alpha_tab_installs SET consented_declaration=? WHERE package=?")
        .bind(large)
        .bind(PACKAGE)
        .execute(&mut *corrupt)
        .await
        .unwrap();
    assert_eq!(
        read(&f, json!({"record_id":"absent"})).await.err(),
        Some(Failure::ProvenanceWork)
    );
    sqlx::query("PRAGMA ignore_check_constraints=OFF")
        .execute(&mut *corrupt)
        .await
        .unwrap();
    corrupt.close().await.unwrap();
    f.db.close().await;
}

#[tokio::test]
async fn trusted_control_replay_retains_v2_but_legacy_v1_clears_active_feature() {
    let mut f = Box::pin(fixture()).await;
    let first = read(&f, json!({"record_id":f.target,"page_bytes":32}))
        .await
        .unwrap();
    let mut connection = f.db.write_pool().acquire().await.unwrap();
    let events = crate::control::read_all_control_events(&mut connection)
        .await
        .unwrap();
    sqlx::query("DELETE FROM alpha_tab_installs")
        .execute(&mut *connection)
        .await
        .unwrap();
    // Rebuild the isolated aggregate INCLUDING its application bookkeeping;
    // replay is idempotent and deliberately skips an already-applied event.
    sqlx::query("DELETE FROM control_event_applications WHERE event_id IN (SELECT id FROM control_events WHERE aggregate_kind='alpha_tab' AND aggregate_id=?)")
        .bind(crate::control::alpha_tab_aggregate_id("acct_alice",PACKAGE))
        .execute(&mut *connection).await.unwrap();
    crate::control::replay_control(&mut connection, &events)
        .await
        .unwrap();
    drop(connection);
    // Restore qualification MUST drain/close/reopen before serving; never
    // treat live-handle in-place projection replacement as an admitted restore.
    let path = f.db.path().to_path_buf();
    f.db.close().await;
    f.db = crate::db::open_existing_database_at(&path).await.unwrap();
    read(&f, json!({"record_id":f.target})).await.unwrap();
    assert_eq!(
        read(&f, next(&first)).await.err(),
        Some(Failure::InvalidCursor)
    );
    append_control_event(
        &f.db,
        NewControlEvent::authored(
            "unit-b-v1-history",
            crate::control::alpha_tab_aggregate_id("acct_alice", PACKAGE),
            "acct_alice",
            None,
            "Historical v1 does not grant body feature",
            ControlEventPayload::AlphaTabAdopted(
                serde_json::from_value(
                    serde_json::to_value(state(&f, &f.original, "shell_auto.v1")).unwrap(),
                )
                .unwrap(),
            ),
        )
        .unwrap(),
    )
    .await
    .unwrap();
    let pointer:Option<String>=sqlx::query_scalar("SELECT body_read_admission_event_id FROM alpha_tab_installs WHERE account_id='acct_alice' AND package=?").bind(PACKAGE).fetch_one(f.db.pool()).await.unwrap();
    assert!(pointer.is_none());
    assert_eq!(
        read(&f, next(&first)).await.err(),
        Some(Failure::AdoptionRequired)
    );
    f.db.close().await;
}

#[test]
fn mixed_reply_buffer_cap_cancel_and_provenance_reservation_are_closed() {
    use std::io::Write;
    let mut budget = Budget::new();
    budget.charge(2 * MIXED_REPLY_BYTES as i64, true).unwrap();
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(MIXED_REPLY_BYTES).unwrap();
    let capacity = bytes.capacity();
    let mut writer = MixedReplyWriter {
        bytes: &mut bytes,
        budget: &budget,
    };
    writer.write_all(&vec![b'x'; MIXED_REPLY_BYTES]).unwrap();
    assert!(writer.write_all(b"x").is_err());
    assert_eq!(bytes.len(), MIXED_REPLY_BYTES);
    assert_eq!(bytes.capacity(), capacity);
    budget.cancelled.store(true, Ordering::SeqCst);
    assert!(MixedReplyWriter {
        bytes: &mut Vec::new(),
        budget: &budget
    }
    .write_all(b"{}")
    .is_err());
    let mut exhausted = Budget::new();
    exhausted.provenance = PROVENANCE;
    assert_eq!(
        exhausted.charge(2 * MIXED_REPLY_BYTES as i64, true).err(),
        Some(Failure::ProvenanceWork)
    );
    // Budget refusal is before reply allocation/publication, not driver ACK.
}

#[tokio::test]
async fn mixed_snapshot_raw_receipt_is_actual_current_v2_and_v1_has_none() {
    Box::pin(async {
        let f = Box::pin(fixture()).await;
        // Explicit operator fixture install precondition; genuine A completion
        // supplies v2. Real Cookie producer qualification is in Held tests.
        for mixed in [false, true] {
            let mut holder = fixture_resources(&f.db, &f.slots).await;
            {
            let Resources { connection, budget, cpu, .. } = &mut holder;
            let transaction = connection.as_mut().unwrap().begin().await.unwrap();
            let mut snapshot = ReadSnapshot { transaction, budget: budget.as_mut().unwrap(),
                viewer: "acct_alice".into(), member: true };
            let handle = f.db.handle_id().to_string();
            let proof = if mixed { resolve_current_mixed(&mut snapshot, PACKAGE, &handle, cpu).await }
                else { resolve_current(&mut snapshot, PACKAGE, &handle, cpu).await }.unwrap();
            assert_eq!(proof.body, BUNDLE);
            if mixed {
                let raw = serde_json::to_value(proof.mixed_binding.as_ref().unwrap()).unwrap();
                assert_eq!(raw["pin"], json!({"package":f.intent.package,"version":f.intent.version,
                    "digest":f.intent.digest,"artifact_id":f.artifact,"source_revision":f.revision,
                    "declaration_digest":crate::alpha_tab_body_admission_v1::declaration_digest(&f.intent.declaration).unwrap()}));
                assert_eq!(raw["install_event_id"], f.original);
                assert_eq!(raw["body_admission_event_id"], f.original);
                assert_ne!(raw["install_event_id"], f.intent.expected_install_event_id);
                assert_eq!(raw["source"], json!({"event_id":f.revision,
                    "bundle_sha256":hex::encode(Sha256::digest(BUNDLE.as_bytes())),
                    "body_digest":hex::encode(Sha256::digest(BUNDLE.as_bytes()))}));
            } else { assert!(proof.mixed_binding.is_none()); }
            snapshot.transaction.rollback().await.unwrap();
            }
            holder.finish().await.unwrap(); // actual raw/registered CPU close
            assert_eq!(f.slots.available_permits(), 2);
        }
        f.db.close().await;
    }).await;
}

#[tokio::test]
async fn mixed_issuance_caller_cancel_before_ack_cleans_reserved_pair_after_real_finalization() {
    Box::pin(async {
        use crate::body_read::hosted::{self, OwnedRequest, Work};
        // Launch preparation validates HTML before the genuine BeforeAck probe.
        // Keep the shared BUNDLE/default fixture unchanged for snapshot tests.
        let source_body = "\u{feff}<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Mixed ACK qualification</title></head><body><main><h1>Mixed ACK qualification</h1><p>Crab 🦀</p></main></body></html>";
        let f = Box::pin(fixture_with_source_body(source_body)).await;
        let owner = hosted::process();
        let delivery = crate::artifact_html::LaunchDelivery::new(
            crate::artifact_html::RuntimeConfig::new(
                "http://localhost:8080",
                "http://artifact.localhost:8080",
            )
            .unwrap(),
        );
        let probe = Arc::new(BrokerProbe {
            phase: ProbePhase::BeforeAck,
            entered: Semaphore::new(0),
            release: tokio::sync::Notify::new(),
            html_wait: std::sync::Mutex::new(None),
            acknowledged: AtomicBool::new(false),
            reserved: AtomicBool::new(false),
            cleaned: AtomicBool::new(false),
        });
        // Synchronous release is installed BEFORE polling/spawning. An assertion
        // unwind cannot strand this actual supervisor at the fixture barrier.
        struct Release(Arc<BrokerProbe>);
        impl Drop for Release {
            fn drop(&mut self) {
                self.0.release.notify_one();
            }
        }
        let _release = Release(probe.clone());
        let barrier = crate::mcp::DeploymentMutationBarrier::default();
        let admission = barrier
            .admit(
                &crate::DeploymentReadOnlyOperation::server("records.body.read.v1"),
                crate::mcp::OperationAccess::Read,
            )
            .unwrap();
        let started = Instant::now();
        let work = Work {
            owner,
            db: f.db.clone(),
            caller: viewer("acct_alice"),
            request: OwnedRequest::IssueMixed(PACKAGE.into()),
            cookie: "fixture-cookie".into(),
            origin: "http://localhost:8080".into(),
            started,
            admission,
            delivery,
            probe: Some(probe.clone()),
        };
        // Internal trusted footing only: no Cookie/Origin HTTP admission claim.
        let caller = tokio::spawn(execute_hosted(work));
        tokio::time::timeout(Duration::from_secs(2), probe.entered.acquire())
            .await
            .unwrap()
            .unwrap()
            .forget();
        assert!(probe.reserved.load(Ordering::SeqCst));
        assert!(!probe.acknowledged.load(Ordering::SeqCst));
        assert!(!probe.cleaned.load(Ordering::SeqCst));
        assert_eq!(owner.slots.available_permits(), 1);
        caller.abort();
        assert!(matches!(caller.await, Err(e) if e.is_cancelled()));
        assert_eq!(owner.slots.available_permits(), 1); // caller reap is NOT ACK
        probe.release.notify_one();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !probe.cleaned.load(Ordering::SeqCst) || owner.slots.available_permits() != 2 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        assert!(probe.acknowledged.load(Ordering::SeqCst));
        // These flags are set by actual finish_physical/reservation Drop, not
        // injected ACK/counts; no Issued reply can reach the abandoned caller.
        f.db.close().await;
    })
    .await;
}
