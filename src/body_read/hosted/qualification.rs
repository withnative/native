//! Native operator fixtures qualify the REAL hosted supervisor; HTTP credential
//! verification is covered separately by the genuine Held private router.
//! Only ordinary account/record fixtures are initialized. Install, preview,
//! receipt, v2 and source lineage are produced by the accepted private services.
use super::*;
use crate::body_read::sqlite::{BrokerProbe, ProbePhase};
use crate::mcp::tools::alpha_tabs::{adoption_intent as adoption, hosted_producer as producer};
use axum::{
    body::Body,
    http::{header::HOST, HeaderValue, Request as HttpRequest},
};
use futures::FutureExt;
use serde_json::{json, Value};
use sqlx::Row;
use tower::ServiceExt;

struct Fixture {
    _directory: tempfile::TempDir,
    db: Db,
    caller: Caller,
    delivery: crate::artifact_html::LaunchDelivery,
    owner: &'static Process,
    barrier: crate::mcp::DeploymentMutationBarrier,
    target: String,
    root_intent: adoption::Intent,
    root_nonce: Option<String>,
    root_event: String,
    root_audit: (Option<String>, Option<i64>, Option<String>),
}
const PACKAGE: &str = "fixture.supervisor";
const ORIGIN: &str = "https://parent.test";
const BODY: &str = "\u{feff}<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Supervisor</title></head><body>Actual producer é😀</body></html>";
enum FixtureConsent {
    HumanReceipt,
    TrustedAuthored,
}
async fn fixture() -> Fixture {
    fixture_with_consent(FixtureConsent::HumanReceipt).await
}
async fn fixture_with_consent(consent: FixtureConsent) -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let db = crate::create_database(directory.path().join("supervisor.db").to_str().unwrap())
        .await
        .unwrap();
    let account = "acct_supervisor";
    let person = crate::store::create_record(
        &db,
        json!({"type":"Entity","kind":"person","name":"Operator fixture","home_id":crate::schema::ROOT_RECORD_ID}),
    )
    .await
    .unwrap();
    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    let mut act = crate::act::ActAllocation::new();
    crate::identity::add_binding_internal_in(
        &mut tx,
        account,
        "Provision audited operator fixture identity",
        &person,
        "account",
        account,
        true,
        &mut act,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let caller = Caller::authenticated(account).with_hosting_member(true);
    let artifact = crate::store::create_record_as(
        &db,
        json!({"type":"Document","kind":"artifact","name":"Genuine supervisor source","home_id":crate::schema::ROOT_RECORD_ID,"body":BODY}),
        Some(account),
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
    let revision: String = sqlx::query_scalar(
        "SELECT id FROM content_events WHERE record_id=? AND type='record.created'",
    )
    .bind(&artifact)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let declaration = json!({"needs":[{"need":"records.body.read.v1","scope":"viewer-visible-current-bodies"}],"effects":[]});
    let digest = crate::mcp::tools::alpha_tabs::alpha_tab_digest(
        &crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(BODY),
        "b543054776df55c1cee9a703a50ea398e88ac3df40f322e437264ab6d450cae4",
        "native.html.v1",
    );
    let mut raw = json!({"action":"install","package":PACKAGE,"version":"1.0.0","digest":digest,"artifact_id":artifact,"source_revision":revision,"declaration":declaration,"reason":"Genuine private fixture","idempotency_key":"supervisor-install"});
    let barrier = crate::mcp::DeploymentMutationBarrier::default();
    let _lease = barrier
        .admit(
            &crate::DeploymentReadOnlyOperation::server("manage_alpha_tabs"),
            crate::mcp::OperationAccess::Mutation,
        )
        .unwrap();
    let request = producer::Request::parse(&serde_json::to_vec(&raw).unwrap()).unwrap();
    // SAFETY: Native qualification fixture owns selected bound account/Db and
    // operator-trusted host facts/admission. This is not an HTTP auth claim.
    let ingress =
        unsafe { producer::Ingress::from_verified_host(&db, &caller, &request, Instant::now()) }
            .unwrap();
    let installed = producer::install(&ingress).await.unwrap().original;
    raw["action"] = json!("preview");
    raw["expected_install_event_id"] = json!(installed.event_id.clone());
    raw.as_object_mut().unwrap().remove("idempotency_key");
    let delivery = crate::artifact_html::LaunchDelivery::isolated_fixture(
        crate::artifact_html::RuntimeConfig::new(ORIGIN, "https://artifact.test").unwrap(),
    );
    let (intent, root_nonce) = match consent {
        FixtureConsent::HumanReceipt => {
            let request = producer::Request::parse(&serde_json::to_vec(&raw).unwrap()).unwrap();
            let ingress = unsafe {
                producer::Ingress::from_verified_host(&db, &caller, &request, Instant::now())
            }
            .unwrap();
            let preview: Value = serde_json::from_slice(
                &producer::preview(&ingress, &delivery)
                    .await
                    .unwrap()
                    .expose()
                    .unwrap(),
            )
            .unwrap();
            raw["action"] = json!("adopt");
            raw["idempotency_key"] = json!("supervisor-adopt");
            for key in ["receipt_id", "nonce", "preview_session"] {
                raw[key] = preview["receipt"][key].clone();
            }
            let request = producer::Request::parse(&serde_json::to_vec(&raw).unwrap()).unwrap();
            let intent = request.adopt_intent().unwrap();
            (intent, request.nonce().map(str::to_owned))
        }
        FixtureConsent::TrustedAuthored => (
            adoption::Intent {
                package: PACKAGE.into(),
                version: raw["version"].as_str().unwrap().into(),
                digest: raw["digest"].as_str().unwrap().into(),
                artifact_id: raw["artifact_id"].as_str().unwrap().into(),
                source_revision: raw["source_revision"].as_str().unwrap().into(),
                declaration: raw["declaration"].clone(),
                expected_install_event_id: installed.event_id.clone(),
                reason: "Existing trusted embedding asserts authored adoption".into(),
                idempotency_key: Some("supervisor-authored".into()),
                consent: adoption::Consent::Authored {
                    launch_id: Some("fixture-authored-launch".into()),
                    authored_run_key: Some("fixture-authored-run".into()),
                },
            },
            None,
        ),
    };
    let ingress =
        unsafe { adoption::Ingress::from_verified_host(&db, &caller, &intent, Instant::now()) }
            .unwrap();
    let outcome = match adoption::begin(&ingress).await.unwrap() {
        adoption::Decision::Fresh(f) => f
            .prepare_current_pin()
            .unwrap()
            .qualify()
            .await
            .unwrap()
            .commit(root_nonce.as_deref())
            .await
            .unwrap(),
        adoption::Decision::Recovered(_) => panic!("fixture must genuinely adopt"),
    };
    assert_eq!(outcome.event_type, "alpha_tab.adopted.v2");
    drop(_lease);
    let target = crate::store::create_record_as(
        &db,
        json!({"type":"Document","kind":"note","name":"Supervisor target","home_id":crate::schema::ROOT_RECORD_ID,"body":"abcdefgh é😀"}),
        Some(account),
    )
    .await
    .unwrap();
    let mut key = [0; 32];
    let mut correlation = [0; 32];
    rand::rng().fill_bytes(&mut key);
    rand::rng().fill_bytes(&mut correlation);
    // Explicit isolated test owner; no global hook/replacement or production
    // safe constructor. Its same two slots/codec cover all fixture requests.
    let owner = Box::leak(Box::new(Process {
        slots: Arc::new(Semaphore::new(2)),
        jobs: Arc::new(sqlite::owned_jobs::Registry::default()),
        codec: Codec::process(),
        epoch: Instant::now(),
        cipher: XChaCha20Poly1305::new((&key).into()),
        correlation,
    }));
    Fixture {
        _directory: directory,
        db,
        caller,
        delivery,
        owner,
        barrier,
        target,
        root_intent: intent,
        root_nonce,
        root_event: outcome.event_id,
        root_audit: (
            outcome.original_run_key,
            outcome.original_act,
            outcome.original_request,
        ),
    }
}
fn work(f: &Fixture, request: OwnedRequest, probe: Option<Arc<BrokerProbe>>) -> Work {
    let started = Instant::now();
    let admission = f
        .barrier
        .admit(
            &crate::DeploymentReadOnlyOperation::server("records.body.read.v1"),
            crate::mcp::OperationAccess::Read,
        )
        .unwrap();
    Work {
        owner: f.owner,
        db: f.db.clone(),
        caller: f.caller.clone(),
        request,
        cookie: "fixture-cookie".into(),
        origin: ORIGIN.into(),
        started,
        admission,
        delivery: f.delivery.clone(),
        probe,
    }
}
async fn issue(f: &Fixture) -> String {
    match sqlite::execute_hosted(work(f, OwnedRequest::Issue(PACKAGE.into()), None)).await {
        Reply::Issued(bytes) => serde_json::from_slice::<Value>(bytes.as_bytes()).unwrap()
            ["mount_token"]
            .as_str()
            .unwrap()
            .to_owned(),
        Reply::Body(b) => panic!("issuance refused {}", String::from_utf8_lossy(b.as_bytes())),
        Reply::HostRefused(e) => panic!("issuance refused {e:?}"),
        _ => panic!("issuance type"),
    }
}
async fn redeemed(f: &Fixture) -> String {
    let reply = sqlite::execute_hosted(work(f, OwnedRequest::Issue(PACKAGE.into()), None)).await;
    let Reply::Issued(bytes) = reply else {
        panic!("expected genuine issued mount")
    };
    let issued: Value = serde_json::from_slice(bytes.as_bytes()).unwrap();
    let url = url::Url::parse(issued["launch"]["url"].as_str().unwrap()).unwrap();
    let response = f
        .delivery
        .router()
        .oneshot(
            HttpRequest::builder()
                .uri(url.path())
                .header(HOST, HeaderValue::from_static("artifact.test"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let html = axum::body::to_bytes(response.into_body(), 1048576)
        .await
        .unwrap();
    assert!(std::str::from_utf8(&html)
        .unwrap()
        .contains("Actual producer é😀"));
    issued["mount_token"].as_str().unwrap().to_owned()
}
async fn useful(f: &Fixture, tokens: &[String]) {
    for token in tokens {
        let request = serde_json::to_vec(&json!({"record_id":f.target,"page_bytes":4})).unwrap();
        let Reply::Body(bytes) =
            sqlite::execute_hosted(work(f, OwnedRequest::Page(token.clone(), request), None)).await
        else {
            panic!("old mount unavailable")
        };
        let page: Value = serde_json::from_slice(bytes.as_bytes()).unwrap();
        assert!(page.get("error").is_none());
        assert_eq!(page["text"], "abcd");
        assert!(page["body_digest"].as_str().unwrap().len() == 64);
    }
}
fn probe(phase: ProbePhase) -> (Arc<BrokerProbe>, std::sync::mpsc::Sender<()>) {
    let (send, wait) = std::sync::mpsc::channel();
    (
        Arc::new(BrokerProbe {
            phase,
            entered: Semaphore::new(0),
            release: tokio::sync::Notify::new(),
            html_wait: std::sync::Mutex::new(Some(wait)),
            acknowledged: AtomicBool::new(false),
            reserved: AtomicBool::new(false),
            cleaned: AtomicBool::new(false),
        }),
        send,
    )
}
async fn entered(p: &BrokerProbe) {
    tokio::time::timeout(Duration::from_secs(3), p.entered.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
}
async fn terminal(f: &Fixture, probes: &[Arc<BrokerProbe>]) {
    // Diagnostic observation only; never substitutes ACK or changes request time.
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if f.owner.slots.available_permits() == 2 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    for p in probes {
        assert!(p.acknowledged.load(Ordering::SeqCst));
    }
}
async fn third_is_busy(f: &Fixture) {
    let Reply::Body(b) =
        sqlite::execute_hosted(work(f, OwnedRequest::Issue(PACKAGE.into()), None)).await
    else {
        panic!("third job must refuse")
    };
    let value: Value = serde_json::from_slice(b.as_bytes()).unwrap();
    assert_eq!(
        value["error"],
        json!({"code":"resource_exhausted","reason":"process_busy"})
    );
}

struct Projection {
    pin: crate::control::AlphaTabStatePayload,
    event: String,
    status: String,
    provenance: Option<String>,
    pointer: Option<String>,
}
async fn projection_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    f: &Fixture,
) -> Projection {
    let row = sqlx::query("SELECT * FROM alpha_tab_installs WHERE account_id=? AND package=?")
        .bind(f.caller.credential())
        .bind(PACKAGE)
        .fetch_one(&mut **tx)
        .await
        .unwrap();
    Projection {
        pin: crate::control::AlphaTabStatePayload {
            account_id: row.try_get("account_id").unwrap(),
            package: row.try_get("package").unwrap(),
            version: row.try_get("version").unwrap(),
            digest: row.try_get("digest").unwrap(),
            artifact_id: row.try_get("artifact_id").unwrap(),
            consented_source_revision: row.try_get("consented_source_revision").unwrap(),
            declaration_digest: row.try_get("declaration_digest").unwrap(),
            consented_declaration: serde_json::from_str(
                &row.try_get::<String, _>("consented_declaration").unwrap(),
            )
            .unwrap(),
            adoption: row.try_get("adoption").unwrap(),
            request: row.try_get("request").unwrap(),
            previous_event_id: None,
        },
        event: row.try_get("event_id").unwrap(),
        status: row.try_get("status").unwrap(),
        provenance: row.try_get("adoption_provenance").unwrap(),
        pointer: row.try_get("body_read_admission_event_id").unwrap(),
    }
}
async fn projection(f: &Fixture) -> Projection {
    let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
    let result = projection_in(&mut tx, f).await;
    tx.rollback().await.unwrap();
    result
}
async fn counts(f: &Fixture) -> (i64, i64) {
    sqlx::query_as(
        "SELECT (SELECT count(*) FROM control_events),next_act FROM act_state WHERE singleton=1",
    )
    .fetch_one(f.db.pool())
    .await
    .unwrap()
}
async fn root_payload(f: &Fixture) -> String {
    sqlx::query_scalar(
        "SELECT payload FROM control_events WHERE id=? AND type='alpha_tab.adopted.v2'",
    )
    .bind(&f.root_event)
    .fetch_one(f.db.pool())
    .await
    .unwrap()
}
async fn shared_update_in(f: &Fixture, declaration: Value, key: &str) -> String {
    let _lease = f
        .barrier
        .admit(
            &crate::DeploymentReadOnlyOperation::server("manage_alpha_tabs"),
            crate::mcp::OperationAccess::Mutation,
        )
        .unwrap();
    let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
    let previous = projection_in(&mut tx, f).await;
    let dd = crate::alpha_tab_body_admission_v1::declaration_digest(&declaration).unwrap();
    // Equality is qualified ONLY for these selected descriptor/inert-name fixtures.
    assert_eq!(
        dd,
        crate::mcp::tools::alpha_tabs::alpha_tab_declaration_digest(&declaration).unwrap()
    );
    let digest = crate::alpha_tab_body_admission_v1::install_digest(
        &crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(BODY),
        &dd,
        "native.html.v1",
    );
    let mut update = crate::control::AlphaTabUpdatePayload {
        account_id: previous.pin.account_id.clone(),
        package: PACKAGE.into(),
        version: previous.pin.version.clone(),
        digest,
        artifact_id: previous.pin.artifact_id.clone(),
        consented_source_revision: previous.pin.consented_source_revision.clone(),
        declaration_digest: dd,
        consented_declaration: declaration,
        previous_event_id: previous.event,
        previous_pin_digest: String::new(),
        status: String::new(),
        request: previous.pin.request,
        command_digest: crate::canonical_json::digest_json(&json!({"fixture_update":key})),
        adoption: String::new(),
        adoption_basis: String::new(),
        adoption_provenance: None,
    };
    // No outcome/pointer is supplied: real completion and fold independently derive it.
    crate::control::complete_alpha_tab_update_in(&mut tx, &mut update)
        .await
        .unwrap();
    let mut act = crate::act::ActAllocation::new();
    let event = crate::control::append_control_event_in(
        &mut tx,
        crate::control::NewControlEvent::authored(
            key,
            crate::control::alpha_tab_aggregate_id(f.caller.credential(), PACKAGE),
            f.caller.actor(),
            None,
            "Privileged fixture tests shared completion, not public update admission",
            crate::control::ControlEventPayload::AlphaTabUpdated(Box::new(update)),
        )
        .unwrap(),
        &mut act,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    event.id
}
async fn current_preview(f: &Fixture, key: &str) -> (adoption::Intent, String) {
    let p = projection(f).await;
    let mut raw = json!({"action":"preview","package":PACKAGE,"version":p.pin.version,
        "digest":p.pin.digest,"artifact_id":p.pin.artifact_id,"source_revision":p.pin.consented_source_revision,
        "declaration":p.pin.consented_declaration,"expected_install_event_id":p.event,"reason":"Fresh operator-qualified human receipt"});
    let _lease = f
        .barrier
        .admit(
            &crate::DeploymentReadOnlyOperation::server("manage_alpha_tabs"),
            crate::mcp::OperationAccess::Mutation,
        )
        .unwrap();
    let request = producer::Request::parse(&serde_json::to_vec(&raw).unwrap()).unwrap();
    // SAFETY: same explicit native operator trust as fixture(); no browser consent claim.
    let ingress = unsafe {
        producer::Ingress::from_verified_host(&f.db, &f.caller, &request, Instant::now())
    }
    .unwrap();
    let packet: Value = serde_json::from_slice(
        &producer::preview(&ingress, &f.delivery)
            .await
            .unwrap()
            .expose()
            .unwrap(),
    )
    .unwrap();
    raw["action"] = json!("adopt");
    raw["idempotency_key"] = json!(key);
    for field in ["receipt_id", "nonce", "preview_session"] {
        raw[field] = packet["receipt"][field].clone();
    }
    let request = producer::Request::parse(&serde_json::to_vec(&raw).unwrap()).unwrap();
    (
        request.adopt_intent().unwrap(),
        request.nonce().unwrap().to_owned(),
    )
}
async fn fresh_consent(
    f: &Fixture,
    intent: &adoption::Intent,
    nonce: Option<&str>,
) -> adoption::Outcome {
    let _lease = f
        .barrier
        .admit(
            &crate::DeploymentReadOnlyOperation::server("manage_alpha_tabs"),
            crate::mcp::OperationAccess::Mutation,
        )
        .unwrap();
    // SAFETY: native fixture owns the selected account, action, handle and lease.
    let ingress =
        unsafe { adoption::Ingress::from_verified_host(&f.db, &f.caller, intent, Instant::now()) }
            .unwrap();
    let adoption::Decision::Fresh(fresh) = adoption::begin(&ingress).await.unwrap() else {
        panic!("new consent must be fresh");
    };
    fresh
        .prepare_current_pin()
        .unwrap()
        .qualify()
        .await
        .unwrap()
        .commit(nonce)
        .await
        .unwrap()
}
async fn page(f: &Fixture, token: &str, request: Value) -> Reply {
    sqlite::execute_hosted(work(
        f,
        OwnedRequest::Page(token.into(), serde_json::to_vec(&request).unwrap()),
        None,
    ))
    .await
}
fn body_failure(reply: Reply, code: &str) {
    let Reply::Body(bytes) = reply else {
        panic!("canonical source refusal required");
    };
    let v: Value = serde_json::from_slice(bytes.as_bytes()).unwrap();
    assert_eq!(
        v,
        json!({"contract":"records.body.read.v1","error":{"code":code,"reason":"source"}})
    );
}
async fn pending_refuses(f: &Fixture, old: &str) {
    let p = projection(f).await;
    assert_eq!(p.status, "installed");
    assert!(p.pointer.is_none());
    // Valid grammar and a canonical missing id: target diagnostics cannot mask source refusal.
    body_failure(
        page(
            f,
            old,
            json!({"record_id":"ba000000-0000-4000-8000-000000000001","page_bytes":4}),
        )
        .await,
        "adoption_required",
    );
    body_failure(
        sqlite::execute_hosted(work(f, OwnedRequest::Issue(PACKAGE.into()), None)).await,
        "adoption_required",
    );
}
async fn actual_page(f: &Fixture, token: &str) -> Value {
    let Reply::Body(bytes) = page(f, token, json!({"record_id":f.target,"page_bytes":4})).await
    else {
        panic!("useful page required");
    };
    let v: Value = serde_json::from_slice(bytes.as_bytes()).unwrap();
    assert_eq!(v["text"], "abcd");
    assert!(v.get("error").is_none());
    assert_eq!(
        v["body_digest"],
        crate::mcp::tools::lifecycle::body_digest(Some("abcdefgh é😀"))
    );
    assert!(v["revision"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(v["next_cursor"].as_str().is_some_and(|s| !s.is_empty()));
    v
}
async fn old_cursor_refuses(f: &Fixture, new: &str, first: &Value) {
    let Reply::Body(bytes) = page(
        f,
        new,
        json!({"record_id":f.target,"revision":first["revision"],"cursor":first["next_cursor"]}),
    )
    .await
    else {
        panic!("canonical cursor refusal required");
    };
    assert_eq!(
        serde_json::from_slice::<Value>(bytes.as_bytes()).unwrap(),
        json!({"contract":"records.body.read.v1","error":{"code":"invalid_cursor","reason":"cursor"}})
    );
}
async fn retire(f: &Fixture, token: &str) {
    assert!(matches!(
        sqlite::execute_hosted(work(f, OwnedRequest::Retire(token.into()), None)).await,
        Reply::Retired
    ));
}
async fn close_fixture(f: &Fixture, tokens: &[String]) {
    for token in tokens {
        retire(f, token).await;
    }
    assert!(f.db.fence_body_retirement().drain().await);
    f.db.close().await;
}
async fn assert_rebuilt(f: &Fixture) {
    assert!(
        Box::pin(crate::conformance::rebuild_and_diff_control(&f.db))
            .await
            .unwrap()
            .equal
    );
}
async fn assert_original_retry(f: &Fixture) {
    let before = counts(f).await;
    let current = projection(f).await;
    let _lease = f
        .barrier
        .admit(
            &crate::DeploymentReadOnlyOperation::server("manage_alpha_tabs"),
            crate::mcp::OperationAccess::Mutation,
        )
        .unwrap();
    let ingress = unsafe {
        adoption::Ingress::from_verified_host(&f.db, &f.caller, &f.root_intent, Instant::now())
    }
    .unwrap();
    let adoption::Decision::Recovered(out) = adoption::begin(&ingress).await.unwrap() else {
        panic!("original outcome must recover before fresh work");
    };
    assert_eq!(out.event_id, f.root_event);
    assert_eq!(out.event_type, "alpha_tab.adopted.v2");
    assert_eq!(
        (out.original_run_key, out.original_act, out.original_request),
        f.root_audit
    );
    assert_eq!(counts(f).await, before);
    let after = projection(f).await;
    assert_eq!(after.event, current.event);
    assert_eq!(after.pointer, current.pointer);
    // Original immutable intent still includes the original receipt association;
    // no new nonce/reset is consulted during recovery.
    if let adoption::Consent::Receipt { receipt_id, .. } = &f.root_intent.consent {
        assert!(f.root_nonce.is_some());
        assert!(
            crate::mcp::tools::alpha_tabs::find_alpha_tab_preview_receipt(receipt_id)
                .unwrap()
                .1
        );
    }
}
async fn stale_receipt_refuses(f: &Fixture, mut intent: adoption::Intent, nonce: &str) {
    let before = counts(f).await;
    let p = projection(f).await;
    intent.expected_install_event_id = p.event.clone();
    let adoption::Consent::Receipt { receipt_id, .. } = &intent.consent else {
        panic!("actual receipt required");
    };
    let receipt_id = receipt_id.clone();
    let _lease = f
        .barrier
        .admit(
            &crate::DeploymentReadOnlyOperation::server("manage_alpha_tabs"),
            crate::mcp::OperationAccess::Mutation,
        )
        .unwrap();
    let ingress =
        unsafe { adoption::Ingress::from_verified_host(&f.db, &f.caller, &intent, Instant::now()) }
            .unwrap();
    let adoption::Decision::Fresh(fresh) = adoption::begin(&ingress).await.unwrap() else {
        panic!("unconsumed preview has no outcome");
    };
    let ready = fresh
        .prepare_current_pin()
        .unwrap()
        .qualify()
        .await
        .unwrap();
    assert!(ready.commit(Some(nonce)).await.is_err());
    assert!(
        !crate::mcp::tools::alpha_tabs::find_alpha_tab_preview_receipt(&receipt_id)
            .unwrap()
            .1
    );
    assert_eq!(counts(f).await, before);
    let after = projection(f).await;
    assert_eq!(after.event, p.event);
    assert_eq!(after.pointer, p.pointer);
}
async fn carry_case(consent: FixtureConsent) {
    let authored = matches!(consent, FixtureConsent::TrustedAuthored);
    let f = fixture_with_consent(consent).await;
    let immutable = root_payload(&f).await;
    let original = projection(&f).await;
    let root: crate::control::AlphaTabAdoptionProvenance =
        serde_json::from_str(original.provenance.as_ref().unwrap()).unwrap();
    let old = redeemed(&f).await;
    let first = actual_page(&f, &old).await;
    let (stale, nonce) = current_preview(&f, "union-stale").await;
    let before = counts(&f).await;
    let updated = shared_update_in(
        &f,
        original.pin.consented_declaration.clone(),
        "union-carry",
    )
    .await;
    assert_eq!(counts(&f).await, (before.0 + 1, before.1 + 1));
    let carried = projection(&f).await;
    assert_eq!(carried.status, "installed");
    let proof: crate::control::AlphaTabAdoptionProvenance =
        serde_json::from_str(carried.provenance.as_ref().unwrap()).unwrap();
    let mut expected = root.clone();
    expected.carried_from_event_id = Some(f.root_event.clone());
    assert_eq!(proof, expected);
    assert_eq!(proof.original_adoption_event_id, f.root_event);
    assert_eq!(
        proof.original_source_revision,
        original.pin.consented_source_revision
    );
    assert_eq!(proof.original_bundle_digest, original.pin.digest);
    assert_eq!(
        proof.adopted_declaration_digest,
        original.pin.declaration_digest
    );
    assert_eq!(
        proof.original_adoption_method,
        if authored {
            "shell_auto.v1"
        } else {
            "shell_adopt.v1"
        }
    );
    if authored {
        assert!(proof.reviewed_source_revision.is_none() && proof.reviewed_bundle_digest.is_none());
        assert_eq!(proof.launch_id.as_deref(), Some("fixture-authored-launch"));
        assert_eq!(
            proof.authored_run_key.as_deref(),
            Some("fixture-authored-run")
        );
    } else {
        assert_eq!(
            proof.reviewed_source_revision.as_deref(),
            Some(proof.original_source_revision.as_str())
        );
        assert_eq!(
            proof.reviewed_bundle_digest.as_deref(),
            Some(proof.original_bundle_digest.as_str())
        );
        assert!(proof.launch_id.is_none() && proof.authored_run_key.is_none());
    }
    assert_eq!(carried.pin.adoption, proof.original_adoption_method);
    assert_eq!(carried.event, updated);
    assert_eq!(root_payload(&f).await, immutable);
    pending_refuses(&f, &old).await;
    stale_receipt_refuses(&f, stale, &nonce).await;
    assert_original_retry(&f).await;
    assert_rebuilt(&f).await;
    let before_fresh = counts(&f).await;
    let outcome = if authored {
        let p = projection(&f).await;
        let intent = adoption::Intent {
            package: PACKAGE.into(),
            version: p.pin.version,
            digest: p.pin.digest,
            artifact_id: p.pin.artifact_id,
            source_revision: p.pin.consented_source_revision,
            declaration: p.pin.consented_declaration,
            expected_install_event_id: p.event,
            reason: "Genuinely fresh trusted embedding assertion".into(),
            idempotency_key: Some("union-new-authored".into()),
            consent: adoption::Consent::Authored {
                launch_id: Some("fresh-launch".into()),
                authored_run_key: None,
            },
        };
        fresh_consent(&f, &intent, None).await
    } else {
        let (intent, nonce) = current_preview(&f, "union-new-human").await;
        fresh_consent(&f, &intent, Some(&nonce)).await
    };
    assert_eq!(counts(&f).await, (before_fresh.0 + 1, before_fresh.1 + 1));
    assert_ne!(outcome.event_id, f.root_event);
    let renewed = projection(&f).await;
    assert_eq!(renewed.pointer.as_deref(), Some(outcome.event_id.as_str()));
    let renewed_proof: crate::control::AlphaTabAdoptionProvenance =
        serde_json::from_str(renewed.provenance.as_ref().unwrap()).unwrap();
    assert_eq!(renewed_proof.original_adoption_event_id, outcome.event_id);
    assert_eq!(
        renewed_proof.original_source_revision,
        renewed.pin.consented_source_revision
    );
    assert_eq!(renewed_proof.original_bundle_digest, renewed.pin.digest);
    assert_eq!(
        renewed_proof.adopted_declaration_digest,
        renewed.pin.declaration_digest
    );
    assert!(renewed_proof.carried_from_event_id.is_none());
    assert_eq!(
        renewed_proof.original_adoption_method,
        if authored {
            "shell_auto.v1"
        } else {
            "shell_adopt.v1"
        }
    );
    if authored {
        assert!(
            renewed_proof.reviewed_source_revision.is_none()
                && renewed_proof.reviewed_bundle_digest.is_none()
        );
        assert_eq!(renewed_proof.launch_id.as_deref(), Some("fresh-launch"));
        assert!(renewed_proof.authored_run_key.is_none());
    }
    assert!(matches!(
        page(&f, &old, json!({"record_id":f.target})).await,
        Reply::HostRefused(HostRefusal::MountUnavailable)
    ));
    let new = redeemed(&f).await;
    let current = actual_page(&f, &new).await;
    assert_eq!(current["body_digest"], first["body_digest"]);
    assert_ne!(current["revision"], first["revision"]);
    old_cursor_refuses(&f, &new, &first).await;
    assert_eq!(root_payload(&f).await, immutable);
    assert_rebuilt(&f).await;
    close_fixture(&f, &[old, new]).await;
}
#[tokio::test]
async fn union_human_v2_shared_update_revokes_mount_and_preserves_reviewed_root() {
    Box::pin(carry_case(FixtureConsent::HumanReceipt)).await;
}
#[tokio::test]
async fn union_trusted_authored_v2_shared_update_revokes_mount_without_human_review() {
    Box::pin(carry_case(FixtureConsent::TrustedAuthored)).await;
}
async fn transition(f: &Fixture, restored: bool) {
    let _lease = f
        .barrier
        .admit(
            &crate::DeploymentReadOnlyOperation::server("manage_alpha_tabs"),
            crate::mcp::OperationAccess::Mutation,
        )
        .unwrap();
    let mut p = projection(f).await;
    p.pin.previous_event_id = Some(p.event);
    p.pin.adoption = "caller_asserted".into();
    let payload = if restored {
        crate::control::ControlEventPayload::AlphaTabRestored(p.pin)
    } else {
        crate::control::ControlEventPayload::AlphaTabDisabled(p.pin)
    };
    crate::control::append_control_event(
        &f.db,
        crate::control::NewControlEvent::authored(
            if restored {
                "union-restore"
            } else {
                "union-disable"
            },
            crate::control::alpha_tab_aggregate_id(f.caller.credential(), PACKAGE),
            f.caller.actor(),
            None,
            "Actual validated transition",
            payload,
        )
        .unwrap(),
    )
    .await
    .unwrap();
}
#[tokio::test]
async fn union_human_receipt_renewal_after_changed_declaration_restore_and_foreign_import() {
    Box::pin(async {
        for boundary in 0..3 {
            let mut f = fixture().await;
            let immutable = root_payload(&f).await;
            let old = redeemed(&f).await;
            let first = actual_page(&f, &old).await;
            let (stale, nonce) = current_preview(&f, "union-boundary-stale").await;
            if boundary == 0 {
                let original = projection(&f).await.pin.consented_declaration;
                let mut changed = original.clone();
                changed["needs"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!("inert.union-boundary"));
                for (key, declaration) in [
                    ("union-changed", changed.clone()),
                    ("union-pending-same", changed),
                    ("union-pending-return", original),
                ] {
                    shared_update_in(&f, declaration, key).await;
                    let p = projection(&f).await;
                    assert_eq!(p.pin.adoption, "caller_asserted");
                    assert!(p.provenance.is_none() && p.pointer.is_none());
                    pending_refuses(&f, &old).await;
                }
            } else if boundary == 1 {
                transition(&f, false).await;
                body_failure(
                    page(&f, &old, json!({"record_id":f.target})).await,
                    "source_integrity",
                );
                body_failure(
                    sqlite::execute_hosted(work(&f, OwnedRequest::Issue(PACKAGE.into()), None))
                        .await,
                    "source_integrity",
                );
                transition(&f, true).await;
                let p = projection(&f).await;
                assert_eq!(p.pin.adoption, "caller_asserted");
                assert!(p.provenance.is_none() && p.pointer.is_none());
                pending_refuses(&f, &old).await;
            } else {
                let bytes = crate::interchange::export_canonical_interchange(&f.db)
                    .await
                    .unwrap();
                // Retire while the OLD handle remains live; then wait actual retained drain.
                retire(&f, &old).await;
                assert!(f.db.fence_body_retirement().drain().await);
                f.db.close().await;
                let destination = f._directory.path().join("foreign.db");
                let imported = Box::pin(crate::interchange::import_canonical_interchange(
                    &bytes,
                    &destination,
                    crate::interchange::ImportContinuity::ForeignBoundary,
                ))
                .await
                .unwrap();
                f.db = imported; // All subsequent work/ingress is recaptured from NEW selected Db.
                let p = projection(&f).await;
                let kind: String = sqlx::query_scalar("SELECT type FROM control_events WHERE id=?")
                    .bind(&p.event)
                    .fetch_one(f.db.pool())
                    .await
                    .unwrap();
                assert_eq!(kind, "alpha_tab.import_reset");
                assert_eq!(p.pin.adoption, "caller_asserted");
                assert!(p.provenance.is_none() && p.pointer.is_none());
                body_failure(
                    sqlite::execute_hosted(work(&f, OwnedRequest::Issue(PACKAGE.into()), None))
                        .await,
                    "adoption_required",
                );
                // Already retired correlation fails BEFORE SQL source resolution, not as a body grant.
                assert!(matches!(
                    page(&f, &old, json!({"record_id":f.target})).await,
                    Reply::HostRefused(HostRefusal::MountUnavailable)
                ));
            }
            stale_receipt_refuses(&f, stale, &nonce).await;
            assert_original_retry(&f).await;
            let (intent, nonce) = current_preview(&f, "union-boundary-fresh").await;
            let before_fresh = counts(&f).await;
            let outcome = fresh_consent(&f, &intent, Some(&nonce)).await;
            assert_eq!(counts(&f).await, (before_fresh.0 + 1, before_fresh.1 + 1));
            assert_ne!(outcome.event_id, f.root_event);
            let p = projection(&f).await;
            assert_eq!(p.pointer.as_deref(), Some(outcome.event_id.as_str()));
            let root: crate::control::AlphaTabAdoptionProvenance =
                serde_json::from_str(p.provenance.as_ref().unwrap()).unwrap();
            assert_eq!(root.original_adoption_event_id, outcome.event_id);
            assert_eq!(root.original_adoption_method, "shell_adopt.v1");
            assert_eq!(
                root.original_source_revision,
                p.pin.consented_source_revision
            );
            assert_eq!(root.original_bundle_digest, p.pin.digest);
            assert_eq!(root.adopted_declaration_digest, p.pin.declaration_digest);
            assert_eq!(
                root.reviewed_source_revision.as_deref(),
                Some(root.original_source_revision.as_str())
            );
            assert_eq!(
                root.reviewed_bundle_digest.as_deref(),
                Some(root.original_bundle_digest.as_str())
            );
            assert!(root.carried_from_event_id.is_none());
            assert!(root.launch_id.is_none() && root.authored_run_key.is_none());
            let new = redeemed(&f).await;
            let current = actual_page(&f, &new).await;
            assert_eq!(current["body_digest"], first["body_digest"]);
            assert_ne!(current["revision"], first["revision"]);
            old_cursor_refuses(&f, &new, &first).await;
            assert!(matches!(
                page(&f, &old, json!({"record_id":f.target})).await,
                Reply::HostRefused(HostRefusal::MountUnavailable)
            ));
            assert_eq!(root_payload(&f).await, immutable);
            assert_rebuilt(&f).await;
            let tokens = if boundary == 2 {
                vec![new]
            } else {
                vec![old, new]
            };
            close_fixture(&f, &tokens).await;
        }
    })
    .await;
}
#[tokio::test]
async fn registration_observation_survives_policy_pending_and_completed_job() {
    Box::pin(async {
        let f = fixture().await;
        let token = redeemed(&f).await;
        let gate = f.db.owned_portability_policy_gate().write_owned().await;
        let registered = f.owner.observe_registration_for_qualification(&f.db);
        let raw = serde_json::to_vec(&json!({"record_id": f.target, "page_bytes": 4})).unwrap();
        let mut caller = Box::pin(sqlite::execute_hosted(work(
            &f,
            OwnedRequest::Page(token, raw),
            None,
        )));
        assert!(caller.as_mut().now_or_never().is_none());
        assert!(f.owner.observe_jobs_for_qualification().is_empty());
        drop(gate);
        let Reply::Body(bytes) = caller.await else {
            panic!("genuine body page refused")
        };
        let page: Value = serde_json::from_slice(bytes.as_bytes()).unwrap();
        assert!(page.get("error").is_none());
        assert_eq!(page["text"], "abcd");
        assert!(f.owner.observe_jobs_for_qualification().is_empty());
        // Registration survives registry pruning and carries this exact job's
        // actual terminal ACK, even though the reply was already delivered.
        let observed = registered.registered().await.unwrap();
        assert_eq!(observed.len(), 1);
        assert!(
            tokio::time::timeout(Duration::from_secs(3), observed.wait())
                .await
                .unwrap()
        );
        assert_eq!(f.owner.slots.available_permits(), 2);
        f.db.close().await;
    })
    .await;
}

#[tokio::test]
async fn returned_raw_cpu_drop_and_original_timeout_hold_slots_until_close_ack() {
    Box::pin(async {
        let f = fixture().await;
        let old = vec![redeemed(&f).await, redeemed(&f).await];
        // These actual CPU workers start AFTER raw connect returned. This
        // deliberately makes no pre-return SQLx startup cancellation claim.
        let (a, release_a) = probe(ProbePhase::RawCpu);
        let (b, release_b) = probe(ProbePhase::RawCpu);
        let wa = work(&f, OwnedRequest::Issue(PACKAGE.into()), Some(a.clone()));
        let wb = work(&f, OwnedRequest::Issue(PACKAGE.into()), Some(b.clone()));
        let start = wb.started;
        let first = tokio::spawn(sqlite::execute_hosted(wa));
        entered(&a).await;
        let second = tokio::spawn(sqlite::execute_hosted(wb));
        entered(&b).await;
        first.abort();
        assert!(matches!(first.await, Err(e) if e.is_cancelled()));
        assert!(matches!(
            second.await.unwrap(),
            Reply::HostRefused(HostRefusal::Deadline)
        ));
        assert!(start.elapsed() >= Duration::from_secs(5));
        assert_eq!(f.owner.slots.available_permits(), 0);
        assert!(!a.acknowledged.load(Ordering::SeqCst) && !b.acknowledged.load(Ordering::SeqCst));
        third_is_busy(&f).await;
        let observed = f.owner.observe_jobs_for_qualification();
        assert_eq!(observed.len(), 2);
        let mut observed = Box::pin(observed.wait());
        assert!(observed.as_mut().now_or_never().is_none());
        assert_eq!(f.owner.slots.available_permits(), 0);
        release_a.send(()).unwrap();
        release_b.send(()).unwrap();
        assert!(tokio::time::timeout(Duration::from_secs(3), observed)
            .await
            .unwrap());
        terminal(&f, &[a.clone(), b.clone()]).await;
        assert!(!a.reserved.load(Ordering::SeqCst) && !b.reserved.load(Ordering::SeqCst));
        useful(&f, &old).await;
        f.db.close().await;
    })
    .await
}
#[tokio::test]
async fn registered_html_cpu_drop_and_timeout_keep_real_workers_and_both_old_mounts() {
    Box::pin(async {
        let f = fixture().await;
        let old = vec![redeemed(&f).await, redeemed(&f).await];
        let (a, send_a) = probe(ProbePhase::Html);
        let (b, send_b) = probe(ProbePhase::Html);
        let first = tokio::spawn(sqlite::execute_hosted(work(
            &f,
            OwnedRequest::Issue(PACKAGE.into()),
            Some(a.clone()),
        )));
        entered(&a).await;
        let second = tokio::spawn(sqlite::execute_hosted(work(
            &f,
            OwnedRequest::Issue(PACKAGE.into()),
            Some(b.clone()),
        )));
        entered(&b).await;
        first.abort();
        assert!(matches!(first.await, Err(e) if e.is_cancelled()));
        assert!(matches!(
            second.await.unwrap(),
            Reply::HostRefused(HostRefusal::Deadline)
        ));
        assert_eq!(f.owner.slots.available_permits(), 0);
        assert!(!a.acknowledged.load(Ordering::SeqCst) && !b.acknowledged.load(Ordering::SeqCst));
        third_is_busy(&f).await;
        send_a.send(()).unwrap();
        send_b.send(()).unwrap();
        terminal(&f, &[a.clone(), b.clone()]).await;
        assert!(!a.reserved.load(Ordering::SeqCst) && !b.reserved.load(Ordering::SeqCst));
        useful(&f, &old).await;
        f.db.close().await;
    })
    .await
}
#[tokio::test]
async fn reserved_publication_drop_and_timeout_clean_only_new_pairs_after_physical_ack() {
    Box::pin(async {
        let f = fixture().await;
        let old = vec![redeemed(&f).await, redeemed(&f).await];
        let (a, _) = probe(ProbePhase::BeforeAck);
        let (b, _) = probe(ProbePhase::BeforeAck);
        let first = tokio::spawn(sqlite::execute_hosted(work(
            &f,
            OwnedRequest::Issue(PACKAGE.into()),
            Some(a.clone()),
        )));
        entered(&a).await;
        let second = tokio::spawn(sqlite::execute_hosted(work(
            &f,
            OwnedRequest::Issue(PACKAGE.into()),
            Some(b.clone()),
        )));
        entered(&b).await;
        assert!(a.reserved.load(Ordering::SeqCst) && b.reserved.load(Ordering::SeqCst));
        first.abort();
        assert!(matches!(first.await, Err(e) if e.is_cancelled()));
        assert!(matches!(
            second.await.unwrap(),
            Reply::HostRefused(HostRefusal::Deadline)
        ));
        assert_eq!(f.owner.slots.available_permits(), 0);
        assert!(!a.acknowledged.load(Ordering::SeqCst) && !b.acknowledged.load(Ordering::SeqCst));
        third_is_busy(&f).await;
        a.release.notify_one();
        b.release.notify_one();
        terminal(&f, &[a.clone(), b.clone()]).await;
        assert!(a.cleaned.load(Ordering::SeqCst) && b.cleaned.load(Ordering::SeqCst));
        useful(&f, &old).await;
        // Both old records plus thirty new reservations fill the exact principal
        // cap. Any leaked tentative failed pair would refuse earlier. Finish
        // before original30s cleanup, so expiry cannot mask a reclamation bug.
        let now = Instant::now();
        for _ in 0..30 {
            let _ = issue(&f).await;
        }
        assert!(now.elapsed() < Duration::from_secs(20));
        let Reply::HostRefused(HostRefusal::Busy) =
            sqlite::execute_hosted(work(&f, OwnedRequest::Issue(PACKAGE.into()), None)).await
        else {
            panic!("principal cap must be full")
        };
        useful(&f, &old).await;
        f.db.close().await;
    })
    .await
}
