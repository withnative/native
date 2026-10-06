use super::*;
use crate::control::{append_control_event, AlphaTabStatePayload};

const BODY: &str = "<!doctype html><html><body>Private qualification</body></html>";
const PREVIEW_BODY: &str = "\u{feff}<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Private qualification</title></head><body>Private qualification</body></html>";
const ARTIFACT: &str = "a0100000-0000-4000-8000-000000000001";
fn declaration() -> Value {
    json!({"needs":[{"need":BODY_READ_NEED,"scope":"viewer-visible-current-bodies"}],"effects":[]})
}
async fn fixture(declaration: Value, consent: Consent) -> (Db, Caller, Intent) {
    fixture_source(declaration, consent, BODY, None).await
}
// Operator-trusted retained-history fixture only. Inject a distinct event before
// installing its exact pin; never rewrite an immutable event or weaken triggers.
async fn fixture_source(
    declaration: Value,
    consent: Consent,
    body: &str,
    payload: Option<(Option<Vec<u8>>, bool, &str, &str)>,
) -> (Db, Caller, Intent) {
    let db = crate::create_database(":memory:").await.unwrap();
    let caller = Caller::local();
    crate::store::create_record(&db,json!({"id":ARTIFACT,"type":"Document","kind":"artifact","name":"Private Unit A","body":body})).await.unwrap();
    // The low-level record writer does not apply the tool's facets envelope.
    crate::store::set_facet(
        &db,
        ARTIFACT,
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
    let mut source_revision:String=sqlx::query_scalar("SELECT id FROM content_events WHERE record_id=? AND json_type(payload,'$.body')='text' ORDER BY seq DESC LIMIT 1")
        .bind(ARTIFACT).fetch_one(db.pool()).await.unwrap();
    if let Some((bytes, blob, kind, record_id)) = payload {
        source_revision = Uuid::new_v4().to_string();
        // Isolated corruption fixture: the metadata insert trigger examines JSON
        // itself. Remove it in this private in-memory database only to retain
        // malformed storage; append-only history triggers remain intact.
        if !blob
            && bytes
                .as_ref()
                .is_some_and(|v| serde_json::from_slice::<Value>(v).is_err())
        {
            sqlx::query("DROP TRIGGER content_event_claim_meta_insert")
                .execute(db.write_pool())
                .await
                .unwrap();
        }
        let query = sqlx::query("INSERT INTO content_events(id,record_id,type,payload,causal_envelope_version,causal_status) VALUES(?,?,?,?,1,'legacy_unknown')")
            .bind(&source_revision).bind(record_id).bind(kind);
        if blob {
            query.bind(bytes).execute(db.write_pool()).await.unwrap();
        } else {
            query
                .bind(bytes.map(|v| String::from_utf8(v).unwrap()))
                .execute(db.write_pool())
                .await
                .unwrap();
        }
    }
    let dd = crate::alpha_tab_body_admission_v1::declaration_digest(&declaration).unwrap();
    let digest = crate::alpha_tab_body_admission_v1::install_digest(
        &alpha_tab_bundle_digest(body),
        &dd,
        "native.html.v1",
    );
    // Explicit operator-trusted historical install fixture; not public preparation.
    let installed = append_control_event(
        &db,
        NewControlEvent::authored(
            "private-install",
            alpha_tab_aggregate_id(caller.credential(), "fixture.unit-a"),
            caller.actor(),
            None,
            "Private install fixture",
            ControlEventPayload::AlphaTabInstalled(AlphaTabStatePayload {
                account_id: caller.credential().into(),
                package: "fixture.unit-a".into(),
                version: "1.0.0".into(),
                digest: digest.clone(),
                artifact_id: ARTIFACT.into(),
                consented_source_revision: source_revision.clone(),
                declaration_digest: dd,
                consented_declaration: declaration.clone(),
                adoption: "caller_asserted".into(),
                request: Some("Original authored request".into()),
                previous_event_id: None,
            }),
        )
        .unwrap(),
    )
    .await
    .unwrap();
    let intent = Intent {
        package: "fixture.unit-a".into(),
        version: "1.0.0".into(),
        digest,
        artifact_id: ARTIFACT.into(),
        source_revision,
        declaration,
        expected_install_event_id: installed.id,
        reason: "Private adoption fixture".into(),
        idempotency_key: Some("private-adopt".into()),
        consent,
    };
    (db, caller, intent)
}
fn authored() -> Consent {
    Consent::Authored {
        launch_id: Some("launch-original".into()),
        authored_run_key: Some("author-original".into()),
    }
}
// Only fixtures' explicit unsafe ingress supplies hosted trust. No Caller pin
// is installed before begin, and preparation cannot precede outcome absence.
async fn qualify_fresh<'request>(fresh: Fresh<'request>) -> Result<Ready<'request>> {
    fresh.prepare_current_pin()?.qualify().await
}
async fn seed_outcome(db: &Db, caller: &Caller, i: &Intent, v2: bool) -> String {
    let (adoption, receipt_id, preview_session, launch_id, authored_run_key, request) =
        match &i.consent {
            Consent::Authored {
                launch_id,
                authored_run_key,
            } => (
                ALPHA_TAB_ADOPTION_SHELL_AUTO,
                None,
                None,
                launch_id.clone(),
                authored_run_key.clone(),
                Some("Original authored request".into()),
            ),
            Consent::Receipt {
                receipt_id,
                preview_session,
            } => (
                ALPHA_TAB_ADOPTION_VERIFIED,
                Some(receipt_id.clone()),
                Some(preview_session.clone()),
                None,
                None,
                None,
            ),
        };
    let dd = crate::alpha_tab_body_admission_v1::declaration_digest(&i.declaration).unwrap();
    let common = AlphaTabAdoptPayload {
        account_id: caller.credential().into(),
        package: i.package.clone(),
        version: i.version.clone(),
        digest: i.digest.clone(),
        artifact_id: i.artifact_id.clone(),
        consented_source_revision: i.source_revision.clone(),
        declaration_digest: dd.clone(),
        consented_declaration: i.declaration.clone(),
        adoption: adoption.into(),
        previous_event_id: i.expected_install_event_id.clone(),
        receipt_id,
        preview_session,
        launch_id,
        authored_run_key,
        request,
    };
    let payload = if v2 {
        ControlEventPayload::AlphaTabAdoptedV2(AlphaTabAdoptV2Payload {
            account_id: common.account_id,
            package: common.package,
            version: common.version,
            digest: common.digest,
            artifact_id: common.artifact_id,
            consented_source_revision: common.consented_source_revision,
            declaration_digest: common.declaration_digest,
            consented_declaration: common.consented_declaration,
            adoption: common.adoption,
            previous_event_id: common.previous_event_id,
            receipt_id: common.receipt_id,
            preview_session: common.preview_session,
            launch_id: common.launch_id,
            authored_run_key: common.authored_run_key,
            request: common.request,
            runtime: "native.html.v1".into(),
            bundle_sha256: alpha_tab_bundle_digest(BODY),
            body_read_admission: descriptor(),
        })
    } else {
        ControlEventPayload::AlphaTabAdopted(common)
    };
    append_control_event(
        db,
        NewControlEvent::authored(
            "private-adopt",
            alpha_tab_aggregate_id(caller.credential(), &i.package),
            caller.actor(),
            Some("original-audit".into()),
            &i.reason,
            payload,
        )
        .unwrap(),
    )
    .await
    .unwrap()
    .id
}

#[tokio::test]
async fn original_v1_and_v2_recovery_never_prepare_project_or_rebuild_current_state() {
    for v2 in [false, true] {
        let mut d = declaration();
        // Structurally frozen, currently inadmissible SQL: no fresh safety replay.
        d["needs"].as_array_mut().unwrap().push(json!({"need":"sql.snapshot.v1","key":"old.query","label":"Old","sql":"DELETE FROM records"}));
        let (db, caller, i) = fixture(d, authored()).await;
        let id = seed_outcome(&db, &caller, &i, v2).await;
        sqlx::query("DELETE FROM alpha_tab_installs")
            .execute(db.write_pool())
            .await
            .unwrap();
        sqlx::query("CREATE TRIGGER refuse_retry_append BEFORE INSERT ON control_events BEGIN SELECT RAISE(ABORT,'retry append'); END").execute(db.write_pool()).await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM control_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        // Qualification caller intentionally has no legacy pin authority. That
        // preparation cannot run before recovery; unsafe ingress is the fixture's
        // explicit trusted-host boundary, never constructed from the old event.
        let ingress =
            unsafe { Ingress::from_verified_host(&db, &caller, &i, Instant::now()) }.unwrap();
        let Decision::Recovered(old) = begin(&ingress).await.unwrap() else {
            panic!("old outcome not recovered")
        };
        assert_eq!(old.event_id, id);
        assert_eq!(
            old.event_type,
            if v2 {
                "alpha_tab.adopted.v2"
            } else {
                "alpha_tab.adopted"
            }
        );
        assert_eq!(
            old.original_request.as_deref(),
            Some("Original authored request")
        );
        assert_eq!(old.original_run_key.as_deref(), Some("original-audit"));
        assert_eq!(
            count,
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM control_events")
                .fetch_one(db.pool())
                .await
                .unwrap()
        );
        assert_eq!(
            0,
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM alpha_tab_installs")
                .fetch_one(db.pool())
                .await
                .unwrap()
        );
    }
}

#[tokio::test]
async fn durable_intent_changes_conflict_without_v1_promotion() {
    let (db, caller, mut i) = fixture(declaration(), authored()).await;
    let id = seed_outcome(&db, &caller, &i, false).await;
    i.reason.push_str(" changed");
    {
        let g = unsafe { Ingress::from_verified_host(&db, &caller, &i, Instant::now()) }.unwrap();
        assert!(begin(&g).await.is_err());
    }
    i.reason = "Private adoption fixture".into();
    i.declaration["sessions"] = json!([]);
    {
        let g = unsafe { Ingress::from_verified_host(&db, &caller, &i, Instant::now()) }.unwrap();
        assert!(begin(&g).await.is_err());
    }
    i.declaration.as_object_mut().unwrap().remove("sessions");
    let g = unsafe { Ingress::from_verified_host(&db, &caller, &i, Instant::now()) }.unwrap();
    let Decision::Recovered(old) = begin(&g).await.unwrap() else {
        panic!()
    };
    assert_eq!(old.event_id, id);
    assert_eq!(old.event_type, "alpha_tab.adopted");
}

#[tokio::test]
async fn fresh_full_sql_safety_and_public_descriptor_refusal_remain_closed() {
    let mut d = declaration();
    d["needs"].as_array_mut().unwrap().push(
        json!({"need":"sql.snapshot.v1","key":"bad.sql","label":"Bad","sql":"DELETE FROM records"}),
    );
    assert!(crate::alpha_tab_body_admission_v1::declaration_digest(&d).is_ok());
    assert!(require_declaration_for_adoption(&d, true).is_err());
    assert!(require_declaration(&declaration())
        .unwrap_err()
        .to_string()
        .contains("body_admission_unavailable"));
    let (db, caller, i) = fixture(d, authored()).await;
    let g = unsafe { Ingress::from_verified_host(&db, &caller, &i, Instant::now()) }.unwrap();
    let Decision::Fresh(fresh) = begin(&g).await.unwrap() else {
        panic!()
    };
    // Currently inadmissible SQL must fail preparation even though its
    // historical commitment is structurally legal and ingress is trusted.
    assert!(fresh.prepare_current_pin().is_err());
}

#[tokio::test]
async fn private_fresh_authored_adoption_recovers_original_after_remove() {
    let (db, caller, i) = fixture(declaration(), authored()).await;
    let g = unsafe { Ingress::from_verified_host(&db, &caller, &i, Instant::now()) }.unwrap();
    let Decision::Fresh(fresh) = begin(&g).await.unwrap() else {
        panic!()
    };
    let old = qualify_fresh(fresh)
        .await
        .unwrap()
        .commit(None)
        .await
        .unwrap();
    assert_eq!(old.event_type, "alpha_tab.adopted.v2");
    let pointer: String =
        sqlx::query_scalar("SELECT body_read_admission_event_id FROM alpha_tab_installs")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(old.event_id, pointer);
    sqlx::query("DELETE FROM alpha_tab_installs")
        .execute(db.write_pool())
        .await
        .unwrap();
    let Decision::Recovered(recovered) = begin(&g).await.unwrap() else {
        panic!()
    };
    assert_eq!(old.event_id, recovered.event_id);
    assert_eq!(
        recovered.original_request.as_deref(),
        Some("Original authored request")
    );
}

async fn checked_preview_receipt(db: &Db, caller: &Caller, i: &Intent) -> AlphaTabPreviewReceipt {
    let raw = serde_json::to_vec(
        &json!({"action":"preview","package":i.package,"version":i.version,
        "digest":i.digest,"artifact_id":i.artifact_id,"source_revision":i.source_revision,
        "declaration":i.declaration,"expected_install_event_id":i.expected_install_event_id,
        "reason":"Checked private preview"}),
    )
    .unwrap();
    let request = super::super::hosted_producer::Request::parse(&raw).unwrap();
    let pg = unsafe {
        super::super::hosted_producer::Ingress::from_verified_host(
            db,
            caller,
            &request,
            Instant::now(),
        )
    }
    .unwrap();
    let out: Value = serde_json::from_slice(
        &super::super::hosted_producer::preview(
            &pg,
            &crate::artifact_html::LaunchDelivery::new(
                crate::artifact_html::RuntimeConfig::new(
                    "http://localhost:8080",
                    "http://artifact.localhost:8080",
                )
                .unwrap(),
            ),
        )
        .await
        .unwrap()
        .expose()
        .unwrap(),
    )
    .unwrap();
    find_alpha_tab_preview_receipt(out["receipt"]["receipt_id"].as_str().unwrap())
        .unwrap()
        .0
}

#[tokio::test]
async fn fresh_receipt_consumes_once_and_retry_has_no_nonce_or_reset() {
    let (db, caller, mut i) = fixture_source(
        declaration(),
        Consent::Receipt {
            receipt_id: "placeholder".into(),
            preview_session: "placeholder".into(),
        },
        PREVIEW_BODY,
        None,
    )
    .await;
    let receipt = checked_preview_receipt(&db, &caller, &i).await;
    i.consent = Consent::Receipt {
        receipt_id: receipt.receipt_id.clone(),
        preview_session: receipt.preview_session.clone(),
    };
    let g = unsafe { Ingress::from_verified_host(&db, &caller, &i, Instant::now()) }.unwrap();
    let Decision::Fresh(fresh) = begin(&g).await.unwrap() else {
        panic!()
    };
    let old = qualify_fresh(fresh)
        .await
        .unwrap()
        .commit(Some(&receipt.nonce))
        .await
        .unwrap();
    assert!(
        find_alpha_tab_preview_receipt(&receipt.receipt_id)
            .unwrap()
            .1
    );
    let Decision::Recovered(recovered) = begin(&g).await.unwrap() else {
        panic!()
    };
    assert_eq!(old.event_id, recovered.event_id);
    assert!(
        find_alpha_tab_preview_receipt(&receipt.receipt_id)
            .unwrap()
            .1
    );
    let raw: String = sqlx::query_scalar("SELECT payload FROM control_events WHERE id=?")
        .bind(old.event_id)
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert!(!raw.contains(&receipt.nonce));
}

#[tokio::test]
async fn fresh_stale_cas_preserves_receipt_and_spent_without_outcome_refuses() {
    let (db, caller, mut i) = fixture_source(
        declaration(),
        Consent::Receipt {
            receipt_id: "placeholder".into(),
            preview_session: "placeholder".into(),
        },
        PREVIEW_BODY,
        None,
    )
    .await;
    let r = checked_preview_receipt(&db, &caller, &i).await;
    i.consent = Consent::Receipt {
        receipt_id: r.receipt_id.clone(),
        preview_session: r.preview_session.clone(),
    };
    i.expected_install_event_id = Uuid::new_v4().to_string();
    {
        let g = unsafe { Ingress::from_verified_host(&db, &caller, &i, Instant::now()) }.unwrap();
        let Decision::Fresh(f) = begin(&g).await.unwrap() else {
            panic!()
        };
        assert!(qualify_fresh(f).await.is_err());
        assert!(!find_alpha_tab_preview_receipt(&r.receipt_id).unwrap().1);
    }
    i.expected_install_event_id = sqlx::query_scalar("SELECT event_id FROM alpha_tab_installs")
        .fetch_one(db.pool())
        .await
        .unwrap();
    preview_receipt_store()
        .lock()
        .unwrap()
        .get_mut(&r.receipt_id)
        .unwrap()
        .1 = true;
    let g = unsafe { Ingress::from_verified_host(&db, &caller, &i, Instant::now()) }.unwrap();
    let Decision::Fresh(f) = begin(&g).await.unwrap() else {
        panic!()
    };
    assert!(qualify_fresh(f)
        .await
        .unwrap()
        .commit(Some(&r.nonce))
        .await
        .is_err());
    assert!(find_alpha_tab_preview_receipt(&r.receipt_id).unwrap().1);
    assert_eq!(
        0,
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM control_events WHERE idempotency_key='private-adopt'"
        )
        .fetch_one(db.pool())
        .await
        .unwrap()
    );
}

#[tokio::test]
async fn raw_account_and_ingress_deadline_are_never_normalized_or_reset() {
    let (db, _, i) = fixture(declaration(), authored()).await;
    let caller = Caller::authenticated(" account with spaces ");
    let g = unsafe { Ingress::from_verified_host(&db, &caller, &i, Instant::now()) }.unwrap();
    assert_eq!(g.caller.credential(), " account with spaces ");
    let Decision::Fresh(f) = begin(&g).await.unwrap() else {
        panic!()
    };
    assert!(qualify_fresh(f).await.is_err());
    assert!(unsafe {
        Ingress::from_verified_host(&db, &caller, &i, Instant::now() - Duration::from_secs(6))
    }
    .is_err());
}

#[tokio::test]
async fn fresh_retained_source_refusals_preserve_receipt_install_and_history() {
    let oversized = serde_json::to_string(
        &json!({"body": "x".repeat(super::super::hosted_producer::SOURCE_BYTES as usize)}),
    )
    .unwrap();
    let cases = vec![
        (
            "object matching rendered pin",
            Some(b"{\"body\":{}}".to_vec()),
            false,
            "{}",
            "record.updated",
            ARTIFACT,
        ),
        (
            "array matching rendered pin",
            Some(b"{\"body\":[]}".to_vec()),
            false,
            "[]",
            "record.updated",
            ARTIFACT,
        ),
        (
            "absent body",
            Some(b"{}".to_vec()),
            false,
            BODY,
            "record.updated",
            ARTIFACT,
        ),
        (
            "null body",
            Some(b"{\"body\":null}".to_vec()),
            false,
            BODY,
            "record.updated",
            ARTIFACT,
        ),
        (
            "number body",
            Some(b"{\"body\":42}".to_vec()),
            false,
            "42",
            "record.updated",
            ARTIFACT,
        ),
        (
            "blob storage matching text pin",
            Some(serde_json::to_vec(&json!({"body":BODY})).unwrap()),
            true,
            BODY,
            "record.updated",
            ARTIFACT,
        ),
        (
            "malformed JSON",
            Some(b"{broken".to_vec()),
            false,
            BODY,
            "record.updated",
            ARTIFACT,
        ),
        (
            "null payload",
            None,
            false,
            BODY,
            "record.updated",
            ARTIFACT,
        ),
        (
            "array root",
            Some(b"[]".to_vec()),
            false,
            BODY,
            "record.updated",
            ARTIFACT,
        ),
        (
            "string root",
            Some(b"\"body\"".to_vec()),
            false,
            BODY,
            "record.updated",
            ARTIFACT,
        ),
        (
            "oversized payload",
            Some(oversized.into_bytes()),
            false,
            BODY,
            "record.updated",
            ARTIFACT,
        ),
        (
            "wrong event type",
            Some(serde_json::to_vec(&json!({"body":BODY})).unwrap()),
            false,
            BODY,
            "facet.set",
            ARTIFACT,
        ),
        (
            "wrong artifact",
            Some(serde_json::to_vec(&json!({"body":BODY})).unwrap()),
            false,
            BODY,
            "record.updated",
            "a0100000-0000-4000-8000-000000000002",
        ),
    ];
    for (name, payload, blob, rendered, kind, record_id) in cases {
        let (db, caller, mut i) = fixture_source(
            declaration(),
            authored(),
            rendered,
            Some((payload, blob, kind, record_id)),
        )
        .await;
        if name.starts_with("object") || name.starts_with("array matching") {
            let extracted: String = sqlx::query_scalar(
                "SELECT json_extract(payload,'$.body') FROM content_events WHERE id=?",
            )
            .bind(&i.source_revision)
            .fetch_one(db.pool())
            .await
            .unwrap();
            assert_eq!(extracted, rendered);
            let dd =
                crate::alpha_tab_body_admission_v1::declaration_digest(&i.declaration).unwrap();
            assert_eq!(
                i.digest,
                crate::alpha_tab_body_admission_v1::install_digest(
                    &alpha_tab_bundle_digest(&extracted),
                    &dd,
                    "native.html.v1"
                )
            );
        }
        let dd = crate::alpha_tab_body_admission_v1::declaration_digest(&i.declaration).unwrap();
        let r = issue_alpha_tab_preview_receipt(
            caller.credential(),
            &i.package,
            &i.version,
            &i.digest,
            &i.artifact_id,
            &i.source_revision,
            &dd,
            vec![],
            vec![],
            None,
            chrono::Utc::now().timestamp(),
        );
        i.consent = Consent::Receipt {
            receipt_id: r.receipt_id.clone(),
            preview_session: r.preview_session.clone(),
        };
        let before: String = sqlx::query_scalar("SELECT json_object('status',status,'event',event_id,'pointer',body_read_admission_event_id,'digest',digest,'revision',consented_source_revision) FROM alpha_tab_installs")
            .fetch_one(db.pool()).await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM control_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let g = unsafe { Ingress::from_verified_host(&db, &caller, &i, Instant::now()) }.unwrap();
        let Decision::Fresh(f) = begin(&g).await.unwrap() else {
            panic!("{name}")
        };
        assert!(qualify_fresh(f).await.is_err(), "{name}");
        assert!(
            !find_alpha_tab_preview_receipt(&r.receipt_id).unwrap().1,
            "{name}"
        );
        let after: String = sqlx::query_scalar("SELECT json_object('status',status,'event',event_id,'pointer',body_read_admission_event_id,'digest',digest,'revision',consented_source_revision) FROM alpha_tab_installs")
            .fetch_one(db.pool()).await.unwrap();
        assert_eq!(before, after, "{name}");
        assert_eq!(
            count,
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM control_events")
                .fetch_one(db.pool())
                .await
                .unwrap(),
            "{name}"
        );
    }
}

#[tokio::test]
async fn fresh_retained_text_preserves_utf8_bom_empty_and_event_grammar() {
    for kind in ["record.created", "record.updated", "receipt.committed.v1"] {
        for body in [BODY, "\u{feff}<html>é😀</html>", ""] {
            let payload = serde_json::to_vec(&json!({"body":body})).unwrap();
            let (db, caller, i) = fixture_source(
                declaration(),
                authored(),
                body,
                Some((Some(payload), false, kind, ARTIFACT)),
            )
            .await;
            let g =
                unsafe { Ingress::from_verified_host(&db, &caller, &i, Instant::now()) }.unwrap();
            let Decision::Fresh(f) = begin(&g).await.unwrap() else {
                panic!()
            };
            let out = qualify_fresh(f).await.unwrap().commit(None).await.unwrap();
            let stored: String = sqlx::query_scalar(
                "SELECT json_extract(payload,'$.bundle_sha256') FROM control_events WHERE id=?",
            )
            .bind(&out.event_id)
            .fetch_one(db.pool())
            .await
            .unwrap();
            assert_eq!(stored, alpha_tab_bundle_digest(body));
            let pointer: String =
                sqlx::query_scalar("SELECT body_read_admission_event_id FROM alpha_tab_installs")
                    .fetch_one(db.pool())
                    .await
                    .unwrap();
            assert_eq!(pointer, out.event_id);
        }
    }
}

#[tokio::test]
async fn consuming_stages_keep_original_real_deadline_and_unspent_receipt() {
    for stage in ["prepare", "qualify", "commit"] {
        let (db, caller, mut i) = fixture(declaration(), authored()).await;
        let dd = crate::alpha_tab_body_admission_v1::declaration_digest(&i.declaration).unwrap();
        let receipt = issue_alpha_tab_preview_receipt(
            caller.credential(),
            &i.package,
            &i.version,
            &i.digest,
            &i.artifact_id,
            &i.source_revision,
            &dd,
            vec![],
            vec![],
            None,
            chrono::Utc::now().timestamp(),
        );
        i.consent = Consent::Receipt {
            receipt_id: receipt.receipt_id.clone(),
            preview_session: receipt.preview_session.clone(),
        };
        let before: (String, Option<String>, i64) = sqlx::query_as("SELECT event_id,body_read_admission_event_id,(SELECT COUNT(*) FROM control_events) FROM alpha_tab_installs")
            .fetch_one(db.pool()).await.unwrap();
        let started = Instant::now();
        let ingress = unsafe { Ingress::from_verified_host(&db, &caller, &i, started) }.unwrap();
        let Decision::Fresh(fresh) = begin(&ingress).await.unwrap() else {
            panic!()
        };
        // Real elapsed monotonic time, not an injected production clock or
        // an already-expired constructor. Each stage owns the original tx.
        let wait = || {
            tokio::time::sleep_until(tokio::time::Instant::from_std(
                started + Duration::from_millis(5100),
            ))
        };
        match stage {
            "prepare" => {
                wait().await;
                assert!(fresh.prepare_current_pin().is_err());
            }
            "qualify" => {
                let prepared = fresh.prepare_current_pin().unwrap();
                wait().await;
                assert!(prepared.qualify().await.is_err());
            }
            "commit" => {
                let ready = fresh
                    .prepare_current_pin()
                    .unwrap()
                    .qualify()
                    .await
                    .unwrap();
                wait().await;
                assert!(ready.commit(Some(&receipt.nonce)).await.is_err());
            }
            _ => unreachable!(),
        }
        assert!(started.elapsed() >= Duration::from_secs(5));
        assert!(
            !find_alpha_tab_preview_receipt(&receipt.receipt_id)
                .unwrap()
                .1,
            "{stage}"
        );
        let after: (String, Option<String>, i64) = sqlx::query_as("SELECT event_id,body_read_admission_event_id,(SELECT COUNT(*) FROM control_events) FROM alpha_tab_installs")
            .fetch_one(db.pool()).await.unwrap();
        assert_eq!(before, after, "{stage}");
    }
}

#[tokio::test]
async fn prepared_current_row_pin_and_runtime_refusals_have_no_marker_bypass() {
    // Explicit projection corruption is confined to separate operator-trusted
    // in-memory fixtures. It tests current consistency, not host authentication.
    for (column, value) in [
        ("account_id", "another-account"),
        ("version", "2.0.0"),
        ("digest", "another-digest"),
        ("artifact_id", "a0100000-0000-4000-8000-000000000004"),
        ("consented_source_revision", "another-source"),
        (
            "declaration_digest",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        ("consented_declaration", "{\"needs\":[],\"effects\":[]}"),
        ("status", "disabled"),
        ("runtime", "native.other.v1"),
    ] {
        let (db, caller, i) = fixture(declaration(), authored()).await;
        let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM control_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        if column == "runtime" {
            sqlx::query("UPDATE facet_values SET value=? WHERE record_id=? AND key='runtime'")
                .bind(value)
                .bind(ARTIFACT)
                .execute(db.write_pool())
                .await
                .unwrap();
        } else {
            if column == "artifact_id" {
                crate::store::create_record(
                    &db,
                    json!({"id":value,"type":"Document","kind":"artifact","name":"Mismatched artifact fixture","body":BODY}),
                )
                .await
                .unwrap();
            }
            sqlx::query(&format!("UPDATE alpha_tab_installs SET {column}=?"))
                .bind(value)
                .execute(db.write_pool())
                .await
                .unwrap();
        }
        // Even a caller carrying an exact reusable legacy pin is irrelevant:
        // the trusted request still needs complete current row/source proof.
        let legacy = alpha_tab_preview_authority_for(
            caller.credential(),
            &i.package,
            &i.version,
            &i.digest,
            &i.artifact_id,
            &i.source_revision,
            &i.declaration,
        )
        .unwrap();
        let caller = caller.with_verified_alpha_tab_adopt_authored(legacy);
        let ingress =
            unsafe { Ingress::from_verified_host(&db, &caller, &i, Instant::now()) }.unwrap();
        let Decision::Fresh(fresh) = begin(&ingress).await.unwrap() else {
            panic!()
        };
        assert!(
            fresh
                .prepare_current_pin()
                .unwrap()
                .qualify()
                .await
                .is_err(),
            "{column}"
        );
        assert_eq!(
            before,
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM control_events")
                .fetch_one(db.pool())
                .await
                .unwrap()
        );
        assert!(sqlx::query_scalar::<_, Option<String>>(
            "SELECT body_read_admission_event_id FROM alpha_tab_installs"
        )
        .fetch_one(db.pool())
        .await
        .unwrap()
        .is_none());
    }
}

#[tokio::test]
async fn preparation_and_qualification_observe_same_uncommitted_writer_transaction() {
    let (db, caller, i) = fixture(declaration(), authored()).await;
    let ingress = unsafe { Ingress::from_verified_host(&db, &caller, &i, Instant::now()) }.unwrap();
    let Decision::Fresh(mut fresh) = begin(&ingress).await.unwrap() else {
        panic!()
    };
    // The outside projection is still installed. Only this transaction sees
    // disabled: a re-opened snapshot would miss it (or deadlock on our writer).
    sqlx::query("UPDATE alpha_tab_installs SET status='disabled'")
        .execute(&mut *fresh.tx)
        .await
        .unwrap();
    let prepared = fresh.prepare_current_pin().unwrap();
    let qualified = tokio::time::timeout(Duration::from_secs(2), prepared.qualify())
        .await
        .expect("qualification replaced its writer transaction");
    assert!(qualified.is_err());
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT status FROM alpha_tab_installs")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        "installed"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM control_events WHERE type='alpha_tab.adopted.v2'"
        )
        .fetch_one(db.pool())
        .await
        .unwrap(),
        0
    );
}
