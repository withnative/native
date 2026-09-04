use native_ce::authorization::{
    effective_capability, replace_explicit_policy, AllowEntry, Capability, Principal,
};
use native_ce::mcp::{
    register_surface_tools, render, Caller, ExposureProfile, ToolKind, ToolRegistry,
};
use native_ce::store::create_record;
use native_ce::{apply_schema, open_database, Db};
use serde_json::{json, Value};

async fn db() -> Db {
    let db = open_database(":memory:").await.unwrap();
    apply_schema(&db).await.unwrap();
    native_ce::meta::seed_vocabularies(&db).await.unwrap();
    native_ce::meta::seed_recommended_pack_schema_config(&db)
        .await
        .unwrap();
    native_ce::seed_content_tier(&db).await.unwrap();
    native_ce::identity::seed_database_identity(&db)
        .await
        .unwrap();
    db
}

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

#[test]
fn secondary_backends_fail_closed_without_relationship_handlers() {
    let registry = registry();
    assert!(registry.get("manage_relationships").is_some());
    assert!(!ToolKind::ManageRelationships
        .exposure()
        .shown_in(ExposureProfile::Focused));
    assert!(ToolKind::ManageRelationships
        .exposure()
        .shown_in(ExposureProfile::Complete));
    #[cfg(feature = "postgres")]
    assert!(
        !registry.has_engine_handler("manage_relationships", native_ce::mcp::EngineKind::Postgres,)
    );
    #[cfg(feature = "turso-local")]
    assert!(!registry.has_engine_handler(
        "manage_relationships",
        native_ce::mcp::EngineKind::TursoLocal,
    ));
}

async fn call(
    registry: &ToolRegistry,
    db: &Db,
    caller: Caller,
    arguments: Value,
) -> native_ce::Result<Value> {
    registry
        .call(db.clone(), caller, "manage_relationships", arguments)
        .await
}

async fn query_sql(
    registry: &ToolRegistry,
    db: &Db,
    caller: Caller,
    sql: &str,
    parameters: Value,
) -> Value {
    registry
        .call(
            db.clone(),
            caller,
            "query_sql",
            json!({"sql": sql, "parameters": parameters}),
        )
        .await
        .unwrap()
}

fn renderer_attestation(outputs: Value) -> Value {
    json!({
        "id":"attestation-1","schema_version":2,"executor_kind":"native",
        "has_verified_interaction":false,"trust":"native_verified",
        "operation":"manage_relationships","action_digest":"action-digest",
        "output_event_set_digest":"output-digest","issuer":"local",
        "issuer_origin_database_id":"origin-1","issued_at":"now","intent_digest":null,
        "outputs":outputs,"output_event_ids":["event-1"],"validity":"valid"
    })
}

#[test]
fn relationship_renderer_dispatches_by_server_action_and_bounds_read_pages() {
    let receipt = json!({
        "action": "add_evidence",
        "status": "evidence_added",
        "relationship_origin_db_id": "origin-1",
        "relationship_id": "relationship-1",
        "relationship_revision": 1,
        "assertion_issuer_origin_db_id": "origin-1",
        "assertion_id": "assertion-1",
        "assertion_stream_version": 2,
        "evidence_id": "evidence-1",
        "output_events": [{
            "domain": "relationship",
            "issuer_origin_db_id": "origin-1",
            "event_id": "event-1"
        }],
        "action_attestation_ids": ["attestation-1"],
        "future_receipt_field": "preserved-exactly"
    });
    let receipt_text = render::render("manage_relationships", &receipt).unwrap();
    assert!(receipt_text.contains("Relationship add_evidence write receipt."));
    assert!(receipt_text.contains("evidence-1"), "{receipt_text}");
    assert!(
        receipt_text.contains("future_receipt_field"),
        "{receipt_text}"
    );
    assert!(
        !receipt_text.contains("preserved-exactly"),
        "{receipt_text}"
    );

    let hostile_receipt = json!({
        "action":"contest",
        "status":"contested",
        "relationship_origin_db_id":"origin-1",
        "relationship_id":"relationship-1",
        "relationship_revision":1,
        "assertion_issuer_origin_db_id":"origin-1",
        "assertion_id":"assertion-1",
        "assertion_stream_version":1,
        "evidence_id":"SECRET-WRONG-ACTION-EVIDENCE",
        "output_events":[{
            "domain":"relationship",
            "issuer_origin_db_id":"origin-1",
            "event_id":"event-1",
            "future_output":"SECRET-WRITE-UNKNOWN"
        }],
        "action_attestation_ids":["attestation-1"]
    });
    let hostile_receipt_text = render::render("manage_relationships", &hostile_receipt).unwrap();
    for name in ["evidence_id", "future_output"] {
        assert!(
            hostile_receipt_text.contains(name),
            "{hostile_receipt_text}"
        );
    }
    assert!(
        !hostile_receipt_text.contains("SECRET-"),
        "{hostile_receipt_text}"
    );

    let why = json!({
        "action": "why",
        "relationship_origin_db_id": "origin-1",
        "relationship_id": "relationship-1",
        "relationship_type": "depends_on",
        "type_definition_id": "depends_on.v1",
        "canonical_proposition_key": "proposition-1",
        "endpoints": [{"role":"subject","portable_ref":"native://origin-1/record-1","record_id":"record-1"}],
        "effective": {
            "state":"active","epistemic_state":"supported",
            "support_count":1,"contest_count":0,"admission_counts":{},
            "reducer_id":"reducer-1","reducer_version":1,
            "assertion_set_digest":"digest-1","knowledge_watermark":[],"recomputed_at":"now"
        },
        "assertions": [{
            "assertion_issuer_origin_db_id":"origin-1",
            "assertion_id":"assertion-1",
            "stance":"support","state":"active","semantic_claimant":"claimant-1",
            "head":{"issuer_origin_db_id":"origin-1","event_id":"event-1","stream_version":1},
            "local_admission":{"state":"admitted","class":null},
            "origin_admission":{
                "schema_version":1,"relationship_type_definition":"depends_on.v1",
                "admission_class":"support","authority_anchor":{"endpoint_role":"subject","endpoint_ref":"native://origin-1/record-1"},
                "admission_rule":"rule-1","authorization_decision_digest":"digest-2",
                "authoring_action_attestation_id":"attestation-1"
            },
            "causal_parents":[],
            "events":[{"stream_version":1,"type":"assertion.created.v1","occurred_at":"now","payload":{}}],
            "evidence":[],
            "rationale": format!("ASSERTION-SENTINEL-{}", "a".repeat(5_000))
        }],
        "authorized_action_provenance": [{
            "attestation":renderer_attestation(json!([{"domain":"relationship","event_id":"event-1"}])),
            "why":{"principal":"local","executor_ref_digest":null,"delegation_present":false,"command_identity_digest":null},
            "interaction":null,
            "detail": format!("PROVENANCE-SENTINEL-{}", "p".repeat(5_000))
        }]
    });
    let why_text = render::render("manage_relationships", &why).unwrap();
    assert!(why_text.contains("Relationship why."), "{why_text}");
    assert!(why_text.contains("ASSERTION-SENTINEL"), "{why_text}");
    assert!(why_text.contains("attestation-1"), "{why_text}");
    assert!(why_text.contains("detail"), "{why_text}");
    assert!(!why_text.contains("PROVENANCE-SENTINEL"), "{why_text}");
    assert!(why_text.contains("format:\"json\""), "{why_text}");

    let find = json!({
        "action": "find",
        "endpoint": {"record_id":"record-1","resolved_from":"record_id"},
        "results": (0..30).map(|index| json!({
            "relationship_origin_db_id":"origin-1",
            "relationship_id": format!("relationship-{index}"),
            "relationship_type":"depends_on","type_definition_id":"depends_on.v1","occurred_at":"now",
            "endpoint":{"record_id":"record-1","role":"subject"},
            "counterpart": {"role":"object","record_id":format!("record-{index}"),"portable_ref":format!("native://origin-1/record-{index}"),"name":"n".repeat(2_000)},
            "effective":{"state":"active","epistemic_state":"supported","support_count":1,"contest_count":0,"recomputed_at":"now"}
        })).collect::<Vec<_>>(),
        "returned": 30,
        "limit": 30,
        "offset": 10,
        "has_more": true,
        "scan_limit_reached": true,
        "future_page_field": "not-echoed"
    });
    let find_text = render::render("manage_relationships", &find).unwrap();
    assert!(find_text.contains("offset 40"), "{find_text}");
    assert!(
        find_text.contains("candidate scan reached its limit"),
        "{find_text}"
    );
    assert!(find_text.contains("future_page_field"), "{find_text}");
    assert!(!find_text.contains("not-echoed"), "{find_text}");
    assert!(find_text.contains("format:\"json\""), "{find_text}");
    assert!(find_text.len() < 25_000, "{find_text}");

    let mut hostile_attestation =
        renderer_attestation(json!([{"domain":"relationship","event_id":"event-1"}]));
    hostile_attestation["future_attestation"] = json!("SECRET-UNKNOWN-ATTESTATION");
    let hostile_nested = json!({
        "action": "why",
        "relationship_origin_db_id": "origin-1",
        "relationship_id": "relationship-1",
        "relationship_type": "depends_on",
        "type_definition_id": "depends_on.v1",
        "canonical_proposition_key": "proposition-1",
        "endpoints": [{
            "role":"subject",
            "portable_ref":"native://record-1",
            "record_id":"record-1",
            "record_kind":{"private":"SECRET-MALFORMED-ENDPOINT"},
            "future_endpoint":{"private":"SECRET-UNKNOWN-ENDPOINT"}
        }],
        "effective": {
            "state":"active",
            "epistemic_state":"supported",
            "support_count":1,"contest_count":0,"admission_counts":{},
            "reducer_id":"reducer-1","reducer_version":1,
            "assertion_set_digest":"digest-1","knowledge_watermark":[],"recomputed_at":"now",
            "future_effective":{"private":"SECRET-UNKNOWN-EFFECTIVE"}
        },
        "assertions": [{
            "assertion_issuer_origin_db_id":"origin-1",
            "assertion_id":"assertion-1",
            "stance":"support",
            "state":"active",
            "semantic_claimant":"claimant-1",
            "head":{"issuer_origin_db_id":"origin-1","event_id":"event-1","stream_version":1,"future_head":"SECRET-UNKNOWN-HEAD"},
            "local_admission":{"state":"admitted","class":null},
            "origin_admission":{
                "schema_version":1,"relationship_type_definition":"depends_on.v1",
                "admission_class":"support","authority_anchor":{"endpoint_role":"subject","endpoint_ref":"native://origin-1/record-1"},
                "admission_rule":"rule-1","authorization_decision_digest":"digest-2",
                "authoring_action_attestation_id":"attestation-1"
            },
            "causal_parents":[],
            "events":[{"stream_version":1,"type":"assertion.created.v1","occurred_at":"now","payload":{"private":"SECRET-EVENT-PAYLOAD"},"future_event":"SECRET-UNKNOWN-EVENT"}],
            "evidence":[],
            "future_assertion":{"private":"SECRET-UNKNOWN-ASSERTION"}
        }],
        "authorized_action_provenance": [{
            "attestation":hostile_attestation,
            "why":{"principal":"local","future_why":"SECRET-UNKNOWN-WHY"},
            "interaction":null,
            "future_provenance":"SECRET-UNKNOWN-PROVENANCE"
        }]
    });
    let hostile_text = render::render("manage_relationships", &hostile_nested).unwrap();
    for name in [
        "record_kind",
        "future_endpoint",
        "future_effective",
        "future_head",
        "future_event",
        "future_assertion",
        "future_attestation",
        "future_why",
        "future_provenance",
    ] {
        assert!(hostile_text.contains(name), "{name}: {hostile_text}");
    }
    assert!(!hostile_text.contains("SECRET-"), "{hostile_text}");

    let mut blank_receipt = receipt.clone();
    blank_receipt["relationship_id"] = json!("  ");
    let mut zero_revision_receipt = receipt.clone();
    zero_revision_receipt["relationship_revision"] = json!(0);
    for malformed in [blank_receipt, zero_revision_receipt] {
        let text = render::render("manage_relationships", &malformed).unwrap();
        assert!(text.contains("no write outcome was inferred"), "{text}");
    }

    let mut saturation = why.clone();
    saturation["action"] = json!("read");
    saturation["assertions"] = json!((0..1_000)
        .map(|index| json!({
            "assertion_issuer_origin_db_id":"origin-1",
            "assertion_id":format!("assertion-{index}"),
            "stance":"support","state":"active","semantic_claimant":"claimant-1",
            "head":{"issuer_origin_db_id":"origin-1","event_id":format!("event-{index}"),"stream_version":1},
            "local_admission":{"state":"admitted","class":null},
            "origin_admission":{
                "schema_version":1,"relationship_type_definition":"depends_on.v1",
                "admission_class":"support","authority_anchor":{"endpoint_role":"subject","endpoint_ref":"native://origin-1/record-1"},
                "admission_rule":"rule-1","authorization_decision_digest":"digest-2",
                "authoring_action_attestation_id":"attestation-1"
            },
            "causal_parents":[],
            "events":[{"stream_version":1,"type":"assertion.created.v1","occurred_at":"now","payload":{}}],
            "evidence":[]
        }))
        .collect::<Vec<_>>());
    let saturation_text = render::render("manage_relationships", &saturation).unwrap();
    assert!(
        saturation_text.contains("Assertion detail:")
            && saturation_text.contains("omitted from text"),
        "{saturation_text}"
    );
    assert!(saturation_text.len() < 35_000, "{}", saturation_text.len());

    let mut nested_saturation = why.clone();
    nested_saturation["action"] = json!("read");
    nested_saturation["assertions"][0]["rationale"] = Value::Null;
    nested_saturation["assertions"][0]["events"] = json!((0..150)
        .map(|index| {
            if index == 0 {
                json!({"stream_version":0,"type":"","occurred_at":"now","payload":{}})
            } else {
                json!({"stream_version":index + 1,"type":"assertion.evidence_added.v1","occurred_at":"now","payload":{}})
            }
        })
        .collect::<Vec<_>>());
    nested_saturation["assertions"][0]["evidence"] =
        json!([{"record_id":"evidence-1","reason":null}]);
    let nested_saturation_text =
        render::render("manage_relationships", &nested_saturation).unwrap();
    assert!(
        nested_saturation_text
            .contains("Assertion nested detail: 99 rendered, 1 malformed, 51 omitted from text"),
        "{nested_saturation_text}"
    );
    assert!(
        nested_saturation_text.len() < 35_000,
        "{}",
        nested_saturation_text.len()
    );

    let provenance_outputs = (0..150)
        .map(|index| {
            if index == 0 {
                json!({"domain":"relationship","event_id":""})
            } else {
                json!({"domain":"relationship","event_id":format!("event-{index}")})
            }
        })
        .collect::<Vec<_>>();
    let provenance_envelope = |attestation| {
        json!({
            "attestation":attestation,
            "why":{"principal":"local","executor_ref_digest":null,"delegation_present":false,"command_identity_digest":null},
            "interaction":null
        })
    };
    let mut provenance_saturation = why.clone();
    provenance_saturation["authorized_action_provenance"] = json!([
        provenance_envelope(json!({})),
        provenance_envelope(renderer_attestation(json!(provenance_outputs)))
    ]);
    let provenance_saturation_text =
        render::render("manage_relationships", &provenance_saturation).unwrap();
    assert!(
        provenance_saturation_text.contains(
            "Provenance receipt/output detail: 98 rendered, 2 malformed, 52 omitted from text"
        ),
        "{provenance_saturation_text}"
    );
    assert!(
        provenance_saturation_text.len() < 35_000,
        "{}",
        provenance_saturation_text.len()
    );

    for malformed in [
        json!({"status":"asserted"}),
        json!({"action":"assert","status":"contested"}),
        json!({"action":"find","endpoint":{},"results":[],"returned":1,"limit":25,"offset":0,"has_more":false,"scan_limit_reached":false}),
        json!({"action":"find","endpoint":{},"results":[],"returned":0,"limit":201,"offset":0,"has_more":false,"scan_limit_reached":false}),
        json!({"action":"find","endpoint":{},"results":[],"returned":0,"limit":25,"offset":1990,"has_more":false,"scan_limit_reached":false}),
        json!({"action":"find","endpoint":{},"results":[],"returned":0,"limit":25,"offset":0,"has_more":true,"scan_limit_reached":false}),
        json!({"action":"find","endpoint":{},"results":[],"returned":0,"limit":25,"offset":0,"has_more":false,"scan_limit_reached":false}),
        json!({"action":"find","endpoint":{"record_id":"record-1","resolved_from":"record_id"},"results":[{}],"returned":1,"limit":2,"offset":0,"has_more":false,"scan_limit_reached":false}),
        json!({"action":"find","endpoint":{},"results":[{}],"returned":1,"limit":2,"offset":0,"has_more":true,"scan_limit_reached":false}),
        json!({"action":"find","endpoint":{},"results":[{},{},{}],"returned":3,"limit":2,"offset":0,"has_more":false,"scan_limit_reached":false}),
        json!({
            "action":"read",
            "relationship_origin_db_id":"origin-1","relationship_id":"relationship-1",
            "relationship_type":"depends_on","type_definition_id":"depends_on.v1",
            "canonical_proposition_key":"proposition-1",
            "endpoints":[{}],"effective":{},"assertions":[{}]
        }),
    ] {
        let text = render::render("manage_relationships", &malformed).unwrap();
        assert!(
            text.contains("outcome was inferred")
                || text.contains("no page claim was inferred")
                || text.contains("was not interpreted"),
            "{text}"
        );
        assert!(text.contains("format:\"json\""), "{text}");
    }
}

async fn bind_account(db: &Db, person: &str, account: &str) {
    native_ce::identity::add_binding(
        db,
        &native_ce::identity::MutationContext {
            actor: "relationship acceptance fixture",
            reason: "bind relationship endpoint",
            run_key: None,
            parent_key: None,
            intent: None,
            internal: true,
            source_read_authorized: false,
        },
        person,
        &native_ce::identity::BindingClaim {
            system: "account".into(),
            identifier: account.into(),
        },
        true,
    )
    .await
    .unwrap();
}

async fn read_effective(
    registry: &ToolRegistry,
    db: &Db,
    caller: Caller,
    receipt: &Value,
) -> Value {
    call(
        registry,
        db,
        caller,
        json!({
            "action":"read",
            "relationship_origin_db_id":receipt["relationship_origin_db_id"],
            "relationship_id":receipt["relationship_id"]
        }),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn public_relationship_tool_rejects_sealed_legacy_link_definition() {
    let db = db().await;
    let registry = registry();
    let source = create_record(
        &db,
        json!({"type":"WorkItem","kind":"task","name":"source"}),
    )
    .await
    .unwrap();
    let target = create_record(
        &db,
        json!({"type":"Outcome","kind":"target","name":"target"}),
    )
    .await
    .unwrap();
    let error = call(
        &registry,
        &db,
        Caller::local(),
        json!({
            "action":"assert",
            "relationship_type":"legacy_link.v1",
            "endpoints":[
                {"role":"source","record_id":source},
                {"role":"target","record_id":target}
            ],
            "idempotency_key":"sealed-definition-rejection"
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("not governed"), "{error}");
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM relationships")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn relationship_actions_are_atomic_idempotent_and_explainable() {
    let db = db().await;
    let registry = registry();
    let subject = create_record(
        &db,
        json!({"type":"WorkItem","kind":"task","name":"subject"}),
    )
    .await
    .unwrap();
    let object = create_record(
        &db,
        json!({"type":"Outcome","kind":"target","name":"object"}),
    )
    .await
    .unwrap();
    let evidence = create_record(
        &db,
        json!({"type":"Document","kind":"note","name":"evidence"}),
    )
    .await
    .unwrap();
    let person = create_record(
        &db,
        json!({"type":"Entity","kind":"person","name":"assignee"}),
    )
    .await
    .unwrap();
    native_ce::identity::add_binding(
        &db,
        &native_ce::identity::MutationContext {
            actor: "local",
            reason: "bind relationship contest endpoint",
            run_key: None,
            parent_key: None,
            intent: None,
            internal: true,
            source_read_authorized: false,
        },
        &person,
        &native_ce::identity::BindingClaim {
            system: "account".into(),
            identifier: "local".into(),
        },
        true,
    )
    .await
    .unwrap();
    let bound_person: Option<String> = sqlx::query_scalar(
        "SELECT record_id FROM bindings WHERE system='account' AND identifier='local' AND is_canonical=1",
    )
    .fetch_optional(db.pool())
    .await
    .unwrap();
    assert_eq!(bound_person.as_deref(), Some(person.as_str()));
    let assertion_args = json!({
        "action":"assert",
        "relationship_type":"depends_on",
        "endpoints":[
            {"role":"object","record_id":object},
            {"role":"subject","record_id":subject}
        ],
        "on_behalf_of":"semantic-context-only",
        "idempotency_key":"assert-1"
    });
    let first = call(&registry, &db, Caller::local(), assertion_args.clone())
        .await
        .unwrap();
    assert_eq!(first["action"], "assert");
    assert_eq!(first["status"], "asserted");
    assert_eq!(first["action_attestation_ids"].as_array().unwrap().len(), 1);

    let retry = call(
        &registry,
        &db,
        Caller::local(),
        json!({
            "action":"assert",
            "relationship_type":"depends_on",
            "endpoints":[
                {"role":"subject","record_id":subject},
                {"role":"object","record_id":object}
            ],
            "on_behalf_of":"semantic-context-only",
            "idempotency_key":" assert-1 "
        }),
    )
    .await
    .unwrap();
    assert_eq!(retry, first, "retry receipt must be byte-identical JSON");
    let conflict = call(
        &registry,
        &db,
        Caller::local(),
        json!({
            "action":"assert","relationship_type":"depends_on",
            "endpoints":[{"role":"subject","record_id":subject},{"role":"object","record_id":object}],
            "rationale":"different semantic input","on_behalf_of":"semantic-context-only",
            "idempotency_key":"assert-1"
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        conflict.contains("reused with conflicting action input"),
        "{conflict}"
    );
    let event_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM relationship_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(event_count, 2);
    let delegation: Option<String> =
        sqlx::query_scalar("SELECT delegation_ref FROM provenance_action_attestations WHERE id=?")
            .bind(first["action_attestation_ids"][0].as_str().unwrap())
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(delegation, None, "on_behalf_of must not become delegation");

    let second = call(
        &registry,
        &db,
        Caller::local(),
        json!({
            "action":"assert","relationship_type":"depends_on",
            "endpoints":[{"role":"subject","record_id":subject},{"role":"object","record_id":object}],
            "idempotency_key":"assert-2"
        }),
    )
    .await
    .unwrap();
    assert_eq!(second["action"], "assert");
    assert_eq!(second["relationship_id"], first["relationship_id"]);
    assert_ne!(second["assertion_id"], first["assertion_id"]);
    let relationships: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM relationships")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(
        relationships, 1,
        "existing proposition gets assertion-only genesis"
    );

    let assigned = call(
        &registry,
        &db,
        Caller::local(),
        json!({
            "action":"assert","relationship_type":"assigned_to",
            "endpoints":[{"role":"subject","record_id":subject},{"role":"object","record_id":person}],
            "idempotency_key":"assigned-1"
        }),
    )
    .await
    .unwrap();
    assert_eq!(assigned["action"], "assert");
    let assigned_read = call(
        &registry,
        &db,
        Caller::local(),
        json!({
            "action":"read",
            "relationship_origin_db_id":assigned["relationship_origin_db_id"],
            "relationship_id":assigned["relationship_id"]
        }),
    )
    .await
    .unwrap();
    assert_eq!(assigned_read["action"], "read");
    assert_eq!(assigned_read["relationship_type"], "assigned_to");
    let assigned_read_text = render::render("manage_relationships", &assigned_read).unwrap();
    assert!(
        assigned_read_text.contains("Relationship read."),
        "{assigned_read_text}"
    );
    assert!(
        assigned_read_text.contains("\"state\":\"active\"")
            && assigned_read_text.contains("\"epistemic_state\":\"supported\""),
        "{assigned_read_text}"
    );
    let contested = call(
        &registry,
        &db,
        Caller::local(),
        json!({
            "action":"contest",
            "relationship_origin_db_id":assigned["relationship_origin_db_id"],
            "relationship_id":assigned["relationship_id"],
            "on_behalf_of":"semantic-only",
            "idempotency_key":"contest-1"
        }),
    )
    .await
    .unwrap();
    assert_eq!(contested["action"], "contest");
    assert_eq!(contested["status"], "contested");
    assert_ne!(contested["assertion_id"], assigned["assertion_id"]);
    let contest_retry = call(
        &registry,
        &db,
        Caller::local(),
        json!({
            "action":"contest",
            "relationship_origin_db_id":assigned["relationship_origin_db_id"],
            "relationship_id":assigned["relationship_id"],
            "on_behalf_of":"semantic-only","idempotency_key":" contest-1 "
        }),
    )
    .await
    .unwrap();
    assert_eq!(contest_retry["action"], "contest");
    assert_eq!(contest_retry, contested);
    let contest_conflict = call(
        &registry,
        &db,
        Caller::local(),
        json!({
            "action":"contest",
            "relationship_origin_db_id":assigned["relationship_origin_db_id"],
            "relationship_id":assigned["relationship_id"],
            "on_behalf_of":"different semantic claim","idempotency_key":"contest-1"
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        contest_conflict.contains("reused with conflicting action input"),
        "{contest_conflict}"
    );

    let evidence_result = call(
        &registry,
        &db,
        Caller::local(),
        json!({
            "action":"add_evidence",
            "assertion_issuer_origin_db_id":first["assertion_issuer_origin_db_id"],
            "assertion_id":first["assertion_id"],
            "evidence_id":evidence,
            "reason":"direct basis",
            "idempotency_key":"evidence-1"
        }),
    )
    .await
    .unwrap();
    assert_eq!(evidence_result["action"], "add_evidence");
    assert_eq!(evidence_result["status"], "evidence_added");
    let evidence_retry = call(
        &registry,
        &db,
        Caller::local(),
        json!({
            "action":"add_evidence",
            "assertion_issuer_origin_db_id":first["assertion_issuer_origin_db_id"],
            "assertion_id":first["assertion_id"],"evidence_id":evidence,
            "reason":"direct basis","idempotency_key":" evidence-1 "
        }),
    )
    .await
    .unwrap();
    assert_eq!(evidence_retry["action"], "add_evidence");
    assert_eq!(evidence_retry, evidence_result);
    let evidence_conflict = call(
        &registry,
        &db,
        Caller::local(),
        json!({
            "action":"add_evidence",
            "assertion_issuer_origin_db_id":first["assertion_issuer_origin_db_id"],
            "assertion_id":first["assertion_id"],"evidence_id":evidence,
            "reason":"different basis","idempotency_key":"evidence-1"
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        evidence_conflict.contains("reused with conflicting action input"),
        "{evidence_conflict}"
    );

    let read = call(
        &registry,
        &db,
        Caller::local(),
        json!({"action":"read","relationship_origin_db_id":first["relationship_origin_db_id"],"relationship_id":first["relationship_id"]}),
    )
    .await
    .unwrap();
    assert_eq!(read["action"], "read");
    assert_eq!(read["assertions"].as_array().unwrap().len(), 2);

    let why = call(
        &registry,
        &db,
        Caller::local(),
        json!({"action":"why","relationship_origin_db_id":first["relationship_origin_db_id"],"relationship_id":first["relationship_id"]}),
    )
    .await
    .unwrap();
    assert_eq!(why["action"], "why");
    assert_eq!(why["assertions"].as_array().unwrap().len(), 2);
    assert!(!why["authorized_action_provenance"]
        .as_array()
        .unwrap()
        .is_empty());
    let why_text = render::render("manage_relationships", &why).unwrap();
    assert!(
        why_text.contains("Authorized action provenance receipts returned:"),
        "{why_text}"
    );

    let retracted = call(
        &registry,
        &db,
        Caller::local(),
        json!({
            "action":"retract",
            "assertion_issuer_origin_db_id":first["assertion_issuer_origin_db_id"],
            "assertion_id":first["assertion_id"],
            "reason":"superseded evidence",
            "idempotency_key":"retract-1"
        }),
    )
    .await
    .unwrap();
    assert_eq!(retracted["action"], "retract");
    assert_eq!(retracted["status"], "retracted");
    let retract_retry = call(
        &registry,
        &db,
        Caller::local(),
        json!({
            "action":"retract",
            "assertion_issuer_origin_db_id":first["assertion_issuer_origin_db_id"],
            "assertion_id":first["assertion_id"],"reason":"superseded evidence",
            "idempotency_key":" retract-1 "
        }),
    )
    .await
    .unwrap();
    assert_eq!(retract_retry, retracted);
    let retract_conflict = call(
        &registry,
        &db,
        Caller::local(),
        json!({
            "action":"retract",
            "assertion_issuer_origin_db_id":first["assertion_issuer_origin_db_id"],
            "assertion_id":first["assertion_id"],"reason":"different reason",
            "idempotency_key":"retract-1"
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        retract_conflict.contains("reused with conflicting action input"),
        "{retract_conflict}"
    );
    let late_evidence_retry = call(
        &registry,
        &db,
        Caller::local(),
        json!({
            "action":"add_evidence",
            "assertion_issuer_origin_db_id":first["assertion_issuer_origin_db_id"],
            "assertion_id":first["assertion_id"],"evidence_id":evidence,
            "reason":"direct basis","idempotency_key":"evidence-1"
        }),
    )
    .await
    .unwrap();
    assert_eq!(late_evidence_retry, evidence_result);

    for (receipt, action) in [
        (&first, "assert"),
        (&contested, "contest"),
        (&evidence_result, "add_evidence"),
        (&retracted, "retract"),
    ] {
        let text = render::render("manage_relationships", receipt).unwrap();
        assert!(
            text.starts_with(&format!("Relationship {action} write receipt")),
            "{text}"
        );
        for handle in [
            &receipt["relationship_origin_db_id"],
            &receipt["relationship_id"],
            &receipt["assertion_issuer_origin_db_id"],
            &receipt["assertion_id"],
        ] {
            assert!(text.contains(handle.as_str().unwrap()), "{text}");
        }
        for event in receipt["output_events"].as_array().unwrap() {
            assert!(text.contains(event["event_id"].as_str().unwrap()), "{text}");
        }
        for attestation_id in receipt["action_attestation_ids"].as_array().unwrap() {
            assert!(text.contains(attestation_id.as_str().unwrap()), "{text}");
        }
    }
    let read_text = render::render("manage_relationships", &read).unwrap();
    assert!(read_text.starts_with("Relationship read."), "{read_text}");
    assert!(
        read_text.contains(first["relationship_id"].as_str().unwrap()),
        "{read_text}"
    );
    for assertion in read["assertions"].as_array().unwrap() {
        assert!(
            read_text.contains(assertion["assertion_id"].as_str().unwrap()),
            "{read_text}"
        );
    }
    let why_text = render::render("manage_relationships", &why).unwrap();
    assert!(why_text.starts_with("Relationship why."), "{why_text}");
    assert!(
        why_text.contains("Authorized action provenance receipts returned:"),
        "{why_text}"
    );
}

#[tokio::test]
async fn relationship_denials_are_opaque_and_leave_no_governed_writes() {
    let db = db().await;
    let registry = registry();
    let subject = create_record(
        &db,
        json!({"type":"WorkItem","kind":"task","name":"subject"}),
    )
    .await
    .unwrap();
    let object = create_record(
        &db,
        json!({"type":"Outcome","kind":"target","name":"object"}),
    )
    .await
    .unwrap();
    let denied = call(
        &registry,
        &db,
        Caller::authenticated("unbound-account"),
        json!({
            "action":"assert","relationship_type":"depends_on",
            "endpoints":[{"role":"subject","record_id":subject},{"role":"object","record_id":object}],
            "idempotency_key":"denied-1"
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(denied.contains("does not exist"), "{denied}");
    let events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM relationship_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let attestations: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM provenance_action_attestations WHERE operation='manage_relationships'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!((events, attestations), (0, 0));

    let person = create_record(
        &db,
        json!({"type":"Entity","kind":"person","name":"person"}),
    )
    .await
    .unwrap();
    let evidence = create_record(
        &db,
        json!({"type":"Document","kind":"note","name":"hidden evidence"}),
    )
    .await
    .unwrap();
    let assigned = call(
        &registry,
        &db,
        Caller::local(),
        json!({
            "action":"assert","relationship_type":"assigned_to",
            "endpoints":[{"role":"subject","record_id":subject},{"role":"object","record_id":person}],
            "idempotency_key":"local-genesis"
        }),
    )
    .await
    .unwrap();
    let before_events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM relationship_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let before_attestations: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM provenance_action_attestations WHERE operation='manage_relationships'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    for arguments in [
        json!({"action":"contest","relationship_origin_db_id":assigned["relationship_origin_db_id"],"relationship_id":assigned["relationship_id"],"idempotency_key":"denied-contest"}),
        json!({"action":"add_evidence","assertion_issuer_origin_db_id":assigned["assertion_issuer_origin_db_id"],"assertion_id":assigned["assertion_id"],"evidence_id":evidence,"reason":"denied","idempotency_key":"denied-evidence"}),
        json!({"action":"retract","assertion_issuer_origin_db_id":assigned["assertion_issuer_origin_db_id"],"assertion_id":assigned["assertion_id"],"reason":"denied","idempotency_key":"denied-retract"}),
        json!({"action":"read","relationship_origin_db_id":assigned["relationship_origin_db_id"],"relationship_id":assigned["relationship_id"]}),
        json!({"action":"why","relationship_origin_db_id":assigned["relationship_origin_db_id"],"relationship_id":assigned["relationship_id"]}),
    ] {
        let error = call(
            &registry,
            &db,
            Caller::authenticated("unbound-account"),
            arguments,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("does not exist"), "{error}");
    }
    let after_events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM relationship_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let after_attestations: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM provenance_action_attestations WHERE operation='manage_relationships'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(
        (after_events, after_attestations),
        (before_events, before_attestations)
    );
}

#[tokio::test]
async fn all_five_governed_types_follow_their_public_worked_examples() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let registry = registry();
    let task = create_record(&db, json!({"type":"WorkItem","kind":"task","name":"Task"}))
        .await
        .unwrap();
    let other = create_record(
        &db,
        json!({"type":"Outcome","kind":"target","name":"Other"}),
    )
    .await
    .unwrap();
    let person = create_record(
        &db,
        json!({"type":"Entity","kind":"person","name":"Person"}),
    )
    .await
    .unwrap();
    bind_account(&db, &person, "person-account").await;
    for endpoint in [&task, &person] {
        replace_explicit_policy(
            &db,
            "relationship acceptance",
            endpoint,
            vec![AllowEntry::account("person-account", Capability::View)],
        )
        .await
        .unwrap();
    }

    for relationship_type in ["depends_on", "blocks"] {
        let asserted = call(
            &registry,
            &db,
            Caller::local(),
            json!({
                "action":"assert","relationship_type":relationship_type,
                "endpoints":[{"role":"subject","record_id":task},{"role":"object","record_id":other}],
                "idempotency_key":format!("{relationship_type}-acceptance")
            }),
        )
        .await
        .unwrap();
        let read = read_effective(&registry, &db, Caller::local(), &asserted).await;
        assert_eq!(read["effective"]["state"], "active");
        assert_eq!(read["effective"]["epistemic_state"], "supported");
        let error = call(
            &registry,
            &db,
            Caller::local(),
            json!({
                "action":"contest",
                "relationship_origin_db_id":asserted["relationship_origin_db_id"],
                "relationship_id":asserted["relationship_id"],
                "idempotency_key":format!("{relationship_type}-contest")
            }),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("contest is not governed for this relationship type"),
            "{relationship_type}: {error}"
        );
    }

    let relates_ab = call(
        &registry,
        &db,
        Caller::local(),
        json!({"action":"assert","relationship_type":"relates_to",
            "endpoints":[{"role":"participant","record_id":task},{"role":"participant","record_id":other}],
            "idempotency_key":"relates-ab"}),
    )
    .await
    .unwrap();
    let ordered_event_ids = relates_ab["output_events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| event["event_id"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    let ordered_types: Vec<String> = sqlx::query_scalar(
        "SELECT type FROM relationship_events WHERE id IN (?1,?2)
         ORDER BY CASE id WHEN ?1 THEN 0 ELSE 1 END",
    )
    .bind(&ordered_event_ids[0])
    .bind(&ordered_event_ids[1])
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(
        ordered_types,
        ["relationship.created.v1", "assertion.created.v1"],
        "genesis output commitment must preserve semantic order"
    );
    let attestation: (i64, String, String) = sqlx::query_as(
        "SELECT a.schema_version,json_extract(e.payload,'$.origin_admission.authoring_action_attestation_id'),
                a.output_event_set_digest
           FROM relationship_events e JOIN provenance_action_attestations a
             ON a.id=json_extract(e.payload,'$.origin_admission.authoring_action_attestation_id')
          WHERE e.id=?1",
    )
    .bind(&ordered_event_ids[1])
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(attestation.0, 2);
    assert_eq!(
        attestation.2,
        native_ce::derivation::digest_json(&json!(ordered_event_ids
            .iter()
            .map(|event_id| json!({"domain":"relationship","event_id":event_id}))
            .collect::<Vec<_>>())),
        "the v2 attestation must commit to the exact ordered domain-qualified output set"
    );
    let committed: Vec<(i64, String, String)> = sqlx::query_as(
        "SELECT ordinal,output_domain,output_event_id FROM provenance_action_outputs
          WHERE action_attestation_id=?1 ORDER BY ordinal",
    )
    .bind(&attestation.1)
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(
        committed,
        ordered_event_ids
            .iter()
            .enumerate()
            .map(|(ordinal, event_id)| (ordinal as i64, "relationship".into(), event_id.clone()))
            .collect::<Vec<_>>()
    );
    let why = call(
        &registry,
        &db,
        Caller::local(),
        json!({"action":"why","relationship_origin_db_id":relates_ab["relationship_origin_db_id"],"relationship_id":relates_ab["relationship_id"]}),
    )
    .await
    .unwrap();
    assert!(!why["authorized_action_provenance"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(why["assertions"][0]["local_admission"]["state"], "admitted");
    assert_eq!(
        why["assertions"][0]["origin_admission"]["schema_version"],
        1
    );
    let relates_ba = call(
        &registry,
        &db,
        Caller::local(),
        json!({"action":"assert","relationship_type":"relates_to",
            "endpoints":[{"role":"participant","record_id":other},{"role":"participant","record_id":task}],
            "idempotency_key":"relates-ba"}),
    )
    .await
    .unwrap();
    assert_eq!(relates_ab["relationship_id"], relates_ba["relationship_id"]);
    assert_ne!(relates_ab["assertion_id"], relates_ba["assertion_id"]);

    for relationship_type in ["assigned_to", "answerable_by"] {
        let asserted = call(
            &registry,
            &db,
            Caller::local(),
            json!({"action":"assert","relationship_type":relationship_type,
                "endpoints":[{"role":"subject","record_id":task},{"role":"object","record_id":person}],
                "idempotency_key":format!("{relationship_type}-support")}),
        )
        .await
        .unwrap();
        let contested = call(
            &registry,
            &db,
            Caller::authenticated("person-account"),
            json!({"action":"contest",
                "relationship_origin_db_id":asserted["relationship_origin_db_id"],
                "relationship_id":asserted["relationship_id"],
                "on_behalf_of":"semantic qualification only",
                "idempotency_key":format!("{relationship_type}-contest")}),
        )
        .await
        .unwrap();
        assert_ne!(asserted["assertion_id"], contested["assertion_id"]);
        let read = read_effective(&registry, &db, Caller::local(), &asserted).await;
        assert_eq!(read["effective"]["epistemic_state"], "contested");
        assert_eq!(
            read["effective"]["state"],
            if relationship_type == "assigned_to" {
                "unresolved"
            } else {
                "active"
            }
        );
        assert!(read["assertions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|assertion| { assertion["on_behalf_of"] == "semantic qualification only" }));
    }

    let rebuilt = native_ce::conformance::rebuild_and_diff_relationship(&db)
        .await
        .unwrap();
    assert!(rebuilt.equal, "{rebuilt:#?}");
    let report = native_ce::conformance::run_conformance(&db).await;
    assert!(report.ok, "{report:#?}");
}

#[tokio::test]
async fn forged_server_fields_partial_access_and_capability_non_effect_are_fail_closed() {
    let db = db().await;
    let registry = registry();
    let subject = create_record(
        &db,
        json!({"type":"WorkItem","kind":"task","name":"Subject"}),
    )
    .await
    .unwrap();
    let object = create_record(
        &db,
        json!({"type":"Outcome","kind":"target","name":"Object"}),
    )
    .await
    .unwrap();
    let evidence = create_record(
        &db,
        json!({"type":"Document","kind":"note","name":"Visible evidence"}),
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        "relationship acceptance",
        &subject,
        vec![AllowEntry::account("acct:editor", Capability::Edit)],
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        "relationship acceptance",
        &object,
        vec![AllowEntry::account("acct:editor", Capability::View)],
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        "relationship acceptance",
        &evidence,
        vec![AllowEntry::account("acct:editor", Capability::View)],
    )
    .await
    .unwrap();
    let before: (i64, i64) = (
        sqlx::query_scalar("SELECT COUNT(*) FROM relationship_events")
            .fetch_one(db.pool()).await.unwrap(),
        sqlx::query_scalar("SELECT COUNT(*) FROM provenance_action_attestations WHERE operation='manage_relationships'")
            .fetch_one(db.pool()).await.unwrap(),
    );
    for forged in [
        json!({"executor_ref":"agent:forged"}),
        json!({"delegation_ref":"person:forged"}),
        json!({"origin_admission":{"schema_version":1}}),
        json!({"authoring_action_attestation_id":"forged"}),
    ] {
        let mut arguments = json!({"action":"assert","relationship_type":"depends_on",
            "endpoints":[{"role":"subject","record_id":subject},{"role":"object","record_id":object}],
            "idempotency_key":"forged-field"});
        arguments
            .as_object_mut()
            .unwrap()
            .extend(forged.as_object().unwrap().clone());
        let error = call(
            &registry,
            &db,
            Caller::authenticated("acct:editor"),
            arguments,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("invalid arguments"), "{error}");
    }
    let after: (i64, i64) = (
        sqlx::query_scalar("SELECT COUNT(*) FROM relationship_events")
            .fetch_one(db.pool()).await.unwrap(),
        sqlx::query_scalar("SELECT COUNT(*) FROM provenance_action_attestations WHERE operation='manage_relationships'")
            .fetch_one(db.pool()).await.unwrap(),
    );
    assert_eq!(before, after);

    let principal = Principal::bound("acct:editor", false);
    let before_subject = effective_capability(&db, principal, &subject)
        .await
        .unwrap();
    let before_object = effective_capability(&db, principal, &object).await.unwrap();
    assert_eq!(before_subject, Capability::Edit);
    assert_eq!(before_object, Capability::View);
    let allowed = call(
        &registry,
        &db,
        Caller::authenticated("acct:editor"),
        json!({"action":"assert","relationship_type":"depends_on",
            "endpoints":[{"role":"subject","record_id":subject},{"role":"object","record_id":object}],
            "idempotency_key":"capability-non-effect"}),
    )
    .await
    .unwrap();
    assert_eq!(
        effective_capability(&db, principal, &subject)
            .await
            .unwrap(),
        before_subject
    );
    assert_eq!(
        effective_capability(&db, principal, &object).await.unwrap(),
        before_object
    );

    replace_explicit_policy(&db, "relationship acceptance", &object, vec![])
        .await
        .unwrap();
    let partial_before: (i64, i64) = (
        sqlx::query_scalar("SELECT COUNT(*) FROM relationship_events")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM provenance_action_attestations WHERE operation='manage_relationships'",
        )
        .fetch_one(db.pool())
        .await
        .unwrap(),
    );
    for arguments in [
        json!({"action":"assert","relationship_type":"depends_on",
            "endpoints":[{"role":"subject","record_id":subject},{"role":"object","record_id":object}],
            "idempotency_key":"partial-denial"}),
        json!({"action":"contest",
            "relationship_origin_db_id":allowed["relationship_origin_db_id"],
            "relationship_id":allowed["relationship_id"],
            "idempotency_key":"partial-contest"}),
        json!({"action":"add_evidence",
            "assertion_issuer_origin_db_id":allowed["assertion_issuer_origin_db_id"],
            "assertion_id":allowed["assertion_id"],"evidence_id":evidence,
            "reason":"must remain opaque","idempotency_key":"partial-evidence"}),
        json!({"action":"retract",
            "assertion_issuer_origin_db_id":allowed["assertion_issuer_origin_db_id"],
            "assertion_id":allowed["assertion_id"],"reason":"must remain opaque",
            "idempotency_key":"partial-retract"}),
        json!({"action":"read","relationship_origin_db_id":allowed["relationship_origin_db_id"],"relationship_id":allowed["relationship_id"]}),
        json!({"action":"why","relationship_origin_db_id":allowed["relationship_origin_db_id"],"relationship_id":allowed["relationship_id"]}),
    ] {
        let error = call(
            &registry,
            &db,
            Caller::authenticated("acct:editor"),
            arguments,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("does not exist"), "{error}");
    }
    let replay = call(
        &registry,
        &db,
        Caller::authenticated("acct:editor"),
        json!({"action":"assert","relationship_type":"depends_on",
            "endpoints":[{"role":"subject","record_id":subject},{"role":"object","record_id":object}],
            "idempotency_key":"capability-non-effect"}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(replay.contains("does not exist"), "{replay}");
    let partial_after: (i64, i64) = (
        sqlx::query_scalar("SELECT COUNT(*) FROM relationship_events")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM provenance_action_attestations WHERE operation='manage_relationships'",
        )
        .fetch_one(db.pool())
        .await
        .unwrap(),
    );
    assert_eq!(
        partial_after, partial_before,
        "opaque denials must not write"
    );
}

// ---------------------------------------------------------------------------
// `action: "find"` — the viewer-scoped read over governed relationships.
//
// Every test below fixes explicit policy on every record it creates, so
// "invisible" means a deliberate empty policy rather than an inherited default.
// ---------------------------------------------------------------------------

async fn task(db: &Db, name: &str, lifecycle: &str) -> String {
    create_record(
        db,
        json!({"type":"WorkItem","kind":"task","name":name,"lifecycle":lifecycle}),
    )
    .await
    .unwrap()
}

async fn person_record(db: &Db, name: &str) -> String {
    create_record(db, json!({"type":"Entity","kind":"person","name":name}))
        .await
        .unwrap()
}

async fn visible_to(db: &Db, record: &str, accounts: &[&str]) {
    replace_explicit_policy(
        db,
        "find acceptance",
        record,
        accounts
            .iter()
            .map(|account| AllowEntry::account(*account, Capability::View))
            .collect(),
    )
    .await
    .unwrap();
}

async fn hidden(db: &Db, record: &str) {
    replace_explicit_policy(db, "find acceptance", record, vec![])
        .await
        .unwrap();
}

async fn assign(registry: &ToolRegistry, db: &Db, task: &str, person: &str, key: &str) -> Value {
    call(
        registry,
        db,
        Caller::local(),
        json!({"action":"assert","relationship_type":"assigned_to",
            "endpoints":[{"role":"subject","record_id":task},{"role":"object","record_id":person}],
            "idempotency_key":key}),
    )
    .await
    .unwrap()
}

async fn find(registry: &ToolRegistry, db: &Db, caller: Caller, mut args: Value) -> Value {
    args.as_object_mut()
        .unwrap()
        .insert("action".into(), json!("find"));
    call(registry, db, caller, args).await.unwrap()
}

fn result_counterparts(response: &Value) -> Vec<String> {
    response["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|result| {
            result["counterpart"]["record_id"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect()
}

#[tokio::test]
async fn find_returns_counterpart_and_both_reduction_axes_inline() {
    let db = db().await;
    let registry = registry();
    let ship = task(&db, "Ship it", "open").await;
    let assignee = person_record(&db, "Assignee").await;
    let asserted = assign(&registry, &db, &ship, &assignee, "find-inline").await;

    let response = find(
        &registry,
        &db,
        Caller::local(),
        json!({"endpoint_record_id":assignee,"relationship_type":"assigned_to"}),
    )
    .await;

    assert_eq!(response["action"], "find");
    assert_eq!(response["endpoint"]["record_id"], json!(assignee));
    assert_eq!(response["endpoint"]["resolved_from"], "record_id");
    assert_eq!(response["returned"], 1);
    assert_eq!(response["has_more"], false);
    assert_eq!(response["scan_limit_reached"], false);
    let response_text = render::render("manage_relationships", &response).unwrap();
    assert!(
        response_text.contains(response["results"][0]["relationship_id"].as_str().unwrap())
            && response_text.contains(
                response["results"][0]["counterpart"]["record_id"]
                    .as_str()
                    .unwrap()
            ),
        "{response_text}"
    );
    let result = &response["results"][0];
    assert_eq!(
        result["relationship_id"], asserted["relationship_id"],
        "find must identify the governed relationship"
    );
    assert_eq!(
        result["relationship_origin_db_id"],
        asserted["relationship_origin_db_id"]
    );
    assert_eq!(result["relationship_type"], "assigned_to");
    assert_eq!(result["type_definition_id"], "assigned_to.v1");
    // The scoped person is the object; the counterpart is the task, returned
    // inline so a feed needs no N-times records_read.
    assert_eq!(result["endpoint"]["role"], "object");
    assert_eq!(result["counterpart"]["role"], "subject");
    assert_eq!(result["counterpart"]["record_id"], json!(ship));
    assert_eq!(result["counterpart"]["record_type"], "WorkItem");
    assert_eq!(result["counterpart"]["record_kind"], "task");
    assert_eq!(result["counterpart"]["name"], "Ship it");
    assert_eq!(result["counterpart"]["lifecycle"], "open");
    // Both axes, independently.
    assert_eq!(result["effective"]["state"], "active");
    assert_eq!(result["effective"]["epistemic_state"], "supported");
    assert_eq!(result["effective"]["support_count"], 1);
    assert_eq!(result["effective"]["contest_count"], 0);
    assert!(result["effective"]["recomputed_at"].is_string());
    let text = render::render("manage_relationships", &response).unwrap();
    assert!(text.starts_with("Relationship find."), "{text}");
    assert!(text.contains(&assignee), "{text}");
    assert!(
        text.contains(asserted["relationship_id"].as_str().unwrap()),
        "{text}"
    );
    assert!(text.contains(&ship), "{text}");
    assert!(text.contains("\"state\":\"active\""), "{text}");
    assert!(text.contains("\"epistemic_state\":\"supported\""), "{text}");
    assert!(
        text.contains("Page: 1 result(s) returned · offset 0 · limit 25 · has_more=false · scan_limit_reached=false."),
        "{text}"
    );
}

#[tokio::test]
async fn find_distinguishes_contested_from_supported() {
    let db = db().await;
    let registry = registry();
    let supported_task = task(&db, "Uncontested", "open").await;
    let contested_task = task(&db, "Contested", "open").await;
    let assignee = person_record(&db, "Assignee").await;
    bind_account(&db, &assignee, "assignee-account").await;
    visible_to(&db, &supported_task, &["assignee-account"]).await;
    visible_to(&db, &contested_task, &["assignee-account"]).await;
    visible_to(&db, &assignee, &["assignee-account"]).await;
    assign(&registry, &db, &supported_task, &assignee, "find-supported").await;
    let contested = assign(&registry, &db, &contested_task, &assignee, "find-contested").await;
    call(
        &registry,
        &db,
        Caller::authenticated("assignee-account"),
        json!({"action":"contest",
            "relationship_origin_db_id":contested["relationship_origin_db_id"],
            "relationship_id":contested["relationship_id"],
            "idempotency_key":"find-contest"}),
    )
    .await
    .unwrap();

    let all = find(
        &registry,
        &db,
        Caller::authenticated("assignee-account"),
        json!({"endpoint_record_id":assignee,"relationship_type":"assigned_to"}),
    )
    .await;
    assert_eq!(all["returned"], 2);
    let states = all["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|result| {
            (
                result["counterpart"]["record_id"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
                result["effective"]["state"].as_str().unwrap().to_owned(),
                result["effective"]["epistemic_state"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
            )
        })
        .collect::<Vec<_>>();
    // A contested assignment is never flattened into the supported shape.
    assert!(
        states.contains(&(supported_task.clone(), "active".into(), "supported".into())),
        "{states:?}"
    );
    assert!(
        states.contains(&(
            contested_task.clone(),
            "unresolved".into(),
            "contested".into()
        )),
        "{states:?}"
    );

    let only_contested = find(
        &registry,
        &db,
        Caller::authenticated("assignee-account"),
        json!({"endpoint_record_id":assignee,"epistemic_state":"contested"}),
    )
    .await;
    assert_eq!(result_counterparts(&only_contested), vec![contested_task]);
    let only_supported = find(
        &registry,
        &db,
        Caller::authenticated("assignee-account"),
        json!({"endpoint_record_id":assignee,"epistemic_state":"supported"}),
    )
    .await;
    assert_eq!(result_counterparts(&only_supported), vec![supported_task]);
}

#[tokio::test]
async fn find_omits_unviewable_counterparts_indistinguishably() {
    let db = db().await;
    let registry = registry();
    let visible_task = task(&db, "Visible", "open").await;
    let secret_task = task(&db, "Secret", "open").await;
    let assignee = person_record(&db, "Assignee").await;
    visible_to(&db, &visible_task, &["acct:viewer"]).await;
    visible_to(&db, &assignee, &["acct:viewer"]).await;
    hidden(&db, &secret_task).await;
    assign(&registry, &db, &visible_task, &assignee, "find-visible").await;

    let before = find(
        &registry,
        &db,
        Caller::authenticated("acct:viewer"),
        json!({"endpoint_record_id":assignee}),
    )
    .await;
    let sql_before = query_sql(
        &registry,
        &db,
        Caller::authenticated("acct:viewer"),
        "SELECT relationship_id,effective_state,epistemic_state,support_count,contest_count FROM effective_relationships ORDER BY relationship_id",
        json!([]),
    )
    .await;

    let secret = assign(&registry, &db, &secret_task, &assignee, "find-secret").await;
    let after = find(
        &registry,
        &db,
        Caller::authenticated("acct:viewer"),
        json!({"endpoint_record_id":assignee}),
    )
    .await;
    let sql_after = query_sql(
        &registry,
        &db,
        Caller::authenticated("acct:viewer"),
        "SELECT relationship_id,effective_state,epistemic_state,support_count,contest_count FROM effective_relationships ORDER BY relationship_id",
        json!([]),
    )
    .await;

    // Non-disclosure: the response is byte-identical before and after a
    // relationship the viewer may not see was created. No redacted row, no
    // changed count, no changed paging flag.
    assert_eq!(
        before, after,
        "an unviewable relationship must be absent, not redacted"
    );
    assert_eq!(
        sql_before, sql_after,
        "SQL must omit a relationship when any endpoint is hidden"
    );
    assert_eq!(result_counterparts(&after), vec![visible_task]);
    assert_eq!(after["returned"], 1);

    // ...and it is the same answer the caller gets for a relationship that
    // does not exist at all.
    let hidden_read = call(
        &registry,
        &db,
        Caller::authenticated("acct:viewer"),
        json!({"action":"read",
            "relationship_origin_db_id":secret["relationship_origin_db_id"],
            "relationship_id":secret["relationship_id"]}),
    )
    .await
    .unwrap_err()
    .to_string();
    let absent_read = call(
        &registry,
        &db,
        Caller::authenticated("acct:viewer"),
        json!({"action":"read",
            "relationship_origin_db_id":secret["relationship_origin_db_id"],
            "relationship_id":"00000000-0000-4000-8000-0000000000ff"}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(hidden_read, absent_read);

    // The local caller, who may see both, still sees both: visibility filtered
    // the viewer's result set, not the stored substrate.
    let local = find(
        &registry,
        &db,
        Caller::local(),
        json!({"endpoint_record_id":assignee}),
    )
    .await;
    assert_eq!(local["returned"], 2);
}

#[tokio::test]
async fn find_honours_evidence_the_viewer_cannot_see() {
    let db = db().await;
    let registry = registry();
    let assigned = task(&db, "Assigned", "open").await;
    let assignee = person_record(&db, "Assignee").await;
    let secret_evidence = create_record(
        &db,
        json!({"type":"Document","kind":"note","name":"Private rebuttal"}),
    )
    .await
    .unwrap();
    bind_account(&db, &assignee, "assignee-account").await;
    visible_to(&db, &assigned, &["assignee-account", "acct:viewer"]).await;
    visible_to(&db, &assignee, &["assignee-account", "acct:viewer"]).await;
    // Only the contesting party can see the evidence record.
    visible_to(&db, &secret_evidence, &["assignee-account"]).await;

    let asserted = assign(&registry, &db, &assigned, &assignee, "find-evidence").await;
    let contested = call(
        &registry,
        &db,
        Caller::authenticated("assignee-account"),
        json!({"action":"contest",
            "relationship_origin_db_id":asserted["relationship_origin_db_id"],
            "relationship_id":asserted["relationship_id"],
            "idempotency_key":"find-evidence-contest"}),
    )
    .await
    .unwrap();
    call(
        &registry,
        &db,
        Caller::authenticated("assignee-account"),
        json!({"action":"add_evidence",
            "assertion_issuer_origin_db_id":contested["assertion_issuer_origin_db_id"],
            "assertion_id":contested["assertion_id"],
            "evidence_id":secret_evidence,
            "reason":"evidence the viewer may not see",
            "idempotency_key":"find-evidence-add"}),
    )
    .await
    .unwrap();

    // Reducer correctness: the contest — and the evidence record behind it,
    // which this viewer cannot View — still determines what the viewer is
    // told about a relationship they CAN see. Hiding rows never edits the
    // reducer's conclusion about a shown row.
    let response = find(
        &registry,
        &db,
        Caller::authenticated("acct:viewer"),
        json!({"endpoint_record_id":assignee}),
    )
    .await;
    assert_eq!(response["returned"], 1);
    assert_eq!(
        response["results"][0]["effective"]["epistemic_state"],
        "contested"
    );
    assert_eq!(response["results"][0]["effective"]["state"], "unresolved");
    assert_eq!(response["results"][0]["effective"]["contest_count"], 1);

    // The ordinary-SQL relation has the same caller-relative result and a
    // deliberately narrower public surface than the projector. Hidden
    // assertion/evidence identifiers, reducer digests and watermarks cannot
    // become existence oracles through SELECT *.
    let projection = query_sql(
        &registry,
        &db,
        Caller::authenticated("acct:viewer"),
        "SELECT * FROM effective_relationships WHERE relationship_id=?1",
        json!([{"type":"text", "value": asserted["relationship_id"]}]),
    )
    .await;
    assert_eq!(projection["row_count"], 1);
    assert_eq!(projection["rows"][0]["epistemic_state"], "contested");
    assert_eq!(projection["rows"][0]["contest_count"], 1);
    for forbidden in [
        "assertion_id",
        "evidence_id",
        "admission_counts",
        "assertion_set_digest",
        "knowledge_watermark",
        "reducer_id",
        "reducer_version",
    ] {
        assert!(
            !projection["columns"]
                .as_array()
                .unwrap()
                .iter()
                .any(|column| column == forbidden),
            "{forbidden} leaked through effective_relationships: {projection}"
        );
    }
    assert!(!projection.to_string().contains(&secret_evidence));

    // Divergence worth knowing: `read` fails closed on the unviewable evidence
    // record, because it projects the assertion stream including evidence
    // references. `find` projects no evidence, so it stays available.
    let read = call(
        &registry,
        &db,
        Caller::authenticated("acct:viewer"),
        json!({"action":"read",
            "relationship_origin_db_id":asserted["relationship_origin_db_id"],
            "relationship_id":asserted["relationship_id"]}),
    )
    .await;
    assert!(read.is_err(), "read remains evidence-opaque: {read:?}");
}

#[tokio::test]
async fn find_filters_by_type_role_states_and_counterpart_lifecycle() {
    let db = db().await;
    let registry = registry();
    let open_task = task(&db, "Open work", "open").await;
    let done_task = task(&db, "Finished work", "completed").await;
    let answerable_task = task(&db, "Answerable work", "open").await;
    let assignee = person_record(&db, "Assignee").await;
    assign(&registry, &db, &open_task, &assignee, "filter-open").await;
    assign(&registry, &db, &done_task, &assignee, "filter-done").await;
    call(
        &registry,
        &db,
        Caller::local(),
        json!({"action":"assert","relationship_type":"answerable_by",
            "endpoints":[{"role":"subject","record_id":answerable_task},{"role":"object","record_id":assignee}],
            "idempotency_key":"filter-answerable"}),
    )
    .await
    .unwrap();

    let unfiltered = find(
        &registry,
        &db,
        Caller::local(),
        json!({"endpoint_record_id":assignee}),
    )
    .await;
    assert_eq!(unfiltered["returned"], 3);

    // type
    let assigned_only = find(
        &registry,
        &db,
        Caller::local(),
        json!({"endpoint_record_id":assignee,"relationship_type":"assigned_to"}),
    )
    .await;
    let mut counterparts = result_counterparts(&assigned_only);
    counterparts.sort();
    let mut expected = vec![open_task.clone(), done_task.clone()];
    expected.sort();
    assert_eq!(counterparts, expected);

    // lifecycle of the counterpart record: "OPEN tasks assigned to this
    // person" is one call.
    let open_assignments = find(
        &registry,
        &db,
        Caller::local(),
        json!({"endpoint_record_id":assignee,"relationship_type":"assigned_to","counterpart_lifecycle":"open"}),
    )
    .await;
    assert_eq!(
        result_counterparts(&open_assignments),
        vec![open_task.clone()]
    );

    // direction / role: the person is always the object, never the subject.
    let as_object = find(
        &registry,
        &db,
        Caller::local(),
        json!({"endpoint_record_id":assignee,"endpoint_role":"object"}),
    )
    .await;
    assert_eq!(as_object["returned"], 3);
    let as_subject = find(
        &registry,
        &db,
        Caller::local(),
        json!({"endpoint_record_id":assignee,"endpoint_role":"subject"}),
    )
    .await;
    assert_eq!(as_subject["returned"], 0);
    // ...and scoping the same substrate at the task shows the mirror role.
    let from_task = find(
        &registry,
        &db,
        Caller::local(),
        json!({"endpoint_record_id":open_task,"endpoint_role":"subject"}),
    )
    .await;
    assert_eq!(result_counterparts(&from_task), vec![assignee.clone()]);
    assert_eq!(from_task["results"][0]["endpoint"]["role"], "subject");
    assert_eq!(from_task["results"][0]["counterpart"]["role"], "object");

    // effective_state and epistemic_state
    let active = find(
        &registry,
        &db,
        Caller::local(),
        json!({"endpoint_record_id":assignee,"effective_state":"active"}),
    )
    .await;
    assert_eq!(active["returned"], 3);
    let inactive = find(
        &registry,
        &db,
        Caller::local(),
        json!({"endpoint_record_id":assignee,"effective_state":"inactive"}),
    )
    .await;
    assert_eq!(inactive["returned"], 0);
    let unsupported = find(
        &registry,
        &db,
        Caller::local(),
        json!({"endpoint_record_id":assignee,"epistemic_state":"unsupported"}),
    )
    .await;
    assert_eq!(unsupported["returned"], 0);
}

#[tokio::test]
async fn find_pages_deterministically() {
    let db = db().await;
    let registry = registry();
    let assignee = person_record(&db, "Assignee").await;
    let mut tasks = Vec::new();
    for index in 0..5 {
        let created = task(&db, &format!("Task {index}"), "open").await;
        assign(
            &registry,
            &db,
            &created,
            &assignee,
            &format!("page-{index}"),
        )
        .await;
        tasks.push(created);
    }

    let full = find(
        &registry,
        &db,
        Caller::local(),
        json!({"endpoint_record_id":assignee,"limit":10}),
    )
    .await;
    assert_eq!(full["action"], "find");
    assert_eq!(full["returned"], 5);
    assert_eq!(full["has_more"], false);
    let ordered = result_counterparts(&full);

    // Repeating the same call returns the same order: no undeclared ordering.
    let repeat = find(
        &registry,
        &db,
        Caller::local(),
        json!({"endpoint_record_id":assignee,"limit":10}),
    )
    .await;
    assert_eq!(full, repeat);

    // Paging walks that same total order exactly once.
    let mut paged = Vec::new();
    for offset in 0..5 {
        let page = find(
            &registry,
            &db,
            Caller::local(),
            json!({"endpoint_record_id":assignee,"limit":1,"offset":offset}),
        )
        .await;
        assert_eq!(page["action"], "find");
        assert_eq!(page["returned"], 1);
        assert_eq!(page["limit"], 1);
        assert_eq!(page["offset"], offset);
        assert_eq!(page["has_more"], offset < 4);
        let text = render::render("manage_relationships", &page).unwrap();
        assert!(
            text.contains(&format!(
                "Page: 1 result(s) returned · offset {offset} · limit 1 · has_more={} · scan_limit_reached=false.",
                offset < 4
            )),
            "{text}"
        );
        assert!(
            text.contains(page["results"][0]["relationship_id"].as_str().unwrap()),
            "{text}"
        );
        if offset < 4 {
            assert!(
                text.contains(&format!("same filters and offset {}", offset + 1)),
                "{text}"
            );
        }
        paged.extend(result_counterparts(&page));
    }
    assert_eq!(paged, ordered);

    let past_the_end = find(
        &registry,
        &db,
        Caller::local(),
        json!({"endpoint_record_id":assignee,"limit":1,"offset":5}),
    )
    .await;
    assert_eq!(past_the_end["action"], "find");
    assert_eq!(past_the_end["returned"], 0);
    assert_eq!(past_the_end["has_more"], false);
    let past_text = render::render("manage_relationships", &past_the_end).unwrap();
    assert!(
        past_text.contains("Page: 0 result(s) returned · offset 5 · limit 1 · has_more=false · scan_limit_reached=false."),
        "{past_text}"
    );

    // Ordering is occurred_at DESC, so the most recent assignment leads.
    let occurred = full["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|result| result["occurred_at"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    let mut sorted = occurred.clone();
    sorted.sort();
    sorted.reverse();
    assert_eq!(
        occurred, sorted,
        "results must be ordered by occurred_at DESC"
    );
}

#[tokio::test]
async fn find_reports_scan_truncation_honestly() {
    let db = db().await;
    let registry = registry();
    let assignee = person_record(&db, "Assignee").await;
    visible_to(&db, &assignee, &["acct:viewer"]).await;
    for index in 0..12 {
        let created = task(&db, &format!("Secret {index}"), "open").await;
        hidden(&db, &created).await;
        assign(
            &registry,
            &db,
            &created,
            &assignee,
            &format!("scan-{index}"),
        )
        .await;
    }

    // limit 1 scans (offset + limit + 1) * 4 = 8 candidates, every one of them
    // invisible. The caller is told the page is empty AND that the scan was
    // truncated; `has_more` stays false because nothing beyond the cap was
    // examined, so claiming more would be a guess.
    let truncated = find(
        &registry,
        &db,
        Caller::authenticated("acct:viewer"),
        json!({"endpoint_record_id":assignee,"limit":1}),
    )
    .await;
    assert_eq!(truncated["action"], "find");
    assert_eq!(truncated["returned"], 0);
    assert_eq!(truncated["has_more"], false);
    assert_eq!(
        truncated["scan_limit_reached"], true,
        "a page shortened by the candidate cap must say so"
    );
    let truncated_text = render::render("manage_relationships", &truncated).unwrap();
    assert!(
        truncated_text.contains("has_more=false · scan_limit_reached=true"),
        "{truncated_text}"
    );
    assert!(
        truncated_text.contains("bounded candidate scan reached its limit"),
        "{truncated_text}"
    );

    // A wide enough page examines all 12 candidates and reports no truncation.
    let complete = find(
        &registry,
        &db,
        Caller::authenticated("acct:viewer"),
        json!({"endpoint_record_id":assignee,"limit":200}),
    )
    .await;
    assert_eq!(complete["action"], "find");
    assert_eq!(complete["returned"], 0);
    assert_eq!(complete["scan_limit_reached"], false);
    let complete_text = render::render("manage_relationships", &complete).unwrap();
    assert!(
        complete_text.contains("has_more=false · scan_limit_reached=false"),
        "{complete_text}"
    );
    assert!(
        !complete_text.contains("bounded candidate scan reached its limit"),
        "{complete_text}"
    );
}

#[tokio::test]
async fn find_omits_relationships_whose_counterpart_endpoint_is_unbound() {
    let db = db().await;
    let registry = registry();
    let bound_task = task(&db, "Bound", "open").await;
    let unbound_task = task(&db, "Unbound", "open").await;
    let assignee = person_record(&db, "Assignee").await;
    assign(&registry, &db, &bound_task, &assignee, "unbound-bound").await;
    let unbound = assign(&registry, &db, &unbound_task, &assignee, "unbound-endpoint").await;
    // Simulate an endpoint that never resolved to a local record — the shape a
    // federated or unbound person endpoint takes. Written directly because no
    // local write path can produce it; this fixture therefore does not run
    // rebuild conformance.
    sqlx::query(
        "UPDATE relationship_endpoints SET record_id=NULL
          WHERE relationship_origin_db_id=? AND relationship_id=? AND role='subject'",
    )
    .bind(unbound["relationship_origin_db_id"].as_str().unwrap())
    .bind(unbound["relationship_id"].as_str().unwrap())
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();

    let response = find(
        &registry,
        &db,
        Caller::local(),
        json!({"endpoint_record_id":assignee}),
    )
    .await;
    // DELIBERATE: an endpoint with no local record_id is not shown, matching
    // `load_endpoints_and_authorize_in`, which treats the same shape as opaque.
    assert_eq!(result_counterparts(&response), vec![bound_task]);
    let opaque = call(
        &registry,
        &db,
        Caller::authenticated("acct:viewer"),
        json!({"action":"read",
            "relationship_origin_db_id":unbound["relationship_origin_db_id"],
            "relationship_id":unbound["relationship_id"]}),
    )
    .await;
    assert!(opaque.is_err(), "read is already opaque for this shape");
}

#[tokio::test]
async fn find_resolves_the_current_person_endpoint() {
    let db = db().await;
    let registry = registry();
    let assigned = task(&db, "Mine", "open").await;
    let assignee = person_record(&db, "Assignee").await;
    bind_account(&db, &assignee, "assignee-account").await;
    visible_to(&db, &assigned, &["assignee-account"]).await;
    visible_to(&db, &assignee, &["assignee-account"]).await;
    assign(&registry, &db, &assigned, &assignee, "current-person").await;

    let response = find(
        &registry,
        &db,
        Caller::authenticated("assignee-account"),
        json!({"endpoint_current_person":true,"relationship_type":"assigned_to","counterpart_lifecycle":"open"}),
    )
    .await;
    assert_eq!(response["endpoint"]["record_id"], json!(assignee));
    assert_eq!(response["endpoint"]["resolved_from"], "current_person");
    assert_eq!(result_counterparts(&response), vec![assigned]);

    let unbound_caller = call(
        &registry,
        &db,
        Caller::authenticated("acct:nobody"),
        json!({"action":"find","endpoint_current_person":true}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        unbound_caller.contains("requires a person bound"),
        "{unbound_caller}"
    );
}

#[tokio::test]
async fn find_rejects_malformed_scope_and_unauthorized_endpoints() {
    let db = db().await;
    let registry = registry();
    let secret = person_record(&db, "Secret person").await;
    hidden(&db, &secret).await;

    for arguments in [
        json!({"action":"find"}),
        json!({"action":"find","endpoint_record_id":"whatever","endpoint_current_person":true}),
    ] {
        let error = call(&registry, &db, Caller::local(), arguments)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("exactly one of"), "{error}");
    }

    // An unviewable scope record is the same answer as an absent one.
    let unviewable = call(
        &registry,
        &db,
        Caller::authenticated("acct:viewer"),
        json!({"action":"find","endpoint_record_id":secret}),
    )
    .await
    .unwrap_err()
    .to_string();
    let absent = call(
        &registry,
        &db,
        Caller::authenticated("acct:viewer"),
        json!({"action":"find","endpoint_record_id":"rec_does_not_exist"}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(unviewable.contains("does not exist"), "{unviewable}");
    assert!(absent.contains("does not exist"), "{absent}");

    // Bounds and vocabularies. The registry dispatches through serde, not the
    // advertised JSON Schema, so every constraint the schema publishes is also
    // enforced here in Rust — a direct registry or HTTP caller cannot bypass it.
    for (arguments, expected) in [
        (
            json!({"action":"find","endpoint_record_id":"x","limit":0}),
            "must be between 1 and 200",
        ),
        (
            json!({"action":"find","endpoint_record_id":"x","limit":201}),
            "must be between 1 and 200",
        ),
        (
            json!({"action":"find","endpoint_record_id":"x","offset":-1}),
            "must be a non-negative integer",
        ),
        (
            json!({"action":"find","endpoint_record_id":"x","relationship_type":"legacy_link.v1"}),
            "not governed",
        ),
        (
            json!({"action":"find","endpoint_record_id":"x","effective_state":"invented"}),
            "effective_state must be one of",
        ),
        (
            json!({"action":"find","endpoint_record_id":"x","epistemic_state":"invented"}),
            "epistemic_state must be one of",
        ),
        (
            json!({"action":"find","endpoint_record_id":"x","unknown_filter":true}),
            "invalid arguments",
        ),
    ] {
        let error = call(&registry, &db, Caller::local(), arguments.clone())
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains(expected), "{arguments} -> {error}");
    }

    // The candidate scan stays bounded even for schema-legal paging.
    let unbounded = call(
        &registry,
        &db,
        Caller::local(),
        json!({"action":"find","endpoint_record_id":"x","limit":200,"offset":1900}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(unbounded.contains("must not exceed"), "{unbounded}");
}

#[tokio::test]
async fn find_access_path_uses_indexes_and_scans_nothing() {
    let db = db().await;
    let registry = registry();
    let assigned = task(&db, "Indexed", "open").await;
    let assignee = person_record(&db, "Assignee").await;
    assign(&registry, &db, &assigned, &assignee, "index-plan").await;
    // Mirrors the handler's join shape. `find` is always endpoint-anchored, so
    // the endpoint index drives it and every other table is reached by primary
    // key; nothing here is a table scan and nothing replays assertion streams.
    use sqlx::Row as _;
    let plan_rows = sqlx::query(
        "EXPLAIN QUERY PLAN
         SELECT eff.effective_state
           FROM relationship_endpoints scope_ep
           JOIN relationships r
             ON r.relationship_origin_db_id = scope_ep.relationship_origin_db_id
            AND r.relationship_id = scope_ep.relationship_id
           JOIN effective_relationships eff
             ON eff.relationship_origin_db_id = r.relationship_origin_db_id
            AND eff.relationship_id = r.relationship_id
          WHERE scope_ep.record_id = ? AND r.status='active'
            AND eff.effective_state='active' AND eff.epistemic_state='supported'",
    )
    .bind(&assignee)
    .fetch_all(db.pool())
    .await
    .unwrap();
    let plan = plan_rows
        .iter()
        .map(|row| row.try_get::<String, _>("detail").unwrap())
        .collect::<Vec<_>>()
        .join(" | ");
    assert!(
        plan.contains("idx_relationship_endpoints_record"),
        "endpoint scope must drive the query: {plan}"
    );
    assert!(
        plan.contains("sqlite_autoindex_effective_relationships_1"),
        "the effective projection must be reached by primary key: {plan}"
    );
    assert!(
        !plan.contains("SCAN "),
        "no step of the find access path may be a table scan: {plan}"
    );
}
