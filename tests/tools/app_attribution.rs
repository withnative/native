//! App contract v2 attribution through the production registry (task
//! `50f5aca`, plan `0350106` I5).
//!
//! A call carrying a host-asserted app keeps exactly the user's authority,
//! records the app beside every action attestation it issues, and is
//! selectable by app through `query_sql`. A claim naming an install that is
//! not a current adopted v2 install of the caller's own account is refused
//! before dispatch, and the provisional refusal list holds for app calls.
//!
//! Every install here is a real one made through `manage_alpha_tabs`, with
//! I3's v2 declaration (`{contract: "native.app.v2", needs: [], effects: []}`)
//! or an ordinary v1 declaration.

use native_ce::mcp::app_attribution::AppAttribution;
use native_ce::mcp::{Caller, ToolRegistry};
use native_ce::Db;
use serde_json::{json, Value};

use crate::alpha_tabs::{
    adopt_fixture_artifact, adopted_package_with_declaration_as, adopted_with_declaration,
    adopted_with_declaration_as, call_as, configure_preview_launch, install_with_declaration,
    v2_declaration, ALICE, ARTIFACT_A, BEA,
};

/// The package I3's `adopted_with_declaration` installs for Alice.
const PACKAGE: &str = "agent.search";
const ALICE_PERSON: &str = "a1d00000-0000-4000-8000-0000000000a1";
const BEA_PERSON: &str = "a1d00000-0000-4000-8000-0000000000b1";

async fn fixture() -> (Db, ToolRegistry) {
    configure_preview_launch();
    let db = native_ce::create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    native_ce::mcp::register_surface_tools(&mut registry).unwrap();
    for (person, account) in [(ALICE_PERSON, ALICE), (BEA_PERSON, BEA)] {
        registry
            .call(
                db.clone(),
                Caller::local(),
                "create_record",
                json!({
                    "id": person, "type": "Entity", "kind": "person", "name": account,
                    "reason": "Person fixture for app-attributed messaging."
                }),
            )
            .await
            .unwrap();
        let principal = format!("native/{account}");
        for (system, identifier) in [
            ("native-principal", principal.as_str()),
            ("account", account),
        ] {
            sqlx::query(
                "INSERT INTO bindings(record_id,system,identifier,is_canonical) VALUES(?,?,?,1)",
            )
            .bind(person)
            .bind(system)
            .bind(identifier)
            .execute(&crate::common::fixture_write_pool(&db).await)
            .await
            .unwrap();
        }
    }
    (db, registry)
}

/// A real adopted v2 install for Alice: install, preview and adopt with
/// I3's v2 declaration. Returns the adopted install generation, the event id
/// the host reads from `manage_alpha_tabs list` and sends.
async fn adopted_v2(registry: &ToolRegistry, db: &Db) -> String {
    adopted_with_declaration(registry, db, v2_declaration()).await
}

fn app(install_event_id: &str) -> AppAttribution {
    AppAttribution::new(PACKAGE, "0.1.0", install_event_id).unwrap()
}

fn send_args(key: &str) -> Value {
    json!({
        "action": "send",
        "body": "sent from an app",
        "origin": {"type": "direct", "participant_ids": [ALICE_PERSON, BEA_PERSON]},
        "addressed_to": [BEA_PERSON],
        "expectation": "none",
        "idempotency_key": key,
        "reason": "Send a message the app attribution tests select by app."
    })
}

async fn attribution_rows(db: &Db) -> Vec<(String, String, String, String, String)> {
    sqlx::query_as(
        "SELECT e.record_id, a.package, a.version, a.install_event_id, a.assertion
           FROM provenance_action_app_attributions a
           JOIN provenance_action_outputs o ON o.action_attestation_id = a.action_attestation_id
           JOIN content_events e ON e.id = o.output_event_id AND o.output_domain = 'content'
          ORDER BY e.seq",
    )
    .fetch_all(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap()
}

#[tokio::test]
async fn app_attributed_send_records_the_app_and_is_selectable_by_app() {
    let (db, registry) = fixture().await;
    let install = adopted_v2(&registry, &db).await;

    let sent = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE).with_host_asserted_app(app(&install)),
        "manage_messages",
        send_args("app-send-1"),
    )
    .await
    .unwrap();
    let message_id = sent["id"].as_str().unwrap().to_string();

    // A direct (unattributed) send by the same user records no app.
    let direct = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_messages",
        send_args("direct-send-1"),
    )
    .await
    .unwrap();
    let direct_id = direct["id"].as_str().unwrap().to_string();

    let rows = attribution_rows(&db).await;
    assert!(!rows.is_empty(), "the app's send recorded an attribution");
    for (record_id, package, version, install_event_id, assertion) in &rows {
        assert_eq!(
            record_id, &message_id,
            "only the app's events are attributed"
        );
        assert_eq!(package, PACKAGE);
        assert_eq!(version, "0.1.0");
        assert_eq!(install_event_id, &install);
        assert_eq!(assertion, "host");
    }

    // The event keeps the user as actor: the app acts with their authority.
    let actor: String = sqlx::query_scalar(
        "SELECT actor FROM content_events WHERE record_id = ? ORDER BY seq LIMIT 1",
    )
    .bind(&message_id)
    .fetch_one(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    assert_eq!(actor, ALICE);

    // "Writes by app" is a query.
    let by_app = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "query_sql",
        json!({"sql": format!(
            "SELECT e.record_id, a.package, a.version, a.install_event_id, a.assertion \
               FROM content_event_apps a JOIN content_events e ON e.id = a.event_id \
              WHERE a.package = '{PACKAGE}' ORDER BY e.local_seq"
        )}),
    )
    .await
    .unwrap();
    assert_eq!(by_app["row_count"], json!(rows.len()), "{by_app:#}");
    let rendered = by_app.to_string();
    assert!(rendered.contains(&message_id), "{by_app:#}");
    assert!(rendered.contains(&install), "{by_app:#}");
    assert!(!rendered.contains(&direct_id), "{by_app:#}");
}

async fn attempt(
    registry: &ToolRegistry,
    db: &Db,
    caller: Caller,
    key: String,
) -> native_ce::Result<Value> {
    call_as(registry, db, caller, "manage_messages", send_args(&key)).await
}

#[tokio::test]
async fn unknown_foreign_unadopted_and_v1_installs_are_refused() {
    let refused = |error: native_ce::Error| {
        let message = error.to_string();
        assert!(message.contains("app_install_unknown"), "{message}");
    };

    // An adopted v1 install is not an app-contract v2 install.
    let (v1_db, v1_registry) = fixture().await;
    let v1_install = adopted_with_declaration(
        &v1_registry,
        &v1_db,
        json!({"needs": ["attention.query.v1"], "effects": []}),
    )
    .await;
    refused(
        attempt(
            &v1_registry,
            &v1_db,
            Caller::authenticated(ALICE).with_host_asserted_app(app(&v1_install)),
            "v1-send".into(),
        )
        .await
        .unwrap_err(),
    );

    // A v2 install that was never adopted (caller-asserted) is refused.
    let (unadopted_db, unadopted_registry) = fixture().await;
    configure_preview_launch();
    adopt_fixture_artifact(&unadopted_registry, &unadopted_db).await;
    let installed = install_with_declaration(&unadopted_registry, &unadopted_db, v2_declaration())
        .await
        .unwrap();
    assert_eq!(installed["install"]["adoption"], "caller_asserted");
    let unadopted = installed["install"]["event_id"]
        .as_str()
        .unwrap()
        .to_string();
    refused(
        attempt(
            &unadopted_registry,
            &unadopted_db,
            Caller::authenticated(ALICE).with_host_asserted_app(app(&unadopted)),
            "unadopted-send".into(),
        )
        .await
        .unwrap_err(),
    );

    let (db, registry) = fixture().await;
    let install = adopted_v2(&registry, &db).await;
    for (caller, label) in [
        // Unknown install generation.
        (
            Caller::authenticated(ALICE).with_host_asserted_app(app("no-such-install")),
            "unknown",
        ),
        // Wrong version of a real install.
        (
            Caller::authenticated(ALICE)
                .with_host_asserted_app(AppAttribution::new(PACKAGE, "9.9.9", &install).unwrap()),
            "version",
        ),
        // Another account's install: Bea cannot borrow Alice's app.
        (
            Caller::authenticated(BEA).with_host_asserted_app(app(&install)),
            "foreign",
        ),
    ] {
        refused(
            attempt(&registry, &db, caller, format!("refused-{label}"))
                .await
                .unwrap_err(),
        );
    }

    for db in [&v1_db, &unadopted_db] {
        assert!(attribution_rows(db).await.is_empty());
    }
    assert!(attribution_rows(&db).await.is_empty());
    let messages: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records WHERE type = 'Message'")
        .fetch_one(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    assert_eq!(messages, 0, "no refused call wrote a message");
}

#[tokio::test]
async fn refused_operations_are_refused_when_app_attributed() {
    let (db, registry) = fixture().await;
    let install = adopted_v2(&registry, &db).await;
    let app_caller = || Caller::authenticated(ALICE).with_host_asserted_app(app(&install));

    for (tool, args) in [
        ("manage_alpha_tabs", json!({"action": "list"})),
        (
            "attach_from_url",
            json!({"record_id": ARTIFACT_A, "url": "https://example.com/?leak=1"}),
        ),
        ("close_run", json!({})),
    ] {
        let message = call_as(&registry, &db, app_caller(), tool, args.clone())
            .await
            .expect_err(&format!("{tool} {args} must be refused for an app"))
            .to_string();
        assert!(
            message.contains("app_operation_refused"),
            "{tool}: {message}"
        );
    }

    // `manage_memberships` is hosted-only, so this surface registry does not
    // carry it; its per-action entries are covered by the module's unit test
    // and the hosted boundary test.

    // The same refused tool is ordinary for the user directly.
    call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "manage_alpha_tabs",
        json!({"action": "list"}),
    )
    .await
    .unwrap();
}

async fn app_row_count(db: &Db) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM provenance_action_app_attributions")
        .fetch_one(&crate::common::fixture_write_pool(db).await)
        .await
        .unwrap()
}

#[tokio::test]
async fn app_batch_write_attributes_every_attestation_it_issues() {
    let (db, registry) = fixture().await;
    let install = adopted_v2(&registry, &db).await;
    let mut ids = Vec::new();
    for name in ["batch-a", "batch-b", "batch-c"] {
        let created = call_as(
            &registry,
            &db,
            Caller::authenticated(ALICE),
            "create_record",
            json!({"type": "Document", "kind": "note", "name": name,
                   "reason": "Note the app's batch will update."}),
        )
        .await
        .unwrap();
        ids.push(created["id"].as_str().unwrap().to_string());
    }
    let before = app_row_count(&db).await;
    let items: Vec<Value> = ids
        .iter()
        .map(|id| json!({"op": "update", "id": id, "summary": "updated by the app"}))
        .collect();
    let receipt = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE).with_host_asserted_app(app(&install)),
        "batch_write",
        json!({"reason": "App batch update.", "items": items, "idempotency_key": "app-batch-1"}),
    )
    .await
    .unwrap();
    assert_eq!(receipt["changed"], 3, "{receipt}");

    // Every attestation the batch issued (per item, plus the keyed anchor)
    // carries exactly one app row, and none is left unattributed.
    let pool = crate::common::fixture_write_pool(&db).await;
    let (attestations, attributed): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COUNT(app.action_attestation_id)
           FROM provenance_action_attestations a
           LEFT JOIN provenance_action_app_attributions app ON app.action_attestation_id = a.id
          WHERE a.operation = 'batch_write'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(attestations >= 3, "{attestations}");
    assert_eq!(attributed, attestations);
    assert_eq!(app_row_count(&db).await - before, attestations);

    // The engine selector for undo reaches an output for every updated record.
    let outputs = native_ce::mcp::app_attribution::app_action_outputs(&db, ALICE, PACKAGE)
        .await
        .unwrap();
    let mut touched = std::collections::BTreeSet::new();
    for output in outputs
        .iter()
        .filter(|output| output.output_domain == "content")
    {
        let record: String =
            sqlx::query_scalar("SELECT record_id FROM content_events WHERE id = ?")
                .bind(&output.output_event_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        touched.insert(record);
    }
    for id in &ids {
        assert!(touched.contains(id), "{id} has no app-attributed output");
    }
    assert!(outputs
        .iter()
        .all(|output| output.install_event_id == install));
}

#[tokio::test]
async fn app_idempotent_replay_records_no_second_attribution() {
    let (db, registry) = fixture().await;
    let install = adopted_v2(&registry, &db).await;
    let app_caller = || Caller::authenticated(ALICE).with_host_asserted_app(app(&install));
    let first = call_as(
        &registry,
        &db,
        app_caller(),
        "manage_messages",
        send_args("app-replay"),
    )
    .await
    .unwrap();
    let rows = attribution_rows(&db).await;
    assert!(!rows.is_empty());
    let replay = call_as(
        &registry,
        &db,
        app_caller(),
        "manage_messages",
        send_args("app-replay"),
    )
    .await
    .unwrap();
    assert_eq!(
        replay["id"], first["id"],
        "the replay converges on the same message"
    );
    assert_eq!(
        attribution_rows(&db).await,
        rows,
        "the replay adds no app row"
    );
}

#[tokio::test]
async fn undo_selector_is_scoped_to_the_account_not_just_the_package() {
    // Alice and Bea each adopt their own v2 install of the same package and
    // each send through it; the selector returns only the asked account's.
    let (db, registry) = fixture().await;
    let alice_install = adopted_v2(&registry, &db).await;
    let bea_install = adopted_with_declaration_as(&registry, &db, BEA, v2_declaration()).await;
    assert_ne!(alice_install, bea_install);

    let alice_sent = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE).with_host_asserted_app(app(&alice_install)),
        "manage_messages",
        send_args("alice-app-send"),
    )
    .await
    .unwrap();
    let mut bea_args = send_args("bea-app-send");
    bea_args["addressed_to"] = json!([ALICE_PERSON]);
    let bea_sent = call_as(
        &registry,
        &db,
        Caller::authenticated(BEA).with_host_asserted_app(app(&bea_install)),
        "manage_messages",
        bea_args,
    )
    .await
    .unwrap();

    let pool = crate::common::fixture_write_pool(&db).await;
    let records_of = |outputs: Vec<native_ce::mcp::app_attribution::AppActionOutput>| {
        let pool = pool.clone();
        async move {
            let mut records = std::collections::BTreeSet::new();
            for output in outputs
                .iter()
                .filter(|output| output.output_domain == "content")
            {
                let record: String =
                    sqlx::query_scalar("SELECT record_id FROM content_events WHERE id = ?")
                        .bind(&output.output_event_id)
                        .fetch_one(&pool)
                        .await
                        .unwrap();
                records.insert(record);
            }
            (outputs, records)
        }
    };
    let (alice_outputs, alice_records) = records_of(
        native_ce::mcp::app_attribution::app_action_outputs(&db, ALICE, PACKAGE)
            .await
            .unwrap(),
    )
    .await;
    let (bea_outputs, bea_records) = records_of(
        native_ce::mcp::app_attribution::app_action_outputs(&db, BEA, PACKAGE)
            .await
            .unwrap(),
    )
    .await;
    let alice_message = alice_sent["id"].as_str().unwrap().to_string();
    let bea_message = bea_sent["id"].as_str().unwrap().to_string();
    assert!(alice_records.contains(&alice_message) && !alice_records.contains(&bea_message));
    assert!(bea_records.contains(&bea_message) && !bea_records.contains(&alice_message));
    assert!(alice_outputs
        .iter()
        .all(|o| o.install_event_id == alice_install));
    assert!(bea_outputs
        .iter()
        .all(|o| o.install_event_id == bea_install));
    assert!(
        native_ce::mcp::app_attribution::app_action_outputs(&db, "carol", PACKAGE)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn adopted_v1_store_app_can_query_records_as_its_user() {
    let (db, registry) = fixture().await;
    let install = adopted_v2(&registry, &db).await;
    let args =
        json!({"steps":[{"step":"filter","types":["Document"]}],"order":"name_asc","limit":500});
    let direct = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "query_record",
        args.clone(),
    )
    .await
    .unwrap();
    let attributed = call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE).with_host_asserted_app(app(&install)),
        "query_record",
        args,
    )
    .await
    .unwrap();
    assert_eq!(attributed["records"], direct["records"]);
    assert!(
        attribution_rows(&db).await.is_empty(),
        "reads do not create write attributions"
    );
    db.close().await;
}

// Snapshot effects and immutable command evidence around a rejected retry.
async fn keyed_context_snapshot(db: &Db) -> Vec<String> {
    let pool = crate::common::fixture_write_pool(db).await;
    let mut result = Vec::new();
    for query in [
        "SELECT json_group_array(json_array(id,seq,record_id,type,payload,act)) FROM (SELECT * FROM content_events ORDER BY seq)",
        "SELECT json_group_array(json_array(id,seq,type,payload,act)) FROM (SELECT * FROM relationship_events ORDER BY seq)",
        "SELECT json_group_array(json_array(id,principal,operation,action_digest,intent_digest,command_identity_digest,output_event_set_digest)) FROM (SELECT * FROM provenance_action_attestations ORDER BY id)",
        "SELECT json_group_array(json_array(attestation_id,issuer_origin_database_id,principal,operation,command_identity_digest)) FROM (SELECT * FROM provenance_local_attestation_authority ORDER BY attestation_id)",
        "SELECT json_group_array(json_array(action_attestation_id,package,version,install_event_id,assertion)) FROM (SELECT * FROM provenance_action_app_attributions ORDER BY action_attestation_id)",
        "SELECT json_group_array(json_array(event_id,parent_event_id)) FROM (SELECT * FROM content_event_causal_frontier ORDER BY event_id,parent_event_id)",
        "SELECT json_group_array(json_array(next_act)) FROM act_state",
        "SELECT json_group_array(event_id) FROM (SELECT event_id FROM content_event_heads ORDER BY event_id)",
        "SELECT json_group_array(json_array(id,name,body,updated_at)) FROM (SELECT * FROM records ORDER BY id)",
    ] {
        result.push(sqlx::query_scalar(query).fetch_one(&pool).await.unwrap());
    }
    result
}

async fn assert_keyed_context_isolation(operation: &str) {
    let (db, registry) = fixture().await;
    let install = adopted_v2(&registry, &db).await;
    let other =
        adopted_package_with_declaration_as(&registry, &db, ALICE, "agent.other", v2_declaration())
            .await;
    let contexts = [
        native_ce::provenance::CommandAppContext::host_app(&app(&install)).unwrap(),
        native_ce::provenance::CommandAppContext::host_app(
            &AppAttribution::new("agent.other", "0.1.0", &other).unwrap(),
        )
        .unwrap(),
        native_ce::provenance::CommandAppContext::no_app(),
    ];
    let callers = [
        Caller::authenticated(ALICE).with_host_asserted_app(app(&install)),
        Caller::authenticated(ALICE)
            .with_host_asserted_app(AppAttribution::new("agent.other", "0.1.0", other).unwrap()),
        Caller::authenticated(ALICE),
    ];
    for (index, owner) in callers.iter().enumerate() {
        let id = uuid::Uuid::new_v4().to_string();
        if operation == "update_record" {
            call_as(&registry, &db, Caller::authenticated(ALICE), "create_record",
                json!({"id":id,"type":"Document","kind":"note","name":"append target","body":"original","reason":"fixture"})).await.unwrap();
        }
        let args = if operation == "create_record" {
            json!({"id":id,"type":"Document","kind":"note","name":"keyed context","body":"saved JSON","reason":"context proof","idempotency_key":format!("context-{operation}-{index}"),"response_mode":"summary"})
        } else {
            json!({"id":id,"body_append":" acknowledged append","reason":"context proof","idempotency_key":format!("context-{operation}-{index}"),"response_mode":"summary"})
        };
        let first = call_as(&registry, &db, owner.clone(), operation, args.clone())
            .await
            .unwrap();
        let origin = native_ce::identity::database_id(&db).await.unwrap();
        let proof = native_ce::provenance::reconcile_deferred_command_with_context(
            &db,
            &origin,
            ALICE,
            operation,
            &args,
            None,
            &contexts[index],
        )
        .await
        .unwrap()
        .expect("matching local commit");
        assert!(first["action_attestation_ids"]
            .as_array()
            .unwrap()
            .contains(&json!(proof)));
        let saved = keyed_context_snapshot(&db).await;
        let matching = call_as(&registry, &db, owner.clone(), operation, args.clone())
            .await
            .unwrap();
        assert_eq!(matching, first, "same exact context retains its receipt");
        assert_eq!(keyed_context_snapshot(&db).await, saved);
        for (candidate, caller) in callers.iter().enumerate() {
            if candidate == index {
                continue;
            }
            let refused = native_ce::provenance::reconcile_deferred_command_with_context(
                &db,
                &origin,
                ALICE,
                operation,
                &args,
                None,
                &contexts[candidate],
            )
            .await
            .unwrap_err();
            assert!(refused.is_idempotency_conflict());
            let result = call_as(&registry, &db, caller.clone(), operation, args.clone()).await;
            assert!(result.as_ref().is_err_and(|e| e.is_idempotency_conflict()), "wrong app/no-app must refuse before effects, {operation} {index}->{candidate}: {result:?}");
            assert_eq!(
                keyed_context_snapshot(&db).await,
                saved,
                "no events, acts, frontiers, records or receipt metadata change"
            );
        }
    }
}

#[tokio::test]
async fn keyed_create_refuses_other_app_and_no_app_without_effects() {
    assert_keyed_context_isolation("create_record").await;
}
#[tokio::test]
async fn keyed_append_refuses_other_app_and_no_app_without_effects() {
    assert_keyed_context_isolation("update_record").await;
}

#[tokio::test]
async fn keyed_app_authorization_precedes_key_disclosure() {
    use native_ce::authorization::Capability;
    let (db, registry) = fixture().await;
    let install = adopted_v2(&registry, &db).await;
    let home = call_as(
        &registry,
        &db,
        Caller::local(),
        "create_record",
        json!({"type":"Collection","kind":"folder","name":"restricted","reason":"Restricted home fixture."}),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    crate::alpha_tabs::grant(&db, &home, ALICE, Capability::Edit).await;
    let id = uuid::Uuid::new_v4().to_string();
    let create = json!({"id":id,"type":"Document","kind":"note","name":"private","body":"private payload","home_id":home,"reason":"fixture","idempotency_key":"private-create"});
    let app = Caller::authenticated(ALICE).with_host_asserted_app(app(&install));
    call_as(&registry, &db, app.clone(), "create_record", create.clone())
        .await
        .unwrap();
    // Record-local owners retain Manage independently of policy (authorization.rs).
    // Use another owner's target so this test revokes an actual removable grant.
    let append_id = call_as(&registry, &db, Caller::local(), "create_record",
        json!({"type":"Document","kind":"note","name":"granted append target","body":"private payload","home_id":home,"reason":"Separately owned revocation fixture."})).await.unwrap()["id"].as_str().unwrap().to_owned();
    crate::alpha_tabs::grant(&db, &append_id, ALICE, Capability::Edit).await;
    let append = json!({"id":append_id,"body_append":" one","reason":"fixture","idempotency_key":"private-append"});
    call_as(&registry, &db, app.clone(), "update_record", append.clone())
        .await
        .unwrap();
    crate::alpha_tabs::revoke_all(&db, &home).await;
    crate::alpha_tabs::revoke_all(&db, &append_id).await;
    for target in [&home, &append_id] {
        for account in [ALICE, BEA] {
            assert!(
                !native_ce::authorization::effective_capability(
                    &db,
                    native_ce::authorization::Principal::bound(account, false),
                    target
                )
                .await
                .unwrap()
                .allows(Capability::Edit),
                "fixture must actually revoke the account's authority before probing its keys"
            );
        }
    }
    for (operation, args) in [("create_record", create), ("update_record", append)] {
        for caller in [
            app.clone(),
            Caller::authenticated(ALICE),
            Caller::authenticated(BEA),
        ] {
            let saved = keyed_context_snapshot(&db).await;
            let old = call_as(&registry, &db, caller.clone(), operation, args.clone())
                .await
                .unwrap_err()
                .to_string();
            let mut fresh = args.clone();
            fresh["idempotency_key"] = json!("never-used");
            let new = call_as(&registry, &db, caller, operation, fresh)
                .await
                .unwrap_err()
                .to_string();
            assert_eq!(
                old, new,
                "unauthorized reused key is indistinguishable from an unknown key"
            );
            assert!(!old.contains("private payload"));
            assert_eq!(keyed_context_snapshot(&db).await, saved);
        }
    }
}

#[tokio::test]
async fn keyed_attribution_context_refuses_in_its_transaction_before_outputs() {
    use sha2::{Digest, Sha256};
    let (db, registry) = fixture().await;
    let install = adopted_v2(&registry, &db).await;
    let note = call_as(&registry, &db, Caller::authenticated(ALICE), "create_record", json!({"type":"Document","kind":"note","name":"statement","body":"exact statement","reason":"fixture"})).await.unwrap();
    let event: String = sqlx::query_scalar(
        "SELECT id FROM content_events WHERE record_id=? AND type='record.created'",
    )
    .bind(note["id"].as_str().unwrap())
    .fetch_one(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    let args = json!({"idempotency_key":"attributed-assessment","bearer_id":note["id"],"target":{"source_event_id":event,"source_body_sha256":hex::encode(Sha256::digest(b"exact statement")),"scope":"whole_revision","selectors":[]},"subject":{"kind":"self_person"},"relation":"expresses_view","polarity":"affirmed","transformation":"summary","confidence":"likely","rationale":"A considered view."});
    let caller = Caller::authenticated(ALICE).with_host_asserted_app(app(&install));
    let first = call_as(
        &registry,
        &db,
        caller.clone(),
        "create_attribution",
        args.clone(),
    )
    .await
    .unwrap();
    let before = keyed_context_snapshot(&db).await;
    assert_eq!(
        call_as(&registry, &db, caller, "create_attribution", args.clone())
            .await
            .unwrap(),
        first
    );
    assert!(call_as(
        &registry,
        &db,
        Caller::authenticated(ALICE),
        "create_attribution",
        args
    )
    .await
    .unwrap_err()
    .is_idempotency_conflict());
    assert_eq!(keyed_context_snapshot(&db).await, before);
}
