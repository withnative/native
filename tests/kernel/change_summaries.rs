//! Public-surface acceptance coverage for the first-party change-summary lifecycle.

use std::collections::BTreeSet;

use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability, Principal};
use native_ce::change_summary::{
    change_summary_recipe_definition, change_summary_renderer_identity, inspect_change_summary,
    query_change_summaries, ChangeSummaryRecipePin, CHANGE_SUMMARY_RECIPE_PROGRAM_ID,
};
use native_ce::conformance::rebuild_and_diff_derivation;
use native_ce::derivation::digest_json;
use native_ce::events::FacetSetPayload;
use native_ce::mcp::{register_surface_tools, render, Caller, ToolRegistry};
use native_ce::recipe::{
    canonical_recipe_definition, publish_recipe_release, PublishRecipeRelease, RECIPE_RUNTIME,
};
use native_ce::schema::UNFILED_RECORD_ID;
use native_ce::{create_database, Db};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;

const OWNER: &str = "acct:change-summary-mcp-owner";
const OUTSIDER: &str = "acct:change-summary-mcp-outsider";
const WORKFLOW: &str = "release:public-mcp-lifecycle";
const RUNS: [&str; 3] = [
    "scout-chair-100001",
    "scout-chair-100002",
    "scout-chair-100003",
];

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

fn caller(actor: &str, run_key: Option<&str>) -> Caller {
    let caller = Caller::authenticated(actor);
    match run_key {
        Some(run_key) => caller.with_run_context(Some(run_key.to_owned()), None),
        None => caller,
    }
}

async fn call(
    registry: &ToolRegistry,
    db: &Db,
    actor: &str,
    run_key: Option<&str>,
    tool: &str,
    mut arguments: Value,
) -> Value {
    if let Some(run_key) = run_key {
        arguments
            .as_object_mut()
            .expect("tool arguments are objects")
            .insert("run_key".into(), Value::String(run_key.into()));
    }
    registry
        .call(db.clone(), Caller::authenticated(actor), tool, arguments)
        .await
        .unwrap()
}

async fn install_accounts(db: &Db) {
    for (record_id, principal, account) in [
        (
            "c8a70000-0000-4000-8000-000000000001",
            "native/change-summary-owner",
            OWNER,
        ),
        (
            "c8a70000-0000-4000-8000-000000000002",
            "native/change-summary-outsider",
            OUTSIDER,
        ),
    ] {
        native_ce::store::create_record(
            db,
            json!({"id":record_id,"type":"Entity","kind":"person","name":record_id}),
        )
        .await
        .unwrap();
        for (system, identifier) in [("native-principal", principal), ("account", account)] {
            sqlx::query(
                "INSERT INTO bindings(record_id,system,identifier,is_canonical)
                 VALUES(?,?,?,1)",
            )
            .bind(record_id)
            .bind(system)
            .bind(identifier)
            .execute(&crate::common::fixture_write_pool(db).await)
            .await
            .unwrap();
        }
    }
}

async fn install_packaged_recipe_record(db: &Db, body: &str) -> String {
    let payload = json!({
        "type":"Program",
        "kind":"recipe",
        "name":"Packaged change-summary recipe",
        "body":body,
        "home_id":UNFILED_RECORD_ID,
        "persistence":"enduring"
    })
    .to_string();
    let mut event = native_ce::events::EventRow {
        local_seq: -1,
        id: Uuid::new_v4().to_string(),
        record_id: CHANGE_SUMMARY_RECIPE_PROGRAM_ID.into(),
        event_type: "record.created".into(),
        payload: Some(payload),
        actor: Some("engine:test-fixture".into()),
        run_key: None,
        parent_key: None,
        intent: Some("historical packaged recipe test fixture".into()),
        created_at: "2026-08-01T00:00:00.000Z".into(),
        causal_envelope: native_ce::events::CausalEnvelopeV1::legacy_unknown(),
    };
    let pool = crate::common::fixture_write_pool(db).await;
    let mut tx = pool.begin().await.unwrap();
    event.local_seq = sqlx::query_scalar(
        "INSERT INTO content_events
           (id,record_id,type,payload,actor,run_key,parent_key,intent,created_at,causal_envelope_version,causal_status)
         VALUES(?,?,?,?,?,NULL,NULL,?,?,1,'legacy_unknown') RETURNING seq",
    )
    .bind(&event.id)
    .bind(&event.record_id)
    .bind(&event.event_type)
    .bind(&event.payload)
    .bind(&event.actor)
    .bind(&event.intent)
    .bind(&event.created_at)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    native_ce::projector::project(&mut tx, &event)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    pool.close().await;
    event.record_id
}

async fn publish_packaged_recipe(db: &Db) -> ChangeSummaryRecipePin {
    replace_explicit_policy(
        db,
        OWNER,
        UNFILED_RECORD_ID,
        vec![AllowEntry::account(OWNER, Capability::Manage)],
    )
    .await
    .unwrap();

    let definition = change_summary_recipe_definition().unwrap();
    let body = canonical_recipe_definition(&definition).unwrap();
    let program_id = install_packaged_recipe_record(db, &body).await;
    native_ce::store::set_facet(
        db,
        &program_id,
        FacetSetPayload {
            key: "runtime".into(),
            value: Some(RECIPE_RUNTIME.into()),
            vocab_ref: None,
            as_of: None,
            observation_only: false,
        },
    )
    .await
    .unwrap();
    replace_explicit_policy(
        db,
        OWNER,
        &program_id,
        vec![AllowEntry::account(OWNER, Capability::Manage)],
    )
    .await
    .unwrap();

    let row = sqlx::query(
        "SELECT id,json_extract(payload,'$.body') AS body
           FROM content_events
          WHERE record_id=? AND json_type(payload,'$.body')='text'
          ORDER BY seq DESC LIMIT 1",
    )
    .bind(&program_id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let source_event_id: String = row.try_get("id").unwrap();
    let source_body: String = row.try_get("body").unwrap();
    let release = publish_recipe_release(
        db,
        Principal::bound(OWNER, true),
        PublishRecipeRelease {
            publication_event_id: Uuid::new_v4().to_string(),
            program_id,
            source_event_id,
            source_sha256: format!("{:x}", Sha256::digest(source_body.as_bytes())),
            definition,
        },
    )
    .await
    .unwrap();
    ChangeSummaryRecipePin {
        publication_id: release.descriptor.publication_event_id,
        descriptor_sha256: release.descriptor_sha256,
        expected_status_event_seq: release.status_event_seq,
    }
}

struct Fixture {
    source_event_ids: Vec<String>,
    context_record_ids: Vec<String>,
    result: Value,
}

async fn fixture(registry: &ToolRegistry, db: &Db) -> Fixture {
    let mut source_event_ids = Vec::new();
    let mut source_citations = Vec::new();
    for (ordinal, run_key) in RUNS.into_iter().enumerate() {
        // Sources keep an id whose ascending order matches `ordinal`, so the
        // derived source sequence stays comparable to the old slug fixture.
        let record_id = format!("c8a70000-0000-4000-8000-00000000001{ordinal}");
        let created = call(
            registry,
            db,
            OWNER,
            Some(run_key),
            "create_record",
            json!({
                "id": record_id,
                "type": "Document",
                "kind": "note",
                "name": format!("Authoritative run {ordinal}"),
                "body": format!("authoritative result from run {ordinal}"),
                "reason": "Create one authoritative run input for the lifecycle test."
            }),
        )
        .await;
        let row = sqlx::query(
            "SELECT id,payload,run_key FROM content_events
              WHERE record_id=? ORDER BY seq DESC LIMIT 1",
        )
        .bind(created["id"].as_str().unwrap())
        .fetch_one(db.pool())
        .await
        .unwrap();
        let event_id: String = row.try_get("id").unwrap();
        let payload: String = row.try_get("payload").unwrap();
        assert_eq!(row.try_get::<String, _>("run_key").unwrap(), run_key);
        source_citations.push(json!({
            "ordinal": ordinal,
            "input_role": "source",
            "input_kind": "content_event",
            "portable_id": event_id,
            "sha256": digest_json(&serde_json::from_str::<Value>(&payload).unwrap())
        }));
        source_event_ids.push(event_id);
    }

    let contexts = [
        (
            "c8a70000-0000-4000-8000-000000000021",
            "Resolution",
            "decision",
            "Explicit confirmation is the shipping decision.",
        ),
        (
            "c8a70000-0000-4000-8000-000000000022",
            "Outcome",
            "impact",
            "Release communication is safer and traceable.",
        ),
        (
            "c8a70000-0000-4000-8000-000000000023",
            "WorkItem",
            "task",
            "Implement the public change-summary lifecycle.",
        ),
    ];
    let mut context_record_ids = Vec::new();
    for (id, record_type, kind, body) in contexts {
        let mut arguments = json!({
            "id": id,
            "type": record_type,
            "kind": kind,
            "name": id,
            "body": body,
            "reason": "Create governed context for the lifecycle test."
        });
        if (record_type, kind) == ("Outcome", "impact") {
            arguments["facets"] = json!({
                "impact": {
                    "claim": "Release communication is safer and traceable.",
                    "method": "derived",
                    "effective_at": "2026-08-03T17:30:00.000Z"
                }
            });
        }
        let created = call(registry, db, OWNER, None, "create_record", arguments).await;
        context_record_ids.push(created["id"].as_str().unwrap().to_owned());
    }

    let mut context_citations = Vec::new();
    let mut sorted_contexts = context_record_ids.clone();
    sorted_contexts.sort();
    for (offset, record_id) in sorted_contexts.iter().enumerate() {
        let row = sqlx::query(
            "SELECT e.id,json_extract(e.payload,'$.body') AS body
               FROM content_events e
              WHERE e.record_id=? AND json_type(e.payload,'$.body')='text'
              ORDER BY e.seq DESC LIMIT 1",
        )
        .bind(record_id)
        .fetch_one(db.pool())
        .await
        .unwrap();
        let event_id: String = row.try_get("id").unwrap();
        let body: String = row.try_get("body").unwrap();
        context_citations.push(json!({
            "ordinal": 3 + offset,
            "input_role": "context",
            "input_kind": "record_body",
            "portable_id": event_id,
            "sha256": format!("{:x}", Sha256::digest(body.as_bytes()))
        }));
    }

    let citations = source_citations
        .into_iter()
        .chain(context_citations)
        .collect::<Vec<_>>();
    let result = json!({
        "schema": "native.change-summary.v1",
        "effective_work_interval": {
            "started_at": "2026-08-01T09:00:00.000Z",
            "ended_at": "2026-08-03T17:30:00.000Z"
        },
        "renderer": change_summary_renderer_identity(),
        "source_groups": RUNS.into_iter().enumerate().map(|(ordinal, run_key)| json!({
            "run_key": run_key,
            "source_ordinal": ordinal
        })).collect::<Vec<_>>(),
        "title": "A traceable release digest",
        "overview": "Three runs converged on one shippable result.",
        "items": [{
            "heading": "Gate the release on explicit confirmation",
            "summary": "The draft and shipping decision remain separate and linked.",
            "citations": citations,
            "materiality": {
                "summary": "This preserves semantic judgement while retaining evidence.",
                "references": [{
                    "record_id": "c8a70000-0000-4000-8000-000000000021",
                    "rationale": "Records the explicit-confirmation decision."
                }]
            },
            "link_suggestions": {
                "work_items": [{
                    "record_id": "c8a70000-0000-4000-8000-000000000023",
                    "relationship": "implements",
                    "rationale": "Owns the implementation represented by this digest."
                }],
                "outcomes": [{
                    "record_id": "c8a70000-0000-4000-8000-000000000022",
                    "relationship": "relates_to",
                    "rationale": "Connects the change to its realised impact."
                }]
            }
        }]
    });

    Fixture {
        source_event_ids,
        context_record_ids,
        result,
    }
}

fn assert_opaque_source_cursor(cursor: &str) {
    assert_eq!(cursor.len(), 64);
    assert!(cursor
        .bytes()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')));
    assert!(!cursor.contains("event"));
    assert!(!cursor.contains("confirmation"));
}

#[tokio::test]
async fn public_mcp_change_summary_lifecycle_is_traceable_current_and_private() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    install_accounts(&db).await;
    let recipe = publish_packaged_recipe(&db).await;
    let fixture = fixture(&registry, &db).await;

    let create_arguments = json!({
        "action": "create_or_reuse",
        "workflow_key": WORKFLOW,
        "name": "Release digest",
        "recipe": recipe,
        "reason": "Create a private stable carrier for the release digest."
    });
    let created = call(
        &registry,
        &db,
        OWNER,
        Some("scout-chair-100010"),
        "manage_change_summaries",
        create_arguments.clone(),
    )
    .await;
    let reused = call(
        &registry,
        &db,
        OWNER,
        Some("scout-chair-100011"),
        "manage_change_summaries",
        create_arguments,
    )
    .await;
    for field in ["carrier_id", "series_id", "binding_id", "assignment_id"] {
        assert_eq!(created[field], reused[field], "{field} must be stable");
    }
    assert_eq!(created["action"], "create_or_reuse");
    assert_eq!(reused["action"], "create_or_reuse");
    let created_text = render::render("manage_change_summaries", &created).unwrap();
    assert!(
        created_text.starts_with("Change-summary workflow created or reused."),
        "{created_text}"
    );
    assert!(
        created_text.contains(&format!("Workflow: {WORKFLOW:?}")),
        "{created_text}"
    );
    assert!(
        created_text.contains(created["carrier_id"].as_str().unwrap()),
        "{created_text}"
    );

    // Deliberately scramble caller order: the product workflow must derive its
    // authoritative source sequence and context order rather than trust it.
    let source_event_ids = vec![
        fixture.source_event_ids[2].clone(),
        fixture.source_event_ids[0].clone(),
        fixture.source_event_ids[1].clone(),
    ];
    let context_record_ids = vec![
        fixture.context_record_ids[2].clone(),
        fixture.context_record_ids[0].clone(),
        fixture.context_record_ids[1].clone(),
    ];
    let derive_arguments = json!({
        "action": "derive",
        "workflow_key": WORKFLOW,
        "source_event_ids": source_event_ids,
        "context_record_ids": context_record_ids,
        "structured_result": fixture.result,
        "expected_recipe_status_event_seq": recipe.expected_status_event_seq,
        "reason": "Derive one digest from three authoritative runs and governed context."
    });
    let first = call(
        &registry,
        &db,
        OWNER,
        Some("scout-chair-100012"),
        "manage_change_summaries",
        derive_arguments.clone(),
    )
    .await;
    assert_eq!(first["executed"], true);
    assert_eq!(first["action"], "derive");
    let first_revision = first["revision_id"].as_str().unwrap().to_owned();
    let first_text = render::render("manage_change_summaries", &first).unwrap();
    assert!(
        first_text.starts_with("Change-summary derivation requested."),
        "{first_text}"
    );
    assert!(
        first_text.contains("Derivation executed and published a candidate."),
        "{first_text}"
    );
    assert!(first_text.contains(&first_revision), "{first_text}");
    let identical_retry = call(
        &registry,
        &db,
        OWNER,
        Some("scout-chair-100013"),
        "manage_change_summaries",
        derive_arguments,
    )
    .await;
    assert_eq!(identical_retry["executed"], false);
    assert_eq!(identical_retry["action"], "derive");
    assert_eq!(identical_retry["revision_id"], first_revision);
    let retry_text = render::render("manage_change_summaries", &identical_retry).unwrap();
    assert!(
        retry_text.contains("Existing succeeded derivation result reused."),
        "{retry_text}"
    );
    assert!(
        !retry_text.contains("Derivation executed and published a candidate."),
        "{retry_text}"
    );

    let inspected = call(
        &registry,
        &db,
        OWNER,
        None,
        "manage_change_summaries",
        json!({"action": "inspect", "workflow_key": WORKFLOW}),
    )
    .await;
    assert_eq!(inspected["action"], "inspect");
    assert_eq!(inspected["selected_revision_id"], first_revision);
    assert!(inspected["confirmed_revision_id"].is_null());
    let inspected_text = render::render("manage_change_summaries", &inspected).unwrap();
    assert!(
        inspected_text.starts_with("Change-summary workflow inspected."),
        "{inspected_text}"
    );
    assert!(
        inspected_text.contains(&format!("Selected revision: {first_revision:?}")),
        "{inspected_text}"
    );
    assert!(
        inspected_text.contains("Confirmed revision: null"),
        "{inspected_text}"
    );

    let first_confirmation = call(
        &registry,
        &db,
        OWNER,
        Some("scout-chair-100014"),
        "manage_change_summaries",
        json!({
            "action": "confirm",
            "workflow_key": WORKFLOW,
            "expected_revision_id": first_revision,
            "reason": "Explicitly ship the grouped result."
        }),
    )
    .await;
    assert_eq!(first_confirmation["action"], "confirm");
    let confirmation_text = render::render("manage_change_summaries", &first_confirmation).unwrap();
    assert!(
        confirmation_text.starts_with("Change-summary revision confirmed."),
        "{confirmation_text}"
    );
    assert!(
        confirmation_text.contains(&first_revision),
        "{confirmation_text}"
    );
    assert!(
        confirmation_text.contains(first_confirmation["confirmation_id"].as_str().unwrap()),
        "{confirmation_text}"
    );

    let listed = call(
        &registry,
        &db,
        OWNER,
        None,
        "query_change_summaries",
        json!({"action": "list", "limit": 10, "source_limit": 100}),
    )
    .await;
    assert_eq!(listed["action"], "list");
    assert_eq!(listed["items"].as_array().unwrap().len(), 1);
    assert!(listed["next_cursor"].is_null());
    let item = &listed["items"][0];
    assert_eq!(item["revision_id"], first_revision);
    assert!(item["confirmed_body"]
        .as_str()
        .unwrap()
        .contains("Three runs converged on one shippable result."));
    let source_runs = item["source_runs"].as_array().unwrap();
    assert_eq!(source_runs.len(), 6);
    let visible_run_keys = source_runs
        .iter()
        .filter(|input| input["input_role"] == "source")
        .map(|input| input["run_key"].as_str().unwrap().to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        visible_run_keys,
        RUNS.into_iter().map(str::to_owned).collect::<BTreeSet<_>>()
    );
    let listed_text = render::render("query_change_summaries", &listed).unwrap();
    for expected in [
        "Confirmed change-summary page: 1 returned item(s).",
        "Evidence page returned 6 item(s): 3 source, 3 context.",
        "Confirmed body preview:",
        "Three runs converged on one shippable result.",
        "List scan exhausted.",
    ] {
        assert!(
            listed_text.contains(expected),
            "missing {expected:?}: {listed_text}"
        );
    }

    let assignment_id = item["assignment_id"].as_str().unwrap().to_owned();
    let opened = call(
        &registry,
        &db,
        OWNER,
        None,
        "query_change_summaries",
        json!({"action": "get", "assignment_id": assignment_id, "source_limit": 1}),
    )
    .await;
    assert_eq!(opened["action"], "get");
    assert_eq!(opened["source_runs"].as_array().unwrap().len(), 1);
    let opened_text = render::render("query_change_summaries", &opened).unwrap();
    let opened_page_counts = match opened["source_runs"][0]["input_role"].as_str() {
        Some("source") => "Evidence page returned 1 item(s): 1 source, 0 context.",
        Some("context") => "Evidence page returned 1 item(s): 0 source, 1 context.",
        role => panic!("unexpected evidence role: {role:?}"),
    };
    for expected in [
        "Confirmed change summary.",
        opened_page_counts,
        "Evidence continuation: {\"action\":\"drill\"",
        "Confirmed body preview:",
        "Three runs converged on one shippable result.",
    ] {
        assert!(
            opened_text.contains(expected),
            "missing {expected:?}: {opened_text}"
        );
    }
    let mut paged_inputs = 1;
    let mut paged_runs = BTreeSet::new();
    let mut rendered_drill_pages = Vec::new();
    if let Some(run_key) = opened["source_runs"][0]["run_key"].as_str() {
        paged_runs.insert(run_key.to_owned());
    }
    let mut cursor = opened["next_source_cursor"].as_str().map(str::to_owned);
    assert!(
        opened_text.contains(cursor.as_deref().expect("bounded get returns a cursor")),
        "{opened_text}"
    );
    while let Some(token) = cursor {
        assert_opaque_source_cursor(&token);
        let page = call(
            &registry,
            &db,
            OWNER,
            None,
            "query_change_summaries",
            json!({
                "action": "drill",
                "assignment_id": assignment_id,
                "cursor": token,
                "limit": 1
            }),
        )
        .await;
        assert_eq!(page["action"], "drill");
        let input = &page["source_runs"][0];
        paged_inputs += 1;
        if input["input_role"] == "source" {
            paged_runs.insert(input["run_key"].as_str().unwrap().to_owned());
        }
        cursor = page["next_cursor"].as_str().map(str::to_owned);
        rendered_drill_pages.push(render::render("query_change_summaries", &page).unwrap());
    }
    assert_eq!(paged_inputs, 6);
    assert_eq!(paged_runs, visible_run_keys);
    assert!(
        rendered_drill_pages
            .first()
            .is_some_and(|text| text.contains("Change-summary evidence page.")
                && text.contains("Evidence continuation: {\"action\":\"drill\"")),
        "{rendered_drill_pages:?}"
    );
    assert!(
        rendered_drill_pages
            .last()
            .is_some_and(|text| text.contains("Evidence page exhausted.")
                && text.contains("Evidence page returned 1 item(s):")),
        "{rendered_drill_pages:?}"
    );

    let mut corrected_result = fixture.result;
    corrected_result["overview"] =
        json!("Three runs converged on one corrected, shippable result.");
    let correction = call(
        &registry,
        &db,
        OWNER,
        Some("scout-chair-100015"),
        "manage_change_summaries",
        json!({
            "action": "derive",
            "workflow_key": WORKFLOW,
            "source_event_ids": source_event_ids,
            "context_record_ids": context_record_ids,
            "structured_result": corrected_result,
            "expected_recipe_status_event_seq": recipe.expected_status_event_seq,
            "reason": "Correct the wording without silently changing the shipped digest."
        }),
    )
    .await;
    let corrected_revision = correction["revision_id"].as_str().unwrap().to_owned();
    assert_ne!(corrected_revision, first_revision);
    let before_correction_confirmation = call(
        &registry,
        &db,
        OWNER,
        None,
        "query_change_summaries",
        json!({"action": "list", "limit": 10, "source_limit": 10}),
    )
    .await;
    assert_eq!(
        before_correction_confirmation["items"][0]["revision_id"],
        first_revision
    );
    assert_eq!(
        before_correction_confirmation["items"][0]["draft_available"],
        true
    );

    let revoked_first = call(
        &registry,
        &db,
        OWNER,
        Some("scout-chair-100016"),
        "manage_change_summaries",
        json!({
            "action": "revoke",
            "workflow_key": WORKFLOW,
            "reason": "Withdraw the first wording before shipping its correction."
        }),
    )
    .await;
    assert_eq!(revoked_first["action"], "revoke");
    assert_eq!(
        revoked_first["confirmation_id"],
        first_confirmation["confirmation_id"]
    );
    let revoked_text = render::render("manage_change_summaries", &revoked_first).unwrap();
    assert!(
        revoked_text.starts_with("Change-summary confirmation revoked."),
        "{revoked_text}"
    );
    assert!(
        !revoked_text.contains("revision confirmed"),
        "{revoked_text}"
    );
    let corrected_confirmation = call(
        &registry,
        &db,
        OWNER,
        Some("scout-chair-100017"),
        "manage_change_summaries",
        json!({
            "action": "confirm",
            "workflow_key": WORKFLOW,
            "expected_revision_id": corrected_revision,
            "reason": "Explicitly ship the corrected digest."
        }),
    )
    .await;
    let corrected_list = call(
        &registry,
        &db,
        OWNER,
        None,
        "query_change_summaries",
        json!({"action": "list", "limit": 10, "source_limit": 10}),
    )
    .await;
    assert_eq!(
        corrected_list["items"][0]["revision_id"],
        corrected_revision
    );
    assert!(corrected_list["items"][0]["confirmed_body"]
        .as_str()
        .unwrap()
        .contains("corrected, shippable result"));

    call(
        &registry,
        &db,
        OWNER,
        Some("scout-chair-100018"),
        "manage_change_summaries",
        json!({
            "action": "revoke",
            "workflow_key": WORKFLOW,
            "reason": "Exercise explicit same-revision revocation and reconfirmation."
        }),
    )
    .await;
    let between = call(
        &registry,
        &db,
        OWNER,
        None,
        "query_change_summaries",
        json!({"action": "list", "limit": 10, "source_limit": 10}),
    )
    .await;
    assert!(between["items"].as_array().unwrap().is_empty());
    let reconfirmed = call(
        &registry,
        &db,
        OWNER,
        Some("scout-chair-100019"),
        "manage_change_summaries",
        json!({
            "action": "confirm",
            "workflow_key": WORKFLOW,
            "expected_revision_id": corrected_revision,
            "reason": "Reconfirm the same immutable corrected revision."
        }),
    )
    .await;
    assert_ne!(
        reconfirmed["confirmation_id"],
        corrected_confirmation["confirmation_id"]
    );

    let outsider_list = call(
        &registry,
        &db,
        OUTSIDER,
        None,
        "query_change_summaries",
        json!({"action": "list", "limit": 10, "source_limit": 10}),
    )
    .await;
    assert!(outsider_list["items"].as_array().unwrap().is_empty());
    let outsider_get = registry
        .call(
            db.clone(),
            caller(OUTSIDER, None),
            "query_change_summaries",
            json!({"action": "get", "assignment_id": assignment_id, "source_limit": 10}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(outsider_get.contains("change summary unavailable"));
    let hidden = registry
        .call(
            db.clone(),
            caller(OUTSIDER, None),
            "manage_change_summaries",
            json!({"action": "inspect", "workflow_key": WORKFLOW}),
        )
        .await
        .unwrap_err()
        .to_string();
    let absent = registry
        .call(
            db.clone(),
            caller(OUTSIDER, None),
            "manage_change_summaries",
            json!({"action": "inspect", "workflow_key": "release:absent"}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(hidden, absent);

    // MCP callers have already passed a live-membership ingress check. Exercise
    // the same product query with the membership bit removed at the public core
    // seam to prove that a former member sees neither listing nor inspection.
    let nonmember = query_change_summaries(&db, Principal::bound(OWNER, false), None, 10, 10)
        .await
        .unwrap();
    assert!(nonmember.items.is_empty());
    assert!(
        inspect_change_summary(&db, Principal::bound(OWNER, false), WORKFLOW)
            .await
            .unwrap_err()
            .to_string()
            .contains("does not exist")
    );

    let replay = rebuild_and_diff_derivation(&db).await.unwrap();
    assert!(
        replay.equal,
        "derivation replay drift: {:?}",
        replay
            .tables
            .iter()
            .filter(|table| !table.mismatches.is_empty())
            .map(|table| (&table.table, &table.mismatches))
            .collect::<Vec<_>>()
    );
    db.close().await;
}
