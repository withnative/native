//! Preview qualification uses the independent public manifest before every
//! compiler call. Singular twins remain effect oracles, never batch helpers.
use super::sql_selected_write_fixtures::{EventIntent, Fixture, Label, Task, REASON};
use native_ce::mcp::executor_prototype::{
    ExecutorPrototypeStdioServer, ExecutorTelemetryContext, ExecutorTelemetrySink,
};
use native_ce::mcp::{
    register_allowlisted_experimental_tools, register_builtin_tools, register_surface_tools,
    Caller, ExperimentalExecutors, ToolRegistry,
};
use serde_json::{json, Value};
use std::sync::Arc;
const CONTRACT: &str = "native.sql-write-selection.v1";
struct Sink;
impl ExecutorTelemetrySink for Sink {
    fn emit(&self, _: &[u8]) -> std::io::Result<()> {
        Ok(())
    }
}
async fn server(f: &Fixture, caller: Caller) -> ExecutorPrototypeStdioServer {
    let mut r = ToolRegistry::new();
    register_builtin_tools(&mut r).unwrap();
    register_surface_tools(&mut r).unwrap();
    let experimental = ExperimentalExecutors::from_env_value(Some("sql_write".into())).unwrap();
    register_allowlisted_experimental_tools(&mut r, &experimental).unwrap();
    ExecutorPrototypeStdioServer::new_with_telemetry_and_experimental(
        Arc::new(r),
        f.db.clone(),
        caller,
        None,
        ExecutorTelemetryContext::new(Arc::new(Sink), 7).unwrap(),
        experimental,
    )
    .await
    .unwrap()
}
async fn global_user_schema_id(f: &Fixture) -> String {
    let schema = f
        .call_as(
            Caller::local(),
            "manage_schema_config",
            json!({"action":"read"}),
        )
        .await
        .unwrap();
    let rows = schema["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["layer"] == "user" && r["applies_to_collection_id"].is_null())
        .collect::<Vec<_>>();
    assert_eq!(
        rows.len(),
        1,
        "fixed baseline has one user schema declaration"
    );
    rows[0]["id"].as_str().unwrap().to_string()
}
fn request(task: Task) -> Value {
    json!({"selection_contract":CONTRACT,"folder_id":Label::F.id(),"statement":if task==Task::Archive {"SELECT id FROM children WHERE current_facet('triage_state')='ready'"} else {"SELECT id FROM children WHERE current_facet('triage_state')='ready' AND archived=false"},"write":match task {Task::Review=>json!({"op":"set_facet","key":"review_state","value":"approved"}),Task::Relate=>json!({"op":"add_link","target_id":Label::D.id()}),Task::Archive=>json!({"op":"archive"})},"reason":REASON})
}
async fn call(s: &ExecutorPrototypeStdioServer, args: Value) -> Value {
    s.handle_message(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sql_write","arguments":args}})).await.unwrap()
}
async fn prepare(s: &ExecutorPrototypeStdioServer, request: Value) -> Value {
    call(s, json!({"operation":"sql_write","arguments":request})).await
}
fn body(v: &Value) -> &Value {
    &v["result"]["structuredContent"]
}
fn approved(v: &Value) -> &Value {
    let b = body(v);
    assert!(b["plan_id"].is_string(), "{v}");
    b
}
async fn confirm(s: &ExecutorPrototypeStdioServer, plan: &Value) -> Value {
    call(s, confirm_arguments(plan)).await
}
fn confirm_arguments(plan: &Value) -> Value {
    json!({"operation":"sql_write","plan_id":plan["plan_id"],"target":plan["target"],"effect_summary":plan["effect_summary"]})
}
fn code(v: &Value) -> &str {
    body(v)["error"]["code"]
        .as_str()
        .or_else(|| body(v)["plan_error"]["code"].as_str())
        .or_else(|| body(v)["code"].as_str())
        .unwrap_or_else(|| panic!("missing code: {v}"))
}
async fn task_preview(task: Task) {
    let f = Fixture::new().await; // Public manifest exists independently first.
    let twin = Fixture::new().await;
    let oracle = twin.singular_oracle(task).await;
    oracle.assert_public_effects();
    let s = server(&f, f.selection_caller()).await;
    let before = f.snapshot().await;
    let response = prepare(&s, request(task)).await;
    let plan = approved(&response);
    let targets = plan["effect"]["targets"].as_array().unwrap();
    assert_eq!(
        targets
            .iter()
            .map(|t| t["record_id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        task.ids()
    );
    assert_eq!(plan["effect"]["target_count"], task.ids().len());
    assert_eq!(plan["effect"]["op_count"], task.ids().len());
    assert_eq!(
        plan["operation_evidence"]["selection"]["candidate_count"],
        5
    ); // A/B/C/X/S, no H/T/N/O.
    for (target, expected) in targets.iter().zip(&oracle.expected) {
        assert_eq!(target["record_id"], expected.label.id());
        assert!(target["name"].is_string());
        assert_eq!(
            target["state_changed"],
            expected.state_changed.map_or(Value::Null, Value::Bool)
        );
        let event = &target["event_intent"];
        match expected.event_intent {
            EventIntent::FacetAssertion => {
                assert_eq!(target["before"], expected.before);
                assert_eq!(target["after"], expected.after);
                assert_eq!(event["event_type"], "facet.set");
                assert_eq!(event["content_events"], 1);
            }
            EventIntent::ArchiveFacet => {
                assert_eq!(target["before"], false);
                assert_eq!(event["content_events"], 1);
            }
            EventIntent::None => {
                assert_eq!(target["before"], true);
                assert_eq!(target["would_append"], false);
                assert_eq!(event["content_events"], 0);
            }
            EventIntent::CreatePropositionAndSupport => assert_eq!(event["relationship_events"], 2),
            EventIntent::AddSupport => {
                assert_eq!(event["relationship_events"], 1);
                assert!(!event["causal_parents"].as_array().unwrap().is_empty());
            }
        }
    }
    assert_eq!(before, f.snapshot().await);
    let confirmation = confirm(&s, plan).await;
    assert_eq!(body(&confirmation)["committed"], false, "{confirmation}");
    assert_eq!(body(&confirmation)["source_dispatch_count"], 0);
    assert_eq!(before, f.snapshot().await);
    let replay = confirm(&s, plan).await;
    assert_eq!(body(&replay)["committed"], false, "{replay}");
    assert_eq!(before, f.snapshot().await);
    // Both workflows measure tools/call arguments and structuredContent, not
    // JSON-RPC framing. The extra replay assertion is outside the two-call
    // measured prepare/confirm workflow; this endpoint remains preview only.
    let prepare_request_bytes =
        serde_json::to_vec(&json!({"operation":"sql_write","arguments":request(task)}))
            .unwrap()
            .len();
    let prepare_result_bytes = serde_json::to_vec(body(&response)).unwrap().len();
    let confirm_request_bytes = serde_json::to_vec(&confirm_arguments(plan)).unwrap().len();
    let confirm_result_bytes = serde_json::to_vec(body(&confirmation)).unwrap().len();
    println!("Preview-only workflow {task:?}: exact {}/{}, calls=2 repairs=0 JSON_level=tool_arguments+structuredContent prepare_bytes={prepare_request_bytes}/{prepare_result_bytes} confirm_bytes={confirm_request_bytes}/{confirm_result_bytes} request_bytes={} response_bytes={}; extra replay verification excluded",targets.len(),task.ids().len(),prepare_request_bytes+confirm_request_bytes,prepare_result_bytes+confirm_result_bytes);
}
#[tokio::test]
async fn selected_task1_exact_public_facet_effects_and_no_mutation() {
    task_preview(Task::Review).await
}
#[tokio::test]
async fn selected_task2_exact_public_support_effects_and_no_mutation() {
    task_preview(Task::Relate).await
}
#[tokio::test]
async fn selected_task3_exact_archived_member_no_event_and_no_mutation() {
    task_preview(Task::Archive).await
}

#[tokio::test]
async fn selected_request_refusals_are_whole_and_non_mutating() {
    let f = Fixture::new().await;
    let s = server(&f, f.selection_caller()).await;
    let before = f.snapshot().await;
    let mut cases = Vec::new();
    for statement in [
        "SELECT id FROM children WHERE name='does not exist'",
        "SELECT id FROM children WHERE summary NOT NULL",
        "SELECT id FROM children LIMIT 2",
        "SELECT id FROM records",
        "SELECT id FROM children WHERE archived='false'",
        "SELECT id FROM children WHERE current_facet(?1)='ready'",
        "SELECT id FROM children WHERE id=id",
        "SELECT id FROM children WHERE archived IS FALSE",
    ] {
        let mut r = request(Task::Review);
        r["statement"] = json!(statement);
        cases.push(r);
    }
    let mut r = request(Task::Review);
    r["selection_contract"] = json!("unknown");
    cases.push(r);
    let mut r = request(Task::Review);
    r.as_object_mut().unwrap().remove("selection_contract");
    cases.push(r);
    let mut r = request(Task::Review);
    r["expected_version"] = Value::Null;
    cases.push(r);
    let mut r = request(Task::Review);
    r["parameters"] = json!(vec![json!({"type":"text","value":"x"}); 257]);
    cases.push(r);
    let mut r = request(Task::Review);
    r["statement"] = json!("SELECT id FROM children WHERE archived=?1");
    r["parameters"] = json!([{"type":"text","value":null}]);
    cases.push(r);
    let mut r = request(Task::Review);
    r["statement"] = json!("SELECT id FROM children WHERE current_facet('triage_state')='ready'");
    cases.push(r); // C archived setter refuses whole.
    for r in cases {
        let response = prepare(&s, r).await;
        assert!(
            matches!(
                code(&response),
                "preparation_validation_failed" | "preparation_rejected"
            ),
            "{response}"
        );
        assert_eq!(before, f.snapshot().await);
    }
    let p = prepare(&s, request(Task::Review)).await;
    let mut tamper = approved(&p).clone();
    tamper["effect_summary"] = json!("approve a different effect");
    let response = confirm(&s, &tamper).await;
    assert_ne!(body(&response)["committed"], true);
    assert_eq!(code(&response), "visible_effect_mismatch");
    assert_eq!(before, f.snapshot().await);
}

#[tokio::test]
async fn selected_visible_filter_drift_and_equal_capability_policy_drift_stale() {
    let f = Fixture::new().await;
    let s = server(&f, f.selection_caller()).await;
    let p = prepare(&s, request(Task::Review)).await;
    let p = approved(&p);
    f.setup_call("update_record",json!({"id":Label::X.id(),"facets":{"triage_state":"ready"},"reason":"Visible unselected input changes membership."})).await;
    let before = f.snapshot().await;
    let response = confirm(&s, p).await;
    assert_eq!(code(&response), "plan_stale");
    assert_eq!(before, f.snapshot().await);
    let p = prepare(&s, request(Task::Review)).await;
    let p = approved(&p);
    let listed = f
        .call_as(
            Caller::local(),
            "manage_record_policy",
            json!({"action":"list","record_id":Label::A.id()}),
        )
        .await
        .unwrap();
    // New irrelevant subject row keeps this principal's Manage but is a real
    // change to a policy set consumed by the canonical evaluator.
    f.call_as(Caller::local(),"manage_record_policy",json!({"action":"replace","record_id":Label::A.id(),"entries":[{"subject":{"kind":"account","account_id":super::sql_selected_write_fixtures::SELECTION_ACCOUNT},"capability":"manage"},{"subject":{"kind":"account","account_id":super::sql_selected_write_fixtures::SETUP_ACCOUNT},"capability":"manage"},{"subject":{"kind":"account","account_id":"acct:other-observer"},"capability":"view"}],"if_policy_revision":listed["policy_revision"],"reason":"Bind relevant policy inputs even at equal capability."})).await.unwrap();
    let before = f.snapshot().await;
    assert_eq!(code(&confirm(&s, p).await), "plan_stale");
    assert_eq!(before, f.snapshot().await);
}

#[tokio::test]
async fn selected_hidden_currency_policy_and_unrelated_schema_do_not_stale() {
    let f = Fixture::new().await;
    let s = server(&f, f.selection_caller()).await;
    let response = prepare(&s, request(Task::Review)).await;
    let p = approved(&response);
    f.setup_call(
        "update_record",
        json!({"id":Label::H.id(),"name":"Hidden changed","reason":"Hidden delta."}),
    )
    .await;
    f.setup_call("manage_links",json!({"action":"add","source_id":Label::H.id(),"target_id":Label::B.id(),"relationship":"supersedes"})).await;
    let listed = f
        .call_as(
            Caller::local(),
            "manage_record_policy",
            json!({"action":"list","record_id":Label::H.id()}),
        )
        .await
        .unwrap();
    f.call_as(Caller::local(),"manage_record_policy",json!({"action":"replace","record_id":Label::H.id(),"entries":[{"subject":{"kind":"account","account_id":super::sql_selected_write_fixtures::SETUP_ACCOUNT},"capability":"manage"},{"subject":{"kind":"account","account_id":"acct:unrelated-hidden"},"capability":"view"}],"if_policy_revision":listed["policy_revision"],"reason":"Unrelated hidden policy."})).await.unwrap();
    f.call_as(Caller::local(),"manage_schema_config",json!({"action":"write","id":global_user_schema_id(&f).await,"data":{"shapes":{"Document:note":{"facets":{"triage_state":{"values":["ready","hold"]},"review_state":{"values":["pending","approved"]},"unrelated_key":{"type":"number"}}}}}})).await.unwrap();
    let before = f.snapshot().await;
    let confirmation = confirm(&s, p).await;
    assert_eq!(body(&confirmation)["committed"], false, "{confirmation}");
    assert_eq!(before, f.snapshot().await);
}

#[tokio::test]
async fn selected_unselected_setter_shape_and_relevant_malformed_containers() {
    let f = Fixture::new().await;
    // S is visible and unselected; its Collection shape must not veto a
    // Document-only setter. Public schema setup, fixed baseline untouched.
    let declaration = f.call_as(Caller::local(),"manage_schema_config",json!({"action":"write","data":{"shapes":{"Document:note":{"facets":{"triage_state":{"values":["ready","hold"]},"review_state":{"values":["pending","approved"]}}},"Collection":{"facets":{"review_state":{"type":"number"}}}}}})).await.unwrap();
    let s = server(&f, f.selection_caller()).await;
    let before = f.snapshot().await;
    let p = prepare(&s, request(Task::Review)).await;
    let p = approved(&p);
    assert_eq!(before, f.snapshot().await);
    // Unsupported unselected setter shapes are projected, not validated.
    // Relevant drift in S's different context must still invalidate the plan.
    f.call_as(Caller::local(),"manage_schema_config",json!({"action":"write","id":declaration["id"],"data":{"shapes":{"Document:note":{"facets":{"triage_state":{"values":["ready","hold"]},"review_state":{"values":["pending","approved"]}}},"Collection":{"facets":{"review_state":{"type":"number","required":true}}}}}})).await.unwrap();
    let before = f.snapshot().await;
    assert_eq!(code(&confirm(&s, p).await), "plan_stale");
    approved(&prepare(&s, request(Task::Review)).await);
    assert_eq!(before, f.snapshot().await);
    // Authoritative storage corruption probe, distinct from public product
    // deltas: relevant parent arrays cannot be normalized into open absence.
    use sqlx::Connection;
    let mut corrupt = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(f.db.path()),
    )
    .await
    .unwrap();
    sqlx::query("UPDATE schema_config SET data=? WHERE applies_to_collection_id IS NULL")
        .bind(r#"{"shapes":{"Document:note":{"facets":[]}}}"#)
        .execute(&mut corrupt)
        .await
        .unwrap();
    corrupt.close().await.unwrap();
    let before = f.snapshot().await;
    let response = prepare(&s, request(Task::Review)).await;
    assert_eq!(code(&response), "preparation_rejected");
    assert!(
        body(&response)
            .to_string()
            .contains("repair authoritative storage"),
        "{response}"
    );
    assert_eq!(before, f.snapshot().await);
}

#[tokio::test]
async fn selected_scope_and_authority_failures_remain_opaque_whole_refusals() {
    let f = Fixture::new().await;
    let s = server(&f, f.selection_caller()).await;
    let before = f.snapshot().await;
    let mut r = request(Task::Review);
    r["folder_id"] = json!(Label::H.id());
    let hidden = prepare(&s, r.clone()).await;
    r["folder_id"] = json!("c0510000-0000-4000-8000-00000000ffff");
    let missing = prepare(&s, r).await;
    assert_eq!(body(&hidden)["error"], body(&missing)["error"]);
    assert_eq!(code(&hidden), "preparation_rejected");
    assert_eq!(before, f.snapshot().await);
    let listed = f
        .call_as(
            Caller::local(),
            "manage_record_policy",
            json!({"action":"list","record_id":Label::B.id()}),
        )
        .await
        .unwrap();
    f.call_as(Caller::local(),"manage_record_policy",json!({"action":"replace","record_id":Label::B.id(),"entries":[{"subject":{"kind":"account","account_id":super::sql_selected_write_fixtures::SELECTION_ACCOUNT},"capability":"view"},{"subject":{"kind":"account","account_id":super::sql_selected_write_fixtures::SETUP_ACCOUNT},"capability":"manage"}],"if_policy_revision":listed["policy_revision"],"reason":"Keep visible but remove required Edit."})).await.unwrap();
    let before = f.snapshot().await;
    assert_eq!(
        code(&prepare(&s, request(Task::Review)).await),
        "preparation_rejected"
    );
    assert_eq!(before, f.snapshot().await);
}

#[tokio::test]
async fn selected_public_artifact_runtime_boundary_refuses_facets_only() {
    let f = Fixture::new().await;
    let artifact = "c0510000-0000-4000-8000-0000000000f1";
    // Public MDX artifact accepts prose; switching its schema-valid runtime to
    // HTML still fails the public compiler. Manifest precedes compilation.
    f.call_as(Caller::local(),"create_record",json!({"id":artifact,"type":"Document","kind":"artifact","name":"Runtime boundary","reason":"Public runtime guard setup.","facets":{"runtime":"native.mdx.v2"},"body":"export const nativeArtifact = { schema: \"native.mdx.artifact.v2\", inputs: {}, module_inputs: {}, capability_requests: [] };\n\n# Ordinary prose without an HTML document.","home_id":Label::F.id()})).await.unwrap();
    let public_before = f.snapshot().await;
    let public=f.call_as(Caller::local(),"update_record",json!({"id":artifact,"facets":{"runtime":"native.html.v1"},"reason":"A schema-valid runtime must still pass the public compiler."})).await;
    assert!(public
        .unwrap_err()
        .to_string()
        .contains("html_invalid_document"));
    assert_eq!(public_before, f.snapshot().await);
    let s = server(&f, Caller::local()).await;
    let mut r = request(Task::Review);
    r["statement"] = json!(format!("SELECT id FROM children WHERE id='{artifact}'"));
    r["write"] = json!({"op":"set_facet","key":"runtime","value":"native.html.v1"});
    let before = f.snapshot().await;
    let refused = prepare(&s, r.clone()).await;
    assert_eq!(code(&refused), "preparation_rejected");
    assert!(
        body(&refused)
            .to_string()
            .contains("unsupported selected compiler"),
        "{refused}"
    );
    assert_eq!(before, f.snapshot().await);
    r["write"] = json!({"op":"archive"});
    approved(&prepare(&s, r.clone()).await);
    r["write"] = json!({"op":"add_link","target_id":Label::D.id()});
    approved(&prepare(&s, r).await);
    assert_eq!(before, f.snapshot().await);
}

#[tokio::test]
async fn selected_governed_public_tokens_assessor_and_canonical_subset() {
    let f = Fixture::new().await;
    f.call_as(Caller::local(),"manage_vocabularies",json!({"action":"create_vocabulary","name":"selected_priority","id":"voc:selected_priority"})).await.unwrap();
    let mut ids = Vec::new();
    for value in ["ready", "approved", "alias"] {
        let proposed=f.call_as(Caller::local(),"manage_vocabularies",json!({"action":"propose_value","vocabulary":"voc:selected_priority","value":value})).await.unwrap();
        let id = proposed["value_id"]
            .as_str()
            .or_else(|| proposed["id"].as_str())
            .unwrap_or_else(|| panic!("{proposed}"));
        f.call_as(
            Caller::local(),
            "manage_vocabularies",
            json!({"action":"promote_value","value_id":id}),
        )
        .await
        .unwrap();
        ids.push(id.to_string());
    }
    f.call_as(
        Caller::local(),
        "manage_vocabularies",
        json!({"action":"alias_value","value_id":ids[2],"canonical_id":ids[1]}),
    )
    .await
    .unwrap();
    f.call_as(Caller::local(),"manage_schema_config",json!({"action":"write","data":{"shapes":{"Document:note":{"facets":{"triage_state":{"values":["ready","hold"]},"review_state":{"values":["pending","approved"]},"priority":{"vocab":"voc:selected_priority"}}}}}})).await.unwrap();
    for id in [Label::A.id(), Label::B.id()] {
        f.setup_call("update_record",json!({"id":id,"facets":{"priority":"ready"},"reason":"Public canonical current text setup."})).await;
    }
    let s = server(&f, f.selection_caller()).await;
    let mut r = request(Task::Review);
    r["statement"] =
        json!("SELECT id FROM children WHERE current_facet('priority')='ready' AND archived=false");
    r["write"] = json!({"op":"set_facet","key":"priority","value":"approved"});
    let before = f.snapshot().await;
    let p = prepare(&s, r.clone()).await;
    let p = approved(&p);
    assert_eq!(p["effect"]["target_count"], 2);
    assert_eq!(
        p["effect"]["targets"][0]["operation"]["after_vocab_ref"],
        "rec:voc:selected_priority"
    );
    assert_eq!(before, f.snapshot().await);
    let mut alias = r.clone();
    alias["write"]["value"] = json!("alias");
    assert_eq!(code(&prepare(&s, alias).await), "preparation_rejected");
    assert_eq!(before, f.snapshot().await);
    f.call_as(
        Caller::local(),
        "manage_vocabularies",
        json!({"action":"deprecate_value","value_id":ids[1]}),
    )
    .await
    .unwrap();
    let before = f.snapshot().await;
    assert_eq!(code(&confirm(&s, p).await), "plan_stale");
    assert_eq!(before, f.snapshot().await);
}

#[tokio::test]
async fn selected_default_raw_text_does_not_infer_origin_and_missing_is_three_valued() {
    let f = Fixture::new().await;
    f.setup_call("update_record",json!({"id":Label::A.id(),"facets":{"raw_lane":123},"reason":"Public number/string carriers share current TEXT."})).await;
    let s = server(&f, f.selection_caller()).await;
    let mut r = request(Task::Review);
    r["statement"] = json!(format!(
        "SELECT id FROM children WHERE id IN ('{}','{}') AND current_facet('raw_lane') <> 'x'",
        Label::A.id(),
        Label::B.id()
    ));
    let before = f.snapshot().await;
    let p = prepare(&s, r.clone()).await;
    let p = approved(&p);
    assert_eq!(p["effect"]["target_count"], 1);
    assert_eq!(p["effect"]["targets"][0]["record_id"], Label::A.id());
    r["statement"]=json!(format!("SELECT id FROM children WHERE id IN ('{}','{}') AND (current_facet('raw_lane') <> 'x' OR current_facet('raw_lane') IS NULL)",Label::A.id(),Label::B.id()));
    assert_eq!(
        approved(&prepare(&s, r.clone()).await)["effect"]["target_count"],
        2
    );
    assert_eq!(before, f.snapshot().await);
    f.call_as(Caller::local(),"manage_schema_config",json!({"action":"write","data":{"shapes":{"Document:note":{"facets":{"triage_state":{"values":["ready","hold"]},"review_state":{"values":["pending","approved"]},"raw_lane":{"type":"number"}}}}}})).await.unwrap();
    let before = f.snapshot().await;
    assert_eq!(code(&prepare(&s, r).await), "preparation_rejected");
    assert_eq!(before, f.snapshot().await);
}

#[tokio::test]
async fn selected_complete_cohort_25_succeeds_26_refuses_without_clipping() {
    let f = Fixture::new().await;
    let ids = (0..26)
        .map(|n| format!("c0510000-0000-4000-8000-{:012x}", 0x100 + n))
        .collect::<Vec<_>>(); // independent manifest before compiler
    for id in &ids {
        f.call_as(Caller::local(),"create_record",json!({"id":id,"type":"Document","kind":"note","name":"Cap member","reason":"Public bounded cohort setup.","home_id":Label::G.id(),"facets":{"triage_state":"ready"}})).await.unwrap();
    }
    let s = server(&f, Caller::local()).await;
    let mut r = request(Task::Archive);
    r["folder_id"] = json!(Label::G.id());
    r["statement"] = json!(format!(
        "SELECT id FROM children WHERE name='Cap member' AND id <> '{}' AND current_facet('triage_state')='ready'",
        ids[25]
    ));
    let before = f.snapshot().await;
    let p = prepare(&s, r.clone()).await;
    let p = approved(&p);
    assert_eq!(
        p["effect"]["targets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["record_id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ids[..25].iter().map(String::as_str).collect::<Vec<_>>()
    );
    r["statement"] = json!(
        "SELECT id FROM children WHERE name='Cap member' AND current_facet('triage_state')='ready'"
    );
    assert_eq!(code(&prepare(&s, r).await), "preparation_rejected");
    assert_eq!(before, f.snapshot().await);
}

#[tokio::test]
async fn selected_strict_evaluator_failure_is_infrastructure_not_hidden_or_drift() {
    let f = Fixture::new().await;
    let s = server(&f, f.selection_caller()).await;
    let p = prepare(&s, request(Task::Review)).await;
    let p = approved(&p);
    // Authoritative malformed-state probe, not a public policy delta.
    use sqlx::Connection;
    let mut corrupt = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(f.db.path()),
    )
    .await
    .unwrap();
    sqlx::query("PRAGMA ignore_check_constraints=ON")
        .execute(&mut corrupt)
        .await
        .unwrap();
    sqlx::query("UPDATE policy_entries SET capability='malformed-capability' WHERE policy_anchor_id=(SELECT policy_anchor_id FROM records WHERE id=?) AND subject_id=?").bind(Label::A.id()).bind(super::sql_selected_write_fixtures::SELECTION_ACCOUNT).execute(&mut corrupt).await.unwrap();
    corrupt.close().await.unwrap();
    let before = f.snapshot().await;
    assert_eq!(
        code(&prepare(&s, request(Task::Review)).await),
        "preparation_rejected"
    );
    assert_eq!(code(&confirm(&s, p).await), "plan_revalidation_failed");
    assert_eq!(before, f.snapshot().await);
}

#[tokio::test]
async fn selected_visible_1000_1001_boundary_and_hidden_pages_have_no_physical_cap() {
    let f = Fixture::new().await;
    // Storage robustness/resource probe, separate from the fixed public task
    // fixture. Manifest is fixed before compilation; these unselected rows
    // deliberately have no content-event versions and never become targets.
    let ids = (0..995)
        .map(|n| format!("c0510000-0000-4000-8000-{:012x}", 0x1000 + n))
        .collect::<Vec<_>>();
    use sqlx::Connection;
    let mut setup = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(f.db.path()),
    )
    .await
    .unwrap();
    for id in &ids[..994] {
        sqlx::query("INSERT INTO records(id,type,kind,name,home_id,policy_anchor_id) VALUES (?,'Document','note','Resource member',?,?)").bind(id).bind(Label::F.id()).bind(Label::H.id()).execute(&mut setup).await.unwrap();
    }
    let s = server(&f, Caller::local()).await;
    let mut r = request(Task::Archive);
    r["statement"] = json!(format!(
        "SELECT id FROM children WHERE id='{}'",
        Label::A.id()
    ));
    let before = f.snapshot().await;
    let p = prepare(&s, r.clone()).await;
    assert_eq!(
        approved(&p)["operation_evidence"]["selection"]["candidate_count"],
        1000
    );
    assert_eq!(before, f.snapshot().await);
    sqlx::query("INSERT INTO records(id,type,kind,name,home_id,policy_anchor_id) VALUES (?,'Document','note','Resource member',?,?)").bind(&ids[994]).bind(Label::F.id()).bind(Label::H.id()).execute(&mut setup).await.unwrap();
    let before = f.snapshot().await;
    let rejected = prepare(&s, r.clone()).await;
    assert_eq!(code(&rejected), "preparation_rejected");
    assert!(body(&rejected).to_string().contains("1000 candidates"));
    assert_eq!(before, f.snapshot().await);
    setup.close().await.unwrap();
    // These added rows have no member/owner grant for the authenticated
    // selection principal: 1001 physical rows do not cap its visible source.
    let authenticated = server(&f, f.selection_caller()).await;
    let p = prepare(&authenticated, r).await;
    assert_eq!(
        approved(&p)["operation_evidence"]["selection"]["candidate_count"],
        5
    );
    assert_eq!(before, f.snapshot().await);
}

#[tokio::test]
async fn selected_measured_agent_baseline_query_then_explicit_batch() {
    // This is an executed baseline workflow, not an effect oracle for v1.
    // Public singular twins above remain the independent effect authority.
    for task in [Task::Review, Task::Relate, Task::Archive] {
        let f = Fixture::new().await;
        let selection = json!({"steps":[{"step":"filter","home_id":Label::F.id(),"facets":[{"key":"triage_state","eq":"ready"}],"include_archived":task==Task::Archive}],"limit":25});
        let result = f.call("query_record", selection.clone()).await;
        let mut ids = result["records"]
            .as_array()
            .unwrap_or_else(|| panic!("{result}"))
            .iter()
            .map(|r| r["id"].as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        ids.sort();
        assert_eq!(ids, task.ids());
        assert_eq!(result["total"], task.ids().len());
        let items=ids.iter().map(|id|match task {Task::Review=>json!({"op":"update","id":id,"facets":{"review_state":"approved"}}),Task::Relate=>json!({"op":"add_link","source_id":id,"target_id":Label::D.id(),"relationship":"relates_to"}),Task::Archive=>json!({"op":"archive","id":id})}).collect::<Vec<_>>();
        let batch = json!({"reason":REASON,"items":items});
        let receipt = f.call("batch_write", batch.clone()).await;
        assert_eq!(receipt["requested"], task.ids().len());
        println!("Committed explicit-batch baseline {task:?}: exact {}/{}, calls=2 repairs=0 JSON_level=tool_arguments+structuredContent request_bytes={} response_bytes={}",ids.len(),task.ids().len(),serde_json::to_vec(&selection).unwrap().len()+serde_json::to_vec(&batch).unwrap().len(),serde_json::to_vec(&result).unwrap().len()+serde_json::to_vec(&receipt).unwrap().len());
    }
}

#[tokio::test]
async fn selected_signed_plan_states_expiry_tamper_and_fresh_principal_footing() {
    let f = Fixture::new().await;
    let s = server(&f, f.selection_caller()).await;
    let response = prepare(&s, request(Task::Review)).await;
    let p = approved(&response);
    let before = f.snapshot().await;
    let path = f.db.path().canonicalize().unwrap();
    let file = path.file_name().unwrap().to_str().unwrap();
    let path = path.with_file_name(format!("{file}.write-plans.sqlite3"));
    use sqlx::Connection;
    let mut store = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(path),
    )
    .await
    .unwrap();
    let (state,dispatch,ttl):(String,i64,i64)=sqlx::query_as("SELECT state,source_dispatch_count,expires_at_ms-created_at_ms FROM write_plans WHERE plan_id=?").bind(p["plan_id"].as_str().unwrap()).fetch_one(&mut store).await.unwrap();
    assert_eq!(state, "prepared");
    assert_eq!(dispatch, 0);
    assert_eq!(ttl, 600_000);
    let changed_footing = server(
        &f,
        f.selection_caller()
            .with_hosting_member(!f.selection_caller().is_host_member()),
    )
    .await;
    assert_eq!(code(&confirm(&changed_footing, p).await), "plan_stale");
    let other = server(
        &f,
        Caller::authenticated("acct:other-principal").with_hosting_owner(false),
    )
    .await;
    assert_eq!(code(&confirm(&other, p).await), "plan_identity_mismatch");
    let mut missing = p.clone();
    missing["plan_id"] = json!("wpl1:unknown");
    assert_eq!(code(&confirm(&s, &missing).await), "plan_not_found");
    let misuse=call(&s,json!({"operation":"sql_write","plan_id":p["plan_id"],"target":p["target"],"effect_summary":p["effect_summary"],"arguments":request(Task::Review)})).await;
    assert!(matches!(
        code(&misuse),
        "raw_arguments_forbidden" | "execution_shape_rejected"
    ));
    sqlx::query("UPDATE write_plans SET state='expired' WHERE plan_id=?")
        .bind(p["plan_id"].as_str().unwrap())
        .execute(&mut store)
        .await
        .unwrap();
    assert_eq!(code(&confirm(&s, p).await), "plan_expired");
    let response = prepare(&s, request(Task::Review)).await;
    let p = approved(&response);
    sqlx::query("UPDATE write_plans SET payload=json_set(payload,'$.operation_evidence.selection.auth','tampered-version') WHERE plan_id=?").bind(p["plan_id"].as_str().unwrap()).execute(&mut store).await.unwrap();
    assert_eq!(code(&confirm(&s, p).await), "plan_integrity_failed");
    let response = prepare(&s, request(Task::Review)).await;
    let p = approved(&response);
    let confirmation = confirm(&s, p).await;
    assert_eq!(body(&confirmation)["source_dispatch_count"], 0);
    let state: String = sqlx::query_scalar("SELECT state FROM write_plans WHERE plan_id=?")
        .bind(p["plan_id"].as_str().unwrap())
        .fetch_one(&mut store)
        .await
        .unwrap();
    assert_eq!(state, "prepared");
    store.close().await.unwrap();
    assert_eq!(before, f.snapshot().await);
}

#[tokio::test]
async fn selected_scope_excludes_folder_even_if_storage_self_homed() {
    let f = Fixture::new().await;
    use sqlx::Connection;
    let mut probe = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(f.db.path()),
    )
    .await
    .unwrap();
    // Authoritative-state robustness, not a new public folder requirement.
    sqlx::query("UPDATE records SET home_id=id WHERE id=?")
        .bind(Label::F.id())
        .execute(&mut probe)
        .await
        .unwrap();
    probe.close().await.unwrap();
    let s = server(&f, f.selection_caller()).await;
    let mut r = request(Task::Archive);
    r["statement"] = json!(format!(
        "SELECT id FROM children WHERE id='{}' OR current_facet('triage_state')='ready'",
        Label::F.id()
    ));
    let before = f.snapshot().await;
    let p = prepare(&s, r).await;
    let p = approved(&p);
    assert_eq!(p["operation_evidence"]["selection"]["candidate_count"], 5);
    assert_eq!(
        p["effect"]["targets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["record_id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        Task::Archive.ids()
    );
    assert_eq!(before, f.snapshot().await);
}

#[tokio::test]
async fn selected_absent_governed_predicate_binds_identity_and_refuses_missing() {
    let f = Fixture::new().await;
    f.call_as(
        Caller::local(),
        "manage_vocabularies",
        json!({"action":"create_vocabulary","name":"selected_empty","id":"voc:selected_empty_one"}),
    )
    .await
    .unwrap();
    let shape = json!({"action":"write","id":global_user_schema_id(&f).await,"data":{"shapes":{"Document:note":{"facets":{"triage_state":{"values":["ready","hold"]},"review_state":{"values":["pending","approved"]},"empty_key":{"vocab":"selected_empty"}}}}}});
    f.call_as(Caller::local(), "manage_schema_config", shape.clone())
        .await
        .unwrap();
    let s = server(&f, f.selection_caller()).await;
    let mut r = request(Task::Archive);
    r["statement"] = json!(format!(
        "SELECT id FROM children WHERE id='{}' AND current_facet('empty_key') IS NULL",
        Label::A.id()
    ));
    let before = f.snapshot().await;
    let p = prepare(&s, r.clone()).await;
    let p = approved(&p);
    assert_eq!(p["effect"]["target_count"], 1);
    assert_eq!(before, f.snapshot().await);
    // Publicly change identity while restoring the exact same name-based shape
    // and leaving every current facet absent. No global revision is the oracle.
    f.call_as(Caller::local(),"manage_schema_config",json!({"action":"write","id":shape["id"],"data":{"shapes":{"Document:note":{"facets":{"triage_state":{"values":["ready","hold"]},"review_state":{"values":["pending","approved"]}}}}}})).await.unwrap();
    f.call_as(
        Caller::local(),
        "manage_vocabularies",
        json!({"action":"delete_vocabulary","vocabulary":"voc:selected_empty_one"}),
    )
    .await
    .unwrap();
    f.call_as(
        Caller::local(),
        "manage_vocabularies",
        json!({"action":"create_vocabulary","name":"selected_empty","id":"voc:selected_empty_two"}),
    )
    .await
    .unwrap();
    f.call_as(Caller::local(), "manage_schema_config", shape)
        .await
        .unwrap();
    let before = f.snapshot().await;
    assert_eq!(code(&confirm(&s, p).await), "plan_stale");
    approved(&prepare(&s, r.clone()).await);
    assert_eq!(before, f.snapshot().await);
    // Missing identity is a distinct privileged-storage robustness probe.
    use sqlx::Connection;
    let mut probe = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(f.db.path()),
    )
    .await
    .unwrap();
    sqlx::query("DELETE FROM vocabularies WHERE id='voc:selected_empty_two'")
        .execute(&mut probe)
        .await
        .unwrap();
    probe.close().await.unwrap();
    let before = f.snapshot().await;
    let rejected = prepare(&s, r).await;
    assert_eq!(code(&rejected), "preparation_rejected");
    assert!(body(&rejected).to_string().contains("missing or ambiguous"));
    assert_eq!(before, f.snapshot().await);
}

#[tokio::test]
async fn selected_stored_resolved_comment_is_included_and_eligibility_drift_stales() {
    let f = Fixture::new().await;
    let comment = "c0510000-0000-4000-8000-0000000000e1";
    f.call_as(Caller::local(),"create_record",json!({"id":comment,"type":"Annotation","kind":"comment","name":"Stored comment","lifecycle":"open","body":"A public concern.","home_id":Label::F.id(),"links":[{"target_id":Label::A.id(),"relationship":"part_of"}],"reason":"Construct ordinary comment before compiler."})).await.unwrap();
    f.call_as(Caller::local(),"update_record",json!({"id":comment,"lifecycle":"resolved","summary":"Resolved constructible concern.","reason":"Stored resolved roots remain ordinary."})).await.unwrap();
    let s = server(&f, f.selection_caller()).await;
    let before = f.snapshot().await;
    let p = prepare(&s, request(Task::Review)).await;
    let p = approved(&p);
    assert_eq!(p["operation_evidence"]["selection"]["candidate_count"], 6);
    assert_eq!(p["effect"]["target_count"], 2);
    assert_eq!(before, f.snapshot().await);
    f.call_as(Caller::local(),"update_record",json!({"id":comment,"body_append":" Same eligibility, distinct consumed body.","reason":"Bind the exact checked eligibility inputs."})).await.unwrap();
    let before = f.snapshot().await;
    assert_eq!(code(&confirm(&s, p).await), "plan_stale");
    assert_eq!(before, f.snapshot().await);
}

#[tokio::test]
async fn selected_unknown_kind_ignores_cross_vocabulary_diagnostic_alternatives() {
    let f = Fixture::new().await;
    // Legacy raw-kind robustness probe: X remains an ordinary, unselected
    // included candidate. Its diagnostic alternatives are not identity inputs.
    use sqlx::Connection;
    let mut probe = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(f.db.path()),
    )
    .await
    .unwrap();
    sqlx::query("UPDATE records SET kind='selected_unknown_kind' WHERE id=?")
        .bind(Label::X.id())
        .execute(&mut probe)
        .await
        .unwrap();
    probe.close().await.unwrap();
    let s = server(&f, f.selection_caller()).await;
    let before = f.snapshot().await;
    let p = prepare(&s, request(Task::Review)).await;
    let p = approved(&p);
    assert_eq!(p["operation_evidence"]["selection"]["candidate_count"], 5);
    assert_eq!(before, f.snapshot().await);
    let values = f
        .call_as(
            Caller::local(),
            "manage_vocabularies",
            json!({"action":"list_values","vocabulary":"voc:kind:Annotation","status":"active"}),
        )
        .await
        .unwrap();
    let metadata = values["values"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["value"] == "comment")
        .unwrap()["metadata"]
        .clone();
    f.call_as(Caller::local(),"manage_vocabularies",json!({"action":"propose_value","vocabulary":"voc:kind:Annotation","value":"selected_unknown_kind","metadata":metadata})).await.unwrap();
    let before = f.snapshot().await;
    assert_eq!(body(&confirm(&s, p).await)["committed"], false);
    assert_eq!(before, f.snapshot().await);
}

#[tokio::test]
async fn selected_existing_link_public_readd_frontier_drift_without_endpoint_sequence_change() {
    let f = Fixture::new().await;
    let s = server(&f, f.selection_caller()).await;
    let p = prepare(&s, request(Task::Relate)).await;
    let p = approved(&p);
    let before = f.snapshot().await;
    let endpoints = |snapshot: &super::sql_selected_write_fixtures::DomainSnapshot| {
        snapshot.rows["content_events"]
            .iter()
            .filter(|e| e["record_id"] == Label::B.id() || e["record_id"] == Label::D.id())
            .cloned()
            .collect::<Vec<_>>()
    };
    let endpoint_events = endpoints(&before);
    f.call("manage_links",json!({"action":"add","source_id":Label::B.id(),"target_id":Label::D.id(),"relationship":"relates_to"})).await;
    let after = f.snapshot().await;
    assert_eq!(
        endpoint_events,
        endpoints(&after),
        "relationship-only re-add cannot move endpoint content sequences"
    );
    assert_ne!(
        before.rows["relationship_events"],
        after.rows["relationship_events"]
    );
    assert_eq!(code(&confirm(&s, p).await), "plan_stale");
    assert_eq!(after, f.snapshot().await);
}

#[tokio::test]
async fn selected_authoritative_malformed_included_id_with_version_refuses_integrity() {
    for malformed in ["malformed-included-record", "", "native:", "native:bad\0id"] {
        for included in [true, false] {
            let f = Fixture::new().await; // Fixed public manifest before corruption/compiler.
            let original = if included {
                Label::A.id()
            } else {
                Label::H.id()
            };
            use sqlx::Connection;
            let mut c = sqlx::SqliteConnection::connect_with(
                &sqlx::sqlite::SqliteConnectOptions::new()
                    .filename(f.db.path())
                    .foreign_keys(false),
            )
            .await
            .unwrap();
            // AUTHORITATIVE STORAGE ROBUSTNESS ONLY: real prior content event,
            // projected facets and exact existing policy retained. Empty IDs
            // specifically exercise the first page; denied IDs remain excluded.
            sqlx::query("UPDATE records SET id=? WHERE id=?")
                .bind(malformed)
                .bind(original)
                .execute(&mut c)
                .await
                .unwrap();
            let guards:Vec<(String,String)>=sqlx::query_as("SELECT name,sql FROM sqlite_master WHERE type='trigger' AND tbl_name='content_events' AND upper(sql) LIKE '%BEFORE UPDATE%'").fetch_all(&mut c).await.unwrap();
            assert!(!guards.is_empty());
            for (name, _) in &guards {
                sqlx::query(&format!("DROP TRIGGER \"{}\"", name.replace('"', "\"\"")))
                    .execute(&mut c)
                    .await
                    .unwrap();
            }
            for table in ["facet_values", "content_events"] {
                sqlx::query(&format!("UPDATE {table} SET record_id=? WHERE record_id=?"))
                    .bind(malformed)
                    .bind(original)
                    .execute(&mut c)
                    .await
                    .unwrap();
            }
            for (_, sql) in &guards {
                sqlx::query(sql).execute(&mut c).await.unwrap();
            }
            let seq: i64 =
                sqlx::query_scalar("SELECT MAX(seq) FROM content_events WHERE record_id=?")
                    .bind(malformed)
                    .fetch_one(&mut c)
                    .await
                    .unwrap();
            assert!(seq > 0);
            c.close().await.unwrap();
            let s = server(&f, f.selection_caller()).await;
            let before = f.snapshot().await;
            let result = prepare(&s, request(Task::Review)).await;
            if included {
                assert_eq!(code(&result), "preparation_rejected");
                if !malformed.is_empty() {
                    assert!(!body(&result).to_string().contains(malformed), "{result}");
                }
                assert!(body(&result)["plan_id"].is_null());
            } else {
                assert_eq!(target_ids(approved(&result)), Task::Review.ids());
            }
            assert_eq!(before, f.snapshot().await);
        }
    }
}

async fn explicit_selection_policy(f: &Fixture, id: &str, cap: Option<&str>) {
    use super::sql_selected_write_fixtures::{SELECTION_ACCOUNT, SETUP_ACCOUNT};
    let listed = f
        .call_as(
            Caller::local(),
            "manage_record_policy",
            json!({"action":"list","record_id":id}),
        )
        .await
        .unwrap();
    let mut entries = vec![
        json!({"subject":{"kind":"account","account_id":SETUP_ACCOUNT},"capability":"manage"}),
    ];
    if let Some(cap) = cap {
        entries.push(
            json!({"subject":{"kind":"account","account_id":SELECTION_ACCOUNT},"capability":cap}),
        );
    }
    f.call_as(Caller::local(),"manage_record_policy",json!({"action":"replace","record_id":id,"entries":entries,"if_policy_revision":listed["policy_revision"],"reason":"Public authority delta for exact scoped acceptance."})).await.unwrap();
}
fn target_ids(p: &Value) -> Vec<String> {
    p["effect"]["targets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["record_id"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn selected_public_hidden_create_update_delete_and_hidden_only_are_invariant() {
    let f = Fixture::new().await;
    let hidden = "ec00b000-0000-4000-8000-000000000be1"; // Independent manifest BEFORE compiler.
    let s = server(&f, f.selection_caller()).await;
    let response = prepare(&s, request(Task::Review)).await;
    let p = approved(&response);
    f.call_as(Caller::local(),"create_record",json!({"id":hidden,"type":"Document","kind":"note","home_id":Label::F.id(),"name":"Hidden creation","facets":{"triage_state":"ready","review_state":"pending"},"reason":"Public hidden creation fixture."})).await.unwrap();
    explicit_selection_policy(&f, hidden, None).await;
    for phase in 0..3 {
        if phase == 1 {
            f.setup_call(
                "update_record",
                json!({"id":hidden,"name":"Hidden changed","reason":"Public hidden update."}),
            )
            .await;
        }
        if phase == 2 {
            f.setup_call(
                "delete_record",
                json!({"id":hidden,"reason":"Public hidden deletion."}),
            )
            .await;
        }
        let before = f.snapshot().await;
        let fresh = prepare(&s, request(Task::Review)).await;
        let fresh = approved(&fresh);
        assert_eq!(p["effect"], fresh["effect"]);
        assert_eq!(p["operation_evidence"], fresh["operation_evidence"]);
        assert_eq!(body(&confirm(&s, p).await)["preview_current"], true);
        let mut only = request(Task::Review);
        only["statement"] = json!(format!("SELECT id FROM children WHERE id='{hidden}'"));
        let hidden_only = prepare(&s, only.clone()).await;
        only["statement"] =
            json!("SELECT id FROM children WHERE name='No matching visible member'");
        let empty = prepare(&s, only).await;
        assert_eq!(body(&hidden_only)["error"], body(&empty)["error"]);
        assert_eq!(code(&hidden_only), code(&empty));
        assert_eq!(before, f.snapshot().await);
    }
}

#[tokio::test]
async fn selected_public_rehome_create_delete_and_visibility_membership_drift() {
    for case in [
        "rehome_out",
        "rehome_in",
        "create",
        "delete",
        "hide",
        "expose",
    ] {
        let f = Fixture::new().await;
        let new = "ec00b000-0000-4000-8000-000000000be2"; // Independent public ID before compiler.
        let s = server(&f, f.selection_caller()).await;
        let response = prepare(&s, request(Task::Review)).await;
        let p = approved(&response);
        let expected = match case {
            "rehome_out" => {
                f.setup_call("update_record",json!({"id":Label::B.id(),"home_id":Label::G.id(),"reason":"Public move out of source."})).await;
                vec![Label::A.id()]
            }
            "rehome_in" => {
                f.setup_call("update_record",json!({"id":Label::O.id(),"home_id":Label::F.id(),"reason":"Public move into source."})).await;
                vec![Label::A.id(), Label::B.id(), Label::O.id()]
            }
            "create" => {
                f.call_as(Caller::local(),"create_record",json!({"id":new,"type":"Document","kind":"note","home_id":Label::F.id(),"name":"Visible creation","facets":{"triage_state":"ready","review_state":"pending"},"reason":"Public visible source creation."})).await.unwrap();
                explicit_selection_policy(&f, new, Some("manage")).await;
                vec![Label::A.id(), Label::B.id(), new]
            }
            "delete" => {
                f.setup_call(
                    "delete_record",
                    json!({"id":Label::A.id(),"reason":"Public visible source deletion."}),
                )
                .await;
                vec![Label::B.id()]
            }
            "hide" => {
                explicit_selection_policy(&f, Label::A.id(), None).await;
                vec![Label::B.id()]
            }
            "expose" => {
                explicit_selection_policy(&f, Label::H.id(), Some("manage")).await;
                vec![Label::A.id(), Label::B.id(), Label::H.id()]
            }
            _ => unreachable!(),
        };
        let before = f.snapshot().await;
        let stale = confirm(&s, p).await;
        assert_eq!(code(&stale), "plan_stale", "case {case}: {stale}");
        let fresh = prepare(&s, request(Task::Review)).await;
        let mut expected = expected.into_iter().map(str::to_owned).collect::<Vec<_>>();
        expected.sort();
        assert_eq!(target_ids(approved(&fresh)), expected, "case {case}");
        assert_eq!(before, f.snapshot().await, "case {case}");
    }
}

#[tokio::test]
async fn selected_public_hidden_supersession_selected_archive_and_unselected_variant() {
    for task in [Task::Review, Task::Archive] {
        let f = Fixture::new().await;
        if task == Task::Review {
            f.setup_call("update_record",json!({"id":Label::B.id(),"facets":{"triage_state":"hold"},"reason":"Independent unselected B variant before compiler."})).await;
        }
        let s = server(&f, f.selection_caller()).await;
        let response = prepare(&s, request(task)).await;
        let p = approved(&response);
        let successors = if task == Task::Review {
            vec![Label::B]
        } else {
            vec![Label::A, Label::C]
        };
        for target in successors {
            f.setup_call("manage_links",json!({"action":"add","source_id":Label::H.id(),"target_id":target.id(),"relationship":"supersedes"})).await;
        }
        f.setup_call("update_record",json!({"id":Label::H.id(),"name":"Hidden superseder changed","reason":"Public hidden supersession delta."})).await;
        let before = f.snapshot().await;
        let fresh = prepare(&s, request(task)).await;
        let fresh = approved(&fresh);
        assert_eq!(p["effect"], fresh["effect"]);
        assert_eq!(p["operation_evidence"], fresh["operation_evidence"]);
        assert_eq!(body(&confirm(&s, p).await)["preview_current"], true);
        assert_eq!(before, f.snapshot().await);
    }
}

#[tokio::test]
async fn selected_public_folder_manage_destination_view_and_opacity() {
    for (id, cap, task) in [
        (Label::F, None, Task::Review),
        (Label::A, Some("edit"), Task::Archive),
        (Label::D, None, Task::Relate),
    ] {
        let f = Fixture::new().await;
        let s = server(&f, f.selection_caller()).await;
        let response = prepare(&s, request(task)).await;
        let p = approved(&response);
        explicit_selection_policy(&f, id.id(), cap).await;
        let before = f.snapshot().await;
        assert_eq!(code(&confirm(&s, p).await), "plan_stale");
        let refused = prepare(&s, request(task)).await;
        assert_eq!(code(&refused), "preparation_rejected");
        if id == Label::D {
            let mut missing = request(task);
            missing["write"]["target_id"] = json!("ec00b000-0000-4000-8000-000000000bee");
            let missing = prepare(&s, missing).await;
            assert_eq!(body(&refused)["error"], body(&missing)["error"]);
        }
        assert_eq!(before, f.snapshot().await);
    }
}

#[tokio::test]
async fn selected_public_link_contest_destination_version_and_archived_source() {
    let f = Fixture::new().await;
    let s = server(&f, f.selection_caller()).await;
    let response = prepare(&s, request(Task::Relate)).await;
    let p = approved(&response);
    f.setup_call("manage_links",json!({"action":"remove","source_id":Label::B.id(),"target_id":Label::D.id(),"relationship":"relates_to"})).await;
    let before = f.snapshot().await;
    assert_eq!(code(&confirm(&s, p).await), "plan_stale");
    let fresh = prepare(&s, request(Task::Relate)).await;
    let fresh = approved(&fresh);
    assert_eq!(
        fresh["effect"]["targets"][1]["operation"]["event_intent"]["kind"],
        "support_existing"
    );
    assert_eq!(before, f.snapshot().await);
    f.setup_call("update_record",json!({"id":Label::D.id(),"name":"Destination version changed","reason":"Public destination drift."})).await;
    let before = f.snapshot().await;
    assert_eq!(code(&confirm(&s, fresh).await), "plan_stale");
    let mut archived = request(Task::Relate);
    archived["statement"] = json!(format!(
        "SELECT id FROM children WHERE id='{}'",
        Label::C.id()
    ));
    let p = prepare(&s, archived).await;
    assert_eq!(target_ids(approved(&p)), vec![Label::C.id().to_owned()]);
    assert_eq!(
        approved(&p)["effect"]["targets"][0]["operation"]["event_intent"]["kind"],
        "create_proposition_and_support"
    );
    assert_eq!(before, f.snapshot().await);
}

#[tokio::test]
async fn selected_public_empty_text_raw_fields_all_atoms_and_escape_matrix() {
    let f = Fixture::new().await;
    f.setup_call(
        "update_record",
        json!({"id":Label::A.id(),"facets":{"empty":""},"reason":"Public empty current text."}),
    )
    .await;
    let s = server(&f, f.selection_caller()).await;
    let before = f.snapshot().await;
    for predicate in [
        "current_facet('empty')=''",
        "current_facet('empty') IS NOT NULL",
        "current_facet('empty') IN ('',NULL)",
        "NOT (current_facet('empty') <> '')",
        "(archived=FALSE AND type='Document') AND (kind='note' OR name='absent')",
        "archived=0 AND summary IS NULL",
        "archived NOT IN (TRUE,NULL) OR archived=false",
        "id IN (?1,?1)",
    ] {
        let mut r = request(Task::Review);
        r["statement"] = json!(format!(
            "SELECT id FROM children WHERE id='{}' AND ({predicate})",
            Label::A.id()
        ));
        if predicate.contains("?1") {
            r["parameters"] = json!([{"type":"text","value":Label::A.id()}]);
        }
        assert_eq!(
            target_ids(approved(&prepare(&s, r).await)),
            vec![Label::A.id().to_owned()],
            "{predicate}"
        );
    }
    for statement in [
        "WITH x AS (SELECT id FROM children) SELECT id FROM x",
        "SELECT DISTINCT id FROM children",
        "SELECT id FROM children UNION SELECT id FROM children",
        "SELECT id FROM children JOIN children x",
        "SELECT id FROM children WHERE EXISTS(SELECT 1)",
        "SELECT id FROM children WHERE id IN (SELECT id FROM children)",
        "SELECT id FROM children GROUP BY id",
        "SELECT id FROM children ORDER BY id",
        "SELECT id FROM children LIMIT 1 OFFSET 0",
        "SELECT count(id) FROM children",
        "SELECT id FROM children WHERE CAST(name AS TEXT)='A'",
        "SELECT id FROM children WHERE CASE WHEN archived THEN 1 ELSE 0 END=0",
        "SELECT id FROM children WHERE name LIKE '%'",
        "SELECT id FROM children WHERE name GLOB '*'",
        "SELECT id FROM children WHERE rowid=1",
        "SELECT id FROM main.children",
        "SELECT id AS other FROM children",
        "SELECT * FROM children",
        "SELECT id FROM children; SELECT id FROM children",
        "DELETE FROM children",
        "PRAGMA table_info(records)",
        "SELECT id FROM children WHERE current_facet('empty','other')=''",
        "SELECT id FROM children WHERE 1",
    ] {
        let mut r = request(Task::Review);
        r["statement"] = json!(statement);
        assert!(
            matches!(
                code(&prepare(&s, r).await),
                "preparation_validation_failed" | "preparation_rejected"
            ),
            "{statement}"
        );
    }
    assert_eq!(before, f.snapshot().await);
}

#[tokio::test]
async fn selected_public_program_suggestion_setter_guards_and_required_values() {
    let f = Fixture::new().await;
    let program = "ec00b000-0000-4000-8000-000000000be3";
    let suggestion = "ec00b000-0000-4000-8000-000000000be4";
    // Public manifests and unsupported path construction precede compiler.
    f.call_as(Caller::local(),"create_record",json!({"id":program,"type":"Program","kind":"recipe","name":"Program guard","body":"summarize changes","home_id":Label::F.id(),"facets":{"runtime":"native.recipe.v1"},"reason":"Public Program setter guard fixture."})).await.unwrap();
    f.call_as(Caller::local(),"create_record",json!({"id":suggestion,"type":"Annotation","kind":"suggestion","name":"Suggestion guard","home_id":Label::F.id(),"links":[{"target_id":Label::A.id(),"relationship":"part_of"}],"lifecycle":"open","body":"replacement","facets":{"proposal.precondition":"none"},"reason":"Public suggestion setter guard fixture."})).await.unwrap();
    let s = server(&f, Caller::local()).await;
    let before = f.snapshot().await;
    for id in [program, suggestion] {
        let mut r = request(Task::Review);
        r["statement"] = json!(format!("SELECT id FROM children WHERE id='{id}'"));
        let refused = prepare(&s, r.clone()).await;
        assert_eq!(code(&refused), "preparation_rejected");
        assert!(
            body(&refused)
                .to_string()
                .contains("unsupported selected compiler"),
            "{refused}"
        );
        r["write"] = json!({"op":"archive"});
        approved(&prepare(&s, r).await);
    }
    assert_eq!(before, f.snapshot().await);
    f.call_as(Caller::local(),"manage_schema_config",json!({"action":"write","id":global_user_schema_id(&f).await,"data":{"shapes":{"Document:note":{"facets":{"triage_state":{"values":["ready","hold"]},"review_state":{"values":["pending","approved"],"required":true}}}}}})).await.unwrap();
    let s = server(&f, f.selection_caller()).await;
    let before = f.snapshot().await;
    approved(&prepare(&s, request(Task::Review)).await); // set-only cannot worsen required presence.
    let mut r = request(Task::Review);
    r["write"]["value"] = json!("outside-vocabulary");
    assert_eq!(code(&prepare(&s, r).await), "preparation_rejected");
    assert_eq!(before, f.snapshot().await);
}

#[tokio::test]
async fn selected_public_owner_binding_and_inheritance_dependencies_stale_equal_caps() {
    use native_ce::identity::hosted::{
        reconcile_hosted_identity, HostedMembershipArrival, HostedMembershipRole,
        HostedMembershipSource,
    };
    let f = Fixture::new().await;
    let arrival = HostedMembershipArrival::new(
        HostedMembershipRole::Owner,
        HostedMembershipSource::Direct,
        "2026-10-03T00:00:00Z".into(),
    )
    .unwrap();
    // Real engine onboarding API, not a fabricated reserved account binding.
    let account = reconcile_hosted_identity(
        &f.db,
        "selected-owner@example.test",
        "selected-owner-catalog",
        &arrival,
        None,
    )
    .await
    .unwrap();
    let person: String = sqlx::query_scalar(
        "SELECT record_id FROM bindings WHERE system='account' AND identifier=? AND is_canonical=1",
    )
    .bind(&account)
    .fetch_one(f.db.pool())
    .await
    .unwrap();
    for (id, cap) in [
        (Label::F, "view"),
        (Label::A, "manage"),
        (Label::B, "manage"),
    ] {
        let listed = f
            .call_as(
                Caller::local(),
                "manage_record_policy",
                json!({"action":"list","record_id":id.id()}),
            )
            .await
            .unwrap();
        // Public list enriches account subjects with a person display object;
        // that read projection is not the closed policy-write wire shape.
        let entries =
            vec![json!({"subject":{"kind":"account","account_id":account},"capability":cap})];
        f.call_as(Caller::local(),"manage_record_policy",json!({"action":"replace","record_id":id.id(),"entries":entries,"if_policy_revision":listed["policy_revision"],"reason":"Public authority for independently reconciled owner account."})).await.unwrap();
    }
    let caller = Caller::authenticated(&account).with_hosting_owner(false);
    let s = server(&f, caller.clone()).await;
    let p = prepare(&s, request(Task::Review)).await;
    let p = approved(&p);
    f.call_as(
        caller.with_hosting_owner(true),
        "claim_unowned_record",
        json!({"record_id":Label::A.id(),"reason":"Public exact ownership recovery."}),
    )
    .await
    .unwrap();
    let before = f.snapshot().await;
    assert_eq!(code(&confirm(&s, p).await), "plan_stale");
    let p = prepare(&s, request(Task::Review)).await;
    let p = approved(&p);
    assert_eq!(target_ids(p), Task::Review.ids());
    assert_eq!(before, f.snapshot().await);
    // Account bindings are reserved durable engine identities; ordinary tools
    // cannot remove them. This exact EXISTS-input drift is STORAGE ROBUSTNESS.
    use sqlx::Connection;
    let mut c = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(f.db.path()),
    )
    .await
    .unwrap();
    sqlx::query("UPDATE bindings SET is_canonical=0 WHERE record_id=? AND system='account' AND identifier=?").bind(&person).bind(&account).execute(&mut c).await.unwrap();
    c.close().await.unwrap();
    let before = f.snapshot().await;
    assert_eq!(code(&confirm(&s, p).await), "plan_stale");
    approved(&prepare(&s, request(Task::Review)).await);
    assert_eq!(before, f.snapshot().await);
    let p = prepare(&s, request(Task::Review)).await;
    let p = approved(&p);
    let listed = f
        .call_as(
            Caller::local(),
            "manage_record_policy",
            json!({"action":"list","record_id":Label::A.id()}),
        )
        .await
        .unwrap();
    f.call_as(Caller::local(),"manage_record_policy",json!({"action":"restore_inheritance","record_id":Label::A.id(),"if_policy_revision":listed["policy_revision"],"reason":"Public inheritance restoration to folder View."})).await.unwrap();
    let before = f.snapshot().await;
    assert_eq!(code(&confirm(&s, p).await), "plan_stale");
    assert_eq!(
        code(&prepare(&s, request(Task::Review)).await),
        "preparation_rejected"
    );
    assert_eq!(before, f.snapshot().await);
}

#[tokio::test]
async fn selected_public_current_governed_alias_deprecation_and_missing_ref_boundary() {
    for delta in ["alias", "deprecate", "missing_ref"] {
        let f = Fixture::new().await;
        f.call_as(
            Caller::local(),
            "manage_vocabularies",
            json!({"action":"create_vocabulary","name":"current_lane","id":"voc:current_lane"}),
        )
        .await
        .unwrap();
        let mut tokens = Vec::new();
        for value in ["ready", "other"] {
            let v = f
                .call_as(
                    Caller::local(),
                    "manage_vocabularies",
                    json!({"action":"propose_value","vocabulary":"voc:current_lane","value":value}),
                )
                .await
                .unwrap();
            let id = v["value_id"]
                .as_str()
                .or_else(|| v["id"].as_str())
                .unwrap()
                .to_owned();
            f.call_as(
                Caller::local(),
                "manage_vocabularies",
                json!({"action":"promote_value","value_id":id}),
            )
            .await
            .unwrap();
            tokens.push(id);
        }
        let schema = global_user_schema_id(&f).await;
        let governed = json!({"action":"write","id":schema,"data":{"shapes":{"Document:note":{"facets":{"triage_state":{"values":["ready","hold"]},"review_state":{"values":["pending","approved"]},"current_lane":{"vocab":"voc:current_lane"}}}}}});
        f.call_as(Caller::local(), "manage_schema_config", governed.clone())
            .await
            .unwrap();
        f.setup_call("update_record",json!({"id":Label::A.id(),"facets":{"current_lane":"ready"},"reason":"Public canonical current token."})).await;
        let s = server(&f, f.selection_caller()).await;
        let mut r = request(Task::Review);
        r["statement"] = json!(format!(
            "SELECT id FROM children WHERE id='{}' AND current_facet('current_lane')='ready'",
            Label::A.id()
        ));
        let p = prepare(&s, r.clone()).await;
        let p = approved(&p);
        match delta {
            "alias" => {
                f.call_as(
                    Caller::local(),
                    "manage_vocabularies",
                    json!({"action":"alias_value","value_id":tokens[0],"canonical_id":tokens[1]}),
                )
                .await
                .unwrap();
            }
            "deprecate" => {
                f.call_as(
                    Caller::local(),
                    "manage_vocabularies",
                    json!({"action":"deprecate_value","value_id":tokens[0]}),
                )
                .await
                .unwrap();
            }
            "missing_ref" => {
                let mut open = governed.clone();
                open["data"]["shapes"]["Document:note"]["facets"]
                    .as_object_mut()
                    .unwrap()
                    .remove("current_lane");
                f.call_as(Caller::local(), "manage_schema_config", open)
                    .await
                    .unwrap();
                f.setup_call("update_record",json!({"id":Label::A.id(),"facets":{"current_lane":"ready"},"reason":"Public open carrier clears governing reference."})).await;
                f.call_as(Caller::local(), "manage_schema_config", governed)
                    .await
                    .unwrap();
            }
            _ => unreachable!(),
        }
        let before = f.snapshot().await;
        assert_eq!(code(&confirm(&s, p).await), "plan_stale", "{delta}");
        assert_eq!(
            code(&prepare(&s, r).await),
            "preparation_rejected",
            "{delta}"
        );
        assert_eq!(before, f.snapshot().await);
    }
}

#[tokio::test]
async fn selected_public_message_content_route_and_expectation_immutability() {
    use native_ce::identity::hosted::{
        reconcile_hosted_identity, HostedMembershipArrival, HostedMembershipRole,
        HostedMembershipSource,
    };
    let f = Fixture::new().await;
    let message = "ec00b000-0000-4000-8000-000000000be6";
    let arrival = HostedMembershipArrival::new(
        HostedMembershipRole::Owner,
        HostedMembershipSource::Direct,
        "2026-10-03T00:00:00Z".into(),
    )
    .unwrap();
    let account = reconcile_hosted_identity(
        &f.db,
        "selected-message@example.test",
        "selected-message-catalog",
        &arrival,
        Some("native/selected-message"),
    )
    .await
    .unwrap();
    let person: String = sqlx::query_scalar(
        "SELECT record_id FROM bindings WHERE system='account' AND identifier=? AND is_canonical=1",
    )
    .bind(&account)
    .fetch_one(f.db.pool())
    .await
    .unwrap();
    // Public sender-only draft with actual reconciled portable sender identity.
    f.call_as(Caller::local(),"create_record",json!({"id":message,"type":"Message","kind":"message","name":"Draft route boundary","owner_id":person,"home_id":Label::F.id(),"body":"Public draft body","addressed_to":[],"facets":{"expectation":"none"},"reason":"Public sender-only Message fixture."})).await.unwrap();
    let s = server(&f, Caller::local()).await;
    let mut r = request(Task::Relate);
    r["statement"] = json!(format!("SELECT id FROM children WHERE id='{message}'"));
    let before = f.snapshot().await;
    let refused = prepare(&s, r.clone()).await;
    assert_eq!(code(&refused), "preparation_rejected");
    assert!(body(&refused).to_string().contains("content-owned"));
    r["write"] = json!({"op":"set_facet","key":"expectation","value":"reply"});
    let refused = prepare(&s, r).await;
    assert_eq!(code(&refused), "preparation_rejected");
    assert!(body(&refused).to_string().contains("immutable"));
    assert_eq!(before, f.snapshot().await);
    // The separately public singular compatibility route is content-owned.
    f.call_as(Caller::local(),"manage_links",json!({"action":"add","source_id":message,"target_id":Label::D.id(),"relationship":"relates_to"})).await.unwrap();
    let row:(i64,i64)=sqlx::query_as("SELECT (SELECT COUNT(*) FROM links WHERE source_id=? AND target_id=? AND relationship='relates_to'),(SELECT COUNT(*) FROM relationship_endpoints WHERE record_id=?)").bind(message).bind(Label::D.id()).bind(message).fetch_one(f.db.pool()).await.unwrap();
    assert_eq!(row, (1, 0));
}

#[tokio::test]
async fn selected_public_destination_type_correction_stales_and_retired_projection_refuses() {
    let f = Fixture::new().await;
    let destination = "ec00b000-0000-4000-8000-000000000be7";
    f.call_as(Caller::local(),"create_record",json!({"id":destination,"type":"Document","kind":"note","name":"Type drift destination","reason":"Public destination without existing relationships."})).await.unwrap();
    let s = server(&f, Caller::local()).await;
    let mut r = request(Task::Relate);
    r["write"]["target_id"] = json!(destination);
    let p = prepare(&s, r).await;
    let p = approved(&p);
    let correction=s.handle_message(json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"records_write","arguments":{"operation":"correct_record_type","arguments":{"record_id":destination,"target_type":"Resolution","target_kind":"decision","reason":"Public type correction for scoped destination drift."}}}})).await.unwrap();
    let c = approved(&correction);
    let changed=s.handle_message(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"records_write","arguments":{"operation":"correct_record_type","plan_id":c["plan_id"],"target":c["target"],"effect_summary":c["effect_summary"]}}})).await.unwrap();
    assert!(body(&changed)["plan_error"].is_null(), "{changed}");
    let actual: String = sqlx::query_scalar("SELECT type FROM records WHERE id=?")
        .bind(destination)
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    assert_eq!(actual, "Resolution");
    let before = f.snapshot().await;
    assert_eq!(code(&confirm(&s, p).await), "plan_stale");
    assert_eq!(before, f.snapshot().await);
    let p = prepare(&s, request(Task::Relate)).await;
    let p = approved(&p);
    // No ordinary retirement producer exists (kernel/federation test events
    // only). This is privileged retired PROJECTION robustness, not public API.
    use sqlx::Connection;
    let mut c = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(f.db.path()),
    )
    .await
    .unwrap();
    sqlx::query("UPDATE relationships SET status='retired' WHERE relationship_id IN (SELECT relationship_id FROM relationship_endpoints WHERE record_id=?)").bind(Label::B.id()).execute(&mut c).await.unwrap();
    c.close().await.unwrap();
    let before = f.snapshot().await;
    assert_eq!(code(&confirm(&s, p).await), "plan_stale");
    assert_eq!(
        code(&prepare(&s, request(Task::Relate)).await),
        "preparation_rejected"
    );
    assert_eq!(before, f.snapshot().await);
}
