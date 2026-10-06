//! Route qualification, independent public protocol manifests before compiler.
//! These fixtures do not replace the independently fixed integration oracles.
use super::*;
use crate::mcp::{register_allowlisted_experimental_tools, ExperimentalExecutors};
use sqlx::{Connection, Row};
use std::sync::atomic::{AtomicI64, Ordering};
const F: &str = "ec00b000-0000-4000-8000-000000000bf1";
const A: &str = "ec00b000-0000-4000-8000-000000000bf2";
const B: &str = "ec00b000-0000-4000-8000-000000000bf3";
const D: &str = "ec00b000-0000-4000-8000-000000000bf4";
struct Fixture {
    db: crate::Db,
    server: Arc<ExecutorPrototypeStdioServer>,
}
impl Fixture {
    async fn new() -> Self {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut r = ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut r).unwrap();
        crate::mcp::register_surface_tools(&mut r).unwrap();
        let experimental = ExperimentalExecutors::from_env_value(Some("sql_write".into())).unwrap();
        register_allowlisted_experimental_tools(&mut r, &experimental).unwrap();
        for args in [
            json!({"id":F,"type":"Collection","kind":"folder","persistence":"enduring","name":"Protocol F","reason":"Independent public protocol scope."}),
            json!({"id":A,"type":"Document","kind":"note","home_id":F,"name":"Protocol A","facets":{"triage":"ready","review":"pending"},"reason":"Independent public protocol A."}),
            json!({"id":B,"type":"Document","kind":"note","home_id":F,"name":"Protocol B","facets":{"triage":"hold","review":"pending"},"reason":"Independent public protocol B."}),
            json!({"id":D,"type":"Document","kind":"note","name":"Protocol D","reason":"Independent public destination."}),
        ] {
            r.call(db.clone(), Caller::local(), "create_record", args)
                .await
                .unwrap();
        }
        r.call(
            db.clone(),
            Caller::local(),
            "manage_links",
            json!({"action":"add","source_id":A,"target_id":D,"relationship":"relates_to"}),
        )
        .await
        .unwrap();
        db.drain_captures_for_tests().await;
        let server = Arc::new(
            ExecutorPrototypeStdioServer::new_with_telemetry_and_experimental(
                Arc::new(r),
                db.clone(),
                Caller::local(),
                None,
                super::super::ExecutorTelemetryContext::new(
                    Arc::new(super::super::telemetry::TestTelemetrySink::default()),
                    7,
                )
                .unwrap(),
                experimental,
            )
            .await
            .unwrap(),
        );
        Self { db, server }
    }
    fn request(op: &str) -> Value {
        json!({"operation":"sql_write","arguments":{"selection_contract":selected::CONTRACT,"folder_id":F,"statement":"SELECT id FROM children WHERE current_facet('triage')='ready'","write":match op {"set_facet"=>json!({"op":op,"key":"review","value":"approved"}),"add_link"=>json!({"op":op,"target_id":D}),_=>json!({"op":"archive"})},"reason":"Qualify scoped preview route."}})
    }
    async fn call(&self, args: Value) -> Value {
        self.server.handle_message(message(args)).await.unwrap()
    }
    async fn prepare(&self, op: &str) -> Value {
        let v = self.call(Self::request(op)).await;
        assert!(body(&v)["plan_id"].is_string(), "{v}");
        v
    }
    async fn public(&self, tool: &str, args: Value) -> Value {
        self.server
            .registry
            .call(self.db.clone(), Caller::local(), tool, args)
            .await
            .unwrap()
    }
    async fn store(&self) -> sqlx::SqliteConnection {
        let p = self.db.path().canonicalize().unwrap();
        let n = p.file_name().unwrap().to_str().unwrap();
        sqlx::SqliteConnection::connect_with(
            &sqlx::sqlite::SqliteConnectOptions::new()
                .filename(p.with_file_name(format!("{n}.write-plans.sqlite3"))),
        )
        .await
        .unwrap()
    }
    fn no_attempts(&self) {
        let r = self.server.write_runtime.as_ref().unwrap();
        assert_eq!(r.claim_attempts.load(Ordering::Relaxed), 0);
        assert_eq!(r.dispatch_attempts.load(Ordering::Relaxed), 0);
    }
    async fn audit(&self) -> Vec<(String, Vec<Vec<String>>)> {
        self.db.drain_captures_for_tests().await;
        let tables:Vec<String>=sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").fetch_all(self.db.pool()).await.unwrap();
        let mut all = Vec::new();
        for table in tables {
            let quote = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
            let cols = sqlx::query(&format!("PRAGMA table_info({})", quote(&table)))
                .fetch_all(self.db.pool())
                .await
                .unwrap();
            let projections = cols
                .iter()
                .map(|r| format!("quote({})", quote(&r.get::<String, _>("name"))))
                .collect::<Vec<_>>()
                .join(",");
            let rows = sqlx::query(&format!(
                "SELECT {projections} FROM {} LIMIT 5001",
                quote(&table)
            ))
            .fetch_all(self.db.pool())
            .await
            .unwrap();
            assert!(rows.len() <= 5000, "bounded audit: {table}");
            let mut rows = rows
                .iter()
                .map(|r| {
                    (0..cols.len())
                        .map(|i| r.get::<String, _>(i))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            rows.sort();
            all.push((table, rows));
        }
        all
    }
}
fn message(args: Value) -> Value {
    json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sql_write","arguments":args}})
}
fn body(v: &Value) -> &Value {
    &v["result"]["structuredContent"]
}
fn execution(v: &Value) -> Value {
    let p = body(v);
    json!({"operation":"sql_write","plan_id":p["plan_id"],"target":p["target"],"effect_summary":p["effect_summary"]})
}
fn code(v: &Value) -> &str {
    body(v)["plan_error"]["code"]
        .as_str()
        .unwrap_or_else(|| panic!("{v}"))
}

#[tokio::test]
async fn selected_valid_signature_version_families_and_projection_integrity() {
    let f = Fixture::new().await;
    let mut c = f.store().await;
    let before = f.audit().await;
    for key in [
        "contract",
        "grammar",
        "source_schema",
        "auth",
        "eligibility",
        "schema",
        "effect_profile",
        "encoding",
    ] {
        for missing in [false, true] {
            let prepared = f.prepare("archive").await;
            let mut plan: WritePlan = serde_json::from_value(
                sqlx::query_scalar::<_, String>("SELECT payload FROM write_plans WHERE plan_id=?")
                    .bind(body(&prepared)["plan_id"].as_str().unwrap())
                    .fetch_one(&mut c)
                    .await
                    .unwrap()
                    .parse::<Value>()
                    .unwrap(),
            )
            .unwrap();
            if missing {
                plan.operation_evidence["selection"]
                    .as_object_mut()
                    .unwrap()
                    .remove(key);
            } else {
                plan.operation_evidence["selection"][key] = json!("unsupported.v999");
            }
            let runtime = f.server.write_runtime.as_ref().unwrap();
            plan.integrity = runtime
                .store
                .seal(&plan.signing_key_id, &integrity_payload(&plan))
                .await
                .unwrap();
            runtime.verify(&plan).await.unwrap(); // Valid signature, not a generic HMAC failure.
            sqlx::query("UPDATE write_plans SET payload=? WHERE plan_id=?")
                .bind(serde_json::to_string(&plan).unwrap())
                .bind(&plan.id)
                .execute(&mut c)
                .await
                .unwrap();
            let refused = f.call(execution(&prepared)).await;
            assert_eq!(code(&refused), "plan_contract_mismatch", "{key}/{missing}");
            f.no_attempts();
        }
    }
    for key in [
        "folder_digest",
        "source_digest",
        "authority_digest",
        "schema_digest",
        "selected_versions_digest",
        "effect_dependencies_digest",
        "approval_digest",
        "request_digest",
    ] {
        let p = f.prepare("set_facet").await;
        sqlx::query("UPDATE write_plans SET payload=json_set(payload,?,?) WHERE plan_id=?")
            .bind(format!("$.operation_evidence.selection.{key}"))
            .bind("tampered")
            .bind(body(&p)["plan_id"].as_str().unwrap())
            .execute(&mut c)
            .await
            .unwrap();
        assert_eq!(
            code(&f.call(execution(&p)).await),
            "plan_integrity_failed",
            "{key}"
        );
        f.no_attempts();
    }
    let p = f.prepare("archive").await;
    let mut plan: WritePlan = serde_json::from_str(
        &sqlx::query_scalar::<_, String>("SELECT payload FROM write_plans WHERE plan_id=?")
            .bind(body(&p)["plan_id"].as_str().unwrap())
            .fetch_one(&mut c)
            .await
            .unwrap(),
    )
    .unwrap();
    plan.revalidation_arguments = json!({"statement":format!("SELECT id AS record_id, 'archive' AS op, NULL AS key, NULL AS value FROM records WHERE id='{A}'"),"parameters":[],"reason":"Qualify scoped preview route."});
    plan.revalidation_arguments_digest = digest(&plan.revalidation_arguments).unwrap();
    let runtime = f.server.write_runtime.as_ref().unwrap();
    plan.integrity = runtime
        .store
        .seal(&plan.signing_key_id, &integrity_payload(&plan))
        .await
        .unwrap();
    runtime.verify(&plan).await.unwrap();
    sqlx::query("UPDATE write_plans SET payload=? WHERE plan_id=?")
        .bind(serde_json::to_string(&plan).unwrap())
        .bind(&plan.id)
        .execute(&mut c)
        .await
        .unwrap();
    let misuse = f.call(execution(&p)).await;
    assert_eq!(code(&misuse), "plan_stale");
    f.no_attempts();
    assert_eq!(before, f.audit().await);
    c.close().await.unwrap();
}

#[tokio::test]
async fn selected_sql_final_reload_success_error_races_and_clock_expiry() {
    for error_path in [false, true] {
        for delta in [
            "missing",
            "payload",
            "key",
            "expiry",
            "clock",
            "executing",
            "indeterminate",
            "completed",
            "unavailable",
        ] {
            let f = Fixture::new().await;
            let p = f.prepare("archive").await;
            if error_path {
                f.public("update_record",json!({"id":A,"name":"Public stale input","reason":"Deliberate delta before error audit."})).await;
            }
            let before = f.audit().await;
            let gate = DispatchGate::new();
            let clock = Arc::new(AtomicI64::new(now_ms()));
            let pending = {
                let s = Arc::clone(&f.server);
                let args = execution(&p);
                let g = Arc::clone(&gate);
                let clock = Arc::clone(&clock);
                tokio::spawn(async move {
                    SQL_TEST_CLOCK
                        .scope(
                            clock,
                            SQL_RELOAD_GATE.scope(g, s.handle_message(message(args))),
                        )
                        .await
                        .unwrap()
                })
            };
            gate.entered.acquire().await.unwrap().forget();
            let mut c = f.store().await;
            let id = body(&p)["plan_id"].as_str().unwrap();
            let expected = match delta {
                "missing" => {
                    sqlx::query("DELETE FROM write_plans WHERE plan_id=?")
                        .bind(id)
                        .execute(&mut c)
                        .await
                        .unwrap();
                    "plan_not_found"
                }
                "payload" => {
                    sqlx::query("UPDATE write_plans SET payload=json_set(payload,'$.nonce','race') WHERE plan_id=?").bind(id).execute(&mut c).await.unwrap();
                    "plan_integrity_failed"
                }
                "key" => {
                    sqlx::query("INSERT INTO write_plan_keys(key_id,secret,status,created_at_ms,retired_at_ms) VALUES('unknown-race-key',zeroblob(32),'retired',1,2)").execute(&mut c).await.unwrap();
                    sqlx::query("UPDATE write_plans SET key_id='unknown-race-key' WHERE plan_id=?")
                        .bind(id)
                        .execute(&mut c)
                        .await
                        .unwrap();
                    "plan_integrity_failed"
                }
                "expiry" => {
                    sqlx::query(
                        "UPDATE write_plans SET expires_at_ms=expires_at_ms+1 WHERE plan_id=?",
                    )
                    .bind(id)
                    .execute(&mut c)
                    .await
                    .unwrap();
                    "plan_integrity_failed"
                }
                "clock" => {
                    clock.fetch_add(600001, Ordering::Relaxed);
                    "plan_expired"
                }
                "unavailable" => {
                    sqlx::query("DROP TABLE write_plans")
                        .execute(&mut c)
                        .await
                        .unwrap();
                    "plan_store_unavailable"
                }
                state => {
                    sqlx::query("UPDATE write_plans SET state=?,attempt_id='test-attempt',execution_owner='test-owner',started_at_ms=1,completed_at_ms=2,result=? WHERE plan_id=?").bind(state).bind(serde_json::to_string(&json!({"retained_replay":true})).unwrap()).bind(id).execute(&mut c).await.unwrap();
                    if state == "completed" {
                        if error_path {
                            "retained_replay"
                        } else {
                            "plan_store_conflict"
                        }
                    } else if error_path {
                        "plan_execution_indeterminate"
                    } else {
                        "plan_store_conflict"
                    }
                }
            };
            c.close().await.unwrap();
            gate.release.add_permits(1);
            let response = pending.await.unwrap();
            if expected == "retained_replay" {
                assert!(
                    response.to_string().contains("retained_replay"),
                    "{response}"
                );
                assert_ne!(body(&response)["preview_current"], true);
            } else {
                assert_eq!(
                    code(&response),
                    expected,
                    "{delta}/{error_path}: {response}"
                );
            }
            f.no_attempts();
            assert_eq!(before, f.audit().await, "{delta}/{error_path}");
        }
    }
}

#[tokio::test]
async fn selected_public_snapshot_interleaves_prepare_and_confirm_all_scoped_families() {
    for confirmation in [false, true] {
        for family in ["source", "filter", "schema", "permission", "proposition"] {
            let f = Fixture::new().await;
            let op = if family == "proposition" {
                "add_link"
            } else {
                "set_facet"
            };
            let p = f.prepare(op).await;
            let gate = DispatchGate::new();
            let pending = {
                let s = Arc::clone(&f.server);
                let args = if confirmation {
                    execution(&p)
                } else {
                    Fixture::request(op)
                };
                let g = Arc::clone(&gate);
                tokio::spawn(async move {
                    selected::SNAPSHOT_GATE
                        .scope(g, s.handle_message(message(args)))
                        .await
                        .unwrap()
                })
            };
            gate.entered.acquire().await.unwrap().forget();
            match family {
                "source" => {
                    f.public("update_record",json!({"id":B,"home_id":"native:unfiled","reason":"Public source membership during snapshot."})).await;
                }
                "filter" => {
                    f.public("update_record",json!({"id":B,"facets":{"triage":"ready"},"reason":"Public predicate during snapshot."})).await;
                }
                "schema" => {
                    f.public("manage_schema_config",json!({"action":"write","data":{"shapes":{"Document:note":{"facets":{"triage":{"values":["ready","hold"]},"review":{"values":["pending","approved"]}}}}}})).await;
                }
                "permission" => {
                    let l = f
                        .public(
                            "manage_record_policy",
                            json!({"action":"list","record_id":A}),
                        )
                        .await;
                    f.public("manage_record_policy",json!({"action":"replace","record_id":A,"entries":[{"subject":{"kind":"account","account_id":"acct:snapshot-equal-cap"},"capability":"view"}],"if_policy_revision":l["policy_revision"],"reason":"Public equal-capability authority during snapshot."})).await;
                }
                "proposition" => {
                    f.public("manage_links",json!({"action":"add","source_id":A,"target_id":D,"relationship":"relates_to"})).await;
                }
                _ => unreachable!(),
            }
            let before = f.audit().await;
            gate.release.add_permits(1);
            let response = pending.await.unwrap();
            if confirmation {
                assert_eq!(
                    body(&response)["preview_current"],
                    true,
                    "{family}: {response}"
                );
            } else {
                assert_eq!(body(&response)["effect"], body(&p)["effect"]);
                assert_eq!(
                    body(&response)["operation_evidence"],
                    body(&p)["operation_evidence"]
                );
            }
            assert_eq!(code(&f.call(execution(&p)).await), "plan_stale", "{family}");
            let fresh = f.prepare(op).await;
            assert_ne!(
                body(&fresh)["operation_evidence"],
                body(&p)["operation_evidence"]
            );
            f.no_attempts();
            assert_eq!(before, f.audit().await, "{family}/{confirmation}");
        }
    }
}

#[tokio::test]
async fn selected_all_operations_infrastructure_integrity_and_error_attempts() {
    for op in ["set_facet", "add_link", "archive"] {
        let f = Fixture::new().await;
        let p = f.prepare(op).await;
        let before = f.audit().await;
        let confirmed = f.call(execution(&p)).await;
        assert_eq!(body(&confirmed)["preview_current"], true);
        let ttl_before: i64 =
            sqlx::query_scalar("SELECT expires_at_ms FROM write_plans WHERE plan_id=?")
                .bind(body(&p)["plan_id"].as_str().unwrap())
                .fetch_one(&mut f.store().await)
                .await
                .unwrap();
        assert_eq!(body(&f.call(execution(&p)).await)["preview_current"], true);
        let mut c = f.store().await;
        let ttl_after: i64 =
            sqlx::query_scalar("SELECT expires_at_ms FROM write_plans WHERE plan_id=?")
                .bind(body(&p)["plan_id"].as_str().unwrap())
                .fetch_one(&mut c)
                .await
                .unwrap();
        assert_eq!(ttl_before, ttl_after);
        sqlx::query("UPDATE write_plans SET payload=json_set(payload,'$.operation_evidence.selection.approval_digest','bad') WHERE plan_id=?").bind(body(&p)["plan_id"].as_str().unwrap()).execute(&mut c).await.unwrap();
        assert_eq!(code(&f.call(execution(&p)).await), "plan_integrity_failed");
        f.no_attempts();
        assert_eq!(before, f.audit().await);
        let p = f.prepare(op).await;
        // Privileged relevant-kind identity corruption causes an actual Engine
        // normalization/storage failure, not a semantic selection denial.
        let mut corrupt = sqlx::SqliteConnection::connect_with(
            &sqlx::sqlite::SqliteConnectOptions::new().filename(f.db.path()),
        )
        .await
        .unwrap();
        sqlx::query("PRAGMA ignore_check_constraints=ON")
            .execute(&mut corrupt)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE vocabulary_values SET metadata='not JSON' WHERE id='vv:voc:kind:Document:note'",
        )
        .execute(&mut corrupt)
        .await
        .unwrap();
        corrupt.close().await.unwrap();
        let before = f.audit().await;
        assert_eq!(
            code(&f.call(execution(&p)).await),
            "plan_revalidation_failed"
        );
        assert_eq!(
            code(&f.call(Fixture::request(op)).await),
            "preparation_rejected"
        );
        f.no_attempts();
        assert_eq!(before, f.audit().await);
        c.close().await.unwrap();
    }
}

#[tokio::test]
async fn selected_real_enrolled_custody_refuses_only_facet_serving_path() {
    let f = Fixture::new().await;
    f.db.drain_captures_for_tests().await;
    crate::db::checkpoint_and_close_hosted_adoption_database(f.db.clone())
        .await
        .unwrap();
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("databases")).unwrap();
    let generation = uuid::Uuid::new_v4().to_string();
    let path = root
        .path()
        .join("databases")
        .join(format!("{generation}.db"));
    let adoption =
        crate::managed_custody::reserve_fresh_adoption(root.path(), &path, &generation).unwrap();
    std::fs::copy(f.db.path(), &path).unwrap();
    adoption.finalize().unwrap();
    let enrolled = crate::db::open_existing_database_at(&path).await.unwrap();
    assert!(enrolled.is_enrolled());
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(enrolled.pool())
        .await
        .unwrap();
    let err = selected::prepare(
        &enrolled,
        &Caller::local(),
        Fixture::request("set_facet")["arguments"].clone(),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, Error::Conflict(_)));
    assert!(err.to_string().contains("enrolled/coedit"));
    for op in ["archive", "add_link"] {
        selected::prepare(
            &enrolled,
            &Caller::local(),
            Fixture::request(op)["arguments"].clone(),
        )
        .await
        .unwrap();
    }
    assert_eq!(
        before,
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM content_events")
            .fetch_one(enrolled.pool())
            .await
            .unwrap()
    );
    enrolled.close().await;
}

#[tokio::test]
async fn selected_unit_external_bearer_policy_dependency_uses_canonical_engine_event() {
    let f = Fixture::new().await;
    let unit = "ec00b000-0000-4000-8000-000000000bf5";
    let account = "acct:selected-unit-proof";
    f.public("update_record",json!({"id":B,"home_id":"native:unfiled","reason":"External Unit bearer outside candidate source."})).await;
    for (id, cap) in [(F, "view"), (A, "manage"), (B, "manage"), (D, "view")] {
        let list = f
            .public(
                "manage_record_policy",
                json!({"action":"list","record_id":id}),
            )
            .await;
        f.public("manage_record_policy",json!({"action":"replace","record_id":id,"entries":[{"subject":{"kind":"account","account_id":account},"capability":cap}],"if_policy_revision":list["policy_revision"],"reason":"Fixed authenticated Unit proof authority."})).await;
    }
    // Reserved semantic-unit creation follows the kernel's canonical record
    // event seam; ordinary create_record correctly refuses this reserved kind.
    crate::store::append(&f.db,crate::store::AppendSpec{record_id:unit.into(),event_type:"record.created".into(),payload:json!({"type":"Entity","kind":"semantic-unit","home_id":F,"name":"Unit dependency carrier","persistence":"enduring"}),actor:Some("test:unit-engine".into())}).await.unwrap();
    // Engine kernel event construction: no ordinary MCP unit-created producer.
    // This canonical event setup qualifies the strict Unit dependency seam;
    // it is not a claim of ordinary public Unit minting or selected Unit writes.
    crate::store::append(&f.db,crate::store::AppendSpec{record_id:unit.into(),event_type:"unit.created.v1".into(),payload:json!({"semantic_contract_version":"native.freshness-kernel.v1","authority_bearer_record_id":B,"label":"Unit proof"}),actor:Some("test:unit-engine".into())}).await.unwrap();
    let experimental = ExperimentalExecutors::from_env_value(Some("sql_write".into())).unwrap();
    let s = ExecutorPrototypeStdioServer::new_with_telemetry_and_experimental(
        Arc::clone(&f.server.registry),
        f.db.clone(),
        Caller::authenticated(account),
        None,
        super::super::ExecutorTelemetryContext::new(
            Arc::new(super::super::telemetry::TestTelemetrySink::default()),
            7,
        )
        .unwrap(),
        experimental,
    )
    .await
    .unwrap();
    let prepared = s
        .handle_message(message(Fixture::request("set_facet")))
        .await
        .unwrap();
    assert!(body(&prepared)["plan_id"].is_string(), "{prepared}");
    assert_eq!(
        body(&prepared)["operation_evidence"]["selection"]["candidate_count"],
        2
    );
    let seq: i64 = sqlx::query_scalar("SELECT MAX(seq) FROM content_events WHERE record_id=?")
        .bind(B)
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    let list = f
        .public(
            "manage_record_policy",
            json!({"action":"list","record_id":B}),
        )
        .await;
    f.public("manage_record_policy",json!({"action":"replace","record_id":B,"entries":[{"subject":{"kind":"account","account_id":account},"capability":"manage"},{"subject":{"kind":"account","account_id":"acct:other-unit-row"},"capability":"view"}],"if_policy_revision":list["policy_revision"],"reason":"Public equal-capability external Unit bearer policy delta."})).await;
    let before = f.audit().await;
    assert_eq!(
        seq,
        sqlx::query_scalar::<_, i64>("SELECT MAX(seq) FROM content_events WHERE record_id=?")
            .bind(B)
            .fetch_one(f.db.pool())
            .await
            .unwrap()
    );
    let stale = s
        .handle_message(message(execution(&prepared)))
        .await
        .unwrap();
    assert_eq!(code(&stale), "plan_stale");
    let fresh = s
        .handle_message(message(Fixture::request("set_facet")))
        .await
        .unwrap();
    assert!(body(&fresh)["plan_id"].is_string(), "{fresh}");
    assert_eq!(body(&prepared)["effect"], body(&fresh)["effect"]);
    assert_ne!(
        body(&prepared)["operation_evidence"]["selection"]["authority_digest"],
        body(&fresh)["operation_evidence"]["selection"]["authority_digest"]
    );
    let r = s.write_runtime.as_ref().unwrap();
    assert_eq!(r.claim_attempts.load(Ordering::Relaxed), 0);
    assert_eq!(r.dispatch_attempts.load(Ordering::Relaxed), 0);
    assert_eq!(before, f.audit().await);
}

#[tokio::test]
async fn selected_expiry_during_workspace_revalidation_keeps_zero_attempts() {
    let f = Fixture::new().await;
    let p = f.prepare("archive").await;
    let before = f.audit().await;
    let gate = DispatchGate::new();
    let clock = Arc::new(AtomicI64::new(now_ms()));
    let pending = {
        let s = Arc::clone(&f.server);
        let args = execution(&p);
        let g = Arc::clone(&gate);
        let clock = Arc::clone(&clock);
        tokio::spawn(async move {
            SQL_TEST_CLOCK
                .scope(
                    clock,
                    selected::SNAPSHOT_GATE.scope(g, s.handle_message(message(args))),
                )
                .await
                .unwrap()
        })
    };
    gate.entered.acquire().await.unwrap().forget();
    clock.fetch_add(600001, Ordering::Relaxed);
    gate.release.add_permits(1);
    assert_eq!(code(&pending.await.unwrap()), "plan_expired");
    f.no_attempts();
    assert_eq!(before, f.audit().await);
}

#[tokio::test]
async fn selected_unselected_malformed_identity_is_infrastructure_on_confirm() {
    let f = Fixture::new().await;
    let p = f.prepare("set_facet").await;
    // Privileged projection robustness. B is predicate-unselected; its record
    // keeps ordinary type/kind/authority. No selected version is changed.
    let mut corrupt = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new()
            .filename(f.db.path())
            .foreign_keys(false),
    )
    .await
    .unwrap();
    assert_eq!(
        sqlx::query("UPDATE records SET id='native:' WHERE id=?")
            .bind(B)
            .execute(&mut corrupt)
            .await
            .unwrap()
            .rows_affected(),
        1
    );
    corrupt.close().await.unwrap();
    let before = f.audit().await;
    assert_eq!(
        code(&f.call(execution(&p)).await),
        "plan_revalidation_failed"
    );
    assert_eq!(
        code(&f.call(Fixture::request("set_facet")).await),
        "preparation_rejected"
    );
    f.no_attempts();
    assert_eq!(before, f.audit().await);
}

#[tokio::test]
async fn selected_required_capability_is_placed_in_authority_component() {
    let f = Fixture::new().await;
    let before = f.audit().await;
    let edit = f.prepare("set_facet").await;
    let manage = f.prepare("archive").await;
    let a = &body(&edit)["operation_evidence"]["selection"];
    let b = &body(&manage)["operation_evidence"]["selection"];
    assert_eq!(a["source_digest"], b["source_digest"]);
    assert_eq!(a["selected_versions_digest"], b["selected_versions_digest"]);
    // Same source/principal/visible canonical authority, no destination. Only
    // the checked selected requirement changes from Edit to Manage here.
    assert_ne!(a["authority_digest"], b["authority_digest"]);
    f.no_attempts();
    assert_eq!(before, f.audit().await);
}

#[tokio::test]
async fn selected_present_null_and_public_nontext_time_inputs_refuse_without_filtering() {
    for declared in ["number", "object", "date", "instant", "zoned", "when"] {
        let f = Fixture::new().await;
        let p = f.prepare("set_facet").await;
        f.public("manage_schema_config",json!({"action":"write","data":{"shapes":{"Document:note":{"facets":{"triage":{"type":declared}}}}}})).await;
        let before = f.audit().await;
        assert_eq!(
            code(&f.call(execution(&p)).await),
            "plan_stale",
            "{declared}"
        );
        assert_eq!(
            code(&f.call(Fixture::request("set_facet")).await),
            "preparation_rejected",
            "{declared}"
        );
        f.no_attempts();
        assert_eq!(before, f.audit().await);
    }
    let f = Fixture::new().await;
    let p = f.prepare("set_facet").await;
    // Privileged malformed current-row robustness. Ordinary facet null unsets
    // the row, and cannot create this present-NULL carrier. B is unselected:
    // all included predicate contexts still require checked current values.
    assert_eq!(
        sqlx::query("UPDATE facet_values SET value=NULL WHERE record_id=? AND key='triage'")
            .bind(B)
            .execute(f.db.write_pool())
            .await
            .unwrap()
            .rows_affected(),
        1
    );
    let before = f.audit().await;
    assert_eq!(code(&f.call(execution(&p)).await), "plan_stale");
    assert_eq!(
        code(&f.call(Fixture::request("set_facet")).await),
        "preparation_rejected"
    );
    f.no_attempts();
    assert_eq!(before, f.audit().await);

    let f = Fixture::new().await;
    f.public("manage_schema_config",json!({"action":"write","data":{"shapes":{"Document:note":{"facets":{"protocol_due":{"type":"date"}}}}}})).await;
    f.public("update_record",json!({"id":A,"facets":{"protocol_due":"2026-10-03"},"reason":"Public time carrier before selector."})).await;
    let rows = f
        .public("manage_schema_config", json!({"action":"read"}))
        .await;
    let id = rows["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| {
            r["layer"] == "user"
                && r["data"]["shapes"]["Document:note"]["facets"]["protocol_due"]["type"] == "date"
        })
        .unwrap()["id"]
        .clone();
    // Public schema removal leaves the existing derived time marker intact;
    // current TEXT alone must not reinterpret it as the default text lane.
    f.public(
        "manage_schema_config",
        json!({"action":"write","id":id,"data":{"shapes":{}}}),
    )
    .await;
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM facet_times WHERE record_id=? AND key='protocol_due'"
        )
        .bind(A)
        .fetch_one(f.db.pool())
        .await
        .unwrap(),
        1
    );
    let mut request = Fixture::request("archive");
    request["arguments"]["statement"] =
        json!("SELECT id FROM children WHERE current_facet('protocol_due') IS NOT NULL");
    let before = f.audit().await;
    assert_eq!(code(&f.call(request).await), "preparation_rejected");
    f.no_attempts();
    assert_eq!(before, f.audit().await);
}

#[tokio::test]
async fn selected_checked_comment_consumed_failures_are_infrastructure_not_absence() {
    use crate::comments::CommentShape;
    const TARGET: &str = "ec00b000-0000-4000-8000-000000000bf8";
    const ROOT: &str = "ec00b000-0000-4000-8000-000000000bf9";
    const REPLY: &str = "ec00b000-0000-4000-8000-000000000bfa";
    for probe in [
        "root_kind",
        "root_annotation_decode",
        "reply_annotation_decode",
        "root_body_decode",
        "reply_body_decode",
        "root_blank",
        "root_bad_anchor",
        "reply_targeted",
    ] {
        let f = Fixture::new().await;
        // Independent public manifest before any compiler call. Only REPLY is
        // a source candidate; its consumed root and target live outside F.
        f.public("create_record",json!({"id":TARGET,"type":"WorkItem","kind":"task","name":"Comment target","body":"anchored passage","reason":"Public external comment target."})).await;
        f.public("create_record",json!({"id":ROOT,"type":"Annotation","kind":"comment","name":"Checked root","body":"Public root concern.","lifecycle":"open","links":[{"target_id":TARGET,"relationship":"part_of"}],"target":{"target_record_id":TARGET,"source_slot":"body","selectors":[{"type":"text_quote","exact":"anchored passage"}]},"reason":"Public root before selector."})).await;
        f.public("create_record",json!({"id":REPLY,"type":"Annotation","kind":"comment","name":"Checked reply","body":"Public reply.","home_id":F,"links":[{"target_id":ROOT,"relationship":"part_of"}],"reason":"Public visible reply before selector."})).await;
        let p = f.prepare("set_facet").await;
        assert_eq!(
            body(&p)["operation_evidence"]["selection"]["candidate_count"],
            3
        );
        // LABELED STORAGE ROBUSTNESS: public creation cannot emit these
        // malformed projections. Disable CHECK only on this setup connection.
        let mut c = sqlx::SqliteConnection::connect_with(
            &sqlx::sqlite::SqliteConnectOptions::new().filename(f.db.path()),
        )
        .await
        .unwrap();
        sqlx::query("PRAGMA ignore_check_constraints=ON")
            .execute(&mut c)
            .await
            .unwrap();
        match probe {
            "root_kind" => {
                assert_eq!(sqlx::query("UPDATE vocabulary_values SET metadata='not JSON' WHERE id='vv:voc:kind:WorkItem:task'").execute(&mut c).await.unwrap().rows_affected(),1);
            }
            "root_annotation_decode" => {
                assert_eq!(
                    sqlx::query(
                        "UPDATE annotation_targets SET source_slot=X'FF' WHERE annotation_id=?"
                    )
                    .bind(ROOT)
                    .execute(&mut c)
                    .await
                    .unwrap()
                    .rows_affected(),
                    1
                );
            }
            "root_body_decode" | "reply_body_decode" => {
                let id = if probe == "root_body_decode" {
                    ROOT
                } else {
                    REPLY
                };
                assert_eq!(
                    sqlx::query("UPDATE records SET body=X'FF' WHERE id=?")
                        .bind(id)
                        .execute(&mut c)
                        .await
                        .unwrap()
                        .rows_affected(),
                    1
                );
            }
            "root_blank" => {
                sqlx::query("UPDATE records SET body='' WHERE id=?")
                    .bind(ROOT)
                    .execute(&mut c)
                    .await
                    .unwrap();
            }
            "root_bad_anchor" => {
                sqlx::query(
                    "UPDATE annotation_targets SET target_record_id=? WHERE annotation_id=?",
                )
                .bind(D)
                .bind(ROOT)
                .execute(&mut c)
                .await
                .unwrap();
            }
            "reply_annotation_decode" | "reply_targeted" => {
                assert_eq!(sqlx::query("INSERT INTO annotation_targets(annotation_id,target_record_id,source_slot,source_event_seq,blob_id,source_sha256,selectors,purpose,created_at,updated_at) SELECT ?,target_record_id,source_slot,source_event_seq,blob_id,source_sha256,selectors,purpose,created_at,updated_at FROM annotation_targets WHERE annotation_id=?").bind(REPLY).bind(ROOT).execute(&mut c).await.unwrap().rows_affected(),1);
                if probe == "reply_annotation_decode" {
                    sqlx::query(
                        "UPDATE annotation_targets SET source_slot=X'FF' WHERE annotation_id=?",
                    )
                    .bind(REPLY)
                    .execute(&mut c)
                    .await
                    .unwrap();
                }
            }
            _ => unreachable!(),
        }
        c.close().await.unwrap();
        let before = f.audit().await;
        let mut tx = f.db.pool().begin().await.unwrap();
        let mut consumed = Vec::new();
        let checked =
            crate::comments::validate_stored_checked_on(&mut tx, REPLY, &mut consumed).await;
        let shape = match probe {
            "root_blank" => Some(CommentShape::BlankBody),
            "root_bad_anchor" => Some(CommentShape::BadAnchor),
            "reply_targeted" => Some(CommentShape::ReplyTargeted),
            _ => None,
        };
        if let Some(shape) = &shape {
            assert_eq!(checked.unwrap(), Err(shape.clone()), "{probe}");
        } else {
            assert!(
                matches!(checked, Err(Error::Engine(_) | Error::Sqlx(_))),
                "{probe}: {checked:?}"
            );
            if probe == "root_kind" {
                assert!(consumed.iter().any(
                    |v| v["template"] == "eligibility.kind-input.v1" && v["type"] == "WorkItem"
                ));
            }
            if probe.contains("annotation") {
                assert!(consumed
                    .iter()
                    .any(|v| v["template"] == "eligibility.root-target.v1" && v["id"] == TARGET));
            }
        }
        tx.rollback().await.unwrap();
        let confirmation = f.call(execution(&p)).await;
        let preparation = f.call(Fixture::request("set_facet")).await;
        if shape.is_some() {
            assert_eq!(code(&confirmation), "plan_stale", "{probe}");
            assert!(
                body(&preparation)["plan_id"].is_string(),
                "{probe}: {preparation}"
            );
            assert_eq!(
                body(&preparation)["operation_evidence"]["selection"]["candidate_count"],
                2
            );
            assert_eq!(body(&preparation)["effect"], body(&p)["effect"]);
        } else {
            assert_eq!(code(&confirmation), "plan_revalidation_failed", "{probe}");
            assert_eq!(code(&preparation), "preparation_rejected", "{probe}");
        }
        f.no_attempts();
        assert_eq!(before, f.audit().await, "{probe}");
    }
}
