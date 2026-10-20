use super::*;
use crate::identity::hosted::{
    reconcile_hosted_identity, HostedMembershipArrival, HostedMembershipRole,
    HostedMembershipSource,
};
use crate::mcp::{register_surface_tools, ExposureProfile};
use crate::meta::{
    promote_value, propose_value_with_kind_metadata_as, write_user_schema_config, KindMetadataV1,
    SchemaConfigOptions, VocabularyValueTerminality,
};

struct Fixture {
    db: Db,
    registry: ToolRegistry,
    a: String,
    b: String,
}
async fn fixture(install: bool) -> Fixture {
    let db = crate::create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    let mut accounts = Vec::new();
    for (email, catalog, role) in [
        (
            "config-a@example.test",
            "config-a",
            HostedMembershipRole::Owner,
        ),
        (
            "config-b@example.test",
            "config-b",
            HostedMembershipRole::Member,
        ),
    ] {
        let arrival = HostedMembershipArrival::new(
            role,
            HostedMembershipSource::Direct,
            "2026-10-09T00:00:00Z".into(),
        )
        .unwrap();
        accounts.push(
            reconcile_hosted_identity(&db, email, catalog, &arrival, None)
                .await
                .unwrap(),
        );
    }
    let a = accounts.remove(0);
    let b = accounts.remove(0);
    for account in [&a, &b] {
        registry.call(db.clone(), Caller::local(), "manage_record_policy", json!({"action":"grant",
            "record_id":crate::schema::UNFILED_RECORD_ID,"subject":{"kind":"account","account_id":account},
            "capability":"edit","reason":"Account config fixture may file preferences."})).await.unwrap();
    }
    let f = Fixture { db, registry, a, b };
    if install {
        install_kind_and_shape(&f.db).await;
    }
    f
}
async fn install_kind_and_shape(db: &Db) {
    let id = propose_value_with_kind_metadata_as(
        db,
        "kind:Configuration",
        KIND,
        None,
        0.0,
        VocabularyValueTerminality::Open,
        Some(KindMetadataV1::legacy("Configuration", KIND)),
        None,
    )
    .await
    .unwrap();
    promote_value(db, &id).await.unwrap();
    let shape: Value = serde_json::from_str(APPROVED).unwrap();
    write_user_schema_config(db, json!({"shapes":{"Configuration:focus_preferences":{"facets":{"focus.preferences":shape}}}}),
        SchemaConfigOptions::default()).await.unwrap();
}
async fn call(f: &Fixture, account: &str, args: Value) -> Value {
    let r = f
        .registry
        .call(f.db.clone(), Caller::authenticated(account), TOOL, args)
        .await
        .unwrap();
    logical_receipt(r)
}
fn logical_receipt(mut r: Value) -> Value {
    let object = r.as_object_mut().unwrap();
    // Only these ordinary transport metadata fields sit outside the receipt.
    // Pin their actual registry types and retain attribution at the boundary.
    assert!(object.remove("run_context").unwrap().is_object());
    let attestations = object.remove("action_attestation_ids");
    if object.get("created") == Some(&Value::Bool(true)) {
        assert!(!attestations
            .as_ref()
            .unwrap()
            .as_array()
            .unwrap()
            .is_empty());
    }
    if let Some(ids) = attestations {
        assert!(ids
            .as_array()
            .unwrap()
            .iter()
            .all(|id| id.as_str().is_some_and(|s| !s.is_empty())));
    }
    assert_receipt_keys(&r);
    r
}
fn assert_receipt_keys(r: &Value) {
    let keys: BTreeSet<_> = r.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        [
            "status",
            "outcome",
            "reason",
            "refusal",
            "record_id",
            "content_revision",
            "policy_revision",
            "created"
        ]
        .into_iter()
        .collect()
    );
}
fn inspect() -> Value {
    json!({"action":"inspect","kind":KIND})
}
fn ensure() -> Value {
    json!({"action":"ensure","kind":KIND,"reason":"Provision canonical preferences."})
}
fn replace(id: &str) -> Value {
    json!({"action":"replace","kind":KIND,"expected_record_id":id,"reason":"Explicit replacement of unusable preferences."})
}
async fn effects(db: &Db) -> Vec<i64> {
    let mut values = vec![];
    for table in [
        "records",
        "facet_values",
        "record_policies",
        "policy_entries",
        "content_events",
        "policy_events",
        "control_events",
        "control_event_applications",
        "account_configs",
        "provenance_action_attestations",
    ] {
        values.push(
            sqlx::query_scalar::<_, i64>(&format!("SELECT COUNT(*) FROM {table}"))
                .fetch_one(db.pool())
                .await
                .unwrap(),
        );
    }
    values.push(
        sqlx::query_scalar::<_, i64>("SELECT next_act FROM act_state WHERE singleton=1")
            .fetch_one(db.pool())
            .await
            .unwrap(),
    );
    values
}
async fn assert_guard_bytes(f: &Fixture, account: &str, receipt: &Value) {
    let id = receipt["record_id"].as_str().unwrap();
    let rows = f
        .registry
        .call(
            f.db.clone(),
            Caller::authenticated(account),
            "query_record",
            json!({"steps":[{"step":"filter","types":["Configuration"]}],"limit":100}),
        )
        .await
        .unwrap();
    let record = rows["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == id)
        .unwrap();
    let content = receipt["content_revision"].as_str().unwrap();
    let query = record["updated_at"].as_str().unwrap();
    assert_eq!(content.as_bytes(),query.as_bytes(),"host CAS requires the exact raw query_record timestamp, including millisecond-Z representation");
    assert!(content.ends_with('Z'));
    let policy = f
        .registry
        .call(
            f.db.clone(),
            Caller::authenticated(account),
            "manage_record_policy",
            json!({"action":"list","record_id":id}),
        )
        .await
        .unwrap();
    assert_eq!(
        receipt["policy_revision"].as_str().unwrap().as_bytes(),
        policy["policy_revision"].as_str().unwrap().as_bytes()
    );
}
async fn update(f: &Fixture, id: &str, fields: Value) {
    let guard = call(f, &f.a, inspect()).await;
    let mut args = json!({"id":id,"if_unmodified_since":guard["content_revision"],"if_policy_revision":guard["policy_revision"],
        "reason":"Edit winner with current content and policy guards."});
    args.as_object_mut()
        .unwrap()
        .extend(fields.as_object().unwrap().clone());
    f.registry
        .call(
            f.db.clone(),
            Caller::authenticated(&f.a),
            "update_record",
            args,
        )
        .await
        .unwrap();
}
async fn raw(f: &Fixture, id: &str, event_type: &str, payload: Value) {
    let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
    append_in(
        &f.db,
        &mut tx,
        AppendSpec {
            record_id: id.into(),
            event_type: event_type.into(),
            payload,
            actor: Some(f.a.clone()),
        },
        &mut crate::act::ActAllocation::new(),
    )
    .await
    .unwrap();
    f.db.commit_content(tx).await.unwrap();
}
async fn grant(f: &Fixture, id: &str, account: &str, capability: &str) {
    f.registry.call(f.db.clone(), Caller::local(), "manage_record_policy", json!({"action":"grant","record_id":id,
        "subject":{"kind":"account","account_id":account},"capability":capability,"reason":"Test explicit policy boundary."})).await.unwrap();
}
async fn old_state(db: &Db, id: &str) -> Value {
    let record: String = sqlx::query_scalar("SELECT json_object('type',type,'kind',kind,'name',name,'body',body,'updated_at',updated_at,'archived',archived,'deleted_at',deleted_at,'policy_anchor_id',policy_anchor_id) FROM records WHERE id=?")
        .bind(id).fetch_one(db.pool()).await.unwrap();
    let facets: Vec<(String, String)> =
        sqlx::query_as("SELECT key,value FROM facet_values WHERE record_id=? ORDER BY key,value")
            .bind(id)
            .fetch_all(db.pool())
            .await
            .unwrap();
    let entries: Vec<(String,String,String)> = sqlx::query_as("SELECT subject_kind,subject_id,capability FROM policy_entries WHERE policy_anchor_id=? ORDER BY subject_kind,subject_id,capability").bind(id).fetch_all(db.pool()).await.unwrap();
    json!({"record":record,"facets":facets,"policy":entries})
}
#[tokio::test]
async fn two_accounts_first_commit_private_stray_ignored_and_hit_zero_effects() {
    let f = fixture(true).await;
    let produced = manage_account_config(f.db.clone(), Caller::authenticated(&f.a), inspect())
        .await
        .unwrap();
    assert_receipt_keys(&produced);
    assert_eq!(produced["status"], "absent");
    assert!(produced.get("run_context").is_none());
    assert!(produced.get("action_attestation_ids").is_none());
    let before = effects(&f.db).await;
    assert_eq!(
        call(&f, &f.a, inspect()).await,
        json!({"status":"absent","outcome":"inspected","reason":null,"refusal":null,
        "record_id":null,"content_revision":null,"policy_revision":null,"created":null})
    );
    assert_eq!(effects(&f.db).await, before);
    // A stray matching-kind record is deliberately never adopted.
    f.registry.call(f.db.clone(),Caller::authenticated(&f.a),"create_record",json!({"type":"Configuration","kind":KIND,
        "facets":{"focus.preferences":{"version":1,"foci":[]}},"access_policy":"account_only","reason":"Stray noncanonical preference fixture."})).await.unwrap();
    assert_eq!(call(&f, &f.a, inspect()).await["status"], "absent");
    let first = call(&f, &f.a, ensure()).await;
    assert_guard_bytes(&f, &f.a, &first).await;
    assert_eq!(first["outcome"], "created");
    assert_eq!(first["created"], true);
    let id = first["record_id"].as_str().unwrap();
    for action in [inspect(), ensure(), replace(id)] {
        let produced = manage_account_config(f.db.clone(), Caller::authenticated(&f.a), action)
            .await
            .unwrap();
        assert_receipt_keys(&produced);
        assert!(produced.get("run_context").is_none());
        assert!(produced.get("action_attestation_ids").is_none());
    }
    assert!(canonical_record_id(id));
    assert!(first["policy_revision"]
        .as_str()
        .unwrap()
        .starts_with("prv1:"));
    let hidden = f
        .registry
        .call(
            f.db.clone(),
            Caller::authenticated(&f.b),
            "get_record",
            json!({"ids":[id]}),
        )
        .await
        .unwrap();
    assert_ne!(hidden["records"][0]["status"], "found");
    let policy = f
        .registry
        .call(
            f.db.clone(),
            Caller::authenticated(&f.a),
            "manage_record_policy",
            json!({"action":"list","record_id":id}),
        )
        .await
        .unwrap();
    assert_eq!(policy["policy_revision"], first["policy_revision"]);
    assert_eq!(policy["entries"].as_array().unwrap().len(), 1);
    let other = call(&f, &f.b, ensure()).await;
    assert_ne!(other["record_id"], first["record_id"]);
    update(
        &f,
        id,
        json!({"name":"Edited winner","facets":{"focus.preferences":{"version":1,"foci":[
        {"focus_id":"90220000-0000-4000-8000-000000000001","tier":"now","hidden":true}]}}}),
    )
    .await;
    let state = old_state(&f.db, id).await;
    let before = effects(&f.db).await;
    let hit = call(&f, &f.a, ensure()).await;
    assert_guard_bytes(&f, &f.a, &hit).await;
    assert_eq!(hit["created"], false);
    assert_eq!(hit["outcome"], "existing");
    assert_eq!(hit["record_id"], first["record_id"]);
    assert_eq!(effects(&f.db).await, before);
    assert_eq!(old_state(&f.db, id).await, state);
}
#[tokio::test]
async fn concurrent_distinct_session_intent_ensure_converges_one_record() {
    let f = fixture(true).await;
    let mut runs = Vec::new();
    for intent in ["first intent", "second intent"] {
        let boot = f
            .registry
            .call(
                f.db.clone(),
                Caller::authenticated(&f.a),
                "bootstrap",
                json!({}),
            )
            .await
            .unwrap();
        let key = boot["run"]["run_key"].as_str().unwrap().to_owned();
        f.registry
            .call(
                f.db.clone(),
                Caller::authenticated(&f.a),
                "set_intent",
                json!({"run_key":key,"intent":intent}),
            )
            .await
            .unwrap();
        runs.push(key);
    }
    assert_ne!(runs[0], runs[1]);
    let mut args1 = ensure();
    args1["run_key"] = json!(runs[0]);
    let mut args2 = ensure();
    args2["run_key"] = json!(runs[1]);
    let (a, b) = tokio::join!(
        f.registry
            .call(f.db.clone(), Caller::authenticated(&f.a), TOOL, args1),
        f.registry
            .call(f.db.clone(), Caller::authenticated(&f.a), TOOL, args2)
    );
    let a = a.unwrap();
    let b = b.unwrap();
    assert_eq!(a["run_context"]["intent"], "first intent");
    assert_eq!(b["run_context"]["intent"], "second intent");
    let a = logical_receipt(a);
    let b = logical_receipt(b);
    assert_eq!(a["record_id"], b["record_id"]);
    assert_eq!(
        [
            a["created"].as_bool().unwrap(),
            b["created"].as_bool().unwrap()
        ]
        .into_iter()
        .filter(|v| *v)
        .count(),
        1
    );
    let rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM records WHERE type='Configuration' AND kind='focus_preferences'",
    )
    .fetch_one(f.db.pool())
    .await
    .unwrap();
    assert_eq!(rows, 1);
    let events: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM control_events WHERE type='account_config.provisioned'",
    )
    .fetch_one(f.db.pool())
    .await
    .unwrap();
    assert_eq!(events, 1);
    let (actor, run): (String, Option<String>) = sqlx::query_as(
        "SELECT actor,run_key FROM control_events WHERE type='account_config.provisioned'",
    )
    .fetch_one(f.db.pool())
    .await
    .unwrap();
    assert_eq!(actor, f.a);
    assert!(run.is_some_and(|key| runs.contains(&key)));
}
#[tokio::test]
async fn malformed_identity_payload_and_missing_registration_write_nothing() {
    let f = fixture(false).await;
    let before = effects(&f.db).await;
    assert_eq!(call(&f, &f.a, inspect()).await["status"], "absent");
    let e = f
        .registry
        .call(f.db.clone(), Caller::authenticated(&f.a), TOOL, ensure())
        .await
        .unwrap_err();
    assert!(e.to_string().contains("kind_not_registered"));
    for account in [
        "local",
        "acct_ABCDEFABCDEFABCDEFABCDEFABCDEFAB",
        "acct_deadbeef",
    ] {
        assert!(f
            .registry
            .call(
                f.db.clone(),
                Caller::authenticated(account),
                TOOL,
                inspect()
            )
            .await
            .is_err());
    }
    for args in [
        json!({"action":"inspect","kind":KIND,"account_id":f.b}),
        json!({"action":"inspect","kind":KIND,"x":true}),
        json!({"action":"ensure","kind":KIND,"reason":" "}),
        json!({"action":"replace","kind":KIND,"reason":"test","expected_record_id":"native:root"}),
    ] {
        assert!(f
            .registry
            .call(f.db.clone(), Caller::authenticated(&f.a), TOOL, args)
            .await
            .is_err());
    }
    assert_eq!(effects(&f.db).await, before);
    install_kind_and_shape(&f.db).await;
    let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
    sqlx::query("DELETE FROM schema_config WHERE layer='user'")
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let before = effects(&f.db).await;
    let e = f
        .registry
        .call(f.db.clone(), Caller::authenticated(&f.a), TOOL, ensure())
        .await
        .unwrap_err();
    assert!(e.to_string().contains("kind_not_registered"));
    assert_eq!(effects(&f.db).await, before);
}
#[tokio::test]
async fn statuses_precedence_and_unsupported_recovery_are_total() {
    let f = fixture(true).await;
    let first = call(&f, &f.a, ensure()).await;
    let id = first["record_id"].as_str().unwrap();
    raw(&f,id,"facet.set",json!({"key":FACET,"value":"{\"version\":1,\"foci\":[{\"focus_id\":\"90220000-0000-4000-8000-000000000001\",\"tier\":\"now\",\"hidden\":false},{\"focus_id\":\"90220000-0000-4000-8000-000000000001\",\"tier\":\"now\",\"hidden\":true}]}"})).await;
    assert_eq!(call(&f, &f.a, inspect()).await["reason"], "invalid_content");
    assert_eq!(
        call(&f, &f.a, replace(id)).await["refusal"],
        "unsupported_recovery"
    );
    f.registry
        .call(
            f.db.clone(),
            Caller::authenticated(&f.a),
            "archive_record",
            json!({"id":id,"archived":true,"reason":"Test archived precedence."}),
        )
        .await
        .unwrap();
    assert_eq!(call(&f, &f.a, inspect()).await["reason"], "archived");
    assert_eq!(
        call(&f, &f.a, replace(id)).await["refusal"],
        "unsupported_recovery"
    );
    grant(&f, id, &f.b, "view").await;
    assert_eq!(
        call(&f, &f.a, inspect()).await["reason"],
        "policy_not_account_only"
    );
    raw(&f, id, "record.updated", json!({"kind":"other_kind"})).await;
    assert_eq!(call(&f, &f.a, inspect()).await["reason"], "wrong_kind");
    f.registry
        .call(
            f.db.clone(),
            Caller::local(),
            "manage_record_policy",
            json!({"action":"revoke","record_id":id,
        "subject":{"kind":"account","account_id":f.a},"reason":"Remove owner grant."}),
        )
        .await
        .unwrap();
    let forbidden = call(&f, &f.a, inspect()).await;
    assert_eq!(forbidden["reason"], "forbidden");
    assert!(forbidden["record_id"].is_null());
    assert!(forbidden["content_revision"].is_null());
    assert!(forbidden["policy_revision"].is_null());
    let before = effects(&f.db).await;
    let refuse = call(&f, &f.a, ensure()).await;
    assert_eq!(refuse["outcome"], "refused");
    assert!(refuse["refusal"].is_null());
    assert_eq!(effects(&f.db).await, before);
    raw(&f, id, "record.deleted", json!({})).await;
    assert_eq!(call(&f, &f.a, inspect()).await["reason"], "deleted");
}
#[tokio::test]
async fn replacement_cas_retry_old_unchanged_and_mapping_advanced() {
    let f = fixture(true).await;
    let absent = call(&f, &f.a, replace("90220000-0000-4000-8000-000000000001")).await;
    assert_eq!(absent["refusal"], "absent");
    let first = call(&f, &f.a, ensure()).await;
    let id = first["record_id"].as_str().unwrap();
    assert_eq!(call(&f, &f.a, replace(id)).await["refusal"], "not_unusable");
    let cas = call(&f, &f.a, replace("90220000-0000-4000-8000-000000000001")).await;
    assert_eq!(cas["refusal"], "cas_mismatch");
    assert_eq!(cas["record_id"], first["record_id"]);
    assert_eq!(cas["content_revision"], first["content_revision"]);
    grant(&f, id, &f.b, "view").await;
    let old = old_state(&f.db, id).await;
    let rebound = call(&f, &f.a, replace(id)).await;
    let winner = rebound["record_id"].as_str().unwrap();
    assert_eq!(rebound["outcome"], "replaced");
    assert_ne!(winner, id);
    assert_eq!(old_state(&f.db, id).await, old);
    update(&f, winner, json!({"name":"Keep edited retry winner"})).await;
    let before = effects(&f.db).await;
    let retry=call(&f,&f.a,json!({"action":"replace","kind":KIND,"expected_record_id":id,"reason":"Different reason on explicit retry."})).await;
    assert_guard_bytes(&f, &f.a, &retry).await;
    assert_eq!(retry["outcome"], "replayed");
    assert_eq!(retry["created"], false);
    assert_eq!(
        retry["content_revision"],
        call(&f, &f.a, inspect()).await["content_revision"]
    );
    assert_eq!(effects(&f.db).await, before);
    f.registry
        .call(
            f.db.clone(),
            Caller::authenticated(&f.a),
            "archive_record",
            json!({"id":winner,"archived":true,"reason":"Winner now unusable."}),
        )
        .await
        .unwrap();
    let before = effects(&f.db).await;
    let retry = call(&f, &f.a, replace(id)).await;
    assert_eq!(retry["refusal"], "already_replaced");
    assert_eq!(retry["reason"], "archived");
    assert_eq!(retry["record_id"], winner);
    assert_eq!(effects(&f.db).await, before);
    raw(&f, winner, "record.updated", json!({"kind":"other_kind"})).await;
    let next = call(&f, &f.a, replace(winner)).await;
    let before = effects(&f.db).await;
    let moved = call(&f, &f.a, replace(id)).await;
    assert_eq!(moved["refusal"], "mapping_changed");
    assert_eq!(moved["status"], "healthy");
    assert_eq!(moved["record_id"], next["record_id"]);
    assert_eq!(effects(&f.db).await, before);
    assert_eq!(old_state(&f.db, id).await, old);
}
#[tokio::test]
async fn projection_rebuild_strict_lineage_purge_restrict_and_interchange_round_trip() {
    let f = fixture(true).await;
    let first = call(&f, &f.a, ensure()).await;
    let old = first["record_id"].as_str().unwrap();
    grant(&f, old, &f.b, "view").await;
    let next = call(&f, &f.a, replace(old)).await;
    let id = next["record_id"].as_str().unwrap();
    let before = call(&f, &f.a, inspect()).await;
    let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
    assert!(sqlx::query("DELETE FROM records WHERE id=?")
        .bind(id)
        .execute(&mut *tx)
        .await
        .is_err());
    assert_eq!(mapping(&mut tx, &f.a).await.unwrap().as_deref(), Some(id));
    tx.rollback().await.unwrap();
    let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
    let events = crate::control::read_all_control_events(&mut tx)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.aggregate_kind == "account_config")
        .collect::<Vec<_>>();
    sqlx::query("DELETE FROM account_configs")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("DELETE FROM control_event_applications WHERE event_id IN (SELECT id FROM control_events WHERE aggregate_kind='account_config')").execute(&mut *tx).await.unwrap();
    for e in &events {
        crate::control::project_control(&mut tx, e).await.unwrap();
    }
    assert_eq!(mapping(&mut tx, &f.a).await.unwrap().as_deref(), Some(id));
    sqlx::query("DELETE FROM account_configs")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("DELETE FROM control_event_applications WHERE event_id=?")
        .bind(&events[1].id)
        .execute(&mut *tx)
        .await
        .unwrap();
    assert!(crate::control::project_control(&mut tx, &events[1])
        .await
        .unwrap_err()
        .to_string()
        .contains("lineage CAS"));
    tx.rollback().await.unwrap();
    assert_eq!(call(&f, &f.a, inspect()).await, before);
    assert!(
        crate::conformance::rebuild_and_diff_control(&f.db)
            .await
            .unwrap()
            .equal
    );
    let bytes = crate::interchange::export_canonical_interchange(&f.db)
        .await
        .unwrap();
    let bundle: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(bundle["manifest"]["revision"], 8);
    assert!(bundle["sections"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["name"] == "account_configs"));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.db");
    crate::interchange::import_canonical_interchange(
        &bytes,
        &path,
        crate::interchange::ImportContinuity::ForeignBoundary,
    )
    .await
    .unwrap();
    let imported = crate::open_existing_database_at(&path).await.unwrap();
    let after = f
        .registry
        .call(
            imported.clone(),
            Caller::authenticated(&f.a),
            TOOL,
            inspect(),
        )
        .await
        .unwrap();
    assert_eq!(logical_receipt(after), before);
    assert!(
        crate::conformance::rebuild_and_diff_control(&imported)
            .await
            .unwrap()
            .equal
    );
    imported.close().await;
}
#[test]
fn complete_only_mixed_freeze_and_offline_classifications() {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    assert!(registry
        .specs_for_profile(ExposureProfile::Complete)
        .any(|s| s.name == TOOL));
    assert!(!registry
        .specs_for_profile(ExposureProfile::Focused)
        .any(|s| s.name == TOOL));
    let spec = registry.get(TOOL).unwrap();
    let validator = jsonschema::validator_for(&spec.input_schema).unwrap();
    for mut args in [
        inspect(),
        ensure(),
        replace("90220000-0000-4000-8000-000000000001"),
    ] {
        args["run_key"] = json!("schema-proof");
        assert!(validator.is_valid(&args), "{args}");
    }
    for mut args in [
        json!({"action":"inspect","kind":KIND,"reason":"Not accepted for inspect."}),
        json!({"action":"inspect","kind":KIND,"expected_record_id":"90220000-0000-4000-8000-000000000001"}),
        json!({"action":"ensure","kind":KIND}),
        json!({"action":"ensure","kind":KIND,"reason":"Ensure.","expected_record_id":"90220000-0000-4000-8000-000000000001"}),
        json!({"action":"replace","kind":KIND,"reason":"Replace."}),
        json!({"action":"inspect","kind":KIND,"unknown":true}),
    ] {
        args["run_key"] = json!("schema-proof");
        assert!(!validator.is_valid(&args), "{args}");
    }
    let lens =
        crate::mcp::lens_descriptor_projection(&registry, ExposureProfile::Complete).unwrap();
    let lens_tool = lens.iter().find(|tool| tool.name == TOOL).unwrap();
    println!(
        "account config descriptor: ordinary={} lens={}",
        spec.descriptor_bytes(),
        lens_tool.descriptor_bytes()
    );
    assert!(ToolKind::ManageAccountConfig
        .authoritative_disposition()
        .admits(&inspect()));
    assert!(!ToolKind::ManageAccountConfig
        .authoritative_disposition()
        .admits(&ensure()));
    assert!(!ToolKind::ManageAccountConfig
        .authoritative_disposition()
        .admits(&replace("90220000-0000-4000-8000-000000000001")));
    assert_eq!(
        crate::schema::member_classification::MEMBER_TABLE_DISPOSITIONS
            .iter()
            .find(|(n, _)| *n == "account_configs")
            .unwrap()
            .1,
        crate::schema::member_classification::MemberTableKind::CallerBound
    );
}

#[tokio::test]
async fn frozen_inspect_and_all_offline_actions_observe_admission_before_writes() {
    let mut f = fixture(true).await;
    let barrier = crate::mcp::DeploymentMutationBarrier::default();
    f.registry.set_deployment_mutation_barrier(barrier.clone());
    let frozen = barrier.freeze().await;
    let before = effects(&f.db).await;
    assert_eq!(call(&f, &f.a, inspect()).await["status"], "absent");
    for args in [ensure(), replace("90220000-0000-4000-8000-000000000001")] {
        let error = f
            .registry
            .call(f.db.clone(), Caller::authenticated(&f.a), TOOL, args)
            .await
            .unwrap_err();
        assert_eq!(error.deployment_read_only_operation(), Some(TOOL));
    }
    assert_eq!(effects(&f.db).await, before);
    drop(frozen);
    f.registry.set_standby_read_only(true);
    for args in [
        inspect(),
        ensure(),
        replace("90220000-0000-4000-8000-000000000001"),
    ] {
        let error = f
            .registry
            .call(f.db.clone(), Caller::authenticated(&f.a), TOOL, args)
            .await
            .unwrap_err();
        assert!(matches!(error, Error::UnavailableOffline { .. }), "{error}");
    }
    assert_eq!(effects(&f.db).await, before);
    assert_eq!(
        ToolKind::ManageAccountConfig.member_scope(),
        crate::mcp::member_scope::MemberScope::UnavailableOffline
    );
}
#[tokio::test]
async fn all_four_replacement_reasons_create_private_new_record_without_touching_old() {
    for reason in [
        Reason::Deleted,
        Reason::Forbidden,
        Reason::WrongKind,
        Reason::PolicyNotAccountOnly,
    ] {
        let f = fixture(true).await;
        let first = call(&f, &f.a, ensure()).await;
        let id = first["record_id"].as_str().unwrap();
        match reason {
            Reason::Deleted => raw(&f, id, "record.deleted", json!({})).await,
            Reason::Forbidden => {
                f.registry.call(f.db.clone(),Caller::local(),"manage_record_policy",json!({"action":"revoke","record_id":id,
                    "subject":{"kind":"account","account_id":f.a},"reason":"Test forbidden replacement."})).await.unwrap();
            }
            Reason::WrongKind => raw(&f, id, "record.updated", json!({"kind":"other"})).await,
            Reason::PolicyNotAccountOnly => grant(&f, id, &f.b, "view").await,
            _ => unreachable!(),
        }
        let old = old_state(&f.db, id).await;
        let replacement = call(&f, &f.a, replace(id)).await;
        assert_eq!(replacement["status"], "healthy");
        assert_eq!(replacement["outcome"], "replaced");
        assert_eq!(replacement["created"], true);
        assert_eq!(old_state(&f.db, id).await, old);
        let new = replacement["record_id"].as_str().unwrap();
        let mut tx = f.db.pool().begin().await.unwrap();
        assert!(valid_facet(&mut tx, new).await.unwrap());
        tx.rollback().await.unwrap();
        assert_eq!(
            f.registry
                .call(
                    f.db.clone(),
                    Caller::authenticated(&f.b),
                    "get_record",
                    json!({"ids":[new]})
                )
                .await
                .unwrap()["records"][0]["status"],
            "not_found"
        );
    }
}
#[tokio::test]
async fn lost_kind_shape_and_null_facet_are_unusable_with_no_ensure_effects() {
    let f = fixture(true).await;
    let first = call(&f, &f.a, ensure()).await;
    let id = first["record_id"].as_str().unwrap();
    let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
    sqlx::query("UPDATE vocabulary_values SET status='deprecated' WHERE vocabulary_id='voc:kind:Configuration' AND value=?").bind(KIND).execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(call(&f, &f.a, inspect()).await["reason"], "wrong_kind");
    let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
    sqlx::query("UPDATE vocabulary_values SET status='active' WHERE vocabulary_id='voc:kind:Configuration' AND value=?").bind(KIND).execute(&mut *tx).await.unwrap();
    sqlx::query("DELETE FROM schema_config WHERE layer='user'")
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(call(&f, &f.a, inspect()).await["reason"], "invalid_content");
    let before = effects(&f.db).await;
    assert_eq!(call(&f, &f.a, ensure()).await["status"], "unusable");
    assert_eq!(effects(&f.db).await, before);
    let shape: Value = serde_json::from_str(APPROVED).unwrap();
    write_user_schema_config(&f.db,json!({"shapes":{"Configuration:focus_preferences":{"facets":{"focus.preferences":shape}}}}),SchemaConfigOptions::default()).await.unwrap();
    let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
    sqlx::query("UPDATE facet_values SET value=NULL WHERE record_id=? AND key=?")
        .bind(id)
        .bind(FACET)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(call(&f, &f.a, inspect()).await["reason"], "invalid_content");
    let before = effects(&f.db).await;
    assert_eq!(call(&f, &f.a, ensure()).await["outcome"], "refused");
    assert_eq!(effects(&f.db).await, before);
}
#[tokio::test]
async fn caller_bound_member_copy_and_read_only_standby_preserve_mapping() {
    let f = fixture(true).await;
    let a = call(&f, &f.a, ensure()).await;
    let b = call(&f, &f.b, ensure()).await;
    let dir = tempfile::tempdir().unwrap();
    for (i, account, expected) in [(0, &f.a, &a), (1, &f.b, &b)] {
        let path = dir.path().join(format!("member-{i}.db"));
        crate::member_copy_producer::build_member_copy(
            &f.db,
            crate::member_copy_producer::MemberCopyRequest {
                member_account: account.clone(),
                scope_ref: format!("scope-config-{i}"),
                hosted_route_database_id: "route-config".into(),
                ordinal: 1,
                consumer: crate::standby_snapshot::StandbyConsumerIdentity {
                    contract: crate::standby_snapshot::STANDBY_CONSUMER_CONTRACT.into(),
                    version: 1,
                    platform: crate::standby_snapshot::StandbyConsumerPlatform::LinuxX8664,
                    source_sha: "c".repeat(40),
                    artifact_sha256: "d".repeat(64),
                    engine_schema_version: crate::CURRENT_ENGINE_SCHEMA_VERSION,
                    ddl_sha256: crate::schema::contract::ddl_sha256(),
                },
                out_path: path.clone(),
            },
        )
        .await
        .unwrap();
        let copy = crate::db::open_member_database_read_only(path.to_str().unwrap())
            .await
            .unwrap();
        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT account_id,record_id FROM account_configs ORDER BY account_id")
                .fetch_all(copy.pool())
                .await
                .unwrap();
        assert_eq!(
            rows,
            vec![(
                account.clone(),
                expected["record_id"].as_str().unwrap().to_owned()
            )]
        );
        copy.close().await;
    }
    let path = dir.path().join("standby.db");
    let bytes = crate::interchange::export_canonical_interchange(&f.db)
        .await
        .unwrap();
    let exported = crate::interchange::import_canonical_interchange(
        &bytes,
        &path,
        crate::interchange::ImportContinuity::ForeignBoundary,
    )
    .await
    .unwrap();
    exported.close().await;
    let standby = crate::db::open_existing_database_standby_read_only(path.to_str().unwrap())
        .await
        .unwrap();
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry.set_standby_read_only(true);
    let mut tx = standby.pool().begin().await.unwrap();
    assert_eq!(
        mapping(&mut tx, &f.a).await.unwrap().as_deref(),
        a["record_id"].as_str()
    );
    tx.rollback().await.unwrap();
    for args in [
        inspect(),
        ensure(),
        replace(a["record_id"].as_str().unwrap()),
    ] {
        assert!(matches!(
            registry
                .call(standby.clone(), Caller::authenticated(&f.a), TOOL, args)
                .await
                .unwrap_err(),
            Error::UnavailableOffline { .. }
        ));
    }
    standby.close().await;
}

#[tokio::test]
async fn schema88_to89_migration_step_down_preserves_core_and_restores_projection() {
    assert_eq!(
        crate::schema::contract::ddl_sha256(),
        crate::schema::contract::FROZEN_DDL_SHA256
    );
    let revision6 = crate::interchange::source_history_application_id(6);
    let revision7 = crate::interchange::source_history_application_id(7);
    let steps = crate::migrations::EngineMigrationRegistry::production()
        .pending(88, 89)
        .unwrap();
    assert_eq!(steps.len(), 1);
    for marker in [
        revision6,
        crate::interchange::source_history_application_id(5),
        0,
    ] {
        // step_down starts from current, while this historical edge ends at 89.
        let f = fixture(false).await;
        let before = effects(&f.db).await;
        let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
        for statement in crate::schema::step_down::statements(88) {
            sqlx::query(&statement).execute(&mut *tx).await.unwrap();
        }
        assert_eq!(
            sqlx::query_scalar::<_, i64>("PRAGMA user_version")
                .fetch_one(&mut *tx)
                .await
                .unwrap(),
            88
        );
        sqlx::query(&format!("PRAGMA application_id={marker}"))
            .execute(&mut *tx)
            .await
            .unwrap();
        steps[0].preflight(&mut tx).await.unwrap();
        steps[0].apply(&mut tx).await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("PRAGMA application_id")
                .fetch_one(&mut *tx)
                .await
                .unwrap(),
            if marker == revision6 {
                revision7
            } else {
                marker
            }
        );
        sqlx::query("PRAGMA user_version=89")
            .execute(&mut *tx)
            .await
            .unwrap();
        crate::db::validate_supported_engine_migration_source(&mut tx, 89)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(effects(&f.db).await, before);
        assert_eq!(call(&f, &f.a, inspect()).await["status"], "absent");
    }
}

#[tokio::test]
async fn authenticated_archived_recovery_requires_both_guards_and_preserves_content() {
    let f = fixture(true).await;
    let first = call(&f, &f.a, ensure()).await;
    let id = first["record_id"].as_str().unwrap();
    update(&f,id,json!({"name":"Retain preferences across archive recovery","facets":{"focus.preferences":{"version":1,"foci":[
        {"focus_id":"90220000-0000-4000-8000-000000000001","tier":"background","hidden":false}]}}})).await;
    f.registry
        .call(
            f.db.clone(),
            Caller::authenticated(&f.a),
            "archive_record",
            json!({"id":id,"archived":true,"reason":"Archive for out-of-band recovery proof."}),
        )
        .await
        .unwrap();
    let before = call(&f, &f.a, inspect()).await;
    assert_eq!(before["reason"], "archived");
    assert!(before["content_revision"].is_null());
    let record = f
        .registry
        .call(
            f.db.clone(),
            Caller::authenticated(&f.a),
            "get_record",
            json!({"ids":[id]}),
        )
        .await
        .unwrap();
    let policy = f
        .registry
        .call(
            f.db.clone(),
            Caller::authenticated(&f.a),
            "manage_record_policy",
            json!({"action":"list","record_id":id}),
        )
        .await
        .unwrap();
    let state = old_state(&f.db, id).await;
    let batch = |revision: &str| {
        json!({"reason":"Explicitly restore archived preferences without loss.","items":[
        {"op":"update","id":id,"if_unmodified_since":record["records"][0]["updated_at"],"if_policy_revision":revision},
        {"op":"archive","id":id,"archived":false}]})
    };
    let effects_before = effects(&f.db).await;
    assert!(f
        .registry
        .call(
            f.db.clone(),
            Caller::authenticated(&f.a),
            "batch_write",
            batch("prv1:stale")
        )
        .await
        .is_err());
    assert_eq!(old_state(&f.db, id).await, state);
    assert_eq!(effects(&f.db).await, effects_before);
    f.registry
        .call(
            f.db.clone(),
            Caller::authenticated(&f.a),
            "batch_write",
            batch(policy["policy_revision"].as_str().unwrap()),
        )
        .await
        .unwrap();
    let healthy = call(&f, &f.a, inspect()).await;
    assert_eq!(healthy["status"], "healthy");
    assert_guard_bytes(&f, &f.a, &healthy).await;
    let after = old_state(&f.db, id).await;
    let preferences = |state: &Value| {
        state["facets"]
            .as_array()
            .unwrap()
            .iter()
            .find(|facet| facet[0] == FACET)
            .unwrap()
            .clone()
    };
    assert_eq!(preferences(&after), preferences(&state));
    assert_eq!(after["policy"], state["policy"]);
    let before_record: Value = serde_json::from_str(state["record"].as_str().unwrap()).unwrap();
    let after_record: Value = serde_json::from_str(after["record"].as_str().unwrap()).unwrap();
    for field in ["type", "kind", "name", "body", "policy_anchor_id"] {
        assert_eq!(after_record[field], before_record[field]);
    }
    assert_eq!(after_record["archived"], 0);
}
