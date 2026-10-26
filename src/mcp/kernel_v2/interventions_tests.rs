use super::*;
use crate::identity::hosted::{
    reconcile_hosted_identity, HostedMembershipArrival, HostedMembershipRole,
    HostedMembershipSource,
};
// source_id, origin, payload, account_principal, record_id, observed_at.
type DirectoryStateRow = (
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    String,
);

struct Fixture {
    dir: tempfile::TempDir,
    source: Db,
    target: Db,
    owner: String,
    member: String,
    message: String,
    id: String,
    origin: String,
}
async fn call(db: &Db, v2: bool, account: &str, tool: &str, args: Value) -> Result<Value> {
    registry()
        .call_engine(
            if v2 {
                EngineHandle::KernelV2(db.clone())
            } else {
                EngineHandle::Sqlite(db.clone())
            },
            Caller::authenticated(account),
            tool,
            args,
        )
        .await
}
async fn resume(f: &Fixture) {
    let report = crate::v1_import::run(crate::v1_import::Options {
        source: f.dir.path().join("source.db"),
        target: f.dir.path().join("target.db"),
        seeds: vec![],
        all: true,
        history: true,
        resume: true,
        members_file: Some(f.dir.path().join("members.txt")),
    })
    .await
    .unwrap();
    assert!(
        report.refusals.is_empty(),
        "{}",
        serde_json::to_string(&report.refusals).unwrap()
    );
    assert!(report.review.is_empty());
}
async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let source = crate::create_database(dir.path().join("source.db").to_str().unwrap())
        .await
        .unwrap();
    let mut accounts = vec![];
    for (label, role) in [
        ("owner", HostedMembershipRole::Owner),
        ("member", HostedMembershipRole::Member),
    ] {
        accounts.push(
            reconcile_hosted_identity(
                &source,
                &format!("{label}@example.test"),
                label,
                &HostedMembershipArrival::new(
                    role,
                    HostedMembershipSource::Direct,
                    "2026-10-20T00:00:00Z".into(),
                )
                .unwrap(),
                Some(&format!("native/synthetic-{label}")),
            )
            .await
            .unwrap(),
        );
    }
    let owner = accounts.remove(0);
    let member = accounts.remove(0);
    registry().call(source.clone(),Caller::local(),"manage_record_policy",json!({"action":"grant","record_id":"native:root","subject":{"kind":"account","account_id":owner},"capability":"manage","reason":"Synthetic escalation policy owner"})).await.unwrap();
    let people:Vec<(String,String)>=sqlx::query_as("SELECT a.identifier,p.identifier FROM bindings a JOIN bindings p ON p.record_id=a.record_id AND p.system='native-principal' AND p.is_canonical=1 WHERE a.system='account' AND a.is_canonical=1").fetch_all(source.pool()).await.unwrap();
    let sender_principal = people.iter().find(|(a, _)| a == &owner).unwrap().1.clone();
    let sender: String = sqlx::query_scalar(
        "SELECT record_id FROM bindings WHERE system='account' AND is_canonical=1 AND identifier=?",
    )
    .bind(&owner)
    .fetch_one(source.pool())
    .await
    .unwrap();
    let recipient: String = sqlx::query_scalar(
        "SELECT record_id FROM bindings WHERE system='account' AND is_canonical=1 AND identifier=?",
    )
    .bind(&member)
    .fetch_one(source.pool())
    .await
    .unwrap();
    let policy=call(&source,false,&owner,"create_record",json!({"type":"Document","kind":"escalation-policy","name":"Synthetic escalation policy","body":json!({"format":"native.escalation-policy.v1","issuer_principal_id":sender_principal,"statements":[{"statement_id":"block","kind":"hard_rule","scope":{},"when":{"all":[{"field":"action.operation","op":"eq","value":"send_message"}]},"effect":{"disposition":"block_and_request_authority"}}]}).to_string(),"reason":"Synthetic intervention fixture"})).await.unwrap()["id"].as_str().unwrap().to_owned();
    let position = call(
        &source,
        false,
        &owner,
        "manage_instructions",
        json!({"action":"list","scope":"member"}),
    )
    .await
    .unwrap()["bindings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|b| b["position"].as_i64())
        .max()
        .unwrap_or(0)
        + 100;
    call(&source,false,&owner,"manage_instructions",json!({"action":"create_binding","scope":"member","source_record_id":policy,"position":position,"idempotency_key":"synthetic-policy","reason":"Synthetic intervention fixture"})).await.unwrap();
    let sent=call(&source,false,&owner,"manage_messages",json!({"action":"send","body":"PRIVATE UNDELIVERED BODY","preview":"Safe target preview","origin":{"type":"direct","participant_ids":[sender,recipient]},"addressed_to":[recipient],"expectation":"reply","idempotency_key":"synthetic-send","reason":"Synthetic intervention fixture"})).await.unwrap();
    let message = sent["id"].as_str().unwrap().to_owned();
    let id:String=sqlx::query_scalar("SELECT json_extract(payload,'$.intervention_id') FROM content_events WHERE type='intervention.raised.v1' AND record_id=?").bind(&message).fetch_one(source.pool()).await.unwrap();
    let origin: String =
        sqlx::query_scalar("SELECT origin_db_id FROM database_identity WHERE singleton=1")
            .fetch_one(source.pool())
            .await
            .unwrap();
    std::fs::write(
        dir.path().join("members.txt"),
        format!("{owner}\n{member}\n"),
    )
    .unwrap();
    let report = crate::v1_import::run(crate::v1_import::Options {
        source: dir.path().join("source.db"),
        target: dir.path().join("target.db"),
        seeds: vec![],
        all: true,
        history: true,
        resume: false,
        members_file: Some(dir.path().join("members.txt")),
    })
    .await
    .unwrap();
    assert!(
        report.refusals.is_empty(),
        "{}",
        serde_json::to_string(&report.refusals).unwrap()
    );
    assert!(report.review.is_empty());
    let target = kernel::open_marked_v2_database(dir.path().join("target.db").to_str().unwrap())
        .await
        .unwrap();
    Fixture {
        dir,
        source,
        target,
        owner,
        member,
        message,
        id,
        origin,
    }
}
async fn parity(f: &Fixture) -> Value {
    let args = json!({"action":"get","intervention_id":f.id});
    let expected = call(
        &f.source,
        false,
        &f.member,
        "manage_interventions",
        args.clone(),
    )
    .await
    .unwrap();
    let mut actual = call(&f.target, true, &f.member, "manage_interventions", args)
        .await
        .unwrap();
    assert_eq!(actual["identity"]["resolver_database_id"], f.origin);
    assert!(!actual.to_string().contains("PRIVATE UNDELIVERED BODY"));
    assert_eq!(actual["mutations_available"], false);
    assert!(actual["affordances"]
        .as_array()
        .unwrap()
        .iter()
        .all(|a| a["enabled"] == false));
    actual
        .as_object_mut()
        .unwrap()
        .remove("mutations_available");
    actual
        .as_object_mut()
        .unwrap()
        .remove("unavailable_message");
    actual["affordances"] = expected["affordances"].clone();
    assert_eq!(actual, expected);
    actual
}
#[tokio::test]
async fn kernel_v2_intervention_get_matches_v1_target_preview_and_terminal_delta() {
    let registered = registry();
    assert!(registered.has_engine_operation(
        "manage_interventions",
        EngineKind::KernelV2,
        Some(("action", "get"))
    ));
    for action in ["query", "cancel", "resume_delivery"] {
        assert!(!registered.has_engine_operation(
            "manage_interventions",
            EngineKind::KernelV2,
            Some(("action", action))
        ));
        assert!(registered.has_engine_operation(
            "manage_interventions",
            EngineKind::Sqlite,
            Some(("action", action))
        ));
    }
    let f = fixture().await;
    let plan:Vec<String>=sqlx::query("EXPLAIN QUERY PLAN SELECT e.payload FROM main.kernel_legacy_sql_events h JOIN main.content_events e ON e.seq=h.seq WHERE h.source_stream='content_events' AND h.event_type IN ('intervention.raised.v1','intervention.cancelled.v1','intervention.execution_resumed.v1') AND json_extract(e.payload,'$.legacy.payload.intervention_id')=? ORDER BY h.seq").bind(&f.id).fetch_all(f.target.pool()).await.unwrap().iter().map(|r|sqlx::Row::get::<String,_>(r,"detail")).collect();
    assert!(
        plan.iter()
            .any(|p| p.contains("idx_kernel_legacy_interventions")),
        "{plan:?}"
    );

    let before = kernel::dump_all_kernel_tables(&f.target).await.unwrap();
    let view = parity(&f).await;
    let routed = registry()
        .call_engine(
            EngineHandle::KernelV2(f.target.clone()),
            Caller::authenticated(&f.member)
                .with_hosting_context("synthetic-catalog-member", "synthetic-route-alias")
                .with_hosting_member(true),
            "manage_interventions",
            json!({"action":"get","intervention_id":f.id}),
        )
        .await
        .unwrap();
    assert_eq!(
        routed["identity"], view["identity"],
        "retained canonical identity is the v1 source identity, not an invented route alias"
    );
    for account in [&f.owner, "not-a-member"] {
        assert!(call(
            &f.target,
            true,
            account,
            "manage_interventions",
            json!({"action":"get","intervention_id":f.id})
        )
        .await
        .is_err());
    }
    let error = call(
        &f.target,
        true,
        &f.owner,
        "manage_interventions",
        json!({"action":"get","intervention_id":f.id}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("intervention unavailable"));
    assert!(!error.contains("Safe target preview"));
    assert!(call(
        &f.target,
        true,
        &f.member,
        "get_record",
        json!({"id":f.message})
    )
    .await
    .unwrap()
    .to_string()
    .contains("not_found"));
    assert_eq!(
        before,
        kernel::dump_all_kernel_tables(&f.target).await.unwrap()
    );
    call(&f.source,false,&f.member,"manage_interventions",json!({"action":"cancel","intervention_id":f.id,"expected_intervention_seq":view["guard_tokens"]["expected_intervention_seq"],"idempotency_key":"synthetic-cancel","reason":"Synthetic terminal delta"})).await.unwrap();
    resume(&f).await;
    assert_eq!(parity(&f).await["state"]["execution"]["state"], "cancelled");
    let before = kernel::dump_all_kernel_tables(&f.target).await.unwrap();
    kernel::replay_all_projections(&f.target).await.unwrap();
    assert_eq!(
        before,
        kernel::dump_all_kernel_tables(&f.target).await.unwrap()
    );
    parity(&f).await;
    f.source.close().await;
    f.target.close().await;
}
#[tokio::test]
async fn kernel_v2_intervention_get_refuses_rebound_target_and_is_physically_read_only() {
    let f = fixture().await;
    let readonly = crate::db::open_marked_v2_database_read_only_at(&f.dir.path().join("target.db"))
        .await
        .unwrap();
    call(
        &readonly,
        true,
        &f.member,
        "manage_interventions",
        json!({"action":"get","intervention_id":f.id}),
    )
    .await
    .unwrap();
    readonly.close().await;
    sqlx::query("UPDATE kernel_v1_state SET payload=json_set(payload,'$.native_principal_id','native/rebound') WHERE section='account_directory'")
        .execute(f.target.write_pool())
        .await
        .unwrap();
    let error = call(
        &f.target,
        true,
        &f.member,
        "manage_interventions",
        json!({"action":"get","intervention_id":f.id}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("intervention unavailable"));
    kernel::replay_all_projections(&f.target).await.unwrap();
    parity(&f).await;
    for args in [
        json!({"action":"get","intervention_id":f.id,"extra":true}),
        json!({"action":"get","intervention_id":"missing"}),
    ] {
        assert!(call(
            &f.source,
            false,
            &f.member,
            "manage_interventions",
            args.clone()
        )
        .await
        .is_err());
        assert!(
            call(&f.target, true, &f.member, "manage_interventions", args)
                .await
                .is_err()
        );
    }
    f.source.close().await;
    f.target.close().await;
}

#[tokio::test]
async fn kernel_v2_intervention_get_authorizes_before_decoding_private_retained_fields() {
    let f = fixture().await;
    let host = kernel::resolve_principal_by_binding(&f.target, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let raw: String = sqlx::query_scalar(
        "SELECT payload FROM content_events WHERE type='intervention.raised.v1' AND record_id=?",
    )
    .bind(&f.message)
    .fetch_one(f.source.pool())
    .await
    .unwrap();
    let mut payload: Value = serde_json::from_str(&raw).unwrap();
    payload["intervention_id"] = json!("malformed-retained-intervention");
    payload["PRIVATE_UNKNOWN_FIELD"] = json!("PRIVATE FIELD VALUE");
    kernel::import_event_as(&f.target,&host,&f.message,&kernel::LegacyEvent {
        source:Some(json!({"origin":f.origin,"stream":"content_events","metadata":{"record_id":f.message,"seq":1_000_000},"subjects":[f.message]})),
        id:uuid::Uuid::new_v4().to_string(),event_type:"intervention.raised.v1".into(),payload,created_at:crate::store::now_iso(),actor:Some(f.owner.clone()),run_key:None,
    }).await.unwrap();
    let args = json!({"action":"get","intervention_id":"malformed-retained-intervention"});
    let error = call(
        &f.target,
        true,
        &f.owner,
        "manage_interventions",
        args.clone(),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("intervention unavailable"), "{error}");
    assert!(!error.contains("PRIVATE_UNKNOWN_FIELD"));
    assert!(!error.contains("PRIVATE FIELD VALUE"));
    let error = call(&f.target, true, &f.member, "manage_interventions", args)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("PRIVATE_UNKNOWN_FIELD"),
        "the actual target reaches the malformed envelope diagnostic: {error}"
    );
    f.source.close().await;
    f.target.close().await;
}

#[tokio::test]
async fn kernel_v2_intervention_identity_capture_requires_resume_and_native_binding_overrides_it() {
    let f = fixture().await;
    let (count,): (i64,) = sqlx::query_as("SELECT count(*) FROM kernel_identity_bindings")
        .fetch_one(f.target.pool())
        .await
        .unwrap();
    assert_eq!(
        count, 0,
        "source evidence must not fabricate public binding rows"
    );
    sqlx::query("DELETE FROM kernel_v1_state WHERE section='identity_directory_capture'")
        .execute(f.target.write_pool())
        .await
        .unwrap();
    let before = kernel::dump_all_kernel_tables(&f.target).await.unwrap();
    let args = json!({"action":"get","intervention_id":f.id});
    let error = call(
        &f.target,
        true,
        &f.member,
        "manage_interventions",
        args.clone(),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("identity directory needs preparation"),
        "{error}"
    );
    let error = call(
        &f.target,
        true,
        &f.owner,
        "manage_interventions",
        args.clone(),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("intervention unavailable"));
    assert!(!error.contains("preparation"));
    assert!(
        kernel::verify_marked_v2_file_read_only(&f.dir.path().join("target.db"))
            .await
            .unwrap_err()
            .to_string()
            .contains("identity directory needs preparation")
    );
    assert_eq!(
        before,
        kernel::dump_all_kernel_tables(&f.target).await.unwrap()
    );
    kernel::prepare_v2_database(&f.target).await.unwrap();
    assert!(call(
        &f.target,
        true,
        &f.member,
        "manage_interventions",
        args.clone()
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("needs preparation"));
    resume(&f).await;
    parity(&f).await;
    kernel::verify_marked_v2_file_read_only(&f.dir.path().join("target.db"))
        .await
        .unwrap();
    let person: String = sqlx::query_scalar(
        "SELECT record_id FROM bindings WHERE system='account' AND is_canonical=1 AND identifier=?",
    )
    .bind(&f.member)
    .fetch_one(f.source.pool())
    .await
    .unwrap();
    call(&f.target,true,&f.owner,"manage_bindings",json!({"action":"add","record_id":person,"binding":{"system":"native-principal","identifier":"native/rebound"},"canonical":true,"reason":"Synthetic current public identity change"})).await.unwrap();
    let error = call(&f.target, true, &f.member, "manage_interventions", args)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("intervention unavailable"));
    f.source.close().await;
    f.target.close().await;
}

#[tokio::test]
async fn kernel_v2_intervention_old_directory_rows_require_data_resume_not_schema_preparation() {
    let f = fixture().await;
    let host = kernel::resolve_principal_by_binding(&f.target, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let rows: Vec<DirectoryStateRow> = sqlx::query_as("SELECT source_id,origin,payload,account_principal,record_id,observed_at FROM kernel_v1_state WHERE section='account_directory'").fetch_all(f.target.pool()).await.unwrap();
    for (source_id, origin, payload, account_principal, record_id, observed_at) in rows {
        let mut value: Value = serde_json::from_str(&payload).unwrap();
        value.as_object_mut().unwrap().remove("native_principal_id");
        // Seal the actual old importer row shape so replay cannot accidentally
        // repair this fixture using a newer canonical envelope.
        kernel::v1_state::import_state_batch_as(
            &f.target,
            &host,
            &[kernel::v1_state::ImportedState {
                section: "account_directory".into(),
                source_id,
                origin,
                value_json: Some(value.to_string()),
                account_principal,
                record_id,
                observed_at,
                snapshot: json!({"fixture":"old-directory"}),
            }],
        )
        .await
        .unwrap();
    }
    kernel::replay_all_projections(&f.target).await.unwrap();
    kernel::prepare_v2_database(&f.target).await.unwrap();
    assert!(
        kernel::verify_marked_v2_file_read_only(&f.dir.path().join("target.db"))
            .await
            .unwrap_err()
            .to_string()
            .contains("identity directory needs preparation")
    );
    resume(&f).await;
    parity(&f).await;
    kernel::verify_marked_v2_file_read_only(&f.dir.path().join("target.db"))
        .await
        .unwrap();
    let raw: String = sqlx::query_scalar(
        "SELECT payload FROM kernel_v1_state WHERE section='identity_directory_capture'",
    )
    .fetch_one(f.target.pool())
    .await
    .unwrap();
    let mut old_receipt: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(
        old_receipt["version"],
        kernel::v1_state::IDENTITY_CAPTURE_VERSION
    );
    old_receipt["version"] = json!(1);
    old_receipt.as_object_mut().unwrap().remove("refused");
    kernel::v1_state::import_state_batch_as(
        &f.target,
        &host,
        &[kernel::v1_state::ImportedState {
            section: kernel::v1_state::IDENTITY_CAPTURE.into(),
            source_id: "identity-directory/v1".into(),
            origin: f.origin.clone(),
            value_json: Some(old_receipt.to_string()),
            account_principal: None,
            record_id: None,
            observed_at: chrono::Utc::now().to_rfc3339(),
            snapshot: json!({"fixture":"version-one-receipt"}),
        }],
    )
    .await
    .unwrap();
    // A complete directory does not make an older receipt safe for activation.
    assert!(
        kernel::verify_marked_v2_file_read_only(&f.dir.path().join("target.db"))
            .await
            .unwrap_err()
            .to_string()
            .contains("identity directory needs preparation")
    );
    resume(&f).await;
    kernel::verify_marked_v2_file_read_only(&f.dir.path().join("target.db"))
        .await
        .unwrap();
    f.source.close().await;
    f.target.close().await;
}

#[tokio::test]
async fn kernel_v2_intervention_ambiguous_source_identity_invalidates_prior_capture_receipt() {
    let f = fixture().await;
    // Deliberately damaged legacy fixture: current v1's canonical uniqueness
    // index normally prevents this shape, but the importer must refuse it.
    sqlx::query("DROP INDEX idx_bindings_one_canonical_per_system")
        .execute(f.source.write_pool())
        .await
        .unwrap();
    sqlx::query("INSERT INTO bindings(record_id,system,identifier,is_canonical) SELECT record_id,'native-principal','native/ambiguous-second',1 FROM bindings WHERE system='account' AND identifier=? AND is_canonical=1").bind(&f.member).execute(f.source.write_pool()).await.unwrap();
    let report = crate::v1_import::run(crate::v1_import::Options {
        source: f.dir.path().join("source.db"),
        target: f.dir.path().join("target.db"),
        seeds: vec![],
        all: true,
        history: true,
        resume: true,
        members_file: Some(f.dir.path().join("members.txt")),
    })
    .await
    .unwrap();
    assert!(!report.state.identity_directory_prepared);
    assert_eq!(report.state.sections["account_directory"].refused, 1);
    let gate = crate::v1_import::cutover::capture_report(
        &report,
        &f.dir.path().join("source.db"),
        true,
        true,
        true,
    )
    .await
    .unwrap();
    assert_eq!(gate["capture_complete"], false);
    assert!(report
        .refusals
        .iter()
        .any(|r| r.reason.contains("ambiguous canonical native-principal")));
    assert!(
        kernel::verify_marked_v2_file_read_only(&f.dir.path().join("target.db"))
            .await
            .unwrap_err()
            .to_string()
            .contains("identity directory needs preparation")
    );
    kernel::replay_all_projections(&f.target).await.unwrap();
    assert!(
        kernel::verify_marked_v2_file_read_only(&f.dir.path().join("target.db"))
            .await
            .is_err()
    );
    f.source.close().await;
    f.target.close().await;
}

#[tokio::test]
async fn kernel_v2_intervention_activated_target_refuses_resume_without_changing_evidence() {
    let f = fixture().await;
    let roster = [
        ("owner".to_owned(), "owner@example.test".to_owned()),
        ("member".to_owned(), "member@example.test".to_owned()),
    ]
    .into_iter()
    .collect::<std::collections::BTreeMap<_, _>>();
    let caller = kernel::hosted_identity::reconcile_hosted_caller(&f.target, |_| async {
        // SAFETY: complete synthetic catalogue/roster, never production data.
        Ok(unsafe {
            kernel::hosted_identity::VerifiedHostedMembership::from_catalog_unchecked(
                "member".into(),
                roster.clone(),
                roster,
            )
        })
    })
    .await
    .unwrap();
    assert_eq!(caller.credential(), f.member);
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM content_events WHERE type='kernel.hosted_membership.v1'",
    )
    .fetch_one(f.target.pool())
    .await
    .unwrap();
    assert!(count > 0);
    let before = crate::v1_import::cutover::snapshot_digest(&f.dir.path().join("target.db"))
        .await
        .unwrap();
    let error = crate::v1_import::run(crate::v1_import::Options {
        source: f.dir.path().join("source.db"),
        target: f.dir.path().join("target.db"),
        seeds: vec![],
        all: true,
        history: true,
        resume: true,
        members_file: Some(f.dir.path().join("members.txt")),
    })
    .await
    .err()
    .unwrap();
    assert!(error.to_string().contains("--resume is forbidden"));
    assert_eq!(
        before,
        crate::v1_import::cutover::snapshot_digest(&f.dir.path().join("target.db"))
            .await
            .unwrap()
    );
    f.source.close().await;
    f.target.close().await;
}
