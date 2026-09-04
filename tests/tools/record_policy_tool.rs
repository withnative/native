use native_ce::authorization::{
    effective_capability, replace_explicit_policy, Capability, Principal,
};

use native_ce::conformance::rebuild_and_diff_policy;
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::store::create_record;
use native_ce::Db;
use serde_json::{json, Value};

// Fixture record ids. A record id must be a canonical lowercase v4/v7 UUID,
// so these pinned literals stand in for the readable slugs they name.
// Hardcoded, never generated, so assertions stay deterministic.
/// `owner-person`
const OWNER_PERSON: &str = "90110000-0000-4000-8000-000000000004";
/// `bob-person`
const BOB_PERSON: &str = "90110000-0000-4000-8000-000000000005";
/// `policy-target`
const POLICY_TARGET: &str = "90110000-0000-4000-8000-000000000006";
/// `policy-errors`
const POLICY_ERRORS: &str = "90110000-0000-4000-8000-000000000007";
/// `bearer-owner`
const BEARER_OWNER: &str = "90110000-0000-4000-8000-000000000008";
/// `policy-bearer`
const POLICY_BEARER: &str = "90110000-0000-4000-8000-000000000009";
/// `rollback-policy-target`
const ROLLBACK_POLICY_TARGET: &str = "90110000-0000-4000-8000-00000000000a";

async fn call(
    registry: &ToolRegistry,
    db: &Db,
    caller: Caller,
    arguments: Value,
) -> native_ce::Result<Value> {
    registry
        .call(db.clone(), caller, "manage_record_policy", arguments)
        .await
}

async fn bind_account(db: &Db, person_id: &str, account_id: &str) {
    sqlx::query(
        "INSERT INTO bindings (record_id,system,identifier,is_canonical)
         VALUES (?,'account',?,1)",
    )
    .bind(person_id)
    .bind(account_id)
    .execute(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap();
}

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

#[test]
fn policy_schema_is_action_discriminated_and_requires_each_actions_inputs() {
    let registry = registry();
    let schema = &registry.get("manage_record_policy").unwrap().input_schema;
    let branches = schema["oneOf"].as_array().unwrap();
    assert_eq!(branches.len(), 8);
    let by_action = |action: &str| {
        branches
            .iter()
            .find(|branch| branch["properties"]["action"]["const"] == action)
            .unwrap_or_else(|| panic!("missing {action} schema branch"))
    };

    assert_eq!(
        by_action("inspect")["required"],
        json!(["action", "record_id", "run_key"])
    );
    assert_eq!(
        by_action("list")["required"],
        json!(["action", "record_id", "run_key"])
    );
    assert_eq!(
        by_action("set_many")["required"],
        json!(["action", "items", "reason", "run_key"])
    );
    assert_eq!(by_action("set_many")["properties"]["items"]["minItems"], 1);
    assert_eq!(
        by_action("set_many")["properties"]["items"]["maxItems"],
        100
    );
    assert_eq!(
        by_action("grant")["required"],
        json!([
            "action",
            "record_id",
            "subject",
            "capability",
            "reason",
            "run_key"
        ])
    );
    assert_eq!(
        by_action("revoke")["required"],
        json!(["action", "record_id", "subject", "reason", "run_key"])
    );
    assert_eq!(
        by_action("set_members_baseline")["required"],
        json!(["action", "record_id", "reason", "run_key"])
    );
    assert_eq!(
        by_action("replace")["required"],
        json!([
            "action",
            "record_id",
            "entries",
            "if_policy_revision",
            "reason",
            "run_key"
        ])
    );
    assert_eq!(
        by_action("restore_inheritance")["required"],
        json!([
            "action",
            "record_id",
            "if_policy_revision",
            "reason",
            "run_key"
        ])
    );
    assert!(by_action("inspect")["properties"].get("subject").is_none());
    assert!(by_action("revoke")["properties"]
        .get("capability")
        .is_none());
    assert!(by_action("replace")["properties"].get("entries").is_some());
}

#[tokio::test]
async fn set_many_is_exact_atomic_indexed_and_safe_to_retry() {
    const FIRST: &str = "90110000-0000-4000-8000-00000000000b";
    const SECOND: &str = "90110000-0000-4000-8000-00000000000c";
    let db = native_ce::create_database(":memory:").await.unwrap();
    let registry = registry();
    for (id, name) in [(FIRST, "First exact set"), (SECOND, "Second exact set")] {
        registry
            .call(
                db.clone(),
                Caller::local(),
                "create_record",
                json!({
                    "id":id,
                    "type":"Document",
                    "kind":"note",
                    "name":name,
                    "reason":"Create an exact-set policy fixture.",
                }),
            )
            .await
            .unwrap();
    }
    call(
        &registry,
        &db,
        Caller::local(),
        json!({
            "action":"grant",
            "record_id":FIRST,
            "subject":{"kind":"account","account_id":"acct:exact"},
            "capability":"manage",
            "reason":"Establish the stronger grant that set_many will downgrade.",
        }),
    )
    .await
    .unwrap();

    let request = json!({
        "action":"set_many",
        "items":[
            {
                "record_id":FIRST,
                "subject":{"kind":"account","account_id":"acct:exact"},
                "capability":"view",
            },
            {
                "record_id":SECOND,
                "subject":{"kind":"account","account_id":"acct:absent"},
                "capability":null,
            },
            {
                "record_id":FIRST,
                "subject":{"kind":"account","account_id":"acct:second-on-first"},
                "capability":"edit",
            }
        ],
        "reason":"Converge both account grants to their exact requested state.",
    });
    let first = call(&registry, &db, Caller::local(), request.clone())
        .await
        .unwrap();
    assert_eq!(first["item_count"], 3);
    assert_eq!(first["changed_count"], 2);
    assert_eq!(first["outcomes"][0]["index"], 0);
    assert_eq!(first["outcomes"][0]["changed"], true);
    assert_eq!(first["outcomes"][1]["index"], 1);
    assert_eq!(first["outcomes"][1]["changed"], false);
    assert_eq!(first["outcomes"][2]["index"], 2);
    assert_eq!(first["outcomes"][2]["changed"], true);
    let listed = call(
        &registry,
        &db,
        Caller::local(),
        json!({"action":"list","record_id":FIRST}),
    )
    .await
    .unwrap();
    let entries = listed["entries"].as_array().unwrap();
    assert!(entries.iter().any(|entry| {
        entry["subject"]["account_id"] == "acct:exact" && entry["capability"] == "view"
    }));
    assert!(entries.iter().any(|entry| {
        entry["subject"]["account_id"] == "acct:second-on-first" && entry["capability"] == "edit"
    }));
    let event_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policy_events")
        .fetch_one(db.pool())
        .await
        .unwrap();

    let retry = call(&registry, &db, Caller::local(), request)
        .await
        .unwrap();
    assert_eq!(retry["changed_count"], 0);
    assert!(retry["outcomes"]
        .as_array()
        .unwrap()
        .iter()
        .all(|outcome| outcome["changed"] == false));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM policy_events")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        event_count,
        "retrying an already converged set appended a policy event"
    );

    let before_invalid = event_count;
    let invalid = call(
        &registry,
        &db,
        Caller::local(),
        json!({
            "action":"set_many",
            "items":[
                {
                    "record_id":FIRST,
                    "subject":{"kind":"account","account_id":"acct:would-change"},
                    "capability":"edit",
                },
                {
                    "record_id":SECOND,
                    "subject":{"kind":"members"},
                    "capability":"manage",
                }
            ],
            "reason":"Prove complete validation happens before mutation.",
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(invalid.contains("set_many item 1"), "{invalid}");
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM policy_events")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        before_invalid,
        "an invalid later item allowed an earlier policy mutation"
    );
    db.close().await;
}

#[tokio::test]
async fn set_many_rejects_ancestor_and_descendant_targets_without_writing() {
    const PARENT: &str = "90110000-0000-4000-8000-00000000000d";
    const CHILD: &str = "90110000-0000-4000-8000-00000000000e";
    let db = native_ce::create_database(":memory:").await.unwrap();
    let registry = registry();
    for arguments in [
        json!({
            "id":PARENT,
            "type":"Collection",
            "kind":"folder",
            "name":"Policy batch ancestor",
            "reason":"Create the ancestor policy fixture.",
        }),
        json!({
            "id":CHILD,
            "type":"Document",
            "kind":"note",
            "name":"Policy batch descendant",
            "home_id":PARENT,
            "reason":"Create the descendant policy fixture.",
        }),
    ] {
        registry
            .call(db.clone(), Caller::local(), "create_record", arguments)
            .await
            .unwrap();
    }
    let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policy_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let error = call(
        &registry,
        &db,
        Caller::local(),
        json!({
            "action":"set_many",
            "items":[
                {
                    "record_id":PARENT,
                    "subject":{"kind":"account","account_id":"acct:ancestor"},
                    "capability":"edit",
                },
                {
                    "record_id":CHILD,
                    "subject":{"kind":"account","account_id":"acct:descendant"},
                    "capability":"view",
                }
            ],
            "reason":"This cross-boundary set must be rejected atomically.",
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("ancestor/descendant"), "{error}");
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM policy_events")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        events_before,
        "ancestor/descendant rejection appended a policy event"
    );
    db.close().await;
}

#[tokio::test]
async fn policy_shape_errors_fail_before_record_authorization_or_mutation() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let registry = registry();
    for arguments in [
        json!({
            "action":"grant","record_id":"missing",
            "subject":{"kind":"account","account_id":"acct:test"},"capability":"view"
        }),
        json!({
            "action":"replace","record_id":"missing","entries":[],
            "reason":"The revision is deliberately absent."
        }),
        json!({
            "action":"inspect","record_id":"missing",
            "subject":{"kind":"members"}
        }),
    ] {
        let error = call(
            &registry,
            &db,
            Caller::authenticated("acct:test"),
            arguments,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("invalid arguments for manage_record_policy"),
            "{error}"
        );
        assert!(!error.contains("record missing does not exist"), "{error}");
    }
}

#[tokio::test]
async fn policy_tool_enforces_disclosure_deltas_guards_and_durable_reasons() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let owner = create_record(
        &db,
        json!({"id":OWNER_PERSON,"type":"Entity","kind":"person","name":"Owner"}),
    )
    .await
    .unwrap();
    bind_account(&db, &owner, "acct:owner").await;
    let bob = create_record(
        &db,
        json!({"id":BOB_PERSON,"type":"Entity","kind":"person","name":"Bob"}),
    )
    .await
    .unwrap();
    bind_account(&db, &bob, "acct:bob").await;
    let target = create_record(
        &db,
        json!({"id":POLICY_TARGET,"type":"Document","kind":"note","name":"Policy target","owner_id":owner}),
    )
    .await
    .unwrap();

    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    let owner_caller = Caller::authenticated("acct:owner");
    let viewer = Caller::authenticated("acct:viewer");

    let inspected = call(
        &registry,
        &db,
        viewer.clone(),
        json!({"action":"inspect","record_id":target}),
    )
    .await
    .unwrap();
    assert_eq!(inspected["mode"], "inherit");
    assert_eq!(inspected["caller_capability"], "edit");
    assert!(inspected.get("entries").is_none());
    assert!(inspected.get("policy_revision").is_none());

    let denied = call(
        &registry,
        &db,
        viewer,
        json!({"action":"list","record_id":target}),
    )
    .await
    .unwrap_err();
    assert!(denied.to_string().contains("does not exist"));

    let initial = call(
        &registry,
        &db,
        owner_caller.clone(),
        json!({"action":"list","record_id":target}),
    )
    .await
    .unwrap();
    let stale_revision = initial["policy_revision"].as_str().unwrap().to_string();
    let event_count_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policy_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let inherited_noop = call(
        &registry,
        &db,
        owner_caller.clone(),
        json!({
            "action":"grant","record_id":target,"subject":{"kind":"members"},
            "capability":"view","reason":"Confirm the inherited members grant is already satisfied."
        }),
    )
    .await
    .unwrap();
    assert_eq!(inherited_noop["changed"], false);
    assert!(inherited_noop.get("boundary_created").is_none());
    let event_count_after_inherited_noop: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM policy_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(event_count_after_inherited_noop, event_count_before);
    let inherited_boundary: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM record_policies WHERE record_id=?")
            .bind(&target)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(inherited_boundary, 0);
    let inherited_anchor: String =
        sqlx::query_scalar("SELECT policy_anchor_id FROM records WHERE id=?")
            .bind(&target)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(inherited_anchor, native_ce::schema::ROOT_RECORD_ID);

    let granted = call(
        &registry,
        &db,
        owner_caller.clone(),
        json!({
            "action":"grant",
            "record_id":target,
            "subject":{"kind":"person","person_record_id":bob},
            "capability":"view",
            "reason":"Bob needs to review this record while keeping unrelated grants intact"
        }),
    )
    .await
    .unwrap();
    assert_eq!(granted["changed"], true);
    assert_eq!(granted["boundary_created"], true);
    assert_eq!(granted["before"]["mode"], "inherit");
    assert_eq!(granted["after"]["mode"], "explicit");
    let persisted_reason: String =
        sqlx::query_scalar("SELECT reason FROM policy_events ORDER BY seq DESC LIMIT 1")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(
        persisted_reason,
        "Bob needs to review this record while keeping unrelated grants intact"
    );

    let noop = call(
        &registry,
        &db,
        owner_caller.clone(),
        json!({
            "action":"grant",
            "record_id":target,
            "subject":{"kind":"account","account_id":"acct:bob"},
            "capability":"view",
            "reason":"Retry the already-satisfied Bob grant"
        }),
    )
    .await
    .unwrap();
    assert_eq!(noop["changed"], false);
    let event_count_after_noop: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policy_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(event_count_after_noop, event_count_before + 1);

    let (carol, dana) = tokio::join!(
        call(
            &registry,
            &db,
            owner_caller.clone(),
            json!({
                "action":"grant","record_id":target,
                "subject":{"kind":"account","account_id":"acct:carol"},
                "capability":"edit","reason":"Carol needs to edit the working record"
            }),
        ),
        call(
            &registry,
            &db,
            owner_caller.clone(),
            json!({
                "action":"grant","record_id":target,
                "subject":{"kind":"account","account_id":"acct:dana"},
                "capability":"view","reason":"Dana needs read-only review access"
            }),
        )
    );
    assert_eq!(carol.unwrap()["changed"], true);
    assert_eq!(dana.unwrap()["changed"], true);
    let listed = call(
        &registry,
        &db,
        owner_caller.clone(),
        json!({"action":"list","record_id":target}),
    )
    .await
    .unwrap();
    let encoded = listed["entries"].to_string();
    for account in ["acct:bob", "acct:carol", "acct:dana"] {
        assert!(encoded.contains(account), "missing {account}: {encoded}");
    }
    assert!(encoded.contains(BOB_PERSON));

    let conflict = call(
        &registry,
        &db,
        owner_caller.clone(),
        json!({
            "action":"replace","record_id":target,"entries":[],
            "if_policy_revision":stale_revision,
            "reason":"Replace the complete policy after explicit inspection"
        }),
    )
    .await
    .unwrap_err();
    assert!(conflict.to_string().contains("policy revision conflict"));

    let baseline = call(
        &registry,
        &db,
        owner_caller.clone(),
        json!({
            "action":"set_members_baseline","record_id":target,"capability":"view",
            "reason":"Narrow the non-root members baseline through the real boundary."
        }),
    )
    .await
    .unwrap();
    assert_eq!(baseline["changed"], true);
    assert_eq!(baseline["boundary_created"], false);
    assert!(baseline["event"]["seq"].is_i64());

    let revoked = call(
        &registry,
        &db,
        owner_caller.clone(),
        json!({
            "action":"revoke","record_id":target,
            "subject":{"kind":"account","account_id":"acct:dana"},
            "reason":"Remove the temporary reviewer through the real boundary."
        }),
    )
    .await
    .unwrap();
    assert_eq!(revoked["changed"], true);
    assert_eq!(revoked["boundary_created"], false);
    assert!(revoked["event"]["id"].is_string());

    let before_replace = call(
        &registry,
        &db,
        owner_caller.clone(),
        json!({"action":"list","record_id":target}),
    )
    .await
    .unwrap();
    let replaced = call(
        &registry,
        &db,
        owner_caller.clone(),
        json!({
            "action":"replace","record_id":target,
            "entries":[
                {"subject":{"kind":"account","account_id":"acct:editor"},"capability":"edit"},
                {"subject":{"kind":"members"},"capability":"view"}
            ],
            "if_policy_revision":before_replace["policy_revision"],
            "reason":"Replace the complete policy through the real boundary."
        }),
    )
    .await
    .unwrap();
    assert_eq!(replaced["changed"], true);
    assert_eq!(replaced["after"]["mode"], "explicit");
    let replaced_subjects: Vec<String> = sqlx::query_scalar(
        "SELECT subject_id FROM policy_entries WHERE policy_anchor_id=? ORDER BY subject_id",
    )
    .bind(&target)
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(
        replaced_subjects,
        vec!["acct:editor", native_ce::authorization::MEMBERS_SUBJECT_ID]
    );

    let reasons: Vec<String> = sqlx::query_scalar(
        "SELECT reason FROM policy_events WHERE record_id=? ORDER BY seq DESC LIMIT 3",
    )
    .bind(&target)
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(
        reasons,
        vec![
            "Replace the complete policy through the real boundary.",
            "Remove the temporary reviewer through the real boundary.",
            "Narrow the non-root members baseline through the real boundary.",
        ]
    );

    let restored = call(
        &registry,
        &db,
        owner_caller,
        json!({
            "action":"restore_inheritance","record_id":target,
            "if_policy_revision":replaced["policy_revision"],
            "reason":"Return to the parent policy after the review window closed"
        }),
    )
    .await
    .unwrap();
    assert_eq!(restored["after"]["mode"], "inherit");

    rebuild_and_diff_policy(&db).await.unwrap();
}

#[tokio::test]
async fn policy_tool_rejects_invalid_subjects_members_manage_root_restore_and_tombstones() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    let caller = Caller::local();
    let target = create_record(
        &db,
        json!({"id":POLICY_ERRORS,"type":"Document","kind":"note","name":"Errors"}),
    )
    .await
    .unwrap();
    let count_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policy_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let members_manage = call(
        &registry,
        &db,
        caller.clone(),
        json!({
            "action":"set_members_baseline","record_id":target,"capability":"manage",
            "reason":"Attempt an invalid broad manage grant"
        }),
    )
    .await
    .unwrap_err();
    assert!(members_manage.to_string().contains("cannot grant manage"));
    let bad_person = call(
        &registry,
        &db,
        caller.clone(),
        json!({
            "action":"grant","record_id":target,
            "subject":{"kind":"person","person_record_id":target},"capability":"view",
            "reason":"Attempt to resolve a non-person subject"
        }),
    )
    .await
    .unwrap_err();
    assert!(bad_person.to_string().contains("not an Entity:person"));
    let count_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policy_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(count_after, count_before);

    sqlx::query("UPDATE records SET deleted_at='2026-08-04T00:00:00Z' WHERE id=?")
        .bind(&target)
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    let tombstone = call(
        &registry,
        &db,
        caller,
        json!({"action":"inspect","record_id":target}),
    )
    .await
    .unwrap_err();
    assert!(tombstone.to_string().contains("does not exist"));
}

#[tokio::test]
async fn derived_artifact_inspection_matches_enforcement_and_every_mutation_requires_the_bearer() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let registry = registry();
    let owner = create_record(
        &db,
        json!({"id":BEARER_OWNER,"type":"Entity","kind":"person","name":"Bearer owner"}),
    )
    .await
    .unwrap();
    bind_account(&db, &owner, "acct:bearer-owner").await;
    let bearer = create_record(
        &db,
        json!({"id":POLICY_BEARER,"type":"Document","kind":"note","name":"Bearer","owner_id":owner}),
    )
    .await
    .unwrap();
    for (id, record_type, kind) in [
        ("derived-annotation", "Annotation", "suggestion"),
        ("derived-attachment", "Document", "attachment"),
    ] {
        sqlx::query(
            "INSERT INTO records (id,type,kind,name,home_id,policy_anchor_id)
             VALUES (?,?,?,?, 'native:unfiled','native:root')",
        )
        .bind(id)
        .bind(record_type)
        .bind(kind)
        .bind(id)
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO links (id,source_id,target_id,relationship)
             VALUES (?,?,?,'part_of')",
        )
        .bind(format!("part-of-{id}"))
        .bind(id)
        .bind(&bearer)
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    }

    let caller = Caller::authenticated("acct:bearer-owner")
        .with_hosting_context("catalog-user", "catalog-db")
        .with_hosting_owner(false);
    let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policy_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    for artifact in ["derived-annotation", "derived-attachment"] {
        let enforced =
            effective_capability(&db, Principal::bound("acct:bearer-owner", true), artifact)
                .await
                .unwrap();
        assert_eq!(enforced, Capability::Manage);
        let inspected = call(
            &registry,
            &db,
            caller.clone(),
            json!({"action":"inspect","record_id":artifact}),
        )
        .await
        .unwrap();
        assert_eq!(inspected["authorization_target_id"], bearer);
        assert_eq!(inspected["caller_capability"], "manage");
        assert_eq!(inspected["policy_administration_authorized"], true);
        assert_eq!(inspected["anchor_id"], native_ce::schema::ROOT_RECORD_ID);
        let listed = call(
            &registry,
            &db,
            caller.clone(),
            json!({"action":"list","record_id":artifact}),
        )
        .await
        .unwrap();
        assert_eq!(listed["authorization_target_id"], bearer);
        let revision = listed["policy_revision"].as_str().unwrap();
        let mut mutations = vec![
            json!({
                "action":"grant","record_id":artifact,
                "subject":{"kind":"account","account_id":"acct:reader"},
                "capability":"view","reason":"This must target the bearer explicitly."
            }),
            json!({
                "action":"set_many",
                "items":[{
                    "record_id":artifact,
                    "subject":{"kind":"account","account_id":"acct:reader"},
                    "capability":"view"
                }],
                "reason":"This batch must target the bearer explicitly."
            }),
        ];
        if artifact == "derived-annotation" {
            mutations.extend([
                json!({
                "action":"revoke","record_id":artifact,
                "subject":{"kind":"account","account_id":"acct:reader"},
                "reason":"This must target the bearer explicitly."
                }),
                json!({
                "action":"set_members_baseline","record_id":artifact,"capability":"view",
                "reason":"This must target the bearer explicitly."
                }),
                json!({
                "action":"replace","record_id":artifact,"entries":[],
                "if_policy_revision":revision,
                "reason":"This must target the bearer explicitly."
                }),
                json!({
                "action":"restore_inheritance","record_id":artifact,
                "if_policy_revision":revision,
                "reason":"This must target the bearer explicitly."
                }),
            ]);
        }
        for mutation in mutations {
            let is_set_many = mutation["action"] == "set_many";
            let error = call(&registry, &db, caller.clone(), mutation)
                .await
                .unwrap_err()
                .to_string();
            let expected = if is_set_many {
                "manage_record_policy: set_many item 0: manage_record_policy: derived records cannot be policy mutation targets; target the authorization bearer explicitly"
            } else {
                "manage_record_policy: derived records cannot be policy mutation targets; target the authorization bearer explicitly"
            };
            assert_eq!(error, expected);
        }
    }
    let events_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policy_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(events_after, events_before);
    let accidental_boundaries: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM record_policies
          WHERE record_id IN ('derived-annotation','derived-attachment')",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(accidental_boundaries, 0);
}

#[tokio::test]
async fn canonical_root_uses_real_standalone_and_host_owner_administration_only() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let registry = registry();
    let root = native_ce::schema::ROOT_RECORD_ID;
    let standalone = Caller::authenticated("acct:stdio-operator");
    let standalone_list = call(
        &registry,
        &db,
        standalone.clone(),
        json!({"action":"list","record_id":root}),
    )
    .await
    .unwrap();
    assert_eq!(standalone_list["caller_capability"], "edit");
    assert_eq!(standalone_list["policy_administration_authorized"], true);
    let restore_error = call(
        &registry,
        &db,
        standalone,
        json!({
            "action":"restore_inheritance","record_id":root,
            "if_policy_revision":standalone_list["policy_revision"],
            "reason":"The root refusal must remain stable for an authorized operator."
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(restore_error.contains("canonical root policy cannot inherit"));

    let hosted_owner = Caller::authenticated("acct:host-owner")
        .with_hosting_context("catalog-owner", "catalog-db")
        .with_hosting_owner(true);
    let hosted_owner_list = call(
        &registry,
        &db,
        hosted_owner,
        json!({"action":"list","record_id":root}),
    )
    .await
    .unwrap();
    assert_eq!(hosted_owner_list["caller_capability"], "edit");
    assert_eq!(hosted_owner_list["policy_administration_authorized"], true);

    let hosted_member = Caller::authenticated("acct:host-member")
        .with_hosting_context("catalog-member", "catalog-db")
        .with_hosting_owner(false);
    let inspected = call(
        &registry,
        &db,
        hosted_member.clone(),
        json!({"action":"inspect","record_id":root}),
    )
    .await
    .unwrap();
    assert_eq!(inspected["caller_capability"], "edit");
    assert_eq!(inspected["policy_administration_authorized"], false);
    let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policy_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    for arguments in [
        json!({"action":"list","record_id":root}),
        json!({
            "action":"grant","record_id":root,
            "subject":{"kind":"account","account_id":"acct:reader"},
            "capability":"view","reason":"A hosted member must not administer root."
        }),
    ] {
        let error = call(&registry, &db, hosted_member.clone(), arguments)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("record native:root does not exist"),
            "{error}"
        );
    }
    let events_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policy_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(events_after, events_before);
}

#[tokio::test]
async fn canonical_root_operator_repairs_an_empty_policy_before_the_view_gate() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let registry = registry();
    let root = native_ce::schema::ROOT_RECORD_ID;
    replace_explicit_policy(&db, "test:empty-imported-root", root, vec![])
        .await
        .unwrap();

    let hosted_owner = Caller::authenticated("acct:host-owner")
        .with_hosting_context("catalog-owner", "catalog-db")
        .with_hosting_owner(true);
    let owner_inspect = call(
        &registry,
        &db,
        hosted_owner.clone(),
        json!({"action":"inspect","record_id":root}),
    )
    .await
    .unwrap();
    assert_eq!(owner_inspect["caller_capability"], "none");
    assert_eq!(owner_inspect["policy_administration_authorized"], true);
    let owner_list = call(
        &registry,
        &db,
        hosted_owner.clone(),
        json!({"action":"list","record_id":root}),
    )
    .await
    .unwrap();
    assert_eq!(owner_list["entries"], json!([]));
    assert_eq!(owner_list["caller_capability"], "none");
    let restore_error = call(
        &registry,
        &db,
        hosted_owner.clone(),
        json!({
            "action":"restore_inheritance","record_id":root,
            "if_policy_revision":owner_list["policy_revision"],
            "reason":"The root refusal remains reachable during repair."
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(restore_error.contains("canonical root policy cannot inherit"));
    let owner_repair = call(
        &registry,
        &db,
        hosted_owner,
        json!({
            "action":"grant","record_id":root,"subject":{"kind":"members"},
            "capability":"edit","reason":"Repair the imported root member baseline."
        }),
    )
    .await
    .unwrap();
    assert_eq!(owner_repair["changed"], true);

    replace_explicit_policy(&db, "test:empty-root-again", root, vec![])
        .await
        .unwrap();
    let standalone = Caller::authenticated("acct:stdio-operator");
    let standalone_list = call(
        &registry,
        &db,
        standalone.clone(),
        json!({"action":"list","record_id":root}),
    )
    .await
    .unwrap();
    assert_eq!(standalone_list["caller_capability"], "none");
    assert_eq!(standalone_list["policy_administration_authorized"], true);
    let standalone_repair = call(
        &registry,
        &db,
        standalone,
        json!({
            "action":"set_members_baseline","record_id":root,"capability":"edit",
            "if_policy_revision":standalone_list["policy_revision"],
            "reason":"Repair the ejected file root member baseline."
        }),
    )
    .await
    .unwrap();
    assert_eq!(standalone_repair["changed"], true);

    replace_explicit_policy(&db, "test:empty-root-member-denial", root, vec![])
        .await
        .unwrap();
    let hosted_member = Caller::authenticated("acct:host-member")
        .with_hosting_context("catalog-member", "catalog-db")
        .with_hosting_owner(false);
    let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policy_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    for arguments in [
        json!({"action":"inspect","record_id":root}),
        json!({"action":"list","record_id":root}),
        json!({
            "action":"grant","record_id":root,"subject":{"kind":"members"},
            "capability":"edit","reason":"A hosted member cannot repair root."
        }),
    ] {
        let error = call(&registry, &db, hosted_member.clone(), arguments)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("record native:root does not exist"),
            "{error}"
        );
    }
    let events_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policy_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(events_after, events_before);
}

#[tokio::test]
async fn refresh_failure_rolls_back_policy_event_projection_and_anchor_changes() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let registry = registry();
    let target = create_record(
        &db,
        json!({"id":ROLLBACK_POLICY_TARGET,"type":"Document","kind":"note","name":"Rollback target"}),
    )
    .await
    .unwrap();
    let event_count_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policy_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let anchor_before: String =
        sqlx::query_scalar("SELECT policy_anchor_id FROM records WHERE id=?")
            .bind(&target)
            .fetch_one(db.pool())
            .await
            .unwrap();
    sqlx::query(&format!(
        "CREATE TRIGGER inject_policy_anchor_refresh_failure
         BEFORE UPDATE OF policy_anchor_id ON records
         WHEN NEW.id='{ROLLBACK_POLICY_TARGET}'
         BEGIN SELECT RAISE(ABORT,'injected policy anchor refresh failure'); END"
    ))
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();

    let error = call(
        &registry,
        &db,
        Caller::local(),
        json!({
            "action":"grant","record_id":target,
            "subject":{"kind":"account","account_id":"acct:reader"},
            "capability":"view","reason":"Exercise rollback after event projection."
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("injected policy anchor refresh failure"),
        "{error}"
    );

    let event_count_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policy_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(event_count_after, event_count_before);
    let projected_policies: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM record_policies WHERE record_id=?")
            .bind(&target)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(projected_policies, 0);
    let projected_entries: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM policy_entries WHERE policy_anchor_id=?")
            .bind(&target)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(projected_entries, 0);
    let anchor_after: String =
        sqlx::query_scalar("SELECT policy_anchor_id FROM records WHERE id=?")
            .bind(&target)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(anchor_after, anchor_before);
}
