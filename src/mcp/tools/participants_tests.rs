use super::*;
use crate::mcp::{register_builtin_tools, register_surface_tools};
use crate::query::principal::QueryPrincipal;
use crate::query::sql::query_sql;

pub(crate) const ALICE: &str = "a11ce000-0000-4000-8000-000000000001";
pub(crate) const BOB: &str = "b0b00000-0000-4000-8000-000000000002";

pub(crate) fn registry() -> ToolRegistry {
    let mut r = ToolRegistry::new();
    register_builtin_tools(&mut r).unwrap();
    register_surface_tools(&mut r).unwrap();
    r
}

pub(crate) async fn fixture(db: &Db) -> (String, String) {
    crate::authorization::replace_explicit_policy(
        db,
        "local",
        crate::schema::ROOT_RECORD_ID,
        vec![
            AllowEntry::account("alice", Capability::Manage),
            AllowEntry::account("bob", Capability::Edit),
        ],
    )
    .await
    .unwrap();
    for (id, account, principal) in [(ALICE, "alice", "native/alice"), (BOB, "bob", "native/bob")] {
        crate::store::create_record(db,json!({"id":id,"type":"Entity","kind":"person","name":account,"home_id":crate::schema::ROOT_RECORD_ID})).await.unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act = crate::act::ActAllocation::new();
        for (system, ident) in [("account", account), ("native-principal", principal)] {
            crate::identity::add_binding_internal_in(
                &mut tx,
                "local",
                "install fixture identity",
                id,
                system,
                ident,
                true,
                &mut act,
            )
            .await
            .unwrap();
        }
        db.commit_authorization(tx).await.unwrap();
    }
    let r = registry();
    let shared=r.call(db.clone(),Caller::authenticated("alice"),"create_record",json!({"type":"Collection","kind":"folder","name":"Shared thread","home_id":crate::schema::ROOT_RECORD_ID,"reason":"fixture"})).await.unwrap()["id"].as_str().unwrap().to_owned();
    let hidden=r.call(db.clone(),Caller::authenticated("bob"),"create_record",json!({"type":"Collection","kind":"folder","name":"Bob private","home_id":crate::schema::ROOT_RECORD_ID,"reason":"fixture"})).await.unwrap()["id"].as_str().unwrap().to_owned();
    crate::authorization::replace_explicit_policy(
        db,
        "bob",
        &hidden,
        vec![AllowEntry::account("bob", Capability::Manage)],
    )
    .await
    .unwrap();
    (shared, hidden)
}

async fn chief(db: &Db) -> String {
    registry().call(db.clone(),Caller::authenticated("alice"),"manage_participants",json!({"action":"register_persona","name":"Chief","home_id":crate::schema::ROOT_RECORD_ID,"facets":{"colour":"blue","model_route":"operator"},"reason":"fixture"})).await.unwrap()["persona_id"].as_str().unwrap().to_owned()
}

pub(crate) async fn send(
    db: &Db,
    origin: &str,
    key: &str,
    speaker: Option<Value>,
    recipients: &[&str],
    expectation: &str,
    reply_to: Option<&str>,
) -> Result<Value> {
    let mut args = json!({"action":"send","body":"Choose an option","origin":{"type":"collection","collection_id":origin},"addressed_to":recipients,"expectation":expectation,"idempotency_key":key,"reason":"fixture"});
    if let Some(speaker) = speaker {
        args["speaker"] = speaker;
    }
    if let Some(target) = reply_to {
        args["links"] = json!([{"target_id":target,"relationship":"reply_to"}]);
    }
    registry()
        .call(
            db.clone(),
            Caller::authenticated("alice"),
            "manage_messages",
            args,
        )
        .await
}

async fn sql(db: &Db, account: &str, sql: &str) -> Vec<Value> {
    query_sql(db, &QueryPrincipal::authenticated(account, true), sql)
        .await
        .unwrap()
        .rows
}

async fn expectation(db: &Db, message: &str) -> Value {
    registry()
        .call(
            db.clone(),
            Caller::authenticated("alice"),
            "get_record",
            json!({"ids":[message]}),
        )
        .await
        .unwrap()["records"][0]["message_expectation_state"]["state"]
        .clone()
}

#[tokio::test]
async fn persona_owner_lock_retirement_and_private_profile() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (shared, _) = fixture(&db).await;
    let p = chief(&db).await;
    assert_eq!(
        sql(&db, "alice", "SELECT kind,state FROM my_participants").await,
        json!([{"kind":"persona","state":"active"}])
            .as_array()
            .unwrap()
            .clone()
    );
    assert!(sql(&db, "bob", "SELECT * FROM my_participants")
        .await
        .is_empty());
    let read = registry()
        .call(
            db.clone(),
            Caller::authenticated("bob"),
            "get_record",
            json!({"ids":[p]}),
        )
        .await
        .unwrap();
    assert_ne!(read["records"][0]["status"], "found");
    assert!(crate::authorization::replace_explicit_policy(
        &db,
        "alice",
        &p,
        vec![AllowEntry::account("bob", Capability::View)]
    )
    .await
    .is_err());
    assert!(crate::authorization::restore_inheritance(&db, "alice", &p)
        .await
        .is_err());
    for patch in [
        json!({"owner_id":BOB}),
        json!({"kind":"person"}),
        json!({"home_id":shared}),
    ] {
        let mut args = patch;
        args["id"] = json!(p);
        args["reason"] = json!("try identity mutation");
        assert!(registry()
            .call(
                db.clone(),
                Caller::authenticated("alice"),
                "update_record",
                args
            )
            .await
            .is_err());
    }
    assert!(registry()
        .call(
            db.clone(),
            Caller::authenticated("alice"),
            "delete_record",
            json!({"id":p,"reason":"delete persona"})
        )
        .await
        .is_err());
    registry().call(db.clone(),Caller::authenticated("alice"),"update_record",json!({"id":p,"name":"Chief renamed","facets":{"colour":"green"},"reason":"edit profile"})).await.unwrap();
    let old = send(
        &db,
        &shared,
        "old",
        Some(json!({"persona_id":p})),
        &[ALICE],
        "reply",
        None,
    )
    .await
    .unwrap();
    registry()
        .call(
            db.clone(),
            Caller::authenticated("alice"),
            "manage_participants",
            json!({"action":"retire_persona","persona_id":p,"reason":"retire"}),
        )
        .await
        .unwrap();
    let retry = send(&db, &shared, "old", None, &[ALICE], "reply", None)
        .await
        .unwrap();
    assert_eq!(retry["id"], old["id"]);
    assert_eq!(retry["speaker_claim_status"], "recorded");
    assert_eq!(retry["speaker"], old["speaker"]);
    let after = send(
        &db,
        &shared,
        "after",
        Some(json!({"persona_id":p})),
        &[ALICE],
        "none",
        None,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        after.ends_with("manage_messages.send: speaker not found"),
        "{after}"
    );
    assert_eq!(
        sql(&db, "alice", "SELECT state FROM my_participants").await[0]["state"],
        "retired"
    );
    let oldread = registry()
        .call(
            db.clone(),
            Caller::authenticated("alice"),
            "get_record",
            json!({"ids":[old["id"]]}),
        )
        .await
        .unwrap();
    assert_eq!(
        oldread["records"][0]["speaker"]["display_name"],
        "Chief renamed"
    );
    assert!(
        crate::conformance::rebuild::rebuild_and_diff(&db)
            .await
            .unwrap()
            .equal
    );
}

#[tokio::test]
async fn persona_speaker_never_changes_allow_deny_or_idempotent_intent() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (shared, hidden) = fixture(&db).await;
    let p = chief(&db).await;
    // Identical permission outcomes for no speaker and a valid speaker.
    for (i, speaker) in [None, Some(json!({"persona_id":p}))]
        .into_iter()
        .enumerate()
    {
        let allowed = send(
            &db,
            &shared,
            &format!("allow-{i}"),
            speaker.clone(),
            &[BOB],
            "reply",
            None,
        )
        .await
        .unwrap();
        assert_eq!(allowed["owner_id"], ALICE);
        let denied = send(
            &db,
            &hidden,
            &format!("deny-{i}"),
            speaker,
            &[BOB],
            "reply",
            None,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(denied.contains("does not exist"), "{denied}");
    }
    let first = send(&db, &shared, "same", None, &[BOB], "none", None)
        .await
        .unwrap();
    let replay = send(
        &db,
        &shared,
        "same",
        Some(json!({"persona_id":p})),
        &[BOB],
        "none",
        None,
    )
    .await
    .unwrap();
    assert_eq!(first["id"], replay["id"]);
    assert_eq!(replay["speaker_claim_status"], "absent");
    assert!(replay.get("speaker").is_none());
    let claim = send(
        &db,
        &shared,
        "run-claim",
        Some(json!({"persona_id":p})),
        &[BOB],
        "none",
        None,
    )
    .await
    .unwrap();
    assert_eq!(claim["speaker"]["assurance"], "client_asserted");
    let retry = send(
        &db,
        &shared,
        "run-claim",
        Some(json!({"persona_id":p})),
        &[BOB],
        "none",
        None,
    )
    .await
    .unwrap();
    assert_eq!(retry["id"], claim["id"]);
    assert_eq!(retry["speaker_claim_status"], "recorded");
    assert_eq!(retry["speaker"], claim["speaker"]);
}

#[tokio::test]
async fn persona_speaker_unread_attention_and_human_reply_evidence_in_shared_thread() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (shared, _) = fixture(&db).await;
    let p = chief(&db).await;
    let own = send(&db, &shared, "human", None, &[BOB], "none", None)
        .await
        .unwrap();
    let attention = registry()
        .call(
            db.clone(),
            Caller::authenticated("alice"),
            "manage_messages",
            json!({"action":"get_attention"}),
        )
        .await
        .unwrap();
    assert_eq!(attention["has_new_messages"], false);
    let spoken = send(
        &db,
        &shared,
        "persona",
        Some(json!({"persona_id":p})),
        &[ALICE],
        "reply",
        None,
    )
    .await
    .unwrap();
    let id = spoken["id"].as_str().unwrap();
    assert_eq!(expectation(&db, id).await, "open");
    let states = sql(
        &db,
        "alice",
        "SELECT message_id,unread,is_own FROM my_message_state ORDER BY message_id",
    )
    .await;
    assert_eq!(
        states.iter().find(|r| r["message_id"] == id).unwrap()["unread"],
        1
    );
    assert_eq!(
        states
            .iter()
            .find(|r| r["message_id"] == own["id"])
            .unwrap()["is_own"],
        1
    );
    let attention = registry()
        .call(
            db.clone(),
            Caller::authenticated("alice"),
            "manage_messages",
            json!({"action":"get_attention"}),
        )
        .await
        .unwrap();
    assert_eq!(attention["has_new_messages"], true);
    let inbox = registry()
        .call(
            db.clone(),
            Caller::authenticated("alice"),
            "manage_messages",
            json!({"action":"list_inbox","view":"needs_me"}),
        )
        .await
        .unwrap();
    assert!(
        inbox["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["message_id"] == id),
        "{inbox}"
    );
    send(
        &db,
        &shared,
        "persona-followup",
        Some(json!({"persona_id":p})),
        &[ALICE],
        "none",
        Some(id),
    )
    .await
    .unwrap();
    assert_eq!(expectation(&db, id).await, "open");
    send(&db, &shared, "human-reply", None, &[], "none", Some(id))
        .await
        .unwrap();
    assert_eq!(expectation(&db, id).await, "satisfied");
    let bob_speakers = sql(
        &db,
        "bob",
        "SELECT display_name,assurance FROM message_speakers ORDER BY message_id",
    )
    .await;
    assert!(!bob_speakers.is_empty());
    assert_eq!(bob_speakers[0]["assurance"], "client_asserted");
    let context = registry()
        .call(
            db.clone(),
            Caller::authenticated("bob"),
            "manage_messages",
            json!({"action":"list_context","origin":{"type":"collection","collection_id":shared}}),
        )
        .await
        .unwrap();
    assert!(context["messages"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| m["id"] == id && m["speaker"]["id"] == p));
    let rendered = registry()
        .call(
            db.clone(),
            Caller::authenticated("bob"),
            "render_record",
            json!({"id":id}),
        )
        .await
        .unwrap();
    assert_eq!(rendered["speaker"]["id"], p);
    assert!(crate::store::export_native_messages(&db, &[id.to_owned()])
        .await
        .unwrap_err()
        .to_string()
        .contains("participant_message_not_federatable"));
    let bob_inbox = registry()
        .call(
            db.clone(),
            Caller::authenticated("bob"),
            "manage_messages",
            json!({"action":"list_inbox","view":"needs_me"}),
        )
        .await
        .unwrap();
    assert!(!bob_inbox["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| m["message_id"] == id));
}

#[tokio::test]
async fn persona_canonical_interchange_round_trip_and_rebuild() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (shared, _) = fixture(&db).await;
    let p = chief(&db).await;
    send(
        &db,
        &shared,
        "export",
        Some(json!({"persona_id":p})),
        &[ALICE],
        "reply",
        None,
    )
    .await
    .unwrap();
    registry()
        .call(
            db.clone(),
            Caller::authenticated("alice"),
            "manage_participants",
            json!({"action":"retire_persona","persona_id":p,"reason":"retain history"}),
        )
        .await
        .unwrap();
    let bytes = crate::interchange::export_canonical_interchange(&db)
        .await
        .unwrap();
    let temp = tempfile::tempdir().unwrap();
    let imported = crate::interchange::import_canonical_interchange(
        &bytes,
        &temp.path().join("import.db"),
        crate::interchange::ImportContinuity::ForeignBoundary,
    )
    .await
    .unwrap();
    assert_eq!(
        sql(&db, "alice", "SELECT * FROM my_participants").await,
        sql(&imported, "alice", "SELECT * FROM my_participants").await
    );
    assert_eq!(
        sql(&db, "alice", "SELECT * FROM message_speakers").await,
        sql(&imported, "alice", "SELECT * FROM message_speakers").await
    );
    assert!(
        crate::conformance::rebuild::rebuild_and_diff(&imported)
            .await
            .unwrap()
            .equal
    );
}

#[tokio::test]
async fn persona_invalid_claims_are_uniform_atomic_and_refused_on_retries() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (shared, hidden) = fixture(&db).await;
    let retired = chief(&db).await;
    registry()
        .call(
            db.clone(),
            Caller::authenticated("alice"),
            "manage_participants",
            json!({"action":"retire_persona","persona_id":retired,"reason":"retire"}),
        )
        .await
        .unwrap();
    let foreign = registry()
        .call(
            db.clone(),
            Caller::authenticated("bob"),
            "manage_participants",
            json!({"action":"register_persona","name":"Foreign Chief","reason":"fixture"}),
        )
        .await
        .unwrap();
    send(&db, &shared, "existing", None, &[BOB], "none", None)
        .await
        .unwrap();
    let before: (i64, i64, i64) = sqlx::query_as("SELECT (SELECT COUNT(*) FROM content_events),(SELECT COUNT(*) FROM records),(SELECT COUNT(*) FROM message_speakers)").fetch_one(db.pool()).await.unwrap();
    let denied_without = send(&db, &hidden, "denied", None, &[BOB], "none", None)
        .await
        .unwrap_err()
        .to_string();
    let mut common = None;
    for claim in [
        json!({"persona_id":"missing"}),
        json!({"persona_id":foreign["persona_id"]}),
        json!({"persona_id":retired}),
        json!({"persona_id":ALICE}),
        json!({"persona_id":" "}),
        json!({"persona_id":retired,"assurance":"host_asserted"}),
        json!("malformed"),
        Value::Null,
        json!({}),
    ] {
        // Both fresh sends and keyed retries refuse the supplied claim.
        for key in ["fresh", "existing"] {
            let error = send(&db, &shared, key, Some(claim.clone()), &[BOB], "none", None)
                .await
                .unwrap_err()
                .to_string();
            assert!(
                error.ends_with("manage_messages.send: speaker not found"),
                "{error}"
            );
            if let Some(expected) = &common {
                assert_eq!(&error, expected);
            } else {
                common = Some(error);
            }
        }
        // Claims don't influence an ordinary permission refusal.
        let denied = send(&db, &hidden, "denied", Some(claim), &[BOB], "none", None)
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(denied, denied_without);
    }
    let after: (i64, i64, i64) = sqlx::query_as("SELECT (SELECT COUNT(*) FROM content_events),(SELECT COUNT(*) FROM records),(SELECT COUNT(*) FROM message_speakers)").fetch_one(db.pool()).await.unwrap();
    assert_eq!(before, after, "invalid claims, including the foreign claim, write neither a speaker nor a Message nor an event");
}

#[tokio::test]
async fn persona_second_viewer_visibility_and_human_only_obligations_are_unchanged() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (shared, hidden) = fixture(&db).await;
    let p = chief(&db).await;
    let human = send(
        &db,
        &shared,
        "ordinary-open-ask",
        None,
        &[BOB],
        "reply",
        None,
    )
    .await
    .unwrap();
    let spoken = send(
        &db,
        &shared,
        "spoken-open-ask",
        Some(json!({"persona_id":p})),
        &[BOB],
        "reply",
        None,
    )
    .await
    .unwrap();
    for message in [&human, &spoken] {
        let id = message["id"].as_str().unwrap();
        let read = registry()
            .call(
                db.clone(),
                Caller::authenticated("bob"),
                "get_record",
                json!({"ids":[id]}),
            )
            .await
            .unwrap();
        assert_eq!(read["records"][0]["status"], "found", "{read}");
        assert_eq!(read["records"][0]["owner_id"], ALICE);
        let state = sql(
            &db,
            "bob",
            &format!("SELECT unread,is_own FROM my_message_state WHERE message_id='{id}'"),
        )
        .await;
        assert_eq!(state, vec![json!({"unread":1,"is_own":0})]);
        let context = registry().call(db.clone(),Caller::authenticated("bob"),"manage_messages",json!({"action":"list_context","origin":{"type":"collection","collection_id":shared}})).await.unwrap();
        assert!(context["messages"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["id"] == id));
        let search = registry()
            .call(
                db.clone(),
                Caller::authenticated("bob"),
                "search",
                json!({"query":"Choose an option"}),
            )
            .await
            .unwrap();
        assert!(search.to_string().contains(id), "{search}");
    }
    let inbox = registry()
        .call(
            db.clone(),
            Caller::authenticated("alice"),
            "manage_messages",
            json!({"action":"list_inbox","view":"needs_me"}),
        )
        .await
        .unwrap();
    let items = inbox["items"].as_array().unwrap();
    assert!(
        items.iter().any(|m| m["message_id"] == human["id"]),
        "ordinary open asks remain obligations for visible non-addressees: {inbox}"
    );
    assert!(
        !items.iter().any(|m| m["message_id"] == spoken["id"]),
        "speaker obligations require an addressed viewer: {inbox}"
    );
    assert!(sql(
        &db,
        "bob",
        &format!("SELECT id FROM records WHERE id='{p}'")
    )
    .await
    .is_empty());
    let hidden_search = registry()
        .call(
            db.clone(),
            Caller::authenticated("bob"),
            "search",
            json!({"query":"Chief"}),
        )
        .await
        .unwrap();
    assert!(!hidden_search.to_string().contains(&p), "{hidden_search}");
    // Also verify the second viewer is refused a thread without View in both cases.
    crate::authorization::replace_explicit_policy(
        &db,
        "bob",
        &hidden,
        vec![AllowEntry::account("alice", Capability::Manage)],
    )
    .await
    .unwrap();
    for speaker in [None, Some(json!({"persona_id":p}))] {
        let message = send(
            &db,
            &hidden,
            if speaker.is_some() {
                "hidden-spoken"
            } else {
                "hidden-human"
            },
            speaker,
            &[],
            "none",
            None,
        )
        .await
        .unwrap();
        let read = registry()
            .call(
                db.clone(),
                Caller::authenticated("bob"),
                "get_record",
                json!({"ids":[message["id"]]}),
            )
            .await
            .unwrap();
        assert_ne!(read["records"][0]["status"], "found");
    }
}

#[tokio::test]
async fn persona_register_existing_requires_owner_only_and_input_schema_matches_handler() {
    let db = crate::create_database(":memory:").await.unwrap();
    fixture(&db).await;
    let r = registry();
    let profile = r.call(db.clone(),Caller::authenticated("alice"),"create_record",json!({"type":"Entity","kind":"persona","name":"Existing Chief","home_id":crate::schema::ROOT_RECORD_ID,"reason":"fixture"})).await.unwrap();
    let id = profile["id"].as_str().unwrap();
    let args = json!({"action":"register_persona","record_id":id,"reason":"register"});
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policy_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let refused = r
        .call(
            db.clone(),
            Caller::authenticated("alice"),
            "manage_participants",
            args.clone(),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(refused.contains("must already be owner-only"), "{refused}");
    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policy_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(before, after);
    assert!(
        !crate::persona::registered(&mut db.pool().acquire().await.unwrap(), id)
            .await
            .unwrap()
    );
    crate::authorization::replace_explicit_policy(
        &db,
        "alice",
        id,
        vec![AllowEntry::account("alice", Capability::Manage)],
    )
    .await
    .unwrap();
    let registered = r
        .call(
            db.clone(),
            Caller::authenticated("alice"),
            "manage_participants",
            args.clone(),
        )
        .await
        .unwrap();
    assert_eq!(registered["persona_id"], id);
    assert!(r
        .call(
            db.clone(),
            Caller::authenticated("alice"),
            "manage_participants",
            args.clone()
        )
        .await
        .is_err());
    // A foreign/non-persona record cannot be registered, even with inherited Manage.
    let foreign = r.call(db.clone(),Caller::authenticated("bob"),"create_record",json!({"type":"Entity","kind":"persona","name":"Bob profile","home_id":crate::schema::ROOT_RECORD_ID,"reason":"fixture"})).await.unwrap();
    for target in [BOB, ALICE, foreign["id"].as_str().unwrap()] {
        assert!(r
            .call(
                db.clone(),
                Caller::authenticated("alice"),
                "manage_participants",
                json!({"action":"register_persona","record_id":target,"reason":"refuse"})
            )
            .await
            .is_err());
    }
    let spec = r.specs().find(|s| s.name == "manage_participants").unwrap();
    let validator = jsonschema::validator_for(&spec.input_schema).unwrap();
    let mut schema_args = args.clone();
    schema_args["run_key"] = json!("schema-contract");
    assert!(
        validator.is_valid(&schema_args),
        "{:?}",
        validator
            .iter_errors(&schema_args)
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
    );
    assert!(validator.is_valid(&json!({"action":"register_persona","name":"Chief","body":"Profile","home_id":"native:root","reason":"create","run_key":"schema-contract"})));
    for invalid in [
        json!({"record_id":id,"body":"edited"}),
        json!({"record_id":id,"home_id":"native:root"}),
        json!({"record_id":id,"name":"edit"}),
        json!({"name":" "}),
        json!({"name":"Chief","body":" "}),
        json!({"name":"Chief","home_id":" "}),
        json!({"record_id":" "}),
        json!({"name":"Chief","reason":" "}),
    ] {
        let mut input = invalid;
        input["action"] = json!("register_persona");
        if input.get("reason").is_none() {
            input["reason"] = json!("test");
        }
        let mut schema_input = input.clone();
        schema_input["run_key"] = json!("schema-contract");
        assert!(
            !validator.is_valid(&schema_input),
            "schema accepted {schema_input}"
        );
        assert!(r
            .call(
                db.clone(),
                Caller::authenticated("alice"),
                "manage_participants",
                input
            )
            .await
            .is_err());
    }
}

#[tokio::test]
async fn persona_policy_tool_correction_and_owner_facet_are_refused() {
    let db = crate::create_database(":memory:").await.unwrap();
    fixture(&db).await;
    let p = chief(&db).await;
    let r = registry();
    let error = r.call(db.clone(),Caller::authenticated("alice"),"manage_record_policy",json!({"action":"grant","record_id":p,"subject":{"kind":"person","person_record_id":BOB},"capability":"view","reason":"sharing forbidden"})).await.unwrap_err().to_string();
    assert!(error.contains("owner-locked"), "{error}");
    let error = super::super::lifecycle::prepare_correct_record_type(&db,&Caller::authenticated("alice"),json!({"record_id":p,"target_type":"Document","target_kind":"note","reason":"correction forbidden"})).await.unwrap_err().to_string();
    assert!(error.contains("owner-locked"), "{error}");
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let error = crate::store::append(
        &db,
        AppendSpec {
            record_id: p.clone(),
            event_type: "facet.set".into(),
            payload: json!({"key":"owner","value":BOB}),
            actor: Some("alice".into()),
        },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("owner-locked"), "{error}");
    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(before, after);
    assert!(
        crate::conformance::rebuild::rebuild_and_diff(&db)
            .await
            .unwrap()
            .equal
    );
}

#[tokio::test]
async fn persona_my_mentions_distinguishes_human_speech_for_both_routes() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (shared, _) = fixture(&db).await;
    let p = chief(&db).await;
    let r = registry();
    for (n, speaker) in [None, Some(json!({"persona_id":p}))]
        .into_iter()
        .enumerate()
    {
        let mut args = json!({"action":"send","body":format!("Reference [{}](https://n8v.to/{ALICE})" ,"Alice"),"origin":{"type":"collection","collection_id":shared},"addressed_to":[BOB],"expectation":"none","idempotency_key":format!("mention-{n}"),"reason":"fixture"});
        if let Some(speaker) = speaker {
            args["speaker"] = speaker;
            args["addressed_to"] = json!([ALICE]);
            args["mentions"] = json!([{"mention_id":format!("mention-{n}"),"target_kind":"principal","target_id":ALICE,"span_start":11,"span_end":16,"authored_label":"Alice"}]);
        }
        let message = r
            .call(
                db.clone(),
                Caller::authenticated("alice"),
                "manage_messages",
                args,
            )
            .await
            .unwrap();
        let id = message["id"].as_str().unwrap();
        let rows = sql(
            &db,
            "alice",
            &format!("SELECT via,own_source FROM my_mentions WHERE source_id='{id}' ORDER BY via"),
        )
        .await;
        assert_eq!(
            rows,
            if n == 0 {
                vec![json!({"via":"reference","own_source":1})]
            } else {
                vec![
                    json!({"via":"principal","own_source":0}),
                    json!({"via":"reference","own_source":0}),
                ]
            }
        );
    }
}

/// Row counts of every table a persona write can touch, to prove a refusal wrote nothing.
async fn persona_write_surface(db: &Db) -> (i64, i64, i64) {
    let count = |table: &'static str| async move {
        sqlx::query_scalar::<_, i64>(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(db.pool())
            .await
            .unwrap()
    };
    (
        count("content_events").await,
        count("policy_events").await,
        count("personas").await,
    )
}

async fn participants_call(db: &Db, account: &str, args: Value) -> Result<Value> {
    registry()
        .call(
            db.clone(),
            Caller::authenticated(account),
            "manage_participants",
            args,
        )
        .await
}

#[tokio::test]
async fn manage_participants_list_is_owner_scoped_and_discloses_no_foreign_persona() {
    let db = crate::create_database(":memory:").await.unwrap();
    fixture(&db).await;
    let p = chief(&db).await;
    let before = persona_write_surface(&db).await;
    let listed = participants_call(&db, "alice", json!({"action":"list"}))
        .await
        .unwrap();
    assert_eq!(
        listed["participants"],
        json!([{"kind":"persona","persona_id":p,"participant_address":format!("persona:{p}"),
                "display_name":"Chief","state":"active"}])
    );
    // Another person sees none of the owner's personas, not even their existence.
    let foreign = participants_call(&db, "bob", json!({"action":"list"}))
        .await
        .unwrap();
    assert_eq!(foreign["participants"], json!([]));
    // A caller with no canonical owner Person is refused before any row is read.
    let unbound = participants_call(&db, "carol", json!({"action":"list"}))
        .await
        .unwrap_err()
        .to_string();
    assert!(
        unbound.contains("requires one canonical owner Person"),
        "{unbound}"
    );
    assert!(!unbound.contains(&p), "{unbound}");
    // A retired persona stays listed for its owner, still hidden from others.
    participants_call(
        &db,
        "alice",
        json!({"action":"retire_persona","persona_id":p,"reason":"retire"}),
    )
    .await
    .unwrap();
    let after_retire = persona_write_surface(&db).await;
    let owner = participants_call(&db, "alice", json!({"action":"list"}))
        .await
        .unwrap();
    assert_eq!(owner["participants"][0]["state"], "retired");
    let foreign = participants_call(&db, "bob", json!({"action":"list"}))
        .await
        .unwrap();
    assert_eq!(foreign["participants"], json!([]));
    assert_ne!(before, after_retire);
    assert_eq!(after_retire, persona_write_surface(&db).await, "list wrote");
}

#[tokio::test]
async fn register_persona_requires_an_owner_person_and_home_edit_and_a_refusal_writes_nothing() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (shared, hidden) = fixture(&db).await;
    let baseline = persona_write_surface(&db).await;
    // A home the owner cannot see is refused as not found, with nothing written.
    let no_home = participants_call(
        &db,
        "alice",
        json!({"action":"register_persona","name":"Chief","home_id":hidden,"reason":"refuse"}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(no_home.contains("does not exist"), "{no_home}");
    assert_eq!(baseline, persona_write_surface(&db).await);
    // A caller with no canonical owner Person cannot register at all.
    let unbound = participants_call(
        &db,
        "carol",
        json!({"action":"register_persona","name":"Chief","home_id":shared,"reason":"refuse"}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        unbound.contains("requires one canonical owner Person"),
        "{unbound}"
    );
    assert_eq!(baseline, persona_write_surface(&db).await);
    // Another person's persona profile cannot be adopted, even where Manage is inherited.
    let foreign = registry()
        .call(
            db.clone(),
            Caller::authenticated("bob"),
            "create_record",
            json!({"type":"Entity","kind":"persona","name":"Bob profile","home_id":crate::schema::ROOT_RECORD_ID,"reason":"fixture"}),
        )
        .await
        .unwrap();
    let baseline = persona_write_surface(&db).await;
    let adopted = participants_call(
        &db,
        "alice",
        json!({"action":"register_persona","record_id":foreign["id"],"reason":"refuse"}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        adopted.contains("requires the caller's owned Entity/persona profile"),
        "{adopted}"
    );
    assert_eq!(baseline, persona_write_surface(&db).await);
    // The owner registers into a home they can Edit; the profile is theirs alone.
    let registered = participants_call(
        &db,
        "alice",
        json!({"action":"register_persona","name":"Chief","home_id":shared,"reason":"register"}),
    )
    .await
    .unwrap();
    let id = registered["persona_id"].as_str().unwrap();
    assert_eq!(registered["state"], "active");
    assert_eq!(persona_write_surface(&db).await.2, baseline.2 + 1);
    let bob_read = registry()
        .call(
            db.clone(),
            Caller::authenticated("bob"),
            "get_record",
            json!({"ids":[id]}),
        )
        .await
        .unwrap();
    assert_ne!(bob_read["records"][0]["status"], "found");
}

#[tokio::test]
async fn retire_persona_requires_owner_manage_of_an_active_persona_and_a_refusal_writes_nothing() {
    let db = crate::create_database(":memory:").await.unwrap();
    let (shared, _) = fixture(&db).await;
    let p = chief(&db).await;
    let baseline = persona_write_surface(&db).await;
    // Another person gets the same answer for a real persona as for one that never existed.
    let refused = participants_call(
        &db,
        "bob",
        json!({"action":"retire_persona","persona_id":p,"reason":"refuse"}),
    )
    .await
    .unwrap_err()
    .to_string();
    let missing = "00000000-0000-4000-8000-00000000dead";
    let absent = participants_call(
        &db,
        "bob",
        json!({"action":"retire_persona","persona_id":missing,"reason":"refuse"}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(refused.replace(&p, "ID"), absent.replace(missing, "ID"));
    assert_eq!(baseline, persona_write_surface(&db).await);
    // A caller with no canonical owner Person is refused.
    let unbound = participants_call(
        &db,
        "carol",
        json!({"action":"retire_persona","persona_id":p,"reason":"refuse"}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        unbound.contains("requires one canonical owner Person"),
        "{unbound}"
    );
    // Managing some other record is not retiring a persona.
    let not_persona = participants_call(
        &db,
        "alice",
        json!({"action":"retire_persona","persona_id":shared,"reason":"refuse"}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        not_persona.contains("persona does not exist or is not active"),
        "{not_persona}"
    );
    assert_eq!(baseline, persona_write_surface(&db).await);
    // The owner retires once; a repeat is refused and writes nothing.
    let retired = participants_call(
        &db,
        "alice",
        json!({"action":"retire_persona","persona_id":p,"reason":"retire"}),
    )
    .await
    .unwrap();
    assert_eq!(retired["state"], "retired");
    let after = persona_write_surface(&db).await;
    assert_ne!(baseline, after);
    let again = participants_call(
        &db,
        "alice",
        json!({"action":"retire_persona","persona_id":p,"reason":"again"}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        again.contains("persona does not exist or is not active"),
        "{again}"
    );
    assert_eq!(after, persona_write_surface(&db).await);
}
