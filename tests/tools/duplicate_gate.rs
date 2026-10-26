use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::meta::{
    create_vocabulary, promote_value, propose_value_with_kind_metadata_as, KindDedupMode,
    KindDedupV1, KindIdentityV1, KindMetadataV1, VocabularyValueTerminality,
    KIND_METADATA_SCHEMA_VERSION,
};
use native_ce::provenance::Channel;
use native_ce::{create_database, Db};
use serde_json::{json, Value};

async fn setup() -> (Db, ToolRegistry) {
    let db = create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    (db, registry)
}
fn note(name: &str) -> Value {
    json!({"type":"Document", "kind":"note", "name":name, "reason":"duplicate gate fixture"})
}
async fn call(
    db: &Db,
    registry: &ToolRegistry,
    caller: Caller,
    args: Value,
) -> native_ce::Result<Value> {
    registry
        .call(db.clone(), caller, "create_record", args)
        .await
}
async fn seed(db: &Db, registry: &ToolRegistry, args: Value) -> Value {
    call(db, registry, Caller::local(), args).await.unwrap()
}
fn mcp() -> Caller {
    Caller::local().with_channel(Channel::Mcp)
}
fn refusal(error: native_ce::Error) -> Value {
    let message = error.to_string();
    let json_start = message.find('{').expect(&message);
    let value: Value = serde_json::from_str(&message[json_start..]).unwrap();
    assert_eq!(value["code"], "likely_duplicate");
    assert_eq!(value["applied"], false);
    value
}
async fn counts(db: &Db) -> (i64, i64, i64) {
    (
        crate::common::count(db, "SELECT COUNT(*) AS n FROM records").await,
        crate::common::count(db, "SELECT COUNT(*) AS n FROM content_events").await,
        crate::common::count(
            db,
            "SELECT COUNT(*) AS n FROM provenance_action_attestations",
        )
        .await,
    )
}

#[tokio::test]
async fn title_refuses_without_writes_and_confirm_succeeds_with_replay() {
    let (db, registry) = setup().await;
    let old = seed(&db, &registry, note("Opening Reviews (3)")).await;
    let mut args = note("Opening reviews (4)");
    args["idempotency_key"] = json!("duplicate-gate-retry");
    args["body"] = json!("body must not be echoed ".repeat(4096));
    let before = counts(&db).await;
    let refused = refusal(call(&db, &registry, mcp(), args.clone()).await.unwrap_err());
    assert_eq!(counts(&db).await, before);
    assert_eq!(refused["candidates"][0]["id"], old["id"]);
    assert_eq!(refused["candidates"][0]["kind"], "note");
    assert!(refused["candidates"][0]["display_reference"].is_string());
    assert_eq!(refused["next_calls"].as_array().unwrap().len(), 3);
    assert!(refused.to_string().len() < 5000);
    assert!(!refused.to_string().contains("body must not be echoed"));
    let update = &refused["next_calls"][0]["arguments"];
    assert_eq!(update["record_id"], old["id"]);
    assert!(update.get("name").is_none());
    assert!(refused["next_calls"][2]["arguments_patch"]["confirm"] == true);
    args["confirm"] = json!(true);
    let created = call(&db, &registry, mcp(), args.clone()).await.unwrap();
    assert_eq!(
        created["duplicate_gate"]["confirmed_over"],
        json!([old["id"]])
    );
    let persisted: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events WHERE record_id=? AND json_type(payload,'$.duplicate_gate') IS NOT NULL")
        .bind(created["id"].as_str().unwrap()).fetch_one(db.pool()).await.unwrap();
    assert_eq!(
        persisted, 0,
        "confirmation ids must never enter content events"
    );
    let after = counts(&db).await;
    // confirm is presentation/consent, not action identity, even on replay.
    args.as_object_mut().unwrap().remove("confirm");
    let replay = call(&db, &registry, mcp(), args.clone()).await.unwrap();
    let mut expected_replay = created.clone();
    expected_replay
        .as_object_mut()
        .unwrap()
        .remove("duplicate_gate");
    assert_eq!(expected_replay, replay);
    assert_eq!(counts(&db).await, after);
    args["response_mode"] = json!("verbose");
    let verbose = call(&db, &registry, mcp(), args).await.unwrap();
    assert!(verbose.get("duplicate_gate").is_none());
    db.close().await;
}

#[tokio::test]
async fn shared_target_requires_the_existing_name_similarity_threshold() {
    let (db, registry) = setup().await;
    let target = seed(&db, &registry, note("Anchor")).await;
    let links = json!([{"relationship":"relates_to", "target_id":target["id"]}]);
    let mut old = note("Quarterly logistics manifest");
    old["links"] = links.clone();
    let old = seed(&db, &registry, old).await;
    let mut review = note("Quarterly logistics review");
    review["links"] = links.clone();
    assert!(call(&db, &registry, mcp(), review).await.is_ok());
    let mut similar = note("Quarterly logistics manifest review");
    similar["links"] = links.clone();
    let refused = refusal(call(&db, &registry, mcp(), similar).await.unwrap_err());
    // Both existing titles are contained in the longer title; candidate order
    // is not part of the contract.
    let matched = refused["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .find(|candidate| candidate["id"] == old["id"])
        .unwrap();
    assert_eq!(matched["why"], "shared_link_target_and_similar_name");
    let mut unrelated = note("Trombone lighthouse garden");
    unrelated["links"] = links;
    assert!(call(&db, &registry, mcp(), unrelated).await.is_ok());
    // Similar name alone stays advisory.
    assert!(
        call(&db, &registry, mcp(), note("Quarterly logistics summary"))
            .await
            .is_ok()
    );
    db.close().await;
}

#[tokio::test]
async fn recurring_titles_with_different_digit_tokens_pass() {
    let (db, registry) = setup().await;
    let project = seed(&db, &registry, note("Acme project")).await;
    let links = json!([{"relationship":"relates_to", "target_id":project["id"]}]);
    for (old, new) in [
        ("Acme weekly sync 2026-10-01", "Acme weekly sync 2026-10-08"),
        ("Acme Q3 report", "Acme Q4 report"),
        ("Acme review 2", "Acme review 2 phase 3"),
    ] {
        let mut args = note(old);
        args["links"] = links.clone();
        seed(&db, &registry, args).await;
        let mut args = note(new);
        args["links"] = links.clone();
        let receipt = call(&db, &registry, mcp(), args).await.unwrap();
        assert!(receipt.get("duplicate_gate").is_none());
    }
    // Terms beyond the advisory's twelve-term budget still matter.
    let mut args =
        note("alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima manifest");
    args["links"] = links.clone();
    seed(&db, &registry, args).await;
    let mut args =
        note("alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima review");
    args["links"] = links;
    assert!(call(&db, &registry, mcp(), args).await.is_ok());
    db.close().await;
}

#[tokio::test]
async fn exact_titles_survive_kind_and_body_hit_caps() {
    let (db, registry) = setup().await;
    // Both old kind rows and body-only hits used to exhaust discovery caps.
    for i in 0..110 {
        let mut args = note(&format!("Older unrelated record {i}"));
        args["body"] = json!("Opening reviews");
        let old = seed(&db, &registry, args).await;
        if i % 2 == 0 {
            registry
                .call(
                    db.clone(),
                    Caller::local(),
                    "archive_record",
                    json!({"id":old["id"], "reason":"archive old fixture"}),
                )
                .await
                .unwrap();
        }
    }
    let recent = seed(&db, &registry, note("Opening Reviews (3)")).await;
    let refused = refusal(
        call(&db, &registry, mcp(), note("Opening reviews (4)"))
            .await
            .unwrap_err(),
    );
    assert_eq!(refused["candidates"][0]["id"], recent["id"]);
    // An exact title also remains discoverable beyond the newest-kind window.
    for i in 0..110 {
        seed(&db, &registry, note(&format!("Newer unrelated record {i}"))).await;
    }
    let before = counts(&db).await;
    let refused = refusal(
        call(&db, &registry, mcp(), note("Opening reviews [2]"))
            .await
            .unwrap_err(),
    );
    assert_eq!(refused["candidates"][0]["id"], recent["id"]);
    assert_eq!(counts(&db).await, before);
    db.close().await;
}

#[tokio::test]
async fn shared_targets_filter_other_kinds_before_the_cap() {
    let (db, registry) = setup().await;
    let target = seed(&db, &registry, note("Anchor")).await;
    let links = json!([{"relationship":"relates_to", "target_id":target["id"]}]);
    let mut args = note("Quarterly logistics manifest");
    args["links"] = links.clone();
    let old = seed(&db, &registry, args).await;
    for i in 0..110 {
        let mut args = note(&format!("Other kind neighbour {i}"));
        args["kind"] = json!("research");
        args["links"] = links.clone();
        seed(&db, &registry, args).await;
        seed(&db, &registry, note(&format!("New unrelated note {i}"))).await;
    }
    let mut args = note("Quarterly logistics manifest review");
    args["links"] = links;
    let refused = refusal(call(&db, &registry, mcp(), args).await.unwrap_err());
    assert_eq!(refused["candidates"][0]["id"], old["id"]);
    db.close().await;
}

#[tokio::test]
async fn digits_kinds_linked_candidates_and_non_agent_channels_pass() {
    let (db, registry) = setup().await;
    seed(&db, &registry, note("Q3 report")).await;
    let receipt = call(&db, &registry, mcp(), note("Q4 report"))
        .await
        .unwrap();
    assert!(receipt.get("duplicate_gate").is_none());
    let mut different = note("Q3 report");
    different["kind"] = json!("research");
    assert!(call(&db, &registry, mcp(), different).await.is_ok());
    let old = seed(&db, &registry, note("Known subject")).await;
    let mut linked = note("Known subject");
    linked["links"] = json!([{"relationship":"supersedes", "target_id":old["id"]}]);
    assert!(call(&db, &registry, mcp(), linked).await.is_ok());
    for channel in [Channel::Local, Channel::Web] {
        assert!(call(
            &db,
            &registry,
            Caller::local().with_channel(channel),
            note("Q3 report")
        )
        .await
        .is_ok());
    }
    db.close().await;
}

#[tokio::test]
async fn archived_superseded_deleted_and_terminal_candidates_are_ignored() {
    let (db, registry) = setup().await;
    let archived = seed(&db, &registry, note("Archived subject")).await;
    registry
        .call(
            db.clone(),
            Caller::local(),
            "archive_record",
            json!({"id":archived["id"],"reason":"archive fixture"}),
        )
        .await
        .unwrap();
    assert!(call(&db, &registry, mcp(), note("Archived subject"))
        .await
        .is_ok());
    let old = seed(&db, &registry, note("Superseded subject")).await;
    let mut successor = note("Successor");
    successor["links"] = json!([{"relationship":"supersedes", "target_id":old["id"]}]);
    seed(&db, &registry, successor).await;
    assert!(call(&db, &registry, mcp(), note("Superseded subject"))
        .await
        .is_ok());
    let deleted = seed(&db, &registry, note("Deleted subject")).await;
    registry
        .call(
            db.clone(),
            Caller::local(),
            "delete_record",
            json!({"id":deleted["id"],"reason":"delete fixture"}),
        )
        .await
        .unwrap();
    assert!(call(&db, &registry, mcp(), note("Deleted subject"))
        .await
        .is_ok());
    for lifecycle in ["completed", "closed"] {
        let task = json!({"type":"WorkItem", "kind":"task", "name":format!("Terminal {lifecycle}"), "lifecycle":lifecycle, "reason":"fixture"});
        seed(&db, &registry, task.clone()).await;
        assert!(call(&db, &registry, mcp(), task).await.is_ok());
    }
    db.close().await;
}

#[tokio::test]
async fn invisible_candidates_never_leak_in_refusals() {
    let (db, registry) = setup().await;
    let person = seed(
        &db,
        &registry,
        json!({"type":"Entity", "kind":"person", "name":"Bea", "reason":"fixture"}),
    )
    .await;
    sqlx::query("INSERT INTO bindings (record_id, system, identifier, is_canonical) VALUES (?, 'account', 'acct:bea', 1)")
        .bind(person["id"].as_str().unwrap()).execute(&crate::common::fixture_write_pool(&db).await).await.unwrap();
    let secret = seed(&db, &registry, note("Private subject")).await;
    replace_explicit_policy(
        &db,
        "fixture:private",
        secret["id"].as_str().unwrap(),
        vec![AllowEntry::account("acct:alice", Capability::View)],
    )
    .await
    .unwrap();
    let caller = Caller::authenticated("acct:bea")
        .with_hosting_context("host:bea", "db:test")
        .with_channel(Channel::Mcp);
    let created = call(&db, &registry, caller.clone(), note("Private subject"))
        .await
        .unwrap();
    assert!(created.get("duplicate_gate").is_none());
    assert!(!created.to_string().contains(secret["id"].as_str().unwrap()));
    let refused = refusal(
        call(&db, &registry, caller, note("Private subject"))
            .await
            .unwrap_err(),
    );
    assert!(!refused.to_string().contains(secret["id"].as_str().unwrap()));
    assert_eq!(refused["candidates"][0]["id"], created["id"]);
    db.close().await;
}

#[tokio::test]
async fn no_match_omits_gate_even_when_confirm_is_true() {
    let (db, registry) = setup().await;
    let mut args = note("Unique subject");
    args["confirm"] = json!(true);
    let receipt = call(&db, &registry, mcp(), args).await.unwrap();
    assert!(receipt.get("duplicate_gate").is_none());
    db.close().await;
}

#[tokio::test]
async fn canonical_kind_aliases_match_and_the_refusal_is_capped() {
    let (db, registry) = setup().await;
    let pool = crate::common::fixture_write_pool(&db).await;
    sqlx::query("INSERT INTO vocabulary_values (id,vocabulary_id,value,status,alias_of) SELECT 'fixture:old-note', vocabulary_id, 'old_note', 'deprecated', id FROM vocabulary_values WHERE id='vv:voc:kind:Document:note'")
        .execute(&pool).await.unwrap();
    let old = seed(&db, &registry, note("Aliased subject")).await;
    // Simulate a historical projection, before writes canonicalized this alias.
    sqlx::query("UPDATE records SET kind='old_note' WHERE id=?")
        .bind(old["id"].as_str().unwrap())
        .execute(&pool)
        .await
        .unwrap();
    let refused = refusal(
        call(&db, &registry, mcp(), note("Aliased subject"))
            .await
            .unwrap_err(),
    );
    assert_eq!(refused["candidates"][0]["id"], old["id"]);
    assert_eq!(refused["candidates"][0]["kind"], "note");
    let criterion: String = sqlx::query_scalar("SELECT json_extract(metadata,'$.identity.criterion') FROM vocabulary_values WHERE id='vv:voc:kind:Document:note'")
        .fetch_one(db.pool()).await.unwrap();
    assert_eq!(refused["identity_criterion"], criterion);
    for _ in 0..4 {
        seed(&db, &registry, note("Crowded subject")).await;
    }
    let refused = refusal(
        call(&db, &registry, mcp(), note("Crowded subject"))
            .await
            .unwrap_err(),
    );
    assert_eq!(refused["candidates"].as_array().unwrap().len(), 3);
    db.close().await;
}

#[tokio::test]
async fn ordinary_comments_and_sender_only_drafts_are_ungated() {
    let (db, registry) = setup().await;
    let target = seed(&db, &registry, note("Comment bearer")).await;
    let comment = json!({"type":"Annotation", "kind":"comment", "name":"Same comment",
        "body":"An independent utterance", "reason":"fixture",
        "links":[{"relationship":"part_of", "target_id":target["id"]}]});
    for _ in 0..2 {
        let receipt = call(&db, &registry, mcp(), comment.clone()).await.unwrap();
        assert!(receipt.get("duplicate_gate").is_none());
    }
    use native_ce::identity::hosted::{
        reconcile_hosted_identity, HostedMembershipArrival, HostedMembershipRole,
        HostedMembershipSource,
    };
    let arrival = HostedMembershipArrival::new(
        HostedMembershipRole::Owner,
        HostedMembershipSource::Direct,
        "2026-10-21T00:00:00Z".into(),
    )
    .unwrap();
    let account = reconcile_hosted_identity(
        &db,
        "draft-sender@example.test",
        "duplicate-gate-draft",
        &arrival,
        Some("native/duplicate-gate-draft"),
    )
    .await
    .unwrap();
    let draft = json!({"type":"Message", "kind":"text", "name":"Same draft", "body":"A draft",
        "addressed_to":[], "facets":{"expectation":"none"}, "reason":"fixture"});
    let sender = Caller::authenticated(&account)
        .with_hosting_context("host:draft-sender", "db:test")
        .with_channel(Channel::Mcp);
    for _ in 0..2 {
        let receipt = call(&db, &registry, sender.clone(), draft.clone())
            .await
            .unwrap();
        assert!(receipt.get("duplicate_gate").is_none());
    }
    db.close().await;
}

/// Govern one test kind with a declared identity rule, through the same
/// event-sourced vocabulary lifecycle extensions use.
async fn govern_identity_kind(
    db: &Db,
    record_type: &str,
    token: &str,
    mode: KindDedupMode,
    keys: &[&str],
) {
    create_vocabulary(db, &format!("kind:{record_type}"), None)
        .await
        .unwrap();
    let metadata = KindMetadataV1 {
        schema_version: KIND_METADATA_SCHEMA_VERSION,
        provenance_ref: "rec:test-fixture".into(),
        definition: "Test-declared identity fixture.".into(),
        identity: KindIdentityV1 {
            criterion: "Same declared tuple means the same record.".into(),
            dedup: KindDedupV1 {
                mode,
                keys: keys.iter().map(|key| key.to_string()).collect(),
            },
        },
        declared_capabilities: Vec::new(),
        legacy_unattested: false,
    };
    let id = propose_value_with_kind_metadata_as(
        db,
        &format!("kind:{record_type}"),
        token,
        None,
        0.0,
        VocabularyValueTerminality::Open,
        Some(metadata),
        None,
    )
    .await
    .unwrap();
    promote_value(db, &id).await.unwrap();
}

fn gadget(name: &str, site: &str, name_key: &str) -> Value {
    json!({"type":"Document", "kind":"gadget", "name":name,
        "reason":"declared identity fixture",
        "facets":{"site":site, "name_key":name_key}})
}

/// A refused `create_many` item carries the duplicate refusal structurally:
/// its own code, the matched candidates, and batch-coordinate advice.
fn batch_refusal(receipt: &Value, index: u64) -> Value {
    let error = receipt["errors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|error| error["index"] == index)
        .unwrap();
    assert_eq!(error["code"], "likely_duplicate");
    let candidates = error["candidates"].as_array().unwrap();
    assert!(!candidates.is_empty());
    assert_eq!(
        error["advice"],
        json!(format!(
            "Set confirm: true on records[{index}] to create despite the match, or change the identity tuple."
        ))
    );
    error.clone()
}

#[tokio::test]
async fn same_tuple_under_a_different_name_is_a_declared_duplicate() {
    let (db, registry) = setup().await;
    govern_identity_kind(
        &db,
        "Document",
        "gadget",
        KindDedupMode::FacetTuple,
        &["site", "name_key"],
    )
    .await;
    let old = seed(&db, &registry, gadget("Alpha", "acme", "widget")).await;
    let before = counts(&db).await;
    let refused = refusal(
        call(&db, &registry, mcp(), gadget("Beta", "acme", "widget"))
            .await
            .unwrap_err(),
    );
    assert_eq!(counts(&db).await, before);
    assert_eq!(refused["candidates"].as_array().unwrap().len(), 1);
    let candidate = &refused["candidates"][0];
    assert_eq!(candidate["id"], old["id"]);
    assert_eq!(candidate["why"], "declared_identity");
    assert_eq!(
        candidate["identity"],
        json!({"mode":"facet_tuple", "keys":["site","name_key"],
            "values":{"site":"acme", "name_key":"widget"}})
    );
    assert_eq!(
        refused["identity_criterion"],
        "Same declared tuple means the same record."
    );
    // A declared refusal must not suggest the supersedes retry: the same
    // tuple is refused again. Update or a deliberate confirm instead.
    assert_eq!(refused["next_calls"].as_array().unwrap().len(), 2);
    assert_eq!(refused["next_calls"][0]["operation"], "update_record");
    assert_eq!(
        refused["next_calls"][1]["arguments_patch"],
        json!({"confirm": true})
    );
    assert!(
        !refused.to_string().contains("supersedes"),
        "declared refusal must not suggest a supersedes retry"
    );
    db.close().await;
}

#[tokio::test]
async fn different_tuple_under_the_same_name_is_allowed() {
    let (db, registry) = setup().await;
    govern_identity_kind(
        &db,
        "Document",
        "gadget",
        KindDedupMode::FacetTuple,
        &["site", "name_key"],
    )
    .await;
    seed(&db, &registry, gadget("Same name", "acme", "widget")).await;
    // Same name, disjoint tuple: the name check would refuse this, but the
    // declared rule owns the kind, so the name carries no signal.
    let receipt = call(&db, &registry, mcp(), gadget("Same name", "acme", "other"))
        .await
        .unwrap();
    assert!(receipt.get("duplicate_gate").is_none());
    db.close().await;
}

#[tokio::test]
async fn missing_or_blank_key_falls_back_to_the_name_check() {
    let (db, registry) = setup().await;
    govern_identity_kind(
        &db,
        "Document",
        "gadget",
        KindDedupMode::FacetTuple,
        &["site", "name_key"],
    )
    .await;
    seed(&db, &registry, gadget("Fallback", "acme", "widget")).await;
    // Tuple incomplete on the new record: same name still refuses, but
    // through today's name path, not the declared rule.
    let mut partial = gadget("Fallback", "acme", "widget");
    partial["facets"]
        .as_object_mut()
        .unwrap()
        .remove("name_key");
    let refused = refusal(call(&db, &registry, mcp(), partial).await.unwrap_err());
    assert_eq!(refused["candidates"][0]["why"], "normalized_name");
    // ... while a different name with the same partial tuple is allowed.
    let mut partial = gadget("Entirely different", "acme", "widget");
    partial["facets"]
        .as_object_mut()
        .unwrap()
        .remove("name_key");
    let receipt = call(&db, &registry, mcp(), partial).await.unwrap();
    assert!(receipt.get("duplicate_gate").is_none());
    // A blank key counts as missing: same name refuses through the name path.
    let refused = refusal(
        call(&db, &registry, mcp(), gadget("Fallback", "acme", "   "))
            .await
            .unwrap_err(),
    );
    assert_eq!(refused["candidates"][0]["why"], "normalized_name");
    db.close().await;
}

#[tokio::test]
async fn tuple_comparison_normalises_strings_and_matches_numbers_exactly() {
    let (db, registry) = setup().await;
    govern_identity_kind(
        &db,
        "Document",
        "gadget",
        KindDedupMode::FacetTuple,
        &["site", "name_key"],
    )
    .await;
    seed(&db, &registry, gadget("Alpha", "Acme", "Widget")).await;
    // Case and surrounding whitespace are not identity.
    let refused = refusal(
        call(&db, &registry, mcp(), gadget("Beta", "  acme ", "WIDGET"))
            .await
            .unwrap_err(),
    );
    assert_eq!(refused["candidates"][0]["why"], "declared_identity");
    govern_identity_kind(
        &db,
        "Document",
        "tally",
        KindDedupMode::FacetTuple,
        &["site", "count"],
    )
    .await;
    let numbered = json!({"type":"Document", "kind":"tally", "name":"Alpha",
        "reason":"declared identity fixture", "facets":{"site":"acme", "count":3}});
    seed(&db, &registry, numbered).await;
    let mut same_number = json!({"type":"Document", "kind":"tally", "name":"Beta",
        "reason":"declared identity fixture", "facets":{"site":"acme", "count":3}});
    let refused = refusal(
        call(&db, &registry, mcp(), same_number.clone())
            .await
            .unwrap_err(),
    );
    assert_eq!(refused["candidates"][0]["why"], "declared_identity");
    same_number["facets"]["count"] = json!(4);
    let receipt = call(&db, &registry, mcp(), same_number).await.unwrap();
    assert!(receipt.get("duplicate_gate").is_none());
    db.close().await;
}

#[tokio::test]
async fn confirm_true_overrides_a_declared_tuple_match() {
    let (db, registry) = setup().await;
    govern_identity_kind(
        &db,
        "Document",
        "gadget",
        KindDedupMode::FacetTuple,
        &["site", "name_key"],
    )
    .await;
    let old = seed(&db, &registry, gadget("Alpha", "acme", "widget")).await;
    let mut args = gadget("Beta", "acme", "widget");
    args["confirm"] = json!(true);
    let created = call(&db, &registry, mcp(), args).await.unwrap();
    assert_eq!(
        created["duplicate_gate"]["confirmed_over"],
        json!([old["id"]])
    );
    db.close().await;
}

#[tokio::test]
async fn external_binding_with_declared_keys_behaves_like_facet_tuple() {
    let (db, registry) = setup().await;
    govern_identity_kind(
        &db,
        "Document",
        "extfind",
        KindDedupMode::ExternalBinding,
        &["site", "name_key"],
    )
    .await;
    let ext = |name: &str, site: &str, name_key: &str| {
        json!({"type":"Document", "kind":"extfind", "name":name,
            "reason":"declared identity fixture",
            "facets":{"site":site, "name_key":name_key}})
    };
    let old = seed(&db, &registry, ext("Alpha", "acme", "widget")).await;
    let refused = refusal(
        call(&db, &registry, mcp(), ext("Beta", "acme", "widget"))
            .await
            .unwrap_err(),
    );
    assert_eq!(refused["candidates"][0]["id"], old["id"]);
    assert_eq!(refused["candidates"][0]["why"], "declared_identity");
    assert_eq!(
        refused["candidates"][0]["identity"]["mode"],
        "external_binding"
    );
    // Different tuple under the same name is allowed, as with facet_tuple.
    let receipt = call(&db, &registry, mcp(), ext("Alpha", "acme", "other"))
        .await
        .unwrap();
    assert!(receipt.get("duplicate_gate").is_none());
    db.close().await;
}

#[tokio::test]
async fn record_id_kind_keeps_todays_name_check() {
    let (db, registry) = setup().await;
    govern_identity_kind(&db, "Document", "recid", KindDedupMode::RecordId, &[]).await;
    let rec = |name: &str, site: &str| {
        json!({"type":"Document", "kind":"recid", "name":name,
            "reason":"declared identity fixture", "facets":{"site":site}})
    };
    seed(&db, &registry, rec("Same name", "a")).await;
    // Same name with disjoint facets still refuses: no declared rule owns it.
    let refused = refusal(
        call(&db, &registry, mcp(), rec("Same name", "b"))
            .await
            .unwrap_err(),
    );
    assert_eq!(refused["candidates"][0]["why"], "normalized_name");
    // Different name with identical facets is allowed.
    let receipt = call(&db, &registry, mcp(), rec("Other name", "a"))
        .await
        .unwrap();
    assert!(receipt.get("duplicate_gate").is_none());
    db.close().await;
}

async fn call_many(db: &Db, registry: &ToolRegistry, args: Value) -> Value {
    registry
        .call(db.clone(), mcp(), "create_many", args)
        .await
        .unwrap()
}

#[tokio::test]
async fn create_many_refuses_an_item_matching_an_existing_tuple() {
    let (db, registry) = setup().await;
    govern_identity_kind(
        &db,
        "Document",
        "gadget",
        KindDedupMode::FacetTuple,
        &["site", "name_key"],
    )
    .await;
    let old = seed(&db, &registry, gadget("Alpha", "acme", "widget")).await;
    let before = counts(&db).await;
    let receipt = call_many(
        &db,
        &registry,
        json!({"reason":"batch declared identity fixture", "records":[
            {"type":"Document", "kind":"gadget", "name":"Beta",
                "facets":{"site":"acme", "name_key":"widget"}}
        ]}),
    )
    .await;
    assert_eq!(receipt["ok"], false);
    assert!(receipt["ids"][0].is_null());
    let refused = batch_refusal(&receipt, 0);
    assert_eq!(refused["candidates"][0]["id"], old["id"]);
    assert_eq!(refused["candidates"][0]["why"], "declared_identity");
    assert_eq!(counts(&db).await, before);
    db.close().await;
}

#[tokio::test]
async fn create_many_refuses_an_intra_batch_duplicate_and_blocks_dependants() {
    let (db, registry) = setup().await;
    govern_identity_kind(
        &db,
        "Document",
        "gadget",
        KindDedupMode::FacetTuple,
        &["site", "name_key"],
    )
    .await;
    let receipt = call_many(
        &db,
        &registry,
        json!({"reason":"batch intra-batch identity fixture", "records":[
            {"type":"Document", "kind":"gadget", "name":"First",
                "facets":{"site":"acme", "name_key":"widget"}},
            {"ref":"second", "type":"Document", "kind":"gadget", "name":"Second",
                "facets":{"site":"acme", "name_key":"widget"}},
            {"type":"Document", "kind":"note", "name":"Blocked",
                "parent_ref":"second"},
            {"type":"Document", "kind":"note", "name":"Independent"}
        ]}),
    )
    .await;
    assert_eq!(receipt["ok"], false);
    assert!(receipt["ids"][0].is_string());
    assert!(receipt["ids"][1].is_null());
    assert!(receipt["ids"][2].is_null());
    assert!(receipt["ids"][3].is_string());
    let refused = batch_refusal(&receipt, 1);
    assert_eq!(refused["candidates"][0]["id"], receipt["ids"][0]);
    assert_eq!(refused["candidates"][0]["why"], "declared_identity");
    let dependant = receipt["errors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|error| error["index"] == 2)
        .unwrap();
    assert_eq!(dependant["code"], "dependency_failed");
    assert_eq!(dependant["dependency_indexes"], json!([1]));
    db.close().await;
}

#[tokio::test]
async fn create_many_honours_per_item_confirm() {
    let (db, registry) = setup().await;
    govern_identity_kind(
        &db,
        "Document",
        "gadget",
        KindDedupMode::FacetTuple,
        &["site", "name_key"],
    )
    .await;
    let old = seed(&db, &registry, gadget("Alpha", "acme", "widget")).await;
    let receipt = call_many(
        &db,
        &registry,
        json!({"reason":"batch per-item consent fixture", "response_mode":"verbose", "records":[
            {"type":"Document", "kind":"gadget", "name":"Beta", "confirm":true,
                "facets":{"site":"acme", "name_key":"widget"}}
        ]}),
    )
    .await;
    assert_eq!(receipt["ok"], true);
    assert_eq!(
        receipt["results"][0]["record"]["duplicate_gate"]["confirmed_over"],
        json!([old["id"]])
    );
    db.close().await;
}

#[tokio::test]
async fn keyed_create_many_replay_is_not_a_duplicate_of_itself() {
    let (db, registry) = setup().await;
    govern_identity_kind(
        &db,
        "Document",
        "gadget",
        KindDedupMode::FacetTuple,
        &["site", "name_key"],
    )
    .await;
    seed(&db, &registry, gadget("Alpha", "acme", "widget")).await;
    // One item creates, the other is refused: the retry adds consent for the
    // refused item only, and the key must not treat that consent as a new
    // record set.
    let keyed = |confirm: bool| {
        let fresh = json!({"type":"Document", "kind":"gadget", "name":"Gamma",
            "facets":{"site":"fresh", "name_key":"widget"}});
        let mut dup = json!({"type":"Document", "kind":"gadget", "name":"Beta",
            "facets":{"site":"acme", "name_key":"widget"}});
        if confirm {
            dup["confirm"] = json!(true);
        }
        json!({"reason":"batch keyed identity fixture",
            "idempotency_key":"duplicate-gate-batch-replay",
            "records":[fresh, dup]})
    };
    let first = call_many(&db, &registry, keyed(false)).await;
    assert_eq!(first["ok"], false);
    assert!(first["ids"][0].is_string());
    batch_refusal(&first, 1);
    let resumed = call_many(&db, &registry, keyed(true)).await;
    assert_eq!(resumed["ok"], true);
    assert_eq!(resumed["ids"][0], first["ids"][0]);
    assert!(resumed["ids"][1].is_string());
    let after = counts(&db).await;
    // An identical replay replays both items instead of refusing either as a
    // duplicate of itself.
    let replay = call_many(&db, &registry, keyed(true)).await;
    assert_eq!(replay["ok"], true);
    assert_eq!(replay["ids"], resumed["ids"]);
    assert_eq!(counts(&db).await, after);
    db.close().await;
}

#[tokio::test]
async fn an_older_tuple_match_survives_bulk_neighbours() {
    let (db, registry) = setup().await;
    govern_identity_kind(
        &db,
        "Document",
        "gadget",
        KindDedupMode::FacetTuple,
        &["site", "name_key"],
    )
    .await;
    let old = seed(&db, &registry, gadget("Alpha", "acme", "widget")).await;
    // Bury the match under more than 600 newer records of the same kind with
    // different tuples. The pre-fix recency window (512 recent, 100
    // eligible) missed the original here; value-driven discovery must not.
    // Seeded through create_many without the agent channel, so the gate
    // stays out of the fixture's way.
    let local = Caller::local();
    for batch in 0..25 {
        let records: Vec<Value> = (0..25)
            .map(|item| {
                let n = batch * 25 + item;
                json!({"type":"Document", "kind":"gadget",
                    "name":format!("Bulk {n}"),
                    "facets":{"site":"bulk", "name_key":format!("key-{n}")}})
            })
            .collect();
        let receipt = registry
            .call(
                db.clone(),
                local.clone(),
                "create_many",
                json!({"reason":"bulk recall fixture", "records":records}),
            )
            .await
            .unwrap();
        assert_eq!(receipt["ok"], true);
    }
    let refused = refusal(
        call(&db, &registry, mcp(), gadget("Beta", "acme", "widget"))
            .await
            .unwrap_err(),
    );
    assert_eq!(refused["candidates"][0]["id"], old["id"]);
    assert_eq!(refused["candidates"][0]["why"], "declared_identity");
    db.close().await;
}

#[tokio::test]
async fn a_declared_spine_key_reads_the_records_column() {
    let (db, registry) = setup().await;
    govern_identity_kind(
        &db,
        "Document",
        "owned",
        KindDedupMode::FacetTuple,
        &["owner", "site"],
    )
    .await;
    let homemaker = |name: &str, owner: &str, site: &str| {
        json!({"type":"Document", "kind":"owned", "name":name,
            "owner_id":owner, "reason":"declared identity fixture",
            "facets":{"site":site}})
    };
    let owner_1 = seed(
        &db,
        &registry,
        json!({"type":"Entity", "kind":"person", "name":"Owner One", "reason":"fixture"}),
    )
    .await;
    let owner_2 = seed(
        &db,
        &registry,
        json!({"type":"Entity", "kind":"person", "name":"Owner Two", "reason":"fixture"}),
    )
    .await;
    let old = seed(
        &db,
        &registry,
        homemaker("Alpha", owner_1["id"].as_str().unwrap(), "acme"),
    )
    .await;
    // `owner` is filed as top-level `owner_id`; the tuple is only complete
    // when the gate reads that column.
    let refused = refusal(
        call(
            &db,
            &registry,
            mcp(),
            homemaker("Beta", owner_1["id"].as_str().unwrap(), "acme"),
        )
        .await
        .unwrap_err(),
    );
    assert_eq!(refused["candidates"][0]["id"], old["id"]);
    assert_eq!(refused["candidates"][0]["why"], "declared_identity");
    let receipt = call(
        &db,
        &registry,
        mcp(),
        homemaker("Beta", owner_2["id"].as_str().unwrap(), "acme"),
    )
    .await
    .unwrap();
    assert!(receipt.get("duplicate_gate").is_none());
    db.close().await;
}

#[tokio::test]
async fn tuple_comparison_uses_stored_text_form() {
    let (db, registry) = setup().await;
    govern_identity_kind(
        &db,
        "Document",
        "tally",
        KindDedupMode::FacetTuple,
        &["site", "count"],
    )
    .await;
    let numbered = json!({"type":"Document", "kind":"tally", "name":"Alpha",
        "reason":"declared identity fixture", "facets":{"site":"acme", "count":3}});
    seed(&db, &registry, numbered).await;
    // `facet_values` is TEXT, so a string "3" and a number 3 share one
    // stored form and match. This pins the deliberate rule: open facets are
    // compared by stored form, and types the storage erases can't be told
    // apart.
    let mut crossed = json!({"type":"Document", "kind":"tally", "name":"Beta",
        "reason":"declared identity fixture", "facets":{"site":"acme", "count":"3"}});
    let refused = refusal(
        call(&db, &registry, mcp(), crossed.clone())
            .await
            .unwrap_err(),
    );
    assert_eq!(refused["candidates"][0]["why"], "declared_identity");
    crossed["facets"]["count"] = json!("4");
    let receipt = call(&db, &registry, mcp(), crossed).await.unwrap();
    assert!(receipt.get("duplicate_gate").is_none());
    db.close().await;
}

#[tokio::test]
async fn archived_superseded_and_deleted_tuple_matches_are_ignored() {
    let (db, registry) = setup().await;
    govern_identity_kind(
        &db,
        "Document",
        "gadget",
        KindDedupMode::FacetTuple,
        &["site", "name_key"],
    )
    .await;
    let archived = seed(&db, &registry, gadget("Archived", "acme", "widget-a")).await;
    registry
        .call(
            db.clone(),
            Caller::local(),
            "archive_record",
            json!({"id":archived["id"],"reason":"archive fixture"}),
        )
        .await
        .unwrap();
    assert!(call(
        &db,
        &registry,
        mcp(),
        gadget("Archived", "acme", "widget-a")
    )
    .await
    .is_ok());
    // Supersession retires the old revision: the same tuple is free again.
    let old = seed(&db, &registry, gadget("Old", "acme", "widget-s")).await;
    let mut successor = gadget("New", "fresh", "widget-s");
    successor["links"] = json!([{"relationship":"supersedes", "target_id":old["id"]}]);
    seed(&db, &registry, successor).await;
    let retry = call(&db, &registry, mcp(), gadget("Old", "acme", "widget-s")).await;
    assert!(retry
        .map_err(|error| panic!("superseded retry failed: {error}"))
        .is_ok());
    let deleted = seed(&db, &registry, gadget("Deleted", "acme", "widget-d")).await;
    registry
        .call(
            db.clone(),
            Caller::local(),
            "delete_record",
            json!({"id":deleted["id"],"reason":"delete fixture"}),
        )
        .await
        .unwrap();
    assert!(
        call(&db, &registry, mcp(), gadget("Deleted", "acme", "widget-d"))
            .await
            .is_ok()
    );
    db.close().await;
}

#[tokio::test]
async fn invisible_tuple_matches_are_neither_refused_nor_disclosed() {
    let (db, registry) = setup().await;
    govern_identity_kind(
        &db,
        "Document",
        "gadget",
        KindDedupMode::FacetTuple,
        &["site", "name_key"],
    )
    .await;
    let secret = seed(&db, &registry, gadget("Private", "acme", "widget")).await;
    replace_explicit_policy(
        &db,
        "fixture:private",
        secret["id"].as_str().unwrap(),
        vec![AllowEntry::account("acct:alice", Capability::View)],
    )
    .await
    .unwrap();
    let person = seed(
        &db,
        &registry,
        json!({"type":"Entity", "kind":"person", "name":"Bea", "reason":"fixture"}),
    )
    .await;
    sqlx::query("INSERT INTO bindings (record_id, system, identifier, is_canonical) VALUES (?, 'account', 'acct:bea', 1)")
        .bind(person["id"].as_str().unwrap()).execute(&crate::common::fixture_write_pool(&db).await).await.unwrap();
    let caller = Caller::authenticated("acct:bea")
        .with_hosting_context("host:bea", "db:test")
        .with_channel(Channel::Mcp);
    // Bea cannot see the secret, so the same tuple must not refuse — and the
    // receipt must not name it either way.
    let created = call(
        &db,
        &registry,
        caller.clone(),
        gadget("Private", "acme", "widget"),
    )
    .await
    .unwrap();
    assert!(created.get("duplicate_gate").is_none());
    assert!(!created.to_string().contains(secret["id"].as_str().unwrap()));
    db.close().await;
}

#[tokio::test]
async fn kind_alias_rows_match_the_declared_tuple() {
    let (db, registry) = setup().await;
    govern_identity_kind(
        &db,
        "Document",
        "gadget",
        KindDedupMode::FacetTuple,
        &["site", "name_key"],
    )
    .await;
    let pool = crate::common::fixture_write_pool(&db).await;
    sqlx::query("INSERT INTO vocabulary_values (id,vocabulary_id,value,status,alias_of) SELECT 'fixture:old-gadget', vocabulary_id, 'old_gadget', 'deprecated', id FROM vocabulary_values WHERE value='gadget' AND vocabulary_id IN (SELECT id FROM vocabularies WHERE name='kind:Document')")
        .execute(&pool).await.unwrap();
    let old = seed(&db, &registry, gadget("Alpha", "acme", "widget")).await;
    // Simulate a historical projection, before writes canonicalized this alias.
    sqlx::query("UPDATE records SET kind='old_gadget' WHERE id=?")
        .bind(old["id"].as_str().unwrap())
        .execute(&pool)
        .await
        .unwrap();
    let refused = refusal(
        call(&db, &registry, mcp(), gadget("Beta", "acme", "widget"))
            .await
            .unwrap_err(),
    );
    assert_eq!(refused["candidates"][0]["id"], old["id"]);
    assert_eq!(refused["candidates"][0]["why"], "declared_identity");
    assert_eq!(refused["candidates"][0]["kind"], "gadget");
    db.close().await;
}

#[tokio::test]
async fn terminal_match_stored_under_an_alias_is_ignored() {
    let (db, registry) = setup().await;
    govern_identity_kind(
        &db,
        "Document",
        "twidget",
        KindDedupMode::FacetTuple,
        &["site", "name_key"],
    )
    .await;
    // Govern lifecycle on the canonical kind through the shared work-status
    // vocabulary, so a closed row resolves terminal.
    registry
        .call(
            db.clone(),
            Caller::local(),
            "manage_schema_config",
            json!({ "action": "write", "data": { "shapes": {
                "Document:twidget": { "facets": { "lifecycle": {
                    "vocab_ref": "lifecycle",
                    "axis": { "key": "work_status", "label": "Work status" } } } }
            } } }),
        )
        .await
        .unwrap();
    let pool = crate::common::fixture_write_pool(&db).await;
    sqlx::query("INSERT INTO vocabulary_values (id,vocabulary_id,value,status,alias_of) SELECT 'fixture:old-twidget', vocabulary_id, 'old_twidget', 'deprecated', id FROM vocabulary_values WHERE value='twidget' AND vocabulary_id IN (SELECT id FROM vocabularies WHERE name='kind:Document')")
        .execute(&pool).await.unwrap();
    let closed = json!({"type":"Document", "kind":"twidget", "name":"Old",
        "reason":"declared identity fixture", "lifecycle":"closed",
        "facets":{"site":"acme", "name_key":"widget"}});
    let old = seed(&db, &registry, closed).await;
    // Simulate a historical projection, before writes canonicalized this alias.
    // The interpreter must judge the resolved canonical kind: under the alias
    // the row reads as unclassified (never terminal) and would block.
    sqlx::query("UPDATE records SET kind='old_twidget' WHERE id=?")
        .bind(old["id"].as_str().unwrap())
        .execute(&pool)
        .await
        .unwrap();
    let retry = json!({"type":"Document", "kind":"twidget", "name":"New",
        "reason":"declared identity fixture",
        "facets":{"site":"acme", "name_key":"widget"}});
    assert!(call(&db, &registry, mcp(), retry).await.is_ok());
    db.close().await;
}
