//! Acceptance coverage for the contribution-provenance slice.
//!
//! Each test here names one collapse the specification exists to prevent.
//! Where a test asserts an absence, it says which absence: "withheld" and
//! "false" are different answers, and so are "unavailable" and "empty".

// Record ids must be canonical v4/v7 UUIDs, so every fixture id here is a
// pinned `c07b0000-0000-4000-8000-<counter>` literal, counters assigned in the
// ascending order of the slugs they replaced.

use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
use native_ce::contribution::{Assurance, DisplayInference};
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::provenance::Channel;
use native_ce::{create_database, Db};
use serde_json::{json, Value};

async fn db() -> Db {
    let db = create_database(":memory:").await.unwrap();
    native_ce::meta::seed_vocabularies(&db).await.unwrap();
    db
}

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

async fn call_as(
    registry: &ToolRegistry,
    db: &Db,
    caller: Caller,
    tool: &str,
    args: Value,
) -> Value {
    registry
        .call(
            db.clone(),
            caller,
            tool,
            crate::common::with_test_reason(tool, args),
        )
        .await
        .unwrap_or_else(|error| panic!("{tool} failed: {error}"))
}

async fn call(registry: &ToolRegistry, db: &Db, tool: &str, args: Value) -> Value {
    call_as(registry, db, Caller::local(), tool, args).await
}

/// An MCP-channel caller under the ordinary authenticated principal — the
/// bucket essentially all real agent traffic lands in today.
fn mcp() -> Caller {
    Caller::authenticated("local").with_channel(Channel::Mcp)
}

fn web() -> Caller {
    Caller::authenticated("local").with_channel(Channel::Web)
}

/// The run key is a CALLER-ASSERTED argument, not transport state: the request
/// pipeline lifts it out of the arguments and stamps it on the event. Setting
/// it on a `Caller` directly would be overwritten, which is exactly the
/// distinction between authenticated identity and asserted correlation.
fn in_run(run_key: &str, mut args: Value) -> Value {
    args.as_object_mut()
        .expect("tool arguments are an object")
        .insert("run_key".into(), json!(run_key));
    args
}

/// Bind the `local` credential to a visible person record so contributions
/// have a resolvable principal.
async fn bind_local_person(registry: &ToolRegistry, db: &Db) {
    call(
        registry,
        db,
        "create_record",
        json!({ "id": "c07b0000-0000-4000-8000-000000000013", "type": "Entity", "kind": "person", "name": "Richard" }),
    )
    .await;
    sqlx::query(
        "INSERT INTO bindings(record_id,system,identifier,is_canonical)
         VALUES('c07b0000-0000-4000-8000-000000000013','account','local',1)",
    )
    .execute(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap();
}

async fn bearer(registry: &ToolRegistry, db: &Db, id: &str) -> String {
    call(
        registry,
        db,
        "create_record",
        json!({ "id": id, "type": "Document", "kind": "note", "name": id, "body": "Bearer body" }),
    )
    .await;
    id.to_string()
}

async fn comment_in_run(
    registry: &ToolRegistry,
    db: &Db,
    caller: Caller,
    run_key: Option<&str>,
    id: &str,
    bearer_id: &str,
    body: &str,
) -> Value {
    let args = json!({
        "id": id, "type": "Annotation", "kind": "comment", "name": id, "body": body,
        "links": [{ "target_id": bearer_id, "relationship": "part_of" }]
    });
    let args = match run_key {
        Some(run_key) => in_run(run_key, args),
        None => args,
    };
    call_as(registry, db, caller, "create_record", args).await
}

async fn comments_on(
    registry: &ToolRegistry,
    db: &Db,
    caller: Caller,
    bearer_id: &str,
) -> Vec<Value> {
    let read = call_as(
        registry,
        db,
        caller,
        "get_record",
        json!({ "ids": [bearer_id], "include_comments": true }),
    )
    .await;
    read["records"][0]["comments"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

fn contribution(comment: &Value) -> &Value {
    &comment["contribution"]
}

// ---------------------------------------------------------------------------
// Run-scoped speaker identity
// ---------------------------------------------------------------------------

#[tokio::test]
async fn two_exact_runs_are_two_speakers_even_under_one_principal() {
    let db = db().await;
    let registry = registry();
    bind_local_person(&registry, &db).await;
    let bearer_id = bearer(&registry, &db, "c07b0000-0000-4000-8000-000000000018").await;

    comment_in_run(
        &registry,
        &db,
        mcp(),
        Some("plover-archery-aaaaaa"),
        "c07b0000-0000-4000-8000-000000000021",
        &bearer_id,
        "We should ship the narrow slice.",
    )
    .await;
    comment_in_run(
        &registry,
        &db,
        mcp(),
        Some("plover-archery-bbbbbb"),
        "c07b0000-0000-4000-8000-000000000022",
        &bearer_id,
        "We should not ship the narrow slice.",
    )
    .await;

    let comments = comments_on(&registry, &db, Caller::local(), &bearer_id).await;
    assert_eq!(comments.len(), 2);
    let runs: Vec<&str> = comments
        .iter()
        .map(|comment| contribution(comment)["run"]["run_key"].as_str().unwrap())
        .collect();
    assert!(runs.contains(&"plover-archery-aaaaaa"));
    assert!(runs.contains(&"plover-archery-bbbbbb"));

    // Same persistent agent key. Two runs. They must not merge into one
    // participant that appears to argue with itself.
    let agent_keys: Vec<&str> = comments
        .iter()
        .map(|comment| contribution(comment)["run"]["agent_key"].as_str().unwrap())
        .collect();
    assert_eq!(agent_keys, vec!["plover-archery", "plover-archery"]);
    assert_ne!(runs[0], runs[1]);

    for comment in &comments {
        // Ownership is standing, not speech. Both survive, separately.
        assert_eq!(
            comment["owner_id"],
            json!("c07b0000-0000-4000-8000-000000000013")
        );
        assert_eq!(
            contribution(comment)["run"]["assurance"],
            json!("correlation_only")
        );
        assert!(contribution(comment)["interpretation_limits"]
            .as_array()
            .unwrap()
            .iter()
            .any(|limit| limit == "run_key_does_not_establish_persistent_agent_identity"));
    }
}

#[tokio::test]
async fn several_utterances_from_one_run_stay_one_participant() {
    let db = db().await;
    let registry = registry();
    bind_local_person(&registry, &db).await;
    let bearer_id = bearer(&registry, &db, "c07b0000-0000-4000-8000-000000000009").await;
    for (index, body) in ["First point.", "Second point.", "Third point."]
        .iter()
        .enumerate()
    {
        comment_in_run(
            &registry,
            &db,
            mcp(),
            Some("scout-chair-a748b2"),
            // Pinned UUID ids whose counter is the loop index, so the three replies
            // keep their creation and id order.
            &format!("c07b0001-0000-4000-8000-{index:012}"),
            &bearer_id,
            body,
        )
        .await;
    }
    let comments = comments_on(&registry, &db, Caller::local(), &bearer_id).await;
    assert_eq!(comments.len(), 3);
    for comment in &comments {
        assert_eq!(
            contribution(comment)["run"]["run_key"],
            json!("scout-chair-a748b2")
        );
    }
}

#[tokio::test]
async fn a_missing_run_key_yields_separate_contribution_identities_not_one_unknown_speaker() {
    let db = db().await;
    let registry = registry();
    bind_local_person(&registry, &db).await;
    let bearer_id = bearer(&registry, &db, "c07b0000-0000-4000-8000-000000000016").await;
    let keyless = Caller::authenticated("local").with_channel(Channel::Mcp);
    comment_in_run(
        &registry,
        &db,
        keyless.clone(),
        None,
        "c07b0000-0000-4000-8000-000000000014",
        &bearer_id,
        "One.",
    )
    .await;
    comment_in_run(
        &registry,
        &db,
        keyless,
        None,
        "c07b0000-0000-4000-8000-000000000015",
        &bearer_id,
        "Two.",
    )
    .await;

    let comments = comments_on(&registry, &db, Caller::local(), &bearer_id).await;
    assert_eq!(comments.len(), 2);
    for comment in &comments {
        assert!(
            contribution(comment)["run"].is_null(),
            "no run means no run, not a synthetic shared one"
        );
    }
    // Identity falls back to the exact producing event, which is distinct per
    // contribution. Nothing merges them into one "unknown agent".
    let events: Vec<&str> = comments
        .iter()
        .map(|comment| {
            contribution(comment)["revision"]["event_id"]
                .as_str()
                .unwrap()
        })
        .collect();
    assert_ne!(events[0], events[1]);
}

// ---------------------------------------------------------------------------
// Executor kind, channel, and the hedge that must never occupy the ledger
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_mcp_write_renders_likely_agent_while_the_ledger_still_says_authenticated_principal() {
    let db = db().await;
    let registry = registry();
    bind_local_person(&registry, &db).await;
    let bearer_id = bearer(&registry, &db, "c07b0000-0000-4000-8000-000000000007").await;
    comment_in_run(
        &registry,
        &db,
        mcp(),
        Some("plover-archery-kt0gyr"),
        "c07b0000-0000-4000-8000-000000000008",
        &bearer_id,
        "Written over MCP.",
    )
    .await;

    let comments = comments_on(&registry, &db, Caller::local(), &bearer_id).await;
    let projected = contribution(&comments[0]).clone();
    assert_eq!(
        projected["executor"]["kind"],
        json!("authenticated_principal"),
        "the hedge must never be written into the attested executor slot"
    );
    assert_eq!(projected["executor"]["assurance"], json!("engine_attested"));
    assert_eq!(projected["channel"]["kind"], json!("mcp"));
    assert_eq!(projected["channel"]["assurance"], json!("server_observed"));
    assert_eq!(
        projected["channel"]["display_inference"],
        json!("likely_agent")
    );
    assert!(projected["interpretation_limits"]
        .as_array()
        .unwrap()
        .iter()
        .any(|limit| limit == "channel_display_inference_is_not_attested_execution"));
}

#[tokio::test]
async fn a_web_write_infers_nothing_and_never_claims_a_human_executor() {
    let db = db().await;
    let registry = registry();
    bind_local_person(&registry, &db).await;
    let bearer_id = bearer(&registry, &db, "c07b0000-0000-4000-8000-000000000023").await;
    comment_in_run(
        &registry,
        &db,
        web(),
        Some("scout-chair-c748b2"),
        "c07b0000-0000-4000-8000-000000000024",
        &bearer_id,
        "Typed in the workbench.",
    )
    .await;

    let comments = comments_on(&registry, &db, Caller::local(), &bearer_id).await;
    let projected = contribution(&comments[0]).clone();
    assert_eq!(projected["channel"]["kind"], json!("web"));
    // Trusted web ingress is a channel observation. Only the signed
    // interaction verifier stamps `human`, and it is not wired, so an honest
    // read reports the fall-through rather than inventing a person.
    assert_eq!(
        projected["executor"]["kind"],
        json!("authenticated_principal")
    );
    assert!(
        projected["channel"]["display_inference"].is_null(),
        "web ingress alone must not imply a human executor"
    );
}

#[tokio::test]
async fn a_verified_human_interaction_stamps_human_and_renders_as_a_person() {
    let db = db().await;
    let registry = registry();
    bind_local_person(&registry, &db).await;
    let bearer_id = bearer(&registry, &db, "c07b0000-0000-4000-8000-000000000005").await;

    let arguments = crate::common::with_test_reason(
        "create_record",
        json!({
            "id": "c07b0000-0000-4000-8000-000000000006", "type": "Annotation", "kind": "comment",
            "name": "c07b0000-0000-4000-8000-000000000006", "body": "I typed this myself.",
            "links": [{ "target_id": bearer_id, "relationship": "part_of" }]
        }),
    );
    let issuer = native_ce::provenance::ProvenanceInteractionTokenIssuer::random("workbench-ui");
    let scope = native_ce::provenance::verified_action_scope("create_record", &arguments);
    let token = issuer.issue("local", &scope, 60).unwrap();
    let caller = Caller::authenticated("local")
        .with_channel(Channel::Web)
        .with_provenance_interaction_token(&issuer, &token, &scope)
        .unwrap();
    registry
        .call(db.clone(), caller, "create_record", arguments)
        .await
        .unwrap();

    let comments = comments_on(&registry, &db, Caller::local(), &bearer_id).await;
    let projected = contribution(&comments[0]).clone();
    assert_eq!(projected["executor"]["kind"], json!("human"));
    assert_eq!(projected["channel"]["display_inference"], json!("human"));
    // Human authorship is still not endorsement. Typing something is not the
    // same as standing behind it.
    assert!(projected["interpretation_limits"]
        .as_array()
        .unwrap()
        .iter()
        .any(|limit| limit == "principal_association_does_not_establish_endorsement"));
}

// ---------------------------------------------------------------------------
// Revision provenance
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_body_replaced_by_another_run_attributes_the_current_body_to_the_editor() {
    let db = db().await;
    let registry = registry();
    bind_local_person(&registry, &db).await;
    let bearer_id = bearer(&registry, &db, "c07b0000-0000-4000-8000-000000000001").await;
    comment_in_run(
        &registry,
        &db,
        mcp(),
        Some("plover-archery-aaaaaa"),
        "c07b0000-0000-4000-8000-000000000002",
        &bearer_id,
        "The original wording.",
    )
    .await;
    let digest = call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": ["c07b0000-0000-4000-8000-000000000002"] }),
    )
    .await["records"][0]["body_digest"]
        .as_str()
        .unwrap()
        .to_owned();
    call_as(
        &registry,
        &db,
        mcp(),
        "update_record",
        in_run(
            "scout-chair-bbbbbb",
            json!({
                "id": "c07b0000-0000-4000-8000-000000000002", "body": "Rewritten by a different run.",
                "if_body_digest": digest
            }),
        ),
    )
    .await;

    let comments = comments_on(&registry, &db, Caller::local(), &bearer_id).await;
    let projected = contribution(&comments[0]).clone();
    assert_eq!(
        projected["run"]["run_key"],
        json!("scout-chair-bbbbbb"),
        "the primary byline follows the event that produced the body being read"
    );
    assert_eq!(
        projected["created_by"]["run_key"],
        json!("plover-archery-aaaaaa"),
        "creation provenance remains visible secondarily"
    );
    assert_eq!(projected["created_by"]["same_run"], json!(false));
    // Each label addresses its own exact event, so both remain independently
    // inspectable.
    assert_ne!(
        projected["revision"]["event_id"],
        projected["created_by"]["event_id"]
    );
    assert_eq!(projected["revision"]["event_type"], json!("record.updated"));
}

#[tokio::test]
async fn an_unedited_contribution_reports_one_participant() {
    let db = db().await;
    let registry = registry();
    bind_local_person(&registry, &db).await;
    let bearer_id = bearer(&registry, &db, "c07b0000-0000-4000-8000-000000000019").await;
    comment_in_run(
        &registry,
        &db,
        mcp(),
        Some("plover-archery-kt0gyr"),
        "c07b0000-0000-4000-8000-000000000020",
        &bearer_id,
        "Said once.",
    )
    .await;
    let comments = comments_on(&registry, &db, Caller::local(), &bearer_id).await;
    let projected = contribution(&comments[0]).clone();
    assert_eq!(projected["created_by"]["same_run"], json!(true));
    assert_eq!(
        projected["created_by"]["event_id"],
        projected["revision"]["event_id"]
    );
}

// ---------------------------------------------------------------------------
// Visibility and disclosure
// ---------------------------------------------------------------------------

#[tokio::test]
async fn another_principals_run_is_withheld_and_same_run_is_null_not_false() {
    let db = db().await;
    let registry = registry();
    bind_local_person(&registry, &db).await;
    let bearer_id = bearer(&registry, &db, "c07b0000-0000-4000-8000-000000000011").await;
    comment_in_run(
        &registry,
        &db,
        mcp(),
        Some("plover-archery-aaaaaa"),
        "c07b0000-0000-4000-8000-000000000012",
        &bearer_id,
        "Produced by someone else's run.",
    )
    .await;
    // Edit from a SECOND run, so creation and current body are genuinely
    // different events. Without that, `same_run` is trivially true from event
    // identity alone and the disclosure rule is never exercised.
    let digest = call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": ["c07b0000-0000-4000-8000-000000000012"] }),
    )
    .await["records"][0]["body_digest"]
        .as_str()
        .unwrap()
        .to_owned();
    call_as(
        &registry,
        &db,
        mcp(),
        "update_record",
        in_run(
            "scout-chair-bbbbbb",
            json!({
                "id": "c07b0000-0000-4000-8000-000000000012", "body": "Rewritten by a second run.",
                "if_body_digest": digest
            }),
        ),
    )
    .await;

    // Hide the ACTOR'S person record from everyone but the actor. This is the
    // condition the disclosure rule is about: the bearer and its comments stay
    // readable, but who acted — and therefore the run that acted — does not.
    replace_explicit_policy(
        &db,
        "test:policy",
        "c07b0000-0000-4000-8000-000000000013",
        vec![AllowEntry::account("local", Capability::Manage)],
    )
    .await
    .unwrap();

    // A different authenticated principal with no visibility on the actor.
    let stranger = Caller::authenticated("stranger").with_channel(Channel::Mcp);
    let read = registry
        .call(
            db.clone(),
            stranger,
            "get_record",
            json!({ "ids": [bearer_id], "include_comments": true }),
        )
        .await
        .expect("the bearer itself is readable; only the actor's run is withheld");
    let comments = read["records"][0]["comments"].as_array().unwrap().clone();
    let projected = contribution(&comments[0]).clone();
    assert!(
        projected["run"].is_null(),
        "a non-caller run is withheld, not partially disclosed"
    );
    assert!(
        projected["created_by"]["same_run"].is_null(),
        "a withheld run yields unknown, never false"
    );
    let serialized = projected.to_string();
    assert!(
        !serialized.contains("plover-archery-aaaaaa") && !serialized.contains("scout-chair-bbbbbb"),
        "a withheld run key must not survive anywhere in the envelope"
    );
    // The attested class is non-identifying and survives.
    assert_eq!(
        projected["executor"]["kind"],
        json!("authenticated_principal")
    );
}

#[tokio::test]
async fn the_assurance_vocabulary_never_distinguishes_absence_from_denial() {
    // One token for both, so a caller cannot use the reason as an oracle.
    let withheld = serde_json::to_value(Assurance::UnknownOrWithheld).unwrap();
    assert_eq!(withheld, json!("unknown_or_withheld"));
    assert_eq!(
        serde_json::to_value(Assurance::EngineAttested).unwrap(),
        json!("engine_attested")
    );
    assert_eq!(
        serde_json::to_value(DisplayInference::LikelyAgent).unwrap(),
        json!("likely_agent")
    );
}

// ---------------------------------------------------------------------------
// Explicit alternatives and selection
// ---------------------------------------------------------------------------

async fn five_candidate_exploration(registry: &ToolRegistry, db: &Db) -> Value {
    call_as(
        registry,
        db,
        mcp(),
        "create_exploration",
        json!({
            "reason": "Richard asked for five possible homepage directions.",
            "exploration": {
                "create": {
                    "name": "Homepage directions",
                    "body": "Five directions generated in response to Richard's request. None is his view."
                }
            },
            "candidates": (1..=5).map(|index| json!({
                "type": "Document", "kind": "note",
                "name": format!("Direction {index}"),
                "body": format!("Homepage direction number {index}.")
            })).collect::<Vec<_>>()
        }),
    )
    .await
}

#[tokio::test]
async fn one_composite_call_creates_the_exploration_every_candidate_and_every_membership() {
    let db = db().await;
    let registry = registry();
    bind_local_person(&registry, &db).await;
    let created = five_candidate_exploration(&registry, &db).await;

    assert_eq!(created["exploration_created"], json!(true));
    assert_eq!(created["selection_role"], json!("alternative_set"));
    let candidates = created["candidates"].as_array().unwrap();
    assert_eq!(candidates.len(), 5);
    assert_eq!(
        created["candidate_order_is_request_order_only"],
        json!(true)
    );

    let exploration_id = created["exploration"]["id"].as_str().unwrap().to_owned();
    for candidate in candidates {
        let id = candidate["id"].as_str().unwrap();
        let read = call(&registry, &db, "get_record", json!({ "ids": [id] })).await;
        let projected = &read["records"][0]["contribution"];
        assert_eq!(
            projected["context"]["alternative_set"]["id"],
            json!(exploration_id)
        );
        assert_eq!(
            projected["context"]["alternative_set"]["label"],
            json!("Homepage directions")
        );
        assert_eq!(
            projected["context"]["alternative_set"]["visible_member_count"],
            json!(5)
        );
        assert_eq!(projected["context"]["mode"], json!("option"));
        // Five candidates are not five beliefs.
        let limits = projected["interpretation_limits"].as_array().unwrap();
        assert!(limits
            .iter()
            .any(|limit| limit == "content_creation_does_not_establish_stance"));
        assert!(limits
            .iter()
            .any(|limit| limit == "alternative_set_membership_has_no_authored_order"));
        let rendered = native_ce::mcp::render::render("get_record", &read).unwrap();
        for expected in [
            exploration_id.as_str(),
            "visible_member_count",
            "content_creation_does_not_establish_stance",
            "alternative_set_membership_has_no_authored_order",
        ] {
            assert!(
                rendered.contains(expected),
                "missing {expected}: {rendered}"
            );
        }
    }
}

#[tokio::test]
async fn no_candidate_carries_an_authored_ordinal() {
    let db = db().await;
    let registry = registry();
    bind_local_person(&registry, &db).await;
    let created = five_candidate_exploration(&registry, &db).await;
    for candidate in created["candidates"].as_array().unwrap() {
        let id = candidate["id"].as_str().unwrap();
        let read = call(&registry, &db, "get_record", json!({ "ids": [id] })).await;
        let serialized = read["records"][0].to_string();
        assert!(
            !serialized.contains("ordinal"),
            "v1 must not imply that presentation order is authored order"
        );
        let set = &read["records"][0]["contribution"]["context"]["alternative_set"];
        assert!(set.get("ordinal").is_none());
        assert!(set.get("position").is_none());
    }
}

#[tokio::test]
async fn any_candidate_failure_rolls_the_whole_exploration_back() {
    let db = db().await;
    let registry = registry();
    bind_local_person(&registry, &db).await;
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records")
        .fetch_one(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();

    let error = registry
        .call(
            db.clone(),
            mcp(),
            "create_exploration",
            json!({
                "reason": "Four good candidates and one impossible one.",
                "exploration": { "create": { "name": "Doomed exploration" } },
                "candidates": [
                    { "type": "Document", "kind": "note", "name": "Fine", "body": "ok" },
                    { "type": "NotASpineType", "kind": "note", "name": "Broken" }
                ]
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("not a spine type"), "{error}");

    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records")
        .fetch_one(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    assert_eq!(
        before, after,
        "a half-populated exploration reads as a complete one, so nothing may land"
    );
}

#[tokio::test]
async fn an_unmarked_selection_is_not_an_exploration() {
    let db = db().await;
    let registry = registry();
    bind_local_person(&registry, &db).await;
    call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": "c07b0000-0000-4000-8000-000000000010", "type": "Collection", "kind": "selection",
            "name": "An ordinary curated list"
        }),
    )
    .await;
    let error = registry
        .call(
            db.clone(),
            Caller::local(),
            "create_exploration",
            json!({
                "reason": "Trying to reuse a curated list.",
                "exploration": { "id": "c07b0000-0000-4000-8000-000000000010" },
                "candidates": [{ "type": "Document", "kind": "note", "name": "A", "body": "a" }]
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("not marked"),
        "silently marking someone's curated list would rewrite what they meant by it: {error}"
    );
}

#[tokio::test]
async fn selection_creates_a_separate_decision_and_erases_no_candidate() {
    let db = db().await;
    let registry = registry();
    bind_local_person(&registry, &db).await;
    let created = five_candidate_exploration(&registry, &db).await;
    let exploration_id = created["exploration"]["id"].as_str().unwrap().to_owned();
    let chosen = created["candidates"][2]["id"].as_str().unwrap().to_owned();

    call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": "c07b0000-0000-4000-8000-000000000004", "type": "Resolution", "kind": "decision",
            "name": "Homepage direction three",
            "body": "Direction three it is.",
            "links": [
                { "target_id": exploration_id, "relationship": "derived_from" },
                { "target_id": chosen, "relationship": "selects" }
            ]
        }),
    )
    .await;

    // The chosen candidate reports the decision.
    let read = call(&registry, &db, "get_record", json!({ "ids": [&chosen] })).await;
    let selection = &read["records"][0]["contribution"]["context"]["selection"];
    assert_eq!(
        selection["decision_id"],
        json!("c07b0000-0000-4000-8000-000000000004")
    );
    assert_eq!(selection["effective"], json!(true));

    // Every candidate, chosen or not, remains a member. The option history is
    // the point.
    for candidate in created["candidates"].as_array().unwrap() {
        let id = candidate["id"].as_str().unwrap();
        let read = call(&registry, &db, "get_record", json!({ "ids": [id] })).await;
        assert_eq!(
            read["records"][0]["contribution"]["context"]["alternative_set"]["id"],
            json!(exploration_id),
            "selection must not remove unchosen members"
        );
        assert_eq!(
            read["records"][0]["contribution"]["context"]["alternative_set"]
                ["visible_member_count"],
            json!(5)
        );
    }

    // The decision is its own record with its own contribution provenance. An
    // agent recording it does not make it Richard's endorsement.
    let decision = call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": ["c07b0000-0000-4000-8000-000000000004"] }),
    )
    .await;
    let projected = &decision["records"][0]["contribution"];
    assert!(projected["revision"]["event_id"].is_string());
    assert!(projected["interpretation_limits"]
        .as_array()
        .unwrap()
        .iter()
        .any(|limit| limit == "principal_association_does_not_establish_endorsement"));
}

#[tokio::test]
async fn a_later_decision_supersedes_without_removing_the_earlier_one() {
    let db = db().await;
    let registry = registry();
    bind_local_person(&registry, &db).await;
    let created = five_candidate_exploration(&registry, &db).await;
    let exploration_id = created["exploration"]["id"].as_str().unwrap().to_owned();
    let first = created["candidates"][0]["id"].as_str().unwrap().to_owned();

    call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": "c07b0000-0000-4000-8000-000000000003", "type": "Resolution", "kind": "decision",
            "name": "Direction one", "body": "One for now.",
            "links": [
                { "target_id": exploration_id, "relationship": "derived_from" },
                { "target_id": first, "relationship": "selects" }
            ]
        }),
    )
    .await;
    call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": "c07b0000-0000-4000-8000-000000000017", "type": "Resolution", "kind": "decision",
            "name": "Direction two after all", "body": "Changed our minds.",
            "links": [{ "target_id": "c07b0000-0000-4000-8000-000000000003", "relationship": "supersedes" }]
        }),
    )
    .await;

    let read = call(&registry, &db, "get_record", json!({ "ids": [&first] })).await;
    let selection = &read["records"][0]["contribution"]["context"]["selection"];
    assert_eq!(
        selection["decision_id"],
        json!("c07b0000-0000-4000-8000-000000000003")
    );
    assert_eq!(
        selection["effective"],
        json!(false),
        "both decisions stay inspectable; the superseded one stops being effective"
    );
}
