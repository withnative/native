//! Deny-by-default guard: no workspace-wide counter reaches a non-owner
//! (design 08b4c21 §4 S1, task a5804e8).
//!
//! The rule (Richard, settled): a non-owner may learn the *timing* of activity
//! they cannot see, but not its count, identity or content. This test builds a
//! workspace with an owner and a member where the owner has a record the member
//! cannot see, calls the MCP tool surface as the **member**, and walks every
//! JSON response and error for counters:
//!
//! - banned keys and values are `native_ce::mcp::counter_fence`'s, the same
//!   list the member-copy scrub and the member-copy fence tests use;
//! - an error that prints the current workspace head also counts.
//!
//! Every hit on today's code sits on [`ALLOWLIST`] as (tool, normalised JSON
//! path), tagged with the slice that removes it. The guard fails on a counter
//! that is not listed (a new leak) and on a listed entry that no longer occurs
//! (stale), so the list shrinks honestly and an empty list is the acceptance.
//!
//! # Tool coverage
//!
//! Every tool in the local registry is accounted for: either called here (all
//! the read tools and read actions, plus representative writes), or named in
//! [`NOT_EXERCISED`] with a reason. A tool whose authoritative disposition is
//! `Read` may never be in `NOT_EXERCISED`, so a new read tool cannot slip past
//! the guard. Writes are exercised once per distinct response family (record
//! create/update/archive, links, attachments, facet observations, work claim,
//! messaging, batch), not once per tool.
//!
//! # The mdx v2 render path (M2)
//!
//! The fixture owns a minimal `native.mdx.v2` artifact (no inputs, modules or
//! capability requests) and installs the same test-local HTML runtime origins
//! `alpha_tabs` already installs for this binary, so `render_artifact` reaches
//! its success path as a member and the S5 counters it carries
//! (`plan.provenance.*snapshot_event_seq`, `*content_event_seq`,
//! `*authorization_revision`) are allowlisted. This needs no renderer, module
//! or verification service: the `tests/records` runtime-config lease is not
//! reused, because that file's globals are only needed by tests that change
//! the configuration, and the origins here are idempotent.
//!
//! Still unreached, and named rather than hidden: `verify_artifact` (needs the
//! verification service and MDX issuer configured), and the success paths in
//! [`READ_SUCCESS_GAPS`]. Until those are reached the guard does not claim that
//! every read path is covered.
//!
//! # Deferred: action-aware allowlist (L3)
//!
//! The allowlist key is `(tool, path)`, not `(tool, action, path)`. A *new*
//! action on an existing tool that echoes an already-listed path — for example
//! a new `manage_messages` action returning `$.act` — therefore passes without a
//! new entry. This is a known coverage limitation, deliberately not silent: the
//! guard stays deny-by-default for new tools and new path shapes, and this note
//! is the record that the action dimension is not yet checked.

use std::collections::{BTreeMap, BTreeSet};

use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
use native_ce::freshness::current_record_body_revision;
use native_ce::identity::hosted::{
    reconcile_hosted_identity, HostedMembershipArrival, HostedMembershipRole,
    HostedMembershipSource,
};
use native_ce::mcp::counter_fence::{find_counters, text_names_head};
use native_ce::mcp::tools::hcp_v2::{register_hcp_v2_tools, PseudonymKey, ADD_PREFERENCE};
use native_ce::mcp::{
    register_builtin_tools, register_surface_tools, AuthoritativeDisposition, Caller, ToolRegistry,
};
use native_ce::meta::{
    promote_value, propose_value_with_kind_metadata_as, write_user_schema_config, KindMetadataV1,
    SchemaConfigOptions, VocabularyValueTerminality,
};
use native_ce::{create_database, Db};
use serde_json::{json, Value};

/// The slice (design 08b4c21 §4) that removes an allowlisted counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Slice {
    /// Close the head-on-demand channels nobody reads.
    S2,
    /// Remaining replacement outputs (history, whats_changed, snapshots, ...).
    S3b,
    /// Stream and `render_artifact` switch to positions.
    S5,
    /// Remove numbers from non-owner MCP responses.
    S6,
    /// SQL seq columns: sortable, not selectable.
    S7,
    /// Residue: authorization epoch, canvas ordinals.
    S8,
}

/// The pseudo-path for an error whose text names the workspace head.
const ERROR_PATH: &str = "<error text>";

/// Today's known counters for a non-owner: (tool, normalised path, slice).
/// `$` is the response; `.key` descends an object; `[]` any array element.
const ALLOWLIST: &[(&str, &str, Slice)] = &[
    ("archive_record", "$.previous_seq", Slice::S6),
    ("batch_write", "$.results[].previous_seq", Slice::S6),
    ("create_many", "$.results[].record.previous_seq", Slice::S6),
    ("create_record", "$.previous_seq", Slice::S6),
    ("create_record", "$.version", Slice::S6),
    ("delete_record", "$.previous_seq", Slice::S6),
    (
        "get_event_context",
        "$.event.causal_envelope.frontier",
        Slice::S2,
    ),
    ("get_event_context", "$.event.local_seq", Slice::S6),
    (
        "get_history",
        "$.events[].causal_envelope.frontier",
        Slice::S2,
    ),
    ("get_history", "$.events[].local_seq", Slice::S6),
    ("get_history", "$.next_after_local_seq", Slice::S3b),
    ("get_record", "$.as_of.content_seq", Slice::S6),
    ("get_record", "$.content_head_seq", Slice::S2),
    ("get_record", "$.records[].facets[].version", Slice::S6),
    ("instantiate_artifact", "$.facets[].version", Slice::S6),
    ("instantiate_artifact", "$.previous_seq", Slice::S6),
    (
        "get_record",
        "$.records[].history_summary.latest.causal_envelope.frontier",
        Slice::S2,
    ),
    (
        "get_record",
        "$.records[].history_summary.latest.local_seq",
        Slice::S6,
    ),
    (
        "get_record",
        "$.records[].history_summary.oldest.causal_envelope.frontier",
        Slice::S2,
    ),
    (
        "get_record",
        "$.records[].history_summary.oldest.local_seq",
        Slice::S6,
    ),
    ("get_record", "$.records[].version", Slice::S6),
    ("get_record", "$.resolved_content_seq", Slice::S2),
    ("get_record", ERROR_PATH, Slice::S2),
    (
        "get_reuse_context",
        "$.basis.output_revision_seq",
        Slice::S6,
    ),
    (
        "get_reuse_context",
        "$.record.revision.revision_seq",
        Slice::S6,
    ),
    ("get_workspace_snapshot", "$.content_seq", Slice::S6),
    ("get_workspace_snapshot", "$.authorization_epoch", Slice::S8),
    ("get_workspace_snapshot", "$.relationship_seq", Slice::S6),
    ("manage_facet_observations", "$.event_seq", Slice::S6),
    (
        "manage_facet_observations",
        "$.observations[].event_seq",
        Slice::S6,
    ),
    ("manage_facet_observations", "$.previous_seq", Slice::S6),
    (
        "manage_interventions",
        "$.items[].guard_tokens.expected_intervention_seq",
        Slice::S6,
    ),
    (
        "manage_interventions",
        "$.items[].projection_seq",
        Slice::S6,
    ),
    (
        "manage_interventions",
        "$.items[].state.execution.basis_event_seq",
        Slice::S6,
    ),
    (
        "manage_interventions",
        "$.items[].trigger.message_content_seq",
        Slice::S6,
    ),
    ("manage_links", "$.previous_seq", Slice::S6),
    ("manage_messages", "$.candidates[].seq", Slice::S6),
    ("manage_messages", "$.content_head", Slice::S2),
    ("manage_messages", "$.facets[].version", Slice::S6),
    ("manage_messages", "$.heads", Slice::S2),
    ("manage_messages", "$.previous_seq", Slice::S6),
    ("manage_messages", ERROR_PATH, Slice::S2),
    (
        "preview_record_shape",
        "$.advisory_basis.event_heads",
        Slice::S6,
    ),
    (
        "preview_record_shape",
        "$.advisory_basis.schema_state_revision",
        Slice::S3b,
    ),
    (
        "query_record",
        "$.activities[].event.causal_envelope.frontier",
        Slice::S2,
    ),
    ("query_record", "$.activities[].event.local_seq", Slice::S6),
    ("query_record", "$.as_of.content_seq", Slice::S6),
    ("query_record", "$.content_head_seq", Slice::S2),
    ("query_record", "$.high_water_local_seq", Slice::S2),
    ("query_record", "$.records[].version", Slice::S6),
    ("query_record", "$.resolved_content_seq", Slice::S2),
    ("query_record", "$.subject_as_of_local_seq", Slice::S6),
    ("query_record", ERROR_PATH, Slice::S2),
    ("query_sql", "$.as_of_seq", Slice::S2),
    ("query_sql", "$.rows[].local_seq", Slice::S7),
    ("read_attributions", "$.as_of_event_seq", Slice::S6),
    (
        "read_attributions",
        "$.interpretation.as_of_event_seq",
        Slice::S6,
    ),
    ("read_canvas", "$.after", Slice::S8),
    ("read_canvas", "$.batches[].canvas_version", Slice::S8),
    ("read_canvas", "$.batches[].event_seq", Slice::S6),
    ("read_canvas", "$.canvas.record_version", Slice::S8),
    ("read_canvas", "$.canvas_version", Slice::S8),
    (
        "read_canvas",
        "$.history.batches[].canvas_version",
        Slice::S8,
    ),
    ("read_canvas", "$.history.batches[].event_seq", Slice::S6),
    ("read_canvas", "$.next_after", Slice::S8),
    ("read_canvas", "$.objects[].versions.content", Slice::S8),
    ("read_canvas", "$.objects[].versions.geometry", Slice::S8),
    ("read_canvas", "$.resolved_content_seq", Slice::S2),
    (
        "read_canvas",
        "$.scene.objects[].versions.content",
        Slice::S8,
    ),
    (
        "read_canvas",
        "$.scene.objects[].versions.geometry",
        Slice::S8,
    ),
    ("render_record_version_diff", "$.after.as_of_seq", Slice::S6),
    (
        "render_record_version_diff",
        "$.after.record.facets[].version",
        Slice::S6,
    ),
    (
        "render_record_version_diff",
        "$.before.as_of_seq",
        Slice::S6,
    ),
    (
        "render_record_version_diff",
        "$.events[].causal_envelope.frontier",
        Slice::S2,
    ),
    (
        "render_record_version_diff",
        "$.events[].local_seq",
        Slice::S6,
    ),
    ("render_record_version_diff", ERROR_PATH, Slice::S2),
    (
        "render_suggestion_review",
        "$.target.current_seq",
        Slice::S6,
    ),
    // The mdx v2 success path (M2): provenance names the snapshot and
    // authorization positions as raw counters until S5 switches to positions.
    ("render_artifact", "$.plan.provenance.event_seq", Slice::S5),
    (
        "render_artifact",
        "$.plan.provenance.input_bundle.revision.authorization_revision",
        Slice::S5,
    ),
    (
        "render_artifact",
        "$.plan.provenance.input_bundle.revision.content_event_seq",
        Slice::S5,
    ),
    (
        "render_artifact",
        "$.plan.provenance.revalidation.authorization_revision",
        Slice::S5,
    ),
    (
        "render_artifact",
        "$.plan.provenance.revalidation.snapshot_event_seq",
        Slice::S5,
    ),
    (
        "render_artifact",
        "$.plan.provenance.snapshot_event_seq",
        Slice::S5,
    ),
    ("resolve_facets", "$.values[].version", Slice::S6),
    ("update_record", "$.previous_seq", Slice::S6),
    ("update_record", "$.version", Slice::S6),
    ("whats_changed", "$.after_local_seq", Slice::S3b),
    ("whats_changed", "$.changes[].first_local_seq", Slice::S6),
    ("whats_changed", "$.changes[].last_local_seq", Slice::S6),
    ("whats_changed", "$.high_water_local_seq", Slice::S3b),
    ("whats_changed", "$.next_after_local_seq", Slice::S3b),
    (
        "whats_changed",
        "$.next_request.after_local_seq",
        Slice::S3b,
    ),
    (
        "whats_changed",
        "$.next_request.through_local_seq",
        Slice::S3b,
    ),
    ("whats_changed", "$.scanned_through_local_seq", Slice::S3b),
    ("whats_changed", ERROR_PATH, Slice::S2),
    ("manage_canvas", "$.canvas_version", Slice::S8),
    ("manage_canvas", "$.objects.n2.content", Slice::S8),
    ("manage_canvas", "$.objects.n2.geometry", Slice::S8),
    ("manage_canvas", "$.write_receipt.event.seq", Slice::S6),
];

/// Tools the guard does not call, each with the reason. Read tools may not
/// appear here. These are writes whose fixtures (a suggestion, an annotation,
/// a citation, an artifact interaction, a network fetch) the guard does not
/// build.
///
/// The `act` direct-insert sites of S2a are no longer here:
/// `resolve_external`, `observe_external`, `manage_bindings` (add) and
/// `instantiate_artifact` have successful fixtures in [`plan`], and the one
/// outward projection in `ToolRegistry` (not a per-site edit) is what keeps
/// their `act` away from the member. `invoke_artifact_interaction`, whose
/// committed creation hoists an `act` beside `refresh.record.act`, is not
/// reachable from this workspace fixture; it is proved by
/// `tests/records/artifact_interactions.rs`
/// (`non_owner_creation_invocation_withholds_act_at_both_positions`), and stays
/// listed so the gap is named, not hidden. The remaining entries are ordinary
/// writes whose fixtures are not built; where they echo an act it is through
/// the same projection.
const NOT_EXERCISED: &[(&str, &str)] = &[
    (
        "advance_artifact_port_pin",
        "write: needs an artifact fixture",
    ),
    (
        "invoke_artifact_interaction",
        "write: needs an artifact fixture",
    ),
    ("attach_from_url", "write: performs a network fetch"),
    ("resolve_suggestions", "write: needs pending suggestions"),
    ("manage_citations", "write: needs an existing citation"),
    (
        "create_attribution",
        "write: needs an attribution target fixture",
    ),
    ("manage_attributions", "write: needs an existing annotation"),
    (
        "manage_change_summaries",
        "write: needs a published recipe and source runs",
    ),
    ("create_exploration", "write: needs a candidate fixture"),
];

/// Mutation tools the guard only ever drives to an error in this fixture, each
/// with the reason. No read tool may appear here.
const ERROR_ONLY: &[(&str, &str)] = &[
    ("claim_unowned_record", "host-owner authority is required"),
    (
        "correct_record_type",
        "executes only through a claimed plan",
    ),
];

/// Read surfaces whose success path this fixture cannot reach. Each is a
/// **known, explicit coverage gap**, named here rather than hidden in
/// `ERROR_ONLY`, with the fixture it would need. The coverage test fails if one
/// starts succeeding, so the gap is deleted when it is closed (M4).
const READ_SUCCESS_GAPS: &[(&str, &str)] = &[
    ("manage_named_views", "all six actions refuse on this ordinary SQLite fixture; hosted-v2 successes and authority boundaries are tested in src/named_views/execution_tests.rs"),
    ("manage_onboarding", "database owner host role required"),
    ("manage_mdx_modules", "no module fixture"),
    ("resolve_citation", "no citation fixture"),
    ("resolve_rollup", "no rollup facet fixture"),
];

// ---------------------------------------------------------------------------
// The evaluator: pure, so a negative test can drive it with synthetic input.
// ---------------------------------------------------------------------------

type Observed = BTreeSet<(String, String)>;

/// Counters found in one response (or error) for `tool`.
fn observe(tool: &str, response: &Value, observed: &mut Observed) {
    for hit in find_counters(response) {
        observed.insert((tool.to_string(), hit.path));
    }
}

/// Every way `observed` disagrees with `allowlist`: a counter that is not
/// listed (a new leak) or a listed entry that no longer occurs (stale).
fn verdict(observed: &Observed, allowlist: &[(&str, &str, Slice)]) -> Vec<String> {
    let allowed: BTreeSet<(String, String)> = allowlist
        .iter()
        .map(|(tool, path, _)| ((*tool).to_string(), (*path).to_string()))
        .collect();
    let mut problems = Vec::new();
    for (tool, path) in observed.difference(&allowed) {
        problems.push(format!("NEW counter for a non-owner: {tool} {path}"));
    }
    for (tool, path) in allowed.difference(observed) {
        problems.push(format!(
            "STALE allowlist entry (no longer occurs; delete it): {tool} {path}"
        ));
    }
    problems
}

// ---------------------------------------------------------------------------
// The fixture.
// ---------------------------------------------------------------------------

struct Fixture {
    db: Db,
    registry: ToolRegistry,
    config_account: String,
}

fn member() -> Caller {
    Caller::authenticated("acct:member")
        .with_hosting_context("host:member", "db:test")
        .with_hosting_owner(false)
        .with_hosting_member(true)
}

async fn owner_call(fx: &Fixture, tool: &str, arguments: Value) -> Value {
    fx.registry
        .call(fx.db.clone(), Caller::local(), tool, arguments)
        .await
        .unwrap_or_else(|error| panic!("owner {tool} failed: {error}"))
}

async fn head(db: &Db) -> i64 {
    sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap()
}

async fn bind_account(db: &Db, person: &str, account: &str, principal: &str) {
    for (system, identifier) in [("account", account), ("native-principal", principal)] {
        sqlx::query(
            "INSERT INTO bindings (record_id, system, identifier, is_canonical)
             VALUES (?, ?, ?, 1)",
        )
        .bind(person)
        .bind(system)
        .bind(identifier)
        .execute(&crate::common::fixture_write_pool(db).await)
        .await
        .unwrap();
    }
}

/// A `native.mdx.v2` artifact with no inputs, modules or capability requests.
const MDX_SOURCE: &str = r#"export const nativeArtifact = { schema: "native.mdx.artifact.v2", inputs: {}, module_inputs: {}, capability_requests: [] }

<Metric label="Current" value={1} />"#;

/// Ids the call plan refers to.
struct Ids {
    owner: String,
    member: String,
    /// A record the member can see, with facets, a link and an attachment.
    shared: String,
    /// A second visible record (link target, task).
    task: String,
    /// A record only the owner can see, written to repeatedly so the member's
    /// visible log has gaps.
    hidden: String,
    /// A collection holding `shared`.
    folder: String,
    /// An event the member can see, and one it cannot.
    visible_event: String,
    hidden_event: String,
    /// `local_seq` of the first event of `shared`.
    shared_first_seq: i64,
    /// A visible note used as `save_account`'s declared source, with the exact
    /// body-revision events of itself and `shared` (M4).
    source: String,
    shared_body_revision: String,
    source_body_revision: String,
    attachment: String,
    conversation: String,
    message: String,
    canvas: String,
    unowned: String,
    /// A visible `native.mdx.v2` artifact, so `render_artifact` reaches its
    /// success path (M2).
    mdx: String,
    /// Sealed HCP histories, interleaved across accounts; never fake facets.
    audit_entry: String,
    owner_audit_entry: String,
    owner_audit_cursor: String,
}

async fn fixture() -> (Fixture, Ids) {
    let db = create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_builtin_tools(&mut registry).unwrap();
    register_surface_tools(&mut registry).unwrap();
    // The config seam requires a canonical principal. Keep the existing
    // legacy member probes and exercise this seam as a normally onboarded
    // non-owner, never a synthetic account binding.
    let arrival = HostedMembershipArrival::new(
        HostedMembershipRole::Member,
        HostedMembershipSource::Direct,
        "2026-10-10T00:00:00Z".into(),
    )
    .unwrap();
    let config_account = reconcile_hosted_identity(
        &db,
        "counter-config@example.test",
        "counter-config-member",
        &arrival,
        None,
    )
    .await
    .unwrap();
    let fx = Fixture {
        db,
        registry,
        config_account,
    };
    owner_call(
        &fx,
        "manage_record_policy",
        json!({"action":"grant",
        "record_id":native_ce::schema::UNFILED_RECORD_ID,
        "subject":{"kind":"account","account_id":fx.config_account},
        "capability":"edit","reason":"Counter probe may file preferences."}),
    )
    .await;
    let kind = propose_value_with_kind_metadata_as(
        &fx.db,
        "kind:Configuration",
        "focus_preferences",
        None,
        0.0,
        VocabularyValueTerminality::Open,
        Some(KindMetadataV1::legacy("Configuration", "focus_preferences")),
        None,
    )
    .await
    .unwrap();
    promote_value(&fx.db, &kind).await.unwrap();
    let shape: Value = serde_json::from_str(include_str!(
        "../../src/mcp/tools/account_config/preferences-shape.json"
    ))
    .unwrap();
    write_user_schema_config(&fx.db,
        json!({"shapes":{"Configuration:focus_preferences":{"facets":{"focus.preferences":shape}}}}),
        SchemaConfigOptions::default()).await.unwrap();

    // `render_artifact`'s mdx v2 success path needs the process-wide HTML
    // runtime origins. The same test-local values `alpha_tabs` installs for
    // this binary, so the call is idempotent across parallel tests (M2).
    native_ce::artifact_html::configure(
        native_ce::artifact_html::RuntimeConfig::new(
            "http://localhost:8080",
            "http://artifact.localhost:8080",
        )
        .expect("counter guard HTML runtime configuration"),
    );

    // Start the workspace log at a distinctive, large head so the decimal head
    // an error may echo cannot collide with a limit, port or timestamp in the
    // text (H1). `content_events.seq` is `AUTOINCREMENT`, so seeding its
    // `sqlite_sequence` row before the first write makes the following insert
    // take 7_340_312 and the head stay seven digits for the whole fixture.
    // Clear any row the migrations may already have written first: a duplicate
    // `sqlite_sequence` entry is not unique and the lower one can win.
    let write_pool = crate::common::fixture_write_pool(&fx.db).await;
    for statement in [
        "DELETE FROM sqlite_sequence WHERE name = 'content_events'",
        "INSERT INTO sqlite_sequence (name, seq) VALUES ('content_events', 7340311)",
    ] {
        sqlx::query(statement).execute(&write_pool).await.unwrap();
    }

    let create = |arguments: Value| {
        let fx = &fx;
        async move {
            let mut arguments = arguments;
            arguments
                .as_object_mut()
                .unwrap()
                .entry("reason")
                .or_insert_with(|| json!("counter guard fixture"));
            owner_call(fx, "create_record", arguments).await["id"]
                .as_str()
                .unwrap()
                .to_string()
        }
    };
    let owner = create(json!({ "type": "Entity", "kind": "person", "name": "Olive Owner" })).await;
    let member_person =
        create(json!({ "type": "Entity", "kind": "person", "name": "Mabel Member" })).await;
    bind_account(&fx.db, &owner, "acct:owner", "native/olive-owner").await;
    bind_account(&fx.db, &member_person, "acct:member", "native/mabel-member").await;

    let folder =
        create(json!({ "type": "Collection", "kind": "folder", "name": "Shared folder" })).await;
    let shared = create(json!({
        "type": "Document", "kind": "note", "name": "Shared plan",
        "body": "A plan the whole workspace can read.",
        "home_id": folder, "owner_id": owner,
        "facets": { "status": "draft" }
    }))
    .await;
    let task = create(json!({
        "type": "WorkItem", "kind": "task", "name": "Shared task",
        "home_id": folder, "owner_id": owner
    }))
    .await;
    let hidden = create(json!({
        "type": "Document", "kind": "note", "name": "Owner private notes",
        "body": "Only the owner may read this.", "owner_id": owner
    }))
    .await;
    replace_explicit_policy(
        &fx.db,
        "test:policy",
        &hidden,
        vec![AllowEntry::account("acct:owner", Capability::Manage)],
    )
    .await
    .unwrap();

    // Hidden activity interleaved with visible activity: the member's view of
    // the log must have gaps a counter would reveal.
    for round in 0..3 {
        owner_call(
            &fx,
            "update_record",
            json!({
                "id": hidden,
                "body_append": format!("\nprivate round {round}"),
                "reason": "hidden activity"
            }),
        )
        .await;
        owner_call(
            &fx,
            "update_record",
            json!({
                "id": shared,
                "body_append": format!("\nvisible round {round}"),
                "reason": "visible activity"
            }),
        )
        .await;
    }
    owner_call(
        &fx,
        "manage_links",
        json!({ "action": "add", "source_id": shared, "target_id": task, "relationship": "relates_to" }),
    )
    .await;
    let attachment = owner_call(
        &fx,
        "attach_text",
        json!({ "record_id": shared, "text": "attached words", "filename": "notes.txt" }),
    )
    .await;
    let attachment_id = attachment["attachment_id"]
        .as_str()
        .or_else(|| attachment["id"].as_str())
        .unwrap_or_default()
        .to_string();
    let conversation = fx
        .registry
        .call(
            fx.db.clone(),
            Caller::authenticated("acct:owner"),
            "manage_messages",
            json!({
                "action": "send",
                "body": "hello from the owner",
                "origin": { "type": "direct", "participant_ids": [owner, member_person] },
                "addressed_to": [member_person],
                "expectation": "none",
                "idempotency_key": "counter-guard-owner-hello",
                "reason": "counter guard fixture"
            }),
        )
        .await
        .unwrap();
    if std::env::var("COUNTER_GUARD_VERBOSE").is_ok() {
        eprintln!("SEND RESPONSE {conversation}");
    }
    let message = conversation["id"].as_str().unwrap_or_default().to_string();
    let conversation = conversation["conversation_id"]
        .as_str()
        .or_else(|| conversation["id"].as_str())
        .unwrap_or_default()
        .to_string();

    let event_of = |record: String| {
        let db = fx.db.clone();
        async move {
            sqlx::query_scalar::<_, String>(
                "SELECT id FROM content_events WHERE record_id = ? ORDER BY seq DESC LIMIT 1",
            )
            .bind(record)
            .fetch_one(db.pool())
            .await
            .unwrap()
        }
    };
    let unowned = create(json!({
        "type": "Document", "kind": "note", "name": "Nobody owns this", "home_id": folder
    }))
    .await;
    let canvas = create(json!({
        "type": "Document", "kind": "canvas", "name": "Sprint sketch", "owner_id": owner
    }))
    .await;
    // The smallest mdx v2 artifact that renders with only the HTML runtime
    // origins configured: no inputs, modules or capability requests (M2).
    let mdx = create(json!({
        "type": "Document", "kind": "artifact", "name": "Guard metric",
        "body": MDX_SOURCE, "owner_id": owner,
        "facets": { "runtime": "native.mdx.v2" }
    }))
    .await;
    owner_call(
        &fx,
        "manage_canvas",
        json!({
            "action": "commit_batch",
            "batch": {
                "version": "native.canvas-batch.v1",
                "canvas_id": canvas,
                "batch_id": "guard-b1",
                "origin": { "kind": "agent" },
                "ops": [{ "op": "create", "object": {
                    "id": "n1", "kind": "note", "x": 0.0, "y": 20, "w": 200, "h": 120, "z": "an1",
                    "props": { "text": "hello", "color": "yellow" }
                }}]
            }
        }),
    )
    .await;
    let visible_event = event_of(shared.clone()).await;
    let hidden_event = event_of(hidden.clone()).await;
    let source = create(json!({
        "type": "Document", "kind": "note", "name": "Account source",
        "body": "The premise this account rests on.", "owner_id": owner
    }))
    .await;
    let shared_body_revision = current_record_body_revision(&fx.db, &shared)
        .await
        .unwrap()
        .revision_event_id;
    let source_body_revision = current_record_body_revision(&fx.db, &source)
        .await
        .unwrap()
        .revision_event_id;
    let shared_first_seq: i64 =
        sqlx::query_scalar("SELECT MIN(seq) FROM content_events WHERE record_id = ?")
            .bind(&shared)
            .fetch_one(fx.db.pool())
            .await
            .unwrap();

    crate::common::govern_kind(&fx.db, "Resolution", "hcp_entry").await;
    let mut hcp = ToolRegistry::new();
    register_hcp_v2_tools(&mut hcp, PseudonymKey::from_secret(&[0x42; 32]).unwrap()).unwrap();
    let mut entries = Vec::new();
    // Member -> owner -> member makes a global position disclose hidden work.
    for (who, preference) in [
        (member(), "Member audit first"),
        (Caller::authenticated("acct:owner"), "Owner audit private"),
        (member(), "Member audit last"),
    ] {
        let frame = hcp
            .call(
                fx.db.clone(),
                who.with_oauth_client_id(Some("counter-audit-client".into())),
                ADD_PREFERENCE,
                json!({"category":"general_preferences", "preference":preference,
                "declarationType":"user-declared", "sourceContext":"counter-guard"}),
            )
            .await
            .unwrap();
        assert_eq!(frame["isError"], false, "{frame}");
        entries.push(
            frame["structuredContent"]["id"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
    }
    let owners = fx
        .registry
        .call(
            fx.db.clone(),
            Caller::authenticated("acct:owner"),
            "read_hcp_audit",
            json!({}),
        )
        .await
        .unwrap();
    let owner_audit_cursor = owners["events"][0]["eventId"].as_str().unwrap().to_owned();
    let ids = Ids {
        audit_entry: entries[0].clone(),
        owner_audit_entry: entries[1].clone(),
        owner_audit_cursor,
        owner,
        member: member_person,
        shared,
        task,
        hidden,
        folder,
        visible_event,
        hidden_event,
        shared_first_seq,
        source,
        shared_body_revision,
        source_body_revision,
        attachment: attachment_id,
        conversation,
        message,
        canvas,
        unowned,
        mdx,
    };
    (fx, ids)
}

// ---------------------------------------------------------------------------
// The call plan.
// ---------------------------------------------------------------------------

/// Replace whole-string placeholders (`$created`, `$run_key`) in `arguments`
/// with values learned from earlier calls in the plan.
fn substitute(arguments: Value, values: &[(&str, &str)]) -> Value {
    match arguments {
        Value::String(text) => match values.iter().find(|(name, _)| *name == text) {
            Some((_, value)) => Value::String((*value).to_string()),
            None => Value::String(text),
        },
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(|item| substitute(item, values))
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| (key, substitute(value, values)))
                .collect(),
        ),
        other => other,
    }
}

/// The outcome a planned call must produce. Coverage is per call, not per
/// tool: a tool that has one succeeding call must still declare its failing
/// calls, so a surface that quietly starts erroring cannot hide behind a
/// sibling's success (M4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expected {
    Ok,
    Err,
}

struct Call {
    tool: &'static str,
    arguments: Value,
    expected: Expected,
}

fn call(tool: &'static str, arguments: Value) -> Call {
    Call {
        tool,
        arguments,
        expected: Expected::Ok,
    }
}

fn call_err(tool: &'static str, arguments: Value) -> Call {
    Call {
        tool,
        arguments,
        expected: Expected::Err,
    }
}

/// Read calls first, then representative writes. `too_far` is a number above
/// the workspace head, used to provoke the errors that echo the head.
fn plan(ids: &Ids, too_far: i64) -> Vec<Call> {
    let shared = &ids.shared;
    let hidden = &ids.hidden;
    vec![
        // ---- builtins and orientation
        call("ping", json!({})),
        call("engine_info", json!({})),
        call("bootstrap", json!({})),
        call("quickstart", json!({})),
        call("read_guide", json!({ "topic": "coordination" })),
        call("describe_schema", json!({})),
        call("get_dashboard", json!({})),
        call(
            "get_structure",
            json!({ "root_id": "native:root", "max_depth": 4 }),
        ),
        // ---- record reads
        call(
            "get_record",
            json!({
                "ids": [shared, &ids.task, &ids.folder, hidden],
                "include_history_summary": true,
                "include_comments": true,
                "include_citations": true,
                "include_suggestions": true
            }),
        ),
        call(
            "get_record",
            json!({ "ids": [shared], "as_of": { "content_seq": ids.shared_first_seq } }),
        ),
        call_err(
            "get_record",
            json!({ "ids": [shared], "as_of": { "content_seq": too_far } }),
        ),
        call(
            "resolve_many",
            json!({ "names": ["Shared plan", "Owner private notes"] }),
        ),
        call("render_record", json!({ "id": shared })),
        call_err("render_record", json!({ "id": hidden })),
        call("get_reuse_context", json!({ "record_id": shared })),
        call("open_collection", json!({ "id": &ids.folder })),
        // ---- history and activity
        call("read_hcp_audit", json!({})),
        call_err(
            "read_hcp_audit",
            json!({"after_cursor":ids.owner_audit_cursor}),
        ),
        call_err("read_hcp_audit", json!({"account_id":"acct:owner"})),
        call("get_history", json!({ "limit": 50 })),
        call(
            "get_history",
            json!({ "record_id": shared, "detail": "full" }),
        ),
        call_err("get_history", json!({ "record_id": hidden })),
        call("get_history", json!({ "after_local_seq": too_far })),
        call("whats_changed", json!({})),
        call("whats_changed", json!({ "after_local_seq": 0, "limit": 5 })),
        call_err("whats_changed", json!({ "after_local_seq": too_far })),
        call("get_run_activity", json!({})),
        call(
            "get_event_context",
            json!({ "event_id": &ids.visible_event }),
        ),
        call_err(
            "get_event_context",
            json!({ "event_id": &ids.hidden_event }),
        ),
        call(
            "render_record_version_diff",
            json!({ "record_id": shared, "before_seq": ids.shared_first_seq }),
        ),
        call_err(
            "render_record_version_diff",
            json!({ "record_id": shared, "before_seq": too_far }),
        ),
        call("read_attributions", json!({ "bearer_id": &ids.owner })),
        // ---- querying
        call("search", json!({ "query": "plan" })),
        call("scan", json!({ "query": "plan" })),
        call(
            "query_record",
            json!({ "steps": [{ "step": "filter", "types": ["Document"] }] }),
        ),
        call(
            "query_record",
            json!({
                "steps": [{ "step": "filter", "types": ["Document"] }],
                "activity": { "actions": { "any": [{ "kind": "event", "event_types": ["record.updated"] }] }, "limit": 5 }
            }),
        ),
        call_err(
            "query_record",
            json!({
                "steps": [{ "step": "filter", "types": ["Document"] }],
                "as_of": { "content_seq": too_far }
            }),
        ),
        call(
            "query_record",
            json!({
                "steps": [{ "step": "filter", "types": ["Document"] }],
                "include_coordination": true
            }),
        ),
        call(
            "query_sql",
            json!({ "sql": "SELECT id, name FROM records ORDER BY name LIMIT 5" }),
        ),
        call(
            "query_sql",
            json!({ "sql": "SELECT local_seq, record_id FROM content_events ORDER BY local_seq DESC LIMIT 3" }),
        ),
        call("get_workspace_snapshot", json!({ "action": "open" })),
        call("resolve_facets", json!({ "record_id": shared })),
        call(
            "suggest_facet_values",
            json!({ "facet_key": "status", "type": "Document" }),
        ),
        call_err(
            "resolve_rollup",
            json!({ "rollup_name": "child_count", "record_id": &ids.folder }),
        ),
        call(
            "manage_facet_observations",
            json!({ "action": "list", "record_id": shared, "key": "status" }),
        ),
        // ---- links, attachments, relationships, citations
        call(
            "manage_links",
            json!({ "action": "list", "record_id": shared }),
        ),
        call(
            "manage_relationships",
            json!({ "action": "find", "endpoint_record_id": shared }),
        ),
        call(
            "manage_attachments",
            json!({ "action": "list", "record_id": shared }),
        ),
        call(
            "manage_attachments",
            json!({ "action": "inspect", "attachment_id": &ids.attachment }),
        ),
        call(
            "read_attachment",
            json!({ "attachment_id": &ids.attachment }),
        ),
        call_err(
            "resolve_citation",
            json!({ "citation_id": "00000000-0000-4000-8000-000000000001" }),
        ),
        call("render_suggestion_review", json!({ "id": shared })),
        // ---- messaging
        call("manage_messages", json!({ "action": "list_inbox" })),
        call(
            "manage_messages",
            json!({ "action": "list_my_conversations" }),
        ),
        call("manage_messages", json!({ "action": "list_unclassified" })),
        call("manage_messages", json!({ "action": "list_destinations" })),
        call("manage_messages", json!({ "action": "get_attention" })),
        call(
            "manage_messages",
            json!({ "action": "list_notification_candidates" }),
        ),
        call(
            "manage_messages",
            json!({ "action": "list_conversation", "conversation_id": &ids.conversation }),
        ),
        call(
            "manage_messages",
            json!({ "action": "list_message_state", "message_ids": [&ids.message] }),
        ),
        call(
            "manage_messages",
            json!({ "action": "list_context", "origin": { "type": "collection", "collection_id": &ids.folder } }),
        ),
        call_err(
            "manage_messages",
            json!({ "action": "share_history", "recipient_id": &ids.owner, "conversation_id": &ids.conversation, "snapshot_seq": too_far, "reason": "counter guard probe" }),
        ),
        // ---- governance and configuration reads
        call(
            "manage_bindings",
            json!({ "action": "list", "record_id": &ids.member }),
        ),
        call(
            "manage_bindings",
            json!({ "action": "observations", "record_id": &ids.member }),
        ),
        call(
            "manage_record_policy",
            json!({ "action": "inspect", "record_id": shared }),
        ),
        call_err(
            "manage_record_policy",
            json!({ "action": "list", "record_id": &ids.folder }),
        ),
        call("manage_instructions", json!({ "action": "list" })),
        call_err("manage_onboarding", json!({ "action": "list_programmes" })),
        call("manage_participants", json!({ "action": "list" })),
        call("manage_interventions", json!({ "action": "query" })),
        call(
            "manage_vocabularies",
            json!({ "action": "list_values", "vocabulary": "kind:Document" }),
        ),
        call("manage_schema_config", json!({ "action": "read" })),
        call(
            "preview_record_shape",
            json!({ "type": "Document", "kind": "note" }),
        ),
        call(
            "manage_surface_bindings",
            json!({ "action": "list", "surface": "home" }),
        ),
        call("manage_alpha_tabs", json!({ "action": "list" })),
        call(
            "manage_account_config",
            json!({"action":"inspect","kind":"focus_preferences"}),
        ),
        call(
            "manage_account_config",
            json!({"action":"ensure","kind":"focus_preferences",
            "reason":"Counter probe provisions private preferences."}),
        ),
        call(
            "manage_account_config",
            json!({"action":"inspect","kind":"focus_preferences"}),
        ),
        call(
            "manage_account_config",
            json!({"action":"ensure","kind":"focus_preferences",
            "reason":"Counter probe reads the existing winner."}),
        ),
        call(
            "manage_account_config",
            json!({"action":"replace","kind":"focus_preferences",
            "expected_record_id":"$preferences","reason":"Counter probe refuses healthy replacement."}),
        ),
        call_err(
            "manage_named_views",
            json!({"action":"get_view_revision","view_id":"native.named-view:bearer","revision_id":"revision"}),
        ),
        call_err(
            "manage_named_views",
            json!({"action":"list_view_revisions","view_id":"native.named-view:bearer"}),
        ),
        call_err(
            "manage_named_views",
            json!({"action":"record_view_revision","id":ids.shared,"definition":{},"idempotency_key":"counter-draft"}),
        ),
        call_err(
            "manage_named_views",
            json!({"action":"activate_view","id":ids.shared,"pin":{},"name":"view_counter","expected_binding_event_id":null,"idempotency_key":"counter-publish"}),
        ),
        call_err(
            "manage_named_views",
            json!({"action":"unpublish_view","id":ids.shared,"expected_binding_event_id":null,"idempotency_key":"counter-unpublish"}),
        ),
        call_err(
            "manage_named_views",
            json!({"action":"prepare_named_views"}),
        ),
        call("query_change_summaries", json!({ "action": "list" })),
        call(
            "manage_renderer_binding",
            json!({ "action": "read", "artifact_id": &ids.mdx }),
        ),
        call(
            "manage_artifact_inputs",
            json!({ "action": "read", "artifact_id": &ids.mdx }),
        ),
        call(
            "manage_artifact_module_grants",
            json!({ "action": "read", "artifact_id": &ids.mdx }),
        ),
        call_err(
            "manage_mdx_modules",
            json!({ "action": "inspect", "module_id": shared }),
        ),
        call("render_artifact", json!({ "id": shared })),
        call("render_artifact", json!({ "id": &ids.mdx })),
        call("verify_artifact", json!({ "id": shared })),
        call(
            "read_canvas",
            json!({ "action": "get_scene", "canvas_id": &ids.canvas }),
        ),
        call(
            "read_canvas",
            json!({ "action": "changes", "canvas_id": &ids.canvas, "after": "canvas:0" }),
        ),
        call(
            "read_canvas",
            json!({ "action": "describe", "canvas_id": &ids.canvas }),
        ),
        call(
            "read_canvas",
            json!({ "action": "export", "canvas_id": &ids.canvas }),
        ),
        // ---- run bookkeeping
        call(
            "set_intent",
            json!({ "intent": "counter guard", "run_key": "$run_key" }),
        ),
        call("close_run", json!({ "run_key": "$run_key" })),
        // ---- representative writes (one per response family)
        call(
            "create_record",
            json!({
                "type": "Document", "kind": "note", "name": "Member note",
                "body": "written by the member", "home_id": &ids.folder,
                "reason": "counter guard write"
            }),
        ),
        call(
            "update_record",
            json!({ "id": shared, "name": "Shared plan v2", "reason": "counter guard write" }),
        ),
        call(
            "archive_record",
            json!({ "id": "$created", "archived": true, "reason": "counter guard write" }),
        ),
        call(
            "archive_record",
            json!({ "id": "$created", "archived": false, "reason": "counter guard write" }),
        ),
        call(
            "manage_links",
            json!({ "action": "remove", "source_id": shared, "target_id": &ids.task, "relationship": "relates_to" }),
        ),
        call(
            "manage_links",
            json!({ "action": "add", "source_id": shared, "target_id": &ids.task, "relationship": "relates_to" }),
        ),
        call(
            "attach_text",
            json!({ "record_id": shared, "text": "member words", "filename": "member.txt" }),
        ),
        // Keyed replays take a different `act` path from the first write
        // (`attachments.rs`, `messaging.rs`): the second call must not carry
        // an act to the member either.
        call(
            "attach_text",
            json!({
                "record_id": shared, "text": "keyed member words", "filename": "keyed.txt",
                "idempotency_key": "counter-guard-keyed-attach"
            }),
        ),
        call(
            "attach_text",
            json!({
                "record_id": shared, "text": "keyed member words", "filename": "keyed.txt",
                "idempotency_key": "counter-guard-keyed-attach"
            }),
        ),
        call(
            "manage_facet_observations",
            json!({
                "action": "set", "record_id": shared, "key": "priority", "value": "high",
                "as_of": "2026-10-01T00:00:00Z", "reason": "counter guard write"
            }),
        ),
        call(
            "start_work",
            json!({ "record_id": &ids.task, "action": "claim" }),
        ),
        call(
            "start_work",
            json!({ "record_id": &ids.task, "action": "release" }),
        ),
        call(
            "manage_messages",
            json!({
                "action": "send", "body": "hello from the member",
                "origin": { "type": "direct", "participant_ids": [&ids.owner, &ids.member] },
                "addressed_to": [&ids.owner],
                "expectation": "none",
                "idempotency_key": "counter-guard-member-hello",
                "reason": "counter guard write"
            }),
        ),
        call(
            "manage_messages",
            json!({
                "action": "send", "body": "hello from the member",
                "origin": { "type": "direct", "participant_ids": [&ids.owner, &ids.member] },
                "addressed_to": [&ids.owner],
                "expectation": "none",
                "idempotency_key": "counter-guard-member-hello",
                "reason": "counter guard write"
            }),
        ),
        call(
            "create_many",
            json!({
                "reason": "counter guard write",
                "records": [
                    { "type": "Document", "kind": "note", "name": "Batch one", "home_id": &ids.folder },
                    { "type": "Document", "kind": "note", "name": "Batch two", "home_id": &ids.folder }
                ]
            }),
        ),
        // create_many verbose nests each item's create receipt at
        // `results[].record` (S2a position).
        call(
            "create_many",
            json!({
                "reason": "counter guard write",
                "response_mode": "verbose",
                "records": [
                    { "type": "Document", "kind": "note", "name": "Verbose one", "home_id": &ids.folder }
                ]
            }),
        ),
        // Direct act sites (not `echo_act`): identity, binding and artifact copy.
        call(
            "resolve_external",
            json!({
                "bindings": [{ "system": "native-principal", "identifier": "native/guard-external" }],
                "hints": { "record_type": "Entity", "kind": "person", "name": "Guard External" },
                "reason": "counter guard write"
            }),
        ),
        call(
            "observe_external",
            json!({
                "bindings": [{ "system": "native-principal", "identifier": "native/guard-observed" }],
                "source_binding": { "system": "native-principal", "identifier": "native/guard-observed" },
                "hints": { "record_type": "Entity", "kind": "person", "name": "Guard Observed" },
                "quality": "reported",
                "materialization_policy": "identity_only",
                "as_of": null,
                "provenance": {
                    "freshness": "unknown", "retention_state": "none",
                    "source_availability": "unknown", "refresh_outcome": "not_attempted"
                },
                "display_name": "Guard Observed",
                "snapshot_base64": null,
                "snapshot_mime": null,
                "snapshot_filename": null,
                "reason": "counter guard write"
            }),
        ),
        call(
            "manage_bindings",
            json!({
                "action": "add", "record_id": "$external",
                "binding": { "system": "native-principal", "identifier": "native/guard-external-alias" },
                "reason": "counter guard write"
            }),
        ),
        call(
            "instantiate_artifact",
            json!({ "source_id": &ids.mdx, "title": "Guard metric copy" }),
        ),
        call(
            "batch_write",
            json!({
                "reason": "counter guard write",
                "items": [
                    { "op": "update", "id": "$created", "name": "Member note renamed" },
                    { "op": "update", "id": &ids.task, "name": "Shared task renamed" }
                ]
            }),
        ),
        call_err(
            "claim_unowned_record",
            json!({ "record_id": &ids.unowned, "reason": "counter guard write" }),
        ),
        call_err(
            "correct_record_type",
            json!({
                "record_id": "$created", "target_type": "Document", "target_kind": "reference",
                "reason": "counter guard write"
            }),
        ),
        call(
            "save_account",
            json!({
                "record_id": shared,
                "expected_revision_event_id": &ids.shared_body_revision,
                "body": "saved account body",
                "sources": [{
                    "record_id": &ids.source,
                    "revision_event_id": &ids.source_body_revision,
                    "role": "Reviewed premise",
                    "reason": "counter guard"
                }],
                "idempotency_key": "counter-guard-save-account",
                "reason": "counter guard write"
            }),
        ),
        call(
            "manage_canvas",
            json!({
                "action": "commit_batch",
                "batch": {
                    "version": "native.canvas-batch.v1",
                    "canvas_id": &ids.canvas,
                    "batch_id": "guard-member-b1",
                    "origin": { "kind": "agent" },
                    "ops": [{ "op": "create", "object": {
                        "id": "n2", "kind": "note", "x": 5.0, "y": 20, "w": 200, "h": 120, "z": "an2",
                        "props": { "text": "member note", "color": "blue" }
                    }}]
                }
            }),
        ),
        call(
            "delete_record",
            json!({ "id": "$created", "reason": "counter guard write" }),
        ),
    ]
}

// ---------------------------------------------------------------------------
// The guard.
// ---------------------------------------------------------------------------

/// Run the whole plan as the member and return what was observed, how each
/// tool's calls fared (for the coverage report), and any per-call outcome
/// mismatch (a call that returned the opposite of its declared `Expected`).
async fn run_plan() -> (
    Observed,
    BTreeMap<String, (usize, usize)>,
    Vec<String>,
    Fixture,
) {
    assert!(
        !member().counter_footing().is_owner(),
        "the guard must run as a non-owner"
    );
    let (fx, ids) = fixture().await;
    let too_far = head(&fx.db).await + 1_000;
    let mut observed = Observed::new();
    let mut outcomes: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut call_problems = Vec::new();
    let mut created = String::new();
    let mut run_key = String::new();
    let mut external = String::new();
    let mut preferences = String::new();
    for planned in plan(&ids, too_far) {
        let arguments = substitute(
            planned.arguments.clone(),
            &[
                ("$created", &created),
                ("$run_key", &run_key),
                ("$external", &external),
                ("$preferences", &preferences),
            ],
        );
        let head_before = head(&fx.db).await;
        let caller = if planned.tool == "manage_account_config" {
            Caller::authenticated(&fx.config_account)
                .with_hosting_context("host:config-member", "db:test")
                .with_hosting_owner(false)
                .with_hosting_member(true)
        } else {
            member()
        };
        assert!(!caller.counter_footing().is_owner());
        let result = fx
            .registry
            .call(fx.db.clone(), caller, planned.tool, arguments)
            .await;
        let head_after = head(&fx.db).await;
        let entry = outcomes.entry(planned.tool.to_string()).or_default();
        match result {
            Ok(response) => {
                entry.0 += 1;
                if planned.expected == Expected::Err {
                    call_problems.push(format!("{} expected Err but returned Ok", planned.tool));
                }
                if planned.tool == "read_hcp_audit" {
                    let events = response["events"].as_array().unwrap();
                    assert_eq!(events.len(), 2, "exercise non-empty success");
                    assert_eq!(events[0]["entryId"], ids.audit_entry);
                    assert!(events.iter().all(|e| e["entryId"] != ids.owner_audit_entry));
                    assert!(find_counters(&response).is_empty());
                    assert_eq!(head_before, head_after);
                }
                if planned.tool == "create_record" {
                    created = response["id"].as_str().unwrap_or_default().to_string();
                }
                if planned.tool == "manage_account_config" {
                    match planned.arguments["action"].as_str().unwrap() {
                        "inspect" => {
                            assert_eq!(response["outcome"], "inspected");
                            assert_eq!(head_before, head_after);
                        }
                        "ensure" => {
                            assert_eq!(response["status"], "healthy");
                            if preferences.is_empty() {
                                assert_eq!(response["outcome"], "created");
                                assert_eq!(response["created"], true);
                            } else {
                                assert_eq!(response["outcome"], "existing");
                                assert_eq!(response["created"], false);
                                assert_eq!(response["record_id"], preferences);
                                assert_eq!(head_before, head_after);
                            }
                        }
                        "replace" => {
                            assert_eq!(response["outcome"], "refused");
                            assert_eq!(response["refusal"], "not_unusable");
                            assert_eq!(head_before, head_after);
                        }
                        _ => unreachable!(),
                    }
                    if let Some(id) = response["record_id"].as_str() {
                        preferences = id.to_owned();
                    }
                }
                if planned.tool == "resolve_external" {
                    external = response["record_id"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string();
                }
                if planned.tool == "bootstrap" {
                    run_key = response["run"]["run_key"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string();
                }
                observe(planned.tool, &response, &mut observed);
            }
            Err(error) => {
                entry.1 += 1;
                if planned.expected == Expected::Ok {
                    call_problems.push(format!(
                        "{} expected Ok but returned Err: {error}",
                        planned.tool
                    ));
                }
                let text = error.to_string();
                if text_names_head(&text, head_before) || text_names_head(&text, head_after) {
                    observed.insert((planned.tool.to_string(), ERROR_PATH.to_string()));
                }
                if std::env::var("COUNTER_GUARD_VERBOSE").is_ok() {
                    eprintln!("ERR {} {}: {}", planned.tool, planned.arguments, text);
                }
            }
        }
    }
    (observed, outcomes, call_problems, fx)
}

/// Authorization owner for the per-person audit operation: successful private
/// reads and uniform foreign/unknown cursor denials, through production dispatch.
#[tokio::test]
async fn hcp_audit_non_owner_reads_only_own_events_and_refuses_foreign_cursors() {
    let (fx, ids) = fixture().await;
    let before = head(&fx.db).await;
    let read =
        |who: Caller, args: Value| fx.registry.call(fx.db.clone(), who, "read_hcp_audit", args);
    let own = read(member(), json!({"limit":1})).await.unwrap();
    assert_eq!(own["events"][0]["entryId"], ids.audit_entry);
    assert_eq!(own["next_cursor"], own["events"][0]["eventId"]);
    assert_eq!(own["has_more"], true);
    let last = read(member(), json!({"after_cursor":own["next_cursor"]}))
        .await
        .unwrap();
    assert_eq!(last["events"].as_array().unwrap().len(), 1);
    assert_ne!(last["events"][0]["entryId"], ids.owner_audit_entry);
    let owner = read(Caller::authenticated("acct:owner"), json!({}))
        .await
        .unwrap();
    assert_eq!(owner["events"].as_array().unwrap().len(), 1);
    assert_eq!(owner["events"][0]["entryId"], ids.owner_audit_entry);
    let empty = read(Caller::authenticated("acct:no-hcp-history"), json!({}))
        .await
        .unwrap();
    assert_eq!(empty["events"], json!([]));
    for response in [&own, &last, &owner, &empty] {
        assert!(find_counters(response).is_empty(), "{response}");
    }
    for cursor in [
        ids.owner_audit_cursor.as_str(),
        "urn:uuid:00000000-0000-4000-8000-000000000001",
        "invalid-cursor",
    ] {
        let error = read(member(), json!({"after_cursor":cursor}))
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(error, "invalid HCP audit cursor");
        assert!(!text_names_head(&error, before));
    }
    assert!(read(member(), json!({"account_id":"acct:owner"}))
        .await
        .is_err());
    assert_eq!(
        head(&fx.db).await,
        before,
        "audit and denials are read-only"
    );
}

#[tokio::test]
async fn non_owner_responses_carry_no_unlisted_counter() {
    let (observed, outcomes, call_problems, fx) = run_plan().await;
    if std::env::var("COUNTER_GUARD_VERBOSE").is_ok() {
        for (tool, path) in &observed {
            eprintln!("HIT {tool} {path}");
        }
        for (tool, (ok, err)) in &outcomes {
            eprintln!("OUTCOME {tool} ok={ok} err={err}");
        }
    }
    let mut problems = call_problems;
    problems.extend(verdict(&observed, ALLOWLIST));
    assert!(problems.is_empty(), "\n{}\n", problems.join("\n"));
    drop(fx);
}

#[test]
fn an_unlisted_counter_key_fails_the_guard() {
    let mut observed = Observed::new();
    observe(
        "get_record",
        &json!({ "records": [{ "id": "x", "head_act": 9 }], "frontier": ["a"] }),
        &mut observed,
    );
    let problems = verdict(&observed, &[]);
    assert_eq!(
        problems,
        vec![
            "NEW counter for a non-owner: get_record $.frontier".to_string(),
            "NEW counter for a non-owner: get_record $.records[].head_act".to_string(),
        ]
    );
}

#[test]
fn an_unlisted_counter_value_fails_the_guard() {
    let mut observed = Observed::new();
    observe(
        "get_record",
        &json!({ "records": [{ "version": "rec:12" }] }),
        &mut observed,
    );
    let problems = verdict(&observed, &[]);
    assert_eq!(
        problems,
        vec!["NEW counter for a non-owner: get_record $.records[].version".to_string()]
    );
}

#[test]
fn a_listed_counter_passes_and_a_stale_entry_fails() {
    let list = [("get_record", "$.records[].version", Slice::S6)];
    let mut observed = Observed::new();
    observe(
        "get_record",
        &json!({ "records": [{ "version": "rec:12" }] }),
        &mut observed,
    );
    assert!(verdict(&observed, &list).is_empty());

    let stale = verdict(&Observed::new(), &list);
    assert_eq!(
        stale,
        vec![
            "STALE allowlist entry (no longer occurs; delete it): get_record $.records[].version"
                .to_string()
        ]
    );
}

/// Every registered tool is called or explicitly excused, no read tool is
/// excused, and a tool whose success path is unreached is an explicit gap.
#[tokio::test]
async fn every_registered_tool_is_covered() {
    let (_observed, outcomes, call_problems, fx) = run_plan().await;
    let excused: BTreeMap<&str, &str> = NOT_EXERCISED.iter().copied().collect();
    let error_only: BTreeMap<&str, &str> = ERROR_ONLY.iter().copied().collect();
    let read_gaps: BTreeMap<&str, &str> = READ_SUCCESS_GAPS.iter().copied().collect();
    let mut problems = call_problems;
    for spec in fx.registry.specs() {
        let name = spec.name.as_str();
        let called = outcomes.contains_key(name);
        if called && excused.contains_key(name) {
            problems.push(format!("{name} is called and also listed in NOT_EXERCISED"));
        }
        if !called && !excused.contains_key(name) {
            problems.push(format!(
                "{name} is neither called nor listed in NOT_EXERCISED"
            ));
        }
        let read = spec
            .kind
            .is_some_and(|kind| kind.authoritative_disposition() == AuthoritativeDisposition::Read);
        if read && excused.contains_key(name) {
            problems.push(format!("{name} is a read tool and must be exercised"));
        }
        let gap = error_only.contains_key(name) || read_gaps.contains_key(name);
        if let Some((ok, _)) = outcomes.get(name) {
            if *ok == 0 && !gap {
                problems.push(format!(
                    "{name} never succeeds; fix the call or name its gap in ERROR_ONLY/READ_SUCCESS_GAPS"
                ));
            }
            if *ok > 0 && gap {
                problems.push(format!(
                    "{name} now succeeds; remove it from ERROR_ONLY/READ_SUCCESS_GAPS"
                ));
            }
            // A `Read` tool that only errors must be an explicit gap, never a
            // silent hole behind a sibling action's success.
            if read && *ok == 0 && !read_gaps.contains_key(name) {
                problems.push(format!(
                    "{name} is a read tool whose success path is unreached; name it in READ_SUCCESS_GAPS"
                ));
            }
        }
    }
    let registered: BTreeSet<&str> = fx.registry.specs().map(|spec| spec.name.as_str()).collect();
    for name in excused
        .keys()
        .chain(error_only.keys())
        .chain(read_gaps.keys())
    {
        if !registered.contains(name) {
            problems.push(format!(
                "NOT_EXERCISED/ERROR_ONLY/READ_SUCCESS_GAPS names unregistered tool {name}"
            ));
        }
    }
    assert!(problems.is_empty(), "\n{}\n", problems.join("\n"));
}
