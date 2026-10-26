//! Checks for the Native context tools registered as labelled extensions on the
//! HCP v2 registry: their names and descriptions, that they work there, that no
//! HCP v2 entry is ever read or returned by them, the host's opt-in and client
//! rules, and the lexical fallback without a model key. `/hcp` itself is
//! covered by the existing suites, which run unchanged.

use std::time::Duration;

use serde_json::{json, Value};

use super::claude::{mock, TestModel};
use super::extensions::{
    hcp_v2_extension_descriptors, register_hcp_v2_extensions, EXTENSION_TOOL_NAMES,
    NATIVE_PROPOSE_CONTEXT_ITEM, NATIVE_RESOLVE_CONTEXT_ITEM, NATIVE_SEARCH_CONTEXT,
    NATIVE_TRACE_CONTEXT_ITEM,
};
use super::tests::{alice, caller, onboard};
use crate::db::{create_database, Db};
use crate::mcp::registry::{Caller, ToolRegistry};
use crate::mcp::tools::hcp_v2::{self, PseudonymKey};

/// The distinctive words of the HCP entry every test hides from the extensions.
const ENTRY_TEXT: &str = "I keep a pet axolotl named Quillfeather.";
const ENTRY_WORD: &str = "Quillfeather";

struct Host {
    db: Db,
    /// The HCP v2 registry: the spec tools and the extensions.
    registry: ToolRegistry,
}

fn bob() -> Caller {
    caller("acct:bob", Some("client_bob_app"))
}

async fn manage_vocabularies(db: &Db, arguments: Value) -> Value {
    let mut registry = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::register_surface_tools(&mut registry).unwrap();
    Box::pin(registry.call(
        db.clone(),
        Caller::local(),
        "manage_vocabularies",
        arguments,
    ))
    .await
    .unwrap()
}

/// What a workspace admin does to enable the HCP v2 interface.
async fn enable_hcp_v2(db: &Db) {
    let proposed = manage_vocabularies(
        db,
        json!({
            "action": "propose_value",
            "vocabulary": "kind:Resolution",
            "value": "hcp_entry",
            "gloss": "One entry of a person's Human Context Protocol context.",
            "metadata": {
                "schema_version": 1,
                "provenance_ref": "rec:455149af-2ec6-45ed-b895-f0582e889400",
                "definition": "One entry of a person's Human Context Protocol context: a statement about that person, held as the current version of a grouped-form entry with its provenance and lifecycle.",
                "identity": {
                    "criterion": "Continuity of one HCP entry across its versions; a revision is a new version of the same record.",
                    "dedup": { "mode": "record_id", "keys": [] }
                },
                "declared_capabilities": []
            }
        }),
    )
    .await;
    assert_eq!(proposed["status"], "proposed", "{proposed}");
    let promoted = manage_vocabularies(
        db,
        json!({ "action": "promote_value", "value_id": "vv:voc:kind:Resolution:hcp_entry" }),
    )
    .await;
    assert_eq!(promoted["status"], "active", "{promoted}");
}

async fn host_without_the_kind() -> Host {
    host_at(None).await
}

/// The registry as the HCP host builds it: link origins first, then the tools.
async fn host_at(origin: Option<&str>) -> Host {
    let db = create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    registry.set_public_origin(origin.map(str::to_string));
    hcp_v2::register_hcp_v2_tools(
        &mut registry,
        PseudonymKey::from_secret(&[0x42; 32]).unwrap(),
    )
    .unwrap();
    register_hcp_v2_extensions(&mut registry).unwrap();
    onboard(&db, "acct:alice").await;
    onboard(&db, "acct:bob").await;
    Host { db, registry }
}

/// A workspace whose admin enabled HCP v2 (and not `/hcp` preferences).
async fn host() -> Host {
    let h = host_without_the_kind().await;
    enable_hcp_v2(&h.db).await;
    h
}

impl Host {
    /// The tool's body, as the registry returns it.
    async fn call(&self, who: &Caller, tool: &str, args: Value) -> Value {
        Box::pin(self.registry.call(self.db.clone(), who.clone(), tool, args))
            .await
            .unwrap_or_else(|error| panic!("{tool} failed: {error}"))
    }

    async fn search(&self, task: &str) -> Value {
        self.call(&alice(), NATIVE_SEARCH_CONTEXT, json!({ "task": task }))
            .await
    }

    /// Alice stores an HCP entry through the spec tool, as a client would.
    async fn add_entry(&self, text: &str) -> String {
        let frame = Box::pin(hcp_v2::call_tool(
            &self.registry,
            self.db.clone(),
            alice(),
            hcp_v2::ADD_PREFERENCE,
            json!({
                "category": "general_preferences",
                "preference": text,
                "declarationType": "user-declared",
                "sourceContext": "conversation:test",
            }),
            None,
        ))
        .await
        .expect("a spec tool");
        assert_eq!(frame["isError"], false, "{frame}");
        let record_id = sqlx::query_scalar::<_, String>(
            "SELECT id FROM records WHERE type = 'Resolution' AND kind = 'hcp_entry' \
             ORDER BY created_at DESC LIMIT 1",
        )
        .fetch_one(self.db.pool())
        .await
        .unwrap();
        record_id
    }
}

async fn native(db: &Db, who: &Caller, tool: &str, arguments: Value) -> Value {
    let mut registry = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::register_surface_tools(&mut registry).unwrap();
    Box::pin(registry.call(db.clone(), who.clone(), tool, arguments))
        .await
        .unwrap_or_else(|error| panic!("{tool} failed: {error}"))
}

async fn make(h: &Host, kind: &str, name: &str, body: &str, extra: Value) -> String {
    let mut arguments = json!({
        "type": "Resolution",
        "kind": kind,
        "name": name,
        "body": body,
        "reason": "extension fixture",
        "sources": [],
        // Fixtures deliberately reuse similar names; skip the duplicate gate.
        "confirm": true,
    });
    for (key, value) in extra.as_object().cloned().unwrap_or_default() {
        arguments[key] = value;
    }
    let created = native(&h.db, &alice(), "create_record", arguments).await;
    created["id"].as_str().expect("created").to_string()
}

fn items(body: &Value) -> Vec<Value> {
    body["items"].as_array().cloned().unwrap_or_default()
}

fn mentions(value: &Value, word: &str) -> bool {
    value.to_string().contains(word)
}

// ---- listing ----------------------------------------------------------------

#[test]
fn the_four_context_tools_are_listed_under_native_names() {
    assert_eq!(
        EXTENSION_TOOL_NAMES,
        [
            "native_searchContext",
            "native_traceContextItem",
            "native_proposeContextItem",
            "native_resolveContextItem"
        ]
    );
    let mut registry = ToolRegistry::new();
    hcp_v2::register_hcp_v2_tools(
        &mut registry,
        PseudonymKey::from_secret(&[0x42; 32]).unwrap(),
    )
    .unwrap();
    register_hcp_v2_extensions(&mut registry).unwrap();
    for name in hcp_v2::TOOL_NAMES.iter().chain(EXTENSION_TOOL_NAMES.iter()) {
        assert!(registry.get(name).is_some(), "{name} missing");
    }
    // Registering twice is refused, as for the spec tools.
    assert!(register_hcp_v2_extensions(&mut registry).is_err());
}

#[test]
fn an_extension_cannot_be_mistaken_for_a_spec_tool() {
    for name in EXTENSION_TOOL_NAMES {
        assert!(name.starts_with("native_"), "{name}");
        assert!(!hcp_v2::TOOL_NAMES.contains(&name), "{name}");
        assert!(!name.starts_with("hcp_"), "{name}");
    }
    let descriptors = hcp_v2_extension_descriptors();
    assert_eq!(descriptors.len(), 4);
    for descriptor in &descriptors {
        let description = descriptor["description"].as_str().unwrap();
        assert!(
            description.starts_with("Native extension, not part of HCP:"),
            "{description}"
        );
        // It says what it adds.
        assert!(
            description.contains("shared workspace context"),
            "{description}"
        );
        // Nothing points at a tool this host does not have.
        assert!(
            !mentions(descriptor, "mutatePreferences"),
            "{}",
            descriptor["name"]
        );
        assert_eq!(descriptor["inputSchema"]["type"], "object");
    }
    let by_name = |name: &str| descriptors.iter().find(|d| d["name"] == name).unwrap();
    assert_eq!(
        by_name(NATIVE_SEARCH_CONTEXT)["inputSchema"]["required"],
        json!(["task"])
    );
    assert_eq!(
        by_name(NATIVE_TRACE_CONTEXT_ITEM)["inputSchema"]["required"],
        json!(["ref"])
    );
    for (name, read_only) in [
        (NATIVE_SEARCH_CONTEXT, true),
        (NATIVE_TRACE_CONTEXT_ITEM, true),
        (NATIVE_PROPOSE_CONTEXT_ITEM, false),
        (NATIVE_RESOLVE_CONTEXT_ITEM, false),
    ] {
        assert_eq!(
            by_name(name)["annotations"]["readOnlyHint"],
            read_only,
            "{name}"
        );
    }
}

// ---- they work on this host ---------------------------------------------------

#[tokio::test]
async fn search_and_trace_work_without_any_hcp_preference_setup() {
    let h = host().await;
    let decision = make(
        &h,
        "decision",
        "Wombat policy",
        "We feed wombats on Fridays.",
        json!({}),
    )
    .await;
    let _model = TestModel::not_configured();
    let body = h.search("wombats").await;
    assert_eq!(body["success"], true, "{body}");
    let found = items(&body);
    assert_eq!(found.len(), 1, "{body}");
    assert_eq!(found[0]["title"], "Wombat policy");
    let reference = found[0]["ref"].as_str().unwrap();

    let traced = h
        .call(
            &alice(),
            NATIVE_TRACE_CONTEXT_ITEM,
            json!({ "ref": reference }),
        )
        .await;
    assert_eq!(traced["success"], true, "{traced}");
    assert_eq!(traced["item"]["title"], "Wombat policy");
    assert!(decision.starts_with(reference));
}

#[tokio::test]
async fn propose_and_resolve_work_and_attribute_the_client() {
    let h = host().await;
    let proposed = h
        .call(
            &alice(),
            NATIVE_PROPOSE_CONTEXT_ITEM,
            json!({ "kind": "decision", "statement": "Wombats are fed on Fridays." }),
        )
        .await;
    assert_eq!(proposed["outcome"], "proposed", "{proposed}");
    let reference = proposed["proposal"]["ref"].as_str().unwrap().to_string();

    let traced = h
        .call(
            &alice(),
            NATIVE_TRACE_CONTEXT_ITEM,
            json!({ "ref": reference }),
        )
        .await;
    assert_eq!(traced["item"]["status"], "proposed", "{traced}");
    let revision = traced["item"]["revision"].as_str().unwrap().to_string();

    let resolved = h
        .call(
            &alice(),
            NATIVE_RESOLVE_CONTEXT_ITEM,
            json!({
                "ref": reference, "action": "accept", "expectedRevision": revision,
                "reason": "agreed in the wombat meeting",
            }),
        )
        .await;
    assert_eq!(resolved["outcome"], "accepted", "{resolved}");
    assert_eq!(
        h.call(
            &alice(),
            NATIVE_TRACE_CONTEXT_ITEM,
            json!({ "ref": reference })
        )
        .await["item"]["status"],
        "accepted"
    );
}

#[tokio::test]
async fn record_urls_get_the_deployments_origin() {
    let h = host_at(Some("https://hcp.example.test")).await;
    enable_hcp_v2(&h.db).await;
    make(
        &h,
        "decision",
        "Wombat policy",
        "We feed wombats on Fridays.",
        json!({}),
    )
    .await;
    let _model = TestModel::not_configured();
    let body = h.search("wombats").await;
    let url = items(&body)[0]["url"].as_str().unwrap().to_string();
    assert!(url.starts_with("https://hcp.example.test/"), "{url}");
}

// ---- HCP v2 entries are never read or returned --------------------------------

#[tokio::test]
async fn a_search_never_returns_an_hcp_entry() {
    let h = host().await;
    h.add_entry(ENTRY_TEXT).await;
    make(
        &h,
        "decision",
        "Axolotl husbandry",
        "Axolotls need cool water.",
        json!({}),
    )
    .await;
    let _model = TestModel::not_configured();

    // The entry's own words find nothing of it, and only the ordinary record
    // that shares a word comes back.
    let body = h.search("axolotl Quillfeather").await;
    assert!(!mentions(&body, ENTRY_WORD), "{body}");
    assert!(!mentions(&body, "pet axolotl"), "{body}");
    let titles: Vec<&str> = items(&body)
        .iter()
        .map(|item| item["title"].as_str().unwrap())
        .collect::<Vec<_>>()
        .into_iter()
        .map(|title| {
            if title == "Axolotl husbandry" {
                "Axolotl husbandry"
            } else {
                "other"
            }
        })
        .collect();
    assert_eq!(titles, ["Axolotl husbandry"], "{body}");

    // Asking for entry-shaped kinds does not widen the search.
    let body = h
        .call(
            &alice(),
            NATIVE_SEARCH_CONTEXT,
            json!({ "task": "axolotl", "kinds": ["hcp_entry", "Resolution/hcp_entry"] }),
        )
        .await;
    assert!(items(&body).is_empty(), "{body}");
}

#[tokio::test]
async fn an_hcp_entry_never_reaches_the_ranking_model() {
    let h = host().await;
    h.add_entry(ENTRY_TEXT).await;
    let kept = make(
        &h,
        "decision",
        "Axolotl husbandry",
        "Axolotls need cool water.",
        json!({}),
    )
    .await;
    let server = mock::MockServer::start(
        vec![(
            200,
            mock::ranking_response(&[(kept.as_str(), "water")], "axolotl care"),
        )],
        None,
    )
    .await;
    let _model = TestModel::point_at("test-key", &server.base_url, Duration::from_secs(10));
    let body = h.search("axolotl").await;
    assert_eq!(body["ranking"], "model", "{body}");
    assert_eq!(server.calls(), 1);
    for (_, _, sent) in server.seen() {
        assert!(!mentions(&sent, ENTRY_WORD), "{sent}");
    }
}

#[tokio::test]
async fn an_hcp_entry_cannot_be_traced_by_any_form_of_its_id() {
    let h = host().await;
    let entry = h.add_entry(ENTRY_TEXT).await;
    let missing = h
        .call(
            &alice(),
            NATIVE_TRACE_CONTEXT_ITEM,
            json!({ "ref": "00000000-0000-4000-8000-000000000000" }),
        )
        .await;
    for reference in [entry.clone(), entry[..8].to_string()] {
        let body = h
            .call(
                &alice(),
                NATIVE_TRACE_CONTEXT_ITEM,
                json!({ "ref": reference }),
            )
            .await;
        // Indistinguishable from a record that is not there.
        assert_eq!(body, missing, "{reference}: {body}");
        assert!(!mentions(&body, ENTRY_WORD));
    }
}

#[tokio::test]
async fn records_linked_to_an_hcp_entry_do_not_name_it() {
    let h = host().await;
    let entry = h.add_entry(ENTRY_TEXT).await;
    // An ordinary decision that cites the entry as evidence, has it as
    // its subject and supersedes it.
    let decision = make(
        &h,
        "decision",
        "Axolotl husbandry",
        "Axolotls need cool water.",
        json!({ "links": [
            { "target_id": entry, "relationship": "supersedes" },
            { "target_id": entry, "relationship": "subject" },
            { "target_id": entry, "relationship": "evidence" },
        ] }),
    )
    .await;
    let _model = TestModel::not_configured();
    let body = h.search("axolotl").await;
    assert_eq!(items(&body).len(), 1, "{body}");
    assert!(!mentions(&body, ENTRY_WORD), "{body}");
    assert!(!mentions(&body, &entry), "{body}");

    let traced = h
        .call(
            &alice(),
            NATIVE_TRACE_CONTEXT_ITEM,
            json!({ "ref": decision }),
        )
        .await;
    assert_eq!(traced["success"], true, "{traced}");
    assert!(!mentions(&traced, ENTRY_WORD), "{traced}");
    assert!(!mentions(&traced, &entry), "{traced}");
    assert_eq!(traced["supersession"]["supersedes"], json!([]), "{traced}");
}

#[tokio::test]
async fn nothing_can_be_proposed_against_or_about_an_hcp_entry() {
    let h = host().await;
    let entry = h.add_entry(ENTRY_TEXT).await;
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records")
        .fetch_one(h.db.pool())
        .await
        .unwrap();
    let digest = native(&h.db, &alice(), "get_record", json!({ "ids": [entry] })).await["records"]
        [0]["body_digest"]
        .as_str()
        .unwrap()
        .to_string();

    // A change proposal on the entry is refused exactly as one on a record
    // that is not there.
    let propose_on = |target: String| {
        json!({
            "statement": "I do not keep an axolotl.",
            "target": { "ref": target, "expectedRevision": digest },
        })
    };
    let missing = h
        .call(
            &alice(),
            NATIVE_PROPOSE_CONTEXT_ITEM,
            propose_on("00000000-0000-4000-8000-000000000000".into()),
        )
        .await;
    let refused = h
        .call(
            &alice(),
            NATIVE_PROPOSE_CONTEXT_ITEM,
            propose_on(entry.clone()),
        )
        .await;
    assert_eq!(refused["success"], false, "{refused}");
    assert_eq!(refused, missing);
    assert!(!mentions(&refused, ENTRY_WORD), "{refused}");

    // A new item that names the entry as its subject, scope or evidence.
    for extra in [
        json!({ "subject": entry }),
        json!({ "appliesTo": [entry] }),
        json!({ "evidence": [{ "ref": entry }] }),
    ] {
        let mut arguments = json!({ "kind": "decision", "statement": "Axolotls are lovely." });
        for (key, value) in extra.as_object().unwrap() {
            arguments[key] = value.clone();
        }
        let refused = h
            .call(&alice(), NATIVE_PROPOSE_CONTEXT_ITEM, arguments)
            .await;
        assert_eq!(refused["success"], false, "{refused}");
        assert_eq!(refused["changed"], false, "{refused}");
    }

    // Accepting or superseding it.
    for arguments in [
        json!({
            "ref": entry, "action": "accept", "expectedRevision": digest, "reason": "test",
        }),
        json!({
            "ref": entry, "action": "supersede", "expectedRevision": digest, "reason": "test",
            "replacement": { "ref": entry },
        }),
    ] {
        let refused = h
            .call(&alice(), NATIVE_RESOLVE_CONTEXT_ITEM, arguments)
            .await;
        assert_eq!(refused["success"], false, "{refused}");
        assert_eq!(refused["changed"], false, "{refused}");
    }

    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records")
        .fetch_one(h.db.pool())
        .await
        .unwrap();
    assert_eq!(before, after, "no record was written");
}

#[tokio::test]
async fn a_proposal_on_an_hcp_entry_made_elsewhere_does_not_surface() {
    let h = host().await;
    let entry = h.add_entry(ENTRY_TEXT).await;
    // Someone suggests a change to the entry in Native; it is a suggestion
    // record attached to the entry.
    let digest = native(&h.db, &alice(), "get_record", json!({ "ids": [entry] })).await["records"]
        [0]["body_digest"]
        .as_str()
        .unwrap()
        .to_string();
    native(
        &h.db,
        &alice(),
        "create_record",
        json!({
            "type": "Annotation",
            "kind": "suggestion",
            "lifecycle": "open",
            "body": "Quillfeather should be a salamander.",
            "links": [{ "target_id": entry, "relationship": "part_of" }],
            "facets": { "proposal.precondition": "digest", "anchor.base_digest": digest },
            "reason": "extension fixture",
            "sources": [],
        }),
    )
    .await;
    let _model = TestModel::not_configured();
    let body = h
        .call(
            &alice(),
            NATIVE_SEARCH_CONTEXT,
            json!({ "task": "axolotl Quillfeather salamander", "include": { "proposed": true } }),
        )
        .await;
    assert!(!mentions(&body, ENTRY_WORD), "{body}");
    assert!(items(&body).is_empty(), "{body}");
}

#[tokio::test]
async fn the_spec_tools_still_return_the_entry_and_the_extensions_leave_it_unchanged() {
    let h = host().await;
    let entry = h.add_entry(ENTRY_TEXT).await;
    let _ = h.search("axolotl").await;
    let frame = Box::pin(hcp_v2::call_tool(
        &h.registry,
        h.db.clone(),
        alice(),
        hcp_v2::SEARCH_PREFERENCES,
        json!({ "query": "axolotl", "categories": ["general_preferences"], "purpose": "test" }),
        None,
    ))
    .await
    .unwrap();
    assert_eq!(frame["isError"], false, "{frame}");
    assert!(mentions(&frame, ENTRY_WORD), "{frame}");
    let version: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records WHERE id = ?")
        .bind(&entry)
        .fetch_one(h.db.pool())
        .await
        .unwrap();
    assert_eq!(version, 1);
}

#[tokio::test]
async fn on_slash_hcp_an_entry_is_not_hidden_because_that_surface_is_unchanged() {
    // The exclusion is the HCP v2 host's rule. `/hcp` never ran on this
    // registry, and it still reads the person's records as it always did.
    let h = host().await;
    let entry = h.add_entry(ENTRY_TEXT).await;
    let loaded = super::context_search::resolve_input_ref(&h.db, &alice(), &entry[..8])
        .await
        .unwrap();
    assert_eq!(loaded.as_deref(), Some(entry.as_str()));
}

// ---- the host's rules ---------------------------------------------------------

#[tokio::test]
async fn every_extension_refuses_until_the_workspace_enables_hcp_v2() {
    let h = host_without_the_kind().await;
    let count = || async {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM records")
            .fetch_one(h.db.pool())
            .await
            .unwrap()
    };
    let before = count().await;
    for tool in EXTENSION_TOOL_NAMES {
        let body = h
            .call(
                &alice(),
                tool,
                json!({ "task": "x", "ref": "x", "statement": "x", "action": "accept" }),
            )
            .await;
        assert_eq!(body["success"], false, "{tool}: {body}");
        assert_eq!(body["code"], "native:not-configured", "{tool}");
        assert!(
            body["error"].as_str().unwrap().contains("`hcp_entry` kind"),
            "{tool}: {body}"
        );
    }
    assert_eq!(count().await, before, "a refused call wrote nothing");
}

#[tokio::test]
async fn a_call_with_no_client_is_refused() {
    let h = host().await;
    let anonymous = caller("acct:alice", None);
    for tool in EXTENSION_TOOL_NAMES {
        let body = h.call(&anonymous, tool, json!({ "task": "x" })).await;
        assert_eq!(body["success"], false, "{tool}: {body}");
        assert_eq!(body["code"], "native:client-required");
    }
}

#[tokio::test]
async fn access_is_the_persons_own_with_no_per_client_grants() {
    let h = host().await;
    make(
        &h,
        "decision",
        "Wombat policy",
        "We feed wombats on Fridays.",
        json!({}),
    )
    .await;
    // Another person's client sees none of Alice's private records, and
    // Alice's two clients see the same thing.
    let _model = TestModel::not_configured();
    let theirs = h
        .call(&bob(), NATIVE_SEARCH_CONTEXT, json!({ "task": "wombats" }))
        .await;
    assert_eq!(theirs["success"], true, "{theirs}");
    let second = caller("acct:alice", Some("client_two"));
    let first = h.search("wombats").await;
    let other = h
        .call(&second, NATIVE_SEARCH_CONTEXT, json!({ "task": "wombats" }))
        .await;
    assert_eq!(items(&first), items(&other));
    assert!(!items(&first).is_empty());
}

#[tokio::test]
async fn ranking_degrades_to_lexical_without_a_model_key() {
    let h = host().await;
    make(
        &h,
        "decision",
        "Wombat policy",
        "We feed wombats on Fridays.",
        json!({}),
    )
    .await;
    let _model = TestModel::not_configured();
    let body = h.search("wombats").await;
    assert_eq!(body["success"], true, "{body}");
    assert_eq!(body["ranking"], "lexical", "{body}");
    assert_eq!(items(&body).len(), 1);
}

// ---- old /hcp preference records are hidden like entries ----------------------

/// A `Resolution/preference` record, as the stopped `/hcp` surface left them,
/// plus an ordinary decision that shares its words.
async fn with_an_old_preference(h: &Host) -> (String, String) {
    super::tests::propose_preference_kind(&h.db).await;
    super::tests::promote_preference_kind(&h.db).await;
    let preference = make(
        h,
        "preference",
        "writing.length",
        "\"Quillfeather prefers long answers about axolotls\"",
        json!({}),
    )
    .await;
    let decision = make(
        h,
        "decision",
        "Axolotl husbandry",
        "Axolotls need cool water.",
        json!({}),
    )
    .await;
    (preference, decision)
}

#[tokio::test]
async fn old_preference_records_are_never_returned_or_traced() {
    let h = host().await;
    let (preference, _) = with_an_old_preference(&h).await;
    let _model = TestModel::not_configured();
    let body = h.search("axolotl Quillfeather").await;
    assert_eq!(items(&body).len(), 1, "{body}");
    assert_eq!(items(&body)[0]["title"], "Axolotl husbandry");
    assert!(!mentions(&body, ENTRY_WORD), "{body}");

    let missing = h
        .call(
            &alice(),
            NATIVE_TRACE_CONTEXT_ITEM,
            json!({ "ref": "00000000-0000-4000-8000-000000000000" }),
        )
        .await;
    for reference in [preference.clone(), preference[..8].to_string()] {
        let traced = h
            .call(
                &alice(),
                NATIVE_TRACE_CONTEXT_ITEM,
                json!({ "ref": reference }),
            )
            .await;
        assert_eq!(traced, missing, "{traced}");
    }
}

#[tokio::test]
async fn old_preference_records_never_reach_the_ranking_model_or_a_link() {
    let h = host().await;
    let (preference, decision) = with_an_old_preference(&h).await;
    // A decision that supersedes the old preference does not name it.
    let linked = make(
        &h,
        "decision",
        "Axolotl policy",
        "Axolotls are kept cool.",
        json!({ "links": [{ "target_id": preference, "relationship": "supersedes" }] }),
    )
    .await;
    let server = mock::MockServer::start(
        vec![(
            200,
            mock::ranking_response(&[(decision.as_str(), "water")], "axolotl care"),
        )],
        None,
    )
    .await;
    let _model = TestModel::point_at("test-key", &server.base_url, Duration::from_secs(10));
    let body = h.search("axolotl Quillfeather").await;
    assert_eq!(body["ranking"], "model", "{body}");
    for (_, _, sent) in server.seen() {
        // The task names the word; the old preference's own text must not be there.
        assert!(!mentions(&sent, "prefers long answers"), "{sent}");
        assert!(!mentions(&sent, "writing.length"), "{sent}");
    }
    let traced = h
        .call(
            &alice(),
            NATIVE_TRACE_CONTEXT_ITEM,
            json!({ "ref": linked }),
        )
        .await;
    assert_eq!(traced["supersession"]["supersedes"], json!([]), "{traced}");
    assert!(!mentions(&traced, &preference), "{traced}");
}

#[tokio::test]
async fn nothing_can_be_proposed_against_an_old_preference_and_the_refusals_point_to_hcp_entries() {
    let h = host().await;
    let (preference, _) = with_an_old_preference(&h).await;
    let digest = native(
        &h.db,
        &alice(),
        "get_record",
        json!({ "ids": [preference] }),
    )
    .await["records"][0]["body_digest"]
        .as_str()
        .unwrap()
        .to_string();
    let target = |reference: &str| {
        json!({
            "statement": "Short answers please.",
            "target": { "ref": reference, "expectedRevision": digest },
        })
    };
    let missing = h
        .call(
            &alice(),
            NATIVE_PROPOSE_CONTEXT_ITEM,
            target("00000000-0000-4000-8000-000000000000"),
        )
        .await;
    let refused = h
        .call(&alice(), NATIVE_PROPOSE_CONTEXT_ITEM, target(&preference))
        .await;
    assert_eq!(refused, missing, "{refused}");

    // Asking for the old kind, or sending a value, is told what is true here.
    for arguments in [
        json!({ "kind": "preference", "statement": "Short answers please." }),
        json!({ "kind": "Resolution/preference", "statement": "Short answers please." }),
        json!({ "kind": "decision", "statement": "Short.", "value": "\"short\"" }),
    ] {
        let refused = h
            .call(&alice(), NATIVE_PROPOSE_CONTEXT_ITEM, arguments)
            .await;
        assert_eq!(refused["success"], false, "{refused}");
        assert!(!mentions(&refused, "mutatePreferences"), "{refused}");
    }
    let refused = h
        .call(
            &alice(),
            NATIVE_PROPOSE_CONTEXT_ITEM,
            json!({ "kind": "preference", "statement": "Short answers please." }),
        )
        .await;
    assert!(mentions(&refused, "hcp_addPreference"), "{refused}");
}

#[test]
fn the_search_description_says_what_leaves_the_server_when_a_model_key_is_set() {
    let descriptors = hcp_v2_extension_descriptors();
    let search = descriptors
        .iter()
        .find(|d| d["name"] == NATIVE_SEARCH_CONTEXT)
        .unwrap()["description"]
        .as_str()
        .unwrap();
    assert!(search.contains("sent to Anthropic"), "{search}");
    assert!(search.contains("nothing leaves the server"), "{search}");
}

// ---- the old /hcp preference catalog document ----------------------------------

#[tokio::test]
async fn the_old_preference_catalog_is_hidden_like_the_preferences_it_defines() {
    let h = host().await;
    // The stopped `/hcp` surface keeps its preference definitions in one note,
    // marked by a facet. Make one through the real tool, as that surface did.
    super::tests::propose_preference_kind(&h.db).await;
    super::tests::promote_preference_kind(&h.db).await;
    let defined = Box::pin(super::call_tool(
        &{
            let mut registry = ToolRegistry::new();
            super::register_hcp_tools(&mut registry).unwrap();
            registry
        },
        h.db.clone(),
        alice(),
        super::MUTATE_PREFERENCES,
        json!({
            "operation": "CREATE_DEFINITION",
            "definition": {
                "slug": "writing.axolotl",
                "description": "Quillfeather axolotl answers",
                "valueType": "STRING",
                "scope": "GLOBAL",
            },
        }),
        None,
    ))
    .await;
    assert_eq!(defined["isError"], false, "{defined}");
    let catalog = sqlx::query_scalar::<_, String>(
        "SELECT record_id FROM facet_values WHERE key = 'hcp.role' AND value = 'preference-catalog'",
    )
    .fetch_one(h.db.pool())
    .await
    .unwrap();

    // Traced by id, in full or by short form, it is not found: the same
    // answer as a record that is not there.
    let missing = h
        .call(
            &alice(),
            NATIVE_TRACE_CONTEXT_ITEM,
            json!({ "ref": "00000000-0000-4000-8000-000000000000" }),
        )
        .await;
    for reference in [catalog.clone(), catalog[..8].to_string()] {
        let traced = h
            .call(
                &alice(),
                NATIVE_TRACE_CONTEXT_ITEM,
                json!({ "ref": reference }),
            )
            .await;
        assert_eq!(traced, missing, "{traced}");
    }

    // It is not a search result, and nothing can be proposed against it.
    let _model = TestModel::not_configured();
    let body = h.search("HCP preference catalog Quillfeather").await;
    assert!(!mentions(&body, "Quillfeather"), "{body}");
    assert!(!mentions(&body, "writing.axolotl"), "{body}");
    let digest = native(&h.db, &alice(), "get_record", json!({ "ids": [catalog] })).await
        ["records"][0]["body_digest"]
        .as_str()
        .unwrap()
        .to_string();
    let refused = h
        .call(
            &alice(),
            NATIVE_PROPOSE_CONTEXT_ITEM,
            json!({
                "statement": "Rename the slug.",
                "target": { "ref": catalog, "expectedRevision": digest },
            }),
        )
        .await;
    assert_eq!(refused["code"], "NOT_FOUND", "{refused}");
    assert!(!mentions(&refused, "mutatePreferences"), "{refused}");

    // A decision that links to it does not name it.
    let linked = make(
        &h,
        "decision",
        "Axolotl policy",
        "Axolotls are kept cool.",
        json!({ "links": [{ "target_id": catalog, "relationship": "supersedes" }] }),
    )
    .await;
    let traced = h
        .call(
            &alice(),
            NATIVE_TRACE_CONTEXT_ITEM,
            json!({ "ref": linked }),
        )
        .await;
    assert_eq!(traced["supersession"]["supersedes"], json!([]), "{traced}");
    assert!(!mentions(&traced, &catalog), "{traced}");
}

// ---- suggestions on hidden records ---------------------------------------------

/// An open suggestion record on `target`, as the workbench writes one.
async fn suggest_on(h: &Host, target: &str, body: &str) -> String {
    let digest = native(&h.db, &alice(), "get_record", json!({ "ids": [target] })).await["records"]
        [0]["body_digest"]
        .as_str()
        .unwrap()
        .to_string();
    let created = native(
        &h.db,
        &alice(),
        "create_record",
        json!({
            "type": "Annotation",
            "kind": "suggestion",
            "lifecycle": "open",
            "body": body,
            "links": [{ "target_id": target, "relationship": "part_of" }],
            "facets": { "proposal.precondition": "digest", "anchor.base_digest": digest },
            "reason": "extension fixture",
            "sources": [],
        }),
    )
    .await;
    created["id"].as_str().expect("created").to_string()
}

#[tokio::test]
async fn suggestions_on_hidden_records_are_hidden_by_every_route() {
    let h = host().await;
    let entry = h.add_entry(ENTRY_TEXT).await;
    let (preference, _) = with_an_old_preference(&h).await;
    let on_entry = suggest_on(&h, &entry, "Quillfeather should be a salamander.").await;
    let on_preference = suggest_on(&h, &preference, "Quillfeather wants walrus answers.").await;
    // An ordinary suggestion on an ordinary record stays reachable.
    let ordinary = make(
        &h,
        "decision",
        "Axolotl policy",
        "Axolotls are kept cool.",
        json!({}),
    )
    .await;
    let on_ordinary = suggest_on(&h, &ordinary, "Axolotls are kept very cool.").await;

    let missing_ref = "00000000-0000-4000-8000-000000000000";
    let missing_trace = h
        .call(
            &alice(),
            NATIVE_TRACE_CONTEXT_ITEM,
            json!({ "ref": missing_ref }),
        )
        .await;
    let missing_resolve = h
        .call(
            &alice(),
            NATIVE_RESOLVE_CONTEXT_ITEM,
            json!({ "ref": missing_ref, "action": "accept", "reason": "x" }),
        )
        .await;
    let revision = "0".repeat(64);
    let missing_propose = h
        .call(
            &alice(),
            NATIVE_PROPOSE_CONTEXT_ITEM,
            json!({
                "statement": "x",
                "target": { "ref": missing_ref, "expectedRevision": revision },
            }),
        )
        .await;
    for hidden in [&on_entry, &on_preference] {
        // Direct read, by full id and by short reference.
        for reference in [hidden.clone(), hidden[..8].to_string()] {
            let traced = h
                .call(
                    &alice(),
                    NATIVE_TRACE_CONTEXT_ITEM,
                    json!({ "ref": reference }),
                )
                .await;
            assert_eq!(traced, missing_trace, "{traced}");
        }
        // Acting on it.
        let resolved = h
            .call(
                &alice(),
                NATIVE_RESOLVE_CONTEXT_ITEM,
                json!({ "ref": hidden, "action": "accept", "reason": "x" }),
            )
            .await;
        assert_eq!(resolved, missing_resolve, "{resolved}");
        let proposed = h
            .call(
                &alice(),
                NATIVE_PROPOSE_CONTEXT_ITEM,
                json!({
                    "statement": "x",
                    "target": { "ref": hidden, "expectedRevision": revision },
                }),
            )
            .await;
        assert_eq!(proposed, missing_propose, "{proposed}");
    }

    // A record that cites a hidden suggestion as evidence does not name it,
    // and the search never offers one.
    let citing = make(
        &h,
        "decision",
        "Axolotl husbandry",
        "Axolotls need cool water.",
        json!({ "links": [
            { "target_id": on_entry, "relationship": "evidence" },
            { "target_id": on_preference, "relationship": "evidence" },
        ] }),
    )
    .await;
    let traced = h
        .call(
            &alice(),
            NATIVE_TRACE_CONTEXT_ITEM,
            json!({ "ref": citing }),
        )
        .await;
    assert_eq!(traced["evidence"], json!([]), "{traced}");
    for hidden in [&on_entry, &on_preference] {
        assert!(!mentions(&traced, hidden), "{traced}");
    }
    let _model = TestModel::not_configured();
    let body = h
        .call(
            &alice(),
            NATIVE_SEARCH_CONTEXT,
            json!({ "task": "axolotl Quillfeather salamander walrus", "include": { "proposed": true } }),
        )
        .await;
    assert!(!mentions(&body, ENTRY_WORD), "{body}");
    assert!(!mentions(&body, "walrus"), "{body}");
    assert!(!mentions(&body, "salamander"), "{body}");
    // The ordinary one is still there to be traced.
    let traced = h
        .call(
            &alice(),
            NATIVE_TRACE_CONTEXT_ITEM,
            json!({ "ref": on_ordinary }),
        )
        .await;
    assert_eq!(traced["success"], true, "{traced}");
}

// ---- hidden records do not displace results through limits -----------------------

#[tokio::test]
async fn hidden_records_do_not_displace_ordinary_results_through_any_limit() {
    let h = host().await;
    super::tests::propose_preference_kind(&h.db).await;
    super::tests::promote_preference_kind(&h.db).await;
    // More hidden matches than the per-word hit cap, each matching harder
    // than the ordinary records do.
    for index in 0..60 {
        make(
            &h,
            "preference",
            &format!("zebra zebra {index}"),
            "\"zebra zebra zebra zebra\"",
            json!({}),
        )
        .await;
    }
    let mut ordinary = Vec::new();
    for name in ["Giraffe", "Okapi", "Gnu"] {
        ordinary.push(make(&h, "decision", name, "We discuss zebra herds.", json!({})).await);
    }
    let _model = TestModel::not_configured();
    let body = h.search("zebra").await;
    let mut titles: Vec<&str> = items(&body)
        .iter()
        .map(|item| item["title"].as_str().unwrap())
        .collect::<Vec<_>>()
        .into_iter()
        .map(|title| match title {
            "Giraffe" => "Giraffe",
            "Okapi" => "Okapi",
            "Gnu" => "Gnu",
            _ => "other",
        })
        .collect();
    titles.sort_unstable();
    assert_eq!(titles, ["Giraffe", "Gnu", "Okapi"], "{body}");
}

// ---- supersession errors do not reveal hidden successors -------------------------

#[tokio::test]
async fn a_hidden_superseding_link_makes_no_difference_to_resolving() {
    let h = host().await;
    super::tests::propose_preference_kind(&h.db).await;
    super::tests::promote_preference_kind(&h.db).await;
    let old = make(
        &h,
        "decision",
        "Feeding",
        "Feed wombats on Fridays.",
        json!({}),
    )
    .await;
    let replacement = make(
        &h,
        "decision",
        "Feeding v2",
        "Feed wombats on Mondays.",
        json!({}),
    )
    .await;
    // An old preference record claims to supersede the decision.
    make(
        &h,
        "preference",
        "writing.length",
        "\"short\"",
        json!({ "links": [{ "target_id": old, "relationship": "supersedes" }] }),
    )
    .await;
    let traced = h
        .call(&alice(), NATIVE_TRACE_CONTEXT_ITEM, json!({ "ref": old }))
        .await;
    assert_eq!(traced["item"]["status"], "accepted", "{traced}");
    let revision = traced["item"]["revision"].as_str().unwrap().to_string();
    let resolved = h
        .call(
            &alice(),
            NATIVE_RESOLVE_CONTEXT_ITEM,
            json!({
                "ref": old, "action": "supersede", "expectedRevision": revision,
                "reason": "moved to Mondays", "replacement": { "ref": replacement },
            }),
        )
        .await;
    assert_eq!(resolved["outcome"], "superseded", "{resolved}");
}

// ---- the extensions cannot create hidden kinds -----------------------------------

#[tokio::test]
async fn the_extensions_refuse_to_create_hidden_kinds_whatever_they_are_called() {
    let h = host().await;
    // A deprecated alias of the entry kind: the same records under another name.
    let legacy = manage_vocabularies(
        &h.db,
        json!({
            "action": "propose_value",
            "vocabulary": "kind:Resolution",
            "value": "legacy_entry",
            "gloss": "An older name for HCP entries.",
            "metadata": {
                "schema_version": 1,
                "provenance_ref": "rec:455149af-2ec6-45ed-b895-f0582e889400",
                "definition": "An older name for HCP entries, kept as an alias of hcp_entry.",
                "identity": {
                    "criterion": "Continuity of one HCP entry across its versions.",
                    "dedup": { "mode": "record_id", "keys": [] }
                },
                "declared_capabilities": []
            }
        }),
    )
    .await;
    assert_eq!(legacy["status"], "proposed", "{legacy}");
    let aliased = manage_vocabularies(
        &h.db,
        json!({
            "action": "alias_value",
            "value_id": "vv:voc:kind:Resolution:legacy_entry",
            "canonical_id": "vv:voc:kind:Resolution:hcp_entry",
        }),
    )
    .await;
    assert_eq!(aliased["status"], "deprecated", "{aliased}");

    let count = || async {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM records")
            .fetch_one(h.db.pool())
            .await
            .unwrap()
    };
    let before = count().await;
    for kind in [
        "Resolution/hcp_entry",
        "Resolution/preference",
        "preference",
        "Resolution/legacy_entry",
    ] {
        let refused = h
            .call(
                &alice(),
                NATIVE_PROPOSE_CONTEXT_ITEM,
                json!({ "kind": kind, "statement": "I keep axolotls." }),
            )
            .await;
        assert_eq!(refused["success"], false, "{kind}: {refused}");
        assert_eq!(refused["changed"], false, "{kind}: {refused}");
        assert!(
            !mentions(&refused, "mutatePreferences"),
            "{kind}: {refused}"
        );
    }
    assert_eq!(count().await, before, "nothing was created");
    // An ordinary kind still works.
    let proposed = h
        .call(
            &alice(),
            NATIVE_PROPOSE_CONTEXT_ITEM,
            json!({ "kind": "decision", "statement": "Axolotls stay cool." }),
        )
        .await;
    assert_eq!(proposed["outcome"], "proposed", "{proposed}");
}

#[test]
fn the_search_description_states_the_full_model_payload() {
    let descriptors = hcp_v2_extension_descriptors();
    let search = descriptors
        .iter()
        .find(|d| d["name"] == NATIVE_SEARCH_CONTEXT)
        .unwrap()["description"]
        .as_str()
        .unwrap();
    for part in [
        "the task text",
        "the requested limit",
        "ref, kind, title, summary and status",
        "up to 500 characters",
        "fixed instructions",
        "after a failed model request",
    ] {
        assert!(search.contains(part), "missing {part:?}: {search}");
    }
}

// ---- discussion and attachments hang off their bearer, however deep --------------

/// A comment (`reply_to: None`) or a reply, borne by `bearer`.
async fn comment_on(h: &Host, bearer: &str, body: &str) -> String {
    let created = native(
        &h.db,
        &alice(),
        "create_record",
        json!({
            "type": "Annotation", "kind": "comment", "name": "",
            "body": body,
            "links": [{ "target_id": bearer, "relationship": "part_of" }],
            "reason": "extension fixture", "sources": [],
        }),
    )
    .await;
    created["id"]
        .as_str()
        .unwrap_or_else(|| panic!("{created}"))
        .to_string()
}

/// A file attached to `bearer`.
async fn attach_to(h: &Host, bearer: &str, name: &str, body: &str) -> String {
    let created = native(
        &h.db,
        &alice(),
        "create_record",
        json!({
            "type": "Document", "kind": "attachment", "name": name,
            "body": body,
            "links": [{ "target_id": bearer, "relationship": "part_of" }],
            "reason": "extension fixture", "sources": [],
        }),
    )
    .await;
    created["id"]
        .as_str()
        .unwrap_or_else(|| panic!("{created}"))
        .to_string()
}

async fn not_found(h: &Host, reference: &str) -> bool {
    let missing = h
        .call(
            &alice(),
            NATIVE_TRACE_CONTEXT_ITEM,
            json!({ "ref": "00000000-0000-4000-8000-000000000000" }),
        )
        .await;
    let traced = h
        .call(
            &alice(),
            NATIVE_TRACE_CONTEXT_ITEM,
            json!({ "ref": reference }),
        )
        .await;
    traced == missing
}

#[tokio::test]
async fn a_reply_to_a_comment_on_a_hidden_record_is_hidden() {
    let h = host().await;
    let entry = h.add_entry(ENTRY_TEXT).await;
    let (preference, _) = with_an_old_preference(&h).await;
    for bearer in [&entry, &preference] {
        let root = comment_on(&h, bearer, "Quillfeather tank talk, root.").await;
        let reply = comment_on(&h, &root, "Quillfeather tank talk, reply.").await;
        for hidden in [&root, &reply] {
            assert!(not_found(&h, hidden).await, "{hidden}");
            assert!(not_found(&h, &hidden[..8]).await, "{hidden} (short)");
        }
    }
    let _model = TestModel::not_configured();
    let body = h.search("Quillfeather tank talk").await;
    assert!(items(&body).is_empty(), "{body}");
    assert!(!mentions(&body, "tank talk"), "{body}");

    // The same shapes on an ordinary record stay reachable.
    let ordinary = make(
        &h,
        "decision",
        "Tank policy",
        "Tanks are cleaned weekly.",
        json!({}),
    )
    .await;
    let root = comment_on(&h, &ordinary, "Weekly cleaning is fine.").await;
    let reply = comment_on(&h, &root, "Agreed on weekly cleaning.").await;
    for visible in [&root, &reply] {
        assert!(!not_found(&h, visible).await, "{visible}");
    }
}

#[tokio::test]
async fn an_attachment_on_a_hidden_record_is_hidden_from_trace_search_and_the_model() {
    let h = host().await;
    let entry = h.add_entry(ENTRY_TEXT).await;
    let attachment = attach_to(
        &h,
        &entry,
        "Quillfeather vet scan",
        "Quillfeather vet scan notes",
    )
    .await;
    let kept = make(
        &h,
        "decision",
        "Vet policy",
        "Vets see the axolotl yearly.",
        json!({}),
    )
    .await;
    assert!(not_found(&h, &attachment).await);
    assert!(not_found(&h, &attachment[..8]).await);

    // No search path returns it, and the ranking model is never shown it.
    let server = mock::MockServer::start(
        vec![(
            200,
            mock::ranking_response(&[(kept.as_str(), "vets")], "vet visits"),
        )],
        None,
    )
    .await;
    let _model = TestModel::point_at("test-key", &server.base_url, Duration::from_secs(10));
    let body = h.search("vets axolotl scanned").await;
    assert!(!mentions(&body, "vet scan"), "{body}");
    assert!(!mentions(&body, "attachment text"), "{body}");
    assert_eq!(items(&body).len(), 1, "{body}");
    for (_, _, sent) in server.seen() {
        assert!(!mentions(&sent, "Quillfeather vet scan"), "{sent}");
        assert!(!mentions(&sent, "attachment text"), "{sent}");
    }
}

#[tokio::test]
async fn a_deep_bearer_chain_is_hidden() {
    let h = host().await;
    let entry = h.add_entry(ENTRY_TEXT).await;
    // entry <- attachment <- comment <- reply, and one more level of attachment.
    let attachment = attach_to(
        &h,
        &entry,
        "Quillfeather deep file",
        "Quillfeather deep file",
    )
    .await;
    let comment = comment_on(&h, &attachment, "Quillfeather deep comment").await;
    let reply = comment_on(&h, &comment, "Quillfeather deep reply").await;
    let nested = attach_to(
        &h,
        &reply,
        "Quillfeather deepest file",
        "Quillfeather deepest file",
    )
    .await;
    for hidden in [&attachment, &comment, &reply, &nested] {
        assert!(not_found(&h, hidden).await, "{hidden}");
    }
    let _model = TestModel::not_configured();
    let body = h.search("Quillfeather deep file comment reply").await;
    assert!(items(&body).is_empty(), "{body}");
}
