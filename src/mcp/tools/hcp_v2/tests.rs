//! Checks for the HCP v2 entry tools against the MCP binding (HCP v2 §10) and
//! the Core behaviour it carries (§3-§7): envelopes, validation, provenance,
//! per-client pseudonyms, versions, soft delete, redaction, the minimization
//! report, the quantity bound, indistinguishable not-authorized answers and the
//! workspace opt-in.

use serde_json::{json, Value};

use super::client::ClientIdentity;
use super::store::Store;
use super::*;
use crate::db::{create_database, Db};
use crate::mcp::registry::{Caller, ToolRegistry};
use crate::provenance::Channel;
use native_policy_kernel::{AllowEntry, Capability};

struct Harness {
    db: Db,
    registry: ToolRegistry,
    /// Native's own tools, which is how a person or an agent edits a record.
    native: ToolRegistry,
}

/// The deployment secret the tests register the tools with.
fn test_key() -> PseudonymKey {
    PseudonymKey::from_secret(&[0x42; 32]).unwrap()
}

fn caller(account: &str, client: Option<&str>) -> Caller {
    Caller::authenticated(account)
        .with_channel(Channel::Mcp)
        .with_oauth_client_id(client.map(str::to_string))
}

/// Alice through the first of her two HCP clients.
fn alice() -> Caller {
    caller("acct:alice", Some("client_one"))
}

/// Alice's other client: the same person, a different HCP Client.
fn alice_two() -> Caller {
    caller("acct:alice", Some("client_two"))
}

fn bob() -> Caller {
    caller("acct:bob", Some("client_one"))
}

/// A hosted member has a person record bound to their account; entries are
/// created account-only and need that binding.
async fn onboard(db: &Db, account: &str) {
    let person = Box::pin(crate::mcp::tools::lifecycle::create_record(
        db.clone(),
        Caller::local(),
        json!({ "type": "Entity", "kind": "person", "name": account, "reason": "test fixture" }),
    ))
    .await
    .unwrap();
    for (system, identifier) in [
        ("account", account.to_string()),
        ("native-principal", format!("native/{account}")),
    ] {
        sqlx::query(
            "INSERT INTO bindings (record_id, system, identifier, is_canonical) VALUES (?, ?, ?, 1)",
        )
        .bind(person["id"].as_str().unwrap())
        .bind(system)
        .bind(identifier)
        .execute(db.write_pool())
        .await
        .unwrap();
    }
}

/// What a workspace admin sends to define the `hcp_entry` kind: the real
/// `manage_vocabularies` operations, here through the full registry as a local
/// owner.
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

async fn propose_kind(db: &Db) {
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
}

async fn promote_kind(db: &Db) {
    let promoted = manage_vocabularies(
        db,
        json!({ "action": "promote_value", "value_id": "vv:voc:kind:Resolution:hcp_entry" }),
    )
    .await;
    assert_eq!(promoted["status"], "active", "{promoted}");
}

async fn unconfigured() -> Harness {
    let db = create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_hcp_v2_tools(&mut registry, test_key()).unwrap();
    onboard(&db, "acct:alice").await;
    onboard(&db, "acct:bob").await;
    let native = native_tools();
    Harness {
        db,
        registry,
        native,
    }
}

/// A workspace whose admin has defined and promoted the `hcp_entry` kind.
async fn harness() -> Harness {
    let h = unconfigured().await;
    propose_kind(&h.db).await;
    promote_kind(&h.db).await;
    h
}

impl Harness {
    /// The full MCP result frame.
    async fn frame(&self, who: &Caller, tool: &str, args: Value) -> Value {
        call_tool(
            &self.registry,
            self.db.clone(),
            who.clone(),
            tool,
            args,
            None,
        )
        .await
        .expect("a known tool")
    }

    /// A successful result's `structuredContent`; panics on a tool error.
    async fn ok(&self, who: &Caller, tool: &str, args: Value) -> Value {
        let frame = self.frame(who, tool, args).await;
        assert_eq!(frame["isError"], false, "{frame}");
        frame["structuredContent"].clone()
    }

    /// An error frame's `structuredContent`; panics if the call succeeded.
    async fn err(&self, who: &Caller, tool: &str, args: Value) -> Value {
        let frame = self.frame(who, tool, args).await;
        assert_eq!(frame["isError"], true, "{frame}");
        frame["structuredContent"].clone()
    }

    async fn add(&self, who: &Caller, category: &str, preference: &str) -> Value {
        self.ok(
            who,
            ADD_PREFERENCE,
            json!({
                "category": category,
                "preference": preference,
                "declarationType": "user-declared",
                "sourceContext": "conversation:test",
            }),
        )
        .await
    }

    async fn search(&self, who: &Caller, query: &str, categories: Value) -> Value {
        self.ok(
            who,
            SEARCH_PREFERENCES,
            json!({ "query": query, "categories": categories, "purpose": "test" }),
        )
        .await
    }

    fn store<'a>(&'a self, who: &'a Caller) -> Store<'a> {
        Store::new(
            &self.db,
            who,
            ClientIdentity::of(who).expect("a client"),
            test_key(),
        )
    }

    /// `(record id, entry)` of every entry `who` holds in trusted state (the
    /// fold of their events), as held (unredacted), in order of creation.
    async fn stored(&self, who: &Caller) -> Vec<(String, Value)> {
        let fold = self.store(who).fold_all().await.unwrap();
        let mut entries: Vec<Value> = fold
            .entries
            .values()
            .map(|folded| folded.current().0.clone())
            .collect();
        entries.sort_by(|a, b| {
            a["record"]["provenance"]["recordedAt"]
                .as_str()
                .cmp(&b["record"]["provenance"]["recordedAt"].as_str())
                .then_with(|| a["id"].as_str().cmp(&b["id"].as_str()))
        });
        entries
            .into_iter()
            .map(|entry| (record_id_of_entry(&entry), entry))
            .collect()
    }

    /// `(record id, body)` of every view record `who` can see, oldest first,
    /// as stored. A view is not evidence: this is what the person sees.
    async fn views(&self, who: &Caller) -> Vec<(String, Value)> {
        let result = Box::pin(crate::mcp::tools::querying::query_sql(
            self.db.clone(),
            who.clone(),
            json!({
                "sql": "SELECT id, body FROM records WHERE kind = 'hcp_entry' ORDER BY created_at, id",
                "parameters": [],
            }),
        ))
        .await
        .unwrap();
        result["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| {
                (
                    row["id"].as_str().unwrap().to_string(),
                    serde_json::from_str(row["body"].as_str().unwrap()).unwrap(),
                )
            })
            .collect()
    }

    async fn facet(&self, who: &Caller, record_id: &str, key: &str) -> Option<String> {
        let result = Box::pin(crate::mcp::tools::querying::query_sql(
            self.db.clone(),
            who.clone(),
            json!({
                "sql": "SELECT value FROM facet_values WHERE record_id = ?1 AND key = ?2",
                "parameters": [record_id, key],
            }),
        ))
        .await
        .unwrap();
        result["rows"][0]["value"].as_str().map(str::to_string)
    }

    /// Edit an entry's view record the way a person could in Native.
    async fn edit_view(&self, who: &Caller, record_id: &str, edit: impl FnOnce(&mut Value)) {
        edit_record(&self.db, &self.native, who, record_id, edit).await;
    }

    /// Append a new version of `urn` the way a later slice's operation will
    /// (a confirmation, an expiry): `edit` changes the grouped entry, the
    /// version numbers are advanced. Returns the new version.
    async fn inject_version(
        &self,
        who: &Caller,
        urn: &str,
        edit: impl FnOnce(&mut Value),
    ) -> Value {
        let store = self.store(who);
        let mut tx = store.begin().await.unwrap();
        let current = store.entry_in(&mut tx, urn).await.unwrap().unwrap();
        let mut next = current.entry.clone();
        next.0["record"]["version"] = json!(current.entry.version() + 1);
        next.0["record"]["previousVersion"] = json!(current.entry.version());
        edit(&mut next.0);
        let mut act = crate::act::ActAllocation::new();
        store
            .append_update(&mut tx, &mut act, &current, &next, "test injection")
            .await
            .unwrap();
        store.commit(tx).await.unwrap();
        next.0
    }

    /// Append a status change of `urn`'s current version.
    async fn inject_status(&self, who: &Caller, urn: &str, to: &str, cause: &str) {
        let store = self.store(who);
        let mut tx = store.begin().await.unwrap();
        let current = store.entry_in(&mut tx, urn).await.unwrap().unwrap();
        let mut act = crate::act::ActAllocation::new();
        store
            .append_status(&mut tx, &mut act, &current, to, cause, "test injection")
            .await
            .unwrap();
        store.commit(tx).await.unwrap();
    }
}

/// Native's own tools, which is how a person or an agent edits a record.
fn native_tools() -> ToolRegistry {
    let mut native = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut native).unwrap();
    crate::mcp::register_surface_tools(&mut native).unwrap();
    native
}

async fn edit_record(
    db: &Db,
    native: &ToolRegistry,
    who: &Caller,
    record_id: &str,
    edit: impl FnOnce(&mut Value),
) {
    let raw = Box::pin(crate::mcp::tools::querying::query_sql(
        db.clone(),
        who.clone(),
        json!({ "sql": "SELECT body FROM records WHERE id = ?1", "parameters": [record_id] }),
    ))
    .await
    .unwrap();
    let body_text = raw["rows"][0]["body"].as_str().unwrap().to_string();
    let mut body: Value = serde_json::from_str(&body_text).unwrap();
    let digest = store::sha256_hex(&body_text);
    edit(&mut body);
    Box::pin(native.call(
        db.clone(),
        who.clone(),
        "update_record",
        json!({
            "id": record_id,
            "body_set": body.to_string(),
            "if_body_digest": digest,
            "reason": "test edit in Native",
            "sources": [],
        }),
    ))
    .await
    .unwrap();
}

fn record_id_of_entry(entry: &Value) -> String {
    entry["id"]
        .as_str()
        .unwrap()
        .strip_prefix("urn:uuid:")
        .unwrap()
        .to_string()
}

// ---- descriptors and registration -----------------------------------------

#[test]
fn registers_exactly_the_five_tools_with_schemas() {
    let descriptors = hcp_v2_tool_descriptors();
    let names: Vec<&str> = descriptors
        .iter()
        .map(|d| d["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "hcp_searchPreferences",
            "hcp_getPreference",
            "hcp_addPreference",
            "hcp_updatePreference",
            "hcp_deletePreference"
        ]
    );
    for descriptor in &descriptors {
        assert_eq!(descriptor["inputSchema"]["type"], "object");
        assert!(
            descriptor["outputSchema"]["anyOf"]
                .as_array()
                .unwrap()
                .len()
                == 2
        );
        assert!(!descriptor["description"].as_str().unwrap().is_empty());
    }
    let required = |tool: usize| -> Vec<String> {
        descriptors[tool]["inputSchema"]["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect()
    };
    assert_eq!(required(0), ["query", "categories", "purpose"]);
    assert_eq!(required(1), ["entryId", "purpose"]);
    assert_eq!(
        required(2),
        ["category", "preference", "declarationType", "sourceContext"]
    );
    assert_eq!(required(3), ["entryId", "updatedPreference", "reason"]);
    assert_eq!(required(4), ["entryId", "reason"]);
    // The add tool offers no issuer-attested declaration type (§10.3.3).
    assert_eq!(
        descriptors[2]["inputSchema"]["properties"]["declarationType"]["enum"],
        json!(["user-declared", "model-inferred"])
    );

    let mut registry = ToolRegistry::new();
    register_hcp_v2_tools(&mut registry, test_key()).unwrap();
    let mut twice = ToolRegistry::new();
    register_hcp_v2_tools(&mut twice, test_key()).unwrap();
    assert!(
        register_hcp_v2_tools(&mut twice, test_key()).is_err(),
        "double registration is refused"
    );
}

#[tokio::test]
async fn an_unknown_tool_is_not_ours_to_answer() {
    let h = harness().await;
    assert!(call_tool(
        &h.registry,
        h.db.clone(),
        alice(),
        "hcp_nope",
        json!({}),
        None
    )
    .await
    .is_none());
}

// ---- opt-in and attribution -----------------------------------------------

#[tokio::test]
async fn every_tool_refuses_until_the_workspace_enables_the_kind() {
    let h = unconfigured().await;
    let calls = [
        (
            SEARCH_PREFERENCES,
            json!({ "query": "q", "categories": ["general_preferences"], "purpose": "p" }),
        ),
        (
            GET_PREFERENCE,
            json!({ "entryId": "urn:uuid:00000000-0000-4000-8000-000000000000", "purpose": "p" }),
        ),
        (
            ADD_PREFERENCE,
            json!({ "category": "general_preferences", "preference": "x", "declarationType": "user-declared", "sourceContext": "s" }),
        ),
        (
            UPDATE_PREFERENCE,
            json!({ "entryId": "urn:uuid:00000000-0000-4000-8000-000000000000", "updatedPreference": "x", "reason": "r" }),
        ),
        (
            DELETE_PREFERENCE,
            json!({ "entryId": "urn:uuid:00000000-0000-4000-8000-000000000000", "reason": "r" }),
        ),
    ];
    for (tool, args) in &calls {
        let error = h.err(&alice(), tool, args.clone()).await;
        assert_eq!(error["type"], "native:not-configured", "{tool}: {error}");
        assert!(error["detail"].as_str().unwrap().contains("hcp_entry"));
    }
    // Nothing was written: no entry and no facets.
    assert!(h.stored(&alice()).await.is_empty());
    let key = Box::pin(crate::mcp::tools::querying::query_sql(
        h.db.clone(),
        alice(),
        json!({ "sql": "SELECT COUNT(*) AS n FROM facet_values WHERE key LIKE 'hcp2.%'", "parameters": [] }),
    ))
    .await
    .unwrap();
    assert_eq!(key["rows"][0]["n"], 0);
}

#[tokio::test]
async fn a_proposed_but_unpromoted_kind_is_still_refused() {
    let h = unconfigured().await;
    propose_kind(&h.db).await;
    let error = h
        .err(&alice(), ADD_PREFERENCE, json!({ "category": "general_preferences", "preference": "x", "declarationType": "user-declared", "sourceContext": "s" }))
        .await;
    assert_eq!(error["type"], "native:not-configured");
    assert!(error["detail"].as_str().unwrap().contains("promote"));
    assert!(h.stored(&alice()).await.is_empty());
}

#[tokio::test]
async fn a_call_with_no_client_is_not_authorized() {
    let h = harness().await;
    let anonymous = caller("acct:alice", None);
    let error = h
        .err(&anonymous, ADD_PREFERENCE, json!({ "category": "general_preferences", "preference": "x", "declarationType": "user-declared", "sourceContext": "s" }))
        .await;
    assert_eq!(error["type"], "scope-denied");
    assert!(h.stored(&alice()).await.is_empty());
}

// ---- envelope ---------------------------------------------------------------

#[tokio::test]
async fn results_come_in_structured_content_and_as_json_text() {
    let h = harness().await;
    let frame = h
        .frame(&alice(), ADD_PREFERENCE, json!({ "category": "general_preferences", "preference": "Prefer concise answers.", "declarationType": "user-declared", "sourceContext": "conversation:1" }))
        .await;
    assert_eq!(frame["isError"], false);
    let text: Value = serde_json::from_str(frame["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(text, frame["structuredContent"]);

    let error = h
        .frame(&alice(), SEARCH_PREFERENCES, json!({ "query": "q" }))
        .await;
    assert_eq!(error["isError"], true);
    let body = &error["structuredContent"];
    assert_eq!(body["type"], "malformed-request");
    assert_eq!(
        error["content"][0]["text"],
        format!(
            "{}: {}",
            body["type"].as_str().unwrap(),
            body["detail"].as_str().unwrap()
        )
    );
}

// ---- add --------------------------------------------------------------------

#[tokio::test]
async fn add_creates_a_version_one_entry_in_grouped_form() {
    let h = harness().await;
    let entry = h
        .ok(
            &alice(),
            ADD_PREFERENCE,
            json!({
                "category": "work_context",
                "dimension": "Meeting   Times",
                "preference": "I do not take calls before 10am.",
                "declarationType": "user-declared",
                "sourceContext": "conversation:abc",
            }),
        )
        .await;
    assert!(entry["id"].as_str().unwrap().starts_with("urn:uuid:"));
    assert_eq!(entry["type"], json!(["HCPEntry"]));
    assert_eq!(entry["credentialType"], "NLPreference");
    assert_eq!(
        entry["claim"]["subject"]["preference"],
        "I do not take calls before 10am."
    );
    assert_eq!(entry["claim"]["expirationDate"], Value::Null);
    let record = &entry["record"];
    assert_eq!(record["category"], "work_context");
    assert_eq!(record["dimension"], "Meeting   Times", "stored as sent");
    assert_eq!(record["declarationType"], "user-declared");
    assert_eq!(record["confidence"], Value::Null);
    assert_eq!(record["status"], "active");
    assert_eq!(record["version"], 1);
    assert_eq!(record["previousVersion"], Value::Null);
    assert_eq!(
        record["provenance"]["assertedBy"]["assurance"],
        "unverified"
    );
    assert_eq!(
        record["provenance"]["recordedByProvider"],
        "https://hcp.withnative.ai"
    );
    assert_eq!(record["provenance"]["confirmations"], json!([]));

    // One private Native record holds it, with the filterable facets.
    let stored = h.stored(&alice()).await;
    assert_eq!(stored.len(), 1);
    let (record_id, body) = &stored[0];
    assert_eq!(body["id"], entry["id"], "the entry id is the record id");
    assert_eq!(entry["id"], format!("urn:uuid:{record_id}"));
    assert_eq!(
        h.facet(&alice(), record_id, "hcp2.category")
            .await
            .as_deref(),
        Some("work_context")
    );
    assert_eq!(
        h.facet(&alice(), record_id, "hcp2.dimension")
            .await
            .as_deref(),
        Some("meeting_times")
    );
    assert_eq!(
        h.facet(&alice(), record_id, "hcp2.declaration_type")
            .await
            .as_deref(),
        Some("user-declared")
    );
    assert_eq!(
        h.facet(&alice(), record_id, "hcp2.status").await.as_deref(),
        Some("active")
    );
    assert_eq!(
        h.facet(&alice(), record_id, "hcp2.version")
            .await
            .as_deref(),
        Some("1")
    );
    // Private to the person.
    assert!(h.stored(&bob()).await.is_empty());
}

#[tokio::test]
async fn add_records_a_model_inference_with_its_asserter_and_confidence() {
    let h = harness().await;
    let entry = h
        .ok(
            &alice(),
            ADD_PREFERENCE,
            json!({
                "category": "general_preferences",
                "preference": "Probably prefers morning flights.",
                "declarationType": "model-inferred",
                "confidence": "medium",
                "assertedBy": "example-model-2026-10",
                "sourceContext": "conversation:7",
            }),
        )
        .await;
    assert_eq!(entry["record"]["declarationType"], "model-inferred");
    assert_eq!(entry["record"]["confidence"], "medium");
    let (record_id, stored) = h.stored(&alice()).await.remove(0);
    let provenance = &stored["record"]["provenance"];
    assert_eq!(provenance["assertedBy"]["id"], "example-model-2026-10");
    assert_eq!(provenance["assertedBy"]["assurance"], "unverified");
    assert_eq!(
        stored["claim"]["issuer"]["id"], "example-model-2026-10",
        "issuer equals the asserter"
    );
    assert_eq!(
        h.facet(&alice(), &record_id, "hcp2.confidence")
            .await
            .as_deref(),
        Some("medium")
    );
}

#[tokio::test]
async fn add_rejects_what_the_schema_and_the_confidence_rule_forbid() {
    let h = harness().await;
    let base = json!({
        "category": "general_preferences",
        "preference": "x",
        "declarationType": "user-declared",
        "sourceContext": "s",
    });
    let with = |key: &str, value: Value| {
        let mut args = base.clone();
        args[key] = value;
        args
    };
    let without = |key: &str| {
        let mut args = base.clone();
        args.as_object_mut().unwrap().remove(key);
        args
    };
    let model = |extra: Value| {
        let mut args = with("declarationType", json!("model-inferred"));
        for (key, value) in extra.as_object().unwrap() {
            args[key] = value.clone();
        }
        args
    };
    let invalid = [
        // The confidence rule (§5.2.3, §10.3.3).
        model(json!({ "assertedBy": "m" })),
        model(json!({ "assertedBy": "m", "confidence": null })),
        model(json!({ "confidence": "high" })),
        model(json!({ "assertedBy": "  ", "confidence": "high" })),
        model(json!({ "assertedBy": "m", "confidence": "certain" })),
        with("confidence", json!("high")),
        // Missing or malformed fields.
        without("category"),
        without("preference"),
        without("declarationType"),
        without("sourceContext"),
        with("preference", json!("   ")),
        with("preference", json!(42)),
        with("declarationType", json!("guess")),
        with("category", json!("not_a_category")),
        with("category", json!("hcp-custom:")),
        with("dimension", json!(7)),
    ];
    for args in invalid {
        let error = h.err(&alice(), ADD_PREFERENCE, args.clone()).await;
        assert_eq!(error["type"], "malformed-request", "{args}: {error}");
    }
    // A Context Client cannot attest on an issuer's behalf (§3.7).
    let error = h
        .err(
            &alice(),
            ADD_PREFERENCE,
            with("declarationType", json!("issuer-attested")),
        )
        .await;
    assert_eq!(error["type"], "scope-denied");
    assert!(h.stored(&alice()).await.is_empty(), "nothing was written");
}

#[tokio::test]
async fn add_accepts_a_custom_category() {
    let h = harness().await;
    let entry = h
        .add(&alice(), "hcp-custom:garden", "I grow tomatoes.")
        .await;
    assert_eq!(entry["record"]["category"], "hcp-custom:garden");
}

#[tokio::test]
async fn provider_set_provenance_is_never_taken_from_the_request() {
    let h = harness().await;
    h.ok(&alice(), ADD_PREFERENCE, json!({
        "category": "general_preferences",
        "preference": "Use metric units.",
        "declarationType": "user-declared",
        "sourceContext": "conversation:real",
        // None of these is a field of the tool; each is ignored.
        "assertedBy": "someone-else",
        "assurance": "cryptographically-verified",
        "submittedByClient": { "id": "forged", "name": "Forged", "operator": { "id": "x", "name": "x" } },
        "authorizedUnder": "urn:uuid:forged",
        "recordedAt": "1999-01-01T00:00:00Z",
        "recordedByProvider": "https://elsewhere.example",
        "confirmations": [{ "disposition": "confirmed", "confirmedBy": { "id": "me" }, "confirmedAt": "1999-01-01T00:00:00Z" }],
        "record": { "status": "deprecated", "version": 9, "provenance": { "assertedBy": { "assurance": "authenticated" } } },
        "claim": { "issuer": { "id": "forged" }, "issuanceDate": "1999-01-01T00:00:00Z", "expirationDate": "2001-01-01T00:00:00Z" },
        "id": "urn:uuid:11111111-1111-4111-8111-111111111111",
    }))
    .await;
    let (_, stored) = h.stored(&alice()).await.remove(0);
    let record = &stored["record"];
    let provenance = &record["provenance"];
    assert_ne!(
        stored["id"],
        "urn:uuid:11111111-1111-4111-8111-111111111111"
    );
    assert_eq!(record["status"], "active");
    assert_eq!(record["version"], 1);
    assert_eq!(provenance["assertedBy"]["assurance"], "unverified");
    assert_eq!(
        provenance["submittedByClient"]["id"], "client_one",
        "from the OAuth client id"
    );
    assert_ne!(provenance["authorizedUnder"], "urn:uuid:forged");
    assert!(provenance["authorizedUnder"]
        .as_str()
        .unwrap()
        .contains("ordinary-access"));
    assert_eq!(
        provenance["recordedByProvider"],
        "https://hcp.withnative.ai"
    );
    assert_ne!(provenance["recordedAt"], "1999-01-01T00:00:00Z");
    assert_eq!(provenance["source"], "conversation:real");
    assert_eq!(provenance["confirmations"], json!([]));
    // A user-declared entry is asserted by the Context Subject, whatever the
    // client names (§5.2.3), and the issuer follows (§3.5).
    assert_ne!(provenance["assertedBy"]["id"], "someone-else");
    assert_eq!(
        stored["claim"]["issuer"]["id"],
        provenance["assertedBy"]["id"]
    );
    assert_eq!(stored["claim"]["issuanceDate"], provenance["recordedAt"]);
    assert_eq!(stored["claim"]["expirationDate"], Value::Null);
}

// ---- subject pseudonyms -----------------------------------------------------

#[tokio::test]
async fn each_client_sees_its_own_stable_pseudonym_for_the_person() {
    let h = harness().await;
    h.add(&alice(), "general_preferences", "I like short answers.")
        .await;
    h.add(
        &alice_two(),
        "general_preferences",
        "I like short summaries.",
    )
    .await;
    let subject_of = |entry: &Value| {
        entry["claim"]["subject"]["id"]
            .as_str()
            .unwrap()
            .to_string()
    };

    let one = h
        .search(&alice(), "short", json!(["general_preferences"]))
        .await;
    let two = h
        .search(&alice_two(), "short", json!(["general_preferences"]))
        .await;
    assert_eq!(one["entries"].as_array().unwrap().len(), 2);
    let ids_one: Vec<String> = one["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(subject_of)
        .collect();
    let ids_two: Vec<String> = two["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(subject_of)
        .collect();
    // Stable within a client, across entries and across calls.
    assert_eq!(ids_one[0], ids_one[1]);
    let again = h
        .search(&alice(), "short", json!(["general_preferences"]))
        .await;
    assert_eq!(subject_of(&again["entries"][0]), ids_one[0]);
    // Different between clients (§3.4).
    assert_eq!(ids_two[0], ids_two[1]);
    assert_ne!(ids_one[0], ids_two[0]);
    // And neither is the identifier the entry is stored with.
    let (_, stored) = h.stored(&alice()).await.remove(0);
    let held = stored["claim"]["subject"]["id"].as_str().unwrap();
    assert_ne!(held, ids_one[0]);
    assert_ne!(held, ids_two[0]);
    // A different person has a different pseudonym for the same client.
    h.add(&bob(), "general_preferences", "I like short replies.")
        .await;
    let bobs = h
        .search(&bob(), "short", json!(["general_preferences"]))
        .await;
    assert_ne!(subject_of(&bobs["entries"][0]), ids_one[0]);
    // The same entry fetched by id shows the fetching client's pseudonym.
    let entry_id = one["entries"][0]["id"].as_str().unwrap();
    let got = h
        .ok(
            &alice_two(),
            GET_PREFERENCE,
            json!({ "entryId": entry_id, "purpose": "p" }),
        )
        .await;
    assert_eq!(subject_of(&got["entry"]), ids_two[0]);
}

// ---- search -----------------------------------------------------------------

#[tokio::test]
async fn search_returns_the_relevant_entries_in_relevance_order() {
    let h = harness().await;
    h.add(
        &alice(),
        "general_preferences",
        "I prefer vegetarian restaurants.",
    )
    .await;
    h.add(
        &alice(),
        "general_preferences",
        "I prefer window seats on long flights.",
    )
    .await;
    h.add(
        &alice(),
        "general_preferences",
        "I prefer quiet flights, window seats, and morning flights.",
    )
    .await;
    let result = h
        .search(
            &alice(),
            "window seats on morning flights",
            json!(["general_preferences"]),
        )
        .await;
    let preferences: Vec<&str> = result["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["claim"]["subject"]["preference"].as_str().unwrap())
        .collect();
    assert_eq!(
        preferences,
        [
            "I prefer quiet flights, window seats, and morning flights.",
            "I prefer window seats on long flights."
        ],
        "most overlap first; the unrelated entry is not returned"
    );
    assert_eq!(result["categoriesSearched"], json!(["general_preferences"]));
    assert!(result["retrievalId"]
        .as_str()
        .unwrap()
        .starts_with("urn:uuid:"));
    assert!(result["timestamp"].as_str().unwrap().ends_with('Z'));
    let other = h
        .search(
            &alice(),
            "window seats on morning flights",
            json!(["general_preferences"]),
        )
        .await;
    assert_ne!(
        result["retrievalId"], other["retrievalId"],
        "a fresh retrievalId each time"
    );
}

#[tokio::test]
async fn search_stays_inside_the_categories_named() {
    let h = harness().await;
    h.add(
        &alice(),
        "health_context",
        "I need high arch support in shoes.",
    )
    .await;
    h.add(&alice(), "work_context", "I wear safety shoes on site.")
        .await;
    let result = h.search(&alice(), "shoes", json!(["work_context"])).await;
    let entries = result["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["record"]["category"], "work_context");
    let both = h
        .search(&alice(), "shoes", json!(["work_context", "health_context"]))
        .await;
    assert_eq!(both["entries"].as_array().unwrap().len(), 2);
    assert_eq!(
        both["categoriesSearched"],
        json!(["work_context", "health_context"])
    );
}

#[tokio::test]
async fn search_rejects_a_bad_request() {
    let h = harness().await;
    let good = json!({ "query": "q", "categories": ["general_preferences"], "purpose": "p" });
    let with = |key: &str, value: Value| {
        let mut args = good.clone();
        args[key] = value;
        args
    };
    let without = |key: &str| {
        let mut args = good.clone();
        args.as_object_mut().unwrap().remove(key);
        args
    };
    for args in [
        without("query"),
        without("categories"),
        without("purpose"),
        with("purpose", json!("  ")),
        with("categories", json!([])),
        with("categories", json!("general_preferences")),
        with("categories", json!([1])),
        with(
            "categories",
            json!(["general_preferences", "not_a_category"]),
        ),
        with("maxEntries", json!(0)),
        with("maxEntries", json!(-3)),
        with("maxEntries", json!("five")),
        with("responseDetail", json!("verbose")),
    ] {
        let error = h.err(&alice(), SEARCH_PREFERENCES, args.clone()).await;
        assert_eq!(error["type"], "malformed-request", "{args}: {error}");
    }
}

#[tokio::test]
async fn search_honours_the_quantity_bound_and_never_pads() {
    let h = harness().await;
    for n in 0..25 {
        h.add(
            &alice(),
            "general_preferences",
            &format!("Tea number {n} is welcome."),
        )
        .await;
    }
    h.add(&alice(), "general_preferences", "Coffee is fine too.")
        .await;
    let count = |result: &Value| result["entries"].as_array().unwrap().len();
    let search = |extra: Value| {
        let mut args =
            json!({ "query": "tea", "categories": ["general_preferences"], "purpose": "p" });
        for (key, value) in extra.as_object().unwrap() {
            args[key] = value.clone();
        }
        args
    };
    assert_eq!(
        count(&h.ok(&alice(), SEARCH_PREFERENCES, search(json!({}))).await),
        5,
        "default 5"
    );
    assert_eq!(
        count(
            &h.ok(
                &alice(),
                SEARCH_PREFERENCES,
                search(json!({ "maxEntries": 3 }))
            )
            .await
        ),
        3
    );
    assert_eq!(
        count(
            &h.ok(
                &alice(),
                SEARCH_PREFERENCES,
                search(json!({ "maxEntries": 20 }))
            )
            .await
        ),
        20
    );
    assert_eq!(
        count(
            &h.ok(
                &alice(),
                SEARCH_PREFERENCES,
                search(json!({ "maxEntries": 1000 }))
            )
            .await
        ),
        20,
        "ceiling 20"
    );

    // Two relevant entries, ten asked for: two returned, not ten.
    let h = harness().await;
    h.add(
        &alice(),
        "general_preferences",
        "Oolong tea in the morning.",
    )
    .await;
    h.add(&alice(), "general_preferences", "Green tea after lunch.")
        .await;
    for n in 0..8 {
        h.add(
            &alice(),
            "general_preferences",
            &format!("Unrelated note {n}."),
        )
        .await;
    }
    let result = h
        .ok(
            &alice(),
            SEARCH_PREFERENCES,
            search(json!({ "maxEntries": 10 })),
        )
        .await;
    assert_eq!(count(&result), 2);
    assert!(
        result.get("nextCursor").is_none() && result.get("cursor").is_none(),
        "no pagination"
    );
    let nothing = h
        .search(&alice(), "submarines", json!(["general_preferences"]))
        .await;
    assert_eq!(count(&nothing), 0);
}

#[tokio::test]
async fn search_in_minimal_mode_returns_only_id_category_dimension_and_value() {
    let h = harness().await;
    let added = h
        .ok(&alice(), ADD_PREFERENCE, json!({ "category": "health_context", "dimension": "Footwear Support", "preference": "High arch support in footwear.", "declarationType": "user-declared", "sourceContext": "s" }))
        .await;
    h.add(&alice(), "health_context", "Footwear: no dimension here.")
        .await;
    let result = h
        .ok(&alice(), SEARCH_PREFERENCES, json!({ "query": "footwear", "categories": ["health_context"], "purpose": "p", "responseDetail": "minimal" }))
        .await;
    let entries = result["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    let with_dimension = entries.iter().find(|e| e["id"] == added["id"]).unwrap();
    assert_eq!(
        with_dimension,
        &json!({
            "id": added["id"],
            "record": { "category": "health_context", "dimension": "Footwear Support" },
            "value": "High arch support in footwear.",
        })
    );
    let without = entries.iter().find(|e| e["id"] != added["id"]).unwrap();
    assert_eq!(without["record"]["dimension"], Value::Null);
    // The report is the one a full response carries (§5.3).
    let full = h
        .search(&alice(), "footwear", json!(["health_context"]))
        .await;
    assert_eq!(result["minimization"], full["minimization"]);
}

#[tokio::test]
async fn context_clients_get_redacted_entries_and_a_report_without_counts() {
    let h = harness().await;
    let added = h
        .add(&alice(), "general_preferences", "Reply in plain English.")
        .await;
    // The person confirms it (a later slice will add the operation; the
    // confirmation is trusted state, so it lands in the events).
    h.inject_version(&alice(), added["id"].as_str().unwrap(), |entry| {
        entry["record"]["provenance"]["confirmations"] = json!([
            { "disposition": "confirmed", "confirmedBy": { "id": "person" }, "confirmedAt": "2026-10-01T09:00:00Z" }
        ]);
    })
    .await;

    let result = h
        .search(&alice(), "plain english", json!(["general_preferences"]))
        .await;
    let entry = &result["entries"][0];
    let record = &entry["record"];
    let provenance = &record["provenance"];
    // Omitted (§7.4).
    assert!(provenance.get("source").is_none());
    assert!(provenance.get("submittedByClient").is_none());
    assert!(provenance.get("authorizedUnder").is_none());
    assert!(provenance["assertedBy"].get("id").is_none());
    assert!(entry["claim"].get("issuer").is_none());
    assert!(provenance["confirmations"][0].get("confirmedBy").is_none());
    // Kept: what a client needs to judge standing.
    assert_eq!(record["declarationType"], "user-declared");
    assert_eq!(provenance["assertedBy"]["assurance"], "unverified");
    assert_eq!(provenance["confirmations"][0]["disposition"], "confirmed");
    assert_eq!(
        provenance["confirmations"][0]["confirmedAt"],
        "2026-10-01T09:00:00Z"
    );
    assert!(provenance["recordedAt"].is_string());
    assert!(provenance["recordedByProvider"].is_string());
    assert!(entry["claim"]["issuanceDate"].is_string());

    // The report names every omitted field and carries no count (§7.5).
    assert_eq!(
        result["minimization"],
        json!({
            "method": "lexical",
            "redactedFields": [
                "record.provenance.source",
                "record.provenance.submittedByClient",
                "record.provenance.authorizedUnder",
                "record.provenance.assertedBy.id",
                "record.provenance.confirmations[].confirmedBy",
                "claim.issuer"
            ]
        })
    );
    let mut keys: Vec<&String> = result.as_object().unwrap().keys().collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "categoriesSearched",
            "entries",
            "minimization",
            "retrievalId",
            "timestamp"
        ]
    );

    // Redaction is a property of the response, not of storage (§7.4).
    let (_, stored) = h.stored(&alice()).await.remove(0);
    assert_eq!(
        stored["record"]["provenance"]["source"],
        "conversation:test"
    );
    assert_eq!(
        stored["record"]["provenance"]["submittedByClient"]["id"],
        "client_one"
    );
    assert_eq!(
        stored["record"]["provenance"]["confirmations"][0]["confirmedBy"]["id"],
        "person"
    );

    // The add result is an entry returned to a Context Client too.
    assert!(added["record"]["provenance"]
        .get("submittedByClient")
        .is_none());
    assert!(added["claim"].get("issuer").is_none());
}

// ---- get --------------------------------------------------------------------

#[tokio::test]
async fn get_returns_the_entry_with_a_report_whose_method_is_none() {
    let h = harness().await;
    let added = h
        .add(&alice(), "values_and_ethics", "No gambling content.")
        .await;
    let got = h
        .ok(
            &alice(),
            GET_PREFERENCE,
            json!({ "entryId": added["id"], "purpose": "checking a boundary" }),
        )
        .await;
    assert_eq!(got["entry"]["id"], added["id"]);
    assert_eq!(
        got["entry"]["claim"]["subject"]["preference"],
        "No gambling content."
    );
    assert!(got["entry"]["record"]["provenance"].get("source").is_none());
    assert!(got["retrievalId"]
        .as_str()
        .unwrap()
        .starts_with("urn:uuid:"));
    assert_eq!(got["minimization"]["method"], "none");
    assert_eq!(
        got["minimization"]["redactedFields"]
            .as_array()
            .unwrap()
            .len(),
        6
    );
    assert!(got["timestamp"].is_string());
    let error = h
        .err(&alice(), GET_PREFERENCE, json!({ "entryId": added["id"] }))
        .await;
    assert_eq!(error["type"], "malformed-request", "purpose is required");
    let error = h
        .err(
            &alice(),
            GET_PREFERENCE,
            json!({ "entryId": added["id"], "purpose": "p", "version": 0 }),
        )
        .await;
    assert_eq!(error["type"], "malformed-request");
}

#[tokio::test]
async fn not_authorized_cannot_be_told_from_not_found() {
    let h = harness().await;
    let mine = h
        .add(&alice(), "general_preferences", "Visible to me.")
        .await;
    let bobs = h.add(&bob(), "general_preferences", "Bob's entry.").await;
    let deleted = h
        .add(&alice(), "general_preferences", "Soon deleted.")
        .await;
    h.ok(
        &alice(),
        DELETE_PREFERENCE,
        json!({ "entryId": deleted["id"], "reason": "r" }),
    )
    .await;
    let conflicted = h.add(&alice(), "general_preferences", "Quarantined.").await;
    h.inject_status(
        &alice(),
        conflicted["id"].as_str().unwrap(),
        "conflicted",
        "conflict",
    )
    .await;
    let expired = h.add(&alice(), "general_preferences", "Lapsed.").await;
    h.inject_version(&alice(), expired["id"].as_str().unwrap(), |b| {
        b["claim"]["expirationDate"] = json!("2020-01-01T00:00:00Z")
    })
    .await;
    // Another kind of record in the same account is not an entry.
    let note = Box::pin(crate::mcp::tools::lifecycle::create_record(
        h.db.clone(),
        alice(),
        json!({ "type": "Document", "kind": "note", "name": "Plain note", "reason": "t" }),
    ))
    .await
    .unwrap();

    let absent = h
        .frame(
            &alice(),
            GET_PREFERENCE,
            json!({ "entryId": "urn:uuid:22222222-2222-4222-8222-222222222222", "purpose": "p" }),
        )
        .await;
    assert_eq!(absent["structuredContent"]["type"], "scope-denied");
    for id in [
        bobs["id"].clone(),
        deleted["id"].clone(),
        conflicted["id"].clone(),
        expired["id"].clone(),
        json!(format!("urn:uuid:{}", note["id"].as_str().unwrap())),
        json!("not-a-urn"),
        json!("urn:uuid:NOT-A-UUID"),
    ] {
        let frame = h
            .frame(
                &alice(),
                GET_PREFERENCE,
                json!({ "entryId": id, "purpose": "p" }),
            )
            .await;
        assert_eq!(frame, absent, "{id}");
    }
    // The same for versions that do not exist, and for changes.
    let no_version = h
        .frame(
            &alice(),
            GET_PREFERENCE,
            json!({ "entryId": mine["id"], "purpose": "p", "version": 9 }),
        )
        .await;
    assert_eq!(no_version, absent);
    for (tool, args) in [
        (
            UPDATE_PREFERENCE,
            json!({ "updatedPreference": "x", "reason": "r" }),
        ),
        (DELETE_PREFERENCE, json!({ "reason": "r" })),
    ] {
        for id in [
            bobs["id"].clone(),
            deleted["id"].clone(),
            expired["id"].clone(),
            json!("urn:uuid:22222222-2222-4222-8222-222222222222"),
        ] {
            let mut args = args.clone();
            args["entryId"] = id.clone();
            assert_eq!(h.frame(&alice(), tool, args).await, absent, "{tool} {id}");
        }
    }
    // Nothing of Bob's changed.
    let (_, still) = h.stored(&bob()).await.remove(0);
    assert_eq!(still["record"]["status"], "active");
    assert_eq!(still["record"]["version"], 1);
}

#[tokio::test]
async fn search_leaves_out_deleted_conflicted_and_expired_entries() {
    let h = harness().await;
    let keep = h
        .add(
            &alice(),
            "general_preferences",
            "Banana smoothie is welcome.",
        )
        .await;
    let deleted = h
        .add(&alice(), "general_preferences", "Banana bread is welcome.")
        .await;
    let conflicted = h
        .add(&alice(), "general_preferences", "Banana split is welcome.")
        .await;
    let expired = h
        .add(
            &alice(),
            "general_preferences",
            "Banana pudding is welcome.",
        )
        .await;
    h.ok(
        &alice(),
        DELETE_PREFERENCE,
        json!({ "entryId": deleted["id"], "reason": "r" }),
    )
    .await;
    h.inject_status(
        &alice(),
        conflicted["id"].as_str().unwrap(),
        "conflicted",
        "conflict",
    )
    .await;
    h.inject_version(&alice(), expired["id"].as_str().unwrap(), |b| {
        b["claim"]["expirationDate"] = json!("2020-01-01T00:00:00Z")
    })
    .await;
    let result = h
        .search(&alice(), "banana", json!(["general_preferences"]))
        .await;
    let ids: Vec<&Value> = result["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| &e["id"])
        .collect();
    assert_eq!(ids, [&keep["id"]]);
    // Held, not removed.
    assert_eq!(h.stored(&alice()).await.len(), 4);
}

// ---- update and versions ----------------------------------------------------

#[tokio::test]
async fn update_makes_a_new_version_and_earlier_versions_stay_readable() {
    let h = harness().await;
    let added = h
        .add(&alice(), "general_preferences", "Reply in French.")
        .await;
    let id = added["id"].clone();
    let v2 = h
        .ok(&alice_two(), UPDATE_PREFERENCE, json!({ "entryId": id, "updatedPreference": "Reply in Spanish.", "reason": "changed my mind", "sourceContext": "conversation:2" }))
        .await;
    assert_eq!(v2["id"], id, "the id is stable");
    assert_eq!(v2["record"]["version"], 2);
    assert_eq!(v2["record"]["previousVersion"], 1);
    assert_eq!(v2["record"]["status"], "active");
    assert_eq!(v2["claim"]["subject"]["preference"], "Reply in Spanish.");
    let v3 = h
        .ok(
            &alice(),
            UPDATE_PREFERENCE,
            json!({ "entryId": id, "updatedPreference": "Reply in German.", "reason": "again" }),
        )
        .await;
    assert_eq!(v3["record"]["version"], 3);
    assert_eq!(v3["record"]["previousVersion"], 2);

    let current = h
        .ok(
            &alice(),
            GET_PREFERENCE,
            json!({ "entryId": id, "purpose": "p" }),
        )
        .await;
    assert_eq!(current["entry"]["record"]["version"], 3);
    for (version, text) in [
        (1, "Reply in French."),
        (2, "Reply in Spanish."),
        (3, "Reply in German."),
    ] {
        let got = h
            .ok(
                &alice(),
                GET_PREFERENCE,
                json!({ "entryId": id, "purpose": "p", "version": version }),
            )
            .await;
        assert_eq!(got["entry"]["record"]["version"], version);
        assert_eq!(got["entry"]["claim"]["subject"]["preference"], text);
        assert_eq!(got["minimization"]["method"], "none");
        assert!(
            got["entry"]["record"]["provenance"]
                .get("submittedByClient")
                .is_none(),
            "earlier versions are redacted too"
        );
    }
    // Search sees only the current version.
    let found = h
        .search(&alice(), "reply language", json!(["general_preferences"]))
        .await;
    assert_eq!(found["entries"].as_array().unwrap().len(), 1);
    assert_eq!(
        found["entries"][0]["claim"]["subject"]["preference"],
        "Reply in German."
    );

    // Each version has its own provenance; the stored current one is v3's.
    let (record_id, stored) = h.stored(&alice()).await.remove(0);
    assert_eq!(
        stored["record"]["provenance"]["submittedByClient"]["id"],
        "client_one"
    );
    assert_eq!(
        h.facet(&alice(), &record_id, "hcp2.version")
            .await
            .as_deref(),
        Some("3")
    );
    let second = h
        .ok(
            &alice(),
            GET_PREFERENCE,
            json!({ "entryId": id, "purpose": "p", "version": 2 }),
        )
        .await;
    assert_eq!(
        second["entry"]["claim"]["issuanceDate"],
        v2["claim"]["issuanceDate"]
    );
}

#[tokio::test]
async fn a_revision_is_attributed_to_its_own_client_and_starts_unconfirmed() {
    let h = harness().await;
    let added = h
        .add(&alice(), "general_preferences", "Call me Rick.")
        .await;
    // Version 2 carries a confirmation (a later slice's operation), so the
    // revision after it has something it must not inherit.
    h.inject_version(&alice(), added["id"].as_str().unwrap(), |b| {
        b["record"]["provenance"]["confirmations"] = json!([
            { "disposition": "confirmed", "confirmedBy": { "id": "person" }, "confirmedAt": "2026-10-01T09:00:00Z" }
        ]);
    })
    .await;
    h.ok(&alice_two(), UPDATE_PREFERENCE, json!({ "entryId": added["id"], "updatedPreference": "Call me Richard.", "reason": "r", "sourceContext": "conversation:9" }))
        .await;
    let (_, stored) = h.stored(&alice()).await.remove(0);
    let provenance = &stored["record"]["provenance"];
    assert_eq!(provenance["submittedByClient"]["id"], "client_two");
    assert_eq!(provenance["source"], "conversation:9");
    assert_eq!(
        provenance["confirmations"],
        json!([]),
        "no inherited endorsement (§3.8)"
    );
    assert_eq!(provenance["assertedBy"]["assurance"], "unverified");
    assert_eq!(stored["claim"]["issuanceDate"], provenance["recordedAt"]);
    // Version 2 still carries the confirmation it earned.
    let first = h
        .ok(
            &alice(),
            GET_PREFERENCE,
            json!({ "entryId": added["id"], "purpose": "p", "version": 2 }),
        )
        .await;
    assert_eq!(
        first["entry"]["record"]["provenance"]["confirmations"][0]["disposition"],
        "confirmed"
    );
}

#[tokio::test]
async fn an_update_without_a_source_does_not_claim_the_old_one() {
    let h = harness().await;
    let added = h
        .add(&alice(), "general_preferences", "Call me Rick.")
        .await;
    h.ok(
        &alice(),
        UPDATE_PREFERENCE,
        json!({ "entryId": added["id"], "updatedPreference": "Call me R.", "reason": "r" }),
    )
    .await;
    let (_, stored) = h.stored(&alice()).await.remove(0);
    assert_eq!(stored["record"]["provenance"]["source"], "unspecified");
}

#[tokio::test]
async fn update_applies_the_confidence_rule_to_the_declaration_type_it_ends_with() {
    let h = harness().await;
    let inferred = h
        .ok(&alice(), ADD_PREFERENCE, json!({ "category": "general_preferences", "preference": "Likes jazz.", "declarationType": "model-inferred", "confidence": "low", "assertedBy": "model-a", "sourceContext": "s" }))
        .await;
    let id = inferred["id"].clone();
    let update = |extra: Value| {
        let mut args =
            json!({ "entryId": id, "updatedPreference": "Likes jazz and blues.", "reason": "r" });
        for (key, value) in extra.as_object().unwrap() {
            args[key] = value.clone();
        }
        args
    };
    // Unchanged type is still model-inferred: it needs its confidence and asserter.
    for args in [
        update(json!({})),
        update(json!({ "confidence": "high" })),
        update(json!({ "assertedBy": "model-b" })),
        update(json!({ "declarationType": "user-declared", "confidence": "high" })),
        update(json!({ "declarationType": "model-inferred", "assertedBy": "m" })),
    ] {
        let error = h.err(&alice(), UPDATE_PREFERENCE, args.clone()).await;
        assert_eq!(error["type"], "malformed-request", "{args}: {error}");
    }
    let error = h
        .err(
            &alice(),
            UPDATE_PREFERENCE,
            update(json!({ "declarationType": "issuer-attested" })),
        )
        .await;
    assert_eq!(error["type"], "scope-denied");
    let ok = h
        .ok(
            &alice(),
            UPDATE_PREFERENCE,
            update(json!({ "confidence": "high", "assertedBy": "model-b" })),
        )
        .await;
    assert_eq!(ok["record"]["declarationType"], "model-inferred");
    assert_eq!(ok["record"]["confidence"], "high");
    // Back to the person's own word: confidence goes.
    let own = h
        .ok(
            &alice(),
            UPDATE_PREFERENCE,
            update(json!({ "declarationType": "user-declared" })),
        )
        .await;
    assert_eq!(own["record"]["declarationType"], "user-declared");
    assert_eq!(own["record"]["confidence"], Value::Null);
    assert_eq!(own["record"]["version"], 3);
    let (record_id, stored) = h.stored(&alice()).await.remove(0);
    assert_eq!(
        h.facet(&alice(), &record_id, "hcp2.confidence").await,
        None,
        "the facet follows"
    );
    assert_ne!(
        stored["record"]["provenance"]["assertedBy"]["id"],
        "model-b"
    );
}

#[tokio::test]
async fn update_refuses_an_entry_whose_current_version_the_person_rejected() {
    let h = harness().await;
    let added = h
        .add(&alice(), "general_preferences", "Always cc my manager.")
        .await;
    let absent = h
        .frame(&alice(), UPDATE_PREFERENCE, json!({ "entryId": "urn:uuid:22222222-2222-4222-8222-222222222222", "updatedPreference": "x", "reason": "r" }))
        .await;
    h.inject_version(&alice(), added["id"].as_str().unwrap(), |b| {
        b["record"]["provenance"]["confirmations"] = json!([
            { "disposition": "rejected", "confirmedBy": { "id": "person" }, "confirmedAt": "2026-10-01T09:00:00Z" }
        ]);
    })
    .await;
    let frame = h
        .frame(&alice(), UPDATE_PREFERENCE, json!({ "entryId": added["id"], "updatedPreference": "Never cc my manager.", "reason": "r" }))
        .await;
    assert_eq!(frame, absent, "indistinguishable from an absent entry");
    let (_, stored) = h.stored(&alice()).await.remove(0);
    assert_eq!(stored["record"]["version"], 2, "the update changed nothing");
    assert_eq!(
        stored["claim"]["subject"]["preference"],
        "Always cc my manager."
    );
}

#[tokio::test]
async fn update_rejects_a_bad_request() {
    let h = harness().await;
    let added = h.add(&alice(), "general_preferences", "x y z").await;
    for args in [
        json!({ "updatedPreference": "x", "reason": "r" }),
        json!({ "entryId": added["id"], "reason": "r" }),
        json!({ "entryId": added["id"], "updatedPreference": "x" }),
        json!({ "entryId": added["id"], "updatedPreference": "  ", "reason": "r" }),
        json!({ "entryId": added["id"], "updatedPreference": "x", "reason": "  " }),
        json!({ "entryId": added["id"], "updatedPreference": "x", "reason": "r", "declarationType": "guess" }),
    ] {
        let error = h.err(&alice(), UPDATE_PREFERENCE, args.clone()).await;
        assert_eq!(error["type"], "malformed-request", "{args}: {error}");
    }
}

#[tokio::test]
async fn concurrent_updates_never_skip_or_reuse_a_version() {
    let h = harness().await;
    let added = h.add(&alice(), "general_preferences", "Start.").await;
    let (first_client, second_client) = (alice(), alice_two());
    let one = h.ok(
        &first_client,
        UPDATE_PREFERENCE,
        json!({ "entryId": added["id"], "updatedPreference": "First.", "reason": "r" }),
    );
    let two = h.ok(
        &second_client,
        UPDATE_PREFERENCE,
        json!({ "entryId": added["id"], "updatedPreference": "Second.", "reason": "r" }),
    );
    let (a, b) = tokio::join!(one, two);
    let mut versions = [
        a["record"]["version"].as_u64().unwrap(),
        b["record"]["version"].as_u64().unwrap(),
    ];
    versions.sort();
    assert_eq!(versions, [2, 3]);
    for version in [1, 2, 3] {
        h.ok(
            &alice(),
            GET_PREFERENCE,
            json!({ "entryId": added["id"], "purpose": "p", "version": version }),
        )
        .await;
    }
}

// ---- delete -----------------------------------------------------------------

#[tokio::test]
async fn delete_is_soft_hides_the_entry_and_keeps_it_for_the_person() {
    let h = harness().await;
    let added = h
        .add(
            &alice(),
            "general_preferences",
            "Cilantro tastes like soap.",
        )
        .await;
    let deleted = h
        .ok(
            &alice(),
            DELETE_PREFERENCE,
            json!({ "entryId": added["id"], "reason": "no longer true" }),
        )
        .await;
    assert_eq!(deleted["entryId"], added["id"]);
    assert_eq!(deleted["status"], "deleted");
    assert!(deleted["timestamp"].is_string());

    let found = h
        .search(&alice(), "cilantro", json!(["general_preferences"]))
        .await;
    assert!(found["entries"].as_array().unwrap().is_empty());
    let error = h
        .err(
            &alice(),
            GET_PREFERENCE,
            json!({ "entryId": added["id"], "purpose": "p" }),
        )
        .await;
    assert_eq!(error["type"], "scope-denied");
    let error = h
        .err(
            &alice(),
            UPDATE_PREFERENCE,
            json!({ "entryId": added["id"], "updatedPreference": "x", "reason": "r" }),
        )
        .await;
    assert_eq!(error["type"], "scope-denied");
    let error = h
        .err(
            &alice(),
            DELETE_PREFERENCE,
            json!({ "entryId": added["id"], "reason": "again" }),
        )
        .await;
    assert_eq!(error["type"], "scope-denied", "already hidden");

    // Held and visible to the person: the record is still there, marked deleted,
    // at the same version.
    let (record_id, stored) = h.stored(&alice()).await.remove(0);
    assert_eq!(stored["record"]["status"], "deleted");
    assert_eq!(stored["record"]["version"], 1);
    assert_eq!(
        stored["claim"]["subject"]["preference"],
        "Cilantro tastes like soap."
    );
    assert_eq!(
        h.facet(&alice(), &record_id, "hcp2.status")
            .await
            .as_deref(),
        Some("deleted")
    );
}

#[tokio::test]
async fn delete_needs_an_entry_id_and_a_reason() {
    let h = harness().await;
    let added = h.add(&alice(), "general_preferences", "x y z").await;
    for args in [
        json!({ "reason": "r" }),
        json!({ "entryId": added["id"] }),
        json!({ "entryId": added["id"], "reason": " " }),
    ] {
        let error = h.err(&alice(), DELETE_PREFERENCE, args.clone()).await;
        assert_eq!(error["type"], "malformed-request", "{args}");
    }
    let found = h
        .search(&alice(), "x y z", json!(["general_preferences"]))
        .await;
    assert_eq!(
        found["entries"].as_array().unwrap().len(),
        0,
        "single letters are not search terms"
    );
    let got = h.ok(&alice(), GET_PREFERENCE, get_args(&added)).await;
    assert_eq!(
        got["entry"]["id"], added["id"],
        "add disclosed the entry even without search terms"
    );
    assert_eq!(h.stored(&alice()).await[0].1["record"]["status"], "active");
}

// ---- a historical version is subject to the same visibility ------------------

#[tokio::test]
async fn an_earlier_version_is_hidden_when_it_was_conflicted_or_expired() {
    let h = harness().await;
    let added = h
        .add(&alice(), "general_preferences", "Mushrooms are fine.")
        .await;
    let id = added["id"].clone();
    let urn = id.as_str().unwrap();
    // Version 1 was conflicted when it was superseded.
    h.inject_status(&alice(), urn, "conflicted", "conflict")
        .await;
    h.ok(
        &alice_two(),
        UPDATE_PREFERENCE,
        json!({ "entryId": id, "updatedPreference": "Mushrooms are great.", "reason": "r" }),
    )
    .await;
    // C2 releases the revised version atomically; version 1 stays conflicted.
    let current = h
        .ok(
            &alice(),
            GET_PREFERENCE,
            json!({ "entryId": id, "purpose": "p" }),
        )
        .await;
    assert_eq!(current["entry"]["record"]["version"], 2);
    let error = h
        .err(
            &alice(),
            GET_PREFERENCE,
            json!({ "entryId": id, "purpose": "p", "version": 1 }),
        )
        .await;
    assert_eq!(error["type"], "scope-denied");

    // And one that had already expired.
    let added = h
        .add(&alice(), "general_preferences", "Olives are fine.")
        .await;
    let id = added["id"].clone();
    let urn = id.as_str().unwrap();
    h.inject_version(&alice(), urn, |b| {
        b["claim"]["expirationDate"] = json!("2020-01-01T00:00:00Z")
    })
    .await;
    h.inject_version(&alice(), urn, |b| {
        b["claim"]["expirationDate"] = Value::Null;
        b["claim"]["subject"]["preference"] = json!("Olives are great.");
    })
    .await;
    let current = h
        .ok(
            &alice(),
            GET_PREFERENCE,
            json!({ "entryId": id, "purpose": "p" }),
        )
        .await;
    assert_eq!(current["entry"]["record"]["version"], 3);
    for version in [2, 1] {
        let got = h
            .frame(
                &alice(),
                GET_PREFERENCE,
                json!({ "entryId": id, "purpose": "p", "version": version }),
            )
            .await;
        // Version 1 was never expired; version 2 had lapsed.
        assert_eq!(got["isError"], version == 2, "version {version}: {got}");
    }
}

// ---- Native refusals read as not authorized ----------------------------------

#[test]
fn native_refusals_are_not_authorized_and_other_failures_are_not() {
    let absent = error_frame(SCOPE_DENIED, SCOPE_DENIED_DETAIL);
    for message in [
        "record 'abc' requires Manage; caller has None",
        "update_record: record abc requires edit capability; caller has view capability",
        "update_record: record abc does not exist or is not visible to the caller",
        "create_record: caller has no portable account binding",
    ] {
        assert_eq!(fail(Error::engine(message)).unwrap(), absent, "{message}");
    }
    let internal = fail(Error::engine("disk on fire")).unwrap();
    assert_eq!(
        internal["structuredContent"]["type"],
        "native:internal-error"
    );
    assert_ne!(internal, absent);
    assert!(
        fail(Error::DeploymentReadOnly(
            crate::error::DeploymentReadOnlyOperation::server("frozen")
        ))
        .is_err(),
        "fences go to the transport"
    );
    let fenced = failure_frame(&Error::DeploymentReadOnly(
        crate::error::DeploymentReadOnlyOperation::server("frozen"),
    ));
    assert_eq!(
        fenced["structuredContent"]["type"],
        "native:deployment-read-only"
    );
}

// ---- reading many entries ------------------------------------------------------

#[tokio::test]
async fn search_reads_many_large_entries() {
    let h = harness().await;
    // Forty entries of about 50 KiB each (the person keeps notes in metadata):
    // four megabytes of events, folded for one search.
    let note = "n".repeat(50 * 1024);
    for n in 0..40 {
        let added = h
            .add(
                &alice(),
                "general_preferences",
                &format!("Sparkling water number {n}."),
            )
            .await;
        h.inject_version(&alice(), added["id"].as_str().unwrap(), |entry| {
            entry["record"]["metadata"] = json!({ "notes": note });
        })
        .await;
    }
    let result = h
        .search(&alice(), "sparkling water", json!(["general_preferences"]))
        .await;
    assert_eq!(result["entries"].as_array().unwrap().len(), 5);
}

// ---- pseudonyms come from the server key --------------------------------------

fn person_hash(account: &str) -> String {
    store::sha256_hex(account)
}

fn subject_of(entry: &Value) -> String {
    entry["claim"]["subject"]["id"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn pseudonyms_come_from_the_server_key_and_nothing_is_stored_for_them() {
    let h = harness().await;
    // Notes planted in shared space with Alice's facets have no say.
    for name in ["planted before", "planted after"] {
        Box::pin(crate::mcp::tools::lifecycle::create_record(
            h.db.clone(),
            bob(),
            json!({
                "type": "Document", "kind": "note", "name": name, "reason": "attack",
                "body": "not yours",
                "facets": {
                    "hcp2.role": "pseudonym-key",
                    "hcp2.person": person_hash("acct:alice"),
                    "hcp2.pseudonym_key": "00".repeat(32),
                },
            }),
        ))
        .await
        .unwrap();
    }
    h.add(&alice(), "general_preferences", "Plain words please.")
        .await;
    let first = h
        .search(&alice(), "plain words", json!(["general_preferences"]))
        .await;
    let expected = test_key().pseudonym("acct:alice", "client_one");
    assert_eq!(subject_of(&first["entries"][0]), expected);
    let again = h
        .search(&alice(), "plain words", json!(["general_preferences"]))
        .await;
    assert_eq!(subject_of(&again["entries"][0]), expected, "no rekeying");

    // Another deployment secret gives every pseudonym a different value.
    let mut rotated = ToolRegistry::new();
    register_hcp_v2_tools(
        &mut rotated,
        PseudonymKey::from_secret(&[0x43; 32]).unwrap(),
    )
    .unwrap();
    let after = call_tool(
        &rotated,
        h.db.clone(),
        alice(),
        SEARCH_PREFERENCES,
        json!({ "query": "plain words", "categories": ["general_preferences"], "purpose": "p" }),
        None,
    )
    .await
    .unwrap();
    assert_eq!(after["isError"], false);
    assert_ne!(
        subject_of(&after["structuredContent"]["entries"][0]),
        expected
    );
}

#[tokio::test]
async fn the_entry_bound_is_inside_nativess_cell_limit_and_enforced_on_write() {
    assert_eq!(limits::MAX_ENTRY_BYTES, 64 * 1024);
    let h = harness().await;
    // The largest preference, all control characters (six bytes each once
    // escaped), still fits and reads back.
    let control = "\u{1}".repeat(8 * 1024);
    let added = h.add(&alice(), "general_preferences", &control).await;
    let got = h
        .ok(
            &alice(),
            GET_PREFERENCE,
            json!({ "entryId": added["id"], "purpose": "p" }),
        )
        .await;
    assert_eq!(got["entry"]["claim"]["subject"]["preference"], control);
    let (_, stored) = h.stored(&alice()).await.remove(0);
    assert!(stored.to_string().len() <= limits::MAX_ENTRY_BYTES);

    // Everything at its largest at once does not fit and is refused.
    let error = h
        .err(
            &alice(),
            ADD_PREFERENCE,
            json!({
                "category": "general_preferences",
                "dimension": "\u{1}".repeat(2 * 1024),
                "preference": control,
                "declarationType": "user-declared",
                "sourceContext": "\u{1}".repeat(2 * 1024),
            }),
        )
        .await;
    assert_eq!(error["type"], "malformed-request");
    assert!(error["detail"].as_str().unwrap().contains("65536"));
}

// ---- the record is a view: nothing in it is evidence --------------------------

#[tokio::test]
async fn records_that_merely_look_like_entries_are_never_returned() {
    let h = harness().await;
    let genuine = h
        .add(&alice(), "general_preferences", "Genuine tea preference.")
        .await;
    let (_, genuine_body) = h.stored(&alice()).await.remove(0);
    let forged = |text: &str| -> (String, Value) {
        let id = uuid::Uuid::new_v4().to_string();
        let mut body = genuine_body.clone();
        body["id"] = json!(format!("urn:uuid:{id}"));
        body["claim"]["subject"]["preference"] = json!(text);
        (id, body)
    };
    let facets = json!({
        "hcp2.person": person_hash("acct:alice"),
        "hcp2.category": "general_preferences",
        "hcp2.status": "active",
        "hcp2.version": "1",
    });
    // A shared record Bob made, carrying Alice's facets.
    let (shared_id, shared_body) = forged("Planted tea preference by Bob.");
    Box::pin(crate::mcp::tools::lifecycle::create_record(
        h.db.clone(),
        bob(),
        json!({
            "id": shared_id, "type": "Resolution", "kind": "hcp_entry", "name": "planted",
            "body": shared_body.to_string(), "facets": facets, "reason": "attack",
        }),
    ))
    .await
    .unwrap();
    // A private record Alice made by hand, which no event backs.
    let (hand_id, hand_body) = forged("Hand made tea preference.");
    Box::pin(crate::mcp::tools::lifecycle::create_record(
        h.db.clone(),
        alice(),
        json!({
            "id": hand_id, "type": "Resolution", "kind": "hcp_entry", "name": "by hand",
            "body": hand_body.to_string(), "facets": facets, "reason": "by hand",
            "access_policy": "account_only",
        }),
    ))
    .await
    .unwrap();

    let found = h
        .search(&alice(), "tea preference", json!(["general_preferences"]))
        .await;
    let ids: Vec<&Value> = found["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| &e["id"])
        .collect();
    assert_eq!(ids, [&genuine["id"]]);
    for id in [&shared_id, &hand_id] {
        for (tool, args) in [
            (GET_PREFERENCE, json!({ "purpose": "p" })),
            (
                UPDATE_PREFERENCE,
                json!({ "updatedPreference": "x", "reason": "r" }),
            ),
            (DELETE_PREFERENCE, json!({ "reason": "r" })),
        ] {
            let mut args = args;
            args["entryId"] = json!(format!("urn:uuid:{id}"));
            let error = h.err(&alice(), tool, args).await;
            assert_eq!(error["type"], "scope-denied", "{tool} {id}");
        }
    }
    assert_eq!(h.stored(&alice()).await.len(), 1);
}

/// Replace the whole body of an entry's view with `text`, the way pasting
/// into the record would.
async fn replace_view_body(h: &Harness, who: &Caller, record_id: &str, text: &str) {
    let raw = Box::pin(crate::mcp::tools::querying::query_sql(
        h.db.clone(),
        who.clone(),
        json!({ "sql": "SELECT body FROM records WHERE id = ?1", "parameters": [record_id] }),
    ))
    .await
    .unwrap();
    let digest = store::sha256_hex(raw["rows"][0]["body"].as_str().unwrap());
    Box::pin(h.native.call(
        h.db.clone(),
        who.clone(),
        "update_record",
        json!({
            "id": record_id,
            "body_set": text,
            "if_body_digest": digest,
            "reason": "test paste in Native",
            "sources": [],
        }),
    ))
    .await
    .unwrap();
}

/// The view body of `record_id` exactly as stored.
async fn view_text(h: &Harness, who: &Caller, record_id: &str) -> String {
    let raw = Box::pin(crate::mcp::tools::querying::query_sql(
        h.db.clone(),
        who.clone(),
        json!({ "sql": "SELECT body FROM records WHERE id = ?1", "parameters": [record_id] }),
    ))
    .await
    .unwrap();
    raw["rows"][0]["body"].as_str().unwrap().to_string()
}

fn get_args(entry: &Value) -> Value {
    json!({ "entryId": entry["id"], "purpose": "p" })
}

#[tokio::test]
async fn editing_server_set_fields_of_the_view_leaves_trusted_state_unchanged() {
    let h = harness().await;
    let added = h
        .add(&alice(), "general_preferences", "Reply in plain English.")
        .await;
    let record_id = record_id_of_entry(&added);
    let before = h.stored(&alice()).await;
    h.edit_view(&alice(), &record_id, |body| {
        let record = &mut body["record"];
        record["provenance"]["assertedBy"]["assurance"] = json!("cryptographically-verified");
        record["provenance"]["submittedByClient"] = json!({ "id": "forged", "name": "F", "operator": { "id": "f", "name": "f" } });
        record["provenance"]["authorizedUnder"] = json!("urn:uuid:forged");
        record["provenance"]["recordedAt"] = json!("1999-01-01T00:00:00Z");
        record["provenance"]["confirmations"] = json!([
            { "disposition": "confirmed", "confirmedBy": { "id": "me" }, "confirmedAt": "2026-10-01T09:00:00Z" }
        ]);
        record["declarationType"] = json!("model-inferred");
        record["confidence"] = json!("high");
        record["version"] = json!(7);
        record["previousVersion"] = json!(6);
        record["status"] = json!("deleted");
    })
    .await;
    // And the facets search used to narrow by.
    Box::pin(h.native.call(
        h.db.clone(),
        alice(),
        "update_record",
        json!({
            "id": record_id,
            "facets": {
                "hcp2.status": "deleted", "hcp2.category": "health_context",
                "hcp2.person": person_hash("acct:bob"), "hcp2.version": "7",
            },
            "reason": "tamper", "sources": [],
        }),
    ))
    .await
    .unwrap();

    let found = h
        .search(&alice(), "plain english", json!(["general_preferences"]))
        .await;
    assert_eq!(found["entries"].as_array().unwrap().len(), 1);
    let got = h.ok(&alice(), GET_PREFERENCE, get_args(&added)).await;
    let record = &got["entry"]["record"];
    assert_eq!(
        record["provenance"]["assertedBy"]["assurance"],
        "unverified"
    );
    assert_eq!(record["provenance"]["confirmations"], json!([]));
    assert_eq!(record["declarationType"], "user-declared");
    assert_eq!(record["version"], 1);
    assert_eq!(record["status"], "active");
    // Nothing the person manages changed, so there is no new version.
    assert_eq!(h.stored(&alice()).await, before);
    assert_eq!(events_of(&h, &alice()).await.len(), 1);
    // Searching in the category the facet claims finds nothing.
    let found = h
        .search(&alice(), "plain english", json!(["health_context"]))
        .await;
    assert!(found["entries"].as_array().unwrap().is_empty());

    // The get put the view right again, from the state.
    let (_, view) = h.views(&alice()).await.remove(0);
    assert_eq!(view, before[0].1);
    assert_eq!(
        h.facet(&alice(), &record_id, "hcp2.status")
            .await
            .as_deref(),
        Some("active")
    );
    assert_eq!(
        h.facet(&alice(), &record_id, "hcp2.person").await,
        Some(person_hash("acct:alice"))
    );
}

#[tokio::test]
async fn a_statement_edited_in_native_becomes_the_next_version() {
    let h = harness().await;
    let added = h
        .add(&alice(), "general_preferences", "Reply in French.")
        .await;
    let record_id = record_id_of_entry(&added);
    h.edit_view(&alice(), &record_id, |body| {
        body["claim"]["subject"]["preference"] = json!("Reply in Italian.");
    })
    .await;

    let got = h.ok(&alice(), GET_PREFERENCE, get_args(&added)).await;
    let entry = &got["entry"];
    assert_eq!(entry["record"]["version"], 2);
    assert_eq!(entry["record"]["previousVersion"], 1);
    assert_eq!(entry["claim"]["subject"]["preference"], "Reply in Italian.");
    assert_eq!(entry["record"]["declarationType"], "user-declared");
    assert_eq!(entry["record"]["status"], "active");
    assert_eq!(
        entry["record"]["provenance"]["assertedBy"]["assurance"],
        "unverified"
    );
    assert_eq!(entry["record"]["provenance"]["confirmations"], json!([]));
    // The first version is still the first version.
    let v1 = h
        .ok(
            &alice(),
            GET_PREFERENCE,
            json!({ "entryId": added["id"], "purpose": "p", "version": 1 }),
        )
        .await;
    assert_eq!(
        v1["entry"]["claim"]["subject"]["preference"],
        "Reply in French."
    );

    // One event, honestly attributed: the person's, through Native itself.
    let events = events_of(&h, &alice()).await;
    assert_eq!(events.len(), 2);
    let (kind, event) = &events[1];
    assert_eq!(kind, "hcp.entry.versioned.v1");
    assert_eq!(event["cause"], "native-edit");
    assert_eq!(event["version"], 2);
    assert_eq!(event["_actor"], "acct:alice");
    assert_eq!(event["account_id"], "acct:alice");
    assert_eq!(event["client"]["id"], "native");
    assert!(event["_reason"].as_str().unwrap().contains("native-edit"));
    let stored = h.stored(&alice()).await.remove(0).1;
    let provenance = &event["entry"]["record"]["provenance"];
    assert_eq!(provenance["source"], "native-edit");
    assert_eq!(provenance["submittedByClient"]["id"], "native");
    assert_eq!(provenance["assertedBy"]["id"], subject_of(&stored));
    assert_eq!(provenance["assertedBy"]["assurance"], "unverified");
    assert_eq!(event["entry"], stored);

    // The view is the state again, and reading again adds nothing.
    let (_, view) = h.views(&alice()).await.remove(0);
    assert_eq!(view, stored);
    assert_eq!(
        h.facet(&alice(), &record_id, "hcp2.version")
            .await
            .as_deref(),
        Some("2")
    );
    h.ok(&alice(), GET_PREFERENCE, get_args(&added)).await;
    assert_eq!(events_of(&h, &alice()).await.len(), 2);
}

#[tokio::test]
async fn an_edit_takes_the_persons_content_and_nothing_the_server_sets() {
    let h = harness().await;
    let added = h
        .add(&alice(), "general_preferences", "Reply in French.")
        .await;
    let record_id = record_id_of_entry(&added);
    h.edit_view(&alice(), &record_id, |body| {
        body["claim"]["subject"]["preference"] = json!("Reply in Italian.");
        body["claim"]["subject"]["relationship"] = json!("self");
        body["claim"]["expirationDate"] = json!("2099-01-01T00:00:00Z");
        let record = &mut body["record"];
        record["category"] = json!("values_and_ethics");
        record["dimension"] = json!("Reply Language");
        record["metadata"] = json!({ "note": "mine" });
        // None of these is the person's to set.
        record["status"] = json!("deleted");
        record["version"] = json!(9);
        record["declarationType"] = json!("model-inferred");
        record["provenance"]["assertedBy"]["assurance"] = json!("authenticated");
        record["provenance"]["confirmations"] = json!([{ "disposition": "confirmed" }]);
        record["provenance"]["recordedAt"] = json!("1999-01-01T00:00:00Z");
    })
    .await;

    // Searching in the new category finds it, in the old one does not.
    let moved = h
        .search(&alice(), "italian", json!(["values_and_ethics"]))
        .await;
    assert_eq!(moved["entries"].as_array().unwrap().len(), 1);
    let entry = &moved["entries"][0];
    assert_eq!(entry["record"]["version"], 2);
    assert_eq!(entry["record"]["status"], "active");
    assert_eq!(entry["record"]["declarationType"], "user-declared");
    assert_eq!(entry["record"]["category"], "values_and_ethics");
    assert_eq!(entry["record"]["dimension"], "Reply Language");
    assert_eq!(entry["record"]["metadata"], json!({ "note": "mine" }));
    assert_eq!(entry["claim"]["expirationDate"], "2099-01-01T00:00:00Z");
    assert_eq!(entry["claim"]["subject"]["relationship"], "self");
    assert_eq!(
        entry["record"]["provenance"]["assertedBy"]["assurance"],
        "unverified"
    );
    assert_eq!(entry["record"]["provenance"]["confirmations"], json!([]));
    assert_ne!(
        entry["record"]["provenance"]["recordedAt"],
        "1999-01-01T00:00:00Z"
    );
    let old = h
        .search(&alice(), "italian", json!(["general_preferences"]))
        .await;
    assert!(old["entries"].as_array().unwrap().is_empty());

    let events = events_of(&h, &alice()).await;
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].1["prior_category"], "general_preferences");
    assert_eq!(
        h.facet(&alice(), &record_id, "hcp2.category")
            .await
            .as_deref(),
        Some("values_and_ethics")
    );
}

#[tokio::test]
async fn a_body_an_earlier_event_projected_is_stale_and_rewritten_not_versioned() {
    let h = harness().await;
    let added = h
        .add(&alice(), "general_preferences", "Reply in French.")
        .await;
    let record_id = record_id_of_entry(&added);
    let v1_text = view_text(&h, &alice(), &record_id).await;
    h.ok(
        &alice_two(),
        UPDATE_PREFERENCE,
        json!({ "entryId": added["id"], "updatedPreference": "Reply in German.", "reason": "r" }),
    )
    .await;
    // Something puts the first version's body back (an undo, a sync).
    replace_view_body(&h, &alice(), &record_id, &v1_text).await;

    let got = h.ok(&alice(), GET_PREFERENCE, get_args(&added)).await;
    assert_eq!(got["entry"]["record"]["version"], 2);
    assert_eq!(
        got["entry"]["claim"]["subject"]["preference"],
        "Reply in German."
    );
    assert_eq!(events_of(&h, &alice()).await.len(), 2);
    let (_, view) = h.views(&alice()).await.remove(0);
    assert_eq!(view["claim"]["subject"]["preference"], "Reply in German.");
}

#[tokio::test]
async fn a_revision_builds_on_an_edit_made_before_it() {
    let h = harness().await;
    let added = h
        .add(&alice(), "general_preferences", "Reply in French.")
        .await;
    h.edit_view(&alice(), &record_id_of_entry(&added), |body| {
        body["claim"]["subject"]["preference"] = json!("Reply in Italian.");
    })
    .await;
    // The client never read between the edit and its update.
    let updated = h
        .ok(
            &alice_two(),
            UPDATE_PREFERENCE,
            json!({ "entryId": added["id"], "updatedPreference": "Reply in German.", "reason": "r" }),
        )
        .await;
    assert_eq!(updated["record"]["version"], 3);
    assert_eq!(updated["record"]["previousVersion"], 2);
    for (version, text) in [
        (1, "Reply in French."),
        (2, "Reply in Italian."),
        (3, "Reply in German."),
    ] {
        let got = h
            .ok(
                &alice(),
                GET_PREFERENCE,
                json!({ "entryId": added["id"], "purpose": "p", "version": version }),
            )
            .await;
        assert_eq!(got["entry"]["claim"]["subject"]["preference"], text);
    }
    let causes: Vec<Value> = events_of(&h, &alice())
        .await
        .into_iter()
        .map(|(_, event)| event["cause"].clone())
        .collect();
    assert_eq!(
        causes,
        [json!("add"), json!("native-edit"), json!("update")]
    );
    let (_, view) = h.views(&alice()).await.remove(0);
    assert_eq!(view["claim"]["subject"]["preference"], "Reply in German.");
}

#[tokio::test]
async fn search_and_delete_pick_up_an_edit_too() {
    let h = harness().await;
    let searched = h
        .add(&alice(), "general_preferences", "Reply in French.")
        .await;
    let deleted = h
        .add(&alice(), "general_preferences", "Lunch at noon.")
        .await;
    for (entry, text) in [
        (&searched, "Reply in Italian."),
        (&deleted, "Lunch at one."),
    ] {
        h.edit_view(&alice(), &record_id_of_entry(entry), |body| {
            body["claim"]["subject"]["preference"] = json!(text);
        })
        .await;
    }
    let found = h
        .search(&alice(), "italian", json!(["general_preferences"]))
        .await;
    assert_eq!(found["entries"].as_array().unwrap().len(), 1);
    assert_eq!(found["entries"][0]["record"]["version"], 2);
    let gone = h
        .search(&alice(), "french", json!(["general_preferences"]))
        .await;
    assert!(gone["entries"].as_array().unwrap().is_empty());

    h.ok(
        &alice(),
        DELETE_PREFERENCE,
        json!({ "entryId": deleted["id"], "reason": "r" }),
    )
    .await;
    let stored = h.stored(&alice()).await;
    let entry = &stored
        .iter()
        .find(|(id, _)| *id == record_id_of_entry(&deleted))
        .unwrap()
        .1;
    // Deleted at the version the person's edit made.
    assert_eq!(entry["record"]["version"], 2);
    assert_eq!(entry["record"]["status"], "deleted");
    assert_eq!(entry["claim"]["subject"]["preference"], "Lunch at one.");
}

/// A way of spoiling an entry's view body, given the entry as the state has it.
type Spoil = fn(&Value) -> String;

#[tokio::test]
async fn an_edit_that_cannot_be_taken_changes_nothing_and_is_not_overwritten() {
    let h = harness().await;
    let cases: Vec<(&str, Spoil)> = vec![
        ("not JSON", (|_| "this is not json".to_string())),
        ("not an entry", (|_| json!({ "hello": 1 }).to_string())),
        (
            "blank statement",
            (|state| {
                let mut body = state.clone();
                body["claim"]["subject"]["preference"] = json!("   ");
                body.to_string()
            }),
        ),
        (
            "bad expiry",
            (|state| {
                let mut body = state.clone();
                body["claim"]["subject"]["preference"] = json!("Changed.");
                body["claim"]["expirationDate"] = json!("someday");
                body.to_string()
            }),
        ),
        (
            "unknown category",
            (|state| {
                let mut body = state.clone();
                body["claim"]["subject"]["preference"] = json!("Changed.");
                body["record"]["category"] = json!("not_a_category");
                body.to_string()
            }),
        ),
        (
            "another entry's body",
            (|state| {
                let mut body = state.clone();
                body["claim"]["subject"]["preference"] = json!("Changed.");
                body["id"] = json!(format!("urn:uuid:{}", uuid::Uuid::new_v4()));
                body.to_string()
            }),
        ),
        (
            "statement too long",
            (|state| {
                let mut body = state.clone();
                body["claim"]["subject"]["preference"] = json!("x".repeat(9 * 1024));
                body.to_string()
            }),
        ),
    ];
    for (label, make) in &cases {
        let added = h
            .add(
                &alice(),
                "general_preferences",
                &format!("Original ({label})."),
            )
            .await;
        let record_id = record_id_of_entry(&added);
        let state = h
            .stored(&alice())
            .await
            .into_iter()
            .find(|(id, _)| *id == record_id)
            .unwrap()
            .1;
        let events_before = events_of(&h, &alice()).await.len();
        let text = make(&state);
        replace_view_body(&h, &alice(), &record_id, &text).await;

        for _ in 0..2 {
            let got = h.ok(&alice(), GET_PREFERENCE, get_args(&added)).await;
            assert_eq!(got["entry"]["record"]["version"], 1, "{label}");
            assert_eq!(
                got["entry"]["claim"]["subject"]["preference"],
                format!("Original ({label})."),
                "{label}"
            );
        }
        assert_eq!(
            events_of(&h, &alice()).await.len(),
            events_before,
            "{label}"
        );
        // The person's text is still there, with a note that says why.
        assert_eq!(view_text(&h, &alice(), &record_id).await, text, "{label}");
        let note = h.facet(&alice(), &record_id, "hcp2.edit_note").await;
        assert!(
            note.as_deref()
                .is_some_and(|n| n.starts_with("Not applied")),
            "{label}: {note:?}"
        );
    }

    // A client can still revise it: the revision builds on the state, and the
    // person's text stays for them to fix.
    let (record_id, state) = h.stored(&alice()).await.remove(0);
    let urn = state["id"].as_str().unwrap().to_string();
    let text = view_text(&h, &alice(), &record_id).await;
    let updated = h
        .ok(
            &alice(),
            UPDATE_PREFERENCE,
            json!({ "entryId": urn, "updatedPreference": "Revised.", "reason": "r" }),
        )
        .await;
    assert_eq!(updated["record"]["version"], 2);
    assert_eq!(view_text(&h, &alice(), &record_id).await, text);

    // Fixing the text is picked up, and the note goes.
    let mut fixed = h
        .stored(&alice())
        .await
        .into_iter()
        .find(|(id, _)| *id == record_id)
        .unwrap()
        .1;
    fixed["claim"]["subject"]["preference"] = json!("Fixed by hand.");
    replace_view_body(&h, &alice(), &record_id, &fixed.to_string()).await;
    let got = h
        .ok(
            &alice(),
            GET_PREFERENCE,
            json!({ "entryId": urn, "purpose": "p" }),
        )
        .await;
    assert_eq!(got["entry"]["record"]["version"], 3);
    assert_eq!(
        got["entry"]["claim"]["subject"]["preference"],
        "Fixed by hand."
    );
    assert_eq!(h.facet(&alice(), &record_id, "hcp2.edit_note").await, None);
}

#[tokio::test]
async fn putting_the_body_back_as_it_was_clears_the_note() {
    let h = harness().await;
    let added = h
        .add(&alice(), "general_preferences", "Reply in French.")
        .await;
    let record_id = record_id_of_entry(&added);
    let good = view_text(&h, &alice(), &record_id).await;
    replace_view_body(&h, &alice(), &record_id, "oops").await;
    h.ok(&alice(), GET_PREFERENCE, get_args(&added)).await;
    assert!(h
        .facet(&alice(), &record_id, "hcp2.edit_note")
        .await
        .is_some());
    replace_view_body(&h, &alice(), &record_id, &good).await;
    h.ok(&alice(), GET_PREFERENCE, get_args(&added)).await;
    assert_eq!(h.facet(&alice(), &record_id, "hcp2.edit_note").await, None);
    assert_eq!(events_of(&h, &alice()).await.len(), 1);
}

#[tokio::test]
async fn the_fold_with_native_edits_is_the_same_on_every_replay() {
    let h = harness().await;
    let added = h
        .add(&alice(), "general_preferences", "Reply in French.")
        .await;
    h.edit_view(&alice(), &record_id_of_entry(&added), |body| {
        body["claim"]["subject"]["preference"] = json!("Reply in Italian.");
        body["record"]["category"] = json!("values_and_ethics");
    })
    .await;
    h.ok(&alice(), GET_PREFERENCE, get_args(&added)).await;
    h.ok(
        &alice_two(),
        UPDATE_PREFERENCE,
        json!({ "entryId": added["id"], "updatedPreference": "Reply in German.", "reason": "r" }),
    )
    .await;

    let first = h.store(&alice()).fold_all().await.unwrap();
    assert!(first.rejected.is_empty(), "{:?}", first.rejected);
    assert_eq!(first.entries.values().next().unwrap().versions.len(), 3);
    let replayed = replayed_elsewhere(&h).await;
    let second = replayed.store(&alice()).fold_all().await.unwrap();
    assert_eq!(fold_shape(&first), fold_shape(&second));
    assert!(second.rejected.is_empty());
    assert_eq!(
        crate::control::state_violations(&h.db).await.unwrap(),
        Vec::<String>::new()
    );
}

#[tokio::test]
async fn an_edit_of_a_shared_or_transferred_view_affects_nobody() {
    let h = harness().await;
    let mine = h
        .add(&alice(), "general_preferences", "Tea, with milk.")
        .await;
    let bobs = h
        .add(&bob(), "general_preferences", "Tea, with honey.")
        .await;
    let mine_record = record_id_of_entry(&mine);
    let bobs_record = record_id_of_entry(&bobs);

    // Alice shares her view with the workspace.
    crate::authorization::replace_explicit_policy(
        &h.db,
        "acct:alice",
        &mine_record,
        vec![
            AllowEntry::account("acct:alice", Capability::Manage),
            AllowEntry::members(Capability::View),
        ],
    )
    .await
    .unwrap();
    // Bob hands his view to Alice.
    crate::authorization::replace_explicit_policy(
        &h.db,
        "acct:bob",
        &bobs_record,
        vec![AllowEntry::account("acct:alice", Capability::Manage)],
    )
    .await
    .unwrap();

    // The edits are made by someone who can write the records.
    h.edit_view(&alice(), &mine_record, |body| {
        body["claim"]["subject"]["preference"] = json!("Tea, with arsenic.");
    })
    .await;
    h.edit_view(&alice(), &bobs_record, |body| {
        body["claim"]["subject"]["preference"] = json!("Tea, with arsenic.");
    })
    .await;

    for (who, entry) in [(alice(), &mine), (bob(), &bobs)] {
        let got = h.ok(&who, GET_PREFERENCE, get_args(entry)).await;
        assert_eq!(got["entry"]["record"]["version"], 1);
        let found = h.search(&who, "tea", json!(["general_preferences"])).await;
        assert_eq!(found["entries"][0]["record"]["version"], 1);
        assert!(!found["entries"][0]["claim"]["subject"]["preference"]
            .as_str()
            .unwrap()
            .contains("arsenic"));
        assert_eq!(events_of(&h, &who).await.len(), 1);
    }
    // The shared record is left exactly as the edit made it.
    assert!(view_text(&h, &alice(), &mine_record)
        .await
        .contains("arsenic"));
}

#[tokio::test]
async fn a_view_that_is_shared_or_transferred_affects_nobody_and_no_history() {
    let h = harness().await;
    let mine = h
        .add(&alice(), "general_preferences", "Tea, with milk.")
        .await;
    let bobs = h
        .add(&bob(), "general_preferences", "Tea, with honey.")
        .await;
    let mine_record = record_id_of_entry(&mine);
    let bobs_record = record_id_of_entry(&bobs);

    // Alice shares her view with the workspace; Bob can now read it.
    crate::authorization::replace_explicit_policy(
        &h.db,
        "acct:alice",
        &mine_record,
        vec![
            AllowEntry::account("acct:alice", Capability::Manage),
            AllowEntry::members(Capability::View),
        ],
    )
    .await
    .unwrap();
    // Bob hands his view to Alice (sole Manage) and points its facet at her.
    Box::pin(h.native.call(
        h.db.clone(),
        bob(),
        "update_record",
        json!({
            "id": bobs_record, "facets": { "hcp2.person": person_hash("acct:alice") },
            "reason": "transfer", "sources": [],
        }),
    ))
    .await
    .unwrap();
    crate::authorization::replace_explicit_policy(
        &h.db,
        "acct:bob",
        &bobs_record,
        vec![AllowEntry::account("acct:alice", Capability::Manage)],
    )
    .await
    .unwrap();

    // Neither person's entries moved.
    let found = h
        .search(&alice(), "tea", json!(["general_preferences"]))
        .await;
    let ids: Vec<&Value> = found["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| &e["id"])
        .collect();
    assert_eq!(ids, [&mine["id"]]);
    let found = h
        .search(&bob(), "tea", json!(["general_preferences"]))
        .await;
    let ids: Vec<&Value> = found["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| &e["id"])
        .collect();
    assert_eq!(ids, [&bobs["id"]]);
    for (who, other) in [(alice(), &bobs), (bob(), &mine)] {
        for tool in [GET_PREFERENCE, UPDATE_PREFERENCE, DELETE_PREFERENCE] {
            let error = h
                .err(
                    &who,
                    tool,
                    json!({
                        "entryId": other["id"], "purpose": "p", "updatedPreference": "x", "reason": "r",
                    }),
                )
                .await;
            assert_eq!(error["type"], "scope-denied", "{tool}");
        }
    }

    // The owners still write; their history keeps growing from the events.
    let updated = h
        .ok(
            &alice(),
            UPDATE_PREFERENCE,
            json!({ "entryId": mine["id"], "updatedPreference": "Tea, with lemon.", "reason": "r" }),
        )
        .await;
    assert_eq!(updated["record"]["version"], 2);
    let v1 = h
        .ok(
            &alice(),
            GET_PREFERENCE,
            json!({ "entryId": mine["id"], "purpose": "p", "version": 1 }),
        )
        .await;
    assert_eq!(
        v1["entry"]["claim"]["subject"]["preference"],
        "Tea, with milk."
    );
    // The shared view is no longer private to Alice, so it is left as it was:
    // nothing is written into a record other people can reach.
    let (_, shared_view) = h
        .views(&alice())
        .await
        .into_iter()
        .find(|(id, _)| *id == mine_record)
        .unwrap();
    assert_eq!(shared_view["record"]["version"], 1);
    // Nothing of Bob's changed.
    let (_, still) = h.stored(&bob()).await.remove(0);
    assert_eq!(still["record"]["version"], 1);
    assert_eq!(still["claim"]["subject"]["preference"], "Tea, with honey.");
}

#[tokio::test]
async fn a_view_that_cannot_be_written_loses_nothing_and_is_written_when_it_can() {
    let h = harness().await;
    // Carol has no person record bound to her account, so her private view
    // cannot be created; her trusted state does not need it.
    let carol = caller("acct:carol", Some("client_one"));
    let added = h
        .add(&carol, "general_preferences", "Carol takes tea.")
        .await;
    assert!(h.views(&carol).await.is_empty());
    let found = h
        .search(&carol, "tea", json!(["general_preferences"]))
        .await;
    assert_eq!(found["entries"][0]["id"], added["id"]);
    let updated = h
        .ok(
            &carol,
            UPDATE_PREFERENCE,
            json!({ "entryId": added["id"], "updatedPreference": "Carol takes coffee.", "reason": "r" }),
        )
        .await;
    assert_eq!(updated["record"]["version"], 2);

    onboard(&h.db, "acct:carol").await;
    h.ok(
        &carol,
        GET_PREFERENCE,
        json!({ "entryId": added["id"], "purpose": "p" }),
    )
    .await;
    let (_, view) = h.views(&carol).await.remove(0);
    assert_eq!(view["record"]["version"], 2);
    assert_eq!(
        view["claim"]["subject"]["preference"],
        "Carol takes coffee."
    );
}

// ---- the events ---------------------------------------------------------------

/// `(type, event payload)` of the HCP events `who` has, in log order.
async fn events_of(h: &Harness, who: &Caller) -> Vec<(String, Value)> {
    let rows = sqlx::query(
        "SELECT type, payload, actor, aggregate_id, reason FROM control_events \
          WHERE aggregate_kind = 'hcp_state' AND aggregate_id = ?1 ORDER BY seq",
    )
    .bind(crate::control::hcp_state_aggregate_id(who.credential()))
    .fetch_all(h.db.write_pool())
    .await
    .unwrap();
    rows.iter()
        .map(|row| {
            use sqlx::Row;
            let mut payload: Value =
                serde_json::from_str(&row.get::<String, _>("payload")).unwrap();
            payload["_actor"] = json!(row.get::<String, _>("actor"));
            payload["_reason"] = json!(row.get::<String, _>("reason"));
            (row.get::<String, _>("type"), payload)
        })
        .collect()
}

#[tokio::test]
async fn each_operation_appends_its_events_with_client_reason_and_view_digest() {
    let h = harness().await;
    let added = h
        .add(
            &alice(),
            "general_preferences",
            "Cilantro tastes like soap.",
        )
        .await;
    h.ok(
        &alice_two(),
        UPDATE_PREFERENCE,
        json!({ "entryId": added["id"], "updatedPreference": "Cilantro is fine.", "reason": "changed my mind" }),
    )
    .await;
    h.ok(
        &alice(),
        DELETE_PREFERENCE,
        json!({ "entryId": added["id"], "reason": "no longer true" }),
    )
    .await;
    // Reads append to hcp_audit; the state aggregate below stays unchanged.
    h.search(&alice(), "cilantro", json!(["general_preferences"]))
        .await;

    let events = events_of(&h, &alice()).await;
    let kinds: Vec<&str> = events.iter().map(|(kind, _)| kind.as_str()).collect();
    assert_eq!(
        kinds,
        [
            "hcp.entry.versioned.v1",
            "hcp.entry.versioned.v1",
            "hcp.entry.status_set.v1"
        ]
    );
    let [(_, add), (_, update), (_, delete)] = &events[..] else {
        unreachable!()
    };
    for event in [add, update, delete] {
        assert_eq!(event["account_id"], "acct:alice");
        assert_eq!(event["_actor"], "acct:alice");
        assert_eq!(event["entry_id"], added["id"]);
    }
    assert_eq!(
        (add["version"].clone(), add["cause"].clone()),
        (json!(1), json!("add"))
    );
    assert_eq!(add["client"]["id"], "client_one");
    assert_eq!(update["version"], 2);
    assert_eq!(update["cause"], "update");
    assert_eq!(update["client"]["id"], "client_two");
    assert_eq!(update["reason"], "changed my mind");
    assert!(update["_reason"].as_str().unwrap().contains("client_two"));
    assert_eq!(
        update["entry"]["claim"]["subject"]["preference"],
        "Cilantro is fine."
    );
    assert_eq!(delete["version"], 2);
    assert_eq!(
        (delete["from"].clone(), delete["to"].clone()),
        (json!("active"), json!("deleted"))
    );
    assert_eq!(delete["cause"], "client_delete");
    assert_eq!(delete["reason"], "no longer true");

    // Each event names the digest of the view body it projected.
    use sha2::{Digest, Sha256};
    let digest = |text: &str| hex::encode(Sha256::digest(text.as_bytes()));
    assert_eq!(add["view_digest"], digest(&add["entry"].to_string()));
    assert_eq!(update["view_digest"], digest(&update["entry"].to_string()));
    let (_, view) = h.views(&alice()).await.remove(0);
    assert_eq!(delete["view_digest"], digest(&view.to_string()));
    assert_eq!(view["record"]["status"], "deleted");

    // The log is consistent as a whole.
    assert_eq!(
        crate::control::state_violations(&h.db).await.unwrap(),
        Vec::<String>::new()
    );
    // Another person's aggregate holds none of it.
    assert!(events_of(&h, &bob()).await.is_empty());
}

/// What a fold holds, comparable across databases.
fn fold_shape(fold: &fold::Fold) -> Vec<(String, Vec<Value>, Vec<String>)> {
    fold.entries
        .iter()
        .map(|(id, entry)| {
            (
                id.clone(),
                entry.versions.iter().map(|v| v.0.clone()).collect(),
                entry.view_digests.clone(),
            )
        })
        .collect()
}

/// Replay the HCP events of `h` into a database that has never seen them, as
/// restore or a standby does.
async fn replayed_elsewhere(h: &Harness) -> Harness {
    let mut conn = h.db.write_pool().acquire().await.unwrap();
    let all = crate::control::read_all_control_events(&mut conn)
        .await
        .unwrap();
    let hcp: Vec<_> = all
        .into_iter()
        .filter(|event| matches!(event.aggregate_kind.as_str(), "hcp_state" | "hcp_audit"))
        .collect();
    let fresh = create_database(":memory:").await.unwrap();
    let mut fresh_conn = fresh.write_pool().acquire().await.unwrap();
    crate::control::replay_control(&mut fresh_conn, &hcp)
        .await
        .unwrap();
    Harness {
        db: fresh,
        registry: ToolRegistry::new(),
        native: native_tools(),
    }
}

#[tokio::test]
async fn the_fold_is_the_same_on_every_replay() {
    let h = harness().await;
    let a = h.add(&alice(), "general_preferences", "First thing.").await;
    h.add(&bob(), "general_preferences", "Bob's thing.").await;
    h.ok(
        &alice_two(),
        UPDATE_PREFERENCE,
        json!({ "entryId": a["id"], "updatedPreference": "Second thing.", "reason": "r" }),
    )
    .await;
    let b = h.add(&alice(), "values_and_ethics", "Another.").await;
    h.ok(
        &alice(),
        DELETE_PREFERENCE,
        json!({ "entryId": b["id"], "reason": "r" }),
    )
    .await;

    // Folding the same events again gives the same state.
    let first = h.store(&alice()).fold_all().await.unwrap();
    let second = h.store(&alice()).fold_all().await.unwrap();
    let shape = fold_shape;
    assert_eq!(shape(&first), shape(&second));
    assert_eq!(first.entries.len(), 2);
    assert!(first.rejected.is_empty());

    // Replaying the log into a database that has never seen it (as restore
    // or a standby does) reaches the same state.
    let replayed = replayed_elsewhere(&h).await;
    assert_eq!(
        shape(&replayed.store(&alice()).fold_all().await.unwrap()),
        shape(&first)
    );
}

#[tokio::test]
async fn versions_are_never_reused() {
    let h = harness().await;
    let added = h.add(&alice(), "general_preferences", "Original.").await;
    let urn = added["id"].as_str().unwrap();
    h.ok(
        &alice(),
        UPDATE_PREFERENCE,
        json!({ "entryId": urn, "updatedPreference": "Second.", "reason": "r" }),
    )
    .await;

    // The log itself refuses a second event for a version.
    let who = alice();
    let store = h.store(&who);
    let stale = {
        let fold = store.fold_all().await.unwrap();
        let folded = fold.entries.get(urn).unwrap();
        super::store::Stored {
            entry: folded.versions[0].clone(),
            versions: vec![folded.versions[0].clone()],
        }
    };
    let mut again = stale.entry.clone();
    again.0["record"]["version"] = json!(2);
    again.0["record"]["previousVersion"] = json!(1);
    again.0["claim"]["subject"]["preference"] = json!("Rewritten second.");
    let mut tx = store.begin().await.unwrap();
    let mut act = crate::act::ActAllocation::new();
    let refused = store
        .append_update(&mut tx, &mut act, &stale, &again, "r")
        .await;
    assert!(refused.is_err(), "version 2 already has an event");
    drop(tx);

    // And a row that got into the log anyway (a gap, a repeat, a rewrite of
    // version 1) is ignored by the fold: the numbers keep their meaning.
    for (n, (version, previous, text)) in [
        (2, 1, "Repeated second."),
        (4, 3, "Gap."),
        (1, 0, "Rewrite."),
    ]
    .into_iter()
    .enumerate()
    {
        let mut forged = stale.entry.clone();
        forged.0["record"]["version"] = json!(version);
        forged.0["record"]["previousVersion"] = if previous == 0 {
            Value::Null
        } else {
            json!(previous)
        };
        forged.0["claim"]["subject"]["preference"] = json!(text);
        insert_raw_event(
            &h,
            "acct:alice",
            &format!("forged-{n}"),
            "hcp.entry.versioned.v1",
            json!({
                "account_id": "acct:alice", "entry_id": urn, "version": version,
                "cause": if version == 1 { "add" } else { "update" },
                "client": { "id": "x", "name": "x", "operator_id": "x", "operator_name": "x" },
                "entry": forged.0, "view_digest": "0".repeat(64),
            }),
        )
        .await;
    }
    let fold = h.store(&alice()).fold_all().await.unwrap();
    assert_eq!(fold.rejected.len(), 3, "{:?}", fold.rejected);
    let folded = fold.entries.get(urn).unwrap();
    assert_eq!(folded.versions.len(), 2);
    assert_eq!(folded.current().preference(), "Second.");
    // The next update takes the next number.
    let third = h
        .ok(
            &alice(),
            UPDATE_PREFERENCE,
            json!({ "entryId": urn, "updatedPreference": "Third.", "reason": "r" }),
        )
        .await;
    assert_eq!(third["record"]["version"], 3);
}

/// Put a row in a person's `hcp_state` aggregate without any validation, as a
/// corrupted or hand-edited database could.
async fn insert_raw_event(h: &Harness, account: &str, key: &str, event_type: &str, payload: Value) {
    sqlx::query(
        "INSERT INTO control_events \
         (id, idempotency_key, type, schema_version, aggregate_kind, aggregate_id, actor, run_key, reason, payload, created_at, act) \
         VALUES (?1, ?2, ?3, 1, 'hcp_state', ?4, ?5, NULL, 'forged', ?6, '2026-10-01T00:00:00Z', NULL)",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(key)
    .bind(event_type)
    .bind(crate::control::hcp_state_aggregate_id(account))
    .bind(account)
    .bind(payload.to_string())
    .execute(h.db.write_pool())
    .await
    .unwrap();
}

#[tokio::test]
async fn another_accounts_events_are_never_folded_for_this_caller() {
    let h = harness().await;
    let bobs = h.add(&bob(), "general_preferences", "Bob likes tea.").await;
    let (_, bobs_entry) = h.stored(&bob()).await.remove(0);
    assert!(h.stored(&alice()).await.is_empty());

    // Rows that reached Alice's aggregate by some other road: an event that
    // names Bob, and Bob's entry copied under Alice's own name.
    let client = json!({ "id": "x", "name": "x", "operator_id": "x", "operator_name": "x" });
    insert_raw_event(
        &h,
        "acct:alice",
        "other-person",
        "hcp.entry.versioned.v1",
        json!({
            "account_id": "acct:bob", "entry_id": bobs["id"], "version": 1, "cause": "add",
            "client": client, "entry": bobs_entry, "view_digest": "0".repeat(64),
        }),
    )
    .await;
    insert_raw_event(
        &h,
        "acct:alice",
        "copied-entry",
        "hcp.entry.versioned.v1",
        json!({
            "account_id": "acct:alice", "entry_id": bobs["id"], "version": 1, "cause": "add",
            "client": client, "entry": bobs_entry, "view_digest": "0".repeat(64),
        }),
    )
    .await;
    let fold = h.store(&alice()).fold_all().await.unwrap();
    assert!(fold.entries.is_empty());
    assert_eq!(fold.rejected.len(), 2);
    let found = h
        .search(&alice(), "tea", json!(["general_preferences"]))
        .await;
    assert!(found["entries"].as_array().unwrap().is_empty());
    for tool in [GET_PREFERENCE, UPDATE_PREFERENCE, DELETE_PREFERENCE] {
        let error = h
            .err(
                &alice(),
                tool,
                json!({ "entryId": bobs["id"], "purpose": "p", "updatedPreference": "x", "reason": "r" }),
            )
            .await;
        assert_eq!(error["type"], "scope-denied", "{tool}");
    }
    // Bob's state is as he left it.
    let (_, still) = h.stored(&bob()).await.remove(0);
    assert_eq!(still, bobs_entry);
}

/// The real, valid HCP event rows of a short life: a version and a status
/// change, as the handler wrote them.
async fn valid_hcp_rows(h: &Harness) -> Vec<crate::control::ControlEventRow> {
    let added = h.add(&alice(), "general_preferences", "Real rows.").await;
    h.ok(
        &alice(),
        DELETE_PREFERENCE,
        json!({ "entryId": added["id"], "reason": "r" }),
    )
    .await;
    let mut conn = h.db.write_pool().acquire().await.unwrap();
    let rows: Vec<_> = crate::control::read_all_control_events(&mut conn)
        .await
        .unwrap()
        .into_iter()
        .filter(|event| event.aggregate_kind == "hcp_state")
        .collect();
    assert_eq!(
        rows.iter()
            .map(|r| r.event_type.as_str())
            .collect::<Vec<_>>(),
        ["hcp.entry.versioned.v1", "hcp.entry.status_set.v1"]
    );
    rows
}

#[tokio::test]
async fn the_reservation_alone_keeps_valid_hcp_rows_off_the_generic_validator() {
    let h = harness().await;
    for row in valid_hcp_rows(&h).await {
        // Replay and restore accept the row exactly as the handler wrote it...
        crate::control::validate_stored_control_event(&row)
            .unwrap_or_else(|e| panic!("{}: {e}", row.event_type));
        // ...and the path for new appends from outside refuses that same row:
        // only the reservation can be the reason, since the row is valid.
        let refused = crate::control::validate_control_event(&row).unwrap_err();
        assert!(
            refused
                .to_string()
                .contains("reserved for the HCP v2 handler"),
            "{}: {refused}",
            row.event_type
        );
    }
}

#[tokio::test]
async fn a_generic_command_cannot_be_given_an_hcp_payload() {
    use crate::control::{ControlEventPayload, NewControlEvent};
    let h = harness().await;
    let rows = valid_hcp_rows(&h).await;
    for row in &rows {
        let payload = match row.event_type.as_str() {
            "hcp.entry.versioned.v1" => {
                ControlEventPayload::HcpEntryVersioned(serde_json::from_str(&row.payload).unwrap())
            }
            _ => {
                ControlEventPayload::HcpEntryStatusSet(serde_json::from_str(&row.payload).unwrap())
            }
        };
        let aggregate = crate::control::hcp_state_aggregate_id("acct:alice");
        // The constructors refuse an HCP payload outright.
        assert!(NewControlEvent::authored(
            "k",
            aggregate.clone(),
            "acct:alice",
            None,
            "r",
            payload.clone()
        )
        .is_err());
        assert!(
            NewControlEvent::engine_provisioned("k", aggregate.clone(), "r", payload.clone())
                .is_err()
        );
        // The HCP constructor takes nothing else.
        assert!(NewControlEvent::hcp_state(
            &HcpWriteSeal::mint(),
            "k",
            None,
            "r",
            ControlEventPayload::NotificationPreferenceSet(
                crate::control::NotificationPreferencePayload {
                    account_id: "acct:alice".into(),
                    arrival: "all".into(),
                }
            )
        )
        .is_err());

        // A generic command, built honestly, whose payload is swapped for the
        // valid HCP one before it is appended: the append refuses it, and
        // nothing is written.
        let mut command = NewControlEvent::authored(
            format!("swap-{}", row.event_type),
            crate::control::notification_preference_aggregate_id("acct:alice"),
            "acct:alice",
            None,
            "swapped",
            ControlEventPayload::NotificationPreferenceSet(
                crate::control::NotificationPreferencePayload {
                    account_id: "acct:alice".into(),
                    arrival: "all".into(),
                },
            ),
        )
        .unwrap();
        command.aggregate_id = aggregate;
        command.payload = payload;
        let mut tx = h.store(&alice()).begin().await.unwrap();
        let mut act = crate::act::ActAllocation::new();
        let refused = crate::control::append_control_event_in(&mut tx, command, &mut act)
            .await
            .unwrap_err();
        assert!(
            refused
                .to_string()
                .contains("reserved for the HCP v2 handler"),
            "{}: {refused}",
            row.event_type
        );
        drop(tx);
    }
    assert_eq!(
        events_of(&h, &alice()).await.len(),
        2,
        "nothing was appended"
    );
}

#[tokio::test]
async fn the_log_checks_hcp_events_for_the_person_and_the_size_bound() {
    let h = harness().await;
    let added = h.add(&alice(), "general_preferences", "Small.").await;
    let urn = added["id"].as_str().unwrap();
    let who = alice();
    let store = h.store(&who);
    let current = store.entry(urn).await.unwrap().unwrap();

    // An entry beyond the bound is refused by the log, not only by the tool.
    let mut huge = current.entry.clone();
    huge.0["record"]["version"] = json!(2);
    huge.0["record"]["previousVersion"] = json!(1);
    huge.0["claim"]["subject"]["preference"] = json!("x".repeat(70 * 1024));
    let mut tx = store.begin().await.unwrap();
    let mut act = crate::act::ActAllocation::new();
    assert!(store
        .append_update(&mut tx, &mut act, &current, &huge, "r")
        .await
        .is_err());
    drop(tx);
    assert_eq!(h.stored(&alice()).await.len(), 1);

    // Another person's account cannot be written into Alice's aggregate.
    let client = crate::control::HcpClientPayload {
        id: "c".into(),
        name: "c".into(),
        operator_id: "o".into(),
        operator_name: "o".into(),
    };
    let payload = crate::control::ControlEventPayload::HcpEntryStatusSet(
        crate::control::HcpEntryStatusSetPayload {
            account_id: "acct:bob".into(),
            entry_id: urn.into(),
            version: 1,
            from: "active".into(),
            to: "deleted".into(),
            cause: "client_delete".into(),
            related_entry_id: None,
            client,
            reason: None,
            view_digest: None,
        },
    );
    let event = crate::control::NewControlEvent::hcp_state(
        &HcpWriteSeal::mint(),
        "k-bob",
        None,
        "r",
        payload,
    )
    .unwrap();
    let mut tx = store.begin().await.unwrap();
    let mut act = crate::act::ActAllocation::new();
    crate::control::append_control_event_in(&mut tx, event, &mut act)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    // It is Bob's aggregate that got it, not Alice's.
    assert_eq!(events_of(&h, &alice()).await.len(), 1);
    assert_eq!(events_of(&h, &bob()).await.len(), 1);
    assert_eq!(h.stored(&alice()).await.len(), 1);
}

// ---- the status chain's preconditions ------------------------------------------

/// An entry at version 2 (active) and the client block the forged rows use.
async fn entry_at_version_two(h: &Harness) -> String {
    let added = h.add(&alice(), "general_preferences", "Original.").await;
    let urn = added["id"].as_str().unwrap().to_string();
    h.ok(
        &alice(),
        UPDATE_PREFERENCE,
        json!({ "entryId": urn, "updatedPreference": "Second.", "reason": "r" }),
    )
    .await;
    urn
}

fn status_row(urn: &str, version: u64, from: &str, to: &str) -> Value {
    json!({
        "account_id": "acct:alice", "entry_id": urn, "version": version,
        "from": from, "to": to, "cause": "client_delete",
        "client": { "id": "x", "name": "x", "operator_id": "x", "operator_name": "x" },
    })
}

/// After a status row the chain must ignore: it is listed as rejected, the
/// entry is as it was, and a database that replays the log agrees.
async fn assert_status_row_ignored(h: &Harness, urn: &str, before: &fold::Fold) {
    let fold = h.store(&alice()).fold_all().await.unwrap();
    assert_eq!(fold.rejected.len(), 1, "{:?}", fold.rejected);
    let entry = fold.entries.get(urn).unwrap();
    assert_eq!(entry.current().version(), 2);
    assert_eq!(entry.current().status(), "active");
    assert_eq!(fold_shape(&fold), fold_shape(before));
    let found = h
        .search(&alice(), "second", json!(["general_preferences"]))
        .await;
    assert_eq!(found["entries"].as_array().unwrap().len(), 1);

    let replayed = replayed_elsewhere(h).await;
    let again = replayed.store(&alice()).fold_all().await.unwrap();
    assert_eq!(fold_shape(&again), fold_shape(&fold));
    assert_eq!(again.rejected.len(), 1, "{:?}", again.rejected);
    assert_eq!(again.rejected, fold.rejected);
}

#[tokio::test]
async fn a_status_change_of_a_version_that_is_not_current_is_ignored() {
    let h = harness().await;
    let urn = entry_at_version_two(&h).await;
    let before = h.store(&alice()).fold_all().await.unwrap();
    // Version 1 is history: a status change naming it must not touch version 2.
    insert_raw_event(
        &h,
        "acct:alice",
        "stale-version-status",
        "hcp.entry.status_set.v1",
        status_row(&urn, 1, "active", "deleted"),
    )
    .await;
    assert_status_row_ignored(&h, &urn, &before).await;
}

#[tokio::test]
async fn a_status_change_from_a_status_the_entry_does_not_have_is_ignored() {
    let h = harness().await;
    let urn = entry_at_version_two(&h).await;
    let before = h.store(&alice()).fold_all().await.unwrap();
    // The entry is active; a change that starts from conflicted is not about it.
    insert_raw_event(
        &h,
        "acct:alice",
        "wrong-from-status",
        "hcp.entry.status_set.v1",
        status_row(&urn, 2, "conflicted", "deleted"),
    )
    .await;
    assert_status_row_ignored(&h, &urn, &before).await;
}

// ---- whose text it is, and what it was edited from --------------------------

/// Alice's entry, with `holders` as the only accounts that can manage its view.
async fn hand_view_to(h: &Harness, record_id: &str, holders: &[&str]) {
    crate::authorization::replace_explicit_policy(
        &h.db,
        "acct:alice",
        record_id,
        holders
            .iter()
            .map(|account| AllowEntry::account(*account, Capability::Manage))
            .collect(),
    )
    .await
    .unwrap();
}

async fn edit_note_of(h: &Harness, record_id: &str) -> Option<String> {
    h.facet(&alice(), record_id, "hcp2.edit_note").await
}

#[tokio::test]
async fn text_a_collaborator_saved_is_not_adopted_when_the_view_is_private_again() {
    let h = harness().await;
    let added = h
        .add(&alice(), "general_preferences", "Tea, with milk.")
        .await;
    let record_id = record_id_of_entry(&added);

    // Shared with Bob, who edits it; Alice does not touch the body.
    hand_view_to(&h, &record_id, &["acct:alice", "acct:bob"]).await;
    h.edit_view(&bob(), &record_id, |body| {
        body["claim"]["subject"]["preference"] = json!("Tea, with arsenic.");
    })
    .await;
    let got = h.ok(&alice(), GET_PREFERENCE, get_args(&added)).await;
    assert_eq!(got["entry"]["record"]["version"], 1);

    // Unsharing does not make Bob's text hers.
    hand_view_to(&h, &record_id, &["acct:alice"]).await;
    let got = h.ok(&alice(), GET_PREFERENCE, get_args(&added)).await;
    assert_eq!(got["entry"]["record"]["version"], 1);
    assert_eq!(
        got["entry"]["claim"]["subject"]["preference"],
        "Tea, with milk."
    );
    assert_eq!(events_of(&h, &alice()).await.len(), 1);
    assert!(view_text(&h, &alice(), &record_id)
        .await
        .contains("arsenic"));
    let note = edit_note_of(&h, &record_id).await.unwrap();
    assert!(
        note.starts_with("Not applied") && note.contains("someone else"),
        "{note}"
    );

    // Alice saves it herself: that is hers, and the note goes.
    h.edit_view(&alice(), &record_id, |body| {
        body["claim"]["subject"]["preference"] = json!("Tea, with oat milk.");
    })
    .await;
    let got = h.ok(&alice(), GET_PREFERENCE, get_args(&added)).await;
    assert_eq!(got["entry"]["record"]["version"], 2);
    assert_eq!(
        got["entry"]["claim"]["subject"]["preference"],
        "Tea, with oat milk."
    );
    assert_eq!(edit_note_of(&h, &record_id).await, None);
}

#[tokio::test]
async fn text_saved_while_the_view_was_handed_over_is_not_adopted_on_its_return() {
    let h = harness().await;
    let added = h
        .add(&alice(), "general_preferences", "Tea, with milk.")
        .await;
    let record_id = record_id_of_entry(&added);

    // Handed to Bob alone, who edits it; then handed back.
    hand_view_to(&h, &record_id, &["acct:bob"]).await;
    h.edit_view(&bob(), &record_id, |body| {
        body["claim"]["subject"]["preference"] = json!("Tea, with arsenic.");
    })
    .await;
    hand_view_to(&h, &record_id, &["acct:alice"]).await;

    let got = h.ok(&alice(), GET_PREFERENCE, get_args(&added)).await;
    assert_eq!(got["entry"]["record"]["version"], 1);
    let found = h
        .search(&alice(), "arsenic", json!(["general_preferences"]))
        .await;
    assert!(found["entries"].as_array().unwrap().is_empty());
    assert_eq!(events_of(&h, &alice()).await.len(), 1);
    assert!(view_text(&h, &alice(), &record_id)
        .await
        .contains("arsenic"));
    assert!(edit_note_of(&h, &record_id).await.is_some());
}

#[tokio::test]
async fn a_status_only_edit_of_a_stale_view_makes_no_version_and_undoes_nothing() {
    let h = harness().await;
    let added = h
        .add(&alice(), "general_preferences", "Reply in French.")
        .await;
    let record_id = record_id_of_entry(&added);
    // A client revision whose view write failed: the view still shows v1.
    h.inject_version(&alice(), added["id"].as_str().unwrap(), |entry| {
        entry["claim"]["subject"]["preference"] = json!("Reply in German.");
    })
    .await;
    h.edit_view(&alice(), &record_id, |body| {
        body["record"]["status"] = json!("deleted");
    })
    .await;

    let got = h.ok(&alice(), GET_PREFERENCE, get_args(&added)).await;
    assert_eq!(got["entry"]["record"]["version"], 2);
    assert_eq!(got["entry"]["record"]["status"], "active");
    assert_eq!(
        got["entry"]["claim"]["subject"]["preference"],
        "Reply in German."
    );
    assert_eq!(events_of(&h, &alice()).await.len(), 2);
    let (_, view) = h.views(&alice()).await.remove(0);
    assert_eq!(view["record"]["version"], 2);
    assert_eq!(view["claim"]["subject"]["preference"], "Reply in German.");
}

#[tokio::test]
async fn an_edit_of_a_stale_view_applies_only_what_the_person_changed() {
    let h = harness().await;
    for (label, edit_view, expect) in [
        (
            "statement",
            (|body: &mut Value| body["claim"]["subject"]["preference"] = json!("Reply in Italian."))
                as fn(&mut Value),
            ("Reply in Italian.", "tone"),
        ),
        (
            "dimension",
            |body: &mut Value| body["record"]["dimension"] = json!("Formality"),
            ("Reply in German.", "Formality"),
        ),
    ] {
        let added = h
            .add(
                &alice(),
                "general_preferences",
                &format!("Reply in French ({label})."),
            )
            .await;
        let record_id = record_id_of_entry(&added);
        let urn = added["id"].as_str().unwrap();
        // v2 is the client's: a new statement and a dimension. The view is v1.
        h.inject_version(&alice(), urn, |entry| {
            entry["claim"]["subject"]["preference"] = json!("Reply in German.");
            entry["record"]["dimension"] = json!("tone");
        })
        .await;
        h.edit_view(&alice(), &record_id, edit_view).await;

        let got = h.ok(&alice(), GET_PREFERENCE, get_args(&added)).await;
        let entry = &got["entry"];
        assert_eq!(entry["record"]["version"], 3, "{label}");
        assert_eq!(entry["claim"]["subject"]["preference"], expect.0, "{label}");
        assert_eq!(entry["record"]["dimension"], expect.1, "{label}");
        let causes: Vec<Value> = events_of(&h, &alice())
            .await
            .into_iter()
            .filter(|(_, event)| event["entry_id"] == added["id"])
            .map(|(_, event)| event["cause"].clone())
            .collect();
        assert_eq!(
            causes,
            [json!("add"), json!("update"), json!("native-edit")],
            "{label}"
        );
        // The client's version is still what it was.
        let v2 = h
            .ok(
                &alice(),
                GET_PREFERENCE,
                json!({ "entryId": urn, "purpose": "p", "version": 2 }),
            )
            .await;
        assert_eq!(
            v2["entry"]["claim"]["subject"]["preference"], "Reply in German.",
            "{label}"
        );
    }
}

#[tokio::test]
async fn a_native_edit_and_a_client_revision_made_together_both_stand() {
    let h = harness().await;
    let added = h
        .add(&alice(), "general_preferences", "Reply in French.")
        .await;
    let urn = added["id"].as_str().unwrap();
    // The person edits the statement; a client revises the dimension before
    // anything has read the edit.
    h.edit_view(&alice(), &record_id_of_entry(&added), |body| {
        body["claim"]["subject"]["preference"] = json!("Reply in Italian.");
    })
    .await;
    h.inject_version(&alice(), urn, |entry| {
        entry["record"]["dimension"] = json!("tone");
    })
    .await;

    let got = h.ok(&alice(), GET_PREFERENCE, get_args(&added)).await;
    assert_eq!(got["entry"]["record"]["version"], 3);
    assert_eq!(
        got["entry"]["claim"]["subject"]["preference"],
        "Reply in Italian."
    );
    assert_eq!(got["entry"]["record"]["dimension"], "tone");
    // Reading again, as another reader would, adds nothing.
    h.search(&alice_two(), "italian", json!(["general_preferences"]))
        .await;
    h.ok(&alice_two(), GET_PREFERENCE, get_args(&added)).await;
    assert_eq!(events_of(&h, &alice()).await.len(), 3);
}

#[tokio::test]
async fn each_managed_field_alone_makes_exactly_one_version() {
    let h = harness().await;
    type Change = fn(&mut Value);
    let changes: [(&str, Change); 5] = [
        ("category", |body| {
            body["record"]["category"] = json!("values_and_ethics")
        }),
        ("dimension", |body| {
            body["record"]["dimension"] = json!("Tone")
        }),
        ("metadata", |body| {
            body["record"]["metadata"] = json!({ "note": "mine" })
        }),
        ("expiry", |body| {
            body["claim"]["expirationDate"] = json!("2099-01-01T00:00:00Z")
        }),
        ("relationship", |body| {
            body["claim"]["subject"]["relationship"] = json!("self")
        }),
    ];
    for (label, change) in changes {
        let added = h
            .add(
                &alice(),
                "general_preferences",
                &format!("Reply in French ({label})."),
            )
            .await;
        h.edit_view(&alice(), &record_id_of_entry(&added), change)
            .await;
        for _ in 0..3 {
            let got = h
                .ok(
                    &alice(),
                    GET_PREFERENCE,
                    json!({ "entryId": added["id"], "purpose": "p" }),
                )
                .await;
            assert_eq!(got["entry"]["record"]["version"], 2, "{label}");
            assert_eq!(
                got["entry"]["claim"]["subject"]["preference"],
                format!("Reply in French ({label})."),
                "{label}"
            );
        }
        let versions = events_of(&h, &alice())
            .await
            .into_iter()
            .filter(|(_, event)| event["entry_id"] == added["id"])
            .count();
        assert_eq!(versions, 2, "{label}");
    }
}

#[tokio::test]
async fn an_entry_over_the_size_bound_is_not_applied_and_search_clears_a_stale_note() {
    let h = harness().await;
    let added = h
        .add(&alice(), "general_preferences", "Reply in French.")
        .await;
    let record_id = record_id_of_entry(&added);
    let good = view_text(&h, &alice(), &record_id).await;
    h.edit_view(&alice(), &record_id, |body| {
        body["record"]["metadata"] = json!({ "big": "x".repeat(70_000) });
    })
    .await;
    h.ok(&alice(), GET_PREFERENCE, get_args(&added)).await;
    let note = edit_note_of(&h, &record_id).await.unwrap();
    assert!(note.contains("too large"), "{note}");
    assert_eq!(events_of(&h, &alice()).await.len(), 1);

    // Putting it back is enough; a search notices as well as a get.
    replace_view_body(&h, &alice(), &record_id, &good).await;
    h.search(&alice(), "french", json!(["general_preferences"]))
        .await;
    assert_eq!(edit_note_of(&h, &record_id).await, None);
}

#[path = "c2_tests.rs"]
mod c2;

#[path = "c3_tests.rs"]
mod c3_tests;
