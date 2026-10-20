//! Layer 1 checks for the HCP preference tools, against the conformance
//! checklist in e5ae9ef: envelopes, literal search rules, `includeSuggestions`,
//! the JSON-string value encoding, delete-resolves-slug, error codes,
//! sensitivity filtering and write-then-fresh-read.

use serde_json::{json, Value};

use super::*;
use crate::db::{create_database, Db};
use crate::mcp::registry::{Caller, ToolRegistry};
use crate::provenance::Channel;

pub(super) struct Harness {
    pub(super) db: Db,
    pub(super) registry: ToolRegistry,
}

pub(super) fn caller(account: &str, client: Option<&str>) -> Caller {
    Caller::authenticated(account)
        .with_channel(Channel::Mcp)
        .with_oauth_client_id(client.map(str::to_string))
}

pub(super) fn alice() -> Caller {
    caller("acct:alice", Some("client_alice_app"))
}

/// A hosted member has a person record bound to their account; HCP writes
/// need that binding (records are created account-only).
pub(super) async fn onboard(db: &Db, account: &str) {
    let person = Box::pin(crate::mcp::tools::lifecycle::create_record(
        db.clone(),
        Caller::local(),
        json!({
            "type": "Entity", "kind": "person", "name": account, "reason": "test fixture"
        }),
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

/// What a workspace admin sends to define the `preference` kind: the real
/// `manage_vocabularies` operations, here through the full registry as a local
/// owner (hosted workspaces send the same arguments through the plan-gated
/// `schema_admin` executor).
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

pub(super) async fn propose_preference_kind(db: &Db) {
    let proposed = manage_vocabularies(
        db,
        json!({
            "action": "propose_value",
            "vocabulary": "kind:Resolution",
            "value": "preference",
            "gloss": "A standing personal preference held as one revisable value.",
            "metadata": {
                "schema_version": 1,
                "provenance_ref": "rec:87ce011b-36f4-41d2-9c97-7275768df913",
                "definition": "A standing personal preference: a settled position about how something should be done for one person, held as a single revisable value.",
                "identity": {
                    "criterion": "Continuity of the same person's position on one preference slug; its value is revised in place and history keeps earlier values.",
                    "dedup": { "mode": "record_id", "keys": [] }
                },
                "declared_capabilities": []
            }
        }),
    )
    .await;
    assert_eq!(proposed["status"], "proposed", "{proposed}");
}

pub(super) async fn promote_preference_kind(db: &Db) {
    let promoted = manage_vocabularies(
        db,
        json!({ "action": "promote_value", "value_id": "vv:voc:kind:Resolution:preference" }),
    )
    .await;
    assert_eq!(promoted["status"], "active", "{promoted}");
}

/// A workspace with no HCP setup at all.
pub(super) async fn unconfigured_harness() -> Harness {
    let db = create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_hcp_tools(&mut registry).unwrap();
    onboard(&db, "acct:alice").await;
    Harness { db, registry }
}

/// A workspace whose admin has defined and promoted the `preference` kind.
pub(super) async fn harness() -> Harness {
    let h = unconfigured_harness().await;
    propose_preference_kind(&h.db).await;
    promote_preference_kind(&h.db).await;
    h
}

impl Harness {
    /// The full MCP result frame, as `/hcp` returns it.
    pub(super) async fn frame(&self, who: &Caller, tool: &str, args: Value) -> Value {
        call_tool(
            &self.registry,
            self.db.clone(),
            who.clone(),
            tool,
            args,
            None,
        )
        .await
    }

    /// The ContextRouter body (`structuredContent`).
    pub(super) async fn call(&self, who: &Caller, tool: &str, args: Value) -> Value {
        self.frame(who, tool, args).await["structuredContent"].clone()
    }

    pub(super) async fn mutate(&self, who: &Caller, args: Value) -> Value {
        self.call(who, MUTATE_PREFERENCES, args).await
    }

    pub(super) async fn define(
        &self,
        who: &Caller,
        slug: &str,
        value_type: &str,
        extra: Value,
    ) -> Value {
        let mut definition = json!({
            "slug": slug,
            "description": format!("Description of {slug}"),
            "valueType": value_type,
            "scope": "GLOBAL",
        });
        for (key, value) in extra.as_object().cloned().unwrap_or_default() {
            definition[key] = value;
        }
        self.mutate(
            who,
            json!({ "operation": "CREATE_DEFINITION", "definition": definition }),
        )
        .await
    }

    pub(super) async fn set(&self, who: &Caller, slug: &str, value: Value) -> Value {
        self.mutate(
            who,
            json!({
                "operation": "SET_PREFERENCE",
                "preference": { "slug": slug, "value": value.to_string() },
            }),
        )
        .await
    }

    pub(super) async fn suggest(
        &self,
        who: &Caller,
        slug: &str,
        value: Value,
        confidence: f64,
    ) -> Value {
        self.mutate(
            who,
            json!({
                "operation": "SUGGEST_PREFERENCE",
                "preference": {
                    "slug": slug,
                    "value": value.to_string(),
                    "confidence": confidence,
                    "evidence": { "quote": "said so" },
                },
            }),
        )
        .await
    }

    pub(super) async fn search(&self, who: &Caller, args: Value) -> Value {
        self.call(who, SEARCH_PREFERENCES, args).await
    }

    pub(super) async fn slugs(&self, who: &Caller) -> Vec<String> {
        self.call(who, LIST_PREFERENCE_SLUGS, json!({})).await["preferences"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["slug"].as_str().unwrap().to_string())
            .collect()
    }
}

pub(super) fn values(search: &Value, list: &str) -> Vec<(String, Value)> {
    search[list]["preferences"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| (p["slug"].as_str().unwrap().to_string(), p["value"].clone()))
        .collect()
}

// ---- registry and descriptors ------------------------------------------

#[test]
fn only_the_five_slice_two_tools_are_advertised() {
    let descriptors = hcp_tool_descriptors();
    let names: Vec<&str> = descriptors
        .iter()
        .map(|d| d["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "listPreferenceSlugs",
            "searchPreferences",
            "listPermissionGrants",
            "mutatePreferences",
            "smartSearchPreferences"
        ]
    );
    let mut registry = ToolRegistry::new();
    register_hcp_tools(&mut registry).unwrap();
    let registered: Vec<&str> = registry.specs().map(|spec| spec.name.as_str()).collect();
    assert_eq!(registered, names, "registry and descriptors agree");
    assert!(
        !names.contains(&"consolidateSchema"),
        "consolidateSchema is not in this slice"
    );
    // Checklist 6: read tools readOnly/closed-world; mutate writes, not idempotent.
    for descriptor in &descriptors {
        let annotations = &descriptor["annotations"];
        assert_eq!(annotations["openWorldHint"], false);
        if descriptor["name"] == "mutatePreferences" {
            assert_eq!(annotations["readOnlyHint"], false);
            assert_eq!(annotations["idempotentHint"], false);
            assert_eq!(descriptor["inputSchema"]["required"], json!(["operation"]));
            assert_eq!(
                descriptor["inputSchema"]["properties"]["operation"]["enum"]
                    .as_array()
                    .unwrap()
                    .len(),
                6
            );
        } else {
            assert_eq!(annotations["readOnlyHint"], true);
        }
    }
}

#[tokio::test]
async fn list_permission_grants_is_honestly_empty() {
    let h = harness().await;
    let body = h.call(&alice(), LIST_PERMISSION_GRANTS, json!({})).await;
    assert_eq!(
        body,
        json!({
            "success": true,
            "grants": [],
            "native": { "perClientGrants": "not_implemented", "access": "principal" }
        })
    );
}

// ---- catalog ------------------------------------------------------------

#[tokio::test]
async fn definitions_list_with_sorted_unique_categories_and_category_filter() {
    let h = harness().await;
    let a = alice();
    assert_eq!(
        h.call(&a, LIST_PREFERENCE_SLUGS, json!({})).await,
        json!({ "success": true, "categories": [], "count": 0, "preferences": [] })
    );
    let created = h
        .define(
            &a,
            "writing.length",
            "STRING",
            json!({ "displayName": "Length" }),
        )
        .await;
    assert_eq!(created["success"], true);
    assert_eq!(created["changed"], true);
    assert_eq!(created["operation"], "CREATE_DEFINITION");
    assert_eq!(created["requiredPermission"], "DEFINE");
    assert_eq!(created["target"], "writing.length");
    assert_eq!(created["definition"]["category"], "writing");
    assert_eq!(created["audit"]["origin"], "MCP");
    assert_eq!(created["audit"]["actorClientKey"], "client_alice_app");
    assert!(created["audit"]["correlationId"].as_str().unwrap().len() >= 32);
    h.define(
        &a,
        "food.diet",
        "ENUM",
        json!({ "options": ["vegan", "none"] }),
    )
    .await;
    h.define(&a, "writing.tone", "BOOLEAN", json!({})).await;

    let all = h.call(&a, LIST_PREFERENCE_SLUGS, json!({})).await;
    assert_eq!(all["success"], true);
    assert_eq!(all["categories"], json!(["food", "writing"]));
    assert_eq!(all["count"], 3);
    let first = &all["preferences"][1];
    assert_eq!(first["slug"], "writing.length");
    assert_eq!(first["category"], "writing");
    assert_eq!(first["displayName"], "Length");
    assert_eq!(first["valueType"], "STRING");
    assert_eq!(first["scope"], "GLOBAL");
    assert!(first.get("options").is_none());
    assert_eq!(all["preferences"][0]["options"], json!(["vegan", "none"]));
    assert!(
        all["preferences"][0].get("value").is_none(),
        "no values in the catalog"
    );

    let writing = h
        .call(&a, LIST_PREFERENCE_SLUGS, json!({ "category": "writing" }))
        .await;
    assert_eq!(writing["categories"], json!(["writing"]));
    assert_eq!(writing["count"], 2);
    // The category is the part before the first dot, so a prefix is not a match.
    let none = h
        .call(&a, LIST_PREFERENCE_SLUGS, json!({ "category": "writ" }))
        .await;
    assert_eq!(none["count"], 0);
}

// ---- search -------------------------------------------------------------

#[tokio::test]
async fn search_uses_literal_slug_prefix_category_or_description_not_values() {
    let h = harness().await;
    let a = alice();
    h.define(
        &a,
        "writing.length",
        "STRING",
        json!({ "description": "How long answers run" }),
    )
    .await;
    h.define(
        &a,
        "food.diet",
        "STRING",
        json!({ "description": "Dietary pattern" }),
    )
    .await;
    h.set(&a, "writing.length", json!("verbose")).await;
    h.set(&a, "food.diet", json!("vegan")).await;

    let everything = h.search(&a, json!({})).await;
    assert_eq!(everything["success"], true);
    assert_eq!(everything["active"]["count"], 2);
    assert!(everything.get("suggested").is_none());
    // Omitting the query and passing an empty one both return all active.
    assert_eq!(
        h.search(&a, json!({ "query": "" })).await["active"]["count"],
        2
    );

    let cases: [(&str, &[&str]); 7] = [
        ("writing.len", &["writing.length"]), // slug prefix
        ("WRITING", &["writing.length"]),     // category substring, case-insensitive
        ("rit", &["writing.length"]),         // category substring
        ("answers", &["writing.length"]),     // description substring
        ("DIETARY", &["food.diet"]),          // description substring, lowercased
        ("length", &[]),                      // slug substring is NOT a match
        ("verbose", &[]),                     // values are never searched
    ];
    for (query, expected) in cases {
        let found = h.search(&a, json!({ "query": query })).await;
        let slugs: Vec<String> = values(&found, "active")
            .into_iter()
            .map(|(s, _)| s)
            .collect();
        assert_eq!(slugs, expected, "query {query:?}");
    }

    let found = h.search(&a, json!({ "query": "writing" })).await;
    let preference = &found["active"]["preferences"][0];
    assert_eq!(preference["slug"], "writing.length");
    assert_eq!(preference["value"], "verbose");
    assert_eq!(preference["status"], "ACTIVE");
    assert_eq!(preference["sourceType"], "INFERRED");
    assert_eq!(preference["confidence"], Value::Null);
    assert_eq!(preference["locationId"], Value::Null);
    assert_eq!(preference["category"], "writing");
    assert_eq!(preference["description"], "How long answers run");
    assert!(preference["id"].as_str().is_some());
    assert!(preference["updatedAt"].as_str().is_some());
}

#[tokio::test]
async fn search_truncates_each_list_and_rejects_location_and_bad_flags() {
    let h = harness().await;
    let a = alice();
    let bad = h.search(&a, json!({ "locationId": "office" })).await;
    assert_eq!(bad["success"], false);
    assert_eq!(bad["code"], "UNSUPPORTED_SCOPE");
    let bad = h.search(&a, json!({ "includeSuggestions": "yes" })).await;
    assert_eq!(bad["success"], false);
    assert!(bad["error"]
        .as_str()
        .unwrap()
        .contains("includeSuggestions"));
    let bad = h.search(&a, json!({ "query": 5 })).await;
    assert_eq!(bad["success"], false);
}

// ---- suggestions --------------------------------------------------------

#[tokio::test]
async fn suggestions_appear_only_when_asked_and_are_not_active_values() {
    let h = harness().await;
    let a = alice();
    h.define(&a, "writing.length", "STRING", json!({})).await;
    h.set(&a, "writing.length", json!("verbose")).await;
    let suggestion = h.suggest(&a, "writing.length", json!("brief"), 0.8).await;
    assert_eq!(suggestion["success"], true, "{suggestion}");
    assert_eq!(suggestion["changed"], true);
    assert_eq!(suggestion["requiredPermission"], "SUGGEST");
    assert_eq!(suggestion["preference"]["status"], "SUGGESTED");
    assert_eq!(suggestion["preference"]["value"], "brief");
    assert_eq!(suggestion["preference"]["confidence"], 0.8);

    let plain = h.search(&a, json!({})).await;
    assert!(
        plain.get("suggested").is_none(),
        "key absent unless includeSuggestions === true"
    );
    assert_eq!(
        values(&plain, "active"),
        [("writing.length".into(), json!("verbose"))]
    );
    let falsy = h.search(&a, json!({ "includeSuggestions": false })).await;
    assert!(falsy.get("suggested").is_none());

    let asked = h.search(&a, json!({ "includeSuggestions": true })).await;
    assert_eq!(
        values(&asked, "active"),
        [("writing.length".into(), json!("verbose"))]
    );
    assert_eq!(
        values(&asked, "suggested"),
        [("writing.length".into(), json!("brief"))]
    );
    assert_eq!(asked["suggested"]["count"], 1);
    assert_ne!(
        asked["suggested"]["preferences"][0]["id"],
        asked["active"]["preferences"][0]["id"]
    );
    // An empty suggested list is still present when asked for.
    h.define(&a, "food.diet", "STRING", json!({})).await;
    let empty = h
        .search(&a, json!({ "query": "food", "includeSuggestions": true }))
        .await;
    assert_eq!(empty["suggested"], json!({ "count": 0, "preferences": [] }));
}

#[tokio::test]
async fn a_suggestion_for_a_slug_without_a_value_is_suggested_only_until_accepted() {
    let h = harness().await;
    let a = alice();
    h.define(&a, "writing.length", "STRING", json!({})).await;
    let suggestion = h.suggest(&a, "writing.length", json!("brief"), 0.6).await;
    assert_eq!(suggestion["success"], true, "{suggestion}");
    let asked = h.search(&a, json!({ "includeSuggestions": true })).await;
    assert_eq!(
        asked["active"]["count"], 0,
        "a value-less record is not an ACTIVE value"
    );
    assert_eq!(asked["suggested"]["count"], 1);
    let suggestion_id = asked["suggested"]["preferences"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Accepting in Native revises the preference record in place.
    let accepted = crate::mcp::tools::suggestions::resolve_suggestions(
        h.db.clone(),
        alice(),
        json!({ "action": "accept", "suggestion_ids": [suggestion_id], "reason": "reviewed" }),
    )
    .await
    .unwrap();
    assert_eq!(accepted["status"], "accepted", "{accepted}");
    let after = h.search(&a, json!({ "includeSuggestions": true })).await;
    assert_eq!(
        values(&after, "active"),
        [("writing.length".into(), json!("brief"))]
    );
    assert_eq!(after["suggested"]["count"], 0);
}

#[tokio::test]
async fn repeat_suggestions_revise_one_row_and_suppress_no_ops() {
    let h = harness().await;
    let a = alice();
    h.define(&a, "writing.length", "STRING", json!({})).await;
    h.set(&a, "writing.length", json!("verbose")).await;
    // Suggesting the value that is already active changes nothing.
    let same = h.suggest(&a, "writing.length", json!("verbose"), 0.9).await;
    assert_eq!(same["success"], true);
    assert_eq!(same["changed"], false);
    assert_eq!(same["code"], "SUGGESTION_SUPPRESSED");
    assert!(same.get("preference").is_none());

    assert_eq!(
        h.suggest(&a, "writing.length", json!("brief"), 0.5).await["changed"],
        true
    );
    let again = h.suggest(&a, "writing.length", json!("terse"), 0.7).await;
    assert_eq!(again["changed"], true);
    assert_eq!(again["preference"]["value"], "terse");
    let repeat = h.suggest(&a, "writing.length", json!("terse"), 0.7).await;
    assert_eq!(repeat["code"], "SUGGESTION_SUPPRESSED");
    let asked = h.search(&a, json!({ "includeSuggestions": true })).await;
    assert_eq!(asked["suggested"]["count"], 1, "one SUGGESTED row per slug");
    assert_eq!(
        values(&asked, "suggested"),
        [("writing.length".into(), json!("terse"))]
    );
}

// ---- value encoding and input validation -------------------------------

#[tokio::test]
async fn values_travel_as_json_strings_and_are_checked_against_the_value_type() {
    let h = harness().await;
    let a = alice();
    h.define(&a, "writing.length", "STRING", json!({})).await;
    h.define(&a, "ui.dark", "BOOLEAN", json!({})).await;
    h.define(
        &a,
        "food.diet",
        "ENUM",
        json!({ "options": ["vegan", "none"] }),
    )
    .await;
    h.define(&a, "food.avoid", "ARRAY", json!({})).await;

    for (slug, value) in [
        ("writing.length", json!("concise")),
        ("ui.dark", json!(true)),
        ("food.diet", json!("vegan")),
        ("food.avoid", json!(["nuts", "dairy"])),
    ] {
        let result = h.set(&a, slug, value.clone()).await;
        assert_eq!(result["success"], true, "{slug}: {result}");
        assert_eq!(
            result["preference"]["value"], value,
            "decoded on the way out"
        );
    }

    let wire = |slug: &str, value: Value| json!({ "operation": "SET_PREFERENCE", "preference": { "slug": slug, "value": value } });
    // Not a JSON-encoded string: raw JSON values and unparseable text.
    for bad in [
        json!("not json"),
        json!(""),
        json!(true),
        json!(["x"]),
        Value::Null,
    ] {
        let result = h.mutate(&a, wire("writing.length", bad.clone())).await;
        assert_eq!(result["success"], false, "{bad}");
        assert_eq!(result["code"], "INVALID_MUTATION_INPUT", "{bad}: {result}");
        assert_eq!(result["changed"], false);
    }
    // Valid JSON of the wrong type or outside the options.
    for (slug, value) in [
        ("writing.length", "true"),
        ("ui.dark", "\"yes\""),
        ("food.diet", "\"carnivore\""),
        ("food.avoid", "\"nuts\""),
    ] {
        let result = h.mutate(&a, wire(slug, json!(value))).await;
        assert_eq!(
            result["code"], "INVALID_PREFERENCE_VALUE",
            "{slug}: {result}"
        );
    }
    let unchanged = h.search(&a, json!({ "query": "writing" })).await;
    assert_eq!(
        values(&unchanged, "active"),
        [("writing.length".into(), json!("concise"))]
    );
}

#[tokio::test]
async fn suggestions_need_confidence_and_evidence_must_be_a_structured_object() {
    let h = harness().await;
    let a = alice();
    h.define(&a, "writing.length", "STRING", json!({})).await;
    let preference = |extra: Value| {
        let mut p = json!({ "slug": "writing.length", "value": "\"brief\"" });
        for (k, v) in extra.as_object().unwrap() {
            p[k] = v.clone();
        }
        p
    };
    let attempt = |operation: &str, extra: Value| json!({ "operation": operation, "preference": preference(extra) });

    for (operation, extra) in [
        ("SUGGEST_PREFERENCE", json!({})), // confidence required
        ("SUGGEST_PREFERENCE", json!({ "confidence": 1.5 })),
        ("SUGGEST_PREFERENCE", json!({ "confidence": -0.1 })),
        ("SUGGEST_PREFERENCE", json!({ "confidence": "high" })),
        ("SET_PREFERENCE", json!({ "confidence": 2 })),
        ("SET_PREFERENCE", json!({ "evidence": "{\"quote\":\"x\"}" })), // JSON-encoded string
        ("SET_PREFERENCE", json!({ "evidence": ["x"] })),               // array
        ("SET_PREFERENCE", json!({ "evidence": null })),                // null
        (
            "SUGGEST_PREFERENCE",
            json!({ "confidence": 0.5, "evidence": 7 }),
        ),
    ] {
        let result = h.mutate(&a, attempt(operation, extra.clone())).await;
        assert_eq!(
            result["code"], "INVALID_MUTATION_INPUT",
            "{operation} {extra}: {result}"
        );
        assert_eq!(result["success"], false);
    }
    // Confidence is optional for SET and evidence may be omitted.
    assert_eq!(
        h.mutate(&a, attempt("SET_PREFERENCE", json!({}))).await["success"],
        true
    );
    let with_both = h
        .mutate(
            &a,
            attempt(
                "SET_PREFERENCE",
                json!({ "confidence": 0.25, "evidence": { "quote": "x" } }),
            ),
        )
        .await;
    assert_eq!(with_both["preference"]["confidence"], 0.25);
}

#[tokio::test]
async fn unknown_operation_slug_and_scope_errors() {
    let h = harness().await;
    let a = alice();
    h.define(&a, "writing.length", "STRING", json!({})).await;
    let missing = h.mutate(&a, json!({})).await;
    assert_eq!(missing["success"], false);
    assert_eq!(missing["code"], "INVALID_MUTATION_OPERATION");
    let unknown = h.mutate(&a, json!({ "operation": "WIPE" })).await;
    assert_eq!(unknown["code"], "INVALID_MUTATION_OPERATION");
    assert_eq!(unknown["audit"]["origin"], "MCP");
    let no_preference = h.mutate(&a, json!({ "operation": "SET_PREFERENCE" })).await;
    assert_eq!(no_preference["code"], "INVALID_MUTATION_INPUT");
    let unknown_slug = h.set(&a, "nobody.knows", json!("x")).await;
    assert_eq!(unknown_slug["code"], "UNKNOWN_PREFERENCE_SLUG");
    assert_eq!(unknown_slug["target"], "nobody.knows");
    let located = h
        .mutate(
            &a,
            json!({ "operation": "SET_PREFERENCE",
                    "preference": { "slug": "writing.length", "value": "\"x\"", "locationId": "office" } }),
        )
        .await;
    assert_eq!(located["code"], "UNSUPPORTED_SCOPE");
    let location_definition = h
        .define(&a, "home.theme", "STRING", json!({ "scope": "LOCATION" }))
        .await;
    assert_eq!(location_definition["code"], "UNSUPPORTED_SCOPE");
}

// ---- revise in place and history ----------------------------------------

#[tokio::test]
async fn set_revises_the_same_record_and_history_keeps_earlier_values() {
    let h = harness().await;
    let a = alice();
    h.define(&a, "writing.length", "STRING", json!({})).await;
    let first = h.set(&a, "writing.length", json!("verbose")).await;
    let id = first["preference"]["id"].as_str().unwrap().to_string();
    let second = h.set(&a, "writing.length", json!("concise")).await;
    assert_eq!(
        second["preference"]["id"], id,
        "revised in place: stable id"
    );
    assert_eq!(second["preference"]["value"], "concise");

    let found = h.search(&a, json!({})).await;
    assert_eq!(found["active"]["count"], 1);
    assert_eq!(found["active"]["preferences"][0]["id"], id);

    let bodies: Vec<String> =
        sqlx::query_scalar("SELECT payload FROM content_events WHERE record_id = ? ORDER BY seq")
            .bind(&id)
            .fetch_all(h.db.pool())
            .await
            .unwrap();
    assert!(
        bodies.iter().any(|p| p.contains("verbose"))
            && bodies.iter().any(|p| p.contains("concise")),
        "both values survive in history: {bodies:?}"
    );
}

#[tokio::test]
async fn the_preference_is_a_governed_resolution_preference_record() {
    let h = harness().await;
    let a = alice();
    h.define(&a, "writing.length", "STRING", json!({})).await;
    let set = h.set(&a, "writing.length", json!("concise")).await;
    let id = set["preference"]["id"].as_str().unwrap();
    let (record_type, kind, name, body): (String, String, String, String) =
        sqlx::query_as("SELECT type, kind, name, body FROM records WHERE id = ?")
            .bind(id)
            .fetch_one(h.db.pool())
            .await
            .unwrap();
    assert_eq!(
        (record_type.as_str(), kind.as_str()),
        ("Resolution", "preference")
    );
    assert_eq!(name, "writing.length");
    assert_eq!(body, "\"concise\"");
}

// ---- delete -------------------------------------------------------------

#[tokio::test]
async fn delete_resolves_the_slug_from_the_id_and_clears_the_value() {
    let h = harness().await;
    let a = alice();
    h.define(&a, "writing.length", "STRING", json!({})).await;
    let set = h.set(&a, "writing.length", json!("concise")).await;
    let id = set["preference"]["id"].as_str().unwrap().to_string();

    // The caller names only the id; the slug comes back as the target.
    let deleted = h
        .mutate(
            &a,
            json!({ "operation": "DELETE_PREFERENCE", "preference": { "id": id } }),
        )
        .await;
    assert_eq!(deleted["success"], true, "{deleted}");
    assert_eq!(deleted["changed"], true);
    assert_eq!(deleted["requiredPermission"], "WRITE");
    assert_eq!(deleted["target"], "writing.length");
    assert_eq!(deleted["preference"]["value"], "concise");
    assert_eq!(h.search(&a, json!({})).await["active"]["count"], 0);

    let again = h
        .mutate(
            &a,
            json!({ "operation": "DELETE_PREFERENCE", "preference": { "id": id } }),
        )
        .await;
    assert_eq!(again["code"], "PREFERENCE_NOT_FOUND");
    let missing_id = h
        .mutate(
            &a,
            json!({ "operation": "DELETE_PREFERENCE", "preference": {} }),
        )
        .await;
    assert_eq!(missing_id["code"], "INVALID_MUTATION_INPUT");

    // Deleting clears the value and keeps the record (pending suggestions stay
    // attached to it), so a value set afterwards revives the same record.
    let reset = h.set(&a, "writing.length", json!("brief")).await;
    assert_eq!(reset["preference"]["id"], id.as_str());
}

#[tokio::test]
async fn deleting_a_suggestion_id_rejects_that_suggestion() {
    let h = harness().await;
    let a = alice();
    h.define(&a, "writing.length", "STRING", json!({})).await;
    h.set(&a, "writing.length", json!("verbose")).await;
    let suggested = h.suggest(&a, "writing.length", json!("brief"), 0.8).await;
    let suggestion_id = suggested["preference"]["id"].as_str().unwrap().to_string();
    let deleted = h
        .mutate(
            &a,
            json!({ "operation": "DELETE_PREFERENCE", "preference": { "id": suggestion_id } }),
        )
        .await;
    assert_eq!(deleted["success"], true, "{deleted}");
    assert_eq!(deleted["target"], "writing.length");
    assert_eq!(deleted["preference"]["status"], "SUGGESTED");
    let after = h.search(&a, json!({ "includeSuggestions": true })).await;
    assert_eq!(after["suggested"]["count"], 0);
    assert_eq!(
        values(&after, "active"),
        [("writing.length".into(), json!("verbose"))]
    );
}

// ---- definition operations ----------------------------------------------

#[tokio::test]
async fn definition_create_update_archive_and_their_error_codes() {
    let h = harness().await;
    let a = alice();
    let invalid = |slug: &str| json!({ "slug": slug, "description": "d", "valueType": "STRING", "scope": "GLOBAL" });
    for bad in ["nodot", "Upper.case", "a..b"] {
        let result = h
            .mutate(
                &a,
                json!({ "operation": "CREATE_DEFINITION", "definition": invalid(bad) }),
            )
            .await;
        assert_eq!(
            result["code"], "INVALID_PREFERENCE_DEFINITION",
            "{bad}: {result}"
        );
    }
    let missing = h
        .mutate(
            &a,
            json!({ "operation": "CREATE_DEFINITION", "definition": { "slug": "a.b" } }),
        )
        .await;
    assert_eq!(missing["code"], "INVALID_MUTATION_INPUT");
    // ENUM needs options; other types forbid them.
    assert_eq!(
        h.define(&a, "a.b", "ENUM", json!({})).await["code"],
        "INVALID_PREFERENCE_DEFINITION"
    );
    assert_eq!(
        h.define(&a, "a.b", "STRING", json!({ "options": ["x"] }))
            .await["code"],
        "INVALID_PREFERENCE_DEFINITION"
    );
    assert_eq!(
        h.define(&a, "a.b", "CHAOS", json!({})).await["code"],
        "INVALID_PREFERENCE_DEFINITION"
    );
    assert_eq!(
        h.define(&a, "writing.length", "STRING", json!({})).await["success"],
        true
    );
    assert_eq!(
        h.define(&a, "writing.length", "STRING", json!({})).await["code"],
        "PREFERENCE_DEFINITION_CONFLICT"
    );

    // UPDATE by slug.
    let updated = h
        .mutate(
            &a,
            json!({ "operation": "UPDATE_DEFINITION",
                    "definition": { "slug": "writing.length", "description": "New words", "displayName": "Len" } }),
        )
        .await;
    assert_eq!(updated["success"], true, "{updated}");
    assert_eq!(updated["requiredPermission"], "DEFINE");
    assert_eq!(updated["definition"]["description"], "New words");
    assert_eq!(updated["definition"]["displayName"], "Len");
    // A type change that strands a stored value is refused.
    h.set(&a, "writing.length", json!("concise")).await;
    let strand = h
        .mutate(
            &a,
            json!({ "operation": "UPDATE_DEFINITION",
                    "definition": { "slug": "writing.length", "valueType": "BOOLEAN" } }),
        )
        .await;
    assert_eq!(strand["code"], "INVALID_PREFERENCE_DEFINITION");
    let rename = h
        .mutate(
            &a,
            json!({ "operation": "UPDATE_DEFINITION",
                    "definition": { "id": updated["definition"]["id"], "slug": "writing.other" } }),
        )
        .await;
    assert_eq!(rename["code"], "INVALID_MUTATION_INPUT");
    let unknown = h
        .mutate(
            &a,
            json!({ "operation": "UPDATE_DEFINITION", "definition": { "slug": "no.such" } }),
        )
        .await;
    assert_eq!(unknown["code"], "PREFERENCE_DEFINITION_NOT_FOUND");
    let neither = h
        .mutate(
            &a,
            json!({ "operation": "UPDATE_DEFINITION", "definition": {} }),
        )
        .await;
    assert_eq!(neither["code"], "INVALID_MUTATION_INPUT");

    // ARCHIVE hides the definition and its values; archived definitions refuse edits.
    let id = updated["definition"]["id"].clone();
    let archived = h
        .mutate(
            &a,
            json!({ "operation": "ARCHIVE_DEFINITION", "definition": { "id": id } }),
        )
        .await;
    assert_eq!(archived["success"], true, "{archived}");
    assert_eq!(archived["definition"]["category"], "writing");
    assert!(archived["definition"]["archivedAt"].as_str().is_some());
    assert!(h.slugs(&a).await.is_empty());
    assert_eq!(h.search(&a, json!({})).await["active"]["count"], 0);
    assert_eq!(
        h.set(&a, "writing.length", json!("x")).await["code"],
        "UNKNOWN_PREFERENCE_SLUG"
    );
    let again = h
        .mutate(
            &a,
            json!({ "operation": "ARCHIVE_DEFINITION", "definition": { "id": id } }),
        )
        .await;
    assert_eq!(again["code"], "PREFERENCE_DEFINITION_ARCHIVED");
    let edit = h
        .mutate(&a, json!({ "operation": "UPDATE_DEFINITION", "definition": { "id": id, "description": "x" } }))
        .await;
    assert_eq!(edit["code"], "PREFERENCE_DEFINITION_ARCHIVED");
    // An archived slug is free to define again.
    assert_eq!(
        h.define(&a, "writing.length", "STRING", json!({})).await["success"],
        true
    );
}

// ---- sensitivity --------------------------------------------------------

#[tokio::test]
async fn sensitive_definitions_and_values_stay_out_of_this_interface() {
    let h = harness().await;
    let a = alice();
    let denied = h
        .define(
            &a,
            "health.condition",
            "STRING",
            json!({ "isSensitive": true }),
        )
        .await;
    assert_eq!(denied["success"], false);
    assert_eq!(denied["code"], "MCP_PERMISSION_DENIED");
    assert_eq!(denied["error"], "Sensitive preference access denied");

    // Seed a sensitive definition and value the way Native itself could hold
    // them (written below this interface), then check every read path.
    h.define(&a, "health.condition", "STRING", json!({})).await;
    h.set(&a, "health.condition", json!("asthma")).await;
    h.define(&a, "writing.length", "STRING", json!({})).await;
    h.set(&a, "writing.length", json!("concise")).await;
    h.suggest(&a, "health.condition", json!("pollen"), 0.5)
        .await;
    {
        let store = Store::new(&h.db, &a);
        let record = store.load_catalog().await.unwrap().unwrap();
        let mut catalog = record.catalog.clone();
        for definition in &mut catalog.definitions {
            if definition.slug == "health.condition" {
                definition.is_sensitive = true;
            }
        }
        store
            .save_catalog(Some(&record), &catalog, "test seed")
            .await
            .unwrap();
    }

    assert_eq!(h.slugs(&a).await, ["writing.length"]);
    let listed = h
        .call(&a, LIST_PREFERENCE_SLUGS, json!({ "category": "health" }))
        .await;
    assert_eq!(listed["count"], 0);
    assert_eq!(listed["categories"], json!([]));
    let found = h.search(&a, json!({ "includeSuggestions": true })).await;
    assert_eq!(
        values(&found, "active"),
        [("writing.length".into(), json!("concise"))]
    );
    assert_eq!(found["suggested"]["count"], 0);
    assert!(!found.to_string().contains("asthma") && !found.to_string().contains("pollen"));

    let set = h.set(&a, "health.condition", json!("flu")).await;
    assert_eq!(set["code"], "MCP_PERMISSION_DENIED");
    let suggest = h.suggest(&a, "health.condition", json!("flu"), 0.1).await;
    assert_eq!(suggest["code"], "MCP_PERMISSION_DENIED");
    let update = h
        .mutate(
            &a,
            json!({ "operation": "UPDATE_DEFINITION",
                    "definition": { "slug": "health.condition", "description": "x" } }),
        )
        .await;
    assert_eq!(update["code"], "MCP_PERMISSION_DENIED");
    let archive = h
        .mutate(&a, json!({ "operation": "ARCHIVE_DEFINITION", "definition": { "slug": "health.condition" } }))
        .await;
    assert_eq!(archive["code"], "MCP_PERMISSION_DENIED");
    // Marking an existing definition sensitive is refused too.
    let flag = h
        .mutate(
            &a,
            json!({ "operation": "UPDATE_DEFINITION",
                    "definition": { "slug": "writing.length", "isSensitive": true } }),
        )
        .await;
    assert_eq!(flag["code"], "MCP_PERMISSION_DENIED");

    // DELETE resolves the slug from the id first, then refuses on the slug.
    let sensitive_id: String = sqlx::query_scalar(
        "SELECT r.id FROM records r JOIN facet_values f ON f.record_id = r.id AND f.key = 'hcp.slug' \
         WHERE r.type = 'Resolution' AND f.value = 'health.condition'",
    )
    .fetch_one(h.db.pool())
    .await
    .unwrap();
    let delete = h
        .mutate(
            &a,
            json!({ "operation": "DELETE_PREFERENCE", "preference": { "id": sensitive_id } }),
        )
        .await;
    assert_eq!(delete["code"], "MCP_PERMISSION_DENIED");
    assert_eq!(delete["target"], "health.condition");
    assert!(
        !delete.to_string().contains("asthma"),
        "no value leaks through a refusal"
    );
}

// ---- Native authorization, attribution, fresh reads ---------------------

#[tokio::test]
async fn a_write_is_visible_to_a_fresh_read_and_only_to_its_person() {
    let h = harness().await;
    let a = alice();
    h.define(&a, "writing.length", "STRING", json!({})).await;
    h.set(&a, "writing.length", json!("concise")).await;

    // A new caller value for the same account (a fresh connection) reads it back.
    let fresh = caller("acct:alice", Some("another_client"));
    assert_eq!(h.slugs(&fresh).await, ["writing.length"]);
    let found = h.search(&fresh, json!({})).await;
    assert_eq!(
        values(&found, "active"),
        [("writing.length".into(), json!("concise"))]
    );

    // Another person sees none of it: Native's own authorization holds the
    // catalog and values account-only, and their calls start from nothing.
    onboard(&h.db, "acct:bob").await;
    let bob = caller("acct:bob", Some("client_alice_app"));
    assert!(h.slugs(&bob).await.is_empty());
    assert_eq!(h.search(&bob, json!({})).await["active"]["count"], 0);
    assert_eq!(
        h.set(&bob, "writing.length", json!("x")).await["code"],
        "UNKNOWN_PREFERENCE_SLUG"
    );
    assert_eq!(
        h.define(&bob, "writing.length", "STRING", json!({})).await["success"],
        true
    );
    h.set(&bob, "writing.length", json!("verbose")).await;
    // Bob's write did not touch Alice's value.
    let alice_again = h.search(&a, json!({})).await;
    assert_eq!(
        values(&alice_again, "active"),
        [("writing.length".into(), json!("concise"))]
    );
}

#[tokio::test]
async fn client_id_is_attribution_only() {
    let h = harness().await;
    let named = caller("acct:alice", Some("client_one"));
    let other = caller("acct:alice", Some("client_two"));
    let anonymous = caller("acct:alice", None);

    let defined = h
        .define(&named, "writing.length", "STRING", json!({}))
        .await;
    assert_eq!(defined["audit"]["actorClientKey"], "client_one");
    let set = h.set(&other, "writing.length", json!("concise")).await;
    assert_eq!(set["success"], true);
    assert_eq!(set["audit"]["actorClientKey"], "client_two");
    // Same person, any client (or none): identical access.
    let id = set["preference"]["id"].as_str().unwrap().to_string();
    for who in [&named, &other, &anonymous] {
        let found = h.search(who, json!({})).await;
        assert_eq!(
            values(&found, "active"),
            [("writing.length".into(), json!("concise"))]
        );
        assert_eq!(
            h.call(who, LIST_PERMISSION_GRANTS, json!({})).await["grants"],
            json!([])
        );
    }
    let anon_set = h.set(&anonymous, "writing.length", json!("brief")).await;
    assert_eq!(anon_set["success"], true);
    assert_eq!(anon_set["audit"]["actorClientKey"], "unknown");

    let (client, correlation): (String, String) = sqlx::query_as(
        "SELECT c.value, o.value FROM facet_values c \
         JOIN facet_values o ON o.record_id = c.record_id AND o.key = 'hcp.correlation' \
         WHERE c.record_id = ? AND c.key = 'hcp.client'",
    )
    .bind(&id)
    .fetch_one(h.db.pool())
    .await
    .unwrap();
    assert_eq!(client, "unknown", "the latest writer is recorded");
    assert_eq!(
        correlation,
        anon_set["audit"]["correlationId"].as_str().unwrap()
    );
}

#[tokio::test]
async fn each_mutation_gets_its_own_correlation_id() {
    let h = harness().await;
    let a = alice();
    let one = h.define(&a, "writing.length", "STRING", json!({})).await;
    let two = h.set(&a, "writing.length", json!("x")).await;
    assert_ne!(one["audit"]["correlationId"], two["audit"]["correlationId"]);
}

#[tokio::test]
async fn read_failures_use_the_success_false_envelope() {
    let h = harness().await;
    let result = h
        .call(&alice(), LIST_PREFERENCE_SLUGS, json!({ "category": 7 }))
        .await;
    assert_eq!(result["success"], false);
    assert!(result["error"].as_str().is_some());
}

// ---- MCP framing ----------------------------------------------------------

#[tokio::test]
async fn results_are_framed_as_context_router_envelopes() {
    let h = harness().await;
    let a = alice();
    // Success: text is the JSON of structuredContent; no isError.
    let listed = h.frame(&a, LIST_PREFERENCE_SLUGS, json!({})).await;
    assert_eq!(listed["isError"], false);
    let text: Value = serde_json::from_str(listed["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(text, listed["structuredContent"]);
    assert_eq!(listed["content"].as_array().unwrap().len(), 1);

    // Business failure: success:false with isError, for reads and for mutations.
    let failed_read = h
        .frame(&a, SEARCH_PREFERENCES, json!({ "locationId": "x" }))
        .await;
    assert_eq!(failed_read["isError"], true);
    assert_eq!(failed_read["structuredContent"]["success"], false);
    let failed_write = h
        .frame(&a, MUTATE_PREFERENCES, json!({ "operation": "NOPE" }))
        .await;
    assert_eq!(failed_write["isError"], true);
    assert_eq!(failed_write["structuredContent"]["changed"], false);
    // A no-op suggestion is a success, not an error.
    h.define(&a, "writing.length", "STRING", json!({})).await;
    h.set(&a, "writing.length", json!("x")).await;
    let suppressed = h
        .frame(
            &a,
            MUTATE_PREFERENCES,
            json!({ "operation": "SUGGEST_PREFERENCE",
                    "preference": { "slug": "writing.length", "value": "\"x\"", "confidence": 0.5 } }),
        )
        .await;
    assert_eq!(suppressed["isError"], false);
    assert_eq!(
        suppressed["structuredContent"]["code"],
        "SUGGESTION_SUPPRESSED"
    );
    // The universal run-context echo is not part of this contract.
    assert!(listed["structuredContent"].get("run_context").is_none());
}

#[tokio::test]
async fn an_unknown_tool_returns_error_without_a_success_field() {
    let h = harness().await;
    for name in ["consolidateSchema", "bootstrap", "create_record"] {
        let frame = h.frame(&alice(), name, json!({})).await;
        assert_eq!(frame["isError"], true, "{name}");
        assert_eq!(
            frame["structuredContent"],
            json!({ "error": format!("Unknown tool: {name}") })
        );
    }
}

#[tokio::test]
async fn re_creating_an_archived_slug_starts_empty() {
    let h = harness().await;
    let a = alice();
    let first = h.define(&a, "writing.length", "STRING", json!({})).await;
    h.set(&a, "writing.length", json!("concise")).await;
    h.suggest(&a, "writing.length", json!("brief"), 0.5).await;
    let archived = h
        .mutate(
            &a,
            json!({ "operation": "ARCHIVE_DEFINITION", "definition": { "id": first["definition"]["id"] } }),
        )
        .await;
    assert_eq!(archived["success"], true);

    // Same slug, new definition: nothing written under the old one reappears.
    assert_eq!(
        h.define(&a, "writing.length", "STRING", json!({})).await["success"],
        true
    );
    let found = h.search(&a, json!({ "includeSuggestions": true })).await;
    assert_eq!(found["active"]["count"], 0);
    assert_eq!(found["suggested"]["count"], 0);
    let set = h.set(&a, "writing.length", json!("verbose")).await;
    assert_eq!(set["success"], true);
    let found = h.search(&a, json!({ "includeSuggestions": true })).await;
    assert_eq!(
        values(&found, "active"),
        [("writing.length".into(), json!("verbose"))]
    );
    assert_eq!(found["suggested"]["count"], 0);
}

#[test]
fn item10_admission_classifies_the_read_tools_as_reads_and_the_mutator_as_a_mutation() {
    use crate::mcp::OperationAccess;
    let mut registry = ToolRegistry::new();
    register_hcp_tools(&mut registry).unwrap();
    for name in [
        LIST_PREFERENCE_SLUGS,
        SEARCH_PREFERENCES,
        LIST_PERMISSION_GRANTS,
        SMART_SEARCH_PREFERENCES,
    ] {
        let (_, access) = registry.registered_operation(name, &json!({})).unwrap();
        assert_eq!(access, OperationAccess::Read, "{name}");
    }
    // Arguments cannot change a tool's classification.
    let (_, access) = registry
        .registered_operation(
            MUTATE_PREFERENCES,
            &json!({ "operation": "SEARCH", "readOnly": true }),
        )
        .unwrap();
    assert_eq!(access, OperationAccess::Mutation);
    // Only custom tools can be declared read-only.
    let mut shipped = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut shipped).unwrap();
    assert!(shipped.declare_read_only("ping").is_err());
}

// ---- the workspace opt-in check -----------------------------------------

async fn every_tool_refuses(h: &Harness, expected_fragment: &str) {
    let a = alice();
    let calls = [
        (LIST_PREFERENCE_SLUGS, json!({})),
        (SEARCH_PREFERENCES, json!({ "query": "x" })),
        (LIST_PERMISSION_GRANTS, json!({})),
        (SMART_SEARCH_PREFERENCES, json!({ "query": "x" })),
        (
            MUTATE_PREFERENCES,
            json!({ "operation": "CREATE_DEFINITION",
                    "definition": { "slug": "a.b", "description": "d",
                                    "valueType": "STRING", "scope": "GLOBAL" } }),
        ),
        (
            MUTATE_PREFERENCES,
            json!({ "operation": "NOT_AN_OPERATION" }),
        ),
    ];
    for (tool, args) in calls {
        let frame = h.frame(&a, tool, args).await;
        assert_eq!(frame["isError"], true, "{tool}: {frame}");
        let body = &frame["structuredContent"];
        assert_eq!(body["success"], false, "{tool}");
        assert_eq!(body["code"], "HCP_NOT_CONFIGURED", "{tool}: {body}");
        let message = body["error"].as_str().unwrap();
        assert!(message.contains(expected_fragment), "{tool}: {message}");
        assert!(message.contains("docs/hosted-mcp.md"), "{tool}: {message}");
        if tool == MUTATE_PREFERENCES {
            assert_eq!(body["changed"], false);
            assert_eq!(body["audit"]["origin"], "MCP");
        }
    }
}

async fn nothing_was_written(h: &Harness) {
    let records: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM records WHERE kind IN ('preference') \
            OR name = 'HCP preference catalog'",
    )
    .fetch_one(h.db.pool())
    .await
    .unwrap();
    assert_eq!(records, 0, "a refused call must not write");
    let kind_active: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM vocabulary_values WHERE id = 'vv:voc:kind:Resolution:preference' \
            AND status = 'active'",
    )
    .fetch_one(h.db.pool())
    .await
    .unwrap();
    assert_eq!(kind_active, 0, "/hcp never promotes the kind itself");
}

#[tokio::test]
async fn every_tool_refuses_while_the_preference_kind_is_not_defined() {
    let h = unconfigured_harness().await;
    every_tool_refuses(&h, "is not defined").await;
    nothing_was_written(&h).await;
    // Not even a proposal was made on the workspace's behalf.
    let proposed: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM vocabulary_values WHERE id = 'vv:voc:kind:Resolution:preference'",
    )
    .fetch_one(h.db.pool())
    .await
    .unwrap();
    assert_eq!(proposed, 0);
}

#[tokio::test]
async fn every_tool_refuses_while_the_kind_is_proposed_but_not_promoted() {
    let h = unconfigured_harness().await;
    propose_preference_kind(&h.db).await;
    every_tool_refuses(&h, "has not been promoted").await;
    nothing_was_written(&h).await;
}

#[tokio::test]
async fn promotion_takes_effect_on_the_next_request_and_deprecation_stops_hcp() {
    let h = unconfigured_harness().await;
    let a = alice();
    propose_preference_kind(&h.db).await;
    assert_eq!(
        h.call(&a, LIST_PREFERENCE_SLUGS, json!({})).await["code"],
        "HCP_NOT_CONFIGURED"
    );
    promote_preference_kind(&h.db).await;
    // No restart, no cache to wait out.
    assert_eq!(
        h.call(&a, LIST_PREFERENCE_SLUGS, json!({})).await["success"],
        true
    );
    assert_eq!(
        h.define(&a, "writing.length", "STRING", json!({})).await["success"],
        true
    );

    let deprecated = manage_vocabularies(
        &h.db,
        json!({ "action": "deprecate_value", "value_id": "vv:voc:kind:Resolution:preference" }),
    )
    .await;
    assert_eq!(deprecated["status"], "deprecated", "{deprecated}");
    assert_eq!(
        h.call(&a, SEARCH_PREFERENCES, json!({})).await["code"],
        "HCP_NOT_CONFIGURED"
    );
}
