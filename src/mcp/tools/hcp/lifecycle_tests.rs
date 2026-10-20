//! Lifecycle and concurrency checks from the independent review of slice 1.
//! Each test names the review item it pins; every one failed against the
//! reviewed head (`f2419099e`) before its fix.

use serde_json::{json, Value};

use super::limits::TestBounds;
use super::store::Store;
use super::tests::{alice, harness, values, Harness};
use crate::mcp::registry::Caller;

/// What Native itself does with a suggestion, outside HCP. It goes through the
/// full tool registry, so the resolution is an attested `resolve_suggestions`
/// action exactly as in production (an unattested one cannot be shown to have
/// produced the body).
async fn native_resolve(h: &Harness, who: &Caller, action: &str, id: &str) -> Value {
    let mut registry = crate::mcp::registry::ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::register_surface_tools(&mut registry).unwrap();
    Box::pin(registry.call(
        h.db.clone(),
        who.clone(),
        "resolve_suggestions",
        json!({ "action": action, "suggestion_ids": [id], "reason": "test review" }),
    ))
    .await
    .unwrap()
}

async fn count_preference_records(h: &Harness, slug: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM records r JOIN facet_values f ON f.record_id = r.id AND f.key = 'hcp.slug' \
         WHERE r.type = 'Resolution' AND r.kind = 'preference' AND f.value = ?",
    )
    .bind(slug)
    .fetch_one(h.db.pool())
    .await
    .unwrap()
}

async fn suggestion_id(h: &Harness, who: &Caller, slug: &str) -> String {
    let found = h
        .search(who, json!({ "query": slug, "includeSuggestions": true }))
        .await;
    found["suggested"]["preferences"][0]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("no open suggestion for {slug}: {found}"))
        .to_string()
}

async fn stored_body(h: &Harness, id: &str) -> Option<String> {
    sqlx::query_scalar("SELECT body FROM records WHERE id = ?")
        .bind(id)
        .fetch_one(h.db.pool())
        .await
        .unwrap()
}

// ---- 1: a suggestion on an empty slug cannot overwrite a later SET --------

#[tokio::test]
async fn item1_a_shell_suggestion_is_anchored_to_the_empty_body() {
    let h = harness().await;
    let a = alice();
    h.define(&a, "writing.length", "STRING", json!({})).await;
    assert_eq!(
        h.suggest(&a, "writing.length", json!("brief"), 0.6).await["success"],
        true
    );
    let id = suggestion_id(&h, &a, "writing.length").await;
    let set = h.set(&a, "writing.length", json!("concise")).await;
    assert_eq!(set["success"], true);

    let accepted = native_resolve(&h, &a, "accept", &id).await;
    assert_ne!(
        accepted["status"], "accepted",
        "the later SET must survive: {accepted}"
    );
    let found = h.search(&a, json!({})).await;
    assert_eq!(
        values(&found, "active"),
        [("writing.length".into(), json!("concise"))]
    );
}

// ---- 2: UPDATE_DEFINITION and open suggestions ---------------------------

#[tokio::test]
async fn item2_a_definition_change_is_refused_while_a_suggestion_would_stop_fitting() {
    let h = harness().await;
    let a = alice();
    h.define(&a, "writing.length", "STRING", json!({})).await;
    h.suggest(&a, "writing.length", json!("brief"), 0.6).await;
    let to_boolean = json!({ "operation": "UPDATE_DEFINITION",
                             "definition": { "slug": "writing.length", "valueType": "BOOLEAN" } });
    let refused = h.mutate(&a, to_boolean.clone()).await;
    assert_eq!(
        refused["code"], "INVALID_PREFERENCE_DEFINITION",
        "{refused}"
    );
    assert!(
        refused["error"].as_str().unwrap().contains("suggestion"),
        "{refused}"
    );

    // The caller can clear the suggestion over HCP and then proceed.
    let id = suggestion_id(&h, &a, "writing.length").await;
    let deleted = h
        .mutate(
            &a,
            json!({ "operation": "DELETE_PREFERENCE", "preference": { "id": id } }),
        )
        .await;
    assert_eq!(deleted["success"], true, "{deleted}");
    assert_eq!(h.mutate(&a, to_boolean).await["success"], true);

    // An ENUM whose options narrow past a pending suggestion is refused too,
    // even though the active value still fits.
    h.define(
        &a,
        "food.diet",
        "ENUM",
        json!({ "options": ["a", "b", "c"] }),
    )
    .await;
    h.set(&a, "food.diet", json!("a")).await;
    h.suggest(&a, "food.diet", json!("c"), 0.5).await;
    let narrowed = h
        .mutate(
            &a,
            json!({ "operation": "UPDATE_DEFINITION",
                    "definition": { "slug": "food.diet", "options": ["a", "b"] } }),
        )
        .await;
    assert_eq!(
        narrowed["code"], "INVALID_PREFERENCE_DEFINITION",
        "{narrowed}"
    );
}

#[tokio::test]
async fn item2_a_definition_change_and_a_set_are_serialised() {
    let h = harness().await;
    let a = alice();
    h.define(&a, "food.diet", "ENUM", json!({ "options": ["a", "b"] }))
        .await;
    let narrow = h.mutate(
        &a,
        json!({ "operation": "UPDATE_DEFINITION",
                "definition": { "slug": "food.diet", "options": ["a"] } }),
    );
    let set_b = h.set(&a, "food.diet", json!("b"));
    let (narrow, set_b) = tokio::join!(narrow, set_b);
    assert!(
        narrow["success"] == true || set_b["success"] == true,
        "{narrow} {set_b}"
    );
    // Whatever the order, the stored value must satisfy the final definition.
    let listed = h.call(&a, super::LIST_PREFERENCE_SLUGS, json!({})).await;
    let options = listed["preferences"][0]["options"]
        .as_array()
        .unwrap()
        .clone();
    let found = h.search(&a, json!({})).await;
    for (_, value) in values(&found, "active") {
        assert!(options.contains(&value), "{value} outside {options:?}");
    }
    let stored: Vec<Option<String>> = sqlx::query_scalar(
        "SELECT r.body FROM records r JOIN facet_values f ON f.record_id = r.id AND f.key = 'hcp.slug' \
         WHERE r.kind = 'preference' AND f.value = 'food.diet'",
    )
    .fetch_all(h.db.pool())
    .await
    .unwrap();
    for body in stored.into_iter().flatten().filter(|b| !b.is_empty()) {
        let value: Value = serde_json::from_str(&body).unwrap();
        assert!(
            options.contains(&value),
            "stored {value} outside {options:?}"
        );
    }
}

// ---- 3: one record per slug under concurrency ----------------------------

#[tokio::test]
async fn item3_concurrent_first_sets_create_one_record() {
    let h = harness().await;
    let a = alice();
    h.define(&a, "writing.length", "STRING", json!({})).await;
    let (r1, r2, r3, r4) = tokio::join!(
        h.set(&a, "writing.length", json!("one")),
        h.set(&a, "writing.length", json!("two")),
        h.set(&a, "writing.length", json!("three")),
        h.set(&a, "writing.length", json!("four")),
    );
    for result in [&r1, &r2, &r3, &r4] {
        assert_eq!(result["success"], true, "{result}");
    }
    assert_eq!(count_preference_records(&h, "writing.length").await, 1);
    let found = h.search(&a, json!({})).await;
    assert_eq!(found["active"]["count"], 1, "{found}");
}

#[tokio::test]
async fn item3_concurrent_suggestions_and_a_set_keep_one_record() {
    let h = harness().await;
    let a = alice();
    h.define(&a, "writing.length", "STRING", json!({})).await;
    let (s1, s2, set) = tokio::join!(
        h.suggest(&a, "writing.length", json!("brief"), 0.5),
        h.suggest(&a, "writing.length", json!("terse"), 0.5),
        h.set(&a, "writing.length", json!("concise")),
    );
    for result in [&s1, &s2, &set] {
        assert_eq!(result["success"], true, "{result}");
    }
    assert_eq!(count_preference_records(&h, "writing.length").await, 1);
    let found = h.search(&a, json!({ "includeSuggestions": true })).await;
    assert_eq!(found["active"]["count"], 1);
    assert_eq!(
        found["suggested"]["count"], 1,
        "one SUGGESTED row per slug: {found}"
    );
}

// ---- 4: mutations do not depend on a bounded enumeration -----------------

#[tokio::test]
async fn item4_mutations_find_records_beyond_the_enumeration_page() {
    let h = harness().await;
    let a = alice();
    let _bounds = TestBounds::set(3, 2);
    for n in 1..=6 {
        let slug = format!("pages.k{n}");
        assert_eq!(
            h.define(&a, &slug, "STRING", json!({})).await["success"],
            true
        );
        assert_eq!(
            h.set(&a, &slug, json!(format!("v{n}"))).await["success"],
            true
        );
    }
    // A read narrowed to the last slug still finds it, past the first page.
    let last = h.search(&a, json!({ "query": "pages.k6" })).await;
    assert_eq!(values(&last, "active"), [("pages.k6".into(), json!("v6"))]);
    let id = last["active"]["preferences"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();

    // SET revises that record instead of creating a duplicate.
    let again = h.set(&a, "pages.k6", json!("changed")).await;
    assert_eq!(again["preference"]["id"], id.as_str(), "{again}");
    assert_eq!(count_preference_records(&h, "pages.k6").await, 1);

    // SUGGEST attaches to it, and a definition change sees its stored value.
    assert_eq!(
        h.suggest(&a, "pages.k6", json!("alt"), 0.5).await["success"],
        true
    );
    assert_eq!(count_preference_records(&h, "pages.k6").await, 1);
    let blocked = h
        .mutate(
            &a,
            json!({ "operation": "UPDATE_DEFINITION",
                    "definition": { "slug": "pages.k6", "valueType": "BOOLEAN" } }),
        )
        .await;
    assert_eq!(
        blocked["code"], "INVALID_PREFERENCE_DEFINITION",
        "{blocked}"
    );

    // DELETE by id works too.
    let deleted = h
        .mutate(
            &a,
            json!({ "operation": "DELETE_PREFERENCE", "preference": { "id": id } }),
        )
        .await;
    assert_eq!(deleted["success"], true, "{deleted}");
    assert_eq!(deleted["target"], "pages.k6");
}

#[tokio::test]
async fn item4_each_list_is_truncated_to_the_result_cap() {
    let h = harness().await;
    let a = alice();
    let _bounds = TestBounds::set(2, 3);
    for n in 1..=5 {
        let slug = format!("cap.k{n}");
        h.define(&a, &slug, "STRING", json!({})).await;
        h.set(&a, &slug, json!("v")).await;
        h.suggest(&a, &slug, json!("w"), 0.5).await;
    }
    let found = h.search(&a, json!({ "includeSuggestions": true })).await;
    assert_eq!(found["active"]["count"], 3, "{found}");
    assert_eq!(found["active"]["preferences"].as_array().unwrap().len(), 3);
    assert_eq!(found["suggested"]["count"], 3, "{found}");
}

// ---- 5: DELETE of the active value keeps the pending suggestion ----------

#[tokio::test]
async fn item5_deleting_the_active_value_keeps_its_pending_suggestion() {
    let h = harness().await;
    let a = alice();
    h.define(&a, "writing.length", "STRING", json!({})).await;
    let set = h.set(&a, "writing.length", json!("concise")).await;
    let active_id = set["preference"]["id"].as_str().unwrap().to_string();
    h.suggest(&a, "writing.length", json!("brief"), 0.7).await;
    let suggestion = suggestion_id(&h, &a, "writing.length").await;

    let deleted = h
        .mutate(
            &a,
            json!({ "operation": "DELETE_PREFERENCE", "preference": { "id": active_id } }),
        )
        .await;
    assert_eq!(deleted["success"], true, "{deleted}");
    assert_eq!(deleted["preference"]["value"], "concise");

    let found = h.search(&a, json!({ "includeSuggestions": true })).await;
    assert_eq!(found["active"]["count"], 0);
    assert_eq!(
        found["suggested"]["count"], 1,
        "the suggestion survives: {found}"
    );
    // The deleted id is gone for DELETE, as upstream's is.
    let again = h
        .mutate(
            &a,
            json!({ "operation": "DELETE_PREFERENCE", "preference": { "id": active_id } }),
        )
        .await;
    assert_eq!(again["code"], "PREFERENCE_NOT_FOUND");

    // It can still be accepted in Native (re-anchored to the empty value) ...
    let accepted = native_resolve(&h, &a, "accept", &suggestion).await;
    assert_eq!(accepted["status"], "accepted", "{accepted}");
    let after = h.search(&a, json!({})).await;
    assert_eq!(
        values(&after, "active"),
        [("writing.length".into(), json!("brief"))]
    );
}

#[tokio::test]
async fn item5_a_pending_suggestion_stays_deletable_after_the_active_value_is_deleted() {
    let h = harness().await;
    let a = alice();
    h.define(&a, "writing.length", "STRING", json!({})).await;
    let set = h.set(&a, "writing.length", json!("concise")).await;
    let active_id = set["preference"]["id"].clone();
    h.suggest(&a, "writing.length", json!("brief"), 0.7).await;
    let suggestion = suggestion_id(&h, &a, "writing.length").await;
    h.mutate(
        &a,
        json!({ "operation": "DELETE_PREFERENCE", "preference": { "id": active_id } }),
    )
    .await;
    let deleted = h
        .mutate(
            &a,
            json!({ "operation": "DELETE_PREFERENCE", "preference": { "id": suggestion } }),
        )
        .await;
    assert_eq!(deleted["success"], true, "{deleted}");
    assert_eq!(deleted["target"], "writing.length");
    // A value set afterwards revives the same slug.
    assert_eq!(
        h.set(&a, "writing.length", json!("again")).await["success"],
        true
    );
    assert_eq!(count_preference_records(&h, "writing.length").await, 1);
}

// ---- 6: stale-digest updates are conflicts -------------------------------

#[tokio::test]
async fn item6_a_stale_preference_update_is_a_conflict_not_an_engine_error() {
    let h = harness().await;
    let a = alice();
    h.define(&a, "writing.length", "STRING", json!({})).await;
    h.set(&a, "writing.length", json!("one")).await;
    let store = Store::new(&h.db, &a);
    let stale = store.load_preferences().await.unwrap().remove(0);
    let catalog = store.load_catalog().await.unwrap().unwrap();
    let definition = catalog.catalog.active("writing.length").unwrap().clone();
    h.set(&a, "writing.length", json!("two")).await;

    let result = store
        .revise_preference(
            &stale,
            &definition,
            "\"three\"",
            &Default::default(),
            "test",
        )
        .await;
    assert!(
        matches!(result, Err(crate::error::Error::Conflict(_))),
        "{result:?}"
    );
    let fresh = h.search(&a, json!({})).await;
    assert_eq!(
        values(&fresh, "active"),
        [("writing.length".into(), json!("two"))]
    );
}

#[tokio::test]
async fn item6_a_stale_update_of_an_empty_body_still_carries_a_digest() {
    let h = harness().await;
    let a = alice();
    h.define(&a, "writing.length", "STRING", json!({})).await;
    h.suggest(&a, "writing.length", json!("brief"), 0.5).await; // creates the empty shell
    let store = Store::new(&h.db, &a);
    let stale_shell = store.load_preferences().await.unwrap().remove(0);
    assert!(!stale_shell.has_value());
    let definition = store
        .load_catalog()
        .await
        .unwrap()
        .unwrap()
        .catalog
        .active("writing.length")
        .unwrap()
        .clone();
    h.set(&a, "writing.length", json!("concise")).await;

    let result = store
        .revise_preference(
            &stale_shell,
            &definition,
            "\"late\"",
            &Default::default(),
            "test",
        )
        .await;
    assert!(
        matches!(result, Err(crate::error::Error::Conflict(_))),
        "{result:?}"
    );
    let found = h.search(&a, json!({})).await;
    assert_eq!(
        values(&found, "active"),
        [("writing.length".into(), json!("concise"))]
    );
}

#[tokio::test]
async fn item6_a_stale_catalog_write_is_a_conflict() {
    let h = harness().await;
    let a = alice();
    h.define(&a, "writing.length", "STRING", json!({})).await;
    let store = Store::new(&h.db, &a);
    let stale = store.load_catalog().await.unwrap().unwrap();
    h.define(&a, "food.diet", "STRING", json!({})).await;
    let result = store
        .save_catalog(Some(&stale), &stale.catalog, "test")
        .await;
    assert!(
        matches!(result, Err(crate::error::Error::Conflict(_))),
        "{result:?}"
    );
}

// ---- 7: withdrawing a suggestion that changed state ----------------------

#[tokio::test]
async fn item7_withdrawing_a_suggestion_that_was_accepted_meanwhile_conflicts() {
    let h = harness().await;
    let a = alice();
    h.define(&a, "writing.length", "STRING", json!({})).await;
    h.set(&a, "writing.length", json!("verbose")).await;
    h.suggest(&a, "writing.length", json!("brief"), 0.5).await;
    let id = suggestion_id(&h, &a, "writing.length").await;
    let store = Store::new(&h.db, &a);
    let looked_up = store.load_suggestions().await.unwrap().remove(0);

    // Native accepts it after the lookup, before the withdrawal.
    assert_eq!(
        native_resolve(&h, &a, "accept", &id).await["status"],
        "accepted"
    );
    let result = store.withdraw_suggestion(&looked_up, "test").await;
    assert!(
        matches!(result, Err(crate::error::Error::Conflict(_))),
        "{result:?}"
    );
}

// ---- 8: suppression after a rejection in Native --------------------------

#[tokio::test]
async fn item8_a_suggestion_rejected_in_native_suppresses_later_ones() {
    let h = harness().await;
    let a = alice();
    h.define(&a, "writing.length", "STRING", json!({})).await;
    h.suggest(&a, "writing.length", json!("brief"), 0.6).await;
    let id = suggestion_id(&h, &a, "writing.length").await;
    assert_eq!(
        native_resolve(&h, &a, "reject", &id).await["status"],
        "rejected"
    );

    // Upstream's rule is per person and definition, whatever the value.
    for value in ["brief", "terse"] {
        let again = h.suggest(&a, "writing.length", json!(value), 0.9).await;
        assert_eq!(again["success"], true, "{again}");
        assert_eq!(again["changed"], false, "{value}: {again}");
        assert_eq!(again["code"], "SUGGESTION_SUPPRESSED");
    }
    let found = h.search(&a, json!({ "includeSuggestions": true })).await;
    assert_eq!(found["suggested"]["count"], 0);
    // A SET is not a suggestion and still works.
    assert_eq!(
        h.set(&a, "writing.length", json!("concise")).await["success"],
        true
    );
    // Other slugs are unaffected.
    h.define(&a, "food.diet", "STRING", json!({})).await;
    assert_eq!(
        h.suggest(&a, "food.diet", json!("x"), 0.5).await["changed"],
        true
    );
}

#[tokio::test]
async fn item8_deleting_a_suggestion_over_hcp_does_not_suppress_and_a_new_definition_starts_clean()
{
    let h = harness().await;
    let a = alice();
    h.define(&a, "writing.length", "STRING", json!({})).await;
    h.suggest(&a, "writing.length", json!("brief"), 0.6).await;
    let id = suggestion_id(&h, &a, "writing.length").await;
    // Upstream's MCP delete removes the row; it does not record a rejection.
    let deleted = h
        .mutate(
            &a,
            json!({ "operation": "DELETE_PREFERENCE", "preference": { "id": id } }),
        )
        .await;
    assert_eq!(deleted["success"], true, "{deleted}");
    let (lifecycle, archived): (String, i64) =
        sqlx::query_as("SELECT lifecycle, archived FROM records WHERE id = ?")
            .bind(&id)
            .fetch_one(h.db.pool())
            .await
            .unwrap();
    assert_eq!(
        (lifecycle.as_str(), archived),
        ("open", 1),
        "withdrawn, not rejected"
    );
    assert_eq!(
        h.suggest(&a, "writing.length", json!("terse"), 0.6).await["changed"],
        true
    );

    // A rejection belongs to the definition it was made under.
    let id = suggestion_id(&h, &a, "writing.length").await;
    native_resolve(&h, &a, "reject", &id).await;
    let archived = h
        .mutate(&a, json!({ "operation": "ARCHIVE_DEFINITION", "definition": { "slug": "writing.length" } }))
        .await;
    assert_eq!(archived["success"], true);
    h.define(&a, "writing.length", "STRING", json!({})).await;
    assert_eq!(
        h.suggest(&a, "writing.length", json!("terse"), 0.6).await["changed"],
        true
    );
}

// ---- 9: accepted suggestions carry their own metadata --------------------

#[tokio::test]
async fn item9_an_accepted_suggestion_reports_its_own_confidence() {
    let h = harness().await;
    let a = alice();
    h.define(&a, "writing.length", "STRING", json!({})).await;
    let set = h
        .mutate(
            &a,
            json!({ "operation": "SET_PREFERENCE",
                    "preference": { "slug": "writing.length", "value": "\"concise\"", "confidence": 0.9 } }),
        )
        .await;
    assert_eq!(set["preference"]["confidence"], 0.9);
    h.suggest(&a, "writing.length", json!("brief"), 0.4).await;
    let id = suggestion_id(&h, &a, "writing.length").await;
    assert_eq!(
        native_resolve(&h, &a, "accept", &id).await["status"],
        "accepted"
    );

    let found = h.search(&a, json!({ "includeSuggestions": true })).await;
    let active = &found["active"]["preferences"][0];
    assert_eq!(active["value"], "brief");
    assert_eq!(
        active["confidence"], 0.4,
        "the old value's confidence must not carry over: {found}"
    );
    assert_eq!(found["suggested"]["count"], 0);

    // A later HCP SET owns its metadata again, including "no confidence".
    let again = h.set(&a, "writing.length", json!("terse")).await;
    assert_eq!(again["preference"]["confidence"], Value::Null);
}

#[tokio::test]
async fn item9_a_body_edited_in_native_has_no_stale_confidence() {
    let h = harness().await;
    let a = alice();
    h.define(&a, "writing.length", "STRING", json!({})).await;
    let set = h
        .mutate(
            &a,
            json!({ "operation": "SET_PREFERENCE",
                    "preference": { "slug": "writing.length", "value": "\"concise\"", "confidence": 0.9 } }),
        )
        .await;
    let id = set["preference"]["id"].as_str().unwrap().to_string();
    let current = stored_body(&h, &id).await.unwrap();
    Box::pin(crate::mcp::tools::lifecycle::update_record(
        h.db.clone(),
        a.clone(),
        json!({ "id": id, "body_set": "\"hand edited\"",
                "if_body_digest": super::store::sha256_hex(&current), "reason": "person edited it" }),
    ))
    .await
    .unwrap();
    let found = h.search(&a, json!({})).await;
    assert_eq!(
        values(&found, "active"),
        [("writing.length".into(), json!("hand edited"))]
    );
    assert_eq!(found["active"]["preferences"][0]["confidence"], Value::Null);
}

// ---- re-review of b7e8e000 -------------------------------------------------

/// A suggestion a person authored in Native: replace the span `old` with `new`.
async fn native_span_suggestion(
    h: &Harness,
    who: &Caller,
    target: &str,
    old: &str,
    new: &str,
) -> String {
    let created = Box::pin(crate::mcp::tools::lifecycle::create_record(
        h.db.clone(),
        who.clone(),
        json!({
            "type": "Annotation", "kind": "suggestion", "lifecycle": "open", "body": new,
            "links": [{ "target_id": target, "relationship": "part_of" }],
            "facets": { "proposal.precondition": "span", "anchor.old": old },
            "reason": "a person proposed an edit in Native",
        }),
    ))
    .await
    .unwrap();
    created["id"].as_str().unwrap().to_string()
}

async fn lifecycle_and_archived(h: &Harness, id: &str) -> (String, i64) {
    sqlx::query_as("SELECT lifecycle, archived FROM records WHERE id = ?")
        .bind(id)
        .fetch_one(h.db.pool())
        .await
        .unwrap()
}

// R1: re-anchoring on DELETE touches only HCP's own proposals.
#[tokio::test]
async fn r1_deleting_the_active_value_leaves_a_native_span_suggestion_alone() {
    let h = harness().await;
    let a = alice();
    h.define(&a, "writing.length", "STRING", json!({})).await;
    let set = h.set(&a, "writing.length", json!("verbose")).await;
    let id = set["preference"]["id"].as_str().unwrap().to_string();
    let span = native_span_suggestion(&h, &a, &id, "verbose", "brief").await;

    let deleted = h
        .mutate(
            &a,
            json!({ "operation": "DELETE_PREFERENCE", "preference": { "id": id } }),
        )
        .await;
    assert_eq!(deleted["success"], true, "{deleted}");

    // The span no longer matches the cleared body; it must go stale, not be
    // widened into a whole-body replacement that leaves bare `brief` behind.
    let accepted = native_resolve(&h, &a, "accept", &span).await;
    assert_ne!(accepted["status"], "accepted", "{accepted}");
    assert_eq!(stored_body(&h, &id).await.unwrap_or_default(), "");
    let found = h.search(&a, json!({})).await;
    assert_eq!(found["active"]["count"], 0);
}

#[tokio::test]
async fn r1_hcp_does_not_overwrite_a_native_suggestion_when_it_suggests() {
    let h = harness().await;
    let a = alice();
    h.define(&a, "writing.length", "STRING", json!({})).await;
    let set = h.set(&a, "writing.length", json!("verbose")).await;
    let id = set["preference"]["id"].as_str().unwrap().to_string();
    let span = native_span_suggestion(&h, &a, &id, "verbose", "brief").await;

    let suggested = h.suggest(&a, "writing.length", json!("terse"), 0.5).await;
    assert_eq!(suggested["changed"], true, "{suggested}");
    assert_eq!(stored_body(&h, &span).await.as_deref(), Some("brief"));
    assert_eq!(lifecycle_and_archived(&h, &span).await, ("open".into(), 0));
    // And the span still applies cleanly in Native.
    assert_eq!(
        native_resolve(&h, &a, "accept", &span).await["status"],
        "accepted"
    );
    let found = h.search(&a, json!({})).await;
    assert_eq!(
        values(&found, "active"),
        [("writing.length".into(), json!("brief"))]
    );
}

// R2: a withdrawn suggestion cannot be accepted in Native.
#[tokio::test]
async fn r2_a_withdrawn_suggestion_cannot_be_accepted_after_the_definition_changes() {
    let h = harness().await;
    let a = alice();
    h.define(&a, "writing.length", "STRING", json!({})).await;
    h.suggest(&a, "writing.length", json!("brief"), 0.6).await;
    let id = suggestion_id(&h, &a, "writing.length").await;
    let withdrawn = h
        .mutate(
            &a,
            json!({ "operation": "DELETE_PREFERENCE", "preference": { "id": id } }),
        )
        .await;
    assert_eq!(withdrawn["success"], true, "{withdrawn}");
    let changed = h
        .mutate(
            &a,
            json!({ "operation": "UPDATE_DEFINITION",
                    "definition": { "slug": "writing.length", "valueType": "BOOLEAN" } }),
        )
        .await;
    assert_eq!(changed["success"], true, "{changed}");

    let accepted = native_resolve(&h, &a, "accept", &id).await;
    assert_eq!(accepted["status"], "conflict", "{accepted}");
    assert_eq!(accepted["causes"][0]["code"], "suggestion_archived");
    // Nothing invisible to HCP was written.
    let (body,): (Option<String>,) = sqlx::query_as(
        "SELECT r.body FROM records r JOIN facet_values f ON f.record_id = r.id AND f.key = 'hcp.slug' \
         WHERE r.kind = 'preference' AND f.value = 'writing.length'",
    )
    .fetch_one(h.db.pool())
    .await
    .unwrap();
    assert_eq!(body.unwrap_or_default(), "");
}

// R3: replacing a suggestion requires it to still be open.
#[tokio::test]
async fn r3_replacing_a_suggestion_that_native_accepted_meanwhile_conflicts() {
    let h = harness().await;
    let a = alice();
    h.define(&a, "writing.length", "STRING", json!({})).await;
    h.set(&a, "writing.length", json!("verbose")).await;
    h.suggest(&a, "writing.length", json!("brief"), 0.5).await;
    let store = Store::new(&h.db, &a);
    let looked_up = store.load_suggestions().await.unwrap().remove(0);
    let target = store.load_preferences().await.unwrap().remove(0);

    // Native accepts it after HCP read it, before HCP writes.
    assert_eq!(
        native_resolve(&h, &a, "accept", &looked_up.id).await["status"],
        "accepted"
    );
    let result = store
        .revise_suggestion(
            &looked_up,
            &target,
            "\"terse\"",
            &Default::default(),
            "test",
        )
        .await;
    assert!(
        matches!(result, Err(crate::error::Error::Conflict(_))),
        "{result:?}"
    );

    // The accepted annotation is untouched and the accepted value stands.
    assert_eq!(
        stored_body(&h, &looked_up.id).await.as_deref(),
        Some("\"brief\"")
    );
    assert_eq!(
        lifecycle_and_archived(&h, &looked_up.id).await,
        ("accepted".into(), 0)
    );
    let found = h.search(&a, json!({ "includeSuggestions": true })).await;
    assert_eq!(
        values(&found, "active"),
        [("writing.length".into(), json!("brief"))]
    );
    assert_eq!(found["suggested"]["count"], 0);
}

#[tokio::test]
async fn r3_a_replaced_suggestion_cannot_be_accepted_any_more() {
    let h = harness().await;
    let a = alice();
    h.define(&a, "writing.length", "STRING", json!({})).await;
    h.set(&a, "writing.length", json!("verbose")).await;
    h.suggest(&a, "writing.length", json!("brief"), 0.5).await;
    let old = suggestion_id(&h, &a, "writing.length").await;
    let replaced = h.suggest(&a, "writing.length", json!("terse"), 0.5).await;
    assert_eq!(replaced["changed"], true, "{replaced}");
    let found = h.search(&a, json!({ "includeSuggestions": true })).await;
    assert_eq!(
        values(&found, "suggested"),
        [("writing.length".into(), json!("terse"))]
    );
    let accepted = native_resolve(&h, &a, "accept", &old).await;
    assert_eq!(accepted["status"], "conflict", "{accepted}");
}

// R4: confidence comes from the event that produced the body, not its text.
#[tokio::test]
async fn r4_a_body_edited_back_to_an_earlier_text_does_not_inherit_its_confidence() {
    let h = harness().await;
    let a = alice();
    h.define(&a, "writing.length", "STRING", json!({})).await;
    h.set(&a, "writing.length", json!("start")).await;
    h.suggest(&a, "writing.length", json!("B"), 0.4).await;
    let id = suggestion_id(&h, &a, "writing.length").await;
    assert_eq!(
        native_resolve(&h, &a, "accept", &id).await["status"],
        "accepted"
    );
    let found = h.search(&a, json!({})).await;
    assert_eq!(found["active"]["preferences"][0]["confidence"], 0.4);

    let set_c = h.set(&a, "writing.length", json!("C")).await;
    assert_eq!(set_c["preference"]["confidence"], Value::Null);
    let record = set_c["preference"]["id"].as_str().unwrap().to_string();
    let current = stored_body(&h, &record).await.unwrap();
    Box::pin(crate::mcp::tools::lifecycle::update_record(
        h.db.clone(),
        a.clone(),
        json!({ "id": record, "body_set": "\"B\"",
                "if_body_digest": super::store::sha256_hex(&current), "reason": "person edited it back" }),
    ))
    .await
    .unwrap();

    let found = h.search(&a, json!({})).await;
    assert_eq!(
        values(&found, "active"),
        [("writing.length".into(), json!("B"))]
    );
    assert_eq!(
        found["active"]["preferences"][0]["confidence"],
        Value::Null,
        "{found}"
    );
}

#[tokio::test]
async fn r4_a_hand_edit_to_the_text_hcp_last_wrote_has_no_confidence() {
    let h = harness().await;
    let a = alice();
    h.define(&a, "writing.length", "STRING", json!({})).await;
    let set = h
        .mutate(
            &a,
            json!({ "operation": "SET_PREFERENCE",
                    "preference": { "slug": "writing.length", "value": "\"A\"", "confidence": 0.9 } }),
        )
        .await;
    let record = set["preference"]["id"].as_str().unwrap().to_string();
    // Edit away and back to exactly what HCP wrote: the text matches HCP's last
    // write, but the producing event is the person's.
    for text in ["\"other\"", "\"A\""] {
        let current = stored_body(&h, &record).await.unwrap();
        Box::pin(crate::mcp::tools::lifecycle::update_record(
            h.db.clone(),
            a.clone(),
            json!({ "id": record, "body_set": text,
                    "if_body_digest": super::store::sha256_hex(&current), "reason": "person edit" }),
        ))
        .await
        .unwrap();
    }
    let found = h.search(&a, json!({})).await;
    assert_eq!(
        found["active"]["preferences"][0]["confidence"],
        Value::Null,
        "{found}"
    );
}
