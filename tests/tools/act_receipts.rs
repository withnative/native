//! Outward write receipts carry the engine `act` / `acts` only for an owner
//! (design 08b4c21 §4 S2a, task a5804e8).
//!
//! The act itself is still allocated and stored for every caller: these tests
//! read it back from `content_events` for the non-owner, and compare the
//! non-owner's receipt with the owner's, which may differ by the act and
//! nothing else. Single writes, `create_many` in both response modes, the
//! direct-insert sites (identity, binding, artifact copy, work claim) and a
//! keyed replay all go through the one registry projection.

use std::collections::BTreeSet;

use native_ce::mcp::counter_fence::find_counters;
use native_ce::mcp::{register_builtin_tools, register_surface_tools, Caller, ToolRegistry};
use native_ce::{create_database, Db};
use serde_json::{json, Value};

const MDX_SOURCE: &str = r#"export const nativeArtifact = { schema: "native.mdx.artifact.v2", inputs: {}, module_inputs: {}, capability_requests: [] }

<Metric label="Current" value={1} />"#;

/// A caller the engine proves is the workspace owner, and the three footings
/// that must never read as one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Footing {
    LocalOwner,
    HostedOwner,
    HostedMember,
    UnhostedAuthenticated,
}

impl Footing {
    const ALL: [Footing; 4] = [
        Footing::LocalOwner,
        Footing::HostedOwner,
        Footing::HostedMember,
        Footing::UnhostedAuthenticated,
    ];

    fn sees_act(self) -> bool {
        matches!(self, Footing::LocalOwner | Footing::HostedOwner)
    }

    fn caller(self) -> Caller {
        match self {
            Footing::LocalOwner => Caller::local_owner("acct:owner"),
            Footing::HostedOwner => Caller::authenticated("acct:owner")
                .with_hosting_context("host:owner", "db:test")
                .with_hosting_owner(true),
            Footing::HostedMember => Caller::authenticated("acct:member")
                .with_hosting_context("host:member", "db:test")
                .with_hosting_owner(false)
                .with_hosting_member(true),
            Footing::UnhostedAuthenticated => Caller::authenticated("acct:unhosted"),
        }
    }
}

async fn fixture() -> (Db, ToolRegistry) {
    let db = create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_builtin_tools(&mut registry).unwrap();
    register_surface_tools(&mut registry).unwrap();
    // A non-local caller needs a portable account binding to write, so bind
    // each footing's account to a person the owner creates.
    for (label, account) in [
        ("Owner", "acct:owner"),
        ("Member", "acct:member"),
        ("Unhosted", "acct:unhosted"),
    ] {
        let person = registry
            .call(
                db.clone(),
                Caller::local(),
                "create_record",
                json!({ "type": "Entity", "kind": "person", "name": label,
                        "reason": "act receipt fixture" }),
            )
            .await
            .unwrap();
        for (system, identifier) in [
            ("account", account.to_string()),
            ("native-principal", format!("native/{label}")),
        ] {
            sqlx::query(
                "INSERT INTO bindings (record_id, system, identifier, is_canonical)
                 VALUES (?, ?, ?, 1)",
            )
            .bind(person["id"].as_str().unwrap())
            .bind(system)
            .bind(identifier)
            .execute(&crate::common::fixture_write_pool(&db).await)
            .await
            .unwrap();
        }
    }
    (db, registry)
}

async fn call(
    registry: &ToolRegistry,
    db: &Db,
    footing: Footing,
    tool: &str,
    arguments: Value,
) -> Value {
    registry
        .call(db.clone(), footing.caller(), tool, arguments)
        .await
        .unwrap_or_else(|error| panic!("{footing:?} {tool} failed: {error}"))
}

/// Every `act` / `acts` position in a response, by normalised path.
fn act_positions(response: &Value) -> Vec<String> {
    find_counters(response)
        .into_iter()
        .map(|hit| hit.path)
        .filter(|path| path.ends_with(".act") || path.ends_with(".acts"))
        .collect()
}

fn top_level_keys(response: &Value) -> BTreeSet<String> {
    response
        .as_object()
        .unwrap_or_else(|| panic!("object response expected: {response}"))
        .keys()
        .cloned()
        .collect()
}

/// The newest act the engine stored for `record`.
async fn stored_act(db: &Db, record: &str) -> Option<i64> {
    sqlx::query_scalar("SELECT MAX(act) FROM content_events WHERE record_id = ?")
        .bind(record)
        .fetch_one(db.pool())
        .await
        .unwrap()
}

/// What a footing is shown for a receipt, checked against the stored act.
/// Owners get exactly the stored number; everyone else gets no act position,
/// while the act is still stored.
async fn assert_receipt_footing(db: &Db, footing: Footing, record: &str, receipt: &Value) {
    let stored = stored_act(db, record).await;
    assert!(
        stored.is_some_and(|act| act > 0),
        "{footing:?}: the write must still allocate and store its act"
    );
    if footing.sees_act() {
        assert_eq!(receipt["act"].as_i64(), stored, "{footing:?}: {receipt}");
    } else {
        assert!(
            act_positions(receipt).is_empty(),
            "{footing:?} must not see an act: {receipt}"
        );
    }
}

/// The workspace's current act (the singleton `act_state` counter).
async fn current_act(db: &Db) -> i64 {
    sqlx::query_scalar("SELECT next_act FROM act_state WHERE singleton = 1")
        .fetch_one(db.pool())
        .await
        .unwrap()
}

/// One write that must allocate exactly one act. The act is stored for every
/// caller; the receipt shows it, as the exact stored number, to owners only.
async fn write(
    registry: &ToolRegistry,
    db: &Db,
    footing: Footing,
    tool: &str,
    arguments: Value,
) -> Value {
    let before = current_act(db).await;
    let receipt = call(registry, db, footing, tool, arguments).await;
    let after = current_act(db).await;
    assert_eq!(
        after,
        before + 1,
        "{footing:?} {tool} must allocate exactly one act: {receipt}"
    );
    if footing.sees_act() {
        assert_eq!(receipt["act"].as_i64(), Some(after), "{footing:?} {tool}");
    } else {
        assert!(
            act_positions(&receipt).is_empty(),
            "{footing:?} {tool} must not show an act: {receipt}"
        );
    }
    receipt
}

#[tokio::test]
async fn single_writes_keep_the_stored_act_and_show_it_to_owners_only() {
    let mut shapes: Vec<(Footing, &str, BTreeSet<String>)> = Vec::new();
    for footing in Footing::ALL {
        let (db, registry) = fixture().await;
        let created = write(
            &registry,
            &db,
            footing,
            "create_record",
            json!({ "type": "Document", "kind": "note", "name": "Receipt note",
                    "body": "first", "reason": "act receipt fixture" }),
        )
        .await;
        let record = created["id"].as_str().unwrap().to_string();
        shapes.push((footing, "create_record", top_level_keys(&created)));

        let updated = write(
            &registry,
            &db,
            footing,
            "update_record",
            json!({ "id": record, "name": "Receipt note v2", "reason": "act receipt fixture" }),
        )
        .await;
        shapes.push((footing, "update_record", top_level_keys(&updated)));

        let attached = write(
            &registry,
            &db,
            footing,
            "attach_text",
            json!({ "record_id": record, "text": "attached", "filename": "a.txt" }),
        )
        .await;
        shapes.push((footing, "attach_text", top_level_keys(&attached)));

        let claimed = write(
            &registry,
            &db,
            footing,
            "start_work",
            json!({ "record_id": record, "action": "claim" }),
        )
        .await;
        shapes.push((footing, "start_work", top_level_keys(&claimed)));
        db.close().await;
    }
    // A non-owner receipt is the owner's receipt without the act, nothing more.
    for (footing, tool, keys) in &shapes {
        let owner = shapes
            .iter()
            .find(|(f, t, _)| *f == Footing::LocalOwner && t == tool)
            .map(|(_, _, keys)| keys)
            .unwrap();
        let mut expected = owner.clone();
        if !footing.sees_act() {
            expected.remove("act");
        }
        // Ids and per-run fields can differ by footing in unrelated ways, so
        // only the act key is compared here; every other key must be present.
        assert_eq!(
            keys.contains("act"),
            footing.sees_act(),
            "{footing:?} {tool}"
        );
        let missing: Vec<_> = expected.difference(keys).collect();
        assert!(missing.is_empty(), "{footing:?} {tool} lost {missing:?}");
    }
}

#[tokio::test]
async fn keyed_replay_stays_idempotent_and_carries_no_act_for_non_owners() {
    for footing in Footing::ALL {
        let (db, registry) = fixture().await;
        let arguments = json!({
            "type": "Document", "kind": "note", "name": "Keyed note", "body": "once",
            "idempotency_key": "act-receipt-keyed", "reason": "act receipt fixture"
        });
        let first = call(&registry, &db, footing, "create_record", arguments.clone()).await;
        let replay = call(&registry, &db, footing, "create_record", arguments).await;
        assert_eq!(first["id"], replay["id"], "{footing:?}");
        let record = first["id"].as_str().unwrap();
        let events: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM content_events WHERE record_id = ?")
                .bind(record)
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(events, 1, "{footing:?}: the replay must not append");
        assert_receipt_footing(&db, footing, record, &first).await;
        assert_receipt_footing(&db, footing, record, &replay).await;
        if footing.sees_act() {
            assert_eq!(first["act"], replay["act"], "{footing:?}: exact owner act");
        }
        db.close().await;
    }
}

#[tokio::test]
async fn create_many_compact_and_verbose_withhold_acts_from_non_owners_only() {
    for footing in Footing::ALL {
        for mode in ["summary", "verbose"] {
            let (db, registry) = fixture().await;
            let response = call(
                &registry,
                &db,
                footing,
                "create_many",
                json!({
                    "reason": "act receipt fixture",
                    "response_mode": mode,
                    "records": [
                        { "type": "Document", "kind": "note", "name": "Batch one" },
                        { "type": "Document", "kind": "note", "name": "Batch two" }
                    ]
                }),
            )
            .await;
            assert_eq!(
                response["ok"],
                json!(true),
                "{footing:?} {mode}: {response}"
            );
            let ids = response["ids"].as_array().unwrap();
            assert_eq!(ids.len(), 2);
            for id in ids {
                assert!(stored_act(&db, id.as_str().unwrap()).await.is_some());
            }
            let positions = act_positions(&response);
            if footing.sees_act() {
                let expected = if mode == "summary" {
                    vec!["$.acts".to_string()]
                } else {
                    vec![
                        "$.results[].record.act".to_string(),
                        "$.results[].record.act".to_string(),
                    ]
                };
                // `find_counters` reports once per array row.
                let mut got = positions.clone();
                got.dedup();
                let mut want = expected;
                want.dedup();
                assert_eq!(got, want, "{footing:?} {mode}: {response}");
            } else {
                assert!(positions.is_empty(), "{footing:?} {mode}: {response}");
                // The wrapper is intact: each verbose item still carries its
                // created record's identity.
                if mode == "verbose" {
                    for (index, item) in response["results"].as_array().unwrap().iter().enumerate()
                    {
                        assert_eq!(item["status"], "created");
                        assert_eq!(item["record"]["id"], ids[index]);
                    }
                }
            }
            db.close().await;
        }
    }
}

#[tokio::test]
async fn direct_insert_sites_withhold_the_act_and_still_commit() {
    for footing in Footing::ALL {
        let (db, registry) = fixture().await;
        let resolved = write(
            &registry,
            &db,
            footing,
            "resolve_external",
            json!({
                "bindings": [{ "system": "native-principal", "identifier": "native/ada" }],
                "hints": { "record_type": "Entity", "kind": "person", "name": "Ada" },
                "reason": "act receipt fixture"
            }),
        )
        .await;
        assert_eq!(resolved["status"], "created", "{resolved}");
        let person = resolved["record_id"].as_str().unwrap().to_string();

        let observed = write(
            &registry,
            &db,
            footing,
            "observe_external",
            json!({
                "bindings": [{ "system": "native-principal", "identifier": "native/grace" }],
                "source_binding": { "system": "native-principal", "identifier": "native/grace" },
                "hints": { "record_type": "Entity", "kind": "person", "name": "Grace" },
                "quality": "reported",
                "materialization_policy": "identity_only",
                "as_of": null,
                "provenance": {
                    "freshness": "unknown", "retention_state": "none",
                    "source_availability": "unknown", "refresh_outcome": "not_attempted"
                },
                "display_name": "Grace",
                "snapshot_base64": null, "snapshot_mime": null, "snapshot_filename": null,
                "reason": "act receipt fixture"
            }),
        )
        .await;
        assert_eq!(observed["status"], "observed", "{observed}");

        let bound = write(
            &registry,
            &db,
            footing,
            "manage_bindings",
            json!({
                "action": "add", "record_id": person,
                "binding": { "system": "native-principal", "identifier": "native/ada-alias" },
                "reason": "act receipt fixture"
            }),
        )
        .await;
        assert_eq!(bound["changed"], json!(true), "{bound}");

        let source = write(
            &registry,
            &db,
            footing,
            "create_record",
            json!({ "type": "Document", "kind": "artifact", "name": "Metric source",
                    "body": MDX_SOURCE, "facets": { "runtime": "native.mdx.v2" },
                    "reason": "act receipt fixture" }),
        )
        .await;
        let source_id = source["id"].as_str().unwrap();
        let copy = write(
            &registry,
            &db,
            footing,
            "instantiate_artifact",
            json!({ "source_id": source_id, "title": "Metric copy" }),
        )
        .await;
        assert!(copy["id"].is_string(), "{copy}");
        db.close().await;
    }
}

#[tokio::test]
async fn authored_json_with_counter_key_names_is_returned_unchanged() {
    // Caller-authored body text and names that happen to use the keys `act`,
    // `acts`, `seq` and `frontier` are data, not engine metadata. (Nested
    // authored objects at the named positions are pinned by the registry and
    // `counter_fence` unit tests.)
    let authored = r#"{"act":7,"acts":[1,2],"seq":3,"frontier":["f"],"previous_seq":4}"#;
    for footing in Footing::ALL {
        let (db, registry) = fixture().await;
        let created = call(
            &registry,
            &db,
            footing,
            "create_record",
            json!({ "type": "Document", "kind": "note", "name": "acts",
                    "body": authored, "reason": "act receipt fixture" }),
        )
        .await;
        let id = created["id"].as_str().unwrap();
        let read = call(&registry, &db, footing, "get_record", json!({ "id": id })).await;
        assert_eq!(read["records"][0]["body"], json!(authored), "{footing:?}");
        assert_eq!(read["records"][0]["name"], json!("acts"), "{footing:?}");

        db.close().await;
    }
}
