//! Fit, refusal and wire round-trip fixtures (§7.3).
//!
//! Each fixture is a v2-shaped value mirroring a v1 shape (no v1 mapping
//! runs here: mapping v1 rows to v2 records is the migration increment).
//! Values are validated by the real `/5` validator (via kernel create,
//! reusing the increment 1 pattern) **and** by [`super::foci_consumer`],
//! and the outcome is asserted.
//!
//! The wire round trip covers the adapter leg only (storage → wire →
//! storage, ending in a second `/5` create). The app reader/capture leg —
//! the TypeScript Docs/Tracker readers — never runs from Rust, and
//! Tracker's open-time refusal of the schema-maximal view is app-side
//! (§5.1.6): both are deferred to the behavioural-proof increment.

#[cfg(test)]
mod fixtures {
    use std::collections::{HashMap, HashSet};

    use serde_json::{json, Value};

    use super::super::foci::{FOCUS_FAMILY, PREFERENCES_FAMILY, SAVED_VIEW_FAMILY};
    use super::super::foci_consumer::{
        check_order_write, check_preferences_write, read_preferences, repair_order_read,
        resolve_membership_refresh, resolve_parent, validate_focus_strings,
        validate_preferences_strings, validate_query_view_strings, validate_record_view_strings,
        PreferenceEntry, PresentationParent,
    };
    use super::super::foci_wire::{wire_capture, wire_open, SAVED_VIEW_PIN};
    use crate::events::KERNEL_ROOT_ID;
    use crate::kernel;

    fn map(value: Value) -> serde_json::Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    async fn world() -> (tempfile::TempDir, crate::db::Db, String) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("foci-consumer-fixtures.db");
        let (db, admin) =
            kernel::create_v2_database(path.to_str().unwrap(), "account", "Admin", "acct:admin")
                .await
                .unwrap();
        let manifest = super::super::foci::package();
        let identity = manifest.identity().unwrap();
        kernel::install_package_as(&db, &admin, &manifest)
            .await
            .unwrap();
        kernel::adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &manifest, Some(&identity), &[])
            .await
            .unwrap();
        (dir, db, admin)
    }

    async fn create(
        db: &crate::db::Db,
        actor: &str,
        family: &str,
        kind: &str,
        fields: &serde_json::Map<String, Value>,
    ) -> crate::Result<String> {
        kernel::create_json_as(
            db,
            actor,
            family,
            kind,
            &serde_json::to_string(fields).unwrap(),
            KERNEL_ROOT_ID,
        )
        .await
    }

    /// Deterministic v4 uuids for fixture ids.
    fn uuid(i: u32) -> String {
        format!("550e8400-e29b-41d4-a716-{i:012x}")
    }

    fn v7() -> String {
        "0193f9f2-7c1e-7f2a-9b3c-4d5e6f7a8b9c".to_string()
    }

    fn tracker_definition(with_text: bool) -> Value {
        let mut definition = json!({
            "app": "agent.tracker",
            "format": "tracker-query/1",
            "filter": {"combine": "all", "terms": [
                {"field": "status", "op": "neq", "value": "done"},
                {"field": "status", "op": "neq", "value": "(none)"},
            ]},
            "sort": [{"field": "updated", "direction": "desc"}],
            "group_by": "status",
        });
        if with_text {
            definition["text"] = json!("urgent");
        }
        definition
    }

    #[tokio::test]
    async fn focus_fit_no_colour_empty_order_and_full_order() {
        let (_dir, db, admin) = world().await;
        // No colour, empty order.
        let bare = json!({"name": "Now", "view_order": []});
        let id = create(&db, &admin, FOCUS_FAMILY, "focus", &map(bare.clone()))
            .await
            .unwrap();
        let read = kernel::read_record_as(&db, &admin, &id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(Value::Object(read.fields.clone()), bare);
        validate_focus_strings(&bare).unwrap();
        // Colour plus a 128-id order.
        let order: Vec<Value> = (0..128).map(|i| json!(uuid(i))).collect();
        let full = json!({"name": "Later", "colour": "#112233", "view_order": order});
        let id = create(&db, &admin, FOCUS_FAMILY, "focus", &map(full.clone()))
            .await
            .unwrap();
        let read = kernel::read_record_as(&db, &admin, &id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(Value::Object(read.fields.clone()), full);
        validate_focus_strings(&full).unwrap();
        db.close().await;
    }

    #[tokio::test]
    async fn record_view_targets_v7_uuid_and_native_root() {
        let (_dir, db, admin) = world().await;
        for target in [v7(), "native:root".to_string()] {
            let fields = json!({"name": "Plan", "definition": {
                "app": "agent.docs", "target": {"record_id": target}}});
            let id = create(
                &db,
                &admin,
                SAVED_VIEW_FAMILY,
                "record_view",
                &map(fields.clone()),
            )
            .await
            .unwrap();
            let read = kernel::read_record_as(&db, &admin, &id)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(Value::Object(read.fields.clone()), fields);
            validate_record_view_strings(&fields).unwrap();
        }
        db.close().await;
    }

    #[tokio::test]
    async fn tracker_views_as_written_with_and_without_text() {
        let (_dir, db, admin) = world().await;
        for with_text in [false, true] {
            let fields = json!({"name": "Work", "definition": tracker_definition(with_text)});
            create(
                &db,
                &admin,
                SAVED_VIEW_FAMILY,
                "query_view",
                &map(fields.clone()),
            )
            .await
            .unwrap();
            validate_query_view_strings(&fields).unwrap();
        }
        db.close().await;
    }

    #[tokio::test]
    async fn schema_maximal_query_view_is_structurally_accepted() {
        // 8 sorts and 16 terms pass `/5` structure and the consumer's string
        // rules. Tracker's open-time refusal (one sort column) is app-side
        // (§5.1.6) and deferred to the behavioural-proof increment.
        let (_dir, db, admin) = world().await;
        let terms: Vec<Value> = (0..16)
            .map(|i| json!({"field": format!("field{i}"), "op": "eq", "value": "open"}))
            .collect();
        let sorts: Vec<Value> = (0..8)
            .map(|i| json!({"field": format!("field{i}"), "direction": "asc"}))
            .collect();
        let fields = json!({"name": "Max", "definition": {
            "app": "agent.tracker", "format": "tracker-query/1",
            "text": "urgent",
            "filter": {"combine": "all", "terms": terms},
            "sort": sorts, "group_by": "status"}});
        create(
            &db,
            &admin,
            SAVED_VIEW_FAMILY,
            "query_view",
            &map(fields.clone()),
        )
        .await
        .unwrap();
        validate_query_view_strings(&fields).unwrap();
        db.close().await;
    }

    #[tokio::test]
    async fn preferences_empty_and_128_mixed() {
        let (_dir, db, admin) = world().await;
        let empty = json!({"foci": []});
        create(
            &db,
            &admin,
            PREFERENCES_FAMILY,
            "focus_preferences",
            &map(empty.clone()),
        )
        .await
        .unwrap();
        validate_preferences_strings(&empty).unwrap();
        let entries: Vec<Value> = (0..128)
            .map(|i| {
                json!({"focus_id": uuid(i),
                    "tier": if i % 2 == 0 { "now" } else { "background" },
                    "hidden": i % 3 == 0})
            })
            .collect();
        let full = json!({"foci": entries});
        create(
            &db,
            &admin,
            PREFERENCES_FAMILY,
            "focus_preferences",
            &map(full.clone()),
        )
        .await
        .unwrap();
        validate_preferences_strings(&full).unwrap();
        db.close().await;
    }

    #[tokio::test]
    async fn identical_record_views_keep_distinct_ids() {
        let (_dir, db, admin) = world().await;
        let fields = json!({"name": "Plan", "definition": {
            "app": "agent.docs", "target": {"record_id": "native:root"}}});
        let one = create(
            &db,
            &admin,
            SAVED_VIEW_FAMILY,
            "record_view",
            &map(fields.clone()),
        )
        .await
        .unwrap();
        let two = create(
            &db,
            &admin,
            SAVED_VIEW_FAMILY,
            "record_view",
            &map(fields.clone()),
        )
        .await
        .unwrap();
        assert_ne!(one, two);
        db.close().await;
    }

    #[tokio::test]
    async fn weaker_contract_malformed_strings_store_but_consumer_refuses() {
        // The `/5` store cannot express the v1 patterns, so these create
        // fine; the consumer refuses them. This is the weaker contract
        // stated in the module docs (per decision A the store-level rules
        // wait for G9, a prerequisite for migrating real data).
        let (_dir, db, admin) = world().await;
        for (family, kind, fields) in [
            (
                FOCUS_FAMILY,
                "focus",
                json!({"name": "Now", "colour": "red", "view_order": []}),
            ),
            (
                SAVED_VIEW_FAMILY,
                "record_view",
                json!({"name": "Plan", "definition": {
                    "app": "docs", "target": {"record_id": "native:root"}}}),
            ),
            (
                SAVED_VIEW_FAMILY,
                "query_view",
                json!({"name": "Work", "definition": {
                    "app": "agent.tracker", "format": "tracker-query",
                    "filter": {"combine": "all", "terms": []}, "sort": []}}),
            ),
        ] {
            create(&db, &admin, family, kind, &map(fields.clone()))
                .await
                .unwrap();
            let refused = match kind {
                "focus" => validate_focus_strings(&fields).unwrap_err(),
                "record_view" => validate_record_view_strings(&fields).unwrap_err(),
                _ => validate_query_view_strings(&fields).unwrap_err(),
            };
            assert!(!refused.rule.is_empty());
        }
        db.close().await;
    }

    #[tokio::test]
    async fn structural_refusals_still_come_from_the_store() {
        let (_dir, db, admin) = world().await;
        let over: Vec<Value> = (0..129).map(|i| json!(uuid(i % 128))).collect();
        let mut null_target = json!({"name": "Plan", "definition": {
            "app": "agent.docs", "target": {"record_id": "native:root"}}});
        null_target["definition"]["target"]["record_id"] = Value::Null;
        let mut unknown = json!({"name": "Now", "view_order": []});
        unknown["bogus"] = json!("x");
        let missing = json!({"view_order": []});
        let mut bad_choice = json!({"name": "Work", "definition": {
            "app": "agent.tracker", "format": "tracker-query/1",
            "filter": {"combine": "all", "terms": []}, "sort": []}});
        bad_choice["definition"]["sort"] = json!([{"field": "status", "direction": "down"}]);
        for (family, kind, fields, expected) in [
            (FOCUS_FAMILY, "focus", unknown, "unknown_member at /bogus"),
            (FOCUS_FAMILY, "focus", missing, "required_missing at /name"),
            (
                FOCUS_FAMILY,
                "focus",
                json!({"name": "Now", "view_order": over}),
                "limit_exceeded at /view_order",
            ),
            (
                SAVED_VIEW_FAMILY,
                "record_view",
                null_target,
                "null_not_supported at /definition/target/record_id",
            ),
            (
                SAVED_VIEW_FAMILY,
                "query_view",
                bad_choice,
                "wrong_type at /definition/sort/0/direction",
            ),
        ] {
            let err = create(&db, &admin, family, kind, &map(fields))
                .await
                .unwrap_err();
            assert_eq!(err.to_string(), expected, "{kind}");
        }
        db.close().await;
    }

    #[tokio::test]
    async fn archived_focus_refuses_order_write_and_graph_repairs() {
        let (_dir, db, admin) = world().await;
        // Two foci with one live view each, linked member_of in the store.
        let focus_a = create(
            &db,
            &admin,
            FOCUS_FAMILY,
            "focus",
            &map(json!({"name": "A", "view_order": []})),
        )
        .await
        .unwrap();
        let focus_b = create(
            &db,
            &admin,
            FOCUS_FAMILY,
            "focus",
            &map(json!({"name": "B", "view_order": []})),
        )
        .await
        .unwrap();
        let view_a = create(
            &db,
            &admin,
            SAVED_VIEW_FAMILY,
            "record_view",
            &map(json!({"name": "VA", "definition": {
                "app": "agent.docs", "target": {"record_id": "native:root"}}})),
        )
        .await
        .unwrap();
        let view_b = create(
            &db,
            &admin,
            SAVED_VIEW_FAMILY,
            "record_view",
            &map(json!({"name": "VB", "definition": {
                "app": "agent.docs", "target": {"record_id": "native:root"}}})),
        )
        .await
        .unwrap();
        kernel::link_as(&db, &admin, &view_a, "member_of", &focus_a)
            .await
            .unwrap();
        kernel::link_as(&db, &admin, &view_b, "member_of", &focus_b)
            .await
            .unwrap();
        // Archived Focus (explicit stand-in bool until G1) refuses the write.
        let live_a: HashSet<String> = [view_a.clone()].into();
        let refused = check_order_write(std::slice::from_ref(&view_a), &live_a, true).unwrap_err();
        assert_eq!(refused.rule, "order-archived");
        // A non-member id refuses too.
        let refused = check_order_write(std::slice::from_ref(&view_b), &live_a, false).unwrap_err();
        assert_eq!(refused.rule, "order-unknown");
        assert!(check_order_write(std::slice::from_ref(&view_a), &live_a, false).is_ok());
        // Duplicate order refuses for that Focus only: B still repairs.
        let dup = repair_order_read(&[view_b.clone(), view_b.clone()], &[view_b.clone()].into());
        assert_eq!(dup.unwrap_err().rule, "order-duplicate");
        let fixed = repair_order_read(&[], &[view_a.clone()].into()).unwrap();
        assert_eq!(fixed.order, vec![view_a.clone()]);
        assert_eq!(fixed.anomaly, None);
        // Zero/two memberships hide only that view; others still show.
        let refresh = resolve_membership_refresh(&[
            (view_a.clone(), vec![focus_a.clone()]),
            (view_b.clone(), vec![]),
            ("ghost".to_string(), vec![focus_a.clone(), focus_b.clone()]),
        ]);
        assert_eq!(refresh.shown.len(), 1);
        assert_eq!(refresh.shown[&focus_a], vec![view_a.clone()]);
        assert_eq!(refresh.hidden.len(), 2);
        assert_eq!(refresh.anomalies.len(), 2);
        db.close().await;
    }

    #[test]
    fn parent_cycle_depth_and_self_parent_are_roots() {
        let visible: HashSet<String> = ["a", "b", "c", "d", "e", "f", "g"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let mut parents: HashMap<String, Vec<String>> = HashMap::new();
        parents.insert("a".into(), vec!["b".into()]);
        parents.insert("b".into(), vec!["a".into()]); // two-cycle
        parents.insert("c".into(), vec!["c".into()]); // self-parent
        parents.insert("d".into(), vec!["e".into()]);
        parents.insert("e".into(), vec!["f".into()]); // depth 2
        parents.insert("f".into(), vec![]);
        parents.insert("g".into(), vec!["gone".into()]); // absent: clean root
        for id in ["a", "b", "c", "d"] {
            let PresentationParent::Root { anomaly } = resolve_parent(id, &parents, &visible)
            else {
                panic!("{id} should be a root");
            };
            assert!(anomaly.is_some(), "{id}");
        }
        let PresentationParent::Root { anomaly } = resolve_parent("a", &parents, &visible) else {
            panic!("cycle should be a root");
        };
        assert!(anomaly.expect("cycle anomaly").contains("cycle"));
        assert!(matches!(
            resolve_parent("g", &parents, &visible),
            PresentationParent::Root { anomaly: None }
        ));
    }

    #[tokio::test]
    async fn wire_round_trip_docs_and_tracker() {
        let (_dir, db, admin) = world().await;
        // Docs-style record_view.
        let docs = json!({"name": "Plan", "definition": {
            "app": "agent.docs", "target": {"record_id": "native:root"}}});
        let docs_id = create(
            &db,
            &admin,
            SAVED_VIEW_FAMILY,
            "record_view",
            &map(docs.clone()),
        )
        .await
        .unwrap();
        let stored_docs = kernel::read_record_as(&db, &admin, &docs_id)
            .await
            .unwrap()
            .unwrap();
        let stored_docs = Value::Object(stored_docs.fields.clone());
        assert_eq!(stored_docs, docs);
        validate_record_view_strings(&stored_docs).unwrap();
        let wire = wire_open(SAVED_VIEW_PIN, &stored_docs["definition"]).unwrap();
        assert_eq!(wire["version"], json!(1));
        assert_eq!(wire["app"], json!("agent.docs"));
        let captured = wire_capture(SAVED_VIEW_PIN, &wire).unwrap();
        assert_eq!(captured, stored_docs["definition"]);
        // The round trip ends back in storage: the captured definition
        // creates a second `/5` record unchanged.
        let docs_again = json!({"name": "Plan (copy)", "definition": captured});
        let docs_id2 = create(
            &db,
            &admin,
            SAVED_VIEW_FAMILY,
            "record_view",
            &map(docs_again.clone()),
        )
        .await
        .unwrap();
        let reread = kernel::read_record_as(&db, &admin, &docs_id2)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(Value::Object(reread.fields.clone()), docs_again);
        // Tracker-style query_view.
        let tracker = json!({"name": "Work", "definition": tracker_definition(true)});
        let tracker_id = create(
            &db,
            &admin,
            SAVED_VIEW_FAMILY,
            "query_view",
            &map(tracker.clone()),
        )
        .await
        .unwrap();
        let stored_tracker = kernel::read_record_as(&db, &admin, &tracker_id)
            .await
            .unwrap()
            .unwrap();
        let stored_tracker = Value::Object(stored_tracker.fields.clone());
        validate_query_view_strings(&stored_tracker).unwrap();
        let wire = wire_open(SAVED_VIEW_PIN, &stored_tracker["definition"]).unwrap();
        assert_eq!(wire["version"], json!(1));
        assert_eq!(wire["format"], json!("tracker-query/1"));
        let captured = wire_capture(SAVED_VIEW_PIN, &wire).unwrap();
        assert_eq!(captured, stored_tracker["definition"]);
        // Same storage leg for the Tracker-style view.
        let tracker_again = json!({"name": "Work (copy)", "definition": captured});
        let tracker_id2 = create(
            &db,
            &admin,
            SAVED_VIEW_FAMILY,
            "query_view",
            &map(tracker_again.clone()),
        )
        .await
        .unwrap();
        let reread = kernel::read_record_as(&db, &admin, &tracker_id2)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(Value::Object(reread.fields.clone()), tracker_again);
        // Capture with version 2 or a missing version refuses.
        let mut v2 = wire.clone();
        v2["version"] = json!(2);
        assert_eq!(
            wire_capture(SAVED_VIEW_PIN, &v2).unwrap_err().rule,
            "wire-version"
        );
        let mut missing = wire.clone();
        missing.as_object_mut().unwrap().remove("version");
        assert_eq!(
            wire_capture(SAVED_VIEW_PIN, &missing).unwrap_err().rule,
            "wire-version"
        );
        db.close().await;
    }

    #[test]
    fn preferences_write_drops_known_unavailable_on_the_way_to_store() {
        // Mirrors the host rule (v1 LF:214-217) at the consumer boundary:
        // a newly supplied ghost refuses, a previously known one is dropped.
        let available: HashSet<String> = [uuid(1), uuid(2)].into();
        let known: HashSet<String> = ["gone".to_string()].into();
        let entries = vec![
            PreferenceEntry {
                focus_id: uuid(2),
                tier: "background".into(),
                hidden: true,
            },
            PreferenceEntry {
                focus_id: "gone".into(),
                tier: "now".into(),
                hidden: false,
            },
            PreferenceEntry {
                focus_id: uuid(1),
                tier: "now".into(),
                hidden: false,
            },
        ];
        let stored = check_preferences_write(&entries, &available, &known).unwrap();
        assert_eq!(
            stored.iter().map(|e| &e.focus_id).collect::<Vec<_>>(),
            [&uuid(2), &uuid(1)]
        );
        let read = read_preferences(&stored, &available);
        assert_eq!(read, stored);
        let fresh_ghost = vec![PreferenceEntry {
            focus_id: "fresh-ghost".into(),
            tier: "now".into(),
            hidden: false,
        }];
        assert_eq!(
            check_preferences_write(&fresh_ghost, &available, &known)
                .unwrap_err()
                .rule,
            "preferences-unavailable"
        );
    }

    #[test]
    fn archived_view_is_not_a_live_member() {
        // Archived stand-in: the view exists in storage but is excluded from
        // the live-member set, so a stored order naming it is repaired by
        // dropping it, and an order write naming it is refused.
        let live: HashSet<String> = ["v-live".to_string()].into();
        let repaired = repair_order_read(&["v-live".into(), "v-archived".into()], &live).unwrap();
        assert_eq!(repaired.order, vec!["v-live"]);
        assert_eq!(repaired.dropped, vec!["v-archived"]);
        let refused =
            check_order_write(&["v-live".into(), "v-archived".into()], &live, false).unwrap_err();
        assert_eq!(refused.rule, "order-unknown");
    }

    #[test]
    fn moved_string_rules_accept_exact_max_and_refuse_max_plus_one() {
        // Name: 60 code points fit, 61 refuse.
        assert!(validate_focus_strings(&json!({"name": "x".repeat(60), "view_order": []})).is_ok());
        assert_eq!(
            validate_focus_strings(&json!({"name": "x".repeat(61), "view_order": []}))
                .unwrap_err()
                .rule,
            "name"
        );
        // App id: exactly 128 chars fit, 129 refuse.
        let app128 = format!("a.{}", "b".repeat(126));
        assert_eq!(app128.chars().count(), 128);
        let record = |app: &str| {
            json!({"name": "Plan", "definition": {
                "app": app, "target": {"record_id": "native:root"}}})
        };
        assert!(validate_record_view_strings(&record(&app128)).is_ok());
        assert_eq!(
            validate_record_view_strings(&record(&format!("a.{}", "b".repeat(127))))
                .unwrap_err()
                .rule,
            "app"
        );
        // Format: exactly 64 chars fit, 65 refuse.
        let format64 = format!("ab/{}", "1".repeat(61));
        assert_eq!(format64.chars().count(), 64);
        let query = |definition: Value| json!({"name": "Work", "definition": definition});
        let definition = |format: &str, text: &str| {
            json!({"app": "agent.tracker", "format": format, "text": text,
                "filter": {"combine": "all", "terms": []}, "sort": []})
        };
        assert!(validate_query_view_strings(&query(definition(&format64, "t"))).is_ok());
        assert_eq!(
            validate_query_view_strings(&query(definition(&format!("ab/{}", "1".repeat(62)), "t")))
                .unwrap_err()
                .rule,
            "format"
        );
        // Field: exactly 64 chars fit, 65 refuse (via group_by).
        let with_group = |group_by: &str| {
            json!({"name": "Work", "definition": {
                "app": "agent.tracker", "format": "tracker-query/1",
                "filter": {"combine": "all", "terms": []}, "sort": [],
                "group_by": group_by}})
        };
        assert!(validate_query_view_strings(&with_group(&"f".repeat(64))).is_ok());
        assert_eq!(
            validate_query_view_strings(&with_group(&"f".repeat(65)))
                .unwrap_err()
                .rule,
            "field"
        );
        // Text: exactly 512 chars fit, 513 refuse; blank refuses.
        assert!(validate_query_view_strings(&query(definition(
            "tracker-query/1",
            &"x".repeat(512)
        )))
        .is_ok());
        assert_eq!(
            validate_query_view_strings(&query(definition("tracker-query/1", &"x".repeat(513))))
                .unwrap_err()
                .rule,
            "text"
        );
        assert_eq!(
            validate_query_view_strings(&query(definition("tracker-query/1", "   ")))
                .unwrap_err()
                .rule,
            "text"
        );
    }
}
