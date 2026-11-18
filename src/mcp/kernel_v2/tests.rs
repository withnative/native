use super::*;
use crate::{events::KERNEL_ROOT_ID, mcp::render};

#[cfg(feature = "v2-kernel-probe")]
#[path = "candidate_index_tests.rs"]
mod candidate_index_tests;

#[tokio::test]
async fn kernel_v2_document_create_mints_id_and_replays_keyed_receipt() {
    let w = world().await;
    let package = crate::v2_standard::document_package();
    let identity = package.identity().unwrap();
    kernel::install_package_as(&w.db, &w.admin, &package)
        .await
        .unwrap();
    kernel::adopt_package_at(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &package,
        Some(&identity),
        &package.declared_reads,
    )
    .await
    .unwrap();
    let home = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let args = json!({"type":"Document","kind":"note","name":"Untitled document",
        "body":"","home_id":home,"reason":"Docs create contract regression",
        "idempotency_key":"docs-logical-attempt"});
    let mut caller_id = args.clone();
    caller_id["id"] = json!("13425364-7576-4788-8990-aabbccddeeff");
    let error = call_as(&w, "acct:admin", "create_record", caller_id)
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("id is only supported for messaging sends"),
        "{error}"
    );

    let receipt = call_as(&w, "acct:admin", "create_record", args.clone())
        .await
        .unwrap();
    let id = receipt["id"].as_str().unwrap();
    assert!(uuid::Uuid::parse_str(id).is_ok());
    // Losing the first response cannot lose the transaction's durable receipt.
    let before_replay = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    let replay = call_as(&w, "acct:admin", "create_record", args.clone())
        .await
        .unwrap();
    assert_eq!(replay, receipt);
    assert_eq!(
        before_replay,
        kernel::dump_all_kernel_tables(&w.db).await.unwrap()
    );
    let mut changed = args.clone();
    changed["name"] = json!("Different request");
    let error = call_as(&w, "acct:admin", "create_record", changed)
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("idempotency_key reused for different request"),
        "{error}"
    );
    let mut distinct = args;
    distinct["idempotency_key"] = json!("docs-another-attempt");
    let another = call_as(&w, "acct:admin", "create_record", distinct)
        .await
        .unwrap();
    assert_ne!(another["id"], receipt["id"]);
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_catalogue_refuses_saved_and_composed_reads() {
    let w = world().await;
    let args = json!({"sql":"SELECT executor FROM catalog_operations ORDER BY executor"});
    let error = super::sql::query_stored_saved_sql(&w.db, &w.admin, args)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("catalog_operations"), "{error}");
    let mut tx = w.db.write_pool().begin().await.unwrap();
    let reads = std::collections::BTreeSet::from([(
        "catalog_operations".to_owned(),
        "executor".to_owned(),
    )]);
    let error = super::sql::install(&mut tx, &w.admin, &reads)
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("serving executor catalogue"),
        "{error}"
    );
}

pub(super) fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
    register_kernel_v2_tools(&mut registry).unwrap();
    registry
}

struct World {
    _dir: tempfile::TempDir,
    db: Db,
    admin: String,
    viewer: String,
    first: String,
    second: String,
    hidden: String,
}
async fn world() -> World {
    let dir = tempfile::tempdir().unwrap();
    let (db, admin) = kernel::create_v2_database(
        dir.path().join("v2.db").to_str().unwrap(),
        "account",
        "Admin",
        "acct:admin",
    )
    .await
    .unwrap();
    let viewer = kernel::create_principal(&db, "account", "Viewer", "acct:viewer", &admin)
        .await
        .unwrap();
    let definition = json!({
        "family": "fixture.mcp", "version": 1, "interpreter": "native.defn/2",
        "primary_type": "Document", "kinds": [{"token": "note", "description": "MCP fixture",
            "maturity": "current", "identity": {"field": "title"},
            "fields": [{"name": "title", "type": "text", "required": true}, {"name": "body", "type": "text", "required": false}],
            "links": [{"predicate": "relates_to", "target": {"primary_type": "Document", "kind": "note"}, "direction": "out", "cardinality": "many"}]}]
    });
    let pin = kernel::install_definition_as(
        &db,
        &admin,
        "fixture.mcp",
        1,
        &serde_json::to_vec(&definition).unwrap(),
    )
    .await
    .unwrap();
    kernel::adopt_definition_as(&db, &admin, &pin.family, Some(&pin))
        .await
        .unwrap();
    let home = kernel::create_home(&db, KERNEL_ROOT_ID, Some(&[(&viewer, "view")]), &admin)
        .await
        .unwrap();
    let private = kernel::create_home(&db, KERNEL_ROOT_ID, Some(&[]), &admin)
        .await
        .unwrap();
    let mut ids = Vec::new();
    for (title, home) in [("Alpha", &home), ("Beta", &home), ("Secret", &private)] {
        ids.push(
            kernel::create_as(
                &db,
                &admin,
                "fixture.mcp",
                "note",
                json!({"title": title, "body": "original"})
                    .as_object()
                    .unwrap(),
                home,
            )
            .await
            .unwrap(),
        );
    }
    kernel::revise_as(
        &db,
        &admin,
        &ids[0],
        json!({"body": "revised"}).as_object().unwrap(),
    )
    .await
    .unwrap();
    kernel::link_as(&db, &admin, &ids[0], "relates_to", &ids[1])
        .await
        .unwrap();
    kernel::link_as(&db, &admin, &ids[0], "relates_to", &ids[2])
        .await
        .unwrap();
    World {
        _dir: dir,
        db,
        admin,
        viewer,
        first: ids[0].clone(),
        second: ids[1].clone(),
        hidden: ids[2].clone(),
    }
}
#[tokio::test]
async fn record_hook_v2_matches_records_view_currency() {
    let w = world().await;
    let page = call_as(
        &w,
        "acct:admin",
        "query_record",
        json!({
            "projection": "record_hook.v1",
            "steps": [{"step": "filter", "types": ["Document"], "ids": [w.first]}]
        }),
    )
    .await
    .unwrap();
    let direct = call_as(
        &w,
        "acct:admin",
        "query_sql",
        json!({
            "sql": "SELECT id, created_at, updated_at_ms, is_current, lifecycle FROM records WHERE id = ?1",
            "parameters": [{"type": "text", "value": w.first}]
        }),
    )
    .await
    .unwrap();
    let row = &page["records"][0];
    let view = &direct["rows"][0];
    assert_eq!(row["id"], view["id"], "page={page} direct={direct}");
    assert_eq!(
        row["created_at"], view["created_at"],
        "page={page} direct={direct}"
    );
    assert_eq!(
        row["updated_at_ms"], view["updated_at_ms"],
        "page={page} direct={direct}"
    );
    assert_eq!(
        row["is_current"], view["is_current"],
        "page={page} direct={direct}"
    );
    assert_eq!(
        row["lifecycle"], view["lifecycle"],
        "page={page} direct={direct}"
    );
    assert!(row.get("body").is_none());
    assert!(row.get("body_digest").is_none());
    assert!(row.get("lifecycle_interpretation").is_some());
    let hidden = call_as(
        &w,
        "acct:viewer",
        "query_record",
        json!({
            "projection": "record_hook.v1",
            "steps": [{"step": "filter", "types": ["Document"], "ids": [w.hidden]}]
        }),
    )
    .await
    .unwrap();
    assert_eq!(hidden["records"].as_array().unwrap().len(), 0);
    assert!(hidden.get("total").is_none());
    assert_eq!(hidden["returned"], 0);
    assert_eq!(hidden["has_more"], false);
    let metadata = call_as(
        &w,
        "acct:admin",
        "query_record",
        json!({
            "projection": "metadata",
            "steps": [{"step": "filter", "types": ["Document"], "ids": [w.first]}]
        }),
    )
    .await
    .unwrap();
    assert!(metadata["records"][0].get("updated_at_ms").is_none());
    assert!(metadata["records"][0].get("is_current").is_none());
    let prefixed = call_as(
        &w,
        "acct:admin",
        "query_record",
        json!({
            "projection": "record_hook.v1",
            "body_chars": 3,
            "steps": [{"step": "filter", "types": ["Document"], "ids": [w.first]}]
        }),
    )
    .await
    .unwrap();
    let direct = call_as(
        &w,
        "acct:admin",
        "query_sql",
        json!({
            "sql": "SELECT substr(body, 1, ?1) AS body, length(body) AS body_length FROM records WHERE id = ?2",
            "parameters": [
                {"type": "integer", "value": "3"},
                {"type": "text", "value": w.first}
            ]
        }),
    )
    .await
    .unwrap();
    assert_eq!(prefixed["records"][0]["body"], "rev");
    assert_eq!(prefixed["records"][0]["body_length"], 7);
    assert_eq!(prefixed["records"][0]["body"], direct["rows"][0]["body"]);
    assert_eq!(
        prefixed["records"][0]["body_length"],
        direct["rows"][0]["body_length"]
    );
    assert!(prefixed["records"][0].get("body_digest").is_none());
    kernel::revise_as(
        &w.db,
        &w.admin,
        &w.first,
        json!({"body": "ab😀cd"}).as_object().unwrap(),
    )
    .await
    .unwrap();
    let emoji = call_as(
        &w,
        "acct:admin",
        "query_record",
        json!({
            "projection": "record_hook.v1",
            "body_chars": 3,
            "steps": [{"step": "filter", "types": ["Document"], "ids": [w.first]}]
        }),
    )
    .await
    .unwrap();
    let emoji_direct = call_as(
        &w,
        "acct:admin",
        "query_sql",
        json!({
            "sql": "SELECT substr(body, 1, ?1) AS body, length(body) AS body_length FROM records WHERE id = ?2",
            "parameters": [
                {"type": "integer", "value": "3"},
                {"type": "text", "value": w.first}
            ]
        }),
    )
    .await
    .unwrap();
    assert_eq!(emoji["records"][0]["body"], "ab😀");
    assert_eq!(emoji["records"][0]["body_length"], 5);
    assert_eq!(emoji["records"][0]["body"], emoji_direct["rows"][0]["body"]);
    assert_eq!(
        emoji["records"][0]["body_length"],
        emoji_direct["rows"][0]["body_length"]
    );
    let absent = call_as(
        &w,
        "acct:admin",
        "query_record",
        json!({
            "projection": "record_hook.v1",
            "steps": [{"step": "filter", "types": ["Document"], "ids": [w.first]}]
        }),
    )
    .await
    .unwrap();
    assert!(absent["records"][0].get("body").is_none());
    assert!(absent["records"][0].get("body_length").is_none());
    for args in [
        json!({
            "projection": "metadata",
            "body_chars": 3,
            "steps": [{"step": "filter", "types": ["Document"], "ids": [w.first]}]
        }),
        json!({
            "projection": "record_hook.v1",
            "body_chars": 3,
            "steps": [{"step": "filter", "types": ["Document"], "ids": [w.first, w.second]}]
        }),
        json!({
            "projection": "record_hook.v1",
            "body_chars": 3,
            "steps": [{"step": "filter", "types": ["Document"], "home_id": "home-1"}]
        }),
        json!({
            "projection": "record_hook.v1",
            "body_chars": 0,
            "steps": [{"step": "filter", "types": ["Document"], "ids": [w.first]}]
        }),
        json!({
            "projection": "record_hook.v1",
            "body_chars": "3",
            "steps": [{"step": "filter", "types": ["Document"], "ids": [w.first]}]
        }),
    ] {
        assert!(
            call_as(&w, "acct:admin", "query_record", args)
                .await
                .is_err(),
            "selector should be refused"
        );
    }
}

async fn call(world: &World, name: &str, args: Value) -> Result<Value> {
    call_as(world, "acct:viewer", name, args).await
}

async fn call_as(world: &World, credential: &str, name: &str, args: Value) -> Result<Value> {
    registry()
        .call_engine(
            EngineHandle::KernelV2(world.db.clone()),
            Caller::authenticated(credential),
            name,
            args,
        )
        .await
}

/// Compat carrier for `Annotation`/`comment` records: every non-note v1
/// pair rides `native.v1.record@1`, so the comment tests adopt it.
async fn install_comment_carrier(world: &World) {
    let manifest = crate::v2_standard::v1_compat::package();
    let identity = manifest.identity().unwrap();
    kernel::install_package_as(&world.db, &world.admin, &manifest)
        .await
        .unwrap();
    kernel::adopt_package_at(
        &world.db,
        &world.admin,
        KERNEL_ROOT_ID,
        &manifest,
        Some(&identity),
        &manifest.declared_reads,
    )
    .await
    .unwrap();
}

fn anchored_target(bearer: &str, exact: &str, start: u64, end: u64) -> Value {
    json!({
        "target_record_id": bearer,
        "source_slot": "body",
        "selectors": [
            {"type": "text_quote", "exact": exact},
            {"type": "data_position", "start": start, "end": end},
        ],
    })
}

#[cfg(feature = "v2-kernel-probe")]
async fn assert_comment_history_with_broken_root_bearer(duplicate: bool) {
    let world = world().await;
    install_comment_carrier(&world).await;
    let outsider = kernel::create_principal(
        &world.db,
        "account",
        "Outsider",
        "acct:outsider",
        &world.admin,
    )
    .await
    .unwrap();
    let root = call(
        &world,
        "create_record",
        json!({
            "type":"Annotation", "kind":"comment", "body":"Root comment.",
            "links":[{"target_id":world.first,"relationship":"part_of"}],
        }),
    )
    .await
    .unwrap();
    let root_id = root["id"].as_str().unwrap();
    let reply = call(
        &world,
        "create_record",
        json!({
            "type":"Annotation", "kind":"comment", "body":"Reply comment.",
            "links":[{"target_id":root_id,"relationship":"part_of"}],
        }),
    )
    .await
    .unwrap();
    let reply_id = reply["id"].as_str().unwrap();
    // Both records have history visible to the author and the root manager
    // before the root's chain is broken. The reply's own bearer stays intact.
    for id in [root_id, reply_id] {
        for principal in [&world.admin, &world.viewer] {
            assert!(!kernel::history_as(&world.db, principal, id)
                .await
                .unwrap()
                .is_empty());
        }
    }
    // Malformed retained projections cannot be created through the ordinary
    // comment API. Corrupt only the root's bearer, keeping its history intact.
    if duplicate {
        assert_eq!(
            sqlx::query("INSERT INTO kernel_generic_links(link_id,source_id,target_id,relationship,note,created_at,actor,active,event_seq,imported) SELECT 'duplicate-root-bearer',source_id,?,relationship,note,created_at,actor,active,event_seq,imported FROM kernel_generic_links WHERE source_id=? AND relationship='part_of' AND active=1")
                .bind(&world.second)
                .bind(root_id)
                .execute(world.db.write_pool())
                .await
                .unwrap()
                .rows_affected(),
            1
        );
    } else {
        assert_eq!(
            sqlx::query("DELETE FROM kernel_generic_links WHERE source_id=? AND relationship='part_of' AND active=1")
                .bind(root_id)
                .execute(world.db.write_pool())
                .await
                .unwrap()
                .rows_affected(),
            1
        );
    }
    for (principal, credential) in [
        (&world.admin, "acct:admin"),
        (&world.viewer, "acct:viewer"),
        (&outsider, "acct:outsider"),
    ] {
        for id in [root_id, reply_id] {
            assert!(kernel::history_as(&world.db, principal, id)
                .await
                .unwrap()
                .is_empty());
            let read = call_as(&world, credential, "get_record", json!({"ids":[id]}))
                .await
                .unwrap();
            assert_ne!(read["records"][0]["status"], "found", "{read}");
            let bearer = call_as(
                &world,
                credential,
                "get_record",
                json!({"ids":[world.first,world.second],"include_comments":true}),
            )
            .await
            .unwrap();
            assert!(!bearer.to_string().contains(id), "{bearer}");
            let listed = call_as(
                &world,
                credential,
                "query_record",
                json!({"steps":[{"step":"filter","types":["Annotation"],"kinds":["comment"]}]}),
            )
            .await
            .unwrap();
            assert!(!listed.to_string().contains(id), "{listed}");
            let sql = call_as(&world, credential, "query_sql", json!({"sql":"SELECT id FROM records WHERE id=?1", "parameters":[{"type":"text","value":id}]})).await.unwrap();
            assert_eq!(sql["rows"], json!([]));
            let searched = call_as(&world, credential, "search", json!({"query":"comment"}))
                .await
                .unwrap();
            assert!(!searched.to_string().contains(id), "{searched}");
            for anchor in [
                world.first.as_str(),
                world.second.as_str(),
                root_id,
                reply_id,
            ] {
                let links =
                    kernel::generic_links::visible_link_rows_as(&world.db, principal, anchor)
                        .await
                        .unwrap();
                assert!(
                    !serde_json::to_string(&links).unwrap().contains(id),
                    "{links:?}"
                );
            }
            for full in [false, true] {
                assert!(kernel::history_page_as(
                    &world.db, principal, id, None, false, 100, full, true,
                )
                .await
                .unwrap()
                .is_empty());
                assert!(call_as(
                    &world,
                    credential,
                    "get_history",
                    json!({"record_id":id,"detail":if full {"full"} else {"metadata"}}),
                )
                .await
                .is_err());
            }
        }
    }
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_comment_history_missing_root_bearer_is_empty_for_every_caller() {
    assert_comment_history_with_broken_root_bearer(false).await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_comment_history_duplicated_root_bearer_is_empty_for_every_caller() {
    assert_comment_history_with_broken_root_bearer(true).await;
}

#[tokio::test]
async fn kernel_v2_comment_thread_create_reply_resolve_and_list() {
    let world = world().await;
    install_comment_carrier(&world).await;
    let admin = "acct:admin";
    // The anchor pins the body lane: set it before quoting.
    call_as(
        &world,
        admin,
        "update_record",
        json!({"id": world.first, "body_set": "alpha brave revised passage"}),
    )
    .await
    .unwrap();
    // Anchored root on the visible note: the quote pins the current body.
    let root_args = json!({
        "type": "Annotation", "kind": "comment", "body": "Needs a second pair of eyes.",
        "links": [{"target_id": world.first, "relationship": "part_of"}],
        "target": anchored_target(&world.first, "revised", 12, 19),
        "idempotency_key": "w3-thread-root",
    });
    let root = call_as(&world, admin, "create_record", root_args.clone())
        .await
        .unwrap();
    let root_id = root["id"].as_str().unwrap().to_owned();
    // Idempotent retry returns the record already created, not a duplicate.
    let retry = call_as(&world, admin, "create_record", root_args.clone())
        .await
        .unwrap();
    assert_eq!(retry["id"], root["id"]);
    let listed = call(
        &world,
        "get_record",
        json!({"ids": [world.first], "include_comments": true}),
    )
    .await
    .unwrap();
    assert_eq!(listed["records"][0]["comment_count"], 1);
    let summary = &listed["records"][0]["comments"][0];
    assert_eq!(summary["body"], "Needs a second pair of eyes.");
    assert_eq!(summary["position"], "root");
    assert_eq!(summary["lifecycle"], "informational");
    assert_eq!(
        summary["target"]["target_record_id"], world.first,
        "{summary:#}"
    );
    assert_eq!(summary["target"]["validation"]["status"], "current");
    // Reply bears on the root, targetless, with a null lifecycle.
    let reply = call_as(
        &world,
        admin,
        "create_record",
        json!({
            "type": "Annotation", "kind": "comment", "body": "Agreed, on it.",
            "links": [{"target_id": root_id, "relationship": "part_of"}],
            "idempotency_key": "w3-thread-reply",
        }),
    )
    .await
    .unwrap();
    let reply_id = reply["id"].as_str().unwrap().to_owned();
    let thread = call_as(
        &world,
        admin,
        "get_record",
        json!({"ids": [root_id], "include_comments": true}),
    )
    .await
    .unwrap();
    assert_eq!(thread["records"][0]["comment_count"], 1);
    let reply_summary = &thread["records"][0]["comments"][0];
    assert_eq!(reply_summary["id"], reply_id);
    assert_eq!(reply_summary["position"], "reply");
    assert_eq!(reply_summary["root_id"], root_id);
    assert!(reply_summary["lifecycle"].is_null());
    // Replies inherit the root's target context without copying anchor rows.
    assert_eq!(
        reply_summary["target"]["target_record_id"], world.first,
        "{reply_summary:#}"
    );
    world.db.close().await;
}

#[tokio::test]
async fn kernel_v2_comment_resolve_rules_match_v1() {
    let world = world().await;
    install_comment_carrier(&world).await;
    let admin = "acct:admin";
    // An FYI root (no lifecycle) is deliberately not resolvable.
    let fyi = call_as(
        &world,
        admin,
        "create_record",
        json!({
            "type": "Annotation", "kind": "comment", "body": "For the record.",
            "links": [{"target_id": world.first, "relationship": "part_of"}],
        }),
    )
    .await
    .unwrap();
    let fyi_id = fyi["id"].as_str().unwrap();
    let refused = call_as(
        &world,
        admin,
        "update_record",
        json!({"id": fyi_id, "lifecycle": "resolved", "summary": "Done"}),
    )
    .await
    .unwrap_err();
    assert!(
        refused.to_string().contains("not resolvable"),
        "{refused:#}"
    );
    // Roots cannot be born resolved; resolve is open -> resolved with prose.
    let born = call_as(
        &world,
        admin,
        "create_record",
        json!({
            "type": "Annotation", "kind": "comment", "body": "Please fix.",
            "lifecycle": "resolved", "summary": "Done",
            "links": [{"target_id": world.first, "relationship": "part_of"}],
        }),
    )
    .await
    .unwrap_err();
    assert!(
        born.to_string().contains("cannot be created resolved"),
        "{born:#}"
    );
    let open = call_as(
        &world,
        admin,
        "create_record",
        json!({
            "type": "Annotation", "kind": "comment", "body": "Please fix.",
            "lifecycle": "open",
            "links": [{"target_id": world.first, "relationship": "part_of"}],
        }),
    )
    .await
    .unwrap();
    let open_id = open["id"].as_str().unwrap();
    // A summary may not land on an open root at all.
    let summary_only = call_as(
        &world,
        admin,
        "update_record",
        json!({"id": open_id, "summary": "Early note"}),
    )
    .await
    .unwrap_err();
    assert!(
        summary_only
            .to_string()
            .contains("only valid on a resolved root"),
        "{summary_only:#}"
    );
    let resolved = call_as(
        &world,
        admin,
        "update_record",
        json!({"id": open_id, "lifecycle": "resolved", "summary": "Fixed in revision two."}),
    )
    .await
    .unwrap();
    assert_eq!(resolved["effect"], "updated");
    // Rewriting the summary without the transition is refused even on a
    // resolved root: prose only travels with open -> resolved.
    let rewrite = call_as(
        &world,
        admin,
        "update_record",
        json!({"id": open_id, "summary": "Different prose"}),
    )
    .await
    .unwrap_err();
    assert!(
        rewrite
            .to_string()
            .contains("atomically with open -> resolved"),
        "{rewrite:#}"
    );
    let read = call_as(
        &world,
        admin,
        "get_record",
        json!({"ids": [world.first], "include_comments": true}),
    )
    .await
    .unwrap();
    let states: Vec<String> = read["records"][0]["comments"]
        .as_array()
        .unwrap()
        .iter()
        .map(|comment| comment["lifecycle"].as_str().unwrap_or("null").to_owned())
        .collect();
    assert!(states.contains(&"resolved".to_owned()), "{states:?}");
    // Replies carry no thread state, and nesting is refused.
    let reply = call_as(
        &world,
        admin,
        "create_record",
        json!({
            "type": "Annotation", "kind": "comment", "body": "Working on it.",
            "links": [{"target_id": open_id, "relationship": "part_of"}],
        }),
    )
    .await
    .unwrap();
    let reply_id = reply["id"].as_str().unwrap();
    let reply_lifecycle = call_as(
        &world,
        admin,
        "create_record",
        json!({
            "type": "Annotation", "kind": "comment", "body": "Bad reply.",
            "lifecycle": "open",
            "links": [{"target_id": open_id, "relationship": "part_of"}],
        }),
    )
    .await
    .unwrap_err();
    assert!(
        reply_lifecycle.to_string().contains("null lifecycle"),
        "{reply_lifecycle:#}"
    );
    let reply_target = call_as(
        &world,
        admin,
        "create_record",
        json!({
            "type": "Annotation", "kind": "comment", "body": "Bad reply.",
            "links": [{"target_id": open_id, "relationship": "part_of"}],
            "target": anchored_target(&world.first, "revised", 12, 19),
        }),
    )
    .await
    .unwrap_err();
    assert!(
        reply_target.to_string().contains("targetless"),
        "{reply_target:#}"
    );
    let nested = call_as(
        &world,
        admin,
        "create_record",
        json!({
            "type": "Annotation", "kind": "comment", "body": "Nested.",
            "links": [{"target_id": reply_id, "relationship": "part_of"}],
        }),
    )
    .await
    .unwrap_err();
    assert!(
        nested.to_string().contains("directly on a root"),
        "{nested:#}"
    );
    world.db.close().await;
}

#[tokio::test]
async fn kernel_v2_comment_null_lifecycle_is_refused_without_changing_state() {
    let world = world().await;
    install_comment_carrier(&world).await;
    let root = call_as(
        &world,
        "acct:admin",
        "create_record",
        json!({
            "type": "Annotation", "kind": "comment", "body": "Question", "lifecycle": "open",
            "links": [{"target_id": world.first, "relationship": "part_of"}]
        }),
    )
    .await
    .unwrap();
    let id = root["id"].as_str().unwrap();
    for state in ["open", "resolved"] {
        if state == "resolved" {
            call_as(
                &world,
                "acct:admin",
                "update_record",
                json!({
                    "id": id, "lifecycle": "resolved", "summary": "Answered"
                }),
            )
            .await
            .unwrap();
        }
        for patch in [
            json!({"id": id, "lifecycle": null}),
            json!({"id": id, "lifecycle": null, "summary": null}),
        ] {
            assert!(call_as(&world, "acct:admin", "update_record", patch)
                .await
                .is_err());
            let read = call_as(&world, "acct:admin", "get_record", json!({"ids": [id]}))
                .await
                .unwrap();
            assert_eq!(read["records"][0]["lifecycle"], state);
            assert_eq!(
                read["records"][0]["summary"],
                if state == "resolved" {
                    json!("Answered")
                } else {
                    Value::Null
                }
            );
        }
    }
    world.db.close().await;
}

#[tokio::test]
async fn kernel_v2_comment_reopen_requires_edit_and_clears_summary() {
    let world = world().await;
    install_comment_carrier(&world).await;
    let root = call_as(
        &world,
        "acct:admin",
        "create_record",
        json!({
            "type": "Annotation", "kind": "comment", "body": "Question", "lifecycle": "open",
            "links": [{"target_id": world.first, "relationship": "part_of"}]
        }),
    )
    .await
    .unwrap();
    let id = root["id"].as_str().unwrap();
    call_as(
        &world,
        "acct:admin",
        "update_record",
        json!({
            "id": id, "lifecycle": "resolved", "summary": "Answered"
        }),
    )
    .await
    .unwrap();
    // View authorizes a reply, but never a lifecycle write to its root.
    let reply = call(
        &world,
        "create_record",
        json!({
            "type": "Annotation", "kind": "comment", "body": "Another question",
            "links": [{"target_id": id, "relationship": "part_of"}]
        }),
    )
    .await
    .unwrap();
    let reopen = json!({"id": id, "lifecycle": "open", "summary": null,
        "idempotency_key": "comment-reopen"});
    let denied = call(&world, "update_record", reopen.clone())
        .await
        .unwrap_err();
    assert!(
        denied.to_string().contains("requires edit capability"),
        "{denied}"
    );
    for args in [
        json!({"id": id, "lifecycle": "open"}),
        json!({"id": id, "lifecycle": "open", "summary": "Answered"}),
        json!({"id": reply["id"], "lifecycle": "open", "summary": null}),
    ] {
        assert!(call_as(&world, "acct:admin", "update_record", args)
            .await
            .is_err());
    }
    let mut stale = reopen.clone();
    stale["if_unmodified_since"] = json!("2000-01-01T00:00:00Z");
    stale["idempotency_key"] = json!("comment-reopen-stale");
    assert!(call_as(&world, "acct:admin", "update_record", stale)
        .await
        .is_err());
    call_as(&world, "acct:admin", "update_record", reopen.clone())
        .await
        .unwrap();
    call_as(&world, "acct:admin", "update_record", reopen)
        .await
        .unwrap();
    let read = call_as(&world, "acct:admin", "get_record", json!({"ids": [id]}))
        .await
        .unwrap();
    assert_eq!(read["records"][0]["lifecycle"], "open");
    assert!(read["records"][0]["summary"].is_null(), "{read}");
    world.db.close().await;
}

#[tokio::test]
async fn kernel_v2_comment_view_only_member_can_annotate_not_resolve() {
    let world = world().await;
    install_comment_carrier(&world).await;
    // The viewer holds View and nothing else on the note's home.
    call_as(
        &world,
        "acct:admin",
        "update_record",
        json!({"id": world.first, "body_set": "alpha brave revised passage"}),
    )
    .await
    .unwrap();
    // View of the bearer authorizes creation and replies; the comment files
    // in the bearer's home without home Edit, exactly like v1 at ROOT.
    // An admin thread anchors the resolve refusal below: the viewer owns
    // their own comments (owner floor) but may not resolve another's.
    let admin_root = call_as(
        &world,
        "acct:admin",
        "create_record",
        json!({
            "type": "Annotation", "kind": "comment", "body": "Admin question.",
            "lifecycle": "open",
            "links": [{"target_id": world.first, "relationship": "part_of"}],
            "idempotency_key": "w3-admin-open",
        }),
    )
    .await
    .unwrap();
    let admin_root_id = admin_root["id"].as_str().unwrap();
    let unanchored_reply = call(
        &world,
        "create_record",
        json!({
            "type":"Annotation", "kind":"comment", "body":"Unanchored reply.",
            "links":[{"target_id":admin_root_id,"relationship":"part_of"}],
        }),
    )
    .await
    .unwrap();
    for id in [admin_root_id, unanchored_reply["id"].as_str().unwrap()] {
        let history = call(&world, "get_history", json!({"record_id":id}))
            .await
            .unwrap();
        assert!(!history["events"].as_array().unwrap().is_empty());
    }
    let mut hidden_bearer = world.hidden.clone();
    for body in ["Hidden root.", "Hidden reply."] {
        let created = call_as(
            &world,
            "acct:admin",
            "create_record",
            json!({
                "type":"Annotation", "kind":"comment", "body":body,
                "links":[{"target_id":hidden_bearer,"relationship":"part_of"}],
            }),
        )
        .await
        .unwrap();
        hidden_bearer = created["id"].as_str().unwrap().to_owned();
        assert!(
            call(&world, "get_history", json!({"record_id":hidden_bearer}))
                .await
                .is_err()
        );
        let own = call_as(
            &world,
            "acct:admin",
            "get_history",
            json!({"record_id":hidden_bearer}),
        )
        .await
        .unwrap();
        assert!(!own["events"].as_array().unwrap().is_empty());
    }

    let root = call(
        &world,
        "create_record",
        json!({
            "type": "Annotation", "kind": "comment", "body": "Viewer remark.",
            "lifecycle": "open",
            "links": [{"target_id": world.first, "relationship": "part_of"}],
            "target": anchored_target(&world.first, "revised", 12, 19),
            "idempotency_key": "w3-viewer-root",
        }),
    )
    .await
    .unwrap();
    let root_id = root["id"].as_str().unwrap().to_owned();
    call(
        &world,
        "create_record",
        json!({
            "type": "Annotation", "kind": "comment", "body": "Viewer reply.",
            "links": [{"target_id": root_id, "relationship": "part_of"}],
            "idempotency_key": "w3-viewer-reply",
        }),
    )
    .await
    .unwrap();
    // Resolve stays Edit-gated: the viewer may not resolve another's thread.
    let refused = call(
        &world,
        "update_record",
        json!({"id": admin_root_id, "lifecycle": "resolved", "summary": "Viewer fix."}),
    )
    .await
    .unwrap_err();
    assert!(
        refused.to_string().contains("requires edit capability"),
        "{refused:#}"
    );
    let listed = call(
        &world,
        "get_record",
        json!({"ids": [world.first], "include_comments": true}),
    )
    .await
    .unwrap();
    assert_eq!(listed["records"][0]["comment_count"], 2);
    world.db.close().await;
}

#[tokio::test]
async fn kernel_v2_comment_terminal_owner_sees_thread_everywhere() {
    let world = world().await;
    install_comment_carrier(&world).await;
    let admin = "acct:admin";
    // A home with an empty policy: nobody sees through it, so the note's
    // owner reads the note — and its thread — by owner floor alone.
    let home = kernel::create_home(&world.db, KERNEL_ROOT_ID, Some(&[]), &world.admin)
        .await
        .unwrap();
    // The world never adopts the standard document family: file the note
    // through the world's own fixture definition, then set its body lane.
    let note_id = kernel::create_as(
        &world.db,
        &world.admin,
        "fixture.mcp",
        "note",
        &serde_json::json!({"title": "Floor note"})
            .as_object()
            .unwrap()
            .clone(),
        &home,
    )
    .await
    .unwrap();
    call_as(
        &world,
        admin,
        "update_record",
        json!({"id": note_id, "body_set": "owner floor passage here"}),
    )
    .await
    .expect("floor body set");
    call_as(
        &world,
        admin,
        "create_record",
        json!({
            "type": "Annotation", "kind": "comment", "body": "Floor remark.",
            "links": [{"target_id": note_id, "relationship": "part_of"}],
            "target": {
                "target_record_id": note_id, "source_slot": "body",
                "selectors": [{"type": "text_quote", "exact": "floor"}],
            },
        }),
    )
    .await
    .unwrap();
    // The viewer holds nothing here: note and thread are missing on the
    // record path, the SQL path, the query path, and full-text search.
    let hidden = call(
        &world,
        "get_record",
        json!({"ids": [note_id], "include_comments": true}),
    )
    .await
    .unwrap();
    assert_eq!(hidden["records"][0]["status"], "not_found");
    let staged = call(
        &world,
        "query_sql",
        json!({"sql": "SELECT id FROM records WHERE id = ?1", "parameters": [{"type": "text", "value": note_id}]}),
    )
    .await
    .unwrap();
    assert_eq!(staged["rows"], json!([]), "{staged:#}");
    let sought = call(
        &world,
        "query_record",
        json!({"steps": [{"step": "filter", "ids": [note_id]}]}),
    )
    .await
    .unwrap();
    assert!(!sought.to_string().contains(&note_id), "{sought:#}");
    let found = call(&world, "search", json!({"query": "floor"}))
        .await
        .unwrap();
    assert!(!found.to_string().contains(&note_id), "{found:#}");
    // The note owner reads the thread on every path by owner floor alone:
    // record with comments, staged rows, query hits, search hits, links.
    let seen = call_as(
        &world,
        admin,
        "get_record",
        json!({"ids": [note_id], "include_comments": true}),
    )
    .await
    .unwrap();
    assert_eq!(seen["records"][0]["comment_count"], 1);
    assert_eq!(seen["records"][0]["comments"][0]["body"], "Floor remark.");
    let staged = call_as(
        &world,
        admin,
        "query_sql",
        json!({"sql": "SELECT id FROM records WHERE id = ?1", "parameters": [{"type": "text", "value": note_id}]}),
    )
    .await
    .unwrap();
    assert_eq!(staged["rows"], json!([{"id": note_id}]), "{staged:#}");
    let sought = call_as(
        &world,
        admin,
        "query_record",
        json!({"steps": [{"step": "filter", "ids": [note_id]}]}),
    )
    .await
    .unwrap();
    assert!(sought.to_string().contains(&note_id), "{sought:#}");
    let found = call_as(&world, admin, "search", json!({"query": "floor"}))
        .await
        .unwrap();
    assert!(found.to_string().contains(&note_id), "{found:#}");
    let links = call_as(
        &world,
        admin,
        "manage_links",
        json!({"action": "list", "record_id": note_id}),
    )
    .await
    .unwrap();
    assert!(links["returned"].as_u64().unwrap_or(0) >= 1, "{links:#}");
    world.db.close().await;
}

#[tokio::test]
async fn kernel_v2_comment_visibility_follows_target_and_replay_rebuilds() {
    let world = world().await;
    install_comment_carrier(&world).await;
    let admin = "acct:admin";
    call_as(
        &world,
        admin,
        "update_record",
        json!({"id": world.hidden, "body_set": "original secret text"}),
    )
    .await
    .unwrap();
    call_as(
        &world,
        admin,
        "create_record",
        json!({
            "type": "Annotation", "kind": "comment", "body": "Secret remark.",
            "links": [{"target_id": world.hidden, "relationship": "part_of"}],
            "target": anchored_target(&world.hidden, "secret", 9, 15),
        }),
    )
    .await
    .unwrap();
    // The hidden note reads as missing, with or without comments: the same
    // refusal either way, so no comment leaks through the listing.
    for args in [
        json!({"ids": [world.hidden]}),
        json!({"ids": [world.hidden], "include_comments": true}),
    ] {
        let hidden = call(&world, "get_record", args).await.unwrap();
        assert_eq!(hidden["records"][0]["status"], "not_found");
    }
    let seen = call_as(
        &world,
        admin,
        "get_record",
        json!({"ids": [world.hidden], "include_comments": true}),
    )
    .await
    .unwrap();
    assert_eq!(seen["records"][0]["comment_count"], 1);
    assert_eq!(seen["records"][0]["comments"][0]["body"], "Secret remark.");
    // Replay rebuilds the thread, the anchor, and the bearer link exactly.
    let before = kernel::dump_all_kernel_tables(&world.db).await.unwrap();
    kernel::replay_all_projections(&world.db).await.unwrap();
    let after = kernel::dump_all_kernel_tables(&world.db).await.unwrap();
    assert_eq!(before, after);
    assert_eq!(before.comment_anchors.len(), 1);
    let relisted = call_as(
        &world,
        admin,
        "get_record",
        json!({"ids": [world.hidden], "include_comments": true}),
    )
    .await
    .unwrap();
    assert_eq!(
        relisted["records"][0]["comments"][0]["body"],
        "Secret remark."
    );
    world.db.close().await;
}

#[tokio::test]
async fn kernel_v2_registry_reads_shapes_and_visibility() {
    let world = world().await;
    let before = kernel::dump_all_kernel_tables(&world.db).await.unwrap();
    let result = call(
        &world,
        "get_record",
        json!({"ids": [world.first, world.hidden, "missing"], "run_key": "scout-chair-a748b2"}),
    )
    .await
    .unwrap();
    assert_eq!(result["records"][0]["status"], "found");
    assert_eq!(result["records"][0]["type"], "Document");
    assert_eq!(result["records"][0]["name"], "Alpha");
    assert_eq!(result["records"][0]["body"], "revised");
    assert!(result["records"][0]["created_at"].is_string());
    assert_eq!(result["records"][0]["links_out_count"], 1);
    assert_eq!(
        result["records"][0]["links_out"][0]["source_id"],
        world.first
    );
    assert_eq!(
        result["records"][0]["links_out"][0]["target_id"],
        world.second
    );
    assert_eq!(
        result["records"][0]["links_out"][0]["relationship"],
        "relates_to"
    );
    let links_page = call(
        &world,
        "get_record",
        json!({"ids": [world.first], "links_limit": 0, "links_offset": 1}),
    )
    .await
    .unwrap();
    assert_eq!(links_page["records"][0]["links_out"], json!([]));
    assert_eq!(links_page["records"][0]["links_out_count"], 1);

    assert_eq!(
        result["records"][0]["owner_id"],
        Value::Null,
        "viewer cannot see root directory attribution"
    );
    assert_eq!(
        result["records"][1],
        json!({"id": world.hidden, "status": "not_found"})
    );
    assert_eq!(
        result["records"][2],
        json!({"id": "missing", "status": "not_found"})
    );
    assert_eq!(result["run_context"]["run_key"], "scout-chair-a748b2");
    let short = call(&world, "get_record", json!({"ids": [&world.first[..8]]}))
        .await
        .unwrap();
    assert_eq!(short["records"][0]["id"], world.first);
    let query = call(&world, "query_record", json!({"steps": [{"step": "filter", "types": ["Document"], "kinds": ["note"]}], "limit": 1})).await.unwrap();
    assert_eq!(query["shape"], "records");
    assert_eq!(query["total"], 2);
    assert_eq!(query["returned"], 1);
    assert_eq!(query["has_more"], true);
    let second_page = call(
        &world,
        "query_record",
        json!({"steps": [{"step": "filter"}], "offset": 1, "limit": 1}),
    )
    .await
    .unwrap();
    assert_ne!(query["records"][0]["id"], second_page["records"][0]["id"]);
    assert_eq!(second_page["has_more"], false);
    let linked = call(&world, "query_record", json!({"steps": [
        {"step": "filter", "ids": [world.first]},
        {"step": "traverse", "target": "links", "relationship": "relates_to", "direction": "out"},
        {"step": "filter", "types": ["Document"]}
    ]})).await.unwrap();
    assert_eq!(linked["records"].as_array().unwrap().len(), 1);
    assert_eq!(linked["records"][0]["id"], world.second);
    let history = call(
        &world,
        "get_history",
        json!({"record_id": world.first, "limit": 1}),
    )
    .await
    .unwrap();
    assert_eq!(history["events"].as_array().unwrap().len(), 1);
    assert!(history["events"][0]["local_seq"].is_i64());
    assert_eq!(history["events"][0]["type"], "record.created");
    assert_eq!(history["events"][0]["actor"], Value::Null);
    assert_eq!(history["events"][0]["actor_name"], Value::Null);
    assert!(uuid::Uuid::parse_str(history["events"][0]["id"].as_str().unwrap()).is_ok());
    let own_history = registry()
        .call_engine(
            EngineHandle::KernelV2(world.db.clone()),
            Caller::authenticated("acct:admin"),
            "get_history",
            json!({"record_id": world.first}),
        )
        .await
        .unwrap();
    assert_eq!(own_history["events"][0]["actor"], world.admin);
    assert_eq!(own_history["events"][0]["actor_name"], "Admin");

    let next = call(&world, "get_history", json!({"record_id": world.first, "after_local_seq": history["next_after_local_seq"], "order": "oldest_first"})).await.unwrap();
    assert!(next["events"][0]["local_seq"].as_i64() > history["events"][0]["local_seq"].as_i64());
    assert!(next["next_after_local_seq"].is_null());
    for id in [&world.hidden, "missing"] {
        let error = call(&world, "get_history", json!({"record_id": id}))
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            Error::engine(format!("get_history: record {id} does not exist")).to_string()
        );
    }
    // Both transport representations use the existing renderer/JSON payload.
    for (name, value) in [
        ("get_record", result),
        ("query_record", query),
        ("get_history", history),
    ] {
        let text = render::render(name, &value).unwrap();
        assert!(!text.is_empty());
        assert!(!text.contains("Secret"));
        assert_eq!(
            serde_json::from_str::<Value>(&serde_json::to_string(&value).unwrap()).unwrap(),
            value
        );
    }
    assert_eq!(
        before,
        kernel::dump_all_kernel_tables(&world.db).await.unwrap(),
        "reads must append nothing"
    );
    // Keep fixture identities alive to exercise two real principals, not bypass.
    assert_ne!(world.admin, world.viewer);
    world.db.close().await;
}

#[tokio::test]
async fn kernel_v2_unknown_callers_and_unsupported_options_refuse() {
    let world = world().await;
    let registry = registry();
    for (name, args) in [
        ("get_record", json!({"ids": [world.first]})),
        ("query_record", json!({"steps": [{"step": "filter"}]})),
        ("get_history", json!({"record_id": world.first})),
    ] {
        let err = registry
            .call_engine(
                EngineHandle::KernelV2(world.db.clone()),
                Caller::authenticated("unknown"),
                name,
                args,
            )
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("no principal auth_binding"),
            "{err}"
        );
    }
    let before = kernel::dump_all_kernel_tables(&world.db).await.unwrap();
    for binding in [
        kernel::HOST_IMPORT_BINDING,
        kernel::relates_to_port::HOST_TRANSFORM_BINDING,
        "host:not-created",
    ] {
        assert!(
            kernel::resolve_caller_principal_by_binding(&world.db, binding)
                .await
                .unwrap_err()
                .to_string()
                .contains("host bindings")
        );
        for (name, args) in [
            ("get_record", json!({"ids":[world.first]})),
            (
                "create_record",
                json!({"type":"Document","kind":"note","name":"forbidden host write"}),
            ),
            ("bootstrap", json!({})),
        ] {
            let error = registry
                .call_engine(
                    EngineHandle::KernelV2(world.db.clone()),
                    Caller::authenticated(binding),
                    name,
                    args,
                )
                .await
                .unwrap_err();
            assert!(
                error.to_string().contains("host bindings"),
                "{binding} {name}: {error}"
            );
        }
    }
    assert_eq!(
        before,
        kernel::dump_all_kernel_tables(&world.db).await.unwrap()
    );
    for (name, args) in [
        (
            "get_record",
            json!({"ids": [world.first], "include_interpretation": true}),
        ),
        (
            "get_record",
            json!({"ids": [world.first], "as_of": {"event_seq": 1}}),
        ),
        (
            "query_record",
            json!({"steps": [{"step": "filter", "name_regex": "Alpha"}]}),
        ),
        (
            "query_record",
            json!({"steps": [{"step": "filter"}], "count_by": "type"}),
        ),
        (
            "query_record",
            json!({"steps": [{"step": "filter"}], "order": "name"}),
        ),
        (
            "get_history",
            json!({"record_id": world.first, "detail": "unknown"}),
        ),
        (
            "get_history",
            json!({"for_run": "scout-chair-a748b2", "unsupported_history_option": true}),
        ),
    ] {
        let error = call(&world, name, args).await.unwrap_err();
        assert!(error.to_string().contains("unsupported"), "{error}");
    }
    // Frozen app queries now use v1 facet predicates; an absent value yields
    // an empty result rather than an unsupported-option refusal.
    let filtered = call(
        &world,
        "query_record",
        json!({"steps": [{"step": "filter", "facets": [{"key": "title", "eq": "Alpha"}]}]}),
    )
    .await
    .unwrap();
    assert_eq!(filtered["records"], json!([]));
    let error = call(
        &world,
        "create_record",
        json!({"type": "Document", "kind": "note", "name": "write"}),
    )
    .await
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("kernel target missing or hidden"),
        "{error}"
    );
    world.db.close().await;
}

#[tokio::test]
async fn kernel_v2_v1_read_envelope_parity() {
    let world = world().await;
    let db = crate::create_database(":memory:").await.unwrap();
    let registry = registry();
    let id = uuid::Uuid::new_v4().to_string();
    registry.call(db.clone(), Caller::local(), "create_record", json!({
        "id": id, "type": "Document", "kind": "note", "name": "Alpha", "body": "revised", "reason": "shape fixture"
    })).await.unwrap();
    let old = registry
        .call(
            db.clone(),
            Caller::local(),
            "get_record",
            json!({"ids": [id, "missing"]}),
        )
        .await
        .unwrap();
    let new = call(
        &world,
        "get_record",
        json!({"ids": [world.first, "missing"]}),
    )
    .await
    .unwrap();
    for key in ["status", "type", "kind", "name", "body"] {
        assert_eq!(old["records"][0][key], new["records"][0][key], "{key}");
    }
    assert_eq!(old["records"][1], new["records"][1]);
    let args = json!({"steps": [{"step": "filter", "types": ["Document"], "kinds": ["note"]}], "limit": 1});
    let old = registry
        .call(db.clone(), Caller::local(), "query_record", args.clone())
        .await
        .unwrap();
    let new = call(&world, "query_record", args).await.unwrap();
    for key in ["shape", "returned", "offset"] {
        assert_eq!(old[key], new[key], "{key}");
    }
    for key in [
        "id",
        "type",
        "kind",
        "name",
        "body",
        "home_id",
        "owner_id",
        "created_at",
        "updated_at",
    ] {
        assert!(old["records"][0].get(key).is_some(), "v1 {key}");
        assert!(new["records"][0].get(key).is_some(), "v2 {key}");
    }
    let old = registry
        .call(
            db.clone(),
            Caller::local(),
            "get_history",
            json!({"record_id": id}),
        )
        .await
        .unwrap();
    let new = call(&world, "get_history", json!({"record_id": world.first}))
        .await
        .unwrap();
    for key in [
        "local_database_id",
        "events",
        "next_after_local_seq",
        "order",
        "representation",
    ] {
        assert!(old.get(key).is_some(), "v1 {key}");
        assert!(new.get(key).is_some(), "v2 {key}");
    }
    for key in [
        "local_seq",
        "id",
        "record_id",
        "type",
        "actor",
        "actor_name",
        "created_at",
        "run_key",
        "parent_key",
        "intent",
        "causal_envelope",
        "payload_omitted",
        "payload_json_utf8_bytes",
        "changed_fields",
    ] {
        assert!(old["events"][0].get(key).is_some(), "v1 {key}");
        assert!(new["events"][0].get(key).is_some(), "v2 {key}");
    }
    db.drain_captures().await;
    db.close().await;
    world.db.close().await;
}

#[tokio::test]
async fn kernel_v2_stdio_text_and_json_use_ordinary_tools() {
    let world = world().await;
    let server = crate::mcp::stdio::StdioServer::new(
        std::sync::Arc::new(registry()),
        EngineHandle::KernelV2(world.db.clone()),
        Caller::authenticated("acct:viewer"),
    );
    for (name, args) in [
        ("get_record", json!({"ids": [world.first]})),
        (
            "query_record",
            json!({"steps": [{"step": "filter", "types": ["Document"]}]}),
        ),
        ("get_history", json!({"record_id": world.first})),
    ] {
        for format in ["text", "json"] {
            let mut args = args.clone();
            args["format"] = json!(format);
            let request = format!(
                "{}\n",
                json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args}})
            );
            let mut output = Vec::new();
            server
                .serve(tokio::io::BufReader::new(request.as_bytes()), &mut output)
                .await
                .unwrap();
            let response: Value = serde_json::from_slice(&output).unwrap();
            assert!(response.get("error").is_none(), "{response}");
            assert_ne!(response["result"]["isError"], true, "{response}");
            let text = response["result"]["content"][0]["text"].as_str().unwrap();
            assert!(!text.is_empty());
            assert!(!text.contains("Secret"));
            if format == "text" && name == "get_history" {
                assert!(text.contains("unavailable"), "{text}");
                assert!(!text.contains("Request detail"), "{text}");
            }
            if format == "json" {
                let payload: Value = serde_json::from_str(text).unwrap();
                assert!(
                    payload
                        .get(if name == "get_history" {
                            "events"
                        } else {
                            "records"
                        })
                        .is_some(),
                    "{payload}"
                );
                assert_eq!(response["result"]["structuredContent"], payload);
            }
        }
    }
    world.db.close().await;
}

#[test]
fn kernel_v2_compat_type_kind_uses_bound_v1_carrier() {
    let fields = json!({"v1_type": "WorkItem", "v1_kind": "task", "title": "Carried task"});
    let fields = fields.as_object().unwrap();
    assert_eq!(
        v1_type_and_kind(
            Some("native.v1.record"),
            Some(1),
            Some("V1"),
            Some("record"),
            fields
        ),
        (Some("WorkItem"), Some("task"))
    );
    // Matching fields alone cannot relabel an unrelated or future definition.
    assert_eq!(
        v1_type_and_kind(
            Some("fixture.mcp"),
            Some(1),
            Some("Document"),
            Some("note"),
            fields
        ),
        (Some("Document"), Some("note"))
    );
    assert_eq!(
        v1_type_and_kind(
            Some("native.v1.record"),
            Some(2),
            Some("V1"),
            Some("record"),
            fields
        ),
        (Some("V1"), Some("record"))
    );
    assert_eq!(
        v1_type_and_kind(
            Some("native.standard.document"),
            Some(3),
            Some("Document"),
            Some("note"),
            &serde_json::Map::new()
        ),
        (Some("Document"), Some("note"))
    );
}

async fn revision_of(world: &World, id: &str) -> i64 {
    kernel::read_record_as(&world.db, &world.admin, id)
        .await
        .unwrap()
        .unwrap()
        .revision
}

#[tokio::test]
async fn kernel_v2_search_finds_title_field_body_and_lane_body() {
    let world = world().await;
    // A lane body alongside the body field: both are indexed.
    kernel::hq::set_body_as(
        &world.db,
        &world.admin,
        &world.first,
        "quetzal lane body",
        revision_of(&world, &world.first).await,
    )
    .await
    .unwrap();
    // Title word.
    let hits = call(&world, "search", json!({"query": "Alpha"}))
        .await
        .unwrap();
    assert_eq!(hits["total"], 1);
    assert_eq!(hits["hits"][0]["id"], world.first);
    assert_eq!(hits["hits"][0]["type"], "Document");
    assert_eq!(hits["hits"][0]["kind"], "note");
    assert_eq!(hits["hits"][0]["name"], "Alpha");
    assert!(hits["hits"][0]["score"].is_number());
    assert!(!hits["hits"][0]["snippet"].as_str().unwrap().is_empty());
    assert_eq!(hits["limit"], 20);
    assert_eq!(hits["limit_reached"], false);
    // Body-field word ("revised" is Alpha's body field).
    let hits = call(&world, "search", json!({"query": "revised"}))
        .await
        .unwrap();
    assert!(hits["hits"]
        .as_array()
        .unwrap()
        .iter()
        .any(|h| h["id"] == world.first));
    // Lane-body word.
    let hits = call(&world, "search", json!({"query": "quetzal"}))
        .await
        .unwrap();
    assert_eq!(hits["total"], 1);
    assert_eq!(hits["hits"][0]["id"], world.first);
    // A caller-set cap above the v1 maximum clamps to 200.
    let hits = call(&world, "search", json!({"query": "Alpha", "limit": 500}))
        .await
        .unwrap();
    assert_eq!(hits["limit"], 200);
    let text = render::render("search", &hits).unwrap();
    assert!(!text.is_empty());
    assert!(!text.contains("Secret"));
    world.db.close().await;
}

#[tokio::test]
async fn kernel_v2_search_hides_hidden_records_from_counts() {
    let world = world().await;
    // "original" is the body field of Beta (visible) and Secret (hidden).
    let hits = call(&world, "search", json!({"query": "original"}))
        .await
        .unwrap();
    assert_eq!(hits["total"], 1, "hidden matches must not count");
    assert_eq!(hits["returned"], 1);
    assert_eq!(hits["hits"][0]["id"], world.second);
    assert!(!serde_json::to_string(&hits).unwrap().contains("Secret"));
    assert!(!serde_json::to_string(&hits)
        .unwrap()
        .contains(&world.hidden));
    // The record owner sees both, proving the hidden row is indexed.
    let admin_hits = registry()
        .call_engine(
            EngineHandle::KernelV2(world.db.clone()),
            Caller::authenticated("acct:admin"),
            "search",
            json!({"query": "original"}),
        )
        .await
        .unwrap();
    assert_eq!(admin_hits["total"], 2);
    world.db.close().await;
}

#[tokio::test]
async fn kernel_v2_search_archived_excluded_unless_asked() {
    let world = world().await;
    kernel::hq::set_archived_as(
        &world.db,
        &world.admin,
        &world.second,
        true,
        revision_of(&world, &world.second).await,
    )
    .await
    .unwrap();
    let hits = call(&world, "search", json!({"query": "Beta"}))
        .await
        .unwrap();
    assert_eq!(hits["total"], 0);
    assert_eq!(hits["hits"], json!([]));
    let hits = call(
        &world,
        "search",
        json!({"query": "Beta", "include_archived": true}),
    )
    .await
    .unwrap();
    assert_eq!(hits["total"], 1);
    assert_eq!(hits["hits"][0]["id"], world.second);
    world.db.close().await;
}

#[tokio::test]
async fn kernel_v2_search_rejects_scope_and_bad_arguments() {
    let world = world().await;
    for args in [
        json!({"query": "Alpha", "scope": [world.first]}),
        json!({"query": "Alpha", "nope": true}),
    ] {
        let error = call(&world, "search", args).await.unwrap_err();
        assert!(error.to_string().contains("unsupported"), "{error}");
    }
    for args in [
        json!({"query": "   "}),
        json!({"query": "Alpha", "limit": 0}),
    ] {
        call(&world, "search", args).await.unwrap_err();
    }
    world.db.close().await;
}

#[tokio::test]
async fn kernel_v2_bounded_query_reads_scale_with_limit() {
    let world = world().await;
    let home = kernel::read_record_as(&world.db, &world.admin, &world.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    for i in 0..30 {
        kernel::create_as(
            &world.db,
            &world.admin,
            "fixture.mcp",
            "note",
            json!({"title": format!("Bulk {i:02}")})
                .as_object()
                .unwrap(),
            &home,
        )
        .await
        .unwrap();
    }
    let groups = kernel::search_v2::distinct_groups(&world.db).await.unwrap();
    assert_eq!(
        groups,
        vec![("fixture.mcp".to_string(), "note".to_string())]
    );
    // Direct bounded call with a per-call counter: 32 visible records, page
    // of 2, exactly one scan page, one bulk field read, one bulk revision
    // read, and zero body reads.
    let counters = kernel::search_v2::S7aCounters::default();
    let page = kernel::search_v2::bounded_query_as(
        &world.db,
        &world.viewer,
        &groups,
        None,
        Some(&["Document".to_string()]),
        Some(&["note".to_string()]),
        None,
        2,
        0,
        &counters,
    )
    .await
    .unwrap();
    assert_eq!(page.total, 32);
    assert_eq!(page.records.len(), 2);
    assert_ne!(page.records[0].id, page.records[1].id);
    assert_eq!(counters.snapshot(), (1, 1, 0, 1));
    // A far offset still reports the exact total with the same read shape.
    let counters = kernel::search_v2::S7aCounters::default();
    let far = kernel::search_v2::bounded_query_as(
        &world.db,
        &world.viewer,
        &groups,
        None,
        Some(&["Document".to_string()]),
        Some(&["note".to_string()]),
        None,
        2,
        30,
        &counters,
    )
    .await
    .unwrap();
    assert_eq!(far.total, 32);
    assert_eq!(far.records.len(), 2);
    assert_eq!(counters.snapshot(), (1, 1, 0, 1));
    // Through the registry: same totals, v1-shaped envelope, no hidden leak.
    let query = call(
        &world,
        "query_record",
        json!({"steps": [{"step": "filter", "types": ["Document"], "kinds": ["note"]}], "limit": 2}),
    )
    .await
    .unwrap();
    assert_eq!(query["shape"], "records");
    assert_eq!(query["total"], 32);
    assert_eq!(query["returned"], 2);
    assert_eq!(query["has_more"], true);
    assert!(!serde_json::to_string(&query).unwrap().contains("Secret"));
    world.db.close().await;
}

#[tokio::test]
async fn kernel_v2_bounded_query_survives_hq_scale_groups() {
    let world = world().await;
    let visible_home = kernel::read_record_as(&world.db, &world.admin, &world.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let hidden_home = kernel::read_record_as(&world.db, &world.admin, &world.hidden)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    // One (family, kind) group past the old 5000-row scan bound: 200 records
    // the viewer sees, 5000 it must never observe.
    for n in 0..200 {
        kernel::create_as(
            &world.db,
            &world.admin,
            "fixture.mcp",
            "note",
            json!({"title": format!("Bulk visible {n:03}")})
                .as_object()
                .unwrap(),
            &visible_home,
        )
        .await
        .unwrap();
    }
    async fn hidden_bulk(world: &World, home: &str, from: usize, count: usize) {
        for n in from..from + count {
            kernel::create_as(
                &world.db,
                &world.admin,
                "fixture.mcp",
                "note",
                json!({"title": format!("Bulk hidden {n:05}")})
                    .as_object()
                    .unwrap(),
                home,
            )
            .await
            .unwrap();
        }
    }
    hidden_bulk(&world, &hidden_home, 0, 5000).await;
    let probe = json!({"steps": [{"step": "filter", "types": ["Document"], "kinds": ["note"]}], "limit": 2});
    let first = call(&world, "query_record", probe.clone()).await.unwrap();
    assert_eq!(first["total"], 202);
    assert_eq!(first["returned"], 2);
    assert_eq!(first["has_more"], true);
    // Growing the hidden count changes nothing visible: same total, same page.
    hidden_bulk(&world, &hidden_home, 5000, 500).await;
    let second = call(&world, "query_record", probe).await.unwrap();
    assert_eq!(second["total"], 202);
    assert_eq!(second["records"], first["records"]);
    let text = serde_json::to_string(&second).unwrap();
    assert!(!text.contains("Secret"));
    assert!(!text.contains("Bulk hidden"));
    // The counting walk stays cheap: one visible page, bulk hydration only.
    let groups = kernel::search_v2::distinct_groups(&world.db).await.unwrap();
    let counters = kernel::search_v2::S7aCounters::default();
    let page = kernel::search_v2::bounded_query_as(
        &world.db,
        &world.viewer,
        &groups,
        None,
        Some(&["Document".to_string()]),
        Some(&["note".to_string()]),
        None,
        2,
        0,
        &counters,
    )
    .await
    .unwrap();
    assert_eq!(page.total, 202);
    assert_eq!(counters.snapshot(), (1, 1, 0, 1));
    // Search sees only the visible slice of the same group.
    let hits = call(
        &world,
        "search",
        json!({"query": "Bulk visible", "limit": 200}),
    )
    .await
    .unwrap();
    assert_eq!(hits["total"], 200);
    world.db.close().await;
}

#[tokio::test]
async fn kernel_v2_hidden_bare_record_keeps_viewer_answers() {
    let world = world().await;
    let probe = json!({"steps": [{"step": "filter"}], "limit": 10});
    let before = call(&world, "query_record", probe.clone()).await.unwrap();
    assert_eq!(before["total"], 2);
    // Admin plants a bare record where the viewer cannot see it: the
    // identical viewer query must stay an identical Ok, not a refusal.
    let hidden_home = kernel::read_record_as(&world.db, &world.admin, &world.hidden)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    kernel::create_record_as(&world.db, &world.admin, &hidden_home)
        .await
        .unwrap();
    let after = call(&world, "query_record", probe).await.unwrap();
    assert_eq!(after, before);
    world.db.close().await;
}

#[tokio::test]
async fn kernel_v2_search_index_rebuilt_by_replay() {
    let world = world().await;
    let before = call(&world, "search", json!({"query": "Alpha"}))
        .await
        .unwrap();
    assert_eq!(before["total"], 1);
    sqlx::query("DELETE FROM kernel_search_fts")
        .execute(world.db.write_pool())
        .await
        .unwrap();
    let gone = call(&world, "search", json!({"query": "Alpha"}))
        .await
        .unwrap();
    assert_eq!(gone["total"], 0);
    kernel::replay_all_projections(&world.db).await.unwrap();
    let back = call(&world, "search", json!({"query": "Alpha"}))
        .await
        .unwrap();
    assert_eq!(back["total"], 1);
    assert_eq!(back["hits"][0]["id"], world.first);
    world.db.close().await;
}

#[tokio::test]
async fn kernel_v2_search_backfills_databases_predating_the_index() {
    let world = world().await;
    // Simulate a database from before the probe schema existed.
    sqlx::query("DROP TABLE kernel_search_fts")
        .execute(world.db.write_pool())
        .await
        .unwrap();
    sqlx::query("DROP INDEX IF EXISTS idx_kernel_records_family_kind_accession")
        .execute(world.db.write_pool())
        .await
        .unwrap();
    let gone = call(&world, "search", json!({"query": "Alpha"})).await;
    assert!(
        gone.is_err(),
        "reads never create the index; the open path must"
    );
    // The open path ensures the schema and backfills pre-existing records.
    kernel::ensure_search_index(&world.db).await.unwrap();
    let back = call(&world, "search", json!({"query": "Alpha"}))
        .await
        .unwrap();
    assert_eq!(back["total"], 1);
    assert_eq!(back["hits"][0]["id"], world.first);
    // Second call is a no-op on a current database.
    kernel::ensure_search_index(&world.db).await.unwrap();
    // A stale version marker rebuilds too (the lazy era wrote no marker).
    sqlx::query("UPDATE kernel_search_meta SET version = 0")
        .execute(world.db.write_pool())
        .await
        .unwrap();
    kernel::ensure_search_index(&world.db).await.unwrap();
    let again = call(&world, "search", json!({"query": "Alpha"}))
        .await
        .unwrap();
    assert_eq!(again["total"], 1);
    world.db.close().await;
}

#[tokio::test]
async fn kernel_v2_search_matches_terms_across_fields() {
    let world = world().await;
    // "Alpha" lives in the title, "revised" in the body field: v1 semantics
    // match terms anywhere in the document, not per column.
    let hits = call(&world, "search", json!({"query": "Alpha revised"}))
        .await
        .unwrap();
    assert_eq!(hits["total"], 1);
    assert_eq!(hits["hits"][0]["id"], world.first);
    let none = call(&world, "search", json!({"query": "Alpha zebra"}))
        .await
        .unwrap();
    assert_eq!(none["total"], 0);
    world.db.close().await;
}

#[tokio::test]
async fn kernel_v2_query_survives_malformed_policy_entries() {
    let world = world().await;
    // Fresh home + record, both API-made and viewer-visible.
    let home = kernel::create_home(
        &world.db,
        KERNEL_ROOT_ID,
        Some(&[(world.viewer.as_str(), "view")]),
        &world.admin,
    )
    .await
    .unwrap();
    let id = kernel::create_as(
        &world.db,
        &world.admin,
        "fixture.mcp",
        "note",
        json!({"title": "Fragile record"}).as_object().unwrap(),
        &home,
    )
    .await
    .unwrap();
    let visible = json!({"steps": [{"step": "filter", "types": ["Document"]}], "limit": 10});
    let before = call(&world, "query_record", visible.clone()).await.unwrap();
    assert_eq!(before["total"], 3);
    // Poison this home's anchor with a malformed entry: evaluation fails,
    // so its records must read as hidden — without failing the whole call.
    sqlx::query("INSERT OR IGNORE INTO kernel_policies(root_id, created_at) VALUES(?, '2026-10-17T00:00:00Z')")
        .bind(&home)
        .execute(world.db.write_pool())
        .await
        .unwrap();
    sqlx::query("INSERT INTO kernel_policy_entries(root_id, subject_kind, subject_id, effect, capability) VALUES(?, 'bogus', 'x', 'bogus', 'view')")
        .bind(&home)
        .execute(world.db.write_pool())
        .await
        .unwrap();
    let after = call(&world, "query_record", visible).await.unwrap();
    assert_eq!(after["total"], 2);
    assert!(!serde_json::to_string(&after).unwrap().contains("Fragile"));
    // The owner sees the same exclusion, not an error either.
    let admin_after = registry()
        .call_engine(
            EngineHandle::KernelV2(world.db.clone()),
            Caller::authenticated("acct:admin"),
            "query_record",
            json!({"steps": [{"step": "filter", "types": ["Document"]}], "limit": 10}),
        )
        .await
        .unwrap();
    assert_eq!(admin_after["total"], 3);
    assert!(!serde_json::to_string(&admin_after)
        .unwrap()
        .contains("Fragile"));
    assert!(!serde_json::to_string(&admin_after).unwrap().contains(&id));
    world.db.close().await;
}
// Included under this module so the existing probe CI filter executes S6 proofs.
#[path = "coordination_tests.rs"]
mod coordination;
#[tokio::test]
async fn kernel_v2_sql_hq_scale_stages_only_needed_values() {
    let w = world().await;
    // Bulk fixture setup deliberately avoids 10k unrelated admission/event writes.
    sqlx::query("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<10000) INSERT INTO kernel_records(id,home_id,owner_id,created_seq,created_at) SELECT printf('scale:%05d',x),r.home_id,r.owner_id,r.created_seq,r.created_at FROM n CROSS JOIN kernel_records r WHERE r.id=?")
        .bind(&w.first).execute(w.db.write_pool()).await.unwrap();
    // Complete the deliberately raw, pre-metadata bulk fixture as startup does.
    kernel::ensure_record_metadata(&w.db).await.unwrap();
    let started = std::time::Instant::now();
    let (pulse, pulse_stats) = super::sql::measured(call(
        &w,
        "query_sql",
        json!({"sql":"SELECT id, updated_at FROM records WHERE id IN (?1,?2)",
            "parameters":[{"type":"text","value":w.first},{"type":"text","value":w.hidden}]}),
    ))
    .await;
    assert_eq!(pulse.unwrap()["row_count"], 1);
    assert_eq!(pulse_stats.staged_records, 1);
    assert_eq!(pulse_stats.staged_relations, 1);
    assert!(pulse_stats.staging_vm_ops < 250_000, "{pulse_stats:?}");
    let (wide, wide_stats) = super::sql::measured(call(
        &w, "query_sql", json!({"sql":"SELECT id, type, kind, name, summary, home_id, lifecycle, maturity, updated_at, last_activity_at FROM records WHERE deleted_at IS NULL AND id IN (?1,?2)",
            "parameters":[{"type":"text","value":w.first},{"type":"text","value":w.hidden}]}),
    )).await;
    assert_eq!(wide.unwrap()["row_count"], 1);
    assert!(wide_stats.staged_records <= 2, "{wide_stats:?}");
    assert_eq!(wide_stats.staged_relations, 1);
    assert!(wide_stats.staging_vm_ops < 250_000, "{wide_stats:?}");
    let (out, stats) = super::sql::measured(call(
        &w,
        "query_sql",
        json!({"sql":"SELECT id FROM records ORDER BY id LIMIT 5"}),
    ))
    .await;
    let elapsed = started.elapsed();
    assert_eq!(out.unwrap()["row_count"], 5);
    assert_eq!(
        stats.staged_records, 5,
        "closed ID prefixes stage only the returned visible window"
    );
    assert_eq!(stats.staged_metadata_records, 0);
    assert_eq!(stats.staged_relations, 1);
    assert_eq!(stats.home_checks, 3);
    // A deterministic VM work bound, rather than shared-host wall-clock timing.
    // Also proves the progress handler was already active during staging.
    assert!(
        stats.staging_vm_ops > 0 && stats.staging_vm_ops < 1_000_000,
        "{stats:?}"
    );
    eprintln!("S8 HQ-scale: 10000 added records, id LIMIT 5: {elapsed:?}; {stats:?}");
    let (out, stats) = super::sql::measured(call(
        &w,
        "query_sql",
        json!({"sql":"SELECT relation_name FROM catalog_relations ORDER BY relation_name"}),
    ))
    .await;
    let out = out.unwrap();
    // Includes attachment-scoped blobs, typed times, and the caller viewer.
    assert_eq!(out["row_count"], 26);
    let names = out["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["relation_name"].as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        names,
        std::collections::BTreeSet::from([
            "records",
            "blobs",
            "links",
            "runs",
            "run_intents",
            "actors",
            "viewer",
            "comment_anchors",
            "vocabularies",
            "vocabulary_values",
            "record_lifecycle_interpretations",
            "agent_activity",
            "agent_activity_claims",
            "facet_values",
            "facet_observations",
            "facet_times",
            "bindings",
            "content_events",
            "message_reactions",
            "my_mentions",
            "my_message_state",
            "messages_awaiting_reply",
            "catalog_relations",
            "catalog_columns",
            "catalog_operations",
            "catalog_view_definitions",
        ])
    );
    assert_eq!(stats.staged_records, 0);
    assert_eq!(stats.staged_relations, 0);
    assert_eq!(stats.home_checks, 0);
    let started = std::time::Instant::now();
    let listed = kernel::list_records_as(&w.db, &w.viewer).await.unwrap();
    assert_eq!(listed.len(), 10002);
    eprintln!(
        "S8 HQ-scale: list_records_as returns 10002 records in {:?}",
        started.elapsed()
    );
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_sql_saved_inputs_keep_separate_bounded_staging_and_vm_deadlines() {
    use std::time::Duration;
    let w = world().await;
    let request = json!({"sql":"SELECT id FROM records ORDER BY id LIMIT 2"});
    // Deterministic elapsed offsets exercise admission without sleeps or a
    // shared-host timing assertion. Native preparation exceeds the caller VM
    // budget, but remains within the separately bounded saved-input allowance.
    let result = super::sql::with_elapsed(
        Duration::from_secs(3),
        Duration::ZERO,
        super::sql::query_stored_saved_sql(&w.db, &w.viewer, request.clone()),
    )
    .await
    .unwrap();
    assert_eq!(result["row_count"], 2);
    let denied = super::sql::with_elapsed(
        Duration::from_secs(3),
        Duration::ZERO,
        super::sql::query_sql(&w.db, &w.viewer, request.clone()),
    )
    .await
    .unwrap_err();
    assert!(
        denied.to_string().contains("query_sql [timeout]"),
        "{denied}"
    );
    let denied = super::sql::with_elapsed(
        Duration::from_secs(9),
        Duration::ZERO,
        super::sql::query_stored_saved_sql(&w.db, &w.viewer, request),
    )
    .await
    .unwrap_err();
    assert!(
        denied.to_string().contains("query_sql [timeout]"),
        "{denied}"
    );

    sqlx::query("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<20) INSERT INTO kernel_records(id,home_id,owner_id,created_seq,created_at) SELECT printf('vm-bound:%05d',x),r.home_id,r.owner_id,r.created_seq,r.created_at FROM n CROSS JOIN kernel_records r WHERE r.id=?")
        .bind(&w.first).execute(w.db.write_pool()).await.unwrap();
    // A saved query cannot spend the preparation allowance executing caller
    // SQL. The ordinary VM deadline still interrupts its first progress tick.
    let denied = super::sql::with_elapsed(Duration::ZERO, Duration::from_secs(3),
        super::sql::query_stored_saved_sql(&w.db, &w.viewer,
            json!({"sql":"SELECT count(*) AS n FROM records a CROSS JOIN records b CROSS JOIN records c"}))).await.unwrap_err();
    assert!(
        denied.to_string().contains("query_sql [timeout]"),
        "{denied}"
    );
}

#[tokio::test]
async fn kernel_v2_sql_broken_policy_scope_is_omitted_and_diagnosed() {
    let w = world().await;
    let home: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
        .bind(&w.hidden)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    sqlx::query("DELETE FROM kernel_policies WHERE root_id=?")
        .bind(&home)
        .execute(w.db.write_pool())
        .await
        .unwrap();
    sqlx::query("UPDATE kernel_roots SET parent_id=root_id WHERE root_id=?")
        .bind(&home)
        .execute(w.db.write_pool())
        .await
        .unwrap();
    let (out, stats) = super::sql::measured(call(
        &w,
        "query_sql",
        json!({"sql":"SELECT count(*) AS n FROM records"}),
    ))
    .await;
    assert_eq!(out.unwrap()["rows"][0]["n"], 2);
    assert_eq!(stats.failed_homes, 1);
    assert_eq!(
        kernel::list_records_as(&w.db, &w.viewer)
            .await
            .unwrap()
            .len(),
        2
    );
    // Even its owner cannot bypass a broken authority chain.
    let admin = registry()
        .call_engine(
            EngineHandle::KernelV2(w.db.clone()),
            Caller::authenticated("acct:admin"),
            "query_sql",
            json!({"sql":"SELECT count(*) AS n FROM records"}),
        )
        .await
        .unwrap();
    assert_eq!(admin["rows"][0]["n"], 2);
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_sql_existing_database_without_run_owner_index() {
    let mut w = world().await;
    let key = kernel::mint_run_as(&w.db, &w.viewer, None).await.unwrap();
    let context = kernel::open_run_as(&w.db, &w.viewer, &key).await.unwrap();
    kernel::set_run_intent_as(&w.db, &context, "Existing database intent")
        .await
        .unwrap();
    // Simulate an import target created before the optional owner index existed.
    sqlx::query("DROP INDEX idx_kernel_runs_owner")
        .execute(w.db.write_pool())
        .await
        .unwrap();
    w.db.close().await;
    w.db = crate::db::open_database(w._dir.path().join("v2.db").to_str().unwrap())
        .await
        .unwrap();
    for sql in [
        "SELECT run_key FROM runs ORDER BY run_key",
        "SELECT run_key,intent FROM run_intents ORDER BY run_key,ordinal",
    ] {
        let out = call(&w, "query_sql", json!({"sql":sql})).await.unwrap();
        assert_eq!(out["row_count"], 1);
        assert_eq!(out["rows"][0]["run_key"], key);
        if sql.contains("run_intents") {
            assert_eq!(out["rows"][0]["intent"], "Existing database intent");
        }
    }
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_sql_visibility_propagates_database_failures() {
    let w = world().await;
    // Enumeration still works; a subsequent per-home policy read now fails.
    // This must propagate, rather than silently omit every home as malformed.
    sqlx::query("DROP TABLE kernel_policy_entries")
        .execute(w.db.write_pool())
        .await
        .unwrap();
    let mut conn = w.db.write_pool().acquire().await.unwrap();
    let error = match kernel::visible_home_anchors_as(&mut conn, &w.viewer).await {
        Ok(_) => panic!("storage failure was swallowed as a visibility refusal"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        crate::Error::Sqlx(sqlx::Error::Database(_))
    ));
    drop(conn);
    assert!(call(
        &w,
        "query_sql",
        json!({"sql":"SELECT count(*) AS n FROM records"})
    )
    .await
    .is_err());
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_sql_star_and_generic_currency_are_visibility_scoped() {
    let w = world().await;
    let visible = kernel::add_generic_link_as(
        &w.db,
        &w.admin,
        &w.second,
        &w.first,
        "supersedes",
        Some("Visible successor".into()),
    )
    .await
    .unwrap();
    kernel::add_generic_link_as(
        &w.db,
        &w.admin,
        &w.hidden,
        &w.first,
        "supersedes",
        Some("Hidden successor".into()),
    )
    .await
    .unwrap();
    let out = call(
        &w,
        "query_sql",
        json!({"sql":"SELECT * FROM records ORDER BY id LIMIT 5"}),
    )
    .await
    .unwrap();
    assert_eq!(
        out["columns"],
        json!(
            crate::query::sql_contract::LOGICAL_RELATIONS
                .iter()
                .find(|r| r.name == "records")
                .unwrap()
                .columns
        )
    );
    let row = out["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == w.first)
        .unwrap();
    assert_eq!(row["successor_count"], 1);
    assert!(row["is_current"].is_null());
    let out = call(
        &w,
        "query_sql",
        json!({"sql":"SELECT * FROM links WHERE relationship='supersedes' ORDER BY id"}),
    )
    .await
    .unwrap();
    assert_eq!(out["row_count"], 1);
    assert_eq!(out["rows"][0]["id"], visible.link.link_id);
    assert_eq!(out["rows"][0]["note"], "Visible successor");
    assert!(out["rows"][0]["created_at"]
        .as_str()
        .unwrap()
        .ends_with('Z'));
    assert!(out["rows"][0]["created_at_ms"].is_i64());
    let out=call(&w,"query_sql",json!({"sql":"SELECT r.successor_count FROM records r JOIN links l ON l.target_id=r.id WHERE l.relationship='supersedes' ORDER BY r.id"})).await.unwrap();
    assert_eq!(out["rows"][0]["successor_count"], 1);
    kernel::remove_generic_link_as(&w.db, &w.admin, &w.second, &visible.link.link_id)
        .await
        .unwrap();
    let out=call(&w,"query_sql",json!({"sql":"SELECT successor_count,is_current FROM records WHERE id=?1","parameters":[{"type":"text","value":w.first}]})).await.unwrap();
    assert_eq!(out["rows"][0], json!({"successor_count":0,"is_current":1}));
    let events = call(
        &w,
        "query_sql",
        json!({"sql":"SELECT * FROM content_events ORDER BY local_seq LIMIT 5"}),
    )
    .await
    .unwrap();
    assert!(events["columns"]
        .as_array()
        .unwrap()
        .iter()
        .any(|column| column == "channel_kind"));
    for row in events["rows"].as_array().unwrap() {
        assert_ne!(row["record_id"], w.hidden);
        assert!(row["actor"].is_null());
        assert!(row["channel_kind"].is_null());
    }
    // Payloads remain outside the public logical event-header contract.
    let error = call(
        &w,
        "query_sql",
        json!({"sql":"SELECT payload FROM content_events LIMIT 5"}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("syntax_or_type") && error.contains("payload"),
        "{error}"
    );
    w.db.close().await;
}

// Keep the supplied kit's query exact: its otherwise small record read observes
// is_current, including body, logical home and lifecycle alongside metadata.
fn scoped_currency_kit_query(id: &str) -> Value {
    json!({"sql":"SELECT id, name, type, kind, lifecycle, summary, home_id, created_at, updated_at, updated_at_ms, is_current, substr(body, 1, 120000) AS body, length(body) AS body_length FROM records WHERE id = ?1 AND deleted_at IS NULL AND archived = 0 AND type IN (?2, ?3, ?4, ?5, ?6) AND COALESCE(kind, '') NOT IN ('artifact', 'attachment', 'query', 'selection') ORDER BY id ASC LIMIT 1",
        "parameters":[{"type":"text","value":id},{"type":"text","value":"Document"},{"type":"text","value":"Collection"},{"type":"text","value":"Resolution"},{"type":"text","value":"WorkItem"},{"type":"text","value":"Outcome"}]})
}

async fn scoped_currency_pair(
    w: &World,
    credential: &str,
    args: Value,
) -> (Value, super::sql::Stats, super::sql::Stats) {
    let (narrow, stats) =
        super::sql::measured(call_as(w, credential, "query_sql", args.clone())).await;
    let (full, full_stats) = super::sql::measured(super::sql::with_full_record_scope_staging(
        call_as(w, credential, "query_sql", args),
    ))
    .await;
    let narrow = narrow.unwrap();
    let full = full.unwrap();
    for field in ["columns", "rows", "row_count", "truncated", "assumed_order"] {
        assert_eq!(
            narrow[field], full[field],
            "{credential}: {field}; narrow={stats:?}; full={full_stats:?}"
        );
    }
    (narrow, stats, full_stats)
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_scoped_currency_kit_read_stages_only_direct_visible_sources() {
    let w = world().await;
    install_comment_carrier(&w).await;
    let home = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let folder = call_as(
        &w,
        "acct:admin",
        "create_record",
        json!({"type":"Collection","kind":"folder","name":"Currency folder","home_id":home}),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    call_as(
        &w,
        "acct:admin",
        "update_record",
        json!({"id":w.first,"home_id":folder}),
    )
    .await
    .unwrap();
    let mut unrelated = Vec::new();
    for index in 0..32 {
        unrelated.push(
            kernel::create_as(
                &w.db,
                &w.admin,
                "fixture.mcp",
                "note",
                json!({"title":format!("Unrelated {index}")})
                    .as_object()
                    .unwrap(),
                &home,
            )
            .await
            .unwrap(),
        );
    }
    for pair in unrelated.windows(2) {
        kernel::add_generic_link_as(&w.db, &w.admin, &pair[0], &pair[1], "supersedes", None)
            .await
            .unwrap();
    }
    // Hidden source, a successor of the direct source, and a successor of the
    // placement dependency must not widen the one-hop frontier.
    for (source, target) in [
        (&w.second, &w.first),
        (&w.hidden, &w.first),
        (&unrelated[0], &w.second),
        (&unrelated[1], &folder),
    ] {
        kernel::add_generic_link_as(&w.db, &w.admin, source, target, "supersedes", None)
            .await
            .unwrap();
    }
    for (credential, expected_sources) in [("acct:viewer", 1), ("acct:admin", 2)] {
        let (out, stats, full) =
            scoped_currency_pair(&w, credential, scoped_currency_kit_query(&w.first)).await;
        assert_eq!(out["rows"][0]["is_current"], Value::Null);
        assert_eq!(out["rows"][0]["home_id"], folder);
        assert_eq!(stats.staged_currency_records, expected_sources, "{stats:?}");
        assert!(stats.staged_records <= expected_sources + 2, "{stats:?}");
        assert!(full.staged_records >= 35, "{full:?}");
        assert!(
            stats.staged_records < full.staged_records,
            "narrow={stats:?}; full={full:?}"
        );
        eprintln!("scoped currency work {credential}: narrow={stats:?}; full={full:?}");
    }
    // A hidden target never seeds a raw-link frontier, even when a visible
    // source supersedes it. SELECT * also exercises both currency columns.
    kernel::add_generic_link_as(&w.db, &w.admin, &w.second, &w.hidden, "supersedes", None)
        .await
        .unwrap();
    let (out, stats, _) = scoped_currency_pair(&w,"acct:viewer",json!({"sql":"SELECT * FROM records WHERE id=?1","parameters":[{"type":"text","value":w.hidden}]})).await;
    assert_eq!(out["rows"], json!([]));
    assert_eq!(stats.staged_records, 0, "{stats:?}");
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_scoped_currency_cycles_revocation_deletion_and_replay_match_full() {
    let w = world().await;
    let source_home = kernel::create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.viewer, "view")]),
        &w.admin,
    )
    .await
    .unwrap();
    let source = kernel::create_as(
        &w.db,
        &w.admin,
        "fixture.mcp",
        "note",
        json!({"title":"Revocable source"}).as_object().unwrap(),
        &source_home,
    )
    .await
    .unwrap();
    for (from, to) in [
        (&w.first, &w.first),
        (&w.first, &w.second),
        (&w.second, &w.first),
        (&source, &w.first),
        (&w.hidden, &w.second),
    ] {
        kernel::add_generic_link_as(&w.db, &w.admin, from, to, "supersedes", None)
            .await
            .unwrap();
    }
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    // The canonical projector forbids duplicate active triples. A refused
    // imported duplicate must leave the existing source count unchanged.
    let duplicate = kernel::generic_links::import_generic_link_as(
        &w.db,
        &host,
        &kernel::GenericLink {
            link_id: "currency-duplicate-source".into(),
            source_id: w.second.clone(),
            target_id: w.first.clone(),
            relationship: "supersedes".into(),
            note: None,
            created_at: "2026-11-09T00:00:00Z".into(),
            actor: None,
        },
    )
    .await;
    assert!(matches!(duplicate, Err(Error::Conflict(_))));
    // An archived, itself-superseded source still contributes under the
    // existing currency definition; it is not filtered by the caller's type.
    let revision = kernel::read_record_as(&w.db, &w.admin, &w.second)
        .await
        .unwrap()
        .unwrap()
        .revision;
    kernel::set_archived_as(&w.db, &w.admin, &w.second, true, revision)
        .await
        .unwrap();
    let args = json!({"sql":"SELECT r.id,r.home_id,r.lifecycle,r.successor_count,r.is_current,(SELECT count(*) FROM facet_values f WHERE f.record_id=r.id) AS facets FROM records r WHERE r.id=?1 OR r.id=?2 ORDER BY r.id","parameters":[{"type":"text","value":w.first},{"type":"text","value":w.second}]});
    for credential in ["acct:viewer", "acct:admin"] {
        let (out, _, _) = scoped_currency_pair(&w, credential, args.clone()).await;
        let first = out["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == w.first)
            .unwrap();
        assert_eq!(first["successor_count"], 3);
    }
    kernel::replace_home_policy(&w.db, &w.admin, &source_home, &[])
        .await
        .unwrap();
    let (out, _, _) = scoped_currency_pair(&w, "acct:viewer", args.clone()).await;
    assert_eq!(
        out["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == w.first)
            .unwrap()["successor_count"],
        2
    );
    call_as(
        &w,
        "acct:admin",
        "delete_record",
        json!({"id":w.second,"reason":"Currency must ignore a deleted successor"}),
    )
    .await
    .unwrap();
    for credential in ["acct:viewer", "acct:admin"] {
        scoped_currency_pair(&w, credential, args.clone()).await;
    }
    kernel::replay_all_projections(&w.db).await.unwrap();
    for credential in ["acct:viewer", "acct:admin"] {
        scoped_currency_pair(&w, credential, args.clone()).await;
        scoped_currency_pair(&w,credential,json!({"sql":"SELECT * FROM records WHERE id=?1 AND (is_current=1 OR successor_count>0) ORDER BY successor_count","parameters":[{"type":"text","value":w.first}]})).await;
    }
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_sql_run_ledger_preserves_owner_visibility_and_intent_order() {
    let w = world().await;
    let own = kernel::mint_run_as(&w.db, &w.viewer, None).await.unwrap();
    let hidden = kernel::mint_run_as(&w.db, &w.admin, None).await.unwrap();
    let context = kernel::open_run_as(&w.db, &w.viewer, &own).await.unwrap();
    kernel::set_run_intent_as(&w.db, &context, "First intent")
        .await
        .unwrap();
    kernel::set_run_intent_as(&w.db, &context, "Second intent")
        .await
        .unwrap();
    kernel::set_run_intent_as(
        &w.db,
        &context,
        &"x".repeat(crate::query::sql::MAX_RUN_INTENT_BYTES + 1),
    )
    .await
    .unwrap();
    kernel::finish_run_as(&w.db, &context).await.unwrap();
    let other = kernel::open_run_as(&w.db, &w.admin, &hidden).await.unwrap();
    kernel::set_run_intent_as(&w.db, &other, "Secret intent")
        .await
        .unwrap();
    let (out, stats) = super::sql::measured(call(
        &w,
        "query_sql",
        json!({"sql":"SELECT * FROM runs ORDER BY run_key"}),
    ))
    .await;
    let out = out.unwrap();
    assert_eq!(stats.staged_records, 0);
    assert_eq!(stats.home_checks, 0);
    assert_eq!(out["row_count"], 1);
    assert_eq!(out["rows"][0]["run_key"], own);
    assert!(out["rows"][0]["started_at_ms"].is_i64());
    assert!(out["rows"][0]["ended_at_ms"].is_i64());
    assert!(out["rows"][0]["principal_person_id"].is_null());
    assert_eq!(out["rows"][0]["model_assurance"], "self_declared");
    let out = call(
        &w,
        "query_sql",
        json!({"sql":"SELECT * FROM run_intents ORDER BY run_key,ordinal"}),
    )
    .await
    .unwrap();
    assert_eq!(out["row_count"], 3);
    assert_eq!(out["rows"][0]["ordinal"], 1);
    assert_eq!(out["rows"][0]["intent"], "First intent");
    assert_eq!(out["rows"][1]["ordinal"], 2);
    assert_eq!(out["rows"][1]["intent"], "Second intent");
    assert_eq!(out["rows"][2]["ordinal"], 3);
    assert!(out["rows"][2]["intent"].is_null());
    for key in [hidden.as_str(), "missing"] {
        let out=call(&w,"query_sql",json!({"sql":"SELECT count(*) AS n FROM runs r JOIN run_intents i USING(run_key) WHERE r.run_key=?1","parameters":[{"type":"text","value":key}]})).await.unwrap();
        assert_eq!(out["rows"][0]["n"], 0);
    }
    let out = registry()
        .call_engine(
            EngineHandle::KernelV2(w.db.clone()),
            Caller::authenticated("acct:admin"),
            "query_sql",
            json!({"sql":"SELECT count(*) AS n FROM runs"}),
        )
        .await
        .unwrap();
    assert_eq!(out["rows"][0]["n"], 2);
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_sql_imported_home_names_only_visible_folder_records() {
    let w = world().await;
    let native: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
        .bind(&w.first)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let out=call(&w,"query_sql",json!({"sql":"SELECT home_id FROM records WHERE id=?1","parameters":[{"type":"text","value":w.first}]})).await.unwrap();
    assert_eq!(out["rows"][0]["home_id"], native);
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::hq::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let mapped = kernel::hq::v1_import_home_id(&w.second);
    kernel::hq::import_home_as(
        &w.db,
        &host,
        &mapped,
        &w.second,
        KERNEL_ROOT_ID,
        &w.admin,
        Some(&[(&w.viewer, "view")]),
    )
    .await
    .unwrap();
    sqlx::query("UPDATE kernel_records SET home_id=? WHERE id=?")
        .bind(&mapped)
        .bind(&w.first)
        .execute(w.db.write_pool())
        .await
        .unwrap();
    let out=call(&w,"query_sql",json!({"sql":"SELECT home_id FROM records WHERE id=?1","parameters":[{"type":"text","value":w.first}]})).await.unwrap();
    assert_eq!(out["rows"][0]["home_id"], w.second);
    // A record-local imported policy boundary is not its logical parent.
    let own_boundary = kernel::hq::v1_import_home_id(&w.first);
    kernel::hq::import_home_as(
        &w.db,
        &host,
        &own_boundary,
        &w.first,
        KERNEL_ROOT_ID,
        &w.admin,
        Some(&[(&w.viewer, "view")]),
    )
    .await
    .unwrap();
    kernel::hq::import_event_as(
        &w.db,
        &host,
        &w.first,
        &kernel::hq::LegacyEvent {
            source: None,
            id: uuid::Uuid::new_v4().to_string(),
            event_type: "v1.snapshot_provenance".into(),
            payload: json!({"policy_anchor":w.first,"original_home":w.second}),
            created_at: "2026-10-16T00:00:00Z".into(),
            actor: None,
            run_key: None,
        },
    )
    .await
    .unwrap();
    sqlx::query("UPDATE kernel_records SET home_id=? WHERE id=?")
        .bind(&own_boundary)
        .bind(&w.first)
        .execute(w.db.write_pool())
        .await
        .unwrap();
    let out=call(&w,"query_sql",json!({"sql":"SELECT home_id FROM records WHERE id=?1","parameters":[{"type":"text","value":w.first}]})).await.unwrap();
    assert_eq!(out["rows"][0]["home_id"], w.second);
    #[cfg(feature = "v2-kernel-probe")]
    {
        let (out, _, _) = bounded_placement_get_pair(
            &w,
            "acct:viewer",
            &w.viewer,
            json!({"ids":[w.first],"children_limit":50}),
        )
        .await;
        assert_eq!(out["records"][0]["home_id"], w.second);
    }
    let private: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
        .bind(&w.hidden)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE kernel_records SET home_id=? WHERE id=?")
        .bind(private)
        .bind(&w.second)
        .execute(w.db.write_pool())
        .await
        .unwrap();
    let out=call(&w,"query_sql",json!({"sql":"SELECT home_id FROM records WHERE id=?1","parameters":[{"type":"text","value":w.first}]})).await.unwrap();
    assert!(out["rows"][0]["home_id"].is_null());
    #[cfg(feature = "v2-kernel-probe")]
    {
        let (out, _, _) = bounded_placement_get_pair(
            &w,
            "acct:viewer",
            &w.viewer,
            json!({"ids":[w.first,w.second],"children_limit":50}),
        )
        .await;
        assert!(out["records"][0]["home_id"].is_null());
        assert_eq!(out["records"][1]["status"], "not_found");
    }
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_sql_imported_root_is_structural_and_visibility_scoped() {
    let w = world().await;
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::hq::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    kernel::hq::import_home_policy_as(&w.db, &host, KERNEL_ROOT_ID, &[(&w.viewer, "view")])
        .await
        .unwrap();
    sqlx::query("UPDATE kernel_records SET home_id=? WHERE id=?")
        .bind(KERNEL_ROOT_ID)
        .bind(&w.first)
        .execute(w.db.write_pool())
        .await
        .unwrap();
    let out=call(&w,"query_sql",json!({"sql":"SELECT home_id FROM records WHERE id=?1","parameters":[{"type":"text","value":w.first}]})).await.unwrap();
    assert_eq!(out["rows"][0]["home_id"], "native:root");
    // Keep the record visible through its own imported boundary while hiding
    // the structural parent. The raw root token must then read as NULL.
    let own = kernel::hq::v1_import_home_id(&w.first);
    kernel::hq::import_home_as(
        &w.db,
        &host,
        &own,
        &w.first,
        KERNEL_ROOT_ID,
        &w.admin,
        Some(&[(&w.viewer, "view")]),
    )
    .await
    .unwrap();
    kernel::hq::import_event_as(
        &w.db,
        &host,
        &w.first,
        &kernel::hq::LegacyEvent {
            source: None,
            id: uuid::Uuid::new_v4().to_string(),
            event_type: "v1.snapshot_provenance".into(),
            payload: json!({"policy_anchor":w.first,"original_home":"native:root"}),
            created_at: "2026-10-16T00:00:00Z".into(),
            actor: None,
            run_key: None,
        },
    )
    .await
    .unwrap();
    sqlx::query("UPDATE kernel_records SET home_id=? WHERE id=?")
        .bind(&own)
        .bind(&w.first)
        .execute(w.db.write_pool())
        .await
        .unwrap();
    kernel::hq::import_home_policy_as(&w.db, &host, KERNEL_ROOT_ID, &[])
        .await
        .unwrap();
    let out=call(&w,"query_sql",json!({"sql":"SELECT home_id FROM records WHERE id=?1","parameters":[{"type":"text","value":w.first}]})).await.unwrap();
    assert_eq!(out["row_count"], 1);
    assert!(out["rows"][0]["home_id"].is_null());
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_sql_relations_visibility_and_guards() {
    let w = world().await;
    for id in [&w.first, &w.second, &w.hidden] {
        kernel::observe_facet_as(
            &w.db,
            &w.admin,
            id,
            &kernel::FacetObservation {
                key: "status".into(),
                value: Some("active".into()),
                value_num: None,
                vocab_ref: None,
                as_of: "2026-10-16T00:00:00Z".into(),
            },
            None,
        )
        .await
        .unwrap();
    }
    let query = |sql: &str| json!({"sql":sql});
    let out = call(
        &w,
        "query_sql",
        query("SELECT id,type,kind,name FROM records ORDER BY id LIMIT 5"),
    )
    .await
    .unwrap();
    assert_eq!(out["row_count"], 2);
    for row in out["rows"].as_array().unwrap() {
        assert_eq!(row["type"], "Document");
        assert_eq!(row["kind"], "note");
        assert_ne!(row["id"], w.hidden);
    }
    let out = call(&w,"query_sql",query("SELECT r.id,f.value FROM records r JOIN facet_values f ON f.record_id=r.id ORDER BY r.id LIMIT 5")).await.unwrap();
    assert_eq!(out["row_count"], 2);
    let out = call(&w,"query_sql",query("SELECT source_id,target_id,relationship FROM links ORDER BY source_id,target_id LIMIT 5")).await.unwrap();
    assert_eq!(
        out["rows"],
        json!([{"source_id":w.first,"target_id":w.second,"relationship":"relates_to"}])
    );
    // The hidden-target link must also disappear from event counts.
    let out = call(
        &w,
        "query_sql",
        query("SELECT count(*) AS n FROM content_events WHERE type='link.added'"),
    )
    .await
    .unwrap();
    assert_eq!(out["rows"][0]["n"], 1);
    for relation in ["records", "facet_values", "content_events"] {
        let id = if relation == "records" {
            "id"
        } else {
            "record_id"
        };
        let out = call(&w,"query_sql",json!({"sql":format!("SELECT count(*) AS n FROM {relation} WHERE {id}=?1"),"parameters":[{"type":"text","value":w.hidden}]})).await.unwrap();
        assert_eq!(out["rows"][0]["n"], 0, "{relation}");
    }
    let out = call(
        &w,
        "query_sql",
        query("SELECT count(*) AS n FROM records a JOIN records b ON a.id=b.id"),
    )
    .await
    .unwrap();
    assert_eq!(out["rows"][0]["n"], 2);
    kernel::sql_event_projection::catch_up(&w.db).await.unwrap();
    {
        let mut conn = w.db.pool().acquire().await.unwrap();
        assert!(kernel::sql_event_projection::frontier_on(
            &mut conn,
            w.db.sql_event_projection_generation()
        )
        .await
        .unwrap()
        .is_some());
    }
    // Authored expressions must never run on hidden source rows, even if
    // SQLite pushes a predicate ahead of a join. These stored strings are
    // deliberately invalid JSON; hidden and missing both return zero.
    for (relation, id_column, value_column) in [
        ("records", "id", "name"),
        ("facet_values", "record_id", "value"),
        ("links", "target_id", "relationship"),
        ("content_events", "record_id", "type"),
    ] {
        for id in [w.hidden.as_str(), "missing"] {
            let sql = format!("SELECT count(*) AS n FROM {relation} WHERE CASE WHEN {id_column}=?1 THEN json_extract({value_column}, '$.x') ELSE 0 END");
            let out = call(
                &w,
                "query_sql",
                json!({"sql":sql,"parameters":[{"type":"text","value":id}]}),
            )
            .await
            .unwrap();
            assert_eq!(out["rows"][0]["n"], 0, "{relation}");
        }
    }
    // Supported messaging projections remain empty without verified Person
    // bindings or governed Message state; physical records alone grant neither.
    // Untyped native facets likewise create no typed-time rows.
    for relation in [
        "bindings",
        "message_reactions",
        "my_mentions",
        "facet_times",
    ] {
        let out = call(
            &w,
            "query_sql",
            query(&format!("SELECT count(*) AS n FROM {relation}")),
        )
        .await
        .unwrap();
        assert_eq!(out["rows"][0]["n"], 0, "{relation}");
    }
    let error = call(
        &w,
        "query_sql",
        query("SELECT count(*) AS n FROM facet_keys"),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("not yet supported on v2"), "{error}");
    for sql in [
        "DELETE FROM records",
        "SELECT id FROM records; SELECT id FROM records",
        "SELECT id FROM main.kernel_records",
        "PRAGMA table_info(kernel_records)",
        "WITH x AS (SELECT id FROM records LIMIT 1) SELECT * FROM x",
    ] {
        assert!(call(&w, "query_sql", query(sql)).await.is_err(), "{sql}");
    }
    let out = call(&w,"query_sql",query("SELECT column_name FROM catalog_columns WHERE relation_name='records' ORDER BY column_position")).await.unwrap();
    assert!(out["rows"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["column_name"] == "home_id"));
    // Column-less count observes the same unsupported relation even in a CTE.
    for relation in crate::query::sql_contract::LOGICAL_RELATIONS {
        if super::sql::columns_for_test(relation.name) {
            continue;
        }
        let error = call(
            &w,
            "query_sql",
            query(&format!(
                "WITH q AS (SELECT count(*) AS n FROM {}) SELECT n FROM q",
                relation.name
            )),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("not yet supported on v2") && error.contains(relation.name),
            "{}: {error}",
            relation.name
        );
    }
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_sql_body_is_lazy_and_bounded() {
    let w = world().await;
    for (id, ch) in [(&w.hidden, "s"), (&w.first, "x")] {
        let revision = kernel::read_record_as(&w.db, &w.admin, id)
            .await
            .unwrap()
            .unwrap()
            .revision;
        kernel::set_body_as(&w.db, &w.admin, id, &ch.repeat(400_000), revision)
            .await
            .unwrap();
        if id == &w.hidden {
            let out = call(
                &w,
                "query_sql",
                json!({"sql":"SELECT count(*) AS n FROM records WHERE length(body)>0"}),
            )
            .await
            .unwrap();
            assert_eq!(out["rows"][0]["n"], 2);
        }
    }
    for sql in [
        "SELECT id,name FROM records ORDER BY id LIMIT 5",
        "SELECT count(*) AS n FROM records",
        "SELECT id,substr(body,1,20) AS preview FROM records ORDER BY id LIMIT 5",
    ] {
        // SQLite's value ceiling applies on loading a selected oversized body,
        // even before substr (the v1 behavior); metadata remains readable.
        let out = call(&w, "query_sql", json!({"sql":sql})).await;
        if sql.contains("substr") {
            assert!(out.is_err());
        } else {
            out.unwrap();
        }
    }
    assert!(call(
        &w,
        "query_sql",
        json!({"sql":"SELECT body FROM records ORDER BY id LIMIT 5"})
    )
    .await
    .is_err());
    let out = call(&w,"query_sql",json!({"sql":"SELECT body FROM records WHERE id=?1", "parameters":[{"type":"text","value":w.second}]})).await.unwrap();
    assert_eq!(out["rows"][0]["body"], "original");
    let out = call(
        &w,
        "query_sql",
        json!({"sql":"SELECT id FROM records LIMIT 1"}),
    )
    .await
    .unwrap();
    assert!(out["assumed_order"].is_object());
    // A failed read must not change the connection or its next caller's scope.
    let out = registry()
        .call_engine(
            EngineHandle::KernelV2(w.db.clone()),
            Caller::authenticated("acct:admin"),
            "query_sql",
            json!({"sql":"SELECT count(*) AS n FROM records"}),
        )
        .await
        .unwrap();
    assert_eq!(out["rows"][0]["n"], 3);
    let out = call(
        &w,
        "query_sql",
        json!({"sql":"SELECT count(*) AS n FROM records"}),
    )
    .await
    .unwrap();
    assert_eq!(out["rows"][0]["n"], 2);
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_sql_carrier_and_provider_relations() {
    let w = world().await;
    let carrier = crate::v2_standard::v1_compat::package();
    let installed = kernel::install_package_as(&w.db, &w.admin, &carrier)
        .await
        .unwrap();
    kernel::adopt_package_at(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &carrier,
        Some(&installed),
        &carrier.declared_reads,
    )
    .await
    .unwrap();
    let home: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
        .bind(&w.first)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let fields = crate::v2_standard::v1_compat::compat_fields(
        "WorkItem",
        "task",
        Some("Imported task"),
        None,
        None,
    );
    let id = kernel::create_json_as(
        &w.db,
        &w.admin,
        crate::v2_standard::v1_compat::FAMILY,
        crate::v2_standard::v1_compat::KIND,
        &serde_json::to_string(&fields).unwrap(),
        &home,
    )
    .await
    .unwrap();
    {
        let out = call(
            &w,
            "query_sql",
            json!({"sql":"SELECT id,type,kind,name FROM records ORDER BY id LIMIT 5"}),
        )
        .await
        .unwrap();
        let carried = out["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == id)
            .unwrap();
        assert_eq!(
            carried,
            &json!({"id":id,"type":"WorkItem","kind":"task","name":"Imported task"})
        );
    }
    let package = crate::v2_standard::relates_to::package();
    let installed = kernel::install_package_as(&w.db, &w.admin, &package)
        .await
        .unwrap();
    kernel::adopt_package_at(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &package,
        Some(&installed),
        &package.declared_reads,
    )
    .await
    .unwrap();
    let source = id.clone();
    for (key, target) in [("visible", &w.second), ("hidden", &w.hidden)] {
        let request = kernel::prepare_provider_as(
            &w.db,
            &w.admin,
            &source,
            target,
            key,
            crate::v2_standard::relates_to::Command::Assert { sources: vec![] },
        )
        .await
        .unwrap();
        kernel::commit_provider_as(&w.db, &w.admin, &request)
            .await
            .unwrap();
    }
    let out=call(&w,"query_sql",json!({"sql":"SELECT source_id,target_id,relationship FROM links WHERE source_id=?1 AND relationship='relates_to' ORDER BY target_id","parameters":[{"type":"text","value":source}]})).await.unwrap();
    assert_eq!(
        out["rows"],
        json!([{"source_id":source,"target_id":w.second,"relationship":"relates_to"}])
    );
    // Preserve S7's record-anchor fence as well as the provider subject fence:
    // an aggregate alone is not a caller-visible record in this relation.
    let out=call(&w,"query_sql",json!({"sql":"SELECT count(*) AS n FROM content_events WHERE type='kernel.provider_outcome.v1'"})).await.unwrap();
    assert_eq!(out["rows"][0]["n"], 0);
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_app_body_read_save_and_stale_draft_keep_coherent_receipts() {
    let world = world().await;
    let before = kernel::read_record_as(&world.db, &world.admin, &world.first)
        .await
        .unwrap()
        .unwrap();
    kernel::hq::set_body_as(
        &world.db,
        &world.admin,
        &world.first,
        "Draft base",
        before.revision,
    )
    .await
    .unwrap();
    let snapshot = kernel::dump_all_kernel_tables(&world.db).await.unwrap();
    // Exact get_record shape used by appV2's fallback body reader, including
    // disabled enrichments and the registry's existing short-ref middleware.
    let read = call(
        &world,
        "get_record",
        json!({
            "ids": [&world.first[..8], world.hidden], "children_limit": 0,
            "links_limit": 0, "include_comments": false, "include_citations": false,
            "include_suggestions": false, "include_history_summary": false
        }),
    )
    .await
    .unwrap();
    let base = &read["records"][0];
    assert_eq!(base["id"], world.first);
    assert_eq!(base["body"], "Draft base");
    assert_eq!(base["version"], base["record_version"]);
    assert!(base["version"].as_str().unwrap().starts_with("rec:"));
    assert_eq!(
        base["body_digest"],
        crate::mcp::tools::lifecycle::body_digest(Some("Draft base"))
    );
    assert_eq!(read["records"][1]["status"], "not_found");
    for options in [
        json!({"children_limit":1}),
        json!({"include_history_summary":true}),
    ] {
        let mut args = options;
        args["ids"] = json!([world.first]);
        let enriched = call(&world, "get_record", args).await.unwrap();
        assert_eq!(enriched["records"][0]["id"], world.first);
    }
    assert_eq!(
        snapshot,
        kernel::dump_all_kernel_tables(&world.db).await.unwrap()
    );
    let saved = call_as(
        &world,
        "acct:admin",
        "update_record",
        json!({
            "id":world.first, "body_set":"Saved draft", "if_body_digest":base["body_digest"]
        }),
    )
    .await
    .unwrap();
    assert_eq!(saved["id"], world.first);
    assert_eq!(saved["version"], saved["record_version"]);
    assert_ne!(saved["version"], base["version"]);
    assert_eq!(
        saved["body_digest"],
        crate::mcp::tools::lifecycle::body_digest(Some("Saved draft"))
    );
    let committed = kernel::dump_all_kernel_tables(&world.db).await.unwrap();
    let stale = call_as(
        &world,
        "acct:admin",
        "update_record",
        json!({
            "id":world.first, "body_set":"Other stale draft", "if_body_digest":base["body_digest"]
        }),
    )
    .await
    .unwrap_err();
    assert!(
        stale.to_string().contains("stale if_body_digest"),
        "{stale}"
    );
    assert_eq!(
        committed,
        kernel::dump_all_kernel_tables(&world.db).await.unwrap()
    );
    let reread = call(
        &world,
        "get_record",
        json!({"ids":[world.first],"children_limit":0,"links_limit":0}),
    )
    .await
    .unwrap();
    assert_eq!(reread["records"][0]["body"], "Saved draft");
    assert_eq!(reread["records"][0]["version"], saved["version"]);
    world.db.close().await;
}

#[tokio::test]
async fn kernel_v2_frozen_docs_spaces_sql_reads_threads_anchors_and_authors() {
    let world = world().await;
    install_comment_carrier(&world).await;
    call_as(
        &world,
        "acct:admin",
        "update_record",
        json!({"id":world.first,"body_set":"alpha brave revised passage"}),
    )
    .await
    .unwrap();
    let root = call_as(
        &world,
        "acct:admin",
        "create_record",
        json!({
            "type":"Annotation","kind":"comment","body":"Visible discussion",
            "links":[{"target_id":world.first,"relationship":"part_of"}],
            "target":anchored_target(&world.first,"revised",12,19)
        }),
    )
    .await
    .unwrap();
    let hidden = call_as(
        &world,
        "acct:admin",
        "create_record",
        json!({
            "type":"Annotation","kind":"comment","body":"Hidden discussion",
            "links":[{"target_id":world.hidden,"relationship":"part_of"}]
        }),
    )
    .await
    .unwrap();
    let folder = kernel::read_record_as(&world.db, &world.admin, &world.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/kernel_v2_app_reads.json"
    ))
    .unwrap();
    let before = kernel::dump_all_kernel_tables(&world.db).await.unwrap();
    for (source, definition) in fixture["sources"].as_object().unwrap() {
        for need in definition["needs"].as_array().unwrap() {
            let sections = if need["key"].as_str().unwrap().ends_with(".links") {
                ["details", "threads", "history"]
                    .into_iter()
                    .filter(|section| {
                        need["sql"]
                            .as_str()
                            .unwrap()
                            .contains(&format!("'{section}'"))
                    })
                    .collect::<Vec<_>>()
            } else {
                vec!["details"]
            };
            for section in sections {
                let parameters: Vec<_> = need["params"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|p| {
                        let value = match p["name"].as_str().unwrap() {
                            "record_id" => world.first.as_str(),
                            "folder" => folder.as_str(),
                            "section" => section,
                            "after_name" | "after_id" => "",
                            other => panic!("unknown frozen app parameter {other}"),
                        };
                        json!({"type":"text","value":value})
                    })
                    .collect();
                let result = call(
                    &world,
                    "query_sql",
                    json!({"sql":need["sql"],"parameters":parameters}),
                )
                .await
                .unwrap_or_else(|e| panic!("{source} {} {section}: {e}", need["key"]));
                let encoded = result.to_string();
                assert!(
                    !encoded.contains(hidden["id"].as_str().unwrap()),
                    "{source} {} leaked hidden comment",
                    need["key"]
                );
                if need["key"].as_str().unwrap().ends_with(".links") && section == "threads" {
                    assert!(
                        encoded.contains(root["id"].as_str().unwrap()),
                        "{source} {} omitted visible comment",
                        need["key"]
                    );
                }
            }
        }
    }
    let anchors = call(&world,"query_sql",json!({"sql":"SELECT annotation_id,target_record_id,source_event_seq,source_sha256 FROM comment_anchors ORDER BY annotation_id"})).await.unwrap();
    assert_eq!(anchors["rows"].as_array().unwrap().len(), 1);
    assert_eq!(anchors["rows"][0]["annotation_id"], root["id"]);
    let authors = call_as(&world,"acct:admin","query_sql",json!({"sql":"SELECT e.id,e.actor,e.channel_kind,a.display_name FROM content_events e LEFT JOIN actors a ON a.actor=e.actor WHERE e.record_id=?1 AND e.type='record.created' ORDER BY e.local_seq","parameters":[{"type":"text","value":root["id"]}]})).await.unwrap();
    assert_eq!(authors["rows"].as_array().unwrap().len(), 1);
    assert_eq!(authors["rows"][0]["actor"], world.admin);
    assert_eq!(authors["rows"][0]["display_name"], "Admin");
    assert_eq!(authors["rows"][0]["channel_kind"], "unknown");
    assert_eq!(
        before,
        kernel::dump_all_kernel_tables(&world.db).await.unwrap(),
        "SQL reads must not write"
    );
    world.db.close().await;
}

#[tokio::test]
async fn kernel_v2_legacy_sql_headers_follow_disclosure_and_rebuild_without_source() {
    let mut world = world().await;
    let host = kernel::resolve_principal_by_binding(&world.db, kernel::hq::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    for (id, subjects) in [
        ("legacy-visible", vec![world.first.clone()]),
        (
            "legacy-hidden-reference",
            vec![world.first.clone(), world.hidden.clone()],
        ),
    ] {
        kernel::hq::import_event_as(&world.db,&host,&world.first,&kernel::hq::LegacyEvent {
            source:Some(json!({"origin":"synthetic","stream":"content_events","metadata":{"record_id":world.first},"subjects":subjects})),
            id:id.into(),event_type:"record.updated".into(),payload:json!({"body":"legacy bytes"}),
            created_at:"2026-01-01T00:00:00Z".into(),actor:Some("acct:admin".into()),run_key:Some("legacy-run".into())
        }).await.unwrap();
    }
    // Legacy envelopes without a SQL header still advance the scanned log
    // position. Otherwise each reopen would try the same tail again.
    kernel::hq::import_event_as(
        &world.db,
        &host,
        &world.first,
        &kernel::hq::LegacyEvent {
            source: None,
            id: "opaque-retained-envelope".into(),
            event_type: "fixture.opaque".into(),
            payload: json!({}),
            created_at: "2026-01-02T00:00:00Z".into(),
            actor: None,
            run_key: None,
        },
    )
    .await
    .unwrap();
    let out=call(&world,"query_sql",json!({"sql":"SELECT id,type,actor,run_key,created_at FROM content_events WHERE id LIKE 'legacy-%' ORDER BY id"})).await.unwrap();
    assert_eq!(out["rows"].as_array().unwrap().len(), 1);
    assert_eq!(out["rows"][0]["id"], "legacy-visible");
    assert_eq!(out["rows"][0]["type"], "record.updated");
    assert!(out["rows"][0]["actor"].is_null());
    assert!(out["rows"][0]["run_key"].is_null());
    assert_eq!(out["rows"][0]["created_at"], "2026-01-01T00:00:00.000Z");
    let admin=call_as(&world,"acct:admin","query_sql",json!({"sql":"SELECT id,actor,run_key FROM content_events WHERE id LIKE 'legacy-%' ORDER BY id"})).await.unwrap();
    assert_eq!(admin["rows"].as_array().unwrap().len(), 2);
    assert_eq!(admin["rows"][1]["actor"], world.admin);
    let before = kernel::dump_all_kernel_tables(&world.db).await.unwrap();
    // Simulate an older writer: W5 disclosure is present, but the new
    // header projection and progress did not include its latest envelopes.
    let tail: i64 = sqlx::query_scalar(
        "SELECT seq FROM kernel_legacy_sql_events WHERE source_id='legacy-hidden-reference'",
    )
    .fetch_one(world.db.pool())
    .await
    .unwrap();
    sqlx::query("DELETE FROM kernel_legacy_sql_events WHERE seq=?")
        .bind(tail)
        .execute(world.db.write_pool())
        .await
        .unwrap();
    sqlx::query("UPDATE kernel_legacy_sql_progress SET scanned_seq=?")
        .bind(tail - 1)
        .execute(world.db.write_pool())
        .await
        .unwrap();
    let stale = call(
        &world,
        "query_sql",
        json!({"sql":"SELECT id FROM records ORDER BY id LIMIT 1"}),
    )
    .await
    .unwrap_err();
    assert!(stale.to_string().contains("needs catchup"), "{stale}");
    world.db.close().await;
    let path = world._dir.path().join("v2.db");
    let refused = kernel::open_v2_database(path.to_str().unwrap())
        .await
        .err()
        .unwrap();
    assert!(refused.to_string().contains("needs catchup"));
    // Preparation uses a controlled raw opener; serving never repairs a gap.
    world.db = crate::db::open_existing_v2_file(path.to_str().unwrap())
        .await
        .unwrap();
    let still_stale = call(
        &world,
        "query_sql",
        json!({"sql":"SELECT id FROM records LIMIT 1"}),
    )
    .await
    .unwrap_err();
    assert!(still_stale.to_string().contains("needs catchup"));
    kernel::prepare_v2_database(&world.db).await.unwrap();
    assert_eq!(
        before,
        kernel::dump_all_kernel_tables(&world.db).await.unwrap()
    );
    // Serving refuses a missing projection. Explicit preparation rebuilds it.
    sqlx::query("DROP TABLE kernel_legacy_sql_events")
        .execute(world.db.write_pool())
        .await
        .unwrap();
    world.db.close().await;
    let path = world._dir.path().join("v2.db");
    let error = kernel::open_v2_database(path.to_str().unwrap())
        .await
        .err()
        .unwrap();
    assert!(
        error.to_string().contains("kernel_legacy_sql_events"),
        "{error}"
    );
    world.db = crate::db::open_existing_v2_file(path.to_str().unwrap())
        .await
        .unwrap();
    kernel::prepare_v2_database(&world.db).await.unwrap();
    assert_eq!(
        before,
        kernel::dump_all_kernel_tables(&world.db).await.unwrap()
    );
    kernel::replay_all_projections(&world.db).await.unwrap();
    assert_eq!(
        before,
        kernel::dump_all_kernel_tables(&world.db).await.unwrap()
    );
    let restored=call(&world,"query_sql",json!({"sql":"SELECT id,type,actor,run_key,created_at FROM content_events WHERE id LIKE 'legacy-%' ORDER BY id"})).await.unwrap();
    assert_eq!(out["rows"], restored["rows"]);
    world.db.close().await;
}

#[tokio::test]
async fn kernel_v2_imported_birth_time_keeps_native_clock_and_guarded_edit_identity() {
    let world = world().await;
    call_as(
        &world,
        "acct:admin",
        "update_record",
        json!({"id":world.first,"body_set":"Before"}),
    )
    .await
    .unwrap();
    let native_birth: String =
        sqlx::query_scalar("SELECT created_at FROM kernel_records WHERE id=?")
            .bind(&world.first)
            .fetch_one(world.db.pool())
            .await
            .unwrap();
    let host = kernel::resolve_principal_by_binding(&world.db, kernel::hq::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    kernel::hq::import_event_as(
        &world.db,
        &host,
        &world.first,
        &kernel::hq::LegacyEvent {
            source: None,
            id: "synthetic-source-birth".into(),
            event_type: "v1.snapshot_provenance".into(),
            payload: json!({"record_id":world.first,"created_at":"2001-01-01T00:00:00Z"}),
            created_at: "2001-01-01T00:00:00Z".into(),
            actor: None,
            run_key: None,
        },
    )
    .await
    .unwrap();
    let read = call(
        &world,
        "get_record",
        json!({"ids":[world.first],"children_limit":0,"links_limit":0}),
    )
    .await
    .unwrap();
    let base = &read["records"][0];
    assert_eq!(base["created_at"], "2001-01-01T00:00:00Z");
    assert_eq!(base["kernel_v2"]["native_created_at"], native_birth);
    let sql=call(&world,"query_sql",json!({"sql":"SELECT created_at FROM records WHERE id=?1","parameters":[{"type":"text","value":world.first}]})).await.unwrap();
    assert_eq!(sql["rows"][0]["created_at"], "2001-01-01T00:00:00.000Z");
    let saved=call_as(&world,"acct:admin","update_record",json!({"id":world.first,"body_set":"After","if_body_digest":base["body_digest"],"if_unmodified_since":base["updated_at"]})).await.unwrap();
    assert_ne!(saved["version"], base["version"]);
    let after = call(
        &world,
        "get_record",
        json!({"ids":[world.first],"children_limit":0,"links_limit":0}),
    )
    .await
    .unwrap();
    assert_eq!(after["records"][0]["created_at"], base["created_at"]);
    assert_eq!(after["records"][0]["body"], "After");
    assert_eq!(
        after["records"][0]["kernel_v2"]["native_created_at"],
        native_birth
    );
    world.db.close().await;
}

#[tokio::test]
async fn kernel_v2_sql_hq_scale_historical_claims_use_run_key_index_and_catalogue_counts() {
    let w = world().await;
    install_comment_carrier(&w).await;
    // Mixed carrier/comment population catches a recursive visibility plan
    // that scans the entire carrier family on each bearer-chain step.
    sqlx::query("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<5000) INSERT INTO kernel_records(id,home_id,owner_id,primary_type,kind,accession,pin_family,pin_version,pin_digest,created_seq,created_at) SELECT printf('carrier:%d',x),r.home_id,r.owner_id,'WorkItem','record',printf('carrier-accession:%d',x),'native.v1.record',1,'synthetic',r.created_seq,r.created_at FROM n CROSS JOIN kernel_records r WHERE r.id=?").bind(&w.first).execute(w.db.write_pool()).await.unwrap();
    sqlx::query("INSERT INTO kernel_record_fields SELECT id,'v1_type','\"WorkItem\"',created_seq FROM kernel_records WHERE id LIKE 'carrier:%'").execute(w.db.write_pool()).await.unwrap();
    kernel::ensure_record_metadata(&w.db).await.unwrap();
    for n in 0..32 {
        call(&w,"create_record",json!({"type":"Annotation","kind":"comment","body":"Synthetic scale comment","links":[{"target_id":w.first,"relationship":"part_of"}],"idempotency_key":format!("claim-scale-comment:{n}")})).await.unwrap();
    }

    // Projection-only scale fixture: avoids thousands of unrelated source
    // admission acts while exercising the exact governed SQL staging path.
    sqlx::query("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<5100) INSERT INTO kernel_v1_state SELECT 'runs',printf('run:%d',x),'synthetic',json_object('activity_id',printf('activity:%d',x),'run_key',printf('legacy-key:%d',x),'account_id','acct:viewer','started_at','2026-01-01T00:00:00Z'),?,NULL,'2026-01-02T00:00:00Z',0 FROM n").bind(&w.viewer).execute(w.db.write_pool()).await.unwrap();
    sqlx::query("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<1340) INSERT INTO kernel_v1_state SELECT 'claims',printf('claim:%d',x),'synthetic',json_object('id',printf('claim:%d',x),'run_key',printf('legacy-key:%d',x),'claimed_at','2026-01-01T00:00:00Z'),?,?,'2026-01-02T00:00:00Z',0 FROM n").bind(&w.viewer).bind(&w.first).execute(w.db.write_pool()).await.unwrap();
    let (out, stats) = super::sql::measured(call(
        &w,
        "query_sql",
        json!({"sql":"SELECT count(*) AS n,sum(is_current) AS live FROM agent_activity_claims"}),
    ))
    .await;
    assert_eq!(out.unwrap()["rows"], json!([{"n":1340,"live":0}]));
    assert!(stats.staging_vm_ops < 2_000_000, "{stats:?}");
    for relation in [
        "vocabularies",
        "vocabulary_values",
        "record_lifecycle_interpretations",
        "runs",
        "run_intents",
    ] {
        let out = call(
            &w,
            "query_sql",
            json!({"sql":format!("SELECT count(*) AS n FROM {relation}")}),
        )
        .await
        .unwrap_or_else(|error| panic!("{relation}: {error}"));
        assert!(out["rows"][0]["n"].is_number(), "{relation}");
    }
    assert!(call(
        &w,
        "query_sql",
        json!({"sql":"SELECT count(*) FROM kernel_v1_state"})
    )
    .await
    .is_err());
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_sql_hq_scale_lifecycle_interpretations_use_cached_bulk_staging() {
    let w = world().await;
    sqlx::query("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<5000) INSERT INTO kernel_records(id,home_id,owner_id,created_seq,created_at) SELECT printf('lifecycle:%05d',x),r.home_id,r.owner_id,r.created_seq,r.created_at FROM n CROSS JOIN kernel_records r WHERE r.id=?").bind(&w.first).execute(w.db.write_pool()).await.unwrap();
    kernel::ensure_record_metadata(&w.db).await.unwrap();
    let (out,stats)=super::sql::measured(call(&w,"query_sql",json!({"sql":"SELECT status,count(*) AS n FROM record_lifecycle_interpretations GROUP BY status"}))).await;
    assert_eq!(out.unwrap()["rows"], json!([{"status":"absent","n":5002}]));
    assert!(stats.staging_vm_ops < 5_000_000, "{stats:?}");
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_legacy_sql_frontier_cannot_skip_an_older_writer_gap() {
    let world = world().await;
    let host = kernel::resolve_principal_by_binding(&world.db, kernel::hq::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    for id in ["old-writer-gap", "new-writer-tail"] {
        kernel::hq::import_event_as(&world.db, &host, &world.first, &kernel::hq::LegacyEvent {
            source:Some(json!({"origin":"synthetic","stream":"content_events","metadata":{"record_id":world.first},"subjects":[world.first]})),
            id:id.into(),event_type:"record.updated".into(),payload:json!({}),
            created_at:"2026-01-01T00:00:00Z".into(),actor:None,run_key:None,
        }).await.unwrap();
        if id == "old-writer-gap" {
            let seq: i64 = sqlx::query_scalar(
                "SELECT seq FROM kernel_legacy_sql_events WHERE source_id='old-writer-gap'",
            )
            .fetch_one(world.db.pool())
            .await
            .unwrap();
            sqlx::query("DELETE FROM kernel_legacy_sql_events WHERE seq=?")
                .bind(seq)
                .execute(world.db.write_pool())
                .await
                .unwrap();
            sqlx::query("UPDATE kernel_legacy_sql_progress SET scanned_seq=?")
                .bind(seq - 1)
                .execute(world.db.write_pool())
                .await
                .unwrap();
        }
    }
    let error = call(
        &world,
        "query_sql",
        json!({"sql":"SELECT id FROM records LIMIT 1"}),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("run explicit v2 preparation"));
    kernel::prepare_v2_database(&world.db).await.unwrap();
    let rows = call(&world, "query_sql", json!({"sql":"SELECT id FROM content_events WHERE id IN ('old-writer-gap','new-writer-tail') ORDER BY id"})).await.unwrap();
    assert_eq!(rows["rows"].as_array().unwrap().len(), 2);
    let before = kernel::dump_all_kernel_tables(&world.db).await.unwrap();
    // Upgrade a target whose old max-only frontier already skipped a header.
    sqlx::query("DELETE FROM kernel_legacy_sql_events WHERE source_id='old-writer-gap'")
        .execute(world.db.write_pool())
        .await
        .unwrap();
    sqlx::raw_sql("DROP TABLE kernel_legacy_sql_progress; CREATE TABLE kernel_legacy_sql_progress(singleton INTEGER PRIMARY KEY,scanned_seq INTEGER NOT NULL); INSERT INTO kernel_legacy_sql_progress SELECT 1,max(seq) FROM content_events WHERE type='kernel.legacy_recorded.v1'").execute(world.db.write_pool()).await.unwrap();
    assert!(kernel::verify_v2_ready(&world.db).await.is_err());
    kernel::prepare_v2_database(&world.db).await.unwrap();
    assert_eq!(
        before,
        kernel::dump_all_kernel_tables(&world.db).await.unwrap()
    );
    world.db.close().await;
}

#[tokio::test]
async fn kernel_v2_rehome_refuses_comments_and_bearers_without_partial_moves() {
    let w = world().await;
    install_comment_carrier(&w).await;
    let root = call(&w,"create_record",json!({"type":"Annotation","kind":"comment","body":"Thread","links":[{"target_id":w.first,"relationship":"part_of"}]})).await.unwrap();
    let reply = call(&w,"create_record",json!({"type":"Annotation","kind":"comment","body":"Reply","links":[{"target_id":root["id"],"relationship":"part_of"}]})).await.unwrap();
    let destination = kernel::create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.admin, "manage")]),
        &w.admin,
    )
    .await
    .unwrap();
    for id in [
        w.first.as_str(),
        root["id"].as_str().unwrap(),
        reply["id"].as_str().unwrap(),
    ] {
        let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
        let err = kernel::rehome_record_as(&w.db, &w.admin, id, &destination)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("requires the atomic member move"),
            "{err}"
        );
        assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    }
    kernel::rehome_record_as(&w.db, &w.admin, &w.second, &destination)
        .await
        .unwrap();
    assert_eq!(
        kernel::read_record_as(&w.db, &w.admin, &w.second)
            .await
            .unwrap()
            .unwrap()
            .home_id,
        destination
    );
}

#[cfg(all(unix, feature = "v2-kernel-probe"))]
#[tokio::test]
async fn kernel_v2_vault_uses_authorized_views_and_keeps_large_bodies_whole() {
    let w = world().await;
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &[(&w.admin, "manage"), (&w.viewer, "view")],
    )
    .await
    .unwrap();
    let body = "visible long body\n".repeat(24_000);
    call_as(
        &w,
        "acct:admin",
        "update_record",
        json!({"id":w.first,"body_set":body}),
    )
    .await
    .unwrap();
    let before: (i64, i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM content_events),(SELECT count(*) FROM meta_events),(SELECT next_act FROM act_state WHERE singleton=1)").fetch_one(w.db.pool()).await.unwrap();
    let snapshot = crate::query::sql::projection_snapshot(
        &w.db,
        crate::query::QueryPrincipal::authenticated("acct:viewer", true),
    )
    .await
    .unwrap();
    assert_eq!(
        snapshot.records[&w.first].body.as_deref(),
        Some(body.as_str())
    );
    assert_eq!(
        snapshot.records["native:root"].name.as_deref(),
        Some("Native workspace")
    );
    assert!(!snapshot.records.contains_key(&w.hidden));
    for id in snapshot
        .records
        .keys()
        .filter(|id| id.as_str() != "native:root")
    {
        assert!(
            kernel::read_record_as(&w.db, &w.viewer, id)
                .await
                .unwrap()
                .is_some(),
            "{id}"
        );
    }
    assert!(snapshot
        .links
        .iter()
        .all(|l| snapshot.records.contains_key(&l.source_id)
            && snapshot.records.contains_key(&l.target_id)));
    let after: (i64, i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM content_events),(SELECT count(*) FROM meta_events),(SELECT next_act FROM act_state WHERE singleton=1)").fetch_one(w.db.pool()).await.unwrap();
    assert_eq!(before, after);
    let admin = crate::query::sql::projection_snapshot(
        &w.db,
        crate::query::QueryPrincipal::authenticated("acct:admin", true),
    )
    .await
    .unwrap();
    assert!(admin.records.contains_key(&w.hidden));
    // A pooled owner read must not seed the member's next snapshot.
    let again = crate::query::sql::projection_snapshot(
        &w.db,
        crate::query::QueryPrincipal::authenticated("acct:viewer", true),
    )
    .await
    .unwrap();
    assert!(!again.records.contains_key(&w.hidden));
}

#[cfg(all(unix, feature = "v2-kernel-probe"))]
#[tokio::test]
async fn kernel_v2_vault_publishes_threads_and_purges_revoked_bearers() {
    let w = world().await;
    install_comment_carrier(&w).await;
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &[(&w.admin, "manage"), (&w.viewer, "view")],
    )
    .await
    .unwrap();
    call_as(
        &w,
        "acct:admin",
        "update_record",
        json!({"id":w.first,"body_set":"alpha brave revised passage"}),
    )
    .await
    .unwrap();
    let root = call_as(&w,"acct:admin","create_record",json!({"type":"Annotation","kind":"comment","body":"visible thread content","links":[{"relationship":"part_of","target_id":w.first}],"target":anchored_target(&w.first,"revised",12,19)})).await.unwrap();
    let root_id = root["id"].as_str().unwrap();
    let reply=call(&w,"create_record",json!({"type":"Annotation","kind":"comment","body":"visible reply content","links":[{"relationship":"part_of","target_id":root_id}]})).await.unwrap();
    let hidden=call_as(&w,"acct:admin","create_record",json!({"type":"Annotation","kind":"comment","body":"secret thread content","links":[{"relationship":"part_of","target_id":w.hidden}]})).await.unwrap();
    let source = crate::query::sql::projection_snapshot(
        &w.db,
        crate::query::QueryPrincipal::authenticated("acct:viewer", true),
    )
    .await
    .unwrap();
    assert_eq!(source.records[root_id].anchors.len(), 1);
    assert!(source.records.contains_key(reply["id"].as_str().unwrap()));
    assert!(!source.records.contains_key(hidden["id"].as_str().unwrap()));
    let folder = tempfile::tempdir().unwrap();
    let mut publisher = crate::markdown_vault::Publisher::open(folder.path()).unwrap();
    assert!(publisher.cycle(&source).unwrap().is_empty());
    fn text(path: &std::path::Path) -> String {
        let mut result = String::new();
        for entry in std::fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            if entry.file_name() == ".native" {
                continue;
            }
            if entry.file_type().unwrap().is_dir() {
                result.push_str(&text(&entry.path()));
            } else {
                result.push_str(&std::fs::read_to_string(entry.path()).unwrap());
            }
        }
        result
    }
    let output = text(folder.path());
    assert!(output.contains("visible thread content"));
    assert!(output.contains("visible reply content"));
    assert!(output.contains("revised"));
    assert!(!output.contains("secret thread content"));
    let home = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    kernel::replace_home_policy(&w.db, &w.admin, &home, &[])
        .await
        .unwrap();
    let revoked = crate::query::sql::projection_snapshot(
        &w.db,
        crate::query::QueryPrincipal::authenticated("acct:viewer", true),
    )
    .await
    .unwrap();
    assert!(!revoked.records.contains_key(root_id));
    assert!(!revoked.records.contains_key(reply["id"].as_str().unwrap()));
    assert!(publisher.cycle(&revoked).unwrap().is_empty());
    let output = text(folder.path());
    assert!(!output.contains("visible thread content"));
    assert!(!output.contains("visible reply content"));
}

#[cfg(all(unix, feature = "v2-kernel-probe"))]
#[tokio::test]
async fn kernel_v2_vault_collects_on_physical_read_only_and_refuses_unknown_accounts() {
    use sqlx::Connection;
    let w = world().await;
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(w._dir.path().join("v2.db"))
        .read_only(true);
    let mut connection = sqlx::SqliteConnection::connect_with(&options)
        .await
        .unwrap();
    let schema: Vec<(String, Option<String>)> =
        sqlx::query_as("SELECT name,sql FROM sqlite_master ORDER BY name")
            .fetch_all(&mut connection)
            .await
            .unwrap();
    let source = crate::markdown_vault::kernel_v2::snapshot_on(&mut connection, "acct:admin")
        .await
        .unwrap();
    assert!(source.records.contains_key(&w.first));
    let after: Vec<(String, Option<String>)> =
        sqlx::query_as("SELECT name,sql FROM sqlite_master ORDER BY name")
            .fetch_all(&mut connection)
            .await
            .unwrap();
    assert_eq!(schema, after);
    assert!(sqlx::query("UPDATE act_state SET next_act=next_act")
        .execute(&mut connection)
        .await
        .is_err());
    connection.close().await.unwrap();
    assert!(crate::query::sql::projection_snapshot(
        &w.db,
        crate::query::QueryPrincipal::authenticated("unknown", true)
    )
    .await
    .is_err());
    // Known identity with no root View cannot inspect imported root metadata.
    assert!(crate::query::sql::projection_snapshot(
        &w.db,
        crate::query::QueryPrincipal::authenticated("acct:viewer", true)
    )
    .await
    .is_err());
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_browser_metadata_sql_never_reads_retained_bundle_payloads() {
    let w = world().await;
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    for id in [&w.first, &w.hidden] {
        for (event_type, payload) in [
            (
                "v1.snapshot_provenance",
                json!({"policy_anchor":null,"original_home":null}),
            ),
            (
                "record.updated",
                json!({"id":id,"body":"bundle".repeat(140_000)}),
            ),
        ] {
            kernel::import_event_as(
                &w.db,
                &host,
                id,
                &kernel::LegacyEvent {
                    source: None,
                    id: uuid::Uuid::new_v4().to_string(),
                    event_type: event_type.into(),
                    created_at: "2026-10-19T00:00:00Z".into(),
                    actor: None,
                    run_key: None,
                    payload,
                },
            )
            .await
            .unwrap();
        }
    }
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    // Exact alpha index projection: no body is requested. Its home lookup
    // must seek the small provenance header, not parse other legacy payloads.
    let out=call(&w,"query_sql",json!({"sql":"SELECT id, type, kind, name, summary, home_id, lifecycle, maturity, updated_at, last_activity_at FROM records WHERE deleted_at IS NULL AND id > ?1 ORDER BY id LIMIT 1000","parameters":[{"type":"text","value":""}]})).await.unwrap();
    assert_eq!(out["rows"].as_array().unwrap().len(), 2);
    assert!(!out.to_string().contains(&w.hidden));
    assert!(!out.to_string().contains("bundle"));
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_browser_get_record_enrichment_arguments_are_observational() {
    let w = world().await;
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    let plain = call(
        &w,
        "get_record",
        json!({"ids":[w.first],"children_limit":0}),
    )
    .await
    .unwrap();
    assert!(plain["records"][0].get("suggestions").is_none());
    assert!(plain["records"][0].get("history_summary").is_none());
    for (key, value) in [
        ("suggestions_limit", json!(20)),
        ("suggestions_offset", json!(0)),
        ("citations_limit", json!(20)),
        ("citations_offset", json!(0)),
        ("children_offset", json!(0)),
    ] {
        let mut args = json!({"ids":[w.first,w.hidden],"include_suggestions":true,"include_citations":true,"include_history_summary":true,"children_limit":0});
        args[key] = value;
        let out = call(&w, "get_record", args).await.unwrap();
        let record = &out["records"][0];
        assert_eq!(record["suggestions"], json!([]), "{key}");
        assert_eq!(record["suggestion_count"], 0);
        assert_eq!(record["citations"], json!([]));
        assert_eq!(record["citation_count"], 0);
        assert_eq!(record["children"], json!([]));
        assert_eq!(
            record["history_summary"]["oldest"]["type"],
            "record.created"
        );
        assert_eq!(record["history_summary"]["latest"]["type"], "link.added");
        assert_eq!(
            out["records"][1],
            json!({"id":w.hidden,"status":"not_found"})
        );
    }
    for key in [
        "children_limit",
        "children_offset",
        "suggestions_limit",
        "suggestions_offset",
        "citations_limit",
        "citations_offset",
    ] {
        let mut args = json!({"ids":[w.first]});
        args[key] = json!(-1);
        assert!(call(&w, "get_record", args).await.is_err(), "{key}");
        if key.ends_with("limit") {
            let mut args = json!({"ids":[w.first]});
            args[key] = json!(1001);
            assert!(call(&w, "get_record", args).await.is_err(), "{key}");
        }
    }
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_browser_query_order_filter_and_link_pipeline_arguments() {
    let w = world().await;
    for order in [
        "name_asc",
        "updated_desc",
        "created_desc",
        "last_activity_desc",
    ] {
        let out=call(&w,"query_record",json!({"steps":[{"step":"filter","types":["Document"],"include_archived":false}],"order":order,"limit":1,"offset":0})).await.unwrap();
        assert_eq!(out["total"], 2, "{order}");
        assert_eq!(out["returned"], 1);
        assert_eq!(out["has_more"], true);
        assert!(!out.to_string().contains(&w.hidden));
        let next=call(&w,"query_record",json!({"steps":[{"step":"filter","types":["Document"]}],"order":order,"limit":1,"offset":1})).await.unwrap();
        assert_ne!(next["records"][0]["id"], out["records"][0]["id"]);
        assert_eq!(next["has_more"], false);
        if order == "name_asc" {
            assert_eq!(out["records"][0]["name"], "Alpha");
            assert_eq!(next["records"][0]["name"], "Beta");
        }
    }
    // Workbench's two-step assignment walk and its three-step people/rejection
    // walks: omitted relationship means all links, not an unknown argument.
    for steps in [
        json!([{"step":"filter","ids":[w.first]},{"step":"traverse","target":"links","direction":"out"}]),
        json!([{"step":"filter","ids":[w.first]},{"step":"traverse","target":"links","direction":"out","relationship":"relates_to"},{"step":"filter","types":["Document"]}]),
    ] {
        let out = call(
            &w,
            "query_record",
            json!({"steps":steps,"order":"name_asc"}),
        )
        .await
        .unwrap();
        assert_eq!(out["total"], 1);
        assert_eq!(out["records"][0]["id"], w.second);
    }
    let revision = kernel::read_record_as(&w.db, &w.admin, &w.second)
        .await
        .unwrap()
        .unwrap()
        .revision;
    kernel::set_archived_as(&w.db, &w.admin, &w.second, true, revision)
        .await
        .unwrap();
    for archived in [false, true] {
        let out=call(&w,"query_record",json!({"steps":[{"step":"filter","types":["Document"],"include_archived":archived}],"order":"name_asc"})).await.unwrap();
        assert_eq!(out["total"], if archived { 2 } else { 1 });
    }
    let out=call(&w,"query_record",json!({"steps":[{"step":"filter","lifecycle":["rejected"],"include_archived":true}],"order":"created_desc"})).await.unwrap();
    assert_eq!(out["records"], json!([]));
    for (key, value) in [
        ("name_contains", json!("Alpha")),
        ("updated_since", json!("2000-01-01T00:00:00Z")),
        ("last_activity_since", json!("2000-01-01T00:00:00Z")),
        ("persistence", json!("enduring")),
    ] {
        let mut filter = json!({"step":"filter","ids":[w.first]});
        filter[key] = value;
        let out = call(
            &w,
            "query_record",
            json!({"steps":[filter],"order":"name_asc"}),
        )
        .await
        .unwrap();
        assert_eq!(out["total"], 1, "{key}");
    }
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_browser_folder_children_structure_and_scoped_search() {
    let w = world().await;
    install_comment_carrier(&w).await;
    let package = crate::v2_standard::document_package();
    let identity = package.identity().unwrap();
    kernel::install_package_as(&w.db, &w.admin, &package)
        .await
        .unwrap();
    kernel::adopt_package_at(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &package,
        Some(&identity),
        &package.declared_reads,
    )
    .await
    .unwrap();
    let home = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let folder = call_as(
        &w,
        "acct:admin",
        "create_record",
        json!({"type":"Collection","kind":"folder","name":"Browser folder","home_id":home}),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut children = Vec::new();
    for name in ["Alpha child", "Beta child"] {
        children.push(call_as(&w,"acct:admin","create_record",json!({"type":"Document","kind":"note","name":name,"body":"scopedneedle","home_id":folder})).await.unwrap()["id"].as_str().unwrap().to_owned());
    }
    let revision = kernel::read_record_as(&w.db, &w.admin, &children[1])
        .await
        .unwrap()
        .unwrap()
        .revision;
    kernel::set_archived_as(&w.db, &w.admin, &children[1], true, revision)
        .await
        .unwrap();
    // Enriched children include archived, while generic folder browse does not.
    for (limit, offset, wanted) in [
        (1, 0, Some(&children[0])),
        (1, 1, Some(&children[1])),
        (0, 0, None),
    ] {
        let out = call(
            &w,
            "get_record",
            json!({"ids":[folder],"children_limit":limit,"children_offset":offset}),
        )
        .await
        .unwrap();
        assert_eq!(out["records"][0]["child_count"], 2);
        if let Some(id) = wanted {
            assert_eq!(out["records"][0]["children"][0]["id"], *id);
        } else {
            assert_eq!(out["records"][0]["children"], json!([]));
        }
    }
    for archived in [false, true] {
        let out=call(&w,"query_record",json!({"steps":[{"step":"filter","home_id":folder,"include_archived":archived}],"order":"name_asc"})).await.unwrap();
        assert_eq!(out["total"], if archived { 2 } else { 1 });
        let out=call(&w,"get_structure",json!({"root_id":folder,"max_depth":1,"max_children_per_node":1,"include_archived":archived})).await.unwrap();
        assert_eq!(out["nodes"].as_array().unwrap().len(), 2);
        assert_eq!(out["nodes"][0]["child_count"], if archived { 2 } else { 1 });
        assert!(
            !out.to_string().contains("scopedneedle"),
            "structure must not return bodies"
        );
    }
    let out = call(&w, "open_collection", json!({"id":folder}))
        .await
        .unwrap();
    assert_eq!(out["status"], "opened");
    assert_eq!(out["input"]["records"].as_array().unwrap().len(), 1);
    let outside = call_as(&w,"acct:admin","create_record",json!({"type":"Document","kind":"note","name":"scopedneedle","body":"scopedneedle","home_id":home})).await.unwrap()["id"].clone();
    let out = call(
        &w,
        "search",
        json!({"query":"scopedneedle","scope":folder,"include_archived":true,"limit":1}),
    )
    .await
    .unwrap();
    assert_eq!(out["hits"].as_array().unwrap().len(), 1);
    assert_eq!(out["scope"], folder);
    assert_eq!(out["total"], 1);
    assert_ne!(
        out["hits"][0]["id"], outside,
        "a better-ranked out-of-scope title cannot displace a scoped hit"
    );
    assert!(children.iter().any(|id| out["hits"][0]["id"] == *id));
    let hidden = call(&w, "get_structure", json!({"root_id":w.hidden}))
        .await
        .unwrap_err()
        .to_string();
    let missing = call(&w, "get_structure", json!({"root_id":"missing"}))
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(hidden, missing);
    for field in ["max_depth", "max_children_per_node"] {
        let mut args = json!({"root_id":folder});
        args[field] = json!(-1);
        assert!(call(&w, "get_structure", args).await.is_err());
    }
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_browser_suggestion_and_citation_windows_return_real_records() {
    let w = world().await;
    install_comment_carrier(&w).await;
    let home = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let mut expected = std::collections::BTreeMap::new();
    for kind in ["suggestion", "citation"] {
        let mut ids = Vec::new();
        for name in ["First", "Second"] {
            let fields = json!({"title":name,"v1_type":"Annotation","v1_kind":kind});
            let id = kernel::create_json_as(
                &w.db,
                &w.admin,
                crate::v2_standard::v1_compat::FAMILY,
                "record",
                &fields.to_string(),
                &home,
            )
            .await
            .unwrap();
            kernel::generic_links::add_generic_link_as(
                &w.db, &w.admin, &id, &w.first, "part_of", None,
            )
            .await
            .unwrap();
            ids.push(id);
        }
        expected.insert(kind, ids);
    }
    for offset in [0, 1, 2] {
        let out=call(&w,"get_record",json!({"ids":[w.first],"children_limit":0,"include_suggestions":true,"suggestions_limit":1,"suggestions_offset":offset,"include_citations":true,"citations_limit":1,"citations_offset":offset})).await.unwrap();
        for kind in ["suggestion", "citation"] {
            let record = &out["records"][0];
            assert_eq!(record[format!("{kind}_count")], 2);
            let page = &record[format!("{kind}s")];
            if offset < 2 {
                assert_eq!(page[0]["id"], expected[kind][offset]);
            } else {
                assert_eq!(*page, json!([]));
            }
        }
    }
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_browser_imported_facets_and_vocabulary_arguments() {
    let w = world().await;
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let rows = [
        (
            "vocabularies",
            json!({"id":"voc:priority","name":"priority"}),
        ),
        (
            "vocabulary_values",
            json!({"id":"vv:low","vocabulary_id":"voc:priority","value":"low","status":"active","gloss":null,"ordinal":0,"terminality":"open","metadata":"{}","alias_of":null}),
        ),
        (
            "vocabulary_values",
            json!({"id":"vv:alias","vocabulary_id":"voc:priority","value":"small","status":"active","gloss":null,"ordinal":1,"terminality":"open","metadata":"{}","alias_of":"vv:low"}),
        ),
        (
            "vocabulary_values",
            json!({"id":"vv:old","vocabulary_id":"voc:priority","value":"old","status":"deprecated","gloss":null,"ordinal":2,"terminality":"open","metadata":"{}","alias_of":null}),
        ),
        (
            "schema_config",
            json!({"id":"schema:priority","layer":"pack","name":"Priority","created_at":"2026-10-19T00:00:00Z","applies_to_collection_id":null,"version_lineage":null,"data":json!({"shapes":{"Document:note":{"facets":{"priority":{"type":"string","vocab":"rec:voc:priority"}}}}}).to_string()}),
        ),
        (
            "schema_config",
            json!({"id":"schema:hidden","layer":"user","name":"Hidden schema","created_at":"2026-10-19T00:00:01Z","applies_to_collection_id":w.hidden,"version_lineage":null,"data":json!({"shapes":{"Document:note":{"facets":{"secret-schema":{"type":"string"}}}}}).to_string()}),
        ),
    ];
    let rows = rows
        .into_iter()
        .map(|(section, row)| kernel::v1_state::ImportedState {
            section: section.into(),
            source_id: row["id"].as_str().unwrap().into(),
            origin: "synthetic-browser".into(),
            value_json: Some(row.to_string()),
            account_principal: None,
            record_id: None,
            observed_at: "2026-10-19T00:00:00Z".into(),
            snapshot: json!({}),
        })
        .collect::<Vec<_>>();
    kernel::v1_state::import_state_batch_as(&w.db, &host, &rows)
        .await
        .unwrap();
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    for args in [
        json!({"record_id":w.first}),
        json!({"type":"Document","kind":"note"}),
        json!({"type":"Document"}),
    ] {
        let out = call(&w, "resolve_facets", args).await.unwrap();
        assert!(!out.to_string().contains("secret-schema"));
        assert!(out.get("shape").is_some());
    }
    let out = call(&w, "resolve_facets", json!({"record_id":w.first}))
        .await
        .unwrap();
    assert_eq!(out["shape"]["priority"]["vocab"], "rec:voc:priority");
    for aliases in [true, false] {
        let out=call(&w,"manage_vocabularies",json!({"action":"list_values","vocabulary":"priority","status":"active","resolve_aliases":aliases})).await.unwrap();
        assert_eq!(out["values"].as_array().unwrap().len(), 2);
        assert_eq!(out["vocab_ref"], "rec:voc:priority");
        assert_eq!(out["values"][1].get("canonical").is_some(), aliases);
    }
    let out = call(
        &w,
        "suggest_facet_values",
        json!({"record_id":w.first,"facet_key":"priority"}),
    )
    .await
    .unwrap();
    assert_eq!(out["suggestions"].as_array().unwrap().len(), 2);
    let out = call(
        &w,
        "suggest_facet_values",
        json!({"type":"Document","kind":"note","facet_key":"absent"}),
    )
    .await
    .unwrap();
    assert_eq!(out["suggestions"], json!([]));
    assert_eq!(out["vocabulary"], Value::Null);
    for name in ["resolve_facets", "suggest_facet_values"] {
        let mut args = json!({"record_id":w.hidden});
        if name == "suggest_facet_values" {
            args["facet_key"] = json!("priority");
        }
        let hidden = call(&w, name, args.clone()).await.unwrap_err().to_string();
        args["record_id"] = json!("missing");
        assert_eq!(hidden, call(&w, name, args).await.unwrap_err().to_string());
    }
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_browser_global_history_and_read_activity_are_write_free() {
    let w = world().await;
    let own_key = "scout-chair-a748b2";
    kernel::open_run_as(&w.db, &w.viewer, own_key)
        .await
        .unwrap();
    let other_key = "scout-chair-b748b2";
    kernel::open_run_as(&w.db, &w.admin, other_key)
        .await
        .unwrap();
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let legacy_key = "scout-chair-d748b2";
    for (id, key, parent) in [
        (&w.first, legacy_key, None),
        (&w.hidden, "scout-chair-e748b2", Some(legacy_key)),
        (&w.second, "scout-chair-f748b2", Some("scout-chair-e748b2")),
    ] {
        kernel::import_event_as(
            &w.db,
            &host,
            id,
            &kernel::LegacyEvent {
                source: Some(json!({"origin":"synthetic-browser","stream":"content_events","metadata":{"record_id":id,"parent_key":parent},"subjects":[id]})),
                id: uuid::Uuid::new_v4().to_string(),
                event_type: "record.updated".into(),
                payload: json!({"body":"Historical browser body"}),
                created_at: "2026-10-19T00:00:00Z".into(),
                actor: Some("acct:viewer".into()),
                run_key: Some(key.into()),
            },
        )
        .await
        .unwrap();
    }
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    let all = call(
        &w,
        "get_history",
        json!({"limit":1,"order":"newest_first","detail":"metadata"}),
    )
    .await
    .unwrap();
    assert_eq!(all["events"].as_array().unwrap().len(), 1);
    assert!(!all.to_string().contains(&w.hidden));
    let next = call(
        &w,
        "get_history",
        json!({"limit":1,"after_local_seq":all["next_after_local_seq"],"order":"newest_first"}),
    )
    .await
    .unwrap();
    assert_ne!(
        next["events"][0]["local_seq"],
        all["events"][0]["local_seq"]
    );
    for children in [false, true] {
        let out = call(
            &w,
            "get_history",
            json!({"for_run":legacy_key,"include_child_runs":children,"detail":"full","limit":50}),
        )
        .await
        .unwrap();
        assert!(!out.to_string().contains(&w.hidden));
        assert_eq!(
            out["events"].as_array().unwrap().len(),
            if children { 2 } else { 1 }
        );
        if children {
            let child = out["events"]
                .as_array()
                .unwrap()
                .iter()
                .find(|event| event["run_key"] == "scout-chair-f748b2")
                .unwrap();
            assert_eq!(child["parent_key"], "scout-chair-e748b2");
        }
        assert!(
            !out["events"].as_array().unwrap().is_empty(),
            "run history contains the visible retained event"
        );
        let activity = call(
            &w,
            "get_run_activity",
            json!({"for_run":own_key,"include_child_runs":children}),
        )
        .await
        .unwrap();
        assert_eq!(activity["read_activity"], json!([]));
        assert_eq!(activity["availability"]["status"], "unavailable");
    }
    let hidden = call(&w, "get_run_activity", json!({"for_run":other_key}))
        .await
        .unwrap_err()
        .to_string();
    let absent = call(
        &w,
        "get_run_activity",
        json!({"for_run":"scout-chair-c748b2"}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(hidden, absent);
    assert!(call(
        &w,
        "get_run_activity",
        json!({"for_run":own_key,"limit":10})
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("discovery-only"));
    assert!(call(&w, "get_history", json!({"include_child_runs":true}))
        .await
        .is_err());
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_browser_neutral_root_aliases_share_real_children_and_visibility() {
    let w = world().await;
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    kernel::import_home_policy_as(&w.db, &host, KERNEL_ROOT_ID, &[(&w.viewer, "view")])
        .await
        .unwrap();
    let id = kernel::create_as(
        &w.db,
        &w.admin,
        "fixture.mcp",
        "note",
        json!({"title":"Root child"}).as_object().unwrap(),
        KERNEL_ROOT_ID,
    )
    .await
    .unwrap();
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    for root in [KERNEL_ROOT_ID, "native:root"] {
        let out = call(&w, "get_record", json!({"ids":[root],"children_limit":20}))
            .await
            .unwrap();
        assert_eq!(out["records"][0]["kernel_v2"]["virtual_root"], true);
        assert!(out["records"][0]["body"].is_null());
        assert!(out["records"][0]["children"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["id"] == id));
        let out = call(
            &w,
            "query_record",
            json!({"steps":[{"step":"filter","home_id":root}],"order":"name_asc"}),
        )
        .await
        .unwrap();
        assert!(out["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["id"] == id));
        let out = call(&w, "get_structure", json!({"root_id":root,"max_depth":1}))
            .await
            .unwrap();
        assert!(out["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["id"] == id));
    }
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    kernel::import_home_policy_as(&w.db, &host, KERNEL_ROOT_ID, &[])
        .await
        .unwrap();
    let out = call(
        &w,
        "get_record",
        json!({"ids":[KERNEL_ROOT_ID,"native:root"]}),
    )
    .await
    .unwrap();
    assert!(out["records"]
        .as_array()
        .unwrap()
        .iter()
        .all(|v| v["status"] == "not_found"));
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_browser_upgrade_backfills_early_provenance_on_complete_frontier() {
    let w = world().await;
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let boundary = kernel::hq::v1_import_home_id(&w.first);
    kernel::hq::import_home_as(
        &w.db,
        &host,
        &boundary,
        &w.first,
        KERNEL_ROOT_ID,
        &w.admin,
        Some(&[(&w.viewer, "view")]),
    )
    .await
    .unwrap();
    kernel::import_event_as(
        &w.db,
        &host,
        &w.first,
        &kernel::LegacyEvent {
            source: None,
            id: "early-private-provenance".into(),
            event_type: "v1.snapshot_provenance".into(),
            payload: json!({"policy_anchor":w.first,"original_home":w.second}),
            created_at: "2026-10-19T00:00:00Z".into(),
            actor: None,
            run_key: None,
        },
    )
    .await
    .unwrap();
    sqlx::query("UPDATE kernel_records SET home_id=? WHERE id=?")
        .bind(&boundary)
        .bind(&w.first)
        .execute(w.db.write_pool())
        .await
        .unwrap();
    // Exact old projection state: the old scanner was caught up, but did not
    // index the early envelope because its payload lacked record_id.
    sqlx::query("DELETE FROM kernel_legacy_sql_events WHERE source_id='early-private-provenance'")
        .execute(w.db.write_pool())
        .await
        .unwrap();
    sqlx::raw_sql("ALTER TABLE kernel_legacy_sql_progress DROP COLUMN provenance_headers")
        .execute(w.db.write_pool())
        .await
        .unwrap();
    let (scanned,head):(i64,i64)=sqlx::query_as("SELECT scanned_seq,(SELECT max(seq) FROM content_events WHERE type='kernel.legacy_recorded.v1') FROM kernel_legacy_sql_progress WHERE singleton=1")
        .fetch_one(w.db.pool()).await.unwrap();
    assert_eq!(scanned, head);
    let before_events: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    assert!(kernel::verify_v2_ready(&w.db)
        .await
        .unwrap_err()
        .to_string()
        .contains("provenance header format"));
    kernel::prepare_v2_database(&w.db).await.unwrap();
    kernel::verify_v2_ready(&w.db).await.unwrap();
    let sql=call(&w,"query_sql",json!({"sql":"SELECT home_id FROM records WHERE id=?1","parameters":[{"type":"text","value":w.first}]})).await.unwrap();
    assert_eq!(sql["rows"][0]["home_id"], w.second);
    let get = call(&w, "get_record", json!({"ids":[w.first,w.second]}))
        .await
        .unwrap();
    assert_eq!(get["records"][0]["home_id"], w.second);
    assert_eq!(get["records"][1]["children"][0]["id"], w.first);
    let listing = call(
        &w,
        "query_record",
        json!({"steps":[{"step":"filter","home_id":w.second}],"order":"name_asc"}),
    )
    .await
    .unwrap();
    assert_eq!(listing["records"][0]["id"], w.first);
    let search = call(&w, "search", json!({"query":"revised","scope":w.second}))
        .await
        .unwrap();
    assert!(search["hits"]
        .as_array()
        .unwrap()
        .iter()
        .any(|h| h["id"] == w.first));
    let ready = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::prepare_v2_database(&w.db).await.unwrap();
    assert_eq!(ready, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    assert_eq!(
        before_events,
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events")
            .fetch_one(w.db.pool())
            .await
            .unwrap()
    );
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_browser_artifact_windows_accept_active_kind_aliases() {
    let w = world().await;
    install_comment_carrier(&w).await;
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let mut state = Vec::new();
    state.push(kernel::v1_state::ImportedState {
        section: "vocabularies".into(),
        source_id: "voc:kind:Annotation".into(),
        origin: "synthetic-browser".into(),
        value_json: Some(json!({"id":"voc:kind:Annotation","name":"kind:Annotation"}).to_string()),
        account_principal: None,
        record_id: None,
        observed_at: "2026-10-19T00:00:00Z".into(),
        snapshot: json!({}),
    });

    for (token, alias) in [("suggestion", "advice"), ("citation", "reference")] {
        let vocab = "voc:kind:Annotation";
        let canonical = format!("vv:{vocab}:{token}");
        for (id, value, alias_of, status) in [
            (canonical.clone(), token, None, "active"),
            (
                format!("vv:{vocab}:{alias}"),
                alias,
                Some(canonical.clone()),
                "deprecated",
            ),
        ] {
            state.push(kernel::v1_state::ImportedState{section:"vocabulary_values".into(),source_id:id.clone(),origin:"synthetic-browser".into(),value_json:Some(json!({"id":id,"vocabulary_id":vocab,"value":value,"status":status,"alias_of":alias_of,"terminality":"open","ordinal":0,"metadata":"{}","gloss":null}).to_string()),account_principal:None,record_id:None,observed_at:"2026-10-19T00:00:00Z".into(),snapshot:json!({})});
        }
        let home = kernel::read_record_as(&w.db, &w.admin, &w.first)
            .await
            .unwrap()
            .unwrap()
            .home_id;
        let id = kernel::create_json_as(
            &w.db,
            &w.admin,
            crate::v2_standard::v1_compat::FAMILY,
            "record",
            &json!({"title":alias,"v1_type":"Annotation","v1_kind":alias}).to_string(),
            &home,
        )
        .await
        .unwrap();
        kernel::generic_links::add_generic_link_as(&w.db, &w.admin, &id, &w.first, "part_of", None)
            .await
            .unwrap();
    }
    kernel::v1_state::import_state_batch_as(&w.db, &host, &state)
        .await
        .unwrap();
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    let get = call(
        &w,
        "get_record",
        json!({"ids":[w.first],"include_suggestions":true,"include_citations":true}),
    )
    .await
    .unwrap();
    assert_eq!(get["records"][0]["suggestion_count"], 1);
    assert_eq!(get["records"][0]["suggestions"][0]["kind"], "advice");
    assert_eq!(get["records"][0]["citation_count"], 1);
    assert_eq!(get["records"][0]["citations"][0]["kind"], "reference");
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_browser_filing_traversals_refuse_link_direction() {
    let w = world().await;
    for target in ["children", "parents"] {
        for direction in ["in", "out", "both"] {
            let error=call(&w,"query_record",json!({"steps":[{"step":"filter","ids":[w.first]},{"step":"traverse","target":target,"direction":direction}],"order":"name_asc"})).await.unwrap_err().to_string();
            assert!(
                error.contains("'relationship' and 'direction' apply to target 'links' only"),
                "{error}"
            );
        }
    }
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_browser_history_filtered_page_keeps_continuation() {
    let w = world().await;
    let first_seq: i64 = sqlx::query_scalar("SELECT created_seq FROM kernel_records WHERE id=?")
        .bind(&w.first)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let private: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
        .bind(&w.hidden)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let page = super::sql::with_read_session(
        &w.db,
        &w.viewer,
        &[
            ("content_events", "local_seq"),
            ("content_events", "record_id"),
            ("content_events", "run_key"),
            ("content_events", "parent_key"),
        ],
        async {
            // Freeze header selection at the old authority snapshot, then revoke
            // this subject before the independent, fail-closed hydration snapshot.
            kernel::rehome_record_as(&w.db, &w.admin, &w.first, &private).await?;
            super::read_surface::history_in_session(
                &w.db,
                &w.viewer,
                json!({"after_local_seq":first_seq-1,"limit":1,"order":"oldest_first"}),
            )
            .await
        },
    )
    .await
    .unwrap();
    assert_eq!(page["events"], json!([]));
    assert_eq!(page["next_after_local_seq"], first_seq);
    let next = call(
        &w,
        "get_history",
        json!({"after_local_seq":page["next_after_local_seq"],"limit":1}),
    )
    .await
    .unwrap();
    assert!(!next["events"].as_array().unwrap().is_empty());
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_browser_hq_scale_batch_get_and_global_history_share_staging() {
    let w = world().await;
    // Projection-only synthetic load, as in S8: 10k complete native note rows
    // in a shared home, plus the world's private note. No private data input.
    sqlx::query("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<10000) INSERT INTO kernel_records(id,home_id,owner_id,primary_type,kind,accession,pin_family,pin_version,pin_digest,interpreter,created_seq,created_at) SELECT printf('browser-scale:%05d',x),r.home_id,r.owner_id,r.primary_type,r.kind,printf('browser-scale:%05d',x),r.pin_family,r.pin_version,r.pin_digest,r.interpreter,r.created_seq,r.created_at FROM n CROSS JOIN kernel_records r WHERE r.id=?")
        .bind(&w.first).execute(w.db.write_pool()).await.unwrap();
    sqlx::query("INSERT INTO kernel_record_fields SELECT r.id,f.name,CASE WHEN f.name='title' THEN json_quote(r.id) ELSE f.value_json END,f.created_seq FROM kernel_records r CROSS JOIN kernel_record_fields f WHERE r.id LIKE 'browser-scale:%' AND f.record_id=?")
        .bind(&w.first).execute(w.db.write_pool()).await.unwrap();
    kernel::ensure_record_metadata(&w.db).await.unwrap();
    // A thousand real update events on distinct subjects makes the global
    // window exercise per-subject disclosure rather than a single cached note.
    for x in 1..=1000 {
        kernel::revise_as(
            &w.db,
            &w.admin,
            &format!("browser-scale:{x:05}"),
            json!({"body":"Synthetic benchmark update"})
                .as_object()
                .unwrap(),
        )
        .await
        .unwrap();
    }
    let ids = (1..=100)
        .map(|x| format!("browser-scale:{x:05}"))
        .collect::<Vec<_>>();
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    if std::env::var_os("NATIVE_CE_BENCH_UNSHARED").is_some() {
        let started = std::time::Instant::now();
        let (unshared, stats) = super::sql::measured(super::get_record_in_session(
            &w.db,
            &w.viewer,
            json!({"ids":ids,"children_limit":0}),
        ))
        .await;
        let elapsed = started.elapsed();
        assert_eq!(unshared.unwrap()["records"].as_array().unwrap().len(), 100);
        assert_eq!(stats.installations, 300);
        eprintln!("BROWSER_READ_BENCH unshared_get_record ids=100 children_limit=0 visible=10002 elapsed_ms={:.3} installations={}",elapsed.as_secs_f64()*1000.0,stats.installations);
    }
    for children_limit in [0, 50] {
        let started = std::time::Instant::now();
        let (get, stats) = super::sql::measured(call(
            &w,
            "get_record",
            json!({"ids":ids,"children_limit":children_limit}),
        ))
        .await;
        let elapsed = started.elapsed();
        let get = get.unwrap();
        assert_eq!(get["records"].as_array().unwrap().len(), 100);
        assert!(get["records"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["status"] == "found"));
        assert_eq!(stats.installations, 1, "{stats:?}");
        assert_eq!(
            stats.staged_records, 100,
            "Get stages its requested notes, not unrelated workspace metadata"
        );
        eprintln!("BROWSER_READ_BENCH get_record ids=100 children_limit={children_limit} visible=10002 elapsed_ms={:.3} installations={}",elapsed.as_secs_f64()*1000.0,stats.installations);
    }
    let started = std::time::Instant::now();
    let (history, stats) = super::sql::measured(call(
        &w,
        "get_history",
        json!({"limit":1000,"order":"newest_first","detail":"metadata"}),
    ))
    .await;
    let elapsed = started.elapsed();
    assert_eq!(history.unwrap()["events"].as_array().unwrap().len(), 1000);
    assert_eq!(stats.installations, 1, "{stats:?}");
    eprintln!("BROWSER_READ_BENCH global_history limit=1000 distinct_subjects=1000 visible=10002 elapsed_ms={:.3} installations={}",elapsed.as_secs_f64()*1000.0,stats.installations);
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_browser_shared_staging_is_caller_bound_and_cancellation_safe() {
    let w = world().await;
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    super::sql::with_read_session(&w.db, &w.viewer, &[("records", "id")], async {
        let error = super::sql::query_sql(
            &w.db,
            &w.admin,
            json!({"sql":"SELECT id FROM records LIMIT 1"}),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("composed SQL read caller/database differs"));
        let error = super::sql::query_sql(
            &w.db,
            &w.viewer,
            json!({"sql":"SELECT body FROM records LIMIT 1"}),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("exceeds declared relations/columns"));
        Ok(())
    })
    .await
    .unwrap();
    let ready = std::sync::Arc::new(tokio::sync::Notify::new());
    let task = {
        let db = w.db.clone();
        let actor = w.viewer.clone();
        let ready = ready.clone();
        tokio::spawn(async move {
            super::sql::with_read_session(&db, &actor, &[("records", "id")], async {
                ready.notify_one();
                std::future::pending::<Result<()>>().await
            })
            .await
        })
    };
    ready.notified().await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let result = call(
        &w,
        "query_sql",
        json!({"sql":"SELECT id FROM records ORDER BY id"}),
    )
    .await
    .unwrap();
    assert_eq!(result["row_count"], 2);
    assert!(!result.to_string().contains(&w.hidden));
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    // A retained SQL session must not consume ordinary helper capacity. With
    // every ordinary slot occupied, its own staging/query still completes.
    let mut ordinary = Vec::new();
    for _ in 0..w.db.write_pool().options().get_max_connections() {
        ordinary.push(w.db.write_pool().acquire().await.unwrap());
    }
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        super::sql::with_read_session(&w.db, &w.viewer, &[("records", "id")], async {
            let out = super::sql::query_sql(
                &w.db,
                &w.viewer,
                json!({"sql":"SELECT id FROM records ORDER BY id"}),
            )
            .await?;
            assert_eq!(out["row_count"], 2);
            Ok(())
        }),
    )
    .await
    .expect("composed SQL must not wait for an ordinary pool slot")
    .unwrap();
    drop(ordinary);
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_browser_batched_history_preserves_record_disclosure_and_payloads() {
    let w = world().await;
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    for id in [&w.first, &w.hidden] {
        kernel::import_event_as(&w.db,&host,id,&kernel::LegacyEvent {
            source:Some(json!({"origin":"synthetic-history","stream":"content_events","metadata":{"record_id":id},"subjects":[id]})),
            id:uuid::Uuid::new_v4().to_string(),event_type:"record.updated".into(),
            payload:json!({"body":"Synthetic retained body","related_record_id":w.hidden}),
            created_at:"2026-10-19T00:00:00Z".into(),actor:Some("acct:viewer".into()),run_key:None,
        }).await.unwrap();
    }
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    for detail in ["metadata", "full"] {
        let global = call(&w, "get_history", json!({"limit":1000,"detail":detail}))
            .await
            .unwrap();
        assert!(!global.to_string().contains(&w.hidden));
        assert!(!global["events"].as_array().unwrap().is_empty());
        for event in global["events"].as_array().unwrap() {
            let record = call(
                &w,
                "get_history",
                json!({"record_id":event["record_id"],"detail":detail,"limit":1000}),
            )
            .await
            .unwrap();
            let ordinary = record["events"]
                .as_array()
                .unwrap()
                .iter()
                .find(|e| e["local_seq"] == event["local_seq"])
                .unwrap();
            for field in [
                "id",
                "record_id",
                "type",
                "actor",
                "actor_name",
                "payload",
                "payload_omitted",
                "changed_fields",
            ] {
                assert_eq!(event[field], ordinary[field], "{detail} {field}");
            }
        }
    }
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    w.db.close().await;
}
/// Collection kind:query envelopes stay body-free past the 500-row page
/// boundary: 600 members open identically with empty and 64KiB bodies, keep
/// the envelope contract (ordering, visibility, facets, summary, maturity,
/// persistence, lifecycle interpretation) and carry no body payload.
#[tokio::test]
async fn kernel_v2_collection_envelope_ignores_member_bodies() {
    let w = world().await;
    // Collection records ride the v1 compat carrier, as in the saved
    // collection fixture below.
    install_comment_carrier(&w).await;
    let home = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    const MEMBERS: usize = 600;
    let mut ids = Vec::with_capacity(MEMBERS);
    for n in 0..MEMBERS {
        let name = format!("Envelope member {n:04}");
        let id = kernel::create_as(
            &w.db,
            &w.admin,
            "fixture.mcp",
            "note",
            json!({"title": name, "body": ""}).as_object().unwrap(),
            &home,
        )
        .await
        .unwrap();
        kernel::observe_facet_as(
            &w.db,
            &w.admin,
            &id,
            &kernel::FacetObservation {
                key: "source".into(),
                value: Some("envelope-probe".into()),
                value_num: None,
                vocab_ref: None,
                as_of: crate::store::now_iso(),
            },
            None,
        )
        .await
        .unwrap();
        ids.push(id);
    }
    // One more candidate the viewer must never see: membership is authorized,
    // so it stays out of every page and never reaches the batched fetch.
    let hidden_home = kernel::read_record_as(&w.db, &w.admin, &w.hidden)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let hidden_probe = kernel::create_as(
        &w.db,
        &w.admin,
        "fixture.mcp",
        "note",
        json!({"title": "Envelope member hidden", "body": ""})
            .as_object()
            .unwrap(),
        &hidden_home,
    )
    .await
    .unwrap();
    ids.push(hidden_probe.clone());
    // A short substring filter names the whole 600-row corpus (including the
    // hidden probe, which authorization still filters) without listing 601
    // UUIDs in the saved definition.
    let query = json!({"v":"0.2","query":{"steps":[{"step":"filter","name_contains":"Envelope member"}],"order":"name_asc"}}).to_string();
    let coll = call_as(
        &w,
        "acct:admin",
        "create_record",
        json!({"type":"Collection","kind":"query","name":"Envelope bodies","home_id":home,"facets":{"query":query},"reason":"envelope body-freedom fixture"}),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    for (key, value) in [
        ("query", query),
        ("input_membership", "all_matching".to_owned()),
    ] {
        kernel::observe_facet_as(
            &w.db,
            &w.admin,
            &coll,
            &kernel::FacetObservation {
                key: key.into(),
                value: Some(value),
                value_num: None,
                vocab_ref: None,
                as_of: crate::store::now_iso(),
            },
            None,
        )
        .await
        .unwrap();
    }
    let (opened_empty, probe_empty) = super::read_surface::envelope_diagnostics::scoped(call(
        &w,
        "open_collection",
        json!({"id": coll}),
    ))
    .await;
    let opened_empty = opened_empty.unwrap();
    assert_eq!(opened_empty["status"], "opened", "{opened_empty:#}");
    // The whole open hydrates zero body bytes: member rows ride the private
    // envelope width, and the one remaining full read (the collection
    // descriptor) carries no body. The definition facet read is the only
    // per-record transaction; member facets arrive in two page-scoped
    // fetches across the 500-row boundary.
    assert_eq!(probe_empty.body_bytes, 0);
    assert_eq!(probe_empty.facet_transactions, 1);
    assert_eq!(probe_empty.envelope_pages, 2);
    let members_empty = opened_empty["input"]["records"].as_array().unwrap();
    // 600 visible members cross the 500-row page boundary; the hidden probe
    // is filtered by authorization, not by paging.
    assert_eq!(members_empty.len(), MEMBERS);
    assert_eq!(members_empty[0]["name"], "Envelope member 0000");
    assert_eq!(members_empty[MEMBERS - 1]["name"], "Envelope member 0599");
    assert!(!opened_empty.to_string().contains(&hidden_probe));
    for record in members_empty {
        for field in [
            "id",
            "type",
            "kind",
            "name",
            "summary",
            "lifecycle_interpretation",
            "maturity",
            "persistence",
            "facets",
        ] {
            assert!(record.get(field).is_some(), "{field}");
        }
        assert!(record.get("body").is_none());
        assert!(record.get("body_digest").is_none());
        assert!(record.get("historical_claims").is_none());
        assert_eq!(record["persistence"], "enduring");
        assert_eq!(record["facets"]["source"], "envelope-probe");
    }
    let bytes_empty = serde_json::to_vec(&opened_empty).unwrap().len();
    // Grow every member body to 64KiB. A body-free envelope must not move.
    let big = "B".repeat(65536);
    for id in ids.iter().filter(|id| *id != &hidden_probe) {
        kernel::revise_as(
            &w.db,
            &w.admin,
            id,
            json!({"body": big}).as_object().unwrap(),
        )
        .await
        .unwrap();
    }
    let (opened_big, probe_big) = super::read_surface::envelope_diagnostics::scoped(call(
        &w,
        "open_collection",
        json!({"id": coll}),
    ))
    .await;
    let opened_big = opened_big.unwrap();
    assert_eq!(probe_big.body_bytes, 0);
    assert_eq!(probe_big.facet_transactions, 1);
    assert_eq!(probe_big.envelope_pages, 2);
    let bytes_big = serde_json::to_vec(&opened_big).unwrap().len();
    eprintln!("collection envelope members={MEMBERS} empty_bytes={bytes_empty} big_bytes={bytes_big} loads={} pages={}", probe_big.body_loads, probe_big.envelope_pages);
    assert!(
        !serde_json::to_string(&opened_big)
            .unwrap()
            .contains(&big[..1024]),
        "no member body bytes reach the envelope"
    );
    assert_eq!(opened_empty, opened_big);
    // Old-style oracle: the exact work the previous resolver performed for
    // real on the same 64KiB fixture — full-hydration paging plus one facet
    // transaction per member. This is the work the envelope no longer pays.
    // The oracle filters by the same substring, so it pages the same corpus.
    let visible_ids: Vec<String> = ids
        .iter()
        .filter(|id| *id != &hidden_probe)
        .cloned()
        .collect();
    let (oracle, probe_oracle) =
        super::read_surface::envelope_diagnostics::scoped(async {
            let mut hydrated = Vec::new();
            let mut offset = 0;
            loop {
                let page = super::read_surface::query_record(
                    &w.db,
                    &w.viewer,
                    json!({"steps":[{"step":"filter","name_contains":"Envelope member"}],"order":"name_asc","limit":500,"offset":offset}),
                )
                .await
                .unwrap();
                let members = page["records"].as_array().unwrap().clone();
                if members.is_empty() {
                    break;
                }
                offset += members.len() as i64;
                hydrated.extend(members);
                if page["has_more"] != true {
                    break;
                }
            }
            for id in &visible_ids {
                super::metadata_reads::facet_values(&w.db, &w.viewer, id)
                    .await
                    .unwrap();
            }
            hydrated
        })
        .await;
    assert_eq!(oracle.len(), MEMBERS);
    let oracle_bytes = serde_json::to_vec(&oracle).unwrap().len();
    eprintln!("collection envelope oracle rows={} hydrated_bytes={oracle_bytes} body_loads={} body_bytes={} facet_transactions={}", oracle.len(), probe_oracle.body_loads, probe_oracle.body_bytes, probe_oracle.facet_transactions);
    assert_eq!(probe_oracle.body_loads, MEMBERS as u64);
    assert_eq!(probe_oracle.body_bytes, MEMBERS as u64 * 65536);
    assert_eq!(probe_oracle.facet_transactions, MEMBERS as u64);
    assert_eq!(probe_oracle.envelope_pages, 0);
    assert!(
        oracle_bytes > 30_000_000,
        "the oracle really hydrated member bodies"
    );
    w.db.close().await;
}
async fn saved_collection_fixture() -> (World, Db, String, Vec<String>) {
    let w = world().await;
    install_comment_carrier(&w).await;
    let v1 = crate::create_database(":memory:").await.unwrap();
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let at = crate::store::now_iso();
    for (section,sql) in [
        ("schema_config","SELECT json_object('id',id,'layer',layer,'name',name,'data',data,'applies_to_collection_id',applies_to_collection_id,'version_lineage',version_lineage,'created_at',created_at) FROM schema_config"),
        ("vocabularies","SELECT json_object('id',id,'name',name,'created_at',created_at) FROM vocabularies"),
        ("vocabulary_values","SELECT json_object('id',id,'vocabulary_id',vocabulary_id,'value',value,'gloss',gloss,'status',status,'ordinal',ordinal,'terminality',terminality,'metadata',metadata,'alias_of',alias_of) FROM vocabulary_values"),
    ] {
        let rows:Vec<String>=sqlx::query_scalar(sql).fetch_all(v1.pool()).await.unwrap();
        let rows:Vec<_>=rows.into_iter().map(|raw|{let row:Value=serde_json::from_str(&raw).unwrap();kernel::v1_state::ImportedState{section:section.into(),source_id:row["id"].as_str().unwrap().into(),origin:"saved-collection-fixture".into(),value_json:Some(raw),account_principal:None,record_id:None,observed_at:at.clone(),snapshot:json!({})}}).collect();
        for batch in rows.chunks(256){kernel::v1_state::import_state_batch_as(&w.db,&host,batch).await.unwrap();}
    }
    let home = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let mut ids = Vec::new();
    for n in 0..51 {
        let name = format!("Member {n:03}");
        let id = kernel::create_as(
            &w.db,
            &w.admin,
            "fixture.mcp",
            "note",
            json!({"title":name}).as_object().unwrap(),
            &home,
        )
        .await
        .unwrap();
        registry().call(v1.clone(),Caller::local(),"create_record",json!({"id":id,"type":"Document","kind":"note","name":name,"reason":"saved collection fixture"})).await.unwrap();
        ids.push(id);
    }
    // Same saved definition on both engines. The additional v2 record is
    // hidden; its absence on v1 produces the same authorized membership.
    ids.push(w.hidden.clone());
    let query =
        json!({"v":"0.2","query":{"steps":[{"step":"filter","ids":ids}],"order":"name_asc"}})
            .to_string();
    let id=call_as(&w,"acct:admin","create_record",json!({"type":"Collection","kind":"query","name":"Saved membership","home_id":home,"facets":{"query":query},"reason":"saved collection fixture"})).await.unwrap()["id"].as_str().unwrap().to_owned();
    registry().call(v1.clone(),Caller::local(),"create_record",json!({"id":id,"type":"Collection","kind":"query","name":"Saved membership","facets":{"query":query},"reason":"saved collection fixture"})).await.unwrap();
    (w, v1, id, ids)
}
async fn saved_collection_facet(w: &World, v1: &Db, id: &str, key: &str, value: &str) {
    kernel::observe_facet_as(
        &w.db,
        &w.admin,
        id,
        &kernel::FacetObservation {
            key: key.into(),
            value: Some(value.into()),
            value_num: None,
            vocab_ref: None,
            as_of: crate::store::now_iso(),
        },
        None,
    )
    .await
    .unwrap();
    // Read parity deliberately includes malformed/imported saved definitions.
    // V1's read adapter must diagnose those stored rows too.
    sqlx::query("INSERT INTO facet_values(id,record_id,key,value,vocab_ref) VALUES(?,?,?,?,NULL) ON CONFLICT(record_id,key) DO UPDATE SET value=excluded.value").bind(uuid::Uuid::new_v4().to_string()).bind(id).bind(key).bind(value).execute(v1.write_pool()).await.unwrap();
}
async fn compare_saved_collection(w: &World, v1: &Db, id: &str) -> Value {
    let actual = call(w, "open_collection", json!({"id":id})).await.unwrap();
    let expected = registry()
        .call(
            v1.clone(),
            Caller::local(),
            "open_collection",
            json!({"id":id}),
        )
        .await
        .unwrap();
    assert_eq!(actual, expected);
    assert!(!actual.to_string().contains(&w.hidden));
    actual
}
#[tokio::test]
async fn kernel_v2_saved_query_collection_preserves_v1_page_and_explicit_membership() {
    let (w, v1, id, ids) = saved_collection_fixture().await;
    let first = compare_saved_collection(&w, &v1, &id).await;
    assert_eq!(first["input"]["records"].as_array().unwrap().len(), 50);
    saved_collection_facet(&w, &v1, &id, "input_membership", "all_matching").await;
    let all = compare_saved_collection(&w, &v1, &id).await;
    assert_eq!(all["input"]["records"].as_array().unwrap().len(), 51);
    let query=json!({"v":"0.2","query":{"steps":[{"step":"filter","ids":ids}],"order":"name_asc","limit":2,"offset":1}}).to_string();
    saved_collection_facet(&w, &v1, &id, "query", &query).await;
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    let page = compare_saved_collection(&w, &v1, &id).await;
    assert_eq!(page["input"]["records"].as_array().unwrap().len(), 2);
    assert_eq!(page["input"]["records"][0]["name"], "Member 001");
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(page, compare_saved_collection(&w, &v1, &id).await);
    // Opening needs View, never Edit. A viewer's mutation remains refused.
    assert!(call(
        &w,
        "update_record",
        json!({"id":id,"name":"forbidden","reason":"not an editor"})
    )
    .await
    .is_err());
    for bad in [
        "not-json".to_owned(),
        json!({"v":"9.9","query":{"steps":[{"step":"filter"}]}}).to_string(),
        json!({"v":"0.2","query":{"steps":[{"step":"filter"}],"count":true}}).to_string(),
    ] {
        saved_collection_facet(&w, &v1, &id, "query", &bad).await;
        let result = compare_saved_collection(&w, &v1, &id).await;
        assert_eq!(result["status"], "error");
        assert_eq!(result["diagnostic"]["code"], "input_resolution_failed");
    }
    assert!(
        call_as(&w, "acct:unknown", "open_collection", json!({"id":id}))
            .await
            .is_err()
    );
    assert!(call(&w, "open_collection", json!({"id":id,"limit":1}))
        .await
        .is_err());
    let home = kernel::read_record_as(&w.db, &w.admin, &id)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    kernel::replace_home_policy(&w.db, &w.admin, &home, &[])
        .await
        .unwrap();
    for hidden in [&id, &w.hidden, "missing-collection"] {
        assert!(call(&w, "open_collection", json!({"id":hidden}))
            .await
            .is_err());
    }
    v1.close().await;
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_run_discovery_is_own_account_and_observational() {
    let w = world().await;
    let first = "scout-chair-aaaaaa";
    let second = "scout-chair-bbbbbb";
    let other = "scout-chair-cccccc";
    let one = kernel::open_run_as(&w.db, &w.viewer, first).await.unwrap();
    kernel::set_run_intent_as(&w.db, &one, "Visible intent")
        .await
        .unwrap();
    let two = kernel::open_run_as(&w.db, &w.viewer, second).await.unwrap();
    kernel::run_ledger::close_run_as(&w.db, &two).await.unwrap();
    let foreign = kernel::open_run_as(&w.db, &w.admin, other).await.unwrap();
    kernel::set_run_intent_as(&w.db, &foreign, "Secret intent")
        .await
        .unwrap();
    let before: i64 = sqlx::query_scalar("SELECT MAX(seq) FROM content_events")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let page = call(&w, "get_run_activity", json!({"limit":1}))
        .await
        .unwrap();
    assert_eq!(page["mode"], "discovery");
    assert_eq!(page["runs"][0]["run_key"], first);
    assert_eq!(page["runs"][0]["intent"]["value"], "Visible intent");
    assert_eq!(
        page["runs"][0]["activity_freshness"]["reason"],
        "read_log_unavailable"
    );
    assert_eq!(
        page["runs"][0]["channel"]["assurance"],
        "unknown_or_withheld"
    );
    assert_eq!(page["has_more"], true);
    let args = json!({"limit":1,"cursor":page["next_cursor"]});
    let next = call(&w, "get_run_activity", args.clone()).await.unwrap();
    assert_eq!(next, call(&w, "get_run_activity", args).await.unwrap());
    assert_eq!(next["runs"][0]["run_key"], second);
    assert_eq!(next["runs"][0]["run_state"], "closed");
    assert_eq!(next["has_more"], false);
    let all = call(&w, "get_run_activity", json!({})).await.unwrap();
    assert_eq!(all["returned"], 2);
    assert!(!all.to_string().contains("Secret intent"));
    let filtered = call(
        &w,
        "get_run_activity",
        json!({"for_run":first,"include_child_runs":true}),
    )
    .await
    .unwrap();
    assert_eq!(filtered["availability"]["reason"], "read_log_unavailable");
    assert_eq!(filtered["read_activity"], json!([]));
    let refusal = call(&w, "get_run_activity", json!({"for_run":other}))
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        refusal,
        call(
            &w,
            "get_run_activity",
            json!({"for_run":"scout-chair-dddddd"})
        )
        .await
        .unwrap_err()
        .to_string()
    );
    for args in [
        json!({"limit":0}),
        json!({"limit":51}),
        json!({"for_run":first,"limit":1}),
        json!({"include_child_runs":false}),
        json!({"cursor":{"observed_at":"bad","sort_at":"bad","open_rank":0,"activity_id":"x"}}),
    ] {
        assert!(call(&w, "get_run_activity", args).await.is_err());
    }
    assert!(call_as(&w, "acct:unknown", "get_run_activity", json!({}))
        .await
        .is_err());
    let after: i64 = sqlx::query_scalar("SELECT MAX(seq) FROM content_events")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    assert_eq!(before, after);
    w.db.close().await;
}

async fn import_catalogue(
    w: &World,
    section: &str,
    id: &str,
    value: Value,
    account: Option<&str>,
    observed: &str,
) {
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    kernel::v1_state::import_state_batch_as(
        &w.db,
        &host,
        &[kernel::v1_state::ImportedState {
            section: section.into(),
            source_id: id.into(),
            origin: "fixture".into(),
            value_json: Some(value.to_string()),
            account_principal: account.map(str::to_owned),
            record_id: None,
            observed_at: observed.into(),
            snapshot: json!({}),
        }],
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn kernel_v2_shape_preview_uses_v1_predicates_and_visible_schema_only() {
    let w = world().await;
    let schema = json!({"shapes":{"Document":{"facets":{"score":{"type":"number"},"mandatory":{"required":true}}}}});
    let at = "2026-10-19T12:00:00Z";
    let row = json!({"id":"shape-fixture","layer":"user","name":"fixture","data":schema.to_string(),"applies_to_collection_id":null,"version_lineage":null,"created_at":at});
    import_catalogue(&w, "schema_config", "shape-fixture", row, None, at).await;
    let secret = json!({"id":"secret-shape","layer":"user","name":"Secret schema","data":"malformed hidden schema","applies_to_collection_id":w.hidden,"version_lineage":null,"created_at":at});
    import_catalogue(&w, "schema_config", "secret-shape", secret, None, at).await;
    assert!(call_as(
        &w,
        "acct:admin",
        "preview_record_shape",
        json!({"type":"Document"})
    )
    .await
    .is_err());
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    let v1 = crate::db::open_database(":memory:").await.unwrap();
    crate::db::apply_schema(&v1).await.unwrap();
    sqlx::query("INSERT INTO schema_config(id,layer,name,data,created_at) VALUES('shape-fixture','user','fixture',?,?)")
        .bind(schema.to_string()).bind(at).execute(v1.write_pool()).await.unwrap();
    for facets in [
        json!({"score":7,"mandatory":"yes"}),
        json!({"score":"bad","mandatory":"yes"}),
        json!({"score":7}),
        json!({"assigned_to":"secret"}),
    ] {
        let args = json!({"type":"Document","kind":"note","facets":facets});
        let actual = call(&w, "preview_record_shape", args.clone())
            .await
            .unwrap();
        let expected = registry()
            .call(
                v1.clone(),
                Caller::local(),
                "preview_record_shape",
                args.clone(),
            )
            .await
            .unwrap();
        assert_eq!(actual["selection"], expected["selection"]);
        assert_eq!(actual["proposed_facets"], expected["proposed_facets"]);
        assert_eq!(actual["catalogs"], expected["catalogs"]);
        assert_eq!(
            actual,
            call(&w, "preview_record_shape", args).await.unwrap()
        );
        assert!(!actual.to_string().contains("Secret schema"));
        assert!(actual["advisory_basis"]["event_heads"].is_null());
        assert!(actual["advisory_basis"]["schema_state_revision"]
            .as_str()
            .unwrap()
            .starts_with("kernel-schema-state-v1:"));
    }
    let accepted = call(
        &w,
        "preview_record_shape",
        json!({"type":"Document","kind":"note","facets":{"score":7,"mandatory":"yes"}}),
    )
    .await
    .unwrap();
    assert_eq!(accepted["proposed_facets"]["status"], "accepted");
    assert_eq!(
        call(
            &w,
            "preview_record_shape",
            json!({"type":"Document","facets":{"score":"bad"}})
        )
        .await
        .unwrap()["proposed_facets"]["status"],
        "rejected"
    );
    for args in [
        json!({"kind":"note"}),
        json!({"type":"Unknown"}),
        json!({"facets":{}}),
        json!({"type":"Document","facets":null}),
    ] {
        assert!(call(&w, "preview_record_shape", args).await.is_err());
    }
    assert!(
        call_as(&w, "acct:unknown", "preview_record_shape", json!({}))
            .await
            .is_err()
    );
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    v1.close().await;
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_run_discovery_imported_history_is_honest_and_owner_scoped() {
    let w = world().await;
    let now = chrono::Utc::now();
    let at =
        (now - chrono::Duration::hours(1)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let old =
        (now - chrono::Duration::hours(25)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    for (id, account, principal, time) in [
        ("imported", "acct:viewer", &w.viewer, &at),
        ("foreign", "acct:admin", &w.admin, &at),
        ("expired", "acct:viewer", &w.viewer, &old),
    ] {
        import_catalogue(&w,"runs",id,json!({"activity_id":id,"run_key":format!("{id}-worker-aaaaaa"),"account_id":account,"started_at":time,"ended_at":if id=="expired" {json!(time)} else {Value::Null},"start_event_id":format!("{id}-event"),"start_event_seq":1}),Some(principal),time).await;
    }
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    let page = call(&w, "get_run_activity", json!({})).await.unwrap();
    assert_eq!(page["returned"], 1);
    assert_eq!(page["runs"][0]["activity_id"], "imported");
    assert_eq!(page["runs"][0]["run_state"], "open");
    assert!(page["runs"][0]["ended_at"].is_null());
    assert_eq!(page["runs"][0]["historical"], true);
    assert_eq!(page["runs"][0]["historical_observed_at"], at);
    assert_eq!(
        page["runs"][0]["activity_freshness"]["appears_active"],
        false
    );
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    w.db.close().await;
}

#[test]
fn kernel_v2_run_activity_has_exactly_one_handler() {
    // Building the complete registry itself refuses duplicate registrations.
    let mut registry = registry();
    assert!(registry.has_engine_handler("get_run_activity", EngineKind::KernelV2));
    let duplicate = registry.register_engine_handler(
        "get_run_activity",
        EngineKind::KernelV2,
        |_, _, _| async { Ok::<Value, Error>(Value::Null) },
    );
    assert!(duplicate.unwrap_err().to_string().contains("already has a"));
}

#[test]
fn kernel_v2_bindings_has_exactly_one_handler() {
    let mut registry = registry();
    assert!(registry.has_engine_handler("manage_bindings", EngineKind::KernelV2));
    let duplicate = registry.register_engine_handler(
        "manage_bindings",
        EngineKind::KernelV2,
        |_, _, _| async { Ok::<Value, Error>(Value::Null) },
    );
    assert!(duplicate.unwrap_err().to_string().contains("already has a"));
}

async fn binding_fixture() -> (World, Db, String) {
    let w = world().await;
    let v1 = crate::create_database(":memory:").await.unwrap();
    crate::authorization::replace_explicit_policy(
        &v1,
        "local",
        crate::schema::ROOT_RECORD_ID,
        vec![crate::authorization::AllowEntry::account(
            "local",
            crate::authorization::Capability::Manage,
        )],
    )
    .await
    .unwrap();
    let definition = json!({"family":"fixture.bindings","version":1,"interpreter":"native.defn/2","primary_type":"Entity","kinds":[{"token":"person","description":"Binding parity","maturity":"current","identity":{"field":"title"},"fields":[{"name":"title","type":"text","required":true}],"links":[]}]});
    let pin = kernel::install_definition_as(
        &w.db,
        &w.admin,
        "fixture.bindings",
        1,
        &serde_json::to_vec(&definition).unwrap(),
    )
    .await
    .unwrap();
    kernel::adopt_definition_as(&w.db, &w.admin, &pin.family, Some(&pin))
        .await
        .unwrap();
    let home = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let person = kernel::create_as(
        &w.db,
        &w.admin,
        &pin.family,
        "person",
        json!({"title":"Binding Person"}).as_object().unwrap(),
        &home,
    )
    .await
    .unwrap();
    for (id, typ, kind) in [
        (&w.first, "Document", "note"),
        (&w.second, "Document", "note"),
        (&w.hidden, "Document", "note"),
        (&person, "Entity", "person"),
    ] {
        registry().call(v1.clone(),Caller::local(),"create_record",json!({"id":id,"type":typ,"kind":kind,"name":id,"reason":"Synthetic binding parity fixture"})).await.unwrap();
    }
    (w, v1, person)
}

fn binding_claim(record: &str) -> Value {
    json!({"system":"native-record","identifier":crate::identity::encode_native_record("ndb_00000000000000000000000000000000",record).unwrap()})
}

#[tokio::test]
async fn kernel_v2_bindings_v1_add_list_canonical_noop_and_replay() {
    let (w, v1, person) = binding_fixture().await;
    let alpha = binding_claim("alpha");
    let beta = binding_claim("beta");
    for (record, binding, canonical) in [
        (&w.first, alpha.clone(), false),
        (&w.first, alpha.clone(), true),
        (&w.first, alpha.clone(), false),
        (&w.first, beta.clone(), true),
        (&w.first, beta.clone(), true),
        (
            &person,
            json!({"system":"native-principal","identifier":"native/A"}),
            true,
        ),
    ] {
        let args = json!({"action":"add","record_id":record,"binding":binding,"canonical":canonical,"reason":"Binding parity"});
        let expected = registry()
            .call(v1.clone(), Caller::local(), "manage_bindings", args.clone())
            .await
            .unwrap();
        let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
        let actual = call_as(&w, "acct:admin", "manage_bindings", args)
            .await
            .unwrap();
        for key in ["status", "record_id", "changed"] {
            assert_eq!(actual[key], expected[key], "{key}");
        }
        if expected["changed"] == false {
            assert!(actual.get("act").is_none());
            assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
        }
        let args = json!({"action":"list","record_id":record});
        let expected = registry()
            .call(v1.clone(), Caller::local(), "manage_bindings", args.clone())
            .await
            .unwrap();
        assert_eq!(call(&w, "manage_bindings", args).await.unwrap(), expected);
    }
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    let events:Vec<(String,String,Option<i64>)>=sqlx::query_as("SELECT actor,payload,act FROM content_events WHERE type='kernel.identity_binding_added.v1' ORDER BY seq").fetch_all(w.db.pool()).await.unwrap();
    assert_eq!(events.len(), 4);
    assert!(events.iter().all(|(actor, payload, act)| actor == &w.admin
        && act.is_some()
        && serde_json::from_str::<Value>(payload).unwrap()["reason"] == "Binding parity"));
    v1.close().await;
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_bindings_v1_reserved_shape_and_argument_refusals() {
    let (w, v1, person) = binding_fixture().await;
    for args in [
        json!({"action":"add","record_id":person,"binding":{"system":"email","identifier":"a@example.test"},"reason":"Reserved"}),
        json!({"action":"add","record_id":person,"binding":{"system":"account","identifier":"account"},"reason":"Reserved"}),
        json!({"action":"add","record_id":person,"binding":{"system":"unknown","identifier":"x"},"reason":"Unknown"}),
        json!({"action":"add","record_id":w.first,"binding":{"system":"native-principal","identifier":"native/A"},"reason":"Wrong shape"}),
        json!({"action":"add","record_id":person,"binding":{"system":"native-principal","identifier":w.admin},"reason":"Kernel IDs are not wire addresses"}),
        json!({"action":"add","record_id":w.first,"binding":binding_claim("key"),"reason":"   "}),
        json!({"action":"add","record_id":w.first,"binding":binding_claim("key"),"reason":"Invalid key","idempotency_key":"not accepted by v1"}),
        json!({"action":"list","record_id":w.first,"reason":"Not accepted on list"}),
    ] {
        let expected = registry()
            .call(v1.clone(), Caller::local(), "manage_bindings", args.clone())
            .await
            .unwrap_err()
            .to_string();
        let actual = call_as(&w, "acct:admin", "manage_bindings", args)
            .await
            .unwrap_err()
            .to_string();
        if !expected.contains("invalid arguments") {
            assert_eq!(actual, expected);
        } else {
            assert!(actual.contains("invalid arguments"), "{actual}");
        }
    }
    v1.close().await;
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_bindings_authority_hidden_collisions_and_cas_are_atomic() {
    let (w, v1, _person) = binding_fixture().await;
    let args = |record: &str, claim: Value| json!({"action":"add","record_id":record,"binding":claim,"canonical":true,"reason":"Authority parity"});
    for id in [w.hidden.as_str(), "missing"] {
        assert!(call(
            &w,
            "manage_bindings",
            json!({"action":"list","record_id":id})
        )
        .await
        .unwrap_err()
        .to_string()
        .contains(kernel::HIDDEN_OR_MISSING));
    }
    let claim = binding_claim("occupied");
    call_as(
        &w,
        "acct:admin",
        "manage_bindings",
        args(&w.hidden, claim.clone()),
    )
    .await
    .unwrap();
    let home = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    for cap in ["view", "edit"] {
        kernel::replace_home_policy(
            &w.db,
            &w.admin,
            &home,
            &[(&w.admin, "manage"), (&w.viewer, cap)],
        )
        .await
        .unwrap();
        let capability = if cap == "view" {
            crate::authorization::Capability::View
        } else {
            crate::authorization::Capability::Edit
        };
        crate::authorization::replace_explicit_policy(
            &v1,
            "local",
            &w.first,
            vec![crate::authorization::AllowEntry::members(capability)],
        )
        .await
        .unwrap();
        assert!(registry()
            .call(
                v1.clone(),
                Caller::local(),
                "manage_bindings",
                args(&w.first, binding_claim("new"))
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("requires Manage"));
        let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
        assert!(
            call(&w, "manage_bindings", args(&w.first, binding_claim("new")))
                .await
                .is_err()
        );
        assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    }
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        &home,
        &[(&w.admin, "manage"), (&w.viewer, "manage")],
    )
    .await
    .unwrap();
    let error = call(&w, "manage_bindings", args(&w.first, claim.clone()))
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("binding_not_visible"), "{error}");
    assert!(!error.contains(&w.hidden));
    let visible = call_as(&w, "acct:admin", "manage_bindings", args(&w.first, claim))
        .await
        .unwrap_err()
        .to_string();
    assert!(visible.contains("binding collision"));
    let mut snapshot = w.db.pool().begin().await.unwrap();
    let revision = kernel::identity_bindings::revision_on(&mut snapshot, &w.first)
        .await
        .unwrap();
    snapshot.rollback().await.unwrap();
    let mut guarded = args(&w.first, binding_claim("guarded"));
    guarded["if_binding_state_revision"] = json!(revision);
    call(&w, "manage_bindings", guarded.clone()).await.unwrap();
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    assert!(call(&w, "manage_bindings", guarded)
        .await
        .unwrap_err()
        .to_string()
        .contains("binding state revision conflict"));
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    sqlx::query("CREATE TRIGGER fail_binding_projection BEFORE INSERT ON kernel_identity_bindings BEGIN SELECT RAISE(ABORT,'synthetic binding failure'); END").execute(w.db.write_pool()).await.unwrap();
    assert!(call(
        &w,
        "manage_bindings",
        args(&w.first, binding_claim("rollback"))
    )
    .await
    .is_err());
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    v1.close().await;
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_bindings_audit_keeps_body_guard_and_history_unchanged() {
    let w = world().await;
    let before = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap();
    call_as(&w,"acct:admin","manage_bindings",json!({"action":"add","record_id":w.first,"binding":binding_claim("separate-audit"),"reason":"Binding audit is not body history"})).await.unwrap();
    let after = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(before.revision, after.revision);
    assert_eq!(before.metadata, after.metadata);
    assert_eq!(before.body, after.body);
    for actor in [&w.admin, &w.viewer] {
        let history =
            kernel::history_page_as(&w.db, actor, &w.first, None, false, 1000, true, false)
                .await
                .unwrap();
        assert!(history
            .iter()
            .all(|event| event.event_type != "kernel.identity_binding_added.v1"));
    }
    let sql=call_as(&w,"acct:admin","query_sql",json!({"sql":"SELECT count(*) AS n FROM content_events WHERE type='kernel.identity_binding_added.v1'"})).await.unwrap();
    assert_eq!(sql["rows"][0]["n"], 0);
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_shape_preview_capability_error_is_hidden() {
    let w = world().await;
    let at = "2026-10-19T12:00:00Z";
    import_catalogue(&w, "schema_config", "visible", json!({"id":"visible","layer":"user","name":"visible","data":json!({"shapes":{"Document":{"facets":{"score":{"type":"number"}}}}}).to_string(),"applies_to_collection_id":null,"version_lineage":null,"created_at":at}), None, at).await;
    let args = json!({"type":"Document","facets":{"score":7}});
    let expected = call(&w, "preview_record_shape", args.clone())
        .await
        .unwrap();
    let missing = uuid::Uuid::new_v4().to_string();
    let mut connection = w.db.pool().acquire().await.unwrap();
    assert!(
        kernel::kernel_effective_capability_on(&mut connection, &w.viewer, &missing)
            .await
            .is_err()
    );
    drop(connection);
    import_catalogue(&w, "schema_config", "unresolvable", json!({"id":"unresolvable","layer":"user","name":"hidden schema secret","data":"invalid JSON hidden by capability error","applies_to_collection_id":missing,"version_lineage":null,"created_at":at}), None, at).await;
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    let actual = call(&w, "preview_record_shape", args.clone())
        .await
        .unwrap();
    for key in ["selection", "proposed_facets", "catalogs"] {
        assert_eq!(actual[key], expected[key]);
    }
    assert!(!actual.to_string().contains("hidden schema secret"));
    assert_eq!(
        actual,
        call(&w, "preview_record_shape", args).await.unwrap()
    );
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    w.db.close().await;
}
#[tokio::test]
async fn kernel_v2_event_context_body_delta_matches_v1_after_later_edits() {
    let w = world().await;
    let v1 = crate::create_database(":memory:").await.unwrap();
    registry().call(v1.clone(),Caller::local(),"create_record",json!({"id":w.first,"type":"Document","kind":"note","name":"Context","body":"revised","reason":"context fixture"})).await.unwrap();
    let mut selected = String::new();
    let mut expected_event = String::new();
    let mut previous_body = "revised";
    for body in ["first edit", "later edit", "latest edit"] {
        let current = kernel::read_record_as(&w.db, &w.admin, &w.first)
            .await
            .unwrap()
            .unwrap();
        kernel::set_body_as(&w.db, &w.admin, &w.first, body, current.revision)
            .await
            .unwrap();
        registry()
            .call(
                v1.clone(),
                Caller::local(),
                "update_record",
                json!({"id":w.first,"body_set":body,"if_body_digest":crate::mcp::tools::lifecycle::body_digest(Some(previous_body)),"reason":"context fixture"}),
            )
            .await
            .unwrap();
        previous_body = body;
        if selected.is_empty() {
            selected=sqlx::query_scalar("SELECT id FROM content_events WHERE record_id=? AND type='kernel.body_set.v1' ORDER BY seq DESC LIMIT 1").bind(&w.first).fetch_one(w.db.pool()).await.unwrap();
            expected_event=sqlx::query_scalar("SELECT id FROM content_events WHERE record_id=? AND type='record.updated' ORDER BY seq DESC LIMIT 1").bind(&w.first).fetch_one(v1.pool()).await.unwrap();
        }
    }
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    let result = call_as(
        &w,
        "acct:admin",
        "get_event_context",
        json!({"event_id":selected}),
    )
    .await
    .unwrap();
    let expected = registry()
        .call(
            v1.clone(),
            Caller::local(),
            "get_event_context",
            json!({"event_id":expected_event}),
        )
        .await
        .unwrap();
    for field in ["kind", "record_id", "before", "after", "is_creation"] {
        assert_eq!(result["delta"][field], expected["delta"][field], "{field}");
    }
    assert_eq!(result["delta"]["after"], "first edit");
    assert_eq!(result["consulted"]["status"], "unavailable");
    assert_eq!(result["basis"], expected["basis"]);
    assert_eq!(
        result["interpretation_limits"],
        expected["interpretation_limits"]
    );
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(
        result,
        call_as(
            &w,
            "acct:admin",
            "get_event_context",
            json!({"event_id":selected})
        )
        .await
        .unwrap()
    );
    assert!(call_as(
        &w,
        "acct:unknown",
        "get_event_context",
        json!({"event_id":selected})
    )
    .await
    .is_err());
    assert!(call(
        &w,
        "get_event_context",
        json!({"event_id":selected,"record_id":w.first})
    )
    .await
    .is_err());
    let hidden: String =
        sqlx::query_scalar("SELECT id FROM content_events WHERE record_id=? ORDER BY seq LIMIT 1")
            .bind(&w.hidden)
            .fetch_one(w.db.pool())
            .await
            .unwrap();
    for id in [hidden, "missing-event".into()] {
        let error = call(&w, "get_event_context", json!({"event_id":id}))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("does not exist"));
        assert!(!error.contains(&w.hidden));
    }
    v1.close().await;
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_event_context_retained_basis_and_neighbours_are_currently_visible() {
    let w = world().await;
    kernel::replace_home_policy(&w.db, &w.admin, KERNEL_ROOT_ID, &[(&w.viewer, "view")])
        .await
        .unwrap();
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let key = "context-proof-aaaaaa";
    let selected = uuid::Uuid::new_v4().to_string();
    let events = [
        (
            &w.first,
            uuid::Uuid::new_v4().to_string(),
            "record.created",
            json!({"body":"retained before"}),
            "before",
        ),
        (
            &w.first,
            selected.clone(),
            "record.updated",
            json!({"body":"retained after","basis":{"format":"native.source-basis.v1","sources":[{"record_id":w.second,"role":"context","reason":"visible basis"},{"record_id":w.hidden,"role":"private basis","reason":"secret basis reason"}]}}),
            "then",
        ),
        (
            &w.second,
            uuid::Uuid::new_v4().to_string(),
            "record.updated",
            json!({"summary":"visible neighbour"}),
            "later",
        ),
        (
            &w.hidden,
            uuid::Uuid::new_v4().to_string(),
            "record.updated",
            json!({"body":"secret neighbour body"}),
            "hidden",
        ),
    ];
    for (n, (record, id, typ, payload, intent)) in events.into_iter().enumerate() {
        kernel::import_event_as(&w.db,&host,record,&kernel::LegacyEvent{ id,event_type:typ.into(),payload,created_at:format!("2020-01-01T00:00:0{n}Z"),actor:Some("acct:admin".into()),run_key:Some(key.into()),source:Some(json!({"stream":"content","subjects":[record],"metadata":{"record_id":record,"intent":intent}}))}).await.unwrap();
    }
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    let result = call(&w, "get_event_context", json!({"event_id":selected}))
        .await
        .unwrap();
    assert_eq!(result["delta"]["kind"], "unavailable");
    assert!(result["delta"].get("before").is_none());
    assert!(result["delta"].get("after").is_none());
    assert_eq!(result["intent_at_event"], "then");
    assert_eq!(result["basis"]["status"], "declared");
    assert_eq!(result["basis"]["completeness"], "partial");
    assert_eq!(result["basis"]["sources"].as_array().unwrap().len(), 1);
    assert_eq!(result["consulted"]["status"], "unavailable");
    let encoded = result.to_string();
    for secret in [
        &w.hidden,
        "secret basis reason",
        "private basis",
        "secret neighbour body",
    ] {
        assert!(!encoded.contains(secret), "{encoded}");
    }
    assert!(encoded.contains("visible neighbour"));
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    // The record and visible basis source remain Viewable after losing root
    // View, but retained history now releases only a marker. Raw source-basis
    // prose must not bypass that stricter payload disclosure gate.
    kernel::replace_home_policy(&w.db, &w.admin, KERNEL_ROOT_ID, &[])
        .await
        .unwrap();
    assert!(kernel::read_record_as(&w.db, &w.viewer, &w.first)
        .await
        .unwrap()
        .is_some());
    assert!(kernel::read_record_as(&w.db, &w.viewer, &w.second)
        .await
        .unwrap()
        .is_some());
    let marker = call(&w, "get_event_context", json!({"event_id":selected}))
        .await
        .unwrap();
    assert_eq!(marker["basis"]["status"], "not_declared");
    assert_eq!(marker["basis"]["completeness"], "partial");
    assert_eq!(marker["basis"]["sources"], json!([]));
    assert!(!marker.to_string().contains("visible basis"));
    let home = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    kernel::replace_home_policy(&w.db, &w.admin, &home, &[])
        .await
        .unwrap();
    assert!(call(&w, "get_event_context", json!({"event_id":selected}))
        .await
        .is_err());
    w.db.close().await;
}
#[tokio::test]
async fn kernel_v2_version_diff_matches_v1_body_and_live_visibility() {
    let w = world().await;
    let record = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap();
    kernel::set_body_as(&w.db, &w.admin, &w.first, "one", record.revision)
        .await
        .unwrap();
    let cutoff: i64 = sqlx::query_scalar("SELECT max(seq) FROM content_events")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let v1 = crate::create_database(":memory:").await.unwrap();
    registry().call(v1.clone(),Caller::local(),"create_record",json!({"id":w.first,"type":"Document","kind":"note","name":"Alpha","body":"one","reason":"diff fixture"})).await.unwrap();
    let v1_cutoff: i64 = sqlx::query_scalar("SELECT max(seq) FROM content_events")
        .fetch_one(v1.pool())
        .await
        .unwrap();
    let record = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap();
    kernel::set_body_as(&w.db, &w.admin, &w.first, "two", record.revision)
        .await
        .unwrap();
    registry().call(v1.clone(),Caller::local(),"update_record",json!({"id":w.first,"body_set":"two","if_body_digest":crate::mcp::tools::lifecycle::body_digest(Some("one")),"reason":"diff fixture"})).await.unwrap();
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    let result = call(
        &w,
        "render_record_version_diff",
        json!({"record_id":w.first,"before_seq":cutoff}),
    )
    .await
    .unwrap();
    let expected = registry()
        .call(
            v1.clone(),
            Caller::local(),
            "render_record_version_diff",
            json!({"record_id":w.first,"before_seq":v1_cutoff}),
        )
        .await
        .unwrap();
    assert_eq!(result["view"], expected["view"]);
    for endpoint in ["before", "after"] {
        for field in [
            "id",
            "name",
            "type",
            "kind",
            "body",
            "summary",
            "archived",
            "persistence",
            "maturity",
        ] {
            assert_eq!(
                result[endpoint]["record"][field], expected[endpoint]["record"][field],
                "{endpoint}/{field}"
            );
        }
    }
    assert_eq!(result["before"]["record"]["body"], "one");
    assert_eq!(result["after"]["record"]["body"], "two");
    assert_eq!(result["before"]["as_of_seq"], cutoff);
    assert_eq!(result["after"]["record"]["links_out_count"], 1);
    assert!(!result.to_string().contains(&w.hidden));
    assert_eq!(result["events"].as_array().unwrap().len(), 1);
    assert_eq!(result["events"][0]["payload"]["body"], "two");
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(
        result,
        call(
            &w,
            "render_record_version_diff",
            json!({"record_id":w.first,"before_seq":cutoff})
        )
        .await
        .unwrap()
    );
    for args in [
        json!({"record_id":w.hidden,"before_seq":cutoff}),
        json!({"record_id":"missing","before_seq":cutoff}),
        json!({"record_id":w.first,"before_seq":0}),
        json!({"record_id":w.first,"before_seq":i64::MAX}),
        json!({"record_id":w.first,"before_seq":cutoff,"before_event_id":"extra"}),
    ] {
        assert!(call(&w, "render_record_version_diff", args).await.is_err());
    }
    v1.close().await;
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_version_diff_uses_workspace_head_for_related_children() {
    let w = world().await;
    install_comment_carrier(&w).await;
    let folder = call_as(
        &w,
        "acct:admin",
        "create_record",
        json!({"type":"Collection","kind":"folder","name":"Parent","reason":"diff fixture"}),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let cutoff: i64 = sqlx::query_scalar("SELECT max(seq) FROM content_events")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let child = kernel::create_as(
        &w.db,
        &w.admin,
        "fixture.mcp",
        "note",
        json!({"title":"Later child"}).as_object().unwrap(),
        &crate::v1_import::derived(&folder),
    )
    .await
    .unwrap();
    let revision = kernel::read_record_as(&w.db, &w.admin, &child)
        .await
        .unwrap()
        .unwrap()
        .revision;
    kernel::set_archived_as(&w.db, &w.admin, &child, true, revision)
        .await
        .unwrap();
    let result = call_as(
        &w,
        "acct:admin",
        "render_record_version_diff",
        json!({"record_id":folder,"before_seq":cutoff}),
    )
    .await
    .unwrap();
    assert_eq!(result["before"]["record"]["child_count"], 0);
    assert_eq!(result["after"]["record"]["child_count"], 1);
    assert_eq!(
        result["after"]["record"]["children"][0]["name"],
        "Later child"
    );
    assert_eq!(result["events"], json!([]));
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_version_diff_import_baselines_and_clears_are_not_provenance() {
    let w = world().await;
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let home = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let id = uuid::Uuid::new_v4().to_string();
    // Record identity admits an unchanged identity through snapshot resume;
    // the field-identity import port independently refuses that resume today.
    let definition = json!({"family":"fixture.history.imported","version":1,"interpreter":"native.defn/4","primary_type":"Document",
        "kinds":[{"token":"note","description":"Imported history","maturity":"current","identity":{"mode":"record"},
            "fields":[{"name":"title","type":"text","required":true}],"links":[]}]});
    let pin = kernel::install_definition_as(
        &w.db,
        &w.admin,
        "fixture.history.imported",
        1,
        &serde_json::to_vec(&definition).unwrap(),
    )
    .await
    .unwrap();
    kernel::adopt_definition_as(&w.db, &w.admin, &pin.family, Some(&pin))
        .await
        .unwrap();
    let mut state = kernel::ImportRecordState {
        definition: Some(kernel::ImportDefinition {
            pin,
            primary_type: "Document".into(),
            kind: "note".into(),
            fields: json!({"title":"Imported bound note"})
                .as_object()
                .unwrap()
                .clone(),
        }),
        body: Some("imported baseline".into()),
        ..Default::default()
    };
    kernel::import_record_as(&w.db, &host, &id, &home, Some(&w.admin), &state)
        .await
        .unwrap();
    let cutoff: i64 = sqlx::query_scalar("SELECT max(seq) FROM content_events")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let acts: Vec<(String, Option<i64>)> =
        sqlx::query_as("SELECT type,act FROM content_events WHERE record_id=? ORDER BY seq")
            .bind(&id)
            .fetch_all(w.db.pool())
            .await
            .unwrap();
    assert_eq!(acts.len(), 2);
    assert!(
        acts.iter().all(|(_, act)| act.is_some()),
        "import creation/snapshot must carry acts: {acts:?}"
    );
    assert_eq!(acts[0].1, acts[1].1, "atomic import shares its act");
    let imported = call_as(
        &w,
        "acct:admin",
        "render_record_version_diff",
        json!({"record_id":id,"before_seq":cutoff}),
    )
    .await
    .unwrap();
    assert_eq!(imported["before"]["record"]["body"], "imported baseline");
    assert_eq!(imported["before"]["record"]["name"], "Imported bound note");
    assert_eq!(imported["before"]["record"], imported["after"]["record"]);
    state.body = None;
    kernel::hq::resume_record_with_blob_as(&w.db, &host, &id, &home, Some(&w.admin), &state, None)
        .await
        .unwrap();
    let clear:String=sqlx::query_scalar("SELECT id FROM content_events WHERE record_id=? AND type='kernel.import_state_delta.v1' ORDER BY seq DESC LIMIT 1").bind(&id).fetch_one(w.db.pool()).await.unwrap();
    let context = call_as(
        &w,
        "acct:admin",
        "get_event_context",
        json!({"event_id":clear}),
    )
    .await
    .unwrap();
    assert_eq!(context["delta"]["before"], "imported baseline");
    assert_eq!(context["delta"]["after"], "");
    let version = kernel::read_record_as(&w.db, &w.admin, &id)
        .await
        .unwrap()
        .unwrap()
        .revision;
    kernel::set_body_as(&w.db, &w.admin, &id, "native after clear", version)
        .await
        .unwrap();
    let body_event:String=sqlx::query_scalar("SELECT id FROM content_events WHERE record_id=? AND type='kernel.body_set.v1' ORDER BY seq DESC LIMIT 1").bind(&id).fetch_one(w.db.pool()).await.unwrap();
    let context = call_as(
        &w,
        "acct:admin",
        "get_event_context",
        json!({"event_id":body_event}),
    )
    .await
    .unwrap();
    assert_eq!(context["delta"]["before"], "");
    assert_eq!(context["delta"]["after"], "native after clear");
    // Both older import transitions use their subject history rather than
    // reading the current body or replaying a workspace prefix.
    let older_clear = call_as(
        &w,
        "acct:admin",
        "get_event_context",
        json!({"event_id":clear}),
    )
    .await
    .unwrap();
    assert_eq!(older_clear["delta"]["before"], "imported baseline");
    assert_eq!(older_clear["delta"]["after"], "");
    let baseline: String = sqlx::query_scalar(
        "SELECT id FROM content_events WHERE record_id=? AND type='kernel.import_state.v1'",
    )
    .bind(&id)
    .fetch_one(w.db.pool())
    .await
    .unwrap();
    let older_baseline = call_as(
        &w,
        "acct:admin",
        "get_event_context",
        json!({"event_id":baseline}),
    )
    .await
    .unwrap();
    assert_eq!(older_baseline["delta"]["before"], "");
    assert_eq!(older_baseline["delta"]["after"], "imported baseline");
    let legacy_id = uuid::Uuid::new_v4().to_string();
    kernel::import_event_as(
        &w.db,
        &host,
        &id,
        &kernel::LegacyEvent {
            id: legacy_id.clone(),
            event_type: "record.updated".into(),
            payload: json!({"body":"old source text"}),
            created_at: "2001-01-01T00:00:00Z".into(),
            actor: Some("acct:admin".into()),
            run_key: None,
            source: Some(json!({"stream":"content","subjects":[id],"metadata":{"record_id":id}})),
        },
    )
    .await
    .unwrap();
    let missing_acts: i64 =
        sqlx::query_scalar("SELECT count(*) FROM content_events WHERE record_id=? AND act IS NULL")
            .bind(&id)
            .fetch_one(w.db.pool())
            .await
            .unwrap();
    assert_eq!(
        missing_acts, 0,
        "import snapshots, deltas and retained events carry acts"
    );
    let source_seq: i64 = sqlx::query_scalar("SELECT seq FROM content_events WHERE id=?")
        .bind(&legacy_id)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let error = call_as(
        &w,
        "acct:admin",
        "render_record_version_diff",
        json!({"record_id":id,"before_seq":source_seq}),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("source_position_unavailable"));
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    let result = call_as(
        &w,
        "acct:admin",
        "render_record_version_diff",
        json!({"record_id":id,"before_seq":cutoff}),
    )
    .await
    .unwrap();
    assert_eq!(result["before"]["record"]["body"], "imported baseline");
    assert_eq!(result["after"]["record"]["body"], "native after clear");
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_version_diff_object_facets_use_v1_current_schema() {
    let w = world().await;
    let v1 = crate::create_database(":memory:").await.unwrap();
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let data = json!({"shapes":{"Document":{"facets":{"detail":{"type":"object"}}}}}).to_string();
    let schema_id = uuid::Uuid::new_v4().to_string();
    let at = crate::store::now_iso();
    let row = json!({"id":schema_id,"layer":"user","name":"Object facet","data":data,"applies_to_collection_id":null,"version_lineage":null,"created_at":at});
    kernel::v1_state::import_state_batch_as(
        &w.db,
        &host,
        &[kernel::v1_state::ImportedState {
            section: "schema_config".into(),
            source_id: schema_id.clone(),
            origin: "object-facet-fixture".into(),
            value_json: Some(row.to_string()),
            account_principal: None,
            record_id: None,
            observed_at: at.clone(),
            snapshot: json!({}),
        }],
    )
    .await
    .unwrap();
    sqlx::query("INSERT INTO schema_config(id,layer,name,data,created_at) VALUES(?,'user','Object facet',?,?)").bind(&schema_id).bind(&data).bind(&at).execute(v1.write_pool()).await.unwrap();
    registry().call(v1.clone(),Caller::local(),"create_record",json!({"id":w.first,"type":"Document","kind":"note","name":"Alpha","body":"revised","reason":"facet fixture"})).await.unwrap();
    let mut cutoffs = Vec::new();
    for n in [1, 2] {
        let object = json!({"answer":n});
        kernel::observe_facet_as(
            &w.db,
            &w.admin,
            &w.first,
            &kernel::FacetObservation {
                key: "detail".into(),
                value: Some(object.to_string()),
                value_num: None,
                vocab_ref: None,
                as_of: crate::store::now_iso(),
            },
            None,
        )
        .await
        .unwrap();
        registry()
            .call(
                v1.clone(),
                Caller::local(),
                "update_record",
                json!({"id":w.first,"facets":{"detail":object},"reason":"facet fixture"}),
            )
            .await
            .unwrap();
        let k: i64 = sqlx::query_scalar("SELECT max(seq) FROM content_events")
            .fetch_one(w.db.pool())
            .await
            .unwrap();
        let v: i64 = sqlx::query_scalar("SELECT max(seq) FROM content_events")
            .fetch_one(v1.pool())
            .await
            .unwrap();
        cutoffs.push((k, v));
    }
    let actual = call(
        &w,
        "render_record_version_diff",
        json!({"record_id":w.first,"before_seq":cutoffs[0].0}),
    )
    .await
    .unwrap();
    let expected = registry()
        .call(
            v1.clone(),
            Caller::local(),
            "render_record_version_diff",
            json!({"record_id":w.first,"before_seq":cutoffs[0].1}),
        )
        .await
        .unwrap();
    for endpoint in ["before", "after"] {
        let find = |value: &Value| {
            value[endpoint]["record"]["facets"]
                .as_array()
                .unwrap()
                .iter()
                .find(|f| f["key"] == "detail")
                .unwrap()["value"]
                .clone()
        };
        assert_eq!(find(&actual), find(&expected));
        assert!(find(&actual).is_object());
    }
    v1.close().await;
    w.db.close().await;
}
#[tokio::test]
async fn kernel_v2_history_prefix_bounds_meta_and_keeps_only_blob_handles() {
    let w = world().await;
    install_comment_carrier(&w).await;
    let target = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap();
    kernel::set_body_as(&w.db, &w.admin, &w.first, "before meta", target.revision)
        .await
        .unwrap();
    let attachment = call_as(
        &w,
        "acct:admin",
        "attach_text",
        json!({"record_id":w.first,"text":"x".repeat(1024*1024),"filename":"historical.txt"}),
    )
    .await
    .unwrap();
    // An unrelated immutable blob must not enter the projection either.
    let bytes = b"unreferenced synthetic bytes";
    let unused = crate::blob::new_blob_meta(bytes, Some("text/plain"), None);
    let mut tx = crate::db::begin_write(w.db.write_pool()).await.unwrap();
    kernel::blobs::put(&mut tx, bytes, &unused).await.unwrap();
    tx.commit().await.unwrap();
    let cutoff: i64 = sqlx::query_scalar("SELECT max(seq) FROM content_events")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let raw: String = sqlx::query_scalar(
        "SELECT artifact_bytes FROM definition_artifacts WHERE family='fixture.mcp' AND version=1",
    )
    .fetch_one(w.db.pool())
    .await
    .unwrap();
    let mut definition: Value = serde_json::from_str(&raw).unwrap();
    definition["family"] = json!("fixture.future");
    kernel::install_definition_as(
        &w.db,
        &w.admin,
        "fixture.future",
        1,
        &serde_json::to_vec(&definition).unwrap(),
    )
    .await
    .unwrap();
    let target = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap();
    kernel::set_body_as(&w.db, &w.admin, &w.first, "after meta", target.revision)
        .await
        .unwrap();
    let (selected_seq, selected_id): (i64, String) =
        sqlx::query_as("SELECT seq,id FROM content_events ORDER BY seq DESC LIMIT 1")
            .fetch_one(w.db.pool())
            .await
            .unwrap();
    let other = kernel::read_record_as(&w.db, &w.admin, &w.second)
        .await
        .unwrap()
        .unwrap();
    kernel::set_body_as(
        &w.db,
        &w.admin,
        &w.second,
        "later unrelated",
        other.revision,
    )
    .await
    .unwrap();
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    let mut live = w.db.pool().begin().await.unwrap();
    let historical = kernel::historical::prefix_on(&mut live, cutoff)
        .await
        .unwrap();
    let future: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM definition_artifacts WHERE family='fixture.future'",
    )
    .fetch_one(historical.pool())
    .await
    .unwrap();
    assert_eq!(
        future, 0,
        "later meta-only definitions must not enter the prefix"
    );
    let byte_columns: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pragma_table_info('kernel_blobs') WHERE name='bytes'",
    )
    .fetch_one(historical.pool())
    .await
    .unwrap();
    assert_eq!(
        byte_columns, 0,
        "the projection cannot store fabricated or copied bytes"
    );
    let handles: i64 = sqlx::query_scalar("SELECT count(*) FROM kernel_blobs")
        .fetch_one(historical.pool())
        .await
        .unwrap();
    assert_eq!(handles, 1, "only the referenced content handle is replayed");
    let metadata: String =
        sqlx::query_scalar("SELECT metadata FROM kernel_attachment_blobs WHERE record_id=?")
            .bind(attachment["attachment_id"].as_str().unwrap())
            .fetch_one(historical.pool())
            .await
            .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&metadata).unwrap(),
        attachment["blob"]
    );
    kernel::historical::advance_body_on(&mut live, &historical, selected_seq)
        .await
        .unwrap();
    let future: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM definition_artifacts WHERE family='fixture.future'",
    )
    .fetch_one(historical.pool())
    .await
    .unwrap();
    assert_eq!(
        future, 1,
        "advancement folds the selected event's intervening meta"
    );
    let body: String =
        sqlx::query_scalar("SELECT body FROM kernel_record_bodies WHERE record_id=?")
            .bind(&w.first)
            .fetch_one(historical.pool())
            .await
            .unwrap();
    assert_eq!(body, "after meta");
    historical.close().await;
    live.rollback().await.unwrap();
    let context = call(&w, "get_event_context", json!({"event_id":selected_id}))
        .await
        .unwrap();
    assert_eq!(context["delta"]["before"], "before meta");
    assert_eq!(context["delta"]["after"], "after meta");
    let history =
        kernel::history_page_as(&w.db, &w.viewer, &w.first, None, false, 256, true, false)
            .await
            .unwrap();
    let previous = context["delta"]["before_event_id"].as_str().unwrap();
    assert!(
        history.iter().any(|event| event.id == previous),
        "prior event id must pass canonical disclosure"
    );
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    let diff = call(
        &w,
        "render_record_version_diff",
        json!({"record_id":attachment["attachment_id"],"before_seq":cutoff}),
    )
    .await
    .unwrap();
    assert_eq!(diff["before"]["record"]["blob"], attachment["blob"]);
    assert_eq!(diff["after"]["record"]["blob"], attachment["blob"]);
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_version_diff_does_not_classify_another_records_cutoff() {
    let w = world().await;
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    kernel::import_event_as(
        &w.db,
        &host,
        &w.hidden,
        &kernel::LegacyEvent {
            source: None,
            id: uuid::Uuid::new_v4().to_string(),
            event_type: "record.updated".into(),
            payload: json!({"body":"secret retained body"}),
            actor: None,
            run_key: None,
            created_at: "2020-01-01T00:00:00Z".into(),
        },
    )
    .await
    .unwrap();
    let retained: i64 = sqlx::query_scalar("SELECT max(seq) FROM content_events")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let before = call(
        &w,
        "render_record_version_diff",
        json!({"record_id":w.first,"before_seq":retained}),
    )
    .await
    .unwrap();
    let hidden = kernel::read_record_as(&w.db, &w.admin, &w.hidden)
        .await
        .unwrap()
        .unwrap();
    kernel::set_body_as(
        &w.db,
        &w.admin,
        &w.hidden,
        "secret native body",
        hidden.revision,
    )
    .await
    .unwrap();
    let native: i64 = sqlx::query_scalar("SELECT max(seq) FROM content_events")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let control = call(
        &w,
        "render_record_version_diff",
        json!({"record_id":w.first,"before_seq":native}),
    )
    .await
    .unwrap();
    assert_eq!(before["before"]["record"], control["before"]["record"]);
    assert_eq!(before["events"], json!([]));
    for secret in [&w.hidden, "secret retained body", "secret native body"] {
        assert!(!before.to_string().contains(secret));
        assert!(!control.to_string().contains(secret));
    }
    // Current View on the record also must not reveal a retained event that
    // canonical history withholds because it names a hidden dependency.
    kernel::import_event_as(&w.db, &host, &w.first, &kernel::LegacyEvent {
        source: Some(json!({"stream":"content","subjects":[w.first,w.hidden],"metadata":{"record_id":w.first}})),
        id: uuid::Uuid::new_v4().to_string(), event_type: "record.updated".into(),
        payload: json!({"body":"secret dependency event"}), actor: None, run_key: None,
        created_at: "2020-01-01T00:00:01Z".into(),
    }).await.unwrap();
    let withheld: i64 = sqlx::query_scalar("SELECT max(seq) FROM content_events")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let disclosed = kernel::history_page_in_range_as(
        &w.db,
        &w.viewer,
        &w.first,
        Some(withheld - 1),
        false,
        1,
        false,
        false,
        (withheld, withheld),
    )
    .await
    .unwrap();
    assert!(disclosed.is_empty());
    let ordinary_position = call(
        &w,
        "render_record_version_diff",
        json!({"record_id":w.first,"before_seq":withheld}),
    )
    .await
    .unwrap();
    assert_eq!(
        ordinary_position["before"]["record"]["body"],
        control["before"]["record"]["body"]
    );
    assert!(!ordinary_position
        .to_string()
        .contains("secret dependency event"));
    assert!(!ordinary_position.to_string().contains(&w.hidden));
    let hidden_error = call(
        &w,
        "render_record_version_diff",
        json!({"record_id":w.hidden,"before_seq":retained}),
    )
    .await
    .unwrap_err()
    .to_string();
    let missing_error = call(
        &w,
        "render_record_version_diff",
        json!({"record_id":uuid::Uuid::new_v4().to_string(),"before_seq":retained}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(hidden_error, missing_error);
    assert!(!hidden_error.contains("source_position_unavailable"));
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_scoped_history_matches_canonical_subject_state() {
    let w = world().await;
    let mut positions = Vec::new();
    for (i, facet_value) in [Some("new"), Some("older"), None].into_iter().enumerate() {
        kernel::revise_as(
            &w.db,
            &w.admin,
            &w.first,
            json!({"body":if i==2 {Value::Null} else {json!(format!("field {i}"))}})
                .as_object()
                .unwrap(),
        )
        .await
        .unwrap();
        kernel::observe_facet_as(
            &w.db,
            &w.admin,
            &w.first,
            &kernel::FacetObservation {
                key: "free.form".into(),
                value: facet_value.map(str::to_owned),
                value_num: facet_value.map(|_| 0.12345678912345678),
                vocab_ref: None,
                as_of: if i == 1 {
                    "2026-10-19T00:00:00Z"
                } else {
                    "2026-10-20T00:00:00Z"
                }
                .into(),
            },
            None,
        )
        .await
        .unwrap();
        let record = kernel::read_record_as(&w.db, &w.admin, &w.first)
            .await
            .unwrap()
            .unwrap();
        kernel::set_record_metadata_as(
            &w.db,
            &w.admin,
            &w.first,
            None,
            Some(if i == 2 { None } else { Some("current") }),
            record.revision,
        )
        .await
        .unwrap();
        positions.push(
            sqlx::query_scalar::<_, i64>("SELECT max(seq) FROM content_events")
                .fetch_one(w.db.pool())
                .await
                .unwrap(),
        );
    }
    let link = kernel::add_generic_link_as(
        &w.db,
        &w.admin,
        &w.second,
        &w.first,
        "cites",
        Some("before".into()),
    )
    .await
    .unwrap();
    positions.push(
        sqlx::query_scalar::<_, i64>("SELECT max(seq) FROM content_events")
            .fetch_one(w.db.pool())
            .await
            .unwrap(),
    );
    kernel::add_generic_link_as(
        &w.db,
        &w.admin,
        &w.second,
        &w.first,
        "cites",
        Some("after".into()),
    )
    .await
    .unwrap();
    positions.push(
        sqlx::query_scalar::<_, i64>("SELECT max(seq) FROM content_events")
            .fetch_one(w.db.pool())
            .await
            .unwrap(),
    );
    kernel::remove_generic_link_as(&w.db, &w.admin, &w.second, &link.link.link_id)
        .await
        .unwrap();
    positions.push(
        sqlx::query_scalar::<_, i64>("SELECT max(seq) FROM content_events")
            .fetch_one(w.db.pool())
            .await
            .unwrap(),
    );
    // Exercise every directed/generic link envelope the canonical replay
    // projects, at positions before and after each addition/note/removal.
    let home = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let mut directed_sources = Vec::new();
    for (family, interpreter, target, identity) in [
        (
            "fixture.history.directed",
            "native.defn/4",
            json!({"any_record":true}),
            json!({"mode":"record"}),
        ),
        (
            "fixture.history.legacy",
            "native.defn/2",
            json!({"primary_type":"Document","kind":"note"}),
            json!({"field":"title"}),
        ),
    ] {
        let definition = json!({"family":family,"version":1,"interpreter":interpreter,"primary_type":"Document",
            "kinds":[{"token":"note","description":"Historical links","maturity":"current","identity":identity,
                "fields":[{"name":"title","type":"text","required":true}],
                "links":[{"predicate":"backs","target":target,"direction":"out","cardinality":"many"}]}]});
        let pin = kernel::install_definition_as(
            &w.db,
            &w.admin,
            family,
            1,
            &serde_json::to_vec(&definition).unwrap(),
        )
        .await
        .unwrap();
        kernel::adopt_definition_as(&w.db, &w.admin, family, Some(&pin))
            .await
            .unwrap();
        let source = kernel::create_as(
            &w.db,
            &w.admin,
            family,
            "note",
            json!({"title":family}).as_object().unwrap(),
            &home,
        )
        .await
        .unwrap();
        directed_sources.push(source);
    }
    for source in &directed_sources {
        kernel::link_as(&w.db, &w.admin, source, "backs", &w.first)
            .await
            .unwrap();
        let cutoff: i64 = sqlx::query_scalar("SELECT max(seq) FROM content_events")
            .fetch_one(w.db.pool())
            .await
            .unwrap();
        positions.push(cutoff);
        // The actual tool must not invent an addition for an unchanged edge.
        let diff = call_as(
            &w,
            "acct:admin",
            "render_record_version_diff",
            json!({"record_id":source,"before_seq":cutoff}),
        )
        .await
        .unwrap();
        assert_eq!(
            diff["before"]["record"]["links_out"],
            diff["after"]["record"]["links_out"]
        );
        assert!(diff["before"]["record"]["links_out"]
            .as_array()
            .unwrap()
            .iter()
            .any(|l| l["relationship"] == "backs"));
        let revision = kernel::read_record_as(&w.db, &w.admin, source)
            .await
            .unwrap()
            .unwrap()
            .revision;
        kernel::unlink_as(&w.db, &w.admin, source, "backs", &w.first, revision)
            .await
            .unwrap();
        positions.push(
            sqlx::query_scalar("SELECT max(seq) FROM content_events")
                .fetch_one(w.db.pool())
                .await
                .unwrap(),
        );
    }
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let mut imported = kernel::GenericLink {
        link_id: uuid::Uuid::new_v4().to_string(),
        source_id: w.second.clone(),
        target_id: w.first.clone(),
        relationship: "imported cites".into(),
        note: Some("original import".into()),
        created_at: "2020-01-01T00:00:00Z".into(),
        actor: Some("source author".into()),
    };
    kernel::import_generic_link_as(&w.db, &host, &imported)
        .await
        .unwrap();
    positions.push(
        sqlx::query_scalar("SELECT max(seq) FROM content_events")
            .fetch_one(w.db.pool())
            .await
            .unwrap(),
    );
    imported.note = Some("revised import".into());
    kernel::import_generic_link_as(&w.db, &host, &imported)
        .await
        .unwrap();
    positions.push(
        sqlx::query_scalar("SELECT max(seq) FROM content_events")
            .fetch_one(w.db.pool())
            .await
            .unwrap(),
    );
    kernel::import_generic_link_removal_as(
        &w.db,
        &host,
        &imported.link_id,
        &kernel::ImportRemovalEvidence {
            source_origin: "synthetic".into(),
            snapshot: "fixture".into(),
            reason: "source removal".into(),
            deleted_at: None,
            source_event: None,
        },
    )
    .await
    .unwrap();
    positions.push(
        sqlx::query_scalar("SELECT max(seq) FROM content_events")
            .fetch_one(w.db.pool())
            .await
            .unwrap(),
    );
    let types: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT type FROM content_events WHERE type LIKE 'kernel.%link_%' ORDER BY type",
    )
    .fetch_all(w.db.pool())
    .await
    .unwrap();
    for typ in [
        "kernel.link_added.v1",
        "kernel.link_added.v2",
        "kernel.link_removed.v1",
        "kernel.generic_link_added.v1",
        "kernel.generic_link_note_updated.v1",
        "kernel.generic_link_removed.v1",
        "kernel.generic_link_imported.v1",
        "kernel.generic_link_note_imported.v1",
        "kernel.generic_link_removal_imported.v1",
    ] {
        assert!(
            types.iter().any(|t| t == typ),
            "missing oracle fixture for {typ}"
        );
    }
    let package = crate::v2_standard::relates_to::package();
    let package_id = kernel::install_package_as(&w.db, &w.admin, &package)
        .await
        .unwrap();
    kernel::adopt_package_at(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &package,
        Some(&package_id),
        &package.declared_reads,
    )
    .await
    .unwrap();
    let bare = kernel::create_record_as(&w.db, &w.admin, KERNEL_ROOT_ID)
        .await
        .unwrap();
    let request = kernel::prepare_provider_as(
        &w.db,
        &w.admin,
        &bare,
        &w.first,
        "history-assert",
        crate::v2_standard::relates_to::Command::Assert { sources: vec![] },
    )
    .await
    .unwrap();
    let receipt = kernel::commit_provider_as(&w.db, &w.admin, &request)
        .await
        .unwrap();
    positions.push(receipt.event_seq);
    let request = kernel::prepare_provider_as(
        &w.db,
        &w.admin,
        &bare,
        &w.first,
        "history-retract",
        crate::v2_standard::relates_to::Command::Retract {
            assertion_id: receipt.assertion_id,
        },
    )
    .await
    .unwrap();
    positions.push(
        kernel::commit_provider_as(&w.db, &w.admin, &request)
            .await
            .unwrap()
            .event_seq,
    );
    directed_sources.push(bare);
    let untouched = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    let mut live = w.db.pool().begin().await.unwrap();
    for seq in positions {
        let scoped = kernel::historical::record_at_on(&mut live, &w.admin, &w.first, seq)
            .await
            .unwrap()
            .unwrap();
        let oracle = kernel::historical::prefix_on(&mut live, seq).await.unwrap();
        let mut historical = oracle.pool().begin().await.unwrap();
        let expected = kernel::read_record_unchecked_on(&mut historical, &w.admin, &w.first)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(scoped.fields, expected.fields, "fields at {seq}");
        assert_eq!(scoped.body, expected.body, "body at {seq}");
        assert_eq!(scoped.metadata, expected.metadata, "metadata at {seq}");
        assert_eq!(scoped.archived, expected.archived);
        assert_eq!(scoped.home_id, expected.home_id);
        assert_eq!(scoped.revision, expected.revision);
        let facets:Vec<kernel::FacetObservation>=sqlx::query_as("SELECT key,value,value_num,vocab_ref,as_of FROM kernel_facets WHERE record_id=? ORDER BY key").bind(&w.first).fetch_all(&mut *historical).await.unwrap();
        assert_eq!(scoped.facets.values().cloned().collect::<Vec<_>>(), facets);
        for id in [&w.first, &w.second]
            .into_iter()
            .chain(directed_sources.iter())
        {
            let links = kernel::historical::links_at_on(&mut live, &w.admin, id, seq)
                .await
                .unwrap();
            let mut expected:Vec<String>=sqlx::query_scalar("SELECT json_object('id',link_id,'source_id',source_id,'target_id',target_id,'relationship',relationship,'note',note,'created_at',created_at) FROM kernel_generic_links WHERE (source_id=?1 OR target_id=?1) AND active=1 UNION ALL SELECT json_object('id',NULL,'source_id',l.source_id,'target_id',l.target_id,'relationship',l.relationship,'note',NULL,'created_at',e.created_at) FROM kernel_links l JOIN content_events e ON e.seq=l.created_seq WHERE l.source_id=?1 OR l.target_id=?1").bind(id).fetch_all(&mut *historical).await.unwrap();
            let states:Vec<String>=sqlx::query_scalar("SELECT p.state_json FROM kernel_provider_state p JOIN kernel_provider_subjects s ON s.aggregate_id=p.id WHERE s.subject_id=? AND p.provider_key='relates_to.v1'").bind(id).fetch_all(&mut *historical).await.unwrap();
            for state in states {
                if let Some((left, right)) =
                    kernel::relates_to_port::active_pair_from_state(&state).unwrap()
                {
                    for (source, target) in [(&left, &right), (&right, &left)] {
                        expected.push(serde_json::to_string(&json!({"id":null,"source_id":source,"target_id":target,"relationship":"relates_to","note":null,"created_at":null})).unwrap());
                    }
                }
            }
            // Compare complete edge objects across all predicates and both
            // directions, including original timestamps and updated notes.
            let mut actual = links
                .into_iter()
                .map(|mut link| {
                    link.as_object_mut().unwrap().remove("_subjects");
                    serde_json::to_string(&link).unwrap()
                })
                .collect::<Vec<_>>();
            let mut expected = expected
                .into_iter()
                .map(|raw| {
                    serde_json::to_string(&serde_json::from_str::<Value>(&raw).unwrap()).unwrap()
                })
                .collect::<Vec<_>>();
            actual.sort();
            expected.sort();
            assert_eq!(actual, expected, "links for {id} at {seq}");
        }
        historical.rollback().await.unwrap();
        oracle.close().await;
    }
    assert!(
        kernel::historical::record_at_on(&mut live, &w.viewer, &w.hidden, i64::MAX)
            .await
            .unwrap()
            .is_none()
    );
    live.rollback().await.unwrap();
    assert_eq!(
        untouched,
        kernel::dump_all_kernel_tables(&w.db).await.unwrap()
    );
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_scoped_history_never_replays_unrelated_payloads() {
    let w = world().await;
    let before = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap();
    let cutoff = before.revision;
    kernel::set_body_as(&w.db, &w.admin, &w.first, "subject only", before.revision)
        .await
        .unwrap();
    let event:String=sqlx::query_scalar("SELECT id FROM content_events WHERE record_id=? AND type='kernel.body_set.v1' ORDER BY seq DESC LIMIT 1").bind(&w.first).fetch_one(w.db.pool()).await.unwrap();
    let args = json!({"record_id":w.first,"before_seq":cutoff});
    let mut expected_diff = call(&w, "render_record_version_diff", args.clone())
        .await
        .unwrap();
    let expected_context = call(&w, "get_event_context", json!({"event_id":event}))
        .await
        .unwrap();
    // Fault injection in an unrelated stream: full-prefix replay would parse
    // this invalid body envelope. Subject readers must never load or fold it.
    let mut tx = crate::db::begin_write(w.db.write_pool()).await.unwrap();
    sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at,act,causal_envelope_version,causal_status) SELECT ?,?,'kernel.body_set.v1','{}',actor,created_at,act,causal_envelope_version,causal_status FROM content_events ORDER BY seq DESC LIMIT 1")
        .bind(uuid::Uuid::new_v4().to_string()).bind(&w.hidden).execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    let mut actual = call(&w, "render_record_version_diff", args).await.unwrap();
    expected_diff["after"]["as_of_seq"] = Value::Null;
    actual["after"]["as_of_seq"] = Value::Null;
    assert_eq!(actual, expected_diff);
    assert_eq!(
        call(&w, "get_event_context", json!({"event_id":event}))
            .await
            .unwrap(),
        expected_context
    );
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_scoped_history_keeps_moved_children_and_removed_parts_at_cutoff() {
    let w = world().await;
    install_comment_carrier(&w).await;
    let folder=call_as(&w,"acct:admin","create_record",json!({"type":"Collection","kind":"folder","name":"Earlier parent","reason":"history fixture"})).await.unwrap()["id"].as_str().unwrap().to_owned();
    let child = kernel::create_as(
        &w.db,
        &w.admin,
        "fixture.mcp",
        "note",
        json!({"title":"Moved later"}).as_object().unwrap(),
        &crate::v1_import::derived(&folder),
    )
    .await
    .unwrap();
    let comment=call_as(&w,"acct:admin","create_record",json!({"type":"Annotation","kind":"comment","body":"Earlier comment","links":[{"target_id":folder,"relationship":"part_of"}]})).await.unwrap()["id"].as_str().unwrap().to_owned();
    let cutoff: i64 = sqlx::query_scalar("SELECT max(seq) FROM content_events")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    kernel::rehome_record_as(&w.db, &w.admin, &child, KERNEL_ROOT_ID)
        .await
        .unwrap();
    // Native removals retain the stable link identity for historical discovery.
    let part:String=sqlx::query_scalar("SELECT link_id FROM kernel_generic_links WHERE source_id=? AND target_id=? AND relationship='part_of' AND active=1").bind(&comment).bind(&folder).fetch_one(w.db.pool()).await.unwrap();
    kernel::remove_generic_link_as(&w.db, &w.admin, &comment, &part)
        .await
        .unwrap();
    let result = call_as(
        &w,
        "acct:admin",
        "render_record_version_diff",
        json!({"record_id":folder,"before_seq":cutoff}),
    )
    .await
    .unwrap();
    assert_eq!(result["before"]["record"]["child_count"], 1);
    assert_eq!(result["before"]["record"]["children"][0]["id"], child);
    assert_eq!(result["after"]["record"]["child_count"], 0);
    // Detached annotations fail the live bearer View gate, even though the
    // old part_of event and child exist at the historical position.
    assert_eq!(result["before"]["record"]["comment_count"], 0);
    assert_eq!(result["after"]["record"]["comment_count"], 0);
    w.db.close().await;
}

async fn suggestion_v1_fixture(w: &World) -> Db {
    let v1 = crate::create_database(":memory:").await.unwrap();
    install_comment_carrier(w).await;
    let target = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap();
    kernel::set_body_as(&w.db, &w.admin, &w.first, "revised", target.revision)
        .await
        .unwrap();
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let at = crate::store::now_iso();
    for (section,sql) in [
        ("vocabularies","SELECT json_object('id',id,'name',name,'created_at',created_at) FROM vocabularies"),
        ("vocabulary_values","SELECT json_object('id',id,'vocabulary_id',vocabulary_id,'value',value,'gloss',gloss,'status',status,'ordinal',ordinal,'terminality',terminality,'metadata',metadata,'alias_of',alias_of) FROM vocabulary_values"),
    ] {
        let rows: Vec<String> = sqlx::query_scalar(sql).fetch_all(v1.pool()).await.unwrap();
        let rows: Vec<_> = rows.into_iter().map(|raw| {
            let row: Value = serde_json::from_str(&raw).unwrap();
            kernel::v1_state::ImportedState {section:section.into(),source_id:row["id"].as_str().unwrap().into(),origin:"suggestion-fixture".into(),value_json:Some(raw),account_principal:None,record_id:None,observed_at:at.clone(),snapshot:json!({})}
        }).collect();
        for batch in rows.chunks(256) {kernel::v1_state::import_state_batch_as(&w.db,&host,batch).await.unwrap();}
    }
    registry().call(v1.clone(),Caller::local(),"create_record",json!({"id":w.first,"type":"Document","kind":"note","name":"Target","body":"revised","reason":"suggestion parity fixture"})).await.unwrap();
    v1
}
async fn make_suggestion(
    w: &World,
    v1: &Db,
    old: Option<&str>,
    replacement: &str,
    precondition: &str,
) -> String {
    let mut facets = json!({"proposal.precondition":precondition});
    if let Some(old) = old {
        facets["anchor.old"] = json!(old);
    }
    let mut args = json!({"type":"Annotation","kind":"suggestion","name":"Suggestion","body":replacement,"lifecycle":"open","facets":facets,"links":[{"target_id":w.first,"relationship":"part_of"}],"reason":"suggestion fixture"});
    let created = call_as(w, "acct:admin", "create_record", args.clone())
        .await
        .unwrap();
    let id = created["id"].as_str().unwrap().to_owned();
    args["id"] = json!(id);
    registry()
        .call(v1.clone(), Caller::local(), "create_record", args)
        .await
        .unwrap();
    id
}
fn suggestion_outcome(mut value: Value) -> Value {
    if let Some(object) = value.as_object_mut() {
        object.remove("act");
        object.remove("app_attribution");
        object.remove("action_attestation_ids");
    }
    value
}
async fn compare_suggestion(w: &World, v1: &Db, args: Value) -> Value {
    let actual = call_as(w, "acct:admin", "resolve_suggestions", args.clone())
        .await
        .unwrap();
    let expected = registry()
        .call(v1.clone(), Caller::local(), "resolve_suggestions", args)
        .await
        .unwrap();
    assert_eq!(
        suggestion_outcome(actual.clone()),
        suggestion_outcome(expected)
    );
    actual
}

#[tokio::test]
async fn kernel_v2_suggestions_share_v1_preconditions_dry_run_and_authority() {
    let w = world().await;
    let v1 = suggestion_v1_fixture(&w).await;
    let id = make_suggestion(&w, &v1, Some("revised"), "accepted text", "span").await;
    let dry = json!({"action":"accept","suggestion_ids":[id],"reason":"preview","dry_run":true});
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    let preview = compare_suggestion(&w, &v1, dry.clone()).await;
    assert_eq!(preview["status"], "would_accept");
    assert_eq!(preview["prospective_body"], "accepted text");
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    assert!(call(&w, "resolve_suggestions", dry.clone()).await.is_err());
    assert!(call_as(&w, "acct:unknown", "resolve_suggestions", dry)
        .await
        .is_err());
    let accepted = compare_suggestion(
        &w,
        &v1,
        json!({"action":"accept","suggestion_ids":[id],"reason":"accept"}),
    )
    .await;
    assert_eq!(accepted["status"], "accepted");
    assert_eq!(
        kernel::read_record_as(&w.db, &w.admin, &w.first)
            .await
            .unwrap()
            .unwrap()
            .body
            .as_deref(),
        Some("accepted text")
    );
    let conflict = compare_suggestion(
        &w,
        &v1,
        json!({"action":"accept","suggestion_ids":[id],"reason":"repeat","dry_run":true}),
    )
    .await;
    assert_eq!(conflict["status"], "would_conflict");
    for precondition in ["field_equals", "seq"] {
        let id = make_suggestion(&w, &v1, None, "replacement", precondition).await;
        let args = json!({"action":"accept","suggestion_ids":[id],"reason":"reserved predicate","dry_run":true});
        let actual = call_as(&w, "acct:admin", "resolve_suggestions", args.clone())
            .await
            .unwrap_err()
            .to_string();
        let expected = registry()
            .call(v1.clone(), Caller::local(), "resolve_suggestions", args)
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(actual, expected);
    }
    let home: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
        .bind(&w.first)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    kernel::replace_home_policy(&w.db, &w.admin, &home, &[])
        .await
        .unwrap();
    assert!(call(
        &w,
        "resolve_suggestions",
        json!({"action":"reject","suggestion_ids":[id],"reason":"no View"})
    )
    .await
    .is_err());
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    v1.close().await;
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_suggestions_stale_and_reject_replay_match_v1() {
    let w = world().await;
    let v1 = suggestion_v1_fixture(&w).await;
    let stale = make_suggestion(&w, &v1, Some("absent"), "replacement", "span").await;
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    assert_eq!(
        compare_suggestion(
            &w,
            &v1,
            json!({"action":"accept","suggestion_ids":[stale],"reason":"preview","dry_run":true})
        )
        .await["status"],
        "would_stale"
    );
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    assert_eq!(
        compare_suggestion(
            &w,
            &v1,
            json!({"action":"accept","suggestion_ids":[stale],"reason":"stale"})
        )
        .await["status"],
        "stale"
    );
    let id = make_suggestion(&w, &v1, None, "replacement", "none").await;
    let args = json!({"action":"reject","suggestion_ids":[id],"reason":"reject","idempotency_key":"reject-proof"});
    let first = compare_suggestion(&w, &v1, args.clone()).await;
    assert_eq!(first["status"], "rejected");
    assert_eq!(
        first,
        call_as(&w, "acct:admin", "resolve_suggestions", args.clone())
            .await
            .unwrap()
    );
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(
        first,
        call_as(&w, "acct:admin", "resolve_suggestions", args.clone())
            .await
            .unwrap()
    );
    // A keyed accept commits once and replays identically on the kernel
    // engine, matching V1's receipt.
    let fresh = make_suggestion(&w, &v1, None, "replacement", "none").await;
    let keyed = json!({"action":"accept","suggestion_ids":[fresh],"reason":"keyed accept","idempotency_key":"accept-proof"});
    let first = compare_suggestion(&w, &v1, keyed.clone()).await;
    assert_eq!(first["status"], "accepted", "{first}");
    let replayed = call_as(&w, "acct:admin", "resolve_suggestions", keyed.clone())
        .await
        .unwrap();
    assert_eq!(replayed, first);
    let mut changed = args.clone();
    changed["reason"] = json!("changed");
    assert!(call_as(&w, "acct:admin", "resolve_suggestions", changed)
        .await
        .is_err());
    // A keyed accept of an already-resolved suggestion is a structured
    // conflict on both engines: the key replays only what it first wrote,
    // and this key wrote nothing.
    let resolved = compare_suggestion(
        &w,
        &v1,
        json!({"action":"accept","suggestion_ids":[id],"reason":"keyed","idempotency_key":"accept"}),
    )
    .await;
    assert_eq!(resolved["status"], "conflict", "{resolved}");
    for args in [
        json!({"action":"reject","suggestion_ids":[id],"reason":"preview","dry_run":true}),
        json!({"action":"accept","suggestion_ids":[id],"reason":"unsupported","replacement":{"text":"forbidden"}}),
    ] {
        assert!(
            call_as(&w, "acct:admin", "resolve_suggestions", args.clone())
                .await
                .is_err()
        );
        assert!(registry()
            .call(v1.clone(), Caller::local(), "resolve_suggestions", args)
            .await
            .is_err());
    }
    v1.close().await;
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_suggestions_ordered_batch_conflicts_are_atomic() {
    let w = world().await;
    let v1 = suggestion_v1_fixture(&w).await;
    let one = make_suggestion(&w, &v1, Some("revised"), "one", "span").await;
    let two = make_suggestion(&w, &v1, Some("revised"), "two", "span").await;
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    for dry in [true, false] {
        let outcome = compare_suggestion(
            &w,
            &v1,
            json!({"action":"accept","suggestion_ids":[one,two],"reason":"overlap","dry_run":dry}),
        )
        .await;
        assert_eq!(outcome["causes"][0]["code"], "batch_overlap");
        assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    }
    let one = make_suggestion(&w, &v1, Some("re"), "RE", "span").await;
    let two = make_suggestion(&w, &v1, Some("vised"), "VISED", "none").await;
    let preview = compare_suggestion(
        &w,
        &v1,
        json!({"action":"accept","suggestion_ids":[one,two],"reason":"ordered","dry_run":true}),
    )
    .await;
    assert_eq!(preview["prospective_body"], "REVISED");
    assert_eq!(
        compare_suggestion(
            &w,
            &v1,
            json!({"action":"accept","suggestion_ids":[one,two],"reason":"ordered"})
        )
        .await["status"],
        "accepted"
    );
    let one = make_suggestion(&w, &v1, None, "one", "none").await;
    let two = make_suggestion(&w, &v1, None, "two", "none").await;
    let args =
        json!({"action":"accept","suggestion_ids":[one,two],"reason":"whole body cannot batch"});
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    assert!(
        call_as(&w, "acct:admin", "resolve_suggestions", args.clone())
            .await
            .is_err()
    );
    assert!(registry()
        .call(v1.clone(), Caller::local(), "resolve_suggestions", args)
        .await
        .is_err());
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    let home: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
        .bind(&w.first)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    kernel::replace_home_policy(&w.db, &w.admin, &home, &[(&w.viewer, "edit")])
        .await
        .unwrap();
    // Annotation placement is at the admin root. Bearer Edit is sufficient;
    // resolution must not require Edit on that independent filing home.
    assert_eq!(
        call(
            &w,
            "resolve_suggestions",
            json!({"action":"reject","suggestion_ids":[one],"reason":"bearer editor"})
        )
        .await
        .unwrap()["status"],
        "rejected"
    );
    v1.close().await;
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_suggestions_archived_state_matches_current_v1() {
    let w = world().await;
    let v1 = suggestion_v1_fixture(&w).await;
    let id = make_suggestion(&w, &v1, None, "replacement", "none").await;
    let record = kernel::read_record_as(&w.db, &w.admin, &id)
        .await
        .unwrap()
        .unwrap();
    kernel::set_archived_as(&w.db, &w.admin, &id, true, record.revision)
        .await
        .unwrap();
    registry()
        .call(
            v1.clone(),
            Caller::local(),
            "archive_record",
            json!({"id":id,"reason":"withdrawn"}),
        )
        .await
        .unwrap();
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    for args in [
        json!({"action":"accept","suggestion_ids":[id],"reason":"preview withdrawn","dry_run":true}),
        json!({"action":"accept","suggestion_ids":[id],"reason":"accept withdrawn"}),
        json!({"action":"reject","suggestion_ids":[id],"reason":"reject withdrawn"}),
    ] {
        let expected_status = if args["dry_run"] == true {
            "would_conflict"
        } else {
            "conflict"
        };
        let outcome = compare_suggestion(&w, &v1, args).await;
        assert_eq!(outcome["status"], expected_status);
        assert_eq!(outcome["causes"][0]["code"], "suggestion_archived");
        assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    }
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    let record = kernel::read_record_as(&w.db, &w.admin, &id)
        .await
        .unwrap()
        .unwrap();
    kernel::set_archived_as(&w.db, &w.admin, &id, false, record.revision)
        .await
        .unwrap();
    registry()
        .call(
            v1.clone(),
            Caller::local(),
            "archive_record",
            json!({"id":id,"archived":false,"reason":"restore"}),
        )
        .await
        .unwrap();
    let outcome = compare_suggestion(
        &w,
        &v1,
        json!({"action":"accept","suggestion_ids":[id],"reason":"preview restored","dry_run":true}),
    )
    .await;
    assert_eq!(outcome["status"], "would_accept");
    v1.close().await;
    w.db.close().await;
}
fn image_fixture_bytes() -> Vec<u8> {
    let mut bytes = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(image::ImageBuffer::from_pixel(
        1,
        1,
        image::Rgba([30, 80, 120, 255]),
    ))
    .write_to(&mut bytes, image::ImageFormat::Png)
    .unwrap();
    bytes.into_inner()
}
fn image_fixture_metadata(id: &str, body: &str) -> crate::record_images::ImageInsertMetadata {
    serde_json::from_value(json!({"version":"native.record-image-insert.v1","idempotency_key":id,
        "if_body_digest":crate::mcp::tools::lifecycle::body_digest(Some(body)),"splice":{"start":7,"end":7},
        "placement":{"alt":"diagram [one]","caption":"A \"caption\"","size":"medium","alignment":"center"},"filename":"diagram.png"})).unwrap()
}
async fn image_fixture_target(w: &World, body: &str) {
    install_comment_carrier(w).await;
    let record = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap();
    kernel::set_body_as(&w.db, &w.admin, &w.first, body, record.revision)
        .await
        .unwrap();
    kernel::replace_home_policy(&w.db, &w.admin, &record.home_id, &[(&w.viewer, "edit")])
        .await
        .unwrap();
}
#[tokio::test]
async fn kernel_v2_record_image_matches_v1_atomic_splice_and_replay() {
    let mut w = world().await;
    let body = "before\nafter\n";
    image_fixture_target(&w, body).await;
    let v1 = crate::create_database(":memory:").await.unwrap();
    registry().call(v1.clone(),Caller::local(),"create_record",json!({"id":w.first,"type":"Document","kind":"note","name":"Target","body":body,"reason":"image fixture"})).await.unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let meta = image_fixture_metadata(&id, body);
    let bytes = image_fixture_bytes();
    let caller = Caller::authenticated("acct:viewer");
    let actual = super::record_images::insert(
        &w.db,
        &caller,
        &w.first,
        meta.clone(),
        body.into(),
        bytes.clone(),
        "image/png",
    )
    .await
    .unwrap();
    let expected = crate::record_images::insert_record_image(
        &v1,
        &Caller::local(),
        &w.first,
        meta.clone(),
        body.into(),
        bytes.clone(),
        "image/png",
    )
    .await
    .unwrap();
    assert_eq!(
        serde_json::to_value(&actual).unwrap(),
        serde_json::to_value(&expected).unwrap()
    );
    let stored = kernel::read_record_as(&w.db, &w.viewer, &w.first)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.body.as_deref(),
        Some(format!("before\n{}after\n", actual.placement_source).as_str())
    );
    let image = super::record_images::read(&w.db, &caller, &w.first, &id)
        .await
        .unwrap();
    assert_eq!(image.bytes, bytes);
    assert_eq!(image.mime, "image/png");
    assert_eq!(image.filename.as_deref(), Some("diagram.png"));
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    let retry = super::record_images::insert(
        &w.db,
        &caller,
        &w.first,
        meta.clone(),
        body.into(),
        bytes.clone(),
        "image/png",
    )
    .await
    .unwrap();
    assert!(retry.replayed);
    assert_eq!(retry.body_digest, actual.body_digest);
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    w.db.close().await;
    w.db = kernel::open_v2_database(w._dir.path().join("v2.db").to_str().unwrap())
        .await
        .unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    assert_eq!(
        super::record_images::read(&w.db, &caller, &w.first, &id)
            .await
            .unwrap()
            .bytes,
        bytes
    );
    assert!(
        super::record_images::insert(
            &w.db,
            &caller,
            &w.first,
            meta.clone(),
            body.into(),
            bytes.clone(),
            "image/png"
        )
        .await
        .unwrap()
        .replayed
    );
    let later = kernel::read_record_as(&w.db, &w.viewer, &w.first)
        .await
        .unwrap()
        .unwrap();
    kernel::set_body_as(&w.db, &w.viewer, &w.first, "later edit", later.revision)
        .await
        .unwrap();
    assert!(
        super::record_images::insert(
            &w.db,
            &caller,
            &w.first,
            meta.clone(),
            body.into(),
            bytes.clone(),
            "image/png"
        )
        .await
        .unwrap()
        .replayed
    );
    let mut changed = meta.clone();
    changed.filename = Some("different.png".into());
    assert!(matches!(
        super::record_images::insert(
            &w.db,
            &caller,
            &w.first,
            changed,
            body.into(),
            bytes.clone(),
            "image/png"
        )
        .await,
        Err(crate::record_images::RecordImageError::Conflict)
    ));
    kernel::replace_home_policy(&w.db, &w.admin, &stored.home_id, &[(&w.viewer, "view")])
        .await
        .unwrap();
    assert!(matches!(
        super::record_images::insert(
            &w.db,
            &caller,
            &w.first,
            meta.clone(),
            body.into(),
            bytes.clone(),
            "image/png"
        )
        .await,
        Err(crate::record_images::RecordImageError::NotFound)
    ));
    assert!(super::record_images::read(&w.db, &caller, &w.first, &id)
        .await
        .is_ok());
    kernel::replace_home_policy(&w.db, &w.admin, &stored.home_id, &[])
        .await
        .unwrap();
    assert!(matches!(
        super::record_images::read(&w.db, &caller, &w.first, &id).await,
        Err(crate::record_images::RecordImageError::NotFound)
    ));
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    for bearer in [&w.hidden, "missing-record"] {
        assert!(matches!(
            super::record_images::insert(
                &w.db,
                &caller,
                bearer,
                meta.clone(),
                body.into(),
                bytes.clone(),
                "image/png"
            )
            .await,
            Err(crate::record_images::RecordImageError::NotFound)
        ));
    }
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    v1.close().await;
    w.db.close().await;
}
#[tokio::test]
async fn kernel_v2_record_image_rolls_back_blobs_links_receipt_and_body_on_failure() {
    let w = world().await;
    let body = "before\nafter\n";
    image_fixture_target(&w, body).await;
    let caller = Caller::authenticated("acct:viewer");
    let id = uuid::Uuid::new_v4().to_string();
    let mut meta = image_fixture_metadata(&id, body);
    let bytes = image_fixture_bytes();
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    meta.if_body_digest = "0".repeat(64);
    assert!(matches!(
        super::record_images::insert(
            &w.db,
            &caller,
            &w.first,
            meta.clone(),
            body.into(),
            bytes.clone(),
            "image/png"
        )
        .await,
        Err(crate::record_images::RecordImageError::Conflict)
    ));
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    meta = image_fixture_metadata(&id, body);
    meta.splice.start = usize::MAX;
    assert!(matches!(
        super::record_images::insert(
            &w.db,
            &caller,
            &w.first,
            meta.clone(),
            body.into(),
            bytes.clone(),
            "image/png"
        )
        .await,
        Err(crate::record_images::RecordImageError::BadRequest(_))
    ));
    meta = image_fixture_metadata(&id, body);
    assert!(matches!(
        super::record_images::insert(
            &w.db,
            &caller,
            &w.first,
            meta.clone(),
            body.into(),
            vec![1, 2, 3],
            "image/png"
        )
        .await,
        Err(crate::record_images::RecordImageError::UnsupportedMedia(_))
    ));
    sqlx::query("CREATE TRIGGER fixture_image_failure BEFORE UPDATE ON kernel_record_bodies WHEN NEW.body LIKE '%attachment:%' BEGIN SELECT RAISE(ABORT,'fixture body failure'); END")
        .execute(w.db.write_pool()).await.unwrap();
    let schema: Vec<(String, Option<String>)> =
        sqlx::query_as("SELECT name,sql FROM sqlite_schema ORDER BY name")
            .fetch_all(w.db.pool())
            .await
            .unwrap();
    assert!(super::record_images::insert(
        &w.db,
        &caller,
        &w.first,
        meta.clone(),
        body.into(),
        bytes.clone(),
        "image/png"
    )
    .await
    .is_err());
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    let after: Vec<(String, Option<String>)> =
        sqlx::query_as("SELECT name,sql FROM sqlite_schema ORDER BY name")
            .fetch_all(w.db.pool())
            .await
            .unwrap();
    assert_eq!(schema, after);
    sqlx::query("DROP TRIGGER fixture_image_failure")
        .execute(w.db.write_pool())
        .await
        .unwrap();
    assert!(
        !super::record_images::insert(
            &w.db,
            &caller,
            &w.first,
            meta,
            body.into(),
            bytes,
            "image/png"
        )
        .await
        .unwrap()
        .replayed
    );
    w.db.close().await;
}

#[path = "private_create_tests.rs"]
mod private_create_tests;
async fn reference_fixture() -> (World, Db, Vec<String>) {
    let w = world().await;
    let v1 = crate::create_database(":memory:").await.unwrap();
    let visible_home = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let hidden_home = kernel::read_record_as(&w.db, &w.admin, &w.hidden)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let pin = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .pin
        .unwrap();
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let ids: Vec<String> = [
        "ba5e0100-0000-4000-8000-000000000001",
        "ba5e01ff-0000-4000-8000-000000000002",
        "ba5e0100-0000-4000-8000-000000000003",
        "de1e7e00-0000-4000-8000-000000000004",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    for (index, id) in ids.iter().enumerate() {
        kernel::import_record_as(
            &w.db,
            &host,
            id,
            if index == 2 {
                &hidden_home
            } else {
                &visible_home
            },
            Some(&w.admin),
            &kernel::ImportRecordState {
                definition: Some(kernel::ImportDefinition {
                    pin: pin.clone(),
                    primary_type: "Document".into(),
                    kind: "note".into(),
                    fields: json!({"title":id}).as_object().unwrap().clone(),
                }),
                body: Some("Synthetic reference body".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        crate::store::create_record(
            &v1,
            json!({"id":id,"type":"Document","kind":"note","name":id}),
        )
        .await
        .unwrap();
    }
    crate::authorization::replace_explicit_policy(
        &v1,
        "fixture",
        &ids[2],
        vec![crate::authorization::AllowEntry::account(
            "other",
            crate::authorization::Capability::Manage,
        )],
    )
    .await
    .unwrap();
    kernel::import_removal_as(
        &w.db,
        &host,
        &ids[3],
        kernel::ImportedRemovalKind::Record,
        &kernel::ImportRemovalEvidence {
            source_origin: "synthetic-reference".into(),
            snapshot: "reference-fixture".into(),
            reason: "Source tombstone".into(),
            deleted_at: Some(crate::store::now_iso()),
            source_event: None,
        },
    )
    .await
    .unwrap();
    crate::store::delete_record(&v1, &ids[3]).await.unwrap();
    (w, v1, ids)
}

#[tokio::test]
async fn kernel_v2_reference_matches_v1_grammar_visibility_and_tombstones() {
    use crate::mcp::hosted_transport::{resolve_hosted_reference, HostedReferenceResolution};
    let (w, v1, ids) = reference_fixture().await;
    let caller = Caller::authenticated("acct:viewer");
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    for reference in [
        ids[0].as_str(),
        ids[2].as_str(),
        ids[3].as_str(),
        "ba5e01",
        "BA5E0100",
        "ba5e0100-0000-4",
        "ba-5e-0100",
        "de1e7e",
        "ba5e0",
        "not-a-reference",
        "native:root",
        "BA5E0100-0000-4000-8000-000000000001",
        "ffffffff-ffff-4fff-8fff-ffffffffffff",
    ] {
        let expected =
            resolve_hosted_reference(&v1, &Caller::authenticated("reference-viewer"), reference)
                .await
                .unwrap();
        let actual = reference_read::resolve_as(&w.db, &caller, reference)
            .await
            .unwrap();
        assert_eq!(actual, expected, "{reference}");
    }
    assert_eq!(
        reference_read::resolve_as(&w.db, &caller, "ba5e01")
            .await
            .unwrap(),
        HostedReferenceResolution::Ambiguous
    );
    assert_eq!(
        reference_read::resolve_as(&w.db, &caller, "ba5e0100")
            .await
            .unwrap(),
        HostedReferenceResolution::Resolved(ids[0].clone())
    );
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    assert!(
        reference_read::resolve_as(&w.db, &Caller::authenticated("missing"), &ids[0])
            .await
            .unwrap_err()
            .to_string()
            .contains("no principal auth_binding")
    );
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        &kernel::read_record_as(&w.db, &w.admin, &ids[0])
            .await
            .unwrap()
            .unwrap()
            .home_id,
        &[(&w.admin, "manage")],
    )
    .await
    .unwrap();
    assert_eq!(
        reference_read::resolve_as(&w.db, &caller, "ba5e0100")
            .await
            .unwrap(),
        HostedReferenceResolution::Unresolved
    );
    v1.close().await;
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_reference_excludes_v1_attribution_aliases() {
    use crate::mcp::hosted_transport::{resolve_hosted_reference, HostedReferenceResolution};
    let (w, v1, _ids) = reference_fixture().await;
    let at = crate::store::now_iso();
    sqlx::query("INSERT INTO vocabulary_values(id,vocabulary_id,value,status,metadata,alias_of) VALUES('fixture:reference-credit','voc:kind:Annotation','reference-credit','active','{}','vv:voc:kind:Annotation:attribution')").execute(v1.write_pool()).await.unwrap();
    for (section,sql) in [
        ("vocabularies","SELECT json_object('id',id,'name',name,'created_at',created_at) FROM vocabularies WHERE id='voc:kind:Annotation'"),
        ("vocabulary_values","SELECT json_object('id',id,'vocabulary_id',vocabulary_id,'value',value,'gloss',gloss,'status',status,'ordinal',ordinal,'terminality',terminality,'metadata',metadata,'alias_of',alias_of) FROM vocabulary_values WHERE vocabulary_id='voc:kind:Annotation'"),
    ] {
        let rows:Vec<String>=sqlx::query_scalar(sql).fetch_all(v1.pool()).await.unwrap();
        for raw in rows {
            let row:Value=serde_json::from_str(&raw).unwrap();
            import_catalogue(&w,section,row["id"].as_str().unwrap(),row.clone(),None,&at).await;
        }
    }
    let definition = json!({"family":"fixture.reference.annotation","version":1,"interpreter":"native.defn/2","primary_type":"Annotation","kinds":[{"token":"reference-credit","description":"Reference alias fixture","maturity":"current","identity":{"field":"title"},"fields":[{"name":"title","type":"text","required":true}],"links":[]}]});
    let pin = kernel::install_definition_as(
        &w.db,
        &w.admin,
        "fixture.reference.annotation",
        1,
        &serde_json::to_vec(&definition).unwrap(),
    )
    .await
    .unwrap();
    kernel::adopt_definition_as(&w.db, &w.admin, &pin.family, Some(&pin))
        .await
        .unwrap();
    let home = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let id = "a77b0100-0000-4000-8000-000000000001";
    kernel::import_record_as(
        &w.db,
        &host,
        id,
        &home,
        Some(&w.admin),
        &kernel::ImportRecordState {
            definition: Some(kernel::ImportDefinition {
                pin,
                primary_type: "Annotation".into(),
                kind: "reference-credit".into(),
                fields: json!({"title":"Attribution alias"})
                    .as_object()
                    .unwrap()
                    .clone(),
            }),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    sqlx::query("INSERT INTO records(id,type,kind,name,policy_anchor_id,created_at,updated_at) VALUES(?,'Annotation','reference-credit','Attribution alias','native:root',?,?)").bind(id).bind(&at).bind(&at).execute(v1.write_pool()).await.unwrap();
    assert!(kernel::read_record_as(&w.db, &w.viewer, id)
        .await
        .unwrap()
        .is_some());
    for status in ["active", "deprecated"] {
        sqlx::query("UPDATE vocabulary_values SET status=? WHERE id='fixture:reference-credit'")
            .bind(status)
            .execute(v1.write_pool())
            .await
            .unwrap();
        let raw:String=sqlx::query_scalar("SELECT json_object('id',id,'vocabulary_id',vocabulary_id,'value',value,'gloss',gloss,'status',status,'ordinal',ordinal,'terminality',terminality,'metadata',metadata,'alias_of',alias_of) FROM vocabulary_values WHERE id='fixture:reference-credit'").fetch_one(v1.pool()).await.unwrap();
        import_catalogue(
            &w,
            "vocabulary_values",
            "fixture:reference-credit",
            serde_json::from_str(&raw).unwrap(),
            None,
            &at,
        )
        .await;
        for reference in [id, "a77b01"] {
            assert_eq!(
                resolve_hosted_reference(&v1, &Caller::local(), reference)
                    .await
                    .unwrap(),
                HostedReferenceResolution::Unresolved
            );
            assert_eq!(
                reference_read::resolve_as(&w.db, &Caller::authenticated("acct:viewer"), reference)
                    .await
                    .unwrap(),
                HostedReferenceResolution::Unresolved
            );
        }
    }
    v1.close().await;
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_delete_matches_v1_tombstone_children_derived_and_replay() {
    let w = world().await;
    let v1 = suggestion_v1_fixture(&w).await;
    registry().call(v1.clone(), Caller::local(), "create_record", json!({"id":w.second,"type":"Document","kind":"note","name":"Child","body":"kept","reason":"Retention fixture","links":[{"target_id":w.first,"relationship":"part_of"}]})).await.unwrap();
    call_as(
        &w,
        "acct:admin",
        "manage_links",
        json!({"action":"add","source_id":w.second,"target_id":w.first,"relationship":"part_of"}),
    )
    .await
    .unwrap();
    let comment = call(&w,"create_record",json!({"type":"Annotation","kind":"comment","body":"Retained thread","links":[{"target_id":w.first,"relationship":"part_of"}]})).await.unwrap()["id"].as_str().unwrap().to_owned();
    registry().call(v1.clone(),Caller::local(),"create_record",json!({"id":comment,"type":"Annotation","kind":"comment","body":"Retained thread","reason":"Retention fixture","links":[{"target_id":w.first,"relationship":"part_of"}]})).await.unwrap();
    let attachment = call_as(
        &w,
        "acct:admin",
        "attach_text",
        json!({"record_id":w.first,"text":"retained bytes","filename":"fixture.txt"}),
    )
    .await
    .unwrap()["attachment_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let binary_before: (String, i64) =
        sqlx::query_as("SELECT a.sha256,b.size_bytes FROM kernel_attachment_blobs a JOIN kernel_blobs b ON b.sha256=a.sha256 WHERE a.record_id=?")
            .bind(&attachment)
            .fetch_one(w.db.pool())
            .await
            .unwrap();
    let args = json!({"id":w.first,"reason":"Remove the parent"});
    let old = registry()
        .call(v1.clone(), Caller::local(), "delete_record", args.clone())
        .await
        .unwrap();
    let result = call_as(&w, "acct:admin", "delete_record", args.clone())
        .await
        .unwrap();
    assert_eq!(result["deleted"], old["deleted"]);
    assert_eq!(result["id"], old["id"]);
    assert!(result["deleted_at"].is_string());
    assert!(result["previous_seq"].is_number());
    for id in [&w.first, &comment, &attachment] {
        assert!(kernel::read_record_as(&w.db, &w.admin, id)
            .await
            .unwrap()
            .is_none());
    }
    assert!(
        kernel::read_record_as(&w.db, &w.viewer, &w.second)
            .await
            .unwrap()
            .is_some(),
        "ordinary part_of children survive"
    );
    assert!(crate::mcp::tools::can_record(
        &v1,
        &Caller::local(),
        &w.second,
        crate::authorization::Capability::View
    )
    .await
    .unwrap());
    assert!(!crate::mcp::tools::can_record(
        &v1,
        &Caller::local(),
        &comment,
        crate::authorization::Capability::View
    )
    .await
    .unwrap());
    let retained: i64 =
        sqlx::query_scalar("SELECT count(*) FROM kernel_records WHERE id IN (?,?,?)")
            .bind(&w.first)
            .bind(&comment)
            .bind(&attachment)
            .fetch_one(w.db.pool())
            .await
            .unwrap();
    assert_eq!(retained, 3);
    let binary_after: (String, i64) =
        sqlx::query_as("SELECT a.sha256,b.size_bytes FROM kernel_attachment_blobs a JOIN kernel_blobs b ON b.sha256=a.sha256 WHERE a.record_id=?")
            .bind(&attachment)
            .fetch_one(w.db.pool())
            .await
            .unwrap();
    assert_eq!(binary_before, binary_after);
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    assert!(call_as(&w, "acct:admin", "delete_record", args.clone())
        .await
        .is_err());
    assert!(registry()
        .call(v1.clone(), Caller::local(), "delete_record", args)
        .await
        .is_err());
    for (tool, args) in [
        ("update_record", json!({"id":w.first,"body":"resurrect"})),
        ("archive_record", json!({"id":w.first,"reason":"resurrect"})),
        ("get_history", json!({"record_id":w.first})),
    ] {
        assert!(call_as(&w, "acct:admin", tool, args).await.is_err());
    }
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    v1.close().await;
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_delete_view_edit_hidden_cas_and_argument_refusals_are_atomic() {
    let w = world().await;
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    for args in [
        json!({"id":w.first,"reason":"viewer"}),
        json!({"id":w.hidden,"reason":"hidden"}),
        json!({"id":"missing","reason":"missing"}),
    ] {
        assert!(call(&w, "delete_record", args).await.is_err());
    }
    let home = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        &home,
        &[(&w.viewer, "edit"), (&w.admin, "manage")],
    )
    .await
    .unwrap();
    assert!(call(
        &w,
        "delete_record",
        json!({"id":w.first,"reason":"Edit is insufficient"})
    )
    .await
    .is_err());
    let root_error = call_as(
        &w,
        "acct:admin",
        "delete_record",
        json!({"id":KERNEL_ROOT_ID,"reason":"A home is not a record"}),
    )
    .await
    .unwrap_err();
    assert!(matches!(root_error, Error::Engine(_)));
    let guarded = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    for args in [
        json!({"id":w.first,"reason":""}),
        json!({"id":w.first,"reason":"stale","if_content_seq":1}),
        json!({"id":w.first,"reason":"unsupported","idempotency_key":"no-v1-contract"}),
        json!({"id":w.first,"reason":"unsupported","if_body_digest":"no-v1-contract"}),
    ] {
        assert!(call_as(&w, "acct:admin", "delete_record", args)
            .await
            .is_err());
    }
    assert_eq!(
        guarded,
        kernel::dump_all_kernel_tables(&w.db).await.unwrap()
    );
    assert_eq!(before.records, guarded.records);
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_delete_matches_v1_active_instruction_guards_without_hidden_ids() {
    let w = world().await;
    let v1 = suggestion_v1_fixture(&w).await;
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let at = crate::store::now_iso();
    let mut binding = kernel::ImportInstructionBinding {
        id: "private-binding-id".into(),
        scope_kind: "database".into(),
        scope_id: "native:database".into(),
        account_principal: None,
        source_record_id: w.first.clone(),
        position: 9999,
        enabled: true,
        created_at: at.clone(),
        actor: Some("local".into()),
    };
    kernel::import_instruction_binding_as(&w.db, &host, &binding)
        .await
        .unwrap();
    sqlx::query("INSERT INTO instruction_bindings(id,scope_kind,scope_id,source_record_id,position,enabled,created_by,created_at,updated_at) VALUES(?,'database','native:database',?,9999,1,'local',?,?)").bind(&binding.id).bind(&w.first).bind(&at).bind(&at).execute(v1.write_pool()).await.unwrap();
    let args = json!({"id":w.first,"reason":"Try an active source"});
    for _ in 0..2 {
        let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
        let error = call_as(&w, "acct:admin", "delete_record", args.clone())
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("active instruction source"), "{error}");
        assert!(!error.contains("private-binding-id"));
        assert!(!error.contains("private-programme-id"));
        assert!(registry()
            .call(v1.clone(), Caller::local(), "delete_record", args.clone())
            .await
            .unwrap_err()
            .to_string()
            .contains("active instruction source"));
        assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
        if binding.enabled {
            binding.enabled = false;
            kernel::import_instruction_binding_as(&w.db, &host, &binding)
                .await
                .unwrap();
            sqlx::query("UPDATE instruction_bindings SET enabled=0 WHERE id=?")
                .bind(&binding.id)
                .execute(v1.write_pool())
                .await
                .unwrap();
            sqlx::query("INSERT INTO onboarding_programmes(id,trigger_key,position,enabled,created_by,created_at,updated_at) VALUES('private-programme-id','fixture',9999,1,'local',?,?)").bind(&at).bind(&at).execute(v1.write_pool()).await.unwrap();
            sqlx::query("INSERT INTO onboarding_programme_sources VALUES('private-programme-id',?,'guidance',0)").bind(&w.first).execute(v1.write_pool()).await.unwrap();
            for (section, id, value) in [
                (
                    "onboarding_programmes",
                    "programme",
                    json!({"id":"private-programme-id","enabled":1}),
                ),
                (
                    "onboarding_programme_sources",
                    "source",
                    json!({"programme_id":"private-programme-id","source_record_id":w.first,"source_role":"guidance"}),
                ),
            ] {
                kernel::v1_state::import_state_batch_as(
                    &w.db,
                    &host,
                    &[kernel::v1_state::ImportedState {
                        section: section.into(),
                        source_id: id.into(),
                        origin: "deletion-fixture".into(),
                        value_json: Some(value.to_string()),
                        account_principal: None,
                        record_id: None,
                        observed_at: at.clone(),
                        snapshot: json!({}),
                    }],
                )
                .await
                .unwrap();
            }
        }
    }
    kernel::v1_state::import_state_batch_as(
        &w.db,
        &host,
        &[kernel::v1_state::ImportedState {
            section: "onboarding_programmes".into(),
            source_id: "programme".into(),
            origin: "deletion-fixture".into(),
            value_json: Some(json!({"id":"private-programme-id","enabled":0}).to_string()),
            account_principal: None,
            record_id: None,
            observed_at: at.clone(),
            snapshot: json!({}),
        }],
    )
    .await
    .unwrap();
    sqlx::query("UPDATE onboarding_programmes SET enabled=0 WHERE id='private-programme-id'")
        .execute(v1.write_pool())
        .await
        .unwrap();
    assert_eq!(
        call_as(&w, "acct:admin", "delete_record", args.clone())
            .await
            .unwrap()["deleted"],
        true
    );
    assert_eq!(
        registry()
            .call(v1.clone(), Caller::local(), "delete_record", args)
            .await
            .unwrap()["deleted"],
        true
    );
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    v1.close().await;
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_delete_replays_after_deleting_member_leaves_roster() {
    let w = world().await;
    async fn roster(db: &Db, actor: &str, members: &[&str]) {
        kernel::hosted_identity::reconcile_hosted_caller(db, |_| async {
            // SAFETY: complete synthetic host-owned roster, without request input.
            Ok(unsafe {
                kernel::hosted_identity::VerifiedHostedMembership::from_accounts_unchecked(
                    actor.into(),
                    members.iter().map(|member| (*member).into()).collect(),
                )
            })
        })
        .await
        .unwrap();
    }
    roster(&w.db, "acct:admin", &["acct:admin", "acct:viewer"]).await;
    call_as(
        &w,
        "acct:admin",
        "delete_record",
        json!({"id":w.first,"reason":"Delete before departing"}),
    )
    .await
    .unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    roster(&w.db, "acct:viewer", &["acct:viewer"]).await;
    assert!(
        !kernel::kernel_effective_capability(&w.db, &w.admin, &w.second)
            .await
            .unwrap()
            .allows(crate::authorization::Capability::View)
    );
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_bindings_native_fields_cannot_impersonate_v1_person_shape() {
    let (w, v1, _) = binding_fixture().await;
    let definition = json!({"family":"fixture.binding-shape","version":1,"interpreter":"native.defn/2","primary_type":"Document","kinds":[{"token":"note","description":"Native fields are not v1 spine","maturity":"current","identity":{"field":"title"},"fields":[{"name":"title","type":"text","required":true},{"name":"v1_type","type":"text","required":false},{"name":"v1_kind","type":"text","required":false}],"links":[]}]});
    let pin = kernel::install_definition_as(
        &w.db,
        &w.admin,
        "fixture.binding-shape",
        1,
        &serde_json::to_vec(&definition).unwrap(),
    )
    .await
    .unwrap();
    kernel::adopt_definition_as(&w.db, &w.admin, &pin.family, Some(&pin))
        .await
        .unwrap();
    let home = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let id = kernel::create_as(
        &w.db,
        &w.admin,
        &pin.family,
        "note",
        json!({"title":"Document with misleading fields","v1_type":"Entity","v1_kind":"person"})
            .as_object()
            .unwrap(),
        &home,
    )
    .await
    .unwrap();
    registry().call(v1.clone(),Caller::local(),"create_record",json!({"id":id,"type":"Document","kind":"note","name":"Actual document","reason":"Shape parity"})).await.unwrap();
    let args = json!({"action":"add","record_id":id,"binding":{"system":"native-principal","identifier":"native/A"},"reason":"No type impersonation"});
    let expected = registry()
        .call(v1.clone(), Caller::local(), "manage_bindings", args.clone())
        .await
        .unwrap_err()
        .to_string();
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    let actual = call_as(&w, "acct:admin", "manage_bindings", args)
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(actual, expected);
    assert!(actual.contains("incompatible record kind"));
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    v1.close().await;
    w.db.close().await;
}

#[path = "interventions_tests.rs"]
mod interventions_tests;
#[path = "member_configuration_tests.rs"]
mod member_configuration_tests;
#[path = "surface_bindings_tests.rs"]
mod surface_bindings_tests;

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_browser_home_staging_uses_subject_index_and_preserves_visibility() {
    use sqlx::Row;
    let w = world().await;
    let mut connection = w.db.governed_pool().acquire().await.unwrap();
    connection.close_on_drop();
    sqlx::query("BEGIN")
        .execute(&mut *connection)
        .await
        .unwrap();
    let reads = [("records".into(), "home_id".into())].into_iter().collect();
    super::sql::install(&mut connection, &w.viewer, &reads)
        .await
        .unwrap();
    let plan = sqlx::query(&format!("EXPLAIN QUERY PLAN {}", super::sql::HOME_MAP_SQL))
        .fetch_all(&mut *connection)
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.get::<String, _>(3))
        .collect::<Vec<_>>();
    assert!(
        plan.iter().any(|detail| detail.contains("SEARCH e")
            && detail.contains("record_id=?")
            && detail.contains("type=?")),
        "home lookup must seek both subject and type: {plan:?}"
    );
    assert!(
        !plan.iter().any(|detail| detail.starts_with("SCAN e")),
        "unrelated history must never be scanned: {plan:?}"
    );
    let provenance_plan = sqlx::query(&format!(
        "EXPLAIN QUERY PLAN {}",
        crate::v1_import::SNAPSHOT_PROVENANCE_SQL
    ))
    .bind(&w.first)
    .fetch_all(&mut *connection)
    .await
    .unwrap()
    .into_iter()
    .map(|row| row.get::<String, _>(3))
    .collect::<Vec<_>>();
    assert!(
        provenance_plan
            .iter()
            .any(|detail| detail.contains("SEARCH h")
                && detail.contains("record_id=?")
                && detail.contains("source_stream=?")),
        "snapshot lookup must seek the prepared header: {provenance_plan:?}"
    );
    // Main materializes trusted placement before caller SQL. Check the
    // preparation query, since the public view now only seeks that table.
    let placement_plan = sqlx::query(&format!(
        "EXPLAIN QUERY PLAN {}",
        super::sql::logical_home_rows_sql()
    ))
    .fetch_all(&mut *connection)
    .await
    .unwrap()
    .into_iter()
    .map(|row| row.get::<String, _>(3))
    .collect::<Vec<_>>();
    assert!(
        placement_plan
            .iter()
            .any(|detail| detail.contains("idx_kernel_hosted_event_lookup")
                && detail.contains("record_id=?")
                && detail.contains("type=?")),
        "rehome lookup must seek by subject and exact type: {placement_plan:?}"
    );
    sqlx::query("ROLLBACK")
        .execute(&mut *connection)
        .await
        .unwrap();
    drop(connection);
    kernel::create_principal(&w.db, "account", "No grants", "acct:outsider", &w.admin)
        .await
        .unwrap();
    for (credential, visible_status, hidden_status) in [
        ("acct:viewer", "found", "not_found"),
        ("acct:admin", "found", "found"),
        ("acct:outsider", "not_found", "not_found"),
    ] {
        let answer = call_as(
            &w,
            credential,
            "get_record",
            json!({"ids":[w.first,w.hidden],"children_limit":0,"links_limit":0}),
        )
        .await
        .unwrap();
        assert_eq!(answer["records"][0]["status"], visible_status);
        assert_eq!(answer["records"][1]["status"], hidden_status);
    }
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_browser_get_stages_only_part_of_and_keeps_provider_links() {
    let w = world().await;
    install_comment_carrier(&w).await;
    let home: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
        .bind(&w.first)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let fields = crate::v2_standard::v1_compat::compat_fields(
        "WorkItem",
        "task",
        Some("Provider source"),
        None,
        None,
    );
    let source = kernel::create_json_as(
        &w.db,
        &w.admin,
        crate::v2_standard::v1_compat::FAMILY,
        crate::v2_standard::v1_compat::KIND,
        &serde_json::to_string(&fields).unwrap(),
        &home,
    )
    .await
    .unwrap();
    let package = crate::v2_standard::relates_to::package();
    let installed = kernel::install_package_as(&w.db, &w.admin, &package)
        .await
        .unwrap();
    kernel::adopt_package_at(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &package,
        Some(&installed),
        &package.declared_reads,
    )
    .await
    .unwrap();
    for (key, target) in [("visible", &w.second), ("hidden", &w.hidden)] {
        let request = kernel::prepare_provider_as(
            &w.db,
            &w.admin,
            &source,
            target,
            key,
            crate::v2_standard::relates_to::Command::Assert { sources: vec![] },
        )
        .await
        .unwrap();
        kernel::commit_provider_as(&w.db, &w.admin, &request)
            .await
            .unwrap();
    }
    let (result, stats) =
        super::sql::measured(call(&w, "get_record", json!({"ids":[source]}))).await;
    let result = result.unwrap();
    assert_eq!(stats.provider_states_decoded, 0, "{stats:?}");
    let links = result["records"][0]["links_out"].as_array().unwrap();
    assert!(links.iter().any(|link| link["target_id"] == w.second));
    assert!(links.iter().all(|link| link["target_id"] != w.hidden));
    let (sql, stats) = super::sql::measured(call(&w,"query_sql",json!({"sql":"SELECT DISTINCT target_id FROM links WHERE source_id=?1 AND relationship='relates_to' ORDER BY target_id","parameters":[{"type":"text","value":source}]}))).await;
    assert_eq!(sql.unwrap()["rows"], json!([{"target_id":w.second}]));
    assert_eq!(stats.provider_states_decoded, 0, "{stats:?}");
    sqlx::query("DELETE FROM kernel_provider_link_heads")
        .execute(w.db.write_pool())
        .await
        .unwrap();
    assert!(call(&w, "get_record", json!({"ids":[source]}))
        .await
        .unwrap_err()
        .to_string()
        .contains("provider-link read projection is not ready"));
    assert!(call(
        &w,
        "query_sql",
        json!({"sql":"SELECT source_id,target_id FROM links LIMIT 100"})
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("provider-link read projection is not ready"));
    kernel::prepare_v2_database(&w.db).await.unwrap();
    assert!(call(&w, "get_record", json!({"ids":[source]}))
        .await
        .is_ok());
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_browser_request_cache_binds_actor_database_heads_and_lifetime() {
    let w = world().await;
    kernel::read_cache::scope_request(async {
        let viewer = call_as(
            &w,
            "acct:viewer",
            "get_record",
            json!({"ids":[w.first,w.hidden]}),
        )
        .await
        .unwrap();
        assert_eq!(viewer["records"][1]["status"], "not_found");
        let owner = call_as(&w, "acct:admin", "get_record", json!({"ids":[w.hidden]}))
            .await
            .unwrap();
        assert_eq!(owner["records"][0]["status"], "found");
        let mut old_snapshot = w.db.write_pool().begin().await.unwrap();
        let old_key = kernel::read_cache::key_on(&mut old_snapshot, &w.viewer, "home_visibility")
            .await
            .unwrap();
        assert!(kernel::read_cache::get::<kernel::VisibleHomeAnchors>(&old_key).is_some());
        let home: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
            .bind(&w.first)
            .fetch_one(&mut *old_snapshot)
            .await
            .unwrap();
        kernel::replace_home_policy(&w.db, &w.admin, &home, &[])
            .await
            .unwrap();
        // An old transaction keeps its own snapshot; a new transaction must
        // never reuse its authority, even inside this one request scope.
        assert!(
            kernel::read_cache::key_on(&mut old_snapshot, &w.viewer, "home_visibility")
                .await
                .unwrap()
                == old_key
        );
        old_snapshot.rollback().await.unwrap();
        let refused = call_as(&w, "acct:viewer", "get_record", json!({"ids":[w.first]}))
            .await
            .unwrap();
        assert_eq!(refused["records"][0]["status"], "not_found");
        let mut current = w.db.write_pool().begin().await.unwrap();
        let new_key = kernel::read_cache::key_on(&mut current, &w.viewer, "home_visibility")
            .await
            .unwrap();
        assert!(new_key != old_key);
        assert!(kernel::read_cache::get::<kernel::VisibleHomeAnchors>(&new_key).is_some());
        current.rollback().await.unwrap();
        let copy_dir = tempfile::tempdir().unwrap();
        let copy_path = copy_dir.path().join("copy.db");
        sqlx::query("VACUUM INTO ?")
            .bind(copy_path.to_str().unwrap())
            .execute(w.db.write_pool())
            .await
            .unwrap();
        let copy = kernel::open_marked_v2_database(copy_path.to_str().unwrap())
            .await
            .unwrap();
        let mut snapshot = copy.write_pool().begin().await.unwrap();
        let copy_key = kernel::read_cache::key_on(&mut snapshot, &w.viewer, "home_visibility")
            .await
            .unwrap();
        assert!(
            copy_key != new_key,
            "identical heads in another physical database must not alias"
        );
        assert!(kernel::read_cache::get::<kernel::VisibleHomeAnchors>(&copy_key).is_none());
        snapshot.rollback().await.unwrap();
        copy.close().await;
    })
    .await;
    let mut snapshot = w.db.write_pool().begin().await.unwrap();
    assert!(
        kernel::read_cache::key_on(&mut snapshot, &w.viewer, "home_visibility")
            .await
            .unwrap()
            .is_none()
    );
    snapshot.rollback().await.unwrap();
    kernel::read_cache::scope_request(async {
        let mut snapshot = w.db.write_pool().begin().await.unwrap();
        let key = kernel::read_cache::key_on(&mut snapshot, &w.viewer, "home_visibility")
            .await
            .unwrap();
        assert!(
            kernel::read_cache::get::<kernel::VisibleHomeAnchors>(&key).is_none(),
            "a new request starts empty"
        );
        snapshot.rollback().await.unwrap();
    })
    .await;
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_browser_bounded_get_matches_full_staging_for_filing_and_windows() {
    let w = world().await;
    install_comment_carrier(&w).await;
    call_as(&w,"acct:admin","create_record",json!({"type":"Annotation","kind":"comment","body":"Unrelated annotation","links":[{"target_id":w.second,"relationship":"part_of"}]})).await.unwrap();
    let package = crate::v2_standard::document_package();
    let identity = package.identity().unwrap();
    kernel::install_package_as(&w.db, &w.admin, &package)
        .await
        .unwrap();
    kernel::adopt_package_at(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &package,
        Some(&identity),
        &package.declared_reads,
    )
    .await
    .unwrap();
    let home = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let folder = call_as(
        &w,
        "acct:admin",
        "create_record",
        json!({"type":"Collection","kind":"folder","name":"Scoped folder","home_id":home}),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let child=call_as(&w,"acct:admin","create_record",json!({"type":"Document","kind":"note","name":"Scoped child","body":"child","home_id":folder})).await.unwrap()["id"].as_str().unwrap().to_owned();
    call_as(
        &w,
        "acct:admin",
        "update_record",
        json!({"id":w.first,"home_id":folder}),
    )
    .await
    .unwrap();
    let citation=call_as(&w,"acct:admin","create_record",json!({"type":"Annotation","kind":"citation","body":"Cited passage","links":[{"target_id":child,"relationship":"part_of"}]})).await.unwrap()["id"].as_str().unwrap().to_owned();
    let revision = kernel::read_record_as(&w.db, &w.admin, &child)
        .await
        .unwrap()
        .unwrap()
        .revision;
    kernel::set_archived_as(&w.db, &w.admin, &child, true, revision)
        .await
        .unwrap();
    let reads = [
        ("records", "id"),
        ("records", "type"),
        ("records", "kind"),
        ("records", "name"),
        ("records", "archived"),
        ("records", "created_at"),
        ("records", "home_id"),
        ("links", "source_id"),
        ("links", "target_id"),
        ("links", "relationship"),
    ];
    // Compare batch child windows with the original individual section
    // reader, including empty/offset pages and duplicate requested ids.
    for (limit, offset) in [(0, 0), (1, 0), (1, 1), (50, 0)] {
        let ids = vec![
            folder.clone(),
            child.clone(),
            folder.clone(),
            w.hidden.clone(),
        ];
        let opts = crate::query::read::EnrichOptions {
            children_limit: limit,
            children_offset: offset,
            ..Default::default()
        };
        kernel::read_cache::scope_request(super::sql::with_read_session(&w.db, &w.viewer, &reads, async {
            let batched = super::read_surface::child_sections(&w.db, &w.viewer, &ids, &opts).await.unwrap();
            for id in &ids {
                let expected = super::read_surface::section(&w.db,&w.viewer,"r.home_id=?1 AND NOT (r.type='Annotation' AND coalesce(r.kind,'') IN ('comment','suggestion','citation','attribution','acknowledgement')) AND NOT (r.type='Entity' AND r.kind IS 'semantic-unit')",vec![json!({"type":"text","value":id})],"r.name,r.id",limit,offset).await.unwrap();
                assert_eq!(batched.get(id).unwrap(), &expected);
            }
            Ok(())
        })).await.unwrap();
    }
    for (credential, actor) in [("acct:viewer", &w.viewer), ("acct:admin", &w.admin)] {
        for ids in [
            json!([w.first]),
            json!([folder]),
            json!([child, citation, w.hidden]),
            json!([KERNEL_ROOT_ID, "native:root"]),
            json!(["missing", w.hidden]),
        ] {
            let args = json!({"ids":ids,"children_limit":50,"include_citations":true,"include_suggestions":true});
            let expected = kernel::read_cache::scope_request(super::sql::with_read_session(
                &w.db,
                actor,
                &reads,
                super::get_record_in_session(&w.db, actor, args.clone()),
            ))
            .await
            .unwrap();
            let actual = call_as(&w, credential, "get_record", args).await.unwrap();
            assert_eq!(actual["records"], expected["records"], "{credential}");
        }
    }
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_browser_bounded_get_move_destinations_match_full_placement() {
    let w = Box::pin(world()).await;
    Box::pin(install_comment_carrier(&w)).await;
    let package = crate::v2_standard::document_package();
    let identity = package.identity().unwrap();
    Box::pin(kernel::install_package_as(&w.db, &w.admin, &package))
        .await
        .unwrap();
    Box::pin(kernel::adopt_package_at(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &package,
        Some(&identity),
        &package.declared_reads,
    ))
    .await
    .unwrap();
    let home = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let mut folders = Vec::new();
    for name in ["Move source", "Move destination"] {
        folders.push(
            bounded_placement_call(
                &w,
                "acct:admin",
                "create_record",
                json!({"type":"Collection","kind":"folder","name":name,"home_id":home}),
            )
            .await
            .unwrap()["id"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
    }
    let create_note = |name: &str, parent: &str, private: bool| {
        let mut args = json!({"type":"Document","kind":"note","name":name,"body":"placement fixture","home_id":parent});
        if private {
            args["access_policy"] = json!("account_only");
        }
        args
    };
    let mover = bounded_placement_call(
        &w,
        "acct:admin",
        "create_record",
        create_note("Moving child", &home, false),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let private = bounded_placement_call(
        &w,
        "acct:admin",
        "create_record",
        create_note("Private child", &folders[0], true),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let private_home = kernel::read_record_as(&w.db, &w.admin, &private)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    assert_ne!(private_home, folders[0]);
    let descendant = bounded_placement_call(
        &w,
        "acct:admin",
        "create_record",
        create_note("Unmoved descendant", &folders[0], false),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let descendant_home = kernel::read_record_as(&w.db, &w.admin, &descendant)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    // Historical destination membership is deliberately a superset: moving
    // away cannot retain the child in the previous parent's exact window.
    for (index, destination) in [&folders[0], &folders[1], &folders[0]]
        .into_iter()
        .enumerate()
    {
        bounded_placement_call(
            &w,
            "acct:admin",
            "update_record",
            json!({"id":mover,"home_id":destination}),
        )
        .await
        .unwrap();
        // A projected receipt can name a logical parent independently of
        // storage. This ordinary fixture has no mapped self-home, so only
        // the logical-destination union can nominate it as a folder child.
        sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) SELECT ?1,id,'kernel.record_rehomed.v2',json_object('new_home_id',home_id,'logical_home_id',?2,'parent_update',NULL),?3,created_at,1,'legacy_unknown' FROM kernel_records WHERE id=?4")
            .bind(format!("bounded-logical-move:{index}")).bind(destination).bind(&w.admin).bind(&w.second).execute(w.db.write_pool()).await.unwrap();
        bounded_placement_call(
            &w,
            "acct:admin",
            "update_record",
            json!({"id":private,"home_id":destination}),
        )
        .await
        .unwrap();
        assert_eq!(
            kernel::read_record_as(&w.db, &w.admin, &private)
                .await
                .unwrap()
                .unwrap()
                .home_id,
            private_home
        );
        for (credential, actor) in [("acct:admin", &w.admin), ("acct:viewer", &w.viewer)] {
            let (out, _, _) = bounded_placement_get_pair(
                &w,
                credential,
                actor,
                json!({"ids":folders,"children_limit":50}),
            )
            .await;
            for record in out["records"].as_array().unwrap() {
                let children = record["children"].as_array().unwrap();
                assert_eq!(
                    children.iter().any(|row| row["id"] == mover),
                    record["id"] == *destination
                );
                assert_eq!(
                    children.iter().any(|row| row["id"] == w.second),
                    record["id"] == *destination
                );
                assert_eq!(
                    children.iter().any(|row| row["id"] == private),
                    credential == "acct:admin" && record["id"] == *destination
                );
            }
        }
    }
    // A newer legacy receipt with no logical destination restores physical
    // filing, even though older moves still nominate this row for both folders.
    sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) SELECT 'bounded-logical-fallback',id,'kernel.record_rehomed.v1',json_object('new_home_id',home_id),?2,created_at,1,'legacy_unknown' FROM kernel_records WHERE id=?1")
        .bind(&w.second).bind(&w.admin).execute(w.db.write_pool()).await.unwrap();
    for (credential, actor) in [("acct:admin", &w.admin), ("acct:viewer", &w.viewer)] {
        let (out, _, _) = bounded_placement_get_pair(
            &w,
            credential,
            actor,
            json!({"ids":[folders[0],folders[1],w.second],"children_limit":50}),
        )
        .await;
        for record in &out["records"].as_array().unwrap()[..2] {
            assert!(!record["children"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["id"] == w.second));
        }
        assert_eq!(out["records"][2]["home_id"], home);
    }
    // Moving the folder changes its own placement and reparents its bound
    // policy home; the descendant's own physical home remains unchanged.
    bounded_placement_call(
        &w,
        "acct:admin",
        "update_record",
        json!({"id":folders[0],"home_id":folders[1]}),
    )
    .await
    .unwrap();
    assert_eq!(
        kernel::read_record_as(&w.db, &w.admin, &descendant)
            .await
            .unwrap()
            .unwrap()
            .home_id,
        descendant_home
    );
    // Retained v1 moves may have no logical destination. In that case current
    // physical/mapped placement still supplies the child's candidate branch.
    sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) SELECT 'bounded-legacy-move',id,'kernel.record_rehomed.v1',json_object('new_home_id',home_id),?2,created_at,1,'legacy_unknown' FROM kernel_records WHERE id=?1")
        .bind(&descendant).bind(&w.admin).execute(w.db.write_pool()).await.unwrap();
    for (credential, actor) in [("acct:admin", &w.admin), ("acct:viewer", &w.viewer)] {
        bounded_placement_get_pair(
            &w,
            credential,
            actor,
            json!({"ids":[folders[0],folders[1],descendant,private],"children_limit":50}),
        )
        .await;
    }
    // A visible row can retain a hidden logical parent under an independent
    // imported policy home. Its body stays visible and its parent stays hidden.
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::hq::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let mapped = kernel::hq::v1_import_home_id(&w.hidden);
    kernel::hq::import_home_as(
        &w.db,
        &host,
        &mapped,
        &w.hidden,
        KERNEL_ROOT_ID,
        &w.admin,
        Some(&[(&w.viewer, "view")]),
    )
    .await
    .unwrap();
    sqlx::query("UPDATE kernel_records SET home_id=? WHERE id=?")
        .bind(&mapped)
        .bind(&w.first)
        .execute(w.db.write_pool())
        .await
        .unwrap();
    let (out, _, _) = bounded_placement_get_pair(
        &w,
        "acct:viewer",
        &w.viewer,
        json!({"ids":[w.first,w.hidden],"children_limit":50}),
    )
    .await;
    assert_eq!(out["records"][0]["status"], "found");
    assert!(out["records"][0]["home_id"].is_null());
    assert_eq!(out["records"][1]["status"], "not_found");
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
// These tests await many registry calls. Erase their large debug future types
// at construction so they do not all occupy the outer test's stack frame.
fn bounded_placement_call<'a>(
    w: &'a World,
    credential: &'a str,
    tool: &'a str,
    args: Value,
) -> futures::future::BoxFuture<'a, Result<Value>> {
    Box::pin(call_as(w, credential, tool, args))
}

#[cfg(feature = "v2-kernel-probe")]
fn bounded_placement_get_pair<'a>(
    w: &'a World,
    credential: &'a str,
    actor: &'a str,
    args: Value,
) -> futures::future::BoxFuture<'a, (Value, sql::Stats, sql::Stats)> {
    Box::pin(async move {
        let reads = [
            ("records", "id"),
            ("records", "type"),
            ("records", "kind"),
            ("records", "name"),
            ("records", "archived"),
            ("records", "created_at"),
            ("records", "home_id"),
            ("links", "source_id"),
            ("links", "target_id"),
            ("links", "relationship"),
        ];
        let (full, full_stats) = Box::pin(sql::measured(kernel::read_cache::scope_request(
            sql::with_read_session(
                &w.db,
                actor,
                &reads,
                super::get_record_in_session(&w.db, actor, args.clone()),
            ),
        )))
        .await;
        let (narrow, narrow_stats) =
            sql::measured(bounded_placement_call(w, credential, "get_record", args)).await;
        let narrow = narrow.unwrap();
        // The registry attaches transport run context; the internal full-session
        // oracle returns only the data payload. Compare every other top-level key.
        let mut full = full.unwrap();
        let mut narrow_payload = narrow.clone();
        full.as_object_mut().unwrap().remove("run_context");
        narrow_payload
            .as_object_mut()
            .unwrap()
            .remove("run_context");
        assert_eq!(narrow_payload, full, "{credential}");
        (narrow, narrow_stats, full_stats)
    })
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_browser_bounded_get_unrelated_move_history_does_not_stage_records() {
    let w = Box::pin(world()).await;
    small_read_unrelated_fixture(&w).await;
    for (credential, actor) in [("acct:admin", &w.admin), ("acct:viewer", &w.viewer)] {
        let args = json!({"ids":[w.first],"children_limit":50});
        let (before, before_stats, _) =
            bounded_placement_get_pair(&w, credential, actor, args.clone()).await;
        // These serving fixtures include explicit logical destinations and
        // old v1 receipts with only physical destinations. Neither visits the
        // requested parent; all 300 used to enter the blanket move union.
        sqlx::query("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<3) INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) SELECT ?1||r.id||':'||x,r.id,CASE WHEN x=2 THEN 'kernel.record_rehomed.v2' ELSE 'kernel.record_rehomed.v1' END,CASE WHEN x=3 THEN json_object('new_home_id',r.home_id) ELSE json_object('new_home_id',r.home_id,'logical_home_id',r.home_id,'parent_update',NULL) END,?2,r.created_at,1,'legacy_unknown' FROM n CROSS JOIN kernel_records r WHERE r.id LIKE 'small:unrelated:%'")
            .bind(format!("bounded-unrelated:{credential}:" )).bind(&w.admin).execute(w.db.write_pool()).await.unwrap();
        let (after, after_stats, full_stats) =
            bounded_placement_get_pair(&w, credential, actor, args).await;
        assert_eq!(after, before);
        assert_eq!(after_stats.installations, 1);
        assert_eq!(after_stats.staged_records, before_stats.staged_records);
        assert_eq!(
            after_stats.staged_metadata_records,
            before_stats.staged_metadata_records
        );
        assert!(
            after_stats.staged_records + 300 <= full_stats.staged_records,
            "narrow={after_stats:?}, full={full_stats:?}"
        );
    }
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_browser_readiness_requires_indexes_and_current_headers() {
    let w = world().await;
    for index in [
        "idx_kernel_record_event_clock",
        "idx_kernel_record_moves",
        "idx_kernel_record_filing_types",
        "idx_kernel_record_message_types",
        "idx_kernel_v1_state_record",
        "idx_kernel_historical_home",
        "idx_kernel_historical_target",
    ] {
        sqlx::query(&format!("DROP INDEX {index}"))
            .execute(w.db.write_pool())
            .await
            .unwrap();
        let error = kernel::verify_v2_ready(&w.db).await.unwrap_err();
        assert!(error.to_string().contains(index));
        assert!(
            kernel::open_marked_v2_database(w.db.path().to_str().unwrap())
                .await
                .is_err()
        );
        kernel::prepare_v2_database(&w.db).await.unwrap();
        kernel::verify_v2_ready(&w.db).await.unwrap();
    }
    let plan: Vec<(i64,i64,i64,String)> = sqlx::query_as("EXPLAIN QUERY PLAN SELECT EXISTS(SELECT 1 FROM kernel_record_fields WHERE name='v1_type' AND value_json='\"Message\"')")
        .fetch_all(w.db.pool()).await.unwrap();
    assert!(plan
        .iter()
        .any(|row| row.3.contains("idx_kernel_record_message_types")));
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    kernel::import_event_as(
        &w.db,
        &host,
        &w.first,
        &kernel::LegacyEvent {
            source: None,
            id: "readiness-frontier".into(),
            event_type: "v1.snapshot_provenance".into(),
            payload: json!({"record_id":w.first}),
            created_at: "2026-10-21T00:00:00Z".into(),
            actor: None,
            run_key: None,
        },
    )
    .await
    .unwrap();
    sqlx::query("UPDATE kernel_legacy_sql_progress SET scanned_seq=0 WHERE singleton=1")
        .execute(w.db.write_pool())
        .await
        .unwrap();
    assert!(kernel::verify_v2_ready(&w.db)
        .await
        .unwrap_err()
        .to_string()
        .contains("catchup"));
    assert!(
        kernel::open_marked_v2_database(w.db.path().to_str().unwrap())
            .await
            .is_err()
    );
    // Existing handles also fail closed; both direct reads bypass SQL staging.
    assert!(crate::v1_import::placement_as(&w.db, &w.viewer, &w.first)
        .await
        .is_err());
    for (tool, args) in [
        (
            "query_record",
            json!({"steps":[{"step":"filter","ids":[w.first]}]}),
        ),
        ("search", json!({"query":"revised"})),
    ] {
        assert!(call(&w, tool, args).await.is_err(), "{tool}");
    }
    kernel::prepare_v2_database(&w.db).await.unwrap();
    kernel::verify_v2_ready(&w.db).await.unwrap();
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_browser_write_request_caches_follow_authority_events() {
    let w = world().await;
    kernel::read_cache::scope_request(async {
        let namespaces = [
            "home_visibility",
            "lifecycle",
            "ancestor_descriptors",
            "disclosed_accounts",
        ];
        let mut snapshot = w.db.write_pool().begin().await.unwrap();
        let mut before = Vec::new();
        for namespace in namespaces {
            let key = kernel::read_cache::key_on(&mut snapshot, &w.viewer, namespace)
                .await
                .unwrap();
            kernel::read_cache::put(key.clone(), std::sync::Arc::new(17usize));
            before.push(key);
        }
        let home = kernel::read_record_on(&mut snapshot, &w.viewer, &w.first)
            .await
            .unwrap()
            .unwrap()
            .home_id;
        assert!(
            kernel::read_cache::with_capabilities(kernel::kernel_effective_capability_on(
                &mut snapshot,
                &w.viewer,
                &w.first
            ))
            .await
            .unwrap()
            .allows(crate::authorization::Capability::View)
        );
        snapshot.rollback().await.unwrap();
        // A writer inside this very request changes projected authority. The
        // policy API must also append an event before another read can reuse
        // any of the caches (not only the capability cache, disabled on writes).
        kernel::replace_home_policy(&w.db, &w.admin, &home, &[])
            .await
            .unwrap();
        let mut snapshot = w.db.write_pool().begin().await.unwrap();
        for (namespace, old) in namespaces.into_iter().zip(before) {
            let current = kernel::read_cache::key_on(&mut snapshot, &w.viewer, namespace)
                .await
                .unwrap();
            assert!(
                current != old,
                "{namespace}: authority writes must advance event heads"
            );
            assert!(kernel::read_cache::get::<usize>(&current).is_none());
        }
        assert!(
            !kernel::read_cache::with_capabilities(kernel::kernel_effective_capability_on(
                &mut snapshot,
                &w.viewer,
                &w.first
            ))
            .await
            .unwrap()
            .allows(crate::authorization::Capability::View)
        );
        assert!(kernel::read_record_on(&mut snapshot, &w.viewer, &w.first)
            .await
            .unwrap()
            .is_none());
        snapshot.rollback().await.unwrap();
    })
    .await;
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_browser_batch_hydration_keeps_the_staged_snapshot() {
    let w = world().await;
    let first = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap();
    let reads = [
        ("records", "id"),
        ("records", "type"),
        ("records", "kind"),
        ("records", "name"),
        ("records", "archived"),
        ("records", "created_at"),
        ("records", "home_id"),
        ("links", "source_id"),
        ("links", "target_id"),
        ("links", "relationship"),
    ];
    let ids = vec![w.first.clone(), w.second.clone()];
    let value = kernel::read_cache::scope_request(super::sql::with_part_of_read_session(
        &w.db,
        &w.admin,
        &reads,
        &ids,
        async {
            // Simulate a concurrent writer after staging pinned its read snapshot.
            kernel::set_body_as(&w.db, &w.admin, &w.first, "newer body", first.revision).await?;
            kernel::observe_facet_as(
                &w.db,
                &w.admin,
                &w.first,
                &kernel::FacetObservation {
                    key: "snapshot-proof".into(),
                    value: Some("newer facet".into()),
                    value_num: None,
                    vocab_ref: None,
                    as_of: crate::store::now_iso(),
                },
                None,
            )
            .await?;
            super::get_record_in_session(&w.db, &w.admin, json!({"ids":ids})).await
        },
    ))
    .await
    .unwrap();
    assert_eq!(
        value["records"][0]["version"],
        format!("rec:{}", first.revision)
    );
    assert_ne!(value["records"][0]["body"], "newer body");
    assert!(!value["records"][0]["facets"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["key"] == "snapshot-proof"));
    assert_eq!(
        kernel::read_record_as(&w.db, &w.admin, &w.first)
            .await
            .unwrap()
            .unwrap()
            .body
            .as_deref(),
        Some("newer body")
    );
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_browser_batch_large_body_does_not_inherit_sql_cell_limit() {
    let w = world().await;
    let body = "x".repeat(crate::query::sql::MAX_SQLITE_VALUE_BYTES as usize + 4096);
    let record = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap();
    kernel::set_body_as(&w.db, &w.admin, &w.first, &body, record.revision)
        .await
        .unwrap();
    // Counts/enrichment execute governed SQL before the next record is hydrated.
    let result = call(&w, "get_record", json!({"ids":[w.first,w.second,w.first]}))
        .await
        .unwrap();
    assert_eq!(result["records"][0]["body"], body);
    assert_eq!(result["records"][2]["body"], body);
    assert_eq!(result["records"][1]["status"], "found");
    // The SQL ceiling itself is unchanged.
    assert!(call(&w, "query_sql", json!({"sql":"SELECT body FROM records WHERE id=?1","parameters":[{"type":"text","value":w.first}]})).await.is_err());
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_browser_global_history_windows_match_full_staging() {
    let w = world().await;
    // A whole candidate window is invisible to the member. Scanning it must
    // neither end the page early nor disclose a hidden position as its cursor.
    for n in 0..300 {
        let revision = kernel::read_record_as(&w.db, &w.admin, &w.hidden)
            .await
            .unwrap()
            .unwrap()
            .revision;
        kernel::set_body_as(
            &w.db,
            &w.admin,
            &w.hidden,
            &format!("private revision {n}"),
            revision,
        )
        .await
        .unwrap();
    }
    let reads = &[
        ("content_events", "local_seq"),
        ("content_events", "record_id"),
        ("content_events", "run_key"),
        ("content_events", "parent_key"),
    ];
    for actor in [&w.viewer, &w.admin] {
        for order in ["oldest_first", "newest_first"] {
            for detail in ["metadata", "full"] {
                let mut cursor = None;
                for _ in 0..3 {
                    let mut args = json!({"limit":2,"order":order,"detail":detail});
                    if let Some(seq) = cursor {
                        args["after_local_seq"] = json!(seq);
                    }
                    let expected = kernel::read_cache::scope_request(sql::with_read_session(
                        &w.db,
                        actor,
                        reads,
                        read_surface::history_in_session(&w.db, actor, args.clone()),
                    ))
                    .await
                    .unwrap();
                    let actual = kernel::read_cache::scope_request(read_surface::history(
                        &w.db, actor, args,
                    ))
                    .await
                    .unwrap();
                    assert_eq!(actual, expected, "{order} {detail}");
                    cursor = actual["next_after_local_seq"].as_i64();
                    if cursor.is_none() {
                        break;
                    }
                }
            }
        }
    }
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_search_windows_preserve_tiers_archive_visibility_and_body_snippets() {
    let w = world().await;
    let public = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let private = kernel::read_record_as(&w.db, &w.admin, &w.hidden)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let mut expected = Vec::new();
    for n in 0..230 {
        let hidden = n % 9 == 0;
        let archived = n % 17 == 0;
        let title_match = n % 7 == 0;
        let title = if title_match {
            format!("windowneedle title {n}")
        } else {
            format!("Entry {n}")
        };
        let id = kernel::create_as(
            &w.db,
            &w.admin,
            "fixture.mcp",
            "note",
            json!({"title":title,"body":format!("windowneedle body {n}")})
                .as_object()
                .unwrap(),
            if hidden { &private } else { &public },
        )
        .await
        .unwrap();
        if archived {
            let revision = kernel::read_record_as(&w.db, &w.admin, &id)
                .await
                .unwrap()
                .unwrap()
                .revision;
            kernel::hq::set_archived_as(&w.db, &w.admin, &id, true, revision)
                .await
                .unwrap();
        }
        expected.push((if title_match { 0 } else { 2 }, id, hidden, archived));
    }
    // More than two windows, with hidden/archived ids interspersed. Later
    // title hits must displace earlier body hits, without changing id ties.
    for actor in [&w.viewer, &w.admin] {
        for include_archived in [false, true] {
            let mut wanted: Vec<_> = expected
                .iter()
                .filter(|(_, _, hidden, archived)| {
                    (!hidden || actor == &w.admin) && (!archived || include_archived)
                })
                .collect();
            wanted.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));
            wanted.truncate(200);
            let (hits, truncated) =
                kernel::search_v2::search_as(&w.db, actor, "windowneedle", 200, include_archived)
                    .await
                    .unwrap();
            assert!(!truncated);
            assert_eq!(
                hits.iter()
                    .map(|hit| (&hit.id, hit.score as i64))
                    .collect::<Vec<_>>(),
                wanted.iter().map(|row| (&row.1, row.0)).collect::<Vec<_>>()
            );
            assert!(hits
                .iter()
                .filter(|hit| hit.score == 2.0)
                .all(|hit| hit.snippet.contains("windowneedle body")));
        }
    }
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_browser_materialized_record_cache_is_read_only_and_head_bound() {
    let w = world().await;
    kernel::read_cache::scope_request(async {
        let before = kernel::read_cache::with_capabilities(kernel::read_record_as(&w.db, &w.viewer, &w.first)).await.unwrap().unwrap();
        assert_eq!(before.fields["body"], "revised");
        kernel::revise_as(&w.db,&w.admin,&w.first,json!({"body":"New event"}).as_object().unwrap()).await.unwrap();
        let after = kernel::read_cache::with_capabilities(kernel::read_record_as(&w.db,&w.viewer,&w.first)).await.unwrap().unwrap();
        assert_eq!(after.fields["body"], "New event");
        assert!(after.revision > before.revision);
        assert!(kernel::read_cache::with_capabilities(kernel::read_record_as(&w.db,&w.viewer,&w.hidden)).await.unwrap().is_none());
        assert!(kernel::read_cache::with_capabilities(kernel::read_record_as(&w.db,&w.admin,&w.hidden)).await.unwrap().is_some());
        // An intermediate projection edit in a write transaction must never
        // consume a view memoized by an earlier closed read of the same head.
        let mut tx = w.db.write_pool().begin().await.unwrap();
        kernel::read_cache::with_capabilities(kernel::read_record_on(&mut tx,&w.viewer,&w.first)).await.unwrap();
        sqlx::query("UPDATE kernel_record_fields SET value_json='\"Intermediate projection\"' WHERE record_id=? AND name='body'").bind(&w.first).execute(&mut *tx).await.unwrap();
        let fresh = kernel::read_record_on(&mut tx,&w.viewer,&w.first).await.unwrap().unwrap();
        assert_eq!(fresh.fields["body"], "Intermediate projection");
        tx.rollback().await.unwrap();
        let home = after.home_id;
        kernel::replace_home_policy(&w.db,&w.admin,&home,&[]).await.unwrap();
        assert!(kernel::read_cache::with_capabilities(kernel::read_record_as(&w.db,&w.viewer,&w.first)).await.unwrap().is_none());
    }).await;
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_browser_sql_id_prefix_matches_full_barrier() {
    let w = world().await;
    for (credential, actor) in [("acct:viewer", &w.viewer), ("acct:admin", &w.admin)] {
        for statement in [
            "SELECT id,name FROM records ORDER BY id LIMIT 1",
            "SELECT name FROM records ORDER BY id ASC LIMIT 2",
            "SELECT id,name FROM records WHERE name IS NOT NULL ORDER BY id LIMIT 1",
            "SELECT name AS id FROM records ORDER BY id LIMIT 1",
        ] {
            let expected = kernel::read_cache::scope_request(super::sql::with_read_session(
                &w.db,
                actor,
                &[("records", "id"), ("records", "name")],
                super::sql::query_sql(&w.db, actor, json!({"sql":statement})),
            ))
            .await
            .unwrap();
            let (actual, stats) = super::sql::measured(call_as(
                &w,
                credential,
                "query_sql",
                json!({"sql":statement}),
            ))
            .await;
            let mut actual = actual.unwrap();
            actual.as_object_mut().unwrap().remove("run_context");
            assert_eq!(actual, expected, "{credential}/{statement}");
            if statement == "SELECT id,name FROM records ORDER BY id LIMIT 1" {
                assert_eq!(stats.staged_records, 1);
            }
            if credential == "acct:viewer" {
                assert!(!actual.to_string().contains("Secret"));
            }
        }
    }
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_browser_counted_query_never_decodes_a_hidden_carrier() {
    let w = world().await;
    install_comment_carrier(&w).await;
    let hidden = call_as(&w,"acct:admin","create_record",json!({"type":"Annotation","kind":"comment","body":"Hidden malformed carrier","links":[{"target_id":w.hidden,"relationship":"part_of"}]})).await.unwrap()["id"].as_str().unwrap().to_owned();
    sqlx::query(
        "UPDATE kernel_record_fields SET value_json='{' WHERE record_id=? AND name='v1_kind'",
    )
    .bind(&hidden)
    .execute(w.db.write_pool())
    .await
    .unwrap();
    let args = json!({"steps":[{"step":"filter","types":["Document","Annotation"],"kinds":["note"]}],"limit":100});
    let actual = call(&w, "query_record", args.clone()).await.unwrap();
    let expected = kernel::search_v2::FORCE_GROUP_SCAN
        .scope(true, call(&w, "query_record", args.clone()))
        .await
        .unwrap();
    assert_eq!(actual, expected);
    assert_eq!(actual["total"], 2);
    assert!(
        call_as(&w, "acct:admin", "query_record", args)
            .await
            .is_err(),
        "a visible malformed carrier still reports its decoding failure"
    );
    w.db.close().await;
}

/// The counted window now reads its exact total from the page itself
/// (`count(*) OVER ()`), falling back to a separate count only for an empty
/// page past offset 0. Totals and windows must still match the group scan at
/// every offset, including past the end.
#[tokio::test]
async fn kernel_v2_counted_window_total_matches_group_scan_at_every_offset() {
    let w = world().await;
    for offset in [0, 1, 2, 5, 1_000] {
        for limit in [1, 2, 100] {
            let args = json!({"steps":[{"step":"filter","types":["Document"]}],"limit":limit,"offset":offset});
            let actual = call(&w, "query_record", args.clone()).await.unwrap();
            let expected = kernel::search_v2::FORCE_GROUP_SCAN
                .scope(true, call(&w, "query_record", args))
                .await
                .unwrap();
            assert_eq!(actual, expected, "offset {offset} limit {limit}");
        }
    }
    let full = call(
        &w,
        "query_record",
        json!({"steps":[{"step":"filter","types":["Document"]}],"limit":100}),
    )
    .await
    .unwrap();
    assert!(
        full["total"].as_u64().unwrap() >= 2,
        "fixture needs several documents: {full}"
    );
    let past_end = call(
        &w,
        "query_record",
        json!({"steps":[{"step":"filter","types":["Document"]}],"limit":5,"offset":1_000}),
    )
    .await
    .unwrap();
    assert_eq!(
        past_end["total"], full["total"],
        "an empty page past the end still reports the exact total"
    );
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_browser_history_admission_seeks_only_selected_positions() {
    use sqlx::Row;
    let w = world().await;
    let mut connection = w.db.governed_pool().acquire().await.unwrap();
    connection.close_on_drop();
    sqlx::query("BEGIN")
        .execute(&mut *connection)
        .await
        .unwrap();
    let reads = [("content_events".into(), "id".into())]
        .into_iter()
        .collect();
    super::sql::install(&mut connection, &w.viewer, &reads)
        .await
        .unwrap();
    let plan = sqlx::query(&format!(
        "EXPLAIN QUERY PLAN {}",
        super::sql::LEGACY_ADMISSION_SQL
    ))
    .bind(false)
    .bind("acct:viewer")
    .fetch_all(&mut *connection)
    .await
    .unwrap()
    .into_iter()
    .map(|row| row.get::<String, _>(3))
    .collect::<Vec<_>>();
    assert!(plan.iter().any(|p| p.starts_with("SCAN a")), "{plan:?}");
    for alias in ["m", "h"] {
        assert!(
            !plan.iter().any(|p| p.starts_with(&format!("SCAN {alias}"))),
            "selected positions must precede retained headers: {plan:?}"
        );
    }
    sqlx::query("ROLLBACK")
        .execute(&mut *connection)
        .await
        .unwrap();
    drop(connection);
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_browser_clean_connection_reuse_drops_all_caller_state() {
    let w = world().await;
    // Force all successive requests onto one physical slot. An ordinary pool
    // page cache may survive; TEMP rows and authority must never survive.
    let mut held = Vec::new();
    for _ in 1..w.db.governed_pool().options().get_max_connections() {
        held.push(w.db.governed_pool().acquire().await.unwrap());
    }
    let mut connection = w.db.governed_pool().acquire().await.unwrap();
    let baseline: i64 = sqlx::query_scalar("SELECT total_changes()")
        .fetch_one(&mut *connection)
        .await
        .unwrap();
    drop(connection);
    let visible = call_as(
        &w,
        "acct:viewer",
        "get_record",
        json!({"ids":[w.first,w.hidden]}),
    )
    .await
    .unwrap();
    assert_eq!(visible["records"][0]["status"], "found");
    assert_eq!(visible["records"][1]["status"], "not_found");
    let mut connection = w.db.governed_pool().acquire().await.unwrap();
    let after: i64 = sqlx::query_scalar("SELECT total_changes()")
        .fetch_one(&mut *connection)
        .await
        .unwrap();
    assert!(after > baseline, "successful reads reuse the physical slot");
    let remaining: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM temp.sqlite_schema WHERE name NOT GLOB 'sqlite_*'",
    )
    .fetch_one(&mut *connection)
    .await
    .unwrap();
    assert_eq!(
        remaining, 0,
        "all materialized caller relations were rolled back"
    );
    let query_only: i64 = sqlx::query_scalar("PRAGMA query_only")
        .fetch_one(&mut *connection)
        .await
        .unwrap();
    assert_eq!(query_only, 0);
    drop(connection);
    let owner = call_as(&w, "acct:admin", "get_record", json!({"ids":[w.hidden]}))
        .await
        .unwrap();
    assert_eq!(owner["records"][0]["status"], "found");
    let home: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
        .bind(&w.first)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    kernel::replace_home_policy(&w.db, &w.admin, &home, &[])
        .await
        .unwrap();
    let revoked = call_as(
        &w,
        "acct:viewer",
        "get_record",
        json!({"ids":[w.first,w.hidden]}),
    )
    .await
    .unwrap();
    assert!(revoked["records"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["status"] == "not_found"));
    let failure = super::sql::with_read_session(&w.db, &w.admin, &[("records", "id")], async {
        Err::<(), _>(Error::engine("fixture read failure"))
    })
    .await
    .unwrap_err();
    assert!(failure.to_string().contains("fixture read failure"));
    let mut connection = w.db.governed_pool().acquire().await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM temp.sqlite_schema WHERE name NOT GLOB 'sqlite_*'"
        )
        .fetch_one(&mut *connection)
        .await
        .unwrap(),
        0
    );
    drop(connection);
    let ready = std::sync::Arc::new(tokio::sync::Notify::new());
    let task = {
        let db = w.db.clone();
        let actor = w.admin.clone();
        let ready = ready.clone();
        tokio::spawn(async move {
            super::sql::with_read_session(&db, &actor, &[("records", "id")], async {
                ready.notify_one();
                std::future::pending::<Result<()>>().await
            })
            .await
        })
    };
    ready.notified().await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let mut connection = w.db.governed_pool().acquire().await.unwrap();
    let changes: i64 = sqlx::query_scalar("SELECT total_changes()")
        .fetch_one(&mut *connection)
        .await
        .unwrap();
    assert_eq!(changes, 0, "cancellation closes the physical connection");
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM temp.sqlite_schema WHERE name NOT GLOB 'sqlite_*'"
        )
        .fetch_one(&mut *connection)
        .await
        .unwrap(),
        0
    );
    drop(connection);
    let revoked = call_as(&w, "acct:viewer", "get_record", json!({"ids":[w.hidden]}))
        .await
        .unwrap();
    assert_eq!(revoked["records"][0]["status"], "not_found");
    drop(held);
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_browser_batch_wall_deadline_refuses_without_partial_results() {
    let w = world().await;
    // Expire while waiting for a governed slot, so the outer cap demonstrably
    // includes pool acquisition, before any per-statement/subject guard exists.
    let pool = w.db.governed_pool();
    let mut held = Vec::new();
    for _ in 0..pool.options().get_max_connections() {
        held.push(pool.acquire().await.unwrap());
    }
    let result = GET_BATCH_DEADLINE_OVERRIDE
        .scope(
            std::time::Duration::from_millis(20),
            call(&w, "get_record", json!({"ids":[w.first,w.second]})),
        )
        .await;
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("batch deadline exceeded; no partial results returned"));
    drop(held);
    assert!(call(&w, "get_record", json!({"ids":[w.first]}))
        .await
        .is_ok());
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_browser_write_request_caches_follow_tombstone_events() {
    let w = world().await;
    kernel::read_cache::scope_request(async {
        let mut snapshot = w.db.write_pool().begin().await.unwrap();
        let namespaces = [
            "home_visibility",
            "lifecycle",
            "ancestor_descriptors",
            "disclosed_accounts",
        ];
        let mut before = Vec::new();
        for namespace in namespaces {
            let key = kernel::read_cache::key_on(&mut snapshot, &w.viewer, namespace)
                .await
                .unwrap();
            kernel::read_cache::put(key.clone(), std::sync::Arc::new(17usize));
            before.push(key);
        }
        assert!(kernel::read_record_on(&mut snapshot, &w.viewer, &w.first)
            .await
            .unwrap()
            .is_some());
        snapshot.rollback().await.unwrap();
        call_as(
            &w,
            "acct:admin",
            "delete_record",
            json!({"id":w.first,"reason":"cache tombstone proof"}),
        )
        .await
        .unwrap();
        let mut snapshot = w.db.write_pool().begin().await.unwrap();
        for (namespace, old) in namespaces.into_iter().zip(before) {
            let current = kernel::read_cache::key_on(&mut snapshot, &w.viewer, namespace)
                .await
                .unwrap();
            assert!(current != old, "{namespace}");
            assert!(kernel::read_cache::get::<usize>(&current).is_none());
        }
        assert!(kernel::read_record_on(&mut snapshot, &w.viewer, &w.first)
            .await
            .unwrap()
            .is_none());
        snapshot.rollback().await.unwrap();
    })
    .await;
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_provider_link_lazy_columns_preserve_clocks_notes_and_disclosure_barrier() {
    let w = world().await;
    let large = "x".repeat(crate::query::sql::MAX_SQLITE_VALUE_BYTES as usize + 1);
    let link = kernel::add_generic_link_as(
        &w.db,
        &w.admin,
        &w.first,
        &w.second,
        "lazy-clock-proof",
        Some(large.clone()),
    )
    .await
    .unwrap()
    .link;
    let count = call(
        &w,
        "query_sql",
        json!({"sql":"SELECT count(*) AS n FROM links WHERE relationship='lazy-clock-proof'"}),
    )
    .await
    .unwrap();
    assert_eq!(
        count["rows"][0]["n"], 1,
        "unused oversized note must not poison a count"
    );
    let note=call(&w,"query_sql",json!({"sql":"SELECT note FROM links WHERE id=?1","parameters":[{"type":"text","value":link.link_id}]})).await;
    assert!(
        note.is_err(),
        "requested oversized values retain the ordinary SQL value bound"
    );
    kernel::add_generic_link_as(
        &w.db,
        &w.admin,
        &w.first,
        &w.second,
        "lazy-clock-proof",
        Some("{\"x\":1}".into()),
    )
    .await
    .unwrap();
    let row=call(&w,"query_sql",json!({"sql":"SELECT * FROM links WHERE id=?1","parameters":[{"type":"text","value":link.link_id}]})).await.unwrap();
    assert_eq!(row["rows"][0]["note"], "{\"x\":1}");
    assert_eq!(row["rows"][0]["source_id"], w.first);
    assert_eq!(row["rows"][0]["target_id"], w.second);
    assert!(row["rows"][0]["created_at"].is_string());
    assert!(row["rows"][0]["created_at_ms"].is_i64());
    kernel::add_generic_link_as(
        &w.db,
        &w.admin,
        &w.first,
        &w.hidden,
        "lazy-clock-proof",
        Some("malformed private JSON".into()),
    )
    .await
    .unwrap();
    for target in [w.hidden.as_str(), "missing"] {
        let out=call(&w,"query_sql",json!({"sql":"SELECT count(*) AS n FROM links WHERE CASE WHEN target_id=?1 THEN json_extract(note,'$.x') ELSE 0 END","parameters":[{"type":"text","value":target}]})).await.unwrap();
        assert_eq!(
            out["rows"][0]["n"], 0,
            "caller expressions may not reach hidden rows"
        );
    }
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_provider_link_joined_metadata_matches_lazy_values_and_endpoint_gate() {
    let w = world().await;
    for target in [&w.second, &w.hidden] {
        kernel::add_generic_link_as(
            &w.db,
            &w.admin,
            &w.first,
            target,
            "joined-metadata-proof",
            None,
        )
        .await
        .unwrap();
    }
    for credential in ["acct:viewer", "acct:admin"] {
        let query = "SELECT r.id,r.type,r.kind,r.name,l.relationship FROM links l JOIN records r ON r.id=l.target_id WHERE l.relationship='joined-metadata-proof' ORDER BY r.id";
        let fast = call_as(&w, credential, "query_sql", json!({"sql":query}))
            .await
            .unwrap();
        // Adding body selects the original lazy path. Compare every metadata
        // value against it, with the same live endpoint fence for both callers.
        let lazy_query = query.replacen("l.relationship FROM", "l.relationship,r.body FROM", 1);
        let mut lazy = call_as(&w, credential, "query_sql", json!({"sql":lazy_query}))
            .await
            .unwrap();
        for row in lazy["rows"].as_array_mut().unwrap() {
            row.as_object_mut().unwrap().remove("body");
        }
        assert_eq!(fast["rows"], lazy["rows"]);
        let cte = call_as(&w, credential, "query_sql", json!({"sql":"SELECT target_id AS id FROM links WHERE relationship='joined-metadata-proof' ORDER BY target_id"})).await.unwrap();
        assert_eq!(
            fast["rows"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r["id"].clone())
                .collect::<Vec<_>>(),
            cte["rows"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r["id"].clone())
                .collect::<Vec<_>>()
        );
        // Neither count reads a link column. The joined path must preserve
        // row multiplicity through its private _row column, including hidden
        // endpoints being absent for the member.
        let count = call_as(
            &w,
            credential,
            "query_sql",
            json!({"sql":"SELECT count(*) AS n FROM links"}),
        )
        .await
        .unwrap();
        let joined_count = call_as(&w, credential, "query_sql", json!({"sql":"SELECT count(*) AS n FROM records r CROSS JOIN links l WHERE r.id=?1", "parameters":[{"type":"text","value":w.first}]})).await.unwrap();
        assert_eq!(count["rows"], joined_count["rows"]);
        assert_eq!(
            fast["rows"].as_array().unwrap().len(),
            if credential == "acct:admin" { 2 } else { 1 }
        );
    }
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_workspace_snapshot_pages_are_private_caller_and_database_bound() {
    let w = world().await;
    let opened = call(&w, "get_workspace_snapshot", json!({"action":"open"}))
        .await
        .unwrap();
    let token = opened["snapshot_token"]
        .as_str()
        .expect("real snapshot pin");
    let mut ids = Vec::new();
    let mut after = Value::Null;
    loop {
        let page=call(&w,"get_workspace_snapshot",json!({"action":"page","snapshot_token":token,"section":"records","limit":1,"after_id":after})).await.unwrap();
        assert!(page["rows"].as_array().unwrap().len() <= 1);
        ids.extend(
            page["rows"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r["id"].as_str().unwrap().to_owned()),
        );
        if page["has_more"] == false {
            break;
        }
        after = page["after_id"].clone();
    }
    assert!(ids.contains(&w.first) && ids.contains(&w.second));
    assert!(!ids.contains(&w.hidden));
    for section in ["facets", "links", "content_events"] {
        let page = call(
            &w,
            "get_workspace_snapshot",
            json!({"action":"page","snapshot_token":token,"section":section,"limit":1000}),
        )
        .await
        .unwrap();
        assert!(page["rows"].is_array(), "{page}");
        assert!(!page.to_string().contains(&w.hidden));
    }
    let other = call_as(
        &w,
        "acct:admin",
        "get_workspace_snapshot",
        json!({"action":"page","snapshot_token":token,"section":"records"}),
    )
    .await
    .unwrap();
    assert_eq!(other["reason"], "token_expired_or_unknown");
    let second = world().await;
    let other = call(
        &second,
        "get_workspace_snapshot",
        json!({"action":"page","snapshot_token":token,"section":"records"}),
    )
    .await
    .unwrap();
    assert_eq!(other["reason"], "token_expired_or_unknown");
}

#[tokio::test]
async fn kernel_v2_workspace_snapshot_catch_up_resume_and_fence_move() {
    let w = world().await;
    let opened = call(&w, "get_workspace_snapshot", json!({"action":"open"}))
        .await
        .unwrap();
    let token = opened["snapshot_token"].clone();
    kernel::revise_as(
        &w.db,
        &w.admin,
        &w.first,
        json!({"body":"Changed body"}).as_object().unwrap(),
    )
    .await
    .unwrap();
    let pinned = call(
        &w,
        "get_workspace_snapshot",
        json!({"action":"page","snapshot_token":token,"section":"records"}),
    )
    .await
    .unwrap();
    assert!(
        pinned["rows"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["id"] == w.first && r["name"] == "Alpha"),
        "content edits do not drift pinned pages"
    );
    let delta = call(
        &w,
        "get_workspace_snapshot",
        json!({"action":"catch_up","snapshot_token":token}),
    )
    .await
    .unwrap();
    assert!(delta["upsert_records"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["id"] == w.first));
    let events = delta["content_events"].as_array().unwrap();
    assert!(events
        .windows(2)
        .all(|w| w[0]["seq"].as_i64() < w[1]["seq"].as_i64()));
    let changed = call(
        &w,
        "whats_changed",
        json!({"after_local_seq":0,"through_local_seq":delta["content_seq"],"limit":1000}),
    )
    .await
    .unwrap();
    let changed: Vec<_> = changed["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["last_local_seq"].clone())
        .collect();
    // Snapshot's content lane excludes home/control events that the general
    // change feed also discloses. Every included event still has precisely the
    // canonical sequence and order; the latest actual edit must be present.
    assert!(events.iter().all(|e| changed.contains(&e["seq"])));
    assert_eq!(
        events.last().unwrap()["seq"],
        changed.last().unwrap().clone()
    );
    let resumed=call(&w,"get_workspace_snapshot",json!({"action":"resume","manifest":{"version":1,"profile":crate::workspace_snapshot::RESUME_MANIFEST_PROFILE,"records":[],"facets":[],"links":[]}})).await.unwrap();
    assert!(resumed["upsert_records"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["id"] == w.first));
    assert!(!resumed.to_string().contains(&w.hidden));
    let home: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
        .bind(&w.first)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    kernel::replace_home_policy(&w.db, &w.admin, &home, &[])
        .await
        .unwrap();
    let page = call(
        &w,
        "get_workspace_snapshot",
        json!({"action":"page","snapshot_token":resumed["snapshot_token"],"section":"records"}),
    )
    .await
    .unwrap();
    assert_eq!(page["reason"], "authorization_epoch_moved");
    let restart = call(
        &w,
        "get_workspace_snapshot",
        json!({"action":"catch_up","snapshot_token":resumed["snapshot_token"]}),
    )
    .await
    .unwrap();
    assert_eq!(restart["reason"], "authorization_epoch_moved");
    let moved=call(&w,"get_workspace_snapshot",json!({"action":"catch_up","snapshot_token":resumed["snapshot_token"],"accept_fence_moved":true})).await.unwrap();
    assert_eq!(moved["fence_moved"], true);
    assert!(moved["delete_record_ids"]
        .as_array()
        .unwrap()
        .contains(&json!(w.first)));
    assert!(!moved["upsert_records"].to_string().contains(&w.first));
}

#[tokio::test]
async fn kernel_v2_workspace_snapshot_unrepresentable_native_records_are_unavailable_not_empty() {
    let w = world().await;
    let home: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
        .bind(&w.first)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let bare = kernel::create_record_as(&w.db, &w.admin, &home)
        .await
        .unwrap();
    assert!(kernel::read_record_as(&w.db, &w.viewer, &bare)
        .await
        .unwrap()
        .is_some());
    // The low-level neutral constructor genuinely has no primary type. Carry
    // NULL exactly like get_record / SQL, not a made-up Document classification.
    let get = call(&w, "get_record", json!({"ids":[bare],"children_limit":0}))
        .await
        .unwrap();
    assert!(get["records"][0]["type"].is_null());
    let opened = call(&w, "get_workspace_snapshot", json!({"action":"open"}))
        .await
        .unwrap();
    assert!(opened["snapshot_token"].is_string(), "{opened}");
    let page = call(
        &w,
        "get_workspace_snapshot",
        json!({"action":"page","snapshot_token":opened["snapshot_token"],"section":"records"}),
    )
    .await
    .unwrap();
    let row = page["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == bare)
        .unwrap();
    assert!(row["type"].is_null());
    let resumed=call(&w,"get_workspace_snapshot",json!({"action":"resume","manifest":{"version":1,"profile":crate::workspace_snapshot::RESUME_MANIFEST_PROFILE,"records":[],"facets":[],"links":[]}})).await.unwrap();
    assert!(resumed["snapshot_token"].is_string());
    assert!(resumed["upsert_records"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["id"] == bare && r["type"].is_null()));
    let package = crate::v2_standard::document_package();
    let identity = package.identity().unwrap();
    kernel::install_package_as(&w.db, &w.admin, &package)
        .await
        .unwrap();
    kernel::adopt_package_at(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &package,
        Some(&identity),
        &package.declared_reads,
    )
    .await
    .unwrap();
    let typed=call_as(&w,"acct:admin","create_record",json!({"type":"Document","kind":"note","name":"Native member create","home_id":home,"reason":"native snapshot parity"})).await.unwrap();
    let old_page = call(
        &w,
        "get_workspace_snapshot",
        json!({"action":"page","snapshot_token":opened["snapshot_token"],"section":"records"}),
    )
    .await
    .unwrap();
    assert_eq!(
        old_page["reason"], "authorization_epoch_moved",
        "native creation has v1's INSERT fence"
    );
    let new_open = call(&w, "get_workspace_snapshot", json!({"action":"open"}))
        .await
        .unwrap();
    let page = call(
        &w,
        "get_workspace_snapshot",
        json!({"action":"page","snapshot_token":new_open["snapshot_token"],"section":"records"}),
    )
    .await
    .unwrap();
    assert!(page["rows"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["id"] == typed["id"] && r["type"] == "Document" && r["kind"] == "note"));
}

#[tokio::test]
async fn kernel_v2_workspace_snapshot_agent_control_chatter_keeps_pages_and_content_window() {
    let w = world().await;
    let context = kernel::run_ledger::open_run_as(&w.db, &w.admin, "scout-chair-a748b2")
        .await
        .unwrap();
    let opened = call(&w, "get_workspace_snapshot", json!({"action":"open"}))
        .await
        .unwrap();
    let first=call(&w,"get_workspace_snapshot",json!({"action":"page","snapshot_token":opened["snapshot_token"],"section":"records","limit":1})).await.unwrap();
    assert_eq!(first["has_more"], true);
    for index in 0..520 {
        kernel::run_ledger::set_run_intent_as(&w.db, &context, &format!("Agent activity {index}"))
            .await
            .unwrap();
    }
    kernel::hq::observe_facet_as(
        &w.db,
        &w.admin,
        &w.first,
        &kernel::hq::FacetObservation {
            key: "phase".into(),
            value: Some("active".into()),
            value_num: None,
            vocab_ref: None,
            as_of: "2026-01-01T00:00:00Z".into(),
        },
        None,
    )
    .await
    .unwrap();
    let revision: i64 = sqlx::query_scalar("SELECT max(seq) FROM content_events WHERE record_id=?")
        .bind(&w.first)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    kernel::hq::set_archived_as(&w.db, &w.admin, &w.first, true, revision)
        .await
        .unwrap();
    let next=call(&w,"get_workspace_snapshot",json!({"action":"page","snapshot_token":opened["snapshot_token"],"section":"records","limit":1,"after_id":first["after_id"]})).await.unwrap();
    assert!(next["rows"].is_array(), "{next}");
    assert!(!next["restart_required"].as_bool().unwrap_or(false));
    let delta = call(
        &w,
        "get_workspace_snapshot",
        json!({"action":"catch_up","snapshot_token":opened["snapshot_token"]}),
    )
    .await
    .unwrap();
    assert!(delta["snapshot_token"].is_string(), "{delta}");
    assert!(delta["content_events"]
        .as_array()
        .unwrap()
        .windows(2)
        .all(|r| r[0]["seq"].as_i64() < r[1]["seq"].as_i64()));
    let home: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
        .bind(&w.first)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    kernel::replace_home_policy(&w.db, &w.admin, &home, &[])
        .await
        .unwrap();
    let revoked = call(
        &w,
        "get_workspace_snapshot",
        json!({"action":"page","snapshot_token":delta["snapshot_token"],"section":"records"}),
    )
    .await
    .unwrap();
    assert_eq!(revoked["reason"], "authorization_epoch_moved");
}

#[tokio::test]
async fn kernel_v2_workspace_snapshot_real_content_exhausts_gap_without_moving_fences() {
    let w = world().await;
    let opened = call(&w, "get_workspace_snapshot", json!({"action":"open"}))
        .await
        .unwrap();
    for index in 0..513 {
        kernel::hq::observe_facet_as(
            &w.db,
            &w.admin,
            &w.first,
            &kernel::hq::FacetObservation {
                key: "churn".into(),
                value: Some(index.to_string()),
                value_num: None,
                vocab_ref: None,
                as_of: "2026-01-01T00:00:00Z".into(),
            },
            None,
        )
        .await
        .unwrap();
    }
    let page = call(
        &w,
        "get_workspace_snapshot",
        json!({"action":"page","snapshot_token":opened["snapshot_token"],"section":"records"}),
    )
    .await
    .unwrap();
    assert!(
        page["rows"].is_array(),
        "facet writes leave pinned pages unchanged"
    );
    let delta = call(
        &w,
        "get_workspace_snapshot",
        json!({"action":"catch_up","snapshot_token":opened["snapshot_token"]}),
    )
    .await
    .unwrap();
    assert_eq!(delta["reason"], "content_gap_outside_window");
}

#[tokio::test]
async fn kernel_v2_workspace_snapshot_relationship_and_unit_fences_are_distinct() {
    let w = world().await;
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    for (stream, event_type, expected) in [
        (
            "relationship_events",
            "relationship.asserted.v1",
            "relationship_seq_moved",
        ),
        ("content_events", "unit.created.v1", "unit_seq_moved"),
    ] {
        let opened = call(&w, "get_workspace_snapshot", json!({"action":"open"}))
            .await
            .unwrap();
        kernel::import_event_as(&w.db, &host, &w.first, &kernel::LegacyEvent {
            source: Some(json!({"origin":"synthetic-snapshot-fences","stream":stream,"metadata":{"record_id":w.first},"subjects":[w.first]})),
            id: uuid::Uuid::new_v4().to_string(), event_type: event_type.into(), payload: json!({}),
            created_at: "2026-01-01T00:00:00Z".into(), actor: None, run_key: None,
        }).await.unwrap();
        let page = call(
            &w,
            "get_workspace_snapshot",
            json!({"action":"page","snapshot_token":opened["snapshot_token"],"section":"records"}),
        )
        .await
        .unwrap();
        assert_eq!(page["reason"], expected);
    }
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn provider_link_write_predicates_do_not_require_prepared_read_indexes() {
    let w = world().await;
    install_comment_carrier(&w).await;
    let comment = call(&w, "create_record", json!({"type":"Annotation","kind":"comment","body":"Unprepared write proof","links":[{"target_id":w.first,"relationship":"part_of"}]})).await.unwrap()["id"].as_str().unwrap().to_owned();
    let destination = kernel::create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.admin, "manage")]),
        &w.admin,
    )
    .await
    .unwrap();
    sqlx::query("DROP INDEX idx_kernel_read_type; DROP INDEX idx_kernel_read_kind")
        .execute(w.db.write_pool())
        .await
        .unwrap();
    assert!(kernel::verify_v2_ready(&w.db).await.is_err());
    // Low-level kernel writers deliberately do not imply serving readiness.
    kernel::rehome_record_as(&w.db, &w.admin, &w.second, &destination)
        .await
        .unwrap();
    let err = kernel::rehome_record_as(&w.db, &w.admin, &w.first, &destination)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("requires the atomic member move"),
        "{err}"
    );
    let mut tx = crate::db::begin_write(w.db.write_pool()).await.unwrap();
    let mut acts = crate::act::ActAllocation::new();
    kernel::move_record_with_comments_in(
        &w.db,
        &mut tx,
        &mut acts,
        &w.admin,
        &w.first,
        &destination,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    for id in [&w.first, &comment] {
        assert_eq!(
            kernel::read_record_as(&w.db, &w.admin, id)
                .await
                .unwrap()
                .unwrap()
                .home_id,
            destination
        );
    }
    // The shared Message predicate must also compile without optional indexes.
    let homes = "SELECT root_id AS id,1 AS view FROM kernel_roots";
    let unhinted = kernel::messaging::sql_guard("r", "?1", homes, false);
    let query = format!("SELECT id FROM kernel_records r WHERE {unhinted} ORDER BY id");
    let expected: Vec<String> = sqlx::query_scalar(&query)
        .bind(&w.admin)
        .fetch_all(w.db.pool())
        .await
        .unwrap();
    call_as(
        &w,
        "acct:admin",
        "delete_record",
        json!({"id":w.first,"reason":"Unprepared delete proof"}),
    )
    .await
    .unwrap();
    assert!(kernel::read_record_as(&w.db, &w.admin, &comment)
        .await
        .unwrap()
        .is_none());
    kernel::prepare_v2_database(&w.db).await.unwrap();
    kernel::verify_v2_ready(&w.db).await.unwrap();
    let hinted = kernel::messaging::sql_guard("r", "?1", homes, true);
    let actual: Vec<String> = sqlx::query_scalar(&format!(
        "SELECT id FROM kernel_records r WHERE {hinted} ORDER BY id"
    ))
    .bind(&w.admin)
    .fetch_all(w.db.pool())
    .await
    .unwrap();
    // Message audience predicate is independent of the deletion lifecycle gate.
    assert_eq!(actual, expected);
}

#[tokio::test]
async fn kernel_v2_sql_metadata_pulse_matches_full_gate_and_rechecks_revocation() {
    let w = world().await;
    let home: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
        .bind(&w.first)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    // A real imported home names a separate logical filing record. Its
    // visibility is a dependency even outside the caller's ID list.
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let imported_home = kernel::v1_import_home_id(&w.second);
    kernel::import_home_as(
        &w.db,
        &host,
        &imported_home,
        &w.second,
        &home,
        &w.admin,
        None,
    )
    .await
    .unwrap();
    kernel::rehome_record_as(&w.db, &w.admin, &w.first, &imported_home)
        .await
        .unwrap();
    let args = json!({"sql":"SELECT id, updated_at FROM records WHERE id IN (?1,?2,?3,?4,?5,?6)",
        "parameters":[{"type":"text","value":w.first},{"type":"text","value":w.second},
            {"type":"text","value":w.hidden},{"type":"text","value":w.first},
            {"type":"text","value":null},{"type":"text","value":"missing'); SELECT 1;--"}]});
    // Same statement through the unrestricted staging oracle. Qualification
    // deliberately excludes it from the closed optimization.
    let mut full = args.clone();
    full["sql"] =
        json!("SELECT r.id, r.updated_at FROM records r WHERE r.id IN (?1,?2,?3,?4,?5,?6)");
    for phase in 0..3 {
        for who in ["acct:viewer", "acct:admin"] {
            let (narrow, stats) =
                super::sql::measured(call_as(&w, who, "query_sql", args.clone())).await;
            let narrow = narrow.unwrap();
            let oracle = call_as(&w, who, "query_sql", full.clone()).await.unwrap();
            assert_eq!(narrow["rows"], oracle["rows"]);
            assert_eq!(narrow["truncated"], oracle["truncated"]);
            assert!(stats.staged_records <= 3);
            let wide_sql = "SELECT id, type, kind, name, summary, home_id, lifecycle, maturity, updated_at, last_activity_at FROM records WHERE deleted_at IS NULL AND id IN (?1,?2,?3,?4,?5,?6)";
            let mut wide = args.clone();
            wide["sql"] = json!(wide_sql);
            let (wide_out, wide_stats) =
                super::sql::measured(call_as(&w, who, "query_sql", wide.clone())).await;
            let wide_out = wide_out.unwrap();
            wide["sql"] = json!(wide_sql.replace("FROM records WHERE", "FROM records AS r WHERE"));
            let wide_oracle = call_as(&w, who, "query_sql", wide).await.unwrap();
            assert_eq!(wide_out["rows"], wide_oracle["rows"]);
            assert!(wide_stats.staged_records <= 6, "{wide_stats:?}");
            let mut one = json!({"sql":wide_sql.replace("?1,?2,?3,?4,?5,?6", "?1"),
                "parameters":[{"type":"text","value":w.first}]});
            let one_out = call_as(&w, who, "query_sql", one.clone()).await.unwrap();
            one["sql"] = json!(one["sql"]
                .as_str()
                .unwrap()
                .replace("FROM records WHERE", "FROM records AS r WHERE"));
            let one_oracle = call_as(&w, who, "query_sql", one).await.unwrap();
            assert_eq!(one_out["rows"], one_oracle["rows"]);
            if phase == 0 && who == "acct:viewer" {
                assert_eq!(one_out["rows"][0]["home_id"], w.second);
            }
            if who == "acct:viewer" {
                assert!(!narrow["rows"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|r| r["id"] == w.hidden));
                if phase == 0 {
                    assert_eq!(narrow["row_count"], 2);
                }
                if phase == 2 {
                    assert_eq!(narrow["row_count"], 0);
                }
            }
        }
        if phase == 0 {
            // An unsealed Message remains hidden even when its home is visible.
            sqlx::query("UPDATE kernel_records SET primary_type='Message' WHERE id=?")
                .bind(&w.second)
                .execute(w.db.write_pool())
                .await
                .unwrap();
        } else if phase == 1 {
            // The imported home inherits this original policy anchor.
            kernel::replace_home_policy(&w.db, &w.admin, &home, &[])
                .await
                .unwrap();
        }
    }
    // Even record ownership cannot admit a caller removed from the roster.
    assert!(
        call_as(&w, "acct:admin", "query_sql", args.clone())
            .await
            .unwrap()["row_count"]
            .as_u64()
            .unwrap()
            > 0
    );
    for members in [vec!["acct:admin", "acct:viewer"], vec!["acct:viewer"]] {
        let actor = members[0].to_owned();
        kernel::hosted_identity::reconcile_hosted_caller(&w.db, |_| async move {
            // SAFETY: complete synthetic host-owned roster, no tool input.
            Ok(unsafe {
                kernel::hosted_identity::VerifiedHostedMembership::from_accounts_unchecked(
                    actor,
                    members.into_iter().map(str::to_owned).collect(),
                )
            })
        })
        .await
        .unwrap();
    }
    let offboarded_narrow = call_as(&w, "acct:admin", "query_sql", args)
        .await
        .unwrap_err();
    let offboarded_full = call_as(&w, "acct:admin", "query_sql", full)
        .await
        .unwrap_err();
    assert_eq!(offboarded_narrow.to_string(), offboarded_full.to_string());
    assert_eq!(
        offboarded_narrow.to_string(),
        "database membership not found"
    );
    w.db.close().await;
}

fn named_view_fixture_definition(sql: &str, labels: &[&str], dependencies: &[&str]) -> Value {
    use sha2::{Digest, Sha256};
    let columns: Vec<_> = labels.iter().map(|name| json!({"name":name,"type":if *name == "id" {"identifier"} else {"text"},"nullable":*name != "id"})).collect();
    let schema = format!(
        "{:x}",
        Sha256::digest(native_artifact_runtime::mdx_v2::canonical_json_bytes(
            &json!(columns)
        ))
    );
    let relations: serde_json::Map<_, _> = dependencies
        .iter()
        .map(|name| {
            let r = crate::query::sql_contract::LOGICAL_RELATIONS
                .iter()
                .find(|r| r.name == *name)
                .unwrap();
            (
                (*name).into(),
                json!({"identity":r.identity,"semantic_version":r.semantic_version}),
            )
        })
        .collect();
    let profile = crate::query::sql_contract::QuerySqlProfile::SqliteLocal.contract();
    json!({"v":"1.1","kind":"governed_sql","profile":{"id":profile.id,"revision":profile.revision},
        "catalog_revision":crate::query::sql_contract::LOGICAL_CATALOG_REVISION,"relations":relations,"sql":sql,"parameters":[],
        "output":{"columns":columns,"schema_sha256":schema,"row_identity":["id"],"order":[{"column":"id","direction":"asc"}]},"bounds":{"rows":1000}})
}

async fn named_view_save(w: &World, bearer: &str, definition: &Value) {
    kernel::observe_facet_as(
        &w.db,
        &w.admin,
        bearer,
        &kernel::FacetObservation {
            key: "query".into(),
            value: Some(definition.to_string()),
            value_num: None,
            vocab_ref: None,
            as_of: chrono::Utc::now().to_rfc3339(),
        },
        None,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn kernel_v2_named_views_select_join_visibility_and_cleanup() {
    let w = world().await;
    let body = "SELECT id,name FROM records WHERE type='Document'";
    let definition = named_view_fixture_definition(body, &["id", "name"], &["records"]);
    named_view_save(&w, &w.first, &definition).await;
    kernel::named_views::publish(&w.db, &w.admin, &w.first, "view_notes")
        .await
        .unwrap();
    named_view_save(&w, &w.second, &definition).await;
    kernel::named_views::publish(&w.db, &w.admin, &w.second, "view_other")
        .await
        .unwrap();
    for actor in [&w.viewer, &w.admin, &w.viewer] {
        for sql in [
            "SELECT id,name FROM view_notes ORDER BY id",
            "SELECT count(*) AS n FROM view_notes",
            "SELECT id,name FROM view_notes WHERE 0",
            "SELECT id,name FROM view_notes LIMIT 1",
            "SELECT v.id,v.name FROM view_notes v JOIN records r ON r.id=v.id ORDER BY v.id",
            "SELECT v.id,v.name FROM view_notes v JOIN view_other o ON o.id=v.id ORDER BY v.id",
        ] {
            let inline = sql
                .replace("view_notes", &format!("({body})"))
                .replace("view_other", &format!("({body})"));
            let (actual, stats) =
                super::sql::measured(super::sql::query_sql(&w.db, actor, json!({"sql":sql}))).await;
            let actual = actual.unwrap();
            assert_eq!(stats.uncached_caller_statements, 1);
            let expected = super::sql::query_sql(&w.db, actor, json!({"sql":inline}))
                .await
                .unwrap();
            assert_eq!(actual["rows"], expected["rows"], "{sql}");
            assert_eq!(actual["columns"], expected["columns"]);
            if actor == &w.viewer {
                assert!(!actual["rows"].to_string().contains(&w.hidden));
            }
        }
    }
    for sql in [
        "CREATE VIEW leaked AS SELECT * FROM view_notes",
        "SELECT * FROM main.kernel_records",
        "SELECT load_extension('x') FROM view_notes",
        "SELECT bad FROM view_notes",
    ] {
        assert!(
            super::sql::query_sql(&w.db, &w.viewer, json!({"sql":sql}))
                .await
                .is_err(),
            "{sql}"
        );
    }
    let slot = w.db.governed_pool().acquire().await.unwrap();
    let mut slot = slot;
    let leftovers: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM temp.sqlite_schema WHERE name NOT GLOB 'sqlite_*'",
    )
    .fetch_one(&mut *slot)
    .await
    .unwrap();
    assert_eq!(leftovers, 0);
    drop(slot);
    // A stale definition never replaces the admitted one implicitly.
    let changed = named_view_fixture_definition(
        "SELECT id,name FROM records WHERE name='Secret'",
        &["id", "name"],
        &["records"],
    );
    named_view_save(&w, &w.first, &changed).await;
    let error = super::sql::query_sql(&w.db, &w.viewer, json!({"sql":"SELECT * FROM view_notes"}))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("digest changed"), "{error}");
}

#[tokio::test]
async fn kernel_v2_named_views_private_bearer_and_admission_boundary() {
    let w = world().await;
    let definition = named_view_fixture_definition(
        "SELECT id,utc_date_label(created_at_ms) AS day FROM records",
        &["id", "day"],
        &["records"],
    );
    named_view_save(&w, &w.hidden, &definition).await;
    assert!(
        kernel::named_views::publish(&w.db, &w.viewer, &w.hidden, "view_private")
            .await
            .is_err()
    );
    kernel::named_views::publish(&w.db, &w.admin, &w.hidden, "view_private")
        .await
        .unwrap();
    let error = super::sql::query_sql(
        &w.db,
        &w.viewer,
        json!({"sql":"SELECT * FROM view_private"}),
    )
    .await
    .unwrap_err();
    assert!(!error.to_string().contains("Secret"));
    assert!(
        super::sql::query_sql(&w.db, &w.admin, json!({"sql":"SELECT * FROM view_private"}))
            .await
            .is_ok()
    );
    let view = super::sql::query_sql(
        &w.db,
        &w.admin,
        json!({"sql":"SELECT id,day FROM view_private ORDER BY id"}),
    )
    .await
    .unwrap();
    let inline = super::sql::query_sql(
        &w.db,
        &w.admin,
        json!({"sql":"SELECT id,utc_date_label(created_at_ms) AS day FROM records ORDER BY id"}),
    )
    .await
    .unwrap();
    assert_eq!(view["rows"], inline["rows"]);
    let spec = crate::store::AppendSpec {
        record_id: w.first.clone(),
        event_type: kernel::named_views::EVENT.into(),
        payload: json!({}),
        actor: Some(w.admin.clone()),
    };
    let error = crate::store::append(&w.db, spec).await.unwrap_err();
    assert!(error.to_string().contains("engine-owned"), "{error}");
    assert!(kernel::observe_facet_as(
        &w.db,
        &w.admin,
        &w.first,
        &kernel::FacetObservation {
            key: "named_view".into(),
            value: Some("{}".into()),
            value_num: None,
            vocab_ref: None,
            as_of: chrono::Utc::now().to_rfc3339(),
        },
        None
    )
    .await
    .is_err());
}

#[tokio::test]
async fn kernel_v2_named_views_catalog_is_visible_verified_and_hosted_only() {
    let w = world().await;
    let definition =
        named_view_fixture_definition("SELECT id,name FROM records", &["id", "name"], &["records"]);
    named_view_save(&w, &w.first, &definition).await;
    named_view_save(&w, &w.hidden, &definition).await;
    kernel::named_views::publish(&w.db, &w.admin, &w.first, "view_visible")
        .await
        .unwrap();
    kernel::named_views::publish(&w.db, &w.admin, &w.hidden, "view_hidden")
        .await
        .unwrap();
    let out = super::sql::query_sql(&w.db, &w.viewer, json!({"sql":"SELECT relation_name,identity,caller_relative,profiles,comment FROM catalog_relations WHERE substr(relation_name,1,5)='view_' ORDER BY relation_name"})).await.unwrap();
    // Slice 1 carriers fold for compatibility, but retained discovery does
    // not reconstruct immutable revisions from present-day facets.
    assert_eq!(out["row_count"], 0);
    assert_eq!(out["notices"][0]["code"], "view_catalog_incomplete");
    let out = super::sql::query_sql(&w.db, &w.viewer, json!({"sql":"SELECT column_name,column_position FROM catalog_columns WHERE relation_name='view_visible' ORDER BY column_position"})).await.unwrap();
    assert_eq!(out["rows"], json!([]));
    assert_eq!(out["notices"][0]["code"], "view_catalog_incomplete");
    let static_rows = super::sql::query_sql(
        &w.db,
        &w.viewer,
        json!({"sql":"SELECT relation_name FROM catalog_relations WHERE relation_name='records'"}),
    )
    .await
    .unwrap();
    assert_eq!(static_rows["row_count"], 1);
    // A v2 standby shares this handler but must never load copied bindings.
    let offline =
        crate::db::open_kernel_v2_standby_read_only(w._dir.path().join("v2.db").to_str().unwrap())
            .await
            .unwrap();
    let (catalog, stats) = super::sql::measured(super::sql::query_sql(&offline, &w.viewer,
        json!({"sql":"SELECT relation_name FROM catalog_relations WHERE substr(relation_name,1,5)='view_'"}))).await;
    assert_eq!(catalog.unwrap()["row_count"], 0);
    assert_eq!(stats.named_registry_loads, 0);
    assert!(super::sql::query_sql(
        &offline,
        &w.viewer,
        json!({"sql":"SELECT * FROM view_visible"})
    )
    .await
    .is_err());
    offline.close().await;
    // Shared portable/v1/member schemas never gain the hosted registry.
    assert!(crate::query::sql::validate("SELECT * FROM view_visible").is_err());
    assert!(!crate::query::sql_contract::LOGICAL_RELATIONS
        .iter()
        .any(|r| r.name.starts_with("view_")));
    assert!(!crate::mcp::member_scope::QUERY_SQL_SERVED_RELATIONS
        .iter()
        .any(|r| r.starts_with("view_")));
    let changed = named_view_fixture_definition(
        "SELECT id,name FROM records WHERE 0",
        &["id", "name"],
        &["records"],
    );
    named_view_save(&w, &w.first, &changed).await;
    let out = super::sql::query_sql(&w.db, &w.viewer, json!({"sql":"SELECT relation_name FROM catalog_relations WHERE substr(relation_name,1,5)='view_'"})).await.unwrap();
    assert_eq!(out["row_count"], 0);
}

#[tokio::test]
async fn kernel_v2_named_views_ship_dark_and_skip_registry_for_static_reads() {
    let w = world().await;
    let args = json!({"sql":"SELECT id FROM records ORDER BY id LIMIT 1"});
    let (baseline, before) =
        super::sql::measured(super::sql::query_sql(&w.db, &w.viewer, args.clone())).await;
    let baseline = baseline.unwrap();
    assert_eq!(before.named_registry_loads, 0);
    let catalogs = json!({"sql":"SELECT relation_name,column_name,column_position FROM catalog_columns ORDER BY relation_name,column_position"});
    let catalog_before = super::sql::query_sql(&w.db, &w.viewer, catalogs.clone())
        .await
        .unwrap();
    let definition =
        named_view_fixture_definition("SELECT id,name FROM records", &["id", "name"], &["records"]);
    named_view_save(&w, &w.first, &definition).await;
    // Saving SQL alone has no discovery or execution effect.
    let catalog_after = super::sql::query_sql(&w.db, &w.viewer, catalogs)
        .await
        .unwrap();
    assert_eq!(catalog_before["rows"], catalog_after["rows"]);
    assert!(
        super::sql::query_sql(&w.db, &w.viewer, json!({"sql":"SELECT * FROM view_notes"}))
            .await
            .is_err()
    );
    for published in [false, true] {
        if published {
            kernel::named_views::publish(&w.db, &w.admin, &w.first, "view_notes")
                .await
                .unwrap();
        }
        let (result, after) =
            super::sql::measured(super::sql::query_sql(&w.db, &w.viewer, args.clone())).await;
        let result = result.unwrap();
        assert_eq!(result["rows"], baseline["rows"]);
        assert_eq!(result["columns"], baseline["columns"]);
        assert_eq!(after.named_registry_loads, 0);
        assert_eq!(after.uncached_caller_statements, 0);
        assert_eq!(after.staged_records, before.staged_records);
        assert_eq!(after.installations, before.installations);
        assert_eq!(after.staged_relations, before.staged_relations);
        assert!(
            after.staged_records <= 1,
            "id-prefix narrowing retained: {after:?}"
        );
    }
    assert!(registry().get("admit_named_view").is_none());
}

#[tokio::test]
async fn kernel_v2_named_views_admission_negatives_collisions_and_cap() {
    let w = world().await;
    for (sql, labels, deps) in [
        (
            "SELECT id,name FROM main.records",
            vec!["id", "name"],
            vec!["records"],
        ),
        (
            "SELECT r.id,b.url AS name FROM records r JOIN bindings b ON b.record_id=r.id",
            vec!["id", "name"],
            vec!["records", "bindings"],
        ),
        (
            "SELECT id,name FROM view_other",
            vec!["id", "name"],
            vec!["records"],
        ),
        (
            "SELECT id,load_extension('x') AS name FROM records",
            vec!["id", "name"],
            vec!["records"],
        ),
        (
            "SELECT id,now_ms() AS name FROM records",
            vec!["id", "name"],
            vec!["records"],
        ),
        (
            "SELECT id,name FROM records; SELECT 1",
            vec!["id", "name"],
            vec!["records"],
        ),
        (
            "SELECT relation_name AS id,comment AS name FROM catalog_relations",
            vec!["id", "name"],
            vec!["catalog_relations"],
        ),
    ] {
        let definition: crate::mcp::tools::querying::SavedSqlDefinition =
            serde_json::from_value(named_view_fixture_definition(sql, &labels, &deps)).unwrap();
        assert!(
            kernel::named_views::validate_definition(&definition).is_err(),
            "{sql}"
        );
    }
    let definition =
        named_view_fixture_definition("SELECT id,name FROM records", &["id", "name"], &["records"]);
    for changed in [
        {
            let mut d = definition.clone();
            d["sql"] = json!("SELECT id,name FROM records WHERE id=?1");
            d["parameters"] = json!([{"type":"text","value":"x"}]);
            d
        },
        {
            let mut d = definition.clone();
            d["output"]["schema_sha256"] = json!("bad digest");
            d
        },
        {
            let mut d = definition.clone();
            d["sql"] = json!("x".repeat(crate::query::sql_contract::MAX_SQL_BYTES + 1));
            d
        },
    ] {
        let changed = serde_json::from_value(changed).unwrap();
        assert!(kernel::named_views::validate_definition(&changed).is_err());
    }
    named_view_save(&w, &w.first, &definition).await;
    assert!(
        kernel::named_views::publish(&w.db, &w.viewer, &w.first, "view_notes")
            .await
            .is_err()
    );
    kernel::named_views::publish(&w.db, &w.admin, &w.first, "view_notes")
        .await
        .unwrap();
    named_view_save(&w, &w.second, &definition).await;
    for name in [
        "view_notes",
        "VIEW_NOTES",
        "records",
        "view_other;DROP TABLE records",
    ] {
        assert!(
            kernel::named_views::publish(&w.db, &w.admin, &w.second, name)
                .await
                .is_err(),
            "{name}"
        );
    }
    let home = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    for i in 1..=8 {
        let bearer = kernel::create_as(
            &w.db,
            &w.admin,
            "fixture.mcp",
            "note",
            json!({"title":format!("View bearer {i}")})
                .as_object()
                .unwrap(),
            &home,
        )
        .await
        .unwrap();
        named_view_save(&w, &bearer, &definition).await;
        let result =
            kernel::named_views::publish(&w.db, &w.admin, &bearer, &format!("view_fixture_{i}"))
                .await;
        assert_eq!(result.is_ok(), i < 8, "binding {i}: {result:?}");
    }
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM kernel_facets WHERE key='named_view'")
            .fetch_one(w.db.pool())
            .await
            .unwrap();
    assert_eq!(count, 8);
}

#[tokio::test]
async fn kernel_v2_named_views_snapshot_revocation_timeout_and_cancellation() {
    use std::sync::Arc;
    use tokio::sync::Barrier;
    let w = world().await;
    let definition = named_view_fixture_definition(
        "SELECT id,name,archived FROM records WHERE type='Document'",
        &["id", "name", "archived"],
        &["records"],
    );
    named_view_save(&w, &w.first, &definition).await;
    kernel::named_views::publish(&w.db, &w.admin, &w.first, "view_notes")
        .await
        .unwrap();
    let arrived = Arc::new(Barrier::new(2));
    let resume = Arc::new(Barrier::new(2));
    let db = w.db.clone();
    let actor = w.viewer.clone();
    let task = tokio::spawn(super::sql::with_named_read_pause(
        arrived.clone(),
        resume.clone(),
        async move {
            super::sql::query_sql(
                &db,
                &actor,
                json!({"sql":"SELECT id,name,archived FROM view_notes ORDER BY id"}),
            )
            .await
        },
    ));
    tokio::time::timeout(std::time::Duration::from_secs(10), arrived.wait())
        .await
        .expect("named read reached pre-staging registry pause");
    let changed = named_view_fixture_definition(
        "SELECT id,name,archived FROM records WHERE 0",
        &["id", "name", "archived"],
        &["records"],
    );
    named_view_save(&w, &w.first, &changed).await;
    let source = kernel::read_record_as(&w.db, &w.admin, &w.second)
        .await
        .unwrap()
        .unwrap();
    kernel::set_archived_as(&w.db, &w.admin, &w.second, true, source.revision)
        .await
        .unwrap();

    resume.wait().await;
    let old = task.await.unwrap().unwrap();
    assert_eq!(
        old["row_count"], 2,
        "read must retain its old definition and source snapshot"
    );
    let old_source = old["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == w.second)
        .unwrap();
    assert_eq!(old_source["name"], "Beta");
    assert_eq!(
        old_source["archived"], 0,
        "staging must use the pinned source snapshot"
    );
    let current = super::sql::query_sql(&w.db, &w.viewer,
        json!({"sql":"SELECT archived FROM records WHERE id=?1", "parameters":[{"type":"text","value":w.second}]})).await.unwrap();
    assert_eq!(current["rows"][0]["archived"], 1);
    assert!(
        super::sql::query_sql(&w.db, &w.viewer, json!({"sql":"SELECT * FROM view_notes"}))
            .await
            .unwrap_err()
            .to_string()
            .contains("digest changed")
    );
    named_view_save(&w, &w.first, &definition).await;
    let error = super::sql::with_elapsed(
        std::time::Duration::ZERO,
        std::time::Duration::from_secs(3),
        super::sql::query_sql(&w.db, &w.viewer, json!({"sql":"SELECT count(*) AS n FROM view_notes a CROSS JOIN records b CROSS JOIN records c CROSS JOIN records d CROSS JOIN records e CROSS JOIN records f CROSS JOIN records g CROSS JOIN records h CROSS JOIN records i CROSS JOIN records j"})),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("timeout"), "{error}");
    let arrived = Arc::new(Barrier::new(2));
    let resume = Arc::new(Barrier::new(2));
    let db = w.db.clone();
    let actor = w.admin.clone();
    let task = tokio::spawn(super::sql::with_named_read_pause(
        arrived.clone(),
        resume,
        async move {
            super::sql::query_sql(&db, &actor, json!({"sql":"SELECT * FROM view_notes"})).await
        },
    ));
    tokio::time::timeout(std::time::Duration::from_secs(10), arrived.wait())
        .await
        .expect("named read reached pre-staging registry pause");
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    // Inspect every possible pooled physical connection, including reuse after
    // the error and cancelled admin read, before another caller borrows it.
    let mut slots = Vec::new();
    for _ in 0..w.db.governed_pool().options().get_max_connections() {
        let mut slot = w.db.governed_pool().acquire().await.unwrap();
        let leftovers: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM temp.sqlite_schema WHERE name NOT GLOB 'sqlite_*'",
        )
        .fetch_one(&mut *slot)
        .await
        .unwrap();
        assert_eq!(leftovers, 0);
        let query_only: bool = sqlx::query_scalar("PRAGMA query_only")
            .fetch_one(&mut *slot)
            .await
            .unwrap();
        assert!(!query_only);
        slots.push(slot);
    }
    drop(slots);
    // A new read after cancellation must rebuild its own staging/definition.
    let out = super::sql::query_sql(
        &w.db,
        &w.viewer,
        json!({"sql":"SELECT count(*) AS n FROM view_notes"}),
    )
    .await
    .unwrap();
    assert_eq!(out["rows"][0]["n"], 2);
    let home = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    kernel::replace_home_policy(&w.db, &w.admin, &home, &[])
        .await
        .unwrap();
    assert!(
        super::sql::query_sql(&w.db, &w.viewer, json!({"sql":"SELECT * FROM view_notes"}))
            .await
            .is_err()
    );
    let out = super::sql::query_sql(&w.db, &w.viewer, json!({"sql":"SELECT relation_name FROM catalog_relations WHERE relation_name='view_notes'"})).await.unwrap();
    assert_eq!(out["row_count"], 0);
}

/// Synthetic HQ-sized staging evidence. Direct bulk fixture inserts avoid
/// measuring the canonical write API rather than the read path under study.
#[tokio::test]
#[ignore = "Manual HQ-sized staging and catalog cost measurement; see named-views-slice1-design.md"]
async fn kernel_v2_named_views_measure_hq_sized_staging() {
    let work = async {
        if std::env::var_os("NATIVE_MEASURE_SQL").is_some() {
            let _ = tracing_subscriber::fmt()
                .with_max_level(tracing::Level::DEBUG)
                .with_ansi(false)
                .try_init();
        }
        let w = world().await;
        // Deliberately model an older, unprepared file despite normal creation.
        sqlx::query("DROP INDEX idx_kernel_named_view_lifecycle")
            .execute(w.db.write_pool())
            .await
            .unwrap();
        sqlx::query("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<3000) INSERT INTO kernel_records(id,home_id,owner_id,primary_type,kind,accession,pin_family,pin_version,pin_digest,interpreter,created_seq,created_at) SELECT printf('measure:%05d',x),r.home_id,r.owner_id,'WorkItem','task',printf('measure-accession:%05d',x),r.pin_family,r.pin_version,r.pin_digest,r.interpreter,r.created_seq,r.created_at FROM n CROSS JOIN kernel_records r WHERE r.id=?")
        .bind(&w.first).execute(w.db.write_pool()).await.unwrap();
        sqlx::query("INSERT INTO kernel_record_fields(record_id,name,value_json,created_seq) SELECT r.id,'title',json_quote(r.id),r.created_seq FROM kernel_records r WHERE r.id LIKE 'measure:%'")
        .execute(w.db.write_pool()).await.unwrap();
        sqlx::query("WITH RECURSIVE k(x) AS (VALUES(0) UNION ALL SELECT x+1 FROM k WHERE x<7) INSERT INTO kernel_facets(record_id,key,value,as_of,event_seq) SELECT r.id,printf('measure_key_%03d',(CAST(substr(r.id,9) AS INTEGER)*8+x)%701),'value','2026-10-24T00:00:00Z',r.created_seq FROM kernel_records r CROSS JOIN k WHERE r.id LIKE 'measure:%'")
        .execute(w.db.write_pool()).await.unwrap();
        sqlx::query("INSERT INTO kernel_generic_links(link_id,source_id,target_id,relationship,created_at,active,event_seq,imported) SELECT 'edge:'||r.id,r.id,?,'related','2026-10-24T00:00:00Z',1,r.created_seq,0 FROM kernel_records r WHERE r.id LIKE 'measure:%'")
        .bind(&w.second).execute(w.db.write_pool()).await.unwrap();
        let key_count: i64 = sqlx::query_scalar("SELECT count(DISTINCT key) FROM kernel_facets")
            .fetch_one(w.db.pool())
            .await
            .unwrap();
        assert!(key_count >= 701);
        // Deliberately synthetic uninterpreted headers measure fallback cost;
        // no replay or producer qualification is inferred from this bulk fixture.
        sqlx::query("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<65000) INSERT INTO content_events(id,record_id,type,payload,created_at,causal_envelope_version,causal_status) SELECT printf('measure-log:%05d',x),?,'fixture','{}','2026-10-25',1,'legacy_unknown' FROM n").bind(&w.first).execute(w.db.write_pool()).await.unwrap();
        eprintln!("NAMED_VIEW_HISTORY index=absent unrelated_headers=65000");
        named_view_measure_catalog(&w, 0).await;
        let prep_registry = registry();
        prep_registry
            .call_engine(
                EngineHandle::KernelV2(w.db.clone()),
                Caller::authenticated("acct:admin"),
                "manage_named_views",
                json!({"action":"prepare_named_views"}),
            )
            .await
            .unwrap();
        eprintln!("NAMED_VIEW_HISTORY index=present unrelated_headers=65000 bindings=0");
        named_view_measure_catalog(&w, 0).await;
        let body = "SELECT r.id,r.name,f.value AS facet_value,l.target_id AS linked_id FROM records r JOIN facet_values f ON f.record_id=r.id AND f.key='measure_key_000' JOIN links l ON l.source_id=r.id WHERE r.type='WorkItem'";
        let definition = named_view_fixture_definition(
            body,
            &["id", "name", "facet_value", "linked_id"],
            &["records", "facet_values", "links"],
        );
        let mut query = serde_json::to_value(&definition).unwrap();
        query["v"] = json!("1.2");
        let meanings:serde_json::Map<String,Value>=definition["output"]["columns"].as_array().unwrap().iter().map(|c|(c["name"].as_str().unwrap().to_owned(),json!({"meaning":format!("Synthetic measurement field {}",c["name"].as_str().unwrap()),"source_mapping":"fixture SELECT expression","vocabulary":null,"unit":null,"encoding":null}))).collect();
        let retained = json!({"query":query,"origin":{"kind":"authored"},"description":"HQ-sized synthetic records, facets and links","scope":{"description":"Caller-visible task rows with fixture facet and link","cardinality":"one row per fixture facet and related link","default_inclusion":"matching caller-visible tasks"},"columns":meanings,"source_pins":[]});
        let home = kernel::read_record_as(&w.db, &w.admin, &w.first)
            .await
            .unwrap()
            .unwrap()
            .home_id;
        for i in 0..8 {
            let bearer = if i == 0 {
                w.first.clone()
            } else {
                kernel::create_as(
                    &w.db,
                    &w.admin,
                    "fixture.mcp",
                    "note",
                    json!({"title":format!("Measure view {i}")})
                        .as_object()
                        .unwrap(),
                    &home,
                )
                .await
                .unwrap()
            };
            // Bulk setup measures reads, not mutation admission over this
            // deliberately uninterpreted history. Producer paths are covered
            // separately by the operation/executor fixtures.
            use crate::named_views::{Action, Pin, Revision, Transition, REVISION, TRANSITION};
            let definition: crate::named_views::contract::Definition =
                serde_json::from_value(retained.clone()).unwrap();
            let mut revision = Revision {
                v: 1,
                view_id: format!("native.named-view:{bearer}"),
                definition_sha256: String::new(),
                definition: serde_json::to_value(&definition).unwrap(),
            };
            revision.definition_sha256 = revision.digest();
            let revision_id = uuid::Uuid::new_v4().to_string();
            let binding = Transition {
                v: 1,
                view_id: revision.view_id.clone(),
                expected: None,
                action: Action::Activate {
                    name: if i == 0 {
                        "view_measure".into()
                    } else {
                        format!("view_measure_{i}")
                    },
                    pin: Pin {
                        view_id: revision.view_id.clone(),
                        revision_id: revision_id.clone(),
                        definition_sha256: revision.definition_sha256.clone(),
                        schema_sha256: definition.query.output.schema_sha256.clone(),
                    },
                },
            };
            for (event_id, kind, payload) in [
                (
                    revision_id,
                    REVISION,
                    serde_json::to_value(revision).unwrap(),
                ),
                (
                    uuid::Uuid::new_v4().to_string(),
                    TRANSITION,
                    serde_json::to_value(binding).unwrap(),
                ),
            ] {
                sqlx::query("INSERT INTO content_events(id,record_id,type,payload,created_at,causal_envelope_version,causal_status) VALUES(?,?,?,?,?,1,'legacy_unknown')")
                    .bind(event_id).bind(&bearer).bind(kind).bind(payload.to_string()).bind("2026-10-25")
                    .execute(w.db.write_pool()).await.unwrap();
            }
        }
        // Drop only for the read-fallback measurement under study.
        sqlx::query("DROP INDEX idx_kernel_named_view_lifecycle")
            .execute(w.db.write_pool())
            .await
            .unwrap();
        crate::query::sql::view_validation::clear_cache();
        eprintln!("NAMED_VIEW_HISTORY index=absent unrelated_headers=65000 bindings=8 cache=cold_then_warm");
        // Continuity omits dynamic rows until the accelerator is available.
        named_view_measure_catalog(&w, 0).await;
        prep_registry
            .call_engine(
                EngineHandle::KernelV2(w.db.clone()),
                Caller::authenticated("acct:admin"),
                "manage_named_views",
                json!({"action":"prepare_named_views"}),
            )
            .await
            .unwrap();
        eprintln!("NAMED_VIEW_HISTORY index=present unrelated_headers=65000 bindings=8 cache=cold_then_warm");
        named_view_measure_catalog(&w, 8).await;
        for iteration in 0..4 {
            let mut results = Vec::new();
            for (label, sql) in [
                ("inline", format!("SELECT * FROM ({body}) ORDER BY id")),
                ("view", "SELECT * FROM view_measure ORDER BY id".into()),
            ] {
                let started = std::time::Instant::now();
                let (result, stats) = super::sql::measured(super::sql::query_sql(
                    &w.db,
                    &w.viewer,
                    json!({"sql":sql}),
                ))
                .await;
                let total_us = started.elapsed().as_micros();
                eprintln!("NAMED_VIEW_SCALE iteration={iteration} path={label} records=3000 facets=24000 keys=701 links=3000 staging_us={} total_us={total_us} staged_records={} result={}", stats.staging_us, stats.staged_records, if result.is_ok() {"ok"} else {"error"});
                let result = result.expect(
                "HQ-sized named view must fit the unchanged two-second budget; STOP if this fails",
            );
                results.push(result["rows"].clone());
            }
            assert_eq!(results[0], results[1]);
        }
        // Replace an existing binding at the eight-view cap, then cycle the
        // same bearer through draft, activation and removal using real writes.
        named_view_measure_writes(&w, retained).await;
    };
    crate::named_views::gate::testing(true, work).await;
}

async fn named_view_measure_writes(w: &World, definition: Value) {
    let registry = registry();
    let mut conn = w.db.pool().acquire().await.unwrap();
    assert!(crate::named_views::storage::verify_index_on(&mut conn)
        .await
        .unwrap());
    let head: i64 = sqlx::query_scalar("SELECT max(seq) FROM content_events")
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    assert!(head > 65_000);
    let state = crate::named_views::load_prefix(&mut conn, head, None)
        .await
        .unwrap();
    let (view, binding) = state
        .bindings
        .iter()
        .find(|(_, b)| {
            b.active
                .as_ref()
                .is_some_and(|(name, _)| name == "view_measure_7")
        })
        .unwrap();
    let id = view.strip_prefix("native.named-view:").unwrap().to_owned();
    let mut previous = binding.event_id.clone();
    drop(conn);
    let plan_caller = |action: &str| {
        Caller::authenticated("acct:admin")
            .with_hosting_context("admin", "workspace")
            .with_hosting_owner(true)
            .with_write_plan_execution(crate::mcp::registry::WritePlanExecution {
                plan_id: "measurement".into(),
                effect_digest: "measurement".into(),
                executor: "records_write".into(),
                operation: action.into(),
            })
    };
    // All calls below use registered source handlers and their unchanged
    // absolute deadline. A trusted fixture plan marker isolates source latency
    // from the separate prepare/confirm protocol already covered elsewhere.
    for iteration in 0..4 {
        let started = std::time::Instant::now();
        let draft = registry
            .call_engine(
                EngineHandle::KernelV2(w.db.clone()),
                Caller::authenticated("acct:admin"),
                "manage_named_views",
                json!({"action":"record_view_revision","id":id,"definition":definition,
                "idempotency_key":format!("measure-draft-{iteration}")}),
            )
            .await;
        eprintln!("NAMED_VIEW_WRITE iteration={iteration} operation=record_view_revision total_us={} result={}",
            started.elapsed().as_micros(), if draft.is_ok() { "ok" } else { "error" });
        let draft = draft.expect("indexed HQ revision admission must fit the unchanged two-second budget; STOP on failure");
        let started = std::time::Instant::now();
        let active = registry.call_engine(EngineHandle::KernelV2(w.db.clone()),
            plan_caller("activate_view"), "manage_named_views",
            json!({"action":"activate_view","id":id,"pin":draft["pin"],"name":"view_measure_7",
                "expected_binding_event_id":previous,"idempotency_key":format!("measure-activate-{iteration}")})).await;
        eprintln!(
            "NAMED_VIEW_WRITE iteration={iteration} operation=activate_view total_us={} result={}",
            started.elapsed().as_micros(),
            if active.is_ok() { "ok" } else { "error" }
        );
        let active = active.expect(
            "indexed HQ activation must fit the unchanged two-second budget; STOP on failure",
        );
        let started = std::time::Instant::now();
        let inactive = registry.call_engine(EngineHandle::KernelV2(w.db.clone()),
            plan_caller("unpublish_view"), "manage_named_views",
            json!({"action":"unpublish_view","id":id,"expected_binding_event_id":active["event_id"],
                "idempotency_key":format!("measure-unpublish-{iteration}")})).await;
        eprintln!(
            "NAMED_VIEW_WRITE iteration={iteration} operation=unpublish_view total_us={} result={}",
            started.elapsed().as_micros(),
            if inactive.is_ok() { "ok" } else { "error" }
        );
        let inactive = inactive.expect(
            "indexed HQ unpublish must fit the unchanged two-second budget; STOP on failure",
        );
        previous = inactive["event_id"].as_str().unwrap().into();
    }
}

async fn named_view_measure_catalog(w: &World, bindings: usize) {
    for iteration in 0..4 {
        for relation in ["catalog_relations", "catalog_columns"] {
            let started = std::time::Instant::now();
            let ((out, stats), scanned) = crate::named_views::storage::measured_fallback(
                super::sql::measured(super::sql::query_sql(
                    &w.db,
                    &w.viewer,
                    json!({"sql":format!("SELECT * FROM {relation} ORDER BY relation_name")}),
                )),
            )
            .await;
            assert_eq!(scanned, 0, "catalog reads never scan event history");
            let total_us = started.elapsed().as_micros();
            let out = out.expect("HQ-sized catalog must fit the unchanged two-second budget");
            let dynamic = out["rows"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|r| r["relation_name"].as_str().unwrap().starts_with("view_"))
                .count();
            assert_eq!(
                dynamic,
                bindings * if relation == "catalog_columns" { 4 } else { 1 }
            );
            assert_eq!(stats.named_registry_loads, 1);
            eprintln!("NAMED_VIEW_CATALOG iteration={iteration} visible_bindings={bindings} relation={relation} staging_us={} total_us={total_us}", stats.staging_us);
        }
    }
}

#[tokio::test]
async fn kernel_v2_named_views_discovery_index_preparation_and_rebuild() {
    async fn plan(db: &Db) -> Vec<(i64, i64, i64, String)> {
        use sqlx::Connection;
        // EXPLAIN may retain a pooled connection's pre-DDL schema cache even
        // without a cached statement. Inspect each schema on a fresh handle.
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(db.path())
            .read_only(true)
            .create_if_missing(false);
        let mut connection = sqlx::SqliteConnection::connect_with(&options)
            .await
            .unwrap();
        let plan = sqlx::query_as(&format!(
            "EXPLAIN QUERY PLAN {}",
            kernel::named_views::DISCOVER_SQL
        ))
        .persistent(false)
        .fetch_all(&mut connection)
        .await
        .unwrap();
        connection.close().await.unwrap();
        plan
    }
    let w = world().await;
    let definition =
        named_view_fixture_definition("SELECT id,name FROM records", &["id", "name"], &["records"]);
    named_view_save(&w, &w.first, &definition).await;
    kernel::named_views::publish(&w.db, &w.admin, &w.first, "view_rebuilt")
        .await
        .unwrap();
    let indexed = plan(&w.db).await;
    assert!(
        indexed
            .iter()
            .any(|p| p.3.contains("idx_kernel_named_view_admissions")),
        "{indexed:?}"
    );
    let queries = [
        "SELECT id,name FROM view_rebuilt ORDER BY id",
        "SELECT relation_name FROM catalog_relations WHERE relation_name='view_rebuilt'",
        "SELECT column_name,column_position FROM catalog_columns WHERE relation_name='view_rebuilt' ORDER BY column_position",
    ];
    let mut expected = Vec::new();
    for sql in queries {
        expected.push(
            super::sql::query_sql(&w.db, &w.viewer, json!({"sql":sql}))
                .await
                .unwrap()["rows"]
                .clone(),
        );
    }
    sqlx::query("DROP INDEX idx_kernel_named_view_admissions")
        .execute(w.db.write_pool())
        .await
        .unwrap();
    let unindexed = plan(&w.db).await;
    assert!(
        !unindexed
            .iter()
            .any(|p| p.3.contains("idx_kernel_named_view_admissions")),
        "{unindexed:?}"
    );
    assert!(
        unindexed
            .iter()
            .any(|p| p.3.contains("SCAN main.content_events")),
        "{unindexed:?}"
    );
    let schema: i64 = sqlx::query_scalar("PRAGMA schema_version")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    kernel::verify_v2_ready(&w.db).await.unwrap();
    let path = w._dir.path().join("v2.db");
    // Both hosted/local writable openers must admit older files without repair.
    for reopened in [
        kernel::open_v2_database(path.to_str().unwrap())
            .await
            .unwrap(),
        kernel::open_marked_v2_database(path.to_str().unwrap())
            .await
            .unwrap(),
    ] {
        for (sql, rows) in queries.iter().zip(&expected) {
            let out = super::sql::query_sql(&reopened, &w.viewer, json!({"sql":sql}))
                .await
                .unwrap();
            assert_eq!(&out["rows"], rows, "{sql}");
        }
        reopened.close().await;
    }
    // Read-only node/member admission also stays compatible. Its static SQL
    // contract continues to omit/refuse named views, even with a copied binding.
    let readonly = crate::db::open_marked_v2_database_read_only_at(&path)
        .await
        .unwrap();
    let out = super::sql::query_sql(
        &readonly,
        &w.viewer,
        json!({"sql":"SELECT id,name FROM records ORDER BY id"}),
    )
    .await
    .unwrap();
    assert_eq!(out["rows"], expected[0]);
    for relation in ["catalog_relations", "catalog_columns"] {
        let out = super::sql::query_sql(&readonly, &w.viewer,
            json!({"sql":format!("SELECT relation_name FROM {relation} WHERE relation_name='view_rebuilt'")})).await.unwrap();
        assert_eq!(out["row_count"], 0);
    }
    assert!(
        super::sql::query_sql(&readonly, &w.viewer, json!({"sql":queries[0]}))
            .await
            .is_err()
    );
    readonly.close().await;
    let after: i64 = sqlx::query_scalar("PRAGMA schema_version")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    assert_eq!(
        schema, after,
        "opens and reads must not create the optional index"
    );
    kernel::prepare_v2_database(&w.db).await.unwrap();
    assert!(plan(&w.db)
        .await
        .iter()
        .any(|p| p.3.contains("idx_kernel_named_view_admissions")));
    let prepared: i64 = sqlx::query_scalar("PRAGMA schema_version")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    kernel::prepare_v2_database(&w.db).await.unwrap();
    let repeated: i64 = sqlx::query_scalar("PRAGMA schema_version")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    assert_eq!(prepared, repeated);
    kernel::replay_all_projections(&w.db).await.unwrap();
    let out = super::sql::query_sql(&w.db, &w.viewer, json!({"sql":queries[1]}))
        .await
        .unwrap();
    assert_eq!(out["rows"], expected[1]);
}

#[tokio::test]
async fn kernel_v2_named_views_historic_facet_rebuild_is_not_publication() {
    let w = world().await;
    let observation = kernel::FacetObservation {
        key: "named_view".into(),
        value: Some(
            json!({"v":1,"name":"view_impostor","definition_sha256":"unused","origin":"authored"})
                .to_string(),
        ),
        value_num: None,
        vocab_ref: None,
        as_of: chrono::Utc::now().to_rfc3339(),
    };
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    kernel::hq::import_event_with_facet_as(
        &w.db,
        &host,
        &w.first,
        &kernel::LegacyEvent {
            id: "historic-user-named-view".into(),
            event_type: "facet.set".into(),
            payload: json!({"key":"named_view","value":observation.value}),
            created_at: observation.as_of.clone(),
            actor: None,
            run_key: None,
            source: None,
        },
        Some(&observation),
    )
    .await
    .unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    let stored: String = sqlx::query_scalar(
        "SELECT value FROM kernel_facets WHERE record_id=? AND key='named_view'",
    )
    .bind(&w.first)
    .fetch_one(w.db.pool())
    .await
    .unwrap();
    assert!(stored.contains("view_impostor"));
    let out = super::sql::query_sql(&w.db, &w.viewer, json!({"sql":"SELECT relation_name FROM catalog_relations WHERE relation_name='view_impostor'"})).await.unwrap();
    assert_eq!(out["row_count"], 0);
    assert!(super::sql::query_sql(
        &w.db,
        &w.viewer,
        json!({"sql":"SELECT * FROM view_impostor"})
    )
    .await
    .is_err());
    let mut new_observation = observation;
    new_observation.key = "named_view".into();
    assert!(
        kernel::observe_facet_as(&w.db, &w.admin, &w.second, &new_observation, None)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn kernel_v2_named_views_outer_predicates_preserve_other_records() {
    let w = world().await;
    kernel::observe_facet_as(
        &w.db,
        &w.admin,
        &w.second,
        &kernel::FacetObservation {
            key: "other_record_marker".into(),
            value: Some("present".into()),
            value_num: None,
            vocab_ref: None,
            as_of: chrono::Utc::now().to_rfc3339(),
        },
        None,
    )
    .await
    .unwrap();
    kernel::link_as(&w.db, &w.admin, &w.second, "relates_to", &w.first)
        .await
        .unwrap();
    let body = "SELECT r.id,r.type,(SELECT count(*) FROM facet_values f WHERE f.record_id<>r.id) AS other_facets,(SELECT count(*) FROM links l WHERE l.source_id<>r.id) AS other_links FROM records r";
    let definition = named_view_fixture_definition(
        body,
        &["id", "type", "other_facets", "other_links"],
        &["records", "facet_values", "links"],
    );
    named_view_save(&w, &w.first, &definition).await;
    kernel::named_views::publish(&w.db, &w.admin, &w.first, "view_counts")
        .await
        .unwrap();
    for (suffix, parameters) in [
        (
            "WHERE id=?1 ORDER BY id",
            json!([{"type":"text","value":w.first}]),
        ),
        ("WHERE type='Document' ORDER BY id", json!([])),
        ("ORDER BY id LIMIT 1", json!([])),
    ] {
        let (actual, stats) = super::sql::measured(super::sql::query_sql(
            &w.db,
            &w.viewer,
            json!({"sql":format!("SELECT * FROM view_counts {suffix}"),"parameters":parameters}),
        ))
        .await;
        let actual = actual.unwrap();
        let expected = super::sql::with_full_record_scope_staging(super::sql::with_full_facet_staging(super::sql::with_full_record_class_staging(super::sql::query_sql(&w.db, &w.viewer,
            json!({"sql":format!("SELECT * FROM ({body}) {suffix}"),"parameters":parameters}))))).await.unwrap();
        assert_eq!(actual["rows"], expected["rows"], "{suffix}");
        assert_eq!(stats.staged_records, 2, "{suffix}");
        if suffix.starts_with("WHERE id") {
            assert!(actual["rows"][0]["other_facets"].as_i64().unwrap() > 0);
            assert!(actual["rows"][0]["other_links"].as_i64().unwrap() > 0);
        }
    }
}

#[tokio::test]
async fn kernel_v2_named_views_bad_binding_isolated_from_catalog_and_good_view() {
    let w = world().await;
    let definition =
        named_view_fixture_definition("SELECT id,name FROM records", &["id", "name"], &["records"]);
    for (record, name) in [(&w.first, "view_broken"), (&w.second, "view_healthy")] {
        named_view_save(&w, record, &definition).await;
        kernel::named_views::publish(&w.db, &w.admin, record, name)
            .await
            .unwrap();
    }
    let original: String = sqlx::query_scalar(
        "SELECT value FROM kernel_facets WHERE record_id=? AND key='named_view'",
    )
    .bind(&w.first)
    .fetch_one(w.db.pool())
    .await
    .unwrap();
    let mut bad_shape: Value = serde_json::from_str(&original).unwrap();
    bad_shape["v"] = json!("bad version");
    let mut bad_name: Value = serde_json::from_str(&original).unwrap();
    bad_name["name"] = json!("view_bad-name");
    for raw in [
        "{".to_owned(),
        bad_shape.to_string(),
        bad_name.to_string(),
        "x".repeat(256 * 1024 + 1),
    ] {
        sqlx::query("UPDATE kernel_facets SET value=? WHERE record_id=? AND key='named_view'")
            .bind(raw)
            .bind(&w.first)
            .execute(w.db.write_pool())
            .await
            .unwrap();
        for relation in ["catalog_relations", "catalog_columns"] {
            let out = super::sql::query_sql(&w.db, &w.viewer,
                json!({"sql":format!("SELECT relation_name FROM {relation} WHERE substr(relation_name,1,5)='view_' ORDER BY relation_name")})).await.unwrap();
            assert_eq!(out["row_count"], 0);
            assert_eq!(out["notices"][0]["code"], "view_catalog_incomplete");
        }
        let error =
            super::sql::query_sql(&w.db, &w.viewer, json!({"sql":"SELECT * FROM view_broken"}))
                .await
                .unwrap_err();
        assert!(
            error.to_string().contains("view_broken' unavailable"),
            "{error}"
        );
        assert!(super::sql::query_sql(
            &w.db,
            &w.viewer,
            json!({"sql":"SELECT * FROM view_healthy ORDER BY id"})
        )
        .await
        .is_ok());
    }
    sqlx::query("UPDATE kernel_facets SET value=? WHERE record_id=? AND key='named_view'")
        .bind(&original)
        .bind(&w.first)
        .execute(w.db.write_pool())
        .await
        .unwrap();
    for bad_sql in [
        "SELECT id,name FROM records WHERE",
        "SELECT id,name FROM main.kernel_records",
    ] {
        let mut bad_definition = definition.clone();
        bad_definition["sql"] = json!(bad_sql);
        named_view_save(&w, &w.first, &bad_definition).await;
        let out = super::sql::query_sql(&w.db, &w.viewer,
            json!({"sql":"SELECT relation_name FROM catalog_relations WHERE substr(relation_name,1,5)='view_'"})).await.unwrap();
        assert_eq!(out["row_count"], 0);
        assert_eq!(out["notices"][0]["code"], "view_catalog_incomplete");
        let error =
            super::sql::query_sql(&w.db, &w.viewer, json!({"sql":"SELECT * FROM view_broken"}))
                .await
                .unwrap_err();
        assert!(
            error.to_string().contains("view_broken' unavailable"),
            "{error}"
        );
    }
    let outsider =
        kernel::create_principal(&w.db, "account", "Outsider", "acct:outsider", &w.admin)
            .await
            .unwrap();
    let missing = super::sql::query_sql(
        &w.db,
        &outsider,
        json!({"sql":"SELECT * FROM view_healthy"}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(missing.contains("no such table: view_healthy"), "{missing}");
    // The retained registry rejects corrupt legacy history before reaching its
    // test-only Slice 1 adapter. No production legacy producer is supported.
    for _ in 0..7 {
        sqlx::query("INSERT INTO content_events(id,record_id,type,payload,causal_envelope_version,causal_status) VALUES(?,?,'kernel.named_view_admitted.v1',?,1,'legacy_unknown')")
            .bind(uuid::Uuid::new_v4().to_string()).bind(&w.first).bind(&original)
            .execute(w.db.write_pool()).await.unwrap();
    }
    for relation in ["catalog_relations", "catalog_columns"] {
        let out = super::sql::query_sql(
            &w.db,
            &w.viewer,
            json!({"sql":format!("SELECT relation_name FROM {relation}")}),
        )
        .await
        .unwrap();
        assert!(out["row_count"].as_u64().unwrap() > 0);
        assert_eq!(out["notices"][0]["code"], "view_catalog_incomplete");
        assert!(out["rows"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| !r["relation_name"].as_str().unwrap().starts_with("view_")));
    }
    for (actor, sql) in [
        (&w.viewer, "SELECT * FROM view_healthy"),
        (&outsider, "SELECT * FROM view_healthy"),
    ] {
        let error = super::sql::query_sql(&w.db, actor, json!({"sql":sql}))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("legacy admission history limit"), "{error}");
        assert!(!error.contains(&w.first));
        assert!(!error.contains(&w.second));
    }
}

#[tokio::test]
async fn named_view_detail_catalog_refuses_stored_unpinned_and_pinned_reads() {
    let (db, actor) =
        crate::kernel::create_v2_database(":memory:", "account", "Admin", "acct:admin")
            .await
            .unwrap();
    for pins in [None, Some(serde_json::json!({}))] {
        let mut args = serde_json::json!({"sql":"SELECT relation_name FROM catalog_view_definitions ORDER BY relation_name"});
        if let Some(pins) = pins {
            args["_named_view_pins"] = pins;
        }
        let error = sql::query_stored_saved_sql(&db, &actor, args)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("saved governed SQL cannot read 'catalog_view_definitions'"),
            "{error}"
        );
    }
    sql::query_sql(
        &db,
        &actor,
        serde_json::json!({"sql":"SELECT relation_name FROM catalog_view_definitions"}),
    )
    .await
    .unwrap();
}

#[path = "containment_cache_proof.rs"]
mod containment_cache_proof;

#[tokio::test]
async fn kernel_v2_viewer_matches_actor_names_without_history() {
    let w = world().await;
    let newcomer =
        kernel::create_principal(&w.db, "account", "Fallback", "acct:newcomer", &w.admin)
            .await
            .unwrap();
    let query = |sql: &str| json!({"sql":sql});
    let viewer_sql = "SELECT person_id, display_name FROM viewer";
    let author_sql = "SELECT person_id, display_name FROM actors WHERE actor=current_principal()";
    let before = call_as(&w, "acct:newcomer", "query_sql", query(viewer_sql))
        .await
        .unwrap();
    assert_eq!(
        before["rows"],
        json!([{"person_id":null,"display_name":"Fallback"}])
    );
    assert_eq!(
        call_as(
            &w,
            "acct:newcomer",
            "query_sql",
            query("SELECT count(*) AS n FROM viewer")
        )
        .await
        .unwrap()["rows"][0]["n"],
        1
    );
    assert_eq!(
        call_as(&w, "acct:newcomer", "query_sql", query(author_sql))
            .await
            .unwrap()["rows"],
        json!([])
    );
    // The admin's first write already exists in world(). Test every person
    // state against that caller's actual author row in the same snapshot.
    sqlx::query("INSERT INTO kernel_message_people(person_id,principal_id) VALUES(?,?)")
        .bind(&w.first)
        .bind(&w.admin)
        .execute(w.db.write_pool())
        .await
        .unwrap();
    for name in [
        Some("Alice".to_owned()),
        None,
        Some("x".repeat(1501)),
        Some("  Alice \t ".to_owned()),
    ] {
        sqlx::query(
            "UPDATE kernel_record_fields SET value_json=? WHERE record_id=? AND name='title'",
        )
        .bind(serde_json::to_string(&name).unwrap())
        .bind(&w.first)
        .execute(w.db.write_pool())
        .await
        .unwrap();
        let viewer = call_as(&w, "acct:admin", "query_sql", query(viewer_sql))
            .await
            .unwrap();
        let author = call_as(&w, "acct:admin", "query_sql", query(author_sql))
            .await
            .unwrap();
        assert_eq!(viewer["rows"], author["rows"]);
        assert_eq!(
            viewer["rows"][0]["display_name"],
            json!(name.unwrap_or_else(|| "Admin".into()))
        );
    }
    // An earlier hidden directory row must not mask a later visible person.
    // The caller can see many workspace records, but viewer stages just its
    // candidate people (one visible record here).
    for (source, person) in [("viewer:0", &w.hidden), ("viewer:1", &w.first)] {
        sqlx::query("INSERT INTO kernel_v1_state(section,source_id,origin,payload,account_principal,record_id,observed_at,event_seq) VALUES('account_directory',?,'test','{}',?,?,'2026-11-06T00:00:00Z',1)")
            .bind(source).bind(&w.viewer).bind(person).execute(w.db.write_pool()).await.unwrap();
    }
    let (visible_viewer, stats) =
        sql::measured(call_as(&w, "acct:viewer", "query_sql", query(viewer_sql))).await;
    assert_eq!(visible_viewer.unwrap()["rows"][0]["person_id"], w.first);
    assert_eq!(stats.staged_records, 1);
    sqlx::query(
        "DELETE FROM kernel_v1_state WHERE account_principal=? AND section='account_directory'",
    )
    .bind(&w.viewer)
    .execute(w.db.write_pool())
    .await
    .unwrap();
    // Retained import state can have several directory source rows for
    // one principal. The viewer stays a singleton and names an actual author.
    for (source, person) in [
        ("viewer:a", &w.first),
        ("viewer:b", &w.first),
        ("viewer:z", &w.second),
    ] {
        sqlx::query("INSERT INTO kernel_v1_state(section,source_id,origin,payload,account_principal,record_id,observed_at,event_seq) VALUES('account_directory',?,'test','{}',?,?,'2026-11-06T00:00:00Z',1)")
            .bind(source).bind(&w.admin).bind(person).execute(w.db.write_pool()).await.unwrap();
    }
    let singleton = call_as(&w, "acct:admin", "query_sql", query(viewer_sql))
        .await
        .unwrap();
    let authors = call_as(&w, "acct:admin", "query_sql", query(author_sql))
        .await
        .unwrap();
    assert_eq!(singleton["rows"].as_array().unwrap().len(), 1);
    assert!(authors["rows"]
        .as_array()
        .unwrap()
        .contains(&singleton["rows"][0]));
    assert_eq!(singleton["rows"][0]["person_id"], w.first);
    sqlx::query("DELETE FROM kernel_v1_state WHERE section='account_directory' AND source_id LIKE 'viewer:%'")
        .execute(w.db.write_pool()).await.unwrap();
    sqlx::query("DELETE FROM kernel_message_people WHERE principal_id=?")
        .bind(&w.admin)
        .execute(w.db.write_pool())
        .await
        .unwrap();
    let viewer = call_as(&w, "acct:admin", "query_sql", query(viewer_sql))
        .await
        .unwrap();
    assert_eq!(
        viewer["rows"],
        call_as(&w, "acct:admin", "query_sql", query(author_sql))
            .await
            .unwrap()["rows"]
    );
    let own_home = kernel::create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&newcomer, "edit")]),
        &w.admin,
    )
    .await
    .unwrap();
    kernel::create_as(
        &w.db,
        &newcomer,
        "fixture.mcp",
        "note",
        json!({"title":"First write"}).as_object().unwrap(),
        &own_home,
    )
    .await
    .unwrap();
    assert_eq!(
        call_as(&w, "acct:newcomer", "query_sql", query(viewer_sql))
            .await
            .unwrap()["rows"],
        call_as(&w, "acct:newcomer", "query_sql", query(author_sql))
            .await
            .unwrap()["rows"]
    );
    // A person outside this caller's visible homes cannot supply its name.
    sqlx::query("INSERT INTO kernel_message_people(person_id,principal_id) VALUES(?,?)")
        .bind(&w.hidden)
        .bind(&newcomer)
        .execute(w.db.write_pool())
        .await
        .unwrap();
    assert_eq!(
        call_as(&w, "acct:newcomer", "query_sql", query(viewer_sql))
            .await
            .unwrap()["rows"],
        before["rows"]
    );
    assert_eq!(
        call_as(&w, "acct:newcomer", "query_sql", query(viewer_sql))
            .await
            .unwrap()["rows"],
        call_as(&w, "acct:newcomer", "query_sql", query(author_sql))
            .await
            .unwrap()["rows"]
    );
    sqlx::query("DELETE FROM kernel_message_people WHERE principal_id=?")
        .bind(&newcomer)
        .execute(w.db.write_pool())
        .await
        .unwrap();
    sqlx::query("INSERT INTO kernel_message_people(person_id,principal_id) VALUES(?,?)")
        .bind(&w.second)
        .bind(&w.admin)
        .execute(w.db.write_pool())
        .await
        .unwrap();
    call_as(
        &w,
        "acct:admin",
        "delete_record",
        json!({"id":w.second,"reason":"viewer lifecycle parity"}),
    )
    .await
    .unwrap();
    assert_eq!(
        call_as(&w, "acct:admin", "query_sql", query(viewer_sql))
            .await
            .unwrap()["rows"],
        call_as(&w, "acct:admin", "query_sql", query(author_sql))
            .await
            .unwrap()["rows"]
    );
}

#[tokio::test]
async fn kernel_v2_get_links_preserve_provider_source_identity_direction_and_visibility() {
    use crate::v2_standard::relates_to::{Command, Source};
    let w = world().await;
    let package = crate::v2_standard::relates_to::package();
    let installed = kernel::install_package_as(&w.db, &w.admin, &package)
        .await
        .unwrap();
    kernel::adopt_package_at(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &package,
        Some(&installed),
        &package.declared_reads,
    )
    .await
    .unwrap();
    let home = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let source = kernel::create_record_as(&w.db, &w.admin, &home)
        .await
        .unwrap();
    let target = kernel::create_record_as(&w.db, &w.admin, &home)
        .await
        .unwrap();
    let mut sources = Vec::new();
    // Two distinct assertions in one direction must not collapse by triple.
    for (id, from, to) in [
        ("retained-a", &source, &target),
        ("retained-b", &source, &target),
        ("retained-reverse", &target, &source),
    ] {
        sources.push(Source {
            source_id: id.into(),
            from: from.clone(),
            to: to.clone(),
            claimed_author: None,
            claimed_timestamp: Some("2026-09-03T12:34:56+01:00".into()),
            note: Some(format!("note for {id}")),
        });
    }
    let request = kernel::prepare_provider_as(
        &w.db,
        &w.admin,
        &source,
        &target,
        "retained-links",
        Command::Assert { sources },
    )
    .await
    .unwrap();
    let assertion = kernel::commit_provider_as(&w.db, &w.admin, &request)
        .await
        .unwrap();
    let request = kernel::prepare_provider_as(
        &w.db,
        &w.admin,
        &source,
        &w.hidden,
        "hidden-link",
        Command::Assert { sources: vec![] },
    )
    .await
    .unwrap();
    kernel::commit_provider_as(&w.db, &w.admin, &request)
        .await
        .unwrap();

    #[cfg(feature = "v2-kernel-probe")]
    for credential in ["acct:admin", "acct:viewer"] {
        let args = json!({"id":source});
        let expected = call_as(&w, credential, "render_record", args.clone())
            .await
            .unwrap();
        let (actual, details) = small_read_detailed_call(
            true,
            true,
            false,
            None,
            call_as(&w, credential, "render_record", args),
        )
        .await;
        assert_eq!(actual.unwrap(), expected);
        assert!(!details["candidates"].as_array().unwrap().is_empty());
        assert_eq!(details["links"].as_array().unwrap().len(), 1);
        assert_eq!(details["links"][0]["succeeded"], true);
    }

    let sql = call(&w, "query_sql", json!({"sql":"SELECT id,source_id,target_id,relationship,note,created_at FROM links WHERE source_id=?1 OR target_id=?1 ORDER BY relationship,created_at,id,source_id,target_id", "parameters":[{"type":"text","value":source}]})).await.unwrap();
    assert_eq!(sql["row_count"], 3);
    let get = call(&w, "get_record", json!({"ids":[source,target]}))
        .await
        .unwrap();
    for (record, outgoing, incoming) in [(&get["records"][0], 2, 1), (&get["records"][1], 1, 2)] {
        assert_eq!(record["links_out_count"], outgoing);
        assert_eq!(record["links_in_count"], incoming);
        for row in record["links_out"]
            .as_array()
            .unwrap()
            .iter()
            .chain(record["links_in"].as_array().unwrap())
        {
            assert!(sql["rows"].as_array().unwrap().contains(row));
            assert_eq!(row["created_at"], "2026-09-03T11:34:56.000Z");
        }
    }
    let page = call(
        &w,
        "get_record",
        json!({"ids":[source],"links_limit":1,"links_offset":1}),
    )
    .await
    .unwrap();
    assert_eq!(page["records"][0]["links_out_count"], 2);
    assert_eq!(
        page["records"][0]["links_out"],
        json!([get["records"][0]["links_out"][1]])
    );
    assert_eq!(page["records"][0]["links_in"], json!([]));
    let list = call(
        &w,
        "manage_links",
        json!({"action":"list","record_id":source}),
    )
    .await
    .unwrap();
    assert_eq!(list["links_out"], get["records"][0]["links_out"]);
    assert_eq!(list["links_in"], get["records"][0]["links_in"]);

    let request = kernel::prepare_provider_as(
        &w.db,
        &w.admin,
        &source,
        &target,
        "retract-retained",
        Command::Retract {
            assertion_id: assertion.assertion_id,
        },
    )
    .await
    .unwrap();
    kernel::commit_provider_as(&w.db, &w.admin, &request)
        .await
        .unwrap();
    let get = call(&w, "get_record", json!({"ids":[source]}))
        .await
        .unwrap();
    assert_eq!(get["records"][0]["links_out"], json!([]));
    assert_eq!(get["records"][0]["links_in"], json!([]));

    // A native assertion still exposes its symmetric pair, now with the same
    // stable identities and host-stamped creation time as SQL.
    let request = kernel::prepare_provider_as(
        &w.db,
        &w.admin,
        &source,
        &target,
        "native-link",
        Command::Assert { sources: vec![] },
    )
    .await
    .unwrap();
    kernel::commit_provider_as(&w.db, &w.admin, &request)
        .await
        .unwrap();
    let get = call(&w, "get_record", json!({"ids":[source]}))
        .await
        .unwrap();
    let sql = call(&w, "query_sql", json!({"sql":"SELECT id,source_id,target_id,relationship,note,created_at FROM links WHERE source_id=?1 OR target_id=?1 ORDER BY id", "parameters":[{"type":"text","value":source}]})).await.unwrap();
    assert_eq!(sql["row_count"], 2);
    for row in get["records"][0]["links_out"]
        .as_array()
        .unwrap()
        .iter()
        .chain(get["records"][0]["links_in"].as_array().unwrap())
    {
        assert!(row["id"].is_string());
        assert!(row["created_at"].is_string());
        assert!(sql["rows"].as_array().unwrap().contains(row));
    }
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_direct_removal_attachment_is_guarded_retains_bytes_and_replays() {
    let w = world().await;
    install_comment_carrier(&w).await;
    let attached = call_as(
        &w,
        "acct:admin",
        "attach_text",
        json!({
            "record_id":w.first,"text":"retained detached bytes","filename":"detached.txt"
        }),
    )
    .await
    .unwrap();
    let id = attached["attachment_id"].as_str().unwrap();
    let head: i64 = sqlx::query_scalar("SELECT max(seq) FROM content_events WHERE record_id=?")
        .bind(id)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let bytes: Vec<u8> = sqlx::query_scalar("SELECT b.bytes FROM kernel_blobs b JOIN kernel_attachment_blobs a ON a.sha256=b.sha256 WHERE a.record_id=?")
        .bind(id).fetch_one(w.db.pool()).await.unwrap();
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    for (credential, args) in [
        ("acct:viewer", json!({"action":"detach","attachment_id":id})),
        (
            "acct:admin",
            json!({"action":"detach","attachment_id":id,"if_content_seq":head-1}),
        ),
        (
            "acct:admin",
            json!({"action":"detach","attachment_id":w.first}),
        ),
    ] {
        assert!(call_as(&w, credential, "manage_attachments", args)
            .await
            .is_err());
        assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    }
    let member = Caller::authenticated("acct:admin")
        .with_hosting_context("synthetic-admin", "removal-fixture")
        .with_hosting_member(true)
        .with_hosting_owner(false);
    assert!(!member.counter_footing().is_owner());
    let result = registry()
        .call_engine(
            EngineHandle::KernelV2(w.db.clone()),
            member,
            "manage_attachments",
            json!({"action":"detach","attachment_id":id,"if_content_seq":head}),
        )
        .await
        .unwrap();
    assert!(
        crate::mcp::counter_fence::find_counters(&result).is_empty(),
        "{result}"
    );
    uuid::Uuid::parse_str(result["event_id"].as_str().unwrap()).unwrap();
    assert_eq!(result["detached"], true);
    assert_eq!(result["blob_retained"], true);
    assert_eq!(result["blob_id"], attached["blob"]["id"]);
    assert!(kernel::read_record_as(&w.db, &w.admin, id)
        .await
        .unwrap()
        .is_none());
    assert!(kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .is_some());
    let retained: Vec<u8> = sqlx::query_scalar("SELECT b.bytes FROM kernel_blobs b JOIN kernel_attachment_blobs a ON a.sha256=b.sha256 WHERE a.record_id=?")
        .bind(id).fetch_one(w.db.pool()).await.unwrap();
    assert_eq!(bytes, retained);
    let after = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    assert!(call_as(
        &w,
        "acct:admin",
        "manage_attachments",
        json!({"action":"detach","attachment_id":id})
    )
    .await
    .is_err());
    assert_eq!(after, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(after, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_direct_removal_citation_preserves_comment_and_replays() {
    let w = world().await;
    install_comment_carrier(&w).await;
    call_as(
        &w,
        "acct:admin",
        "update_record",
        json!({
            "id":w.first,"body_set":"alpha brave revised passage"
        }),
    )
    .await
    .unwrap();
    let root = call_as(
        &w,
        "acct:admin",
        "create_record",
        json!({
            "type":"Annotation","kind":"comment","body":"quoted comment",
            "links":[{"relationship":"part_of","target_id":w.first}],
            "target":anchored_target(&w.first,"revised",12,19)
        }),
    )
    .await
    .unwrap();
    let id = root["id"].as_str().unwrap();
    let head: i64 = sqlx::query_scalar("SELECT max(seq) FROM content_events WHERE record_id=?")
        .bind(id)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    for (credential, args) in [
        (
            "acct:viewer",
            json!({"action":"remove","citation_id":id,"reason":"remove quote"}),
        ),
        (
            "acct:admin",
            json!({"action":"remove","citation_id":id,"reason":" "}),
        ),
        (
            "acct:admin",
            json!({"action":"remove","citation_id":id,"reason":"remove quote","if_content_seq":head-1}),
        ),
    ] {
        assert!(call_as(&w, credential, "manage_citations", args)
            .await
            .is_err());
        assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    }
    let member = Caller::authenticated("acct:admin")
        .with_hosting_context("synthetic-admin", "removal-fixture")
        .with_hosting_member(true)
        .with_hosting_owner(false);
    assert!(!member.counter_footing().is_owner());
    let result = registry().call_engine(EngineHandle::KernelV2(w.db.clone()), member,
        "manage_citations", json!({"action":"remove","citation_id":id,"reason":"remove obsolete quote","if_content_seq":head})
    ).await.unwrap();
    assert!(
        crate::mcp::counter_fence::find_counters(&result).is_empty(),
        "{result}"
    );
    uuid::Uuid::parse_str(result["event_id"].as_str().unwrap()).unwrap();
    assert_eq!(result["action"], "removed");
    assert!(kernel::read_record_as(&w.db, &w.admin, id)
        .await
        .unwrap()
        .is_some());
    let targets: i64 =
        sqlx::query_scalar("SELECT count(*) FROM kernel_comment_anchors WHERE annotation_id=?")
            .bind(id)
            .fetch_one(w.db.pool())
            .await
            .unwrap();
    assert_eq!(targets, 0);
    let after = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    assert!(call_as(
        &w,
        "acct:admin",
        "manage_citations",
        json!({"action":"remove","citation_id":id,"reason":"repeat"})
    )
    .await
    .is_err());
    assert_eq!(after, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(after, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    w.db.close().await;
}

fn assert_record_read_contract(name: &str) {
    use crate::mcp::{executor_prototype::ExecutorPrototypeStdioServer, ExperimentalExecutors};
    let pinned = ExecutorPrototypeStdioServer::pin_hosted_catalogue_for_engine(
        &registry(),
        &ExperimentalExecutors::empty(),
        crate::mcp::McpSurfaceMode::Executor,
        EngineKind::KernelV2,
    )
    .unwrap();
    assert!(pinned.classify_call("records_read", Some(name)).is_some());
}

async fn small_read_fixture_record(w: &World, id: &str, home: &str, fields: Value) {
    sqlx::query("INSERT INTO kernel_records(id,home_id,owner_id,primary_type,kind,accession,pin_family,pin_version,pin_digest,interpreter,created_seq,created_at) SELECT ?1,?2,owner_id,primary_type,kind,?1,pin_family,pin_version,pin_digest,interpreter,created_seq,created_at FROM kernel_records WHERE id=?3")
        .bind(id).bind(home).bind(&w.first).execute(w.db.write_pool()).await.unwrap();
    sqlx::query("INSERT INTO kernel_record_fields(record_id,name,value_json,created_seq) SELECT ?1,j.key,json_quote(j.value),r.created_seq FROM kernel_records r CROSS JOIN json_each(?2) j WHERE r.id=?3")
        .bind(id).bind(fields.to_string()).bind(&w.first).execute(w.db.write_pool()).await.unwrap();
    // Keep raw scale fixtures valid for ordinary authorized metadata reads,
    // including disclosure names. Native creation folds this row atomically.
    sqlx::query("INSERT INTO kernel_record_metadata(record_id,persistence,maturity,last_activity_at,event_seq) SELECT ?1,persistence,maturity,last_activity_at,event_seq FROM kernel_record_metadata WHERE record_id=?2")
        .bind(id).bind(&w.first).execute(w.db.write_pool()).await.unwrap();
}

async fn small_read_unrelated_fixture(w: &World) {
    let home = kernel::create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.viewer, "view")]),
        &w.admin,
    )
    .await
    .unwrap();
    sqlx::query("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<300) INSERT INTO kernel_records(id,home_id,owner_id,primary_type,kind,accession,pin_family,pin_version,pin_digest,interpreter,created_seq,created_at) SELECT printf('small:unrelated:%03d',x),?1,r.owner_id,r.primary_type,r.kind,printf('small:unrelated:%03d',x),r.pin_family,r.pin_version,r.pin_digest,r.interpreter,r.created_seq,r.created_at FROM n CROSS JOIN kernel_records r WHERE r.id=?2")
        .bind(&home).bind(&w.first).execute(w.db.write_pool()).await.unwrap();
}

#[tokio::test]
async fn kernel_v2_bootstrap_roots_match_tree_without_unrelated_record_staging() {
    let w = Box::pin(world()).await;
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &[(&w.admin, "manage"), (&w.viewer, "view")],
    )
    .await
    .unwrap();
    let home = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    // Native moves use kernel:root; imported native:root aliases are exercised
    // by the policy fixture. Other children keep their physical ACL home and
    // use the latest logical move destination.
    for id in ["root:direct", "root:archived", "root:moved", "root:away"] {
        small_read_fixture_record(&w, id, &home, json!({"title":id})).await;
    }
    sqlx::query("UPDATE kernel_records SET home_id=? WHERE id='root:direct'")
        .bind(KERNEL_ROOT_ID)
        .execute(w.db.write_pool())
        .await
        .unwrap();
    for (index, (id, parent)) in [
        ("root:archived", KERNEL_ROOT_ID),
        ("root:moved", KERNEL_ROOT_ID),
        ("root:away", KERNEL_ROOT_ID),
        ("root:away", home.as_str()),
        (w.hidden.as_str(), KERNEL_ROOT_ID),
    ]
    .into_iter()
    .enumerate()
    {
        sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) SELECT ?1,id,'kernel.record_rehomed.v2',json_object('new_home_id',home_id,'logical_home_id',?2,'parent_update',NULL),?3,created_at,1,'legacy_unknown' FROM kernel_records WHERE id=?4")
            .bind(format!("root-preview-move:{index}")).bind(parent).bind(&w.admin).bind(id)
            .execute(w.db.write_pool()).await.unwrap();
    }
    // These are serving-projection fixtures, not complete mutation histories.
    sqlx::query("INSERT INTO kernel_lifecycle(record_id,archived) VALUES('root:archived',1)")
        .execute(w.db.write_pool())
        .await
        .unwrap();
    // A direct root annotation is visible but belongs to a dedicated family,
    // so it must not inflate the ordinary tree child count.
    small_read_fixture_record(
        &w,
        "root:annotation",
        KERNEL_ROOT_ID,
        json!({"title":"root annotation"}),
    )
    .await;
    sqlx::query("UPDATE kernel_records SET primary_type='Annotation',kind='comment' WHERE id='root:annotation'")
        .execute(w.db.write_pool()).await.unwrap();
    for actor in [&w.admin, &w.viewer] {
        let (before, before_stats) = Box::pin(sql::measured(super::read_surface::bootstrap_roots(
            &w.db, actor,
        )))
        .await;
        let before = before.unwrap();
        let count = if actor == &w.admin { 3 } else { 2 };
        assert_eq!(before[0]["child_count"], count);
        // Add an unrelated, visible corpus only once; compare with an empty
        // added corpus first and then with the generic tree oracle for both.
        if actor == &w.admin {
            small_read_unrelated_fixture(&w).await;
        }
        let (narrow, narrow_stats) = Box::pin(sql::measured(super::read_surface::bootstrap_roots(
            &w.db, actor,
        )))
        .await;
        let (full, full_stats) = Box::pin(sql::measured(super::read_surface::get_structure(
            &w.db,
            actor,
            json!({"root_id":"native:root","max_depth":0,"max_children_per_node":0}),
        )))
        .await;
        let narrow = narrow.unwrap();
        assert_eq!(narrow, before);
        assert_eq!(narrow, full.unwrap()["nodes"]);
        assert_eq!(narrow_stats.staged_records, before_stats.staged_records);
        assert_eq!(
            narrow_stats.staged_metadata_records,
            before_stats.staged_metadata_records
        );
        assert!(
            narrow_stats.staged_records + 300 <= full_stats.staged_records,
            "narrow={narrow_stats:?}, full={full_stats:?}"
        );
    }
    let (before, before_stats) = Box::pin(sql::measured(super::read_surface::bootstrap_roots(
        &w.db, &w.viewer,
    )))
    .await;
    // The reused anchor envelope conservatively retains Collections as
    // placement witnesses. Measure that residual work honestly: this repair
    // avoids unrelated ordinary records, but is not independent of all
    // unrelated containers or policy homes.
    for index in 0..12 {
        let id = format!("root:nested-folder:{index}");
        small_read_fixture_record(&w, &id, &home, json!({"title":id})).await;
        sqlx::query("UPDATE kernel_records SET primary_type='Collection',kind='folder' WHERE id=?")
            .bind(&id)
            .execute(w.db.write_pool())
            .await
            .unwrap();
    }
    let (after, after_stats) = Box::pin(sql::measured(super::read_surface::bootstrap_roots(
        &w.db, &w.viewer,
    )))
    .await;
    assert_eq!(after.unwrap(), before.unwrap());
    let added = after_stats.staged_records as i128 - before_stats.staged_records as i128;
    eprintln!("bootstrap root preview: added nested Collections=12, added staged records={added}");
    assert!(after_stats.staged_records <= before_stats.staged_records + 12);
    w.db.close().await;
}

#[tokio::test]
async fn record_reads_small_name_staging_matches_full_relation_and_exact_ambiguity() {
    let w = world().await;
    small_read_unrelated_fixture(&w).await;
    let home = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let private = kernel::read_record_as(&w.db, &w.admin, &w.hidden)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    for (id, placement, fields) in [
        ("small:duplicate", &home, json!({"title":"Alpha"})),
        ("small:hidden-duplicate", &private, json!({"title":"Alpha"})),
        (
            "small:shadowed",
            &home,
            json!({"title":"Display","name":"Alpha"}),
        ),
        (
            "small:empty-title",
            &home,
            json!({"title":"","name":"Alpha"}),
        ),
        (
            "small:fallback",
            &home,
            json!({"title":null,"name":"Fallback"}),
        ),
    ] {
        small_read_fixture_record(&w, id, placement, fields).await;
    }
    for index in 0..105 {
        small_read_fixture_record(
            &w,
            &format!("small:crowded:{index:03}"),
            &home,
            json!({"title":"Crowded"}),
        )
        .await;
    }
    let args = json!({"names":["Alpha","alpha","Display","Fallback","Crowded","Alpha"]});
    let (full, full_stats) = sql::measured(record_reads::with_full_small_read_staging(call(
        &w,
        "resolve_many",
        args.clone(),
    )))
    .await;
    let (narrow, narrow_stats) = sql::measured(call(&w, "resolve_many", args)).await;
    let narrow = narrow.unwrap();
    assert_eq!(narrow, full.unwrap());
    assert_eq!(narrow["results"][0]["match_count"], 2);
    assert_eq!(narrow["results"][1]["status"], "not_found");
    assert_eq!(narrow["results"][2]["match"]["id"], "small:shadowed");
    assert_eq!(narrow["results"][3]["match"]["id"], "small:fallback");
    assert_eq!(narrow["results"][4]["match_count"], 105);
    assert_eq!(
        narrow["results"][4]["matches"].as_array().unwrap().len(),
        105
    );
    assert_eq!(narrow_stats.installations, 1);
    assert!(
        narrow_stats.staged_records + 300 <= full_stats.staged_records,
        "full={full_stats:?}, narrow={narrow_stats:?}"
    );
    assert_eq!(narrow_stats.staged_records, 110);
}

#[tokio::test]
async fn record_reads_small_render_staging_matches_full_links_names_and_successors() {
    use crate::v2_standard::relates_to::Command;
    let w = world().await;
    small_read_unrelated_fixture(&w).await;
    let home = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let anchor = kernel::create_record_as(&w.db, &w.admin, &home)
        .await
        .unwrap();
    let endpoint = kernel::create_record_as(&w.db, &w.admin, &home)
        .await
        .unwrap();
    for (id, title) in [(&anchor, "Render anchor"), (&endpoint, "Provider endpoint")] {
        sqlx::query("INSERT INTO kernel_record_fields(record_id,name,value_json,created_seq) SELECT id,'title',json_quote(?2),created_seq FROM kernel_records WHERE id=?1")
            .bind(id).bind(title).execute(w.db.write_pool()).await.unwrap();
    }
    let package = crate::v2_standard::relates_to::package();
    let installed = kernel::install_package_as(&w.db, &w.admin, &package)
        .await
        .unwrap();
    kernel::adopt_package_at(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &package,
        Some(&installed),
        &package.declared_reads,
    )
    .await
    .unwrap();
    let request = kernel::prepare_provider_as(
        &w.db,
        &w.admin,
        &anchor,
        &endpoint,
        "small-render-provider",
        Command::Assert { sources: vec![] },
    )
    .await
    .unwrap();
    kernel::commit_provider_as(&w.db, &w.admin, &request)
        .await
        .unwrap();
    kernel::add_generic_link_as(
        &w.db,
        &w.admin,
        &anchor,
        &w.second,
        "arbitrary-relationship",
        None,
    )
    .await
    .unwrap();
    kernel::add_generic_link_as(&w.db, &w.admin, &w.hidden, &anchor, "supersedes", None)
        .await
        .unwrap();
    for index in 0..5 {
        let id = format!("small:successor:{index}");
        small_read_fixture_record(
            &w,
            &id,
            &home,
            json!({"title":format!("Successor {index}")}),
        )
        .await;
        kernel::add_generic_link_as(&w.db, &w.admin, &id, &anchor, "supersedes", None)
            .await
            .unwrap();
    }
    // The SQL links relation retains both legacy and generic provenance.
    sqlx::query("INSERT INTO kernel_links(source_id,target_id,relationship,created_seq) SELECT 'small:successor:0',?1,'supersedes',created_seq FROM kernel_records WHERE id=?1")
        .bind(&anchor).execute(w.db.write_pool()).await.unwrap();
    let args = json!({"id":anchor});
    let (full, full_stats) = sql::measured(record_reads::with_full_small_read_staging(call(
        &w,
        "render_record",
        args.clone(),
    )))
    .await;
    let (narrow, narrow_stats) = sql::measured(call(&w, "render_record", args)).await;
    let narrow = narrow.unwrap();
    assert_eq!(narrow, full.unwrap());
    let markdown = narrow["markdown"].as_str().unwrap();
    for name in ["Provider endpoint", "Beta", "arbitrary-relationship"] {
        assert!(markdown.contains(name), "{markdown}");
    }
    assert!(!markdown.contains("Secret"), "{markdown}");
    assert_eq!(narrow_stats.installations, 1);
    assert!(
        narrow_stats.staged_records + 300 <= full_stats.staged_records,
        "full={full_stats:?}, narrow={narrow_stats:?}"
    );
    // Inspect the structured result too: the renderer shows at most 3 of 6
    // SQL successor rows even though Get deduplicates their link envelope.
    let actor = w.viewer.clone();
    let id = anchor.clone();
    let successors = sql::with_part_of_read_session(
        &w.db,
        &w.viewer,
        &[("records", "id")],
        std::slice::from_ref(&anchor),
        sql::in_snapshot(&w.db, &w.viewer, move |conn| {
            Box::pin(async move { record_reads::render_successors_on(conn, &actor, &id).await })
        }),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(successors.total_count, 6);
    assert_eq!(successors.items.len(), 3);
}

#[tokio::test]
async fn record_reads_resolve_many_visible_shape_and_hidden_cardinality() {
    assert_record_read_contract("resolve_many");
    let w = world().await;
    let out = call(
        &w,
        "resolve_many",
        json!({"names":["Alpha","Secret","Alpha","alpha"]}),
    )
    .await
    .unwrap();
    assert_eq!(out["results"][0]["match"]["id"], w.first);
    assert_eq!(out["results"][1]["status"], "not_found");
    assert_eq!(out["results"][2]["match"]["id"], w.first);
    assert_eq!(
        out["counts"],
        json!({"resolved":2,"not_found":2,"ambiguous":0,"not_held":0})
    );
    assert!(!out.to_string().contains(&w.hidden));
    let private = kernel::read_record_as(&w.db, &w.admin, &w.hidden)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    install_comment_carrier(&w).await;
    let duplicate = kernel::create_json_as(
        &w.db,
        &w.admin,
        crate::v2_standard::v1_compat::FAMILY,
        crate::v2_standard::v1_compat::KIND,
        &json!({"v1_type":"Document","v1_kind":"note","title":"Alpha"}).to_string(),
        &private,
    )
    .await
    .unwrap();
    let out = call(&w, "resolve_many", json!({"names":["Alpha"]}))
        .await
        .unwrap();
    assert_eq!(out["results"][0]["status"], "resolved");
    assert!(!out.to_string().contains(&w.hidden));
    assert!(!out.to_string().contains(&duplicate));
}

#[tokio::test]
async fn record_reads_render_record_visible_shape_and_hidden_links() {
    assert_record_read_contract("render_record");
    let w = world().await;
    let out = call(&w, "render_record", json!({"id":w.first}))
        .await
        .unwrap();
    assert_eq!(out["id"], w.first);
    let markdown = out["markdown"].as_str().unwrap();
    assert!(markdown.starts_with("# Alpha\n"));
    assert!(markdown.contains("revised"));
    assert!(markdown.contains(&w.second));
    assert!(!markdown.contains(&w.hidden));
    assert!(!markdown.contains("Secret"));
    assert!(call(&w, "render_record", json!({"id":w.hidden}))
        .await
        .is_err());
    assert!(call(
        &w,
        "render_record",
        json!({"id":w.first,"include_interpretation":true})
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("interpretation"));
}

#[tokio::test]
async fn record_reads_dashboard_visible_shape_and_hidden_counts() {
    assert_record_read_contract("get_dashboard");
    let w = world().await;
    let baseline = call(&w, "get_dashboard", json!({})).await.unwrap();
    assert_eq!(baseline["lifecycle_census"]["total"], 2);
    assert_eq!(baseline["active_total"], 0);
    assert_eq!(baseline["stale_total"], 0);
    assert!(!baseline.to_string().contains(&w.hidden));
    assert!(!baseline.to_string().contains("Secret"));
    assert!(call(&w, "get_dashboard", json!({"scope":w.hidden}))
        .await
        .is_err());
    assert_eq!(
        call(&w, "get_dashboard", json!({"scope":w.first}))
            .await
            .unwrap()["lifecycle_census"]["total"],
        1
    );
    assert!(call(&w, "get_dashboard", json!({"limit":0})).await.is_err());
    assert!(call(&w, "get_dashboard", json!({"stale_after_days":36501}))
        .await
        .is_err());
    assert!(call(&w, "get_dashboard", json!({"limit":101}))
        .await
        .is_err());
    assert!(call(
        &w,
        "get_dashboard",
        json!({"limit":100,"stale_after_days":36500})
    )
    .await
    .is_ok());
    install_comment_carrier(&w).await;
    let home = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let private = kernel::read_record_as(&w.db, &w.admin, &w.hidden)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let mut tasks = Vec::new();
    for (name, home) in [("Visible task", home), ("Private task", private)] {
        tasks.push(
            kernel::create_json_as(
                &w.db,
                &w.admin,
                crate::v2_standard::v1_compat::FAMILY,
                crate::v2_standard::v1_compat::KIND,
                &json!({"v1_type":"WorkItem","v1_kind":"task","title":name,"lifecycle":"open"})
                    .to_string(),
                &home,
            )
            .await
            .unwrap(),
        );
    }
    let out = call(&w, "get_dashboard", json!({"limit":1})).await.unwrap();
    assert_eq!(
        out["active_total"].as_i64().unwrap() + out["stale_total"].as_i64().unwrap(),
        1
    );
    assert_eq!(out["unclassified_lifecycle"]["total_count"], 1);
    assert_eq!(out["lifecycle_census"]["total"], 3);
    assert!(!out.to_string().contains(&tasks[1]));
    assert!(out.to_string().contains(&tasks[0]));
    assert!(!out.to_string().contains(&w.hidden));
    assert!(!out.to_string().contains("Secret"));
}

#[tokio::test]
async fn record_reads_resolution_filters_and_visible_ambiguity() {
    let w = world().await;
    let home = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    install_comment_carrier(&w).await;
    let duplicate = kernel::create_json_as(
        &w.db,
        &w.admin,
        crate::v2_standard::v1_compat::FAMILY,
        crate::v2_standard::v1_compat::KIND,
        &json!({"v1_type":"Document","v1_kind":"note","title":"Alpha"}).to_string(),
        &home,
    )
    .await
    .unwrap();
    let out = call(
        &w,
        "resolve_many",
        json!({"names":["Alpha"],"type":"Document","kind":"note"}),
    )
    .await
    .unwrap();
    assert_eq!(out["results"][0]["status"], "ambiguous");
    assert_eq!(out["results"][0]["match_count"], 2);
    let revision = kernel::read_record_as(&w.db, &w.admin, &duplicate)
        .await
        .unwrap()
        .unwrap()
        .revision;
    kernel::set_archived_as(&w.db, &w.admin, &duplicate, true, revision)
        .await
        .unwrap();
    assert_eq!(
        call(&w, "resolve_many", json!({"names":["Alpha"]}))
            .await
            .unwrap()["results"][0]["status"],
        "resolved"
    );
    assert_eq!(
        call(
            &w,
            "resolve_many",
            json!({"names":["Alpha"],"include_archived":true})
        )
        .await
        .unwrap()["results"][0]["match_count"],
        2
    );
    assert_eq!(
        call(
            &w,
            "resolve_many",
            json!({"names":["Alpha"],"type":"Entity"})
        )
        .await
        .unwrap()["results"][0]["status"],
        "not_found"
    );
    assert_eq!(
        call(
            &w,
            "resolve_many",
            json!({"names":["Alpha"],"kind":"other"})
        )
        .await
        .unwrap()["results"][0]["status"],
        "not_found"
    );
    for args in [
        json!({"names":[]}),
        json!({"names":[""]}),
        json!({"names":["Alpha"],"type":"Invalid"}),
        json!({"names":["Alpha"],"kind":""}),
    ] {
        assert!(call(&w, "resolve_many", args).await.is_err());
    }
}

#[tokio::test]
async fn record_reads_dashboard_and_render_ignore_hidden_blockers_and_successors() {
    let w = world().await;
    kernel::add_generic_link_as(&w.db, &w.admin, &w.hidden, &w.first, "blocks", None)
        .await
        .unwrap();
    kernel::add_generic_link_as(&w.db, &w.admin, &w.hidden, &w.first, "supersedes", None)
        .await
        .unwrap();
    // A visible blocker pointing at a hidden record must not create a bucket.
    kernel::add_generic_link_as(&w.db, &w.admin, &w.second, &w.hidden, "blocks", None)
        .await
        .unwrap();
    let out = call(&w, "get_dashboard", json!({})).await.unwrap();
    assert_eq!(out["blocked_total"], 0);
    assert_eq!(out["blocked"], json!([]));
    let rendered = call(&w, "render_record", json!({"id":w.first}))
        .await
        .unwrap();
    assert!(!rendered.to_string().contains("superseded"));
    assert!(!rendered.to_string().contains(&w.hidden));
    assert!(!rendered.to_string().contains("Secret"));
    kernel::add_generic_link_as(&w.db, &w.admin, &w.second, &w.first, "blocks", None)
        .await
        .unwrap();
    kernel::add_generic_link_as(&w.db, &w.admin, &w.second, &w.first, "supersedes", None)
        .await
        .unwrap();
    let out = call(&w, "get_dashboard", json!({})).await.unwrap();
    assert_eq!(out["blocked_total"], 1);
    assert_eq!(
        out["blocked"][0]["blocked_by"],
        json!([{"id":w.second,"relationship":"blocks"}])
    );
    assert_eq!(out["blocked"][0]["superseded_by"]["total_count"], 1);
    let reference = out["blocked"][0]["superseded_by"]["items"][0]["display_reference"]
        .as_str()
        .unwrap();
    assert!(w.second.replace('-', "").starts_with(reference));
    let rendered = call(&w, "render_record", json!({"id":w.first}))
        .await
        .unwrap();
    assert!(rendered["markdown"].as_str().unwrap().contains("Beta"));
    assert!(rendered["markdown"].as_str().unwrap().contains(reference));
    assert!(!rendered.to_string().contains(&w.hidden));
    assert!(!rendered.to_string().contains("Secret"));
    let revision = kernel::read_record_as(&w.db, &w.admin, &w.second)
        .await
        .unwrap()
        .unwrap()
        .revision;
    kernel::set_archived_as(&w.db, &w.admin, &w.second, true, revision)
        .await
        .unwrap();
    assert_eq!(
        call(&w, "get_dashboard", json!({})).await.unwrap()["blocked_total"],
        0
    );
}

fn disclosure_rule<'a>(record: &'a Value, relationship: &str) -> Option<&'a Value> {
    record
        .get("read_disclosures")?
        .as_array()?
        .iter()
        .find(|rule| rule["relationship"] == relationship)
}

/// Governed open/done lifecycle for WorkItem:task, mirroring the dashboard
/// scale fixture: without this the interpreter reports unclassified.
async fn install_governed_task_lifecycle(w: &World) {
    let vocab = "disclosure:WorkItem:task";
    let data = json!({"shapes":{"WorkItem:task":{"facets":{"lifecycle":{"axis":{"key":"WorkItem:task","label":"Status"},"vocab_ref":vocab}}}}});
    let schema = json!({"id":"schema:disclosure-task","layer":"pack","created_at":"2026-11-01T00:00:00Z","data":data.to_string()});
    let mut rows = vec![
        ("schema_config", schema),
        ("vocabularies", json!({"id":vocab,"name":vocab})),
    ];
    for (raw, terminality) in [("open", "open"), ("done", "terminal_positive")] {
        rows.push((
            "vocabulary_values",
            json!({"id":format!("{vocab}:{raw}"),"vocabulary_id":vocab,"value":raw,"status":"active","terminality":terminality}),
        ));
    }
    for (section, value) in rows {
        sqlx::query("INSERT INTO kernel_v1_state(section,source_id,origin,payload,observed_at,event_seq) VALUES(?,?,'disclosure',?,'2026-11-01T00:00:00Z',0)")
            .bind(section)
            .bind(value["id"].as_str().unwrap())
            .bind(value.to_string())
            .execute(w.db.write_pool())
            .await
            .unwrap();
    }
}

async fn disclosure_task(w: &World, title: &str, lifecycle: &str, home: &str) -> String {
    kernel::create_json_as(
        &w.db,
        &w.admin,
        crate::v2_standard::v1_compat::FAMILY,
        crate::v2_standard::v1_compat::KIND,
        &json!({"v1_type":"WorkItem","v1_kind":"task","title":title,"lifecycle":lifecycle})
            .to_string(),
        home,
    )
    .await
    .unwrap()
}

async fn disclosure_note(w: &World, title: &str, home: &str) -> String {
    kernel::create_as(
        &w.db,
        &w.admin,
        "fixture.mcp",
        "note",
        json!({"title": title, "body": "original"})
            .as_object()
            .unwrap(),
        home,
    )
    .await
    .unwrap()
}

/// Append a historical envelope at an explicit clock. Content events are
/// append-only, so temporal fixtures insert rather than rewrite them.
async fn append_event(w: &World, id: &str, record: &str, typ: &str, actor: &str, at: &str) {
    sqlx::query("INSERT INTO main.content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) VALUES (?,?,?,'{}',?,?,1,'legacy_unknown')")
        .bind(id)
        .bind(record)
        .bind(typ)
        .bind(actor)
        .bind(at)
        .execute(w.db.write_pool())
        .await
        .unwrap();
}

/// Adopt the v1 compatibility carrier for fixtures that create v1-shaped
/// records such as WorkItem tasks.
async fn install_v1_compat(w: &World) {
    let package = crate::v2_standard::v1_compat::package();
    let installed = kernel::install_package_as(&w.db, &w.admin, &package)
        .await
        .unwrap();
    kernel::adopt_package_at(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &package,
        Some(&installed),
        &package.declared_reads,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn read_disclosures_get_covers_slice_rules_with_bounds_and_visibility() {
    let w = world().await;
    let home = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    // Four visible successors plus one hidden: newest-first window of 3 with
    // a visible-only remainder. Explicit clocks keep the order stable.
    let mut successors = Vec::new();
    for (name, day) in [("S1", "10"), ("S2", "11"), ("S3", "12"), ("S4", "13")] {
        let id = disclosure_note(&w, name, &home).await;
        kernel::add_generic_link_as(&w.db, &w.admin, &id, &w.first, "supersedes", None)
            .await
            .unwrap();
        sqlx::query("UPDATE main.kernel_generic_links SET created_at=? WHERE source_id=? AND target_id=? AND relationship='supersedes'")
            .bind(format!("2026-01-{day}T00:00:00.000Z"))
            .bind(&id)
            .bind(&w.first)
            .execute(w.db.write_pool())
            .await
            .unwrap();
        successors.push(id);
    }
    kernel::add_generic_link_as(&w.db, &w.admin, &w.hidden, &w.first, "supersedes", None)
        .await
        .unwrap();
    // draws_from: one source newer than the anchor's last body write, one
    // source backdated older. Only the newer work is disclosed. Source
    // creation clocks are pinned explicitly so same-millisecond ties cannot
    // flake the verdict; content events stay append-only.
    let newer = disclosure_note(&w, "Newer", &home).await;
    let older = disclosure_note(&w, "Older", &home).await;
    sqlx::query("UPDATE main.kernel_records SET created_at='2030-01-01T00:00:00.000Z' WHERE id=?")
        .bind(&newer)
        .execute(w.db.write_pool())
        .await
        .unwrap();
    sqlx::query("UPDATE main.kernel_records SET created_at='2001-01-01T00:00:00.000Z' WHERE id=?")
        .bind(&older)
        .execute(w.db.write_pool())
        .await
        .unwrap();
    for source in [&newer, &older] {
        kernel::add_generic_link_as(&w.db, &w.admin, source, &w.first, "draws_from", None)
            .await
            .unwrap();
    }
    // part_of forward: the anchor names what it is part of.
    kernel::add_generic_link_as(&w.db, &w.admin, &w.first, &w.second, "part_of", None)
        .await
        .unwrap();
    // links_limit: 0 suppresses the link windows but never the disclosures.
    let out = call(
        &w,
        "get_record",
        json!({"ids": [w.first], "links_limit": 0}),
    )
    .await
    .unwrap();
    let record = &out["records"][0];
    assert_eq!(record["links_out"], json!([]));
    assert_eq!(record["links_in"], json!([]));
    let superseded = disclosure_rule(record, "supersedes").expect("supersedes disclosure");
    assert_eq!(superseded["kind"], "claim");
    assert_eq!(superseded["total_count"], 4);
    let items: Vec<&str> = superseded["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["id"].as_str().unwrap())
        .collect();
    assert_eq!(items.len(), 3);
    assert_eq!(
        items,
        vec![
            successors[3].as_str(),
            successors[2].as_str(),
            successors[1].as_str()
        ]
    );
    assert!(!superseded.to_string().contains(&w.hidden));
    assert!(superseded["summary"]
        .as_str()
        .unwrap()
        .starts_with("superseded by "));
    assert!(items.iter().all(|id| superseded["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["id"] == *id && item["display_reference"].is_string())));
    let draws = disclosure_rule(record, "draws_from").expect("draws_from disclosure");
    assert_eq!(draws["kind"], "fact");
    assert_eq!(draws["total_count"], 1);
    assert_eq!(draws["items"][0]["id"], newer);
    assert_eq!(draws["items"][0]["name"], "Newer");
    assert!(draws["summary"]
        .as_str()
        .unwrap()
        .starts_with("newer work builds on this: "));
    let part_of = disclosure_rule(record, "part_of").expect("part_of disclosure");
    assert_eq!(part_of["total_count"], 1);
    assert_eq!(part_of["items"][0]["id"], w.second);
    assert!(disclosure_rule(record, "blocks").is_none());
    assert!(disclosure_rule(record, "relates_to").is_none());
    // Untouched records carry no disclosure key at all.
    let plain = call(&w, "get_record", json!({"ids": [w.second]}))
        .await
        .unwrap();
    assert!(plain["records"][0].get("read_disclosures").is_none());
    w.db.close().await;
}

#[tokio::test]
async fn read_disclosures_blocks_require_governed_open_and_visibility() {
    let w = world().await;
    install_v1_compat(&w).await;
    install_governed_task_lifecycle(&w).await;
    let home = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let private = kernel::read_record_as(&w.db, &w.admin, &w.hidden)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let open = disclosure_task(&w, "Open blocker", "open", &home).await;
    let done = disclosure_task(&w, "Done blocker", "done", &home).await;
    let unclassified = disclosure_note(&w, "Plain note", &home).await;
    let hidden_open = disclosure_task(&w, "Hidden blocker", "open", &private).await;
    for source in [&open, &done, &unclassified, &hidden_open] {
        kernel::add_generic_link_as(&w.db, &w.admin, source, &w.first, "blocks", None)
            .await
            .unwrap();
    }
    // Viewer: only the governed-open visible source is named and counted.
    let out = call(&w, "get_record", json!({"ids": [w.first]}))
        .await
        .unwrap();
    let blocks = disclosure_rule(&out["records"][0], "blocks").expect("blocks disclosure");
    assert_eq!(blocks["total_count"], 1);
    assert_eq!(blocks["items"][0]["id"], open);
    // Admin sees the hidden open blocker too, without disturbing the rest.
    let admin = call_as(&w, "acct:admin", "get_record", json!({"ids": [w.first]}))
        .await
        .unwrap();
    let blocks = disclosure_rule(&admin["records"][0], "blocks").expect("blocks disclosure");
    assert_eq!(blocks["total_count"], 2);
    assert!(!blocks.to_string().contains(&done));
    assert!(!blocks.to_string().contains(&unclassified));
    w.db.close().await;
}

#[tokio::test]
async fn read_disclosures_ride_search_and_query_record_hits() {
    let w = world().await;
    let home = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let successor = disclosure_note(&w, "Successor", &home).await;
    kernel::add_generic_link_as(&w.db, &w.admin, &successor, &w.first, "supersedes", None)
        .await
        .unwrap();
    let hits = call(&w, "search", json!({"query": "Alpha"})).await.unwrap();
    let hit = hits["hits"]
        .as_array()
        .unwrap()
        .iter()
        .find(|hit| hit["id"] == w.first)
        .expect("Alpha hit");
    let rule = disclosure_rule(hit, "supersedes").expect("hit disclosure");
    assert_eq!(rule["total_count"], 1);
    assert_eq!(rule["items"][0]["id"], successor);
    let listed = call(
        &w,
        "query_record",
        json!({"steps": [{"step": "filter", "ids": [w.first]}]}),
    )
    .await
    .unwrap();
    let row = listed["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == w.first)
        .expect("listed row");
    let rule = disclosure_rule(row, "supersedes").expect("row disclosure");
    assert_eq!(rule["total_count"], 1);
    w.db.close().await;
}

#[tokio::test]
async fn read_disclosures_preserve_imported_source_time_over_migration_clock() {
    use crate::identity::hosted::{
        reconcile_hosted_identity, HostedMembershipArrival, HostedMembershipRole,
        HostedMembershipSource,
    };
    // Genuine v1 source with old source times: no projection rows are forged.
    let dir = tempfile::tempdir().unwrap();
    let source = crate::create_database(dir.path().join("source.db").to_str().unwrap())
        .await
        .unwrap();
    let account = reconcile_hosted_identity(
        &source,
        "read-fence-owner@example.test",
        "read-fence-owner",
        &HostedMembershipArrival::new(
            HostedMembershipRole::Owner,
            HostedMembershipSource::Direct,
            "2026-10-28T00:00:00Z".into(),
        )
        .unwrap(),
        None,
    )
    .await
    .unwrap();
    registry()
        .call(
            source.clone(),
            Caller::local(),
            "manage_record_policy",
            json!({"action":"grant","record_id":"native:root","subject":{"kind":"account","account_id":account},"capability":"manage","reason":"Establish source importer owner"}),
        )
        .await
        .unwrap();
    let record = registry()
        .call(
            source.clone(),
            Caller::authenticated(account.clone()),
            "create_record",
            json!({"type":"Document","kind":"note","name":"Imported source","body":"genuine V1 source body","home_id":"native:root","reason":"Prepare imported disclosure target"}),
        )
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    // Backdate the SOURCE times before snapshotting: the migration itself
    // runs now, so a migration clock would read "now" here.
    sqlx::query("UPDATE records SET created_at='2020-01-01T00:00:00.000Z', updated_at='2020-01-01T00:00:00.000Z' WHERE id=?")
        .bind(&record)
        .execute(source.write_pool())
        .await
        .unwrap();
    std::fs::write(dir.path().join("members.txt"), format!("{account}\n")).unwrap();
    let report = crate::v1_import::run(crate::v1_import::Options {
        source: dir.path().join("source.db"),
        target: dir.path().join("target.db"),
        seeds: vec![],
        all: true,
        history: true,
        resume: false,
        members_file: Some(dir.path().join("members.txt")),
    })
    .await
    .unwrap();
    assert!(
        report.refusals.is_empty(),
        "{}",
        serde_json::to_string(&report.refusals).unwrap()
    );
    assert!(
        report.review.is_empty(),
        "{}",
        serde_json::to_string(&report.review).unwrap()
    );
    let db = kernel::open_v2_database(dir.path().join("target.db").to_str().unwrap())
        .await
        .unwrap();
    let provenance: Option<String> = sqlx::query_scalar(
        "SELECT json_extract(e.payload,'$.legacy.payload.updated_at') FROM kernel_legacy_sql_events h JOIN main.content_events e ON e.seq=h.seq WHERE h.record_id=? AND h.source_stream='snapshot_provenance' ORDER BY h.seq DESC LIMIT 1",
    )
    .bind(&record)
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    assert_eq!(provenance.as_deref(), Some("2020-01-01T00:00:00.000Z"));
    let home = kernel::read_record_as(&db, &report.principals[&account], &record)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    // Newer native work created after migration, then backdated between the
    // source time and the migration clock: migration-time semantics would
    // hide it, source-time semantics disclose it.
    let newer = registry()
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            Caller::authenticated(account.clone()),
            "create_record",
            json!({"type":"Document","kind":"note","name":"Newer work","body":"builds on the import","home_id":home,"reason":"Newer work over an old import"}),
        )
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    sqlx::query("UPDATE main.kernel_records SET created_at='2021-01-01T00:00:00.000Z' WHERE id=?")
        .bind(&newer)
        .execute(db.write_pool())
        .await
        .unwrap();
    kernel::add_generic_link_as(
        &db,
        &report.principals[&account],
        &newer,
        &record,
        "draws_from",
        None,
    )
    .await
    .unwrap();
    let out = registry()
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            Caller::authenticated(account.clone()),
            "get_record",
            json!({"ids": [record]}),
        )
        .await
        .unwrap();
    let rule = disclosure_rule(&out["records"][0], "draws_from").expect("imported draws_from");
    assert_eq!(rule["total_count"], 1);
    assert_eq!(rule["items"][0]["id"], newer);
    db.close().await;
}

#[tokio::test]
async fn read_disclosures_name_candidates_without_hydrating_bodies() {
    let w = world().await;
    install_v1_compat(&w).await;
    install_governed_task_lifecycle(&w).await;
    let home = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let named = disclosure_note(&w, "Named candidate", &home).await;
    let blocker = disclosure_task(&w, "Open blocker", "open", &home).await;
    let links = vec![
        json!({
            "source_id": named,
            "target_id": w.first,
            "relationship": "supersedes",
            "created_at": "2026-01-01T00:00:00.000Z"
        }),
        json!({
            "source_id": blocker,
            "target_id": w.first,
            "relationship": "blocks",
            "created_at": "2026-01-02T00:00:00.000Z"
        }),
    ];
    let refs = [(w.first.as_str(), links.as_slice())];
    let mut snapshot = w.db.pool().begin().await.unwrap();
    let (rules, disclosure_loads) = kernel::body_read_probe::scoped(
        super::read_disclosures::disclosures_for(&mut snapshot, &w.admin, &refs),
    )
    .await;
    let rules = rules.unwrap();
    let superseded = rules[&w.first]
        .iter()
        .find(|rule| rule["relationship"] == "supersedes")
        .expect("supersedes disclosure");
    assert_eq!(superseded["items"][0]["name"], "Named candidate");
    let blocks = rules[&w.first]
        .iter()
        .find(|rule| rule["relationship"] == "blocks")
        .expect("blocks disclosure");
    assert_eq!(blocks["total_count"], 1);
    assert_eq!(blocks["items"][0]["id"], blocker);
    // Naming and governed-open counting are presentation over metadata: a
    // disclosure pass must not hydrate a candidate body.
    assert_eq!(disclosure_loads, 0);
    // Control: the same probe observes the real kernel body query.
    let (view, full_loads) =
        kernel::body_read_probe::scoped(kernel::read_record_on(&mut snapshot, &w.admin, &named))
            .await;
    assert!(view.unwrap().is_some());
    assert_eq!(full_loads, 1);
    snapshot.rollback().await.unwrap();
    w.db.close().await;
}

#[tokio::test]
async fn read_disclosures_ignore_importer_and_metadata_envelope_clocks() {
    let w = world().await;
    let home = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    // Newer work sits between the anchor's ordinary content and every ignored
    // envelope below. If any migration or housekeeping clock moved the anchor,
    // it would disappear.
    let source = disclosure_note(&w, "Newer work", &home).await;
    sqlx::query("UPDATE main.kernel_records SET created_at='2028-01-01T00:00:00.000Z' WHERE id=?")
        .bind(&source)
        .execute(w.db.write_pool())
        .await
        .unwrap();
    kernel::add_generic_link_as(&w.db, &w.admin, &source, &w.first, "draws_from", None)
        .await
        .unwrap();
    // The sealed import host's UUID-preserving record event is still a
    // migration clock; so are import deltas and every housekeeping envelope.
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    append_event(
        &w,
        "clock-import-created",
        &w.first,
        "kernel.record_created.v1",
        &host,
        "2029-01-01T00:00:00.000Z",
    )
    .await;
    append_event(
        &w,
        "clock-import-delta",
        &w.first,
        "kernel.import_state_delta.v1",
        &host,
        "2029-02-01T00:00:00.000Z",
    )
    .await;
    append_event(
        &w,
        "clock-metadata",
        &w.first,
        "kernel.metadata_set.v1",
        &w.admin,
        "2029-03-01T00:00:00.000Z",
    )
    .await;
    append_event(
        &w,
        "clock-rehome",
        &w.first,
        "kernel.record_rehomed.v1",
        &w.admin,
        "2029-04-01T00:00:00.000Z",
    )
    .await;
    let out = call(&w, "get_record", json!({"ids": [w.first]}))
        .await
        .unwrap();
    let draws = disclosure_rule(&out["records"][0], "draws_from")
        .expect("migration and housekeeping clocks must not hide newer work");
    assert_eq!(draws["total_count"], 1);
    assert_eq!(draws["items"][0]["id"], source);
    // A genuine native content write does move the substantive clock.
    append_event(
        &w,
        "clock-native-body",
        &w.first,
        "kernel.body_set.v1",
        &w.admin,
        "2031-01-01T00:00:00.000Z",
    )
    .await;
    let out = call(&w, "get_record", json!({"ids": [w.first]}))
        .await
        .unwrap();
    assert!(disclosure_rule(&out["records"][0], "draws_from").is_none());
    w.db.close().await;
}

#[tokio::test]
async fn read_disclosures_imported_clock_ignores_metadata_only_source_updates() {
    let w = world().await;
    let template = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap();
    let home = template.home_id.clone();
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let id = uuid::Uuid::new_v4().to_string();
    // A raw imported record avoids unrelated definition-identity admission:
    // this regression exercises body/provenance and owner-only source resumes.
    let state = kernel::ImportRecordState {
        body: Some("source body".into()),
        ..Default::default()
    };
    kernel::import_record_as(&w.db, &host, &id, &home, Some(w.admin.as_str()), &state)
        .await
        .unwrap();
    // The source creation time is stable; only the payload `updated_at` moves.
    let provenance = |id: &str, updated: &str| kernel::LegacyEvent {
        source: None,
        id: format!("clock-provenance-{updated}"),
        event_type: "v1.snapshot_provenance".into(),
        payload: json!({
            "record_id": id,
            "created_at": "2020-01-01T00:00:00.000Z",
            "updated_at": updated
        }),
        created_at: "2020-01-01T00:00:00.000Z".into(),
        actor: Some("v1:source".into()),
        run_key: None,
    };
    kernel::import_event_as(
        &w.db,
        &host,
        &id,
        &provenance(&id, "2020-01-01T00:00:00.000Z"),
    )
    .await
    .unwrap();
    // Newer work sits between the source content time and the later
    // metadata-only source clock.
    let source = disclosure_note(&w, "Newer work", &home).await;
    sqlx::query("UPDATE main.kernel_records SET created_at='2022-01-01T00:00:00.000Z' WHERE id=?")
        .bind(&source)
        .execute(w.db.write_pool())
        .await
        .unwrap();
    kernel::add_generic_link_as(&w.db, &w.admin, &source, &id, "draws_from", None)
        .await
        .unwrap();
    // Genuine v1 resume that changes only the owner: same body and content
    // fields, but a later source `updated_at`.
    kernel::hq::resume_record_with_blob_as(
        &w.db,
        &host,
        &id,
        &home,
        Some(w.viewer.as_str()),
        &state,
        None,
    )
    .await
    .unwrap();
    kernel::import_event_as(
        &w.db,
        &host,
        &id,
        &provenance(&id, "2025-01-01T00:00:00.000Z"),
    )
    .await
    .unwrap();
    let out = call(&w, "get_record", json!({"ids": [id]})).await.unwrap();
    let draws = disclosure_rule(&out["records"][0], "draws_from")
        .expect("a metadata-only source update must not hide newer work");
    assert_eq!(draws["total_count"], 1);
    assert_eq!(draws["items"][0]["id"], source);
    // A genuine source content change does move the imported clock.
    let mut revised = state.clone();
    revised.body = Some("revised source body".into());
    kernel::hq::resume_record_with_blob_as(
        &w.db,
        &host,
        &id,
        &home,
        Some(w.viewer.as_str()),
        &revised,
        None,
    )
    .await
    .unwrap();
    kernel::import_event_as(
        &w.db,
        &host,
        &id,
        &provenance(&id, "2026-01-01T00:00:00.000Z"),
    )
    .await
    .unwrap();
    let out = call(&w, "get_record", json!({"ids": [id]})).await.unwrap();
    assert!(disclosure_rule(&out["records"][0], "draws_from").is_none());
    w.db.close().await;
}

#[tokio::test]
async fn record_reads_dashboard_candidate_cap_is_after_scope_and_lifecycle_filters() {
    let w = world().await;
    // Two visible ordinary records exceed this cap, but neither needs attention.
    let out = record_reads::TEST_DASHBOARD_CANDIDATE_LIMIT
        .scope(1, call(&w, "get_dashboard", json!({})))
        .await
        .unwrap();
    assert_eq!(out["lifecycle_census"]["total"], 2);
    kernel::add_generic_link_as(&w.db, &w.admin, &w.second, &w.first, "blocks", None)
        .await
        .unwrap();
    kernel::add_generic_link_as(&w.db, &w.admin, &w.first, &w.second, "blocks", None)
        .await
        .unwrap();
    let refused = record_reads::TEST_DASHBOARD_CANDIDATE_LIMIT
        .scope(1, call(&w, "get_dashboard", json!({})))
        .await
        .unwrap_err();
    assert!(refused.to_string().contains("candidate set exceeds 1"));
    let scoped = record_reads::TEST_DASHBOARD_CANDIDATE_LIMIT
        .scope(1, call(&w, "get_dashboard", json!({"scope":w.first})))
        .await
        .unwrap();
    assert_eq!(scoped["lifecycle_census"]["total"], 1);
    assert_eq!(scoped["blocked_total"], 1);
}

#[tokio::test]
async fn record_reads_render_counts_and_hidden_containment() {
    let w = world().await;
    // A private child/inbound edge must affect neither the renderer's list nor
    // its total. Hidden comment-kind records obey the same View gate.
    kernel::add_generic_link_as(&w.db, &w.admin, &w.hidden, &w.first, "part_of", None)
        .await
        .unwrap();
    install_comment_carrier(&w).await;
    let created = call_as(&w, "acct:admin", "create_record", json!({"type":"Annotation","kind":"comment","body":"secret remark","links":[{"target_id":w.first,"relationship":"part_of"}]})).await.unwrap();
    let comment = created["id"].as_str().unwrap().to_owned();
    // Comments derive visibility from exactly one bearer. A malformed retained
    // comment with an extra bearer must fail closed, including its counts.
    sqlx::query("INSERT INTO kernel_generic_links(link_id,source_id,target_id,relationship,note,created_at,actor,active,event_seq,imported) SELECT 'private-extra-bearer',source_id,?,'part_of',note,created_at,actor,active,event_seq,imported FROM kernel_generic_links WHERE source_id=? AND relationship='part_of' AND active=1")
        .bind(&w.hidden).bind(&comment).execute(w.db.write_pool()).await.unwrap();
    let get = call(&w, "get_record", json!({"ids":[w.first]}))
        .await
        .unwrap();
    let enriched = record_reads::render_enrichment(&get["records"][0]);
    assert_eq!(enriched.links_in_count, 0);
    assert_eq!(enriched.child_count, 0);
    assert_eq!(enriched.comment_count, 0);
    let rendered = call(&w, "render_record", json!({"id":w.first}))
        .await
        .unwrap();
    let markdown = rendered["markdown"].as_str().unwrap();
    assert!(!markdown.contains("## Links (incoming)"), "{markdown}");
    assert!(!markdown.contains("## Children"), "{markdown}");
    assert!(!markdown.contains("showing "), "{markdown}");
    for hidden in [&w.hidden, &comment, "Private comment", "secret remark"] {
        assert!(!rendered.to_string().contains(hidden));
    }
    // Exercise the same all-links render session with a visible child too:
    // hidden rows must not inflate either section's displayed total.
    kernel::add_generic_link_as(&w.db, &w.admin, &w.second, &w.first, "part_of", None)
        .await
        .unwrap();
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::hq::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let visible_home = kernel::hq::v1_import_home_id(&w.first);
    kernel::hq::import_home_as(
        &w.db,
        &host,
        &visible_home,
        &w.first,
        KERNEL_ROOT_ID,
        &w.admin,
        Some(&[(&w.viewer, "view")]),
    )
    .await
    .unwrap();
    sqlx::query("UPDATE kernel_records SET home_id=? WHERE id=?")
        .bind(&visible_home)
        .bind(&w.second)
        .execute(w.db.write_pool())
        .await
        .unwrap();
    let rendered = call(&w, "render_record", json!({"id":w.first}))
        .await
        .unwrap();
    let markdown = rendered["markdown"].as_str().unwrap();
    for heading in ["## Links (incoming)", "## Children"] {
        let section = markdown
            .split_once(heading)
            .unwrap_or_else(|| panic!("missing {heading}: {markdown}"))
            .1;
        let section = section.split("\n## ").next().unwrap();
        assert!(section.contains("Beta"), "{markdown}");
        assert!(section.contains(&w.second), "{markdown}");
    }
    assert!(!markdown.contains("showing "), "{markdown}");
    assert!(!markdown.contains(&w.hidden), "{markdown}");
    assert!(!markdown.contains(&comment), "{markdown}");
    // Imported placement allows a visible child under a hidden logical parent.
    let mapped = kernel::hq::v1_import_home_id(&w.hidden);
    kernel::hq::import_home_as(
        &w.db,
        &host,
        &mapped,
        &w.hidden,
        KERNEL_ROOT_ID,
        &w.admin,
        Some(&[(&w.viewer, "view")]),
    )
    .await
    .unwrap();
    sqlx::query("UPDATE kernel_records SET home_id=? WHERE id=?")
        .bind(&mapped)
        .bind(&w.second)
        .execute(w.db.write_pool())
        .await
        .unwrap();
    let get = call(&w, "get_record", json!({"ids":[w.second]}))
        .await
        .unwrap();
    assert_eq!(get["records"][0]["status"], "found");
    let rendered = call(&w, "render_record", json!({"id":w.second}))
        .await
        .unwrap();
    assert!(!rendered.to_string().contains(&w.hidden));
    assert!(!rendered.to_string().contains("Secret"));
}

/// Bulk projections model read costs without timing 16,500 canonical writes.
#[tokio::test]
async fn record_reads_dashboard_hq_scale() {
    if std::env::var_os("NATIVE_MEASURE_SQL").is_some() {
        use tracing_subscriber::prelude::*;
        let _ = tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_ansi(false)
                    .with_filter(tracing_subscriber::filter::filter_fn(|meta| {
                        meta.target() == "native_ce::read_staging"
                    })),
            )
            .try_init();
    }
    let w = world().await;
    install_comment_carrier(&w).await;
    let mut home = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    for _ in 0..4 {
        home = kernel::create_home(&w.db, &home, None, &w.admin)
            .await
            .unwrap();
    }
    for (typ, kind) in [
        ("WorkItem", "task"),
        ("WorkItem", "issue"),
        ("WorkItem", "project"),
        ("Document", "task"),
    ] {
        let vocab = format!("dashboard:{typ}:{kind}");
        let data = json!({"shapes":{format!("{typ}:{kind}"):{"facets":{"lifecycle":{"axis":{"key":format!("{typ}:{kind}"),"label":"Status"},"vocab_ref":vocab}}}}});
        let schema = json!({"id":format!("schema:{typ}:{kind}"),"layer":"pack","created_at":"2026-11-01T00:00:00Z","data":data.to_string()});
        let mut rows = vec![
            ("schema_config", schema),
            ("vocabularies", json!({"id":vocab,"name":vocab})),
        ];
        for (raw, terminality) in [("open", "open"), ("done", "terminal_positive")] {
            rows.push(("vocabulary_values",json!({"id":format!("{vocab}:{raw}"),"vocabulary_id":vocab,"value":raw,"status":"active","terminality":terminality})));
        }
        for (section, value) in rows {
            sqlx::query("INSERT INTO kernel_v1_state(section,source_id,origin,payload,observed_at,event_seq) VALUES(?,?,'dashboard',?,'2026-11-01T00:00:00Z',0)")
                .bind(section).bind(value["id"].as_str().unwrap()).bind(value.to_string()).execute(w.db.write_pool()).await.unwrap();
        }
    }
    sqlx::query("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<16500) INSERT INTO kernel_records(id,home_id,owner_id,primary_type,kind,accession,pin_family,pin_version,pin_digest,interpreter,created_seq,created_at) SELECT printf('dashboard:%05d',x),CASE WHEN x%2=0 THEN ?2 ELSE r.home_id END,r.owner_id,'WorkItem','record',printf('dashboard:%05d',x),'native.v1.record',1,r.pin_digest,r.interpreter,r.created_seq,r.created_at FROM n CROSS JOIN kernel_records r WHERE r.id=?1")
        .bind(&w.first).bind(&home).execute(w.db.write_pool()).await.unwrap();
    for (name, value) in [("v1_type", "\"WorkItem\""), ("v1_kind", "\"task\"")] {
        sqlx::query("INSERT INTO kernel_record_fields(record_id,name,value_json,created_seq) SELECT id,?, ?,created_seq FROM kernel_records WHERE id LIKE 'dashboard:%'").bind(name).bind(value).execute(w.db.write_pool()).await.unwrap();
    }
    sqlx::query("UPDATE kernel_record_fields SET value_json=json_quote(CASE CAST(substr(record_id,11) AS INTEGER)%3 WHEN 0 THEN 'task' WHEN 1 THEN 'issue' ELSE 'project' END) WHERE name='v1_kind' AND record_id LIKE 'dashboard:%'").execute(w.db.write_pool()).await.unwrap();
    // Same lifecycle and bearer, but distinct type/kind vocabularies: dropping
    // either type or kind from the interpretation cache key must be observable.
    sqlx::query("UPDATE kernel_record_fields SET value_json='\"Document\"' WHERE name='v1_type' AND record_id LIKE 'dashboard:%' AND CAST(substr(record_id,11) AS INTEGER)%6=0").execute(w.db.write_pool()).await.unwrap();
    sqlx::query("INSERT INTO kernel_record_fields(record_id,name,value_json,created_seq) SELECT id,'lifecycle',json_quote(CASE (CAST(substr(id,11) AS INTEGER)/3)%3 WHEN 0 THEN 'open' WHEN 1 THEN 'done' ELSE 'unknown' END),created_seq FROM kernel_records WHERE id LIKE 'dashboard:%' AND CAST(substr(id,11) AS INTEGER)<=3600").execute(w.db.write_pool()).await.unwrap();
    sqlx::query("INSERT INTO kernel_generic_links(link_id,source_id,target_id,relationship,created_at,active,event_seq,imported) SELECT 'edge:'||id,id,?,CASE CAST(substr(id,11) AS INTEGER)%3 WHEN 0 THEN 'blocks' WHEN 1 THEN 'supersedes' ELSE 'depends_on' END,created_at,1,created_seq,1 FROM kernel_records WHERE id LIKE 'dashboard:%' AND CAST(substr(id,11) AS INTEGER)<=300").bind(&w.first).execute(w.db.write_pool()).await.unwrap();
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::hq::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let mapped = kernel::hq::v1_import_home_id(&w.second);
    kernel::hq::import_home_as(
        &w.db,
        &host,
        &mapped,
        &w.second,
        KERNEL_ROOT_ID,
        &w.admin,
        Some(&[(&w.viewer, "view")]),
    )
    .await
    .unwrap();
    kernel::hq::import_event_as(
        &w.db,
        &host,
        &w.second,
        &kernel::hq::LegacyEvent {
            source: None,
            id: "dashboard-provenance".into(),
            event_type: "v1.snapshot_provenance".into(),
            payload: json!({"policy_anchor":w.second,"original_home":w.first}),
            created_at: "2026-11-01T00:00:00Z".into(),
            actor: None,
            run_key: None,
        },
    )
    .await
    .unwrap();
    sqlx::query("UPDATE kernel_records SET home_id=? WHERE id=?")
        .bind(&mapped)
        .bind(&w.second)
        .execute(w.db.write_pool())
        .await
        .unwrap();
    // Exercise the self-bearer exception as well as the shared physical homes.
    sqlx::query("INSERT INTO kernel_record_fields(record_id,name,value_json,created_seq) SELECT id,'lifecycle','\"open\"',created_seq FROM kernel_records WHERE id=?").bind(&w.second).execute(w.db.write_pool()).await.unwrap();
    kernel::ensure_record_metadata(&w.db).await.unwrap();
    for credential in ["acct:admin", "acct:viewer"] {
        for (op, args) in [
            ("get_dashboard", json!({"limit":100})),
            ("resolve_many", json!({"names":["Alpha"]})),
            ("render_record", json!({"id":w.first})),
        ] {
            let started = std::time::Instant::now();
            let (out, stats) = sql::measured(call_as(&w, credential, op, args)).await;
            eprintln!(
                "HQ {credential} {op} elapsed={:?} stats={stats:?} error={:?}",
                started.elapsed(),
                out.as_ref().err()
            );
            let out = out.unwrap();
            if op == "get_dashboard" {
                assert_eq!(
                    out["lifecycle_census"]["total"],
                    if credential == "acct:admin" {
                        16503
                    } else {
                        16502
                    }
                );
                assert_eq!(
                    out["active_total"].as_i64().unwrap() + out["stale_total"].as_i64().unwrap(),
                    2401
                );
                assert_eq!(out["blocked_total"], 101);
                assert_eq!(out["unclassified_lifecycle"]["total_count"], 1201);
                let samples = out["active"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .chain(out["stale"].as_array().unwrap())
                    .filter(|item| item["id"].as_str().unwrap().starts_with("dashboard:"))
                    .take(20)
                    .cloned()
                    .collect::<Vec<_>>();
                assert_eq!(samples.len(), 20);
                let actor = if credential == "acct:admin" {
                    &w.admin
                } else {
                    &w.viewer
                };
                let actor_owned = actor.clone();
                sql::in_snapshot(&w.db, actor, move |conn| Box::pin(async move {
                    let mut groups = std::collections::BTreeSet::new();
                    for item in samples {
                        let id = item["id"].as_str().unwrap();
                        let typ = item["type"].as_str().unwrap();
                        let kind = item["kind"].as_str().unwrap();
                        let raw: String = sqlx::query_scalar("SELECT json_extract(value_json,'$') FROM main.kernel_record_fields WHERE record_id=? AND name='lifecycle'")
                            .bind(id).fetch_one(&mut *conn).await?;
                        let scalar = kernel::v1_state::lifecycle_on(conn, &actor_owned, typ, Some(kind), id, Some(&raw)).await?;
                        assert_eq!(item["lifecycle_interpretation"], scalar, "{id}");
                        if raw == "open" {
                            assert_eq!(scalar["axis"]["key"], format!("{typ}:{kind}"));
                        }
                        groups.insert((typ.to_owned(), kind.to_owned()));
                    }
                    assert_eq!(groups.len(), 4);
                    Ok(())
                })).await.unwrap();
                assert_eq!(stats.installations, 1);
                assert!(!out.to_string().contains(&w.hidden));
            }
        }
    }
    // Make the imported self-bearer's original logical home observable in
    // interpretation, and compare it with the canonical scalar path for both
    // callers. This overlay is visible through Alpha, not the physical home.
    let schema = json!({"id":"schema:self-home","layer":"user","created_at":"2026-11-01T00:00:00Z","applies_to_collection_id":w.first,
        "data":json!({"shapes":{"Document:note":{"facets":{"lifecycle":{"axis":{"key":"self_home","label":"Self home"},"vocab_ref":"dashboard:WorkItem:task"}}}}}).to_string()});
    sqlx::query("INSERT INTO kernel_v1_state(section,source_id,origin,payload,observed_at,event_seq) VALUES('schema_config','schema:self-home','dashboard',?,'2026-11-01T00:00:00Z',0)").bind(schema.to_string()).execute(w.db.write_pool()).await.unwrap();
    sqlx::query("UPDATE kernel_record_metadata SET last_activity_at='2026-01-01T00:00:00Z' WHERE record_id=?").bind(&w.second).execute(w.db.write_pool()).await.unwrap();
    for (credential, actor) in [("acct:admin", &w.admin), ("acct:viewer", &w.viewer)] {
        let out = call_as(&w, credential, "get_dashboard", json!({}))
            .await
            .unwrap();
        let item = out["stale"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["id"] == w.second)
            .unwrap();
        let id = w.second.clone();
        let actor_owned = actor.clone();
        let scalar = sql::in_snapshot(&w.db, actor, move |conn| {
            Box::pin(async move {
                kernel::v1_state::lifecycle_on(
                    conn,
                    &actor_owned,
                    "Document",
                    Some("note"),
                    &id,
                    Some("open"),
                )
                .await
            })
        })
        .await
        .unwrap();
        assert_eq!(item["lifecycle_interpretation"], scalar);
        assert_eq!(scalar["axis"]["key"], "self_home");
    }
    w.db.close().await;
}

#[tokio::test]
async fn record_reads_scan_visibility_defaults_bounds_and_lexical_count() {
    assert_record_read_contract("scan");
    let w = world().await;
    let out = call(&w, "scan", json!({"query":"original","high_degree_min":1}))
        .await
        .unwrap();
    assert_eq!(
        out["axes"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec![
            "authored_by",
            "lexical",
            "recent",
            "high_degree",
            "containers"
        ]
    );
    assert!(out["census"]["by_type"].get("untyped_count").is_none());
    assert!(out["census"]["by_type"]
        .get("interpretation_note")
        .is_none());
    assert_eq!(out["corpus_size"], 2);
    assert_eq!(out["axes"]["lexical"]["count"], 1);
    assert_eq!(out["axes"]["high_degree"]["count"], 2);
    assert_eq!(out["axes"]["high_degree"]["samples"][0]["degree"], 1);
    assert_eq!(out["axes"]["authored_by"]["count"], 0);
    assert_eq!(
        out["census"]["provenance"]["buckets"],
        json!([{"key":"unknown","count":2}])
    );
    assert_eq!(out["thresholds"]["recent_window_days"], 14);
    assert_eq!(out["thresholds"]["saturation_threshold"], 0.10);
    for key in ["by_type", "by_kind", "by_lifecycle", "provenance"] {
        assert_eq!(out["census"][key]["total"], 2);
    }
    let encoded = out.to_string();
    let rendered = render::render("scan", &out).unwrap();
    for forbidden in [
        &w.hidden,
        &w.admin,
        &w.viewer,
        "acct:admin",
        "Admin",
        "Viewer",
    ] {
        assert!(!encoded.contains(forbidden), "{forbidden}: {encoded}");
        assert!(!rendered.contains(forbidden));
    }
    assert!(out["axes"]["high_degree"]["samples"][0]["record_path"].is_string());
    assert!(out["axes"]["high_degree"]["samples"][0]["lifecycle_interpretation"].is_object());
    for args in [
        json!({"recent_window_days":0}),
        json!({"recent_window_days":36501}),
        json!({"high_degree_min":0}),
        json!({"authored_by":"acct:admin"}),
        json!({"scope":w.hidden}),
    ] {
        assert!(call(&w, "scan", args).await.is_err());
    }
    let defaults = call(&w, "scan", json!({})).await.unwrap();
    assert_eq!(defaults["axes"]["high_degree"]["count"], 0);
    assert_eq!(defaults["thresholds"]["high_degree_min"], 8);
    assert_eq!(defaults["thresholds"]["sample_limit"], 3);
    assert_eq!(
        call(&w, "scan", json!({"types":["Entity"]})).await.unwrap()["corpus_size"],
        0
    );
    assert_eq!(
        call(&w, "scan", json!({"query":"   "})).await.unwrap()["axes"].get("lexical"),
        None
    );
    assert_eq!(
        call_as(
            &w,
            "acct:admin",
            "scan",
            json!({"authored_by":"acct:admin"})
        )
        .await
        .unwrap()["axes"]["authored_by"]["count"],
        3
    );
    assert!(call_as(
        &w,
        "acct:admin",
        "scan",
        json!({"authored_by":"acct:missing"})
    )
    .await
    .is_err());
    let home = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let bare = kernel::create_record_as(&w.db, &w.admin, &home)
        .await
        .unwrap();
    let untyped = call(&w, "scan", json!({"scope":bare})).await.unwrap();
    assert_eq!(untyped["corpus_size"], 1);
    assert_eq!(untyped["census"]["by_type"]["untyped_count"], 1);
    let workspace = call(&w, "scan", json!({})).await.unwrap();
    assert_eq!(workspace["corpus_size"], 3);
    assert_eq!(workspace["census"]["by_type"]["untyped_count"], 1);
    assert_eq!(untyped["axes"]["recent"]["samples"][0]["type"], "untyped");
    let owner_untyped = call_as(&w, "acct:admin", "scan", json!({"scope":bare}))
        .await
        .unwrap();
    assert_eq!(owner_untyped["convergence"][0]["id"], bare);
    assert_eq!(
        untyped["census"]["by_type"]["buckets"],
        json!([{"key":null,"count":1}])
    );
    assert!(render::render("scan", &untyped)
        .unwrap()
        .contains("untyped records"));
    w.db.close().await;
}

#[tokio::test]
async fn record_reads_scan_legacy_classes_and_restricted_genesis() {
    let w = world().await;
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::hq::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    for (record, actor, run, subjects) in [
        (&w.first, "acct:viewer", None, vec![w.first.clone()]),
        (
            &w.second,
            "acct:admin",
            Some("secret-worker-run"),
            vec![w.second.clone()],
        ),
    ] {
        kernel::hq::import_event_as(&w.db,&host,record,&kernel::hq::LegacyEvent {
            id:format!("create-{record}"),event_type:"record.created".into(),payload:json!({}),created_at:"2020-01-01T00:00:00Z".into(),actor:Some(actor.into()),run_key:run.map(str::to_owned),
            source:Some(json!({"origin":"synthetic","stream":"content_events","metadata":{"record_id":record},"subjects":subjects})),
        }).await.unwrap();
    }
    kernel::hq::import_event_as(&w.db,&host,&w.first,&kernel::hq::LegacyEvent {
        id:"later-hidden-edit".into(),event_type:"record.updated".into(),payload:json!({}),created_at:"2021-01-01T00:00:00Z".into(),actor:Some("acct:viewer".into()),run_key:None,
        source:Some(json!({"origin":"synthetic","stream":"content_events","metadata":{"record_id":w.first},"subjects":[w.first,w.hidden]})),
    }).await.unwrap();
    let out = call(&w, "scan", json!({"authored_by":"acct:viewer"}))
        .await
        .unwrap();
    assert_eq!(
        out["census"]["provenance"]["buckets"],
        json!([{"key":"agent","count":1},{"key":"you","count":1}])
    );
    assert_eq!(out["axes"]["authored_by"]["count"], 1);
    assert_eq!(
        out["axes"]["authored_by"]["samples"][0]["authored_at"],
        "2020-01-01T00:00:00Z"
    );
    for text in [out.to_string(), render::render("scan", &out).unwrap()] {
        for forbidden in [
            &host,
            &w.admin,
            &w.viewer,
            "secret-worker-run",
            "acct:viewer",
            "acct:admin",
        ] {
            assert!(!text.contains(forbidden));
        }
    }
    // An admitted source birth replaces the import/native genesis. A source
    // restricted birth is unknown, never host attribution.
    let w2 = world().await;
    let host2 = kernel::resolve_principal_by_binding(&w2.db, kernel::hq::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    kernel::hq::import_event_as(&w2.db,&host2,&w2.first,&kernel::hq::LegacyEvent {
        id:"restricted-create".into(),event_type:"record.created".into(),payload:json!({}),created_at:"2020-01-01T00:00:00Z".into(),actor:Some("acct:viewer".into()),run_key:Some("hidden-run-key".into()),
        source:Some(json!({"origin":"synthetic","stream":"content_events","metadata":{"record_id":w2.first},"subjects":[w2.first]})),
    }).await.unwrap();
    // Fabricate a retained restricted header to exercise its independent gate.
    sqlx::query("UPDATE kernel_legacy_history SET restricted=1,owner='acct:admin' WHERE seq=(SELECT seq FROM kernel_legacy_sql_events WHERE source_id='restricted-create')").execute(w2.db.write_pool()).await.unwrap();
    let out = call(&w2, "scan", json!({})).await.unwrap();
    assert_eq!(
        out["census"]["provenance"]["buckets"],
        json!([{"key":"unknown","count":2}])
    );
    assert!(!out.to_string().contains("hidden-run-key"));
    let root = call_as(&w2, "acct:admin", "scan", json!({})).await.unwrap();
    assert!(root["census"]["provenance"]["buckets"]
        .as_array()
        .unwrap()
        .contains(&json!({"key":"you","count":2})));
    w.db.close().await;
    w2.db.close().await;
}

#[tokio::test]
async fn record_reads_scan_scope_archives_children_and_convergence() {
    let w = world().await;
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::hq::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let home = kernel::hq::v1_import_home_id(&w.first);
    kernel::hq::import_home_as(
        &w.db,
        &host,
        &home,
        &w.first,
        KERNEL_ROOT_ID,
        &w.admin,
        Some(&[]),
    )
    .await
    .unwrap();
    sqlx::query("UPDATE kernel_records SET home_id=?,owner_id=? WHERE id=?")
        .bind(&home)
        .bind(&w.viewer)
        .bind(&w.second)
        .execute(w.db.write_pool())
        .await
        .unwrap();
    // The private record has logical placement under Alpha but stays hidden.
    kernel::add_generic_link_as(&w.db, &w.admin, &w.hidden, &w.first, "part_of", None)
        .await
        .unwrap();
    // The closed child home admits Beta through its owner floor while
    // Secret remains hidden under the same logical parent.
    sqlx::query("UPDATE kernel_records SET home_id=? WHERE id=?")
        .bind(&home)
        .bind(&w.hidden)
        .execute(w.db.write_pool())
        .await
        .unwrap();
    let out = call(&w, "scan", json!({"scope":w.first,"high_degree_min":1}))
        .await
        .unwrap();
    assert_eq!(out["corpus_size"], 2);
    assert_eq!(out["axes"]["containers"]["count"], 1);
    assert_eq!(out["axes"]["containers"]["samples"][0]["child_count"], 1);
    assert_eq!(out["convergence"][0]["id"], w.first);
    let short = out["axes"]["containers"]["samples"][0]["display_reference"].clone();
    assert_eq!(
        call(&w, "scan", json!({"scope":short})).await.unwrap()["corpus_size"],
        2
    );
    let rev = kernel::read_record_as(&w.db, &w.viewer, &w.second)
        .await
        .unwrap()
        .unwrap()
        .revision;
    kernel::set_archived_as(&w.db, &w.viewer, &w.second, true, rev)
        .await
        .unwrap();
    assert_eq!(call(&w, "scan", json!({})).await.unwrap()["corpus_size"], 1);
    assert_eq!(
        call(&w, "scan", json!({"include_archived":true}))
            .await
            .unwrap()["corpus_size"],
        2
    );
    assert_eq!(
        call(&w, "scan", json!({"scope":w.first,"include_archived":true}))
            .await
            .unwrap()["corpus_size"],
        1
    );
    let error = call(
        &w,
        "scan",
        json!({"scope":w.second,"include_archived":true}),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("archived"));
    w.db.close().await;
}

#[tokio::test]
async fn record_reads_scan_thousands_of_records_exact_pools_and_sample_cap() {
    let w = world().await;
    sqlx::query("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<3000) INSERT INTO kernel_records(id,home_id,owner_id,primary_type,kind,accession,pin_family,pin_version,pin_digest,interpreter,created_seq,created_at) SELECT printf('scan:%05d',x),r.home_id,r.owner_id,r.primary_type,r.kind,printf('scan-accession:%05d',x),r.pin_family,r.pin_version,r.pin_digest,r.interpreter,r.created_seq,r.created_at FROM n CROSS JOIN kernel_records r WHERE r.id=?")
        .bind(&w.first).execute(w.db.write_pool()).await.unwrap();
    sqlx::query("INSERT INTO kernel_record_fields(record_id,name,value_json,created_seq) SELECT id,'title',json_quote(id),created_seq FROM kernel_records WHERE id LIKE 'scan:%'").execute(w.db.write_pool()).await.unwrap();
    sqlx::query("INSERT INTO kernel_search_fts(record_id,title,summary,body) SELECT id,'scan','','' FROM kernel_records WHERE id LIKE 'scan:%'").execute(w.db.write_pool()).await.unwrap();
    sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) SELECT 'scan-event:'||id,id,'kernel.record_revised.v1','{}',?,'2026-11-08T00:00:00Z',1,'legacy_unknown' FROM kernel_records WHERE id LIKE 'scan:%'").bind(&w.admin).execute(w.db.write_pool()).await.unwrap();
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let home = kernel::hq::v1_import_home_id(&w.first);
    kernel::hq::import_home_as(
        &w.db,
        &host,
        &home,
        &w.first,
        KERNEL_ROOT_ID,
        &w.admin,
        Some(&[(&w.viewer, "view")]),
    )
    .await
    .unwrap();
    sqlx::query("UPDATE kernel_records SET home_id=? WHERE id LIKE 'scan:%'")
        .bind(home)
        .execute(w.db.write_pool())
        .await
        .unwrap();
    let started = std::time::Instant::now();
    let out = call(
        &w,
        "scan",
        json!({"query":"scan","scope":w.first,"high_degree_min":1}),
    )
    .await
    .unwrap();
    eprintln!(
        "scan 3001 scoped records from 3002 visible records: {:?}",
        started.elapsed()
    );
    assert_eq!(out["corpus_size"], 3001);
    assert_eq!(out["axes"]["high_degree"]["quality"], "focused");
    assert_eq!(out["axes"]["authored_by"]["quality"], "empty");
    assert_eq!(out["axes"]["lexical"]["quality"], "saturated");
    assert_eq!(out["census"]["by_type"]["total"], 3001);
    let root = call_as(&w, "acct:admin", "scan", json!({})).await.unwrap();
    assert_eq!(root["axes"]["authored_by"]["count"], 3003);
    assert_eq!(out["axes"]["lexical"]["count"], 3000);
    assert_eq!(
        out["axes"]["lexical"]["samples"].as_array().unwrap().len(),
        3
    );
    assert_eq!(
        root["axes"]["authored_by"]["samples"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert_eq!(root["axes"]["authored_by"]["quality"], "saturated");
    for axis in out["axes"].as_object().unwrap().values() {
        assert!(axis["samples"].as_array().unwrap().len() <= 3);
    }
    w.db.close().await;
}

#[tokio::test]
async fn record_reads_scan_native_self_and_owner_named_account() {
    let w = world().await;
    let home = kernel::create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.viewer, "edit")]),
        &w.admin,
    )
    .await
    .unwrap();
    let id = kernel::create_as(
        &w.db,
        &w.viewer,
        "fixture.mcp",
        "note",
        json!({"title":"Own note"}).as_object().unwrap(),
        &home,
    )
    .await
    .unwrap();
    let out = call(&w, "scan", json!({})).await.unwrap();
    assert_eq!(out["axes"]["authored_by"]["count"], 1, "{out}");
    assert_eq!(out["axes"]["authored_by"]["samples"][0]["id"], id);
    assert!(out["census"]["provenance"]["buckets"]
        .as_array()
        .unwrap()
        .contains(&json!({"key":"you","count":1})));
    let private = kernel::read_record_as(&w.db, &w.admin, &w.hidden)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    kernel::replace_home_policy(&w.db, &w.admin, &private, &[(&w.viewer, "view")])
        .await
        .unwrap();
    kernel::link_as(&w.db, &w.viewer, &id, "relates_to", &w.hidden)
        .await
        .unwrap();
    kernel::replace_home_policy(&w.db, &w.admin, &private, &[])
        .await
        .unwrap();
    let after = call(&w, "scan", json!({})).await.unwrap();
    assert_eq!(
        after["axes"]["authored_by"], out["axes"]["authored_by"],
        "a now-hidden endpoint must not supply authored evidence"
    );
    // Root/home ownership does not bypass an explicit record visibility
    // boundary. Grant View before expecting the owner's named-account read.
    let hidden_from_owner = call_as(
        &w,
        "acct:admin",
        "scan",
        json!({"authored_by":"acct:viewer"}),
    )
    .await
    .unwrap();
    assert_eq!(hidden_from_owner["axes"]["authored_by"]["count"], 0);
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        &home,
        &[(&w.viewer, "edit"), (&w.admin, "view")],
    )
    .await
    .unwrap();
    let root = call_as(
        &w,
        "acct:admin",
        "scan",
        json!({"authored_by":"acct:viewer"}),
    )
    .await
    .unwrap();
    assert_eq!(root["axes"]["authored_by"]["count"], 1, "{root}");
    assert!(root["census"]["provenance"]["buckets"]
        .as_array()
        .unwrap()
        .contains(&json!({"key":"other_account","count":1})));
    assert_eq!(root["axes"]["authored_by"]["samples"][0]["id"], id);
    assert!(call(&w, "scan", json!({"authored_by":"acct:admin"}))
        .await
        .is_err());
    w.db.close().await;
}

#[tokio::test]
async fn record_reads_scan_successors_and_hidden_endpoint_invariance() {
    let w = world().await;
    let baseline = call(&w, "scan", json!({"high_degree_min":1}))
        .await
        .unwrap();
    kernel::add_generic_link_as(&w.db, &w.admin, &w.hidden, &w.first, "supersedes", None)
        .await
        .unwrap();
    let hidden = call(&w, "scan", json!({"high_degree_min":1}))
        .await
        .unwrap();
    for key in [
        "corpus_size",
        "census",
        "axes",
        "convergence",
        "convergence_basis",
    ] {
        assert_eq!(baseline[key], hidden[key], "hidden endpoint changed {key}");
    }
    kernel::add_generic_link_as(&w.db, &w.admin, &w.second, &w.first, "supersedes", None)
        .await
        .unwrap();
    let out = call(&w, "scan", json!({"high_degree_min":1}))
        .await
        .unwrap();
    let sample = out["axes"]["high_degree"]["samples"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == w.first)
        .unwrap();
    assert_eq!(sample["superseded_by"]["total_count"], 1);
    assert_eq!(sample["superseded_by"]["items"][0]["id"], w.second);
    assert!(!out.to_string().contains(&w.hidden));
    let mut marked = out.clone();
    marked["axes"]["lexical"] =
        json!({"count":10,"samples":[],"quality":"focused","sample_selection_bounded":true});
    assert!(render::render("scan", &marked)
        .unwrap()
        .contains("pool count is exact"));
    w.db.close().await;
}

#[tokio::test]
async fn record_reads_scan_import_genesis_credits_original_author() {
    let w = world().await;
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let home = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let definition = json!({"family":"fixture.scan.imported","version":1,"interpreter":"native.defn/4","primary_type":"Document","kinds":[{"token":"note","description":"Scan import","maturity":"current","identity":{"mode":"record"},"fields":[{"name":"title","type":"text","required":true}],"links":[]}]});
    let pin = kernel::install_definition_as(
        &w.db,
        &w.admin,
        "fixture.scan.imported",
        1,
        &serde_json::to_vec(&definition).unwrap(),
    )
    .await
    .unwrap();
    kernel::adopt_definition_as(&w.db, &w.admin, &pin.family, Some(&pin))
        .await
        .unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    kernel::import_record_as(
        &w.db,
        &host,
        &id,
        &home,
        Some(&w.admin),
        &kernel::ImportRecordState {
            definition: Some(kernel::ImportDefinition {
                pin,
                primary_type: "Document".into(),
                kind: "note".into(),
                fields: json!({"title":"Imported note"})
                    .as_object()
                    .unwrap()
                    .clone(),
            }),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let before = call(&w, "scan", json!({"scope":id})).await.unwrap();
    assert_eq!(
        before["census"]["provenance"]["buckets"],
        json!([{"key":"unknown","count":1}])
    );
    kernel::hq::import_event_as(&w.db,&host,&id,&kernel::hq::LegacyEvent {
        id:"source-create".into(),event_type:"record.created".into(),payload:json!({}),created_at:"2020-01-01T00:00:00Z".into(),actor:Some("acct:viewer".into()),run_key:None,
        source:Some(json!({"origin":"synthetic","stream":"content_events","metadata":{"record_id":id},"subjects":[id]})),
    }).await.unwrap();
    let after = call(&w, "scan", json!({"scope":id})).await.unwrap();
    assert_eq!(
        after["census"]["provenance"]["buckets"],
        json!([{"key":"you","count":1}])
    );
    assert_eq!(after["axes"]["authored_by"]["count"], 1);
    w.db.close().await;
}

#[test]
fn record_reads_scan_convergence_orders_count_name_and_id() {
    let z = json!({"id":"4","type":"Document","name":"Zeta"});
    let b1 = json!({"id":"1","type":"Document","name":"Beta"});
    let b2 = json!({"id":"2","type":"Document","name":"Beta"});
    let g = json!({"id":"3","type":"Document","name":"Gamma"});
    let axes = json!({
        "lexical":{"samples":[z,b2,g]},
        "recent":{"samples":[z,b1,g]},
        "high_degree":{"samples":[z,b1,b2]},
        "containers":{"samples":[z]},
    });
    let result = crate::mcp::tools::querying::build_scan_convergence(axes.as_object().unwrap());
    assert_eq!(
        result
            .iter()
            .map(|v| v["id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["4", "1", "2", "3"]
    );
    assert_eq!(result[0]["axis_count"], 4);
    assert!(result[1..].iter().all(|v| v["axis_count"] == 2));
}

#[tokio::test]
async fn record_reads_scan_long_unadmitted_chain() {
    let w = world().await;
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    kernel::hq::import_event_as(&w.db,&host,&w.first,&kernel::hq::LegacyEvent {
        id:"scan-chain-birth".into(),event_type:"record.created".into(),payload:json!({}),created_at:"2020-01-01T00:00:00Z".into(),actor:Some("acct:viewer".into()),run_key:None,
        source:Some(json!({"origin":"synthetic","stream":"content_events","metadata":{"record_id":w.first},"subjects":[w.first]})),
    }).await.unwrap();
    sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) VALUES('admitted-scan-edit',?,'kernel.record_revised.v1','{}',?,'2020-02-01T00:00:00Z',1,'legacy_unknown')")
        .bind(&w.first).bind(&w.viewer).execute(w.db.write_pool()).await.unwrap();
    sqlx::query("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<4096) INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) SELECT 'hidden-chain:'||x,?1,'kernel.link_removed.v1',json_object('target_id',?2),?3,'2021-01-01T00:00:00Z',1,'legacy_unknown' FROM n")
        .bind(&w.first).bind(&w.hidden).bind(&w.viewer).execute(w.db.write_pool()).await.unwrap();
    sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) VALUES('scan-no-admitted-history',?1,'kernel.link_removed.v1',json_object('target_id',?2),?3,'2021-01-01T00:00:00Z',1,'legacy_unknown')")
        .bind(&w.second).bind(&w.hidden).bind(&w.viewer).execute(w.db.write_pool()).await.unwrap();
    let out = call(&w, "scan", json!({})).await.unwrap();
    assert_eq!(out["axes"]["authored_by"]["count"], 1);
    assert_eq!(
        out["axes"]["authored_by"]["samples"][0]["authored_at"],
        "2020-02-01T00:00:00Z"
    );
    assert!(!out.to_string().contains("hidden-chain"));
    w.db.close().await;
}

#[tokio::test]
async fn record_reads_scan_lexical_sample_reaches_real_candidate_bound() {
    let w = world().await;
    // Body-only hits never fill the title tier's early-exit condition.
    sqlx::query("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<5100) INSERT INTO kernel_records(id,home_id,owner_id,primary_type,kind,accession,pin_family,pin_version,pin_digest,interpreter,created_seq,created_at) SELECT printf('bound:%05d',x),r.home_id,r.owner_id,r.primary_type,r.kind,printf('bound-accession:%05d',x),r.pin_family,r.pin_version,r.pin_digest,r.interpreter,r.created_seq,r.created_at FROM n CROSS JOIN kernel_records r WHERE r.id=?")
        .bind(&w.first).execute(w.db.write_pool()).await.unwrap();
    sqlx::query("INSERT INTO kernel_record_fields(record_id,name,value_json,created_seq) SELECT id,'title',json_quote(id),created_seq FROM kernel_records WHERE id LIKE 'bound:%'").execute(w.db.write_pool()).await.unwrap();
    sqlx::query("INSERT INTO kernel_search_fts(record_id,title,summary,body) SELECT id,id,'','boundneedle' FROM kernel_records WHERE id LIKE 'bound:%'").execute(w.db.write_pool()).await.unwrap();
    // This exercises the real 5,000-candidate boundary, not latency. Keep
    // staging on its production budget; allow snapshot work extra time
    // under parallel test contention.
    let out = sql::TEST_SNAPSHOT_BUDGET
        .scope(
            std::time::Duration::from_secs(10),
            call(&w, "scan", json!({"query":"boundneedle"})),
        )
        .await
        .unwrap();
    assert_eq!(out["axes"]["lexical"]["count"], 5100);
    assert_eq!(
        out["axes"]["lexical"]["samples"].as_array().unwrap().len(),
        3
    );
    assert_eq!(out["axes"]["lexical"]["sample_selection_bounded"], true);
    assert!(render::render("scan", &out)
        .unwrap()
        .contains("search candidate bound"));
    w.db.close().await;
}

#[tokio::test]
async fn record_reads_scan_attribution_budget_exhaustion_is_explicit() {
    let w = world().await;
    // Give the caller admitted authored history so convergence would otherwise
    // include this axis; exhaustion must discard that contribution.
    sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) VALUES('budget-visible-edit',?1,'kernel.record_revised.v1','{}',?2,'2026-01-01T00:00:00Z',1,'legacy_unknown')")
        .bind(&w.first).bind(&w.viewer).execute(w.db.write_pool()).await.unwrap();
    let args = json!({"query":"Alpha","high_degree_min":1});
    let normal = call(&w, "scan", args.clone()).await.unwrap();
    assert!(normal["census"]["provenance"]["buckets"].is_array());
    assert!(normal.get("convergence_basis").is_none());
    assert_eq!(normal["axes"]["authored_by"]["count"], 1);
    assert!(normal["convergence"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["axes"]
            .as_array()
            .unwrap()
            .contains(&json!("authored_by"))));
    let exhausted = sql::TEST_SCAN_ATTRIBUTION_BUDGET
        .scope(std::time::Duration::ZERO, call(&w, "scan", args.clone()))
        .await
        .unwrap();
    let marker = json!({"status":"unavailable","reason":"attribution_budget_exhausted",
        "interpretation_note":"Attribution exceeded its time budget; provenance and authored_by are unavailable, including authored_by contributions to convergence."});
    assert_eq!(exhausted["census"]["provenance"], marker);
    assert_eq!(exhausted["axes"]["authored_by"], marker);
    assert_eq!(exhausted["corpus_size"], normal["corpus_size"]);
    for axis in ["lexical", "recent", "high_degree", "containers"] {
        assert_eq!(exhausted["axes"][axis], normal["axes"][axis]);
    }
    for name in ["by_type", "by_kind", "by_lifecycle"] {
        assert_eq!(exhausted["census"][name], normal["census"][name]);
    }
    let mut available_axes = normal["axes"].as_object().unwrap().clone();
    available_axes.shift_remove("authored_by");
    assert_eq!(
        exhausted["convergence"],
        json!(crate::mcp::tools::querying::build_scan_convergence(
            &available_axes
        ))
    );
    assert_eq!(
        exhausted["convergence_basis"],
        json!({
            "kind":"served_axes",
            "axes":crate::mcp::tools::querying::served_scan_axes(&available_axes),
            "excluded_axes":["authored_by"],
        })
    );
    // Exit after populated headers, admitted event rows, and latest positions.
    // These leave partially filled TEMP tables in the shared snapshot; the
    // remaining scan still succeeds and a subsequent read sees no residue.
    for checkpoint in [4, 7, 9] {
        let midflight = sql::TEST_SCAN_ATTRIBUTION_EXIT_AT
            .scope(std::cell::Cell::new(checkpoint), async {
                let result = call(&w, "scan", args.clone()).await;
                assert_eq!(
                    sql::TEST_SCAN_ATTRIBUTION_EXIT_AT.with(std::cell::Cell::get),
                    0
                );
                result
            })
            .await
            .unwrap();
        for key in [
            "corpus_size",
            "census",
            "axes",
            "convergence",
            "convergence_basis",
        ] {
            assert_eq!(
                midflight[key], exhausted[key],
                "checkpoint {checkpoint}: {key}"
            );
        }
    }
    let text = render::render("scan", &exhausted).unwrap();
    assert!(text.contains("provenance: unavailable (attribution_budget_exhausted)"));
    assert!(text.contains("authored_by: unavailable (attribution_budget_exhausted)"));
    assert!(text.contains("authored_by contributions to convergence are unavailable"));
    assert!(!text.contains("authored_by: 0"));
    assert!(!text.contains("provenance: 0"));
    // Even with a zero budget, selector validation is never bypassed.
    assert!(sql::TEST_SCAN_ATTRIBUTION_BUDGET
        .scope(
            std::time::Duration::ZERO,
            call(&w, "scan", json!({"authored_by":"acct:missing"}))
        )
        .await
        .is_err());
    // Hidden history changes neither the fixed marker nor the visible answer.
    sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) VALUES('budget-hidden-event',?1,'kernel.link_removed.v1',json_object('target_id',?2),?3,'2026-01-01T00:00:00Z',1,'legacy_unknown')")
        .bind(&w.first).bind(&w.hidden).bind(&w.admin).execute(w.db.write_pool()).await.unwrap();
    let after = sql::TEST_SCAN_ATTRIBUTION_BUDGET
        .scope(std::time::Duration::ZERO, call(&w, "scan", args))
        .await
        .unwrap();
    for key in [
        "corpus_size",
        "census",
        "axes",
        "convergence",
        "convergence_basis",
    ] {
        assert_eq!(after[key], exhausted[key], "{key}");
    }
    // The override is task-local; the normal response remains unchanged.
    assert_eq!(
        call(&w, "scan", json!({"query":"Alpha","high_degree_min":1}))
            .await
            .unwrap()["census"]["provenance"],
        normal["census"]["provenance"]
    );
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
fn small_read_detailed_call<'a, F>(
    candidates: bool,
    links: bool,
    trial_indexes: bool,
    barrier: Option<std::sync::Arc<tokio::sync::Barrier>>,
    work: F,
) -> futures::future::BoxFuture<'a, (F::Output, Value)>
where
    F: std::future::Future + Send + 'a,
    F::Output: Send,
{
    Box::pin(async move {
        use kernel::generic_links::diagnostics::{with_link_read_diagnostics, Options};
        if candidates && links {
            let ((out, link_details), candidate_details) = sql::with_candidate_diagnostics(
                trial_indexes,
                with_link_read_diagnostics(
                    Options {
                        explain: true,
                        before_batch: barrier,
                    },
                    work,
                ),
            )
            .await;
            (
                out,
                json!({"candidates":candidate_details,"links":link_details}),
            )
        } else if candidates {
            let (out, details) = sql::with_candidate_diagnostics(trial_indexes, work).await;
            (out, json!({"candidates":details}))
        } else if links {
            let (out, details) = with_link_read_diagnostics(
                Options {
                    explain: true,
                    before_batch: barrier,
                },
                work,
            )
            .await;
            (out, json!({"links":details}))
        } else {
            (work.await, Value::Null)
        }
    })
}

/// Canonical provider fixture: fixed selected degree, independently sized
/// unrelated aggregate fleet. Setup is never included in serving latency.
#[cfg(feature = "v2-kernel-probe")]
fn small_read_provider_fixture<'a>(
    w: &'a World,
    home: &'a str,
    unrelated: usize,
    slots: usize,
) -> futures::future::BoxFuture<'a, (String, String)> {
    Box::pin(async move {
        assert!(unrelated <= slots);
        use crate::v2_standard::relates_to::{Command, Source};
        let package = crate::v2_standard::relates_to::package();
        let installed = kernel::install_package_as(&w.db, &w.admin, &package)
            .await
            .unwrap();
        kernel::adopt_package_at(
            &w.db,
            &w.admin,
            KERNEL_ROOT_ID,
            &package,
            Some(&installed),
            &package.declared_reads,
        )
        .await
        .unwrap();
        let anchor = kernel::create_record_as(&w.db, &w.admin, home)
            .await
            .unwrap();
        let target = kernel::create_record_as(&w.db, &w.admin, home)
            .await
            .unwrap();
        let empty = kernel::create_record_as(&w.db, &w.admin, home)
            .await
            .unwrap();
        let sources = [
            ("diag-provider-a", &anchor, &target),
            ("diag-provider-b", &anchor, &target),
            ("diag-provider-reverse", &target, &anchor),
        ]
        .into_iter()
        .map(|(id, from, to)| Source {
            source_id: id.into(),
            from: from.clone(),
            to: to.clone(),
            claimed_author: None,
            claimed_timestamp: Some("2026-09-03T12:34:56+01:00".into()),
            note: Some(format!("note for {id}")),
        })
        .collect();
        let request = kernel::prepare_provider_as(
            &w.db,
            &w.admin,
            &anchor,
            &target,
            "diag-provider-selected",
            Command::Assert { sources },
        )
        .await
        .unwrap();
        kernel::commit_provider_as(&w.db, &w.admin, &request)
            .await
            .unwrap();
        let request = kernel::prepare_provider_as(
            &w.db,
            &w.admin,
            &anchor,
            &w.hidden,
            "diag-provider-hidden",
            Command::Assert { sources: vec![] },
        )
        .await
        .unwrap();
        kernel::commit_provider_as(&w.db, &w.admin, &request)
            .await
            .unwrap();
        if slots > 0 {
            let fleet_anchor = kernel::create_record_as(&w.db, &w.admin, home)
                .await
                .unwrap();
            for index in 0..slots {
                let endpoint = kernel::create_record_as(&w.db, &w.admin, home)
                    .await
                    .unwrap();
                if index >= unrelated {
                    continue;
                }
                let request = kernel::prepare_provider_as(
                    &w.db,
                    &w.admin,
                    &fleet_anchor,
                    &endpoint,
                    &format!("diag-provider-fleet:{index}"),
                    Command::Assert { sources: vec![] },
                )
                .await
                .unwrap();
                kernel::commit_provider_as(&w.db, &w.admin, &request)
                    .await
                    .unwrap();
            }
        }
        (anchor, empty)
    })
}

#[cfg(feature = "v2-kernel-probe")]
fn small_read_candidate_index_fixture(w: &World) -> futures::future::BoxFuture<'_, Value> {
    Box::pin(async move {
        let page_size: i64 = sqlx::query_scalar("PRAGMA page_size")
            .fetch_one(w.db.write_pool())
            .await
            .unwrap();
        let mut costs = Vec::new();
        for (name, ddl) in [
            ("idx_trial_record_names", "CREATE INDEX idx_trial_record_names ON kernel_record_fields(json_extract(value_json,'$') COLLATE BINARY,record_id) WHERE name IN ('title','name')"),
            ("idx_trial_move_destinations", "CREATE INDEX idx_trial_move_destinations ON content_events(json_extract(payload,'$.logical_home_id'),record_id) WHERE type IN ('kernel.record_rehomed.v1','kernel.record_rehomed.v2')"),
        ] {
            let pages: i64 = sqlx::query_scalar("PRAGMA page_count").fetch_one(w.db.write_pool()).await.unwrap();
            let free: i64 = sqlx::query_scalar("PRAGMA freelist_count").fetch_one(w.db.write_pool()).await.unwrap();
            let started = std::time::Instant::now();
            sqlx::query(ddl).execute(w.db.write_pool()).await.unwrap();
            let create_us = started.elapsed().as_micros() as u64;
            let pages_after: i64 = sqlx::query_scalar("PRAGMA page_count").fetch_one(w.db.write_pool()).await.unwrap();
            let free_after: i64 = sqlx::query_scalar("PRAGMA freelist_count").fetch_one(w.db.write_pool()).await.unwrap();
            costs.push(json!({"index":name,"create_us":create_us,"page_size":page_size,"allocated_bytes_delta":((pages_after-free_after)-(pages-free))*page_size,"storage_measurement":"logical allocated main-database pages; not physical I/O or WAL bytes"}));
        }
        json!(costs)
    })
}

#[cfg(feature = "v2-kernel-probe")]
fn small_read_index_write_probe<'a>(
    w: &'a World,
    id: &'a str,
    home: &'a str,
    folder: &'a str,
    pairs: usize,
) -> futures::future::BoxFuture<'a, Value> {
    Box::pin(async move {
        let mut rename = Vec::new();
        let mut moves = Vec::new();
        for wave in 0..=pairs {
            for name in [
                format!("Diagnostic rename {wave}"),
                "Diagnostic write probe".into(),
            ] {
                let started = std::time::Instant::now();
                call_as(
                    w,
                    "acct:admin",
                    "update_record",
                    json!({"id":id,"name":name}),
                )
                .await
                .unwrap();
                if wave > 0 {
                    rename.push(started.elapsed().as_micros() as u64);
                }
            }
            for destination in [folder, home] {
                let started = std::time::Instant::now();
                call_as(
                    w,
                    "acct:admin",
                    "update_record",
                    json!({"id":id,"home_id":destination}),
                )
                .await
                .unwrap();
                if wave > 0 {
                    moves.push(started.elapsed().as_micros() as u64);
                }
            }
        }
        let actual = kernel::read_record_as(&w.db, &w.admin, id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(actual.home_id, home);
        json!({"rename_call_us":rename,"move_call_us":moves,"warmup_requests":4,"failures":0,"method":"sequential canonical MCP updates; one warmup pair excluded per operation; histories grow and order is not randomized"})
    })
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn record_reads_disposable_indexes_preserve_names_moves_and_canonical_writes() {
    let w = Box::pin(world()).await;
    Box::pin(install_comment_carrier(&w)).await;
    let home = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let private = kernel::read_record_as(&w.db, &w.admin, &w.hidden)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    for (id, placement, fields) in [
        ("trial:duplicate", &home, json!({"title":"Alpha"})),
        ("trial:hidden", &private, json!({"title":"Alpha"})),
        (
            "trial:shadowed",
            &home,
            json!({"title":"Display","name":"Alpha"}),
        ),
        ("trial:null", &home, json!({"title":null,"name":"Fallback"})),
        (
            "trial:numeric",
            &home,
            json!({"title":10,"name":"Numeric fallback"}),
        ),
        (
            "trial:empty",
            &home,
            json!({"title":"","name":"Hidden fallback"}),
        ),
        (
            "trial:escaped",
            &home,
            json!({"title":"Quoted \"name\"\nλ"}),
        ),
    ] {
        Box::pin(small_read_fixture_record(&w, id, placement, fields)).await;
    }
    let package = crate::v2_standard::document_package();
    let installed = Box::pin(kernel::install_package_as(&w.db, &w.admin, &package))
        .await
        .unwrap();
    Box::pin(kernel::adopt_package_at(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &package,
        Some(&installed),
        &package.declared_reads,
    ))
    .await
    .unwrap();
    let folder = Box::pin(call_as(
        &w,
        "acct:admin",
        "create_record",
        json!({"type":"Collection","kind":"folder","name":"Write destination","home_id":home}),
    ))
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let record = Box::pin(call_as(
        &w,
        "acct:admin",
        "create_record",
        json!({"type":"Document","kind":"note","name":"Diagnostic write probe","home_id":home}),
    ))
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    small_read_index_write_probe(&w, &record, &home, &folder, 1).await;
    small_read_candidate_index_fixture(&w).await;
    small_read_index_write_probe(&w, &record, &home, &folder, 1).await;
    let fresh_folder = Box::pin(call_as(
        &w,
        "acct:admin",
        "create_record",
        json!({"type":"Collection","kind":"folder","name":"Post-index destination","home_id":home}),
    ))
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    Box::pin(call_as(
        &w,
        "acct:admin",
        "update_record",
        json!({"id":record,"name":"Post-index renamed","home_id":fresh_folder}),
    ))
    .await
    .unwrap();
    for credential in ["acct:admin", "acct:viewer"] {
        let args = json!({"names":["Alpha","alpha","Fallback","Display","10","Numeric fallback","Hidden fallback","Quoted \"name\"\nλ","Post-index renamed","Diagnostic write probe","Diagnostic rename 0","Diagnostic rename 1","Missing"]});
        let expected = record_reads::with_full_small_read_staging(call_as(
            &w,
            credential,
            "resolve_many",
            args.clone(),
        ))
        .await
        .unwrap();
        let (actual, details) = small_read_detailed_call(
            true,
            false,
            true,
            None,
            call_as(&w, credential, "resolve_many", args),
        )
        .await;
        assert_eq!(actual.unwrap(), expected);
        assert_eq!(details["candidates"][0]["trial_indexes"], true);
        for id in [&record, &folder, &fresh_folder] {
            let args = json!({"id":id});
            let expected = record_reads::with_full_small_read_staging(call_as(
                &w,
                credential,
                "render_record",
                args.clone(),
            ))
            .await
            .unwrap();
            let (actual, _) = small_read_detailed_call(
                true,
                false,
                true,
                None,
                call_as(&w, credential, "render_record", args),
            )
            .await;
            assert_eq!(actual.unwrap(), expected);
        }
    }
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn record_reads_detailed_probes_preserve_orphan_receipts_and_missing_anchors() {
    let w = Box::pin(world()).await;
    let home = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let (anchor, _) = small_read_provider_fixture(&w, &home, 2, 2).await;
    // A retained event need not have a live projected subject. Serving ignores
    // that receipt; diagnostics must report it without inventing a record.
    sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) VALUES('diag-orphan-move','diag:absent-subject','kernel.record_rehomed.v2',json_object('new_home_id',?1,'logical_home_id',?2,'parent_update',NULL),?3,'2026-01-01T00:00:00Z',1,'legacy_unknown')")
        .bind(&home).bind(&anchor).bind(&w.admin).execute(w.db.write_pool()).await.unwrap();
    for credential in ["acct:admin", "acct:viewer"] {
        let args = json!({"id":anchor});
        let expected = record_reads::with_full_small_read_staging(call_as(
            &w,
            credential,
            "render_record",
            args.clone(),
        ))
        .await
        .unwrap();
        let (actual, details) = small_read_detailed_call(
            true,
            true,
            false,
            None,
            call_as(&w, credential, "render_record", args),
        )
        .await;
        assert_eq!(actual.unwrap(), expected);
        assert_eq!(details["candidates"][0]["orphan_lookup_ids"], 1);
        assert_eq!(details["links"][0]["succeeded"], true);
        let args = json!({"names":["Alpha","alpha","Secret","Missing"]});
        let expected = record_reads::with_full_small_read_staging(call_as(
            &w,
            credential,
            "resolve_many",
            args.clone(),
        ))
        .await
        .unwrap();
        let (actual, details) = small_read_detailed_call(
            true,
            false,
            false,
            None,
            call_as(&w, credential, "resolve_many", args),
        )
        .await;
        assert_eq!(actual.unwrap(), expected);
        assert_eq!(details["candidates"][0]["kind"], "names");
    }
    let missing = vec!["diag:absent-anchor".to_owned()];
    let missing_owned = missing.clone();
    let actor_owned = w.viewer.clone();
    let (result, details) = small_read_detailed_call(
        false,
        true,
        false,
        None,
        sql::with_part_of_read_session(
            &w.db,
            &w.viewer,
            &[("records", "id")],
            &missing,
            sql::in_snapshot(&w.db, &w.viewer, move |conn| {
                Box::pin(async move {
                    kernel::generic_links::visible_link_rows_for_on(
                        conn,
                        &actor_owned,
                        &missing_owned,
                    )
                    .await
                })
            }),
        ),
    )
    .await;
    assert!(result.unwrap().is_empty());
    assert_eq!(details["links"][0]["rows"], 0);
    assert_eq!(details["links"][0]["succeeded"], true);
    w.db.close().await;
}

// Disposable serving projections plus immutable import witnesses. This models
// directory disclosure cost without qualifying importer/replay behavior.
async fn seed_claim_directory_diagnostic(w: &World) {
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let package = crate::v2_standard::v1_compat::package();
    let mut tx = w.db.write_pool().begin().await.unwrap();
    for (id, source) in [
        ("claims:person-visible", &w.first),
        ("claims:person-hidden", &w.hidden),
    ] {
        sqlx::query("INSERT INTO kernel_records(id,home_id,owner_id,primary_type,kind,accession,pin_family,pin_version,pin_digest,interpreter,created_seq,created_at) SELECT ?1,home_id,owner_id,'V1','record',?1,?2,1,?3,'native.defn/5',created_seq,created_at FROM kernel_records WHERE id=?4")
            .bind(id).bind(crate::v2_standard::v1_compat::FAMILY).bind(&package.definitions[0].digest).bind(source).execute(&mut *tx).await.unwrap();
        for (field, value) in [("v1_type", "Entity"), ("v1_kind", "person")] {
            sqlx::query("INSERT INTO kernel_record_fields SELECT id,?,json_quote(?),created_seq FROM kernel_records WHERE id=?")
                .bind(field).bind(value).bind(id).execute(&mut *tx).await.unwrap();
        }
        sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,causal_envelope_version,causal_status) VALUES(?,?,'kernel.import_state.v1','{}',?,1,'legacy_unknown')")
            .bind(format!("claims-witness:{id}")).bind(id).bind(&host).execute(&mut *tx).await.unwrap();
    }
    sqlx::query("WITH RECURSIVE n(x) AS (VALUES(0) UNION ALL SELECT x+1 FROM n WHERE x<99) INSERT INTO kernel_v1_state SELECT 'account_directory',printf('claims-directory:%d',x),'synthetic','{}',printf('claims:visible:%d',x),'claims:person-visible','2026-11-09T00:00:00Z',0 FROM n")
        .execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO kernel_v1_state VALUES('account_directory','claims-directory:hidden','synthetic','{}','claims:hidden','claims:person-hidden','2026-11-09T00:00:00Z',0)")
        .execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    kernel::ensure_record_metadata(&w.db).await.unwrap();
}

#[tokio::test]
async fn kernel_v2_empty_claims_skip_directory_work_and_preserve_disclosure() {
    use std::sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    };
    let w = world().await;
    seed_claim_directory_diagnostic(&w).await;
    let mut tx = w.db.write_pool().begin().await.unwrap();
    let mut work = Vec::new();
    // Each mode gets a fresh request memo and the same pinned database state.
    // The eager arm is the original empty-claims order, including admission.
    for eager in [true, false] {
        let meter = Arc::new(AtomicU64::new(0));
        let count = meter.clone();
        tx.lock_handle()
            .await
            .unwrap()
            .set_progress_handler(1, move || {
                count.fetch_add(1, Ordering::Relaxed);
                true
            });
        kernel::read_cache::scope_request(kernel::read_cache::with_capabilities(async {
            if eager {
                kernel::app_installs::admit_dispatched_on(&mut tx, &w.viewer).await.unwrap();
                kernel::kernel_require(&mut tx, &w.viewer, &w.first, crate::authorization::Capability::View).await.unwrap();
                kernel::v1_state::disclosed_accounts_on(&mut tx, &w.viewer).await.unwrap();
                let rows: Vec<(String,String,Option<String>)> = sqlx::query_as("SELECT payload,observed_at,account_principal FROM kernel_v1_state WHERE section='claims' AND record_id=? ORDER BY source_id")
                    .bind(&w.first).fetch_all(&mut *tx).await.unwrap();
                assert!(rows.is_empty());
            } else {
                assert!(kernel::v1_state::claims_on(&mut tx, &w.viewer, &w.first).await.unwrap().is_empty());
            }
            let key = kernel::read_cache::key_on(&mut tx, &w.viewer, "disclosed_accounts").await.unwrap();
            assert_eq!(kernel::read_cache::get::<std::collections::BTreeSet<String>>(&key).is_some(), eager,
                "an empty claims read must not load the account disclosure directory");
        })).await;
        tx.lock_handle().await.unwrap().remove_progress_handler();
        work.push(meter.load(Ordering::Relaxed));
    }
    assert!(
        work[1] < work[0],
        "empty claims still paid eager directory VM work: {work:?}"
    );
    eprintln!(
        "{}",
        json!({"empty_claims_vm_steps":{"eager_directory":work[0],"empty_fast_path":work[1],"directory_rows":101}})
    );
    for id in [&w.hidden, &"claims:missing".to_owned()] {
        assert!(
            kernel::v1_state::claims_on(&mut tx, &w.viewer, id)
                .await
                .is_err(),
            "{id}"
        );
    }
    for (source, account, payload) in [
        (
            "a-own",
            Some(w.viewer.as_str()),
            json!({"id":"own","released_at":null}).to_string(),
        ),
        (
            "b-visible",
            Some("claims:visible:0"),
            json!({"id":"visible","released_at":"2026-11-08T01:00:00Z"}).to_string(),
        ),
        // Hidden and unattributed claims must remain absent from the result.
        (
            "c-hidden",
            Some("claims:hidden"),
            json!({"id":"hidden"}).to_string(),
        ),
        (
            "d-unattributed",
            None,
            json!({"id":"unattributed"}).to_string(),
        ),
    ] {
        sqlx::query("INSERT INTO kernel_v1_state VALUES('claims',?,'synthetic',?,?,?,'2026-11-09T00:00:00Z',0)")
            .bind(source).bind(payload).bind(account).bind(&w.first).execute(&mut *tx).await.unwrap();
    }
    assert_eq!(
        kernel::read_cache::with_capabilities(kernel::v1_state::claims_on(
            &mut tx, &w.viewer, &w.first
        ))
        .await
        .unwrap(),
        vec![
            json!({"id":"own","released_at":null,"historical":true,"occupied":false,"source_observed_at":"2026-11-09T00:00:00Z","effective_released_at":"2026-11-09T00:00:00Z","release_basis":"cutover_nonoccupying"}),
            json!({"id":"visible","released_at":"2026-11-08T01:00:00Z","historical":true,"occupied":false,"source_observed_at":"2026-11-09T00:00:00Z","effective_released_at":"2026-11-08T01:00:00Z","release_basis":"source_release"}),
        ]
    );
    tx.rollback().await.unwrap();
    w.db.close().await;
}

/// Isolate readiness from renderer staging, admission and endpoint shaping.
/// Fixed record slots retain equal record/home dimensions across fleet sizes.
#[cfg(feature = "v2-kernel-probe")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn record_reads_provider_readiness_diagnostics() {
    use kernel::generic_links::diagnostics::{measure_dispatch_control, measure_readiness};
    use sqlx::Connection;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    let scales: Vec<usize> = std::env::var("NATIVE_READINESS_SCALES")
        .unwrap_or_else(|_| "0,2".into())
        .split(',')
        .map(|v| v.parse().unwrap())
        .collect();
    assert!(!scales.is_empty() && scales.iter().all(|n| *n <= 2000));
    let slots = *scales.iter().max().unwrap();
    let waves: usize = std::env::var("NATIVE_READINESS_WAVES").map_or(1, |v| v.parse().unwrap());
    assert!((1..=100).contains(&waves));
    assert!(crate::db::governed_sql_pool_size() >= 4);
    for providers in scales {
        let w = Box::pin(world()).await;
        let home: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
            .bind(&w.first)
            .fetch_one(w.db.pool())
            .await
            .unwrap();
        let _ = small_read_provider_fixture(&w, &home, providers, slots).await;
        let dimensions: (i64, i64, i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM kernel_records),(SELECT count(*) FROM kernel_roots),(SELECT count(*) FROM kernel_provider_state),(SELECT count(*) FROM kernel_provider_link_heads),(SELECT count(*) FROM kernel_provider_link_rows)"
        ).fetch_one(w.db.pool()).await.unwrap();
        let mut plans = Vec::new();
        for (name, query) in [
            ("coverage", kernel::provider_link_reads::COVERAGE_SQL),
            (
                "pins",
                "SELECT DISTINCT pins_json FROM kernel_provider_link_heads",
            ),
        ] {
            let rows: Vec<(i64, i64, i64, String)> =
                sqlx::query_as(&format!("EXPLAIN QUERY PLAN {query}"))
                    .fetch_all(w.db.pool())
                    .await
                    .unwrap();
            plans.push(json!({"name":name,"rows":rows}));
        }
        eprintln!(
            "{}",
            json!({"readiness_fixture":{"added_providers":providers,"provider_slots":slots,"records":dimensions.0,"homes":dimensions.1,"provider_states":dimensions.2,"projection_heads":dimensions.3,"projection_rows":dimensions.4,"plans":plans,"debug_assertions":cfg!(debug_assertions),"fixture":"canonical provider commits; no writes during measured samples; direct readiness is not a full renderer request"}})
        );
        // Retain all four leases across warmups and samples. Acquisition is
        // excluded, statements can stay warm, and no nested pool slot is used.
        let mut connections = Vec::new();
        for _ in 0..4 {
            let mut connection = w.db.governed_pool().acquire().await.unwrap();
            // Abandonment must retire any still-installed observer and guard.
            connection.close_on_drop();
            connections.push(connection);
        }
        for wave in 0..waves + 2 {
            let mut cases = [(0, 1), (4, 1), (9, 1), (0, 4), (4, 4), (9, 4)];
            cases.rotate_left(wave % 6);
            if wave % 2 == 1 {
                cases.reverse();
            }
            for (control_statements, callers) in cases {
                let control = control_statements > 0;
                let barrier = Arc::new(tokio::sync::Barrier::new(callers));
                let mut workers = Vec::new();
                for worker in 0..callers {
                    let mut connection = connections.pop().unwrap();
                    let barrier = barrier.clone();
                    workers.push(tokio::spawn(async move {
                        let pin_started = Instant::now();
                        let mut tx = connection.begin().await.unwrap();
                        let snapshot: i64 = sqlx::query_scalar("SELECT count(*) FROM kernel_provider_link_heads")
                            .fetch_one(&mut *tx).await.unwrap();
                        let pin_us = pin_started.elapsed().as_micros();
                        let barrier_started = Instant::now();
                        tokio::time::timeout(Duration::from_secs(2), barrier.wait()).await.unwrap();
                        let barrier_us = barrier_started.elapsed().as_micros();
                        // Arm this isolated operation's budget once, after
                        // pinning/barrier. The trace observer must retain it.
                        let deadline = Instant::now() + Duration::from_secs(2);
                        tx.lock_handle().await.unwrap().set_progress_handler(1000, move || Instant::now() < deadline);
                        let started = Instant::now();
                        let (result, diagnostic) = if control {
                            measure_dispatch_control(&mut tx, control_statements).await
                        } else {
                            measure_readiness(&mut tx).await
                        };
                        let elapsed_us = started.elapsed().as_micros();
                        tx.lock_handle().await.unwrap().remove_progress_handler();
                        let error = result.err().map(|e| e.to_string());
                        let rollback = tx.rollback().await.err().map(|e| e.to_string());
                        eprintln!("{}",json!({"readiness_sample":{"added_providers":providers,"wave":wave,"warmup":wave<2,"worker":worker,"callers":callers,"control":control,"control_statements":if control {Some(control_statements)} else {None},"snapshot_heads":snapshot,"pin_us":pin_us,"barrier_us":barrier_us,"call_us":elapsed_us,"diagnostic":diagnostic,"error":error,"rollback_error":rollback}}));
                        assert!(error.is_none() && rollback.is_none(), "{error:?} {rollback:?}");
                        connection
                    }));
                }
                for worker in workers {
                    connections.push(worker.await.unwrap());
                }
            }
        }
        drop(connections);
        w.db.close().await;
    }
}

/// The production link queries on a governed snapshot, with cold/warm SQLx
/// statement caches and a separate synthetic TEMP-invalidation stress control.
/// Normal CI uses a small fixture; larger repetitions are explicitly selected.
#[cfg(feature = "v2-kernel-probe")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn record_reads_link_preparation_diagnostics() {
    use kernel::generic_links::diagnostics::{
        measure_preparation_control, with_link_query_preparation, with_link_read_diagnostics,
        Options, QueryPreparation,
    };
    use sqlx::Connection;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    fn multiset(rows: &[Value]) -> Vec<String> {
        let mut rows: Vec<_> = rows.iter().map(Value::to_string).collect();
        rows.sort();
        rows
    }
    async fn cookies(conn: &mut sqlx::SqliteConnection) -> Result<(i64, i64)> {
        let main = sqlx::query_scalar("PRAGMA main.schema_version")
            .persistent(false)
            .fetch_one(&mut *conn)
            .await?;
        let temp = sqlx::query_scalar("PRAGMA temp.schema_version")
            .persistent(false)
            .fetch_one(conn)
            .await?;
        Ok((main, temp))
    }
    let providers: usize =
        std::env::var("NATIVE_LINK_PREPARATION_PROVIDERS").map_or(2, |v| v.parse().unwrap());
    let waves: usize =
        std::env::var("NATIVE_LINK_PREPARATION_WAVES").map_or(1, |v| v.parse().unwrap());
    assert!(providers <= 2000 && (1..=100).contains(&waves));
    assert!(crate::db::governed_sql_pool_size() >= 4);
    let w = Arc::new(Box::pin(world()).await);
    let home: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
        .bind(&w.first)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let (provider_anchor, _) = small_read_provider_fixture(&w, &home, providers, providers).await;
    kernel::add_generic_link_as(
        &w.db,
        &w.admin,
        &w.second,
        &w.first,
        "supersedes",
        Some("visible preparation fixture".into()),
    )
    .await
    .unwrap();
    kernel::add_generic_link_as(
        &w.db,
        &w.admin,
        &w.hidden,
        &w.first,
        "supersedes",
        Some("hidden preparation fixture".into()),
    )
    .await
    .unwrap();
    let anchors = vec![w.first.clone(), provider_anchor];
    let dimensions: (i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM kernel_records),(SELECT count(*) FROM kernel_roots),(SELECT count(*) FROM kernel_provider_state),(SELECT count(*) FROM kernel_provider_link_heads),(SELECT count(*) FROM kernel_provider_link_rows)"
    ).fetch_one(w.db.pool()).await.unwrap();
    eprintln!(
        "{}",
        json!({"link_preparation_fixture":{
            "added_providers":providers,"records":dimensions.0,"homes":dimensions.1,
            "provider_states":dimensions.2,"projection_heads":dimensions.3,
            "projection_rows":dimensions.4,"debug_assertions":cfg!(debug_assertions),
            "workers":4,"warmup_waves":2,"measured_waves":waves,
            "method":"exact helper after excluded priming; same governed snapshot and guard; no timed EXPLAIN; cold/warm means SQL statement cache only; synthetic TEMP DDL occurs between optional prepare and execute, separately timed"
        }})
    );
    for (role, actor) in [("owner", w.admin.clone()), ("member", w.viewer.clone())] {
        let mut expected_rows = None;
        for wave in 0..waves + 2 {
            let mut cases = Vec::new();
            for callers in [1, 4] {
                for warm_cache in [false, true] {
                    for invalidate_temp in [false, true] {
                        for arm in 0..4 {
                            cases.push((callers, warm_cache, invalidate_temp, arm));
                        }
                    }
                }
            }
            let positions = cases.len();
            cases.rotate_left(wave % positions);
            if wave % 2 == 1 {
                cases.reverse();
            }
            for (callers, warm_cache, invalidate_temp, arm) in cases {
                let barrier = Arc::new(tokio::sync::Barrier::new(callers));
                let mut workers = Vec::new();
                for worker in 0..callers {
                    let w = w.clone();
                    let actor = actor.clone();
                    let anchors = anchors.clone();
                    let barrier = barrier.clone();
                    workers.push(tokio::spawn(async move {
                        let actor_on = actor.clone();
                        let anchors_on = anchors.clone();
                        let control = arm >= 2;
                        let mode = if arm % 2 == 0 { QueryPreparation::Ordinary }
                            else { QueryPreparation::PrepareFirst };
                        let started = Instant::now();
                        let sample = kernel::read_cache::scope_request(sql::with_part_of_read_session(
                            &w.db, &actor, &[("records", "id")], &anchors,
                            sql::in_snapshot(&w.db, &actor, move |conn| Box::pin(async move {
                                // Prime the same helper/admission/scope before every arm.
                                // Only SQLite's statement-cache state differs at measurement.
                                conn.clear_cached_statements().await?;
                                let prime_started = Instant::now();
                                let rows = kernel::generic_links::visible_link_rows_for_on(
                                    conn, &actor_on, &anchors_on).await?;
                                if control {
                                    let (result, _) = measure_preparation_control(
                                        conn, QueryPreparation::Ordinary, false).await;
                                    result?;
                                }
                                let prime_us = prime_started.elapsed().as_micros() as u64;
                                let clear_started = Instant::now();
                                if !warm_cache { conn.clear_cached_statements().await?; }
                                let cache_clear_us = clear_started.elapsed().as_micros() as u64;
                                let before = cookies(conn).await?;
                                let cache_before = conn.cached_statements_size();
                                if warm_cache { assert!(cache_before > 0); }
                                else { assert_eq!(cache_before, 0); }
                                let wait_started = Instant::now();
                                tokio::time::timeout(Duration::from_secs(2), barrier.wait()).await
                                    .map_err(|_| Error::engine("preparation diagnostic barrier expired"))?;
                                let barrier_us = wait_started.elapsed().as_micros() as u64;
                                let measured = Instant::now();
                                let (diagnostic, call_us) = if control {
                                    let (result, diagnostic) = measure_preparation_control(
                                        conn, mode, invalidate_temp).await;
                                    let call_us = measured.elapsed().as_micros() as u64;
                                    result?;
                                    (diagnostic, call_us)
                                } else {
                                    let (actual, mut diagnostics) = with_link_read_diagnostics(
                                        Options { explain:false, before_batch:None },
                                        with_link_query_preparation(mode, invalidate_temp,
                                            kernel::generic_links::visible_link_rows_for_on(
                                                conn, &actor_on, &anchors_on)),
                                    ).await;
                                    let call_us = measured.elapsed().as_micros() as u64;
                                    assert_eq!(multiset(&actual?), multiset(&rows));
                                    assert_eq!(diagnostics.len(), 1);
                                    (diagnostics.remove(0), call_us)
                                };
                                let cache_after = conn.cached_statements_size();
                                let after = cookies(conn).await?;
                                assert_eq!(before.0, after.0, "main schema changed");
                                if invalidate_temp { assert!(after.1 > before.1); }
                                else { assert_eq!(before.1, after.1); }
                                assert!(diagnostic.succeeded);
                                assert!(diagnostic.plans.is_empty());
                                assert!(diagnostic.statement_timeline.iter().all(|s| s.finished_ns.is_some()));
                                Ok((rows, json!({"prime_us":prime_us,"cache_clear_us":cache_clear_us,
                                    "barrier_us":barrier_us,"call_us":call_us,
                                    "cache_before":cache_before,"cache_after":cache_after,
                                    "schema_before":before,"schema_after":after,"diagnostic":diagnostic})))
                            })),
                        )).await.unwrap();
                        use sha2::Digest;
                        let result_hash = format!("{:x}", sha2::Sha256::digest(
                            serde_json::to_vec(&multiset(&sample.0)).unwrap()));
                        eprintln!("{}",json!({"link_preparation_sample":{
                            "role":role,"wave":wave,"warmup":wave<2,"worker":worker,
                            "callers":callers,"warm_cache":warm_cache,
                            "invalidate_temp":invalidate_temp,"arm":arm,
                            "result_rows":sample.0.len(),"result_multiset_sha256":result_hash,
                            "session_us":started.elapsed().as_micros() as u64,"sample":sample.1
                        }}));
                        sample.0
                    }));
                }
                for worker in workers {
                    let rows = multiset(&worker.await.unwrap());
                    if let Some(expected) = &expected_rows {
                        assert_eq!(&rows, expected);
                    } else {
                        assert!(!rows.is_empty());
                        expected_rows = Some(rows);
                    }
                }
            }
        }
    }
    w.db.close().await;
}

/// Observe ordinary renderer sessions without priming, cache clearing, explicit
/// preparation or synthetic invalidation. Plain calls control probe overhead.
#[cfg(feature = "v2-kernel-probe")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn record_reads_renderer_cache_lifecycle_diagnostics() {
    use kernel::generic_links::diagnostics::{
        with_link_read_diagnostics, with_link_statement_metadata, Options,
    };
    use sha2::Digest;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    fn dimension(name: &str, default: usize, max: usize) -> usize {
        let value = std::env::var(name).map_or(default, |v| v.parse().unwrap());
        assert!(value <= max, "{name}");
        value
    }
    let providers = dimension("NATIVE_RENDERER_CACHE_PROVIDERS", 2, 2000);
    let records = dimension("NATIVE_RENDERER_CACHE_RECORDS", 0, 25_000);
    let homes = dimension("NATIVE_RENDERER_CACHE_HOMES", 0, 500);
    let waves = dimension("NATIVE_RENDERER_CACHE_WAVES", 1, 100);
    assert!(waves > 0 && crate::db::governed_sql_pool_size() >= 4);
    let w = Arc::new(Box::pin(world()).await);
    let home: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
        .bind(&w.first)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let private: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
        .bind(&w.hidden)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let (provider_anchor, empty) =
        small_read_provider_fixture(&w, &home, providers, providers).await;
    kernel::add_generic_link_as(
        &w.db,
        &w.admin,
        &w.second,
        &w.first,
        "supersedes",
        Some("visible lifecycle fixture".into()),
    )
    .await
    .unwrap();
    kernel::add_generic_link_as(
        &w.db,
        &w.admin,
        &w.hidden,
        &w.first,
        "supersedes",
        Some("hidden lifecycle fixture".into()),
    )
    .await
    .unwrap();
    let mut home_ids = vec![home.clone()];
    for _ in 0..homes {
        home_ids.push(
            kernel::create_home(&w.db, &home, None, &w.admin)
                .await
                .unwrap(),
        );
    }
    if records > 0 {
        // Disposable serving projection scale, following the existing small-read
        // diagnostic; retained history/replay correctness is outside this fixture.
        let mut tx = w.db.write_pool().begin().await.unwrap();
        sqlx::query("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<?1) INSERT INTO kernel_records(id,home_id,owner_id,primary_type,kind,accession,pin_family,pin_version,pin_digest,interpreter,created_seq,created_at) SELECT printf('cache:%05d',x),CASE WHEN x%10=0 THEN ?4 ELSE json_extract(?3,'$['||((x-1)%?5)||']') END,r.owner_id,r.primary_type,r.kind,printf('cache:%05d',x),r.pin_family,r.pin_version,r.pin_digest,r.interpreter,r.created_seq,r.created_at FROM n CROSS JOIN kernel_records r WHERE r.id=?2")
            .bind(records as i64).bind(&w.first).bind(serde_json::to_string(&home_ids).unwrap())
            .bind(&private).bind(home_ids.len() as i64).execute(&mut *tx).await.unwrap();
        sqlx::query("INSERT INTO kernel_record_fields(record_id,name,value_json,created_seq) SELECT id,'title',json_quote('Lifecycle fixture '||id),created_seq FROM kernel_records WHERE id LIKE 'cache:%'")
            .execute(&mut *tx).await.unwrap();
        tx.commit().await.unwrap();
        kernel::ensure_record_metadata(&w.db).await.unwrap();
    }
    let dimensions: (i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM kernel_records),(SELECT count(*) FROM kernel_roots),(SELECT count(*) FROM content_events),(SELECT count(*) FROM kernel_provider_link_heads),(SELECT count(*) FROM kernel_provider_link_rows)"
    ).fetch_one(w.db.pool()).await.unwrap();
    eprintln!(
        "{}",
        json!({"renderer_cache_fixture":{
            "records":dimensions.0,"homes":dimensions.1,"events":dimensions.2,
            "projection_heads":dimensions.3,"projection_rows":dimensions.4,
            "added_providers":providers,"added_bulk_records":records,"added_homes":homes,
            "measured_waves":waves,"warmup_waves":2,"debug_assertions":cfg!(debug_assertions),
            "fixture":"canonical selected links/providers plus optional bulk serving projections; fixed degree; not a retained-history/HQ clone",
            "method":"ordinary render_record dispatch; observed vs plain; start barrier before request; no synthetic DDL, cache clear, priming or explicit preparation"
        }})
    );
    let registry = Arc::new(registry());
    let targets = [
        ("linked", w.first.clone()),
        ("provider", provider_anchor),
        ("empty", empty),
    ];
    let mut expected = std::collections::BTreeMap::new();
    for wave in 0..waves + 2 {
        let mut cases = Vec::new();
        for (role, credential) in [("owner", "acct:admin"), ("member", "acct:viewer")] {
            for (case, id) in &targets {
                for callers in [1, 4] {
                    for observed in [true, false] {
                        cases.push((role, credential, *case, id.clone(), callers, observed));
                    }
                }
            }
        }
        let positions = cases.len();
        cases.rotate_left(wave % positions);
        if wave % 2 == 1 {
            cases.reverse();
        }
        for (role, credential, case, id, callers, observed) in cases {
            let barrier = Arc::new(tokio::sync::Barrier::new(callers));
            let mut workers = Vec::new();
            for worker in 0..callers {
                let db = w.db.clone();
                let registry = registry.clone();
                let barrier = barrier.clone();
                let id = id.clone();
                workers.push(tokio::spawn(async move {
                    tokio::time::timeout(Duration::from_secs(2), barrier.wait())
                        .await
                        .unwrap();
                    let started = Instant::now();
                    let invoke = registry.call_engine(
                        EngineHandle::KernelV2(db),
                        Caller::authenticated(credential),
                        "render_record",
                        json!({"id":id}),
                    );
                    let (answer, links, lifecycle, call_us) = if observed {
                        let ((answer, links), lifecycle) = sql::with_session_lifecycle(
                            with_link_statement_metadata(with_link_read_diagnostics(
                                Options {
                                    explain: false,
                                    before_batch: None,
                                },
                                invoke,
                            )),
                        )
                        .await;
                        let call_us = started.elapsed().as_micros() as u64;
                        (answer, json!(links), json!(lifecycle), call_us)
                    } else {
                        let answer = invoke.await;
                        let call_us = started.elapsed().as_micros() as u64;
                        (answer, Value::Null, Value::Null, call_us)
                    };
                    let answer = answer.unwrap();
                    if observed {
                        assert!(!links.as_array().unwrap().is_empty());
                        assert_eq!(lifecycle.as_array().unwrap().len(), 5);
                        for sample in lifecycle.as_array().unwrap() {
                            assert!(sample["error"].is_null(), "{sample}");
                            assert!(sample["connection_id"].is_u64());
                        }
                        for detail in links.as_array().unwrap() {
                            assert_eq!(detail["succeeded"], true);
                            let metadata = detail["query_metadata"].as_array().unwrap();
                            assert_eq!(metadata.len(), 3);
                            for entry in metadata {
                                assert_eq!(
                                    entry["before"]["connection_id"],
                                    lifecycle[0]["connection_id"]
                                );
                                assert_eq!(
                                    entry["after"]["connection_id"],
                                    lifecycle[0]["connection_id"]
                                );
                                assert_eq!(
                                    entry["before"]["main_cookie"],
                                    entry["after"]["main_cookie"]
                                );
                                assert_eq!(
                                    entry["before"]["temp_cookie"],
                                    entry["after"]["temp_cookie"]
                                );
                                assert_eq!(
                                    entry["after"]["matching_statements"]
                                        .as_array()
                                        .unwrap()
                                        .len(),
                                    1
                                );
                                assert!(!entry["deltas"].as_array().unwrap().is_empty());
                            }
                            assert!(detail["plans"].as_array().unwrap().is_empty());
                            assert!(detail["statement_timeline"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .all(|s| !s["finished_ns"].is_null()));
                        }
                        assert_eq!(lifecycle[0]["phase"], "acquire_before_begin");
                        assert_eq!(lifecycle[4]["phase"], "after_finish");
                        assert_eq!(lifecycle[0]["autocommit"], true);
                        assert_eq!(lifecycle[0]["temp_user_objects"], 0);
                        assert_eq!(lifecycle[3]["autocommit"], true);
                        assert_eq!(lifecycle[3]["temp_user_objects"], 0);
                        assert_eq!(lifecycle[4]["autocommit"], true);
                        assert_eq!(lifecycle[4]["temp_user_objects"], 0);
                        assert_eq!(lifecycle[4]["reusable"], true);
                        for sample in lifecycle.as_array().unwrap() {
                            assert_eq!(sample["connection_id"], lifecycle[0]["connection_id"]);
                            assert_eq!(
                                sample["main_schema_cookie"],
                                lifecycle[0]["main_schema_cookie"]
                            );
                            assert_eq!(
                                sample["cache_count_before_probe"],
                                sample["cache_count_after_probe"]
                            );
                        }
                    }
                    let bytes = serde_json::to_vec(&answer).unwrap();
                    let hash = format!("{:x}", sha2::Sha256::digest(&bytes));
                    eprintln!(
                        "{}",
                        json!({"renderer_cache_sample":{
                            "wave":wave,"warmup":wave<2,"role":role,"case":case,"callers":callers,
                            "worker":worker,"observed":observed,"call_us":call_us,
                            "response_bytes":bytes.len(),"response_sha256":hash,"links":links,
                            "lifecycle":lifecycle
                        }})
                    );
                    answer
                }));
            }
            for worker in workers {
                let answer = worker.await.unwrap();
                if let Some(prior) = expected.get(&(role, case)) {
                    assert_eq!(&answer, prior);
                } else {
                    expected.insert((role, case), answer);
                }
            }
            // Let ordinary asynchronous pool release progress; do not acquire,
            // retain, pin or force a particular physical lease between requests.
            tokio::task::yield_now().await;
        }
    }
    assert_eq!(expected.len(), 6);
    w.db.close().await;
}

/// Paired ordinary renderer calls for the generic-only visibility SQL trial.
/// Endpoint degree varies within one fixture; no request primes or clears caches.
#[cfg(feature = "v2-kernel-probe")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn record_reads_generic_visibility_trial_diagnostics() {
    use kernel::generic_links::diagnostics::{
        with_generic_visibility_variant, with_link_read_diagnostics, with_link_statement_metadata,
        Options,
    };
    use sha2::Digest;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    fn dimension(name: &str, default: usize, max: usize) -> usize {
        let value = std::env::var(name).map_or(default, |v| v.parse().unwrap());
        assert!(value <= max, "{name}");
        value
    }
    let degrees: Vec<usize> = std::env::var("NATIVE_GENERIC_VISIBILITY_DEGREES")
        .unwrap_or_else(|_| "0,8,128".into())
        .split(',')
        .map(|v| v.trim().parse().unwrap())
        .collect();
    assert!(!degrees.is_empty() && degrees.iter().all(|v| [0, 8, 128, 1024].contains(v)));
    assert_eq!(
        degrees
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        degrees.len()
    );
    let providers = dimension("NATIVE_RENDERER_CACHE_PROVIDERS", 2, 2000);
    let records = dimension("NATIVE_RENDERER_CACHE_RECORDS", 0, 25_000);
    let homes = dimension("NATIVE_RENDERER_CACHE_HOMES", 0, 500);
    let waves = dimension("NATIVE_RENDERER_CACHE_WAVES", 1, 100);
    assert!(waves > 0 && crate::db::governed_sql_pool_size() >= 4);
    let w = Arc::new(Box::pin(world()).await);
    let home: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
        .bind(&w.first)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let private: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
        .bind(&w.hidden)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let _ = small_read_provider_fixture(&w, &home, providers, providers).await;
    let maximum_degree = *degrees.iter().max().unwrap();
    let mut endpoints = Vec::new();
    for index in 0..maximum_degree {
        endpoints.push(
            kernel::create_as(
                &w.db,
                &w.admin,
                "fixture.mcp",
                "note",
                json!({"title":format!("Generic endpoint {index}"),"body":"endpoint"})
                    .as_object()
                    .unwrap(),
                if index % 2 == 0 { &home } else { &private },
            )
            .await
            .unwrap(),
        );
    }
    let mut targets = Vec::new();
    for degree in &degrees {
        let id = kernel::create_as(
            &w.db,
            &w.admin,
            "fixture.mcp",
            "note",
            json!({"title":format!("Generic degree {degree}"),"body":"anchor"})
                .as_object()
                .unwrap(),
            &home,
        )
        .await
        .unwrap();
        targets.push((*degree, id));
    }
    // Selected records and generic links use canonical writes. Only optional
    // unrelated bulk scale below uses disposable serving projections.
    for (degree, anchor) in &targets {
        for (index, endpoint) in endpoints.iter().take(*degree).enumerate() {
            let (source, target) = if index % 2 == 0 {
                (anchor, endpoint)
            } else {
                (endpoint, anchor)
            };
            kernel::add_generic_link_as(
                &w.db,
                &w.admin,
                source,
                target,
                "diagnostic_edge",
                Some(format!("degree {degree}, edge {index}")),
            )
            .await
            .unwrap();
        }
    }
    let mut home_ids = vec![home.clone()];
    for _ in 0..homes {
        home_ids.push(
            kernel::create_home(&w.db, &home, None, &w.admin)
                .await
                .unwrap(),
        );
    }
    if records > 0 {
        let mut tx = w.db.write_pool().begin().await.unwrap();
        sqlx::query("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<?1) INSERT INTO kernel_records(id,home_id,owner_id,primary_type,kind,accession,pin_family,pin_version,pin_digest,interpreter,created_seq,created_at) SELECT printf('generic-trial:bulk:%05d',x),CASE WHEN x%10=0 THEN ?4 ELSE json_extract(?3,'$['||((x-1)%?5)||']') END,r.owner_id,r.primary_type,r.kind,printf('generic-trial:bulk:%05d',x),r.pin_family,r.pin_version,r.pin_digest,r.interpreter,r.created_seq,r.created_at FROM n CROSS JOIN kernel_records r WHERE r.id=?2")
            .bind(records as i64).bind(&w.first).bind(serde_json::to_string(&home_ids).unwrap())
            .bind(&private).bind(home_ids.len() as i64).execute(&mut *tx).await.unwrap();
        sqlx::query("INSERT INTO kernel_record_fields(record_id,name,value_json,created_seq) SELECT id,'title',json_quote('Generic trial '||id),created_seq FROM kernel_records WHERE id LIKE 'generic-trial:bulk:%'")
            .execute(&mut *tx).await.unwrap();
        tx.commit().await.unwrap();
        kernel::ensure_record_metadata(&w.db).await.unwrap();
    }
    let dimensions: (i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM kernel_records),(SELECT count(*) FROM kernel_roots),(SELECT count(*) FROM content_events),(SELECT count(*) FROM kernel_generic_links WHERE active=1),(SELECT count(*) FROM kernel_provider_link_rows)"
    ).fetch_one(w.db.pool()).await.unwrap();
    eprintln!(
        "{}",
        json!({"generic_visibility_fixture":{
            "degrees":degrees,"records":dimensions.0,"homes":dimensions.1,"events":dimensions.2,
            "active_generic_links":dimensions.3,"provider_rows":dimensions.4,
            "added_providers":providers,"added_bulk_records":records,"added_homes":homes,
            "endpoint_pool":maximum_degree,"measured_waves":waves,"warmup_waves":2,
            "debug_assertions":cfg!(debug_assertions),
            "fixture":"independent anchors share endpoint pool; public outgoing/private incoming; canonical selected records/edges plus optional bulk serving projections; not replay/HQ history",
            "method":"ordinary renderer A/B with observed/plain arms; no cache clear, priming, explicit prepare or synthetic DDL; plans collected only after timed matrix"
        }})
    );
    let registry = Arc::new(registry());
    let mut expected = std::collections::BTreeMap::new();
    for wave in 0..waves + 2 {
        let mut cases = Vec::new();
        for (role, credential) in [("owner", "acct:admin"), ("member", "acct:viewer")] {
            for (degree, id) in &targets {
                for callers in [1, 4] {
                    for candidate in [false, true] {
                        for observed in [true, false] {
                            cases.push((
                                role,
                                credential,
                                *degree,
                                id.clone(),
                                callers,
                                candidate,
                                observed,
                            ));
                        }
                    }
                }
            }
        }
        let positions = cases.len();
        cases.rotate_left(wave % positions);
        if wave % 2 == 1 {
            cases.reverse();
        }
        for (role, credential, degree, id, callers, candidate, observed) in cases {
            let barrier = Arc::new(tokio::sync::Barrier::new(callers));
            let mut workers = Vec::new();
            for worker in 0..callers {
                let db = w.db.clone();
                let registry = registry.clone();
                let barrier = barrier.clone();
                let id = id.clone();
                workers.push(tokio::spawn(async move {
                    tokio::time::timeout(Duration::from_secs(2), barrier.wait()).await.unwrap();
                    let started = Instant::now();
                    let invoke = with_generic_visibility_variant(candidate, registry.call_engine(
                        EngineHandle::KernelV2(db), Caller::authenticated(credential),
                        "render_record", json!({"id":id})));
                    let (answer, links, lifecycle, call_us) = if observed {
                        let ((answer, links), lifecycle) = sql::with_session_lifecycle(
                            with_link_statement_metadata(with_link_read_diagnostics(
                                Options { explain:false, before_batch:None }, invoke))).await;
                        let call_us = started.elapsed().as_micros() as u64;
                        (answer, json!(links), json!(lifecycle), call_us)
                    } else {
                        let answer = invoke.await;
                        let call_us = started.elapsed().as_micros() as u64;
                        (answer, Value::Null, Value::Null, call_us)
                    };
                    let answer = answer.unwrap();
                    if observed {
                        assert_eq!(lifecycle.as_array().unwrap().len(), 5);
                        for sample in lifecycle.as_array().unwrap() {
                            assert!(sample["error"].is_null(), "{sample}");
                            assert_eq!(sample["connection_id"], lifecycle[0]["connection_id"]);
                            assert_eq!(sample["cache_count_before_probe"], sample["cache_count_after_probe"]);
                        }
                        assert_eq!(lifecycle[3]["temp_user_objects"], 0);
                        assert_eq!(lifecycle[4]["temp_user_objects"], 0);
                        assert_eq!(lifecycle[4]["reusable"], true);
                        assert_eq!(links.as_array().unwrap().len(), 1);
                        let detail = &links[0];
                        assert_eq!(detail["succeeded"], true);
                        assert!(detail["plans"].as_array().unwrap().is_empty());
                        assert!(detail["statement_timeline"].as_array().unwrap().iter()
                            .all(|s| !s["finished_ns"].is_null()));
                        let phases = detail["phases"].as_array().unwrap();
                        let generic = phases.iter().find(|p| p["phase"]=="generic_query").unwrap();
                        assert_eq!(generic["returned_rows"].as_u64().unwrap(),
                            if role=="owner" { degree as u64 } else { (degree/2) as u64 });
                        let metadata = detail["query_metadata"].as_array().unwrap();
                        assert_eq!(metadata.len(), 3);
                        for entry in metadata {
                            assert_eq!(entry["after"]["connection_id"], lifecycle[0]["connection_id"]);
                            assert_eq!(entry["after"]["matching_statements"].as_array().unwrap().len(), 1);
                        }
                    }
                    let bytes = serde_json::to_vec(&answer).unwrap();
                    eprintln!("{}",json!({"generic_visibility_sample":{
                        "wave":wave,"warmup":wave<2,"role":role,"degree":degree,
                        "callers":callers,"worker":worker,"candidate":candidate,"observed":observed,
                        "call_us":call_us,"response_bytes":bytes.len(),
                        "response_sha256":format!("{:x}",sha2::Sha256::digest(&bytes)),
                        "links":links,"lifecycle":lifecycle
                    }}));
                    answer
                }));
            }
            for worker in workers {
                let answer = worker.await.unwrap();
                if let Some(prior) = expected.get(&(role, degree)) {
                    assert_eq!(&answer, prior);
                } else {
                    expected.insert((role, degree), answer);
                }
            }
            tokio::task::yield_now().await;
        }
    }
    assert_eq!(expected.len(), targets.len() * 2);
    // Plan collection intentionally follows all latency samples. EXPLAIN can
    // warm schema/compiler state, so these observations are never timed arms.
    for (role, credential) in [("owner", "acct:admin"), ("member", "acct:viewer")] {
        for (degree, id) in &targets {
            for candidate in [false, true] {
                let (answer, details) = with_generic_visibility_variant(
                    candidate,
                    with_link_read_diagnostics(
                        Options {
                            explain: true,
                            before_batch: None,
                        },
                        call_as(&w, credential, "render_record", json!({"id":id})),
                    ),
                )
                .await;
                assert_eq!(answer.unwrap(), expected[&(role, *degree)]);
                assert_eq!(details.len(), 1);
                let detail = serde_json::to_value(&details[0]).unwrap();
                let plan = detail["plans"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|p| p["phase"] == "generic_query")
                    .unwrap();
                assert!(plan["bytecode_ops"].as_u64().unwrap() > 0);
                if candidate {
                    let rows = plan["rows"].as_array().unwrap();
                    assert!(rows.iter().any(|p| p["detail"]
                        .as_str()
                        .unwrap()
                        .contains("MATERIALIZE candidates")));
                    assert!(!rows.iter().any(|p| matches!(
                        p["detail"].as_str().unwrap(),
                        "MATERIALIZE visible" | "MATERIALIZE endpoints"
                    )));
                    assert!(rows.iter().any(|p| p["detail"]
                        .as_str()
                        .unwrap()
                        .contains("SEARCH r USING INDEX sqlite_autoindex_kernel_records_1")));
                    assert!(!rows
                        .iter()
                        .any(|p| p["detail"].as_str().unwrap().starts_with("SCAN r")));
                    for endpoint in ["source", "target"] {
                        assert!(rows.iter().any(|p| {
                            let text = p["detail"].as_str().unwrap();
                            text.contains("SEARCH")
                                && text.contains(&format!("idx_kernel_generic_links_{endpoint}"))
                        }));
                    }
                }
                eprintln!(
                    "{}",
                    json!({"generic_visibility_plan":{
                        "role":role,"degree":degree,"candidate":candidate,"detail":detail
                    }})
                );
            }
        }
    }
    w.db.close().await;
}

/// Default-sized correctness check; opt in to the same diagnostic at HQ scale.
/// Bulk projection/header setup measures serving costs, not replay correctness.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn record_reads_small_read_diagnostics() {
    fn dimension(name: &str, default: usize, min: usize, max: usize) -> usize {
        let value = std::env::var(name).map_or(default, |v| {
            v.parse().expect("numeric diagnostic dimension")
        });
        assert!((min..=max).contains(&value), "{name} outside {min}..={max}");
        value
    }
    fn quantiles(mut values: Vec<u64>) -> Value {
        values.sort_unstable();
        let n = values.len();
        json!({"min":values[0],"p50":values[n/2],"p95":values[(n*95).div_ceil(100)-1],"p99":values[(n*99).div_ceil(100)-1],"max":values[n-1]})
    }
    use tracing::Instrument;
    if std::env::var_os("NATIVE_SMALL_READ_PROFILE").is_some() {
        use tracing_subscriber::prelude::*;
        let _ = tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_ansi(false)
                    .with_test_writer()
                    .with_filter(tracing_subscriber::filter::filter_fn(|m| {
                        m.target() == "native_ce::read_staging"
                    })),
            )
            .try_init();
    }
    let diagnostic = std::env::var_os("NATIVE_SMALL_READ_DIAGNOSTICS").is_some();
    let detail = std::env::var("NATIVE_SMALL_READ_DETAIL").unwrap_or_else(|_| "off".into());
    assert!(matches!(
        detail.as_str(),
        "off" | "candidates" | "links" | "both"
    ));
    let synchronize_links = std::env::var_os("NATIVE_SMALL_READ_SYNC_LINKS").is_some();
    let trial_indexes = std::env::var_os("NATIVE_SMALL_READ_INDEX_TRIAL").is_some();
    assert!(!trial_indexes || matches!(detail.as_str(), "candidates" | "both"));
    assert!(!synchronize_links || matches!(detail.as_str(), "links" | "both"));
    assert!(
        !synchronize_links || !diagnostic || crate::db::governed_sql_pool_size() >= 4,
        "four-caller synchronization requires four governed slots"
    );
    #[cfg(not(feature = "v2-kernel-probe"))]
    assert_eq!(detail, "off", "detailed probes require v2-kernel-probe");
    let provider_fixture = std::env::var_os("NATIVE_SMALL_READ_PROVIDERS").is_some();
    let providers = dimension("NATIVE_SMALL_READ_PROVIDERS", 0, 0, 2000);
    let provider_slots = dimension(
        "NATIVE_SMALL_READ_PROVIDER_SLOTS",
        providers.max(256),
        providers,
        2000,
    );
    let extra_links = dimension("NATIVE_SMALL_READ_EXTRA_LINKS", 0, 0, 50_000);
    let records = dimension(
        "NATIVE_SMALL_READ_RECORDS",
        if diagnostic { 16_500 } else { 128 },
        100,
        25_000,
    );
    let edits = dimension(
        "NATIVE_SMALL_READ_EDITS",
        if diagnostic { 28 } else { 2 },
        0,
        50,
    );
    let homes = dimension(
        "NATIVE_SMALL_READ_HOMES",
        if diagnostic { 360 } else { 12 },
        6,
        600,
    );
    let moved = dimension(
        "NATIVE_SMALL_READ_MOVED_PERCENT",
        if diagnostic { 100 } else { 50 },
        0,
        100,
    );
    let move_format = std::env::var("NATIVE_SMALL_READ_MOVE_FORMAT")
        .unwrap_or_else(|_| if diagnostic { "legacy" } else { "v2" }.into());
    assert!(matches!(move_format.as_str(), "legacy" | "v2"));
    let write_pairs = dimension("NATIVE_SMALL_READ_INDEX_WRITE_PAIRS", 0, 0, 100);
    assert!(write_pairs == 0 || (trial_indexes && move_format == "v2"));
    let waves = dimension(
        "NATIVE_SMALL_READ_WAVES",
        if diagnostic { 5 } else { 1 },
        1,
        100,
    );
    let w = world().await;
    let root = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let private = kernel::read_record_as(&w.db, &w.admin, &w.hidden)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let mut home_ids = Vec::new();
    for index in 0..homes {
        let parent = if index % 6 == 0 {
            &root
        } else {
            &home_ids[index - 1]
        };
        home_ids.push(
            kernel::create_home(&w.db, parent, None, &w.admin)
                .await
                .unwrap(),
        );
    }
    install_comment_carrier(&w).await;
    let logical_folder = if move_format == "v2" {
        Some(
            call_as(&w, "acct:admin", "create_record", json!({"type":"Collection","kind":"folder","name":"Diagnostic move destination","home_id":root}))
                .await.unwrap()["id"].as_str().unwrap().to_owned(),
        )
    } else {
        None
    };
    let package = crate::v2_standard::v1_compat::package();
    let definition = &package.definitions[0];
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let message = kernel::MessageState {
        author: Some(w.admin.clone()),
        audience: std::collections::BTreeMap::from([
            (w.admin.clone(), "manage".into()),
            (w.viewer.clone(), "view".into()),
        ]),
        origin: Value::Null,
        ..Default::default()
    };
    kernel::import_record_as(
        &w.db,
        &host,
        "diag:message-template",
        &root,
        Some(&w.admin),
        &kernel::ImportRecordState {
            definition: Some(kernel::ImportDefinition {
                pin: crate::meta::definition_artifact::RevisionIdentity {
                    family: definition.family.clone(),
                    version: definition.version,
                    digest: definition.digest.clone(),
                },
                primary_type: "V1".into(),
                kind: crate::v2_standard::v1_compat::KIND.into(),
                fields: crate::v2_standard::v1_compat::compat_fields(
                    "Message",
                    "text",
                    Some("Diagnostic message template"),
                    None,
                    None,
                ),
            }),
            body: Some("message fixture".into()),
            message: Some(message.clone()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let mut tx = w.db.write_pool().begin().await.unwrap();
    sqlx::query("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<?1) INSERT INTO kernel_records(id,home_id,owner_id,primary_type,kind,accession,pin_family,pin_version,pin_digest,interpreter,created_seq,created_at) SELECT printf('diag:%05d',x),CASE WHEN x%10=0 THEN ?4 ELSE json_extract(?3,'$['||((x-1)%?5)||']') END,r.owner_id,r.primary_type,r.kind,printf('diag:%05d',x),r.pin_family,r.pin_version,r.pin_digest,r.interpreter,r.created_seq,r.created_at FROM n CROSS JOIN kernel_records r WHERE r.id=?2")
        .bind(records as i64).bind(&w.first).bind(serde_json::to_string(&home_ids).unwrap()).bind(&private).bind(homes as i64).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO kernel_record_fields(record_id,name,value_json,created_seq) SELECT r.id,'title',json_quote(CASE WHEN r.id IN ('diag:00002','diag:00003') THEN 'Alpha' ELSE 'Diagnostic '||substr(r.id,6) END),r.created_seq FROM kernel_records r WHERE r.id LIKE 'diag:%' AND r.id!='diag:message-template'")
        .execute(&mut *tx).await.unwrap();
    let large_body = "large document paragraph\n".repeat(11_000);
    sqlx::query("INSERT INTO kernel_record_fields(record_id,name,value_json,created_seq) SELECT id,'body',json_quote(CASE WHEN id='diag:00001' OR CAST(substr(id,6) AS INTEGER)%1000=1 THEN ?1 ELSE ?2 END),created_seq FROM kernel_records WHERE id LIKE 'diag:%' AND id!='diag:message-template'")
        .bind(&large_body).bind("small fixture paragraph\n".repeat(50)).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO kernel_record_fields(record_id,name,value_json,created_seq) SELECT id,'lifecycle','\"active\"',created_seq FROM kernel_records WHERE id LIKE 'diag:%' AND id!='diag:message-template' AND CAST(substr(id,6) AS INTEGER)<=min(?1,3600)")
        .bind(records as i64).execute(&mut *tx).await.unwrap();
    let messages = (records / 8).min(2000);
    sqlx::query("UPDATE kernel_records AS r SET primary_type=t.primary_type,kind=t.kind,pin_family=t.pin_family,pin_version=t.pin_version,pin_digest=t.pin_digest,interpreter=t.interpreter FROM kernel_records t WHERE t.id='diag:message-template' AND r.id LIKE 'diag:%' AND r.id!='diag:message-template' AND CAST(substr(r.id,6) AS INTEGER)>?1")
        .bind((records-messages) as i64).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO kernel_record_fields(record_id,name,value_json,created_seq) SELECT r.id,f.name,f.value_json,r.created_seq FROM kernel_records r CROSS JOIN kernel_record_fields f WHERE r.id LIKE 'diag:%' AND r.id!='diag:message-template' AND CAST(substr(r.id,6) AS INTEGER)>?1 AND f.record_id='diag:message-template' AND f.name IN ('v1_type','v1_kind')")
        .bind((records-messages) as i64).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO kernel_messages SELECT id,?2,created_seq FROM kernel_records WHERE id LIKE 'diag:%' AND id!='diag:message-template' AND CAST(substr(id,6) AS INTEGER)>?1")
        .bind((records-messages) as i64).bind(serde_json::to_string(&message).unwrap()).execute(&mut *tx).await.unwrap();
    if edits > 0 {
        sqlx::query("WITH RECURSIVE edits(k) AS (VALUES(1) UNION ALL SELECT k+1 FROM edits WHERE k<?1) INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) SELECT 'diag-edit:'||r.id||':'||k,r.id,CASE WHEN k%2=0 THEN 'kernel.legacy_recorded.v1' ELSE 'kernel.body_set.v1' END,CASE WHEN k%2=0 THEN '{}' ELSE json_object('body','retained fixture revision') END,CASE WHEN k%3=0 THEN ?3 ELSE ?2 END,'2026-11-08T02:00:00Z',1,'legacy_unknown' FROM edits CROSS JOIN kernel_records r WHERE r.id LIKE 'diag:%' AND r.id!='diag:message-template' ORDER BY k,r.id")
            .bind(edits as i64).bind(&w.admin).bind(&w.viewer).execute(&mut *tx).await.unwrap();
        sqlx::query("INSERT INTO kernel_legacy_sql_events SELECT seq,id,record_id,'record.updated',CASE WHEN actor=?1 THEN 'v1:acct:admin' ELSE 'v1:acct:viewer' END,NULL,NULL,created_at,'content_events' FROM content_events WHERE id LIKE 'diag-edit:%' AND type='kernel.legacy_recorded.v1'; INSERT INTO kernel_legacy_history SELECT seq,'record.updated',json_array(record_id),NULL,0,0,0,2 FROM content_events WHERE id LIKE 'diag-edit:%' AND type='kernel.legacy_recorded.v1'; INSERT INTO kernel_legacy_subjects SELECT record_id,seq FROM content_events WHERE id LIKE 'diag-edit:%' AND type='kernel.legacy_recorded.v1'; INSERT OR REPLACE INTO kernel_legacy_sql_progress VALUES(1,(SELECT coalesce(max(seq),0) FROM content_events WHERE type='kernel.legacy_recorded.v1'),1,1)")
            .bind(&w.admin).execute(&mut *tx).await.unwrap();
    }
    if moved > 0 {
        if let Some(folder) = &logical_folder {
            // Preserve physical ACL placement, including private rows, while
            // exercising independently filed logical destinations. Half the
            // rows visiting the requested folder subsequently leave it.
            sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) SELECT 'diag-move:'||id,id,'kernel.record_rehomed.v2',json_object('new_home_id',home_id,'logical_home_id',CASE WHEN CAST(substr(id,6) AS INTEGER)%20 IN (0,2) THEN ?3 ELSE home_id END,'parent_update',NULL),?1,'2026-11-08T03:00:00Z',1,'legacy_unknown' FROM kernel_records WHERE id LIKE 'diag:%' AND id!='diag:message-template' AND CAST(substr(id,6) AS INTEGER)%100<?2")
                .bind(&w.admin).bind(moved as i64).bind(folder).execute(&mut *tx).await.unwrap();
            sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) SELECT 'diag-move-away:'||id,id,'kernel.record_rehomed.v2',json_object('new_home_id',home_id,'logical_home_id',home_id,'parent_update',NULL),?1,'2026-11-08T04:00:00Z',1,'legacy_unknown' FROM kernel_records WHERE id LIKE 'diag:%' AND id!='diag:message-template' AND CAST(substr(id,6) AS INTEGER)%100<?2 AND CAST(substr(id,6) AS INTEGER)%40 IN (0,2)")
                .bind(&w.admin).bind(moved as i64).execute(&mut *tx).await.unwrap();
        } else {
            // Retain the original serving shape: valid legacy move receipts
            // may omit the logical destination and use physical placement.
            sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) SELECT 'diag-move:'||id,id,'kernel.record_rehomed.v1',json_object('new_home_id',home_id),?1,'2026-11-08T03:00:00Z',1,'legacy_unknown' FROM kernel_records WHERE id LIKE 'diag:%' AND id!='diag:message-template' AND CAST(substr(id,6) AS INTEGER)%100<?2")
                .bind(&w.admin).bind(moved as i64).execute(&mut *tx).await.unwrap();
        }
    }
    sqlx::query("INSERT INTO kernel_generic_links(link_id,source_id,target_id,relationship,created_at,active,event_seq,imported) SELECT 'diag-link:'||id,id,printf('diag:%05d',(CAST(substr(id,6) AS INTEGER)%?1)+1),'relates_to',created_at,1,created_seq,1 FROM kernel_records WHERE id LIKE 'diag:%' AND id!='diag:message-template' AND CAST(substr(id,6) AS INTEGER)<=4000")
        .bind(records as i64).execute(&mut *tx).await.unwrap();
    if extra_links > 0 {
        sqlx::query("WITH RECURSIVE extra(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM extra WHERE n<?1) INSERT INTO kernel_generic_links(link_id,source_id,target_id,relationship,created_at,active,event_seq,imported) SELECT 'diag-extra-link:'||n,'diag:00003','diag:00004','diag_extra_'||n,r.created_at,1,r.created_seq,1 FROM extra CROSS JOIN kernel_records r WHERE r.id='diag:00003'")
            .bind(extra_links as i64).execute(&mut *tx).await.unwrap();
    }
    tx.commit().await.unwrap();
    kernel::ensure_record_metadata(&w.db).await.unwrap();
    #[cfg(feature = "v2-kernel-probe")]
    let provider_anchor = if provider_fixture {
        Some(small_read_provider_fixture(&w, &root, providers, provider_slots).await)
    } else {
        None
    };
    #[cfg(not(feature = "v2-kernel-probe"))]
    let provider_anchor: Option<(String, String)> = {
        assert!(
            !provider_fixture,
            "provider fixtures require v2-kernel-probe"
        );
        let _ = (providers, provider_slots);
        None
    };
    #[cfg(feature = "v2-kernel-probe")]
    if trial_indexes {
        let production_indexes_present: i64 = sqlx::query_scalar("SELECT count(*) FROM sqlite_schema WHERE type='index' AND name IN ('idx_kernel_record_names','idx_kernel_record_logical_homes')")
            .fetch_one(w.db.write_pool()).await.unwrap();
        let write_fixture = if write_pairs > 0 {
            let package = crate::v2_standard::document_package();
            let installed = kernel::install_package_as(&w.db, &w.admin, &package)
                .await
                .unwrap();
            kernel::adopt_package_at(
                &w.db,
                &w.admin,
                KERNEL_ROOT_ID,
                &package,
                Some(&installed),
                &package.declared_reads,
            )
            .await
            .unwrap();
            Some(call_as(&w, "acct:admin", "create_record", json!({"type":"Document","kind":"note","name":"Diagnostic write probe","home_id":root})).await.unwrap()["id"].as_str().unwrap().to_owned())
        } else {
            None
        };
        let before = if let Some(id) = &write_fixture {
            small_read_index_write_probe(
                &w,
                id,
                &root,
                logical_folder.as_ref().unwrap(),
                write_pairs,
            )
            .await
        } else {
            Value::Null
        };
        let build = small_read_candidate_index_fixture(&w).await;
        let after = if let Some(id) = &write_fixture {
            small_read_index_write_probe(
                &w,
                id,
                &root,
                logical_folder.as_ref().unwrap(),
                write_pairs,
            )
            .await
        } else {
            Value::Null
        };
        eprintln!(
            "{}",
            json!({"small_read_index_trial_setup":{"indexes":build,"production_indexes_present":production_indexes_present,"canonical_writes_before_disposable_indexes":before,"canonical_writes_after_disposable_indexes":after}})
        );
    }
    let dimensions: (i64,i64,i64,i64,i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM kernel_records),(SELECT count(*) FROM content_events),(SELECT count(*) FROM kernel_roots),(SELECT count(*) FROM kernel_legacy_sql_events),(SELECT count(*) FROM content_events WHERE type IN ('kernel.record_rehomed.v1','kernel.record_rehomed.v2')),(SELECT sum(length(CAST(value_json AS BLOB))) FROM kernel_record_fields WHERE name='body')")
        .fetch_one(w.db.write_pool()).await.unwrap();
    let move_dimensions: (i64,i64,i64) = sqlx::query_as("SELECT coalesce(sum(type='kernel.record_rehomed.v1'),0),coalesce(sum(type='kernel.record_rehomed.v2'),0),coalesce(sum(json_extract(payload,'$.logical_home_id') IS NOT NULL),0) FROM content_events WHERE type IN ('kernel.record_rehomed.v1','kernel.record_rehomed.v2')")
        .fetch_one(w.db.write_pool()).await.unwrap();
    let link_dimensions: (i64,i64,i64,i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM kernel_generic_links WHERE active=1),(SELECT count(*) FROM kernel_links),(SELECT count(*) FROM kernel_provider_state WHERE provider_key='relates_to.v1'),(SELECT count(*) FROM kernel_provider_link_rows),(SELECT count(*) FROM kernel_provider_subjects)")
        .fetch_one(w.db.write_pool()).await.unwrap();
    eprintln!(
        "{}",
        json!({"small_read_fixture":{"records":dimensions.0,"events":dimensions.1,"homes":dimensions.2,"retained_headers":dimensions.3,"moves":dimensions.4,"move_format":move_format,"v1_moves":move_dimensions.0,"v2_moves":move_dimensions.1,"moves_with_logical_home":move_dimensions.2,"encoded_body_bytes":dimensions.5,"added_message_states":messages,"added_lifecycle_fields":records.min(3600),"added_home_depth":6,"generic_links":link_dimensions.0,"legacy_links":link_dimensions.1,"provider_aggregates":link_dimensions.2,"provider_rows":link_dimensions.3,"provider_subjects":link_dimensions.4,"added_unrelated_providers":providers,"provider_record_slots":provider_slots,"added_unrelated_links":extra_links,"trial_indexes":trial_indexes,"detail":detail,"synchronize_links":synchronize_links,"fixture":"bulk serving projections and event headers plus optional canonical providers; not a replay qualification","debug_assertions":cfg!(debug_assertions)}})
    );
    let mut names = vec![
        "Alpha".to_owned(),
        "Secret".to_owned(),
        "Alpha".to_owned(),
        "alpha".to_owned(),
        "Missing diagnostic name".to_owned(),
    ];
    names.extend((1..=95).map(|n| format!("Diagnostic {n:05}")));
    let mut cases = vec![
        ("render_small", "render_record", json!({"id":w.first})),
        ("render_large", "render_record", json!({"id":"diag:00001"})),
        ("resolve_one", "resolve_many", json!({"names":["Alpha"]})),
        ("resolve_100", "resolve_many", json!({"names":names})),
    ];
    if let Some(folder) = logical_folder {
        cases.push((
            "render_moved_children",
            "render_record",
            json!({"id":folder}),
        ));
    }
    if let Some((anchor, empty)) = provider_anchor {
        cases.push(("render_provider", "render_record", json!({"id":anchor})));
        cases.push(("render_no_links", "render_record", json!({"id":empty})));
    }
    let registry = std::sync::Arc::new(registry());
    let mut expected = std::collections::BTreeMap::new();
    let mut narrow_failures = 0;
    for credential in ["acct:admin", "acct:viewer"] {
        for (case, tool, args) in &cases {
            for callers in if diagnostic { vec![1, 4] } else { vec![1] } {
                // Rotate and reverse all three implementations so none always
                // receives the first warm-cache observation. The old anchor
                // selector isolates this change from the prior renderer work.
                let mut samples = [Vec::new(), Vec::new(), Vec::new()];
                let mut warmup_failures = [0, 0, 0];
                for wave in 0..=waves {
                    let mut order = [0usize, 1, 2];
                    order.rotate_left(wave % 3);
                    if wave % 2 == 1 {
                        order.reverse();
                    }
                    for mode in order {
                        let staging = ["full_oracle", "all_moved_candidates", "narrow"][mode];
                        let barrier = (mode == 2 && synchronize_links && *tool == "render_record")
                            .then(|| std::sync::Arc::new(tokio::sync::Barrier::new(callers)));
                        let mut workers = Vec::new();
                        for worker in 0..callers {
                            let db = w.db.clone();
                            let registry = registry.clone();
                            let args = args.clone();
                            let tool = *tool;
                            let barrier = barrier.clone();
                            let detail = detail.clone();
                            let span = tracing::info_span!(target:"native_ce::read_staging", "small_read_sample", credential, case, wave, worker, staging);
                            workers.push(tokio::spawn(
                                async move {
                                    let started = std::time::Instant::now();
                                    let invoke = registry.call_engine(
                                        EngineHandle::KernelV2(db),
                                        Caller::authenticated(credential),
                                        tool,
                                        args,
                                    );
                                    let work = async {
                                        if mode == 0 {
                                            record_reads::with_full_small_read_staging(invoke).await
                                        } else if mode == 1 {
                                            sql::with_all_moved_candidates(invoke).await
                                        } else {
                                            invoke.await
                                        }
                                    };
                                    #[cfg(feature = "v2-kernel-probe")]
                                    let ((answer, details), stats) =
                                        sql::measured(small_read_detailed_call(
                                            mode == 2
                                                && matches!(detail.as_str(), "candidates" | "both"),
                                            mode == 2
                                                && matches!(detail.as_str(), "links" | "both"),
                                            trial_indexes,
                                            barrier,
                                            work,
                                        ))
                                        .await;
                                    #[cfg(not(feature = "v2-kernel-probe"))]
                                    let ((answer, details), stats) = {
                                        let _ = (barrier, detail, trial_indexes);
                                        let (answer, stats) = sql::measured(work).await;
                                        ((answer, Value::Null), stats)
                                    };
                                    let call_us = started.elapsed().as_micros() as u64;
                                    let started = std::time::Instant::now();
                                    let bytes = answer
                                        .as_ref()
                                        .ok()
                                        .map(|v| serde_json::to_vec(v).unwrap().len())
                                        .unwrap_or(0);
                                    (
                                        answer,
                                        stats,
                                        call_us,
                                        started.elapsed().as_micros() as u64,
                                        bytes,
                                        details,
                                    )
                                }
                                .instrument(span),
                            ));
                        }
                        for worker in workers {
                            let (answer, stats, call_us, serialize_us, bytes, details) =
                                worker.await.unwrap();
                            if !details.is_null() {
                                eprintln!(
                                    "{}",
                                    json!({"small_read_detail":{"caller":credential,"case":case,"callers":callers,"wave":wave,"synchronize_links":synchronize_links,"succeeded":answer.is_ok(),"details":details,"timing":"instrumented probes; separate from latency comparisons"}})
                                );
                            }
                            let failed = answer.is_err();
                            if mode == 2 && failed {
                                narrow_failures += 1;
                            }
                            if wave == 0 && failed {
                                warmup_failures[mode] += 1;
                            }
                            let timeout = answer.as_ref().err().is_some_and(|e| {
                                ["interrupted", "timeout", "deadline", "cannot rollback"]
                                    .iter()
                                    .any(|s| e.to_string().contains(s))
                            });
                            if let Ok(value) = answer {
                                if let Some(prior) = expected.get(&(credential, *case)) {
                                    assert_eq!(&value, prior, "{credential} {case}");
                                } else {
                                    expected.insert((credential, *case), value);
                                }
                            } else if !diagnostic {
                                panic!("default small-read diagnostic failed: {credential} {case}");
                            }
                            if wave > 0 {
                                samples[mode].push((
                                    call_us,
                                    serialize_us,
                                    bytes,
                                    failed,
                                    timeout,
                                    stats.staged_records,
                                    stats.home_checks,
                                    stats.installations,
                                    stats.staging_us,
                                    stats.staging_vm_ops,
                                    stats.pool_wait_us,
                                ));
                            }
                        }
                    }
                }
                for (mode, samples) in samples.into_iter().enumerate() {
                    let staging = ["full_oracle", "all_moved_candidates", "narrow"][mode];
                    eprintln!(
                        "{}",
                        json!({"small_read_measurement":{"caller":credential,"case":case,"staging":staging,"thermal":"warm; one warmup wave excluded; rotating/reversed implementation order","callers":callers,"samples":samples.len(),"warmup_failures":warmup_failures[mode],"baseline_failures_permitted":diagnostic && mode!=2,"failures":samples.iter().filter(|s|s.3).count(),"timeouts_or_rollback_errors":samples.iter().filter(|s|s.4).count(),"call_us":quantiles(samples.iter().map(|s|s.0).collect()),"serialization_us":quantiles(samples.iter().map(|s|s.1).collect()),"max_response_bytes":samples.iter().map(|s|s.2).max(),"staged_records":quantiles(samples.iter().map(|s|s.5).collect()),"max_home_checks":samples.iter().map(|s|s.6).max(),"max_installations":samples.iter().map(|s|s.7).max(),"staging_us":quantiles(samples.iter().map(|s|s.8).collect()),"staging_vm_ops":quantiles(samples.iter().map(|s|s.9).collect()),"pool_wait_us":quantiles(samples.iter().map(|s|s.10).collect())}})
                    );
                }
            }
        }
    }
    // Keep ordinary-get claim fixtures outside the renderer measurement matrix.
    seed_claim_directory_diagnostic(&w).await;
    let get_dimensions: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM kernel_records),(SELECT count(*) FROM content_events)",
    )
    .fetch_one(w.db.pool())
    .await
    .unwrap();
    eprintln!(
        "{}",
        json!({"ordinary_get_fixture":{"records":get_dimensions.0,"events":get_dimensions.1,"directory_rows":101,"serving_projection_fixture":true}})
    );
    // Ordinary get_record, not render_record's closed renderer entry point.
    // One warmup + one measured pair per caller; no concurrency/perf matrix.
    for credential in ["acct:admin", "acct:viewer"] {
        let mut default_value: Option<Value> = None;
        for (case, args) in [
            ("default", json!({"ids":["diag:00001"]})),
            (
                "lean",
                json!({"ids":["diag:00001"],"include_comments":false,"include_citations":false,"include_suggestions":false,"include_history_summary":false,"children_limit":0,"links_limit":0}),
            ),
        ] {
            for wave in 0..2 {
                let span = tracing::info_span!(target:"native_ce::read_staging", "ordinary_get_sample", credential, case, wave);
                let started = std::time::Instant::now();
                let (answer, stats) =
                    sql::measured(call_as(&w, credential, "get_record", args.clone()))
                        .instrument(span)
                        .await;
                let elapsed = started.elapsed().as_micros() as u64;
                let value = answer.unwrap();
                assert_eq!(value["records"][0]["status"], "found");
                if wave == 1 {
                    let mut comparable = value.clone();
                    for key in ["children", "links_in", "links_out"] {
                        comparable["records"][0]
                            .as_object_mut()
                            .unwrap()
                            .remove(key);
                    }
                    if let Some(default_value) = &default_value {
                        assert_eq!(
                            &comparable, default_value,
                            "default/lean counts and core data differ"
                        );
                    } else {
                        default_value = Some(comparable);
                    }
                    eprintln!(
                        "{}",
                        json!({"ordinary_get_measurement":{"caller":credential,"case":case,"warmup_excluded":true,"call_us":elapsed,"pool_wait_us":stats.pool_wait_us,"staging_us":stats.staging_us,"remaining_call_us":elapsed.saturating_sub(stats.pool_wait_us+stats.staging_us),"staging_vm_ops":stats.staging_vm_ops,"staged_records":stats.staged_records,"home_checks":stats.home_checks,"response_bytes":serde_json::to_vec(&value).unwrap().len(),"directory_rows":101,"failures":0,"retries":0}})
                    );
                }
            }
        }
    }
    w.db.close().await;
    assert_eq!(
        narrow_failures, 0,
        "narrow requests failed; inspect emitted diagnostic measurements"
    );
}

#[tokio::test]
async fn record_reads_temp_write_interrupt_preserves_deadline_error() {
    let w = world().await;
    let error = sql::TEST_SNAPSHOT_BUDGET.scope(
        std::time::Duration::from_millis(5),
        sql::with_read_session(
            &w.db,
            &w.admin,
            &[("records", "id")],
            sql::in_snapshot(&w.db, &w.admin, |conn| Box::pin(async move {
                sqlx::query("CREATE TEMP TABLE _interrupt_probe(n INTEGER)")
                    .execute(&mut *conn).await?;
                let error = sqlx::query("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<100000000) INSERT INTO temp._interrupt_probe SELECT x FROM n")
                    .execute(&mut *conn).await.unwrap_err();
                let mut handle = conn.lock_handle().await?;
                // SAFETY: the locked SQLite handle is exclusively borrowed and live.
                assert_ne!(unsafe { libsqlite3_sys::sqlite3_get_autocommit(handle.as_raw_handle().as_ptr()) }, 0);
                Err::<(), _>(error.into())
            })),
        ),
    ).await.unwrap_err();
    assert!(
        error.to_string().contains("(code: 9) interrupted"),
        "{error}"
    );
    let out = call_as(&w, "acct:admin", "scan", json!({})).await.unwrap();
    assert_eq!(out["corpus_size"], 3);
    w.db.close().await;
}

#[path = "sql_hq_bench.rs"]
mod sql_hq_bench;

#[tokio::test]
async fn kernel_v2_composed_body_reads_match_standalone_for_points_and_filters() {
    let w = world().await;
    kernel::revise_as(
        &w.db,
        &w.admin,
        &w.hidden,
        json!({"body":"private body witness"}).as_object().unwrap(),
    )
    .await
    .unwrap();
    let queries = [
        ("SELECT id, body FROM records WHERE id = ?1", Some(w.first.as_str())),
        ("SELECT id, name, body FROM records WHERE body LIKE ?1 ORDER BY id", Some("%original%")),
        ("SELECT id, substr(body,1,8) AS excerpt, length(body) AS body_length FROM records ORDER BY id", None),
        ("SELECT body FROM records WHERE body LIKE ?1 ORDER BY body", Some("%")),
    ];
    for actor in [&w.admin, &w.viewer] {
        for (statement, parameter) in queries {
            let mut args = json!({"sql":statement});
            if let Some(value) = parameter {
                args["parameters"] = json!([{"type":"text","value":value}]);
            }
            let expected = sql::query_sql(&w.db, actor, args.clone()).await.unwrap();
            let actual = sql::with_query_read_session(
                &w.db,
                actor,
                &[statement],
                sql::query_sql(&w.db, actor, args),
            )
            .await
            .unwrap();
            assert_eq!(actual["columns"], expected["columns"]);
            assert_eq!(actual["rows"], expected["rows"], "{statement}");
            if actor == &w.viewer {
                assert!(!actual["rows"].to_string().contains("private body witness"));
            }
            if statement == queries[0].0 {
                assert_eq!(actual["rows"][0]["body"], "revised");
            }
        }
    }
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_composed_point_body_ignores_unrelated_oversized_body() {
    let w = world().await;
    kernel::revise_as(
        &w.db,
        &w.admin,
        &w.second,
        json!({"body":"x".repeat(crate::query::sql::MAX_SQLITE_VALUE_BYTES as usize + 4096)})
            .as_object()
            .unwrap(),
    )
    .await
    .unwrap();
    let statement =
        "SELECT id, body FROM records WHERE id = ?1 AND type = 'Document' AND kind = 'note'";
    for projected in [false, true] {
        if projected {
            kernel::sql_record_projection::catch_up(&w.db)
                .await
                .unwrap();
        }
        for actor in [&w.admin, &w.viewer] {
            let args = json!({"sql":statement,"parameters":[{"type":"text","value":w.first}]});
            let expected = sql::query_sql(&w.db, actor, args.clone()).await.unwrap();
            let actual = sql::with_query_read_session(
                &w.db,
                actor,
                &[statement],
                sql::query_sql(&w.db, actor, args),
            )
            .await
            .unwrap();
            assert_eq!(actual["rows"], expected["rows"], "projected={projected}");
        }
    }
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_prism_bound_event_reads_match_full_staging() {
    let w = world().await;
    install_comment_carrier(&w).await;
    kernel::hosted_identity::reconcile_hosted_caller(&w.db, |_| async {
        // SAFETY: complete synthetic membership matching this fixture's bindings.
        Ok(unsafe {
            kernel::hosted_identity::VerifiedHostedMembership::from_catalog_unchecked(
                "acct:admin".into(),
                std::collections::BTreeMap::from([
                    ("acct:admin".into(), "admin@example.test".into()),
                    ("acct:viewer".into(), "viewer@example.test".into()),
                ]),
                std::collections::BTreeMap::new(),
            )
        })
    })
    .await
    .unwrap();
    let mut tasks = Vec::new();
    for parent in [&w.first, &w.hidden] {
        let home = kernel::read_record_as(&w.db, &w.admin, parent)
            .await
            .unwrap()
            .unwrap()
            .home_id;
        let task = call_as(&w,"acct:admin","create_record",json!({"type":"WorkItem","kind":"task","name":"Prism subject","body":"Selected body","home_id":home})).await.unwrap()["id"].as_str().unwrap().to_owned();
        call_as(&w,"acct:admin","create_record",json!({"type":"Annotation","kind":"comment","body":"Discussion","links":[{"target_id":task,"relationship":"part_of"}]})).await.unwrap();
        kernel::observe_facet_as(
            &w.db,
            &w.admin,
            &task,
            &kernel::FacetObservation {
                key: "prism-proof".into(),
                value: Some("kept".into()),
                value_num: None,
                vocab_ref: None,
                as_of: chrono::Utc::now().to_rfc3339(),
            },
            None,
        )
        .await
        .unwrap();
        tasks.push(task);
    }
    kernel::add_generic_link_as(&w.db, &w.admin, &tasks[0], &tasks[1], "supersedes", None)
        .await
        .unwrap();
    let needs: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/kernel_v2_prism_reads.json"
    ))
    .unwrap();
    for projected in [false, true] {
        if projected {
            kernel::sql_record_projection::catch_up(&w.db)
                .await
                .unwrap();
            kernel::sql_event_projection::catch_up(&w.db).await.unwrap();
        }
        for actor in [&w.admin, &w.viewer] {
            for target in [&tasks[0], &tasks[1]] {
                for need in needs.as_array().unwrap().iter().filter(|n| {
                    ["prism.history", "prism.comments", "prism.runs"]
                        .contains(&n["key"].as_str().unwrap())
                }) {
                    let args =
                        json!({"sql":need["sql"],"parameters":[{"type":"text","value":target}]});
                    let (expected, full_stats) = sql::measured(sql::with_full_event_staging(
                        sql::query_sql(&w.db, actor, args.clone()),
                    ))
                    .await;
                    let expected = expected.unwrap();
                    let (actual, stats) = sql::measured(sql::with_bound_query_read_session(
                        &w.db,
                        actor,
                        std::slice::from_ref(&args),
                        sql::query_sql(&w.db, actor, args.clone()),
                    ))
                    .await;
                    let actual = actual.unwrap();
                    assert_eq!(
                        actual["rows"], expected["rows"],
                        "{} projected={projected}",
                        need["key"]
                    );
                    assert_eq!(actual["columns"], expected["columns"]);
                    if !projected {
                        assert!(
                            stats.native_event_rows + stats.legacy_event_rows
                                < full_stats.native_event_rows + full_stats.legacy_event_rows,
                            "{} did not reduce staged events: {stats:?} vs {full_stats:?}",
                            need["key"]
                        );
                    }
                    if actor == &w.viewer && target == &tasks[1] {
                        assert_eq!(actual["row_count"], 0);
                    }
                    if actor == &w.admin && need["key"] != "prism.runs" {
                        assert!(actual["row_count"].as_u64().unwrap() > 0);
                        if need["key"] == "prism.history" {
                            assert!(actual["rows"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .any(|r| r["facet_key"] == "prism-proof"
                                    && r["facet_value"] == "kept"));
                        }
                    }
                }
            }
        }
    }
    w.db.close().await;
}

/// Explicit disposable-copy diagnostic; never point this at a serving store.
#[tokio::test]
#[ignore = "Installed Prism SQL on an explicitly supplied disposable HQ copy (d8550c6)"]
async fn kernel_v2_prism_disposable_copy_profile() {
    use crate::realtime::v2::{AppDataNeeds, AppDataRequest};
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};
    let _ = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .without_time()
                .with_writer(std::io::stderr)
                .with_filter(tracing_subscriber::filter::filter_fn(|m| {
                    m.target() == "native_ce::read_staging"
                })),
        )
        .try_init();
    let path = std::path::PathBuf::from(
        std::env::var("NATIVE_PRISM_BENCH_COPY").expect("explicit copy required"),
    )
    .canonicalize()
    .unwrap();
    let target = std::env::current_dir()
        .unwrap()
        .join("target")
        .canonicalize()
        .unwrap();
    assert!(
        path.starts_with(&target),
        "diagnostic copy must be inside this checkout's target directory"
    );
    let record = std::env::var("NATIVE_PRISM_BENCH_RECORD").expect("explicit record required");
    let db = kernel::open_marked_v2_database(path.to_str().unwrap())
        .await
        .unwrap();
    let installs: Vec<(String,String,String,String)> = sqlx::query_as("SELECT p.auth_binding,a.generation,json_extract(a.row_json,'$.version'),json_extract(a.row_json,'$.consented_declaration') FROM kernel_app_installs a JOIN kernel_principals p ON p.principal_id=a.principal WHERE a.package='agent.prism' AND a.status='installed'").fetch_all(db.pool()).await.unwrap();
    assert_eq!(
        installs.len(),
        1,
        "select an unambiguous installed Prism copy"
    );
    let (binding, generation, version, declaration) = &installs[0];
    let declaration: Value = serde_json::from_str(declaration).unwrap();
    let app_v2 = declaration["contract"] == "native.app.v2";
    let caller = Caller::authenticated(binding);
    let app_caller = caller.clone().with_host_asserted_app(
        crate::mcp::app_attribution::AppAttribution::new("agent.prism", version, generation)
            .unwrap(),
    );
    let registry = registry();
    let needs: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/kernel_v2_prism_reads.json"
    ))
    .unwrap();
    eprintln!(
        "PRISM_COPY_MODE {}",
        json!({"version":version,"path":if app_v2 {"current_app_query_sql"} else {"declared_live_read"}})
    );
    let cache = sql::visible_cache::enable_for_test(&db).await;
    let mut failures = 0;
    for warm in [false, true] {
        if warm {
            let started = std::time::Instant::now();
            kernel::sql_record_projection::catch_up(&db).await.unwrap();
            kernel::sql_event_projection::catch_up(&db).await.unwrap();
            eprintln!(
                "PRISM_COPY_FOLD {}",
                json!({"ms":started.elapsed().as_millis()})
            );
        }
        for need in needs.as_array().unwrap() {
            let key = (need["key"] != "prism.records").then(|| need["key"].as_str().unwrap());
            let request = AppDataRequest {
                package: "agent.prism".into(),
                expected_install_event_id: generation.clone(),
                need: key.map(str::to_owned),
                params: if key.is_some() {
                    json!({"id":record})
                } else {
                    json!({})
                },
            };
            let started = std::time::Instant::now();
            let (result, stats) = if app_v2 {
                // Prism 0.2 preserves the seven SQL statements but uses the
                // shared host's ordinary app-attributed query_sql path. Keep
                // its current source/install/grant admission intact.
                let parameters = if key.is_some() {
                    json!([{"type":"text","value":record}])
                } else {
                    json!([])
                };
                sql::measured(registry.call_engine(
                    EngineHandle::KernelV2(db.clone()),
                    app_caller.clone(),
                    "query_sql",
                    json!({"sql":need["sql"],"parameters":parameters}),
                ))
                .await
            } else {
                let (result, stats) =
                    sql::measured(super::NativeAppDataNeeds.evaluate(&db, &caller, &request)).await;
                (result.map(|v| v.result), stats)
            };
            failures += usize::from(result.is_err());
            if let Err(error) = &result {
                // Refusal/error diagnostics only; returned bodies/rows are
                // never emitted by this explicit private-copy profile.
                eprintln!("PRISM_COPY_ERROR {error}");
            }
            eprintln!(
                "PRISM_COPY_READ {}",
                json!({"need":key.unwrap_or("startup"),"warm":warm,"ms":started.elapsed().as_millis(),"ok":result.is_ok(),"rows":result.as_ref().ok().and_then(|v|v["row_count"].as_u64().or_else(||v["result"]["row_count"].as_u64())),"stats":stats,"visibility_cache":format!("{:?}",cache.stats.lock().unwrap())})
            );
        }
    }
    sql::visible_cache::disable_for_test(&db);
    db.close().await;
    assert_eq!(
        failures, 0,
        "inspect numeric copy diagnostics; no production acceptance is implied"
    );
}

/// Native design 3a3eabb, proof obligation 1 (pre-implementation): for every
/// recognised anchor-first extended query_record, every row the CURRENT full
/// staging path returns lies inside the plan's direct candidate superset.
/// Adversarial fixture: hidden and private records, moves in and out of
/// private homes, a deletion, links of several relationships including to a
/// hidden record, a self-link and a cycle, missing anchor ids and root aliases.
#[tokio::test]
async fn extended_query_record_results_lie_within_anchor_candidates() {
    use std::collections::BTreeSet;
    let w = world().await;
    let note = |title: &str| json!({"title": title}).as_object().unwrap().clone();
    let shared = kernel::create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.viewer, "view")]),
        &w.admin,
    )
    .await
    .unwrap();
    let private = kernel::create_home(&w.db, KERNEL_ROOT_ID, Some(&[]), &w.admin)
        .await
        .unwrap();
    let mut made = Vec::new();
    for (title, home) in [
        ("Root note", KERNEL_ROOT_ID),
        ("Shared a", shared.as_str()),
        ("Shared b", shared.as_str()),
        ("Private a", private.as_str()),
        ("Mover in", private.as_str()),
        ("Mover out", shared.as_str()),
        ("Doomed", shared.as_str()),
    ] {
        made.push(
            kernel::create_as(&w.db, &w.admin, "fixture.mcp", "note", &note(title), home)
                .await
                .unwrap(),
        );
    }
    let [root_note, shared_a, shared_b, private_a, mover_in, mover_out, doomed] =
        made.try_into().unwrap();
    kernel::rehome_record_as(&w.db, &w.admin, &mover_in, &shared)
        .await
        .unwrap();
    kernel::rehome_record_as(&w.db, &w.admin, &mover_out, &private)
        .await
        .unwrap();
    let links = [
        (&shared_a, &shared_b, "relates_to"),
        (&shared_b, &shared_a, "relates_to"),  // cycle
        (&shared_a, &shared_a, "relates_to"),  // self-link
        (&shared_b, &private_a, "relates_to"), // to a hidden endpoint
        (&private_a, &shared_a, "relates_to"), // from a hidden endpoint
        (&root_note, &shared_a, "part_of"),
        (&mover_in, &doomed, "relates_to"),
        (&w.first, &shared_a, "relates_to"),
    ];
    for (source, target, relationship) in links {
        let _ = call_as(&w, "acct:admin", "manage_links", json!({"action":"add","source_id":source,"target_id":target,"relationship":relationship})).await;
    }
    call_as(
        &w,
        "acct:admin",
        "delete_record",
        json!({"id": doomed, "reason": "anchor oracle fixture"}),
    )
    .await
    .unwrap();

    let mut pipelines = Vec::new();
    for home in [
        shared.as_str(),
        private.as_str(),
        KERNEL_ROOT_ID,
        "native:root",
        "no-such-home",
    ] {
        for extra in [
            json!({}),
            json!({"types":["Document"]}),
            json!({"kinds":["note"]}),
            json!({"include_archived":true}),
        ] {
            let mut filter = json!({"step":"filter","home_id":home});
            filter
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            pipelines.push(json!({"steps":[filter]}));
        }
    }
    let anchor_sets: Vec<Vec<String>> = vec![
        vec![shared_a.clone()],
        vec![shared_b.clone()],
        vec![private_a.clone()],
        vec![w.hidden.clone()],
        vec![doomed.clone()],
        vec!["no-such-record".into()],
        vec![shared_a.clone(), private_a.clone(), "missing".into()],
        vec![mover_in.clone()],
        vec![w.first.clone(), w.second.clone()],
        vec![root_note.clone()],
        vec![shared_b.clone(), root_note.clone()],
    ];
    for ids in &anchor_sets {
        for relationship in [None, Some("relates_to"), Some("part_of"), Some("nope")] {
            for direction in [None, Some("in"), Some("out"), Some("both")] {
                let mut traverse = json!({"step":"traverse","target":"links"});
                if let Some(r) = relationship {
                    traverse["relationship"] = json!(r);
                }
                if let Some(d) = direction {
                    traverse["direction"] = json!(d);
                }
                pipelines.push(json!({"steps":[{"step":"filter","ids":ids},traverse]}));
                pipelines.push(json!({"steps":[{"step":"filter","ids":ids},traverse,{"step":"filter","types":["Document"],"include_archived":true}]}));
            }
        }
    }
    let mut checked = 0;
    for steps in pipelines {
        for order in [
            "updated_desc",
            "created_desc",
            "last_activity_desc",
            "name_asc",
        ] {
            let mut args = steps.clone();
            args["order"] = json!(order);
            args["limit"] = json!(500);
            let plan = super::read_surface::recognize_args(&args)
                .unwrap_or_else(|| panic!("not recognised: {args}"));
            let mut conn = w.db.pool().acquire().await.unwrap();
            let candidates = super::read_surface::direct_candidates_on(&mut conn, &plan)
                .await
                .unwrap();
            drop(conn);
            for credential in ["acct:admin", "acct:viewer"] {
                assert_narrowed_identical(&w, credential, &args).await;
                let Ok(result) = call_as(&w, credential, "query_record", args.clone()).await else {
                    continue;
                };
                let returned: BTreeSet<String> = result["records"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|r| r["id"].as_str().unwrap().to_owned())
                    .collect();
                let outside: Vec<_> = returned.difference(&candidates).collect();
                assert!(
                    outside.is_empty(),
                    "{credential} {args}: returned rows outside candidates {outside:?}"
                );
                checked += 1;
            }
        }
    }
    assert!(checked > 500, "oracle exercised {checked} calls");

    // Fallback shapes are never recognised.
    for args in [
        json!({"steps":[{"step":"filter","ids":[shared_a]},{"step":"traverse","target":"links"},{"step":"traverse","target":"links"}],"order":"name_asc"}),
        json!({"steps":[{"step":"filter","home_id":shared,"last_activity_since":"2000-01-01T00:00:00Z"}],"order":"name_asc"}),
        json!({"steps":[{"step":"filter","ids":[shared_a]},{"step":"traverse","target":"links"},{"step":"filter","last_activity_since":"2000-01-01T00:00:00Z"}],"order":"name_asc"}),
        json!({"steps":[{"step":"filter","ids":[shared_a]},{"step":"traverse","target":"children"}],"order":"name_asc"}),
        json!({"steps":[{"step":"filter","types":["Document"]}],"order":"name_asc"}),
        json!({"steps":[{"step":"filter","ids":[shared_a],"home_id":shared}],"order":"name_asc"}),
        json!({"steps":[{"step":"filter","home_id":shared,"facets":[]}],"order":"name_asc"}),
        json!({"steps":[{"step":"filter","ids":[shared_a]},{"step":"traverse","target":"links"},{"step":"filter","home_id":shared}],"order":"name_asc"}),
    ] {
        assert!(
            super::read_surface::recognize_args(&args).is_none(),
            "must fall back: {args}"
        );
    }
}

/// Own-row filter fields (lifecycle, maturity, persistence, name, updated
/// time) narrow P1 and P2 with byte-identical results to forced full
/// staging, stay inside the direct candidate superset, and actually select
/// rows. Includes the workbench rejection log: a record's `part_of`
/// suggestions filtered to `lifecycle:["rejected"]`.
#[tokio::test]
async fn extended_query_record_own_row_filters_narrow_with_full_staging_parity() {
    use std::collections::BTreeSet;
    let w = world().await;
    let v1 = suggestion_v1_fixture(&w).await;
    let kept = make_suggestion(&w, &v1, None, "keep", "none").await;
    let rejected = make_suggestion(&w, &v1, None, "drop", "none").await;
    let out = call_as(
        &w,
        "acct:admin",
        "resolve_suggestions",
        json!({"action":"reject","suggestion_ids":[rejected],"reason":"rejection log fixture"}),
    )
    .await
    .unwrap();
    assert_eq!(out["status"], "rejected");
    let shared = kernel::create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.viewer, "view")]),
        &w.admin,
    )
    .await
    .unwrap();
    let note = |title: &str| json!({"title": title}).as_object().unwrap().clone();
    let mut plans = Vec::new();
    for title in ["Draft plan", "Occurrent plan", "Other note"] {
        plans.push(
            kernel::create_as(
                &w.db,
                &w.admin,
                "fixture.mcp",
                "note",
                &note(title),
                &shared,
            )
            .await
            .unwrap(),
        );
    }
    call_as(
        &w,
        "acct:admin",
        "update_record",
        json!({"id":plans[0],"maturity":"draft","reason":"own-row fixture"}),
    )
    .await
    .unwrap();
    call_as(
        &w,
        "acct:admin",
        "update_record",
        json!({"id":plans[1],"persistence":"occurrent","reason":"own-row fixture"}),
    )
    .await
    .unwrap();

    let rejection_log = json!({"steps":[
        {"step":"filter","ids":[w.first]},
        {"step":"traverse","target":"links","relationship":"part_of","direction":"in"},
        {"step":"filter","kinds":["suggestion"],"lifecycle":["rejected"],"include_archived":true}
    ],"order":"created_desc","limit":20,"offset":0});
    let mut cases: Vec<(Value, Option<Vec<String>>)> =
        vec![(rejection_log, Some(vec![rejected.clone()]))];
    for (trailing, expect) in [
        (
            json!({"kinds":["suggestion"],"lifecycle":["open"]}),
            Some(vec![kept.clone()]),
        ),
        (json!({"kinds":["suggestion"],"name_contains":"sugg"}), None),
        (
            json!({"kinds":["suggestion"],"updated_since":"2000-01-01T00:00:00Z"}),
            None,
        ),
        (
            json!({"kinds":["suggestion"],"updated_since":"2999-01-01T00:00:00Z"}),
            Some(vec![]),
        ),
        (
            json!({"kinds":["suggestion"],"persistence":"enduring"}),
            None,
        ),
        (json!({"kinds":["suggestion"],"maturity":["draft"]}), None),
    ] {
        for direction in ["in", "both"] {
            let mut filter = json!({"step":"filter"});
            filter
                .as_object_mut()
                .unwrap()
                .extend(trailing.as_object().unwrap().clone());
            cases.push((
                json!({"steps":[
                    {"step":"filter","ids":[w.first]},
                    {"step":"traverse","target":"links","relationship":"part_of","direction":direction},
                    filter
                ],"order":"created_desc"}),
                expect.clone(),
            ));
        }
    }
    for home in [shared.as_str(), KERNEL_ROOT_ID] {
        let mine = home == shared;
        for (extra, expect) in [
            (json!({"maturity":["draft"]}), Some(vec![plans[0].clone()])),
            (
                json!({"persistence":"occurrent"}),
                Some(vec![plans[1].clone()]),
            ),
            (
                json!({"name_contains":"PLAN"}),
                Some(vec![plans[0].clone(), plans[1].clone()]),
            ),
            (json!({"lifecycle":["open"]}), None),
            (
                json!({"updated_since":"2000-01-01T00:00:00Z","types":["Document"]}),
                None,
            ),
            (
                json!({"updated_since":"2999-01-01T00:00:00Z"}),
                Some(vec![]),
            ),
        ] {
            let mut filter = json!({"step":"filter","home_id":home});
            filter
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            cases.push((
                json!({"steps":[filter],"order":"name_asc"}),
                if mine { expect } else { None },
            ));
        }
    }
    let mut selected = 0;
    for (args, expect) in cases {
        let plan = super::read_surface::recognize_args(&args)
            .unwrap_or_else(|| panic!("own-row filter not recognised: {args}"));
        let mut conn = w.db.pool().acquire().await.unwrap();
        let candidates = super::read_surface::direct_candidates_on(&mut conn, &plan)
            .await
            .unwrap();
        drop(conn);
        // Narrowing really engaged: fewer records staged than full staging.
        let (narrowed, full) = staged_narrowed_and_full(&w, "acct:admin", &args).await;
        assert!(
            narrowed < full,
            "{args}: narrowed {narrowed} vs full {full}"
        );
        for credential in ["acct:admin", "acct:viewer"] {
            assert_narrowed_identical(&w, credential, &args).await;
            let mut full = args.clone();
            full["limit"] = json!(500);
            full["offset"] = json!(0);
            let result = call_as(&w, credential, "query_record", full).await.unwrap();
            let returned: Vec<String> = result["records"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r["id"].as_str().unwrap().to_owned())
                .collect();
            let outside: Vec<_> = returned
                .iter()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .filter(|id| !candidates.contains(*id))
                .collect();
            assert!(
                outside.is_empty(),
                "{credential} {args}: outside candidates {outside:?}"
            );
            if let (Some(expect), "acct:admin") = (&expect, credential) {
                let mut want = expect.clone();
                want.sort();
                let mut got = returned.clone();
                got.sort();
                assert_eq!(
                    got, want,
                    "{args}: the filter must select exactly these rows"
                );
                selected += usize::from(!want.is_empty());
            }
        }
    }
    assert!(
        selected >= 5,
        "fixtures must make filters select rows: {selected}"
    );
}

/// Provider-derived links (LinkScope::All): a provider link is visible only
/// when every subject of its aggregate is staged. Containment over P2
/// pipelines on bare records with: a visible pair, a provider whose other
/// subject is HIDDEN, providers sharing endpoints, and a cycle. Also: a
/// duplicated provider link id disables narrowing (full fallback).
#[tokio::test]
async fn extended_query_record_provider_links_lie_within_anchor_candidates() {
    use crate::v2_standard::relates_to::Command;
    use std::collections::BTreeSet;
    let w = world().await;
    let package = crate::v2_standard::relates_to::package();
    let installed = kernel::install_package_as(&w.db, &w.admin, &package)
        .await
        .unwrap();
    kernel::adopt_package_at(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &package,
        Some(&installed),
        &package.declared_reads,
    )
    .await
    .unwrap();
    let shared = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let private = kernel::read_record_as(&w.db, &w.admin, &w.hidden)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    let a = kernel::create_record_as(&w.db, &w.admin, &shared)
        .await
        .unwrap();
    let b = kernel::create_record_as(&w.db, &w.admin, &shared)
        .await
        .unwrap();
    let c = kernel::create_record_as(&w.db, &w.admin, &shared)
        .await
        .unwrap();
    let h = kernel::create_record_as(&w.db, &w.admin, &private)
        .await
        .unwrap();
    for (left, right, key) in [
        (&a, &b, "p-ab"),
        (&a, &h, "p-ah-hidden"),
        (&b, &c, "p-bc"),
        (&c, &a, "p-ca-cycle"),
    ] {
        let request = kernel::prepare_provider_as(
            &w.db,
            &w.admin,
            left,
            right,
            key,
            Command::Assert { sources: vec![] },
        )
        .await
        .unwrap();
        kernel::commit_provider_as(&w.db, &w.admin, &request)
            .await
            .unwrap();
    }
    let mut conn = w.db.pool().acquire().await.unwrap();
    assert!(super::read_surface::narrowing_supported_on(&mut conn)
        .await
        .unwrap());
    drop(conn);
    let mut checked = 0;
    let mut nonempty = 0;
    for ids in [
        vec![a.clone()],
        vec![b.clone()],
        vec![h.clone()],
        vec![a.clone(), h.clone()],
        vec![c.clone(), "missing".into()],
    ] {
        for relationship in [None, Some("relates_to")] {
            for direction in [None, Some("in"), Some("out"), Some("both")] {
                let mut traverse = json!({"step":"traverse","target":"links"});
                if let Some(r) = relationship {
                    traverse["relationship"] = json!(r);
                }
                if let Some(d) = direction {
                    traverse["direction"] = json!(d);
                }
                for order in ["updated_desc", "name_asc"] {
                    let args = json!({"steps":[{"step":"filter","ids":ids},traverse],"order":order,"limit":500});
                    let plan = super::read_surface::recognize_args(&args).expect("recognised");
                    let mut conn = w.db.pool().acquire().await.unwrap();
                    let candidates = super::read_surface::direct_candidates_on(&mut conn, &plan)
                        .await
                        .unwrap();
                    drop(conn);
                    for credential in ["acct:admin", "acct:viewer"] {
                        assert_narrowed_identical(&w, credential, &args).await;
                        let Ok(result) =
                            call_as(&w, credential, "query_record", args.clone()).await
                        else {
                            continue;
                        };
                        let returned: BTreeSet<String> = result["records"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|r| r["id"].as_str().unwrap().to_owned())
                            .collect();
                        if !returned.is_empty() {
                            nonempty += 1;
                        }
                        let outside: Vec<_> = returned.difference(&candidates).collect();
                        assert!(
                            outside.is_empty(),
                            "{credential} {args}: provider rows outside candidates {outside:?}"
                        );
                        if credential == "acct:viewer" {
                            assert!(!returned.contains(&h), "hidden subject leaked: {args}");
                        }
                        checked += 1;
                    }
                }
            }
        }
    }
    assert!(
        checked > 0 && nonempty > 0,
        "provider oracle must exercise non-empty results (checked {checked}, nonempty {nonempty})"
    );

    let (aggregate, link): (String, String) = sqlx::query_as("SELECT aggregate_id,id FROM kernel_provider_link_rows ORDER BY aggregate_id,ordinal LIMIT 1")
        .fetch_one(w.db.pool()).await.unwrap();
    sqlx::query("INSERT INTO kernel_provider_link_rows(aggregate_id,ordinal,id,source_id,target_id,note,created_at,created_at_ms,raw_json,if_absent) SELECT aggregate_id||'-dup',ordinal,id,source_id,target_id,note,created_at,created_at_ms,raw_json,if_absent FROM kernel_provider_link_rows WHERE aggregate_id=? AND id=?")
        .bind(&aggregate).bind(&link).execute(w.db.write_pool()).await.unwrap();
    let mut conn = w.db.pool().acquire().await.unwrap();
    assert!(
        !super::read_surface::narrowing_supported_on(&mut conn)
            .await
            .unwrap(),
        "duplicate provider ids must disable narrowing"
    );
    drop(conn);
    // End to end: the production candidate queries yield their NULL row and
    // the session falls back to full staging, with identical output.
    for args in [
        json!({"steps":[{"step":"filter","ids":[a]},{"step":"traverse","target":"links"}],"order":"name_asc","limit":500}),
        json!({"steps":[{"step":"filter","home_id":KERNEL_ROOT_ID}],"order":"updated_desc","limit":500}),
    ] {
        for credential in ["acct:admin", "acct:viewer"] {
            assert_narrowed_identical(&w, credential, &args).await;
            let (narrowed, full) = staged_narrowed_and_full(&w, credential, &args).await;
            assert_eq!(
                narrowed, full,
                "{credential} {args}: duplicate providers must stage in full"
            );
        }
    }
}

/// Logical-home placement cases P1 must cover (Native 3a3eabb, owed by
/// review): a mapped physical root whose exposed home record differs from the
/// root id; a logical (v2) move that beats the home map, and a physical-only
/// v1 rehome that does not; a legacy
/// policy-anchor `original_home`; a mapped root the viewer cannot see; and
/// homes with no record (the physical root id itself, an unknown id).
/// Containment plus byte-identity for admin and viewer.
#[tokio::test]
async fn extended_query_record_logical_home_placements_lie_within_anchor_candidates() {
    use std::collections::BTreeSet;
    let w = world().await;
    let note = |title: &str| json!({"title": title}).as_object().unwrap().clone();
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::hq::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let shared = kernel::create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.viewer, "view")]),
        &w.admin,
    )
    .await
    .unwrap();
    let destination = kernel::create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.viewer, "view")]),
        &w.admin,
    )
    .await
    .unwrap();
    let import = |root: String, source: String, entries: Vec<(String, &'static str)>| {
        let (db, host, admin) = (w.db.clone(), host.clone(), w.admin.clone());
        async move {
            let entries: Vec<(&str, &str)> =
                entries.iter().map(|(s, c)| (s.as_str(), *c)).collect();
            kernel::hq::import_home_as(
                &db,
                &host,
                &root,
                &source,
                KERNEL_ROOT_ID,
                &admin,
                Some(&entries),
            )
            .await
            .unwrap();
        }
    };
    // Mapped root: physical root != the record that names it.
    let mapped = kernel::hq::v1_import_home_id(&w.second);
    import(
        mapped.clone(),
        w.second.clone(),
        vec![(w.viewer.clone(), "view")],
    )
    .await;
    // Mapped root the viewer cannot see.
    let mapped_hidden = kernel::hq::v1_import_home_id(&w.hidden);
    import(mapped_hidden.clone(), w.hidden.clone(), vec![]).await;
    let mut made = Vec::new();
    for title in [
        "Mapped a",
        "Mapped b",
        "Mapped then rehomed",
        "Mapped then moved",
        "Hidden mapped",
        "Legacy anchored",
    ] {
        made.push(
            kernel::create_as(
                &w.db,
                &w.admin,
                "fixture.mcp",
                "note",
                &note(title),
                &shared,
            )
            .await
            .unwrap(),
        );
    }
    let [mapped_a, mapped_b, rehomed, moved, hidden_mapped, legacy] = made.try_into().unwrap();
    // A physical-only v1 rehome (no logical_home_id) does NOT beat the map;
    // a logical v2 move does. Both are then placed physically under the map.
    kernel::rehome_record_as(&w.db, &w.admin, &rehomed, &destination)
        .await
        .unwrap();
    let mut tx = crate::db::begin_write(w.db.write_pool()).await.unwrap();
    let mut acts = crate::act::ActAllocation::new();
    kernel::move_record_with_comments_in(&w.db, &mut tx, &mut acts, &w.admin, &moved, &destination)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    // Legacy policy anchor: own boundary root, logical parent from provenance.
    let own_boundary = kernel::hq::v1_import_home_id(&legacy);
    import(
        own_boundary.clone(),
        legacy.clone(),
        vec![(w.viewer.clone(), "view")],
    )
    .await;
    kernel::hq::import_event_as(
        &w.db,
        &host,
        &legacy,
        &kernel::hq::LegacyEvent {
            source: None,
            id: uuid::Uuid::new_v4().to_string(),
            event_type: "v1.snapshot_provenance".into(),
            payload: json!({"policy_anchor":legacy,"original_home":w.second}),
            created_at: "2026-10-16T00:00:00Z".into(),
            actor: None,
            run_key: None,
        },
    )
    .await
    .unwrap();
    for (id, home) in [
        (&mapped_a, &mapped),
        (&mapped_b, &mapped),
        (&rehomed, &mapped),
        (&moved, &mapped),
        (&hidden_mapped, &mapped_hidden),
        (&legacy, &own_boundary),
    ] {
        sqlx::query("UPDATE kernel_records SET home_id=? WHERE id=?")
            .bind(home)
            .bind(id)
            .execute(w.db.write_pool())
            .await
            .unwrap();
    }
    let _ = call_as(&w, "acct:admin", "manage_links", json!({"action":"add","source_id":mapped_a,"target_id":rehomed,"relationship":"relates_to"})).await;
    let _ = call_as(
        &w,
        "acct:admin",
        "manage_links",
        json!({"action":"add","source_id":legacy,"target_id":mapped_b,"relationship":"relates_to"}),
    )
    .await;

    let mut pipelines = Vec::new();
    for home in [
        w.second.as_str(),
        mapped.as_str(),
        shared.as_str(),
        destination.as_str(),
        w.hidden.as_str(),
        mapped_hidden.as_str(),
        legacy.as_str(),
        own_boundary.as_str(),
        KERNEL_ROOT_ID,
        "native:root",
        "no-such-home",
    ] {
        for extra in [
            json!({}),
            json!({"kinds":["note"]}),
            json!({"include_archived":true}),
        ] {
            let mut filter = json!({"step":"filter","home_id":home});
            filter
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            pipelines.push(json!({"steps":[filter]}));
        }
    }
    for ids in [
        vec![mapped_a.clone()],
        vec![legacy.clone()],
        vec![hidden_mapped.clone(), rehomed.clone()],
        vec![moved.clone()],
    ] {
        for direction in [None, Some("in"), Some("out")] {
            let mut traverse = json!({"step":"traverse","target":"links"});
            if let Some(d) = direction {
                traverse["direction"] = json!(d);
            }
            pipelines.push(json!({"steps":[{"step":"filter","ids":ids},traverse]}));
        }
    }
    let mut checked = 0;
    let mut placed = BTreeSet::new();
    for steps in pipelines {
        for order in ["updated_desc", "last_activity_desc", "name_asc"] {
            let mut args = steps.clone();
            args["order"] = json!(order);
            args["limit"] = json!(500);
            let plan = super::read_surface::recognize_args(&args)
                .unwrap_or_else(|| panic!("not recognised: {args}"));
            let mut conn = w.db.pool().acquire().await.unwrap();
            let candidates = super::read_surface::direct_candidates_on(&mut conn, &plan)
                .await
                .unwrap();
            drop(conn);
            for credential in ["acct:admin", "acct:viewer"] {
                assert_narrowed_identical(&w, credential, &args).await;
                let Ok(result) = call_as(&w, credential, "query_record", args.clone()).await else {
                    continue;
                };
                for r in result["records"].as_array().unwrap() {
                    let id = r["id"].as_str().unwrap().to_owned();
                    assert!(
                        candidates.contains(&id),
                        "{credential} {args}: {id} outside candidates"
                    );
                    if let Some(home) = steps["steps"][0]["home_id"].as_str() {
                        placed.insert((id, home.to_owned()));
                    }
                }
                checked += 1;
            }
        }
    }
    assert!(checked > 150, "oracle exercised {checked} calls");
    // Narrowing really engaged on both shapes (not a silent full fallback).
    for args in [
        json!({"steps":[{"step":"filter","home_id":w.second}],"order":"updated_desc","limit":500}),
        json!({"steps":[{"step":"filter","ids":[mapped_a]},{"step":"traverse","target":"links"}],"order":"name_asc","limit":500}),
    ] {
        let (narrowed, full) = staged_narrowed_and_full(&w, "acct:admin", &args).await;
        assert!(
            narrowed < full,
            "{args}: narrowed staged {narrowed}, full {full}"
        );
    }
    // The fixture must actually exercise each placement rule.
    let names = [
        ("second", &w.second),
        ("mapped", &mapped),
        ("shared", &shared),
        ("destination", &destination),
        ("hidden", &w.hidden),
        ("mapped_hidden", &mapped_hidden),
        ("legacy", &legacy),
        ("own_boundary", &own_boundary),
    ];
    let name = |h: &String| {
        names
            .iter()
            .find(|(_, v)| *v == h)
            .map(|(n, _)| n.to_string())
            .unwrap_or(h.clone())
    };
    for (label, id, home) in [
        ("mapped_a", &mapped_a, &w.second),
        ("mapped_b", &mapped_b, &w.second),
        ("rehomed (v1, physical only)", &rehomed, &w.second),
        ("moved (v2, logical)", &moved, &destination),
        ("legacy", &legacy, &w.second),
    ] {
        let seen: Vec<_> = placed
            .iter()
            .filter(|(r, _)| r == id)
            .map(|(_, h)| name(h))
            .collect();
        assert!(
            placed.contains(&(id.clone(), home.clone())),
            "{label} not placed under {}; seen under {seen:?}",
            name(home)
        );
    }
    assert!(
        !placed.contains(&(moved.clone(), w.second.clone())),
        "a logical move must beat the home map"
    );
}

/// Staged-record counts (narrowed default, forced full) for one call, so a
/// test can prove narrowing really engaged or really fell back; byte parity
/// alone would also pass if narrowing were silently disabled.
async fn staged_narrowed_and_full(w: &World, credential: &str, args: &Value) -> (u64, u64) {
    let (_, narrowed) =
        super::sql::measured(call_as(w, credential, "query_record", args.clone())).await;
    let (_, full) = super::read_surface::FORCE_FULL_STAGING
        .scope(
            true,
            super::sql::measured(call_as(w, credential, "query_record", args.clone())),
        )
        .await;
    (narrowed.staged_records, full.staged_records)
}

/// Byte-identity oracle (Native 3a3eabb): for each limit/offset variant, the
/// narrowed (default) run returns exactly the same JSON, or exactly
/// the same error text, as forced full staging.
async fn assert_narrowed_identical(w: &World, credential: &str, args: &Value) {
    for (limit, offset) in [(500, 0), (2, 1), (1, 0), (3, 1000)] {
        let mut variant = args.clone();
        variant["limit"] = json!(limit);
        variant["offset"] = json!(offset);
        let full = super::read_surface::FORCE_FULL_STAGING
            .scope(
                true,
                call_as(w, credential, "query_record", variant.clone()),
            )
            .await;
        let narrowed = call_as(w, credential, "query_record", variant.clone()).await;
        match (&full, &narrowed) {
            (Ok(a), Ok(b)) => assert_eq!(
                serde_json::to_string(a).unwrap(),
                serde_json::to_string(b).unwrap(),
                "{credential} {variant}: narrowed output differs"
            ),
            (Err(a), Err(b)) => assert_eq!(
                a.to_string(),
                b.to_string(),
                "{credential} {variant}: refusal differs"
            ),
            _ => panic!("{credential} {variant}: full {full:?} vs narrowed {narrowed:?}"),
        }
    }
}

/// Opt-in HQ-shaped byte-identity oracle (Native 3a3eabb). Fixtures cannot
/// reproduce real logical-home mapping (on HQ, ~all records sit under roots
/// whose exposed home record differs). Run against a scratch COPY:
///   NATIVE_HQ_COPY=/path/to/hq.db NATIVE_HQ_ACCOUNT=<auth binding> \
///   RUST_MIN_STACK=67108864 cargo test --lib --features v2-kernel-probe \
///   extended_query_record_narrowed_matches_full_on_hq_copy -- --ignored --nocapture
/// Prints shapes, counts and timings only; mismatches report ids, never bodies.
#[tokio::test]
#[ignore]
async fn extended_query_record_narrowed_matches_full_on_hq_copy() {
    let source = std::env::var("NATIVE_HQ_COPY").expect("NATIVE_HQ_COPY");
    let account = std::env::var("NATIVE_HQ_ACCOUNT").expect("NATIVE_HQ_ACCOUNT");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hq.db");
    std::fs::copy(&source, &path).unwrap();
    let db = kernel::open_v2_database(path.to_str().unwrap())
        .await
        .unwrap();
    let registry = registry();
    let caller = || Caller::authenticated(&account);
    // P1 anchors: root and the most populated exposed homes (mapped records).
    let mut homes: Vec<String> = sqlx::query_scalar(
        "SELECT h FROM (SELECT coalesce((SELECT json_extract(e.payload,'$.source_record_id') FROM content_events e WHERE e.record_id=r.home_id AND e.type IN ('kernel.import_home.v1','kernel.home_created.v1') AND json_extract(e.payload,'$.source_record_id') IS NOT NULL LIMIT 1), r.home_id) AS h, count(*) n FROM kernel_records r GROUP BY 1 ORDER BY n DESC LIMIT 25)",
    ).fetch_all(db.pool()).await.unwrap();
    homes.insert(0, "native:root".into());
    // P2 anchors: the most-linked records plus the caller's person.
    let mut anchors: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM (SELECT target_id id, count(*) n FROM kernel_generic_links WHERE active=1 GROUP BY 1 UNION ALL SELECT target_id, count(*) FROM kernel_links GROUP BY 1) GROUP BY id ORDER BY sum(n) DESC LIMIT 15",
    ).fetch_all(db.pool()).await.unwrap();
    if let Ok(person) = std::env::var("NATIVE_HQ_PERSON") {
        anchors.insert(0, person);
    }
    let mut cases = Vec::new();
    for home in &homes {
        for archived in [false, true] {
            cases.push(json!({"steps":[{"step":"filter","home_id":home,"include_archived":archived}],"order":"last_activity_desc"}));
        }
    }
    for id in &anchors {
        cases.push(json!({"steps":[{"step":"filter","ids":[id]},{"step":"traverse","target":"links","relationship":"assigned_to","direction":"in"}],"order":"last_activity_desc"}));
        cases.push(json!({"steps":[{"step":"filter","ids":[id]},{"step":"traverse","target":"links","direction":"both"}],"order":"updated_desc"}));
        cases.push(json!({"steps":[{"step":"filter","ids":[id]},{"step":"traverse","target":"links","direction":"in"},{"step":"filter","types":["Entity"],"kinds":["person"]}],"order":"name_asc"}));
    }
    let (mut compared, mut nonempty, mut refusals) = (0usize, 0usize, 0usize);
    let (mut full_time, mut narrow_time) = (std::time::Duration::ZERO, std::time::Duration::ZERO);
    for case in &cases {
        for (limit, offset) in [(60, 0), (24, 0), (5, 3), (10, 100000)] {
            let mut args = case.clone();
            args["limit"] = json!(limit);
            args["offset"] = json!(offset);
            let started = std::time::Instant::now();
            let full = super::read_surface::FORCE_FULL_STAGING
                .scope(
                    true,
                    registry.call_engine(
                        EngineHandle::KernelV2(db.clone()),
                        caller(),
                        "query_record",
                        args.clone(),
                    ),
                )
                .await;
            full_time += started.elapsed();
            let started = std::time::Instant::now();
            let narrowed = registry
                .call_engine(
                    EngineHandle::KernelV2(db.clone()),
                    caller(),
                    "query_record",
                    args.clone(),
                )
                .await;
            narrow_time += started.elapsed();
            match (&full, &narrowed) {
                (Ok(a), Ok(b)) => {
                    if a != b {
                        let ids = |v: &Value| {
                            v["records"]
                                .as_array()
                                .map(|r| {
                                    r.iter()
                                        .map(|x| x["id"].as_str().unwrap_or("").to_owned())
                                        .collect::<Vec<_>>()
                                })
                                .unwrap_or_default()
                        };
                        panic!(
                            "HQ mismatch {args}: total {} vs {}, ids {:?} vs {:?}",
                            a["total"],
                            b["total"],
                            ids(a),
                            ids(b)
                        );
                    }
                    if a["records"].as_array().is_some_and(|r| !r.is_empty()) {
                        nonempty += 1;
                    }
                }
                (Err(a), Err(b)) => {
                    assert_eq!(a.to_string(), b.to_string(), "HQ refusal differs {args}");
                    refusals += 1;
                }
                _ => panic!(
                    "HQ outcome differs {args}: full ok={} narrowed ok={}",
                    full.is_ok(),
                    narrowed.is_ok()
                ),
            }
            compared += 1;
        }
    }
    eprintln!("HQ oracle: {compared} comparisons ({nonempty} non-empty, {refusals} identical refusals); full {full_time:?} vs narrowed {narrow_time:?}");
    assert!(nonempty > 0);
    db.close().await;
}

// ---------------------------------------------------------------------------
// Visible-set access fence, slice 1 (Native b171a9d). The fence is inert; these
// tests pin the classification to the gate's real inputs and prove each seam.

/// The 56 event types present on an HQ production copy (10 Nov 2026). Every
/// one must be explicitly classified, never left to the unknown fallback.
const HQ_EVENT_TYPES: [&str; 56] = [
    "kernel.legacy_recorded.v1",
    "kernel.import_receipt.v1",
    "kernel.v1_state_imported.v1",
    "kernel.record_created.v1",
    "kernel.import_state.v1",
    "kernel.generic_link_imported.v1",
    "kernel.provider_outcome.v1",
    "kernel.import_home_policy.v1",
    "kernel.import_member_policy.v1",
    "kernel.mcp_write_receipt_recorded.v1",
    "kernel.attachment_bound.v1",
    "kernel.body_set.v1",
    "kernel.facet_observed.v1",
    "kernel.app_state_imported.v1",
    "kernel.import_home.v1",
    "kernel.generic_link_added.v1",
    "kernel.record_revised.v2",
    "kernel.principal_created.v1",
    "kernel.run_opened.v1",
    "kernel.artifact_closure_activated.v1",
    "kernel.run_intent_set.v1",
    "kernel.artifact_excluded.v1",
    "kernel.import_record_created.v1",
    "kernel.record_rehomed.v2",
    "kernel.comment_anchor_imported.v1",
    "kernel.run_closed.v1",
    "kernel.metadata_set.v1",
    "kernel.home_created.v1",
    "kernel.saved_tab_changed.v1",
    "kernel.message_command_committed.v1",
    "kernel.message_destination_imported.v1",
    "kernel.message_created.v1",
    "kernel.archive_changed.v1",
    "kernel.import_removed.v1",
    "kernel.instruction_binding_imported.v1",
    "kernel.canvas_activated.v1",
    "kernel.package_adopted.v1",
    "kernel.definition_adopted.v1",
    "kernel.membership_bundle_defined.v1",
    "kernel.import_source_head.v1",
    "kernel.webhook_accepted.v1",
    "kernel.message_state.v1",
    "kernel.app_source_published.v1",
    "kernel.app_install_recorded.v1",
    "kernel.app_install_adopted.v1",
    "kernel.workspace_metadata_imported.v1",
    "kernel.webhook_configured.v1",
    "kernel.root_created.v1",
    "kernel.root_admin_bootstrapped.v1",
    "kernel.import_state_delta.v1",
    "kernel.import_members_roster.v1",
    "kernel.import_hosted_accounts.v1",
    "kernel.hosted_membership.v1",
    "kernel.host_transform_created.v1",
    "kernel.host_import_created.v1",
    "kernel.app_installs_activated.v1",
];

#[test]
fn access_fence_classifies_every_hq_event_type_and_refines_by_payload() {
    use crate::kernel::access_fence::{class_of, classify, AccessClass::*};
    for event_type in HQ_EVENT_TYPES {
        assert!(
            class_of(event_type).is_some(),
            "unclassified HQ event type {event_type}"
        );
    }
    let none = json!({});
    // Ordinary content never takes the database-wide fallback.
    for (event_type, expected) in [
        ("kernel.body_set.v1", NoEffect),
        ("kernel.facet_observed.v1", NoEffect),
        ("kernel.metadata_set.v1", NoEffect),
        ("kernel.archive_changed.v1", NoEffect),
        ("kernel.record_created.v1", PatchClosure),
        ("kernel.record_revised.v2", PatchClosure),
        ("kernel.record_deleted.v1", PatchClosure),
        ("kernel.message_created.v1", PatchClosure),
        ("kernel.home_created.v1", PatchHome),
        ("kernel.hosted_membership.v1", RecomputePrincipals),
        ("kernel.home_policy_replaced.v1", RecomputeAll),
        ("kernel.root_admin_bootstrapped.v1", RecomputeAll),
        ("kernel.not_a_real_type.v9", RecomputeAll),
        ("policy.replaced", RecomputeAll),
    ] {
        assert_eq!(classify(event_type, &none, false), expected, "{event_type}");
    }
    let link = |relationship: &str| json!({"relationship": relationship});
    assert_eq!(
        classify("kernel.generic_link_added.v1", &link("part_of"), false),
        PatchClosure
    );
    assert_eq!(
        classify("kernel.generic_link_added.v1", &link("relates_to"), false),
        NoEffect
    );
    assert_eq!(
        classify("kernel.generic_link_removed.v1", &none, false),
        PatchClosure
    );
    assert_eq!(
        classify(
            "kernel.import_removed.v1",
            &json!({"kind": "record"}),
            false
        ),
        PatchClosure
    );
    assert_eq!(
        classify("kernel.import_removed.v1", &json!({"kind": "link"}), false),
        NoEffect
    );
    let rehome = json!({"new_home_id": "h", "logical_home_id": "h", "parent_update": null});
    assert_eq!(
        classify("kernel.record_rehomed.v2", &rehome, false),
        PatchClosure
    );
    assert_eq!(
        classify("kernel.record_rehomed.v2", &rehome, true),
        RecomputeAll
    );
    let reparent = json!({"new_home_id": "h", "logical_home_id": "h", "parent_update": {"home_id": "h", "parent_id": "p"}});
    assert_eq!(
        classify("kernel.record_rehomed.v2", &reparent, false),
        RecomputeAll
    );
}

/// Main-database (table, column) pairs SQLite reports reading while it
/// prepares and runs the real gate: `sql_record_visible` (tombstones, derived
/// bearer, message guard) and `visible_home_anchors_as` (scopes).
async fn gate_input_columns(w: &World) -> std::collections::BTreeSet<(String, String)> {
    use std::collections::BTreeSet;
    use std::ffi::{c_char, c_int, c_void, CStr};
    use std::sync::Mutex;
    unsafe extern "C" fn authorize(
        context: *mut c_void,
        action: c_int,
        table: *const c_char,
        column: *const c_char,
        database: *const c_char,
        _trigger: *const c_char,
    ) -> c_int {
        if action == libsqlite3_sys::SQLITE_READ && !table.is_null() && !database.is_null() {
            // SAFETY: SQLite passes NUL-terminated strings valid for this call;
            // context is the Mutex owned by the enclosing test frame.
            let (table, database) = unsafe { (CStr::from_ptr(table), CStr::from_ptr(database)) };
            if database.to_bytes() == b"main" {
                let column = if column.is_null() {
                    String::new()
                } else {
                    unsafe { CStr::from_ptr(column) }
                        .to_string_lossy()
                        .into_owned()
                };
                let reads = unsafe { &*context.cast::<Mutex<BTreeSet<(String, String)>>>() };
                reads
                    .lock()
                    .unwrap()
                    .insert((table.to_string_lossy().into_owned(), column));
            }
        }
        libsqlite3_sys::SQLITE_OK
    }
    let reads: Mutex<BTreeSet<(String, String)>> = Mutex::default();
    let mut conn = w.db.write_pool().acquire().await.unwrap();
    sqlx::query("CREATE TEMP TABLE _v2_scopes(home_id TEXT, valid INTEGER, policy_view INTEGER, home_view INTEGER)")
        .execute(&mut *conn)
        .await
        .unwrap();
    let raw: *mut libsqlite3_sys::sqlite3 = conn
        .lock_handle()
        .await
        .unwrap()
        .as_raw_handle()
        .as_ptr()
        .cast();
    // SAFETY: raw is this connection's handle; the context outlives the
    // authorizer, which is removed below before `reads` is dropped.
    unsafe {
        libsqlite3_sys::sqlite3_set_authorizer(
            raw,
            Some(authorize),
            std::ptr::from_ref(&reads).cast_mut().cast(),
        );
    }
    let gate = kernel::sql_record_visible(
        "r",
        "?1",
        "SELECT home_id AS id,policy_view AS view FROM temp._v2_scopes WHERE valid",
        true,
    );
    sqlx::query(&format!(
        "SELECT r.id FROM main.kernel_records r WHERE {gate}"
    ))
    .persistent(false)
    .bind(&w.viewer)
    .fetch_all(&mut *conn)
    .await
    .unwrap();
    kernel::visible_home_anchors_as(&mut conn, &w.viewer)
        .await
        .unwrap();
    unsafe {
        libsqlite3_sys::sqlite3_set_authorizer(raw, None, std::ptr::null_mut());
    }
    sqlx::query("DROP TABLE temp._v2_scopes")
        .execute(&mut *conn)
        .await
        .unwrap();
    reads.into_inner().unwrap()
}

/// A digest of every gate-input column, over all rows except one filter the
/// gate SQL itself applies: only `part_of` rows of `kernel_generic_links`.
/// (`kernel_record_fields` is digested in full, which is conservative.)
/// `content_events` reads are not digested here; admission-read event types
/// are covered by classification (never NoEffect), not by this digest.
/// Unchanged digest means the gate's answer cannot have changed.
async fn gate_input_digest(
    w: &World,
    columns: &std::collections::BTreeSet<(String, String)>,
) -> String {
    let gate = kernel::sql_record_visible("r", "?1", "SELECT 1 AS id,1 AS view", true);
    let mut by_table: std::collections::BTreeMap<&str, Vec<&str>> = Default::default();
    for (table, column) in columns {
        if table != "content_events" && !column.is_empty() {
            by_table.entry(table).or_default().push(column);
        }
    }
    let mut digest = String::new();
    for (table, columns) in by_table {
        let filter = match table {
            "kernel_generic_links" => {
                assert!(
                    gate.contains("'part_of'"),
                    "gate no longer filters part_of links"
                );
                " WHERE relationship='part_of'"
            }
            _ => "",
        };
        let list = columns.join(",");
        let rows: Vec<String> = sqlx::query_scalar(&format!(
            "SELECT json_array({list}) FROM main.{table}{filter} ORDER BY 1"
        ))
        .fetch_all(w.db.pool())
        .await
        .unwrap();
        digest.push_str(&format!("{table}:{}\n", rows.join(";")));
    }
    digest
}

/// The check slice 2 relies on: a transaction whose appended events are all
/// NoEffect must leave every gate input unchanged.
fn no_effect_check(
    classes: &[crate::kernel::access_fence::AccessClass],
    digest_changed: bool,
) -> std::result::Result<(), String> {
    use crate::kernel::access_fence::AccessClass::NoEffect;
    if !classes.is_empty() && classes.iter().all(|c| *c == NoEffect) && digest_changed {
        return Err(format!(
            "events classified NoEffect {classes:?} changed a gate input"
        ));
    }
    Ok(())
}

async fn appended_classes(
    w: &World,
    after: i64,
) -> Vec<(String, crate::kernel::access_fence::AccessClass)> {
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT e.type,e.payload,e.record_id FROM content_events e WHERE e.seq>? ORDER BY e.seq",
    )
    .bind(after)
    .fetch_all(w.db.pool())
    .await
    .unwrap();
    let mut out = Vec::new();
    for (event_type, payload, record) in rows {
        let is_home: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_roots WHERE root_id=?)")
                .bind(&record)
                .fetch_one(w.db.pool())
                .await
                .unwrap();
        let payload: Value = serde_json::from_str(&payload).unwrap_or(Value::Null);
        out.push((
            event_type.clone(),
            crate::kernel::access_fence::classify(&event_type, &payload, is_home),
        ));
    }
    out
}

async fn head_seq(w: &World) -> i64 {
    sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM content_events")
        .fetch_one(w.db.pool())
        .await
        .unwrap()
}

#[tokio::test]
async fn access_fence_no_effect_writes_leave_every_gate_input_unchanged() {
    use crate::kernel::access_fence::AccessClass;
    let w = world().await;
    let columns = gate_input_columns(&w).await;
    let tables: std::collections::BTreeSet<&str> =
        columns.iter().map(|(t, _)| t.as_str()).collect();
    for expected in [
        "kernel_records",
        "kernel_import_tombstones",
        "kernel_generic_links",
        "kernel_messages",
        "kernel_roots",
        "kernel_policies",
        "kernel_policy_entries",
    ] {
        assert!(
            tables.contains(expected),
            "gate no longer reads {expected}: {tables:?}"
        );
    }
    let note = |title: &str| json!({"title": title}).as_object().unwrap().clone();
    let record = kernel::create_as(
        &w.db,
        &w.admin,
        "fixture.mcp",
        "note",
        &note("Fence subject"),
        KERNEL_ROOT_ID,
    )
    .await
    .unwrap();
    let other = kernel::create_as(
        &w.db,
        &w.admin,
        "fixture.mcp",
        "note",
        &note("Fence other"),
        KERNEL_ROOT_ID,
    )
    .await
    .unwrap();
    let get = |id: String| {
        let w = &w;
        async move {
            call_as(w, "acct:admin", "get_record", json!({"id": id}))
                .await
                .unwrap()
        }
    };
    let mut ordinary = Vec::new();
    // Body, facet, metadata, archive and a non-part_of link: ordinary content.
    let version = get(record.clone()).await["version"].clone();
    ordinary.push(json!({"tool":"update_record","args":{"id":record,"body_set":"v2","if_unmodified_since":null,"reason":"fence body","expected_version":version}}));
    for step in [
        json!({"tool":"update_record","args":{"id":record,"facets":{"fence_score":3},"reason":"fence facet"}}),
        json!({"tool":"update_record","args":{"id":record,"maturity":"draft","reason":"fence metadata"}}),
        json!({"tool":"manage_links","args":{"action":"add","source_id":record,"target_id":other,"relationship":"relates_to","reason":"fence link"}}),
    ] {
        ordinary.push(step);
    }
    let mut exercised = 0;
    for step in ordinary {
        let before_seq = head_seq(&w).await;
        let before = gate_input_digest(&w, &columns).await;
        let mut args = step["args"].clone();
        if let Some(map) = args.as_object_mut() {
            map.retain(|_, v| !v.is_null());
        }
        if call_as(
            &w,
            "acct:admin",
            step["tool"].as_str().unwrap(),
            args.clone(),
        )
        .await
        .is_err()
        {
            continue;
        }
        let classes = appended_classes(&w, before_seq).await;
        let after = gate_input_digest(&w, &columns).await;
        let only: Vec<AccessClass> = classes.iter().map(|(_, c)| *c).collect();
        assert!(
            only.iter().all(|c| *c == AccessClass::NoEffect),
            "{args}: ordinary step appended non-NoEffect events {classes:?}"
        );
        no_effect_check(&only, before != after).unwrap_or_else(|e| panic!("{args}: {e}"));
        exercised += 1;
    }
    assert!(exercised >= 3, "only {exercised} ordinary steps exercised");

    // The check bites: a create changes a gate input, so tagging it NoEffect fails.
    let before_seq = head_seq(&w).await;
    let before = gate_input_digest(&w, &columns).await;
    kernel::create_as(
        &w.db,
        &w.admin,
        "fixture.mcp",
        "note",
        &note("Fence created"),
        KERNEL_ROOT_ID,
    )
    .await
    .unwrap();
    let after = gate_input_digest(&w, &columns).await;
    assert_ne!(before, after, "a create must change a gate input");
    let classes = appended_classes(&w, before_seq).await;
    assert!(
        classes.iter().any(|(_, c)| *c == AccessClass::PatchClosure),
        "{classes:?}"
    );
    assert!(
        no_effect_check(&[AccessClass::NoEffect], before != after).is_err(),
        "mis-tagged create must fail the check"
    );
    assert!(no_effect_check(
        &classes.iter().map(|(_, c)| *c).collect::<Vec<_>>(),
        before != after
    )
    .is_ok());
}

async fn viewer_sees(w: &World, id: &str) -> usize {
    call_as(
        w,
        "acct:viewer",
        "query_record",
        json!({"steps":[{"step":"filter","ids":[id]}]}),
    )
    .await
    .map(|out| out["records"].as_array().map(|r| r.len()).unwrap_or(0))
    .unwrap_or(0)
}

#[tokio::test]
async fn access_fence_policy_grant_removal_is_a_recompute_event() {
    use crate::kernel::access_fence::AccessClass;
    let w = world().await;
    let home = kernel::create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.viewer, "view")]),
        &w.admin,
    )
    .await
    .unwrap();
    let note = json!({"title": "Granted"}).as_object().unwrap().clone();
    let record = kernel::create_as(&w.db, &w.admin, "fixture.mcp", "note", &note, &home)
        .await
        .unwrap();
    assert_eq!(
        viewer_sees(&w, &record).await,
        1,
        "viewer must see the record before removal"
    );
    let before_seq = head_seq(&w).await;
    kernel::replace_home_policy(&w.db, &w.admin, &home, &[(&w.admin, "manage")])
        .await
        .unwrap();
    let classes = appended_classes(&w, before_seq).await;
    assert!(
        classes.iter().any(|(_, c)| *c == AccessClass::RecomputeAll),
        "a grant removal must append a RecomputeAll event visible to the cursor: {classes:?}"
    );
    assert_eq!(
        viewer_sees(&w, &record).await,
        0,
        "grant removal must hide the record"
    );
}

#[tokio::test]
async fn access_fence_generation_and_incarnation_seams() {
    let w = world().await;
    // Undeclared handles carry no fence: the ownership invariant is not
    // established, so a future cache must bypass them.
    assert_eq!(w.db.access_fence(), None);
    w.db.declare_exclusive_access_owner();
    let start =
        w.db.access_fence()
            .expect("a declared read-write owner carries a fence");
    // Clones share the fence; inert reads never move it.
    assert_eq!(w.db.clone().access_fence(), Some(start));
    call_as(
        &w,
        "acct:admin",
        "query_record",
        json!({"steps":[{"step":"filter","types":["Document"]}]}),
    )
    .await
    .unwrap();
    assert_eq!(w.db.access_fence(), Some(start));
    // A full projection rebuild appends no content event, so it bumps.
    kernel::replay_all_projections(&w.db).await.unwrap();
    let rebuilt = w.db.access_fence().unwrap();
    assert_eq!(rebuilt.incarnation, start.incarnation);
    assert!(
        rebuilt.generation > start.generation,
        "rebuild must bump the generation"
    );
    // Preparation may rebuild too.
    kernel::prepare_v2_database(&w.db).await.unwrap();
    let prepared = w.db.access_fence().unwrap();
    assert!(prepared.generation > rebuilt.generation);
    let path = w.db.path().to_owned();
    // Why ownership must be declared: a rebuild through a SECOND read-write
    // handle on the same file cannot move this handle's generation, and the
    // event cursor does not advance either. Only an exclusive owner may fence.
    let second = kernel::open_v2_database(path.to_str().unwrap())
        .await
        .unwrap();
    assert_eq!(
        second.access_fence(),
        None,
        "a second handle is not the declared owner"
    );
    let head_before: i64 = sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM content_events")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    kernel::replay_all_projections(&second).await.unwrap();
    let head_after: i64 = sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM content_events")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    assert_eq!(head_before, head_after, "rebuild appends no content event");
    assert_eq!(
        w.db.access_fence(),
        Some(prepared),
        "another handle's rebuild is invisible to this fence"
    );
    // A fresh open is a new incarnation once declared.
    second.declare_exclusive_access_owner();
    assert_ne!(
        second.access_fence().unwrap().incarnation,
        start.incarnation
    );
    second.close().await;
    // A standby read-only handle never carries a fence, even if declared: a
    // refresh, swap or FULL replay through another handle cannot bump it.
    let standby = crate::db::open_kernel_v2_standby_read_only(path.to_str().unwrap())
        .await
        .unwrap();
    assert_eq!(
        standby.open_mode(),
        crate::db::DatabaseOpenMode::StandbyReadOnly
    );
    standby.declare_exclusive_access_owner();
    assert_eq!(standby.access_fence(), None);
    standby.close().await;
}

async fn epoch_table_present(db: &Db) -> bool {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='kernel_access_epoch')")
        .fetch_one(db.pool())
        .await
        .unwrap()
}

async fn epoch_of(db: &Db) -> Option<i64> {
    let mut conn = db.pool().acquire().await.unwrap();
    crate::kernel::access_fence::read_epoch_on(&mut conn)
        .await
        .unwrap()
}

/// The persisted access epoch is created lazily by serving start only; the
/// writers bump it inside their own transaction only when it exists; and it
/// never changes the certified schema, projection inventory or digest.
#[tokio::test]
async fn access_epoch_is_lazy_bumped_in_writer_transactions_and_uncertified() {
    use crate::kernel::access_fence::{bump_epoch_on, ensure_epoch_on};
    let w = world().await;
    // Creation, preparation and a rebuild never create the table.
    assert!(
        !epoch_table_present(&w.db).await,
        "creation must not create the epoch"
    );
    kernel::prepare_v2_database(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert!(
        !epoch_table_present(&w.db).await,
        "prepare/rebuild must not create the epoch"
    );
    assert_eq!(
        epoch_of(&w.db).await,
        None,
        "no table means no epoch (do not cache)"
    );
    // A bump with the table absent is a no-op.
    let mut tx = crate::db::begin_write(w.db.write_pool()).await.unwrap();
    bump_epoch_on(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    assert!(!epoch_table_present(&w.db).await);

    // Certified coordinates and digest before serving creates the epoch.
    let mut conn = w.db.pool().acquire().await.unwrap();
    let before = crate::standby::kernel_v2::coordinates(&mut conn)
        .await
        .unwrap();
    let dump_before = crate::kernel::projection_dump::dump_on(&mut conn)
        .await
        .unwrap();
    drop(conn);

    // Serving start creates and seeds it (writer transaction).
    let mut tx = crate::db::begin_write(w.db.write_pool()).await.unwrap();
    ensure_epoch_on(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    let seeded = epoch_of(&w.db).await.expect("seeded");
    assert!(seeded > 0);
    let mut tx = crate::db::begin_write(w.db.write_pool()).await.unwrap();
    ensure_epoch_on(&mut tx).await.unwrap(); // idempotent: never reseeds
    tx.commit().await.unwrap();
    assert_eq!(epoch_of(&w.db).await, Some(seeded));

    let mut conn = w.db.pool().acquire().await.unwrap();
    let after = crate::standby::kernel_v2::coordinates(&mut conn)
        .await
        .unwrap();
    let dump_after = crate::kernel::projection_dump::dump_on(&mut conn)
        .await
        .unwrap();
    drop(conn);
    assert_eq!(
        after.schema_sha256, before.schema_sha256,
        "epoch must not enter the certified schema"
    );
    assert_eq!(
        after.projection_tables, before.projection_tables,
        "epoch must not be a certified projection"
    );
    assert!(!after
        .projection_tables
        .iter()
        .any(|t| t == "kernel_access_epoch"));
    assert_eq!(
        format!("{dump_after:?}"),
        format!("{dump_before:?}"),
        "epoch must not enter the projection digest"
    );

    // A rebuild bumps it by exactly one, inside its own transaction.
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(epoch_of(&w.db).await, Some(seeded + 1));

    // A rebuild through a SECOND handle on the same file is visible to the
    // first handle's next snapshot: the epoch lives in the file.
    let path = w.db.path().to_owned();
    let second = kernel::open_v2_database(path.to_str().unwrap())
        .await
        .unwrap();
    kernel::replay_all_projections(&second).await.unwrap();
    second.close().await;
    assert_eq!(
        epoch_of(&w.db).await,
        Some(seeded + 2),
        "another handle's rebuild must be visible"
    );

    // An older snapshot keeps its epoch while a rebuild commits elsewhere.
    let mut reader = w.db.pool().acquire().await.unwrap();
    sqlx::query("BEGIN").execute(&mut *reader).await.unwrap();
    let pinned = crate::kernel::access_fence::read_epoch_on(&mut reader)
        .await
        .unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(
        crate::kernel::access_fence::read_epoch_on(&mut reader)
            .await
            .unwrap(),
        pinned,
        "a snapshot sees one epoch"
    );
    sqlx::query("ROLLBACK").execute(&mut *reader).await.unwrap();
    drop(reader);
    assert_eq!(epoch_of(&w.db).await, Some(seeded + 3));

    // The v1 policy log does not exist on a v2 database, so it cannot write
    // gate inputs here; `project_kernel_policy_rows` still bumps the epoch
    // (defence in depth) should a v2 file ever carry it.
    let policy_log: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='policy_events')",
    )
    .fetch_one(w.db.pool())
    .await
    .unwrap();
    assert!(!policy_log, "v2 databases carry no policy log");
}

// ---------------------------------------------------------------------------
// Visible-set cache candidate (Native b171a9d S2-S4; disabled unless a test
// registers it). Equivalence is against the same call with no cache.

use super::sql::visible_cache as vcache;

async fn ids_as(w: &World, credential: &str) -> Value {
    let out = call_as(
        w,
        credential,
        "query_sql",
        json!({"sql":"SELECT id,home_id,type,name FROM records ORDER BY id"}),
    )
    .await
    .unwrap();
    out["rows"].clone()
}

/// The same query with this handle's cache temporarily unregistered.
async fn fresh_as(w: &World, credential: &str) -> Value {
    vcache::set_bypass_for_test(&w.db, true);
    let out = ids_as(w, credential).await;
    vcache::set_bypass_for_test(&w.db, false);
    out
}

async fn cached_world() -> World {
    world().await
}

async fn settle_refresh(w: &World, before: vcache::Stats) -> vcache::Stats {
    for _ in 0..200 {
        let now = vcache::stats(&w.db);
        if now.refreshes > before.refreshes {
            return now;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    vcache::stats(&w.db)
}

#[tokio::test]
async fn visible_cache_equivalent_isolated_and_reuses_ordinary_writes() {
    let w = cached_world().await;
    let admin_fresh = fresh_as(&w, "acct:admin").await;
    let viewer_fresh = fresh_as(&w, "acct:viewer").await;
    assert_ne!(
        admin_fresh, viewer_fresh,
        "fixture must give the two principals different visibility"
    );
    vcache::enable_for_test(&w.db).await;
    // Miss then hit, for each principal, interleaved: never another's set.
    for _ in 0..2 {
        assert_eq!(ids_as(&w, "acct:viewer").await, viewer_fresh);
        assert_eq!(ids_as(&w, "acct:admin").await, admin_fresh);
    }
    let after_warm = vcache::stats(&w.db);
    assert!(after_warm.hits >= 2, "warm reads must hit: {after_warm:?}");

    // Ordinary writes between cached reads: reuse or patch, never recompute,
    // never a meta event, always equal to fresh staging.
    let meta_before: i64 = sqlx::query_scalar("SELECT count(*) FROM meta_events")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let note = |title: &str| json!({"title": title}).as_object().unwrap().clone();
    let created = kernel::create_as(
        &w.db,
        &w.admin,
        "fixture.mcp",
        "note",
        &note("Cache create"),
        KERNEL_ROOT_ID,
    )
    .await
    .unwrap();
    let steps: Vec<Value> = vec![
        json!({"tool":"update_record","args":{"id":created,"facets":{"cache_score":1},"reason":"cache facet"}}),
        json!({"tool":"manage_links","args":{"action":"add","source_id":created,"target_id":w.first,"relationship":"relates_to","reason":"cache link"}}),
        json!({"tool":"manage_links","args":{"action":"add","source_id":created,"target_id":w.first,"relationship":"part_of","reason":"cache part_of"}}),
    ];
    let check = |label: String| {
        let w = &w;
        async move {
            let stale_before = vcache::stats(&w.db).stale_serves;
            for credential in ["acct:viewer", "acct:admin"] {
                let cached = ids_as(w, credential).await;
                let fresh = fresh_as(w, credential).await;
                assert_eq!(
                    cached, fresh,
                    "{label}: {credential} cached differs from fresh"
                );
            }
            assert_eq!(
                vcache::stats(&w.db).stale_serves,
                stale_before,
                "{label}: ordinary write must not take the stale path"
            );
        }
    };
    check("create".into()).await;
    for step in steps {
        let _ = call_as(
            &w,
            "acct:admin",
            step["tool"].as_str().unwrap(),
            step["args"].clone(),
        )
        .await;
        check(format!("{}", step["args"])).await;
    }
    let meta_after: i64 = sqlx::query_scalar("SELECT count(*) FROM meta_events")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    assert_eq!(
        meta_before, meta_after,
        "ordinary writes must not append meta events"
    );
    let s = vcache::stats(&w.db);
    assert!(
        s.patches >= 1,
        "a create/part_of must patch in place: {s:?}"
    );
    vcache::disable_for_test(&w.db);
}

#[tokio::test]
async fn visible_cache_revocation_serves_last_known_then_converges_and_survives_refresh_failure() {
    let w = cached_world().await;
    let home = kernel::create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.viewer, "view")]),
        &w.admin,
    )
    .await
    .unwrap();
    let note = json!({"title": "Revocable"}).as_object().unwrap().clone();
    let record = kernel::create_as(&w.db, &w.admin, "fixture.mcp", "note", &note, &home)
        .await
        .unwrap();
    let has = |rows: &Value| {
        rows.as_array()
            .unwrap()
            .iter()
            .any(|r| r["id"] == json!(record))
    };
    vcache::enable_for_test(&w.db).await;
    assert!(has(&ids_as(&w, "acct:viewer").await));
    assert!(has(&ids_as(&w, "acct:viewer").await), "warm");

    // Prolonged refresh failure: the known result is retained, never refused.
    vcache::set_fail_refresh(&w.db, true);
    kernel::replace_home_policy(&w.db, &w.admin, &home, &[(&w.admin, "manage")])
        .await
        .unwrap();
    for _ in 0..5 {
        assert!(
            has(&ids_as(&w, "acct:viewer").await),
            "last-known set retained while refresh fails"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let s = vcache::stats(&w.db);
    assert!(s.stale_serves >= 5, "{s:?}");
    // Failure never degrades into another principal's set.
    let admin_fresh = fresh_as(&w, "acct:admin").await;
    vcache::enable_for_test(&w.db).await;
    assert_eq!(
        ids_as(&w, "acct:admin").await,
        admin_fresh,
        "a different principal never inherits the stale set"
    );

    // Recovery: the next stale read retries; once it succeeds the revoked
    // record is absent and the result equals fresh staging.
    vcache::set_fail_refresh(&w.db, false);
    let before = vcache::stats(&w.db);
    let _ = ids_as(&w, "acct:viewer").await;
    settle_refresh(&w, before).await;
    let converged = ids_as(&w, "acct:viewer").await;
    assert!(
        !has(&converged),
        "after a successful refresh the revoked record is absent"
    );
    let viewer_fresh = fresh_as(&w, "acct:viewer").await;
    assert_eq!(converged, viewer_fresh);
}

#[tokio::test]
async fn visible_cache_rebuild_epoch_older_snapshot_and_concurrent_readers() {
    let w = cached_world().await;
    vcache::enable_for_test(&w.db).await;
    let viewer_fresh = fresh_as(&w, "acct:viewer").await;
    vcache::enable_for_test(&w.db).await;
    assert_eq!(ids_as(&w, "acct:viewer").await, viewer_fresh);

    // An older snapshot never uses an entry published ahead of it.
    let mut pinned = w.db.governed_pool().acquire().await.unwrap();
    sqlx::query("BEGIN").execute(&mut *pinned).await.unwrap();
    let _: i64 = sqlx::query_scalar("SELECT count(*) FROM main.content_events")
        .fetch_one(&mut *pinned)
        .await
        .unwrap();
    let note = json!({"title": "After pin"}).as_object().unwrap().clone();
    kernel::create_as(
        &w.db,
        &w.admin,
        "fixture.mcp",
        "note",
        &note,
        KERNEL_ROOT_ID,
    )
    .await
    .unwrap();
    let _ = ids_as(&w, "acct:viewer").await; // publishes an entry stamped after the pin
    assert_eq!(
        vcache::plan_kind_for_test(&mut pinned, &w.db, &w.viewer).await,
        "miss_no_publish"
    );
    sqlx::query("ROLLBACK").execute(&mut *pinned).await.unwrap();
    drop(pinned);

    // A rebuild changes the persisted epoch: last-known is served, a refresh
    // converges, and the result equals fresh staging.
    let before = vcache::stats(&w.db);
    kernel::replay_all_projections(&w.db).await.unwrap();
    let _ = ids_as(&w, "acct:viewer").await;
    assert!(
        vcache::stats(&w.db).stale_serves > before.stale_serves,
        "epoch change takes the refresh path"
    );
    settle_refresh(&w, before).await;
    let viewer_fresh = fresh_as(&w, "acct:viewer").await;
    vcache::enable_for_test(&w.db).await;
    assert_eq!(ids_as(&w, "acct:viewer").await, viewer_fresh);

    // Concurrent readers after an access change: all succeed, and once the
    // single-flight refresh lands the result is fresh.
    kernel::replay_all_projections(&w.db).await.unwrap();
    let before = vcache::stats(&w.db);
    let reads = (0..8).map(|_| ids_as(&w, "acct:viewer"));
    let results = futures::future::join_all(reads).await;
    assert_eq!(results.len(), 8);
    let after = settle_refresh(&w, before).await;
    assert!(
        after.refreshes - before.refreshes <= 2,
        "refresh is single-flight: {before:?} -> {after:?}"
    );
    let viewer_fresh = fresh_as(&w, "acct:viewer").await;
    vcache::enable_for_test(&w.db).await;
    assert_eq!(ids_as(&w, "acct:viewer").await, viewer_fresh);
    vcache::disable_for_test(&w.db);
}

/// Periodic re-verify (Native 788c170): a change the delta cannot see (a
/// projection edited with no event, standing in for any classification gap)
/// converges after one re-verify, and no read waits for it.
#[tokio::test]
async fn visible_cache_reverify_converges_on_an_unclassified_change_without_blocking() {
    let w = world().await;
    let private = kernel::create_home(&w.db, KERNEL_ROOT_ID, Some(&[]), &w.admin)
        .await
        .unwrap();
    let note = json!({"title": "Will move silently"})
        .as_object()
        .unwrap()
        .clone();
    let record = kernel::create_as(&w.db, &w.admin, "fixture.mcp", "note", &note, &private)
        .await
        .unwrap();
    let has = |rows: &Value| {
        rows.as_array()
            .unwrap()
            .iter()
            .any(|r| r["id"] == json!(record))
    };
    vcache::enable_for_test(&w.db).await;
    assert!(!has(&ids_as(&w, "acct:viewer").await));
    assert!(!has(&ids_as(&w, "acct:viewer").await), "warm hit");
    // Silent projection change into the viewer's view: no event, so the cursor
    // sees nothing and the cached set lags (a stand-in for any classification gap).
    let shared = kernel::create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.viewer, "view")]),
        &w.admin,
    )
    .await
    .unwrap();
    sqlx::query("UPDATE kernel_records SET home_id=? WHERE id=?")
        .bind(&shared)
        .bind(&record)
        .execute(w.db.write_pool())
        .await
        .unwrap();
    assert!(
        has(&fresh_as(&w, "acct:viewer").await),
        "fresh staging sees the move"
    );
    assert!(
        !has(&ids_as(&w, "acct:viewer").await),
        "before re-verify the cached set lags"
    );
    let before = vcache::stats(&w.db);
    vcache::age_entries_for_test(&w.db);
    let started = std::time::Instant::now();
    let _ = ids_as(&w, "acct:viewer").await; // due: served at once, re-verify starts
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "the due read is not blocked"
    );
    let after = settle_refresh(&w, before).await;
    assert!(
        after.reverifies > before.reverifies,
        "{before:?} -> {after:?}"
    );
    let converged = ids_as(&w, "acct:viewer").await;
    assert!(
        has(&converged),
        "after one re-verify the change is reflected"
    );
    assert_eq!(converged, fresh_as(&w, "acct:viewer").await);
}

/// The approved periodic background re-verify (788c170): a real timer, owned
/// by the serving registration, converges a change the delta cannot see with
/// no read at all, even while the entry is continuously patched by ordinary
/// writes (age is measured from the last full verification only).
#[tokio::test]
async fn visible_cache_timer_reverifies_busy_entries_and_converges_without_reads() {
    let w = world().await;
    let private = kernel::create_home(&w.db, KERNEL_ROOT_ID, Some(&[]), &w.admin)
        .await
        .unwrap();
    let shared = kernel::create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.viewer, "view")]),
        &w.admin,
    )
    .await
    .unwrap();
    let note = |t: &str| json!({"title": t}).as_object().unwrap().clone();
    let record = kernel::create_as(
        &w.db,
        &w.admin,
        "fixture.mcp",
        "note",
        &note("Silent"),
        &private,
    )
    .await
    .unwrap();
    let has = |rows: &Value| {
        rows.as_array()
            .unwrap()
            .iter()
            .any(|r| r["id"] == json!(record))
    };
    let cache =
        vcache::enable_with_interval_for_test(&w.db, std::time::Duration::from_millis(120)).await;
    assert!(!has(&ids_as(&w, "acct:viewer").await));

    // Busy entry: ordinary creates patch it continuously; the timer still
    // performs full refreshes because patches never reset the verified age.
    // Keep patching until two refreshes land rather than for a fixed count:
    // a loaded runner can starve the 120 ms timer for a while, and that says
    // nothing about whether patches reset the age. The deadline bounds a
    // genuine regression (patches suppressing refreshes) to a clear failure.
    let start = cache.stats.lock().unwrap().timer_refreshes;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let mut i = 0;
    while cache.stats.lock().unwrap().timer_refreshes - start < 2
        && std::time::Instant::now() < deadline
    {
        kernel::create_as(
            &w.db,
            &w.admin,
            "fixture.mcp",
            "note",
            &note(&format!("Busy {i}")),
            &shared,
        )
        .await
        .unwrap();
        i += 1;
        let _ = ids_as(&w, "acct:viewer").await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let busy = cache.stats.lock().unwrap().timer_refreshes - start;
    assert!(
        busy >= 2,
        "a continuously patched entry is still fully re-verified each period: {busy}"
    );

    // Planted gap: a silent projection move into the viewer's view. No reads
    // at all until well after a timer period; the next read is converged.
    sqlx::query("UPDATE kernel_records SET home_id=? WHERE id=?")
        .bind(&shared)
        .bind(&record)
        .execute(w.db.write_pool())
        .await
        .unwrap();
    let before = *cache.stats.lock().unwrap();
    // Wait for the timer itself (bounded) rather than a fixed 500 ms, which a
    // loaded runner can overrun; still no reads in the meantime.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    while cache.stats.lock().unwrap().timer_refreshes <= before.timer_refreshes
        && std::time::Instant::now() < deadline
    {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let after = *cache.stats.lock().unwrap();
    assert!(
        after.timer_refreshes > before.timer_refreshes,
        "{before:?} -> {after:?}"
    );
    assert_eq!(after.reverifies, before.reverifies, "no read triggered it");
    let converged = ids_as(&w, "acct:viewer").await;
    assert!(
        has(&converged),
        "the timer converged the planted gap with no read"
    );
    assert_eq!(converged, fresh_as(&w, "acct:viewer").await);
    vcache::disable_for_test(&w.db);
}

/// The aggregate stats line measures real reads: a miss stages through the
/// gate, a repeat read stages from cached ids, an ordinary write is read as a
/// delta and patched, and a failed background refresh is counted. Lines are
/// emitted only by the timer, at most once per window, carry no caller data,
/// and stop when serving stops.
#[tokio::test]
async fn visible_cache_stats_line_counts_real_reads_and_stops_with_serving() {
    let w = world().await;
    let home = kernel::create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.viewer, "view")]),
        &w.admin,
    )
    .await
    .unwrap();
    // A 10 s re-verify interval: the timer ticks every ~5 s (and so emits),
    // but never refreshes an entry during the counted reads below, even on
    // a slow debug run.
    let cache =
        vcache::enable_with_interval_for_test(&w.db, std::time::Duration::from_secs(10)).await;
    let window = std::time::Duration::from_millis(400);
    vcache::set_stats_window_for_test(&w.db, window);
    let started = std::time::Instant::now();
    let fresh = fresh_as(&w, "acct:viewer").await;
    let base = *cache.stats.lock().unwrap();

    assert_eq!(ids_as(&w, "acct:viewer").await, fresh);
    let first = *cache.stats.lock().unwrap();
    assert_eq!(first.plans - base.plans, 1);
    assert_eq!(first.misses - base.misses, 1, "{first:?}");
    assert_eq!(
        first.gate_stages - base.gate_stages,
        1,
        "a miss stages through the gate"
    );
    assert_eq!(first.cached_stages, base.cached_stages);

    assert_eq!(ids_as(&w, "acct:viewer").await, fresh);
    let second = *cache.stats.lock().unwrap();
    assert_eq!(second.hits - first.hits, 1, "{second:?}");
    assert_eq!(
        second.cached_stages - first.cached_stages,
        1,
        "a hit stages cached ids"
    );
    assert_eq!(second.gate_stages, first.gate_stages);

    let note = json!({"title": "Stats create"})
        .as_object()
        .unwrap()
        .clone();
    kernel::create_as(
        &w.db,
        &w.admin,
        "fixture.mcp",
        "note",
        &note,
        KERNEL_ROOT_ID,
    )
    .await
    .unwrap();
    assert_eq!(
        ids_as(&w, "acct:viewer").await,
        fresh_as(&w, "acct:viewer").await
    );
    let third = *cache.stats.lock().unwrap();
    assert!(
        third.delta_rows > second.delta_rows,
        "the write is read as a delta: {third:?}"
    );
    assert_eq!(
        third.patches - second.patches,
        1,
        "an ordinary create patches: {third:?}"
    );
    assert!(third.closure_ids > second.closure_ids);
    assert!(third.plan_us >= second.plan_us && third.cached_stage_us >= second.cached_stage_us);

    // An access change serves the last-known set and starts a background
    // refresh; a failing refresh is counted, and the entry is retained.
    vcache::set_fail_refresh(&w.db, true);
    kernel::replace_home_policy(&w.db, &w.admin, &home, &[(&w.admin, "manage")])
        .await
        .unwrap();
    let _ = ids_as(&w, "acct:viewer").await;
    assert!(cache.stats.lock().unwrap().stale_serves > third.stale_serves);
    for _ in 0..200 {
        if cache.stats.lock().unwrap().refresh_failures > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(cache.stats.lock().unwrap().refresh_failures > 0);
    vcache::set_fail_refresh(&w.db, false);
    let mut counted = false;
    for _ in 0..300 {
        if cache
            .emitted
            .lock()
            .unwrap()
            .iter()
            .any(|l| !l.contains(" refresh_failures=0 "))
        {
            counted = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(counted, "a timer line reports the failed refresh");

    // Once-per-window is pinned by the unit test; here every line comes from
    // a timer tick (~interval/2 apart), so lines never outnumber ticks.
    let lines = cache.emitted.lock().unwrap().clone();
    assert!(
        !lines.is_empty(),
        "the timer emits once a window has elapsed"
    );
    let elapsed = started.elapsed();
    assert!(
        lines.len() as u128 <= elapsed.as_millis() / 4_750 + 1,
        "at most one line per timer tick: {} lines in {elapsed:?}",
        lines.len()
    );
    let sum = |field: &str| -> u64 {
        lines
            .iter()
            .map(|l| {
                l.split(' ')
                    .find_map(|kv| kv.strip_prefix(&format!("{field}=")))
                    .unwrap_or_else(|| panic!("{field} missing in {l}"))
                    .parse::<u64>()
                    .unwrap()
            })
            .sum()
    };
    assert!(sum("plans") >= 3, "{lines:?}");
    assert!(sum("misses") >= 1 && sum("patches") >= 1 && sum("hits") >= 1);
    assert!(sum("gate_stages") >= 1 && sum("cached_stages") >= 2);
    assert!(sum("refresh_failures") >= 1, "{lines:?}");
    let path = w.db.path().to_string_lossy().into_owned();
    for line in &lines {
        assert!(line.starts_with("visible-cache window_s="), "{line}");
        for secret in [
            w.viewer.as_str(),
            w.admin.as_str(),
            "acct:viewer",
            path.as_str(),
        ] {
            assert!(
                !secret.is_empty() && !line.contains(secret),
                "caller data in {line}"
            );
        }
        assert!(
            !line.contains("SELECT") && !line.contains("Stats create"),
            "{line}"
        );
    }

    // Lifecycle-bound: no line after serving stops, whatever the activity.
    // Reads bypass a disabled cache, so record activity directly on the
    // retained cache: a timer still running would report it at its next tick.
    vcache::disable_for_test(&w.db);
    for _ in 0..100 {
        if cache.stats.lock().unwrap().timer_exits == 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(
        cache.stats.lock().unwrap().timer_exits,
        1,
        "the timer exits when serving stops"
    );
    let stopped = cache.emitted.lock().unwrap().len();
    cache.stats.lock().unwrap().plans += 1;
    // Longer than a timer tick (~5 s) and the stats window: a live timer
    // would have emitted a line for this activity.
    tokio::time::sleep(std::time::Duration::from_secs(6)).await;
    assert_eq!(
        cache.emitted.lock().unwrap().len(),
        stopped,
        "emission ends with the timer"
    );
}

/// Lifecycle: stop_serving cancels the timer, drops the registration's Db
/// clone (no self-owned cycle), and no refresh runs afterwards.
#[tokio::test]
async fn visible_cache_stop_serving_cancels_timer_and_releases_the_handle() {
    let w = world().await;
    let cache =
        vcache::enable_with_interval_for_test(&w.db, std::time::Duration::from_millis(40)).await;
    let _ = ids_as(&w, "acct:viewer").await;
    let weak = vcache::registration_weak_for_test(&w.db);
    assert!(weak.upgrade().is_some());
    vcache::disable_for_test(&w.db); // stop_serving
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    assert!(
        weak.upgrade().is_none(),
        "registration (and its Db clone) is released: no cycle"
    );
    let stopped = *cache.stats.lock().unwrap();
    assert_eq!(stopped.timer_exits, 1, "the timer task exited: {stopped:?}");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(
        cache.stats.lock().unwrap().timer_refreshes,
        stopped.timer_refreshes,
        "no refresh after stop"
    );
    // Closing a handle that is still registered stops it too.
    vcache::enable_with_interval_for_test(&w.db, std::time::Duration::from_millis(40)).await;
    let weak = vcache::registration_weak_for_test(&w.db);
    w.db.close().await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        weak.upgrade().is_none(),
        "close stops a still-registered cache"
    );
}

/// Cancellation safety: aborting a refresh between BEGIN and its gate query
/// must never return a pooled connection with an open transaction.
#[tokio::test]
async fn visible_cache_aborted_refresh_leaves_no_open_transaction_in_the_pool() {
    let w = world().await;
    vcache::enable_for_test(&w.db).await;
    let entered = vcache::park_refresh_for_test(&w.db);
    let (db, viewer) = (w.db.clone(), w.viewer.clone());
    let task = tokio::spawn(async move { vcache::refresh_for_test(&db, &viewer).await });
    entered.notified().await;
    task.abort();
    let _ = task.await;
    let pool = w.db.governed_pool();
    let max = pool.options().get_max_connections() as usize;
    let mut held = Vec::new();
    for _ in 0..max {
        let mut conn = pool.acquire().await.unwrap();
        sqlx::query("BEGIN")
            .execute(&mut *conn)
            .await
            .expect("no transaction left open by an aborted refresh");
        sqlx::query("ROLLBACK").execute(&mut *conn).await.unwrap();
        held.push(conn);
    }
    drop(held);
    vcache::disable_for_test(&w.db);
}

/// Serving start must never write (a serving open is often triggered by a
/// read); the persisted epoch is created by the first ordinary write.
#[tokio::test]
async fn visible_cache_serving_start_never_writes_and_first_write_creates_the_epoch() {
    let w = world().await;
    let path = w.db.path().to_owned();
    let wal = format!("{}-wal", path.display());
    let main_before = std::fs::read(&path).unwrap();
    let wal_before = std::fs::read(&wal).ok();
    vcache::start_serving_for_test(&w.db).await;
    let _ = ids_as(&w, "acct:viewer").await; // a read through the cache
    assert_eq!(
        std::fs::read(&path).unwrap(),
        main_before,
        "serving start + read changed the main file"
    );
    assert_eq!(
        std::fs::read(&wal).ok(),
        wal_before,
        "serving start + read changed the WAL"
    );
    assert!(
        !epoch_table_present(&w.db).await,
        "no epoch before any write"
    );
    let note = json!({"title": "First write"}).as_object().unwrap().clone();
    kernel::create_as(
        &w.db,
        &w.admin,
        "fixture.mcp",
        "note",
        &note,
        KERNEL_ROOT_ID,
    )
    .await
    .unwrap();
    assert!(
        epoch_table_present(&w.db).await,
        "the first ordinary write creates the epoch"
    );
    let _ = ids_as(&w, "acct:viewer").await; // a miss publishes now that the epoch exists
    let before = vcache::stats(&w.db);
    let _ = ids_as(&w, "acct:viewer").await;
    assert!(
        vcache::stats(&w.db).hits > before.hits,
        "the cache engages once the epoch exists"
    );
    vcache::disable_for_test(&w.db);
}

#[cfg(feature = "v2-kernel-probe")]
async fn page_snapshot_section(world: &World, token: &str, section: &str) -> Vec<Value> {
    let mut rows = Vec::new();
    let mut after = Value::Null;
    loop {
        let page = call(
            world,
            "get_workspace_snapshot",
            json!({
                "action": "page",
                "snapshot_token": token,
                "section": section,
                "limit": 100,
                "after_id": after
            }),
        )
        .await
        .unwrap();
        rows.extend(page["rows"].as_array().cloned().unwrap());
        if !page["has_more"].as_bool().unwrap() {
            break;
        }
        after = page["after_id"].clone();
    }
    rows
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn snapshot_currency_matches_sql_with_hidden_successor_source() {
    let w = world().await;
    kernel::add_generic_link_as(&w.db, &w.admin, &w.hidden, &w.first, "supersedes", None)
        .await
        .unwrap();
    let hidden_sql = call(
        &w,
        "query_sql",
        json!({
            "sql": "SELECT is_current, updated_at_ms, archived FROM records WHERE id=?1",
            "parameters": [{"type":"text","value": w.first}]
        }),
    )
    .await
    .unwrap();
    assert_eq!(hidden_sql["rows"][0]["is_current"], json!(1));
    let opened = call(&w, "get_workspace_snapshot", json!({"action":"open"}))
        .await
        .unwrap();
    let token = opened["snapshot_token"].as_str().unwrap();
    let records = page_snapshot_section(&w, token, "records").await;
    let row = records.iter().find(|row| row["id"] == w.first).unwrap();
    assert_eq!(row["is_current"], hidden_sql["rows"][0]["is_current"]);
    assert_eq!(row["updated_at_ms"], hidden_sql["rows"][0]["updated_at_ms"]);
    assert_eq!(row["archived"], hidden_sql["rows"][0]["archived"]);
    let links = page_snapshot_section(&w, token, "links").await;
    assert!(
        links.iter().all(|row| row["source_id"] != w.hidden),
        "a hidden successor source is not a visible link"
    );

    kernel::add_generic_link_as(&w.db, &w.admin, &w.second, &w.first, "supersedes", None)
        .await
        .unwrap();
    let visible_sql = call(
        &w,
        "query_sql",
        json!({
            "sql": "SELECT is_current, updated_at_ms, archived FROM records WHERE id=?1",
            "parameters": [{"type":"text","value": w.first}]
        }),
    )
    .await
    .unwrap();
    assert!(visible_sql["rows"][0]["is_current"].is_null());
    let opened = call(&w, "get_workspace_snapshot", json!({"action":"open"}))
        .await
        .unwrap();
    let token = opened["snapshot_token"].as_str().unwrap();
    let records = page_snapshot_section(&w, token, "records").await;
    let row = records.iter().find(|row| row["id"] == w.first).unwrap();
    assert_eq!(row["is_current"], visible_sql["rows"][0]["is_current"]);
    assert_eq!(
        row["updated_at_ms"],
        visible_sql["rows"][0]["updated_at_ms"]
    );
    assert_eq!(row["archived"], visible_sql["rows"][0]["archived"]);
    let links = page_snapshot_section(&w, token, "links").await;
    assert!(links.iter().any(|row| {
        row["source_id"] == w.second
            && row["target_id"] == w.first
            && row["relationship"] == "supersedes"
    }));
    assert!(links.iter().all(|row| row["source_id"] != w.hidden));

    let revision = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .expect("visible record exists")
        .revision;
    kernel::set_archived_as(&w.db, &w.admin, &w.first, true, revision)
        .await
        .unwrap();
    let archived_sql = call(
        &w,
        "query_sql",
        json!({
            "sql": "SELECT is_current, updated_at_ms, archived FROM records WHERE id=?1",
            "parameters": [{"type":"text","value": w.first}]
        }),
    )
    .await
    .unwrap();
    assert_eq!(archived_sql["rows"][0]["archived"], json!(1));
    let opened = call(&w, "get_workspace_snapshot", json!({"action":"open"}))
        .await
        .unwrap();
    let records =
        page_snapshot_section(&w, opened["snapshot_token"].as_str().unwrap(), "records").await;
    let row = records.iter().find(|row| row["id"] == w.first).unwrap();
    assert_eq!(row["archived"], archived_sql["rows"][0]["archived"]);
    assert_eq!(row["is_current"], archived_sql["rows"][0]["is_current"]);
    assert_eq!(
        row["updated_at_ms"],
        archived_sql["rows"][0]["updated_at_ms"]
    );
    w.db.close().await;
}

#[path = "demand_tests.rs"]
mod demand_tests;
#[path = "record_projection_tests.rs"]
mod record_projection_tests;
