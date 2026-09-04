use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
use native_ce::conformance::rebuild_and_diff;
use native_ce::events::{EventRow, LinkAddedPayload, LinkRemovedPayload};
use native_ce::mcp::{register_surface_tools, render, Caller, ToolRegistry};
use native_ce::projector::replay_with_blob_seeds;
use native_ce::query::events::log_prefix;
use native_ce::store::{add_link, append, remove_link, AppendSpec};
use native_ce::{create_database, Db};
use serde_json::{json, Value};
use sqlx::Row;

async fn db() -> Db {
    create_database(":memory:").await.unwrap()
}

async fn replay_db() -> Db {
    let db = native_ce::open_database(":memory:").await.unwrap();
    native_ce::apply_schema(&db).await.unwrap();
    db
}

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

async fn call(registry: &ToolRegistry, db: &Db, tool: &str, args: Value) -> Value {
    let args = canonical_citation_args(tool, args);
    registry
        .call(
            db.clone(),
            Caller::local(),
            tool,
            crate::common::with_test_reason(tool, args),
        )
        .await
        .unwrap()
}

/// Read the current write token the way a caller must: through `get_record`.
/// Whole-body replacement is guarded, so the rewrites below carry the digest
/// they actually read rather than asserting an unguarded overwrite.
async fn current_body_digest(registry: &ToolRegistry, db: &Db, id: &str) -> String {
    call(registry, db, "get_record", json!({ "ids": [id] })).await["records"][0]["body_digest"]
        .as_str()
        .expect("get_record exposes body_digest")
        .to_owned()
}

async fn call_err(registry: &ToolRegistry, db: &Db, tool: &str, args: Value) -> String {
    let args = canonical_citation_args(tool, args);
    registry
        .call(
            db.clone(),
            Caller::local(),
            tool,
            crate::common::with_test_reason(tool, args),
        )
        .await
        .unwrap_err()
        .to_string()
}

async fn call_as(
    registry: &ToolRegistry,
    db: &Db,
    caller: Caller,
    tool: &str,
    args: Value,
) -> native_ce::Result<Value> {
    registry
        .call(
            db.clone(),
            caller,
            tool,
            crate::common::with_test_reason(tool, canonical_citation_args(tool, args)),
        )
        .await
}

async fn historical_record(registry: &ToolRegistry, db: &Db, record_id: &str, seq: i64) -> Value {
    let out = call(
        registry,
        db,
        "get_record",
        json!({ "ids": [record_id], "as_of": { "content_seq": seq } }),
    )
    .await;
    json!({ "record": out["records"][0].clone() })
}

fn canonical_citation_args(tool: &str, mut args: Value) -> Value {
    if tool == "create_record"
        && args.get("type") == Some(&json!("Annotation"))
        && args.get("kind") == Some(&json!("citation"))
    {
        let object = args.as_object_mut().unwrap();
        if let Some(bearer) = object.remove("home_id") {
            object.insert(
                "links".into(),
                json!([{ "target_id": bearer, "relationship": "part_of" }]),
            );
        }
    }
    args
}

async fn create(registry: &ToolRegistry, db: &Db, mut args: Value) -> String {
    if args.get("type") == Some(&json!("Annotation"))
        && args.get("kind") == Some(&json!("citation"))
    {
        let object = args.as_object_mut().unwrap();
        if let Some(bearer) = object.remove("home_id") {
            object.insert(
                "links".into(),
                json!([{ "target_id": bearer, "relationship": "part_of" }]),
            );
        }
    }
    call(registry, db, "create_record", args).await["id"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn body_citation(
    registry: &ToolRegistry,
    db: &Db,
    bearer: &str,
    source: &str,
    exact: &str,
) -> String {
    create(
        registry,
        db,
        json!({
            "type": "Annotation",
            "kind": "citation",
            "name": "Source evidence",
            "home_id": bearer,
            "body": "Why this evidence matters",
            "target": {
                "target_record_id": source,
                "source_slot": "body",
                "purpose": "extracted_from",
                "selectors": [{ "type": "text_quote", "exact": exact }]
            }
        }),
    )
    .await
}

#[tokio::test]
async fn meeting_citation_keeps_anchored_evidence_and_reports_relocated_stale_and_conflict() {
    let db = db().await;
    let registry = registry();
    let source = create(
        &registry,
        &db,
        json!({ "type": "Document", "name": "Meeting", "body": "Intro. Richard ships Friday. End." }),
    )
    .await;
    let bearer = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "name": "Ship Friday" }),
    )
    .await;
    let citation = body_citation(&registry, &db, &bearer, &source, "Richard ships Friday.").await;

    let initial = call(
        &registry,
        &db,
        "resolve_citation",
        json!({ "citation_id": citation }),
    )
    .await;
    assert_eq!(initial["validation"]["status"], "current");
    assert_eq!(
        initial["anchored"]["excerpt"]["text"],
        "Richard ships Friday."
    );
    assert_eq!(initial["read_only"], true);
    let initial_text = render::render("resolve_citation", &initial).unwrap();
    for expected in [
        citation.as_str(),
        source.as_str(),
        initial["anchored"]["source_sha256"].as_str().unwrap(),
        initial["current"]["source_sha256"].as_str().unwrap(),
        "Richard ships Friday.",
        "\"status\":\"current\"",
        "Read only: true",
    ] {
        assert!(
            initial_text.contains(expected),
            "missing {expected}: {initial_text}"
        );
    }

    call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": source, "body": "New intro. Richard ships Friday. End.",
            "if_body_digest": current_body_digest(&registry, &db, &source).await
        }),
    )
    .await;
    let relocated = call(
        &registry,
        &db,
        "resolve_citation",
        json!({ "citation_id": citation }),
    )
    .await;
    assert_eq!(relocated["validation"]["status"], "relocated");
    assert_eq!(relocated["anchored"]["excerpt"]["start"], 7);
    assert_ne!(relocated["current"]["excerpt"]["start"], 7);
    let relocated_text = render::render("resolve_citation", &relocated).unwrap();
    let current_start = format!("\"start\":{}", relocated["current"]["excerpt"]["start"]);
    for expected in [
        relocated["anchored"]["source_sha256"].as_str().unwrap(),
        relocated["current"]["source_sha256"].as_str().unwrap(),
        relocated["validation"]["detail"].as_str().unwrap(),
        "relocated",
        current_start.as_str(),
    ] {
        assert!(
            relocated_text.contains(expected),
            "missing {expected}: {relocated_text}"
        );
    }

    call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": source, "body": "The action was removed.",
            "if_body_digest": current_body_digest(&registry, &db, &source).await
        }),
    )
    .await;
    let stale = call(
        &registry,
        &db,
        "resolve_citation",
        json!({ "citation_id": citation }),
    )
    .await;
    assert_eq!(stale["validation"]["status"], "stale");
    let stale_text = render::render("resolve_citation", &stale).unwrap();
    assert!(
        stale_text.contains(stale["validation"]["detail"].as_str().unwrap()),
        "{stale_text}"
    );
    assert!(
        stale_text.contains(stale["current"]["detail"].as_str().unwrap()),
        "{stale_text}"
    );
    assert!(stale_text.contains("Current source: {"), "{stale_text}");

    call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": source, "body": "Richard ships Friday. Then Richard ships Friday.",
            "if_body_digest": current_body_digest(&registry, &db, &source).await
        }),
    )
    .await;
    let conflict = call(
        &registry,
        &db,
        "resolve_citation",
        json!({ "citation_id": citation }),
    )
    .await;
    assert_eq!(conflict["validation"]["status"], "conflict");
    let conflict_text = render::render("resolve_citation", &conflict).unwrap();
    assert!(
        conflict_text.contains(conflict["validation"]["detail"].as_str().unwrap()),
        "{conflict_text}"
    );
    assert!(
        conflict_text.contains(conflict["current"]["detail"].as_str().unwrap()),
        "{conflict_text}"
    );
    assert!(
        conflict_text.contains("Current source: {"),
        "{conflict_text}"
    );
}

#[tokio::test]
async fn finance_blob_citation_round_trips_csv_fragment_and_retained_bytes() {
    let db = db().await;
    let registry = registry();
    let bearer = create(
        &registry,
        &db,
        json!({ "type": "Entity", "kind": "transaction", "name": "Coffee" }),
    )
    .await;
    let csv = "date,merchant,amount\n2026-08-01,Coffee,4.50\n";
    let attachment = call(
        &registry,
        &db,
        "attach_text",
        json!({ "record_id": bearer, "text": csv, "filename": "statement.csv", "mime": "text/csv" }),
    )
    .await["attachment_id"]
    .as_str()
    .unwrap()
    .to_string();
    // Both capture and later resolution must hash retained bytes themselves,
    // not trust the blob row's cached digest.
    sqlx::query(
        "UPDATE blobs SET sha256 = 'tampered-cache' WHERE id =
         (SELECT value FROM facet_values WHERE record_id = ? AND key = 'blob_ref')",
    )
    .bind(&attachment)
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    let selected = "2026-08-01,Coffee,4.50";
    let start = csv.find(selected).unwrap();
    let citation = create(
        &registry,
        &db,
        json!({
            "type": "Annotation", "kind": "citation", "name": "CSV row", "home_id": bearer,
            "target": {
                "target_record_id": attachment, "source_slot": "blob", "purpose": "imported_from",
                "selectors": [
                    { "type": "data_position", "start": start, "end": start + selected.len() },
                    { "type": "fragment", "conforms_to": "https://www.rfc-editor.org/rfc/rfc7111", "value": "row=2" }
                ]
            }
        }),
    )
    .await;
    let target_seq: i64 = sqlx::query_scalar(
        "SELECT MAX(seq) FROM content_events WHERE record_id = ? AND type = 'annotation.target.set'",
    )
    .bind(&citation)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let blob_id: String = sqlx::query_scalar(
        "SELECT value FROM facet_values WHERE record_id = ? AND key = 'blob_ref'",
    )
    .bind(&attachment)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let resolved = call(
        &registry,
        &db,
        "resolve_citation",
        json!({ "citation_id": citation }),
    )
    .await;
    assert_eq!(resolved["validation"]["status"], "current");
    assert_eq!(resolved["anchored"]["excerpt"]["text"], selected);
    assert_eq!(resolved["selectors"][1]["value"], "row=2");
    assert!(resolved["selectors"][0]["selected_sha256"]
        .as_str()
        .is_some_and(|digest| digest.len() == 64));

    assert_ne!(resolved["anchored"]["source_sha256"], "tampered-cache");
    assert_eq!(
        call(
            &registry,
            &db,
            "resolve_citation",
            json!({ "citation_id": citation })
        )
        .await["validation"]["status"],
        "current"
    );

    let rebuilt = rebuild_and_diff(&db).await.unwrap();
    assert!(rebuilt.equal, "{:?}", rebuilt.tables);
    let historical = historical_record(&registry, &db, &citation, target_seq).await;
    assert_eq!(
        historical["record"]["target"]["validation"]["status"],
        "current"
    );
    assert_eq!(
        historical["record"]["target"]["source_state"]["blob_id"],
        blob_id
    );

    // Reconstructing this later body anchor must seed the earlier blob target's
    // FK identity without hydrating/copying its attachment bytes.
    let body_source = create(
        &registry,
        &db,
        json!({ "type": "Document", "name": "Unrelated minutes", "body": "body evidence" }),
    )
    .await;
    let body = body_citation(&registry, &db, &bearer, &body_source, "body evidence").await;
    assert_eq!(
        call(
            &registry,
            &db,
            "resolve_citation",
            json!({ "citation_id": body })
        )
        .await["validation"]["status"],
        "current"
    );

    call(
        &registry,
        &db,
        "manage_attachments",
        json!({ "action": "detach", "attachment_id": attachment }),
    )
    .await;
    let detached = call(
        &registry,
        &db,
        "resolve_citation",
        json!({ "citation_id": citation }),
    )
    .await;
    assert_eq!(detached["anchored"]["available"], true);
    assert_eq!(detached["validation"]["status"], "stale");
    assert_eq!(detached["current"], Value::Null);
    assert!(detached["validation"]["detail"]
        .as_str()
        .unwrap()
        .contains("anchored evidence is verified"));

    call(
        &registry,
        &db,
        "manage_citations",
        json!({ "action": "remove", "citation_id": citation, "reason": "Withdraw missing attachment evidence" }),
    )
    .await;
    // Once the target is deliberately removed the Annotation may move to an
    // honest open kind without violating a target invariant. `comment` is a
    // governed family with its own body/lifecycle contract, so it is no longer
    // an interchangeable stand-in for generic annotation content.
    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": citation, "kind": "withdrawn-citation", "reason": "Convert withdrawn evidence to ordinary annotation content" }),
    )
    .await;
    sqlx::query("DELETE FROM blobs WHERE id = ?")
        .bind(&blob_id)
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    let historical_missing = historical_record(&registry, &db, &citation, target_seq).await;
    assert_eq!(
        historical_missing["record"]["target"]["validation"]["status"],
        "unavailable"
    );
    let rebuilt_without_direct_blob = rebuild_and_diff(&db).await.unwrap();
    assert!(
        rebuilt_without_direct_blob.equal,
        "{:?}",
        rebuilt_without_direct_blob.tables
    );
}

#[tokio::test]
async fn rfc7111_row_and_cell_select_raw_csv_with_quotes_and_embedded_newlines() {
    let db = db().await;
    let registry = registry();
    let bearer = create(
        &registry,
        &db,
        json!({ "type": "Entity", "name": "Ledger" }),
    )
    .await;
    let csv = "id,note,amount\r\n1,\"line one\r\nline two\",10\r\n2,\"Revenue, net\",20\r\n3,\"He said \"\"go\"\"\",30\r\n";
    let attachment = call(
        &registry,
        &db,
        "attach_text",
        json!({ "record_id": bearer, "text": csv, "filename": "ledger.csv", "mime": "text/csv" }),
    )
    .await["attachment_id"]
        .as_str()
        .unwrap()
        .to_string();

    for (name, selected, fragment) in [
        ("quoted row", "2,\"Revenue, net\",20", "row=3"),
        ("multiline cell", "\"line one\r\nline two\"", "cell=2,2"),
        ("escaped quote cell", "\"He said \"\"go\"\"\"", "cell=4,2"),
    ] {
        let start = csv.find(selected).unwrap();
        let citation = create(
            &registry,
            &db,
            json!({
                "type": "Annotation", "kind": "citation", "name": name, "home_id": bearer,
                "target": {
                    "target_record_id": attachment, "source_slot": "blob",
                    "selectors": [
                        { "type": "data_position", "start": start, "end": start + selected.len() },
                        { "type": "fragment", "conforms_to": "https://www.rfc-editor.org/rfc/rfc7111", "value": fragment }
                    ]
                }
            }),
        )
        .await;
        let resolved = call(
            &registry,
            &db,
            "resolve_citation",
            json!({ "citation_id": citation }),
        )
        .await;
        assert_eq!(resolved["validation"]["status"], "current");
        assert_eq!(resolved["anchored"]["excerpt"]["text"], selected);
    }
}

#[tokio::test]
async fn rfc7111_disagreement_malformed_forms_and_unknown_conformance_fail_atomically() {
    let db = db().await;
    let registry = registry();
    let bearer = create(
        &registry,
        &db,
        json!({ "type": "Entity", "name": "Ledger" }),
    )
    .await;
    let csv = "id,value\n1,alpha\n2,beta\n";
    let attachment = call(
        &registry,
        &db,
        "attach_text",
        json!({ "record_id": bearer, "text": csv, "filename": "ledger.csv" }),
    )
    .await["attachment_id"]
        .as_str()
        .unwrap()
        .to_string();
    let selected = "2,beta";
    let start = csv.find(selected).unwrap();
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();

    for (conforms_to, fragment, expected) in [
        (
            "https://www.rfc-editor.org/rfc/rfc7111",
            "row=2",
            "disagree",
        ),
        (
            "https://www.rfc-editor.org/rfc/rfc7111",
            "row=2-3",
            "one row coordinate",
        ),
        (
            "https://www.rfc-editor.org/rfc/rfc7111",
            "cell=2",
            "positive base-10 integer",
        ),
        ("https://example.test/fragments", "row=3", "unsupported"),
    ] {
        let error = call_err(
            &registry,
            &db,
            "create_record",
            json!({
                "type": "Annotation", "kind": "citation", "home_id": bearer,
                "target": {
                    "target_record_id": attachment, "source_slot": "blob",
                    "selectors": [
                        { "type": "data_position", "start": start, "end": start + selected.len() },
                        { "type": "fragment", "conforms_to": conforms_to, "value": fragment }
                    ]
                }
            }),
        )
        .await;
        assert!(error.contains(expected), "{fragment}: {error}");
    }
    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(after, before);
}

#[tokio::test]
async fn citation_reads_are_first_class_hidden_and_independently_paged() {
    let db = db().await;
    let registry = registry();
    let source = create(
        &registry,
        &db,
        json!({ "type": "Document", "name": "Source", "body": "one two three" }),
    )
    .await;
    let bearer = create(
        &registry,
        &db,
        json!({ "type": "Resolution", "kind": "decision", "name": "Resolution" }),
    )
    .await;
    let first = body_citation(&registry, &db, &bearer, &source, "one").await;
    let second = body_citation(&registry, &db, &bearer, &source, "three").await;
    assert_ne!(first, second);

    let hidden = call(&registry, &db, "get_record", json!({ "ids": [bearer] })).await;
    assert_eq!(hidden["records"][0]["citation_count"], 2);
    assert_eq!(hidden["records"][0]["child_count"], 0);
    assert!(hidden["records"][0].get("citations").is_none());
    let hidden_text = native_ce::mcp::render::render("get_record", &hidden).unwrap();
    assert!(
        hidden_text.contains("Citations: 2 hidden (re-read with include_citations:true)"),
        "{hidden_text}"
    );

    let page = call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": [bearer], "include_citations": true, "citations_limit": 1, "citations_offset": 1 }),
    )
    .await;
    assert_eq!(page["records"][0]["citations"].as_array().unwrap().len(), 1);
    let page_text = native_ce::mcp::render::render("get_record", &page).unwrap();
    assert!(
        page_text.contains("Citations (2 total, showing 2–2)"),
        "{page_text}"
    );
    assert!(page_text.contains(&second), "{page_text}");

    let direct = call(&registry, &db, "get_record", json!({ "ids": [first] })).await;
    assert_eq!(direct["records"][0]["type"], "Annotation");
    assert_eq!(
        direct["records"][0]["target"]["validation"]["status"],
        "current"
    );
    assert!(direct["records"][0]["target"]["display"]
        .as_str()
        .unwrap()
        .contains(" body "));
    let direct_text = native_ce::mcp::render::render("get_record", &direct).unwrap();
    for expected in [
        source.as_str(),
        "Target details:",
        "source_slot",
        "selectors",
        "validation",
        "anchored",
        "current",
    ] {
        assert!(
            direct_text.contains(expected),
            "missing {expected}: {direct_text}"
        );
    }

    let ordinary = call(
        &registry,
        &db,
        "query_record",
        json!({ "steps": [{ "step": "filter", "home_id": bearer }] }),
    )
    .await;
    assert_eq!(ordinary["returned"], 0);
    let explicit = call(
        &registry,
        &db,
        "query_record",
        json!({ "steps": [{ "step": "filter", "kinds": ["citation"] }] }),
    )
    .await;
    assert_eq!(explicit["returned"], 2);
}

#[tokio::test]
async fn visibility_is_type_scoped_and_hidden_family_opt_ins_are_independent() {
    let db = db().await;
    let registry = registry();
    let bearer = create(
        &registry,
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Bearer" }),
    )
    .await;
    let source = create(
        &registry,
        &db,
        json!({ "type": "Document", "name": "Source", "body": "evidence" }),
    )
    .await;
    let ordinary_citation_kind = create(
        &registry,
        &db,
        json!({ "type": "Document", "kind": "citation", "name": "Open kind", "home_id": bearer }),
    )
    .await;
    let uncharacterised_annotation = "annotation-with-null-kind".to_string();
    sqlx::query(
        "INSERT INTO records
           (id, type, kind, name, home_id, policy_anchor_id, persistence,
            last_activity_at, created_at, updated_at)
         VALUES (?, 'Annotation', NULL, 'Uncharacterised annotation', ?,
                 (SELECT policy_anchor_id FROM records WHERE id = ?),
                 'enduring', ?, ?, ?)",
    )
    .bind(&uncharacterised_annotation)
    .bind(&bearer)
    .bind(&bearer)
    .bind("2026-08-01T12:00:00.000Z")
    .bind("2026-08-01T12:00:00.000Z")
    .bind("2026-08-01T12:00:00.000Z")
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    add_link(
        &db,
        LinkAddedPayload {
            id: Some("uncharacterised-annotation-bearer".into()),
            source_id: uncharacterised_annotation.clone(),
            target_id: bearer.clone(),
            relationship: "part_of".into(),
            note: None,
        },
    )
    .await
    .unwrap();
    let suggestion = create(
        &registry,
        &db,
        json!({
            "type": "Annotation",
            "kind": "suggestion",
            "name": "Hidden suggestion",
            "home_id": bearer,
            // Suggestions are authored `open`; the governed vocabulary rejects
            // an omitted lifecycle. This test is about citation visibility, so
            // it just needs a validly authored suggestion.
            "lifecycle": "open",
            "links": [{ "target_id": bearer, "relationship": "part_of" }],
            "facets": { "proposal.precondition": "none" }
        }),
    )
    .await;
    let citation = body_citation(&registry, &db, &bearer, &source, "evidence").await;

    let ordinary = call(
        &registry,
        &db,
        "query_record",
        json!({ "steps": [{ "step": "filter", "home_id": bearer }] }),
    )
    .await;
    let ordinary_ids: Vec<&str> = ordinary["records"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|row| row["id"].as_str())
        .collect();
    assert!(ordinary_ids.contains(&ordinary_citation_kind.as_str()));
    assert!(ordinary_ids.contains(&uncharacterised_annotation.as_str()));
    assert!(!ordinary_ids.contains(&citation.as_str()));
    assert!(!ordinary_ids.contains(&suggestion.as_str()));

    let ordinary_read = call(&registry, &db, "get_record", json!({ "ids": [bearer] })).await;
    assert_eq!(ordinary_read["records"][0]["child_count"], 2);
    let child_ids: Vec<&str> = ordinary_read["records"][0]["children"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|child| child["id"].as_str())
        .collect();
    assert!(child_ids.contains(&ordinary_citation_kind.as_str()));
    assert!(child_ids.contains(&uncharacterised_annotation.as_str()));
    let structure = call(
        &registry,
        &db,
        "get_structure",
        json!({ "root_id": bearer, "max_depth": 1 }),
    )
    .await;
    assert!(structure.to_string().contains(&ordinary_citation_kind));
    assert!(structure.to_string().contains(&uncharacterised_annotation));
    assert!(!structure.to_string().contains(&citation));
    assert!(!structure.to_string().contains(&suggestion));
    let search = call(&registry, &db, "search", json!({ "query": "Open kind" })).await;
    assert!(search.to_string().contains(&ordinary_citation_kind));
    let scan = call(&registry, &db, "scan", json!({ "query": "Open kind" })).await;
    assert!(scan.to_string().contains(&ordinary_citation_kind));
    let null_kind_search = call(
        &registry,
        &db,
        "search",
        json!({ "query": "Uncharacterised annotation" }),
    )
    .await;
    assert!(null_kind_search
        .to_string()
        .contains(&uncharacterised_annotation));

    let citation_round_trip = call(
        &registry,
        &db,
        "query_record",
        json!({
            "steps": [
                { "step": "filter", "kinds": ["citation"] }
            ]
        }),
    )
    .await;
    let citation_ids: Vec<&str> = citation_round_trip["records"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|row| row["id"].as_str())
        .collect();
    assert!(citation_ids.contains(&citation.as_str()));
    assert!(citation_ids.contains(&ordinary_citation_kind.as_str()));
    assert!(!citation_ids.contains(&suggestion.as_str()));

    let suggestion_round_trip = call(
        &registry,
        &db,
        "query_record",
        json!({
            "steps": [
                { "step": "filter", "kinds": ["suggestion"] }
            ]
        }),
    )
    .await;
    let suggestion_ids: Vec<&str> = suggestion_round_trip["records"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|row| row["id"].as_str())
        .collect();
    assert!(suggestion_ids.contains(&suggestion.as_str()));
    assert!(!suggestion_ids.contains(&ordinary_citation_kind.as_str()));
    assert!(!suggestion_ids.contains(&citation.as_str()));
}

#[tokio::test]
async fn verified_anchor_survives_source_deletion_as_stale_current_state() {
    let db = db().await;
    let registry = registry();
    let source = create(
        &registry,
        &db,
        json!({ "type": "Document", "name": "Source", "body": "durable evidence" }),
    )
    .await;
    let bearer = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "name": "Task" }),
    )
    .await;
    let citation = body_citation(&registry, &db, &bearer, &source, "durable evidence").await;
    call(
        &registry,
        &db,
        "delete_record",
        json!({ "id": source, "reason": "Remove current source after capture" }),
    )
    .await;
    let resolved = call(
        &registry,
        &db,
        "resolve_citation",
        json!({ "citation_id": citation }),
    )
    .await;
    assert_eq!(resolved["anchored"]["available"], true);
    assert_eq!(resolved["anchored"]["excerpt"]["text"], "durable evidence");
    assert_eq!(resolved["validation"]["status"], "stale");
    assert_eq!(resolved["current"], Value::Null);
}

#[tokio::test]
async fn large_exact_evidence_relocates_once_and_conflicts_when_duplicated() {
    let db = db().await;
    let registry = registry();
    let evidence = format!("BEGIN:{}:END", "proof".repeat(4096));
    let original = format!("{}{}{}", "a".repeat(512_000), evidence, "z".repeat(512_000));
    let start = original.find(&evidence).unwrap();
    let source = create(
        &registry,
        &db,
        json!({ "type": "Document", "name": "Large source", "body": original }),
    )
    .await;
    let bearer = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "name": "Task" }),
    )
    .await;
    let citation = create(
        &registry,
        &db,
        json!({
            "type": "Annotation", "kind": "citation", "home_id": bearer,
            "target": {
                "target_record_id": source, "source_slot": "body",
                "selectors": [{ "type": "data_position", "start": start, "end": start + evidence.len() }]
            }
        }),
    )
    .await;

    let moved = format!("{}{}{}", "b".repeat(600_000), evidence, "c".repeat(424_000));
    call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": source, "body": moved,
            "if_body_digest": current_body_digest(&registry, &db, &source).await
        }),
    )
    .await;
    assert_eq!(
        call(
            &registry,
            &db,
            "resolve_citation",
            json!({ "citation_id": citation })
        )
        .await["validation"]["status"],
        "relocated"
    );

    call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": source, "body": format!("left{evidence}middle{evidence}right"),
            "if_body_digest": current_body_digest(&registry, &db, &source).await
        }),
    )
    .await;
    assert_eq!(
        call(
            &registry,
            &db,
            "resolve_citation",
            json!({ "citation_id": citation })
        )
        .await["validation"]["status"],
        "conflict"
    );
}

#[tokio::test]
async fn reanchor_and_remove_are_audited_and_temporal_state_survives() {
    let db = db().await;
    let registry = registry();
    let source = create(
        &registry,
        &db,
        json!({ "type": "Document", "name": "Source", "body": "alpha beta" }),
    )
    .await;
    let bearer = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "name": "Task" }),
    )
    .await;
    let citation = body_citation(&registry, &db, &bearer, &source, "alpha").await;
    let reanchor_receipt = call(
        &registry,
        &db,
        "manage_citations",
        json!({
            "action": "reanchor", "citation_id": citation,
            "target": { "target_record_id": source, "source_slot": "body", "selectors": [{ "type": "text_quote", "exact": "beta" }] },
            "reason": "The evidence is the second assertion"
        }),
    )
    .await;
    assert_eq!(reanchor_receipt["action"], "reanchored");
    let reanchor_text = render::render("manage_citations", &reanchor_receipt).unwrap();
    let reanchor_event = format!("Event sequence: {}", reanchor_receipt["event_seq"]);
    for expected in [
        citation.as_str(),
        "reanchored",
        reanchor_event.as_str(),
        "The evidence is the second assertion",
    ] {
        assert!(
            reanchor_text.contains(expected),
            "missing {expected}: {reanchor_text}"
        );
    }
    let reanchored = call(
        &registry,
        &db,
        "resolve_citation",
        json!({ "citation_id": citation }),
    )
    .await;
    assert_eq!(reanchored["anchored"]["excerpt"]["text"], "beta");
    let target_seq: i64 = sqlx::query_scalar(
        "SELECT MAX(seq) FROM content_events WHERE record_id = ? AND type = 'annotation.target.set'",
    )
    .bind(&citation)
    .fetch_one(db.pool())
    .await
    .unwrap();

    let remove_receipt = call(
        &registry,
        &db,
        "manage_citations",
        json!({ "action": "remove", "citation_id": citation, "reason": "Evidence withdrawn after review" }),
    )
    .await;
    assert_eq!(remove_receipt["action"], "removed");
    let remove_text = render::render("manage_citations", &remove_receipt).unwrap();
    let remove_event = format!("Event sequence: {}", remove_receipt["event_seq"]);
    for expected in [
        citation.as_str(),
        "removed",
        remove_event.as_str(),
        "Evidence withdrawn after review",
    ] {
        assert!(
            remove_text.contains(expected),
            "missing {expected}: {remove_text}"
        );
    }
    let history = call(
        &registry,
        &db,
        "get_history",
        json!({ "record_id": citation }),
    )
    .await;
    assert!(history["events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|event| event["type"] == "annotation.target.removed"));
    let temporal = historical_record(&registry, &db, &citation, target_seq).await;
    assert_eq!(
        temporal["record"]["target"]["selectors"][0]["exact"],
        "beta"
    );
    assert!(call_err(
        &registry,
        &db,
        "resolve_citation",
        json!({ "citation_id": citation })
    )
    .await
    .contains("has no target"));
}

#[tokio::test]
async fn portable_remove_fails_closed_for_a_mixed_authority_multi_bearer_citation() {
    let db = db().await;
    let registry = registry();
    let editable_bearer = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "name": "Editable task" }),
    )
    .await;
    let hidden_bearer = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "name": "Hidden task" }),
    )
    .await;
    replace_explicit_policy(
        &db,
        "test:policy",
        &editable_bearer,
        vec![AllowEntry::account("acct:bea", Capability::Edit)],
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        "test:policy",
        &hidden_bearer,
        vec![AllowEntry::account("acct:alice", Capability::Manage)],
    )
    .await
    .unwrap();
    let source = create(
        &registry,
        &db,
        json!({ "type": "Document", "name": "Source", "body": "alpha beta" }),
    )
    .await;
    let citation = body_citation(&registry, &db, &editable_bearer, &source, "alpha").await;
    sqlx::query(
        "INSERT INTO links (id, source_id, target_id, relationship)
         VALUES ('mixed-authority-citation-bearer', ?, ?, 'part_of')",
    )
    .bind(&citation)
    .bind(&hidden_bearer)
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();

    let error = call_as(
        &registry,
        &db,
        Caller::authenticated("acct:bea")
            .with_hosting_context("host:bea", "db:test")
            .with_hosting_owner(false),
        "manage_citations",
        json!({
            "action": "remove", "citation_id": citation,
            "reason": "Attempted portable cleanup"
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("does not exist"), "{error}");
    let target_still_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM annotation_targets WHERE annotation_id = ?)",
    )
    .bind(&citation)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert!(target_still_exists);

    call(
        &registry,
        &db,
        "manage_citations",
        json!({
            "action": "remove", "citation_id": citation,
            "reason": "Trusted repair of malformed citation"
        }),
    )
    .await;
    let target_still_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM annotation_targets WHERE annotation_id = ?)",
    )
    .bind(&citation)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert!(!target_still_exists);
    db.close().await;
}

#[tokio::test]
async fn targets_replay_and_malformed_or_unicode_split_selectors_fail_atomically() {
    let db = db().await;
    let registry = registry();
    let source = create(
        &registry,
        &db,
        json!({ "type": "Document", "name": "Unicode", "body": "A café B" }),
    )
    .await;
    let bearer = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "name": "Task" }),
    )
    .await;
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let error = call_err(
        &registry,
        &db,
        "create_record",
        json!({
            "type": "Annotation", "kind": "citation", "home_id": bearer,
            "target": { "target_record_id": source, "source_slot": "body", "selectors": [{ "type": "data_position", "start": 5, "end": 6 }] }
        }),
    )
    .await;
    assert!(error.contains("UTF-8 code point"));
    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(before, after);

    let citation = body_citation(&registry, &db, &bearer, &source, "café").await;
    assert!(!citation.is_empty());
    let diff = rebuild_and_diff(&db).await.unwrap();
    assert!(diff.equal, "{:?}", diff.tables);
}

#[tokio::test]
async fn projector_rejects_target_events_unless_record_is_a_target_bearing_annotation() {
    let db = db().await;
    let registry = registry();
    let wrong_type = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "kind": "citation", "name": "Open kind task" }),
    )
    .await;
    // Record ids must be canonical v4/v7 UUIDs; this one is pinned and only has
    // to exist as an Annotation of the wrong kind.
    let wrong_kind = "c17a7104-0000-4000-8000-000000000001".to_string();
    append(
        &db,
        AppendSpec {
            record_id: wrong_kind.clone(),
            event_type: "record.created".into(),
            payload: json!({ "type": "Annotation", "kind": "suggestion", "name": "Suggestion" }),
            actor: None,
        },
    )
    .await
    .unwrap();

    for record_id in [wrong_type, wrong_kind] {
        let event_type = "annotation.target.removed";
        let error = append(
            &db,
            AppendSpec {
                record_id,
                event_type: event_type.into(),
                payload: json!({}),
                actor: None,
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("not a target-bearing Annotation"), "{error}");
    }
    let target_events: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM content_events WHERE type LIKE 'annotation.target.%'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(target_events, 0);
}

#[tokio::test]
async fn targeted_citation_shape_is_preserved_atomically_in_writes_and_replay() {
    let db = db().await;
    let registry = registry();
    let source = create(
        &registry,
        &db,
        json!({ "type": "Document", "name": "Source", "body": "evidence" }),
    )
    .await;
    let bearer = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "name": "Bearer" }),
    )
    .await;
    let citation = body_citation(&registry, &db, &bearer, &source, "evidence").await;
    let base_seq: i64 = sqlx::query_scalar("SELECT MAX(seq) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let prefix = log_prefix(&db, base_seq).await.unwrap();

    for (label, payload, tool_expected, replay_expected) in [
        (
            "clear kind",
            json!({ "kind": null }),
            "kind is replaceable but cannot be cleared",
            "requires a non-null kind",
        ),
        (
            "change kind",
            json!({ "kind": "comment" }),
            "comment identity cannot be added",
            "targeted Annotation",
        ),
    ] {
        let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let mut tool_args = payload.clone();
        tool_args["id"] = json!(citation);
        tool_args["reason"] = json!(label);
        let tool_error = call_err(&registry, &db, "update_record", tool_args).await;
        assert!(tool_error.contains(tool_expected), "{label}: {tool_error}");
        let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(after, before, "{label} wrote a rejected event");

        let mut replay_events = prefix.clone();
        replay_events.push(EventRow {
            local_seq: base_seq + 1,
            id: format!("invalid-{label}"),
            record_id: citation.clone(),
            event_type: "record.updated".into(),
            payload: Some(payload.to_string()),
            actor: None,
            run_key: None,
            parent_key: None,
            intent: None,
            created_at: "2026-08-01T12:00:00.000Z".into(),
            causal_envelope: native_ce::events::CausalEnvelopeV1::default(),
        });
        let scratch = replay_db().await;
        {
            let mut conn = crate::common::fixture_write_pool(&scratch)
                .await
                .acquire()
                .await
                .unwrap();
            let replay_error = replay_with_blob_seeds(&db, &mut conn, &replay_events, None)
                .await
                .unwrap_err()
                .to_string();
            assert!(
                replay_error.contains(replay_expected),
                "{label}: {replay_error}"
            );
        }
        let unchanged = sqlx::query("SELECT kind, home_id FROM records WHERE id = ?")
            .bind(&citation)
            .fetch_one(scratch.pool())
            .await
            .unwrap();
        assert_eq!(
            unchanged.try_get::<Option<String>, _>("kind").unwrap(),
            Some("citation".into())
        );
        assert_eq!(
            unchanged.try_get::<Option<String>, _>("home_id").unwrap(),
            Some(native_ce::schema::UNFILED_RECORD_ID.into())
        );
        scratch.close().await;
    }

    call(
        &registry,
        &db,
        "delete_record",
        json!({ "id": citation, "reason": "Delete the citation Annotation" }),
    )
    .await;
    let resolve_error = call_err(
        &registry,
        &db,
        "resolve_citation",
        json!({ "citation_id": citation }),
    )
    .await;
    assert!(
        resolve_error.contains("not a live citation"),
        "{resolve_error}"
    );
}

#[tokio::test]
async fn generic_part_of_links_remain_open_on_a_targeted_citation() {
    let db = db().await;
    let registry = registry();
    let source = create(
        &registry,
        &db,
        json!({ "type": "Document", "name": "Source", "body": "evidence" }),
    )
    .await;
    let bearer = create(
        &registry,
        &db,
        json!({ "type": "WorkItem", "name": "Bearer" }),
    )
    .await;
    let extra = create(
        &registry,
        &db,
        json!({ "type": "Outcome", "name": "Additional domain context" }),
    )
    .await;
    let citation = body_citation(&registry, &db, &bearer, &source, "evidence").await;

    add_link(
        &db,
        LinkAddedPayload {
            id: Some("citation-extra-part-of".into()),
            source_id: citation.clone(),
            target_id: extra.clone(),
            relationship: "part_of".into(),
            note: Some("domain-authored context".into()),
        },
    )
    .await
    .unwrap();
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM links WHERE source_id = ? AND relationship = 'part_of'",
    )
    .bind(&citation)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(count, 2);
    let error = call_err(
        &registry,
        &db,
        "resolve_citation",
        json!({ "citation_id": citation }),
    )
    .await;
    assert!(
        error.contains("not a live citation with a bearer"),
        "{error}"
    );

    remove_link(
        &db,
        LinkRemovedPayload {
            source_id: citation.clone(),
            target_id: extra,
            relationship: "part_of".into(),
        },
    )
    .await
    .unwrap();
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM links WHERE source_id = ? AND relationship = 'part_of'",
    )
    .bind(&citation)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(count, 1);
    call(
        &registry,
        &db,
        "resolve_citation",
        json!({ "citation_id": citation }),
    )
    .await;
}
