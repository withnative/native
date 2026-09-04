//! Definition documents and their glossary-term identity contract (da4a16e).

use native_ce::conformance::{rebuild_and_diff, rebuild_and_diff_meta};
use native_ce::events::{FacetSetPayload, LinkAddedPayload};
use native_ce::generated::kinds::CoreKind;
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::meta::{
    alias_value, list_values, promote_value, propose_value, seed_recommended_pack_schema_config,
    seed_vocabularies, ListValuesOptions,
};
use native_ce::store::{
    add_link, append, archive_record, create_record, delete_record, restore_record, set_facet,
    update_record, AppendSpec,
};
use native_ce::{create_database, Db};
use serde_json::{json, Value};
use sqlx::Row;

/// Fixture record ids. Record ids must be canonical lowercase UUIDs, so the
/// readable name lives in the constant. All pinned literals, never generated.
///
/// The ids marked *named in an error* are load-bearing: the conflict messages
/// quote the offending record id verbatim, and the assertions below match on
/// the constant, so the id text still has to survive into the message.
const ILLEGAL_PRECONDITION: &str = "9de70000-0000-4000-8000-000000000001";
const MISSING_PRECONDITION: &str = "9de70000-0000-4000-8000-000000000002";
const LEGACY_SUGGESTION_BEARER: &str = "9de70000-0000-4000-8000-000000000003";
const LEGACY_SUGGESTION: &str = "9de70000-0000-4000-8000-000000000004";
const DEFAULTED_TASK: &str = "9de70000-0000-4000-8000-000000000005";
const COMPLETED_TASK: &str = "9de70000-0000-4000-8000-000000000006";
const INVALID_TASK: &str = "9de70000-0000-4000-8000-000000000007";
const LEGACY_NULL_TASK: &str = "9de70000-0000-4000-8000-000000000008";
const DEFAULTED_EPIC: &str = "9de70000-0000-4000-8000-000000000009";
const OPEN_EPIC: &str = "9de70000-0000-4000-8000-00000000000a";
const MISSING_TERM: &str = "9de70000-0000-4000-8000-00000000000b";
const PROPOSED_TERM: &str = "9de70000-0000-4000-8000-00000000000c";
const VALID_TERM: &str = "9de70000-0000-4000-8000-00000000000d";
/// Named in an error: the current definition a duplicate collides with.
const ARTIFACT_CURRENT: &str = "9de70000-0000-4000-8000-00000000000e";
const ARTIFACT_DRAFT_A: &str = "9de70000-0000-4000-8000-00000000000f";
const ARTIFACT_DRAFT_B: &str = "9de70000-0000-4000-8000-000000000010";
const ARTIFACT_OLD: &str = "9de70000-0000-4000-8000-000000000011";
const WIDGET_CURRENT: &str = "9de70000-0000-4000-8000-000000000012";
const TOOL_DUPLICATE: &str = "9de70000-0000-4000-8000-000000000013";
const DUPLICATE: &str = "9de70000-0000-4000-8000-000000000014";
/// Named in an error: the incumbent every promotion path must report.
const EXISTING: &str = "9de70000-0000-4000-8000-000000000015";
/// Named in an error: the promoted draft a restore would collide with.
const DRAFT: &str = "9de70000-0000-4000-8000-000000000016";
const KIND_FLIP: &str = "9de70000-0000-4000-8000-000000000017";
const TERM_CHANGE: &str = "9de70000-0000-4000-8000-000000000018";
const DEFINITION_ARTIFACT: &str = "9de70000-0000-4000-8000-000000000019";
/// Named in an error: the alias-spelled definition blocking the alias.
const DEFINITION_WIDGET: &str = "9de70000-0000-4000-8000-00000000001a";
/// Named in an error: both sides of the refused identity merge.
const SOURCE_VIA_ALIAS: &str = "9de70000-0000-4000-8000-00000000001b";
const TARGET_DEFINITION: &str = "9de70000-0000-4000-8000-00000000001c";
const LEGACY_ONE: &str = "9de70000-0000-4000-8000-00000000001d";
const LEGACY_TWO: &str = "9de70000-0000-4000-8000-00000000001e";
const CANDIDATE_A: &str = "9de70000-0000-4000-8000-00000000001f";
const CANDIDATE_B: &str = "9de70000-0000-4000-8000-000000000020";
const COMPLETED_EPIC: &str = "9de70000-0000-4000-8000-000000000021";
const CLOSED_EPIC: &str = "9de70000-0000-4000-8000-000000000022";
const INVALID_EPIC: &str = "9de70000-0000-4000-8000-000000000023";
const FUTURE_WORK: &str = "9de70000-0000-4000-8000-000000000024";
const INVALID_FUTURE_WORK: &str = "9de70000-0000-4000-8000-000000000025";
const HISTORICAL_EPIC: &str = "9de70000-0000-4000-8000-000000000027";
const HISTORICAL_EPIC_ALIAS: &str = "9de70000-0000-4000-8000-000000000028";

async fn db() -> Db {
    let db = create_database(":memory:").await.unwrap();
    seed_vocabularies(&db).await.unwrap();
    seed_recommended_pack_schema_config(&db).await.unwrap();
    db
}

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

async fn call(registry: &ToolRegistry, db: &Db, tool: &str, args: Value) -> Value {
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

async fn call_err(registry: &ToolRegistry, db: &Db, tool: &str, args: Value) -> String {
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

async fn active_term(db: &Db, term: &str) -> String {
    let id = propose_value(db, "glossary", term, Some("short form"))
        .await
        .unwrap();
    promote_value(db, &id).await.unwrap();
    id
}

async fn raw_definition(db: &Db, id: &str, term: &str, maturity: &str) {
    create_record(
        db,
        json!({
            "id": id,
            "type": "Document",
            "kind": "definition",
            "name": term,
            "maturity": maturity
        }),
    )
    .await
    .unwrap();
    set_facet(
        db,
        id,
        FacetSetPayload {
            key: "term".into(),
            value: Some(term.into()),
            vocab_ref: Some("rec:voc:glossary".into()),
            as_of: None,
            observation_only: false,
        },
    )
    .await
    .unwrap();
}

async fn current_count(db: &Db, term: &str) -> i64 {
    sqlx::query(
        "SELECT COUNT(*) AS n
           FROM records r
           JOIN facet_values f ON f.record_id = r.id
          WHERE r.type = 'Document' AND r.kind = 'definition'
            AND r.maturity = 'decided' AND r.deleted_at IS NULL
            AND f.key = 'term' AND f.value = ?
            AND NOT EXISTS (
                SELECT 1 FROM facet_values a
                 WHERE a.record_id = r.id AND a.key = 'archived'
            )",
    )
    .bind(term)
    .fetch_one(db.pool())
    .await
    .unwrap()
    .get("n")
}

#[tokio::test]
async fn seeds_governed_pack_vocabularies_and_shapes_idempotently() {
    let db = create_database(":memory:").await.unwrap();
    seed_vocabularies(&db).await.unwrap();
    seed_recommended_pack_schema_config(&db).await.unwrap();
    let after_first: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM meta_events")
        .fetch_one(db.pool())
        .await
        .unwrap();

    seed_vocabularies(&db).await.unwrap();
    seed_recommended_pack_schema_config(&db).await.unwrap();
    let after_second: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM meta_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(after_second, after_first);

    let glossary: (String, String, i64) = sqlx::query_as(
        "SELECT v.id, v.name,
                (SELECT COUNT(*) FROM vocabulary_values vv WHERE vv.vocabulary_id = v.id)
           FROM vocabularies v WHERE v.id = 'voc:glossary'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(glossary, ("voc:glossary".into(), "glossary".into(), 0));

    let data: String =
        sqlx::query_scalar("SELECT data FROM schema_config WHERE id = 'pack:@native/recommended'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    let data: Value = serde_json::from_str(&data).unwrap();
    assert!(data["shapes"]
        .as_object()
        .unwrap()
        .keys()
        .all(|shape| shape.contains(':') || shape == "Message"));
    assert_eq!(
        data["shapes"]["Document:definition"]["facets"]["term"],
        json!({ "vocab_ref": "glossary", "required": true })
    );
    assert_eq!(
        data["shapes"]["Document:artifact"]["facets"]["runtime"],
        json!({ "vocab_ref": "artifact-runtime", "required": true })
    );
    assert_eq!(
        data["shapes"]["Program:module"]["facets"]["runtime"],
        json!({ "vocab_ref": "artifact-runtime", "required": true })
    );
    assert_eq!(
        data["shapes"]["Program:recipe"]["facets"]["runtime"],
        json!({ "vocab_ref": "recipe-runtime", "required": true })
    );
    assert_eq!(
        data["shapes"]["Message"]["facets"]["expectation"],
        json!({ "vocab_ref": "message-expectation", "required": true })
    );
    assert_eq!(
        data["shapes"]["WorkItem:task"]["facets"]["lifecycle"],
        json!({ "vocab_ref": "lifecycle", "required": true,
            "axis": { "key": "work_status", "label": "Work status" } })
    );
    assert_eq!(
        data["shapes"]["WorkItem:epic"]["facets"]["lifecycle"],
        data["shapes"]["WorkItem:task"]["facets"]["lifecycle"]
    );
    assert_eq!(
        data["shapes"]["Annotation:suggestion"]["facets"]["lifecycle"],
        json!({ "vocab_ref": "suggestion-lifecycle", "required": true,
            "axis": { "key": "proposal_disposition", "label": "Suggestion disposition" } })
    );
    assert!(data["shapes"].get("WorkItem").is_none());
    let lifecycle: Vec<(String, f64, String)> = sqlx::query_as(
        "SELECT value, ordinal, terminality FROM vocabulary_values
          WHERE vocabulary_id = 'voc:lifecycle' ORDER BY ordinal, value",
    )
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(
        lifecycle,
        vec![
            ("open".into(), 100.0, "open".into()),
            ("in_progress".into(), 200.0, "open".into()),
            ("blocked".into(), 300.0, "open".into()),
            ("completed".into(), 400.0, "terminal_positive".into()),
            ("closed".into(), 500.0, "terminal_negative".into()),
        ]
    );
    let suggestion_lifecycle: Vec<(String, f64, String)> = sqlx::query_as(
        "SELECT value, ordinal, terminality FROM vocabulary_values
          WHERE vocabulary_id = 'voc:suggestion-lifecycle' ORDER BY ordinal, value",
    )
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(
        suggestion_lifecycle,
        vec![
            ("open".into(), 100.0, "open".into()),
            ("accepted".into(), 200.0, "terminal_positive".into()),
            ("rejected".into(), 300.0, "terminal_negative".into()),
            ("stale".into(), 400.0, "terminal_negative".into()),
        ]
    );
    let expectations: Vec<String> = sqlx::query_scalar(
        "SELECT value FROM vocabulary_values WHERE vocabulary_id = 'voc:message-expectation' ORDER BY ordinal, value",
    )
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(
        expectations,
        vec!["ack", "action", "decision", "none", "reply"]
    );
    assert_eq!(
        data["shapes"]["Annotation:suggestion"]["facets"],
        json!({
            "proposal.precondition": {
                "values": ["none", "span", "digest", "field_equals", "seq"],
                "required": true
            },
            "anchor.old": {},
            "anchor.base_digest": {},
            "lifecycle": { "vocab_ref": "suggestion-lifecycle", "required": true,
                "axis": { "key": "proposal_disposition", "label": "Suggestion disposition" } }
        })
    );
    let governed: Vec<(String, String)> = sqlx::query_as(
        "SELECT v.name, vv.value
           FROM vocabularies v
           JOIN vocabulary_values vv ON vv.vocabulary_id = v.id
          WHERE v.name LIKE 'kind:%' AND vv.status = 'active'
          ORDER BY v.name, vv.value",
    )
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(
        governed,
        vec![
            ("kind:Annotation".into(), "acknowledgement".into()),
            ("kind:Annotation".into(), "attribution".into()),
            ("kind:Annotation".into(), "citation".into()),
            ("kind:Annotation".into(), "comment".into()),
            ("kind:Annotation".into(), "suggestion".into()),
            ("kind:Collection".into(), "folder".into()),
            ("kind:Collection".into(), "query".into()),
            ("kind:Collection".into(), "selection".into()),
            ("kind:Conversation".into(), "discussion".into()),
            ("kind:Conversation".into(), "transcript".into()),
            ("kind:Document".into(), "artifact".into()),
            ("kind:Document".into(), "attachment".into()),
            ("kind:Document".into(), "canvas".into()),
            ("kind:Document".into(), "definition".into()),
            ("kind:Document".into(), "handoff".into()),
            ("kind:Document".into(), "note".into()),
            ("kind:Document".into(), "sheet".into()),
            ("kind:Document".into(), "slides".into()),
            ("kind:Entity".into(), "organization".into()),
            ("kind:Entity".into(), "person".into()),
            ("kind:Message".into(), "text".into()),
            ("kind:Outcome".into(), "impact".into()),
            ("kind:Outcome".into(), "milestone".into()),
            ("kind:Outcome".into(), "target".into()),
            ("kind:Program".into(), "module".into()),
            ("kind:Program".into(), "recipe".into()),
            ("kind:Resolution".into(), "decision".into()),
            ("kind:Resolution".into(), "rule".into()),
            ("kind:WorkItem".into(), "epic".into()),
            ("kind:WorkItem".into(), "task".into()),
        ]
    );
    assert!(rebuild_and_diff_meta(&db).await.unwrap().equal);
}

#[tokio::test]
async fn suggestion_shape_is_discoverable_and_enforced_forward() {
    let db = db().await;
    let registry = registry();

    let resolved = call(
        &registry,
        &db,
        "resolve_facets",
        json!({ "type": "Annotation", "kind": "suggestion" }),
    )
    .await;
    assert_eq!(
        resolved["shape"],
        json!({
            "proposal.precondition": {
                "values": ["none", "span", "digest", "field_equals", "seq"],
                "required": true
            },
            "anchor.old": {},
            "anchor.base_digest": {},
            "lifecycle": { "vocab_ref": "suggestion-lifecycle", "required": true,
                "axis": { "key": "proposal_disposition", "label": "Suggestion disposition" } }
        })
    );

    let err = call_err(
        &registry,
        &db,
        "create_record",
        json!({
            "id": ILLEGAL_PRECONDITION,
            "type": "Annotation",
            "kind": "suggestion",
            "lifecycle": "open",
            "facets": { "proposal.precondition": "maybe" }
        }),
    )
    .await;
    assert!(err.contains("not in the declared values set"), "{err}");
    for legal in ["none", "span", "digest", "field_equals", "seq"] {
        assert!(err.contains(legal), "missing legal value {legal:?}: {err}");
    }

    let err = call_err(
        &registry,
        &db,
        "create_record",
        json!({
            "id": MISSING_PRECONDITION,
            "type": "Annotation",
            "kind": "suggestion",
            "lifecycle": "open"
        }),
    )
    .await;
    assert!(
        err.contains("missing required facet 'proposal.precondition'"),
        "{err}"
    );

    create_record(
        &db,
        json!({
            "id": LEGACY_SUGGESTION_BEARER,
            "type": "WorkItem",
            "kind": "task",
            "name": "Legacy suggestion target"
        }),
    )
    .await
    .unwrap();
    create_record(
        &db,
        json!({
            "id": LEGACY_SUGGESTION,
            "type": "Annotation",
            "kind": "suggestion",
            "name": "Legacy suggestion"
        }),
    )
    .await
    .unwrap();
    add_link(
        &db,
        LinkAddedPayload {
            id: Some("legacy-suggestion-part-of".into()),
            source_id: LEGACY_SUGGESTION.into(),
            target_id: LEGACY_SUGGESTION_BEARER.into(),
            relationship: "part_of".into(),
            note: None,
        },
    )
    .await
    .unwrap();
    let updated = call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": LEGACY_SUGGESTION,
            "summary": "Still editable"
        }),
    )
    .await;
    assert_eq!(updated["summary"], "Still editable");
}

#[tokio::test]
async fn task_and_epic_lifecycle_writes_are_kind_scoped_and_preserve_historical_evidence() {
    let db = db().await;
    let registry = registry();

    let defaulted = call(
        &registry,
        &db,
        "create_record",
        json!({ "id": DEFAULTED_TASK, "type": "WorkItem", "kind": "task" }),
    )
    .await;
    assert_eq!(
        defaulted["lifecycle_interpretation"]["value"]["canonical"],
        "open"
    );

    let explicit = call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": COMPLETED_TASK,
            "type": "WorkItem",
            "kind": "task",
            "lifecycle": "completed"
        }),
    )
    .await;
    assert_eq!(
        explicit["lifecycle_interpretation"]["value"]["canonical"],
        "completed"
    );

    let invalid = call_err(
        &registry,
        &db,
        "create_record",
        json!({
            "id": INVALID_TASK,
            "type": "WorkItem",
            "kind": "task",
            "lifecycle": "claimed"
        }),
    )
    .await;
    assert!(invalid.contains("not an active member"), "{invalid}");

    let clear = call_err(
        &registry,
        &db,
        "update_record",
        json!({ "id": COMPLETED_TASK, "lifecycle": null }),
    )
    .await;
    assert!(
        clear.contains("missing required facet 'lifecycle'"),
        "{clear}"
    );

    create_record(
        &db,
        json!({
            "id": LEGACY_NULL_TASK,
            "type": "WorkItem",
            "kind": "task",
            "name": "Predates governed lifecycle"
        }),
    )
    .await
    .unwrap();
    let legacy = call(
        &registry,
        &db,
        "update_record",
        json!({ "id": LEGACY_NULL_TASK, "summary": "Still a comparative gap" }),
    )
    .await;
    assert_eq!(legacy["lifecycle_interpretation"]["status"], "absent");

    let defaulted_epic = call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": DEFAULTED_EPIC,
            "type": "WorkItem",
            "kind": "epic"
        }),
    )
    .await;
    assert_eq!(
        defaulted_epic["lifecycle_interpretation"]["axis"]["key"],
        "work_status"
    );
    assert_eq!(
        defaulted_epic["lifecycle_interpretation"]["value"]["canonical"],
        "open"
    );
    assert_eq!(
        defaulted_epic["lifecycle_interpretation"]["terminality"],
        "open"
    );
    let epic_alias = native_ce::meta::propose_value_with_kind_metadata_as(
        &db,
        "kind:WorkItem",
        "initiative",
        Some("Deprecated epic alias"),
        999.0,
        native_ce::meta::VocabularyValueTerminality::Open,
        Some(native_ce::meta::KindMetadataV1::legacy(
            "WorkItem",
            "initiative",
        )),
        None,
    )
    .await
    .unwrap();
    promote_value(&db, &epic_alias).await.unwrap();
    alias_value(&db, &epic_alias, "vv:voc:kind:WorkItem:epic")
        .await
        .unwrap();
    let defaulted_alias = call(
        &registry,
        &db,
        "create_record",
        json!({
            "type": "WorkItem",
            "kind": "initiative"
        }),
    )
    .await;
    assert_eq!(defaulted_alias["kind"], "epic");
    assert_eq!(
        defaulted_alias["lifecycle_interpretation"]["value"]["canonical"],
        "open"
    );
    create_record(
        &db,
        json!({
            "id": HISTORICAL_EPIC_ALIAS,
            "type": "WorkItem",
            "kind": "initiative",
            "name": "Historical alias-spelled epic",
            "lifecycle": "open"
        }),
    )
    .await
    .unwrap();
    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": HISTORICAL_EPIC_ALIAS, "lifecycle": "completed" }),
    )
    .await;
    let historical_alias: (String, String) =
        sqlx::query_as("SELECT kind, lifecycle FROM records WHERE id = ?")
            .bind(HISTORICAL_EPIC_ALIAS)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(historical_alias, ("initiative".into(), "completed".into()));

    for (id, lifecycle, terminality) in [
        (OPEN_EPIC, "open", "open"),
        (COMPLETED_EPIC, "completed", "terminal_positive"),
        (CLOSED_EPIC, "closed", "terminal_negative"),
    ] {
        let epic = call(
            &registry,
            &db,
            "create_record",
            json!({
                "id": id,
                "type": "WorkItem",
                "kind": "epic",
                "lifecycle": lifecycle
            }),
        )
        .await;
        assert_eq!(epic["lifecycle_interpretation"]["status"], "governed");
        assert_eq!(
            epic["lifecycle_interpretation"]["axis"]["key"],
            "work_status"
        );
        assert_eq!(
            epic["lifecycle_interpretation"]["value"]["canonical"],
            lifecycle
        );
        assert_eq!(epic["lifecycle_interpretation"]["terminality"], terminality);
    }

    let invalid_epic = call_err(
        &registry,
        &db,
        "create_record",
        json!({
            "id": INVALID_EPIC,
            "type": "WorkItem",
            "kind": "epic",
            "lifecycle": "bespoke"
        }),
    )
    .await;
    assert!(
        invalid_epic.contains("not an active member"),
        "{invalid_epic}"
    );

    crate::common::govern_kind(&db, "WorkItem", "future-work").await;
    let future = call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": FUTURE_WORK,
            "type": "WorkItem",
            "kind": "future-work"
        }),
    )
    .await;
    assert_eq!(future["lifecycle_interpretation"]["status"], "absent");
    let invalid_future = call_err(
        &registry,
        &db,
        "create_record",
        json!({
            "id": INVALID_FUTURE_WORK,
            "type": "WorkItem",
            "kind": "future-work",
            "lifecycle": "open"
        }),
    )
    .await;
    assert!(
        invalid_future.contains("ordinary non-null lifecycle writes require"),
        "{invalid_future}"
    );

    let missing_on_entry = call_err(
        &registry,
        &db,
        "update_record",
        json!({ "id": FUTURE_WORK, "kind": "epic" }),
    )
    .await;
    assert!(
        missing_on_entry.contains("missing required facet 'lifecycle'"),
        "{missing_on_entry}"
    );
    let entered_epic = call(
        &registry,
        &db,
        "update_record",
        json!({ "id": FUTURE_WORK, "kind": "epic", "lifecycle": "open" }),
    )
    .await;
    assert_eq!(entered_epic["kind"], "epic");
    assert_eq!(
        entered_epic["lifecycle_interpretation"]["value"]["canonical"],
        "open"
    );
    let ungoverned_exit = call_err(
        &registry,
        &db,
        "update_record",
        json!({ "id": FUTURE_WORK, "kind": "future-work" }),
    )
    .await;
    assert!(
        ungoverned_exit.contains("ordinary non-null lifecycle writes require"),
        "{ungoverned_exit}"
    );
    let cleared_exit = call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": FUTURE_WORK,
            "kind": "future-work",
            "lifecycle": null
        }),
    )
    .await;
    assert_eq!(cleared_exit["kind"], "future-work");
    assert_eq!(cleared_exit["lifecycle_interpretation"]["status"], "absent");

    let task_to_epic = call(
        &registry,
        &db,
        "update_record",
        json!({ "id": COMPLETED_TASK, "kind": "epic" }),
    )
    .await;
    assert_eq!(task_to_epic["kind"], "epic");
    assert_eq!(
        task_to_epic["lifecycle_interpretation"]["value"]["canonical"],
        "completed"
    );
    let epic_to_task = call(
        &registry,
        &db,
        "update_record",
        json!({ "id": CLOSED_EPIC, "kind": "task" }),
    )
    .await;
    assert_eq!(epic_to_task["kind"], "task");
    assert_eq!(
        epic_to_task["lifecycle_interpretation"]["value"]["canonical"],
        "closed"
    );

    append(
        &db,
        AppendSpec {
            record_id: HISTORICAL_EPIC.into(),
            event_type: "record.created".into(),
            payload: json!({
                "type": "WorkItem",
                "kind": "epic",
                "name": "Imported unresolved epic",
                "lifecycle": "bespoke"
            }),
            actor: Some("import:test".into()),
        },
    )
    .await
    .unwrap();
    let historical = call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": [HISTORICAL_EPIC] }),
    )
    .await;
    let historical = &historical["records"][0];
    assert_eq!(
        historical["lifecycle_interpretation"]["status"],
        "unclassified"
    );
    assert_eq!(historical["lifecycle_interpretation"]["raw"], "bespoke");
    assert_eq!(
        historical["lifecycle_interpretation"]["reason"],
        "unknown_or_inactive_value"
    );
    assert!(rebuild_and_diff(&db).await.unwrap().equal);
}

#[test]
fn resolve_suggestions_description_explains_authoring_recipe() {
    let registry = registry();
    let description = &registry.get("resolve_suggestions").unwrap().description;
    for phrase in [
        "ordinary create_record",
        "type Annotation",
        "kind suggestion",
        "exactly one outgoing part_of link",
        "links: [{ target_id:",
        "target_id",
        "relationship: \"part_of\"",
        "lifecycle open",
        "replacement text",
        "proposal.precondition",
        "anchor.old",
        "anchor.base_digest",
    ] {
        assert!(
            description.contains(phrase),
            "missing {phrase:?}: {description}"
        );
    }
}

#[test]
fn lifecycle_tool_descriptions_explain_comment_authoring_discovery_and_resolution() {
    let registry = registry();
    let create = &registry.get("create_record").unwrap().description;
    for phrase in [
        "type Annotation",
        "kind comment",
        "nonblank body",
        "exactly one outgoing part_of link",
        "reply bears directly on the root comment",
        "canonical UTF-8 data_position",
        "Replies stay targetless",
    ] {
        assert!(create.contains(phrase), "missing {phrase:?}: {create}");
    }
    let get = &registry.get("get_record").unwrap().description;
    for phrase in [
        "full ids or short record references",
        "comment_count",
        "include_comments",
        "comments_offset",
        "exact anchored passage",
    ] {
        assert!(get.contains(phrase), "missing {phrase:?}: {get}");
    }
    let ids = registry.get("get_record").unwrap().input_schema["properties"]["ids"]["description"]
        .as_str()
        .unwrap();
    for phrase in ["short record references", "search.query", "unknown text"] {
        assert!(ids.contains(phrase), "missing {phrase:?}: {ids}");
    }
    let update = &registry.get("update_record").unwrap().description;
    for phrase in [
        "lifecycle:\"resolved\"",
        "nonblank summary",
        "open -> resolved",
    ] {
        assert!(update.contains(phrase), "missing {phrase:?}: {update}");
    }
    let start = &registry.get("start_work").unwrap().description;
    assert!(start.contains("direct open comment roots"), "{start}");
}

#[tokio::test]
async fn supported_writes_require_one_active_glossary_term() {
    let db = db().await;
    let registry = registry();

    let err = call_err(
        &registry,
        &db,
        "create_record",
        json!({ "id": MISSING_TERM, "type": "Document", "kind": "definition" }),
    )
    .await;
    assert!(err.contains("missing required facet 'term'"), "{err}");

    propose_value(&db, "glossary", "artifact", None)
        .await
        .unwrap();
    let err = call_err(
        &registry,
        &db,
        "create_record",
        json!({
            "id": PROPOSED_TERM,
            "type": "Document",
            "kind": "definition",
            "facets": { "term": "artifact" }
        }),
    )
    .await;
    assert!(err.contains("not an active member"), "{err}");

    promote_value(&db, "vv:voc:glossary:artifact")
        .await
        .unwrap();
    call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": VALID_TERM,
            "type": "Document",
            "kind": "definition",
            "maturity": "decided",
            "facets": { "term": "artifact" }
        }),
    )
    .await;
    let stored_ref: String = sqlx::query_scalar(
        "SELECT vocab_ref FROM facet_values WHERE record_id = ? AND key = 'term'",
    )
    .bind(VALID_TERM)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(stored_ref, "rec:voc:glossary");

    let err = call_err(
        &registry,
        &db,
        "update_record",
        json!({ "id": VALID_TERM, "facets": { "term": null } }),
    )
    .await;
    assert!(err.contains("missing required facet 'term'"), "{err}");
}

#[tokio::test]
async fn current_uniqueness_allows_drafts_history_and_different_terms() {
    let db = db().await;
    let registry = registry();
    active_term(&db, "artifact").await;
    active_term(&db, "widget").await;
    raw_definition(&db, ARTIFACT_CURRENT, "artifact", "decided").await;
    raw_definition(&db, ARTIFACT_DRAFT_A, "artifact", "candidate").await;
    raw_definition(&db, ARTIFACT_DRAFT_B, "artifact", "proposed").await;
    raw_definition(&db, ARTIFACT_OLD, "artifact", "superseded").await;
    raw_definition(&db, WIDGET_CURRENT, "widget", "decided").await;

    let err = call_err(
        &registry,
        &db,
        "create_record",
        json!({
            "id": TOOL_DUPLICATE,
            "type": "Document",
            "kind": "definition",
            "maturity": "decided",
            "facets": { "term": "artifact" }
        }),
    )
    .await;
    assert!(err.contains(ARTIFACT_CURRENT), "{err}");
    for table in ["records", "facet_values", "content_events"] {
        let count: i64 = sqlx::query_scalar(&format!(
            "SELECT COUNT(*) FROM {table} WHERE {} = ?",
            if table == "records" {
                "id"
            } else {
                "record_id"
            }
        ))
        .bind(TOOL_DUPLICATE)
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(count, 0, "failed tool create left a row in {table}");
    }

    let before_events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    create_record(
        &db,
        json!({
            "id": DUPLICATE,
            "type": "Document",
            "kind": "definition",
            "maturity": "decided"
        }),
    )
    .await
    .unwrap();
    let err = append(
        &db,
        AppendSpec {
            record_id: DUPLICATE.into(),
            event_type: "facet.set".into(),
            payload: json!({
                "key": "term",
                "value": "artifact",
                "vocab_ref": "rec:voc:glossary"
            }),
            actor: None,
        },
    )
    .await
    .expect_err("duplicate current term")
    .to_string();
    assert!(err.contains("artifact"), "{err}");
    assert!(err.contains(ARTIFACT_CURRENT), "{err}");
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        before_events + 1,
        "only the preceding record.created exists; the rejected facet event is atomic"
    );
    assert_eq!(current_count(&db, "artifact").await, 1);
    assert_eq!(current_count(&db, "widget").await, 1);
    assert!(rebuild_and_diff(&db).await.unwrap().equal);
}

#[tokio::test]
async fn every_transition_into_the_current_set_revalidates() {
    let db = db().await;
    active_term(&db, "artifact").await;
    active_term(&db, "widget").await;
    raw_definition(&db, EXISTING, "artifact", "decided").await;

    raw_definition(&db, DRAFT, "artifact", "proposed").await;
    let err = set_facet(
        &db,
        DRAFT,
        FacetSetPayload {
            key: "maturity".into(),
            value: Some("decided".into()),
            vocab_ref: None,
            as_of: None,
            observation_only: false,
        },
    )
    .await
    .expect_err("promotion conflict")
    .to_string();
    assert!(err.contains(EXISTING), "{err}");

    create_record(
        &db,
        json!({ "id": KIND_FLIP, "type": "Document", "kind": "note", "maturity": "decided" }),
    )
    .await
    .unwrap();
    set_facet(
        &db,
        KIND_FLIP,
        FacetSetPayload {
            key: "term".into(),
            value: Some("artifact".into()),
            vocab_ref: Some("voc:glossary".into()),
            as_of: None,
            observation_only: false,
        },
    )
    .await
    .unwrap();
    let err = update_record(&db, KIND_FLIP, json!({ "kind": "definition" }))
        .await
        .expect_err("kind conflict")
        .to_string();
    assert!(err.contains(EXISTING), "{err}");

    raw_definition(&db, TERM_CHANGE, "widget", "decided").await;
    let err = set_facet(
        &db,
        TERM_CHANGE,
        FacetSetPayload {
            key: "term".into(),
            value: Some("artifact".into()),
            vocab_ref: Some("rec:voc:glossary".into()),
            as_of: None,
            observation_only: false,
        },
    )
    .await
    .expect_err("term conflict")
    .to_string();
    assert!(err.contains(EXISTING), "{err}");

    archive_record(&db, EXISTING).await.unwrap();
    set_facet(
        &db,
        DRAFT,
        FacetSetPayload {
            key: "maturity".into(),
            value: Some("decided".into()),
            vocab_ref: None,
            as_of: None,
            observation_only: false,
        },
    )
    .await
    .unwrap();
    let err = restore_record(&db, EXISTING)
        .await
        .expect_err("restore conflict")
        .to_string();
    assert!(err.contains(DRAFT), "{err}");

    delete_record(&db, DRAFT).await.unwrap();
    restore_record(&db, EXISTING).await.unwrap();
    assert_eq!(current_count(&db, "artifact").await, 1);
    assert!(rebuild_and_diff(&db).await.unwrap().equal);
}

#[tokio::test]
async fn aliases_are_resolved_for_lookup_and_protected_for_current_definitions() {
    let db = db().await;
    let registry = registry();
    let artifact = active_term(&db, "artifact").await;
    let artefact = active_term(&db, "artefact").await;
    alias_value(&db, &artefact, &artifact).await.unwrap();
    raw_definition(&db, DEFINITION_ARTIFACT, "artifact", "decided").await;

    let listed = list_values(
        &db,
        "glossary",
        ListValuesOptions {
            status: None,
            resolve_aliases: true,
        },
    )
    .await
    .unwrap();
    let resolved = listed
        .iter()
        .find(|value| value.row.value == "artefact")
        .unwrap()
        .canonical
        .as_ref()
        .unwrap()
        .value
        .clone();
    assert_eq!(resolved, "artifact");

    let queried = call(
        &registry,
        &db,
        "query_record",
        json!({ "steps": [{
            "step": "filter",
            "types": ["Document"],
            "kinds": ["definition"],
            "maturity": ["decided"],
            "facets": [{ "key": "term", "eq": resolved }]
        }] }),
    )
    .await;
    assert_eq!(queried["total"], 1);
    assert_eq!(queried["records"][0]["id"], DEFINITION_ARTIFACT);

    let resolved_facets = call(
        &registry,
        &db,
        "resolve_facets",
        json!({ "record_id": DEFINITION_ARTIFACT }),
    )
    .await;
    assert_eq!(resolved_facets["shape"]["term"]["vocab_ref"], "glossary");
    assert_eq!(resolved_facets["values"][0]["key"], "term");
    assert_eq!(
        resolved_facets["values"][0]["vocab_ref"],
        "rec:voc:glossary"
    );

    let widget = active_term(&db, "widget").await;
    raw_definition(&db, DEFINITION_WIDGET, "widget", "decided").await;
    let definition_alias = native_ce::meta::propose_value_with_kind_metadata_as(
        &db,
        "kind:Document",
        "glossary_definition",
        None,
        0.0,
        native_ce::meta::VocabularyValueTerminality::Open,
        Some(native_ce::meta::KindMetadataV1::legacy(
            "Document",
            "glossary_definition",
        )),
        None,
    )
    .await
    .unwrap();
    native_ce::meta::promote_value(&db, &definition_alias)
        .await
        .unwrap();
    alias_value(
        &db,
        &definition_alias,
        CoreKind::DocumentDefinition.value_id(),
    )
    .await
    .unwrap();
    // Model a historical/imported row retaining the alias spelling.
    sqlx::query("UPDATE records SET kind = 'glossary_definition' WHERE id = ?")
        .bind(DEFINITION_WIDGET)
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    let before_meta: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM meta_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let err = alias_value(&db, &widget, &artifact)
        .await
        .expect_err("defined source")
        .to_string();
    assert!(err.contains(DEFINITION_WIDGET), "{err}");
    assert!(err.contains("retarget or supersede"), "{err}");
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM meta_events")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        before_meta
    );
}

#[tokio::test]
async fn aliasing_cannot_merge_legacy_definition_identities() {
    let db = db().await;
    let target = active_term(&db, "target").await;
    let source = active_term(&db, "source").await;
    let old_spelling = active_term(&db, "old-spelling").await;
    alias_value(&db, &old_spelling, &source).await.unwrap();
    raw_definition(&db, SOURCE_VIA_ALIAS, "old-spelling", "decided").await;
    raw_definition(&db, TARGET_DEFINITION, "target", "decided").await;

    let err = alias_value(&db, &source, &target)
        .await
        .expect_err("canonical collision")
        .to_string();
    assert!(err.contains("multiple current agreed definitions"), "{err}");
    assert!(err.contains(SOURCE_VIA_ALIAS), "{err}");
    assert!(err.contains(TARGET_DEFINITION), "{err}");
}

#[tokio::test]
async fn unrelated_legacy_duplicate_does_not_block_a_safe_alias() {
    let db = db().await;
    let legacy_canonical = active_term(&db, "legacy-canonical").await;
    let legacy_alias = active_term(&db, "legacy-alias").await;
    alias_value(&db, &legacy_alias, &legacy_canonical)
        .await
        .unwrap();
    raw_definition(&db, LEGACY_ONE, "legacy-canonical", "proposed").await;
    raw_definition(&db, LEGACY_TWO, "legacy-alias", "proposed").await;
    // Model a malformed pre-guard/imported projection: both records occupy one
    // unrelated canonical identity. The alias under test must judge only the
    // identity it changes, not turn unrelated corruption into a global lock.
    sqlx::query(
        "UPDATE records SET maturity = 'decided'
          WHERE id IN (?, ?)",
    )
    .bind(LEGACY_ONE)
    .bind(LEGACY_TWO)
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();

    let safe_target = active_term(&db, "safe-target").await;
    let safe_source = active_term(&db, "safe-source").await;
    alias_value(&db, &safe_source, &safe_target).await.unwrap();
    let alias_of: String =
        sqlx::query_scalar("SELECT alias_of FROM vocabulary_values WHERE id = ?")
            .bind(&safe_source)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(alias_of, safe_target);
}

#[tokio::test]
async fn concurrent_raw_promotions_have_one_atomic_winner() {
    let db = db().await;
    active_term(&db, "artifact").await;
    raw_definition(&db, CANDIDATE_A, "artifact", "proposed").await;
    raw_definition(&db, CANDIDATE_B, "artifact", "proposed").await;

    let promote = |db: Db, id: &'static str| async move {
        set_facet(
            &db,
            id,
            FacetSetPayload {
                key: "maturity".into(),
                value: Some("decided".into()),
                vocab_ref: None,
                as_of: None,
                observation_only: false,
            },
        )
        .await
    };
    let (a, b) = tokio::join!(
        promote(db.clone(), CANDIDATE_A),
        promote(db.clone(), CANDIDATE_B)
    );
    assert_ne!(
        a.is_ok(),
        b.is_ok(),
        "exactly one promotion must win: {a:?} {b:?}"
    );
    assert_eq!(current_count(&db, "artifact").await, 1);
    let decided_events: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM content_events
          WHERE type = 'facet.set'
            AND json_extract(payload, '$.key') = 'maturity'
            AND json_extract(payload, '$.value') = 'decided'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(decided_events, 1, "the loser must leave no event behind");
    assert!(rebuild_and_diff(&db).await.unwrap().equal);
}
