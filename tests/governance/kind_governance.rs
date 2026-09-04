use native_ce::conformance::rebuild_and_diff_meta;
use native_ce::events::FacetSetPayload;
use native_ce::generated::kinds::{
    CoreKind, CORE_KIND_MANIFEST_DIGEST, CORE_KIND_MANIFEST_SCHEMA_VERSION,
};
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::meta::kind::{
    core_kind_manifest, core_kind_manifest_digest, KindClassification, KindDedupMode,
    KindMetadataV1,
};
use native_ce::meta::{
    alias_value, create_vocabulary, delete_value, deprecate_value, promote_value,
    propose_value_with_kind_metadata_as, seed_vocabularies, set_value_metadata_as,
    VocabularyValueTerminality,
};
use native_ce::store::{create_record, set_facet};
use native_ce::{apply_schema, create_database, open_database, open_existing_database_at, Db};
use serde_json::{json, Value};
use sqlx::Row;

/// Fixture record ids. Record ids must be canonical lowercase UUIDs, so the
/// readable name lives in the constant. All pinned literals, never generated.
const ATTACHMENT_WRITE_BEARER: &str = "c0de0000-0000-4000-8000-000000000001";
const ALIAS_WRITE: &str = "c0de0000-0000-4000-8000-000000000002";
const UNKNOWN_WRITE: &str = "c0de0000-0000-4000-8000-000000000003";
const QUARANTINED_ALIAS_CREATE: &str = "c0de0000-0000-4000-8000-000000000004";
const WRONG_SIBLING: &str = "c0de0000-0000-4000-8000-000000000005";
const UNKNOWN_KIND: &str = "c0de0000-0000-4000-8000-000000000006";
const PROPOSED_KIND: &str = "c0de0000-0000-4000-8000-000000000007";
const DEPRECATED_KIND: &str = "c0de0000-0000-4000-8000-000000000008";
const LEGACY_ALIAS: &str = "c0de0000-0000-4000-8000-000000000009";
const CANONICAL_TASK: &str = "c0de0000-0000-4000-8000-00000000000a";
const ALIAS_TASK: &str = "c0de0000-0000-4000-8000-00000000000b";
const DELETED_REVIEW: &str = "c0de0000-0000-4000-8000-00000000000c";
const ALIAS_REVIEW: &str = "c0de0000-0000-4000-8000-00000000000d";
const HANDOFF_WRITE: &str = "c0de0000-0000-4000-8000-00000000000e";
const INVENTED_HANDOFF: &str = "c0de0000-0000-4000-8000-00000000000f";
const MISFILED_DECISION: &str = "c0de0000-0000-4000-8000-000000000010";
const UNGOVERNED_DOCUMENT: &str = "c0de0000-0000-4000-8000-000000000011";

const HANDOFF_PROVENANCE: &str = "rec:e4a92a9";
const HANDOFF_GLOSS: &str = "Session-continuity briefing for a later inhabitant.";
const STALE_HANDOFF_GLOSS: &str = "Provisional handoff label";

async fn db() -> Db {
    let db = create_database(":memory:").await.unwrap();
    seed_vocabularies(&db).await.unwrap();
    db
}

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

async fn call(
    registry: &ToolRegistry,
    db: &Db,
    tool: &str,
    args: Value,
) -> native_ce::Result<Value> {
    registry.call(db.clone(), Caller::local(), tool, args).await
}

async fn install_kind(db: &Db, record_type: &str, token: &str, promote: bool) -> String {
    let id = propose_value_with_kind_metadata_as(
        db,
        &format!("kind:{record_type}"),
        token,
        None,
        0.0,
        VocabularyValueTerminality::Open,
        Some(KindMetadataV1::legacy(record_type, token)),
        None,
    )
    .await
    .unwrap();
    if promote {
        promote_value(db, &id).await.unwrap();
    }
    id
}

#[tokio::test]
async fn unknown_kind_warning_names_other_governed_types_and_preserves_the_fallback() {
    let db = db().await;
    let registry = registry();

    let misfiled = call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": MISFILED_DECISION,
            "type": "Document",
            "kind": "decision",
            "name": "Misfiled decision",
            "reason": "Exercise a governed kind paired with the wrong spine type."
        }),
    )
    .await
    .unwrap();
    assert_eq!(misfiled["kind_governance"]["classification"], "unknown");
    assert_eq!(misfiled["kind_governance"]["quarantined"], true);
    let warning = misfiled["kind_governance"]["warning"].as_str().unwrap();
    assert!(warning.contains("not governed by kind:Document"));
    assert!(warning.contains("governed under type Resolution (kind:Resolution)"));
    assert!(warning.contains("did you mean that type?"));
    assert!(warning.contains("stored for interoperability but quarantined"));

    install_kind(&db, "Entity", "decision", true).await;
    let multiple = native_ce::meta::kind::resolve(&db, "Document", "decision")
        .await
        .unwrap();
    assert_eq!(
        multiple.warning.as_deref(),
        Some(
            "kind 'decision' is not governed by kind:Document. It is governed under multiple types: Entity (kind:Entity), Resolution (kind:Resolution); choose the intended type. The record was stored for interoperability but quarantined from governed dispatch"
        )
    );

    let canonical = install_kind(&db, "Program", "judgment", true).await;
    let alias = install_kind(&db, "Program", "verdict", true).await;
    alias_value(&db, &alias, &canonical).await.unwrap();
    let aliased = native_ce::meta::kind::resolve(&db, "Document", "verdict")
        .await
        .unwrap();
    assert!(aliased
        .warning
        .as_deref()
        .unwrap()
        .contains("governed under type Program (kind:Program)"));

    deprecate_value(&db, &canonical).await.unwrap();
    let retired_alias = native_ce::meta::kind::resolve(&db, "Document", "verdict")
        .await
        .unwrap();
    assert_eq!(
        retired_alias.warning.as_deref(),
        Some(
            "kind 'verdict' is not governed by kind:Document; stored for interoperability but quarantined from governed dispatch"
        )
    );

    let ungoverned = call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": UNGOVERNED_DOCUMENT,
            "type": "Document",
            "kind": "x-unknown-kind",
            "name": "Ungoverned document",
            "reason": "Exercise the fallback for a token governed by no spine type."
        }),
    )
    .await
    .unwrap();
    let fallback = ungoverned["kind_governance"]["warning"].as_str().unwrap();
    assert_eq!(
        fallback,
        "kind 'x-unknown-kind' is not governed by kind:Document; stored for interoperability but quarantined from governed dispatch"
    );
}

#[tokio::test]
async fn core_manifest_generated_artifacts_and_pristine_registry_conform() {
    let db = db().await;
    let manifest = core_kind_manifest().unwrap();
    assert_eq!(CORE_KIND_MANIFEST_SCHEMA_VERSION, manifest.schema_version);
    assert_eq!(CORE_KIND_MANIFEST_DIGEST, core_kind_manifest_digest());
    assert_eq!(CoreKind::MessageText.record_type(), "Message");
    assert_eq!(CoreKind::MessageText.token(), "text");
    assert_eq!(CoreKind::MessageText.value_id(), "vv:voc:kind:Message:text");
    assert_eq!(CoreKind::ProgramModule.record_type(), "Program");
    assert_eq!(
        CoreKind::ProgramModule.value_id(),
        "vv:voc:kind:Document:module"
    );
    assert_eq!(CoreKind::ProgramRecipe.token(), "recipe");
    assert!(manifest
        .kinds
        .iter()
        .any(|kind| kind.record_type == "Message" && kind.token == "text"));
    assert!(!manifest
        .kinds
        .iter()
        .any(|kind| kind.record_type == "Message" && kind.token == "note"));

    let mut seeded = Vec::new();
    for record_type in native_ce::schema::SPINE_TYPES {
        for kind in native_ce::meta::kind::list_active(&db, record_type)
            .await
            .unwrap()
        {
            seeded.push((
                kind.record_type,
                kind.token,
                kind.value_id,
                serde_json::to_value(kind.metadata).unwrap(),
            ));
        }
    }
    let mut expected: Vec<_> = manifest
        .kinds
        .iter()
        .map(|kind| {
            (
                kind.record_type.clone(),
                kind.token.clone(),
                kind.value_id.clone(),
                serde_json::to_value(&kind.metadata).unwrap(),
            )
        })
        .collect();
    seeded.sort_by(|left, right| (&left.0, &left.1).cmp(&(&right.0, &right.1)));
    expected.sort_by(|left, right| (&left.0, &left.1).cmp(&(&right.0, &right.1)));
    assert_eq!(seeded, expected);

    let ts = std::fs::read_to_string(format!(
        "{}/web/generated/kinds.ts",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    assert!(ts.contains(CORE_KIND_MANIFEST_DIGEST));
    assert!(ts.contains("MessageText"));
    let retired_message_variant = ["Message", "Note"].concat();
    assert!(!ts.contains(&retired_message_variant));
    for kind in &manifest.kinds {
        assert!(ts.contains(&kind.value_id));
    }
    assert!(rebuild_and_diff_meta(&db).await.unwrap().equal);
}

#[tokio::test]
async fn reconciled_core_kinds_resolve_and_project_from_governed_registry() {
    let db = db().await;
    let registry = registry();
    let cases = [
        (
            "Collection",
            "query",
            "rec:c362d12",
            "A collection whose membership is computed live from its stored, versioned query over existing records.",
            "Continuity of the same stored query that intensionally defines membership; replacing the query establishes a different collection.",
            KindDedupMode::RecordId,
        ),
        (
            "Document",
            "note",
            "rec:761ffae",
            "An ordinary authored prose or capture document.",
            "Each note record is a distinct document; matching titles or content do not establish identity.",
            KindDedupMode::RecordId,
        ),
        (
            "Document",
            "handoff",
            HANDOFF_PROVENANCE,
            "An authored session-continuity briefing whose body states live position, boundaries, and working instructions for a later inhabitant.",
            "Each handoff record is a distinct session-continuity briefing; matching titles or content do not establish identity.",
            KindDedupMode::RecordId,
        ),
        (
            "Document",
            "slides",
            "rec:761ffae",
            "A document whose content is organized as a presentation or slide deck.",
            "Each slides record is a distinct document; matching titles or content do not establish identity.",
            KindDedupMode::RecordId,
        ),
        (
            "Entity",
            "person",
            "rec:761ffae",
            "A human individual represented as an enduring referent.",
            "Continuity of the same human individual across changes of name, employment, account or contact details.",
            KindDedupMode::ExternalBinding,
        ),
        (
            "Entity",
            "organization",
            "rec:761ffae",
            "An organized institution or legal body represented as an enduring referent.",
            "Continuity of the same organized body across changes of name, branding, domain or representation.",
            KindDedupMode::ExternalBinding,
        ),
        (
            "Conversation",
            "discussion",
            "rec:761ffae",
            "A continuing authored exchange classified by its messages and distinct from any Message reply chain.",
            "Continuity of the same authored exchange across its classified messages; classification does not make member content referentially dependent or grant access.",
            KindDedupMode::ExternalBinding,
        ),
        (
            "Conversation",
            "transcript",
            "rec:761ffae",
            "A bounded capture of one exchange whose sequence or utterances may be addressed, cited or acted upon.",
            "Continuity of the same meeting, session or exchange occurrence across exports or representations.",
            KindDedupMode::ExternalBinding,
        ),
        (
            "WorkItem",
            "task",
            "rec:40384f2",
            "An ordinary work item whose completion directly discharges the commitment it records.",
            "Each task record is a distinct commitment to work; matching titles, descriptions or placement do not establish identity.",
            KindDedupMode::RecordId,
        ),
        (
            "WorkItem",
            "epic",
            "rec:40384f2",
            "A work item whose achievement is entailed by completion of its constituent child work.",
            "Each epic record is a distinct commitment to a whole body of work discharged by its parts; magnitude, titles or placement do not establish identity.",
            KindDedupMode::RecordId,
        ),
        (
            "Outcome",
            "impact",
            "rec:f8db3a5",
            "One claimed realised effect for a particular subject and effective period, represented by the governed atomic impact facet.",
            "Each impact record denotes one claimed realised effect for one effective occurrence or period; corrections to the same claim preserve record identity.",
            KindDedupMode::RecordId,
        ),
        (
            "Outcome",
            "milestone",
            "rec:3b8a090",
            "An outcome intended to become true once and remain durably true thereafter.",
            "Each milestone record denotes one desired durable achievement; matching measures, dates or wording do not establish identity.",
            KindDedupMode::RecordId,
        ),
        (
            "Outcome",
            "target",
            "rec:3b8a090",
            "An outcome intended to be true at a specified observation time.",
            "Each target record denotes one desired time-bound state; matching measures, dates or wording do not establish identity.",
            KindDedupMode::RecordId,
        ),
        (
            "Message",
            "text",
            "rec:f297950",
            "An addressed Message whose canonical semantic payload conforms to the plain textual-body contract. Channel and physical media are represented separately; richer Message kinds identify additional semantic payload schemas.",
            "Each text message is a distinct message occurrence; matching payloads or subjects do not establish identity.",
            KindDedupMode::RecordId,
        ),
        (
            "Resolution",
            "decision",
            "rec:c850e0f",
            "An authorised settled choice or commitment among live alternatives.",
            "Continuity of the same authorised choice or commitment across rewrites of its documentation; withdrawal occurs through supersession, revocation or rescission.",
            KindDedupMode::RecordId,
        ),
        (
            "Resolution",
            "rule",
            "rec:c850e0f",
            "An instituted norm that governs conduct because an authorised actor or process laid it down.",
            "Continuity of the same instituted norm across rewrites of its documentation; withdrawal occurs through supersession, repeal, revocation or rescission.",
            KindDedupMode::RecordId,
        ),
    ];

    let described = call(
        &registry,
        &db,
        "describe_schema",
        json!({ "include_ddl": false }),
    )
    .await
    .unwrap();

    for record_type in native_ce::schema::SPINE_TYPES {
        let active = native_ce::meta::kind::list_active(&db, record_type)
            .await
            .unwrap();
        assert!(
            !active.is_empty(),
            "pristine list_active has no governed kind for {record_type}"
        );
        assert!(
            !described["kind_registry"][record_type]
                .as_array()
                .unwrap()
                .is_empty(),
            "pristine describe_schema has no governed kind for {record_type}"
        );
        assert!(
            !described["resolved_schema_config"]["shapes"][record_type]["kinds"]
                .as_array()
                .unwrap()
                .is_empty(),
            "pristine resolved schema has no governed kind for {record_type}"
        );
    }

    for (record_type, expected) in [
        ("Collection", vec!["folder", "query", "selection"]),
        ("WorkItem", vec!["epic", "task"]),
        ("Outcome", vec!["impact", "milestone", "target"]),
        ("Message", vec!["text"]),
        ("Resolution", vec!["decision", "rule"]),
    ] {
        let tokens: Vec<_> = native_ce::meta::kind::list_active(&db, record_type)
            .await
            .unwrap()
            .into_iter()
            .map(|kind| kind.token)
            .collect();
        assert_eq!(
            tokens, expected,
            "unexpected governed set for {record_type}"
        );
    }

    assert!(
        described["resolved_schema_config"]["shapes"]["Collection"]["kinds"]
            .as_array()
            .unwrap()
            .iter()
            .all(|kind| kind != "view")
    );

    for (record_type, token, provenance, definition, criterion, dedup_mode) in cases {
        let resolution = native_ce::meta::kind::resolve(&db, record_type, token)
            .await
            .unwrap();
        assert_eq!(
            resolution.classification,
            KindClassification::ActiveCanonical
        );
        assert!(!resolution.quarantined);
        let expected_value_id = format!("vv:voc:kind:{record_type}:{token}");
        assert_eq!(
            resolution.canonical_value_id.as_deref(),
            Some(expected_value_id.as_str())
        );
        let metadata = resolution.metadata.unwrap();
        assert_eq!(metadata.provenance_ref, provenance);
        assert_eq!(metadata.definition, definition);
        assert_eq!(metadata.identity.criterion, criterion);
        assert_eq!(metadata.identity.dedup.mode, dedup_mode);
        assert!(metadata.identity.dedup.keys.is_empty());

        assert!(
            described["resolved_schema_config"]["shapes"][record_type]["kinds"]
                .as_array()
                .unwrap()
                .iter()
                .any(|kind| kind == token)
        );
    }
}

#[tokio::test]
async fn deprecated_core_kind_survives_reopen_without_reactivation_or_seed_writes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("deprecated-core-kind.db");
    let db = create_database(&path.to_string_lossy()).await.unwrap();
    deprecate_value(&db, CoreKind::DocumentAttachment.value_id())
        .await
        .unwrap();
    let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM meta_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    db.close().await;

    let reopened = open_existing_database_at(&path).await.unwrap();
    let status: String = sqlx::query_scalar("SELECT status FROM vocabulary_values WHERE id=?")
        .bind(CoreKind::DocumentAttachment.value_id())
        .fetch_one(reopened.pool())
        .await
        .unwrap();
    assert_eq!(status, "deprecated");
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM meta_events")
            .fetch_one(reopened.pool())
            .await
            .unwrap(),
        events_before,
        "reopen seeding must neither reactivate nor rewrite a deprecated core kind"
    );
    let resolution = native_ce::meta::kind::resolve(&reopened, "Document", "attachment")
        .await
        .unwrap();
    assert_eq!(
        resolution.classification,
        KindClassification::DeprecatedNonAlias
    );
    assert!(resolution.quarantined);
    reopened.close().await;
}

#[tokio::test]
async fn core_seed_still_rejects_malformed_metadata_and_aliased_core_identities() {
    for malformed in ["metadata", "alias"] {
        let db = db().await;
        match malformed {
            "metadata" => {
                sqlx::query("UPDATE vocabulary_values SET metadata='{}' WHERE id=?")
                    .bind(CoreKind::DocumentAttachment.value_id())
                    .execute(&crate::common::fixture_write_pool(&db).await)
                    .await
                    .unwrap();
            }
            "alias" => {
                sqlx::query(
                    "UPDATE vocabulary_values
                        SET status='deprecated', alias_of=?
                      WHERE id=?",
                )
                .bind(CoreKind::DocumentNote.value_id())
                .bind(CoreKind::DocumentAttachment.value_id())
                .execute(&crate::common::fixture_write_pool(&db).await)
                .await
                .unwrap();
            }
            _ => unreachable!(),
        }
        let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM meta_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let error = seed_vocabularies(&db).await.unwrap_err().to_string();
        assert!(
            error.contains("core kind identity/payload conflict for Document:attachment"),
            "{malformed}: {error}"
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM meta_events")
                .fetch_one(db.pool())
                .await
                .unwrap(),
            events_before,
            "{malformed}: a rejected seed must append no events"
        );
        db.close().await;
    }
}

#[tokio::test]
async fn core_seed_conflict_commits_no_partial_kind_registry() {
    // This test deliberately installs a conflicting identity before the first
    // seed, so stand up only the DDL rather than the normal seeded database.
    let db = open_database(":memory:").await.unwrap();
    apply_schema(&db).await.unwrap();
    create_vocabulary(
        &db,
        "kind:WorkItem",
        Some("extension-owned-work-item-kinds"),
    )
    .await
    .unwrap();
    let error = seed_vocabularies(&db).await.unwrap_err().to_string();
    assert!(
        error.contains("core kind vocabulary identity conflict"),
        "{error}"
    );
    let kind_vocabularies: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM vocabularies WHERE name LIKE 'kind:%'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(kind_vocabularies, 1);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM vocabulary_values WHERE vocabulary_id LIKE 'voc:kind:%'",
        )
        .fetch_one(db.pool())
        .await
        .unwrap(),
        0
    );
}

#[tokio::test]
async fn write_table_canonicalises_aliases_and_quarantines_open_values() {
    let db = db().await;
    let registry = registry();
    let alias = install_kind(&db, "Document", "file", true).await;
    alias_value(&db, &alias, CoreKind::DocumentAttachment.value_id())
        .await
        .unwrap();
    let proposed = install_kind(&db, "Document", "draft_format", false).await;
    let deprecated = install_kind(&db, "Document", "retired_format", true).await;
    deprecate_value(&db, &deprecated).await.unwrap();

    let alias_resolution = native_ce::meta::kind::resolve(&db, "Document", "file")
        .await
        .unwrap();
    assert_eq!(
        alias_resolution.classification,
        KindClassification::DeprecatedAlias
    );
    assert!(!alias_resolution.quarantined);
    assert!(CoreKind::DocumentAttachment.matches(&alias_resolution));

    for (token, classification) in [
        ("draft_format", KindClassification::Proposed),
        ("retired_format", KindClassification::DeprecatedNonAlias),
        ("foreign_format", KindClassification::Unknown),
    ] {
        let resolution = native_ce::meta::kind::resolve(&db, "Document", token)
            .await
            .unwrap();
        assert_eq!(resolution.classification, classification);
        assert!(resolution.quarantined);
    }

    let attachment_bearer = create_record(
        &db,
        json!({
            "id": ATTACHMENT_WRITE_BEARER,
            "type": "WorkItem",
            "kind": "task",
            "name": "Attachment write target"
        }),
    )
    .await
    .unwrap();

    let created = call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": ALIAS_WRITE,
            "type": "Document",
            "kind": "file",
            "name": "Alias write",
            "links": [{ "target_id": attachment_bearer, "relationship": "part_of" }],
            "reason": "Exercise canonical kind storage."
        }),
    )
    .await
    .unwrap();
    assert_eq!(created["kind"], "attachment");
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT kind FROM records WHERE id = ?")
            .bind(ALIAS_WRITE)
            .fetch_one(db.pool())
            .await
            .unwrap(),
        "attachment"
    );

    let unknown = call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": UNKNOWN_WRITE,
            "type": "Document",
            "kind": "foreign_format",
            "name": "Foreign",
            "links": [{ "target_id": attachment_bearer, "relationship": "part_of" }],
            "reason": "Preserve open interoperable data."
        }),
    )
    .await
    .unwrap();
    assert_eq!(unknown["kind"], "foreign_format");
    assert_eq!(unknown["kind_governance"]["quarantined"], true);
    assert!(unknown["kind_governance"]["warning"]
        .as_str()
        .unwrap()
        .contains("quarantined"));

    call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": UNKNOWN_WRITE,
            "kind": "file",
            "reason": "Canonicalise an alias on update."
        }),
    )
    .await
    .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT kind FROM records WHERE id = ?")
            .bind(UNKNOWN_WRITE)
            .fetch_one(db.pool())
            .await
            .unwrap(),
        "attachment"
    );

    deprecate_value(&db, CoreKind::DocumentAttachment.value_id())
        .await
        .unwrap();
    let quarantined_alias = native_ce::meta::kind::resolve(&db, "Document", "file")
        .await
        .unwrap();
    assert!(quarantined_alias.quarantined);
    assert_eq!(
        quarantined_alias.canonical_kind.as_deref(),
        Some("attachment")
    );
    assert_eq!(quarantined_alias.canonical_kind_for_write(), None);

    let created_after_target_deprecation = call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": QUARANTINED_ALIAS_CREATE,
            "type": "Document",
            "kind": "file",
            "name": "Historical alias",
            "reason": "Preserve an alias whose target left service."
        }),
    )
    .await
    .unwrap();
    assert_eq!(created_after_target_deprecation["kind"], "file");
    assert_eq!(
        created_after_target_deprecation["kind_governance"]["quarantined"],
        true
    );
    assert!(
        created_after_target_deprecation["kind_governance"]["warning"]
            .as_str()
            .unwrap()
            .contains("quarantined")
    );

    let updated_after_target_deprecation = call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": UNKNOWN_WRITE,
            "kind": "file",
            "reason": "Preserve the now-quarantined alias on update."
        }),
    )
    .await
    .unwrap();
    assert_eq!(updated_after_target_deprecation["kind"], "file");
    assert_eq!(
        updated_after_target_deprecation["kind_governance"]["quarantined"],
        true
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT kind FROM records WHERE id = ?")
            .bind(UNKNOWN_WRITE)
            .fetch_one(db.pool())
            .await
            .unwrap(),
        "file"
    );

    let _ = proposed;
}

#[tokio::test]
async fn wrong_sibling_and_quarantined_kinds_fail_before_dispatch_side_effects() {
    let db = db().await;
    let registry = registry();
    let sibling = install_kind(&db, "Document", "judgment", true).await;
    let alias = install_kind(&db, "Document", "file", true).await;
    alias_value(&db, &alias, CoreKind::DocumentAttachment.value_id())
        .await
        .unwrap();
    let proposed = install_kind(&db, "Document", "draft_format", false).await;
    let deprecated = install_kind(&db, "Document", "retired_format", true).await;
    deprecate_value(&db, &deprecated).await.unwrap();

    let root = create_record(
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Root" }),
    )
    .await
    .unwrap();
    let attachment = call(
        &registry,
        &db,
        "attach_text",
        json!({ "record_id": root, "text": "payload", "filename": "proof.txt" }),
    )
    .await
    .unwrap();
    let blob_id = attachment["blob"]["id"].as_str().unwrap().to_string();

    for (id, token) in [
        (WRONG_SIBLING, "judgment"),
        (UNKNOWN_KIND, "foreign_format"),
        (PROPOSED_KIND, "draft_format"),
        (DEPRECATED_KIND, "retired_format"),
    ] {
        create_record(
            &db,
            json!({ "id": id, "type": "Document", "kind": token, "name": token }),
        )
        .await
        .unwrap();
        set_facet(
            &db,
            id,
            FacetSetPayload {
                key: "blob_ref".into(),
                value: Some(blob_id.clone()),
                vocab_ref: None,
                as_of: None,
                observation_only: false,
            },
        )
        .await
        .unwrap();
    }
    create_record(
        &db,
        json!({ "id": LEGACY_ALIAS, "type": "Document", "kind": "file", "name": "alias" }),
    )
    .await
    .unwrap();
    set_facet(
        &db,
        LEGACY_ALIAS,
        FacetSetPayload {
            key: "blob_ref".into(),
            value: Some(blob_id.clone()),
            vocab_ref: None,
            as_of: None,
            observation_only: false,
        },
    )
    .await
    .unwrap();

    let before: (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM content_events),
                (SELECT COUNT(*) FROM meta_events),
                (SELECT COUNT(*) FROM blobs)",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    for id in [
        WRONG_SIBLING,
        UNKNOWN_KIND,
        PROPOSED_KIND,
        DEPRECATED_KIND,
        LEGACY_ALIAS,
    ] {
        let error = call(
            &registry,
            &db,
            "read_attachment",
            json!({ "attachment_id": id }),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("does not exist"), "{id}: {error}");
    }
    let after: (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM content_events),
                (SELECT COUNT(*) FROM meta_events),
                (SELECT COUNT(*) FROM blobs)",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(
        before, after,
        "dispatch validation must be side-effect free"
    );
    let _ = (sibling, proposed);
}

#[tokio::test]
async fn metadata_events_replay_bytes_and_schema_advertises_active_only() {
    let db = db().await;
    let registry = registry();
    let id = install_kind(&db, "WorkItem", "review", true).await;
    let mut metadata = KindMetadataV1::legacy("WorkItem", "review");
    metadata.definition = "A task whose governed purpose is review.".into();
    set_value_metadata_as(&db, &id, metadata.clone(), Some("test:actor"))
        .await
        .unwrap();
    let stored: String = sqlx::query("SELECT metadata FROM vocabulary_values WHERE id = ?")
        .bind(&id)
        .fetch_one(db.pool())
        .await
        .unwrap()
        .get("metadata");
    assert_eq!(stored, serde_json::to_string(&metadata).unwrap());
    assert!(rebuild_and_diff_meta(&db).await.unwrap().equal);

    let proposed = install_kind(&db, "WorkItem", "not_yet", false).await;
    let described = call(
        &registry,
        &db,
        "describe_schema",
        json!({ "include_ddl": false }),
    )
    .await
    .unwrap();
    assert_eq!(
        described["resolved_schema_config"]["shapes"]["WorkItem"]["kinds"],
        json!(["epic", "review", "task"])
    );
    let _ = proposed;
}

#[tokio::test]
async fn extension_reinstall_is_event_idempotent_and_deprecation_counts_alias_records() {
    let db = db().await;
    let registry = registry();
    let metadata = KindMetadataV1::legacy("WorkItem", "review");
    let value_id = install_kind(&db, "WorkItem", "review", true).await;
    let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM meta_events")
        .fetch_one(db.pool())
        .await
        .unwrap();

    let replay = call(
        &registry,
        &db,
        "manage_vocabularies",
        json!({
            "action": "propose_value",
            "vocabulary": "kind:WorkItem",
            "value": "review",
            "metadata": metadata,
        }),
    )
    .await
    .unwrap();
    assert_eq!(replay["status"], "active");
    call(
        &registry,
        &db,
        "manage_vocabularies",
        json!({ "action": "promote_value", "value_id": value_id }),
    )
    .await
    .unwrap();
    let events_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM meta_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(events_before, events_after);

    let alias_id = install_kind(&db, "WorkItem", "inspection", true).await;
    alias_value(&db, &alias_id, &value_id).await.unwrap();
    create_record(
        &db,
        json!({ "id": CANONICAL_TASK, "type": "WorkItem", "kind": "review" }),
    )
    .await
    .unwrap();
    create_record(
        &db,
        json!({ "id": ALIAS_TASK, "type": "WorkItem", "kind": "inspection" }),
    )
    .await
    .unwrap();
    let deprecated = call(
        &registry,
        &db,
        "manage_vocabularies",
        json!({ "action": "deprecate_value", "value_id": value_id }),
    )
    .await
    .unwrap();
    assert_eq!(deprecated["records_quarantined"], 2);
    let events_after_first: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM meta_events WHERE subject_id = ? AND type = 'vocab_value.deprecated'",
    )
    .bind(&value_id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let repeated = call(
        &registry,
        &db,
        "manage_vocabularies",
        json!({ "action": "deprecate_value", "value_id": value_id }),
    )
    .await
    .unwrap();
    assert_eq!(repeated["records_quarantined"], 0);
    let events_after_repeat: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM meta_events WHERE subject_id = ? AND type = 'vocab_value.deprecated'",
    )
    .bind(&value_id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(events_after_first, events_after_repeat);
}

#[tokio::test]
async fn kind_value_deletion_guards_raw_record_tokens_by_matching_type_including_tombstones() {
    let db = db().await;

    let canonical = install_kind(&db, "WorkItem", "review", true).await;
    create_record(
        &db,
        json!({ "id": DELETED_REVIEW, "type": "WorkItem", "kind": "review" }),
    )
    .await
    .unwrap();
    native_ce::store::delete_record(&db, DELETED_REVIEW)
        .await
        .unwrap();
    let canonical_error = delete_value(&db, &canonical).await.unwrap_err().to_string();
    assert!(
        canonical_error.contains("including tombstones"),
        "{canonical_error}"
    );

    let alias_target = install_kind(&db, "WorkItem", "approve", true).await;
    let alias = install_kind(&db, "WorkItem", "inspection", true).await;
    alias_value(&db, &alias, &alias_target).await.unwrap();
    create_record(
        &db,
        json!({ "id": ALIAS_REVIEW, "type": "WorkItem", "kind": "inspection" }),
    )
    .await
    .unwrap();
    let alias_error = delete_value(&db, &alias).await.unwrap_err().to_string();
    assert!(
        alias_error.contains("record(s) of type 'WorkItem'"),
        "{alias_error}"
    );

    let unrelated = install_kind(&db, "Outcome", "inspection", true).await;
    // The WorkItem record carrying the same spelling is not a reference to the
    // Outcome vocabulary value.
    delete_value(&db, &unrelated).await.unwrap();
}

#[tokio::test]
async fn document_handoff_seeds_resolves_projects_and_writes_without_quarantine() {
    let db = db().await;
    let registry = registry();

    let resolution = native_ce::meta::kind::resolve(&db, "Document", "handoff")
        .await
        .unwrap();
    assert_eq!(
        resolution.classification,
        KindClassification::ActiveCanonical
    );
    assert!(!resolution.quarantined);
    assert_eq!(
        resolution.canonical_value_id.as_deref(),
        Some(CoreKind::DocumentHandoff.value_id())
    );
    let metadata = resolution.metadata.unwrap();
    assert_eq!(metadata.provenance_ref, HANDOFF_PROVENANCE);
    assert_eq!(
        metadata.definition,
        "An authored session-continuity briefing whose body states live position, boundaries, and working instructions for a later inhabitant."
    );
    let gloss: Option<String> =
        sqlx::query_scalar("SELECT gloss FROM vocabulary_values WHERE id = ?")
            .bind(CoreKind::DocumentHandoff.value_id())
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(gloss.as_deref(), Some(HANDOFF_GLOSS));

    let described = call(
        &registry,
        &db,
        "describe_schema",
        json!({ "include_ddl": false }),
    )
    .await
    .unwrap();
    assert!(described["kind_registry"]["Document"]
        .as_array()
        .unwrap()
        .iter()
        .any(|kind| kind["token"] == "handoff"));
    assert!(
        described["resolved_schema_config"]["shapes"]["Document"]["kinds"]
            .as_array()
            .unwrap()
            .iter()
            .any(|kind| kind == "handoff")
    );

    let created = call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": HANDOFF_WRITE,
            "type": "Document",
            "kind": "handoff",
            "name": "Session handoff",
            "body": "Live position, boundaries, and working instructions.",
            "reason": "Exercise governed Document kind:handoff writes."
        }),
    )
    .await
    .unwrap();
    assert_eq!(created["kind"], "handoff");
    assert_eq!(created["kind_governance"]["quarantined"], false);

    let updated = call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": HANDOFF_WRITE,
            "name": "Revised session handoff",
            "reason": "Exercise governed Document kind:handoff updates."
        }),
    )
    .await
    .unwrap();
    assert_eq!(updated["kind"], "handoff");
    assert_eq!(updated["kind_governance"]["quarantined"], false);
}

#[tokio::test]
async fn invented_document_handoff_values_remain_compatible_after_core_seed() {
    let db = db().await;
    let registry = registry();

    sqlx::query("DELETE FROM vocabulary_values WHERE id = ?")
        .bind(CoreKind::DocumentHandoff.value_id())
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();

    let proposed_id = propose_value_with_kind_metadata_as(
        &db,
        "kind:Document",
        "handoff",
        Some(STALE_HANDOFF_GLOSS),
        0.0,
        VocabularyValueTerminality::Open,
        Some(KindMetadataV1::legacy("Document", "handoff")),
        None,
    )
    .await
    .unwrap();
    assert_eq!(proposed_id, CoreKind::DocumentHandoff.value_id());
    let (status, gloss): (String, Option<String>) =
        sqlx::query_as("SELECT status, gloss FROM vocabulary_values WHERE id = ?")
            .bind(CoreKind::DocumentHandoff.value_id())
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(status, "proposed");
    assert_eq!(gloss.as_deref(), Some(STALE_HANDOFF_GLOSS));

    let proposed_resolution = native_ce::meta::kind::resolve(&db, "Document", "handoff")
        .await
        .unwrap();
    assert_eq!(
        proposed_resolution.classification,
        KindClassification::Proposed
    );
    assert!(proposed_resolution.quarantined);

    let invented = call(
        &registry,
        &db,
        "create_record",
        json!({
            "id": INVENTED_HANDOFF,
            "type": "Document",
            "kind": "handoff",
            "name": "Invented handoff",
            "body": "Pre-governance spelling.",
            "reason": "Preserve an invented handoff before governance arrives."
        }),
    )
    .await
    .unwrap();
    assert_eq!(invented["kind"], "handoff");
    assert_eq!(invented["kind_governance"]["quarantined"], true);

    seed_vocabularies(&db).await.unwrap();

    let (status, gloss): (String, Option<String>) =
        sqlx::query_as("SELECT status, gloss FROM vocabulary_values WHERE id = ?")
            .bind(CoreKind::DocumentHandoff.value_id())
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(status, "active");
    assert_eq!(gloss.as_deref(), Some(HANDOFF_GLOSS));

    let resolution = native_ce::meta::kind::resolve(&db, "Document", "handoff")
        .await
        .unwrap();
    assert_eq!(
        resolution.classification,
        KindClassification::ActiveCanonical
    );
    assert!(!resolution.quarantined);
    let metadata = resolution.metadata.unwrap();
    assert_eq!(metadata.provenance_ref, HANDOFF_PROVENANCE);
    assert!(!metadata.legacy_unattested);

    let read = call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": [INVENTED_HANDOFF] }),
    )
    .await
    .unwrap();
    assert_eq!(read["records"][0]["kind"], "handoff");
    assert_eq!(read["records"][0]["kind_governance"]["quarantined"], false);
}

#[tokio::test]
async fn proposed_core_kind_reconciliation_clears_stale_gloss_without_manifest_admission_gloss() {
    let db = db().await;

    sqlx::query("DELETE FROM vocabulary_values WHERE id = ?")
        .bind(CoreKind::DocumentNote.value_id())
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();

    propose_value_with_kind_metadata_as(
        &db,
        "kind:Document",
        "note",
        Some("Provisional note gloss"),
        0.0,
        VocabularyValueTerminality::Open,
        Some(KindMetadataV1::legacy("Document", "note")),
        None,
    )
    .await
    .unwrap();

    let gloss_before: Option<String> =
        sqlx::query_scalar("SELECT gloss FROM vocabulary_values WHERE id = ?")
            .bind(CoreKind::DocumentNote.value_id())
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(gloss_before.as_deref(), Some("Provisional note gloss"));

    seed_vocabularies(&db).await.unwrap();

    let (status, gloss): (String, Option<String>) =
        sqlx::query_as("SELECT status, gloss FROM vocabulary_values WHERE id = ?")
            .bind(CoreKind::DocumentNote.value_id())
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(status, "active");
    assert_eq!(gloss, None);
}
