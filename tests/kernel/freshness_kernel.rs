use crate::common::{ev, project_one};
use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability, Principal};
use native_ce::conformance::rebuild_and_diff;
use native_ce::create_database;
use native_ce::events::LinkAddedPayload;
use native_ce::freshness::{
    bind_occurrence, current_history_high_water, current_record_body_revision, list_occurrences,
    promote_idea, read_unit, read_unit_revision, resolve_occurrence, revise_unit,
    BindOccurrenceInput, ExpressionRole, IdempotencyKey, OccurrenceId, OccurrenceResolutionState,
    OccurrenceSelector, PromoteIdeaInput, ReviseUnitInput, UnitContent, UnitId,
    SEMANTIC_CONTRACT_VERSION, UNIT_REVISION_FORMAT,
};
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::query::tree::{descendants, TreeOptions};
use native_ce::schema::UNFILED_RECORD_ID;
use native_ce::store::{add_link, append, create_record, update_record, AppendSpec};
use serde_json::json;
use serde_json::Value;

const ACTOR: &str = "test:freshness";
const ACCOUNT: &str = "acct:freshness";

fn principal() -> Principal<'static> {
    Principal::bound(ACCOUNT, true)
}

fn quote(exact: &str) -> Vec<OccurrenceSelector> {
    vec![OccurrenceSelector::TextQuote {
        exact: exact.into(),
        prefix: None,
        suffix: None,
        position_hint: None,
    }]
}

async fn create_document(db: &native_ce::Db, name: &str, body: &str) -> String {
    create_record(
        db,
        json!({"type":"Document","kind":"note","name":name,"body":body}),
    )
    .await
    .unwrap()
}

async fn event_count(db: &native_ce::Db) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap()
}

#[tokio::test]
async fn backdated_unit_revision_advances_the_record_wide_timestamp_token() {
    let db = create_database(":memory:").await.unwrap();
    let source = create_document(&db, "Unit source", "Source idea.").await;
    let promoted = promote_idea(
        &db,
        principal(),
        ACTOR,
        PromoteIdeaInput {
            source_revision: current_record_body_revision(&db, &source).await.unwrap(),
            selectors: quote("Source idea."),
            first_content: UnitContent::text("First unit revision.").unwrap(),
            expression_role: ExpressionRole::Canonical,
            label: None,
            requested_unit_id: None,
            requested_occurrence_id: None,
            idempotency_key: IdempotencyKey::new("unit-token-promotion").unwrap(),
        },
    )
    .await
    .unwrap();
    let before: String = sqlx::query_scalar("SELECT updated_at FROM records WHERE id=?")
        .bind(promoted.unit_id.as_str())
        .fetch_one(db.pool())
        .await
        .unwrap();
    let content = UnitContent::text("Backdated second revision.").unwrap();
    let mut revision = ev(
        promoted.unit_id.as_str(),
        "unit.revision.recorded.v1",
        "2000-01-01T00:00:00.000Z",
        json!({
            "format": UNIT_REVISION_FORMAT,
            "semantic_contract_version": SEMANTIC_CONTRACT_VERSION,
            "content_sha256": content.sha256(),
            "content": content,
            "based_on_revision_event_id": promoted.first_revision.revision_event_id,
            "rationale": "Exercise monotonic record token projection."
        }),
    );
    revision.local_seq = 1_000_000;
    revision.actor = Some(ACTOR.into());
    let fixture_pool = crate::common::fixture_write_pool(&db).await;
    sqlx::query(
        "INSERT INTO content_events(seq,id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) \
         VALUES(?,?,?,?,?,?,?,1,'legacy_unknown')",
    )
    .bind(revision.local_seq)
    .bind(&revision.id)
    .bind(&revision.record_id)
    .bind(&revision.event_type)
    .bind(&revision.payload)
    .bind(&revision.actor)
    .bind(&revision.created_at)
    .execute(&fixture_pool)
    .await
    .unwrap();
    project_one(&db, &revision).await.unwrap();

    let after: String = sqlx::query_scalar("SELECT updated_at FROM records WHERE id=?")
        .bind(promoted.unit_id.as_str())
        .fetch_one(db.pool())
        .await
        .unwrap();
    let expected = (chrono::DateTime::parse_from_rfc3339(&before).unwrap()
        + chrono::Duration::milliseconds(1))
    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    assert_eq!(after, expected);
}

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

async fn call_as(
    registry: &ToolRegistry,
    db: &native_ce::Db,
    account: &str,
    tool: &str,
    mut arguments: Value,
) -> native_ce::Result<Value> {
    if matches!(tool, "update_record" | "delete_record" | "archive_record") {
        arguments
            .as_object_mut()
            .unwrap()
            .entry("reason")
            .or_insert_with(|| json!("freshness authorization test"));
    }
    registry
        .call(db.clone(), Caller::authenticated(account), tool, arguments)
        .await
}

#[tokio::test]
async fn event_sourced_kernel_preserves_exactness_multiplicity_guards_and_replay() {
    let db = create_database(":memory:").await.unwrap();
    let sentence = "The primary launch audience is technical founders.";
    let source_a = create_document(&db, "Audience note", sentence).await;
    let source_a_revision = current_record_body_revision(&db, &source_a).await.unwrap();

    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM semantic_units")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        0,
        "natural authoring creates no semantic Unit"
    );

    let promotion_input = PromoteIdeaInput {
        source_revision: source_a_revision.clone(),
        selectors: quote(sentence),
        first_content: UnitContent::text("Primary launch audience: technical founders.").unwrap(),
        expression_role: ExpressionRole::Canonical,
        label: Some("Launch audience".into()),
        requested_unit_id: None,
        requested_occurrence_id: None,
        idempotency_key: IdempotencyKey::new("promote-audience").unwrap(),
    };
    let promoted = promote_idea(&db, principal(), ACTOR, promotion_input.clone())
        .await
        .unwrap();
    assert_ne!(promoted.unit_id.as_str(), source_a);
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT body FROM records WHERE id=?")
            .bind(promoted.unit_id.as_str())
            .fetch_one(db.pool())
            .await
            .unwrap(),
        "Primary launch audience: technical founders."
    );
    let source_home: String = sqlx::query_scalar("SELECT home_id FROM records WHERE id=?")
        .bind(&source_a)
        .fetch_one(db.pool())
        .await
        .unwrap();
    let unit_home: String = sqlx::query_scalar("SELECT home_id FROM records WHERE id=?")
        .bind(promoted.unit_id.as_str())
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(
        unit_home, source_home,
        "Unit preserves folder-only containment"
    );

    let tree = descendants(
        &db,
        UNFILED_RECORD_ID,
        TreeOptions {
            max_depth: 1,
            ..TreeOptions::default()
        },
    )
    .await
    .unwrap();
    assert!(tree.iter().all(|node| node.id != promoted.unit_id.as_str()));
    assert!(read_unit(&db, principal(), &promoted.unit_id).await.is_ok());

    let replay_input = promotion_input.clone();
    let retry = promote_idea(&db, principal(), ACTOR, promotion_input)
        .await
        .unwrap();
    assert_eq!(retry, promoted);

    let source_b_text = "We are initially building for founders comfortable with technical tools.";
    let source_b = create_document(&db, "Homepage brief", source_b_text).await;
    let source_b_revision = current_record_body_revision(&db, &source_b).await.unwrap();
    let bound = bind_occurrence(
        &db,
        principal(),
        ACTOR,
        BindOccurrenceInput {
            unit_revision: promoted.first_revision.clone(),
            artefact_revision: source_b_revision,
            selectors: quote(source_b_text),
            expression_role: ExpressionRole::Paraphrase,
            requested_occurrence_id: None,
            idempotency_key: IdempotencyKey::new("bind-homepage-brief").unwrap(),
        },
    )
    .await
    .unwrap();
    let occurrences = list_occurrences(&db, principal(), &promoted.unit_id)
        .await
        .unwrap();
    assert_eq!(occurrences.len(), 2);
    assert_ne!(occurrences[0].occurrence_id, occurrences[1].occurrence_id);

    let revision_input = ReviseUnitInput {
        unit_id: promoted.unit_id.clone(),
        expected_current: promoted.first_revision.clone(),
        content: UnitContent::text(
            "Primary launch audience: nontechnical operators adopting agents.",
        )
        .unwrap(),
        rationale: "Audience decision changed after positioning review".into(),
        idempotency_key: IdempotencyKey::new("revise-audience-u2").unwrap(),
    };
    let revised = revise_unit(&db, principal(), ACTOR, revision_input.clone())
        .await
        .unwrap();
    assert_eq!(
        read_unit_revision(&db, principal(), &promoted.first_revision)
            .await
            .unwrap()
            .content
            .content,
        "Primary launch audience: technical founders."
    );
    assert_eq!(
        read_unit_revision(&db, principal(), &revised.new_revision)
            .await
            .unwrap()
            .content
            .content,
        "Primary launch audience: nontechnical operators adopting agents."
    );
    assert_eq!(
        revise_unit(&db, principal(), ACTOR, revision_input)
            .await
            .unwrap(),
        revised
    );

    let before_guard = event_count(&db).await;
    assert!(
        update_record(&db, promoted.unit_id.as_str(), json!({"body":"bypass"}))
            .await
            .unwrap_err()
            .to_string()
            .contains("unit.revision.recorded.v1")
    );
    assert_eq!(event_count(&db).await, before_guard);

    let stale_expected = ReviseUnitInput {
        unit_id: promoted.unit_id.clone(),
        expected_current: promoted.first_revision.clone(),
        content: UnitContent::text("Another candidate").unwrap(),
        rationale: "Exercise expected-current".into(),
        idempotency_key: IdempotencyKey::new("stale-u1-write").unwrap(),
    };
    assert!(revise_unit(&db, principal(), ACTOR, stale_expected)
        .await
        .unwrap_err()
        .to_string()
        .contains("expected-current"));
    assert_eq!(event_count(&db).await, before_guard);

    update_record(
        &db,
        &source_a,
        json!({"body":format!("Context before.\n\n{sentence}\n\nContext after.")}),
    )
    .await
    .unwrap();
    let relocated = resolve_occurrence(&db, principal(), &promoted.occurrence_id)
        .await
        .unwrap();
    assert_eq!(relocated.state, OccurrenceResolutionState::Relocated);
    assert_eq!(relocated.original_artefact_revision, source_a_revision);
    assert!(relocated.current_range.is_some());

    update_record(
        &db,
        &source_b,
        json!({"body":"The expression was removed."}),
    )
    .await
    .unwrap();
    let stale = resolve_occurrence(&db, principal(), &bound.occurrence.occurrence_id)
        .await
        .unwrap();
    assert_eq!(stale.state, OccurrenceResolutionState::Stale);
    assert_eq!(
        list_occurrences(&db, principal(), &promoted.unit_id)
            .await
            .unwrap()
            .len(),
        2,
        "resolution never mutates the original bindings"
    );

    let rebuilt = rebuild_and_diff(&db).await.unwrap();
    assert!(rebuilt.equal, "{:?}", rebuilt.tables);

    replace_explicit_policy(
        &db,
        ACTOR,
        &source_a,
        vec![AllowEntry::account(ACCOUNT, Capability::Manage)],
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        ACTOR,
        promoted.unit_id.as_str(),
        vec![AllowEntry::account(ACCOUNT, Capability::Manage)],
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        ACTOR,
        &source_b,
        vec![
            AllowEntry::account(ACCOUNT, Capability::Manage),
            AllowEntry::account("acct:other", Capability::View),
        ],
    )
    .await
    .unwrap();
    let hidden = Principal::bound("acct:other", true);
    let missing_unit = UnitId::new("missing-unit").unwrap();
    assert_eq!(
        read_unit(&db, hidden, &promoted.unit_id)
            .await
            .unwrap_err()
            .to_string(),
        read_unit(&db, hidden, &missing_unit)
            .await
            .unwrap_err()
            .to_string(),
        "a direct Unit read must not reveal whether an unauthorized Unit exists"
    );
    assert_eq!(
        list_occurrences(&db, hidden, &promoted.unit_id)
            .await
            .unwrap_err()
            .to_string(),
        list_occurrences(&db, hidden, &missing_unit)
            .await
            .unwrap_err()
            .to_string(),
        "occurrence enumeration must not reveal hidden Unit occupancy"
    );
    let mut missing_revision = promoted.first_revision.clone();
    missing_revision.subject_id = missing_unit.as_str().into();
    assert_eq!(
        read_unit_revision(&db, hidden, &promoted.first_revision)
            .await
            .unwrap_err()
            .to_string(),
        read_unit_revision(&db, hidden, &missing_revision)
            .await
            .unwrap_err()
            .to_string(),
        "a Unit revision read must not reveal hidden Unit occupancy"
    );
    assert_eq!(
        resolve_occurrence(&db, hidden, &bound.occurrence.occurrence_id)
            .await
            .unwrap_err()
            .to_string(),
        resolve_occurrence(
            &db,
            hidden,
            &OccurrenceId::new("missing-occurrence").unwrap(),
        )
        .await
        .unwrap_err()
        .to_string(),
        "an artefact-visible viewer without Unit authority must not learn that an Occurrence exists"
    );
    assert!(promote_idea(&db, hidden, ACTOR, replay_input)
        .await
        .is_err());
}

#[tokio::test]
async fn same_idempotency_key_with_different_intent_appends_nothing() {
    let db = create_database(":memory:").await.unwrap();
    let source = create_document(&db, "Source", "One exact idea.").await;
    let source_revision = current_record_body_revision(&db, &source).await.unwrap();
    let base = PromoteIdeaInput {
        source_revision,
        selectors: quote("One exact idea."),
        first_content: UnitContent::text("One exact idea.").unwrap(),
        expression_role: ExpressionRole::Canonical,
        label: None,
        requested_unit_id: None,
        requested_occurrence_id: None,
        idempotency_key: IdempotencyKey::new("same-key").unwrap(),
    };
    promote_idea(&db, principal(), ACTOR, base.clone())
        .await
        .unwrap();
    let before = event_count(&db).await;
    let mut changed = base;
    changed.first_content = UnitContent::text("Different idea.").unwrap();
    assert!(promote_idea(&db, principal(), ACTOR, changed)
        .await
        .unwrap_err()
        .to_string()
        .contains("different freshness command"));
    assert_eq!(event_count(&db).await, before);
}

#[tokio::test]
async fn occurrence_bindings_reject_exact_semantic_duplicates_but_allow_distinct_roles() {
    let db = create_database(":memory:").await.unwrap();
    let source = create_document(&db, "Source", "An exact reusable idea.").await;
    let source_revision = current_record_body_revision(&db, &source).await.unwrap();
    let promoted = promote_idea(
        &db,
        principal(),
        ACTOR,
        PromoteIdeaInput {
            source_revision: source_revision.clone(),
            selectors: quote("An exact reusable idea."),
            first_content: UnitContent::text("An exact reusable idea.").unwrap(),
            expression_role: ExpressionRole::Canonical,
            label: None,
            requested_unit_id: None,
            requested_occurrence_id: None,
            idempotency_key: IdempotencyKey::new("duplicate-promote").unwrap(),
        },
    )
    .await
    .unwrap();
    let before = event_count(&db).await;
    let duplicate = BindOccurrenceInput {
        unit_revision: promoted.first_revision.clone(),
        artefact_revision: source_revision.clone(),
        selectors: quote("An exact reusable idea."),
        expression_role: ExpressionRole::Canonical,
        requested_occurrence_id: None,
        idempotency_key: IdempotencyKey::new("duplicate-new-command").unwrap(),
    };
    assert!(bind_occurrence(&db, principal(), ACTOR, duplicate)
        .await
        .unwrap_err()
        .to_string()
        .contains("identical semantic Occurrence"));
    assert_eq!(event_count(&db).await, before);

    bind_occurrence(
        &db,
        principal(),
        ACTOR,
        BindOccurrenceInput {
            unit_revision: promoted.first_revision,
            artefact_revision: source_revision,
            selectors: quote("An exact reusable idea."),
            expression_role: ExpressionRole::Quotation,
            requested_occurrence_id: None,
            idempotency_key: IdempotencyKey::new("same-anchor-distinct-role").unwrap(),
        },
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn rfc7111_occurrences_require_integrity_evidence_and_changed_bytes_are_stale() {
    let db = create_database(":memory:").await.unwrap();
    let csv = "name,status\nalpha,active\nbeta,paused\n";
    let source = create_document(&db, "CSV source", csv).await;
    let revision = current_record_body_revision(&db, &source).await.unwrap();
    let fragment = OccurrenceSelector::Fragment {
        conforms_to: "https://www.rfc-editor.org/rfc/rfc7111".into(),
        value: "row=2".into(),
    };
    let base = PromoteIdeaInput {
        source_revision: revision.clone(),
        selectors: vec![fragment.clone()],
        first_content: UnitContent::text("Alpha is active.").unwrap(),
        expression_role: ExpressionRole::Canonical,
        label: None,
        requested_unit_id: None,
        requested_occurrence_id: None,
        idempotency_key: IdempotencyKey::new("bare-fragment").unwrap(),
    };
    let before = event_count(&db).await;
    assert!(promote_idea(&db, principal(), ACTOR, base)
        .await
        .unwrap_err()
        .to_string()
        .contains("paired data_position"));
    assert_eq!(event_count(&db).await, before);

    let start = csv.find("alpha,active").unwrap() as u64;
    let end = start + "alpha,active".len() as u64;
    let promoted = promote_idea(
        &db,
        principal(),
        ACTOR,
        PromoteIdeaInput {
            source_revision: revision,
            selectors: vec![
                OccurrenceSelector::DataPosition {
                    start,
                    end,
                    selected_sha256: None,
                },
                fragment,
            ],
            first_content: UnitContent::text("Alpha is active.").unwrap(),
            expression_role: ExpressionRole::Canonical,
            label: None,
            requested_unit_id: None,
            requested_occurrence_id: None,
            idempotency_key: IdempotencyKey::new("captured-fragment").unwrap(),
        },
    )
    .await
    .unwrap();
    update_record(
        &db,
        &source,
        json!({"body":"name,status\nalpha,closed\nbeta,paused\n"}),
    )
    .await
    .unwrap();
    let resolved = resolve_occurrence(&db, principal(), &promoted.occurrence_id)
        .await
        .unwrap();
    assert_eq!(resolved.state, OccurrenceResolutionState::Stale);
}

#[tokio::test]
async fn idempotency_is_subject_scoped_and_unauthorized_callers_cannot_probe_it() {
    let db = create_database(":memory:").await.unwrap();
    let source_a = create_document(&db, "A", "Idea A.").await;
    let source_b = create_document(&db, "B", "Idea B.").await;
    let make_input = |source_revision, exact: &str| PromoteIdeaInput {
        source_revision,
        selectors: quote(exact),
        first_content: UnitContent::text(exact).unwrap(),
        expression_role: ExpressionRole::Canonical,
        label: None,
        requested_unit_id: None,
        requested_occurrence_id: None,
        idempotency_key: IdempotencyKey::new("same-key-different-subject").unwrap(),
    };
    let input_a = make_input(
        current_record_body_revision(&db, &source_a).await.unwrap(),
        "Idea A.",
    );
    let input_b = make_input(
        current_record_body_revision(&db, &source_b).await.unwrap(),
        "Idea B.",
    );
    promote_idea(&db, principal(), ACTOR, input_a.clone())
        .await
        .unwrap();
    promote_idea(&db, principal(), ACTOR, input_b)
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM freshness_command_results WHERE idempotency_key=?"
        )
        .bind("same-key-different-subject")
        .fetch_one(db.pool())
        .await
        .unwrap(),
        2
    );

    replace_explicit_policy(
        &db,
        ACTOR,
        &source_a,
        vec![AllowEntry::account(ACCOUNT, Capability::Manage)],
    )
    .await
    .unwrap();
    let before = event_count(&db).await;
    let error = promote_idea(&db, Principal::bound("acct:intruder", true), ACTOR, input_a)
        .await
        .unwrap_err()
        .to_string();
    assert!(!error.contains("idempotency"), "{error}");
    assert_eq!(event_count(&db).await, before);
}

#[tokio::test]
async fn generic_surfaces_require_unit_and_bearer_and_keep_units_subordinate() {
    const BOTH: &str = "acct:both";
    const ENVELOPE_ONLY: &str = "acct:envelope";
    const BEARER_ONLY: &str = "acct:bearer";
    const FOLDER_ONLY: &str = "acct:folder";

    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let source = create_document(&db, "Source", "Secret idea expression.").await;
    let source_revision = current_record_body_revision(&db, &source).await.unwrap();
    let promoted = promote_idea(
        &db,
        principal(),
        ACTOR,
        PromoteIdeaInput {
            source_revision,
            selectors: quote("Secret idea expression."),
            first_content: UnitContent::text("Secret semantic unit token.").unwrap(),
            expression_role: ExpressionRole::Canonical,
            label: Some("Unique semantic unit label".into()),
            requested_unit_id: None,
            requested_occurrence_id: None,
            idempotency_key: IdempotencyKey::new("generic-auth-promote").unwrap(),
        },
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        ACTOR,
        &source,
        vec![
            AllowEntry::account(ACCOUNT, Capability::Manage),
            AllowEntry::account(BOTH, Capability::Manage),
            AllowEntry::account(BEARER_ONLY, Capability::Manage),
        ],
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        ACTOR,
        promoted.unit_id.as_str(),
        vec![
            AllowEntry::account(ACCOUNT, Capability::Manage),
            AllowEntry::account(BOTH, Capability::Manage),
            AllowEntry::account(ENVELOPE_ONLY, Capability::Manage),
        ],
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        ACTOR,
        UNFILED_RECORD_ID,
        vec![
            AllowEntry::account(ACCOUNT, Capability::Manage),
            AllowEntry::account(FOLDER_ONLY, Capability::Manage),
        ],
    )
    .await
    .unwrap();

    let visible = call_as(
        &registry,
        &db,
        BOTH,
        "get_record",
        json!({"ids":[promoted.unit_id.as_str()]}),
    )
    .await
    .unwrap();
    assert_eq!(visible["records"][0]["status"], "found");
    for account in [ENVELOPE_ONLY, BEARER_ONLY, FOLDER_ONLY] {
        let hidden = call_as(
            &registry,
            &db,
            account,
            "get_record",
            json!({"ids":[promoted.unit_id.as_str()]}),
        )
        .await
        .unwrap();
        assert_eq!(hidden["records"][0]["status"], "not_found", "{account}");
        assert!(call_as(
            &registry,
            &db,
            account,
            "get_history",
            json!({"record_id":promoted.unit_id.as_str()}),
        )
        .await
        .is_err());
    }
    let before = event_count(&db).await;
    assert!(call_as(
        &registry,
        &db,
        ENVELOPE_ONLY,
        "update_record",
        json!({"id":promoted.unit_id.as_str(),"name":"leak"}),
    )
    .await
    .is_err());
    assert_eq!(event_count(&db).await, before);

    let search = call_as(
        &registry,
        &db,
        BOTH,
        "search",
        json!({"query":"Unique semantic unit label"}),
    )
    .await
    .unwrap();
    assert!(!search.to_string().contains(promoted.unit_id.as_str()));
    let sql = call_as(
        &registry,
        &db,
        BOTH,
        "query_sql",
        json!({"sql":"SELECT id FROM records WHERE kind = 'semantic-unit'"}),
    )
    .await
    .unwrap();
    assert_eq!(sql["row_count"], 0);

    let envelope_created_seq: i64 = sqlx::query_scalar(
        "SELECT seq FROM content_events WHERE record_id=? AND type='record.created'",
    )
    .bind(promoted.unit_id.as_str())
    .fetch_one(db.pool())
    .await
    .unwrap();
    let historical = call_as(
        &registry,
        &db,
        BOTH,
        "query_record",
        json!({
            "steps":[{"step":"filter","ids":[promoted.unit_id.as_str()]}],
            "as_of":{"content_seq":envelope_created_seq}
        }),
    )
    .await
    .unwrap();
    assert_eq!(historical["total"], 0);
    let structure = call_as(
        &registry,
        &db,
        FOLDER_ONLY,
        "get_record",
        json!({"ids":[UNFILED_RECORD_ID]}),
    )
    .await
    .unwrap();
    assert!(!structure.to_string().contains(promoted.unit_id.as_str()));

    let before = event_count(&db).await;
    let error = call_as(
        &registry,
        &db,
        BOTH,
        "update_record",
        json!({"id":promoted.unit_id.as_str(),"kind":"note"}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("identity envelope"), "{error}");
    assert_eq!(event_count(&db).await, before);
}

#[tokio::test]
async fn unit_history_suppresses_private_occurrence_before_page_occupancy() {
    const VIEWER: &str = "acct:viewer";
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let source_a = create_document(&db, "Public expression", "Public phrase.").await;
    let source_b = create_document(&db, "Private expression", "Private phrase.").await;
    let promoted = promote_idea(
        &db,
        principal(),
        ACTOR,
        PromoteIdeaInput {
            source_revision: current_record_body_revision(&db, &source_a).await.unwrap(),
            selectors: quote("Public phrase."),
            first_content: UnitContent::text("Shared unit.").unwrap(),
            expression_role: ExpressionRole::Canonical,
            label: None,
            requested_unit_id: None,
            requested_occurrence_id: None,
            idempotency_key: IdempotencyKey::new("history-promote").unwrap(),
        },
    )
    .await
    .unwrap();
    let activity_before_private: Option<String> =
        sqlx::query_scalar("SELECT last_activity_at FROM records WHERE id=?")
            .bind(promoted.unit_id.as_str())
            .fetch_one(db.pool())
            .await
            .unwrap();
    bind_occurrence(
        &db,
        principal(),
        ACTOR,
        BindOccurrenceInput {
            unit_revision: promoted.first_revision.clone(),
            artefact_revision: current_record_body_revision(&db, &source_b).await.unwrap(),
            selectors: quote("Private phrase."),
            expression_role: ExpressionRole::Quotation,
            requested_occurrence_id: None,
            idempotency_key: IdempotencyKey::new("history-private-bind").unwrap(),
        },
    )
    .await
    .unwrap();
    let activity_after_private: Option<String> =
        sqlx::query_scalar("SELECT last_activity_at FROM records WHERE id=?")
            .bind(promoted.unit_id.as_str())
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(activity_after_private, activity_before_private);
    for record_id in [&source_a, promoted.unit_id.as_str()] {
        replace_explicit_policy(
            &db,
            ACTOR,
            record_id,
            vec![
                AllowEntry::account(ACCOUNT, Capability::Manage),
                AllowEntry::account(VIEWER, Capability::View),
            ],
        )
        .await
        .unwrap();
    }
    replace_explicit_policy(
        &db,
        ACTOR,
        &source_b,
        vec![AllowEntry::account(ACCOUNT, Capability::Manage)],
    )
    .await
    .unwrap();

    let history = call_as(
        &registry,
        &db,
        VIEWER,
        "get_history",
        json!({"record_id":promoted.unit_id.as_str(),"limit":100}),
    )
    .await
    .unwrap();
    let occurrences = history["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["type"] == "occurrence.bound.v1")
        .count();
    assert_eq!(occurrences, 1);
    assert!(!history.to_string().contains("Private phrase."));
    let newest = call_as(
        &registry,
        &db,
        VIEWER,
        "get_history",
        json!({"record_id":promoted.unit_id.as_str(),"limit":1,"order":"newest_first","detail":"full"}),
    )
    .await
    .unwrap();
    assert_eq!(newest["events"][0]["type"], "occurrence.bound.v1");
    assert!(newest.to_string().contains("Public phrase."));

    let changed = call_as(
        &registry,
        &db,
        VIEWER,
        "whats_changed",
        json!({"after_local_seq":0,"limit":1000}),
    )
    .await
    .unwrap();
    let unit_group = changed["changes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|change| change["record_id"] == promoted.unit_id.as_str())
        .unwrap();
    assert_eq!(unit_group["event_count"], 4);
}

#[tokio::test]
async fn trusted_local_generic_queries_validate_bearer_shape() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let bearer_a = create_document(&db, "Bearer A", "a").await;
    let bearer_b = create_document(&db, "Bearer B", "b").await;
    let malformed = create_record(
        &db,
        json!({"type":"Document","kind":"attachment","name":"Malformed derived"}),
    )
    .await
    .unwrap();
    for (id, target) in [("part-a", &bearer_a), ("part-b", &bearer_b)] {
        add_link(
            &db,
            LinkAddedPayload {
                id: Some(id.into()),
                source_id: malformed.clone(),
                target_id: target.clone(),
                relationship: "part_of".into(),
                note: None,
            },
        )
        .await
        .unwrap();
    }
    let direct = registry
        .call(
            db.clone(),
            Caller::local(),
            "get_record",
            json!({"ids":[malformed]}),
        )
        .await
        .unwrap();
    assert_eq!(direct["records"][0]["status"], "not_found");
    assert!(registry
        .call(
            db.clone(),
            Caller::local(),
            "get_history",
            json!({"record_id":malformed}),
        )
        .await
        .is_err());
    let query = registry
        .call(
            db.clone(),
            Caller::local(),
            "query_record",
            json!({"steps":[{"step":"filter","ids":[malformed]}]}),
        )
        .await
        .unwrap();
    assert_eq!(query["total"], 0);
}

#[tokio::test]
async fn derived_source_owner_floor_is_preserved_on_promoted_unit() {
    let db = create_database(":memory:").await.unwrap();
    let owner = create_record(&db, json!({"type":"Entity","kind":"person","name":"Owner"}))
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO bindings(record_id,system,identifier,is_canonical)
         VALUES(?,'account',?,1)",
    )
    .bind(&owner)
    .bind(ACCOUNT)
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    let bearer = create_record(
        &db,
        json!({
            "type":"Document","kind":"note","name":"Bearer","body":"Bearer body",
            "owner_id":owner
        }),
    )
    .await
    .unwrap();
    replace_explicit_policy(&db, ACTOR, &bearer, Vec::new())
        .await
        .unwrap();
    let derived = create_record(
        &db,
        json!({
            "type":"Document","kind":"attachment","name":"Derived expression",
            "body":"Owner-only derived idea."
        }),
    )
    .await
    .unwrap();
    add_link(
        &db,
        LinkAddedPayload {
            id: Some("derived-bearer".into()),
            source_id: derived.clone(),
            target_id: bearer,
            relationship: "part_of".into(),
            note: None,
        },
    )
    .await
    .unwrap();
    let promoted = promote_idea(
        &db,
        principal(),
        ACTOR,
        PromoteIdeaInput {
            source_revision: current_record_body_revision(&db, &derived).await.unwrap(),
            selectors: quote("Owner-only derived idea."),
            first_content: UnitContent::text("Owner-only idea.").unwrap(),
            expression_role: ExpressionRole::Canonical,
            label: None,
            requested_unit_id: None,
            requested_occurrence_id: None,
            idempotency_key: IdempotencyKey::new("derived-owner-floor").unwrap(),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, Option<String>>("SELECT owner_id FROM records WHERE id=?")
            .bind(promoted.unit_id.as_str())
            .fetch_one(db.pool())
            .await
            .unwrap(),
        Some(owner)
    );
    assert!(read_unit(&db, principal(), &promoted.unit_id).await.is_ok());
}

#[tokio::test]
async fn raw_semantic_events_require_nonblank_actor_and_append_nothing() {
    let db = create_database(":memory:").await.unwrap();
    let source = create_document(&db, "Raw target", "body").await;
    for (index, event_type) in [
        "unit.created.v1",
        "unit.revision.recorded.v1",
        "occurrence.bound.v1",
    ]
    .into_iter()
    .enumerate()
    {
        let before = event_count(&db).await;
        let actor = (index != 0).then(|| "   ".to_string());
        let error = append(
            &db,
            AppendSpec {
                record_id: source.clone(),
                event_type: event_type.into(),
                payload: json!({}),
                actor,
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("nonblank immutable actor"), "{error}");
        assert_eq!(event_count(&db).await, before);
    }

    let source_revision = current_record_body_revision(&db, &source).await.unwrap();
    let promoted = promote_idea(
        &db,
        principal(),
        ACTOR,
        PromoteIdeaInput {
            source_revision: source_revision.clone(),
            selectors: quote("body"),
            first_content: UnitContent::text("Valid unit content.").unwrap(),
            expression_role: ExpressionRole::Canonical,
            label: None,
            requested_unit_id: None,
            requested_occurrence_id: None,
            idempotency_key: IdempotencyKey::new("raw-boundary-promotion").unwrap(),
        },
    )
    .await
    .unwrap();

    let before = event_count(&db).await;
    let invalid_content = append(
        &db,
        AppendSpec {
            record_id: promoted.unit_id.as_str().into(),
            event_type: "unit.revision.recorded.v1".into(),
            payload: json!({
                "format":UNIT_REVISION_FORMAT,
                "semantic_contract_version":SEMANTIC_CONTRACT_VERSION,
                "content":{
                    "content":"   ",
                    "content_media_type":"text/plain",
                    "encoding_version":1
                },
                "content_sha256":"a".repeat(64),
                "based_on_revision_event_id":promoted.first_revision.revision_event_id,
                "rationale":"raw replay boundary"
            }),
            actor: Some(ACTOR.into()),
        },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(invalid_content.contains("unit content must not be blank"));
    assert_eq!(event_count(&db).await, before);

    let canonical_selectors = list_occurrences(&db, principal(), &promoted.unit_id)
        .await
        .unwrap()
        .remove(0)
        .selectors;
    for (occurrence_id, idempotency_key) in [
        (" ".to_string(), "valid-raw-command".to_string()),
        ("valid-raw-occurrence".to_string(), "x".repeat(201)),
    ] {
        let before = event_count(&db).await;
        let error = append(
            &db,
            AppendSpec {
                record_id: promoted.unit_id.as_str().into(),
                event_type: "occurrence.bound.v1".into(),
                payload: json!({
                    "semantic_contract_version":SEMANTIC_CONTRACT_VERSION,
                    "occurrence_id":occurrence_id,
                    "unit_revision":promoted.first_revision,
                    "artefact_revision":source_revision,
                    "selectors":canonical_selectors,
                    "expression_role":"quotation",
                    "command":{
                        "operation":"bind_occurrence",
                        "scope_record_id":promoted.unit_id.as_str(),
                        "idempotency_key":idempotency_key,
                        "intent_sha256":"a".repeat(64),
                        "authorization_revision_observed":0
                    }
                }),
                actor: Some(ACTOR.into()),
            },
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("occurrence id") || error.contains("idempotency key"),
            "{error}"
        );
        assert_eq!(event_count(&db).await, before);
    }
}

#[tokio::test]
async fn history_high_water_reads_one_coherent_snapshot() {
    let db = create_database(":memory:").await.unwrap();
    create_document(&db, "Receipt source", "body").await;
    let receipt = current_history_high_water(&db).await.unwrap();
    let content_seq: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(receipt.content_seq, content_seq);
    assert_eq!(
        receipt.authorization_revision_observed,
        sqlx::query_scalar::<_, i64>("SELECT epoch FROM authorization_revision WHERE id=1")
            .fetch_one(db.pool())
            .await
            .unwrap()
    );
}
