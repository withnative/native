//! The optional declared source basis on ordinary writes (slice A).
//!
//! A declaration rides on the write event beside `reason`, under
//! `native.source-basis.v1`. These tests pin the distinctions the feature is
//! for: absent versus declared-as-none, a real but stale revision versus the
//! engine-stamped head, and a hidden citation refused by ordinal rather than
//! disclosed by id. The extra payload key must stay inert to the fold, so the
//! content rebuild-and-diff check must still pass.

use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::provenance::Channel;
use native_ce::{create_database, Db};
use serde_json::{json, Value};

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

async fn call(
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
            crate::common::with_test_reason(tool, args),
        )
        .await
}

fn in_run(run: &str, mut args: Value) -> Value {
    args.as_object_mut()
        .expect("tool arguments are an object")
        .insert("run_key".into(), json!(run));
    args
}

async fn create(
    registry: &ToolRegistry,
    db: &Db,
    caller: Caller,
    args: Value,
) -> native_ce::Result<Value> {
    call(registry, db, caller, "create_record", args).await
}

async fn created_payload(db: &Db, id: &str) -> Value {
    let raw: String = sqlx::query_scalar(
        "SELECT payload FROM content_events WHERE record_id=? AND type='record.created' \
         ORDER BY seq LIMIT 1",
    )
    .bind(id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    serde_json::from_str(&raw).unwrap()
}

async fn event_id_of_type(db: &Db, id: &str, event_type: &str) -> String {
    sqlx::query_scalar(
        "SELECT id FROM content_events WHERE record_id=? AND type=? ORDER BY seq DESC LIMIT 1",
    )
    .bind(id)
    .bind(event_type)
    .fetch_one(db.pool())
    .await
    .unwrap()
}

async fn latest_body_event(db: &Db, id: &str) -> String {
    sqlx::query_scalar(
        "SELECT id FROM content_events WHERE record_id=? \
           AND (type='record.created' \
             OR (type='record.updated' AND json_type(payload,'$.body') IS NOT NULL)) \
         ORDER BY seq DESC LIMIT 1",
    )
    .bind(id)
    .fetch_one(db.pool())
    .await
    .unwrap()
}

async fn updated_payloads(db: &Db, id: &str) -> Vec<Value> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT payload FROM content_events WHERE record_id=? AND type='record.updated' ORDER BY seq",
    )
    .bind(id)
    .fetch_all(db.pool())
    .await
    .unwrap();
    rows.iter()
        .map(|raw| serde_json::from_str(raw).unwrap())
        .collect()
}

async fn facet_set_payloads(db: &Db, id: &str) -> Vec<Value> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT payload FROM content_events WHERE record_id=? AND type='facet.set' ORDER BY seq",
    )
    .bind(id)
    .fetch_all(db.pool())
    .await
    .unwrap();
    rows.iter()
        .map(|raw| serde_json::from_str(raw).unwrap())
        .collect()
}

async fn seed_source(registry: &ToolRegistry, db: &Db, name: &str) -> String {
    create(
        registry,
        db,
        Caller::local(),
        json!({ "type": "Document", "kind": "note", "name": name, "body": "v1" }),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn create_stores_a_caller_supplied_revision_basis_beside_reason() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let source_id = seed_source(&registry, &db, "source").await;
    let source_created = event_id_of_type(&db, &source_id, "record.created").await;

    let created = create(
        &registry,
        &db,
        Caller::local(),
        json!({
            "type": "Document",
            "kind": "note",
            "name": "citing",
            "body": "composed from the source",
            "facets": { "area": "mcp" },
            "sources": [{
                "record_id": source_id,
                "reason": "the note I worked from",
                "role": "primary",
                "revision_event_id": source_created,
            }],
        }),
    )
    .await
    .unwrap();
    let id = created["id"].as_str().unwrap().to_string();

    assert_eq!(created["basis"]["status"], json!("declared"));
    assert_eq!(created["basis"]["source_count"], json!(1));
    assert_eq!(
        created["basis"]["message"],
        json!("basis: 1 source recorded")
    );

    let payload = created_payload(&db, &id).await;
    let basis = &payload["basis"];
    assert_eq!(basis["format"], json!("native.source-basis.v1"));
    let source = &basis["sources"][0];
    assert_eq!(source["ordinal"], json!(0));
    assert_eq!(source["record_id"], json!(source_id));
    assert_eq!(source["revision_event_id"], json!(source_created));
    assert_eq!(source["revision_supplied_by"], json!("caller"));
    assert_eq!(source["role"], json!("primary"));
    assert_eq!(source["reason"], json!("the note I worked from"));

    // The basis is bound to the write event alone; the facet event this same
    // call emitted must not carry it.
    let facet_raw: String = sqlx::query_scalar(
        "SELECT payload FROM content_events WHERE record_id=? AND type='facet.set'",
    )
    .bind(&id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let facet: Value = serde_json::from_str(&facet_raw).unwrap();
    assert!(
        facet.get("basis").is_none(),
        "basis leaked onto a facet event"
    );
}

#[tokio::test]
async fn empty_sources_is_stored_distinctly_from_absent() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();

    let declared_none = create(
        &registry,
        &db,
        Caller::local(),
        json!({ "type": "Document", "kind": "note", "name": "none", "sources": [] }),
    )
    .await
    .unwrap();
    let none_id = declared_none["id"].as_str().unwrap().to_string();
    assert_eq!(declared_none["basis"]["status"], json!("declared_none"));
    assert_eq!(declared_none["basis"]["source_count"], json!(0));
    assert_eq!(
        declared_none["basis"]["message"],
        json!("basis: declared as none")
    );
    let none_payload = created_payload(&db, &none_id).await;
    assert_eq!(
        none_payload["basis"]["format"],
        json!("native.source-basis.v1")
    );
    assert_eq!(none_payload["basis"]["sources"], json!([]));

    let absent = create(
        &registry,
        &db,
        Caller::local(),
        json!({ "type": "Document", "kind": "note", "name": "absent" }),
    )
    .await
    .unwrap();
    let absent_id = absent["id"].as_str().unwrap().to_string();
    let absent_payload = created_payload(&db, &absent_id).await;
    assert!(
        absent_payload.get("basis").is_none(),
        "absent must store nothing at all"
    );
    // A local (non-MCP) channel gets no absence pointer either.
    assert!(absent.get("basis").is_none());
}

#[tokio::test]
async fn a_hidden_citation_is_refused_by_ordinal_without_disclosure() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let source_id = seed_source(&registry, &db, "secret-source").await;
    let target_id = seed_source(&registry, &db, "target").await;

    // The source becomes invisible to everyone but a third party; the target
    // stays editable by `other`.
    native_ce::authorization::replace_explicit_policy(
        &db,
        "test:policy",
        &source_id,
        vec![native_ce::authorization::AllowEntry::account(
            "third-party",
            native_ce::authorization::Capability::Manage,
        )],
    )
    .await
    .unwrap();
    native_ce::authorization::replace_explicit_policy(
        &db,
        "test:policy",
        &target_id,
        vec![native_ce::authorization::AllowEntry::account(
            "other",
            native_ce::authorization::Capability::Manage,
        )],
    )
    .await
    .unwrap();

    let other = Caller::authenticated("other").with_channel(Channel::Mcp);
    let error = call(
        &registry,
        &db,
        other,
        "update_record",
        json!({
            "id": target_id,
            "summary": "attempted",
            "sources": [{ "record_id": source_id, "reason": "I read it" }],
        }),
    )
    .await
    .unwrap_err()
    .to_string();

    assert!(error.contains("sources[0]"), "{error}");
    assert!(
        !error.contains(&source_id),
        "the refusal must not disclose the hidden record id: {error}"
    );
}

#[tokio::test]
async fn a_non_body_revision_event_is_refused() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let source_id = seed_source(&registry, &db, "source").await;

    call(
        &registry,
        &db,
        Caller::local(),
        "update_record",
        json!({ "id": source_id, "facets": { "area": "mcp" } }),
    )
    .await
    .unwrap();
    let facet_event = event_id_of_type(&db, &source_id, "facet.set").await;

    let error = create(
        &registry,
        &db,
        Caller::local(),
        json!({
            "type": "Document",
            "kind": "note",
            "name": "citing",
            "sources": [{
                "record_id": source_id,
                "reason": "citing a non-body event",
                "revision_event_id": facet_event,
            }],
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("sources[0].revision_event_id"), "{error}");
}

#[tokio::test]
async fn the_current_body_head_is_stamped_when_no_revision_is_supplied() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let source_id = seed_source(&registry, &db, "source").await;
    let first_head = latest_body_event(&db, &source_id).await;

    let first = create(
        &registry,
        &db,
        Caller::local(),
        json!({
            "type": "Document",
            "kind": "note",
            "name": "first-citing",
            "sources": [{ "record_id": source_id, "reason": "read it" }],
        }),
    )
    .await
    .unwrap();
    let first_payload = created_payload(&db, first["id"].as_str().unwrap()).await;
    let stamped = &first_payload["basis"]["sources"][0];
    assert_eq!(stamped["revision_supplied_by"], json!("engine"));
    assert_eq!(stamped["revision_event_id"], json!(first_head));

    // A later body revision moves the head, and the engine stamps the newer
    // one — it is the revision the caller would have read, not a fixed one.
    call(
        &registry,
        &db,
        Caller::local(),
        "update_record",
        json!({ "id": source_id, "body_append": " more" }),
    )
    .await
    .unwrap();
    let later_head = latest_body_event(&db, &source_id).await;
    assert_ne!(later_head, first_head);

    let second = create(
        &registry,
        &db,
        Caller::local(),
        json!({
            "type": "Document",
            "kind": "note",
            "name": "second-citing",
            "sources": [{ "record_id": source_id, "reason": "read it again" }],
        }),
    )
    .await
    .unwrap();
    let second_payload = created_payload(&db, second["id"].as_str().unwrap()).await;
    assert_eq!(
        second_payload["basis"]["sources"][0]["revision_event_id"],
        json!(later_head)
    );
}

#[tokio::test]
async fn a_write_may_cite_its_own_target() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let target_id = seed_source(&registry, &db, "self-citing").await;

    let updated = call(
        &registry,
        &db,
        Caller::local(),
        "update_record",
        json!({
            "id": target_id,
            "summary": "updated in place",
            "sources": [{ "record_id": target_id, "reason": "I re-read it before editing" }],
        }),
    )
    .await
    .unwrap();
    assert_eq!(updated["basis"]["status"], json!("declared"));
    let updated_payload: Value = serde_json::from_str(
        &sqlx::query_scalar::<_, String>(
            "SELECT payload FROM content_events WHERE record_id=? AND type='record.updated' \
             ORDER BY seq DESC LIMIT 1",
        )
        .bind(&target_id)
        .fetch_one(db.pool())
        .await
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        updated_payload["basis"]["sources"][0]["record_id"],
        json!(target_id)
    );
}

#[tokio::test]
async fn the_batch_update_form_rejects_sources() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let first = seed_source(&registry, &db, "one").await;
    let second = seed_source(&registry, &db, "two").await;

    let error = call(
        &registry,
        &db,
        Caller::local(),
        "update_record",
        json!({
            "ids": [first, second],
            "facets": { "area": "mcp" },
            "sources": [{ "record_id": first, "reason": "one basis for many" }],
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("not supported on the batch form"), "{error}");

    // `null` folds to `None` through serde, so the parsed field cannot see it;
    // it must be caught on the raw arguments, or a caller meaning "none" gets a
    // silent no-declaration mutation.
    let facets_before = facet_set_payloads(&db, &first).await.len();
    let null_error = call(
        &registry,
        &db,
        Caller::local(),
        "update_record",
        json!({
            "ids": [first],
            "facets": { "area": "mcp" },
            "sources": null,
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        null_error.contains("not supported on the batch form"),
        "{null_error}"
    );
    assert_eq!(
        facet_set_payloads(&db, &first).await.len(),
        facets_before,
        "a rejected batch must not mutate the record"
    );
}

#[tokio::test]
async fn idempotent_create_conflicts_on_differing_sources() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let source_id = seed_source(&registry, &db, "source").await;

    let base = json!({
        "type": "Document",
        "kind": "note",
        "name": "keyed",
        "body": "durable prose",
        "idempotency_key": "basis-key-1",
        "sources": [{ "record_id": source_id, "reason": "first reason" }],
    });
    let first = create(&registry, &db, Caller::local(), base.clone())
        .await
        .unwrap();
    assert_eq!(first["basis"]["source_count"], json!(1));

    let retry = create(&registry, &db, Caller::local(), base.clone())
        .await
        .unwrap();
    assert_eq!(retry, first, "an identical retry replays byte-identically");

    let mut different = base;
    different["sources"][0]["reason"] = json!("a different reason");
    let conflict = create(&registry, &db, Caller::local(), different)
        .await
        .unwrap_err()
        .to_string();
    assert!(conflict.contains("conflicting"), "{conflict}");
}

#[tokio::test]
async fn create_many_items_accept_a_basis() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let source_id = seed_source(&registry, &db, "source").await;

    let created = call(
        &registry,
        &db,
        Caller::local(),
        "create_many",
        json!({
            "reason": "batch with a declared basis",
            "records": [
                {
                    "type": "Document",
                    "kind": "note",
                    "name": "batch-citing",
                    "sources": [{ "record_id": source_id, "reason": "the batch source" }],
                },
                { "type": "Document", "kind": "note", "name": "batch-plain" },
            ],
        }),
    )
    .await
    .unwrap();
    assert_eq!(created["ok"], json!(true));
    let citing_id = created["ids"][0].as_str().unwrap();
    let payload = created_payload(&db, citing_id).await;
    assert_eq!(
        payload["basis"]["sources"][0]["record_id"],
        json!(source_id)
    );
    let plain_id = created["ids"][1].as_str().unwrap();
    assert!(created_payload(&db, plain_id).await.get("basis").is_none());
}

#[tokio::test]
async fn the_absence_pointer_shows_once_a_run_has_not_declared_and_then_stops() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    // A non-legacy caller is required here: the trusted-local in-process route
    // suppresses run-key persistence, and this behaviour is defined against a
    // run. The binding below is what ordinary authoring requires anyway.
    let person = create(
        &registry,
        &db,
        Caller::local(),
        json!({ "type": "Entity", "kind": "person", "name": "Richard" }),
    )
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO bindings(record_id,system,identifier,is_canonical) \
         VALUES(?,'account','local',1)",
    )
    .bind(person["id"].as_str().unwrap())
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    let source_id = seed_source(&registry, &db, "source").await;
    let agent = Caller::authenticated("local").with_channel(Channel::Mcp);
    let run = "scout-chair-a1b2c3";

    let first = call(
        &registry,
        &db,
        agent.clone(),
        "create_record",
        in_run(
            run,
            json!({ "type": "Document", "kind": "note", "name": "undeclared-one" }),
        ),
    )
    .await
    .unwrap();
    assert_eq!(first["basis"]["status"], json!("not_declared"));
    assert_eq!(first["basis"]["message"], json!("no sources declared"));

    let declared = call(
        &registry,
        &db,
        agent.clone(),
        "create_record",
        in_run(
            run,
            json!({
                "type": "Document",
                "kind": "note",
                "name": "declaring",
                "sources": [{ "record_id": source_id, "reason": "read it" }],
            }),
        ),
    )
    .await
    .unwrap();
    assert_eq!(declared["basis"]["status"], json!("declared"));

    let after = call(
        &registry,
        &db,
        agent,
        "create_record",
        in_run(
            run,
            json!({ "type": "Document", "kind": "note", "name": "undeclared-two" }),
        ),
    )
    .await
    .unwrap();
    assert!(
        after.get("basis").is_none(),
        "the pointer is suppressed once the run has declared"
    );
}

#[tokio::test]
async fn a_declared_basis_stays_inert_to_the_rebuild_and_diff_check() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let source_id = seed_source(&registry, &db, "source").await;

    let created = create(
        &registry,
        &db,
        Caller::local(),
        json!({
            "type": "Document",
            "kind": "note",
            "name": "citing",
            "body": "composed",
            "sources": [{ "record_id": source_id, "reason": "the source" }],
        }),
    )
    .await
    .unwrap();
    let id = created["id"].as_str().unwrap();
    let payload = created_payload(&db, id).await;
    assert_eq!(payload["basis"]["format"], json!("native.source-basis.v1"));

    let check = native_ce::conformance::check_rebuild_and_diff(&db).await;
    assert!(check.ok, "rebuild-and-diff drift: {:?}", check.violations);
}

#[tokio::test]
async fn a_stale_but_real_revision_is_accepted() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let source_id = seed_source(&registry, &db, "source").await;
    let first_body = latest_body_event(&db, &source_id).await;

    // The source moves on after the caller read it: the pinned revision is now
    // stale, but it is real, and the honest case must be accepted rather than
    // refused for not being the head.
    call(
        &registry,
        &db,
        Caller::local(),
        "update_record",
        json!({ "id": source_id, "body_append": " more" }),
    )
    .await
    .unwrap();
    assert_ne!(latest_body_event(&db, &source_id).await, first_body);

    let created = create(
        &registry,
        &db,
        Caller::local(),
        json!({
            "type": "Document",
            "kind": "note",
            "name": "citing",
            "sources": [{
                "record_id": source_id,
                "reason": "composed from the revision I read",
                "revision_event_id": first_body,
            }],
        }),
    )
    .await
    .unwrap();
    let payload = created_payload(&db, created["id"].as_str().unwrap()).await;
    let stored = &payload["basis"]["sources"][0];
    assert_eq!(stored["revision_event_id"], json!(first_body));
    assert_eq!(stored["revision_supplied_by"], json!("caller"));
}

#[tokio::test]
async fn invisible_and_nonexistent_citations_are_refused_identically() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let hidden_id = seed_source(&registry, &db, "hidden").await;
    let target_id = seed_source(&registry, &db, "target").await;
    native_ce::authorization::replace_explicit_policy(
        &db,
        "test:policy",
        &hidden_id,
        vec![native_ce::authorization::AllowEntry::account(
            "third-party",
            native_ce::authorization::Capability::Manage,
        )],
    )
    .await
    .unwrap();
    native_ce::authorization::replace_explicit_policy(
        &db,
        "test:policy",
        &target_id,
        vec![native_ce::authorization::AllowEntry::account(
            "other",
            native_ce::authorization::Capability::Manage,
        )],
    )
    .await
    .unwrap();
    let other = Caller::authenticated("other").with_channel(Channel::Mcp);
    let nonexistent = "e0e70000-0000-4000-8000-0000000000ff";

    let invisible = call(
        &registry,
        &db,
        other.clone(),
        "update_record",
        json!({
            "id": target_id,
            "summary": "a",
            "sources": [{ "record_id": hidden_id, "reason": "r" }],
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    let missing = call(
        &registry,
        &db,
        other,
        "update_record",
        json!({
            "id": target_id,
            "summary": "b",
            "sources": [{ "record_id": nonexistent, "reason": "r" }],
        }),
    )
    .await
    .unwrap_err()
    .to_string();

    assert_eq!(
        invisible, missing,
        "an invisible id and a nonexistent id must be indistinguishable"
    );
    assert!(invisible.contains("sources[0]"), "{invisible}");
    assert!(!invisible.contains(&hidden_id), "{invisible}");
}

#[tokio::test]
async fn a_revision_from_another_record_is_refused() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let source_id = seed_source(&registry, &db, "source").await;
    let other_id = seed_source(&registry, &db, "other").await;
    let other_created = event_id_of_type(&db, &other_id, "record.created").await;

    let error = create(
        &registry,
        &db,
        Caller::local(),
        json!({
            "type": "Document",
            "kind": "note",
            "name": "citing",
            "sources": [{
                "record_id": source_id,
                "reason": "a revision that belongs to someone else",
                "revision_event_id": other_created,
            }],
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("sources[0].revision_event_id"), "{error}");
}

#[tokio::test]
async fn basis_shape_rules_are_enforced() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let source_id = seed_source(&registry, &db, "source").await;

    let duplicate = create(
        &registry,
        &db,
        Caller::local(),
        json!({
            "type": "Document",
            "kind": "note",
            "name": "duplicate",
            "sources": [
                { "record_id": source_id, "reason": "once" },
                { "record_id": source_id, "reason": "twice" },
            ],
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(duplicate.contains("repeats a record_id"), "{duplicate}");

    let too_many: Vec<Value> = (0..=50)
        .map(|_| json!({ "record_id": source_id, "reason": "r" }))
        .collect();
    let over = create(
        &registry,
        &db,
        Caller::local(),
        json!({
            "type": "Document",
            "kind": "note",
            "name": "too-many",
            "sources": too_many,
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(over.contains("at most 50"), "{over}");
}

#[tokio::test]
async fn basis_source_lines_are_validated_like_save_account() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let source_id = seed_source(&registry, &db, "source").await;

    let blank_reason = create(
        &registry,
        &db,
        Caller::local(),
        json!({
            "type": "Document",
            "kind": "note",
            "name": "blank-reason",
            "sources": [{ "record_id": source_id, "reason": "   " }],
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(blank_reason.contains("sources[0].reason"), "{blank_reason}");

    let blank_role = create(
        &registry,
        &db,
        Caller::local(),
        json!({
            "type": "Document",
            "kind": "note",
            "name": "blank-role",
            "sources": [{ "record_id": source_id, "reason": "ok", "role": "  " }],
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(blank_role.contains("sources[0].role"), "{blank_role}");

    let control_id = create(
        &registry,
        &db,
        Caller::local(),
        json!({
            "type": "Document",
            "kind": "note",
            "name": "control-id",
            "sources": [{ "record_id": "abc\u{7}", "reason": "ok" }],
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(control_id.contains("sources[0].record_id"), "{control_id}");
    assert!(control_id.contains("control characters"), "{control_id}");
}

#[tokio::test]
async fn null_sources_is_rejected_rather_than_meaning_not_declared() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();

    let on_create = create(
        &registry,
        &db,
        Caller::local(),
        json!({ "type": "Document", "kind": "note", "name": "null-sources", "sources": null }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        on_create.contains("'sources' must be an array"),
        "{on_create}"
    );
    assert!(on_create.contains("[]"), "{on_create}");

    let target_id = seed_source(&registry, &db, "target").await;
    let on_update = call(
        &registry,
        &db,
        Caller::local(),
        "update_record",
        json!({ "id": target_id, "summary": "x", "sources": null }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        on_update.contains("'sources' must be an array"),
        "{on_update}"
    );

    // A `create_many` item is a singular create, so it is refused per item.
    let batch = call(
        &registry,
        &db,
        Caller::local(),
        "create_many",
        json!({
            "reason": "null item sources",
            "records": [
                { "type": "Document", "kind": "note", "name": "null-item", "sources": null },
            ],
        }),
    )
    .await
    .unwrap();
    assert_eq!(batch["ok"], json!(false));
    let message = batch["errors"][0]["message"].as_str().unwrap();
    assert!(message.contains("'sources' must be an array"), "{message}");
}

#[tokio::test]
async fn update_record_stores_empty_sources_distinctly_from_absent() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let target_id = seed_source(&registry, &db, "target").await;

    let declared_none = call(
        &registry,
        &db,
        Caller::local(),
        "update_record",
        json!({ "id": target_id, "summary": "declared none", "sources": [] }),
    )
    .await
    .unwrap();
    assert_eq!(declared_none["basis"]["status"], json!("declared_none"));
    let payloads = updated_payloads(&db, &target_id).await;
    let last = payloads.last().unwrap();
    assert_eq!(last["basis"]["format"], json!("native.source-basis.v1"));
    assert_eq!(last["basis"]["sources"], json!([]));

    let absent = call(
        &registry,
        &db,
        Caller::local(),
        "update_record",
        json!({ "id": target_id, "summary": "absent" }),
    )
    .await
    .unwrap();
    assert!(absent.get("basis").is_none());
    let payloads = updated_payloads(&db, &target_id).await;
    assert!(
        payloads.last().unwrap().get("basis").is_none(),
        "an update with no declaration must store nothing"
    );
}

#[tokio::test]
async fn create_many_item_stores_empty_sources_distinctly_from_absent() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();

    let created = call(
        &registry,
        &db,
        Caller::local(),
        "create_many",
        json!({
            "reason": "empty vs absent per item",
            "records": [
                { "type": "Document", "kind": "note", "name": "declared-none", "sources": [] },
                { "type": "Document", "kind": "note", "name": "undeclared" },
            ],
        }),
    )
    .await
    .unwrap();
    assert_eq!(created["ok"], json!(true));

    let declared_none_id = created["ids"][0].as_str().unwrap();
    let payload = created_payload(&db, declared_none_id).await;
    assert_eq!(payload["basis"]["sources"], json!([]));

    let undeclared_id = created["ids"][1].as_str().unwrap();
    assert!(created_payload(&db, undeclared_id)
        .await
        .get("basis")
        .is_none());
}

#[tokio::test]
async fn a_facet_only_update_places_the_basis_on_the_first_facet_event() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    let target_id = seed_source(&registry, &db, "target").await;

    call(
        &registry,
        &db,
        Caller::local(),
        "update_record",
        json!({
            "id": target_id,
            "facets": { "area": "mcp", "phase": "draft" },
            "sources": [{ "record_id": target_id, "reason": "re-read before tagging" }],
        }),
    )
    .await
    .unwrap();

    assert!(
        updated_payloads(&db, &target_id).await.is_empty(),
        "a facet-only update emits no record.updated"
    );
    let facets = facet_set_payloads(&db, &target_id).await;
    assert_eq!(facets.len(), 2);
    assert_eq!(
        facets[0]["basis"]["sources"][0]["record_id"],
        json!(target_id),
        "the basis belongs to the first facet event this call emits"
    );
    assert!(
        facets[1].get("basis").is_none(),
        "the basis must not be copied onto later facet events"
    );
}
