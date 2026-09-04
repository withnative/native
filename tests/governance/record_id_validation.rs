use native_ce::events::EventRow;
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::store::{append, create_record_as, AppendSpec};
use native_ce::{create_database, Db};
use serde_json::{json, Value};
use uuid::Uuid;

const SHAPE_ERROR: &str = "record id must contain 1..=128 ASCII bytes using only [A-Za-z0-9._:-]";
const RESERVED_ERROR: &str = "record id prefix 'native:' is reserved for engine-owned records";
const UUID_ERROR: &str = "record id must be a canonical lowercase UUID of version 4 or 7";

/// A canonical lowercase v4 and v7. Hardcoded rather than generated so every
/// assertion below is deterministic.
const VALID_V4: &str = "4d0a20cc-48c3-4f20-a62b-799dc8ef8584";
const VALID_V7: &str = "01920b7a-6f2b-7c3d-8e4f-5a6b7c8d9e0f";

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

async fn counts(db: &Db) -> (i64, i64) {
    let events = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let records = sqlx::query_scalar("SELECT COUNT(*) FROM records")
        .fetch_one(db.pool())
        .await
        .unwrap();
    (events, records)
}

async fn create(registry: &ToolRegistry, db: &Db, id: Option<String>) -> native_ce::Result<Value> {
    let mut arguments = json!({
        "type": "Document",
        "kind": "note",
        "name": "Record id validation",
        "reason": "Exercise the record id admission contract."
    });
    if let Some(id) = id {
        arguments["id"] = json!(id);
    }
    registry
        .call(db.clone(), Caller::local(), "create_record", arguments)
        .await
}

#[tokio::test]
async fn mcp_and_store_create_paths_validate_before_writing() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    // The schema pattern must state the same rule the engine enforces, so a
    // rejected id fails at the tool boundary rather than deeper in.
    let schema = &registry.get("create_record").unwrap().input_schema["properties"]["id"];
    assert_eq!(
        schema["pattern"],
        "^[0-9a-f]{8}-[0-9a-f]{4}-[47][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    );
    assert!(schema.get("minLength").is_none());
    assert!(schema.get("maxLength").is_none());

    let initial = counts(&db).await;
    for id in [
        "",
        " ",
        "two words",
        " leading",
        "trailing ",
        "line\nbreak",
        "nul\0byte",
        "record/slash",
        "café",
        // Escaping-hostile: rejected on create, but renderers still have to
        // JSON-escape it on read — see the matching read-path test in
        // tests/records/render.rs, since un-admitted ids still reach the renderer.
        "a\"b\\c",
    ] {
        assert_eq!(
            create(&registry, &db, Some(id.into()))
                .await
                .unwrap_err()
                .to_string(),
            SHAPE_ERROR,
            "{id:?}"
        );
        assert_eq!(counts(&db).await, initial);
    }
    assert_eq!(
        create(&registry, &db, Some("a".repeat(129)))
            .await
            .unwrap_err()
            .to_string(),
        SHAPE_ERROR
    );
    assert_eq!(counts(&db).await, initial);
    for id in ["native:anything", native_ce::schema::ROOT_RECORD_ID] {
        assert_eq!(
            create(&registry, &db, Some(id.into()))
                .await
                .unwrap_err()
                .to_string(),
            RESERVED_ERROR
        );
        assert_eq!(counts(&db).await, initial);
    }

    assert_eq!(
        create_record_as(
            &db,
            json!({"id":"raw/slash","type":"Document","kind":"note"}),
            Some("test:record-id"),
        )
        .await
        .unwrap_err()
        .to_string(),
        SHAPE_ERROR
    );
    assert_eq!(counts(&db).await, initial);

    assert_eq!(
        append(
            &db,
            AppendSpec {
                record_id: "kernel/slash".into(),
                event_type: "record.created".into(),
                payload: json!({
                    "type":"Document", "kind":"note",
                    "home_id":native_ce::schema::UNFILED_RECORD_ID,
                    "persistence":"enduring"
                }),
                actor: Some("test:record-id".into()),
            },
        )
        .await
        .unwrap_err()
        .to_string(),
        SHAPE_ERROR
    );
    assert_eq!(counts(&db).await, initial);

    assert_eq!(
        append(
            &db,
            AppendSpec {
                record_id: "native:kernel-squat".into(),
                event_type: "record.created".into(),
                payload: json!({
                    "type":"Document", "kind":"note",
                    "home_id":native_ce::schema::UNFILED_RECORD_ID,
                    "persistence":"enduring"
                }),
                actor: Some("engine:seed".into()),
            },
        )
        .await
        .unwrap_err()
        .to_string(),
        RESERVED_ERROR
    );
    assert_eq!(counts(&db).await, initial);

    // Previously-valid shapes, now rejected on write. The 128-byte boundary was
    // the widest id the old shape rule admitted; the slugs are the shapes real
    // callers and fixtures used.
    for id in [
        "release-path-changes-merge-blind",
        "corpus:create:full",
        &"b".repeat(128),
    ] {
        assert_eq!(
            create(&registry, &db, Some(id.into()))
                .await
                .unwrap_err()
                .to_string(),
            UUID_ERROR,
            "{id:?}"
        );
        assert_eq!(counts(&db).await, initial);
    }

    // Canonical v4 and v7 are the only accepted caller-supplied ids.
    for id in [VALID_V4, VALID_V7] {
        assert_eq!(
            create(&registry, &db, Some(id.into())).await.unwrap()["id"],
            id
        );
    }
    let after_uuids = counts(&db).await;
    assert!(create(&registry, &db, Some(VALID_V4.into())).await.is_err());
    assert_eq!(counts(&db).await, after_uuids);

    // Deterministic UUID versions stay out. v5 is the load-bearing case: it is
    // a hash of (namespace, name), so two databases deriving one from the same
    // business key mint the IDENTICAL id — the cross-database collision this
    // rule exists to prevent. Do not "fix" this by widening the accepted set.
    for id in [
        "d9428888-122b-11e1-b85c-61cd3cbb3210", // v1, time/node derived
        "3d813cbb-47fb-32ba-91df-831e1593ac29", // v3, MD5 of namespace + name
        "886313e1-3b8a-5372-9b90-0c9aee199e5d", // v5, SHA-1 of namespace + name
        "00000000-0000-0000-0000-000000000000", // nil, no version at all
    ] {
        assert_eq!(
            create(&registry, &db, Some(id.into()))
                .await
                .unwrap_err()
                .to_string(),
            UUID_ERROR,
            "{id:?}"
        );
        assert_eq!(counts(&db).await, after_uuids);
    }

    // Uppercase and unhyphenated spellings of an otherwise valid v4 are
    // rejected by canonical round-trip, not by a second rule.
    for id in [
        "4D0A20CC-48C3-4F20-A62B-799DC8EF8584",
        "4d0a20cc48c34f20a62b799dc8ef8584",
    ] {
        assert_eq!(
            create(&registry, &db, Some(id.into()))
                .await
                .unwrap_err()
                .to_string(),
            UUID_ERROR,
            "{id:?}"
        );
        assert_eq!(counts(&db).await, after_uuids);
    }

    let generated = create(&registry, &db, None).await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let parsed = Uuid::parse_str(&generated).unwrap();
    assert_eq!(parsed.get_version(), Some(uuid::Version::Random));
    assert_eq!(parsed.hyphenated().to_string(), generated);
}

#[tokio::test]
async fn fresh_genesis_is_exact_and_historical_malformed_ids_still_replay() {
    let db = create_database(":memory:").await.unwrap();
    let seeded: Vec<String> =
        sqlx::query_scalar("SELECT id FROM records WHERE id LIKE 'native:%' ORDER BY id")
            .fetch_all(db.pool())
            .await
            .unwrap();
    assert_eq!(
        seeded,
        [
            native_ce::schema::ROOT_RECORD_ID,
            native_ce::schema::UNFILED_RECORD_ID,
        ]
    );
    let seeded_events: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM content_events WHERE type='record.created' AND record_id IN (?,?)",
    )
    .bind(native_ce::schema::ROOT_RECORD_ID)
    .bind(native_ce::schema::UNFILED_RECORD_ID)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(seeded_events, 2);

    let payload = json!({
        "type":"Document", "kind":"note",
        "home_id":native_ce::schema::UNFILED_RECORD_ID,
        "persistence":"enduring"
    })
    .to_string();
    let mut event = EventRow {
        local_seq: -1,
        id: "legacy-malformed-id-event".into(),
        record_id: "legacy/id".into(),
        event_type: "record.created".into(),
        payload: Some(payload),
        actor: Some("engine:migration".into()),
        run_key: None,
        parent_key: None,
        intent: None,
        created_at: "2026-01-01T00:00:00.000Z".into(),
        causal_envelope: native_ce::events::CausalEnvelopeV1::legacy_unknown(),
    };
    let pool = crate::common::fixture_write_pool(&db).await;
    let mut tx = pool.begin().await.unwrap();
    event.local_seq = sqlx::query_scalar(
        "INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) VALUES(?,?,?,?,?,?,1,'legacy_unknown') RETURNING seq",
    )
    .bind(&event.id)
    .bind(&event.record_id)
    .bind(&event.event_type)
    .bind(&event.payload)
    .bind(&event.actor)
    .bind(&event.created_at)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    native_ce::projector::project(&mut tx, &event)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    pool.close().await;

    let rebuilt = native_ce::conformance::rebuild_and_diff(&db).await.unwrap();
    assert!(rebuilt.equal, "{rebuilt:?}");
}
