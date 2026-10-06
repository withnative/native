//! Typed time facets and the `facet_times` projection (task fef3469, design
//! proposal D2 slice T2).
//!
//! A schema shape declares `date`, `instant`, `zoned` or `when`; supported
//! writers validate and store the normalised form, zoned values record the tz
//! database version, and the content projector keeps one `facet_times` row
//! per current typed value. Replay must reproduce every row.

use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::meta::seed_vocabularies;
use native_ce::typed_time::TZDB_VERSION;
use native_ce::{apply_schema, open_database, Db};
use serde_json::{json, Value};

/// Fixture record ids: canonical lowercase UUIDs, pinned literals.
const TASK: &str = "7e0e1000-0000-4000-8000-000000000001";
const OTHER: &str = "7e0e1000-0000-4000-8000-000000000002";
const HISTORICAL: &str = "7e0e1000-0000-4000-8000-000000000003";

async fn db() -> Db {
    let db = open_database(":memory:").await.unwrap();
    apply_schema(&db).await.unwrap();
    native_ce::seed_content_tier(&db).await.unwrap();
    native_ce::identity::seed_database_identity(&db)
        .await
        .unwrap();
    seed_vocabularies(&db).await.unwrap();
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

/// The shape every test here writes: one facet of each typed time type on
/// notes, plus a `when` that refuses DST-ambiguous wall times.
async fn declare_time_facets(registry: &ToolRegistry, db: &Db) -> Value {
    call(
        registry,
        db,
        "manage_schema_config",
        json!({ "action": "write", "data": { "shapes": { "Document:note": { "facets": {
            "due": { "type": "date" },
            "logged_at": { "type": "instant" },
            "call": { "type": "zoned" },
            "slot": { "type": "when" },
            "strict_slot": { "type": "when", "disambiguation": "reject" },
        } } } } }),
    )
    .await
}

async fn create_task(registry: &ToolRegistry, db: &Db, id: &str, facets: Value) {
    call(
        registry,
        db,
        "create_record",
        json!({ "id": id, "type": "Document", "kind": "note", "name": "Typed time", "facets": facets }),
    )
    .await;
}

async fn stored_value(db: &Db, id: &str, key: &str) -> Option<String> {
    sqlx::query_scalar("SELECT value FROM facet_values WHERE record_id = ? AND key = ?")
        .bind(id)
        .bind(key)
        .fetch_optional(db.pool())
        .await
        .unwrap()
}

type TimeRow = (
    String,
    String,
    i64,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<i64>,
    Option<String>,
    Option<String>,
);

/// `(key, kind, all_day, start_date, end_date, start_ms, end_ms, tz,
/// tzdb_version)` for one record, ordered by key.
async fn time_rows(db: &Db, id: &str) -> Vec<TimeRow> {
    sqlx::query_as(
        "SELECT key, kind, all_day, start_date, end_date, start_ms, end_ms, tz, tzdb_version
           FROM facet_times WHERE record_id = ? ORDER BY key",
    )
    .bind(id)
    .fetch_all(db.pool())
    .await
    .unwrap()
}

fn ms(instant: &str) -> i64 {
    chrono::DateTime::parse_from_rfc3339(instant)
        .unwrap()
        .timestamp_millis()
}

async fn assert_replay_converges(db: &Db) {
    let result = native_ce::conformance::rebuild_and_diff(db).await.unwrap();
    assert!(
        result.equal,
        "facet_times must converge under replay: {}",
        serde_json::to_string_pretty(&result.tables).unwrap()
    );
}

#[tokio::test]
async fn schema_config_admits_time_types_and_their_disambiguation_only() {
    let db = db().await;
    let registry = registry();
    let written = declare_time_facets(&registry, &db).await;
    assert_eq!(written["nonconforming_stored_values"], 0);
    let read = call(
        &registry,
        &db,
        "manage_schema_config",
        json!({ "action": "read" }),
    )
    .await;
    assert_eq!(
        read["declared_facet_types"],
        json!(["number", "object", "date", "instant", "zoned", "when"])
    );
    for (facet, expected) in [
        (json!({ "type": "datetime" }), "supported declared types"),
        (
            json!({ "type": "date", "disambiguation": "reject" }),
            "applies only to type `zoned` or `when`",
        ),
        (
            json!({ "disambiguation": "compatible" }),
            "applies only to type `zoned` or `when`",
        ),
        (
            json!({ "type": "zoned", "disambiguation": "later" }),
            "use `compatible`",
        ),
        (
            json!({ "type": "when", "json_schema": { "type": "object" } }),
            "json_schema only with type: \"object\"",
        ),
    ] {
        let err = call_err(
            &registry,
            &db,
            "manage_schema_config",
            json!({ "action": "write", "data": { "shapes": { "Document:note": {
                "facets": { "due": facet }
            } } } }),
        )
        .await;
        assert!(err.contains(expected), "{facet}: {err}");
    }
}

#[tokio::test]
async fn declared_time_values_are_validated_normalised_and_versioned() {
    let db = db().await;
    let registry = registry();
    declare_time_facets(&registry, &db).await;
    create_task(
        &registry,
        &db,
        TASK,
        json!({
            "due": "2026-10-05",
            "logged_at": "2026-10-05T10:00:00+01:00",
            "call": { "local": "2026-10-05T10:00", "tz": "Europe/London" },
            "notes_date": "5 Oct",
        }),
    )
    .await;
    assert_eq!(stored_value(&db, TASK, "due").await.unwrap(), "2026-10-05");
    assert_eq!(
        stored_value(&db, TASK, "logged_at").await.unwrap(),
        "2026-10-05T09:00:00.000Z"
    );
    let call_value: Value =
        serde_json::from_str(&stored_value(&db, TASK, "call").await.unwrap()).unwrap();
    assert_eq!(
        call_value,
        json!({ "local": "2026-10-05T10:00", "tz": "Europe/London", "offset": "+01:00", "tzdb": TZDB_VERSION })
    );
    // An undeclared facet is untouched and never projected.
    assert_eq!(
        stored_value(&db, TASK, "notes_date").await.unwrap(),
        "5 Oct"
    );
    let rows = time_rows(&db, TASK).await;
    assert_eq!(
        rows,
        vec![
            (
                "call".into(),
                "zoned".into(),
                0,
                None,
                None,
                Some(ms("2026-10-05T09:00:00Z")),
                Some(ms("2026-10-05T09:00:00Z")),
                Some("Europe/London".into()),
                Some(TZDB_VERSION.into()),
            ),
            (
                "due".into(),
                "date".into(),
                1,
                Some("2026-10-05".into()),
                Some("2026-10-06".into()),
                None,
                None,
                None,
                None,
            ),
            (
                "logged_at".into(),
                "instant".into(),
                0,
                None,
                None,
                Some(ms("2026-10-05T09:00:00Z")),
                Some(ms("2026-10-05T09:00:00Z")),
                None,
                None,
            ),
        ]
    );

    for (facets, expected) in [
        (json!({ "due": "05/10/2026" }), "is declared type 'date'"),
        (json!({ "due": 20261005 }), "is not a date"),
        (
            json!({ "logged_at": "2026-10-05T10:00" }),
            "is not an instant",
        ),
        (
            json!({ "call": "2026-10-05T10:00" }),
            "zoned value must be an object",
        ),
        (
            json!({ "call": { "local": "2026-10-05T10:00", "tz": "Europe/Atlantis" } }),
            "not a known IANA time zone",
        ),
        (
            json!({ "call": { "local": "2026-07-01T10:00", "tz": "Europe/London", "offset": "+00:00" } }),
            "offset +00:00 is not valid",
        ),
    ] {
        let err = call_err(
            &registry,
            &db,
            "update_record",
            json!({ "id": TASK, "facets": facets }),
        )
        .await;
        assert!(err.contains(expected), "{facets}: {err}");
    }
    // Refused writes change nothing.
    assert_eq!(time_rows(&db, TASK).await, rows);
    assert_replay_converges(&db).await;
}

#[tokio::test]
async fn when_values_cover_all_day_instants_zones_across_dst_and_refuse_end_before_start() {
    let db = db().await;
    let registry = registry();
    declare_time_facets(&registry, &db).await;
    create_task(
        &registry,
        &db,
        TASK,
        json!({ "slot": { "all_day": true, "start": "2026-10-05", "end": "2026-10-07" } }),
    )
    .await;
    assert_eq!(
        time_rows(&db, TASK).await,
        vec![(
            "slot".into(),
            "when".into(),
            1,
            Some("2026-10-05".into()),
            Some("2026-10-07".into()),
            None,
            None,
            None,
            None,
        )]
    );

    // Timed, on the UTC timeline, with a duration resolved to end.
    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": TASK, "facets": { "slot": {
            "all_day": false, "start": "2026-10-05T09:00:00Z", "duration": "PT30M"
        } } }),
    )
    .await;
    let stored: Value =
        serde_json::from_str(&stored_value(&db, TASK, "slot").await.unwrap()).unwrap();
    assert_eq!(
        stored,
        json!({ "all_day": false, "start": "2026-10-05T09:00:00.000Z", "end": "2026-10-05T09:30:00.000Z" })
    );
    let row = &time_rows(&db, TASK).await[0];
    assert_eq!(
        (row.2, row.5, row.6),
        (
            0,
            Some(ms("2026-10-05T09:00:00Z")),
            Some(ms("2026-10-05T09:30:00Z"))
        )
    );

    // Timed and zoned across London's autumn change: one nominal day keeps
    // 10:00 on the wall clock, so it lasts 25 hours.
    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": TASK, "facets": { "slot": {
            "all_day": false,
            "start": { "local": "2026-10-24T10:00", "tz": "Europe/London" },
            "duration": "P1D",
        } } }),
    )
    .await;
    let stored: Value =
        serde_json::from_str(&stored_value(&db, TASK, "slot").await.unwrap()).unwrap();
    assert_eq!(
        stored["end"],
        json!({ "local": "2026-10-25T10:00", "tz": "Europe/London", "offset": "+00:00", "tzdb": TZDB_VERSION })
    );
    let row = &time_rows(&db, TASK).await[0];
    assert_eq!(row.5, Some(ms("2026-10-24T09:00:00Z")));
    assert_eq!(row.6, Some(ms("2026-10-25T10:00:00Z")));
    assert_eq!(row.6.unwrap() - row.5.unwrap(), 25 * 3_600_000);
    assert_eq!(row.7.as_deref(), Some("Europe/London"));
    assert_eq!(row.8.as_deref(), Some(TZDB_VERSION));

    for (slot, expected) in [
        (
            json!({ "all_day": false, "start": "2026-10-05T10:00:00Z", "end": "2026-10-05T09:00:00Z" }),
            "cannot end before it starts",
        ),
        (
            json!({ "all_day": true, "start": "2026-10-07", "end": "2026-10-05" }),
            "cannot end before it starts",
        ),
        (
            json!({ "all_day": true, "start": "2026-10-05", "end": "2026-10-05" }),
            "must cover at least one day",
        ),
        (
            json!({ "all_day": false, "start": "2026-10-05T09:00:00Z", "duration": "PT1H", "rrule": "FREQ=WEEKLY" }),
            "recurrence",
        ),
    ] {
        let err = call_err(
            &registry,
            &db,
            "update_record",
            json!({ "id": TASK, "facets": { "slot": slot } }),
        )
        .await;
        assert!(err.contains(expected), "{slot}: {err}");
    }

    // The shape's disambiguation governs DST gaps: compatible moves 01:30
    // forward past London's spring gap, reject refuses it.
    let gap = json!({
        "all_day": false,
        "start": { "local": "2026-03-29T01:30", "tz": "Europe/London" },
        "duration": "PT1H",
    });
    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": TASK, "facets": { "slot": gap } }),
    )
    .await;
    let stored: Value =
        serde_json::from_str(&stored_value(&db, TASK, "slot").await.unwrap()).unwrap();
    assert_eq!(stored["start"]["local"], json!("2026-03-29T02:30"));
    let err = call_err(
        &registry,
        &db,
        "update_record",
        json!({ "id": TASK, "facets": { "strict_slot": gap } }),
    )
    .await;
    assert!(err.contains("does not exist in Europe/London"), "{err}");
    assert_replay_converges(&db).await;
}

#[tokio::test]
async fn facet_times_follow_set_update_and_unset() {
    let db = db().await;
    let registry = registry();
    declare_time_facets(&registry, &db).await;
    create_task(&registry, &db, TASK, json!({ "due": "2026-10-05" })).await;
    create_task(&registry, &db, OTHER, json!({ "due": "2026-11-01" })).await;
    assert_eq!(
        time_rows(&db, TASK).await[0].3.as_deref(),
        Some("2026-10-05")
    );

    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": TASK, "facets": { "due": "2026-10-09" } }),
    )
    .await;
    let rows = time_rows(&db, TASK).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].3.as_deref(), Some("2026-10-09"));
    assert_eq!(rows[0].4.as_deref(), Some("2026-10-10"));

    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": TASK, "facets": { "due": null } }),
    )
    .await;
    assert!(time_rows(&db, TASK).await.is_empty());
    // Unsetting one record's facet leaves another's alone.
    assert_eq!(time_rows(&db, OTHER).await.len(), 1);

    // A valid-time observation does not move the current projection.
    call(
        &registry,
        &db,
        "manage_facet_observations",
        json!({ "action": "set", "record_id": OTHER, "key": "due", "value": "2026-01-01", "as_of": "2026-01-01T00:00:00Z", "reason": "Earlier due date." }),
    )
    .await;
    assert_eq!(
        time_rows(&db, OTHER).await[0].3.as_deref(),
        Some("2026-11-01")
    );
    assert_replay_converges(&db).await;
}

/// Declaring a type is forward-only: a value stored before is reported if it
/// would not be accepted, is not rewritten, and joins `facet_times` only when
/// next written through a supported writer.
#[tokio::test]
async fn declaring_a_time_type_reports_but_never_rewrites_history() {
    let db = db().await;
    let registry = registry();
    create_task(
        &registry,
        &db,
        HISTORICAL,
        json!({ "due": "someday", "logged_at": "2026-10-05T10:00:00+01:00" }),
    )
    .await;
    let written = declare_time_facets(&registry, &db).await;
    // `someday` is not a date; the un-normalised instant is still valid.
    assert_eq!(written["nonconforming_stored_values"], 1);
    assert_eq!(
        stored_value(&db, HISTORICAL, "due").await.unwrap(),
        "someday"
    );
    assert_eq!(
        stored_value(&db, HISTORICAL, "logged_at").await.unwrap(),
        "2026-10-05T10:00:00+01:00"
    );
    assert!(time_rows(&db, HISTORICAL).await.is_empty());
    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": HISTORICAL, "facets": { "logged_at": "2026-10-05T10:00:00+01:00" } }),
    )
    .await;
    assert_eq!(time_rows(&db, HISTORICAL).await.len(), 1);
    assert_replay_converges(&db).await;
}

/// Declare `slot` (when) and `call` (zoned) on every Document kind and on
/// Entity organizations, so a record keeps the same typed facets across a
/// kind change or a type correction.
async fn declare_across_shapes(registry: &ToolRegistry, db: &Db) {
    let facets = json!({
        "slot": { "type": "when" },
        "call": { "type": "zoned" },
    });
    call(
        registry,
        db,
        "manage_schema_config",
        json!({ "action": "write", "data": { "shapes": {
            "Document": { "facets": facets },
            "Entity:organization": { "facets": facets },
        } } }),
    )
    .await;
}

async fn create_typed_note(registry: &ToolRegistry, db: &Db) -> (String, String) {
    create_task(
        registry,
        db,
        TASK,
        json!({
            "slot": { "all_day": false, "start": { "local": "2026-10-05T10:00", "tz": "Europe/London" }, "duration": "PT30M" },
            "call": { "local": "2026-10-05T10:00", "tz": "Europe/London" },
        }),
    )
    .await;
    (
        stored_value(db, TASK, "slot").await.unwrap(),
        stored_value(db, TASK, "call").await.unwrap(),
    )
}

/// Review finding: a shape-context change revalidates the stored facets,
/// and the snapshot rebuilt stored `when`/`zoned` values as strings, which
/// their declared types refused. They are decoded back to objects, so the
/// change succeeds and the stored values and rows are left exactly as they
/// were.
#[tokio::test]
async fn kind_change_keeps_stored_when_and_zoned_facets() {
    let db = db().await;
    let registry = registry();
    declare_across_shapes(&registry, &db).await;
    let (slot, zoned) = create_typed_note(&registry, &db).await;
    let rows = time_rows(&db, TASK).await;
    assert_eq!(rows.len(), 2);

    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": TASK, "kind": "handoff" }),
    )
    .await;
    let kind: String = sqlx::query_scalar("SELECT kind FROM records WHERE id = ?")
        .bind(TASK)
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(kind, "handoff");
    assert_eq!(stored_value(&db, TASK, "slot").await.unwrap(), slot);
    assert_eq!(stored_value(&db, TASK, "call").await.unwrap(), zoned);
    assert_eq!(time_rows(&db, TASK).await, rows);

    // A kind change beside an ordinary facet write behaves the same.
    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": TASK, "kind": "note", "facets": { "topic": "planning" } }),
    )
    .await;
    assert_eq!(time_rows(&db, TASK).await, rows);
    // An untyped facet holding object-looking text is still a string.
    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": TASK, "facets": { "topic": "{\"local\":\"x\"}" } }),
    )
    .await;
    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": TASK, "kind": "handoff" }),
    )
    .await;
    assert_eq!(
        stored_value(&db, TASK, "topic").await.unwrap(),
        "{\"local\":\"x\"}"
    );
    assert_replay_converges(&db).await;
}

/// Public readers decode `zoned` and `when` values to objects, as they do
/// for declared `object` facets; `date` and `instant` stay strings.
#[tokio::test]
async fn record_readers_return_typed_time_objects() {
    let db = db().await;
    let registry = registry();
    declare_time_facets(&registry, &db).await;
    create_task(
        &registry,
        &db,
        TASK,
        json!({
            "due": "2026-10-05",
            "call": { "local": "2026-10-05T10:00", "tz": "Europe/London" },
            "slot": { "all_day": true, "start": "2026-10-05", "end": "2026-10-06" },
        }),
    )
    .await;
    let read = call(&registry, &db, "get_record", json!({ "ids": [TASK] })).await;
    let facets = read["records"][0]["facets"].as_array().unwrap().clone();
    let value = |key: &str| {
        facets
            .iter()
            .find(|facet| facet["key"] == key)
            .unwrap_or_else(|| panic!("{key} in {facets:?}"))["value"]
            .clone()
    };
    assert_eq!(value("due"), json!("2026-10-05"));
    assert_eq!(
        value("call"),
        json!({ "local": "2026-10-05T10:00", "tz": "Europe/London", "offset": "+01:00", "tzdb": TZDB_VERSION })
    );
    assert_eq!(
        value("slot"),
        json!({ "all_day": true, "start": "2026-10-05", "end": "2026-10-06" })
    );
    let resolved = call(
        &registry,
        &db,
        "resolve_facets",
        json!({ "record_id": TASK }),
    )
    .await;
    let resolved = resolved.to_string();
    assert!(
        resolved.contains("\"offset\":\"+01:00\""),
        "resolve_facets decodes the zoned object: {resolved}"
    );
}

/// Orchestrator decision (fef3469 T2 review): readers decode by the current
/// declaration, not by how a value was written, the same as for `object`.
/// Text stored as an untyped string reads back as an object once its key is
/// declared `zoned`; the stored text is untouched and, having no
/// `time_kind` provenance, it never joins `facet_times`.
#[tokio::test]
async fn reads_follow_the_current_declaration_not_write_provenance() {
    let db = db().await;
    let registry = registry();
    let text = r#"{"local":"2026-10-05T10:00","tz":"Europe/London"}"#;
    create_task(&registry, &db, TASK, json!({ "call": text })).await;
    let read_call = || async {
        let read = call(&registry, &db, "get_record", json!({ "ids": [TASK] })).await;
        read["records"][0]["facets"]
            .as_array()
            .unwrap()
            .iter()
            .find(|facet| facet["key"] == "call")
            .unwrap()["value"]
            .clone()
    };
    assert_eq!(read_call().await, json!(text));
    declare_time_facets(&registry, &db).await;
    assert_eq!(
        read_call().await,
        json!({ "local": "2026-10-05T10:00", "tz": "Europe/London" })
    );
    assert_eq!(stored_value(&db, TASK, "call").await.unwrap(), text);
    assert!(time_rows(&db, TASK).await.is_empty());
}
