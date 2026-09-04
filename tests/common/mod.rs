//! Shared helpers for the integration-test crates.
#![allow(dead_code)]

use native_ce::events::EventRow;
use native_ce::Db;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::Row;
use std::str::FromStr;
use std::time::Duration;

/// Open a deliberately privileged pool for fixture construction and corruption
/// tests. Production callers receive only `Db::pool()`'s physically read-only
/// observation pool; integration tests that must model malformed/historical
/// storage cross the file-owner boundary explicitly here.
pub async fn fixture_write_pool(db: &Db) -> sqlx::SqlitePool {
    let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", db.path().display()))
        .unwrap()
        .create_if_missing(false)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5));
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap()
}

/// Install one governed test kind through the same event-sourced vocabulary
/// lifecycle used by extensions. Idempotent for repeated fixture setup.
pub async fn govern_kind(db: &Db, record_type: &str, token: &str) {
    let vocabulary = format!("kind:{record_type}");
    native_ce::meta::create_vocabulary(db, &vocabulary, None)
        .await
        .unwrap();
    let resolution = native_ce::meta::kind::resolve(db, record_type, token)
        .await
        .unwrap();
    if !resolution.quarantined {
        return;
    }
    let id = native_ce::meta::propose_value_with_kind_metadata_as(
        db,
        &vocabulary,
        token,
        None,
        0.0,
        native_ce::meta::VocabularyValueTerminality::Open,
        Some(native_ce::meta::KindMetadataV1::legacy(record_type, token)),
        None,
    )
    .await
    .unwrap();
    native_ce::meta::promote_value(db, &id).await.unwrap();
}

/// Run a `SELECT ... AS n` scalar count query.
pub async fn count(db: &Db, sql: &str) -> i64 {
    sqlx::query(sql)
        .fetch_one(db.pool())
        .await
        .expect("count query")
        .get("n")
}

/// Fetch one nullable text column from a single-row query.
pub async fn text_of(db: &Db, sql: &str, column: &str) -> Option<String> {
    sqlx::query(sql)
        .fetch_one(db.pool())
        .await
        .expect("text query")
        .get(column)
}

/// Build a synthetic event row (the tests' analogue of the TS `ev()` helper).
pub fn ev(
    record_id: &str,
    event_type: &str,
    created_at: &str,
    payload: serde_json::Value,
) -> EventRow {
    EventRow {
        local_seq: 0,
        id: format!("{event_type}:{record_id}:{created_at}"),
        record_id: record_id.to_string(),
        event_type: event_type.to_string(),
        payload: Some(payload.to_string()),
        actor: None,
        run_key: None,
        parent_key: None,
        intent: None,
        created_at: created_at.to_string(),
        causal_envelope: native_ce::events::CausalEnvelopeV1::default(),
    }
}

/// Apply one synthetic event through the projector on a pooled connection.
pub async fn project_one(db: &Db, event: &EventRow) -> native_ce::Result<()> {
    let fixture_pool = fixture_write_pool(db).await;
    let mut conn = fixture_pool.acquire().await?;
    native_ce::projector::project(&mut conn, event).await
}

/// The six authoring tools that require a `reason` (spec fbfaf25 §3.1 plus
/// suggestion and citation resolution).
pub const REASON_REQUIRED_TOOLS: [&str; 6] = [
    "create_record",
    "update_record",
    "archive_record",
    "delete_record",
    "manage_citations",
    "resolve_suggestions",
];

/// Supply stand-in authoring fields for tests whose subject is something else.
///
/// Tests that are ABOUT the requirement pass their own value (or deliberately
/// omit it); everything else would otherwise have to restate a reason it does not
/// care about on every write, which buries the assertions under boilerplate. The
/// helper never overwrites a reason or kind the caller supplied, so tests
/// asserting either contract still control it. `x-test-fixture` is deliberately
/// a novel honest token: it exercises open-additive storage without pretending
/// to be a governed domain classification.
pub fn with_test_reason(tool: &str, mut args: serde_json::Value) -> serde_json::Value {
    if tool == "create_record" {
        if let Some(object) = args.as_object_mut() {
            object
                .entry("kind")
                .or_insert_with(|| serde_json::Value::String("x-test-fixture".into()));
        }
    }
    if !REASON_REQUIRED_TOOLS.contains(&tool) {
        return args;
    }
    if let Some(object) = args.as_object_mut() {
        object.entry("reason").or_insert_with(|| {
            serde_json::Value::String(
                "Test fixture write — this call's subject is not the reason field.".into(),
            )
        });
    }
    args
}
