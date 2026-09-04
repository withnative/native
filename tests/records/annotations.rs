//! The caller-stamped annotation columns (spec fbfaf25 §2.1, §5.3, §6).
//!
//! Two properties, both of which exist because the columns are ANNOTATIONS —
//! nullable, caller-supplied, informing read-time projections and gating nothing:
//!
//!   1. **Projector isolation.** The fold reads none of `run_key`, `parent_key`,
//!      `intent` or `actor`. `rebuild-and-diff` is only sound while that holds.
//!   2. **Lineage termination.** `parent_key` is an unverified assertion, so the
//!      walk over it must survive a cycle and a deep chain.

use native_ce::query::lineage::{lineage_walk, LineageEnd, MAX_LINEAGE_DEPTH};
use native_ce::schema::PROJECTION_TABLES;
use native_ce::{create_database, Db};
use sqlx::Row;

// ---------------------------------------------------------------------------
// 1. Projector isolation
// ---------------------------------------------------------------------------

/// Insert one event directly into the log, with full control of the annotation
/// columns, then fold it. Bypasses `store` on purpose: the point is to feed the
/// projector two logs that differ ONLY in the annotations, which the write API
/// gives no way to express.
async fn append_and_project(
    db: &Db,
    seq_id: &str,
    record_id: &str,
    event_type: &str,
    payload: &str,
    annotations: Option<(&str, &str, &str, &str)>,
) {
    let (actor, run_key, parent_key, intent) = match annotations {
        Some(values) => (
            Some(values.0),
            Some(values.1),
            Some(values.2),
            Some(values.3),
        ),
        None => (None, None, None, None),
    };
    let row = sqlx::query(
        "INSERT INTO content_events
             (id, record_id, type, payload, actor, run_key, parent_key, intent, created_at, causal_envelope_version, causal_status)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, '2027-01-01T00:00:00.000Z', 1, 'legacy_unknown')
           RETURNING seq",
    )
    .bind(seq_id)
    .bind(record_id)
    .bind(event_type)
    .bind(payload)
    .bind(actor)
    .bind(run_key)
    .bind(parent_key)
    .bind(intent)
    .fetch_one(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap();

    let event = native_ce::events::EventRow {
        local_seq: row.try_get("seq").unwrap(),
        id: seq_id.to_string(),
        record_id: record_id.to_string(),
        event_type: event_type.to_string(),
        payload: Some(payload.to_string()),
        actor: actor.map(String::from),
        run_key: run_key.map(String::from),
        parent_key: parent_key.map(String::from),
        intent: intent.map(String::from),
        created_at: "2027-01-01T00:00:00.000Z".into(),
        causal_envelope: native_ce::events::CausalEnvelopeV1::legacy_unknown(),
    };
    let mut conn = crate::common::fixture_write_pool(db)
        .await
        .acquire()
        .await
        .unwrap();
    native_ce::projector::project(&mut conn, &event)
        .await
        .unwrap();
}

/// Dump every projection table, every column, as a single comparable string.
async fn projection_fingerprint(db: &Db) -> String {
    let mut out = String::new();
    for table in PROJECTION_TABLES {
        // Ordering by every selected column gives a stable fingerprint without
        // assuming that every projection has an `id` column. Positional terms
        // also keep this self-updating as projection schemas evolve.
        let columns = sqlx::query(&format!("PRAGMA table_info({table})"))
            .fetch_all(db.pool())
            .await
            .unwrap();
        assert!(
            !columns.is_empty(),
            "projection table {table} has no columns"
        );
        let order = (1..=columns.len())
            .map(|position| position.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let sql = if table == "records" {
            format!(
                "SELECT * FROM records WHERE id NOT IN ('native:root', 'native:unfiled') ORDER BY {order}"
            )
        } else {
            format!("SELECT * FROM {table} ORDER BY {order}")
        };
        let rows = sqlx::query(&sql).fetch_all(db.pool()).await.unwrap();
        out.push_str(table);
        for row in rows {
            for i in 0..row.len() {
                let cell: Option<String> = row.try_get(i).unwrap_or(None);
                out.push('|');
                out.push_str(cell.as_deref().unwrap_or("<null>"));
            }
            out.push('\n');
        }
    }
    out
}

/// The fold reads NONE of the four annotation columns.
///
/// Asserted behaviourally rather than by reading the projector's source, because
/// the risk this guards against is not a stray SELECT — it is someone later
/// projecting `actor` or `intent` onto `records` "for convenience" and thereby
/// making a forgeable, caller-supplied value load-bearing for truth. A source
/// grep would not catch that arriving through a helper; identical projections
/// from differently-annotated logs does.
#[tokio::test]
async fn the_fold_ignores_run_key_parent_key_intent_and_actor() {
    let annotated = create_database(":memory:").await.unwrap();
    let bare = create_database(":memory:").await.unwrap();

    let events: [(&str, &str, &str, &str); 4] = [
        (
            "e1",
            "rec:1",
            "record.created",
            r#"{"type":"Document","kind":"note","name":"Annotated","home_id":"native:unfiled"}"#,
        ),
        (
            "e2",
            "rec:1",
            "record.updated",
            r#"{"summary":"A summary."}"#,
        ),
        ("e3", "rec:1", "facet.set", r#"{"key":"stage","value":"x"}"#),
        (
            "e4",
            "rec:2",
            "record.created",
            r#"{"type":"WorkItem","kind":"task","name":"Second","home_id":"native:unfiled"}"#,
        ),
    ];

    for (id, record_id, event_type, payload) in events {
        append_and_project(
            &annotated,
            id,
            record_id,
            event_type,
            payload,
            // Every annotation populated, and deliberately misleading: an `actor`
            // that is not the writer, an `intent` that contradicts the payload.
            // If any of it reached a projection, the comparison below breaks.
            Some((
                "impostor-actor",
                "scout-jam-d748b2",
                "pilot-reef-e748b2",
                "declared intent that must not surface in truth",
            )),
        )
        .await;
        append_and_project(&bare, id, record_id, event_type, payload, None).await;
    }

    assert_eq!(
        projection_fingerprint(&annotated).await,
        projection_fingerprint(&bare).await,
        "the projector's output changed when only the caller-stamped annotation \
         columns changed — the fold has grown a dependency on run_key / \
         parent_key / intent / actor, which makes a forgeable value load-bearing \
         for truth and silently invalidates rebuild-and-diff"
    );

    annotated.close().await;
    bare.close().await;
}

// ---------------------------------------------------------------------------
// 2. Lineage: cycle and depth
// ---------------------------------------------------------------------------

/// Record a run's asserted parent by writing one content event carrying it.
async fn assert_parent(db: &Db, run_key: &str, parent_key: &str) {
    sqlx::query(
        "INSERT INTO content_events
             (id, record_id, type, payload, run_key, parent_key, created_at, causal_envelope_version, causal_status)
           VALUES (?, 'rec:lineage', 'record.updated', '{}', ?, ?, '2027-01-01T00:00:00.000Z', 1, 'legacy_unknown')",
    )
    .bind(format!("lin:{run_key}"))
    .bind(run_key)
    .bind(parent_key)
    .execute(&crate::common::fixture_write_pool(db).await)
    .await
    .unwrap();
}

/// A mutually-asserting pair returns a truncated path, PROMPTLY, rather than
/// hanging. The timeout is the assertion that matters — omitting cycle detection
/// produces a hang, not a wrong answer, and a hang is the worse failure.
#[tokio::test]
async fn a_mutually_asserting_parent_pair_truncates_rather_than_hanging() {
    let db = create_database(":memory:").await.unwrap();
    assert_parent(&db, "scout-jam-d748b2", "pilot-reef-e748b2").await;
    assert_parent(&db, "pilot-reef-e748b2", "scout-jam-d748b2").await;

    let lineage = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        lineage_walk(&db, "scout-jam-d748b2"),
    )
    .await
    .expect("the lineage walk hung on a cycle — it needs cycle detection, not a longer timeout")
    .unwrap();

    assert_eq!(lineage.end, LineageEnd::Cycle);
    assert!(lineage.truncated);
    assert_eq!(
        lineage.path,
        vec![
            "scout-jam-d748b2".to_string(),
            "pilot-reef-e748b2".to_string()
        ],
        "the cycle should truncate at the point it closed, with no key repeated"
    );

    db.close().await;
}

/// A run asserting ITSELF as parent is the degenerate cycle, and the one most
/// likely to arrive by a copy-paste.
#[tokio::test]
async fn a_self_asserting_parent_truncates_at_one() {
    let db = create_database(":memory:").await.unwrap();
    assert_parent(&db, "scout-jam-d748b2", "scout-jam-d748b2").await;

    let lineage = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        lineage_walk(&db, "scout-jam-d748b2"),
    )
    .await
    .expect("the lineage walk hung on a self-referential parent")
    .unwrap();

    assert_eq!(lineage.end, LineageEnd::Cycle);
    assert_eq!(lineage.path, vec!["scout-jam-d748b2".to_string()]);

    db.close().await;
}

/// An acyclic chain longer than the cap truncates at the cap rather than walking
/// it out.
#[tokio::test]
async fn a_chain_deeper_than_the_cap_truncates_at_the_cap() {
    let db = create_database(":memory:").await.unwrap();
    let chain: Vec<String> = (0..MAX_LINEAGE_DEPTH + 10)
        .map(|i| format!("scout-link-{i:03}"))
        .collect();
    for pair in chain.windows(2) {
        assert_parent(&db, &pair[0], &pair[1]).await;
    }

    let lineage = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        lineage_walk(&db, &chain[0]),
    )
    .await
    .expect("the lineage walk hung on a deep chain")
    .unwrap();

    assert_eq!(lineage.end, LineageEnd::DepthCap);
    assert!(lineage.truncated);
    assert_eq!(lineage.path.len(), MAX_LINEAGE_DEPTH);

    db.close().await;
}

/// The ordinary case still works: a short chain to a genuine root reports itself
/// as complete. Without this, every assertion above would pass on a walk that
/// simply always truncates.
#[tokio::test]
async fn a_rooted_chain_is_not_reported_as_truncated() {
    let db = create_database(":memory:").await.unwrap();
    assert_parent(&db, "scout-jam-d748b2", "pilot-reef-e748b2").await;
    assert_parent(&db, "pilot-reef-e748b2", "envoy-dune-h748b2").await;

    let lineage = lineage_walk(&db, "scout-jam-d748b2").await.unwrap();
    assert_eq!(lineage.end, LineageEnd::Rooted);
    assert!(!lineage.truncated);
    assert_eq!(lineage.path.len(), 3);

    db.close().await;
}

/// The walk must survive the read log being dropped — resolution degrades, the
/// call does not fail.
#[tokio::test]
async fn the_walk_degrades_rather_than_failing_without_the_read_log() {
    let db = create_database(":memory:").await.unwrap();
    for statement in ["DROP TABLE read_log_touches", "DROP TABLE read_log_calls"] {
        sqlx::query(statement)
            .execute(&crate::common::fixture_write_pool(&db).await)
            .await
            .unwrap();
    }
    assert_parent(&db, "scout-jam-d748b2", "pilot-reef-e748b2").await;

    let lineage = lineage_walk(&db, "scout-jam-d748b2").await.unwrap();
    assert_eq!(lineage.end, LineageEnd::Rooted);
    assert_eq!(lineage.path.len(), 2);

    db.close().await;
}
