//! The `embed()` seam (decision `3bc7fd0`) — the no-op write-path hook semantic
//! search will hang off later.
//!
//! Two things are worth pinning about a hook that does nothing: **exactly which
//! mutations fire it** (a seam that misses a text change serves a stale vector
//! forever; one that fires on lifecycle churn burns an embedding budget), and
//! that it is **dormant and additive** — no `embeddings` rows, no DDL change, no
//! effect on rebuild-and-diff. Both are executable here rather than asserted in
//! a comment.

use std::sync::{Arc, Mutex};

use futures::future::{BoxFuture, FutureExt};
use native_ce::conformance::rebuild_and_diff;
use native_ce::embed::{Embedder, TextChange, TextChangeKind};
use native_ce::events::{FacetSetPayload, LinkAddedPayload};
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::store::{
    add_link, archive_record, create_record, delete_record, restore_record, set_facet, unset_facet,
    update_record, update_record_when_lifecycle,
};
use native_ce::{create_database, Db, Result};
use serde_json::{json, Value};
use sqlx::SqliteConnection;

use crate::common::count;

/// One call of the seam, flattened so a test can compare whole vectors.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Seen {
    record_id: String,
    kind: TextChangeKind,
    seq: i64,
}

/// An [`Embedder`] that records what it was handed and writes nothing.
#[derive(Debug, Default)]
struct Recorder {
    seen: Mutex<Vec<Seen>>,
}

impl Recorder {
    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    fn ids(&self) -> Vec<String> {
        self.seen().into_iter().map(|s| s.record_id).collect()
    }
}

impl Embedder for Recorder {
    fn on_text_changed<'a>(
        &'a self,
        _conn: &'a mut SqliteConnection,
        change: TextChange<'a>,
    ) -> BoxFuture<'a, Result<()>> {
        async move {
            assert!(
                !change.at.is_empty(),
                "the seam carries the event's timestamp, not now()"
            );
            self.seen.lock().unwrap().push(Seen {
                record_id: change.record_id.to_string(),
                kind: change.kind,
                seq: change.seq,
            });
            Ok(())
        }
        .boxed()
    }
}

/// An embedder that populates the dormant `embeddings` table — the shape a
/// hosted tier fills in. Stands in for the real thing: a fixed byte vector
/// instead of a provider call, because the point under test is that the seam
/// *reaches* `embeddings` transactionally, not what goes in it.
#[derive(Debug)]
struct WritesEmbeddings;

impl Embedder for WritesEmbeddings {
    fn on_text_changed<'a>(
        &'a self,
        conn: &'a mut SqliteConnection,
        change: TextChange<'a>,
    ) -> BoxFuture<'a, Result<()>> {
        async move {
            sqlx::query(
                "INSERT INTO embeddings (record_id, provider, dim, vector, updated_at)
                   VALUES (?, 'test', 2, ?, ?)
                   ON CONFLICT (record_id) DO UPDATE SET
                     vector = excluded.vector, updated_at = excluded.updated_at",
            )
            .bind(change.record_id)
            .bind(vec![0u8, 1u8])
            .bind(change.at)
            .execute(conn)
            .await?;
            Ok(())
        }
        .boxed()
    }
}

/// An embedder that always refuses — for the rollback contract.
#[derive(Debug)]
struct Refuses;

impl Embedder for Refuses {
    fn on_text_changed<'a>(
        &'a self,
        _conn: &'a mut SqliteConnection,
        _change: TextChange<'a>,
    ) -> BoxFuture<'a, Result<()>> {
        async { Err(native_ce::Error::engine("embedder refused")) }.boxed()
    }
}

async fn db() -> Db {
    create_database(":memory:").await.unwrap()
}

async fn recording_db() -> (Db, Arc<Recorder>) {
    let recorder = Arc::new(Recorder::default());
    let db = db().await.with_embedder(recorder.clone());
    (db, recorder)
}

async fn seed(db: &Db, name: &str) -> String {
    create_record(
        db,
        json!({ "type": "Document", "kind": "note", "name": name }),
    )
    .await
    .unwrap()
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

// ---------------------------------------------------------------------------
// Dormancy — the v1 state
// ---------------------------------------------------------------------------

/// With no embedder installed — every v1 deployment — a full session of writes
/// leaves `embeddings` empty. "Dormant" is a claim about the table, not just
/// about the absence of a vec index.
#[tokio::test]
async fn embeddings_stays_empty_with_no_embedder_installed() {
    let db = db().await;
    let id = seed(&db, "first").await;
    update_record(&db, &id, json!({ "name": "second", "body": "text" }))
        .await
        .unwrap();
    let other = seed(&db, "other").await;
    add_link(
        &db,
        LinkAddedPayload {
            id: None,
            source_id: id.clone(),
            target_id: other,
            relationship: "relates_to".into(),
            note: None,
        },
    )
    .await
    .unwrap();
    archive_record(&db, &id).await.unwrap();
    delete_record(&db, &id).await.unwrap();

    assert_eq!(count(&db, "SELECT count(*) AS n FROM embeddings").await, 0);
}

/// The seam is additive by construction: the frozen DDL is untouched, so the
/// event log still rebuilds the projections byte-identically.
#[tokio::test]
async fn rebuild_and_diff_survives_a_seam_driven_session() {
    let (db, recorder) = recording_db().await;
    let id = seed(&db, "alpha").await;
    update_record(&db, &id, json!({ "body": "beta" }))
        .await
        .unwrap();

    let before = recorder.seen().len();
    assert_eq!(before, 2);
    let result = rebuild_and_diff(&db).await.unwrap();
    assert!(result.equal, "rebuild-and-diff: {result:?}");

    // Replay folds events through the projector, which does NOT carry the seam
    // — a rebuild must not re-embed the corpus.
    assert_eq!(recorder.seen().len(), before);
}

// ---------------------------------------------------------------------------
// What fires it
// ---------------------------------------------------------------------------

#[tokio::test]
async fn creation_fires_the_seam_once() {
    let (db, recorder) = recording_db().await;
    let id = seed(&db, "hello").await;
    assert_eq!(
        recorder.seen(),
        vec![Seen {
            record_id: id,
            kind: TextChangeKind::Created,
            seq: 3,
        }]
    );
}

#[tokio::test]
async fn name_and_body_updates_fire_the_seam_once_each() {
    let (db, recorder) = recording_db().await;
    let id = seed(&db, "hello").await;
    update_record(&db, &id, json!({ "name": "renamed" }))
        .await
        .unwrap();
    update_record(&db, &id, json!({ "body": "written" }))
        .await
        .unwrap();
    // Both columns in one event is still ONE change to embed.
    update_record(&db, &id, json!({ "name": "again", "body": "again" }))
        .await
        .unwrap();

    let kinds: Vec<TextChangeKind> = recorder.seen().into_iter().map(|s| s.kind).collect();
    assert_eq!(
        kinds,
        vec![
            TextChangeKind::Created,
            TextChangeKind::Revised,
            TextChangeKind::Revised,
            TextChangeKind::Revised,
        ]
    );
    // seq is the event's own sequence — a watermark an out-of-band worker can
    // advance past, not a per-record counter.
    let seqs: Vec<i64> = recorder.seen().into_iter().map(|s| s.seq).collect();
    assert_eq!(seqs, vec![3, 4, 5, 6]);
}

/// Clearing the body is a text change like any other — an implementation that
/// only fired on non-empty text would leave the old vector standing.
#[tokio::test]
async fn nulling_the_body_fires_the_seam() {
    let (db, recorder) = recording_db().await;
    let id = seed(&db, "hello").await;
    update_record(&db, &id, json!({ "body": Value::Null }))
        .await
        .unwrap();
    assert_eq!(recorder.seen().len(), 2);
}

/// The MCP tools open their own transaction and call `store::append_in`
/// directly — they do not go through `store::create_record`. The seam sits at
/// that choke point precisely so the tool surface cannot bypass it.
#[tokio::test]
async fn the_tool_surface_fires_the_seam_too() {
    let (db, recorder) = recording_db().await;
    let registry = registry();

    let created = call(
        &registry,
        &db,
        "create_record",
        json!({ "type": "Document", "name": "from the tool", "facets": { "confidence": "high" } }),
    )
    .await;
    let id = created["id"].as_str().unwrap().to_string();
    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": id, "body": "edited through the tool" }),
    )
    .await;
    // A facet-only tool call must not fire it.
    call(
        &registry,
        &db,
        "update_record",
        json!({ "id": id, "facets": { "confidence": "low" } }),
    )
    .await;

    assert_eq!(
        recorder
            .seen()
            .into_iter()
            .map(|s| s.kind)
            .collect::<Vec<_>>(),
        vec![TextChangeKind::Created, TextChangeKind::Revised]
    );
}

/// `attach_text` creates an attachment record — a real record with a `name` —
/// through its own batch. It is a text change like any other.
#[tokio::test]
async fn attachments_fire_the_seam_for_the_attachment_record() {
    let (db, recorder) = recording_db().await;
    let registry = registry();
    let parent = seed(&db, "parent").await;
    let out = call(
        &registry,
        &db,
        "attach_text",
        json!({ "record_id": parent, "name": "note.txt", "text": "hello" }),
    )
    .await;
    let attachment = out["attachment_id"].as_str().unwrap().to_string();
    assert_eq!(recorder.ids(), vec![parent, attachment]);
}

// ---------------------------------------------------------------------------
// What deliberately does not
// ---------------------------------------------------------------------------

/// The seam mirrors `records_fts`'s columns exactly. Everything here changes
/// the record without changing its indexed text.
#[tokio::test]
async fn non_text_mutations_stay_silent() {
    let (db, recorder) = recording_db().await;
    let id = seed(&db, "subject").await;
    let target = seed(&db, "target").await;
    let baseline = recorder.seen().len();
    assert_eq!(baseline, 2);

    update_record(
        &db,
        &id,
        json!({ "lifecycle": "claimed", "summary": "not indexed" }),
    )
    .await
    .unwrap();
    set_facet(
        &db,
        &id,
        FacetSetPayload {
            key: "topic".into(),
            value: Some("search".into()),
            vocab_ref: None,
            as_of: None,
            observation_only: false,
        },
    )
    .await
    .unwrap();
    unset_facet(&db, &id, "topic").await.unwrap();
    archive_record(&db, &id).await.unwrap();
    restore_record(&db, &id).await.unwrap();
    add_link(
        &db,
        LinkAddedPayload {
            id: None,
            source_id: id.clone(),
            target_id: target,
            relationship: "relates_to".into(),
            note: None,
        },
    )
    .await
    .unwrap();

    assert_eq!(recorder.seen().len(), baseline);
}

/// Soft delete does not change `name`/`body`. Tombstones are filtered by the
/// read layer, exactly as they are for `records_fts` — whose DDL triggers also
/// leave a soft-deleted row indexed. Hard deletes need no hook: the
/// `embeddings.record_id` FK is `ON DELETE CASCADE`.
#[tokio::test]
async fn soft_delete_stays_silent() {
    let (db, recorder) = recording_db().await;
    let id = seed(&db, "doomed").await;
    delete_record(&db, &id).await.unwrap();
    assert_eq!(recorder.seen().len(), 1);
}

/// The generic conditional lifecycle write shares the same choke point. A
/// lifecycle-only write stays silent; the same CAS carrying text does not.
#[tokio::test]
async fn the_conditional_lifecycle_write_follows_the_same_rule() {
    let (db, recorder) = recording_db().await;
    let id = seed(&db, "claimable").await;

    update_record_when_lifecycle(&db, &id, None, json!({ "lifecycle": "active" }))
        .await
        .unwrap();
    assert_eq!(recorder.seen().len(), 1);

    update_record_when_lifecycle(
        &db,
        &id,
        Some("active"),
        json!({ "lifecycle": "active", "body": "progress" }),
    )
    .await
    .unwrap();
    assert_eq!(recorder.seen().len(), 2);
}

// ---------------------------------------------------------------------------
// The transactional contract — what makes the seam fillable
// ---------------------------------------------------------------------------

/// The hook runs on the caller's write transaction, so an implementation can
/// populate the dormant `embeddings` table from inside it and have the row
/// commit with the mutation that caused it. This is the "additive migration"
/// the decision asked for: no tool-contract change, no DDL change.
#[tokio::test]
async fn an_embedder_can_populate_the_dormant_table_from_the_seam() {
    let db = db().await.with_embedder(Arc::new(WritesEmbeddings));
    let id = seed(&db, "embed me").await;
    update_record(&db, &id, json!({ "body": "revised" }))
        .await
        .unwrap();

    assert_eq!(count(&db, "SELECT count(*) AS n FROM embeddings").await, 1);
    let stored = crate::common::text_of(
        &db,
        &format!("SELECT record_id FROM embeddings WHERE record_id = '{id}'"),
        "record_id",
    )
    .await;
    assert_eq!(stored.as_deref(), Some(id.as_str()));
}

/// The hook runs after the projector's fold, so the row it reads is the one the
/// mutation just wrote — not the pre-image.
#[tokio::test]
async fn the_seam_sees_post_fold_text() {
    #[derive(Debug, Default)]
    struct ReadsBack {
        names: Mutex<Vec<String>>,
    }
    impl Embedder for ReadsBack {
        fn on_text_changed<'a>(
            &'a self,
            conn: &'a mut SqliteConnection,
            change: TextChange<'a>,
        ) -> BoxFuture<'a, Result<()>> {
            async move {
                let name: String = sqlx::query_scalar("SELECT name FROM records WHERE id = ?")
                    .bind(change.record_id)
                    .fetch_one(conn)
                    .await?;
                self.names.lock().unwrap().push(name);
                Ok(())
            }
            .boxed()
        }
    }

    let reader = Arc::new(ReadsBack::default());
    let db = db().await.with_embedder(reader.clone());
    let id = seed(&db, "before").await;
    update_record(&db, &id, json!({ "name": "after" }))
        .await
        .unwrap();

    assert_eq!(
        *reader.names.lock().unwrap(),
        vec!["before".to_string(), "after".to_string()]
    );
}

/// A refusing embedder rolls the whole mutation back — event included. The
/// alternative (swallow the error) would commit a record the semantic index can
/// never learn about, which is the failure mode the seam exists to prevent.
#[tokio::test]
async fn a_failing_embedder_rolls_the_mutation_back() {
    let db = db().await.with_embedder(Arc::new(Refuses));
    let err = create_record(
        &db,
        json!({ "type": "Document", "kind": "note", "name": "doomed" }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains("embedder refused"), "{err}");

    assert_eq!(count(&db, "SELECT count(*) AS n FROM records").await, 2);
    assert_eq!(
        count(&db, "SELECT count(*) AS n FROM content_events").await,
        2
    );
}
