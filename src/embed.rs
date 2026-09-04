//! The `embed()` seam — the write-path hook semantic search will hang off.
//!
//! **At v1 this does nothing, and that is the whole point.** Decision `3bc7fd0`
//! ships search as FTS5 + tree only and defers semantic search to a hosted
//! fast-follow. What it asked for *now* is the seam, so that landing semantic
//! search later is an **additive migration**: the frozen DDL already carries a
//! dormant `embeddings` table, and this module is the one place a hosted tier
//! fills in to start populating it — **without a tool-contract change and
//! without a `FROZEN_DDL_SHA256` re-freeze**.
//!
//! ## Where it fires, and why there
//!
//! [`text_change_for`] classifies an event; `store::append_in` calls
//! [`embed`] for every event it classifies. `append_in` is the single choke
//! point for content mutation — `append`, `append_batch`, the conditional
//! lifecycle write and the MCP tools that open their own transaction all funnel
//! through it — the same reason the `vocab_ref` guard lives there. Hooking
//! `store::create_record` / `update_record` instead would miss every tool that
//! composes its own batch (`create_record`, `update_record`, `attach_text`).
//!
//! The hook runs **after** the projector has folded the event, on the caller's
//! write transaction: an implementation reading `records.name` / `records.body`
//! sees the post-fold values, and anything it writes commits or rolls back with
//! the mutation that caused it. A record can never be committed with a stale
//! marker saying it is embedded.
//!
//! ## Not in the projector
//!
//! Deliberately. The projector's contract is a deterministic, replayable fold
//! (`crate::conformance` rebuilds a fresh database from the log and diffs it);
//! embedding is an external, non-deterministic side effect. Firing on replay
//! would re-embed the whole corpus on every rebuild-and-diff. The seam is a
//! **live-write** hook; `projector::replay` does not call it, and
//! `tests/records/embed_seam.rs` pins that.
//!
//! ## What an implementation may do here (and what it must not)
//!
//! It must **not** compute a vector inline. This runs inside `BEGIN IMMEDIATE`,
//! which serializes every writer on the database; a network round-trip to an
//! embedding provider would hold that lock for its duration. The transactional
//! job is to record the *intent* — an outbox row keyed by
//! [`TextChange::record_id`] and [`TextChange::seq`] (a watermark an
//! out-of-band worker can advance past) — and let that worker do the call and
//! the `embeddings` write.
//!
//! ## Deliberate non-triggers
//!
//! - **Soft delete.** `record.deleted` sets `deleted_at`; it does not change
//!   `name`/`body`. Tombstones are filtered by the read layer (`deleted_at IS
//!   NULL`), exactly as they are for `records_fts`, which the DDL triggers also
//!   keep populated for soft-deleted rows. Hard deletes need no hook at all:
//!   `embeddings.record_id` is `REFERENCES records(id) ON DELETE CASCADE`.
//! - **Facets, links, lifecycle, archive.** None of them touch the indexed
//!   columns. The seam mirrors `records_fts`'s columns (`name`, `body`)
//!   exactly — `summary` is not indexed today, so it is not a trigger here.

use std::sync::Arc;

use futures::future::BoxFuture;
use serde_json::Value;
use sqlx::SqliteConnection;

use crate::error::Result;
use crate::events::EventRow;

/// The `records` columns the seam watches — the same two `records_fts` indexes.
const INDEXED_COLUMNS: [&str; 2] = ["name", "body"];

/// Whether the record's indexed text arrived with the record or replaced
/// earlier text. An implementation upserting one row per record can ignore it;
/// one keeping a re-embed queue can use it to tell a first embed from a
/// refresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextChangeKind {
    /// `record.created` — the record's first `name`/`body`.
    Created,
    /// `record.updated` carrying `name` and/or `body`.
    Revised,
}

/// One indexed-text change, as the write path sees it.
///
/// Borrows from the event that caused it: no allocation on the write path while
/// the seam is dormant.
#[derive(Debug, Clone, Copy)]
pub struct TextChange<'a> {
    /// The record whose `name`/`body` changed.
    pub record_id: &'a str,
    /// First text, or a revision.
    pub kind: TextChangeKind,
    /// `seq` of the event that carried the change — monotonic per database, so
    /// an out-of-band worker can keep a watermark rather than a queue.
    pub seq: i64,
    /// The event's timestamp. Read from the event, never from `now()`, so the
    /// seam sees the same clock the projector wrote.
    pub at: &'a str,
}

/// Classify one event: `Some` if it changed `records.name` or `records.body`.
///
/// `payload` is passed alongside rather than re-parsed out of
/// `event.payload` — the write path already holds it as a `Value`, and the
/// seam should not cost a third JSON parse per mutation while it is dormant.
///
/// Triggers on presence of the key, not value inequality — the old value is
/// gone by the time the projector has folded, and re-notifying on a no-change
/// write is the safe direction (an implementation that cares dedupes on a
/// content hash; one that misses a change serves a stale vector forever).
pub fn text_change_for<'a>(event: &'a EventRow, payload: &Value) -> Option<TextChange<'a>> {
    let kind = match event.event_type.as_str() {
        // Every record has a `name` column (the projector defaults a missing
        // one to ''), so creation always seeds the index.
        "record.created" => TextChangeKind::Created,
        "record.updated" | "receipt.committed.v1" => {
            let fields = payload.as_object()?;
            if !INDEXED_COLUMNS.iter().any(|col| fields.contains_key(*col)) {
                return None;
            }
            TextChangeKind::Revised
        }
        _ => return None,
    };
    Some(TextChange {
        record_id: &event.record_id,
        kind,
        seq: event.local_seq,
        at: &event.created_at,
    })
}

/// What a hosted tier installs to make the seam live. See the module docs for
/// the transactional contract — notably: no network calls in here.
pub trait Embedder: Send + Sync + std::fmt::Debug {
    /// Called once per indexed-text change, inside the mutation's own write
    /// transaction, after the projector has folded the event. Returning `Err`
    /// rolls the whole mutation back.
    fn on_text_changed<'a>(
        &'a self,
        conn: &'a mut SqliteConnection,
        change: TextChange<'a>,
    ) -> BoxFuture<'a, Result<()>>;
}

/// A shared [`Embedder`], as [`crate::Db`] holds it.
pub type EmbedderRef = Arc<dyn Embedder>;

/// The seam itself.
///
/// With no embedder installed — every v1 deployment, community and hosted — it
/// is a no-op, and `embeddings` stays empty. That is what "dormant" means: the
/// call happens on every indexed-text change, and there is nothing on the other
/// end of it yet.
pub(crate) async fn embed(
    conn: &mut SqliteConnection,
    embedder: Option<&EmbedderRef>,
    change: TextChange<'_>,
) -> Result<()> {
    match embedder {
        None => Ok(()),
        Some(embedder) => embedder.on_text_changed(conn, change).await,
    }
}
