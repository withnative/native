//! Deferred body derivations for a private scratch fold.
//!
//! A body-carrying event rebuilds four record-keyed projections from the body
//! it carries: `body_blocks`, `record_mentions`, `body_task_items` and
//! `record_body_json_nodes`. Each replacement deletes the record's rows first
//! and then inserts what the new body yields, so a replayed fold only ever
//! needs the LAST call per (table, record): every earlier one is overwritten
//! before anything can read it. On a long history that is most of the cost of
//! an `as_of` read, because large records are rewritten thousands of times.
//!
//! [`BodyDeferrals`] records those calls instead of running them, and
//! [`BodyDeferrals::flush`] runs each surviving call once. It is an explicit
//! value, owned by the one fold that asked for it and threaded by hand through
//! the projector down to the writers. It is deliberately not ambient state: a
//! task-local would capture any projection that happened to run on the same
//! task, including nested or unrelated ones on another connection. With no
//! value supplied every writer executes immediately, exactly as before — live
//! writes, `projector::replay` and the low-level `replay_with_blob_*` helpers
//! never see this module's deferral.
//!
//! Why last-call-wins is equivalent at the end of a successful fold:
//!
//! - Nothing in the projector or planner reads the four tables between
//!   events, and no trigger derives other state from them.
//! - Each call is a pure function of its arguments (record id, source event
//!   sequence, the body text, and for `body_blocks` the body format — a
//!   non-string JSON body is Opaque, which cannot be recovered from the
//!   coerced text, so the format is kept). The entry keeps exactly the
//!   arguments of the last call, so the flush writes what that call would
//!   have written.
//! - Deferral is per table, not per record. `record.deleted` clears the
//!   record's mentions only: blocks, tasks and JSON nodes are retained on a
//!   tombstone, and a bodyless update touches none of them. A mention clear
//!   therefore overwrites only the mentions slot.
//!
//! The accepted difference is in failure, not in successful state. Today a
//! body whose task extraction or block parse fails aborts the fold at that
//! event even if a later event replaces the body. Deferred, only the LAST body
//! per record is ever extracted, so an invalid body that is later superseded
//! no longer aborts, and when several records are invalid the one reported
//! (and its order relative to a later event's own validation error) can
//! differ. An invalid FINAL body still fails, and the scratch transaction
//! rolls back.

use super::{replace_body_task_items, replace_record_mentions};
use crate::body_blocks::BodyFormat;
use crate::error::Result;
use sqlx::SqliteConnection;
use std::collections::BTreeMap;
use std::sync::Arc;

/// The last `body_blocks` call for one record.
struct BlocksCall {
    source_event_seq: i64,
    body: Option<Arc<str>>,
    format: BodyFormat,
}

/// The last call for each table for one record. `None` means the fold has not
/// touched that table for the record, so the flush leaves it alone.
#[derive(Default)]
struct PendingRecord {
    blocks: Option<BlocksCall>,
    mentions: Option<(i64, Option<Arc<str>>)>,
    tasks: Option<(i64, Option<Arc<str>>)>,
    nodes: Option<Option<Arc<str>>>,
}

/// Body derivations a single scratch fold has deferred. See the module docs.
#[derive(Default)]
pub(crate) struct BodyDeferrals {
    pending: BTreeMap<String, PendingRecord>,
}

impl BodyDeferrals {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Run every record's last deferred call once, in the caller's
    /// transaction, and leave the set empty. Records are independent keys and
    /// every parent row already exists, so the order across records does not
    /// matter; within a record the tables run in the order the immediate
    /// path runs them.
    pub(crate) async fn flush(&mut self, conn: &mut SqliteConnection) -> Result<()> {
        // Consume entries as they flush so each body is freed once written.
        for (record_id, entry) in std::mem::take(&mut self.pending) {
            if let Some(call) = entry.blocks {
                crate::body_blocks_projection::replace_sqlite(
                    conn,
                    &record_id,
                    call.source_event_seq,
                    call.body.as_deref(),
                    call.format,
                )
                .await?;
            }
            if let Some((seq, body)) = entry.mentions {
                replace_record_mentions(conn, &record_id, seq, body.as_deref().map(str::to_owned))
                    .await?;
            }
            if let Some((seq, body)) = entry.tasks {
                replace_body_task_items(conn, &record_id, seq, body.as_deref().map(str::to_owned))
                    .await?;
            }
            if let Some(body) = entry.nodes {
                crate::facet_value_json_nodes::replace_record_body(
                    conn,
                    &record_id,
                    body.as_deref(),
                )
                .await?;
            }
        }
        Ok(())
    }
}

/// Replace all four body derivations for `record_id` from one body — what
/// `record.created`, a body-carrying `record.updated` (and the update a
/// `receipt.committed.v1` synthesizes) and `unit.revision.recorded.v1` all
/// do. With a deferral set the call is recorded (last call wins, per table,
/// sharing one copy of the body); without one it runs immediately.
///
/// `source_event_seq` is the sequence of the event that supplied the body. For
/// a synthesized update it is the original event's sequence, which the caller
/// has already preserved on the event it passes down.
pub(super) async fn replace_body_derivations(
    conn: &mut SqliteConnection,
    defer: Option<&mut BodyDeferrals>,
    record_id: &str,
    source_event_seq: i64,
    body: Option<&str>,
    format: BodyFormat,
) -> Result<()> {
    if let Some(defer) = defer {
        let body: Option<Arc<str>> = body.map(Arc::from);
        let entry = defer.pending.entry(record_id.to_owned()).or_default();
        entry.blocks = Some(BlocksCall {
            source_event_seq,
            body: body.clone(),
            format,
        });
        entry.mentions = Some((source_event_seq, body.clone()));
        entry.tasks = Some((source_event_seq, body.clone()));
        entry.nodes = Some(body);
        return Ok(());
    }
    crate::body_blocks_projection::replace_sqlite(conn, record_id, source_event_seq, body, format)
        .await?;
    replace_record_mentions(conn, record_id, source_event_seq, body.map(str::to_owned)).await?;
    // E3 M3 increment 2A: body-task rows fold with the same body the mention
    // rows scan.
    replace_body_task_items(conn, record_id, source_event_seq, body.map(str::to_owned)).await?;
    // E3 M3 record-body nodes fold the same coerced stored text; scalar,
    // malformed or over-limit bodies leave no nodes without failing the write.
    crate::facet_value_json_nodes::replace_record_body(conn, record_id, body).await
}

/// Clear a record's mention rows, as a tombstone does. Only `record_mentions`
/// is cleared: a soft delete retains the record's blocks, tasks and JSON
/// nodes, so a deferred clear overwrites only the mentions slot.
pub(super) async fn clear_record_mentions(
    conn: &mut SqliteConnection,
    defer: Option<&mut BodyDeferrals>,
    record_id: &str,
    source_event_seq: i64,
) -> Result<()> {
    if let Some(defer) = defer {
        defer
            .pending
            .entry(record_id.to_owned())
            .or_default()
            .mentions = Some((source_event_seq, None));
        return Ok(());
    }
    replace_record_mentions(conn, record_id, source_event_seq, None).await
}
