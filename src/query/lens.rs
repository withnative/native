//! Typed sources for structured reads.
//!
//! A replay database contains a content projection, not a complete Native
//! database.  These wrappers make that boundary visible in function
//! signatures: projection-only helpers cannot reach live metadata or blobs,
//! while cross-tier readers must ask for each source explicitly.

use chrono::{DateTime, SecondsFormat, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::Row;

use crate::db::Db;
use crate::error::Result;

use super::error::contract_violation;

/// One explicit point in the authoritative content log.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum AsOfSelector {
    ContentSeq(ContentSeqSelector),
    Timestamp(TimestampSelector),
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContentSeqSelector {
    #[schemars(range(min = 0))]
    pub content_seq: i64,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TimestampSelector {
    pub timestamp: String,
}

/// Resolution metadata echoed by every explicit historical read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ResolvedAsOf {
    pub as_of: AsOfSelector,
    pub resolved_content_seq: i64,
    pub content_head_seq: i64,
}

/// The four named read capabilities of the query contract. Query names WHAT
/// it reads (projection, live meta, live blobs, the content log) and the two
/// consistency tiers it reads at; the SQLite kernel's `Db` implements them.
/// Query code never needs — and after the capability migration never gets —
/// the concrete `Db` handle out of a lens.
///
/// `snapshot_pool` is the read-your-writes tier (today `Db::write_pool`);
/// `shared_pool` is the concurrent shared read tier (today `Db::pool`). The
/// distinction is deliberate and load-bearing: several readers require
/// snapshot consistency with the latest commit. Migrations between tiers are
/// never a mechanical simplification.
pub(crate) trait ProjectionCapability {
    fn snapshot_pool(&self) -> &sqlx::SqlitePool;
    fn shared_pool(&self) -> &sqlx::SqlitePool;
}

/// Live schema and vocabulary capability.
pub(crate) trait MetaCapability {
    fn snapshot_pool(&self) -> &sqlx::SqlitePool;
    fn shared_pool(&self) -> &sqlx::SqlitePool;
}

/// Live content-addressed blob capability.
pub(crate) trait BlobCapability {
    fn shared_pool(&self) -> &sqlx::SqlitePool;
}

/// Authoritative content-event capability used for anchored citation evidence.
pub(crate) trait ContentLogCapability {
    fn snapshot_pool(&self) -> &sqlx::SqlitePool;
}

/// The content projection capability (`records`, links, facets, targets,
/// projection-maintained indexes). It deliberately exposes no `Db` publicly.
#[derive(Clone, Copy)]
pub struct ProjectionRead<'a> {
    db: &'a Db,
}

impl<'a> ProjectionRead<'a> {
    pub(crate) fn new(db: &'a Db) -> Self {
        Self { db }
    }

    /// Read-your-writes projection tier.
    pub(crate) fn snapshot_pool(self) -> &'a sqlx::SqlitePool {
        ProjectionCapability::snapshot_pool(self.db)
    }

    /// Concurrent shared projection tier.
    pub(crate) fn shared_pool(self) -> &'a sqlx::SqlitePool {
        ProjectionCapability::shared_pool(self.db)
    }
}

/// Live schema and vocabulary capability.
#[derive(Clone, Copy)]
pub struct LiveMetaRead<'a> {
    db: &'a Db,
}

impl<'a> LiveMetaRead<'a> {
    pub(crate) fn new(db: &'a Db) -> Self {
        Self { db }
    }

    pub(crate) fn snapshot_pool(self) -> &'a sqlx::SqlitePool {
        MetaCapability::snapshot_pool(self.db)
    }

    pub(crate) fn shared_pool(self) -> &'a sqlx::SqlitePool {
        MetaCapability::shared_pool(self.db)
    }
}

/// Live content-addressed blob capability.
#[derive(Clone, Copy)]
pub struct LiveBlobRead<'a> {
    db: &'a Db,
}

impl<'a> LiveBlobRead<'a> {
    pub(crate) fn new(db: &'a Db) -> Self {
        Self { db }
    }

    pub(crate) fn shared_pool(self) -> &'a sqlx::SqlitePool {
        BlobCapability::shared_pool(self.db)
    }
}

/// Authoritative content-event capability used for anchored citation evidence.
#[derive(Clone, Copy)]
pub struct ContentLogRead<'a> {
    db: &'a Db,
}

impl<'a> ContentLogRead<'a> {
    pub(crate) fn new(db: &'a Db) -> Self {
        Self { db }
    }

    pub(crate) fn snapshot_pool(self) -> &'a sqlx::SqlitePool {
        ContentLogCapability::snapshot_pool(self.db)
    }
}

/// The complete, honest source set for a structured read.
#[derive(Clone, Copy)]
pub struct ReadLens<'a> {
    projection: ProjectionRead<'a>,
    meta: LiveMetaRead<'a>,
    blobs: LiveBlobRead<'a>,
    content_log: ContentLogRead<'a>,
    temporal: Option<&'a ResolvedAsOf>,
}

impl<'a> ReadLens<'a> {
    /// The unchanged live fast path: every capability addresses the live DB.
    pub fn live(db: &'a Db) -> Self {
        Self {
            projection: ProjectionRead::new(db),
            meta: LiveMetaRead::new(db),
            blobs: LiveBlobRead::new(db),
            content_log: ContentLogRead::new(db),
            temporal: None,
        }
    }

    /// A replayed content projection combined with explicit live tiers.
    pub fn historical(projection: &'a Db, live: &'a Db, temporal: &'a ResolvedAsOf) -> Self {
        Self {
            projection: ProjectionRead::new(projection),
            meta: LiveMetaRead::new(live),
            blobs: LiveBlobRead::new(live),
            content_log: ContentLogRead::new(live),
            temporal: Some(temporal),
        }
    }

    /// Re-derive this lens with a different content projection while retaining
    /// its live metadata, blob and content-log tiers.
    pub(crate) fn with_projection<'b>(
        &'b self,
        projection: &'b Db,
        temporal: &'b ResolvedAsOf,
    ) -> ReadLens<'b> {
        ReadLens {
            projection: ProjectionRead::new(projection),
            meta: LiveMetaRead::new(self.meta.db),
            blobs: LiveBlobRead::new(self.blobs.db),
            content_log: ContentLogRead::new(self.content_log.db),
            temporal: Some(temporal),
        }
    }

    pub fn projection(self) -> ProjectionRead<'a> {
        self.projection
    }

    pub fn meta(self) -> LiveMetaRead<'a> {
        self.meta
    }

    pub fn blobs(self) -> LiveBlobRead<'a> {
        self.blobs
    }

    pub fn content_log(self) -> ContentLogRead<'a> {
        self.content_log
    }

    pub fn temporal(self) -> Option<&'a ResolvedAsOf> {
        self.temporal
    }
}

/// Resolve an explicit selector against one observed content-log head.
pub async fn resolve_as_of(db: &Db, selector: AsOfSelector) -> Result<ResolvedAsOf> {
    let (resolved_content_seq, content_head_seq) = match &selector {
        AsOfSelector::ContentSeq(value) => {
            if value.content_seq < 0 {
                return Err(contract_violation("as_of content_seq must be >= 0"));
            }
            let head: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM content_events")
                .fetch_one(db.write_pool())
                .await?;
            if value.content_seq > head {
                return Err(contract_violation(format!(
                    "as_of content_seq {} is beyond current content head {}",
                    value.content_seq, head
                )));
            }
            (value.content_seq, head)
        }
        AsOfSelector::Timestamp(value) => {
            let parsed = DateTime::parse_from_rfc3339(&value.timestamp).map_err(|_| {
                contract_violation("as_of timestamp must be a valid RFC 3339 timestamp")
            })?;
            let normalized = parsed
                .with_timezone(&Utc)
                .to_rfc3339_opts(SecondsFormat::Millis, true);
            // Both values come from one SQLite statement and therefore one
            // snapshot. MAX(seq) is the deterministic tie-break for equal
            // event timestamps.
            let row = sqlx::query(
                "SELECT COALESCE(MAX(seq), 0) AS head,\n\
                        COALESCE(MAX(CASE WHEN created_at <= ? THEN seq END), 0) AS resolved\n\
                   FROM content_events",
            )
            .bind(normalized)
            .fetch_one(db.write_pool())
            .await?;
            (row.try_get("resolved")?, row.try_get("head")?)
        }
    };
    Ok(ResolvedAsOf {
        as_of: selector,
        resolved_content_seq,
        content_head_seq,
    })
}

/// Replay one pinned content prefix into a fresh projection database.
///
/// The fold runs inside one transaction. Without it every projector statement
/// autocommits, and since a scratch database is an ordinary WAL file under
/// `$TMPDIR` (`open_database` gives `:memory:` a temp file so pooled
/// connections share one database) at SQLite's default `synchronous=FULL`,
/// each of the four to six statements an event projects costs its own commit
/// and flush. That is the whole of this function's cost: it is not the size of
/// the fold, it is committing several thousand times per render. One
/// transaction turns those into one commit.
///
/// The scratch database is discarded when the read completes, so the
/// transaction buys no durability — it is purely the batching that makes an
/// `as_of` read affordable. Every caller either propagates the error or
/// returns a diagnostic and closes the scratch, so rolling the fold back on
/// failure is not observable. The wrapping is here rather than inside
/// `replay_with_blob_seeds` because that function's failure behaviour is
/// asserted directly by tests which replay a deliberately invalid prefix and
/// then read what survived; keeping it a plain connection leaves those
/// assertions meaning what they meant.
///
/// This deliberately does not go through `Db::begin_write`. That boundary is
/// for governed writes to a real store — it enforces the storage-portability
/// policy, which a private temp file rebuilding a derived projection is not
/// subject to. The `BEGIN IMMEDIATE` it takes guards against a deferred
/// transaction reading before its first write and hitting SQLite's
/// deadlock-upgrade `SQLITE_BUSY`; neither half of that applies here, because
/// the fold's first statement on the scratch is an insert and a scratch
/// database has exactly one writer.
pub async fn replay_projection(live: &Db, scratch: &Db, seq: i64) -> Result<()> {
    replay_projection_in_pool(live.write_pool(), scratch, seq).await
}

pub(crate) async fn replay_projection_in_pool(
    live_pool: &sqlx::SqlitePool,
    scratch: &Db,
    seq: i64,
) -> Result<()> {
    let events = crate::query::events::log_prefix_in_pool(live_pool, seq).await?;
    let mut tx = scratch.write_pool().begin().await?;
    // Blob identities are projector prerequisites only. Read paths never treat
    // these placeholders as retained evidence; the lens routes bytes live.
    crate::projector::replay_with_blob_placeholders(&mut tx, &events).await?;
    tx.commit().await?;
    Ok(())
}

/// Add temporal metadata to a structured response without changing live
/// response shapes when `as_of` was omitted.
pub fn echo_temporal(value: &mut Value, resolved: &ResolvedAsOf) {
    let object = value
        .as_object_mut()
        .expect("structured read responses are JSON objects");
    object.insert(
        "as_of".into(),
        serde_json::to_value(&resolved.as_of).expect("as_of selector serializes"),
    );
    object.insert(
        "resolved_content_seq".into(),
        resolved.resolved_content_seq.into(),
    );
    object.insert("content_head_seq".into(), resolved.content_head_seq.into());
}

/// Remove and validate the optional selector before a handler deserializes its
/// ordinary arguments with `deny_unknown_fields`.
pub fn take_as_of(tool: &str, arguments: &mut Value) -> Result<Option<AsOfSelector>> {
    let Some(object) = arguments.as_object_mut() else {
        return Ok(None);
    };
    object
        .remove("as_of")
        .map(|value| {
            serde_json::from_value(value).map_err(|error| {
                contract_violation(format!("invalid arguments for {tool}: {error}"))
            })
        })
        .transpose()
}

pub fn as_of_input_schema() -> Value {
    serde_json::json!({
        "oneOf": [
            {
                "type": "object",
                "properties": { "content_seq": { "type": "integer", "minimum": 0 } },
                "required": ["content_seq"],
                "additionalProperties": false
            },
            {
                "type": "object",
                "properties": {
                    "timestamp": {
                        "type": "string",
                        "format": "date-time"
                    }
                },
                "required": ["timestamp"],
                "additionalProperties": false
            }
        ],
        "description": "Replay the pinned content projection at exactly one sequence or RFC 3339 timestamp. Schema/vocabulary and retained blob bytes resolve live."
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Compile-time evidence: a projection capability has no route to a live
    // metadata/blob source. Cross-tier code must receive ReadLens explicitly.
    fn projection_only(source: ProjectionRead<'_>) -> &sqlx::SqlitePool {
        source.snapshot_pool()
    }

    #[test]
    fn selector_requires_exactly_one_arm() {
        assert!(serde_json::from_value::<AsOfSelector>(serde_json::json!({
            "content_seq": 1,
            "timestamp": "2026-01-01T00:00:00Z"
        }))
        .is_err());
        assert!(serde_json::from_value::<AsOfSelector>(serde_json::json!({})).is_err());
        let _ = projection_only;
    }
}
