//! Small kernel-v2 deltas applied IN PLACE to the serving generation (epic
//! c15a932 slice 4, design record 5738e8d, option C). Opt-in and off by
//! default; every other delta keeps the staged copy-and-publish path in
//! `kernel_delta.rs`, which is also the periodic re-checkpoint.
//!
//! Safety properties, and what enforces each:
//!
//! * Readers see head N or head N+1, never a mixture. The whole fold, the full
//!   projection digest, the foreign-key check and the apply receipt run inside
//!   ONE write transaction on a WAL database; readers hold SQLite snapshots.
//! * The head sidecar (`heads/<id>.json`, read by `live_serving()`) is never
//!   ahead of what readers see. It is written only after the commit returns,
//!   and the writer uses `synchronous=FULL`, so the commit is durable first.
//!   It is a cache of the database: after a crash it can lag, and verification
//!   and the refresh tick repair it from the database, never the reverse.
//! * The AUTHORITATIVE record of what was applied lives in the database, in
//!   `kernel_standby_apply_receipts`, written in the same transaction as the
//!   fold. A `base` receipt (ordinal 0) anchors the chain to the checkpoint
//!   file hash from the manifest; each `delta` receipt carries the
//!   authenticated delta digest, the certified projection digest, a digest of
//!   the canonical event rows the delta added, and a link in a hash chain.
//!   Because the receipt commits with the data, there is no window in which
//!   the data advanced without its receipt; a missing, lagging or inconsistent
//!   receipt chain is a refusal, never something to re-derive from local state.
//! * Canonical bytes keep independent coverage. Event rows (excluded from the
//!   projection digest) are covered by per-segment row digests: the base
//!   receipt digests every row of the verified checkpoint (the file hash is
//!   verified immediately before the first in-place write, which is the last
//!   moment it can be), and each delta receipt digests the rows it added.
//!   Blobs are content addressed, so every blob row is checked against its own
//!   key and size; that covers base and added blobs alike without a chain.
//! * A digest mismatch rolls the transaction back untouched.
use super::*;
use crate::standby::kernel_v2::KernelGeneration;
use crate::standby::kernel_v2_delta::{self, TrustedKernelDelta};
use crate::standby::phase_timings::PhaseTimings;
use crate::standby_snapshot::sha256_bytes;
use futures::TryStreamExt;

pub(crate) mod at_rest;
pub(crate) mod audit;
pub(crate) mod set_path;
pub(crate) mod trust;
pub(crate) use set_path::{SetPathCounters, SUPPRESS_AFTER_RESEEDS};

pub(crate) const RECEIPTS_TABLE: &str = "kernel_standby_apply_receipts";
/// Exact DDL, validated by the v2 schema inventory like the MCP write ledger
/// (the table is permitted in a standby copy but is not part of its
/// compatibility coordinates or projection digest).
pub(crate) const RECEIPTS_DDL: &str = "CREATE TABLE kernel_standby_apply_receipts (ordinal INTEGER PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN ('base','delta')), from_act INTEGER NOT NULL, to_act INTEGER NOT NULL, content_seq_from INTEGER NOT NULL, content_seq_to INTEGER NOT NULL, meta_seq_from INTEGER NOT NULL, meta_seq_to INTEGER NOT NULL, delta_sha256 TEXT NOT NULL, projection_sha256 TEXT NOT NULL, events_sha256 TEXT NOT NULL, blob_count INTEGER NOT NULL, fixed_sha256 TEXT NOT NULL, derived_sha256 TEXT NOT NULL, chain_sha256 TEXT NOT NULL)";

/// The receipts DDL a node that also proves the projection by set digest
/// creates (design record 5065900): `kind` adds `'delta-set'`, the v1 digest
/// becomes nullable beside a nullable `projection_set_sha256`, and at least one
/// must be present. This node never creates it, but accepts it, verifies chains
/// written under it, and keeps appending to it.
pub(crate) const RECEIPTS_DDL_V2: &str = "CREATE TABLE kernel_standby_apply_receipts (ordinal INTEGER PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN ('base','delta','delta-set')), from_act INTEGER NOT NULL, to_act INTEGER NOT NULL, content_seq_from INTEGER NOT NULL, content_seq_to INTEGER NOT NULL, meta_seq_from INTEGER NOT NULL, meta_seq_to INTEGER NOT NULL, delta_sha256 TEXT NOT NULL, projection_sha256 TEXT, projection_set_sha256 TEXT, events_sha256 TEXT NOT NULL, blob_count INTEGER NOT NULL, fixed_sha256 TEXT NOT NULL, derived_sha256 TEXT NOT NULL, chain_sha256 TEXT NOT NULL, CHECK(projection_sha256 IS NOT NULL OR projection_set_sha256 IS NOT NULL))";
/// The optional cache of per-table set-digest accumulators. Never
/// authoritative: the rows are. This node knows it (exempt from the schema
/// inventory and excluded from the projection digest), never writes it, and
/// empties it in the same transaction as any in-place apply.
pub(crate) const ACCUMULATOR_TABLE: &str = "kernel_standby_projection_set";
pub(crate) const ACCUMULATOR_DDL: &str = "CREATE TABLE kernel_standby_projection_set (name TEXT PRIMARY KEY, schema_sha256 TEXT NOT NULL, rows INTEGER NOT NULL, value BLOB NOT NULL, ordinal INTEGER NOT NULL)";

/// After this many in-place deltas the next delta takes the staged path,
/// which re-hashes, re-verifies and re-publishes the whole file. Bounds how
/// long a copy can drift from a digest-checked checkpoint.
pub(crate) const RECHECKPOINT_AFTER_DELTAS: u64 = 2048;
/// Likewise, once the checkpoint is this old.
pub(crate) const RECHECKPOINT_AFTER_SECONDS: i64 = 24 * 60 * 60;
pub(crate) const INJECTED_CRASH: &str = "injected_in_place_crash";
/// The in-database receipts do not continue the database: refuse in place.
pub(crate) const RECEIPTS_INCONSISTENT: &str = "kernel_v2_in_place_receipts_inconsistent";
/// The copy a staged re-checkpoint would inherit cannot be proved: refuse.
pub(crate) const BASE_UNPROVED: &str = "kernel_v2_in_place_base_unproved";

#[cfg(test)]
thread_local! {
    pub(crate) static RECHECKPOINT_OVERRIDE: std::cell::Cell<Option<(u64, i64)>> =
        const { std::cell::Cell::new(None) };
}

fn recheckpoint_limits() -> (u64, i64) {
    #[cfg(test)]
    if let Some(limits) = RECHECKPOINT_OVERRIDE.with(std::cell::Cell::get) {
        return limits;
    }
    (RECHECKPOINT_AFTER_DELTAS, RECHECKPOINT_AFTER_SECONDS)
}

/// Test-only fault points. Production callers always pass `None`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InPlaceCrash {
    /// After the head is marked `delta`, before the base receipt commits.
    AfterMarkBeforeBaseReceipt,
    /// After the base receipt commits, before the first fold.
    AfterBaseReceipt,
    BeforeCommit,
    AfterCommitBeforeSidecar,
    AfterSidecar,
}

#[derive(Clone, Debug, sqlx::FromRow)]
pub(crate) struct Receipt {
    pub ordinal: i64,
    pub kind: String,
    pub from_act: i64,
    pub to_act: i64,
    pub content_seq_from: i64,
    pub content_seq_to: i64,
    pub meta_seq_from: i64,
    pub meta_seq_to: i64,
    pub delta_sha256: String,
    /// The v1 projection digest this receipt certifies; NULL on a `delta-set`
    /// receipt that certifies only the set digest.
    pub projection_sha256: Option<String>,
    /// The set digest this receipt certifies; NULL on every receipt this node
    /// writes, and on any receipt in the first receipts DDL.
    pub projection_set_sha256: Option<String>,
    pub events_sha256: String,
    pub blob_count: i64,
    /// The cutover tables, which no delta may ever change.
    pub fixed_sha256: String,
    /// Tables the projection digest excludes that legitimately move with
    /// deltas: the head set, the legacy scan cursor and the act counter.
    pub derived_sha256: String,
    pub chain_sha256: String,
}

/// Which receipts DDL a database carries. The two differ in columns and in the
/// bytes each receipt's chain link covers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReceiptsDdl {
    V1,
    V2,
}

impl ReceiptsDdl {
    /// A column list that yields the same `Receipt` shape under either DDL.
    fn columns(self) -> &'static str {
        match self {
            Self::V1 => "ordinal,kind,from_act,to_act,content_seq_from,content_seq_to,meta_seq_from,meta_seq_to,delta_sha256,projection_sha256,NULL AS projection_set_sha256,events_sha256,blob_count,fixed_sha256,derived_sha256,chain_sha256",
            Self::V2 => "ordinal,kind,from_act,to_act,content_seq_from,content_seq_to,meta_seq_from,meta_seq_to,delta_sha256,projection_sha256,projection_set_sha256,events_sha256,blob_count,fixed_sha256,derived_sha256,chain_sha256",
        }
    }
}

/// The receipts DDL in this database, by exact text.
async fn receipts_ddl(conn: &mut sqlx::SqliteConnection) -> Result<ReceiptsDdl> {
    let sql: Option<String> =
        sqlx::query_scalar("SELECT sql FROM sqlite_schema WHERE type='table' AND name=?")
            .bind(RECEIPTS_TABLE)
            .fetch_optional(&mut *conn)
            .await?;
    match sql.as_deref() {
        Some(sql) if sql == RECEIPTS_DDL => Ok(ReceiptsDdl::V1),
        Some(sql) if sql == RECEIPTS_DDL_V2 => Ok(ReceiptsDdl::V2),
        _ => Err(Error::engine(
            "kernel-v2 apply-receipt schema is not recognised",
        )),
    }
}

fn genesis_hash(checkpoint_sha256: &str) -> String {
    sha256_bytes(
        format!("native.standby-kernel-v2-apply-receipts.v1:{checkpoint_sha256}").as_bytes(),
    )
}

/// `0` for NULL; `1`, a little-endian u64 length and the bytes for a value.
fn put_optional(bytes: &mut Vec<u8>, value: Option<&str>) {
    match value {
        None => bytes.push(0),
        Some(value) => {
            bytes.push(1);
            bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
            bytes.extend_from_slice(value.as_bytes());
        }
    }
}

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Receipt {
    /// Every digest a receipt stores is exactly 64 lowercase hex characters
    /// (the optional ones only when present).
    fn digests_well_formed(&self) -> bool {
        [
            Some(self.delta_sha256.as_str()),
            self.projection_sha256.as_deref(),
            self.projection_set_sha256.as_deref(),
            Some(self.events_sha256.as_str()),
            Some(self.fixed_sha256.as_str()),
            Some(self.derived_sha256.as_str()),
            Some(self.chain_sha256.as_str()),
        ]
        .into_iter()
        .flatten()
        .all(is_lower_hex_64)
    }

    /// The next chain value. The first receipts DDL keeps its original link
    /// bytes. The second binds a format tag (`apply-receipts.v2`), the kind and
    /// BOTH projection digests with explicit presence, so neither the kind nor
    /// either digest can be changed, dropped or replaced by a literal without
    /// breaking the chain. The format belongs to the table, not to a receipt:
    /// a chain cannot mix formats.
    fn link(&self, previous: &str, ddl: ReceiptsDdl) -> String {
        let text = match ddl {
            ReceiptsDdl::V1 => format!(
                "{previous}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
                self.ordinal,
                self.kind,
                self.from_act,
                self.to_act,
                self.content_seq_from,
                self.content_seq_to,
                self.meta_seq_from,
                self.meta_seq_to,
                self.delta_sha256,
                self.projection_sha256.as_deref().unwrap_or(""),
                self.events_sha256,
                self.blob_count,
                self.fixed_sha256,
                self.derived_sha256
            ),
            ReceiptsDdl::V2 => {
                // Presence is explicit: a tag byte, then a length-framed value,
                // so NULL and any literal (`-` included) can never coincide.
                let mut bytes = format!(
                    "{previous}:apply-receipts.v2:{}:{}:{}:{}:{}:{}:{}:{}:{}:",
                    self.ordinal,
                    self.kind,
                    self.from_act,
                    self.to_act,
                    self.content_seq_from,
                    self.content_seq_to,
                    self.meta_seq_from,
                    self.meta_seq_to,
                    self.delta_sha256,
                )
                .into_bytes();
                put_optional(&mut bytes, self.projection_sha256.as_deref());
                put_optional(&mut bytes, self.projection_set_sha256.as_deref());
                bytes.extend_from_slice(
                    format!(
                        ":{}:{}:{}:{}",
                        self.events_sha256, self.blob_count, self.fixed_sha256, self.derived_sha256
                    )
                    .as_bytes(),
                );
                return sha256_bytes(&bytes);
            }
        };
        sha256_bytes(text.as_bytes())
    }
}

/// Digest of the canonical event rows with `seq` in `(from, to]` in each log
/// and the causal-frontier rows of those content events. The projection digest
/// excludes these tables, so this is their only coverage after a delta.
pub(crate) async fn events_digest(
    conn: &mut sqlx::SqliteConnection,
    content: (i64, i64),
    meta: (i64, i64),
) -> Result<String> {
    use crate::kernel::projection_dump::digest_rows;
    let mut combined = String::from("native.standby-event-rows.v1");
    for (table, range, order) in [
        ("content_events", content, "seq"),
        ("meta_events", meta, "seq"),
    ] {
        let columns: i64 = sqlx::query_scalar(&format!(
            "SELECT COUNT(*) FROM pragma_table_info('{table}')"
        ))
        .fetch_one(&mut *conn)
        .await?;
        let (rows, digest) = digest_rows(
            conn,
            table,
            &format!("SELECT * FROM {table} WHERE seq>? AND seq<=? ORDER BY {order}"),
            &[range.0, range.1],
            columns as usize,
        )
        .await?;
        combined.push_str(&format!(":{table}:{rows}:{digest}"));
    }
    let columns: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pragma_table_info('content_event_causal_frontier')",
    )
    .fetch_one(&mut *conn)
    .await?;
    let (rows, digest) = digest_rows(
        conn,
        "content_event_causal_frontier",
        "SELECT * FROM content_event_causal_frontier WHERE event_id IN (SELECT id FROM content_events WHERE seq>? AND seq<=?) ORDER BY event_id,parent_event_id",
        &[content.0, content.1],
        columns as usize,
    )
    .await?;
    combined.push_str(&format!(":frontier:{rows}:{digest}"));
    Ok(sha256_bytes(combined.as_bytes()))
}

/// Digest of whole small tables the projection digest excludes. A table that
/// does not exist digests as absent (older bases lack the legacy scan cursor).
async fn tables_digest(conn: &mut sqlx::SqliteConnection, tables: &[&str]) -> Result<String> {
    use crate::kernel::projection_dump::digest_rows;
    let mut combined = String::from("native.standby-excluded-tables.v1");
    for table in tables {
        let present: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?)",
        )
        .bind(table)
        .fetch_one(&mut *conn)
        .await?;
        if !present {
            combined.push_str(&format!(":{table}:absent"));
            continue;
        }
        let columns: i64 = sqlx::query_scalar(&format!(
            "SELECT COUNT(*) FROM pragma_table_info('{table}')"
        ))
        .fetch_one(&mut *conn)
        .await?;
        // The first column is the primary key of each of these tables.
        let (rows, digest) = digest_rows(
            conn,
            table,
            &format!("SELECT * FROM {table} ORDER BY 1"),
            &[],
            columns as usize,
        )
        .await?;
        combined.push_str(&format!(":{table}:{rows}:{digest}"));
    }
    Ok(sha256_bytes(combined.as_bytes()))
}

/// Cutover rows: fixed for the life of a checkpoint (the successor fence
/// requires them preserved exactly), so a delta may never change them.
pub(crate) async fn fixed_digest(conn: &mut sqlx::SqliteConnection) -> Result<String> {
    tables_digest(conn, &["act_cutover", "content_event_causal_cutover"]).await
}

pub(crate) async fn derived_digest(conn: &mut sqlx::SqliteConnection) -> Result<String> {
    tables_digest(
        conn,
        &[
            "act_state",
            "content_event_heads",
            "kernel_legacy_sql_progress",
        ],
    )
    .await
}

async fn last_receipt(conn: &mut sqlx::SqliteConnection) -> Result<Option<Receipt>> {
    let ddl = receipts_ddl(conn).await?;
    Ok(sqlx::query_as(&format!(
        "SELECT {} FROM {RECEIPTS_TABLE} ORDER BY ordinal DESC LIMIT 1",
        ddl.columns()
    ))
    .fetch_optional(conn)
    .await?)
}

/// Before any mutation: the state the fold starts from must be exactly what
/// the last receipt certified (cutover and derived tables included), or the
/// new receipt would certify tampering as its own.
pub(crate) async fn verify_prior_state(tx: &mut sqlx::SqliteConnection) -> Result<()> {
    let inconsistent = || Error::engine(RECEIPTS_INCONSISTENT);
    let previous = last_receipt(tx)
        .await
        .map_err(|_| inconsistent())?
        .ok_or_else(inconsistent)?;
    if fixed_digest(tx).await? != previous.fixed_sha256
        || derived_digest(tx).await? != previous.derived_sha256
    {
        return Err(inconsistent());
    }
    Ok(())
}

/// What a new receipt certifies, and what happens to the accumulator cache.
pub(crate) enum Certified<'a> {
    /// The v1 digest only, whatever the delta carried (this node's behaviour
    /// on the first receipts DDL). Any accumulator cache is emptied.
    V1Only,
    /// `delta-set`: the set digest only. The composed accumulator is written.
    /// `set_sha256` is what the accumulator composes to: hosted's, when the
    /// delta carried one and it matched, else this node's own (wire version 3).
    Set {
        acc: &'a [set_path::AccRow],
        set_sha256: &'a str,
    },
    /// A full scan: both digests. The accumulator is reseeded from its values.
    Dual {
        set_sha256: &'a str,
        values: &'a [crate::kernel::projection_dump::SetValue],
    },
}

/// Record, inside the fold's own transaction, that this delta was applied on
/// top of exactly the state the previous receipt describes.
pub(crate) async fn record_delta_receipt(
    tx: &mut sqlx::SqliteConnection,
    before: &KernelGeneration,
    delta: &kernel_v2_delta::KernelDelta,
) -> Result<Receipt> {
    record_receipt(tx, before, delta, Certified::V1Only).await
}

pub(crate) async fn record_receipt(
    tx: &mut sqlx::SqliteConnection,
    before: &KernelGeneration,
    delta: &kernel_v2_delta::KernelDelta,
    certified: Certified<'_>,
) -> Result<Receipt> {
    let inconsistent = || Error::engine(RECEIPTS_INCONSISTENT);
    let ddl = receipts_ddl(tx).await.map_err(|_| inconsistent())?;
    let previous = last_receipt(tx).await.map_err(|_| inconsistent())?;
    let previous = previous.ok_or_else(inconsistent)?;
    // The receipts must continue the state the fold started from.
    if previous.to_act != before.head_act
        || previous.content_seq_to != before.content_event_seq
        || previous.meta_seq_to != before.meta_event_seq
        || previous.blob_count != before.blob_count
    {
        return Err(inconsistent());
    }
    let head = &delta.head;
    // The fold never touches the cutover tables; if they differ from the
    // anchored ones, the copy was altered and nothing more may be applied.
    let fixed = fixed_digest(tx).await?;
    if fixed != previous.fixed_sha256 {
        return Err(inconsistent());
    }
    let (kind, projection_sha256, projection_set_sha256) = match &certified {
        // This node certifies the v1 digest only, whatever the delta carried.
        // Only a delta that carries one can be applied this way.
        Certified::V1Only => {
            let v1 = head.projection_sha256.clone().ok_or_else(inconsistent)?;
            ("delta", Some(v1), None)
        }
        Certified::Set { set_sha256, .. } => ("delta-set", None, Some((*set_sha256).to_owned())),
        // A full scan certifies what hosted attested: both digests for a
        // version-2 delta; for version 3, which attests nothing, this node's
        // own set digest alone.
        Certified::Dual { set_sha256, .. } => match &head.projection_sha256 {
            Some(v1) => ("delta", Some(v1.clone()), Some((*set_sha256).to_owned())),
            None => ("delta-set", None, Some((*set_sha256).to_owned())),
        },
    };
    if projection_set_sha256.is_some() && ddl != ReceiptsDdl::V2 {
        return Err(inconsistent());
    }
    let mut receipt = Receipt {
        ordinal: previous.ordinal + 1,
        kind: kind.into(),
        from_act: before.head_act,
        to_act: head.head_act,
        content_seq_from: before.content_event_seq,
        content_seq_to: head.content_event_seq,
        meta_seq_from: before.meta_event_seq,
        meta_seq_to: head.meta_event_seq,
        delta_sha256: delta.content_sha256.clone(),
        projection_sha256,
        projection_set_sha256,
        events_sha256: events_digest(
            tx,
            (before.content_event_seq, head.content_event_seq),
            (before.meta_event_seq, head.meta_event_seq),
        )
        .await?,
        blob_count: head.blob_count,
        fixed_sha256: fixed,
        derived_sha256: derived_digest(tx).await?,
        chain_sha256: String::new(),
    };
    receipt.chain_sha256 = receipt.link(&previous.chain_sha256, ddl);
    insert_receipt(tx, &receipt, ddl).await?;
    match certified {
        Certified::V1Only => {
            // Any accumulator cache describes the state BEFORE this delta and
            // this path does not maintain it: empty it in the same
            // transaction, so a cache is never left standing behind a receipt
            // it does not belong to.
            if accumulator_table_present(tx).await? {
                sqlx::query(&format!("DELETE FROM {ACCUMULATOR_TABLE}"))
                    .execute(&mut *tx)
                    .await?;
            }
        }
        Certified::Set { acc, .. } => set_path::write_composed(tx, acc, receipt.ordinal).await?,
        Certified::Dual { values, .. } => set_path::reseed(tx, values, receipt.ordinal).await?,
    }
    Ok(receipt)
}

async fn accumulator_table_present(conn: &mut sqlx::SqliteConnection) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?)",
    )
    .bind(ACCUMULATOR_TABLE)
    .fetch_one(conn)
    .await?)
}

async fn insert_receipt(
    conn: &mut sqlx::SqliteConnection,
    r: &Receipt,
    ddl: ReceiptsDdl,
) -> Result<()> {
    let query = match ddl {
        ReceiptsDdl::V1 => format!(
            "INSERT INTO {RECEIPTS_TABLE}(ordinal,kind,from_act,to_act,content_seq_from,content_seq_to,meta_seq_from,meta_seq_to,delta_sha256,projection_sha256,events_sha256,blob_count,fixed_sha256,derived_sha256,chain_sha256) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
        ),
        ReceiptsDdl::V2 => format!(
            "INSERT INTO {RECEIPTS_TABLE}(ordinal,kind,from_act,to_act,content_seq_from,content_seq_to,meta_seq_from,meta_seq_to,delta_sha256,projection_sha256,projection_set_sha256,events_sha256,blob_count,fixed_sha256,derived_sha256,chain_sha256) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
        ),
    };
    let mut query = sqlx::query(&query)
        .bind(r.ordinal)
        .bind(&r.kind)
        .bind(r.from_act)
        .bind(r.to_act)
        .bind(r.content_seq_from)
        .bind(r.content_seq_to)
        .bind(r.meta_seq_from)
        .bind(r.meta_seq_to)
        .bind(&r.delta_sha256)
        .bind(&r.projection_sha256);
    if ddl == ReceiptsDdl::V2 {
        query = query.bind(&r.projection_set_sha256);
    }
    query
        .bind(&r.events_sha256)
        .bind(r.blob_count)
        .bind(&r.fixed_sha256)
        .bind(&r.derived_sha256)
        .bind(&r.chain_sha256)
        .execute(conn)
        .await?;
    Ok(())
}

/// Create the receipts table and its base receipt, anchored to the verified
/// checkpoint. Runs once per generation, before the first fold.
async fn create_base_receipt(
    db: &crate::Db,
    generation: &InstalledGeneration,
    with_set: bool,
) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
    let manifest = &generation.manifest;
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?)",
    )
    .bind(RECEIPTS_TABLE)
    .fetch_one(&mut *tx)
    .await?;
    if exists {
        // Already anchored (an earlier attempt committed it).
        tx.rollback().await?;
        return Ok(None);
    }
    let coordinates = crate::standby::kernel_v2::coordinates(&mut tx).await?;
    let acquired = chrono::Utc::now();
    let expected = manifest
        .kernel_v2
        .as_ref()
        .ok_or_else(|| Error::engine("in-place kernel apply requires a v2 generation"))?;
    if &coordinates != expected {
        return Err(Error::engine("checkpoint does not match its manifest"));
    }
    // Computed in this transaction, while the checkpoint file hash has just
    // been verified under the exclusive checkpoint lock: the certified
    // projection of the base, which every later full check compares against.
    // Under the second receipts DDL (the first delta is version 2) the base
    // certifies both digests and seeds the accumulator at ordinal 0.
    let (base_projection, base_set, base_values) = if with_set {
        let (v1, set, values) =
            crate::kernel::projection_dump::dump_on_dual_values(&mut tx).await?;
        (v1.sha256, Some(set.sha256), values)
    } else {
        (
            crate::kernel::projection_dump::dump_on(&mut tx)
                .await?
                .sha256,
            None,
            Vec::new(),
        )
    };
    let ddl = if with_set {
        ReceiptsDdl::V2
    } else {
        ReceiptsDdl::V1
    };
    sqlx::query(if with_set {
        RECEIPTS_DDL_V2
    } else {
        RECEIPTS_DDL
    })
    .execute(&mut *tx)
    .await?;
    let mut receipt = Receipt {
        ordinal: 0,
        kind: "base".into(),
        from_act: coordinates.head_act,
        to_act: coordinates.head_act,
        content_seq_from: 0,
        content_seq_to: coordinates.content_event_seq,
        meta_seq_from: 0,
        meta_seq_to: coordinates.meta_event_seq,
        delta_sha256: manifest.snapshot.sha256.clone(),
        projection_sha256: Some(base_projection),
        projection_set_sha256: base_set,
        events_sha256: events_digest(
            &mut tx,
            (0, coordinates.content_event_seq),
            (0, coordinates.meta_event_seq),
        )
        .await?,
        blob_count: coordinates.blob_count,
        fixed_sha256: fixed_digest(&mut tx).await?,
        derived_sha256: derived_digest(&mut tx).await?,
        chain_sha256: String::new(),
    };
    receipt.chain_sha256 = receipt.link(&genesis_hash(&manifest.snapshot.sha256), ddl);
    insert_receipt(&mut tx, &receipt, ddl).await?;
    if with_set {
        set_path::reseed(&mut tx, &base_values, 0).await?;
    }
    tx.commit().await?;
    // The base's rows were digested in this transaction.
    Ok(Some(acquired))
}

/// A failure around an in-place apply, split at the commit: before it the
/// serving database is unchanged, after it the database has advanced and only
/// the head sidecar may lag.
#[derive(Debug)]
pub(crate) enum InPlaceError {
    BeforeCommit(Error),
    AfterCommit(Error),
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum InPlaceApplied {
    Applied,
    /// A verification is still hashing the unadvanced checkpoint.
    CheckpointVerifying,
}

/// What the in-database receipts say about a copy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InPlaceState {
    /// Never advanced in place.
    NotAdvanced,
    Sound {
        applied: u64,
        db_head_act: i64,
        accumulator: AccumulatorStatus,
    },
}

/// What a full check found out about the optional accumulator cache. A cache
/// that disagrees with the rows is never a reason to refuse the copy (the rows
/// and the receipt are authoritative); it is only reason to stop trusting it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AccumulatorStatus {
    /// The light check does not look.
    NotChecked,
    /// No accumulator rows.
    Absent,
    /// Present, the last receipt certifies a set digest, and every row equals
    /// what the rows recompute to, at the last receipt's ordinal.
    Valid,
    /// Present but not provably current: disagrees with the rows, is at another
    /// ordinal, or sits behind a receipt that certifies no set digest.
    Invalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IntegrityDepth {
    /// O(1): the receipts continue the database and the head sidecar does
    /// not lead it. Run on every refresh tick and on predecessor re-checks.
    Light,
    /// Everything: receipt chain, canonical event rows, every blob against
    /// its content address, and the whole-database projection digest against
    /// the last certified one. Run on startup, rebinding and audit.
    Full,
}

impl GenerationStore {
    /// Coordinate only first-transition setup, not authority or receipt proof.
    /// The caller's existing deadline/cancellation bounds this async wait.
    #[cfg(feature = "v2-kernel-probe")]
    pub(crate) async fn working_source_checkpoint(&self, id: &str) -> Result<File> {
        acquire_checkpoint_shared(&self.root.join("leases"), id).await
    }

    #[cfg(all(test, feature = "v2-kernel-probe"))]
    pub(crate) fn pause_working_transition_for_test(
        &self,
        entered: std::sync::Arc<tokio::sync::Notify>,
        release: std::sync::Arc<tokio::sync::Notify>,
    ) {
        *self.working_transition_pause.lock().unwrap() = Some((entered, release));
    }

    /// Why this delta must take the staged path instead, or `None`.
    pub(crate) fn kernel_in_place_ineligible(
        &self,
        current: &InstalledGeneration,
        observed: &ObservedInstalledConsumerIdentity,
        state: InPlaceState,
    ) -> Option<&'static str> {
        // The file is rewritten under the serving reader. Only a live process
        // of this build is known to open it as an ordinary (not immutable)
        // SQLite file that notices the WAL; anything else keeps the staged
        // path, which never touches the serving file.
        if !self.served_by_build(&current.id, &observed.source_sha) {
            return Some("reader_not_upgraded");
        }
        self.kernel_recheckpoint_due(current, state)
    }

    /// Whether a copy advanced in place has gone on long enough that the next
    /// delta (or, with none pending, the next tick) must re-checkpoint it.
    pub(crate) fn kernel_recheckpoint_due(
        &self,
        current: &InstalledGeneration,
        state: InPlaceState,
    ) -> Option<&'static str> {
        let InPlaceState::Sound { applied, .. } = state else {
            return None;
        };
        let (max_deltas, max_seconds) = recheckpoint_limits();
        if applied >= max_deltas {
            return Some("recheckpoint_delta_count");
        }
        let completed =
            chrono::DateTime::parse_from_rfc3339(&current.manifest.snapshot_completed_at).ok()?;
        (chrono::Utc::now()
            .signed_duration_since(completed)
            .num_seconds()
            >= max_seconds)
            .then_some("recheckpoint_age")
    }

    /// Open the serving kernel-v2 database for one in-place delta. The first
    /// time, and only while the file is still exactly its checkpoint, verify
    /// the checkpoint hash, mark the head `delta` (as for v1) and anchor the
    /// receipt chain. That first transition waits for no one: if a
    /// verification is still hashing the checkpoint this returns `None`.
    async fn open_kernel_in_place_writer(
        &self,
        generation: &InstalledGeneration,
        crash: Option<InPlaceCrash>,
        base_with_set: bool,
    ) -> Result<Option<crate::Db>> {
        if generation.manifest.kernel_v2.is_none() {
            return Err(Error::engine(
                "in-place kernel apply requires a v2 generation",
            ));
        }
        let mut head = self
            .generation_head(&generation.id)?
            .unwrap_or_else(|| GenerationHead::checkpoint(generation));
        if head.full_refresh_required {
            return Err(Error::engine("generation requires a whole snapshot"));
        }
        let first = !head.advanced_in_place();
        // Keep the existing transition fence until its base receipt commits.
        // Marking the sidecar alone is not completed source admission.
        let mut checkpoint_guard = None;
        if first {
            let checkpoint =
                open_generation_lock(&self.root.join("leases"), &generation.id, "checkpoint")?;
            match checkpoint.try_lock_exclusive() {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
                Err(error) => return Err(error.into()),
            }
            // The last moment the file hash can mean anything: after this the
            // receipt chain, anchored to this hash, takes over.
            let path = generation.snapshot_path.clone();
            let manifest = generation.manifest.clone();
            tokio::task::spawn_blocking(move || {
                verify_snapshot_byte_identity(&path, &manifest, None)
            })
            .await
            .map_err(|_| Error::engine("checkpoint verification worker failed"))??;
            head.materialization = StandbyGenerationMaterialization::Delta;
            head.version = 2;
            self.write_generation_head(&head)?;
            checkpoint_guard = Some(checkpoint);
            if crash == Some(InPlaceCrash::AfterMarkBeforeBaseReceipt) {
                return Err(Error::engine(INJECTED_CRASH));
            }
            #[cfg(all(test, feature = "v2-kernel-probe"))]
            {
                let pause = self.working_transition_pause.lock().unwrap().take();
                if let Some((entered, release)) = pause {
                    entered.notify_one();
                    release.notified().await;
                }
            }
        }
        let directory = generation
            .snapshot_path
            .parent()
            .ok_or_else(|| Error::engine("standby generation has no directory"))?;
        set_mode(directory, 0o700)?;
        set_mode(&generation.snapshot_path, 0o600)?;
        let writer = crate::db::open_kernel_v2_in_place_writer(&generation.snapshot_path).await?;
        if first {
            let created = create_base_receipt(&writer, generation, base_with_set).await;
            // The base receipt is an audit of the checkpoint (published only
            // after its commit); a generation is unaudited until it exists.
            if let Ok(Some(acquired)) = &created {
                let _ = self.write_audit(&generation.id, 0, *acquired, audit::AUDIT_VERIFIED);
            }
            let created = match created {
                Ok(_) if crash == Some(InPlaceCrash::AfterBaseReceipt) => {
                    Err(Error::engine(INJECTED_CRASH))
                }
                Ok(_) => Ok(()),
                Err(error) => Err(error),
            };
            if let Err(error) = created {
                writer.close().await;
                return Err(error);
            }
        }
        drop(checkpoint_guard); // base receipt commit acknowledged before admission.
        Ok(Some(writer))
    }

    /// Apply one authenticated small delta to the serving database inside one
    /// WAL transaction (fold, digests, receipt), then (and only then) update
    /// the head sidecar.
    pub(crate) async fn apply_kernel_delta_in_place(
        &self,
        current: &InstalledGeneration,
        delta: &TrustedKernelDelta,
        synced_at: &str,
        timings: &PhaseTimings,
        crash: Option<InPlaceCrash>,
    ) -> std::result::Result<InPlaceApplied, InPlaceError> {
        let before = InPlaceError::BeforeCommit;
        let after = InPlaceError::AfterCommit;
        // Retention takes this lease exclusively before removing a generation.
        let _lease = self.acquire_serving_lease(&current.id).map_err(before)?;
        timings.lap("in_place_lease");
        let Some(writer) = self
            .open_kernel_in_place_writer(
                current,
                crash,
                delta.delta().version != kernel_v2_delta::WIRE_VERSION_1,
            )
            .await
            .map_err(|error| {
                // A failed base receipt or checkpoint proof is trouble with
                // this copy; busy, I/O and cancellation are not.
                self.note_at_rest_refusal(&current.id, None, &error);
                before(error)
            })?
        else {
            return Ok(InPlaceApplied::CheckpointVerifying);
        };
        timings.lap("in_place_open_writer");
        let hook = move || {
            if crash == Some(InPlaceCrash::BeforeCommit) {
                Err(Error::engine(INJECTED_CRASH))
            } else {
                Ok(())
            }
        };
        // After enough damaged-cache reseeds in one generation the set path
        // stays off until the generation is re-checkpointed.
        let mode =
            if self.set_path_counters(&current.id).mismatch_reseeded >= SUPPRESS_AFTER_RESEEDS {
                kernel_v2_delta::ApplyMode::InPlaceSetSuppressed
            } else {
                kernel_v2_delta::ApplyMode::InPlace
            };
        let result = kernel_v2_delta::apply_with_hook(&writer, delta, timings, mode, &hook).await;
        writer.close().await;
        self.note_set_path(&current.id, timings);
        timings.lap("in_place_close_writer");
        result.map_err(|error| {
            // An apply that refuses (a projection divergence, inconsistent
            // receipts, ...) removes standing at-rest trust at once. A weaker
            // SUCCESS below never writes an at-rest record.
            self.note_at_rest_refusal(&current.id, None, &error);
            before(error)
        })?;
        // ---- the commit has returned: durable, and visible to new reads ----
        // A full-scan apply verified every row against hosted's digest: now
        // that it has committed, that is an audit. (Never before: an aborted
        // transaction must not refresh serving eligibility.)
        if let Some((scanned_at, ordinal)) = timings.full_scan_evidence() {
            let _ = self.write_audit(&current.id, ordinal, scanned_at, audit::AUDIT_VERIFIED);
        }
        if crash == Some(InPlaceCrash::AfterCommitBeforeSidecar) {
            return Err(after(Error::engine(INJECTED_CRASH)));
        }
        self.record_synced(current, delta.delta().head.head_act, synced_at)
            .map_err(after)?;
        // The apply emptied any accumulator cache, so its marker is stale.
        let _ = self.clear_accumulator_marker(&current.id);
        timings.lap("in_place_sidecars");
        if crash == Some(InPlaceCrash::AfterSidecar) {
            return Err(after(Error::engine(INJECTED_CRASH)));
        }
        Ok(InPlaceApplied::Applied)
    }

    fn set_path_counters_file(&self, id: &str) -> PathBuf {
        self.root.join("heads").join(format!("{id}.set-path.json"))
    }

    /// This generation's set-path counters (zero when none were recorded or the
    /// file is unreadable: they only ever turn the fast path off, never on).
    pub(crate) fn set_path_counters(&self, id: &str) -> SetPathCounters {
        if !is_generation_id(id) {
            return SetPathCounters::default();
        }
        fs::read(self.set_path_counters_file(id))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    /// Count one attempt's outcome against its generation. Best effort: the
    /// counters feed telemetry and the suppression threshold, nothing else.
    fn note_set_path(&self, id: &str, timings: &PhaseTimings) {
        let mut report = timings.set_path_json();
        let Some(kind) = report["kind"].as_str().map(str::to_owned) else {
            return;
        };
        let mut counters = self.set_path_counters(id);
        counters.record(&kind);
        report["counters"] = serde_json::to_value(&counters).unwrap_or_default();
        report["suppressed"] = (counters.mismatch_reseeded >= SUPPRESS_AFTER_RESEEDS).into();
        timings.set_set_path(report);
        if !is_generation_id(id) {
            return;
        }
        let write = || -> Result<()> {
            let heads = self.root.join("heads");
            let mut temp = tempfile::NamedTempFile::new_in(&heads)?;
            temp.write_all(&serde_json::to_vec(&counters)?)?;
            temp.persist(self.set_path_counters_file(id))
                .map_err(|e| e.error)?;
            Ok(())
        };
        let _ = write();
    }

    /// Repair a head sidecar that lags its database (a crash after the
    /// commit). Only ever raises `head_act` to what the database proves, and
    /// keeps `synced_at`: freshness is a claim about hosted, not about disk.
    pub(crate) fn heal_head_from_database(&self, id: &str, db_head_act: i64) -> Result<()> {
        if let Some(mut head) = self.generation_head(id)? {
            if head.advanced_in_place() && head.head_act < db_head_act {
                head.head_act = db_head_act;
                self.write_generation_head(&head)?;
            }
        }
        Ok(())
    }

    /// Full integrity of a consistent private COPY of an in-place-advanced
    /// generation, before a staged re-checkpoint inherits it. Any failure of
    /// the copy's own proof forces a hosted whole snapshot.
    pub(crate) async fn verify_advanced_copy(
        &self,
        copy: &Path,
        generation: &InstalledGeneration,
    ) -> Result<()> {
        let result = prove_advanced_copy(copy, generation).await;
        self.refuse_unproved_copy(generation, result)
    }

    /// Map a failed proof of an inherited base to the refusal that requires a
    /// whole snapshot; infrastructure failures stay retryable.
    fn refuse_unproved_copy(
        &self,
        generation: &InstalledGeneration,
        result: Result<()>,
    ) -> Result<()> {
        match result {
            Ok(()) => Ok(()),
            Err(error) if audit_infrastructure_error(&error) => Err(error),
            Err(_) => {
                self.note_at_rest_failure(&generation.id, None);
                let _ = self.require_full_refresh(generation);
                Err(Error::engine(BASE_UNPROVED))
            }
        }
    }

    /// Admission check for every path that accepts an already-installed
    /// kernel-v2 copy (startup, consumer rebinding, predecessor re-check):
    /// verify it, and repair a head sidecar that merely lags the database.
    pub(crate) async fn admit_kernel_in_place(
        &self,
        generation: &InstalledGeneration,
        depth: IntegrityDepth,
    ) -> Result<()> {
        let (state, acquired) = self
            .check_in_place_integrity_acquired(generation, depth)
            .await;
        let state = match state {
            Ok(state) => state,
            Err(error) => {
                self.note_at_rest_refusal(&generation.id, acquired, &error);
                return Err(error);
            }
        };
        if let InPlaceState::Sound { db_head_act, .. } = state {
            // Best effort: the sidecar is only a cache of the database.
            let _ = self.heal_head_from_database(&generation.id, db_head_act);
        }
        self.record_integrity_findings(&generation.id, state);
        // A Full check judged every row against the last receipt: it is an
        // audit, and it counts as one (the Light check looks at nothing).
        if depth == IntegrityDepth::Full {
            if let (
                InPlaceState::Sound {
                    applied,
                    accumulator,
                    ..
                },
                Some(acquired),
            ) = (state, acquired)
            {
                let outcome = if accumulator == AccumulatorStatus::Invalid {
                    audit::AUDIT_CACHE_INVALID
                } else {
                    audit::AUDIT_VERIFIED
                };
                let _ = self.write_audit(&generation.id, applied as i64, acquired, outcome);
            }
        }
        Ok(())
    }

    /// Persist what a full check learned about the accumulator cache. Every
    /// caller of the full check does this (admission and audit; the
    /// re-checkpoint pre-verification examines a private copy whose cache is
    /// about to be dropped, so there is nothing to mark). The marker is advisory
    /// and self-healing: written on `Invalid`, removed by any full check that
    /// finds the cache `Absent` (an empty cache counts as absent) or `Valid`,
    /// and by an in-place apply, which empties the cache.
    pub(crate) fn record_integrity_findings(&self, id: &str, state: InPlaceState) {
        if let InPlaceState::Sound { accumulator, .. } = state {
            let _ = match accumulator {
                AccumulatorStatus::Invalid => self.mark_accumulator_invalid(id),
                AccumulatorStatus::Absent | AccumulatorStatus::Valid => {
                    self.clear_accumulator_marker(id)
                }
                AccumulatorStatus::NotChecked => Ok(()),
            };
        }
    }

    pub(crate) fn clear_accumulator_marker(&self, id: &str) -> Result<()> {
        if !is_generation_id(id) {
            return Ok(());
        }
        match fs::remove_file(
            self.root
                .join("heads")
                .join(format!("{id}.accumulator-invalid")),
        ) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    /// Record that the accumulator cache of this generation must not be
    /// trusted (`heads/<id>.accumulator-invalid`, empty). The check that found
    /// it cannot write the database, and the rows stay authoritative, so the
    /// copy keeps serving; whoever maintains the cache reads this marker.
    pub(crate) fn mark_accumulator_invalid(&self, id: &str) -> Result<()> {
        if !is_generation_id(id) {
            return Err(Error::engine("invalid standby generation id"));
        }
        let path = self
            .root
            .join("heads")
            .join(format!("{id}.accumulator-invalid"));
        OpenOptions::new().create(true).append(true).open(&path)?;
        set_mode(&path, 0o600)?;
        File::open(self.root.join("heads"))?.sync_all()?;
        Ok(())
    }

    #[cfg(all(test, feature = "v2-kernel-probe"))]
    pub(crate) fn accumulator_marked_invalid(&self, id: &str) -> bool {
        is_generation_id(id)
            && self
                .root
                .join("heads")
                .join(format!("{id}.accumulator-invalid"))
                .exists()
    }

    /// Integrity of a kernel-v2 copy that may have been advanced in place,
    /// judged only from the database's own receipts and canonical rows. Any
    /// failure means in-place serving of this copy is refused and a staged or
    /// whole-snapshot recovery is required; nothing is repaired by hashing
    /// unverified local state.
    pub(crate) async fn check_in_place_integrity(
        &self,
        generation: &InstalledGeneration,
        depth: IntegrityDepth,
    ) -> Result<InPlaceState> {
        self.check_in_place_integrity_acquired(generation, depth)
            .await
            .0
    }

    /// [`Self::check_in_place_integrity`], also reporting when its read
    /// snapshot was acquired (`None` if it never got that far).
    pub(crate) async fn check_in_place_integrity_acquired(
        &self,
        generation: &InstalledGeneration,
        depth: IntegrityDepth,
    ) -> (Result<InPlaceState>, Option<chrono::DateTime<chrono::Utc>>) {
        let mut acquired = None;
        let result = self
            .check_in_place_on_snapshot(generation, depth, &mut acquired, None)
            .await;
        (result, acquired)
    }

    /// The scheduled audit's check: [`IntegrityDepth::Full`] plus the at-rest
    /// coverage (`quick_check`, foreign keys, shape/frontier), all inside ONE
    /// pinned read transaction. The evidence (`ordinal`, `chain_sha256`,
    /// receipts DDL) is read on that same snapshot; it is `None` only for a
    /// copy that is not advanced in place.
    pub(crate) async fn check_in_place_at_rest_acquired(
        &self,
        generation: &InstalledGeneration,
    ) -> (
        Result<(InPlaceState, Option<at_rest::AtRestEvidence>)>,
        Option<chrono::DateTime<chrono::Utc>>,
    ) {
        let mut acquired = None;
        let mut evidence = None;
        let state = self
            .check_in_place_on_snapshot(
                generation,
                IntegrityDepth::Full,
                &mut acquired,
                Some(&mut evidence),
            )
            .await;
        (state.map(|state| (state, evidence)), acquired)
    }

    async fn check_in_place_on_snapshot(
        &self,
        generation: &InstalledGeneration,
        depth: IntegrityDepth,
        acquired: &mut Option<chrono::DateTime<chrono::Utc>>,
        at_rest: Option<&mut Option<at_rest::AtRestEvidence>>,
    ) -> Result<InPlaceState> {
        async {
            let id = &generation.id;
            let Some(head) = self.generation_head(id)? else {
                return Ok(InPlaceState::NotAdvanced);
            };
            if !head.advanced_in_place() || generation.manifest.kernel_v2.is_none() {
                return Ok(InPlaceState::NotAdvanced);
            }
            // Sidecar first, database second: the sidecar can only lag the
            // database, so this order never reports a false "ahead".
            let mut conn = sqlx::SqliteConnection::connect_with(
                &sqlx::sqlite::SqliteConnectOptions::new()
                    .filename(&generation.snapshot_path)
                    .create_if_missing(false)
                    .read_only(true)
                    .busy_timeout(std::time::Duration::from_secs(60)),
            )
            .await?;
            let result = verify_receipts(
                &mut conn,
                generation,
                head.head_act,
                depth,
                acquired,
                at_rest,
            )
            .await;
            conn.close().await?;
            result
        }
        .await
    }
}

/// The proof behind [`GenerationStore::verify_advanced_copy`], returning the
/// real error (a foreign-key violation, a receipt mismatch) rather than the
/// refusal it is mapped to.
///
/// Startup, rebinding and audit already run the whole-database foreign-key
/// check (inside `verify_snapshot_database`) before the receipt check. The
/// staged re-checkpoint did not: it copied the base, applied a delta and
/// published a fresh file hash. The check runs here, first, so a violation is
/// named as such rather than as a digest mismatch.
pub(crate) async fn prove_advanced_copy(
    copy: &Path,
    generation: &InstalledGeneration,
) -> Result<()> {
    let mut conn = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new()
            .filename(copy)
            .create_if_missing(false)
            .read_only(true)
            .busy_timeout(std::time::Duration::from_secs(60)),
    )
    .await?;
    let result = async {
        let violated: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)")
                .fetch_one(&mut conn)
                .await?;
        if violated {
            return Err(Error::engine(
                "kernel-v2 in-place copy: foreign-key violation",
            ));
        }
        verify_receipts(
            &mut conn,
            generation,
            0,
            IntegrityDepth::Full,
            &mut None,
            None,
        )
        .await
        .map(|_| ())
    }
    .await;
    conn.close().await?;
    result
}

/// Verify a current accepted source on the SAME snapshot retained by its owner.
/// `head` was sampled from the generation sidecar BEFORE pinning the database;
/// it is a lower bound, never a head invented from the coordinates being judged.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn verify_working_source_on(
    tx: &mut sqlx::SqliteConnection,
    generation: &InstalledGeneration,
    head: Option<&super::GenerationHead>,
) -> Result<KernelGeneration> {
    let checkpoint = generation
        .manifest
        .kernel_v2
        .as_ref()
        .ok_or_else(|| Error::engine("working source is not kernel-v2"))?;
    let native = crate::standby::kernel_v2::coordinates(tx).await?;
    let expected_head = head.map_or(checkpoint.head_act, |head| head.head_act);
    if head.is_some_and(|head| head.generation_id != generation.id || head.full_refresh_required)
        || expected_head > native.head_act
        || native.genesis_event_id != checkpoint.genesis_event_id
        || native.reader_format != checkpoint.reader_format
        || native.schema_sha256 != checkpoint.schema_sha256
        || crate::standby::kernel_v2::origin(tx, &native).await?
            != generation.manifest.origin_database_id
    {
        return Err(Error::engine("verified working source coordinates changed"));
    }
    if native != *checkpoint || head.is_some_and(|head| head.advanced_in_place()) {
        let violated: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)")
                .fetch_one(&mut *tx)
                .await?;
        if violated {
            return Err(Error::engine(
                "kernel-v2 in-place copy: foreign-key violation",
            ));
        }
        // Existing authenticated checkpoint/receipt/event/blob/projection proof,
        // not a raw current-coordinate assertion or a certificate for W.
        verify_receipts_on(tx, generation, expected_head, IntegrityDepth::Full).await?;
    }
    Ok(native)
}

async fn verify_receipts(
    conn: &mut sqlx::SqliteConnection,
    generation: &InstalledGeneration,
    head_act: i64,
    depth: IntegrityDepth,
    acquired: &mut Option<chrono::DateTime<chrono::Utc>>,
    at_rest: Option<&mut Option<at_rest::AtRestEvidence>>,
) -> Result<InPlaceState> {
    if generation.manifest.kernel_v2.is_none() {
        return Err(Error::engine(
            "kernel-v2 in-place copy: not a kernel-v2 generation",
        ));
    }
    let mut tx = sqlx::Connection::begin(&mut *conn).await?;
    // One dedicated first read pins the snapshot, and the time is taken
    // immediately after it, before any other work: the audit's time is when
    // the rows it is about to judge were current, not when the check got
    // around to them (`coordinates` below reads several tables).
    let _ = sqlx::query_scalar::<_, i64>("SELECT 1 FROM sqlite_schema LIMIT 1")
        .fetch_optional(&mut *tx)
        .await?;
    *acquired = Some(chrono::Utc::now());
    #[cfg(test)]
    audit::stall_after_pin().await;
    let result = match at_rest {
        None => verify_receipts_on(&mut tx, generation, head_act, depth).await?,
        Some(evidence) => {
            // Coverage 1 on the one pinned snapshot, each step a timed
            // phase: SQLite health (cheap, so first), the receipt Full
            // check, then shape and the receipt anchor.
            at_rest::health_checks(&mut tx).await?;
            let state = verification_phase(
                "audit-receipts-full",
                verify_receipts_on(&mut tx, generation, head_act, depth),
            )
            .await?;
            *evidence = Some(at_rest::shape_and_evidence(&mut tx, generation).await?);
            state
        }
    };
    if depth == IntegrityDepth::Full {
        tx.rollback().await?;
    }
    Ok(result)
}

// Same proof on the caller's retained snapshot. No BEGIN/rollback here: the
// source pin must survive through the working restart grounding comparison.
async fn verify_receipts_on(
    tx: &mut sqlx::SqliteConnection,
    generation: &InstalledGeneration,
    head_act: i64,
    depth: IntegrityDepth,
) -> Result<InPlaceState> {
    let bad = |what: &str| Error::engine(format!("kernel-v2 in-place copy: {what}"));
    let manifest = &generation.manifest;
    let base = manifest
        .kernel_v2
        .as_ref()
        .ok_or_else(|| bad("not a kernel-v2 generation"))?;
    let coordinates = crate::standby::kernel_v2::coordinates(tx).await?;
    if head_act > coordinates.head_act {
        return Err(bad("head record is ahead of its database"));
    }
    let table: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?)",
    )
    .bind(RECEIPTS_TABLE)
    .fetch_one(&mut *tx)
    .await?;
    if !table {
        // Marked advanced yet never anchored (an interrupted first write, or
        // a dropped table): the copy is unproved, whatever its coordinates.
        return Err(bad("advanced without apply receipts"));
    }
    let ddl = receipts_ddl(&mut *tx).await?;
    let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {RECEIPTS_TABLE}"))
        .fetch_one(&mut *tx)
        .await?;
    let last = last_receipt(&mut *tx)
        .await?
        .ok_or_else(|| bad("empty receipt chain"))?;
    if last.ordinal + 1 != count
        || last.to_act != coordinates.head_act
        || last.content_seq_to != coordinates.content_event_seq
        || last.meta_seq_to != coordinates.meta_event_seq
        || last.blob_count != coordinates.blob_count
    {
        return Err(bad("receipts do not continue the database"));
    }
    // The cutover rows are tiny and must equal the anchored ones at every
    // depth; the base receipt (ordinal 0) carries the anchor.
    let anchor: String = sqlx::query_scalar(&format!(
        "SELECT fixed_sha256 FROM {RECEIPTS_TABLE} WHERE ordinal=0"
    ))
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| bad("no base receipt"))?;
    if last.fixed_sha256 != anchor || fixed_digest(&mut *tx).await? != anchor {
        return Err(bad("cutover rows differ from the checkpoint's"));
    }
    if depth == IntegrityDepth::Light {
        return Ok(InPlaceState::Sound {
            applied: (count - 1) as u64,
            db_head_act: coordinates.head_act,
            accumulator: AccumulatorStatus::NotChecked,
        });
    }
    // ---- full: receipt chain from the checkpoint anchor ----
    let receipts: Vec<Receipt> = sqlx::query_as(&format!(
        "SELECT {} FROM {RECEIPTS_TABLE} ORDER BY ordinal",
        ddl.columns()
    ))
    .fetch_all(&mut *tx)
    .await?;
    let mut previous: Option<&Receipt> = None;
    let mut chain = genesis_hash(&manifest.snapshot.sha256);
    for (index, receipt) in receipts.iter().enumerate() {
        let well_formed = receipt_well_formed(
            receipt,
            previous,
            index as i64,
            ddl,
            manifest,
            base,
            &anchor,
        );
        chain = receipt.link(&chain, ddl);
        if !well_formed || chain != receipt.chain_sha256 {
            return Err(bad("receipt chain is broken"));
        }
        // Canonical event rows of this segment against what was recorded.
        let digest = events_digest(
            &mut *tx,
            (receipt.content_seq_from, receipt.content_seq_to),
            (receipt.meta_seq_from, receipt.meta_seq_to),
        )
        .await?;
        if digest != receipt.events_sha256 {
            return Err(bad("canonical event rows differ from their receipt"));
        }
        previous = Some(receipt);
    }
    // Blobs are content addressed: every row must be what its key says.
    let blobs: i64 = {
        let mut stream = sqlx::query_as::<_, (String, Vec<u8>, i64)>(
            "SELECT sha256,bytes,size_bytes FROM kernel_blobs",
        )
        .fetch(&mut *tx);
        let mut seen = 0_i64;
        while let Some((key, bytes, size)) = stream.try_next().await? {
            if size != bytes.len() as i64 || sha256_bytes(&bytes) != key {
                return Err(bad("a blob differs from its content address"));
            }
            seen += 1;
        }
        seen
    };
    if blobs != coordinates.blob_count {
        return Err(bad("blob count differs from the database head"));
    }
    // Excluded tables that move with deltas, as of the last receipt.
    if derived_digest(&mut *tx).await? != last.derived_sha256 {
        return Err(bad("derived tables differ from the last receipt"));
    }
    // The rows recompute to every digest the last receipt certifies, in one
    // ordered pass: the v1 digest if it carries one, the set digest if it
    // carries one. A receipt this node wrote has no set digest and is checked
    // on v1 only. A mismatch is receipt-versus-rows, and refuses.
    let (v1, set, values) = crate::kernel::projection_dump::dump_on_dual_values(&mut *tx).await?;
    if last.projection_sha256.is_none() && last.projection_set_sha256.is_none() {
        return Err(bad("the last receipt certifies no projection digest"));
    }
    if last
        .projection_sha256
        .as_deref()
        .is_some_and(|certified| certified != v1.sha256)
    {
        return Err(bad("projection differs from the last authenticated delta"));
    }
    if last
        .projection_set_sha256
        .as_deref()
        .is_some_and(|certified| certified != set.sha256)
    {
        return Err(bad(
            "projection set digest differs from the last authenticated delta",
        ));
    }
    // The optional accumulator cache is judged against the rows, never the
    // other way round: if it disagrees, the copy still passes and the cache is
    // reported invalid for whoever maintains it.
    let accumulator = accumulator_status(&mut *tx, &values, &last).await?;
    Ok(InPlaceState::Sound {
        applied: (count - 1) as u64,
        db_head_act: coordinates.head_act,
        accumulator,
    })
}

/// The per-receipt predicates the Full check applies to every receipt: kind and
/// certified digest, contiguous acts and sequences with the previous receipt,
/// the cutover anchor, and well-formed digests. The chain LINK is checked
/// separately by the caller. The trusted-at-rest suffix check applies exactly
/// these to the receipts after its anchor, so the two cannot drift apart.
pub(super) fn receipt_well_formed(
    receipt: &Receipt,
    previous: Option<&Receipt>,
    index: i64,
    ddl: ReceiptsDdl,
    manifest: &StandbySnapshotManifest,
    base: &KernelGeneration,
    anchor: &str,
) -> bool {
    let well_formed = match previous {
        None => {
            receipt.kind == "base"
                && receipt.ordinal == 0
                && receipt.delta_sha256 == manifest.snapshot.sha256
                && receipt.from_act == base.head_act
                && receipt.to_act == base.head_act
                && receipt.content_seq_from == 0
                && receipt.content_seq_to == base.content_event_seq
                && receipt.meta_seq_from == 0
                && receipt.meta_seq_to == base.meta_event_seq
                && receipt.blob_count == base.blob_count
        }
        Some(prior) => {
            // `delta` certifies the v1 digest; `delta-set` (second DDL
            // only) certifies the set digest. Either way something is
            // certified.
            let certifies = match receipt.kind.as_str() {
                "delta" => receipt.projection_sha256.is_some(),
                "delta-set" => ddl == ReceiptsDdl::V2 && receipt.projection_set_sha256.is_some(),
                _ => false,
            };
            certifies
                && receipt.ordinal == index
                && receipt.from_act == prior.to_act
                && receipt.to_act >= receipt.from_act
                && receipt.content_seq_from == prior.content_seq_to
                && receipt.content_seq_to >= receipt.content_seq_from
                && receipt.meta_seq_from == prior.meta_seq_to
                && receipt.meta_seq_to >= receipt.meta_seq_from
        }
    };
    well_formed && receipt.fixed_sha256 == anchor && receipt.digests_well_formed()
}

async fn accumulator_status(
    conn: &mut sqlx::SqliteConnection,
    values: &[crate::kernel::projection_dump::SetValue],
    last: &Receipt,
) -> Result<AccumulatorStatus> {
    let present: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?)",
    )
    .bind(ACCUMULATOR_TABLE)
    .fetch_one(&mut *conn)
    .await?;
    if !present {
        return Ok(AccumulatorStatus::Absent);
    }
    let raw = sqlx::query(&format!(
        "SELECT name,schema_sha256,rows,value,ordinal FROM {ACCUMULATOR_TABLE} ORDER BY name"
    ))
    .fetch_all(&mut *conn)
    .await?;
    // The cache is untrusted: a row of the wrong types or shape is a cache
    // problem (Invalid), never a reason to fail a check the rows already passed.
    let mut rows = Vec::with_capacity(raw.len());
    for row in &raw {
        use sqlx::Row as _;
        let decoded = (|| -> std::result::Result<_, sqlx::Error> {
            Ok((
                row.try_get::<String, _>(0)?,
                row.try_get::<String, _>(1)?,
                row.try_get::<i64, _>(2)?,
                row.try_get::<Vec<u8>, _>(3)?,
                row.try_get::<i64, _>(4)?,
            ))
        })();
        match decoded {
            Ok(decoded) if decoded.3.len() == crate::kernel::projection_set::BYTE_SIZE => {
                rows.push(decoded)
            }
            _ => return Ok(AccumulatorStatus::Invalid),
        }
    }
    if raw.is_empty() {
        return Ok(AccumulatorStatus::Absent);
    }
    if last.projection_set_sha256.is_none() {
        // Behind a receipt that certifies no set digest it cannot be current.
        return Ok(AccumulatorStatus::Invalid);
    }
    let matches = rows.len() == values.len()
        && rows.iter().zip(values).all(|(row, value)| {
            row.0 == value.name
                && row.1 == value.schema_sha256
                && row.2 == value.rows as i64
                && row.3 == value.value
                && row.4 == last.ordinal
        });
    Ok(if matches {
        AccumulatorStatus::Valid
    } else {
        AccumulatorStatus::Invalid
    })
}

/// Test fixture: rewrite a node-written (first DDL) generation into the shape a
/// node that also proves the set digest leaves behind. The receipts move to the
/// second DDL with its link format, the newest `delta` becomes a `delta-set`
/// that certifies only the set digest, and a populated accumulator cache sits
/// at that receipt's ordinal.
#[cfg(all(test, feature = "v2-kernel-probe"))]
pub(crate) async fn convert_to_n2_shape(
    path: &Path,
    generation: &InstalledGeneration,
) -> Result<()> {
    convert_to_n2_shape_with(path, generation, false).await
}

/// [`convert_to_n2_shape`], optionally with the newest receipt certifying the
/// v1 digest as well as the set digest.
#[cfg(all(test, feature = "v2-kernel-probe"))]
pub(crate) async fn convert_to_n2_shape_with(
    path: &Path,
    generation: &InstalledGeneration,
    certify_v1_too: bool,
) -> Result<()> {
    let mut conn = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new()
            .filename(path)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal),
    )
    .await?;
    let mut tx = sqlx::Connection::begin(&mut conn).await?;
    let old: Vec<Receipt> = sqlx::query_as(&format!(
        "SELECT {} FROM {RECEIPTS_TABLE} ORDER BY ordinal",
        ReceiptsDdl::V1.columns()
    ))
    .fetch_all(&mut *tx)
    .await?;
    sqlx::query(&format!("DROP TABLE {RECEIPTS_TABLE}"))
        .execute(&mut *tx)
        .await?;
    sqlx::query(RECEIPTS_DDL_V2).execute(&mut *tx).await?;
    let (v1, set, values) = crate::kernel::projection_dump::dump_on_dual_values(&mut tx).await?;
    let mut chain = genesis_hash(&generation.manifest.snapshot.sha256);
    let last = old.len() - 1;
    for (index, mut receipt) in old.into_iter().enumerate() {
        if index == last && index > 0 {
            receipt.kind = "delta-set".into();
            receipt.projection_sha256 = certify_v1_too.then(|| v1.sha256.clone());
            receipt.projection_set_sha256 = Some(set.sha256.clone());
        }
        receipt.chain_sha256 = receipt.link(&chain, ReceiptsDdl::V2);
        chain = receipt.chain_sha256.clone();
        insert_receipt(&mut tx, &receipt, ReceiptsDdl::V2).await?;
    }
    sqlx::query(ACCUMULATOR_DDL).execute(&mut *tx).await?;
    for value in values {
        sqlx::query(&format!(
            "INSERT INTO {ACCUMULATOR_TABLE}(name,schema_sha256,rows,value,ordinal) VALUES(?,?,?,?,?)"
        ))
        .bind(&value.name)
        .bind(&value.schema_sha256)
        .bind(value.rows as i64)
        .bind(&value.value)
        .bind(last as i64)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    conn.close().await?;
    Ok(())
}

/// Test fixture: recompute every `chain_sha256` of a (possibly hand-edited)
/// receipt table, choosing each receipt's link format, so that a test can
/// change one thing without the chain noticing first.
#[cfg(all(test, feature = "v2-kernel-probe"))]
pub(crate) async fn rechain_receipts(
    path: &Path,
    generation: &InstalledGeneration,
    format_of: impl Fn(i64) -> ReceiptsDdl,
) -> Result<()> {
    let mut conn = sqlx::SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new()
            .filename(path)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal),
    )
    .await?;
    let ddl = receipts_ddl(&mut conn).await?;
    let receipts: Vec<Receipt> = sqlx::query_as(&format!(
        "SELECT {} FROM {RECEIPTS_TABLE} ORDER BY ordinal",
        ddl.columns()
    ))
    .fetch_all(&mut conn)
    .await?;
    let mut chain = genesis_hash(&generation.manifest.snapshot.sha256);
    for receipt in receipts {
        chain = receipt.link(&chain, format_of(receipt.ordinal));
        sqlx::query(&format!(
            "UPDATE {RECEIPTS_TABLE} SET chain_sha256=? WHERE ordinal=?"
        ))
        .bind(&chain)
        .bind(receipt.ordinal)
        .execute(&mut conn)
        .await?;
    }
    conn.close().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt(projection: Option<&str>, set: Option<&str>) -> Receipt {
        Receipt {
            ordinal: 3,
            kind: "delta-set".into(),
            from_act: 1,
            to_act: 2,
            content_seq_from: 1,
            content_seq_to: 2,
            meta_seq_from: 0,
            meta_seq_to: 0,
            delta_sha256: "a".repeat(64),
            projection_sha256: projection.map(str::to_owned),
            projection_set_sha256: set.map(str::to_owned),
            events_sha256: "b".repeat(64),
            blob_count: 0,
            fixed_sha256: "c".repeat(64),
            derived_sha256: "d".repeat(64),
            chain_sha256: String::new(),
        }
    }

    /// NULL, a literal dash and an empty string are three different links, and
    /// moving a value between the two optional columns changes the link too.
    #[test]
    fn second_format_links_distinguish_null_from_every_literal() {
        let hex = "e".repeat(64);
        let links = [
            receipt(None, Some(&hex)).link("p", ReceiptsDdl::V2),
            receipt(Some("-"), Some(&hex)).link("p", ReceiptsDdl::V2),
            receipt(Some(""), Some(&hex)).link("p", ReceiptsDdl::V2),
            receipt(Some(&hex), None).link("p", ReceiptsDdl::V2),
            receipt(Some(&hex), Some("-")).link("p", ReceiptsDdl::V2),
            receipt(None, Some("-")).link("p", ReceiptsDdl::V2),
        ];
        let distinct: std::collections::HashSet<_> = links.iter().collect();
        assert_eq!(distinct.len(), links.len());
        // And the two link formats never agree.
        assert_ne!(
            receipt(Some(&hex), None).link("p", ReceiptsDdl::V1),
            receipt(Some(&hex), None).link("p", ReceiptsDdl::V2)
        );
    }
}
