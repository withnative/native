//! Capture of a transaction's effect on the projection's set digest, from
//! SQLite's preupdate hook (design record 5065900, slice 4). Self-contained:
//! nothing calls it yet, and it never writes an accumulator.
//!
//! A writer wraps its connection (inside `BEGIN`) in [`Hooked`]. The hook logs
//! `(table, rowid, base image)` on FIRST touch only: the key of the row as it
//! was before the transaction touched it (the row's element in the set digest),
//! or "absent" for an insert. [`Hooked::finish`] then disarms and unregisters
//! the hook, reads the touched keys' final images back with the same
//! `SELECT *` path the full scan uses, and returns, per table,
//! `Π M(final) / Π M(base)` as a [`MuHash`] with the row-count delta. Applying
//! that to a table's accumulator gives the accumulator after the transaction.
//!
//! Anything the capture cannot prove complete yields [`CaptureOutcome::Anomaly`]
//! and the caller falls back to a full scan: a write to a TEMP table outside the
//! allowlist, to an unknown table or another schema, to a WITHOUT ROWID table,
//! an incremental blob write, an undecodable value, an FTS table whose
//! definition is not the pinned one, or more than [`MAX_TOUCHES`] touched rows
//! or [`MAX_BASE_IMAGE_BYTES`] of base images.

// Unwired until slice 5 (the apply path); tests exercise all of it.
#![allow(dead_code)]
use super::projection_dump::{
    begin_row, hash_cell, hash_row, included_in_projection, put_frame, Cell, RowSink,
    SET_ELEMENT_PREFIX,
};
use super::projection_set::MuHash;
use crate::{Error, Result};
use sha2::{Digest, Sha256};
use sqlx::{Executor, Row, SqliteConnection};
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Touched rows beyond this are an anomaly (the caller does a full scan).
///
/// 8,192 because a capture only pays off while it is much cheaper than the
/// full scan it replaces. Past a few thousand touched rows the read-back
/// (two MuHash elements per changed row) and the hook's per-row cost approach
/// what the full scan costs anyway, so falling back there loses almost
/// nothing, and it bounds the TEMP key table, the base-image map and G3's
/// read-back (measured at this limit in `measure_capture_costs`). A 256-event
/// delta touches far fewer rows than this (see the same measurement).
pub(crate) const MAX_TOUCHES: usize = 8_192;
/// Base-image bytes hashed beyond this are an anomaly.
pub(crate) const MAX_BASE_IMAGE_BYTES: usize = 64 * 1024 * 1024;
/// The only TEMP tables a projector may write while a capture is armed.
pub(crate) fn is_allowlisted_temp(name: &str) -> bool {
    TEMP_ALLOWLIST
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(name))
}
pub(crate) const TEMP_ALLOWLIST: [&str; 2] =
    ["_facet_time_refresh_targets", "_facet_time_snapshots"];
const FTS_LOGICAL: &str = "kernel_search_fts";
const FTS_CONTENT: &str = "kernel_search_fts_content";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Anomaly {
    NonAllowlistedTempWrite(String),
    UnknownTable(String),
    OtherSchema(String),
    BlobWrite,
    PreupdateError,
    UnsupportedStorageClass,
    FtsDdlMismatch,
    WithoutRowid(String),
    ColumnCountMismatch(String),
    /// The old image ends in NULLs under a non-NULL declared default: the
    /// stored record may be shorter than the table (ALTER TABLE ADD COLUMN
    /// after the row was written), and `sqlite3_preupdate_old` reports NULL
    /// where `SELECT *` yields the default. SQLite exposes no stored field
    /// count, so this cannot be told from an explicit NULL.
    ShortRecordDefault(String),
    /// `sqlite_master` (main, or temp outside the allowlist) differs from the
    /// arm-time snapshot: DDL the hook cannot see.
    SchemaChanged,
    /// All of `rowid`, `_rowid_` and `oid` are declared columns.
    RowidShadowed(String),
    /// A TEMP table or view has the name of a main projection table.
    TempShadowsMain(String),
    TooManyTouches,
    BaseImagesTooLarge,
}

impl Anomaly {
    /// A short machine label for telemetry (`kernel-replay.json`).
    pub(crate) fn reason(&self) -> String {
        match self {
            Self::NonAllowlistedTempWrite(_) => "non_allowlisted_temp_write",
            Self::UnknownTable(_) => "unknown_table",
            Self::OtherSchema(_) => "other_schema",
            Self::BlobWrite => "blob_write",
            Self::PreupdateError => "preupdate_error",
            Self::UnsupportedStorageClass => "unsupported_storage_class",
            Self::FtsDdlMismatch => "fts_ddl_mismatch",
            Self::WithoutRowid(_) => "without_rowid",
            Self::ColumnCountMismatch(_) => "column_count_mismatch",
            Self::ShortRecordDefault(_) => "short_record_default",
            Self::SchemaChanged => "schema_changed",
            Self::RowidShadowed(_) => "rowid_shadowed",
            Self::TempShadowsMain(_) => "temp_shadows_main",
            Self::TooManyTouches => "too_many_touches",
            Self::BaseImagesTooLarge => "base_images_too_large",
        }
        .to_owned()
    }
}

/// One table's effect: the multiset delta and the change in its row count.
#[derive(Debug, Clone)]
pub(crate) struct TableDelta {
    pub name: String,
    pub row_delta: i64,
    /// `Π M(final) / Π M(base)`, un-normalised (no inversion has happened).
    pub delta: MuHash,
}

#[derive(Debug)]
pub(crate) enum CaptureOutcome {
    /// Touched tables, by name.
    Delta(Vec<TableDelta>),
    Anomaly(Anomaly),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    /// A projection table: logged and read back.
    Regular,
    /// The FTS5 content shadow table: rows map to logical `kernel_search_fts`.
    FtsContent,
    /// Canonical or physical-layout tables the projection digest excludes.
    Ignored,
    WithoutRowid,
}

/// An owned stored value, as the digest hashes it.
#[derive(Clone, Debug)]
enum Val {
    Null,
    Int(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}
impl Val {
    fn cell(&self) -> Cell<'_> {
        match self {
            Val::Null => Cell::Null,
            Val::Int(v) => Cell::Int(*v),
            Val::Real(v) => Cell::Real(*v),
            Val::Text(v) => Cell::Text(v),
            Val::Blob(v) => Cell::Blob(v),
        }
    }
}

/// A column's declared default, as far as the capture can use it.
#[derive(Clone, Debug)]
enum Dflt {
    /// No default, or `DEFAULT NULL`.
    None,
    /// A default the capture will not evaluate (an expression, a keyword).
    Unevaluable,
    /// A plain literal, evaluated by SQLite with the column's affinity.
    Value(Val),
}

#[derive(Clone, Debug)]
struct ColDefault {
    not_null: bool,
    default: Dflt,
}

#[derive(Debug)]
struct TableInfo {
    kind: Kind,
    /// The table whose rows these are in the digest.
    logical: String,
    /// Columns the hook reports for the table.
    hook_columns: usize,
    /// Columns the digest's `SELECT *` yields for the logical table.
    logical_columns: usize,
    /// Declared REAL affinity, per hook column.
    real_affinity: Vec<bool>,
    /// The first of `rowid`, `_rowid_`, `oid` not shadowed by a column.
    rowid_alias: Option<&'static str>,
    /// Declared NOT NULL and non-NULL default, per hook column.
    defaults: Vec<ColDefault>,
}

#[derive(Debug, Default)]
struct Catalog {
    by_name: HashMap<String, usize>,
    tables: Vec<TableInfo>,
}

#[derive(Default)]
struct State {
    anomaly: Option<Anomaly>,
    /// `(table index, rowid)` -> the base element key, `None` for absent.
    touched: HashMap<(usize, i64), Option<[u8; 32]>>,
    base_bytes: usize,
    /// Old images hashed (for measurement of the short-record rule).
    base_rows: usize,
}

/// Counts the bytes it is fed while hashing them.
struct CountingSink {
    hasher: Sha256,
    bytes: usize,
}
impl RowSink for CountingSink {
    fn put(&mut self, bytes: &[u8]) {
        self.bytes += bytes.len();
        self.hasher.update(bytes);
    }
}

/// SQLite's affinity rules, reduced to what the capture needs: does a column
/// store integral REAL values as integers and convert them back on read?
fn declared_real(declared: &str) -> bool {
    let upper = declared.to_ascii_uppercase();
    if upper.contains("INT")
        || upper.contains("CHAR")
        || upper.contains("CLOB")
        || upper.contains("TEXT")
        || upper.contains("BLOB")
        || upper.is_empty()
    {
        return false;
    }
    upper.contains("REAL") || upper.contains("FLOA") || upper.contains("DOUB")
}

/// A digest of every schema object the capture depends on: all of `main`'s
/// `sqlite_master`, and `temp`'s apart from the allowlisted projector tables
/// (and their indexes). Triggers, even on allowlisted tables, are included.
async fn schema_snapshot(conn: &mut SqliteConnection) -> Result<SchemaSnapshot> {
    let rows = sqlx::query(
        "SELECT 'main', type, name, tbl_name, sql FROM main.sqlite_master \
         UNION ALL \
         SELECT 'temp', type, name, tbl_name, sql FROM temp.sqlite_master \
         WHERE NOT (type IN ('table','index') AND tbl_name COLLATE NOCASE IN (?, ?)) \
         ORDER BY 1, 2, 3",
    )
    .bind(TEMP_ALLOWLIST[0])
    .bind(TEMP_ALLOWLIST[1])
    .fetch_all(&mut *conn)
    .await?;
    let mut hasher = Sha256::new();
    for row in rows {
        for column in 0..4 {
            let text: String = row.try_get(column)?;
            put_frame(&mut hasher, text.as_bytes());
        }
        match row.try_get::<Option<String>, _>(4)? {
            Some(sql) => {
                hasher.update([1]);
                put_frame(&mut hasher, sql.as_bytes());
            }
            None => hasher.update([0]),
        }
    }
    let main_version: i64 = sqlx::query_scalar("PRAGMA main.schema_version")
        .fetch_one(&mut *conn)
        .await?;
    let temp_version: i64 = sqlx::query_scalar("PRAGMA temp.schema_version")
        .fetch_one(&mut *conn)
        .await?;
    Ok(SchemaSnapshot {
        digest: hasher.finalize().into(),
        main_version,
        temp_version,
    })
}

/// What the schema looked like at one moment. A digest alone misses a table
/// dropped and recreated with identical DDL; `schema_version` moves on every
/// schema change, however identical the result.
#[derive(Clone, Debug)]
struct SchemaSnapshot {
    digest: [u8; 32],
    main_version: i64,
    temp_version: i64,
}

impl SchemaSnapshot {
    /// Did the schema change since `self`? Any movement of either schema
    /// version counts: the projectors' scratch tables are created before
    /// arming, so nothing legitimate changes the schema while armed.
    fn changed_by(&self, now: &Self) -> bool {
        self.digest != now.digest
            || self.main_version != now.main_version
            || self.temp_version != now.temp_version
    }
}

/// The stored form `sqlite_master` keeps of the pinned FTS definition (SQLite
/// drops `IF NOT EXISTS`).
fn normalised_fts_ddl() -> String {
    super::search_v2::SEARCH_FTS_DDL.replacen(" IF NOT EXISTS", "", 1)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Affinity {
    Integer,
    Text,
    Blob,
    Real,
    Numeric,
}

/// SQLite's column affinity rules, by declared type.
fn affinity(declared: &str) -> Affinity {
    let upper = declared.to_ascii_uppercase();
    if upper.contains("INT") {
        Affinity::Integer
    } else if upper.contains("CHAR") || upper.contains("CLOB") || upper.contains("TEXT") {
        Affinity::Text
    } else if upper.contains("BLOB") || upper.is_empty() {
        Affinity::Blob
    } else if upper.contains("REAL") || upper.contains("FLOA") || upper.contains("DOUB") {
        Affinity::Real
    } else {
        Affinity::Numeric
    }
}

/// The value `SELECT` yields for an absent column, but only where it is
/// provably the literal itself, whatever the SQLite version:
///
/// * an integer literal (optional sign, decimal digits, fitting an i64) in an
///   INTEGER or NUMERIC affinity column;
/// * a single-quoted string literal in a TEXT affinity column;
/// * never in a STRICT table.
///
/// Everything else (`1e2` into TEXT reads back "1e2" but a probe says
/// "100.0"; REAL, BLOB and ANY columns; expressions) is `None`.
fn evaluate_default(strict: bool, declared: &str, default: &str) -> Option<Val> {
    if strict {
        return None;
    }
    match affinity(declared) {
        Affinity::Integer | Affinity::Numeric => {
            let digits = default.strip_prefix(['+', '-']).unwrap_or(default);
            if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            default.parse::<i64>().ok().map(Val::Int)
        }
        Affinity::Text => {
            let inner = default.strip_prefix('\'')?.strip_suffix('\'')?;
            let mut out = String::with_capacity(inner.len());
            let mut chars = inner.chars();
            while let Some(c) = chars.next() {
                if c == '\'' {
                    // Only an escaped pair is legal inside the quotes.
                    if chars.next() != Some('\'') {
                        return None;
                    }
                }
                out.push(c);
            }
            Some(Val::Text(out))
        }
        _ => None,
    }
}

async fn build_catalog(conn: &mut SqliteConnection) -> Result<(Catalog, Option<Anomaly>)> {
    let private = super::working_undo_schema::exclusions(conn).await?;
    let v2: i64 = sqlx::query_scalar("PRAGMA application_id")
        .fetch_one(&mut *conn)
        .await?;
    let is_v2 = v2 == crate::db::V2_APPLICATION_ID;
    let rows = sqlx::query(
        "SELECT name, sql FROM main.sqlite_master WHERE type='table' AND name NOT GLOB 'sqlite_*' ORDER BY name",
    )
    .fetch_all(&mut *conn)
    .await?;
    let without_rowid: std::collections::HashSet<String> =
        sqlx::query_scalar("SELECT name FROM pragma_table_list WHERE schema='main' AND wr=1")
            .fetch_all(&mut *conn)
            .await?
            .into_iter()
            .collect();
    let strict: std::collections::HashSet<String> =
        sqlx::query_scalar("SELECT name FROM pragma_table_list WHERE schema='main' AND strict=1")
            .fetch_all(&mut *conn)
            .await?
            .into_iter()
            .collect();
    let temp_names: std::collections::HashSet<String> = sqlx::query_scalar(
        "SELECT lower(name) FROM temp.sqlite_master WHERE type IN ('table','view')",
    )
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .collect();
    let mut catalog = Catalog::default();
    let mut anomaly = None;
    for row in rows {
        let name: String = row.try_get(0)?;
        let sql: Option<String> = row.try_get(1)?;
        if name.eq_ignore_ascii_case(FTS_LOGICAL)
            && sql.as_deref() != Some(normalised_fts_ddl().as_str())
        {
            anomaly = Some(Anomaly::FtsDdlMismatch);
        }
        let kind = if name.eq_ignore_ascii_case(FTS_CONTENT) {
            Kind::FtsContent
        } else if private.contains(&name) || !included_in_projection(is_v2, &name) {
            Kind::Ignored
        } else if without_rowid.contains(&name) {
            Kind::WithoutRowid
        } else {
            Kind::Regular
        };
        // Virtual tables never fire the hook, and their columns are read from
        // `table_xinfo` all the same.
        let columns: Vec<(String, String, i64, Option<String>, i64)> = sqlx::query_as(&format!(
            "SELECT name, type, hidden, dflt_value, \"notnull\" FROM pragma_table_xinfo('{}', 'main')",
            name.replace('\'', "''")
        ))
        .fetch_all(&mut *conn)
        .await?;
        let visible = columns.iter().filter(|c| c.2 == 0).count();
        let (logical, logical_columns, skip) = match kind {
            Kind::FtsContent => (FTS_LOGICAL.to_owned(), visible.saturating_sub(1), 1),
            _ => (name.clone(), visible, 0),
        };
        let real_affinity = columns
            .iter()
            .skip(skip)
            .map(|c| declared_real(&c.1))
            .collect();
        let mut defaults = Vec::new();
        for column in columns.iter().filter(|c| c.2 == 0) {
            defaults.push(ColDefault {
                not_null: column.4 != 0,
                default: match column.3.as_deref() {
                    None => Dflt::None,
                    Some(d) if d.trim().eq_ignore_ascii_case("null") => Dflt::None,
                    Some(d) => {
                        match evaluate_default(strict.contains(&name), &column.1, d.trim()) {
                            Some(value) => Dflt::Value(value),
                            None => Dflt::Unevaluable,
                        }
                    }
                },
            });
        }
        // `rowid` may be shadowed by a declared column of that name; the first
        // of the three aliases that is not a column reaches the real rowid.
        let rowid_alias = ["rowid", "_rowid_", "oid"]
            .into_iter()
            .find(|alias| !columns.iter().any(|c| c.0.eq_ignore_ascii_case(alias)));
        // A TEMP table or view of the same name would capture unqualified
        // references (and ours, were they unqualified).
        if kind != Kind::Ignored
            && temp_names.contains(&name.to_ascii_lowercase())
            && !is_allowlisted_temp(&name)
        {
            anomaly.get_or_insert(Anomaly::TempShadowsMain(name.clone()));
        }
        catalog.by_name.insert(name, catalog.tables.len());
        catalog.tables.push(TableInfo {
            rowid_alias,
            kind,
            logical,
            hook_columns: visible,
            logical_columns,
            real_affinity,
            defaults,
        });
    }
    Ok((catalog, anomaly))
}

fn note(state: &mut State, anomaly: Anomaly) {
    if state.anomaly.is_none() {
        state.anomaly = Some(anomaly);
    }
}

/// The hook body: classify the write, then log the first touch of each key.
fn on_write(
    event: sqlx::sqlite::PreupdateHookResult<'_>,
    catalog: &Catalog,
    state: &mut State,
    db: usize,
) {
    use sqlx::sqlite::SqliteOperation;
    if state.anomaly.is_some() {
        return;
    }
    // An incremental-blob write changes bytes without a row-level image.
    // SAFETY: `db` is this connection's handle, valid while the hook is
    // registered (the guard unregisters before the connection goes away), and
    // the call is only made from inside the hook, as SQLite requires.
    if unsafe { libsqlite3_sys::sqlite3_preupdate_blobwrite(db as *mut libsqlite3_sys::sqlite3) }
        >= 0
    {
        return note(state, Anomaly::BlobWrite);
    }
    match event.database {
        "main" => {}
        "temp" => {
            if !is_allowlisted_temp(event.table) {
                note(
                    state,
                    Anomaly::NonAllowlistedTempWrite(event.table.to_owned()),
                );
            }
            return;
        }
        other => return note(state, Anomaly::OtherSchema(other.to_owned())),
    }
    let Some(&index) = catalog.by_name.get(event.table) else {
        return note(state, Anomaly::UnknownTable(event.table.to_owned()));
    };
    let info = &catalog.tables[index];
    match info.kind {
        Kind::Ignored => return,
        Kind::WithoutRowid => return note(state, Anomaly::WithoutRowid(event.table.to_owned())),
        Kind::Regular | Kind::FtsContent => {}
    }
    if info.kind == Kind::Regular && info.rowid_alias.is_none() {
        return note(state, Anomaly::RowidShadowed(event.table.to_owned()));
    }
    if event.get_column_count() as usize != info.hook_columns {
        return note(state, Anomaly::ColumnCountMismatch(event.table.to_owned()));
    }
    let (old, new) = match event.operation {
        SqliteOperation::Insert => (None, event.get_new_row_id().ok()),
        SqliteOperation::Delete => (event.get_old_row_id().ok(), None),
        SqliteOperation::Update => (event.get_old_row_id().ok(), event.get_new_row_id().ok()),
        _ => return note(state, Anomaly::PreupdateError),
    };
    if let Some(rowid) = old {
        if !state.touched.contains_key(&(index, rowid)) {
            match base_key(&event, info) {
                Ok((key, bytes)) => {
                    state.base_rows += 1;
                    if !log(state, index, rowid, Some(key), bytes) {
                        return;
                    }
                }
                Err(anomaly) => return note(state, anomaly),
            }
        }
    }
    // An insert, or the destination of a rowid-changing update: absent before,
    // unless an earlier event (for example a REPLACE conflict deletion) has
    // already recorded what was there.
    if let Some(rowid) = new {
        if old != Some(rowid) && !state.touched.contains_key(&(index, rowid)) {
            log(state, index, rowid, None, 0);
        }
    }
}

/// Record a first touch; false (and an anomaly) past a limit.
fn log(state: &mut State, index: usize, rowid: i64, key: Option<[u8; 32]>, bytes: usize) -> bool {
    if state.touched.len() >= MAX_TOUCHES {
        note(state, Anomaly::TooManyTouches);
        return false;
    }
    state.base_bytes += bytes;
    if state.base_bytes > MAX_BASE_IMAGE_BYTES {
        note(state, Anomaly::BaseImagesTooLarge);
        return false;
    }
    state.touched.insert((index, rowid), key);
    true
}

/// Rowids and base keys of one table's touched rows.
type TableTouches = (Vec<i64>, Vec<Option<[u8; 32]>>);

/// The element key of the row about to be changed or deleted, exactly as the
/// full scan would hash it: stored values normalised by declared affinity.
#[allow(clippy::needless_range_loop)]
fn base_key(
    event: &sqlx::sqlite::PreupdateHookResult<'_>,
    info: &TableInfo,
) -> std::result::Result<([u8; 32], usize), Anomaly> {
    use sqlx::{TypeInfo as _, Value as _};
    let mut sink = CountingSink {
        hasher: Sha256::new(),
        bytes: 0,
    };
    sink.hasher.update(SET_ELEMENT_PREFIX);
    put_frame(&mut sink.hasher, info.logical.as_bytes());
    // Only the row's own bytes count toward the limit.
    sink.bytes = 0;
    begin_row(&mut sink);
    // The content shadow table's first column is the rowid `id`; the logical
    // FTS row is its `c0..` columns.
    let skip = usize::from(info.kind == Kind::FtsContent);
    // Pass 1: the stored old values, as the scan would read them.
    let mut old = Vec::with_capacity(info.hook_columns);
    for index in 0..info.hook_columns {
        if index < skip {
            old.push(Val::Null);
            continue;
        }
        let value = event
            .get_old_column_value(index as i32)
            .map_err(|_| Anomaly::PreupdateError)?;
        let owned = sqlx::ValueRef::to_owned(&value);
        let real = info
            .real_affinity
            .get(index - skip)
            .copied()
            .unwrap_or(false);
        old.push(if owned.is_null() {
            Val::Null
        } else {
            match owned.type_info().name() {
                // A REAL column stores an integral value as an integer and the
                // scan reads it back as REAL (so -0.0 comes back +0.0).
                "INTEGER" => {
                    let value: i64 = owned.try_decode().map_err(|_| Anomaly::PreupdateError)?;
                    if real {
                        Val::Real(value as f64)
                    } else {
                        Val::Int(value)
                    }
                }
                "REAL" => Val::Real(owned.try_decode().map_err(|_| Anomaly::PreupdateError)?),
                "TEXT" => Val::Text(owned.try_decode().map_err(|_| Anomaly::PreupdateError)?),
                "BLOB" => Val::Blob(owned.try_decode().map_err(|_| Anomaly::PreupdateError)?),
                _ => return Err(Anomaly::UnsupportedStorageClass),
            }
        });
    }
    // A record written before an ALTER TABLE ADD COLUMN is shorter than the
    // table, and the hook reports NULL for the missing trailing columns where
    // the scan yields their default.
    let default_of = |i: usize| info.defaults.get(i - skip).map(|d| &d.default);
    let has_default = |i: usize| matches!(default_of(i), Some(Dflt::Value(_) | Dflt::Unevaluable));
    // A NOT NULL column that reads NULL can only be absent from a short
    // record, which proves every column from there on is absent too: their
    // values are their defaults, exactly.
    let proven = (skip..info.hook_columns).find(|&i| {
        matches!(old[i], Val::Null)
            && info.defaults.get(i - skip).is_some_and(|d| d.not_null)
            && has_default(i)
    });
    // Before the proof (or without one), only a trailing run of NULLs can be a
    // gap, and a defaulted column inside it is an unprovable NULL.
    let end = proven.unwrap_or(info.hook_columns);
    let run_start = old[..end]
        .iter()
        .rposition(|v| !matches!(v, Val::Null))
        .map_or(skip, |last| (last + 1).max(skip));
    if (run_start..end).any(has_default) {
        return Err(Anomaly::ShortRecordDefault(info.logical.clone()));
    }
    if let Some(start) = proven {
        for i in start..info.hook_columns {
            match default_of(i) {
                Some(Dflt::Value(value)) => old[i] = value.clone(),
                Some(Dflt::Unevaluable) => {
                    return Err(Anomaly::ShortRecordDefault(info.logical.clone()))
                }
                _ => old[i] = Val::Null,
            }
        }
    }
    // Pass 2: hash.
    for value in &old[skip..] {
        hash_cell(&mut sink, &value.cell());
    }
    let bytes = sink.bytes;
    Ok((sink.hasher.finalize().into(), bytes))
}

/// A connection with the capture hook armed. Statements run through it
/// (`&mut *hooked` is the wrapped connection or transaction); [`finish`]
/// disarms, unregisters and reads back. Dropping it, including when the
/// future holding it is cancelled, disarms and unregisters the hook too.
///
/// [`finish`]: Hooked::finish
pub(crate) struct Hooked<'c, C: HookTarget> {
    target: &'c mut C,
    state: Arc<Mutex<State>>,
    armed: Arc<AtomicBool>,
    catalog: Arc<Catalog>,
    catalog_anomaly: Option<Anomaly>,
    /// Digest of the schema (main, and temp outside the allowlist) at arm.
    schema: SchemaSnapshot,
    registered: bool,
}

/// What a hook can be armed on: a connection, or a transaction on one.
pub(crate) trait HookTarget {
    fn connection(&mut self) -> &mut SqliteConnection;
}
impl HookTarget for SqliteConnection {
    fn connection(&mut self) -> &mut SqliteConnection {
        self
    }
}
impl HookTarget for sqlx::Transaction<'_, sqlx::Sqlite> {
    fn connection(&mut self) -> &mut SqliteConnection {
        self
    }
}

impl<C: HookTarget> std::ops::Deref for Hooked<'_, C> {
    type Target = C;
    fn deref(&self) -> &C {
        self.target
    }
}
impl<C: HookTarget> std::ops::DerefMut for Hooked<'_, C> {
    fn deref_mut(&mut self) -> &mut C {
        self.target
    }
}

impl<'c, C: HookTarget> Hooked<'c, C> {
    /// Arm the capture on a connection that is inside a transaction.
    pub(crate) async fn arm(target: &'c mut C) -> Result<Self> {
        // The facet-time projector's scratch tables, with its exact DDL, so
        // that it never has to create them (a TEMP schema change) while armed.
        target
            .connection()
            .execute(super::facet_time_reads::TEMP_SCRATCH_DDL)
            .await?;
        let (catalog, catalog_anomaly) = build_catalog(target.connection()).await?;
        let schema = schema_snapshot(target.connection()).await?;
        let catalog = Arc::new(catalog);
        let state = Arc::new(Mutex::new(State::default()));
        let armed = Arc::new(AtomicBool::new(true));
        {
            let mut handle = target.connection().lock_handle().await?;
            let raw = handle.as_raw_handle().as_ptr();
            // SAFETY: a plain read of the connection's autocommit flag.
            if unsafe { libsqlite3_sys::sqlite3_get_autocommit(raw) } != 0 {
                return Err(Error::engine(
                    "projection capture must be armed after BEGIN",
                ));
            }
            let db = raw as usize;
            let (hook_state, hook_armed, hook_catalog) =
                (state.clone(), armed.clone(), catalog.clone());
            handle.set_preupdate_hook(move |event| {
                if !hook_armed.load(Ordering::Acquire) {
                    return;
                }
                if let Ok(mut state) = hook_state.lock() {
                    on_write(event, &hook_catalog, &mut state, db);
                }
            });
        }
        Ok(Self {
            target,
            state,
            armed,
            catalog,
            catalog_anomaly,
            schema,
            registered: true,
        })
    }

    async fn unregister(&mut self) -> Result<()> {
        self.armed.store(false, Ordering::Release);
        if self.registered {
            self.target
                .connection()
                .lock_handle()
                .await?
                .remove_preupdate_hook();
            self.registered = false;
        }
        Ok(())
    }

    /// Old images hashed so far (denominator of the short-record rule).
    pub(crate) fn base_rows_len(&self) -> usize {
        self.state.lock().map(|s| s.base_rows).unwrap_or(0)
    }

    /// Distinct rows touched so far (for measurement and diagnostics).
    pub(crate) fn touched_len(&self) -> usize {
        self.state.lock().map(|s| s.touched.len()).unwrap_or(0)
    }

    /// Disarm and unregister the hook FIRST (the read-back below writes a TEMP
    /// table), then read the touched keys' final images and compute each
    /// touched table's delta.
    pub(crate) async fn finish(mut self) -> Result<CaptureOutcome> {
        self.unregister().await?;
        // A private log may have become populated since arm. Never publish
        // a cached delta that silently omits those retained images.
        super::working_undo_schema::exclusions(self.target.connection()).await?;
        let (anomaly, touched) = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| Error::engine("capture state"))?;
            (state.anomaly.take(), std::mem::take(&mut state.touched))
        };
        if let Some(anomaly) = self.catalog_anomaly.take().or(anomaly) {
            return Ok(CaptureOutcome::Anomaly(anomaly));
        }
        // DDL is invisible to the hook but changes the digest.
        if self
            .schema
            .changed_by(&schema_snapshot(self.target.connection()).await?)
        {
            return Ok(CaptureOutcome::Anomaly(Anomaly::SchemaChanged));
        }
        // Group by logical table.
        let mut by_table: BTreeMap<&str, TableTouches> = BTreeMap::new();
        for ((index, rowid), base) in &touched {
            let entry = by_table
                .entry(self.catalog.tables[*index].logical.as_str())
                .or_default();
            entry.0.push(*rowid);
            entry.1.push(*base);
        }
        let conn = self.target.connection();
        let mut deltas = Vec::new();
        for (logical, (mut rowids, bases)) in by_table {
            rowids.sort_unstable();
            let columns: i64 = sqlx::query_scalar(&format!(
                "SELECT COUNT(*) FROM pragma_table_info('{}', 'main')",
                logical.replace('\'', "''")
            ))
            .fetch_one(&mut *conn)
            .await?;
            let Some(alias) = self
                .catalog
                .by_name
                .get(logical)
                .and_then(|&i| self.catalog.tables[i].rowid_alias)
            else {
                return Ok(CaptureOutcome::Anomaly(Anomaly::RowidShadowed(
                    logical.to_owned(),
                )));
            };
            let mut prefix = Sha256::new();
            prefix.update(SET_ELEMENT_PREFIX);
            put_frame(&mut prefix, logical.as_bytes());
            // Final images by rowid. A key whose final element equals its base
            // element cancels exactly (a REPLACE of a row by itself, a change
            // rolled back to a savepoint), so it costs no multiplication.
            let mut base_of: HashMap<i64, Option<[u8; 32]>> =
                rowids.iter().copied().zip(bases.iter().copied()).collect();
            let mut delta = MuHash::new();
            let mut row_delta = 0_i64;
            {
                use futures::TryStreamExt;
                let query = format!(
                    "SELECT t.*, t.{alias} AS _capture_rowid FROM json_each(?) AS k JOIN main.\"{}\" AS t ON t.{alias} = k.value",
                    logical.replace('"', "\"\"")
                );
                // The keys travel as a bound JSON array: read-back owns no
                // scratch table, so no trigger can be attached to it, and it
                // only ever SELECTs, so it cannot fire one on main or temp.
                let keys = serde_json::to_string(&rowids)?;
                let mut stream = sqlx::query(&query).bind(keys).fetch(&mut *conn);
                while let Some(row) = stream.try_next().await? {
                    let rowid: i64 = row.try_get(columns as usize)?;
                    let mut element = prefix.clone();
                    hash_row(&mut element, &row, columns as usize)?;
                    let key: [u8; 32] = element.finalize().into();
                    match base_of.remove(&rowid) {
                        Some(Some(base)) if base == key => {}
                        Some(Some(base)) => {
                            delta.insert_key(&key);
                            delta.remove_key(&base);
                        }
                        _ => {
                            delta.insert_key(&key);
                            row_delta += 1;
                        }
                    }
                }
            }
            // Touched rows that are gone: only their base remains to remove.
            for base in base_of.into_values().flatten() {
                delta.remove_key(&base);
                row_delta -= 1;
            }
            deltas.push(TableDelta {
                name: logical.to_owned(),
                row_delta,
                delta,
            });
        }
        Ok(CaptureOutcome::Delta(deltas))
    }
}

impl<C: HookTarget> Drop for Hooked<'_, C> {
    fn drop(&mut self) {
        // The hook goes inert at once, whatever happens next.
        self.armed.store(false, Ordering::Release);
        if self.registered {
            // Dropped without `finish` (an error, or the future was cancelled):
            // unregister for real. The connection's worker thread answers the
            // handle request even if it is finishing a statement, so waiting
            // here cannot deadlock; a connection that has already failed
            // simply has no hook left to remove.
            let connection = self.target.connection();
            futures::executor::block_on(async {
                if let Ok(mut handle) = connection.lock_handle().await {
                    handle.remove_preupdate_hook();
                }
            });
            self.registered = false;
        }
    }
}

#[cfg(test)]
mod tests;
