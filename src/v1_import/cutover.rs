//! Read-only, content-redacted cutover receipts. Not an authorization token.
use super::*;
use sha2::{Digest, Sha256};

/// Read-only conversion admission, not an authorization token. The caller must
/// hold its stable source snapshot (import) or frozen writer/control locks
/// through publication (hosted flip). Kernel-v2 cannot enforce these fences.
#[doc(hidden)]
pub async fn require_unfenced_source_on(conn: &mut SqliteConnection) -> crate::Result<()> {
    let present: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='provenance_local_command_cancellations')",
    ).fetch_one(&mut *conn).await?;
    if present {
        let fenced: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM provenance_local_command_cancellations)",
        )
        .fetch_one(&mut *conn)
        .await?;
        if fenced {
            return Err(crate::Error::engine(
                "v2 conversion cannot discard local command cancellation authority; keep the source database",
            ));
        }
    }
    Ok(())
}

/// Provenance emitted by every library/CLI report, including failed captures.
#[derive(Serialize)]
pub struct ImportBuild {
    pub importer_build_sha: &'static str,
}
impl Default for ImportBuild {
    fn default() -> Self {
        Self {
            importer_build_sha: crate::FULL_GIT_SHA,
        }
    }
}

/// An override acknowledges a build mismatch only; all data/admission guards
/// remain mandatory. Unstamped development binaries cannot prove same-build.
pub fn admit_build_sha(
    importer: Option<&str>,
    operator: &str,
    allow_mismatch: bool,
) -> crate::Result<bool> {
    let valid = |s: &str| {
        s.len() == 40
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    let matches = valid(operator) && importer.is_some_and(|s| valid(s) && s == operator);
    if matches {
        return Ok(false);
    }
    if allow_mismatch {
        return Ok(true);
    }
    Err(crate::Error::engine("v2 cutover refused: build SHA differs or is unavailable; use matching stamped importer/operator/hosting builds, or explicitly --allow-build-mismatch"))
}

/// Hash the complete logical SQLite snapshot, including WAL-visible rows.
/// Length-prefix schema/table/row bytes; sort encoded rows, preserving duplicate
/// rows and SQLite value types. Never emit source values in diagnostics.
pub async fn snapshot_digest(path: &std::path::Path) -> Result<String> {
    Ok(snapshot_evidence(path, false).await?.digest)
}

/// Logical snapshot evidence for local cutover pre-inspection. This is not a
/// credential. Record partitions are useful ONLY for proven standalone readers;
/// data-bound/module readers must use the complete digest.
pub struct SnapshotEvidence {
    pub digest: String,
    pub environment: String,
    pub records: std::collections::BTreeMap<String, String>,
}

fn feed_hash(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
}

/// Tables whose rows key a record partition, and the column naming the record.
fn partition_key(table: &str) -> Option<&'static str> {
    match table {
        "records" => Some("id"),
        "content_events" | "facet_values" => Some("record_id"),
        _ => None,
    }
}

/// Shared schema/identity tables that feed the standalone environment hash.
fn environment_table(table: &str) -> bool {
    matches!(
        table,
        "database_identity"
            | "schema_config"
            | "vocabularies"
            | "vocabulary_values"
            | "meta_events"
    )
}

fn quote_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// Sorter memory for the fallback scan. SQLite sizes each sorted run from the
/// page-cache budget; the 2 MiB default turns a multi-GB table into thousands
/// of runs and several merge passes through temp files. Pragmas change only
/// how SQLite sorts, never what the query returns.
const SCAN_CACHE_KIB: i64 = 256 * 1024;
const SCAN_SORT_THREADS: i64 = 4;
/// Memory bounds for the keyed scan. Exceeding either reverts that table to
/// the SQLite sorter, so they bound memory without changing any digest.
#[derive(Clone, Copy)]
struct KeyedScanLimits {
    key_bytes: usize,
    tie_bytes: usize,
}
const KEYED_SCAN_LIMITS: KeyedScanLimits = KeyedScanLimits {
    key_bytes: 512 << 20,
    tie_bytes: 256 << 20,
};

/// Produce the ordinary snapshot digest and optional conservative partitions in
/// one scan. The full digest still covers every table. Standalone partitions
/// cover each record's source/history/facets and the shared schema/identity
/// read by the legacy renderer. Callers MUST recheck current View authority;
/// these partitions alone do not establish permission or a data-bound input.
/// Keep this read contract aligned with imported_content::preinspection::key.
///
/// # Digest format and why this scan reproduces it
/// The format is fixed by `reference_snapshot_evidence`: per table, each row
/// is encoded as the SQLite text `json_array(typeof(c1),hex(CAST(c1 AS
/// BLOB)),...)`, and rows are hashed in `ORDER BY encoded COLLATE BINARY`
/// order. This scan produces the same bytes in the same order without asking
/// SQLite to build and sort that text. SQLite still performs every `typeof`
/// and `CAST` conversion; Rust only hex-encodes and frames the results.
///
/// The encoded order is the lexicographic order of the per-column pairs
/// `(typeof(c), CAST(c AS BLOB))`, comparing type names as text and values as
/// bytes, shorter prefix first. The five `typeof` names differ in their first
/// byte. Within one type, the uppercase hex text compares exactly as the bytes
/// do, because each byte maps to two order-preserving digits and the closing
/// `"` (0x22) sorts below every hex digit. Rows whose full encodings tie are
/// byte-identical, so their relative order cannot change any hash.
///
/// Each table is scanned in one of two ways, inside one read transaction:
/// - **Keyed** (ordinary rowid tables): read only the first column's pair and
///   the rowid, sort those in memory, then fetch rows by rowid in that order.
///   Rows whose first-column pairs tie are fetched together and sorted by
///   their full encoding. Large rows are never copied through a sorter.
/// - **Sorted** (virtual and WITHOUT ROWID tables, or when the keyed scan
///   would exceed its memory bounds): SQLite sorts on all the pairs.
pub async fn snapshot_evidence(
    path: &std::path::Path,
    partition: bool,
) -> Result<SnapshotEvidence> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || scan_snapshot(&path, partition, KEYED_SCAN_LIMITS))
        .await
        .map_err(|error| format!("snapshot digest scan did not complete: {error}"))?
}

#[derive(Clone)]
struct Hashes {
    digest: Sha256,
    environment: Sha256,
    records: std::collections::BTreeMap<String, Sha256>,
}

/// How one table's rows reach the hashes.
struct TableScan<'a> {
    table: &'a str,
    quoted: String,
    columns: Vec<String>,
    /// Every declared column, including generated ones that `table_info`
    /// omits from `columns`; any of them can shadow a rowid alias.
    declared: Vec<String>,
    /// `typeof`/`CAST` pairs for every column, then the partition key if any.
    fields: String,
    key: Option<&'static str>,
    environment_rows: bool,
}

impl TableScan<'_> {
    fn emit(&self, hashes: &mut Hashes, encoded: &[u8], key: Option<&str>) {
        feed_hash(&mut hashes.digest, encoded);
        if let Some(id) = key {
            let hash = hashes.records.entry(id.to_owned()).or_default();
            feed_hash(hash, self.table.as_bytes());
            feed_hash(hash, encoded);
        } else if self.environment_rows {
            feed_hash(&mut hashes.environment, encoded);
        }
    }

    /// Encode one `fields` row; returns its partition key, decoded exactly as
    /// the original `Option<String>` column was.
    fn encode<'r>(&self, row: &'r rusqlite::Row, out: &mut Vec<u8>) -> Result<Option<&'r str>> {
        use rusqlite::types::ValueRef;
        out.clear();
        out.push(b'[');
        for column in 0..self.columns.len() {
            if column > 0 {
                out.push(b',');
            }
            let ValueRef::Text(kind) = row.get_ref(column * 2)? else {
                return Err("snapshot digest scan: typeof() did not return text".into());
            };
            out.push(b'"');
            out.extend_from_slice(kind);
            out.extend_from_slice(b"\",\"");
            match row.get_ref(column * 2 + 1)? {
                ValueRef::Blob(bytes) => push_upper_hex(out, bytes),
                ValueRef::Null => {}
                _ => return Err("snapshot digest scan: CAST AS BLOB did not return a blob".into()),
            }
            out.push(b'"');
        }
        out.push(b']');
        if self.key.is_none() {
            return Ok(None);
        }
        match row.get_ref(self.columns.len() * 2)? {
            ValueRef::Null => Ok(None),
            ValueRef::Text(id) => Ok(Some(
                std::str::from_utf8(id).map_err(|_| "snapshot partition key is not UTF-8")?,
            )),
            _ => Err("snapshot partition key is not text".into()),
        }
    }

    /// SQLite sorts on every pair. Always correct; used as the fallback.
    fn sorted(&self, db: &rusqlite::Connection, hashes: &mut Hashes) -> Result<()> {
        let order: Vec<String> = (1..=self.columns.len() * 2)
            .map(|i| i.to_string())
            .collect();
        let query = format!(
            "SELECT {} FROM {} ORDER BY {}",
            self.fields,
            self.quoted,
            order.join(",")
        );
        let mut statement = db.prepare(&query)?;
        let mut rows = statement.query([])?;
        let mut encoded = Vec::new();
        while let Some(row) = rows.next()? {
            let key = self.encode(row, &mut encoded)?;
            self.emit(hashes, &encoded, key);
        }
        Ok(())
    }

    /// A name that addresses this table's rowid, or None for virtual and
    /// WITHOUT ROWID tables and tables whose columns shadow every rowid alias.
    fn rowid(&self, db: &rusqlite::Connection, ddl: &str) -> Option<&'static str> {
        // Virtual tables need not have unique, addressable rowids.
        let mut words = ddl.split_ascii_whitespace();
        if words
            .next()
            .is_some_and(|w| w.eq_ignore_ascii_case("CREATE"))
            && words
                .next()
                .is_some_and(|w| w.eq_ignore_ascii_case("VIRTUAL"))
        {
            return None;
        }
        let alias = ["_rowid_", "rowid", "oid"]
            .into_iter()
            .find(|alias| !self.declared.iter().any(|c| c.eq_ignore_ascii_case(alias)))?;
        db.prepare(&format!("SELECT {alias} FROM {} LIMIT 0", self.quoted))
            .ok()
            .map(|_| alias)
    }

    /// Returns Ok(false), with nothing emitted, when a memory bound is hit.
    fn keyed(
        &self,
        db: &rusqlite::Connection,
        hashes: &mut Hashes,
        rowid: &str,
        limits: KeyedScanLimits,
    ) -> Result<bool> {
        use rusqlite::types::ValueRef;
        let first = quote_ident(&self.columns[0]);
        let mut keys: Vec<(u8, Box<[u8]>, i64)> = Vec::new();
        let mut key_bytes = 0usize;
        {
            let mut statement = db.prepare(&format!(
                "SELECT {rowid},typeof({first}),CAST({first} AS BLOB) FROM {}",
                self.quoted
            ))?;
            let mut rows = statement.query([])?;
            while let Some(row) = rows.next()? {
                let rowid: i64 = row.get(0)?;
                let ValueRef::Text(kind) = row.get_ref(1)? else {
                    return Err("snapshot digest scan: typeof() did not return text".into());
                };
                // Alphabetical, matching the type names' order as text.
                let rank = match kind {
                    b"blob" => 0,
                    b"integer" => 1,
                    b"null" => 2,
                    b"real" => 3,
                    b"text" => 4,
                    _ => return Err("snapshot digest scan: unknown typeof() result".into()),
                };
                let value: Box<[u8]> = match row.get_ref(2)? {
                    ValueRef::Blob(bytes) => bytes.into(),
                    ValueRef::Null => Box::new([]),
                    _ => {
                        return Err(
                            "snapshot digest scan: CAST AS BLOB did not return a blob".into()
                        )
                    }
                };
                key_bytes += value.len() + 48;
                if key_bytes > limits.key_bytes {
                    return Ok(false);
                }
                keys.push((rank, value, rowid));
            }
        }
        // Backstop for the alias choice: each fetch must address one row.
        let mut rowids: Vec<i64> = keys.iter().map(|entry| entry.2).collect();
        rowids.sort_unstable();
        if rowids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Ok(false);
        }
        drop(rowids);
        keys.sort_unstable_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));
        let mut fetch = db.prepare(&format!(
            "SELECT {} FROM {} WHERE {rowid}=?1",
            self.fields, self.quoted
        ))?;
        let mut fetch_row = |rowid: i64, out: &mut Vec<u8>| -> Result<Option<String>> {
            let mut rows = fetch.query([rowid])?;
            let row = rows
                .next()?
                .ok_or("snapshot digest scan: row vanished inside its read transaction")?;
            let key = self.encode(row, out)?.map(str::to_owned);
            if rows.next()?.is_some() {
                return Err("snapshot digest scan: rowid addressed more than one row".into());
            }
            Ok(key)
        };
        let saved = hashes.clone_for(self.key.is_some());
        let mut encoded = Vec::new();
        let mut start = 0;
        while start < keys.len() {
            let mut end = start + 1;
            while end < keys.len() && keys[end].0 == keys[start].0 && keys[end].1 == keys[start].1 {
                end += 1;
            }
            if end - start == 1 {
                let key = fetch_row(keys[start].2, &mut encoded)?;
                self.emit(hashes, &encoded, key.as_deref());
            } else {
                let mut tied = Vec::with_capacity(end - start);
                let mut tied_bytes = 0usize;
                for entry in &keys[start..end] {
                    let mut out = Vec::new();
                    let key = fetch_row(entry.2, &mut out)?;
                    tied_bytes += out.len() + 64;
                    if tied_bytes > limits.tie_bytes {
                        saved.restore(hashes);
                        return Ok(false);
                    }
                    tied.push((out, key));
                }
                tied.sort_unstable_by(|a, b| a.0.cmp(&b.0));
                for (out, key) in &tied {
                    self.emit(hashes, out, key.as_deref());
                }
            }
            start = end;
        }
        Ok(true)
    }
}

/// Hash state saved before a keyed scan, so a bounded fallback can rerun the
/// table. Record partitions are copied only for tables that write them.
struct SavedHashes {
    digest: Sha256,
    environment: Sha256,
    records: Option<std::collections::BTreeMap<String, Sha256>>,
}

impl Hashes {
    fn clone_for(&self, partitioned: bool) -> SavedHashes {
        SavedHashes {
            digest: self.digest.clone(),
            environment: self.environment.clone(),
            records: partitioned.then(|| self.records.clone()),
        }
    }
}

impl SavedHashes {
    fn restore(self, hashes: &mut Hashes) {
        hashes.digest = self.digest;
        hashes.environment = self.environment;
        if let Some(records) = self.records {
            hashes.records = records;
        }
    }
}

fn scan_snapshot(
    path: &std::path::Path,
    partition: bool,
    limits: KeyedScanLimits,
) -> Result<SnapshotEvidence> {
    let db = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    // `PRAGMA threads` reports its value as a row; step and discard it.
    for pragma in [
        format!("PRAGMA cache_size=-{SCAN_CACHE_KIB}"),
        format!("PRAGMA threads={SCAN_SORT_THREADS}"),
    ] {
        let mut statement = db.prepare(&pragma)?;
        let mut rows = statement.query([])?;
        while rows.next()?.is_some() {}
    }
    // One read transaction: every table comes from the same snapshot.
    db.execute_batch("BEGIN")?;
    let mut hashes = Hashes {
        digest: Sha256::new(),
        environment: Sha256::new(),
        records: Default::default(),
    };
    for pragma in ["application_id", "user_version"] {
        let value: i64 = db.query_row(&format!("PRAGMA {pragma}"), [], |row| row.get(0))?;
        for hash in [&mut hashes.digest, &mut hashes.environment] {
            feed_hash(hash, pragma.as_bytes());
            feed_hash(hash, &value.to_le_bytes());
        }
    }
    let schema: Vec<(String, String)> = db
        .prepare("SELECT name,sql FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_stat%' ORDER BY name")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<std::result::Result<_, _>>()?;
    for (table, ddl) in &schema {
        for hash in [&mut hashes.digest, &mut hashes.environment] {
            feed_hash(hash, table.as_bytes());
            feed_hash(hash, ddl.as_bytes());
        }
        let quoted = quote_ident(table);
        let columns: Vec<String> = db
            .prepare(&format!("PRAGMA table_info({quoted})"))?
            .query_map([], |row| row.get::<_, String>("name"))?
            .collect::<std::result::Result<_, _>>()?;
        let declared: Vec<String> = db
            .prepare(&format!("PRAGMA table_xinfo({quoted})"))?
            .query_map([], |row| row.get::<_, String>("name"))?
            .collect::<std::result::Result<_, _>>()?;
        let key = partition.then(|| partition_key(table)).flatten();
        let mut fields: Vec<String> = columns
            .iter()
            .map(|name| {
                let name = quote_ident(name);
                format!("typeof({name}),CAST({name} AS BLOB)")
            })
            .collect();
        if let Some(key) = key {
            fields.push(quote_ident(key));
        }
        let scan = TableScan {
            table,
            quoted,
            fields: fields.join(","),
            environment_rows: partition && key.is_none() && environment_table(table),
            columns,
            declared,
            key,
        };
        let keyed = match scan.rowid(&db, ddl) {
            Some(rowid) => scan.keyed(&db, &mut hashes, rowid, limits)?,
            None => false,
        };
        if !keyed {
            scan.sorted(&db, &mut hashes)?;
        }
    }
    drop(db);
    Ok(SnapshotEvidence {
        digest: hex::encode(hashes.digest.finalize()),
        environment: hex::encode(hashes.environment.finalize()),
        records: hashes
            .records
            .into_iter()
            .map(|(id, hash)| (id, hex::encode(hash.finalize())))
            .collect(),
    })
}

fn push_upper_hex(out: &mut Vec<u8>, bytes: &[u8]) {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let start = out.len();
    out.resize(start + bytes.len() * 2, 0);
    for (pair, byte) in out[start..].as_chunks_mut::<2>().0.iter_mut().zip(bytes) {
        pair[0] = DIGITS[(byte >> 4) as usize];
        pair[1] = DIGITS[(byte & 15) as usize];
    }
}

/// The original sqlx formulation of [`snapshot_evidence`], kept as the
/// executable definition of the digest format for equivalence tests and the
/// HQ-snapshot benchmark. Not for production use: it is several times slower.
#[cfg(any(test, feature = "v2-kernel-probe"))]
#[doc(hidden)]
pub async fn reference_snapshot_evidence(
    path: &std::path::Path,
    partition: bool,
) -> Result<SnapshotEvidence> {
    let mut db = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new()
            .filename(path)
            .read_only(true),
    )
    .await?;
    sqlx::query("BEGIN").execute(&mut db).await?;
    let mut digest = Sha256::new();
    let mut environment = Sha256::new();
    let mut records = std::collections::BTreeMap::<String, Sha256>::new();
    for pragma in ["application_id", "user_version"] {
        let value: i64 = sqlx::query_scalar(&format!("PRAGMA {pragma}"))
            .fetch_one(&mut db)
            .await?;
        for hash in [&mut digest, &mut environment] {
            feed_hash(hash, pragma.as_bytes());
            feed_hash(hash, &value.to_le_bytes());
        }
    }
    let schema:Vec<(String,String)>=sqlx::query_as("SELECT name,sql FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_stat%' ORDER BY name").fetch_all(&mut db).await?;
    for (table, ddl) in schema {
        for hash in [&mut digest, &mut environment] {
            feed_hash(hash, table.as_bytes());
            feed_hash(hash, ddl.as_bytes());
        }
        let quoted = format!("\"{}\"", table.replace('"', "\"\""));
        let columns = sqlx::query(&format!("PRAGMA table_info({quoted})"))
            .fetch_all(&mut db)
            .await?;
        let mut fields = Vec::new();
        for column in columns {
            let name: String = column.get("name");
            let name = format!("\"{}\"", name.replace('"', "\"\""));
            fields.push(format!("typeof({name}),hex(CAST({name} AS BLOB))"));
        }
        let key = if partition {
            match table.as_str() {
                "records" => "id",
                "content_events" | "facet_values" => "record_id",
                _ => "NULL",
            }
        } else {
            "NULL"
        };
        let query = format!(
            "SELECT {key},json_array({}) AS encoded FROM {quoted} ORDER BY encoded COLLATE BINARY",
            fields.join(",")
        );
        use futures::TryStreamExt;
        let mut rows = sqlx::query_as::<_, (Option<String>, String)>(&query).fetch(&mut db);
        while let Some((key, row)) = rows.try_next().await? {
            feed_hash(&mut digest, row.as_bytes());
            if partition {
                if let Some(key) = key {
                    let hash = records.entry(key).or_default();
                    feed_hash(hash, table.as_bytes());
                    feed_hash(hash, row.as_bytes());
                } else if matches!(
                    table.as_str(),
                    "database_identity"
                        | "schema_config"
                        | "vocabularies"
                        | "vocabulary_values"
                        | "meta_events"
                ) {
                    feed_hash(&mut environment, row.as_bytes());
                }
            }
        }
    }
    db.close().await?;
    Ok(SnapshotEvidence {
        digest: hex::encode(digest.finalize()),
        environment: hex::encode(environment.finalize()),
        records: records
            .into_iter()
            .map(|(id, hash)| (id, hex::encode(hash.finalize())))
            .collect(),
    })
}

/// Add a receipt only after an all/history import completed successfully.
/// A later operator checks both digests again against the frozen source and
/// still-unpublished target. The source must remain unchanged throughout import.
pub async fn attach_receipt(
    report: &Report,
    source: &std::path::Path,
    target: &std::path::Path,
    initial_source_digest: &str,
    all: bool,
    history: bool,
    resume: bool,
) -> Result<serde_json::Value> {
    let mut value = capture_report(report, source, all, history, resume).await?;
    let source_digest = snapshot_digest(source).await?;
    if source_digest != initial_source_digest {
        return Err("source changed during import; fresh immutable snapshot required".into());
    }
    let proof = &value["cutover_verification"];
    value["cutover_verification"] = json!({"schema":"native.v2-import-receipt.v1","importer_build_sha":crate::FULL_GIT_SHA,"all":all,"history":history,"resume":resume,"history_complete":proof["history_complete"],"source_records":proof["source_records"],"origin_db_id":proof["origin_db_id"],"source_digest":source_digest,"target_digest":snapshot_digest(target).await?,"target":target.canonicalize()?});
    Ok(value)
}

/// A non-binding progress gate for a capture-only pass. Every ordinary
/// all/history resume emits a digest-bound receipt for identity preparation.
pub async fn capture_report(
    report: &Report,
    source: &std::path::Path,
    all: bool,
    history: bool,
    resume: bool,
) -> Result<serde_json::Value> {
    let mut db = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new()
            .filename(source)
            .read_only(true),
    )
    .await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM records WHERE id<>'native:root'")
        .fetch_one(&mut db)
        .await?;
    let origin: String =
        sqlx::query_scalar("SELECT origin_db_id FROM database_identity WHERE singleton=1")
            .fetch_one(&mut db)
            .await?;
    db.close().await?;
    let mismatches = report.refusals.len()
        + report.review.len()
        + report.message_non_audience_leaks
        + report.message_v1_visible_but_v2_denied
        + report.message_v2_visible_but_v1_hidden;
    let history_complete = history
        && !report.history.streams.is_empty()
        && report
            .history
            .streams
            .values()
            .all(|s| s.source == s.verified);
    // Only these three reviewed outcomes are counted without blocking. An
    // inherited tombstone is already part of tombstones_verified, not an
    // additional excluded source row. No refusal category is a waiver.
    let counted_complete = report.counted.iter().all(|i| {
        matches!(
            i.reason.as_str(),
            "excluded_deleted" | "excluded_invisible_in_v1" | "inherited_bearer_tombstone"
        )
    }) && report
        .counted
        .iter()
        .filter(|i| i.reason == "excluded_deleted")
        .count()
        == report.excluded_deleted
        && report
            .counted
            .iter()
            .filter(|i| i.reason == "inherited_bearer_tombstone")
            .count()
            == report.inherited_bearer_tombstones
        && report
            .counted
            .iter()
            .filter(|i| i.reason == "excluded_invisible_in_v1")
            .count()
            == report.excluded_invisible_in_v1
        && report.excluded_invisible_tombstones_verified <= report.excluded_invisible_in_v1
        && report.excluded_invisible_tombstones_verified <= report.tombstones_verified
        && report.inherited_bearer_tombstones <= report.tombstones_verified
        && report
            .counted_breakdown
            .iter()
            .map(|i| i.count)
            .sum::<usize>()
            == report.counted.len();
    let capture_complete = all
        && report.state.member_contexts_prepared
        && counted_complete
        && history_complete
        && mismatches == 0
        && usize::try_from(count)?
            == report.verified
                + report.tombstones_verified
                + report.excluded_deleted
                + report.excluded_invisible_in_v1
                - report.excluded_invisible_tombstones_verified;
    let mut value = serde_json::to_value(report)?;
    value["capture_complete"] = json!(capture_complete);
    value["mismatches"] = json!(mismatches);
    value["cutover_verification"] = json!({"schema":"native.v2-import-capture.v1","importer_build_sha":crate::FULL_GIT_SHA,"all":all,"history":history,"resume":resume,"history_complete":history_complete,"source_records":count,"origin_db_id":origin});
    Ok(value)
}

#[cfg(test)]
mod fast_scan_equivalence_tests {
    use super::*;
    use rand::{Rng, SeedableRng};

    /// Compare against the reference under the production limits and under
    /// limits small enough to force every fallback, including a tie group
    /// that overflows after earlier rows of its table were already hashed.
    async fn assert_equivalent(path: &std::path::Path) {
        let forced = [
            KEYED_SCAN_LIMITS,
            KeyedScanLimits {
                key_bytes: 0,
                tie_bytes: usize::MAX,
            },
            KeyedScanLimits {
                key_bytes: usize::MAX,
                tie_bytes: 0,
            },
            KeyedScanLimits {
                key_bytes: usize::MAX,
                tie_bytes: 200,
            },
        ];
        for partition in [false, true] {
            let reference = reference_snapshot_evidence(path, partition).await.unwrap();
            for limits in forced {
                let owned = path.to_owned();
                let fast =
                    tokio::task::spawn_blocking(move || scan_snapshot(&owned, partition, limits))
                        .await
                        .unwrap()
                        .unwrap();
                let context = format!(
                    "partition={partition} key={} tie={}",
                    limits.key_bytes, limits.tie_bytes
                );
                assert_eq!(fast.digest, reference.digest, "{context}");
                assert_eq!(fast.environment, reference.environment, "{context}");
                assert_eq!(fast.records, reference.records, "{context}");
            }
            let public = snapshot_evidence(path, partition).await.unwrap();
            assert_eq!(public.digest, reference.digest);
        }
    }

    /// Values chosen to sit on every ordering boundary of the encoded text:
    /// mixed types in one column, byte prefixes, empty text/blob versus NULL,
    /// integers whose decimal text sorts differently from their value, REAL
    /// rendering, NUL bytes, non-ASCII text and duplicate rows.
    #[tokio::test]
    async fn fast_scan_matches_reference_on_ordering_edge_cases() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("edge.db");
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute_batch(
            r#"PRAGMA journal_mode=WAL; PRAGMA application_id=7; PRAGMA user_version=3;
            CREATE TABLE records(id TEXT, body ANY, n REAL, "odd ""name"" col" BLOB);
            CREATE TABLE "quoted ""table"""(a, b INTEGER);
            CREATE TABLE content_events(id TEXT, record_id TEXT, payload);
            CREATE TABLE facet_values(record_id TEXT, key TEXT, value);
            CREATE TABLE vocabularies(id TEXT, name TEXT);
            CREATE TABLE empty_table(x);
            CREATE TABLE without_rowid(k TEXT PRIMARY KEY, v) WITHOUT ROWID;
            CREATE TABLE all_aliases_shadowed("rowid" TEXT, "_ROWID_" INTEGER, "Oid" BLOB);
            CREATE TABLE one_alias_shadowed(_rowid_ TEXT, b);
            CREATE VIRTUAL TABLE search USING fts5(body);
            CREATE TABLE tied(first, second, third);
            CREATE TABLE nocase(t TEXT COLLATE NOCASE, u);
            INSERT INTO nocase VALUES ('b', 1), ('A', 2), ('a', 3), ('B', 4), ('a', 0);
            CREATE TABLE generated_rowid(a TEXT, _rowid_ INTEGER GENERATED ALWAYS AS (0) VIRTUAL);
            CREATE TABLE generated_stored(a TEXT, "ROWID" INTEGER GENERATED ALWAYS AS (length(a)) STORED);
            CREATE TABLE generated_all(a TEXT, _rowid_ AS (1), rowid AS (2), oid AS (3));
            INSERT INTO generated_rowid(a) VALUES ('a'), ('b'), ('c');
            INSERT INTO generated_stored(a) VALUES ('xx'), ('y'), ('zz');
            INSERT INTO generated_all(a) VALUES ('m'), ('n');
            INSERT INTO without_rowid VALUES ('b', 1), ('a', x'00'), ('c', NULL);
            INSERT INTO all_aliases_shadowed VALUES ('z', 2, x'01'), ('a', 1, NULL), ('a', 1, NULL);
            INSERT INTO one_alias_shadowed VALUES ('q', 1), ('p', 2), (NULL, 3);
            INSERT INTO search VALUES ('alpha beta'), ('gamma'), ('alpha beta');
            INSERT INTO tied VALUES (1, 'b', 2), (1, 'a', 3), (1, 'a', 2), (1, 'a', 2), ('1', 0, 0),
              (NULL, 'z', 1), (NULL, 'y', 1), (x'31', 1, 1), (1.0, 1, 1), (2, 'x', 'long enough to overflow a tiny tie budget');
            INSERT INTO records VALUES
              ('a', 'x', 1.0, x''), ('a', 'x', 1.0, x''), ('b', x'00', 0.1, NULL),
              ('c', 'x' || char(0) || 'y', -0.0, x'01'), ('d', 9, 1e300, x'0102'),
              ('e', 10, 2.5e-300, x'01FF'), ('f', -1, 123456789012345678.0, x'FF'),
              ('g', '', 3, x'00'), (NULL, NULL, NULL, NULL), ('h', 'é☃', 1.5, 'text'),
              ('i', 9223372036854775807, -9223372036854775808, 0.30000000000000004),
              ('j', -9223372036854775808, 1e15, 1e16);
            INSERT INTO "quoted ""table""" VALUES (1, '1'), ('1', 1), (x'31', 1.0), (NULL, ''), (2, 10), (2, 9);
            INSERT INTO content_events VALUES ('e1', 'a', 'p'), ('e2', NULL, 'q'), ('e3', 'b', x'00'), ('e4', 'a', 'p');
            INSERT INTO facet_values VALUES ('a', 'k', 1), ('z', 'k', 'v');
            INSERT INTO vocabularies VALUES ('v', 'name'), ('w', NULL);"#,
        )
        .unwrap();
        // Rows committed to the WAL but not checkpointed are part of the snapshot.
        assert_equivalent(&path).await;
        db.execute_batch("INSERT INTO records VALUES ('k', 'late', 2.0, x'02')")
            .unwrap();
        assert_equivalent(&path).await;
        drop(db);
    }

    /// UTF-16 storage changes the bytes CAST(text AS BLOB) yields; partition
    /// keys are still decoded to UTF-8 by both implementations.
    #[tokio::test]
    async fn fast_scan_matches_reference_on_a_utf16_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("utf16.db");
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute_batch(
            "PRAGMA encoding='UTF-16le';
            CREATE TABLE records(id TEXT, body);
            CREATE TABLE content_events(record_id TEXT, payload);
            INSERT INTO records VALUES ('é', 'ünïcode'), ('a', 'x'), ('b', 2), (NULL, x'00');
            INSERT INTO content_events VALUES ('é', 'p'), ('a', 'q');",
        )
        .unwrap();
        drop(db);
        assert_equivalent(&path).await;
    }

    /// The original refuses a non-text partition key (sqlx decodes
    /// Option<String> from TEXT only); the fast scan must refuse too.
    #[tokio::test]
    async fn fast_scan_refuses_non_text_partition_keys_like_the_reference() {
        for value in ["x'61'", "1", "1.5"] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("keys.db");
            let db = rusqlite::Connection::open(&path).unwrap();
            db.execute_batch(&format!(
                "CREATE TABLE records(id, body); INSERT INTO records VALUES ('a', 1), ({value}, 2);"
            ))
            .unwrap();
            drop(db);
            assert!(
                reference_snapshot_evidence(&path, true).await.is_err(),
                "{value}"
            );
            assert!(snapshot_evidence(&path, true).await.is_err(), "{value}");
            assert_eq!(
                snapshot_evidence(&path, false).await.unwrap().digest,
                reference_snapshot_evidence(&path, false)
                    .await
                    .unwrap()
                    .digest
            );
        }
    }

    #[tokio::test]
    async fn fast_scan_matches_reference_on_random_tables() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x5eed_d16e57);
        for round in 0..6 {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("random.db");
            let mut db = rusqlite::Connection::open(&path).unwrap();
            let tables = [
                "records",
                "content_events",
                "facet_values",
                "schema_config",
                "other",
            ];
            for (index, table) in tables.iter().enumerate() {
                let width = 1 + (round + index) % 4;
                let mut columns = vec!["id TEXT".to_owned()];
                if *table != "records" {
                    columns.push("record_id TEXT".into());
                }
                columns.extend((0..width).map(|c| format!("c{c}")));
                db.execute_batch(&format!("CREATE TABLE {table}({})", columns.join(",")))
                    .unwrap();
                let tx = db.transaction().unwrap();
                let count = columns.len();
                let placeholders = vec!["?"; count].join(",");
                let mut insert = tx
                    .prepare(&format!("INSERT INTO {table} VALUES({placeholders})"))
                    .unwrap();
                for _ in 0..400 {
                    let row: Vec<rusqlite::types::Value> = (0..count)
                        .map(|column| random_value(&mut rng, column < 2))
                        .collect();
                    insert
                        .execute(rusqlite::params_from_iter(row.iter()))
                        .unwrap();
                }
                drop(insert);
                tx.commit().unwrap();
            }
            drop(db);
            assert_equivalent(&path).await;
        }
    }

    fn random_value(rng: &mut impl Rng, id_like: bool) -> rusqlite::types::Value {
        use rusqlite::types::Value;
        let short = |rng: &mut dyn rand::RngCore| -> Vec<u8> {
            let len = [0usize, 1, 1, 2, 3, 8][(rng.next_u32() % 6) as usize];
            (0..len)
                .map(|_| [0u8, 1, 0x30, 0x41, 0x7f, 0xff][(rng.next_u32() % 6) as usize])
                .collect()
        };
        if id_like {
            return match rng.random_range(0..10) {
                0 => Value::Null,
                _ => Value::Text(format!("r{}", rng.random_range(0..12))),
            };
        }
        match rng.random_range(0..6) {
            0 => Value::Null,
            1 => Value::Integer([0, 1, -1, 9, 10, 100, i64::MAX, i64::MIN][rng.random_range(0..8)]),
            2 => Value::Real(
                [
                    0.0,
                    -0.0,
                    0.1,
                    1.0,
                    1e100,
                    -2.5e-7,
                    1.0 / 3.0,
                    4503599627370497.0,
                ][rng.random_range(0..8)],
            ),
            3 => Value::Text(
                String::from_utf8_lossy(&short(rng)).into_owned()
                    + ["", "é", "a"][rng.random_range(0..3)],
            ),
            _ => Value::Blob(short(rng)),
        }
    }
}

#[cfg(test)]
mod preinspection_evidence_tests {
    use super::*;

    #[tokio::test]
    async fn partitions_preserve_full_digest_and_invalidate_source_authority_and_unknown_data() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source.db");
        let mut db = SqliteConnection::connect_with(
            &sqlx::sqlite::SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true),
        )
        .await
        .unwrap();
        use sqlx::Executor;
        db.execute("CREATE TABLE records(id TEXT,type TEXT,kind TEXT,home_id TEXT,owner_id TEXT,policy_anchor_id TEXT,deleted_at TEXT,body TEXT); CREATE TABLE content_events(id TEXT,record_id TEXT,payload TEXT); CREATE TABLE facet_values(record_id TEXT,key TEXT,value TEXT); CREATE TABLE new_dependency(value BLOB); INSERT INTO records VALUES('a','Document','artifact',NULL,NULL,'root',NULL,'one'),('b','Document','artifact',NULL,NULL,'root',NULL,'two'); INSERT INTO content_events VALUES('event-a','a','source-a'),('event-b','b','source-b'); INSERT INTO new_dependency VALUES(x'0001');").await.unwrap();
        let before = snapshot_evidence(&path, true).await.unwrap();
        assert_eq!(before.digest, snapshot_digest(&path).await.unwrap());
        sqlx::query("UPDATE records SET body='changed' WHERE id='a'")
            .execute(&mut db)
            .await
            .unwrap();
        let edited = snapshot_evidence(&path, true).await.unwrap();
        assert_ne!(before.digest, edited.digest);
        assert_ne!(before.records["a"], edited.records["a"]);
        assert_eq!(before.records["b"], edited.records["b"]);
        assert_eq!(before.environment, edited.environment);
        sqlx::query("UPDATE records SET home_id='new-parent' WHERE id='a'")
            .execute(&mut db)
            .await
            .unwrap();
        let moved = snapshot_evidence(&path, true).await.unwrap();
        assert_ne!(edited.records["a"], moved.records["a"]);
        sqlx::query("UPDATE new_dependency SET value=x'0002'")
            .execute(&mut db)
            .await
            .unwrap();
        let unknown = snapshot_evidence(&path, true).await.unwrap();
        // Unknown data remains in the full key used by bound/unknown readers;
        // standalone renderers cannot consume this table.
        assert_eq!(moved.environment, unknown.environment);
        assert_ne!(moved.digest, unknown.digest);
        assert_eq!(unknown.digest, snapshot_digest(&path).await.unwrap());
        db.close().await.unwrap();
    }
}
