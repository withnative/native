//! Schema-derived projection coverage and a bounded-memory, full-state digest.
use super::*;
use futures::TryStreamExt;
use sha2::{Digest, Sha256};
use sqlx::{Row, TypeInfo, ValueRef};

/// Canonical authority is transported separately, not rebuilt by projectors.
/// FTS shadow tables are physical index layout; the logical FTS table and its
/// version metadata ARE included. Exact exclusions cannot hide a future table.
pub const EXCLUDED_TABLES: &[&str] = &[
    "content_events",
    "meta_events",
    "act_state",
    "act_cutover",
    "content_event_causal_frontier",
    "content_event_causal_cutover",
    // Trigger-maintained function of the two canonical tables above: it moves
    // whenever events are appended (including by an import resume), never by
    // projection replay, so it cannot be part of the projection digest. Tests
    // pin it equal to the frontier anti-join instead.
    "content_event_heads",
    "kernel_blobs",
    // Derived access-epoch accelerator for the visible-set cache (Native
    // b171a9d). Seeded randomly and bumped by rebuilds, so files with
    // identical events legitimately differ here. Never an authorization input.
    "kernel_access_epoch",
    // A standby copy advanced in place records what it applied here, in the
    // transaction that applied it. Local bookkeeping, never hosted state.
    "kernel_standby_apply_receipts",
    // The optional cache of per-table set-digest accumulators (design record
    // 5065900). Derived, never authoritative: the rows are.
    "kernel_standby_projection_set",
    // Preparation can advance this gap-free scan cursor independently of event
    // folding. It is derived recovery progress, not user-visible content. The
    // canonical envelopes and kernel_legacy_sql_events headers remain checked.
    "kernel_legacy_sql_progress",
    "kernel_sql_record_projection",
    "kernel_sql_record_projection_state",
    // Stored visibility marking (73ad275): local accelerators, never
    // canonical, and absent on files that never enabled marking.
    // Every name in `stored_visibility::TABLES` (pinned by its tests).
    "p_dirty",
    "p_marking",
    "p_state",
    "p_generation",
    "p_home_anchor",
    "p_principal",
    "p_scope_access",
    "kernel_sql_event_projection",
    "kernel_sql_event_subject_sets",
    "kernel_sql_event_projection_state",
    "kernel_search_fts_data",
    "kernel_search_fts_idx",
    "kernel_search_fts_content",
    "kernel_search_fts_docsize",
    "kernel_search_fts_config",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectionTableDump {
    pub name: String,
    pub rows: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectionDump {
    pub tables: Vec<ProjectionTableDump>,
    pub sha256: String,
}

pub async fn dump(db: &Db) -> Result<ProjectionDump> {
    let mut tx = db.pool().begin().await?;
    let result = dump_on(&mut tx).await?;
    tx.commit().await?;
    Ok(result)
}

pub(crate) async fn dump_on(conn: &mut SqliteConnection) -> Result<ProjectionDump> {
    dump_on_observed(conn, &mut |_, _, _| {}).await
}

/// [`dump_on`], reporting `(table, rows, wall time)` as each table is digested.
/// Diagnostic only: the observer cannot change the digest.
pub(crate) async fn dump_on_observed(
    conn: &mut SqliteConnection,
    observer: &mut (dyn FnMut(&str, u64, std::time::Duration) + Send),
) -> Result<ProjectionDump> {
    Ok(dump_core(conn, observer, false).await?.0)
}

/// One table's order-independent summary: its row multiset as a MuHash3072.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetTableDump {
    pub name: String,
    /// SHA-256 of the framed `(name, table_info)` JSON the v1 digest also uses.
    pub schema_sha256: String,
    pub rows: u64,
    /// SHA-256 of the normalised 384-byte little-endian MuHash value.
    pub set_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetDump {
    pub tables: Vec<SetTableDump>,
    /// `SHA256("native.kernel-projection-set.v1\0" || JCS(tables))`.
    pub sha256: String,
}

/// `SHA256("native.kernel-projection-set.v1\0" || JCS(tables))`.
pub(crate) fn set_digest(tables: &[SetTableDump]) -> Result<String> {
    let mut whole = Sha256::new();
    whole.update(b"native.kernel-projection-set.v1\0");
    whole.update(serde_jcs::to_vec(&tables)?);
    Ok(hex::encode(whole.finalize()))
}

/// Whether a main-schema table is part of the projection digest. Bare v2 owns
/// every non-canonical table; compatibility kernel tests also carry the
/// unrelated frozen v1 schema, so only that older test mode needs a namespace
/// filter for its kernel/registry projections.
pub(crate) fn included_in_projection(is_v2: bool, name: &str) -> bool {
    !(EXCLUDED_TABLES.contains(&name)
        || (!is_v2
            && !name.starts_with("kernel_")
            && ![
                "definition_artifacts",
                "definition_adoptions",
                "package_artifacts",
                "consumer_requirements",
                "rule_installations",
            ]
            .contains(&name)))
}

/// One table's `schema_sha256` as the set digest reports it: SHA-256 of the
/// framed `(name, table_info)` JSON, read from `main`.
pub(crate) async fn table_schema_sha256(conn: &mut SqliteConnection, name: &str) -> Result<String> {
    #[allow(clippy::type_complexity)]
    let columns: Vec<(i64, String, String, i64, Option<String>, i64)> =
        sqlx::query_as(&format!("PRAGMA table_info({})", quote(name)))
            .fetch_all(&mut *conn)
            .await?;
    let schema_json = serde_json::to_vec(&(name, &columns))?;
    let mut schema = Sha256::new();
    frame(&mut schema, &schema_json);
    Ok(hex::encode(schema.finalize()))
}

/// Both digests in ONE ordered pass over each table: the v1 digest, byte for
/// byte as [`dump_on`] produces it, and the set digest. Not yet wired into any
/// wire format, receipt or apply path.
pub(crate) async fn dump_on_dual(conn: &mut SqliteConnection) -> Result<(ProjectionDump, SetDump)> {
    let (dump, set, _) = dump_core(conn, &mut |_, _, _| {}, true).await?;
    Ok((dump, set.expect("set digest requested")))
}

/// One table's normalised MuHash value, as an accumulator cache would hold it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SetValue {
    pub name: String,
    pub schema_sha256: String,
    pub rows: u64,
    /// The 384-byte little-endian normalised value; its SHA-256 is the
    /// table's `set_sha256`.
    pub value: Vec<u8>,
}

/// [`dump_on_dual`] that also returns each table's normalised value.
pub(crate) async fn dump_on_dual_values(
    conn: &mut SqliteConnection,
) -> Result<(ProjectionDump, SetDump, Vec<SetValue>)> {
    let (dump, set, values) = dump_core(conn, &mut |_, _, _| {}, true).await?;
    Ok((dump, set.expect("set digest requested"), values))
}

async fn dump_core(
    conn: &mut SqliteConnection,
    observer: &mut (dyn FnMut(&str, u64, std::time::Duration) + Send),
    want_set: bool,
) -> Result<(ProjectionDump, Option<SetDump>, Vec<SetValue>)> {
    let private = super::working_undo_schema::exclusions(conn).await?;
    let v2: i64 = sqlx::query_scalar("PRAGMA application_id")
        .fetch_one(&mut *conn)
        .await?;
    let names: Vec<String> = sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type='table' AND name NOT GLOB 'sqlite_*' ORDER BY name")
        .fetch_all(&mut *conn).await?;
    let mut tables = Vec::new();
    let mut set_tables = Vec::new();
    let mut set_values = Vec::new();
    for name in names {
        // Bare v2 owns every non-canonical table. Compatibility kernel tests
        // also carry the unrelated frozen v1 schema: only that older test
        // mode needs a namespace filter for its kernel/registry projections.
        if private.contains(&name)
            || !included_in_projection(v2 == crate::db::V2_APPLICATION_ID, &name)
        {
            continue;
        }
        let table_started = std::time::Instant::now();
        let quoted = quote(&name);
        #[allow(clippy::type_complexity)]
        let columns: Vec<(i64, String, String, i64, Option<String>, i64)> =
            sqlx::query_as(&format!("PRAGMA table_info({quoted})"))
                .fetch_all(&mut *conn)
                .await?;
        let mut keys: Vec<_> = columns.iter().filter(|c| c.5 > 0).collect();
        keys.sort_by_key(|c| c.5);
        if keys.is_empty() {
            keys = columns.iter().collect();
        }
        let order = keys
            .iter()
            .map(|c| quote(&c.1))
            .collect::<Vec<_>>()
            .join(",");
        let mut digest = Sha256::new();
        digest.update(b"native.kernel-projection-table.v1\0");
        let schema_json = serde_json::to_vec(&(&name, &columns))?;
        frame(&mut digest, &schema_json);
        // Set digest: e(t, r) = prefix || frame(t) || ROW(r), mapped into the
        // group through its SHA-256 key.
        let mut element_prefix = Sha256::new();
        element_prefix.update(SET_ELEMENT_PREFIX);
        frame(&mut element_prefix, name.as_bytes());
        let mut set = super::projection_set::MuHash::new();
        let query = format!("SELECT * FROM {quoted} ORDER BY {order}");
        let mut stream = sqlx::query(&query).fetch(&mut *conn);
        let mut rows = 0_u64;
        while let Some(row) = stream.try_next().await? {
            if want_set {
                let mut element = element_prefix.clone();
                hash_row(&mut Tee(&mut digest, &mut element), &row, columns.len())?;
                set.insert_key(&element.finalize().into());
            } else {
                hash_row(&mut digest, &row, columns.len())?;
            }
            rows += 1;
        }
        digest.update(rows.to_le_bytes());
        if want_set {
            let mut schema = Sha256::new();
            frame(&mut schema, &schema_json);
            let value = set.normalise();
            let schema_sha256 = hex::encode(schema.finalize());
            set_values.push(SetValue {
                name: name.clone(),
                schema_sha256: schema_sha256.clone(),
                rows,
                value: value.to_vec(),
            });
            set_tables.push(SetTableDump {
                name: name.clone(),
                schema_sha256,
                rows,
                set_sha256: hex::encode(Sha256::digest(value)),
            });
        }
        observer(&name, rows, table_started.elapsed());
        tables.push(ProjectionTableDump {
            name,
            rows,
            sha256: hex::encode(digest.finalize()),
        });
    }
    let mut digest = Sha256::new();
    digest.update(b"native.kernel-projections.v1\0");
    digest.update(serde_json::to_vec(&tables)?);
    let dump = ProjectionDump {
        tables,
        sha256: hex::encode(digest.finalize()),
    };
    let set = if want_set {
        Some(SetDump {
            sha256: set_digest(&set_tables)?,
            tables: set_tables,
        })
    } else {
        None
    };
    Ok((dump, set, set_values))
}

pub(crate) const SET_ELEMENT_PREFIX: &[u8] = b"native.kernel-projection-row.v1\0";

/// Where a row's canonical bytes go. The v1 digest hashes them into one
/// SHA-256; the set digest hashes the same bytes (after its own prefix) into a
/// second; `Tee` feeds both in a single pass, so the two encodings can never
/// drift apart.
pub(crate) trait RowSink {
    fn put(&mut self, bytes: &[u8]);
}
impl RowSink for Sha256 {
    fn put(&mut self, bytes: &[u8]) {
        self.update(bytes);
    }
}
pub(crate) struct Tee<'a>(pub &'a mut Sha256, pub &'a mut Sha256);
impl RowSink for Tee<'_> {
    fn put(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
        self.1.update(bytes);
    }
}

/// One column value of a row, by storage class.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Cell<'a> {
    Null,
    Int(i64),
    Real(f64),
    Text(&'a str),
    Blob(&'a [u8]),
}

/// One column's bytes inside `ROW(r)`: the storage class tag, then the value
/// (REAL by its bit pattern, so -0.0 and 0.0 differ; TEXT and BLOB framed).
pub(crate) fn hash_cell<S: RowSink>(sink: &mut S, cell: &Cell<'_>) {
    match cell {
        Cell::Null => sink.put(b"null\0"),
        Cell::Int(value) => {
            sink.put(b"int\0");
            sink.put(&value.to_le_bytes());
        }
        Cell::Real(value) => {
            sink.put(b"real\0");
            sink.put(&value.to_bits().to_le_bytes());
        }
        Cell::Text(value) => {
            sink.put(b"text\0");
            put_frame(sink, value.as_bytes());
        }
        Cell::Blob(value) => {
            sink.put(b"blob\0");
            put_frame(sink, value);
        }
    }
}

/// The start of `ROW(r)`.
pub(crate) fn begin_row<S: RowSink>(sink: &mut S) {
    sink.put(b"row\0");
}

/// `ROW(r)`: one row's columns, storage-class tagged and length framed. This is
/// the single definition of the row encoding (v1 digests, set elements and
/// captured base images all go through [`begin_row`] and [`hash_cell`]).
pub(crate) fn hash_row<S: RowSink>(
    sink: &mut S,
    row: &sqlx::sqlite::SqliteRow,
    columns: usize,
) -> Result<()> {
    begin_row(sink);
    for index in 0..columns {
        let raw = row.try_get_raw(index)?;
        if raw.is_null() {
            hash_cell(sink, &Cell::Null);
            continue;
        }
        match raw.type_info().name() {
            "INTEGER" => hash_cell(sink, &Cell::Int(row.try_get::<i64, _>(index)?)),
            "REAL" => hash_cell(sink, &Cell::Real(row.try_get::<f64, _>(index)?)),
            "TEXT" => hash_cell(sink, &Cell::Text(row.try_get::<&str, _>(index)?)),
            "BLOB" => hash_cell(sink, &Cell::Blob(row.try_get::<&[u8], _>(index)?)),
            _ => return Err(Error::engine("unsupported projection storage class")),
        }
    }
    Ok(())
}

pub(crate) fn put_frame<S: RowSink>(sink: &mut S, bytes: &[u8]) {
    sink.put(&(bytes.len() as u64).to_le_bytes());
    sink.put(bytes);
}

/// Digest of the rows `sql` selects (in the order it selects them, which the
/// caller must make total), with the number of rows. Used to cover canonical
/// event rows, which the projection digest deliberately excludes.
pub(crate) async fn digest_rows(
    conn: &mut SqliteConnection,
    label: &str,
    sql: &str,
    binds: &[i64],
    columns: usize,
) -> Result<(u64, String)> {
    let mut digest = Sha256::new();
    digest.update(b"native.kernel-row-range.v1\0");
    frame(&mut digest, label.as_bytes());
    let mut query = sqlx::query(sql);
    for value in binds {
        query = query.bind(*value);
    }
    let mut stream = query.fetch(&mut *conn);
    let mut rows = 0_u64;
    while let Some(row) = stream.try_next().await? {
        hash_row(&mut digest, &row, columns)?;
        rows += 1;
    }
    digest.update(rows.to_le_bytes());
    Ok((rows, hex::encode(digest.finalize())))
}

fn frame(digest: &mut Sha256, bytes: &[u8]) {
    put_frame(digest, bytes);
}
fn quote(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Connection;

    #[tokio::test]
    async fn working_undo_payload_is_not_hidden_in_generic_digests() {
        use sqlx::Executor;
        for table in ["working_undo", "working_undo_boundaries"] {
            let mut c = SqliteConnection::connect("sqlite::memory:").await.unwrap();
            c.execute(format!("PRAGMA application_id={}; CREATE TABLE {table}(payload TEXT); INSERT INTO {table} VALUES('erased image')",crate::db::V2_APPLICATION_ID).as_str()).await.unwrap();
            assert!(dump_on(&mut c).await.is_err());
            assert!(dump_on_dual(&mut c).await.is_err());
            c.execute(format!("DELETE FROM {table}").as_str())
                .await
                .unwrap();
            assert!(
                dump_on(&mut c)
                    .await
                    .unwrap()
                    .tables
                    .iter()
                    .any(|t| t.name == table),
                "an altered private table must remain included"
            );
        }
    }
    /// A deterministic table covering every storage class and the awkward
    /// values: NULL, -0.0, i64 extremes, empty TEXT/BLOB and TEXT with NUL.
    pub(crate) async fn golden_fixture() -> SqliteConnection {
        let mut conn = SqliteConnection::connect("sqlite::memory:").await.unwrap();
        sqlx::query("CREATE TABLE kernel_golden(id INTEGER PRIMARY KEY, a, b)")
            .execute(&mut conn)
            .await
            .unwrap();
        sqlx::query("INSERT INTO kernel_golden VALUES(1,NULL,'x')")
            .execute(&mut conn)
            .await
            .unwrap();
        sqlx::query("INSERT INTO kernel_golden VALUES(2,?,'')")
            .bind(-0.0_f64)
            .execute(&mut conn)
            .await
            .unwrap();
        sqlx::query("INSERT INTO kernel_golden VALUES(3,?,?)")
            .bind(i64::MAX)
            .bind(&[0_u8, 255][..])
            .execute(&mut conn)
            .await
            .unwrap();
        sqlx::query("INSERT INTO kernel_golden VALUES(4,?,?)")
            .bind(i64::MIN)
            .bind("a\0b")
            .execute(&mut conn)
            .await
            .unwrap();
        sqlx::query("INSERT INTO kernel_golden VALUES(5,?,?)")
            .bind(1.5_f64)
            .bind(&[][..] as &[u8])
            .execute(&mut conn)
            .await
            .unwrap();
        conn
    }

    #[tokio::test]
    async fn v1_digest_is_byte_identical_on_the_golden_fixture() {
        let mut conn = golden_fixture().await;
        let dump = dump_on(&mut conn).await.unwrap();
        assert_eq!(dump.tables.len(), 1);
        assert_eq!(dump.tables[0].rows, 5);
        // Captured from the encoder before it was factored out; any change to
        // the v1 byte layout (hosted and standby digests) breaks this.
        assert_eq!(
            dump.sha256,
            "1a4bc732ecb5dcfefa6ff4a3e6527ec100d7f1be54bf92aacffc40b2bea0e883"
        );
    }
}

#[cfg(test)]
mod set_tests {
    use super::tests::golden_fixture;
    use super::*;
    use sqlx::Connection;

    async fn fresh() -> SqliteConnection {
        SqliteConnection::connect("sqlite::memory:").await.unwrap()
    }

    /// Constants from an independent Python implementation (hashlib,
    /// `cryptography` ChaCha20, `pow(x, -1, p)`): the row encoding, the element
    /// key, the keystream mapping, the product and the summary framing.
    #[tokio::test]
    async fn golden_vectors_match_an_independent_implementation() {
        let mut conn = golden_fixture().await;
        let (v1, set) = dump_on_dual(&mut conn).await.unwrap();
        assert_eq!(set.tables.len(), 1);
        let table = &set.tables[0];
        assert_eq!(table.name, "kernel_golden");
        assert_eq!(table.rows, 5);
        assert_eq!(
            table.schema_sha256,
            "af7358712c05458c0f5c64b28f6fb574fe3869f7d854a9b550f1c46ce239b3ae"
        );
        assert_eq!(
            table.set_sha256,
            "8a4da0892d570030a33c2a1522d2b7c6f927c0644df0ea9fed4d701298aa71da"
        );
        assert_eq!(
            set.sha256,
            "ff8b736f9213549f70ae392a7b9044174e72cc1153697d90e08d8e05a6ca1c52"
        );
        // The one pass leaves the v1 digest exactly as the v1 pass computes it.
        assert_eq!(v1, dump_on(&mut conn).await.unwrap());
        assert_eq!(
            v1.sha256,
            "1a4bc732ecb5dcfefa6ff4a3e6527ec100d7f1be54bf92aacffc40b2bea0e883"
        );
    }

    async fn single(value_sql: &str) -> String {
        let mut conn = fresh().await;
        sqlx::query("CREATE TABLE kernel_one(a)")
            .execute(&mut conn)
            .await
            .unwrap();
        sqlx::query(&format!("INSERT INTO kernel_one VALUES({value_sql})"))
            .execute(&mut conn)
            .await
            .unwrap();
        dump_on_dual(&mut conn).await.unwrap().1.tables[0]
            .set_sha256
            .clone()
    }

    #[tokio::test]
    async fn awkward_values_are_distinct_and_stable() {
        let mut seen = std::collections::HashSet::new();
        for value in [
            "NULL",
            "0.0",
            "0",
            "9223372036854775807",
            "-9223372036854775807-1",
            "''",
            "X''",
            "char(0)",
            "'a'||char(0)||'b'",
            "'a'",
        ] {
            assert!(seen.insert(single(value).await), "{value} collided");
        }
        // -0.0 cannot be written as SQL text; bind it.
        let mut conn = fresh().await;
        sqlx::query("CREATE TABLE kernel_one(a)")
            .execute(&mut conn)
            .await
            .unwrap();
        sqlx::query("INSERT INTO kernel_one VALUES(?)")
            .bind(-0.0_f64)
            .execute(&mut conn)
            .await
            .unwrap();
        let negative = dump_on_dual(&mut conn).await.unwrap().1.tables[0]
            .set_sha256
            .clone();
        assert_ne!(negative, single("0.0").await);
        assert!(seen.insert(negative));
    }

    async fn table_with(rows: &[(i64, &str)], order: &[usize]) -> SetDump {
        let mut conn = fresh().await;
        sqlx::query("CREATE TABLE kernel_t(id INTEGER PRIMARY KEY, body TEXT)")
            .execute(&mut conn)
            .await
            .unwrap();
        for index in order {
            sqlx::query("INSERT INTO kernel_t VALUES(?,?)")
                .bind(rows[*index].0)
                .bind(rows[*index].1)
                .execute(&mut conn)
                .await
                .unwrap();
        }
        dump_on_dual(&mut conn).await.unwrap().1
    }

    #[tokio::test]
    async fn shuffled_insertion_gives_the_same_set_digest() {
        let rows: Vec<(i64, &str)> = (0..50).map(|i| (i, "row")).collect();
        let forward: Vec<usize> = (0..50).collect();
        let mut shuffled = forward.clone();
        let mut state = 12345_u64;
        for i in (1..shuffled.len()).rev() {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            shuffled.swap(i, (state >> 33) as usize % (i + 1));
        }
        assert_ne!(forward, shuffled);
        assert_eq!(
            table_with(&rows, &forward).await,
            table_with(&rows, &shuffled).await
        );
    }

    /// `k` copies of one row.
    async fn copies(ddl: &str, table: &str, value: &str, k: usize) -> String {
        let mut conn = fresh().await;
        sqlx::query(ddl).execute(&mut conn).await.unwrap();
        sqlx::query(&format!(
            "WITH RECURSIVE c(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM c WHERE n<{k}) INSERT INTO {table}(body) SELECT {value} FROM c"
        ))
        .execute(&mut conn)
        .await
        .unwrap();
        let (_, set) = dump_on_dual(&mut conn).await.unwrap();
        // The logical table's own digest: the whole digest would also include
        // FTS5's physical shadow tables, which a test table (unlike the
        // canonical `kernel_search_fts`) does not exclude.
        set.tables
            .iter()
            .find(|t| t.name == table)
            .expect("logical table is summarised")
            .set_sha256
            .clone()
    }

    async fn multiplicity_differs(ks: &[usize]) {
        for k in ks {
            for (ddl, table) in [
                ("CREATE TABLE kernel_m(body TEXT)", "kernel_m"),
                ("CREATE VIRTUAL TABLE kernel_m USING fts5(body)", "kernel_m"),
            ] {
                let a = copies(ddl, table, "'alpha'", *k).await;
                let b = copies(ddl, table, "'beta'", *k).await;
                assert_ne!(a, b, "{ddl} x {k}");
                // And a different count of the same row differs too.
                let fewer = copies(ddl, table, "'alpha'", *k - 1).await;
                assert_ne!(a, fewer, "{ddl} x {k}");
            }
        }
    }

    /// A x k against B x k must differ, in a table with no primary key and in
    /// FTS (a counting scheme with 16-bit counters would collide at 2^16).
    #[tokio::test]
    async fn equal_multiplicities_of_different_rows_differ() {
        multiplicity_differs(&[2, 64]).await;
    }

    /// The boundary multiplicities 2^15, 2^16 and 2^16+1; too slow for the
    /// default lane (hundreds of thousands of rows through unoptimised
    /// arithmetic), so a measured entry: see ci/test-gates.toml.
    #[tokio::test]
    #[ignore = "measured: 2^15..2^16+1 rows per variant through unoptimised arithmetic"]
    async fn equal_multiplicities_differ_at_the_counter_boundaries() {
        multiplicity_differs(&[1 << 15, 1 << 16, (1 << 16) + 1]).await;
    }
}

#[cfg(test)]
mod measurements {
    use super::*;

    /// Measurement, not a regression test: the v1 pass against the one-pass
    /// dual digest on a large synthetic hosted base, and the cost of one
    /// inversion per touched table. Debug-profile arithmetic is two orders of
    /// magnitude slower than release; the per-row set cost to quote is the
    /// release micro-benchmark. Set `TMPDIR` to a scratch directory.
    ///
    /// ```text
    /// C15A932_RECORDS=100000 C15A932_BLOB_MIB=1900 cargo test --lib \
    ///   measure_set_digest_on_a_large_base -- --ignored --nocapture
    /// ```
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "measurement harness; builds a multi-gigabyte scratch database"]
    async fn measure_set_digest_on_a_large_base() {
        fn env(name: &str, default: usize) -> usize {
            std::env::var(name)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default)
        }
        let records = env("C15A932_RECORDS", 2000);
        let blob_mib = env("C15A932_BLOB_MIB", 0);
        let scratch = tempfile::tempdir().unwrap();
        let path = scratch.path().join("hosted.db");
        let (db, admin) = crate::kernel::create_v2_database(
            path.to_str().unwrap(),
            "account",
            "Owner",
            "acct:fixture",
        )
        .await
        .unwrap();
        for _ in 0..records {
            crate::kernel::create_record_as(&db, &admin, crate::events::KERNEL_ROOT_ID)
                .await
                .unwrap();
        }
        for number in 0..blob_mib {
            let bytes = vec![(number % 251) as u8; 1024 * 1024];
            let key = format!("{:064x}", number);
            sqlx::query("INSERT INTO kernel_blobs VALUES(?,?,?,NULL)")
                .bind(key)
                .bind(bytes.as_slice())
                .bind(bytes.len() as i64)
                .execute(db.write_pool())
                .await
                .unwrap();
        }
        let mut conn = db.write_pool().acquire().await.unwrap();
        let started = std::time::Instant::now();
        let v1 = dump_on(&mut conn).await.unwrap();
        let v1_time = started.elapsed();
        let started = std::time::Instant::now();
        let (dual_v1, set) = dump_on_dual(&mut conn).await.unwrap();
        let dual_time = started.elapsed();
        assert_eq!(v1, dual_v1);
        let rows: u64 = v1.tables.iter().map(|t| t.rows).sum();
        println!(
            "MEASURE rows={rows} v1_ms={} dual_ms={} extra_us_per_row={:.2}",
            v1_time.as_millis(),
            dual_time.as_millis(),
            (dual_time.as_secs_f64() - v1_time.as_secs_f64()) * 1e6 / rows as f64
        );
        let mut tables: Vec<_> = set.tables.iter().filter(|t| t.rows > 0).collect();
        tables.sort_by_key(|t| std::cmp::Reverse(t.rows));
        println!(
            "MEASURE populated_tables={} top={:?}",
            tables.len(),
            tables
                .iter()
                .take(4)
                .map(|t| (&t.name, t.rows))
                .collect::<Vec<_>>()
        );
        // G2: one inversion per touched table, at the small-delta cap.
        let touched = tables.len().min(20);
        let started = std::time::Instant::now();
        for table in tables.iter().take(touched) {
            let mut acc = super::super::projection_set::MuHash::new();
            acc.insert_key(&[table.rows as u8; 32]);
            acc.remove_key(&[1; 32]);
            std::hint::black_box(acc.normalise());
        }
        println!(
            "MEASURE normalise_x{touched}_ms={}",
            started.elapsed().as_millis()
        );
    }
}
