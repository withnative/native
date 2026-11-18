use super::*;
use crate::kernel::projection_dump::dump_on_dual_values;
use crate::kernel::projection_set::{Num3072, BYTE_SIZE};
use sqlx::{Connection, Executor, SqliteConnection};

type Tables = BTreeMap<String, (u64, Vec<u8>)>;

/// Every projection table's row count and normalised set value, recomputed
/// from scratch with the full scan.
async fn recompute(conn: &mut SqliteConnection) -> Tables {
    let (_, _, values) = dump_on_dual_values(conn).await.unwrap();
    values
        .into_iter()
        .map(|v| (v.name, (v.rows, v.value)))
        .collect()
}

/// The accumulators after a transaction, from the accumulators before it and
/// the captured deltas.
fn applied(before: &Tables, deltas: &[TableDelta]) -> Tables {
    let mut out = before.clone();
    for delta in deltas {
        let (rows, value) = out
            .get_mut(&delta.name)
            .unwrap_or_else(|| panic!("captured a table the digest does not know: {}", delta.name));
        let mut bytes = [0_u8; BYTE_SIZE];
        bytes.copy_from_slice(value);
        let mut acc = MuHash::from_numerator(Num3072::from_le_bytes(&bytes));
        acc.combine(&delta.delta);
        *value = acc.normalise().to_vec();
        *rows = (*rows as i64 + delta.row_delta) as u64;
    }
    out
}

fn assert_same(expected: &Tables, actual: &Tables, context: &str) {
    for (name, want) in expected {
        let got = actual
            .get(name)
            .unwrap_or_else(|| panic!("{context}: lost {name}"));
        assert_eq!(want.0, got.0, "{context}: row count of {name}");
        assert_eq!(want.1, got.1, "{context}: set value of {name}");
    }
    assert_eq!(expected.len(), actual.len(), "{context}: table set");
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len() as u64) as usize]
    }
}

fn literal(rng: &mut Rng) -> String {
    match rng.below(20) {
        0 => "NULL".into(),
        1 => format!("{}", rng.below(6)),
        2 => format!("{}", -(rng.below(4) as i64)),
        3 => "9223372036854775807".into(),
        4 => "(-9223372036854775807-1)".into(),
        5 => format!("{}.5", rng.below(5)),
        6 => format!("{}.0", rng.below(5)),
        7 => "-0.0".into(),
        8 => "(0.0 * -1.0)".into(),
        9 => "''".into(),
        10 => format!("'t{}'", rng.below(4)),
        11 => "('a' || char(0) || 'b')".into(),
        12 => "x'00ff'".into(),
        // Numeric-looking text and blobs, which NUMERIC / INTEGER affinity
        // columns convert (or, for blobs, leave alone).
        13 => "'42'".into(),
        14 => "'3.0'".into(),
        15 => "' 7 '".into(),
        16 => "'1e2'".into(),
        17 => "'-0'".into(),
        18 => "x'3432'".into(),
        _ => "'0x10'".into(),
    }
}

#[derive(Clone)]
struct Spec {
    name: String,
    /// `id INTEGER PRIMARY KEY` present.
    ipk: bool,
    columns: Vec<String>,
}

fn random_schema(rng: &mut Rng) -> (Vec<String>, Vec<Spec>) {
    let declared = [
        "TEXT",
        "REAL",
        "INTEGER",
        "BLOB",
        "",
        "NUMERIC",
        "DOUBLE PRECISION",
        "FLOAT",
    ];
    let mut ddl = Vec::new();
    let mut specs = Vec::new();
    for t in 0..(2 + rng.below(3)) {
        let name = format!("kernel_p{t}");
        let ipk = t == 0 || rng.below(2) == 0;
        let mut columns = Vec::new();
        let mut parts = Vec::new();
        if ipk {
            parts.push("id INTEGER PRIMARY KEY".to_owned());
        }
        for c in 0..(1 + rng.below(4)) {
            let ty = *rng.pick(&declared);
            let unique = if c == 0 && rng.below(3) == 0 {
                " UNIQUE"
            } else {
                ""
            };
            parts.push(format!("c{c} {ty}{unique}"));
            columns.push(format!("c{c}"));
        }
        if t > 0 && rng.below(2) == 0 {
            // A child cascade from table 0.
            parts.push(
                "parent INTEGER REFERENCES kernel_p0(id) ON DELETE CASCADE ON UPDATE CASCADE"
                    .into(),
            );
            columns.push("parent".into());
        }
        ddl.push(format!("CREATE TABLE {name}({})", parts.join(", ")));
        specs.push(Spec { name, ipk, columns });
    }
    // A trigger that writes another table from a delete.
    if specs.len() > 1 && rng.below(2) == 0 {
        let from = &specs[0];
        let into = &specs[1];
        if into.columns.len() == 1 {
            ddl.push(format!(
                "CREATE TRIGGER kernel_trg AFTER DELETE ON {} BEGIN INSERT INTO {}({}) VALUES (old.id); END",
                from.name, into.name, into.columns[0]
            ));
        }
    }
    (ddl, specs)
}

fn random_statements(rng: &mut Rng, specs: &[Spec], count: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut open = 0_usize;
    for _ in 0..count {
        let table = rng.pick(specs);
        let key = if table.ipk { "id" } else { "rowid" };
        let target = rng.below(8) + 1;
        let values = |rng: &mut Rng| {
            table
                .columns
                .iter()
                .map(|c| {
                    if c == "parent" {
                        format!("{}", rng.below(8) + 1)
                    } else {
                        literal(rng)
                    }
                })
                .collect::<Vec<_>>()
        };
        let cols = table.columns.join(",");
        let statement = match rng.below(17) {
            0 | 1 => {
                let verb = *rng.pick(&["INSERT", "INSERT OR REPLACE", "INSERT OR IGNORE"]);
                let id = if table.ipk {
                    format!("id,{cols}")
                } else {
                    cols.clone()
                };
                let vals = values(rng).join(",");
                let vals = if table.ipk {
                    format!("{target},{vals}")
                } else {
                    vals
                };
                format!("{verb} INTO {}({id}) VALUES ({vals})", table.name)
            }
            2 if table.ipk => {
                let column = rng.pick(&table.columns);
                format!(
                    "INSERT INTO {}(id,{cols}) VALUES ({target},{}) ON CONFLICT(id) DO UPDATE SET {column}=excluded.{column}",
                    table.name,
                    values(rng).join(",")
                )
            }
            3 | 4 => {
                let column = rng.pick(&table.columns);
                format!(
                    "UPDATE {} SET {column}={} WHERE {key}={target}",
                    table.name,
                    literal(rng)
                )
            }
            5 => format!(
                "UPDATE {} SET {key}={key}+{} WHERE {key}={target}",
                table.name,
                rng.below(5) + 1
            ),
            6 => format!(
                "UPDATE OR REPLACE {} SET {key}={} WHERE {key}={target}",
                table.name,
                rng.below(8) + 1
            ),
            7 | 8 => format!("DELETE FROM {} WHERE {key}={target}", table.name),
            9 => format!("DELETE FROM {} WHERE {key}>{target}", table.name),
            10 => {
                open += 1;
                format!("SAVEPOINT s{open}")
            }
            11 if open > 0 => format!("ROLLBACK TO s{open}"),
            12 if open > 0 => {
                open -= 1;
                format!("RELEASE s{}", open + 1)
            }
            // An unconditional DELETE (SQLite's truncate optimisation is off
            // while a preupdate hook is registered).
            13 if rng.below(3) == 0 => format!("DELETE FROM {}", table.name),
            // A multi-row INSERT that fails on its third row, after writing
            // the first two: genuine partial execution, undone by the
            // statement journal without any further hook call.
            14 if table.ipk => {
                let first = values(rng).join(",");
                let second = values(rng).join(",");
                let third = values(rng).join(",");
                format!(
                    "INSERT INTO {t}(id,{cols}) VALUES ({a},{first}),({b},{second}),({a},{third})",
                    t = table.name,
                    a = 100 + rng.below(3),
                    b = 110 + rng.below(3)
                )
            }
            // An UPDATE that fails partway through its rows.
            15 if table.ipk => format!("UPDATE {} SET id = {}", table.name, 1 + rng.below(3)),
            // A statement that fails before executing, then execution continues.
            _ => format!(
                "INSERT INTO {}({}) VALUES ('definitely', 'wrong')",
                table.name, "nope"
            ),
        };
        out.push(statement);
    }
    while open > 0 {
        out.push(format!("RELEASE s{open}"));
        open -= 1;
    }
    out
}

/// Run `transactions` hooked transactions of `statements`, each checked
/// against a full recompute, committing or rolling back at random.
async fn run_property(
    conn: &mut SqliteConnection,
    rng: &mut Rng,
    transactions: usize,
    mut statements: impl FnMut(&mut Rng) -> Vec<String>,
    label: &str,
) -> usize {
    let mut captured_tables = 0;
    for t in 0..transactions {
        let before = recompute(conn).await;
        conn.execute("BEGIN").await.unwrap();
        let mut hooked = Hooked::arm(conn).await.unwrap();
        for statement in statements(rng) {
            // Failures are part of the property: execution continues.
            let _ = (&mut *hooked).execute(statement.as_str()).await;
        }
        let outcome = hooked.finish().await.unwrap();
        let context = format!("{label} transaction {t}");
        match outcome {
            CaptureOutcome::Delta(deltas) => {
                captured_tables += deltas.len();
                let after = recompute(conn).await;
                assert_same(&applied(&before, &deltas), &after, &context);
            }
            CaptureOutcome::Anomaly(anomaly) => panic!("{context}: unexpected anomaly {anomaly:?}"),
        }
        conn.execute(if rng.below(3) == 0 {
            "ROLLBACK"
        } else {
            "COMMIT"
        })
        .await
        .unwrap();
    }
    captured_tables
}

#[tokio::test]
async fn property_random_schemas_base_times_delta_equals_a_full_recompute() {
    let mut total = 0;
    for seed in 1..=24_u64 {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15 ^ seed.wrapping_mul(0x1234_5678_9abc_def1));
        let (ddl, specs) = random_schema(&mut rng);
        let mut conn = SqliteConnection::connect("sqlite::memory:").await.unwrap();
        for statement in &ddl {
            conn.execute(statement.as_str()).await.unwrap();
        }
        total += run_property(
            &mut conn,
            &mut rng,
            20,
            |rng| {
                let count = 3 + rng.below(18) as usize;
                random_statements(rng, &specs, count)
            },
            &format!("seed {seed}"),
        )
        .await;
        conn.close().await.unwrap();
    }
    assert!(
        total > 200,
        "the generator must actually touch tables: {total}"
    );
}

#[tokio::test]
async fn integral_real_and_negative_zero_read_back_as_the_scan_reads_them() {
    let mut conn = SqliteConnection::connect("sqlite::memory:").await.unwrap();
    conn.execute("CREATE TABLE kernel_r(id INTEGER PRIMARY KEY, r REAL, f FLOAT, n NUMERIC, a)")
        .await
        .unwrap();
    conn.execute(
        "INSERT INTO kernel_r VALUES (1, 2.0, 3.0, 4.0, 5.0), (2, -0.0, -0.0, -0.0, -0.0)",
    )
    .await
    .unwrap();
    let mut rng = Rng(7);
    run_property(
        &mut conn,
        &mut rng,
        6,
        |_| {
            vec![
                "UPDATE kernel_r SET r=r+0 WHERE id=1".into(),
                "UPDATE kernel_r SET r=6.0 WHERE id=2".into(),
                "DELETE FROM kernel_r WHERE id=1".into(),
                "INSERT OR REPLACE INTO kernel_r VALUES (2, -0.0, 7.0, -0.0, 1e0)".into(),
                "UPDATE kernel_r SET id=9 WHERE id=2".into(),
            ]
        },
        "integral real",
    )
    .await;
}

/// The real kernel schema, and the FTS table, mutated at random: deletes with
/// cascades, REPLACEs of a row by itself, rowid moves, FTS duplicates and rowid
/// reuse.
#[tokio::test]
async fn property_real_kernel_schema_with_fts() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("kernel.db");
    let (db, admin) = crate::kernel::create_v2_database(
        path.to_str().unwrap(),
        "account",
        "Owner",
        "acct:capture",
    )
    .await
    .unwrap();
    for _ in 0..8 {
        crate::kernel::create_record_as(&db, &admin, crate::events::KERNEL_ROOT_ID)
            .await
            .unwrap();
    }
    let mut conn = db.write_pool().acquire().await.unwrap();
    // Table shapes, from the schema itself.
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT GLOB 'sqlite_*' ORDER BY name",
    )
    .fetch_all(&mut *conn)
    .await
    .unwrap()
    .into_iter()
    .filter(|name: &String| crate::kernel::projection_dump::included_in_projection(true, name))
    .filter(|name| name != "kernel_search_fts")
    .collect();
    let mut shapes = Vec::new();
    for name in &names {
        let columns: Vec<String> =
            sqlx::query_scalar(&format!("SELECT name FROM pragma_table_info('{name}')"))
                .fetch_all(&mut *conn)
                .await
                .unwrap();
        shapes.push((name.clone(), columns));
    }
    // A few records' FTS rows exist already (create_record_as indexes them).
    let mut rng = Rng(0xfeed_beef_cafe_f00d);
    let mut touched_real_tables = std::collections::BTreeSet::new();
    for seed in 0..10_u64 {
        let before = recompute(&mut conn).await;
        conn.execute("BEGIN").await.unwrap();
        let mut hooked = Hooked::arm(&mut *conn).await.unwrap();
        for _ in 0..(8 + rng.below(20)) {
            let (name, columns) = rng.pick(&shapes).clone();
            let list = columns.join(",");
            let one = format!("(SELECT rowid FROM {name} ORDER BY random() LIMIT 1)");
            let statement = match rng.below(14) {
                0 => format!("DELETE FROM {name} WHERE rowid={one}"),
                1 => format!("INSERT OR REPLACE INTO {name}({list}) SELECT {list} FROM {name} WHERE rowid={one}"),
                2 => format!("UPDATE OR REPLACE {name} SET rowid=rowid+{} WHERE rowid={one}", 1 + rng.below(3)),
                3 => format!("INSERT OR REPLACE INTO {name}(rowid,{list}) SELECT rowid+1000,{list} FROM {name} WHERE rowid={one}"),
                4 => "SAVEPOINT cap".to_owned(),
                5 => "ROLLBACK TO cap".to_owned(),
                6 => format!(
                    "INSERT INTO kernel_search_fts(rowid,record_id,title,summary,body) VALUES ({},'r{}','title {}','sum','body {}')",
                    1 + rng.below(12),
                    rng.below(4),
                    rng.below(3),
                    rng.below(3)
                ),
                7 => format!("DELETE FROM kernel_search_fts WHERE rowid={}", 1 + rng.below(12)),
                // FTS5 maintenance commands (some are refused for this table
                // kind; execution continues either way).
                9 => "INSERT INTO kernel_search_fts(kernel_search_fts) VALUES('optimize')".to_owned(),
                10 => "INSERT INTO kernel_search_fts(kernel_search_fts, rank) VALUES('merge', 2)".to_owned(),
                11 => format!(
                    "INSERT INTO kernel_search_fts(kernel_search_fts, rowid, record_id, title, summary, body) VALUES('delete', {}, 'r1', 'title 1', 'sum', 'body 1')",
                    1 + rng.below(12)
                ),
                12 => "INSERT INTO kernel_search_fts(kernel_search_fts) VALUES('rebuild')".to_owned(),
                13 => "DELETE FROM kernel_search_fts".to_owned(),
                _ => format!(
                    "UPDATE kernel_search_fts SET title='t{}', body=NULL WHERE rowid={}",
                    rng.below(3),
                    1 + rng.below(12)
                ),
            };
            let _ = (&mut *hooked).execute(statement.as_str()).await;
        }
        let _ = (&mut *hooked).execute("RELEASE cap").await;
        let outcome = hooked.finish().await.unwrap();
        match outcome {
            CaptureOutcome::Delta(deltas) => {
                for delta in &deltas {
                    touched_real_tables.insert(delta.name.clone());
                }
                let after = recompute(&mut conn).await;
                assert_same(
                    &applied(&before, &deltas),
                    &after,
                    &format!("kernel seed {seed}"),
                );
            }
            CaptureOutcome::Anomaly(anomaly) => panic!("kernel seed {seed}: anomaly {anomaly:?}"),
        }
        conn.execute(if seed % 3 == 0 { "ROLLBACK" } else { "COMMIT" })
            .await
            .unwrap();
    }
    assert!(
        touched_real_tables.contains("kernel_search_fts"),
        "{touched_real_tables:?}"
    );
    assert!(touched_real_tables.len() > 3, "{touched_real_tables:?}");
    drop(conn);
    db.close().await;
}

async fn outcome_of(conn: &mut SqliteConnection, statements: &[&str]) -> CaptureOutcome {
    conn.execute("BEGIN").await.unwrap();
    let mut hooked = Hooked::arm(conn).await.unwrap();
    for statement in statements {
        let _ = (&mut *hooked).execute(*statement).await;
    }
    let outcome = hooked.finish().await.unwrap();
    conn.execute("ROLLBACK").await.unwrap();
    outcome
}

async fn plain_connection() -> SqliteConnection {
    let mut conn = SqliteConnection::connect("sqlite::memory:").await.unwrap();
    conn.execute("CREATE TABLE kernel_a(id INTEGER PRIMARY KEY, v TEXT, b BLOB)")
        .await
        .unwrap();
    conn.execute("INSERT INTO kernel_a VALUES (1,'x',x'00'),(2,'y',x'01')")
        .await
        .unwrap();
    conn
}

#[tokio::test]
async fn temp_writes_are_allowlisted_and_anything_else_is_an_anomaly() {
    let mut conn = plain_connection().await;
    // The two projector TEMP tables are fine, with main writes beside them.
    let outcome = outcome_of(
        &mut conn,
        &[
            "CREATE TEMP TABLE IF NOT EXISTS _facet_time_refresh_targets(id TEXT PRIMARY KEY)",
            "INSERT INTO temp._facet_time_refresh_targets VALUES ('a')",
            "CREATE TEMP TABLE IF NOT EXISTS _facet_time_snapshots(record_id TEXT PRIMARY KEY, payload TEXT)",
            "INSERT INTO temp._facet_time_snapshots VALUES ('a','p')",
            "UPDATE kernel_a SET v='z' WHERE id=1",
        ],
    )
    .await;
    assert!(
        matches!(outcome, CaptureOutcome::Delta(ref d) if d.len() == 1),
        "{outcome:?}"
    );
    // An unknown TEMP table is not.
    let outcome = outcome_of(
        &mut conn,
        &[
            "CREATE TEMP TABLE _mystery(x)",
            "INSERT INTO temp._mystery VALUES (1)",
            "UPDATE kernel_a SET v='z' WHERE id=1",
        ],
    )
    .await;
    assert!(
        matches!(outcome, CaptureOutcome::Anomaly(Anomaly::NonAllowlistedTempWrite(ref t)) if t == "_mystery"),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn unknown_tables_other_schemas_and_without_rowid_are_anomalies() {
    let mut conn = plain_connection().await;
    conn.execute("CREATE TABLE kernel_w(k TEXT PRIMARY KEY, v) WITHOUT ROWID")
        .await
        .unwrap();
    // Created after the hook was armed: not in the catalog.
    let outcome = outcome_of(
        &mut conn,
        &[
            "CREATE TABLE kernel_late(x)",
            "INSERT INTO kernel_late VALUES (1)",
        ],
    )
    .await;
    assert!(
        matches!(outcome, CaptureOutcome::Anomaly(Anomaly::UnknownTable(ref t)) if t == "kernel_late"),
        "{outcome:?}"
    );
    let outcome = outcome_of(
        &mut conn,
        &[
            "ATTACH DATABASE ':memory:' AS aux",
            "CREATE TABLE aux.kernel_a(x)",
            "INSERT INTO aux.kernel_a VALUES (1)",
        ],
    )
    .await;
    assert!(
        matches!(outcome, CaptureOutcome::Anomaly(Anomaly::OtherSchema(ref s)) if s == "aux"),
        "{outcome:?}"
    );
    conn.execute("DETACH DATABASE aux").await.ok();
    let outcome = outcome_of(&mut conn, &["INSERT INTO kernel_w VALUES ('a', 1)"]).await;
    assert!(
        matches!(outcome, CaptureOutcome::Anomaly(Anomaly::WithoutRowid(ref t)) if t == "kernel_w"),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn an_incremental_blob_write_is_an_anomaly() {
    let mut conn = plain_connection().await;
    conn.execute("INSERT INTO kernel_a VALUES (7,'blob',zeroblob(16))")
        .await
        .unwrap();
    conn.execute("BEGIN").await.unwrap();
    let hooked = Hooked::arm(&mut conn).await.unwrap();
    {
        let mut hooked = hooked;
        let mut handle = hooked.lock_handle().await.unwrap();
        let db = handle.as_raw_handle().as_ptr();
        let mut blob = std::ptr::null_mut();
        // SAFETY: documented SQLite blob I/O on this connection's own handle.
        unsafe {
            let (main, table, column) = (c"main", c"kernel_a", c"b");
            assert_eq!(
                libsqlite3_sys::sqlite3_blob_open(
                    db,
                    main.as_ptr(),
                    table.as_ptr(),
                    column.as_ptr(),
                    7,
                    1,
                    &mut blob
                ),
                libsqlite3_sys::SQLITE_OK
            );
            assert_eq!(
                libsqlite3_sys::sqlite3_blob_write(blob, b"abcd".as_ptr().cast(), 4, 0),
                libsqlite3_sys::SQLITE_OK
            );
            libsqlite3_sys::sqlite3_blob_close(blob);
        }
        drop(handle);
        let outcome = hooked.finish().await.unwrap();
        assert!(
            matches!(outcome, CaptureOutcome::Anomaly(Anomaly::BlobWrite)),
            "{outcome:?}"
        );
    }
    conn.execute("ROLLBACK").await.unwrap();
}

#[tokio::test]
async fn limits_are_anomalies() {
    let mut conn = plain_connection().await;
    conn.execute("BEGIN").await.unwrap();
    let mut hooked = Hooked::arm(&mut conn).await.unwrap();
    // MAX_TOUCHES + 1 distinct rows in one statement.
    (&mut *hooked)
        .execute(
            format!(
                "WITH RECURSIVE n(i) AS (SELECT 100 UNION ALL SELECT i+1 FROM n WHERE i < {}) INSERT INTO kernel_a(id,v) SELECT i,'x' FROM n",
                100 + MAX_TOUCHES
            )
            .as_str(),
        )
        .await
        .unwrap();
    let outcome = hooked.finish().await.unwrap();
    assert!(
        matches!(outcome, CaptureOutcome::Anomaly(Anomaly::TooManyTouches)),
        "{outcome:?}"
    );
    conn.execute("ROLLBACK").await.unwrap();

    // 70 MiB of base images (70 rows of 1 MiB blobs updated).
    conn.execute("BEGIN").await.unwrap();
    for id in 1000..1070 {
        sqlx::query("INSERT INTO kernel_a VALUES (?, 'big', zeroblob(1048576))")
            .bind(id)
            .execute(&mut conn)
            .await
            .unwrap();
    }
    conn.execute("COMMIT").await.unwrap();
    let outcome = outcome_of(
        &mut conn,
        &["UPDATE kernel_a SET v='changed' WHERE id>=1000"],
    )
    .await;
    assert!(
        matches!(
            outcome,
            CaptureOutcome::Anomaly(Anomaly::BaseImagesTooLarge)
        ),
        "{outcome:?}"
    );
}

/// What this proves, and no more: the hook is per-connection, so a commit
/// made by another connection while this one is armed is neither logged nor
/// visible in this connection's snapshot. It does not prove behaviour under
/// concurrent writers (SQLite allows one at a time; the apply path holds the
/// single writer).
#[tokio::test]
async fn hook_logs_only_its_own_connections_writes_and_snapshot_isolation_holds() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("two.db");
    let url = format!("sqlite:{}?mode=rwc", path.display());
    let mut one = SqliteConnection::connect(&url).await.unwrap();
    one.execute("PRAGMA journal_mode=WAL").await.unwrap();
    one.execute("CREATE TABLE kernel_a(id INTEGER PRIMARY KEY, v TEXT)")
        .await
        .unwrap();
    one.execute("CREATE TABLE kernel_b(id INTEGER PRIMARY KEY, v TEXT)")
        .await
        .unwrap();
    let mut two = SqliteConnection::connect(&url).await.unwrap();
    one.execute("BEGIN").await.unwrap();
    let mut hooked = Hooked::arm(&mut one).await.unwrap();
    // The other connection commits before this one has written anything.
    two.execute("INSERT INTO kernel_b VALUES (1,'other')")
        .await
        .unwrap();
    // This connection only reads while armed (its snapshot would go stale
    // if it wrote after the other's commit).
    let seen: i64 = sqlx::query_scalar("SELECT count(*) FROM kernel_b")
        .fetch_one(&mut *hooked)
        .await
        .unwrap();
    assert_eq!(seen, 0, "snapshot isolation");
    two.execute("INSERT INTO kernel_a VALUES (2,'other again')")
        .await
        .unwrap();
    let CaptureOutcome::Delta(deltas) = hooked.finish().await.unwrap() else {
        panic!("anomaly")
    };
    assert!(
        deltas.is_empty(),
        "the other connection's writes are invisible to the hook: {deltas:?}"
    );
    one.execute("ROLLBACK").await.unwrap();
}

/// After SQLite is told to unregister, a second call returns the previous user
/// data pointer: null means nothing was registered.
async fn hook_registered(conn: &mut SqliteConnection) -> bool {
    let mut handle = conn.lock_handle().await.unwrap();
    let db = handle.as_raw_handle().as_ptr();
    // SAFETY: unregistering with a null callback is always valid.
    let previous =
        unsafe { libsqlite3_sys::sqlite3_preupdate_hook(db, None, std::ptr::null_mut()) };
    !previous.is_null()
}

#[tokio::test]
async fn a_cancelled_future_leaves_no_armed_hook() {
    let mut conn = plain_connection().await;
    conn.execute("BEGIN").await.unwrap();
    let cancelled = tokio::time::timeout(std::time::Duration::from_millis(50), async {
        let mut hooked = Hooked::arm(&mut conn).await.unwrap();
        (&mut *hooked)
            .execute("UPDATE kernel_a SET v='held' WHERE id=1")
            .await
            .unwrap();
        // Never finishes: the timeout drops this future with the hook armed.
        std::future::pending::<()>().await;
    })
    .await;
    assert!(cancelled.is_err());
    assert!(
        !hook_registered(&mut conn).await,
        "hook survived cancellation"
    );
    conn.execute("ROLLBACK").await.unwrap();
    // An error path drops it too.
    conn.execute("BEGIN").await.unwrap();
    {
        let mut hooked = Hooked::arm(&mut conn).await.unwrap();
        let failed = (&mut *hooked)
            .execute("INSERT INTO nowhere VALUES (1)")
            .await;
        assert!(failed.is_err());
    }
    assert!(
        !hook_registered(&mut conn).await,
        "hook survived an error path"
    );
    conn.execute("ROLLBACK").await.unwrap();
    // And arming outside a transaction is refused.
    assert!(Hooked::arm(&mut conn).await.is_err());
}

/// The real projectors: ingest a hosted delta's rows and fold them with
/// `replay_projection_tail_on` on a hooked transaction, exactly the standby
/// apply's work; the captured delta must reproduce the full recompute.
/// Hosted moves on from a local copy by `events` creations (titled ones feed
/// the search index); the delta is applied to the local copy in a hooked
/// transaction through the real ingest + projector path, and the captured
/// delta must reproduce the full recompute. Returns the delta's table names
/// and the number of rows touched.
async fn real_projector_case(titled: bool, events: usize) -> (Vec<String>, usize, usize) {
    use crate::interchange::ConflictMode;
    use serde_json::json;
    let dir = tempfile::tempdir().unwrap();
    let hosted_path = dir.path().join("hosted.db");
    let (hosted, admin) = crate::kernel::create_v2_database(
        hosted_path.to_str().unwrap(),
        "account",
        "Owner",
        "acct:capture",
    )
    .await
    .unwrap();
    for _ in 0..3 {
        crate::kernel::create_record_as(&hosted, &admin, crate::events::KERNEL_ROOT_ID)
            .await
            .unwrap();
    }
    let definition = br#"{"family":"test.capture","version":1,"interpreter":"native.defn/4","primary_type":"Fixture","kinds":[{"token":"note","fields":[{"name":"title","type":"text","required":false}],"identity":{"mode":"record"},"links":[],"maturity":"current","description":"Fixture."}]}"#;
    let revision =
        crate::kernel::install_definition_as(&hosted, &admin, "test.capture", 1, definition)
            .await
            .unwrap();
    crate::kernel::adopt_definition_as(&hosted, &admin, "test.capture", Some(&revision))
        .await
        .unwrap();
    // The local copy at this point.
    let local_path = dir.path().join("local.db");
    {
        let mut conn = hosted.write_pool().acquire().await.unwrap();
        sqlx::query("VACUUM INTO ?")
            .bind(local_path.to_string_lossy().as_ref())
            .execute(&mut *conn)
            .await
            .unwrap();
    }
    let local_head = {
        let mut conn = SqliteConnection::connect(&format!("sqlite:{}", local_path.display()))
            .await
            .unwrap();
        let head = crate::standby::kernel_v2::coordinates(&mut conn)
            .await
            .unwrap();
        conn.close().await.unwrap();
        head
    };
    // Hosted moves on.
    for i in 0..events {
        if titled {
            crate::kernel::create_as(
                &hosted,
                &admin,
                "test.capture",
                "note",
                json!({"title": format!("Captured search text {i}")})
                    .as_object()
                    .unwrap(),
                crate::events::KERNEL_ROOT_ID,
            )
            .await
            .unwrap();
        } else {
            crate::kernel::create_record_as(&hosted, &admin, crate::events::KERNEL_ROOT_ID)
                .await
                .unwrap();
        }
    }
    let delta = {
        let mut conn = hosted.pool().acquire().await.unwrap();
        crate::standby::kernel_v2_delta::cut_versioned(&mut conn, local_head.head_act, &[], 1)
            .await
            .unwrap()
    };
    let mut conn = SqliteConnection::connect(&format!("sqlite:{}", local_path.display()))
        .await
        .unwrap();
    let before = recompute(&mut conn).await;
    let mut tx = conn.begin().await.unwrap();
    let mut hooked = Hooked::arm(&mut tx).await.unwrap();
    for section in &delta.sections {
        crate::interchange::ingest_section_rows(
            &mut hooked,
            section,
            if ["kernel_blobs", "content_event_causal_frontier"].contains(&section.name.as_str()) {
                ConflictMode::ImmutableAllowIdentical
            } else {
                ConflictMode::ActLogRefuseExisting
            },
        )
        .await
        .unwrap();
    }
    sqlx::query("UPDATE act_state SET next_act=? WHERE singleton=1")
        .bind(delta.head.head_act)
        .execute(&mut **hooked)
        .await
        .unwrap();
    crate::kernel::replay_projection_tail_on(
        &mut hooked,
        local_head.content_event_seq,
        local_head.meta_event_seq,
    )
    .await
    .unwrap();
    let touches = hooked.touched_len();
    let base_rows = hooked.base_rows_len();
    let CaptureOutcome::Delta(deltas) = hooked.finish().await.unwrap() else {
        panic!("the real fold is expected to be capturable");
    };
    let after = recompute(&mut tx).await;
    assert_same(&applied(&before, &deltas), &after, "real projectors");
    let names = deltas.iter().map(|d| d.name.clone()).collect();
    tx.rollback().await.unwrap();
    conn.close().await.unwrap();
    hosted.close().await;
    (names, touches, base_rows)
}

#[tokio::test]
async fn real_projectors_through_a_hooked_apply() {
    let (names, _, _) = real_projector_case(false, 4).await;
    assert!(names.contains(&"kernel_records".to_owned()), "{names:?}");
}

/// Titled records feed the search index: the FTS table must appear in the
/// captured delta, and the delta must still equal the full recompute.
#[tokio::test]
async fn real_projectors_with_search_index_changes() {
    let (names, _, _) = real_projector_case(true, 4).await;
    assert!(names.contains(&"kernel_search_fts".to_owned()), "{names:?}");
    assert!(names.contains(&"kernel_records".to_owned()), "{names:?}");
}

/// The facet-time refresh (TEMP tables, allowlisted) and a canvas dry fold
/// (SAVEPOINT / ROLLBACK TO around real canvas projectors, REAL columns).
#[tokio::test]
async fn facet_time_refresh_and_a_canvas_dry_fold() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("kernel.db");
    let (db, admin) = crate::kernel::create_v2_database(
        path.to_str().unwrap(),
        "account",
        "Owner",
        "acct:capture",
    )
    .await
    .unwrap();
    for _ in 0..3 {
        crate::kernel::create_record_as(&db, &admin, crate::events::KERNEL_ROOT_ID)
            .await
            .unwrap();
    }
    let mut conn = db.write_pool().acquire().await.unwrap();
    // 1. Facet-time refresh.
    let before = recompute(&mut conn).await;
    conn.execute("BEGIN").await.unwrap();
    let mut hooked = Hooked::arm(&mut *conn).await.unwrap();
    crate::kernel::facet_time_reads::prepare_on(&mut hooked)
        .await
        .unwrap();
    let outcome = hooked.finish().await.unwrap();
    match outcome {
        CaptureOutcome::Delta(deltas) => {
            let after = recompute(&mut conn).await;
            assert_same(&applied(&before, &deltas), &after, "facet time");
        }
        CaptureOutcome::Anomaly(anomaly) => panic!("facet time: {anomaly:?}"),
    }
    conn.execute("ROLLBACK").await.unwrap();
    // 2. Canvas dry fold: creates inside a savepoint, rolls the savepoint back.
    let envelope: crate::canvas::BatchEnvelope = serde_json::from_value(serde_json::json!({
        "version": crate::canvas::BATCH_VERSION,
        "canvas_id": "c1",
        "batch_id": "b1",
        "origin": { "kind": "gesture" },
        "ops": [
            { "op": "create", "object": { "id": "n1", "kind": "note", "x": 10.0, "y": 20.0, "w": 200.0, "h": 120.0, "z": "a0", "parent": null, "props": { "text": "hi" } } }
        ],
    }))
    .unwrap();
    let before = recompute(&mut conn).await;
    conn.execute("BEGIN").await.unwrap();
    let mut hooked = Hooked::arm(&mut *conn).await.unwrap();
    let prepared = crate::kernel::canvas_v2::prepare_batch(&mut hooked, &envelope, 1).await;
    assert!(prepared.is_ok());
    let outcome = hooked.finish().await.unwrap();
    match outcome {
        CaptureOutcome::Delta(mut deltas) => {
            // Exact outcome: a delta, not an anomaly. The dry fold writes
            // inside a savepoint and rolls it back, so every touched row nets
            // out: the table is listed (its rows were touched) with a zero row
            // delta and an identity MuHash, and the sets are unchanged.
            let after = recompute(&mut conn).await;
            assert_same(&applied(&before, &deltas), &after, "canvas dry fold");
            assert_same(&before, &after, "a dry fold changes nothing");
            assert_eq!(
                deltas.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(),
                ["canvas_objects"]
            );
            assert_eq!(deltas[0].row_delta, 0);
            assert_eq!(
                deltas[0].delta.normalise(),
                MuHash::new().normalise(),
                "identity delta"
            );
        }
        CaptureOutcome::Anomaly(anomaly) => panic!("canvas dry fold: {anomaly:?}"),
    }
    conn.execute("ROLLBACK").await.unwrap();
    drop(conn);
    db.close().await;
}

#[tokio::test]
async fn a_changed_fts_definition_is_an_anomaly() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("kernel.db");
    let (db, _admin) = crate::kernel::create_v2_database(
        path.to_str().unwrap(),
        "account",
        "Owner",
        "acct:capture",
    )
    .await
    .unwrap();
    let mut conn = db.write_pool().acquire().await.unwrap();
    // The pinned definition arms cleanly.
    conn.execute("BEGIN").await.unwrap();
    let hooked = Hooked::arm(&mut *conn).await.unwrap();
    assert!(matches!(
        hooked.finish().await.unwrap(),
        CaptureOutcome::Delta(_)
    ));
    conn.execute("ROLLBACK").await.unwrap();
    conn.execute("DROP TABLE kernel_search_fts").await.unwrap();
    conn.execute(
        "CREATE VIRTUAL TABLE kernel_search_fts USING fts5(record_id UNINDEXED, title, summary, body, tokenize='ascii')",
    )
    .await
    .unwrap();
    conn.execute("BEGIN").await.unwrap();
    let hooked = Hooked::arm(&mut *conn).await.unwrap();
    assert!(matches!(
        hooked.finish().await.unwrap(),
        CaptureOutcome::Anomaly(Anomaly::FtsDdlMismatch)
    ));
    conn.execute("ROLLBACK").await.unwrap();
    drop(conn);
    db.close().await;
}

/// Measurement, not a regression test (gate G3 and the hook's cost per row).
///
/// ```text
/// cargo test --release --lib measure_capture_costs -- --ignored --nocapture
/// ```
#[tokio::test]
#[ignore = "measurement harness for gate G3 and ns per hooked row"]
async fn measure_capture_costs() {
    // The touch count a 256-event delta really has on the synthetic base.
    let (names, realistic, base_rows) = real_projector_case(true, 256).await;
    println!("MEASURE 256-event delta touches={realistic} old_images={base_rows} tables={names:?}");
    for rows in [realistic, MAX_TOUCHES] {
        measure_at(rows as i64).await;
    }
}

async fn measure_at(rows: i64) {
    let mut conn = SqliteConnection::connect("sqlite::memory:").await.unwrap();
    conn.execute("CREATE TABLE kernel_m(id INTEGER PRIMARY KEY, a TEXT, b REAL, c BLOB)")
        .await
        .unwrap();
    conn.execute(
        format!(
            "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < {rows}) INSERT INTO kernel_m SELECT i, 'row ' || i, i * 1.5, zeroblob(32) FROM n"
        )
        .as_str(),
    )
    .await
    .unwrap();
    // ns per hooked row: the same UPDATE of every row, bare and hooked.
    let started = std::time::Instant::now();
    conn.execute("BEGIN").await.unwrap();
    conn.execute("UPDATE kernel_m SET a = a || '!'")
        .await
        .unwrap();
    let bare = started.elapsed();
    conn.execute("ROLLBACK").await.unwrap();
    conn.execute("BEGIN").await.unwrap();
    let mut hooked = Hooked::arm(&mut conn).await.unwrap();
    let started = std::time::Instant::now();
    (&mut *hooked)
        .execute("UPDATE kernel_m SET a = a || '!'")
        .await
        .unwrap();
    let with_hook = started.elapsed();
    // G3: read-back with every one of the rows genuinely changed.
    let started = std::time::Instant::now();
    let outcome = hooked.finish().await.unwrap();
    let readback = started.elapsed();
    conn.execute("ROLLBACK").await.unwrap();
    let CaptureOutcome::Delta(deltas) = outcome else {
        panic!("unexpected anomaly")
    };
    println!(
        "MEASURE touches={} bare_update_ms={} hooked_update_ms={} hook_ns_per_row={} G3_readback_ms={} row_delta={}",
        rows,
        bare.as_millis(),
        with_hook.as_millis(),
        (with_hook.as_nanos() as i64 - bare.as_nanos() as i64) / rows.max(1),
        readback.as_millis(),
        deltas[0].row_delta
    );
}

/// The exact reproduction from review: a column added by ALTER TABLE after a
/// row was written. `sqlite3_preupdate_old` reports NULL for it where
/// `SELECT *` yields the default, and SQLite exposes no stored field count, so
/// the capture must refuse rather than compute a wrong delta.
#[tokio::test]
async fn alter_added_default_column_on_an_old_row_is_an_anomaly() {
    let mut conn = SqliteConnection::connect("sqlite::memory:").await.unwrap();
    conn.execute("CREATE TABLE kernel_s(id INTEGER PRIMARY KEY, a TEXT)")
        .await
        .unwrap();
    conn.execute("INSERT INTO kernel_s VALUES (1, 'old'), (2, 'old')")
        .await
        .unwrap();
    conn.execute("ALTER TABLE kernel_s ADD COLUMN n NUMERIC DEFAULT '42'")
        .await
        .unwrap();
    // The premise: the scan sees the default.
    let seen: i64 = sqlx::query_scalar("SELECT n FROM kernel_s WHERE id = 1")
        .fetch_one(&mut conn)
        .await
        .unwrap();
    assert_eq!(seen, 42);
    let outcome = outcome_of(&mut conn, &["UPDATE kernel_s SET a = 'new' WHERE id = 1"]).await;
    assert!(
        matches!(outcome, CaptureOutcome::Anomaly(Anomaly::ShortRecordDefault(ref t)) if t == "kernel_s"),
        "{outcome:?}"
    );
    // A DELETE is the same.
    let outcome = outcome_of(&mut conn, &["DELETE FROM kernel_s WHERE id = 2"]).await;
    assert!(
        matches!(
            outcome,
            CaptureOutcome::Anomaly(Anomaly::ShortRecordDefault(_))
        ),
        "{outcome:?}"
    );
}

/// The conservative rule does not fire when the record provably reaches the
/// defaulted column, so common cases stay captured and exact.
#[tokio::test]
async fn short_record_rule_is_quiet_when_the_record_provably_covers_the_column() {
    let mut conn = SqliteConnection::connect("sqlite::memory:").await.unwrap();
    conn.execute("CREATE TABLE kernel_s(id INTEGER PRIMARY KEY, a TEXT)")
        .await
        .unwrap();
    conn.execute("INSERT INTO kernel_s VALUES (1, 'old')")
        .await
        .unwrap();
    conn.execute("ALTER TABLE kernel_s ADD COLUMN n NUMERIC DEFAULT '42'")
        .await
        .unwrap();
    conn.execute("ALTER TABLE kernel_s ADD COLUMN m TEXT")
        .await
        .unwrap();
    // Written after the ALTER: the record includes n (= 42) and m.
    conn.execute("INSERT INTO kernel_s(id, a) VALUES (2, 'new')")
        .await
        .unwrap();
    // An explicit NULL in a defaulted column with a later non-NULL value.
    conn.execute("INSERT INTO kernel_s(id, a, n, m) VALUES (3, 'x', NULL, 'later')")
        .await
        .unwrap();
    let before = recompute(&mut conn).await;
    conn.execute("BEGIN").await.unwrap();
    let mut hooked = Hooked::arm(&mut conn).await.unwrap();
    (&mut *hooked)
        .execute("UPDATE kernel_s SET a = 'changed' WHERE id IN (2, 3)")
        .await
        .unwrap();
    let CaptureOutcome::Delta(deltas) = hooked.finish().await.unwrap() else {
        panic!("anomaly")
    };
    let after = recompute(&mut conn).await;
    assert_same(&applied(&before, &deltas), &after, "covered columns");
    conn.execute("ROLLBACK").await.unwrap();
}

/// A TEMP table named like the old scratch table, with a trigger that writes
/// projection rows. Read-back must not touch it: it owns no scratch table and
/// only SELECTs, so no trigger fires and the delta stays exact.
#[tokio::test]
async fn read_back_fires_no_triggers_even_on_a_preexisting_scratch_name() {
    let mut conn = plain_connection().await;
    conn.execute("CREATE TEMP TABLE _capture_keys(k INTEGER PRIMARY KEY)")
        .await
        .unwrap();
    for event in ["INSERT", "DELETE"] {
        conn.execute(
            format!(
                "CREATE TEMP TRIGGER trap_{event} AFTER {event} ON _capture_keys BEGIN UPDATE kernel_a SET v = 'TRAP'; END"
            )
            .as_str(),
        )
        .await
        .unwrap();
    }
    let before = recompute(&mut conn).await;
    conn.execute("BEGIN").await.unwrap();
    let mut hooked = Hooked::arm(&mut conn).await.unwrap();
    (&mut *hooked)
        .execute("UPDATE kernel_a SET v = 'mine' WHERE id = 1")
        .await
        .unwrap();
    let CaptureOutcome::Delta(deltas) = hooked.finish().await.unwrap() else {
        panic!("anomaly")
    };
    let after = recompute(&mut conn).await;
    assert_same(&applied(&before, &deltas), &after, "no trigger fired");
    let trapped: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM kernel_a WHERE v = 'TRAP'")
        .fetch_one(&mut conn)
        .await
        .unwrap();
    assert_eq!(trapped, 0, "a trigger fired during read-back");
    conn.execute("ROLLBACK").await.unwrap();
}

#[tokio::test]
async fn schema_changes_while_armed_are_anomalies() {
    let mut conn = plain_connection().await;
    for (label, statements) in [
        (
            "alter add column",
            vec!["ALTER TABLE kernel_a ADD COLUMN z TEXT DEFAULT 'q'"],
        ),
        ("create table", vec!["CREATE TABLE kernel_fresh(x)"]),
        (
            "create index",
            vec!["CREATE INDEX kernel_a_v ON kernel_a(v)"],
        ),
        (
            "temp trigger",
            vec!["CREATE TEMP TRIGGER t1 AFTER INSERT ON main.kernel_a BEGIN SELECT 1; END"],
        ),
    ] {
        let outcome = outcome_of(&mut conn, &statements).await;
        assert!(
            matches!(outcome, CaptureOutcome::Anomaly(Anomaly::SchemaChanged)),
            "{label}: {outcome:?}"
        );
    }
    // The allowlisted projector TEMP tables are not a schema change.
    let outcome = outcome_of(
        &mut conn,
        &[
            "CREATE TEMP TABLE IF NOT EXISTS _facet_time_snapshots(record_id TEXT PRIMARY KEY, payload TEXT)",
        ],
    )
    .await;
    assert!(matches!(outcome, CaptureOutcome::Delta(_)), "{outcome:?}");
}

/// A NOT NULL column that reads NULL can only be absent from a short record,
/// so the declared default (with the column's affinity) is substituted
/// exactly, and so are the defaulted columns after it.
#[tokio::test]
async fn not_null_alter_added_defaults_are_substituted_exactly() {
    let mut conn = SqliteConnection::connect("sqlite::memory:").await.unwrap();
    conn.execute("CREATE TABLE kernel_nn(id INTEGER PRIMARY KEY, a TEXT)")
        .await
        .unwrap();
    conn.execute("INSERT INTO kernel_nn VALUES (1,'old'),(2,'old'),(3,'old')")
        .await
        .unwrap();
    for column in [
        "n INTEGER NOT NULL DEFAULT 7",
        "m INTEGER NOT NULL DEFAULT -3",
        "q NUMERIC NOT NULL DEFAULT 42",
        "t TEXT NOT NULL DEFAULT 'x''y'",
        // Nullable but after the proving column: absent too, so exact.
        "z TEXT DEFAULT 'later'",
        "y",
    ] {
        conn.execute(format!("ALTER TABLE kernel_nn ADD COLUMN {column}").as_str())
            .await
            .unwrap();
    }
    // One row written after the ALTERs has a full record.
    conn.execute(
        "INSERT INTO kernel_nn(id, a, n, m, q, t, z, y) VALUES (4,'new',1,1,1,'t',NULL,'y')",
    )
    .await
    .unwrap();
    let before = recompute(&mut conn).await;
    conn.execute("BEGIN").await.unwrap();
    let mut hooked = Hooked::arm(&mut conn).await.unwrap();
    for statement in [
        "UPDATE kernel_nn SET a = 'changed' WHERE id = 1",
        "DELETE FROM kernel_nn WHERE id = 2",
        "UPDATE kernel_nn SET a = 'changed' WHERE id = 4",
        "UPDATE kernel_nn SET id = 30 WHERE id = 3",
    ] {
        (&mut *hooked).execute(statement).await.unwrap();
    }
    let CaptureOutcome::Delta(deltas) = hooked.finish().await.unwrap() else {
        panic!("exact substitution expected, not an anomaly")
    };
    let after = recompute(&mut conn).await;
    assert_same(&applied(&before, &deltas), &after, "NOT NULL defaults");
    conn.execute("ROLLBACK").await.unwrap();
}

/// A nullable defaulted column before the proving NOT NULL column stays
/// ambiguous, and a default that is not a plain literal is never evaluated.
#[tokio::test]
async fn ambiguous_or_unevaluable_defaults_stay_anomalies() {
    let mut conn = SqliteConnection::connect("sqlite::memory:").await.unwrap();
    conn.execute("CREATE TABLE kernel_amb(id INTEGER PRIMARY KEY, a TEXT)")
        .await
        .unwrap();
    conn.execute("INSERT INTO kernel_amb VALUES (1,'old')")
        .await
        .unwrap();
    conn.execute("ALTER TABLE kernel_amb ADD COLUMN x TEXT DEFAULT 'maybe'")
        .await
        .unwrap();
    conn.execute("ALTER TABLE kernel_amb ADD COLUMN y INTEGER NOT NULL DEFAULT 1")
        .await
        .unwrap();
    let outcome = outcome_of(&mut conn, &["UPDATE kernel_amb SET a = 'new' WHERE id = 1"]).await;
    assert!(
        matches!(
            outcome,
            CaptureOutcome::Anomaly(Anomaly::ShortRecordDefault(_))
        ),
        "{outcome:?}"
    );

    conn.execute("CREATE TABLE kernel_expr(id INTEGER PRIMARY KEY, a TEXT)")
        .await
        .unwrap();
    conn.execute("INSERT INTO kernel_expr VALUES (1,'old')")
        .await
        .unwrap();
    conn.execute("ALTER TABLE kernel_expr ADD COLUMN e INTEGER NOT NULL DEFAULT TRUE")
        .await
        .unwrap();
    let outcome = outcome_of(
        &mut conn,
        &["UPDATE kernel_expr SET a = 'new' WHERE id = 1"],
    )
    .await;
    assert!(
        matches!(
            outcome,
            CaptureOutcome::Anomaly(Anomaly::ShortRecordDefault(_))
        ),
        "{outcome:?}"
    );
}

/// The whitelist is the only substitution: everything else is an anomaly, and
/// the premise is checked against SQLite itself (`1e2` in a TEXT column reads
/// back as the text it was written as, which a probe would have got wrong).
#[tokio::test]
async fn only_provably_identical_defaults_are_substituted() {
    let mut conn = SqliteConnection::connect("sqlite::memory:").await.unwrap();
    for (n, column) in [
        "v TEXT NOT NULL DEFAULT 1e2",
        "v REAL NOT NULL DEFAULT 3",
        "v NUMERIC NOT NULL DEFAULT '42'",
        "v BLOB NOT NULL DEFAULT x'00ff'",
        "v INTEGER NOT NULL DEFAULT 1.5",
        "v TEXT NOT NULL DEFAULT 5",
        "v NUMERIC NOT NULL DEFAULT 1e2",
        "v INTEGER NOT NULL DEFAULT 99999999999999999999",
    ]
    .into_iter()
    .enumerate()
    {
        let table = format!("kernel_wl{n}");
        conn.execute(format!("CREATE TABLE {table}(id INTEGER PRIMARY KEY, a TEXT)").as_str())
            .await
            .unwrap();
        conn.execute(format!("INSERT INTO {table} VALUES (1, 'old')").as_str())
            .await
            .unwrap();
        conn.execute(format!("ALTER TABLE {table} ADD COLUMN {column}").as_str())
            .await
            .unwrap();
        if n == 0 {
            let seen: String = sqlx::query_scalar(&format!("SELECT v FROM {table}"))
                .fetch_one(&mut conn)
                .await
                .unwrap();
            assert_eq!(seen, "1e2", "the scan keeps the literal's own text");
        }
        let outcome = outcome_of(
            &mut conn,
            &[format!("UPDATE {table} SET a = 'new' WHERE id = 1").as_str()],
        )
        .await;
        assert!(
            matches!(
                outcome,
                CaptureOutcome::Anomaly(Anomaly::ShortRecordDefault(_))
            ),
            "{column}: {outcome:?}"
        );
    }
    // STRICT tables are never substituted, even for a whitelisted literal.
    conn.execute("CREATE TABLE kernel_strict(id INTEGER PRIMARY KEY, a TEXT) STRICT")
        .await
        .unwrap();
    conn.execute("INSERT INTO kernel_strict VALUES (1, 'old')")
        .await
        .unwrap();
    conn.execute("ALTER TABLE kernel_strict ADD COLUMN v INTEGER NOT NULL DEFAULT 7")
        .await
        .unwrap();
    let outcome = outcome_of(
        &mut conn,
        &["UPDATE kernel_strict SET a = 'new' WHERE id = 1"],
    )
    .await;
    assert!(
        matches!(
            outcome,
            CaptureOutcome::Anomaly(Anomaly::ShortRecordDefault(_))
        ),
        "{outcome:?}"
    );
}

/// A table dropped and recreated with identical DDL leaves the digest alone;
/// `schema_version` still moves.
#[tokio::test]
async fn drop_and_recreate_with_identical_ddl_is_an_anomaly() {
    let mut conn = plain_connection().await;
    let outcome = outcome_of(
        &mut conn,
        &[
            "DROP TABLE kernel_a",
            "CREATE TABLE kernel_a(id INTEGER PRIMARY KEY, v TEXT, b BLOB)",
        ],
    )
    .await;
    assert!(
        matches!(outcome, CaptureOutcome::Anomaly(Anomaly::SchemaChanged)),
        "{outcome:?}"
    );
    // The same for an allowlisted TEMP table that already existed.
    conn.execute(
        "CREATE TEMP TABLE _facet_time_snapshots(record_id TEXT PRIMARY KEY, payload TEXT)",
    )
    .await
    .unwrap();
    let outcome = outcome_of(
        &mut conn,
        &[
            "DROP TABLE temp._facet_time_snapshots",
            "CREATE TEMP TABLE _facet_time_snapshots(record_id TEXT PRIMARY KEY, payload TEXT)",
        ],
    )
    .await;
    assert!(
        matches!(outcome, CaptureOutcome::Anomaly(Anomaly::SchemaChanged)),
        "{outcome:?}"
    );
}

/// A declared column named `rowid` shadows the real one; read-back uses the
/// first alias that is not shadowed, and gives up when all three are.
#[tokio::test]
async fn declared_rowid_columns_are_handled() {
    let mut conn = SqliteConnection::connect("sqlite::memory:").await.unwrap();
    conn.execute("CREATE TABLE kernel_rs(id INTEGER PRIMARY KEY, rowid TEXT, v TEXT)")
        .await
        .unwrap();
    conn.execute("INSERT INTO kernel_rs VALUES (1,'a','x'),(2,'b','y'),(3,'c','z')")
        .await
        .unwrap();
    let before = recompute(&mut conn).await;
    conn.execute("BEGIN").await.unwrap();
    let mut hooked = Hooked::arm(&mut conn).await.unwrap();
    for statement in [
        "UPDATE kernel_rs SET v = 'changed' WHERE id = 2",
        "DELETE FROM kernel_rs WHERE id = 3",
        "INSERT INTO kernel_rs VALUES (9, 'new', 'n')",
    ] {
        (&mut *hooked).execute(statement).await.unwrap();
    }
    let CaptureOutcome::Delta(deltas) = hooked.finish().await.unwrap() else {
        panic!("anomaly")
    };
    let after = recompute(&mut conn).await;
    assert_same(&applied(&before, &deltas), &after, "shadowed rowid");
    conn.execute("ROLLBACK").await.unwrap();

    conn.execute("CREATE TABLE kernel_all(rowid, _rowid_, oid, v)")
        .await
        .unwrap();
    let outcome = outcome_of(&mut conn, &["INSERT INTO kernel_all VALUES (1, 2, 3, 4)"]).await;
    assert!(
        matches!(outcome, CaptureOutcome::Anomaly(Anomaly::RowidShadowed(ref t)) if t == "kernel_all"),
        "{outcome:?}"
    );
}

/// A TEMP table named like a main projection table captures unqualified
/// references, so the capture refuses to arm usefully.
#[tokio::test]
async fn temp_objects_shadowing_main_tables_are_anomalies() {
    let mut conn = plain_connection().await;
    conn.execute("CREATE TEMP TABLE kernel_a(x)").await.unwrap();
    let outcome = outcome_of(&mut conn, &[]).await;
    assert!(
        matches!(outcome, CaptureOutcome::Anomaly(Anomaly::TempShadowsMain(ref t)) if t == "kernel_a"),
        "{outcome:?}"
    );
    conn.execute("DROP TABLE temp.kernel_a").await.unwrap();
    conn.execute("CREATE TEMP VIEW kernel_a AS SELECT 1 AS x")
        .await
        .unwrap();
    let outcome = outcome_of(&mut conn, &[]).await;
    assert!(
        matches!(
            outcome,
            CaptureOutcome::Anomaly(Anomaly::TempShadowsMain(_))
        ),
        "{outcome:?}"
    );
}

/// TEMP DDL that nets out (created then dropped, or recreated identically)
/// moves `temp.schema_version` while leaving the digest alone. There is no
/// exception for it: the projector's scratch tables are created before
/// arming, so the TEMP version must be exactly unchanged at finish.
#[tokio::test]
async fn temp_ddl_that_nets_out_is_an_anomaly_even_with_scratch_tables_absent() {
    let mut conn = plain_connection().await;
    // The scratch tables are absent before arming (fresh connection).
    for (label, statements) in [
        (
            "view created then dropped",
            vec!["CREATE TEMP VIEW v1 AS SELECT 1", "DROP VIEW temp.v1"],
        ),
        (
            "trigger created then dropped",
            vec![
                "CREATE TEMP TRIGGER t1 AFTER INSERT ON main.kernel_a BEGIN SELECT 1; END",
                "DROP TRIGGER temp.t1",
            ],
        ),
        (
            "shadowing table created then dropped",
            vec!["CREATE TEMP TABLE kernel_a(x)", "DROP TABLE temp.kernel_a"],
        ),
    ] {
        let outcome = outcome_of(&mut conn, &statements).await;
        assert!(
            matches!(outcome, CaptureOutcome::Anomaly(Anomaly::SchemaChanged)),
            "{label}: {outcome:?}"
        );
    }
    // An identically recreated non-allowlisted TEMP object.
    conn.execute("CREATE TEMP TABLE scratch(x)").await.unwrap();
    let outcome = outcome_of(
        &mut conn,
        &["DROP TABLE temp.scratch", "CREATE TEMP TABLE scratch(x)"],
    )
    .await;
    assert!(
        matches!(outcome, CaptureOutcome::Anomaly(Anomaly::SchemaChanged)),
        "{outcome:?}"
    );
    // Arming itself creates the projector's scratch tables, so its refresh
    // finds them and changes no schema.
    conn.execute("BEGIN").await.unwrap();
    let mut hooked = Hooked::arm(&mut conn).await.unwrap();
    let present: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM temp.sqlite_master WHERE name IN ('_facet_time_refresh_targets','_facet_time_snapshots')",
    )
    .fetch_one(&mut *hooked)
    .await
    .unwrap();
    assert_eq!(present, 2);
    assert!(matches!(
        hooked.finish().await.unwrap(),
        CaptureOutcome::Delta(_)
    ));
    conn.execute("ROLLBACK").await.unwrap();
}

/// SQLite resolves object names case-insensitively.
#[tokio::test]
async fn temp_shadowing_is_case_insensitive() {
    let mut conn = plain_connection().await;
    conn.execute("CREATE TEMP TABLE KERNEL_A(x)").await.unwrap();
    let outcome = outcome_of(&mut conn, &[]).await;
    assert!(
        matches!(
            outcome,
            CaptureOutcome::Anomaly(Anomaly::TempShadowsMain(_))
        ),
        "{outcome:?}"
    );
}
