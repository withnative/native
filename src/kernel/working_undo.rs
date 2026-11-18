//! Private working undo collector; the off-default manager owns its admission.
//! Private working-copy undo collector and admission qualifications.
//! SQLite foreign-key actions remain active during undo; strict inverse checks
//! refuse unsupported orderings and roll the inverse savepoint back.
#![allow(dead_code)]

use crate::{Error, Result};
use sqlx::SqliteConnection;

/// The caller owns a sqlx Transaction; dropping it rolls back outer work.
/// Run a synchronous phase with exclusive ownership of sqlx's
/// native handle. There is no await between changing connection configuration
/// and restoring it, so dropping the future cannot strand suppression enabled.
pub(crate) async fn with_handle<T>(
    conn: &mut SqliteConnection,
    f: impl FnOnce(&rusqlite::Connection) -> Result<T>,
) -> Result<T> {
    let mut handle = conn.lock_handle().await?;
    // SAFETY: sqlx's worker is excluded by LockedSqliteHandle. The wrapper
    // is non-owning, but rusqlite's Drop still unregisters the shared handle's
    // hooks. Never run it. Explicitly flush our cache on success and unwind
    // while the sqlx lock is held; no borrowed statement can escape f.
    struct Borrowed(std::mem::ManuallyDrop<rusqlite::Connection>);
    impl Drop for Borrowed {
        fn drop(&mut self) {
            self.0.flush_prepared_statement_cache();
        }
    }
    let raw = Borrowed(std::mem::ManuallyDrop::new(
        unsafe { rusqlite::Connection::from_handle(handle.as_raw_handle().as_ptr()) }
            .map_err(|e| Error::engine(e.to_string()))?,
    ));
    raw.0.set_prepared_statement_cache_capacity(0);
    f(&raw.0)
}

// The collector stays private. Its off-default caller must qualify physical
// writer lifetime and exact schema admission, call proposal() inside each
// proposal's savepoint, and roll back that savepoint on *any* capture error.
use rusqlite::{params, types::Value as Cell, Connection};
use std::collections::{BTreeMap, BTreeSet};
pub(crate) type UndoResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
fn fail(s: &str) -> Box<dyn std::error::Error + Send + Sync> {
    std::io::Error::other(s).into()
}
fn ident(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}
fn literal(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}
type SchemaObject = (String, String, String, String);

use super::working_undo_schema::{DDL, TABLES as PRIVATE};
#[derive(Clone, Debug)]
struct Table {
    name: String,
    columns: Vec<String>,
    keys: Vec<usize>,
    fts: bool,
}
fn image(t: &Table, alias: &str) -> String {
    let cells=t.columns.iter().map(|n| {
        let v=format!("{alias}.{}",ident(n));
        format!("json_array(typeof({v}),CASE typeof({v}) WHEN 'text' THEN hex(CAST({v} AS BLOB)) WHEN 'blob' THEN hex({v}) WHEN 'real' THEN printf('%!.26g',{v}) ELSE {v} END)")
    }).collect::<Vec<_>>();
    format!("json_array({})", cells.join(","))
}
fn decode(s: &str) -> UndoResult<Vec<Cell>> {
    let values: Vec<(String, serde_json::Value)> = serde_json::from_str(s)?;
    values
        .into_iter()
        .map(|(kind, v)| {
            Ok(match kind.as_str() {
                "null" => Cell::Null,
                "integer" => {
                    Cell::Integer(v.as_i64().ok_or_else(|| fail("invalid integer image"))?)
                }
                "real" => Cell::Real(
                    v.as_str()
                        .ok_or_else(|| fail("invalid real image"))?
                        .parse()?,
                ),
                "text" => Cell::Text(String::from_utf8(hex::decode(
                    v.as_str().ok_or_else(|| fail("invalid text image"))?,
                )?)?),
                "blob" => Cell::Blob(hex::decode(
                    v.as_str().ok_or_else(|| fail("invalid blob image"))?,
                )?),
                _ => return Err(fail("unknown image storage class")),
            })
        })
        .collect()
}
fn same_cell(a: &Cell, b: &Cell) -> bool {
    match (a, b) {
        (Cell::Real(a), Cell::Real(b)) => a.to_bits() == b.to_bits(),
        _ => a == b,
    }
}
fn same_image(a: Option<&[Cell]>, b: Option<&[Cell]>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => a.len() == b.len() && a.iter().zip(b).all(|(a, b)| same_cell(a, b)),
        _ => false,
    }
}
fn trigger(t: &Table, op: &str) -> (String, String) {
    let name = format!("working_undo_{}_{}", hex::encode(t.name.as_bytes()), op);
    let old = if op == "INSERT" {
        "NULL".into()
    } else {
        image(t, "old")
    };
    let new = if op == "DELETE" {
        "NULL".into()
    } else {
        image(t, "new")
    };
    let sql=format!("CREATE TRIGGER {} AFTER {op} ON {} WHEN (SELECT enabled FROM working_undo_control WHERE singleton=1)=1 BEGIN INSERT INTO working_undo(proposal,t,op,before_image,after_image) SELECT proposal,{},{},{old},{new} FROM working_undo_control WHERE singleton=1; UPDATE working_undo_control SET rows=rows+1,bytes=bytes+coalesce(length({old}),0)+coalesce(length({new}),0) WHERE singleton=1; SELECT CASE WHEN (SELECT rows>max_rows OR bytes>max_bytes FROM working_undo_control WHERE singleton=1) THEN RAISE(ABORT,'working undo budget exceeded') END; END",ident(&name),ident(&t.name),literal(&t.name),literal(op));
    (name, sql)
}
fn schema(c: &Connection) -> UndoResult<Vec<SchemaObject>> {
    Ok(c.prepare(
        "SELECT type,name,tbl_name,coalesce(sql,'') FROM main.sqlite_schema ORDER BY type,name",
    )?
    .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
    .collect::<std::result::Result<_, _>>()?)
}
fn catalog(
    c: &Connection,
    registered_keys: &BTreeMap<String, Vec<String>>,
) -> UndoResult<Vec<Table>> {
    let rows = c
        .prepare("SELECT name,type,wr FROM pragma_table_list WHERE schema='main' ORDER BY name")?
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut tables = vec![];
    let mut saw_fts = false;
    for (name, kind, wr) in rows {
        // Stored visibility accelerators are not canonical: an inverse never
        // restores them; it invalidates them instead (73ad275 M6).
        if PRIVATE.contains(&name.as_str())
            || name.starts_with("sqlite_")
            || kind == "view"
            || super::stored_visibility::TABLES.contains(&name.as_str())
        {
            continue;
        }
        if kind == "virtual" {
            if name != "kernel_search_fts" {
                return Err(fail("unregistered virtual table"));
            }
            let ddl: String = c.query_row(
                "SELECT sql FROM main.sqlite_schema WHERE name='kernel_search_fts'",
                [],
                |r| r.get(0),
            )?;
            let normalized = |sql: &str| {
                sql.chars()
                    .filter(|ch| !ch.is_ascii_whitespace())
                    .flat_map(char::to_lowercase)
                    .collect::<String>()
            };
            let expected = super::search_v2::SEARCH_FTS_DDL.replacen(" IF NOT EXISTS", "", 1);
            if normalized(&ddl) != normalized(&expected) {
                return Err(fail("unsupported FTS storage definition"));
            }
            let cols=c.prepare("SELECT name FROM pragma_table_xinfo('kernel_search_fts') WHERE hidden=0 ORDER BY cid")?
                .query_map([],|r|r.get::<_,String>(0))?.collect::<std::result::Result<Vec<_>,_>>()?;
            if cols != ["record_id", "title", "summary", "body"] {
                return Err(fail("unsupported logical FTS column mapping"));
            }
            saw_fts = true;
            continue;
        }
        let fts = name == "kernel_search_fts_content";
        if kind == "shadow" && !fts {
            continue;
        }
        let cols = c
            .prepare(&format!("PRAGMA main.table_xinfo({})", ident(&name)))?
            .query_map([], |r| Ok((r.get::<_, String>(1)?, r.get::<_, i64>(6)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if cols
            .iter()
            .any(|(n, h)| n.eq_ignore_ascii_case("_rowid_") || ![0, 2, 3].contains(h))
        {
            return Err(fail("unsupported column layout"));
        }
        let mut columns: Vec<_> = cols
            .into_iter()
            .filter(|(_, h)| *h == 0)
            .map(|(n, _)| n)
            .collect();
        let keys = if wr == 0 {
            columns.insert(0, "_rowid_".into());
            vec![0]
        } else {
            registered_keys
                .get(&name)
                .ok_or_else(|| fail("WITHOUT ROWID needs registered key"))?
                .iter()
                .map(|k| {
                    columns
                        .iter()
                        .position(|n| n == k)
                        .ok_or_else(|| fail("unknown registered key"))
                })
                .collect::<UndoResult<Vec<_>>>()?
        };
        if wr != 0 {
            let actual = c
                .prepare(&format!("PRAGMA main.table_info({})", ident(&name)))?
                .query_map([], |r| Ok((r.get::<_, String>(1)?, r.get::<_, i64>(5)?)))?
                .collect::<std::result::Result<Vec<_>, _>>()?
                .into_iter()
                .filter(|(_, pk)| *pk > 0)
                .map(|(n, _)| n)
                .collect::<BTreeSet<_>>();
            let registered = keys
                .iter()
                .map(|i| columns[*i].clone())
                .collect::<BTreeSet<_>>();
            if actual != registered || registered.len() != keys.len() {
                return Err(fail("registered key must equal WITHOUT ROWID primary key"));
            }
        }
        if keys.is_empty() {
            return Err(fail("missing inverse key"));
        }
        if fts
            && (kind != "shadow" || wr != 0 || columns != ["_rowid_", "id", "c0", "c1", "c2", "c3"])
        {
            return Err(fail("unsupported FTS content column mapping"));
        }
        tables.push(Table {
            name,
            columns,
            keys,
            fts,
        });
    }
    if saw_fts != tables.iter().any(|t| t.fts) {
        return Err(fail("FTS requires its registered internal content table"));
    }
    Ok(tables)
}
fn sequences(c: &Connection) -> UndoResult<String> {
    let exists: bool = c.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='sqlite_sequence')",
        [],
        |r| r.get(0),
    )?;
    let rows: Vec<(String, i64)> = if exists {
        c.prepare("SELECT name,seq FROM sqlite_sequence ORDER BY name")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<std::result::Result<_, _>>()?
    } else {
        vec![]
    };
    Ok(serde_json::to_string(&rows)?)
}
/// Small coordinates cover canonical state excluded from projection digests.
fn coordinates(c: &Connection) -> UndoResult<String> {
    let mut out = vec![];
    for table in [
        "act_state",
        "content_events",
        "meta_events",
        "kernel_blobs",
        "content_event_heads",
    ] {
        let exists: bool = c.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name=?)",
            [table],
            |r| r.get(0),
        )?;
        if !exists {
            continue;
        }
        let query = match table {
            "content_events" | "meta_events" => {
                format!("SELECT coalesce(max(seq),0),count(*) FROM {}", ident(table))
            }
            "kernel_blobs" => "SELECT count(*) FROM kernel_blobs".into(),
            _ => format!("SELECT * FROM {} ORDER BY 1", ident(table)),
        };
        let mut stmt = c.prepare(&query)?;
        let width = stmt.column_count();
        let rows = stmt
            .query_map([], |r| {
                let mut row = vec![];
                for i in 0..width {
                    row.push(format!("{:?}", r.get::<_, Cell>(i)?));
                }
                Ok(row)
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        out.push((table, rows));
    }
    Ok(serde_json::to_string(&out)?)
}
/// Expected refusal: the caller rolls the outer transaction back and rebuilds W.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum UndoRefused {
    #[error("foreign key action would change an unlogged child: {parent_table} -> {child_table}")]
    ForeignKeyAction {
        parent_table: String,
        child_table: String,
    },
    #[error("cannot resolve foreign key metadata for {table}: {detail}")]
    ForeignKeyMetadata { table: String, detail: String },
    #[error("inverse change-count mismatch: expected {expected}, observed {observed}")]
    UnexpectedChanges { expected: u64, observed: u64 },
}
#[derive(Clone, Debug)]
struct ForeignKey {
    parent_table: String,
    child_table: String,
    parent_columns: Vec<usize>,
    child_columns: Vec<String>,
    delete_action: bool,
    update_action: bool,
}
fn unresolved(table: &str, detail: &str) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(UndoRefused::ForeignKeyMetadata {
        table: table.into(),
        detail: detail.into(),
    })
}
fn primary_key(c: &Connection, table: &str) -> UndoResult<Vec<String>> {
    let mut cols = c
        .prepare(&format!("PRAGMA main.table_info({})", ident(table)))?
        .query_map([], |r| Ok((r.get::<_, String>(1)?, r.get::<_, i64>(5)?)))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    cols.retain(|(_, pk)| *pk > 0);
    cols.sort_by_key(|(_, pk)| *pk);
    Ok(cols.into_iter().map(|(n, _)| n).collect())
}
fn foreign_keys(c: &Connection, tables: &[Table]) -> UndoResult<BTreeMap<String, Vec<ForeignKey>>> {
    let mut by_parent = BTreeMap::<String, Vec<ForeignKey>>::new();
    for child in tables {
        let mut stmt = c.prepare(&format!(
            "PRAGMA main.foreign_key_list({})",
            ident(&child.name)
        ))?;
        let mut groups = BTreeMap::<i64, Vec<_>>::new();
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, String>(6)?,
            ))
        })?;
        for row in rows {
            let row = row?;
            groups.entry(row.0).or_default().push(row);
        }
        for mut group in groups.into_values() {
            group.sort_by_key(|r| r.1);
            let first = &group[0];
            let parent = tables
                .iter()
                .find(|t| t.name.eq_ignore_ascii_case(&first.2))
                .ok_or_else(|| unresolved(&first.2, "parent table is not registered"))?;
            let pk = primary_key(c, &parent.name)?;
            let implicit = first.4.is_none();
            if implicit && pk.len() != group.len() {
                return Err(unresolved(
                    &parent.name,
                    "implicit primary-key arity differs",
                ));
            }
            let mut parent_columns = vec![];
            let mut child_columns = vec![];
            for (i, r) in group.iter().enumerate() {
                if r.1 != i as i64
                    || r.2 != first.2
                    || r.5 != first.5
                    || r.6 != first.6
                    || r.4.is_none() != implicit
                {
                    return Err(unresolved(
                        &parent.name,
                        "inconsistent composite foreign key",
                    ));
                }
                let col = if implicit {
                    &pk[i]
                } else {
                    r.4.as_ref().unwrap()
                };
                parent_columns.push(
                    parent
                        .columns
                        .iter()
                        .position(|n| n.eq_ignore_ascii_case(col))
                        .ok_or_else(|| {
                            unresolved(&parent.name, "unregistered referenced column")
                        })?,
                );
                child_columns.push(
                    child
                        .columns
                        .iter()
                        .find(|n| n.eq_ignore_ascii_case(&r.3))
                        .ok_or_else(|| unresolved(&parent.name, "unregistered child column"))?
                        .clone(),
                );
            }
            for action in [&first.5, &first.6] {
                if ![
                    "NO ACTION",
                    "RESTRICT",
                    "CASCADE",
                    "SET NULL",
                    "SET DEFAULT",
                ]
                .contains(&action.as_str())
                {
                    return Err(unresolved(&parent.name, "unknown foreign key action"));
                }
            }
            let fk = ForeignKey {
                parent_table: parent.name.clone(),
                child_table: child.name.clone(),
                parent_columns,
                child_columns,
                delete_action: ["CASCADE", "SET NULL", "SET DEFAULT"].contains(&first.6.as_str()),
                update_action: first.5 != "NO ACTION",
            };
            by_parent.entry(parent.name.clone()).or_default().push(fk);
        }
    }
    Ok(by_parent)
}
impl ForeignKey {
    fn existence_sql(&self, parent: &Table) -> String {
        let join = self
            .parent_columns
            .iter()
            .zip(&self.child_columns)
            .map(|(i, col)| {
                let p = format!("p.{}", ident(&parent.columns[*i]));
                let c = format!("c.{}", ident(col));
                // Match the comparison used by SQLite's action trigger. In
                // mixed-affinity cases this may be broader than the FK
                // constraint lookup itself; conservative refusal is required.
                format!("{p}={c}")
            })
            .collect::<Vec<_>>()
            .join(" AND ");
        let key = parent
            .keys
            .iter()
            .map(|i| format!("p.{} IS ?", ident(&parent.columns[*i])))
            .collect::<Vec<_>>()
            .join(" AND ");
        format!(
            "SELECT EXISTS(SELECT 1 FROM main.{} p JOIN main.{} c ON {join} WHERE {key})",
            ident(&parent.name),
            ident(&self.child_table)
        )
    }
    fn precheck(
        &self,
        c: &Connection,
        parent: &Table,
        op: &str,
        before: Option<&[Cell]>,
        after: &[Cell],
    ) -> UndoResult<()> {
        let may_act = match op {
            "INSERT" => self.delete_action,
            "UPDATE" => {
                self.update_action
                    && self
                        .parent_columns
                        .iter()
                        .any(|i| before.is_none_or(|v| v[*i] != after[*i]))
            }
            _ => false,
        };
        if may_act {
            let key = parent.keys.iter().map(|i| &after[*i]);
            if c.query_row(
                &self.existence_sql(parent),
                rusqlite::params_from_iter(key),
                |r| r.get::<_, bool>(0),
            )? {
                return Err(Box::new(UndoRefused::ForeignKeyAction {
                    parent_table: self.parent_table.clone(),
                    child_table: self.child_table.clone(),
                }));
            }
        }
        Ok(())
    }
}

pub(crate) struct Collector {
    tables: Vec<Table>,
    schema: Vec<SchemaObject>,
    foreign_keys: BTreeMap<String, Vec<ForeignKey>>,
    writer_handle: usize,
}
/// Discover declared WITHOUT ROWID primary keys after the owner has admitted
/// the exact native/private schema. This is not schema admission by itself.
pub(crate) fn registered_primary_keys(c: &Connection) -> UndoResult<BTreeMap<String, Vec<String>>> {
    let names = c
        .prepare("SELECT name FROM pragma_table_list WHERE schema='main' AND wr=1 ORDER BY name")?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut keys = BTreeMap::new();
    for name in names {
        let columns = c
            .prepare(&format!("PRAGMA main.table_info({})", ident(&name)))?
            .query_map([], |row| {
                Ok((row.get::<_, String>(1)?, row.get::<_, i64>(5)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        keys.insert(
            name,
            columns
                .into_iter()
                .filter(|(_, pk)| *pk > 0)
                .map(|(name, _)| name)
                .collect(),
        );
    }
    Ok(keys)
}
impl Collector {
    /// Admission is explicit: the schema at installation is the registered
    /// surface. Any later DDL or writer TEMP trigger refuses at the boundary.
    pub(crate) fn install(
        c: &Connection,
        keys: &BTreeMap<String, Vec<String>>,
        max_rows: i64,
        max_bytes: i64,
    ) -> UndoResult<Self> {
        if !c.is_autocommit() {
            return Err(fail("install outside transaction"));
        }
        if max_rows < 0 || max_bytes < 0 {
            return Err(fail("negative budget"));
        }
        c.execute_batch("PRAGMA recursive_triggers=ON; PRAGMA foreign_keys=ON")?;
        let tables = catalog(c, keys)?;
        reject_temp(c)?;
        let foreign_keys = foreign_keys(c, &tables)?;
        c.execute_batch("SAVEPOINT working_install")?;
        let result = (|| {
            for ddl in DDL {
                c.execute_batch(ddl)?;
            }
            c.execute(
                "INSERT INTO working_undo_control VALUES(1,0,1,'',0,0,?,?)",
                params![max_rows, max_bytes],
            )?;
            for t in &tables {
                for op in ["INSERT", "UPDATE", "DELETE"] {
                    c.execute_batch(&trigger(t, op).1)?;
                }
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        })();
        if result.is_err() {
            c.execute_batch("ROLLBACK TO working_install; RELEASE working_install")?;
            result?;
        } else {
            c.execute_batch("RELEASE working_install")?;
        }
        Ok(Self {
            tables,
            schema: schema(c)?,
            foreign_keys,
            writer_handle: unsafe { c.handle() } as usize,
        })
    }
    /// Exact objects generated by THIS collector, not caller-supplied ignored
    /// names. Native/private working admission must still compare its complete
    /// inventory and call check on the actual physical writer.
    pub(crate) fn private_objects(&self) -> Vec<(String, String, String, Option<String>)> {
        let mut objects = PRIVATE
            .iter()
            .zip(DDL)
            .map(|(name, ddl)| {
                (
                    "table".into(),
                    name.to_string(),
                    name.to_string(),
                    Some(ddl.to_string()),
                )
            })
            .collect::<Vec<_>>();
        for table in &self.tables {
            for op in ["INSERT", "UPDATE", "DELETE"] {
                let (name, ddl) = trigger(table, op);
                objects.push(("trigger".into(), name, table.name.clone(), Some(ddl)));
            }
        }
        objects
    }
    /// Reconstruct the registry after restart, refusing missing or altered
    /// private objects. The log and proposal boundaries remain in W.
    pub(crate) fn open(c: &Connection, keys: &BTreeMap<String, Vec<String>>) -> UndoResult<Self> {
        let objects = schema(c)?;
        for (name, ddl) in PRIVATE.iter().zip(DDL) {
            if !objects.iter().any(|o| {
                o == &(
                    "table".into(),
                    name.to_string(),
                    name.to_string(),
                    ddl.to_string(),
                )
            }) {
                return Err(fail("private undo schema mismatch"));
            }
        }
        let tables = catalog(c, keys)?;
        for t in &tables {
            for op in ["INSERT", "UPDATE", "DELETE"] {
                let (name, ddl) = trigger(t, op);
                if !objects
                    .iter()
                    .any(|o| o == &("trigger".into(), name.clone(), t.name.clone(), ddl.clone()))
                {
                    return Err(fail("private undo trigger missing or changed"));
                }
            }
        }
        c.execute_batch("PRAGMA recursive_triggers=ON; PRAGMA foreign_keys=ON")?;
        let foreign_keys = foreign_keys(c, &tables)?;
        let result = Self {
            foreign_keys,
            tables,
            schema: objects,
            writer_handle: unsafe { c.handle() } as usize,
        };
        result.check(c)?;
        Ok(result)
    }
    /// A capture gap is irreversible for this generation. Callers may retry a
    /// proposal with this off switch, but must rebuild W before a later rebase.
    pub(crate) fn disable_capture(&self, c: &Connection) -> UndoResult<()> {
        self.retry_without_capture(c)
    }
    fn assert_writer(&self, c: &Connection) -> UndoResult<()> {
        // The manager must retain this physical writer for the collector's
        // lifetime. All speculative SQL runs on it, never a general pool.
        if unsafe { c.handle() } as usize != self.writer_handle {
            return Err(fail(
                "working undo requires its single pinned writer connection",
            ));
        }
        Ok(())
    }
    pub(crate) fn check(&self, c: &Connection) -> UndoResult<()> {
        self.assert_writer(c)?;
        reject_temp(c)?;
        if schema(c)? != self.schema {
            return Err(fail("uncovered schema change"));
        }
        if !c.db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER)? {
            return Err(fail("capture needs enabled triggers"));
        }
        if !c.query_row("PRAGMA foreign_keys", [], |r| r.get::<_, bool>(0))? {
            return Err(fail("capture needs enabled foreign keys"));
        }
        let recursive: bool = c.query_row("PRAGMA recursive_triggers", [], |r| r.get(0))?;
        if !recursive {
            return Err(fail(
                "recursive triggers required to capture REPLACE deletes",
            ));
        }
        Ok(())
    }
    /// Call inside the proposal savepoint; the snapshot and control row roll
    /// back with a refused or over-budget proposal.
    pub(crate) fn proposal(&self, c: &Connection, tag: &str) -> UndoResult<()> {
        if c.is_autocommit() {
            return Err(fail("proposal needs caller write transaction"));
        }
        self.check(c)?;
        let available: bool =
            c.query_row("SELECT available FROM working_undo_control", [], |r| {
                r.get(0)
            })?;
        if !available {
            return Err(fail("undo unavailable"));
        }
        c.execute("INSERT INTO working_undo_boundaries VALUES(?,(SELECT coalesce(max(seq),0)+1 FROM working_undo),?,?)",params![tag,sequences(c)?,coordinates(c)?])?;
        c.execute(
            "UPDATE working_undo_control SET enabled=1,proposal=?",
            [tag],
        )?;
        Ok(())
    }
    /// Finish only the active proposal's capture on the pinned writer. Private
    /// publication bookkeeping and a trusted accepted fold must not enter its
    /// inverse. This does not discard images or restore unavailable capture.
    pub(crate) fn finish_proposal(&self, c: &Connection, tag: &str) -> UndoResult<()> {
        if c.is_autocommit() {
            return Err(fail("capture finish needs caller write transaction"));
        }
        self.check(c)?;
        let changed = c.execute(
            "UPDATE working_undo_control SET enabled=0 WHERE singleton=1 AND enabled=1 AND available=1 AND proposal=?",
            [tag],
        )?;
        if changed != 1 {
            return Err(fail("capture finish proposal mismatch or unavailable"));
        }
        Ok(())
    }
    /// After rolling back the failing proposal's savepoint, retry the ordinary
    /// handler under a fresh savepoint with capture off. This flag commits in W
    /// with that retry; no caller may interpret its result as undo-capable.
    pub(crate) fn retry_without_capture(&self, c: &Connection) -> UndoResult<()> {
        self.assert_writer(c)?;
        if c.is_autocommit() {
            return Err(fail("retry needs caller write transaction"));
        }
        c.execute("UPDATE working_undo_control SET enabled=0,available=0", [])?;
        Ok(())
    }
    pub(crate) fn undo(&self, c: &Connection, proposal: &str) -> UndoResult<()> {
        if c.is_autocommit() {
            return Err(fail("undo needs caller write transaction"));
        }
        self.check(c)?;
        let available: bool =
            c.query_row("SELECT available FROM working_undo_control", [], |r| {
                r.get(0)
            })?;
        if !available {
            return Err(fail("undo unavailable"));
        }
        let (first, seq, coords): (i64, String, String) = c.query_row(
            "SELECT first_seq,sequences,coordinates FROM working_undo_boundaries WHERE proposal=?",
            [proposal],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        c.execute_batch("SAVEPOINT working_inverse")?;
        // The inverse writes kernel inputs with triggers suppressed, so the
        // marking triggers cannot see it. Invalidate stored visibility in the
        // same savepoint (73ad275 M6); it rolls back with a refused inverse.
        let result = self
            .inverse(c, first, &seq, &coords)
            .and_then(|()| Ok(super::stored_visibility::invalidate_all_raw(c)?));
        if let Err(e) = result {
            c.execute_batch("ROLLBACK TO working_inverse; RELEASE working_inverse")?;
            return Err(e);
        }
        c.execute("DELETE FROM working_undo WHERE seq>=?", [first])?;
        c.execute(
            "DELETE FROM working_undo_boundaries WHERE first_seq>=?",
            [first],
        )?;
        c.execute("UPDATE working_undo_control SET enabled=0,rows=(SELECT count(*) FROM working_undo),bytes=(SELECT coalesce(sum(coalesce(length(before_image),0)+coalesce(length(after_image),0)),0) FROM working_undo)",[])?;
        c.execute_batch("RELEASE working_inverse")?;
        Ok(())
    }
    fn inverse(&self, c: &Connection, first: i64, sequences: &str, coords: &str) -> UndoResult<()> {
        let entries=c.prepare("SELECT t,op,before_image,after_image FROM working_undo WHERE seq>=? ORDER BY seq DESC")?.query_map([first],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,Option<String>>(2)?,r.get::<_,Option<String>>(3)?)))?.collect::<std::result::Result<Vec<_>,_>>()?;
        // Check before suppression: inverse authority never includes terminal images.
        for (name, _, before, after) in &entries {
            let table = self
                .tables
                .iter()
                .find(|t| &t.name == name)
                .ok_or_else(|| fail("unknown undo table"))?;
            let col = if name == "kernel_mcp_write_receipts" {
                "outcome_kind"
            } else if name == "content_events" {
                "type"
            } else {
                continue;
            };
            if let Some(index) = table.columns.iter().position(|c| c == col) {
                for raw in [before, after].into_iter().flatten() {
                    let image = decode(raw)?;
                    if matches!(image.get(index),Some(Cell::Text(v)) if v=="unapplied_terminal" || v=="kernel.mcp_write_fenced.v1")
                    {
                        return Err(fail("terminal image cannot be undone"));
                    }
                }
            }
        }
        let _guard = Suppressed::new(c)?;
        let affected: BTreeSet<_> = entries.iter().map(|e| e.0.as_str()).collect();
        let total_before = c.total_changes();
        let mut statements = 0u64;
        let mut fts_physical_changes = 0u64;
        for (name, op, before, after) in &entries {
            let t = self
                .tables
                .iter()
                .find(|t| &t.name == name)
                .ok_or_else(|| fail("unknown undo table"))?;
            let old = before.as_deref().map(decode).transpose()?;
            let new = after.as_deref().map(decode).transpose()?;
            let lookup = new
                .as_ref()
                .or(old.as_ref())
                .ok_or_else(|| fail("empty inverse"))?;
            let predicate = t
                .keys
                .iter()
                .map(|i| format!("{} IS ?", ident(&t.columns[*i])))
                .collect::<Vec<_>>()
                .join(" AND ");
            let key = t
                .keys
                .iter()
                .map(|i| lookup[*i].clone())
                .collect::<Vec<_>>();
            let select = format!(
                "SELECT {} FROM main.{} WHERE {predicate}",
                t.columns
                    .iter()
                    .map(|n| ident(n))
                    .collect::<Vec<_>>()
                    .join(","),
                ident(name)
            );
            let current = match c.query_row(&select, rusqlite::params_from_iter(&key), |r| {
                (0..t.columns.len())
                    .map(|i| r.get(i))
                    .collect::<std::result::Result<Vec<Cell>, _>>()
            }) {
                Ok(r) => Some(r),
                Err(rusqlite::Error::QueryReturnedNoRows) => None,
                Err(e) => return Err(e.into()),
            };
            if !same_image(current.as_deref(), new.as_deref()) {
                return Err(fail("inverse after-image mismatch"));
            }
            if let Some(edges) = self.foreign_keys.get(name) {
                for fk in edges {
                    fk.precheck(c, t, op, old.as_deref(), lookup)?;
                }
            }
            let changes_before = c.total_changes();
            // The logical FTS rows are captured via their content backing
            // table. Restore through the virtual table, keeping its physical
            // index consistent and preserving the original logical rowid.
            let (target, columns) = if t.fts {
                (
                    "kernel_search_fts".to_string(),
                    vec!["rowid", "rowid", "record_id", "title", "summary", "body"]
                        .into_iter()
                        .map(str::to_owned)
                        .collect::<Vec<_>>(),
                )
            } else {
                (name.clone(), t.columns.clone())
            };
            let mut values = old.clone().unwrap_or_default();
            let mut columns = columns;
            if t.fts {
                if values.len() > 1 {
                    values.remove(1);
                }
                columns.remove(1);
            }
            match op.as_str() {
                "INSERT" => {
                    let p = if t.fts {
                        "rowid IS ?".to_string()
                    } else {
                        predicate
                    };
                    c.execute(
                        &format!("DELETE FROM main.{} WHERE {p}", ident(&target)),
                        rusqlite::params_from_iter(key),
                    )?;
                }
                "DELETE" => {
                    let placeholders = vec!["?"; columns.len()].join(",");
                    c.execute(
                        &format!(
                            "INSERT INTO main.{}({}) VALUES({placeholders})",
                            ident(&target),
                            columns
                                .iter()
                                .map(|n| ident(n))
                                .collect::<Vec<_>>()
                                .join(",")
                        ),
                        rusqlite::params_from_iter(values),
                    )?;
                }
                "UPDATE" => {
                    let p = if t.fts {
                        "rowid IS ?".to_string()
                    } else {
                        predicate
                    };
                    values.extend(key);
                    c.execute(
                        &format!(
                            "UPDATE main.{} SET {} WHERE {p}",
                            ident(&target),
                            columns
                                .iter()
                                .map(|n| format!("{}=?", ident(n)))
                                .collect::<Vec<_>>()
                                .join(",")
                        ),
                        rusqlite::params_from_iter(values),
                    )?;
                }
                _ => return Err(fail("unknown inverse operation")),
            }
            if t.fts {
                // FTS5 may defer shadow writes until the next unrelated
                // statement savepoint. Flush now so those writes remain in
                // this explicit FTS accounting window, never an ordinary
                // inverse's count. This flushes pending terms, not the index.
                c.execute(
                    "INSERT INTO kernel_search_fts(kernel_search_fts) VALUES('flush')",
                    [],
                )?;
                // Ordinary FTS DML legitimately writes several physical
                // shadow rows. Count it separately from ordinary inverses;
                // its FK-action risk is still checked before execution.
                fts_physical_changes += c.total_changes() - changes_before;
            } else {
                statements += 1;
            }
        }
        let observed = c.total_changes() - total_before - fts_physical_changes;
        if observed != statements {
            return Err(Box::new(UndoRefused::UnexpectedChanges {
                expected: statements,
                observed,
            }));
        }
        // Deferral clears SQLite's pending-violation tracking when switched
        // off. Check changed tables and every referencing child first, even
        // when that child has no undo entry.
        let mut checks = affected
            .iter()
            .map(|n| n.to_string())
            .collect::<BTreeSet<_>>();
        for parent in &affected {
            if let Some(edges) = self.foreign_keys.get(*parent) {
                checks.extend(edges.iter().map(|fk| fk.child_table.clone()));
            }
        }
        for name in checks {
            if c.prepare(&format!("PRAGMA main.foreign_key_check({})", ident(&name)))?
                .exists([])?
            {
                return Err(fail("undo foreign key violation"));
            }
        }
        let snapshots: Vec<(String, i64)> = serde_json::from_str(sequences)?;
        let exists: bool = c.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='sqlite_sequence')",
            [],
            |r| r.get(0),
        )?;
        if exists {
            c.execute("DELETE FROM sqlite_sequence", [])?;
            for (name, n) in snapshots {
                c.execute("INSERT INTO sqlite_sequence VALUES(?,?)", params![name, n])?;
            }
        }
        let heads: bool = c.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='content_event_heads')",
            [],
            |r| r.get(0),
        )?;
        if heads {
            let invalid:bool=c.query_row("SELECT EXISTS(SELECT event_id FROM content_event_heads EXCEPT SELECT id FROM content_events WHERE NOT EXISTS(SELECT 1 FROM content_event_causal_frontier WHERE parent_event_id=content_events.id)) OR EXISTS(SELECT id FROM content_events WHERE NOT EXISTS(SELECT 1 FROM content_event_causal_frontier WHERE parent_event_id=content_events.id) EXCEPT SELECT event_id FROM content_event_heads)",[],|r|r.get(0))?;
            if invalid {
                return Err(fail("undo heads differ from frontier anti-join"));
            }
        }
        if coordinates(c)? != coords {
            return Err(fail("undo coordinate mismatch"));
        }
        Ok(())
    }
}
/// Exact DDL exemptions: unknown objects remain in the inventory. No prefix
/// wildcard is used, and the owning ordinary tables remain certified.
pub(crate) async fn certification_objects(
    conn: &mut SqliteConnection,
) -> Result<Vec<SchemaObject>> {
    if super::working_undo_schema::exclusions(conn)
        .await?
        .is_empty()
    {
        return Ok(vec![]);
    }
    with_handle(conn, |c| {
        let installed: bool = c
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='working_undo')",
                [],
                |r| r.get(0),
            )
            .map_err(|e| Error::engine(e.to_string()))?;
        if !installed {
            return Ok(vec![]);
        }
        let keys = c
            .prepare("SELECT name FROM pragma_table_list WHERE schema='main' AND wr=1")
            .map_err(|e| Error::engine(e.to_string()))?
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(|e| Error::engine(e.to_string()))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| Error::engine(e.to_string()))?;
        let mut registered = BTreeMap::new();
        for name in keys {
            let cols = c
                .prepare(&format!("PRAGMA table_info({})", ident(&name)))
                .map_err(|e| Error::engine(e.to_string()))?
                .query_map([], |r| Ok((r.get::<_, String>(1)?, r.get::<_, i64>(5)?)))
                .map_err(|e| Error::engine(e.to_string()))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| Error::engine(e.to_string()))?;
            registered.insert(
                name,
                cols.into_iter()
                    .filter(|(_, pk)| *pk > 0)
                    .map(|(n, _)| n)
                    .collect(),
            );
        }
        let mut objects = PRIVATE
            .iter()
            .zip(DDL)
            .map(|(n, sql)| {
                (
                    "table".into(),
                    n.to_string(),
                    n.to_string(),
                    sql.to_string(),
                )
            })
            .collect::<Vec<_>>();
        for t in catalog(c, &registered).map_err(|e| Error::engine(e.to_string()))? {
            for op in ["INSERT", "UPDATE", "DELETE"] {
                let (name, sql) = trigger(&t, op);
                objects.push(("trigger".into(), name, t.name.clone(), sql));
            }
        }
        Ok(objects)
    })
    .await
}
#[cfg(test)]
pub(crate) fn test_keys(c: &Connection) -> BTreeMap<String, Vec<String>> {
    let names = c
        .prepare("SELECT name FROM pragma_table_list WHERE schema='main' AND wr=1")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap();
    names
        .into_iter()
        .map(|n| {
            let cols = c
                .prepare(&format!("PRAGMA table_info({})", ident(&n)))
                .unwrap()
                .query_map([], |r| Ok((r.get::<_, String>(1)?, r.get::<_, i64>(5)?)))
                .unwrap()
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap();
            (
                n,
                cols.into_iter()
                    .filter(|(_, pk)| *pk > 0)
                    .map(|(n, _)| n)
                    .collect(),
            )
        })
        .collect()
}
#[cfg(test)]
pub(crate) fn test_snapshot(c: &Connection) -> UndoResult<BTreeMap<String, Vec<String>>> {
    let mut out = BTreeMap::new();
    for t in catalog(c, &test_keys(c))? {
        let sql = format!(
            "SELECT {} FROM main.{} ORDER BY {}",
            image(&t, "r"),
            ident(&t.name),
            t.keys
                .iter()
                .map(|i| format!("r.{}", ident(&t.columns[*i])))
                .collect::<Vec<_>>()
                .join(",")
        );
        out.insert(
            t.name,
            c.prepare(&sql.replace(" ORDER BY", " AS r ORDER BY"))?
                .query_map([], |r| r.get(0))?
                .collect::<std::result::Result<_, _>>()?,
        );
    }
    out.insert("sqlite_sequence".into(), vec![sequences(c)?]);
    Ok(out)
}
fn reject_temp(c: &Connection) -> UndoResult<()> {
    let unsupported:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM pragma_database_list WHERE name NOT IN ('main','temp')) OR EXISTS(SELECT 1 FROM sqlite_temp_schema WHERE type IN ('table','view') AND name NOT IN ('_facet_time_refresh_targets','_facet_time_snapshots'))",[],|r|r.get(0))?;
    if unsupported {
        return Err(fail("uncovered attached or TEMP schema"));
    }
    let any: bool = c.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_temp_schema WHERE type='trigger')",
        [],
        |r| r.get(0),
    )?;
    if any {
        return Err(fail("TEMP writer triggers prohibited"));
    }
    Ok(())
}
struct Suppressed<'a> {
    c: &'a Connection,
    triggers: bool,
    deferred: bool,
}
impl<'a> Suppressed<'a> {
    fn new(c: &'a Connection) -> UndoResult<Self> {
        use rusqlite::config::DbConfig;
        let triggers = c.db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER)?;
        let deferred = c.query_row("PRAGMA defer_foreign_keys", [], |r| r.get(0))?;
        let guard = Self {
            c,
            triggers,
            deferred,
        };
        c.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)?;
        c.execute_batch("PRAGMA defer_foreign_keys=ON")?;
        Ok(guard)
    }
}
impl Drop for Suppressed<'_> {
    fn drop(&mut self) {
        // SQLite db_config cannot fail for this supported boolean option. If a
        // configuration restoration ever fails, fail closed rather than let a
        // pool reuse a connection with enforcement disabled.
        if self
            .c
            .set_db_config(
                rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER,
                self.triggers,
            )
            .is_err()
            || self
                .c
                .execute_batch(if self.deferred {
                    "PRAGMA defer_foreign_keys=ON"
                } else {
                    "PRAGMA defer_foreign_keys=OFF"
                })
                .is_err()
        {
            std::process::abort();
        }
    }
}

#[cfg(test)]
pub(crate) fn test_fk_index_report(c: &Connection) -> UndoResult<Vec<String>> {
    let tables = catalog(c, &test_keys(c))?;
    let keys = foreign_keys(c, &tables)?;
    let mut missing = vec![];
    for fk in keys.values().flatten() {
        let child = tables.iter().find(|t| t.name == fk.child_table).unwrap();
        let mut prefixes = vec![];
        let indexes = c
            .prepare(&format!("PRAGMA main.index_list({})", ident(&child.name)))?
            .query_map([], |r| Ok((r.get::<_, String>(1)?, r.get::<_, i64>(4)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for (index, partial) in indexes {
            if partial != 0 {
                continue;
            }
            let cols = c
                .prepare(&format!("PRAGMA main.index_info({})", ident(&index)))?
                .query_map([], |r| r.get::<_, Option<String>>(2))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            if cols.len() >= fk.child_columns.len() {
                if let Some(cols) = cols[..fk.child_columns.len()]
                    .iter()
                    .cloned()
                    .collect::<Option<Vec<_>>>()
                {
                    prefixes.push(cols);
                }
            }
        }
        // INTEGER PRIMARY KEY aliases the rowid and has no index_list row.
        let pk = primary_key(c, &child.name)?;
        if pk.len() == 1 {
            let info = c
                .prepare(&format!("PRAGMA main.table_info({})", ident(&child.name)))?
                .query_map([], |r| Ok((r.get::<_, String>(1)?, r.get::<_, String>(2)?)))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            if info
                .iter()
                .any(|(n, ty)| n == &pk[0] && ty.eq_ignore_ascii_case("INTEGER"))
            {
                prefixes.push(pk);
            }
        }
        let indexed = prefixes.iter().any(|cols| {
            cols.len() == fk.child_columns.len()
                && cols
                    .iter()
                    .map(|n| n.to_ascii_lowercase())
                    .collect::<BTreeSet<_>>()
                    == fk
                        .child_columns
                        .iter()
                        .map(|n| n.to_ascii_lowercase())
                        .collect::<BTreeSet<_>>()
        });
        if !indexed {
            missing.push(format!(
                "{}({}) -> {} [delete_action={}, update_action={}]",
                fk.child_table,
                fk.child_columns.join(","),
                fk.parent_table,
                fk.delete_action,
                fk.update_action
            ));
        }
    }
    missing.sort();
    missing.dedup();
    Ok(missing)
}

#[cfg(all(test, feature = "v2-kernel-probe"))]
mod tests {
    use super::*;
    use rusqlite::config::DbConfig;
    use sqlx::{Connection as _, Executor};

    fn engine(e: rusqlite::Error) -> Error {
        Error::engine(e.to_string())
    }

    /// The exact cached SQL is executed with guards on, off, then on again,
    /// within one transaction. This tests cache invalidation, not just newly
    /// prepared statements through a second SQLite wrapper.
    #[tokio::test]
    async fn trigger_toggle_invalidates_sqlx_cached_statements() {
        let mut c = SqliteConnection::connect("sqlite::memory:").await.unwrap();
        c.execute("CREATE TABLE p(id INTEGER PRIMARY KEY, v INTEGER); INSERT INTO p VALUES(1,0); CREATE TRIGGER guard BEFORE UPDATE ON p BEGIN SELECT RAISE(ABORT,'guard'); END; BEGIN IMMEDIATE;").await.unwrap();
        let sql = "UPDATE p SET v=? WHERE id=1";
        assert!(sqlx::query(sql).bind(1).execute(&mut c).await.is_err());
        with_handle(&mut c, |raw| {
            raw.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)
                .map_err(engine)?;
            Ok(())
        })
        .await
        .unwrap();
        sqlx::query(sql).bind(2).execute(&mut c).await.unwrap();
        with_handle(&mut c, |raw| {
            raw.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, true)
                .map_err(engine)?;
            Ok(())
        })
        .await
        .unwrap();
        assert!(sqlx::query(sql).bind(3).execute(&mut c).await.is_err());
        c.execute("ROLLBACK").await.unwrap();
        let value: i64 = sqlx::query_scalar("SELECT v FROM p")
            .fetch_one(&mut c)
            .await
            .unwrap();
        assert_eq!(value, 0);
    }

    /// DBCONFIG trigger suppression does not suppress foreign-key actions.
    /// Deferral postpones constraint checks; it does not postpone CASCADE.
    /// This is an executable counterexample to treating each inverse as a
    /// change to just its logged row. The row-level inverse check would refuse
    /// the next inverse, despite an unmodified, valid speculative tail.
    #[tokio::test]
    async fn deferred_cascade_changes_the_next_inverse_after_image() {
        let mut c = SqliteConnection::connect("sqlite::memory:").await.unwrap();
        c.execute("PRAGMA foreign_keys=ON; CREATE TABLE parent(id INTEGER PRIMARY KEY); CREATE TABLE child(id INTEGER PRIMARY KEY,p INTEGER REFERENCES parent(id) ON DELETE CASCADE); CREATE TABLE working_undo(seq INTEGER PRIMARY KEY,t TEXT,id INTEGER); CREATE TRIGGER capture_parent AFTER INSERT ON parent BEGIN INSERT INTO working_undo(t,id) VALUES('parent',new.id); END; CREATE TRIGGER capture_child AFTER INSERT ON child BEGIN INSERT INTO working_undo(t,id) VALUES('child',new.id); END; CREATE TRIGGER nested BEFORE INSERT ON parent BEGIN INSERT INTO child VALUES(new.id,new.id); END; BEGIN IMMEDIATE; PRAGMA defer_foreign_keys=ON; INSERT INTO parent VALUES(1);").await.unwrap();
        let log: Vec<(String, i64)> =
            sqlx::query_as("SELECT t,id FROM working_undo ORDER BY seq DESC")
                .fetch_all(&mut c)
                .await
                .unwrap();
        assert_eq!(log, vec![("parent".into(), 1), ("child".into(), 1)]);
        with_handle(&mut c, |raw| {
            raw.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)
                .map_err(engine)?;
            let result = raw
                .execute("DELETE FROM parent WHERE id=1", [])
                .map_err(engine);
            raw.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, true)
                .map_err(engine)?;
            result?;
            Ok(())
        })
        .await
        .unwrap();
        let child_count: i64 = sqlx::query_scalar("SELECT count(*) FROM child")
            .fetch_one(&mut c)
            .await
            .unwrap();
        assert_eq!(
            child_count, 0,
            "CASCADE ran despite trigger suppression and deferral"
        );
        // No integrity check can recover or flag that extra change: the result
        // is referentially valid. A strict after-image check must now refuse.
        let violations = sqlx::query("PRAGMA foreign_key_check")
            .fetch_all(&mut c)
            .await
            .unwrap();
        assert!(violations.is_empty());
        c.execute("ROLLBACK").await.unwrap();
        c.execute("BEGIN; PRAGMA defer_foreign_keys=ON; INSERT INTO parent VALUES(2); ROLLBACK;")
            .await
            .unwrap();
    }
    fn fixture(max_rows: i64) -> (Connection, Collector) {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch("PRAGMA foreign_keys=ON; CREATE TABLE p(id INTEGER PRIMARY KEY AUTOINCREMENT,v BLOB); INSERT INTO p(v) VALUES('base');").unwrap();
        let collector = Collector::install(&c, &BTreeMap::new(), max_rows, 1_000_000).unwrap();
        (c, collector)
    }

    // Frozen byte fixture from a42acba6d5fa65c6935408a250b2f6ce01d3a840.
    // Do not derive this expected SQL from the current trigger() implementation.
    fn previous_a42_trigger(t: &Table, op: &str) -> (String, String) {
        let name = format!("working_undo_{}_{}", hex::encode(t.name.as_bytes()), op);
        let old = if op == "INSERT" {
            "NULL".into()
        } else {
            image(t, "old")
        };
        let new = if op == "DELETE" {
            "NULL".into()
        } else {
            image(t, "new")
        };
        let sql=format!("CREATE TRIGGER {} AFTER {op} ON {} WHEN (SELECT enabled FROM working_undo_control WHERE singleton=1)=1 BEGIN INSERT INTO working_undo(proposal,t,op,before_image,after_image) SELECT proposal,{},{},{old},{new} FROM working_undo_control WHERE singleton=1; UPDATE working_undo_control SET rows=rows+1,bytes=bytes+coalesce(length({old}),0)+coalesce(length({new}),0) WHERE singleton=1; SELECT CASE WHEN (SELECT rows>max_rows OR bytes>max_bytes FROM working_undo_control WHERE singleton=1) THEN RAISE(ABORT,'working undo budget exceeded') END; END",ident(&name),ident(&t.name),literal(&t.name),literal(op));
        (name, sql)
    }

    #[test]
    fn original_settlement_previous_capture_sql_reopens_and_new_sql_is_identical() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("previous-working.db");
        let c = Connection::open(&path).unwrap();
        c.execute_batch("CREATE TABLE p(id INTEGER PRIMARY KEY,v TEXT); INSERT INTO p VALUES(1,'base'); CREATE TABLE content_events(seq INTEGER PRIMARY KEY,type TEXT); CREATE TABLE kernel_mcp_write_receipts(id INTEGER PRIMARY KEY,outcome_kind TEXT);").unwrap();
        let keys = BTreeMap::new();
        let collector = Collector::install(&c, &keys, 100, 1_000_000).unwrap();
        let fresh_schema = schema(&c).unwrap();
        for table in &collector.tables {
            for op in ["INSERT", "UPDATE", "DELETE"] {
                let (name, expected) = previous_a42_trigger(table, op);
                assert_eq!(trigger(table, op), (name.clone(), expected.clone()));
                let actual = fresh_schema
                    .iter()
                    .find(|o| o.0 == "trigger" && o.1 == name)
                    .unwrap();
                assert_eq!(
                    actual.3, expected,
                    "new copy must retain previous capture SQL"
                );
                // Persist the previous-build fixture, not the current generator.
                c.execute_batch(&format!("DROP TRIGGER {}; {}", ident(&name), expected))
                    .unwrap();
            }
        }
        c.execute_batch("BEGIN IMMEDIATE").unwrap();
        collector.proposal(&c, "retained").unwrap();
        c.execute("UPDATE p SET v='pending' WHERE id=1", [])
            .unwrap();
        collector.finish_proposal(&c, "retained").unwrap();
        c.execute_batch("COMMIT").unwrap();
        drop(collector);
        drop(c);
        let c = Connection::open(&path).unwrap();
        let reopened = Collector::open(&c, &keys).expect("previous-build working copy reopens");
        c.execute_batch("BEGIN IMMEDIATE").unwrap();
        reopened.undo(&c, "retained").unwrap();
        assert_eq!(
            c.query_row("SELECT v FROM p WHERE id=1", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "base"
        );
        c.execute_batch("ROLLBACK").unwrap();
    }

    #[test]
    fn original_settlement_terminal_images_refuse_inverse_before_suppression() {
        // Defensive inverse qualification: the unchanged capture SQL can record
        // arbitrary DML. Such images never grant authority to undo terminal facts.
        for statement in [
            "INSERT INTO kernel_mcp_write_receipts VALUES(2,'unapplied_terminal')",
            "UPDATE kernel_mcp_write_receipts SET outcome_kind='accepted' WHERE id=1",
            "DELETE FROM kernel_mcp_write_receipts WHERE id=1",
            "INSERT INTO content_events VALUES(2,'kernel.mcp_write_fenced.v1')",
            "UPDATE content_events SET type='other' WHERE seq=1",
            "DELETE FROM content_events WHERE seq=1",
        ] {
            let c = Connection::open_in_memory().unwrap();
            c.execute_batch("CREATE TABLE content_events(seq INTEGER PRIMARY KEY,type TEXT); INSERT INTO content_events VALUES(1,'kernel.mcp_write_fenced.v1'); CREATE TABLE kernel_mcp_write_receipts(id INTEGER PRIMARY KEY,outcome_kind TEXT); INSERT INTO kernel_mcp_write_receipts VALUES(1,'unapplied_terminal');").unwrap();
            let collector = Collector::install(&c, &BTreeMap::new(), 100, 1_000_000).unwrap();
            c.execute_batch("BEGIN IMMEDIATE").unwrap();
            collector.proposal(&c, "unsupported-terminal").unwrap();
            c.execute(statement, []).unwrap();
            collector
                .finish_proposal(&c, "unsupported-terminal")
                .unwrap();
            let before = test_snapshot(&c).unwrap();
            let error = collector.undo(&c, "unsupported-terminal").unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("terminal image cannot be undone"),
                "{statement}: {error}"
            );
            assert_eq!(
                test_snapshot(&c).unwrap(),
                before,
                "refused inverse changes nothing"
            );
            assert!(c
                .db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER)
                .unwrap());
            assert_eq!(
                c.query_row("SELECT count(*) FROM working_undo_boundaries", [], |r| r
                    .get::<_, i64>(0))
                    .unwrap(),
                1,
                "refusal retains the proposal for owner recovery"
            );
            c.execute_batch("ROLLBACK").unwrap();
        }
    }
    #[test]
    fn typed_images_round_trip_and_savepoints() {
        let (c, collector) = fixture(100);
        let base = test_snapshot(&c).unwrap();
        c.execute_batch("BEGIN IMMEDIATE; SAVEPOINT proposal")
            .unwrap();
        collector.proposal(&c, "a").unwrap();
        c.execute_batch("UPDATE p SET v=x'00ff' WHERE id=1; INSERT INTO p(v) VALUES(0.12345678901234567); SAVEPOINT refused; DELETE FROM p; ROLLBACK TO refused; RELEASE refused; RELEASE proposal;").unwrap();
        collector.undo(&c, "a").unwrap();
        assert_eq!(test_snapshot(&c).unwrap(), base);
        assert!(c
            .db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER)
            .unwrap());
        c.execute_batch("COMMIT").unwrap();
    }
    #[test]
    fn proposal_capture_finish_preserves_images_and_next_proposal() {
        let (c, collector) = fixture(100);
        assert!(collector.finish_proposal(&c, "a").is_err());
        c.execute_batch("BEGIN IMMEDIATE").unwrap();
        collector.proposal(&c, "a").unwrap();
        c.execute("UPDATE p SET v='pending a' WHERE id=1", [])
            .unwrap();
        assert!(collector.finish_proposal(&c, "other").is_err());
        let enabled: i64 = c
            .query_row("SELECT enabled FROM working_undo_control", [], |r| r.get(0))
            .unwrap();
        assert_eq!(enabled, 1);
        collector.finish_proposal(&c, "a").unwrap();
        assert!(collector.finish_proposal(&c, "a").is_err());
        let before: i64 = c
            .query_row("SELECT count(*) FROM working_undo", [], |r| r.get(0))
            .unwrap();
        c.execute("INSERT INTO p(v) VALUES('outside proposal')", [])
            .unwrap();
        let after: i64 = c
            .query_row("SELECT count(*) FROM working_undo", [], |r| r.get(0))
            .unwrap();
        assert_eq!(before, after, "non-proposal writes are not inverse images");
        collector.proposal(&c, "b").unwrap();
        c.execute("UPDATE p SET v='pending b' WHERE id=1", [])
            .unwrap();
        collector.finish_proposal(&c, "b").unwrap();
        let count: i64 = c
            .query_row("SELECT count(*) FROM working_undo", [], |r| r.get(0))
            .unwrap();
        assert!(
            count > after,
            "finishing capture keeps later capture available"
        );
        collector.undo(&c, "b").unwrap();
        let body: String = c
            .query_row("SELECT v FROM p WHERE id=1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(body, "pending a");
        c.execute_batch("ROLLBACK").unwrap();
    }
    #[test]
    fn budget_abort_then_visible_retry_is_persistently_unavailable() {
        let (c, collector) = fixture(0);
        c.execute_batch("BEGIN IMMEDIATE; SAVEPOINT proposal")
            .unwrap();
        collector.proposal(&c, "a").unwrap();
        assert!(c.execute("INSERT INTO p(v) VALUES('pending')", []).is_err());
        c.execute_batch("ROLLBACK TO proposal; RELEASE proposal; SAVEPOINT retry")
            .unwrap();
        collector.retry_without_capture(&c).unwrap();
        c.execute_batch(
            "INSERT INTO p(v) VALUES('pending'); RELEASE retry; COMMIT; BEGIN IMMEDIATE",
        )
        .unwrap();
        assert!(collector
            .undo(&c, "a")
            .unwrap_err()
            .to_string()
            .contains("unavailable"));
        assert_eq!(
            c.query_row("SELECT count(*) FROM p", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            2
        );
    }
    #[test]
    fn mismatch_rolls_back_every_inverse_and_restores_configuration() {
        let (c, collector) = fixture(100);
        c.execute_batch("BEGIN IMMEDIATE").unwrap();
        collector.proposal(&c, "a").unwrap();
        c.execute_batch("UPDATE p SET v='one'; INSERT INTO p(v) VALUES('two'); UPDATE working_undo_control SET enabled=0; UPDATE p SET v='tampered' WHERE id=1").unwrap();
        let pending = test_snapshot(&c).unwrap();
        assert!(collector
            .undo(&c, "a")
            .unwrap_err()
            .to_string()
            .contains("after-image"));
        assert_eq!(pending, test_snapshot(&c).unwrap());
        assert!(c
            .db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER)
            .unwrap());
        assert!(!c
            .query_row("PRAGMA defer_foreign_keys", [], |r| r.get::<_, bool>(0))
            .unwrap());
        c.execute_batch("INSERT INTO p(v) VALUES('usable'); ROLLBACK")
            .unwrap();
    }
    #[test]
    fn temp_triggers_and_schema_drift_are_refused() {
        let (c, collector) = fixture(100);
        c.execute_batch(
            "BEGIN IMMEDIATE; CREATE TEMP TRIGGER extra AFTER INSERT ON main.p BEGIN SELECT 1; END",
        )
        .unwrap();
        assert!(collector
            .proposal(&c, "a")
            .unwrap_err()
            .to_string()
            .contains("TEMP"));
        c.execute_batch("DROP TRIGGER temp.extra; CREATE TABLE unknown(v)")
            .unwrap();
        assert!(collector
            .proposal(&c, "a")
            .unwrap_err()
            .to_string()
            .contains("schema"));
    }
    #[test]
    fn without_rowid_requires_explicit_key_registration() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch("CREATE TABLE p(k TEXT PRIMARY KEY,v INTEGER) WITHOUT ROWID")
            .unwrap();
        assert!(Collector::install(&c, &BTreeMap::new(), 100, 10000).is_err());
        let keys = BTreeMap::from([("p".into(), vec!["k".into()])]);
        let collector = Collector::install(&c, &keys, 100, 10000).unwrap();
        c.execute_batch("BEGIN IMMEDIATE").unwrap();
        collector.proposal(&c, "a").unwrap();
        c.execute_batch("INSERT INTO p VALUES('key',1); UPDATE p SET v=2")
            .unwrap();
        collector.undo(&c, "a").unwrap();
        assert_eq!(
            c.query_row("SELECT count(*) FROM p", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    #[test]
    fn inverse_defers_fk_and_checks_untouched_children() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch("PRAGMA foreign_keys=ON; CREATE TABLE p(id INTEGER PRIMARY KEY); CREATE TABLE child(id INTEGER PRIMARY KEY,p INTEGER REFERENCES p(id)); INSERT INTO p VALUES(1)").unwrap();
        let collector = Collector::install(&c, &BTreeMap::new(), 100, 10000).unwrap();
        c.execute_batch("BEGIN IMMEDIATE").unwrap();
        collector.proposal(&c, "a").unwrap();
        c.execute_batch("INSERT INTO p VALUES(2); UPDATE working_undo_control SET enabled=0; INSERT INTO child VALUES(1,2)").unwrap();
        let before = test_snapshot(&c).unwrap();
        assert!(collector
            .undo(&c, "a")
            .unwrap_err()
            .to_string()
            .contains("foreign key"));
        assert_eq!(test_snapshot(&c).unwrap(), before);
    }
    /// The inverse writes inputs with triggers suppressed, so stored
    /// visibility marking cannot see it: a successful undo invalidates every
    /// family in the same transaction (73ad275 M6), and a refused undo rolls
    /// that invalidation back with its own writes. Accelerators are never
    /// captured or restored.
    #[test]
    fn undo_invalidates_stored_visibility_and_refusal_rolls_it_back() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch("PRAGMA foreign_keys=ON; CREATE TABLE t(id INTEGER PRIMARY KEY); CREATE TABLE child(id INTEGER PRIMARY KEY,p INTEGER REFERENCES t(id)); CREATE TABLE p_marking(singleton INTEGER PRIMARY KEY, enabled INTEGER NOT NULL, marking_since_seq INTEGER NOT NULL, invalidation_epoch INTEGER NOT NULL, fingerprint TEXT NOT NULL); INSERT INTO p_marking VALUES(1,1,0,7,'f'); CREATE TABLE p_state(family TEXT PRIMARY KEY, ready INTEGER NOT NULL); INSERT INTO p_state VALUES('f',1)").unwrap();
        let collector = Collector::install(&c, &BTreeMap::new(), 100, 10000).unwrap();
        let state = |c: &Connection| -> (i64, i64) {
            c.query_row(
                "SELECT (SELECT invalidation_epoch FROM p_marking), (SELECT ready FROM p_state)",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap()
        };
        c.execute_batch("BEGIN IMMEDIATE").unwrap();
        collector.proposal(&c, "a").unwrap();
        c.execute_batch("INSERT INTO t VALUES(1)").unwrap();
        collector.undo(&c, "a").unwrap();
        assert_eq!(state(&c), (8, 0));
        c.execute_batch("UPDATE p_state SET ready=1").unwrap();
        collector.proposal(&c, "b").unwrap();
        c.execute_batch("INSERT INTO t VALUES(2); UPDATE working_undo_control SET enabled=0; INSERT INTO child VALUES(1,2)").unwrap();
        assert!(collector.undo(&c, "b").is_err());
        assert_eq!(state(&c), (8, 1), "a refused inverse invalidates nothing");
    }
    #[test]
    fn logical_fts_rows_and_rowids_are_restored_with_index() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch("CREATE VIRTUAL TABLE kernel_search_fts USING fts5(record_id UNINDEXED,title,summary,body,tokenize='unicode61'); INSERT INTO kernel_search_fts VALUES('a','old','','base'); INSERT INTO kernel_search_fts VALUES('b','second','','tail')").unwrap();
        let collector = Collector::install(&c, &BTreeMap::new(), 100, 100000).unwrap();
        let base = test_snapshot(&c).unwrap();
        c.execute_batch("BEGIN IMMEDIATE").unwrap();
        collector.proposal(&c, "a").unwrap();
        c.execute_batch("DELETE FROM kernel_search_fts WHERE record_id='a'; INSERT INTO kernel_search_fts VALUES('a','new','','pending'); INSERT INTO kernel_search_fts VALUES('c','third','','extra')").unwrap();
        collector.undo(&c, "a").unwrap();
        assert_eq!(test_snapshot(&c).unwrap(), base);
        c.execute_batch(
            "INSERT INTO kernel_search_fts(kernel_search_fts) VALUES('integrity-check')",
        )
        .unwrap();
        assert_eq!(
            c.query_row(
                "SELECT count(*) FROM kernel_search_fts WHERE kernel_search_fts MATCH 'base'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
    }
    #[test]
    fn nested_trigger_order_requires_deferral_and_cascades_refuse_atomically() {
        for cascade in [false, true] {
            let c = Connection::open_in_memory().unwrap();
            c.execute_batch(&format!("PRAGMA foreign_keys=ON; CREATE TABLE p(id INTEGER PRIMARY KEY); CREATE TABLE child(id INTEGER PRIMARY KEY,p REFERENCES p(id) {}); CREATE TRIGGER nested BEFORE INSERT ON p BEGIN INSERT INTO child VALUES(new.id,new.id); END;",if cascade{"ON DELETE CASCADE"}else{""})).unwrap();
            let collector = Collector::install(&c, &BTreeMap::new(), 100, 100000).unwrap();
            let base = test_snapshot(&c).unwrap();
            c.execute_batch("BEGIN IMMEDIATE").unwrap();
            collector.proposal(&c, "a").unwrap();
            c.execute_batch("INSERT INTO p VALUES(1)").unwrap();
            let pending = test_snapshot(&c).unwrap();
            let result = collector.undo(&c, "a");
            if cascade {
                assert!(result
                    .unwrap_err()
                    .to_string()
                    .contains("foreign key action"));
                assert_eq!(test_snapshot(&c).unwrap(), pending);
            } else {
                result.unwrap();
                assert_eq!(test_snapshot(&c).unwrap(), base);
            }
        }
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelling_undo_restores_triggers_and_outer_transaction_rolls_back() {
        use sqlx::sqlite::SqlitePoolOptions;
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        let mut conn = pool.acquire().await.unwrap();
        let collector = with_handle(&mut conn, |c| {
            c.execute_batch(
                "CREATE TABLE p(id INTEGER PRIMARY KEY,v INTEGER); INSERT INTO p VALUES(1,0)",
            )
            .unwrap();
            let collector = Collector::install(c, &BTreeMap::new(), 100, 100000).unwrap();
            c.execute_batch("BEGIN IMMEDIATE").unwrap();
            collector.proposal(c, "a").unwrap();
            c.execute_batch("UPDATE p SET v=1; COMMIT").unwrap();
            Ok(collector)
        })
        .await
        .unwrap();
        drop(conn);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let task_pool = pool.clone();
        let task = tokio::spawn(async move {
            let mut tx = task_pool.begin().await.unwrap();
            with_handle(&mut tx, move |c| {
                let guard = Suppressed::new(c).unwrap();
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                drop(guard);
                collector.undo(c, "a").unwrap();
                Ok(())
            })
            .await
            .unwrap();
            // Deliver cancellation before a commit can publish this undo.
            std::future::pending::<()>().await;
        });
        started_rx.await.unwrap();
        task.abort();
        release_tx.send(()).unwrap();
        assert!(task.await.unwrap_err().is_cancelled());
        let mut conn = pool.acquire().await.unwrap();
        with_handle(&mut conn, |c| {
            assert!(c
                .db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER)
                .unwrap());
            assert_eq!(
                c.query_row("SELECT v FROM p", [], |r| r.get::<_, i64>(0))
                    .unwrap(),
                1
            );
            c.execute_batch("UPDATE p SET v=2").unwrap();
            Ok(())
        })
        .await
        .unwrap();
    }
    /// Safety gate, deliberately expected to refuse. A child outside the undo
    /// range must not disappear merely because its parent is being undone.
    /// Capturing is paused here only to construct the untouched-child anomaly;
    /// normal retries must instead mark the entire copy unavailable.
    #[test]
    fn untouched_cascading_child_must_refuse_without_partial_change() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch("PRAGMA foreign_keys=ON; CREATE TABLE p(id INTEGER PRIMARY KEY); CREATE TABLE child(id INTEGER PRIMARY KEY,p REFERENCES p(id) ON DELETE CASCADE)").unwrap();
        let collector = Collector::install(&c, &BTreeMap::new(), 100, 100000).unwrap();
        let base = test_snapshot(&c).unwrap();
        c.execute_batch("BEGIN IMMEDIATE").unwrap();
        collector.proposal(&c, "a").unwrap();
        c.execute_batch("INSERT INTO p VALUES(1); UPDATE working_undo_control SET enabled=0; INSERT INTO child VALUES(1,1)").unwrap();
        let before = test_snapshot(&c).unwrap();
        let result = collector.undo(&c, "a");
        assert_eq!(
            result.unwrap_err().downcast_ref::<UndoRefused>(),
            Some(&UndoRefused::ForeignKeyAction {
                parent_table: "p".into(),
                child_table: "child".into()
            })
        );
        assert_eq!(test_snapshot(&c).unwrap(), before);
        c.execute_batch("ROLLBACK").unwrap();
        assert_eq!(test_snapshot(&c).unwrap(), base);
    }
    #[test]
    fn fk_actions_refuse_delete_and_referenced_key_update() {
        for action in ["CASCADE", "SET NULL", "SET DEFAULT"] {
            for update in [false, true] {
                let c = Connection::open_in_memory().unwrap();
                c.execute_batch(&format!("PRAGMA foreign_keys=ON; CREATE TABLE p(id INTEGER PRIMARY KEY); CREATE TABLE child(id INTEGER PRIMARY KEY,p INTEGER DEFAULT 0 REFERENCES p(id) ON DELETE {action} ON UPDATE {action}); INSERT INTO p VALUES(0); INSERT INTO p VALUES(1)")).unwrap();
                let collector = Collector::install(&c, &BTreeMap::new(), 100, 100000).unwrap();
                let base = test_snapshot(&c).unwrap();
                c.execute_batch("BEGIN IMMEDIATE").unwrap();
                collector.proposal(&c, "a").unwrap();
                c.execute_batch(if update {
                    "UPDATE p SET id=2 WHERE id=1"
                } else {
                    "INSERT INTO p VALUES(2)"
                })
                .unwrap();
                c.execute_batch(
                    "UPDATE working_undo_control SET enabled=0; INSERT INTO child VALUES(1,2)",
                )
                .unwrap();
                let pending = test_snapshot(&c).unwrap();
                let error = collector.undo(&c, "a").unwrap_err();
                assert_eq!(
                    error.downcast_ref::<UndoRefused>(),
                    Some(&UndoRefused::ForeignKeyAction {
                        parent_table: "p".into(),
                        child_table: "child".into()
                    }),
                    "{action}, update={update}"
                );
                assert_eq!(test_snapshot(&c).unwrap(), pending);
                c.execute_batch("ROLLBACK").unwrap();
                assert_eq!(test_snapshot(&c).unwrap(), base);
            }
        }
    }
    #[test]
    fn captured_children_are_undone_before_cascading_parent() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch("PRAGMA foreign_keys=ON; CREATE TABLE p(id INTEGER PRIMARY KEY); CREATE TABLE child(id INTEGER PRIMARY KEY,p REFERENCES p ON DELETE CASCADE)").unwrap();
        let collector = Collector::install(&c, &BTreeMap::new(), 100, 100000).unwrap();
        let base = test_snapshot(&c).unwrap();
        c.execute_batch("BEGIN IMMEDIATE").unwrap();
        collector.proposal(&c, "a").unwrap();
        c.execute_batch("INSERT INTO p VALUES(1); INSERT INTO child VALUES(1,1)")
            .unwrap();
        collector.undo(&c, "a").unwrap();
        assert_eq!(test_snapshot(&c).unwrap(), base);
    }
    #[test]
    fn fk_composite_implicit_keys_affinities_and_collations() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch("PRAGMA foreign_keys=ON; CREATE TABLE p(a TEXT COLLATE NOCASE,b INTEGER,PRIMARY KEY(a,b)); CREATE TABLE child(x TEXT,y TEXT,FOREIGN KEY(x,y) REFERENCES p ON DELETE CASCADE); INSERT INTO p VALUES('accepted',0)").unwrap();
        let collector = Collector::install(&c, &BTreeMap::new(), 100, 100000).unwrap();
        c.execute_batch("BEGIN IMMEDIATE").unwrap();
        collector.proposal(&c, "a").unwrap();
        c.execute_batch("INSERT INTO p VALUES('MixedCase',1); UPDATE working_undo_control SET enabled=0; INSERT INTO child VALUES('mixedcase','01')").unwrap();
        let pending = test_snapshot(&c).unwrap();
        assert!(matches!(
            collector
                .undo(&c, "a")
                .unwrap_err()
                .downcast_ref::<UndoRefused>(),
            Some(UndoRefused::ForeignKeyAction { .. })
        ));
        assert_eq!(test_snapshot(&c).unwrap(), pending);
        // SQLite's action trigger can match a NUMERIC child against TEXT
        // '01' even when the FK constraint lookup distinguishes it from '1'.
        // Refuse conservatively before that broader action can run.
        let d = Connection::open_in_memory().unwrap();
        d.execute_batch("CREATE TABLE p(k TEXT PRIMARY KEY); CREATE TABLE child(k INTEGER REFERENCES p(k) ON DELETE CASCADE); INSERT INTO p VALUES('1'); INSERT INTO child VALUES(1)").unwrap();
        let collector = Collector::install(&d, &BTreeMap::new(), 100, 100000).unwrap();
        d.execute_batch("BEGIN IMMEDIATE").unwrap();
        collector.proposal(&d, "a").unwrap();
        d.execute_batch("INSERT INTO p VALUES('01')").unwrap();
        let pending = test_snapshot(&d).unwrap();
        assert!(matches!(
            collector
                .undo(&d, "a")
                .unwrap_err()
                .downcast_ref::<UndoRefused>(),
            Some(UndoRefused::ForeignKeyAction { .. })
        ));
        assert_eq!(test_snapshot(&d).unwrap(), pending);
        assert_eq!(
            d.query_row("SELECT count(*) FROM child", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
    #[test]
    fn unresolved_fk_metadata_fails_closed() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch("CREATE TABLE child(p REFERENCES missing(id) ON DELETE CASCADE)")
            .unwrap();
        assert!(matches!(
            Collector::install(&c, &BTreeMap::new(), 100, 100000)
                .err()
                .unwrap()
                .downcast_ref::<UndoRefused>(),
            Some(UndoRefused::ForeignKeyMetadata { .. })
        ));
    }
    #[test]
    fn sqlite_total_changes_counts_fk_actions_with_triggers_disabled() {
        for update in [false, true] {
            for action in ["CASCADE", "SET NULL", "SET DEFAULT"] {
                let c = Connection::open_in_memory().unwrap();
                c.execute_batch(&format!("PRAGMA foreign_keys=ON; CREATE TABLE p(id INTEGER PRIMARY KEY); CREATE TABLE child(p INTEGER DEFAULT 0 REFERENCES p ON DELETE {action} ON UPDATE {action}); INSERT INTO p VALUES(0),(1); INSERT INTO child VALUES(1); BEGIN IMMEDIATE;")).unwrap();
                let _guard = Suppressed::new(&c).unwrap();
                let start = c.total_changes();
                let direct = c
                    .execute(
                        if update {
                            "UPDATE p SET id=2 WHERE id=1"
                        } else {
                            "DELETE FROM p WHERE id=1"
                        },
                        [],
                    )
                    .unwrap();
                assert_eq!(direct, 1);
                assert_eq!(
                    c.total_changes() - start,
                    2,
                    "SQLite counts the parent and its FK-action child: {action}, update={update}"
                );
            }
        }
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch("CREATE VIRTUAL TABLE kernel_search_fts USING fts5(record_id UNINDEXED,title,summary,body); BEGIN IMMEDIATE").unwrap();
        let _guard = Suppressed::new(&c).unwrap();
        let start = c.total_changes();
        assert_eq!(
            c.execute(
                "INSERT INTO kernel_search_fts VALUES('r','title','','body')",
                []
            )
            .unwrap(),
            1
        );
        let physical = c.total_changes() - start;
        assert!(physical > 1, "ordinary FTS DML also changes shadow rows");
        eprintln!("FTS logical insert: direct_changes=1 total_changes={physical}");
    }
    #[test]
    fn fk_existence_check_cost_with_and_without_child_index() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch("CREATE TABLE p(id INTEGER PRIMARY KEY); CREATE TABLE child(id INTEGER PRIMARY KEY,p INTEGER REFERENCES p ON DELETE CASCADE); INSERT INTO p VALUES(1),(2); WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<50000) INSERT INTO child SELECT x,1 FROM n").unwrap();
        let collector = Collector::install(&c, &BTreeMap::new(), 100, 100000).unwrap();
        let parent = collector.tables.iter().find(|t| t.name == "p").unwrap();
        let fk = &collector.foreign_keys["p"][0];
        for indexed in [false, true] {
            if indexed {
                c.execute_batch("CREATE INDEX child_p ON child(p)").unwrap();
            }
            let sql = fk.existence_sql(parent);
            let plan = c
                .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                .unwrap()
                .query_map([2], |r| r.get::<_, String>(3))
                .unwrap()
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap();
            let start = std::time::Instant::now();
            let mut stmt = c.prepare(&sql).unwrap();
            for _ in 0..100 {
                assert!(!stmt.query_row([2], |r| r.get::<_, bool>(0)).unwrap());
            }
            eprintln!("FK existence: child_rows=50000 indexed={indexed} iterations=100 elapsed_us={} plan={plan:?}",start.elapsed().as_micros());
        }
    }
    #[test]
    fn total_changes_surplus_refuses_if_precheck_registry_is_corrupted() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch("PRAGMA foreign_keys=ON; CREATE TABLE p(id INTEGER PRIMARY KEY); CREATE TABLE child(p REFERENCES p ON DELETE CASCADE)").unwrap();
        let mut collector = Collector::install(&c, &BTreeMap::new(), 100, 100000).unwrap();
        c.execute_batch("BEGIN IMMEDIATE").unwrap();
        collector.proposal(&c, "a").unwrap();
        c.execute_batch("INSERT INTO p VALUES(1); UPDATE working_undo_control SET enabled=0; INSERT INTO child VALUES(1)").unwrap();
        let pending = test_snapshot(&c).unwrap();
        // Test-only fault injection bypasses the first line of defence.
        collector.foreign_keys.clear();
        assert_eq!(
            collector
                .undo(&c, "a")
                .unwrap_err()
                .downcast_ref::<UndoRefused>(),
            Some(&UndoRefused::UnexpectedChanges {
                expected: 1,
                observed: 2
            })
        );
        assert_eq!(test_snapshot(&c).unwrap(), pending);
    }
    #[test]
    fn parent_non_key_update_does_not_refuse_existing_child() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch("PRAGMA foreign_keys=ON; CREATE TABLE p(id INTEGER PRIMARY KEY,v TEXT); CREATE TABLE child(p REFERENCES p ON UPDATE CASCADE); INSERT INTO p VALUES(1,'base'); INSERT INTO child VALUES(1)").unwrap();
        let collector = Collector::install(&c, &BTreeMap::new(), 100, 100000).unwrap();
        let base = test_snapshot(&c).unwrap();
        c.execute_batch("BEGIN IMMEDIATE").unwrap();
        collector.proposal(&c, "a").unwrap();
        c.execute_batch("UPDATE p SET v='pending' WHERE id=1")
            .unwrap();
        collector.undo(&c, "a").unwrap();
        assert_eq!(test_snapshot(&c).unwrap(), base);
    }
    #[tokio::test]
    async fn borrowed_handle_preserves_progress_and_commit_hooks() {
        use futures::FutureExt;
        use std::sync::atomic::{AtomicUsize, Ordering};
        static PROGRESS: AtomicUsize = AtomicUsize::new(0);
        static COMMITS: AtomicUsize = AtomicUsize::new(0);
        unsafe extern "C" fn progress(_: *mut std::ffi::c_void) -> std::ffi::c_int {
            PROGRESS.fetch_add(1, Ordering::SeqCst);
            0
        }
        unsafe extern "C" fn commit(_: *mut std::ffi::c_void) -> std::ffi::c_int {
            COMMITS.fetch_add(1, Ordering::SeqCst);
            0
        }
        let mut c = SqliteConnection::connect("sqlite::memory:").await.unwrap();
        c.execute("CREATE TABLE hook_probe(v INTEGER)")
            .await
            .unwrap();
        {
            let mut handle = c.lock_handle().await.unwrap();
            // SAFETY: callbacks use only process-lifetime atomics; the SQLx
            // worker is locked out, and callbacks never unwind or call SQLite.
            unsafe {
                libsqlite3_sys::sqlite3_progress_handler(
                    handle.as_raw_handle().as_ptr(),
                    1,
                    Some(progress),
                    std::ptr::null_mut(),
                );
                libsqlite3_sys::sqlite3_commit_hook(
                    handle.as_raw_handle().as_ptr(),
                    Some(commit),
                    std::ptr::null_mut(),
                );
            }
        }
        for mode in 0..3 {
            let result = std::panic::AssertUnwindSafe(with_handle(&mut c, |raw| -> Result<()> {
                raw.prepare_cached("SELECT 1")
                    .unwrap()
                    .query_row([], |r| r.get::<_, i64>(0))
                    .unwrap();
                if mode == 2 {
                    panic!("qualification unwind");
                }
                if mode == 1 {
                    return Err(Error::engine("qualification error"));
                }
                Ok(())
            }))
            .catch_unwind()
            .await;
            match mode {
                0 => result.unwrap().unwrap(),
                1 => assert!(result.unwrap().is_err()),
                _ => assert!(result.is_err()),
            }
            let before = (
                PROGRESS.load(Ordering::SeqCst),
                COMMITS.load(Ordering::SeqCst),
            );
            c.execute("BEGIN; INSERT INTO hook_probe VALUES(1); COMMIT;")
                .await
                .unwrap();
            assert!(
                PROGRESS.load(Ordering::SeqCst) > before.0,
                "progress handler lost, mode={mode}"
            );
            assert!(
                COMMITS.load(Ordering::SeqCst) > before.1,
                "commit hook lost, mode={mode}"
            );
        }
        let mut handle = c.lock_handle().await.unwrap();
        // SAFETY: detach these test callbacks before releasing the connection.
        unsafe {
            libsqlite3_sys::sqlite3_progress_handler(
                handle.as_raw_handle().as_ptr(),
                0,
                None,
                std::ptr::null_mut(),
            );
            libsqlite3_sys::sqlite3_commit_hook(
                handle.as_raw_handle().as_ptr(),
                None,
                std::ptr::null_mut(),
            );
        }
    }
    #[test]
    fn pinned_writer_and_recursive_trigger_contract_are_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("writer.db");
        let c = Connection::open(&path).unwrap();
        c.execute_batch(
            "CREATE TABLE p(id INTEGER PRIMARY KEY,v TEXT); INSERT INTO p VALUES(1,'base')",
        )
        .unwrap();
        let collector = Collector::install(&c, &BTreeMap::new(), 100, 100000).unwrap();
        let base = test_snapshot(&c).unwrap();
        c.execute_batch("PRAGMA recursive_triggers=OFF; BEGIN IMMEDIATE")
            .unwrap();
        let result = collector.proposal(&c, "forbidden").and_then(|()| {
            c.execute("INSERT OR REPLACE INTO p VALUES(1,'lost')", [])?;
            Ok(())
        });
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("recursive triggers"));
        assert_eq!(test_snapshot(&c).unwrap(), base);
        c.execute_batch("ROLLBACK; PRAGMA recursive_triggers=ON")
            .unwrap();
        let other = Connection::open(&path).unwrap();
        other
            .execute_batch("PRAGMA foreign_keys=ON; PRAGMA recursive_triggers=ON; BEGIN IMMEDIATE")
            .unwrap();
        assert!(collector
            .proposal(&other, "wrong-writer")
            .unwrap_err()
            .to_string()
            .contains("single pinned writer"));
        other.execute_batch("ROLLBACK").unwrap();
        assert_eq!(test_snapshot(&c).unwrap(), base);
    }
    #[test]
    fn real_after_image_comparison_distinguishes_signed_zero() {
        assert!(!same_image(
            Some(&[Cell::Real(-0.0)]),
            Some(&[Cell::Real(0.0)])
        ));
        assert!(same_image(
            Some(&[Cell::Real(-0.0)]),
            Some(&decode("[[\"real\",\"-0.0\"]]").unwrap())
        ));
        assert!(!same_image(
            Some(&[Cell::Integer(0)]),
            Some(&[Cell::Real(0.0)])
        ));
        let (c, collector) = fixture(100);
        c.execute_batch("BEGIN IMMEDIATE").unwrap();
        collector.proposal(&c, "a").unwrap();
        c.execute_batch("UPDATE p SET v=0.0").unwrap();
        // Corrupt only the recorded sign to exercise refusal through undo,
        // not only the comparison helper. SQLite may normalize stored -0.0.
        let t = collector.tables.iter().find(|t| t.name == "p").unwrap();
        let raw: String = c
            .query_row(&format!("SELECT {} FROM p r", image(t, "r")), [], |r| {
                r.get(0)
            })
            .unwrap();
        let mut cells: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let idx = t.columns.iter().position(|n| n == "v").unwrap();
        cells[idx] = serde_json::json!([
            "real",
            if cells[idx][1].as_str().unwrap_or("").starts_with('-') {
                "0.0"
            } else {
                "-0.0"
            }
        ]);
        c.execute("UPDATE working_undo SET after_image=?", [cells.to_string()])
            .unwrap();
        let pending = test_snapshot(&c).unwrap();
        assert!(collector
            .undo(&c, "a")
            .unwrap_err()
            .to_string()
            .contains("after-image"));
        assert_eq!(test_snapshot(&c).unwrap(), pending);
    }
    #[test]
    fn fts_mapping_is_validated_before_capture_installation() {
        for ddl in [
            "CREATE VIRTUAL TABLE kernel_search_fts USING fts5(record_id,body,summary,title)",
            "CREATE VIRTUAL TABLE kernel_search_fts USING fts5(record_id,title,summary,body,content='')",
        ] {
            let c=Connection::open_in_memory().unwrap();c.execute_batch(ddl).unwrap();
            assert!(Collector::install(&c,&BTreeMap::new(),100,100000).is_err());
            assert_eq!(c.query_row("SELECT count(*) FROM sqlite_schema WHERE name='working_undo'",[],|r|r.get::<_,i64>(0)).unwrap(),0);
        }
    }
    #[test]
    fn replace_upsert_and_proposal_boundary_suffix_round_trip() {
        let (c, collector) = fixture(100);
        let base = test_snapshot(&c).unwrap();
        c.execute_batch("BEGIN IMMEDIATE").unwrap();
        collector.proposal(&c, "first").unwrap();
        c.execute_batch("INSERT INTO p VALUES(2,'first'); COMMIT")
            .unwrap();
        let first = test_snapshot(&c).unwrap();
        c.execute_batch("BEGIN IMMEDIATE").unwrap();
        collector.proposal(&c, "second").unwrap();
        c.execute_batch("INSERT OR REPLACE INTO p VALUES(1,'replacement'); INSERT INTO p VALUES(2,'upsert') ON CONFLICT(id) DO UPDATE SET v=excluded.v; COMMIT; BEGIN IMMEDIATE").unwrap();
        collector.undo(&c, "second").unwrap();
        assert_eq!(test_snapshot(&c).unwrap(), first);
        collector.undo(&c, "first").unwrap();
        assert_eq!(test_snapshot(&c).unwrap(), base);
        assert_eq!(
            c.query_row("SELECT count(*) FROM working_undo_boundaries", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    async fn certification_fixture(install: bool) -> SqliteConnection {
        let mut c = SqliteConnection::connect("sqlite::memory:").await.unwrap();
        c.execute(format!("PRAGMA application_id={}; CREATE TABLE p(id INTEGER PRIMARY KEY,v TEXT); INSERT INTO p VALUES(1,'base')",crate::db::V2_APPLICATION_ID).as_str()).await.unwrap();
        if install {
            with_handle(&mut c, |raw| {
                Collector::install(raw, &BTreeMap::new(), 100, 100000).unwrap();
                Ok(())
            })
            .await
            .unwrap();
        }
        c
    }
    #[tokio::test]
    async fn standby_and_digest_exempt_only_exact_empty_disabled_objects() {
        let mut base = certification_fixture(false).await;
        let mut private = certification_fixture(true).await;
        assert_eq!(
            crate::standby::kernel_v2::working_undo_schema_inventory(&mut base)
                .await
                .unwrap(),
            crate::standby::kernel_v2::working_undo_schema_inventory(&mut private)
                .await
                .unwrap()
        );
        assert_eq!(
            super::super::projection_dump::dump_on_dual(&mut base)
                .await
                .unwrap(),
            super::super::projection_dump::dump_on_dual(&mut private)
                .await
                .unwrap()
        );
    }
    #[tokio::test]
    async fn standby_keeps_altered_ddl_and_stray_private_names_visible() {
        for mode in 0..3 {
            let mut c = certification_fixture(true).await;
            let name = match mode {
                0 => {
                    c.execute("DROP TRIGGER working_undo_70_INSERT; CREATE TRIGGER working_undo_70_INSERT AFTER INSERT ON p BEGIN SELECT 1; END").await.unwrap();
                    "working_undo_70_INSERT"
                }
                1 => {
                    c.execute("ALTER TABLE working_undo ADD COLUMN unexpected TEXT")
                        .await
                        .unwrap();
                    "working_undo"
                }
                _ => {
                    c.execute("CREATE TABLE working_undo_x(payload TEXT); INSERT INTO working_undo_x VALUES('visible')").await.unwrap();
                    "working_undo_x"
                }
            };
            let inventory = crate::standby::kernel_v2::working_undo_schema_inventory(&mut c)
                .await
                .unwrap();
            assert!(inventory.iter().any(|o| o.1 == name), "{name} was hidden");
            if mode != 0 {
                assert!(super::super::projection_dump::dump_on(&mut c)
                    .await
                    .unwrap()
                    .tables
                    .iter()
                    .any(|t| t.name == name));
            }
        }
    }
    #[tokio::test]
    async fn standby_and_digest_refuse_private_rows_boundaries_or_capture() {
        for sql in [
            "INSERT INTO working_undo(proposal,t,op,before_image) VALUES('p','p','DELETE','erased row image')",
            "INSERT INTO working_undo_boundaries VALUES('p',1,'[]','[]')",
            "UPDATE working_undo_control SET enabled=1",
        ] {
            let mut c=certification_fixture(true).await;c.execute(sql).await.unwrap();
            assert!(crate::standby::kernel_v2::working_undo_schema_inventory(&mut c).await.is_err());
            assert!(super::super::projection_dump::dump_on(&mut c).await.is_err());
            assert!(super::super::projection_dump::dump_on_dual(&mut c).await.is_err());
        }
    }
    #[tokio::test]
    async fn borrowed_handle_preserves_capture_and_finish_rechecks_private_state() {
        use super::super::projection_capture::{CaptureOutcome, Hooked};
        let mut c = certification_fixture(true).await;
        c.execute("BEGIN IMMEDIATE").await.unwrap();
        let mut capture = Hooked::arm(&mut c).await.unwrap();
        with_handle(&mut capture, |raw| {
            raw.query_row("SELECT 1", [], |r| r.get::<_, i64>(0))
                .unwrap();
            Ok(())
        })
        .await
        .unwrap();
        capture.execute("UPDATE p SET v='changed'").await.unwrap();
        assert!(
            matches!(capture.finish().await.unwrap(),CaptureOutcome::Delta(rows) if !rows.is_empty()),
            "borrowing the handle removed the projection preupdate hook"
        );
        c.execute("ROLLBACK; BEGIN IMMEDIATE").await.unwrap();
        let mut capture = Hooked::arm(&mut c).await.unwrap();
        capture.execute("UPDATE working_undo_control SET enabled=1; INSERT INTO p VALUES(2,'private image')").await.unwrap();
        assert!(
            capture.finish().await.is_err(),
            "a cached proof hid private images populated after arm"
        );
        c.execute("ROLLBACK").await.unwrap();
    }
}
