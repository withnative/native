//! Private transactional before-images for the opt-in v1 node working copy.
//!
//! Persistent triggers cover *all* engine connections and roll back with their
//! enclosing transaction/savepoint. A second preupdate hook would replace the
//! kernel collector, and preupdate alone does not distinguish rolled-back
//! writes. No capture objects are ever installed on an accepted generation.
use super::*;
use rusqlite::{params, types::Value as Cell, Connection};
use std::collections::{BTreeMap, BTreeSet};

type CaptureResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
const PREFIX: &str = "_node_pending_";

#[derive(Default)]
struct Jobs {
    count: std::sync::Mutex<usize>,
    done: tokio::sync::Notify,
}
struct Job(Arc<Jobs>);
impl Drop for Job {
    fn drop(&mut self) {
        *self.0.count.lock().unwrap_or_else(|e| e.into_inner()) -= 1;
        self.0.done.notify_one();
    }
}

// Only unquoted SQL words matter for conflict policies. In particular comments
// must not hide `OR /* comment */ REPLACE`, or split the scanned keyword pair.
fn sql_words(sql: &str) -> Vec<String> {
    let bytes = sql.as_bytes();
    let mut words = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\'' | b'"' | b'`' | b'[' => {
                let end = if bytes[i] == b'[' { b']' } else { bytes[i] };
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == end {
                        i += 1;
                        if end != b']' && bytes.get(i) == Some(&end) {
                            i += 1;
                        } else {
                            break;
                        }
                    } else {
                        i += 1;
                    }
                }
            }
            b'-' if bytes.get(i + 1) == Some(&b'-') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i < bytes.len() {
                    if bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/') {
                        i += 2;
                        break;
                    }
                    i += 1;
                }
            }
            ch if ch.is_ascii_alphabetic() || ch == b'_' => {
                let start = i;
                i += 1;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                words.push(sql[start..i].to_ascii_uppercase());
            }
            _ => i += 1,
        }
    }
    words
}

// Conflict REPLACE can silently delete rows without firing our DELETE hook.
// Reject schema-level policies, including user triggers. Runtime operations
// are restricted to note create/plain append; their SQL is trace-tested below.
fn reject_replace(c: &Connection) -> CaptureResult<()> {
    let mut stmt = c.prepare("SELECT sql FROM sqlite_schema WHERE sql IS NOT NULL")?;
    for sql in stmt.query_map([], |r| r.get::<_, String>(0))? {
        let words = sql_words(&sql?);
        if words.windows(2).any(|w| {
            w == ["OR", "REPLACE"] || w == ["CONFLICT", "REPLACE"] || w == ["REPLACE", "INTO"]
        }) {
            return Err(fail("unsupported REPLACE conflict resolution"));
        }
    }
    Ok(())
}

fn ident(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}
fn literal(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}
fn fail(message: &str) -> Box<dyn std::error::Error + Send + Sync> {
    std::io::Error::other(message).into()
}

#[derive(Clone)]
struct Table {
    name: String,
    columns: Vec<String>,
    keys: Vec<usize>,
    #[cfg(test)]
    rowid: bool,
}
fn catalog(c: &Connection) -> CaptureResult<Vec<Table>> {
    let mut stmt = c.prepare("SELECT name,type,wr FROM pragma_table_list WHERE schema='main' AND name NOT LIKE 'sqlite_%' ORDER BY name")?;
    let raw = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut tables = vec![];
    for (name, kind, wr) in raw {
        if name.starts_with(PREFIX) || kind == "shadow" || kind == "view" {
            continue;
        }
        if kind == "virtual" {
            if !["records_fts", "records_name_idx"].contains(&name.as_str()) {
                return Err(fail("unsupported virtual table"));
            }
            continue;
        }
        let mut stmt = c.prepare(&format!("PRAGMA table_xinfo({})", ident(&name)))?;
        let cols = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(5)?,
                    r.get::<_, i64>(6)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if cols
            .iter()
            .any(|(n, _, hidden)| n.eq_ignore_ascii_case("_rowid_") || ![0, 2, 3].contains(hidden))
        {
            return Err(fail(&format!("unsupported column layout in {name}")));
        }
        // Generated columns cannot be INSERTed. SQLite recomputes them from
        // the restored writable inputs under the unchanged schema fingerprint.
        let cols: Vec<_> = cols
            .into_iter()
            .filter(|(_, _, hidden)| *hidden == 0)
            .collect();
        let mut columns: Vec<_> = cols.iter().map(|(n, _, _)| n.clone()).collect();
        let keys = if wr == 0 {
            columns.insert(0, "_rowid_".into());
            vec![0]
        } else {
            cols.iter()
                .enumerate()
                .filter_map(|(i, (_, pk, _))| (*pk > 0).then_some(i))
                .collect()
        };
        if keys.is_empty() {
            return Err(fail("missing inverse key"));
        }
        tables.push(Table {
            name,
            columns,
            keys,
            #[cfg(test)]
            rowid: wr == 0,
        });
    }
    Ok(tables)
}
fn schema(c: &Connection) -> CaptureResult<String> {
    let mut h = Sha256::new();
    let mut stmt = c.prepare(
        "SELECT type,name,tbl_name,coalesce(sql,'') FROM sqlite_schema ORDER BY type,name",
    )?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        for i in 0..4 {
            let value: String = row.get(i)?;
            h.update((value.len() as u64).to_le_bytes());
            h.update(value.as_bytes());
        }
    }
    Ok(format!("{:x}", h.finalize()))
}
// Images preserve SQLite storage classes, text including embedded NUL bytes,
// and exact binary64 bits (SQLite's round-trip decimal format for reals).
fn image(table: &Table, alias: &str) -> String {
    let cells = table.columns.iter().map(|n| {
        let v=format!("{alias}.{}",ident(n));
        format!("json_array(typeof({v}),CASE typeof({v}) WHEN 'text' THEN hex(CAST({v} AS BLOB)) WHEN 'blob' THEN hex({v}) WHEN 'real' THEN printf('%!.26g',{v}) ELSE {v} END)")
    }).collect::<Vec<_>>();
    format!("json_array({})", cells.join(","))
}
fn decode(raw: &str) -> CaptureResult<Vec<Cell>> {
    let cells: Vec<(String, Value)> = serde_json::from_str(raw)?;
    cells
        .into_iter()
        .map(|(kind, value)| {
            Ok(match kind.as_str() {
                "null" => Cell::Null,
                "integer" => Cell::Integer(
                    value
                        .as_i64()
                        .ok_or_else(|| fail("invalid integer image"))?,
                ),
                "real" => Cell::Real(
                    value
                        .as_str()
                        .ok_or_else(|| fail("invalid real image"))?
                        .parse()?,
                ),
                "text" | "blob" => {
                    let bytes =
                        hex::decode(value.as_str().ok_or_else(|| fail("invalid byte image"))?)?;
                    if kind == "text" {
                        Cell::Text(String::from_utf8(bytes)?)
                    } else {
                        Cell::Blob(bytes)
                    }
                }
                _ => return Err(fail("unknown image storage class")),
            })
        })
        .collect()
}

pub(super) struct Capture {
    path: PathBuf,
    schema: String,
    epoch: String,
    tables: Vec<Table>,
    jobs: Arc<Jobs>,
}
impl Capture {
    pub(super) async fn install(db: &Db) -> Result<Self> {
        db.drain_captures().await;
        let path = db.path().to_path_buf();
        blocking(move || {
            let c=Connection::open(&path)?;
            reject_replace(&c)?;
            let tables=catalog(&c)?;
            c.execute_batch("BEGIN IMMEDIATE; CREATE TABLE _node_pending_control(enabled INTEGER NOT NULL,epoch TEXT NOT NULL,bytes INTEGER NOT NULL); CREATE TABLE _node_pending_images(seq INTEGER PRIMARY KEY,t TEXT NOT NULL,old TEXT,new TEXT); CREATE TABLE _node_pending_sequences AS SELECT * FROM sqlite_sequence;")?;
            let epoch=Uuid::new_v4().to_string();
            c.execute("INSERT INTO _node_pending_control VALUES(0,?,0)",[&epoch])?;
            for (i,table) in tables.iter().enumerate() {
                for op in ["INSERT","DELETE","UPDATE"] {
                    let old=if op=="INSERT" {"NULL".into()} else {image(table,"old")};
                    let new=if op=="DELETE" {"NULL".into()} else {image(table,"new")};
                    c.execute_batch(&format!("CREATE TRIGGER _node_pending_{i}_{op} AFTER {op} ON {} WHEN (SELECT enabled FROM _node_pending_control)=1 BEGIN INSERT INTO _node_pending_images(t,old,new) VALUES({},{old},{new}); UPDATE _node_pending_control SET bytes=bytes+coalesce(length({old}),0)+coalesce(length({new}),0); SELECT CASE WHEN (SELECT bytes FROM _node_pending_control)>67108864 THEN RAISE(ABORT,'pending capture overflow') END; END;",ident(&table.name),literal(&table.name)))?;
                }
            }
            c.execute_batch("COMMIT;")?;
            let capture=Self { schema:schema(&c)?,path,epoch,tables,jobs:Arc::default() };
            capture.arm(&c)?;
            Ok(capture)
        }).await
    }
    fn check(&self, c: &Connection) -> CaptureResult<()> {
        if schema(c)? != self.schema {
            return Err(fail("capture schema changed"));
        }
        let state: (i64, String) =
            c.query_row("SELECT enabled,epoch FROM _node_pending_control", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })?;
        if state != (1, self.epoch.clone()) {
            return Err(fail("capture interval gap"));
        }
        Ok(())
    }
    fn arm(&self, c: &Connection) -> CaptureResult<()> {
        c.execute_batch("BEGIN IMMEDIATE; DELETE FROM _node_pending_images; DELETE FROM _node_pending_sequences; INSERT INTO _node_pending_sequences SELECT * FROM sqlite_sequence; UPDATE _node_pending_control SET enabled=1,bytes=0; COMMIT;")?;
        Ok(())
    }
    pub(super) async fn verify(&self) -> Result<()> {
        let this = self.clone_for_job();
        self.run(move || this.check(&Connection::open(&this.path)?))
            .await
    }
    pub(super) async fn undo(&self) -> Result<()> {
        let this = self.clone_for_job();
        self.run(move || this.undo_sync()).await
    }
    async fn run<T: Send + 'static>(
        &self,
        job: impl FnOnce() -> CaptureResult<T> + Send + 'static,
    ) -> Result<T> {
        *self.jobs.count.lock().unwrap_or_else(|e| e.into_inner()) += 1;
        let guard = Job(self.jobs.clone());
        blocking(move || {
            let _guard = guard;
            job()
        })
        .await
    }
    pub(super) async fn drain(&self) {
        loop {
            let done = self.jobs.done.notified();
            if *self.jobs.count.lock().unwrap_or_else(|e| e.into_inner()) == 0 {
                break;
            }
            done.await;
        }
    }
    fn clone_for_job(&self) -> Self {
        Self {
            path: self.path.clone(),
            schema: self.schema.clone(),
            epoch: self.epoch.clone(),
            tables: self.tables.clone(),
            jobs: self.jobs.clone(),
        }
    }
    fn undo_sync(&self) -> CaptureResult<()> {
        let c = Connection::open(&self.path)?;
        c.busy_timeout(std::time::Duration::from_secs(30))?;
        // Leave up to one busy-timeout interval for safe rollback/drainage
        // inside the owner's 120s publication deadline.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
        c.progress_handler(10_000, Some(move || std::time::Instant::now() >= deadline));
        self.check(&c)?;
        let mut stmt = c.prepare("SELECT t,old,new FROM _node_pending_images ORDER BY seq DESC")?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, Option<String>>(2)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let tables: BTreeMap<_, _> = self.tables.iter().map(|t| (t.name.as_str(), t)).collect();
        let mut touched = BTreeSet::new();
        for (table, old, new) in &rows {
            if table == "records" {
                for value in [old, new].into_iter().flatten() {
                    if let Some(Cell::Integer(id)) = decode(value)?.first() {
                        touched.insert(*id);
                    }
                }
            }
        }
        c.set_db_config(
            rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER,
            false,
        )?;
        c.execute_batch("PRAGMA foreign_keys=OFF; BEGIN IMMEDIATE;")?;
        for id in &touched {
            fts(&c, *id, true)?;
        }
        for (name, old, new) in rows {
            if std::time::Instant::now() >= deadline {
                return Err(fail("inverse deadline exceeded"));
            }
            let table = tables
                .get(name.as_str())
                .ok_or_else(|| fail("unknown captured table"))?;
            let old = old.map(|s| decode(&s)).transpose()?;
            let new = new.map(|s| decode(&s)).transpose()?;
            let key = new
                .as_ref()
                .or(old.as_ref())
                .ok_or_else(|| fail("empty image"))?;
            if key.len() != table.columns.len() {
                return Err(fail("image width mismatch"));
            }
            let predicate = table
                .keys
                .iter()
                .map(|i| format!("{} IS ?", ident(&table.columns[*i])))
                .collect::<Vec<_>>()
                .join(" AND ");
            let key_values = table.keys.iter().map(|i| &key[*i]).collect::<Vec<_>>();
            let actual = c
                .prepare(&format!(
                    "SELECT {} FROM {} WHERE {predicate}",
                    table
                        .columns
                        .iter()
                        .map(|n| ident(n))
                        .collect::<Vec<_>>()
                        .join(","),
                    ident(name.as_str())
                ))?
                .query_map(
                    rusqlite::params_from_iter(key_values.iter().copied()),
                    |r| {
                        (0..table.columns.len())
                            .map(|i| r.get::<_, Cell>(i))
                            .collect::<std::result::Result<Vec<_>, _>>()
                    },
                )?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            if actual != new.clone().into_iter().collect::<Vec<_>>() {
                return Err(fail("inverse after-image conflict"));
            }
            if new.is_some() {
                let count = c.execute(
                    &format!("DELETE FROM {} WHERE {predicate}", ident(&name)),
                    rusqlite::params_from_iter(key_values.iter().copied()),
                )?;
                if count != 1 {
                    return Err(fail("inverse delete conflict"));
                }
            }
            if let Some(old) = old {
                c.execute(
                    &format!(
                        "INSERT INTO {}({}) VALUES({})",
                        ident(&name),
                        table
                            .columns
                            .iter()
                            .map(|n| ident(n))
                            .collect::<Vec<_>>()
                            .join(","),
                        vec!["?"; table.columns.len()].join(",")
                    ),
                    rusqlite::params_from_iter(old),
                )?;
            }
        }
        c.execute_batch("DELETE FROM sqlite_sequence; INSERT INTO sqlite_sequence SELECT * FROM _node_pending_sequences; UPDATE _node_pending_control SET enabled=0;")?;
        for id in &touched {
            fts(&c, *id, false)?;
        }
        c.execute_batch("COMMIT;")?;
        Ok(())
    }
    pub(super) async fn rearm(&self) -> Result<()> {
        let this = self.clone_for_job();
        self.run(move || {
            let c = Connection::open(&this.path)?;
            if schema(&c)? != this.schema {
                return Err(fail("schema changed during delta"));
            }
            this.arm(&c)
        })
        .await
    }
    pub(super) fn binding(&self) -> (&str, &str) {
        (&self.schema, &self.epoch)
    }
}
fn fts(c: &Connection, id: i64, delete: bool) -> CaptureResult<()> {
    if delete {
        c.execute("INSERT INTO records_fts(records_fts,rowid,name,body) SELECT 'delete',rowid,name,body FROM records WHERE rowid=?",[id])?;
        c.execute("INSERT INTO records_name_idx(records_name_idx,rowid,name) SELECT 'delete',rowid,name FROM records WHERE rowid=?",[id])?;
    } else {
        c.execute("INSERT INTO records_fts(rowid,name,body) SELECT rowid,name,body FROM records WHERE rowid=?",[id])?;
        c.execute(
            "INSERT INTO records_name_idx(rowid,name) SELECT rowid,name FROM records WHERE rowid=?",
            [id],
        )?;
        for table in ["records_fts", "records_name_idx"] {
            let matches:bool=c.query_row(&format!("SELECT (SELECT EXISTS(SELECT 1 FROM {table}_docsize WHERE id=?))=(SELECT EXISTS(SELECT 1 FROM records WHERE rowid=?))"),params![id,id],|r|r.get(0))?;
            if !matches {
                return Err(fail("touched FTS membership mismatch"));
            }
        }
    }
    Ok(())
}
async fn blocking<T: Send + 'static>(
    job: impl FnOnce() -> CaptureResult<T> + Send + 'static,
) -> Result<T> {
    tokio::task::spawn_blocking(job)
        .await
        .map_err(|e| ForkError::Uncertain(Error::engine(e.to_string())))?
        .map_err(|e| ForkError::Uncertain(Error::engine(format!("pending capture: {e}"))))
}

#[cfg(test)]
mod tests;
