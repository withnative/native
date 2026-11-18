//! Exact private undo schema and read-only certification admission.
use crate::{Error, Result};
use sqlx::SqliteConnection;

pub(crate) const TABLES: [&str; 3] = [
    "working_undo",
    "working_undo_control",
    "working_undo_boundaries",
];
pub(crate) const DDL: [&str; 3] = [
    "CREATE TABLE working_undo(seq INTEGER PRIMARY KEY,proposal TEXT NOT NULL,t TEXT NOT NULL,op TEXT NOT NULL,before_image TEXT,after_image TEXT)",
    "CREATE TABLE working_undo_control(singleton INTEGER PRIMARY KEY CHECK(singleton=1),enabled INTEGER NOT NULL,available INTEGER NOT NULL,proposal TEXT NOT NULL,rows INTEGER NOT NULL,bytes INTEGER NOT NULL,max_rows INTEGER NOT NULL,max_bytes INTEGER NOT NULL)",
    "CREATE TABLE working_undo_boundaries(proposal TEXT PRIMARY KEY,first_seq INTEGER NOT NULL,sequences TEXT NOT NULL,coordinates TEXT NOT NULL)",
];

/// Only an exact, empty, disabled private closure can disappear from a proof.
/// This is available without v2-kernel-probe, so generic digests never hide
/// retained row images under a private table name. Call in the proof snapshot.
pub(crate) async fn exclusions(conn: &mut SqliteConnection) -> Result<Vec<String>> {
    let actual:Vec<(String,String,String)>=sqlx::query_as("SELECT name,type,coalesce(sql,'') FROM main.sqlite_schema WHERE name IN ('working_undo','working_undo_control','working_undo_boundaries')")
        .fetch_all(&mut *conn).await?;
    if actual.is_empty() {
        return Ok(vec![]);
    }
    for name in ["working_undo", "working_undo_boundaries"] {
        if actual
            .iter()
            .any(|(n, kind, _)| n == name && kind == "table")
        {
            let occupied: bool =
                sqlx::query_scalar(&format!("SELECT EXISTS(SELECT 1 FROM main.{name})"))
                    .fetch_one(&mut *conn)
                    .await?;
            if occupied {
                return Err(Error::engine(
                    "private undo row images or proposal boundaries cannot be certified",
                ));
            }
        }
    }
    if !TABLES.iter().zip(DDL).all(|(name, ddl)| {
        actual
            .iter()
            .any(|(n, kind, sql)| n == name && kind == "table" && sql == ddl)
    }) {
        // Altered/partial private schema stays visible, never exempted.
        return Ok(vec![]);
    }
    let disabled:bool=sqlx::query_scalar("SELECT count(*)=1 AND coalesce(min(singleton=1 AND enabled=0),0) FROM main.working_undo_control").fetch_one(&mut *conn).await?;
    if !disabled {
        return Err(Error::engine(
            "private undo capture must be disabled before certification",
        ));
    }
    Ok(TABLES.iter().map(|n| n.to_string()).collect())
}

// Exact metadata owned only by the off-default W coordinator. These are not
// exclusions for accepted verification/certification.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) const WORKING_PUBLICATION_DDL:&str="CREATE TABLE _native_working_publication(singleton INTEGER PRIMARY KEY CHECK(singleton=1), state TEXT NOT NULL)";
#[cfg(feature = "v2-kernel-probe")]
pub(crate) const WORKING_APPLIED_DDL:&str="CREATE TABLE _native_working_applied(proposal_id TEXT PRIMARY KEY,request_fingerprint TEXT NOT NULL,actor TEXT NOT NULL,publication INTEGER NOT NULL,original_ordinal INTEGER NOT NULL)";
#[cfg(feature = "v2-kernel-probe")]
pub(crate) const WORKING_BASES_DDL: &str =
    "CREATE TABLE _native_working_bases(publication INTEGER PRIMARY KEY,state TEXT NOT NULL)";
#[cfg(feature = "v2-kernel-probe")]
pub(crate) const WORKING_METADATA: [(&str, &str); 3] = [
    ("_native_working_publication", WORKING_PUBLICATION_DDL),
    ("_native_working_applied", WORKING_APPLIED_DDL),
    ("_native_working_bases", WORKING_BASES_DDL),
];
