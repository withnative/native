//! Member copy producer: build a `member-read-v1` SQLite file from a
//! workspace database (contract c323277 rev 7, slice P1).
//!
//! Scope of this increment: **no transport, no authorization fence, no MCP
//! tool, no ordinal assignment, no lifecycle barrier.** It produces the
//! artifact and its [`ReplicaGenerationManifest`] from a workspace `Db`.
//!
//! Design rules it obeys:
//! - **One consistent read transaction** (§4.3 step 3 "W"). Every read runs
//!   inside a single snapshot opened on the governed pool; nothing copies the
//!   whole database and deletes afterwards (task 766ede6).
//! - **E(m) from the engine's full evaluator** (§3.2 records row): the same
//!   `_query_sql_visible_records` relation `query_sql` and
//!   `member_offline_fixtures::assert_evaluator_agreement` treat as E(m).
//!   That relation already applies the owner floor, the bearer minimum, and
//!   subtracts attribution/acknowledgement annotations, semantic Units and
//!   anything they bear.
//! - **Producer rule** (§0): only rows in E(m), caller-bound rows, and values
//!   the online server discloses to *m* ship. Every shipped column is taken
//!   from §3.2; hidden handles are nulled, gated, or withheld per §3.3.
//! - **One physical profile**: the file is created from
//!   [`member_ddl_statements`] and only shipped columns are inserted.
//!
//! What is deliberately left to later increments: the C1/C2 catalog fence,
//! `scope_ref` minting (§1.5; it is an input here), the lazy
//! `ordering.ordinal` assignment (an input here), staging/promote-by-pointer
//! and `native-held-runtime` admission.
//!
//! ## Recorded inferences and decisions
//!
//! - **Caller-bound rows.** `member_contexts` ships the caller's row only when
//!   its `person_record_id` and `root_record_id` are in E(m), so the member
//!   profile's `REFERENCES records(id)` stays satisfiable. `instruction_bindings`
//!   ships the caller's account scope or a database-scope row, and (decision #4)
//!   **only when `source_record_id` ∈ E(m)** — an account-scope row to a hidden
//!   source would disclose that record's identity (§0).
//! - **`schema_incomplete_for`.** `["global"]` when any global row is
//!   withheld, otherwise the sorted visible collection ids whose row was
//!   withheld (§3.3 rule 6).
//! - **Exact-id gate allowlist.** `native:root`, `native:unfiled`, the seven
//!   `ENGINE_PROVISIONED_RECORD_IDS`, plus `native:members` and
//!   `native:database`. An unknown `native:`/UUID id is withheld, which is
//!   stricter than online and permitted by R4.
//! - **`member_display_references`.** A row ships only when the engine's
//!   reference function returns `Some`; a non-canonical id (`native:*`) gets
//!   none. The value is computed inside the producer's read transaction
//!   (decision #2) so the shipped prefix is the online value at the same cut.
//! - **Fresh output.** The producer refuses an existing `out_path`; staging
//!   and promote-by-pointer belong to the transport/lifecycle increment.

use std::collections::{BTreeSet, HashSet};
use std::sync::OnceLock;

use regex::Regex;
use rusqlite::types::Value as SqlValue;
use sqlx::sqlite::SqliteRow;
use sqlx::{Acquire, Row, Sqlite, Transaction, TypeInfo, ValueRef};

use crate::db::Db;
use crate::error::{Error, Result};
use crate::holding::HoldingDisclosureV2;
use crate::member_digest::content_digest;
use crate::query::sql::install_visible_records_in;
use crate::query::QueryPrincipal;
use crate::replica_generation::{
    ReplicaGenerationManifest, ReplicaOrdering, ReplicaOwnWrites, ReplicaProfile,
    REPLICA_GENERATION_CONTRACT, REPLICA_GENERATION_VERSION,
};
use crate::schema::member_classification::{
    shipped_column_order, MemberColumnKind, MEMBER_COLUMN_DISPOSITIONS,
};
use crate::schema::member_schema::{
    member_ddl_statements, member_schema_digest, EXTERNAL_REF_WITHHELD_COLUMN,
};
use crate::schema::{ENGINE_PROVISIONED_RECORD_IDS, ROOT_RECORD_ID, UNFILED_RECORD_ID};
use crate::standby_snapshot::{
    sha256_bytes, StandbyConsumerIdentity, StandbyGenerationMaterialization, StandbySnapshotBytes,
    StandbySnapshotEngineIdentity, STANDBY_SNAPSHOT_MEDIA_TYPE,
};

/// Everything the producer needs besides the workspace database. `scope_ref`
/// and `ordinal` are **inputs** here: minting `scope_ref` (§1.5) and the lazy
/// ordinal assignment (§1.3 F4) belong to the transport/request increment.
#[derive(Clone, Debug)]
pub struct MemberCopyRequest {
    /// The portable account identifier of the member (the credential
    /// `query_sql` filters by).
    pub member_account: String,
    /// Opaque, server-issued scope reference (§1.5). Not minted here.
    pub scope_ref: String,
    /// The hosting route database id the manifest names (§1.3).
    pub hosted_route_database_id: String,
    /// Per-scope monotonic ordinal (§1.3). Assigned lazily by the request
    /// path; supplied here so the manifest can be validated.
    pub ordinal: i64,
    /// The declared consumer identity (§1.3). Supplied by the composition
    /// root so this increment never invents a transport declaration.
    pub consumer: StandbyConsumerIdentity,
    /// Destination for the fresh member SQLite file. Must not exist: a
    /// partial copy is never overwritten in place.
    pub out_path: std::path::PathBuf,
}

/// The produced artifact's identity.
#[derive(Clone, Debug)]
pub struct MemberCopy {
    pub manifest: ReplicaGenerationManifest,
    pub content_digest: String,
    /// `[]`, `["global"]`, or the visible collection ids whose schema row the
    /// exact-id gate withheld (§3.3 rule 6).
    pub schema_incomplete_for: Vec<String>,
}

/// One SQLite cell, carrying its storage class (the digest distinguishes
/// INTEGER from REAL from TEXT; `member_digest` re-reads the same classes).
#[derive(Clone, Debug)]
enum Cell {
    Null,
    Integer(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

impl Cell {
    fn to_sql(&self) -> SqlValue {
        match self {
            Self::Null => SqlValue::Null,
            Self::Integer(value) => SqlValue::Integer(*value),
            Self::Real(value) => SqlValue::Real(*value),
            Self::Text(value) => SqlValue::Text(value.clone()),
            Self::Blob(value) => SqlValue::Blob(value.clone()),
        }
    }

    fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(value) => Some(value),
            _ => None,
        }
    }
}

/// Read one cell, branching on its actual storage class. sqlx exposes only a
/// storage-class-typed value ref publicly, so decode through the matching
/// Rust type.
fn read_cell(row: &SqliteRow, index: usize) -> Result<Cell> {
    let raw = row
        .try_get_raw(index)
        .map_err(|e| Error::engine(format!("member copy: cell {index} unreadable: {e}")))?;
    if raw.is_null() {
        return Ok(Cell::Null);
    }
    let class = raw.type_info().name().to_owned();
    let cell = match class.as_str() {
        "INTEGER" => Cell::Integer(row.try_get::<i64, _>(index).map_err(cell_error)?),
        "REAL" => Cell::Real(row.try_get::<f64, _>(index).map_err(cell_error)?),
        "TEXT" => Cell::Text(row.try_get::<String, _>(index).map_err(cell_error)?),
        "BLOB" => Cell::Blob(row.try_get::<Vec<u8>, _>(index).map_err(cell_error)?),
        other => {
            return Err(Error::engine(format!(
                "member copy: unsupported SQLite storage class {other}"
            )))
        }
    };
    Ok(cell)
}

fn cell_error(error: sqlx::Error) -> Error {
    Error::engine(format!("member copy: cell decode failed: {error}"))
}

/// Engine-owned record ids the exact-id gate admits even when they are not in
/// E(m) (§3.3 rule 6 "E(m) ∪ {engine-owned ids}"). Kept conservative: an
/// unknown `native:` id is withheld, which is stricter than online and
/// permitted by R4.
fn engine_owned_ids() -> &'static BTreeSet<&'static str> {
    static IDS: OnceLock<BTreeSet<&'static str>> = OnceLock::new();
    IDS.get_or_init(|| {
        let mut ids: BTreeSet<&'static str> = BTreeSet::new();
        ids.insert(ROOT_RECORD_ID);
        ids.insert(UNFILED_RECORD_ID);
        for id in ENGINE_PROVISIONED_RECORD_IDS {
            ids.insert(id);
        }
        // Scope subjects that appear in free-text configuration.
        ids.insert("native:members");
        ids.insert("native:database");
        ids
    })
}

fn canonical_uuid_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
            .expect("canonical UUID pattern compiles")
    })
}

fn native_id_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN
        .get_or_init(|| Regex::new(r"native:[A-Za-z0-9_:\-]+").expect("native id pattern compiles"))
}

/// §3.3 rule 6: does `text` embed a full canonical record id outside
/// `visible ∪ engine-owned`? Only exact canonical UUIDs and `native:` ids are
/// matched; short references and `wiki_name` forms are opaque authored text
/// and never resolved (N1).
fn exact_id_gate_withholds(text: &str, visible: &HashSet<String>) -> bool {
    let engine_owned = engine_owned_ids();
    canonical_uuid_pattern()
        .find_iter(text)
        .chain(native_id_pattern().find_iter(text))
        .any(|m| {
            let id = m.as_str();
            !visible.contains(id) && !engine_owned.contains(id)
        })
}

/// Shipped columns of one table in insert order, member-only physical columns
/// appended last (as [`member_ddl_statements`] emits them).
fn member_columns(table: &str) -> Vec<String> {
    let mut columns: Vec<String> = shipped_column_order(table)
        .iter()
        .map(|column| (*column).to_owned())
        .collect();
    if table == "blobs" {
        columns.push(EXTERNAL_REF_WITHHELD_COLUMN.to_owned());
    }
    columns
}

fn column_kind(table: &str, column: &str) -> Option<MemberColumnKind> {
    MEMBER_COLUMN_DISPOSITIONS
        .iter()
        .find(|(name, candidate, _)| *name == table && *candidate == column)
        .map(|(_, _, kind)| *kind)
}

/// Source relation and row predicate for one shipped table, mirroring the
/// governed `query_sql` view of the same name (§3.2 row rules). `binds_account`
/// says the predicate takes the member account as its first positional bind.
fn table_source(table: &str) -> (String, &'static str, bool) {
    match table {
        "records" => (
            "main.records AS t JOIN temp._query_sql_visible_records AS v ON v.id = t.id".into(),
            "",
            false,
        ),
        "links" => (
            "main.links AS t \
             JOIN temp._query_sql_visible_records AS sv ON sv.id = t.source_id \
             JOIN temp._query_sql_visible_records AS tv ON tv.id = t.target_id"
                .into(),
            "",
            false,
        ),
        "facet_values" => (
            "main.facet_values AS t JOIN temp._query_sql_visible_records AS v ON v.id = t.record_id"
                .into(),
            "",
            false,
        ),
        "facet_times" => (
            "main.facet_times AS t JOIN temp._query_sql_visible_records AS v ON v.id = t.record_id"
                .into(),
            "",
            false,
        ),
        "vocabularies" => ("main.vocabularies AS t".into(), "", false),
        "vocabulary_values" => ("main.vocabulary_values AS t".into(), "", false),
        "schema_config" => (
            "main.schema_config AS t".into(),
            "(t.applies_to_collection_id IS NULL OR EXISTS (SELECT 1 FROM \
             temp._query_sql_visible_records AS v WHERE v.id = t.applies_to_collection_id))",
            false,
        ),
        "blobs" => (
            "main.blobs AS t".into(),
            "EXISTS (SELECT 1 FROM main.records AS attachment \
             JOIN temp._query_sql_visible_records AS attachment_visible ON attachment_visible.id = attachment.id \
             JOIN main.facet_values AS blob_ref ON blob_ref.record_id = attachment.id AND blob_ref.key = 'blob_ref' AND blob_ref.value = t.id \
             JOIN main.links AS bearer ON bearer.source_id = attachment.id AND bearer.relationship = 'part_of' \
             JOIN temp._query_sql_visible_records AS bearer_visible ON bearer_visible.id = bearer.target_id \
             WHERE attachment.type = 'Document' AND attachment.kind = 'attachment')",
            false,
        ),
        "annotation_targets" => (
            "main.annotation_targets AS t \
             JOIN temp._query_sql_visible_records AS av ON av.id = t.annotation_id \
             JOIN temp._query_sql_visible_records AS tv ON tv.id = t.target_record_id"
                .into(),
            "",
            false,
        ),
        "record_mentions" => (
            "main.record_mentions AS t JOIN temp._query_sql_visible_records AS v ON v.id = t.source_id"
                .into(),
            "",
            false,
        ),
        "bindings" => (
            "main.bindings AS t".into(),
            "t.system IN ('account','email') \
             AND EXISTS (SELECT 1 FROM main.bindings AS own_account \
                         WHERE own_account.record_id = t.record_id \
                           AND own_account.system = 'account' \
                           AND own_account.identifier = ? \
                           AND own_account.is_canonical = 1) \
             AND EXISTS (SELECT 1 FROM temp._query_sql_visible_records AS v WHERE v.id = t.record_id)",
            true,
        ),
        "member_contexts" => (
            "main.member_contexts AS t".into(),
            "t.account_id = ? \
             AND EXISTS (SELECT 1 FROM temp._query_sql_visible_records AS v WHERE v.id = t.person_record_id) \
             AND EXISTS (SELECT 1 FROM temp._query_sql_visible_records AS v WHERE v.id = t.root_record_id)",
            true,
        ),
        // §3.2 caller-bound: the caller's account scope, or a database-scope
        // row. Both must name a source in E(m) (Richard, decision #4, §0): an
        // account-scope row whose source is hidden would ship the hidden
        // record's identity.
        "instruction_bindings" => (
            "main.instruction_bindings AS t".into(),
            "EXISTS (SELECT 1 FROM temp._query_sql_visible_records AS v \
              WHERE v.id = t.source_record_id) \
             AND ((t.scope_kind = 'account' AND t.scope_id = ?) \
                  OR t.scope_kind = 'database')",
            true,
        ),
        other => unreachable!("no member source declared for {other}"),
    }
}

/// Where a withheld schema row applies (§3.3 rule 6): `None` means global.
#[derive(Default)]
struct SchemaGate {
    global: bool,
    collections: BTreeSet<String>,
}

impl SchemaGate {
    fn record(&mut self, applies_to: Option<&str>) {
        match applies_to {
            Some(collection) => {
                self.collections.insert(collection.to_owned());
            }
            None => self.global = true,
        }
    }

    fn into_incomplete_for(self) -> Vec<String> {
        if self.global {
            vec!["global".to_owned()]
        } else {
            self.collections.into_iter().collect()
        }
    }
}

fn cell_at<'a>(columns: &[String], cells: &'a [Cell], name: &str) -> Option<&'a Cell> {
    columns
        .iter()
        .position(|c| c == name)
        .map(|index| &cells[index])
}

fn source_error(error: sqlx::Error) -> Error {
    Error::engine(format!("member copy: source read failed: {error}"))
}

/// Copy rows of one shipped table into the member file, applying the
/// nulled_if_hidden and exact-id-gate rules. The caller has already filtered
/// rows to E(m) in `sql`.
///
/// B3/Send: `out` is an exclusive `&mut rusqlite::Connection`. rusqlite's
/// `Connection` is `Send` but not `Sync`, so `&Connection` held across a
/// `sqlx` await makes the future `!Send` (fine for the current-thread
/// registry tests, fatal to the multi-thread HTTP transport), while
/// `&mut Connection` is `Send`. Keeping the exclusive borrow preserves the
/// original bounded per-table memory and row order.
async fn copy_table(
    tx: &mut Transaction<'_, Sqlite>,
    out: &mut rusqlite::Connection,
    visible: &HashSet<String>,
    account: &str,
    table: &str,
    gate: &mut SchemaGate,
) -> Result<()> {
    let insert_columns = member_columns(table);
    let source_columns: Vec<String> = shipped_column_order(table)
        .iter()
        .map(|column| (*column).to_owned())
        .collect();
    let (from_clause, predicate, binds_account) = table_source(table);
    let projection = source_columns
        .iter()
        .map(|column| format!("t.{column}"))
        .collect::<Vec<_>>()
        .join(", ");
    let mut sql = format!("SELECT {projection} FROM {from_clause}");
    if !predicate.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(predicate);
    }
    let mut query = sqlx::query(&sql);
    if binds_account {
        query = query.bind(account);
    }
    let rows = query.fetch_all(&mut **tx).await.map_err(source_error)?;
    for row in rows {
        let mut cells = Vec::with_capacity(source_columns.len());
        for index in 0..source_columns.len() {
            cells.push(read_cell(&row, index)?);
        }
        if let Some(values) = finalize_row(table, &source_columns, &cells, visible, gate)? {
            insert_row(out, table, &insert_columns, values)?;
        }
    }
    Ok(())
}

/// Apply per-column dispositions to one source row. `None` means the row is
/// withheld entirely (a gated `schema_config`/`vocabulary_values` row).
fn finalize_row(
    table: &str,
    columns: &[String],
    cells: &[Cell],
    visible: &HashSet<String>,
    gate: &mut SchemaGate,
) -> Result<Option<Vec<SqlValue>>> {
    if table == "blobs" {
        let external =
            cell_at(columns, cells, "storage_tier").and_then(Cell::as_text) == Some("external");
        let mut values = Vec::with_capacity(columns.len() + 1);
        let mut withheld = false;
        for (index, column) in columns.iter().enumerate() {
            let cell = &cells[index];
            match column.as_str() {
                // Producer obligation (review F6): external-tier rows carry no
                // bytes; the member profile admits `bytes IS NULL`.
                "bytes" => values.push(if external {
                    SqlValue::Null
                } else {
                    cell.to_sql()
                }),
                // §2.4 item 11a: withhold the value, keep the row.
                "external_ref" => {
                    if cell
                        .as_text()
                        .is_some_and(|text| exact_id_gate_withholds(text, visible))
                    {
                        withheld = true;
                        values.push(SqlValue::Null);
                    } else {
                        values.push(cell.to_sql());
                    }
                }
                _ => values.push(cell.to_sql()),
            }
        }
        values.push(SqlValue::Integer(if withheld { 1 } else { 0 }));
        return Ok(Some(values));
    }

    let mut values = Vec::with_capacity(columns.len());
    for (index, column) in columns.iter().enumerate() {
        let cell = &cells[index];
        match column_kind(table, column) {
            Some(MemberColumnKind::Gated) => {
                if cell
                    .as_text()
                    .is_some_and(|text| exact_id_gate_withholds(text, visible))
                {
                    let applies_to =
                        cell_at(columns, cells, "applies_to_collection_id").and_then(Cell::as_text);
                    gate.record(applies_to);
                    return Ok(None);
                }
                values.push(cell.to_sql());
            }
            Some(MemberColumnKind::NulledIfHidden) => {
                let nulled = cell.as_text().is_some_and(|id| !visible.contains(id));
                values.push(if nulled {
                    SqlValue::Null
                } else {
                    cell.to_sql()
                });
            }
            _ => values.push(cell.to_sql()),
        }
    }
    Ok(Some(values))
}

fn insert_row(
    out: &rusqlite::Connection,
    table: &str,
    columns: &[String],
    values: Vec<SqlValue>,
) -> Result<()> {
    let placeholders = vec!["?"; columns.len()].join(", ");
    let sql = format!(
        "INSERT INTO {table} ({}) VALUES ({placeholders})",
        columns.join(", ")
    );
    out.execute(&sql, rusqlite::params_from_iter(values))
        .map_err(|error| {
            Error::engine(format!("member copy: insert into {table} failed: {error}"))
        })?;
    Ok(())
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Build a member copy for one account. See the module docs for scope.
///
/// Opens the one consistent read snapshot (§4.3 step 3 "W") and delegates to
/// [`build_member_copy_in_tx`]. The generation registry calls the inner form
/// so the authorization counters and the slice share one snapshot.
pub async fn build_member_copy(db: &Db, request: MemberCopyRequest) -> Result<MemberCopy> {
    let mut connection = db.governed_pool().acquire().await?;
    let mut tx = connection.begin().await?;
    install_visible_records_in(
        &mut tx,
        QueryPrincipal::authenticated(request.member_account.clone(), true),
    )
    .await?;
    let result = build_member_copy_in_tx(&mut tx, request).await;
    let rollback = tx.rollback().await;
    connection.close_on_drop();
    let copy = result?;
    rollback?;
    Ok(copy)
}

/// Build a member copy inside a caller-owned read transaction on the governed
/// pool, with the visibility views already installed. Does not touch the
/// transaction lifecycle: the caller commits or rolls back.
pub(crate) async fn build_member_copy_in_tx(
    tx: &mut Transaction<'_, Sqlite>,
    request: MemberCopyRequest,
) -> Result<MemberCopy> {
    if request.out_path.exists() {
        return Err(Error::engine(
            "member copy: refusing to overwrite an existing output file",
        ));
    }
    if request.scope_ref.trim().is_empty() {
        return Err(Error::engine("member copy: scope_ref must not be empty"));
    }
    let captured_at = now_iso();

    // E(m): the engine's full evaluator, as the governed views and the
    // fixture agreement test use it.
    let visible: HashSet<String> =
        sqlx::query_scalar("SELECT id FROM temp._query_sql_visible_records")
            .fetch_all(&mut **tx)
            .await
            .map_err(source_error)?
            .into_iter()
            .collect();

    let origin_database_id: String =
        sqlx::query_scalar("SELECT origin_db_id FROM main.database_identity WHERE singleton = 1")
            .fetch_one(&mut **tx)
            .await
            .map_err(source_error)?;
    let schema_version: i64 = sqlx::query_scalar("SELECT user_version FROM pragma_user_version")
        .fetch_one(&mut **tx)
        .await
        .map_err(source_error)?;

    // A fresh member file from the compiled profile DDL.
    //
    // B3/Send: `out` is an exclusive `&mut` below. rusqlite's `Connection`
    // is `Send` but not `Sync`, so a shared `&Connection` held across a
    // `sqlx` await makes the future `!Send`; `&mut Connection` is `Send`,
    // and per-table read-then-write keeps the original bounded memory and
    // row order exactly.
    let mut out = rusqlite::Connection::open(&request.out_path)
        .map_err(|error| Error::engine(format!("member copy: cannot create output: {error}")))?;
    // Explicit rollback-journal mode and FK state, so the on-disk shape never
    // depends on a connection default: no `-wal`/`-shm` sidecar can hold
    // bytes the raw scan would miss, and VACUUM below can compact freely.
    out.execute_batch("PRAGMA journal_mode = DELETE; PRAGMA foreign_keys = OFF;")
        .map_err(|error| Error::engine(format!("member copy: output pragmas failed: {error}")))?;
    out.execute_batch(&member_ddl_statements().join(";\n"))
        .map_err(|error| Error::engine(format!("member copy: member DDL failed: {error}")))?;

    let mut gate = SchemaGate::default();
    for table in crate::schema::member_schema::shipped_tables() {
        if table == "member_display_references" {
            continue;
        }
        copy_table(
            tx,
            &mut out,
            &visible,
            &request.member_account,
            table,
            &mut gate,
        )
        .await?;
    }
    copy_display_references(tx, &mut out, &visible).await?;

    // The read snapshot is the caller's to end; everything below is the
    // detached file.

    // Compact before hashing (F4): a free page left by any future
    // delete/update cannot retain bytes the raw scan would not see. VACUUM
    // rewrites only the physical file; logical values — and so the digest —
    // are unchanged.
    out.execute_batch("VACUUM;")
        .map_err(|error| Error::engine(format!("member copy: VACUUM failed: {error}")))?;
    let content_digest = content_digest(&out)
        .map_err(|error| Error::engine(format!("member copy: content digest failed: {error}")))?;
    drop(out);

    let file_bytes = std::fs::read(&request.out_path)
        .map_err(|error| Error::engine(format!("member copy: cannot read output: {error}")))?;
    let snapshot_completed_at = now_iso();

    let schema_incomplete_for = gate.into_incomplete_for();
    let manifest = ReplicaGenerationManifest {
        contract: REPLICA_GENERATION_CONTRACT.to_owned(),
        version: REPLICA_GENERATION_VERSION,
        origin_database_id,
        hosted_route_database_id: request.hosted_route_database_id,
        captured_at,
        snapshot_completed_at,
        producer: StandbySnapshotEngineIdentity {
            name: crate::ENGINE_NAME.to_owned(),
            source_sha: crate::FULL_GIT_SHA.to_owned(),
            schema_version,
            ddl_sha256: crate::schema::FROZEN_DDL_SHA256.to_owned(),
        },
        consumer: request.consumer,
        bytes: StandbySnapshotBytes {
            media_type: STANDBY_SNAPSHOT_MEDIA_TYPE.to_owned(),
            size_bytes: file_bytes.len() as u64,
            sha256: sha256_bytes(&file_bytes),
        },
        materialization: StandbyGenerationMaterialization::Snapshot,
        scope: crate::holding::ReplicaScope::Member {
            scope_ref: request.scope_ref.clone(),
        },
        ordering: ReplicaOrdering::Scoped {
            ordinal: request.ordinal,
        },
        holding: HoldingDisclosureV2::member(request.scope_ref.clone(), request.ordinal),
        profile: ReplicaProfile::MemberReadV1 {
            member_schema_digest: member_schema_digest(),
        },
        content_digest: content_digest.clone(),
        own_writes: ReplicaOwnWrites::not_computed(),
        frontier: None,
        schema_incomplete_for: schema_incomplete_for.clone(),
    };
    manifest.validate()?;

    Ok(MemberCopy {
        manifest,
        content_digest,
        schema_incomplete_for,
    })
}

/// Q6c: ship the online `display_reference` value for every record in E(m),
/// computed by the engine's own reference function so the member sees exactly
/// what the online server would show (a hidden sibling may lengthen a prefix;
/// that is allowed timing/prefix disclosure, R1a).
///
/// B3/Send: `out` is an exclusive `&mut rusqlite::Connection`, which is `Send`
/// (the shared `&Connection` form is not), so the future stays transport-safe.
async fn copy_display_references(
    tx: &mut Transaction<'_, Sqlite>,
    out: &mut rusqlite::Connection,
    visible: &HashSet<String>,
) -> Result<()> {
    let ids: Vec<&str> = visible.iter().map(String::as_str).collect();
    // Inside the producer's read transaction: `display_references_in` runs the
    // engine's own reference scan over physical `records` (hidden included) on
    // this connection, so the shipped value is the online value at the same
    // cut. The public `display_references_in_pool` form opens its own
    // snapshot, which task 766ede6's "one consistent read" forbids.
    let references = {
        let mut executor = crate::portable_sql::BorrowedSqliteStatementExecutor::new(&mut *tx);
        crate::mcp::record_ref::display_references_in(&mut executor, &ids).await?
    };
    let columns = member_columns("member_display_references");
    for (record_id, reference) in references {
        if let Some(reference) = reference {
            insert_row(
                out,
                "member_display_references",
                &columns,
                vec![SqlValue::Text(record_id), SqlValue::Text(reference)],
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::Path;

    use rusqlite::Connection as RusqliteConnection;

    use super::*;
    use crate::member_offline_fixtures::{self as fixtures, assert_no_counter_fields};
    use crate::standby_snapshot::{StandbyConsumerPlatform, STANDBY_CONSUMER_CONTRACT};

    fn consumer() -> StandbyConsumerIdentity {
        StandbyConsumerIdentity {
            contract: STANDBY_CONSUMER_CONTRACT.to_owned(),
            version: 1,
            platform: StandbyConsumerPlatform::LinuxX8664,
            source_sha: "c".repeat(40),
            artifact_sha256: "d".repeat(64),
            engine_schema_version: crate::CURRENT_ENGINE_SCHEMA_VERSION,
            ddl_sha256: "e".repeat(64),
        }
    }

    fn request(account: &str, scope_ref: &str, out: &Path) -> MemberCopyRequest {
        MemberCopyRequest {
            member_account: account.to_owned(),
            scope_ref: scope_ref.to_owned(),
            hosted_route_database_id: "route-test".to_owned(),
            ordinal: 1,
            consumer: consumer(),
            out_path: out.to_path_buf(),
        }
    }

    fn open_copy(path: &Path) -> RusqliteConnection {
        RusqliteConnection::open(path).expect("member copy opens")
    }

    fn record_ids(path: &Path) -> BTreeSet<String> {
        let connection = open_copy(path);
        let mut statement = connection.prepare("SELECT id FROM records").unwrap();
        let ids = statement
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<std::result::Result<BTreeSet<_>, _>>()
            .unwrap();
        ids
    }

    fn file_bytes(path: &Path) -> Vec<u8> {
        std::fs::read(path).unwrap()
    }

    fn assert_absent(bytes: &[u8], needles: &[&str], context: &str) {
        let haystack = String::from_utf8_lossy(bytes);
        for needle in needles {
            assert!(
                !haystack.contains(needle),
                "{context}: hidden handle {needle:?} leaked into the member copy"
            );
        }
    }

    fn assert_present(bytes: &[u8], needle: &str, context: &str) {
        let haystack = String::from_utf8_lossy(bytes);
        assert!(
            haystack.contains(needle),
            "{context}: expected value {needle:?} is missing"
        );
    }

    /// All columns of one `records` row, keyed by name.
    fn record_columns(path: &Path, id: &str) -> BTreeMap<String, String> {
        let connection = open_copy(path);
        let names: Vec<String> = connection
            .prepare("PRAGMA table_info(records)")
            .unwrap()
            .query_map([], |row| row.get(1))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        let projection = names.join(", ");
        connection
            .query_row(
                &format!("SELECT {projection} FROM records WHERE id = ?1"),
                [id],
                |row| {
                    let mut map = BTreeMap::new();
                    for (index, name) in names.iter().enumerate() {
                        let value: rusqlite::types::Value = row.get(index)?;
                        map.insert(name.clone(), format!("{value:?}"));
                    }
                    Ok(map)
                },
            )
            .unwrap()
    }

    /// The shipped `display_reference` for one record, if any.
    fn display_reference_of(path: &Path, record_id: &str) -> Option<String> {
        let connection = open_copy(path);
        let mut statement = connection
            .prepare("SELECT display_reference FROM member_display_references WHERE record_id = ?1")
            .unwrap();
        let mut rows = statement.query([record_id]).unwrap();
        rows.next().unwrap().map(|row| row.get(0).unwrap())
    }

    fn assert_link_endpoints_visible(path: &Path, visible: &BTreeSet<String>) {
        let connection = open_copy(path);
        let endpoints: Vec<(String, String)> = connection
            .prepare("SELECT source_id, target_id FROM links")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        for (source, target) in endpoints {
            assert!(visible.contains(&source), "link source {source} is hidden");
            assert!(visible.contains(&target), "link target {target} is hidden");
        }
    }

    /// §7.2 item 3 (`two_caller`): A's and B's artifacts differ exactly as
    /// E(A)/E(B) say; neither holds a byte of the other's private additions.
    #[tokio::test]
    async fn two_caller_artifacts_hold_only_each_members_e() {
        use fixtures::two_caller as tc;
        let world = tc::build().await;
        // Decision #4 bindings, seeded here rather than in the shared world
        // (NEW-1: the shared world is reused by the qualification suite, where
        // an account-scope binding to a hidden source is `invalid`).
        fixtures::insert_instruction_binding(
            &world.db,
            tc::BINDING_VISIBLE_SOURCE,
            fixtures::ACCT_A,
            tc::SHARED_CHILD,
            0,
        )
        .await;
        fixtures::insert_instruction_binding(
            &world.db,
            tc::BINDING_HIDDEN_SOURCE,
            fixtures::ACCT_A,
            tc::B_ONLY,
            1,
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let a_path = dir.path().join("a.db");
        let b_path = dir.path().join("b.db");
        let copy_a = build_member_copy(&world.db, request(fixtures::ACCT_A, "scope-a", &a_path))
            .await
            .unwrap();
        let copy_b = build_member_copy(&world.db, request(fixtures::ACCT_B, "scope-b", &b_path))
            .await
            .unwrap();

        // Row sets equal the engine evaluator's E(m).
        let ea: BTreeSet<String> = fixtures::online_visible_ids(&world.db, fixtures::ACCT_A)
            .await
            .into_iter()
            .collect();
        let eb: BTreeSet<String> = fixtures::online_visible_ids(&world.db, fixtures::ACCT_B)
            .await
            .into_iter()
            .collect();
        assert_eq!(record_ids(&a_path), ea);
        assert_eq!(record_ids(&b_path), eb);
        assert_link_endpoints_visible(&a_path, &ea);
        assert_link_endpoints_visible(&b_path, &eb);

        // Raw scan: hidden ids, names, bodies, links and external_ref values.
        let a_bytes = file_bytes(&a_path);
        let b_bytes = file_bytes(&b_path);
        let ext_ref_value = tc::ext_ref_value();
        let authored = tc::authored_disclosed_ids();
        let hidden_from_a: Vec<&str> = tc::hidden_from_a()
            .into_iter()
            .filter(|id| !authored.contains(id))
            .collect();
        let hidden_from_b: Vec<&str> = tc::hidden_from_b()
            .into_iter()
            .filter(|id| !authored.contains(id))
            .collect();
        assert_absent(&a_bytes, &hidden_from_a, "A");
        assert_absent(
            &a_bytes,
            &["b-only note", tc::B_ONLY_FACET, ext_ref_value.as_str()],
            "A",
        );
        assert_absent(&b_bytes, &hidden_from_b, "B");
        assert_absent(
            &b_bytes,
            &[
                "a-only bytes",
                tc::LINK_VIS_HIDDEN,
                tc::LINK_SUPERSEDES,
                tc::HIDDEN_PARENT_FACET,
            ],
            "B",
        );

        // The manifest JSON is scanned too: no hidden handle reaches it.
        let a_manifest = serde_json::to_vec(&copy_a.manifest).unwrap();
        let b_manifest = serde_json::to_vec(&copy_b.manifest).unwrap();
        assert_absent(&a_manifest, &hidden_from_a, "A manifest");
        assert_absent(
            &a_manifest,
            &["b-only note", ext_ref_value.as_str()],
            "A manifest",
        );
        assert_absent(&b_manifest, &hidden_from_b, "B manifest");

        // Neither holds the other's private additions.
        let a_private = [
            tc::A_OWNED,
            tc::BEARER_A,
            tc::ATT_A,
            tc::HIDDEN_PARENT,
            tc::NEWER_HIDDEN,
            tc::MSG_A,
            tc::HIDDEN_COLLECTION,
            tc::LINK_VIS_HIDDEN,
            tc::LINK_SUPERSEDES,
            tc::BINDING_VISIBLE_SOURCE,
            tc::HIDDEN_PARENT_FACET,
            "a-only bytes",
        ];
        assert_absent(&b_bytes, &a_private, "B-private");
        assert_absent(&b_manifest, &a_private, "B manifest");
        assert_absent(
            &a_bytes,
            &[
                tc::B_ONLY,
                "b-only note",
                tc::B_ONLY_FACET,
                ext_ref_value.as_str(),
            ],
            "B-private",
        );
        // A's own private additions do ship to A.
        assert_present(&a_bytes, tc::A_OWNED, "A");
        assert_present(&a_bytes, "a-only bytes", "A");
        assert_present(&b_bytes, tc::B_ONLY, "B");
        assert_present(&b_bytes, ext_ref_value.as_str(), "B");

        // §7.2 item 3: A's external blob row ships with the value withheld.
        let a_conn = open_copy(&a_path);
        let (ext_ref, withheld): (Option<String>, i64) = a_conn
            .query_row(
                "SELECT external_ref, external_ref_withheld FROM blobs WHERE id = ?1",
                [tc::EXT_BLOB],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(ext_ref, None, "A must not learn B_ONLY from external_ref");
        assert_eq!(withheld, 1, "A's gated NULL must carry the F5 marker");
        let b_conn = open_copy(&b_path);
        let (ext_ref, withheld): (Option<String>, i64) = b_conn
            .query_row(
                "SELECT external_ref, external_ref_withheld FROM blobs WHERE id = ?1",
                [tc::EXT_BLOB],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(ext_ref, Some(tc::ext_ref_value()));
        assert_eq!(withheld, 0);

        // Decision #4: only the binding whose source is in E(A) ships.
        let mut binding_statement = a_conn
            .prepare("SELECT id FROM instruction_bindings ORDER BY id")
            .unwrap();
        let binding_ids: Vec<String> = binding_statement
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        assert_eq!(binding_ids, vec![tc::BINDING_VISIBLE_SOURCE.to_owned()]);
        assert_absent(&a_bytes, &[tc::BINDING_HIDDEN_SOURCE], "A");
        assert_present(&a_bytes, tc::BINDING_VISIBLE_SOURCE, "A");

        // §3.3 rule 1: the child of a hidden parent keeps its row but has
        // home_id nulled; for A the parent is visible, so the id is kept.
        let a_home: Option<String> = a_conn
            .query_row(
                "SELECT home_id FROM records WHERE id = ?1",
                [tc::VISIBLE_CHILD],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(a_home.as_deref(), Some(tc::HIDDEN_PARENT));
        let b_home: Option<String> = b_conn
            .query_row(
                "SELECT home_id FROM records WHERE id = ?1",
                [tc::VISIBLE_CHILD],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(b_home, None, "a hidden parent must be nulled, not named");

        // The gate-failing schema row embeds HIDDEN_MENTIONED: visible to A,
        // so A's row ships and A is not incomplete; hidden from B, so B's row
        // is withheld and only that visible collection refuses.
        assert!(copy_a.schema_incomplete_for.is_empty());
        assert_eq!(copy_b.schema_incomplete_for, vec![tc::SHARED.to_owned()]);
    }

    /// §7.2 item 1 (`hidden_change`): hidden-only change, no hidden identity,
    /// content or count; fields that differ are ones online also shows.
    #[tokio::test]
    async fn hidden_only_change_keeps_visible_content_at_online_parity() {
        use fixtures::hidden_change as hc;
        let worlds = hc::build().await;
        let dir = tempfile::tempdir().unwrap();
        let a_path = dir.path().join("a.db");
        let b_path = dir.path().join("b.db");
        let copy_a = build_member_copy(&worlds.a, request(fixtures::ACCT_B, "scope", &a_path))
            .await
            .unwrap();
        let copy_b = build_member_copy(&worlds.b, request(fixtures::ACCT_B, "scope", &b_path))
            .await
            .unwrap();

        let e_a: BTreeSet<String> = fixtures::online_visible_ids(&worlds.a, fixtures::ACCT_B)
            .await
            .into_iter()
            .collect();
        let e_b: BTreeSet<String> = fixtures::online_visible_ids(&worlds.b, fixtures::ACCT_B)
            .await
            .into_iter()
            .collect();
        assert_eq!(e_a, e_b, "hidden-only deltas change no record for B");
        assert_eq!(record_ids(&a_path), e_a);
        assert_eq!(record_ids(&b_path), e_b);

        let authored = hc::authored_disclosed_ids();
        let hidden: Vec<&str> = hc::hidden_from_b()
            .into_iter()
            .filter(|id| !authored.contains(id))
            .collect();
        let b_bytes = file_bytes(&b_path);
        assert_absent(&b_bytes, &hidden, "hidden-change B");
        assert_absent(
            &b_bytes,
            &[
                hc::HIDDEN_BODY_BASE,
                hc::HIDDEN_BODY_EDITED,
                hc::HIDDEN_BODY_NEW,
                hc::HIDDEN_BODY_PREFIX,
                hc::HIDDEN_BODY_NEWER,
                // §7.2 item 1(a): hidden link ids and hidden facet values too.
                hc::LINK_VIS_HIDDEN,
                hc::LINK_SUPERSEDES,
                hc::HIDDEN_FACET_VALUE,
            ],
            "hidden-change B",
        );

        // §7.2 item 1(d): the global schema row embedding HIDDEN_H is withheld.
        assert_eq!(copy_a.schema_incomplete_for, Vec::<String>::new());
        assert_eq!(copy_b.schema_incomplete_for, vec!["global".to_owned()]);

        // §7.2 item 1(c): only VIS_H's link-touched timestamps differ.
        for id in hc::visible_to_b() {
            let a = record_columns(&a_path, id);
            let b = record_columns(&b_path, id);
            for (column, a_value) in &a {
                if id == hc::VIS_H && (column == "updated_at" || column == "last_activity_at") {
                    continue;
                }
                assert_eq!(
                    a_value, &b[column],
                    "visible {id}.{column} moved under a hidden-only change"
                );
            }
            if id == hc::VIS_H {
                assert_ne!(
                    a["updated_at"], b["updated_at"],
                    "the hidden link-touch must move VIS_H.updated_at"
                );
            }
        }
    }

    /// §7.2 item 2 (N1): a short reference must not resolve, so the artifact
    /// is identical whether or not a hidden record shares that prefix.
    #[tokio::test]
    async fn prefix_gate_outcome_is_independent_of_hidden_prefix() {
        use fixtures::prefix_gate as pg;
        let worlds = pg::build().await;
        let dir = tempfile::tempdir().unwrap();
        let without_path = dir.path().join("without.db");
        let with_path = dir.path().join("with.db");
        let without = build_member_copy(
            &worlds.without,
            request(fixtures::ACCT_B, "s", &without_path),
        )
        .await
        .unwrap();
        let with = build_member_copy(&worlds.with, request(fixtures::ACCT_B, "s", &with_path))
            .await
            .unwrap();
        assert_eq!(
            without.content_digest, with.content_digest,
            "a hidden prefix must not change the member artifact"
        );
        assert!(!without.schema_incomplete_for.iter().any(|s| s == "global"));
        assert!(!with.schema_incomplete_for.iter().any(|s| s == "global"));
        assert_present(&file_bytes(&without_path), pg::SHORT_REF_DATA, "without");
        assert_present(&file_bytes(&with_path), pg::SHORT_REF_DATA, "with");
        assert_absent(&file_bytes(&with_path), &[pg::HIDDEN_PREFIX], "with");
    }

    /// §7.2 item 8 (R5, §2.6): no counter-bearing field anywhere in the
    /// manifest.
    #[tokio::test]
    async fn manifest_has_no_counter_fields() {
        let world = fixtures::two_caller::build().await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.db");
        let copy = build_member_copy(&world.db, request(fixtures::ACCT_A, "s", &path))
            .await
            .unwrap();
        let value = serde_json::to_value(&copy.manifest).unwrap();
        assert_no_counter_fields(&value, "member manifest");
        // Non-tautological (F5): the scan must actually catch a planted
        // counter, so a passing real manifest means something.
        let mut planted_key = value.clone();
        planted_key["as_of_seq"] = serde_json::json!(9);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                assert_no_counter_fields(&planted_key, "planted key");
            }))
            .is_err(),
            "the scan must catch a planted counter key"
        );
        let mut planted_token = value.clone();
        planted_token["opaque"] = serde_json::json!("rec:123");
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                assert_no_counter_fields(&planted_token, "planted token");
            }))
            .is_err(),
            "the scan must catch a planted rec: token"
        );
    }

    #[tokio::test]
    async fn building_twice_is_deterministic() {
        let world = fixtures::two_caller::build().await;
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("one.db");
        let second = dir.path().join("two.db");
        let a = build_member_copy(&world.db, request(fixtures::ACCT_A, "s", &first))
            .await
            .unwrap();
        let b = build_member_copy(&world.db, request(fixtures::ACCT_A, "s", &second))
            .await
            .unwrap();
        assert_eq!(a.content_digest, b.content_digest);
    }

    /// F4: VACUUM is physical only; the content digest is unchanged by it.
    #[tokio::test]
    async fn vacuum_preserves_content_digest() {
        let world = fixtures::two_caller::build().await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.db");
        let copy = build_member_copy(&world.db, request(fixtures::ACCT_A, "s", &path))
            .await
            .unwrap();
        let connection = open_copy(&path);
        let before = content_digest(&connection).unwrap();
        connection.execute_batch("VACUUM;").unwrap();
        let after = content_digest(&connection).unwrap();
        assert_eq!(before, after, "VACUUM must not change the content digest");
        assert_eq!(copy.content_digest, after);
    }

    /// §7.2 item 1 (Q6c/R1a): a hidden record sharing a 7-hex prefix with a
    /// visible one lengthens the visible record's display reference at online
    /// parity; nothing beyond the shared prefix leaks.
    #[tokio::test]
    async fn hidden_prefix_lengthens_visible_display_reference() {
        use crate::authorization::{AllowEntry, Capability};
        use crate::schema::ROOT_RECORD_ID;
        const PERSON_A: &str = "e5000000-0000-4000-8000-0000000000a1";
        const PERSON_B: &str = "e5000000-0000-4000-8000-0000000000b1";
        const VISIBLE: &str = "d4000000-0000-4000-8000-000000000001";
        // Shares "d400000" with VISIBLE, then differs at hex index 7.
        const HIDDEN: &str = "d400000f-0000-4000-8000-000000000001";

        let db = crate::db::create_database(":memory:").await.unwrap();
        fixtures::create_member(&db, PERSON_A, fixtures::ACCT_A).await;
        fixtures::create_member(&db, PERSON_B, fixtures::ACCT_B).await;
        fixtures::grant(&db, PERSON_A, vec![AllowEntry::members(Capability::View)]).await;
        fixtures::grant(&db, PERSON_B, vec![AllowEntry::members(Capability::View)]).await;
        fixtures::mk_doc(&db, VISIBLE, ROOT_RECORD_ID, None, None).await;
        fixtures::grant(&db, VISIBLE, vec![AllowEntry::members(Capability::View)]).await;

        let dir = tempfile::tempdir().unwrap();
        let before_path = dir.path().join("before.db");
        build_member_copy(&db, request(fixtures::ACCT_A, "s", &before_path))
            .await
            .unwrap();
        assert_eq!(
            display_reference_of(&before_path, VISIBLE).as_deref(),
            Some("d400000"),
            "without a sibling the reference is the 7-hex minimum"
        );

        // Hidden from A: granted to B only, so it is in main.records but not
        // E(A) — the prefix corpus still sees it (online parity).
        fixtures::mk_doc(&db, HIDDEN, ROOT_RECORD_ID, None, None).await;
        fixtures::grant(
            &db,
            HIDDEN,
            vec![AllowEntry::account(fixtures::ACCT_B, Capability::View)],
        )
        .await;
        let after_path = dir.path().join("after.db");
        build_member_copy(&db, request(fixtures::ACCT_A, "s", &after_path))
            .await
            .unwrap();
        assert_eq!(
            display_reference_of(&after_path, VISIBLE).as_deref(),
            Some("d4000000"),
            "a hidden sibling must lengthen the visible reference"
        );
        assert_absent(&file_bytes(&after_path), &[HIDDEN], "hidden prefix");
    }
}
