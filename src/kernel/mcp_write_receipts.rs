//! Private, immutable keyed outcomes carried by the canonical content log.
//! A receipt-only success advances an act without changing a domain record.
use super::*;
pub(crate) mod fences;
use crate::act::ActAllocation;
use serde_json::{json, Value};

pub(crate) const STREAM: &str = "kernel:mcp-write-receipts";
pub(crate) const EVENT: &str = "kernel.mcp_write_receipt_recorded.v1";
pub(crate) const INDEX: &str = "idx_kernel_mcp_write_receipt_events";
pub(crate) const INDEX_DDL: &str = "CREATE INDEX IF NOT EXISTS idx_kernel_mcp_write_receipt_events ON content_events(actor,CAST(json_extract(payload,'$.operation') AS TEXT),CAST(json_extract(payload,'$.operation_key') AS TEXT),seq) WHERE record_id='kernel:mcp-write-receipts' AND type='kernel.mcp_write_receipt_recorded.v1'";

// These expression indexes are optional accelerators, created lazily for
// ordinary receipts. The unhinted constants are safe cold fallbacks; use
// indexed_sql_on on the caller snapshot to avoid parsing wide rows when indexed.
pub(crate) const ACCEPTED_LOOKUP_SQL: &str = "SELECT id,type,payload FROM main.content_events WHERE record_id='kernel:mcp-write-receipts' AND type='kernel.mcp_write_receipt_recorded.v1' AND actor=? AND CAST(json_extract(payload,'$.operation') AS TEXT)=? AND CAST(json_extract(payload,'$.operation_key') AS TEXT)=? ORDER BY seq LIMIT 2";
const FACT_LOOKUP_SQL: &str = "SELECT payload FROM main.content_events WHERE record_id='kernel:mcp-write-receipts' AND type='kernel.mcp_write_receipt_recorded.v1' AND actor=? AND CAST(json_extract(payload,'$.operation') AS TEXT)=? AND CAST(json_extract(payload,'$.operation_key') AS TEXT)=? ORDER BY seq DESC LIMIT 1";

// These are the existing adapter fingerprints. In particular attachment bytes
// are digested before they enter either the ledger or the receipt event.
fn request_fingerprint(tool: &str, mut request: Value) -> Result<String> {
    if !request.is_object() {
        return Err(Error::engine("kernel-v2 write: expected object"));
    }
    request.as_object_mut().unwrap().remove("idempotency_key");
    if tool == "attach_text" {
        if let Some(text) = request["text"].as_str() {
            use sha2::{Digest, Sha256};
            request["text"] = json!({"sha256":hex::encode(Sha256::digest(text.as_bytes())),"size_bytes":text.len()});
        }
    }
    request.sort_all_objects();
    Ok(serde_json::to_string(&request)?)
}

pub(crate) fn intent_fingerprint(tool: &str, request: Value, app: Value) -> Result<String> {
    let arguments: Value = serde_json::from_str(&request_fingerprint(tool, request)?)?;
    let mut intent = json!({"schema":"kernel.mcp.intent.v1", "app":app, "arguments":arguments});
    intent.sort_all_objects();
    Ok(serde_json::to_string(&intent)?)
}

pub(crate) fn stored_fingerprint(tool: &str, request: Value) -> Result<String> {
    if request["schema"] == "kernel.mcp.intent.v1" {
        intent_fingerprint(tool, request["arguments"].clone(), request["app"].clone())
    } else {
        intent_fingerprint(tool, request, Value::Null)
    }
}

pub(super) fn normalized_request(operation: &str, raw: &str) -> Result<String> {
    let value = serde_json::from_str(raw)?;
    match operation {
        "attach_text" | "create_record" | "update_record" | "manage_links" | "archive_record"
        | "batch_write" | "merge_body" | "attach_from_url" => stored_fingerprint(operation, value),
        op if op.starts_with("manage_named_views.") => {
            stored_fingerprint("manage_named_views", value)
        }
        // Image insertion and suggestion resolution have distinct established
        // formats; do not wrap them in the ordinary adapter's intent envelope.
        _ => Ok(raw.to_owned()),
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Fact {
    pub(super) operation: String,
    pub(super) operation_key: String,
    pub(super) request_json: String,
    pub(super) receipt_json: String,
}

pub(crate) struct Outcome<'a> {
    pub principal: &'a str,
    pub operation: &'a str,
    pub key: &'a str,
    pub request: &'a str,
    pub receipt: &'a str,
}

pub(crate) async fn ensure_schema(conn: &mut SqliteConnection) -> Result<()> {
    sqlx::query(MCP_WRITE_RECEIPTS_DDL)
        .execute(&mut *conn)
        .await?;
    sqlx::query(INDEX_DDL).execute(&mut *conn).await?;
    fences::install_guards_on(conn).await?;
    Ok(())
}

fn validate(principal: &str, fact: &Fact) -> Result<()> {
    if principal.is_empty() || fact.operation.is_empty() || fact.operation_key.trim().is_empty() {
        return Err(Error::engine("invalid kernel keyed outcome identity"));
    }
    let _: Value = serde_json::from_str(&fact.receipt_json)?;
    if normalized_request(&fact.operation, &fact.request_json)? != fact.request_json {
        return Err(Error::engine(
            "kernel keyed outcome request is not normalized",
        ));
    }
    Ok(())
}

async fn fact_on(
    conn: &mut SqliteConnection,
    principal: &str,
    operation: &str,
    key: &str,
) -> Result<Option<Fact>> {
    let query = indexed_sql_on(conn, FACT_LOOKUP_SQL, "main.content_events", INDEX).await?;
    let raw: Option<String> = sqlx::query_scalar(&query)
        .bind(principal)
        .bind(operation)
        .bind(key)
        .fetch_optional(conn)
        .await?;
    raw.map(|raw| serde_json::from_str(&raw).map_err(Into::into))
        .transpose()
}

#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn observe_ordinary_receipt_on(
    conn: &mut SqliteConnection,
    principal: &str,
    operation: &str,
    key: &str,
) -> Result<Option<(String, String)>> {
    if fences::typed_on(conn).await? {
        use super::original_settlement::KeyedOutcome;
        return match super::original_settlement::lookup_outcome_on(conn, principal, operation, key)
            .await?
        {
            KeyedOutcome::Absent => Ok(None),
            KeyedOutcome::Accepted {
                request, receipt, ..
            } => Ok(Some((request, receipt))),
            KeyedOutcome::Terminal { .. } => {
                Err(Error::conflict("release outbox key is terminally fenced"))
            }
        };
    }
    let row: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT request_json,receipt_json FROM kernel_mcp_write_receipts
         WHERE principal_id=? AND operation=? AND operation_key=?",
    )
    .bind(principal)
    .bind(operation)
    .bind(key)
    .fetch_optional(&mut *conn)
    .await?;
    let fact = fact_on(conn, principal, operation, key).await?;
    match (row, fact) {
        (None, None) => Ok(None),
        (Some((request, Some(receipt))), Some(fact))
            if fact.operation == operation
                && fact.operation_key == key
                && normalized_request(operation, &request)? == fact.request_json
                && receipt == fact.receipt_json =>
        {
            Ok(Some((fact.request_json, receipt)))
        }
        _ => Err(Error::engine("kernel keyed receipt cannot be reconciled")),
    }
}

async fn fold_row(conn: &mut SqliteConnection, principal: &str, fact: &Fact) -> Result<()> {
    validate(principal, fact)?;
    fences::refuse_key_on(conn, principal, &fact.operation, &fact.operation_key).await?;
    let previous: Option<(String, String)> = sqlx::query_as("SELECT request_json,receipt_json FROM kernel_mcp_write_receipts WHERE principal_id=? AND operation=? AND operation_key=?")
        .bind(principal).bind(&fact.operation).bind(&fact.operation_key).fetch_optional(&mut *conn).await?;
    if let Some((request, receipt)) = previous {
        if receipt != fact.receipt_json
            || normalized_request(&fact.operation, &request)? != fact.request_json
        {
            return Err(Error::conflict("conflicting kernel keyed outcome"));
        }
    }
    // A legacy full-text request can become only its equivalent compact
    // fingerprint. The original response bytes are immutable.
    let insert = if fences::typed_on(conn).await? {
        "INSERT INTO kernel_mcp_write_receipts (principal_id,operation,operation_key,request_json,receipt_json,outcome_kind) VALUES(?,?,?,?,?,'accepted') ON CONFLICT(principal_id,operation,operation_key) DO UPDATE SET request_json=excluded.request_json"
    } else {
        "INSERT INTO kernel_mcp_write_receipts (principal_id,operation,operation_key,request_json,receipt_json) VALUES(?,?,?,?,?) ON CONFLICT(principal_id,operation,operation_key) DO UPDATE SET request_json=excluded.request_json"
    };
    sqlx::query(insert)
        .bind(principal)
        .bind(&fact.operation)
        .bind(&fact.operation_key)
        .bind(&fact.request_json)
        .bind(&fact.receipt_json)
        .execute(conn)
        .await?;
    Ok(())
}

pub(crate) async fn project(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    let fact: Fact = event_payload(event)?;
    if event.record_id != STREAM || event.event_type != EVENT {
        return Err(Error::engine("invalid kernel keyed outcome stream"));
    }
    ensure_schema(conn).await?;
    fold_row(conn, event.actor.as_deref().unwrap_or_default(), &fact).await
}

pub(crate) async fn record_on(
    db: &Db,
    conn: &mut SqliteConnection,
    acts: &mut ActAllocation,
    outcome: Outcome<'_>,
) -> Result<()> {
    ensure_schema(conn).await?;
    fences::refuse_key_on(conn, outcome.principal, outcome.operation, outcome.key).await?;
    let fact = Fact {
        operation: outcome.operation.into(),
        operation_key: outcome.key.into(),
        request_json: normalized_request(outcome.operation, outcome.request)?,
        receipt_json: outcome.receipt.into(),
    };
    validate(outcome.principal, &fact)?;
    if let Some(old) = fact_on(conn, outcome.principal, outcome.operation, outcome.key).await? {
        if old.request_json != fact.request_json || old.receipt_json != fact.receipt_json {
            return Err(Error::conflict("conflicting kernel keyed outcome history"));
        }
        // Current-policy admission belongs to the calling writer. Repairing
        // an equivalent legacy fingerprint appends no duplicate fact or act.
        return fold_row(conn, outcome.principal, &old).await;
    }
    crate::store::append_kernel_mcp_receipt_on(
        db,
        conn,
        AppendSpec {
            record_id: STREAM.into(),
            event_type: EVENT.into(),
            payload: serde_json::to_value(fact)?,
            actor: Some(outcome.principal.into()),
        },
        acts,
    )
    .await?;
    Ok(())
}

/// Canonical maintenance only. Neither serving reads nor standby apply may
/// manufacture missing canonical receipt events from an unverified ledger.
pub(crate) async fn prepare(db: &Db) -> Result<()> {
    let mut tx = begin_write(db.write_pool()).await?;
    ensure_schema(&mut tx).await?;
    let typed = fences::typed_on(&mut tx).await?;
    let mut after = (String::new(), String::new(), String::new());
    let mut acts = ActAllocation::new();
    loop {
        let rows: Vec<(String,String,String,String,String)> = sqlx::query_as(if typed { "SELECT principal_id,operation,operation_key,request_json,receipt_json FROM kernel_mcp_write_receipts WHERE outcome_kind='accepted' AND (principal_id,operation,operation_key)>(?,?,?) ORDER BY principal_id,operation,operation_key LIMIT 32" } else { "SELECT principal_id,operation,operation_key,request_json,receipt_json FROM kernel_mcp_write_receipts WHERE (principal_id,operation,operation_key)>(?,?,?) ORDER BY principal_id,operation,operation_key LIMIT 32" })
            .bind(&after.0).bind(&after.1).bind(&after.2).fetch_all(&mut *tx).await?;
        if rows.is_empty() {
            break;
        }
        for (principal, operation, key, request, receipt) in rows {
            record_on(
                db,
                &mut tx,
                &mut acts,
                Outcome {
                    principal: &principal,
                    operation: &operation,
                    key: &key,
                    request: &request,
                    receipt: &receipt,
                },
            )
            .await?;
            after = (principal, operation, key);
        }
    }
    // Also recover a missing projection row from an existing canonical fact.
    let mut after_seq = 0_i64;
    loop {
        let rows: Vec<(i64,Option<String>,String)> = sqlx::query_as("SELECT seq,actor,payload FROM content_events WHERE record_id='kernel:mcp-write-receipts' AND type='kernel.mcp_write_receipt_recorded.v1' AND seq>? ORDER BY seq LIMIT 32")
            .bind(after_seq).fetch_all(&mut *tx).await?;
        if rows.is_empty() {
            break;
        }
        for (seq, principal, raw) in rows {
            let fact: Fact = serde_json::from_str(&raw)?;
            fold_row(&mut tx, principal.as_deref().unwrap_or_default(), &fact).await?;
            after_seq = seq;
        }
    }
    if typed {
        fences::repair_on(&mut tx).await?;
    }
    db.commit_kernel_content(tx).await?;
    Ok(())
}

/// Explicit, gated maintenance only. Ordinary schema creation and preparation
/// must retain format 1. The hosting operator supplies the separate opt-in after
/// freezing/draining and verifying its preimage; W must never call this lazily.
pub(crate) async fn prepare_typed(db: &Db, enabled: bool) -> Result<()> {
    if !enabled {
        return Err(Error::auth("settlement_preparation_disabled"));
    }
    let marker: i64 = sqlx::query_scalar("PRAGMA application_id")
        .fetch_one(db.pool())
        .await?;
    if marker != crate::db::V2_APPLICATION_ID {
        return Err(Error::engine(
            "settlement preparation requires an existing v2 database",
        ));
    }
    prepare(db).await?;
    let mut tx = begin_write(db.write_pool()).await?;
    let marker: i64 = sqlx::query_scalar("PRAGMA application_id")
        .fetch_one(&mut *tx)
        .await?;
    if marker != crate::db::V2_APPLICATION_ID {
        return Err(Error::engine(
            "settlement preparation requires an existing v2 database",
        ));
    }
    ensure_schema(&mut tx).await?;
    if !fences::typed_on(&mut tx).await? {
        sqlx::query("ALTER TABLE kernel_mcp_write_receipts RENAME TO kernel_mcp_write_receipts_legacy_migration").execute(&mut *tx).await?;
        sqlx::query(MCP_TYPED_WRITE_RECEIPTS_DDL)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO kernel_mcp_write_receipts(principal_id,operation,operation_key,request_json,receipt_json,outcome_kind) SELECT principal_id,operation,operation_key,request_json,receipt_json,'accepted' FROM kernel_mcp_write_receipts_legacy_migration").execute(&mut *tx).await?;
        sqlx::query("DROP TABLE kernel_mcp_write_receipts_legacy_migration")
            .execute(&mut *tx)
            .await?;
        fences::install_guards_on(&mut tx).await?;
    }
    fences::install_guards_on(&mut tx).await?;
    require_covered_on(&mut tx).await?;
    super::verify_v2_ready_on(&mut tx).await?;
    tx.commit().await?;
    Ok(())
}

/// Export is read-only and refuses legacy rows until explicit canonical
/// preparation has recorded them. An old event cursor cannot silently omit
/// outcomes created before this build.
pub(crate) async fn require_profile_on(conn: &mut SqliteConnection) -> Result<()> {
    let present: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='kernel_mcp_write_receipts')").fetch_one(&mut *conn).await?;
    if !present {
        return Err(Error::engine("kernel receipt profile requires explicit canonical preparation and a fresh FULL capture"));
    }
    Ok(())
}

/// With their indexes present, head observations check key identities without
/// reading potentially MiB-sized request/response bodies. A head is a coordinate, never a projection-byte
/// certificate. Exact payload coverage remains mandatory on cuts and FULLs.
const HEAD_MISSING_SQL: &str = "SELECT EXISTS(SELECT 1 FROM kernel_mcp_write_receipts r WHERE NOT EXISTS(SELECT 1 FROM main.content_events accepted WHERE accepted.record_id='kernel:mcp-write-receipts' AND accepted.type='kernel.mcp_write_receipt_recorded.v1' AND accepted.actor=r.principal_id AND CAST(json_extract(accepted.payload,'$.operation') AS TEXT)=r.operation AND CAST(json_extract(accepted.payload,'$.operation_key') AS TEXT)=r.operation_key) AND NOT EXISTS(SELECT 1 FROM main.content_events fenced WHERE fenced.record_id='kernel:mcp-write-receipts' AND fenced.type='kernel.mcp_write_fenced.v1' AND fenced.actor=r.principal_id AND CAST(json_extract(fenced.payload,'$.operation') AS TEXT)=r.operation AND CAST(json_extract(fenced.payload,'$.operation_key') AS TEXT)=r.operation_key))";
const LEGACY_HEAD_MISSING_SQL: &str = "SELECT EXISTS(SELECT 1 FROM kernel_mcp_write_receipts r WHERE NOT EXISTS(SELECT 1 FROM main.content_events accepted WHERE accepted.record_id='kernel:mcp-write-receipts' AND accepted.type='kernel.mcp_write_receipt_recorded.v1' AND accepted.actor=r.principal_id AND CAST(json_extract(accepted.payload,'$.operation') AS TEXT)=r.operation AND CAST(json_extract(accepted.payload,'$.operation_key') AS TEXT)=r.operation_key))";
const HEAD_ORPHAN_SQL: &str = "SELECT EXISTS(SELECT 1 FROM main.content_events accepted WHERE accepted.record_id='kernel:mcp-write-receipts' AND accepted.type='kernel.mcp_write_receipt_recorded.v1' AND NOT EXISTS(SELECT 1 FROM kernel_mcp_write_receipts r WHERE r.principal_id=accepted.actor AND r.operation=CAST(json_extract(accepted.payload,'$.operation') AS TEXT) AND r.operation_key=CAST(json_extract(accepted.payload,'$.operation_key') AS TEXT))) OR EXISTS(SELECT 1 FROM main.content_events fenced WHERE fenced.record_id='kernel:mcp-write-receipts' AND fenced.type='kernel.mcp_write_fenced.v1' AND NOT EXISTS(SELECT 1 FROM kernel_mcp_write_receipts r WHERE r.principal_id=fenced.actor AND r.operation=CAST(json_extract(fenced.payload,'$.operation') AS TEXT) AND r.operation_key=CAST(json_extract(fenced.payload,'$.operation_key') AS TEXT)))";
const LEGACY_HEAD_ORPHAN_SQL: &str = "SELECT EXISTS(SELECT 1 FROM main.content_events accepted WHERE accepted.record_id='kernel:mcp-write-receipts' AND accepted.type='kernel.mcp_write_receipt_recorded.v1' AND NOT EXISTS(SELECT 1 FROM kernel_mcp_write_receipts r WHERE r.principal_id=accepted.actor AND r.operation=CAST(json_extract(accepted.payload,'$.operation') AS TEXT) AND r.operation_key=CAST(json_extract(accepted.payload,'$.operation_key') AS TEXT)))";

pub(crate) async fn require_head_identity_coverage_on(conn: &mut SqliteConnection) -> Result<()> {
    require_profile_on(conn).await?;
    let typed = fences::typed_on(conn).await?;
    let (missing_query, orphan_query) = head_coverage_sql_on(conn, typed).await?;
    let missing: bool = sqlx::query_scalar(&missing_query)
        .fetch_one(&mut *conn)
        .await?;
    let orphan: bool = sqlx::query_scalar(&orphan_query).fetch_one(conn).await?;
    if missing || orphan {
        return Err(Error::engine("kernel keyed outcome identities require explicit canonical preparation before standby head observation"));
    }
    Ok(())
}

#[derive(sqlx::FromRow)]
struct CoverageRow {
    actor: Option<String>,
    payload: String,
    request_json: Option<String>,
    receipt_json: Option<String>,
    outcome_kind: Option<String>,
    terminal_json: Option<String>,
    retired_record_id: Option<String>,
}

/// One ordered canonical pass per event family, joined by the projection
/// primary key. Use the accelerator when present, or scan safely before lazy
/// creation. Never rescan the receipt stream for each fence.
pub(crate) async fn require_covered_on(conn: &mut SqliteConnection) -> Result<()> {
    use futures::TryStreamExt;
    require_profile_on(conn).await?;
    let typed = fences::typed_on(conn).await?;
    if !typed {
        let fences: bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.content_events WHERE record_id='kernel:mcp-write-receipts' AND type='kernel.mcp_write_fenced.v1')").fetch_one(&mut *conn).await?;
        if fences {
            return Err(Error::engine(
                "legacy keyed outcome profile contains terminal facts",
            ));
        }
    }
    let mut count = 0_i64;
    for terminal in [false, true] {
        if terminal && !typed {
            continue;
        }
        let query = coverage_sql_on(conn, terminal, typed).await?;
        let mut rows = sqlx::query_as::<_, CoverageRow>(&query).fetch(&mut *conn);
        let mut previous = None;
        while let Some(row) = rows.try_next().await? {
            let actor = row.actor.as_deref().unwrap_or_default();
            let (operation, key) = if terminal {
                let f: fences::FenceFact = serde_json::from_str(&row.payload)?;
                crate::kernel::original_settlement::validate_fact(&f, actor)?;
                if row.request_json.as_deref() != Some(f.request_json.as_str())
                    || row.receipt_json.is_some()
                    || row.outcome_kind.as_deref() != Some("unapplied_terminal")
                    || row.terminal_json.as_deref()
                        != Some(serde_jcs::to_string(&f.terminal)?.as_str())
                    || row.retired_record_id != f.terminal.retired_record_id
                {
                    return Err(Error::engine("terminal outcome coverage differs"));
                }
                (f.operation, f.operation_key)
            } else {
                let f: Fact = serde_json::from_str(&row.payload)?;
                validate(actor, &f)?;
                if row.request_json.as_deref() != Some(f.request_json.as_str())
                    || row.receipt_json.as_deref() != Some(f.receipt_json.as_str())
                    || row.outcome_kind.as_deref() != Some("accepted")
                    || row.terminal_json.is_some()
                    || row.retired_record_id.is_some()
                {
                    return Err(Error::engine("accepted outcome coverage differs"));
                }
                (f.operation, f.operation_key)
            };
            let key = (actor.to_owned(), operation, key);
            if previous.as_ref() == Some(&key) {
                return Err(Error::engine("duplicate canonical keyed outcome"));
            }
            previous = Some(key);
            count += 1;
        }
    }
    let projected: i64 = sqlx::query_scalar("SELECT count(*) FROM main.kernel_mcp_write_receipts")
        .fetch_one(conn)
        .await?;
    if projected != count {
        return Err(Error::engine("keyed outcome projection has uncarried rows"));
    }
    Ok(())
}

pub(crate) fn coverage_sql(terminal: bool, typed: bool) -> String {
    let event = if terminal { fences::EVENT } else { EVENT };
    let columns = if typed {
        "r.outcome_kind,r.terminal_json,r.retired_record_id"
    } else {
        "'accepted' AS outcome_kind,NULL AS terminal_json,NULL AS retired_record_id"
    };
    format!("SELECT e.actor,e.payload,r.request_json,r.receipt_json,{columns} FROM main.content_events e LEFT JOIN main.kernel_mcp_write_receipts r ON r.principal_id=e.actor AND r.operation=CAST(json_extract(e.payload,'$.operation') AS TEXT) AND r.operation_key=CAST(json_extract(e.payload,'$.operation_key') AS TEXT) WHERE e.record_id='kernel:mcp-write-receipts' AND e.type='{event}' ORDER BY e.actor,CAST(json_extract(e.payload,'$.operation') AS TEXT),CAST(json_extract(e.payload,'$.operation_key') AS TEXT),e.seq")
}

// Index hints are an optimization, never authority or a schema prerequisite.
// The catalog read pins the caller transaction's schema before a hinted query.
// Bare connections and missing indexes use unhinted SQL: that cold path may
// scan and parse canonical JSON (per projected key for head coverage), and may
// sort for exact coverage. It never creates indexes or changes reader format.
async fn indexed_source_on(
    conn: &mut SqliteConnection,
    source: &str,
    index: &str,
) -> Result<String> {
    use sqlx::{sqlite::SqliteTransactionManager, TransactionManager};
    if SqliteTransactionManager::get_transaction_depth(conn) == 0 {
        return Ok(source.into());
    }
    let present: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM main.sqlite_schema WHERE type='index' AND name=?)",
    )
    .bind(index)
    .fetch_one(&mut *conn)
    .await?;
    Ok(if present {
        format!("{source} INDEXED BY {index}")
    } else {
        source.into()
    })
}

pub(super) async fn indexed_sql_on(
    conn: &mut SqliteConnection,
    query: &str,
    source: &str,
    index: &str,
) -> Result<String> {
    let indexed = indexed_source_on(conn, source, index).await?;
    Ok(query.replacen(&format!("FROM {source}"), &format!("FROM {indexed}"), 1))
}

async fn head_coverage_sql_on(
    conn: &mut SqliteConnection,
    typed: bool,
) -> Result<(String, String)> {
    let (mut missing, mut orphan) = if typed {
        (HEAD_MISSING_SQL.to_owned(), HEAD_ORPHAN_SQL.to_owned())
    } else {
        (
            LEGACY_HEAD_MISSING_SQL.to_owned(),
            LEGACY_HEAD_ORPHAN_SQL.to_owned(),
        )
    };
    for (source, index) in [
        ("main.content_events accepted", INDEX),
        (
            "main.content_events fenced",
            "idx_kernel_mcp_write_fence_events",
        ),
    ] {
        if !typed && source.ends_with(" fenced") {
            continue;
        }
        let indexed = indexed_source_on(conn, source, index).await?;
        missing = missing.replacen(&format!("FROM {source}"), &format!("FROM {indexed}"), 1);
        orphan = orphan.replacen(&format!("FROM {source}"), &format!("FROM {indexed}"), 1);
    }
    Ok((missing, orphan))
}

async fn coverage_sql_on(
    conn: &mut SqliteConnection,
    terminal: bool,
    typed: bool,
) -> Result<String> {
    let index = if terminal {
        "idx_kernel_mcp_write_fence_events"
    } else {
        INDEX
    };
    indexed_sql_on(
        conn,
        &coverage_sql(terminal, typed),
        "main.content_events e",
        index,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Connection as _;

    async fn fixture() -> (Db, String) {
        let (db, principal) = create_v2_database(":memory:", "account", "Owner", "acct:owner")
            .await
            .unwrap();
        prepare_typed(&db, true).await.unwrap();
        (db, principal)
    }

    #[tokio::test]
    async fn original_settlement_query_plans_use_namespace_and_retirement_indexes() {
        let (db, _) = fixture().await;
        let mut conn = db.write_pool().acquire().await.unwrap();
        // Planner-only rows: no projection or settlement consumes these facts.
        // A forced INDEXED BY made the old empty-stream assertion tautological.
        // Qualify the optimizer's actual choice on a substantial namespace mix;
        // a tiny/empty stream may legitimately use the generic event index.
        sqlx::query("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<2000), kinds(t) AS (VALUES('kernel.mcp_write_receipt_recorded.v1'),('kernel.mcp_write_fenced.v1')) INSERT INTO content_events(id,record_id,type,payload,actor,causal_envelope_version,causal_status) SELECT 'plan:'||t||':'||x,'kernel:mcp-write-receipts',t,json_object('operation','update_record','operation_key','key:'||x),'actor:'||(x%50),1,'legacy_unknown' FROM n CROSS JOIN kinds")
            .execute(&mut *conn).await.unwrap();
        sqlx::query("ANALYZE main.content_events")
            .execute(&mut *conn)
            .await
            .unwrap();
        for (sql, index, bindings) in [
            (ACCEPTED_LOOKUP_SQL.to_owned(), INDEX, 3),
            (
                fences::LOOKUP_SQL.to_owned(),
                "idx_kernel_mcp_write_fence_events",
                3,
            ),
            (
                fences::RETIRED_LOOKUP_SQL.to_owned(),
                "idx_kernel_mcp_retired_record_id",
                1,
            ),
        ] {
            let query = format!("EXPLAIN QUERY PLAN {sql}");
            let mut q = sqlx::query_as::<_, (i64, i64, i64, String)>(&query);
            for _ in 0..bindings {
                q = q.bind("probe");
            }
            let plan = q
                .fetch_all(&mut *conn)
                .await
                .unwrap()
                .into_iter()
                .map(|r| r.3)
                .collect::<Vec<_>>()
                .join("\n");
            println!("{index}: {plan}");
            assert!(plan.contains("SEARCH") && plan.contains(index), "{plan}");
            assert!(
                !plan.contains("SCAN") && !plan.contains("TEMP B-TREE"),
                "{plan}"
            );
        }
        let mut tx = conn.begin().await.unwrap();
        for terminal in [false, true] {
            let query = format!(
                "EXPLAIN QUERY PLAN {}",
                coverage_sql_on(&mut tx, terminal, true).await.unwrap()
            );
            let plan = sqlx::query_as::<_, (i64, i64, i64, String)>(&query)
                .fetch_all(&mut *tx)
                .await
                .unwrap()
                .into_iter()
                .map(|r| r.3)
                .collect::<Vec<_>>()
                .join("\n");
            println!("coverage terminal={terminal}: {plan}");
            // One ordered canonical scan, one indexed projection lookup per
            // fact; no correlated per-fence scan of the canonical stream.
            assert!(
                plan.contains(if terminal {
                    "idx_kernel_mcp_write_fence_events"
                } else {
                    INDEX
                }),
                "{plan}"
            );
            assert!(
                plan.contains("SEARCH r USING INDEX sqlite_autoindex_kernel_mcp_write_receipts_1"),
                "{plan}"
            );
            assert!(
                !plan.contains("CORRELATED") && !plan.contains("TEMP B-TREE"),
                "{plan}"
            );
        }
        tx.rollback().await.unwrap();
    }

    async fn receipt(db: &Db, principal: &str) {
        let mut tx = begin_write(db.write_pool()).await.unwrap();
        record_on(
            db,
            &mut tx,
            &mut ActAllocation::new(),
            Outcome {
                principal,
                operation: "resolve_suggestions",
                key: "original",
                request: "{}",
                receipt: "{\"z\":1,\"a\":2}",
            },
        )
        .await
        .unwrap();
        db.commit_kernel_content(tx).await.unwrap();
    }

    #[tokio::test]
    async fn receipt_only_outcome_advances_one_act_and_rebuilds_exact_bytes() {
        let (db, principal) = fixture().await;
        let before: i64 = sqlx::query_scalar("SELECT next_act FROM act_state WHERE singleton=1")
            .fetch_one(db.pool())
            .await
            .unwrap();
        receipt(&db, &principal).await;
        let after: i64 = sqlx::query_scalar("SELECT next_act FROM act_state WHERE singleton=1")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(after, before + 1);
        let original = projection_dump::dump(&db).await.unwrap();
        replay_all_projections(&db).await.unwrap();
        assert_eq!(projection_dump::dump(&db).await.unwrap(), original);
        let raw: String = sqlx::query_scalar(
            "SELECT receipt_json FROM kernel_mcp_write_receipts WHERE operation_key='original'",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(raw, "{\"z\":1,\"a\":2}");
        db.close().await;
    }

    #[tokio::test]
    async fn canonical_backfill_compacts_legacy_attachment_before_recording() {
        let (db, principal) = fixture().await;
        ensure_schema(&mut db.write_pool().acquire().await.unwrap())
            .await
            .unwrap();
        let request = json!({"text":"private legacy attachment bytes","record_id":"target","reason":"reason"}).to_string();
        sqlx::query("INSERT INTO kernel_mcp_write_receipts(principal_id,operation,operation_key,request_json,receipt_json,outcome_kind) VALUES(?,'attach_text','legacy',?,?,'accepted')")
            .bind(&principal)
            .bind(&request)
            .bind("{\"original\":true}")
            .execute(db.write_pool())
            .await
            .unwrap();
        let mut conn = db.pool().acquire().await.unwrap();
        assert!(require_covered_on(&mut conn).await.is_err());
        drop(conn);
        prepare(&db).await.unwrap();
        let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        prepare(&db).await.unwrap();
        let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(before, after);
        let payload: String = sqlx::query_scalar("SELECT payload FROM content_events WHERE type=?")
            .bind(EVENT)
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert!(!payload.contains("private legacy attachment bytes"));
        assert!(payload.contains("sha256"));
        let mut conn = db.pool().acquire().await.unwrap();
        require_covered_on(&mut conn).await.unwrap();
        drop(conn);
        db.close().await;
    }

    #[tokio::test]
    async fn coverage_refuses_deleted_projection_and_conflicting_response() {
        let (db, principal) = fixture().await;
        receipt(&db, &principal).await;
        sqlx::query("DELETE FROM kernel_mcp_write_receipts")
            .execute(db.write_pool())
            .await
            .unwrap();
        let mut conn = db.pool().acquire().await.unwrap();
        assert!(require_covered_on(&mut conn).await.is_err());
        drop(conn);
        prepare(&db).await.unwrap();
        sqlx::query("DROP TRIGGER kernel_mcp_outcome_immutable")
            .execute(db.write_pool())
            .await
            .unwrap();
        sqlx::query("UPDATE kernel_mcp_write_receipts SET receipt_json='{}'")
            .execute(db.write_pool())
            .await
            .unwrap();
        assert!(
            prepare(&db).await.is_err(),
            "maintenance must not bless a response conflicting with canonical history"
        );
        let mut conn = db.pool().acquire().await.unwrap();
        assert!(require_covered_on(&mut conn).await.is_err());
        drop(conn);
        db.close().await;
    }

    #[tokio::test]
    async fn canonical_backfill_failure_rolls_back_all_rows_and_act() {
        let (db, principal) = fixture().await;
        ensure_schema(&mut db.write_pool().acquire().await.unwrap())
            .await
            .unwrap();
        for key in ["a", "b"] {
            sqlx::query(
                "INSERT INTO kernel_mcp_write_receipts(principal_id,operation,operation_key,request_json,receipt_json,outcome_kind) VALUES(?,'update_record',?,'{}','{}','accepted')",
            )
            .bind(&principal)
            .bind(key)
            .execute(db.write_pool())
            .await
            .unwrap();
        }
        let before: (i64,i64) = sqlx::query_as("SELECT (SELECT COUNT(*) FROM content_events),(SELECT next_act FROM act_state WHERE singleton=1)").fetch_one(db.pool()).await.unwrap();
        sqlx::query("CREATE TRIGGER fail_second_receipt BEFORE INSERT ON content_events WHEN NEW.type='kernel.mcp_write_receipt_recorded.v1' AND json_extract(NEW.payload,'$.operation_key')='b' BEGIN SELECT RAISE(ABORT,'injected receipt failure'); END").execute(db.write_pool()).await.unwrap();
        assert!(prepare(&db).await.is_err());
        let after: (i64,i64) = sqlx::query_as("SELECT (SELECT COUNT(*) FROM content_events),(SELECT next_act FROM act_state WHERE singleton=1)").fetch_one(db.pool()).await.unwrap();
        assert_eq!(before, after);
        let changed: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM kernel_mcp_write_receipts WHERE request_json!='{}'",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(changed, 0);
        db.close().await;
    }

    #[tokio::test]
    async fn generic_append_and_import_cannot_mint_private_receipts() {
        let (db, principal) = fixture().await;
        let spec = || AppendSpec {
            record_id: STREAM.into(),
            event_type: EVENT.into(),
            actor: Some(principal.clone()),
            payload: json!({"operation":"resolve_suggestions","operation_key":"forged","request_json":"{}","receipt_json":"{}"}),
        };
        let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert!(crate::store::append(&db, spec()).await.is_err());
        let mut tx = begin_write(db.write_pool()).await.unwrap();
        assert!(
            crate::store::append_in(&db, &mut tx, spec(), &mut ActAllocation::new())
                .await
                .is_err()
        );
        tx.rollback().await.unwrap();
        let mut tx = begin_write(db.write_pool()).await.unwrap();
        assert!(crate::store::append_migration_on(
            &mut tx,
            Uuid::new_v4().to_string(),
            spec(),
            "2026-11-08T00:00:00Z"
        )
        .await
        .is_err());
        tx.rollback().await.unwrap();
        let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(before, after);
        db.close().await;
    }

    #[tokio::test]
    async fn head_identity_coverage_is_distinct_from_exact_materialization_proof() {
        let (db, principal) = fixture().await;
        receipt(&db, &principal).await;
        // Same-key payload corruption does not change the advertised history
        // coordinates. A cut must still refuse the damaged projection bytes.
        sqlx::query("DROP TRIGGER kernel_mcp_outcome_immutable")
            .execute(db.write_pool())
            .await
            .unwrap();
        sqlx::query("UPDATE kernel_mcp_write_receipts SET receipt_json='{}'")
            .execute(db.write_pool())
            .await
            .unwrap();
        fences::install_guards_on(&mut db.write_pool().acquire().await.unwrap())
            .await
            .unwrap();
        crate::standby::delta_transport::observe_authority_act_head(&db, "route-1")
            .await
            .unwrap();
        let mut conn = db.pool().acquire().await.unwrap();
        assert!(crate::standby::kernel_v2_delta::cut(&mut conn, 0, &[])
            .await
            .is_err());
        assert!(require_covered_on(&mut conn).await.is_err());
        drop(conn);
        // A legacy key added without any event/act must be detected even at
        // an otherwise unchanged head.
        sqlx::query("INSERT INTO kernel_mcp_write_receipts(principal_id,operation,operation_key,request_json,receipt_json,outcome_kind) VALUES(?,'resolve_suggestions','uncarried','{}','{}','accepted')").bind(&principal).execute(db.write_pool()).await.unwrap();
        assert!(
            crate::standby::delta_transport::observe_authority_act_head(&db, "route-1")
                .await
                .is_err()
        );
        sqlx::query("DELETE FROM kernel_mcp_write_receipts")
            .execute(db.write_pool())
            .await
            .unwrap();
        assert!(
            crate::standby::delta_transport::observe_authority_act_head(&db, "route-1")
                .await
                .is_err(),
            "a dangling canonical fact must also refuse head observation"
        );
        db.close().await;
    }

    #[tokio::test]
    async fn head_coverage_queries_do_not_load_wide_request_or_receipt_payloads() {
        let (db, principal) = fixture().await;
        let body = json!({"large":"private body".repeat(4096)}).to_string();
        let mut tx = begin_write(db.write_pool()).await.unwrap();
        record_on(
            &db,
            &mut tx,
            &mut ActAllocation::new(),
            Outcome {
                principal: &principal,
                operation: "resolve_suggestions",
                key: "wide",
                request: &body,
                receipt: &body,
            },
        )
        .await
        .unwrap();
        db.commit_kernel_content(tx).await.unwrap();
        let mut read = db.pool().begin().await.unwrap();
        let indexes:i64=sqlx::query_scalar("SELECT count(*) FROM main.sqlite_schema WHERE type='index' AND name IN ('idx_kernel_mcp_write_receipt_events','idx_kernel_mcp_write_fence_events')").fetch_one(&mut *read).await.unwrap();
        assert_eq!(indexes, 2, "this VM guard qualifies the index-present path");
        let roots: Vec<(String, i64)> = sqlx::query_as("SELECT name,rootpage FROM sqlite_schema WHERE type='table' AND name IN ('content_events','kernel_mcp_write_receipts')").fetch_all(&mut *read).await.unwrap();
        for typed in [false, true] {
            let (missing, orphan) = head_coverage_sql_on(&mut read, typed).await.unwrap();
            for query in [missing, orphan] {
                assert!(query.contains("INDEXED BY idx_kernel_mcp_write_receipt_events"));
                if typed {
                    assert!(query.contains("INDEXED BY idx_kernel_mcp_write_fence_events"));
                }
                let rows = sqlx::query(&format!("EXPLAIN {query}"))
                    .fetch_all(&mut *read)
                    .await
                    .unwrap();
                let mut wide_cursors = std::collections::BTreeMap::new();
                for row in &rows {
                    if row.get::<String, _>("opcode") == "OpenRead" {
                        let root: i64 = row.get("p2");
                        if let Some((table, _)) = roots.iter().find(|(_, page)| *page == root) {
                            wide_cursors.insert(row.get::<i64, _>("p1"), table.as_str());
                        }
                    }
                }
                for row in rows {
                    if row.get::<String, _>("opcode") == "Column" {
                        let cursor: i64 = row.get("p1");
                        let column: i64 = row.get("p2");
                        match wide_cursors.get(&cursor).copied() {
                            Some("content_events") => assert_ne!(
                                column, 4,
                                "head coverage must not load canonical payload JSON"
                            ),
                            Some("kernel_mcp_write_receipts") => assert!(
                                ![3, 4].contains(&column),
                                "head coverage must not load request/receipt bytes"
                            ),
                            _ => (),
                        }
                    }
                }
            }
        }
        read.rollback().await.unwrap();
        db.close().await;
    }
}
