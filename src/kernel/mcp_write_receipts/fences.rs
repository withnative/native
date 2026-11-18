//! Canonical terminal outcomes in the existing keyed-outcome namespace.
use super::*;
use crate::error::{NativeFenceReference, OriginalConflict, OriginalConflictKind};

pub(crate) const EVENT: &str = "kernel.mcp_write_fenced.v1";
pub(crate) const INDEX_DDL: &str = "CREATE INDEX IF NOT EXISTS idx_kernel_mcp_write_fence_events ON content_events(actor,CAST(json_extract(payload,'$.operation') AS TEXT),CAST(json_extract(payload,'$.operation_key') AS TEXT),seq) WHERE record_id='kernel:mcp-write-receipts' AND type='kernel.mcp_write_fenced.v1'";
// A missing accelerator must not disable the serialized key/ID backstops.
// Exact expression predicates still use the indexes when they are present.
pub(crate) const LOOKUP_SQL: &str = "SELECT id,type,payload FROM main.content_events WHERE record_id='kernel:mcp-write-receipts' AND type='kernel.mcp_write_fenced.v1' AND actor=? AND CAST(json_extract(payload,'$.operation') AS TEXT)=? AND CAST(json_extract(payload,'$.operation_key') AS TEXT)=? ORDER BY seq LIMIT 2";
pub(crate) const RETIRED_LOOKUP_SQL: &str = "SELECT principal_id,operation,operation_key FROM main.kernel_mcp_write_receipts WHERE outcome_kind='unapplied_terminal' AND retired_record_id IS NOT NULL AND retired_record_id=?";
pub(crate) const RETIRED_DDL: &str = "CREATE UNIQUE INDEX IF NOT EXISTS idx_kernel_mcp_retired_record_id ON kernel_mcp_write_receipts(retired_record_id) WHERE outcome_kind='unapplied_terminal' AND retired_record_id IS NOT NULL";
pub(crate) const INSERT_GUARD: &str = "CREATE TRIGGER IF NOT EXISTS kernel_mcp_terminal_no_replace BEFORE INSERT ON kernel_mcp_write_receipts WHEN EXISTS(SELECT 1 FROM kernel_mcp_write_receipts WHERE principal_id=NEW.principal_id AND operation=NEW.operation AND operation_key=NEW.operation_key AND outcome_kind='unapplied_terminal') BEGIN SELECT RAISE(ABORT,'immutable kernel terminal fence'); END";
pub(crate) const DELETE_GUARD: &str = "CREATE TRIGGER IF NOT EXISTS kernel_mcp_terminal_no_delete BEFORE DELETE ON kernel_mcp_write_receipts WHEN OLD.outcome_kind='unapplied_terminal' BEGIN SELECT RAISE(ABORT,'immutable kernel terminal fence'); END";
pub(crate) const UPDATE_GUARD: &str = "CREATE TRIGGER IF NOT EXISTS kernel_mcp_outcome_immutable BEFORE UPDATE ON kernel_mcp_write_receipts WHEN OLD.principal_id IS NOT NEW.principal_id OR OLD.operation IS NOT NEW.operation OR OLD.operation_key IS NOT NEW.operation_key OR OLD.outcome_kind IS NOT NEW.outcome_kind OR OLD.receipt_json IS NOT NEW.receipt_json OR OLD.terminal_json IS NOT NEW.terminal_json OR OLD.retired_record_id IS NOT NEW.retired_record_id OR (OLD.outcome_kind='unapplied_terminal' AND OLD.request_json IS NOT NEW.request_json) BEGIN SELECT RAISE(ABORT,'immutable kernel keyed outcome'); END";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Terminal {
    pub schema: String,
    pub fence_id: String,
    pub reason: String,
    pub scope: String,
    pub retired_record_id: Option<String>,
    pub namespace_sha256: String,
    pub original_binding_sha256: String,
    pub account_id: String,
    pub principal_id: String,
    pub database_id: String,
    pub origin_database_id: String,
    pub journal_variant: u32,
    pub retained_contract_digest: String,
    pub catalog_executor: String,
    pub catalog_operation: String,
    pub mint_context: Option<String>,
    pub delegation_ref: Option<String>,
    pub assertion: String,
    pub app: Option<Value>,
    pub asserting_client_id: Option<String>,
    pub asserting_device_id: Option<String>,
    pub settled_by_client_id: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FenceFact {
    pub format: u32,
    pub operation: String,
    pub operation_key: String,
    pub request_json: String,
    pub terminal: Terminal,
}

pub(crate) async fn typed_on(conn: &mut SqliteConnection) -> Result<bool> {
    Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pragma_table_info('kernel_mcp_write_receipts','main') WHERE name='outcome_kind')").fetch_one(conn).await?)
}
pub(crate) async fn install_guards_on(conn: &mut SqliteConnection) -> Result<()> {
    if !typed_on(conn).await? {
        return Ok(());
    } // Explicit maintenance migrates old files.
    for ddl in [
        INDEX_DDL,
        RETIRED_DDL,
        INSERT_GUARD,
        DELETE_GUARD,
        UPDATE_GUARD,
    ] {
        sqlx::query(ddl).execute(&mut *conn).await?;
    }
    Ok(())
}
pub(crate) async fn suspend_delete_guard_on(conn: &mut SqliteConnection) -> Result<()> {
    sqlx::query("DROP TRIGGER IF EXISTS kernel_mcp_terminal_no_delete")
        .execute(conn)
        .await?;
    Ok(())
}

pub(crate) async fn native_on(
    conn: &mut SqliteConnection,
    id: &str,
) -> Result<NativeFenceReference> {
    let (seq, act, status): (i64, Option<i64>, String) =
        sqlx::query_as("SELECT seq,act,causal_status FROM main.content_events WHERE id=?")
            .bind(id)
            .fetch_one(&mut *conn)
            .await?;
    let parents:Vec<String> = sqlx::query_scalar("SELECT parent_event_id FROM main.content_event_causal_frontier WHERE event_id=? ORDER BY parent_event_id").bind(id).fetch_all(&mut *conn).await?;
    let genesis: String =
        sqlx::query_scalar("SELECT id FROM main.content_events WHERE type=? ORDER BY seq LIMIT 1")
            .bind(crate::events::KERNEL_GENESIS_EVENT)
            .fetch_one(&mut *conn)
            .await?;
    let origin = origin_on(conn).await?;
    let envelope =
        serde_json::from_value(json!({"version":"v1","status":status,"frontier":parents}))?;
    Ok(NativeFenceReference {
        canonical_event_id: id.into(),
        origin_database_id: origin,
        genesis_event_id: genesis,
        local_seq: seq,
        act: act.ok_or_else(|| Error::engine("fence native act unavailable"))?,
        causal_envelope: envelope,
    })
}
fn conflict(fact: &FenceFact, native: NativeFenceReference, record: Option<&str>) -> Error {
    Error::OriginalConflict(Box::new(OriginalConflict {
        schema: "native.original-conflict.v1".into(),
        kind: if record.is_some() {
            OriginalConflictKind::RecordIdRetired
        } else {
            OriginalConflictKind::KeyFenced
        },
        record_id: record.map(str::to_owned),
        fence_id: fact.terminal.fence_id.clone(),
        native_fence: native,
        namespace_sha256: fact.terminal.namespace_sha256.clone(),
        fenced_original_binding_sha256: fact.terminal.original_binding_sha256.clone(),
        requested_original_binding_sha256: None,
    }))
}
pub(crate) async fn refuse_key_on(
    conn: &mut SqliteConnection,
    principal: &str,
    operation: &str,
    key: &str,
) -> Result<()> {
    if !typed_on(conn).await? {
        return Ok(());
    }
    let query = super::indexed_sql_on(
        conn,
        LOOKUP_SQL,
        "main.content_events",
        "idx_kernel_mcp_write_fence_events",
    )
    .await?;
    let rows: Vec<(String, String, String)> = sqlx::query_as(&query)
        .bind(principal)
        .bind(operation)
        .bind(key)
        .fetch_all(&mut *conn)
        .await?;
    if rows.len() > 1 {
        return Err(Error::engine("duplicate terminal outcome"));
    }
    let row = rows.into_iter().next().map(|(id, _, raw)| (id, raw));
    if let Some((id, raw)) = row {
        let fact: FenceFact = serde_json::from_str(&raw)?;
        let native = native_on(conn, &id).await?;
        return Err(conflict(&fact, native, None));
    }
    Ok(())
}
pub(crate) async fn refuse_retired_on(
    conn: &mut SqliteConnection,
    id: &str,
    create_event: Option<&EventRow>,
) -> Result<()> {
    if !typed_on(conn).await? {
        return Ok(());
    }
    let query = super::indexed_sql_on(
        conn,
        RETIRED_LOOKUP_SQL,
        "main.kernel_mcp_write_receipts",
        "idx_kernel_mcp_retired_record_id",
    )
    .await?;
    let retired: Option<(String, String, String)> = sqlx::query_as(&query)
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?;
    let Some((actor, operation, key)) = retired else {
        return Ok(());
    };
    let query = super::indexed_sql_on(
        conn,
        LOOKUP_SQL,
        "main.content_events",
        "idx_kernel_mcp_write_fence_events",
    )
    .await?;
    let rows: Vec<(String, String, String)> = sqlx::query_as(&query)
        .bind(&actor)
        .bind(&operation)
        .bind(&key)
        .fetch_all(&mut *conn)
        .await?;
    if rows.len() != 1 {
        return Err(Error::engine("retired ID canonical coverage differs"));
    }
    let (event, _, raw) = rows.into_iter().next().expect("one canonical fence");
    let seq: i64 = sqlx::query_scalar("SELECT seq FROM main.content_events WHERE id=?")
        .bind(&event)
        .fetch_one(&mut *conn)
        .await?;
    let row = Some((event, raw, seq));
    if let Some((event, raw, seq)) = row {
        // The sealed chronological projector preserves native event sequences.
        // Historical creates before retirement MUST still replay.
        if let Some(create) = create_event.filter(|e| e.local_seq > 0 && e.local_seq < seq) {
            let retained: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM main.content_events WHERE id=? AND seq=? AND record_id=?)",
            )
            .bind(&create.id)
            .bind(create.local_seq)
            .bind(id)
            .fetch_one(&mut *conn)
            .await?;
            if retained {
                return Ok(());
            }
        }
        let fact: FenceFact = serde_json::from_str(&raw)?;
        if fact.terminal.retired_record_id.as_deref() != Some(id) {
            return Err(Error::engine("retired ID canonical coverage differs"));
        }
        let native = native_on(conn, &event).await?;
        return Err(conflict(&fact, native, Some(id)));
    }
    Ok(())
}

pub(crate) async fn project(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    if event.record_id != STREAM || event.event_type != EVENT {
        return Err(Error::engine("invalid terminal outcome stream"));
    }
    let fact: FenceFact = event_payload(event)?;
    crate::kernel::original_settlement::validate_fact(
        &fact,
        event.actor.as_deref().unwrap_or_default(),
    )?;
    if !typed_on(conn).await? {
        return Err(Error::engine(
            "terminal outcomes require explicit schema preparation",
        ));
    }
    ensure_schema(conn).await?;
    fold_on(conn, event.actor.as_deref().unwrap_or_default(), &fact).await
}
async fn fold_on(conn: &mut SqliteConnection, principal: &str, fact: &FenceFact) -> Result<()> {
    let terminal = serde_jcs::to_string(&fact.terminal)?;
    sqlx::query("INSERT INTO kernel_mcp_write_receipts(principal_id,operation,operation_key,request_json,receipt_json,outcome_kind,terminal_json,retired_record_id) VALUES(?,?,?,?,NULL,'unapplied_terminal',?,?)")
      .bind(principal).bind(&fact.operation).bind(&fact.operation_key).bind(&fact.request_json).bind(terminal).bind(&fact.terminal.retired_record_id).execute(conn).await?;
    Ok(())
}
pub(crate) async fn repair_on(conn: &mut SqliteConnection) -> Result<()> {
    let facts:Vec<(Option<String>,String)>=sqlx::query_as("SELECT actor,payload FROM main.content_events WHERE record_id='kernel:mcp-write-receipts' AND type='kernel.mcp_write_fenced.v1' ORDER BY seq").fetch_all(&mut *conn).await?;
    for (principal, raw) in facts {
        let principal = principal.as_deref().unwrap_or_default();
        let fact: FenceFact = serde_json::from_str(&raw)?;
        crate::kernel::original_settlement::validate_fact(&fact, principal)?;
        let present:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.kernel_mcp_write_receipts WHERE principal_id=? AND operation=? AND operation_key=?)").bind(principal).bind(&fact.operation).bind(&fact.operation_key).fetch_one(&mut *conn).await?;
        if !present {
            fold_on(conn, principal, &fact).await?;
        }
    }
    require_covered_on(conn).await
}
pub(crate) async fn require_covered_on(conn: &mut SqliteConnection) -> Result<()> {
    super::require_covered_on(conn).await
}

pub(crate) async fn origin_on(conn: &mut SqliteConnection) -> Result<String> {
    crate::kernel::legacy_history::require_sql_frontier_on(conn).await?;
    let origins:Vec<String>=sqlx::query_scalar("SELECT DISTINCT json_extract(payload,'$.legacy.payload.source_origin') FROM main.content_events WHERE type='kernel.legacy_recorded.v1' AND json_extract(payload,'$.legacy.event_type')='v1.snapshot_provenance' AND json_extract(payload,'$.legacy.payload.source_origin') IS NOT NULL").fetch_all(&mut *conn).await?;
    match origins.as_slice() {
        [one] if crate::identity::is_database_id(one) => Ok(one.clone()),
        [] => {
            let id: String = sqlx::query_scalar(
                "SELECT id FROM main.content_events WHERE type=? ORDER BY seq LIMIT 1",
            )
            .bind(crate::events::KERNEL_GENESIS_EVENT)
            .fetch_one(conn)
            .await?;
            Ok(format!(
                "ndb_{}",
                Uuid::parse_str(&id)
                    .map_err(|_| Error::engine("invalid native genesis"))?
                    .simple()
            ))
        }
        _ => Err(Error::engine("ambiguous original origin")),
    }
}

pub(crate) async fn require_current_guards_on(conn: &mut SqliteConnection) -> Result<()> {
    for (name, ddl) in [
        ("kernel_mcp_terminal_no_replace", INSERT_GUARD),
        ("kernel_mcp_terminal_no_delete", DELETE_GUARD),
        ("kernel_mcp_outcome_immutable", UPDATE_GUARD),
    ] {
        let actual:Option<String>=sqlx::query_scalar("SELECT sql FROM main.sqlite_schema WHERE type='trigger' AND name=? AND tbl_name='kernel_mcp_write_receipts'").bind(name).fetch_optional(&mut *conn).await?;
        if actual.as_deref() != Some(ddl.replacen(" IF NOT EXISTS", "", 1).as_str()) {
            return Err(Error::engine("terminal guard preparation required"));
        }
    }
    Ok(())
}
