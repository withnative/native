//! Host-imported standing-instruction bindings. Legacy attribution is data;
//! only the authenticated import principal authors the sealed kernel event.
use super::*;

pub(crate) const EVENT: &str = "kernel.instruction_binding_imported.v1";
pub(crate) const UPDATE: &str = "kernel.instruction_binding_updated.v1";

/// Binding imports may advance current state; record imports remain immutable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum InstructionBindingImportResult {
    Created,
    Updated,
    Unchanged,
}
pub(super) const DDL: &str = "CREATE TABLE kernel_instruction_bindings (
 id TEXT PRIMARY KEY, scope_kind TEXT NOT NULL, scope_id TEXT NOT NULL,
 account_principal TEXT REFERENCES kernel_principals(principal_id),
 source_record_id TEXT NOT NULL, position INTEGER NOT NULL, enabled INTEGER NOT NULL,
 created_at TEXT NOT NULL, legacy_actor TEXT, event_seq INTEGER NOT NULL)";

/// Current v1 binding, including its original identity and attribution.
/// Scope IDs retain original v1 account IDs or `native:database`. The import
/// host maps account scopes to kernel principals explicitly, as S4 does for
/// owners; authentication bindings can have a source-specific namespace.
/// Targets may be absent during incremental import.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::FromRow)]
#[serde(deny_unknown_fields)]
pub struct ImportInstructionBinding {
    pub id: String,
    pub scope_kind: String,
    pub scope_id: String,
    pub account_principal: Option<String>,
    pub source_record_id: String,
    pub position: i64,
    pub enabled: bool,
    pub created_at: String,
    pub actor: Option<String>,
}

/// Import current binding state. Identical retries append nothing; changes to
/// enabled/position/target append a sealed update, preserving creation provenance.
/// Does not grant record visibility or execute legacy actors.
pub async fn import_instruction_binding_as(
    db: &Db,
    principal: &str,
    binding: &ImportInstructionBinding,
) -> Result<InstructionBindingImportResult> {
    let mut tx = begin_write(db.write_pool()).await?;
    hq::require_import(&mut tx, principal).await?;
    hq::require_source_import_open(&mut tx).await?;
    validate(binding)?;
    validate_account(&mut tx, binding).await?;
    let existing = snapshot_before(&mut tx, &binding.id, i64::MAX).await?;
    let (event_type, result) = if let Some((original, actor)) = existing {
        if actor.as_deref() != Some(principal) {
            return Err(Error::conflict("instruction binding import actor differs"));
        }
        preserve_identity(&original, binding)?;
        if original == *binding {
            return Ok(InstructionBindingImportResult::Unchanged);
        }
        (UPDATE, InstructionBindingImportResult::Updated)
    } else {
        (EVENT, InstructionBindingImportResult::Created)
    };
    let mut acts = crate::act::ActAllocation::new();
    crate::store::append_kernel_instruction_binding_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: binding.id.clone(),
            event_type: event_type.into(),
            payload: serde_json::to_value(binding)?,
            actor: Some(principal.into()),
        },
        &mut acts,
    )
    .await?;
    tx.commit().await?;
    Ok(result)
}

async fn snapshot_before(
    conn: &mut SqliteConnection,
    id: &str,
    before: i64,
) -> Result<Option<(ImportInstructionBinding, Option<String>)>> {
    let row: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT payload,actor FROM content_events WHERE type IN (?,?) AND record_id=? AND seq<? ORDER BY seq DESC LIMIT 1")
        .bind(EVENT).bind(UPDATE).bind(id).bind(before).fetch_optional(&mut *conn).await?;
    let Some((payload, actor)) = row else {
        return Ok(None);
    };
    let mut binding: ImportInstructionBinding = serde_json::from_str(&payload)?;
    let removed:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events r WHERE r.record_id=? AND r.type='kernel.import_removed.v1' AND json_extract(r.payload,'$.kind')='instruction_binding' AND r.seq<? AND r.seq>(SELECT max(seq) FROM content_events WHERE record_id=? AND type IN (?,?) AND seq<?))")
        .bind(id).bind(before).bind(id).bind(EVENT).bind(UPDATE).bind(before).fetch_one(conn).await?;
    if removed {
        binding.enabled = false;
    }
    Ok(Some((binding, actor)))
}

fn preserve_identity(
    original: &ImportInstructionBinding,
    next: &ImportInstructionBinding,
) -> Result<()> {
    if original.id != next.id
        || original.scope_kind != next.scope_kind
        || original.scope_id != next.scope_id
        || original.account_principal != next.account_principal
        || original.created_at != next.created_at
        || original.actor != next.actor
    {
        return Err(Error::conflict(
            "instruction binding identity or creation provenance differs",
        ));
    }
    Ok(())
}

fn validate(binding: &ImportInstructionBinding) -> Result<()> {
    if binding.id.trim().is_empty()
        || binding.scope_id.trim().is_empty()
        || binding.source_record_id.trim().is_empty()
        || binding.created_at.trim().is_empty()
        || !matches!(binding.scope_kind.as_str(), "database" | "account")
        || (binding.scope_kind == "database"
            && (binding.scope_id != "native:database" || binding.account_principal.is_some()))
        || (binding.scope_kind == "account" && binding.account_principal.is_none())
    {
        return Err(Error::engine("invalid instruction binding import"));
    }
    Ok(())
}

async fn validate_account(
    conn: &mut SqliteConnection,
    binding: &ImportInstructionBinding,
) -> Result<()> {
    if let Some(account) = &binding.account_principal {
        let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_principals WHERE principal_id=? AND kind='account')")
            .bind(account).fetch_one(conn).await?;
        if !valid {
            return Err(Error::engine(
                "instruction binding requires a mapped kernel account",
            ));
        }
    }
    Ok(())
}

pub(crate) async fn project(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    hq::require_import(conn, event.actor.as_deref().unwrap_or_default()).await?;
    let binding: ImportInstructionBinding = event_payload(event)?;
    validate(&binding)?;
    validate_account(conn, &binding).await?;
    if event.record_id != binding.id {
        return Err(Error::engine("instruction binding identity mismatch"));
    }
    let prior = snapshot_before(conn, &binding.id, event.local_seq).await?;
    match (event.event_type.as_str(), prior) {
        (EVENT, None) => {}
        (UPDATE, Some((original, actor))) if actor == event.actor => {
            preserve_identity(&original, &binding)?;
            let changed = sqlx::query("UPDATE kernel_instruction_bindings SET source_record_id=?,position=?,enabled=?,event_seq=? WHERE id=?")
                .bind(binding.source_record_id).bind(binding.position).bind(binding.enabled)
                .bind(event.local_seq).bind(binding.id).execute(conn).await?.rows_affected();
            if changed != 1 {
                return Err(Error::engine(
                    "instruction binding update requires an existing binding",
                ));
            }
            return Ok(());
        }
        _ => return Err(Error::engine("invalid instruction binding import sequence")),
    }
    sqlx::query("INSERT INTO kernel_instruction_bindings(id,scope_kind,scope_id,account_principal,source_record_id,position,enabled,created_at,legacy_actor,event_seq) VALUES(?,?,?,?,?,?,?,?,?,?)")
        .bind(binding.id).bind(binding.scope_kind).bind(binding.scope_id).bind(binding.account_principal)
        .bind(binding.source_record_id).bind(binding.position).bind(binding.enabled)
        .bind(binding.created_at).bind(binding.actor.map(|a| format!("v1:{a}")))
        .bind(event.local_seq).execute(conn).await?;
    Ok(())
}
