//! KernelV2 validation for the hosted release-window append path.
use crate::{kernel, mcp::Caller, Db, Error, Result};
use serde_json::Value;
use sqlx::{Connection, SqliteConnection};

/// Accept only the native singular append shape with a caller-owned exact key.
/// Transport metadata (including run_key) is validated outside the tool arguments.
pub fn target_and_key(args: &Value) -> Result<(&str, &str)> {
    let target = crate::fork::kernel_v2_plain_append_target(args)
        .filter(|target| args["id"].as_str() == Some(*target))
        .ok_or_else(|| Error::engine("release outbox requires a singular plain append"))?;
    let key = args["idempotency_key"]
        .as_str()
        .filter(|key| !key.is_empty() && key.trim() == *key && key.chars().count() <= 200)
        .ok_or_else(|| Error::engine("release outbox requires an exact idempotency key"))?;
    if args.to_string().len() > 1024 * 1024
        || args["body_append"]
            .as_str()
            .is_none_or(|body| body.trim().is_empty())
        || args.get("reason").is_some_and(|reason| !reason.is_string())
        || args.get("response_mode").is_some()
    {
        return Err(Error::engine("unsupported release outbox append arguments"));
    }
    Ok((target, key))
}

/// Check the frozen accepted state without mutating the base or granting access.
pub async fn validate_frozen(db: &Db, caller: &Caller, args: &Value) -> Result<()> {
    let mut snapshot = db.pool().begin().await?;
    let actor = super::principal_on(&mut snapshot, caller).await?;
    validate_on(&mut snapshot, &actor, args).await?;
    snapshot.rollback().await?;
    Ok(())
}

/// Resolve an existing run owned by this browser's admitted account. Frozen
/// acceptance may never create a run or adopt one owned by another caller.
pub async fn intent(
    db: &Db,
    caller: &Caller,
    run: &str,
    require_open: bool,
) -> Result<Option<String>> {
    if !matches!(
        crate::runkey::validate_full(Some(run)),
        crate::runkey::KeyOutcome::Valid(_)
    ) {
        return Err(Error::auth("outbox_existing_run_required"));
    }
    let actor = super::principal(db, caller).await?;
    let context = super::coordination::existing_run(db, &actor, run)
        .await
        .map_err(|error| match error {
            Error::Engine(ref message) if message == kernel::HIDDEN_OR_MISSING => {
                Error::auth("outbox_existing_run_required")
            }
            error => error,
        })?
        .ok_or_else(|| Error::auth("outbox_existing_run_required"))?;
    if require_open
        && kernel::run_ledger::run_witness_as(db, &context)
            .await?
            .closed
    {
        return Err(Error::auth("outbox_existing_run_required"));
    }
    kernel::run_ledger::run_intent_as(db, &context).await
}

/// Returning a retained outcome requires current visibility, even when the
/// edit can no longer be attempted (for example, after an archive).
pub async fn require_receipt_visibility(db: &Db, caller: &Caller, args: &Value) -> Result<()> {
    let (id, _) = target_and_key(args)?;
    let mut snapshot = db.pool().begin().await?;
    let actor = super::principal_on(&mut snapshot, caller).await?;
    kernel::kernel_require(
        &mut snapshot,
        &actor,
        id,
        crate::authorization::Capability::View,
    )
    .await?;
    snapshot.rollback().await?;
    Ok(())
}

/// Run the same scope check before the canonical write, inside its transaction.
pub(super) async fn validate_on(
    tx: &mut SqliteConnection,
    actor: &str,
    args: &Value,
) -> Result<()> {
    let (id, _) = target_and_key(args)?;
    kernel::kernel_require(tx, actor, id, crate::authorization::Capability::Edit).await?;
    let record = kernel::read_record_on(tx, actor, id)
        .await?
        .ok_or_else(|| Error::engine(kernel::HIDDEN_OR_MISSING))?;
    let primary: Option<String> =
        sqlx::query_scalar("SELECT primary_type FROM kernel_records WHERE id=?")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    if record.archived
        || super::v1_type_and_kind(
            record.family.as_deref(),
            record.pin.as_ref().map(|pin| pin.version),
            primary.as_deref(),
            record.kind.as_deref(),
            &record.fields,
        ) != (Some("Document"), Some("note"))
    {
        return Err(Error::conflict(
            "release outbox target is no longer a live plain note",
        ));
    }
    let instruction_source: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM kernel_instruction_bindings WHERE source_record_id=? AND enabled=1)",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    if instruction_source {
        return Err(Error::conflict(
            "release outbox cannot append to an instruction source",
        ));
    }
    Ok(())
}

/// Observe the existing canonical keyed write ledger without attempting a mutation.
/// A database error or a conflicting key must never be treated as a missing receipt.
pub async fn lookup(db: &Db, credential: &str, args: &Value) -> Result<Option<Value>> {
    let (_, key) = target_and_key(args)?;
    let mut connection = db.write_pool().acquire().await?;
    let mut tx = connection.begin_with("BEGIN IMMEDIATE").await?;
    let actor: String =
        sqlx::query_scalar("SELECT principal_id FROM kernel_principals WHERE auth_binding=?")
            .bind(credential)
            .fetch_one(&mut *tx)
            .await?;
    let row = kernel::mcp_write_receipts::observe_ordinary_receipt_on(
        &mut tx,
        &actor,
        "update_record",
        key,
    )
    .await?;
    tx.rollback().await?;
    let Some((request, receipt)) = row else {
        return Ok(None);
    };
    let expected = super::writes::intent_fingerprint("update_record", args.clone(), Value::Null)?;
    let stored =
        super::writes::stored_fingerprint("update_record", serde_json::from_str(&request)?)?;
    if stored != expected {
        return Err(Error::conflict(
            "release outbox idempotency key already belongs to another outcome",
        ));
    }
    Ok(Some(serde_json::from_str(&receipt)?))
}
