//! Claims host adapter. Opaque run contexts, visibility and all mutable witnesses
//! are resolved in the same transaction as occupancy. No request attribution is trusted.
use super::links_v2::{endpoint, retained_bytes, EndpointWitness};
use super::provider_catalogue::{Decoded, StoredState, ValidationFuture};
use super::run_ledger::{self, Witness};
use super::*;
use crate::v2_standard::claims_v1 as provider;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
// Claims /1 host wire: future versions retain this frame rather than extend it.
pub struct ClaimRequest {
    pub principal_id: String,
    pub run: Witness,
    pub operation_key: String,
    pub target: EndpointWitness,
    pub scope_home: String,
    pub selection_head: i64,
    pub guard_head: i64,
    pub authority_head: i64,
    pub policy_head: i64,
    pub expected_head: Option<i64>,
    pub aggregate_id: String,
    pub pins: InterpretationPins,
    pub command: provider::Command,
    pub request_checksum: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimReceipt {
    pub aggregate_id: String,
    pub receipt_id: String,
    pub event_seq: i64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ClaimResult {
    Committed(ClaimReceipt),
    Unchanged,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClaimRead {
    pub record_id: String,
    pub occupied: bool,
    pub withheld: bool,
    pub holder: Option<provider::Holder>,
    pub generation: Option<u64>,
    pub head: Option<i64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Outcome {
    pub request: ClaimRequest,
    pub receipt_id: String,
}
fn checksum(r: &ClaimRequest) -> Result<String> {
    let mut unsigned = r.clone();
    unsigned.request_checksum.clear();
    Ok(crate::meta::definition_artifact::digest_artifact_bytes(
        &serde_json::to_vec(&unsigned)?,
    ))
}
fn operation_key(key: &str) -> Result<()> {
    if key.is_empty() || key.len() > 256 || !key.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(Error::engine("invalid claims operation key"));
    }
    Ok(())
}
fn aggregate(record: &str) -> String {
    format!(
        "claims:{}",
        crate::meta::definition_artifact::digest_artifact_bytes(
            &serde_json::to_vec(&(provider::PROVIDER_KEY, record)).expect("strings")
        )
    )
}
async fn visible(conn: &mut SqliteConnection, principal: &str, record: &str) -> Result<()> {
    if !kernel_effective_capability_on(conn, principal, record)
        .await?
        .allows(Capability::View)
    {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    }
    endpoint(conn, record, i64::MAX).await?;
    Ok(())
}
async fn edit(conn: &mut SqliteConnection, r: &ClaimRequest) -> Result<()> {
    visible(conn, &r.principal_id, &r.target.record_id).await?;
    if !kernel_effective_capability_on(conn, &r.principal_id, &r.target.record_id)
        .await?
        .allows(Capability::Edit)
    {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    }
    Ok(())
}
async fn state(
    conn: &mut SqliteConnection,
    id: &str,
    record: &str,
) -> Result<(Option<i64>, Option<provider::State>)> {
    let row: Option<(String, String, String, i64)> = sqlx::query_as(
        "SELECT provider_key,subjects_json,state_json,head FROM kernel_provider_state WHERE id=?",
    )
    .bind(id)
    .fetch_optional(conn)
    .await?;
    match row {
        None => Ok((None, None)),
        Some((key, subjects, json, head)) => {
            if key != provider::PROVIDER_KEY
                || serde_json::from_str::<Vec<String>>(&subjects)? != vec![record.to_owned()]
            {
                return Err(Error::engine("claims aggregate identity mismatch"));
            }
            let stored: StoredState = serde_json::from_str(&json)?;
            let s: provider::State = serde_json::from_value(stored.view()?)?;
            if s.record_id != record {
                return Err(Error::engine("claims aggregate identity mismatch"));
            }
            Ok((Some(head), Some(s)))
        }
    }
}
async fn authority_head(conn: &mut SqliteConnection, before: i64) -> Result<i64> {
    Ok(sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events WHERE seq < ? AND type IN ('kernel.home_created.v1','kernel.import_home.v1','kernel.import_home_delta.v1','kernel.import_state_delta.v1','kernel.import_removed.v1','kernel.home_created_for.v1','kernel.home_policy_replaced.v1','kernel.import_home_policy.v1','kernel.hosted_offboarding.v1','kernel.hosted_membership.v1','kernel.import_member_policy.v1','kernel.root_admin_bootstrapped.v1','kernel.record_rehomed.v1','kernel.record_rehomed.v2','kernel.principal_created.v1','kernel.host_transform_created.v1')").bind(before).fetch_one(conn).await?)
}
async fn policy_head(conn: &mut SqliteConnection) -> Result<i64> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='policy_events' AND type='table')",
    )
    .fetch_one(&mut *conn)
    .await?;
    if !exists {
        return Ok(0);
    }
    Ok(
        sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM policy_events")
            .fetch_one(conn)
            .await?,
    )
}
// Conservative per-package closure frontier. Dependencies come from the
// recorded package, not a hardcoded record kind or a kernel admission policy.
async fn guard_head(conn: &mut SqliteConnection, before: i64) -> Result<i64> {
    let mut head = 0;
    for definition in provider::package().definitions {
        let next:i64=sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events WHERE seq<? AND type=? AND json_extract(payload,'$.family')=?")
            .bind(before).bind(KERNEL_DEFINITION_ADOPTED_EVENT).bind(definition.family).fetch_one(&mut *conn).await?;
        head = head.max(next);
    }
    Ok(head)
}
async fn active(conn: &mut SqliteConnection, home: &str) -> Result<StoredPackageSelection> {
    let (selection, manifest) =
        require_package_active_in(conn, home, provider::NAMESPACE, provider::PACKAGE).await?;
    if !provider::known_package(&manifest) {
        return Err(Error::engine("unsupported claims provider"));
    }
    Ok(selection)
}
fn folded(
    r: &ClaimRequest,
    current: Option<&provider::State>,
    head: Option<i64>,
    receipt: &str,
    time: &str,
    seq: i64,
) -> Result<Option<provider::State>> {
    provider::fold(
        &r.command,
        &r.target.record_id,
        current,
        &provider::HostStamp {
            principal: &r.principal_id,
            run_id: &r.run.run_id,
            receipt_id: receipt,
            timestamp: time,
            seq,
            head,
        },
    )
}
async fn retry(
    conn: &mut SqliteConnection,
    principal: &str,
    command: &provider::Command,
    key: &str,
) -> Result<Option<(ClaimRequest, ClaimReceipt)>> {
    let row:Option<(String,String,i64)>=sqlx::query_as("SELECT request_json,assertion_id,event_seq FROM kernel_provider_receipts WHERE principal_id=? AND operation=? AND operation_key=?").bind(principal).bind(command.operation()).bind(key).fetch_optional(&mut *conn).await?;
    let Some((json, id, seq)) = row else {
        return Ok(None);
    };
    let r: ClaimRequest = serde_json::from_str(&json)?;
    let logged: Option<(String, Option<String>, Option<String>)> =
        sqlx::query_as("SELECT record_id,actor,payload FROM content_events WHERE seq=? AND type=?")
            .bind(seq)
            .bind(commit_port::PROVIDER_OUTCOME_EVENT)
            .fetch_optional(conn)
            .await?;
    let (record, actor, payload) =
        logged.ok_or_else(|| Error::engine("claims receipt/log mismatch"))?;
    let outcome: Outcome = serde_json::from_str(payload.as_deref().unwrap_or_default())?;
    if r.principal_id != principal
        || r.operation_key != key
        || r.command.operation() != command.operation()
        || record != r.aggregate_id
        || actor.as_deref() != Some(principal)
        || outcome.request != r
        || outcome.receipt_id != id
    {
        return Err(Error::engine("claims receipt/log mismatch"));
    }
    // Receipt validation intentionally does not inspect today's occupancy.
    Ok(Some((
        r.clone(),
        ClaimReceipt {
            aggregate_id: r.aggregate_id,
            receipt_id: id,
            event_seq: seq,
        },
    )))
}
/// Prepare one real selected package command in a single snapshot.
pub async fn prepare_claim_as(
    db: &Db,
    context: &RunContext,
    record: &str,
    key: &str,
    command: provider::Command,
) -> Result<ClaimRequest> {
    let mut tx = db.write_pool().begin().await?;
    let run = run_ledger::resolve(&mut tx, context, false).await?;
    visible(&mut tx, &run.owner, record).await?;
    operation_key(key)?;
    if let Some((r, _)) = retry(&mut tx, &run.owner, &command, key).await? {
        if r.target.record_id != record || r.run.run_id != run.run_id || r.command != command {
            return Err(Error::conflict("claims retry key reused"));
        }
        return Ok(r);
    }
    let run = run_ledger::resolve(&mut tx, context, true).await?;
    let target = endpoint(&mut tx, record, i64::MAX).await?;
    retained_bytes(&mut tx, &target.binding).await?;
    let home: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
        .bind(record)
        .fetch_one(&mut *tx)
        .await?;
    let selection = active(&mut tx, &home).await?;
    let aggregate_id = aggregate(record);
    let (expected_head, current) = state(&mut tx, &aggregate_id, record).await?;
    let mut r = ClaimRequest {
        principal_id: run.owner.clone(),
        run,
        operation_key: key.into(),
        target,
        scope_home: home,
        selection_head: selection.event_seq,
        guard_head: guard_head(&mut tx, i64::MAX).await?,
        authority_head: authority_head(&mut tx, i64::MAX).await?,
        policy_head: policy_head(&mut tx).await?,
        expected_head,
        aggregate_id,
        pins: provider::pins(),
        command,
        request_checksum: String::new(),
    };
    r.request_checksum = checksum(&r)?;
    live(&mut tx, &r).await?;
    validate(&mut tx, &r, i64::MAX).await?;
    folded(&r, current.as_ref(), expected_head, "validation", "", 0)?;
    tx.rollback().await?;
    Ok(r)
}
async fn validate(conn: &mut SqliteConnection, r: &ClaimRequest, before: i64) -> Result<()> {
    operation_key(&r.operation_key)?;
    if r.request_checksum != checksum(r)?
        || r.pins != provider::pins()
        || r.aggregate_id != aggregate(&r.target.record_id)
        || r.principal_id != r.run.owner
        || r.run.closed
    {
        return Err(Error::engine("invalid claims request witnesses"));
    }
    if run_ledger::witness(conn, &r.run.run_id).await? != r.run {
        return Err(Error::conflict("claims run witness moved"));
    }
    if authority_head(conn, before).await? != r.authority_head {
        return Err(Error::conflict("claims authority frontier moved"));
    }
    if guard_head(conn, before).await? != r.guard_head {
        return Err(Error::conflict("claims package guard moved"));
    }
    let selection = resolve_effective_package_selection_before(
        conn,
        &r.scope_home,
        provider::NAMESPACE,
        provider::PACKAGE,
        before,
    )
    .await?
    .ok_or_else(|| Error::engine("missing claims selection witness"))?;
    if selection.event_seq != r.selection_head
        || selection.selected.as_ref() != Some(&r.pins.package)
        || selection.event_seq >= before
    {
        return Err(Error::conflict("claims selection witness moved"));
    }
    let stored = crate::meta::package::read_package_in(
        conn,
        &r.pins.package.namespace,
        &r.pins.package.name,
        r.pins.package.version,
        &r.pins.package.digest,
    )
    .await?
    .ok_or_else(|| Error::engine("missing retained claims package"))?;
    if !provider::known_package(&stored.manifest) {
        return Err(Error::engine("retained claims package mismatch"));
    }
    if endpoint(conn, &r.target.record_id, before).await? != r.target {
        return Err(Error::conflict("claims target binding or head moved"));
    }
    retained_bytes(conn, &r.target.binding).await?;
    let home: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
        .bind(&r.target.record_id)
        .fetch_one(&mut *conn)
        .await?;
    // Evaluate lifecycle at the recorded boundary so a later archive does not
    // invalidate an earlier retained claim during replay or validation.
    let archived: bool = sqlx::query_scalar("SELECT CASE WHEN type='kernel.import_state.v1' THEN json_extract(payload,'$.state.archived') WHEN type='kernel.import_state_delta.v1' THEN json_extract(payload,'$.snapshot.state.archived') WHEN type='kernel.import_removed.v1' THEN 1 ELSE json_extract(payload,'$.archived') END FROM content_events WHERE record_id=? AND (type IN ('kernel.archive_changed.v1','kernel.import_state.v1','kernel.import_state_delta.v1') OR (type='kernel.import_removed.v1' AND json_extract(payload,'$.kind')='record')) AND seq<? ORDER BY seq DESC LIMIT 1")
        .bind(&r.target.record_id).bind(before).fetch_optional(&mut *conn).await?.unwrap_or(false);
    if home != r.scope_home || !provider::eligible(!archived) {
        return Err(Error::conflict("claims target eligibility moved"));
    }
    let (head, current) = state(conn, &r.aggregate_id, &r.target.record_id).await?;
    // Foreign conflicts never reveal the aggregate head/generation/holder, even to Manage.
    if current
        .as_ref()
        .and_then(|s| s.holder.as_ref())
        .is_some_and(|h| h.principal != r.principal_id)
    {
        return Err(Error::conflict("already_claimed"));
    }
    if head != r.expected_head {
        return Err(Error::conflict("stale_claim"));
    }
    Ok(())
}
async fn live(conn: &mut SqliteConnection, r: &ClaimRequest) -> Result<()> {
    edit(conn, r).await?;
    if policy_head(conn).await? != r.policy_head {
        return Err(Error::conflict("claims policy frontier moved"));
    }
    let run = run_ledger::witness(conn, &r.run.run_id).await?;
    if run.closed {
        return Err(Error::engine("run_closed"));
    }
    if run != r.run {
        return Err(Error::conflict("claims run witness moved"));
    }
    let selection = active(conn, &r.scope_home).await?;
    if selection.event_seq != r.selection_head
        || selection.selected.as_ref() != Some(&r.pins.package)
    {
        return Err(Error::conflict("claims selection head moved"));
    }
    Ok(())
}
pub async fn commit_claim_as(
    db: &Db,
    context: &RunContext,
    r: &ClaimRequest,
) -> Result<ClaimResult> {
    Ok(commit_claim_with_change_as(db, context, r).await?.0)
}
/// Same authority and receipt path, plus whether this call appended a change.
pub(crate) async fn commit_claim_with_change_as(
    db: &Db,
    context: &RunContext,
    r: &ClaimRequest,
) -> Result<(ClaimResult, bool)> {
    let mut tx = begin_write(db.write_pool()).await?;
    let run = run_ledger::resolve(&mut tx, context, false).await?;
    visible(&mut tx, &run.owner, &r.target.record_id).await?;
    if run.owner != r.principal_id {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    }
    operation_key(&r.operation_key)?;
    if let Some((old, receipt)) = retry(&mut tx, &run.owner, &r.command, &r.operation_key).await? {
        if old != *r {
            return Err(Error::conflict("claims retry key reused"));
        }
        return Ok((ClaimResult::Committed(receipt), false));
    }
    // A completed receipt belongs to the principal, not the caller's current
    // run. Fresh mutations must match the context's run exactly.
    if run.run_id != r.run.run_id {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    }
    run_ledger::resolve(&mut tx, context, true).await?;
    live(&mut tx, r).await?;
    validate(&mut tx, r, i64::MAX).await?;
    let (head, current) = state(&mut tx, &r.aggregate_id, &r.target.record_id).await?;
    if folded(r, current.as_ref(), head, "validation", "", 0)?.is_none() {
        tx.rollback().await?;
        return Ok((ClaimResult::Unchanged, false));
    }
    let receipt_id = Uuid::new_v4().to_string();
    let mut acts = crate::act::ActAllocation::new();
    let event = crate::store::append_kernel_provider_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: r.aggregate_id.clone(),
            event_type: commit_port::PROVIDER_OUTCOME_EVENT.into(),
            payload: serde_json::to_value(Outcome {
                request: r.clone(),
                receipt_id: receipt_id.clone(),
            })?,
            actor: Some(run.owner),
        },
        &mut acts,
    )
    .await?;
    tx.commit().await?;
    Ok((
        ClaimResult::Committed(ClaimReceipt {
            aggregate_id: r.aggregate_id.clone(),
            receipt_id,
            event_seq: event.local_seq,
        }),
        true,
    ))
}
fn envelope(event: &EventRow, o: &Outcome) -> Result<()> {
    let id = Uuid::parse_str(&o.receipt_id)
        .map_err(|_| Error::engine("claims receipt must be a host UUID"))?;
    if id.get_version_num() != 4
        || id.to_string() != o.receipt_id
        || event.record_id != o.request.aggregate_id
        || event.actor.as_deref() != Some(&o.request.principal_id)
    {
        return Err(Error::engine("claims host envelope mismatch"));
    }
    Ok(())
}
pub(crate) fn admit_recorded<'a>(
    conn: &'a mut SqliteConnection,
    event: &'a EventRow,
) -> ValidationFuture<'a> {
    Box::pin(async move {
        let o: Outcome = event_payload(event)?;
        envelope(event, &o)?;
        live(conn, &o.request).await?;
        validate(conn, &o.request, i64::MAX).await?;
        let (head, current) =
            state(conn, &o.request.aggregate_id, &o.request.target.record_id).await?;
        if folded(
            &o.request,
            current.as_ref(),
            head,
            &o.receipt_id,
            &event.created_at,
            event.local_seq,
        )?
        .is_none()
        {
            return Err(Error::engine("no-op claims must not append"));
        }
        Ok(())
    })
}
pub(crate) fn validate_recorded<'a>(
    conn: &'a mut SqliteConnection,
    event: &'a EventRow,
    decoded: &'a Decoded,
    replay: bool,
) -> ValidationFuture<'a> {
    Box::pin(async move {
        let o: Outcome = serde_json::from_value(decoded.domain.clone())?;
        envelope(event, &o)?;
        if !replay {
            live(conn, &o.request).await?;
        }
        validate(conn, &o.request, event.local_seq).await
    })
}
/// Bounded explicit target reads. View is checked for every target before occupancy.
pub async fn claims_as(db: &Db, principal: &str, records: &[String]) -> Result<Vec<ClaimRead>> {
    if records.len() > 100 {
        return Err(Error::engine(
            "claims reads require at most 100 explicit record IDs",
        ));
    }
    let ids: std::collections::BTreeSet<_> = records.iter().collect();
    let mut tx = db.write_pool().begin().await?;
    for id in &ids {
        visible(&mut tx, principal, id).await?;
    }
    let mut result = Vec::new();
    for id in ids {
        let (head, current) = state(&mut tx, &aggregate(id), id).await?;
        let occupied = current.as_ref().is_some_and(|s| s.holder.is_some());
        let owner = current
            .as_ref()
            .and_then(|s| s.holder.as_ref())
            .is_some_and(|h| h.principal == principal);
        result.push(ClaimRead {
            record_id: id.clone(),
            occupied,
            withheld: occupied && !owner,
            holder: current
                .as_ref()
                .and_then(|s| s.holder.clone())
                .filter(|_| owner),
            generation: current.as_ref().map(|s| s.generation).filter(|_| owner),
            head: head.filter(|_| owner),
        });
    }
    Ok(result)
}

/// Recover the original release command for an operation-key retry, before
/// inspecting today's occupancy. This does not authorize a new release.
#[cfg(feature = "v2-kernel-probe")]
pub async fn release_retry_command_as(
    db: &Db,
    context: &RunContext,
    record: &str,
    key: &str,
) -> Result<Option<provider::Command>> {
    let mut tx = db.write_pool().begin().await?;
    let run = run_ledger::resolve(&mut tx, context, false).await?;
    visible(&mut tx, &run.owner, record).await?;
    operation_key(key)?;
    let placeholder = provider::Command::Release {
        holder_run_id: String::new(),
        generation: 0,
        head: 0,
    };
    if let Some((r, _)) = retry(&mut tx, &run.owner, &placeholder, key).await? {
        if r.target.record_id != record || r.run.run_id != run.run_id {
            return Err(Error::conflict("claims retry key reused"));
        }
        return Ok(Some(r.command));
    }
    Ok(None)
}
