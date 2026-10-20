//! Portable half of the catalogue's fenced offboarding saga. One sealed event
//! atomically transfers recoverable content, strips grants, and retires activity.
use super::*;
use crate::identity::hosted::HostedMembershipCleanupCounts;
use crate::kernel::provider_catalogue::StoredState;

pub(crate) const EVENT: &str = "kernel.hosted_offboarding.v1";

/// Host-only proof of a fenced catalogue operation. No tool-deserializable data.
pub struct VerifiedOffboarding {
    operation_id: String,
    actor: String,
    target: String,
    recipient: String,
    reason: String,
}
impl VerifiedOffboarding {
    /// # Safety
    /// The catalogue must have begun this exact operation, fenced the target,
    /// authorized the actor, and protected its active transfer recipient. Hold
    /// deployment/database writable admission through cleanup and finalization.
    /// IDs and recipient selection come from that operation, never tool input.
    pub unsafe fn from_catalog_unchecked(
        operation_id: String,
        actor: String,
        target: String,
        recipient: String,
        reason: String,
    ) -> Self {
        Self {
            operation_id,
            actor,
            target,
            recipient,
            reason,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cleanup {
    operation_id: String,
    actor_catalog_id: String,
    target_catalog_id: String,
    recipient_catalog_id: String,
    target_principal: Option<String>,
    recipient_principal: String,
    reason: String,
    counts: HostedMembershipCleanupCounts,
}

async fn principal_for(
    conn: &mut SqliteConnection,
    roster: &Roster,
    catalog: &str,
) -> Result<Option<String>> {
    let Some(binding) = roster.catalog_accounts.get(catalog) else {
        return Ok(None);
    };
    Ok(sqlx::query_scalar(
        "SELECT principal_id FROM main.kernel_principals WHERE auth_binding=? AND kind='account'",
    )
    .bind(binding)
    .fetch_optional(conn)
    .await?)
}

/// Retry-safe: recovery returns the original event's counts, including after a
/// catalogue acknowledgement failed. A new operation is required after rejoin.
pub async fn apply(
    db: &Db,
    operation: VerifiedOffboarding,
) -> Result<HostedMembershipCleanupCounts> {
    if Uuid::parse_str(&operation.operation_id)
        .map(|id| id.to_string())
        .ok()
        .as_deref()
        != Some(&operation.operation_id)
        || operation.reason.trim().is_empty()
        || operation.target == operation.recipient
    {
        return Err(Error::engine("invalid hosted v2 cleanup operation"));
    }
    let mut tx = begin_write(db.write_pool()).await?;
    let old: Option<String> = sqlx::query_scalar("SELECT payload FROM main.content_events WHERE type=? AND json_extract(payload,'$.operation_id')=?")
        .bind(EVENT).bind(&operation.operation_id).fetch_optional(&mut *tx).await?;
    if let Some(raw) = old {
        let old: Cleanup = serde_json::from_str(&raw)?;
        if old.actor_catalog_id != operation.actor
            || old.target_catalog_id != operation.target
            || old.recipient_catalog_id != operation.recipient
            || old.reason != operation.reason
        {
            return Err(Error::conflict("hosted v2 cleanup operation conflicts"));
        }
        return Ok(old.counts);
    }
    let roster = roster_on(&mut tx)
        .await?
        .ok_or_else(|| Error::engine("hosted v2 cleanup requires identity activation"))?;
    let target = principal_for(&mut tx, &roster, &operation.target).await?;
    let recipient = principal_for(&mut tx, &roster, &operation.recipient)
        .await?
        .ok_or_else(|| Error::engine("hosted v2 cleanup recipient identity is unavailable"))?;
    if target
        .as_ref()
        .is_some_and(|id| roster.members.values().any(|m| m == id))
        || !roster.members.values().any(|m| m == &recipient)
    {
        return Err(Error::engine(
            "hosted v2 cleanup requires a fenced target and active recipient",
        ));
    }
    let counts = counts_on(&mut tx, target.as_deref()).await?;
    let host: String =
        sqlx::query_scalar("SELECT principal_id FROM main.kernel_principals WHERE auth_binding=?")
            .bind(hq::HOST_IMPORT_BINDING)
            .fetch_one(&mut *tx)
            .await?;
    let payload = Cleanup {
        operation_id: operation.operation_id,
        actor_catalog_id: operation.actor,
        target_catalog_id: operation.target,
        recipient_catalog_id: operation.recipient,
        target_principal: target,
        recipient_principal: recipient,
        reason: operation.reason,
        counts,
    };
    append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: KERNEL_ROOT_ID.into(),
            event_type: EVENT.into(),
            payload: serde_json::to_value(payload)?,
            actor: Some(host),
        },
        &mut crate::act::ActAllocation::new(),
    )
    .await?;
    tx.commit().await?;
    Ok(counts)
}

// The shared predicate also retains native/imported Message state if its
// carrier is damaged. Unrelated fields cannot spoof a Message's native type.
async fn owned_records(conn: &mut SqliteConnection, target: &str) -> Result<(Vec<String>, i64)> {
    let ids: Vec<String> =
        sqlx::query_scalar("SELECT id FROM main.kernel_records WHERE owner_id=? ORDER BY id")
            .bind(target)
            .fetch_all(&mut *conn)
            .await?;
    let mut transferable = Vec::new();
    let mut retained = 0;
    for id in ids {
        if crate::kernel::is_message_record(conn, &id).await? {
            retained += 1;
        } else {
            transferable.push(id);
        }
    }
    Ok((transferable, retained))
}

async fn counts_on(
    conn: &mut SqliteConnection,
    target: Option<&str>,
) -> Result<HostedMembershipCleanupCounts> {
    let Some(target) = target else {
        return Ok(HostedMembershipCleanupCounts {
            transferred_record_count: 0,
            removed_grant_count: 0,
            retained_authorship_count: 0,
        });
    };
    let (records, retained) = owned_records(conn, target).await?;
    let homes: i64 = sqlx::query_scalar("SELECT count(*) FROM main.kernel_roots WHERE owner_id=?")
        .bind(target)
        .fetch_one(&mut *conn)
        .await?;
    let grants: i64 = sqlx::query_scalar("SELECT count(*) FROM main.kernel_policy_entries WHERE subject_kind='account' AND subject_id=?")
        .bind(target).fetch_one(conn).await?;
    Ok(HostedMembershipCleanupCounts {
        transferred_record_count: records.len() as i64 + homes,
        removed_grant_count: grants,
        retained_authorship_count: retained,
    })
}

pub(super) async fn project(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    let p: Cleanup = event_payload(event)?;
    let logged: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.content_events WHERE seq=? AND id=? AND type=? AND record_id=? AND payload IS ? AND actor IS ? AND created_at=?)")
        .bind(event.local_seq).bind(&event.id).bind(EVENT).bind(&event.record_id).bind(&event.payload).bind(&event.actor).bind(&event.created_at).fetch_one(&mut *conn).await?;
    let duplicate: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.content_events WHERE type=? AND json_extract(payload,'$.operation_id')=? AND seq<?)")
        .bind(EVENT).bind(&p.operation_id).bind(event.local_seq).fetch_one(&mut *conn).await?;
    if !logged
        || duplicate
        || p.reason.trim().is_empty()
        || p.target_catalog_id == p.recipient_catalog_id
        || Uuid::parse_str(&p.operation_id)
            .map(|id| id.to_string())
            .ok()
            .as_deref()
            != Some(&p.operation_id)
    {
        return Err(Error::engine("invalid hosted v2 cleanup event"));
    }
    let roster = roster_before(conn, event.local_seq)
        .await?
        .ok_or_else(|| Error::engine("hosted v2 cleanup requires identity activation"))?;
    if event.record_id != KERNEL_ROOT_ID
        || principal_for(conn, &roster, &p.target_catalog_id).await? != p.target_principal
        || principal_for(conn, &roster, &p.recipient_catalog_id)
            .await?
            .as_deref()
            != Some(&p.recipient_principal)
        || !roster.members.values().any(|m| m == &p.recipient_principal)
        || p.target_principal
            .as_ref()
            .is_some_and(|t| roster.members.values().any(|m| m == t))
        || counts_on(conn, p.target_principal.as_deref()).await? != p.counts
    {
        return Err(Error::engine("hosted v2 cleanup witness mismatch"));
    }
    crate::kernel::app_installs::revoke_offboarded(conn, event).await?;
    let Some(target) = p.target_principal else {
        return Ok(());
    };
    // Messages retain immutable authorship, as in v1. Every recoverable home
    // (including private homes and the workspace root) follows its recipient.
    for id in owned_records(conn, &target).await?.0 {
        sqlx::query("UPDATE main.kernel_records SET owner_id=? WHERE id=?")
            .bind(&p.recipient_principal)
            .bind(id)
            .execute(&mut *conn)
            .await?;
    }
    sqlx::query("UPDATE main.kernel_roots SET owner_id=? WHERE owner_id=?")
        .bind(&p.recipient_principal)
        .bind(&target)
        .execute(&mut *conn)
        .await?;
    sqlx::query("UPDATE main.kernel_root_bootstrap SET principal_id=? WHERE principal_id=?")
        .bind(&p.recipient_principal)
        .bind(&target)
        .execute(&mut *conn)
        .await?;
    sqlx::query(
        "DELETE FROM main.kernel_policy_entries WHERE subject_kind='account' AND subject_id=?",
    )
    .bind(&target)
    .execute(&mut *conn)
    .await?;
    sqlx::query("UPDATE main.kernel_runs SET closed=1,head=? WHERE owner_principal=? AND closed=0")
        .bind(event.local_seq)
        .bind(&target)
        .execute(&mut *conn)
        .await?;
    // Receipts describe the old membership epoch. Reusing an operation key
    // after rejoin must validate current state, not return an old success for
    // a claim just released by this fold. Historical outcome events remain.
    sqlx::query("DELETE FROM main.kernel_provider_receipts WHERE principal_id=?")
        .bind(&target)
        .execute(&mut *conn)
        .await?;
    let claims: Vec<(String, String)> = sqlx::query_as(
        "SELECT id,state_json FROM main.kernel_provider_state WHERE provider_key=? ORDER BY id",
    )
    .bind(crate::v2_standard::claims_v1::PROVIDER_KEY)
    .fetch_all(&mut *conn)
    .await?;
    for (id, raw) in claims {
        let mut stored: StoredState = serde_json::from_str(&raw)?;
        let mut state: crate::v2_standard::claims_v1::State =
            serde_json::from_value(stored.view()?)?;
        if state.holder.as_ref().is_some_and(|h| h.principal == target) {
            state.holder = None;
            stored.state = serde_json::to_value(state)?;
            sqlx::query("UPDATE main.kernel_provider_state SET state_json=?,head=? WHERE id=?")
                .bind(serde_json::to_string(&stored)?)
                .bind(event.local_seq)
                .bind(id)
                .execute(&mut *conn)
                .await?;
        }
    }
    Ok(())
}
