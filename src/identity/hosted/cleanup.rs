use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;
use uuid::Uuid;

use crate::db::Db;
use crate::error::{Error, Result};
use crate::policy::NormalizedPolicyEntry;
use crate::store::{append_in, AppendSpec};

use super::existing_hosted_identity_in_snapshot;

/// Durable counts produced by one portable hosted-membership cleanup.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostedMembershipCleanupCounts {
    pub transferred_record_count: i64,
    pub removed_grant_count: i64,
    pub retained_authorship_count: i64,
}

impl HostedMembershipCleanupCounts {
    fn validate(self) -> Result<Self> {
        if self.transferred_record_count < 0
            || self.removed_grant_count < 0
            || self.retained_authorship_count < 0
        {
            return Err(Error::engine("membership cleanup count is invalid"));
        }
        Ok(self)
    }
}

/// Exact portable state captured for a hosted membership-offboarding plan.
///
/// Fields remain private so held callers cannot synthesize partial state. The
/// serde representation deliberately matches the historical hosted projection
/// byte-for-byte because prepared executor evidence can survive a deployment.
#[doc(hidden)]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostedMembershipCleanupProjection {
    target_account_id: Option<String>,
    target_person_id: Option<String>,
    recipient_account_id: Option<String>,
    recipient_person_id: Option<String>,
    transferable_record_ids: Vec<String>,
    retained_authorship_record_ids: Vec<String>,
    affected_policy_entries: Vec<Value>,
    removed_grants: Vec<Value>,
    recovered_receipt: Option<(i64, i64, i64)>,
}

impl HostedMembershipCleanupProjection {
    pub fn from_recovered_counts(counts: HostedMembershipCleanupCounts) -> Result<Self> {
        let counts = counts.validate()?;
        Ok(Self {
            target_account_id: None,
            target_person_id: None,
            recipient_account_id: None,
            recipient_person_id: None,
            transferable_record_ids: Vec::new(),
            retained_authorship_record_ids: Vec::new(),
            affected_policy_entries: Vec::new(),
            removed_grants: Vec::new(),
            recovered_receipt: Some((
                counts.transferred_record_count,
                counts.removed_grant_count,
                counts.retained_authorship_count,
            )),
        })
    }

    pub fn counts(&self) -> Result<HostedMembershipCleanupCounts> {
        match self.recovered_receipt {
            Some((transferred, removed, retained)) => HostedMembershipCleanupCounts {
                transferred_record_count: transferred,
                removed_grant_count: removed,
                retained_authorship_count: retained,
            }
            .validate(),
            None => Ok(HostedMembershipCleanupCounts {
                transferred_record_count: i64::try_from(self.transferable_record_ids.len())
                    .map_err(|_| Error::engine("membership cleanup count overflow"))?,
                removed_grant_count: i64::try_from(self.removed_grants.len())
                    .map_err(|_| Error::engine("membership cleanup count overflow"))?,
                retained_authorship_count: i64::try_from(self.retained_authorship_record_ids.len())
                    .map_err(|_| Error::engine("membership cleanup count overflow"))?,
            }),
        }
    }

    pub fn transferable_record_ids(&self) -> &[String] {
        &self.transferable_record_ids
    }

    pub fn retained_authorship_record_ids(&self) -> &[String] {
        &self.retained_authorship_record_ids
    }

    pub fn removed_grants(&self) -> &[Value] {
        &self.removed_grants
    }
}

fn validate_operation_id(operation_id: &str) -> Result<()> {
    let parsed = Uuid::parse_str(operation_id)
        .map_err(|_| Error::engine("membership cleanup operation id is invalid"))?;
    if parsed.hyphenated().to_string() != operation_id {
        return Err(Error::engine(
            "membership cleanup operation id is not canonical",
        ));
    }
    Ok(())
}

fn ownership_actor_prefix(operation_id: &str) -> String {
    format!("engine:membership-offboarding:{operation_id}:ownership-transfer:retained-authorship:")
}

fn grant_actor_prefix(operation_id: &str) -> String {
    format!("engine:membership-offboarding:{operation_id}:removed-grants:")
}

fn parse_retained_count(actor: &str, prefix: &str) -> Option<i64> {
    actor
        .strip_prefix(prefix)?
        .parse::<i64>()
        .ok()
        .filter(|value| *value >= 0)
}

async fn recovered_cleanup_counts_in(
    connection: &mut sqlx::SqliteConnection,
    operation_id: &str,
) -> Result<Option<HostedMembershipCleanupCounts>> {
    let ownership_prefix = ownership_actor_prefix(operation_id);
    let transferred: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM content_events
         WHERE actor LIKE ? || '%' AND type = 'record.updated'",
    )
    .bind(&ownership_prefix)
    .fetch_one(&mut *connection)
    .await?;
    let ownership_actors: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT actor FROM content_events
         WHERE actor LIKE ? || '%' AND type = 'record.updated' ORDER BY actor",
    )
    .bind(&ownership_prefix)
    .fetch_all(&mut *connection)
    .await?;
    let prefix = grant_actor_prefix(operation_id);
    let actors: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT actor FROM policy_events WHERE actor LIKE ? || '%' ORDER BY actor",
    )
    .bind(&prefix)
    .fetch_all(&mut *connection)
    .await?;
    if ownership_actors.is_empty() && actors.is_empty() {
        return Ok(None);
    }
    let mut removed: Option<i64> = None;
    let mut retained: Option<i64> = None;
    for actor in ownership_actors {
        let count = parse_retained_count(&actor, &ownership_prefix)
            .ok_or_else(|| Error::engine("membership cleanup receipt is malformed"))?;
        if retained.is_some_and(|prior| prior != count) {
            return Err(Error::engine("membership cleanup receipt conflicts"));
        }
        retained = Some(count);
    }
    for actor in actors {
        let suffix = actor
            .strip_prefix(&prefix)
            .ok_or_else(|| Error::engine("membership cleanup receipt is malformed"))?;
        let (removed_raw, retained_raw) = suffix
            .split_once(":retained-authorship:")
            .ok_or_else(|| Error::engine("membership cleanup receipt is malformed"))?;
        let removed_count = removed_raw
            .parse::<i64>()
            .ok()
            .filter(|value| *value >= 0)
            .ok_or_else(|| Error::engine("membership cleanup receipt is malformed"))?;
        let retained_count = retained_raw
            .parse::<i64>()
            .ok()
            .filter(|value| *value >= 0)
            .ok_or_else(|| Error::engine("membership cleanup receipt is malformed"))?;
        if removed.is_some_and(|prior| prior != removed_count)
            || retained.is_some_and(|prior| prior != retained_count)
        {
            return Err(Error::engine("membership cleanup receipt conflicts"));
        }
        removed = Some(removed_count);
        retained = Some(retained_count);
    }
    Ok(Some(HostedMembershipCleanupCounts {
        transferred_record_count: transferred,
        removed_grant_count: removed.unwrap_or(0),
        retained_authorship_count: retained.unwrap_or(0),
    }))
}

async fn project_in(
    connection: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    operation_id: Option<&str>,
    target_email: &str,
    recipient_email: &str,
) -> Result<HostedMembershipCleanupProjection> {
    if let Some(operation_id) = operation_id {
        validate_operation_id(operation_id)?;
        if let Some(receipt) = recovered_cleanup_counts_in(connection, operation_id).await? {
            return HostedMembershipCleanupProjection::from_recovered_counts(receipt);
        }
    }
    let target = existing_hosted_identity_in_snapshot(connection, target_email).await?;
    let recipient = existing_hosted_identity_in_snapshot(connection, recipient_email).await?;
    let Some(target) = target else {
        return Ok(HostedMembershipCleanupProjection {
            target_account_id: None,
            target_person_id: None,
            recipient_account_id: recipient
                .as_ref()
                .map(|identity| identity.account_id.clone()),
            recipient_person_id: recipient
                .as_ref()
                .map(|identity| identity.person_record_id.clone()),
            transferable_record_ids: Vec::new(),
            retained_authorship_record_ids: Vec::new(),
            affected_policy_entries: Vec::new(),
            removed_grants: Vec::new(),
            recovered_receipt: None,
        });
    };
    let target_account_id = target.account_id;
    let target_person_id = target.person_record_id;
    let record_rows = sqlx::query(
        "SELECT id, type FROM records
         WHERE owner_id = ? AND deleted_at IS NULL ORDER BY id",
    )
    .bind(&target_person_id)
    .fetch_all(&mut **connection)
    .await?;
    let mut transferable_record_ids = Vec::new();
    let mut retained_authorship_record_ids = Vec::new();
    for row in record_rows {
        let id: String = row.try_get("id")?;
        if row.try_get::<String, _>("type")? == "Message" {
            retained_authorship_record_ids.push(id);
        } else {
            transferable_record_ids.push(id);
        }
    }
    if !transferable_record_ids.is_empty() && recipient.is_none() {
        return Err(Error::engine(
            "membership cleanup requires the transfer owner to establish a portable identity",
        ));
    }
    let policy_rows = sqlx::query(
        "SELECT policy_anchor_id, subject_kind, subject_id, effect, capability
         FROM policy_entries
         WHERE policy_anchor_id IN (
           SELECT DISTINCT policy_anchor_id FROM policy_entries
           WHERE subject_kind = 'account' AND subject_id = ?
         )
         ORDER BY policy_anchor_id, subject_kind, subject_id, effect, capability",
    )
    .bind(&target_account_id)
    .fetch_all(&mut **connection)
    .await?;
    let mut affected_policy_entries = Vec::with_capacity(policy_rows.len());
    let mut removed_grants = Vec::new();
    for row in policy_rows {
        let entry = json!({
            "policy_anchor_id":row.try_get::<String, _>("policy_anchor_id")?,
            "subject_kind":row.try_get::<String, _>("subject_kind")?,
            "subject_id":row.try_get::<String, _>("subject_id")?,
            "effect":row.try_get::<String, _>("effect")?,
            "capability":row.try_get::<String, _>("capability")?,
        });
        if entry["subject_kind"] == "account" && entry["subject_id"] == target_account_id {
            removed_grants.push(entry.clone());
        }
        affected_policy_entries.push(entry);
    }
    Ok(HostedMembershipCleanupProjection {
        target_account_id: Some(target_account_id),
        target_person_id: Some(target_person_id),
        recipient_account_id: recipient
            .as_ref()
            .map(|identity| identity.account_id.clone()),
        recipient_person_id: recipient
            .as_ref()
            .map(|identity| identity.person_record_id.clone()),
        transferable_record_ids,
        retained_authorship_record_ids,
        affected_policy_entries,
        removed_grants,
        recovered_receipt: None,
    })
}

/// Read the exact portable state used to prepare a hosted offboarding plan.
#[doc(hidden)]
pub async fn project_hosted_membership_cleanup(
    db: &Db,
    operation_id: Option<&str>,
    target_email: &str,
    recipient_email: &str,
) -> Result<HostedMembershipCleanupProjection> {
    let mut transaction = db.write_pool().begin().await?;
    let projection = project_in(
        &mut transaction,
        operation_id,
        target_email,
        recipient_email,
    )
    .await?;
    transaction.rollback().await?;
    Ok(projection)
}

fn projection_field(value: &Value, field: &str) -> Result<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| Error::engine("membership cleanup projection is malformed"))
}

/// Atomically apply the portable half of a fenced hosted membership cleanup.
#[doc(hidden)]
pub async fn apply_hosted_membership_cleanup(
    db: &Db,
    operation_id: &str,
    reason: &str,
    target_email: &str,
    recipient_email: &str,
    expected_projection: Option<&HostedMembershipCleanupProjection>,
) -> Result<HostedMembershipCleanupCounts> {
    validate_operation_id(operation_id)?;
    let mut transaction = crate::db::begin_write(db.write_pool()).await?;
    let projection = project_in(
        &mut transaction,
        Some(operation_id),
        target_email,
        recipient_email,
    )
    .await?;
    if expected_projection.is_some_and(|expected| expected != &projection) {
        transaction.rollback().await?;
        return Err(Error::engine(
            "membership cleanup state changed since preparation",
        ));
    }
    if let Some((transferred, removed, retained)) = projection.recovered_receipt {
        transaction.rollback().await?;
        return Ok(HostedMembershipCleanupCounts {
            transferred_record_count: transferred,
            removed_grant_count: removed,
            retained_authorship_count: retained,
        });
    }
    let Some(target_account_id) = projection.target_account_id.as_deref() else {
        transaction.rollback().await?;
        return Ok(HostedMembershipCleanupCounts {
            transferred_record_count: 0,
            removed_grant_count: 0,
            retained_authorship_count: 0,
        });
    };
    let retained_authorship_count = i64::try_from(projection.retained_authorship_record_ids.len())
        .map_err(|_| Error::engine("membership cleanup count overflow"))?;
    let mut policies: BTreeMap<String, Vec<NormalizedPolicyEntry>> = BTreeMap::new();
    let mut removed_grant_count = 0_i64;
    for row in &projection.affected_policy_entries {
        let anchor = row
            .get("policy_anchor_id")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::engine("membership cleanup projection is malformed"))?
            .to_owned();
        let entry = NormalizedPolicyEntry {
            subject_kind: projection_field(row, "subject_kind")?,
            subject_id: projection_field(row, "subject_id")?,
            effect: projection_field(row, "effect")?,
            capability: projection_field(row, "capability")?,
        };
        let retained = policies.entry(anchor).or_default();
        if entry.subject_kind == "account" && entry.subject_id == target_account_id {
            removed_grant_count += 1;
        } else {
            retained.push(entry);
        }
    }

    let content_actor = format!(
        "{}{}",
        ownership_actor_prefix(operation_id),
        retained_authorship_count
    );
    if let Some(recipient_person_id) = projection.recipient_person_id.as_deref() {
        for record_id in &projection.transferable_record_ids {
            append_in(
                db,
                &mut transaction,
                AppendSpec {
                    record_id: record_id.clone(),
                    event_type: "record.updated".into(),
                    payload: json!({"owner_id": recipient_person_id}),
                    actor: Some(content_actor.clone()),
                },
            )
            .await?;
        }
    }
    let policy_actor = format!(
        "{}{}:retained-authorship:{}",
        grant_actor_prefix(operation_id),
        removed_grant_count,
        retained_authorship_count,
    );
    for (anchor, entries) in policies {
        crate::policy::append_replaced_in(
            &mut transaction,
            &anchor,
            entries,
            &policy_actor,
            reason,
        )
        .await?;
    }
    db.commit_content(transaction).await?;
    Ok(HostedMembershipCleanupCounts {
        transferred_record_count: i64::try_from(projection.transferable_record_ids.len())
            .map_err(|_| Error::engine("membership cleanup count overflow"))?,
        removed_grant_count,
        retained_authorship_count,
    })
}

#[cfg(test)]
mod tests {
    use super::validate_operation_id;

    #[test]
    fn cleanup_operation_ids_are_canonical_uuids() {
        let canonical = "8ec6b09c-9c8d-4f5f-b7bf-779392f39313";
        validate_operation_id(canonical).unwrap();

        for invalid in [
            "8EC6B09C-9C8D-4F5F-B7BF-779392F39313",
            "8ec6b09c9c8d4f5fb7bf779392f39313",
            "operation%",
        ] {
            assert!(validate_operation_id(invalid).is_err(), "{invalid}");
        }
    }
}
