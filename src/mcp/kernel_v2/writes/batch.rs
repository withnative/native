//! The Shell's atomic guard + archive/reopen batch, using the ordinary leaves.
//! Other batch operations refuse explicitly until their v2 parity is qualified.
use super::*;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    reason: String,
    idempotency_key: Option<String>,
    items: Vec<Item>,
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Item {
    Update {
        id: String,
        if_unmodified_since: Option<String>,
        if_policy_revision: Option<String>,
    },
    Archive {
        id: String,
        archived: Option<bool>,
    },
}
impl Item {
    fn id(&self) -> &str {
        match self {
            Self::Update { id, .. } | Self::Archive { id, .. } => id,
        }
    }
    fn op(&self) -> &'static str {
        match self {
            Self::Update { .. } => "update",
            Self::Archive { .. } => "archive",
        }
    }
}

pub(super) async fn execute(db: &Db, actor: &str, raw: Value) -> Result<Value> {
    let args: Args = parse("batch_write (v2 supports guard-only update and archive/reopen; other batch operations aren't available yet)", raw.clone())?;
    if args.reason.trim().is_empty() {
        return Err(invalid("batch_write requires a nonblank reason"));
    }
    if args.items.is_empty() || args.items.len() > crate::mcp::tools::batch_write::MAX_BATCH_WRITE {
        return Err(invalid("batch_write requires 1..25 items"));
    }
    let key = args.idempotency_key.as_deref().map(str::trim);
    if key.is_some_and(|k| k.is_empty() || k.chars().count() > 200) {
        return Err(invalid("idempotency_key must be 1..200 characters"));
    }
    let mut seen = HashMap::new();
    for (index, item) in args.items.iter().enumerate() {
        if !crate::mcp::record_ref::is_canonical_uuid_v4_or_v7(item.id()) {
            return Err(invalid(format!(
                "batch_write items[{index}].id requires an exact canonical v4/v7 UUID"
            )));
        }
        if let Item::Update {
            if_unmodified_since,
            if_policy_revision,
            ..
        } = item
        {
            if if_unmodified_since.is_none() && if_policy_revision.is_none() {
                return Err(invalid(format!(
                    "batch_write items[{index}] names no changes or guards"
                )));
            }
        }
        if let Some(previous) = seen.insert(item.id(), index) {
            if index != previous + 1
                || !matches!(args.items[previous], Item::Update { .. })
                || !matches!(item, Item::Archive { .. })
            {
                return Err(invalid("batch_write only permits a repeated id for an adjacent guard-only update followed by archive"));
            }
        }
    }
    let fingerprint = dispatched_fingerprint("batch_write", raw)?;
    let mut tx = begin_write(db.write_pool()).await?;
    kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
    sqlx::query(RECEIPTS).execute(&mut *tx).await?;
    if let Some(key) = key {
        let old: Option<(String,String)> = sqlx::query_as("SELECT request_json,receipt_json FROM kernel_mcp_write_receipts WHERE principal_id=? AND operation='batch_write' AND operation_key=?")
            .bind(actor).bind(key).fetch_optional(&mut *tx).await?;
        if let Some((request, receipt)) = old {
            if stored_fingerprint("batch_write", serde_json::from_str(&request)?)? != fingerprint {
                return Err(Error::conflict(
                    "idempotency_key reused for different request",
                ));
            }
            // V1 batch replay returns a historical receipt after current View
            // on every disclosed target; it must not re-execute old guards.
            for item in &args.items {
                kernel::kernel_require(&mut tx, actor, item.id(), Capability::View).await?;
            }
            let receipt = serde_json::from_str(&receipt)?;
            tx.rollback().await?;
            return Ok(receipt);
        }
    }
    let mut acts = ActAllocation::new();
    // Prove the whole cohort before allocating attribution or appending data.
    for item in &args.items {
        kernel::kernel_require(
            &mut tx,
            actor,
            item.id(),
            if matches!(item, Item::Archive { .. }) {
                Capability::Manage
            } else {
                Capability::Edit
            },
        )
        .await?;
    }
    use sha2::{Digest, Sha256};
    let pending = kernel::app_installs::start_app_action_in(
        db,
        &mut tx,
        actor,
        "batch_write",
        hex::encode(Sha256::digest(fingerprint.as_bytes())),
        Some(args.reason.clone()),
        &mut acts,
    )
    .await?;
    let mut changed = 0;
    let mut results = Vec::new();
    for (index, item) in args.items.iter().enumerate() {
        let (previous_seq, previous_event_id): (i64, String) = sqlx::query_as(
            "SELECT seq,id FROM main.content_events WHERE record_id=? ORDER BY seq DESC LIMIT 1",
        )
        .bind(item.id())
        .fetch_one(&mut *tx)
        .await?;
        let did_change = match item {
            Item::Update {
                id,
                if_unmodified_since,
                if_policy_revision,
            } => {
                kernel::policy_read::assert_revision_on(
                    &mut tx,
                    actor,
                    id,
                    if_policy_revision.as_deref(),
                )
                .await?;
                if let Some(expected) = if_unmodified_since {
                    let expected = chrono::DateTime::parse_from_rfc3339(expected)
                        .map_err(|_| invalid("if_unmodified_since must be RFC3339"))?;
                    // Match the public SQL clock, including record-local events
                    // that do not advance the typed-definition revision.
                    let current: String = sqlx::query_scalar("SELECT strftime('%Y-%m-%dT%H:%M:%fZ',created_at) FROM content_events WHERE record_id=? ORDER BY seq DESC LIMIT 1")
                        .bind(id).fetch_one(&mut *tx).await?;
                    let current = chrono::DateTime::parse_from_rfc3339(&current)
                        .map_err(|_| invalid("invalid kernel timestamp"))?;
                    if current != expected {
                        return Err(Error::conflict(
                            "batch_write: stale if_unmodified_since; nothing written",
                        ));
                    }
                }
                false
            }
            Item::Archive { id, archived } => {
                archive(
                    db,
                    &mut tx,
                    &mut acts,
                    actor,
                    &json!({"id":id,"archived":archived.unwrap_or(true),"reason":args.reason}),
                )
                .await?["changed"]
                    == true
            }
        };
        changed += usize::from(did_change);
        results.push(json!({"index":index,"op":item.op(),"id":item.id(),"status":if did_change {"changed"} else {"unchanged"},"previous_seq":previous_seq,"previous_event_id":previous_event_id}));
    }
    let mut receipt = json!({"requested":args.items.len(),"changed":changed,"unchanged":args.items.len()-changed,"results":results});
    if let Some(act) = acts.get() {
        receipt["act"] = json!(act);
    }
    if let Some(attribution) =
        kernel::app_installs::finish_app_action_in(db, &mut tx, actor, pending, &mut acts).await?
    {
        receipt["app_attribution"] = attribution;
    }
    if let Some(key) = key {
        sqlx::query("INSERT INTO kernel_mcp_write_receipts VALUES(?,'batch_write',?,?,?)")
            .bind(actor)
            .bind(key)
            .bind(fingerprint)
            .bind(serde_json::to_string(&receipt)?)
            .execute(&mut *tx)
            .await?;
    }
    db.commit_kernel_content(tx).await?;
    Ok(receipt)
}
