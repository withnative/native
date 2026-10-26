//! Durable read/disclosure events and a Native-only per-account audit view.
//! Version and status events *are* the write audit; there is no second append
//! that could leave a write acknowledged without its audit. Confirmations
//! carry the locally verified management resolution and its version binding.

use super::client::PROVIDER_ID;
use super::store::{Store, WriteTx};
use crate::control::{
    hcp_audit_aggregate_id, hcp_state_aggregate_id, ControlEventPayload, HcpEntryConfirmedPayload,
    HcpEntryStatusSetPayload, HcpEntryVersionedPayload, HcpReadPayload,
};
use crate::db::Db;
use crate::error::{Error, Result};
use crate::mcp::registry::{Caller, ToolRegistry};
use crate::mcp::ToolKind;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Row;

pub const AUDIT_TOOL: &str = "read_hcp_audit";

impl Store<'_> {
    pub(super) async fn disclosed_in(&self, tx: &mut WriteTx, urn: &str) -> Result<bool> {
        // A successful add/update returns the entry to its submitting client.
        // Its accepted version event is both the write audit and disclosure:
        // no separate ledger append (or synthetic read) can diverge from it.
        // Native edits belong to Native, never to the client noticing them.
        #[cfg(feature = "v2-kernel-probe")]
        if self.is_kernel() {
            return Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_hcp_disclosures WHERE principal_id=? AND client_id=? AND entry_id=?)")
                .bind(self.account()).bind(&self.client.id).bind(urn).fetch_one(&mut **tx).await?);
        }
        let events = self.events(tx, Some(urn)).await?;
        let folded = self.fold_events(&events);
        for event in events.iter().filter(|event| {
            event.event_type == "hcp.entry.versioned.v1"
                && !folded.rejected.iter().any(|r| r.seq == event.seq)
        }) {
            let version: HcpEntryVersionedPayload = serde_json::from_str(&event.payload)?;
            if matches!(version.cause.as_str(), "add" | "update")
                && version.client.id == self.client.id
            {
                return Ok(true);
            }
        }
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT payload FROM control_events WHERE aggregate_kind = 'hcp_audit' \
             AND aggregate_id = ? AND type = 'hcp.read.v1' ORDER BY seq",
        )
        .bind(hcp_audit_aggregate_id(self.account()))
        .fetch_all(&mut **tx)
        .await?;
        for row in rows {
            let read: HcpReadPayload = serde_json::from_str(&row)?;
            if read.account_id == self.account()
                && read.client.id == self.client.id
                && read.entry_ids.iter().any(|id| id == urn)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(super) async fn record_read(
        &self,
        tx: &mut WriteTx,
        kind: &str,
        purpose: &str,
        retrieval_id: &str,
        categories: Vec<String>,
        entry_ids: Vec<String>,
    ) -> Result<()> {
        let mut act = crate::act::ActAllocation::new();
        self.append(
            tx,
            &mut act,
            format!("hcp-read:{}:{retrieval_id}", self.account()),
            self.reason("read", Some(purpose)),
            ControlEventPayload::HcpRead(HcpReadPayload {
                account_id: self.account().into(),
                kind: kind.into(),
                client: self.client_payload(),
                purpose: purpose.into(),
                retrieval_id: retrieval_id.into(),
                categories,
                entry_ids,
            }),
        )
        .await
    }
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Filter {
    client_id: Option<String>,
    category: Option<String>,
    event_type: Option<String>,
    from: Option<String>,
    through: Option<String>,
    after_cursor: Option<String>,
    #[serde(default = "default_limit")]
    limit: usize,
}
fn default_limit() -> usize {
    100
}

pub(super) fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(ToolKind::ReadHcpAudit,
        "Read your own HCP audit, with client, category, event type and date filters. Events are durable before acknowledgment and ordered by event history. Continue with next_cursor as after_cursor: an opaque eventId resolved only within your audit. Invalid cursors receive the same refusal. No person's account can be selected. JSON-LD export uses the same pages.",
        json!({"type":"object","properties":{
            "client_id":{"type":"string"},"category":{"type":"string"},
            "event_type":{"type":"string"},"from":{"type":"string","format":"date-time"},
            "through":{"type":"string","format":"date-time"},
            "after_cursor":{"type":"string"},"limit":{"type":"integer","minimum":1,"maximum":500}
        },"additionalProperties":false}), read)?;
    #[cfg(feature = "v2-kernel-probe")]
    registry.register_engine_handler(
        AUDIT_TOOL,
        crate::mcp::registry::EngineKind::KernelV2,
        |engine, caller, args| async move {
            let crate::mcp::registry::EngineHandle::KernelV2(db) = engine else {
                unreachable!()
            };
            let principal = crate::mcp::kernel_v2::principal(&db, &caller).await?;
            read_on(db, caller, args, Some(principal)).await
        },
    )?;
    Ok(())
}

async fn read(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    read_on(db, caller, arguments, None).await
}
async fn read_on(
    db: Db,
    caller: Caller,
    arguments: Value,
    kernel_principal: Option<String>,
) -> Result<Value> {
    if arguments
        .get("after_cursor")
        .is_some_and(|cursor| !cursor.is_string())
    {
        return Err(Error::engine("invalid HCP audit cursor"));
    }
    let filter: Filter = serde_json::from_value(arguments)?;
    if filter.limit == 0 || filter.limit > 500 {
        return Err(Error::engine("invalid HCP audit page"));
    }
    let parse = |text: &str| {
        chrono::DateTime::parse_from_rfc3339(text)
            .map_err(|_| Error::engine("HCP audit dates must be RFC 3339"))
    };
    let from = filter.from.as_deref().map(parse).transpose()?;
    let through = filter.through.as_deref().map(parse).transpose()?;
    let account = kernel_principal
        .as_deref()
        .unwrap_or_else(|| caller.credential());
    let mut tx = db.write_pool().begin().await?;
    // Both logs and the chain judgement share one snapshot. Ignore rejected
    // state events just as the entry reader does; imported log shape remains
    // the existing operator boundary, not authority granted to record editors.
    let rows = if kernel_principal.is_some() {
        sqlx::query("SELECT event_seq AS seq,event_id AS id,event_type AS type,payload,created_at FROM kernel_hcp_audit WHERE principal_id=? ORDER BY event_seq")
            .bind(account).fetch_all(&mut *tx).await?
    } else {
        sqlx::query(
            "SELECT seq, id, type, payload, created_at FROM control_events \
        WHERE (aggregate_kind = 'hcp_state' AND aggregate_id = ?1) \
           OR (aggregate_kind = 'hcp_audit' AND aggregate_id = ?2) ORDER BY seq",
        )
        .bind(hcp_state_aggregate_id(account))
        .bind(hcp_audit_aggregate_id(account))
        .fetch_all(&mut *tx)
        .await?
    };
    let state: Vec<super::fold::StoredEvent> = rows
        .iter()
        .filter(|r| r.get::<String, _>("type") != "hcp.read.v1")
        .map(|r| super::fold::StoredEvent {
            seq: r.get("seq"),
            event_type: r.get("type"),
            payload: r.get("payload"),
        })
        .collect();
    let folded = super::fold::fold(
        account,
        &super::store::stored_subject_id_of(account),
        &state,
    );
    // Resolve identities only within the caller-derived aggregates already
    // loaded above. Never look up a foreign event or reveal its existence.
    // SQL positions order the snapshot internally; none leave this tool.
    let after = filter
        .after_cursor
        .as_deref()
        .map(|cursor| {
            let invalid = || Error::engine("invalid HCP audit cursor");
            let id = cursor
                .strip_prefix("urn:uuid:")
                .and_then(|id| uuid::Uuid::parse_str(id).ok())
                .ok_or_else(invalid)?
                .to_string();
            rows.iter()
                .find(|row| {
                    row.get::<String, _>("id") == id
                        && !folded
                            .rejected
                            .iter()
                            .any(|r| r.seq == row.get::<i64, _>("seq"))
                })
                .map(|row| row.get::<i64, _>("seq"))
                .ok_or_else(invalid)
        })
        .transpose()?;
    let mut events = Vec::new();
    let mut next_cursor = filter.after_cursor;
    let mut has_more = false;
    for row in rows {
        let seq: i64 = row.try_get("seq")?;
        if after.is_some_and(|after| seq <= after) || folded.rejected.iter().any(|r| r.seq == seq) {
            continue;
        }
        if row.get::<String, _>("type") == "hcp.entry.suggestion.v1" {
            continue;
        }
        let mut event = render(&row, account)?;
        if matches!(
            row.get::<String, _>("type").as_str(),
            "hcp.entry.status_set.v1" | "hcp.entry.confirmed.v1"
        ) {
            let p: Value = serde_json::from_str(&row.get::<String, _>("payload"))?;
            if let Some(entry) = folded
                .entries
                .get(p["entry_id"].as_str().unwrap_or_default())
                .and_then(|f| {
                    f.versions
                        .get(p["version"].as_u64().unwrap_or(0).saturating_sub(1) as usize)
                })
            {
                event["category"] = json!(entry.category());
                event["categories"] = json!([entry.category()]);
            }
        }
        let at = parse(event["timestamp"].as_str().unwrap_or_default())?;
        if filter
            .client_id
            .as_deref()
            .is_some_and(|id| event["native_client_id"] != id)
            || filter.category.as_deref().is_some_and(|cat| {
                !event["categories"]
                    .as_array()
                    .is_some_and(|cats| cats.iter().any(|c| c == cat))
            })
            || filter
                .event_type
                .as_deref()
                .is_some_and(|t| event["eventType"] != t)
            || from.is_some_and(|t| at < t)
            || through.is_some_and(|t| at > t)
        {
            continue;
        }
        if events.len() == filter.limit {
            has_more = true;
            break;
        }
        next_cursor = event["eventId"].as_str().map(str::to_owned);
        events.push(event);
    }
    tx.rollback().await?;
    Ok(
        json!({"@context":{"@vocab":"urn:native:hcp:audit:","eventId":"@id","eventType":"@type"},"events":events,
        "next_cursor":next_cursor,"has_more":has_more,"durabilityWindowMs":0}),
    )
}

fn render(row: &sqlx::sqlite::SqliteRow, account: &str) -> Result<Value> {
    let ty: String = row.try_get("type")?;
    let payload: String = row.try_get("payload")?;
    let (kind, client, entry, related, categories, purpose, retrieval, detail, provider) =
        match ty.as_str() {
            "hcp.entry.versioned.v1" => {
                let p: HcpEntryVersionedPayload = serde_json::from_str(&payload)?;
                let mut categories = vec![p.entry["record"]["category"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string()];
                if let Some(prior) = p.prior_category {
                    if !categories.contains(&prior) {
                        categories.push(prior);
                    }
                }
                (
                    if p.cause == "add" {
                        "preference.created"
                    } else {
                        "preference.updated"
                    },
                    p.client,
                    Some(p.entry_id),
                    None,
                    categories,
                    None,
                    None,
                    p.reason.or(Some(p.cause)),
                    false,
                )
            }
            "hcp.entry.status_set.v1" => {
                let p: HcpEntryStatusSetPayload = serde_json::from_str(&payload)?;
                let kind = match p.cause.as_str() {
                    "conflict" => "conflict.detected",
                    "release" | "confirmed" | "rejected" | "deprecated" => "conflict.resolved",
                    _ => "preference.deleted",
                };
                // Recover category from the accepted version event in read() below.
                (
                    kind,
                    p.client,
                    Some(p.entry_id),
                    if kind.starts_with("conflict.") {
                        p.related_entry_id
                    } else {
                        None
                    },
                    vec![],
                    None,
                    None,
                    p.reason,
                    matches!(p.cause.as_str(), "conflict" | "release" | "deprecated"),
                )
            }
            "hcp.entry.confirmed.v1" => {
                let p: HcpEntryConfirmedPayload = serde_json::from_str(&payload)?;
                (
                    "preference.confirmed",
                    p.client,
                    Some(p.entry_id),
                    None,
                    vec![],
                    None,
                    None,
                    Some(p.disposition),
                    false,
                )
            }
            "hcp.read.v1" => {
                let p: HcpReadPayload = serde_json::from_str(&payload)?;
                (
                    "preference.read",
                    p.client,
                    if p.kind == "get" {
                        p.entry_ids.first().cloned()
                    } else {
                        None
                    },
                    None,
                    p.categories,
                    Some(p.purpose),
                    Some(p.retrieval_id),
                    Some(p.kind),
                    false,
                )
            }
            _ => return Err(Error::engine("unknown HCP audit event")),
        };
    let mut participants = json!({"initiator":{"role":if provider {"hcp-provider"} else if client.id == "native" {"management-client"} else {"context-client"},
        "id":if provider {PROVIDER_ID} else {&client.id}},"provider":{"id":PROVIDER_ID}});
    if !provider {
        participants["clientOperator"] =
            json!({"id":client.operator_id,"name":client.operator_name});
    }
    if let Some(id) = retrieval {
        participants["retrievalId"] = json!(id);
        participants["requestingParty"] = json!({"id":client.id});
        participants["authorizingPrincipal"] =
            json!({"id":super::store::stored_subject_id_of(account)});
    }
    let category = if ty == "hcp.read.v1" && categories.len() != 1 {
        Value::Null
    } else {
        categories.first().map(|c| json!(c)).unwrap_or(Value::Null)
    };
    let mut rendered = json!({"eventId":format!("urn:uuid:{}",row.try_get::<String,_>("id")?),"eventType":kind,
        "timestamp":row.try_get::<String,_>("created_at")?,"participants":participants,"entryId":entry,
        "relatedEntryId":related,"category":category,
        "categories":categories,"purpose":purpose,"grantId":if provider || client.id == "native" {Value::Null} else {json!(format!("urn:native:hcp:ordinary-access:{}",client.id))},
        "detail":detail,"native_client_id":client.id});
    if ty == "hcp.read.v1" {
        let p: HcpReadPayload = serde_json::from_str(&payload)?;
        rendered["disclosedEntries"] = json!(p.entry_ids);
    }
    if ty == "hcp.entry.confirmed.v1" {
        let p: HcpEntryConfirmedPayload = serde_json::from_str(&payload)?;
        rendered["timestamp"] = json!(p.confirmed_at);
        rendered["confirmedAt"] = json!(p.confirmed_at);
        rendered["confirmedBy"] = json!({"id":super::store::stored_subject_id_of(account)});
        rendered["version"] = json!(p.version);
        rendered["suggestionId"] = json!(p.suggestion_id);
        rendered["resolutionEventId"] = json!(p.resolution_event_id);
    }

    Ok(rendered)
}
