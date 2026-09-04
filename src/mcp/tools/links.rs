//! Tool 13 — `manage_links`: add/remove/list typed links.
//!
//! Generic open-additive writes enter the sealed `legacy_link.v1` relationship
//! adapter; Message, federated, and the closed engine-semantic set retain their
//! replay-compatible content events. The list action reads the common `links`
//! compatibility projection. Endpoint authorization and non-disclosure happen
//! before either write route is selected.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;

use crate::authorization::Capability;
use crate::db::Db;
use crate::error::{Error, Result};
use crate::events::{LinkAddedPayload, LinkRemovedPayload};
use crate::query::{link_from_row, LinkRow};
use crate::store::{append_in, AppendSpec};

use super::super::registry::{Caller, ToolRegistry};
use super::super::ToolKind;
use super::{
    can_record_in, parse_args, previous_record_seq_in, require_record_in, visible_ids_in,
    PREVIOUS_SEQ_DESCRIPTION,
};

const DEFAULT_LIST_LIMIT: usize = 50;
const MAX_LIST_LIMIT: usize = 200;

#[derive(Debug, Serialize, Deserialize)]
struct LinkListCursor {
    schema: u8,
    account_id: String,
    record_id: String,
    limit: usize,
    direction_rank: i64,
    relationship: String,
    created_at: String,
    link_id: String,
}

struct LinkCandidate {
    direction_rank: i64,
    link: LinkRow,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "action", rename_all = "snake_case")]
enum ManageLinksArgs {
    Add {
        source_id: String,
        target_id: String,
        relationship: String,
        note: Option<String>,
    },
    Remove {
        source_id: String,
        target_id: String,
        relationship: String,
    },
    List {
        record_id: String,
        limit: Option<usize>,
        cursor: Option<String>,
    },
}

fn content_event_receipt(event: &crate::events::EventRow) -> Value {
    json!({
        "kind":"content_event",
        "event":{
            "seq":event.local_seq,
            "event_id":event.id,
            "record_id":event.record_id,
            "event_type":event.event_type,
            "created_at":event.created_at,
        }
    })
}

fn normalize_relationship_receipt(receipt: &Value) -> Result<Value> {
    let object = receipt
        .as_object()
        .ok_or_else(|| Error::engine("manage_links: relationship receipt is malformed"))?;
    let required = |key: &str| {
        object
            .get(key)
            .cloned()
            .ok_or_else(|| Error::engine(format!("manage_links: relationship receipt lacks {key}")))
    };
    Ok(json!({
        "kind":"relationship_assertion",
        "relationship_origin_db_id":required("relationship_origin_db_id")?,
        "relationship_id":required("relationship_id")?,
        "assertion_id":required("assertion_id")?,
        "action_attestation_id":required("action_attestation_id")?,
        "output_events":required("output_events")?,
    }))
}

fn write_response(
    mut compatibility: Value,
    action: &str,
    previous_seq: Option<i64>,
    write_receipt: Value,
) -> Value {
    compatibility["action"] = json!(action);
    compatibility["format"] = json!("native.manage-links-write.v1");
    compatibility["previous_seq"] = json!(previous_seq);
    compatibility["write_receipt"] = write_receipt;
    compatibility
}

async fn manage_links(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    match parse_args("manage_links", arguments)? {
        ManageLinksArgs::Add {
            source_id,
            target_id,
            relationship,
            note,
        } => {
            if relationship.trim().is_empty() {
                return Err(Error::engine(
                    "link relationship must contain non-whitespace text",
                ));
            }
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            require_record_in(
                &mut tx,
                &caller,
                "manage_links",
                &source_id,
                Capability::Edit,
            )
            .await?;
            require_record_in(
                &mut tx,
                &caller,
                "manage_links",
                &target_id,
                Capability::View,
            )
            .await?;
            crate::comments::assert_bearer_immutable_on(
                &mut tx,
                "manage_links",
                &source_id,
                &relationship,
            )
            .await?;
            let previous_seq = previous_record_seq_in(&mut tx, &source_id).await?;
            let relationship_owned =
                relationship_owned_in(&mut tx, &source_id, &target_id, &relationship).await?;
            let receipt = if relationship_owned {
                let compatibility = crate::relationship::legacy::mutate_from_manage_links_in(
                    &mut tx,
                    &caller,
                    &source_id,
                    &target_id,
                    &relationship,
                    note,
                    true,
                )
                .await?;
                let write_receipt = normalize_relationship_receipt(&compatibility)?;
                write_response(compatibility, "add", previous_seq, write_receipt)
            } else {
                let event = append_in(
                    &db,
                    &mut tx,
                    AppendSpec {
                        record_id: source_id.clone(),
                        event_type: "link.added".into(),
                        payload: serde_json::to_value(LinkAddedPayload {
                            id: None,
                            source_id: source_id.clone(),
                            target_id: target_id.clone(),
                            relationship: relationship.clone(),
                            note,
                        })?,
                        actor: Some(caller.actor().into()),
                    },
                )
                .await?;
                write_response(
                    json!({"status":"added","source_id":source_id,"target_id":target_id,"relationship":relationship}),
                    "add",
                    previous_seq,
                    content_event_receipt(&event),
                )
            };
            db.commit_content(tx).await?;
            Ok(receipt)
        }
        ManageLinksArgs::Remove {
            source_id,
            target_id,
            relationship,
        } => {
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            require_record_in(
                &mut tx,
                &caller,
                "manage_links",
                &source_id,
                Capability::Edit,
            )
            .await?;
            require_record_in(
                &mut tx,
                &caller,
                "manage_links",
                &target_id,
                Capability::View,
            )
            .await?;
            crate::comments::assert_bearer_immutable_on(
                &mut tx,
                "manage_links",
                &source_id,
                &relationship,
            )
            .await?;
            let previous_seq = previous_record_seq_in(&mut tx, &source_id).await?;
            let relationship_owned =
                relationship_owned_in(&mut tx, &source_id, &target_id, &relationship).await?;
            let receipt = if relationship_owned {
                let compatibility = crate::relationship::legacy::mutate_from_manage_links_in(
                    &mut tx,
                    &caller,
                    &source_id,
                    &target_id,
                    &relationship,
                    None,
                    false,
                )
                .await?;
                let write_receipt = normalize_relationship_receipt(&compatibility)?;
                write_response(compatibility, "remove", previous_seq, write_receipt)
            } else {
                let event = append_in(
                    &db,
                    &mut tx,
                    AppendSpec {
                        record_id: source_id.clone(),
                        event_type: "link.removed".into(),
                        payload: serde_json::to_value(LinkRemovedPayload {
                            source_id: source_id.clone(),
                            target_id: target_id.clone(),
                            relationship: relationship.clone(),
                        })?,
                        actor: Some(caller.actor().into()),
                    },
                )
                .await?;
                write_response(
                    json!({"status":"removed","source_id":source_id,"target_id":target_id,"relationship":relationship}),
                    "remove",
                    previous_seq,
                    content_event_receipt(&event),
                )
            };
            db.commit_content(tx).await?;
            Ok(receipt)
        }
        ManageLinksArgs::List {
            record_id,
            limit,
            cursor,
        } => {
            let limit = limit.unwrap_or(DEFAULT_LIST_LIMIT);
            if !(1..=MAX_LIST_LIMIT).contains(&limit) {
                return Err(Error::engine(
                    "manage_links.list: limit must be between 1 and 200",
                ));
            }
            let decoded = if let Some(cursor) = cursor.as_deref() {
                let decoded: LinkListCursor =
                    serde_json::from_value(db.get_inbox_snapshot(cursor).map_err(|_| {
                        Error::engine("cursor_reset_required: invalid manage_links list cursor")
                    })?)
                    .map_err(|_| {
                        Error::engine("cursor_reset_required: malformed manage_links list cursor")
                    })?;
                if decoded.schema != 1
                    || decoded.account_id != caller.credential()
                    || decoded.record_id != record_id
                    || decoded.limit != limit
                    || !matches!(decoded.direction_rank, 0 | 1)
                    || decoded.relationship.is_empty()
                    || decoded.created_at.is_empty()
                    || decoded.link_id.is_empty()
                {
                    return Err(Error::engine(
                        "cursor_reset_required: manage_links list cursor does not match this caller, record, or limit",
                    ));
                }
                Some(decoded)
            } else {
                None
            };
            let mut tx = db.write_pool().begin().await?;
            if !can_record_in(&mut tx, &caller, &record_id, Capability::View).await? {
                return Err(Error::engine(format!("record {record_id} does not exist")));
            }
            let after_direction = decoded.as_ref().map(|cursor| cursor.direction_rank);
            let after_relationship = decoded.as_ref().map(|cursor| cursor.relationship.as_str());
            let after_created_at = decoded.as_ref().map(|cursor| cursor.created_at.as_str());
            let after_link_id = decoded.as_ref().map(|cursor| cursor.link_id.as_str());
            let rows = sqlx::query(
                "WITH candidates AS (
                    SELECT 0 AS direction_rank,id,source_id,target_id,relationship,note,created_at
                      FROM links WHERE source_id=?1
                    UNION ALL
                    SELECT 1 AS direction_rank,id,source_id,target_id,relationship,note,created_at
                      FROM links WHERE target_id=?1
                 )
                 SELECT direction_rank,id,source_id,target_id,relationship,note,created_at
                   FROM candidates
                  WHERE ?2 IS NULL OR (direction_rank,relationship,created_at,id)>(?2,?3,?4,?5)
                  ORDER BY direction_rank,relationship,created_at,id
                  LIMIT ?6",
            )
            .bind(&record_id)
            .bind(after_direction)
            .bind(after_relationship)
            .bind(after_created_at)
            .bind(after_link_id)
            .bind((limit + 1) as i64)
            .fetch_all(&mut *tx)
            .await?;
            let has_more = rows.len() > limit;
            let mut candidates = rows
                .iter()
                .take(limit)
                .map(|row| {
                    Ok(LinkCandidate {
                        direction_rank: row.try_get("direction_rank")?,
                        link: link_from_row(row)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let visible = visible_ids_in(
                &mut tx,
                &caller,
                candidates
                    .iter()
                    .map(|candidate| {
                        if candidate.direction_rank == 0 {
                            candidate.link.target_id.clone()
                        } else {
                            candidate.link.source_id.clone()
                        }
                    })
                    .collect(),
            )
            .await?;
            candidates.retain(|candidate| {
                visible.contains(if candidate.direction_rank == 0 {
                    &candidate.link.target_id
                } else {
                    &candidate.link.source_id
                })
            });
            let links_out = candidates
                .iter()
                .filter(|candidate| candidate.direction_rank == 0)
                .map(|candidate| candidate.link.clone())
                .collect::<Vec<_>>();
            let links_in = candidates
                .iter()
                .filter(|candidate| candidate.direction_rank == 1)
                .map(|candidate| candidate.link.clone())
                .collect::<Vec<_>>();
            let next_cursor = if has_more {
                let last = rows
                    .get(limit - 1)
                    .ok_or_else(|| Error::engine("manage_links: cursor page made no progress"))?;
                Some(db.put_inbox_snapshot(serde_json::to_value(LinkListCursor {
                    schema: 1,
                    account_id: caller.credential().into(),
                    record_id: record_id.clone(),
                    limit,
                    direction_rank: last.try_get("direction_rank")?,
                    relationship: last.try_get("relationship")?,
                    created_at: last.try_get("created_at")?,
                    link_id: last.try_get("id")?,
                })?)?)
            } else {
                None
            };
            tx.commit().await?;
            let returned = links_out.len() + links_in.len();
            let next_call = next_cursor.as_ref().map(|cursor| {
                json!({"action":"list","record_id":record_id,"limit":limit,"cursor":cursor})
            });
            Ok(json!({
                "action":"list",
                "format":"native.manage-links-list.v1",
                "record_id":record_id,
                "viewer_relative":true,
                "query_basis":"live_at_each_page_read",
                "scope":"opposite_endpoint_viewable_at_read_time",
                "limit":limit,
                "cursor":cursor,
                "links_out":links_out,
                "links_in":links_in,
                "returned":returned,
                "has_more":has_more,
                "next_cursor":next_cursor,
                "next_call":next_call,
            }))
        }
    }
}

pub(super) async fn relationship_owned_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    source_id: &str,
    target_id: &str,
    relationship: &str,
) -> Result<bool> {
    let row = sqlx::query(
        "SELECT s.type AS source_type,t.type AS target_type
           FROM records s JOIN records t ON t.id=?2 WHERE s.id=?1",
    )
    .bind(source_id)
    .bind(target_id)
    .fetch_one(&mut **tx)
    .await?;
    Ok(crate::relationship::legacy::classify(
        Some(row.try_get::<String, _>("source_type")?.as_str()),
        Some(row.try_get::<String, _>("target_type")?.as_str()),
        None,
        relationship,
    ) == crate::relationship::legacy::LinkOwnership::Relationship)
}

/// Register tool 13.
pub fn register_link_tools(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(
        ToolKind::ManageLinks,
        &format!("Add, remove, or page typed links. Relationship strings are \
         open-additive. Writes echo previous_seq; list returns a bounded, \
         viewer-relative live page. {PREVIOUS_SEQ_DESCRIPTION}"),
        json!({
            "type": "object",
            "properties": {
                "action": { "type": "string", "enum": ["add", "remove", "list"] },
                "source_id": { "type": "string" },
                "target_id": { "type": "string" },
                "relationship": { "type": "string" },
                "note": { "type": "string", "description": "add: optional link note." },
                "record_id": { "type": "string", "description": "list: record to page." },
                "limit": { "type": "integer", "minimum": 1, "maximum": 200, "default": 50, "description": "list: bounded live-page work." },
                "cursor": { "type": "string", "description": "list: opaque prior-page continuation." }
            },
            "required": ["action"],
            "additionalProperties": false
        }),
        manage_links,
    )?;
    Ok(())
}
