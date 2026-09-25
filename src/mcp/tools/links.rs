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
use crate::surface_binding::refuse_reserved_surface_binding;

use super::super::registry::{Caller, ToolRegistry};
use super::super::ToolKind;
use super::{
    can_record_in, can_record_in_pool, echo_act, parse_args, previous_record_seq_in,
    require_record_in, visible_ids_in, visible_ids_in_pool, PREVIOUS_SEQ_DESCRIPTION,
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

/// M4 bounded slice: serve `manage_links.list` physical candidates from the
/// per-workspace index without a write-pool checkout.
///
/// Contract notes (record dbdebe5):
/// - Page-before-filter is preserved exactly: the keyset
///   `(direction_rank, relationship, created_at, id)` pages the PHYSICAL link
///   rows with `limit + 1`, `has_more` and the next cursor derive from that
///   physical page, and only the first `limit` physical rows are filtered by
///   opposite-endpoint visibility. Empty returned pages with `has_more == true`
///   are therefore possible, exactly as on the governed path.
/// - Physical candidates come from the per-record index subset
///   (`Db::indexed_link_candidates`) — never a full-index clone.
/// - Content, authorization, and relationship fences from the governed
///   visible-set evaluation must match the held candidates exactly, and a
///   live fence re-read must still match before serving; anything else falls
///   back. The visible set contributes ONLY the fence triple here — never
///   its ids.
/// - Governed admission parity: the visibility view is narrower than the
///   list's governed predicates for semantic-unit envelopes, acknowledgement
///   annotations, derived unit artefacts, and trusted-local tombstones (and
///   carries no comment predicate at all), so filtering by `visible.ids`
///   would hide — or, for invalid comments, expose — links the governed path
///   treats oppositely. Anchor and opposite-endpoint admission therefore run
///   the SAME governed predicates as `list_governed`, on the read pool:
///   `can_record_in_pool` for the anchor, `visible_ids_in_pool` for the
///   bounded physical page's opposite endpoints. The old comment-kind screen
///   is removed: the helpers already enforce attribution, comment-integrity,
///   derived/Unit, and tombstone admission.
/// - `Ok(None)` means "fall back to the governed path below". It covers an
///   absent or over-cap index, stale fences, a racing commit, and any
///   internal error — never an empty workspace. The anchor-missing case also
///   falls back so the governed path owns the exact not-found semantics.
///
/// Read pools only: governed pool for visibility, read pool for build/fold/
/// rebuild/fences. No `write_pool` checkout on an indexed hit.
///
/// Lock discipline: readiness is the shared M4 point-read policy owned by
/// `Db::indexed_link_candidates` — optimistic read-lock attempt, one content
/// fold on content lag, one refusal-aware rebuild on authorization/
/// relationship movement (converged with the facets slice; no second policy
/// here). Steady over-cap reads skip the rebuild through the shared refusal
/// marker instead of reconstructing and discarding the whole index per read.
/// Hits take only the index read lock; the write guard appears solely on the
/// repair paths, never on a fence-stable hit. Cap discipline is the shared
/// marker, owned by the build/refresh/rebuild paths — there is deliberately
/// no per-call cap scan in the read path.
#[allow(clippy::too_many_lines)]
async fn try_indexed_links_list(
    db: &Db,
    caller: &Caller,
    record_id: &str,
    limit: usize,
    cursor: Option<&str>,
    decoded: Option<&LinkListCursor>,
) -> Result<Option<Value>> {
    // Activity-roster parity: `QueryPrincipal::from(caller)` converts a
    // caller with a hosted activity roster into an activity reader, whose
    // visible set is evaluated under `activity_read` and could admit activity
    // context beyond what the governed path (`can_record_in` /
    // `visible_ids_in` over the ordinary policy principal, which ignores the
    // roster) would serve. Such callers always take the governed fallback,
    // before any cache or index interaction.
    if caller.has_hosted_activity_roster() {
        return Ok(None);
    }
    let principal = crate::query::QueryPrincipal::from(caller);
    // Fences only from here on: `visible.ids` is never consulted. Admission
    // below re-runs the governed predicates on the read pool.
    let visible = match crate::query::sql::workspace_visible_set(db, principal).await {
        Ok(visible) => visible,
        Err(_) => return Ok(None),
    };
    // Anchor admission runs the SAME governed predicate as `list_governed`
    // (`can_record_in`), on the read pool. Denial and internal error both
    // decline to governed: the governed path owns the exact not-found denial
    // and every error string, so the fast path never surfaces a new one.
    match can_record_in_pool(db.pool(), caller, record_id, Capability::View).await {
        Ok(true) => {}
        Ok(false) | Err(_) => return Ok(None),
    }
    // Shared point-read readiness (fold/rebuild/refusal-aware); `Err` and
    // `None` both decline to governed. The returned fences are then matched
    // against this request's governed visible set: a just-repaired index can
    // already be newer than the visibility snapshot, and that is a fallback,
    // never a serve.
    let candidates = match db.indexed_link_candidates(record_id).await {
        Ok(Some(candidates)) => candidates,
        Ok(None) | Err(_) => return Ok(None),
    };
    if candidates.content_seq != visible.content_seq
        || candidates.authorization_epoch != visible.authorization_epoch
        || candidates.relationship_seq != visible.relationship_seq
    {
        return Ok(None);
    }
    struct Physical {
        direction_rank: i64,
        relationship: String,
        created_at: String,
        id: String,
        link: LinkRow,
    }
    let mut physical: Vec<Physical> = Vec::new();
    for held in &candidates.links {
        let link = LinkRow {
            id: held.id.clone(),
            source_id: held.source_id.clone(),
            target_id: held.target_id.clone(),
            relationship: held.relationship.clone(),
            note: held.note.clone(),
            created_at: held.created_at.clone(),
        };
        // A self-link satisfies both UNION ALL legs on the governed path, so
        // it contributes one candidate per direction here as well.
        if held.source_id == record_id {
            physical.push(Physical {
                direction_rank: 0,
                relationship: link.relationship.clone(),
                created_at: link.created_at.clone(),
                id: link.id.clone(),
                link: link.clone(),
            });
        }
        if held.target_id == record_id {
            physical.push(Physical {
                direction_rank: 1,
                relationship: link.relationship.clone(),
                created_at: link.created_at.clone(),
                id: link.id.clone(),
                link,
            });
        }
    }
    if let Some(cursor) = decoded {
        physical.retain(|candidate| {
            (
                candidate.direction_rank,
                candidate.relationship.as_str(),
                candidate.created_at.as_str(),
                candidate.id.as_str(),
            ) > (
                cursor.direction_rank,
                cursor.relationship.as_str(),
                cursor.created_at.as_str(),
                cursor.link_id.as_str(),
            )
        });
    }
    physical.sort_by(|a, b| {
        (
            a.direction_rank,
            a.relationship.as_str(),
            a.created_at.as_str(),
            a.id.as_str(),
        )
            .cmp(&(
                b.direction_rank,
                b.relationship.as_str(),
                b.created_at.as_str(),
                b.id.as_str(),
            ))
    });
    let has_more = physical.len() > limit;
    let page = physical.into_iter().take(limit).collect::<Vec<_>>();
    // Opposite-endpoint admission runs the SAME governed predicate as
    // `list_governed` (`visible_ids_in`: attribution/comment admission plus
    // the derived/Unit/policy/owner capability fold), on the read pool, over
    // the bounded physical page only — never the whole index. A denied
    // endpoint filters out of this page; an internal error declines the whole
    // read to governed rather than surfacing a new error.
    let mut opposite_ids: Vec<String> = Vec::with_capacity(page.len());
    for candidate in &page {
        let opposite = if candidate.direction_rank == 0 {
            candidate.link.target_id.clone()
        } else {
            candidate.link.source_id.clone()
        };
        if !opposite_ids.contains(&opposite) {
            opposite_ids.push(opposite);
        }
    }
    let governed_visible = match visible_ids_in_pool(db.pool(), caller, opposite_ids).await {
        Ok(visible) => visible,
        Err(_) => return Ok(None),
    };
    // Post-read fence check AFTER the policy fold: a concurrent narrowing
    // between admission and serving must fall back, never serve stale rows.
    let live: (i64, i64, i64) = match sqlx::query_as(
        "SELECT (SELECT COALESCE(MAX(seq), 0) FROM content_events), \
                (SELECT COALESCE(MAX(seq), 0) FROM relationship_events), \
                (SELECT epoch FROM authorization_revision WHERE id = 1)",
    )
    .fetch_one(db.pool())
    .await
    {
        Ok(live) => live,
        Err(_) => return Ok(None),
    };
    if live
        != (
            visible.content_seq,
            visible.relationship_seq,
            visible.authorization_epoch,
        )
    {
        return Ok(None);
    }
    let next_cursor = if has_more {
        let last = page
            .last()
            .ok_or_else(|| Error::engine("manage_links: cursor page made no progress"))?;
        Some(db.put_inbox_snapshot(serde_json::to_value(LinkListCursor {
            schema: 1,
            account_id: caller.credential().into(),
            record_id: record_id.to_string(),
            limit,
            direction_rank: last.direction_rank,
            relationship: last.relationship.clone(),
            created_at: last.created_at.clone(),
            link_id: last.id.clone(),
        })?)?)
    } else {
        None
    };
    let mut links_out = Vec::new();
    let mut links_in = Vec::new();
    for candidate in &page {
        let opposite = if candidate.direction_rank == 0 {
            &candidate.link.target_id
        } else {
            &candidate.link.source_id
        };
        if !governed_visible.contains(opposite) {
            continue;
        }
        if candidate.direction_rank == 0 {
            links_out.push(candidate.link.clone());
        } else {
            links_in.push(candidate.link.clone());
        }
    }
    let returned = links_out.len() + links_in.len();
    let next_call = next_cursor
        .as_ref()
        .map(|next| json!({"action":"list","record_id":record_id,"limit":limit,"cursor":next}));
    Ok(Some(json!({
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
    })))
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
    act: Option<i64>,
    write_receipt: Value,
) -> Result<Value> {
    compatibility["action"] = json!(action);
    compatibility["format"] = json!("native.manage-links-write.v1");
    compatibility["previous_seq"] = json!(previous_seq);
    compatibility["write_receipt"] = write_receipt;
    echo_act(compatibility, act)
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
            refuse_reserved_surface_binding("manage_links", &relationship)?;
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            let mut act_alloc = crate::act::ActAllocation::new();
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
                    &mut act_alloc,
                )
                .await?;
                let write_receipt = normalize_relationship_receipt(&compatibility)?;
                write_response(
                    compatibility,
                    "add",
                    previous_seq,
                    act_alloc.get(),
                    write_receipt,
                )
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
                    &mut act_alloc,
                )
                .await?;
                write_response(
                    json!({"status":"added","source_id":source_id,"target_id":target_id,"relationship":relationship}),
                    "add",
                    previous_seq,
                    act_alloc.get(),
                    content_event_receipt(&event),
                )
            };
            db.commit_content(tx).await?;
            Ok(receipt?)
        }
        ManageLinksArgs::Remove {
            source_id,
            target_id,
            relationship,
        } => {
            refuse_reserved_surface_binding("manage_links", &relationship)?;
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            let mut act_alloc = crate::act::ActAllocation::new();
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
                    &mut act_alloc,
                )
                .await?;
                let write_receipt = normalize_relationship_receipt(&compatibility)?;
                write_response(
                    compatibility,
                    "remove",
                    previous_seq,
                    act_alloc.get(),
                    write_receipt,
                )
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
                    &mut act_alloc,
                )
                .await?;
                write_response(
                    json!({"status":"removed","source_id":source_id,"target_id":target_id,"relationship":relationship}),
                    "remove",
                    previous_seq,
                    act_alloc.get(),
                    content_event_receipt(&event),
                )
            };
            db.commit_content(tx).await?;
            Ok(receipt?)
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
            if let Some(indexed) = try_indexed_links_list(
                &db,
                &caller,
                &record_id,
                limit,
                cursor.as_deref(),
                decoded.as_ref(),
            )
            .await?
            {
                crate::mcp::request_timing::record_m4_index_decision(true);
                return Ok(indexed);
            }
            let response =
                list_governed(&db, &caller, &record_id, limit, cursor, decoded.as_ref()).await?;
            crate::mcp::request_timing::record_m4_index_decision(false);
            Ok(response)
        }
    }
}

/// The pre-M4 governed `manage_links.list` implementation, verbatim: physical
/// link rows page from `links` on the write pool with keyset
/// `(direction_rank, relationship, created_at, id)` and `limit + 1`, `has_more`
/// and the cursor derive from that physical page, then the first `limit`
/// opposite endpoints filter by `View`. This is the production fallback for
/// the indexed slice above — and the independent differential oracle its
/// tests compare against field by field.
async fn list_governed(
    db: &Db,
    caller: &Caller,
    record_id: &str,
    limit: usize,
    cursor: Option<String>,
    decoded: Option<&LinkListCursor>,
) -> Result<Value> {
    let mut tx = db.write_pool().begin().await?;
    if !can_record_in(&mut tx, caller, record_id, Capability::View).await? {
        return Err(Error::engine(format!("record {record_id} does not exist")));
    }
    let after_direction = decoded.map(|cursor| cursor.direction_rank);
    let after_relationship = decoded.map(|cursor| cursor.relationship.as_str());
    let after_created_at = decoded.map(|cursor| cursor.created_at.as_str());
    let after_link_id = decoded.map(|cursor| cursor.link_id.as_str());
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
    .bind(record_id)
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
        caller,
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
            record_id: record_id.to_string(),
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
    let next_call = next_cursor
        .as_ref()
        .map(|cursor| json!({"action":"list","record_id":record_id,"limit":limit,"cursor":cursor}));
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
    let list_schema = crate::mcp::record_ref::with_record_selector_aliases(
        "manage_links.list",
        json!({
            "type": "object",
            "properties": {
                "action": { "const": "list" },
                "record_id": { "type": "string", "description": "Record to page." },
                "limit": { "type": "integer", "minimum": 1, "maximum": 200, "default": 50, "description": "Bounded live-page work." },
                "cursor": { "type": "string", "description": "Opaque prior-page continuation." }
            },
            "required": ["action", "record_id"],
            "additionalProperties": false
        }),
    );
    let action_schema = json!({
        "type": "object",
        "oneOf": [
            {
                "type": "object",
                "properties": {
                    "action": { "const": "add" },
                    "source_id": { "type": "string" },
                    "target_id": { "type": "string" },
                    "relationship": { "type": "string" },
                    "note": { "type": "string", "description": "Optional link note." }
                },
                "required": ["action", "source_id", "target_id", "relationship"],
                "additionalProperties": false
            },
            {
                "type": "object",
                "properties": {
                    "action": { "const": "remove" },
                    "source_id": { "type": "string" },
                    "target_id": { "type": "string" },
                    "relationship": { "type": "string" }
                },
                "required": ["action", "source_id", "target_id", "relationship"],
                "additionalProperties": false
            },
            list_schema
        ]
    });
    registry.register(
        ToolKind::ManageLinks,
        &format!(
            "Add, remove, or page typed links. Relationship strings are \
         open-additive. Writes echo previous_seq; list returns a bounded, \
         viewer-relative live page. {PREVIOUS_SEQ_DESCRIPTION}"
        ),
        action_schema,
        manage_links,
    )?;
    Ok(())
}

#[cfg(test)]
mod indexed_links_tests {
    use super::{list_governed, try_indexed_links_list, LinkListCursor};
    use serde_json::{json, Value};

    use crate::authorization::{replace_explicit_policy, AllowEntry, Capability};
    use crate::db::with_write_pool_acquisition_sink;
    use crate::events::LinkAddedPayload;
    use crate::mcp::{Caller, ToolRegistry};
    use crate::store::{add_link, create_record, delete_record};
    use sqlx::Row;

    const ANCHOR: &str = "7e5a0001-0000-4000-8000-000000000001";
    const VISIBLE: &str = "7e5a0001-0000-4000-8000-000000000002";
    const HIDDEN: &str = "7e5a0001-0000-4000-8000-000000000003";
    const EXTRA1: &str = "7e5a0001-0000-4000-8000-000000000004";
    const EXTRA2: &str = "7e5a0001-0000-4000-8000-000000000005";
    const BAD_COMMENT: &str = "7e5a0001-0000-4000-8000-000000000006";

    const LINK_HIDDEN: &str = "7e5a0001-0000-4000-8000-000000000011";
    const LINK_VISIBLE: &str = "7e5a0001-0000-4000-8000-000000000012";
    const LINK_EXTRA1: &str = "7e5a0001-0000-4000-8000-000000000013";
    const LINK_EXTRA2: &str = "7e5a0001-0000-4000-8000-000000000014";
    const LINK_SELF: &str = "7e5a0001-0000-4000-8000-000000000015";
    const LINK_BAD_COMMENT: &str = "7e5a0001-0000-4000-8000-000000000016";
    const LINK_BAD_BEARER: &str = "7e5a0001-0000-4000-8000-000000000017";

    fn alice() -> Caller {
        Caller::authenticated("alice")
    }

    fn bea() -> Caller {
        Caller::authenticated("bea")
    }

    async fn fixture() -> (crate::db::Db, ToolRegistry) {
        let db = crate::db::create_database(":memory:").await.unwrap();
        for (id, name) in [
            (ANCHOR, "anchor"),
            (VISIBLE, "visible"),
            (HIDDEN, "hidden"),
            (EXTRA1, "extra1"),
            (EXTRA2, "extra2"),
        ] {
            create_record(
                &db,
                json!({
                    "id": id, "type": "Document", "kind": "note", "name": name,
                    "home_id": crate::schema::ROOT_RECORD_ID
                }),
            )
            .await
            .unwrap();
        }
        replace_explicit_policy(
            &db,
            "test:policy",
            ANCHOR,
            vec![
                AllowEntry::account("alice", Capability::View),
                AllowEntry::account("bea", Capability::View),
            ],
        )
        .await
        .unwrap();
        for id in [VISIBLE, EXTRA1, EXTRA2] {
            replace_explicit_policy(
                &db,
                "test:policy",
                id,
                vec![
                    AllowEntry::account("alice", Capability::View),
                    AllowEntry::account("bea", Capability::View),
                ],
            )
            .await
            .unwrap();
        }
        replace_explicit_policy(
            &db,
            "test:policy",
            HIDDEN,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();
        // An invalid governed comment: Annotation/kind:comment with exactly
        // one bearer part_of link (so the visibility view's bearer walk still
        // admits it under its own policy) but a blank body (so
        // `ordinary_record_read_eligible` fails it). Policy grants both
        // principals View, isolating exactly the view/comment gap the governed
        // read-pool admission must close.
        create_record(
            &db,
            json!({
                "id": BAD_COMMENT, "type": "Annotation", "kind": "comment",
                "name": "hollow comment", "body": "",
                "home_id": crate::schema::ROOT_RECORD_ID
            }),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            BAD_COMMENT,
            vec![
                AllowEntry::account("alice", Capability::View),
                AllowEntry::account("bea", Capability::View),
            ],
        )
        .await
        .unwrap();
        // Fence-stable content-owned links. The hidden link sorts first
        // physically (`member_of` < `mentions`), so a limit-1 page for bea
        // opens on an empty returned page with `has_more == true` — the
        // page-before-filter contract, not a bug. The self-link satisfies
        // both UNION ALL legs, so it pages twice: once out, once in.
        for (id, source, target, relationship) in [
            (LINK_HIDDEN, ANCHOR, HIDDEN, "member_of"),
            (LINK_VISIBLE, ANCHOR, VISIBLE, "mentions"),
            (LINK_EXTRA1, ANCHOR, EXTRA1, "mentions"),
            (LINK_EXTRA2, ANCHOR, EXTRA2, "mentions"),
            (LINK_SELF, ANCHOR, ANCHOR, "mentions"),
            (LINK_BAD_COMMENT, ANCHOR, BAD_COMMENT, "mentions"),
            // The invalid comment's single bearer link: content-owned, so it
            // folds like any other link, and it touches only BAD_COMMENT and
            // VISIBLE — never the anchor's candidate set.
            (LINK_BAD_BEARER, BAD_COMMENT, VISIBLE, "part_of"),
        ] {
            add_link(
                &db,
                LinkAddedPayload {
                    id: Some(id.to_string()),
                    source_id: source.to_string(),
                    target_id: target.to_string(),
                    relationship: relationship.to_string(),
                    note: None,
                },
            )
            .await
            .unwrap();
        }
        let mut registry = ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        (db, registry)
    }

    async fn list_as(
        registry: &ToolRegistry,
        db: &crate::db::Db,
        caller: Caller,
        args: Value,
    ) -> Value {
        registry
            .call(db.clone(), caller, "manage_links", args)
            .await
            .unwrap()
    }

    /// Tool call with the handler-body write-pool count. Production dispatch
    /// wraps the handler in its own acquisition-counter scope and publishes
    /// the count to this sink — an outer `with_write_pool_acquisition_counter`
    /// around `registry.call` would see zero even on the governed path, so
    /// the sink is the only honest instrument here.
    async fn list_as_counted(
        registry: &ToolRegistry,
        db: &crate::db::Db,
        caller: Caller,
        args: Value,
    ) -> (Value, u64) {
        let sink = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let page = with_write_pool_acquisition_sink(
            std::sync::Arc::clone(&sink),
            list_as(registry, db, caller, args),
        )
        .await;
        (page, sink.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// Governed-only page: the isolated pre-M4 implementation, with the same
    /// cursor decode/validation the handler applies. The independent oracle
    /// for every tool answer below.
    async fn governed_page(
        db: &crate::db::Db,
        caller: &Caller,
        record_id: &str,
        limit: usize,
        cursor: Option<String>,
    ) -> Value {
        let decoded = if let Some(token) = cursor.as_deref() {
            let snapshot = db.get_inbox_snapshot(token).unwrap();
            let decoded: LinkListCursor = serde_json::from_value(snapshot).unwrap();
            assert_eq!(decoded.schema, 1);
            assert_eq!(decoded.account_id, caller.credential());
            assert_eq!(decoded.record_id, record_id);
            assert_eq!(decoded.limit, limit);
            Some(decoded)
        } else {
            None
        };
        list_governed(db, caller, record_id, limit, cursor, decoded.as_ref())
            .await
            .unwrap()
    }

    fn out_ids(page: &Value) -> Vec<String> {
        page["links_out"]
            .as_array()
            .unwrap()
            .iter()
            .map(|link| link["id"].as_str().unwrap().to_string())
            .collect()
    }

    fn in_ids(page: &Value) -> Vec<String> {
        page["links_in"]
            .as_array()
            .unwrap()
            .iter()
            .map(|link| link["id"].as_str().unwrap().to_string())
            .collect()
    }

    /// Field-by-field page equality with normalized opaque cursors:
    /// `next_cursor` tokens are random per call, so presence and the
    /// `next_call` shape are compared instead of the token strings. The
    /// registry wrapper's `run_context` framing is transport, not tool
    /// output, and is ignored on both sides.
    fn comparable(mut page: Value) -> Value {
        if let Some(object) = page.as_object_mut() {
            object.remove("run_context");
        }
        page
    }

    fn assert_same_page(left: &Value, right: &Value) {
        let left = comparable(left.clone());
        let right = comparable(right.clone());
        let (left, right) = (&left, &right);
        // `cursor` echoes the caller's opaque input token, which is minted
        // per path — presence must match, strings must not be compared.
        assert_eq!(
            left["cursor"].is_null(),
            right["cursor"].is_null(),
            "page cursor presence differs"
        );
        for field in [
            "action",
            "format",
            "record_id",
            "viewer_relative",
            "query_basis",
            "scope",
            "limit",
            "links_out",
            "links_in",
            "returned",
            "has_more",
        ] {
            assert_eq!(left[field], right[field], "page field {field} differs");
        }
        match (left["next_cursor"].as_str(), right["next_cursor"].as_str()) {
            (None, None) => {
                assert!(left["next_call"].is_null());
                assert!(right["next_call"].is_null());
            }
            (Some(_), Some(_)) => {
                for (page, name) in [(left, "left"), (right, "right")] {
                    assert_eq!(page["next_call"]["action"], "list");
                    assert_eq!(page["next_call"]["record_id"], page["record_id"]);
                    assert_eq!(page["next_call"]["limit"], page["limit"]);
                    assert_eq!(
                        page["next_call"]["cursor"].as_str().unwrap(),
                        page["next_cursor"].as_str().unwrap(),
                        "{name} next_call must carry its next_cursor"
                    );
                }
            }
            (left_cursor, right_cursor) => {
                panic!("cursor presence differs: {left_cursor:?} vs {right_cursor:?}")
            }
        }
    }

    async fn tool_chain(
        registry: &ToolRegistry,
        db: &crate::db::Db,
        caller: Caller,
        limit: usize,
    ) -> Vec<Value> {
        let mut pages = vec![
            list_as(
                registry,
                db,
                caller.clone(),
                json!({"action": "list", "record_id": ANCHOR, "limit": limit}),
            )
            .await,
        ];
        while pages.last().unwrap()["has_more"] == true {
            let cursor = pages.last().unwrap()["next_cursor"]
                .as_str()
                .unwrap()
                .to_string();
            pages.push(
                list_as(
                    registry,
                    db,
                    caller.clone(),
                    json!({"action": "list", "record_id": ANCHOR, "limit": limit, "cursor": cursor}),
                )
                .await,
            );
        }
        pages
    }

    async fn governed_chain(db: &crate::db::Db, caller: &Caller, limit: usize) -> Vec<Value> {
        let mut pages = vec![governed_page(db, caller, ANCHOR, limit, None).await];
        while pages.last().unwrap()["has_more"] == true {
            let cursor = pages.last().unwrap()["next_cursor"]
                .as_str()
                .unwrap()
                .to_string();
            pages.push(governed_page(db, caller, ANCHOR, limit, Some(cursor)).await);
        }
        pages
    }

    /// Differential oracle for the M4 `manage_links.list` slice: the tool
    /// (indexed hit or governed fallback, per fences) serves exactly the
    /// isolated governed implementation's answer for two principals across
    /// hidden endpoints, a self-link duplicate, an invalid comment (opposite
    /// endpoint and anchor), narrowing, cursor chains, cross-path cursors, a
    /// relationship-owned link, and stale-fence fallbacks.
    #[tokio::test]
    async fn indexed_list_matches_governed_across_phases() {
        let (db, registry) = fixture().await;
        db.ensure_workspace_index().await.unwrap();

        // Phase A1: fence-stable pages with no comment-kind endpoint hit the
        // index with no write-pool use and equal the governed oracle. Limit 2
        // covers the physical head (`member_of`, `mentions`→VISIBLE) without
        // reaching the invalid comment at the tail.
        for caller in [alice(), bea()] {
            assert!(
                try_indexed_links_list(&db, &caller, ANCHOR, 2, None, None)
                    .await
                    .unwrap()
                    .is_some(),
                "comment-free page must hit the index"
            );
            let (tool, writes) = list_as_counted(
                &registry,
                &db,
                caller.clone(),
                json!({"action": "list", "record_id": ANCHOR, "limit": 2}),
            )
            .await;
            assert_eq!(writes, 0, "indexed hit must not check out the write pool");
            assert_same_page(&tool, &governed_page(&db, &caller, ANCHOR, 2, None).await);
        }

        // Phase A2: the invalid-comment gap. The view admits BAD_COMMENT (no
        // comment predicate) while the governed path excludes it; prove the
        // oracle exercises that gap, then prove the indexed path — now
        // filtering through the same governed predicate on the read pool —
        // serves exactly the governed answer with the bad link absent. A hit,
        // not a fallback: no write-pool checkout.
        {
            let visible = crate::query::sql::workspace_visible_set(
                &db,
                crate::query::QueryPrincipal::from(&alice()),
            )
            .await
            .unwrap();
            assert!(
                visible.ids.contains(BAD_COMMENT),
                "oracle must exercise the view/comment gap"
            );
        }
        for caller in [alice(), bea()] {
            assert!(
                try_indexed_links_list(&db, &caller, ANCHOR, 50, None, None)
                    .await
                    .unwrap()
                    .is_some(),
                "comment-filtered page must hit the index"
            );
            let (tool, writes) = list_as_counted(
                &registry,
                &db,
                caller.clone(),
                json!({"action": "list", "record_id": ANCHOR}),
            )
            .await;
            assert_eq!(
                writes, 0,
                "filtered indexed hit must not check out the write pool"
            );
            let governed = governed_page(&db, &caller, ANCHOR, 50, None).await;
            assert_eq!(
                comparable(tool.clone()),
                comparable(governed),
                "filtered indexed hit must equal the governed oracle"
            );
            assert!(
                !out_ids(&tool).contains(&LINK_BAD_COMMENT.to_string()),
                "invalid comment link must stay filtered"
            );
        }
        // The self-link pages twice on the fallback too: once as out, once
        // as in — and the hidden endpoint stays filtered for bea.
        {
            let tool = governed_page(&db, &alice(), ANCHOR, 50, None).await;
            assert!(out_ids(&tool).contains(&LINK_SELF.to_string()));
            assert!(in_ids(&tool).contains(&LINK_SELF.to_string()));
            let bea_tool = governed_page(&db, &bea(), ANCHOR, 50, None).await;
            assert!(!out_ids(&bea_tool).contains(&LINK_HIDDEN.to_string()));
        }

        // Phase A3: an invalid comment as anchor. The governed path reports
        // not-found; the indexed path must decline through the same governed
        // anchor predicate and produce exactly that error, never a served page.
        {
            let tool_err = registry
                .call(
                    db.clone(),
                    alice(),
                    "manage_links",
                    json!({"action": "list", "record_id": BAD_COMMENT}),
                )
                .await
                .unwrap_err()
                .to_string();
            let governed_err = super::list_governed(&db, &alice(), BAD_COMMENT, 50, None, None)
                .await
                .unwrap_err()
                .to_string();
            assert_eq!(tool_err, governed_err, "anchor errors must match exactly");
            assert!(tool_err.contains("does not exist"), "{tool_err}");
        }

        // Phase B: full cursor chains agree page by page at two limits.
        // Bea's limit-1 head page is the empty-page contract: the physical
        // head is the hidden `member_of` link, so nothing is returned but
        // paging continues.
        for (caller, limit) in [(alice(), 1), (bea(), 1), (alice(), 2), (bea(), 2)] {
            let tool_pages = tool_chain(&registry, &db, caller.clone(), limit).await;
            let governed_pages = governed_chain(&db, &caller, limit).await;
            assert_eq!(
                tool_pages.len(),
                governed_pages.len(),
                "chain length must match for {} at limit {limit}",
                caller.credential()
            );
            for (index, (tool_page, governed_page)) in
                tool_pages.iter().zip(governed_pages.iter()).enumerate()
            {
                assert_same_page(tool_page, governed_page);
                if index == 0 && caller.credential() == "bea" && limit == 1 {
                    assert_eq!(tool_page["returned"], 0);
                    assert_eq!(tool_page["has_more"], true);
                }
            }
        }

        // Cross-path cursors: a cursor minted by either implementation pages
        // on the other, proving the shared cursor schema and store.
        let governed_pages = governed_chain(&db, &alice(), 1).await;
        assert!(governed_pages.len() > 1);
        let via_tool = list_as(
            &registry,
            &db,
            alice(),
            json!({
                "action": "list", "record_id": ANCHOR, "limit": 1,
                "cursor": governed_pages[0]["next_cursor"].as_str().unwrap(),
            }),
        )
        .await;
        assert_same_page(&via_tool, &governed_pages[1]);
        let tool_pages = tool_chain(&registry, &db, alice(), 1).await;
        let via_governed = governed_page(
            &db,
            &alice(),
            ANCHOR,
            1,
            Some(tool_pages[0]["next_cursor"].as_str().unwrap().to_string()),
        )
        .await;
        assert_same_page(&via_governed, &tool_pages[1]);

        // Phase C: narrowing the shared record to alice-only bumps the
        // authorization fence. The shared repair policy rebuilds once, so the
        // indexed path serves the narrowed governed answer with no stale row
        // — on the read pool only, never the write pool.
        replace_explicit_policy(
            &db,
            "test:narrow",
            VISIBLE,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();
        assert!(
            try_indexed_links_list(&db, &bea(), ANCHOR, 50, None, None)
                .await
                .unwrap()
                .is_some(),
            "rebuilt index must serve the narrowed answer, never stale rows"
        );
        for caller in [alice(), bea()] {
            let (tool, writes) = list_as_counted(
                &registry,
                &db,
                caller.clone(),
                json!({"action": "list", "record_id": ANCHOR}),
            )
            .await;
            assert_eq!(
                writes, 0,
                "post-rebuild indexed hit must not check out the write pool"
            );
            assert_eq!(
                comparable(tool),
                comparable(governed_page(&db, &caller, ANCHOR, 50, None).await),
                "rebuilt hit must equal the governed oracle"
            );
        }
        let bea_narrowed = governed_page(&db, &bea(), ANCHOR, 50, None).await;
        let mut bea_got = out_ids(&bea_narrowed);
        bea_got.sort();
        assert_eq!(bea_got, vec![LINK_EXTRA1, LINK_EXTRA2, LINK_SELF]);
        assert_eq!(in_ids(&bea_narrowed), vec![LINK_SELF]);

        // Phase D: a relationship-owned link moves the relationship fence.
        // The shared repair policy rebuilds once, so the indexed path serves
        // the new link with no miss — on the read pool only.
        list_as(
            &registry,
            &db,
            Caller::local(),
            json!({
                "action": "add",
                "source_id": VISIBLE,
                "target_id": ANCHOR,
                "relationship": "relates_to",
            }),
        )
        .await;
        assert!(
            try_indexed_links_list(&db, &alice(), ANCHOR, 50, None, None)
                .await
                .unwrap()
                .is_some(),
            "rebuilt index must serve the relationship-owned link, never miss it"
        );
        let (alice_rel, writes) = list_as_counted(
            &registry,
            &db,
            alice(),
            json!({"action": "list", "record_id": ANCHOR}),
        )
        .await;
        assert_eq!(
            writes, 0,
            "post-rebuild indexed hit must not check out the write pool"
        );
        assert_eq!(
            comparable(alice_rel.clone()),
            comparable(governed_page(&db, &alice(), ANCHOR, 50, None).await),
            "rebuilt hit must equal the governed oracle"
        );
        assert!(
            alice_rel["links_in"]
                .as_array()
                .unwrap()
                .iter()
                .any(|link| {
                    link["relationship"] == "relates_to" && link["source_id"] == VISIBLE
                }),
            "relationship-owned link must be served, never missed as stale: {alice_rel}"
        );
        // Bea still sees neither the narrowed record's links nor anything new.
        let bea_rel = governed_page(&db, &bea(), ANCHOR, 50, None).await;
        let mut bea_final = out_ids(&bea_rel);
        bea_final.sort();
        assert_eq!(bea_final, vec![LINK_EXTRA1, LINK_EXTRA2, LINK_SELF]);
        assert_eq!(in_ids(&bea_rel), vec![LINK_SELF]);
        db.close().await;
    }

    const ANCHOR2: &str = "7e5a0002-0000-4000-8000-000000000001";
    const UNIT: &str = "7e5a0002-0000-4000-8000-000000000002";
    const ACK: &str = "7e5a0002-0000-4000-8000-000000000003";
    const LINK_UNIT: &str = "7e5a0002-0000-4000-8000-000000000011";
    const LINK_ACK: &str = "7e5a0002-0000-4000-8000-000000000012";

    async fn admission_fixture() -> (crate::db::Db, ToolRegistry) {
        let db = crate::db::create_database(":memory:").await.unwrap();
        for (id, record_type, kind, name) in [
            (ANCHOR2, "Document", "note", "anchor2"),
            (UNIT, "Document", "note", "unit"),
            (ACK, "Annotation", "acknowledgement", "ack"),
        ] {
            create_record(
                &db,
                json!({
                    "id": id, "type": record_type, "kind": kind, "name": name,
                    "home_id": crate::schema::ROOT_RECORD_ID
                }),
            )
            .await
            .unwrap();
        }
        for id in [ANCHOR2, UNIT, ACK] {
            replace_explicit_policy(
                &db,
                "test:policy",
                id,
                vec![
                    AllowEntry::account("alice", Capability::View),
                    AllowEntry::account("bea", Capability::View),
                ],
            )
            .await
            .unwrap();
        }
        for (id, target) in [(LINK_UNIT, UNIT), (LINK_ACK, ACK)] {
            add_link(
                &db,
                LinkAddedPayload {
                    id: Some(id.to_string()),
                    source_id: ANCHOR2.to_string(),
                    target_id: target.to_string(),
                    relationship: "mentions".to_string(),
                    note: None,
                },
            )
            .await
            .unwrap();
        }
        // Unitize UNIT under ANCHOR2's authority by writing the projected
        // `semantic_units` row directly. This models projection state, not a
        // supported-API interleaving: no claim is made about reaching this
        // exact state through the semantic-actor/kernel promotion path. What
        // matters for the oracle is the resulting admission split — the view
        // hides the unitized record while the governed capability fold serves
        // it — under fences the index already holds (a projection-table write
        // appends no content event, so no fence moves and the index stays
        // fence-current).
        let creation = sqlx::query(
            "SELECT id, seq, created_at FROM content_events \
             WHERE record_id = ? AND type = 'record.created'",
        )
        .bind(UNIT)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO semantic_units \
             (unit_id, authority_bearer_record_id, creation_event_id, creation_event_seq, created_at) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(UNIT)
        .bind(ANCHOR2)
        .bind(creation.try_get::<String, _>("id").unwrap())
        .bind(creation.try_get::<i64, _>("seq").unwrap())
        .bind(creation.try_get::<String, _>("created_at").unwrap())
        .execute(db.write_pool())
        .await
        .unwrap();
        let mut registry = ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        (db, registry)
    }

    /// Governed-admission parity for the endpoints the visibility view hides:
    /// a unitized envelope is served by the governed predicates under policy,
    /// a bearerless acknowledgement carries no capability grant on either
    /// path, and a tombstoned anchor serves the cascaded-empty page on both
    /// (authenticated and trusted-local). The indexed path must equal
    /// `list_governed` in all three cases — hit with governed filtering for
    /// the servable unit link, exclusion parity for the acknowledgement,
    /// empty-page parity for the tombstone.
    #[tokio::test]
    async fn governed_admission_parity_unit_ack_tombstone() {
        let (db, registry) = admission_fixture().await;
        db.ensure_workspace_index().await.unwrap();
        // Gap proof: the view hides the unitized envelope that the governed
        // path serves under policy. The acknowledgement is a
        // parity/exclusion control, not a second gap instance: the governed
        // capability fold grants a bearerless acknowledgement no View, so
        // both paths exclude it and the oracle pins that exclusion.
        {
            let visible = crate::query::sql::workspace_visible_set(
                &db,
                crate::query::QueryPrincipal::from(&alice()),
            )
            .await
            .unwrap();
            assert!(
                !visible.ids.contains(UNIT),
                "oracle must exercise the unitized-envelope gap"
            );
            assert!(
                !visible.ids.contains(ACK),
                "acknowledgement stays out of the view as well"
            );
        }
        for caller in [alice(), bea()] {
            assert!(
                try_indexed_links_list(&db, &caller, ANCHOR2, 50, None, None)
                    .await
                    .unwrap()
                    .is_some(),
                "governed-admitted page must hit the index"
            );
            let (tool, writes) = list_as_counted(
                &registry,
                &db,
                caller.clone(),
                json!({"action": "list", "record_id": ANCHOR2}),
            )
            .await;
            assert_eq!(
                writes, 0,
                "admitted indexed hit must not check out the write pool"
            );
            let governed = governed_page(&db, &caller, ANCHOR2, 50, None).await;
            assert_eq!(
                comparable(tool.clone()),
                comparable(governed),
                "indexed hit must equal the governed oracle"
            );
            let out = out_ids(&tool);
            assert!(
                out.contains(&LINK_UNIT.to_string()),
                "unitized envelope link must be served, never hidden: {tool}"
            );
            // The bearerless acknowledgement carries no capability grant on
            // the governed path either: exclusion parity, pinned on both
            // sides rather than assumed.
            assert!(
                !out.contains(&LINK_ACK.to_string()),
                "acknowledgement link must stay excluded exactly as governed: {tool}"
            );
        }
        // Tombstoned anchor: the governed result depends on caller
        // authorization; compare full Results because success-unwrapping
        // helpers cannot represent denial.
        // Compare the full Results instead, modulo the registry wrapper's
        // `run_context` framing. Direction differs by caller, and both are
        // pinned: the authenticated caller is denied through the capability
        // fold, while trusted-local passes shape validation and serves the
        // cascaded-empty page. Either way the indexed path must match
        // governed exactly — never a stale pre-delete link, never a new
        // error.
        delete_record(&db, ANCHOR2).await.unwrap();
        for caller in [alice(), Caller::local()] {
            let tool = registry
                .call(
                    db.clone(),
                    caller.clone(),
                    "manage_links",
                    json!({"action": "list", "record_id": ANCHOR2}),
                )
                .await
                .map_err(|error| error.to_string());
            let governed = super::list_governed(&db, &caller, ANCHOR2, 50, None, None)
                .await
                .map_err(|error| error.to_string());
            assert_eq!(
                tool.clone().map(comparable),
                governed.clone().map(comparable),
                "tombstone anchor must match the governed result exactly for {}",
                caller.credential()
            );
            // No direction asserted: `ordinary_record_read_eligible_live_in`
            // returns true for any non-comment record regardless of
            // deleted_at, so denial vs cascaded-empty page varies with
            // authorization and the delete projection. Result equality is the
            // pin; the UNIT hit above is the blocker-fix proof.
        }
        db.close().await;
    }

    /// Activity-roster parity: a caller carrying a catalog-verified hosted
    /// activity roster converts to an activity reader under
    /// `QueryPrincipal::from`, while the governed path authorizes through the
    /// ordinary policy principal. The indexed path must decline such callers
    /// outright — even on a comment-free page — and serve exactly the
    /// governed answer.
    #[tokio::test]
    async fn activity_roster_caller_falls_back_to_governed() {
        let (db, registry) = fixture().await;
        db.ensure_workspace_index().await.unwrap();
        let member = unsafe {
            crate::query::principal::ActivityRosterMember::verified_unchecked(
                "alice",
                "native:workspace-member:alice",
            )
        };
        let rostered = unsafe {
            Caller::authenticated("alice").with_verified_hosted_activity(
                "catalog-alice",
                "db-1",
                vec![member],
                true,
            )
        }
        .unwrap();
        // Comment-free page (limit 2 covers only the physical head), so the
        // only reason to decline is the roster itself.
        assert!(
            try_indexed_links_list(&db, &rostered, ANCHOR, 2, None, None)
                .await
                .unwrap()
                .is_none(),
            "activity-roster caller must fall back, never serve from the index"
        );
        let (tool, writes) = list_as_counted(
            &registry,
            &db,
            rostered.clone(),
            json!({"action": "list", "record_id": ANCHOR, "limit": 2}),
        )
        .await;
        assert!(writes > 0, "roster fallback must use the governed path");
        assert_same_page(&tool, &governed_page(&db, &rostered, ANCHOR, 2, None).await);
        db.close().await;
    }
}
