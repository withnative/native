//! Kernel adapter for the shared v1 snapshot protocol. Only governed TEMP
//! metadata and canonical gap-free history enter a pin; never source payloads.
use std::collections::{BTreeSet, HashMap, HashSet};

use futures::TryStreamExt;

use super::*;
use crate::query::QueryPrincipal;
use crate::workspace_index::{
    ContentEventRef, FacetRow, FilteredWorkspaceIndex, LinkRow, RecordHead,
};

// V1's three fences (db.rs::live_snapshot_fences) are distinct streams.
// The kernel shares a log, so select the corresponding authority changes,
// retained relationship stream and semantic-unit creations, not a global head.
// Facets, archive, body/comment edits, run/control state and app activity do not
// replace policies. Record *creation* does fence, just like v1's records INSERT
// trigger (schema/ddl.rs::authorization_revision_records_insert).
const AUTHORITY_EVENT: &str = r#"(
 e.type IN ('kernel.root_admin_bootstrapped.v1',
 'kernel.record_created.v1','kernel.import_record_created.v1','kernel.message_created.v1',
 'kernel.record_deleted.v1','kernel.record_rebound.v1',
 'kernel.home_created.v1','kernel.home_created_for.v1','kernel.home_policy_replaced.v1',
 'kernel.hosted_membership.v1','kernel.hosted_offboarding.v1','kernel.import_member_policy.v1',
 'kernel.import_home.v1','kernel.import_home_delta.v1','kernel.import_home_policy.v1',
 'kernel.import_state.v1','kernel.import_state_delta.v1','kernel.record_rehomed.v1')
 OR (e.type='kernel.import_removed.v1' AND json_extract(e.payload,'$.kind')='record')
 OR (e.type='kernel.record_rehomed.v2' AND NOT EXISTS (
   SELECT 1 FROM kernel_policies p JOIN main.content_events h ON h.record_id=p.root_id
   AND h.type IN ('kernel.home_created.v1','kernel.import_home.v1')
   AND json_extract(h.payload,'$.source_record_id')=e.record_id
   WHERE p.root_id=json_extract(e.payload,'$.new_home_id')))
 OR (e.type IN ('kernel.record_revised.v1','kernel.record_revised.v2') AND EXISTS (
   SELECT 1 FROM json_each(e.payload,'$.fields') f JOIN kernel_records r ON r.id=e.record_id AND r.pin_family='native.v1.record' WHERE f.key IN ('v1_type','v1_kind')))
 OR (e.type IN ('kernel.generic_link_added.v1','kernel.generic_link_imported.v1','kernel.link_added.v1','kernel.link_removed.v1')
   AND json_extract(e.payload,'$.relationship')='part_of')
 OR (e.type IN ('kernel.generic_link_removed.v1','kernel.generic_link_removal_imported.v1','kernel.generic_link_note_updated.v1','kernel.generic_link_note_imported.v1') AND EXISTS (
   SELECT 1 FROM kernel_generic_links l WHERE l.link_id=json_extract(e.payload,'$.link_id') AND l.relationship='part_of'))
)"#;

pub(crate) async fn fences_on(conn: &mut sqlx::SqliteConnection) -> Result<(i64, i64, i64)> {
    let authorization: i64 = sqlx::query_scalar(&format!(
        "SELECT coalesce(max(e.seq),0) FROM main.content_events e WHERE {AUTHORITY_EVENT}"
    ))
    .fetch_one(&mut *conn)
    .await?;
    // Typed relationship and semantic-unit mutations have no native v2 writer
    // yet. Their sealed imported headers are the real stream proof; a generic
    // relates_to edge, definition adoption or app install is neither stream.
    let (relationships, units): (i64,i64) = sqlx::query_as(
        "SELECT coalesce(max(CASE WHEN source_stream='relationship_events' THEN seq END),0),coalesce(max(CASE WHEN source_stream='content_events' AND event_type='unit.created.v1' THEN seq END),0) FROM kernel_legacy_sql_events"
    ).fetch_one(conn).await?;
    Ok((authorization, relationships, units))
}

// Only content-stream mutations consume v1's 512-event gap. Kernel runs,
// receipts, identity/roster, app and member read-state have their own v1
// control/meta lanes. Preserve RAW native sequence numbers/order on the wire:
// this is a count over relevant commits, never a compressed/visible cursor.
fn content_event() -> &'static str {
    r#"(
 e.type IN ('kernel.record_created.v1','kernel.import_record_created.v1','kernel.message_created.v1',
 'kernel.record_revised.v1','kernel.record_revised.v2','kernel.record_deleted.v1',
 'kernel.record_rehomed.v1','kernel.record_rehomed.v2','kernel.body_set.v1',
 'kernel.metadata_set.v1','kernel.facet_observed.v1','kernel.archive_changed.v1',
 'kernel.attachment_bound.v1','kernel.provider_outcome.v1','kernel.link_added.v1','kernel.link_added.v2','kernel.link_removed.v1',
 'kernel.generic_link_added.v1','kernel.generic_link_imported.v1','kernel.generic_link_removed.v1',
 'kernel.generic_link_removal_imported.v1','kernel.generic_link_note_updated.v1','kernel.generic_link_note_imported.v1')
 OR (e.type='kernel.legacy_recorded.v1' AND EXISTS (
   SELECT 1 FROM kernel_legacy_sql_events l WHERE l.seq=e.seq AND l.source_stream='content_events'))
 OR (e.type='kernel.message_state.v1' AND json_extract(e.payload,'$.reactions') IS NOT (
   SELECT json_extract(CASE WHEN p.type='kernel.v1_state_imported.v1' THEN json_extract(p.payload,'$.state.message') ELSE p.payload END,'$.reactions')
   FROM main.content_events p WHERE p.record_id=e.record_id AND p.seq<e.seq
   AND (p.type IN ('kernel.message_created.v1','kernel.message_state.v1') OR (p.type='kernel.v1_state_imported.v1' AND json_type(p.payload,'$.state.message')='object')) ORDER BY p.seq DESC LIMIT 1))
)"#
}

pub(crate) async fn gap_exceeded(db: &Db, after: i64, through: i64) -> Result<bool> {
    let count: i64 = sqlx::query_scalar(&format!(
        "SELECT count(*) FROM (SELECT 1 FROM main.content_events e WHERE e.seq>? AND e.seq<=? AND {} LIMIT 513)", content_event()
    )).bind(after).bind(through).fetch_one(db.governed_pool()).await?;
    Ok(count > crate::workspace_snapshot::SNAPSHOT_MAX_CATCH_UP_GAP)
}

pub(crate) async fn filtered(
    db: &Db,
    principal: QueryPrincipal,
) -> Result<Option<FilteredWorkspaceIndex>> {
    let actor = super::principal(db, &Caller::authenticated(principal.credential())).await?;
    let mut conn = db.governed_pool().acquire().await?;
    conn.close_on_drop();
    sqlx::query("BEGIN").execute(&mut *conn).await?;
    kernel::app_installs::admit_dispatched_on(&mut conn, &actor).await?;
    let head: i64 = sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM main.content_events")
        .fetch_one(&mut *conn)
        .await?;
    let (authorization_epoch, relationship_seq, unit_seq_max) = fences_on(&mut conn).await?;
    let reads: BTreeSet<_> = [
        ("records", "id"),
        ("records", "type"),
        ("records", "kind"),
        ("records", "name"),
        ("records", "home_id"),
        ("records", "created_at"),
        ("records", "updated_at"),
        ("records", "summary"),
        ("records", "lifecycle"),
        ("records", "persistence"),
        ("records", "maturity"),
        ("records", "last_activity_at"),
        ("records", "deleted_at"),
        ("facet_values", "id"),
        ("links", "id"),
        ("links", "source_id"),
        ("links", "target_id"),
        ("links", "relationship"),
        ("links", "note"),
        ("links", "created_at"),
    ]
    .into_iter()
    .map(|(r, c)| (r.to_owned(), c.to_owned()))
    .collect();
    super::sql::install(&mut conn, &actor, &reads).await?;
    // Charge exactly the shared store's typed row representation. Stream one
    // row at a time and stop at the same per-pin cap as v1, never JSON size x2.
    let mut bytes = 1536 + principal.credential().len() + 64;
    let mut native_untyped_records = HashSet::new();
    let mut records = HashMap::new();
    let mut facets = HashMap::new();
    let mut links = HashMap::new();
    for (relation, columns) in [
        ("records", "id,type,kind,name,home_id,lifecycle,persistence,maturity,summary,last_activity_at,created_at,updated_at,deleted_at"),
        ("facet_values", "id,record_id,key,value,value_num,vocab_ref,created_at"),
        ("links", "id,source_id,target_id,relationship,note,created_at"),
    ] {
        // V1 records.name is NOT NULL DEFAULT ''; an unnamed comment
        // has no kernel identity field, which the governed SQL view exposes
        // as NULL. Preserve v1's actual empty display-name shape.
        let fields = columns.split(',').map(|c| {
            if relation == "records" && c == "name" { "'name',coalesce(name,'')".to_owned() }
            else { format!("'{c}',{c}") }
        }).collect::<Vec<_>>().join(",");
        let statement = format!("SELECT json_object({fields}) FROM temp.{relation}");
        let mut rows = sqlx::query_scalar::<_,String>(&statement).persistent(false).fetch(&mut *conn);
        while let Some(row) = rows.try_next().await? {
            match relation {
                "records" => {
                    let Ok(r) = serde_json::from_str::<crate::workspace_snapshot::SnapshotRecord>(&row) else {
                        return Ok(None);
                    };
                    bytes += r.estimated_bytes();
                    if r.record_type.is_none() { native_untyped_records.insert(r.id.clone()); }
                    records.insert(r.id.clone(), RecordHead {
                        id:r.id,record_type:r.record_type.unwrap_or_default(),kind:r.kind,name:r.name,home_id:r.home_id,
                        lifecycle:r.lifecycle,persistence:r.persistence,maturity:r.maturity,summary:r.summary,
                        last_activity_at:r.last_activity_at,created_at:r.created_at,updated_at:r.updated_at,deleted_at:r.deleted_at,
                        owner_id:None,claimed_by_account:None,claimed_run_key:None,claimed_at:None,policy_anchor_id:None,
                    });
                }
                "facet_values" => {
                    let Ok(r) = serde_json::from_str::<crate::workspace_snapshot::SnapshotFacet>(&row) else {
                        return Ok(None);
                    };
                    bytes += r.estimated_bytes();
                    facets.insert(r.id.clone(), FacetRow{id:r.id,record_id:r.record_id,key:r.key,value:r.value,value_num:r.value_num,vocab_ref:r.vocab_ref,created_at:r.created_at});
                }
                _ => {
                    // The governed v2 provider union honestly has no single
                    // creation time for some aggregate links. v1's snapshot
                    // schema requires one, so this projection is unavailable,
                    // rather than inventing a timestamp or dropping the link.
                    let value: Value=serde_json::from_str(&row)?;
                    if value["created_at"].is_null() { return Ok(None); }
                    let Ok(r) = serde_json::from_value::<crate::workspace_snapshot::SnapshotLink>(value) else {
                        return Ok(None);
                    };
                    bytes += r.estimated_bytes();
                    links.insert(r.id.clone(), LinkRow{id:r.id,source_id:r.source_id,target_id:r.target_id,relationship:r.relationship,note:r.note,created_at:r.created_at});
                }
            }
            if bytes > crate::workspace_snapshot::SNAPSHOT_MAX_BYTES { return Ok(None); }
        }
    }
    // Keep the newest 512 relevant content commits, including hidden ones.
    // Control chatter cannot evict evidence or make a raw sequence gap lie.
    let mut raw: Vec<(i64, String, String)> = sqlx::query_as(&format!(
        "SELECT e.seq,e.record_id,e.type FROM main.content_events e WHERE e.seq<=? AND {} ORDER BY e.seq DESC LIMIT 512", content_event()
    )).bind(head).fetch_all(&mut *conn).await?;
    raw.reverse();
    // Canonical history reads the physical log. Remove the unused governed
    // event view so its v1 column names cannot shadow that log on this owned
    // connection; all metadata above remains pinned in the same transaction.
    sqlx::query("DROP VIEW temp.content_events")
        .execute(&mut *conn)
        .await?;
    let mut events = std::collections::BTreeMap::new();
    for (seq, subject, kind) in &raw {
        if kind == kernel::messaging::EVENT {
            continue;
        }
        for e in kernel::history_page_in_range_on(
            &mut conn,
            &actor,
            subject,
            None,
            false,
            1,
            false,
            false,
            (*seq, *seq),
        )
        .await?
        {
            events.insert(
                e.seq,
                ContentEventRef {
                    seq: e.seq,
                    id: e.id,
                    record_id: e.record_id,
                    event_type: e.event_type,
                    created_at: e.created_at,
                },
            );
        }
    }
    // Message commands have their own canonical audience disclosure path.
    for (seq, _, kind) in &raw {
        if kind != kernel::messaging::EVENT {
            continue;
        }
        if let Some(e) = kernel::messaging::change_on(&mut conn, &actor, *seq).await? {
            events.insert(
                e.seq,
                ContentEventRef {
                    seq: e.seq,
                    id: e.id,
                    record_id: e.record_id,
                    event_type: e.event_type,
                    created_at: e.created_at,
                },
            );
        }
    }
    sqlx::query("ROLLBACK").execute(&mut *conn).await?;
    Ok(Some(FilteredWorkspaceIndex {
        native_untyped_records: Some(native_untyped_records),
        content_seq: head,
        authorization_epoch,
        relationship_seq,
        unit_seq_max,
        records,
        facets,
        links,
        content_events: events.into_values().collect(),
    }))
}
