//! Open-vocabulary HQ links. Only exact `relates_to` belongs to its provider;
//! `related_to` and `relates-to` are distinct, verbatim legacy relationships.
//! `supersedes`/`part_of` have no derived semantics here. Both endpoint indexes
//! support their future projections without changing recorded history.
use super::*;

pub(crate) const DDL: &str = "CREATE TABLE kernel_generic_links (
 link_id TEXT PRIMARY KEY, source_id TEXT NOT NULL REFERENCES kernel_records(id),
 target_id TEXT NOT NULL REFERENCES kernel_records(id), relationship TEXT NOT NULL,
 note TEXT, created_at TEXT NOT NULL, actor TEXT, active INTEGER NOT NULL,
 event_seq INTEGER NOT NULL, imported INTEGER NOT NULL)";
const ADDED: &str = "kernel.generic_link_added.v1";
const IMPORTED: &str = "kernel.generic_link_imported.v1";
const NOTE: &str = "kernel.generic_link_note_updated.v1";
const IMPORTED_NOTE: &str = "kernel.generic_link_note_imported.v1";
const REMOVED: &str = "kernel.generic_link_removed.v1";
const IMPORTED_REMOVED: &str = "kernel.generic_link_removal_imported.v1";
pub const MAX_LINK_RELATIONSHIP_BYTES: usize = 1024;

/// Stable identity and original creation provenance; removal does not erase it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::FromRow)]
#[serde(deny_unknown_fields)]
pub struct GenericLink {
    pub link_id: String,
    pub source_id: String,
    pub target_id: String,
    pub relationship: String,
    pub note: Option<String>,
    pub created_at: String,
    pub actor: Option<String>,
}

/// Observable result of a link upsert; unchanged requests append no event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenericLinkOutcome {
    Created,
    Updated,
    Unchanged,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenericLinkWrite {
    pub link: GenericLink,
    pub outcome: GenericLinkOutcome,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinkNote {
    link_id: String,
    note: Option<String>,
}

/// Ordinary creation takes provenance solely from its event envelope.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinkCreation {
    link_id: String,
    source_id: String,
    target_id: String,
    relationship: String,
    note: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinkRemoval {
    link_id: String,
}

fn added_link(event: &EventRow) -> Result<GenericLink> {
    let p: LinkCreation = event_payload(event)?;
    Ok(GenericLink {
        link_id: p.link_id,
        source_id: p.source_id,
        target_id: p.target_id,
        relationship: p.relationship,
        note: p.note,
        created_at: event.created_at.clone(),
        actor: event.actor.clone(),
    })
}

fn validate(p: &GenericLink, source: &str) -> Result<()> {
    if p.link_id.trim().is_empty()
        || p.source_id != source
        || p.relationship.trim().is_empty()
        || p.relationship.len() > MAX_LINK_RELATIONSHIP_BYTES
        || p.relationship == "relates_to"
        || !parseable_creation_time(&p.created_at)
    {
        return Err(Error::engine(
            "invalid generic link (exact relates_to is provider-owned)",
        ));
    }
    crate::surface_binding::refuse_reserved_surface_binding("generic links", &p.relationship)?;
    Ok(())
}

// Preserve original bytes, accepting offset timestamps, RFC 2822, SQLite's
// UTC datetime spelling (including fractions), and ISO calendar dates.
fn parseable_creation_time(value: &str) -> bool {
    let value = value.trim();
    chrono::DateTime::parse_from_rfc3339(value).is_ok()
        || chrono::DateTime::parse_from_rfc2822(value).is_ok()
        || ["%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S%.f"]
            .iter()
            .any(|fmt| chrono::NaiveDateTime::parse_from_str(value, fmt).is_ok())
        || chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d").is_ok()
}

async fn by_id(conn: &mut SqliteConnection, id: &str) -> Result<Option<GenericLink>> {
    Ok(sqlx::query_as("SELECT link_id,source_id,target_id,relationship,note,created_at,actor FROM kernel_generic_links WHERE link_id=?")
        .bind(id).fetch_optional(conn).await?)
}
async fn active_triple(
    conn: &mut SqliteConnection,
    source: &str,
    target: &str,
    rel: &str,
) -> Result<Option<GenericLink>> {
    Ok(sqlx::query_as("SELECT link_id,source_id,target_id,relationship,note,created_at,actor FROM kernel_generic_links WHERE source_id=? AND target_id=? AND relationship=? AND active=1")
        .bind(source).bind(target).bind(rel).fetch_optional(conn).await?)
}
async fn refuse_active_collision(conn: &mut SqliteConnection, link: &GenericLink) -> Result<()> {
    if let Some(active) =
        active_triple(conn, &link.source_id, &link.target_id, &link.relationship).await?
    {
        if active.link_id != link.link_id {
            return Err(Error::conflict(format!("link {} conflicts with active link {} for the same source, target and relationship",link.link_id,active.link_id)));
        }
    }
    Ok(())
}
async fn require_endpoints(conn: &mut SqliteConnection, link: &GenericLink) -> Result<()> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM kernel_records WHERE id=? OR id=?")
        .bind(&link.source_id)
        .bind(&link.target_id)
        .fetch_one(conn)
        .await?;
    if count
        != if link.source_id == link.target_id {
            1
        } else {
            2
        }
    {
        return Err(Error::engine(
            "link import requires both source and target records to exist",
        ));
    }
    Ok(())
}
async fn visible(conn: &mut SqliteConnection, principal: &str, record: &str) -> Result<bool> {
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records WHERE id=?)")
        .bind(record)
        .fetch_one(&mut *conn)
        .await?;
    Ok(exists
        && kernel_effective_capability_on(conn, principal, record)
            .await?
            .allows(Capability::View))
}

/// v1 messaging.rs:2331/:2544 write only the caller's own mark links
/// on that Annotation's single live Message bearer, after Message View,
/// without requiring bearer Edit. Ordinary generic
/// link APIs still check record_edit before appending, so gain no exemption.
async fn own_relevance_write(conn: &mut SqliteConnection, event: &EventRow) -> Result<bool> {
    let (target, rel, note) = match event.event_type.as_str() {
        ADDED => {
            let p = added_link(event)?;
            (p.target_id, p.relationship, p.note)
        }
        REMOVED => {
            let p: LinkRemoval = event_payload(event)?;
            let Some(link) = by_id(conn, &p.link_id).await? else {
                return Ok(false);
            };
            if link.source_id != event.record_id {
                return Ok(false);
            }
            (link.target_id, link.relationship, link.note)
        }
        _ => return Ok(false),
    };
    if rel != "resolves" || note.as_deref() != Some("no_longer_relevant") {
        return Ok(false);
    }
    let actor = event.actor.as_deref().unwrap_or("");
    let owns:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records r JOIN kernel_message_people p ON p.principal_id=r.owner_id WHERE r.id=? AND r.owner_id=? AND r.pin_family='native.v1.record' AND r.pin_version=1 AND EXISTS(SELECT 1 FROM kernel_record_fields WHERE record_id=r.id AND name='v1_type' AND value_json='\"Annotation\"') AND EXISTS(SELECT 1 FROM kernel_record_fields WHERE record_id=r.id AND name='v1_kind' AND value_json='\"no_longer_relevant\"') AND NOT EXISTS(SELECT 1 FROM kernel_lifecycle WHERE record_id=r.id AND archived=1) AND NOT EXISTS(SELECT 1 FROM kernel_import_tombstones WHERE record_id=r.id))")
        .bind(&event.record_id).bind(actor).fetch_one(&mut *conn).await?;
    let bearers = super::comments_v2::bearer_on(conn, &event.record_id).await?;
    Ok(owns
        && bearers.as_slice() == [target.as_str()]
        && super::messaging::is_message(conn, &target).await?
        && visible(conn, actor, &target).await?)
}

pub(crate) async fn admit(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    if !matches!(
        event.event_type.as_str(),
        ADDED | IMPORTED | REMOVED | NOTE | IMPORTED_NOTE | IMPORTED_REMOVED
    ) {
        return Ok(());
    }
    if matches!(
        event.event_type.as_str(),
        IMPORTED | IMPORTED_NOTE | IMPORTED_REMOVED
    ) {
        hq::require_import(conn, event.actor.as_deref().unwrap_or("")).await?;
    } else {
        if !own_relevance_write(conn, event).await? {
            hq::record_edit(
                conn,
                event.actor.as_deref().unwrap_or(""),
                &event.record_id,
                None,
            )
            .await?;
        }
        let target = if matches!(event.event_type.as_str(), REMOVED | NOTE) {
            let id = if event.event_type == REMOVED {
                event_payload::<LinkRemoval>(event)?.link_id
            } else {
                event_payload::<LinkNote>(event)?.link_id
            };
            sqlx::query_scalar("SELECT target_id FROM kernel_generic_links WHERE link_id=? AND source_id=? AND active=1")
                .bind(id).bind(&event.record_id).fetch_optional(&mut *conn).await?
                .ok_or_else(|| Error::engine(HIDDEN_OR_MISSING))?
        } else {
            added_link(event)?.target_id
        };
        if !visible(conn, event.actor.as_deref().unwrap_or(""), &target).await? {
            return Err(Error::engine(HIDDEN_OR_MISSING));
        }
    }
    Ok(())
}

pub(crate) async fn project(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    // The persisted sequence and act exist here. Rejection still rolls back
    // the caller's whole append transaction, and replay proves the same seal.
    if matches!(event.event_type.as_str(), ADDED | REMOVED | NOTE)
        && super::messaging::is_message(conn, &event.record_id).await?
    {
        let creation: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.content_events WHERE record_id=? AND type='kernel.message_created.v1' AND actor=? AND act=? AND seq<?)")
            .bind(&event.record_id).bind(&event.actor).bind(event.act).bind(event.local_seq).fetch_one(&mut *conn).await?;
        if !creation {
            let same_act: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.content_events WHERE record_id=? AND type='kernel.message_state.v1' AND actor=? AND act=? AND seq<?)")
                .bind(&event.record_id).bind(&event.actor).bind(event.act).bind(event.local_seq).fetch_one(&mut *conn).await?;
            let (target, relationship) = if event.event_type == ADDED {
                let link = added_link(event)?;
                (link.target_id, link.relationship)
            } else if event.event_type == REMOVED {
                let removed: LinkRemoval = event_payload(event)?;
                let link = by_id(conn, &removed.link_id)
                    .await?
                    .ok_or_else(|| Error::engine(HIDDEN_OR_MISSING))?;
                (link.target_id, link.relationship)
            } else {
                return Err(Error::engine("sealed Message link notes cannot change"));
            };
            let state = super::messaging::on(conn, &event.record_id)
                .await?
                .ok_or_else(|| Error::engine(HIDDEN_OR_MISSING))?;
            if !same_act
                || relationship != "participates_in"
                || state.conversations.contains(&target) != (event.event_type == ADDED)
            {
                return Err(Error::engine(
                    "sealed Message links require the messaging operation",
                ));
            }
        }
    }
    if matches!(event.event_type.as_str(), NOTE | IMPORTED_NOTE) {
        let p: LinkNote = event_payload(event)?;
        if event.event_type == IMPORTED_NOTE {
            hq::require_import(conn, event.actor.as_deref().unwrap_or("")).await?;
        }
        let existing = by_id(conn, &p.link_id)
            .await?
            .ok_or_else(|| Error::conflict("link is absent"))?;
        if existing.source_id != event.record_id {
            return Err(Error::engine("link source mismatch"));
        }
        crate::surface_binding::refuse_reserved_surface_binding(
            "generic links",
            &existing.relationship,
        )?;
        let allowed: bool = sqlx::query_scalar("SELECT CASE WHEN ? THEN imported=1 ELSE active=1 END FROM kernel_generic_links WHERE link_id=?")
            .bind(event.event_type == IMPORTED_NOTE).bind(&p.link_id).fetch_one(&mut *conn).await?;
        if !allowed {
            return Err(Error::conflict(
                "link note update requires an active link or its sealed import identity",
            ));
        }
        sqlx::query("UPDATE kernel_generic_links SET note=?,event_seq=? WHERE link_id=?")
            .bind(p.note)
            .bind(event.local_seq)
            .bind(p.link_id)
            .execute(conn)
            .await?;
        return Ok(());
    }
    if matches!(event.event_type.as_str(), REMOVED | IMPORTED_REMOVED) {
        let id = if event.event_type == IMPORTED_REMOVED {
            hq::require_import(conn, event.actor.as_deref().unwrap_or_default()).await?;
            let p: ImportedLinkRemoval = event_payload(event)?;
            let imported: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM kernel_generic_links WHERE link_id=? AND imported=1)",
            )
            .bind(&p.link_id)
            .fetch_one(&mut *conn)
            .await?;
            if !imported {
                return Err(Error::engine("link removal requires imported identity"));
            }
            p.link_id
        } else {
            event_payload::<LinkRemoval>(event)?.link_id
        };
        if let Some(link) = by_id(conn, &id).await? {
            crate::surface_binding::refuse_reserved_surface_binding(
                "generic links",
                &link.relationship,
            )?;
        }
        let result = sqlx::query("UPDATE kernel_generic_links SET active=0,event_seq=? WHERE link_id=? AND source_id=? AND active=1")
            .bind(event.local_seq).bind(id).bind(&event.record_id).execute(conn).await?;
        if result.rows_affected() != 1 {
            return Err(Error::conflict("link is absent"));
        }
        return Ok(());
    }
    let p: GenericLink = if event.event_type == ADDED {
        added_link(event)?
    } else {
        event_payload(event)?
    };
    validate(&p, &event.record_id)?;
    if matches!(
        event.event_type.as_str(),
        IMPORTED | IMPORTED_NOTE | IMPORTED_REMOVED
    ) {
        hq::require_import(conn, event.actor.as_deref().unwrap_or("")).await?;
        if p.actor.as_deref().is_some_and(|a| !a.starts_with("v1:")) {
            return Err(Error::engine("import actor requires v1: namespace"));
        }
    }
    require_endpoints(conn, &p).await?;
    refuse_active_collision(conn, &p).await?;
    let existing: Option<GenericLink> = sqlx::query_as("SELECT link_id,source_id,target_id,relationship,note,created_at,actor FROM kernel_generic_links WHERE link_id=?")
        .bind(&p.link_id).fetch_optional(&mut *conn).await?;
    if let Some(existing) = existing {
        // v1 messaging.rs:2407 reasserts an owner's live relevance link under
        // a new command key. Keep its original creation time/identity, but
        // record the latest assertion's sequence and visible history. Its
        // actor remains on that event; the link's creation provenance stays.
        // Every other repeated link id remains a conflict.
        let own_mark: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records r WHERE r.id=? AND r.owner_id=? AND r.pin_family='native.v1.record' AND r.pin_version=1 AND EXISTS(SELECT 1 FROM kernel_record_fields WHERE record_id=r.id AND name='v1_type' AND value_json='\"Annotation\"') AND EXISTS(SELECT 1 FROM kernel_record_fields WHERE record_id=r.id AND name='v1_kind' AND value_json='\"no_longer_relevant\"'))")
            .bind(&p.source_id).bind(&event.actor).fetch_one(&mut *conn).await?;
        let active: bool =
            sqlx::query_scalar("SELECT active FROM kernel_generic_links WHERE link_id=?")
                .bind(&p.link_id)
                .fetch_one(&mut *conn)
                .await?;
        if event.event_type != ADDED
            || !own_mark
            || !active
            || p.source_id != existing.source_id
            || p.target_id != existing.target_id
            || p.relationship != "resolves"
            || existing.relationship != p.relationship
            || p.note.as_deref() != Some("no_longer_relevant")
            || existing.note != p.note
        {
            return Err(Error::conflict("link id already used"));
        }
        sqlx::query("UPDATE kernel_generic_links SET event_seq=? WHERE link_id=?")
            .bind(event.local_seq)
            .bind(&p.link_id)
            .execute(conn)
            .await?;
        return Ok(());
    }
    // Native creation completes the Annotation's bearer last. Evaluate again
    // at that point, when recipient-relative evidence visibility is valid.
    let completes_mark = p.relationship == "part_of"
        && super::messaging::own_relevance_marks_on(
            conn,
            event.actor.as_deref().unwrap_or(""),
            &p.target_id,
        )
        .await?
        .iter()
        .any(|(id, _)| id == &p.source_id);
    let relevance_target = ((p.relationship == "resolves"
        && p.note.as_deref() == Some("no_longer_relevant"))
        || completes_mark)
        .then(|| p.target_id.clone());
    sqlx::query("INSERT INTO kernel_generic_links(link_id,source_id,target_id,relationship,note,created_at,actor,active,event_seq,imported) VALUES(?,?,?,?,?,?,?,1,?,?)")
        .bind(p.link_id).bind(p.source_id).bind(p.target_id).bind(p.relationship).bind(p.note)
        .bind(p.created_at).bind(p.actor).bind(event.local_seq).bind(event.event_type == IMPORTED).execute(&mut *conn).await?;
    if let Some(message) = relevance_target {
        super::notifications::relevance_on(conn, event, &message).await?;
    }
    Ok(())
}

/// Upsert an active triple, retaining its identity and creation provenance.
/// A changed note records a separate event; an identical request is unchanged.
/// Re-adding a removed relationship creates a new identity; the old identity and its removal stay in history. Like facets and
/// S1 unlink, source-anchored events advance only the source record revision.
pub async fn add_generic_link_as(
    db: &Db,
    principal: &str,
    source: &str,
    target: &str,
    relationship: &str,
    note: Option<String>,
) -> Result<GenericLinkWrite> {
    let mut tx = begin_write(db.write_pool()).await?;
    let result = add_generic_link_in(
        db,
        &mut tx,
        &mut crate::act::ActAllocation::new(),
        principal,
        source,
        target,
        relationship,
        note,
    )
    .await?;
    tx.commit().await?;
    Ok(result)
}

/// Compose an ordinary link write with its caller's atomic receipt.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn add_generic_link_in(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    acts: &mut crate::act::ActAllocation,
    principal: &str,
    source: &str,
    target: &str,
    relationship: &str,
    note: Option<String>,
) -> Result<GenericLinkWrite> {
    hq::record_edit(tx, principal, source, None).await?;
    if !visible(tx, principal, target).await? {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    }
    crate::surface_binding::refuse_reserved_surface_binding("generic links", relationship)?;
    if let Some(mut link) = active_triple(tx, source, target, relationship).await? {
        let outcome = if link.note == note {
            GenericLinkOutcome::Unchanged
        } else {
            append_note(db, tx, acts, principal, &link, note.clone(), false).await?;
            link.note = note;
            GenericLinkOutcome::Updated
        };
        return Ok(GenericLinkWrite { link, outcome });
    }
    // Creation provenance comes from the admitted event envelope.
    let creation = LinkCreation {
        link_id: Uuid::new_v4().to_string(),
        source_id: source.into(),
        target_id: target.into(),
        relationship: relationship.into(),
        note,
    };
    let event = append_in(
        db,
        tx,
        AppendSpec {
            record_id: source.into(),
            event_type: ADDED.into(),
            payload: serde_json::to_value(creation)?,
            actor: Some(principal.into()),
        },
        acts,
    )
    .await?;
    let link = added_link(&event)?;
    Ok(GenericLinkWrite {
        link,
        outcome: GenericLinkOutcome::Created,
    })
}

pub async fn remove_generic_link_as(
    db: &Db,
    principal: &str,
    source: &str,
    link_id: &str,
) -> Result<()> {
    let mut tx = begin_write(db.write_pool()).await?;
    // The explicit relevance executor owns the View-only exception. This
    // ordinary API keeps its original source Edit admission.
    hq::record_edit(&mut tx, principal, source, None).await?;
    let mut acts = crate::act::ActAllocation::new();
    append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: source.into(),
            event_type: REMOVED.into(),
            payload: serde_json::to_value(LinkRemoval {
                link_id: link_id.into(),
            })?,
            actor: Some(principal.into()),
        },
        &mut acts,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// V1 removal addresses the active triple; removed identities stay historical.
pub async fn remove_generic_link_triple_as(
    db: &Db,
    principal: &str,
    source: &str,
    target: &str,
    relationship: &str,
) -> Result<()> {
    let mut tx = begin_write(db.write_pool()).await?;
    remove_generic_link_triple_in(
        db,
        &mut tx,
        &mut crate::act::ActAllocation::new(),
        principal,
        source,
        target,
        relationship,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn remove_generic_link_triple_in(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    acts: &mut crate::act::ActAllocation,
    principal: &str,
    source: &str,
    target: &str,
    relationship: &str,
) -> Result<()> {
    hq::record_edit(tx, principal, source, None).await?;
    if !visible(tx, principal, target).await? {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    }
    crate::surface_binding::refuse_reserved_surface_binding("generic links", relationship)?;
    let link = active_triple(tx, source, target, relationship)
        .await?
        .ok_or_else(|| Error::conflict("link is absent"))?;
    append_in(
        db,
        tx,
        AppendSpec {
            record_id: source.into(),
            event_type: REMOVED.into(),
            payload: serde_json::to_value(LinkRemoval {
                link_id: link.link_id,
            })?,
            actor: Some(principal.into()),
        },
        acts,
    )
    .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn append_note(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    acts: &mut crate::act::ActAllocation,
    principal: &str,
    link: &GenericLink,
    note: Option<String>,
    imported: bool,
) -> Result<()> {
    append_in(
        db,
        tx,
        AppendSpec {
            record_id: link.source_id.clone(),
            event_type: if imported { IMPORTED_NOTE } else { NOTE }.into(),
            payload: serde_json::to_value(LinkNote {
                link_id: link.link_id.clone(),
                note,
            })?,
            actor: Some(principal.into()),
        },
        acts,
    )
    .await?;
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportedLinkRemoval {
    link_id: String,
    evidence: ImportRemovalEvidence,
}

/// Host-only removal does not borrow ordinary Edit. Identity, provenance and
/// the tombstone stay in the generic lane; native links cannot be removed.
pub async fn import_generic_link_removal_as(
    db: &Db,
    principal: &str,
    id: &str,
    evidence: &ImportRemovalEvidence,
) -> Result<GenericLinkOutcome> {
    let mut tx = begin_write(db.write_pool()).await?;
    hq::require_import(&mut tx, principal).await?;
    hq::require_source_import_open(&mut tx).await?;
    let row: Option<(String, bool, bool)> = sqlx::query_as(
        "SELECT source_id,active,imported FROM kernel_generic_links WHERE link_id=?",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((source, active, true)) = row else {
        return Err(Error::conflict("link removal requires imported identity"));
    };
    if !active {
        return Ok(GenericLinkOutcome::Unchanged);
    }
    append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: source,
            event_type: IMPORTED_REMOVED.into(),
            payload: serde_json::to_value(ImportedLinkRemoval {
                link_id: id.into(),
                evidence: evidence.clone(),
            })?,
            actor: Some(principal.into()),
        },
        &mut crate::act::ActAllocation::new(),
    )
    .await?;
    tx.commit().await?;
    Ok(GenericLinkOutcome::Updated)
}

/// Sealed import of an original v1 link. Input actor is raw v1 attribution;
/// stored actor is prefixed with `v1:`. A retry checks immutable creation
/// content even after removal and never resurrects a removed link.
pub async fn import_generic_link_as(
    db: &Db,
    principal: &str,
    original: &GenericLink,
) -> Result<GenericLinkOutcome> {
    let mut tx = begin_write(db.write_pool()).await?;
    hq::require_import(&mut tx, principal).await?;
    hq::require_source_import_open(&mut tx).await?;
    let mut link = original.clone();
    link.actor = link.actor.map(|a| format!("v1:{a}"));
    // Validate even retries, before querying or mutating projected state.
    validate(&link, &link.source_id)?;
    require_endpoints(&mut tx, &link).await?;
    let payload = serde_json::to_value(&link)?;
    let prior: Option<GenericLink> = sqlx::query_as("SELECT link_id,source_id,target_id,relationship,note,created_at,actor FROM kernel_generic_links WHERE link_id=?")
        .bind(&link.link_id).fetch_optional(&mut *tx).await?;
    if let Some(mut prior) = prior {
        let imported: bool =
            sqlx::query_scalar("SELECT imported FROM kernel_generic_links WHERE link_id=?")
                .bind(&link.link_id)
                .fetch_one(&mut *tx)
                .await?;
        // An identical retry remains a no-op even after a new active identity
        // has replaced this imported link. Never reactivate the tombstone.
        if imported && prior == link {
            return Ok(GenericLinkOutcome::Unchanged);
        }
        refuse_active_collision(&mut tx, &link).await?;
        prior.note = link.note.clone();
        if imported && prior == link {
            append_note(
                db,
                &mut tx,
                &mut crate::act::ActAllocation::new(),
                principal,
                &link,
                link.note.clone(),
                true,
            )
            .await?;
            tx.commit().await?;
            return Ok(GenericLinkOutcome::Updated);
        }
        return Err(Error::conflict("link import content differs"));
    }
    refuse_active_collision(&mut tx, &link).await?;
    let mut acts = crate::act::ActAllocation::new();
    append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: link.source_id.clone(),
            event_type: IMPORTED.into(),
            payload,
            actor: Some(principal.into()),
        },
        &mut acts,
    )
    .await?;
    tx.commit().await?;
    Ok(GenericLinkOutcome::Created)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenericLinkPage {
    pub links: Vec<GenericLink>,
    pub next: Option<String>,
}

/// Keyset pagination by stable link id, in either direction. A cursor is
/// returned only when another visible hit exists. Hidden and missing anchors
/// both yield an empty page. Candidate windows hold at most 201 rows.
#[allow(clippy::too_many_arguments)]
pub async fn generic_links_as(
    db: &Db,
    principal: &str,
    record: &str,
    incoming: bool,
    relationship: Option<&str>,
    after: Option<&str>,
    limit: usize,
) -> Result<GenericLinkPage> {
    if !(1..=200).contains(&limit) {
        return Err(Error::engine("link page limit must be 1..=200"));
    }
    let mut tx = db.write_pool().begin().await?;
    let mut page = GenericLinkPage {
        links: Vec::new(),
        next: None,
    };
    if !visible(&mut tx, principal, record).await? {
        return Ok(page);
    }
    let column = if incoming { "target_id" } else { "source_id" };
    let mut cursor = after.unwrap_or("").to_string();
    loop {
        let mut sql = format!("SELECT link_id,source_id,target_id,relationship,note,created_at,actor FROM kernel_generic_links WHERE {column}=? AND active=1 AND link_id>?");
        if relationship.is_some() {
            sql.push_str(" AND relationship=?");
        }
        sql.push_str(" ORDER BY link_id LIMIT ?");
        let mut query = sqlx::query_as::<_, GenericLink>(&sql)
            .bind(record)
            .bind(&cursor);
        if let Some(rel) = relationship {
            query = query.bind(rel);
        }
        let fetch = limit + 1 - page.links.len();
        let rows = query.bind(fetch as i64).fetch_all(&mut *tx).await?;
        let exhausted = rows.len() < fetch;
        for link in rows {
            cursor = link.link_id.clone();
            let other = if incoming {
                &link.source_id
            } else {
                &link.target_id
            };
            if visible(&mut tx, principal, other).await? {
                if page.links.len() == limit {
                    page.next = page.links.last().map(|l| l.link_id.clone());
                    return Ok(page);
                }
                page.links.push(link);
            }
        }
        if exhausted {
            return Ok(page);
        }
    }
}

#[cfg(test)]
#[path = "generic_links_tests.rs"]
mod tests;

/// History uses tombstones too, so hiding an endpoint also hides old link acts.
pub(crate) async fn history_visible(
    conn: &mut SqliteConnection,
    principal: &str,
    seq: i64,
) -> Result<bool> {
    let payload: String = sqlx::query_scalar("SELECT payload FROM main.content_events WHERE seq=?")
        .bind(seq)
        .fetch_one(&mut *conn)
        .await?;
    let payload: serde_json::Value = serde_json::from_str(&payload)?;
    let id = payload["link_id"].as_str().unwrap_or("");
    let endpoints: Option<(String, String)> =
        sqlx::query_as("SELECT source_id,target_id FROM kernel_generic_links WHERE link_id=?")
            .bind(id)
            .fetch_optional(&mut *conn)
            .await?;
    if let Some((source, target)) = endpoints {
        return Ok(
            visible(conn, principal, &source).await? && visible(conn, principal, &target).await?
        );
    }
    Ok(false)
}

// Both branches expose equality lookups to the planner. Optional indexes
// improve cost but are not prerequisites for reads on older registry-opened
// databases. Keep the self-link only in the source branch.
const ANCHORED_GENERIC_LINKS: &str = "SELECT * FROM kernel_generic_links WHERE source_id=?3 AND active=1 UNION ALL SELECT * FROM kernel_generic_links WHERE target_id=?3 AND source_id<>?3 AND active=1";
/// Record ids the caller may View: home-policy view, the record-owner
/// floor for ordinary records, and the terminal bearer's floor for
/// derived artifacts (whose own owner never confers visibility). `?1` is the homes
/// JSON, `?2` the principal; both are reused by the comment legs, so call
/// sites keep their binds.
fn visible_cte() -> String {
    let homes = "SELECT id,view FROM _kernel_link_homes";
    format!(
        "WITH _kernel_link_homes AS MATERIALIZED (SELECT json_extract(value,'$.id') AS id,json_extract(value,'$.view') AS view FROM json_each(?1)), visible AS NOT MATERIALIZED (SELECT r.id FROM kernel_records r WHERE {}) ",
        super::sql_record_visible("r", "?2", homes, true)
    )
}

fn visible_generic_links_sql() -> String {
    format!("{} SELECT l.link_id,l.source_id,l.target_id,l.relationship,l.note,l.created_at,l.actor FROM ({ANCHORED_GENERIC_LINKS}) l JOIN visible s ON s.id=l.source_id JOIN visible t ON t.id=l.target_id", visible_cte())
}

pub(crate) const LEGACY_TARGET_INDEX: &str = "CREATE INDEX IF NOT EXISTS idx_kernel_links_target ON kernel_links(target_id,source_id,relationship)";
pub(crate) const PROVIDER_AGGREGATE_INDEX: &str = "CREATE INDEX IF NOT EXISTS idx_kernel_provider_subjects_aggregate ON kernel_provider_subjects(aggregate_id,subject_id)";

/// Upgrade existing probe databases without changing their recorded history.
pub async fn ensure_link_read_indexes(db: &Db) -> Result<()> {
    let mut tx = begin_write(db.write_pool()).await?;
    for ddl in [LEGACY_TARGET_INDEX, PROVIDER_AGGREGATE_INDEX] {
        sqlx::query(ddl).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Ordinary MCP link projection. Record endpoints share one visibility snapshot;
/// principal targets retain the legacy source-only visibility rule.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn visible_link_rows_as(
    db: &Db,
    principal: &str,
    anchor: &str,
) -> Result<Vec<serde_json::Value>> {
    let mut tx = db.write_pool().begin().await?;
    visible_link_rows_for_on(&mut tx, principal, &[anchor.to_owned()]).await
}

/// Batch the subject seeks, preserving the same endpoint visibility oracle.
/// No result is cached outside the caller's read snapshot.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn visible_link_rows_for_on(
    tx: &mut SqliteConnection,
    principal: &str,
    anchors: &[String],
) -> Result<Vec<serde_json::Value>> {
    app_installs::admit_dispatched_on(tx, principal).await?;
    super::provider_link_reads::require_ready_on(tx).await?;
    let scope = visible_home_anchors_as(tx, principal).await?;
    let homes: Vec<_> = scope
        .homes
        .into_iter()
        .filter(|h| h.policy_valid)
        .map(|h| serde_json::json!({"id":h.home_id,"view":h.policy_view}))
        .collect();
    let homes = serde_json::to_string(&homes)?;
    let anchors = serde_json::to_string(anchors)?;
    let cte = visible_cte();
    let sql = visible_generic_links_sql()
        .replace(
            "source_id<>?3",
            "source_id NOT IN (SELECT value FROM json_each(?3))",
        )
        .replace(
            "source_id=?3",
            "source_id IN (SELECT value FROM json_each(?3))",
        )
        .replace(
            "target_id=?3",
            "target_id IN (SELECT value FROM json_each(?3))",
        );
    let links: Vec<GenericLink> = sqlx::query_as(&sql)
        .bind(&homes)
        .bind(principal)
        .bind(&anchors)
        .fetch_all(&mut *tx)
        .await?;
    let mut rows: Vec<_> = links.into_iter().map(|l| serde_json::json!({"id":l.link_id,"source_id":l.source_id,"target_id":l.target_id,"relationship":l.relationship,"note":l.note,"created_at":l.created_at})).collect();
    // Principal targets are not policy-bearing. Record targets still need View.
    let sql = format!("{cte} SELECT l.source_id,l.target_id,l.relationship,e.created_at FROM (SELECT * FROM kernel_links WHERE source_id IN (SELECT value FROM json_each(?3)) UNION ALL SELECT * FROM kernel_links WHERE target_id IN (SELECT value FROM json_each(?3)) AND source_id NOT IN (SELECT value FROM json_each(?3))) l JOIN visible s ON s.id=l.source_id LEFT JOIN visible t ON t.id=l.target_id LEFT JOIN kernel_principals p ON p.principal_id=l.target_id JOIN main.content_events e INDEXED BY idx_kernel_event_birth ON e.seq=l.created_seq WHERE t.id IS NOT NULL OR p.principal_id IS NOT NULL");
    let legacy: Vec<(String, String, String, String)> = sqlx::query_as(&sql)
        .bind(&homes)
        .bind(principal)
        .bind(&anchors)
        .fetch_all(&mut *tx)
        .await?;
    for (source, target, rel, created) in legacy {
        rows.push(serde_json::json!({"id":null,"source_id":source,"target_id":target,"relationship":rel,"note":null,"created_at":created}));
    }
    // Start from the subject index, not every provider state. The reverse
    // subject index bounds the all-endpoints visibility check per aggregate.

    let sql = format!("{cte} SELECT p.left_id,p.right_id FROM kernel_provider_link_heads p WHERE p.active=1 AND p.aggregate_id IN (SELECT aggregate_id FROM kernel_provider_subjects WHERE subject_id IN (SELECT value FROM json_each(?3))) AND NOT EXISTS(SELECT 1 FROM kernel_provider_subjects s WHERE s.aggregate_id=p.aggregate_id AND NOT EXISTS(SELECT 1 FROM visible v WHERE v.id=s.subject_id))");
    let pairs: Vec<(String, String)> = sqlx::query_as(&sql)
        .bind(&homes)
        .bind(principal)
        .bind(&anchors)
        .fetch_all(&mut *tx)
        .await?;
    for (left, right) in pairs {
        for (source, target) in [(&left, &right), (&right, &left)] {
            rows.push(serde_json::json!({"id":null,"source_id":source,"target_id":target,"relationship":"relates_to","note":null,"created_at":null}));
        }
    }
    // Prefer the generic identity/note/provenance when an older declared lane
    // carries the same triple. This does not migrate or mutate the older row.
    let mut seen = std::collections::BTreeSet::new();
    rows.retain(|l| {
        seen.insert((
            l["source_id"].as_str().unwrap().to_owned(),
            l["target_id"].as_str().unwrap().to_owned(),
            l["relationship"].as_str().unwrap().to_owned(),
        ))
    });
    rows.sort_by_key(|l| {
        (
            l["relationship"].as_str().unwrap_or("").to_owned(),
            l["created_at"].as_str().unwrap_or("").to_owned(),
            l["id"].as_str().unwrap_or("").to_owned(),
            l["source_id"].as_str().unwrap_or("").to_owned(),
            l["target_id"].as_str().unwrap_or("").to_owned(),
        )
    });
    Ok(rows)
}
