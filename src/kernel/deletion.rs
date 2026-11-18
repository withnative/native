//! Native soft deletion: preserve records, links, children and bytes; freeze
//! the subject through the kernel's existing tombstone/derived visibility gate.
use super::*;

pub(crate) const EVENT: &str = "kernel.record_deleted.v1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Deleted {
    pub reason: String,
    pub previous_seq: i64,
}

/// Runtime and event admission share the v1 Manage/CAS/source guards.
/// The generic `delete_record` executor calls this entry point, so its
/// rule stays Manage on the record itself for every type, Messages
/// included. Event admission (`admit` below) additionally accepts, for
/// a Message tombstone only, Manage on the Message's origin Collection:
/// that is the `manage_messages.delete` moderation route, whose own
/// gate has already required View on the Message and either authorship
/// or that same channel Manage.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn validate_on(
    conn: &mut SqliteConnection,
    actor: &str,
    id: &str,
    expected: Option<i64>,
    before: i64,
) -> Result<i64> {
    validate_inner(conn, actor, id, expected, before, false).await
}

async fn validate_inner(
    conn: &mut SqliteConnection,
    actor: &str,
    id: &str,
    expected: Option<i64>,
    before: i64,
    allow_origin_channel_manage: bool,
) -> Result<i64> {
    let record: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records WHERE id=?)")
        .bind(id)
        .fetch_one(&mut *conn)
        .await?;
    if !record {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    }
    if !manages_subject_or_origin_channel(conn, actor, id, allow_origin_channel_manage).await? {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    }
    let head: Option<i64> =
        sqlx::query_scalar("SELECT max(seq) FROM content_events WHERE record_id=? AND seq<?")
            .bind(id)
            .bind(before)
            .fetch_one(&mut *conn)
            .await?;
    let head = head.ok_or_else(|| Error::engine(HIDDEN_OR_MISSING))?;
    if expected.is_some_and(|expected| expected != head) {
        return Err(Error::engine(
            "delete_record: content revision conflict; get the record and retry with its current revision",
        ));
    }
    // Like v1, retired personas are still registered identities.
    if messaging::persona_on(conn, id).await?.is_some() {
        return Err(Error::engine(
            "delete_record: registered persona identity is owner-locked; retire it instead",
        ));
    }
    let bound: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_instruction_bindings WHERE source_record_id=? AND enabled=1)")
        .bind(id).fetch_one(&mut *conn).await?;
    let sources = v1_state::rows_on(conn, "onboarding_programme_sources").await?;
    let programmes = v1_state::rows_on(conn, "onboarding_programmes").await?;
    let active_programme = sources
        .iter()
        .filter(|s| s["source_record_id"] == id)
        .any(|source| {
            programmes.iter().any(|p| {
                p["id"] == source["programme_id"] && (p["enabled"] == true || p["enabled"] == 1)
            })
        });
    if bound || active_programme {
        // Do not echo IDs of binding/programme records the caller cannot View.
        return Err(Error::engine(format!("delete_record: record {id} is an active instruction source; disable or remove its bindings/programme sources before deleting it")));
    }
    let imported: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE record_id=? AND type='kernel.import_state.v1' AND seq<?)")
        .bind(id).bind(before).fetch_one(&mut *conn).await?;
    if imported {
        let guard: Option<String> = sqlx::query_scalar("SELECT payload FROM kernel_v1_state WHERE section='record_deletion_guards' AND source_id=? AND record_id=?")
            .bind(id).bind(id).fetch_optional(&mut *conn).await?;
        let guard: Option<serde_json::Value> =
            guard.map(|g| serde_json::from_str(&g)).transpose()?;
        let guard = guard.ok_or_else(|| Error::engine("delete_record: imported deletion guard unavailable; refresh source evidence before cutover"))?;
        let body = guard["active_body_binding"].as_bool();
        let role = guard["active_artifact_role"].as_bool();
        if body.is_none() || role.is_none() || guard["record_id"] != id {
            return Err(Error::engine("delete_record: imported deletion guard unavailable; refresh source evidence before cutover"));
        }
        if body == Some(true) {
            return Err(Error::engine("record cannot be deleted while its derived body binding is active; detach it first"));
        }
        if role == Some(true) {
            return Err(Error::engine("record cannot be deleted while its derivation artifact role is active; retire it first"));
        }
    }
    Ok(head)
}

/// Manage on the subject record, or — only when `allow_origin_channel`
/// and the subject is a Message — View on the Message plus Manage on
/// the Collection declared as its communication origin at send time
/// (`MessageState.origin`, with `native:root` mapped to the kernel
/// root home, exactly as the `manage_messages.delete` gate reads it).
/// The View requirement mirrors the gate's non-disclosure check in
/// admission itself, so no future append route can tombstone a Message
/// its actor cannot see by managing its channel alone. A Conversation
/// the Message was classified into never counts, and a direct Message
/// has no channel. A channel id with no kernel record grants nothing.
async fn manages_subject_or_origin_channel(
    conn: &mut SqliteConnection,
    actor: &str,
    id: &str,
    allow_origin_channel: bool,
) -> Result<bool> {
    let on_subject = kernel_effective_capability_on(conn, actor, id).await?;
    if on_subject.allows(Capability::Manage) {
        return Ok(true);
    }
    if !allow_origin_channel || !on_subject.allows(Capability::View) {
        return Ok(false);
    }
    let Some(state) = messaging::on(conn, id).await? else {
        return Ok(false);
    };
    let channel = (state.origin["type"] == "collection")
        .then(|| state.origin["collection_id"].as_str())
        .flatten();
    let Some(channel) = channel else {
        return Ok(false);
    };
    let channel = if channel == "native:root" {
        KERNEL_ROOT_ID
    } else {
        channel
    };
    match kernel_effective_capability_on(conn, actor, channel).await {
        Ok(capability) => Ok(capability.allows(Capability::Manage)),
        Err(Error::Engine(message)) if message == HIDDEN_OR_MISSING => Ok(false),
        Err(error) => Err(error),
    }
}

pub(crate) async fn admit(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    let p: Deleted = event_payload(event)?;
    if p.reason.trim().is_empty() {
        return Err(Error::engine("delete_record: reason must not be blank"));
    }
    // Admission runs only on append — in production, live append only
    // (the migration seam that also runs admission is `#[cfg(test)]`) —
    // before insert, against projections folded from every earlier
    // event, so the Message state, the channel record and its home
    // policy/owner
    // are all as of this event's position in the log. Replay never calls
    // this: `project` below applies retained tombstones without
    // re-evaluating authority, so widening admission here cannot change
    // what an existing log replays to, and a moderator tombstone stays
    // replayable even if the channel later moves or changes owner.
    validate_inner(
        conn,
        event.actor.as_deref().unwrap_or_default(),
        &event.record_id,
        Some(p.previous_seq),
        if event.local_seq < 0 {
            i64::MAX
        } else {
            event.local_seq
        },
        true,
    )
    .await?;
    Ok(())
}

pub(crate) async fn project(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    // Authority, CAS and instruction-source guards are checked by hq::admit
    // before append. Replay must not consult today's hosted membership roster.
    let p: Deleted = event_payload(event)?;
    if p.reason.trim().is_empty()
        || p.previous_seq < 1
        || p.previous_seq >= event.local_seq
        || event.actor.as_deref().is_none_or(str::is_empty)
    {
        return Err(Error::engine("invalid record deletion event"));
    }
    let live: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records r WHERE r.id=? AND NOT EXISTS(SELECT 1 FROM kernel_import_tombstones t WHERE t.record_id=r.id))")
        .bind(&event.record_id).fetch_one(&mut *conn).await?;
    if !live {
        return Err(Error::engine(
            "record deletion requires an untombstoned record",
        ));
    }
    sqlx::query(
        "INSERT INTO kernel_import_tombstones(record_id,deleted_at,event_seq) VALUES(?,?,?)",
    )
    .bind(&event.record_id)
    .bind(&event.created_at)
    .bind(event.local_seq)
    .execute(&mut *conn)
    .await?;
    messaging::deleted_on(conn, event).await?;
    // Deliberately no cascading SQL: v1's soft tombstone retains the subject's
    // body, facets, links, children, comments and attachment references.
    Ok(())
}
