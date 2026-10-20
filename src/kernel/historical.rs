//! Record-scoped historical reads under live authority. The full-prefix
//! replay below is a test-only oracle; serving paths never construct it.
use super::*;
#[cfg(test)]
use serde_json::Value;

/// Projection-only view: byte content is deliberately unavailable. Keeping the
/// Db private prevents passing this metadata substrate to ordinary blob APIs.
#[cfg(test)]
pub(crate) struct HistoricalProjection(Db);
#[cfg(test)]
impl HistoricalProjection {
    pub(crate) fn pool(&self) -> &sqlx::SqlitePool {
        self.0.pool()
    }
    pub(crate) async fn close(self) {
        self.0.close().await;
    }
}

/// Copy sealed inputs, never current record projections. The retained-v1 lane
/// remains provenance: existing projectors establish imported state only at
/// its actual import snapshot/delta position.
#[cfg(test)]
pub(crate) async fn prefix_on(
    source: &mut SqliteConnection,
    through: i64,
) -> Result<HistoricalProjection> {
    let scratch = open_database(":memory:").await?;
    let result = copy_and_replay(source, &scratch, through).await;
    if let Err(error) = result {
        scratch.close().await;
        return Err(error);
    }
    Ok(HistoricalProjection(scratch))
}

#[cfg(test)]
async fn copy_and_replay(source: &mut SqliteConnection, scratch: &Db, through: i64) -> Result<()> {
    // Sequences belong to separate logs. A workspace act is their shared
    // commit coordinate; later meta-only writes must not enter an older view.
    // Pre-act content has no exact cross-log boundary: fail honestly rather
    // than guessing from timestamps (which can tie or be source-authored).
    let position: Option<Option<i64>> =
        sqlx::query_scalar("SELECT act FROM content_events WHERE seq<=? ORDER BY seq DESC LIMIT 1")
            .bind(through)
            .fetch_optional(&mut *source)
            .await?;
    let meta_act = match position {
        Some(Some(act)) => act,
        None => 0,
        Some(None) => {
            return Err(Error::engine(
                "historical meta position unavailable before workspace act stamping",
            ))
        }
    };
    apply_v2_schema(scratch).await?;
    let mut target = begin_write(scratch.write_pool()).await?;
    // This private replay substrate stores real content handles/metadata, not
    // fabricated empty/NULL bytes. The ordinary database DDL is unchanged.
    // Projectors validate sealed bindings by sha256 + size and rebuild refs;
    // neither history view reads byte content.
    sqlx::query("DROP TABLE kernel_blobs")
        .execute(&mut *target)
        .await?;
    sqlx::query("CREATE TABLE kernel_blobs (sha256 TEXT PRIMARY KEY, size_bytes INTEGER NOT NULL, mime TEXT)")
        .execute(&mut *target).await?;
    for (table, columns, predicate) in [
        ("meta_events", "seq,id,subject_id,type,payload,actor,created_at,act", "?1>0 AND (act<=?1 OR (act IS NULL AND seq<=COALESCE((SELECT last_legacy_seq FROM act_cutover WHERE domain='meta_events'),0)))"),
        ("content_events", "seq,id,record_id,type,payload,actor,run_key,parent_key,intent,causal_envelope_version,causal_status,created_at,act", "seq<=?1"),
        ("content_event_causal_frontier", "event_id,parent_event_id", "event_id IN (SELECT id FROM content_events WHERE seq<=?1)"),
    ] {
        let projection = columns.split(',').enumerate().map(|(i,_)|format!("json_extract(value,'$[{i}]')")).collect::<Vec<_>>().join(",");
        let order = if table == "content_event_causal_frontier" { "event_id,parent_event_id" } else { "seq" };
        let bound = if table == "meta_events" { meta_act } else { through };
        let mut offset = 0;
        loop {
            let rows:Vec<String>=sqlx::query_scalar(&format!("SELECT json_array({columns}) FROM {table} WHERE {predicate} ORDER BY {order} LIMIT 256 OFFSET ?2"))
                .bind(bound).bind(offset).fetch_all(&mut *source).await?;
            if rows.is_empty() {break;}
            let values:Vec<Value>=rows.iter().map(|raw|serde_json::from_str(raw)).collect::<std::result::Result<_,_>>()?;
            sqlx::query(&format!("INSERT INTO {table}({columns}) SELECT {projection} FROM json_each(?)"))
                .bind(serde_json::to_string(&values)?).execute(&mut *target).await?;
            offset += rows.len() as i64;
        }
    }
    // Only metadata actually referenced by this prefix; never SELECT bytes.
    let blobs: Vec<(String, i64, Option<String>)> = sqlx::query_as(
        "SELECT b.sha256,b.size_bytes,b.mime FROM kernel_blobs b WHERE b.sha256 IN (SELECT json_extract(payload,'$.sha256') FROM content_events WHERE seq<=? AND type='kernel.attachment_bound.v1') ORDER BY b.sha256",
    ).bind(through).fetch_all(&mut *source).await?;
    for (hash, size, mime) in blobs {
        sqlx::query("INSERT INTO kernel_blobs VALUES(?,?,?)")
            .bind(hash)
            .bind(size)
            .bind(mime)
            .execute(&mut *target)
            .await?;
    }
    target.commit().await?;
    replay_all_projections(scratch).await
}

/// Advance one native body event through the ordinary projector. Context reads
/// the seq-1 state once, then applies this event instead of replaying a second
/// full prefix. This is projection replay, not a separate body reducer.
#[cfg(test)]
pub(crate) async fn advance_body_on(
    source: &mut SqliteConnection,
    scratch: &HistoricalProjection,
    seq: i64,
) -> Result<()> {
    let row = sqlx::query("SELECT *, (SELECT json_group_array(parent_event_id) FROM content_event_causal_frontier WHERE event_id=content_events.id) AS causal_frontier FROM content_events WHERE seq=?")
        .bind(seq).fetch_one(&mut *source).await?;
    let event = crate::query::events::event_from_row(&row)?;
    if !matches!(
        event.event_type.as_str(),
        "kernel.record_created.v1"
            | "kernel.record_created.v2"
            | "kernel.record_revised.v1"
            | "kernel.record_revised.v2"
            | "kernel.import_record_created.v1"
            | "kernel.body_set.v1"
            | "kernel.import_state.v1"
            | "kernel.import_state_delta.v1"
    ) {
        return Err(Error::engine(
            "historical advance requires a native body event",
        ));
    }
    let act = event.act.ok_or_else(|| {
        Error::engine("historical meta position unavailable before workspace act stamping")
    })?;
    let mut target = begin_write(scratch.0.write_pool()).await?;
    let previous: i64 = sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM content_events")
        .fetch_one(&mut *target)
        .await?;
    let contiguous: bool = sqlx::query_scalar(
        "SELECT ?1>?2 AND NOT EXISTS(SELECT 1 FROM content_events WHERE seq>?2 AND seq<?1)",
    )
    .bind(seq)
    .bind(previous)
    .fetch_one(&mut *source)
    .await?;
    if !contiguous {
        return Err(Error::engine(
            "historical advance is not the next content event",
        ));
    }
    let meta_head: i64 = sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM meta_events")
        .fetch_one(&mut *target)
        .await?;
    #[allow(clippy::type_complexity)]
    let meta: Vec<(i64,String,String,String,Option<String>,Option<String>,String,i64)> = sqlx::query_as(
        "SELECT seq,id,subject_id,type,payload,actor,created_at,act FROM meta_events WHERE seq>? AND act<=? ORDER BY seq",
    ).bind(meta_head).bind(act).fetch_all(&mut *source).await?;
    let mut replay = Vec::with_capacity(meta.len());
    for (seq, id, subject_id, event_type, payload, actor, created_at, act) in meta {
        sqlx::query("INSERT INTO meta_events(seq,id,subject_id,type,payload,actor,created_at,act) VALUES(?,?,?,?,?,?,?,?)")
            .bind(seq).bind(&id).bind(&subject_id).bind(&event_type).bind(&payload)
            .bind(&actor).bind(&created_at).bind(act).execute(&mut *target).await?;
        replay.push(MetaEventRow {
            seq,
            id,
            subject_id,
            event_type,
            payload,
            actor,
            created_at,
        });
    }
    crate::projector::meta::replay_meta(&mut target, &replay).await?;
    let columns = "seq,id,record_id,type,payload,actor,run_key,parent_key,intent,causal_envelope_version,causal_status,created_at,act";
    let raw: String = sqlx::query_scalar(&format!(
        "SELECT json_array({columns}) FROM content_events WHERE seq=?"
    ))
    .bind(seq)
    .fetch_one(&mut *source)
    .await?;
    let projection = columns
        .split(',')
        .enumerate()
        .map(|(i, _)| format!("json_extract(value,'$[{i}]')"))
        .collect::<Vec<_>>()
        .join(",");
    sqlx::query(&format!(
        "INSERT INTO content_events({columns}) SELECT {projection} FROM json_each(?)"
    ))
    .bind(format!("[{raw}]"))
    .execute(&mut *target)
    .await?;
    let parents: Vec<String> = sqlx::query_scalar(
        "SELECT parent_event_id FROM content_event_causal_frontier WHERE event_id=?",
    )
    .bind(&event.id)
    .fetch_all(&mut *source)
    .await?;
    for parent in parents {
        sqlx::query(
            "INSERT INTO content_event_causal_frontier(event_id,parent_event_id) VALUES(?,?)",
        )
        .bind(&event.id)
        .bind(parent)
        .execute(&mut *target)
        .await?;
    }
    crate::projector::project(&mut target, &event).await?;
    target.commit().await?;
    Ok(())
}

mod record;
#[cfg(feature = "v2-kernel-probe")]
pub(crate) use record::*;
