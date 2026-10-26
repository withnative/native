//! Pseudonymous durable activity, under current H3 membership. Imported runs
//! remain closed. Transient intent capture is unavailable, never fabricated.
use crate::{kernel, Error, Result};
use sqlx::SqliteConnection;

pub(super) async fn install(
    tx: &mut SqliteConnection,
    actor: &str,
    observed_ms: i64,
) -> Result<()> {
    let members = kernel::hosted_identity::activity_members_on(tx, actor).await?;
    let origin: Option<String> = sqlx::query_scalar("SELECT json_extract(payload,'$.origin') FROM main.content_events WHERE type='kernel.import_source_head.v1' ORDER BY seq DESC LIMIT 1")
        .fetch_optional(&mut *tx).await?;
    let origin = match origin {
        Some(origin) => origin,
        None => sqlx::query_scalar(
            "SELECT id FROM main.content_events WHERE type=? ORDER BY seq LIMIT 1",
        )
        .bind(crate::events::KERNEL_GENESIS_EVENT)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| Error::engine("activity workspace origin unavailable"))?,
    };
    sqlx::query("CREATE TEMP TABLE _v2_activity_members(principal TEXT PRIMARY KEY,member_ref TEXT NOT NULL)")
        .execute(&mut *tx).await?;
    for (binding, principal) in members {
        sqlx::query("INSERT INTO temp._v2_activity_members VALUES(?,?)")
            .bind(principal)
            .bind(crate::identity::activity_member_ref(&origin, &binding))
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query(ROWS).bind(observed_ms).execute(tx).await?;
    Ok(())
}

// v1's durable fallback: started/ended/content/intent activity, a 24-hour
// window, and five-minute best-effort activity. No model/client/Person identity
// or private intent enters this relation. Historical ends dominate their
// earlier activity, so imported runs require no scan of retained event bodies.
const ROWS: &str = r#"WITH native_runs AS (
 SELECT r.id AS activity_id,
 CASE WHEN p.auth_binding LIKE 'mcp-run:%' THEN substr(p.auth_binding,9) ELSE r.id END AS run_key,
 r.owner_principal AS owner,m.member_ref,opened.created_at AS started_at,
 (SELECT e.created_at FROM main.content_events e WHERE e.record_id=r.id AND e.type='kernel.run_closed.v1' ORDER BY e.seq DESC LIMIT 1) AS ended_at,
 head.created_at AS head_at,r.closed
 FROM main.kernel_runs r JOIN main.kernel_principals p ON p.principal_id=r.run_principal
 JOIN temp._v2_activity_members m ON m.principal=r.owner_principal
 JOIN main.content_events opened ON opened.seq=r.opened_seq
 JOIN main.content_events head ON head.seq=r.head
), durable AS (
 SELECT n.activity_id,n.run_key,n.member_ref,n.started_at,n.ended_at,
 max(n.started_at,coalesce(n.ended_at,n.started_at),n.head_at,
 coalesce((SELECT max(e.created_at) FROM main.content_events e WHERE e.run_key=n.run_key AND e.actor=n.owner
 AND e.type!='kernel.legacy_recorded.v1' AND e.type NOT GLOB 'kernel.import_*'
 AND (n.ended_at IS NULL OR julianday(e.created_at)<=julianday(n.ended_at))),n.started_at)) AS last_at,
 NOT n.closed AS is_open
 FROM native_runs n
 UNION ALL
 SELECT json_extract(s.payload,'$.activity_id'),json_extract(s.payload,'$.run_key'),m.member_ref,
 json_extract(s.payload,'$.started_at'),coalesce(json_extract(s.payload,'$.ended_at'),s.observed_at),
 max(json_extract(s.payload,'$.started_at'),coalesce(json_extract(s.payload,'$.ended_at'),s.observed_at)),0
 FROM main.kernel_v1_state s JOIN temp._v2_activity_members m ON m.principal=s.account_principal
 WHERE s.section='runs' AND NOT EXISTS(SELECT 1 FROM native_runs n WHERE n.run_key=json_extract(s.payload,'$.run_key'))
)
INSERT INTO temp.agent_activity
 SELECT activity_id,run_key,member_ref,NULL,
 strftime('%Y-%m-%dT%H:%M:%fZ',started_at),(CAST(strftime('%s',started_at) AS INTEGER)*1000+CAST(substr(strftime('%f',started_at),4,3) AS INTEGER)),
 strftime('%Y-%m-%dT%H:%M:%fZ',ended_at),(CAST(strftime('%s',ended_at) AS INTEGER)*1000+CAST(substr(strftime('%f',ended_at),4,3) AS INTEGER)),
 strftime('%Y-%m-%dT%H:%M:%fZ',last_at),(CAST(strftime('%s',last_at) AS INTEGER)*1000+CAST(substr(strftime('%f',last_at),4,3) AS INTEGER)),
 strftime('%Y-%m-%dT%H:%M:%fZ',last_at,'+5 minutes'),(CAST(strftime('%s',last_at) AS INTEGER)*1000+CAST(substr(strftime('%f',last_at),4,3) AS INTEGER))+300000,
 CASE WHEN is_open AND julianday(?1/1000.0,'unixepoch')<julianday(last_at,'+5 minutes') THEN 1 ELSE 0 END,
 NULL,'unavailable'
 FROM durable WHERE julianday(last_at)>=julianday(?1/1000.0,'unixepoch','-24 hours')"#;
