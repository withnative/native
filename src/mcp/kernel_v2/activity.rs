//! Own-account discovery: v1 history.rs:3062,3793-4020. No read telemetry is
//! imported or captured by the kernel; never present its absence as measured zero.
use super::*;
use sqlx::SqliteConnection;

#[derive(Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    observed_at: String,
    open_rank: i64,
    sort_at: String,
    activity_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    for_run: Option<String>,
    include_child_runs: Option<bool>,
    cursor: Option<Cursor>,
    limit: Option<i64>,
}
struct Run {
    id: String,
    key: String,
    started: String,
    ended: Option<String>,
    native: bool,
    observed: Option<String>,
}
fn timestamp(value: &str) -> Result<chrono::DateTime<chrono::FixedOffset>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map_err(|_| Error::engine("get_run_activity: malformed activity timestamp"))
}
async fn owned_runs(conn: &mut SqliteConnection, actor: &str) -> Result<Vec<Run>> {
    // Ownership is the same account boundary as v1's agent_runs.account_id,
    // independent of directory or root visibility. Never enumerate other owners.
    let native: Vec<(String, String, String, Option<String>)> = sqlx::query_as(
        "SELECT r.id,substr(p.auth_binding,9),e.created_at,
         (SELECT c.created_at FROM content_events c WHERE c.record_id=r.id
          AND c.type='kernel.run_closed.v1' ORDER BY c.seq DESC LIMIT 1)
         FROM kernel_runs r JOIN kernel_principals p ON p.principal_id=r.run_principal
         JOIN content_events e ON e.seq=r.opened_seq
         WHERE r.owner_principal=? AND p.auth_binding LIKE 'mcp-run:%'",
    )
    .bind(actor)
    .fetch_all(&mut *conn)
    .await?;
    let mut runs: Vec<Run> = native
        .into_iter()
        .map(|(id, key, started, ended)| Run {
            id,
            key,
            started,
            ended,
            native: true,
            observed: None,
        })
        .collect();
    let imported: Vec<(String,String)> = sqlx::query_as(
        "SELECT payload,observed_at FROM kernel_v1_state WHERE section='runs' AND account_principal=? ORDER BY source_id",
    ).bind(actor).fetch_all(&mut *conn).await?;
    for (raw, observed) in imported {
        let row: Value = serde_json::from_str(&raw)?;
        let text = |key: &str| -> Result<String> {
            row[key]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| Error::engine("invalid imported run"))
        };
        let key = text("run_key")?;
        if runs.iter().any(|run| run.key == key) {
            continue;
        }
        runs.push(Run {
            id: text("activity_id")?,
            key,
            started: text("started_at")?,
            // Preserve the source state honestly. An unclosed historical run
            // is not evidence of live authority or observed current activity.
            ended: row["ended_at"].as_str().map(str::to_owned),
            native: false,
            observed: Some(observed),
        });
    }
    Ok(runs)
}

pub(super) async fn read(db: &Db, actor: &str, args: Value) -> Result<Value> {
    let args: Args = parse("get_run_activity", args)?;
    let mut tx = db.pool().begin().await?;
    kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
    let runs = owned_runs(&mut tx, actor).await?;
    if let Some(key) = args.for_run {
        if args.cursor.is_some() || args.limit.is_some() {
            return Err(Error::engine("get_run_activity: cursor and limit are discovery-only; omit for_run to discover runs"));
        }
        if !matches!(
            crate::runkey::validate_full(Some(&key)),
            crate::runkey::KeyOutcome::Valid(_)
        ) {
            return Err(Error::engine("get_run_activity: invalid for_run"));
        }
        if !runs.iter().any(|run| run.key == key) {
            return Err(Error::engine("get_run_activity: run does not exist"));
        }
        return Ok(
            json!({"for_run":key,"include_child_runs":args.include_child_runs.unwrap_or(false),
            "availability":{"status":"unavailable","reason":"read_log_unavailable","visibility_filtered":null,"completeness":"unavailable"},"read_activity":[]}),
        );
    }
    if args.include_child_runs.is_some() {
        return Err(Error::engine(
            "get_run_activity: include_child_runs requires for_run",
        ));
    }
    let limit = args.limit.unwrap_or(20);
    if !(1..=50).contains(&limit) {
        return Err(Error::engine(
            "get_run_activity: discovery limit must be between 1 and 50",
        ));
    }
    if let Some(cursor) = &args.cursor {
        timestamp(&cursor.observed_at)?;
        timestamp(&cursor.sort_at)?;
        if !matches!(cursor.open_rank, 0 | 1) || cursor.activity_id.trim().is_empty() {
            return Err(Error::engine("get_run_activity: invalid discovery cursor"));
        }
    }
    let observed_at = args
        .cursor
        .as_ref()
        .map(|c| c.observed_at.clone())
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true));
    let observed = timestamp(&observed_at)?;
    let cutoff = observed - chrono::Duration::hours(24);
    let mut candidates = Vec::new();
    for mut run in runs {
        if timestamp(&run.started)? > observed {
            continue;
        }
        if run
            .ended
            .as_deref()
            .map(timestamp)
            .transpose()?
            .is_some_and(|t| t > observed)
        {
            run.ended = None;
        }
        if run
            .ended
            .as_deref()
            .map(timestamp)
            .transpose()?
            .is_some_and(|t| t <= cutoff)
        {
            continue;
        }
        let rank = i64::from(run.ended.is_some());
        let sort = run.ended.clone().unwrap_or_else(|| run.started.clone());
        if let Some(c) = &args.cursor {
            if !(rank > c.open_rank
                || (rank == c.open_rank
                    && (sort < c.sort_at || (sort == c.sort_at && run.id > c.activity_id))))
            {
                continue;
            }
        }
        candidates.push((rank, sort, run));
    }
    candidates.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| b.1.cmp(&a.1))
            .then_with(|| a.2.id.cmp(&b.2.id))
    });
    let has_more = candidates.len() > limit as usize;
    candidates.truncate(limit as usize);
    let mut page = Vec::new();
    for (_, _, run) in &candidates {
        let intent: Option<(String, String)> = if run.native {
            sqlx::query_as("SELECT json_extract(payload,'$.intent'),created_at FROM content_events WHERE record_id=? AND type='kernel.run_intent_set.v1' AND actor=? AND created_at<=? ORDER BY seq DESC LIMIT 1")
                .bind(&run.id).bind(actor).bind(&observed_at).fetch_optional(&mut *tx).await?
        } else {
            sqlx::query_as("SELECT json_extract(payload,'$.intent'),json_extract(payload,'$.declared_at') FROM kernel_v1_state WHERE section='run_intents' AND account_principal=? AND json_extract(payload,'$.run_key')=? AND json_extract(payload,'$.declared_at')<=? ORDER BY json_extract(payload,'$.source_seq') DESC,source_id DESC LIMIT 1")
                .bind(actor).bind(&run.key).bind(&observed_at).fetch_optional(&mut *tx).await?
        };
        let intent = match intent {
            Some((value, at)) => json!({"status":"available","value":value,"declared_at":at}),
            None => json!({"status":"unavailable","reason":"read_log_unavailable"}),
        };
        // Read-log calls do not exist. Native run intent/start and visible own
        // record events still provide real durable activity evidence.
        let mut latest = run.started.clone();
        let events: Vec<(String,String)> = sqlx::query_as("SELECT record_id,created_at FROM content_events WHERE actor=? AND created_at<=? AND (run_key=? OR record_id=?) ORDER BY created_at DESC,seq DESC")
            .bind(actor).bind(&observed_at).bind(&run.key).bind(&run.id).fetch_all(&mut *tx).await?;
        for (subject, at) in events {
            if at <= latest {
                break;
            }
            if (run.native && subject == run.id)
                || kernel::read_record_on(&mut tx, actor, &subject)
                    .await?
                    .is_some()
            {
                latest = at;
                break;
            }
        }
        let until = timestamp(&latest)? + chrono::Duration::minutes(5);
        page.push(json!({"activity_id":run.id,"run_key":run.key,"intent":intent,"started_at":run.started,"ended_at":run.ended,
            "run_state":if run.ended.is_some(){"closed"}else{"open"},
            "historical":!run.native,"historical_observed_at":run.observed,
            "channel":{"kind":"unknown","assurance":"unknown_or_withheld"},
            "activity_freshness":{"status":"partial","reason":"read_log_unavailable","last_observed_at":latest,
                "active_until":until.to_rfc3339_opts(chrono::SecondsFormat::Millis,true),"appears_active":run.native && run.ended.is_none() && observed<until}}));
    }
    let cursor = if has_more {
        candidates.last().map(|(rank, sort, run)| Cursor {
            observed_at: observed_at.clone(),
            open_rank: *rank,
            sort_at: sort.clone(),
            activity_id: run.id.clone(),
        })
    } else {
        None
    };
    Ok(
        json!({"mode":"discovery","scope":"own_account","availability":{"status":"available","enumeration":"durable_agent_runs","details":"best_effort","visibility":"own_account_only"},
        "observed_at":observed_at,"recent_window_hours":24,"runs":page,"returned":page.len(),"limit":limit,"has_more":has_more,"next_cursor":cursor}),
    )
}
