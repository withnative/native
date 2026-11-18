//! `agent_activity` recency bound: the bounded relation must return exactly
//! the rows the code on `main` returned, whatever mix of fresh and stale
//! evidence the runs carry. The reference is a verbatim copy of the
//! preparation and view as they stood at `10c5e2d6d` (`Engine::Base`), kept
//! below so the comparison never runs through any of the new code. The
//! expected sets are frozen from that reference.

use super::*;
use crate::authorization::{replace_explicit_policy, AllowEntry, Capability};
use crate::control::close_agent_run;
use crate::store::create_record;
use chrono::{DateTime, Duration, SecondsFormat, Utc};

const OBSERVED: &str = "2026-10-28T12:00:00.000Z";

fn observed() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(OBSERVED)
        .unwrap()
        .with_timezone(&Utc)
}

/// The window edge: `observed_at - 24h`.
fn edge() -> DateTime<Utc> {
    observed() - Duration::hours(24)
}

fn stamp(time: DateTime<Utc>) -> String {
    time.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn run_key(n: u32) -> String {
    format!("scout-chair-{n:06x}")
}

struct Fixture {
    db: Db,
    record_id: String,
    labels: Vec<(u32, String)>,
}

impl Fixture {
    async fn run(&mut self, n: u32, label: &str, account: &str, started: DateTime<Utc>) {
        self.run_text(n, label, account, &stamp(started)).await;
    }

    async fn run_text(&mut self, n: u32, label: &str, account: &str, started: &str) {
        admit_fixture_run(&self.db, &run_key(n), account).await;
        sqlx::query("UPDATE agent_runs SET started_at=? WHERE run_key=?")
            .bind(started)
            .bind(run_key(n))
            .execute(self.db.write_pool())
            .await
            .unwrap();
        self.labels.push((n, label.to_string()));
    }

    async fn close(&mut self, n: u32, account: &str, ended: DateTime<Utc>) {
        self.close_text(n, account, &stamp(ended)).await;
    }

    async fn close_text(&mut self, n: u32, account: &str, ended: &str) {
        close_agent_run(&self.db, &run_key(n), account)
            .await
            .unwrap();
        sqlx::query("UPDATE agent_runs SET ended_at=? WHERE run_key=?")
            .bind(ended)
            .bind(run_key(n))
            .execute(self.db.write_pool())
            .await
            .unwrap();
    }

    async fn content(&self, n: u32, account: &str, at: &str) {
        sqlx::query(
            "INSERT INTO content_events(id,record_id,type,payload,actor,run_key,causal_envelope_version,causal_status,created_at)
             VALUES(?,?,?,?,?,?,?,?,?)",
        )
        .bind(format!("ev-{n}-{at}"))
        .bind(&self.record_id)
        .bind("record.created")
        .bind("{}")
        .bind(account)
        .bind(run_key(n))
        .bind(1)
        .bind("complete")
        .bind(at)
        .execute(self.db.write_pool())
        .await
        .unwrap();
    }

    async fn call(
        &self,
        n: u32,
        account: &str,
        tool: &str,
        intent: Option<&str>,
        outcome: &str,
        at: &str,
    ) {
        sqlx::query(
            "INSERT INTO read_log_calls(id,tool,run_key,intent,actor,outcome,started_at,ended_at)
             VALUES(?,?,?,?,?,?,?,?)",
        )
        .bind(format!("call-{n}-{tool}-{at}-{outcome}"))
        .bind(tool)
        .bind(run_key(n))
        .bind(intent)
        .bind(account)
        .bind(outcome)
        .bind(at)
        .bind(at)
        .execute(self.db.write_pool())
        .await
        .unwrap();
    }
}

/// Runs mixing every kind of evidence the relation can admit on, with the
/// boundary cases exactly at, and one millisecond outside, the window edge.
impl Fixture {
    async fn empty() -> Fixture {
        let db = crate::create_database(":memory:").await.unwrap();
        let record_id = create_record(
            &db,
            serde_json::json!({
                "id": "9e795000-0000-4000-8000-000000000001", "type": "Document", "kind": "note",
                "name": "r", "body": "x", "home_id": "native:root"
            }),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            &record_id,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();
        Fixture {
            db,
            record_id,
            labels: Vec::new(),
        }
    }
}

async fn fixture() -> Fixture {
    let mut f = Fixture::empty().await;
    let old = edge() - Duration::days(10);
    let ms = Duration::milliseconds(1);
    let o = observed();

    // Started inside the window, no other evidence.
    f.run(1, "fresh_started", "alice", o - Duration::hours(1))
        .await;
    // Nothing inside the window anywhere.
    f.run(2, "stale_nothing", "alice", old).await;
    f.content(2, "alice", &stamp(old)).await;
    f.call(
        2,
        "alice",
        "set_intent",
        Some("stale intent"),
        "ok",
        &stamp(old),
    )
    .await;
    // Long-lived run: recent calls, old intent that must survive the bound.
    f.run(3, "old_intent_recent_call", "alice", old).await;
    f.call(
        3,
        "alice",
        "set_intent",
        Some("old intent"),
        "ok",
        &stamp(old + Duration::minutes(1)),
    )
    .await;
    f.call(
        3,
        "alice",
        "query_sql",
        None,
        "ok",
        &stamp(o - Duration::minutes(30)),
    )
    .await;
    // Only content evidence is recent; the intent is old.
    f.run(4, "content_only", "alice", old).await;
    f.call(
        4,
        "alice",
        "set_intent",
        Some("content run intent"),
        "ok",
        &stamp(old),
    )
    .await;
    f.content(4, "alice", &stamp(o - Duration::hours(2))).await;
    // Only observed evidence is recent.
    f.run(5, "observed_only", "alice", old).await;
    f.call(
        5,
        "alice",
        "get_record",
        None,
        "ok",
        &stamp(o - Duration::hours(3)),
    )
    .await;
    // Exactly at the edge is inside; one millisecond before is outside.
    f.run(6, "started_at_edge", "alice", edge()).await;
    f.run(7, "started_before_edge", "alice", edge() - ms).await;
    f.run(8, "content_at_edge", "alice", old).await;
    f.content(8, "alice", &stamp(edge())).await;
    f.run(9, "content_before_edge", "alice", old).await;
    f.content(9, "alice", &stamp(edge() - ms)).await;
    f.run(10, "observed_at_edge", "alice", old).await;
    f.call(10, "alice", "get_record", None, "ok", &stamp(edge()))
        .await;
    f.run(11, "observed_before_edge", "alice", old).await;
    f.call(11, "alice", "get_record", None, "ok", &stamp(edge() - ms))
        .await;
    // Closed inside the window: ended_at alone admits it.
    f.run(12, "ended_in_window", "alice", old).await;
    f.close(12, "alice", edge() + Duration::hours(1)).await;
    // Closed before the window; later calls and content are past its end.
    f.run(13, "ended_before_window", "alice", old).await;
    f.close(13, "alice", edge() - Duration::hours(1)).await;
    f.content(13, "alice", &stamp(o - Duration::hours(1))).await;
    f.call(
        13,
        "alice",
        "query_sql",
        None,
        "ok",
        &stamp(o - Duration::hours(1)),
    )
    .await;
    // Another member's run: visible, intent withheld from the viewer.
    f.run(14, "other_account_recent", "bea", old).await;
    f.call(
        14,
        "bea",
        "set_intent",
        Some("bea intent"),
        "ok",
        &stamp(old),
    )
    .await;
    f.call(
        14,
        "bea",
        "query_sql",
        None,
        "ok",
        &stamp(o - Duration::minutes(5)),
    )
    .await;
    // The latest intent wins; an errored or foreign-actor intent never does.
    f.run(15, "latest_intent_wins", "alice", old).await;
    f.call(15, "alice", "set_intent", Some("first"), "ok", &stamp(old))
        .await;
    f.call(
        15,
        "alice",
        "set_intent",
        Some("second"),
        "ok",
        &stamp(o - Duration::hours(5)),
    )
    .await;
    f.call(
        15,
        "alice",
        "set_intent",
        Some("errored"),
        "error",
        &stamp(o - Duration::hours(4)),
    )
    .await;
    f.call(
        15,
        "bea",
        "set_intent",
        Some("foreign"),
        "ok",
        &stamp(o - Duration::hours(3)),
    )
    .await;
    // Started in the window while its only call and intent predate it.
    f.run(
        16,
        "started_after_old_calls",
        "alice",
        o - Duration::hours(2),
    )
    .await;
    f.call(
        16,
        "alice",
        "set_intent",
        Some("pre-start intent"),
        "ok",
        &stamp(old),
    )
    .await;
    // Evidence in a second timestamp spelling, and evidence in the future.
    f.run(17, "space_separated_call", "alice", old).await;
    f.call(17, "alice", "get_record", None, "ok", "2026-10-28 06:00:00")
        .await;
    f.run(18, "future_content", "alice", old).await;
    f.content(18, "alice", &stamp(o + Duration::hours(3))).await;
    // A start-work call is not observed evidence.
    f.run(19, "start_work_only", "alice", old).await;
    f.call(
        19,
        "alice",
        "start_work",
        None,
        "ok",
        &stamp(o - Duration::hours(1)),
    )
    .await;
    // Bulk old history that must not matter.
    for i in 0..40 {
        f.call(
            2,
            "alice",
            "query_sql",
            None,
            "ok",
            &stamp(old + Duration::seconds(i)),
        )
        .await;
        f.call(
            3,
            "alice",
            "query_sql",
            None,
            "ok",
            &stamp(old + Duration::seconds(i)),
        )
        .await;
    }
    f
}

const MIDNIGHT: &str = "2026-10-28T00:00:00.000Z";

/// Spellings of instants at, just inside and just outside the midnight
/// observation's window edge (`2026-10-27T00:00:00Z`). A date-only text
/// floor one day back would drop the `-12:00` ones that sit exactly on it.
const SPELLINGS: [&str; 9] = [
    "2026-10-26T12:00:00-12:00",
    "2026-10-27T14:00:00+14:00",
    "2026-10-26 12:00:00.000-12:00",
    "2026-10-27 14:00:00+14:00",
    "2026-10-26 11:59:59.9999-12:00",
    "2026-10-26T11:59:59-12:00",
    "2026-10-27T13:59:59+14:00",
    "2026-10-26 23:59:59",
    "2026-10-27 00:00:00",
];

/// One run per evidence kind and spelling. Each run's only recent evidence is
/// the one stamp under test; calls and content runs also carry an old intent.
async fn midnight_fixture() -> Fixture {
    let mut f = Fixture::empty().await;
    let old = "2026-10-17T00:00:00.000Z";
    let mut n = 100;
    for kind in ["start", "end", "call", "content"] {
        for spelling in SPELLINGS {
            n += 1;
            let label = format!("{kind}:{spelling}");
            match kind {
                "start" => f.run_text(n, &label, "alice", spelling).await,
                "end" => {
                    f.run_text(n, &label, "alice", old).await;
                    f.close_text(n, "alice", spelling).await;
                }
                _ => {
                    f.run_text(n, &label, "alice", old).await;
                    f.call(
                        n,
                        "alice",
                        "set_intent",
                        Some(&format!("intent {label}")),
                        "ok",
                        old,
                    )
                    .await;
                    if kind == "call" {
                        f.call(n, "alice", "get_record", None, "ok", spelling).await;
                    } else {
                        f.content(n, "alice", spelling).await;
                    }
                }
            }
        }
    }
    f
}

type Row = Vec<Option<String>>;

#[derive(Clone, Copy)]
enum Engine {
    /// The preparation and view in this tree.
    Bounded,
    /// Verbatim copies of both as they were on `main` before the bound.
    Base,
}

const BASE_VIEW: &str = r#"
CREATE TEMP VIEW IF NOT EXISTS agent_activity_base AS
WITH _query_sql_agent_activity_durable AS (
  SELECT run.activity_id, run.run_key, run.account_id, run.started_at, run.ended_at,
         observed.declared_intent,
         max(run.started_at,
             coalesce(run.ended_at, run.started_at),
               coalesce((SELECT max(event.created_at)
                           FROM main.content_events event
                           LEFT JOIN main.content_event_claim_meta AS claim_meta
                             ON claim_meta.event_seq = event.seq
                          WHERE event.run_key=run.run_key
                            AND event.actor=run.account_id
                            AND NOT (event.type='record.updated'
                                     AND (COALESCE(claim_meta.has_claimed_by, 1) = 1
                                          OR COALESCE(claim_meta.has_claimed_run, 1) = 1))
                           AND (run.ended_at IS NULL
                                OR julianday(event.created_at)<=julianday(run.ended_at))),
                       run.started_at),
             coalesce(observed.last_observed_at, run.started_at)) AS last_observed_activity_at
    FROM main.agent_runs run
    LEFT JOIN temp._query_sql_activity_observations observed ON observed.run_key=run.run_key
), _query_sql_agent_activity_admitted AS (
  SELECT durable.*,
         member.member_ref,
         principal.account_id AS viewer_account_id,
         principal.observed_at,
         principal.trusted_local_bypass
    FROM _query_sql_agent_activity_durable durable
    CROSS JOIN temp._query_sql_principal principal
    LEFT JOIN temp._query_sql_activity_members member
      ON member.account_id=durable.account_id
   WHERE principal.activity_read=1
      AND principal.is_member=1
      AND (member.member_ref IS NOT NULL
           OR (principal.trusted_local_bypass=1
               AND durable.account_id=principal.account_id))
)
SELECT activity_id,
       run_key,
       coalesce(member_ref, 'native:local-operator') AS principal_ref,
       NULL AS principal_display_name,
       strftime('%Y-%m-%dT%H:%M:%fZ', started_at) AS started_at,
       CAST(strftime('%s', started_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', started_at), 4, 3) AS INTEGER) AS started_at_ms,
       strftime('%Y-%m-%dT%H:%M:%fZ', ended_at) AS ended_at,
       CAST(strftime('%s', ended_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', ended_at), 4, 3) AS INTEGER) AS ended_at_ms,
       strftime('%Y-%m-%dT%H:%M:%fZ', last_observed_activity_at) AS last_observed_activity_at,
       CAST(strftime('%s', last_observed_activity_at) AS INTEGER) * 1000 + CAST(substr(strftime('%f', last_observed_activity_at), 4, 3) AS INTEGER) AS last_observed_activity_at_ms,
        strftime('%Y-%m-%dT%H:%M:%fZ', last_observed_activity_at, '+5 minutes') AS active_until,
        CAST(strftime('%s', last_observed_activity_at, '+5 minutes') AS INTEGER) * 1000 + CAST(substr(strftime('%f', last_observed_activity_at, '+5 minutes'), 4, 3) AS INTEGER) AS active_until_ms,
        CASE WHEN ended_at IS NULL
                   AND julianday(observed_at) < julianday(last_observed_activity_at, '+5 minutes')
             THEN 1 ELSE 0 END AS appears_active,
        CASE WHEN coalesce((SELECT available FROM temp._query_sql_activity_capture), 0) != 1 THEN NULL
             WHEN account_id = viewer_account_id THEN declared_intent
             ELSE NULL END AS declared_intent,
        CASE WHEN coalesce((SELECT available FROM temp._query_sql_activity_capture), 0) != 1 THEN 'unavailable'
             WHEN account_id != viewer_account_id THEN 'withheld'
             WHEN declared_intent IS NULL THEN 'none'
             ELSE 'disclosed' END AS declared_intent_state
   FROM _query_sql_agent_activity_admitted
  WHERE julianday(last_observed_activity_at) >= julianday(observed_at, '-24 hours');
"#;

async fn base_prepare_activity_observations(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
) -> Result<(bool, Option<i64>)> {
    sqlx::query("DELETE FROM temp._query_sql_activity_observations")
        .execute(&mut **transaction)
        .await?;
    sqlx::query("DELETE FROM temp._query_sql_activity_capture")
        .execute(&mut **transaction)
        .await?;
    let available: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM main.sqlite_master WHERE type='table' AND name='read_log_calls')",
    )
    .fetch_one(&mut **transaction)
    .await?;
    if !available {
        sqlx::query(
            "INSERT INTO temp._query_sql_activity_capture(singleton,available) VALUES(1,0)",
        )
        .execute(&mut **transaction)
        .await?;
        return Ok((false, None));
    }
    sqlx::query(
        "INSERT INTO temp._query_sql_activity_observations(run_key,last_observed_at,declared_intent)
         SELECT calls.run_key,max(calls.ended_at),
                (SELECT intent_calls.intent
                   FROM main.read_log_calls intent_calls
                  WHERE intent_calls.run_key=calls.run_key
                    AND intent_calls.tool='set_intent'
                    AND intent_calls.outcome='ok'
                    AND intent_calls.intent IS NOT NULL
                    AND intent_calls.actor=run.account_id
                    AND julianday(intent_calls.ended_at)<=julianday((SELECT observed_at FROM temp._query_sql_principal))
                    AND (run.ended_at IS NULL OR julianday(intent_calls.ended_at)<=julianday(run.ended_at))
                  ORDER BY intent_calls.seq DESC
                  LIMIT 1)
           FROM main.read_log_calls calls
           JOIN main.agent_runs run ON run.run_key=calls.run_key
          WHERE calls.run_key IS NOT NULL AND calls.outcome='ok'
            AND calls.tool!='start_work'
            AND calls.actor=run.account_id
            AND (EXISTS (SELECT 1 FROM temp._query_sql_activity_members member
                          WHERE member.account_id=run.account_id)
                 OR ((SELECT trusted_local_bypass FROM temp._query_sql_principal)=1
                     AND run.account_id=(SELECT account_id FROM temp._query_sql_principal)))
            AND julianday(calls.ended_at)<=julianday((SELECT observed_at FROM temp._query_sql_principal))
            AND (run.ended_at IS NULL OR julianday(calls.ended_at)<=julianday(run.ended_at))
          GROUP BY calls.run_key",
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query("INSERT INTO temp._query_sql_activity_capture(singleton,available) VALUES(1,1)")
        .execute(&mut **transaction)
        .await?;
    let watermark = sqlx::query_scalar(
        "SELECT max(calls.seq)
           FROM main.read_log_calls calls
           JOIN main.agent_runs run ON run.run_key=calls.run_key
          WHERE calls.outcome='ok'
            AND calls.tool!='start_work'
            AND calls.actor=run.account_id
            AND (EXISTS (SELECT 1 FROM temp._query_sql_activity_members member
                          WHERE member.account_id=run.account_id)
                 OR ((SELECT trusted_local_bypass FROM temp._query_sql_principal)=1
                     AND run.account_id=(SELECT account_id FROM temp._query_sql_principal)))
            AND julianday(calls.ended_at)<=julianday((SELECT observed_at FROM temp._query_sql_principal))
            AND (run.ended_at IS NULL OR julianday(calls.ended_at)<=julianday(run.ended_at))
            AND julianday(max(run.started_at,coalesce(run.ended_at,run.started_at),calls.ended_at))
                >=julianday((SELECT observed_at FROM temp._query_sql_principal),'-24 hours')",
    )
        .fetch_one(&mut **transaction)
        .await?;
    Ok((true, watermark))
}

/// The relation as the engine serves it for Alice at `observed_at`: all 15
/// columns, plus the transient watermark the preparation reports. With
/// `prepare` false the view is read without any preparation at all.
async fn relation(
    db: &Db,
    observed_at: &str,
    engine: Engine,
    prepare: bool,
) -> (Vec<Row>, Option<i64>) {
    let mut connection = db.governed_pool().acquire().await.unwrap();
    for statement in temp_contract()
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        sqlx::query(statement)
            .execute(&mut *connection)
            .await
            .unwrap();
    }
    sqlx::query(BASE_VIEW)
        .execute(&mut *connection)
        .await
        .unwrap();
    for statement in [
        "DELETE FROM temp._query_sql_principal",
        "DELETE FROM temp._query_sql_activity_members",
        "DELETE FROM temp._query_sql_activity_observations",
        "DELETE FROM temp._query_sql_activity_capture",
    ] {
        sqlx::query(statement)
            .execute(&mut *connection)
            .await
            .unwrap();
    }
    sqlx::query(
        "INSERT INTO temp._query_sql_principal(singleton,account_id,trusted_local_bypass,activity_read,is_member,observed_at)
         VALUES(1,'alice',0,1,1,?)",
    )
    .bind(observed_at)
    .execute(&mut *connection)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO temp._query_sql_activity_members(account_id,member_ref)
         VALUES('alice','native:workspace-member:alice'),('bea','native:workspace-member:bea')",
    )
    .execute(&mut *connection)
    .await
    .unwrap();
    let mut transaction = sqlx::Connection::begin(&mut *connection).await.unwrap();
    let watermark = if !prepare {
        None
    } else {
        match engine {
            Engine::Bounded => prepare_activity_observations(&mut transaction).await,
            Engine::Base => base_prepare_activity_observations(&mut transaction).await,
        }
        .unwrap()
        .1
    };
    let view = match engine {
        Engine::Bounded => "temp.agent_activity",
        Engine::Base => "temp.agent_activity_base",
    };
    let rows = sqlx::query(&format!("SELECT * FROM {view} ORDER BY run_key"))
        .fetch_all(&mut *transaction)
        .await
        .unwrap()
        .iter()
        .map(|row| {
            let width = sqlx::Row::columns(row).len();
            assert_eq!(width, 15, "the relation exposes 15 columns");
            (0..width)
                .map(|i| {
                    sqlx::Row::try_get::<Option<String>, _>(row, i).unwrap_or_else(|_| {
                        sqlx::Row::try_get::<Option<i64>, _>(row, i)
                            .unwrap()
                            .map(|v| v.to_string())
                    })
                })
                .collect()
        })
        .collect();
    transaction.rollback().await.unwrap();
    (rows, watermark)
}

fn label_of(fixture: &Fixture, run_key_value: &str) -> String {
    fixture
        .labels
        .iter()
        .find(|(n, _)| run_key(*n) == run_key_value)
        .map(|(_, label)| label.clone())
        .unwrap()
}

/// `label|last_observed_activity_at|declared_intent|declared_intent_state`.
fn summarise(fixture: &Fixture, rows: &[Row]) -> Vec<String> {
    rows.iter()
        .map(|row| {
            format!(
                "{}|{}|{}|{}",
                label_of(fixture, row[1].as_deref().unwrap()),
                row[8].as_deref().unwrap(),
                row[13].as_deref().unwrap_or_default(),
                row[14].as_deref().unwrap()
            )
        })
        .collect()
}

async fn assert_matches_base(f: &Fixture, observed_at: &str) -> Vec<Row> {
    let (bounded, bounded_watermark) = relation(&f.db, observed_at, Engine::Bounded, true).await;
    let (base, base_watermark) = relation(&f.db, observed_at, Engine::Base, true).await;
    assert_eq!(
        bounded, base,
        "the bound must not change any row or any of the 15 columns"
    );
    assert_eq!(
        bounded_watermark, base_watermark,
        "the bound must not change the watermark"
    );
    assert!(bounded_watermark.is_some());
    bounded
}

#[tokio::test]
async fn bounded_agent_activity_matches_base_rows() {
    let f = fixture().await;
    let rows = assert_matches_base(&f, OBSERVED).await;
    assert_eq!(
        summarise(&f, &rows),
        [
            "fresh_started|2026-10-28T11:00:00.000Z||none",
            "old_intent_recent_call|2026-10-28T11:30:00.000Z|old intent|disclosed",
            "content_only|2026-10-28T10:00:00.000Z|content run intent|disclosed",
            "observed_only|2026-10-28T09:00:00.000Z||none",
            "started_at_edge|2026-10-27T12:00:00.000Z||none",
            "content_at_edge|2026-10-27T12:00:00.000Z||none",
            "observed_at_edge|2026-10-27T12:00:00.000Z||none",
            "ended_in_window|2026-10-27T13:00:00.000Z||none",
            "other_account_recent|2026-10-28T11:55:00.000Z||withheld",
            "latest_intent_wins|2026-10-28T07:00:00.000Z|second|disclosed",
            "started_after_old_calls|2026-10-28T10:00:00.000Z|pre-start intent|disclosed",
            "space_separated_call|2026-10-28T06:00:00.000Z||none",
            "future_content|2026-10-28T15:00:00.000Z||none",
        ]
    );
}

#[tokio::test]
async fn bounded_agent_activity_matches_base_at_midnight_in_every_spelling() {
    let f = midnight_fixture().await;
    let rows = assert_matches_base(&f, MIDNIGHT).await;
    assert_eq!(
        summarise(&f, &rows),
        [
            "start:2026-10-26T12:00:00-12:00|2026-10-27T00:00:00.000Z||none",
            "start:2026-10-27T14:00:00+14:00|2026-10-27T00:00:00.000Z||none",
            "start:2026-10-26 12:00:00.000-12:00|2026-10-27T00:00:00.000Z||none",
            "start:2026-10-27 14:00:00+14:00|2026-10-27T00:00:00.000Z||none",
            "start:2026-10-26 11:59:59.9999-12:00|2026-10-27T00:00:00.000Z||none",
            "start:2026-10-27 00:00:00|2026-10-27T00:00:00.000Z||none",
            "end:2026-10-26T12:00:00-12:00|2026-10-27T00:00:00.000Z||none",
            "end:2026-10-27T14:00:00+14:00|2026-10-27T00:00:00.000Z||none",
            "end:2026-10-26 12:00:00.000-12:00|2026-10-27T00:00:00.000Z||none",
            "end:2026-10-27 14:00:00+14:00|2026-10-27T00:00:00.000Z||none",
            "end:2026-10-26 11:59:59.9999-12:00|2026-10-27T00:00:00.000Z||none",
            "end:2026-10-27 00:00:00|2026-10-27T00:00:00.000Z||none",
            "call:2026-10-26T12:00:00-12:00|2026-10-27T00:00:00.000Z|intent call:2026-10-26T12:00:00-12:00|disclosed",
            "call:2026-10-27T14:00:00+14:00|2026-10-27T00:00:00.000Z|intent call:2026-10-27T14:00:00+14:00|disclosed",
            "call:2026-10-26 12:00:00.000-12:00|2026-10-27T00:00:00.000Z|intent call:2026-10-26 12:00:00.000-12:00|disclosed",
            "call:2026-10-27 14:00:00+14:00|2026-10-27T00:00:00.000Z|intent call:2026-10-27 14:00:00+14:00|disclosed",
            "call:2026-10-26 11:59:59.9999-12:00|2026-10-27T00:00:00.000Z|intent call:2026-10-26 11:59:59.9999-12:00|disclosed",
            "call:2026-10-27 00:00:00|2026-10-27T00:00:00.000Z|intent call:2026-10-27 00:00:00|disclosed",
            "content:2026-10-26T12:00:00-12:00|2026-10-27T00:00:00.000Z|intent content:2026-10-26T12:00:00-12:00|disclosed",
            "content:2026-10-27T14:00:00+14:00|2026-10-27T00:00:00.000Z|intent content:2026-10-27T14:00:00+14:00|disclosed",
            "content:2026-10-26 12:00:00.000-12:00|2026-10-27T00:00:00.000Z|intent content:2026-10-26 12:00:00.000-12:00|disclosed",
            "content:2026-10-27 14:00:00+14:00|2026-10-27T00:00:00.000Z|intent content:2026-10-27 14:00:00+14:00|disclosed",
            "content:2026-10-26 11:59:59.9999-12:00|2026-10-27T00:00:00.000Z|intent content:2026-10-26 11:59:59.9999-12:00|disclosed",
            "content:2026-10-27 00:00:00|2026-10-27T00:00:00.000Z|intent content:2026-10-27 00:00:00|disclosed",
        ]
    );
}

/// The view admits a run on start or end evidence by itself, so a read that
/// skips preparation still shows those runs exactly as the old view did.
#[tokio::test]
async fn view_alone_keeps_start_and_end_evidence_in_every_spelling() {
    let f = midnight_fixture().await;
    let keep = |f: &Fixture, rows: Vec<Row>| -> Vec<Row> {
        rows.into_iter()
            .filter(|row| {
                let label = label_of(f, row[1].as_deref().unwrap());
                label.starts_with("start:") || label.starts_with("end:")
            })
            .collect()
    };
    let (bounded, _) = relation(&f.db, MIDNIGHT, Engine::Bounded, false).await;
    let (base, _) = relation(&f.db, MIDNIGHT, Engine::Base, false).await;
    let (bounded, base) = (keep(&f, bounded), keep(&f, base));
    assert_eq!(bounded, base);
    let labels: Vec<String> = bounded
        .iter()
        .map(|row| label_of(&f, row[1].as_deref().unwrap()))
        .collect();
    assert_eq!(
        labels,
        [
            "start:2026-10-26T12:00:00-12:00",
            "start:2026-10-27T14:00:00+14:00",
            "start:2026-10-26 12:00:00.000-12:00",
            "start:2026-10-27 14:00:00+14:00",
            "start:2026-10-26 11:59:59.9999-12:00",
            "start:2026-10-27 00:00:00",
            "end:2026-10-26T12:00:00-12:00",
            "end:2026-10-27T14:00:00+14:00",
            "end:2026-10-26 12:00:00.000-12:00",
            "end:2026-10-27 14:00:00+14:00",
            "end:2026-10-26 11:59:59.9999-12:00",
            "end:2026-10-27 00:00:00",
        ]
    );
}
