//! Test-only observation of the unchanged installer. No deadline is installed
//! here so all phases can finish after the ordinary MCP control hits its limit.
use super::*;
use sqlx::{Executor, Statement};
use std::{
    ffi::{c_void, CStr},
    sync::{Arc, Mutex},
};

type Phases = Arc<Mutex<Vec<(&'static str, f64)>>>;
tokio::task_local! { static PHASES: Phases; }
pub(super) struct Phase(Option<(&'static str, Instant, Phases)>);
impl Phase {
    pub(super) fn new(name: &'static str) -> Self {
        Self(
            PHASES
                .try_with(|log| (name, Instant::now(), log.clone()))
                .ok(),
        )
    }
}
impl Drop for Phase {
    fn drop(&mut self) {
        if let Some((name, started, log)) = &self.0 {
            log.lock()
                .unwrap()
                .push((name, started.elapsed().as_secs_f64() * 1000.0));
        }
    }
}
#[derive(Clone)]
struct Sample {
    sql: String,
    ns: u64,
}
type Samples = Mutex<Vec<Sample>>;
// SQLite invokes PROFILE on its worker, while this Arc remains pinned until
// trace removal under SQLx's exclusive handle lock. Never unwind through C.
unsafe extern "C" fn trace(
    mask: u32,
    context: *mut c_void,
    statement: *mut c_void,
    duration: *mut c_void,
) -> i32 {
    if mask != libsqlite3_sys::SQLITE_TRACE_PROFILE as u32 {
        return 0;
    }
    let _ = std::panic::catch_unwind(|| {
        let sql = libsqlite3_sys::sqlite3_sql(statement.cast());
        if sql.is_null() || duration.is_null() {
            return;
        }
        let sample = Sample {
            sql: CStr::from_ptr(sql).to_string_lossy().into_owned(),
            ns: *(duration as *const u64),
        };
        if let Ok(mut log) = (*(context as *const Samples)).lock() {
            log.push(sample);
        }
    });
    0
}

async fn explain(conn: &mut sqlx::SqliteConnection, sql: &str) -> Value {
    let query = format!("EXPLAIN QUERY PLAN {sql}");
    let statement = match (&mut *conn).prepare(&query).await {
        Ok(s) => s,
        Err(e) => return json!({"error":e.to_string()}),
    };
    let n = match statement.parameters() {
        Some(sqlx::Either::Right(n)) => n,
        Some(sqlx::Either::Left(types)) => types.len(),
        _ => 0,
    };
    let mut q = sqlx::query_as::<_, (i64, i64, i64, String)>(&query);
    for _ in 0..n {
        q = q.bind(None::<String>);
    }
    match q.fetch_all(conn).await {
        Ok(rows) => {
            json!({"parameters":"NULL for plan inspection only; execution used real bindings","rows":rows})
        }
        Err(e) => json!({"error":e.to_string()}),
    }
}

pub(crate) async fn run(db: &Db, actor: &str) -> Value {
    let phases: Phases = Arc::default();
    PHASES.scope(phases.clone(), async {
        let mut conn=db.governed_pool().acquire().await.unwrap();
        conn.close_on_drop();
        sqlx::query("BEGIN").execute(&mut *conn).await.unwrap();
        let samples:Arc<Samples>=Arc::default();
        let context=Arc::into_raw(samples.clone());
        {
            let mut handle=conn.lock_handle().await.unwrap();
            // SAFETY: pinned Arc context, trace is removed under the same lock.
            unsafe {libsqlite3_sys::sqlite3_trace_v2(handle.as_raw_handle().as_ptr(),libsqlite3_sys::SQLITE_TRACE_PROFILE as u32,Some(trace),context as *mut c_void);}
        }
        let reads=BTreeSet::from([
            ("records".into(),"type".into()),("records".into(),"id".into()),
            ("content_events".into(),"local_seq".into()),("content_events".into(),"record_id".into())]);
        let started=Instant::now();
        let (result,stats)=measured(install_relations(&mut conn,actor,&reads,LinkScope::All,None,None,None,None,None,chrono::Utc::now().timestamp_millis(),true,None,db.sql_event_projection_generation(),db.sql_record_projection_generation().as_deref())).await;
        let total_ms=started.elapsed().as_secs_f64()*1000.0;
        {
            let mut handle=conn.lock_handle().await.unwrap();
            // SAFETY: the worker is idle and the exclusive lock prevents trace
            // callbacks until removal finishes, before releasing its Arc owner.
            unsafe {
                libsqlite3_sys::sqlite3_trace_v2(handle.as_raw_handle().as_ptr(),0,None,std::ptr::null_mut());
                drop(Arc::from_raw(context));
            }
        }
        result.unwrap();
        let mut grouped:BTreeMap<String,(u64,u64)>=BTreeMap::new();
        for sample in samples.lock().unwrap().iter() {
            let entry=grouped.entry(sample.sql.clone()).or_default();
            entry.0+=1;entry.1+=sample.ns;
        }
        let mut statements=Vec::new();
        for (sql,(calls,ns)) in grouped {
            let plan=explain(&mut conn,&sql).await;
            statements.push(json!({"sql":sql,"calls":calls,"sqlite_profile_ms":ns as f64/1e6,"plan":plan}));
        }
        statements.sort_by(|a,b|b["sqlite_profile_ms"].as_f64().partial_cmp(&a["sqlite_profile_ms"].as_f64()).unwrap());
        let counts:Vec<(String,i64)>=sqlx::query_as("SELECT type,count(*) FROM temp.content_events GROUP BY type ORDER BY type").fetch_all(&mut *conn).await.unwrap();
        let actor_counts:Vec<(Option<String>,i64,i64)>=sqlx::query_as("SELECT actor,count(*),count(run_key) FROM temp.content_events GROUP BY actor").fetch_all(&mut *conn).await.unwrap();
        // Explain/timing are done. Public-shaped headers are normalized once;
        // source construction, admission and timestamp conversion are outside
        // the copy timer. This is a lower bound, not a maintained ACL design.
        sqlx::query("CREATE TEMP TABLE floor_source AS SELECT e.seq AS local_seq,e.id,e.record_id,coalesce(m.event_type,e.type) AS type,coalesce(m.actor,e.actor) AS actor,coalesce(m.run_key,e.run_key) AS run_key,coalesce(m.parent_key,e.parent_key) AS parent_key,'unknown' AS channel_kind,strftime('%Y-%m-%dT%H:%M:%fZ',e.created_at) AS created_at,CAST(strftime('%s',e.created_at) AS INTEGER)*1000 AS created_at_ms FROM main.content_events e LEFT JOIN main.kernel_legacy_sql_events m ON m.seq=e.seq WHERE e.record_id GLOB 'hq:*' AND e.id GLOB 'hq-event:*'")
            .execute(&mut *conn).await.unwrap();
        sqlx::query("CREATE TEMP TABLE floor_visible(id TEXT PRIMARY KEY); INSERT INTO floor_visible SELECT id FROM temp._v2_visible").execute(&mut *conn).await.unwrap();
        let source_rows:i64=sqlx::query_scalar("SELECT count(*) FROM floor_source").fetch_one(&mut *conn).await.unwrap();
        assert_eq!(source_rows,308000);
        let mut floor=Vec::new();
        for pk in [false,true] {
            sqlx::query(&format!("CREATE TEMP TABLE floor_target(local_seq INTEGER{},id TEXT,record_id TEXT,type TEXT,actor TEXT,run_key TEXT,parent_key TEXT,channel_kind TEXT,created_at TEXT,created_at_ms INTEGER)",if pk {" PRIMARY KEY"}else{""})).execute(&mut *conn).await.unwrap();
            let copy="INSERT INTO temp.floor_target SELECT e.* FROM temp.floor_source e JOIN temp.floor_visible v ON v.id=e.record_id";
            let plan=explain(&mut conn,copy).await;
            let mut times=Vec::new();
            for _ in 0..3 {
                sqlx::query("DELETE FROM floor_target").execute(&mut *conn).await.unwrap();
                let started=Instant::now();
                let rows=sqlx::query(copy).execute(&mut *conn).await.unwrap().rows_affected();
                times.push(started.elapsed().as_secs_f64()*1000.0);
                assert_eq!(rows,308000);
            }
            let started=Instant::now();
            sqlx::query("CREATE INDEX temp.floor_record_type ON floor_target(record_id,type,local_seq)").execute(&mut *conn).await.unwrap();
            let index_ms=started.elapsed().as_secs_f64()*1000.0;
            floor.push(json!({"primary_key":pk,"rows":source_rows,"copy_ms":times,"index_ms":index_ms,"sql":copy,"plan":plan}));
            sqlx::query("DROP TABLE floor_target").execute(&mut *conn).await.unwrap();
        }
        let source_types:Vec<(String,i64)>=sqlx::query_as("SELECT type,count(*) FROM main.content_events WHERE id GLOB 'hq-event:*' AND record_id GLOB 'hq:*' GROUP BY type ORDER BY type").fetch_all(&mut *conn).await.unwrap();
        sqlx::query("ROLLBACK").execute(&mut *conn).await.unwrap();
        json!({"installer_wall_ms":total_ms,"deadline":"none: unchanged installer, standalone diagnostic after ordinary MCP control","phases":phases.lock().unwrap().iter().map(|(name,ms)|json!({"phase":name,"wall_ms":ms})).collect::<Vec<_>>(),"stats":stats,"statements":statements,"public_type_counts":counts,"public_actor_counts_actor_rows_runs":actor_counts,"source_type_counts":source_types,"copy_floor":floor,"trace_clock":"SQLite PROFILE nanoseconds, often millisecond resolution; SQL text grouped; phase wall times include async/Rust work. Plans collected after execution with NULL bindings; trace disabled before EQP/floor."})
    }).await
}
