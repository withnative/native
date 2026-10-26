//! Paired counts/timings only. All paths must name disposable copies.
use native_ce::mcp::registry::{Caller, EngineHandle, ToolRegistry};
use native_ce::{
    authorization::{Capability, Principal},
    kernel, Db,
};
use serde_json::{json, Value};
use std::time::Instant;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
fn registry() -> Result<ToolRegistry> {
    let mut r = ToolRegistry::new();
    native_ce::mcp::register_builtin_tools(&mut r)?;
    native_ce::mcp::register_surface_tools(&mut r)?;
    native_ce::mcp::kernel_v2::register_kernel_v2_tools(&mut r)?;
    Ok(r)
}
fn caller(credential: &str, owner: bool) -> Caller {
    Caller::authenticated(credential)
        .with_hosting_member(true)
        .with_hosting_owner(owner)
}
// Setup verifies these disposable files before measurement. Startup and
// admission are outside request timing; reopening only resets SQLite caches.
async fn open(engine: &str, path: &str) -> Result<Db> {
    Ok(if engine == "v1" {
        native_ce::db::open_database(path).await?
    } else {
        kernel::open_marked_v2_database(path).await?
    })
}
fn handle(engine: &str, db: Db) -> EngineHandle {
    if engine == "v1" {
        EngineHandle::Sqlite(db)
    } else {
        EngineHandle::KernelV2(db)
    }
}
async fn invoke(
    r: &ToolRegistry,
    engine: &str,
    db: &Db,
    who: &str,
    owner: bool,
    tool: &str,
    args: Value,
) -> native_ce::Result<Value> {
    r.call_engine(handle(engine, db.clone()), caller(who, owner), tool, args)
        .await
}
async fn invoke_capped(
    r: &ToolRegistry,
    engine: &str,
    db: &Db,
    who: &str,
    owner: bool,
    tool: &str,
    args: Value,
) -> Option<native_ce::Result<Value>> {
    let f = invoke(r, engine, db, who, owner, tool, args);
    if engine == "v1"
        && tool == "render_record_version_diff"
        && std::env::var_os("PAIRED_NO_CAP").is_none()
    {
        tokio::time::timeout(std::time::Duration::from_secs(60), f)
            .await
            .ok()
    } else {
        Some(f.await)
    }
}

#[tokio::main]
async fn main() {
    // Validators can quote private source values. Never print their messages.
    if let Err(e) = run().await {
        let s = e.to_string();
        let classes: Vec<_> = [
            "schema",
            "refusing to open",
            "no rows",
            "no such",
            "hidden",
            "not found",
            "not a",
            "required",
            "timeout",
            "interrupted",
            "unsupported",
        ]
        .into_iter()
        .filter(|c| s.contains(c))
        .collect();
        eprintln!(
            "{}",
            json!({"benchmark_failed":true,"error_classes":classes})
        );
        std::process::exit(1);
    }
}
async fn diagnose(path: &str, specification: &str, plans_path: &str) -> Result<()> {
    use sqlx::Row;
    let specification: Value = serde_json::from_slice(&std::fs::read(specification)?)?;
    let db = native_ce::db::open_database(path).await?;
    let mut conn = db.pool().acquire().await?;
    sqlx::query(specification["setup"].as_str().ok_or("setup")?)
        .execute(&mut *conn)
        .await?;
    let mut plans = Vec::new();
    for (index, case) in specification["queries"]
        .as_array()
        .ok_or("queries")?
        .iter()
        .enumerate()
    {
        let sql = case["sql"].as_str().ok_or("sql")?;
        let args = case["parameters"].as_array().ok_or("parameters")?;
        let bind = |statement| {
            let mut q = sqlx::query(statement);
            for arg in args {
                q = if let Some(s) = arg.as_str() {
                    q.bind(s)
                } else if let Some(n) = arg.as_i64() {
                    q.bind(n)
                } else {
                    q.bind(None::<String>)
                };
            }
            q
        };
        let mut ms = Vec::new();
        for _ in 0..3 {
            let start = Instant::now();
            let rows = bind(sql).fetch_all(&mut *conn).await?;
            ms.push(start.elapsed().as_secs_f64() * 1000.);
            drop(rows);
        }
        let explain = format!("EXPLAIN QUERY PLAN {sql}");
        let plan = bind(&explain)
            .fetch_all(&mut *conn)
            .await?
            .into_iter()
            .map(|r| r.get::<String, _>(3))
            .collect::<Vec<_>>();
        plans.push(plan);
        println!("{}", json!({"diagnostic_query":index,"ms":ms}));
    }
    std::fs::write(plans_path, serde_json::to_vec(&plans)?)?;
    drop(conn);
    db.close().await;
    Ok(())
}

async fn run() -> Result<()> {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};
    let profile = std::env::var_os("V2_BENCH_PROFILE").is_some();
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .without_time()
                .with_ansi(false)
                .with_writer(std::io::stderr)
                .with_filter(tracing_subscriber::filter::filter_fn(move |metadata| {
                    profile && metadata.target() == "native_ce::read_staging"
                })),
        )
        .init();
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--prepare") {
        let db = native_ce::db::open_database(&args[1]).await?;
        let started = Instant::now();
        kernel::prepare_v2_database(&db).await?;
        let aggregates: i64 = sqlx::query_scalar("SELECT count(*) FROM kernel_provider_link_heads")
            .fetch_one(db.pool())
            .await?;
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM kernel_provider_link_rows")
            .fetch_one(db.pool())
            .await?;
        println!(
            "{}",
            json!({"prepare_ms":started.elapsed().as_millis(),"provider_aggregates":aggregates,"provider_link_rows":rows})
        );
        db.close().await;
        return Ok(());
    }
    if args.first().map(String::as_str) == Some("--diagnose") {
        return diagnose(&args[1], &args[2], &args[3]).await;
    }
    if matches!(
        args.first().map(String::as_str),
        Some("--setup" | "--setup-metadata")
    ) {
        let count = if args[0] == "--setup-metadata" {
            200
        } else {
            100
        };
        return setup(&args[1], &args[2], &args[3], &args[4], count).await;
    }
    if args.len() != 8 {
        return Err("expected engine path plan role case thermal callers repetitions".into());
    }
    let (engine, path, plan_path, role, case, thermal) =
        (&args[0], &args[1], &args[2], &args[3], &args[4], &args[5]);
    let callers: usize = args[6].parse()?;
    let repeats: usize = args[7].parse()?;
    let plan: Value = serde_json::from_slice(&std::fs::read(plan_path)?)?;
    let p = &plan[role];
    let credential = p["credential"].as_str().ok_or("credential")?;
    let owner = role == "owner";
    let (tool, arguments) = case_args(case, &p[engine])?;
    let r = std::sync::Arc::new(registry()?);
    let mut db = open(engine, path).await?;
    if std::env::var_os("PAIRED_KEEP_CACHE").is_none() {
        db.close().await;
        checkpoint(path).await?;
        evict(path)?;
        db = open(engine, path).await?;
    }
    let before = conditions();
    let mut rows = Vec::new();
    let mut warmup_failures = 0usize;
    if thermal == "warm" {
        // Warm the same dispatch path; no application cache survives a request.
        for _ in 0..std::env::var("PAIRED_WARMUPS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(2)
        {
            let work = (0..callers).map(|_| {
                invoke_capped(&r, engine, &db, credential, owner, tool, arguments.clone())
            });
            for answer in futures::future::join_all(work).await {
                warmup_failures += usize::from(!matches!(answer, Some(Ok(_))));
            }
        }
    }
    for _ in 0..repeats {
        if thermal == "cold" {
            db.close().await;
            checkpoint(path).await?;
            evict(path)?;
            db = open(engine, path).await?;
        }
        let work = (0..callers).map(|caller_index| {
            let r = r.clone();
            let db = db.clone();
            let engine = engine.clone();
            let credential = credential.to_owned();
            let arguments = arguments.clone();
            tokio::spawn(async move {
                let markers = std::env::var_os("PAIRED_SAMPLE_MARKERS").is_some();
                if markers {
                    println!("{}", json!({"sample_started":caller_index,"pid":std::process::id()}));
                    use std::io::Write;
                    std::io::stdout().flush().expect("benchmark output");
                }
                let start = Instant::now();
                let result = invoke_capped(
                    &r,
                    &engine,
                    &db,
                    &credential,
                    owner,
                    tool,
                    arguments.clone(),
                )
                .await;
                let ms = start.elapsed().as_secs_f64() * 1000.;
                let censored = result.is_none();
                let (failed, timeout, returned) = match result {
                    None => (false, false, 0),
                    Some(Err(e)) => (
                        true,
                        e.to_string().contains("interrupted")
                            || e.to_string().contains("timeout")
                            || e.to_string().contains("deadline"),
                        0,
                    ),
                    Some(Ok(v)) => {
                        let a = match tool {
                            "get_record" | "query_record" => v["records"].as_array(),
                            "search" => v["hits"].as_array(),
                            "get_history" => v["events"].as_array(),
                            "query_sql" => v["rows"].as_array(),
                            "open_collection" => v["input"]["records"].as_array(),
                            "render_record_version_diff" => v["events"].as_array(),
                            _ => None,
                        };
                        let n = a.map_or(1, Vec::len);
                        let valid = match tool {
                            "get_record" => a.is_some_and(|rs| {
                                rs.len() == arguments["ids"].as_array().unwrap().len()
                                    && rs.iter().all(|x| x["status"] == "found")
                            }),
                            "open_collection" => v["status"] == "opened",
                            "query_record" | "search" | "query_sql" => n > 0,
                            "render_record_version_diff" => v["view"] == "record_version_diff",
                            _ => true,
                        };
                        (!valid, false, n)
                    }
                };
                if markers {
                    println!("{}", json!({"sample_done":caller_index,"elapsed_ms":ms,"failed":failed,"timeout":timeout,"returned":returned,"censored":censored,"peak_rss_kib":rss()}));
                    use std::io::Write;
                    std::io::stdout().flush().expect("benchmark output");
                }
                (ms, failed, timeout, returned, censored)
            })
        });
        for row in futures::future::join_all(work).await {
            rows.push(row?);
        }
    }
    let after = conditions();
    db.close().await;
    let mut ms: Vec<_> = rows.iter().map(|r| r.0).collect();
    ms.sort_by(f64::total_cmp);
    let n = ms.len();
    println!(
        "{}",
        json!({"engine":engine,"role":role,"case":case,"thermal":thermal,"callers":callers,"samples":n,"censored":rows.iter().filter(|r|r.4).count(),"warmup_failures":warmup_failures,"failures":rows.iter().filter(|r|r.1).count(),"timeouts":rows.iter().filter(|r|r.2).count(),"min_returned":rows.iter().map(|r|r.3).min(),"max_returned":rows.iter().map(|r|r.3).max(),"min_ms":ms[0],"p50_ms":ms[n/2],"p95_ms":ms[(n*95).div_ceil(100)-1],"p99_ms":ms[(n*99).div_ceil(100)-1],"max_ms":ms[n-1],"host_before":before,"host_after":after,"peak_rss_kib":rss(),"memory":memory()})
    );
    Ok(())
}
fn case_args(case: &str, p: &Value) -> Result<(&'static str, Value)> {
    let ids = p["ids"].clone();
    let id = &ids[0];
    Ok(match case {
        "metadata_pulse"
        | "metadata_pulse_full"
        | "metadata_pulse_one"
        | "metadata_pulse_one_full"
        | "metadata_wide"
        | "metadata_wide_full"
        | "metadata_wide_one"
        | "metadata_wide_one_full" => {
            let ids = ids.as_array().ok_or("ids")?;
            let ids = if case.contains("_one") {
                &ids[..1]
            } else {
                ids.as_slice()
            };
            let holes = (1..=ids.len())
                .map(|n| format!("?{n}"))
                .collect::<Vec<_>>()
                .join(",");
            // The qualified alias is semantically identical but deliberately
            // outside the closed staging optimization: a full-staging oracle.
            let projection = if case.starts_with("metadata_wide") {
                "id, type, kind, name, summary, home_id, lifecycle, maturity, updated_at, last_activity_at"
            } else {
                "id, updated_at"
            };
            let deleted = if case.starts_with("metadata_wide") {
                "deleted_at IS NULL AND "
            } else {
                ""
            };
            let sql = if case.ends_with("_full") {
                format!("SELECT {projection} FROM records AS r WHERE {deleted}id IN ({holes})")
            } else {
                format!("SELECT {projection} FROM records WHERE {deleted}id IN ({holes})")
            };
            (
                "query_sql",
                json!({"sql":sql,"parameters":ids.iter().map(|id| json!({"type":"text","value":id})).collect::<Vec<_>>()}),
            )
        }
        "get_one" => ("get_record", json!({"ids":[id]})),
        "get_batch" => ("get_record", json!({"ids":ids})),
        "query_record" => (
            "query_record",
            json!({"steps":[{"step":"filter","types":["Document"]}],"limit":100}),
        ),
        "search20" => ("search", json!({"query":"native","limit":20})),
        "search100" => ("search", json!({"query":"native","limit":100})),
        "open_collection" => ("open_collection", json!({"id":p["collection"]})),
        "history_diff" => (
            "render_record_version_diff",
            json!({"record_id":id,"before_seq":p["before_seq"]}),
        ),
        "event_context" => ("get_event_context", json!({"event_id":p["event_id"]})),
        "get_history" => (
            "get_history",
            json!({"record_id":id,"limit":100,"order":"newest_first","detail":"full"}),
        ),
        "get_history_global" => (
            "get_history",
            json!({"limit":100,"order":"newest_first","detail":"metadata"}),
        ),
        "query_sql" => (
            "query_sql",
            json!({"sql":"SELECT id,name FROM records ORDER BY id LIMIT 20"}),
        ),
        "query_sql_join" => (
            "query_sql",
            json!({"sql":"SELECT r.type,count(l.target_id) AS n FROM records r LEFT JOIN links l ON l.source_id=r.id GROUP BY r.type ORDER BY n DESC LIMIT 100"}),
        ),
        "query_sql_join_reverse" => (
            "query_sql",
            json!({"sql":"SELECT r.type,l.relationship,count(*) AS n FROM links l JOIN records r ON r.id=l.target_id GROUP BY r.type,l.relationship ORDER BY n DESC LIMIT 100"}),
        ),
        "query_sql_join_names" => (
            "query_sql",
            json!({"sql":"SELECT s.type AS source_type,t.type AS target_type,count(*) AS n FROM links l JOIN records s ON s.id=l.source_id JOIN records t ON t.id=l.target_id WHERE s.name IS NOT NULL GROUP BY s.type,t.type ORDER BY n DESC LIMIT 100"}),
        ),
        "query_sql_join_clock" => (
            "query_sql",
            json!({"sql":"SELECT l.relationship,count(*) AS n,max(l.created_at_ms) AS latest_ms FROM links l JOIN records s ON s.id=l.source_id JOIN records t ON t.id=l.target_id GROUP BY l.relationship ORDER BY n DESC LIMIT 100"}),
        ),
        _ => return Err("unknown case".into()),
    })
}
async fn setup(
    v1path: &str,
    v2path: &str,
    members_path: &str,
    plan_path: &str,
    id_count: usize,
) -> Result<()> {
    eprintln!("{}", json!({"setup_stage":1}));
    let raw = native_ce::db::open_database(v2path).await?;
    kernel::prepare_v2_database(&raw).await?;
    raw.close().await;
    let v1 = native_ce::open_existing_database(v1path).await?;
    let v2 = open("v2", v2path).await?;
    let r = registry()?;
    eprintln!("{}", json!({"setup_stage":2}));
    let owner:String=sqlx::query_scalar("SELECT subject_id FROM policy_entries WHERE policy_anchor_id='native:root' AND subject_kind='account' AND capability='manage' ORDER BY subject_id LIMIT 1").fetch_one(v1.pool()).await?;
    let roster = std::fs::read_to_string(members_path)?;
    let member = roster
        .lines()
        .map(str::trim)
        .find(|s| !s.is_empty() && *s != owner)
        .ok_or("no member")?;
    let owner_actor = kernel::resolve_principal_by_binding(&v2, &owner)
        .await?
        .ok_or("no owner")?
        .0;
    let candidates:Vec<String>=sqlx::query_scalar("SELECT id FROM records WHERE type='Document' AND deleted_at IS NULL AND body IS NOT NULL AND length(body)>0 ORDER BY id LIMIT 1000").fetch_all(v1.pool()).await?;
    let collections:Vec<String>=sqlx::query_scalar("SELECT id FROM records WHERE type='Collection' AND kind='query' AND deleted_at IS NULL ORDER BY id").fetch_all(v1.pool()).await?;
    let query =
        json!({"v":"0.2","query":{"steps":[{"step":"filter","types":["Document"]}],"limit":100}})
            .to_string();
    let mut plan = json!({});
    for (role, who) in [("member", member), ("owner", owner.as_str())] {
        let actor = kernel::resolve_principal_by_binding(&v2, who)
            .await?
            .ok_or("no member principal")?
            .0;
        let mut ids = Vec::new();
        for id in &candidates {
            if native_ce::authorization::effective_capability(&v1, Principal::bound(who, true), id)
                .await
                .is_ok_and(|c| c.allows(Capability::View))
                && kernel::read_record_as(&v2, &actor, id)
                    .await
                    .ok()
                    .flatten()
                    .is_some()
                && kernel::kernel_effective_capability(&v2, &owner_actor, id)
                    .await?
                    .allows(Capability::Edit)
                && native_ce::authorization::effective_capability(
                    &v1,
                    Principal::bound(&owner, true),
                    id,
                )
                .await?
                .allows(Capability::Edit)
            {
                ids.push(id.clone());
            }
            if ids.len() == id_count {
                break;
            }
        }
        if ids.len() != id_count {
            return Err("need enough shared visible documents".into());
        }
        let mut collection = None;
        for id in &collections {
            if native_ce::authorization::effective_capability(&v1, Principal::bound(who, true), id)
                .await
                .is_ok_and(|c| c.allows(Capability::View))
                && native_ce::authorization::effective_capability(
                    &v1,
                    Principal::bound(&owner, true),
                    id,
                )
                .await?
                .allows(Capability::Edit)
                && kernel::read_record_as(&v2, &actor, id)
                    .await
                    .ok()
                    .flatten()
                    .is_some()
                && kernel::kernel_effective_capability(&v2, &owner_actor, id)
                    .await?
                    .allows(Capability::Edit)
            {
                collection = Some(id.clone());
                break;
            }
        }
        let collection = collection.ok_or("no shared saved collection")?;
        // Canonical writes on disposable copies only. Preserve all user bodies.
        for (engine, db) in [("v1", &v1), ("v2", &v2)] {
            invoke(&r,engine,db,&owner,true,"update_record",json!({"id":collection,"facets":{"query":query},"reason":"Disposable paired read qualification"})).await?;
        }
        let body: Option<String> = sqlx::query_scalar("SELECT body FROM records WHERE id=?")
            .bind(&ids[0])
            .fetch_one(v1.pool())
            .await?;
        let mut before1 = 0;
        let mut event1 = String::new();
        let mut before2 = 0;
        let mut event2 = String::new();
        for index in 0..2 {
            let e = native_ce::store::append(
                &v1,
                native_ce::store::AppendSpec {
                    record_id: ids[0].clone(),
                    event_type: "record.updated".into(),
                    payload: json!({"body":body}),
                    actor: Some(owner.clone()),
                },
            )
            .await?;
            if index == 0 {
                before1 = e.local_seq;
            }
            event1 = e.id;
            let rec = kernel::read_record_as(&v2, &owner_actor, &ids[0])
                .await?
                .ok_or("no subject")?;
            kernel::set_body_as(
                &v2,
                &owner_actor,
                &ids[0],
                body.as_deref().unwrap_or_default(),
                rec.revision,
            )
            .await?;
            let e:(i64,String)=sqlx::query_as("SELECT seq,id FROM content_events WHERE record_id=? AND type='kernel.body_set.v1' ORDER BY seq DESC LIMIT 1").bind(&ids[0]).fetch_one(v2.pool()).await?;
            if index == 0 {
                before2 = e.0;
            }
            event2 = e.1;
        }
        plan[role] = json!({"credential":who,"v1":{"ids":ids,"collection":collection,"before_seq":before1,"event_id":event1},"v2":{"ids":ids,"collection":collection,"before_seq":before2,"event_id":event2}});
        println!(
            "{}",
            json!({"setup_role":role,"shared_ids":id_count,"identical_body_events_per_engine":2,"bounded_query_installed_per_engine":1})
        );
    }
    std::fs::write(plan_path, serde_json::to_vec(&plan)?)?;
    for (engine, db, table) in [("v1", &v1, "records"), ("v2", &v2, "kernel_records")] {
        let count: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
            .fetch_one(db.pool())
            .await?;
        let events: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
            .fetch_one(db.pool())
            .await?;
        println!(
            "{}",
            json!({"engine":engine,"records":count,"events":events})
        );
    }
    v1.close().await;
    v2.close().await;
    Ok(())
}
async fn checkpoint(path: &str) -> Result<()> {
    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{path}?mode=rw")).await?;
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(&pool)
        .await?;
    pool.close().await;
    Ok(())
}
fn evict(path: &str) -> Result<()> {
    use std::os::fd::AsRawFd;
    for suffix in ["", "-wal"] {
        let file = match std::fs::File::open(format!("{path}{suffix}")) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        file.sync_all()?;
        let error =
            unsafe { libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) };
        if error != 0 {
            return Err(std::io::Error::from_raw_os_error(error).into());
        }
    }
    Ok(())
}
fn conditions() -> Value {
    let load = std::fs::read_to_string("/proc/loadavg").ok().map(|s| {
        s.split_whitespace()
            .take(3)
            .filter_map(|v| v.parse::<f64>().ok())
            .collect::<Vec<_>>()
    });
    let available = std::fs::read_to_string("/proc/meminfo").ok().and_then(|s| {
        s.lines()
            .find(|l| l.starts_with("MemAvailable:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse::<u64>().ok())
    });
    json!({"load":load,"mem_available_kib":available})
}
fn rss() -> Option<u64> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find(|l| l.starts_with("VmHWM:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}
fn memory() -> Value {
    let g = std::fs::read_to_string("/proc/self/cgroup")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|s| s.strip_prefix("0::"))
                .map(str::to_owned)
        });
    let Some(g) = g else {
        return Value::Null;
    };
    let root = format!("/sys/fs/cgroup{g}");
    let peak = std::fs::read_to_string(format!("{root}/memory.peak"))
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok());
    let events = std::fs::read_to_string(format!("{root}/memory.events"))
        .ok()
        .map(|s| {
            s.lines()
                .filter_map(|l| {
                    let mut i = l.split_whitespace();
                    Some((i.next()?.to_owned(), i.next()?.parse::<u64>().ok()?))
                })
                .collect::<std::collections::BTreeMap<_, _>>()
        });
    json!({"peak_bytes":peak,"events":events})
}
