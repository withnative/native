//! Counts/timings only. Operates on an explicitly supplied disposable import.
//! `--prepare COPY` explicitly prepares schema through the raw database opener.
//! `COPY SOURCE MEMBERS N --seed` appends identical-body revisions and installs
//! a bounded saved query on that copy only. Never supply a serving/original file.
//! `COPY SOURCE MEMBERS N [--concurrent]` measures one or four callers; optional
//! V2_BENCH_CASES selects comma-separated case names. Output includes p95/p99,
//! failures, process high-water RSS and the containing scope's peak memory.
//! V2_BENCH_PROFILE=1 enables numeric staging traces for a separate profile run.
use native_ce::kernel;
use native_ce::mcp::kernel_v2::register_kernel_v2_tools;
use native_ce::mcp::registry::{Caller, EngineHandle, ToolRegistry};
use serde_json::{json, Value};
use std::time::Instant;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::main]
async fn main() {
    if run().await.is_err() {
        eprintln!("Read benchmark failed; no database content or error details emitted");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};
    let profile = std::env::var_os("V2_BENCH_PROFILE").is_some();
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .without_time()
                .with_writer(std::io::stderr)
                .with_filter(tracing_subscriber::filter::filter_fn(move |metadata| {
                    profile && metadata.target() == "native_ce::read_staging"
                })),
        )
        .init();
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() == 2 && args[0] == "--prepare" {
        let started = Instant::now();
        let db = native_ce::db::open_database(&args[1]).await?;
        kernel::prepare_v2_database(&db).await?;
        db.close().await;
        println!(
            "{}",
            json!({"prepared":true,"elapsed_ms":started.elapsed().as_secs_f64()*1000.0})
        );
        return Ok(());
    }
    let ordered = args.get(4).is_some_and(|v| v == "--ordered");
    let concurrent = args.get(4).is_some_and(|v| v == "--concurrent");
    let seed = args.get(4).is_some_and(|v| v == "--seed");
    if args.len() != 4 && !ordered && !concurrent && !seed {
        return Err("expected disposable target, source, members file, repetitions [--ordered|--concurrent|--seed]".into());
    }
    let repeats: usize = args[3].parse()?;
    if repeats == 0 {
        return Err("repetitions must be positive".into());
    }
    let source = sqlx::SqlitePool::connect(&format!("sqlite://{}?mode=ro", args[1])).await?;
    let owner: String = sqlx::query_scalar("SELECT subject_id FROM policy_entries WHERE policy_anchor_id='native:root' AND subject_kind='account' AND capability='manage'")
        .fetch_one(&source).await?;
    source.close().await;
    let members = std::fs::read_to_string(&args[2])?;
    let member = members
        .lines()
        .map(str::trim)
        .find(|v| !v.is_empty() && *v != owner)
        .ok_or("no member in roster")?;
    let mut db = kernel::open_marked_v2_database(&args[0]).await?;
    let events: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(db.pool())
        .await?;
    let records: i64 = sqlx::query_scalar("SELECT count(*) FROM kernel_records")
        .fetch_one(db.pool())
        .await?;
    let homes: i64 = sqlx::query_scalar("SELECT count(*) FROM kernel_roots")
        .fetch_one(db.pool())
        .await?;
    println!(
        "{}",
        json!({"events":events,"records":records,"homes":homes})
    );
    let mut registry = ToolRegistry::new();
    native_ce::mcp::register_builtin_tools(&mut registry)?;
    native_ce::mcp::register_surface_tools(&mut registry)?;
    register_kernel_v2_tools(&mut registry)?;
    let candidates: Vec<String> = sqlx::query_scalar(
        "SELECT r.id FROM kernel_records r WHERE primary_type='Document' OR EXISTS(SELECT 1 FROM kernel_record_fields f WHERE f.record_id=r.id AND f.name='v1_type' AND f.value_json='\"Document\"') ORDER BY r.id LIMIT 500",
    )
    .fetch_all(db.pool())
    .await?;
    let owner_actor = kernel::resolve_principal_by_binding(&db, &owner)
        .await?
        .ok_or("owner missing")?
        .0;
    for (role, credential) in [("member", member), ("owner", owner.as_str())] {
        let actor = kernel::resolve_principal_by_binding(&db, credential)
            .await?
            .ok_or("principal missing")?
            .0;
        let mut ids = Vec::new();
        for id in &candidates {
            if matches!(kernel::read_record_as(&db, &actor, id).await, Ok(Some(_)))
                && kernel::kernel_effective_capability(&db, &owner_actor, id)
                    .await?
                    .allows(native_ce::authorization::Capability::Edit)
            {
                ids.push(id.clone());
            }
            if ids.len() == 100 {
                break;
            }
        }
        if ids.is_empty() {
            return Err("no visible records selected".into());
        }
        let collections: Vec<String> = sqlx::query_scalar("SELECT r.id FROM kernel_records r JOIN kernel_record_fields f ON f.record_id=r.id WHERE f.name='v1_type' AND f.value_json='\"Collection\"' AND EXISTS(SELECT 1 FROM kernel_record_fields k WHERE k.record_id=r.id AND k.name='v1_kind' AND k.value_json='\"query\"') ORDER BY r.id")
            .fetch_all(db.pool()).await?;
        let mut collection = None;
        for id in collections {
            if matches!(kernel::read_record_as(&db, &actor, &id).await, Ok(Some(_)))
                && kernel::kernel_effective_capability(&db, &owner_actor, &id)
                    .await?
                    .allows(native_ce::authorization::Capability::Edit)
            {
                collection = Some(id);
                break;
            }
        }
        let collection = collection.ok_or("no visible saved query")?;
        if seed {
            // A prepared import may have no disclosed native body revisions.
            // On the disposable copy only, append an identical-body revision
            // so event context measures a real, admitted event-local delta.
            let record = kernel::read_record_as(&db, &owner_actor, &ids[0])
                .await?
                .ok_or("record missing")?;
            let body = record
                .body
                .as_deref()
                .or_else(|| record.fields.get("body").and_then(Value::as_str))
                .unwrap_or_default();
            kernel::set_body_as(&db, &owner_actor, &ids[0], body, record.revision).await?;
            kernel::observe_facet_as(&db,&owner_actor,&collection,&kernel::FacetObservation {
                key:"query".into(),value:Some(json!({"v":"0.2","query":{"steps":[{"step":"filter","types":["Document"]}],"limit":100}}).to_string()),value_num:None,vocab_ref:None,as_of:chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            },None).await?;
            println!(
                "{}",
                json!({"role":role,"identical_body_revision_appended":1,"bounded_saved_query_installed":1})
            );
            continue;
        }
        let position: (i64, String) = sqlx::query_as("SELECT seq,id FROM content_events WHERE record_id=? AND type='kernel.body_set.v1' ORDER BY seq DESC LIMIT 1")
            .bind(&ids[0]).fetch_one(db.pool()).await?;
        let diff_before: i64 = sqlx::query_scalar("SELECT coalesce(max(CASE WHEN type IN ('kernel.import_state.v1','kernel.import_state_delta.v1') THEN seq END),min(seq)) FROM content_events WHERE record_id=?")
            .bind(&ids[0]).fetch_one(db.pool()).await?;
        let cases: Vec<(&str, &str, Value)> = vec![
            (
                "get_history_global",
                "get_history",
                json!({"limit":100,"order":"newest_first","detail":"metadata"}),
            ),
            (
                "get_history",
                "get_history",
                json!({"record_id":ids[0],"limit":100,"order":"newest_first","detail":"full"}),
            ),
            (
                "whats_changed",
                "whats_changed",
                json!({"limit":100,"actor_scope":"all","order":"newest_first","after_local_seq":0}),
            ),
            (
                "get_structure",
                "get_structure",
                json!({"root_id":"native:root","max_depth":1,"max_children_per_node":200}),
            ),
            (
                "open_collection",
                "open_collection",
                json!({"id":collection}),
            ),
            (
                "history_diff",
                "render_record_version_diff",
                json!({"record_id":ids[0],"before_seq":diff_before}),
            ),
            (
                "event_context",
                "get_event_context",
                json!({"event_id":position.1}),
            ),
            (
                "query_sql_join",
                "query_sql",
                json!({"sql":"SELECT r.type,count(l.target_id) AS n FROM records r LEFT JOIN links l ON l.source_id=r.id GROUP BY r.type ORDER BY n DESC LIMIT 100"}),
            ),
            ("get_one", "get_record", json!({"ids":[ids[0]]})),
            ("get_batch", "get_record", json!({"ids":ids})),
            (
                "query_record",
                "query_record",
                json!({"steps":[{"step":"filter","types":["Document"]}],"limit":100}),
            ),
            (
                "query_record_ordered",
                "query_record",
                json!({"steps":[{"step":"filter","types":["Document"]}],"order":"last_activity_desc","limit":100}),
            ),
            ("search", "search", json!({"query":"native","limit":100})),
            (
                "query_sql",
                "query_sql",
                json!({"sql":"SELECT id,name FROM records ORDER BY id LIMIT 20"}),
            ),
            (
                "query_sql_home",
                "query_sql",
                json!({"sql":"SELECT id,name,home_id FROM records ORDER BY id LIMIT 20"}),
            ),
        ];
        for (case, tool, mut arguments) in cases {
            if std::env::var("V2_BENCH_CASES")
                .ok()
                .is_some_and(|v| !v.split(',').any(|s| s == case))
            {
                continue;
            }
            if ordered && case != "query_record" {
                continue;
            }
            let case = if ordered {
                arguments["order"] = json!("updated_desc");
                "query_record_ordered"
            } else {
                case
            };
            // Select identities outside the timed section, then close every
            // SQLite cache and evict the disposable file before this case.
            db.close().await;
            let checkpoint =
                sqlx::SqlitePool::connect(&format!("sqlite://{}?mode=rw", args[0])).await?;
            sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
                .execute(&checkpoint)
                .await?;
            checkpoint.close().await;
            evict_copy(&args[0])?;
            db = kernel::open_marked_v2_database(&args[0]).await?;
            let conditions_before = host_conditions();
            let mut ms = Vec::new();
            let mut failures = 0;
            let mut interrupted = 0;
            let mut returned_counts = Vec::new();
            let callers = if concurrent { 4 } else { 1 };
            for _ in 0..repeats {
                let tasks = (0..callers).map(|_| {
                    let registry = &registry;
                    let arguments = arguments.clone();
                    let db = db.clone();
                    async move {
                        let started = Instant::now();
                        let answer = registry
                            .call_engine(
                                EngineHandle::KernelV2(db),
                                Caller::authenticated(credential),
                                tool,
                                arguments.clone(),
                            )
                            .await;
                        let elapsed = started.elapsed().as_secs_f64() * 1000.0;
                        if std::env::var_os("V2_BENCH_DIAGNOSTIC").is_some() {
                            if let Err(error) = &answer {
                                let message = error.to_string();
                                let classes: Vec<_> = [
                                    "no such column: payload",
                                    "no such column: id",
                                    "no such column: created_at",
                                    "no such table",
                                    "SQL relation staging exceeded query deadline",
                                    "composed SQL read exceeds declared",
                                    "query_sql [timeout]",
                                    "query_sql [invalid_arguments]",
                                    "query_sql [unauthorized_relation]",
                                    "query_sql [result_too_large]",
                                    "cell exceeds",
                                    "encoded result exceeds",
                                    "interrupted",
                                    "no rows returned",
                                    "read snapshot caller/database mismatch",
                                ]
                                .into_iter()
                                .filter(|class| message.contains(class))
                                .collect();
                                println!(
                                    "{}",
                                    json!({"error_classes":classes,"message_bytes":message.len()})
                                );
                            }
                        }

                        let returned = answer
                            .as_ref()
                            .ok()
                            .and_then(|v| {
                                let rows = match tool {
                                    "get_record" | "query_record" => &v["records"],
                                    "search" => &v["hits"],
                                    "query_sql" => &v["rows"],
                                    "get_history" => &v["events"],
                                    "whats_changed" => &v["changes"],
                                    "get_structure" => &v["nodes"],
                                    "open_collection" => &v["input"]["records"],
                                    "render_record_version_diff" => &v["events"],
                                    _ => return Some(1),
                                };
                                rows.as_array().map(Vec::len)
                            })
                            .unwrap_or(0);
                        let (failed, interrupted) = match answer {
                            Err(e) => (true, e.to_string().contains("interrupted")),
                            Ok(v) if tool == "get_record" => (
                                !v["records"].as_array().is_some_and(|r| {
                                    r.len() == arguments["ids"].as_array().unwrap().len()
                                        && r.iter().all(|r| r["status"] == "found")
                                }),
                                false,
                            ),
                            Ok(v) if tool == "open_collection" => (v["status"] != "opened", false),
                            Ok(v) if tool == "query_record" => (
                                !v["records"].as_array().is_some_and(|r| !r.is_empty()),
                                false,
                            ),
                            Ok(v) if tool == "search" => {
                                (!v["hits"].as_array().is_some_and(|r| !r.is_empty()), false)
                            }
                            Ok(v) if tool == "query_sql" => {
                                (!v["rows"].as_array().is_some_and(|r| !r.is_empty()), false)
                            }
                            Ok(_) => (false, false),
                        };
                        (elapsed, failed, interrupted, returned)
                    }
                });
                for (elapsed, failed, was_interrupted, returned) in
                    futures::future::join_all(tasks).await
                {
                    ms.push(elapsed);
                    returned_counts.push(returned);
                    failures += usize::from(failed);
                    interrupted += usize::from(was_interrupted);
                }
            }
            let count = ms.len();
            ms.sort_by(f64::total_cmp);
            println!(
                "{}",
                json!({"host_before":conditions_before,"host_after":host_conditions(),"role":role,"case":case,"repetitions":count,"callers":callers,"file_evicted_start":true,"min_returned":returned_counts.iter().min(),"max_returned":returned_counts.iter().max(),"failures":failures,"interrupted":interrupted,"min_ms":ms[0],"median_ms":ms[count/2],"p95_ms":ms[(count*95).div_ceil(100)-1],"p99_ms":ms[(count*99).div_ceil(100)-1],"max_ms":ms[count-1]})
            );
        }
    }
    db.close().await;
    let rss = std::fs::read_to_string("/proc/self/status")?
        .lines()
        .find(|s| s.starts_with("VmHWM:"))
        .and_then(|s| s.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u64>().ok());
    let cgroup = std::fs::read_to_string("/proc/self/cgroup")?
        .lines()
        .find_map(|s| s.strip_prefix("0::"))
        .map(str::to_owned);
    let peak = cgroup
        .as_ref()
        .and_then(|g| std::fs::read_to_string(format!("/sys/fs/cgroup{g}/memory.peak")).ok())
        .and_then(|s| s.trim().parse::<u64>().ok());
    let events = cgroup
        .as_ref()
        .and_then(|g| std::fs::read_to_string(format!("/sys/fs/cgroup{g}/memory.events")).ok())
        .map(|s| {
            s.lines()
                .filter_map(|line| {
                    let mut parts = line.split_whitespace();
                    Some((parts.next()?.to_owned(), parts.next()?.parse::<u64>().ok()?))
                })
                .collect::<std::collections::BTreeMap<_, _>>()
        });
    println!(
        "{}",
        json!({"peak_rss_kib":rss,"cgroup_peak_bytes":peak,"memory_events":events})
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn evict_copy(path: &str) -> Result<()> {
    use std::os::fd::AsRawFd;
    for suffix in ["", "-wal"] {
        let file = match std::fs::File::open(format!("{path}{suffix}")) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        file.sync_all()?;
        // SAFETY: live file descriptor, whole-file advisory eviction only.
        let error =
            unsafe { libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) };
        if error != 0 {
            return Err(std::io::Error::from_raw_os_error(error).into());
        }
    }
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn evict_copy(_: &str) -> Result<()> {
    Err("file eviction requires Linux".into())
}

fn host_conditions() -> Value {
    let load = std::fs::read_to_string("/proc/loadavg").ok().map(|s| {
        s.split_whitespace()
            .take(3)
            .filter_map(|v| v.parse::<f64>().ok())
            .collect::<Vec<_>>()
    });
    let available_kib = std::fs::read_to_string("/proc/meminfo").ok().and_then(|s| {
        s.lines()
            .find(|line| line.starts_with("MemAvailable:"))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse::<u64>().ok())
    });
    json!({"load":load,"mem_available_kib":available_kib})
}
