//! Opt-in test-only statement observer. PROFILE sees even nonpersistent SQLX
//! statements before finalization; counters reset at STMT, so reuse cannot sum
//! earlier executions. SQLite invokes callbacks on its worker, not Tokio's task.
use super::*;
use libsqlite3_sys as ffi;
use std::sync::{Arc, Mutex};

#[derive(Default, Debug, Clone, serde::Serialize)]
pub(crate) struct Cost {
    pub staging: [u64; 4],
    pub caller: [u64; 4],
    pub staged_rows: u64,
    pub staged_bytes: u64,
    #[serde(skip)]
    phase: usize,
}
tokio::task_local! { static COST: Arc<Mutex<Cost>>; }
pub(crate) fn active() -> bool {
    COST.try_with(|_| ()).is_ok()
}
pub(crate) async fn measure<T>(work: impl std::future::Future<Output = T>) -> (T, Cost) {
    let cost = Arc::new(Mutex::new(Cost::default()));
    let result = COST.scope(cost.clone(), work).await;
    let measured = cost.lock().unwrap().clone();
    (result, measured)
}
unsafe extern "C" fn trace(
    event: u32,
    context: *mut std::ffi::c_void,
    statement: *mut std::ffi::c_void,
    _: *mut std::ffi::c_void,
) -> i32 {
    let context = context.cast::<Arc<Mutex<Cost>>>();
    if event == ffi::SQLITE_TRACE_CLOSE as u32 {
        // SAFETY: one Box is transferred at attach; CLOSE is its final callback.
        unsafe {
            drop(Box::from_raw(context));
        }
        return 0;
    }
    // SAFETY: SQLite retains context until detach or CLOSE, and statement is
    // live throughout STMT/PROFILE. No SQLite calls run on this handle in parallel.
    let cost = unsafe { &*context };
    let mut cost = cost.lock().unwrap();
    let ops = [
        ffi::SQLITE_STMTSTATUS_VM_STEP,
        ffi::SQLITE_STMTSTATUS_FULLSCAN_STEP,
        ffi::SQLITE_STMTSTATUS_SORT,
        ffi::SQLITE_STMTSTATUS_AUTOINDEX,
    ];
    for (i, op) in ops.into_iter().enumerate() {
        let n = unsafe {
            ffi::sqlite3_stmt_status(
                statement.cast(),
                op,
                i32::from(event == ffi::SQLITE_TRACE_STMT as u32),
            )
        };
        if event == ffi::SQLITE_TRACE_PROFILE as u32 && cost.phase < 2 {
            // Optional per-statement diagnosis on synthetic fixtures only.
            // SQL has bound parameter markers, never expanded values.
            static DETAIL: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();
            let threshold = *DETAIL.get_or_init(|| {
                std::env::var("READ_COST_SQL_DETAIL")
                    .ok()
                    .and_then(|v| v.parse().ok())
            });
            if threshold.is_some_and(|t| i == 0 && n as u64 >= t) {
                let raw = unsafe { ffi::sqlite3_sql(statement.cast()) };
                if !raw.is_null() {
                    let sql = unsafe { std::ffi::CStr::from_ptr(raw) }.to_string_lossy();
                    eprintln!(
                        "READ_COST_STATEMENT {}",
                        serde_json::json!({"phase":cost.phase,"vm_step":n,"sql":sql.chars().take(400).collect::<String>()})
                    );
                }
            }
            if cost.phase == 0 {
                cost.staging[i] += n as u64;
            } else {
                cost.caller[i] += n as u64;
            }
        }
    }
    0
}
pub(crate) async fn attach(conn: &mut sqlx::SqliteConnection) -> Result<Option<usize>> {
    let Ok(cost) = COST.try_with(Clone::clone) else {
        return Ok(None);
    };
    cost.lock().unwrap().phase = 0;
    let mut handle = conn.lock_handle().await?;
    let context = Box::into_raw(Box::new(cost));
    // SAFETY: exclusive handle; context owned by trace registration until CLOSE.
    unsafe {
        ffi::sqlite3_trace_v2(
            handle.as_raw_handle().as_ptr(),
            (ffi::SQLITE_TRACE_STMT | ffi::SQLITE_TRACE_PROFILE | ffi::SQLITE_TRACE_CLOSE) as u32,
            Some(trace),
            context.cast(),
        );
    }
    Ok(Some(context as usize))
}
pub(crate) async fn staged(conn: &mut sqlx::SqliteConnection, probe: &Option<usize>) -> Result<()> {
    if probe.is_none() {
        return Ok(());
    }
    COST.with(|c| c.lock().unwrap().phase = 2);
    // Count physical TEMP cells only, including visibility and intermediate
    // copies. Views/lazy main lookups aren't staged bytes. Bytes are UTF-8
    // SQLite cell representations, excluding page/index/allocation overhead.
    let tables: Vec<String> =
        sqlx::query_scalar("SELECT name FROM sqlite_temp_master WHERE type='table' ORDER BY name")
            .fetch_all(&mut *conn)
            .await?;
    let mut rows = 0i64;
    let mut bytes = 0i64;
    for table in tables {
        let quoted = format!("\"{}\"", table.replace('"', "\"\""));
        let columns: Vec<String> = sqlx::query_scalar(&format!(
            "SELECT name FROM pragma_table_info('{table}', 'temp') ORDER BY cid"
        ))
        .fetch_all(&mut *conn)
        .await?;
        let lengths = columns
            .iter()
            .map(|c| {
                format!(
                    "coalesce(length(CAST(\"{}\" AS BLOB)),0)",
                    c.replace('"', "\"\"")
                )
            })
            .collect::<Vec<_>>()
            .join("+");
        let (n, b): (i64, i64) = sqlx::query_as(&format!(
            "SELECT count(*),coalesce(sum({lengths}),0) FROM temp.{quoted}"
        ))
        .fetch_one(&mut *conn)
        .await?;
        rows += n;
        bytes += b;
    }
    COST.with(|c| {
        let mut c = c.lock().unwrap();
        c.staged_rows += rows as u64;
        c.staged_bytes += bytes as u64;
        c.phase = 1;
    });
    Ok(())
}
pub(crate) async fn detach(conn: &mut sqlx::SqliteConnection, probe: Option<usize>) -> Result<()> {
    if let Some(context) = probe {
        let mut handle = conn.lock_handle().await?;
        // SAFETY: worker is idle under this lock; disable before freeing context.
        unsafe {
            ffi::sqlite3_trace_v2(
                handle.as_raw_handle().as_ptr(),
                0,
                None,
                std::ptr::null_mut(),
            );
            drop(Box::from_raw(context as *mut Arc<Mutex<Cost>>));
        }
    }
    Ok(())
}

#[tokio::test]
async fn statement_counters_include_finalized_statements_without_recounting_reuse() {
    use sqlx::{Connection, Executor};
    async fn run(persistent: bool, repetitions: usize) -> Cost {
        let mut conn = sqlx::SqliteConnection::connect("sqlite::memory:")
            .await
            .unwrap();
        let (_, cost) = measure(async {
            let probe = attach(&mut conn).await.unwrap();
            for _ in 0..repetitions {
                conn.execute(sqlx::query("SELECT 1 UNION ALL SELECT 2").persistent(persistent))
                    .await
                    .unwrap();
            }
            detach(&mut conn, probe).await.unwrap();
        })
        .await;
        cost
    }
    let once = run(false, 1).await;
    assert!(once.staging[0] > 0);
    assert_eq!(once.staging[1..], [0, 0, 0]);
    for persistent in [false, true] {
        assert_eq!(
            run(persistent, 2).await.staging,
            once.staging.map(|n| n * 2)
        );
    }
}

tokio::task_local! { static COMPARISON_BUDGET: (); }
/// Equivalence matrices compare semantics, not elapsed-time refusals: the
/// full-staging oracle deliberately does more work. Both paths get the same
/// generous limit; deadline-regression tests keep the product guards.
pub(crate) async fn with_comparison_budget<F: std::future::Future>(work: F) -> F::Output {
    COMPARISON_BUDGET.scope((), work).await
}

/// Counter benchmarks must finish the same work on slower hosts. This is only
/// active inside the observer/comparison scopes; ordinary tests retain product guards.
pub(crate) fn budget(normal: Duration) -> Duration {
    if active() || COMPARISON_BUDGET.try_with(|_| ()).is_ok() {
        Duration::from_secs(120)
    } else {
        normal
    }
}
