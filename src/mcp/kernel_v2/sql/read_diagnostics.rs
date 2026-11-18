//! Opt-in test evidence on the serving transaction, without changing its guard.
//! Plans contain closed SQL and placeholders; record IDs and names stay local.
use super::*;
use std::{
    cell::RefCell,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

#[derive(serde::Serialize)]
pub(crate) struct CandidateDiagnostic {
    kind: &'static str,
    trial_indexes: bool,
    input_count: usize,
    actual_staged_rows: u64,
    orphan_lookup_ids: usize,
    vm_ops_quantum: u64,
    production_staging_plan: Vec<PlanStep>,
    /// All measured SELECTs return IDs only. Hydration is not part of these
    /// comparisons. VM work is sampled in the existing PROGRESS_OPS quanta.
    phases: Vec<Phase>,
    error_class: Option<&'static str>,
}

#[derive(serde::Serialize)]
struct PlanStep {
    id: i64,
    parent: i64,
    detail: String,
}

#[derive(serde::Serialize)]
struct Phase {
    phase: &'static str,
    elapsed_us: u64,
    vm_ops: u64,
    rows: usize,
    unique_rows: usize,
    plan: Vec<PlanStep>,
    error_class: Option<&'static str>,
}

#[derive(Default)]
struct Evidence {
    trial_indexes: bool,
    progress: Option<Arc<AtomicU64>>,
    reports: Vec<CandidateDiagnostic>,
}

tokio::task_local! { static EVIDENCE: RefCell<Evidence>; }

/// Each concurrent worker must own its scope. Diagnostic queries consume the
/// existing staging deadline: this never resets/replaces the progress handler.
/// Use a separate diagnostic run, never primary latency measurements.
pub(crate) async fn with_candidate_diagnostics<F: std::future::Future>(
    trial_indexes: bool,
    work: F,
) -> (F::Output, Vec<CandidateDiagnostic>) {
    EVIDENCE
        .scope(
            RefCell::new(Evidence {
                trial_indexes,
                ..Default::default()
            }),
            async {
                let result = work.await;
                (
                    result,
                    EVIDENCE.with(|e| std::mem::take(&mut e.borrow_mut().reports)),
                )
            },
        )
        .await
}

/// Replace only the closed structural seek. A shape change must not silently
/// produce a supposed baseline/trial pair that exercises the same access path.
fn seek_variant(kind: &str, sql: &str, indexed: bool) -> Result<String> {
    if kind == "moves" {
        // Production now seeks logical destinations. Retain a forced old
        // record/seq scan for the same-snapshot comparison, and also accept
        // that old hint when diagnosing the retained all-moved baseline.
        let old = "INDEXED BY idx_kernel_record_moves";
        let current = "INDEXED BY idx_kernel_record_logical_homes";
        let needle = match (sql.matches(old).count(), sql.matches(current).count()) {
            (1, 0) => old,
            (0, 1) => current,
            _ => {
                return Err(Error::engine(
                    "candidate diagnostic move trial SQL shape changed",
                ))
            }
        };
        let replacement = if indexed {
            "INDEXED BY idx_trial_move_destinations"
        } else {
            old
        };
        return Ok(sql.replacen(needle, replacement, 1));
    }
    let (needle, replacement) = match (kind, indexed) {
        ("names", false) => (
            "main.kernel_record_fields f WHERE",
            "main.kernel_record_fields f NOT INDEXED WHERE",
        ),
        ("names", true) => (
            "main.kernel_record_fields f WHERE",
            "main.kernel_record_fields f INDEXED BY idx_trial_record_names WHERE",
        ),
        _ => return Err(Error::engine("unknown candidate diagnostic trial kind")),
    };
    if sql.matches(needle).count() != 1 {
        return Err(Error::engine(
            "candidate diagnostic trial SQL shape changed",
        ));
    }
    Ok(sql.replacen(needle, replacement, 1))
}

fn verify_trial_plans(report: &CandidateDiagnostic) -> Result<()> {
    let baseline = report
        .phases
        .iter()
        .find(|p| p.phase == "baseline_lookup_ids")
        .ok_or_else(|| Error::engine("candidate diagnostic baseline lookup plan missing"))?;
    let trial = report
        .phases
        .iter()
        .find(|p| p.phase == "trial_lookup_ids")
        .ok_or_else(|| Error::engine("candidate diagnostic trial lookup plan missing"))?;
    if report.kind == "names" && !baseline.plan.iter().any(|p| p.detail.contains("SCAN f")) {
        return Err(Error::engine(
            "candidate diagnostic name baseline did not scan fields",
        ));
    }
    let expected = if report.kind == "names" {
        "idx_trial_record_names"
    } else {
        "idx_trial_move_destinations"
    };
    if !trial
        .plan
        .iter()
        .any(|p| p.detail.contains("SEARCH") && p.detail.contains(expected))
    {
        return Err(Error::engine(
            "candidate diagnostic trial did not seek its expression index",
        ));
    }
    Ok(())
}

pub(super) fn active() -> bool {
    EVIDENCE.try_with(|_| ()).is_ok()
}

pub(super) fn register_progress(progress: &Arc<AtomicU64>) {
    let _ = EVIDENCE.try_with(|e| e.borrow_mut().progress = Some(progress.clone()));
}

fn classify(error: &Error) -> &'static str {
    let message = error.to_string();
    if message.contains("interrupted")
        || message.contains("deadline")
        || message.contains("timeout")
    {
        "timeout_or_interrupted"
    } else {
        "diagnostic_error"
    }
}

async fn plan(
    conn: &mut sqlx::SqliteConnection,
    sql: &str,
    actor: &str,
    input: &str,
) -> Result<Vec<PlanStep>> {
    sqlx::query(&format!("EXPLAIN QUERY PLAN {sql}"))
        .persistent(false)
        .bind(actor)
        .bind(input)
        .fetch_all(conn)
        .await?
        .into_iter()
        .map(|row| {
            Ok(PlanStep {
                id: row.try_get(0)?,
                parent: row.try_get(1)?,
                detail: row.try_get(3)?,
            })
        })
        .collect()
}

async fn measure(
    conn: &mut sqlx::SqliteConnection,
    report: &mut CandidateDiagnostic,
    progress: &AtomicU64,
    phase: &'static str,
    sql: &str,
    actor: &str,
    input: &str,
) -> Result<BTreeSet<String>> {
    // Planning is deliberately outside elapsed/VM measurements. Record an
    // interrupted EXPLAIN too, so deadline failure cannot look like zero work.
    let started = Instant::now();
    let before = progress.load(Ordering::Relaxed);
    let query_plan = plan(conn, sql, actor, input).await;
    if let Err(error) = query_plan {
        report.phases.push(Phase {
            phase,
            elapsed_us: started.elapsed().as_micros() as u64,
            vm_ops: progress.load(Ordering::Relaxed).saturating_sub(before),
            rows: 0,
            unique_rows: 0,
            plan: Vec::new(),
            error_class: Some("explain_failed"),
        });
        return Err(error);
    }
    let query_plan = query_plan?;
    let before = progress.load(Ordering::Relaxed);
    let started = Instant::now();
    let result = sqlx::query_scalar::<_, String>(sql)
        .persistent(false)
        .bind(actor)
        .bind(input)
        .fetch_all(conn)
        .await
        .map_err(Error::from);
    let elapsed_us = started.elapsed().as_micros() as u64;
    let vm_ops = progress.load(Ordering::Relaxed).saturating_sub(before);
    let unique_rows = result
        .as_ref()
        .map_or(0, |rows| rows.iter().collect::<BTreeSet<_>>().len());
    report.phases.push(Phase {
        phase,
        elapsed_us,
        vm_ops,
        rows: result.as_ref().map_or(0, Vec::len),
        unique_rows,
        plan: query_plan,
        error_class: result.as_ref().err().map(classify),
    });
    Ok(result?.into_iter().collect())
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn on_candidates(
    conn: &mut sqlx::SqliteConnection,
    actor: &str,
    kind: &'static str,
    input: &str,
    candidates: &str,
    visibility: &str,
    production_staging: &str,
    actual_staged_rows: u64,
) -> Result<()> {
    let progress = EVIDENCE
        .with(|e| e.borrow().progress.clone())
        .ok_or_else(|| Error::engine("candidate diagnostic missing composed progress counter"))?;
    let trial_indexes = EVIDENCE.with(|e| e.borrow().trial_indexes);
    let mut report = CandidateDiagnostic {
        kind,
        trial_indexes,
        input_count: serde_json::from_str::<Vec<Value>>(input)?.len(),
        actual_staged_rows,
        orphan_lookup_ids: 0,
        vm_ops_quantum: guard::PROGRESS_OPS as u64,
        production_staging_plan: Vec::new(),
        phases: Vec::new(),
        error_class: None,
    };
    let outcome = async {
        report.production_staging_plan = plan(conn, production_staging, actor, input).await?;
        let lookup = match kind {
            "names" => "SELECT f.record_id FROM main.kernel_record_fields f WHERE f.name IN ('title','name') AND json_extract(f.value_json,'$') COLLATE BINARY IN (SELECT value FROM json_each(?2))",
            "moves" => "SELECT record_id FROM main.content_events INDEXED BY idx_kernel_record_logical_homes WHERE type IN ('kernel.record_rehomed.v1','kernel.record_rehomed.v2') AND json_extract(payload,'$.logical_home_id') IN (SELECT value FROM json_each(?2))",
            _ => return Err(Error::engine("unknown candidate diagnostic kind")),
        };
        let lookup_ids = measure(conn, &mut report, &progress, "lookup_ids", lookup, actor, input).await?;
        let lookup_input = serde_json::to_string(&lookup_ids)?;
        let live_lookup = measure(conn, &mut report, &progress, "lookup_live_ids",
            "SELECT r.id FROM main.kernel_records r WHERE r.id IN (SELECT value FROM json_each(?2))",
            actor, &lookup_input).await?;
        report.orphan_lookup_ids = lookup_ids.len().saturating_sub(live_lookup.len());
        let union_sql = format!("SELECT r.id FROM main.kernel_records r WHERE ({candidates})");
        let candidate_ids = measure(conn, &mut report, &progress, "complete_candidate_ids", &union_sql, actor, input).await?;
        if !live_lookup.is_subset(&candidate_ids) {
            return Err(Error::engine("candidate diagnostic lookup escaped complete candidates"));
        }
        let materialized = serde_json::to_string(&candidate_ids)?;
        let authority_sql = format!("SELECT r.id FROM main.kernel_records r WHERE r.id IN (SELECT value FROM json_each(?2)) AND ({visibility})");
        let authorized = measure(conn, &mut report, &progress, "authority_over_candidate_ids", &authority_sql, actor, &materialized).await?;
        let combined_sql = format!("SELECT r.id FROM main.kernel_records r WHERE ({candidates}) AND ({visibility})");
        let combined = measure(conn, &mut report, &progress, "combined_ids", &combined_sql, actor, input).await?;
        if trial_indexes {
            // The root fixture creates disposable indexes before dispatch.
            // Original phases above describe the actual current planner choice,
            // which may already use the name index when one is present. These
            // forced pairs establish the old/new access paths independently.
            for (indexed, lookup_phase, candidate_phase, combined_phase) in [
                (false, "baseline_lookup_ids", "baseline_complete_candidate_ids", "baseline_combined_ids"),
                (true, "trial_lookup_ids", "trial_complete_candidate_ids", "trial_combined_ids"),
            ] {
                let lookup_sql = seek_variant(kind, lookup, indexed)?;
                let paired_lookup = measure(conn, &mut report, &progress, lookup_phase, &lookup_sql, actor, input).await?;
                let paired_candidates = seek_variant(kind, candidates, indexed)?;
                let candidate_sql = format!("SELECT r.id FROM main.kernel_records r WHERE ({paired_candidates})");
                let paired_candidate_ids = measure(conn, &mut report, &progress, candidate_phase, &candidate_sql, actor, input).await?;
                let paired_sql = format!("SELECT r.id FROM main.kernel_records r WHERE ({paired_candidates}) AND ({visibility})");
                let paired_combined = measure(conn, &mut report, &progress, combined_phase, &paired_sql, actor, input).await?;
                if paired_lookup != lookup_ids || paired_candidate_ids != candidate_ids || paired_combined != combined {
                    return Err(Error::engine("candidate diagnostic baseline/trial ID mismatch"));
                }
            }
            verify_trial_plans(&report)?;
        }
        // Actual serving staging ran immediately before this callback, before
        // any dependency expansion. Keep its ID set as an independent oracle.
        let staged: BTreeSet<String> = sqlx::query_scalar("SELECT id FROM temp._v2_visible")
            .fetch_all(&mut *conn).await?.into_iter().collect();
        if authorized != combined || combined != staged || staged.len() as u64 != actual_staged_rows {
            return Err(Error::engine("candidate diagnostic authority/combined/staging mismatch"));
        }
        Ok(())
    }.await;
    report.error_class = outcome.as_ref().err().map(classify);
    EVIDENCE.with(|e| e.borrow_mut().reports.push(report));
    outcome
}

/// Opt-in session boundaries. These probes execute additional read-only SQL;
/// their elapsed/VM overhead is not a production latency measurement.
#[derive(serde::Serialize)]
pub(crate) struct SessionLifecycleSample {
    pub phase: &'static str,
    pub connection_id: Option<u64>,
    pub cache_count_before_probe: usize,
    pub cache_count_after_probe: usize,
    pub main_schema_cookie: Option<i64>,
    pub temp_schema_cookie: Option<i64>,
    pub temp_user_objects: Option<i64>,
    pub autocommit: Option<bool>,
    /// Cleanup qualification only; this does not acknowledge pool release.
    pub reusable: Option<bool>,
    pub probe_us: u64,
    pub error: Option<String>,
}

tokio::task_local! {
    static SESSION_LIFECYCLE: RefCell<Vec<SessionLifecycleSample>>;
}

pub(crate) async fn with_session_lifecycle<F: std::future::Future>(
    work: F,
) -> (F::Output, Vec<SessionLifecycleSample>) {
    SESSION_LIFECYCLE
        .scope(RefCell::new(Vec::new()), async {
            let result = work.await;
            let samples =
                SESSION_LIFECYCLE.with(|samples| std::mem::take(&mut *samples.borrow_mut()));
            (result, samples)
        })
        .await
}

pub(super) async fn observe_session(
    conn: &mut sqlx::SqliteConnection,
    phase: &'static str,
    reusable: Option<bool>,
) {
    if SESSION_LIFECYCLE.try_with(|_| ()).is_err() {
        return;
    }
    use sqlx::Connection;
    let started = Instant::now();
    let mut sample = SessionLifecycleSample {
        phase,
        connection_id: None,
        cache_count_before_probe: 0,
        cache_count_after_probe: 0,
        main_schema_cookie: None,
        temp_schema_cookie: None,
        temp_user_objects: None,
        autocommit: None,
        reusable,
        probe_us: 0,
        error: None,
    };
    let result: Result<()> = async {
        sample.connection_id =
            Some(kernel::generic_links::diagnostics::connection_identity(conn).await?);
        // connection_identity takes SQLx's handle lock, waiting for preceding
        // worker commands to finish. A returned row alone does not synchronize
        // cached_statements_size's worker-published atomic count.
        sample.cache_count_before_probe = conn.cached_statements_size();
        {
            let mut handle = conn.lock_handle().await?;
            // SAFETY: this handle is exclusively locked and live. No trace or
            // progress callback is installed, removed or refreshed here.
            sample.autocommit = Some(unsafe {
                libsqlite3_sys::sqlite3_get_autocommit(handle.as_raw_handle().as_ptr()) != 0
            });
        }
        // fetch_all drives each statement through DONE; no partially consumed
        // metadata statement can spill into a later link trace observer.
        for (sql, output) in [
            ("PRAGMA main.schema_version", &mut sample.main_schema_cookie),
            ("PRAGMA temp.schema_version", &mut sample.temp_schema_cookie),
            (
                "SELECT count(*) FROM temp.sqlite_schema WHERE name NOT GLOB 'sqlite_*'",
                &mut sample.temp_user_objects,
            ),
        ] {
            let values: Vec<i64> = sqlx::query_scalar(sql)
                .persistent(false)
                .fetch_all(&mut *conn)
                .await?;
            if values.len() != 1 {
                return Err(Error::engine(
                    "session lifecycle metadata returned an unexpected row count",
                ));
            }
            *output = Some(values[0]);
        }
        // Wait for the last probe command's worker bookkeeping too. Ping runs
        // no SQL and neither prepares nor clears cached statements.
        conn.ping().await?;
        Ok(())
    }
    .await;
    sample.cache_count_after_probe = conn.cached_statements_size();
    sample.probe_us = started.elapsed().as_micros() as u64;
    sample.error = result.err().map(|error| error.to_string());
    // Preserve serving errors unchanged. The owning diagnostic must reject any
    // recorded probe error; absent metadata is never represented as a zero.
    SESSION_LIFECYCLE.with(|samples| samples.borrow_mut().push(sample));
}

#[cfg(test)]
mod session_lifecycle_tests {
    use super::*;
    use sqlx::Connection;

    #[tokio::test]
    async fn session_lifecycle_metadata_fences_pending_cache_publication() {
        let mut conn = sqlx::SqliteConnection::connect(":memory:").await.unwrap();
        let before = conn.cached_statements_size();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let mut entered_tx = Some(entered_tx);
        conn.lock_handle()
            .await
            .unwrap()
            .set_progress_handler(1, move || {
                if let Some(entered_tx) = entered_tx.take() {
                    let _ = entered_tx.send(());
                    // Hold the worker after preparing a new cached statement but
                    // before it can publish its atomic cache count. A dropped
                    // sender also releases it if an assertion fails.
                    let _ = release_rx.recv();
                }
                true
            });
        {
            let query = sqlx::query_scalar::<_, i64>("SELECT ?1")
                .bind(1_i64)
                .fetch_all(&mut conn);
            tokio::pin!(query);
            tokio::select! {
                entered = entered_rx => entered.unwrap(),
                result = &mut query => panic!("worker did not pause: {result:?}"),
            }
            // Cancel the caller while its worker is still inside SQLite.
        }
        assert_eq!(conn.cached_statements_size(), before);
        let (_, samples) = with_session_lifecycle(async {
            let observation = observe_session(&mut conn, "pending_cache", None);
            tokio::pin!(observation);
            assert!(futures::poll!(&mut observation).is_pending());
            release_tx.send(()).unwrap();
            observation.await;
        })
        .await;
        conn.lock_handle().await.unwrap().remove_progress_handler();
        assert_eq!(samples.len(), 1);
        assert!(samples[0].error.is_none(), "{:?}", samples[0].error);
        assert_eq!(samples[0].cache_count_before_probe, before + 1);
        assert_eq!(samples[0].cache_count_after_probe, before + 1);
        conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn session_lifecycle_waits_for_prior_statement_cache_publication() {
        use futures::TryStreamExt;
        let mut conn = sqlx::SqliteConnection::connect(":memory:").await.unwrap();
        let (entered_tx, mut entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let mut entered_tx = Some(entered_tx);
        conn.lock_handle()
            .await
            .unwrap()
            .set_progress_handler(1000, move || {
                if let Some(tx) = entered_tx.take() {
                    tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                }
                true
            });
        // Hold the SQLx worker inside a newly cached query, before it publishes
        // its cache count. Drain rows until the controlled worker gate is armed.
        let mut rows = sqlx::query("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<10000) SELECT x FROM n")
            .fetch(&mut conn);
        loop {
            tokio::select! {
                result = &mut entered_rx => { result.unwrap(); break; }
                row = rows.try_next() => { assert!(row.unwrap().is_some()); }
            }
        }
        drop(rows);
        assert_eq!(conn.cached_statements_size(), 0);
        let mut probe = Box::pin(with_session_lifecycle(async {
            observe_session(&mut conn, "after_rows", None).await;
        }));
        // Drive the observer to its worker synchronization point before allowing
        // the preceding query to finish. No timing or scheduler luck is needed.
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(probe.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        release_tx.send(()).unwrap();
        let (_, samples) = probe.await;
        assert_eq!(samples.len(), 1);
        assert!(samples[0].error.is_none(), "{:?}", samples[0].error);
        assert_eq!(samples[0].cache_count_before_probe, 1);
        assert_eq!(samples[0].cache_count_after_probe, 1);
        conn.lock_handle().await.unwrap().remove_progress_handler();
        conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn session_lifecycle_metadata_preserves_cache_and_reports_read_errors() {
        let mut conn = sqlx::SqliteConnection::connect(":memory:").await.unwrap();
        let _: Vec<i64> = sqlx::query_scalar("SELECT ?1")
            .bind(1_i64)
            .fetch_all(&mut conn)
            .await
            .unwrap();
        drop(conn.lock_handle().await.unwrap());
        let before = conn.cached_statements_size();
        assert!(before > 0);
        let (_, samples) = with_session_lifecycle(async {
            observe_session(&mut conn, "before", None).await;
            conn.lock_handle()
                .await
                .unwrap()
                .set_progress_handler(1, || false);
            observe_session(&mut conn, "interrupted", None).await;
            conn.lock_handle().await.unwrap().remove_progress_handler();
        })
        .await;
        assert_eq!(samples.len(), 2);
        assert!(samples[0].error.is_none());
        assert_eq!(samples[0].autocommit, Some(true));
        assert_eq!(samples[0].temp_user_objects, Some(0));
        assert_eq!(samples[0].cache_count_before_probe, before);
        assert_eq!(samples[0].cache_count_after_probe, before);
        assert_eq!(samples[0].connection_id, samples[1].connection_id);
        assert!(samples[0].connection_id.is_some());
        assert!(samples[1]
            .error
            .as_deref()
            .is_some_and(|e| e.contains("interrupted")));
        assert!(samples[1].main_schema_cookie.is_none());
        conn.close().await.unwrap();
    }
}
