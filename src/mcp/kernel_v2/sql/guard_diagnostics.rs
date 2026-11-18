//! Attribute actual VM deadline expiry without recording caller data or SQL.
use std::future::Future;
use std::time::{Duration, Instant};

type Shape = std::sync::Arc<std::sync::Mutex<&'static str>>;
tokio::task_local! { static QUERY_RECORD: Shape; }

/// The computed query_record shape label: a fixed static identifier chosen
/// from the narrowing branch actually selected (`p1_home`, `p2_ids`) or the
/// first structural reason a call falls back to full staging. Never caller
/// text, SQL, ids, names or values.
pub(super) async fn query_record<F: Future>(work: F) -> F::Output {
    QUERY_RECORD
        .scope(
            std::sync::Arc::new(std::sync::Mutex::new("unclassified")),
            work,
        )
        .await
}

/// Record the selected shape before any read session opens.
pub(super) fn set_query_record_shape(shape: &'static str) {
    let _ = QUERY_RECORD.try_with(|cell| *cell.lock().unwrap() = shape);
}

/// The selected narrowing plan fell back to full staging at runtime (its
/// candidate query yielded the duplicate-provider NULL row). Relabel so a
/// deadline here is not mistaken for slow narrowing; a guard already
/// constructed for this call shares the label and sees the change.
pub(super) fn mark_selected_plan_staged_in_full() {
    let _ = QUERY_RECORD.try_with(|cell| {
        let mut shape = cell.lock().unwrap();
        *shape = match *shape {
            "p1_home" => "p1_home_full",
            "p2_ids" => "p2_ids_full",
            other => other,
        };
    });
}

#[derive(Clone, Copy)]
pub(super) enum Stage {
    ComposedStaging,
    SnapshotHydration,
}
impl Stage {
    fn name(self) -> &'static str {
        match self {
            Self::ComposedStaging => "composed_staging",
            Self::SnapshotHydration => "snapshot_hydration",
        }
    }
}

/// Captures the task-local label before SQLite calls from its worker thread.
/// Only this guard's own expiry emits a line; a raw SQLITE_INTERRUPT elsewhere
/// is not evidence that this deadline fired. No query or error enters the type.
pub(super) struct VmDeadline {
    started: Instant,
    budget: Duration,
    stage: Stage,
    enabled: bool,
    shape: Option<Shape>,
    reported: bool,
    #[cfg(test)]
    capture: Option<std::sync::Arc<std::sync::Mutex<Vec<String>>>>,
}
impl VmDeadline {
    pub(super) fn new(started: Instant, budget: Duration, stage: Stage) -> Self {
        Self {
            started,
            budget,
            stage,
            enabled: QUERY_RECORD.try_with(|_| ()).is_ok(),
            shape: QUERY_RECORD.try_with(std::sync::Arc::clone).ok(),
            reported: false,
            #[cfg(test)]
            capture: CAPTURE.try_with(std::sync::Arc::clone).ok(),
        }
    }

    /// The same strict elapsed-time permit used by composed SQL before tracing.
    /// A callback may be called again during cleanup; report at most once.
    pub(super) fn evaluate(&mut self) -> (bool, Duration) {
        let elapsed = self.started.elapsed();
        let permit = elapsed < self.budget;
        if !permit && self.enabled && !self.reported {
            self.reported = true;
            let line = format!(
                "[native-ce] read_vm_deadline tool=query_record phase={} interrupt_source=vm_deadline elapsed_ms={} budget_ms={} shape={}",
                self.stage.name(),
                elapsed.as_millis(),
                self.budget.as_millis(),
                self.shape
                    .as_ref()
                    .map(|shape| *shape.lock().unwrap())
                    .unwrap_or("unclassified"),
            );
            eprintln!("{line}");
            #[cfg(test)]
            if let Some(capture) = &self.capture {
                capture.lock().unwrap().push(line);
            }
        }
        (permit, elapsed)
    }
}

#[cfg(test)]
tokio::task_local! {
    static CAPTURE: std::sync::Arc<std::sync::Mutex<Vec<String>>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::{Connection, SqliteConnection};
    use std::sync::{Arc, Mutex};

    fn assert_interrupted(error: sqlx::Error) {
        assert!(matches!(error, sqlx::Error::Database(e) if e.code().as_deref() == Some("9")));
    }

    #[tokio::test]
    async fn query_record_vm_guard_reports_actual_expiry_once_from_sqlite_worker() {
        let capture = Arc::new(Mutex::new(Vec::new()));
        let mut guard = CAPTURE
            .scope(
                capture.clone(),
                query_record(async {
                    set_query_record_shape("p2_ids");
                    VmDeadline::new(Instant::now(), Duration::ZERO, Stage::ComposedStaging)
                }),
            )
            .await;
        let mut connection = SqliteConnection::connect(":memory:").await.unwrap();
        connection
            .lock_handle()
            .await
            .unwrap()
            .set_progress_handler(1, move || guard.evaluate().0);
        for _ in 0..2 {
            assert_interrupted(
                sqlx::query("SELECT 1")
                    .execute(&mut connection)
                    .await
                    .unwrap_err(),
            );
        }
        let lines = capture.lock().unwrap();
        assert_eq!(lines.len(), 1, "one diagnostic per rejecting guard");
        let line = &lines[0];
        let prefix = "[native-ce] read_vm_deadline tool=query_record phase=composed_staging interrupt_source=vm_deadline elapsed_ms=";
        let elapsed = line
            .strip_prefix(prefix)
            .unwrap()
            .strip_suffix(" budget_ms=0 shape=p2_ids")
            .unwrap();
        assert!(!elapsed.is_empty() && elapsed.bytes().all(|b| b.is_ascii_digit()));
    }

    #[tokio::test]
    async fn query_record_vm_guard_reports_runtime_full_staging_of_a_selected_plan() {
        let capture = Arc::new(Mutex::new(Vec::new()));
        let mut guard = CAPTURE
            .scope(
                capture.clone(),
                query_record(async {
                    set_query_record_shape("p2_ids");
                    let guard =
                        VmDeadline::new(Instant::now(), Duration::ZERO, Stage::ComposedStaging);
                    // Candidate query yielded the duplicate-provider NULL row.
                    mark_selected_plan_staged_in_full();
                    guard
                }),
            )
            .await;
        let mut connection = SqliteConnection::connect(":memory:").await.unwrap();
        connection
            .lock_handle()
            .await
            .unwrap()
            .set_progress_handler(1, move || guard.evaluate().0);
        assert_interrupted(
            sqlx::query("SELECT 1")
                .execute(&mut connection)
                .await
                .unwrap_err(),
        );
        let lines = capture.lock().unwrap();
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].ends_with(" budget_ms=0 shape=p2_ids_full"),
            "{}",
            lines[0]
        );
    }

    #[tokio::test]
    async fn query_record_vm_guard_does_not_label_foreign_sqlite_interrupt() {
        let capture = Arc::new(Mutex::new(Vec::new()));
        let mut guard = CAPTURE
            .scope(
                capture.clone(),
                query_record(async {
                    VmDeadline::new(
                        Instant::now(),
                        Duration::from_secs(60),
                        Stage::SnapshotHydration,
                    )
                }),
            )
            .await;
        let mut connection = SqliteConnection::connect(":memory:").await.unwrap();
        connection
            .lock_handle()
            .await
            .unwrap()
            .set_progress_handler(1, move || guard.evaluate().0);
        sqlx::query("SELECT 1")
            .execute(&mut connection)
            .await
            .unwrap();
        // The same connection can be interrupted by another source. Code 9
        // alone must never be relabeled as our VM deadline.
        connection
            .lock_handle()
            .await
            .unwrap()
            .set_progress_handler(1, || false);
        assert_interrupted(
            sqlx::query("SELECT 1")
                .execute(&mut connection)
                .await
                .unwrap_err(),
        );
        assert!(capture.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn query_record_vm_guard_scope_does_not_leak_or_change_unscoped_expiry() {
        let capture = Arc::new(Mutex::new(Vec::new()));
        let mut guard = CAPTURE
            .scope(capture.clone(), async {
                query_record(async {}).await;
                VmDeadline::new(Instant::now(), Duration::ZERO, Stage::SnapshotHydration)
            })
            .await;
        let mut connection = SqliteConnection::connect(":memory:").await.unwrap();
        connection
            .lock_handle()
            .await
            .unwrap()
            .set_progress_handler(1, move || guard.evaluate().0);
        assert_interrupted(
            sqlx::query("SELECT 1")
                .execute(&mut connection)
                .await
                .unwrap_err(),
        );
        assert!(capture.lock().unwrap().is_empty());
    }
}
