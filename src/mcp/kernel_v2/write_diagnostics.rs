//! Payload-free attribution of slow phases in an owned update_record call.
use std::future::Future;
use std::time::{Duration, Instant};

tokio::task_local! { static UPDATE_RECORD: (); }
const SLOW: Duration = Duration::from_secs(1);

/// Enter inside the owned future: the operation owner can outlive its caller.
pub(crate) async fn update_record<F: Future>(work: F) -> F::Output {
    let context = crate::write_diagnostics::current()
        .unwrap_or_else(|| crate::write_diagnostics::Context::new("update_record", None, None))
        .labelled("update_record");
    context.scope(UPDATE_RECORD.scope((), work)).await
}

#[derive(Clone, Copy)]
pub(crate) enum Stage {
    Ownership,
    Preflush,
    Begin,
    Mutation,
    InitialView,
    PreviousView,
    SourceBasis,
    Metadata,
    LiveBody,
    BodyEvent,
    BodyUpsert,
    SearchDelete,
    SearchInsert,
    Receipt,
    Validate,
    Commit,
}
impl Stage {
    fn name(self) -> &'static str {
        match self {
            Self::Ownership => "ownership",
            Self::Preflush => "preflush",
            Self::Begin => "begin",
            Self::Mutation => "mutation",
            Self::InitialView => "initial_view",
            Self::PreviousView => "previous_view",
            Self::SourceBasis => "source_basis",
            Self::Metadata => "metadata",
            Self::LiveBody => "live_body",
            Self::BodyEvent => "body_event",
            Self::BodyUpsert => "body_upsert",
            Self::SearchDelete => "search_delete",
            Self::SearchInsert => "search_insert",
            Self::Receipt => "receipt",
            Self::Validate => "validate",
            Self::Commit => "commit",
        }
    }
}

/// Observes only duration, including errors and cancellation. Nested phases
/// overlap; these are attribution spans, not additive transaction accounting.
pub(crate) async fn phase<F: Future>(stage: Stage, work: F) -> F::Output {
    let timer = Timer::new(stage);
    let result = work.await;
    drop(timer);
    result
}

pub(crate) struct Timer {
    stage: Stage,
    context: Option<crate::write_diagnostics::Context>,
    started: Option<Instant>,
    #[cfg(test)]
    capture: Option<std::sync::Arc<std::sync::Mutex<Vec<String>>>>,
}
impl Timer {
    pub(crate) fn new(stage: Stage) -> Self {
        Self {
            stage,
            context: crate::write_diagnostics::current(),
            started: UPDATE_RECORD.try_with(|_| Instant::now()).ok(),
            #[cfg(test)]
            capture: CAPTURE.try_with(std::sync::Arc::clone).ok(),
        }
    }
    fn line(&self, elapsed: Duration) -> Option<String> {
        (self.started.is_some() && elapsed >= SLOW).then(|| {
            format!(
                "[native-ce] write_phase tool=update_record phase={} elapsed_ms={} {}",
                self.stage.name(),
                elapsed.as_millis(),
                self.context
                    .as_ref()
                    .map(|c| c.fields())
                    .unwrap_or_default()
            )
        })
    }
}
impl Drop for Timer {
    fn drop(&mut self) {
        let Some(started) = self.started else { return };
        if let Some(line) = self.line(started.elapsed()) {
            crate::write_diagnostics::emit(&line);
            #[cfg(test)]
            if let Some(capture) = &self.capture {
                capture.lock().unwrap().push(line);
            }
        }
    }
}

#[cfg(test)]
tokio::task_local! {
    static CAPTURE: std::sync::Arc<std::sync::Mutex<Vec<String>>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn slow_write_phase_requires_operation_scope_and_numeric_threshold() {
        assert!(Timer::new(Stage::SearchDelete).line(SLOW).is_none());
        update_record(async {
            let timer = Timer::new(Stage::SearchDelete);
            assert!(timer.line(SLOW - Duration::from_nanos(1)).is_none());
            assert!(timer.line(SLOW).unwrap().starts_with(
                "[native-ce] write_phase tool=update_record phase=search_delete elapsed_ms=1000 operation=update_record attempt="));
        })
        .await;
        assert!(Timer::new(Stage::Commit).line(SLOW).is_none());
        let background = crate::write_diagnostics::Context::new("kernel_background", None, None);
        background
            .scope(update_record(async {
                assert!(Timer::new(Stage::Commit)
                    .line(SLOW)
                    .unwrap()
                    .contains("operation=update_record "));
            }))
            .await;
    }

    #[tokio::test]
    async fn slow_write_phase_preserves_results_without_formatting_private_errors() {
        let capture = Arc::new(Mutex::new(Vec::new()));
        let result: Result<u8, &str> = CAPTURE
            .scope(
                capture.clone(),
                update_record(phase(Stage::Mutation, async {
                    tokio::time::sleep(SLOW + Duration::from_millis(10)).await;
                    Err("PRIVATE_SQL_ARGUMENT_CREDENTIAL_ERROR")
                })),
            )
            .await;
        assert_eq!(result.unwrap_err(), "PRIVATE_SQL_ARGUMENT_CREDENTIAL_ERROR");
        {
            let lines = capture.lock().unwrap();
            assert_eq!(lines.len(), 1);
            assert!(lines[0].starts_with(
                "[native-ce] write_phase tool=update_record phase=mutation elapsed_ms="
            ));
            assert!(!lines[0].contains("PRIVATE"));
        }
        assert_eq!(update_record(phase(Stage::Commit, async { 42 })).await, 42);
    }

    #[tokio::test]
    async fn slow_write_phase_reports_drop_once_inside_owned_task_without_scope_leak() {
        let capture = Arc::new(Mutex::new(Vec::new()));
        let task_capture = capture.clone();
        tokio::spawn(async move {
            CAPTURE
                .scope(
                    task_capture,
                    update_record(async {
                        let mut timer = Timer::new(Stage::BodyEvent);
                        timer.started = Some(Instant::now() - SLOW);
                        drop(timer);
                    }),
                )
                .await;
        })
        .await
        .unwrap();
        let lines = capture.lock().unwrap();
        assert_eq!(lines.len(), 1);
        let elapsed = lines[0]
            .strip_prefix("[native-ce] write_phase tool=update_record phase=body_event elapsed_ms=")
            .unwrap();
        assert!(
            !elapsed.is_empty()
                && elapsed
                    .split_whitespace()
                    .next()
                    .unwrap()
                    .bytes()
                    .all(|b| b.is_ascii_digit())
        );
        assert!(Timer::new(Stage::BodyEvent).line(SLOW).is_none());
    }
}
