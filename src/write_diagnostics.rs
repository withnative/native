//! Payload-free write attribution. Context is copied explicitly into owned jobs
//! and retained on leases; task locals alone do not survive spawn/pool release.
use std::{future::Future, sync::Arc, time::Duration};

use std::time::Instant;

pub(crate) const SLOW: Duration = Duration::from_secs(1);

#[derive(Clone, Debug)]
pub(crate) struct Context(Arc<Attribution>);
#[derive(Debug)]
struct Attribution {
    attempt: String,
    operation: &'static str,
    request: Option<String>,
    retry: Option<String>,
}

tokio::task_local! { static CURRENT: Context; }

impl Context {
    pub(crate) fn new(
        operation: &'static str,
        request: Option<String>,
        retry: Option<String>,
    ) -> Self {
        Self(Arc::new(Attribution {
            attempt: uuid::Uuid::new_v4().to_string(),
            operation,
            request,
            retry,
        }))
    }
    #[cfg(feature = "v2-kernel-probe")]
    pub(crate) fn labelled(self, operation: &'static str) -> Self {
        if self.0.operation == operation {
            return self;
        }
        Self(Arc::new(Attribution {
            attempt: self.0.attempt.clone(),
            operation,
            request: self.0.request.clone(),
            retry: self.0.retry.clone(),
        }))
    }
    pub(crate) fn background(operation: &'static str) -> Self {
        let parent = current();
        Self::new(
            operation,
            parent.as_ref().and_then(|c| c.0.request.clone()),
            parent.as_ref().and_then(|c| c.0.retry.clone()),
        )
    }
    pub(crate) async fn scope<F: Future>(&self, work: F) -> F::Output {
        CURRENT.scope(self.clone(), work).await
    }
    pub(crate) fn fields(&self) -> String {
        format!(
            "operation={} attempt={} request={} retry={}",
            self.0.operation,
            self.0.attempt,
            self.0.request.as_deref().unwrap_or("none"),
            self.0.retry.as_deref().unwrap_or("none")
        )
    }
}
/// Diagnostic output must never turn a successful operation into a failure.
pub(crate) fn emit(line: &str) {
    use std::io::Write;
    let _ = writeln!(std::io::stderr().lock(), "{line}");
}

pub(crate) fn current() -> Option<Context> {
    CURRENT.try_with(Clone::clone).ok()
}

// Labels come only from this bounded server-side vocabulary, never raw names.
pub(crate) fn operation_label(name: &str) -> &'static str {
    match name {
        "update_record" => "update_record",
        "create_record" => "create_record",
        "set_intent" => "set_intent",
        "bootstrap" => "bootstrap",
        "manage_saved_tabs" => "saved_tabs",
        _ => "other",
    }
}

pub(crate) struct Timer {
    context: Option<Context>,
    phase: &'static str,
    started: Instant,
    outcome: &'static str,
}
impl Timer {
    pub(crate) fn new(phase: &'static str) -> Self {
        Self {
            context: current(),
            phase,
            started: Instant::now(),
            outcome: "incomplete",
        }
    }
    pub(crate) fn finish(mut self, outcome: &'static str) {
        self.outcome = outcome;
    }
    fn line(&self, elapsed: Duration) -> Option<String> {
        if crate::write_contention::uses_bounded_diagnostics() {
            return None;
        }
        let context = self.context.as_ref()?;
        (elapsed >= SLOW).then(|| {
            format!(
                "write_stage {} phase={} elapsed_ms={} outcome={}",
                context.fields(),
                self.phase,
                elapsed.as_millis(),
                self.outcome
            )
        })
    }
}
impl Drop for Timer {
    fn drop(&mut self) {
        if let Some(line) = self.line(self.started.elapsed()) {
            emit(&line);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn owned_attempt_survives_waiter_drop_and_retry_is_separate() {
        let first = Context::new(
            "update_record",
            Some("h1_request1".into()),
            Some("h1_key".into()),
        );
        let retry = Context::new(
            "update_record",
            Some("h1_request2".into()),
            Some("h1_key".into()),
        );
        let (send, recv) = tokio::sync::oneshot::channel::<()>();
        let (ready, wait_ready) = tokio::sync::oneshot::channel();
        let (release, wait_release) = tokio::sync::oneshot::channel();
        let owner = first.clone();
        let task = tokio::spawn(async move {
            owner
                .scope(async {
                    ready.send(()).unwrap();
                    wait_release.await.unwrap();
                    let timer = Timer::new("sqlite_commit_ack");
                    let _ = send.send(());
                    timer.line(SLOW).unwrap()
                })
                .await
        });
        wait_ready.await.unwrap();
        drop(recv);
        let other = retry.scope(async { current().unwrap().fields() }).await;
        release.send(()).unwrap();
        let line = task.await.unwrap();
        assert!(line.contains(&first.fields()));
        assert!(!line.contains("h1_request2"));
        assert_ne!(first.0.attempt, retry.0.attempt);
        assert!(other.contains("retry=h1_key"));
        assert!(current().is_none());
    }
    #[tokio::test]
    async fn timers_are_thresholded_and_preserve_failure_without_payload() {
        Context::new("other", None, None)
            .scope(async {
                let timer = Timer::new("sqlite_commit_ack");
                assert!(timer.line(SLOW - Duration::from_nanos(1)).is_none());
                let line = timer.line(SLOW).unwrap();
                assert!(line.contains("outcome=incomplete"));
                assert!(!line.contains("PRIVATE"));
                timer.finish("uncertain");
            })
            .await;
        assert!(Timer::new("sqlite_commit_ack").line(SLOW).is_none());
        assert_eq!(operation_label("PRIVATE_body_or_path"), "other");
    }
}
