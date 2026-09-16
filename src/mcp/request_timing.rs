//! Request-local phase timing for the hosted plain-JSON tool adapter.
//!
//! The registry and domain lifecycle remain transport-neutral: when a hosted
//! adapter installs a timing scope they publish phase boundaries into it;
//! every other transport pays only a failed task-local lookup.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

tokio::task_local! {
    static CURRENT: RequestTiming;
}

#[derive(Clone, Debug)]
pub struct RequestTiming(Arc<Mutex<State>>);

#[derive(Debug)]
struct State {
    started: Instant,
    connect: Option<Duration>,
    dispatch: Option<Duration>,
    pre_handler: Option<Duration>,
    handler: Option<Duration>,
    capture_enqueue: Option<Duration>,
}

impl RequestTiming {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(State {
            started: Instant::now(),
            connect: None,
            dispatch: None,
            pre_handler: None,
            handler: None,
            capture_enqueue: None,
        })))
    }

    pub async fn scope<F: Future>(&self, future: F) -> F::Output {
        CURRENT.scope(self.clone(), future).await
    }

    pub fn connect_complete(&self) {
        let mut state = self.0.lock().expect("request timing mutex poisoned");
        state.connect = Some(state.started.elapsed());
    }

    pub fn server_timing(&self) -> String {
        let state = self.0.lock().expect("request timing mutex poisoned");
        let mut values = vec![metric("total", state.started.elapsed())];
        if let Some(value) = state.connect {
            values.push(metric("connect", value));
        }
        if let Some(value) = state.dispatch {
            values.push(metric("dispatch", value));
        }
        if let Some(value) = state.pre_handler {
            values.push(metric("pre_handler", value));
        }
        if let Some(value) = state.handler {
            values.push(metric("handler", value));
        }
        if let Some(value) = state.capture_enqueue {
            values.push(metric("capture_enqueue", value));
        }
        values.join(", ")
    }

    pub fn connected(&self) -> bool {
        self.0
            .lock()
            .expect("request timing mutex poisoned")
            .connect
            .is_some()
    }
}

impl Default for RequestTiming {
    fn default() -> Self {
        Self::new()
    }
}

fn metric(name: &str, duration: Duration) -> String {
    format!("{name};dur={:.3}", duration.as_secs_f64() * 1_000.0)
}

pub fn pre_handler_complete() {
    let _ = CURRENT.try_with(|timing| {
        let mut state = timing.0.lock().expect("request timing mutex poisoned");
        if state.pre_handler.is_none() {
            state.pre_handler = Some(state.started.elapsed());
        }
    });
}

pub async fn handler<F: Future>(future: F) -> F::Output {
    let started = CURRENT.try_with(|_| Instant::now()).ok();
    let output = future.await;
    if let Some(started) = started {
        let _ = CURRENT.try_with(|timing| {
            timing
                .0
                .lock()
                .expect("request timing mutex poisoned")
                .handler = Some(started.elapsed());
        });
    }
    output
}

/// Time registry dispatch, including pre-handler work, the handler, and
/// interaction-capture submission. This intentionally overlaps those metrics.
pub async fn dispatch<F: Future>(future: F) -> F::Output {
    let started = CURRENT.try_with(|_| Instant::now()).ok();
    let output = future.await;
    if let Some(started) = started {
        let _ = CURRENT.try_with(|timing| {
            timing
                .0
                .lock()
                .expect("request timing mutex poisoned")
                .dispatch = Some(started.elapsed());
        });
    }
    output
}

pub async fn capture_enqueue<F: Future>(future: F) -> F::Output {
    let started = CURRENT.try_with(|_| Instant::now()).ok();
    let output = future.await;
    if let Some(started) = started {
        let _ = CURRENT.try_with(|timing| {
            timing
                .0
                .lock()
                .expect("request timing mutex poisoned")
                .capture_enqueue = Some(started.elapsed());
        });
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn concurrent_scopes_do_not_share_phase_state() {
        let first = RequestTiming::new();
        let second = RequestTiming::new();
        let barrier = tokio::sync::Barrier::new(2);
        let ((), ()) = tokio::join!(
            first.scope(async {
                pre_handler_complete();
                barrier.wait().await;
            }),
            second.scope(async {
                capture_enqueue(async {
                    barrier.wait().await;
                })
                .await;
            }),
        );
        assert!(first.server_timing().contains("pre_handler;dur="));
        assert!(!first.server_timing().contains("capture_enqueue;dur="));
        assert!(second.server_timing().contains("capture_enqueue;dur="));
        assert!(!second.server_timing().contains("pre_handler;dur="));
    }

    #[tokio::test]
    async fn post_connect_early_response_has_only_completed_phases() {
        let timing = RequestTiming::new();
        timing.scope(async { timing.connect_complete() }).await;
        let header = timing.server_timing();
        assert!(header.starts_with("total;dur="));
        assert!(header.contains(", connect;dur="));
        assert!(!header.contains("dispatch;dur="));
        assert!(!header.contains("handler;dur="));
        assert!(!header.contains("capture_enqueue;dur="));
    }
}
