//! Request-local phase timing for the hosted plain-JSON tool adapter.
//!
//! The registry and domain lifecycle remain transport-neutral: when a hosted
//! adapter installs a timing scope they publish phase boundaries into it;
//! every other transport pays only a failed task-local lookup.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

tokio::task_local! {
    static CURRENT: RequestTiming;
}

#[derive(Clone, Debug)]
pub struct RequestTiming(Arc<Mutex<State>>, Arc<AtomicBool>);

#[derive(Debug)]
struct State {
    started: Instant,
    connect: Option<Duration>,
    dispatch: Option<Duration>,
    pre_handler: Option<Duration>,
    handler: Option<Duration>,
    capture_enqueue: Option<Duration>,
    write_wait: Option<Duration>,
    visible_set_lookups: Option<VisibleSetLookups>,
    m4_index_decisions: Option<M4IndexDecisions>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VisibleSetLookups {
    pub hits: u64,
    pub misses: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct M4IndexDecisions {
    pub hits: u64,
    pub fallbacks: u64,
}

impl RequestTiming {
    pub fn new() -> Self {
        Self(
            Arc::new(Mutex::new(State {
                started: Instant::now(),
                connect: None,
                dispatch: None,
                pre_handler: None,
                handler: None,
                capture_enqueue: None,
                write_wait: None,
                visible_set_lookups: None,
                m4_index_decisions: None,
            })),
            Arc::new(AtomicBool::new(false)),
        )
    }

    /// Enable aggregate cache and M4 index decisions for an opted-in hosted request.
    /// Ordinary requests leave the field absent and do not lock for counting.
    pub fn enable_visible_set_lookups(&self) {
        let mut state = self.0.lock().expect("request timing mutex poisoned");
        state.visible_set_lookups = Some(VisibleSetLookups::default());
        state.m4_index_decisions = Some(M4IndexDecisions::default());
        self.1.store(true, Ordering::Relaxed);
    }

    pub fn visible_set_lookups(&self) -> Option<VisibleSetLookups> {
        self.0
            .lock()
            .expect("request timing mutex poisoned")
            .visible_set_lookups
    }

    pub fn m4_index_decisions(&self) -> Option<M4IndexDecisions> {
        self.0
            .lock()
            .expect("request timing mutex poisoned")
            .m4_index_decisions
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
        if let Some(value) = state.write_wait {
            values.push(metric("write_wait", value));
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

/// Attribute one cache lookup to the current request, if measurement was
/// enabled. No principal, key, or record identifier enters the timing state.
pub(crate) fn record_visible_set_lookup(hit: bool) {
    let _ = CURRENT.try_with(|timing| {
        if !timing.1.load(Ordering::Relaxed) {
            return;
        }
        let mut state = timing.0.lock().expect("request timing mutex poisoned");
        if let Some(counts) = state.visible_set_lookups.as_mut() {
            if hit {
                counts.hits = counts.hits.saturating_add(1);
            } else {
                counts.misses = counts.misses.saturating_add(1);
            }
        }
    });
}

/// Record one successful M4 handler response. The call site decides whether
/// the final response used indexed data; candidates that later fall back are
/// counted as fallbacks. No identity or target enters this request-local state.
pub(crate) fn record_m4_index_decision(hit: bool) {
    let _ = CURRENT.try_with(|timing| {
        if !timing.1.load(Ordering::Relaxed) {
            return;
        }
        let mut state = timing.0.lock().expect("request timing mutex poisoned");
        if let Some(counts) = state.m4_index_decisions.as_mut() {
            if hit {
                counts.hits = counts.hits.saturating_add(1);
            } else {
                counts.fallbacks = counts.fallbacks.saturating_add(1);
            }
        }
    });
}

/// Let a handler avoid allocating a return-path witness on ordinary calls.
pub(crate) fn m4_index_measurement_enabled() -> bool {
    CURRENT
        .try_with(|timing| timing.1.load(Ordering::Relaxed))
        .unwrap_or(false)
}

impl Default for RequestTiming {
    fn default() -> Self {
        Self::new()
    }
}

fn metric(name: &str, duration: Duration) -> String {
    format!("{name};dur={:.3}", duration.as_secs_f64() * 1_000.0)
}

/// Add to this request's total time spent queueing for `BEGIN IMMEDIATE`.
///
/// Accumulated rather than set: a request can open several write transactions,
/// and the question the phase answers is how much of the request went to
/// waiting for the workspace writer, not which single wait was longest.
pub(crate) fn record_write_wait(wait: Duration) {
    let _ = CURRENT.try_with(|timing| {
        let mut state = timing.0.lock().expect("request timing mutex poisoned");
        state.write_wait = Some(state.write_wait.unwrap_or_default() + wait);
    });
}

// There is deliberately no `write_held` phase here to pair with `write_wait`.
// The critical section closes when SQLx returns the connection to its pool,
// which is not reliably this request's task, so a request-scoped phase would
// be absent far more often than it was present and its distribution would be
// whatever subset happened to land inline. The unbiased measurement is the
// process-wide aggregate in `crate::write_contention`, which observes every
// close regardless of task and publishes it to the log.

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
    use serde_json::{json, Value};

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

    #[tokio::test]
    async fn visible_set_lookups_are_opt_in_and_request_local() {
        let ordinary = RequestTiming::new();
        ordinary
            .scope(async {
                record_visible_set_lookup(true);
                record_m4_index_decision(true);
            })
            .await;
        assert_eq!(ordinary.visible_set_lookups(), None);
        assert_eq!(ordinary.m4_index_decisions(), None);

        let first = RequestTiming::new();
        let second = RequestTiming::new();
        first.enable_visible_set_lookups();
        second.enable_visible_set_lookups();
        let barrier = tokio::sync::Barrier::new(2);
        tokio::join!(
            first.scope(async {
                record_visible_set_lookup(false);
                record_m4_index_decision(false);
                barrier.wait().await;
                record_visible_set_lookup(true);
                record_m4_index_decision(true);
            }),
            second.scope(async {
                record_visible_set_lookup(false);
                record_m4_index_decision(false);
                barrier.wait().await;
                record_visible_set_lookup(false);
                record_m4_index_decision(false);
            }),
        );
        assert_eq!(
            first.visible_set_lookups(),
            Some(VisibleSetLookups { hits: 1, misses: 1 })
        );
        assert_eq!(
            second.visible_set_lookups(),
            Some(VisibleSetLookups { hits: 0, misses: 2 })
        );
        assert_eq!(
            first.m4_index_decisions(),
            Some(M4IndexDecisions {
                hits: 1,
                fallbacks: 1
            })
        );
        assert_eq!(
            second.m4_index_decisions(),
            Some(M4IndexDecisions {
                hits: 0,
                fallbacks: 2
            })
        );
    }

    #[tokio::test]
    async fn m4_handlers_report_final_path_once_per_successful_call() {
        use crate::authorization::{replace_explicit_policy, AllowEntry, Capability};
        use crate::mcp::{Caller, ToolRegistry};

        let db = crate::db::create_database(":memory:").await.unwrap();
        let mut registry = ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        let id = registry
            .call(
                db.clone(),
                Caller::local(),
                "create_record",
                json!({"type":"Collection", "kind":"folder", "name":"measurement root",
                       "reason":"M4 request-local index decision oracle"}),
            )
            .await
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned();
        replace_explicit_policy(
            &db,
            "test:m4-measurement",
            &id,
            vec![AllowEntry::account("acct:alice", Capability::View)],
        )
        .await
        .unwrap();

        let caller = Caller::authenticated("acct:alice");
        for (tool, args) in [
            ("get_record", json!({"ids":[id]})),
            ("get_structure", json!({"root_id":id,"max_depth":0})),
            (
                "manage_links",
                json!({"action":"list","record_id":id,"limit":1}),
            ),
            ("resolve_facets", json!({"record_id":id})),
        ] {
            let timing = RequestTiming::new();
            timing.enable_visible_set_lookups();
            let response: Value = timing
                .scope(registry.call(db.clone(), caller.clone(), tool, args))
                .await
                .unwrap();
            assert!(response.is_object(), "{tool}");
            assert_eq!(
                timing.m4_index_decisions(),
                Some(M4IndexDecisions {
                    hits: 1,
                    fallbacks: 0
                }),
                "{tool} must serve indexed data, not only extract a candidate"
            );
        }

        let timing = RequestTiming::new();
        timing.enable_visible_set_lookups();
        timing
            .scope(registry.call(
                db.clone(),
                caller.clone(),
                "resolve_facets",
                json!({"type":"Collection"}),
            ))
            .await
            .unwrap();
        assert_eq!(
            timing.m4_index_decisions(),
            Some(M4IndexDecisions::default()),
            "type-only facets never attempt the record index"
        );

        let timing = RequestTiming::new();
        timing.enable_visible_set_lookups();
        let missing = timing
            .scope(registry.call(
                db.clone(),
                caller.clone(),
                "get_record",
                json!({"ids":["a5000000-0000-4000-8000-000000000001"]}),
            ))
            .await
            .unwrap();
        assert_eq!(missing["records"][0]["status"], "not_found");
        assert_eq!(
            timing.m4_index_decisions(),
            Some(M4IndexDecisions {
                hits: 0,
                fallbacks: 1
            }),
            "extracting an index with no returned header is fallback"
        );

        let timing = RequestTiming::new();
        timing.enable_visible_set_lookups();
        timing
            .scope(registry.call(
                db.clone(),
                Caller::local(),
                "get_structure",
                json!({"root_id":id,"max_depth":0}),
            ))
            .await
            .unwrap();
        assert_eq!(
            timing.m4_index_decisions(),
            Some(M4IndexDecisions {
                hits: 0,
                fallbacks: 1
            }),
            "unsupported local structure path is governed"
        );
        db.close().await;
    }
}
