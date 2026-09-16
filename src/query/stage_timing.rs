//! Optional, content-free query-stage clocks for artifact input resolution.
//!
//! Collection-port `include_timing` needs to split membership, authorization
//! and redaction without changing the pipeline's return value. Callers that
//! never enter [`collect`] see a no-op: the accumulators are task-local and
//! [`add_authorization`] / [`add_redaction`] ignore an absent scope.

use std::cell::RefCell;
use std::future::Future;
use std::time::Instant;

#[derive(Clone, Copy, Debug, Default)]
pub struct QueryStageTimings {
    pub authorization_micros: u64,
    pub redaction_micros: u64,
}

tokio::task_local! {
    static QUERY_STAGE: RefCell<QueryStageTimings>;
}

pub async fn collect<F>(fut: F) -> (F::Output, QueryStageTimings)
where
    F: Future,
{
    QUERY_STAGE
        .scope(RefCell::new(QueryStageTimings::default()), async move {
            let value = fut.await;
            let timings = QUERY_STAGE.with(|cell| *cell.borrow());
            (value, timings)
        })
        .await
}

pub fn add_authorization(started: Instant) {
    add(|timings| {
        timings.authorization_micros = timings
            .authorization_micros
            .saturating_add(elapsed_micros(started));
    });
}

pub fn add_redaction(started: Instant) {
    add(|timings| {
        timings.redaction_micros = timings
            .redaction_micros
            .saturating_add(elapsed_micros(started));
    });
}

fn add(update: impl FnOnce(&mut QueryStageTimings)) {
    let _ = QUERY_STAGE.try_with(|cell| update(&mut cell.borrow_mut()));
}

fn elapsed_micros(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}
