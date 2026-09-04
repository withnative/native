//! Engine kernel: append/project invariants, query, freshness, meta tiers and activity.
//!
//! Every `mod` below was previously its own `tests/*.rs` target. Cargo links
//! one test binary per target against the whole dependency graph, and those
//! link steps are not cacheable, so the suite is grouped into a few binaries
//! instead of a hundred. The tests themselves are unchanged; they now share a
//! process with their neighbours.

mod common;
mod contract;
#[path = "contract/corpus.rs"]
mod corpus;
mod freshness_contract;

#[path = "kernel/activity_query.rs"]
mod activity_query;
#[path = "kernel/as_of.rs"]
mod as_of;
#[path = "kernel/change_summaries.rs"]
mod change_summaries;
#[path = "kernel/corpus_sqlite.rs"]
mod corpus_sqlite;
#[path = "kernel/engine.rs"]
mod engine;
#[path = "kernel/engine_contract.rs"]
mod engine_contract;
#[path = "kernel/freshness_domain.rs"]
mod freshness_domain;
#[path = "kernel/freshness_kernel.rs"]
mod freshness_kernel;
#[path = "kernel/freshness_proof.rs"]
mod freshness_proof;
#[path = "kernel/freshness_runtime.rs"]
mod freshness_runtime;
#[path = "kernel/guards.rs"]
mod guards;
#[path = "kernel/invariants.rs"]
mod invariants;
#[path = "kernel/meta_events.rs"]
mod meta_events;
#[path = "kernel/meta_tier.rs"]
mod meta_tier;
#[path = "kernel/previous_seq.rs"]
mod previous_seq;
#[path = "kernel/query.rs"]
mod query;
#[path = "kernel/query_contract_compat.rs"]
mod query_contract_compat;
#[path = "kernel/robustness.rs"]
mod robustness;
#[path = "kernel/smoke.rs"]
mod smoke;
#[path = "kernel/whats_changed.rs"]
mod whats_changed;
#[path = "kernel/write_path.rs"]
mod write_path;
