#![cfg(feature = "turso-tests")]
//! Deterministic local Turso contract, runtime and qualification (ci lane `turso-local`).
//!
//! Every `mod` below was previously its own `tests/*.rs` target. Cargo links
//! one test binary per target against the whole dependency graph, and those
//! link steps are not cacheable, so the suite is grouped into a few binaries
//! instead of a hundred. The tests themselves are unchanged; they now share a
//! process with their neighbours.

mod common;
mod contract;
#[allow(dead_code)]
#[path = "contract/corpus.rs"]
mod corpus;

#[path = "turso/attachment_contract.rs"]
mod attachment_contract;
#[path = "turso/corpus_turso.rs"]
mod corpus_turso;
#[path = "turso/facets_contract.rs"]
mod facets_contract;
#[path = "turso/identity_contract.rs"]
mod identity_contract;
#[path = "turso/logical_query_contract.rs"]
mod logical_query_contract;
#[path = "turso/turso_checkpoint_semantics.rs"]
mod turso_checkpoint_semantics;
#[path = "turso/turso_contract.rs"]
mod turso_contract;
#[path = "turso/turso_profile_probe.rs"]
mod turso_profile_probe;
#[path = "turso/turso_request_pipeline.rs"]
mod turso_request_pipeline;
#[path = "turso/turso_runtime.rs"]
mod turso_runtime;
#[path = "turso/views_history_contract.rs"]
mod views_history_contract;
