#![cfg(feature = "postgres-tests")]
//! Service-backed Postgres contract and runtime authority (ci lane `postgres`).
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

#[path = "postgres/attachment_contract.rs"]
mod attachment_contract;
#[path = "postgres/corpus_postgres.rs"]
mod corpus_postgres;
#[path = "postgres/facets_contract.rs"]
mod facets_contract;
#[path = "postgres/identity_contract.rs"]
mod identity_contract;
#[path = "postgres/logical_query_contract.rs"]
mod logical_query_contract;
#[path = "postgres/postgres_contract.rs"]
mod postgres_contract;
#[path = "postgres/postgres_query_sql_admission.rs"]
mod postgres_query_sql_admission;
#[path = "postgres/postgres_request_pipeline.rs"]
mod postgres_request_pipeline;
#[path = "postgres/postgres_runtime.rs"]
mod postgres_runtime;
#[path = "postgres/views_history_contract.rs"]
mod views_history_contract;
