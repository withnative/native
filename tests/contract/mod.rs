//! Backend-neutral engine contract support.
//!
//! `scenarios` knows only the narrow [`ContractHarness`] interface. Backend
//! setup and conformance machinery live in `sqlite`, so adding another harness
//! does not require changing the observable scenarios.

mod harness;
#[cfg(feature = "postgres-tests")]
#[allow(dead_code)]
mod postgres;
#[allow(dead_code)]
pub mod scenarios;
#[allow(dead_code)]
mod sqlite;
#[cfg(feature = "turso-tests")]
#[allow(dead_code)]
mod turso;

pub use harness::{ContractHarness, DeliveredMessageFixture, TestCaller};
#[cfg(feature = "postgres-tests")]
#[allow(unused_imports)]
pub use postgres::PostgresHarness;
#[allow(unused_imports)]
pub use sqlite::SqliteHarness;
#[cfg(feature = "turso-tests")]
#[allow(unused_imports)]
pub use turso::TursoHarness;
