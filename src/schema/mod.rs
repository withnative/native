//! Current schema DDL and executable contract.
//!
//! Stands up the frozen v1 schema (spec: Native doc 9561d43, `decided`) — all
//! tables, indexes, triggers, FTS5, and the dormant `embeddings` seam. Per
//! export constraint (note 6c7d211), `embeddings.vector` stays a plain BLOB: no
//! server-side native vector index until it round-trips to stock sqlite3.
//!
//! `DDL_STATEMENTS` is the ordered list of statements applied to a fresh
//! database. `contract` pins the frozen spine contract (types, relationships,
//! facet keys, DDL fingerprint) that `crate::conformance` enforces and successor
//! artifacts (tool-surface enumeration, runtime, forkers) derive from.

pub mod contract;
pub mod ddl;
// Most presentation helpers are consumed by optional backend adapters; the
// default build still uses the column-semantics subset for MCP orientation.
#[cfg_attr(
    not(any(feature = "postgres", feature = "turso-local")),
    allow(dead_code)
)]
pub(crate) mod discovery;

pub use contract::*;
pub use ddl::{
    spine_facet_column, CONTROL_PROJECTION_TABLES, DDL_STATEMENTS, DERIVATION_PROJECTION_TABLES,
    META_PROJECTION_TABLES, POLICY_PROJECTION_TABLES, PROJECTION_TABLES, SPINE_FACET_COLUMNS,
};
