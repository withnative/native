#![recursion_limit = "256"]

//! native-ce — portable community edition engine.
//!
//! Public entry point. The engine is event-authoritative (Fork A): every write
//! appends an event, and the content, meta, policy, and instruction-control projection tables are
//! maintained by app-layer projectors — never by ad-hoc UPDATEs. Because each
//! log is authoritative, its projections can be rebuilt and diffed
//! (`crate::conformance`) — drift is a failing test.
//!
//! The MCP tool surface is the contract (decision `e9f4b98`): hosted (Railway)
//! and self-host (Docker) are the two supported consumption surfaces, and both
//! speak it. This crate is not published (`publish = false`) and every Rust
//! item here — `pub` or not — is internal, with no stability promise; `pub`
//! commonly exists only so the integration tests in `tests/` can reach it.
//!
//! Build layers (goal ddd9b26):
//!   1. `schema`      — the FROZEN v1 DDL + spine contract (spec: Native doc 9561d43)
//!   2. `projector`   — the event -> projection fold (Fork A)
//!   3. `conformance` — the executable spine contract: closed types, open kind,
//!      spine facets/relationships, substrate boundary, and rebuild-and-diff
//!      replay equality (`cargo run --bin conformance`)
//!   + `db` / `store` — open a database and write to it (append-event-then-project)
//!   + `embed`         — the dormant `embed()` write-path seam semantic search
//!     will hang off later (decision 3bc7fd0); a no-op at v1

pub const ENGINE_NAME: &str = "native-ce";

/// The crate version. `0.0.0` until the manifest carries a real one — which is
/// why it is not, on its own, an answer to "what is running?".
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The source revision this binary was built from, stamped by `build.rs`
/// (task 142e0d2; env-only since task 1205e69). Resolved from
/// `NATIVE_CE_GIT_SHA` or `RAILWAY_GIT_COMMIT_SHA` — the deploy paths —
/// and `dev` everywhere else, deliberately including local builds inside a
/// git repository, so that commits never invalidate this crate.
///
/// This is what makes a running instance self-identifying. `railway up` records
/// no commit, so without it the deployed artifact corresponds to no revision.
pub const GIT_SHA: &str = env!("NATIVE_CE_GIT_SHA");

/// The complete source revision for release-admission identity binding.
/// `GIT_SHA` stays the compact human-facing value; this constant must be an
/// exact 40-hex revision before the release-only route can be enabled.
pub const FULL_GIT_SHA: &str = env!("NATIVE_CE_FULL_GIT_SHA");

/// Version and revision as one string — `0.0.0+abc123def456`, the semver
/// build-metadata form. For single-field consumers like MCP's `serverInfo`,
/// which has room for a version and nothing else; structured callers should
/// report `ENGINE_VERSION` and `GIT_SHA` separately.
pub fn engine_version_string() -> String {
    format!("{ENGINE_VERSION}+{GIT_SHA}")
}

// The HTML artifact surface lives in crates/artifact-html; these re-exports
// preserve the public `native_ce::artifact_html` / `native_ce::artifact_verify`
// paths byte-for-byte for every consumer.
pub use native_artifact_html::html as artifact_html;
pub use native_artifact_html::verify as artifact_verify;
pub mod attribution;
pub mod authorization;
mod authorization_revision;
pub mod awareness;
pub mod backup;
pub mod blob;
mod canonical_json;
pub mod canvas;
pub mod change_summary;
pub mod citations;
pub mod comments;
pub mod conformance;
pub mod contribution;
pub mod control;
#[cfg(test)]
mod control_tests;
pub mod db;
pub mod derivation;
pub mod domain_transaction;
pub mod embed;
mod error;
pub mod events;
pub mod export;
pub use native_federation as federation;
pub mod freshness;
pub mod generated;
pub mod identity;
pub(crate) mod instruction_templates;
pub(crate) mod instructions;
/// Canonical, backend-neutral logical export and atomic SQLite import.
pub mod interchange;
pub mod interpretation;
pub mod interventions;
pub mod mcp;
pub mod message_expectation;
pub mod meta;
pub mod migrations;
pub mod policy;
/// Bounded SQL portability for Native-owned relational statements.
///
/// Physical schema, concurrency, search, raw SQL, backup, and topology remain
/// backend-owned; this module is deliberately not a storage/CRUD abstraction.
pub mod portable_sql;
#[cfg(feature = "postgres")]
pub mod postgres;
pub mod projector;
pub mod provenance;
pub mod query;
pub mod realtime;
pub mod recipe;
pub(crate) use native_record_type_correction_kernel as record_type_correction;
pub mod record_images;
pub mod relationship;
pub mod route_error;
/// Run keys — validation, repair, suggestion, and the `actor` resolution rule
/// (spec `fbfaf25` §3.2–§3.4).
pub mod runkey;
pub mod schema;
pub mod standby;
pub mod standby_snapshot;
/// Verified, fail-closed storage target migration and rollback.
pub mod storage_migration;
pub mod storage_profile;
pub mod store;
pub(crate) mod suggestion_lifecycle;
#[cfg(feature = "turso-local")]
pub mod turso_local;
/// The run-key wordlists (task `cb6c9da`) and the distance function that makes a
/// mistyped key repairable rather than merely invalid. Static data plus one
/// metric; `crate::runkey` is the consumer.
pub mod wordlist;

pub use db::{
    apply_schema, create_database, create_database_named, open_database, open_database_at,
    open_existing_database, open_existing_database_at, probe_database, seed_content_tier,
    seed_content_tier_named, DatabaseVersionState, Db, CURRENT_ENGINE_SCHEMA_VERSION,
    SUPPORTED_ENGINE_SCHEMA_BASELINE,
};
pub use error::{DeploymentReadOnlyOperation, Error, Result};
pub use instructions::{
    MAX_BOOTSTRAP_CONTEXT_METADATA_BYTES, MAX_BOOTSTRAP_INSTRUCTION_ENTRIES,
    MAX_BOOTSTRAP_PENDING_OBLIGATIONS, MAX_RESOLVED_INSTRUCTION_BYTES,
};
