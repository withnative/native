//! System / meta tier write API — `vocabularies`, `vocabulary_values` and
//! `schema_config`.
//!
//! EVENT-AUTHORITATIVE since decision ba9f97e: these three tables are
//! projections of the `meta_events` log, folded by `crate::projector::meta` and
//! verified by `crate::conformance::rebuild_and_diff_meta`. They were
//! direct-write at v1 (Fork C), which left the tier's history story half-built —
//! `schema_config` got a `version_lineage` column and vocabularies got nothing,
//! so a vocabulary's whole lifecycle left no trace at all.
//!
//! This is not a reversal of 982f4b2, which segregated the tier in the first
//! place. That decision mandated meta history "distinct from the content Event
//! log" precisely because schema evolution needs versioning content edit-history
//! cannot provide; it was simply only half-implemented. The log is separate, as
//! that decision required — what changed is that it now exists and is
//! authoritative. A non-authoritative changelog was the option deliberately NOT
//! taken: nothing fails when an advisory log is wrong, so it drifts silently,
//! and you discover at promotion time that you were never recording the right
//! events. Authority is what makes rebuild-and-diff a forcing function.
//!
//! This module is also where the v1 contract guards live (Native task e035091),
//! so the future `manage_vocabularies` / `manage_schema_config` tools inherit
//! enforcement instead of re-asserting it:
//!   - vocabulary lifecycle is propose/promote/deprecate/alias — no hard delete
//!     of seeded or referenced values/vocabularies (`vocabulary`)
//!   - engine-reserved facet keys (`archived`) are rejected from schema_config
//!     in either direction (`schema_config`)
//!
//! The guards stay at the WRITE path, never in the fold — see
//! `crate::projector::meta` for why replaying them would fail honest rebuilds.
//!
//! The low-level append path is intentionally not part of the public API:
//! callers must use the guarded vocabulary and schema-config operations.
//!
//! <!-- native-doctest-id: meta-append-private-api -->
//! ```compile_fail
//! use native_ce::meta::{append_meta, MetaAppendSpec};
//! ```

pub mod events;
pub mod kind;
mod log;
pub mod schema_config;
pub mod vocabulary;

pub use events::*;
pub use kind::*;
pub use log::read_all_meta_events;
pub use schema_config::*;
pub use vocabulary::*;
