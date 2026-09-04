#![recursion_limit = "256"]

//! Deterministic, storage-independent artifact compiler and sandbox runtime.
//!
//! Database publication, dependency resolution, authorization, and MCP error
//! mapping remain in the `native-ce` artifact host. This crate accepts resolved
//! source and JSON inputs and owns only runtime-specific compilation, validation,
//! canonicalization, caching, and execution.

pub mod artifact_intents;
pub mod css;
pub mod mdx;
pub mod mdx_v2;
