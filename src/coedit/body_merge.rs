//! Compatibility re-export: the three-way body-merge algorithm now lives in
//! the `native-body-merge` crate (`crates/body-merge`). This module keeps the
//! existing `crate::coedit::body_merge::…` paths resolving for the home
//! `merge_body` operation and node lineage; new code should depend on
//! `native-body-merge` directly.
//!
//! Only the items the current callers use are re-exported.

#[cfg(any(
    test,
    feature = "v2-kernel-probe",
    all(unix, feature = "mcp-executor-prototype")
))]
pub(crate) use native_body_merge::Hunk;
#[cfg(all(unix, feature = "mcp-executor-prototype"))]
pub(crate) use native_body_merge::{hunks_between, merge_hunks};
#[cfg(any(test, feature = "v2-kernel-probe"))]
pub(crate) use native_body_merge::{merge_bodies, MergedClash};
