//! Host-owned, account-private saved working slots.
//!
//! Executable maintenance: `native maintenance saved-tabs --db <canonical-v2.db>
//! --as <admin-account-binding>` (build with `v2-kernel-probe`). Stop the workspace
//! server first; this accepts existing marked canonical v2 files, including
//! activated workspaces, never a node local generation. Exact retries preserve
//! records and append no duplicate package events.
//!
//! Upgrade admission is explicit: run `kernel::prepare_v2_database`, install
//! `package()` with `kernel::install_package_as`, then adopt that exact identity
//! at `KERNEL_ROOT_ID` with `kernel::adopt_package_at`. Package installation and
//! adoption require the workspace administrator. Existing v1 imports install
//! and adopt it through their ordinary package preparation. Serving never runs
//! these operations; missing prerequisites produce `saved_tabs_not_prepared`.
//! If projections were lost rather than merely introduced by this upgrade,
//! run `kernel::replay_all_projections` before resuming service. Both saved-tab
//! tables and operation receipts reconstruct exclusively from canonical events.
//! No production database is changed by compiling or registering this module.
use crate::package_manifest::{DefinitionEntry, PackageManifest};

pub const FAMILY: &str = "native.saved_tabs.tab";
pub const DEFINITION: &str = include_str!("saved_tabs.defn.json");

/// Install and adopt at the workspace root through the ordinary package path.
/// The scoped host operation owns provisioning and all subsequent mutations.
pub fn package() -> PackageManifest {
    PackageManifest {
        namespace: "native.saved_tabs".into(),
        name: "saved_tabs".into(),
        version: 1,
        definitions: vec![DefinitionEntry {
            family: FAMILY.into(),
            version: 1,
            artifact_bytes: DEFINITION.into(),
            digest: crate::meta::definition_artifact::digest_artifact_bytes(DEFINITION.as_bytes()),
        }],
        operations: vec![],
        behaviour: None,
        surface: None,
        declared_reads: vec![],
    }
}
